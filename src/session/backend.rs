use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::session::payload::{
    bytes_sha256_hex, extract_raw_refresh_token_from_session_bytes, parse_session_payload_bytes,
    ParsedSessionPayload,
};
use crate::store::fs_atomic::{
    check_fault_injection, ensure_no_symlink_components_under, fsync_pinned_dir_fd,
    is_single_normal_filename, map_io_error, open_existing_dir_nofollow,
    read_regular_file_opt_bounded, remove_regular_file_durable_under, stat_dir_fd,
    write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum SlotInspectState {
    /// `~/.gemini/antigravity-cli` directory does not exist yet
    Uninitialized,
    /// `~/.gemini/antigravity-cli` exists, `antigravity-oauth-token` does not exist yet
    AbsentInInitializedDir,
    /// Valid regular file / keyring secret parsed cleanly
    Present(ParsedSessionPayload),
    /// Invalid JSON, symlink, directory obstruction, conflicting collections, etc.
    Corrupt(String),
    /// Permission or backend inspection failure
    Unverified(String),
}

impl SlotInspectState {
    pub fn raw_digest(&self) -> Option<&str> {
        match self {
            Self::Present(p) => Some(p.raw_digest.as_str()),
            _ => None,
        }
    }

    pub fn is_absent_clean(&self) -> bool {
        matches!(self, Self::Uninitialized | Self::AbsentInInitializedDir)
    }
}

/// Per-collection SHA-256 digest summary for Secret Service keyring collections (contains ZERO plaintext secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringCollectionDigest {
    pub path: String,
    pub present: bool,
    pub digest: Option<String>,
    /// `Some(refresh_token_digest)` when `present == true` AND the secret parses as a valid session payload.
    pub valid_refresh_token_digest: Option<String>,
}

/// Read-only multi-replica state used by transactional journal diagnosis and reconciliation.
/// Separates "effective identity inspection" (`inspect_slot`) from "all-replica verification" (`inspect_replicas`).
#[derive(Debug, Clone)]
pub struct BackendReplicaInspection {
    pub backend_name: &'static str,
    pub uses_keyring: bool,
    pub uses_file: bool,
    pub keyring: Option<SlotInspectState>,
    pub keyring_all_collections_uniform: bool,
    pub keyring_collections: Vec<KeyringCollectionDigest>,
    pub file: SlotInspectState,
}

impl BackendReplicaInspection {
    /// Project the effective slot state from an already-captured replica inspection
    /// without performing any additional backend or filesystem reads.
    ///
    /// Preserves the exact precedence of `CredentialBackend::inspect_slot`:
    /// - `keyring` (`uses_keyring && !uses_file`): returns the keyring state directly (never falls back to `file`).
    /// - `dual` (`uses_keyring && uses_file`): falls back to `file` ONLY when keyring is cleanly absent
    ///   (`AbsentInInitializedDir` or `Uninitialized`), never masking `Corrupt` or `Unverified`.
    /// - `file` (`!uses_keyring`): returns `file`.
    pub fn effective_slot_state(&self) -> &SlotInspectState {
        if self.uses_keyring {
            if let Some(ref kr_state) = self.keyring {
                if !self.uses_file {
                    return kr_state;
                }
                return match kr_state {
                    SlotInspectState::AbsentInInitializedDir | SlotInspectState::Uninitialized => {
                        &self.file
                    }
                    other => other,
                };
            }
        }
        &self.file
    }
}

/// Pre-switch replica byte snapshots held strictly in memory during an active switch under `L1`.
pub struct BackendPreWriteSnapshot {
    pub backend_name: &'static str,
    pub uses_keyring: bool,
    pub uses_file: bool,
    pub keyring_bytes: Option<Option<Vec<u8>>>,
    pub keyring_uniform: bool,
    pub keyring_collections: Vec<(String, Option<Vec<u8>>)>,
    pub file_bytes: Option<Vec<u8>>,
}

impl BackendPreWriteSnapshot {
    pub fn effective_slot_digest(&self) -> Option<String> {
        let kr = self.keyring_bytes.as_ref().and_then(|o| o.as_deref());
        let file = self
            .uses_file
            .then_some(self.file_bytes.as_deref())
            .flatten();
        kr.or(file).map(bytes_sha256_hex)
    }

    pub fn keyring_digest(&self) -> Option<String> {
        self.keyring_bytes
            .as_ref()
            .and_then(|o| o.as_deref())
            .map(bytes_sha256_hex)
    }

    pub fn keyring_collection_digests(&self) -> Vec<KeyringCollectionDigest> {
        self.keyring_collections
            .iter()
            .map(|(path, opt)| KeyringCollectionDigest {
                path: path.clone(),
                present: opt.is_some(),
                digest: opt.as_deref().map(bytes_sha256_hex),
                valid_refresh_token_digest: opt
                    .as_deref()
                    .and_then(|b| parse_session_payload_bytes(b).ok())
                    .map(|p| p.refresh_token_digest),
            })
            .collect()
    }

    pub fn file_digest(&self) -> Option<String> {
        self.uses_file
            .then_some(self.file_bytes.as_deref())
            .flatten()
            .map(bytes_sha256_hex)
    }
}

/// Exact per-replica CAS expectation passed into mutating backend operations (`write_slot_cas` /
/// `remove_slot_cas`) so pre-checked snapshots are verified immediately before mutation!
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedReplicaContent {
    Absent,
    Digest(String),
}

impl ExpectedReplicaContent {
    pub fn matches_bytes(&self, bytes: Option<&[u8]>) -> bool {
        match (self, bytes) {
            (Self::Absent, None) => true,
            (Self::Digest(exp), Some(actual)) => bytes_sha256_hex(actual) == *exp,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaCasExpectation {
    pub file_expected: Option<ExpectedReplicaContent>,
    pub keyring_expected_collections: Option<Vec<(String, ExpectedReplicaContent)>>,
}

impl ReplicaCasExpectation {
    pub fn from_pre_write_snapshot(snap: &BackendPreWriteSnapshot) -> Self {
        let file_expected = snap.uses_file.then(|| match snap.file_bytes.as_deref() {
            Some(b) => ExpectedReplicaContent::Digest(bytes_sha256_hex(b)),
            None => ExpectedReplicaContent::Absent,
        });
        let keyring_expected_collections = snap.uses_keyring.then(|| {
            snap.keyring_collections
                .iter()
                .map(|(path, opt)| {
                    let exp = match opt.as_deref() {
                        Some(b) => ExpectedReplicaContent::Digest(bytes_sha256_hex(b)),
                        None => ExpectedReplicaContent::Absent,
                    };
                    (path.clone(), exp)
                })
                .collect()
        });
        Self {
            file_expected,
            keyring_expected_collections,
        }
    }

    /// Construct a strict per-replica CAS expectation from a live `BackendReplicaInspection`.
    /// Rejects unverified replicas or non-regular corrupt disk obstructions (`RecoveryIncomplete`).
    pub fn from_replica_inspection(
        paths: &HeadlessPaths,
        replicas: &BackendReplicaInspection,
    ) -> CliResult<Self> {
        let file_expected = if replicas.uses_file {
            match &replicas.file {
                SlotInspectState::AbsentInInitializedDir | SlotInspectState::Uninitialized => {
                    Some(ExpectedReplicaContent::Absent)
                }
                SlotInspectState::Present(p) => {
                    Some(ExpectedReplicaContent::Digest(p.raw_digest.clone()))
                }
                SlotInspectState::Corrupt(_) => {
                    match read_regular_file_opt_bounded(
                        &paths.active_slot_file,
                        MAX_STORE_FILE_BYTES,
                        "Active session file",
                    ) {
                        Ok(Some(bytes)) => {
                            Some(ExpectedReplicaContent::Digest(bytes_sha256_hex(&bytes)))
                        }
                        Ok(None) => Some(ExpectedReplicaContent::Absent),
                        Err(_) => {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Cannot bind CAS expectation to a non-regular corrupt active slot file.",
                            ));
                        }
                    }
                }
                SlotInspectState::Unverified(_) => {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Cannot bind CAS expectation to an unverified active slot file.",
                    ));
                }
            }
        } else {
            None
        };

        let keyring_expected_collections = if replicas.uses_keyring {
            if replicas.keyring_collections.is_empty()
                || matches!(
                    replicas.keyring,
                    None | Some(SlotInspectState::Unverified(_))
                )
            {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Cannot bind CAS expectation without verified keyring collections.",
                ));
            }
            let mut cols = Vec::with_capacity(replicas.keyring_collections.len());
            for c in &replicas.keyring_collections {
                if !c.present {
                    cols.push((c.path.clone(), ExpectedReplicaContent::Absent));
                } else if let Some(ref d) = c.digest {
                    cols.push((c.path.clone(), ExpectedReplicaContent::Digest(d.clone())));
                } else {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Keyring collection is missing a verifiable digest for CAS repair.",
                    ));
                }
            }
            Some(cols)
        } else {
            None
        };

        Ok(Self {
            file_expected,
            keyring_expected_collections,
        })
    }
}

pub trait CredentialBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn uses_keyring(&self) -> bool;
    fn uses_file(&self) -> bool {
        true
    }
    /// Pure read-only effective identity inspection with ZERO file/directory/network/unlock side effects.
    fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState;
    /// Pure read-only inspection of ALL transactional replicas managed by this backend.
    fn inspect_replicas(&self, paths: &HeadlessPaths) -> BackendReplicaInspection {
        BackendReplicaInspection {
            backend_name: self.name(),
            uses_keyring: self.uses_keyring(),
            uses_file: self.uses_file(),
            keyring: None,
            keyring_all_collections_uniform: true,
            keyring_collections: Vec::new(),
            file: self.inspect_slot(paths),
        }
    }
    /// Validate active slot directory is initialized and return raw snapshot bytes before commit.
    fn snapshot_before_write(&self, paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>>;
    /// Capture independent pre-write snapshots of all replicas managed by this backend.
    fn snapshot_replicas_before_write(
        &self,
        paths: &HeadlessPaths,
    ) -> CliResult<BackendPreWriteSnapshot> {
        let file_bytes = self.snapshot_before_write(paths)?;
        Ok(BackendPreWriteSnapshot {
            backend_name: self.name(),
            uses_keyring: false,
            uses_file: self.uses_file(),
            keyring_bytes: None,
            keyring_uniform: true,
            keyring_collections: Vec::new(),
            file_bytes,
        })
    }
    /// Atomically replace active slot payload (caller MUST hold L1 `ActiveSlotLock`).
    fn write_slot(&self, paths: &HeadlessPaths, payload: &str) -> CliResult<()>;
    /// Atomically replace active slot payload ONLY IF all managed replicas still match `expected`
    /// (`PartialCommitOrRecovery` = 7 on concurrent drift; caller MUST hold L1 `ActiveSlotLock`).
    fn write_slot_cas(
        &self,
        paths: &HeadlessPaths,
        payload: &str,
        expected: &ReplicaCasExpectation,
    ) -> CliResult<()> {
        if self.uses_file() {
            let Some(ref exp_file) = expected.file_expected else {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Missing file CAS expectation for slot write.",
                ));
            };
            let cur_bytes = self.snapshot_before_write(paths)?;
            if !exp_file.matches_bytes(cur_bytes.as_deref()) {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Active credential file changed concurrently before CAS write; journal preserved.",
                ));
            }
        }
        self.write_slot(paths, payload)
    }
    /// Remove active slot file/items (caller MUST hold L1 `ActiveSlotLock`).
    fn remove_slot(&self, paths: &HeadlessPaths) -> CliResult<()>;
    /// Remove active slot file/items ONLY IF all managed replicas still match `expected`
    /// (`PartialCommitOrRecovery` = 7 on concurrent drift; caller MUST hold L1 `ActiveSlotLock`).
    fn remove_slot_cas(
        &self,
        paths: &HeadlessPaths,
        expected: &ReplicaCasExpectation,
    ) -> CliResult<()> {
        if self.uses_file() {
            let Some(ref exp_file) = expected.file_expected else {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Missing file CAS expectation for slot removal.",
                ));
            };
            let cur_bytes = read_regular_file_opt_bounded(
                &paths.active_slot_file,
                MAX_STORE_FILE_BYTES,
                "Active session file",
            )?;
            if !exp_file.matches_bytes(cur_bytes.as_deref()) {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Active credential file changed concurrently before CAS removal; journal preserved.",
                ));
            }
        }
        self.remove_slot(paths)
    }
    /// Transactionally clear all managed replicas verifying exact per-replica pre-delete digests,
    /// durably rolling back to `prev` on partial failure or returning `PartialCommitOrRecovery` (`7`)
    /// if rollback/durability cannot be confirmed.
    fn remove_slot_transactional(
        &self,
        paths: &HeadlessPaths,
        prev: &BackendPreWriteSnapshot,
    ) -> CliResult<()> {
        let cas = ReplicaCasExpectation::from_pre_write_snapshot(prev);
        if let Err(rm_err) = self.remove_slot_cas(paths, &cas) {
            if rm_err.exit_code == crate::error::ExitCode::PartialCommitOrRecovery {
                return Err(rm_err);
            }
            let durable_restored = match prev.file_bytes.as_deref() {
                Some(old_bytes) => {
                    if confirm_existing_slot_file_and_parent_durable(paths, old_bytes) {
                        true
                    } else if let Ok(old_str) = std::str::from_utf8(old_bytes) {
                        self.write_slot(paths, old_str).is_ok()
                            && self.inspect_slot(paths).raw_digest()
                                == prev.file_digest().as_deref()
                    } else {
                        false
                    }
                }
                None => false, // `remove_slot` itself failed (e.g. parent fsync), so durability is unconfirmed!
            };
            if !durable_restored {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Active slot removal failed ({}) and pre-delete state could not be durably restored.",
                        rm_err.message
                    ),
                ));
            }
            return Err(rm_err);
        }
        Ok(())
    }
    /// Conditionally roll back all replicas managed by this backend to `prev` without clobbering
    /// valid external credentials, and verify post-rollback replica consistency AND durability.
    fn rollback_replicas(
        &self,
        paths: &HeadlessPaths,
        prev: &BackendPreWriteSnapshot,
        target_digest: &str,
    ) -> CliResult<()> {
        check_fault_injection("slot_rollback", &paths.active_slot_file)?;
        let prev_file_digest = prev.file_digest();
        if let Ok(Some(cur_bytes)) = self.snapshot_before_write(paths) {
            let cur_digest = bytes_sha256_hex(&cur_bytes);
            if cur_digest != target_digest
                && Some(cur_digest.as_str()) != prev_file_digest.as_deref()
                && parse_session_payload_bytes(&cur_bytes).is_ok()
            {
                // Valid third-party external credential on disk: never clobber!
                return Ok(());
            }
        }

        // Always execute durable write/remove (including parent directory `fsync` when `prev.file_bytes` is `None`!)
        // rather than trusting an unsynced in-memory dcache absence!
        match prev.file_bytes.as_deref() {
            Some(old) => {
                if !confirm_existing_slot_file_and_parent_durable(paths, old) {
                    let old_str = std::str::from_utf8(old).map_err(|_| {
                        CliError::data("Previous slot snapshot was not UTF-8 during rollback.")
                    })?;
                    self.write_slot(paths, old_str)?;
                }
            }
            None => {
                self.remove_slot(paths)?;
            }
        }

        let after = self.inspect_slot(paths);
        match prev_file_digest.as_deref() {
            Some(exp) if after.raw_digest() == Some(exp) => Ok(()),
            None if after.is_absent_clean() => Ok(()),
            _ => Err(CliError::partial_commit(
                "recovery_incomplete",
                "Post-rollback credential slot verification did not match pre-switch snapshot.",
            )),
        }
    }
    /// Read raw credential bytes from the system keyring if this backend uses a keyring (`accounts add --from-local`).
    fn read_raw_keyring_secret(&self) -> CliResult<Option<Vec<u8>>> {
        Ok(None)
    }
    /// Read raw credential bytes matching `target_digest` from any keyring collection (cross-replica external preservation).
    fn read_raw_keyring_secret_by_digest(
        &self,
        _target_digest: &str,
    ) -> CliResult<Option<Vec<u8>>> {
        Ok(None)
    }
    /// Return a keyring-only view bound to the same verified local D-Bus socket when this backend
    /// has keyring capability (`dual` or `keyring`), used when reconciling a `keyring`-only journal
    /// so local disk files are never read, created, overwritten, or deleted.
    fn keyring_only_view(&self) -> Option<Box<dyn CredentialBackend>> {
        None
    }
}

/// Default headless file session backend (`~/.gemini/antigravity-cli/antigravity-oauth-token`).
#[derive(Debug, Clone, Default)]
pub struct FileSessionBackend;

fn confirm_existing_slot_file_and_parent_durable(
    paths: &HeadlessPaths,
    expected_bytes: &[u8],
) -> bool {
    let Ok(Some(cur)) = FileSessionBackend.snapshot_before_write(paths) else {
        return false;
    };
    if cur.as_slice() != expected_bytes {
        return false;
    }
    let Ok(Some(parent_fd)) = open_existing_dir_nofollow(&paths.active_slot_dir) else {
        return false;
    };
    let Some(leaf) = paths.active_slot_file.file_name() else {
        return false;
    };
    let Ok(c_leaf) = CString::new(leaf.as_bytes()) else {
        return false;
    };
    let raw_f = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw_f < 0 {
        return false;
    }
    let file = unsafe { std::fs::File::from_raw_fd(raw_f) };
    if file.sync_all().is_err() {
        return false;
    }
    if check_fault_injection("sync_parent_dir", &paths.active_slot_file).is_err() {
        return false;
    }
    fsync_pinned_dir_fd(&parent_fd, &paths.active_slot_dir).is_ok()
}

impl FileSessionBackend {
    fn ensure_slot_dir_initialized(paths: &HeadlessPaths) -> CliResult<()> {
        ensure_no_symlink_components_under(&paths.home_dir, &paths.active_slot_dir)?;
        match fs::symlink_metadata(&paths.active_slot_dir) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_dir() => Ok(()),
            Ok(_) => Err(CliError::data(format!(
                "The agy session directory '{}' must be a real directory, not a file or symlink.",
                paths.active_slot_dir.display()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(CliError::env_not_ready(
                "agy_uninitialized",
                format!(
                    "No initialized agy CLI session directory found at '{}'. Launch `agy` once to initialize its directory before switching accounts.",
                    paths.active_slot_dir.display()
                ),
            )),
            Err(e) => Err(map_io_error(
                e,
                &format!(
                    "Cannot inspect agy session directory '{}'",
                    paths.active_slot_dir.display()
                ),
            )),
        }
    }
}

impl CredentialBackend for FileSessionBackend {
    fn name(&self) -> &'static str {
        "file"
    }

    fn uses_keyring(&self) -> bool {
        false
    }

    fn uses_file(&self) -> bool {
        true
    }

    fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
        if let Err(e) = ensure_no_symlink_components_under(&paths.home_dir, &paths.active_slot_dir)
        {
            return if e.error_code == "data_error" {
                SlotInspectState::Corrupt(e.message)
            } else {
                SlotInspectState::Unverified(e.message)
            };
        }
        match fs::symlink_metadata(&paths.active_slot_dir) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_dir() => {}
            Ok(_) => {
                return SlotInspectState::Corrupt(format!(
                    "'{}' is not a real directory.",
                    paths.active_slot_dir.display()
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return SlotInspectState::Uninitialized
            }
            Err(e) => {
                return SlotInspectState::Unverified(format!(
                    "Cannot inspect '{}': {e}",
                    paths.active_slot_dir.display()
                ))
            }
        }

        match read_regular_file_opt_bounded(
            &paths.active_slot_file,
            MAX_STORE_FILE_BYTES,
            "Active session file",
        ) {
            Ok(Some(bytes)) => match parse_session_payload_bytes(&bytes) {
                Ok(parsed) => SlotInspectState::Present(parsed),
                Err(reason) => SlotInspectState::Corrupt(reason),
            },
            Ok(None) => SlotInspectState::AbsentInInitializedDir,
            Err(e) if e.error_code == "data_error" => SlotInspectState::Corrupt(e.message),
            Err(e) => SlotInspectState::Unverified(e.message),
        }
    }

    fn snapshot_before_write(&self, paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>> {
        Self::ensure_slot_dir_initialized(paths)?;
        read_regular_file_opt_bounded(
            &paths.active_slot_file,
            MAX_STORE_FILE_BYTES,
            "Active session file",
        )
    }

    fn write_slot(&self, paths: &HeadlessPaths, payload: &str) -> CliResult<()> {
        Self::ensure_slot_dir_initialized(paths)?;
        write_atomic_durable(&paths.active_slot_file, payload.as_bytes())
    }

    fn remove_slot(&self, paths: &HeadlessPaths) -> CliResult<()> {
        let _ = remove_regular_file_durable_under(
            &paths.home_dir,
            &paths.active_slot_file,
            "active session file",
        )?;
        Ok(())
    }
}

/// Verified local Unix domain socket identity jointly pinning canonical path, parent directory `(dev, ino)`,
/// and leaf socket `(dev, ino)` across backend resolution, probe, and every D-Bus connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDbusEndpoint {
    pub path: PathBuf,
    pub parent_dev: u64,
    pub parent_ino: u64,
    pub sock_dev: u64,
    pub sock_ino: u64,
}

fn percent_decode_dbus_value(raw: &str) -> Option<Vec<u8>> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            let decoded = ((hi << 4) | lo) as u8;
            if decoded == 0 {
                return None;
            }
            out.push(decoded);
            i += 3;
        } else {
            if bytes[i] == 0 {
                return None;
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Strictly enforce canonical normalized POSIX path syntax (rejecting relative paths, `.`, `..`,
/// duplicate `//`, trailing `/`, NULs, and `/dev/null`) on raw bytes with ZERO filesystem syscalls.
fn is_canonical_unix_socket_path_syntax(path: &Path) -> bool {
    let raw = path.as_os_str().as_bytes();
    if raw.len() < 2 || !raw.starts_with(b"/") || raw.ends_with(b"/") || raw.contains(&0) {
        return false;
    }
    if path == Path::new("/dev/null") {
        return false;
    }
    raw[1..]
        .split(|&b| b == b'/')
        .all(is_single_normal_filename)
}

fn extract_dbus_socket_candidates_from_address_str(addr: &str) -> Vec<PathBuf> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for entry in trimmed.split(';') {
        let entry = entry.trim();
        let Some(opts_str) = entry.strip_prefix("unix:") else {
            continue;
        };
        let mut path_val: Option<PathBuf> = None;
        let mut unsupported_opt = false;
        for kv in opts_str.split(',') {
            let kv = kv.trim();
            if kv.is_empty() {
                continue;
            }
            let Some((key, val)) = kv.split_once('=') else {
                unsupported_opt = true;
                break;
            };
            match key {
                "path" => {
                    let Some(decoded) = percent_decode_dbus_value(val) else {
                        unsupported_opt = true;
                        break;
                    };
                    path_val = Some(PathBuf::from(OsStr::from_bytes(&decoded)));
                }
                "guid" => {}
                _ => {
                    // Reject `abstract=`, `dir=`, `tmpdir=`, or unknown options
                    unsupported_opt = true;
                    break;
                }
            }
        }
        if !unsupported_opt {
            if let Some(candidate) = path_val {
                if is_canonical_unix_socket_path_syntax(&candidate) {
                    out.push(candidate);
                }
            }
        }
    }
    out
}

/// Pure string-only extraction of candidate canonical Unix socket paths from environment variables
/// (ZERO syscalls so callers can place filesystem path walks inside bounded timeout budgets).
fn extract_candidate_dbus_socket_paths() -> Vec<PathBuf> {
    if let Some(addr_os) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") {
        // When `DBUS_SESSION_BUS_ADDRESS` is explicitly set (e.g. `unix:path=/dev/null` or empty),
        // strictly honor it and NEVER fall back to `XDG_RUNTIME_DIR/bus`.
        let Some(addr) = addr_os.to_str() else {
            return Vec::new();
        };
        return extract_dbus_socket_candidates_from_address_str(addr);
    }
    if let Some(rt_os) = std::env::var_os("XDG_RUNTIME_DIR") {
        let Some(rt_str) = rt_os.to_str() else {
            return Vec::new();
        };
        let trimmed = rt_str.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            let bus = PathBuf::from(format!("{trimmed}/bus"));
            if is_canonical_unix_socket_path_syntax(&bus) {
                return vec![bus];
            }
        }
    }
    Vec::new()
}

const DBUS_PATH_CHECK_TIMEOUT: Duration = Duration::from_millis(1500);

/// Walk from `/` via `openat(..., O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` to pin `parent_fd`,
/// pin the exact leaf socket inode via `openat(parent_fd, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC)`,
/// verify `S_IFSOCK` on that pinned FD, and re-verify `parent` `(dev, ino)` and directory entry stability.
pub(crate) fn verify_and_pin_socket_endpoint(
    sock: &Path,
) -> Option<(OwnedFd, OwnedFd, CString, VerifiedDbusEndpoint)> {
    if !is_canonical_unix_socket_path_syntax(sock) {
        return None;
    }
    let parent = sock.parent().filter(|p| !p.as_os_str().is_empty())?;
    let leaf = sock.file_name()?;
    if !is_single_normal_filename(leaf.as_bytes()) {
        return None;
    }
    let c_leaf = CString::new(leaf.as_bytes()).ok()?;
    let parent_fd = open_existing_dir_nofollow(parent).ok().flatten()?;
    let (parent_dev, parent_ino) = stat_dir_fd(&parent_fd, parent).ok()?;

    let raw_sock = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_sock < 0 {
        return None;
    }
    let sock_opath_fd = unsafe { OwnedFd::from_raw_fd(raw_sock) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(sock_opath_fd.as_raw_fd(), &mut st) } != 0
        || (st.st_mode & libc::S_IFMT) != libc::S_IFSOCK
    {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    let (sock_dev, sock_ino) = (st.st_dev as u64, st.st_ino as u64);

    // Re-walk parent and re-stat leaf to confirm ancestor lineage and directory entry stability
    let post_parent_fd = open_existing_dir_nofollow(parent).ok().flatten()?;
    let (post_p_dev, post_p_ino) = stat_dir_fd(&post_parent_fd, parent).ok()?;
    if (post_p_dev, post_p_ino) != (parent_dev, parent_ino) {
        return None;
    }
    let mut entry_st: libc::stat = unsafe { std::mem::zeroed() };
    let entry_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut entry_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    #[allow(clippy::unnecessary_cast)]
    if entry_rc != 0
        || (entry_st.st_mode & libc::S_IFMT) != libc::S_IFSOCK
        || (entry_st.st_dev as u64) != sock_dev
        || (entry_st.st_ino as u64) != sock_ino
    {
        return None;
    }

    Some((
        parent_fd,
        sock_opath_fd,
        c_leaf,
        VerifiedDbusEndpoint {
            path: sock.to_path_buf(),
            parent_dev,
            parent_ino,
            sock_dev,
            sock_ino,
        },
    ))
}

#[cfg(test)]
fn parse_verified_unix_socket_from_dbus_address(addr: &str) -> Option<PathBuf> {
    for cand in extract_dbus_socket_candidates_from_address_str(addr) {
        if let Some((_, _, _, ep)) = verify_and_pin_socket_endpoint(&cand) {
            return Some(ep.path);
        }
    }
    None
}

fn verify_socket_candidates_with_timeout(
    candidates: Vec<PathBuf>,
    timeout: Duration,
) -> Option<VerifiedDbusEndpoint> {
    if candidates.is_empty() {
        return None;
    }
    let deadline = std::time::Instant::now() + timeout;
    let (tx, rx) = std::sync::mpsc::sync_channel::<Option<VerifiedDbusEndpoint>>(1);
    std::thread::spawn(move || {
        for cand in &candidates {
            if std::time::Instant::now() >= deadline {
                let _ = tx.send(None);
                return;
            }
            if let Some((_, _, _, ep)) = verify_and_pin_socket_endpoint(cand) {
                let _ = tx.send(Some(ep));
                return;
            }
        }
        let _ = tx.send(None);
    });
    let rem = deadline.saturating_duration_since(std::time::Instant::now());
    rx.recv_timeout(rem).ok().flatten()
}

/// Resolve and stat-verify a canonical local Unix domain socket strictly within a bounded wall-clock
/// timeout so callers (explicit `dual`/`keyring`, `status` D-Bus note, or `run`) can never hang
/// indefinitely on an unresponsive mount point.
pub fn resolve_verified_dbus_endpoint_with_timeout(
    timeout: Duration,
) -> Option<VerifiedDbusEndpoint> {
    verify_socket_candidates_with_timeout(extract_candidate_dbus_socket_paths(), timeout)
}

pub fn resolve_verified_dbus_endpoint() -> Option<VerifiedDbusEndpoint> {
    resolve_verified_dbus_endpoint_with_timeout(DBUS_PATH_CHECK_TIMEOUT)
}

/// Resolve and stat-verify a canonical local filesystem Unix domain socket for the user's D-Bus session bus.
/// Never accepts `tcp:`, `nonce-tcp:`, `unixexec:`, `ibus:`, `vsock:`, abstract sockets, `..`, or symlinks.
pub fn resolve_verified_local_dbus_socket() -> Option<PathBuf> {
    resolve_verified_dbus_endpoint().map(|ep| ep.path)
}

/// Pure stat-only check (NEVER connects to D-Bus or reads any keyring items!) detecting if a user
/// D-Bus session socket exists in the current environment, which in `agy`'s `composite_token_storage`
/// takes precedence over `antigravity-oauth-token` if an unlocked Secret Service holds a credential.
pub fn detect_dbus_session_socket_warning() -> Option<String> {
    let sock_path = resolve_verified_local_dbus_socket()?;
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        Some(format!(
            "Detected live D-Bus session socket via DBUS_SESSION_BUS_ADDRESS ('{}'). Official `agy` queries D-Bus Secret Service before `~/.gemini/antigravity-cli/antigravity-oauth-token`; use `--backend auto` (or `--backend dual`) to sync keyring, or launch via `agy-switch-cli --backend file run -- agy` to isolate child D-Bus.",
            sock_path.display()
        ))
    } else {
        Some(format!(
            "Detected systemd user D-Bus socket at '{}'. Official `agy` queries D-Bus Secret Service before falling back to `antigravity-oauth-token`; launch via `agy-switch-cli --backend file run -- agy` if stale desktop keyring entries exist.",
            sock_path.display()
        ))
    }
}

/// Fast stat-only check determining whether a verified local session D-Bus socket exists.
/// Returns `false` immediately for non-existent sockets, non-local transports, or `unix:path=/dev/null`.
pub fn has_reachable_dbus_session_bus() -> bool {
    resolve_verified_local_dbus_socket().is_some()
}

/// Returns `true` when `DBUS_SESSION_BUS_ADDRESS` is set in the environment or a session D-Bus
/// socket exists at `$XDG_RUNTIME_DIR/bus`, so `run` under an explicit `file` backend can sanitize
/// `DBUS_SESSION_BUS_ADDRESS=unix:path=/dev/null` for the spawned `agy` child.
pub fn should_isolate_child_dbus_for_explicit_file_backend() -> bool {
    std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() || has_reachable_dbus_session_bus()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    Auto,
    Dual,
    File,
    Keyring,
}

/// Strictly validate `--backend`, `AGY_SWITCH_CLI_BACKEND`, and `config.json` `backend` against the
/// four exact literal values (`auto`, `dual`, `file`, `keyring`) without trimming or case-folding.
/// Distinguishes omitted (`None`) from explicit empty or whitespace-padded strings (`Some("")`, `Some(" FILE ")`).
pub fn validate_backend_choice(
    cli_backend: Option<&str>,
    cfg_backend: Option<&str>,
) -> CliResult<BackendChoice> {
    let env_os = std::env::var_os("AGY_SWITCH_CLI_BACKEND");
    let chosen: &str = if let Some(cli_val) = cli_backend {
        cli_val
    } else if let Some(ref raw_env) = env_os {
        raw_env.to_str().ok_or_else(|| {
            CliError::usage(
                "Unsupported credential backend. Supported values: `auto`, `dual`, `file`, `keyring`.",
            )
        })?
    } else if let Some(cfg_val) = cfg_backend {
        cfg_val
    } else {
        "auto"
    };

    match chosen {
        "auto" => Ok(BackendChoice::Auto),
        "file" => Ok(BackendChoice::File),
        "dual" => {
            #[cfg(feature = "secret-service-backend")]
            {
                Ok(BackendChoice::Dual)
            }
            #[cfg(not(feature = "secret-service-backend"))]
            {
                Err(CliError::usage(
                    "Backend `dual` requires compiling with `--features secret-service-backend` (enabled by default in standard builds).",
                ))
            }
        }
        "keyring" => {
            #[cfg(feature = "secret-service-backend")]
            {
                Ok(BackendChoice::Keyring)
            }
            #[cfg(not(feature = "secret-service-backend"))]
            {
                Err(CliError::usage(
                    "Backend `keyring` requires compiling with `--features secret-service-backend` (enabled by default in standard builds).",
                ))
            }
        }
        _ => Err(CliError::usage(
            "Unsupported credential backend. Supported values: `auto`, `dual`, `file`, `keyring`.",
        )),
    }
}

/// Resolve the configured `CredentialBackend` (`auto` by default: uses `dual` transactional dual-write
/// when a persistent desktop keyring collection is reachable on the verified local D-Bus socket
/// within the unified `1500ms` wall-clock budget, otherwise `file`; also supports explicit `dual`, `file`, and `keyring`).
pub fn resolve_credential_backend(
    cli_backend: Option<&str>,
) -> CliResult<Box<dyn CredentialBackend>> {
    resolve_credential_backend_with_config(cli_backend, None)
}

pub fn resolve_credential_backend_with_config(
    cli_backend: Option<&str>,
    cfg_backend: Option<&str>,
) -> CliResult<Box<dyn CredentialBackend>> {
    match validate_backend_choice(cli_backend, cfg_backend)? {
        BackendChoice::File => Ok(Box::new(FileSessionBackend)),
        BackendChoice::Dual => {
            #[cfg(feature = "secret-service-backend")]
            {
                let ep = resolve_verified_dbus_endpoint();
                Ok(Box::new(SecretServiceSessionBackend::with_endpoint(ep)))
            }
            #[cfg(not(feature = "secret-service-backend"))]
            {
                unreachable!("validate_backend_choice already gated secret-service-backend")
            }
        }
        BackendChoice::Keyring => {
            #[cfg(feature = "secret-service-backend")]
            {
                let ep = resolve_verified_dbus_endpoint();
                Ok(Box::new(
                    SecretServiceSessionBackend::keyring_only_with_endpoint(ep),
                ))
            }
            #[cfg(not(feature = "secret-service-backend"))]
            {
                unreachable!("validate_backend_choice already gated secret-service-backend")
            }
        }
        BackendChoice::Auto => {
            #[cfg(feature = "secret-service-backend")]
            {
                let candidates = extract_candidate_dbus_socket_paths();
                if !candidates.is_empty() {
                    if let Some(ep) = keyring_impl::probe_verified_auto_endpoint(candidates) {
                        return Ok(Box::new(SecretServiceSessionBackend::with_endpoint(Some(
                            ep,
                        ))));
                    }
                }
            }
            Ok(Box::new(FileSessionBackend))
        }
    }
}

/// Read the currently signed-in local `agy` `refresh_token` following the active backend's boundary:
/// - `keyring`: reads ONLY Linux Secret Service keyring (`service="gemini", username="antigravity"`), never touching disk;
/// - `dual` / `auto`: reads Linux Secret Service keyring first, falling back to `~/.gemini/antigravity-cli/antigravity-oauth-token`;
/// - `file`: reads ONLY `~/.gemini/antigravity-cli/antigravity-oauth-token`.
pub fn read_local_active_refresh_token(
    paths: &HeadlessPaths,
    backend: &dyn CredentialBackend,
) -> CliResult<(String, &'static str)> {
    if backend.uses_keyring() {
        if let Some(bytes) = backend.read_raw_keyring_secret()? {
            let rt = extract_raw_refresh_token_from_session_bytes(
                &bytes,
                "Linux Secret Service keyring",
            )?;
            return Ok((rt, "secret_service_keyring"));
        }
        if !backend.uses_file() {
            return Err(CliError::not_found(
                "No Antigravity credential found in Linux Secret Service keyring. Sign in first, or use `--backend auto` / `--backend file` if your credential is stored in `~/.gemini/antigravity-cli/antigravity-oauth-token`.",
            ));
        }
    }

    ensure_no_symlink_components_under(&paths.home_dir, &paths.active_slot_file)?;
    if let Some(bytes) = read_regular_file_opt_bounded(
        &paths.active_slot_file,
        MAX_STORE_FILE_BYTES,
        "Local agy session file",
    )? {
        let rt = extract_raw_refresh_token_from_session_bytes(&bytes, "Local agy session file")?;
        return Ok((rt, "agy_session_file"));
    }

    if !backend.uses_keyring() && detect_dbus_session_socket_warning().is_some() {
        return Err(CliError::not_found(format!(
            "No local agy credential file found at '{}'. Detected an active desktop D-Bus session: omit `--backend file` (or pass `--backend auto` / `--backend keyring`) so `--from-local` can read directly from the system keyring, or sign in via `agy-switch-cli auth login`.",
            paths.active_slot_file.display()
        )));
    }

    Err(CliError::not_found(format!(
        "No local agy credential found at '{}'. Sign in with `agy` first or add an account via `agy-switch-cli auth login`.",
        paths.active_slot_file.display()
    )))
}

/// Non-GUI D-Bus Secret Service backend (`--features secret-service-backend`), supporting both
/// `dual` (keyring + local file transactional dual-write) and `keyring` (keyring-only, zero local file I/O).
/// Permanently bound to the verified local Unix domain socket endpoint `(path, parent_dev, parent_ino, sock_dev, sock_ino)`.
#[cfg(feature = "secret-service-backend")]
#[derive(Debug, Clone)]
pub struct SecretServiceSessionBackend {
    endpoint: Option<VerifiedDbusEndpoint>,
    include_file: bool,
}

#[cfg(feature = "secret-service-backend")]
impl SecretServiceSessionBackend {
    pub fn with_endpoint(endpoint: Option<VerifiedDbusEndpoint>) -> Self {
        Self {
            endpoint,
            include_file: true,
        }
    }

    pub fn keyring_only_with_endpoint(endpoint: Option<VerifiedDbusEndpoint>) -> Self {
        Self {
            endpoint,
            include_file: false,
        }
    }

    pub fn with_socket(socket_path: Option<PathBuf>) -> Self {
        let ep = socket_path.map(|p| vec![p]).and_then(|cands| {
            verify_socket_candidates_with_timeout(cands, DBUS_PATH_CHECK_TIMEOUT)
        });
        Self::with_endpoint(ep)
    }

    pub fn keyring_only_with_socket(socket_path: Option<PathBuf>) -> Self {
        let ep = socket_path.map(|p| vec![p]).and_then(|cands| {
            verify_socket_candidates_with_timeout(cands, DBUS_PATH_CHECK_TIMEOUT)
        });
        Self::keyring_only_with_endpoint(ep)
    }
}

#[cfg(feature = "secret-service-backend")]
pub(crate) fn discover_verified_dbus_endpoint() -> Option<VerifiedDbusEndpoint> {
    for cand in extract_candidate_dbus_socket_paths() {
        if let Some((_, _, _, ep)) = verify_and_pin_socket_endpoint(&cand) {
            return Some(ep);
        }
    }
    None
}

#[cfg(feature = "secret-service-backend")]
pub(crate) async fn connect_verified_session_dbus(
    ep: &VerifiedDbusEndpoint,
    method_timeout: Duration,
) -> CliResult<zbus::Connection> {
    let (pre_parent_fd, sock_opath_fd, c_leaf, live_pre) =
        verify_and_pin_socket_endpoint(&ep.path).ok_or_else(|| {
            CliError::env_not_ready(
                "secret_service_unavailable",
                "Linux Secret Service D-Bus session socket is unavailable or failed local socket verification.",
            )
        })?;
    if live_pre != *ep {
        return Err(CliError::env_not_ready(
            "secret_service_unavailable",
            "Linux Secret Service D-Bus session socket or parent directory changed since initialization.",
        ));
    }

    // Connect STRICTLY through `/proc/self/fd/<sock_opath_fd>` (pinned via `O_PATH | O_NOFOLLOW`
    // to the exact verified socket inode!) so neither ancestor directories NOR leaf names are
    // re-resolved by string path, and NEVER fall back to raw string `ep.path`!
    if !Path::new("/proc/self/fd").is_dir() {
        return Err(CliError::env_not_ready(
            "secret_service_unavailable",
            "Cannot bind D-Bus socket connection to verified inode without `/proc/self/fd`.",
        ));
    }
    let proc_sock_path = PathBuf::from(format!("/proc/self/fd/{}", sock_opath_fd.as_raw_fd()));
    let stream = tokio::net::UnixStream::connect(&proc_sock_path)
        .await
        .map_err(|_| {
            CliError::env_not_ready(
                "secret_service_unavailable",
                "Linux Secret Service D-Bus session socket connection failed.",
            )
        })?;

    let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
    let post_rc = unsafe {
        libc::fstatat(
            pre_parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut post_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    #[allow(clippy::unnecessary_cast)]
    let same_in_pinned_parent = post_rc == 0
        && (post_st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
        && (post_st.st_dev as u64) == ep.sock_dev
        && (post_st.st_ino as u64) == ep.sock_ino;
    if !same_in_pinned_parent {
        return Err(CliError::env_not_ready(
            "secret_service_unavailable",
            "Linux Secret Service D-Bus session socket changed during connection.",
        ));
    }

    // Re-walk from `/` down to `ep.path` AFTER `connect` to prove full path/parent/socket stability!
    let Some((_, _, _, live_post)) = verify_and_pin_socket_endpoint(&ep.path) else {
        return Err(CliError::env_not_ready(
            "secret_service_unavailable",
            "Linux Secret Service D-Bus session socket path failed post-connect verification.",
        ));
    };
    if live_post != *ep {
        return Err(CliError::env_not_ready(
            "secret_service_unavailable",
            "Linux Secret Service D-Bus session socket or parent directory changed during connection.",
        ));
    }

    let peer_cred = stream.peer_cred().map_err(|_| {
        CliError::env_not_ready(
            "secret_service_unavailable",
            "Linux Secret Service D-Bus session socket peer credential verification failed.",
        )
    })?;
    if peer_cred.uid() != unsafe { libc::geteuid() } {
        return Err(CliError::env_not_ready(
            "secret_service_unavailable",
            "Linux Secret Service D-Bus session socket is owned by a different user UID.",
        ));
    }
    zbus::connection::Builder::unix_stream(stream)
        .method_timeout(method_timeout)
        .build()
        .await
        .map_err(|_| {
            CliError::env_not_ready(
                "secret_service_unavailable",
                "Linux Secret Service D-Bus handshake failed.",
            )
        })
}

#[cfg(feature = "secret-service-backend")]
mod keyring_impl {
    use super::*;
    use secret_service::{Collection, EncryptionType, SecretService};
    use std::collections::{BTreeSet, HashMap};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{mpsc, Arc, Condvar, LazyLock, Mutex};
    use std::time::Instant;

    const KEYRING_TIMEOUT: Duration = Duration::from_secs(10);
    const AUTO_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
    const WORKER_CANCEL_GRACE: Duration = Duration::from_millis(200);

    static ACTIVE_MUTATION_WORKERS: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(0));

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum GatePhase {
        BeforeMutation,
        CancelledBeforeMutation,
        MutationEntered,
        TimedOutUncertain,
    }

    struct GateInner {
        phase: GatePhase,
        worker_done: bool,
    }

    /// Mutex-synchronized mutation gate shared between caller and worker thread:
    /// guarantees strict mutual exclusion between caller timeout cancellation and worker mutation
    /// initiation (so no D-Bus write/delete OR local file write/delete can start after timeout!).
    #[derive(Clone)]
    pub(super) struct MutationGate {
        inner: Arc<(Mutex<GateInner>, Condvar)>,
    }

    impl MutationGate {
        pub(super) fn new() -> Self {
            Self {
                inner: Arc::new((
                    Mutex::new(GateInner {
                        phase: GatePhase::BeforeMutation,
                        worker_done: false,
                    }),
                    Condvar::new(),
                )),
            }
        }

        /// Atomically enter (or continue) the mutating region. Fails closed if caller already timed out!
        pub(super) fn enter_mutation(&self) -> Result<(), CliError> {
            let mut g = self
                .inner
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match g.phase {
                GatePhase::BeforeMutation => {
                    g.phase = GatePhase::MutationEntered;
                    Ok(())
                }
                GatePhase::MutationEntered => Ok(()),
                GatePhase::CancelledBeforeMutation | GatePhase::TimedOutUncertain => {
                    Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Linux Secret Service mutation aborted after timeout; switch journal preserved.",
                    ))
                }
            }
        }

        pub(super) fn is_timed_out(&self) -> bool {
            let g = self
                .inner
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            matches!(
                g.phase,
                GatePhase::CancelledBeforeMutation | GatePhase::TimedOutUncertain
            )
        }

        pub(super) fn mark_worker_done(&self) {
            let mut g = self
                .inner
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            g.worker_done = true;
            self.inner.1.notify_all();
        }

        pub(super) fn cancel_on_timeout(&self) -> GatePhase {
            let mut g = self
                .inner
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match g.phase {
                GatePhase::BeforeMutation => {
                    g.phase = GatePhase::CancelledBeforeMutation;
                }
                GatePhase::MutationEntered => {
                    g.phase = GatePhase::TimedOutUncertain;
                }
                GatePhase::CancelledBeforeMutation | GatePhase::TimedOutUncertain => {}
            }
            g.phase
        }

        pub(super) fn wait_worker_done(&self, max_wait: Duration) -> (GatePhase, bool) {
            let g = self
                .inner
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (guard, _) = self
                .inner
                .1
                .wait_timeout_while(g, max_wait, |st| !st.worker_done)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (guard.phase, guard.worker_done)
        }
    }

    pub(super) async fn connect_bound_secret_service(
        endpoint: Option<&VerifiedDbusEndpoint>,
        method_timeout: Duration,
    ) -> CliResult<SecretService<'static>> {
        let ep = endpoint.ok_or_else(|| {
            CliError::env_not_ready(
                "secret_service_unavailable",
                "Linux Secret Service D-Bus session socket is unavailable or not a verified local Unix socket.",
            )
        })?;
        let conn = super::connect_verified_session_dbus(ep, method_timeout).await?;
        SecretService::connect_with_existing(EncryptionType::Dh, conn)
            .await
            .map_err(describe_ss_err)
    }

    fn run_dbus_readonly_with_wall_timeout<T: Send + 'static>(
        timeout: Duration,
        fut: impl Future<Output = CliResult<T>> + Send + 'static,
    ) -> CliResult<T> {
        let (tx, rx) = mpsc::sync_channel::<CliResult<T>>(1);
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(_) => {
                    let _ = tx.send(Err(CliError::io(
                        "keyring_rt_failed",
                        "Failed to initialize async runtime for Secret Service.",
                    )));
                    return;
                }
            };
            let outcome = rt.block_on(async {
                tokio::time::timeout(timeout, fut).await.map_err(|_| {
                    CliError::env_not_ready(
                        "secret_service_timeout",
                        "Linux Secret Service operation timed out.",
                    )
                })?
            });
            let _ = tx.send(outcome);
            rt.shutdown_timeout(Duration::from_millis(50));
        });

        match rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CliError::env_not_ready(
                "secret_service_timeout",
                "Linux Secret Service operation timed out.",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(CliError::io(
                "keyring_worker_panicked",
                "Keyring worker thread terminated unexpectedly.",
            )),
        }
    }

    /// Execute a mutating Secret Service operation (`CreateItem` / `Delete` / dual file write) with
    /// mutex-enforced cancellation exclusion and active-worker tracking:
    /// - Refuses to start a new mutating worker if a previous timed-out worker has not terminated yet (`7`);
    /// - On caller timeout, atomically marks the gate timed out (preventing ANY subsequent D-Bus or file
    ///   mutation from starting), signals async cancellation, and waits briefly for worker exit;
    /// - ONLY returns `EnvNotReady` (`8`) if the worker is confirmed terminated BEFORE entering any mutation;
    ///   otherwise returns `PartialCommitOrRecovery` (`7`) so the switch journal is preserved!
    fn run_dbus_mutating<T: Send + 'static>(
        build_fut: impl FnOnce(MutationGate) -> Pin<Box<dyn Future<Output = CliResult<T>> + Send>>
            + Send
            + 'static,
    ) -> CliResult<T> {
        run_dbus_mutating_with_bounds(KEYRING_TIMEOUT, WORKER_CANCEL_GRACE, build_fut)
    }

    pub(super) fn run_dbus_mutating_with_bounds<T: Send + 'static>(
        timeout: Duration,
        cancel_grace: Duration,
        build_fut: impl FnOnce(MutationGate) -> Pin<Box<dyn Future<Output = CliResult<T>> + Send>>
            + Send
            + 'static,
    ) -> CliResult<T> {
        {
            let mut active = ACTIVE_MUTATION_WORKERS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *active > 0 {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Previous Linux Secret Service mutation worker has not terminated; refusing overlapping mutation and preserving journal.",
                ));
            }
            *active += 1;
        }

        let gate = MutationGate::new();
        let gate_worker = gate.clone();
        let gate_caller = gate.clone();
        let (tx, rx) = mpsc::sync_channel::<CliResult<T>>(1);
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let worker_async_timeout = timeout
            .checked_sub(Duration::from_millis(50))
            .filter(|d| !d.is_zero())
            .unwrap_or(timeout);

        struct WorkerFinishGuard {
            gate: MutationGate,
        }
        impl Drop for WorkerFinishGuard {
            fn drop(&mut self) {
                {
                    let mut active = ACTIVE_MUTATION_WORKERS
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *active = active.saturating_sub(1);
                }
                self.gate.mark_worker_done();
            }
        }

        let spawn_res = std::thread::Builder::new()
            .name("agy-dbus-mut".into())
            .spawn(move || {
                let _finish_guard = WorkerFinishGuard {
                    gate: gate_worker.clone(),
                };
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = tx.send(Err(CliError::io(
                            "keyring_rt_failed",
                            "Failed to initialize async runtime for Secret Service.",
                        )));
                        return;
                    }
                };
                let gate_inner = gate_worker.clone();
                let fut = build_fut(gate_worker);
                let outcome = rt.block_on(async move {
                    tokio::select! {
                        biased;
                        _ = cancel_rx => {
                            let phase = gate_inner.cancel_on_timeout();
                            if phase == GatePhase::CancelledBeforeMutation {
                                Err(CliError::env_not_ready(
                                    "secret_service_timeout",
                                    "Linux Secret Service operation timed out.",
                                ))
                            } else {
                                Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    "Linux Secret Service write/delete timed out with uncertain commit state; switch journal preserved. Retry `agy-switch-cli switch` once Secret Service is responsive.",
                                ))
                            }
                        }
                        res = tokio::time::timeout(worker_async_timeout, fut) => {
                            match res {
                                Ok(inner) => inner,
                                Err(_) => {
                                    let phase = gate_inner.cancel_on_timeout();
                                    if phase == GatePhase::CancelledBeforeMutation {
                                        Err(CliError::env_not_ready(
                                            "secret_service_timeout",
                                            "Linux Secret Service operation timed out.",
                                        ))
                                    } else {
                                        Err(CliError::partial_commit(
                                            "recovery_incomplete",
                                            "Linux Secret Service write/delete timed out with uncertain commit state; switch journal preserved. Retry `agy-switch-cli switch` once Secret Service is responsive.",
                                        ))
                                    }
                                }
                            }
                        }
                    }
                });
                let _ = tx.send(outcome);
                rt.shutdown_timeout(Duration::from_millis(50));
            });

        if spawn_res.is_err() {
            let mut active = ACTIVE_MUTATION_WORKERS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *active = active.saturating_sub(1);
            return Err(CliError::io(
                "keyring_worker_spawn_failed",
                "Failed to spawn keyring worker thread.",
            ));
        }

        match rx.recv_timeout(timeout) {
            Ok(res) => {
                let (_final_phase, worker_exited) = gate_caller.wait_worker_done(cancel_grace);
                if !worker_exited {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Linux Secret Service mutation worker failed to terminate cleanly within grace period; switch journal preserved.",
                    ));
                }
                res
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = gate_caller.cancel_on_timeout();
                let _ = cancel_tx.send(());
                let (final_phase, worker_exited) = gate_caller.wait_worker_done(cancel_grace);
                if final_phase == GatePhase::CancelledBeforeMutation && worker_exited {
                    Err(CliError::env_not_ready(
                        "secret_service_timeout",
                        "Linux Secret Service operation timed out.",
                    ))
                } else {
                    Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Linux Secret Service write/delete timed out with uncertain commit state or active worker; switch journal preserved. Retry `agy-switch-cli switch` once Secret Service is responsive.",
                    ))
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let (final_phase, worker_exited) = gate_caller.wait_worker_done(cancel_grace);
                if matches!(
                    final_phase,
                    GatePhase::BeforeMutation | GatePhase::CancelledBeforeMutation
                ) && worker_exited
                {
                    Err(CliError::io(
                        "keyring_worker_panicked",
                        "Keyring worker thread terminated unexpectedly.",
                    ))
                } else {
                    Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Keyring worker terminated after initiating Secret Service mutation; retry `agy-switch-cli switch` to reconcile.",
                    ))
                }
            }
        }
    }

    /// Unified `1500ms` wall-clock auto-probe encompassing BOTH filesystem `openat`/`fstatat` path
    /// verification AND non-mutating D-Bus `org.freedesktop.secrets` collection discovery (NEVER calls `.unlock()`).
    pub(super) fn probe_verified_auto_endpoint(
        candidates: Vec<PathBuf>,
    ) -> Option<VerifiedDbusEndpoint> {
        let start = Instant::now();
        let deadline = start + AUTO_PROBE_TIMEOUT;
        let (tx, rx) = mpsc::sync_channel::<Option<VerifiedDbusEndpoint>>(1);

        std::thread::spawn(move || {
            let mut pinned_ep: Option<VerifiedDbusEndpoint> = None;
            for cand in &candidates {
                if Instant::now() >= deadline {
                    let _ = tx.send(None);
                    return;
                }
                if let Some((_, _, _, ep)) = verify_and_pin_socket_endpoint(cand) {
                    pinned_ep = Some(ep);
                    break;
                }
            }
            let Some(ep) = pinned_ep else {
                // Fast exit (~microseconds) when no local D-Bus socket exists — zero Tokio runtime overhead!
                let _ = tx.send(None);
                return;
            };
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                let _ = tx.send(None);
                return;
            }
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = tx.send(None);
                return;
            };
            let ep_clone = ep.clone();
            let ok = rt
                .block_on(async move {
                    tokio::time::timeout(rem, async move {
                        let svc = connect_bound_secret_service(Some(&ep_clone), rem).await?;
                        let _ = open_collections(&svc).await?;
                        Ok::<_, CliError>(true)
                    })
                    .await
                })
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false);
            let _ = tx.send(ok.then_some(ep));
            rt.shutdown_timeout(Duration::from_millis(50));
        });

        let wait_rem = deadline.saturating_duration_since(Instant::now());
        rx.recv_timeout(wait_rem).ok().flatten()
    }

    fn keyring_attributes() -> HashMap<&'static str, &'static str> {
        HashMap::from([("service", "gemini"), ("username", "antigravity")])
    }

    fn is_uncertain_fdo_err(fdo_err: &zbus::fdo::Error) -> bool {
        matches!(
            fdo_err,
            zbus::fdo::Error::NoReply(_)
                | zbus::fdo::Error::Timeout(_)
                | zbus::fdo::Error::TimedOut(_)
                | zbus::fdo::Error::Disconnected(_)
                | zbus::fdo::Error::NameHasNoOwner(_)
                | zbus::fdo::Error::IOError(_)
        )
    }

    fn is_uncertain_dbus_err(zerr: &zbus::Error) -> bool {
        match zerr {
            zbus::Error::InputOutput(_)
            | zbus::Error::Handshake(_)
            | zbus::Error::Failure(_)
            | zbus::Error::InvalidReply
            | zbus::Error::MissingField => true,
            zbus::Error::FDO(fdo_err) => {
                is_uncertain_fdo_err(fdo_err)
                    || matches!(fdo_err.as_ref(), zbus::fdo::Error::ZBus(inner) if is_uncertain_dbus_err(inner))
            }
            zbus::Error::MethodError(name, _, _) => matches!(
                name.as_str(),
                "org.freedesktop.DBus.Error.NoReply"
                    | "org.freedesktop.DBus.Error.Timeout"
                    | "org.freedesktop.DBus.Error.TimedOut"
                    | "org.freedesktop.DBus.Error.Disconnected"
                    | "org.freedesktop.DBus.Error.NameHasNoOwner"
                    | "org.freedesktop.DBus.Error.IOError"
            ),
            _ => false,
        }
    }

    fn is_uncertain_dbus_transport_err(err: &secret_service::Error) -> bool {
        match err {
            secret_service::Error::PromptDisconnected => true,
            secret_service::Error::Zbus(zerr) => is_uncertain_dbus_err(zerr),
            secret_service::Error::ZbusFdo(fdo_err) => {
                is_uncertain_fdo_err(fdo_err)
                    || matches!(fdo_err, zbus::fdo::Error::ZBus(inner) if is_uncertain_dbus_err(inner))
            }
            _ => false,
        }
    }

    fn describe_ss_err(err: secret_service::Error) -> CliError {
        match err {
            secret_service::Error::Locked => CliError::env_not_ready(
                "keyring_locked",
                "Linux Secret Service keyring is locked; unlock the keyring or use `--backend file`.",
            ),
            secret_service::Error::Prompt | secret_service::Error::PromptDisconnected => {
                CliError::env_not_ready(
                    "keyring_prompt_unavailable",
                    "Linux Secret Service unlock prompt is unavailable in headless mode.",
                )
            }
            secret_service::Error::NoResult => CliError::env_not_ready(
                "secret_service_no_result",
                "Requested Linux Secret Service collection or item was not found.",
            ),
            secret_service::Error::Zvariant(_) => CliError::env_not_ready(
                "secret_service_invalid_response",
                "Linux Secret Service returned a malformed D-Bus message payload.",
            ),
            secret_service::Error::Crypto(_) => CliError::env_not_ready(
                "secret_service_crypto_error",
                "Linux Secret Service DH/AES session encryption failed.",
            ),
            secret_service::Error::Zbus(_)
            | secret_service::Error::ZbusFdo(_)
            | secret_service::Error::Unavailable => CliError::env_not_ready(
                "secret_service_unavailable",
                "Linux Secret Service D-Bus backend is unavailable.",
            ),
            _ => CliError::env_not_ready(
                "secret_service_unavailable",
                "Linux Secret Service D-Bus backend is unavailable.",
            ),
        }
    }

    fn run_dbus_readonly<T: Send + 'static>(
        fut: impl Future<Output = CliResult<T>> + Send + 'static,
    ) -> CliResult<T> {
        run_dbus_readonly_with_wall_timeout(KEYRING_TIMEOUT, fut)
    }

    async fn open_collections<'a>(
        service: &'a SecretService<'_>,
    ) -> CliResult<Vec<Collection<'a>>> {
        let mut cols: Vec<_> = service
            .get_all_collections()
            .await
            .map_err(describe_ss_err)?
            .into_iter()
            .filter(|c| c.collection_path.as_str().ends_with("/login"))
            .collect();
        // Distinguish confirmed absence of the `default` alias (`Error::NoResult` when `ReadAlias("default")` == `"/"`)
        // from D-Bus errors so a broken alias query NEVER silently drops a collection!
        match service.get_default_collection().await {
            Ok(def) => {
                if !cols
                    .iter()
                    .any(|c| c.collection_path == def.collection_path)
                {
                    cols.push(def);
                }
            }
            Err(secret_service::Error::NoResult) => {}
            Err(err) => return Err(describe_ss_err(err)),
        }
        if cols.is_empty() {
            return Err(CliError::env_not_ready(
                "keyring_no_collection",
                "No persistent login/default Secret Service collection exists.",
            ));
        }
        Ok(cols)
    }

    /// Pure read-only inspection of a Secret Service collection: checks `.is_locked().await`
    /// and NEVER calls `.unlock().await`, preserving zero keyring-state mutation or prompt side effects!
    async fn inspect_collection_readonly(col: &Collection<'_>) -> CliResult<Option<Vec<u8>>> {
        if col.is_locked().await.map_err(describe_ss_err)? {
            return Err(describe_ss_err(secret_service::Error::Locked));
        }
        let items = col
            .search_items(keyring_attributes())
            .await
            .map_err(describe_ss_err)?;
        if items.len() > 1 {
            return Err(CliError::data(
                "Multiple Antigravity credentials exist in one Linux keyring collection.",
            ));
        }
        if let Some(item) = items.first() {
            if item.is_locked().await.map_err(describe_ss_err)? {
                return Err(describe_ss_err(secret_service::Error::Locked));
            }
            let sec = item.get_secret().await.map_err(describe_ss_err)?;
            Ok(Some(sec))
        } else {
            Ok(None)
        }
    }

    async fn snapshot_collection(col: &Collection<'_>) -> CliResult<Option<Vec<u8>>> {
        if col.is_locked().await.map_err(describe_ss_err)? {
            col.unlock().await.map_err(describe_ss_err)?;
        }
        let items = col
            .search_items(keyring_attributes())
            .await
            .map_err(describe_ss_err)?;
        if items.len() > 1 {
            return Err(CliError::data(
                "Multiple Antigravity credentials exist in one Linux keyring collection.",
            ));
        }
        if let Some(item) = items.first() {
            if item.is_locked().await.map_err(describe_ss_err)? {
                item.unlock().await.map_err(describe_ss_err)?;
            }
            let sec = item.get_secret().await.map_err(describe_ss_err)?;
            Ok(Some(sec))
        } else {
            Ok(None)
        }
    }

    async fn replace_collection(
        col: &Collection<'_>,
        payload: &[u8],
        gate: &MutationGate,
    ) -> Result<(), (CliError, bool)> {
        if col
            .is_locked()
            .await
            .map_err(|e| (describe_ss_err(e), false))?
        {
            col.unlock()
                .await
                .map_err(|e| (describe_ss_err(e), false))?;
        }
        gate.enter_mutation().map_err(|e| (e, true))?;
        let item = match col
            .create_item(
                "Password for 'antigravity' on 'gemini'",
                keyring_attributes(),
                payload,
                true,
                "text/plain",
            )
            .await
        {
            Ok(it) => it,
            Err(e) => {
                let uncertain = is_uncertain_dbus_transport_err(&e);
                return Err((describe_ss_err(e), uncertain));
            }
        };
        let readback = item
            .get_secret()
            .await
            .map_err(|e| (describe_ss_err(e), true))?;
        if readback != payload {
            return Err((
                CliError::io(
                    "keyring_readback_mismatch",
                    "Linux Secret Service readback did not match written payload.",
                ),
                true,
            ));
        }
        Ok(())
    }

    async fn clear_collection(
        col: &Collection<'_>,
        gate: &MutationGate,
    ) -> Result<(), (CliError, bool)> {
        if col
            .is_locked()
            .await
            .map_err(|e| (describe_ss_err(e), false))?
        {
            col.unlock()
                .await
                .map_err(|e| (describe_ss_err(e), false))?;
        }
        let items = col
            .search_items(keyring_attributes())
            .await
            .map_err(|e| (describe_ss_err(e), false))?;
        for item in items {
            gate.enter_mutation().map_err(|e| (e, true))?;
            if let Err(e) = item.delete().await {
                let uncertain = is_uncertain_dbus_transport_err(&e);
                return Err((describe_ss_err(e), uncertain));
            }
        }
        if snapshot_collection(col)
            .await
            .map_err(|e| (e, true))?
            .is_some()
        {
            return Err((
                CliError::io(
                    "keyring_clear_incomplete",
                    "Linux Secret Service item persisted after delete.",
                ),
                true,
            ));
        }
        Ok(())
    }

    async fn restore_collections_and_verify(
        cols: &[Collection<'_>],
        prev: &[Option<Vec<u8>>],
        upto_inclusive: usize,
        gate: &MutationGate,
    ) -> bool {
        let mut ok = true;
        for r_idx in (0..=upto_inclusive).rev() {
            if gate.is_timed_out() {
                return false;
            }
            if let Ok(cur) = snapshot_collection(&cols[r_idx]).await {
                if cur == prev[r_idx] {
                    continue;
                }
            }
            let res = match &prev[r_idx] {
                Some(old) => replace_collection(&cols[r_idx], old, gate).await,
                None => clear_collection(&cols[r_idx], gate).await,
            };
            if res.is_err() {
                ok = false;
                continue;
            }
            match snapshot_collection(&cols[r_idx]).await {
                Ok(actual) if actual == prev[r_idx] => {}
                _ => ok = false,
            }
        }
        ok
    }

    fn restore_file_and_verify(
        paths: &HeadlessPaths,
        prev_file: Option<&[u8]>,
        gate: &MutationGate,
    ) -> bool {
        if gate.is_timed_out() {
            return false;
        }
        let op_ok = match prev_file {
            Some(old) => {
                confirm_existing_slot_file_and_parent_durable(paths, old)
                    || write_atomic_durable(&paths.active_slot_file, old).is_ok()
            }
            None => FileSessionBackend.remove_slot(paths).is_ok(),
        };
        if !op_ok {
            return false;
        }
        match FileSessionBackend.snapshot_before_write(paths) {
            Ok(actual) => actual.as_deref() == prev_file,
            Err(_) => false,
        }
    }

    fn verify_live_collections_match_cas(
        cols: &[Collection<'_>],
        snaps: &[Option<Vec<u8>>],
        expected_cols: &[(String, ExpectedReplicaContent)],
    ) -> bool {
        if expected_cols.is_empty() || cols.len() != expected_cols.len() {
            return false;
        }
        let live_set: BTreeSet<&str> = cols.iter().map(|c| c.collection_path.as_str()).collect();
        let exp_set: BTreeSet<&str> = expected_cols.iter().map(|(p, _)| p.as_str()).collect();
        if live_set != exp_set {
            return false;
        }
        for (c, snap) in cols.iter().zip(snaps.iter()) {
            let Some((_, exp)) = expected_cols
                .iter()
                .find(|(p, _)| p == c.collection_path.as_str())
            else {
                return false;
            };
            if !exp.matches_bytes(snap.as_deref()) {
                return false;
            }
        }
        true
    }

    fn inspect_keyring_only(
        endpoint: Option<VerifiedDbusEndpoint>,
    ) -> (SlotInspectState, bool, Vec<KeyringCollectionDigest>) {
        match run_dbus_readonly(async move {
            let svc = connect_bound_secret_service(endpoint.as_ref(), KEYRING_TIMEOUT).await?;
            let cols = open_collections(&svc).await?;
            let mut found: Option<Vec<u8>> = None;
            let mut saw_none = false;
            let mut saw_conflict = false;
            let mut per_col = Vec::with_capacity(cols.len());
            for col in &cols {
                let path_str = col.collection_path.as_str().to_string();
                match inspect_collection_readonly(col).await? {
                    Some(sec) => {
                        let dig = bytes_sha256_hex(&sec);
                        let valid_rt_dig = parse_session_payload_bytes(&sec)
                            .ok()
                            .map(|p| p.refresh_token_digest);
                        if let Some(ref prev_sec) = found {
                            if prev_sec != &sec {
                                saw_conflict = true;
                            }
                        } else {
                            found = Some(sec);
                        }
                        per_col.push(KeyringCollectionDigest {
                            path: path_str,
                            present: true,
                            digest: Some(dig),
                            valid_refresh_token_digest: valid_rt_dig,
                        });
                    }
                    None => {
                        saw_none = true;
                        per_col.push(KeyringCollectionDigest {
                            path: path_str,
                            present: false,
                            digest: None,
                            valid_refresh_token_digest: None,
                        });
                    }
                }
            }
            let uniform = !saw_conflict && (found.is_none() || !saw_none);
            Ok((found, saw_conflict, uniform, per_col))
        }) {
            Ok((_, true, _, per_col)) => (
                SlotInspectState::Corrupt(
                    "Conflicting Antigravity credentials exist across Linux keyring collections."
                        .into(),
                ),
                false,
                per_col,
            ),
            Ok((Some(bytes), false, uniform, per_col)) => match parse_session_payload_bytes(&bytes)
            {
                Ok(parsed) => (SlotInspectState::Present(parsed), uniform, per_col),
                Err(reason) => (SlotInspectState::Corrupt(reason), false, per_col),
            },
            Ok((None, false, _, per_col)) => {
                (SlotInspectState::AbsentInInitializedDir, true, per_col)
            }
            Err(e) if e.error_code == "data_error" => {
                (SlotInspectState::Corrupt(e.message), false, Vec::new())
            }
            Err(e) => (SlotInspectState::Unverified(e.message), false, Vec::new()),
        }
    }

    impl CredentialBackend for SecretServiceSessionBackend {
        fn name(&self) -> &'static str {
            if self.include_file {
                "dual"
            } else {
                "keyring"
            }
        }

        fn uses_keyring(&self) -> bool {
            true
        }

        fn uses_file(&self) -> bool {
            self.include_file
        }

        fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
            let (kr_state, _, _) = inspect_keyring_only(self.endpoint.clone());
            if !self.include_file {
                return kr_state;
            }
            match kr_state {
                SlotInspectState::AbsentInInitializedDir | SlotInspectState::Uninitialized => {
                    FileSessionBackend.inspect_slot(paths)
                }
                other => other,
            }
        }

        fn inspect_replicas(&self, paths: &HeadlessPaths) -> BackendReplicaInspection {
            let (kr_state, uniform, per_col) = inspect_keyring_only(self.endpoint.clone());
            let file_state = if self.include_file {
                FileSessionBackend.inspect_slot(paths)
            } else {
                SlotInspectState::AbsentInInitializedDir
            };
            BackendReplicaInspection {
                backend_name: self.name(),
                uses_keyring: true,
                uses_file: self.include_file,
                keyring: Some(kr_state),
                keyring_all_collections_uniform: uniform,
                keyring_collections: per_col,
                file: file_state,
            }
        }

        fn snapshot_before_write(&self, paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>> {
            let snap = self.snapshot_replicas_before_write(paths)?;
            let kr = snap.keyring_bytes.flatten();
            if self.include_file {
                Ok(kr.or(snap.file_bytes))
            } else {
                Ok(kr)
            }
        }

        fn snapshot_replicas_before_write(
            &self,
            paths: &HeadlessPaths,
        ) -> CliResult<BackendPreWriteSnapshot> {
            let file_snap = if self.include_file {
                FileSessionBackend.snapshot_before_write(paths)?
            } else {
                None
            };
            let ep = self.endpoint.clone();
            let (kr_snap, uniform, kr_cols) = run_dbus_readonly(async move {
                let svc = connect_bound_secret_service(ep.as_ref(), KEYRING_TIMEOUT).await?;
                let cols = open_collections(&svc).await?;
                let mut found: Option<Vec<u8>> = None;
                let mut saw_none = false;
                let mut per_col = Vec::with_capacity(cols.len());
                for col in cols {
                    let path_str = col.collection_path.as_str().to_string();
                    match snapshot_collection(&col).await? {
                        Some(sec) => {
                            if let Some(ref prev_sec) = found {
                                if prev_sec != &sec {
                                    return Err(CliError::data(
                                        "Conflicting Antigravity credentials exist across Linux keyring collections; resolve duplicate entries before switching.",
                                    ));
                                }
                            } else {
                                found = Some(sec.clone());
                            }
                            per_col.push((path_str, Some(sec)));
                        }
                        None => {
                            saw_none = true;
                            per_col.push((path_str, None));
                        }
                    }
                }
                let uniform = found.is_none() || !saw_none;
                Ok((found, uniform, per_col))
            })?;
            Ok(BackendPreWriteSnapshot {
                backend_name: self.name(),
                uses_keyring: true,
                uses_file: self.include_file,
                keyring_bytes: Some(kr_snap),
                keyring_uniform: uniform,
                keyring_collections: kr_cols,
                file_bytes: file_snap,
            })
        }

        fn write_slot(&self, paths: &HeadlessPaths, payload: &str) -> CliResult<()> {
            self.write_slot_internal(paths, payload, None)
        }

        fn write_slot_cas(
            &self,
            paths: &HeadlessPaths,
            payload: &str,
            expected: &ReplicaCasExpectation,
        ) -> CliResult<()> {
            self.write_slot_internal(paths, payload, Some(expected))
        }

        fn rollback_replicas(
            &self,
            paths: &HeadlessPaths,
            prev: &BackendPreWriteSnapshot,
            target_digest: &str,
        ) -> CliResult<()> {
            check_fault_injection("slot_rollback", &paths.active_slot_file)?;
            let include_file = self.include_file;
            let prev_kr_bytes = prev.keyring_bytes.clone().flatten();
            let prev_kr_uniform = prev.keyring_uniform;
            let prev_kr_cols = prev.keyring_collections.clone();
            let prev_file_bytes = prev.file_bytes.clone();
            let prev_file_digest = prev_file_bytes.as_deref().map(bytes_sha256_hex);
            let target_owned = target_digest.to_string();
            let paths_owned = paths.clone();
            let ep = self.endpoint.clone();

            run_dbus_mutating(move |gate| {
                Box::pin(async move {
                    let svc = connect_bound_secret_service(ep.as_ref(), KEYRING_TIMEOUT).await?;
                    let cols = open_collections(&svc).await?;

                    // Require exact collection ID set match against pre-switch snapshot!
                    let live_col_set: BTreeSet<&str> =
                        cols.iter().map(|c| c.collection_path.as_str()).collect();
                    let exp_col_set: BTreeSet<&str> =
                        prev_kr_cols.iter().map(|(p, _)| p.as_str()).collect();
                    if !exp_col_set.is_empty() && live_col_set != exp_col_set {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Linux keyring collection set changed during rollback; switch journal preserved.",
                        ));
                    }

                    let mut cur_kr: Option<Vec<u8>> = None;
                    let mut kr_conflict = false;
                    let mut kr_saw_none = false;
                    let mut cur_per_col = Vec::with_capacity(cols.len());
                    let mut any_col_has_external = false;
                    for c in &cols {
                        let col_path = c.collection_path.as_str();
                        // Strictly use THIS collection's recorded pre-switch digest (explicit absence
                        // `None` MUST NEVER borrow another collection's digest!).
                        let prev_col_dig = prev_kr_cols
                            .iter()
                            .find(|(p, _)| p == col_path)
                            .and_then(|(_, o)| o.as_deref())
                            .map(bytes_sha256_hex);
                        match snapshot_collection(c).await? {
                            Some(sec) => {
                                let d = bytes_sha256_hex(&sec);
                                if Some(d.as_str()) != prev_col_dig.as_deref()
                                    && d != target_owned
                                    && parse_session_payload_bytes(&sec).is_ok()
                                {
                                    any_col_has_external = true;
                                }
                                if let Some(ref existing) = cur_kr {
                                    if existing != &sec {
                                        kr_conflict = true;
                                    }
                                } else {
                                    cur_kr = Some(sec.clone());
                                }
                                cur_per_col.push(Some(sec));
                            }
                            None => {
                                kr_saw_none = true;
                                cur_per_col.push(None);
                            }
                        }
                    }
                    let cur_kr_uniform = !kr_conflict && (cur_kr.is_none() || !kr_saw_none);
                    let cur_kr_digest = cur_kr.as_deref().map(bytes_sha256_hex);

                    let kr_is_external_valid = any_col_has_external && cur_kr_uniform;

                    if !include_file {
                        if kr_is_external_valid {
                            return Ok(());
                        }
                        if any_col_has_external {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "External credential modification left Linux keyring collections out of sync during rollback.",
                            ));
                        }
                    } else {
                        let cur_file_opt = FileSessionBackend
                            .snapshot_before_write(&paths_owned)
                            .ok()
                            .flatten();
                        let cur_file_digest = cur_file_opt.as_deref().map(bytes_sha256_hex);
                        let file_is_external_valid = cur_file_opt.as_deref().is_some_and(|b| {
                            let d = bytes_sha256_hex(b);
                            Some(d.as_str()) != prev_file_digest.as_deref()
                                && d != target_owned
                                && parse_session_payload_bytes(b).is_ok()
                        });

                        if any_col_has_external || file_is_external_valid {
                            if kr_is_external_valid
                                && cur_kr_digest.is_some()
                                && cur_kr_digest == cur_file_digest
                            {
                                return Ok(());
                            }
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "External credential modification left keyring and file replicas out of sync during rollback.",
                            ));
                        }
                    }

                    let expected_for_col = |col_path: &str| -> Option<&[u8]> {
                        if let Some((_, opt)) = prev_kr_cols.iter().find(|(p, _)| p == col_path) {
                            opt.as_deref()
                        } else if prev_kr_uniform {
                            prev_kr_bytes.as_deref()
                        } else {
                            None
                        }
                    };

                    for (idx, c) in cols.iter().enumerate() {
                        let exp = expected_for_col(c.collection_path.as_str());
                        if cur_per_col[idx].as_deref() != exp {
                            let step_res = match exp {
                                Some(old) => replace_collection(c, old, &gate).await,
                                None => clear_collection(c, &gate).await,
                            };
                            if let Err((e, _)) = step_res {
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    format!(
                                        "Failed to restore Linux keyring collection during rollback ({}).",
                                        e.message
                                    ),
                                ));
                            }
                        }
                    }

                    if include_file {
                        gate.enter_mutation()?;
                        if !restore_file_and_verify(&paths_owned, prev_file_bytes.as_deref(), &gate)
                        {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Failed to restore and durably sync local credential file replica during rollback.",
                            ));
                        }
                    }

                    for c in &cols {
                        let exp = expected_for_col(c.collection_path.as_str());
                        let actual = snapshot_collection(c).await?;
                        if actual.as_deref() != exp {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Post-rollback keyring verification did not match pre-switch snapshot.",
                            ));
                        }
                    }
                    Ok(())
                })
            })
        }

        fn remove_slot(&self, paths: &HeadlessPaths) -> CliResult<()> {
            self.remove_slot_internal(paths, None, false)
        }

        fn remove_slot_cas(
            &self,
            paths: &HeadlessPaths,
            expected: &ReplicaCasExpectation,
        ) -> CliResult<()> {
            self.remove_slot_internal(paths, Some(expected), false)
        }

        fn remove_slot_transactional(
            &self,
            paths: &HeadlessPaths,
            prev: &BackendPreWriteSnapshot,
        ) -> CliResult<()> {
            let cas = ReplicaCasExpectation::from_pre_write_snapshot(prev);
            self.remove_slot_internal(paths, Some(&cas), true)
        }

        fn read_raw_keyring_secret(&self) -> CliResult<Option<Vec<u8>>> {
            let ep = self.endpoint.clone();
            run_dbus_readonly(async move {
                let svc = connect_bound_secret_service(ep.as_ref(), KEYRING_TIMEOUT).await?;
                let mut found: Option<Vec<u8>> = None;
                for col in open_collections(&svc).await? {
                    if let Some(sec) = snapshot_collection(&col).await? {
                        if let Some(ref prev_sec) = found {
                            if prev_sec != &sec {
                                return Err(CliError::data(
                                    "Conflicting Antigravity credentials exist across Linux keyring collections.",
                                ));
                            }
                        } else {
                            found = Some(sec);
                        }
                    }
                }
                Ok(found)
            })
        }

        fn read_raw_keyring_secret_by_digest(
            &self,
            target_digest: &str,
        ) -> CliResult<Option<Vec<u8>>> {
            let ep = self.endpoint.clone();
            let wanted = target_digest.to_string();
            run_dbus_readonly(async move {
                let svc = connect_bound_secret_service(ep.as_ref(), KEYRING_TIMEOUT).await?;
                for col in open_collections(&svc).await? {
                    if let Some(sec) = snapshot_collection(&col).await? {
                        if bytes_sha256_hex(&sec) == wanted {
                            return Ok(Some(sec));
                        }
                    }
                }
                Ok(None)
            })
        }

        fn keyring_only_view(&self) -> Option<Box<dyn CredentialBackend>> {
            Some(Box::new(Self::keyring_only_with_endpoint(
                self.endpoint.clone(),
            )))
        }
    }

    impl SecretServiceSessionBackend {
        fn write_slot_internal(
            &self,
            paths: &HeadlessPaths,
            payload: &str,
            cas: Option<&ReplicaCasExpectation>,
        ) -> CliResult<()> {
            let include_file = self.include_file;
            // In `dual` mode, snapshot & validate local file slot FIRST before mutating keyring!
            // In `keyring` mode, NEVER read, create, modify, or require `~/.gemini/antigravity-cli/antigravity-oauth-token`!
            let prev_file = if include_file {
                FileSessionBackend.snapshot_before_write(paths)?
            } else {
                None
            };
            if let Some(exp) = cas {
                if include_file {
                    let Some(ref exp_file) = exp.file_expected else {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Missing file CAS expectation for dual-backend slot write.",
                        ));
                    };
                    if !exp_file.matches_bytes(prev_file.as_deref()) {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Active credential file changed concurrently before CAS write; journal preserved.",
                        ));
                    }
                }
            }

            let cas_owned = cas.cloned();
            let payload_vec = payload.as_bytes().to_vec();
            let paths_owned = paths.clone();
            let payload_str = payload.to_string();
            let ep = self.endpoint.clone();

            run_dbus_mutating(move |gate| {
                Box::pin(async move {
                    let svc = connect_bound_secret_service(ep.as_ref(), KEYRING_TIMEOUT).await?;
                    let cols = open_collections(&svc).await?;
                    let mut prev = Vec::with_capacity(cols.len());
                    for c in &cols {
                        prev.push(snapshot_collection(c).await?);
                    }

                    if let Some(ref exp) = cas_owned {
                        let Some(ref exp_cols) = exp.keyring_expected_collections else {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Missing keyring collection CAS expectation for slot write.",
                            ));
                        };
                        if !verify_live_collections_match_cas(&cols, &prev, exp_cols) {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Linux keyring collection set or content changed concurrently before CAS write; journal preserved.",
                            ));
                        }
                    }

                    for (idx, c) in cols.iter().enumerate() {
                        if let Err((write_err, uncertain)) =
                            replace_collection(c, &payload_vec, &gate).await
                        {
                            if uncertain || gate.is_timed_out() {
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    format!(
                                        "{} Linux Secret Service write outcome was uncertain; switch journal preserved.",
                                        write_err.message
                                    ),
                                ));
                            }
                            let kr_ok =
                                restore_collections_and_verify(&cols, &prev, idx, &gate).await;
                            if !kr_ok {
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    format!(
                                        "{} Linux keyring rollback was incomplete; switch journal preserved.",
                                        write_err.message
                                    ),
                                ));
                            }
                            return Err(write_err);
                        }
                    }

                    if include_file {
                        gate.enter_mutation()?;
                        if let Some(ref exp) = cas_owned {
                            let cur_file = FileSessionBackend.snapshot_before_write(&paths_owned);
                            let file_still_matches = matches!(
                                (&exp.file_expected, &cur_file),
                                (Some(exp_f), Ok(actual)) if exp_f.matches_bytes(actual.as_deref())
                            );
                            if !file_still_matches {
                                let kr_rb_ok = restore_collections_and_verify(
                                    &cols,
                                    &prev,
                                    cols.len().saturating_sub(1),
                                    &gate,
                                )
                                .await;
                                let _ = kr_rb_ok;
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    "Active credential file changed concurrently during CAS dual-write; journal preserved without overwriting disk.",
                                ));
                            }
                        }

                        // Re-verify gate immediately before synchronous disk write so a late worker
                        // can never initiate a file write after caller timeout!
                        gate.enter_mutation()?;
                        if let Err(file_err) =
                            FileSessionBackend.write_slot(&paths_owned, &payload_str)
                        {
                            let file_rb_ok =
                                restore_file_and_verify(&paths_owned, prev_file.as_deref(), &gate);
                            let kr_rb_ok = restore_collections_and_verify(
                                &cols,
                                &prev,
                                cols.len().saturating_sub(1),
                                &gate,
                            )
                            .await;
                            if !file_rb_ok || !kr_rb_ok {
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    format!(
                                        "{} Dual-write rollback across keyring and disk slot was incomplete; switch journal preserved.",
                                        file_err.message
                                    ),
                                ));
                            }
                            return Err(file_err);
                        }
                    }
                    Ok(())
                })
            })
        }

        fn remove_slot_internal(
            &self,
            paths: &HeadlessPaths,
            cas: Option<&ReplicaCasExpectation>,
            transactional_rollback: bool,
        ) -> CliResult<()> {
            let include_file = self.include_file;
            let prev_file = if include_file {
                read_regular_file_opt_bounded(
                    &paths.active_slot_file,
                    MAX_STORE_FILE_BYTES,
                    "Active session file",
                )?
            } else {
                None
            };
            if let Some(exp) = cas {
                if include_file {
                    let Some(ref exp_file) = exp.file_expected else {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Missing file CAS expectation for dual-backend slot removal.",
                        ));
                    };
                    if !exp_file.matches_bytes(prev_file.as_deref()) {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Active credential file changed concurrently before CAS removal; journal preserved.",
                        ));
                    }
                }
            }

            let cas_owned = cas.cloned();
            let paths_owned = paths.clone();
            let ep = self.endpoint.clone();

            run_dbus_mutating(move |gate| {
                Box::pin(async move {
                    let svc = connect_bound_secret_service(ep.as_ref(), KEYRING_TIMEOUT).await?;
                    let cols = open_collections(&svc).await?;
                    let mut prev_per_col = Vec::with_capacity(cols.len());
                    for c in &cols {
                        prev_per_col.push(snapshot_collection(c).await?);
                    }

                    if let Some(ref exp) = cas_owned {
                        let Some(ref exp_cols) = exp.keyring_expected_collections else {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Missing keyring collection CAS expectation for slot removal.",
                            ));
                        };
                        if !verify_live_collections_match_cas(&cols, &prev_per_col, exp_cols) {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Linux keyring collection set or content changed concurrently before CAS slot clear; switch journal preserved.",
                            ));
                        }
                    }

                    let mut cleared_any_col = false;
                    for (idx, c) in cols.iter().enumerate() {
                        if let Err((clear_err, uncertain)) = clear_collection(c, &gate).await {
                            if uncertain || gate.is_timed_out() {
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    format!(
                                        "{} Linux Secret Service delete outcome was uncertain; switch journal preserved.",
                                        clear_err.message
                                    ),
                                ));
                            }
                            if transactional_rollback {
                                let rb_ok = restore_collections_and_verify(
                                    &cols,
                                    &prev_per_col,
                                    idx,
                                    &gate,
                                )
                                .await;
                                if !rb_ok {
                                    return Err(CliError::partial_commit(
                                        "recovery_incomplete",
                                        format!(
                                            "{} Multi-collection keyring clear rollback was incomplete; switch journal preserved.",
                                            clear_err.message
                                        ),
                                    ));
                                }
                                return Err(clear_err);
                            } else if cleared_any_col {
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    format!(
                                        "{} Linux Secret Service multi-collection delete was incomplete; switch journal preserved.",
                                        clear_err.message
                                    ),
                                ));
                            }
                            return Err(clear_err);
                        }
                        cleared_any_col = true;
                    }

                    if include_file {
                        gate.enter_mutation()?;
                        if let Some(ref exp) = cas_owned {
                            let cur_file = read_regular_file_opt_bounded(
                                &paths_owned.active_slot_file,
                                MAX_STORE_FILE_BYTES,
                                "Active session file",
                            );
                            let file_still_matches = matches!(
                                (&exp.file_expected, &cur_file),
                                (Some(exp_f), Ok(actual)) if exp_f.matches_bytes(actual.as_deref())
                            );
                            if !file_still_matches {
                                if transactional_rollback {
                                    let _ = restore_collections_and_verify(
                                        &cols,
                                        &prev_per_col,
                                        cols.len().saturating_sub(1),
                                        &gate,
                                    )
                                    .await;
                                }
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    "Active credential file changed concurrently during CAS slot clear; switch journal preserved.",
                                ));
                            }
                        }

                        // Re-verify gate immediately before synchronous disk unlink so a late worker
                        // can never delete the local file after caller timeout!
                        gate.enter_mutation()?;
                        if let Err(file_err) = FileSessionBackend.remove_slot(&paths_owned) {
                            if transactional_rollback {
                                let file_rb_ok = restore_file_and_verify(
                                    &paths_owned,
                                    prev_file.as_deref(),
                                    &gate,
                                );
                                let kr_rb_ok = restore_collections_and_verify(
                                    &cols,
                                    &prev_per_col,
                                    cols.len().saturating_sub(1),
                                    &gate,
                                )
                                .await;
                                if !file_rb_ok || !kr_rb_ok {
                                    return Err(CliError::partial_commit(
                                        "recovery_incomplete",
                                        format!(
                                            "{} Dual-backend slot clear rollback was incomplete; switch journal preserved.",
                                            file_err.message
                                        ),
                                    ));
                                }
                                return Err(file_err);
                            }
                            if cleared_any_col {
                                return Err(CliError::partial_commit(
                                    "recovery_incomplete",
                                    format!(
                                        "{} Keyring collections were cleared before local file removal failed; switch journal preserved.",
                                        file_err.message
                                    ),
                                ));
                            }
                            return Err(file_err);
                        }
                    }

                    Ok(())
                })
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbus_address_parser_accepts_only_canonical_verified_local_unix_sockets_and_detects_parent_swap(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let bus_dir = tmp.path().join("busdir");
        fs::create_dir_all(&bus_dir).unwrap();
        let sock_path = bus_dir.join("session.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        let valid_addr = format!(
            "unix:path={},guid=0123456789abcdef0123456789abcdef",
            sock_path.display()
        );
        assert_eq!(
            parse_verified_unix_socket_from_dbus_address(&valid_addr).as_deref(),
            Some(sock_path.as_path())
        );

        // Reject TCP, unixexec, ibus, abstract sockets, /dev/null, non-canonical `..`/`.`/`//`/trailing `/`, regular files, and symlinks
        let dotdot_addr = format!("unix:path={}/../busdir/session.sock", bus_dir.display());
        let curdir_addr = format!("unix:path={}/./session.sock", bus_dir.display());
        let dblslash_addr = format!("unix:path={}///session.sock", bus_dir.display());
        let trailing_addr = format!("unix:path={}/", sock_path.display());
        for rejected in [
            "",
            "tcp:host=127.0.0.1,port=12345",
            "nonce-tcp:host=127.0.0.1,port=12345",
            "unixexec:path=/bin/sh",
            "ibus:",
            "unix:abstract=/tmp/dbus-abc",
            "unix:tmpdir=/tmp",
            "unix:path=/dev/null",
            "unix:path=relative/bus.sock",
            dotdot_addr.as_str(),
            curdir_addr.as_str(),
            dblslash_addr.as_str(),
            trailing_addr.as_str(),
        ] {
            assert_eq!(
                parse_verified_unix_socket_from_dbus_address(rejected),
                None,
                "Expected {rejected:?} to be rejected"
            );
        }

        let reg_file = tmp.path().join("not_a_socket");
        fs::write(&reg_file, b"plain").unwrap();
        assert_eq!(
            parse_verified_unix_socket_from_dbus_address(&format!(
                "unix:path={}",
                reg_file.display()
            )),
            None
        );

        let sym_sock = tmp.path().join("sym.sock");
        std::os::unix::fs::symlink(&sock_path, &sym_sock).unwrap();
        assert_eq!(
            parse_verified_unix_socket_from_dbus_address(&format!(
                "unix:path={}",
                sym_sock.display()
            )),
            None
        );

        // Verify `VerifiedDbusEndpoint` detects parent directory replacement even when a new listener
        // owned by the same UID is bound at the identical string path!
        let (_, _, _, pinned_ep) = verify_and_pin_socket_endpoint(&sock_path).unwrap();
        let moved_dir = tmp.path().join("busdir.old");
        fs::rename(&bus_dir, &moved_dir).unwrap();
        fs::create_dir_all(&bus_dir).unwrap();
        let _listener2 = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let (_, _, _, new_ep) = verify_and_pin_socket_endpoint(&sock_path).unwrap();
        assert_ne!(
            pinned_ep, new_ep,
            "Parent directory swap MUST change VerifiedDbusEndpoint identity!"
        );

        #[cfg(feature = "secret-service-backend")]
        {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let Err(err) = rt.block_on(keyring_impl::connect_bound_secret_service(
                Some(&pinned_ep),
                Duration::from_millis(200),
            )) else {
                panic!("expected parent-swap connection rejection");
            };
            assert_eq!(err.error_code, "secret_service_unavailable");
            assert!(
                err.message.contains("changed"),
                "Unexpected error: {}",
                err.message
            );
        }
    }

    #[test]
    fn backend_choice_requires_exact_four_literals_and_rejects_whitespace_case_and_empty() {
        assert_eq!(
            validate_backend_choice(None, None).unwrap(),
            BackendChoice::Auto
        );
        assert_eq!(
            validate_backend_choice(Some("auto"), None).unwrap(),
            BackendChoice::Auto
        );
        assert_eq!(
            validate_backend_choice(Some("file"), None).unwrap(),
            BackendChoice::File
        );
        #[cfg(feature = "secret-service-backend")]
        {
            assert_eq!(
                validate_backend_choice(Some("dual"), None).unwrap(),
                BackendChoice::Dual
            );
            assert_eq!(
                validate_backend_choice(Some("keyring"), None).unwrap(),
                BackendChoice::Keyring
            );
        }
        for invalid in [
            "",
            " ",
            " file",
            "file ",
            " FILE ",
            "FILE",
            "AUTO",
            "DUAL",
            "KEYRING",
            "secret-service",
            "secret_service",
        ] {
            assert!(
                validate_backend_choice(Some(invalid), None).is_err(),
                "CLI backend `{invalid}` must be rejected"
            );
            assert!(
                validate_backend_choice(None, Some(invalid)).is_err(),
                "Config backend `{invalid}` must be rejected"
            );
        }
    }

    #[cfg(feature = "secret-service-backend")]
    #[test]
    fn r3_03_mutation_gate_enforces_cancellation_exclusion_and_prevents_late_mutations() {
        let gate = keyring_impl::MutationGate::new();
        assert_eq!(
            gate.cancel_on_timeout(),
            keyring_impl::GatePhase::CancelledBeforeMutation
        );
        // Once timed out before mutation, `enter_mutation` MUST fail closed (`7`)!
        let err = gate.enter_mutation().unwrap_err();
        assert_eq!(
            err.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );
        assert!(gate.is_timed_out());

        // If mutation was already entered before timeout, timeout transitions to `TimedOutUncertain`!
        let gate2 = keyring_impl::MutationGate::new();
        gate2.enter_mutation().unwrap();
        assert_eq!(
            gate2.cancel_on_timeout(),
            keyring_impl::GatePhase::TimedOutUncertain
        );
        assert!(gate2.enter_mutation().is_err());

        // Verify `connect_bound_secret_service` connects strictly through `/proc/self/fd/<sock_opath_fd>`
        // even when the full canonical socket path exceeds Linux's 108-byte `sun_path` limit!
        if Path::new("/proc/self/fd").is_dir() {
            let tmp = tempfile::tempdir().unwrap();
            let short_dir = tmp.path().join("s");
            fs::create_dir_all(&short_dir).unwrap();
            let short_sock = short_dir.join("bus.sock");
            let listener = std::os::unix::net::UnixListener::bind(&short_sock).unwrap();
            let deep_parent = tmp.path().join(
                "long_segment_aaaaaaaaaaaaaaaaaaaaaaaaaaaa/long_segment_bbbbbbbbbbbbbbbbbbbbbbbbbbbb/long_segment_cccccccccccccccccccccccccccc",
            );
            fs::create_dir_all(&deep_parent).unwrap();
            let moved_dir = deep_parent.join("busdir");
            fs::rename(&short_dir, &moved_dir).unwrap();
            let long_sock = moved_dir.join("bus.sock");
            assert!(
                long_sock.as_os_str().len() > 110,
                "Expected path > 110 bytes, got {}",
                long_sock.as_os_str().len()
            );

            let accept_thread = std::thread::spawn(move || {
                let _ = listener.accept();
            });
            let (_, _, _, pinned_ep) = verify_and_pin_socket_endpoint(&long_sock).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let conn_err = match rt.block_on(keyring_impl::connect_bound_secret_service(
                Some(&pinned_ep),
                Duration::from_millis(500),
            )) {
                Ok(_) => panic!("Expected D-Bus handshake failure on dummy Unix listener"),
                Err(e) => e,
            };
            let _ = accept_thread.join();
            // Reaching `D-Bus handshake failed` proves `UnixStream::connect("/proc/self/fd/<fd>")`,
            // post-connect inode verification, AND `peer_cred().uid()` all succeeded past 108-byte `sun_path`!
            assert!(
                conn_err.message.contains("D-Bus handshake failed"),
                "Expected post-connect D-Bus handshake error on >110B pinned socket, got: {}",
                conn_err.message
            );
        }

        // Verify live `run_dbus_mutating_with_bounds`:
        // (a) async stall BEFORE `enter_mutation` cancels cleanly within grace -> EnvNotReady (8);
        let pre_timeout_err = keyring_impl::run_dbus_mutating_with_bounds(
            Duration::from_millis(80),
            Duration::from_millis(200),
            |_gate| {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Ok(())
                })
            },
        )
        .unwrap_err();
        assert_eq!(
            pre_timeout_err.exit_code,
            crate::error::ExitCode::EnvironmentNotReady
        );

        // (b) async stall AFTER `enter_mutation` returns PartialCommitOrRecovery (7);
        let post_timeout_err = keyring_impl::run_dbus_mutating_with_bounds(
            Duration::from_millis(80),
            Duration::from_millis(200),
            |gate| {
                Box::pin(async move {
                    gate.enter_mutation()?;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Ok(())
                })
            },
        )
        .unwrap_err();
        assert_eq!(
            post_timeout_err.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );

        // (c) synchronous stall past timeout+grace keeps worker active -> returns 7, blocks
        //     overlapping mutations in-process (7), and prevents any late `enter_mutation()` once
        //     the stalled syscall finally returns!
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (late_enter_tx, late_enter_rx) = std::sync::mpsc::channel::<bool>();
        let stuck_err = keyring_impl::run_dbus_mutating_with_bounds(
            Duration::from_millis(60),
            Duration::from_millis(60),
            move |gate| {
                Box::pin(async move {
                    let _ = release_rx.recv_timeout(Duration::from_secs(5));
                    let allowed_late = gate.enter_mutation().is_ok();
                    let _ = late_enter_tx.send(allowed_late);
                    Ok(())
                })
            },
        )
        .unwrap_err();
        assert_eq!(
            stuck_err.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );

        let overlap_err = keyring_impl::run_dbus_mutating_with_bounds(
            Duration::from_millis(60),
            Duration::from_millis(60),
            |_gate| Box::pin(async { Ok(()) }),
        )
        .unwrap_err();
        assert_eq!(
            overlap_err.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );
        assert!(overlap_err.message.contains("has not terminated"));

        // Unblock the stalled worker and verify it refused the late mutation AND cleanly released `ACTIVE_MUTATION_WORKERS`!
        let _ = release_tx.send(());
        let allowed_late = late_enter_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker should report late gate check");
        assert!(
            !allowed_late,
            "Stalled worker MUST NEVER be permitted to enter mutation after caller timed out!"
        );
        // Wait briefly for `WorkerFinishGuard` drop so subsequent mutations work cleanly
        let mut recovered = false;
        for _ in 0..40 {
            if keyring_impl::run_dbus_mutating_with_bounds(
                Duration::from_millis(100),
                Duration::from_millis(100),
                |_gate| Box::pin(async { Ok(()) }),
            )
            .is_ok()
            {
                recovered = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(
            recovered,
            "ACTIVE_MUTATION_WORKERS should drop back to 0 once stalled worker exits"
        );
    }

    #[test]
    fn synthetic_a01_effective_slot_state_matches_backend_precedence_without_extra_io() {
        let sample = |tag: &str| {
            SlotInspectState::Present(ParsedSessionPayload {
                raw_digest: format!("raw-{tag}"),
                refresh_token_digest: format!("rt-{tag}"),
                expiry: Some("2026-11-20T00:00:00Z".into()),
                auth_method: Some("consumer".into()),
                email_hint: Some(format!("{tag}@example.com")),
            })
        };
        let make = |backend_name: &'static str,
                    uses_keyring: bool,
                    uses_file: bool,
                    keyring: Option<SlotInspectState>,
                    file: SlotInspectState| BackendReplicaInspection {
            backend_name,
            uses_keyring,
            uses_file,
            keyring,
            keyring_all_collections_uniform: true,
            keyring_collections: Vec::new(),
            file,
        };

        // 1. `file` backend always projects `file`.
        let file_rep = make("file", false, true, None, sample("file"));
        assert_eq!(
            file_rep.effective_slot_state().raw_digest(),
            Some("raw-file")
        );
        let file_uninit = make("file", false, true, None, SlotInspectState::Uninitialized);
        assert!(matches!(
            file_uninit.effective_slot_state(),
            SlotInspectState::Uninitialized
        ));

        // 2. `dual` backend prefers present/corrupt/unverified keyring over file,
        //    falling back to file ONLY when keyring is cleanly absent.
        let dual_kr_wins = make("dual", true, true, Some(sample("kr")), sample("file"));
        assert_eq!(
            dual_kr_wins.effective_slot_state().raw_digest(),
            Some("raw-kr")
        );

        for absent in [
            SlotInspectState::AbsentInInitializedDir,
            SlotInspectState::Uninitialized,
        ] {
            let dual_fallback = make("dual", true, true, Some(absent), sample("file"));
            assert_eq!(
                dual_fallback.effective_slot_state().raw_digest(),
                Some("raw-file")
            );
        }

        let dual_kr_corrupt = make(
            "dual",
            true,
            true,
            Some(SlotInspectState::Corrupt("kr-bad".into())),
            sample("file"),
        );
        assert!(matches!(
            dual_kr_corrupt.effective_slot_state(),
            SlotInspectState::Corrupt(m) if m == "kr-bad"
        ));

        let dual_kr_unverified = make(
            "dual",
            true,
            true,
            Some(SlotInspectState::Unverified("kr-locked".into())),
            sample("file"),
        );
        assert!(matches!(
            dual_kr_unverified.effective_slot_state(),
            SlotInspectState::Unverified(m) if m == "kr-locked"
        ));

        // Still exposes corrupt disk file directly for dual-replica error reporting even when keyring is Present.
        let dual_disk_corrupt = make(
            "dual",
            true,
            true,
            Some(sample("kr")),
            SlotInspectState::Corrupt("disk-bad".into()),
        );
        assert_eq!(
            dual_disk_corrupt.effective_slot_state().raw_digest(),
            Some("raw-kr")
        );
        assert!(matches!(
            dual_disk_corrupt.file,
            SlotInspectState::Corrupt(ref m) if m == "disk-bad"
        ));

        // 3. `keyring` backend NEVER falls back to file regardless of file state.
        let kr_present_corrupt_file = make(
            "keyring",
            true,
            false,
            Some(sample("kr-only")),
            SlotInspectState::Corrupt("disk-ignored".into()),
        );
        assert_eq!(
            kr_present_corrupt_file.effective_slot_state().raw_digest(),
            Some("raw-kr-only")
        );

        let kr_absent_corrupt_file = make(
            "keyring",
            true,
            false,
            Some(SlotInspectState::AbsentInInitializedDir),
            sample("file"),
        );
        assert!(matches!(
            kr_absent_corrupt_file.effective_slot_state(),
            SlotInspectState::AbsentInInitializedDir
        ));
    }
}
