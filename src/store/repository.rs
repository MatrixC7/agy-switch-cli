use crate::domain::account::{
    is_pending_superseded_by_account, next_account_auth_generation_for_pending,
    validate_account_id, AccountRecord, DisableReasonCode, PendingAuthFlow, PendingAuthRecord,
    StoreIndex, MAX_ARCHIVED_RT_DIGESTS, MAX_IN_MEMORY_RT_DIGESTS, MAX_PREVIOUS_RT_DIGESTS,
    STORE_SCHEMA_VERSION,
};
use crate::domain::config::HeadlessConfig;
use crate::domain::policy::SwitchPolicy;
use crate::domain::quota::QuotaObservation;
use crate::domain::token::{token_digest, TokenRecord};
use crate::error::{format_safe_json_error, CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::store::fs_atomic::{
    cleanup_orphan_temp_files, ensure_no_symlink_components_under, ensure_private_dir,
    map_io_error, read_regular_file_opt_bounded, write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use crate::store::locks::{
    try_acquire_pending_auth_lock_nonblocking, with_store_write_lock, StoreWriteGuard,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

/// Overflow archive for superseded `refresh_token` SHA-256 digests (`<data_dir>/state/token_lineage/<id>.json`, `0600`).
/// Keeps `accounts/<id>.json` compact (`<= 512` inline digests) while retaining up to `65,536` older lineage digests
/// and recording explicit `truncated = true` if retention capacity is ever exceeded so `--overwrite` fails closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenLineageArchive {
    pub schema_version: u32,
    pub account_id: String,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub digests: Vec<String>,
}

/// Monotonic store-wide authorization sequence state (`<data_dir>/state/auth_sequence.json`, `0600`).
/// Starts allocating at `>= 2` so legacy pre-upgrade records (`auth_seq == 0` / `auth_generation == 0`,
/// committed legacy epoch `1`) never collide with newly staged authorizations, independent of wall-clock `created_at`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthSequenceState {
    pub schema_version: u32,
    pub last_auth_seq: u64,
}

pub const MIN_ALLOCATED_AUTH_SEQ: u64 = 2;
pub const DEFAULT_STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct StoreSnapshot {
    pub index: StoreIndex,
    pub accounts: Vec<AccountRecord>,
}

impl StoreSnapshot {
    pub fn selected_account(&self) -> Option<&AccountRecord> {
        let id = self.index.selected_account_id.as_deref()?;
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn select<'a>(&'a self, selector: &str) -> CliResult<&'a AccountRecord> {
        select_from_slice(&self.accounts, selector)
    }
}

/// Strictly validate account selector morphology (`AccountId` or email address) BEFORE lookup.
/// Rejects raw OAuth refresh tokens (`1//...`), access tokens (`ya29....`), JWTs (`eyJ...`), URLs, etc.
pub fn is_valid_account_selector_syntax(selector: &str) -> bool {
    if validate_account_id(selector).is_ok() {
        return true;
    }
    if selector.is_empty() || selector.len() > 254 {
        return false;
    }
    if selector.bytes().any(|b| {
        b.is_ascii_control()
            || b.is_ascii_whitespace()
            || matches!(
                b,
                b'/' | b'\\' | b':' | b'?' | b'=' | b'&' | b'|' | b';' | b'\'' | b'"'
            )
    }) {
        return false;
    }
    let Some((local, domain)) = selector.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.contains('@')
}

/// Resolve an account by exact `AccountId` or case-insensitive `email`.
/// NEVER echoes the raw `selector` string in any error message so accidental secret paste cannot leak!
pub fn select_from_slice<'a>(
    accounts: &'a [AccountRecord],
    selector: &str,
) -> CliResult<&'a AccountRecord> {
    let trimmed = selector.trim();
    if trimmed.is_empty() {
        return Err(CliError::usage("Account selector cannot be empty."));
    }
    if !is_valid_account_selector_syntax(trimmed) {
        return Err(CliError::usage(
            "Invalid account selector format (expected an account ID or email address; never pass tokens or URLs as selectors).",
        ));
    }
    if let Some(exact_id) = accounts.iter().find(|a| a.id == trimmed) {
        return Ok(exact_id);
    }
    let mut email_matches = accounts
        .iter()
        .filter(|a| a.email.eq_ignore_ascii_case(trimmed));
    let Some(first) = email_matches.next() else {
        return Err(CliError::not_found(
            "No account matches the specified selector. Run `agy-switch-cli accounts list` to inspect saved accounts.",
        ));
    };
    if email_matches.next().is_some() {
        return Err(CliError::ambiguous(
            "Multiple accounts share that email address. Specify the exact account ID from `agy-switch-cli accounts list` instead.",
        ));
    }
    Ok(first)
}

#[derive(Debug, Clone)]
pub enum ImportUpsertOutcome {
    Imported(AccountRecord),
    Updated(AccountRecord),
    SkippedDuplicate(AccountRecord),
}

#[derive(Debug, Clone)]
pub struct StoreRepository {
    paths: HeadlessPaths,
    lock_timeout: Duration,
}

impl StoreRepository {
    pub fn new(paths: HeadlessPaths) -> Self {
        Self {
            paths,
            lock_timeout: DEFAULT_STORE_LOCK_TIMEOUT,
        }
    }

    pub fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    pub fn paths(&self) -> &HeadlessPaths {
        &self.paths
    }

    pub fn lock_timeout(&self) -> Duration {
        self.lock_timeout
    }

    /// Pure read-only lookup of a single `TokenLineageArchive` (`<data_dir>/state/token_lineage/<account_id>.json`).
    pub fn read_token_lineage_readonly(
        &self,
        account_id: &str,
    ) -> CliResult<Option<TokenLineageArchive>> {
        validate_account_id(account_id).map_err(CliError::data)?;
        let path = self.paths.token_lineage_file(account_id);
        ensure_no_symlink_components_under(&self.paths.data_dir, &path)?;
        let Some(bytes) =
            read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Token lineage file")?
        else {
            return Ok(None);
        };
        let archive: TokenLineageArchive = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::data(format_safe_json_error(
                &format!("Token lineage file '{}'", path.display()),
                &e,
            ))
        })?;
        if archive.schema_version != STORE_SCHEMA_VERSION {
            return Err(CliError::data(format!(
                "Unsupported token lineage schema_version {} in '{}'.",
                archive.schema_version,
                path.display()
            )));
        }
        if archive.account_id != account_id {
            return Err(CliError::data(format!(
                "Token lineage file ID mismatch: expected '{account_id}', found '{}'.",
                archive.account_id
            )));
        }
        Ok(Some(archive))
    }

    /// Pure read-only lookup of a single `PendingAuthRecord` rotation lineage file (`<data_dir>/state/pending_lineage/<pending_id>.json`).
    pub fn read_pending_lineage_readonly(
        &self,
        pending_id: &str,
    ) -> CliResult<Option<TokenLineageArchive>> {
        validate_account_id(pending_id).map_err(CliError::data)?;
        let path = self.paths.pending_lineage_file(pending_id);
        ensure_no_symlink_components_under(&self.paths.data_dir, &path)?;
        let Some(bytes) =
            read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Pending lineage file")?
        else {
            return Ok(None);
        };
        let archive: TokenLineageArchive = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::data(format_safe_json_error(
                &format!("Pending lineage file '{}'", path.display()),
                &e,
            ))
        })?;
        if archive.schema_version != STORE_SCHEMA_VERSION {
            return Err(CliError::data(format!(
                "Unsupported pending lineage schema_version {} in '{}'.",
                archive.schema_version,
                path.display()
            )));
        }
        if archive.account_id != pending_id {
            return Err(CliError::data(format!(
                "Pending lineage file ID mismatch: expected '{pending_id}', found '{}'.",
                archive.account_id
            )));
        }
        Ok(Some(archive))
    }

    /// Pure read-only validation of all `<data_dir>/state/token_lineage/*.json` and `<data_dir>/state/pending_lineage/*.json` files (used by `doctor`).
    pub fn validate_all_token_lineage_readonly(&self) -> CliResult<()> {
        for (dir, is_pending) in [
            (self.paths.token_lineage_dir(), false),
            (self.paths.pending_lineage_dir(), true),
        ] {
            ensure_no_symlink_components_under(&self.paths.data_dir, &dir)?;
            let entries = match fs::read_dir(&dir) {
                Ok(it) => it,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(map_io_error(
                        e,
                        &format!("Cannot inspect lineage directory '{}'", dir.display()),
                    ))
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name_str) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !name_str.ends_with(".json") || name_str.contains(".tmp.") {
                    continue;
                }
                let Some(id_part) = name_str.strip_suffix(".json") else {
                    continue;
                };
                validate_account_id(id_part).map_err(CliError::data)?;
                if is_pending {
                    let _ = self.read_pending_lineage_readonly(id_part)?;
                } else {
                    let _ = self.read_token_lineage_readonly(id_part)?;
                }
            }
        }
        Ok(())
    }

    /// Check `(is_superseded, is_lineage_truncated)` across BOTH inline `AccountRecord.previous_refresh_token_digests`
    /// and any overflow `<data_dir>/state/token_lineage/<id>.json` archive.
    pub fn check_account_superseded_rt_readonly(
        &self,
        acc: &AccountRecord,
        candidate_rt: &str,
    ) -> CliResult<(bool, bool)> {
        let trimmed = candidate_rt.trim();
        let in_mem_truncated = acc.previous_refresh_token_digests.len() >= MAX_IN_MEMORY_RT_DIGESTS;
        if trimmed.is_empty() {
            let arch_trunc = self
                .read_token_lineage_readonly(&acc.id)?
                .is_some_and(|a| a.truncated);
            return Ok((false, in_mem_truncated || arch_trunc));
        }
        if acc.has_superseded_refresh_token(trimmed) {
            return Ok((true, in_mem_truncated));
        }
        if let Some(archive) = self.read_token_lineage_readonly(&acc.id)? {
            let fp = token_digest(trimmed);
            let found = archive.digests.iter().any(|d| d == &fp);
            return Ok((found, in_mem_truncated || archive.truncated));
        }
        Ok((false, in_mem_truncated))
    }

    pub fn account_has_superseded_rt(
        &self,
        acc: &AccountRecord,
        candidate_rt: &str,
    ) -> CliResult<bool> {
        Ok(self
            .check_account_superseded_rt_readonly(acc, candidate_rt)?
            .0)
    }

    /// Pure read-only strict lookup of a single `PendingAuthRecord` (`<data_dir>/state/pending_auth/<id>.json`).
    pub fn read_pending_auth_opt_readonly(
        &self,
        pending_id: &str,
    ) -> CliResult<Option<PendingAuthRecord>> {
        validate_account_id(pending_id).map_err(CliError::data)?;
        let path = self.paths.pending_auth_file(pending_id);
        ensure_no_symlink_components_under(&self.paths.data_dir, &path)?;
        let Some(bytes) =
            read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Pending auth file")?
        else {
            return Ok(None);
        };
        let rec: PendingAuthRecord = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::data(format_safe_json_error(
                &format!("Pending auth file '{}'", path.display()),
                &e,
            ))
        })?;
        if rec.schema_version != STORE_SCHEMA_VERSION {
            return Err(CliError::data(format!(
                "Unsupported pending auth schema_version {} in '{}'.",
                rec.schema_version,
                path.display()
            )));
        }
        if rec.id != pending_id {
            return Err(CliError::data(format!(
                "Pending auth file ID mismatch: expected '{pending_id}', found '{}'.",
                rec.id
            )));
        }
        Ok(Some(rec))
    }

    /// Pure read-only snapshot: ZERO file/dir creation, ZERO repairs, ZERO network.
    pub fn read_snapshot(&self) -> CliResult<StoreSnapshot> {
        let index_path = self.paths.index_file();
        ensure_no_symlink_components_under(&self.paths.data_dir, &index_path)?;

        let Some(bytes) =
            read_regular_file_opt_bounded(&index_path, MAX_STORE_FILE_BYTES, "Store index")?
        else {
            if self.paths.data_dir.join("accounts.json").exists() {
                return Err(CliError::data(format!(
                    "Data directory '{}' contains a legacy desktop `accounts.json` without headless `index.json`. Run `agy-switch-cli accounts import --from-legacy \"{}\"` into an independent directory.",
                    self.paths.data_dir.display(),
                    self.paths.data_dir.display()
                )));
            }
            ensure_no_symlink_components_under(&self.paths.data_dir, &self.paths.accounts_dir())?;
            match fs::read_dir(self.paths.accounts_dir()) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Ok(mut entries) => {
                    if entries.any(|ent| {
                        ent.ok()
                            .and_then(|x| x.file_name().into_string().ok())
                            .is_some_and(|n| n.ends_with(".json") && !n.contains(".tmp."))
                    }) {
                        return Err(CliError::data(
                            "Account index `index.json` is missing while account files exist. Run `agy-switch-cli doctor --fix` to reconcile.",
                        ));
                    }
                }
                Err(e) => return Err(map_io_error(e, "Cannot inspect accounts directory")),
            }
            return Ok(StoreSnapshot {
                index: StoreIndex::new(0),
                accounts: Vec::new(),
            });
        };

        let index = parse_index_bytes(&bytes)?;
        let mut accounts = Vec::with_capacity(index.account_order.len());
        let mut seen = HashSet::with_capacity(index.account_order.len());

        for id in &index.account_order {
            validate_account_id(id).map_err(CliError::data)?;
            if !seen.insert(id.as_str()) {
                return Err(CliError::data(format!(
                    "Store index contains duplicate account ID '{id}'."
                )));
            }
            let acc = self.read_account_unchecked(id)?;
            accounts.push(acc);
        }

        if let Some(ref sel) = index.selected_account_id {
            validate_account_id(sel).map_err(CliError::data)?;
            if !seen.contains(sel.as_str()) {
                return Err(CliError::data(format!(
                    "Store index `selected_account_id` ('{sel}') does not exist in `account_order`. Run `agy-switch-cli doctor --fix`."
                )));
            }
        }

        Ok(StoreSnapshot { index, accounts })
    }

    pub fn read_account_unchecked(&self, id: &str) -> CliResult<AccountRecord> {
        validate_account_id(id).map_err(CliError::data)?;
        let path = self.paths.account_file(id);
        ensure_no_symlink_components_under(&self.paths.data_dir, &path)?;
        let Some(bytes) =
            read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Account file")?
        else {
            return Err(CliError::data(format!(
                "Indexed account file '{}' is missing.",
                path.display()
            )));
        };
        let acc: AccountRecord = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::data(format_safe_json_error(
                &format!("Account file '{}'", path.display()),
                &e,
            ))
        })?;
        if acc.schema_version != STORE_SCHEMA_VERSION {
            return Err(CliError::data(format!(
                "Unsupported account schema_version {} in '{}'.",
                acc.schema_version,
                path.display()
            )));
        }
        if acc.id != id {
            return Err(CliError::data(format!(
                "Account file ID mismatch: expected '{id}', found '{}'.",
                acc.id
            )));
        }
        Ok(acc)
    }

    /// Locate an existing account matching `refresh_token` (either current fingerprint OR superseded rotation history,
    /// including overflow `token_lineage` archives) without mutating disk state, allowing callers (`accounts add`)
    /// to acquire `L2` BEFORE `/token` network exchange!
    pub fn find_account_by_refresh_token_readonly(
        &self,
        refresh_token: &str,
    ) -> CliResult<Option<AccountRecord>> {
        let trimmed = refresh_token.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let fp = token_digest(trimmed);
        let snap = self.read_snapshot()?;
        for acc in snap.accounts {
            if acc.token.refresh_token_fingerprint() == fp
                || self.account_has_superseded_rt(&acc, trimmed)?
            {
                return Ok(Some(acc));
            }
        }
        Ok(None)
    }

    /// Locate an existing account ID matching import identity (`id`, `refresh_token` current/history, or `email+client`)
    /// so `accounts import` can acquire `L2` on that account before entering `L3`.
    pub fn find_matching_account_id_for_import_readonly(
        &self,
        candidate_id: Option<&str>,
        refresh_token: &str,
        email: &str,
        client_key: Option<&str>,
    ) -> CliResult<Option<String>> {
        let snap = self.read_snapshot()?;
        Ok(find_matching_account_in_slice(
            self,
            &snap.accounts,
            candidate_id,
            refresh_token,
            email,
            client_key,
        )?
        .map(|a| a.id.clone()))
    }

    /// Pure read-only policy fetch: returns `SwitchPolicy::default()` when `policy.json` is absent without creating files.
    pub fn read_policy(&self) -> CliResult<SwitchPolicy> {
        let path = self.paths.policy_file();
        ensure_no_symlink_components_under(&self.paths.data_dir, &path)?;
        let Some(bytes) =
            read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Policy file")?
        else {
            return Ok(SwitchPolicy::default());
        };
        let policy: SwitchPolicy = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::data(format_safe_json_error(
                &format!("Policy file '{}'", path.display()),
                &e,
            ))
        })?;
        if policy.schema_version != STORE_SCHEMA_VERSION {
            return Err(CliError::data(format!(
                "Unsupported policy schema_version {} in '{}'.",
                policy.schema_version,
                path.display()
            )));
        }
        policy.validate(None).map_err(CliError::data)?;
        Ok(policy)
    }

    /// Pure read-only strict lookup of monotonic `AuthSequenceState` (`<data_dir>/state/auth_sequence.json`).
    pub fn read_auth_sequence_readonly(&self) -> CliResult<Option<AuthSequenceState>> {
        let path = self.paths.auth_sequence_file();
        ensure_no_symlink_components_under(&self.paths.data_dir, &path)?;
        let Some(bytes) =
            read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Auth sequence file")?
        else {
            return Ok(None);
        };
        let state: AuthSequenceState = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::data(format_safe_json_error(
                &format!("Auth sequence file '{}'", path.display()),
                &e,
            ))
        })?;
        if state.schema_version != STORE_SCHEMA_VERSION {
            return Err(CliError::data(format!(
                "Unsupported auth sequence schema_version {} in '{}'.",
                state.schema_version,
                path.display()
            )));
        }
        Ok(Some(state))
    }

    /// Pure read-only strict listing of durable `PendingAuthRecord` files (`<data_dir>/state/pending_auth/*.json`).
    /// Used by `doctor` and `auth pending` to surface any corrupted, special, or schema-invalid file.
    pub fn list_pending_auth_readonly(&self) -> CliResult<Vec<PendingAuthRecord>> {
        let _ = self.read_auth_sequence_readonly()?;
        let dir = self.paths.pending_auth_dir();
        ensure_no_symlink_components_under(&self.paths.data_dir, &dir)?;
        let entries = match fs::read_dir(&dir) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Cannot inspect pending_auth directory '{}'", dir.display()),
                ))
            }
        };
        let mut records = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name_str) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name_str.ends_with(".json") || name_str.contains(".tmp.") {
                continue;
            }
            if let Some(bytes) =
                read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Pending auth file")?
            {
                let rec: PendingAuthRecord = serde_json::from_slice(&bytes).map_err(|e| {
                    CliError::data(format_safe_json_error(
                        &format!("Pending auth file '{}'", path.display()),
                        &e,
                    ))
                })?;
                if rec.schema_version != STORE_SCHEMA_VERSION {
                    return Err(CliError::data(format!(
                        "Unsupported pending auth schema_version {} in '{}'.",
                        rec.schema_version,
                        path.display()
                    )));
                }
                validate_account_id(&rec.id).map_err(CliError::data)?;
                let expected_name = format!("{}.json", rec.id);
                if name_str != expected_name {
                    return Err(CliError::data(format!(
                        "Pending auth file name '{}' does not match record ID '{}'.",
                        name_str, rec.id
                    )));
                }
                records.push(rec);
            }
        }
        records.sort_by(|a, b| {
            a.auth_seq
                .cmp(&b.auth_seq)
                .then_with(|| a.created_at.cmp(&b.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(records)
    }

    /// Best-effort read-only scan of valid `PendingAuthRecord` files used when checking whether a new
    /// `accounts add` input resumes an interrupted token exchange (so an unrelated corrupt file never bricks unrelated adds).
    pub fn list_valid_pending_auth_lossy(&self) -> Vec<PendingAuthRecord> {
        let dir = self.paths.pending_auth_dir();
        if ensure_no_symlink_components_under(&self.paths.data_dir, &dir).is_err() {
            return Vec::new();
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut records = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name_str) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name_str.ends_with(".json") || name_str.contains(".tmp.") {
                continue;
            }
            let Ok(Some(bytes)) =
                read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Pending auth file")
            else {
                continue;
            };
            let Ok(rec) = serde_json::from_slice::<PendingAuthRecord>(&bytes) else {
                continue;
            };
            if rec.schema_version == STORE_SCHEMA_VERSION
                && validate_account_id(&rec.id).is_ok()
                && name_str == format!("{}.json", rec.id)
            {
                records.push(rec);
            }
        }
        records.sort_by(|a, b| {
            a.auth_seq
                .cmp(&b.auth_seq)
                .then_with(|| a.created_at.cmp(&b.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        records
    }

    /// Best-effort read-only scan of valid `AccountRecord` files in `<data_dir>/accounts/*.json`
    /// to observe the highest committed `auth_generation` without failing `/token` staging if `index.json`
    /// or an unrelated account file is corrupt.
    pub fn max_valid_account_auth_generation_lossy(&self) -> CliResult<u64> {
        let dir = self.paths.accounts_dir();
        ensure_no_symlink_components_under(&self.paths.data_dir, &dir)?;
        let entries = match fs::read_dir(&dir) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Cannot inspect accounts directory '{}'", dir.display()),
                ))
            }
        };
        let mut max_gen = 0u64;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name_str) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name_str.ends_with(".json") || name_str.contains(".tmp.") {
                continue;
            }
            let Ok(Some(bytes)) =
                read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Account file")
            else {
                continue;
            };
            if let Ok(acc) = serde_json::from_slice::<AccountRecord>(&bytes) {
                max_gen = max_gen.max(acc.auth_generation);
            }
        }
        Ok(max_gen)
    }

    /// Pure read-only config fetch (`<data_dir>/config.json`): returns `HeadlessConfig::default()` when absent without creating files.
    pub fn read_config(&self) -> CliResult<HeadlessConfig> {
        let (cfg, _) = self.read_config_with_warnings()?;
        Ok(cfg)
    }

    pub fn read_config_with_warnings(&self) -> CliResult<(HeadlessConfig, Vec<String>)> {
        read_headless_config_readonly(&self.paths)
    }

    /// Execute a synchronous write transaction protected by L3 `StoreWriteLock`.
    /// Because L3 is scoped exclusively to synchronous `FnOnce(&StoreWriteTx<'_>)`, holding L3 across `.await` is impossible.
    pub fn with_write_lock<T>(
        &self,
        f: impl FnOnce(&StoreWriteTx<'_>) -> CliResult<T>,
    ) -> CliResult<T> {
        self.paths.ensure_not_legacy_store_dir()?;
        with_store_write_lock(&self.paths, self.lock_timeout, |guard| {
            ensure_private_dir(&self.paths.data_dir)?;
            ensure_private_dir(&self.paths.accounts_dir())?;
            ensure_private_dir(&self.paths.state_dir())?;
            ensure_private_dir(&self.paths.leases_dir())?;
            ensure_private_dir(&self.paths.pending_auth_dir())?;
            ensure_private_dir(&self.paths.store_locks_dir())?;
            ensure_no_symlink_components_under(
                &self.paths.data_dir,
                &self.paths.token_lineage_dir(),
            )?;
            ensure_no_symlink_components_under(
                &self.paths.data_dir,
                &self.paths.pending_lineage_dir(),
            )?;

            cleanup_orphan_temp_files(&self.paths.data_dir, Duration::from_secs(60));
            cleanup_orphan_temp_files(&self.paths.accounts_dir(), Duration::from_secs(60));
            cleanup_orphan_temp_files(&self.paths.state_dir(), Duration::from_secs(60));
            cleanup_orphan_temp_files(&self.paths.pending_auth_dir(), Duration::from_secs(60));
            if fs::symlink_metadata(self.paths.token_lineage_dir())
                .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
            {
                cleanup_orphan_temp_files(&self.paths.token_lineage_dir(), Duration::from_secs(60));
            }
            if fs::symlink_metadata(self.paths.pending_lineage_dir())
                .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
            {
                cleanup_orphan_temp_files(
                    &self.paths.pending_lineage_dir(),
                    Duration::from_secs(60),
                );
            }
            crate::session::process::cleanup_stale_leases_under_write_lock(&self.paths);

            let tx = StoreWriteTx {
                repo: self,
                _guard: guard,
            };
            f(&tx)
        })
    }
}

fn find_matching_account_in_slice<'a>(
    repo: &StoreRepository,
    accounts: &'a [AccountRecord],
    candidate_id: Option<&str>,
    refresh_token: &str,
    email: &str,
    client_key: Option<&str>,
) -> CliResult<Option<&'a AccountRecord>> {
    let rt_trimmed = refresh_token.trim();
    let email_trimmed = email.trim();
    for acc in accounts {
        let same_id = candidate_id.is_some_and(|cid| acc.id == cid);
        let same_rt = !rt_trimmed.is_empty()
            && (acc.token.refresh_token.trim() == rt_trimmed
                || repo.account_has_superseded_rt(acc, rt_trimmed)?);
        let same_email_and_compatible_client = !email_trimmed.is_empty()
            && acc.email.eq_ignore_ascii_case(email_trimmed)
            && (acc.token.oauth_client_key.as_deref() == client_key
                || acc.token.oauth_client_key.is_none()
                || client_key.is_none());
        if same_id || same_rt || same_email_and_compatible_client {
            return Ok(Some(acc));
        }
    }
    Ok(None)
}

pub struct StoreWriteTx<'a> {
    repo: &'a StoreRepository,
    _guard: &'a StoreWriteGuard<'a>,
}

impl<'a> StoreWriteTx<'a> {
    pub fn paths(&self) -> &HeadlessPaths {
        &self.repo.paths
    }

    pub fn load_index_or_init(&self, now_unix: i64) -> CliResult<StoreIndex> {
        let index_path = self.repo.paths.index_file();
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &index_path)?;
        match read_regular_file_opt_bounded(&index_path, MAX_STORE_FILE_BYTES, "Store index")? {
            Some(bytes) => parse_index_bytes(&bytes),
            None => Ok(StoreIndex::new(now_unix)),
        }
    }

    pub fn save_index(&self, index: &mut StoreIndex, now_unix: i64) -> CliResult<()> {
        index.schema_version = STORE_SCHEMA_VERSION;
        index.revision = index.revision.saturating_add(1);
        index.updated_at = now_unix;
        let bytes = serde_json::to_vec_pretty(index)
            .map_err(|_| CliError::data("Failed to serialize index.json."))?;
        write_atomic_durable(&self.repo.paths.index_file(), &bytes)
    }

    pub fn save_account(&self, account: &AccountRecord) -> CliResult<()> {
        validate_account_id(&account.id).map_err(CliError::data)?;
        if account.token.expiry_timestamp <= 0 {
            return Err(CliError::data(format!(
                "Invalid expiry_timestamp ({}) for account '{}': must be positive Unix seconds.",
                account.token.expiry_timestamp, account.id
            )));
        }

        if account.previous_refresh_token_digests.len() > MAX_PREVIOUS_RT_DIGESTS {
            let in_mem_hit_ceiling =
                account.previous_refresh_token_digests.len() >= MAX_IN_MEMORY_RT_DIGESTS;
            let mut compact = account.clone();
            let overflow_count =
                compact.previous_refresh_token_digests.len() - MAX_PREVIOUS_RT_DIGESTS;
            let spilled: Vec<String> = compact
                .previous_refresh_token_digests
                .drain(0..overflow_count)
                .collect();

            let mut archive = self
                .repo
                .read_token_lineage_readonly(&compact.id)?
                .unwrap_or_else(|| TokenLineageArchive {
                    schema_version: STORE_SCHEMA_VERSION,
                    account_id: compact.id.clone(),
                    truncated: false,
                    digests: Vec::new(),
                });
            archive.schema_version = STORE_SCHEMA_VERSION;
            archive.account_id = compact.id.clone();
            if in_mem_hit_ceiling {
                archive.truncated = true;
            }
            let current_fp = compact.token.refresh_token_fingerprint();
            for d in spilled {
                if d != current_fp {
                    archive.digests.retain(|existing| existing != &d);
                    archive.digests.push(d);
                }
            }
            archive.digests.retain(|existing| existing != &current_fp);
            if archive.digests.len() > MAX_ARCHIVED_RT_DIGESTS {
                let excess = archive.digests.len() - MAX_ARCHIVED_RT_DIGESTS;
                archive.digests.drain(0..excess);
                archive.truncated = true;
            }
            ensure_private_dir(&self.repo.paths.token_lineage_dir())?;
            let archive_bytes = serde_json::to_vec_pretty(&archive).map_err(|_| {
                CliError::data(format!(
                    "Failed to serialize token lineage archive for '{}'.",
                    compact.id
                ))
            })?;
            write_atomic_durable(
                &self.repo.paths.token_lineage_file(&compact.id),
                &archive_bytes,
            )?;

            let bytes = serde_json::to_vec_pretty(&compact).map_err(|_| {
                CliError::data(format!("Failed to serialize account '{}'.", compact.id))
            })?;
            return write_atomic_durable(&self.repo.paths.account_file(&compact.id), &bytes);
        }

        let bytes = serde_json::to_vec_pretty(account).map_err(|_| {
            CliError::data(format!("Failed to serialize account '{}'.", account.id))
        })?;
        write_atomic_durable(&self.repo.paths.account_file(&account.id), &bytes)
    }

    pub fn account_has_superseded_rt_in_tx(
        &self,
        acc: &AccountRecord,
        candidate_rt: &str,
    ) -> CliResult<(bool, bool)> {
        self.repo
            .check_account_superseded_rt_readonly(acc, candidate_rt)
    }

    pub fn load_account_opt(&self, id: &str) -> CliResult<Option<AccountRecord>> {
        validate_account_id(id).map_err(CliError::data)?;
        let path = self.repo.paths.account_file(id);
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &path)?;
        let Some(bytes) =
            read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Account file")?
        else {
            return Ok(None);
        };
        let acc: AccountRecord = serde_json::from_slice(&bytes).map_err(|e| {
            CliError::data(format_safe_json_error(
                &format!("Account file '{}'", path.display()),
                &e,
            ))
        })?;
        Ok(Some(acc))
    }

    pub fn load_pending_auth_opt(&self, pending_id: &str) -> CliResult<Option<PendingAuthRecord>> {
        self.repo.read_pending_auth_opt_readonly(pending_id)
    }

    pub fn write_auth_sequence_state(&self, last_auth_seq: u64) -> CliResult<()> {
        let target = self.repo.paths.auth_sequence_file();
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &target)?;
        ensure_private_dir(&self.repo.paths.state_dir())?;
        let state = AuthSequenceState {
            schema_version: STORE_SCHEMA_VERSION,
            last_auth_seq,
        };
        let bytes = serde_json::to_vec_pretty(&state)
            .map_err(|_| CliError::data("Failed to serialize auth_sequence.json."))?;
        write_atomic_durable(&target, &bytes)
    }

    pub fn current_max_auth_seq(&self) -> CliResult<u64> {
        let saved = self
            .repo
            .read_auth_sequence_readonly()?
            .map(|s| s.last_auth_seq)
            .unwrap_or(0);
        let mut max_seq = saved.max(self.repo.max_valid_account_auth_generation_lossy()?);
        for p in self.repo.list_valid_pending_auth_lossy() {
            max_seq = max_seq.max(p.auth_seq);
        }
        Ok(max_seq)
    }

    /// Allocate a strictly monotonic `auth_seq` (`>= 2`) inside `L3` and persist it durably to `state/auth_sequence.json`.
    pub fn allocate_next_auth_seq(&self) -> CliResult<u64> {
        let max_seen = self.current_max_auth_seq()?;
        let next = max_seen.saturating_add(1).max(MIN_ALLOCATED_AUTH_SEQ);
        self.write_auth_sequence_state(next)?;
        Ok(next)
    }

    pub fn ensure_auth_sequence_at_least(&self, min_seq: u64) -> CliResult<()> {
        if min_seq == 0 {
            return Ok(());
        }
        let saved = self
            .repo
            .read_auth_sequence_readonly()?
            .map(|s| s.last_auth_seq)
            .unwrap_or(0);
        if saved < min_seq {
            self.write_auth_sequence_state(min_seq)?;
        }
        Ok(())
    }

    /// Atomically verify inside `L3` whether `pending_id` (matching `expected_cas_fp`) is already superseded by
    /// `account_id`'s durable `auth_generation`. If superseded (`Ok(Some(latest_acc))`), absorbs all token digests
    /// and `pending_lineage` into `latest_acc` (leaving `latest_acc.token` and `latest_acc.auth_generation` untouched!),
    /// saves `latest_acc` FIRST, and ONLY THEN CAS-deletes `pending_id`.
    pub fn absorb_superseded_pending_into_account_cas(
        &self,
        pending_id: &str,
        expected_cas_fp: &str,
        account_id: &str,
        matching_input_digest: Option<&str>,
        extra_superseded_digests: &[String],
    ) -> CliResult<Option<AccountRecord>> {
        let live_p = self.verify_pending_auth_cas(pending_id, expected_cas_fp)?;
        let index = self.load_index_or_init(0)?;
        if !index.account_order.iter().any(|id| id == account_id) {
            return Err(CliError::not_found(format!(
                "Account '{account_id}' was removed before pending auth persistence."
            )));
        }
        let mut latest = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!("Account file for '{account_id}' is missing."))
        })?;
        if live_p.email_mismatch
            || !is_pending_superseded_by_account(live_p.auth_seq, latest.auth_generation)
        {
            return Ok(None);
        }
        if let Some(inp) = matching_input_digest {
            latest.record_superseded_digest(inp);
        }
        for d in extra_superseded_digests {
            latest.record_superseded_digest(d);
        }
        if let Some(ref inp) = live_p.input_rt_digest {
            latest.record_superseded_digest(inp);
        }
        if !live_p.token.refresh_token.trim().is_empty() {
            latest.record_superseded_digest(&token_digest(&live_p.token.refresh_token));
        }
        for d in self.load_pending_lineage_digests(pending_id)? {
            latest.record_superseded_digest(&d);
        }
        self.save_account(&latest)?;
        self.remove_pending_auth_cas(pending_id, expected_cas_fp)?;
        Ok(Some(latest))
    }

    /// Verify inside `L3` that `pending_id` still exists on disk and holds the exact `expected_cas_fp` snapshot.
    pub fn verify_pending_auth_cas(
        &self,
        pending_id: &str,
        expected_cas_fp: &str,
    ) -> CliResult<PendingAuthRecord> {
        let Some(live) = self.load_pending_auth_opt(pending_id)? else {
            return Err(CliError::conflict(
                "pending_auth_already_consumed",
                format!(
                    "Pending auth record '{pending_id}' was already bound or removed concurrently."
                ),
            ));
        };
        if live.cas_fingerprint() != expected_cas_fp {
            return Err(CliError::conflict(
                "pending_auth_version_conflict",
                format!(
                    "Pending auth record '{pending_id}' was rotated to a newer version concurrently; refusing stale bind or deletion."
                ),
            ));
        }
        Ok(live)
    }

    pub fn save_pending_auth(&self, pending: &PendingAuthRecord) -> CliResult<()> {
        validate_account_id(&pending.id).map_err(CliError::data)?;
        let target = self.repo.paths.pending_auth_file(&pending.id);
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &target)?;
        ensure_private_dir(&self.repo.paths.pending_auth_dir())?;
        let bytes = serde_json::to_vec_pretty(pending)
            .map_err(|_| CliError::data("Failed to serialize pending auth record."))?;
        write_atomic_durable(&target, &bytes)
    }

    pub fn load_pending_lineage_digests(&self, pending_id: &str) -> CliResult<Vec<String>> {
        Ok(self
            .repo
            .read_pending_lineage_readonly(pending_id)?
            .map(|a| a.digests)
            .unwrap_or_default())
    }

    fn record_pending_lineage_digests(
        &self,
        pending_id: &str,
        extra_digests: &[String],
        current_rt_fp: &str,
    ) -> CliResult<()> {
        let filtered: Vec<&str> = extra_digests
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && *s != current_rt_fp)
            .collect();
        if filtered.is_empty() {
            return Ok(());
        }
        validate_account_id(pending_id).map_err(CliError::data)?;
        let mut archive = self
            .repo
            .read_pending_lineage_readonly(pending_id)?
            .unwrap_or_else(|| TokenLineageArchive {
                schema_version: STORE_SCHEMA_VERSION,
                account_id: pending_id.to_string(),
                truncated: false,
                digests: Vec::new(),
            });
        archive.schema_version = STORE_SCHEMA_VERSION;
        archive.account_id = pending_id.to_string();
        for d in filtered {
            archive.digests.retain(|existing| existing != d);
            archive.digests.push(d.to_string());
        }
        archive.digests.retain(|existing| existing != current_rt_fp);
        if archive.digests.len() > MAX_ARCHIVED_RT_DIGESTS {
            let excess = archive.digests.len() - MAX_ARCHIVED_RT_DIGESTS;
            archive.digests.drain(0..excess);
            archive.truncated = true;
        }
        ensure_private_dir(&self.repo.paths.pending_lineage_dir())?;
        let target = self.repo.paths.pending_lineage_file(pending_id);
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &target)?;
        let bytes = serde_json::to_vec_pretty(&archive).map_err(|_| {
            CliError::data(format!(
                "Failed to serialize pending lineage archive for '{pending_id}'."
            ))
        })?;
        write_atomic_durable(&target, &bytes)
    }

    pub fn remove_pending_lineage(&self, pending_id: &str) -> CliResult<()> {
        validate_account_id(pending_id).map_err(CliError::data)?;
        let path = self.repo.paths.pending_lineage_file(pending_id);
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &path)?;
        match fs::remove_file(&path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    if let Ok(dir_file) = fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(parent)
                    {
                        let _ = dir_file.sync_all();
                    }
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(map_io_error(
                e,
                &format!(
                    "Failed to remove pending lineage archive '{}'",
                    path.display()
                ),
            )),
        }
    }

    /// Compare-and-swap update of a `PendingAuthRecord` inside `L3`:
    /// - When `expected_prev_fp` is `None`, requires `pending.id` to be absent (or byte-equivalent);
    /// - When `expected_prev_fp` is `Some(fp)`, requires `pending.id` on disk to match `fp`;
    /// - Automatically persists any superseded `refresh_token` digest from `current -> pending` into
    ///   `<data_dir>/state/pending_lineage/<id>.json` (`0600`) so multi-step pending rotations NEVER forget intermediate tokens;
    /// - If a concurrent modification occurred after `/token` already issued `pending.token`, preserves `pending.token`
    ///   under a separate `pend-alt-<uuid>` record BEFORE returning `pending_auth_version_conflict` so zero issued tokens can ever be lost!
    pub fn save_pending_auth_cas(
        &self,
        pending: &PendingAuthRecord,
        expected_prev_fp: Option<&str>,
    ) -> CliResult<String> {
        let current = self.load_pending_auth_opt(&pending.id)?;
        let matches_expected = match (expected_prev_fp, &current) {
            (None, None) => true,
            (None, Some(live)) => live.cas_fingerprint() == pending.cas_fingerprint(),
            (Some(exp), Some(live)) => live.cas_fingerprint() == exp,
            (Some(_), None) => false,
        };
        let next_rt_fp = pending.token.refresh_token_fingerprint();
        if matches_expected {
            if let Some(ref live) = current {
                let mut sup = Vec::new();
                if let Some(ref inp) = live.input_rt_digest {
                    sup.push(inp.clone());
                }
                if !live.token.refresh_token.trim().is_empty()
                    && live.token.refresh_token.trim() != pending.token.refresh_token.trim()
                {
                    sup.push(token_digest(&live.token.refresh_token));
                }
                self.record_pending_lineage_digests(&pending.id, &sup, &next_rt_fp)?;
            }
            self.save_pending_auth(pending)?;
            return Ok(pending.id.clone());
        }

        let alt_id = format!("pend-alt-{}", Uuid::new_v4().simple());
        let mut alt_sup = self.load_pending_lineage_digests(&pending.id)?;
        if let Some(ref inp) = pending.input_rt_digest {
            alt_sup.push(inp.clone());
        }
        self.record_pending_lineage_digests(&alt_id, &alt_sup, &next_rt_fp)?;
        let mut alt_rec = pending.clone();
        alt_rec.id = alt_id.clone();
        self.save_pending_auth(&alt_rec)?;
        Err(CliError::conflict(
            "pending_auth_version_conflict",
            format!(
                "Pending auth record '{}' changed concurrently; newly issued token was preserved separately as '{alt_id}'.",
                pending.id
            ),
        ))
    }

    pub fn remove_pending_auth(&self, pending_id: &str) -> CliResult<()> {
        validate_account_id(pending_id).map_err(CliError::data)?;
        let path = self.repo.paths.pending_auth_file(pending_id);
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &path)?;
        match fs::remove_file(&path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    if let Ok(dir_file) = fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(parent)
                    {
                        let _ = dir_file.sync_all();
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Failed to remove pending auth file '{}'", path.display()),
                ))
            }
        }
        self.remove_pending_lineage(pending_id)
    }

    /// Compare-and-delete `pending_id` inside `L3`: refuses deletion if `pending_id` was modified or rotated concurrently!
    pub fn remove_pending_auth_cas(
        &self,
        pending_id: &str,
        expected_cas_fp: &str,
    ) -> CliResult<()> {
        let _ = self.verify_pending_auth_cas(pending_id, expected_cas_fp)?;
        self.remove_pending_auth(pending_id)
    }

    fn find_existing_in_index(
        &self,
        index: &StoreIndex,
        candidate_id: Option<&str>,
        refresh_token: &str,
        email: &str,
        client_key: Option<&str>,
    ) -> CliResult<Option<AccountRecord>> {
        let mut loaded = Vec::with_capacity(index.account_order.len());
        for existing_id in &index.account_order {
            if let Some(acc) = self.load_account_opt(existing_id)? {
                loaded.push(acc);
            }
        }
        Ok(find_matching_account_in_slice(
            self.repo,
            &loaded,
            candidate_id,
            refresh_token,
            email,
            client_key,
        )?
        .cloned())
    }

    /// Upsert a verified account record (insert new or merge into existing by matching ID, refresh_token fingerprint/lineage, or email+client).
    /// Rejects superseded rotated refresh tokens and superseded authorization generations, while preserving concurrent `Manual` / `AccountSuspended` disablement!
    pub fn upsert_account(
        &self,
        mut candidate: AccountRecord,
        select_if_first: bool,
        now_unix: i64,
    ) -> CliResult<(AccountRecord, bool)> {
        validate_account_id(&candidate.id).map_err(CliError::data)?;
        let mut index = self.load_index_or_init(now_unix)?;
        let existing_match = self.find_existing_in_index(
            &index,
            Some(&candidate.id),
            &candidate.token.refresh_token,
            &candidate.email,
            candidate.token.oauth_client_key.as_deref(),
        )?;

        if let Some(mut latest) = existing_match {
            if candidate.auth_generation > 0
                && is_pending_superseded_by_account(
                    candidate.auth_generation,
                    latest.auth_generation,
                )
            {
                return Err(CliError::conflict(
                    "superseded_authorization",
                    format!(
                        "Refusing to overwrite newer authorization generation ({}) on account '{}' with stale generation ({}).",
                        latest.auth_generation, latest.id, candidate.auth_generation
                    ),
                ));
            }
            if self
                .account_has_superseded_rt_in_tx(&latest, &candidate.token.refresh_token)?
                .0
            {
                return Err(CliError::conflict(
                    "stale_rotated_refresh_token",
                    format!(
                        "Refusing to overwrite rotated refresh_token on account '{}' with a previously superseded token.",
                        latest.id
                    ),
                ));
            }
            let token_changed_or_verified = latest.token.refresh_token.trim()
                != candidate.token.refresh_token.trim()
                || candidate.token.granted_scopes.is_some();
            if candidate.auth_generation > 0 {
                latest.auth_generation = next_account_auth_generation_for_pending(
                    latest.auth_generation,
                    candidate.auth_generation,
                );
                self.ensure_auth_sequence_at_least(latest.auth_generation)?;
            } else if token_changed_or_verified {
                latest.auth_generation = self.allocate_next_auth_seq()?;
            }
            latest.email = if candidate.email.trim().is_empty() {
                latest.email
            } else {
                candidate.email
            };
            if candidate.name.is_some() {
                latest.name = candidate.name;
            }
            if candidate.custom_label.is_some() {
                latest.custom_label = candidate.custom_label;
            }
            let preserved_project = candidate
                .token
                .project_id
                .clone()
                .or_else(|| latest.token.project_id.clone());
            latest.record_token_transition(TokenRecord {
                project_id: preserved_project,
                ..candidate.token
            });
            for sup_dig in &candidate.previous_refresh_token_digests {
                latest.record_superseded_digest(sup_dig);
            }
            if let Some(q) = candidate.quota {
                latest.update_quota(q);
            }
            if candidate.disabled {
                latest.disabled = true;
                if !matches!(
                    latest.disabled_code,
                    Some(DisableReasonCode::Manual | DisableReasonCode::AccountSuspended)
                ) || matches!(
                    candidate.disabled_code,
                    Some(DisableReasonCode::Manual | DisableReasonCode::AccountSuspended)
                ) {
                    latest.disabled_code = candidate.disabled_code;
                    latest.disabled_detail = candidate.disabled_detail;
                    latest.disabled_at = candidate.disabled_at;
                }
            } else if latest.disabled
                && token_changed_or_verified
                && matches!(
                    latest.disabled_code,
                    Some(
                        DisableReasonCode::RevokedOrExpiredGrant
                            | DisableReasonCode::ScopeReauthRequired
                    )
                )
            {
                latest.disabled = false;
                latest.disabled_code = None;
                latest.disabled_detail = None;
                latest.disabled_at = None;
            }
            latest.last_used = now_unix;
            self.save_account(&latest)?;
            return Ok((latest, false));
        }

        if candidate.auth_generation > 0 {
            self.ensure_auth_sequence_at_least(candidate.auth_generation)?;
        } else if self.current_max_auth_seq()? > 0
            || !self.repo.list_valid_pending_auth_lossy().is_empty()
        {
            candidate.auth_generation = self.allocate_next_auth_seq()?;
        }
        self.save_account(&candidate)?;
        index.account_order.push(candidate.id.clone());
        if select_if_first && index.selected_account_id.is_none() {
            index.selected_account_id = Some(candidate.id.clone());
        }
        self.save_index(&mut index, now_unix)?;
        Ok((candidate, true))
    }

    /// Safe backup/legacy import entry point (caller MUST hold `L2` if an existing account matched prior to `L3`):
    /// - Always rejects superseded rotated refresh tokens (even with `overwrite == true`);
    /// - When `overwrite == false` (default), NEVER overwrites an existing account's token (`SkippedDuplicate`);
    /// - When `overwrite == true`, preserves fresher `access_token`/`expiry_timestamp` if the `refresh_token` is identical,
    ///   and records token transition history + advances `auth_generation` when replacing with a genuinely new external `refresh_token`.
    pub fn import_account_checked(
        &self,
        mut candidate: AccountRecord,
        overwrite: bool,
        select_if_first: bool,
        now_unix: i64,
    ) -> CliResult<ImportUpsertOutcome> {
        validate_account_id(&candidate.id).map_err(CliError::data)?;
        let mut index = self.load_index_or_init(now_unix)?;
        let existing_match = self.find_existing_in_index(
            &index,
            Some(&candidate.id),
            &candidate.token.refresh_token,
            &candidate.email,
            candidate.token.oauth_client_key.as_deref(),
        )?;

        if let Some(mut latest) = existing_match {
            if !overwrite {
                return Ok(ImportUpsertOutcome::SkippedDuplicate(latest));
            }
            let (is_superseded, is_lineage_truncated) =
                self.account_has_superseded_rt_in_tx(&latest, &candidate.token.refresh_token)?;
            if is_superseded {
                return Err(CliError::conflict(
                    "stale_rotated_refresh_token",
                    format!(
                        "Refusing to overwrite rotated refresh_token on account '{}' with a superseded backup token.",
                        latest.id
                    ),
                ));
            }

            // Explicit `--overwrite`: if refresh_token is identical to what's already on disk, preserve fresher live access_token/expiry!
            let same_rt = latest.token.refresh_token.trim() == candidate.token.refresh_token.trim();
            if !same_rt && is_lineage_truncated {
                return Err(CliError::conflict(
                    "unverifiable_token_lineage",
                    format!(
                        "Refusing `--overwrite` on account '{}' because its historical rotation lineage exceeded retention capacity and rollback safety cannot be proven. Use `auth reauthorize` or `accounts add` instead.",
                        latest.id
                    ),
                ));
            }
            if !same_rt {
                latest.auth_generation = self.allocate_next_auth_seq()?;
            }
            if !candidate.email.trim().is_empty() {
                latest.email = candidate.email;
            }
            if candidate.name.is_some() {
                latest.name = candidate.name;
            }
            if candidate.custom_label.is_some() {
                latest.custom_label = candidate.custom_label;
            }
            if same_rt && latest.token.expiry_timestamp >= candidate.token.expiry_timestamp {
                if latest.token.project_id.is_none() {
                    latest.token.project_id = candidate.token.project_id;
                }
                if latest.token.oauth_client_key.is_none() {
                    latest.token.oauth_client_key = candidate.token.oauth_client_key;
                }
                if latest.token.granted_scopes.is_none() {
                    latest.token.granted_scopes = candidate.token.granted_scopes;
                }
            } else {
                let preserved_project = candidate
                    .token
                    .project_id
                    .clone()
                    .or_else(|| latest.token.project_id.clone());
                let preserved_client = candidate.token.oauth_client_key.clone().or_else(|| {
                    same_rt
                        .then(|| latest.token.oauth_client_key.clone())
                        .flatten()
                });
                let preserved_scopes = candidate.token.granted_scopes.clone().or_else(|| {
                    same_rt
                        .then(|| latest.token.granted_scopes.clone())
                        .flatten()
                });
                latest.record_token_transition(TokenRecord {
                    project_id: preserved_project,
                    oauth_client_key: preserved_client,
                    granted_scopes: preserved_scopes,
                    ..candidate.token
                });
            }
            if let Some(q) = candidate.quota {
                latest.update_quota(q);
            }
            if candidate.disabled {
                latest.disabled = true;
                if !matches!(
                    latest.disabled_code,
                    Some(DisableReasonCode::Manual | DisableReasonCode::AccountSuspended)
                ) || matches!(
                    candidate.disabled_code,
                    Some(DisableReasonCode::Manual | DisableReasonCode::AccountSuspended)
                ) {
                    latest.disabled_code = candidate.disabled_code;
                    latest.disabled_detail = candidate.disabled_detail;
                    latest.disabled_at = candidate.disabled_at;
                }
            } else if !same_rt
                && latest.disabled
                && matches!(
                    latest.disabled_code,
                    Some(
                        DisableReasonCode::RevokedOrExpiredGrant
                            | DisableReasonCode::ScopeReauthRequired
                    )
                )
            {
                latest.disabled = false;
                latest.disabled_code = None;
                latest.disabled_detail = None;
                latest.disabled_at = None;
            }
            latest.last_used = now_unix;
            self.save_account(&latest)?;
            if !same_rt {
                self.cleanup_idle_superseded_reauth_pendings_in_tx(None, &mut latest)?;
            }
            return Ok(ImportUpsertOutcome::Updated(latest));
        }

        if candidate.auth_generation > 0 {
            self.ensure_auth_sequence_at_least(candidate.auth_generation)?;
        } else if self.current_max_auth_seq()? > 0
            || !self.repo.list_valid_pending_auth_lossy().is_empty()
        {
            candidate.auth_generation = self.allocate_next_auth_seq()?;
        }
        self.save_account(&candidate)?;
        index.account_order.push(candidate.id.clone());
        if select_if_first && index.selected_account_id.is_none() {
            index.selected_account_id = Some(candidate.id.clone());
        }
        self.save_index(&mut index, now_unix)?;
        Ok(ImportUpsertOutcome::Imported(candidate))
    }

    /// Non-blockingly absorb and CAS-delete any idle superseded `Reauthorize` pending records targeting `updated_acc.id`.
    /// Never blocks on a busy `PendingAuthLock` (preserving `L1 -> PendingAuthLock -> L2 -> L3` hierarchy); any busy
    /// older pending will observe `updated_acc.auth_generation >= pending.auth_seq` as soon as it acquires `L2`!
    pub fn cleanup_idle_superseded_reauth_pendings_in_tx(
        &self,
        exclude_pending_id: Option<&str>,
        updated_acc: &mut AccountRecord,
    ) -> CliResult<bool> {
        let target_account_id = updated_acc.id.clone();
        let candidates: Vec<String> = self
            .repo
            .list_valid_pending_auth_lossy()
            .into_iter()
            .filter(|p| {
                exclude_pending_id.is_none_or(|ex| p.id != ex)
                    && !p.email_mismatch
                    && is_pending_superseded_by_account(p.auth_seq, updated_acc.auth_generation)
                    && matches!(
                        &p.flow,
                        PendingAuthFlow::Reauthorize {
                            target_account_id: tid
                        } if tid == &target_account_id
                    )
            })
            .map(|p| p.id)
            .collect();
        let mut any_absorbed = false;
        for dup_id in candidates {
            let Ok(Some(_held)) = try_acquire_pending_auth_lock_nonblocking(self.paths(), &dup_id)
            else {
                continue;
            };
            let Some(live_dup) = self.load_pending_auth_opt(&dup_id)? else {
                continue;
            };
            let still_matches = !live_dup.email_mismatch
                && is_pending_superseded_by_account(live_dup.auth_seq, updated_acc.auth_generation)
                && matches!(
                    &live_dup.flow,
                    PendingAuthFlow::Reauthorize {
                        target_account_id: tid
                    } if tid == &target_account_id
                );
            if !still_matches {
                continue;
            }
            let Ok(lin) = self.load_pending_lineage_digests(&dup_id) else {
                continue;
            };
            if let Some(ref inp) = live_dup.input_rt_digest {
                updated_acc.record_superseded_digest(inp);
            }
            let dup_rt = live_dup.token.refresh_token.trim();
            if !dup_rt.is_empty() {
                updated_acc.record_superseded_digest(&token_digest(dup_rt));
            }
            for d in lin {
                updated_acc.record_superseded_digest(&d);
            }
            self.save_account(updated_acc)?;
            let _ = self.remove_pending_auth_cas(&dup_id, &live_dup.cas_fingerprint());
            any_absorbed = true;
        }
        Ok(any_absorbed)
    }

    /// Field-level merge of a refreshed/rotated `TokenRecord` into the latest disk `AccountRecord`.
    /// Never overwrites concurrent `quota`, `custom_label`, `Manual` disablement, `protected_models`, or `auth_generation`.
    pub fn merge_refreshed_token(
        &self,
        account_id: &str,
        new_token: TokenRecord,
        discovered_name: Option<String>,
        now_unix: i64,
    ) -> CliResult<AccountRecord> {
        let index = self.load_index_or_init(now_unix)?;
        if !index.account_order.iter().any(|id| id == account_id) {
            return Err(CliError::not_found(format!(
                "Account '{account_id}' was removed before token persistence."
            )));
        }
        let mut latest = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!("Account file for '{account_id}' is missing."))
        })?;

        if self
            .account_has_superseded_rt_in_tx(&latest, &new_token.refresh_token)?
            .0
        {
            return Err(CliError::conflict(
                "stale_rotated_refresh_token",
                format!("Refusing to merge superseded refresh_token into account '{account_id}'."),
            ));
        }

        let preserved_project = new_token
            .project_id
            .clone()
            .or_else(|| latest.token.project_id.clone());
        latest.record_token_transition(TokenRecord {
            project_id: preserved_project,
            ..new_token
        });
        if latest
            .name
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            if let Some(name) = discovered_name {
                if !name.trim().is_empty() {
                    latest.name = Some(name);
                }
            }
        }
        if latest.disabled
            && matches!(
                latest.disabled_code,
                Some(DisableReasonCode::RevokedOrExpiredGrant)
            )
        {
            latest.disabled = false;
            latest.disabled_code = None;
            latest.disabled_detail = None;
            latest.disabled_at = None;
        }
        self.save_account(&latest)?;
        Ok(latest)
    }

    /// Merge a newly issued token from `auth reauthorize` with explicit `pending_auth_seq` generation verification,
    /// clearing ONLY auth-grant/scope disablement (`RevokedOrExpiredGrant` / `ScopeReauthRequired`) while strictly
    /// preserving concurrent `Manual` / `AccountSuspended` and advancing `auth_generation`!
    pub fn merge_reauthorized_token_for_pending(
        &self,
        account_id: &str,
        new_token: TokenRecord,
        discovered_name: Option<String>,
        missing_scopes: &[String],
        pending_auth_seq: u64,
        now_unix: i64,
    ) -> CliResult<AccountRecord> {
        let current = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!("Account file for '{account_id}' is missing."))
        })?;
        if is_pending_superseded_by_account(pending_auth_seq, current.auth_generation) {
            return Err(CliError::conflict(
                "superseded_authorization",
                format!(
                    "Refusing to apply superseded pending authorization (seq {pending_auth_seq}) onto account '{account_id}' (auth_generation {}).",
                    current.auth_generation
                ),
            ));
        }
        let next_gen =
            next_account_auth_generation_for_pending(current.auth_generation, pending_auth_seq);
        self.ensure_auth_sequence_at_least(next_gen)?;
        let mut merged =
            self.merge_refreshed_token(account_id, new_token, discovered_name, now_unix)?;
        merged.auth_generation = next_gen;
        if missing_scopes.is_empty() {
            if merged.disabled
                && matches!(
                    merged.disabled_code,
                    Some(
                        DisableReasonCode::RevokedOrExpiredGrant
                            | DisableReasonCode::ScopeReauthRequired
                    )
                )
            {
                merged.disabled = false;
                merged.disabled_code = None;
                merged.disabled_detail = None;
                merged.disabled_at = None;
            }
        } else {
            merged.disabled = true;
            if !matches!(
                merged.disabled_code,
                Some(DisableReasonCode::Manual | DisableReasonCode::AccountSuspended)
            ) {
                merged.disabled_code = Some(DisableReasonCode::ScopeReauthRequired);
                merged.disabled_detail = Some(format!(
                    "Reauthorization still missing required scope(s): {}",
                    missing_scopes.join(", ")
                ));
                merged.disabled_at = Some(now_unix);
            }
        }
        self.save_account(&merged)?;
        Ok(merged)
    }

    /// Merge a newly issued token from `auth reauthorize`, allocating a fresh `auth_generation`.
    pub fn merge_reauthorized_token(
        &self,
        account_id: &str,
        new_token: TokenRecord,
        discovered_name: Option<String>,
        missing_scopes: &[String],
        now_unix: i64,
    ) -> CliResult<AccountRecord> {
        let seq = self.allocate_next_auth_seq()?;
        self.merge_reauthorized_token_for_pending(
            account_id,
            new_token,
            discovered_name,
            missing_scopes,
            seq,
            now_unix,
        )
    }

    pub fn mark_account_disabled(
        &self,
        account_id: &str,
        code: DisableReasonCode,
        detail: Option<String>,
        now_unix: i64,
    ) -> CliResult<AccountRecord> {
        let mut latest = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!("Account '{account_id}' does not exist."))
        })?;
        let preserve_manual_or_suspended = latest.disabled
            && matches!(
                latest.disabled_code,
                Some(DisableReasonCode::Manual | DisableReasonCode::AccountSuspended)
            )
            && !matches!(
                code,
                DisableReasonCode::Manual | DisableReasonCode::AccountSuspended
            );
        latest.disabled = true;
        if !preserve_manual_or_suspended {
            latest.disabled_code = Some(code);
            latest.disabled_detail = detail;
            latest.disabled_at = Some(now_unix);
        }
        self.save_account(&latest)?;
        Ok(latest)
    }

    pub fn mark_account_enabled(&self, account_id: &str) -> CliResult<AccountRecord> {
        let mut latest = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!("Account '{account_id}' does not exist."))
        })?;
        latest.disabled = false;
        latest.disabled_code = None;
        latest.disabled_detail = None;
        latest.disabled_at = None;
        latest.validation_blocked = false;
        latest.validation_blocked_until = None;
        latest.validation_blocked_reason = None;
        latest.validation_url = None;
        self.save_account(&latest)?;
        Ok(latest)
    }

    pub fn update_account_identity_metadata(
        &self,
        account_id: &str,
        discovered_email: Option<&str>,
        discovered_name: Option<&str>,
        custom_label: Option<&str>,
    ) -> CliResult<AccountRecord> {
        let mut latest = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!("Account '{account_id}' does not exist."))
        })?;
        if let Some(email) = discovered_email.map(str::trim).filter(|s| !s.is_empty()) {
            latest.email = email.to_string();
        }
        if let Some(name) = discovered_name.map(str::trim).filter(|s| !s.is_empty()) {
            if latest
                .name
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            {
                latest.name = Some(name.to_string());
            }
        }
        if let Some(label) = custom_label.map(str::trim).filter(|s| !s.is_empty()) {
            latest.custom_label = Some(label.to_string());
        }
        self.save_account(&latest)?;
        Ok(latest)
    }

    pub fn update_account_display_name(
        &self,
        account_id: &str,
        discovered_name: &str,
    ) -> CliResult<()> {
        let trimmed = discovered_name.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let Some(mut latest) = self.load_account_opt(account_id)? else {
            return Ok(());
        };
        if latest
            .name
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            latest.name = Some(trimmed.to_string());
            self.save_account(&latest)?;
        }
        Ok(())
    }

    /// Field-level merge of a fresh `QuotaObservation` without touching rotated `access_token` / `refresh_token`.
    /// Only clears `validation_blocked` when `allow_clear_validation_block` is `true` (authoritative primary environment
    /// succeeded without forbidden/validation block — NEVER cleared by a fallback `Daily`/`Sandbox` 200 OK!).
    pub fn merge_quota_observation(
        &self,
        account_id: &str,
        quota: QuotaObservation,
        discovered_project_id: Option<String>,
        validation_block: Option<(String, Option<String>)>,
        allow_clear_validation_block: bool,
    ) -> CliResult<AccountRecord> {
        let mut latest = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!(
                "Account '{account_id}' was removed during quota refresh."
            ))
        })?;
        if let Some(pid) = discovered_project_id.filter(|s| !s.trim().is_empty()) {
            // Never allow a fallback (`Daily`/`Sandbox`) response to overwrite an already-persisted primary `project_id`!
            if allow_clear_validation_block || latest.token.project_id.is_none() {
                latest.token.project_id = Some(pid);
            }
        }
        if let Some((reason, validation_url)) = validation_block {
            latest.validation_blocked = true;
            latest.validation_blocked_reason = Some(reason);
            if validation_url.is_some() {
                latest.validation_url = validation_url;
            }
        } else if allow_clear_validation_block && !quota.is_forbidden && latest.validation_blocked {
            latest.validation_blocked = false;
            latest.validation_blocked_until = None;
            latest.validation_blocked_reason = None;
            latest.validation_url = None;
        }
        latest.update_quota(quota);
        self.save_account(&latest)?;
        Ok(latest)
    }

    /// Commit `selected_account_id` and `last_used` after the active slot has been updated.
    pub fn commit_selected_account(
        &self,
        account_id: &str,
        now_unix: i64,
    ) -> CliResult<(StoreIndex, AccountRecord)> {
        let mut index = self.load_index_or_init(now_unix)?;
        if !index.account_order.iter().any(|id| id == account_id) {
            return Err(CliError::not_found(format!(
                "Target account '{account_id}' was removed before index commit."
            )));
        }
        let mut latest = self.load_account_opt(account_id)?.ok_or_else(|| {
            CliError::not_found(format!(
                "Target account file '{account_id}' is missing before index commit."
            ))
        })?;
        latest.last_used = now_unix;
        self.save_account(&latest)?;
        index.selected_account_id = Some(account_id.to_string());
        self.save_index(&mut index, now_unix)?;
        Ok((index, latest))
    }

    pub fn reorder_accounts(
        &self,
        ordered_ids: Vec<String>,
        now_unix: i64,
    ) -> CliResult<StoreIndex> {
        let mut index = self.load_index_or_init(now_unix)?;
        if ordered_ids.len() != index.account_order.len() {
            return Err(CliError::usage(format!(
                "`accounts order` requires every saved account exactly once (expected {}, got {}).",
                index.account_order.len(),
                ordered_ids.len()
            )));
        }
        let existing_set: HashSet<&str> = index.account_order.iter().map(String::as_str).collect();
        let mut seen = HashSet::with_capacity(ordered_ids.len());
        for id in &ordered_ids {
            if !existing_set.contains(id.as_str()) {
                return Err(CliError::not_found(format!(
                    "Account '{id}' is not in the current store index."
                )));
            }
            if !seen.insert(id.as_str()) {
                return Err(CliError::usage(format!(
                    "Duplicate account '{id}' in order arguments."
                )));
            }
        }
        index.account_order = ordered_ids;
        self.save_index(&mut index, now_unix)?;
        Ok(index)
    }

    /// Delete account with explicit selected-account semantics per Blueprint §8.2 rule 6.
    /// Propagates policy cleanup persistence failures BEFORE removing the account so `policy.json`
    /// is never silently left referencing a deleted candidate account!
    pub fn delete_account(&self, account_id: &str, force: bool, now_unix: i64) -> CliResult<bool> {
        let mut index = self.load_index_or_init(now_unix)?;
        if !index.account_order.iter().any(|id| id == account_id) {
            return Err(CliError::not_found(format!(
                "Account '{account_id}' does not exist."
            )));
        }
        let was_selected = index.selected_account_id.as_deref() == Some(account_id);
        if was_selected && !force {
            return Err(CliError::usage(format!(
                "Account '{account_id}' is currently selected. Switch to another account first, or pass `--force` (and `--clear-active-slot` to also remove the active credential file)."
            )));
        }

        let acc_path = self.repo.paths.account_file(account_id);
        let lineage_path = self.repo.paths.token_lineage_file(account_id);
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &acc_path)?;
        ensure_no_symlink_components_under(&self.repo.paths.data_dir, &lineage_path)?;
        for check_path in [&acc_path, &lineage_path] {
            match fs::symlink_metadata(check_path) {
                Ok(m) if !m.file_type().is_file() => {
                    return Err(CliError::data(format!(
                        "Refusing to delete non-regular store file '{}'.",
                        check_path.display()
                    )));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(map_io_error(
                        e,
                        &format!("Cannot inspect store file '{}'", check_path.display()),
                    ))
                }
            }
        }

        // 1. Clean `account_id` (and any already-stale non-indexed IDs) from `policy.json` FIRST and propagate any I/O failure (`?`)!
        let mut policy = self.repo.read_policy()?;
        let known_remaining: HashSet<&str> = index
            .account_order
            .iter()
            .map(String::as_str)
            .filter(|id| *id != account_id)
            .collect();
        let before_cands = policy.candidate_account_ids.len();
        policy
            .candidate_account_ids
            .retain(|id| id != account_id && known_remaining.contains(id.as_str()));
        if policy.candidate_account_ids.len() != before_cands {
            if policy.candidate_account_ids.is_empty() {
                policy.enabled = false;
            }
            self.save_policy(&mut policy, None, now_unix)?;
        }

        // 2. Remove from `index.json`
        index.account_order.retain(|id| id != account_id);
        if was_selected {
            index.selected_account_id = None;
        }
        self.save_index(&mut index, now_unix)?;

        // 3. Remove `accounts/<id>.json`
        let acc_path = self.repo.paths.account_file(account_id);
        match fs::remove_file(&acc_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Failed to remove account file '{}'", acc_path.display()),
                ))
            }
        }
        if let Some(parent) = acc_path.parent() {
            if let Ok(dir_file) = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(parent)
            {
                let _ = dir_file.sync_all();
            }
        }

        // 4. Clean up any overflow `state/token_lineage/<id>.json` archive for the deleted account
        let lineage_path = self.repo.paths.token_lineage_file(account_id);
        if ensure_no_symlink_components_under(&self.repo.paths.data_dir, &lineage_path).is_ok() {
            match fs::remove_file(&lineage_path) {
                Ok(()) => {
                    if let Some(parent) = lineage_path.parent() {
                        if let Ok(dir_file) = fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                            .open(parent)
                        {
                            let _ = dir_file.sync_all();
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(map_io_error(
                        e,
                        &format!(
                            "Failed to remove token lineage archive '{}'",
                            lineage_path.display()
                        ),
                    ))
                }
            }
        }
        Ok(was_selected)
    }

    pub fn save_policy(
        &self,
        policy: &mut SwitchPolicy,
        expected_revision: Option<u64>,
        now_unix: i64,
    ) -> CliResult<SwitchPolicy> {
        let current = self.repo.read_policy()?;
        if let Some(expected) = expected_revision {
            if current.revision != expected {
                return Err(CliError::conflict(
                    "policy_revision_conflict",
                    format!(
                        "Policy changed concurrently (expected revision {expected}, found {}). Reload and retry.",
                        current.revision
                    ),
                ));
            }
        }
        let index = self.load_index_or_init(now_unix)?;
        let known_ids: HashSet<String> = index.account_order.into_iter().collect();
        policy.validate(Some(&known_ids)).map_err(CliError::usage)?;

        policy.schema_version = STORE_SCHEMA_VERSION;
        policy.revision = current.revision.saturating_add(1);
        policy.updated_at = now_unix;
        let bytes = serde_json::to_vec_pretty(policy)
            .map_err(|_| CliError::data("Failed to serialize policy.json."))?;
        write_atomic_durable(&self.repo.paths.policy_file(), &bytes)?;
        Ok(policy.clone())
    }
}

fn parse_index_bytes(bytes: &[u8]) -> CliResult<StoreIndex> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CliError::data("Store index `index.json` is not valid UTF-8."))?;
    let index: StoreIndex = serde_json::from_str(text.trim_start_matches(['\u{feff}', '\0']))
        .map_err(|e| CliError::data(format_safe_json_error("Store index `index.json`", &e)))?;
    if index.schema_version != STORE_SCHEMA_VERSION {
        return Err(CliError::data(format!(
            "Unsupported index.json schema_version {} (expected {}).",
            index.schema_version, STORE_SCHEMA_VERSION
        )));
    }
    Ok(index)
}

pub fn read_headless_config_readonly(
    paths: &HeadlessPaths,
) -> CliResult<(HeadlessConfig, Vec<String>)> {
    let path = paths.config_file();
    ensure_no_symlink_components_under(&paths.data_dir, &path)?;
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HeadlessConfig::default(), Vec::new()));
        }
        Err(e) => {
            return Err(map_io_error(
                e,
                &format!("Cannot inspect config file '{}'", path.display()),
            ))
        }
    };
    if !meta.file_type().is_file() {
        return Err(CliError::data(format!(
            "Config file '{}' must be a regular file, not a symlink, FIFO, or directory.",
            path.display()
        )));
    }
    let Some(bytes) = read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Config file")?
    else {
        return Ok((HeadlessConfig::default(), Vec::new()));
    };
    let cfg: HeadlessConfig = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::data(format_safe_json_error(
            &format!("Config file '{}'", path.display()),
            &e,
        ))
    })?;
    if cfg.schema_version != STORE_SCHEMA_VERSION {
        return Err(CliError::data(format!(
            "Unsupported config schema_version {} in '{}' (expected {}).",
            cfg.schema_version,
            path.display(),
            STORE_SCHEMA_VERSION
        )));
    }
    let mut warnings = Vec::new();
    let mode = meta.permissions().mode() & 0o777;
    let has_sensitive_cfg = !cfg.oauth.clients.is_empty()
        || cfg
            .network
            .proxy_url
            .as_deref()
            .is_some_and(|u| u.contains('@'));
    if has_sensitive_cfg && (mode & 0o077) != 0 {
        warnings.push(format!(
            "Config file '{}' contains sensitive settings with mode {:04o}; run `chmod 600` or `agy-switch-cli doctor --fix`.",
            path.display(),
            mode
        ));
    }
    Ok((cfg, warnings))
}

pub fn ensure_no_side_effects_dir_check(dir: &Path) -> bool {
    !dir.exists()
}
