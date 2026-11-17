use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::session::payload::{
    extract_raw_refresh_token_from_session_bytes, parse_session_payload_bytes, ParsedSessionPayload,
};
use crate::store::fs_atomic::{
    cleanup_orphan_temp_files, ensure_no_symlink_components_under, map_io_error,
    read_regular_file_opt_bounded, write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use std::fs;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum SlotInspectState {
    /// `~/.gemini/antigravity-cli` directory does not exist yet
    Uninitialized,
    /// `~/.gemini/antigravity-cli` exists, `antigravity-oauth-token` does not exist yet
    AbsentInInitializedDir,
    /// Valid regular file parsed cleanly
    Present(ParsedSessionPayload),
    /// Invalid JSON, symlink, directory obstruction, etc.
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
}

pub trait CredentialBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn uses_keyring(&self) -> bool;
    /// Pure read-only inspection with ZERO file/directory/network side effects.
    fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState;
    /// Validate active slot directory is initialized and return raw snapshot bytes before commit.
    fn snapshot_before_write(&self, paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>>;
    /// Atomically replace active slot payload (caller MUST hold L1 `ActiveSlotLock`).
    fn write_slot(&self, paths: &HeadlessPaths, payload: &str) -> CliResult<()>;
    /// Remove active slot file (caller MUST hold L1 `ActiveSlotLock`).
    fn remove_slot(&self, paths: &HeadlessPaths) -> CliResult<()>;
    /// Read raw credential bytes from the system keyring if this backend uses a keyring (`accounts add --from-local`).
    fn read_raw_keyring_secret(&self) -> CliResult<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Default headless file session backend (`~/.gemini/antigravity-cli/antigravity-oauth-token`).
#[derive(Debug, Clone, Default)]
pub struct FileSessionBackend;

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
        "file_session"
    }

    fn uses_keyring(&self) -> bool {
        false
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
        let _ = cleanup_orphan_temp_files(&paths.active_slot_dir, Duration::from_secs(60));
        write_atomic_durable(&paths.active_slot_file, payload.as_bytes())
    }

    fn remove_slot(&self, paths: &HeadlessPaths) -> CliResult<()> {
        ensure_no_symlink_components_under(&paths.home_dir, &paths.active_slot_file)?;
        match fs::symlink_metadata(&paths.active_slot_file) {
            Ok(meta) if meta.file_type().is_file() => {
                fs::remove_file(&paths.active_slot_file).map_err(|e| {
                    map_io_error(
                        e,
                        &format!(
                            "Failed to remove active session file '{}'",
                            paths.active_slot_file.display()
                        ),
                    )
                })?;
                if let Ok(dir_file) = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&paths.active_slot_dir)
                {
                    let _ = dir_file.sync_all();
                }
                Ok(())
            }
            Ok(_) => Err(CliError::data(format!(
                "Refusing to remove non-regular session target '{}'.",
                paths.active_slot_file.display()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(map_io_error(
                e,
                &format!(
                    "Cannot inspect active session file '{}'",
                    paths.active_slot_file.display()
                ),
            )),
        }
    }
}

/// Pure stat-only check (NEVER connects to D-Bus or reads any keyring items!) detecting if a user
/// D-Bus session socket exists in the current environment, which in `agy` 1.5.7's `composite_token_storage`
/// takes precedence over `antigravity-oauth-token` if an unlocked Secret Service holds a credential.
pub fn detect_dbus_session_socket_warning() -> Option<String> {
    if let Ok(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        if let Some(rest) = addr.strip_prefix("unix:path=") {
            let sock_path = rest.split(',').next().unwrap_or(rest);
            if is_unix_socket(PathBuf::from(sock_path).as_path()) {
                return Some(format!(
                    "Detected live D-Bus session socket via DBUS_SESSION_BUS_ADDRESS ('{sock_path}'). Official `agy` 1.5.7 queries D-Bus Secret Service before `~/.gemini/antigravity-cli/antigravity-oauth-token`; pass `--isolate-dbus` to `agy-switch-cli run` or remove stale desktop keyring entries if `agy` ignores file switches."
                ));
            }
        }
    } else if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let bus = PathBuf::from(runtime_dir).join("bus");
        if is_unix_socket(&bus) {
            return Some(format!(
                "Detected systemd user D-Bus socket at '{}'. Official `agy` 1.5.7 queries D-Bus Secret Service before falling back to `antigravity-oauth-token`; pass `--isolate-dbus` to `agy-switch-cli run` if stale desktop keyring entries exist.",
                bus.display()
            ));
        }
    }
    None
}

fn is_unix_socket(path: &std::path::Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

/// Fast stat-only check determining whether a session D-Bus endpoint exists in the current environment.
/// Returns `false` immediately for non-existent sockets or `unix:path=/dev/null` (`--isolate-dbus`).
pub fn has_reachable_dbus_session_bus() -> bool {
    if let Ok(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        let trimmed = addr.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Some(rest) = trimmed.strip_prefix("unix:path=") {
            let sock_path = rest.split([',', ';']).next().unwrap_or(rest);
            return is_unix_socket(PathBuf::from(sock_path).as_path());
        }
        return true;
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let trimmed = runtime_dir.trim();
        if !trimmed.is_empty() {
            return is_unix_socket(PathBuf::from(trimmed).join("bus").as_path());
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    Auto,
    File,
    SecretService,
}

/// Validate `--backend`, `AGY_SWITCH_CLI_BACKEND`, and `config.json` `backend` syntax without touching D-Bus.
pub fn validate_backend_choice(
    cli_backend: Option<&str>,
    cfg_backend: Option<&str>,
) -> CliResult<BackendChoice> {
    let env_val = std::env::var("AGY_SWITCH_CLI_BACKEND")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let cfg_clean = cfg_backend.map(str::trim).filter(|s| !s.is_empty());
    let chosen = cli_backend
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(env_val.as_deref())
        .or(cfg_clean)
        .unwrap_or("auto");

    match chosen.to_ascii_lowercase().as_str() {
        "auto" => Ok(BackendChoice::Auto),
        "file" | "file_session" => Ok(BackendChoice::File),
        "secret-service" | "secret_service" => {
            #[cfg(feature = "secret-service-backend")]
            {
                Ok(BackendChoice::SecretService)
            }
            #[cfg(not(feature = "secret-service-backend"))]
            {
                Err(CliError::usage(
                    "Backend `secret-service` requires compiling with `--features secret-service-backend` (or installing the `-all-features` release binary).",
                ))
            }
        }
        _ => Err(CliError::usage(
            "Unsupported credential backend. Supported values: `auto`, `file`, `secret-service`.",
        )),
    }
}

/// Resolve the configured `CredentialBackend` (`auto` by default: uses `secret-service` dual-write
/// when compiled in and a persistent desktop keyring collection is reachable on D-Bus, otherwise `file`).
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
        BackendChoice::SecretService => {
            #[cfg(feature = "secret-service-backend")]
            {
                Ok(Box::new(SecretServiceSessionBackend))
            }
            #[cfg(not(feature = "secret-service-backend"))]
            {
                unreachable!("validate_backend_choice already gated secret-service-backend")
            }
        }
        BackendChoice::Auto => {
            #[cfg(feature = "secret-service-backend")]
            {
                if has_reachable_dbus_session_bus()
                    && keyring_impl::probe_secret_service_available()
                {
                    return Ok(Box::new(SecretServiceSessionBackend));
                }
            }
            Ok(Box::new(FileSessionBackend))
        }
    }
}

/// Read the currently signed-in local `agy` `refresh_token` following official priority:
/// 1. Linux Secret Service keyring (`service="gemini", username="antigravity"`) when `backend.uses_keyring()` is true;
/// 2. Official `agy` CLI file slot (`~/.gemini/antigravity-cli/antigravity-oauth-token`).
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
            "No local agy credential file found at '{}'. Detected an active desktop D-Bus session: if you signed in on a Linux desktop (GNOME Keyring / KDE Wallet), use the `-all-features` binary so `--from-local` can read directly from the system keyring, or sign in via `agy-switch-cli auth login`.",
            paths.active_slot_file.display()
        )));
    }

    Err(CliError::not_found(format!(
        "No local agy credential found at '{}'. Sign in with `agy` first or add an account via `agy-switch-cli auth login`.",
        paths.active_slot_file.display()
    )))
}

/// Optional non-GUI D-Bus Secret Service + file dual-write backend (`--features secret-service-backend`) per Blueprint §1.2.
/// Never active unless explicitly selected via `--backend secret-service` / `AGY_SWITCH_CLI_BACKEND=secret-service`.
#[cfg(feature = "secret-service-backend")]
#[derive(Debug, Clone, Default)]
pub struct SecretServiceSessionBackend;

#[cfg(feature = "secret-service-backend")]
mod keyring_impl {
    use super::*;
    use secret_service::{Collection, EncryptionType, SecretService};
    use std::collections::HashMap;
    use std::future::Future;

    const KEYRING_TIMEOUT: Duration = Duration::from_secs(10);
    const AUTO_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

    /// Non-mutating D-Bus probe checking whether `org.freedesktop.secrets` is reachable and exposes
    /// at least one persistent `login`/`default` collection (NEVER calls `.unlock()`!).
    pub(super) fn probe_secret_service_available() -> bool {
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return false;
            };
            rt.block_on(async {
                tokio::time::timeout(AUTO_PROBE_TIMEOUT, async {
                    let Ok(svc) = SecretService::connect(EncryptionType::Dh).await else {
                        return false;
                    };
                    open_collections(&svc).await.is_ok()
                })
                .await
                .unwrap_or(false)
            })
        })
        .join()
        .unwrap_or(false)
    }

    fn keyring_attributes() -> HashMap<&'static str, &'static str> {
        HashMap::from([("service", "gemini"), ("username", "antigravity")])
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
            _ => CliError::env_not_ready(
                "secret_service_unavailable",
                format!("Linux Secret Service D-Bus backend is unavailable: {err}"),
            ),
        }
    }

    fn run_dbus_blocking<T: Send + 'static>(
        fut: impl Future<Output = CliResult<T>> + Send + 'static,
    ) -> CliResult<T> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    CliError::io("keyring_rt_failed", format!("Keyring runtime error: {e}"))
                })?;
            rt.block_on(async {
                tokio::time::timeout(KEYRING_TIMEOUT, fut)
                    .await
                    .map_err(|_| {
                        CliError::env_not_ready(
                            "secret_service_timeout",
                            "Linux Secret Service operation timed out.",
                        )
                    })?
            })
        })
        .join()
        .map_err(|_| CliError::io("keyring_worker_panicked", "Keyring worker thread panicked."))?
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
        if let Ok(def) = service.get_default_collection().await {
            if !cols
                .iter()
                .any(|c| c.collection_path == def.collection_path)
            {
                cols.push(def);
            }
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

    async fn replace_collection(col: &Collection<'_>, payload: &[u8]) -> CliResult<()> {
        let item = col
            .create_item(
                "Password for 'antigravity' on 'gemini'",
                keyring_attributes(),
                payload,
                true,
                "text/plain",
            )
            .await
            .map_err(describe_ss_err)?;
        let readback = item.get_secret().await.map_err(describe_ss_err)?;
        if readback != payload {
            return Err(CliError::io(
                "keyring_readback_mismatch",
                "Linux Secret Service readback did not match written payload.",
            ));
        }
        Ok(())
    }

    async fn clear_collection(col: &Collection<'_>) -> CliResult<()> {
        if col.is_locked().await.map_err(describe_ss_err)? {
            col.unlock().await.map_err(describe_ss_err)?;
        }
        for item in col
            .search_items(keyring_attributes())
            .await
            .map_err(describe_ss_err)?
        {
            item.delete().await.map_err(describe_ss_err)?;
        }
        Ok(())
    }

    impl CredentialBackend for SecretServiceSessionBackend {
        fn name(&self) -> &'static str {
            "secret_service_dual"
        }

        fn uses_keyring(&self) -> bool {
            true
        }

        fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
            match run_dbus_blocking(async {
                let svc = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(describe_ss_err)?;
                let mut found: Option<Vec<u8>> = None;
                for col in open_collections(&svc).await? {
                    if let Some(sec) = inspect_collection_readonly(&col).await? {
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
            }) {
                Ok(Some(bytes)) => match parse_session_payload_bytes(&bytes) {
                    Ok(parsed) => SlotInspectState::Present(parsed),
                    Err(reason) => SlotInspectState::Corrupt(reason),
                },
                Ok(None) => FileSessionBackend.inspect_slot(paths),
                Err(e) if e.error_code == "data_error" => SlotInspectState::Corrupt(e.message),
                Err(e) => SlotInspectState::Unverified(e.message),
            }
        }

        fn snapshot_before_write(&self, paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>> {
            let file_snap = FileSessionBackend.snapshot_before_write(paths)?;
            let kr_snap = run_dbus_blocking(async {
                let svc = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(describe_ss_err)?;
                let mut found: Option<Vec<u8>> = None;
                for col in open_collections(&svc).await? {
                    if let Some(sec) = snapshot_collection(&col).await? {
                        if let Some(ref prev_sec) = found {
                            if prev_sec != &sec {
                                return Err(CliError::data(
                                    "Conflicting Antigravity credentials exist across Linux keyring collections; resolve duplicate entries before switching.",
                                ));
                            }
                        } else {
                            found = Some(sec);
                        }
                    }
                }
                Ok(found)
            })?;
            Ok(kr_snap.or(file_snap))
        }

        fn write_slot(&self, paths: &HeadlessPaths, payload: &str) -> CliResult<()> {
            let payload_vec = payload.as_bytes().to_vec();
            let paths_owned = paths.clone();
            let payload_str = payload.to_string();

            run_dbus_blocking(async move {
                let svc = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(describe_ss_err)?;
                let cols = open_collections(&svc).await?;
                let mut prev = Vec::with_capacity(cols.len());
                for c in &cols {
                    prev.push(snapshot_collection(c).await?);
                }

                for (idx, c) in cols.iter().enumerate() {
                    if let Err(write_err) = replace_collection(c, &payload_vec).await {
                        let mut rollback_failed = false;
                        for r_idx in (0..=idx).rev() {
                            let res = match &prev[r_idx] {
                                Some(old) => replace_collection(&cols[r_idx], old).await,
                                None => clear_collection(&cols[r_idx]).await,
                            };
                            rollback_failed |= res.is_err();
                        }
                        if rollback_failed {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                format!(
                                    "{} Linux keyring rollback was incomplete; run `agy-switch-cli doctor --fix` before retrying.",
                                    write_err.message
                                ),
                            ));
                        }
                        return Err(write_err);
                    }
                }

                if let Err(file_err) = FileSessionBackend.write_slot(&paths_owned, &payload_str) {
                    let mut rollback_failed = false;
                    for r_idx in (0..cols.len()).rev() {
                        let res = match &prev[r_idx] {
                            Some(old) => replace_collection(&cols[r_idx], old).await,
                            None => clear_collection(&cols[r_idx]).await,
                        };
                        rollback_failed |= res.is_err();
                    }
                    if rollback_failed {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            format!(
                                "{} Linux keyring rollback was incomplete; run `agy-switch-cli doctor --fix` before retrying.",
                                file_err.message
                            ),
                        ));
                    }
                    return Err(file_err);
                }
                Ok(())
            })
        }

        fn remove_slot(&self, paths: &HeadlessPaths) -> CliResult<()> {
            run_dbus_blocking(async {
                let svc = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(describe_ss_err)?;
                for col in open_collections(&svc).await? {
                    clear_collection(&col).await?;
                }
                Ok(())
            })?;
            FileSessionBackend.remove_slot(paths)
        }

        fn read_raw_keyring_secret(&self) -> CliResult<Option<Vec<u8>>> {
            run_dbus_blocking(async {
                let svc = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(describe_ss_err)?;
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
    }
}
