use crate::domain::config::{
    is_valid_target_name, target_name_looks_like_secret, HeadlessConfig, OFFICIAL_TOKEN_FILENAME,
};
use crate::error::{path_looks_like_accidental_secret, CliError, CliResult, ExitCode};
use crate::paths::{normalize_components, normalize_lexical, HeadlessPaths};
use crate::session::backend::{parse_backend_choice_literal, BackendChoice, SlotInspectState};
use crate::session::payload::{
    bytes_sha256_hex, extract_external_session_token_from_bytes,
    extract_raw_refresh_token_from_session_bytes, parse_session_payload_bytes,
    ExtractedExternalSessionToken,
};
use crate::store::fs_atomic::{
    ensure_no_symlink_components_under, map_io_error, read_regular_file_opt_bounded,
    write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use serde::Serialize;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Explicit external target application data directory (`--target <NAME>` or `--target-dir <DIR>`).
/// Holds both `<target_dir>/antigravity-oauth-token` (pure-file credential slot) and optional
/// `<target_dir>/conversations/*.db` (for `stats`), strictly decoupled from system Keyring,
/// official `~/.gemini/antigravity-cli`, `index.json::selected_account_id`, and `switch_journal.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSlotTarget {
    pub target_name: Option<String>,
    pub slot_dir: PathBuf,
    pub slot_file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalSlotTargetDto {
    pub name: Option<String>,
    pub target_dir: String,
    pub slot_file: String,
    pub backend: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalStatsTargetDto {
    pub name: Option<String>,
    pub target_dir: String,
}

impl ExternalSlotTarget {
    pub fn dto(&self) -> ExternalSlotTargetDto {
        ExternalSlotTargetDto {
            name: self.target_name.clone(),
            target_dir: self.slot_dir.to_string_lossy().into_owned(),
            slot_file: self.slot_file.to_string_lossy().into_owned(),
            backend: "file",
        }
    }

    pub fn stats_dto(&self) -> ExternalStatsTargetDto {
        ExternalStatsTargetDto {
            name: self.target_name.clone(),
            target_dir: self.slot_dir.to_string_lossy().into_owned(),
        }
    }

    pub fn display_label(&self) -> String {
        match self.target_name.as_deref() {
            Some(name) => format!("target `{name}` ({})", self.slot_dir.display()),
            None => format!("target dir '{}'", self.slot_dir.display()),
        }
    }

    pub fn short_label(&self) -> String {
        match self.target_name.as_deref() {
            Some(name) => format!("{name} ({})", self.slot_dir.display()),
            None => self.slot_dir.display().to_string(),
        }
    }

    pub fn lock_file(&self, paths: &HeadlessPaths) -> PathBuf {
        paths.slot_lock_file_for_path(&self.slot_file)
    }

    /// Resolve an explicit `--target <NAME>` or `--target-dir <DIR>` against `paths` and `config.json`.
    /// When `enforce_pure_file_backend` is true (credential commands), rejects explicit CLI `--backend keyring`.
    /// Rejects secret-like inputs, file paths (including trailing `/antigravity-oauth-token`),
    /// and collisions with official `~/.gemini/antigravity-cli`, `~/.gemini/antigravity`, or store/cache dirs.
    pub fn resolve(
        paths: &HeadlessPaths,
        cfg: &HeadlessConfig,
        cli_explicit_backend: Option<&str>,
        target_name: Option<&str>,
        target_dir_arg: Option<&Path>,
        enforce_pure_file_backend: bool,
    ) -> CliResult<Option<Self>> {
        if target_name.is_none() && target_dir_arg.is_none() {
            return Ok(None);
        }

        if enforce_pure_file_backend {
            if let Some(raw_backend) = cli_explicit_backend {
                if parse_backend_choice_literal(raw_backend)? == BackendChoice::Keyring {
                    return Err(CliError::usage(
                        "External target directories (`--target` / `--target-dir`) use pure file storage and cannot be combined with `--backend keyring`.",
                    ));
                }
            }
        }

        let (resolved_name, normalized_dir) = if let Some(name) = target_name {
            if target_name_looks_like_secret(name) {
                return Err(CliError::usage(
                    "`--target` expects a configured target alias name, not a literal credential value (redacted).",
                ));
            }
            if !is_valid_target_name(name) {
                return Err(CliError::usage(
                    "Invalid `--target` alias name. Names must match `[A-Za-z0-9][A-Za-z0-9._-]*` (1..=64 chars) and must not be `default`.",
                ));
            }
            let raw_configured = cfg.targets.get(name).ok_or_else(|| {
                CliError::new(
                    ExitCode::InvalidUsageOrAmbiguous,
                    "unknown_target",
                    "Requested `--target` alias is not defined in `config.json` (`targets`).",
                )
            })?;
            let expanded = expand_config_target_dir(paths, raw_configured)?;
            (Some(name.to_string()), expanded)
        } else if let Some(raw_path) = target_dir_arg {
            if raw_path.as_os_str().is_empty() {
                return Err(CliError::usage("`--target-dir` path cannot be empty."));
            }
            if path_looks_like_accidental_secret(raw_path) {
                return Err(CliError::usage(
                    "`--target-dir` expects a filesystem directory path, not a literal credential value (redacted).",
                ));
            }
            let normalized = normalize_lexical(raw_path, &paths.home_dir);
            (None, normalized)
        } else {
            return Ok(None);
        };

        validate_resolved_target_dir(&normalized_dir)?;
        let slot_file = normalized_dir.join(OFFICIAL_TOKEN_FILENAME);
        reject_reserved_target_collision(paths, &normalized_dir)?;

        Ok(Some(Self {
            target_name: resolved_name,
            slot_dir: normalized_dir,
            slot_file,
        }))
    }

    /// Pure read-only inspection of `<target_dir>/antigravity-oauth-token` with zero side effects.
    pub fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
        if let Err(e) = ensure_no_symlink_components_under(&paths.home_dir, &self.slot_dir) {
            return if e.error_code == "data_error" {
                SlotInspectState::Corrupt(e.message)
            } else {
                SlotInspectState::Unverified(e.message)
            };
        }
        match fs::symlink_metadata(&self.slot_dir) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_dir() => {}
            Ok(_) => {
                return SlotInspectState::Corrupt(format!(
                    "'{}' is not a real directory.",
                    self.slot_dir.display()
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return SlotInspectState::Uninitialized;
            }
            Err(e) => {
                return SlotInspectState::Unverified(format!(
                    "Cannot inspect '{}': {e}",
                    self.slot_dir.display()
                ));
            }
        }

        match read_regular_file_opt_bounded(
            &self.slot_file,
            MAX_STORE_FILE_BYTES,
            "External session file",
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

    pub fn ensure_slot_dir_initialized(&self, paths: &HeadlessPaths) -> CliResult<()> {
        ensure_no_symlink_components_under(&paths.home_dir, &self.slot_dir)?;
        match fs::symlink_metadata(&self.slot_dir) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_dir() => Ok(()),
            Ok(_) => Err(CliError::data(format!(
                "External target directory '{}' must be a real directory, not a file or symlink.",
                self.slot_dir.display()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(CliError::env_not_ready(
                "slot_dir_uninitialized",
                format!(
                    "External target directory '{}' does not exist. Initialize the target tool's profile directory before targeting it.",
                    self.slot_dir.display()
                ),
            )),
            Err(e) => Err(map_io_error(
                e,
                &format!(
                    "Cannot inspect external target directory '{}'",
                    self.slot_dir.display()
                ),
            )),
        }
    }

    /// Snapshot existing file bytes under strict symlink & regular-file checks (validating JSON
    /// when a file already exists so corrupt/foreign files are never silently overwritten).
    pub fn snapshot_valid_before_write(&self, paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>> {
        self.ensure_slot_dir_initialized(paths)?;
        let bytes = read_regular_file_opt_bounded(
            &self.slot_file,
            MAX_STORE_FILE_BYTES,
            "External session file",
        )?;
        if let Some(ref raw) = bytes {
            parse_session_payload_bytes(raw).map_err(|reason| {
                CliError::data(format!(
                    "External credential file '{}' is corrupt: {reason}",
                    self.slot_file.display()
                ))
            })?;
        }
        Ok(bytes)
    }

    /// Read raw `refresh_token` from `<target_dir>/antigravity-oauth-token`
    /// (`accounts add --from-local --target/--target-dir`).
    pub fn read_raw_refresh_token(&self, paths: &HeadlessPaths) -> CliResult<String> {
        self.ensure_slot_dir_initialized(paths)?;
        let Some(bytes) = read_regular_file_opt_bounded(
            &self.slot_file,
            MAX_STORE_FILE_BYTES,
            "External session file",
        )?
        else {
            return Err(CliError::env_not_ready(
                "external_credential_missing",
                format!(
                    "No `{OFFICIAL_TOKEN_FILENAME}` file found at '{}'.",
                    self.slot_file.display()
                ),
            ));
        };
        extract_raw_refresh_token_from_session_bytes(&bytes, "External agy session file")
    }

    /// Read full parsed token payload from `<target_dir>/antigravity-oauth-token`
    /// (for direct standalone refresh / quota probing).
    pub fn read_extracted_token(
        &self,
        paths: &HeadlessPaths,
    ) -> CliResult<ExtractedExternalSessionToken> {
        self.ensure_slot_dir_initialized(paths)?;
        let Some(bytes) = read_regular_file_opt_bounded(
            &self.slot_file,
            MAX_STORE_FILE_BYTES,
            "External session file",
        )?
        else {
            return Err(CliError::env_not_ready(
                "external_credential_missing",
                format!(
                    "No `{OFFICIAL_TOKEN_FILENAME}` file found at '{}'.",
                    self.slot_file.display()
                ),
            ));
        };
        extract_external_session_token_from_bytes(&bytes, "External agy session file")
    }

    /// Atomically replace `<target_dir>/antigravity-oauth-token` (`0600`, temp file, `fsync`,
    /// `rename`, and parent `fsync`) ONLY if the live file's SHA-256 digest still matches `expected_digest`.
    /// Caller MUST hold path-scoped L1 `ActiveSlotLock`.
    pub fn write_slot_cas(
        &self,
        paths: &HeadlessPaths,
        payload: &str,
        expected_digest: Option<&str>,
    ) -> CliResult<()> {
        self.ensure_slot_dir_initialized(paths)?;
        let live_bytes = read_regular_file_opt_bounded(
            &self.slot_file,
            MAX_STORE_FILE_BYTES,
            "External session file",
        )?;
        let live_digest = live_bytes.as_deref().map(bytes_sha256_hex);
        if live_digest.as_deref() != expected_digest {
            return Err(CliError::conflict(
                "external_slot_modified",
                format!(
                    "External credential slot '{}' was modified concurrently before write. Aborted without overwriting external changes.",
                    self.slot_file.display()
                ),
            ));
        }
        write_atomic_durable(&self.slot_file, payload.as_bytes())
    }
}

fn expand_config_target_dir(paths: &HeadlessPaths, raw: &str) -> CliResult<PathBuf> {
    let trimmed = raw.trim_end_matches('/');
    let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
        paths.home_dir.join(rest)
    } else if trimmed.starts_with('/') {
        PathBuf::from(trimmed)
    } else {
        return Err(CliError::data(
            "Configured target directory path must be an absolute path or start with `~/`.",
        ));
    };
    Ok(normalize_components(&expanded))
}

fn validate_resolved_target_dir(normalized: &Path) -> CliResult<()> {
    if normalized == Path::new("/") {
        return Err(CliError::usage(
            "External target directory cannot resolve to filesystem root `/`.",
        ));
    }
    if normalized.file_name() == Some(OsStr::new(OFFICIAL_TOKEN_FILENAME)) {
        let suggested = normalized
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<dir>".to_string());
        return Err(CliError::usage(format!(
            "External target path must be the directory containing `{OFFICIAL_TOKEN_FILENAME}`, not the token file itself. Pass `{suggested}` instead."
        )));
    }
    if fs::symlink_metadata(normalized).is_ok_and(|m| m.file_type().is_file()) {
        return Err(CliError::usage(format!(
            "External target path '{}' points to a regular file, not a directory.",
            normalized.display()
        )));
    }
    Ok(())
}

fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    let norm = normalize_components(path);
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = norm.as_path();
    while let Some(name) = cur.file_name() {
        suffix.push(name.to_os_string());
        let Some(parent) = cur.parent() else {
            break;
        };
        if let Ok(canon_parent) = fs::canonicalize(parent) {
            let mut out = canon_parent;
            for part in suffix.into_iter().rev() {
                out.push(part);
            }
            return normalize_components(&out);
        }
        cur = parent;
    }
    norm
}

fn paths_overlap_componentwise(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

fn reject_reserved_target_collision(paths: &HeadlessPaths, slot_dir: &Path) -> CliResult<()> {
    let norm_slot_dir = normalize_components(slot_dir);
    let canon_slot_dir = canonicalize_existing_prefix(slot_dir);

    let norm_official_cli = normalize_components(&paths.active_slot_dir);
    let canon_official_cli = canonicalize_existing_prefix(&paths.active_slot_dir);
    if paths_overlap_componentwise(&norm_slot_dir, &norm_official_cli)
        || paths_overlap_componentwise(&canon_slot_dir, &canon_official_cli)
    {
        return Err(CliError::usage(
            "Target directory overlaps the official `agy` CLI directory (`~/.gemini/antigravity-cli`). Omit `--target` / `--target-dir` (or use `stats --source cli`).",
        ));
    }

    let official_app_dir = paths.home_dir.join(".gemini").join("antigravity");
    let norm_official_app = normalize_components(&official_app_dir);
    let canon_official_app = canonicalize_existing_prefix(&official_app_dir);
    if paths_overlap_componentwise(&norm_slot_dir, &norm_official_app)
        || paths_overlap_componentwise(&canon_slot_dir, &canon_official_app)
    {
        return Err(CliError::usage(
            "Target directory overlaps the official Antigravity desktop directory (`~/.gemini/antigravity`). Use `stats --source app` for desktop usage statistics.",
        ));
    }

    for (label, reserved_root) in [("data", &paths.data_dir), ("cache", &paths.cache_dir)] {
        let norm_reserved = normalize_components(reserved_root);
        let canon_reserved = canonicalize_existing_prefix(reserved_root);
        if paths_overlap_componentwise(&norm_slot_dir, &norm_reserved)
            || paths_overlap_componentwise(&canon_slot_dir, &canon_reserved)
        {
            return Err(CliError::usage(format!(
                "Refusing to target an external directory overlapping agy-switch-cli's own {label} directory ('{}').",
                reserved_root.display()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn resolve_rejects_official_dirs_store_dir_token_file_and_keyring_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data = tmp.path().join("data");
        let cache = tmp.path().join("cache");
        let ext_dir = home.join(".t3/userdata/providers/antigravity/hash/antigravity-acp");
        fs::create_dir_all(&ext_dir).unwrap();
        fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
        fs::create_dir_all(home.join(".gemini/antigravity")).unwrap();
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&cache).unwrap();

        let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
        let mut cfg = HeadlessConfig::default();
        cfg.targets.insert(
            "t3".into(),
            "~/.t3/userdata/providers/antigravity/hash/antigravity-acp".into(),
        );

        // Valid `--target` expands `~/`
        let resolved = ExternalSlotTarget::resolve(&paths, &cfg, None, Some("t3"), None, true)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.target_name.as_deref(), Some("t3"));
        assert_eq!(resolved.slot_dir, ext_dir);
        assert_eq!(resolved.slot_file, ext_dir.join(OFFICIAL_TOKEN_FILENAME));

        // Explicit CLI `--backend keyring` rejected on credential commands, ignored on stats
        assert!(
            ExternalSlotTarget::resolve(&paths, &cfg, Some("keyring"), Some("t3"), None, true)
                .is_err()
        );
        assert!(ExternalSlotTarget::resolve(
            &paths,
            &cfg,
            Some("keyring"),
            Some("t3"),
            None,
            false
        )
        .is_ok());
        assert!(
            ExternalSlotTarget::resolve(&paths, &cfg, Some("file"), Some("t3"), None, true).is_ok()
        );
        assert!(
            ExternalSlotTarget::resolve(&paths, &cfg, Some("auto"), Some("t3"), None, true).is_ok()
        );
        assert!(
            ExternalSlotTarget::resolve(&paths, &cfg, Some("dual"), Some("t3"), None, true).is_ok()
        );

        // Token file path or regular file rejected (both direct and via alias expansion)
        let file_err = ExternalSlotTarget::resolve(
            &paths,
            &cfg,
            None,
            None,
            Some(&ext_dir.join(OFFICIAL_TOKEN_FILENAME)),
            true,
        )
        .unwrap_err();
        assert_eq!(file_err.exit_code, ExitCode::InvalidUsageOrAmbiguous);
        let settings = ext_dir.join("settings.json");
        fs::write(&settings, b"{}").unwrap();
        assert!(
            ExternalSlotTarget::resolve(&paths, &cfg, None, None, Some(&settings), true).is_err()
        );

        let mut bad_alias_cfg = cfg.clone();
        bad_alias_cfg
            .targets
            .insert("root_esc".into(), "/a/..".into());
        bad_alias_cfg.targets.insert(
            "token_esc".into(),
            "~/.t3/userdata/providers/antigravity/hash/antigravity-acp/antigravity-oauth-token/sub/..".into(),
        );
        bad_alias_cfg
            .targets
            .insert("file_alias".into(), settings.to_string_lossy().into_owned());
        for alias in ["root_esc", "token_esc", "file_alias"] {
            assert_eq!(
                ExternalSlotTarget::resolve(&paths, &bad_alias_cfg, None, Some(alias), None, true)
                    .unwrap_err()
                    .exit_code,
                ExitCode::InvalidUsageOrAmbiguous,
                "alias `{alias}` should fail shared post-normalization validation"
            );
        }

        // Bidirectional component-wise overlap rejected: exact, child, AND ancestor of official/data/cache
        for bad_dir in [
            paths.active_slot_dir.clone(),
            paths.active_slot_dir.join("conversations"),
            home.join(".gemini"),
            home.clone(),
            home.join(".gemini/antigravity"),
            home.join(".gemini/antigravity/conversations"),
            data.clone(),
            data.join("accounts"),
            cache.clone(),
            cache.join("locks"),
            tmp.path().to_path_buf(), // ancestor of data & cache
        ] {
            assert_eq!(
                ExternalSlotTarget::resolve(&paths, &cfg, None, None, Some(&bad_dir), true)
                    .unwrap_err()
                    .exit_code,
                ExitCode::InvalidUsageOrAmbiguous,
                "expected reserved collision rejection for '{}'",
                bad_dir.display()
            );
        }

        // Unknown, invalid, and secret-like aliases NEVER echo raw input!
        let missing = ExternalSlotTarget::resolve(
            &paths,
            &cfg,
            None,
            Some("missing_alias_marker"),
            None,
            true,
        )
        .unwrap_err();
        assert_eq!(missing.error_code, "unknown_target");
        assert_eq!(missing.exit_code, ExitCode::InvalidUsageOrAmbiguous);
        assert!(!missing.message.contains("missing_alias_marker"));

        let bad_syntax = ExternalSlotTarget::resolve(
            &paths,
            &cfg,
            None,
            Some("bad alias!SECRET_SYNTAX"),
            None,
            true,
        )
        .unwrap_err();
        assert_eq!(bad_syntax.error_code, "invalid_usage");
        assert_eq!(bad_syntax.exit_code, ExitCode::InvalidUsageOrAmbiguous);
        assert!(!bad_syntax.message.contains("SECRET_SYNTAX"));

        for secret_alias in [
            "1//0gFAKE_REFRESH_TOKEN_ALIAS_999",
            "GOCSPX-FAKE_CLIENT_SECRET_ALIAS_999",
            "ya29.FAKE_ACCESS_TOKEN_ALIAS_999",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        ] {
            let err =
                ExternalSlotTarget::resolve(&paths, &cfg, None, Some(secret_alias), None, true)
                    .unwrap_err();
            assert_eq!(err.error_code, "invalid_usage");
            assert_eq!(err.exit_code, ExitCode::InvalidUsageOrAmbiguous);
            assert!(
                !err.message.contains(secret_alias),
                "secret alias leaked in error: {}",
                err.message
            );
        }
    }

    #[test]
    fn external_slot_cas_write_and_symlink_rejection() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data = tmp.path().join("data");
        let cache = tmp.path().join("cache");
        let ext_dir = home.join("ext/antigravity-acp");
        fs::create_dir_all(&ext_dir).unwrap();
        let paths = HeadlessPaths::with_explicit(home.clone(), data, cache);
        let cfg = HeadlessConfig {
            targets: BTreeMap::new(),
            ..HeadlessConfig::default()
        };

        let target = ExternalSlotTarget::resolve(&paths, &cfg, None, None, Some(&ext_dir), true)
            .unwrap()
            .unwrap();

        assert!(matches!(
            target.inspect_slot(&paths),
            SlotInspectState::AbsentInInitializedDir
        ));

        let payload_a = r#"{"token":{"access_token":"ya29.a","token_type":"Bearer","refresh_token":"1//rt-a","expiry":"2099-01-01T00:00:00.000000Z"},"auth_method":"consumer"}"#;
        let payload_b = r#"{"token":{"access_token":"ya29.b","token_type":"Bearer","refresh_token":"1//rt-b","expiry":"2099-01-01T00:00:00.000000Z"},"auth_method":"consumer"}"#;

        target.write_slot_cas(&paths, payload_a, None).unwrap();
        let digest_a = bytes_sha256_hex(payload_a.as_bytes());

        let conflict = target.write_slot_cas(&paths, payload_b, None).unwrap_err();
        assert_eq!(conflict.error_code, "external_slot_modified");

        target
            .write_slot_cas(&paths, payload_b, Some(&digest_a))
            .unwrap();
        assert_eq!(fs::read_to_string(&target.slot_file).unwrap(), payload_b);

        fs::remove_file(&target.slot_file).unwrap();
        let other = ext_dir.join("decoy");
        fs::write(&other, payload_a).unwrap();
        std::os::unix::fs::symlink(&other, &target.slot_file).unwrap();
        assert!(matches!(
            target.inspect_slot(&paths),
            SlotInspectState::Corrupt(_)
        ));
    }
}
