use crate::error::{CliError, CliResult};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

/// Resolved directory topology for `agy-switch-cli` per Blueprint §2.1.
/// All paths can be explicitly overridden or derived from isolated `HOME` / `XDG_*` env vars.
#[derive(Debug, Clone)]
pub struct HeadlessPaths {
    pub home_dir: PathBuf,
    /// Independent versioned store (`~/.local/share/agy-switch-cli`, 0700)
    pub data_dir: PathBuf,
    /// User-global lock and cache scope (`~/.cache/agy-switch-cli`, 0700), never overridden by `--data-dir`
    pub cache_dir: PathBuf,
    /// Official `agy` session directory (`$HOME/.gemini/antigravity-cli`)
    pub active_slot_dir: PathBuf,
    /// Official `agy` token file (`$HOME/.gemini/antigravity-cli/antigravity-oauth-token`)
    pub active_slot_file: PathBuf,
}

impl HeadlessPaths {
    pub fn resolve(explicit_data_dir: Option<&Path>) -> CliResult<Self> {
        let home_dir = resolve_home_dir()?;
        let data_dir = if let Some(explicit) = explicit_data_dir {
            normalize_lexical(explicit, &home_dir)
        } else if let Some(env_dir) = non_empty_env_path("AGY_SWITCH_CLI_DATA_DIR") {
            normalize_lexical(&env_dir, &home_dir)
        } else if let Some(xdg_data) = non_empty_env_path("XDG_DATA_HOME") {
            normalize_lexical(&xdg_data, &home_dir).join("agy-switch-cli")
        } else {
            home_dir.join(".local").join("share").join("agy-switch-cli")
        };

        let cache_dir = if let Some(xdg_cache) = non_empty_env_path("XDG_CACHE_HOME") {
            normalize_lexical(&xdg_cache, &home_dir).join("agy-switch-cli")
        } else {
            home_dir.join(".cache").join("agy-switch-cli")
        };

        let active_slot_dir = home_dir.join(".gemini").join("antigravity-cli");
        let active_slot_file = active_slot_dir.join("antigravity-oauth-token");

        Ok(Self {
            home_dir,
            data_dir,
            cache_dir,
            active_slot_dir,
            active_slot_file,
        })
    }

    pub fn with_explicit(home_dir: PathBuf, data_dir: PathBuf, cache_dir: PathBuf) -> Self {
        let active_slot_dir = home_dir.join(".gemini").join("antigravity-cli");
        let active_slot_file = active_slot_dir.join("antigravity-oauth-token");
        Self {
            home_dir,
            data_dir,
            cache_dir,
            active_slot_dir,
            active_slot_file,
        }
    }

    pub fn index_file(&self) -> PathBuf {
        self.data_dir.join("index.json")
    }

    pub fn accounts_dir(&self) -> PathBuf {
        self.data_dir.join("accounts")
    }

    pub fn account_file(&self, id: &str) -> PathBuf {
        self.accounts_dir().join(format!("{id}.json"))
    }

    pub fn policy_file(&self) -> PathBuf {
        self.data_dir.join("policy.json")
    }

    pub fn config_file(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join("state")
    }

    pub fn switch_journal_file(&self) -> PathBuf {
        self.state_dir().join("switch_journal.json")
    }

    pub fn daemon_state_file(&self) -> PathBuf {
        self.state_dir().join("daemon_state.json")
    }

    pub fn auth_sequence_file(&self) -> PathBuf {
        self.state_dir().join("auth_sequence.json")
    }

    pub fn leases_dir(&self) -> PathBuf {
        self.state_dir().join("leases")
    }

    pub fn pending_auth_dir(&self) -> PathBuf {
        self.state_dir().join("pending_auth")
    }

    pub fn pending_auth_file(&self, id: &str) -> PathBuf {
        self.pending_auth_dir().join(format!("{id}.json"))
    }

    pub fn token_lineage_dir(&self) -> PathBuf {
        self.state_dir().join("token_lineage")
    }

    pub fn token_lineage_file(&self, account_id: &str) -> PathBuf {
        self.token_lineage_dir().join(format!("{account_id}.json"))
    }

    pub fn pending_lineage_dir(&self) -> PathBuf {
        self.state_dir().join("pending_lineage")
    }

    pub fn pending_lineage_file(&self, pending_id: &str) -> PathBuf {
        self.pending_lineage_dir()
            .join(format!("{pending_id}.json"))
    }

    pub fn store_locks_dir(&self) -> PathBuf {
        self.data_dir.join("locks")
    }

    pub fn store_lock_file(&self) -> PathBuf {
        self.store_locks_dir().join("store.lock")
    }

    pub fn daemon_lock_file(&self) -> PathBuf {
        self.store_locks_dir().join("daemon.lock")
    }

    pub fn account_refresh_lock_file(&self, account_id: &str) -> PathBuf {
        self.store_locks_dir()
            .join(format!("refresh-{account_id}.lock"))
    }

    pub fn pending_auth_lock_file(&self, pending_id: &str) -> PathBuf {
        self.store_locks_dir()
            .join(format!("pending-{pending_id}.lock"))
    }

    pub fn global_locks_dir(&self) -> PathBuf {
        self.cache_dir.join("locks")
    }

    pub fn ua_cache_file(&self) -> PathBuf {
        self.cache_dir.join("ua_version_cache.json")
    }

    /// Derive the unified L1 `ActiveSlotLock` path in `~/.cache/agy-switch-cli/locks/slot-<sha256>.lock`.
    /// Canonicalizes the home directory base (without requiring `.gemini/antigravity-cli` to exist yet)
    /// so ALL processes targeting the same `$HOME` active slot — regardless of `--data-dir` OR whether
    /// `--backend file` vs `--backend secret-service` is chosen — ALWAYS collide on the exact same lock file!
    pub fn active_slot_lock_file(&self) -> PathBuf {
        let canonical_home = std::fs::canonicalize(&self.home_dir)
            .unwrap_or_else(|_| normalize_components(&self.home_dir));
        let normalized_slot = canonical_home
            .join(".gemini")
            .join("antigravity-cli")
            .join("antigravity-oauth-token");
        let mut hasher = Sha256::new();
        hasher.update(normalized_slot.to_string_lossy().as_bytes());
        let digest = hex_encode(&hasher.finalize());
        self.global_locks_dir().join(format!("slot-{digest}.lock"))
    }

    /// Additional UID-scoped lock acquired SECOND (after `active_slot_lock_file`) when using `secret-service` backend.
    pub fn keyring_lock_file(&self) -> PathBuf {
        let uid = unsafe { libc::geteuid() };
        self.global_locks_dir().join(format!("keyring-{uid}.lock"))
    }

    pub fn default_legacy_dir(&self) -> PathBuf {
        self.home_dir.join(".antigravity_tools")
    }

    /// Guard against accidentally pointing `--data-dir` at a desktop `agy-switch` directory (`~/.antigravity_tools`).
    /// Per Blueprint §2.1: if legacy `accounts.json` exists and headless `index.json` is absent, reject in-place writes.
    pub fn ensure_not_legacy_store_dir(&self) -> CliResult<()> {
        let index_exists = self.index_file().exists();
        let legacy_accounts = self.data_dir.join("accounts.json");
        if !index_exists && legacy_accounts.exists() {
            return Err(CliError::data(format!(
                "Refusing to overwrite legacy desktop store at '{}'. Run `agy-switch-cli accounts import --from-legacy \"{}\"` into an independent data directory instead.",
                self.data_dir.display(),
                self.data_dir.display()
            )));
        }
        Ok(())
    }
}

fn resolve_home_dir() -> CliResult<PathBuf> {
    if let Some(home) = non_empty_env_path("HOME") {
        if home.is_absolute() {
            return Ok(normalize_components(&home));
        }
    }
    dirs::home_dir()
        .map(|p| normalize_components(&p))
        .ok_or_else(|| {
            CliError::env_not_ready("missing_home", "Cannot resolve user HOME directory.")
        })
}

fn non_empty_env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn normalize_lexical(path: &Path, base_if_relative: &Path) -> PathBuf {
    if path.is_absolute() {
        normalize_components(path)
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| base_if_relative.to_path_buf());
        normalize_components(&cwd.join(path))
    }
}

pub fn normalize_components(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::RootDir) => {}
                Some(Component::Normal(_))
                    if !std::fs::symlink_metadata(&out)
                        .is_ok_and(|m| m.file_type().is_symlink()) =>
                {
                    out.pop();
                }
                _ => out.push(".."),
            },
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}
