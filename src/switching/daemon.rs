use crate::cli::dto::{terminal_text, JsonSuccessEnvelope};
use crate::domain::account::{RuntimeState, SessionIdentity, STORE_SCHEMA_VERSION};
use crate::domain::clock::{AnchoredClock, Clock, SystemClock};
use crate::domain::policy::{PolicyMode, PolicyStrategy, SwitchPolicy};
use crate::domain::quota::{
    cached_candidate_known_below_min_before_reset, evaluate_account_quota,
    evaluate_account_window_quotas, QuotaEval, DEFAULT_QUOTA_MAX_AGE_SECS,
};
use crate::error::{format_safe_json_error, CliError, CliResult, ExitCode};
use crate::oauth::registry::OAuthClientRegistry;
use crate::paths::HeadlessPaths;
use crate::quota::official_cli::{
    refresh_active_slot_quota_detailed, OfficialCliQuotaRunner, RefreshActiveSlotError,
    SystemOfficialCliRunner,
};
use crate::session::backend::{CredentialBackend, SlotInspectState};
use crate::session::journal::{
    journal_on_disk_may_need_keyring, read_journal_readonly, read_journal_record_readonly,
    reconcile_journal_locked, JournalReplicaRecord,
};
use crate::session::payload::resolve_session_identity;
use crate::session::process::observe_runtime_state;
use crate::store::fs_atomic::{
    ensure_no_symlink_components_under, ensure_private_dir, read_regular_file_opt_bounded,
    write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use crate::store::locks::{ActiveSlotLock, DaemonInstanceLock, DaemonLockProbe};
use crate::store::repository::StoreRepository;
use crate::switching::executor::{
    execute_switch_with_slot_lock_and_guard, extract_verified_checkpoint_from_replicas,
    replica_inspection_matches_expectation, slot_matches_selected_rotated_account,
    PreSwitchSlotExpectation, RunningGuardMode,
};
use crate::switching::notify::{
    resolve_effective_notify_enabled, resolve_effective_notify_persistent,
    send_daemon_notification_best_effort, DaemonNotificationEvent,
};
use crate::switching::runner::ordered_candidate_ids;
use crate::switching::systemd::DaemonSystemdProbe;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::MissedTickBehavior;

pub const DEFAULT_DAEMON_INTERVAL_SECS: u64 = 900;
pub const DEFAULT_DAEMON_COOLDOWN_SECS: i64 = 3600;
pub const DEFAULT_TICK_HARD_TIMEOUT: Duration = Duration::from_secs(180);
pub const DEFAULT_STEP_BUFFER_DELAY: Duration = Duration::from_secs(2);
pub const MAX_CONSECUTIVE_COMMIT_FAILURES: u32 = 3;
pub const CANDIDATE_REFRESH_BACKOFF_SECS: i64 = 900;
const ONCE_ALREADY_LOW_GRACE_SECS: i64 = 15;

/// Compute the active-account quota cache max-age for `Wait`-mode pending-plan revalidation
/// and continuous-mode ultra-fresh low-quota grace bounds.
/// Scales to `80%` of the effective tick interval (min `1s`, capped at `DEFAULT_QUOTA_MAX_AGE_SECS`).
/// Eligible scheduled daemon wake-ups explicitly refresh the active account directly rather than
/// inferring staleness from wall-clock elapsed age.
pub fn effective_source_quota_max_age_secs(interval_secs: u64) -> i64 {
    let effective_interval = interval_secs.max(5);
    ((effective_interval.saturating_mul(8)) / 10)
        .max(1)
        .min(DEFAULT_QUOTA_MAX_AGE_SECS as u64) as i64
}

/// Durable daemon state persisted at `<data_dir>/state/daemon_state.json` (`0600`) per Blueprint §7.2.
/// Contains ZERO credentials or emails — only account IDs, cursors, timestamps, and structured reasons.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonPersistentState {
    pub schema_version: u32,
    pub cooldown_until: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotated_candidate_id: Option<String>,
    pub consecutive_commit_failures: u32,
    pub paused_on_failure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_reason: Option<String>,
    pub last_phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<i64>,
}

impl Default for DaemonPersistentState {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            cooldown_until: 0,
            last_rotated_candidate_id: None,
            consecutive_commit_failures: 0,
            paused_on_failure: false,
            paused_reason: None,
            last_phase: "idle".into(),
            last_reason: None,
            last_checked_at: None,
        }
    }
}

pub fn read_daemon_state_readonly(paths: &HeadlessPaths) -> CliResult<DaemonPersistentState> {
    let path = paths.daemon_state_file();
    ensure_no_symlink_components_under(&paths.data_dir, &path)?;
    let Some(bytes) =
        read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Daemon state file")?
    else {
        return Ok(DaemonPersistentState::default());
    };
    let state: DaemonPersistentState = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::data(format_safe_json_error(
            &format!("Daemon state file '{}'", path.display()),
            &e,
        ))
    })?;
    if state.schema_version != STORE_SCHEMA_VERSION {
        return Err(CliError::data(format!(
            "Unsupported daemon state schema_version {} in '{}' (expected {}).",
            state.schema_version,
            path.display(),
            STORE_SCHEMA_VERSION
        )));
    }
    Ok(state)
}

pub fn save_daemon_state_in_tx(
    paths: &HeadlessPaths,
    state: &DaemonPersistentState,
) -> CliResult<()> {
    let target = paths.daemon_state_file();
    ensure_no_symlink_components_under(&paths.data_dir, &target)?;
    ensure_private_dir(&paths.state_dir())?;
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|_| CliError::data("Failed to serialize daemon_state.json."))?;
    write_atomic_durable(&target, &bytes)
}

pub fn clear_daemon_pause_in_tx(paths: &HeadlessPaths, now_unix: i64) -> CliResult<()> {
    let ds_path = paths.daemon_state_file();
    ensure_no_symlink_components_under(&paths.data_dir, &ds_path)?;
    let meta = match std::fs::symlink_metadata(&ds_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(crate::store::fs_atomic::map_io_error(
                e,
                &format!("Cannot inspect daemon state file '{}'", ds_path.display()),
            ));
        }
    };
    if !meta.file_type().is_file() {
        return Ok(());
    }
    let mut st = read_daemon_state_readonly(paths)?;
    if st.paused_on_failure || st.consecutive_commit_failures > 0 {
        st.paused_on_failure = false;
        st.paused_reason = None;
        st.consecutive_commit_failures = 0;
        st.last_phase = "monitoring".into();
        st.last_reason = Some("pause_cleared_by_user_action".into());
        st.last_checked_at = Some(now_unix);
        save_daemon_state_in_tx(paths, &st)?;
    }
    Ok(())
}

/// Used under `L3` on manual switch / policy updates: tightens `0600` permissions, clears failure pause on valid
/// `daemon_state.json`, or resets a corrupted regular `daemon_state.json` while leaving non-regular files (FIFO/symlink/dir) untouched.
/// Propagates save/permission errors so callers NEVER disguise an un-cleared pause state as recovered!
pub fn repair_or_clear_daemon_state_in_tx(
    paths: &HeadlessPaths,
    now_unix: i64,
) -> CliResult<Option<String>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let ds_path = paths.daemon_state_file();
    ensure_no_symlink_components_under(&paths.data_dir, &ds_path)?;
    let meta = match std::fs::symlink_metadata(&ds_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(crate::store::fs_atomic::map_io_error(
                e,
                &format!("Cannot inspect daemon state file '{}'", ds_path.display()),
            ));
        }
    };
    if !meta.file_type().is_file() {
        return Ok(None);
    }
    if (meta.permissions().mode() & 0o077) != 0 {
        let c_path = std::ffi::CString::new(ds_path.as_os_str().as_bytes())
            .map_err(|_| CliError::data("Daemon state file path contains NUL byte."))?;
        let raw_fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            return Err(crate::store::fs_atomic::map_io_error(
                std::io::Error::last_os_error(),
                &format!(
                    "Failed to open daemon state file '{}' to tighten permissions",
                    ds_path.display()
                ),
            ));
        }
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(owned_fd.as_raw_fd(), &mut st) } != 0 {
            return Err(crate::store::fs_atomic::map_io_error(
                std::io::Error::last_os_error(),
                &format!("Failed to stat daemon state file '{}'", ds_path.display()),
            ));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Ok(None);
        }
        if unsafe { libc::fchmod(owned_fd.as_raw_fd(), 0o600) } != 0 {
            return Err(crate::store::fs_atomic::map_io_error(
                std::io::Error::last_os_error(),
                &format!(
                    "Failed to tighten permissions on daemon state file '{}'",
                    ds_path.display()
                ),
            ));
        }
    }
    match read_daemon_state_readonly(paths) {
        Ok(mut st) => {
            if st.paused_on_failure || st.consecutive_commit_failures > 0 {
                st.paused_on_failure = false;
                st.paused_reason = None;
                st.consecutive_commit_failures = 0;
                st.last_phase = "monitoring".into();
                st.last_reason = Some("pause_cleared_by_user_action".into());
                st.last_checked_at = Some(now_unix);
                save_daemon_state_in_tx(paths, &st)?;
                return Ok(Some(
                    "Cleared daemon failure pause in daemon_state.json.".into(),
                ));
            }
            Ok(None)
        }
        Err(_) => {
            let reset = DaemonPersistentState {
                last_checked_at: Some(now_unix),
                ..DaemonPersistentState::default()
            };
            save_daemon_state_in_tx(paths, &reset)?;
            Ok(Some("Reset corrupted daemon_state.json.".into()))
        }
    }
}

/// Outcome returned by `reset_daemon_cooldown` (`daemon --reset-cooldown`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResetCooldownOutcome {
    pub cooldown_reset: bool,
    pub cooldown_was_active: bool,
    pub previous_cooldown_until: i64,
}

/// Clear any persisted post-switch cooldown (`cooldown_until = 0`) in `state/daemon_state.json`
/// strictly under `L3` (`StoreWriteLock`) without acquiring `DaemonInstanceLock`.
/// Safe to invoke concurrently while a `systemd --user` or foreground `daemon` is running.
/// Preserves `last_rotated_candidate_id`, `paused_on_failure`, `consecutive_commit_failures`,
/// and `paused_reason`; idempotent when the state file is absent or already has `cooldown_until == 0`.
pub fn reset_daemon_cooldown(
    repo: &StoreRepository,
    now_unix: i64,
) -> CliResult<ResetCooldownOutcome> {
    repo.with_write_lock(|tx| reset_daemon_cooldown_in_tx(tx.paths(), now_unix))
}

pub fn reset_daemon_cooldown_in_tx(
    paths: &HeadlessPaths,
    now_unix: i64,
) -> CliResult<ResetCooldownOutcome> {
    let ds_path = paths.daemon_state_file();
    ensure_no_symlink_components_under(&paths.data_dir, &ds_path)?;
    match std::fs::symlink_metadata(&ds_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ResetCooldownOutcome {
                cooldown_reset: true,
                cooldown_was_active: false,
                previous_cooldown_until: 0,
            });
        }
        Err(e) => {
            return Err(crate::store::fs_atomic::map_io_error(
                e,
                &format!("Cannot inspect daemon state file '{}'", ds_path.display()),
            ));
        }
    }

    let mut st = read_daemon_state_readonly(paths)?;
    let previous = st.cooldown_until;
    let was_active = previous > now_unix;
    if st.cooldown_until != 0 {
        st.cooldown_until = 0;
        if !st.paused_on_failure && st.last_phase == "cooldown" {
            st.last_phase = "monitoring".into();
            st.last_reason = Some("cooldown_reset_by_user".into());
            st.last_checked_at = Some(now_unix);
        }
        save_daemon_state_in_tx(paths, &st)?;
    }
    Ok(ResetCooldownOutcome {
        cooldown_reset: true,
        cooldown_was_active: was_active,
        previous_cooldown_until: previous,
    })
}

/// Strictly read-only runtime & service status summary reported by `agy-switch-cli status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DaemonRuntimeStatusDto {
    pub mode: &'static str,
    pub running: bool,
    pub pid: Option<u32>,
    pub systemd_unit_installed: bool,
    pub systemd_active_state: Option<String>,
    pub systemd_unit_file_state: Option<String>,
    pub cooldown_active: bool,
    pub cooldown_remaining_secs: i64,
}

fn format_compact_cooldown_remaining(rem_secs: i64) -> String {
    if rem_secs >= 3600 {
        format!("{}h {:02}m", rem_secs / 3600, (rem_secs % 3600) / 60)
    } else if rem_secs >= 60 {
        format!("{}m", rem_secs / 60)
    } else {
        "<1m".into()
    }
}

pub fn build_daemon_runtime_status(
    lock: DaemonLockProbe,
    systemd: &DaemonSystemdProbe,
    state: Option<&DaemonPersistentState>,
    now_unix: i64,
) -> DaemonRuntimeStatusDto {
    let (systemd_unit_installed, systemd_active_state, systemd_unit_file_state, systemd_main_pid) =
        match systemd {
            DaemonSystemdProbe::NotInstalled | DaemonSystemdProbe::InstalledForOtherDataDir => {
                (false, None, None, None)
            }
            DaemonSystemdProbe::InstalledManagerUnreachable => (true, None, None, None),
            DaemonSystemdProbe::Installed {
                active_state,
                unit_file_state,
                main_pid,
            } => (
                true,
                active_state.clone(),
                unit_file_state.clone(),
                *main_pid,
            ),
        };

    let systemd_is_active = matches!(
        systemd_active_state.as_deref(),
        Some("active" | "activating" | "reloading")
    );

    let (mode, running, pid) = if lock.running {
        match (systemd_is_active, lock.pid, systemd_main_pid) {
            (true, Some(lp), Some(sp)) if lp == sp => ("systemd_service", true, Some(lp)),
            _ => ("manual", true, lock.pid),
        }
    } else if systemd_unit_installed {
        ("systemd_stopped", false, None)
    } else {
        ("not_running", false, None)
    };

    let cooldown_remaining_secs = state
        .map(|s| s.cooldown_until.saturating_sub(now_unix).max(0))
        .unwrap_or(0);

    DaemonRuntimeStatusDto {
        mode,
        running,
        pid,
        systemd_unit_installed,
        systemd_active_state,
        systemd_unit_file_state,
        cooldown_active: cooldown_remaining_secs > 0,
        cooldown_remaining_secs,
    }
}

impl DaemonRuntimeStatusDto {
    pub fn format_human(&self, state: Option<&DaemonPersistentState>) -> String {
        let mut out = match self.mode {
            "systemd_service" => match self.pid {
                Some(p) => format!("running (systemd service, pid={p})"),
                None => "running (systemd service)".into(),
            },
            "manual" => {
                let pid_part = self.pid.map(|p| format!(", pid={p}")).unwrap_or_default();
                if self.systemd_unit_installed {
                    let svc = self
                        .systemd_active_state
                        .as_deref()
                        .map(terminal_text)
                        .unwrap_or_else(|| "manager unreachable".into());
                    format!("running (manual/foreground{pid_part}; systemd service {svc})")
                } else {
                    format!("running (manual/foreground{pid_part})")
                }
            }
            "systemd_stopped" => match self.systemd_active_state.as_deref() {
                Some(st) if matches!(st, "active" | "activating" | "reloading") => format!(
                    "stopped (systemd service {}, no lock held here; ready for --once)",
                    terminal_text(st)
                ),
                Some(st) => format!(
                    "stopped (systemd service {}; ready for --once)",
                    terminal_text(st)
                ),
                None => {
                    "stopped (systemd unit installed, manager unreachable; ready for --once)".into()
                }
            },
            _ => "not running (no service; ready for daemon / --once)".into(),
        };

        if self.cooldown_active {
            out.push_str(&format!(
                " · cooldown {}",
                format_compact_cooldown_remaining(self.cooldown_remaining_secs)
            ));
        }

        if let Some(st) = state.filter(|s| s.paused_on_failure) {
            if st.consecutive_commit_failures > 0 {
                let noun = if st.consecutive_commit_failures == 1 {
                    "failure"
                } else {
                    "failures"
                };
                out.push_str(&format!(
                    " · PAUSED: {} consecutive {noun}",
                    st.consecutive_commit_failures
                ));
            } else {
                out.push_str(" · PAUSED (run switch or policy set to resume)");
            }
        }

        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct DaemonPolicyOverlay {
    pub mode: Option<PolicyMode>,
    pub strategy: Option<PolicyStrategy>,
    pub reserve_percentage: Option<u8>,
    pub candidate_min_percentage: Option<u8>,
    pub monitored_model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DaemonConfigOverrides {
    pub interval_secs: u64,
    pub cooldown_secs: i64,
    pub tick_timeout: Duration,
    pub step_buffer_delay: Duration,
    pub explicit_file_backend: bool,
    pub once: bool,
    pub reset_cooldown: bool,
    pub json_mode: bool,
    pub notify_override: Option<bool>,
    pub policy_overlay: DaemonPolicyOverlay,
}

impl Default for DaemonConfigOverrides {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_DAEMON_INTERVAL_SECS,
            cooldown_secs: DEFAULT_DAEMON_COOLDOWN_SECS,
            tick_timeout: DEFAULT_TICK_HARD_TIMEOUT,
            step_buffer_delay: DEFAULT_STEP_BUFFER_DELAY,
            explicit_file_backend: false,
            once: false,
            reset_cooldown: false,
            json_mode: false,
            notify_override: None,
            policy_overlay: DaemonPolicyOverlay::default(),
        }
    }
}

fn resolve_account_notify_label(
    snap: Option<&crate::store::repository::StoreSnapshot>,
    id: &str,
) -> String {
    snap.and_then(|s| s.accounts.iter().find(|a| a.id == id))
        .map(format_account_notify_label)
        .unwrap_or_else(|| id.to_string())
}

fn format_account_notify_label(acc: &crate::domain::account::AccountRecord) -> String {
    if let Some(ref lbl) = acc.custom_label {
        let clean = crate::cli::dto::terminal_text(lbl)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !clean.is_empty() {
            return format!("{} ({clean})", acc.email);
        }
    }
    acc.email.clone()
}

async fn notify_paused_on_failure(
    repo: &StoreRepository,
    notify_override: Option<bool>,
    stage: &str,
    target_account_id: Option<&str>,
    pstate: &DaemonPersistentState,
    reason: &str,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    if *shutdown_rx.borrow() || !resolve_effective_notify_enabled(repo, false, notify_override) {
        return;
    }
    let target_account = target_account_id.map(|id| {
        let snap = repo.read_snapshot().ok();
        resolve_account_notify_label(snap.as_ref(), id)
    });
    send_daemon_notification_best_effort(
        &DaemonNotificationEvent::PausedOnFailure {
            stage: stage.to_string(),
            target_account,
            consecutive_failures: pstate.consecutive_commit_failures,
            max_failures: MAX_CONSECUTIVE_COMMIT_FAILURES,
            reason: reason.to_string(),
        },
        true,
        shutdown_rx,
    )
    .await;
}

/// Resolve effective daemon policy strictly following Blueprint §7.3 priority:
/// `daemon CLI flags > environment variables > policy.json > SwitchPolicy::default()`,
/// without ever writing temporary overrides back to `policy.json`.
pub fn resolve_effective_daemon_policy(
    repo: &StoreRepository,
    overlay: &DaemonPolicyOverlay,
) -> CliResult<(SwitchPolicy, u64)> {
    let mut policy = repo.read_policy()?;
    let disk_revision = policy.revision;

    // 1. Environment variable layer (`AGY_SWITCH_CLI_*`) — never echo raw env values on error!
    if let Some(raw_mode) = non_empty_env("AGY_SWITCH_CLI_MODE") {
        policy.mode = match raw_mode.to_ascii_lowercase().as_str() {
            "immediate" => PolicyMode::Immediate,
            "wait" => PolicyMode::Wait,
            _ => {
                return Err(CliError::usage(
                    "Invalid AGY_SWITCH_CLI_MODE value (expected `immediate` or `wait`).",
                ))
            }
        };
    }
    if let Some(raw_strat) = non_empty_env("AGY_SWITCH_CLI_STRATEGY") {
        policy.strategy = match raw_strat.to_ascii_lowercase().as_str() {
            "priority" => PolicyStrategy::Priority,
            "round-robin" => PolicyStrategy::RoundRobin,
            _ => {
                return Err(CliError::usage(
                    "Invalid AGY_SWITCH_CLI_STRATEGY value (expected `priority` or `round-robin`).",
                ));
            }
        };
    }
    if let Some(raw_res) = non_empty_env("AGY_SWITCH_CLI_RESERVE") {
        policy.reserve_percentage = raw_res.parse::<u8>().map_err(|_| {
            CliError::usage("Invalid AGY_SWITCH_CLI_RESERVE value (expected integer 1..=98).")
        })?;
    }
    if let Some(raw_min) = non_empty_env("AGY_SWITCH_CLI_MINIMUM") {
        policy.candidate_min_percentage = raw_min.parse::<u8>().map_err(|_| {
            CliError::usage("Invalid AGY_SWITCH_CLI_MINIMUM value (expected integer 2..=100).")
        })?;
    }
    if let Some(raw_model) = non_empty_env("AGY_SWITCH_CLI_MODEL") {
        policy.monitored_model = raw_model;
    }

    // 2. Explicit CLI flag layer (highest priority)
    if let Some(m) = overlay.mode {
        policy.mode = m;
    }
    if let Some(s) = overlay.strategy {
        policy.strategy = s;
    }
    if let Some(r) = overlay.reserve_percentage {
        policy.reserve_percentage = r;
    }
    if let Some(min) = overlay.candidate_min_percentage {
        policy.candidate_min_percentage = min;
    }
    if let Some(ref model) = overlay.monitored_model {
        policy.monitored_model = model.clone();
    }

    policy.validate(None).map_err(CliError::usage)?;
    Ok((policy, disk_revision))
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TickStageOutcome {
    Disabled,
    PausedOnFailure {
        reason: String,
    },
    InCooldown {
        until: i64,
    },
    IdleSufficientQuota,
    UncertainHold {
        reason: String,
    },
    NoQualifiedCandidate {
        reason: String,
    },
    BlockedByActiveProcess {
        target_id: String,
    },
    CancelledStalePlan {
        reason: String,
    },
    CommittedSwitch {
        source_id: String,
        target_id: String,
    },
    CommitFailed {
        reason: String,
        paused: bool,
    },
}

/// Structured observation emitted for every completed daemon tick (used for both human/journalctl
/// status lines and `daemon --once --json` output). Never includes tokens or secrets.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonTickReport {
    pub checked_at: i64,
    pub outcome: TickStageOutcome,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitored_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserve_percentage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_min_percentage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_remaining_percentage: Option<f64>,
    pub source_refreshed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_remaining_percentage: Option<f64>,
}

#[derive(Debug, Clone, Default)]
struct TickReportCtx {
    monitored_model: Option<String>,
    reserve_percentage: Option<u8>,
    candidate_min_percentage: Option<u8>,
    source_account_id: Option<String>,
    source_email: Option<String>,
    source_remaining_percentage: Option<f64>,
    source_refreshed: bool,
    target_account_id: Option<String>,
    target_email: Option<String>,
    target_remaining_percentage: Option<f64>,
}

impl TickReportCtx {
    fn into_report(
        self,
        checked_at: i64,
        phase: &str,
        reason: Option<String>,
        outcome: TickStageOutcome,
    ) -> DaemonTickReport {
        DaemonTickReport {
            checked_at,
            outcome,
            phase: phase.to_string(),
            reason,
            monitored_model: self.monitored_model,
            reserve_percentage: self.reserve_percentage,
            candidate_min_percentage: self.candidate_min_percentage,
            source_account_id: self.source_account_id,
            source_email: self.source_email,
            source_remaining_percentage: self.source_remaining_percentage,
            source_refreshed: self.source_refreshed,
            target_account_id: self.target_account_id,
            target_email: self.target_email,
            target_remaining_percentage: self.target_remaining_percentage,
        }
    }
}

pub(crate) fn format_local_ts(unix_secs: i64) -> String {
    if let Ok(ts) = jiff::Timestamp::from_second(unix_secs) {
        let zdt = ts.to_zoned(jiff::tz::TimeZone::system());
        return zdt.strftime("%Y-%m-%d %H:%M:%S").to_string();
    }
    unix_secs.to_string()
}

fn format_pct_short(pct: f64) -> String {
    let clamped = pct.clamp(0.0, 100.0);
    if (clamped - clamped.round()).abs() < 0.05 {
        format!("{}%", clamped.round() as u8)
    } else {
        format!("{clamped:.1}%")
    }
}

fn is_safe_daemon_code_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn safe_daemon_error_code(raw: &str) -> String {
    let trimmed = raw.trim();
    if is_safe_daemon_code_token(trimmed) {
        trimmed.to_string()
    } else {
        "internal_error".to_string()
    }
}

fn sanitize_daemon_tick_error(err: CliError) -> CliError {
    let code = safe_daemon_error_code(&err.error_code);
    CliError::new(
        err.exit_code,
        code.clone(),
        format!("daemon tick failed (code: {code}; run `agy-switch-cli status` to inspect)"),
    )
}

/// Normalize any persisted `paused_reason` (including legacy free-text records written by older
/// versions that may embed local filesystem paths) into a strict path-free reason code before
/// emitting it in `DaemonTickReport`, JSON, or human output.
fn sanitize_persisted_paused_reason(raw: Option<&str>) -> String {
    let Some(text) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return "paused_on_failure".to_string();
    };
    if is_safe_daemon_code_token(text) {
        return text.to_string();
    }
    if let Some(code) = text.strip_prefix("commit_failed: ") {
        if is_safe_daemon_code_token(code) {
            return format!("commit_failed: {code}");
        }
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("corrupted switch journal") || lower.contains("switch journal is corrupt") {
        return "corrupted_switch_journal".to_string();
    }
    if lower.contains("incomplete switch recovery") || lower.contains("recovery_incomplete") {
        return "incomplete_switch_recovery".to_string();
    }
    if lower.contains("paused after") && lower.contains("failure") {
        return "consecutive_commit_failures".to_string();
    }
    "paused_on_failure".to_string()
}

impl DaemonTickReport {
    pub fn format_human_line(&self) -> String {
        let ts = format_local_ts(self.checked_at);
        let src_label = match (
            self.source_account_id.as_deref(),
            self.source_email.as_deref(),
        ) {
            (Some(id), Some(email)) => {
                format!("{} ({})", terminal_text(id), terminal_text(email))
            }
            (Some(id), None) => terminal_text(id),
            _ => "none".to_string(),
        };
        let freshness = if self.source_refreshed {
            "refreshed live"
        } else {
            "cached"
        };

        match &self.outcome {
            TickStageOutcome::Disabled => format!(
                "[{ts}] daemon: disabled — auto-switch policy is disabled (run `agy-switch-cli policy enable`)"
            ),
            TickStageOutcome::PausedOnFailure { reason } => format!(
                "[{ts}] daemon: paused — failure pause active (reason: {}; run `agy-switch-cli status` to inspect)",
                terminal_text(reason)
            ),
            TickStageOutcome::InCooldown { until } => {
                let until_str = format_local_ts(*until);
                let rem = until.saturating_sub(self.checked_at).max(0);
                format!(
                    "[{ts}] daemon: cooldown — active until {until_str} (remaining {rem}s)"
                )
            }
            TickStageOutcome::IdleSufficientQuota => {
                let pct = self
                    .source_remaining_percentage
                    .map(format_pct_short)
                    .unwrap_or_else(|| "?".to_string());
                let res = self.reserve_percentage.unwrap_or(0);
                let model = self
                    .monitored_model
                    .as_deref()
                    .map(terminal_text)
                    .unwrap_or_else(|| "all".to_string());
                format!(
                    "[{ts}] daemon: monitoring — active {src_label} quota {pct} > reserve {res}% (model: {model}, {freshness})"
                )
            }
            TickStageOutcome::NoQualifiedCandidate { reason } => {
                let pct = self
                    .source_remaining_percentage
                    .map(format_pct_short)
                    .unwrap_or_else(|| "?".to_string());
                let res = self.reserve_percentage.unwrap_or(0);
                let min_pct = self.candidate_min_percentage.unwrap_or(0);
                if reason == "no_qualified_candidate" {
                    format!(
                        "[{ts}] daemon: no_candidate — active {src_label} quota {pct} <= reserve {res}%, no candidate >= minimum {min_pct}% ({freshness})"
                    )
                } else {
                    format!(
                        "[{ts}] daemon: no_candidate — active {src_label} quota {pct} <= reserve {res}% (reason: {}, {freshness})",
                        terminal_text(reason)
                    )
                }
            }
            TickStageOutcome::BlockedByActiveProcess { target_id } => format!(
                "[{ts}] daemon: waiting — active agy process running, deferred switch to {} (mode: wait)",
                terminal_text(target_id)
            ),
            TickStageOutcome::CancelledStalePlan { reason } => format!(
                "[{ts}] daemon: cancelled — stale switch plan cancelled (reason: {})",
                terminal_text(reason)
            ),
            TickStageOutcome::UncertainHold { reason } => {
                if reason == "process_state_unverified" {
                    if self.source_account_id.is_some() {
                        format!(
                            "[{ts}] daemon: hold — reason=process_state_unverified (active {src_label}; run `agy-switch-cli status` to inspect)"
                        )
                    } else {
                        format!(
                            "[{ts}] daemon: hold — reason=process_state_unverified (run `agy-switch-cli status` to inspect)"
                        )
                    }
                } else if self.source_account_id.is_some() {
                    format!(
                        "[{ts}] daemon: hold — reason={} (active {src_label})",
                        terminal_text(reason)
                    )
                } else {
                    format!("[{ts}] daemon: hold — reason={}", terminal_text(reason))
                }
            }
            TickStageOutcome::CommittedSwitch {
                source_id,
                target_id,
            } => {
                let src_part = match (
                    self.source_email.as_deref(),
                    self.source_remaining_percentage,
                ) {
                    (Some(em), Some(p)) => format!(
                        "{} ({}, {})",
                        terminal_text(source_id),
                        terminal_text(em),
                        format_pct_short(p)
                    ),
                    (Some(em), None) => {
                        format!("{} ({})", terminal_text(source_id), terminal_text(em))
                    }
                    _ => terminal_text(source_id),
                };
                let tgt_part = match (
                    self.target_email.as_deref(),
                    self.target_remaining_percentage,
                ) {
                    (Some(em), Some(p)) => format!(
                        "{} ({}, {})",
                        terminal_text(target_id),
                        terminal_text(em),
                        format_pct_short(p)
                    ),
                    (Some(em), None) => {
                        format!("{} ({})", terminal_text(target_id), terminal_text(em))
                    }
                    _ => terminal_text(target_id),
                };
                format!(
                    "[{ts}] daemon: switched — active slot moved from {src_part} to {tgt_part}"
                )
            }
            TickStageOutcome::CommitFailed { reason, paused } => {
                let target = self
                    .target_account_id
                    .as_deref()
                    .map(terminal_text)
                    .unwrap_or_else(|| "target".to_string());
                format!(
                    "[{ts}] daemon: commit_failed — switch to {target} failed (paused={paused}, reason: {}; run `agy-switch-cli status` to inspect)",
                    terminal_text(reason)
                )
            }
        }
    }
}

/// In-memory runtime coordinator for the single-pass Step-and-Verify foreground `daemon`.
/// Periodically checks ONLY the active official slot via `agy -p "/usage"` (never polling dormant
/// accounts in the background) and performs bounded single-pass Step-and-Verify when quota drops
/// to or below `reserve_percentage`.
pub struct DaemonEngine {
    pub refresh_backoff_until: HashMap<String, i64>,
    pub last_low_quota_hold_notified_account: Option<String>,
    pub clock: Option<Arc<dyn Clock>>,
    /// Test hook invoked right before the first step switch under `L1` to deterministically
    /// simulate concurrent manual `switch` / `accounts delete` / `policy set`!
    pub before_revalidate_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Default for DaemonEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonEngine {
    pub fn new() -> Self {
        Self {
            refresh_backoff_until: HashMap::new(),
            last_low_quota_hold_notified_account: None,
            clock: None,
            before_revalidate_hook: None,
        }
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            refresh_backoff_until: HashMap::new(),
            last_low_quota_hold_notified_account: None,
            clock: Some(clock),
            before_revalidate_hook: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_single_tick(
        &mut self,
        repo: &StoreRepository,
        backend: &dyn CredentialBackend,
        runner: &dyn OfficialCliQuotaRunner,
        registry: &OAuthClientRegistry,
        overrides: &DaemonConfigOverrides,
        now_unix: i64,
    ) -> CliResult<TickStageOutcome> {
        let (_tx, mut dummy_rx) = tokio::sync::watch::channel(false);
        self.run_single_tick_with_shutdown(
            repo,
            backend,
            runner,
            registry,
            overrides,
            now_unix,
            &mut dummy_rx,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_single_tick_with_shutdown(
        &mut self,
        repo: &StoreRepository,
        backend: &dyn CredentialBackend,
        runner: &dyn OfficialCliQuotaRunner,
        registry: &OAuthClientRegistry,
        overrides: &DaemonConfigOverrides,
        now_unix: i64,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> CliResult<TickStageOutcome> {
        self.run_single_tick_report_with_shutdown(
            repo,
            backend,
            runner,
            registry,
            overrides,
            now_unix,
            shutdown_rx,
        )
        .await
        .map(|report| report.outcome)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_single_tick_report_with_shutdown(
        &mut self,
        repo: &StoreRepository,
        backend: &dyn CredentialBackend,
        runner: &dyn OfficialCliQuotaRunner,
        registry: &OAuthClientRegistry,
        overrides: &DaemonConfigOverrides,
        now_unix: i64,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> CliResult<DaemonTickReport> {
        let active_clock: Arc<dyn Clock> = match self.clock {
            Some(ref c) => c.clone(),
            None => Arc::new(AnchoredClock::new(now_unix)),
        };
        let tick_deadline = tokio::time::Instant::now() + overrides.tick_timeout;
        let mut rctx = TickReportCtx::default();

        let paths = repo.paths();
        let mut pstate = read_daemon_state_readonly(paths)?;

        if pstate.paused_on_failure {
            let reason = sanitize_persisted_paused_reason(pstate.paused_reason.as_deref());
            return Ok(rctx.into_report(
                active_clock.now_unix(),
                "paused_on_failure",
                Some(reason.clone()),
                TickStageOutcome::PausedOnFailure { reason },
            ));
        }

        // Reconcile any leftover `switch_journal.json` before reading `index.json`:
        // - `CommittedIndexPending` / `AbortedUncommitted` auto-reconcile cleanly;
        // - `RecoveryIncomplete` (or corrupted journal) transitions daemon into persistent `PausedOnFailure`!
        match read_journal_record_readonly(paths) {
            Ok(None) => {}
            Ok(Some((_, meta_opt))) => {
                let tick_now = active_clock.now_unix();
                let needs_kr = backend.uses_keyring()
                    || meta_opt
                        .as_ref()
                        .is_none_or(JournalReplicaRecord::needs_keyring);
                let mut slot_lock = match ActiveSlotLock::try_acquire(paths, needs_kr) {
                    Ok(l) => l,
                    Err(e) if e.exit_code == ExitCode::LockBusyOrConflict => {
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "lock_busy",
                            Some("slot_lock_busy"),
                            tick_now,
                        )?;
                        return Ok(rctx.into_report(
                            tick_now,
                            "lock_busy",
                            Some("slot_lock_busy".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "slot_lock_busy".into(),
                            },
                        ));
                    }
                    Err(e) => return Err(e),
                };
                if !slot_lock.includes_keyring_scope() && journal_on_disk_may_need_keyring(paths) {
                    drop(slot_lock);
                    slot_lock = match ActiveSlotLock::try_acquire(paths, true) {
                        Ok(l) => l,
                        Err(e) if e.exit_code == ExitCode::LockBusyOrConflict => {
                            self.persist_status(
                                repo,
                                &mut pstate,
                                "lock_busy",
                                Some("slot_lock_busy"),
                                tick_now,
                            )?;
                            return Ok(rctx.into_report(
                                tick_now,
                                "lock_busy",
                                Some("slot_lock_busy".into()),
                                TickStageOutcome::UncertainHold {
                                    reason: "slot_lock_busy".into(),
                                },
                            ));
                        }
                        Err(e) => return Err(e),
                    };
                }
                let rec_res = reconcile_journal_locked(&slot_lock, repo, backend, false, tick_now);
                drop(slot_lock);
                if let Err(err) = rec_res {
                    if err.exit_code == ExitCode::PartialCommitOrRecovery {
                        pstate.consecutive_commit_failures =
                            pstate.consecutive_commit_failures.saturating_add(1);
                        pstate.paused_on_failure = true;
                        let reason = "incomplete_switch_recovery".to_string();
                        pstate.paused_reason = Some(reason.clone());
                        let p_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "paused_on_failure",
                            Some(&reason),
                            p_now,
                        )?;
                        notify_paused_on_failure(
                            repo,
                            overrides.notify_override,
                            "Journal recovery",
                            None,
                            &pstate,
                            "Incomplete switch recovery requires manual inspection.",
                            shutdown_rx,
                        )
                        .await;
                        return Ok(rctx.into_report(
                            p_now,
                            "paused_on_failure",
                            Some(reason.clone()),
                            TickStageOutcome::PausedOnFailure { reason },
                        ));
                    }
                    return Err(err);
                }
            }
            Err(_corrupt_err) => {
                pstate.consecutive_commit_failures =
                    pstate.consecutive_commit_failures.saturating_add(1);
                pstate.paused_on_failure = true;
                let reason = "corrupted_switch_journal".to_string();
                pstate.paused_reason = Some(reason.clone());
                let p_now = active_clock.now_unix();
                self.persist_status(repo, &mut pstate, "paused_on_failure", Some(&reason), p_now)?;
                notify_paused_on_failure(
                    repo,
                    overrides.notify_override,
                    "Journal check",
                    None,
                    &pstate,
                    "Corrupted switch journal preserved on disk.",
                    shutdown_rx,
                )
                .await;
                return Ok(rctx.into_report(
                    p_now,
                    "paused_on_failure",
                    Some(reason.clone()),
                    TickStageOutcome::PausedOnFailure { reason },
                ));
            }
        }

        let (policy, decision_policy_revision) =
            resolve_effective_daemon_policy(repo, &overrides.policy_overlay)?;
        rctx.monitored_model = Some(policy.monitored_model.clone());
        rctx.reserve_percentage = Some(policy.reserve_percentage);
        rctx.candidate_min_percentage = Some(policy.candidate_min_percentage);

        if !policy.enabled {
            let d_now = active_clock.now_unix();
            self.persist_status(
                repo,
                &mut pstate,
                "disabled",
                Some("policy_disabled"),
                d_now,
            )?;
            return Ok(rctx.into_report(
                d_now,
                "disabled",
                Some("policy_disabled".into()),
                TickStageOutcome::Disabled,
            ));
        }

        let cur_now = active_clock.now_unix();
        if cur_now < pstate.cooldown_until {
            self.persist_status(repo, &mut pstate, "cooldown", Some("in_cooldown"), cur_now)?;
            return Ok(rctx.into_report(
                cur_now,
                "cooldown",
                Some("in_cooldown".into()),
                TickStageOutcome::InCooldown {
                    until: pstate.cooldown_until,
                },
            ));
        }

        // ================= STAGE 1: OBSERVE CURRENT OFFICIAL ACTIVE SLOT =================
        let snapshot = repo.read_snapshot()?;
        let decision_index_revision = snapshot.index.revision;
        let Some(source_acc) = snapshot.selected_account() else {
            let t_now = active_clock.now_unix();
            self.persist_status(
                repo,
                &mut pstate,
                "hold",
                Some("no_selected_account"),
                t_now,
            )?;
            return Ok(rctx.into_report(
                t_now,
                "hold",
                Some("no_selected_account".into()),
                TickStageOutcome::UncertainHold {
                    reason: "no_selected_account".into(),
                },
            ));
        };
        let source_id = source_acc.id.clone();
        rctx.source_account_id = Some(source_id.clone());
        rctx.source_email = Some(source_acc.email.clone());

        let source_replicas = backend.inspect_replicas(paths);
        let slot_state = source_replicas.effective_slot_state();
        let session_id = resolve_session_identity(slot_state, &snapshot);
        if slot_state.raw_digest().is_none() {
            let t_now = active_clock.now_unix();
            self.persist_status(
                repo,
                &mut pstate,
                "hold",
                Some("session_slot_uninitialized_or_corrupt"),
                t_now,
            )?;
            return Ok(rctx.into_report(
                t_now,
                "hold",
                Some("session_slot_uninitialized_or_corrupt".into()),
                TickStageOutcome::UncertainHold {
                    reason: "session_slot_uninitialized_or_corrupt".into(),
                },
            ));
        }
        let slot_matches_source = matches!(
            session_id,
            SessionIdentity::Matched { ref account_id, .. } if account_id == &source_id
        ) || matches!(
            slot_state,
            SlotInspectState::Present(ref parsed)
                if slot_matches_selected_rotated_account(repo, &snapshot, parsed, source_acc)
        );
        let source_checkpoint = if slot_matches_source {
            extract_verified_checkpoint_from_replicas(
                repo,
                &snapshot,
                &source_replicas,
                &source_id,
                true,
            )
        } else {
            None
        };
        let Some(mut expected_checkpoint) = source_checkpoint else {
            let t_now = active_clock.now_unix();
            self.persist_status(
                repo,
                &mut pstate,
                "hold",
                Some("session_identity_not_matched"),
                t_now,
            )?;
            return Ok(rctx.into_report(
                t_now,
                "hold",
                Some("session_identity_not_matched".into()),
                TickStageOutcome::UncertainHold {
                    reason: "session_identity_not_matched".into(),
                },
            ));
        };

        let source_max_age = effective_source_quota_max_age_secs(overrides.interval_secs);
        let obs_now = active_clock.now_unix();
        let mut source_eval =
            evaluate_account_quota(source_acc, &policy.monitored_model, obs_now, source_max_age);
        let backoff_ok = self
            .refresh_backoff_until
            .get(&source_id)
            .copied()
            .unwrap_or(0)
            <= obs_now;
        let low_grace_secs = if overrides.once {
            ONCE_ALREADY_LOW_GRACE_SECS
        } else {
            ONCE_ALREADY_LOW_GRACE_SECS.min(source_max_age.saturating_sub(1))
        };
        let already_ultra_fresh_low = matches!(
            source_eval,
            QuotaEval::Known { remaining_percentage }
                if remaining_percentage <= policy.reserve_percentage as f64
        ) && source_acc.quota.as_ref().is_some_and(|q| {
            let age = obs_now.saturating_sub(q.last_updated);
            (0..=low_grace_secs).contains(&age)
        });
        let should_refresh_source = backoff_ok
            && !matches!(source_eval, QuotaEval::Unavailable { .. })
            && !already_ultra_fresh_low;

        if should_refresh_source {
            enum SourceProbeRace {
                Shutdown,
                Timeout,
                Done(
                    Box<
                        Result<
                            crate::quota::official_cli::ActiveSlotQuotaRefreshOutcome,
                            RefreshActiveSlotError,
                        >,
                    >,
                ),
            }
            let race = tokio::select! {
                _ = shutdown_rx.changed() => SourceProbeRace::Shutdown,
                _ = tokio::time::sleep_until(tick_deadline) => SourceProbeRace::Timeout,
                res = refresh_active_slot_quota_detailed(
                    repo,
                    backend,
                    runner,
                    overrides.explicit_file_backend,
                    Some(&source_id),
                    active_clock.now_unix(),
                ) => SourceProbeRace::Done(Box::new(res)),
            };
            match race {
                SourceProbeRace::Shutdown => {
                    let t_now = active_clock.now_unix();
                    return Ok(rctx.into_report(
                        t_now,
                        "hold",
                        Some("shutdown_signal_received".into()),
                        TickStageOutcome::UncertainHold {
                            reason: "shutdown_signal_received".into(),
                        },
                    ));
                }
                SourceProbeRace::Timeout => {
                    let t_now = active_clock.now_unix();
                    let reason = if overrides.once {
                        "source_refresh_failed: tick_budget_timeout"
                    } else {
                        "tick_budget_timeout"
                    };
                    self.persist_status(repo, &mut pstate, "hold", Some(reason), t_now)?;
                    return Ok(rctx.into_report(
                        t_now,
                        "hold",
                        Some(reason.into()),
                        TickStageOutcome::UncertainHold {
                            reason: reason.into(),
                        },
                    ));
                }
                SourceProbeRace::Done(boxed) => match *boxed {
                    Ok(refreshed) => {
                        rctx.source_refreshed = true;
                        source_eval = evaluate_account_quota(
                            &refreshed.account,
                            &policy.monitored_model,
                            active_clock.now_unix(),
                            source_max_age,
                        );
                        // Advance per-replica expected checkpoint ONLY for replicas already verified
                        // as belonging to `source_id` inside `refresh_active_slot_quota_detailed`.
                        if let Some(ref verified_cp) = refreshed.verified_checkpoint {
                            expected_checkpoint.advance_from_verified_probe(verified_cp);
                        }
                    }
                    Err(RefreshActiveSlotError::PreProbeSlotMismatch(_)) => {
                        let c_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "cancelled",
                            Some("active_slot_digest_changed"),
                            c_now,
                        )?;
                        return Ok(rctx.into_report(
                            c_now,
                            "cancelled",
                            Some("active_slot_digest_changed".into()),
                            TickStageOutcome::CancelledStalePlan {
                                reason: "active_slot_digest_changed".into(),
                            },
                        ));
                    }
                    Err(RefreshActiveSlotError::Cli(ce))
                        if ce.error_code == "active_slot_changed_during_refresh" =>
                    {
                        let c_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "cancelled",
                            Some("selected_account_changed_manually"),
                            c_now,
                        )?;
                        return Ok(rctx.into_report(
                            c_now,
                            "cancelled",
                            Some("selected_account_changed_manually".into()),
                            TickStageOutcome::CancelledStalePlan {
                                reason: "selected_account_changed_manually".into(),
                            },
                        ));
                    }
                    Err(err) => {
                        if let RefreshActiveSlotError::Probe {
                            verified_checkpoint: Some(ref verified_cp),
                            ..
                        } = err
                        {
                            expected_checkpoint.advance_from_verified_probe(verified_cp);
                        }
                        let fail_now = active_clock.now_unix();
                        let backoff_secs =
                            CANDIDATE_REFRESH_BACKOFF_SECS.max(overrides.interval_secs as i64);
                        self.refresh_backoff_until
                            .insert(source_id.clone(), fail_now + backoff_secs);
                        let cli_err = err.into_cli_error();
                        if overrides.once || !matches!(source_eval, QuotaEval::Known { .. }) {
                            source_eval = QuotaEval::Unknown {
                                reason: format!(
                                    "source_refresh_failed: {}",
                                    safe_daemon_error_code(&cli_err.error_code)
                                ),
                            };
                        }
                    }
                },
            }
        }

        // ================= STAGE 2: EVALUATE SOURCE QUOTA =================
        let eval_now = active_clock.now_unix();
        let source_rem = match source_eval {
            QuotaEval::Known {
                remaining_percentage,
            } => remaining_percentage,
            QuotaEval::Unknown { reason }
            | QuotaEval::Stale { reason }
            | QuotaEval::Unavailable { reason } => {
                self.persist_status(repo, &mut pstate, "hold", Some(&reason), eval_now)?;
                return Ok(rctx.into_report(
                    eval_now,
                    "hold",
                    Some(reason.clone()),
                    TickStageOutcome::UncertainHold { reason },
                ));
            }
        };
        rctx.source_remaining_percentage = Some(source_rem);

        if source_rem > policy.reserve_percentage as f64 {
            self.last_low_quota_hold_notified_account = None;
            self.persist_status(
                repo,
                &mut pstate,
                "monitoring",
                Some("quota_sufficient"),
                eval_now,
            )?;
            return Ok(rctx.into_report(
                eval_now,
                "monitoring",
                Some("quota_sufficient".into()),
                TickStageOutcome::IdleSufficientQuota,
            ));
        }

        // ================= STAGE 3: CANDIDATE ORDERING & LOCAL CACHE SKIP =================
        let pre_step_snap = repo.read_snapshot()?;
        if pre_step_snap.index.revision != decision_index_revision
            || pre_step_snap.index.selected_account_id.as_deref() != Some(source_id.as_str())
        {
            let c_now = active_clock.now_unix();
            self.persist_status(
                repo,
                &mut pstate,
                "cancelled",
                Some("store_index_revision_changed"),
                c_now,
            )?;
            return Ok(rctx.into_report(
                c_now,
                "cancelled",
                Some("store_index_revision_changed".into()),
                TickStageOutcome::CancelledStalePlan {
                    reason: "store_index_revision_changed".into(),
                },
            ));
        }

        let ordered_candidates = ordered_candidate_ids(
            &policy.candidate_account_ids,
            &source_id,
            policy.strategy,
            pstate.last_rotated_candidate_id.as_deref(),
        );
        let mut eligible_candidates: Vec<String> = Vec::with_capacity(ordered_candidates.len());
        for cid in &ordered_candidates {
            if self.refresh_backoff_until.get(cid).copied().unwrap_or(0) > eval_now {
                continue;
            }
            let Some(acc) = pre_step_snap.accounts.iter().find(|a| &a.id == cid) else {
                continue;
            };
            if !acc.is_usable_at(eval_now) {
                continue;
            }
            if !registry.missing_required_scopes(&acc.token).is_empty() {
                continue;
            }
            // Local cache skip: skip known exhausted candidates whose blocking reset deadline is still in the future.
            if cached_candidate_known_below_min_before_reset(
                acc,
                &policy.monitored_model,
                policy.candidate_min_percentage,
                eval_now,
            )
            .is_some()
            {
                continue;
            }
            eligible_candidates.push(cid.clone());
        }

        // ================= STAGE 4: PROCESS GUARD =================
        let guard_now = active_clock.now_unix();
        let guard_runtime = observe_runtime_state(paths);
        match guard_runtime {
            RuntimeState::Unverified { .. } => {
                self.persist_status(
                    repo,
                    &mut pstate,
                    "hold",
                    Some("process_state_unverified"),
                    guard_now,
                )?;
                return Ok(rctx.into_report(
                    guard_now,
                    "hold",
                    Some("process_state_unverified".into()),
                    TickStageOutcome::UncertainHold {
                        reason: "process_state_unverified".into(),
                    },
                ));
            }
            RuntimeState::ManagedRunning { .. } | RuntimeState::UnmanagedRunning { .. }
                if policy.mode == PolicyMode::Wait && !eligible_candidates.is_empty() =>
            {
                let first_target = eligible_candidates[0].clone();
                rctx.target_account_id = Some(first_target.clone());
                self.persist_status(
                    repo,
                    &mut pstate,
                    "blocked_by_active_process",
                    Some("waiting_for_agy_idle"),
                    guard_now,
                )?;
                return Ok(rctx.into_report(
                    guard_now,
                    "blocked_by_active_process",
                    Some("waiting_for_agy_idle".into()),
                    TickStageOutcome::BlockedByActiveProcess {
                        target_id: first_target,
                    },
                ));
            }
            _ => {}
        }

        if eligible_candidates.is_empty() {
            let n_now = active_clock.now_unix();
            self.persist_status(
                repo,
                &mut pstate,
                "no_candidate",
                Some("no_qualified_candidate"),
                n_now,
            )?;
            self.notify_holding_low_quota_once(
                repo,
                overrides.notify_override,
                &source_id,
                source_rem,
                policy.candidate_min_percentage,
                shutdown_rx,
            )
            .await;
            return Ok(rctx.into_report(
                n_now,
                "no_candidate",
                Some("no_qualified_candidate".into()),
                TickStageOutcome::NoQualifiedCandidate {
                    reason: "no_qualified_candidate".into(),
                },
            ));
        }

        if let Some(ref hook) = self.before_revalidate_hook {
            hook();
        }

        // ================= STAGE 5: SINGLE-PASS BOUNDED STEP-AND-VERIFY =================
        // Visits each eligible candidate at most ONCE (upper bound N - 1 hops).
        enum StepLoopExit {
            Exhausted,
            Shutdown,
            TimedOut,
            LockBusy,
            ProcessUnverified,
            BlockedByActiveProcess(String),
        }

        let mut current_slot_id = source_id.clone();
        let mut expected_index_revision = decision_index_revision;
        let mut best_below_min: Option<(String, f64)> = None;
        let mut probed_below_min_ids: Vec<String> = Vec::new();
        let mut loop_exit = StepLoopExit::Exhausted;
        let min_pct_f = policy.candidate_min_percentage as f64;
        let guard_mode = match policy.mode {
            PolicyMode::Immediate => RunningGuardMode::AllowVerifiedRunning,
            PolicyMode::Wait => RunningGuardMode::RequireIdle,
        };

        for (hop_idx, cand_id) in eligible_candidates.iter().enumerate() {
            if *shutdown_rx.borrow() {
                loop_exit = StepLoopExit::Shutdown;
                break;
            }
            if tokio::time::Instant::now() >= tick_deadline {
                loop_exit = StepLoopExit::TimedOut;
                break;
            }
            if hop_idx > 0 && !overrides.step_buffer_delay.is_zero() {
                enum BufferRace {
                    Shutdown,
                    Timeout,
                    Ready,
                }
                let race = tokio::select! {
                    _ = shutdown_rx.changed() => BufferRace::Shutdown,
                    _ = tokio::time::sleep_until(tick_deadline) => BufferRace::Timeout,
                    _ = tokio::time::sleep(overrides.step_buffer_delay) => BufferRace::Ready,
                };
                match race {
                    BufferRace::Shutdown => {
                        loop_exit = StepLoopExit::Shutdown;
                        break;
                    }
                    BufferRace::Timeout => {
                        loop_exit = StepLoopExit::TimedOut;
                        break;
                    }
                    BufferRace::Ready => {}
                }
            }

            // Acquire L1 briefly for offline revalidation + switch only (never held across `agy -p "/usage"`).
            let existing_needs_kr = journal_on_disk_may_need_keyring(paths);
            let mut slot_lock = match ActiveSlotLock::try_acquire(
                paths,
                backend.uses_keyring() || existing_needs_kr,
            ) {
                Ok(l) => l,
                Err(e) if e.exit_code == ExitCode::LockBusyOrConflict => {
                    if hop_idx == 0 {
                        let b_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "lock_busy",
                            Some("slot_lock_busy"),
                            b_now,
                        )?;
                        return Ok(rctx.into_report(
                            b_now,
                            "lock_busy",
                            Some("slot_lock_busy".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "slot_lock_busy".into(),
                            },
                        ));
                    }
                    loop_exit = StepLoopExit::LockBusy;
                    break;
                }
                Err(e) => return Err(e),
            };
            if !slot_lock.includes_keyring_scope() && journal_on_disk_may_need_keyring(paths) {
                drop(slot_lock);
                slot_lock = match ActiveSlotLock::try_acquire(paths, true) {
                    Ok(l) => l,
                    Err(e) if e.exit_code == ExitCode::LockBusyOrConflict => {
                        if hop_idx == 0 {
                            let b_now = active_clock.now_unix();
                            self.persist_status(
                                repo,
                                &mut pstate,
                                "lock_busy",
                                Some("slot_lock_busy"),
                                b_now,
                            )?;
                            return Ok(rctx.into_report(
                                b_now,
                                "lock_busy",
                                Some("slot_lock_busy".into()),
                                TickStageOutcome::UncertainHold {
                                    reason: "slot_lock_busy".into(),
                                },
                            ));
                        }
                        loop_exit = StepLoopExit::LockBusy;
                        break;
                    }
                    Err(e) => return Err(e),
                };
            }

            let step_now = active_clock.now_unix();
            if let Err(err) = reconcile_journal_locked(&slot_lock, repo, backend, false, step_now) {
                drop(slot_lock);
                let journal_corrupt = read_journal_readonly(paths).is_err();
                if err.exit_code == ExitCode::PartialCommitOrRecovery || journal_corrupt {
                    pstate.consecutive_commit_failures =
                        pstate.consecutive_commit_failures.saturating_add(1);
                    pstate.paused_on_failure = true;
                    let reason = if journal_corrupt {
                        "corrupted_switch_journal"
                    } else {
                        "incomplete_switch_recovery"
                    }
                    .to_string();
                    pstate.paused_reason = Some(reason.clone());
                    self.persist_status(
                        repo,
                        &mut pstate,
                        "paused_on_failure",
                        Some(&reason),
                        step_now,
                    )?;
                    let (stage, notify_reason) = if journal_corrupt {
                        (
                            "Pre-commit journal check",
                            "Corrupted switch journal preserved on disk.",
                        )
                    } else {
                        (
                            "Pre-commit journal recovery",
                            "Incomplete switch recovery requires manual inspection.",
                        )
                    };
                    notify_paused_on_failure(
                        repo,
                        overrides.notify_override,
                        stage,
                        Some(cand_id),
                        &pstate,
                        notify_reason,
                        shutdown_rx,
                    )
                    .await;
                    return Ok(rctx.into_report(
                        step_now,
                        "paused_on_failure",
                        Some(reason.clone()),
                        TickStageOutcome::PausedOnFailure { reason },
                    ));
                }
                return Err(err);
            }

            // Revalidate under L1 against concurrent manual edits (`switch` / `delete` / `policy set`)
            // on EVERY hop (including ABA revisions after hop 0).
            let live_snap = repo.read_snapshot()?;
            if live_snap.index.revision != expected_index_revision
                || live_snap.index.selected_account_id.as_deref() != Some(current_slot_id.as_str())
            {
                drop(slot_lock);
                let cancel_reason = if live_snap.index.selected_account_id.as_deref()
                    != Some(current_slot_id.as_str())
                {
                    "selected_account_changed_manually"
                } else {
                    "store_index_revision_changed"
                };
                self.persist_status(
                    repo,
                    &mut pstate,
                    "cancelled",
                    Some(cancel_reason),
                    step_now,
                )?;
                return Ok(rctx.into_report(
                    step_now,
                    "cancelled",
                    Some(cancel_reason.into()),
                    TickStageOutcome::CancelledStalePlan {
                        reason: cancel_reason.into(),
                    },
                ));
            }
            let (live_policy, live_policy_rev) =
                resolve_effective_daemon_policy(repo, &overrides.policy_overlay)?;
            if live_policy_rev != decision_policy_revision || !live_policy.enabled {
                drop(slot_lock);
                self.persist_status(
                    repo,
                    &mut pstate,
                    "cancelled",
                    Some("policy_revision_changed_or_disabled"),
                    step_now,
                )?;
                return Ok(rctx.into_report(
                    step_now,
                    "cancelled",
                    Some("policy_revision_changed_or_disabled".into()),
                    TickStageOutcome::CancelledStalePlan {
                        reason: "policy_revision_changed_or_disabled".into(),
                    },
                ));
            }
            let live_replicas = backend.inspect_replicas(paths);
            if !replica_inspection_matches_expectation(
                repo,
                &live_snap,
                &live_replicas,
                PreSwitchSlotExpectation::ExactCheckpoint(&expected_checkpoint),
            ) {
                drop(slot_lock);
                self.persist_status(
                    repo,
                    &mut pstate,
                    "cancelled",
                    Some("active_slot_digest_changed"),
                    step_now,
                )?;
                return Ok(rctx.into_report(
                    step_now,
                    "cancelled",
                    Some("active_slot_digest_changed".into()),
                    TickStageOutcome::CancelledStalePlan {
                        reason: "active_slot_digest_changed".into(),
                    },
                ));
            }
            match observe_runtime_state(paths) {
                RuntimeState::Idle => {}
                RuntimeState::Unverified { .. } => {
                    drop(slot_lock);
                    if hop_idx == 0 {
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "hold",
                            Some("process_state_unverified"),
                            step_now,
                        )?;
                        return Ok(rctx.into_report(
                            step_now,
                            "hold",
                            Some("process_state_unverified".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "process_state_unverified".into(),
                            },
                        ));
                    }
                    loop_exit = StepLoopExit::ProcessUnverified;
                    break;
                }
                RuntimeState::ManagedRunning { .. } | RuntimeState::UnmanagedRunning { .. } => {
                    if live_policy.mode == PolicyMode::Wait {
                        drop(slot_lock);
                        if hop_idx == 0 {
                            self.persist_status(
                                repo,
                                &mut pstate,
                                "cancelled",
                                Some("active_process_started_before_commit"),
                                step_now,
                            )?;
                            return Ok(rctx.into_report(
                                step_now,
                                "cancelled",
                                Some("active_process_started_before_commit".into()),
                                TickStageOutcome::CancelledStalePlan {
                                    reason: "active_process_started_before_commit".into(),
                                },
                            ));
                        }
                        loop_exit = StepLoopExit::BlockedByActiveProcess(cand_id.clone());
                        break;
                    }
                }
            }
            let cand_still_valid = live_policy.candidate_account_ids.contains(cand_id)
                && live_snap
                    .accounts
                    .iter()
                    .find(|a| &a.id == cand_id)
                    .is_some_and(|a| a.is_usable_at(step_now));
            if !cand_still_valid {
                drop(slot_lock);
                continue;
            }

            // Offline switch to `cand_id` (performs automatic Pre-Switch Sync-Back of outgoing slot!)
            // R2-01 / R3-01: Hand off the full per-replica `expected_checkpoint` directly to the
            // executor's own `pre_snap` so an external `agy login` on ANY managed replica (file
            // or keyring) cancels before sync-back, journal write, or slot commit.
            rctx.target_account_id = Some(cand_id.clone());
            let switch_res = execute_switch_with_slot_lock_and_guard(
                &slot_lock,
                repo,
                backend,
                registry,
                cand_id,
                guard_mode,
                false,
                false,
                Some(PreSwitchSlotExpectation::ExactCheckpoint(
                    &expected_checkpoint,
                )),
                step_now,
            );
            let post_switch_rev = if switch_res.is_ok() {
                // Capture expected index revision BEFORE releasing L1 (`slot_lock`) so no
                // concurrent switch can slip into the gap after dropping `slot_lock`.
                // Per-replica slot checkpoint comes directly from `outcome.committed_checkpoint`
                // (never an unverified post-commit re-read!).
                repo.read_snapshot().ok().map(|s| s.index.revision)
            } else {
                None
            };
            drop(slot_lock);

            match switch_res {
                Ok(outcome) => {
                    pstate.consecutive_commit_failures = 0;
                    current_slot_id = cand_id.clone();
                    if let Some(r) = post_switch_rev {
                        expected_index_revision = r;
                    }
                    if let Some(cp) = outcome.committed_checkpoint {
                        expected_checkpoint = cp;
                    }
                }
                Err(err)
                    if matches!(
                        err.error_code.as_str(),
                        "active_slot_digest_changed" | "external_slot_modified"
                    ) =>
                {
                    let c_now = active_clock.now_unix();
                    self.persist_status(
                        repo,
                        &mut pstate,
                        "cancelled",
                        Some("active_slot_digest_changed"),
                        c_now,
                    )?;
                    return Ok(rctx.into_report(
                        c_now,
                        "cancelled",
                        Some("active_slot_digest_changed".into()),
                        TickStageOutcome::CancelledStalePlan {
                            reason: "active_slot_digest_changed".into(),
                        },
                    ));
                }
                Err(err) if err.error_code == "runtime_state_unverified" => {
                    let post_now = active_clock.now_unix();
                    if hop_idx == 0 {
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "hold",
                            Some("process_state_unverified"),
                            post_now,
                        )?;
                        return Ok(rctx.into_report(
                            post_now,
                            "hold",
                            Some("process_state_unverified".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "process_state_unverified".into(),
                            },
                        ));
                    }
                    loop_exit = StepLoopExit::ProcessUnverified;
                    break;
                }
                Err(err) if err.error_code == "active_agy_running" => {
                    let post_now = active_clock.now_unix();
                    if hop_idx == 0 {
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "blocked_by_active_process",
                            Some("waiting_for_agy_idle"),
                            post_now,
                        )?;
                        return Ok(rctx.into_report(
                            post_now,
                            "blocked_by_active_process",
                            Some("waiting_for_agy_idle".into()),
                            TickStageOutcome::BlockedByActiveProcess {
                                target_id: cand_id.clone(),
                            },
                        ));
                    }
                    loop_exit = StepLoopExit::BlockedByActiveProcess(cand_id.clone());
                    break;
                }
                Err(err)
                    if matches!(
                        err.error_code.as_str(),
                        "scope_reauth_required"
                            | "account_reauth_required"
                            | "account_validation_blocked"
                    ) =>
                {
                    let fail_now = active_clock.now_unix();
                    self.refresh_backoff_until.insert(
                        cand_id.clone(),
                        fail_now
                            + CANDIDATE_REFRESH_BACKOFF_SECS
                                .max((overrides.interval_secs as i64).saturating_mul(2)),
                    );
                    continue;
                }
                Err(err) => {
                    let post_now = active_clock.now_unix();
                    return self
                        .record_commit_failure_and_report(
                            repo,
                            &mut pstate,
                            rctx,
                            cand_id,
                            &err,
                            overrides.notify_override,
                            post_now,
                            shutdown_rx,
                        )
                        .await;
                }
            }

            // Live verification of `cand_id` via official `agy -p "/usage"` (with automatic sync-back!)
            enum CandProbeRace {
                Shutdown,
                Timeout,
                Done(
                    Box<
                        Result<
                            crate::quota::official_cli::ActiveSlotQuotaRefreshOutcome,
                            RefreshActiveSlotError,
                        >,
                    >,
                ),
            }
            let cand_race = tokio::select! {
                _ = shutdown_rx.changed() => CandProbeRace::Shutdown,
                _ = tokio::time::sleep_until(tick_deadline) => CandProbeRace::Timeout,
                res = refresh_active_slot_quota_detailed(
                    repo,
                    backend,
                    runner,
                    overrides.explicit_file_backend,
                    Some(cand_id),
                    active_clock.now_unix(),
                ) => CandProbeRace::Done(Box::new(res)),
            };
            match cand_race {
                CandProbeRace::Shutdown => {
                    loop_exit = StepLoopExit::Shutdown;
                    break;
                }
                CandProbeRace::Timeout => {
                    loop_exit = StepLoopExit::TimedOut;
                    break;
                }
                CandProbeRace::Done(boxed) => match *boxed {
                    Ok(refreshed) => {
                        if let Some(ref verified_cp) = refreshed.verified_checkpoint {
                            expected_checkpoint.advance_from_verified_probe(verified_cp);
                        }
                        let probe_now = active_clock.now_unix();
                        let cand_eval = evaluate_account_quota(
                            &refreshed.account,
                            &policy.monitored_model,
                            probe_now,
                            DEFAULT_QUOTA_MAX_AGE_SECS,
                        );
                        match cand_eval {
                            QuotaEval::Known {
                                remaining_percentage,
                            } if remaining_percentage >= min_pct_f => {
                                // ================= LANDED SUCCESSFULLY =================
                                pstate.cooldown_until =
                                    probe_now.saturating_add(overrides.cooldown_secs.max(0));
                                pstate.last_rotated_candidate_id = Some(cand_id.clone());
                                pstate.consecutive_commit_failures = 0;
                                pstate.paused_on_failure = false;
                                pstate.paused_reason = None;
                                self.last_low_quota_hold_notified_account = None;
                                self.persist_commit_status(
                                    repo,
                                    &mut pstate,
                                    "cooldown",
                                    Some("switch_committed"),
                                    probe_now,
                                )?;
                                let snap = repo.read_snapshot().ok();
                                let source_acc = snap
                                    .as_ref()
                                    .and_then(|s| s.accounts.iter().find(|a| a.id == source_id));
                                let target_acc = Some(&refreshed.account);
                                rctx.target_account_id = Some(cand_id.clone());
                                rctx.target_email = Some(refreshed.account.email.clone());
                                rctx.target_remaining_percentage = Some(remaining_percentage);
                                if !*shutdown_rx.borrow()
                                    && resolve_effective_notify_enabled(
                                        repo,
                                        false,
                                        overrides.notify_override,
                                    )
                                {
                                    let from_account = source_acc
                                        .map(format_account_notify_label)
                                        .unwrap_or_else(|| source_id.clone());
                                    let to_account =
                                        format_account_notify_label(&refreshed.account);
                                    let source_windows = source_acc
                                        .map(|a| {
                                            evaluate_account_window_quotas(
                                                a,
                                                &policy.monitored_model,
                                                probe_now,
                                                DEFAULT_QUOTA_MAX_AGE_SECS,
                                            )
                                        })
                                        .unwrap_or_default();
                                    let target_windows = target_acc
                                        .map(|a| {
                                            evaluate_account_window_quotas(
                                                a,
                                                &policy.monitored_model,
                                                probe_now,
                                                DEFAULT_QUOTA_MAX_AGE_SECS,
                                            )
                                        })
                                        .unwrap_or_default();
                                    let persistent_switch =
                                        resolve_effective_notify_persistent(repo);
                                    send_daemon_notification_best_effort(
                                        &DaemonNotificationEvent::Switched {
                                            from_account,
                                            to_account,
                                            source_5h_pct: source_windows.short_5h_pct,
                                            source_weekly_pct: source_windows.weekly_pct,
                                            target_5h_pct: target_windows.short_5h_pct,
                                            target_weekly_pct: target_windows.weekly_pct,
                                        },
                                        persistent_switch,
                                        shutdown_rx,
                                    )
                                    .await;
                                }
                                return Ok(rctx.into_report(
                                    probe_now,
                                    "cooldown",
                                    Some("switch_committed".into()),
                                    TickStageOutcome::CommittedSwitch {
                                        source_id,
                                        target_id: cand_id.clone(),
                                    },
                                ));
                            }
                            QuotaEval::Known {
                                remaining_percentage,
                            } => {
                                // Below candidate_min_percentage: do NOT set switch cooldown; record for hold backoff & best-so-far, then advance!
                                probed_below_min_ids.push(cand_id.clone());
                                if remaining_percentage > source_rem
                                    && best_below_min
                                        .as_ref()
                                        .is_none_or(|(_, best)| remaining_percentage > *best)
                                {
                                    best_below_min = Some((cand_id.clone(), remaining_percentage));
                                }
                            }
                            QuotaEval::Unknown { .. }
                            | QuotaEval::Stale { .. }
                            | QuotaEval::Unavailable { .. } => {
                                self.refresh_backoff_until.insert(
                                    cand_id.clone(),
                                    probe_now
                                        + CANDIDATE_REFRESH_BACKOFF_SECS.max(
                                            (overrides.interval_secs as i64).saturating_mul(2),
                                        ),
                                );
                            }
                        }
                    }
                    Err(RefreshActiveSlotError::PreProbeSlotMismatch(_)) => {
                        let c_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "cancelled",
                            Some("active_slot_digest_changed"),
                            c_now,
                        )?;
                        return Ok(rctx.into_report(
                            c_now,
                            "cancelled",
                            Some("active_slot_digest_changed".into()),
                            TickStageOutcome::CancelledStalePlan {
                                reason: "active_slot_digest_changed".into(),
                            },
                        ));
                    }
                    Err(RefreshActiveSlotError::Cli(ce))
                        if ce.error_code == "active_slot_changed_during_refresh" =>
                    {
                        let c_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "cancelled",
                            Some("selected_account_changed_manually"),
                            c_now,
                        )?;
                        return Ok(rctx.into_report(
                            c_now,
                            "cancelled",
                            Some("selected_account_changed_manually".into()),
                            TickStageOutcome::CancelledStalePlan {
                                reason: "selected_account_changed_manually".into(),
                            },
                        ));
                    }
                    Err(err) => {
                        if let RefreshActiveSlotError::Probe {
                            verified_checkpoint: Some(ref verified_cp),
                            ..
                        } = err
                        {
                            expected_checkpoint.advance_from_verified_probe(verified_cp);
                        }
                        // AuthRequired / RateLimited / Timeout / CommandFailed: no cooldown, backoff and advance!
                        let fail_now = active_clock.now_unix();
                        self.refresh_backoff_until.insert(
                            cand_id.clone(),
                            fail_now
                                + CANDIDATE_REFRESH_BACKOFF_SECS
                                    .max((overrides.interval_secs as i64).saturating_mul(2)),
                        );
                    }
                },
            }
        }

        // ================= STAGE 6: STEADY-STATE FINALIZATION =================
        // Handle mid-hop guards FIRST without switching while an active process or unverified `/proc`
        // prevents safe slot mutation, and without falsely claiming all candidates were exhausted!
        match loop_exit {
            StepLoopExit::BlockedByActiveProcess(target_id) => {
                let end_now = active_clock.now_unix();
                rctx.target_account_id = Some(target_id.clone());
                self.persist_status(
                    repo,
                    &mut pstate,
                    "blocked_by_active_process",
                    Some("waiting_for_agy_idle"),
                    end_now,
                )?;
                return Ok(rctx.into_report(
                    end_now,
                    "blocked_by_active_process",
                    Some("waiting_for_agy_idle".into()),
                    TickStageOutcome::BlockedByActiveProcess { target_id },
                ));
            }
            StepLoopExit::ProcessUnverified => {
                let end_now = active_clock.now_unix();
                self.persist_status(
                    repo,
                    &mut pstate,
                    "hold",
                    Some("process_state_unverified"),
                    end_now,
                )?;
                return Ok(rctx.into_report(
                    end_now,
                    "hold",
                    Some("process_state_unverified".into()),
                    TickStageOutcome::UncertainHold {
                        reason: "process_state_unverified".into(),
                    },
                ));
            }
            StepLoopExit::LockBusy => {
                let end_now = active_clock.now_unix();
                self.persist_status(
                    repo,
                    &mut pstate,
                    "lock_busy",
                    Some("slot_lock_busy"),
                    end_now,
                )?;
                return Ok(rctx.into_report(
                    end_now,
                    "lock_busy",
                    Some("slot_lock_busy".into()),
                    TickStageOutcome::UncertainHold {
                        reason: "slot_lock_busy".into(),
                    },
                ));
            }
            StepLoopExit::Exhausted | StepLoopExit::TimedOut | StepLoopExit::Shutdown => {}
        }

        // Stay on the best probed candidate strictly above `source_rem`, otherwise return to `source_id`.
        let (final_stay_id, final_stay_rem) = match best_below_min {
            Some((best_id, best_rem)) if best_rem > source_rem => (best_id, best_rem),
            _ => (source_id.clone(), source_rem),
        };

        if current_slot_id != final_stay_id {
            let existing_needs_kr = journal_on_disk_may_need_keyring(paths);
            let mut slot_lock = match ActiveSlotLock::try_acquire(
                paths,
                backend.uses_keyring() || existing_needs_kr,
            ) {
                Ok(l) => l,
                Err(e) if e.exit_code == ExitCode::LockBusyOrConflict => {
                    let b_now = active_clock.now_unix();
                    self.persist_status(
                        repo,
                        &mut pstate,
                        "lock_busy",
                        Some("slot_lock_busy"),
                        b_now,
                    )?;
                    return Ok(rctx.into_report(
                        b_now,
                        "lock_busy",
                        Some("slot_lock_busy".into()),
                        TickStageOutcome::UncertainHold {
                            reason: "slot_lock_busy".into(),
                        },
                    ));
                }
                Err(e) => return Err(e),
            };
            if !slot_lock.includes_keyring_scope() && journal_on_disk_may_need_keyring(paths) {
                drop(slot_lock);
                slot_lock = match ActiveSlotLock::try_acquire(paths, true) {
                    Ok(l) => l,
                    Err(e) if e.exit_code == ExitCode::LockBusyOrConflict => {
                        let b_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "lock_busy",
                            Some("slot_lock_busy"),
                            b_now,
                        )?;
                        return Ok(rctx.into_report(
                            b_now,
                            "lock_busy",
                            Some("slot_lock_busy".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "slot_lock_busy".into(),
                            },
                        ));
                    }
                    Err(e) => return Err(e),
                };
            }

            // Only settle back if no external manual switch, policy change/disable, or external
            // slot overwrite intervened!
            let live_snap = repo.read_snapshot()?;
            if live_snap.index.selected_account_id.as_deref() != Some(current_slot_id.as_str())
                || live_snap.index.revision != expected_index_revision
            {
                drop(slot_lock);
                let c_now = active_clock.now_unix();
                let cancel_reason = if live_snap.index.selected_account_id.as_deref()
                    != Some(current_slot_id.as_str())
                {
                    "selected_account_changed_manually"
                } else {
                    "store_index_revision_changed"
                };
                self.persist_status(repo, &mut pstate, "cancelled", Some(cancel_reason), c_now)?;
                return Ok(rctx.into_report(
                    c_now,
                    "cancelled",
                    Some(cancel_reason.into()),
                    TickStageOutcome::CancelledStalePlan {
                        reason: cancel_reason.into(),
                    },
                ));
            }
            let (live_policy, live_policy_rev) =
                resolve_effective_daemon_policy(repo, &overrides.policy_overlay)?;
            if live_policy_rev != decision_policy_revision || !live_policy.enabled {
                drop(slot_lock);
                let c_now = active_clock.now_unix();
                self.persist_status(
                    repo,
                    &mut pstate,
                    "cancelled",
                    Some("policy_revision_changed_or_disabled"),
                    c_now,
                )?;
                return Ok(rctx.into_report(
                    c_now,
                    "cancelled",
                    Some("policy_revision_changed_or_disabled".into()),
                    TickStageOutcome::CancelledStalePlan {
                        reason: "policy_revision_changed_or_disabled".into(),
                    },
                ));
            }
            let settle_pre_slot_expectation = if matches!(loop_exit, StepLoopExit::Exhausted) {
                PreSwitchSlotExpectation::ExactCheckpoint(&expected_checkpoint)
            } else {
                PreSwitchSlotExpectation::CheckpointOrSameAccountRotation {
                    expected: &expected_checkpoint,
                    account_id: current_slot_id.as_str(),
                }
            };
            let live_replicas = backend.inspect_replicas(paths);
            if !replica_inspection_matches_expectation(
                repo,
                &live_snap,
                &live_replicas,
                settle_pre_slot_expectation,
            ) {
                drop(slot_lock);
                let c_now = active_clock.now_unix();
                self.persist_status(
                    repo,
                    &mut pstate,
                    "cancelled",
                    Some("active_slot_digest_changed"),
                    c_now,
                )?;
                return Ok(rctx.into_report(
                    c_now,
                    "cancelled",
                    Some("active_slot_digest_changed".into()),
                    TickStageOutcome::CancelledStalePlan {
                        reason: "active_slot_digest_changed".into(),
                    },
                ));
            }

            let allow_val_block = final_stay_id == source_id;
            let settle_now = active_clock.now_unix();
            let settle_res = execute_switch_with_slot_lock_and_guard(
                &slot_lock,
                repo,
                backend,
                registry,
                &final_stay_id,
                guard_mode,
                false,
                allow_val_block,
                Some(settle_pre_slot_expectation),
                settle_now,
            );
            drop(slot_lock);

            match settle_res {
                Ok(_) => {
                    pstate.consecutive_commit_failures = 0;
                }
                Err(err)
                    if matches!(
                        err.error_code.as_str(),
                        "active_slot_digest_changed" | "external_slot_modified"
                    ) =>
                {
                    let c_now = active_clock.now_unix();
                    self.persist_status(
                        repo,
                        &mut pstate,
                        "cancelled",
                        Some("active_slot_digest_changed"),
                        c_now,
                    )?;
                    return Ok(rctx.into_report(
                        c_now,
                        "cancelled",
                        Some("active_slot_digest_changed".into()),
                        TickStageOutcome::CancelledStalePlan {
                            reason: "active_slot_digest_changed".into(),
                        },
                    ));
                }
                Err(err) if err.error_code == "active_agy_running" => {
                    let b_now = active_clock.now_unix();
                    rctx.target_account_id = Some(final_stay_id.clone());
                    self.persist_status(
                        repo,
                        &mut pstate,
                        "blocked_by_active_process",
                        Some("waiting_for_agy_idle"),
                        b_now,
                    )?;
                    return Ok(rctx.into_report(
                        b_now,
                        "blocked_by_active_process",
                        Some("waiting_for_agy_idle".into()),
                        TickStageOutcome::BlockedByActiveProcess {
                            target_id: final_stay_id,
                        },
                    ));
                }
                Err(err) if err.error_code == "runtime_state_unverified" => {
                    let b_now = active_clock.now_unix();
                    self.persist_status(
                        repo,
                        &mut pstate,
                        "hold",
                        Some("process_state_unverified"),
                        b_now,
                    )?;
                    return Ok(rctx.into_report(
                        b_now,
                        "hold",
                        Some("process_state_unverified".into()),
                        TickStageOutcome::UncertainHold {
                            reason: "process_state_unverified".into(),
                        },
                    ));
                }
                Err(err) => {
                    let post_now = active_clock.now_unix();
                    rctx.target_account_id = Some(final_stay_id.clone());
                    return self
                        .record_commit_failure_and_report(
                            repo,
                            &mut pstate,
                            rctx,
                            &final_stay_id,
                            &err,
                            overrides.notify_override,
                            post_now,
                            shutdown_rx,
                        )
                        .await;
                }
            }
        }

        let end_now = active_clock.now_unix();
        if matches!(loop_exit, StepLoopExit::Shutdown) || *shutdown_rx.borrow() {
            return Ok(rctx.into_report(
                end_now,
                "hold",
                Some("shutdown_signal_received".into()),
                TickStageOutcome::UncertainHold {
                    reason: "shutdown_signal_received".into(),
                },
            ));
        }
        if matches!(loop_exit, StepLoopExit::TimedOut) {
            self.persist_status(
                repo,
                &mut pstate,
                "hold",
                Some("tick_budget_timeout"),
                end_now,
            )?;
            return Ok(rctx.into_report(
                end_now,
                "hold",
                Some("tick_budget_timeout".into()),
                TickStageOutcome::UncertainHold {
                    reason: "tick_budget_timeout".into(),
                },
            ));
        }

        // Write hold backoff for all probed low candidates + outgoing source (excluding `final_stay_id`
        // so the active slot can still be re-checked for recovery on the next scheduled tick without
        // re-hopping/ping-ponging through exhausted dormant accounts).
        let hold_backoff_secs =
            CANDIDATE_REFRESH_BACKOFF_SECS.max((overrides.interval_secs as i64).saturating_mul(2));
        let hold_until = end_now.saturating_add(hold_backoff_secs);
        for low_id in &probed_below_min_ids {
            if low_id != &final_stay_id {
                self.refresh_backoff_until
                    .insert(low_id.clone(), hold_until);
            }
        }
        if source_id != final_stay_id {
            self.refresh_backoff_until
                .insert(source_id.clone(), hold_until);
        }

        rctx.target_account_id = (final_stay_id != source_id).then_some(final_stay_id.clone());
        if final_stay_id != source_id {
            pstate.consecutive_commit_failures = 0;
            rctx.target_email = repo
                .read_account_unchecked(&final_stay_id)
                .ok()
                .map(|a| a.email);
            rctx.target_remaining_percentage = Some(final_stay_rem);
        }
        self.persist_status(
            repo,
            &mut pstate,
            "no_candidate",
            Some("no_qualified_candidate"),
            end_now,
        )?;
        self.notify_holding_low_quota_once(
            repo,
            overrides.notify_override,
            &final_stay_id,
            final_stay_rem,
            policy.candidate_min_percentage,
            shutdown_rx,
        )
        .await;

        Ok(rctx.into_report(
            end_now,
            "no_candidate",
            Some("no_qualified_candidate".into()),
            TickStageOutcome::NoQualifiedCandidate {
                reason: "no_qualified_candidate".into(),
            },
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_commit_failure_and_report(
        &mut self,
        repo: &StoreRepository,
        pstate: &mut DaemonPersistentState,
        rctx: TickReportCtx,
        target_id: &str,
        err: &CliError,
        notify_override: Option<bool>,
        post_now: i64,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> CliResult<DaemonTickReport> {
        pstate.consecutive_commit_failures = pstate.consecutive_commit_failures.saturating_add(1);
        let is_recovery_incomplete = err.error_code == "recovery_incomplete"
            || err.exit_code == ExitCode::PartialCommitOrRecovery;
        let code = safe_daemon_error_code(&err.error_code);
        let reason = if is_recovery_incomplete {
            "incomplete_switch_recovery".to_string()
        } else {
            code.clone()
        };
        if is_recovery_incomplete
            || pstate.consecutive_commit_failures >= MAX_CONSECUTIVE_COMMIT_FAILURES
        {
            pstate.paused_on_failure = true;
            pstate.paused_reason = Some(if is_recovery_incomplete {
                "incomplete_switch_recovery".to_string()
            } else {
                format!("commit_failed: {code}")
            });
        }
        let paused = pstate.paused_on_failure;
        let phase = if paused {
            "paused_on_failure"
        } else {
            "commit_failed"
        };
        let persisted_reason = pstate
            .paused_reason
            .clone()
            .unwrap_or_else(|| reason.clone());
        self.persist_status(repo, pstate, phase, Some(&persisted_reason), post_now)?;
        if paused {
            let (stage, notify_reason) = if is_recovery_incomplete {
                (
                    "Switch commit recovery",
                    "Incomplete switch recovery requires manual inspection.".to_string(),
                )
            } else {
                ("Switch commit", format!("Switch commit failed ({code})."))
            };
            notify_paused_on_failure(
                repo,
                notify_override,
                stage,
                Some(target_id),
                pstate,
                &notify_reason,
                shutdown_rx,
            )
            .await;
        }
        Ok(rctx.into_report(
            post_now,
            phase,
            Some(reason.clone()),
            TickStageOutcome::CommitFailed { reason, paused },
        ))
    }

    async fn notify_holding_low_quota_once(
        &mut self,
        repo: &StoreRepository,
        notify_override: Option<bool>,
        staying_account_id: &str,
        staying_remaining_pct: f64,
        candidate_min_pct: u8,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        if self.last_low_quota_hold_notified_account.as_deref() == Some(staying_account_id) {
            return;
        }
        self.last_low_quota_hold_notified_account = Some(staying_account_id.to_string());
        if *shutdown_rx.borrow() || !resolve_effective_notify_enabled(repo, false, notify_override)
        {
            return;
        }
        let snap = repo.read_snapshot().ok();
        let staying_account = resolve_account_notify_label(snap.as_ref(), staying_account_id);
        let persistent_switch = resolve_effective_notify_persistent(repo);
        send_daemon_notification_best_effort(
            &DaemonNotificationEvent::HoldingLowQuota {
                staying_account,
                staying_remaining_pct: staying_remaining_pct.clamp(0.0, 100.0).round() as u8,
                candidate_min_pct,
            },
            persistent_switch,
            shutdown_rx,
        )
        .await;
    }

    fn persist_status(
        &self,
        repo: &StoreRepository,
        pstate: &mut DaemonPersistentState,
        phase: &str,
        reason: Option<&str>,
        now_unix: i64,
    ) -> CliResult<()> {
        self.persist_status_inner(repo, pstate, phase, reason, now_unix, false)
    }

    fn persist_commit_status(
        &self,
        repo: &StoreRepository,
        pstate: &mut DaemonPersistentState,
        phase: &str,
        reason: Option<&str>,
        now_unix: i64,
    ) -> CliResult<()> {
        self.persist_status_inner(repo, pstate, phase, reason, now_unix, true)
    }

    fn persist_status_inner(
        &self,
        repo: &StoreRepository,
        pstate: &mut DaemonPersistentState,
        phase: &str,
        reason: Option<&str>,
        now_unix: i64,
        commit_cooldown: bool,
    ) -> CliResult<()> {
        repo.with_write_lock(|tx| {
            let mut preserve_reset_phase = false;
            if !commit_cooldown {
                // Guard against lost updates with concurrent `daemon --reset-cooldown`:
                // never clobber an externally cleared `cooldown_until == 0` with a stale
                // pre-tick in-memory `cooldown_until`.
                let disk_state = read_daemon_state_readonly(tx.paths())?;
                if disk_state.cooldown_until == 0 && pstate.cooldown_until != 0 {
                    pstate.cooldown_until = 0;
                    if phase == "cooldown" {
                        pstate.last_phase = disk_state.last_phase;
                        pstate.last_reason = disk_state.last_reason;
                        preserve_reset_phase = true;
                    }
                }
            }
            if !preserve_reset_phase {
                pstate.last_phase = phase.to_string();
                pstate.last_reason = reason.map(str::to_owned);
            }
            pstate.last_checked_at = Some(now_unix);
            save_daemon_state_in_tx(tx.paths(), pstate)
        })
    }
}

/// Apply deterministic basis-point jitter (`-1000..=1000` => `[0.90, 1.10] * base_interval`) per Blueprint §7.2 Rule 1.
pub fn apply_interval_jitter_bps(base_interval: Duration, jitter_bps: i32) -> Duration {
    let clamped = jitter_bps.clamp(-1000, 1000) as i128;
    let base_ns = base_interval.as_nanos() as i128;
    let scaled_ns = (base_ns * (10_000 + clamped) / 10_000).max(1_000_000);
    Duration::from_nanos(scaled_ns as u64)
}

/// Sample uniform `±10%` jittered interval (`[0.90 * base_interval, 1.10 * base_interval]`).
pub fn sample_jittered_interval(base_interval: Duration) -> Duration {
    let bps = rand::thread_rng().gen_range(-1000i32..=1000i32);
    apply_interval_jitter_bps(base_interval, bps)
}

pub(crate) fn spawn_shutdown_signal_watcher() -> tokio::sync::watch::Receiver<bool> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Register Unix signal handlers SYNCHRONOUSLY before spawning so zero race window exists before first poll!
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
    tokio::spawn(async move {
        tokio::select! {
            _ = async {
                if let Some(ref mut s) = sigint { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => {}
            _ = async {
                if let Some(ref mut s) = sigterm { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => {}
        }
        let _ = shutdown_tx.send(true);
    });
    shutdown_rx
}

/// Foreground daemon loop (`agy-switch-cli daemon [--interval] [--cooldown] [--once]`).
/// Never forks into background; handles `SIGINT`/`SIGTERM` cleanly in BOTH `--once` and continuous modes,
/// uses `MissedTickBehavior::Delay` + true `±10%` jitter, and delegates active-slot usage checks to official `agy -p "/usage"`.
pub async fn run_foreground_daemon(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    registry: &OAuthClientRegistry,
    overrides: DaemonConfigOverrides,
) -> CliResult<()> {
    let daemon_lock = DaemonInstanceLock::try_acquire(repo.paths())?;
    let shutdown_rx = spawn_shutdown_signal_watcher();
    let runner = SystemOfficialCliRunner::default();
    run_foreground_daemon_with_shutdown(
        daemon_lock,
        repo,
        backend,
        &runner,
        registry,
        overrides,
        shutdown_rx,
    )
    .await
}

pub async fn run_foreground_daemon_with_shutdown(
    _daemon_lock: DaemonInstanceLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    runner: &dyn OfficialCliQuotaRunner,
    registry: &OAuthClientRegistry,
    overrides: DaemonConfigOverrides,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> CliResult<()> {
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    let mut engine = DaemonEngine::with_clock(Arc::new(SystemClock));

    if overrides.once {
        use std::io::Write;
        let now = SystemClock.now_unix();
        if overrides.reset_cooldown {
            reset_daemon_cooldown(repo, now).map_err(sanitize_daemon_tick_error)?;
        }
        let report = engine
            .run_single_tick_report_with_shutdown(
                repo,
                backend,
                runner,
                registry,
                &overrides,
                now,
                &mut shutdown_rx,
            )
            .await
            .map_err(sanitize_daemon_tick_error)?;
        let cancelled_by_signal = *shutdown_rx.borrow()
            && matches!(
                report.outcome,
                TickStageOutcome::UncertainHold { ref reason }
                    if reason == "shutdown_signal_received"
            );
        if !cancelled_by_signal {
            if overrides.json_mode {
                let envelope = JsonSuccessEnvelope::new(serde_json::json!({ "daemon": report }));
                let rendered = serde_json::to_string_pretty(&envelope)
                    .map_err(|e| CliError::data(format!("JSON serialization error: {e}")))?;
                println!("{rendered}");
            } else {
                println!("{}", report.format_human_line());
            }
            let _ = std::io::stdout().flush();
        }
        return Ok(());
    }

    let base_interval = Duration::from_secs(overrides.interval_secs.max(5));
    let mut ticker = tokio::time::interval(base_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown_rx.changed() => {
                break;
            }
            _ = ticker.tick() => {
                if *shutdown_rx.borrow() {
                    break;
                }
                let tick_started = tokio::time::Instant::now();
                let next_period = sample_jittered_interval(base_interval);
                ticker.reset_at(tick_started + next_period);

                let now = SystemClock.now_unix();
                let tick_res = engine
                    .run_single_tick_report_with_shutdown(
                        repo,
                        backend,
                        runner,
                        registry,
                        &overrides,
                        now,
                        &mut shutdown_rx,
                    )
                    .await;

                if !overrides.json_mode {
                    use std::io::Write;
                    match tick_res {
                        Ok(report) => {
                            let cancelled_by_signal = *shutdown_rx.borrow()
                                && matches!(
                                    report.outcome,
                                    TickStageOutcome::UncertainHold { ref reason }
                                        if reason == "shutdown_signal_received"
                                );
                            if !cancelled_by_signal {
                                println!("{}", report.format_human_line());
                                let _ = std::io::stdout().flush();
                            }
                        }
                        Err(err) => {
                            let ts = format_local_ts(SystemClock.now_unix());
                            eprintln!(
                                "[{ts}] daemon: error — tick failed (code: {}; run `agy-switch-cli status` to inspect)",
                                safe_daemon_error_code(&err.error_code)
                            );
                        }
                    }
                }

                if *shutdown_rx.borrow() {
                    break;
                }

                // If slow network exceeded `next_period`, delay next tick from completion Instant
                // (`MissedTickBehavior::Delay` + `±10%` jitter) so ticks never stack or burst.
                let after_tick = tokio::time::Instant::now();
                if after_tick >= tick_started + next_period {
                    ticker.reset_at(after_tick + sample_jittered_interval(base_interval));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interval_jitter_applies_true_plus_minus_10_percent_without_absorption() {
        let base_60s = Duration::from_secs(60);
        assert_eq!(
            apply_interval_jitter_bps(base_60s, -1000),
            Duration::from_secs(54)
        );
        assert_eq!(
            apply_interval_jitter_bps(base_60s, 0),
            Duration::from_secs(60)
        );
        assert_eq!(
            apply_interval_jitter_bps(base_60s, 1000),
            Duration::from_secs(66)
        );

        let mut saw_below = false;
        let mut saw_above = false;
        for _ in 0..200 {
            let s = sample_jittered_interval(base_60s);
            assert!(s >= Duration::from_secs(54) && s <= Duration::from_secs(66));
            if s < base_60s {
                saw_below = true;
            }
            if s > base_60s {
                saw_above = true;
            }
        }
        assert!(saw_below && saw_above);

        // Verify `ticker.reset_at` delivers BOTH negative (-10%) and positive (+10%) spacing without absorption,
        // using an 800ms base (80ms delta between 720ms and 800ms) + up to 5 attempts against transient OS scheduler pauses.
        let base = Duration::from_millis(800);
        let mut confirmed_neg_unabsorbed = false;
        for _ in 0..5 {
            let mut ticker = tokio::time::interval(base);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await;
            let t0 = tokio::time::Instant::now();
            let neg_period = apply_interval_jitter_bps(base, -1000); // 720ms (< 800ms base)
            ticker.reset_at(t0 + neg_period);
            tokio::time::sleep(Duration::from_millis(40)).await;
            ticker.tick().await;
            let elapsed = tokio::time::Instant::now() - t0;
            if elapsed >= Duration::from_millis(705) && elapsed < Duration::from_millis(792) {
                confirmed_neg_unabsorbed = true;
                break;
            }
        }
        assert!(
            confirmed_neg_unabsorbed,
            "Negative -10% jitter must fire around 720ms (< 800ms base) without being absorbed"
        );

        let mut ticker = tokio::time::interval(base);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;
        let t1 = tokio::time::Instant::now();
        let pos_period = apply_interval_jitter_bps(base, 1000); // 880ms (> 800ms base)
        ticker.reset_at(t1 + pos_period);
        tokio::time::sleep(Duration::from_millis(40)).await;
        ticker.tick().await;
        let elapsed_pos = tokio::time::Instant::now() - t1;
        assert!(
            elapsed_pos >= Duration::from_millis(865),
            "Positive +10% jitter must fire >= 865ms (> 800ms base), got {elapsed_pos:?}"
        );
    }

    #[test]
    fn synthetic_v124_reset_cooldown_preserves_fields_and_persist_status_guards_race() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let repo = StoreRepository::new(paths.clone());

        // 1. Absent `daemon_state.json` is idempotent and does not materialize a file.
        let empty_out = reset_daemon_cooldown(&repo, 1_000).unwrap();
        assert_eq!(
            empty_out,
            ResetCooldownOutcome {
                cooldown_reset: true,
                cooldown_was_active: false,
                previous_cooldown_until: 0,
            }
        );
        assert!(!paths.daemon_state_file().exists());

        // 2. Active cooldown cleared while preserving round-robin cursor and paused_on_failure.
        let seeded = DaemonPersistentState {
            schema_version: STORE_SCHEMA_VERSION,
            cooldown_until: 5_000,
            last_rotated_candidate_id: Some("acc-b".into()),
            consecutive_commit_failures: 2,
            paused_on_failure: true,
            paused_reason: Some("commit_failed: io_error".into()),
            last_phase: "paused_on_failure".into(),
            last_reason: Some("commit_failed: io_error".into()),
            last_checked_at: Some(900),
        };
        repo.with_write_lock(|tx| save_daemon_state_in_tx(tx.paths(), &seeded))
            .unwrap();

        let cleared = reset_daemon_cooldown(&repo, 1_000).unwrap();
        assert_eq!(
            cleared,
            ResetCooldownOutcome {
                cooldown_reset: true,
                cooldown_was_active: true,
                previous_cooldown_until: 5_000,
            }
        );
        let after = read_daemon_state_readonly(&paths).unwrap();
        assert_eq!(after.cooldown_until, 0);
        assert_eq!(after.last_rotated_candidate_id.as_deref(), Some("acc-b"));
        assert!(after.paused_on_failure);
        assert_eq!(after.consecutive_commit_failures, 2);
        assert_eq!(
            after.paused_reason.as_deref(),
            Some("commit_failed: io_error")
        );
        assert_eq!(after.last_phase, "paused_on_failure");
        let mode = std::fs::metadata(paths.daemon_state_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        // 3. Second reset is idempotent (`cooldown_was_active = false`, `previous = 0`).
        let second = reset_daemon_cooldown(&repo, 1_001).unwrap();
        assert_eq!(
            second,
            ResetCooldownOutcome {
                cooldown_reset: true,
                cooldown_was_active: false,
                previous_cooldown_until: 0,
            }
        );

        // 4. `persist_status` race guard: simulate a running daemon holding stale in-memory
        //    `pstate.cooldown_until = 8000` while external `--reset-cooldown` already cleared disk to 0.
        let cooldown_state = DaemonPersistentState {
            schema_version: STORE_SCHEMA_VERSION,
            cooldown_until: 8_000,
            last_rotated_candidate_id: Some("acc-c".into()),
            consecutive_commit_failures: 0,
            paused_on_failure: false,
            paused_reason: None,
            last_phase: "cooldown".into(),
            last_reason: Some("switch_committed".into()),
            last_checked_at: Some(4_400),
        };
        repo.with_write_lock(|tx| save_daemon_state_in_tx(tx.paths(), &cooldown_state))
            .unwrap();
        let mut stale_in_memory = read_daemon_state_readonly(&paths).unwrap();
        // External reset clears cooldown on disk
        let ext = reset_daemon_cooldown(&repo, 4_500).unwrap();
        assert!(ext.cooldown_was_active);
        let after_ext = read_daemon_state_readonly(&paths).unwrap();
        assert_eq!(after_ext.cooldown_until, 0);
        assert_eq!(after_ext.last_phase, "monitoring");
        assert_eq!(
            after_ext.last_reason.as_deref(),
            Some("cooldown_reset_by_user")
        );

        // Ordinary `persist_status("cooldown", ...)` from the stale in-flight tick MUST NOT restore 8_000!
        let engine = DaemonEngine::new();
        engine
            .persist_status(
                &repo,
                &mut stale_in_memory,
                "cooldown",
                Some("in_cooldown"),
                4_501,
            )
            .unwrap();
        let persisted_after_race = read_daemon_state_readonly(&paths).unwrap();
        assert_eq!(persisted_after_race.cooldown_until, 0);
        assert_eq!(persisted_after_race.last_phase, "monitoring");
        assert_eq!(
            persisted_after_race.last_reason.as_deref(),
            Some("cooldown_reset_by_user")
        );
        assert_eq!(stale_in_memory.cooldown_until, 0);

        // Ordinary `persist_status("monitoring", ...)` with another stale snapshot also preserves `0`.
        let mut stale_other = DaemonPersistentState {
            cooldown_until: 9_000,
            ..cooldown_state.clone()
        };
        engine
            .persist_status(
                &repo,
                &mut stale_other,
                "hold",
                Some("slot_lock_busy"),
                4_502,
            )
            .unwrap();
        let persisted_hold = read_daemon_state_readonly(&paths).unwrap();
        assert_eq!(persisted_hold.cooldown_until, 0);
        assert_eq!(persisted_hold.last_phase, "hold");
        assert_eq!(
            persisted_hold.last_reason.as_deref(),
            Some("slot_lock_busy")
        );

        // Stage 7 `persist_commit_status` MUST write the new post-switch cooldown timestamp!
        let mut new_commit = persisted_hold;
        new_commit.cooldown_until = 12_000;
        engine
            .persist_commit_status(
                &repo,
                &mut new_commit,
                "cooldown",
                Some("switch_committed"),
                8_400,
            )
            .unwrap();
        let persisted_commit = read_daemon_state_readonly(&paths).unwrap();
        assert_eq!(persisted_commit.cooldown_until, 12_000);
        assert_eq!(persisted_commit.last_phase, "cooldown");
        assert_eq!(
            persisted_commit.last_reason.as_deref(),
            Some("switch_committed")
        );

        // 5. Symlink `daemon_state.json` is rejected without following or overwriting target.
        let victim = tmp.path().join("victim.txt");
        std::fs::write(&victim, b"do-not-touch").unwrap();
        std::fs::remove_file(paths.daemon_state_file()).unwrap();
        std::os::unix::fs::symlink(&victim, paths.daemon_state_file()).unwrap();
        assert!(reset_daemon_cooldown(&repo, 9_000).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"do-not-touch");
    }

    #[test]
    fn synthetic_daemon_runtime_status_distinguishes_all_modes_and_suffixes() {
        let now = 1_800_000_000i64;
        let clean = DaemonPersistentState::default();

        // 1. Not running, no service installed.
        let s_none = build_daemon_runtime_status(
            DaemonLockProbe {
                running: false,
                pid: None,
            },
            &DaemonSystemdProbe::NotInstalled,
            Some(&clean),
            now,
        );
        assert_eq!(s_none.mode, "not_running");
        assert!(!s_none.running);
        assert_eq!(
            s_none.format_human(Some(&clean)),
            "not running (no service; ready for daemon / --once)"
        );

        // 2. Running via systemd service with active cooldown & paused failure.
        let paused_cd = DaemonPersistentState {
            cooldown_until: now + 2_520, // 42m
            paused_on_failure: true,
            consecutive_commit_failures: 3,
            ..DaemonPersistentState::default()
        };
        let s_svc = build_daemon_runtime_status(
            DaemonLockProbe {
                running: true,
                pid: Some(12345),
            },
            &DaemonSystemdProbe::Installed {
                active_state: Some("active".into()),
                unit_file_state: Some("enabled".into()),
                main_pid: Some(12345),
            },
            Some(&paused_cd),
            now,
        );
        assert_eq!(s_svc.mode, "systemd_service");
        assert!(s_svc.running);
        assert_eq!(s_svc.pid, Some(12345));
        assert!(s_svc.cooldown_active);
        assert_eq!(
            s_svc.format_human(Some(&paused_cd)),
            "running (systemd service, pid=12345) · cooldown 42m · PAUSED: 3 consecutive failures"
        );

        // 3. Running manually/foreground with no service, and with inactive service.
        let s_manual = build_daemon_runtime_status(
            DaemonLockProbe {
                running: true,
                pid: Some(23456),
            },
            &DaemonSystemdProbe::NotInstalled,
            Some(&clean),
            now,
        );
        assert_eq!(s_manual.mode, "manual");
        assert_eq!(
            s_manual.format_human(Some(&clean)),
            "running (manual/foreground, pid=23456)"
        );
        let s_manual_svc = build_daemon_runtime_status(
            DaemonLockProbe {
                running: true,
                pid: Some(23456),
            },
            &DaemonSystemdProbe::Installed {
                active_state: Some("inactive".into()),
                unit_file_state: Some("disabled".into()),
                main_pid: None,
            },
            Some(&clean),
            now,
        );
        assert_eq!(s_manual_svc.mode, "manual");
        assert_eq!(
            s_manual_svc.format_human(Some(&clean)),
            "running (manual/foreground, pid=23456; systemd service inactive)"
        );

        // 4. Installed systemd service stopped / failed / unreachable.
        let s_stopped = build_daemon_runtime_status(
            DaemonLockProbe {
                running: false,
                pid: None,
            },
            &DaemonSystemdProbe::Installed {
                active_state: Some("failed".into()),
                unit_file_state: Some("enabled".into()),
                main_pid: None,
            },
            Some(&clean),
            now,
        );
        assert_eq!(s_stopped.mode, "systemd_stopped");
        assert!(!s_stopped.running);
        assert_eq!(
            s_stopped.format_human(Some(&clean)),
            "stopped (systemd service failed; ready for --once)"
        );

        // 5. Unit installed for a different `--data-dir` must not claim ownership.
        let s_other = build_daemon_runtime_status(
            DaemonLockProbe {
                running: false,
                pid: None,
            },
            &DaemonSystemdProbe::InstalledForOtherDataDir,
            Some(&clean),
            now,
        );
        assert_eq!(s_other.mode, "not_running");
        assert!(!s_other.systemd_unit_installed);

        // 6. P2-02: Manager reports active PID (e.g. old data dir A still running after re-install to B),
        //    but THIS data dir holds NO lock -> must report stopped / running=false / pid=None while
        //    preserving manager observation in `systemd_active_state`.
        let s_active_no_lock = build_daemon_runtime_status(
            DaemonLockProbe {
                running: false,
                pid: None,
            },
            &DaemonSystemdProbe::Installed {
                active_state: Some("active".into()),
                unit_file_state: Some("enabled".into()),
                main_pid: Some(12345),
            },
            Some(&clean),
            now,
        );
        assert_eq!(s_active_no_lock.mode, "systemd_stopped");
        assert!(!s_active_no_lock.running);
        assert_eq!(s_active_no_lock.pid, None);
        assert_eq!(
            s_active_no_lock.systemd_active_state.as_deref(),
            Some("active")
        );
        assert_eq!(
            s_active_no_lock.format_human(Some(&clean)),
            "stopped (systemd service active, no lock held here; ready for --once)"
        );

        // 7. Lock is held in THIS data dir with unknown PID while manager reports active MainPID ->
        //    must NOT attribute unverified MainPID; degrades cleanly to manual with pid=None.
        let s_unknown_lock_pid = build_daemon_runtime_status(
            DaemonLockProbe {
                running: true,
                pid: None,
            },
            &DaemonSystemdProbe::Installed {
                active_state: Some("active".into()),
                unit_file_state: Some("enabled".into()),
                main_pid: Some(12345),
            },
            Some(&clean),
            now,
        );
        assert_eq!(s_unknown_lock_pid.mode, "manual");
        assert!(s_unknown_lock_pid.running);
        assert_eq!(s_unknown_lock_pid.pid, None);
        assert_eq!(
            s_unknown_lock_pid.format_human(Some(&clean)),
            "running (manual/foreground; systemd service active)"
        );

        // 8. Lock held by a DIFFERENT PID than systemd MainPID -> manual with actual lock PID.
        let s_pid_mismatch = build_daemon_runtime_status(
            DaemonLockProbe {
                running: true,
                pid: Some(99999),
            },
            &DaemonSystemdProbe::Installed {
                active_state: Some("active".into()),
                unit_file_state: Some("enabled".into()),
                main_pid: Some(12345),
            },
            Some(&clean),
            now,
        );
        assert_eq!(s_pid_mismatch.mode, "manual");
        assert!(s_pid_mismatch.running);
        assert_eq!(s_pid_mismatch.pid, Some(99999));
        assert_eq!(
            s_pid_mismatch.format_human(Some(&clean)),
            "running (manual/foreground, pid=99999; systemd service active)"
        );
    }
}
