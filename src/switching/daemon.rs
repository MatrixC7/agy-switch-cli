use crate::cli::dto::{terminal_text, JsonSuccessEnvelope};
use crate::domain::account::{RuntimeState, SessionIdentity, STORE_SCHEMA_VERSION};
use crate::domain::clock::{AnchoredClock, Clock, SystemClock};
use crate::domain::policy::{PolicyMode, PolicyStrategy, SwitchPolicy};
use crate::domain::quota::{
    evaluate_account_quota, evaluate_account_window_quotas, QuotaEval, DEFAULT_QUOTA_MAX_AGE_SECS,
};
use crate::error::{format_safe_json_error, CliError, CliResult, ExitCode};
use crate::oauth::refresh::{
    ensure_account_token_fresh_locked, OAuthEndpoints, TOKEN_REFRESH_SKEW_SECONDS,
};
use crate::oauth::registry::OAuthClientRegistry;
use crate::paths::HeadlessPaths;
use crate::quota::client::{
    refresh_account_quota_locked, refresh_account_quota_locked_with_meta, CloudCodeEndpoints,
};
use crate::session::backend::CredentialBackend;
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
use crate::store::locks::{ActiveSlotLock, DaemonInstanceLock};
use crate::store::repository::StoreRepository;
use crate::switching::executor::{execute_switch_with_slot_lock_and_guard, RunningGuardMode};
use crate::switching::notify::{
    resolve_effective_notify_enabled, send_daemon_notification_best_effort, DaemonNotificationEvent,
};
use crate::switching::runner::ordered_candidate_ids;
use crate::transport::client::{BoxFuture, HttpTransport};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::time::MissedTickBehavior;

pub const DEFAULT_DAEMON_INTERVAL_SECS: u64 = 180;
pub const DEFAULT_DAEMON_COOLDOWN_SECS: i64 = 3600;
pub const DEFAULT_TICK_HARD_TIMEOUT: Duration = Duration::from_secs(45);
pub const MAX_CONSECUTIVE_COMMIT_FAILURES: u32 = 3;
pub const CANDIDATE_REFRESH_BACKOFF_SECS: i64 = 300;
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

#[derive(Debug, Clone)]
pub struct PendingSwitchPlan {
    pub source_account_id: String,
    pub target_account_id: String,
    /// Captured at Stage 1/2 (`Observe`/`Evaluate`) BEFORE `Prepare` network I/O!
    pub index_revision: u64,
    /// Captured at Stage 1/2 (`Observe`/`Evaluate`) BEFORE `Prepare` network I/O!
    pub policy_revision: u64,
    /// Snapshot of `(candidate_id, disabled)` for candidates ranked ahead of `target_account_id` at Evaluate time.
    pub higher_priority_candidate_states: Vec<(String, bool)>,
    pub source_slot_digest: String,
    pub created_at: i64,
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
    pub once: bool,
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
            once: false,
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

fn format_local_ts(unix_secs: i64) -> String {
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

/// In-memory runtime coordinator for the 7-stage foreground `daemon` state machine (Blueprint §7.2).
pub struct DaemonEngine {
    pub pending: Option<PendingSwitchPlan>,
    pub refresh_backoff_until: HashMap<String, i64>,
    pub clock: Option<Arc<dyn Clock>>,
    /// Test hook invoked right before Stage 5 (`Revalidate` under L1 lock) to deterministically
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
            pending: None,
            refresh_backoff_until: HashMap::new(),
            clock: None,
            before_revalidate_hook: None,
        }
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            pending: None,
            refresh_backoff_until: HashMap::new(),
            clock: Some(clock),
            before_revalidate_hook: None,
        }
    }

    /// Execute one bounded, non-reentrant 7-stage daemon tick:
    /// `Observe -> Evaluate -> Prepare -> Process Guard -> Revalidate (under L1 lock) -> Commit & Reconcile -> Cooldown / PausedOnFailure`.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_single_tick(
        &mut self,
        repo: &StoreRepository,
        backend: &dyn CredentialBackend,
        transport: &dyn HttpTransport,
        oauth_endpoints: &OAuthEndpoints,
        quota_endpoints: &CloudCodeEndpoints,
        registry: &OAuthClientRegistry,
        user_agent: &str,
        overrides: &DaemonConfigOverrides,
        now_unix: i64,
    ) -> CliResult<TickStageOutcome> {
        let (_tx, mut dummy_rx) = tokio::sync::watch::channel(false);
        self.run_single_tick_with_shutdown(
            repo,
            backend,
            transport,
            oauth_endpoints,
            quota_endpoints,
            registry,
            user_agent,
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
        transport: &dyn HttpTransport,
        oauth_endpoints: &OAuthEndpoints,
        quota_endpoints: &CloudCodeEndpoints,
        registry: &OAuthClientRegistry,
        user_agent: &str,
        overrides: &DaemonConfigOverrides,
        now_unix: i64,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> CliResult<TickStageOutcome> {
        self.run_single_tick_report_with_shutdown(
            repo,
            backend,
            transport,
            oauth_endpoints,
            quota_endpoints,
            registry,
            user_agent,
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
        transport: &dyn HttpTransport,
        oauth_endpoints: &OAuthEndpoints,
        quota_endpoints: &CloudCodeEndpoints,
        registry: &OAuthClientRegistry,
        user_agent: &str,
        overrides: &DaemonConfigOverrides,
        now_unix: i64,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> CliResult<DaemonTickReport> {
        let active_clock: Arc<dyn Clock> = match self.clock {
            Some(ref c) => c.clone(),
            None => Arc::new(AnchoredClock::new(now_unix)),
        };
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

        // Reconcile any leftover `switch_journal.json` before reading `index.json` (Blueprint §3.3 & §7.2 Rule 6):
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
                        self.pending = None;
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
                self.pending = None;
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
            self.pending = None;
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

        let source_max_age = effective_source_quota_max_age_secs(overrides.interval_secs);

        if self.pending.is_none() {
            let source_refresh_in_flight = AtomicBool::new(false);
            let early_opt: Option<DaemonTickReport> = tokio::select! {
                _ = shutdown_rx.changed() => {
                    return Ok(rctx.into_report(
                        active_clock.now_unix(),
                        "hold",
                        Some("shutdown_signal_received".into()),
                        TickStageOutcome::UncertainHold {
                            reason: "shutdown_signal_received".into(),
                        },
                    ));
                }
                _ = tokio::time::sleep(overrides.tick_timeout) => {
                    let t_now = active_clock.now_unix();
                    let reason = if overrides.once && source_refresh_in_flight.load(Ordering::SeqCst) {
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
                res = async {
                    // ================= STAGE 1: OBSERVE =================
                    let snapshot = repo.read_snapshot()?;
                    // Capture the exact store index revision BEFORE any network I/O in Observe/Evaluate/Prepare!
                    let decision_index_revision = snapshot.index.revision;

                    let Some(source_acc) = snapshot.selected_account() else {
                        let t_now = active_clock.now_unix();
                        self.persist_status(repo, &mut pstate, "hold", Some("no_selected_account"), t_now)?;
                        return Ok::<Option<DaemonTickReport>, CliError>(Some(rctx.clone().into_report(
                            t_now,
                            "hold",
                            Some("no_selected_account".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "no_selected_account".into(),
                            },
                        )));
                    };
                    let source_id = source_acc.id.clone();
                    rctx.source_account_id = Some(source_id.clone());
                    rctx.source_email = Some(source_acc.email.clone());

                    let slot_state = backend.inspect_slot(paths);
                    let session_id = resolve_session_identity(&slot_state, &snapshot);
                    let Some(source_slot_digest) = slot_state.raw_digest().map(str::to_owned) else {
                        let t_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "hold",
                            Some("session_slot_uninitialized_or_corrupt"),
                            t_now,
                        )?;
                        return Ok(Some(rctx.clone().into_report(
                            t_now,
                            "hold",
                            Some("session_slot_uninitialized_or_corrupt".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "session_slot_uninitialized_or_corrupt".into(),
                            },
                        )));
                    };
                    if !matches!(session_id, SessionIdentity::Matched { ref account_id, .. } if account_id == &source_id)
                    {
                        let t_now = active_clock.now_unix();
                        self.persist_status(
                            repo,
                            &mut pstate,
                            "hold",
                            Some("session_identity_not_matched"),
                            t_now,
                        )?;
                        return Ok(Some(rctx.clone().into_report(
                            t_now,
                            "hold",
                            Some("session_identity_not_matched".into()),
                            TickStageOutcome::UncertainHold {
                                reason: "session_identity_not_matched".into(),
                            },
                        )));
                    };

                    let obs_now = active_clock.now_unix();
                    let mut source_eval = evaluate_account_quota(
                        source_acc,
                        &policy.monitored_model,
                        obs_now,
                        source_max_age,
                    );
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
                        source_refresh_in_flight.store(true, Ordering::SeqCst);
                        let refresh_res = refresh_account_quota_locked_with_meta(
                            repo,
                            transport,
                            oauth_endpoints,
                            quota_endpoints,
                            registry,
                            user_agent,
                            &source_id,
                            active_clock.now_unix(),
                        )
                        .await;
                        source_refresh_in_flight.store(false, Ordering::SeqCst);
                        match refresh_res {
                            Ok((updated, summary_err_code)) => {
                                let next_eval = evaluate_account_quota(
                                    &updated,
                                    &policy.monitored_model,
                                    active_clock.now_unix(),
                                    source_max_age,
                                );
                                if overrides.once
                                    && summary_err_code.is_some()
                                    && matches!(next_eval, QuotaEval::Unknown { .. })
                                {
                                    let fail_now = active_clock.now_unix();
                                    self.refresh_backoff_until
                                        .insert(source_id.clone(), fail_now + CANDIDATE_REFRESH_BACKOFF_SECS);
                                    source_eval = QuotaEval::Unknown {
                                        reason: format!(
                                            "source_refresh_failed: {}",
                                            summary_err_code.unwrap_or("quota_network_error")
                                        ),
                                    };
                                } else {
                                    rctx.source_refreshed = true;
                                    source_eval = next_eval;
                                }
                            }
                            Err(err) => {
                                let fail_now = active_clock.now_unix();
                                self.refresh_backoff_until
                                    .insert(source_id.clone(), fail_now + CANDIDATE_REFRESH_BACKOFF_SECS);
                                if overrides.once {
                                    source_eval = QuotaEval::Unknown {
                                        reason: format!(
                                            "source_refresh_failed: {}",
                                            safe_daemon_error_code(&err.error_code)
                                        ),
                                    };
                                }
                            }
                        }
                    }

                    // ================= STAGE 2: EVALUATE =================
                    let eval_now = active_clock.now_unix();
                    let source_rem = match source_eval {
                        QuotaEval::Known {
                            remaining_percentage,
                        } => remaining_percentage,
                        QuotaEval::Unknown { reason } | QuotaEval::Stale { reason } => {
                            self.persist_status(repo, &mut pstate, "hold", Some(&reason), eval_now)?;
                            return Ok(Some(rctx.clone().into_report(
                                eval_now,
                                "hold",
                                Some(reason.clone()),
                                TickStageOutcome::UncertainHold { reason },
                            )));
                        }
                        QuotaEval::Unavailable { reason } => {
                            self.persist_status(repo, &mut pstate, "hold", Some(&reason), eval_now)?;
                            return Ok(Some(rctx.clone().into_report(
                                eval_now,
                                "hold",
                                Some(reason.clone()),
                                TickStageOutcome::UncertainHold { reason },
                            )));
                        }
                    };
                    rctx.source_remaining_percentage = Some(source_rem);

                    if source_rem > policy.reserve_percentage as f64 {
                        self.persist_status(repo, &mut pstate, "monitoring", Some("quota_sufficient"), eval_now)?;
                        return Ok(Some(rctx.clone().into_report(
                            eval_now,
                            "monitoring",
                            Some("quota_sufficient".into()),
                            TickStageOutcome::IdleSufficientQuota,
                        )));
                    }

                    let ordered_at_decision = ordered_candidate_ids(
                        &policy.candidate_account_ids,
                        &source_id,
                        policy.strategy,
                        pstate.last_rotated_candidate_id.as_deref(),
                    );
                    let pre_probe_snap = repo.read_snapshot()?;
                    if pre_probe_snap.index.revision != decision_index_revision {
                        let c_now = active_clock.now_unix();
                        self.persist_status(repo, &mut pstate, "cancelled", Some("store_index_revision_changed"), c_now)?;
                        return Ok(Some(rctx.clone().into_report(
                            c_now,
                            "cancelled",
                            Some("store_index_revision_changed".into()),
                            TickStageOutcome::CancelledStalePlan {
                                reason: "store_index_revision_changed".into(),
                            },
                        )));
                    }

                    let Some(target_id) = self
                        .probe_first_qualified_candidate(
                            repo,
                            transport,
                            oauth_endpoints,
                            quota_endpoints,
                            registry,
                            user_agent,
                            &policy,
                            &ordered_at_decision,
                            active_clock.as_ref(),
                        )
                        .await?
                    else {
                        let n_now = active_clock.now_unix();
                        self.persist_status(repo, &mut pstate, "no_candidate", Some("no_qualified_candidate"), n_now)?;
                        return Ok(Some(rctx.clone().into_report(
                            n_now,
                            "no_candidate",
                            Some("no_qualified_candidate".into()),
                            TickStageOutcome::NoQualifiedCandidate {
                                reason: "no_qualified_candidate".into(),
                            },
                        )));
                    };
                    rctx.target_account_id = Some(target_id.clone());

                    let mut higher_priority_states = Vec::new();
                    for cid in &ordered_at_decision {
                        if cid == &target_id {
                            break;
                        }
                        let was_disabled = pre_probe_snap
                            .accounts
                            .iter()
                            .find(|a| a.id == *cid)
                            .map(|a| a.disabled)
                            .unwrap_or(true);
                        higher_priority_states.push((cid.clone(), was_disabled));
                    }

                    // ================= STAGE 3: PREPARE =================
                    if let Err(e) = ensure_account_token_fresh_locked(
                        repo,
                        transport,
                        oauth_endpoints,
                        registry,
                        user_agent,
                        &target_id,
                        false,
                        active_clock.now_unix(),
                    )
                    .await
                    {
                        let fail_now = active_clock.now_unix();
                        self.refresh_backoff_until
                            .insert(target_id, fail_now + CANDIDATE_REFRESH_BACKOFF_SECS);
                        let msg = format!(
                            "target_prepare_refresh_failed: {}",
                            safe_daemon_error_code(&e.error_code)
                        );
                        self.persist_status(repo, &mut pstate, "no_candidate", Some(&msg), fail_now)?;
                        return Ok(Some(rctx.clone().into_report(
                            fail_now,
                            "no_candidate",
                            Some(msg.clone()),
                            TickStageOutcome::NoQualifiedCandidate { reason: msg },
                        )));
                    }

                    // Preserve the ORIGINAL decision revisions (`decision_index_revision` & `decision_policy_revision`)
                    // captured BEFORE network I/O so any manual `policy order/set` or `switch` during Prepare
                    // is deterministically caught in Stage 5 `Revalidate`!
                    self.pending = Some(PendingSwitchPlan {
                        source_account_id: source_id,
                        target_account_id: target_id,
                        index_revision: decision_index_revision,
                        policy_revision: decision_policy_revision,
                        higher_priority_candidate_states: higher_priority_states,
                        source_slot_digest,
                        created_at: active_clock.now_unix(),
                    });
                    Ok(None)
                } => res?,
            };
            if let Some(early) = early_opt {
                return Ok(early);
            }
        }

        if *shutdown_rx.borrow() {
            return Ok(rctx.into_report(
                active_clock.now_unix(),
                "hold",
                Some("shutdown_signal_received".into()),
                TickStageOutcome::UncertainHold {
                    reason: "shutdown_signal_received".into(),
                },
            ));
        }

        let plan = self.pending.clone().expect("pending set above");
        if rctx.source_account_id.is_none() {
            rctx.source_account_id = Some(plan.source_account_id.clone());
        }
        if rctx.target_account_id.is_none() {
            rctx.target_account_id = Some(plan.target_account_id.clone());
        }

        // ================= STAGE 4: PROCESS GUARD =================
        let guard_now = active_clock.now_unix();
        let guard_runtime = observe_runtime_state(paths);
        if matches!(guard_runtime, RuntimeState::Unverified { .. }) {
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

        // Re-check store/policy/slot revisions BEFORE `PolicyMode::Wait` holds on an active process
        // (and use the latest effective policy mode in case policy changed during Stage 3 `Prepare` or between ticks).
        let (guard_policy, guard_policy_rev) =
            resolve_effective_daemon_policy(repo, &overrides.policy_overlay)?;
        let guard_snap = repo.read_snapshot()?;
        if guard_snap.index.revision != plan.index_revision {
            self.pending = None;
            self.persist_status(
                repo,
                &mut pstate,
                "cancelled",
                Some("store_index_revision_changed"),
                guard_now,
            )?;
            return Ok(rctx.into_report(
                guard_now,
                "cancelled",
                Some("store_index_revision_changed".into()),
                TickStageOutcome::CancelledStalePlan {
                    reason: "store_index_revision_changed".into(),
                },
            ));
        }
        if guard_policy_rev != plan.policy_revision || !guard_policy.enabled {
            self.pending = None;
            self.persist_status(
                repo,
                &mut pstate,
                "cancelled",
                Some("policy_revision_changed_or_disabled"),
                guard_now,
            )?;
            return Ok(rctx.into_report(
                guard_now,
                "cancelled",
                Some("policy_revision_changed_or_disabled".into()),
                TickStageOutcome::CancelledStalePlan {
                    reason: "policy_revision_changed_or_disabled".into(),
                },
            ));
        }
        if backend.inspect_slot(paths).raw_digest() != Some(plan.source_slot_digest.as_str()) {
            self.pending = None;
            self.persist_status(
                repo,
                &mut pstate,
                "cancelled",
                Some("active_slot_digest_changed"),
                guard_now,
            )?;
            return Ok(rctx.into_report(
                guard_now,
                "cancelled",
                Some("active_slot_digest_changed".into()),
                TickStageOutcome::CancelledStalePlan {
                    reason: "active_slot_digest_changed".into(),
                },
            ));
        }

        match guard_runtime {
            RuntimeState::Idle => {}
            RuntimeState::ManagedRunning { .. } | RuntimeState::UnmanagedRunning { .. } => {
                match guard_policy.mode {
                    PolicyMode::Immediate => {
                        // Never kill running `agy` processes; proceed to Stage 5 & Stage 6 to
                        // update the credential slot immediately for subsequent `agy` terminals.
                    }
                    PolicyMode::Wait => {
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
                                target_id: plan.target_account_id,
                            },
                        ));
                    }
                }
            }
            RuntimeState::Unverified { .. } => unreachable!("handled above"),
        }

        if let Some(ref hook) = self.before_revalidate_hook {
            hook();
        }

        // ================= STAGE 5: REVALIDATE (HOLDING L1 LOCK!) =================
        let existing_needs_kr = journal_on_disk_may_need_keyring(paths);
        let mut slot_lock =
            match ActiveSlotLock::try_acquire(paths, backend.uses_keyring() || existing_needs_kr) {
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

        // Capture real commit-moment timestamp INSIDE `L1 ActiveSlotLock`!
        let commit_now = active_clock.now_unix();

        if let Err(err) = reconcile_journal_locked(&slot_lock, repo, backend, false, commit_now) {
            drop(slot_lock);
            self.pending = None;
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
                    commit_now,
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
                    Some(&plan.target_account_id),
                    &pstate,
                    notify_reason,
                    shutdown_rx,
                )
                .await;
                return Ok(rctx.into_report(
                    commit_now,
                    "paused_on_failure",
                    Some(reason.clone()),
                    TickStageOutcome::PausedOnFailure { reason },
                ));
            }
            return Err(err);
        }

        let revalidate_source_max_age = if overrides.once {
            DEFAULT_QUOTA_MAX_AGE_SECS
        } else {
            source_max_age
        };
        let commit_mode = match revalidate_pending_under_l1(
            repo,
            backend,
            &plan,
            &overrides.policy_overlay,
            revalidate_source_max_age,
            commit_now,
        )? {
            RevalidateVerdict::Proceed(mode) => mode,
            RevalidateVerdict::HoldUnverified => {
                drop(slot_lock);
                self.persist_status(
                    repo,
                    &mut pstate,
                    "hold",
                    Some("process_state_unverified"),
                    commit_now,
                )?;
                return Ok(rctx.into_report(
                    commit_now,
                    "hold",
                    Some("process_state_unverified".into()),
                    TickStageOutcome::UncertainHold {
                        reason: "process_state_unverified".into(),
                    },
                ));
            }
            RevalidateVerdict::Cancel(cancel_reason) => {
                drop(slot_lock);
                self.pending = None;
                self.persist_status(
                    repo,
                    &mut pstate,
                    "cancelled",
                    Some(&cancel_reason),
                    commit_now,
                )?;
                return Ok(rctx.into_report(
                    commit_now,
                    "cancelled",
                    Some(cancel_reason.clone()),
                    TickStageOutcome::CancelledStalePlan {
                        reason: cancel_reason,
                    },
                ));
            }
        };

        // ================= STAGE 6: COMMIT & RECONCILE =================
        let guard_mode = match commit_mode {
            PolicyMode::Immediate => RunningGuardMode::AllowVerifiedRunning,
            PolicyMode::Wait => RunningGuardMode::RequireIdle,
        };
        let commit_res = execute_switch_with_slot_lock_and_guard(
            &slot_lock,
            repo,
            backend,
            transport,
            oauth_endpoints,
            registry,
            user_agent,
            &plan.target_account_id,
            guard_mode,
            false,
            false,
            commit_now,
        )
        .await;
        drop(slot_lock);
        self.pending = None;

        let post_commit_now = active_clock.now_unix();
        match commit_res {
            Ok(_outcome) => {
                // ================= STAGE 7: COOLDOWN =================
                pstate.cooldown_until =
                    post_commit_now.saturating_add(overrides.cooldown_secs.max(0));
                pstate.last_rotated_candidate_id = Some(plan.target_account_id.clone());
                pstate.consecutive_commit_failures = 0;
                pstate.paused_on_failure = false;
                pstate.paused_reason = None;
                self.persist_status(
                    repo,
                    &mut pstate,
                    "cooldown",
                    Some("switch_committed"),
                    post_commit_now,
                )?;
                let snap = repo.read_snapshot().ok();
                let source_acc = snap
                    .as_ref()
                    .and_then(|s| s.accounts.iter().find(|a| a.id == plan.source_account_id));
                let target_acc = snap
                    .as_ref()
                    .and_then(|s| s.accounts.iter().find(|a| a.id == plan.target_account_id));
                if let Some(s_acc) = source_acc {
                    rctx.source_email = Some(s_acc.email.clone());
                    if rctx.source_remaining_percentage.is_none() {
                        rctx.source_remaining_percentage = evaluate_account_quota(
                            s_acc,
                            &guard_policy.monitored_model,
                            post_commit_now,
                            DEFAULT_QUOTA_MAX_AGE_SECS,
                        )
                        .known_value();
                    }
                }
                if let Some(t_acc) = target_acc {
                    rctx.target_email = Some(t_acc.email.clone());
                    rctx.target_remaining_percentage = evaluate_account_quota(
                        t_acc,
                        &guard_policy.monitored_model,
                        post_commit_now,
                        DEFAULT_QUOTA_MAX_AGE_SECS,
                    )
                    .known_value();
                }
                if !*shutdown_rx.borrow()
                    && resolve_effective_notify_enabled(repo, false, overrides.notify_override)
                {
                    let from_account = source_acc
                        .map(format_account_notify_label)
                        .unwrap_or_else(|| plan.source_account_id.clone());
                    let to_account = target_acc
                        .map(format_account_notify_label)
                        .unwrap_or_else(|| plan.target_account_id.clone());
                    let source_windows = source_acc
                        .map(|a| {
                            evaluate_account_window_quotas(
                                a,
                                &guard_policy.monitored_model,
                                post_commit_now,
                                DEFAULT_QUOTA_MAX_AGE_SECS,
                            )
                        })
                        .unwrap_or_default();
                    let target_windows = target_acc
                        .map(|a| {
                            evaluate_account_window_quotas(
                                a,
                                &guard_policy.monitored_model,
                                post_commit_now,
                                DEFAULT_QUOTA_MAX_AGE_SECS,
                            )
                        })
                        .unwrap_or_default();
                    send_daemon_notification_best_effort(
                        &DaemonNotificationEvent::Switched {
                            from_account,
                            to_account,
                            source_5h_pct: source_windows.short_5h_pct,
                            source_weekly_pct: source_windows.weekly_pct,
                            target_5h_pct: target_windows.short_5h_pct,
                            target_weekly_pct: target_windows.weekly_pct,
                        },
                        shutdown_rx,
                    )
                    .await;
                }
                Ok(rctx.into_report(
                    post_commit_now,
                    "cooldown",
                    Some("switch_committed".into()),
                    TickStageOutcome::CommittedSwitch {
                        source_id: plan.source_account_id,
                        target_id: plan.target_account_id,
                    },
                ))
            }
            Err(err) if err.error_code == "runtime_state_unverified" => {
                self.persist_status(
                    repo,
                    &mut pstate,
                    "hold",
                    Some("process_state_unverified"),
                    post_commit_now,
                )?;
                Ok(rctx.into_report(
                    post_commit_now,
                    "hold",
                    Some("process_state_unverified".into()),
                    TickStageOutcome::UncertainHold {
                        reason: "process_state_unverified".into(),
                    },
                ))
            }
            Err(err) => {
                pstate.consecutive_commit_failures =
                    pstate.consecutive_commit_failures.saturating_add(1);
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
                self.persist_status(
                    repo,
                    &mut pstate,
                    phase,
                    Some(&persisted_reason),
                    post_commit_now,
                )?;
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
                        overrides.notify_override,
                        stage,
                        Some(&plan.target_account_id),
                        &pstate,
                        &notify_reason,
                        shutdown_rx,
                    )
                    .await;
                }
                Ok(rctx.into_report(
                    post_commit_now,
                    phase,
                    Some(reason.clone()),
                    TickStageOutcome::CommitFailed { reason, paused },
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn probe_first_qualified_candidate(
        &mut self,
        repo: &StoreRepository,
        transport: &dyn HttpTransport,
        oauth_endpoints: &OAuthEndpoints,
        quota_endpoints: &CloudCodeEndpoints,
        registry: &OAuthClientRegistry,
        user_agent: &str,
        policy: &SwitchPolicy,
        ordered: &[String],
        clock: &dyn Clock,
    ) -> CliResult<Option<String>> {
        // Probe in bounded concurrent batches of <= 3, stopping and cancelling lower-priority
        // in-flight requests as soon as the highest-priority qualified candidate is confirmed!
        #[derive(Clone)]
        enum SlotProbeState {
            Skipped,
            Resolved(QuotaEval),
            InFlight,
        }

        let min_pct = policy.candidate_min_percentage as f64;

        for chunk in ordered.chunks(3) {
            let chunk_now = clock.now_unix();
            let mut states = vec![SlotProbeState::Skipped; chunk.len()];
            let mut to_refresh: Vec<(usize, String)> = Vec::with_capacity(chunk.len());

            for (idx, cand_id) in chunk.iter().enumerate() {
                if self
                    .refresh_backoff_until
                    .get(cand_id)
                    .copied()
                    .unwrap_or(0)
                    > chunk_now
                {
                    continue;
                }
                let Ok(acc) = repo.read_account_unchecked(cand_id) else {
                    continue;
                };
                if !acc.is_usable_at(chunk_now) {
                    continue;
                }
                let eval = evaluate_account_quota(
                    &acc,
                    &policy.monitored_model,
                    chunk_now,
                    DEFAULT_QUOTA_MAX_AGE_SECS,
                );
                if matches!(eval, QuotaEval::Unknown { .. } | QuotaEval::Stale { .. }) {
                    states[idx] = SlotProbeState::InFlight;
                    to_refresh.push((idx, cand_id.clone()));
                } else {
                    let already_qualified = matches!(
                        eval,
                        QuotaEval::Known { remaining_percentage } if remaining_percentage >= min_pct
                    );
                    states[idx] = SlotProbeState::Resolved(eval);
                    if already_qualified {
                        // No lower-priority candidate in this chunk (> idx) can ever outrank `idx`!
                        break;
                    }
                }
            }

            if to_refresh.is_empty() {
                for (idx, state) in states.iter().enumerate() {
                    if let SlotProbeState::Resolved(QuotaEval::Known {
                        remaining_percentage,
                    }) = state
                    {
                        if *remaining_percentage >= min_pct {
                            return Ok(Some(chunk[idx].clone()));
                        }
                    }
                }
                continue;
            }

            type ProbeFuture<'a> = BoxFuture<
                'a,
                (
                    usize,
                    String,
                    CliResult<crate::domain::account::AccountRecord>,
                ),
            >;
            let mut in_flight: Vec<Option<ProbeFuture<'_>>> = to_refresh
                .into_iter()
                .map(|(idx, cid)| {
                    let start_ts = clock.now_unix();
                    let fut: ProbeFuture<'_> = Box::pin(async move {
                        let res = refresh_account_quota_locked(
                            repo,
                            transport,
                            oauth_endpoints,
                            quota_endpoints,
                            registry,
                            user_agent,
                            &cid,
                            start_ts,
                        )
                        .await;
                        (idx, cid, res)
                    });
                    Some(fut)
                })
                .collect();

            let mut winner: Option<String> = None;
            let mut failed_ids: Vec<String> = Vec::new();
            let monitored_model = policy.monitored_model.clone();

            std::future::poll_fn(|cx| {
                let mut any_pending = false;
                for slot_fut in &mut in_flight {
                    if let Some(fut) = slot_fut {
                        match fut.as_mut().poll(cx) {
                            Poll::Ready((idx, cid, res)) => {
                                *slot_fut = None;
                                match res {
                                    Ok(updated) => {
                                        let eval = evaluate_account_quota(
                                            &updated,
                                            &monitored_model,
                                            clock.now_unix(),
                                            DEFAULT_QUOTA_MAX_AGE_SECS,
                                        );
                                        states[idx] = SlotProbeState::Resolved(eval);
                                    }
                                    Err(_) => {
                                        failed_ids.push(cid);
                                        states[idx] = SlotProbeState::Skipped;
                                    }
                                }
                            }
                            Poll::Pending => {
                                any_pending = true;
                            }
                        }
                    }
                }

                // Check in strict priority/round-robin order if a winner is already settled
                // with zero unresolved higher-priority candidates ahead of it!
                for (idx, st) in states.iter().enumerate() {
                    match st {
                        SlotProbeState::InFlight => break,
                        SlotProbeState::Resolved(QuotaEval::Known {
                            remaining_percentage,
                        }) if *remaining_percentage >= min_pct => {
                            winner = Some(chunk[idx].clone());
                            // Dropping `in_flight` on return immediately cancels remaining lower-priority HTTP calls!
                            return Poll::Ready(());
                        }
                        SlotProbeState::Resolved(_) | SlotProbeState::Skipped => {}
                    }
                }

                if any_pending {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;

            // Drop remaining futures before mutating `self.refresh_backoff_until`
            drop(in_flight);
            let done_now = clock.now_unix();
            for fid in failed_ids {
                self.refresh_backoff_until
                    .insert(fid, done_now + CANDIDATE_REFRESH_BACKOFF_SECS);
            }
            if let Some(chosen) = winner {
                return Ok(Some(chosen));
            }
        }

        Ok(None)
    }

    fn persist_status(
        &self,
        repo: &StoreRepository,
        pstate: &mut DaemonPersistentState,
        phase: &str,
        reason: Option<&str>,
        now_unix: i64,
    ) -> CliResult<()> {
        pstate.last_phase = phase.to_string();
        pstate.last_reason = reason.map(str::to_owned);
        pstate.last_checked_at = Some(now_unix);
        repo.with_write_lock(|tx| save_daemon_state_in_tx(tx.paths(), pstate))
    }
}

enum RevalidateVerdict {
    Proceed(PolicyMode),
    HoldUnverified,
    Cancel(String),
}

fn revalidate_pending_under_l1(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    plan: &PendingSwitchPlan,
    overlay: &DaemonPolicyOverlay,
    source_max_age: i64,
    commit_now: i64,
) -> CliResult<RevalidateVerdict> {
    let paths = repo.paths();
    let (policy, disk_policy_revision) = resolve_effective_daemon_policy(repo, overlay)?;

    // 1. Re-verify runtime state right under L1 lock:
    //    - `Unverified` ALWAYS fails closed (`HoldUnverified`) even in `Immediate` mode;
    //    - Active `agy` processes cancel only in `Wait` mode (`Immediate` updates slot for new terminals).
    match observe_runtime_state(paths) {
        RuntimeState::Idle => {}
        RuntimeState::Unverified { .. } => {
            return Ok(RevalidateVerdict::HoldUnverified);
        }
        RuntimeState::ManagedRunning { .. } | RuntimeState::UnmanagedRunning { .. } => {
            if policy.mode == PolicyMode::Wait {
                return Ok(RevalidateVerdict::Cancel(
                    "active_process_started_before_commit".into(),
                ));
            }
        }
    }

    // 2. Re-read index & policy revisions against ORIGINAL decision snapshot (detects changes during Prepare too!)
    let snapshot = repo.read_snapshot()?;
    if snapshot.index.revision != plan.index_revision {
        return Ok(RevalidateVerdict::Cancel(
            "store_index_revision_changed".into(),
        ));
    }
    if snapshot.index.selected_account_id.as_deref() != Some(plan.source_account_id.as_str()) {
        return Ok(RevalidateVerdict::Cancel(
            "selected_account_changed_manually".into(),
        ));
    }

    if disk_policy_revision != plan.policy_revision || !policy.enabled {
        return Ok(RevalidateVerdict::Cancel(
            "policy_revision_changed_or_disabled".into(),
        ));
    }
    if !policy
        .candidate_account_ids
        .contains(&plan.target_account_id)
    {
        return Ok(RevalidateVerdict::Cancel(
            "target_removed_from_candidates".into(),
        ));
    }

    // Check if any higher-priority candidate was re-enabled OR became qualified while `plan` was pending/waiting!
    for (higher_id, was_disabled) in &plan.higher_priority_candidate_states {
        if let Some(higher_acc) = snapshot.accounts.iter().find(|a| a.id == *higher_id) {
            if *was_disabled && !higher_acc.disabled {
                return Ok(RevalidateVerdict::Cancel(
                    "higher_priority_candidate_enabled".into(),
                ));
            }
            if higher_acc.is_usable_at(commit_now) {
                let h_eval = evaluate_account_quota(
                    higher_acc,
                    &policy.monitored_model,
                    commit_now,
                    DEFAULT_QUOTA_MAX_AGE_SECS,
                );
                if matches!(
                    h_eval,
                    QuotaEval::Known { remaining_percentage } if remaining_percentage >= policy.candidate_min_percentage as f64
                ) {
                    return Ok(RevalidateVerdict::Cancel(
                        "higher_priority_candidate_qualified".into(),
                    ));
                }
            }
        }
    }

    // 3. Re-verify active slot digest matches pre-prepare source slot
    let slot_state = backend.inspect_slot(paths);
    if slot_state.raw_digest() != Some(plan.source_slot_digest.as_str()) {
        return Ok(RevalidateVerdict::Cancel(
            "active_slot_digest_changed".into(),
        ));
    }

    // 4. Re-verify both source and target accounts at REAL `commit_now` (usability, token expiry, reset_time <= commit_now, age)
    let Some(source_acc) = snapshot
        .accounts
        .iter()
        .find(|a| a.id == plan.source_account_id)
    else {
        return Ok(RevalidateVerdict::Cancel("source_account_deleted".into()));
    };
    let Some(target_acc) = snapshot
        .accounts
        .iter()
        .find(|a| a.id == plan.target_account_id)
    else {
        return Ok(RevalidateVerdict::Cancel("target_account_deleted".into()));
    };
    if !target_acc.is_usable_at(commit_now) {
        return Ok(RevalidateVerdict::Cancel(
            "target_account_became_unusable".into(),
        ));
    }
    if target_acc
        .token
        .is_expiring_within(commit_now, TOKEN_REFRESH_SKEW_SECONDS)
    {
        return Ok(RevalidateVerdict::Cancel(
            "target_token_expired_before_commit".into(),
        ));
    }

    let source_eval = evaluate_account_quota(
        source_acc,
        &policy.monitored_model,
        commit_now,
        source_max_age,
    );
    match source_eval {
        QuotaEval::Known {
            remaining_percentage,
        } if remaining_percentage <= policy.reserve_percentage as f64 => {}
        _ => {
            return Ok(RevalidateVerdict::Cancel(
                "source_quota_no_longer_below_reserve".into(),
            ))
        }
    }

    let target_eval = evaluate_account_quota(
        target_acc,
        &policy.monitored_model,
        commit_now,
        DEFAULT_QUOTA_MAX_AGE_SECS,
    );
    match target_eval {
        QuotaEval::Known {
            remaining_percentage,
        } if remaining_percentage >= policy.candidate_min_percentage as f64 => {}
        _ => {
            return Ok(RevalidateVerdict::Cancel(
                "target_quota_no_longer_meets_minimum".into(),
            ))
        }
    }

    Ok(RevalidateVerdict::Proceed(policy.mode))
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
/// uses `MissedTickBehavior::Delay` + true `±10%` jitter, and enforces single-tick hard timeout (`45s`).
#[allow(clippy::too_many_arguments)]
pub async fn run_foreground_daemon(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    quota_endpoints: &CloudCodeEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    overrides: DaemonConfigOverrides,
) -> CliResult<()> {
    let daemon_lock = DaemonInstanceLock::try_acquire(repo.paths())?;
    let shutdown_rx = spawn_shutdown_signal_watcher();
    run_foreground_daemon_with_shutdown(
        daemon_lock,
        repo,
        backend,
        transport,
        oauth_endpoints,
        quota_endpoints,
        registry,
        user_agent,
        overrides,
        shutdown_rx,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_foreground_daemon_with_shutdown(
    _daemon_lock: DaemonInstanceLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    quota_endpoints: &CloudCodeEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
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
        let report = engine
            .run_single_tick_report_with_shutdown(
                repo,
                backend,
                transport,
                oauth_endpoints,
                quota_endpoints,
                registry,
                user_agent,
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
                        transport,
                        oauth_endpoints,
                        quota_endpoints,
                        registry,
                        user_agent,
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
}
