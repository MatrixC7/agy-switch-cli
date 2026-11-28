use crate::domain::account::{AccountRecord, SessionIdentity};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::domain::quota::{
    fraction_is_known, normalize_bucket_reset_time, QuotaBucket, QuotaGroup, QuotaObservation,
    QuotaSourceEnv,
};
use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::session::backend::{
    should_isolate_child_dbus_for_explicit_file_backend, CredentialBackend, SlotInspectState,
};
use crate::session::payload::resolve_session_identity;
use crate::store::repository::{read_headless_config_readonly, StoreRepository};
use crate::switching::executor::{
    slot_matches_selected_rotated_account, sync_back_active_slot_for_account,
};
use crate::transport::client::BoxFuture;
use crate::transport::proxy::SubprocessProxyOverride;
use crate::transport::user_agent::resolve_agy_executable;
use serde::Deserialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

pub const OFFICIAL_CLI_USAGE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_USAGE_OUTPUT_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone)]
pub enum OfficialCliUsageOutcome {
    Quota {
        groups: Vec<QuotaGroup>,
        description: Option<String>,
    },
    ValidationBlocked {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfficialCliQuotaError {
    ExecutableNotFound,
    InvalidProxy(String),
    AuthRequired(String),
    RateLimited,
    Timeout(Duration),
    OutputDrainTimeout(Duration),
    OutputTooLarge,
    CommandFailed(String),
    Protocol(String),
}

impl OfficialCliQuotaError {
    pub fn into_cli_error(self) -> CliError {
        match self {
            Self::ExecutableNotFound => CliError::env_not_ready(
                "agy_not_found",
                "Official `agy` executable not found in PATH. Install `agy` before refreshing quota.",
            ),
            Self::InvalidProxy(msg) => CliError::usage(msg),
            Self::AuthRequired(msg) => CliError::auth("official_cli_auth_required", msg),
            Self::RateLimited => CliError::io(
                "quota_rate_limited",
                "Official `agy` usage query was rate-limited. Retry later.",
            ),
            Self::Timeout(dur) => CliError::io(
                "official_cli_timeout",
                format!(
                    "Official `agy -p \"/usage\"` timed out after {}s and was terminated.",
                    dur.as_secs().max(1)
                ),
            ),
            Self::OutputDrainTimeout(dur) => CliError::io(
                "official_cli_timeout",
                format!(
                    "Official `agy -p \"/usage\"` exited, but draining stdout/stderr timed out after {}s (a background process kept pipes open).",
                    dur.as_secs().max(1)
                ),
            ),
            Self::OutputTooLarge => CliError::data(format!(
                "Official `agy -p \"/usage\"` output exceeded the {} KiB safety limit.",
                MAX_USAGE_OUTPUT_BYTES / 1024
            )),
            Self::CommandFailed(msg) => CliError::io("official_cli_usage_failed", msg),
            Self::Protocol(msg) => CliError::data(msg),
        }
    }
}

pub trait OfficialCliQuotaRunner: Send + Sync {
    fn query_active_usage<'a>(
        &'a self,
        paths: &'a HeadlessPaths,
        explicit_file_backend: bool,
    ) -> BoxFuture<'a, Result<OfficialCliUsageOutcome, OfficialCliQuotaError>>;
}

/// Production official `agy -p "/usage" --output-format json < /dev/null` adapter.
#[derive(Debug, Clone)]
pub struct SystemOfficialCliRunner {
    pub timeout: Duration,
    pub proxy_override: Option<String>,
}

impl Default for SystemOfficialCliRunner {
    fn default() -> Self {
        Self {
            timeout: OFFICIAL_CLI_USAGE_TIMEOUT,
            proxy_override: None,
        }
    }
}

impl SystemOfficialCliRunner {
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            proxy_override: None,
        }
    }

    pub fn with_proxy(proxy_override: Option<String>) -> Self {
        Self {
            timeout: OFFICIAL_CLI_USAGE_TIMEOUT,
            proxy_override,
        }
    }

    pub fn with_timeout_and_proxy(timeout: Duration, proxy_override: Option<String>) -> Self {
        Self {
            timeout,
            proxy_override,
        }
    }
}

impl OfficialCliQuotaRunner for SystemOfficialCliRunner {
    fn query_active_usage<'a>(
        &'a self,
        paths: &'a HeadlessPaths,
        explicit_file_backend: bool,
    ) -> BoxFuture<'a, Result<OfficialCliUsageOutcome, OfficialCliQuotaError>> {
        Box::pin(async move {
            run_official_cli_usage_subprocess(
                paths,
                explicit_file_backend,
                self.timeout,
                self.proxy_override.as_deref(),
            )
            .await
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawAgyUsageOutput {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    command: Option<RawAgyCommand>,
}

#[derive(Debug, Deserialize)]
struct RawAgyCommand {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    data: Option<RawAgyUsageData>,
}

#[derive(Debug, Deserialize)]
struct RawAgyUsageData {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    groups: Vec<RawAgyUsageGroup>,
}

#[derive(Debug, Deserialize)]
struct RawAgyUsageGroup {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, alias = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    buckets: Vec<RawAgyUsageBucket>,
}

#[derive(Debug, Deserialize)]
struct RawAgyUsageBucket {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, alias = "bucketId")]
    bucket_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, alias = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    window: Option<String>,
    #[serde(default, alias = "remainingFraction")]
    remaining_fraction: Option<f64>,
    #[serde(default, alias = "resetTime")]
    reset_time: Option<String>,
}

fn text_indicates_validation_block(lower: &str) -> bool {
    lower.contains("validation_required")
        || lower.contains("validation required")
        || lower.contains("verify your account")
        || lower.contains("further action is required")
        || lower.contains("validation_url")
        || lower.contains("appeal_url")
}

fn text_indicates_auth_required(lower: &str) -> bool {
    lower.contains("authentication required")
        || lower.contains("please visit the url to log in")
        || lower.contains("authentication failed")
        || lower.contains("not authenticated")
        || lower.contains("unauthenticated")
        || lower.contains("not logged in")
        || lower.contains("login required")
        || lower.contains("invalid_grant")
        || lower.contains("expired_token")
        || lower.contains("token expired")
        || lower.contains("oauth2: token expired")
        || lower.contains("cannot fetch token")
        || lower.contains("invalid credentials")
        || lower.contains("no credentials")
        || lower.contains("401 unauthorized")
}

fn text_indicates_rate_limit(lower: &str) -> bool {
    lower.contains("429")
        || lower.contains("rate limit")
        || lower.contains("rate_limit")
        || lower.contains("resource_exhausted")
        || lower.contains("too many requests")
}

fn text_shows_interactive_login_prompt(bytes: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    lower.contains("please visit the url to log in")
        || (lower.contains("authentication required")
            && lower.contains("accounts.google.com/o/oauth2/auth"))
}

fn is_meaningful_agy_usage_json(parsed: &RawAgyUsageOutput) -> bool {
    parsed.status.is_some() || parsed.command.is_some() || parsed.error.is_some()
}

/// Extract `RawAgyUsageOutput` from stdout, tolerating leading/trailing non-JSON diagnostic
/// lines emitted by official `agy` before or after the JSON document.
fn extract_raw_agy_usage_json(stdout_bytes: &[u8]) -> Option<RawAgyUsageOutput> {
    if let Ok(direct) = serde_json::from_slice::<RawAgyUsageOutput>(stdout_bytes) {
        if is_meaningful_agy_usage_json(&direct) {
            return Some(direct);
        }
    }
    let text = std::str::from_utf8(stdout_bytes).ok()?;
    for (idx, ch) in text.char_indices() {
        if ch != '{' {
            continue;
        }
        let mut stream =
            serde_json::Deserializer::from_str(&text[idx..]).into_iter::<RawAgyUsageOutput>();
        if let Some(Ok(candidate)) = stream.next() {
            if is_meaningful_agy_usage_json(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Parse stdout/stderr from `agy -p "/usage" --output-format json`.
pub fn parse_official_cli_usage_output(
    exit_success: bool,
    exit_code: Option<i32>,
    stdout_bytes: &[u8],
    stderr_bytes: &[u8],
) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError> {
    let stdout_str = std::str::from_utf8(stdout_bytes).unwrap_or("");
    let stderr_str = std::str::from_utf8(stderr_bytes).unwrap_or("");
    let combined_lower = format!("{stdout_str}\n{stderr_str}").to_ascii_lowercase();

    // Try structured JSON parsing first (official `agy` may emit structured JSON even on error,
    // or prefix stdout with non-JSON warnings).
    let parsed_json = extract_raw_agy_usage_json(stdout_bytes);

    if let Some(ref parsed) = parsed_json {
        let status_upper = parsed
            .status
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_ascii_uppercase();
        let response_lower = parsed
            .response
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let error_lower = parsed.error.as_deref().unwrap_or("").to_ascii_lowercase();

        if text_indicates_validation_block(&response_lower)
            || text_indicates_validation_block(&error_lower)
        {
            return Ok(OfficialCliUsageOutcome::ValidationBlocked {
                reason: "Official `agy` reported Google account verification is required."
                    .to_string(),
            });
        }

        if status_upper == "SUCCESS" && exit_success {
            let cmd = parsed.command.as_ref().ok_or_else(|| {
                OfficialCliQuotaError::Protocol(
                    "Official `agy -p \"/usage\"` response is missing the `command` object."
                        .to_string(),
                )
            })?;
            if let Some(ref cmd_name) = cmd.name {
                if !cmd_name.trim().is_empty() && !cmd_name.eq_ignore_ascii_case("usage") {
                    return Err(OfficialCliQuotaError::Protocol(
                        "Official `agy` returned unexpected command payload (expected `usage`)."
                            .to_string(),
                    ));
                }
            }
            let data = cmd.data.as_ref().ok_or_else(|| {
                OfficialCliQuotaError::Protocol(
                    "Official `agy -p \"/usage\"` response is missing `command.data`.".to_string(),
                )
            })?;

            let groups: Vec<QuotaGroup> = data
                .groups
                .iter()
                .map(|g| QuotaGroup {
                    display_name: g
                        .name
                        .clone()
                        .or_else(|| g.display_name.clone())
                        .unwrap_or_default(),
                    description: g
                        .description
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                    buckets: g
                        .buckets
                        .iter()
                        .map(|b| {
                            let known = fraction_is_known(b.remaining_fraction);
                            QuotaBucket {
                                bucket_id: b
                                    .id
                                    .clone()
                                    .or_else(|| b.bucket_id.clone())
                                    .unwrap_or_default(),
                                window: b.window.clone().unwrap_or_default(),
                                remaining_fraction: b.remaining_fraction.unwrap_or(0.0),
                                remaining_fraction_known: Some(known),
                                reset_time: normalize_bucket_reset_time(
                                    b.reset_time.as_deref().unwrap_or(""),
                                    b.remaining_fraction,
                                ),
                                display_name: b.name.clone().or_else(|| b.display_name.clone()),
                                description: b.description.clone(),
                            }
                        })
                        .collect(),
                })
                .collect();

            return Ok(OfficialCliUsageOutcome::Quota {
                groups,
                description: data.description.clone(),
            });
        }

        if text_indicates_validation_block(&combined_lower) {
            return Ok(OfficialCliUsageOutcome::ValidationBlocked {
                reason: "Official `agy` reported Google account verification is required."
                    .to_string(),
            });
        }

        if text_indicates_auth_required(&error_lower)
            || text_indicates_auth_required(&response_lower)
            || text_indicates_auth_required(&combined_lower)
        {
            return Err(OfficialCliQuotaError::AuthRequired(
                "Official `agy` reported the active account is not authenticated or its credentials expired. Re-authenticate with `agy` or `agy-switch-cli auth reauthorize <ID|EMAIL>`."
                    .to_string(),
            ));
        }
        if text_indicates_rate_limit(&error_lower)
            || text_indicates_rate_limit(&response_lower)
            || text_indicates_rate_limit(&combined_lower)
        {
            return Err(OfficialCliQuotaError::RateLimited);
        }
        return Err(OfficialCliQuotaError::CommandFailed(format!(
            "Official `agy -p \"/usage\"` returned non-success status (exit={:?}).",
            exit_code
        )));
    }

    // Non-JSON output fallback classification (never echo raw stdout/stderr in case of secret leakage)
    if text_indicates_validation_block(&combined_lower) {
        return Ok(OfficialCliUsageOutcome::ValidationBlocked {
            reason: "Official `agy` reported Google account verification is required.".to_string(),
        });
    }
    if text_indicates_auth_required(&combined_lower) {
        return Err(OfficialCliQuotaError::AuthRequired(
            "Official `agy` reported the active account is not authenticated or its credentials expired. Re-authenticate with `agy` or `agy-switch-cli auth reauthorize <ID|EMAIL>`."
                .to_string(),
        ));
    }
    if text_indicates_rate_limit(&combined_lower) {
        return Err(OfficialCliQuotaError::RateLimited);
    }
    if !exit_success {
        return Err(OfficialCliQuotaError::CommandFailed(format!(
            "Official `agy -p \"/usage\"` failed with exit code {:?}.",
            exit_code
        )));
    }
    Err(OfficialCliQuotaError::Protocol(
        "Official `agy -p \"/usage\" --output-format json` did not return valid JSON.".to_string(),
    ))
}

struct ProcessGroupKillGuard(Option<u32>);

impl ProcessGroupKillGuard {
    fn kill_group_now(&self) {
        if let Some(pid) = self.0 {
            if pid > 1 {
                unsafe {
                    let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                }
            }
        }
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroupKillGuard {
    fn drop(&mut self) {
        self.kill_group_now();
    }
}

struct AbortOnDrop<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    fn take(&mut self) -> Option<tokio::task::JoinHandle<T>> {
        self.0.take()
    }

    fn abort_now(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.abort_now();
    }
}

async fn read_stdout_bounded_with_watch(
    pipe_opt: Option<tokio::process::ChildStdout>,
    max_bytes: usize,
    overflow_tx: tokio::sync::watch::Sender<bool>,
    auth_prompt_tx: tokio::sync::watch::Sender<bool>,
) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let Some(mut pipe) = pipe_opt else {
        return (buf, false);
    };
    let mut chunk = [0u8; 4096];
    let mut overflowed = false;
    let mut auth_signaled = false;
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > max_bytes {
                    let remain = max_bytes.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..remain]);
                    overflowed = true;
                    let _ = overflow_tx.send(true);
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if !auth_signaled && text_shows_interactive_login_prompt(&buf) {
                    auth_signaled = true;
                    let _ = auth_prompt_tx.send(true);
                }
            }
            Err(_) => break,
        }
    }
    (buf, overflowed)
}

async fn read_stderr_bounded_with_auth_watch(
    pipe_opt: Option<tokio::process::ChildStderr>,
    max_bytes: usize,
    auth_prompt_tx: tokio::sync::watch::Sender<bool>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let Some(mut pipe) = pipe_opt else {
        return buf;
    };
    let mut chunk = [0u8; 4096];
    let mut signaled = false;
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let remain = max_bytes.saturating_sub(buf.len());
                if remain > 0 {
                    buf.extend_from_slice(&chunk[..n.min(remain)]);
                }
                if !signaled && text_shows_interactive_login_prompt(&buf) {
                    signaled = true;
                    let _ = auth_prompt_tx.send(true);
                }
                if buf.len() >= max_bytes {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    buf
}

async fn run_official_cli_usage_subprocess(
    paths: &HeadlessPaths,
    explicit_file_backend: bool,
    timeout: Duration,
    proxy_override: Option<&str>,
) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError> {
    let cfg_network = read_headless_config_readonly(paths)
        .ok()
        .map(|(cfg, _)| cfg.network);
    let proxy_directive = SubprocessProxyOverride::resolve(proxy_override, cfg_network.as_ref())
        .map_err(|e| OfficialCliQuotaError::InvalidProxy(e.message))?;

    let bin = resolve_agy_executable().ok_or(OfficialCliQuotaError::ExecutableNotFound)?;

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.args(["-p", "/usage", "--output-format", "json"])
        .process_group(0)
        .kill_on_drop(true)
        .env("HOME", &paths.home_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    proxy_directive.apply_to_tokio_command(&mut cmd);

    if explicit_file_backend && should_isolate_child_dbus_for_explicit_file_backend() {
        cmd.env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null");
    }

    let mut child = cmd.spawn().map_err(|e| {
        OfficialCliQuotaError::CommandFailed(format!(
            "Failed to spawn official `agy` binary '{}': {e}",
            bin.display()
        ))
    })?;
    let mut pgid_guard = ProcessGroupKillGuard(child.id());

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (auth_tx, mut auth_rx) = tokio::sync::watch::channel(false);
    let (overflow_tx, mut overflow_rx) = tokio::sync::watch::channel(false);

    let mut stdout_task = AbortOnDrop::new(tokio::spawn(read_stdout_bounded_with_watch(
        stdout_pipe,
        MAX_USAGE_OUTPUT_BYTES,
        overflow_tx,
        auth_tx.clone(),
    )));
    let mut stderr_task = AbortOnDrop::new(tokio::spawn(read_stderr_bounded_with_auth_watch(
        stderr_pipe,
        MAX_USAGE_OUTPUT_BYTES,
        auth_tx,
    )));

    enum WaitOutcome {
        Exited(std::io::Result<std::process::ExitStatus>),
        AuthPromptDetected,
        OutputTooLarge,
        TimedOut,
    }

    let wait_outcome = tokio::select! {
        res = child.wait() => WaitOutcome::Exited(res),
        _ = async {
            while !*overflow_rx.borrow() {
                if overflow_rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        } => WaitOutcome::OutputTooLarge,
        _ = async {
            while !*auth_rx.borrow() {
                if auth_rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        } => WaitOutcome::AuthPromptDetected,
        _ = tokio::time::sleep(timeout) => WaitOutcome::TimedOut,
    };

    match wait_outcome {
        WaitOutcome::OutputTooLarge => {
            pgid_guard.kill_group_now();
            let _ = child.wait().await;
            pgid_guard.disarm();
            stdout_task.abort_now();
            stderr_task.abort_now();
            Err(OfficialCliQuotaError::OutputTooLarge)
        }
        WaitOutcome::AuthPromptDetected => {
            pgid_guard.kill_group_now();
            let _ = child.wait().await;
            pgid_guard.disarm();
            stdout_task.abort_now();
            stderr_task.abort_now();
            Err(OfficialCliQuotaError::AuthRequired(
                "Official `agy` prompted for interactive login (active account is unauthenticated or its grant expired). Re-authenticate with `agy` or `agy-switch-cli auth reauthorize <ID|EMAIL>`."
                    .to_string(),
            ))
        }
        WaitOutcome::TimedOut => {
            pgid_guard.kill_group_now();
            let _ = child.wait().await;
            pgid_guard.disarm();
            stdout_task.abort_now();
            stderr_task.abort_now();
            Err(OfficialCliQuotaError::Timeout(timeout))
        }
        WaitOutcome::Exited(Err(e)) => {
            pgid_guard.kill_group_now();
            let _ = child.wait().await;
            pgid_guard.disarm();
            stdout_task.abort_now();
            stderr_task.abort_now();
            Err(OfficialCliQuotaError::CommandFailed(format!(
                "Failed waiting for official `agy -p \"/usage\"`: {e}"
            )))
        }
        WaitOutcome::Exited(Ok(status)) => {
            // Ensure no derived helper child outlives `agy -p "/usage"`
            pgid_guard.kill_group_now();
            pgid_guard.disarm();

            // Bound pipe drain so an escaped (`setsid`) grandchild keeping stdout/stderr open
            // cannot hang `agy-switch-cli` indefinitely.
            let drain_limit = Duration::from_secs(2).min(timeout.max(Duration::from_millis(200)));
            let out_handle = stdout_task.take().expect("stdout task present");
            let err_handle = stderr_task.take().expect("stderr task present");
            let mut out_abort = AbortOnDrop::new(out_handle);
            let mut err_abort = AbortOnDrop::new(err_handle);
            let drained = tokio::time::timeout(drain_limit, async {
                let oh = out_abort.0.as_mut().unwrap();
                let eh = err_abort.0.as_mut().unwrap();
                tokio::join!(oh, eh)
            })
            .await;

            let (stdout_bytes, stdout_overflowed, stderr_bytes) = match drained {
                Ok((out_res, err_res)) => {
                    let _ = out_abort.take();
                    let _ = err_abort.take();
                    let (so, ov) = out_res.unwrap_or((Vec::new(), false));
                    let se = err_res.unwrap_or_default();
                    (so, ov, se)
                }
                Err(_) => {
                    out_abort.abort_now();
                    err_abort.abort_now();
                    return Err(OfficialCliQuotaError::OutputDrainTimeout(drain_limit));
                }
            };
            if stdout_overflowed {
                return Err(OfficialCliQuotaError::OutputTooLarge);
            }
            parse_official_cli_usage_output(
                status.success(),
                status.code(),
                &stdout_bytes,
                &stderr_bytes,
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActiveSlotQuotaRefreshOutcome {
    pub account: AccountRecord,
    pub validation_blocked: bool,
    pub token_synced_back: bool,
}

/// Resolve the currently active official slot account ID from `backend` + `StoreRepository`.
/// If `expected_account_id` is provided and does not match the active slot account, returns
/// `InvalidUsageOrAmbiguous` (exit code 2).
pub fn resolve_active_official_slot_account_id(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    expected_account_id: Option<&str>,
) -> CliResult<(String, u64, Option<String>)> {
    resolve_active_official_slot_account_id_detailed(repo, backend, expected_account_id)
        .map_err(RefreshActiveSlotError::into_cli_error)
}

fn resolve_active_official_slot_account_id_detailed(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    expected_account_id: Option<&str>,
) -> Result<(String, u64, Option<String>), RefreshActiveSlotError> {
    let paths = repo.paths();
    let snap = repo.read_snapshot().map_err(RefreshActiveSlotError::Cli)?;
    let slot_state = backend.inspect_slot(paths);
    let session_id = resolve_session_identity(&slot_state, &snap);

    let active_id = match session_id {
        SessionIdentity::Matched { account_id, .. }
        | SessionIdentity::DriftedKnown { account_id, .. } => account_id,
        SessionIdentity::DriftedExternal { .. } => {
            // Under Option 1B, official `agy` may have rotated `refresh_token` on the selected
            // account during interactive usage before the next `refresh` or `quota --refresh`.
            if let (SlotInspectState::Present(ref parsed), Some(sel_acc)) =
                (&slot_state, snap.selected_account())
            {
                if slot_matches_selected_rotated_account(repo, &snap, parsed, sel_acc) {
                    sel_acc.id.clone()
                } else {
                    return Err(RefreshActiveSlotError::PreProbeSlotMismatch(
                        CliError::not_found(
                            "Active official `agy` slot holds an account not saved in this store. Run `agy-switch-cli accounts add --from-local` or `agy-switch-cli switch <ID|EMAIL>` first.",
                        ),
                    ));
                }
            } else {
                return Err(RefreshActiveSlotError::PreProbeSlotMismatch(
                    CliError::not_found(
                        "Active official `agy` slot holds an account not saved in this store. Run `agy-switch-cli accounts add --from-local` or `agy-switch-cli switch <ID|EMAIL>` first.",
                    ),
                ));
            }
        }
        SessionIdentity::Uninitialized => {
            return Err(RefreshActiveSlotError::PreProbeSlotMismatch(
                CliError::env_not_ready(
                    "agy_uninitialized",
                    format!(
                        "No active `agy` credential found at '{}'. Sign in with `agy` or switch to a saved account first.",
                        paths.active_slot_file.display()
                    ),
                ),
            ));
        }
        SessionIdentity::Corrupt { detail } => {
            return Err(RefreshActiveSlotError::PreProbeSlotMismatch(
                CliError::data(format!(
                    "Active official `agy` credential slot is corrupt: {detail}"
                )),
            ));
        }
        SessionIdentity::Unverified { detail } => {
            return Err(RefreshActiveSlotError::PreProbeSlotMismatch(
                CliError::env_not_ready(
                    "slot_unverified",
                    format!("Cannot verify active official `agy` credential slot: {detail}"),
                ),
            ));
        }
    };

    if let Some(exp) = expected_account_id {
        if exp != active_id {
            return Err(RefreshActiveSlotError::PreProbeSlotMismatch(CliError::usage(
                format!(
                    "Account '{exp}' is not currently active on the official `agy` slot (active: '{active_id}'). Only the currently active official slot can be refreshed via `agy -p \"/usage\"`; switch to '{exp}' first (`agy-switch-cli switch {exp}`)."
                ),
            )));
        }
    }

    Ok((
        active_id,
        snap.index.revision,
        snap.index.selected_account_id,
    ))
}

/// Refresh quota for the currently active official `agy` slot using `agy -p "/usage" --output-format json`.
/// - Strictly targets ONLY the active official slot (rejects dormant selectors with exit code 2);
/// - Synchronizes any refreshed `access_token` / rotated `refresh_token` written by official `agy`
///   back into `accounts/<id>.json` purely locally (preserving 66,048-level lineage);
/// - Marks `validation_blocked` on Google verification block responses and clears it on clean success;
/// - Refuses to write back if another process switched accounts while `agy` was running.
pub async fn refresh_active_slot_quota_via_official_cli(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    explicit_file_backend: bool,
    expected_account_id: Option<&str>,
    now_unix: i64,
) -> CliResult<ActiveSlotQuotaRefreshOutcome> {
    refresh_active_slot_quota_via_official_cli_with_proxy(
        repo,
        backend,
        explicit_file_backend,
        None,
        expected_account_id,
        now_unix,
    )
    .await
}

pub async fn refresh_active_slot_quota_via_official_cli_with_proxy(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    explicit_file_backend: bool,
    proxy_override: Option<String>,
    expected_account_id: Option<&str>,
    now_unix: i64,
) -> CliResult<ActiveSlotQuotaRefreshOutcome> {
    let runner = SystemOfficialCliRunner::with_proxy(proxy_override);
    refresh_active_slot_quota_with_runner(
        repo,
        backend,
        &runner,
        explicit_file_backend,
        expected_account_id,
        now_unix,
    )
    .await
}

pub async fn refresh_active_slot_quota_with_runner(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    runner: &dyn OfficialCliQuotaRunner,
    explicit_file_backend: bool,
    expected_account_id: Option<&str>,
    now_unix: i64,
) -> CliResult<ActiveSlotQuotaRefreshOutcome> {
    refresh_active_slot_quota_detailed(
        repo,
        backend,
        runner,
        explicit_file_backend,
        expected_account_id,
        now_unix,
    )
    .await
    .map_err(RefreshActiveSlotError::into_cli_error)
}

#[derive(Debug)]
pub enum RefreshActiveSlotError {
    /// Active slot no longer matched the expected account before probing began (e.g., an external
    /// `agy login`, manual switch, wipe, or corruption occurred prior to pre-probe inspection).
    PreProbeSlotMismatch(CliError),
    Cli(CliError),
    Probe {
        error: OfficialCliQuotaError,
    },
}

impl RefreshActiveSlotError {
    pub fn into_cli_error(self) -> CliError {
        match self {
            Self::PreProbeSlotMismatch(c) | Self::Cli(c) => c,
            Self::Probe { error } => error.into_cli_error(),
        }
    }
}

pub async fn refresh_active_slot_quota_detailed(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    runner: &dyn OfficialCliQuotaRunner,
    explicit_file_backend: bool,
    expected_account_id: Option<&str>,
    now_unix: i64,
) -> Result<ActiveSlotQuotaRefreshOutcome, RefreshActiveSlotError> {
    let clock = AnchoredClock::new(now_unix);
    let paths = repo.paths();

    let (active_id, pre_index_rev, pre_selected_id) =
        resolve_active_official_slot_account_id_detailed(repo, backend, expected_account_id)?;
    let pre_active_email = repo
        .read_account_unchecked(&active_id)
        .map_err(RefreshActiveSlotError::Cli)?
        .email;

    let probe_res = runner
        .query_active_usage(paths, explicit_file_backend)
        .await;

    // Verify no concurrent switch (including ABA switch, multi-collection keyring divergence, or
    // external rollback to a superseded RT), deletion, or slot wipe/corruption changed the active
    // slot while `agy` was executing. Inspect ALL managed replicas once (`inspect_replicas`) so
    // `dual` backends derive verified per-replica checkpoints without trusting unverified files.
    let post_snap = repo.read_snapshot().map_err(RefreshActiveSlotError::Cli)?;
    let post_replicas = backend.inspect_replicas(paths);
    let post_slot = post_replicas.effective_slot_state();
    let post_identity = resolve_session_identity(post_slot, &post_snap);
    let post_active_acc = post_snap.accounts.iter().find(|a| a.id == active_id);
    let post_identity_matches_active = match (&post_identity, post_slot, post_active_acc) {
        (
            SessionIdentity::Matched { account_id, .. }
            | SessionIdentity::DriftedKnown { account_id, .. },
            _,
            Some(_),
        ) => account_id == &active_id,
        (
            SessionIdentity::DriftedExternal { .. },
            SlotInspectState::Present(parsed),
            Some(active_acc),
        ) => {
            parsed
                .email_hint
                .as_deref()
                .is_some_and(|hint| hint.eq_ignore_ascii_case(&pre_active_email))
                && slot_matches_selected_rotated_account(repo, &post_snap, parsed, active_acc)
        }
        _ => false,
    };
    let concurrent_switch = post_active_acc.is_none()
        || post_snap.index.revision != pre_index_rev
        || post_snap.index.selected_account_id != pre_selected_id
        || (post_replicas.uses_keyring && !post_replicas.keyring_all_collections_uniform)
        || !post_identity_matches_active;

    if concurrent_switch {
        return Err(RefreshActiveSlotError::Cli(CliError::conflict(
            "active_slot_changed_during_refresh",
            "Active account changed concurrently while official `agy -p \"/usage\"` was running; discarded stale quota result.",
        )));
    }

    // Pure-local sync-back captures any fresher access_token / rotated refresh_token
    // that official `agy` may have written during `/usage` (even if `/usage` subsequently failed!).
    let sync_outcome =
        sync_back_active_slot_for_account(repo, backend, &active_id, clock.now_unix())
            .map_err(RefreshActiveSlotError::Cli)?;

    let usage_outcome = probe_res.map_err(|error| RefreshActiveSlotError::Probe { error })?;

    let obs_now = clock.now_unix();
    let mut obs = QuotaObservation::new(obs_now, QuotaSourceEnv::OfficialCli);
    obs.summary_source_env = Some(QuotaSourceEnv::OfficialCli);

    let (validation_block, allow_clear_validation_block, is_validation_blocked) =
        match usage_outcome {
            OfficialCliUsageOutcome::Quota { groups, .. } => {
                obs.quota_groups = (!groups.is_empty()).then_some(groups);
                (None, true, false)
            }
            OfficialCliUsageOutcome::ValidationBlocked { reason } => {
                obs.is_forbidden = true;
                (Some((reason, None)), false, true)
            }
        };

    let updated = repo
        .with_write_lock(|tx| {
            tx.merge_quota_observation(
                &active_id,
                obs,
                None,
                validation_block,
                allow_clear_validation_block,
            )
        })
        .map_err(RefreshActiveSlotError::Cli)?;

    Ok(ActiveSlotQuotaRefreshOutcome {
        account: updated,
        validation_blocked: is_validation_blocked,
        token_synced_back: sync_outcome.token_updated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_official_cli_usage_normalizes_epoch0_and_preserves_group_descriptions() {
        let raw = serde_json::json!({
            "conversation_id": "",
            "status": "SUCCESS",
            "response": "ok",
            "duration_seconds": 0,
            "num_turns": 0,
            "usage": {"input_tokens": 0, "output_tokens": 0, "thinking_tokens": 0, "cache_read_tokens": 0, "total_tokens": 0},
            "command": {
                "name": "usage",
                "data": {
                    "description": "Account quota summary",
                    "groups": [
                        {
                            "name": "Gemini Models",
                            "description": "Models within this group: Gemini 2.5 Pro, Gemini 2.5 Flash",
                            "buckets": [
                                {"id": "gemini-weekly", "name": "Weekly Limit Remaining", "window": "weekly", "remaining_fraction": 0.9748547, "reset_time": "2026-12-03T07:17:01Z"},
                                {"id": "gemini-5h", "name": "Five Hour Limit Remaining", "window": "5h", "remaining_fraction": 0.9726360, "reset_time": "2026-11-27T11:18:26Z"}
                            ]
                        },
                        {
                            "name": "Claude and GPT models",
                            "description": "Models within this group: Claude Sonnet 4",
                            "buckets": [
                                {"id": "3p-weekly", "name": "Weekly Limit Remaining", "window": "weekly", "remaining_fraction": 1, "reset_time": "1970-01-01T00:00:00Z"},
                                {"id": "3p-5h", "name": "Five Hour Limit Remaining", "window": "5h", "remaining_fraction": 1, "reset_time": "1970-01-01T00:00:00Z"}
                            ]
                        }
                    ]
                }
            }
        });
        let bytes = serde_json::to_vec(&raw).unwrap();
        let parsed = parse_official_cli_usage_output(true, Some(0), &bytes, b"").unwrap();
        let OfficialCliUsageOutcome::Quota { groups, .. } = parsed else {
            panic!("expected Quota");
        };
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].display_name, "Gemini Models");
        assert_eq!(
            groups[0].description.as_deref(),
            Some("Models within this group: Gemini 2.5 Pro, Gemini 2.5 Flash")
        );
        assert_eq!(groups[0].buckets[0].bucket_id, "gemini-weekly");
        assert_eq!(groups[0].buckets[0].reset_time, "2026-12-03T07:17:01Z");
        // Untouched 100% bucket with epoch 0 MUST be normalized to ""!
        assert_eq!(groups[1].buckets[0].bucket_id, "3p-weekly");
        assert_eq!(groups[1].buckets[0].reset_time, "");
        assert_eq!(groups[1].buckets[1].reset_time, "");
    }

    #[test]
    fn parse_official_cli_usage_classifies_auth_required_and_validation_block_without_secret_echo()
    {
        let auth_json = br#"{"conversation_id":"","status":"ERROR","response":"","error":"authentication failed or timed out"}"#;
        let auth_err = parse_official_cli_usage_output(
            false,
            Some(1),
            auth_json,
            b"Authentication required. Please visit the URL to log in: https://accounts.google.com/o/oauth2/auth?secret=TOP_SECRET_999",
        )
        .unwrap_err();
        assert!(matches!(auth_err, OfficialCliQuotaError::AuthRequired(_)));
        let cli_err = auth_err.into_cli_error();
        assert_eq!(cli_err.exit_code.as_i32(), 6);
        assert_eq!(cli_err.error_code, "official_cli_auth_required");
        assert!(!cli_err.message.contains("TOP_SECRET_999"));

        let val_json = br#"{"status":"ERROR","error":"403 VALIDATION_REQUIRED: https://verify.example/secret-token-123"}"#;
        let val_out = parse_official_cli_usage_output(false, Some(1), val_json, b"").unwrap();
        match val_out {
            OfficialCliUsageOutcome::ValidationBlocked { reason } => {
                assert!(!reason.contains("secret-token-123"));
            }
            _ => panic!("expected ValidationBlocked"),
        }
    }

    #[test]
    fn parse_official_cli_usage_tolerates_non_json_preamble_and_ignores_benign_stderr_on_success() {
        let noisy_stdout = concat!(
            "Warning: loading experimental usage plugin...\n",
            r#"{"status":"SUCCESS","response":"ok","command":{"name":"usage","data":{"groups":[{"name":"Gemini Models","buckets":[{"id":"gemini-weekly","window":"weekly","remaining_fraction":0.85,"reset_time":"2099-12-03T07:17:01Z"},{"id":"gemini-5h","window":"5h","remaining_fraction":0.80,"reset_time":"2099-11-27T11:18:26Z"}]}]}}}"#,
            "\nTrailing diagnostic footer\n"
        );
        // Noisy stderr mentioning `validation_url` must not override a clean SUCCESS quota payload.
        let parsed = parse_official_cli_usage_output(
            true,
            Some(0),
            noisy_stdout.as_bytes(),
            b"debug: validation_url check passed",
        )
        .unwrap();
        match parsed {
            OfficialCliUsageOutcome::Quota { groups, .. } => {
                assert_eq!(groups.len(), 1);
                assert_eq!(groups[0].buckets.len(), 2);
            }
            _ => panic!("expected Quota despite preamble and benign stderr"),
        }
    }

    #[tokio::test]
    async fn synthetic_v127_official_cli_handles_rotated_rt_aba_switch_and_slot_wipe() {
        use crate::domain::token::TokenRecord;
        use crate::session::backend::FileSessionBackend;
        use crate::session::payload::serialize_session_payload;
        use std::fs;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let now = 1_900_000_000i64;

        let mut acc1 = AccountRecord::new(
            "acc-0001".into(),
            "alice@example.com".into(),
            TokenRecord {
                access_token: "ya29.v1".into(),
                refresh_token: "1//RT_ALICE_1".into(),
                expires_in: 3600,
                expiry_timestamp: now + 3600,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: None,
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        );
        acc1.record_superseded_digest(&crate::domain::token::token_digest("1//RT_ALICE_OLD_0"));
        let acc2 = AccountRecord::new(
            "acc-0002".into(),
            "bob@example.com".into(),
            TokenRecord {
                access_token: "ya29.bob".into(),
                refresh_token: "1//RT_BOB_1".into(),
                expires_in: 3600,
                expiry_timestamp: now + 3600,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: None,
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        );
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc1.clone(), true, now)?;
            tx.upsert_account(acc2.clone(), false, now)?;
            Ok(())
        })
        .unwrap();

        // 1. Superseded historical RT in active slot MUST NOT be treated as a valid rotated token.
        fs::write(
            &paths.active_slot_file,
            serde_json::to_vec(&serde_json::json!({
                "token": {"access_token": "ya29.old", "refresh_token": "1//RT_ALICE_OLD_0", "expiry": "2099-01-01T00:00:00Z"},
                "id_token_email": "alice@example.com"
            }))
            .unwrap(),
        )
        .unwrap();
        let sup_err =
            resolve_active_official_slot_account_id(&repo, &FileSessionBackend, None).unwrap_err();
        assert_eq!(sup_err.exit_code.as_i32(), 3);

        // 2. Freshly rotated RT written by official `agy` during interactive usage MUST resolve to `acc-0001`
        //    and sync back into `accounts/acc-0001.json` during `/usage` refresh!
        fs::write(
            &paths.active_slot_file,
            serde_json::to_vec(&serde_json::json!({
                "token": {"access_token": "ya29.v2", "refresh_token": "1//RT_ALICE_2", "expiry": "2099-02-01T00:00:00Z"},
                "id_token_email": "alice@example.com",
                "user_tier": "g1-pro-tier"
            }))
            .unwrap(),
        )
        .unwrap();
        struct HookRunner {
            hook: Arc<dyn Fn() + Send + Sync>,
        }
        impl OfficialCliQuotaRunner for HookRunner {
            fn query_active_usage<'a>(
                &'a self,
                _paths: &'a HeadlessPaths,
                _explicit_file_backend: bool,
            ) -> BoxFuture<'a, Result<OfficialCliUsageOutcome, OfficialCliQuotaError>> {
                Box::pin(async move {
                    (self.hook)();
                    Ok(OfficialCliUsageOutcome::Quota {
                        description: None,
                        groups: vec![QuotaGroup {
                            display_name: "Gemini Models".into(),
                            description: None,
                            buckets: vec![
                                QuotaBucket {
                                    bucket_id: "gemini-5h".into(),
                                    window: "5h".into(),
                                    remaining_fraction: 0.77,
                                    remaining_fraction_known: Some(true),
                                    reset_time: "2099-01-01T05:00:00Z".into(),
                                    display_name: None,
                                    description: None,
                                },
                                QuotaBucket {
                                    bucket_id: "gemini-weekly".into(),
                                    window: "weekly".into(),
                                    remaining_fraction: 0.88,
                                    remaining_fraction_known: Some(true),
                                    reset_time: "2099-01-07T00:00:00Z".into(),
                                    display_name: None,
                                    description: None,
                                },
                            ],
                        }],
                    })
                })
            }
        }
        let ok_runner = HookRunner {
            hook: Arc::new(|| {}),
        };
        let rotated_out = refresh_active_slot_quota_with_runner(
            &repo,
            &FileSessionBackend,
            &ok_runner,
            true,
            Some("acc-0001"),
            now + 5,
        )
        .await
        .unwrap();
        assert!(rotated_out.token_synced_back);
        assert_eq!(rotated_out.account.token.refresh_token, "1//RT_ALICE_2");
        assert_eq!(rotated_out.account.token.access_token, "ya29.v2");

        // 3. ABA concurrent switch (`acc-0001 -> acc-0002 -> acc-0001`) during probe bumps `index.revision`
        //    and MUST discard the stale quota result (`active_slot_changed_during_refresh`)!
        let repo_aba = repo.clone();
        let aba_runner = HookRunner {
            hook: Arc::new(move || {
                repo_aba
                    .with_write_lock(|tx| {
                        tx.commit_selected_account("acc-0002", now + 10)?;
                        tx.commit_selected_account("acc-0001", now + 11)?;
                        Ok(())
                    })
                    .unwrap();
            }),
        };
        let aba_err = refresh_active_slot_quota_with_runner(
            &repo,
            &FileSessionBackend,
            &aba_runner,
            true,
            Some("acc-0001"),
            now + 12,
        )
        .await
        .unwrap_err();
        assert_eq!(aba_err.error_code, "active_slot_changed_during_refresh");

        // 4. Slot deletion (`Uninitialized`) during probe MUST also discard stale quota result!
        let acc1_latest = repo.read_account_unchecked("acc-0001").unwrap();
        fs::write(
            &paths.active_slot_file,
            serialize_session_payload(&acc1_latest.token).unwrap(),
        )
        .unwrap();
        let slot_path = paths.active_slot_file.clone();
        let wipe_runner = HookRunner {
            hook: Arc::new(move || {
                let _ = fs::remove_file(&slot_path);
            }),
        };
        let wipe_err = refresh_active_slot_quota_with_runner(
            &repo,
            &FileSessionBackend,
            &wipe_runner,
            true,
            Some("acc-0001"),
            now + 15,
        )
        .await
        .unwrap_err();
        assert_eq!(wipe_err.error_code, "active_slot_changed_during_refresh");

        // 5. Post-probe concurrent external rollback to a superseded historical RT (inline OR spilled
        //    archive) with matching `email_hint` MUST be rejected with `active_slot_changed_during_refresh`!
        let acc1_now = repo.read_account_unchecked("acc-0001").unwrap();
        assert!(acc1_now.has_superseded_refresh_token("1//RT_ALICE_1"));
        fs::write(
            &paths.active_slot_file,
            serialize_session_payload(&acc1_now.token).unwrap(),
        )
        .unwrap();
        let slot_path_inline = paths.active_slot_file.clone();
        let rollback_inline_runner = HookRunner {
            hook: Arc::new(move || {
                // External actor rolls the slot back to superseded `1//RT_ALICE_1` mid-probe.
                fs::write(
                    &slot_path_inline,
                    serde_json::to_vec(&serde_json::json!({
                        "token": {
                            "access_token": "ya29.stale_v1",
                            "token_type": "Bearer",
                            "refresh_token": "1//RT_ALICE_1",
                            "expiry": "2099-01-01T00:00:00Z"
                        },
                        "id_token_email": "alice@example.com"
                    }))
                    .unwrap(),
                )
                .unwrap();
            }),
        };
        let inline_err = refresh_active_slot_quota_with_runner(
            &repo,
            &FileSessionBackend,
            &rollback_inline_runner,
            true,
            Some("acc-0001"),
            now + 20,
        )
        .await
        .unwrap_err();
        assert_eq!(inline_err.error_code, "active_slot_changed_during_refresh");
        // Verify neither quota timestamp nor current RT was clobbered by the rejected probe.
        let acc1_after_inline = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(acc1_after_inline.token.refresh_token, "1//RT_ALICE_2");
        assert_eq!(
            acc1_after_inline.quota.as_ref().map(|q| q.last_updated),
            Some(now + 5)
        );

        // 5b. Spilled archive lineage digest (`state/token_lineage/acc-0001.json`) is ALSO rejected!
        let archived_rt = "1//RT_ALICE_0_ARCHIVED";
        let archived_digest = crate::domain::token::token_digest(archived_rt);
        let lineage_dir = paths.token_lineage_dir();
        fs::create_dir_all(&lineage_dir).unwrap();
        fs::write(
            paths.token_lineage_file("acc-0001"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "account_id": "acc-0001",
                "digests": [archived_digest],
                "truncated": false
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &paths.active_slot_file,
            serialize_session_payload(&acc1_after_inline.token).unwrap(),
        )
        .unwrap();
        let slot_path_arch = paths.active_slot_file.clone();
        let rollback_arch_runner = HookRunner {
            hook: Arc::new(move || {
                fs::write(
                    &slot_path_arch,
                    serde_json::to_vec(&serde_json::json!({
                        "token": {
                            "access_token": "ya29.stale_v0",
                            "token_type": "Bearer",
                            "refresh_token": archived_rt,
                            "expiry": "2099-01-01T00:00:00Z"
                        },
                        "id_token_email": "alice@example.com"
                    }))
                    .unwrap(),
                )
                .unwrap();
            }),
        };
        let arch_err = refresh_active_slot_quota_with_runner(
            &repo,
            &FileSessionBackend,
            &rollback_arch_runner,
            true,
            Some("acc-0001"),
            now + 25,
        )
        .await
        .unwrap_err();
        assert_eq!(arch_err.error_code, "active_slot_changed_during_refresh");

        // 5c. Legitimate brand-new RT rotation by official `agy` during probe STILL succeeds!
        fs::write(
            &paths.active_slot_file,
            serialize_session_payload(&acc1_after_inline.token).unwrap(),
        )
        .unwrap();
        let slot_path_fresh = paths.active_slot_file.clone();
        let fresh_rot_runner = HookRunner {
            hook: Arc::new(move || {
                fs::write(
                    &slot_path_fresh,
                    serde_json::to_vec(&serde_json::json!({
                        "token": {
                            "access_token": "ya29.fresh_v3",
                            "token_type": "Bearer",
                            "refresh_token": "1//RT_ALICE_3_FRESH",
                            "expiry": "2099-02-01T00:00:00Z"
                        },
                        "id_token_email": "alice@example.com"
                    }))
                    .unwrap(),
                )
                .unwrap();
            }),
        };
        let fresh_ok = refresh_active_slot_quota_with_runner(
            &repo,
            &FileSessionBackend,
            &fresh_rot_runner,
            true,
            Some("acc-0001"),
            now + 30,
        )
        .await
        .unwrap();
        assert!(fresh_ok.token_synced_back);
        assert_eq!(fresh_ok.account.token.refresh_token, "1//RT_ALICE_3_FRESH");
        assert_eq!(fresh_ok.account.token.access_token, "ya29.fresh_v3");

        // 5d. Corrupt `state/token_lineage/acc-0001.json` during a concurrent `DriftedExternal` RT
        //     rotation MUST fail closed with `active_slot_changed_during_refresh` (never clobbering)!
        let acc1_before_corrupt = repo.read_account_unchecked("acc-0001").unwrap();
        fs::write(
            &paths.active_slot_file,
            serialize_session_payload(&acc1_before_corrupt.token).unwrap(),
        )
        .unwrap();
        fs::write(paths.token_lineage_file("acc-0001"), b"{not valid json!!!").unwrap();
        let slot_path_corrupt = paths.active_slot_file.clone();
        let corrupt_lineage_runner = HookRunner {
            hook: Arc::new(move || {
                fs::write(
                    &slot_path_corrupt,
                    serde_json::to_vec(&serde_json::json!({
                        "token": {
                            "access_token": "ya29.unverifiable_v4",
                            "token_type": "Bearer",
                            "refresh_token": "1//RT_ALICE_4_UNVERIFIABLE",
                            "expiry": "2099-03-01T00:00:00Z"
                        },
                        "id_token_email": "alice@example.com"
                    }))
                    .unwrap(),
                )
                .unwrap();
            }),
        };
        let corrupt_err = refresh_active_slot_quota_with_runner(
            &repo,
            &FileSessionBackend,
            &corrupt_lineage_runner,
            true,
            Some("acc-0001"),
            now + 35,
        )
        .await
        .unwrap_err();
        assert_eq!(corrupt_err.error_code, "active_slot_changed_during_refresh");
        let acc1_after_corrupt = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(
            acc1_after_corrupt.token.refresh_token,
            "1//RT_ALICE_3_FRESH"
        );
        assert_eq!(
            acc1_after_corrupt.quota.as_ref().map(|q| q.last_updated),
            Some(now + 30)
        );
    }

    #[test]
    fn empty_groups_success_ignores_benign_stderr_and_drain_timeout_reports_drain_duration() {
        // S6 regression: structured `SUCCESS` with `groups: []` MUST NOT scrape benign stderr
        // containing `validation_url` into `ValidationBlocked`.
        let empty_success = serde_json::json!({
            "conversation_id": "",
            "status": "SUCCESS",
            "response": "No active quota pools returned.",
            "command": {
                "name": "usage",
                "data": {
                    "description": "Empty summary",
                    "groups": []
                }
            }
        })
        .to_string();
        let benign_stderr = b"debug: validation_url check passed\n";
        let parsed =
            parse_official_cli_usage_output(true, Some(0), empty_success.as_bytes(), benign_stderr)
                .unwrap();
        assert!(
            matches!(parsed, OfficialCliUsageOutcome::Quota { ref groups, .. } if groups.is_empty()),
            "empty-groups SUCCESS with benign stderr must remain Quota(empty), got {parsed:?}"
        );

        // Positive control: structured `response` explicitly carrying `VALIDATION_REQUIRED` STILL
        // classifies as `ValidationBlocked`.
        let real_block = serde_json::json!({
            "conversation_id": "",
            "status": "SUCCESS",
            "response": "403 VALIDATION_REQUIRED: further action is required",
            "command": {
                "name": "usage",
                "data": {
                    "description": "",
                    "groups": []
                }
            }
        })
        .to_string();
        let parsed_block =
            parse_official_cli_usage_output(true, Some(0), real_block.as_bytes(), b"").unwrap();
        assert!(
            matches!(
                parsed_block,
                OfficialCliUsageOutcome::ValidationBlocked { .. }
            ),
            "structured validation block in response must still be detected: {parsed_block:?}"
        );

        // Drain timeout diagnostic distinguishes 2s pipe drain from 30s subprocess timeout while
        // preserving error_code `official_cli_timeout`.
        let drain_err =
            OfficialCliQuotaError::OutputDrainTimeout(Duration::from_secs(2)).into_cli_error();
        assert_eq!(drain_err.error_code, "official_cli_timeout");
        assert!(
            drain_err
                .message
                .contains("draining stdout/stderr timed out after 2s"),
            "drain timeout error should report 2s drain duration: {}",
            drain_err.message
        );
        let proc_err = OfficialCliQuotaError::Timeout(Duration::from_secs(30)).into_cli_error();
        assert_eq!(proc_err.error_code, "official_cli_timeout");
        assert!(
            proc_err.message.contains("timed out after 30s"),
            "process timeout error should report 30s subprocess duration: {}",
            proc_err.message
        );
    }
}
