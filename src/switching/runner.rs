use crate::domain::account::{AccountRecord, DisableReasonCode, RuntimeState};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::domain::policy::{PolicyStrategy, SwitchPolicy};
use crate::domain::quota::{evaluate_account_quota, QuotaEval, DEFAULT_QUOTA_MAX_AGE_SECS};
use crate::error::{CliError, CliResult};
use crate::oauth::refresh::{
    persist_disable_or_report_io_error, OAuthEndpoints, TOKEN_REFRESH_SKEW_SECONDS,
};
use crate::oauth::registry::OAuthClientRegistry;
use crate::quota::client::{refresh_account_quota_locked, CloudCodeEndpoints};
use crate::session::backend::{CredentialBackend, SlotInspectState};
use crate::session::journal::reconcile_pending_journal_for_slot_consumer;
use crate::session::payload::{bytes_sha256_hex, serialize_session_payload};
use crate::session::process::{observe_runtime_state, remove_process_lease, write_process_lease};
use crate::store::repository::{StoreRepository, StoreSnapshot};
use crate::switching::executor::{execute_switch, validate_target_usable, SwitchOptions};
use crate::transport::client::HttpTransport;
use crate::transport::user_agent::resolve_agy_executable;
use std::path::PathBuf;
use std::process::Stdio;

/// Pre-invocation managed wrapper (`agy-switch-cli run [--account <SEL>] [--isolate-dbus] -- agy [<ARGS>...]`) per Blueprint §7.1.
#[allow(clippy::too_many_arguments)]
pub async fn run_managed_agy(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    quota_endpoints: &CloudCodeEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    explicit_account: Option<&str>,
    isolate_dbus: bool,
    command_args: &[String],
    now_unix: i64,
) -> CliResult<i32> {
    if command_args.is_empty() {
        return Err(CliError::usage(
            "Missing command after `--`. Expected: `agy-switch-cli run -- agy [<ARGS>...]`.",
        ));
    }
    let program = &command_args[0];
    let prog_base = std::path::Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if prog_base != "agy" {
        return Err(CliError::usage(
            "`run` only wraps the official `agy` executable. Expected: `agy-switch-cli run -- agy ...`.",
        ));
    }

    let resolved_bin: PathBuf = if program.contains('/') {
        let p = PathBuf::from(program);
        if !p.is_file() {
            return Err(CliError::env_not_ready(
                "agy_not_found",
                "Specified `agy` executable path does not exist.",
            ));
        }
        p
    } else {
        resolve_agy_executable().ok_or_else(|| {
            CliError::env_not_ready(
                "agy_not_found",
                "Official `agy` executable not found in PATH.",
            )
        })?
    };

    let paths = repo.paths();
    let clock = AnchoredClock::new(now_unix);

    // 0. Auto-reconcile any pending `switch_journal.json` (or block on `RecoveryIncomplete`) before reading index.json
    reconcile_pending_journal_for_slot_consumer(repo, backend, clock.now_unix())?;

    // 1. Fail-closed runtime process check: reject BOTH unmanaged running `agy` AND unverified `/proc`!
    let runtime = observe_runtime_state(paths);
    match runtime {
        RuntimeState::UnmanagedRunning { ref pids, .. } => {
            return Err(CliError::env_not_ready(
                "unmanaged_agy_running",
                format!(
                    "Unmanaged `agy` process(es) {:?} are currently running. Wait for them to finish or isolate parallel sessions in separate `HOME` directories.",
                    pids
                ),
            ));
        }
        RuntimeState::Unverified { ref detail } => {
            return Err(CliError::env_not_ready(
                "runtime_state_unverified",
                format!(
                    "Cannot verify whether `agy` is currently running ({detail}). Refusing to modify credentials or launch managed session while process state is unverified."
                ),
            ));
        }
        RuntimeState::Idle | RuntimeState::ManagedRunning { .. } => {}
    }

    let active_account_id = prepare_account_before_spawn(
        repo,
        backend,
        transport,
        oauth_endpoints,
        quota_endpoints,
        registry,
        user_agent,
        explicit_account,
        &runtime,
        &clock,
    )
    .await?;

    // 4. Spawn child `agy`, register two-factor lease (`pid` + `/proc/<pid>/stat` field 22 `starttime`),
    // forward signals, and return exact child exit code!
    let mut cmd = tokio::process::Command::new(&resolved_bin);
    cmd.args(&command_args[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if isolate_dbus && !backend.uses_keyring() {
        cmd.env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/dev/null");
    }
    let mut child = cmd.spawn().map_err(|e| {
        CliError::io(
            "agy_spawn_failed",
            format!("Failed to spawn '{}': {e}", resolved_bin.display()),
        )
    })?;

    let Some(pid) = child.id() else {
        let status = child
            .wait()
            .await
            .map_err(|e| CliError::io("agy_wait_failed", format!("Wait failed: {e}")))?;
        return Ok(exit_status_to_code(status));
    };

    // Write two-factor lease (best-effort if child exited in <1ms before /proc/<pid>/stat read)
    let _ = write_process_lease(paths, pid, &active_account_id, clock.now_unix());

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();

    let status = loop {
        tokio::select! {
            res = child.wait() => {
                break res.map_err(|e| CliError::io("agy_wait_failed", format!("Failed waiting for child `agy`: {e}")));
            }
            _ = async {
                if let Some(ref mut s) = sigint {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                unsafe { let _ = libc::kill(pid as i32, libc::SIGINT); }
            }
            _ = async {
                if let Some(ref mut s) = sigterm {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                unsafe { let _ = libc::kill(pid as i32, libc::SIGTERM); }
            }
        }
    };

    remove_process_lease(paths, pid);

    let exit_status = status?;
    Ok(exit_status_to_code(exit_status))
}

fn exit_status_to_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(|sig| 128 + sig).unwrap_or(1)
    }
}

#[allow(clippy::too_many_arguments)]
async fn prepare_account_before_spawn(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    quota_endpoints: &CloudCodeEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    explicit_account: Option<&str>,
    runtime: &RuntimeState,
    clock: &dyn Clock,
) -> CliResult<String> {
    let paths = repo.paths();
    let snapshot = repo.read_snapshot()?;

    // Case A: Explicit `--account <SEL>`
    if let Some(sel) = explicit_account {
        let target = snapshot.select(sel)?;
        let ts = clock.now_unix();
        ensure_account_usable_and_scoped(repo, target, registry, ts)?;
        ensure_no_conflicting_managed_session(runtime, &target.id)?;

        let slot = backend.inspect_slot(paths);
        if !is_slot_synced_and_fresh(&slot, &snapshot, target, ts) {
            execute_switch(
                repo,
                backend,
                transport,
                oauth_endpoints,
                registry,
                user_agent,
                &target.id,
                &SwitchOptions {
                    dry_run: false,
                    allow_running: true, // Same-account managed session (and verified `/proc`) was already confirmed above
                },
                clock.now_unix(),
            )
            .await?;
        }
        return Ok(target.id.clone());
    }

    // Case B: Policy-driven pre-invocation selection
    let selected = snapshot.selected_account().ok_or_else(|| {
        CliError::not_found(
            "No selected account in store. Import/login and `switch` to an account first, or pass `--account <ID|EMAIL>`.",
        )
    })?;
    let selected_id = selected.id.clone();

    let policy = repo.read_policy()?;

    // Step 2: Refresh current account quota if missing or stale when policy is enabled
    let mut current_acc = selected.clone();
    let initial_eval = evaluate_account_quota(
        &current_acc,
        &policy.monitored_model,
        clock.now_unix(),
        DEFAULT_QUOTA_MAX_AGE_SECS,
    );
    if policy.enabled
        && matches!(
            initial_eval,
            QuotaEval::Unknown { .. } | QuotaEval::Stale { .. }
        )
    {
        match refresh_account_quota_locked(
            repo,
            transport,
            oauth_endpoints,
            quota_endpoints,
            registry,
            user_agent,
            &selected_id,
            clock.now_unix(),
        )
        .await
        {
            Ok(updated) => current_acc = updated,
            Err(_) => {
                if let Ok(reloaded) = repo.read_account_unchecked(&selected_id) {
                    current_acc = reloaded;
                }
            }
        }
    }

    let current_eval = evaluate_account_quota(
        &current_acc,
        &policy.monitored_model,
        clock.now_unix(),
        DEFAULT_QUOTA_MAX_AGE_SECS,
    );

    // Step 3: Decide if low-quota / unusable switch is warranted
    let should_try_switch = policy.enabled
        && (matches!(current_eval, QuotaEval::Unavailable { .. })
            || matches!(
                current_eval,
                QuotaEval::Known { remaining_percentage } if remaining_percentage <= policy.reserve_percentage as f64
            ));

    if should_try_switch {
        if let Some(candidate_id) = select_qualified_candidate_lazy(
            repo,
            transport,
            oauth_endpoints,
            quota_endpoints,
            registry,
            user_agent,
            &policy,
            &selected_id,
            None,
            clock.now_unix(),
        )
        .await?
        {
            ensure_no_conflicting_managed_session(runtime, &candidate_id)?;
            execute_switch(
                repo,
                backend,
                transport,
                oauth_endpoints,
                registry,
                user_agent,
                &candidate_id,
                &SwitchOptions {
                    dry_run: false,
                    allow_running: false,
                },
                clock.now_unix(),
            )
            .await?;
            return Ok(candidate_id);
        }
    }

    // Keep current selected account; ensure it is usable/scoped and active slot has the exact fresh serialized token payload!
    ensure_no_conflicting_managed_session(runtime, &selected_id)?;
    let fresh_snapshot = repo.read_snapshot()?;
    let fresh_selected = fresh_snapshot.selected_account().ok_or_else(|| {
        CliError::not_found(format!(
            "Selected account '{selected_id}' was removed before launching `agy`."
        ))
    })?;
    let sync_now = clock.now_unix();
    ensure_account_usable_and_scoped(repo, fresh_selected, registry, sync_now)?;
    let slot = backend.inspect_slot(paths);
    if !is_slot_synced_and_fresh(&slot, &fresh_snapshot, fresh_selected, sync_now) {
        execute_switch(
            repo,
            backend,
            transport,
            oauth_endpoints,
            registry,
            user_agent,
            &selected_id,
            &SwitchOptions {
                dry_run: false,
                allow_running: true,
            },
            clock.now_unix(),
        )
        .await?;
    }

    Ok(selected_id)
}

fn ensure_account_usable_and_scoped(
    repo: &StoreRepository,
    target: &AccountRecord,
    registry: &OAuthClientRegistry,
    now_unix: i64,
) -> CliResult<()> {
    let clock = AnchoredClock::new(now_unix);
    let ts = clock.now_unix();
    validate_target_usable(target, ts)?;
    let missing = registry.missing_required_scopes(&target.token);
    if !missing.is_empty() {
        let scope_err = CliError::auth(
            "scope_reauth_required",
            format!(
                "Account '{}' ({}) lacks required OAuth scope(s) ({}). Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize {}`.",
                target.id,
                target.email,
                missing.join(", "),
                target.id
            ),
        );
        return Err(persist_disable_or_report_io_error(
            repo,
            &target.id,
            DisableReasonCode::ScopeReauthRequired,
            format!(
                "Known granted_scopes missing required scope(s): {}",
                missing.join(", ")
            ),
            ts,
            scope_err,
        ));
    }
    Ok(())
}

/// Verify that `index.json` selects `target`, `target.token` is not near expiry, AND the active slot file
/// byte-for-byte matches `serialize_session_payload(&target.token)`.
/// Prevents spawning `agy` with a stale `access_token` when `refresh_token` remained unchanged across a refresh!
fn is_slot_synced_and_fresh(
    slot: &SlotInspectState,
    snapshot: &StoreSnapshot,
    target: &AccountRecord,
    now_unix: i64,
) -> bool {
    if snapshot.index.selected_account_id.as_deref() != Some(target.id.as_str()) {
        return false;
    }
    if target
        .token
        .is_expiring_within(now_unix, TOKEN_REFRESH_SKEW_SECONDS)
    {
        return false;
    }
    let Ok(expected_payload) = serialize_session_payload(&target.token) else {
        return false;
    };
    let expected_digest = bytes_sha256_hex(expected_payload.as_bytes());
    slot.raw_digest() == Some(expected_digest.as_str())
}

fn ensure_no_conflicting_managed_session(
    runtime: &RuntimeState,
    desired_account_id: &str,
) -> CliResult<()> {
    if let RuntimeState::ManagedRunning {
        account_ids, pids, ..
    } = runtime
    {
        if account_ids.iter().any(|id| id != desired_account_id) {
            return Err(CliError::env_not_ready(
                "parallel_managed_account_conflict",
                format!(
                    "Managed `agy` process(es) {:?} are currently running under different account(s) {:?}. Use isolated `HOME` directories for parallel multi-account execution.",
                    pids, account_ids
                ),
            ));
        }
    }
    Ok(())
}

/// Lazily evaluate/refresh candidate pool according to `policy.strategy` (`Priority` vs `RoundRobin`),
/// returning the first candidate strictly satisfying `Known(c) && c >= policy.candidate_min_percentage`.
#[allow(clippy::too_many_arguments)]
pub async fn select_qualified_candidate_lazy(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    quota_endpoints: &CloudCodeEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    policy: &SwitchPolicy,
    source_id: &str,
    last_rotated_cursor: Option<&str>,
    now_unix: i64,
) -> CliResult<Option<String>> {
    if policy.candidate_account_ids.is_empty() {
        return Ok(None);
    }
    let clock = AnchoredClock::new(now_unix);

    let ordered_candidates = ordered_candidate_ids(
        &policy.candidate_account_ids,
        source_id,
        policy.strategy,
        last_rotated_cursor,
    );

    for cand_id in ordered_candidates {
        let Ok(mut cand_acc) = repo.read_account_unchecked(&cand_id) else {
            continue;
        };
        let eval_ts = clock.now_unix();
        if !cand_acc.is_usable_at(eval_ts) {
            continue;
        }
        let mut eval = evaluate_account_quota(
            &cand_acc,
            &policy.monitored_model,
            eval_ts,
            DEFAULT_QUOTA_MAX_AGE_SECS,
        );
        if matches!(eval, QuotaEval::Unknown { .. } | QuotaEval::Stale { .. }) {
            if let Ok(refreshed) = refresh_account_quota_locked(
                repo,
                transport,
                oauth_endpoints,
                quota_endpoints,
                registry,
                user_agent,
                &cand_id,
                clock.now_unix(),
            )
            .await
            {
                cand_acc = refreshed;
                eval = evaluate_account_quota(
                    &cand_acc,
                    &policy.monitored_model,
                    clock.now_unix(),
                    DEFAULT_QUOTA_MAX_AGE_SECS,
                );
            }
        }
        if let QuotaEval::Known {
            remaining_percentage,
        } = eval
        {
            if remaining_percentage >= policy.candidate_min_percentage as f64 {
                return Ok(Some(cand_id));
            }
        }
    }

    Ok(None)
}

pub fn ordered_candidate_ids(
    candidates: &[String],
    source_id: &str,
    strategy: PolicyStrategy,
    last_rotated_cursor: Option<&str>,
) -> Vec<String> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let start_idx = match strategy {
        PolicyStrategy::Priority => 0,
        PolicyStrategy::RoundRobin => {
            let pivot = last_rotated_cursor.unwrap_or(source_id);
            candidates
                .iter()
                .position(|id| id == pivot)
                .map(|idx| (idx + 1) % candidates.len())
                .unwrap_or(0)
        }
    };

    let mut out = Vec::with_capacity(candidates.len());
    for offset in 0..candidates.len() {
        let id = &candidates[(start_idx + offset) % candidates.len()];
        if id != source_id && !out.contains(id) {
            out.push(id.clone());
        }
    }
    out
}
