use crate::cli::dto::terminal_text;
use crate::domain::account::{AccountRecord, DisableReasonCode, RuntimeState};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::domain::policy::PolicyStrategy;
use crate::error::{CliError, CliResult};
use crate::oauth::refresh::{
    persist_disable_or_report_io_error, OAuthEndpoints, TOKEN_REFRESH_SKEW_SECONDS,
};
use crate::oauth::registry::OAuthClientRegistry;
use crate::session::backend::{
    should_isolate_child_dbus_for_explicit_file_backend, BackendReplicaInspection,
    CredentialBackend,
};
use crate::session::journal::reconcile_pending_journal_for_slot_consumer;
use crate::session::payload::{bytes_sha256_hex, serialize_session_payload};
use crate::session::process::{observe_runtime_state, remove_process_lease, write_process_lease};
use crate::store::repository::{StoreRepository, StoreSnapshot};
use crate::switching::executor::{execute_switch, validate_target_usable, SwitchOptions};
use crate::transport::client::HttpTransport;
use crate::transport::user_agent::resolve_agy_executable;
use std::path::PathBuf;
use std::process::Stdio;

/// Optional managed credential/backend wrapper (`agy-switch-cli [--backend file] run [--account <SEL>] -- agy [<ARGS>...]`).
#[allow(clippy::too_many_arguments)]
pub async fn run_managed_agy(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    explicit_account: Option<&str>,
    explicit_file_backend: bool,
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

    let (active_account_id, target_validation_blocked) = prepare_account_before_spawn(
        repo,
        backend,
        transport,
        oauth_endpoints,
        registry,
        user_agent,
        explicit_account,
        &runtime,
        &clock,
    )
    .await?;

    if target_validation_blocked {
        let safe_id = terminal_text(&active_account_id);
        eprintln!(
            "Note: account `{safe_id}` is currently marked verification-required (`verify-blocked`) and remains excluded from daemon auto-switching. Complete Google verification in `agy`, then run `agy-switch-cli refresh {safe_id}` to clear this status."
        );
    }

    // 4. Spawn child `agy`, register two-factor lease (`pid` + `/proc/<pid>/stat` field 22 `starttime`),
    // forward signals, and return exact child exit code!
    let mut cmd = tokio::process::Command::new(&resolved_bin);
    cmd.args(&command_args[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if explicit_file_backend && should_isolate_child_dbus_for_explicit_file_backend() {
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
    registry: &OAuthClientRegistry,
    user_agent: &str,
    explicit_account: Option<&str>,
    runtime: &RuntimeState,
    clock: &dyn Clock,
) -> CliResult<(String, bool)> {
    let paths = repo.paths();
    let snapshot = repo.read_snapshot()?;

    let target = match explicit_account {
        Some(sel) => snapshot.select(sel)?,
        None => snapshot.selected_account().ok_or_else(|| {
            CliError::not_found(
                "No selected account in store. Import/login and `switch` to an account first, or pass `--account <ID|EMAIL>`.",
            )
        })?,
    };
    let target_id = target.id.clone();
    let ts = clock.now_unix();
    ensure_account_usable_and_scoped(repo, target, registry, ts)?;
    ensure_no_conflicting_managed_session(runtime, &target_id)?;

    let replicas = backend.inspect_replicas(paths);
    let validation_blocked = if !is_slot_synced_and_fresh(&replicas, &snapshot, target, ts) {
        let outcome = execute_switch(
            repo,
            backend,
            transport,
            oauth_endpoints,
            registry,
            user_agent,
            &target_id,
            &SwitchOptions {
                dry_run: false,
                allow_running: true, // Same-account managed session (and verified `/proc`) was already confirmed above
            },
            clock.now_unix(),
        )
        .await?;
        outcome.validation_blocked
    } else {
        target.is_validation_blocked_at(ts)
    };

    Ok((target_id, validation_blocked))
}

fn ensure_account_usable_and_scoped(
    repo: &StoreRepository,
    target: &AccountRecord,
    registry: &OAuthClientRegistry,
    now_unix: i64,
) -> CliResult<()> {
    let clock = AnchoredClock::new(now_unix);
    let ts = clock.now_unix();
    validate_target_usable(target, ts, true)?;
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

/// Verify that `index.json` selects `target`, `target.token` is not near expiry, AND ALL replicas
/// managed by the active backend (`file`, `keyring`, or `dual`) match `serialize_session_payload(&target.token)`.
/// Prevents spawning `agy` with a stale `access_token` or diverged replica!
fn is_slot_synced_and_fresh(
    replicas: &BackendReplicaInspection,
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
    let file_ok =
        !replicas.uses_file || replicas.file.raw_digest() == Some(expected_digest.as_str());
    let kr_ok = !replicas.uses_keyring
        || (replicas.keyring_all_collections_uniform
            && replicas.keyring.as_ref().and_then(|k| k.raw_digest())
                == Some(expected_digest.as_str()));
    file_ok && kr_ok
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
