use crate::domain::account::{DisableReasonCode, RuntimeState};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::error::{CliError, CliResult};
use crate::oauth::refresh::{ensure_account_token_fresh_locked, OAuthEndpoints};
use crate::oauth::registry::OAuthClientRegistry;
use crate::session::backend::{CredentialBackend, SlotInspectState};
use crate::session::journal::{
    clear_journal, diagnose_journal, read_journal_readonly, reconcile_journal_locked,
    write_journal, JournalDiagnosis, JournalPhase, SwitchJournal,
};
use crate::session::payload::{
    bytes_sha256_hex, parse_session_payload_bytes, serialize_session_payload,
};
use crate::session::process::{cleanup_stale_leases_under_write_lock, observe_runtime_state};
use crate::store::fs_atomic::check_fault_injection;
use crate::store::locks::ActiveSlotLock;
use crate::store::repository::StoreRepository;
use crate::transport::client::HttpTransport;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SwitchOptions {
    pub dry_run: bool,
    pub allow_running: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwitchOutcome {
    pub dry_run: bool,
    pub previous_selected_id: Option<String>,
    pub target_account_id: String,
    pub target_email: String,
    pub token_refreshed: bool,
    pub refresh_token_rotated: bool,
    pub runtime_warning: Option<String>,
}

/// Execute a single safe credential switch strictly following `L1 -> L2 -> L3` lock hierarchy
/// and the `switch_journal.json` commit-point protocol (Blueprint §3.1, §3.3).
#[allow(clippy::too_many_arguments)]
pub async fn execute_switch(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    selector: &str,
    options: &SwitchOptions,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    let paths = repo.paths();

    if options.dry_run {
        let slot_state = backend.inspect_slot(paths);
        let journal = read_journal_readonly(paths)?;
        let journal_diag = diagnose_journal(journal.as_ref(), &slot_state);
        if let JournalDiagnosis::RecoveryIncomplete { reason, .. } = journal_diag {
            return Err(CliError::partial_commit(
                "recovery_incomplete",
                format!(
                    "Previous switch recovery is incomplete ({reason}). Run `agy-switch-cli doctor --fix` to reconcile before further switching."
                ),
            ));
        }

        let snapshot = repo.read_snapshot()?;
        let target = snapshot.select(selector)?;
        validate_target_usable(target, now_unix)?;
        let missing_scopes = registry.missing_required_scopes(&target.token);
        if !missing_scopes.is_empty() {
            return Err(CliError::auth(
                "scope_reauth_required",
                format!(
                    "Account '{}' ({}) lacks required OAuth scope(s) ({}). Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize {}`.",
                    target.id,
                    target.email,
                    missing_scopes.join(", "),
                    target.id
                ),
            ));
        }

        if matches!(slot_state, SlotInspectState::Uninitialized) {
            return Err(CliError::env_not_ready(
                "agy_uninitialized",
                format!(
                    "No initialized agy CLI session directory found at '{}'.",
                    paths.active_slot_dir.display()
                ),
            ));
        }
        if let SlotInspectState::Corrupt(detail) = slot_state {
            return Err(CliError::data(format!(
                "Active credential slot is corrupt: {detail}"
            )));
        }

        let runtime = observe_runtime_state(paths);
        let runtime_warning = check_running_guard(&runtime, options.allow_running)?;
        let effective_prev = match journal_diag {
            JournalDiagnosis::CommittedIndexPending { target_account_id } => {
                Some(target_account_id)
            }
            _ => snapshot.index.selected_account_id.clone(),
        };

        return Ok(SwitchOutcome {
            dry_run: true,
            previous_selected_id: effective_prev,
            target_account_id: target.id.clone(),
            target_email: target.email.clone(),
            token_refreshed: false,
            refresh_token_rotated: false,
            runtime_warning,
        });
    }

    // 1. Acquire L1 ActiveSlotLock FIRST (`~/.cache/agy-switch-cli/locks/slot-<sha256>.lock`)
    let slot_lock = ActiveSlotLock::try_acquire(paths, backend.uses_keyring())?;

    execute_switch_with_slot_lock(
        &slot_lock,
        repo,
        backend,
        transport,
        oauth_endpoints,
        registry,
        user_agent,
        selector,
        options.allow_running,
        now_unix,
    )
    .await
}

/// Core switch execution when the caller ALREADY holds L1 `ActiveSlotLock` (used by `execute_switch` and `daemon` Stage 6).
#[allow(clippy::too_many_arguments)]
pub async fn execute_switch_with_slot_lock(
    slot_lock: &ActiveSlotLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    selector: &str,
    allow_running: bool,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    let paths = repo.paths();
    let clock = AnchoredClock::new(now_unix);

    // Auto-reconcile any leftover CommittedIndexPending / AbortedUncommitted journal;
    // block with exit code 7 if RecoveryIncomplete requires `doctor --fix`.
    reconcile_journal_locked(slot_lock, repo, backend, false, clock.now_unix())?;

    // Sweep stale dead leases under L3 before inspecting live processes
    repo.with_write_lock(|tx| {
        cleanup_stale_leases_under_write_lock(tx.paths());
        Ok(())
    })?;

    let runtime = observe_runtime_state(paths);
    let runtime_warning = check_running_guard(&runtime, allow_running)?;

    let snapshot = repo.read_snapshot()?;
    let target_initial = snapshot.select(selector)?.clone();
    validate_target_usable(&target_initial, clock.now_unix())?;

    // Check active slot directory is initialized and snapshot pre-switch bytes
    let prev_slot_bytes = backend.snapshot_before_write(paths)?;
    let prev_slot_digest = prev_slot_bytes.as_deref().map(bytes_sha256_hex);

    let mut journal = SwitchJournal::new_prepared(
        Uuid::new_v4().to_string(),
        snapshot.index.selected_account_id.clone(),
        target_initial.id.clone(),
        prev_slot_digest.clone(),
        clock.now_unix(),
    );

    repo.with_write_lock(|_| write_journal(paths, &journal))?;

    // 2. Ensure target token is fresh under L2 -> L3 (any rotated refresh_token is immediately saved to accounts/<id>.json!)
    let refresh_outcome = match ensure_account_token_fresh_locked(
        repo,
        transport,
        oauth_endpoints,
        registry,
        user_agent,
        &target_initial.id,
        false,
        clock.now_unix(),
    )
    .await
    {
        Ok(out) => out,
        Err(err) => {
            // Active slot was untouched; clear uncommitted journal while NEVER rolling back rotated refresh_token!
            let _ = repo.with_write_lock(|_| clear_journal(paths));
            return Err(err);
        }
    };

    if refresh_outcome.refreshed_over_network {
        journal.phase = JournalPhase::TokenRefreshed;
        journal.token_rotated = refresh_outcome.refresh_token_rotated;
        journal.updated_at = clock.now_unix();
        repo.with_write_lock(|_| write_journal(paths, &journal))?;
    }

    check_fault_injection("after_token_refreshed", &paths.active_slot_file)?;

    // Re-check CAS digest on active slot in case an external process (e.g. native `agy`) modified it during network await!
    let live_before_commit = backend.snapshot_before_write(paths)?;
    let live_digest = live_before_commit.as_deref().map(bytes_sha256_hex);
    if live_digest != prev_slot_digest {
        let _ = repo.with_write_lock(|_| clear_journal(paths));
        return Err(CliError::conflict(
            "external_slot_modified",
            "Active agy credential file was modified externally during switch preparation. Switch aborted without overwriting external changes.",
        ));
    }

    // Re-verify target account still exists and wasn't disabled concurrently
    let commit_now = clock.now_unix();
    let latest_target = repo.read_account_unchecked(&target_initial.id)?;
    validate_target_usable(&latest_target, commit_now)?;

    let payload = serialize_session_payload(&latest_target.token)?;
    let target_digest = bytes_sha256_hex(payload.as_bytes());

    journal.phase = JournalPhase::SlotCommitting;
    journal.target_slot_digest = Some(target_digest.clone());
    journal.updated_at = commit_now;
    repo.with_write_lock(|_| write_journal(paths, &journal))?;

    // 3. [UNIQUE EXTERNAL COMMIT POINT]: Atomically update active slot
    if let Err(write_err) = backend.write_slot(paths, &payload) {
        if write_err.exit_code == crate::error::ExitCode::PartialCommitOrRecovery {
            journal.phase = JournalPhase::RecoveryIncomplete;
            journal.note = Some(write_err.message.clone());
            journal.updated_at = clock.now_unix();
            let _ = repo.with_write_lock(|_| write_journal(paths, &journal));
            return Err(write_err);
        }
        // Conditional best-effort rollback of active slot ONLY (NEVER touch accounts/<id>.json!)
        let rollback_res = attempt_conditional_slot_rollback(
            backend,
            paths,
            prev_slot_bytes.as_deref(),
            prev_slot_digest.as_deref(),
            &target_digest,
        );
        match rollback_res {
            Ok(()) => {
                let _ = repo.with_write_lock(|_| clear_journal(paths));
                return Err(write_err);
            }
            Err(rb_err) => {
                journal.phase = JournalPhase::RecoveryIncomplete;
                journal.note = Some(format!(
                    "Slot write failed ({}) and conditional rollback failed ({}).",
                    write_err.message, rb_err.message
                ));
                journal.updated_at = clock.now_unix();
                let _ = repo.with_write_lock(|_| write_journal(paths, &journal));
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Active slot write failed ({}) and previous credential recovery was incomplete ({}). Run `agy-switch-cli doctor --fix` before retrying.",
                        write_err.message, rb_err.message
                    ),
                ));
            }
        }
    }

    // Active slot HAS BEEN COMMITTED! Any subsequent error MUST map to exit code 7 (`CommittedIndexPending`)!
    let post_commit_now = clock.now_unix();
    journal.phase = JournalPhase::CommittedSlot;
    journal.updated_at = post_commit_now;
    let _ = repo.with_write_lock(|_| write_journal(paths, &journal));

    // 4. Commit `selected_account_id` + `last_used` in `index.json` under L3 StoreWriteLock, and clear journal
    let index_commit = repo.with_write_lock(|tx| {
        check_fault_injection("after_slot_commit", &tx.paths().index_file())?;
        check_fault_injection("before_index_commit", &tx.paths().index_file())?;
        tx.commit_selected_account(&latest_target.id, post_commit_now)?;
        // Manual switch also clears any daemon failure pause state
        crate::switching::daemon::clear_daemon_pause_in_tx(tx.paths(), post_commit_now);
        clear_journal(tx.paths())
    });

    if let Err(idx_err) = index_commit {
        journal.phase = JournalPhase::CommittedIndexPending;
        journal.note = Some(idx_err.message.clone());
        journal.updated_at = clock.now_unix();
        let _ = repo.with_write_lock(|_| write_journal(paths, &journal));

        return Err(CliError::partial_commit(
            "committed_index_pending",
            format!(
                "生效位凭据已切换至目标账号，但本地索引更新未完成（{}）；请运行 doctor --fix 完成对账",
                idx_err.message
            ),
        )
        .with_details(serde_json::json!({
            "state": "committed_index_pending",
            "target_account_id": latest_target.id,
            "target_email": latest_target.email,
        })));
    }

    Ok(SwitchOutcome {
        dry_run: false,
        previous_selected_id: snapshot.index.selected_account_id,
        target_account_id: latest_target.id,
        target_email: latest_target.email,
        token_refreshed: refresh_outcome.refreshed_over_network,
        refresh_token_rotated: refresh_outcome.refresh_token_rotated,
        runtime_warning,
    })
}

pub(crate) fn validate_target_usable(
    target: &crate::domain::account::AccountRecord,
    now_unix: i64,
) -> CliResult<()> {
    if target.disabled {
        return match target.disabled_code {
            Some(DisableReasonCode::ScopeReauthRequired) => Err(CliError::auth(
                "scope_reauth_required",
                format!(
                    "Account '{}' ({}) lacks required OAuth scopes (token refresh cannot upgrade scopes). Run `agy-switch-cli auth reauthorize {}`.",
                    target.id, target.email, target.id
                ),
            )),
            Some(DisableReasonCode::RevokedOrExpiredGrant) => Err(CliError::auth(
                "account_reauth_required",
                format!(
                    "Account '{}' ({}) requires reauthorization. Run `agy-switch-cli auth reauthorize {}`.",
                    target.id, target.email, target.id
                ),
            )),
            _ => Err(CliError::usage(format!(
                "Account '{}' ({}) is disabled. Enable it with `agy-switch-cli accounts enable {}` first.",
                target.id, target.email, target.id
            ))),
        };
    }
    if target.is_validation_blocked_at(now_unix) {
        return Err(CliError::auth(
            "account_validation_blocked",
            format!(
                "Account '{}' ({}) is blocked pending Google account verification.",
                target.id, target.email
            ),
        ));
    }
    Ok(())
}

fn check_running_guard(runtime: &RuntimeState, allow_running: bool) -> CliResult<Option<String>> {
    match runtime {
        RuntimeState::Idle => Ok(None),
        RuntimeState::ManagedRunning { pids, .. } | RuntimeState::UnmanagedRunning { pids, .. } => {
            if allow_running {
                Ok(Some(format!(
                    "Warning: active `agy` process(es) {:?} detected; running processes keep their startup login and only new `agy` invocations will use the switched account.",
                    pids
                )))
            } else {
                Err(CliError::env_not_ready(
                    "active_agy_running",
                    format!(
                        "Detected running `agy` process(es) {:?}. Running `agy` sessions keep their startup login and may conflict with credential updates; wait for them to exit or pass `--allow-running`.",
                        pids
                    ),
                ))
            }
        }
        RuntimeState::Unverified { detail } => {
            if allow_running {
                Ok(Some(format!(
                    "Warning: process state unverified ({detail})."
                )))
            } else {
                Err(CliError::env_not_ready(
                    "runtime_state_unverified",
                    format!("Cannot verify whether `agy` is currently running ({detail}). Pass `--allow-running` to override."),
                ))
            }
        }
    }
}

fn attempt_conditional_slot_rollback(
    backend: &dyn CredentialBackend,
    paths: &crate::paths::HeadlessPaths,
    prev_bytes: Option<&[u8]>,
    prev_digest: Option<&str>,
    target_digest: &str,
) -> CliResult<()> {
    check_fault_injection("slot_rollback", &paths.active_slot_file)?;

    // Inspect current file on disk: if an external process wrote a brand-new valid payload
    // matching neither prev_digest nor target_digest, do NOT clobber the external credential!
    if let Ok(Some(cur_bytes)) = backend.snapshot_before_write(paths) {
        let cur_digest = bytes_sha256_hex(&cur_bytes);
        if Some(cur_digest.as_str()) == prev_digest {
            return Ok(());
        }
        if cur_digest != target_digest && parse_session_payload_bytes(&cur_bytes).is_ok() {
            // Valid external session appeared concurrently — leave it intact rather than overwriting with stale snapshot
            return Ok(());
        }
    }

    match prev_bytes {
        Some(old) => {
            let old_str = std::str::from_utf8(old).map_err(|_| {
                CliError::data("Previous slot snapshot was not UTF-8 during rollback.")
            })?;
            backend.write_slot(paths, old_str)
        }
        None => backend.remove_slot(paths),
    }
}
