use crate::domain::account::{AccountRecord, DisableReasonCode, RuntimeState};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::error::{CliError, CliResult, ExitCode};
use crate::oauth::refresh::{ensure_account_token_fresh_locked, OAuthEndpoints};
use crate::oauth::registry::OAuthClientRegistry;
use crate::session::backend::{CredentialBackend, ReplicaCasExpectation, SlotInspectState};
use crate::session::journal::{
    clear_journal, diagnose_journal_replicas, diagnose_journal_replicas_with_intent,
    journal_on_disk_may_need_keyring, keyring_collection_ids_match, read_journal_full_readonly,
    reconcile_journal_locked, reconcile_pending_journal_before_write,
    replicas_all_absent_with_exact_collections,
    selected_replicas_match_digest_with_exact_collections,
    write_clear_slot_journal_with_replicas_and_meta, write_journal_with_replicas,
    ClearSlotTargetMeta, JournalDiagnosis, JournalPhase, JournalReplicaRecord, SwitchJournal,
};
use crate::session::payload::{bytes_sha256_hex, serialize_session_payload};
use crate::session::process::observe_runtime_state;
use crate::store::fs_atomic::{check_fault_injection, cleanup_owned_orphan_temp_files_pinned};
use crate::store::locks::ActiveSlotLock;
use crate::store::repository::StoreRepository;
use crate::transport::client::HttpTransport;
use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SwitchOptions {
    pub dry_run: bool,
    pub allow_running: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunningGuardMode {
    RequireIdle,
    AllowVerifiedRunning,
    ForceAllowRunningAndUnverified,
}

impl RunningGuardMode {
    fn from_flags(allow_running: bool, require_idle: bool) -> Self {
        if allow_running {
            Self::ForceAllowRunningAndUnverified
        } else if require_idle {
            Self::RequireIdle
        } else {
            Self::AllowVerifiedRunning
        }
    }
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
/// and the multi-replica `switch_journal.json` commit-point protocol (Blueprint §3.1, §3.3).
/// By default (`allow_running == false` and `require_idle == false`), switches immediately even if
/// verified `agy` sessions are running (emitting a non-fatal `runtime_warning` that running sessions
/// keep their startup login), while failing closed on `RuntimeState::Unverified`.
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
    execute_switch_with_idle_policy(
        repo,
        backend,
        transport,
        oauth_endpoints,
        registry,
        user_agent,
        selector,
        options,
        false,
        now_unix,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_switch_with_idle_policy(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    selector: &str,
    options: &SwitchOptions,
    require_idle: bool,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    let paths = repo.paths();
    let guard_mode = RunningGuardMode::from_flags(options.allow_running, require_idle);

    if options.dry_run {
        let replica_state = backend.inspect_replicas(paths);
        let slot_state = replica_state.effective_slot_state();
        let journal_full = read_journal_full_readonly(paths)?;
        let clear_intent = journal_full.as_ref().is_some_and(|(_, _, c)| *c);
        let journal_diag = diagnose_journal_replicas_with_intent(
            journal_full.as_ref().map(|(j, _, _)| j),
            journal_full.as_ref().and_then(|(_, m, _)| m.as_ref()),
            clear_intent,
            &replica_state,
        );
        if let JournalDiagnosis::RecoveryIncomplete { reason, .. } = journal_diag {
            return Err(CliError::partial_commit(
                "recovery_incomplete",
                format!(
                    "Previous switch recovery is incomplete ({reason}). Run `agy-switch-cli switch <ID|EMAIL>` to reconcile before further switching."
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

        if replica_state.uses_file && matches!(replica_state.file, SlotInspectState::Uninitialized)
        {
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
        if replica_state.uses_file {
            if let SlotInspectState::Corrupt(ref detail) = replica_state.file {
                return Err(CliError::data(format!(
                    "Active credential file replica is corrupt: {detail}"
                )));
            }
        }
        if replica_state.uses_keyring {
            if let Some(SlotInspectState::Unverified(ref detail)) = replica_state.keyring {
                return Err(CliError::env_not_ready(
                    "secret_service_unavailable",
                    detail.clone(),
                ));
            }
        }

        let runtime = observe_runtime_state(paths);
        let runtime_warning = check_running_guard(&runtime, guard_mode)?;
        let effective_prev = match journal_diag {
            JournalDiagnosis::CommittedIndexPending { target_account_id } => {
                if clear_intent {
                    snapshot
                        .index
                        .selected_account_id
                        .as_ref()
                        .filter(|s| *s != &target_account_id)
                        .cloned()
                } else {
                    Some(target_account_id)
                }
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
    let existing_needs_kr = journal_on_disk_may_need_keyring(paths);
    let mut slot_lock =
        ActiveSlotLock::try_acquire(paths, backend.uses_keyring() || existing_needs_kr)?;
    if !slot_lock.includes_keyring_scope() && journal_on_disk_may_need_keyring(paths) {
        drop(slot_lock);
        slot_lock = ActiveSlotLock::try_acquire(paths, true)?;
    }

    execute_switch_with_slot_lock_and_guard(
        &slot_lock,
        repo,
        backend,
        transport,
        oauth_endpoints,
        registry,
        user_agent,
        selector,
        guard_mode,
        true,
        now_unix,
    )
    .await
}

/// Core switch execution when the caller ALREADY holds L1 `ActiveSlotLock`.
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
    execute_switch_with_slot_lock_and_guard(
        slot_lock,
        repo,
        backend,
        transport,
        oauth_endpoints,
        registry,
        user_agent,
        selector,
        RunningGuardMode::from_flags(allow_running, false),
        false,
        now_unix,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_switch_with_slot_lock_and_guard(
    slot_lock: &ActiveSlotLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    selector: &str,
    guard_mode: RunningGuardMode,
    allow_repair_incomplete: bool,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    let paths = repo.paths();
    let clock = AnchoredClock::new(now_unix);

    // Reconcile any leftover journal (manual switch also repairs safe cross-replica RecoveryIncomplete;
    // daemon passes `allow_repair_incomplete = false` so incomplete recovery pauses the daemon).
    reconcile_journal_locked(
        slot_lock,
        repo,
        backend,
        allow_repair_incomplete,
        clock.now_unix(),
    )?;

    // Acquire L3 before inspecting live processes so repository entry init and its single stale-lease sweep complete first.
    repo.with_write_lock(|_| Ok(()))?;

    let runtime = observe_runtime_state(paths);
    let runtime_warning = check_running_guard(&runtime, guard_mode)?;

    let snapshot = repo.read_snapshot()?;
    let target_initial = snapshot.select(selector)?.clone();
    validate_target_usable(&target_initial, clock.now_unix())?;

    // Check active slot directory is initialized and snapshot ALL replicas before write
    let pre_snap = backend.snapshot_replicas_before_write(paths)?;
    let prev_slot_digest = pre_snap.effective_slot_digest();
    let replica_record = JournalReplicaRecord::from_pre_write_snapshot(&pre_snap);

    let mut journal = SwitchJournal::new_prepared(
        Uuid::new_v4().to_string(),
        snapshot.index.selected_account_id.clone(),
        target_initial.id.clone(),
        prev_slot_digest,
        clock.now_unix(),
    );

    repo.with_write_lock(|_| write_journal_with_replicas(paths, &journal, Some(&replica_record)))?;

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
            // Active slot was untouched; verify replicas still match pre-switch before clearing uncommitted journal!
            let live_rep = backend.inspect_replicas(paths);
            if matches!(
                diagnose_journal_replicas(Some(&journal), Some(&replica_record), &live_rep),
                JournalDiagnosis::AbortedUncommitted { .. }
            ) {
                let _ = repo.with_write_lock(|_| clear_journal(paths));
            }
            return Err(err);
        }
    };

    if refresh_outcome.refreshed_over_network {
        journal.phase = JournalPhase::TokenRefreshed;
        journal.token_rotated = refresh_outcome.refresh_token_rotated;
        journal.updated_at = clock.now_unix();
        repo.with_write_lock(|_| {
            write_journal_with_replicas(paths, &journal, Some(&replica_record))
        })?;
    }

    check_fault_injection("after_token_refreshed", &paths.active_slot_file)?;

    // Re-check CAS digest on ALL active replicas in case an external process modified keyring or disk during network await!
    let live_before_commit = backend.snapshot_replicas_before_write(paths)?;
    let file_cas_ok =
        !pre_snap.uses_file || live_before_commit.file_digest() == pre_snap.file_digest();
    let kr_cas_ok = !pre_snap.uses_keyring
        || (live_before_commit.keyring_digest() == pre_snap.keyring_digest()
            && live_before_commit.keyring_uniform == pre_snap.keyring_uniform
            && live_before_commit.keyring_collection_digests()
                == pre_snap.keyring_collection_digests());
    let cas_intact = file_cas_ok && kr_cas_ok;
    if !cas_intact {
        let live_kr_ids_ok = !live_before_commit.uses_keyring
            || keyring_collection_ids_match(
                &live_before_commit.keyring_collection_digests(),
                Some(&replica_record),
            );
        let same_external_across_all = live_kr_ids_ok
            && match (
                live_before_commit.uses_file,
                live_before_commit.uses_keyring,
            ) {
                (true, false) => true,
                (false, true) => {
                    live_before_commit.keyring_uniform
                        && live_before_commit.keyring_digest().is_some()
                }
                (true, true) => {
                    live_before_commit.keyring_uniform
                        && live_before_commit.keyring_digest().is_some()
                        && live_before_commit.keyring_digest() == live_before_commit.file_digest()
                }
                (false, false) => false,
            };
        if same_external_across_all {
            let _ = repo.with_write_lock(|_| clear_journal(paths));
            return Err(CliError::conflict(
                "external_slot_modified",
                "Active agy credential slot was modified externally during switch preparation. Switch aborted without overwriting external changes.",
            ));
        }
        journal.phase = JournalPhase::RecoveryIncomplete;
        journal.note = Some(
            "External modification caused credential replicas to diverge before commit.".into(),
        );
        journal.updated_at = clock.now_unix();
        let _ = repo.with_write_lock(|_| {
            write_journal_with_replicas(paths, &journal, Some(&replica_record))
        });
        return Err(CliError::partial_commit(
            "recovery_incomplete",
            "Active agy credential replicas diverged externally during switch preparation. Retry `agy-switch-cli switch` to reconcile.",
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
    repo.with_write_lock(|_| write_journal_with_replicas(paths, &journal, Some(&replica_record)))?;

    // 3. [UNIQUE EXTERNAL COMMIT POINT]: Atomically update active slot(s) with CAS bound to `pre_snap`
    let pre_cas = ReplicaCasExpectation::from_pre_write_snapshot(&pre_snap);
    if let Err(write_err) = backend.write_slot_cas(paths, &payload, &pre_cas) {
        if write_err.exit_code == crate::error::ExitCode::PartialCommitOrRecovery {
            journal.phase = JournalPhase::RecoveryIncomplete;
            journal.note = Some(write_err.message.clone());
            journal.updated_at = clock.now_unix();
            let _ = repo.with_write_lock(|_| {
                write_journal_with_replicas(paths, &journal, Some(&replica_record))
            });
            return Err(write_err);
        }
        // Conditional best-effort rollback across ALL replicas (NEVER touching accounts/<id>.json!)
        let rollback_res = backend.rollback_replicas(paths, &pre_snap, &target_digest);
        match rollback_res {
            Ok(()) => {
                // Verify ALL replicas + exact collection IDs are genuinely consistent before clearing journal!
                let post_rb = backend.inspect_replicas(paths);
                let post_rb_kr_ids_ok = !post_rb.uses_keyring
                    || keyring_collection_ids_match(
                        &post_rb.keyring_collections,
                        Some(&replica_record),
                    );
                let restored_clean = matches!(
                    diagnose_journal_replicas(Some(&journal), Some(&replica_record), &post_rb),
                    JournalDiagnosis::AbortedUncommitted { .. }
                ) || (post_rb_kr_ids_ok
                    && match (post_rb.uses_file, post_rb.uses_keyring) {
                        (true, false) => {
                            post_rb.file.raw_digest().is_some()
                                && post_rb.file.raw_digest() != Some(target_digest.as_str())
                        }
                        (false, true) => {
                            let kd = post_rb.keyring.as_ref().and_then(|k| k.raw_digest());
                            post_rb.keyring_all_collections_uniform
                                && kd.is_some()
                                && kd != Some(target_digest.as_str())
                        }
                        (true, true) => {
                            post_rb.file.raw_digest().is_some()
                                && post_rb.file.raw_digest() != Some(target_digest.as_str())
                                && post_rb.keyring_all_collections_uniform
                                && post_rb.keyring.as_ref().and_then(|k| k.raw_digest())
                                    == post_rb.file.raw_digest()
                        }
                        (false, false) => false,
                    });
                if restored_clean {
                    let _ = repo.with_write_lock(|_| clear_journal(paths));
                    return Err(write_err);
                }
                journal.phase = JournalPhase::RecoveryIncomplete;
                journal.note = Some(format!(
                    "Slot write failed ({}) and post-rollback replica verification detected divergence.",
                    write_err.message
                ));
                journal.updated_at = clock.now_unix();
                let _ = repo.with_write_lock(|_| {
                    write_journal_with_replicas(paths, &journal, Some(&replica_record))
                });
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Active slot write failed ({}) and credential replicas could not be verified clean after rollback.",
                        write_err.message
                    ),
                ));
            }
            Err(rb_err) => {
                journal.phase = JournalPhase::RecoveryIncomplete;
                journal.note = Some(format!(
                    "Slot write failed ({}) and conditional rollback failed ({}).",
                    write_err.message, rb_err.message
                ));
                journal.updated_at = clock.now_unix();
                let _ = repo.with_write_lock(|_| {
                    write_journal_with_replicas(paths, &journal, Some(&replica_record))
                });
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Active slot write failed ({}) and previous credential recovery was incomplete ({}).",
                        write_err.message, rb_err.message
                    ),
                ));
            }
        }
    }

    let temp_cleanup_err = if allow_repair_incomplete && backend.uses_file() {
        cleanup_owned_orphan_temp_files_pinned(
            &paths.active_slot_dir,
            Some("antigravity-oauth-token"),
            Duration::from_secs(60),
        )
        .err()
    } else {
        None
    };

    // Verify ALL required replicas AND exact collection IDs hold `target_digest` before advancing to `CommittedSlot` / clearing journal!
    let post_write_replicas = backend.inspect_replicas(paths);
    let all_committed = selected_replicas_match_digest_with_exact_collections(
        &post_write_replicas,
        &target_digest,
        Some(&replica_record),
        post_write_replicas.uses_file,
        post_write_replicas.uses_keyring,
    );
    if !all_committed {
        journal.phase = JournalPhase::RecoveryIncomplete;
        journal.note = Some("Post-commit verification failed across credential replicas.".into());
        journal.updated_at = clock.now_unix();
        let _ = repo.with_write_lock(|_| {
            write_journal_with_replicas(paths, &journal, Some(&replica_record))
        });
        return Err(CliError::partial_commit(
            "recovery_incomplete",
            "Credential write completed partially across replicas; switch journal preserved.",
        ));
    }

    // Active slot HAS BEEN COMMITTED across all replicas! Any subsequent error MUST map to exit code 7 (`CommittedIndexPending`)!
    let post_commit_now = clock.now_unix();
    journal.phase = JournalPhase::CommittedSlot;
    journal.updated_at = post_commit_now;
    let _ = repo
        .with_write_lock(|_| write_journal_with_replicas(paths, &journal, Some(&replica_record)));

    // 4. Commit `selected_account_id` + `last_used` in `index.json` under L3 StoreWriteLock, and clear journal
    let mut daemon_pause_clear_err: Option<CliError> = None;
    let index_commit = repo.with_write_lock(|tx| {
        check_fault_injection("after_slot_commit", &tx.paths().index_file())?;
        check_fault_injection("before_index_commit", &tx.paths().index_file())?;
        tx.commit_selected_account(&latest_target.id, post_commit_now)?;
        clear_journal(tx.paths())?;
        let pause_res = if allow_repair_incomplete {
            crate::switching::daemon::repair_or_clear_daemon_state_in_tx(
                tx.paths(),
                post_commit_now,
            )
            .map(|_| ())
        } else {
            crate::switching::daemon::clear_daemon_pause_in_tx(tx.paths(), post_commit_now)
        };
        if let Err(err) = pause_res {
            daemon_pause_clear_err = Some(err);
        }
        Ok(())
    });

    if let Err(idx_err) = index_commit {
        journal.phase = JournalPhase::CommittedIndexPending;
        journal.note = Some(idx_err.message.clone());
        journal.updated_at = clock.now_unix();
        let _ = repo.with_write_lock(|_| {
            write_journal_with_replicas(paths, &journal, Some(&replica_record))
        });

        return Err(CliError::partial_commit(
            "committed_index_pending",
            format!(
                "生效位凭据已切换至目标账号，但本地索引更新未完成（{}）；下次执行切号或写入操作时将自动完成对账",
                idx_err.message
            ),
        )
        .with_details(serde_json::json!({
            "state": "committed_index_pending",
            "target_account_id": latest_target.id,
            "target_email": latest_target.email,
        })));
    }

    if let Some(pause_err) = daemon_pause_clear_err {
        return Err(CliError::partial_commit(
            "daemon_pause_clear_failed",
            format!(
                "Active credential slot and index switched to '{}', but clearing daemon failure pause in `daemon_state.json` failed ({}). Daemon remains paused.",
                latest_target.id, pause_err.message
            ),
        )
        .with_details(serde_json::json!({
            "state": "daemon_pause_clear_failed",
            "target_account_id": latest_target.id,
            "target_email": latest_target.email,
        })));
    }

    if let Some(clean_err) = temp_cleanup_err {
        return Err(CliError::partial_commit(
            "slot_temp_cleanup_failed",
            format!(
                "Active credential slot and index switched to '{}', but durably cleaning expired temporary slot files failed ({}).",
                latest_target.id, clean_err.message
            ),
        )
        .with_details(serde_json::json!({
            "state": "slot_temp_cleanup_failed",
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

fn check_running_guard(
    runtime: &RuntimeState,
    guard_mode: RunningGuardMode,
) -> CliResult<Option<String>> {
    match runtime {
        RuntimeState::Idle => Ok(None),
        RuntimeState::ManagedRunning { pids, .. } | RuntimeState::UnmanagedRunning { pids, .. } => {
            if matches!(
                guard_mode,
                RunningGuardMode::AllowVerifiedRunning
                    | RunningGuardMode::ForceAllowRunningAndUnverified
            ) {
                Ok(Some(format!(
                    "Note: active `agy` process(es) {:?} detected; running `agy` sessions keep their startup login and newly opened `agy` sessions will use the switched account.",
                    pids
                )))
            } else {
                Err(CliError::env_not_ready(
                    "active_agy_running",
                    format!(
                        "Detected running `agy` process(es) {:?} while `--require-idle` is active. Wait for them to exit or omit `--require-idle` to switch credentials for newly opened `agy` sessions.",
                        pids
                    ),
                ))
            }
        }
        RuntimeState::Unverified { detail } => {
            if guard_mode == RunningGuardMode::ForceAllowRunningAndUnverified {
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

/// Shared transactional account deletion service used by both `agy-switch-cli accounts delete`
/// and interactive TUI (`x` / `Delete` -> `y`).
/// When `clear_active_slot` is true, acquires `L1`, reconciles any pending journal, records a durable
/// `clear_slot_intent` journal, transactionally clears matching credentials across all replicas, and
/// removes the account from `policy.json`, `index.json`, `accounts/<id>.json`, and `token_lineage`.
pub fn execute_account_delete(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    selector: &str,
    force: bool,
    clear_active_slot: bool,
    now_unix: i64,
) -> CliResult<(AccountRecord, bool)> {
    let paths = repo.paths();
    if clear_active_slot {
        let existing_needs_kr = journal_on_disk_may_need_keyring(paths);
        let mut slot_lock =
            ActiveSlotLock::try_acquire(paths, backend.uses_keyring() || existing_needs_kr)?;
        if !slot_lock.includes_keyring_scope() && journal_on_disk_may_need_keyring(paths) {
            drop(slot_lock);
            slot_lock = ActiveSlotLock::try_acquire(paths, true)?;
        }
        reconcile_journal_locked(&slot_lock, repo, backend, true, now_unix)?;
        let snap = repo.read_snapshot()?;
        let t = snap.select(selector)?.clone();
        if snap.index.selected_account_id.as_deref() == Some(t.id.as_str()) && !force {
            return Err(CliError::usage(format!(
                "Account '{}' is currently selected. Switch to another account first, or pass `--force` (and `--clear-active-slot` to also remove the active credential file).",
                t.id
            )));
        }

        let replicas = backend.inspect_replicas(paths);
        if replicas.uses_file {
            if let SlotInspectState::Unverified(detail) = &replicas.file {
                return Err(CliError::env_not_ready("slot_unverified", detail.clone()));
            }
        }
        if replicas.uses_keyring {
            match &replicas.keyring {
                None => {
                    return Err(CliError::env_not_ready(
                        "secret_service_unavailable",
                        "Linux Secret Service keyring replica could not be verified.",
                    ));
                }
                Some(SlotInspectState::Unverified(detail)) => {
                    return Err(CliError::env_not_ready(
                        "secret_service_unavailable",
                        detail.clone(),
                    ));
                }
                _ => {}
            }
        }

        let t_fp = t.token.refresh_token_fingerprint();
        let file_has_t = replicas.uses_file
            && matches!(&replicas.file, SlotInspectState::Present(pf) if pf.refresh_token_digest == t_fp);
        let file_has_other = replicas.uses_file
            && matches!(&replicas.file, SlotInspectState::Present(pf) if pf.refresh_token_digest != t_fp);
        let kr_has_t = replicas.uses_keyring
            && replicas
                .keyring_collections
                .iter()
                .any(|c| c.valid_refresh_token_digest.as_deref() == Some(t_fp.as_str()));
        let kr_has_other = replicas.uses_keyring
            && replicas.keyring_collections.iter().any(|c| {
                c.present && c.valid_refresh_token_digest.as_deref() != Some(t_fp.as_str())
            });

        if (file_has_t || kr_has_t) && (file_has_other || kr_has_other) {
            return Err(CliError::partial_commit(
                "conflicting_slot_replicas",
                "Active credential replicas hold conflicting credentials across collections or disk; run `agy-switch-cli switch` to synchronize replicas before `--clear-active-slot`.",
            ));
        }

        let pre_snap_opt = if file_has_t || kr_has_t {
            let pre_snap = backend.snapshot_replicas_before_write(paths)?;
            let snap_file_rt = pre_snap
                .uses_file
                .then_some(pre_snap.file_bytes.as_deref())
                .flatten()
                .and_then(|b| {
                    crate::session::payload::parse_session_payload_bytes(b)
                        .ok()
                        .map(|p| p.refresh_token_digest)
                });
            let snap_file_present = pre_snap.uses_file && pre_snap.file_bytes.is_some();
            let snap_file_has_t = snap_file_rt.as_deref() == Some(t_fp.as_str());
            let snap_file_has_other = snap_file_present && !snap_file_has_t;
            let snap_kr_cols = pre_snap.keyring_collection_digests();
            let snap_kr_has_t = pre_snap.uses_keyring
                && snap_kr_cols
                    .iter()
                    .any(|c| c.valid_refresh_token_digest.as_deref() == Some(t_fp.as_str()));
            let snap_kr_has_other = pre_snap.uses_keyring
                && snap_kr_cols.iter().any(|c| {
                    c.present && c.valid_refresh_token_digest.as_deref() != Some(t_fp.as_str())
                });
            if (snap_file_has_t || snap_kr_has_t) && (snap_file_has_other || snap_kr_has_other) {
                return Err(CliError::partial_commit(
                    "conflicting_slot_replicas",
                    "Active credential replicas changed concurrently and hold conflicting credentials.",
                ));
            }
            (snap_file_has_t || snap_kr_has_t).then_some(pre_snap)
        } else {
            None
        };

        let mut cleared_slot = false;
        if let Some(pre_snap) = pre_snap_opt {
            let replica_record = JournalReplicaRecord::from_pre_write_snapshot(&pre_snap);
            let clear_target_meta = ClearSlotTargetMeta {
                auth_generation: Some(t.auth_generation),
                refresh_token_digest: Some(t_fp.clone()),
            };
            let mut journal = SwitchJournal::new_prepared(
                Uuid::new_v4().to_string(),
                snap.index.selected_account_id.clone(),
                t.id.clone(),
                pre_snap.effective_slot_digest(),
                now_unix,
            );
            journal.phase = JournalPhase::SlotCommitting;

            repo.with_write_lock(|_| {
                write_clear_slot_journal_with_replicas_and_meta(
                    paths,
                    &journal,
                    &replica_record,
                    &clear_target_meta,
                )
            })?;

            if let Err(rm_err) = backend.remove_slot_transactional(paths, &pre_snap) {
                if rm_err.exit_code == ExitCode::PartialCommitOrRecovery {
                    journal.phase = JournalPhase::RecoveryIncomplete;
                    journal.note = Some(rm_err.message.clone());
                    let _ = repo.with_write_lock(|_| {
                        write_clear_slot_journal_with_replicas_and_meta(
                            paths,
                            &journal,
                            &replica_record,
                            &clear_target_meta,
                        )
                    });
                    return Err(rm_err);
                }
                let post_rb = backend.inspect_replicas(paths);
                if matches!(
                    diagnose_journal_replicas_with_intent(
                        Some(&journal),
                        Some(&replica_record),
                        true,
                        &post_rb
                    ),
                    JournalDiagnosis::AbortedUncommitted { .. }
                ) {
                    let _ = repo.with_write_lock(|_| clear_journal(paths));
                    return Err(rm_err);
                }
                journal.phase = JournalPhase::RecoveryIncomplete;
                journal.note = Some(rm_err.message.clone());
                let _ = repo.with_write_lock(|_| {
                    write_clear_slot_journal_with_replicas_and_meta(
                        paths,
                        &journal,
                        &replica_record,
                        &clear_target_meta,
                    )
                });
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Active slot clear failed ({}) and replicas could not be verified restored.",
                        rm_err.message
                    ),
                ));
            }

            let post_rm = backend.inspect_replicas(paths);
            if !replicas_all_absent_with_exact_collections(
                &post_rm,
                Some(&replica_record),
                post_rm.uses_file,
                post_rm.uses_keyring,
            ) {
                journal.phase = JournalPhase::RecoveryIncomplete;
                journal.note =
                    Some("Post-clear verification failed across credential replicas.".into());
                let _ = repo.with_write_lock(|_| {
                    write_clear_slot_journal_with_replicas_and_meta(
                        paths,
                        &journal,
                        &replica_record,
                        &clear_target_meta,
                    )
                });
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Active slot clear completed partially across collections; switch journal preserved.",
                ));
            }

            // Stage 1 complete: all active credential replicas verified absent. Durably persist
            // `CommittedIndexPending` BEFORE Stage 2 local store cleanup (`policy.json`, `index.json`,
            // `accounts/<id>.json`, `token_lineage`).
            journal.phase = JournalPhase::CommittedIndexPending;
            repo.with_write_lock(|_| {
                write_clear_slot_journal_with_replicas_and_meta(
                    paths,
                    &journal,
                    &replica_record,
                    &clear_target_meta,
                )
            })
            .map_err(|stage_err| {
                CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Active credential slot was cleared, but failed to durably persist CommittedIndexPending stage in switch journal ({}).",
                        stage_err.message
                    ),
                )
            })?;

            if let Err(del_err) = repo.with_write_lock(|tx| {
                tx.complete_account_deletion_idempotent(
                    &t.id,
                    clear_target_meta.auth_generation,
                    clear_target_meta.refresh_token_digest.as_deref(),
                    now_unix,
                )?;
                clear_journal(tx.paths())
            }) {
                journal.phase = JournalPhase::CommittedIndexPending;
                journal.note = Some(del_err.message.clone());
                let _ = repo.with_write_lock(|_| {
                    write_clear_slot_journal_with_replicas_and_meta(
                        paths,
                        &journal,
                        &replica_record,
                        &clear_target_meta,
                    )
                });
                return Err(CliError::partial_commit(
                    "committed_index_pending",
                    format!(
                        "Active credential slot was cleared, but deleting account record failed ({}).",
                        del_err.message
                    ),
                ));
            }
            cleared_slot = true;
        } else {
            repo.with_write_lock(|tx| tx.delete_account(&t.id, force, now_unix))?;
        }
        Ok((t, cleared_slot))
    } else {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let snap = repo.read_snapshot()?;
        let t = snap.select(selector)?.clone();
        repo.with_write_lock(|tx| tx.delete_account(&t.id, force, now_unix))?;
        Ok((t, false))
    }
}
