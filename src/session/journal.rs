use crate::domain::account::STORE_SCHEMA_VERSION;
use crate::error::{format_safe_json_error, CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::session::backend::{CredentialBackend, SlotInspectState};
use crate::session::payload::serialize_session_payload;
use crate::store::fs_atomic::{
    check_fault_injection, ensure_no_symlink_components_under, map_io_error,
    read_regular_file_opt_bounded, write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use crate::store::locks::ActiveSlotLock;
use crate::store::repository::StoreRepository;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalPhase {
    Prepared,
    TokenRefreshed,
    SlotCommitting,
    CommittedSlot,
    AbortedUncommitted,
    RecoveryIncomplete,
    CommittedIndexPending,
}

/// Intent journal persisted at `<data_dir>/state/switch_journal.json` (`0600`) per Blueprint §3.3.
/// Contains ZERO plaintext tokens — only digests and account IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchJournal {
    pub schema_version: u32,
    pub operation_id: String,
    pub phase: JournalPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_selected_account_id: Option<String>,
    pub target_account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_slot_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_slot_digest: Option<String>,
    pub token_rotated: bool,
    pub started_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JournalDiagnosis {
    Clean,
    AbortedUncommitted {
        target_account_id: String,
        token_rotated: bool,
    },
    CommittedIndexPending {
        target_account_id: String,
    },
    RecoveryIncomplete {
        target_account_id: String,
        reason: String,
    },
}

pub fn read_journal_readonly(paths: &HeadlessPaths) -> CliResult<Option<SwitchJournal>> {
    let path = paths.switch_journal_file();
    ensure_no_symlink_components_under(&paths.data_dir, &path)?;
    let Some(bytes) = read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Switch journal")?
    else {
        return Ok(None);
    };
    let journal: SwitchJournal = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::data(format!(
            "{} Run `agy-switch-cli doctor`.",
            format_safe_json_error(&format!("Switch journal '{}'", path.display()), &e)
        ))
    })?;
    Ok(Some(journal))
}

pub fn write_journal(paths: &HeadlessPaths, journal: &SwitchJournal) -> CliResult<()> {
    check_fault_injection("write_journal", &paths.switch_journal_file())?;
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|_| CliError::data("Failed to serialize switch journal."))?;
    write_atomic_durable(&paths.switch_journal_file(), &bytes)
}

pub fn clear_journal(paths: &HeadlessPaths) -> CliResult<()> {
    let path = paths.switch_journal_file();
    ensure_no_symlink_components_under(&paths.data_dir, &path)?;
    match fs::remove_file(&path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                if let Ok(dir_file) = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(parent)
                {
                    let _ = dir_file.sync_all();
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(map_io_error(
            e,
            &format!("Failed to clear switch journal '{}'", path.display()),
        )),
    }
}

/// Pure read-only classification of an existing `switch_journal.json` against the real-time live slot digest.
pub fn diagnose_journal(
    journal: Option<&SwitchJournal>,
    slot_state: &SlotInspectState,
) -> JournalDiagnosis {
    let Some(j) = journal else {
        return JournalDiagnosis::Clean;
    };

    let current_digest = slot_state.raw_digest();

    match j.phase {
        JournalPhase::AbortedUncommitted => JournalDiagnosis::AbortedUncommitted {
            target_account_id: j.target_account_id.clone(),
            token_rotated: j.token_rotated,
        },
        JournalPhase::RecoveryIncomplete => JournalDiagnosis::RecoveryIncomplete {
            target_account_id: j.target_account_id.clone(),
            reason: j
                .note
                .clone()
                .unwrap_or_else(|| "Previous slot rollback failed.".into()),
        },
        JournalPhase::CommittedSlot | JournalPhase::CommittedIndexPending => {
            if matches!(slot_state, SlotInspectState::Corrupt(_)) {
                JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason: "Active credential slot became corrupt before index reconciliation."
                        .into(),
                }
            } else if matches!(slot_state, SlotInspectState::Unverified(_)) {
                JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason:
                        "Active credential slot could not be verified before index reconciliation."
                            .into(),
                }
            } else if j.target_slot_digest.is_some()
                && current_digest == j.target_slot_digest.as_deref()
            {
                JournalDiagnosis::CommittedIndexPending {
                    target_account_id: j.target_account_id.clone(),
                }
            } else {
                JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason: "Active credential slot digest diverged from journal target (external drift or concurrent switch detected)."
                        .into(),
                }
            }
        }
        JournalPhase::Prepared | JournalPhase::TokenRefreshed | JournalPhase::SlotCommitting => {
            if matches!(slot_state, SlotInspectState::Corrupt(_)) {
                return JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason: "Active credential slot is corrupt after interrupted switch.".into(),
                };
            }
            if matches!(slot_state, SlotInspectState::Unverified(_)) {
                return JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason:
                        "Active credential slot could not be verified after interrupted switch."
                            .into(),
                };
            }
            if j.target_slot_digest.is_some() && current_digest == j.target_slot_digest.as_deref() {
                // Interrupted right after atomic rename succeeded! Commit point WAS reached and slot still matches target.
                return JournalDiagnosis::CommittedIndexPending {
                    target_account_id: j.target_account_id.clone(),
                };
            }
            if current_digest == j.prev_slot_digest.as_deref() {
                return JournalDiagnosis::AbortedUncommitted {
                    target_account_id: j.target_account_id.clone(),
                    token_rotated: j.token_rotated,
                };
            }
            JournalDiagnosis::RecoveryIncomplete {
                target_account_id: j.target_account_id.clone(),
                reason: "Interrupted during slot commit and active slot differs from both pre-switch and target digests.".into(),
            }
        }
    }
}

/// Pre-write auto-reconciliation entry point for non-slot store write commands per Blueprint §3.3 & §11.2.B.
pub fn reconcile_pending_journal_before_write(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    now_unix: i64,
) -> CliResult<JournalDiagnosis> {
    reconcile_pending_journal_inner(repo, backend, true, now_unix)
}

/// Pre-execution auto-reconciliation entry point for slot-observing commands (`run -- agy`).
pub fn reconcile_pending_journal_for_slot_consumer(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    now_unix: i64,
) -> CliResult<JournalDiagnosis> {
    reconcile_pending_journal_inner(repo, backend, false, now_unix)
}

fn reconcile_pending_journal_inner(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    allow_live_precommit_bypass: bool,
    now_unix: i64,
) -> CliResult<JournalDiagnosis> {
    let paths = repo.paths();
    if read_journal_readonly(paths)?.is_none() {
        return Ok(JournalDiagnosis::Clean);
    }

    match ActiveSlotLock::try_acquire(paths, backend.uses_keyring()) {
        Ok(slot_lock) => reconcile_journal_locked(&slot_lock, repo, backend, false, now_unix),
        Err(busy_err) if busy_err.exit_code == crate::error::ExitCode::LockBusyOrConflict => {
            if allow_live_precommit_bypass {
                match read_journal_readonly(paths)? {
                    None => return Ok(JournalDiagnosis::Clean),
                    Some(live)
                        if matches!(
                            live.phase,
                            JournalPhase::Prepared | JournalPhase::TokenRefreshed
                        ) =>
                    {
                        return Ok(JournalDiagnosis::Clean);
                    }
                    Some(_) => {}
                }
            }
            let slot_lock = ActiveSlotLock::acquire(
                paths,
                backend.uses_keyring(),
                crate::store::repository::DEFAULT_STORE_LOCK_TIMEOUT,
            )?;
            reconcile_journal_locked(&slot_lock, repo, backend, false, now_unix)
        }
        Err(other_err) => Err(other_err),
    }
}

/// Reconcile an unfinished journal under L1 `ActiveSlotLock` -> L3 `StoreWriteLock` (`doctor --fix` or pre-write auto-reconcile).
/// CRITICAL INVARIANTS:
/// 1. NEVER rolls back any rotated `refresh_token` already saved in `accounts/<id>.json`.
/// 2. ALWAYS verifies real-time live slot digest CAS before advancing `index.json` or removing a deleted target's slot.
/// 3. Under `doctor --fix`, NEVER overwrites or deletes a valid externally-switched live slot (`SlotInspectState::Present`).
pub fn reconcile_journal_locked(
    _slot_lock: &ActiveSlotLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    allow_repair_incomplete: bool,
    now_unix: i64,
) -> CliResult<JournalDiagnosis> {
    let paths = repo.paths();
    let journal = match read_journal_readonly(paths) {
        Ok(Some(j)) => j,
        Ok(None) => return Ok(JournalDiagnosis::Clean),
        Err(corrupt_err) if allow_repair_incomplete => SwitchJournal {
            schema_version: STORE_SCHEMA_VERSION,
            operation_id: "corrupt-journal-repair".into(),
            phase: JournalPhase::RecoveryIncomplete,
            prev_selected_account_id: None,
            target_account_id: String::new(),
            prev_slot_digest: Some("corrupt".into()),
            target_slot_digest: None,
            token_rotated: false,
            started_at: now_unix,
            updated_at: now_unix,
            note: Some(corrupt_err.message),
        },
        Err(err) => return Err(err),
    };
    let slot_state = backend.inspect_slot(paths);
    let diagnosis = diagnose_journal(Some(&journal), &slot_state);

    match &diagnosis {
        JournalDiagnosis::Clean => Ok(JournalDiagnosis::Clean),
        JournalDiagnosis::AbortedUncommitted { .. } => {
            // Active slot matches pre-switch digest; keep any rotated refresh_token on disk and clear journal.
            repo.with_write_lock(|_| clear_journal(paths))?;
            Ok(diagnosis)
        }
        JournalDiagnosis::CommittedIndexPending { target_account_id } => {
            // Verified in `diagnose_journal`: live slot digest STILL equals `journal.target_slot_digest`!
            let expected_target_digest = journal.target_slot_digest.clone();
            let mut should_remove_deleted_slot = false;

            repo.with_write_lock(|tx| {
                // Re-verify real-time CAS right before mutating `index.json`!
                let live_check = backend.inspect_slot(paths);
                if expected_target_digest.is_none()
                    || live_check.raw_digest() != expected_target_digest.as_deref()
                {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Active credential slot digest changed externally during reconciliation. Run `agy-switch-cli doctor --fix`.",
                    ));
                }

                let mut index = tx.load_index_or_init(now_unix)?;
                let target_exists = index.account_order.iter().any(|id| id == target_account_id)
                    && tx.load_account_opt(target_account_id)?.is_some();
                if target_exists {
                    tx.commit_selected_account(target_account_id, now_unix)?;
                } else {
                    if index
                        .selected_account_id
                        .as_deref()
                        .is_some_and(|sel| !index.account_order.iter().any(|id| id == sel))
                    {
                        index.selected_account_id = None;
                        tx.save_index(&mut index, now_unix)?;
                    }
                    should_remove_deleted_slot = true;
                }
                Ok(())
            })?;

            if should_remove_deleted_slot {
                // CAS check: ONLY remove slot if its live digest STILL matches `journal.target_slot_digest`!
                let live_now = backend.inspect_slot(paths);
                if expected_target_digest.is_some()
                    && live_now.raw_digest() == expected_target_digest.as_deref()
                {
                    backend.remove_slot(paths)?;
                }
            }
            repo.with_write_lock(|_| clear_journal(paths))?;
            Ok(diagnosis)
        }
        JournalDiagnosis::RecoveryIncomplete {
            target_account_id,
            reason,
        } => {
            if !allow_repair_incomplete {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Previous switch recovery is incomplete ({reason}). Run `agy-switch-cli doctor --fix` to reconcile before further switching."
                    ),
                ));
            }

            // If the live active slot currently holds a VALID session payload (e.g. modified externally by
            // another `--data-dir` instance or native `agy`), NEVER overwrite or delete that valid live credential!
            if let SlotInspectState::Present(ref live_parsed) = slot_state {
                repo.with_write_lock(|tx| {
                    let mut index = tx.load_index_or_init(now_unix)?;
                    let mut matched_local_id: Option<String> = None;
                    for id in &index.account_order {
                        if let Some(acc) = tx.load_account_opt(id)? {
                            if acc.token.refresh_token_fingerprint()
                                == live_parsed.refresh_token_digest
                            {
                                matched_local_id = Some(acc.id);
                                break;
                            }
                        }
                    }
                    if let Some(local_id) = matched_local_id {
                        tx.commit_selected_account(&local_id, now_unix)?;
                    } else if index
                        .selected_account_id
                        .as_deref()
                        .is_some_and(|sel| !index.account_order.iter().any(|id| id == sel))
                    {
                        index.selected_account_id = index.account_order.first().cloned();
                        tx.save_index(&mut index, now_unix)?;
                    }
                    clear_journal(paths)
                })?;
                return Ok(diagnosis);
            }

            if matches!(slot_state, SlotInspectState::Unverified(_)) {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Cannot repair incomplete switch while active credential slot is unverified ({reason}). Fix permissions/keyring access and retry `doctor --fix`."
                    ),
                ));
            }

            // If official `agy` session directory does not exist (`Uninitialized`), do NOT fail with exit 8
            // trying to write into a non-existent `~/.gemini/antigravity-cli` — reconcile index and clear journal!
            if matches!(slot_state, SlotInspectState::Uninitialized) {
                repo.with_write_lock(|tx| {
                    let mut index = tx.load_index_or_init(now_unix)?;
                    if index
                        .selected_account_id
                        .as_deref()
                        .is_some_and(|sel| !index.account_order.iter().any(|id| id == sel))
                    {
                        index.selected_account_id = index.account_order.first().cloned();
                        tx.save_index(&mut index, now_unix)?;
                    }
                    clear_journal(paths)
                })?;
                return Ok(diagnosis);
            }

            // Slot is Corrupt or AbsentInInitializedDir: repair from local store candidates under explicit `doctor --fix`,
            // preferring usable (`!disabled` and not validation-blocked) accounts over disabled ones!
            let mut candidate_ids: Vec<String> = Vec::new();
            if let Some(ref prev_id) = journal.prev_selected_account_id {
                if !prev_id.is_empty() {
                    candidate_ids.push(prev_id.clone());
                }
            }
            if !target_account_id.is_empty() && !candidate_ids.contains(target_account_id) {
                candidate_ids.push(target_account_id.clone());
            }
            if let Ok(snap) = repo.read_snapshot() {
                for acc in snap.accounts {
                    if !candidate_ids.contains(&acc.id) {
                        candidate_ids.push(acc.id);
                    }
                }
            }

            let mut usable_choice: Option<(String, String)> = None;
            let mut fallback_choice: Option<(String, String)> = None;
            for cid in &candidate_ids {
                if let Ok(acc) = repo.read_account_unchecked(cid) {
                    if let Ok(payload) = serialize_session_payload(&acc.token) {
                        if acc.is_usable_at(now_unix) {
                            usable_choice = Some((cid.clone(), payload));
                            break;
                        } else if fallback_choice.is_none() {
                            fallback_choice = Some((cid.clone(), payload));
                        }
                    }
                }
            }

            if let Some((repair_id, payload)) = usable_choice.or(fallback_choice) {
                backend.write_slot(paths, &payload)?;
                repo.with_write_lock(|tx| {
                    tx.commit_selected_account(&repair_id, now_unix)?;
                    clear_journal(paths)
                })?;
            } else {
                backend.remove_slot(paths)?;
                repo.with_write_lock(|tx| {
                    let mut index = tx.load_index_or_init(now_unix)?;
                    if index
                        .selected_account_id
                        .as_deref()
                        .is_some_and(|sel| !index.account_order.iter().any(|id| id == sel))
                    {
                        index.selected_account_id = index.account_order.first().cloned();
                        tx.save_index(&mut index, now_unix)?;
                    }
                    clear_journal(paths)
                })?;
            }
            Ok(diagnosis)
        }
    }
}

impl SwitchJournal {
    pub fn new_prepared(
        operation_id: String,
        prev_selected_account_id: Option<String>,
        target_account_id: String,
        prev_slot_digest: Option<String>,
        now_unix: i64,
    ) -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            operation_id,
            phase: JournalPhase::Prepared,
            prev_selected_account_id,
            target_account_id,
            prev_slot_digest,
            target_slot_digest: None,
            token_rotated: false,
            started_at: now_unix,
            updated_at: now_unix,
            note: None,
        }
    }
}
