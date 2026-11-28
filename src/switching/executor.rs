use crate::domain::account::{AccountRecord, DisableReasonCode, RuntimeState};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::domain::token::TokenRecord;
use crate::error::{CliError, CliResult, ExitCode};
use crate::oauth::refresh::persist_disable_or_report_io_error;
use crate::oauth::registry::OAuthClientRegistry;
use crate::session::backend::{
    BackendPreWriteSnapshot, CredentialBackend, ReplicaCasExpectation, SlotInspectState,
};
use crate::session::journal::{
    clear_journal, diagnose_journal_replicas, diagnose_journal_replicas_with_intent,
    journal_on_disk_may_need_keyring, keyring_collection_ids_match, read_journal_full_readonly,
    reconcile_journal_locked, reconcile_pending_journal_before_write,
    replicas_all_absent_with_exact_collections,
    selected_replicas_match_digest_with_exact_collections,
    write_clear_slot_journal_with_replicas_and_meta, write_journal_with_replicas,
    ClearSlotTargetMeta, JournalDiagnosis, JournalPhase, JournalReplicaRecord, SwitchJournal,
};
use crate::session::payload::{
    bytes_sha256_hex, extract_session_token_from_bytes, serialize_session_payload_for_account,
    ExtractedSessionToken, ParsedSessionPayload,
};
use crate::session::process::observe_runtime_state;
use crate::store::fs_atomic::{
    check_fault_injection, cleanup_owned_orphan_temp_files_pinned,
    ensure_no_symlink_components_under, read_regular_file_opt_bounded, MAX_STORE_FILE_BYTES,
};
use crate::store::locks::ActiveSlotLock;
use crate::store::repository::{StoreRepository, StoreSnapshot};
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
    pub validation_blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_warning: Option<String>,
}

pub(crate) fn format_validation_blocked_warning(target_id: &str) -> String {
    format!(
        "Note: account `{target_id}` is currently marked verification-required (`verify-blocked`). Open `agy` to complete Google verification, then run `agy-switch-cli refresh` (or `agy-switch-cli quota --refresh`) to clear this status."
    )
}

#[derive(Debug, Clone, Default)]
pub struct SlotSyncBackOutcome {
    pub synced_account_id: Option<String>,
    pub token_updated: bool,
    pub refresh_token_rotated: bool,
}

fn slot_access_token_is_fresher(extracted: &ExtractedSessionToken, existing: &TokenRecord) -> bool {
    extracted.access_token.as_deref().is_some_and(|at| {
        let trimmed = at.trim();
        if trimmed.is_empty() {
            return false;
        }
        if existing.access_token.trim().is_empty() {
            return true;
        }
        match extracted.expiry_unix {
            Some(exp) if exp > existing.expiry_timestamp => true,
            Some(exp)
                if exp == existing.expiry_timestamp && trimmed != existing.access_token.trim() =>
            {
                true
            }
            _ => false,
        }
    })
}

fn slot_token_updates_account(
    extracted: &ExtractedSessionToken,
    account: &AccountRecord,
) -> (bool, bool) {
    let cur_rt = account.token.refresh_token.trim();
    let new_rt = extracted.refresh_token.trim();
    let rt_rotated = !new_rt.is_empty() && new_rt != cur_rt;
    let at_fresher = slot_access_token_is_fresher(extracted, &account.token);
    let id_token_added = extracted.id_token.is_some() && account.token.id_token.is_none();
    (rt_rotated || at_fresher || id_token_added, rt_rotated)
}

fn build_synced_token_record(
    extracted: &ExtractedSessionToken,
    existing: &TokenRecord,
    now_unix: i64,
) -> TokenRecord {
    let new_rt = extracted.refresh_token.trim();
    let rt_rotated = !new_rt.is_empty() && new_rt != existing.refresh_token.trim();
    let at_fresher = slot_access_token_is_fresher(extracted, existing);
    let extracted_at = extracted
        .access_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Keep `(access_token, expiry_timestamp, expires_in)` strictly paired:
    // - When RT rotated or the slot AT is adopted (`at_fresher`), NEVER borrow the previous AT's
    //   `expiry_timestamp` or `expires_in`; missing/non-positive expiry falls back conservatively
    //   to `(1, 0)` matching offline `--from-local` import.
    // - When neither RT rotated nor AT is fresher (e.g. only adding a previously missing `id_token`),
    //   keep the stored `(access_token, expiry_timestamp, expires_in)` triple completely untouched.
    let (access_token, expiry_timestamp, expires_in) = if rt_rotated || at_fresher {
        let at = if rt_rotated {
            extracted_at.map(str::to_owned).unwrap_or_default()
        } else {
            extracted_at
                .map(str::to_owned)
                .unwrap_or_else(|| existing.access_token.clone())
        };
        let exp = extracted.expiry_unix.filter(|&e| e > 0).unwrap_or(1);
        let exp_in = if exp > now_unix {
            exp.saturating_sub(now_unix).max(60)
        } else {
            0
        };
        (at, exp, exp_in)
    } else {
        (
            existing.access_token.clone(),
            existing.expiry_timestamp.max(1),
            existing.expires_in,
        )
    };

    TokenRecord {
        access_token,
        refresh_token: new_rt.to_string(),
        expires_in,
        expiry_timestamp,
        token_type: if existing.token_type.trim().is_empty() {
            "Bearer".into()
        } else {
            existing.token_type.clone()
        },
        id_token: extracted
            .id_token
            .clone()
            .or_else(|| existing.id_token.clone()),
        oauth_client_key: existing.oauth_client_key.clone(),
        granted_scopes: existing.granted_scopes.clone(),
        project_id: existing.project_id.clone(),
        is_gcp_tos: existing.is_gcp_tos,
    }
}

struct ResolvedSyncBackCandidate<'a> {
    extracted: ExtractedSessionToken,
    owner: &'a AccountRecord,
    via_email_rotation: bool,
}

fn resolve_sync_back_candidate<'a>(
    repo: &StoreRepository,
    snapshot: &'a StoreSnapshot,
    extracted: ExtractedSessionToken,
    pinned_owner_id: Option<&str>,
) -> Option<ResolvedSyncBackCandidate<'a>> {
    let (owner, via_email_rotation) = if let Some(target_id) = pinned_owner_id {
        let target_acc = snapshot.accounts.iter().find(|a| a.id == target_id)?;
        if target_acc.token.refresh_token_fingerprint() == extracted.refresh_token_digest {
            (target_acc, false)
        } else {
            let owned_by_other = snapshot.accounts.iter().any(|a| {
                a.id != target_id
                    && a.token.refresh_token_fingerprint() == extracted.refresh_token_digest
            });
            let email_matches = extracted
                .email_hint
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case(&target_acc.email));
            if owned_by_other || !email_matches {
                return None;
            }
            (target_acc, true)
        }
    } else {
        resolve_owner_for_extracted(&extracted, snapshot)?
    };

    // Never treat an already-superseded historical refresh token as a fresh rotation candidate
    // (fail-closed if the overflow lineage archive cannot be read).
    if via_email_rotation
        && account_has_superseded_rt_digest_readonly(repo, owner, &extracted.refresh_token_digest)
            .unwrap_or(true)
    {
        return None;
    }

    Some(ResolvedSyncBackCandidate {
        extracted,
        owner,
        via_email_rotation,
    })
}

fn prefer_file_sync_back_candidate(
    kr: &ResolvedSyncBackCandidate<'_>,
    file: &ResolvedSyncBackCandidate<'_>,
) -> bool {
    if kr.owner.id != file.owner.id {
        // Diverged replicas pointing to two different saved accounts: keyring is the effective
        // active slot (matching `effective_slot_state()` and `resolve_outgoing_slot_owner_from_pre_snap`).
        return false;
    }

    // Same owning account across keyring and disk file (`dual`):
    // 1. Separate verified non-superseded RT rotation from AT expiry comparison so a single-sided
    //    rotated RT is NEVER discarded just because AT expiry stayed equal, moved earlier, or was
    //    omitted (symmetric for both file-only and keyring-only rotations).
    if file.via_email_rotation != kr.via_email_rotation {
        return file.via_email_rotation;
    }

    // 2. Both replicas hold the stored RT (or both hold verified rotated RTs):
    //    prefer strictly fresher AT expiry, then fresher AT, then `id_token` addition,
    //    preserving keyring preference on ties.
    let kr_exp = kr.extracted.expiry_unix.unwrap_or(0);
    let file_exp = file.extracted.expiry_unix.unwrap_or(0);
    if file_exp != kr_exp {
        return file_exp > kr_exp;
    }

    let kr_at_fresher = slot_access_token_is_fresher(&kr.extracted, &kr.owner.token);
    let file_at_fresher = slot_access_token_is_fresher(&file.extracted, &file.owner.token);
    if file_at_fresher != kr_at_fresher {
        return file_at_fresher;
    }

    let kr_adds_id_token = kr.extracted.id_token.is_some() && kr.owner.token.id_token.is_none();
    let file_adds_id_token =
        file.extracted.id_token.is_some() && file.owner.token.id_token.is_none();
    if file_adds_id_token != kr_adds_id_token {
        return file_adds_id_token;
    }

    false
}

fn select_sync_back_candidate<'a>(
    repo: &StoreRepository,
    snapshot: &'a StoreSnapshot,
    kr_extracted: Option<ExtractedSessionToken>,
    file_extracted: Option<ExtractedSessionToken>,
    pinned_owner_id: Option<&str>,
) -> Option<ResolvedSyncBackCandidate<'a>> {
    let kr_cand = kr_extracted
        .and_then(|ex| resolve_sync_back_candidate(repo, snapshot, ex, pinned_owner_id));
    let file_cand = file_extracted
        .and_then(|ex| resolve_sync_back_candidate(repo, snapshot, ex, pinned_owner_id));

    match (kr_cand, file_cand) {
        (Some(kr), Some(file)) => {
            if prefer_file_sync_back_candidate(&kr, &file) {
                Some(file)
            } else {
                Some(kr)
            }
        }
        (Some(kr), None) => Some(kr),
        (None, Some(file)) => Some(file),
        (None, None) => None,
    }
}

fn extract_replica_tokens_from_pre_snap(
    pre_snap: &BackendPreWriteSnapshot,
) -> (Option<ExtractedSessionToken>, Option<ExtractedSessionToken>) {
    let kr_extracted = if pre_snap.uses_keyring && pre_snap.keyring_uniform {
        pre_snap
            .keyring_bytes
            .as_ref()
            .and_then(|o| o.as_deref())
            .and_then(|b| extract_session_token_from_bytes(b, "Active keyring slot").ok())
    } else {
        None
    };
    let file_extracted = if pre_snap.uses_file {
        pre_snap
            .file_bytes
            .as_deref()
            .and_then(|b| extract_session_token_from_bytes(b, "Active session file").ok())
    } else {
        None
    };
    (kr_extracted, file_extracted)
}

fn read_sync_back_replica_tokens(
    paths: &crate::paths::HeadlessPaths,
    backend: &dyn CredentialBackend,
) -> (Option<ExtractedSessionToken>, Option<ExtractedSessionToken>) {
    let kr_extracted = if backend.uses_keyring() {
        backend
            .read_raw_keyring_secret()
            .ok()
            .flatten()
            .and_then(|bytes| {
                extract_session_token_from_bytes(&bytes, "Linux Secret Service keyring").ok()
            })
    } else {
        None
    };
    let file_extracted = if backend.uses_file() {
        if ensure_no_symlink_components_under(&paths.home_dir, &paths.active_slot_file).is_ok() {
            read_regular_file_opt_bounded(
                &paths.active_slot_file,
                MAX_STORE_FILE_BYTES,
                "Local agy session file",
            )
            .ok()
            .flatten()
            .and_then(|bytes| {
                extract_session_token_from_bytes(&bytes, "Local agy session file").ok()
            })
        } else {
            None
        }
    } else {
        None
    };
    (kr_extracted, file_extracted)
}

/// Purely identify which saved account in `snapshot` owns `extracted`:
/// 1. Exact `refresh_token` fingerprint match (checking `selected_account_id` first);
/// 2. Otherwise, ONLY if no other account holds this `refresh_token` AND `selected_account_id`'s
///    email matches `extracted.email_hint` case-insensitively (rotated refresh token from `agy`).
fn resolve_owner_for_extracted<'a>(
    extracted: &ExtractedSessionToken,
    snapshot: &'a StoreSnapshot,
) -> Option<(&'a AccountRecord, bool)> {
    let sel_id = snapshot.index.selected_account_id.as_deref();
    if let Some(sid) = sel_id {
        if let Some(sel_acc) = snapshot.accounts.iter().find(|a| a.id == sid) {
            if sel_acc.token.refresh_token_fingerprint() == extracted.refresh_token_digest {
                return Some((sel_acc, false));
            }
        }
    }
    if let Some(other) = snapshot
        .accounts
        .iter()
        .find(|a| a.token.refresh_token_fingerprint() == extracted.refresh_token_digest)
    {
        return Some((other, false));
    }
    if let Some(sid) = sel_id {
        if let Some(sel_acc) = snapshot.accounts.iter().find(|a| a.id == sid) {
            if extracted
                .email_hint
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case(&sel_acc.email))
            {
                return Some((sel_acc, true));
            }
        }
    }
    None
}

/// Check read-only whether `rt_digest` is already recorded as a superseded historical refresh
/// token for `acc` (across both inline `previous_refresh_token_digests` and overflow archive).
pub(crate) fn account_has_superseded_rt_digest_readonly(
    repo: &StoreRepository,
    acc: &AccountRecord,
    rt_digest: &str,
) -> CliResult<bool> {
    if acc
        .previous_refresh_token_digests
        .iter()
        .any(|d| d == rt_digest)
    {
        return Ok(true);
    }
    if let Some(archive) = repo.read_token_lineage_readonly(&acc.id)? {
        if archive.digests.iter().any(|d| d == rt_digest) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns `true` when an active slot payload whose `refresh_token` differs from `selected`'s
/// stored token still provably belongs to `selected` after official `agy` rotated its
/// `refresh_token` during interactive usage (Option 1B):
/// - `parsed.email_hint` matches `selected.email` case-insensitively;
/// - NO saved account in `snapshot` owns `parsed.refresh_token_digest`;
/// - `parsed.refresh_token_digest` is NOT a superseded historical token of `selected` (fail-closed
///   if the lineage archive cannot be read).
pub(crate) fn slot_matches_selected_rotated_account(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    parsed: &ParsedSessionPayload,
    selected: &AccountRecord,
) -> bool {
    if !parsed
        .email_hint
        .as_deref()
        .is_some_and(|hint| hint.eq_ignore_ascii_case(&selected.email))
    {
        return false;
    }
    if snapshot
        .accounts
        .iter()
        .any(|a| a.token.refresh_token_fingerprint() == parsed.refresh_token_digest)
    {
        return false;
    }
    !account_has_superseded_rt_digest_readonly(repo, selected, &parsed.refresh_token_digest)
        .unwrap_or(true)
}

fn sync_back_extracted_for_owner(
    repo: &StoreRepository,
    owner_id: &str,
    via_email_rotation_match: bool,
    extracted: &ExtractedSessionToken,
    now_unix: i64,
) -> CliResult<SlotSyncBackOutcome> {
    let owner_snapshot = match repo.read_account_unchecked(owner_id) {
        Ok(a) => a,
        Err(_) => {
            return Ok(SlotSyncBackOutcome::default());
        }
    };
    let (needs_token_update, _) = slot_token_updates_account(extracted, &owner_snapshot);
    if !needs_token_update {
        return Ok(SlotSyncBackOutcome {
            synced_account_id: Some(owner_id.to_string()),
            token_updated: false,
            refresh_token_rotated: false,
        });
    }

    let (accepted, token_updated, refresh_token_rotated) = repo.with_write_lock(|tx| {
        let Some(latest) = tx.load_account_opt(owner_id)? else {
            return Ok((false, false, false));
        };
        // Never roll back a superseded historical refresh_token in the 66,048-level lineage!
        if tx
            .account_has_superseded_rt_in_tx(&latest, &extracted.refresh_token)?
            .0
        {
            return Ok((false, false, false));
        }
        if via_email_rotation_match {
            // Re-verify inside L3 that this refresh_token does not belong to another saved account.
            let index = tx.load_index_or_init(now_unix)?;
            for other_id in &index.account_order {
                if other_id == owner_id {
                    continue;
                }
                if let Some(other) = tx.load_account_opt(other_id)? {
                    if other.token.refresh_token_fingerprint() == extracted.refresh_token_digest {
                        return Ok((false, false, false));
                    }
                }
            }
        }
        let (still_needs_token, rt_rotated) = slot_token_updates_account(extracted, &latest);
        if !still_needs_token {
            return Ok((true, false, false));
        }
        let merged = build_synced_token_record(extracted, &latest.token, now_unix);
        let _ = tx.merge_refreshed_token(owner_id, merged, None, now_unix)?;
        Ok((true, true, rt_rotated))
    })?;

    if !accepted {
        return Ok(SlotSyncBackOutcome::default());
    }

    Ok(SlotSyncBackOutcome {
        synced_account_id: Some(owner_id.to_string()),
        token_updated,
        refresh_token_rotated,
    })
}

/// Resolve the saved account ID that genuinely owns the **effective active slot** in `pre_snap`
/// before switching out, so `commit_selected_account_with_slot_owner` never fabricates
/// `last_switched_out_at` on a stale disk replica when `dual` keyring drifted externally or holds
/// a corrupt/non-uniform payload.
///
/// Effective-slot precedence matches `BackendReplicaInspection::effective_slot_state`:
/// - When `pre_snap.uses_keyring` and keyring has bytes:
///   - require `pre_snap.keyring_uniform` and a parseable keyring payload;
///   - if the keyring payload directly resolves to a saved account (exact RT or Option 1B rotated
///     RT), that account is the outgoing slot owner;
///   - otherwise, ONLY if `pre_snap.uses_file` yields a valid `file_cand` whose superseded RT
///     lineage contains the keyring RT (F-01 single-sided disk rotation where keyring still holds
///     the older superseded RT), return `file_cand.owner.id`;
///   - otherwise (genuinely foreign, corrupt, or non-uniform keyring), return `None`.
/// - When keyring is unused or cleanly absent, fall back to `file` (if `pre_snap.uses_file`).
fn resolve_outgoing_slot_owner_from_pre_snap(
    repo: &StoreRepository,
    pre_snap: &BackendPreWriteSnapshot,
    snapshot: &StoreSnapshot,
) -> Option<String> {
    let file_cand = || -> Option<ResolvedSyncBackCandidate<'_>> {
        if !pre_snap.uses_file {
            return None;
        }
        let file_ex = pre_snap
            .file_bytes
            .as_deref()
            .and_then(|b| extract_session_token_from_bytes(b, "Active session file").ok())?;
        resolve_sync_back_candidate(repo, snapshot, file_ex, None)
    };

    if pre_snap.uses_keyring {
        if !pre_snap.keyring_uniform {
            return None;
        }
        if let Some(kr_bytes) = pre_snap.keyring_bytes.as_ref().and_then(|o| o.as_deref()) {
            let kr_ex = extract_session_token_from_bytes(kr_bytes, "Active keyring slot").ok()?;
            let kr_rt_digest = kr_ex.refresh_token_digest.clone();
            if let Some(kr_cand) = resolve_sync_back_candidate(repo, snapshot, kr_ex, None) {
                return Some(kr_cand.owner.id.clone());
            }
            if let Some(fc) = file_cand() {
                if account_has_superseded_rt_digest_readonly(repo, fc.owner, &kr_rt_digest)
                    .unwrap_or(false)
                {
                    return Some(fc.owner.id.clone());
                }
            }
            return None;
        }
    }

    file_cand().map(|fc| fc.owner.id.clone())
}

/// Pre-switch pure-local sync-back under `L1`:
/// Inspects ALL managed pre-switch active replicas (`keyring` and/or `file`) and merges any
/// verified non-superseded rotated `refresh_token` or fresher `access_token` back into the owning
/// account(s) under `L3` before switching out. When `dual` replicas diverged onto two different
/// saved accounts, preserves any fresher token on the secondary disk replica as well as the
/// effective keyring slot (returning the effective keyring slot's outcome).
pub(crate) fn sync_back_pre_switch_snapshot(
    repo: &StoreRepository,
    pre_snap: &BackendPreWriteSnapshot,
    snapshot: &StoreSnapshot,
    now_unix: i64,
) -> CliResult<SlotSyncBackOutcome> {
    let (kr_extracted, file_extracted) = extract_replica_tokens_from_pre_snap(pre_snap);
    let kr_cand = kr_extracted.and_then(|ex| resolve_sync_back_candidate(repo, snapshot, ex, None));
    let file_cand =
        file_extracted.and_then(|ex| resolve_sync_back_candidate(repo, snapshot, ex, None));

    match (kr_cand, file_cand) {
        (Some(kr), Some(file)) if kr.owner.id != file.owner.id => {
            // Both replicas are about to be overwritten: preserve any fresher token on the
            // secondary disk replica (no-op if stale) AND prioritize the effective keyring slot!
            let _ = sync_back_extracted_for_owner(
                repo,
                &file.owner.id,
                file.via_email_rotation,
                &file.extracted,
                now_unix,
            )?;
            sync_back_extracted_for_owner(
                repo,
                &kr.owner.id,
                kr.via_email_rotation,
                &kr.extracted,
                now_unix,
            )
        }
        (Some(kr), Some(file)) => {
            let chosen = if prefer_file_sync_back_candidate(&kr, &file) {
                file
            } else {
                kr
            };
            sync_back_extracted_for_owner(
                repo,
                &chosen.owner.id,
                chosen.via_email_rotation,
                &chosen.extracted,
                now_unix,
            )
        }
        (Some(only), None) | (None, Some(only)) => sync_back_extracted_for_owner(
            repo,
            &only.owner.id,
            only.via_email_rotation,
            &only.extracted,
            now_unix,
        ),
        (None, None) => Ok(SlotSyncBackOutcome::default()),
    }
}

/// Post-`/usage` pure-local sync-back for a known active account:
/// Independently inspects ALL replicas managed by `backend` (`keyring` and/or `file`, never
/// touching disk in `keyring`-only mode or D-Bus in `file`-only mode), selects any verified
/// non-superseded rotated `refresh_token` or fresher `access_token` belonging to `account_id`,
/// and merges it back into `accounts/<account_id>.json`.
pub(crate) fn sync_back_active_slot_for_account(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    account_id: &str,
    now_unix: i64,
) -> CliResult<SlotSyncBackOutcome> {
    let (kr_extracted, file_extracted) = read_sync_back_replica_tokens(repo.paths(), backend);
    if kr_extracted.is_none() && file_extracted.is_none() {
        return Ok(SlotSyncBackOutcome::default());
    }
    let snapshot = repo.read_snapshot()?;
    let Some(chosen) = select_sync_back_candidate(
        repo,
        &snapshot,
        kr_extracted,
        file_extracted,
        Some(account_id),
    ) else {
        return Ok(SlotSyncBackOutcome::default());
    };
    sync_back_extracted_for_owner(
        repo,
        &chosen.owner.id,
        chosen.via_email_rotation,
        &chosen.extracted,
        now_unix,
    )
}

/// Strictly read-only, zero-network dry-run preview for manual credential switching.
/// Never touches the network, never acquires write locks, and never modifies slot/store state.
pub fn preview_switch_dry_run(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    registry: &OAuthClientRegistry,
    selector: &str,
    allow_running: bool,
    require_idle: bool,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    let paths = repo.paths();
    let guard_mode = RunningGuardMode::from_flags(allow_running, require_idle);

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
    validate_target_usable(target, now_unix, true)?;
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

    if replica_state.uses_file && matches!(replica_state.file, SlotInspectState::Uninitialized) {
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
    let validation_blocked = target.is_validation_blocked_at(now_unix);
    let validation_warning =
        validation_blocked.then(|| format_validation_blocked_warning(&target.id));

    Ok(SwitchOutcome {
        dry_run: true,
        previous_selected_id: effective_prev,
        target_account_id: target.id.clone(),
        target_email: target.email.clone(),
        token_refreshed: false,
        refresh_token_rotated: false,
        runtime_warning,
        validation_blocked,
        validation_warning,
    })
}

/// Execute a single safe, zero-network offline credential switch strictly following `L1 -> L3`
/// lock hierarchy, pre-switch local sync-back of the outgoing slot, and the multi-replica
/// `switch_journal.json` commit-point protocol (Blueprint §3.1, §3.3, Option 1B).
/// By default (`allow_running == false` and `require_idle == false`), switches immediately even if
/// verified `agy` sessions are running (emitting a non-fatal `runtime_warning` that running sessions
/// keep their startup login), while failing closed on `RuntimeState::Unverified`.
pub fn execute_switch(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    registry: &OAuthClientRegistry,
    selector: &str,
    options: &SwitchOptions,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    execute_switch_with_idle_policy(repo, backend, registry, selector, options, false, now_unix)
}

pub fn execute_switch_with_idle_policy(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    registry: &OAuthClientRegistry,
    selector: &str,
    options: &SwitchOptions,
    require_idle: bool,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    let paths = repo.paths();
    let guard_mode = RunningGuardMode::from_flags(options.allow_running, require_idle);

    if options.dry_run {
        return preview_switch_dry_run(
            repo,
            backend,
            registry,
            selector,
            options.allow_running,
            require_idle,
            now_unix,
        );
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
        &slot_lock, repo, backend, registry, selector, guard_mode, true, true, now_unix,
    )
}

/// Core offline switch execution when the caller ALREADY holds L1 `ActiveSlotLock`.
pub fn execute_switch_with_slot_lock(
    slot_lock: &ActiveSlotLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    registry: &OAuthClientRegistry,
    selector: &str,
    allow_running: bool,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    execute_switch_with_slot_lock_and_guard(
        slot_lock,
        repo,
        backend,
        registry,
        selector,
        RunningGuardMode::from_flags(allow_running, false),
        false,
        false,
        now_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_switch_with_slot_lock_and_guard(
    slot_lock: &ActiveSlotLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    registry: &OAuthClientRegistry,
    selector: &str,
    guard_mode: RunningGuardMode,
    allow_repair_incomplete: bool,
    allow_validation_blocked: bool,
    now_unix: i64,
) -> CliResult<SwitchOutcome> {
    let paths = repo.paths();
    let clock = AnchoredClock::new(now_unix);

    // Reconcile any leftover journal (manual switch repairs safe cross-replica RecoveryIncomplete;
    // callers passing `allow_repair_incomplete = false` fail closed on incomplete recovery).
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
    validate_target_usable(&target_initial, clock.now_unix(), allow_validation_blocked)?;

    // Pure-local OAuth scope verification when `granted_scopes` is known (`Some(...)`).
    let missing_scopes = registry.missing_required_scopes(&target_initial.token);
    if !missing_scopes.is_empty() {
        let scope_err = CliError::auth(
            "scope_reauth_required",
            format!(
                "Account '{}' ({}) lacks required OAuth scope(s) ({}). Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize {}`.",
                target_initial.id,
                target_initial.email,
                missing_scopes.join(", "),
                target_initial.id
            ),
        );
        return Err(persist_disable_or_report_io_error(
            repo,
            &target_initial.id,
            DisableReasonCode::ScopeReauthRequired,
            format!(
                "Known granted_scopes missing required scope(s): {}",
                missing_scopes.join(", ")
            ),
            clock.now_unix(),
            scope_err,
        ));
    }

    // Check active slot directory is initialized and snapshot ALL replicas before write
    let pre_snap = backend.snapshot_replicas_before_write(paths)?;

    // Determine the genuine outgoing active-slot owner from the effective pre-switch slot BEFORE
    // mutating the store, so `dual` single-replica external drift on keyring never stamps
    // `last_switched_out_at` onto a stale disk replica.
    let outgoing_slot_owner = resolve_outgoing_slot_owner_from_pre_snap(repo, &pre_snap, &snapshot);

    // Pre-Switch Sync-Back (Option 1B): purely locally merge any fresher `access_token` or rotated
    // `refresh_token` from the outgoing active slot back into `accounts/<A>.json` under `L3`
    // BEFORE overwriting the active slot with target account B!
    let _ = sync_back_pre_switch_snapshot(repo, &pre_snap, &snapshot, clock.now_unix())?;

    let prev_slot_digest = pre_snap.effective_slot_digest();
    let replica_record = JournalReplicaRecord::from_pre_write_snapshot(&pre_snap);

    let mut journal = SwitchJournal::new_prepared(
        Uuid::new_v4().to_string(),
        snapshot.index.selected_account_id.clone(),
        target_initial.id.clone(),
        prev_slot_digest,
        clock.now_unix(),
    )
    .with_observed_outgoing_slot_owner(outgoing_slot_owner.as_deref());

    repo.with_write_lock(|_| write_journal_with_replicas(paths, &journal, Some(&replica_record)))?;

    check_fault_injection("after_token_refreshed", &paths.active_slot_file)?;

    // Re-check CAS digest on ALL active replicas before committing
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

    // Re-read latest target account (also picks up any synced-back fresher token if re-switching to the same account)
    let commit_now = clock.now_unix();
    let latest_target = repo.read_account_unchecked(&target_initial.id)?;
    validate_target_usable(&latest_target, commit_now, allow_validation_blocked)?;

    let payload = serialize_session_payload_for_account(&latest_target)?;
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

    // 4. Commit `selected_account_id`, `last_switched_out_at`, `last_switched_in_at`, and
    //    `last_used` inside one `L3` StoreWriteLock transaction, and clear journal
    let index_commit = repo.with_write_lock(|tx| {
        check_fault_injection("after_slot_commit", &tx.paths().index_file())?;
        check_fault_injection("before_index_commit", &tx.paths().index_file())?;
        tx.commit_selected_account_with_slot_owner(
            &latest_target.id,
            Some(outgoing_slot_owner.as_deref()),
            post_commit_now,
        )?;
        clear_journal(tx.paths())?;
        Ok(())
    });

    if let Err(idx_err) = index_commit {
        journal.phase = JournalPhase::CommittedIndexPending;
        journal.note = Some(idx_err.message.clone());
        journal.updated_at = post_commit_now;
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

    let validation_blocked = latest_target.is_validation_blocked_at(commit_now);
    let validation_warning =
        validation_blocked.then(|| format_validation_blocked_warning(&latest_target.id));

    Ok(SwitchOutcome {
        dry_run: false,
        previous_selected_id: snapshot.index.selected_account_id,
        target_account_id: latest_target.id,
        target_email: latest_target.email,
        token_refreshed: false,
        refresh_token_rotated: false,
        runtime_warning,
        validation_blocked,
        validation_warning,
    })
}

pub(crate) fn validate_target_usable(
    target: &crate::domain::account::AccountRecord,
    now_unix: i64,
    allow_validation_blocked: bool,
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
    if !allow_validation_blocked && target.is_validation_blocked_at(now_unix) {
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
/// removes the account from `index.json`, `accounts/<id>.json`, and `token_lineage`.
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
            // `CommittedIndexPending` BEFORE Stage 2 local store cleanup (`index.json`,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::HeadlessPaths;
    use crate::session::backend::FileSessionBackend;
    use std::fs;

    #[test]
    fn sync_back_rejects_superseded_rt_and_preserves_f01_dual_replica_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let now = 1_900_000_000i64;

        let mut acc = AccountRecord::new(
            "acc-0001".into(),
            "alice@example.com".into(),
            TokenRecord {
                access_token: "ya29.current".into(),
                refresh_token: "1//RT_ALICE_CURRENT".into(),
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
        acc.record_superseded_digest(&crate::domain::token::token_digest("1//RT_ALICE_OLD"));

        repo.with_write_lock(|tx| {
            tx.upsert_account(acc.clone(), true, now)?;
            Ok(())
        })
        .unwrap();

        // 1. Slot rolled back to superseded RT MUST be rejected with zero mutation on disk.
        fs::write(
            &paths.active_slot_file,
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": "ya29.stale",
                    "token_type": "Bearer",
                    "refresh_token": "1//RT_ALICE_OLD",
                    "expiry": "2099-01-01T00:00:00Z"
                },
                "id_token_email": "alice@example.com"
            }))
            .unwrap(),
        )
        .unwrap();
        let rejected =
            sync_back_active_slot_for_account(&repo, &FileSessionBackend, "acc-0001", now + 5)
                .unwrap();
        assert_eq!(rejected.synced_account_id, None);
        assert!(!rejected.token_updated);
        let after_rej = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(after_rej.token.refresh_token, "1//RT_ALICE_CURRENT");

        // 2. S3 regression: same RT + fresher stored AT/expiry (`2050000000`) + older slot AT/expiry
        //    (`1700000000`) with newly added `id_token` MUST keep the fresher stored AT+expiry pair
        //    while merging only the newly added `id_token`!
        let existing_tok = TokenRecord {
            access_token: "ya29.fresher_stored".into(),
            refresh_token: "1//RT_SAME".into(),
            expires_in: 3600,
            expiry_timestamp: 2_050_000_000,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: None,
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        };
        let older_slot_with_jwt = ExtractedSessionToken {
            access_token: Some("ya29.older_slot".into()),
            refresh_token: "1//RT_SAME".into(),
            expiry: Some("2023-11-14T22:13:20Z".into()),
            expiry_unix: Some(1_700_000_000),
            auth_method: Some("consumer".into()),
            id_token: Some("hdr.pay.sig".into()),
            id_token_email: Some("alice@example.com".into()),
            email_hint: Some("alice@example.com".into()),
            raw_digest: "digest-s3".into(),
            refresh_token_digest: crate::domain::token::token_digest("1//RT_SAME"),
        };
        let merged_jwt_only = build_synced_token_record(&older_slot_with_jwt, &existing_tok, now);
        assert_eq!(merged_jwt_only.access_token, "ya29.fresher_stored");
        assert_eq!(merged_jwt_only.expiry_timestamp, 2_050_000_000);
        assert_eq!(merged_jwt_only.expires_in, 3600);
        assert_eq!(merged_jwt_only.id_token.as_deref(), Some("hdr.pay.sig"));

        let fresher_slot = ExtractedSessionToken {
            access_token: Some("ya29.newer_slot".into()),
            expiry_unix: Some(2_060_000_000),
            ..older_slot_with_jwt.clone()
        };
        let merged_fresher = build_synced_token_record(&fresher_slot, &existing_tok, now);
        assert_eq!(merged_fresher.access_token, "ya29.newer_slot");
        assert_eq!(merged_fresher.expiry_timestamp, 2_060_000_000);

        // 2b. R2-02 regression: rotated RT with non-empty new AT and MISSING `expiry` MUST NOT
        //     borrow the old AT's future `expiry_timestamp` (`2050000000`) or `expires_in` (`3600`);
        //     it must conservatively fall back to `(1, 0)` matching offline `--from-local`!
        let rotated_missing_expiry = ExtractedSessionToken {
            access_token: Some("ya29.rotated_no_expiry".into()),
            refresh_token: "1//RT_ROTATED_NEW".into(),
            expiry: None,
            expiry_unix: None,
            refresh_token_digest: crate::domain::token::token_digest("1//RT_ROTATED_NEW"),
            ..older_slot_with_jwt.clone()
        };
        let merged_rot_no_exp =
            build_synced_token_record(&rotated_missing_expiry, &existing_tok, now);
        assert_eq!(merged_rot_no_exp.refresh_token, "1//RT_ROTATED_NEW");
        assert_eq!(merged_rot_no_exp.access_token, "ya29.rotated_no_expiry");
        assert_eq!(merged_rot_no_exp.expiry_timestamp, 1);
        assert_eq!(merged_rot_no_exp.expires_in, 0);

        // Positive control: rotated RT with valid `expiry` adopts both AT and valid expiry.
        let rotated_with_expiry = ExtractedSessionToken {
            expiry: Some("2034-08-23T00:26:40Z".into()),
            expiry_unix: Some(2_040_000_000),
            ..rotated_missing_expiry.clone()
        };
        let merged_rot_exp = build_synced_token_record(&rotated_with_expiry, &existing_tok, now);
        assert_eq!(merged_rot_exp.access_token, "ya29.rotated_no_expiry");
        assert_eq!(merged_rot_exp.expiry_timestamp, 2_040_000_000);
        assert_eq!(merged_rot_exp.expires_in, 2_040_000_000 - now);

        // Empty stored AT with placeholder future expiry adopting a slot AT without expiry also
        // uses conservative `(1, 0)` instead of borrowing the placeholder future expiry.
        let mut empty_at_tok = existing_tok;
        empty_at_tok.access_token.clear();
        let slot_same_rt_no_exp = ExtractedSessionToken {
            access_token: Some("ya29.first_real_at".into()),
            expiry: None,
            expiry_unix: None,
            ..older_slot_with_jwt
        };
        let merged_from_empty = build_synced_token_record(&slot_same_rt_no_exp, &empty_at_tok, now);
        assert_eq!(merged_from_empty.access_token, "ya29.first_real_at");
        assert_eq!(merged_from_empty.expiry_timestamp, 1);
        assert_eq!(merged_from_empty.expires_in, 0);

        // 3. F-01 unit matrix: `select_sync_back_candidate` separates verified non-superseded RT
        //    rotation from AT expiry comparison symmetrically for both `file` and `keyring`,
        //    while disqualifying superseded historical RTs and preserving keyring preference on ties.
        let snap_f01 = repo.read_snapshot().unwrap();
        let make_ex = |rt: &str, at: &str, exp: Option<i64>| ExtractedSessionToken {
            access_token: Some(at.into()),
            refresh_token: rt.into(),
            expiry: exp.map(|_| "2099-01-01T00:00:00Z".into()),
            expiry_unix: exp,
            auth_method: Some("consumer".into()),
            id_token: None,
            id_token_email: Some("alice@example.com".into()),
            email_hint: Some("alice@example.com".into()),
            raw_digest: format!("dig-{rt}-{at}"),
            refresh_token_digest: crate::domain::token::token_digest(rt),
        };
        let kr_stored = make_ex("1//RT_ALICE_CURRENT", "ya29.current", Some(now + 7200));
        let file_rot_same_exp = make_ex("1//RT_ALICE_NEW_FILE", "ya29.current", Some(now + 7200));
        let chosen_f01 = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_stored.clone()),
            Some(file_rot_same_exp),
            Some("acc-0001"),
        )
        .unwrap();
        assert_eq!(chosen_f01.extracted.refresh_token, "1//RT_ALICE_NEW_FILE");
        assert!(chosen_f01.via_email_rotation);

        // Mirror: keyring rotated RT with MISSING expiry beats file holding stored RT + later expiry.
        let kr_rot_no_exp = make_ex("1//RT_ALICE_NEW_KR", "ya29.kr_new", None);
        let file_stored_later =
            make_ex("1//RT_ALICE_CURRENT", "ya29.file_later", Some(now + 99_999));
        let chosen_mirror = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_rot_no_exp),
            Some(file_stored_later),
            None,
        )
        .unwrap();
        assert_eq!(chosen_mirror.extracted.refresh_token, "1//RT_ALICE_NEW_KR");
        assert!(chosen_mirror.via_email_rotation);

        // Superseded historical RT in file is disqualified even if it carries a later expiry.
        let file_superseded = make_ex("1//RT_ALICE_OLD", "ya29.stale_later", Some(now + 999_999));
        let chosen_not_stale = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_stored),
            Some(file_superseded),
            Some("acc-0001"),
        )
        .unwrap();
        assert_eq!(
            chosen_not_stale.extracted.refresh_token,
            "1//RT_ALICE_CURRENT"
        );
        assert!(!chosen_not_stale.via_email_rotation);

        // P2 regression: when BOTH replicas carry the same stored RT AND the same fresher AT +
        // expiry (relative to the store), but ONLY the disk file additionally supplies a missing
        // `id_token`, metadata tie-breaking MUST pick the disk file so `id_token` is populated!
        let kr_fresher_no_id = make_ex(
            "1//RT_ALICE_CURRENT",
            "ya29.shared_fresher",
            Some(now + 88_888),
        );
        let mut file_fresher_with_id = kr_fresher_no_id.clone();
        file_fresher_with_id.id_token = Some("hdr.alice_payload.sig".into());
        let chosen_id = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_fresher_no_id.clone()),
            Some(file_fresher_with_id),
            None,
        )
        .unwrap();
        assert_eq!(
            chosen_id.extracted.id_token.as_deref(),
            Some("hdr.alice_payload.sig")
        );

        // Exact tie with identical metadata still ties back to keyring.
        let file_tie_same = make_ex(
            "1//RT_ALICE_CURRENT",
            "ya29.shared_fresher",
            Some(now + 88_888),
        );
        let mut kr_tie_marker = kr_fresher_no_id;
        kr_tie_marker.raw_digest = "kr-tie-marker".into();
        let chosen_tie = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_tie_marker),
            Some(file_tie_same),
            None,
        )
        .unwrap();
        assert_eq!(chosen_tie.extracted.raw_digest, "kr-tie-marker");
    }

    #[test]
    fn switch_atomically_updates_switched_in_and_out_timestamps_without_fabricating_on_external_drift(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let registry = OAuthClientRegistry::load(&paths).unwrap();
        let t0 = 1_900_000_000i64;

        let mk_acc = |id: &str, email: &str| {
            AccountRecord::new(
                id.into(),
                email.into(),
                TokenRecord {
                    access_token: format!("ya29.{id}"),
                    refresh_token: format!("1//rt-{id}"),
                    expires_in: 3600,
                    expiry_timestamp: t0 + 3600,
                    token_type: "Bearer".into(),
                    id_token: None,
                    oauth_client_key: None,
                    granted_scopes: None,
                    project_id: None,
                    is_gcp_tos: true,
                },
                t0,
            )
        };
        let acc_a = mk_acc("acc-0001", "alice@example.com");
        let acc_b = mk_acc("acc-0002", "bob@example.com");
        let acc_c = mk_acc("acc-0003", "charlie@example.com");
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, t0)?;
            tx.upsert_account(acc_b.clone(), false, t0)?;
            tx.upsert_account(acc_c.clone(), false, t0)?;
            Ok(())
        })
        .unwrap();

        let opts = SwitchOptions {
            dry_run: false,
            allow_running: true,
        };
        // 1. Initial switch into A from empty slot -> A gets last_switched_in_at = t1, no out_at.
        let t1 = t0 + 100;
        execute_switch(&repo, &FileSessionBackend, &registry, "acc-0001", &opts, t1).unwrap();
        let a1 = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(a1.last_switched_in_at, Some(t1));
        assert_eq!(a1.last_switched_out_at, None);
        assert_eq!(a1.last_used, t1);

        // 2. Idempotent re-switch into already-active A at t1+300 preserves last_switched_in_at = t1!
        execute_switch(
            &repo,
            &FileSessionBackend,
            &registry,
            "acc-0001",
            &opts,
            t1 + 300,
        )
        .unwrap();
        let a_same = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(a_same.last_switched_in_at, Some(t1));
        assert_eq!(a_same.last_switched_out_at, None);

        // 3. Switch A -> B at t2 = t1 + 2400 -> A gets last_switched_out_at = t2, B gets last_switched_in_at = t2.
        let t2 = t1 + 2400;
        execute_switch(&repo, &FileSessionBackend, &registry, "acc-0002", &opts, t2).unwrap();
        let a2 = repo.read_account_unchecked("acc-0001").unwrap();
        let b2 = repo.read_account_unchecked("acc-0002").unwrap();
        assert_eq!(a2.last_switched_in_at, Some(t1));
        assert_eq!(a2.last_switched_out_at, Some(t2));
        assert_eq!(a2.last_used, t2);
        assert_eq!(b2.last_switched_in_at, Some(t2));
        assert_eq!(b2.last_switched_out_at, None);
        assert_eq!(b2.last_used, t2);

        // 4. External drift overwrites slot with a foreign account, then switch into C at t3:
        //    B MUST NOT get a fabricated `last_switched_out_at`!
        let t3 = t2 + 7200;
        fs::write(
            &paths.active_slot_file,
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": "ya29.foreign",
                    "token_type": "Bearer",
                    "refresh_token": "1//rt-foreign",
                    "expiry": "2099-01-01T00:00:00Z"
                },
                "id_token_email": "stranger@example.com"
            }))
            .unwrap(),
        )
        .unwrap();
        execute_switch(&repo, &FileSessionBackend, &registry, "acc-0003", &opts, t3).unwrap();
        let b3 = repo.read_account_unchecked("acc-0002").unwrap();
        let c3 = repo.read_account_unchecked("acc-0003").unwrap();
        assert_eq!(b3.last_switched_out_at, None);
        assert_eq!(c3.last_switched_in_at, Some(t3));
        assert_eq!(c3.last_used, t3);
    }

    #[test]
    fn switch_re_switch_in_clears_stale_out_at_even_same_second_and_rollback_and_dual_outgoing_owner_guards_drift(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let registry = OAuthClientRegistry::load(&paths).unwrap();
        let t0 = 1_900_000_000i64;

        let mk_acc = |id: &str, email: &str, rt: &str| {
            AccountRecord::new(
                id.into(),
                email.into(),
                TokenRecord {
                    access_token: format!("ya29.{id}"),
                    refresh_token: rt.into(),
                    expires_in: 3600,
                    expiry_timestamp: t0 + 3600,
                    token_type: "Bearer".into(),
                    id_token: None,
                    oauth_client_key: None,
                    granted_scopes: None,
                    project_id: None,
                    is_gcp_tos: true,
                },
                t0,
            )
        };
        let mut acc_a = mk_acc("acc-0001", "alice@example.com", "1//rt-a-cur");
        acc_a.record_superseded_digest(&crate::domain::token::token_digest("1//rt-a-old"));
        let acc_b = mk_acc("acc-0002", "bob@example.com", "1//rt-b-cur");
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, t0)?;
            tx.upsert_account(acc_b.clone(), false, t0)?;
            Ok(())
        })
        .unwrap();

        let opts = SwitchOptions {
            dry_run: false,
            allow_running: true,
        };
        // 1. Switch A -> B at t2, then switch back B -> A at the EXACT SAME second `t2`:
        //    A must clear `last_switched_out_at = None`, set `last_switched_in_at = Some(t2)`,
        //    and preserve `Some(t2)` on subsequent idempotent re-switch into A!
        let t1 = t0 + 100;
        let t2 = t1 + 600;
        execute_switch(&repo, &FileSessionBackend, &registry, "acc-0001", &opts, t1).unwrap();
        execute_switch(&repo, &FileSessionBackend, &registry, "acc-0002", &opts, t2).unwrap();
        let a_out = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(a_out.last_switched_in_at, Some(t1));
        assert_eq!(a_out.last_switched_out_at, Some(t2));

        execute_switch(&repo, &FileSessionBackend, &registry, "acc-0001", &opts, t2).unwrap();
        let a_back_same_sec = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(a_back_same_sec.last_switched_in_at, Some(t2));
        assert_eq!(a_back_same_sec.last_switched_out_at, None);

        execute_switch(
            &repo,
            &FileSessionBackend,
            &registry,
            "acc-0001",
            &opts,
            t2 + 300,
        )
        .unwrap();
        let a_idem = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(a_idem.last_switched_in_at, Some(t2));
        assert_eq!(a_idem.last_switched_out_at, None);

        // 2. NTP clock rollback across switch-out (t3) then switch-back-in (t3 - 120 < t3):
        //    `last_switched_out_at` is cleared so subsequent idempotent re-switch keeps `t3 - 120`.
        let t3 = t2 + 1200;
        execute_switch(&repo, &FileSessionBackend, &registry, "acc-0002", &opts, t3).unwrap();
        let t_rollback = t3 - 120;
        execute_switch(
            &repo,
            &FileSessionBackend,
            &registry,
            "acc-0001",
            &opts,
            t_rollback,
        )
        .unwrap();
        let a_rb = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(a_rb.last_switched_in_at, Some(t_rollback));
        assert_eq!(a_rb.last_switched_out_at, None);

        execute_switch(
            &repo,
            &FileSessionBackend,
            &registry,
            "acc-0001",
            &opts,
            t_rollback + 45,
        )
        .unwrap();
        let a_rb_idem = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(a_rb_idem.last_switched_in_at, Some(t_rollback));
        assert_eq!(a_rb_idem.last_switched_out_at, None);

        // 3. `resolve_outgoing_slot_owner_from_pre_snap` unit matrix for `dual` backend:
        let snap = repo.read_snapshot().unwrap();
        let payload_json = |rt: &str, email: &str| {
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": format!("ya29.{rt}"),
                    "token_type": "Bearer",
                    "refresh_token": rt,
                    "expiry": "2099-01-01T00:00:00Z"
                },
                "id_token_email": email
            }))
            .unwrap()
        };
        let bytes_a_cur = payload_json("1//rt-a-cur", "alice@example.com");
        let bytes_a_old = payload_json("1//rt-a-old", "alice@example.com");
        let bytes_a_rot = payload_json("1//rt-a-rot-new", "alice@example.com");
        let bytes_b_cur = payload_json("1//rt-b-cur", "bob@example.com");
        let bytes_foreign = payload_json("1//rt-foreign", "stranger@example.com");
        let mk_dual =
            |kr: Option<Vec<u8>>, uniform: bool, file: Option<Vec<u8>>| BackendPreWriteSnapshot {
                backend_name: "dual",
                uses_keyring: true,
                uses_file: true,
                keyring_bytes: Some(kr),
                keyring_uniform: uniform,
                keyring_collections: Vec::new(),
                file_bytes: file,
            };

        // 3a. Foreign keyring + stale saved A on file -> MUST return None (never stamp A!).
        let foreign_kr = mk_dual(Some(bytes_foreign), true, Some(bytes_a_cur.clone()));
        assert_eq!(
            resolve_outgoing_slot_owner_from_pre_snap(&repo, &foreign_kr, &snap),
            None
        );

        // 3b. Corrupt keyring + stale saved A on file -> MUST return None.
        let corrupt_kr = mk_dual(
            Some(b"{not-valid-json".to_vec()),
            true,
            Some(bytes_a_cur.clone()),
        );
        assert_eq!(
            resolve_outgoing_slot_owner_from_pre_snap(&repo, &corrupt_kr, &snap),
            None
        );

        // 3c. Non-uniform keyring + saved A on file -> MUST return None.
        let non_uniform_kr = mk_dual(Some(bytes_a_cur.clone()), false, Some(bytes_a_cur.clone()));
        assert_eq!(
            resolve_outgoing_slot_owner_from_pre_snap(&repo, &non_uniform_kr, &snap),
            None
        );

        // 3d. F-01 single-sided disk rotation: superseded RT of A in keyring + current or newly
        //     rotated RT of A on file -> MUST resolve to `acc-0001`.
        let f01_cur_file = mk_dual(Some(bytes_a_old.clone()), true, Some(bytes_a_cur.clone()));
        assert_eq!(
            resolve_outgoing_slot_owner_from_pre_snap(&repo, &f01_cur_file, &snap).as_deref(),
            Some("acc-0001")
        );
        let f01_rot_file = mk_dual(Some(bytes_a_old), true, Some(bytes_a_rot));
        assert_eq!(
            resolve_outgoing_slot_owner_from_pre_snap(&repo, &f01_rot_file, &snap).as_deref(),
            Some("acc-0001")
        );

        // 3e. Cleanly absent keyring + saved A on file -> falls back to file (`acc-0001`).
        let absent_kr = mk_dual(None, true, Some(bytes_a_cur.clone()));
        assert_eq!(
            resolve_outgoing_slot_owner_from_pre_snap(&repo, &absent_kr, &snap).as_deref(),
            Some("acc-0001")
        );

        // 3f. Keyring holds saved B while file holds stale selected A -> keyring wins (`acc-0002`).
        let kr_b_file_a = mk_dual(Some(bytes_b_cur), true, Some(bytes_a_cur));
        assert_eq!(
            resolve_outgoing_slot_owner_from_pre_snap(&repo, &kr_b_file_a, &snap).as_deref(),
            Some("acc-0002")
        );

        // 3g. Diverged `dual` sync-back (`keyring = B` with fresher AT, `file = A (selected)` with
        //     fresher AT): `select_sync_back_candidate` prioritizes effective keyring `B`, AND
        //     `sync_back_pre_switch_snapshot` preserves BOTH `B`'s and `A`'s fresher ATs before
        //     both replicas are overwritten!
        let bytes_b_fresh = serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.b-fresher-kr",
                "token_type": "Bearer",
                "refresh_token": "1//rt-b-cur",
                "expiry": "2099-05-01T00:00:00Z"
            },
            "id_token_email": "bob@example.com"
        }))
        .unwrap();
        let bytes_a_fresh = serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.a-fresher-file",
                "token_type": "Bearer",
                "refresh_token": "1//rt-a-cur",
                "expiry": "2099-04-01T00:00:00Z"
            },
            "id_token_email": "alice@example.com"
        }))
        .unwrap();
        let kr_b_ex = extract_session_token_from_bytes(&bytes_b_fresh, "kr").unwrap();
        let file_a_ex = extract_session_token_from_bytes(&bytes_a_fresh, "file").unwrap();
        let picked =
            select_sync_back_candidate(&repo, &snap, Some(kr_b_ex), Some(file_a_ex), None).unwrap();
        assert_eq!(picked.owner.id, "acc-0002");

        let diverged_fresh = mk_dual(Some(bytes_b_fresh), true, Some(bytes_a_fresh));
        let sb_out =
            sync_back_pre_switch_snapshot(&repo, &diverged_fresh, &snap, t3 + 100).unwrap();
        assert_eq!(sb_out.synced_account_id.as_deref(), Some("acc-0002"));
        assert!(sb_out.token_updated);
        let a_synced = repo.read_account_unchecked("acc-0001").unwrap();
        let b_synced = repo.read_account_unchecked("acc-0002").unwrap();
        assert_eq!(b_synced.token.access_token, "ya29.b-fresher-kr");
        assert_eq!(a_synced.token.access_token, "ya29.a-fresher-file");
    }
}
