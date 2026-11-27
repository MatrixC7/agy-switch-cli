use crate::domain::account::{AccountRecord, DisableReasonCode, RuntimeState};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::domain::token::TokenRecord;
use crate::error::{CliError, CliResult, ExitCode};
use crate::oauth::refresh::persist_disable_or_report_io_error;
use crate::oauth::registry::OAuthClientRegistry;
use crate::session::backend::{
    BackendPreWriteSnapshot, BackendReplicaInspection, CredentialBackend, ReplicaCasExpectation,
    SlotInspectState,
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
    bytes_sha256_hex, extract_session_token_from_bytes, parse_session_payload_bytes,
    serialize_session_payload_for_account, ExtractedSessionToken, ParsedSessionPayload,
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

/// Expected pre-write state of a single credential replica (`keyring` or `file`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedReplicaState {
    Absent,
    Digest(String),
}

/// Verified per-replica slot checkpoint tracked by `daemon` across Stage 1 -> Stage 5 -> Stage 6
/// and handed directly into `execute_switch_with_slot_lock_and_guard` to validate EVERY active
/// replica in `pre_snap` (`file`, `keyring`, and `dual`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifiedSlotCheckpoint {
    pub keyring: Option<ExpectedReplicaState>,
    pub file: Option<ExpectedReplicaState>,
}

impl VerifiedSlotCheckpoint {
    /// Build a post-commit checkpoint covering all active replicas uniformly written with `target_digest`.
    pub fn from_committed_digest(uses_keyring: bool, uses_file: bool, target_digest: &str) -> Self {
        Self {
            keyring: uses_keyring.then(|| ExpectedReplicaState::Digest(target_digest.to_owned())),
            file: uses_file.then(|| ExpectedReplicaState::Digest(target_digest.to_owned())),
        }
    }

    /// Advance `self` from a post-probe per-replica verification result (`verified`).
    /// Fail-closed rules:
    /// - Updates an active replica ONLY when `verified` supplies a `Digest(new_d)` already proven
    ///   to belong to the expected active account (supporting legitimate single-sided rotations!).
    /// - NEVER overwrites a `Digest(_)` baseline with `Absent` (unexpected external deletion cancels).
    /// - NEVER overwrites a baseline when `verified` is `None` (foreign account, corrupt, or
    ///   unverified replica preserves prior baseline so the next write cancels cleanly!).
    pub fn advance_from_verified_probe(&mut self, verified: &VerifiedSlotCheckpoint) {
        if let Some(ExpectedReplicaState::Digest(ref new_d)) = verified.keyring {
            if self.keyring.is_some() {
                self.keyring = Some(ExpectedReplicaState::Digest(new_d.clone()));
            }
        }
        if let Some(ExpectedReplicaState::Digest(ref new_d)) = verified.file {
            if self.file.is_some() {
                self.file = Some(ExpectedReplicaState::Digest(new_d.clone()));
            }
        }
    }
}

/// Optional caller-approved per-replica pre-write slot baseline verified directly against the
/// EXACT `BackendPreWriteSnapshot` (`pre_snap`) used by `execute_switch_with_slot_lock_and_guard`
/// before any sync-back, journal write, or slot mutation.
/// - `None`: explicit manual `switch` / `run` (preserves manual switching over external slots).
/// - `ExactCheckpoint`: daemon hop or normal Stage 6 settle-back (every active replica must match).
/// - `CheckpointOrSameAccountRotation`: daemon Stage 6 settle-back after shutdown/timeout
///   interruption — every active replica must either match its exact baseline OR parse as a
///   verified payload belonging to `account_id`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PreSwitchSlotExpectation<'a> {
    ExactCheckpoint(&'a VerifiedSlotCheckpoint),
    CheckpointOrSameAccountRotation {
        expected: &'a VerifiedSlotCheckpoint,
        account_id: &'a str,
    },
}

pub(crate) fn parsed_slot_belongs_to_account(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    parsed: &ParsedSessionPayload,
    acc: &AccountRecord,
    allow_superseded_own_rt: bool,
) -> bool {
    if acc.token.refresh_token_fingerprint() == parsed.refresh_token_digest {
        return true;
    }
    if slot_matches_selected_rotated_account(repo, snapshot, parsed, acc) {
        return true;
    }
    allow_superseded_own_rt
        && account_has_superseded_rt_digest_readonly(repo, acc, &parsed.refresh_token_digest)
            .unwrap_or(false)
}

/// Extract a full per-replica baseline from Stage 1's `BackendReplicaInspection` for `account_id`.
/// Returns `None` if keyring collections diverged, any active replica is corrupt/unverified or
/// belongs to another/foreign account, or all active replicas are absent.
pub(crate) fn extract_verified_checkpoint_from_replicas(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    replicas: &BackendReplicaInspection,
    account_id: &str,
    allow_superseded_non_effective: bool,
) -> Option<VerifiedSlotCheckpoint> {
    if !replicas.uses_keyring && !replicas.uses_file {
        return None;
    }
    if replicas.uses_keyring && !replicas.keyring_all_collections_uniform {
        return None;
    }
    let acc = snapshot.accounts.iter().find(|a| a.id == account_id)?;
    let effective_is_keyring = replicas.uses_keyring
        && !replicas
            .keyring
            .as_ref()
            .is_none_or(SlotInspectState::is_absent_clean);

    let keyring = if replicas.uses_keyring {
        match replicas.keyring.as_ref()? {
            SlotInspectState::Present(p)
                if parsed_slot_belongs_to_account(
                    repo,
                    snapshot,
                    p,
                    acc,
                    allow_superseded_non_effective && !effective_is_keyring,
                ) =>
            {
                Some(ExpectedReplicaState::Digest(p.raw_digest.clone()))
            }
            s if s.is_absent_clean() => Some(ExpectedReplicaState::Absent),
            _ => return None,
        }
    } else {
        None
    };

    let file = if replicas.uses_file {
        match &replicas.file {
            SlotInspectState::Present(p)
                if parsed_slot_belongs_to_account(
                    repo,
                    snapshot,
                    p,
                    acc,
                    allow_superseded_non_effective && effective_is_keyring,
                ) =>
            {
                Some(ExpectedReplicaState::Digest(p.raw_digest.clone()))
            }
            s if s.is_absent_clean() => Some(ExpectedReplicaState::Absent),
            _ => return None,
        }
    } else {
        None
    };

    let has_any_present = matches!(keyring, Some(ExpectedReplicaState::Digest(_)))
        || matches!(file, Some(ExpectedReplicaState::Digest(_)));
    if !has_any_present {
        return None;
    }
    Some(VerifiedSlotCheckpoint { keyring, file })
}

/// Extract per-replica verified digests after a `/usage` probe for `account_id`.
/// Each active replica is evaluated independently with `allow_superseded = false`:
/// - Verified same-account payloads yield `Some(ExpectedReplicaState::Digest(_))` so legitimate
///   single-sided rotations advance that replica's checkpoint;
/// - Any foreign, corrupt, unverified, superseded, or absent replica yields `None`, preserving
///   the caller's prior baseline for that replica so subsequent daemon writes cancel cleanly.
pub(crate) fn verified_probe_checkpoint_from_replicas(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    replicas: &BackendReplicaInspection,
    account_id: &str,
) -> VerifiedSlotCheckpoint {
    let Some(acc) = snapshot.accounts.iter().find(|a| a.id == account_id) else {
        return VerifiedSlotCheckpoint::default();
    };
    let keyring = if replicas.uses_keyring && replicas.keyring_all_collections_uniform {
        match replicas.keyring.as_ref() {
            Some(SlotInspectState::Present(p))
                if parsed_slot_belongs_to_account(repo, snapshot, p, acc, false) =>
            {
                Some(ExpectedReplicaState::Digest(p.raw_digest.clone()))
            }
            _ => None,
        }
    } else {
        None
    };
    let file = if replicas.uses_file {
        match &replicas.file {
            SlotInspectState::Present(p)
                if parsed_slot_belongs_to_account(repo, snapshot, p, acc, false) =>
            {
                Some(ExpectedReplicaState::Digest(p.raw_digest.clone()))
            }
            _ => None,
        }
    } else {
        None
    };
    VerifiedSlotCheckpoint { keyring, file }
}

fn single_replica_state_matches_expectation(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    state: &SlotInspectState,
    expected: &ExpectedReplicaState,
    rotation_account_id: Option<&str>,
) -> bool {
    let exact_ok = match expected {
        ExpectedReplicaState::Absent => state.is_absent_clean(),
        ExpectedReplicaState::Digest(exp_d) => state.raw_digest() == Some(exp_d.as_str()),
    };
    if exact_ok {
        return true;
    }
    let Some(acc_id) = rotation_account_id else {
        return false;
    };
    let (SlotInspectState::Present(parsed), Some(acc)) =
        (state, snapshot.accounts.iter().find(|a| a.id == acc_id))
    else {
        return false;
    };
    parsed_slot_belongs_to_account(repo, snapshot, parsed, acc, false)
}

pub(crate) fn replica_inspection_matches_expectation(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    replicas: &BackendReplicaInspection,
    expectation: PreSwitchSlotExpectation<'_>,
) -> bool {
    if !replicas.uses_keyring && !replicas.uses_file {
        return false;
    }
    if replicas.uses_keyring && !replicas.keyring_all_collections_uniform {
        return false;
    }
    let (expected, rot_acc_id) = match expectation {
        PreSwitchSlotExpectation::ExactCheckpoint(cp) => (cp, None),
        PreSwitchSlotExpectation::CheckpointOrSameAccountRotation {
            expected,
            account_id,
        } => (expected, Some(account_id)),
    };
    if replicas.uses_keyring {
        let (Some(ref kr_state), Some(ref exp_kr)) = (&replicas.keyring, &expected.keyring) else {
            return false;
        };
        if !single_replica_state_matches_expectation(repo, snapshot, kr_state, exp_kr, rot_acc_id) {
            return false;
        }
    }
    if replicas.uses_file {
        let Some(ref exp_file) = expected.file else {
            return false;
        };
        if !single_replica_state_matches_expectation(
            repo,
            snapshot,
            &replicas.file,
            exp_file,
            rot_acc_id,
        ) {
            return false;
        }
    }
    true
}

fn single_replica_bytes_match_expectation(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    bytes: Option<&[u8]>,
    expected: &ExpectedReplicaState,
    rotation_account_id: Option<&str>,
) -> bool {
    let exact_ok = match (expected, bytes) {
        (ExpectedReplicaState::Absent, None) => true,
        (ExpectedReplicaState::Digest(exp_d), Some(raw)) => bytes_sha256_hex(raw) == *exp_d,
        _ => false,
    };
    if exact_ok {
        return true;
    }
    let (Some(acc_id), Some(raw)) = (rotation_account_id, bytes) else {
        return false;
    };
    let (Ok(parsed), Some(acc)) = (
        parse_session_payload_bytes(raw),
        snapshot.accounts.iter().find(|a| a.id == acc_id),
    ) else {
        return false;
    };
    parsed_slot_belongs_to_account(repo, snapshot, &parsed, acc, false)
}

fn pre_write_snapshot_matches_expectation(
    repo: &StoreRepository,
    snapshot: &StoreSnapshot,
    pre_snap: &BackendPreWriteSnapshot,
    expectation: PreSwitchSlotExpectation<'_>,
) -> bool {
    if !pre_snap.uses_keyring && !pre_snap.uses_file {
        return false;
    }
    if pre_snap.uses_keyring && !pre_snap.keyring_uniform {
        return false;
    }
    let (expected, rot_acc_id) = match expectation {
        PreSwitchSlotExpectation::ExactCheckpoint(cp) => (cp, None),
        PreSwitchSlotExpectation::CheckpointOrSameAccountRotation {
            expected,
            account_id,
        } => (expected, Some(account_id)),
    };
    if pre_snap.uses_keyring {
        let Some(ref exp_kr) = expected.keyring else {
            return false;
        };
        let kr_bytes = pre_snap.keyring_bytes.as_ref().and_then(|o| o.as_deref());
        if !single_replica_bytes_match_expectation(repo, snapshot, kr_bytes, exp_kr, rot_acc_id) {
            return false;
        }
    }
    if pre_snap.uses_file {
        let Some(ref exp_file) = expected.file else {
            return false;
        };
        let file_bytes = pre_snap.file_bytes.as_deref();
        if !single_replica_bytes_match_expectation(repo, snapshot, file_bytes, exp_file, rot_acc_id)
        {
            return false;
        }
    }
    true
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
    /// Verified per-replica checkpoint uniformly committed by this switch (omitted from JSON wire DTO).
    #[serde(skip_serializing)]
    pub committed_checkpoint: Option<VerifiedSlotCheckpoint>,
}

pub(crate) fn format_validation_blocked_warning(target_id: &str) -> String {
    format!(
        "Note: account `{target_id}` is currently marked verification-required (`verify-blocked`) and remains excluded from daemon auto-switching. Open `agy` to complete Google verification, then run `agy-switch-cli refresh` (or `agy-switch-cli quota --refresh`) to clear this status."
    )
}

#[derive(Debug, Clone, Default)]
pub struct SlotSyncBackOutcome {
    pub synced_account_id: Option<String>,
    pub token_updated: bool,
    pub refresh_token_rotated: bool,
    pub discovered_user_tier: Option<String>,
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
    selected_account_id: Option<&str>,
) -> bool {
    if kr.owner.id != file.owner.id {
        // Diverged replicas pointing to two different saved accounts (only reachable during
        // explicit manual switch): prefer the selected account, tie-breaking to keyring.
        return selected_account_id == Some(file.owner.id.as_str())
            && selected_account_id != Some(kr.owner.id.as_str());
    }

    // Same owning account across keyring and disk file (`dual`):
    // 1. Separate verified non-superseded RT rotation from AT expiry comparison so a single-sided
    //    rotated RT is NEVER discarded just because AT expiry stayed equal, moved earlier, or was
    //    omitted (symmetric for both file-only and keyring-only rotations).
    if file.via_email_rotation != kr.via_email_rotation {
        return file.via_email_rotation;
    }

    // 2. Both replicas hold the stored RT (or both hold verified rotated RTs):
    //    prefer strictly fresher AT expiry, then fresher AT, then metadata update (`id_token` /
    //    `user_tier`), preserving keyring preference on ties.
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

    let kr_updates_tier = slot_tier_updates_account(kr.extracted.user_tier.as_deref(), kr.owner);
    let file_updates_tier =
        slot_tier_updates_account(file.extracted.user_tier.as_deref(), file.owner);
    if file_updates_tier != kr_updates_tier {
        return file_updates_tier;
    }

    false
}

fn select_sync_back_candidate<'a>(
    repo: &StoreRepository,
    snapshot: &'a StoreSnapshot,
    kr_extracted: Option<ExtractedSessionToken>,
    file_extracted: Option<ExtractedSessionToken>,
    pinned_owner_id: Option<&str>,
) -> Option<(ResolvedSyncBackCandidate<'a>, Option<String>)> {
    let kr_cand = kr_extracted
        .and_then(|ex| resolve_sync_back_candidate(repo, snapshot, ex, pinned_owner_id));
    let file_cand = file_extracted
        .and_then(|ex| resolve_sync_back_candidate(repo, snapshot, ex, pinned_owner_id));

    match (kr_cand, file_cand) {
        (Some(kr), Some(file)) => {
            let same_owner = kr.owner.id == file.owner.id;
            let pick_file = prefer_file_sync_back_candidate(
                &kr,
                &file,
                snapshot.index.selected_account_id.as_deref(),
            );
            let (chosen, other_tier) = if pick_file {
                (file, same_owner.then_some(kr.extracted.user_tier).flatten())
            } else {
                (kr, same_owner.then_some(file.extracted.user_tier).flatten())
            };
            let discovered_tier = chosen.extracted.user_tier.clone().or(other_tier);
            Some((chosen, discovered_tier))
        }
        (Some(kr), None) => {
            let tier = kr.extracted.user_tier.clone();
            Some((kr, tier))
        }
        (None, Some(file)) => {
            let tier = file.extracted.user_tier.clone();
            Some((file, tier))
        }
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

fn slot_tier_updates_account(user_tier: Option<&str>, account: &AccountRecord) -> bool {
    account.needs_official_cli_user_tier_update(user_tier)
}

fn apply_synced_user_tier(account: &mut AccountRecord, user_tier: Option<&str>) -> bool {
    account.apply_official_cli_user_tier(user_tier)
}

fn sync_back_extracted_for_owner(
    repo: &StoreRepository,
    owner_id: &str,
    via_email_rotation_match: bool,
    extracted: &ExtractedSessionToken,
    now_unix: i64,
) -> CliResult<SlotSyncBackOutcome> {
    let discovered_user_tier = extracted.user_tier.clone();
    let owner_snapshot = match repo.read_account_unchecked(owner_id) {
        Ok(a) => a,
        Err(_) => {
            return Ok(SlotSyncBackOutcome::default());
        }
    };
    let (needs_token_update, _) = slot_token_updates_account(extracted, &owner_snapshot);
    let needs_tier_update =
        slot_tier_updates_account(discovered_user_tier.as_deref(), &owner_snapshot);
    if !needs_token_update && !needs_tier_update {
        return Ok(SlotSyncBackOutcome {
            synced_account_id: Some(owner_id.to_string()),
            token_updated: false,
            refresh_token_rotated: false,
            discovered_user_tier,
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
        let still_needs_tier = slot_tier_updates_account(discovered_user_tier.as_deref(), &latest);
        if !still_needs_token && !still_needs_tier {
            return Ok((true, false, false));
        }
        let mut updated_acc = if still_needs_token {
            let merged = build_synced_token_record(extracted, &latest.token, now_unix);
            tx.merge_refreshed_token(owner_id, merged, None, now_unix)?
        } else {
            latest
        };
        if apply_synced_user_tier(&mut updated_acc, discovered_user_tier.as_deref()) {
            tx.save_account(&updated_acc)?;
        }
        Ok((true, still_needs_token, rt_rotated))
    })?;

    if !accepted {
        return Ok(SlotSyncBackOutcome::default());
    }

    Ok(SlotSyncBackOutcome {
        synced_account_id: Some(owner_id.to_string()),
        token_updated,
        refresh_token_rotated,
        discovered_user_tier,
    })
}

/// Pre-switch pure-local sync-back under `L1`:
/// Inspects ALL managed pre-switch active replicas (`keyring` and/or `file`) and merges any
/// verified non-superseded rotated `refresh_token` or fresher `access_token` back into the owning
/// account under `L3` before switching out.
pub(crate) fn sync_back_pre_switch_snapshot(
    repo: &StoreRepository,
    pre_snap: &BackendPreWriteSnapshot,
    snapshot: &StoreSnapshot,
    now_unix: i64,
) -> CliResult<SlotSyncBackOutcome> {
    let (kr_extracted, file_extracted) = extract_replica_tokens_from_pre_snap(pre_snap);
    let Some((chosen, discovered_tier)) =
        select_sync_back_candidate(repo, snapshot, kr_extracted, file_extracted, None)
    else {
        return Ok(SlotSyncBackOutcome::default());
    };
    let mut outcome = sync_back_extracted_for_owner(
        repo,
        &chosen.owner.id,
        chosen.via_email_rotation,
        &chosen.extracted,
        now_unix,
    )?;
    if outcome.synced_account_id.is_some() && outcome.discovered_user_tier.is_none() {
        outcome.discovered_user_tier = discovered_tier;
    }
    Ok(outcome)
}

/// Post-`/usage` pure-local sync-back for a known active account:
/// Independently inspects ALL replicas managed by `backend` (`keyring` and/or `file`, never
/// touching disk in `keyring`-only mode or D-Bus in `file`-only mode), selects any verified
/// non-superseded rotated `refresh_token` or fresher `access_token` belonging to `account_id`,
/// merges it back into `accounts/<account_id>.json`, and returns any discovered `user_tier`.
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
    let Some((chosen, discovered_tier)) = select_sync_back_candidate(
        repo,
        &snapshot,
        kr_extracted,
        file_extracted,
        Some(account_id),
    ) else {
        return Ok(SlotSyncBackOutcome::default());
    };
    let mut outcome = sync_back_extracted_for_owner(
        repo,
        &chosen.owner.id,
        chosen.via_email_rotation,
        &chosen.extracted,
        now_unix,
    )?;
    if outcome.synced_account_id.is_some() && outcome.discovered_user_tier.is_none() {
        outcome.discovered_user_tier = discovered_tier;
    }
    Ok(outcome)
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
        committed_checkpoint: None,
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
        &slot_lock, repo, backend, registry, selector, guard_mode, true, true, None, now_unix,
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
        None,
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
    expected_pre_slot: Option<PreSwitchSlotExpectation<'_>>,
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

    // R2-01: When invoked by `daemon`, bind the caller's approved pre-write expectation directly
    // to THIS EXACT `pre_snap` BEFORE any sync-back, journal preparation, or slot mutation so an
    // external `agy login` slipping between daemon inspection and `pre_snap` cancels cleanly.
    if let Some(expectation) = expected_pre_slot {
        if !pre_write_snapshot_matches_expectation(repo, &snapshot, &pre_snap, expectation) {
            return Err(CliError::conflict(
                "active_slot_digest_changed",
                "Active agy credential slot changed externally before switch preparation; daemon plan cancelled without overwriting the slot.",
            ));
        }
    }

    // Pre-Switch Sync-Back (Option 1B): purely locally merge any fresher `access_token` or rotated
    // `refresh_token` from the outgoing active slot back into `accounts/<A>.json` under `L3`
    // BEFORE overwriting the active slot with target account B!
    let _sync_back = sync_back_pre_switch_snapshot(repo, &pre_snap, &snapshot, clock.now_unix())?;

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
        committed_checkpoint: Some(VerifiedSlotCheckpoint::from_committed_digest(
            pre_snap.uses_keyring,
            pre_snap.uses_file,
            &target_digest,
        )),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::quota::{
        evaluate_account_quota, QuotaBucket, QuotaEval, QuotaGroup, QuotaObservation,
        QuotaSourceEnv, DEFAULT_QUOTA_MAX_AGE_SECS,
    };
    use crate::paths::HeadlessPaths;
    use crate::session::backend::FileSessionBackend;
    use std::fs;

    #[test]
    fn sync_back_rejects_superseded_rt_without_leaking_user_tier_and_tags_synced_tier_for_upgrade()
    {
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
        // Seed as upgraded v1.2.6 Production observation without subscription_tier yet.
        let prod_no_tier = QuotaObservation::new(now - 600, QuotaSourceEnv::Production);
        acc.quota = Some(prod_no_tier);

        repo.with_write_lock(|tx| {
            tx.upsert_account(acc.clone(), true, now)?;
            Ok(())
        })
        .unwrap();

        // 1. Slot rolled back to superseded RT carrying `user_tier: "FREE"`: MUST be rejected
        //    with empty outcome (zero `discovered_user_tier` leak, zero mutation on disk).
        fs::write(
            &paths.active_slot_file,
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": "ya29.stale",
                    "token_type": "Bearer",
                    "refresh_token": "1//RT_ALICE_OLD",
                    "expiry": "2099-01-01T00:00:00Z"
                },
                "id_token_email": "alice@example.com",
                "user_tier": "FREE"
            }))
            .unwrap(),
        )
        .unwrap();
        let rejected =
            sync_back_active_slot_for_account(&repo, &FileSessionBackend, "acc-0001", now + 5)
                .unwrap();
        assert_eq!(rejected.synced_account_id, None);
        assert!(!rejected.token_updated);
        assert_eq!(rejected.discovered_user_tier, None);
        let after_rej = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(after_rej.token.refresh_token, "1//RT_ALICE_CURRENT");
        assert_eq!(
            after_rej
                .quota
                .as_ref()
                .and_then(|q| q.subscription_tier.as_deref()),
            None
        );

        // 2. Legitimate active slot carrying `user_tier: "FREE"` synced onto upgraded Production
        //    observation with `subscription_tier == None` MUST tag `tier_source_env = OfficialCli`
        //    so a subsequent OfficialCli weekly-only `update_quota` preserves FREE and evaluates Known!
        fs::write(
            &paths.active_slot_file,
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": "ya29.current",
                    "token_type": "Bearer",
                    "refresh_token": "1//RT_ALICE_CURRENT",
                    "expiry": "2099-01-01T00:00:00Z"
                },
                "id_token_email": "alice@example.com",
                "user_tier": "FREE"
            }))
            .unwrap(),
        )
        .unwrap();
        let synced =
            sync_back_active_slot_for_account(&repo, &FileSessionBackend, "acc-0001", now + 10)
                .unwrap();
        assert_eq!(synced.synced_account_id.as_deref(), Some("acc-0001"));
        assert_eq!(synced.discovered_user_tier.as_deref(), Some("FREE"));
        let mut after_sync = repo.read_account_unchecked("acc-0001").unwrap();
        assert_eq!(
            after_sync
                .quota
                .as_ref()
                .and_then(|q| q.subscription_tier.as_deref()),
            Some("FREE")
        );
        assert_eq!(
            after_sync.quota.as_ref().and_then(|q| q.tier_source_env),
            Some(QuotaSourceEnv::OfficialCli)
        );

        let mut weekly_only = QuotaObservation::new(now + 20, QuotaSourceEnv::OfficialCli);
        weekly_only.quota_groups = Some(vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: None,
            buckets: vec![QuotaBucket {
                bucket_id: "gemini-weekly".into(),
                window: "weekly".into(),
                remaining_fraction: 0.77,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-07T00:00:00Z".into(),
                display_name: None,
                description: None,
            }],
        }]);
        after_sync.update_quota(weekly_only);
        assert_eq!(
            after_sync
                .quota
                .as_ref()
                .and_then(|q| q.subscription_tier.as_deref()),
            Some("FREE")
        );
        assert_eq!(
            evaluate_account_quota(&after_sync, "gemini", now + 20, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 77.0
            }
        );

        // 3. S3 regression: same RT + fresher stored AT/expiry (`2050000000`) + older slot AT/expiry
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
            user_tier: None,
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

        // 3b. R2-02 regression: rotated RT with non-empty new AT and MISSING `expiry` MUST NOT
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
        let mut empty_at_tok = existing_tok.clone();
        empty_at_tok.access_token.clear();
        let slot_same_rt_no_exp = ExtractedSessionToken {
            access_token: Some("ya29.first_real_at".into()),
            expiry: None,
            expiry_unix: None,
            ..older_slot_with_jwt.clone()
        };
        let merged_from_empty = build_synced_token_record(&slot_same_rt_no_exp, &empty_at_tok, now);
        assert_eq!(merged_from_empty.access_token, "ya29.first_real_at");
        assert_eq!(merged_from_empty.expiry_timestamp, 1);
        assert_eq!(merged_from_empty.expires_in, 0);

        // 4. S5 regression: existing v1.2.6 Production `FREE` tier overridden to `PRO` by explicit
        //    official slot `user_tier` WITHOUT disguising `source_env` or `last_updated`!
        let mut prod_free =
            AccountRecord::new("acc-s5".into(), "s5@example.com".into(), existing_tok, now);
        let mut old_prod_q = QuotaObservation::new(1_700_123_456, QuotaSourceEnv::Production);
        old_prod_q.subscription_tier = Some("FREE".into());
        old_prod_q.tier_source_env = Some(QuotaSourceEnv::Production);
        prod_free.quota = Some(old_prod_q);
        assert!(slot_tier_updates_account(Some("PRO"), &prod_free));
        assert!(apply_synced_user_tier(&mut prod_free, Some("PRO")));
        let q_after = prod_free.quota.as_ref().unwrap();
        assert_eq!(q_after.subscription_tier.as_deref(), Some("PRO"));
        assert_eq!(q_after.tier_source_env, Some(QuotaSourceEnv::OfficialCli));
        assert_eq!(q_after.source_env, QuotaSourceEnv::Production);
        assert_eq!(q_after.last_updated, 1_700_123_456);
        assert!(!slot_tier_updates_account(Some("PRO"), &prod_free));

        // 5. F-01 unit matrix: `select_sync_back_candidate` separates verified non-superseded RT
        //    rotation from AT expiry comparison symmetrically for both `file` and `keyring`,
        //    while disqualifying superseded historical RTs and preserving keyring preference on ties.
        let snap_f01 = repo.read_snapshot().unwrap();
        let make_ex =
            |rt: &str, at: &str, exp: Option<i64>, tier: Option<&str>| ExtractedSessionToken {
                access_token: Some(at.into()),
                refresh_token: rt.into(),
                expiry: exp.map(|_| "2099-01-01T00:00:00Z".into()),
                expiry_unix: exp,
                auth_method: Some("consumer".into()),
                id_token: None,
                id_token_email: Some("alice@example.com".into()),
                email_hint: Some("alice@example.com".into()),
                user_tier: tier.map(str::to_owned),
                raw_digest: format!("dig-{rt}-{at}"),
                refresh_token_digest: crate::domain::token::token_digest(rt),
            };
        let kr_stored = make_ex(
            "1//RT_ALICE_CURRENT",
            "ya29.current",
            Some(now + 7200),
            Some("PRO"),
        );
        let file_rot_same_exp = make_ex(
            "1//RT_ALICE_NEW_FILE",
            "ya29.current",
            Some(now + 7200),
            None,
        );
        let (chosen_f01, tier_f01) = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_stored.clone()),
            Some(file_rot_same_exp),
            Some("acc-0001"),
        )
        .unwrap();
        assert_eq!(chosen_f01.extracted.refresh_token, "1//RT_ALICE_NEW_FILE");
        assert!(chosen_f01.via_email_rotation);
        assert_eq!(tier_f01.as_deref(), Some("PRO"));

        // Mirror: keyring rotated RT with MISSING expiry beats file holding stored RT + later expiry.
        let kr_rot_no_exp = make_ex("1//RT_ALICE_NEW_KR", "ya29.kr_new", None, None);
        let file_stored_later = make_ex(
            "1//RT_ALICE_CURRENT",
            "ya29.file_later",
            Some(now + 99_999),
            None,
        );
        let (chosen_mirror, _) = select_sync_back_candidate(
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
        let file_superseded = make_ex(
            "1//RT_ALICE_OLD",
            "ya29.stale_later",
            Some(now + 999_999),
            Some("FREE"),
        );
        let (chosen_not_stale, tier_not_stale) = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_stored.clone()),
            Some(file_superseded),
            Some("acc-0001"),
        )
        .unwrap();
        assert_eq!(
            chosen_not_stale.extracted.refresh_token,
            "1//RT_ALICE_CURRENT"
        );
        assert!(!chosen_not_stale.via_email_rotation);
        assert_eq!(tier_not_stale.as_deref(), Some("PRO"));

        // Exact tie with same stored RT preserves keyring preference (not unconditionally file).
        let file_tie = make_ex(
            "1//RT_ALICE_CURRENT",
            "ya29.current",
            Some(now + 7200),
            Some("FREE"),
        );
        let (chosen_tie, _) =
            select_sync_back_candidate(&repo, &snap_f01, Some(kr_stored), Some(file_tie), None)
                .unwrap();
        assert_eq!(chosen_tie.extracted.user_tier.as_deref(), Some("PRO"));

        // P2 regression: when BOTH replicas carry the same stored RT AND the same fresher AT +
        // expiry (relative to the store), but ONLY the disk file additionally supplies a missing
        // `id_token`, metadata tie-breaking MUST pick the disk file so `id_token` is populated!
        let kr_fresher_no_id = make_ex(
            "1//RT_ALICE_CURRENT",
            "ya29.shared_fresher",
            Some(now + 88_888),
            None,
        );
        let mut file_fresher_with_id = kr_fresher_no_id.clone();
        file_fresher_with_id.id_token = Some("hdr.alice_payload.sig".into());
        let (chosen_id, _) = select_sync_back_candidate(
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

        // Likewise when both carry the same fresher AT + expiry without `id_token`, a disk-only
        // `user_tier` update breaks the tie cleanly; identical metadata still ties back to keyring.
        let file_fresher_with_tier = make_ex(
            "1//RT_ALICE_CURRENT",
            "ya29.shared_fresher",
            Some(now + 88_888),
            Some("PRO"),
        );
        let (chosen_tier, _) = select_sync_back_candidate(
            &repo,
            &snap_f01,
            Some(kr_fresher_no_id),
            Some(file_fresher_with_tier),
            None,
        )
        .unwrap();
        assert_eq!(chosen_tier.extracted.user_tier.as_deref(), Some("PRO"));
    }
}
