use crate::domain::account::STORE_SCHEMA_VERSION;
use crate::error::{format_safe_json_error, CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::session::backend::{
    BackendPreWriteSnapshot, BackendReplicaInspection, CredentialBackend, FileSessionBackend,
    KeyringCollectionDigest, ReplicaCasExpectation, SlotInspectState,
};
use crate::session::payload::{
    bytes_sha256_hex, parse_session_payload_bytes, serialize_session_payload_for_account,
};
use crate::store::fs_atomic::{
    check_fault_injection, confirm_dir_entries_durable_under,
    confirm_file_absent_and_parent_durable_under, ensure_no_symlink_components_under,
    read_regular_file_opt_bounded, remove_regular_file_durable_under,
    restore_regular_file_if_absent_under, write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use crate::store::locks::ActiveSlotLock;
use crate::store::repository::StoreRepository;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

fn default_true() -> bool {
    true
}

/// Per-collection SHA-256 digest metadata recorded in `switch_journal.json` (contains ZERO plaintext tokens).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalCollectionSnapshot {
    pub path: String,
    pub prev_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_digest: Option<String>,
}

/// Per-replica absence and SHA-256 digest record stored in `switch_journal.json` (contains ZERO plaintext tokens).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalReplicaSnapshot {
    pub prev_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_digest: Option<String>,
    #[serde(default = "default_true")]
    pub prev_uniform: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collections: Vec<JournalCollectionSnapshot>,
}

/// Multi-replica transaction metadata persisted alongside `SwitchJournal` in `switch_journal.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalReplicaRecord {
    pub backend: String,
    #[serde(default = "default_true")]
    pub uses_file: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring: Option<JournalReplicaSnapshot>,
    pub file: JournalReplicaSnapshot,
}

impl JournalReplicaRecord {
    pub fn needs_keyring(&self) -> bool {
        matches!(
            self.backend.as_str(),
            "dual" | "keyring" | "secret_service_dual"
        ) || self.keyring.is_some()
    }

    pub fn needs_file(&self) -> bool {
        self.backend != "keyring" && self.uses_file
    }

    pub fn from_pre_write_snapshot(snap: &BackendPreWriteSnapshot) -> Self {
        let keyring = if snap.uses_keyring {
            let kr_dig = snap.keyring_digest();
            let collections = snap
                .keyring_collection_digests()
                .into_iter()
                .map(|c| JournalCollectionSnapshot {
                    path: c.path,
                    prev_present: c.present,
                    prev_digest: c.digest,
                })
                .collect();
            Some(JournalReplicaSnapshot {
                prev_present: kr_dig.is_some(),
                prev_digest: kr_dig,
                prev_uniform: snap.keyring_uniform,
                collections,
            })
        } else {
            None
        };
        let file_dig = snap.file_digest();
        Self {
            backend: snap.backend_name.to_string(),
            uses_file: snap.uses_file,
            keyring,
            file: JournalReplicaSnapshot {
                prev_present: snap.uses_file && file_dig.is_some(),
                prev_digest: file_dig,
                prev_uniform: true,
                collections: Vec::new(),
            },
        }
    }
}

/// Validate internal structural consistency and completeness of recorded `replica_state` metadata.
/// Incomplete or contradictory metadata MUST fail closed (`RecoveryIncomplete`, exit 7) rather than
/// allowing partial-scope or unsupervised journal cleanup.
pub fn validate_replica_meta_completeness(meta: &JournalReplicaRecord) -> Result<(), String> {
    let valid_backend = match meta.backend.as_str() {
        "file" | "file_session" => meta.uses_file && meta.keyring.is_none(),
        "keyring" => !meta.uses_file && meta.keyring.is_some(),
        "dual" | "secret_service_dual" => meta.uses_file && meta.keyring.is_some(),
        _ => false,
    };
    if !valid_backend {
        return Err(format!(
            "Switch journal has invalid or inconsistent replica backend metadata (`{}`).",
            meta.backend
        ));
    }

    if !meta.file.collections.is_empty() {
        return Err(
            "Switch journal file replica metadata must not contain keyring collections.".into(),
        );
    }

    if meta.needs_file() {
        if !meta.file.prev_uniform {
            return Err(
                "Switch journal file replica metadata cannot report `prev_uniform=false`.".into(),
            );
        }
        let has_non_empty_dig = meta
            .file
            .prev_digest
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        if meta.file.prev_present != has_non_empty_dig
            || (!meta.file.prev_present && meta.file.prev_digest.is_some())
        {
            return Err(
                "Switch journal file replica metadata has inconsistent presence/digest fields."
                    .into(),
            );
        }
    } else if meta.file.prev_present || meta.file.prev_digest.is_some() {
        return Err(
            "Switch journal keyring-only replica metadata has unexpected file presence/digest fields."
                .into(),
        );
    }

    if meta.needs_keyring() {
        let Some(ref kr) = meta.keyring else {
            return Err("Switch journal keyring backend lacks keyring replica metadata.".into());
        };
        if kr.collections.is_empty() {
            return Err(
                "Switch journal keyring replica metadata has empty collection list.".into(),
            );
        }
        let mut seen_paths = BTreeSet::new();
        let mut any_col_present = false;
        let mut any_col_absent = false;
        let mut present_digests: BTreeSet<&str> = BTreeSet::new();
        for c in &kr.collections {
            if c.path.is_empty() || !seen_paths.insert(c.path.as_str()) {
                return Err(
                    "Switch journal keyring collection list contains empty or duplicate paths."
                        .into(),
                );
            }
            let has_non_empty_dig = c.prev_digest.as_deref().is_some_and(|s| !s.is_empty());
            if c.prev_present != has_non_empty_dig || (!c.prev_present && c.prev_digest.is_some()) {
                return Err(
                    "Switch journal keyring collection metadata has inconsistent presence/digest fields."
                        .into(),
                );
            }
            if c.prev_present {
                any_col_present = true;
                if let Some(d) = c.prev_digest.as_deref() {
                    present_digests.insert(d);
                }
            } else {
                any_col_absent = true;
            }
        }
        let kr_has_non_empty_dig = kr.prev_digest.as_deref().is_some_and(|s| !s.is_empty());
        if kr.prev_present != any_col_present
            || kr.prev_present != kr_has_non_empty_dig
            || (!kr.prev_present && kr.prev_digest.is_some())
        {
            return Err(
                "Switch journal keyring summary metadata is inconsistent with per-collection records."
                    .into(),
            );
        }
        let actual_uniform = !any_col_present || (!any_col_absent && present_digests.len() == 1);
        if kr.prev_uniform != actual_uniform {
            return Err(
                "Switch journal keyring `prev_uniform` flag contradicts per-collection records."
                    .into(),
            );
        }
        if let Some(summary_d) = kr.prev_digest.as_deref() {
            if !present_digests.contains(summary_d) {
                return Err(
                    "Switch journal keyring summary digest does not match any recorded collection."
                        .into(),
                );
            }
        }
    }

    Ok(())
}

/// Verify that the currently reachable Secret Service collection IDs match the exact collection ID set
/// recorded in `switch_journal.json` (`replica_state.keyring.collections`).
pub fn keyring_collection_ids_match(
    live_cols: &[KeyringCollectionDigest],
    replica_meta: Option<&JournalReplicaRecord>,
) -> bool {
    let Some(kr_meta) = replica_meta.and_then(|m| m.keyring.as_ref()) else {
        return false;
    };
    if kr_meta.collections.is_empty() || live_cols.len() != kr_meta.collections.len() {
        return false;
    }
    let live_set: BTreeSet<&str> = live_cols.iter().map(|c| c.path.as_str()).collect();
    let exp_set: BTreeSet<&str> = kr_meta
        .collections
        .iter()
        .map(|c| c.path.as_str())
        .collect();
    live_set == exp_set
}

/// Exact pre-switch outgoing active-slot owner observed before writing the target credential.
/// Persisted optionally in `switch_journal.json` (contains ZERO plaintext secrets) so crash
/// recovery replay preserves external-drift and `dual` effective-slot semantics instead of
/// fabricating `last_switched_out_at` on a stale `selected_account_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservedOutgoingSlotOwner {
    Account { account_id: String },
    None,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_outgoing_slot_owner: Option<ObservedOutgoingSlotOwner>,
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClearSlotTargetMeta {
    pub auth_generation: Option<u64>,
    pub refresh_token_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSwitchJournal {
    #[serde(flatten)]
    base: SwitchJournal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replica_state: Option<JournalReplicaRecord>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    clear_slot_intent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clear_target_auth_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clear_target_rt_digest: Option<String>,
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

pub type FullJournalWithClearMeta = (
    SwitchJournal,
    Option<JournalReplicaRecord>,
    bool,
    ClearSlotTargetMeta,
);

pub fn read_journal_full_with_clear_meta_readonly(
    paths: &HeadlessPaths,
) -> CliResult<Option<FullJournalWithClearMeta>> {
    let path = paths.switch_journal_file();
    ensure_no_symlink_components_under(&paths.data_dir, &path)?;
    let Some(bytes) = read_regular_file_opt_bounded(&path, MAX_STORE_FILE_BYTES, "Switch journal")?
    else {
        return Ok(None);
    };
    let persisted: PersistedSwitchJournal = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::partial_commit(
            "recovery_incomplete",
            format!(
                "{} Switch journal is corrupt and has unknown replica scope; preserve '{}' and resolve manually before continuing.",
                format_safe_json_error(&format!("Switch journal '{}'", path.display()), &e),
                path.display()
            ),
        )
    })?;
    if persisted.base.schema_version != STORE_SCHEMA_VERSION {
        return Err(CliError::partial_commit(
            "recovery_incomplete",
            format!(
                "Unsupported switch journal schema_version {} in '{}' (expected {}); preserving journal.",
                persisted.base.schema_version,
                path.display(),
                STORE_SCHEMA_VERSION
            ),
        ));
    }
    if persisted.clear_slot_intent && persisted.replica_state.is_none() {
        return Err(CliError::partial_commit(
            "recovery_incomplete",
            "Clear-slot switch journal is missing required replica metadata; preserving journal.",
        ));
    }
    if let Some(ref meta) = persisted.replica_state {
        if let Err(detail) = validate_replica_meta_completeness(meta) {
            return Err(CliError::partial_commit("recovery_incomplete", detail));
        }
    }
    Ok(Some((
        persisted.base,
        persisted.replica_state,
        persisted.clear_slot_intent,
        ClearSlotTargetMeta {
            auth_generation: persisted.clear_target_auth_generation,
            refresh_token_digest: persisted.clear_target_rt_digest,
        },
    )))
}

pub fn read_journal_full_readonly(
    paths: &HeadlessPaths,
) -> CliResult<Option<(SwitchJournal, Option<JournalReplicaRecord>, bool)>> {
    Ok(read_journal_full_with_clear_meta_readonly(paths)?.map(|(b, m, c, _)| (b, m, c)))
}

pub fn read_journal_record_readonly(
    paths: &HeadlessPaths,
) -> CliResult<Option<(SwitchJournal, Option<JournalReplicaRecord>)>> {
    Ok(read_journal_full_readonly(paths)?.map(|(b, m, _)| (b, m)))
}

pub fn read_journal_readonly(paths: &HeadlessPaths) -> CliResult<Option<SwitchJournal>> {
    Ok(read_journal_record_readonly(paths)?.map(|(base, _)| base))
}

/// Returns `true` whenever an existing `switch_journal.json` on disk requires (or may require, in the
/// case of a legacy `replica_state == None` or corrupt/unreadable journal) the global `keyring-<uid>.lock`
/// scope alongside `slot-<sha256>.lock`.
pub fn journal_on_disk_may_need_keyring(paths: &HeadlessPaths) -> bool {
    match read_journal_record_readonly(paths) {
        Ok(Some((_, m))) => m.as_ref().is_none_or(JournalReplicaRecord::needs_keyring),
        Ok(None) => false,
        Err(_) => true,
    }
}

/// Single-replica `file` journal helper (records explicit `backend = "file"` replica metadata).
/// Genuine pre-`v1.2.0` legacy journals on disk lack `replica_state` (`None`).
pub fn write_journal(paths: &HeadlessPaths, journal: &SwitchJournal) -> CliResult<()> {
    let file_only_meta = JournalReplicaRecord {
        backend: "file".to_string(),
        uses_file: true,
        keyring: None,
        file: JournalReplicaSnapshot {
            prev_present: journal.prev_slot_digest.is_some(),
            prev_digest: journal.prev_slot_digest.clone(),
            prev_uniform: true,
            collections: Vec::new(),
        },
    };
    write_journal_with_replicas(paths, journal, Some(&file_only_meta))
}

pub fn write_journal_with_replicas(
    paths: &HeadlessPaths,
    journal: &SwitchJournal,
    replica_state: Option<&JournalReplicaRecord>,
) -> CliResult<()> {
    write_journal_internal(paths, journal, replica_state, false, None)
}

pub fn write_clear_slot_journal_with_replicas(
    paths: &HeadlessPaths,
    journal: &SwitchJournal,
    replica_state: &JournalReplicaRecord,
) -> CliResult<()> {
    write_journal_internal(paths, journal, Some(replica_state), true, None)
}

pub fn write_clear_slot_journal_with_replicas_and_meta(
    paths: &HeadlessPaths,
    journal: &SwitchJournal,
    replica_state: &JournalReplicaRecord,
    clear_meta: &ClearSlotTargetMeta,
) -> CliResult<()> {
    write_journal_internal(paths, journal, Some(replica_state), true, Some(clear_meta))
}

fn write_journal_internal(
    paths: &HeadlessPaths,
    journal: &SwitchJournal,
    replica_state: Option<&JournalReplicaRecord>,
    clear_slot_intent: bool,
    clear_meta: Option<&ClearSlotTargetMeta>,
) -> CliResult<()> {
    check_fault_injection("write_journal", &paths.switch_journal_file())?;
    if clear_slot_intent && matches!(journal.phase, JournalPhase::CommittedIndexPending) {
        check_fault_injection("stage_clear_slot_committed", &paths.switch_journal_file())?;
    }
    let persisted = PersistedSwitchJournal {
        base: journal.clone(),
        replica_state: replica_state.cloned(),
        clear_slot_intent,
        clear_target_auth_generation: clear_meta.and_then(|m| m.auth_generation),
        clear_target_rt_digest: clear_meta.and_then(|m| m.refresh_token_digest.clone()),
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|_| CliError::data("Failed to serialize switch journal."))?;
    write_atomic_durable(&paths.switch_journal_file(), &bytes)
}

pub fn clear_journal(paths: &HeadlessPaths) -> CliResult<()> {
    let _ = remove_regular_file_durable_under(
        &paths.data_dir,
        &paths.switch_journal_file(),
        "switch journal",
    )?;
    Ok(())
}

/// Pure read-only classification of an existing `switch_journal.json` against a single `SlotInspectState`
/// (retained for single-replica `file` callers).
pub fn diagnose_journal(
    journal: Option<&SwitchJournal>,
    slot_state: &SlotInspectState,
) -> JournalDiagnosis {
    let Some(j) = journal else {
        return JournalDiagnosis::Clean;
    };
    let fake_meta = JournalReplicaRecord {
        backend: "file".to_string(),
        uses_file: true,
        keyring: None,
        file: JournalReplicaSnapshot {
            prev_present: j.prev_slot_digest.is_some(),
            prev_digest: j.prev_slot_digest.clone(),
            prev_uniform: true,
            collections: Vec::new(),
        },
    };
    let fake_replicas = BackendReplicaInspection {
        backend_name: "file",
        uses_keyring: false,
        uses_file: true,
        keyring: None,
        keyring_all_collections_uniform: true,
        keyring_collections: Vec::new(),
        file: slot_state.clone(),
    };
    diagnose_journal_replicas(Some(j), Some(&fake_meta), &fake_replicas)
}

/// Pure read-only multi-replica classification of `switch_journal.json` verifying ALL transactional replicas
/// and exact keyring collection ID sets.
pub fn diagnose_journal_replicas(
    journal: Option<&SwitchJournal>,
    replica_meta: Option<&JournalReplicaRecord>,
    replicas: &BackendReplicaInspection,
) -> JournalDiagnosis {
    diagnose_journal_replicas_with_intent(journal, replica_meta, false, replicas)
}

pub fn diagnose_journal_replicas_with_intent(
    journal: Option<&SwitchJournal>,
    replica_meta: Option<&JournalReplicaRecord>,
    clear_slot_intent: bool,
    replicas: &BackendReplicaInspection,
) -> JournalDiagnosis {
    let Some(j) = journal else {
        return JournalDiagnosis::Clean;
    };

    // Historical journals without `replica_state` have unknown backend/collection scope (could be an
    // interrupted pre-v1.2.0 `dual` write). Never auto-clear under single-backend scope: require
    // full `dual` backend visibility (`RecoveryIncomplete` -> exit 7).
    let Some(meta) = replica_meta else {
        return JournalDiagnosis::RecoveryIncomplete {
            target_account_id: j.target_account_id.clone(),
            reason: "Legacy switch journal lacks replica scope metadata; reconcile under `--backend dual` with full backend access."
                .into(),
        };
    };

    if j.schema_version != STORE_SCHEMA_VERSION {
        return JournalDiagnosis::RecoveryIncomplete {
            target_account_id: j.target_account_id.clone(),
            reason: format!(
                "Unsupported switch journal schema_version {} (expected {}).",
                j.schema_version, STORE_SCHEMA_VERSION
            ),
        };
    }

    if let Err(detail) = validate_replica_meta_completeness(meta) {
        return JournalDiagnosis::RecoveryIncomplete {
            target_account_id: j.target_account_id.clone(),
            reason: detail,
        };
    }

    if matches!(j.phase, JournalPhase::RecoveryIncomplete) {
        return JournalDiagnosis::RecoveryIncomplete {
            target_account_id: j.target_account_id.clone(),
            reason: j
                .note
                .clone()
                .unwrap_or_else(|| "Previous slot rollback failed.".into()),
        };
    }

    let check_keyring = meta.needs_keyring();
    let check_file = meta.needs_file();

    if check_keyring && !replicas.uses_keyring {
        return JournalDiagnosis::RecoveryIncomplete {
            target_account_id: j.target_account_id.clone(),
            reason: format!(
                "Switch journal was recorded by `{}` backend; keyring replica cannot be verified under `{}` backend.",
                meta.backend, replicas.backend_name
            ),
        };
    }
    if check_file && !replicas.uses_file {
        return JournalDiagnosis::RecoveryIncomplete {
            target_account_id: j.target_account_id.clone(),
            reason: format!(
                "Switch journal was recorded by `{}` backend; local file replica cannot be verified under `{}` backend.",
                meta.backend, replicas.backend_name
            ),
        };
    }

    if check_file {
        if matches!(replicas.file, SlotInspectState::Corrupt(_)) {
            return JournalDiagnosis::RecoveryIncomplete {
                target_account_id: j.target_account_id.clone(),
                reason: "Active credential file replica is corrupt after switch.".into(),
            };
        }
        if matches!(replicas.file, SlotInspectState::Unverified(_)) {
            return JournalDiagnosis::RecoveryIncomplete {
                target_account_id: j.target_account_id.clone(),
                reason: "Active credential file replica could not be verified.".into(),
            };
        }
    }

    if check_keyring {
        match replicas.keyring.as_ref() {
            None | Some(SlotInspectState::Unverified(_)) => {
                return JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason: "Linux keyring credential replica could not be verified.".into(),
                };
            }
            Some(SlotInspectState::Corrupt(_)) => {
                return JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason: "Linux keyring credential replica is corrupt or conflicting across collections."
                        .into(),
                };
            }
            Some(_) => {}
        }
        if !keyring_collection_ids_match(&replicas.keyring_collections, Some(meta)) {
            return JournalDiagnosis::RecoveryIncomplete {
                target_account_id: j.target_account_id.clone(),
                reason: "Linux keyring collection set differs from the collections recorded in switch journal."
                    .into(),
            };
        }
    }

    let all_match_target = if clear_slot_intent {
        replicas_all_absent_with_exact_collections(replicas, Some(meta), check_file, check_keyring)
    } else {
        j.target_slot_digest.as_deref().is_some_and(|td| {
            selected_replicas_match_digest_with_exact_collections(
                replicas,
                td,
                Some(meta),
                check_file,
                check_keyring,
            )
        })
    };

    let replicas_match_prev = || -> bool {
        let file_matches_prev = if !check_file {
            true
        } else if meta.file.prev_present {
            replicas.file.raw_digest() == meta.file.prev_digest.as_deref()
        } else {
            replicas.file.is_absent_clean()
        };

        let kr_matches_prev = if check_keyring {
            let kr_state = replicas.keyring.as_ref().unwrap();
            if let Some(ref kr_meta) = meta.keyring {
                let per_col_matches =
                    keyring_collection_ids_match(&replicas.keyring_collections, Some(meta))
                        && kr_meta.collections.iter().all(|mc| {
                            replicas
                                .keyring_collections
                                .iter()
                                .find(|rc| rc.path == mc.path)
                                .is_some_and(|rc| {
                                    rc.present == mc.prev_present && rc.digest == mc.prev_digest
                                })
                        });
                let summary_matches = if kr_meta.prev_present {
                    kr_state.raw_digest() == kr_meta.prev_digest.as_deref()
                        && replicas.keyring_all_collections_uniform == kr_meta.prev_uniform
                } else {
                    kr_state.is_absent_clean()
                };
                per_col_matches && summary_matches
            } else {
                false
            }
        } else {
            true
        };

        file_matches_prev && kr_matches_prev
    };

    match j.phase {
        JournalPhase::AbortedUncommitted => {
            if replicas_match_prev() {
                JournalDiagnosis::AbortedUncommitted {
                    target_account_id: j.target_account_id.clone(),
                    token_rotated: j.token_rotated,
                }
            } else {
                JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason:
                        "Aborted switch journal replicas no longer match recorded pre-switch state."
                            .into(),
                }
            }
        }
        JournalPhase::CommittedSlot | JournalPhase::CommittedIndexPending => {
            if all_match_target {
                JournalDiagnosis::CommittedIndexPending {
                    target_account_id: j.target_account_id.clone(),
                }
            } else {
                JournalDiagnosis::RecoveryIncomplete {
                    target_account_id: j.target_account_id.clone(),
                    reason: "Active credential replica(s) diverged from journal target (partial dual-write or external drift detected)."
                        .into(),
                }
            }
        }
        JournalPhase::Prepared | JournalPhase::TokenRefreshed | JournalPhase::SlotCommitting => {
            if all_match_target {
                if clear_slot_intent {
                    return JournalDiagnosis::RecoveryIncomplete {
                        target_account_id: j.target_account_id.clone(),
                        reason: "Clear-slot deletion was interrupted before CommittedIndexPending stage marker was durably persisted."
                            .into(),
                    };
                }
                return JournalDiagnosis::CommittedIndexPending {
                    target_account_id: j.target_account_id.clone(),
                };
            }

            if replicas_match_prev() {
                return JournalDiagnosis::AbortedUncommitted {
                    target_account_id: j.target_account_id.clone(),
                    token_rotated: j.token_rotated,
                };
            }

            JournalDiagnosis::RecoveryIncomplete {
                target_account_id: j.target_account_id.clone(),
                reason: "Interrupted during slot commit and credential replica(s) diverged or differ from pre-switch and target digests."
                    .into(),
            }
        }
        JournalPhase::RecoveryIncomplete => unreachable!(),
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
    let meta_opt = match read_journal_record_readonly(paths) {
        Ok(None) => return Ok(JournalDiagnosis::Clean),
        Ok(Some((_, m))) => m,
        Err(err) => return Err(err),
    };
    // Unknown-scope legacy journals (`meta_opt.is_none()`) may have touched keyring: lock keyring scope too!
    let lock_keyring = backend.uses_keyring()
        || meta_opt
            .as_ref()
            .is_none_or(JournalReplicaRecord::needs_keyring);

    let ensure_keyring_scope = |mut slot_lock: ActiveSlotLock| -> CliResult<ActiveSlotLock> {
        if !slot_lock.includes_keyring_scope() && journal_on_disk_may_need_keyring(paths) {
            drop(slot_lock);
            slot_lock = ActiveSlotLock::acquire(
                paths,
                true,
                crate::store::repository::DEFAULT_STORE_LOCK_TIMEOUT,
            )?;
        }
        Ok(slot_lock)
    };

    match ActiveSlotLock::try_acquire(paths, lock_keyring) {
        Ok(slot_lock) => {
            let slot_lock = ensure_keyring_scope(slot_lock)?;
            reconcile_journal_locked(&slot_lock, repo, backend, true, now_unix)
        }
        Err(busy_err) if busy_err.exit_code == crate::error::ExitCode::LockBusyOrConflict => {
            if allow_live_precommit_bypass && meta_opt.is_some() {
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
                lock_keyring,
                crate::store::repository::DEFAULT_STORE_LOCK_TIMEOUT,
            )?;
            let slot_lock = ensure_keyring_scope(slot_lock)?;
            reconcile_journal_locked(&slot_lock, repo, backend, true, now_unix)
        }
        Err(other_err) => Err(other_err),
    }
}

fn keyring_collection_ids_match_for_repair(
    live_cols: &[KeyringCollectionDigest],
    replica_meta: Option<&JournalReplicaRecord>,
) -> bool {
    match replica_meta.and_then(|m| m.keyring.as_ref()) {
        Some(kr_meta) if !kr_meta.collections.is_empty() => {
            keyring_collection_ids_match(live_cols, replica_meta)
        }
        _ => !live_cols.is_empty(),
    }
}

pub fn selected_replicas_match_digest_with_exact_collections(
    replicas: &BackendReplicaInspection,
    expected_digest: &str,
    replica_meta: Option<&JournalReplicaRecord>,
    check_file: bool,
    check_keyring: bool,
) -> bool {
    let file_ok = !check_file || replicas.file.raw_digest() == Some(expected_digest);
    let kr_ok = if check_keyring {
        let exact_ids = match replica_meta {
            Some(m) if m.needs_keyring() => {
                keyring_collection_ids_match_for_repair(&replicas.keyring_collections, Some(m))
            }
            _ => !replicas.keyring_collections.is_empty(),
        };
        exact_ids
            && replicas.keyring_all_collections_uniform
            && replicas
                .keyring_collections
                .iter()
                .all(|c| c.present && c.digest.as_deref() == Some(expected_digest))
            && replicas.keyring.as_ref().and_then(|k| k.raw_digest()) == Some(expected_digest)
    } else {
        true
    };
    file_ok && kr_ok
}

fn replicas_uniformly_match_digest_with_meta(
    replicas: &BackendReplicaInspection,
    expected_digest: &str,
    replica_meta: Option<&JournalReplicaRecord>,
) -> bool {
    selected_replicas_match_digest_with_exact_collections(
        replicas,
        expected_digest,
        replica_meta,
        replicas.uses_file,
        replicas.uses_keyring,
    )
}

pub fn replicas_all_absent_with_exact_collections(
    replicas: &BackendReplicaInspection,
    replica_meta: Option<&JournalReplicaRecord>,
    check_file: bool,
    check_keyring: bool,
) -> bool {
    let file_ok = !check_file || replicas.file.is_absent_clean();
    let kr_ok = if check_keyring {
        let exact_ids = match replica_meta {
            Some(m) if m.needs_keyring() => {
                keyring_collection_ids_match_for_repair(&replicas.keyring_collections, Some(m))
            }
            _ => !replicas.keyring_collections.is_empty(),
        };
        exact_ids
            && replicas.keyring_collections.iter().all(|c| !c.present)
            && replicas
                .keyring
                .as_ref()
                .is_some_and(|k| k.is_absent_clean())
    } else {
        true
    };
    file_ok && kr_ok
}

#[derive(Debug, Clone)]
struct ObservedExternalCredential {
    refresh_token_digest: String,
    from_file: bool,
}

/// Inspect `replicas` symmetrically across BOTH the local disk file AND every individual Secret Service
/// collection to detect any valid external credential (matching neither `prev` nor `target`).
fn collect_external_credentials(
    journal: &SwitchJournal,
    replica_meta: Option<&JournalReplicaRecord>,
    replicas: &BackendReplicaInspection,
) -> (BTreeMap<String, ObservedExternalCredential>, bool) {
    let mut externals: BTreeMap<String, ObservedExternalCredential> = BTreeMap::new();
    let mut has_corrupt_replica = false;

    let target_d = journal.target_slot_digest.as_deref();
    let prev_file_d = replica_meta
        .filter(|m| m.needs_file())
        .and_then(|m| {
            if m.file.prev_present {
                m.file.prev_digest.as_deref()
            } else {
                None
            }
        })
        .or_else(|| {
            if replica_meta.is_none() {
                journal.prev_slot_digest.as_deref()
            } else {
                None
            }
        });

    if replicas.uses_file {
        match &replicas.file {
            SlotInspectState::Present(pf) => {
                let d = pf.raw_digest.as_str();
                if Some(d) != prev_file_d && Some(d) != target_d {
                    externals
                        .entry(pf.raw_digest.clone())
                        .and_modify(|e| e.from_file = true)
                        .or_insert_with(|| ObservedExternalCredential {
                            refresh_token_digest: pf.refresh_token_digest.clone(),
                            from_file: true,
                        });
                }
            }
            SlotInspectState::Corrupt(_) => {
                has_corrupt_replica = true;
            }
            _ => {}
        }
    }

    if replicas.uses_keyring {
        let legacy_prev_d = if replica_meta.is_none() {
            journal.prev_slot_digest.as_deref()
        } else {
            None
        };

        if replicas.keyring_collections.is_empty()
            && matches!(replicas.keyring, Some(SlotInspectState::Corrupt(_)))
        {
            has_corrupt_replica = true;
        }

        for rc in &replicas.keyring_collections {
            if !rc.present {
                continue;
            }
            // Strictly use THIS collection's recorded `prev_present` / `prev_digest` when replica
            // metadata is present: an explicitly absent collection (`prev_present == false`) MUST
            // NEVER borrow another collection's summary digest!
            let prev_col_d = if let Some(km) = replica_meta.and_then(|m| m.keyring.as_ref()) {
                km.collections
                    .iter()
                    .find(|mc| mc.path == rc.path)
                    .and_then(|mc| {
                        if mc.prev_present {
                            mc.prev_digest.as_deref()
                        } else {
                            None
                        }
                    })
            } else {
                legacy_prev_d
            };

            match (&rc.digest, &rc.valid_refresh_token_digest) {
                (Some(d), Some(rt_fp)) => {
                    if Some(d.as_str()) != prev_col_d && Some(d.as_str()) != target_d {
                        externals
                            .entry(d.clone())
                            .or_insert_with(|| ObservedExternalCredential {
                                refresh_token_digest: rt_fp.clone(),
                                from_file: false,
                            });
                    }
                }
                _ => {
                    has_corrupt_replica = true;
                }
            }
        }
    }

    (externals, has_corrupt_replica)
}

/// Narrow a `CredentialBackend` to match the single-backend scope recorded in `switch_journal.json`
/// (`keyring`-only or `file`-only) when supported by the caller's backend, so journal repair and
/// post-repair verification never touch the unrelated replica side!
pub fn narrow_backend_for_journal<'a>(
    outer_backend: &'a dyn CredentialBackend,
    replica_meta: Option<&JournalReplicaRecord>,
    file_only_holder: &'a FileSessionBackend,
    kr_only_holder: &'a Option<Box<dyn CredentialBackend>>,
) -> &'a dyn CredentialBackend {
    match replica_meta {
        Some(meta) if meta.needs_keyring() && !meta.needs_file() => match kr_only_holder.as_deref()
        {
            Some(kr) => kr,
            None => outer_backend,
        },
        Some(meta) if meta.needs_file() && !meta.needs_keyring() && outer_backend.uses_file() => {
            file_only_holder
        }
        _ => outer_backend,
    }
}

fn is_reconcile_persistence_io_err(err: &CliError) -> bool {
    err.exit_code == crate::error::ExitCode::GeneralOrDataError
        && matches!(
            err.error_code.as_str(),
            "io_error" | "disk_full_enospc" | "read_only_fs_erofs" | "permission_denied"
        )
}

fn map_committed_slot_reconcile_io_err(target_account_id: &str, err: CliError) -> CliError {
    if is_reconcile_persistence_io_err(&err) {
        CliError::partial_commit(
            "committed_index_pending",
            format!(
                "Active credential slot is already committed to '{target_account_id}', but index reconciliation durability could not be confirmed ({}); switch journal preserved.",
                err.message
            ),
        )
    } else {
        err
    }
}

fn map_committed_slot_journal_clear_io_err(
    target_account_id: &str,
    err: CliError,
    journal_preserved: bool,
) -> CliError {
    if is_reconcile_persistence_io_err(&err) {
        let suffix = if journal_preserved {
            "switch journal preserved for retry."
        } else {
            "switch journal removal durability is unconfirmed and the journal file could not be restored."
        };
        CliError::partial_commit(
            "committed_index_pending",
            format!(
                "Active credential slot and index are aligned to '{target_account_id}', but switch journal removal durability could not be confirmed ({}); {suffix}",
                err.message
            ),
        )
    } else {
        err
    }
}

fn finish_staged_clear_slot_deletion_in_tx(
    tx: &crate::store::repository::StoreWriteTx<'_>,
    target_account_id: &str,
    clear_target_meta: &ClearSlotTargetMeta,
    confirm_stage_marker_durable: bool,
    now_unix: i64,
) -> CliResult<()> {
    if confirm_stage_marker_durable {
        let paths = tx.paths();
        let journal_path = paths.switch_journal_file();
        confirm_dir_entries_durable_under(&paths.data_dir, &paths.state_dir(), &[&journal_path])
            .map_err(|sync_err| {
                CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Could not confirm CommittedIndexPending clear-slot journal durability ({}); switch journal preserved.",
                        sync_err.message
                    ),
                )
            })?;
    }
    tx.complete_account_deletion_idempotent(
        target_account_id,
        clear_target_meta.auth_generation,
        clear_target_meta.refresh_token_digest.as_deref(),
        now_unix,
    )
    .map(|_| ())
    .map_err(|del_err| {
        CliError::partial_commit(
            "recovery_incomplete",
            format!(
                "Clear-slot deletion replay could not durably finish local account cleanup ({}); switch journal preserved.",
                del_err.message
            ),
        )
    })
}

/// Reconcile an unfinished journal under L1 `ActiveSlotLock` -> L3 `StoreWriteLock`.
/// CRITICAL INVARIANTS:
/// 1. NEVER rolls back any rotated `refresh_token` already saved in `accounts/<id>.json`.
/// 2. ALWAYS verifies ALL required replicas AND exact collection IDs before advancing `index.json` or clearing `switch_journal.json`.
/// 3. When `allow_repair_incomplete` is true, symmetrically protects valid external credentials on BOTH disk and every keyring collection,
///    refusing automatic overwrite if distinct conflicting external credentials exist!
pub fn reconcile_journal_locked(
    slot_lock: &ActiveSlotLock,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    allow_repair_incomplete: bool,
    now_unix: i64,
) -> CliResult<JournalDiagnosis> {
    let paths = repo.paths();
    let Some((journal, replica_meta, clear_intent, clear_target_meta)) =
        read_journal_full_with_clear_meta_readonly(paths)?
    else {
        return Ok(JournalDiagnosis::Clean);
    };

    // Enforce required L1 lock scope BEFORE touching any replica or clearing any journal!
    let requires_keyring_lock = backend.uses_keyring()
        || replica_meta
            .as_ref()
            .is_none_or(JournalReplicaRecord::needs_keyring);
    if requires_keyring_lock && !slot_lock.includes_keyring_scope() {
        return Err(CliError::partial_commit(
            "recovery_incomplete",
            "ActiveSlotLock lacks required keyring scope to safely reconcile switch journal.",
        ));
    }

    let file_only_backend = FileSessionBackend;
    let kr_only_box = match replica_meta.as_ref() {
        Some(meta) if meta.needs_keyring() && !meta.needs_file() => backend.keyring_only_view(),
        _ => None,
    };
    let backend = narrow_backend_for_journal(
        backend,
        replica_meta.as_ref(),
        &file_only_backend,
        &kr_only_box,
    );

    let replicas = backend.inspect_replicas(paths);
    let diagnosis = diagnose_journal_replicas_with_intent(
        Some(&journal),
        replica_meta.as_ref(),
        clear_intent,
        &replicas,
    );

    match &diagnosis {
        JournalDiagnosis::Clean => Ok(JournalDiagnosis::Clean),
        JournalDiagnosis::AbortedUncommitted { .. } => {
            // Re-verify ALL replicas + exact collection IDs still match pre-switch before clearing journal!
            repo.with_write_lock(|_| {
                let live_rep = backend.inspect_replicas(paths);
                if !matches!(
                    diagnose_journal_replicas_with_intent(
                        Some(&journal),
                        replica_meta.as_ref(),
                        clear_intent,
                        &live_rep
                    ),
                    JournalDiagnosis::AbortedUncommitted { .. }
                ) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Credential replica state changed concurrently before journal cleanup; retry `agy-switch-cli switch`.",
                    ));
                }
                clear_journal(paths)
            })?;
            Ok(diagnosis)
        }
        JournalDiagnosis::CommittedIndexPending { target_account_id } => {
            let expected_target_digest = journal.target_slot_digest.clone();
            let check_keyring = replica_meta
                .as_ref()
                .map_or(replicas.uses_keyring, JournalReplicaRecord::needs_keyring);
            let check_file = replica_meta
                .as_ref()
                .map_or(replicas.uses_file, JournalReplicaRecord::needs_file);
            let mut should_remove_deleted_slot = false;

            repo.with_write_lock(|tx| {
                let live_rep = backend.inspect_replicas(paths);
                if clear_intent {
                    if !replicas_all_absent_with_exact_collections(
                        &live_rep,
                        replica_meta.as_ref(),
                        check_file,
                        check_keyring,
                    ) {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Active credential replica(s) changed during clear-slot reconciliation.",
                        ));
                    }
                    finish_staged_clear_slot_deletion_in_tx(
                        tx,
                        target_account_id,
                        &clear_target_meta,
                        true,
                        now_unix,
                    )?;
                    return Ok(());
                }

                let Some(ref exp_dig) = expected_target_digest else {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Missing target digest in switch journal.",
                    ));
                };
                if !selected_replicas_match_digest_with_exact_collections(
                    &live_rep,
                    exp_dig,
                    replica_meta.as_ref(),
                    check_file,
                    check_keyring,
                ) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Active credential replica(s) changed or diverged during reconciliation.",
                    ));
                }

                let mut index = tx.load_index_or_init(now_unix)?;
                let target_exists = index.account_order.iter().any(|id| id == target_account_id)
                    && tx.load_account_opt(target_account_id)?.is_some();
                if target_exists {
                    let commit_ts = if matches!(
                        journal.phase,
                        JournalPhase::CommittedSlot | JournalPhase::CommittedIndexPending
                    ) && journal.updated_at > 0
                        && journal.updated_at <= now_unix
                    {
                        journal.updated_at
                    } else {
                        now_unix
                    };
                    tx.commit_selected_account_with_slot_owner(
                        target_account_id,
                        journal.observed_outgoing_slot_owner_arg(),
                        commit_ts,
                    )
                    .map_err(|e| map_committed_slot_reconcile_io_err(target_account_id, e))?;
                } else {
                    if index
                        .selected_account_id
                        .as_deref()
                        .is_some_and(|sel| !index.account_order.iter().any(|id| id == sel))
                    {
                        index.selected_account_id = None;
                        tx.save_index(&mut index, now_unix).map_err(|e| {
                            map_committed_slot_reconcile_io_err(target_account_id, e)
                        })?;
                    }
                    should_remove_deleted_slot = true;
                }
                Ok(())
            })?;

            if clear_intent {
                let live_after = backend.inspect_replicas(paths);
                if !replicas_all_absent_with_exact_collections(
                    &live_after,
                    replica_meta.as_ref(),
                    check_file,
                    check_keyring,
                ) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Credential replica changed before clear-slot journal completion.",
                    ));
                }
            } else if should_remove_deleted_slot {
                let live_now = backend.inspect_replicas(paths);
                if let Some(ref exp_dig) = expected_target_digest {
                    if selected_replicas_match_digest_with_exact_collections(
                        &live_now,
                        exp_dig,
                        replica_meta.as_ref(),
                        check_file,
                        check_keyring,
                    ) {
                        let cas_exp =
                            ReplicaCasExpectation::from_replica_inspection(paths, &live_now)?;
                        backend.remove_slot_cas(paths, &cas_exp)?;
                        let after_rm = backend.inspect_replicas(paths);
                        if !replicas_all_absent_with_exact_collections(
                            &after_rm,
                            replica_meta.as_ref(),
                            check_file,
                            check_keyring,
                        ) {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Deleted target credential replica cleanup was incomplete.",
                            ));
                        }
                    }
                }
            } else {
                let live_after = backend.inspect_replicas(paths);
                if let Some(ref exp_dig) = expected_target_digest {
                    if !selected_replicas_match_digest_with_exact_collections(
                        &live_after,
                        exp_dig,
                        replica_meta.as_ref(),
                        check_file,
                        check_keyring,
                    ) {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Credential replica diverged before journal completion.",
                        ));
                    }
                }
            }
            repo.with_write_lock(|_| {
                let journal_path = paths.switch_journal_file();
                let orig_journal_bytes = read_regular_file_opt_bounded(
                    &journal_path,
                    MAX_STORE_FILE_BYTES,
                    "switch journal",
                )?;
                match clear_journal(paths) {
                    Ok(()) => Ok(()),
                    Err(clear_err) => {
                        let preserved = match orig_journal_bytes.as_deref() {
                            Some(raw) => restore_regular_file_if_absent_under(
                                &paths.data_dir,
                                &journal_path,
                                raw,
                                "switch journal",
                            )
                            .unwrap_or(false),
                            None => false,
                        };
                        Err(map_committed_slot_journal_clear_io_err(
                            target_account_id,
                            clear_err,
                            preserved,
                        ))
                    }
                }
            })?;
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
                        "Previous switch recovery is incomplete ({reason}). Run `agy-switch-cli switch <ID|EMAIL>` to reconcile."
                    ),
                ));
            }

            // Guard 1: Legacy journal without `replica_state` has unknown replica scope (could be pre-v1.2.0 `dual`).
            // Refuse to clear or repair unless BOTH file and keyring replicas are verified (`dual` mode)!
            if replica_meta.is_none() && (!replicas.uses_file || !replicas.uses_keyring) {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Legacy switch journal has no replica scope metadata and cannot be safely repaired under `{}` backend. Re-run with `--backend dual` in an active desktop session so both keyring and file replicas can be verified.",
                        replicas.backend_name
                    ),
                ));
            }

            let meta_needs_keyring = replica_meta
                .as_ref()
                .is_some_and(JournalReplicaRecord::needs_keyring);
            let meta_needs_file = replica_meta
                .as_ref()
                .is_some_and(JournalReplicaRecord::needs_file);
            if meta_needs_keyring && !replicas.uses_keyring {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Cannot repair keyring-backed journal under `{}` backend ({reason}). Re-run with `--backend auto`, `--backend dual`, or `--backend keyring`.",
                        replicas.backend_name
                    ),
                ));
            }
            if meta_needs_file && !replicas.uses_file {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Cannot repair file-backed journal under `{}` backend ({reason}). Re-run with `--backend auto`, `--backend dual`, or `--backend file`.",
                        replicas.backend_name
                    ),
                ));
            }

            if (replicas.uses_file && matches!(replicas.file, SlotInspectState::Unverified(_)))
                || replicas
                    .keyring
                    .as_ref()
                    .is_some_and(|k| matches!(k, SlotInspectState::Unverified(_)))
            {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    format!(
                        "Cannot repair incomplete switch while a credential replica is unverified ({reason}). Fix permissions/keyring access and retry."
                    ),
                ));
            }

            // Guard 2: If `replica_meta` recorded keyring collection IDs, require the exact collection ID set!
            if replicas.uses_keyring {
                if let Some(ref meta) = replica_meta {
                    if meta.needs_keyring()
                        && !keyring_collection_ids_match_for_repair(
                            &replicas.keyring_collections,
                            Some(meta),
                        )
                    {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Cannot repair incomplete switch because the reachable Linux keyring collection set differs from the collections recorded in `switch_journal.json`.",
                        ));
                    }
                }
            }

            // If official `agy` session directory does not exist (`Uninitialized`) on a file-using backend
            // and keyring holds no item across all collections (and this is NOT a pending clear-slot delete!),
            // reconcile index and clear journal.
            let uninitialized_and_empty = !clear_intent
                && replicas.uses_file
                && matches!(replicas.file, SlotInspectState::Uninitialized)
                && (!replicas.uses_keyring
                    || (replicas.keyring_collections.iter().all(|c| !c.present)
                        && replicas
                            .keyring
                            .as_ref()
                            .is_some_and(|k| k.is_absent_clean())));
            if uninitialized_and_empty {
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

            // Case A: All required replicas ALREADY hold the exact same valid `Present` session payload
            let agreed_present: Option<&crate::session::payload::ParsedSessionPayload> = match (
                &replicas.file,
                &replicas.keyring,
                replicas.uses_file,
                replicas.uses_keyring,
            ) {
                (SlotInspectState::Present(pf), _, true, false) => Some(pf),
                (_, Some(SlotInspectState::Present(pk)), false, true)
                    if replicas.keyring_all_collections_uniform =>
                {
                    Some(pk)
                }
                (
                    SlotInspectState::Present(pf),
                    Some(SlotInspectState::Present(pk)),
                    true,
                    true,
                ) if replicas.keyring_all_collections_uniform && pf.raw_digest == pk.raw_digest => {
                    Some(pk)
                }
                _ => None,
            };

            if let Some(live_parsed) = agreed_present {
                let agreed_digest = live_parsed.raw_digest.clone();
                let finish_staged_clear_delete =
                    clear_intent && matches!(journal.phase, JournalPhase::CommittedIndexPending);
                repo.with_write_lock(|tx| {
                    let check_rep = backend.inspect_replicas(paths);
                    if !replicas_uniformly_match_digest_with_meta(
                        &check_rep,
                        &agreed_digest,
                        replica_meta.as_ref(),
                    ) {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Credential replica changed concurrently during journal reconciliation.",
                        ));
                    }
                    // If Stage 1 of a `clear_slot_intent` already committed (`CommittedIndexPending`)
                    // and an external credential later appeared across replicas before Stage 2 finished,
                    // preserve the external credential AND complete Stage 2 local account cleanup!
                    if finish_staged_clear_delete {
                        finish_staged_clear_slot_deletion_in_tx(
                            tx,
                            target_account_id,
                            &clear_target_meta,
                            true,
                            now_unix,
                        )?;
                    }
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
                        tx.commit_selected_account_with_slot_owner(
                            &local_id,
                            journal.observed_outgoing_slot_owner_arg(),
                            now_unix,
                        )?;
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

            // Case B: Symmetric external-credential protection across BOTH disk and every keyring collection!
            // - If >= 2 distinct external credentials exist (or external + corrupt replica): refuse overwrite (exit 7)!
            // - If == 1 unique valid external credential exists (on disk OR in any keyring collection):
            //   bind exact per-replica CAS expectation into `write_slot_cas` and synchronize all managed replicas!
            let (external_creds, has_corrupt_replica) =
                collect_external_credentials(&journal, replica_meta.as_ref(), &replicas);
            if external_creds.len() >= 2 || (!external_creds.is_empty() && has_corrupt_replica) {
                return Err(CliError::partial_commit(
                    "conflicting_external_credentials",
                    "Conflicting or unverified external credentials exist across active replicas; refusing automatic overwrite. Resolve manually and retry.",
                ));
            }

            if let Some((ext_digest, ext_info)) = external_creds.into_iter().next() {
                if replicas.uses_file && matches!(replicas.file, SlotInspectState::Uninitialized) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Cannot synchronize external keyring credential to local file because `~/.gemini/antigravity-cli` is uninitialized.",
                    ));
                }

                let raw_ext_bytes = if ext_info.from_file {
                    read_regular_file_opt_bounded(
                        &paths.active_slot_file,
                        MAX_STORE_FILE_BYTES,
                        "Active session file",
                    )?
                } else {
                    backend.read_raw_keyring_secret_by_digest(&ext_digest)?
                }
                .ok_or_else(|| {
                    CliError::partial_commit(
                        "recovery_incomplete",
                        "External credential disappeared concurrently before synchronization; retry.",
                    )
                })?;

                if bytes_sha256_hex(&raw_ext_bytes) != ext_digest
                    || parse_session_payload_bytes(&raw_ext_bytes).is_err()
                {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "External credential changed concurrently during readback; journal preserved.",
                    ));
                }
                let ext_str = std::str::from_utf8(&raw_ext_bytes).map_err(|_| {
                    CliError::partial_commit(
                        "recovery_incomplete",
                        "External credential is not valid UTF-8; journal preserved.",
                    )
                })?;

                // Symmetric CAS re-check AND bind per-replica expectation into `write_slot_cas`!
                let cas_rep = backend.inspect_replicas(paths);
                if replicas.uses_keyring {
                    if let Some(ref meta) = replica_meta {
                        if meta.needs_keyring()
                            && !keyring_collection_ids_match_for_repair(
                                &cas_rep.keyring_collections,
                                Some(meta),
                            )
                        {
                            return Err(CliError::partial_commit(
                                "recovery_incomplete",
                                "Keyring collection set changed concurrently before external credential sync.",
                            ));
                        }
                    }
                }
                let (cas_exts, cas_corrupt) =
                    collect_external_credentials(&journal, replica_meta.as_ref(), &cas_rep);
                if cas_corrupt || cas_exts.len() != 1 || !cas_exts.contains_key(&ext_digest) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Active replicas changed concurrently before external credential synchronization; journal preserved.",
                    ));
                }
                let cas_exp = ReplicaCasExpectation::from_replica_inspection(paths, &cas_rep)?;

                backend.write_slot_cas(paths, ext_str, &cas_exp)?;
                let verify_rep = backend.inspect_replicas(paths);
                if !replicas_uniformly_match_digest_with_meta(
                    &verify_rep,
                    &ext_digest,
                    replica_meta.as_ref(),
                ) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Failed to synchronize credential replicas with external credential; journal preserved.",
                    ));
                }
                let ext_rt_fp = ext_info.refresh_token_digest;
                let finish_staged_clear_delete =
                    clear_intent && matches!(journal.phase, JournalPhase::CommittedIndexPending);
                repo.with_write_lock(|tx| {
                    let check_rep = backend.inspect_replicas(paths);
                    if !replicas_uniformly_match_digest_with_meta(
                        &check_rep,
                        &ext_digest,
                        replica_meta.as_ref(),
                    ) {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Credential replica changed concurrently before journal completion.",
                        ));
                    }
                    if finish_staged_clear_delete {
                        finish_staged_clear_slot_deletion_in_tx(
                            tx,
                            target_account_id,
                            &clear_target_meta,
                            true,
                            now_unix,
                        )?;
                    }
                    let mut index = tx.load_index_or_init(now_unix)?;
                    let mut matched_local_id: Option<String> = None;
                    for id in &index.account_order {
                        if let Some(acc) = tx.load_account_opt(id)? {
                            if acc.token.refresh_token_fingerprint() == ext_rt_fp {
                                matched_local_id = Some(acc.id);
                                break;
                            }
                        }
                    }
                    if let Some(local_id) = matched_local_id {
                        tx.commit_selected_account_with_slot_owner(
                            &local_id,
                            journal.observed_outgoing_slot_owner_arg(),
                            now_unix,
                        )?;
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

            // Case C: Diverged replicas (`prev`/`target`/absent/corrupt, ZERO external credentials) ->
            // bind exact per-replica CAS expectation and repair ALL active backend replicas from
            // local store (or stage & complete `clear_slot_intent`)!
            if replicas.uses_file && matches!(replicas.file, SlotInspectState::Uninitialized) {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "Cannot synchronize file replica because `~/.gemini/antigravity-cli` is uninitialized (if you use keyring-only mode, pass `--backend keyring`).",
                ));
            }

            let pre_repair_rep = backend.inspect_replicas(paths);
            if replicas.uses_keyring {
                if let Some(ref meta) = replica_meta {
                    if meta.needs_keyring()
                        && !keyring_collection_ids_match_for_repair(
                            &pre_repair_rep.keyring_collections,
                            Some(meta),
                        )
                    {
                        return Err(CliError::partial_commit(
                            "recovery_incomplete",
                            "Keyring collection set changed concurrently before journal repair.",
                        ));
                    }
                }
            }
            let (late_exts, _) =
                collect_external_credentials(&journal, replica_meta.as_ref(), &pre_repair_rep);
            if !late_exts.is_empty() {
                return Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "External credential appeared concurrently during journal repair; journal preserved without overwriting.",
                ));
            }
            let cas_exp = ReplicaCasExpectation::from_replica_inspection(paths, &pre_repair_rep)?;

            if clear_intent {
                let already_all_absent = replicas_all_absent_with_exact_collections(
                    &pre_repair_rep,
                    replica_meta.as_ref(),
                    replicas.uses_file,
                    replicas.uses_keyring,
                );
                if already_all_absent {
                    if replicas.uses_file {
                        confirm_file_absent_and_parent_durable_under(
                            &paths.home_dir,
                            &paths.active_slot_file,
                            "active session file",
                        )
                        .map_err(|e| {
                            CliError::partial_commit(
                                "recovery_incomplete",
                                format!(
                                    "Could not confirm active credential slot absence durability ({}); switch journal preserved.",
                                    e.message
                                ),
                            )
                        })?;
                    }
                } else {
                    backend.remove_slot_cas(paths, &cas_exp)?;
                }
                let post_rm = backend.inspect_replicas(paths);
                if !replicas_all_absent_with_exact_collections(
                    &post_rm,
                    replica_meta.as_ref(),
                    replicas.uses_file,
                    replicas.uses_keyring,
                ) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Post-removal verification failed across credential replicas; journal preserved.",
                    ));
                }
                // Stage 1 complete (all active replicas absent). Durably advance journal to
                // `CommittedIndexPending` BEFORE Stage 2 local store cleanup!
                let mut staged = journal.clone();
                staged.phase = JournalPhase::CommittedIndexPending;
                staged.updated_at = now_unix;
                let meta_ref = replica_meta.as_ref().ok_or_else(|| {
                    CliError::partial_commit(
                        "recovery_incomplete",
                        "Clear-slot journal lacks replica metadata during staged replay.",
                    )
                })?;
                repo.with_write_lock(|_| {
                    write_clear_slot_journal_with_replicas_and_meta(
                        paths,
                        &staged,
                        meta_ref,
                        &clear_target_meta,
                    )
                })
                .map_err(|e| {
                    CliError::partial_commit(
                        "recovery_incomplete",
                        format!(
                            "Active slot cleared, but failed to stage clear-slot journal ({}).",
                            e.message
                        ),
                    )
                })?;

                repo.with_write_lock(|tx| {
                    finish_staged_clear_slot_deletion_in_tx(
                        tx,
                        target_account_id,
                        &clear_target_meta,
                        false,
                        now_unix,
                    )?;
                    clear_journal(paths)
                })?;
                return Ok(diagnosis);
            }

            let target_on_keyring = replicas
                .keyring
                .as_ref()
                .and_then(|k| k.raw_digest())
                .is_some_and(|kd| Some(kd) == journal.target_slot_digest.as_deref());

            let mut candidate_ids: Vec<String> = Vec::new();
            if target_on_keyring && !target_account_id.is_empty() {
                candidate_ids.push(target_account_id.clone());
            }
            if let Some(ref prev_id) = journal.prev_selected_account_id {
                if !prev_id.is_empty() && !candidate_ids.contains(prev_id) {
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
                    if let Ok(payload) = serialize_session_payload_for_account(&acc) {
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
                let expected_repair_digest = bytes_sha256_hex(payload.as_bytes());
                backend.write_slot_cas(paths, &payload, &cas_exp)?;
                let post_rep = backend.inspect_replicas(paths);
                if !replicas_uniformly_match_digest_with_meta(
                    &post_rep,
                    &expected_repair_digest,
                    replica_meta.as_ref(),
                ) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Post-repair verification failed across credential replicas; journal preserved.",
                    ));
                }
                repo.with_write_lock(|tx| {
                    tx.commit_selected_account_with_slot_owner(
                        &repair_id,
                        journal.observed_outgoing_slot_owner_arg(),
                        now_unix,
                    )?;
                    clear_journal(paths)
                })?;
            } else {
                backend.remove_slot_cas(paths, &cas_exp)?;
                let post_rm = backend.inspect_replicas(paths);
                if !replicas_all_absent_with_exact_collections(
                    &post_rm,
                    replica_meta.as_ref(),
                    replicas.uses_file,
                    replicas.uses_keyring,
                ) {
                    return Err(CliError::partial_commit(
                        "recovery_incomplete",
                        "Post-removal verification failed across credential replicas; journal preserved.",
                    ));
                }
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
            observed_outgoing_slot_owner: None,
            target_account_id,
            prev_slot_digest,
            target_slot_digest: None,
            token_rotated: false,
            started_at: now_unix,
            updated_at: now_unix,
            note: None,
        }
    }

    pub fn with_observed_outgoing_slot_owner(mut self, owner: Option<&str>) -> Self {
        self.observed_outgoing_slot_owner = Some(match owner {
            Some(id) => ObservedOutgoingSlotOwner::Account {
                account_id: id.to_string(),
            },
            None => ObservedOutgoingSlotOwner::None,
        });
        self
    }

    pub fn observed_outgoing_slot_owner_arg(&self) -> Option<Option<&str>> {
        self.observed_outgoing_slot_owner.as_ref().map(|o| match o {
            ObservedOutgoingSlotOwner::Account { account_id } => Some(account_id.as_str()),
            ObservedOutgoingSlotOwner::None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::account::AccountRecord;
    use crate::domain::token::TokenRecord;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PanickingDualKeyringBackend {
        keyring_writes: AtomicUsize,
    }

    impl CredentialBackend for PanickingDualKeyringBackend {
        fn name(&self) -> &'static str {
            "dual"
        }
        fn uses_keyring(&self) -> bool {
            true
        }
        fn inspect_slot(&self, _paths: &HeadlessPaths) -> SlotInspectState {
            panic!("must narrow to FileSessionBackend and never inspect keyring on file-scoped journal");
        }
        fn inspect_replicas(&self, _paths: &HeadlessPaths) -> BackendReplicaInspection {
            panic!("must narrow to FileSessionBackend and never inspect keyring on file-scoped journal");
        }
        fn snapshot_before_write(&self, _paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>> {
            panic!("must narrow to FileSessionBackend");
        }
        fn write_slot(&self, _paths: &HeadlessPaths, _payload: &str) -> CliResult<()> {
            self.keyring_writes.fetch_add(1, Ordering::SeqCst);
            panic!(
                "must narrow to FileSessionBackend and never clobber unrecorded keyring credential"
            );
        }
        fn remove_slot(&self, _paths: &HeadlessPaths) -> CliResult<()> {
            self.keyring_writes.fetch_add(1, Ordering::SeqCst);
            panic!(
                "must narrow to FileSessionBackend and never remove unrecorded keyring credential"
            );
        }
    }

    #[test]
    fn file_scoped_recovery_incomplete_journal_narrows_backend_under_dual_without_touching_keyring()
    {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        std::fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let now = 1_850_000_000i64;
        let acc = AccountRecord::new(
            "acc-1".into(),
            "alice@example.com".into(),
            TokenRecord {
                access_token: "ya29.1".into(),
                refresh_token: "1//rt-1".into(),
                expires_in: 3600,
                expiry_timestamp: now + 3600,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        );
        repo.with_write_lock(|tx| tx.upsert_account(acc.clone(), true, now))
            .unwrap();
        std::fs::write(&paths.active_slot_file, b"{corrupt-partial-slot").unwrap();

        let mut j = SwitchJournal::new_prepared(
            "op-file-inc".into(),
            Some("acc-1".into()),
            "acc-1".into(),
            None,
            now,
        );
        j.phase = JournalPhase::RecoveryIncomplete;
        repo.with_write_lock(|_| write_journal(&paths, &j)).unwrap();

        let outer_dual = PanickingDualKeyringBackend {
            keyring_writes: AtomicUsize::new(0),
        };
        reconcile_pending_journal_before_write(&repo, &outer_dual, now).unwrap();
        assert_eq!(outer_dual.keyring_writes.load(Ordering::SeqCst), 0);
        assert!(read_journal_readonly(&paths).unwrap().is_none());
        assert_eq!(
            std::fs::read_to_string(&paths.active_slot_file).unwrap(),
            serialize_session_payload_for_account(&acc).unwrap()
        );
    }

    #[test]
    fn r3_01_validates_schema_aborted_scope_absent_collection_external_and_l1_keyring_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        std::fs::create_dir_all(&paths.active_slot_dir).unwrap();
        std::fs::create_dir_all(paths.state_dir()).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let now = 1_850_000_000i64;

        // 1. Unsupported `schema_version` returns exit 7 (`recovery_incomplete`)
        let bad_schema = serde_json::json!({
            "schema_version": 99,
            "operation_id": "op-bad-ver",
            "phase": "prepared",
            "target_account_id": "acc-1",
            "token_rotated": false,
            "started_at": now,
            "updated_at": now,
            "replica_state": {
                "backend": "file",
                "uses_file": true,
                "file": { "prev_present": false, "prev_uniform": true }
            }
        });
        std::fs::write(
            paths.switch_journal_file(),
            serde_json::to_vec(&bad_schema).unwrap(),
        )
        .unwrap();
        let err = read_journal_full_readonly(&paths).unwrap_err();
        assert_eq!(
            err.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );

        // 2. `AbortedUncommitted` does NOT early-return before checking backend scope & replicas
        let mut aborted_kr = SwitchJournal::new_prepared(
            "op-aborted-kr".into(),
            Some("acc-1".into()),
            "acc-2".into(),
            Some("dig-prev".into()),
            now,
        );
        aborted_kr.phase = JournalPhase::AbortedUncommitted;
        let kr_meta = JournalReplicaRecord {
            backend: "keyring".into(),
            uses_file: false,
            keyring: Some(JournalReplicaSnapshot {
                prev_present: true,
                prev_digest: Some("dig-prev".into()),
                prev_uniform: true,
                collections: vec![JournalCollectionSnapshot {
                    path: "/org/freedesktop/secrets/collection/login".into(),
                    prev_present: true,
                    prev_digest: Some("dig-prev".into()),
                }],
            }),
            file: JournalReplicaSnapshot {
                prev_present: false,
                prev_digest: None,
                prev_uniform: true,
                collections: Vec::new(),
            },
        };
        let file_only_inspection = BackendReplicaInspection {
            backend_name: "file",
            uses_keyring: false,
            uses_file: true,
            keyring: None,
            keyring_all_collections_uniform: true,
            keyring_collections: Vec::new(),
            file: SlotInspectState::AbsentInInitializedDir,
        };
        assert!(matches!(
            diagnose_journal_replicas(Some(&aborted_kr), Some(&kr_meta), &file_only_inspection),
            JournalDiagnosis::RecoveryIncomplete { .. }
        ));

        // 3. Explicitly absent collection (`prev_present: false`) MUST NOT borrow sibling collection's
        //    `prev_digest` when classifying external credentials!
        let dual_meta = JournalReplicaRecord {
            backend: "dual".into(),
            uses_file: true,
            keyring: Some(JournalReplicaSnapshot {
                prev_present: true,
                prev_digest: Some("dig-col1".into()),
                prev_uniform: false,
                collections: vec![
                    JournalCollectionSnapshot {
                        path: "/org/freedesktop/secrets/collection/login".into(),
                        prev_present: true,
                        prev_digest: Some("dig-col1".into()),
                    },
                    JournalCollectionSnapshot {
                        path: "/org/freedesktop/secrets/collection/custom".into(),
                        prev_present: false,
                        prev_digest: None,
                    },
                ],
            }),
            file: JournalReplicaSnapshot {
                prev_present: true,
                prev_digest: Some("dig-col1".into()),
                prev_uniform: true,
                collections: Vec::new(),
            },
        };
        let mut sw_j = SwitchJournal::new_prepared(
            "op-absent-col".into(),
            Some("acc-1".into()),
            "acc-2".into(),
            Some("dig-col1".into()),
            now,
        );
        sw_j.target_slot_digest = Some("dig-target".into());
        let live_with_ext_in_absent_col = BackendReplicaInspection {
            backend_name: "dual",
            uses_keyring: true,
            uses_file: true,
            keyring: Some(SlotInspectState::Corrupt("diff".into())),
            keyring_all_collections_uniform: false,
            keyring_collections: vec![
                KeyringCollectionDigest {
                    path: "/org/freedesktop/secrets/collection/login".into(),
                    present: true,
                    digest: Some("dig-col1".into()),
                    valid_refresh_token_digest: Some("rt-col1".into()),
                },
                KeyringCollectionDigest {
                    path: "/org/freedesktop/secrets/collection/custom".into(),
                    present: true,
                    // Even if its digest equals `dig-col1` (sibling's prev_digest!), this collection
                    // was explicitly recorded ABSENT, so it MUST be recognized as external!
                    digest: Some("dig-col1".into()),
                    valid_refresh_token_digest: Some("rt-col1".into()),
                },
            ],
            file: SlotInspectState::AbsentInInitializedDir,
        };
        let (exts, _) =
            collect_external_credentials(&sw_j, Some(&dual_meta), &live_with_ext_in_absent_col);
        assert!(
            exts.contains_key("dig-col1"),
            "Credential appearing in an explicitly absent collection must be detected as external!"
        );

        // 4. `reconcile_journal_locked` enforces L1 lock keyring scope!
        repo.with_write_lock(|_| write_journal_with_replicas(&paths, &aborted_kr, Some(&kr_meta)))
            .unwrap();
        let file_only_l1 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
        let lock_err =
            reconcile_journal_locked(&file_only_l1, &repo, &FileSessionBackend, true, now)
                .unwrap_err();
        assert_eq!(
            lock_err.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );
        assert!(lock_err.message.contains("keyring scope"));

        // 5. `validate_replica_meta_completeness` rejects contradictory `prev_uniform`,
        //    mismatched summary digest, keyring-only with file presence, and non-empty file collections!
        let mut bad_uniform = dual_meta.clone();
        bad_uniform.keyring.as_mut().unwrap().prev_uniform = true;
        assert!(validate_replica_meta_completeness(&bad_uniform).is_err());

        let mut bad_summary_dig = dual_meta.clone();
        bad_summary_dig.keyring.as_mut().unwrap().prev_digest = Some("dig-nonexistent".into());
        assert!(validate_replica_meta_completeness(&bad_summary_dig).is_err());

        let mut bad_kr_file = kr_meta.clone();
        bad_kr_file.file.prev_present = true;
        bad_kr_file.file.prev_digest = Some("dig-prev".into());
        assert!(validate_replica_meta_completeness(&bad_kr_file).is_err());

        let mut bad_file_cols = dual_meta.clone();
        bad_file_cols
            .file
            .collections
            .push(JournalCollectionSnapshot {
                path: "/org/freedesktop/secrets/collection/login".into(),
                prev_present: false,
                prev_digest: None,
            });
        assert!(validate_replica_meta_completeness(&bad_file_cols).is_err());

        // 6. R4-01: file replica metadata (`meta.needs_file()`) MUST reject explicit `prev_uniform=false`,
        //    while omitting `file.prev_uniform` still defaults to `true` and keyring multi-collection
        //    `prev_uniform=false` remains allowed when collections genuinely differ.
        let mut bad_dual_file_uniform = dual_meta.clone();
        bad_dual_file_uniform.file.prev_uniform = false;
        assert!(validate_replica_meta_completeness(&bad_dual_file_uniform).is_err());

        let file_meta_bad_uniform = JournalReplicaRecord {
            backend: "file".into(),
            uses_file: true,
            keyring: None,
            file: JournalReplicaSnapshot {
                prev_present: true,
                prev_digest: Some("dig-prev".into()),
                prev_uniform: false,
                collections: Vec::new(),
            },
        };
        assert!(validate_replica_meta_completeness(&file_meta_bad_uniform).is_err());

        let omitted_uniform_file_meta: JournalReplicaRecord =
            serde_json::from_value(serde_json::json!({
                "backend": "file",
                "uses_file": true,
                "file": { "prev_present": true, "prev_digest": "dig-prev" }
            }))
            .unwrap();
        assert!(omitted_uniform_file_meta.file.prev_uniform);
        assert!(validate_replica_meta_completeness(&omitted_uniform_file_meta).is_ok());

        let bad_file_journal = SwitchJournal {
            schema_version: STORE_SCHEMA_VERSION,
            operation_id: "op-r401-bad-file-uniform".into(),
            phase: JournalPhase::AbortedUncommitted,
            prev_selected_account_id: Some("acc-1".into()),
            observed_outgoing_slot_owner: None,
            target_account_id: "acc-2".into(),
            prev_slot_digest: Some("dig-prev".into()),
            target_slot_digest: None,
            token_rotated: false,
            started_at: now,
            updated_at: now,
            note: None,
        };
        repo.with_write_lock(|_| {
            write_journal_with_replicas(&paths, &bad_file_journal, Some(&file_meta_bad_uniform))
        })
        .unwrap();
        let raw_before = std::fs::read(paths.switch_journal_file()).unwrap();
        let read_err = read_journal_full_with_clear_meta_readonly(&paths).unwrap_err();
        assert_eq!(
            read_err.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );
        assert_eq!(read_err.error_code, "recovery_incomplete");
        assert_eq!(
            std::fs::read(paths.switch_journal_file()).unwrap(),
            raw_before
        );
    }
}
