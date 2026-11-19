use crate::domain::account::{
    validate_account_id, AccountRecord, DisableReasonCode, TransferAccountItem, TransferBundle,
    STORE_SCHEMA_VERSION, TRANSFER_SCHEMA_VERSION,
};
use crate::domain::quota::QuotaObservation;
use crate::domain::token::TokenRecord;
use crate::error::{format_safe_json_error, CliError, CliResult};
use crate::store::fs_atomic::{
    ensure_no_symlink_ancestors, ensure_private_dir, map_io_error, read_regular_file_bounded,
    write_atomic_durable, MAX_STORE_FILE_BYTES,
};
use crate::store::locks::with_account_refresh_lock;
use crate::store::repository::{select_from_slice, ImportUpsertOutcome, StoreRepository};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportItemFailure {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub source: String,
    pub imported_count: usize,
    pub updated_count: usize,
    #[serde(default)]
    pub skipped_count: usize,
    pub failed_count: usize,
    pub imported_ids: Vec<String>,
    pub updated_ids: Vec<String>,
    #[serde(default)]
    pub skipped_ids: Vec<String>,
    pub failures: Vec<ImportItemFailure>,
}

async fn execute_locked_import_item(
    repo: &StoreRepository,
    candidate_id_hint: Option<&str>,
    record: AccountRecord,
    overwrite: bool,
    select_if_first: bool,
    now_unix: i64,
) -> CliResult<ImportUpsertOutcome> {
    let pre_match_id = repo.find_matching_account_id_for_import_readonly(
        candidate_id_hint,
        &record.token.refresh_token,
        &record.email,
        record.token.oauth_client_key.as_deref(),
    )?;

    if let Some(existing_id) = pre_match_id {
        return with_account_refresh_lock(
            repo.paths(),
            &existing_id,
            Duration::from_secs(20),
            || async {
                repo.with_write_lock(|tx| {
                    tx.import_account_checked(record, overwrite, select_if_first, now_unix)
                })
            },
        )
        .await;
    }

    // No account matched before L3; check inside L3 if a concurrent caller created one in the interim!
    enum FastPath {
        Done(Box<ImportUpsertOutcome>),
        RetryUnderL2(String, Box<AccountRecord>),
    }

    let first_try = repo.with_write_lock(|tx| {
        let index = tx.load_index_or_init(now_unix)?;
        for existing_id in &index.account_order {
            if let Some(acc) = tx.load_account_opt(existing_id)? {
                let same_id = candidate_id_hint.is_some_and(|cid| acc.id == cid);
                let same_rt = !record.token.refresh_token.trim().is_empty()
                    && (acc.token.refresh_token.trim() == record.token.refresh_token.trim()
                        || tx
                            .account_has_superseded_rt_in_tx(&acc, &record.token.refresh_token)?
                            .0);
                let same_email = !record.email.trim().is_empty()
                    && acc.email.eq_ignore_ascii_case(&record.email)
                    && (acc.token.oauth_client_key == record.token.oauth_client_key
                        || acc.token.oauth_client_key.is_none()
                        || record.token.oauth_client_key.is_none());
                if same_id || same_rt || same_email {
                    return Ok(FastPath::RetryUnderL2(acc.id, Box::new(record)));
                }
            }
        }
        let outcome = tx.import_account_checked(record, overwrite, select_if_first, now_unix)?;
        Ok(FastPath::Done(Box::new(outcome)))
    })?;

    match first_try {
        FastPath::Done(outcome) => Ok(*outcome),
        FastPath::RetryUnderL2(existing_id, rec_box) => {
            with_account_refresh_lock(
                repo.paths(),
                &existing_id,
                Duration::from_secs(20),
                || async {
                    repo.with_write_lock(|tx| {
                        tx.import_account_checked(*rec_box, overwrite, select_if_first, now_unix)
                    })
                },
            )
            .await
        }
    }
}

/// Read-only import from a `TransferBundle` v1/v2 backup JSON file.
/// Coordinates under `L2 -> L3` for existing accounts, skips duplicates by default (without `--overwrite`),
/// and rejects superseded rotated refresh tokens even when `--overwrite` is requested!
pub async fn import_transfer_bundle_file(
    repo: &StoreRepository,
    bundle_path: &Path,
    overwrite: bool,
    now_unix: i64,
) -> CliResult<ImportReport> {
    if crate::error::path_looks_like_accidental_secret(bundle_path) {
        return Err(CliError::usage(
            "`--from-file` expects a filesystem path to a transfer bundle JSON file, not a literal credential value (redacted).",
        ));
    }
    if let Some(parent) = bundle_path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_no_symlink_ancestors(parent)?;
        }
    }
    let meta = fs::symlink_metadata(bundle_path).map_err(|e| {
        map_io_error(
            e,
            &format!("Cannot inspect import file '{}'", bundle_path.display()),
        )
    })?;
    if !meta.file_type().is_file() {
        return Err(CliError::usage(format!(
            "Import path '{}' must be a regular file, not a symlink, FIFO, or directory.",
            bundle_path.display()
        )));
    }
    let bytes = read_regular_file_bounded(bundle_path, MAX_STORE_FILE_BYTES, "Import file")?;

    // Support both `{ "schema_version": 1|2, "accounts": [...] }` and bare v1 array `[...]`
    let bundle: TransferBundle = if let Ok(b) = serde_json::from_slice::<TransferBundle>(&bytes) {
        if !matches!(b.schema_version, 0..=2) {
            return Err(CliError::data(format!(
                "Unsupported transfer bundle schema_version {} (supported: 1, 2).",
                b.schema_version
            )));
        }
        b
    } else if let Ok(items) = serde_json::from_slice::<Vec<TransferAccountItem>>(&bytes) {
        TransferBundle {
            schema_version: 1,
            accounts: items,
        }
    } else {
        return Err(CliError::data(format!(
            "Import file '{}' is not a valid v1/v2 transfer bundle JSON.",
            bundle_path.display()
        )));
    };

    let mut report = ImportReport {
        source: bundle_path.to_string_lossy().into_owned(),
        imported_count: 0,
        updated_count: 0,
        skipped_count: 0,
        failed_count: 0,
        imported_ids: Vec::new(),
        updated_ids: Vec::new(),
        skipped_ids: Vec::new(),
        failures: Vec::new(),
    };

    for (idx, item) in bundle.accounts.into_iter().enumerate() {
        let email = item.email.trim().to_string();
        let rt = item.refresh_token.trim().to_string();
        let ident = (!email.is_empty()).then(|| email.clone());

        if email.is_empty() || !email.contains('@') {
            report.failed_count += 1;
            report.failures.push(ImportItemFailure {
                index: idx,
                identifier: ident,
                reason: "Missing or invalid email address.".into(),
            });
            continue;
        }
        if rt.is_empty() {
            report.failed_count += 1;
            report.failures.push(ImportItemFailure {
                index: idx,
                identifier: Some(email),
                reason: "Empty refresh_token.".into(),
            });
            continue;
        }

        let id = format!("acc-{}", Uuid::new_v4().simple());
        let token = TokenRecord {
            access_token: String::new(),
            refresh_token: rt,
            expires_in: 0,
            // Positive minimal Unix timestamp so serialization invariants hold while marking token expired
            expiry_timestamp: 1,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: item
                .oauth_client_key
                .map(|k| k.trim().to_ascii_lowercase())
                .filter(|k| !k.is_empty()),
            // Imported from refresh_token only -> granted_scopes strictly unknown (`None`)
            granted_scopes: None,
            project_id: item.project_id.filter(|p| !p.trim().is_empty()),
            is_gcp_tos: item.is_gcp_tos,
        };
        let mut record = AccountRecord::new(id, email.clone(), token, now_unix);
        record.name = item.name.filter(|n| !n.trim().is_empty());
        record.custom_label = item.custom_label.filter(|l| !l.trim().is_empty());

        match execute_locked_import_item(repo, None, record, overwrite, true, now_unix).await {
            Ok(ImportUpsertOutcome::Imported(saved)) => {
                report.imported_count += 1;
                report.imported_ids.push(saved.id);
            }
            Ok(ImportUpsertOutcome::Updated(saved)) => {
                report.updated_count += 1;
                report.updated_ids.push(saved.id);
            }
            Ok(ImportUpsertOutcome::SkippedDuplicate(existing)) => {
                report.skipped_count += 1;
                report.skipped_ids.push(existing.id);
            }
            Err(e) => {
                report.failed_count += 1;
                report.failures.push(ImportItemFailure {
                    index: idx,
                    identifier: Some(email),
                    reason: e.message,
                });
            }
        }
    }

    Ok(report)
}

#[derive(Deserialize)]
struct LegacyIndex {
    #[serde(default)]
    accounts: Vec<LegacySummary>,
    #[serde(default)]
    current_account_id: Option<String>,
}

#[derive(Deserialize)]
struct LegacySummary {
    id: String,
}

#[derive(Deserialize)]
struct LegacyTokenData {
    #[serde(default)]
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    expiry_timestamp: i64,
    #[serde(default = "default_bearer")]
    token_type: String,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    is_gcp_tos: bool,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    oauth_client_key: Option<String>,
}

fn default_bearer() -> String {
    "Bearer".to_string()
}

#[derive(Deserialize)]
struct LegacyAccount {
    id: String,
    email: String,
    #[serde(default)]
    name: Option<String>,
    token: LegacyTokenData,
    #[serde(default)]
    quota: Option<QuotaObservation>,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    disabled_reason: Option<String>,
    #[serde(default)]
    disabled_at: Option<i64>,
    #[serde(default)]
    protected_models: HashSet<String>,
    #[serde(default)]
    validation_blocked: bool,
    #[serde(default)]
    validation_blocked_until: Option<i64>,
    #[serde(default)]
    validation_blocked_reason: Option<String>,
    #[serde(default)]
    validation_url: Option<String>,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    last_used: i64,
    #[serde(default)]
    custom_label: Option<String>,
}

/// Strictly read-only migration from a legacy desktop `agy-switch` directory (e.g. `~/.antigravity_tools`).
/// NEVER writes, locks, or touches any file inside `legacy_dir`.
pub async fn import_from_legacy_dir(
    repo: &StoreRepository,
    legacy_dir: &Path,
    overwrite: bool,
    now_unix: i64,
) -> CliResult<ImportReport> {
    if crate::error::path_looks_like_accidental_secret(legacy_dir) {
        return Err(CliError::usage(
            "`--from-legacy` expects a filesystem directory path, not a literal credential value (redacted).",
        ));
    }
    if legacy_dir == repo.paths().data_dir {
        return Err(CliError::usage(
            "Source `--from-legacy` directory cannot be the same as target `--data-dir`.",
        ));
    }
    ensure_no_symlink_ancestors(legacy_dir)?;
    let meta = fs::symlink_metadata(legacy_dir).map_err(|e| {
        map_io_error(
            e,
            &format!("Cannot access legacy directory '{}'", legacy_dir.display()),
        )
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(CliError::usage(format!(
            "Legacy path '{}' must be a real directory, not a symlink or file.",
            legacy_dir.display()
        )));
    }

    let legacy_index_path = legacy_dir.join("accounts.json");
    let index_bytes =
        read_regular_file_bounded(&legacy_index_path, MAX_STORE_FILE_BYTES, "Legacy index")?;
    let legacy_index: LegacyIndex = serde_json::from_slice(&index_bytes).map_err(|e| {
        CliError::data(format_safe_json_error(
            &format!("Legacy '{}'", legacy_index_path.display()),
            &e,
        ))
    })?;

    let mut report = ImportReport {
        source: legacy_dir.to_string_lossy().into_owned(),
        imported_count: 0,
        updated_count: 0,
        skipped_count: 0,
        failed_count: 0,
        imported_ids: Vec::new(),
        updated_ids: Vec::new(),
        skipped_ids: Vec::new(),
        failures: Vec::new(),
    };

    let mut preferred_selected: Option<String> = None;

    for (idx, summary) in legacy_index.accounts.iter().enumerate() {
        if let Err(reason) = validate_account_id(&summary.id) {
            report.failed_count += 1;
            report.failures.push(ImportItemFailure {
                index: idx,
                identifier: Some(summary.id.clone()),
                reason,
            });
            continue;
        }
        let acc_path = legacy_dir
            .join("accounts")
            .join(format!("{}.json", summary.id));
        let bytes =
            match read_regular_file_bounded(&acc_path, MAX_STORE_FILE_BYTES, "Legacy account") {
                Ok(b) => b,
                Err(e) => {
                    report.failed_count += 1;
                    report.failures.push(ImportItemFailure {
                        index: idx,
                        identifier: Some(summary.id.clone()),
                        reason: format!("Cannot read legacy account file: {}", e.message),
                    });
                    continue;
                }
            };
        let leg: LegacyAccount = match serde_json::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                report.failed_count += 1;
                report.failures.push(ImportItemFailure {
                    index: idx,
                    identifier: Some(summary.id.clone()),
                    reason: format_safe_json_error("Legacy account file", &e),
                });
                continue;
            }
        };
        if leg.id != summary.id {
            report.failed_count += 1;
            report.failures.push(ImportItemFailure {
                index: idx,
                identifier: Some(summary.id.clone()),
                reason: "Legacy account ID does not match index entry.".into(),
            });
            continue;
        }
        if leg.token.refresh_token.trim().is_empty() {
            report.failed_count += 1;
            report.failures.push(ImportItemFailure {
                index: idx,
                identifier: Some(leg.id),
                reason: "Legacy account has empty refresh_token.".into(),
            });
            continue;
        }

        let disabled_code = if leg.disabled {
            let r = leg.disabled_reason.as_deref().unwrap_or("");
            if r.to_ascii_lowercase().contains("invalid_grant") {
                Some(DisableReasonCode::RevokedOrExpiredGrant)
            } else {
                Some(DisableReasonCode::Manual)
            }
        } else {
            None
        };

        let record = AccountRecord {
            schema_version: STORE_SCHEMA_VERSION,
            id: leg.id.clone(),
            email: leg.email,
            name: leg.name,
            custom_label: leg.custom_label,
            token: TokenRecord {
                access_token: leg.token.access_token,
                refresh_token: leg.token.refresh_token,
                expires_in: leg.token.expires_in.max(0),
                expiry_timestamp: if leg.token.expiry_timestamp > 0 {
                    leg.token.expiry_timestamp
                } else {
                    1
                },
                token_type: if leg.token.token_type.trim().is_empty() {
                    "Bearer".into()
                } else {
                    leg.token.token_type
                },
                id_token: leg.token.id_token,
                oauth_client_key: leg
                    .token
                    .oauth_client_key
                    .map(|k| k.trim().to_ascii_lowercase())
                    .filter(|k| !k.is_empty()),
                granted_scopes: None,
                project_id: leg.token.project_id.filter(|p| !p.trim().is_empty()),
                is_gcp_tos: leg.token.is_gcp_tos,
            },
            token_version: 1,
            auth_generation: 0,
            previous_refresh_token_digests: Vec::new(),
            quota: leg.quota,
            disabled: leg.disabled,
            disabled_code,
            disabled_detail: leg.disabled_reason,
            disabled_at: leg.disabled_at,
            validation_blocked: leg.validation_blocked,
            validation_blocked_until: leg.validation_blocked_until,
            validation_blocked_reason: leg.validation_blocked_reason,
            validation_url: leg.validation_url,
            protected_models: leg.protected_models,
            created_at: if leg.created_at > 0 {
                leg.created_at
            } else {
                now_unix
            },
            last_used: if leg.last_used > 0 {
                leg.last_used
            } else {
                now_unix
            },
        };

        let cand_id = summary.id.clone();
        match execute_locked_import_item(repo, Some(&cand_id), record, overwrite, false, now_unix)
            .await
        {
            Ok(ImportUpsertOutcome::Imported(saved)) => {
                if legacy_index.current_account_id.as_deref() == Some(summary.id.as_str()) {
                    preferred_selected = Some(saved.id.clone());
                }
                report.imported_count += 1;
                report.imported_ids.push(saved.id);
            }
            Ok(ImportUpsertOutcome::Updated(saved)) => {
                if legacy_index.current_account_id.as_deref() == Some(summary.id.as_str()) {
                    preferred_selected = Some(saved.id.clone());
                }
                report.updated_count += 1;
                report.updated_ids.push(saved.id);
            }
            Ok(ImportUpsertOutcome::SkippedDuplicate(existing)) => {
                if legacy_index.current_account_id.as_deref() == Some(summary.id.as_str()) {
                    preferred_selected = Some(existing.id.clone());
                }
                report.skipped_count += 1;
                report.skipped_ids.push(existing.id);
            }
            Err(e) => {
                report.failed_count += 1;
                report.failures.push(ImportItemFailure {
                    index: idx,
                    identifier: Some(summary.id.clone()),
                    reason: e.message,
                });
            }
        }
    }

    if report.imported_count > 0 || report.updated_count > 0 || report.skipped_count > 0 {
        repo.with_write_lock(|tx| {
            let mut index = tx.load_index_or_init(now_unix)?;
            if index.selected_account_id.is_none() {
                if let Some(ref sel) = preferred_selected {
                    if index.account_order.contains(sel) {
                        index.selected_account_id = Some(sel.clone());
                        tx.save_index(&mut index, now_unix)?;
                    }
                } else if let Some(first) = index.account_order.first().cloned() {
                    index.selected_account_id = Some(first);
                    tx.save_index(&mut index, now_unix)?;
                }
            }
            Ok(())
        })?;
    }

    Ok(report)
}

/// Private secret export (`0600` file, requires `--include-secrets`, refuses overwrite without `--overwrite`).
pub fn export_transfer_bundle_file(
    repo: &StoreRepository,
    output_path: &Path,
    include_secrets: bool,
    overwrite: bool,
    selectors: &[String],
) -> CliResult<usize> {
    if crate::error::path_looks_like_accidental_secret(output_path) {
        return Err(CliError::usage(
            "`--output` expects a filesystem file path, not a literal credential value (redacted).",
        ));
    }
    if !include_secrets {
        return Err(CliError::usage(
            "Exporting account refresh tokens requires explicit `--include-secrets` confirmation and `--output <FILE>`.",
        ));
    }

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_no_symlink_ancestors(parent)?;
        }
    }
    match fs::symlink_metadata(output_path) {
        Ok(meta) => {
            if !meta.file_type().is_file() {
                return Err(CliError::usage(format!(
                    "Export output '{}' must be a regular file path, not a symlink, FIFO, or directory.",
                    output_path.display()
                )));
            }
            if !overwrite {
                return Err(CliError::usage(format!(
                    "Export output '{}' already exists. Pass `--overwrite` to overwrite.",
                    output_path.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(map_io_error(
                e,
                &format!("Cannot inspect export path '{}'", output_path.display()),
            ))
        }
    }

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            ensure_private_dir(parent)?;
        }
    }

    let snapshot = repo.read_snapshot()?;
    let selected_records: Vec<&AccountRecord> = if selectors.is_empty() {
        snapshot.accounts.iter().collect()
    } else {
        let mut out = Vec::with_capacity(selectors.len());
        let mut seen = HashSet::new();
        for sel in selectors {
            let acc = select_from_slice(&snapshot.accounts, sel)?;
            if seen.insert(acc.id.as_str()) {
                out.push(acc);
            }
        }
        out
    };

    let bundle = TransferBundle {
        schema_version: TRANSFER_SCHEMA_VERSION,
        accounts: selected_records
            .iter()
            .map(|acc| TransferAccountItem {
                email: acc.email.clone(),
                refresh_token: acc.token.refresh_token.clone(),
                name: acc.name.clone(),
                oauth_client_key: acc.token.oauth_client_key.clone(),
                is_gcp_tos: acc.token.is_gcp_tos,
                project_id: acc.token.project_id.clone(),
                custom_label: acc.custom_label.clone(),
            })
            .collect(),
    };

    let count = bundle.accounts.len();
    let bytes = serde_json::to_vec_pretty(&bundle)
        .map_err(|_| CliError::data("Failed to serialize transfer bundle."))?;
    write_atomic_durable(output_path, &bytes)?;
    Ok(count)
}
