use crate::domain::quota::{QuotaObservation, QuotaSourceEnv};
use crate::domain::token::{token_digest, TokenRecord};
use crate::paths::hex_encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

pub const STORE_SCHEMA_VERSION: u32 = 1;
pub const TRANSFER_SCHEMA_VERSION: u32 = 2;
/// Inline superseded `refresh_token` SHA-256 digests kept directly in `accounts/<id>.json` (~35 KiB max);
/// older digests beyond `512` are spilled into `<data_dir>/state/token_lineage/<id>.json` (`MAX_ARCHIVED_RT_DIGESTS = 65_536`).
pub const MAX_PREVIOUS_RT_DIGESTS: usize = 512;
pub const MAX_ARCHIVED_RT_DIGESTS: usize = 65_536;
/// In-memory retention cap (`512 + 65,536 + 1 = 66,049`): keeping `+ 1` sentinel slot ensures that whenever
/// in-memory transitions exceed total inline + archive capacity (`66,048`), both in-memory checks (`len >= MAX_IN_MEMORY_RT_DIGESTS`)
/// and `StoreWriteTx::save_account` (`overflow > MAX_ARCHIVED_RT_DIGESTS`) deterministically observe truncation and set `truncated = true`.
pub const MAX_IN_MEMORY_RT_DIGESTS: usize = MAX_PREVIOUS_RT_DIGESTS + MAX_ARCHIVED_RT_DIGESTS + 1;

/// Validate `AccountId` strictly against path traversal and control chars (`[A-Za-z0-9_-]{1,128}`).
pub fn validate_account_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 128 {
        return Err("Account ID must be 1..=128 ASCII characters.".to_string());
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Account ID may contain only ASCII letters, digits, '-' and '_'.".to_string());
    }
    Ok(())
}

/// 1. Account store index (`index.json`, schema_version: 1)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreIndex {
    pub schema_version: u32,
    pub revision: u64,
    pub selected_account_id: Option<String>,
    pub account_order: Vec<String>,
    pub updated_at: i64,
}

impl StoreIndex {
    pub fn new(now_unix: i64) -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            revision: 0,
            selected_account_id: None,
            account_order: Vec::new(),
            updated_at: now_unix,
        }
    }
}

/// Structured disable reason code per Blueprint §2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisableReasonCode {
    Manual,
    RevokedOrExpiredGrant,
    ScopeReauthRequired,
    AccountSuspended,
}

/// 2. Individual account file (`accounts/<id>.json`, schema_version: 1)
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub schema_version: u32,
    pub id: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    pub token: TokenRecord,
    #[serde(default)]
    pub token_version: u64,
    /// Monotonically advancing authorization grant generation on this account.
    /// Strictly decoupled from routine `token_version` refreshes (`merge_refreshed_token`);
    /// advances ONLY when a new authorization grant (`reauthorize`, `login`/`add` token bind,
    /// or `import --overwrite` with a genuinely new external `refresh_token`) takes effect.
    #[serde(default)]
    pub auth_generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_refresh_token_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<QuotaObservation>,

    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_code: Option<DisableReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<i64>,

    #[serde(default)]
    pub validation_blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_until: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_url: Option<String>,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub protected_models: HashSet<String>,

    pub created_at: i64,
    pub last_used: i64,
}

impl fmt::Debug for AccountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountRecord")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("custom_label", &self.custom_label)
            .field("token", &self.token)
            .field("token_version", &self.token_version)
            .field("auth_generation", &self.auth_generation)
            .field(
                "previous_rt_count",
                &self.previous_refresh_token_digests.len(),
            )
            .field("has_quota", &self.quota.is_some())
            .field("disabled", &self.disabled)
            .field("disabled_code", &self.disabled_code)
            .field(
                "disabled_detail",
                &self.disabled_detail.as_ref().map(|_| "[REDACTED]"),
            )
            .field("disabled_at", &self.disabled_at)
            .field("validation_blocked", &self.validation_blocked)
            .field(
                "validation_url",
                &self.validation_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .finish()
    }
}

impl AccountRecord {
    pub fn new(id: String, email: String, token: TokenRecord, now_unix: i64) -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            id,
            email,
            name: None,
            custom_label: None,
            token,
            token_version: 1,
            auth_generation: 0,
            previous_refresh_token_digests: Vec::new(),
            quota: None,
            disabled: false,
            disabled_code: None,
            disabled_detail: None,
            disabled_at: None,
            validation_blocked: false,
            validation_blocked_until: None,
            validation_blocked_reason: None,
            validation_url: None,
            protected_models: HashSet::new(),
            created_at: now_unix,
            last_used: now_unix,
        }
    }

    pub fn is_validation_blocked_at(&self, now_unix: i64) -> bool {
        self.validation_blocked
            && self
                .validation_blocked_until
                .is_none_or(|until| until > now_unix)
    }

    pub fn is_usable_at(&self, now_unix: i64) -> bool {
        !self.disabled
            && !self.is_validation_blocked_at(now_unix)
            && !self.quota.as_ref().is_some_and(|q| q.is_forbidden)
    }

    pub fn is_usable(&self) -> bool {
        self.is_usable_at(chrono::Utc::now().timestamp())
    }

    /// Record a token update/rotation, tracking superseded `refresh_token` SHA-256 digests so
    /// stale backups or delayed retries can NEVER roll back a server-rotated `refresh_token`.
    /// Up to `MAX_PREVIOUS_RT_DIGESTS` (`512`) are kept inline in `accounts/<id>.json`, while older
    /// digests are durably spilled into `<data_dir>/state/token_lineage/<id>.json` by `StoreWriteTx::save_account`.
    pub fn record_token_transition(&mut self, new_token: TokenRecord) {
        let old_rt_trimmed = self.token.refresh_token.trim();
        let new_rt_trimmed = new_token.refresh_token.trim();
        if !old_rt_trimmed.is_empty() && old_rt_trimmed != new_rt_trimmed {
            let old_fp = token_digest(old_rt_trimmed);
            self.previous_refresh_token_digests.retain(|d| d != &old_fp);
            self.previous_refresh_token_digests.push(old_fp);
            if self.previous_refresh_token_digests.len() > MAX_IN_MEMORY_RT_DIGESTS {
                let excess = self.previous_refresh_token_digests.len() - MAX_IN_MEMORY_RT_DIGESTS;
                self.previous_refresh_token_digests.drain(0..excess);
            }
        }
        self.token_version = self.token_version.saturating_add(1).max(1);
        self.token = new_token;
    }

    /// Record an already-computed SHA-256 `refresh_token` digest as superseded (e.g. from a `PendingAuthRecord`
    /// whose initial or intermediate `refresh_token` rotated prior to account binding).
    pub fn record_superseded_digest(&mut self, digest: &str) {
        let trimmed = digest.trim();
        if trimmed.is_empty() {
            return;
        }
        let current_fp = self.token.refresh_token_fingerprint();
        if trimmed == current_fp {
            return;
        }
        self.previous_refresh_token_digests.retain(|d| d != trimmed);
        self.previous_refresh_token_digests
            .push(trimmed.to_string());
        if self.previous_refresh_token_digests.len() > MAX_IN_MEMORY_RT_DIGESTS {
            let excess = self.previous_refresh_token_digests.len() - MAX_IN_MEMORY_RT_DIGESTS;
            self.previous_refresh_token_digests.drain(0..excess);
        }
    }

    /// Returns `true` if `candidate_rt` matches a previously superseded (rotated-away) `refresh_token`.
    pub fn has_superseded_refresh_token(&self, candidate_rt: &str) -> bool {
        let trimmed = candidate_rt.trim();
        if trimmed.is_empty() {
            return false;
        }
        let fp = token_digest(trimmed);
        self.previous_refresh_token_digests.iter().any(|d| d == &fp)
    }

    /// Update quota while preserving previously discovered `subscription_tier` ONLY when the
    /// previous tier explicitly recorded `tier_source_env == Some(quota.source_env)` (preventing
    /// untagged or cross-environment `Free` tier pollution).
    pub fn update_quota(&mut self, mut quota: QuotaObservation) {
        if let Some(ref existing) = self.quota {
            if quota.subscription_tier.is_none()
                && quota.source_env != QuotaSourceEnv::LegacyUnknown
                && existing.tier_source_env == Some(quota.source_env)
            {
                quota.subscription_tier = existing.subscription_tier.clone();
                if quota.subscription_tier.is_some() {
                    quota.tier_source_env = Some(quota.source_env);
                }
            }
        }
        self.quota = Some(quota);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingAuthFlow {
    AddToken,
    Login,
    Reauthorize { target_account_id: String },
}

/// Returns `true` when a staged `PendingAuthRecord` (`pending_auth_seq`) is older than or equal to
/// an already-committed authorization generation (`account_auth_generation`) on the target account.
/// Legacy pre-upgrade accounts (`account_auth_generation == 0`) allow a legacy pending (`pending_auth_seq == 0`)
/// to bind once (advancing `auth_generation` to `1`), whereas any committed authorization (`account_auth_generation > 0`)
/// rejects all earlier or legacy pendings (`pending_auth_seq <= account_auth_generation`).
pub fn is_pending_superseded_by_account(
    pending_auth_seq: u64,
    account_auth_generation: u64,
) -> bool {
    account_auth_generation > 0 && pending_auth_seq <= account_auth_generation
}

/// Compute the next `auth_generation` when committing a non-superseded `PendingAuthRecord` onto an account.
pub fn next_account_auth_generation_for_pending(
    prev_account_generation: u64,
    pending_auth_seq: u64,
) -> u64 {
    prev_account_generation
        .saturating_add(1)
        .max(pending_auth_seq)
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Durable `0600` pre-userinfo token staging record (`<data_dir>/state/pending_auth/<id>.json`).
/// Ensures newly issued or rotated tokens from `/token` are persisted BEFORE any auxiliary `userinfo` await!
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingAuthRecord {
    pub schema_version: u32,
    pub id: String,
    pub flow: PendingAuthFlow,
    pub token: TokenRecord,
    /// Monotonic store-wide authorization sequence assigned once when this pending grant is first staged
    /// (never rewritten when refreshing an expiring pending `access_token`, and independent of wall-clock `created_at`).
    #[serde(default)]
    pub auth_seq: u64,
    /// Set to `true` once `userinfo` proves a staged `Reauthorize` token belongs to a different Google email
    /// than `target_account_id`, so subsequent reauthorizations of `target_account_id` never delete the preserved
    /// foreign token or pollute `target_account_id`'s superseded `refresh_token` lineage with another user's token.
    #[serde(default, skip_serializing_if = "is_false")]
    pub email_mismatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_rt_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    pub created_at: i64,
}

impl PendingAuthRecord {
    /// Collision-resistant SHA-256 compare-and-swap fingerprint over the exact token, flow, & `auth_seq` snapshot
    /// stored in this `PendingAuthRecord` (used to reject stale concurrent binders or deleters at `L3`).
    pub fn cas_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update([0]);
        match &self.flow {
            PendingAuthFlow::AddToken => hasher.update(b"add_token"),
            PendingAuthFlow::Login => hasher.update(b"login"),
            PendingAuthFlow::Reauthorize { target_account_id } => {
                hasher.update(b"reauthorize:");
                hasher.update(target_account_id.as_bytes());
            }
        }
        hasher.update([0]);
        hasher.update(self.auth_seq.to_le_bytes());
        hasher.update([0]);
        if self.email_mismatch {
            hasher.update(b"email_mismatch:1");
            hasher.update([0]);
        }
        hasher.update(self.token.refresh_token.trim().as_bytes());
        hasher.update([0]);
        hasher.update(self.token.access_token.trim().as_bytes());
        hasher.update([0]);
        hasher.update(self.token.expiry_timestamp.to_le_bytes());
        hasher.update([0]);
        if let Some(ref key) = self.token.oauth_client_key {
            hasher.update(key.as_bytes());
        }
        hasher.update([0]);
        if let Some(ref scopes) = self.token.granted_scopes {
            for sc in scopes {
                hasher.update(sc.as_bytes());
                hasher.update(b" ");
            }
        }
        hasher.update([0]);
        if let Some(ref inp) = self.input_rt_digest {
            hasher.update(inp.as_bytes());
        }
        hex_encode(&hasher.finalize())
    }
}

impl fmt::Debug for PendingAuthRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuthRecord")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("flow", &self.flow)
            .field("auth_seq", &self.auth_seq)
            .field("email_mismatch", &self.email_mismatch)
            .field("token", &self.token)
            .field("input_rt_digest", &self.input_rt_digest)
            .field("custom_label", &self.custom_label)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// 4. Cross-machine transfer bundle (reads v0/v1/v2, writes v2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferBundle {
    #[serde(default)]
    pub schema_version: u32,
    pub accounts: Vec<TransferAccountItem>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferAccountItem {
    #[serde(default)]
    pub email: String,
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_key: Option<String>,
    #[serde(default)]
    pub is_gcp_tos: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
}

impl fmt::Debug for TransferAccountItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferAccountItem")
            .field("email", &self.email)
            .field("refresh_token", &"[REDACTED]")
            .field("name", &self.name)
            .field("oauth_client_key", &self.oauth_client_key)
            .field("is_gcp_tos", &self.is_gcp_tos)
            .field("project_id", &self.project_id)
            .field("custom_label", &self.custom_label)
            .finish()
    }
}

/// Dimension 2 of tri-state current identity (`session_identity`) per Blueprint §2.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionIdentity {
    Matched {
        account_id: String,
        email: String,
        expiry: String,
    },
    DriftedKnown {
        account_id: String,
        email: String,
        expiry: String,
    },
    DriftedExternal {
        #[serde(skip_serializing_if = "Option::is_none")]
        email_hint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expiry: Option<String>,
    },
    Uninitialized,
    Corrupt {
        detail: String,
    },
    Unverified {
        detail: String,
    },
}

/// Dimension 3 of tri-state current identity (`runtime_state`) per Blueprint §2.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RuntimeState {
    Idle,
    ManagedRunning {
        count: usize,
        account_ids: Vec<String>,
        pids: Vec<u32>,
    },
    UnmanagedRunning {
        pids: Vec<u32>,
        identity: String, // Always "unknown"
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        managed_account_ids: Vec<String>,
    },
    Unverified {
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_validation_blocks_traversal_and_special_chars() {
        assert!(validate_account_id("acc-123_ABC").is_ok());
        assert!(validate_account_id("").is_err());
        assert!(validate_account_id("../etc/passwd").is_err());
        assert!(validate_account_id("acc/1").is_err());
        assert!(validate_account_id("acc.json").is_err());
        assert!(validate_account_id("acc 1").is_err());
    }
}
