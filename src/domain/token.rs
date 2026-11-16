use crate::paths::hex_encode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// OAuth token & RFC 6749 client-binding metadata.
/// Hand-implemented `fmt::Debug` guarantees plaintext tokens are NEVER printed to logs or panic messages.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    /// Must be a positive Unix timestamp in seconds.
    pub expiry_timestamp: i64,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// RFC 6749 client key bound to this token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_key: Option<String>,
    /// Scopes actually granted by the server; `None` if unknown (e.g., imported from bare refresh_token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_scopes: Option<Vec<String>>,
    /// Associated Google Cloud / CloudCode project ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default)]
    pub is_gcp_tos: bool,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl fmt::Debug for TokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRecord")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("expiry_timestamp", &self.expiry_timestamp)
            .field("token_type", &self.token_type)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("oauth_client_key", &self.oauth_client_key)
            .field("granted_scopes", &self.granted_scopes)
            .field("project_id", &self.project_id)
            .field("is_gcp_tos", &self.is_gcp_tos)
            .finish()
    }
}

impl TokenRecord {
    pub fn refresh_token_fingerprint(&self) -> String {
        token_digest(&self.refresh_token)
    }

    pub fn is_expiring_within(&self, now_unix: i64, skew_seconds: i64) -> bool {
        self.access_token.trim().is_empty()
            || self.expiry_timestamp <= now_unix.saturating_add(skew_seconds)
    }
}

pub fn token_digest(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.trim().as_bytes());
    hex_encode(&hasher.finalize())
}

pub fn parse_scope_string(raw: Option<&str>) -> Option<Vec<String>> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let mut scopes: Vec<String> = raw
        .split_whitespace()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        None
    } else {
        Some(scopes)
    }
}

/// Extract an unverified `email` claim hint from an OIDC `id_token` JWT solely for `DriftedExternal` display.
pub fn extract_email_hint_from_jwt(id_token: &str) -> Option<String> {
    let mut parts = id_token.trim().split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let _sig = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload_b64.trim_end_matches('='))
        .ok()?;
    let val: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    val.get("email")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_secrets() {
        let rec = TokenRecord {
            access_token: "ya29.super-secret-access".into(),
            refresh_token: "1//super-secret-refresh".into(),
            expires_in: 3600,
            expiry_timestamp: 1_800_000_000,
            token_type: "Bearer".into(),
            id_token: Some("eyJ.super-secret-id.sig".into()),
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: Some(vec!["openid".into()]),
            project_id: Some("proj-1".into()),
            is_gcp_tos: true,
        };
        let rendered = format!("{rec:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
