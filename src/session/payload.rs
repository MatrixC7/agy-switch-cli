use crate::domain::account::SessionIdentity;
use crate::domain::token::{extract_email_hint_from_jwt, token_digest, TokenRecord};
use crate::error::{format_safe_json_error, CliError, CliResult};
use crate::paths::hex_encode;
use crate::session::backend::SlotInspectState;
use crate::store::repository::StoreSnapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

/// Strict serializer for `~/.gemini/antigravity-cli/antigravity-oauth-token` per Blueprint §3.2.
/// Rejects empty tokens and non-positive `expiry_timestamp` instead of silently substituting `Utc::now()`.
pub fn serialize_session_payload(token: &TokenRecord) -> CliResult<String> {
    if token.access_token.trim().is_empty() || token.refresh_token.trim().is_empty() {
        return Err(CliError::data(
            "Invalid token payload: access_token or refresh_token is empty.",
        ));
    }
    if token.expiry_timestamp <= 0 {
        return Err(CliError::data(format!(
            "Invalid token expiry_timestamp ({}): must be positive Unix seconds.",
            token.expiry_timestamp
        )));
    }
    let expiry_datetime =
        chrono::DateTime::from_timestamp(token.expiry_timestamp, 0).ok_or_else(|| {
            CliError::data(format!(
                "Out-of-range token expiry_timestamp ({}).",
                token.expiry_timestamp
            ))
        })?;
    let expiry_rfc3339 = expiry_datetime.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    #[derive(Serialize)]
    struct TokenDetails<'a> {
        access_token: &'a str,
        token_type: &'a str,
        refresh_token: &'a str,
        expiry: String,
    }

    #[derive(Serialize)]
    struct Payload<'a> {
        token: TokenDetails<'a>,
        auth_method: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        id_token: Option<&'a str>,
    }

    serde_json::to_string(&Payload {
        token: TokenDetails {
            access_token: &token.access_token,
            token_type: "Bearer",
            refresh_token: &token.refresh_token,
            expiry: expiry_rfc3339,
        },
        auth_method: "consumer",
        id_token: token.id_token.as_deref(),
    })
    .map_err(|_| CliError::data("Failed to serialize session credential payload."))
}

#[derive(Clone)]
pub struct ParsedSessionPayload {
    pub raw_digest: String,
    pub refresh_token_digest: String,
    pub expiry: Option<String>,
    pub auth_method: Option<String>,
    pub email_hint: Option<String>,
}

impl fmt::Debug for ParsedSessionPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedSessionPayload")
            .field("raw_digest", &self.raw_digest)
            .field("refresh_token_digest", &self.refresh_token_digest)
            .field("expiry", &self.expiry)
            .field("auth_method", &self.auth_method)
            .field("email_hint", &self.email_hint)
            .finish()
    }
}

pub fn bytes_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

pub fn parse_session_payload_bytes(bytes: &[u8]) -> Result<ParsedSessionPayload, String> {
    let raw_str = std::str::from_utf8(bytes)
        .map_err(|_| "Active session file is not valid UTF-8.".to_string())?;
    let trimmed = raw_str.strip_prefix("go-keyring-base64:").and_then(|b64| {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD
            .decode(b64.trim())
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
    });
    let effective_json_str = trimmed.as_deref().unwrap_or(raw_str);

    let json: serde_json::Value = serde_json::from_str(effective_json_str)
        .map_err(|e| format_safe_json_error("Active session file", &e))?;

    let token_obj = json.get("token");
    let refresh_token = token_obj
        .and_then(|t| t.get("refresh_token"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("refresh_token").and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Active session JSON is missing a non-empty `refresh_token`.".to_string())?;

    let expiry = token_obj
        .and_then(|t| t.get("expiry"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let auth_method = json
        .get("auth_method")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let email_hint = json
        .get("id_token")
        .and_then(|v| v.as_str())
        .and_then(extract_email_hint_from_jwt);

    Ok(ParsedSessionPayload {
        raw_digest: bytes_sha256_hex(bytes),
        refresh_token_digest: token_digest(refresh_token),
        expiry,
        auth_method,
        email_hint,
    })
}

/// Compare real-time active slot state against local `StoreSnapshot` per Blueprint §2.2.
pub fn resolve_session_identity(
    slot_state: &SlotInspectState,
    snapshot: &StoreSnapshot,
) -> SessionIdentity {
    match slot_state {
        SlotInspectState::Uninitialized | SlotInspectState::AbsentInInitializedDir => {
            SessionIdentity::Uninitialized
        }
        SlotInspectState::Corrupt(detail) => SessionIdentity::Corrupt {
            detail: detail.clone(),
        },
        SlotInspectState::Unverified(detail) => SessionIdentity::Unverified {
            detail: detail.clone(),
        },
        SlotInspectState::Present(parsed) => {
            let selected_id = snapshot.index.selected_account_id.as_deref();
            // Check selected account first in case of identical refresh_token across imports
            if let Some(sel_id) = selected_id {
                if let Some(sel_acc) = snapshot.accounts.iter().find(|a| a.id == sel_id) {
                    if sel_acc.token.refresh_token_fingerprint() == parsed.refresh_token_digest {
                        return SessionIdentity::Matched {
                            account_id: sel_acc.id.clone(),
                            email: sel_acc.email.clone(),
                            expiry: parsed.expiry.clone().unwrap_or_default(),
                        };
                    }
                }
            }

            if let Some(other_acc) = snapshot
                .accounts
                .iter()
                .find(|a| a.token.refresh_token_fingerprint() == parsed.refresh_token_digest)
            {
                return SessionIdentity::DriftedKnown {
                    account_id: other_acc.id.clone(),
                    email: other_acc.email.clone(),
                    expiry: parsed.expiry.clone().unwrap_or_default(),
                };
            }

            SessionIdentity::DriftedExternal {
                email_hint: parsed.email_hint.clone(),
                expiry: parsed.expiry.clone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token(expiry_ts: i64) -> TokenRecord {
        TokenRecord {
            access_token: "fixture-access".into(),
            refresh_token: "fixture-refresh".into(),
            expires_in: 3600,
            expiry_timestamp: expiry_ts,
            token_type: "Bearer".into(),
            id_token: Some("fixture-id".into()),
            oauth_client_key: None,
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        }
    }

    #[test]
    fn payload_rejects_non_positive_expiry_and_matches_official_contract() {
        assert!(serialize_session_payload(&sample_token(0)).is_err());
        assert!(serialize_session_payload(&sample_token(-50)).is_err());

        let encoded = serialize_session_payload(&sample_token(1_700_000_000)).unwrap();
        let val: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            val,
            serde_json::json!({
                "token": {
                    "access_token": "fixture-access",
                    "token_type": "Bearer",
                    "refresh_token": "fixture-refresh",
                    "expiry": "2023-11-14T22:13:20.000000Z"
                },
                "auth_method": "consumer",
                "id_token": "fixture-id"
            })
        );
        let parsed = parse_session_payload_bytes(encoded.as_bytes()).unwrap();
        assert_eq!(parsed.refresh_token_digest, token_digest("fixture-refresh"));
    }
}
