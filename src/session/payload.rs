use crate::domain::account::{AccountRecord, SessionIdentity};
use crate::domain::quota::QuotaSourceEnv;
use crate::domain::token::{
    extract_email_hint_from_jwt, sanitize_email_hint, token_digest, TokenRecord,
};
use crate::error::{format_safe_json_error, CliError, CliResult};
use crate::paths::hex_encode;
use crate::session::backend::SlotInspectState;
use crate::store::repository::StoreSnapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

const MAX_USER_TIER_BYTES: usize = 128;
const MAX_AUTH_METHOD_BYTES: usize = 64;
const MAX_EXPIRY_BYTES: usize = 64;

fn sanitize_bounded_meta_field(raw: &str, max_bytes: usize) -> Option<String> {
    if raw.len() > max_bytes || raw.chars().any(|c| c.is_control()) {
        return None;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
}

fn validate_required_session_secret_field<'a>(
    raw: &'a str,
    field_name: &str,
    source_desc: &str,
) -> Result<&'a str, String> {
    if raw.len() > crate::cli::secret_input::MAX_SECRET_BYTES {
        return Err(format!(
            "{source_desc} `{field_name}` exceeds maximum allowed size ({} bytes).",
            crate::cli::secret_input::MAX_SECRET_BYTES
        ));
    }
    if raw.chars().any(|c| c.is_control()) {
        return Err(format!(
            "{source_desc} `{field_name}` contains invalid control characters."
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{source_desc} is missing a non-empty `{field_name}`."
        ));
    }
    Ok(trimmed)
}

fn validate_optional_session_secret_field<'a>(
    raw_opt: Option<&'a str>,
    field_name: &str,
    source_desc: &str,
) -> Result<Option<&'a str>, String> {
    let Some(raw) = raw_opt else {
        return Ok(None);
    };
    if raw.len() > crate::cli::secret_input::MAX_SECRET_BYTES {
        return Err(format!(
            "{source_desc} `{field_name}` exceeds maximum allowed size ({} bytes).",
            crate::cli::secret_input::MAX_SECRET_BYTES
        ));
    }
    if raw.chars().any(|c| c.is_control()) {
        return Err(format!(
            "{source_desc} `{field_name}` contains invalid control characters."
        ));
    }
    let trimmed = raw.trim();
    Ok((!trimmed.is_empty()).then_some(trimmed))
}

/// Strict serializer for `~/.gemini/antigravity-cli/antigravity-oauth-token` per Blueprint §3.2.
/// Rejects empty `refresh_token`, non-positive `expiry_timestamp`, overlong (>16,384 B) tokens,
/// and control characters. Permits empty `access_token` (e.g. accounts imported from refresh-only
/// transfer bundles) so offline `switch` can write the slot and let official `agy` refresh on launch.
pub fn serialize_session_payload(token: &TokenRecord) -> CliResult<String> {
    serialize_session_payload_with_meta(token, None, None, None)
}

/// Serialize the active official `agy` slot payload for a verified `AccountRecord`, preserving
/// compact `id_token_email` and any production-trusted `user_tier` (`OfficialCli` / `Production`)
/// so offline `accounts add --from-local` round-trips cleanly after `switch` or `run`.
pub fn serialize_session_payload_for_account(account: &AccountRecord) -> CliResult<String> {
    let user_tier = account.quota.as_ref().and_then(|q| {
        let trusted = matches!(
            q.tier_source_env,
            Some(QuotaSourceEnv::OfficialCli) | Some(QuotaSourceEnv::Production)
        );
        trusted.then_some(q.subscription_tier.as_deref()).flatten()
    });
    serialize_session_payload_with_meta(
        &account.token,
        None,
        Some(account.email.as_str()),
        user_tier,
    )
}

/// Strict serializer for `antigravity-oauth-token` payloads with optional metadata (`auth_method`,
/// compact `id_token_email` used by official `agy 1.5+`, and optional `user_tier`).
pub fn serialize_session_payload_with_meta(
    token: &TokenRecord,
    auth_method: Option<&str>,
    id_token_email: Option<&str>,
    user_tier: Option<&str>,
) -> CliResult<String> {
    let access_token = validate_optional_session_secret_field(
        Some(token.access_token.as_str()),
        "access_token",
        "Session token payload",
    )
    .map_err(CliError::data)?
    .unwrap_or("");
    let refresh_token = validate_required_session_secret_field(
        &token.refresh_token,
        "refresh_token",
        "Session token payload",
    )
    .map_err(CliError::data)?;
    let id_token = validate_optional_session_secret_field(
        token.id_token.as_deref(),
        "id_token",
        "Session token payload",
    )
    .map_err(CliError::data)?;
    if token.expiry_timestamp <= 0 {
        return Err(CliError::data(format!(
            "Invalid token expiry_timestamp ({}): must be positive Unix seconds.",
            token.expiry_timestamp
        )));
    }
    let expiry_rfc3339 = crate::domain::clock::format_unix_rfc3339_micros_utc(
        token.expiry_timestamp,
    )
    .ok_or_else(|| {
        CliError::data(format!(
            "Out-of-range token expiry_timestamp ({}).",
            token.expiry_timestamp
        ))
    })?;

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
        #[serde(skip_serializing_if = "Option::is_none")]
        id_token_email: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_tier: Option<&'a str>,
    }

    let effective_auth_method = auth_method
        .and_then(|s| sanitize_bounded_meta_field(s, MAX_AUTH_METHOD_BYTES))
        .unwrap_or_else(|| "consumer".to_string());
    let effective_email = id_token_email.and_then(sanitize_email_hint);
    let effective_tier =
        user_tier.and_then(|s| sanitize_bounded_meta_field(s, MAX_USER_TIER_BYTES));

    serde_json::to_string(&Payload {
        token: TokenDetails {
            access_token,
            token_type: "Bearer",
            refresh_token,
            expiry: expiry_rfc3339,
        },
        auth_method: &effective_auth_method,
        id_token,
        id_token_email: effective_email.as_deref(),
        user_tier: effective_tier.as_deref(),
    })
    .map_err(|_| CliError::data("Failed to serialize session credential payload."))
}

fn extract_compact_id_token_email_from_session_json(json: &serde_json::Value) -> Option<String> {
    json.get("id_token_email")
        .and_then(|v| v.as_str())
        .and_then(sanitize_email_hint)
}

fn extract_email_hint_from_session_json(
    json: &serde_json::Value,
    compact_id_token_email: Option<&str>,
) -> Option<String> {
    json.get("id_token")
        .and_then(|v| v.as_str())
        .and_then(extract_email_hint_from_jwt)
        .or_else(|| compact_id_token_email.map(str::to_owned))
}

fn extract_user_tier_from_session_json(json: &serde_json::Value) -> Option<String> {
    json.get("user_tier")
        .and_then(|v| v.as_str())
        .and_then(|s| sanitize_bounded_meta_field(s, MAX_USER_TIER_BYTES))
}

#[derive(Clone)]
pub struct ParsedSessionPayload {
    pub raw_digest: String,
    pub refresh_token_digest: String,
    pub expiry: Option<String>,
    pub auth_method: Option<String>,
    pub email_hint: Option<String>,
    pub user_tier: Option<String>,
}

impl fmt::Debug for ParsedSessionPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedSessionPayload")
            .field("raw_digest", &self.raw_digest)
            .field("refresh_token_digest", &self.refresh_token_digest)
            .field("expiry", &self.expiry)
            .field("auth_method", &self.auth_method)
            .field("email_hint", &self.email_hint)
            .field("user_tier", &self.user_tier)
            .finish()
    }
}

pub fn bytes_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

/// Extract the raw `refresh_token` from an official Antigravity session JSON payload
/// (supporting optional `go-keyring-base64:` prefix and both `token.refresh_token` and top-level `refresh_token`).
/// Caller MUST treat the returned string as a secret and never echo or log it.
pub fn extract_raw_refresh_token_from_session_bytes(
    bytes: &[u8],
    source_desc: &str,
) -> CliResult<String> {
    let raw_str = std::str::from_utf8(bytes)
        .map_err(|_| CliError::data(format!("{source_desc} is not valid UTF-8.")))?;
    let trimmed = raw_str.strip_prefix("go-keyring-base64:").and_then(|b64| {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD
            .decode(b64.trim())
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
    });
    let effective_json_str = trimmed.as_deref().unwrap_or(raw_str);

    let json: serde_json::Value = serde_json::from_str(effective_json_str)
        .map_err(|e| CliError::data(format_safe_json_error(source_desc, &e)))?;

    let token_obj = json.get("token");
    let raw_refresh_token = token_obj
        .and_then(|t| t.get("refresh_token"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("refresh_token").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            CliError::data(format!(
                "{source_desc} JSON is missing a non-empty `refresh_token`."
            ))
        })?;
    let refresh_token =
        validate_required_session_secret_field(raw_refresh_token, "refresh_token", source_desc)
            .map_err(CliError::data)?;

    let raw_access_token = token_obj
        .and_then(|t| t.get("access_token"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("access_token").and_then(|v| v.as_str()));
    let _ = validate_optional_session_secret_field(raw_access_token, "access_token", source_desc)
        .map_err(CliError::data)?;

    let raw_id_token = json.get("id_token").and_then(|v| v.as_str());
    let _ = validate_optional_session_secret_field(raw_id_token, "id_token", source_desc)
        .map_err(CliError::data)?;

    Ok(refresh_token.to_string())
}

/// Full parsed representation of an official `antigravity-oauth-token` / keyring payload used for
/// offline `--from-local` import and local pre-switch / post-`/usage` sync-back.
/// Sensitive fields are redacted in `Debug` output.
#[derive(Clone)]
pub struct ExtractedSessionToken {
    pub access_token: Option<String>,
    pub refresh_token: String,
    pub expiry: Option<String>,
    pub expiry_unix: Option<i64>,
    pub auth_method: Option<String>,
    pub id_token: Option<String>,
    /// Preserved compact `id_token_email` field from `agy 1.5+` (distinct from JWT-derived `email_hint`).
    pub id_token_email: Option<String>,
    /// Derived email hint (`id_token` JWT `email` claim, falling back to `id_token_email`).
    pub email_hint: Option<String>,
    pub user_tier: Option<String>,
    pub raw_digest: String,
    pub refresh_token_digest: String,
}

impl fmt::Debug for ExtractedSessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractedSessionToken")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("refresh_token", &"[REDACTED]")
            .field("expiry", &self.expiry)
            .field("expiry_unix", &self.expiry_unix)
            .field("auth_method", &self.auth_method)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("id_token_email", &self.id_token_email)
            .field("email_hint", &self.email_hint)
            .field("user_tier", &self.user_tier)
            .field("raw_digest", &self.raw_digest)
            .field("refresh_token_digest", &self.refresh_token_digest)
            .finish()
    }
}

pub fn extract_session_token_from_bytes(
    bytes: &[u8],
    source_desc: &str,
) -> CliResult<ExtractedSessionToken> {
    let raw_str = std::str::from_utf8(bytes)
        .map_err(|_| CliError::data(format!("{source_desc} is not valid UTF-8.")))?;
    let trimmed = raw_str.strip_prefix("go-keyring-base64:").and_then(|b64| {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD
            .decode(b64.trim())
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
    });
    let effective_json_str = trimmed.as_deref().unwrap_or(raw_str);

    let json: serde_json::Value = serde_json::from_str(effective_json_str)
        .map_err(|e| CliError::data(format_safe_json_error(source_desc, &e)))?;

    let token_obj = json.get("token");
    let raw_refresh_token = token_obj
        .and_then(|t| t.get("refresh_token"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("refresh_token").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            CliError::data(format!(
                "{source_desc} JSON is missing a non-empty `refresh_token`."
            ))
        })?;
    let refresh_token =
        validate_required_session_secret_field(raw_refresh_token, "refresh_token", source_desc)
            .map_err(CliError::data)?;

    let raw_access_token = token_obj
        .and_then(|t| t.get("access_token"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("access_token").and_then(|v| v.as_str()));
    let access_token =
        validate_optional_session_secret_field(raw_access_token, "access_token", source_desc)
            .map_err(CliError::data)?
            .map(str::to_owned);
    let expiry = token_obj
        .and_then(|t| t.get("expiry"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("expiry").and_then(|v| v.as_str()))
        .and_then(|s| sanitize_bounded_meta_field(s, MAX_EXPIRY_BYTES));
    let expiry_unix = expiry
        .as_deref()
        .and_then(crate::domain::clock::parse_rfc3339_unix_seconds);
    let auth_method = json
        .get("auth_method")
        .and_then(|v| v.as_str())
        .and_then(|s| sanitize_bounded_meta_field(s, MAX_AUTH_METHOD_BYTES));
    let raw_id_token = json.get("id_token").and_then(|v| v.as_str());
    let id_token = validate_optional_session_secret_field(raw_id_token, "id_token", source_desc)
        .map_err(CliError::data)?
        .map(str::to_owned);
    let id_token_email = extract_compact_id_token_email_from_session_json(&json);
    let email_hint = extract_email_hint_from_session_json(&json, id_token_email.as_deref());
    let user_tier = extract_user_tier_from_session_json(&json);

    Ok(ExtractedSessionToken {
        access_token,
        refresh_token: refresh_token.to_string(),
        expiry,
        expiry_unix,
        auth_method,
        id_token,
        id_token_email,
        email_hint,
        user_tier,
        raw_digest: bytes_sha256_hex(bytes),
        refresh_token_digest: token_digest(refresh_token),
    })
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
    let raw_refresh_token = token_obj
        .and_then(|t| t.get("refresh_token"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("refresh_token").and_then(|v| v.as_str()))
        .ok_or_else(|| "Active session JSON is missing a non-empty `refresh_token`.".to_string())?;
    let refresh_token = validate_required_session_secret_field(
        raw_refresh_token,
        "refresh_token",
        "Active session JSON",
    )?;
    let raw_access_token = token_obj
        .and_then(|t| t.get("access_token"))
        .and_then(|v| v.as_str())
        .or_else(|| json.get("access_token").and_then(|v| v.as_str()));
    let _ = validate_optional_session_secret_field(
        raw_access_token,
        "access_token",
        "Active session JSON",
    )?;
    let raw_id_token = json.get("id_token").and_then(|v| v.as_str());
    let _ =
        validate_optional_session_secret_field(raw_id_token, "id_token", "Active session JSON")?;

    let expiry = token_obj
        .and_then(|t| t.get("expiry"))
        .and_then(|v| v.as_str())
        .and_then(|s| sanitize_bounded_meta_field(s, MAX_EXPIRY_BYTES));
    let auth_method = json
        .get("auth_method")
        .and_then(|v| v.as_str())
        .and_then(|s| sanitize_bounded_meta_field(s, MAX_AUTH_METHOD_BYTES));
    let compact_email = extract_compact_id_token_email_from_session_json(&json);
    let email_hint = extract_email_hint_from_session_json(&json, compact_email.as_deref());
    let user_tier = extract_user_tier_from_session_json(&json);

    Ok(ParsedSessionPayload {
        raw_digest: bytes_sha256_hex(bytes),
        refresh_token_digest: token_digest(refresh_token),
        expiry,
        auth_method,
        email_hint,
        user_tier,
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

        // Official `agy 1.5+` compact `id_token_email` + `user_tier` fallback when `id_token` JWT is absent
        let compact = br#"{"token":{"access_token":"ya29.c","token_type":"Bearer","refresh_token":"1//rt-c","expiry":"2099-01-01T00:00:00Z"},"auth_method":"consumer","id_token_email":"alice@example.com","user_tier":"PRO"}"#;
        let parsed_compact = parse_session_payload_bytes(compact).unwrap();
        assert_eq!(
            parsed_compact.email_hint.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(parsed_compact.user_tier.as_deref(), Some("PRO"));
        let extracted_compact = extract_session_token_from_bytes(compact, "slot").unwrap();
        assert_eq!(
            extracted_compact.id_token_email.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            extracted_compact.email_hint.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(extracted_compact.user_tier.as_deref(), Some("PRO"));

        // P2-04: JWT and compact `id_token_email` coexist with different values ->
        // display `email_hint` prefers JWT while `id_token_email` preserves original compact field.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let mk_jwt = |email: &str| {
            let hdr = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
            let pay = URL_SAFE_NO_PAD.encode(serde_json::json!({"email": email}).to_string());
            format!("{hdr}.{pay}.sig")
        };
        let both_json = serde_json::json!({
            "token": {"access_token": "ya29.b", "token_type": "Bearer", "refresh_token": "1//rt-b", "expiry": "2099-01-01T00:00:00Z"},
            "auth_method": "consumer",
            "id_token": mk_jwt("jwt-user@example.com"),
            "id_token_email": "compact-user@example.com",
            "user_tier": "ULTRA"
        });
        let both_bytes = serde_json::to_vec(&both_json).unwrap();
        let ex_both = extract_session_token_from_bytes(&both_bytes, "slot").unwrap();
        assert_eq!(ex_both.email_hint.as_deref(), Some("jwt-user@example.com"));
        assert_eq!(
            ex_both.id_token_email.as_deref(),
            Some("compact-user@example.com")
        );
        let rewritten = serialize_session_payload_with_meta(
            &sample_token(1_800_000_000),
            ex_both.auth_method.as_deref(),
            ex_both.id_token_email.as_deref(),
            ex_both.user_tier.as_deref(),
        )
        .unwrap();
        let rewritten_val: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        assert_eq!(rewritten_val["id_token_email"], "compact-user@example.com");

        // Offline switch for transfer-bundle imported accounts (`access_token == ""`, `expiry_timestamp == 1`)
        let mut empty_at_tok = sample_token(1);
        empty_at_tok.access_token = String::new();
        let encoded_empty_at = serialize_session_payload(&empty_at_tok).unwrap();
        let empty_at_val: serde_json::Value = serde_json::from_str(&encoded_empty_at).unwrap();
        assert_eq!(empty_at_val["token"]["access_token"], "");
        assert_eq!(
            empty_at_val["token"]["expiry"],
            "1970-01-01T00:00:01.000000Z"
        );

        // Bad JWT or JWT with internal OR trailing control characters (LF/CR/TAB) falls back cleanly to `id_token_email`.
        for (bad_jwt, bad_tier) in [
            ("not-a-jwt".to_string(), "PRO\x07"),
            (mk_jwt("evil\x1b[31m@example.com"), "PRO\n"),
            (mk_jwt("trailing-lf@example.com\n"), "\rPRO"),
            (mk_jwt("trailing-tab@example.com\t"), "PRO\t"),
            (
                mk_jwt(&format!("{}@example.com", "a".repeat(320))),
                "ULTRA\n",
            ),
        ] {
            let payload_json = serde_json::json!({
                "token": {"access_token": "ya29.x", "token_type": "Bearer", "refresh_token": "1//rt-x", "expiry": "2099-01-01T00:00:00Z"},
                "id_token": bad_jwt,
                "id_token_email": "fallback@example.com",
                "user_tier": bad_tier
            });
            let raw = serde_json::to_vec(&payload_json).unwrap();
            let parsed_fb = parse_session_payload_bytes(&raw).unwrap();
            assert_eq!(
                parsed_fb.email_hint.as_deref(),
                Some("fallback@example.com")
            );
            assert_eq!(parsed_fb.user_tier, None);
            let ex_fb = extract_session_token_from_bytes(&raw, "slot").unwrap();
            assert_eq!(ex_fb.email_hint.as_deref(), Some("fallback@example.com"));
            assert_eq!(
                ex_fb.id_token_email.as_deref(),
                Some("fallback@example.com")
            );
            assert_eq!(ex_fb.user_tier, None);
        }

        // R2-03: Unified length & control-char bounds on raw credential fields across read, extract, and serialize (zero echo!)
        let huge_secret =
            "1//".to_string() + &"a".repeat(crate::cli::secret_input::MAX_SECRET_BYTES);
        for (label, raw_json) in [
            (
                "overlong_rt",
                serde_json::json!({"token": {"refresh_token": huge_secret}}),
            ),
            (
                "lf_rt",
                serde_json::json!({"token": {"refresh_token": "1//rt-bad-LF-SECRET\n"}}),
            ),
            (
                "ctrl_at",
                serde_json::json!({"token": {"refresh_token": "1//rt-ok", "access_token": "ya29.bad-AT-SECRET\n"}}),
            ),
            (
                "top_level_ctrl_at",
                serde_json::json!({"refresh_token": "1//rt-ok", "access_token": "ya29.bad-TOP-AT-SECRET\t"}),
            ),
            (
                "ctrl_id",
                serde_json::json!({"token": {"refresh_token": "1//rt-ok"}, "id_token": "eyJ.bad-ID-SECRET\n"}),
            ),
            (
                "c1_ctrl_id",
                serde_json::json!({"token": {"refresh_token": "1//rt-ok"}, "id_token": "eyJ.bad-C1-ID-SECRET\u{0085}"}),
            ),
            (
                "overlong_at",
                serde_json::json!({"token": {"refresh_token": "1//rt-ok", "access_token": huge_secret}}),
            ),
            (
                "overlong_id",
                serde_json::json!({"token": {"refresh_token": "1//rt-ok"}, "id_token": huge_secret}),
            ),
        ] {
            let raw_bytes = serde_json::to_vec(&raw_json).unwrap();
            let p_err = parse_session_payload_bytes(&raw_bytes)
                .expect_err(&format!("{label} should fail parse_session_payload_bytes"));
            assert!(
                !p_err.contains("SECRET"),
                "leaked secret in {label}: {p_err}"
            );
            let e_err = extract_session_token_from_bytes(&raw_bytes, "slot").expect_err(&format!(
                "{label} should fail extract_session_token_from_bytes"
            ));
            assert_eq!(e_err.exit_code.as_i32(), 1);
            assert_eq!(e_err.error_code, "data_error");
            assert!(
                !e_err.message.contains("SECRET"),
                "leaked secret in {label}: {}",
                e_err.message
            );
            let r_err = extract_raw_refresh_token_from_session_bytes(&raw_bytes, "slot")
                .expect_err(&format!(
                    "{label} should fail extract_raw_refresh_token_from_session_bytes"
                ));
            assert_eq!(r_err.exit_code.as_i32(), 1);
            assert_eq!(r_err.error_code, "data_error");
            assert!(
                !r_err.message.contains("SECRET"),
                "leaked secret in raw extractor {label}: {}",
                r_err.message
            );
        }

        // `go-keyring-base64:`-wrapped bad optional field is also rejected with zero echo.
        {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let b64_bad = format!(
                "go-keyring-base64:{}",
                STANDARD.encode(
                    serde_json::to_vec(&serde_json::json!({
                        "token": {"refresh_token": "1//rt-ok", "access_token": "ya29.B64_SECRET\r"}
                    }))
                    .unwrap()
                )
            );
            let err = extract_raw_refresh_token_from_session_bytes(b64_bad.as_bytes(), "keyring")
                .unwrap_err();
            assert_eq!(err.exit_code.as_i32(), 1);
            assert_eq!(err.error_code, "data_error");
            assert!(!err.message.contains("B64_SECRET"));
        }

        // Positive cases for `extract_raw_refresh_token_from_session_bytes`:
        // omitted optional fields (refresh-only), compact `agy 1.5+`, explicit null/blank optional fields,
        // and exact `MAX_SECRET_BYTES` boundary values MUST continue to succeed.
        let exact_max = "x".repeat(crate::cli::secret_input::MAX_SECRET_BYTES);
        for (label, raw_json, expected_rt) in [
            (
                "refresh_only_nested",
                serde_json::json!({"token": {"refresh_token": " 1//rt-only "}}),
                "1//rt-only",
            ),
            (
                "refresh_only_top",
                serde_json::json!({"refresh_token": "1//rt-top"}),
                "1//rt-top",
            ),
            (
                "compact_no_id_token",
                serde_json::json!({
                    "token": {"access_token": "ya29.c", "refresh_token": "1//rt-compact"},
                    "id_token_email": "alice@example.com",
                    "user_tier": "PRO"
                }),
                "1//rt-compact",
            ),
            (
                "null_and_blank_optionals",
                serde_json::json!({
                    "token": {"refresh_token": "1//rt-null", "access_token": null},
                    "id_token": "   "
                }),
                "1//rt-null",
            ),
            (
                "exact_max_boundary",
                serde_json::json!({
                    "token": {"refresh_token": exact_max, "access_token": exact_max},
                    "id_token": exact_max
                }),
                exact_max.as_str(),
            ),
        ] {
            let raw_bytes = serde_json::to_vec(&raw_json).unwrap();
            let got = extract_raw_refresh_token_from_session_bytes(&raw_bytes, "slot")
                .unwrap_or_else(|e| panic!("{label} should succeed: {}", e.message));
            assert_eq!(got, expected_rt, "label={label}");
            assert!(
                parse_session_payload_bytes(&raw_bytes).is_ok(),
                "{label} should parse"
            );
            assert!(
                extract_session_token_from_bytes(&raw_bytes, "slot").is_ok(),
                "{label} should extract"
            );
        }

        // Serializer enforces the exact same control-char and size bounds without echoing secrets.
        let mut bad_tok_at = sample_token(1_800_000_000);
        bad_tok_at.access_token = "ya29.SER_AT_SECRET\n".into();
        let ser_at_err = serialize_session_payload(&bad_tok_at).unwrap_err();
        assert!(!ser_at_err.message.contains("SER_AT_SECRET"));

        let mut bad_tok_rt = sample_token(1_800_000_000);
        bad_tok_rt.refresh_token = "1//SER_RT_SECRET\r".into();
        let ser_rt_err = serialize_session_payload(&bad_tok_rt).unwrap_err();
        assert!(!ser_rt_err.message.contains("SER_RT_SECRET"));

        let mut bad_tok_id = sample_token(1_800_000_000);
        bad_tok_id.id_token = Some("eyJ.SER_ID_SECRET\n".into());
        let ser_id_err = serialize_session_payload(&bad_tok_id).unwrap_err();
        assert!(!ser_id_err.message.contains("SER_ID_SECRET"));

        let mut huge_tok = sample_token(1_800_000_000);
        huge_tok.access_token =
            "ya29.".to_string() + &"z".repeat(crate::cli::secret_input::MAX_SECRET_BYTES);
        assert!(serialize_session_payload(&huge_tok).is_err());

        let overlong_meta_json = serde_json::to_vec(&serde_json::json!({
            "token": {"refresh_token": "1//rt-ok"},
            "id_token_email": format!("{}@example.com", "b".repeat(320)),
            "user_tier": "T".repeat(200)
        }))
        .unwrap();
        let parsed_over = parse_session_payload_bytes(&overlong_meta_json).unwrap();
        assert_eq!(parsed_over.email_hint, None);
        assert_eq!(parsed_over.user_tier, None);
    }
}
