use crate::domain::account::{
    is_pending_superseded_by_account, validate_account_id, AccountRecord, DisableReasonCode,
    PendingAuthFlow, PendingAuthRecord, STORE_SCHEMA_VERSION,
};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::domain::token::{parse_scope_string, token_digest, TokenRecord};
use crate::error::{CliError, CliResult};
use crate::oauth::flow::PreparedAuthSession;
use crate::oauth::registry::{OAuthClientConfig, OAuthClientRegistry};
use crate::store::locks::{
    is_pending_auth_lock_busy, try_acquire_pending_auth_lock_nonblocking,
    with_account_refresh_lock, with_pending_auth_lock,
};
use crate::store::repository::{StoreRepository, StoreWriteTx};
use crate::transport::client::{
    HttpRequest, HttpResponse, HttpTransport, TimeoutClass, TransportError,
};
use rand::Rng;
use serde::Deserialize;
use std::time::Duration;
use uuid::Uuid;

pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
pub const TOKEN_REFRESH_SKEW_SECONDS: i64 = 900; // 15 minutes

#[derive(Debug, Clone)]
pub struct OAuthEndpoints {
    pub token_url: String,
    pub userinfo_url: String,
    /// Base backoff unit (default `500ms` in production; tests can shrink to `5ms`).
    pub base_backoff: Duration,
}

impl Default for OAuthEndpoints {
    fn default() -> Self {
        Self {
            token_url: GOOGLE_TOKEN_URL.to_string(),
            userinfo_url: GOOGLE_USERINFO_URL.to_string(),
            base_backoff: Duration::from_millis(500),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthErrorKind {
    InvalidGrant,
    InsufficientScope,
    ClientAuthMismatch,
    RateLimited { retry_after_secs: Option<u64> },
    ServerOrTransport,
    ProtocolError,
}

#[derive(Debug, Clone)]
pub struct StructuredOAuthError {
    pub kind: OAuthErrorKind,
    pub http_status: Option<u16>,
    pub oauth_error_code: Option<String>,
    pub safe_summary: String,
}

impl StructuredOAuthError {
    pub fn into_cli_error(self) -> CliError {
        match self.kind {
            OAuthErrorKind::InvalidGrant => CliError::auth(
                "oauth_invalid_grant",
                format!(
                    "{} Run `agy-switch-cli auth reauthorize <ID|EMAIL>` to re-authenticate.",
                    self.safe_summary
                ),
            ),
            OAuthErrorKind::InsufficientScope => CliError::auth(
                "scope_reauth_required",
                format!(
                    "{} Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize <ID|EMAIL>`.",
                    self.safe_summary
                ),
            ),
            OAuthErrorKind::ClientAuthMismatch => CliError::auth(
                "oauth_client_mismatch",
                format!(
                    "{} Check `ANTIGRAVITY_OAUTH_CLIENTS` configuration.",
                    self.safe_summary
                ),
            ),
            OAuthErrorKind::RateLimited { .. } => CliError::io(
                "oauth_rate_limited",
                format!("{} Retry later.", self.safe_summary),
            ),
            OAuthErrorKind::ServerOrTransport => {
                CliError::io("oauth_network_error", self.safe_summary)
            }
            OAuthErrorKind::ProtocolError => {
                CliError::auth("oauth_protocol_error", self.safe_summary)
            }
        }
    }
}

#[derive(Deserialize)]
struct RawTokenResponse {
    access_token: String,
    expires_in: i64,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct RawOAuthErrorBody {
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
}

impl UserInfo {
    pub fn display_name(&self) -> Option<String> {
        if let Some(ref n) = self.name {
            if !n.trim().is_empty() {
                return Some(n.trim().to_string());
            }
        }
        match (&self.given_name, &self.family_name) {
            (Some(g), Some(f)) if !g.trim().is_empty() && !f.trim().is_empty() => {
                Some(format!("{} {}", g.trim(), f.trim()))
            }
            (Some(g), _) if !g.trim().is_empty() => Some(g.trim().to_string()),
            (_, Some(f)) if !f.trim().is_empty() => Some(f.trim().to_string()),
            _ => None,
        }
    }
}

/// Strict compile-time RFC 6749 / OIDC error code allowlist.
/// Unknown upstream `error` strings are mapped to `"unrecognized_oauth_error"` and NEVER echoed!
fn canonical_oauth_error_tag(raw: Option<&str>) -> &'static str {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") => "unspecified",
        Some("invalid_request") => "invalid_request",
        Some("invalid_client") => "invalid_client",
        Some("invalid_grant") => "invalid_grant",
        Some("unauthorized_client") => "unauthorized_client",
        Some("unsupported_grant_type") => "unsupported_grant_type",
        Some("invalid_scope") => "invalid_scope",
        Some("insufficient_scope") => "insufficient_scope",
        Some("access_denied") => "access_denied",
        Some("unsupported_response_type") => "unsupported_response_type",
        Some("server_error") => "server_error",
        Some("temporarily_unavailable") => "temporarily_unavailable",
        Some("interaction_required") => "interaction_required",
        Some("login_required") => "login_required",
        Some("consent_required") => "consent_required",
        Some("slow_down") => "slow_down",
        Some("authorization_pending") => "authorization_pending",
        Some("expired_token") => "expired_token",
        Some(_) => "unrecognized_oauth_error",
    }
}

fn response_indicates_insufficient_scope(resp: &HttpResponse) -> bool {
    if resp
        .header("www-authenticate")
        .is_some_and(|h| h.to_ascii_lowercase().contains("insufficient_scope"))
    {
        return true;
    }
    if let Ok(raw) = std::str::from_utf8(&resp.body) {
        let lower = raw.to_ascii_lowercase();
        if lower.contains("insufficient_scope")
            || lower.contains("access_token_scope_insufficient")
            || lower.contains("insufficient authentication scopes")
            || lower.contains("sign-in update needed")
        {
            return true;
        }
    }
    false
}

fn classify_oauth_http_failure(resp: &HttpResponse, client_key: &str) -> StructuredOAuthError {
    let status = resp.status;
    let raw_err = serde_json::from_slice::<RawOAuthErrorBody>(&resp.body)
        .ok()
        .and_then(|b| b.error);
    let safe_tag = canonical_oauth_error_tag(raw_err.as_deref());
    let opt_tag = (safe_tag != "unspecified").then(|| safe_tag.to_string());

    if status == 429 {
        let retry_after_secs = resp
            .header("retry-after")
            .and_then(|v| v.trim().parse::<u64>().ok());
        return StructuredOAuthError {
            kind: OAuthErrorKind::RateLimited { retry_after_secs },
            http_status: Some(status),
            oauth_error_code: opt_tag,
            safe_summary: format!(
                "OAuth endpoint rate-limited (HTTP 429) for client '{client_key}'."
            ),
        };
    }

    if status >= 500 {
        return StructuredOAuthError {
            kind: OAuthErrorKind::ServerOrTransport,
            http_status: Some(status),
            oauth_error_code: opt_tag,
            safe_summary: format!(
                "OAuth server returned transient HTTP {status} for client '{client_key}'."
            ),
        };
    }

    match safe_tag {
        "invalid_grant" if status == 400 => StructuredOAuthError {
            kind: OAuthErrorKind::InvalidGrant,
            http_status: Some(status),
            oauth_error_code: Some("invalid_grant".into()),
            safe_summary: format!(
                "OAuth grant is expired or revoked (`invalid_grant`) for client '{client_key}'."
            ),
        },
        "invalid_scope" | "insufficient_scope" => StructuredOAuthError {
            kind: OAuthErrorKind::InsufficientScope,
            http_status: Some(status),
            oauth_error_code: Some(safe_tag.into()),
            safe_summary: format!(
                "OAuth token lacks required authorization scopes for client '{client_key}'."
            ),
        },
        "invalid_client" | "unauthorized_client" => StructuredOAuthError {
            kind: OAuthErrorKind::ClientAuthMismatch,
            http_status: Some(status),
            oauth_error_code: Some(safe_tag.into()),
            safe_summary: format!(
                "OAuth client authentication or binding rejected (`{safe_tag}`) for client '{client_key}'."
            ),
        },
        _ if (status == 401 || status == 403) && response_indicates_insufficient_scope(resp) => {
            StructuredOAuthError {
                kind: OAuthErrorKind::InsufficientScope,
                http_status: Some(status),
                oauth_error_code: Some("insufficient_scope".into()),
                safe_summary: format!(
                    "OAuth endpoint rejected token due to insufficient scopes (HTTP {status}) for client '{client_key}'."
                ),
            }
        }
        _ if status == 401 => StructuredOAuthError {
            kind: OAuthErrorKind::ClientAuthMismatch,
            http_status: Some(status),
            oauth_error_code: opt_tag,
            safe_summary: format!(
                "OAuth client credentials rejected (HTTP 401) for client '{client_key}'."
            ),
        },
        _ => StructuredOAuthError {
            kind: OAuthErrorKind::ProtocolError,
            http_status: Some(status),
            oauth_error_code: opt_tag,
            safe_summary: format!(
                "OAuth token request rejected (HTTP {status}, error={safe_tag}) for client '{client_key}'."
            ),
        },
    }
}

fn classify_transport_failure(err: TransportError, client_key: &str) -> StructuredOAuthError {
    StructuredOAuthError {
        kind: OAuthErrorKind::ServerOrTransport,
        http_status: None,
        oauth_error_code: None,
        safe_summary: format!(
            "OAuth network transport error for client '{client_key}': {}",
            err.message
        ),
    }
}

/// Persist an account's disabled state under `L3` and NEVER discard I/O failures!
/// If writing the disabled flag fails (e.g. `EROFS` or `ENOSPC`), propagates the storage I/O error
/// with combined context rather than falsely claiming auth-disable closure succeeded!
pub fn persist_disable_or_report_io_error(
    repo: &StoreRepository,
    account_id: &str,
    code: DisableReasonCode,
    detail: String,
    now_unix: i64,
    auth_err: CliError,
) -> CliError {
    match repo
        .with_write_lock(|tx| tx.mark_account_disabled(account_id, code, Some(detail), now_unix))
    {
        Ok(_) => auth_err,
        Err(io_err) => CliError::new(
            io_err.exit_code,
            io_err.error_code,
            format!(
                "{} (while persisting {:?} state for '{}'; auth error: {})",
                io_err.message, code, account_id, auth_err.message
            ),
        ),
    }
}

async fn execute_token_form_with_backoff(
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    user_agent: &str,
    client: &OAuthClientConfig,
    form: Vec<(String, String)>,
) -> Result<RawTokenResponse, StructuredOAuthError> {
    // Up to 4 attempts total (initial + max 3 bounded retries ONLY for 429 or 5xx/transport)
    // InvalidGrant and ClientAuthMismatch NEVER retry!
    let multipliers_ms = [1u64, 3, 7];
    let mut attempt = 0usize;

    loop {
        let req = HttpRequest::post_form(
            endpoints.token_url.clone(),
            form.clone(),
            TimeoutClass::OAuthToken,
        )
        .with_header("User-Agent", user_agent);

        let outcome = match transport.execute(req).await {
            Ok(resp) if (200..300).contains(&resp.status) => serde_json::from_slice::<
                RawTokenResponse,
            >(&resp.body)
            .map_err(|_| StructuredOAuthError {
                kind: OAuthErrorKind::ProtocolError,
                http_status: Some(resp.status),
                oauth_error_code: None,
                safe_summary: format!(
                    "OAuth token endpoint returned malformed JSON for client '{}'.",
                    client.key
                ),
            }),
            Ok(resp) => Err(classify_oauth_http_failure(&resp, &client.key)),
            Err(terr) => Err(classify_transport_failure(terr, &client.key)),
        };

        match outcome {
            Ok(token_resp) => return Ok(token_resp),
            Err(err) => {
                if attempt >= multipliers_ms.len() {
                    return Err(err);
                }
                let base_wait = match err.kind {
                    OAuthErrorKind::RateLimited {
                        retry_after_secs: Some(secs),
                    } => Duration::from_secs(secs.min(10)),
                    OAuthErrorKind::RateLimited {
                        retry_after_secs: None,
                    }
                    | OAuthErrorKind::ServerOrTransport => endpoints
                        .base_backoff
                        .saturating_mul(multipliers_ms[attempt] as u32),
                    OAuthErrorKind::InvalidGrant
                    | OAuthErrorKind::InsufficientScope
                    | OAuthErrorKind::ClientAuthMismatch
                    | OAuthErrorKind::ProtocolError => {
                        return Err(err);
                    }
                };
                // Add +-15% random jitter
                let jitter_factor = rand::thread_rng().gen_range(85u64..=115u64);
                let sleep_dur = Duration::from_millis(
                    (base_wait.as_millis() as u64 * jitter_factor / 100).max(1),
                );
                tokio::time::sleep(sleep_dur).await;
                attempt += 1;
            }
        }
    }
}

/// Strictly bound authorization code exchange: uses ONLY `session.client` (+ PKCE `code_verifier` + `redirect_uri`).
/// Zero cross-client fallback!
pub async fn exchange_authorization_code(
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    user_agent: &str,
    session: &PreparedAuthSession,
    code: &str,
    now_unix: i64,
) -> CliResult<TokenRecord> {
    let clock = AnchoredClock::new(now_unix);
    let form = vec![
        ("client_id".into(), session.client.client_id.clone()),
        ("client_secret".into(), session.client.client_secret.clone()),
        ("code".into(), code.to_string()),
        ("code_verifier".into(), session.code_verifier.clone()),
        ("redirect_uri".into(), session.redirect_uri.clone()),
        ("grant_type".into(), "authorization_code".into()),
    ];

    let raw =
        execute_token_form_with_backoff(transport, endpoints, user_agent, &session.client, form)
            .await
            .map_err(StructuredOAuthError::into_cli_error)?;

    let post_now = clock.now_unix();
    let refresh_token = raw
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CliError::auth(
                "missing_refresh_token",
                "Google OAuth response did not include a `refresh_token`. Revoke prior app consent in your Google Account and run `auth login` again.",
            )
        })?
        .to_string();

    let expires_in = raw.expires_in.max(60);
    let expiry_timestamp = post_now.saturating_add(expires_in).max(1);

    Ok(TokenRecord {
        access_token: raw.access_token.trim().to_string(),
        refresh_token,
        expires_in,
        expiry_timestamp,
        token_type: if raw.token_type.trim().is_empty() {
            "Bearer".into()
        } else {
            raw.token_type
        },
        id_token: raw.id_token.filter(|s| !s.trim().is_empty()),
        oauth_client_key: Some(session.client.key.clone()),
        // Record ONLY the scopes actually returned by Google's token response!
        granted_scopes: parse_scope_string(raw.scope.as_deref()),
        project_id: None,
        is_gcp_tos: true,
    })
}

pub struct StandaloneRefreshOutcome {
    pub token: TokenRecord,
    pub refresh_token_rotated: bool,
}

/// Refresh an unpooled / standalone `refresh_token` directly via the specified OAuth client
/// without modifying the local account store (`accounts/` or `index.json`).
pub async fn refresh_standalone_refresh_token(
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    client: &OAuthClientConfig,
    user_agent: &str,
    refresh_token: &str,
    previous_id_token: Option<&str>,
    now_unix: i64,
) -> CliResult<StandaloneRefreshOutcome> {
    let clock = AnchoredClock::new(now_unix);
    let form = vec![
        ("client_id".into(), client.client_id.clone()),
        ("client_secret".into(), client.client_secret.clone()),
        ("refresh_token".into(), refresh_token.to_string()),
        ("grant_type".into(), "refresh_token".into()),
    ];
    let raw = execute_token_form_with_backoff(transport, endpoints, user_agent, client, form)
        .await
        .map_err(StructuredOAuthError::into_cli_error)?;
    let post_now = clock.now_unix();
    let access_token = raw.access_token.trim().to_string();
    if access_token.is_empty() {
        return Err(CliError::auth(
            "oauth_protocol_error",
            "OAuth token refresh response returned an empty `access_token`.",
        ));
    }
    let rotated_rt = raw
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let refresh_token_rotated = rotated_rt
        .as_deref()
        .is_some_and(|next| next != refresh_token);
    let effective_rt = rotated_rt.unwrap_or_else(|| refresh_token.to_string());
    let expires_in = raw.expires_in.max(60);
    let expiry_timestamp = post_now.saturating_add(expires_in).max(1);
    let id_token = raw
        .id_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| previous_id_token.map(str::to_owned));

    Ok(StandaloneRefreshOutcome {
        token: TokenRecord {
            access_token,
            refresh_token: effective_rt,
            expires_in,
            expiry_timestamp,
            token_type: if raw.token_type.trim().is_empty() {
                "Bearer".into()
            } else {
                raw.token_type
            },
            id_token,
            oauth_client_key: Some(client.key.clone()),
            granted_scopes: parse_scope_string(raw.scope.as_deref()),
            project_id: None,
            is_gcp_tos: true,
        },
        refresh_token_rotated,
    })
}

pub async fn fetch_userinfo(
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    user_agent: &str,
    access_token: &str,
) -> CliResult<UserInfo> {
    let req = HttpRequest::get(endpoints.userinfo_url.clone(), TimeoutClass::StandardApi)
        .with_bearer_auth(access_token)
        .with_header("User-Agent", user_agent);

    let resp = transport.execute(req).await.map_err(|e| {
        CliError::io(
            "userinfo_network_error",
            format!("Userinfo request failed: {e}"),
        )
    })?;

    if !(200..300).contains(&resp.status) {
        if (resp.status == 401 || resp.status == 403)
            && response_indicates_insufficient_scope(&resp)
        {
            return Err(CliError::auth(
                "scope_reauth_required",
                format!(
                    "Userinfo endpoint rejected access token due to insufficient OAuth scopes (HTTP {}). Run `agy-switch-cli auth reauthorize <ID|EMAIL>`.",
                    resp.status
                ),
            ));
        }
        return Err(CliError::auth(
            "userinfo_rejected",
            format!(
                "Userinfo endpoint rejected access token (HTTP {}).",
                resp.status
            ),
        ));
    }

    let info: UserInfo = serde_json::from_slice(&resp.body)
        .map_err(|_| CliError::data("Userinfo endpoint returned invalid JSON."))?;
    if info.email.trim().is_empty() {
        return Err(CliError::data(
            "Userinfo response did not contain an email address.",
        ));
    }
    Ok(info)
}

fn pending_matches_add_digest(repo: &StoreRepository, p: &PendingAuthRecord, digest: &str) -> bool {
    if !matches!(p.flow, PendingAuthFlow::AddToken) && !p.email_mismatch {
        return false;
    }
    if p.input_rt_digest.as_deref() == Some(digest) || p.token.refresh_token_fingerprint() == digest
    {
        return true;
    }
    repo.read_pending_lineage_readonly(&p.id)
        .ok()
        .flatten()
        .is_some_and(|arch| arch.digests.iter().any(|d| d == digest))
}

fn cleanup_superseded_duplicate_pendings(
    repo: &StoreRepository,
    tx: &StoreWriteTx<'_>,
    primary_pending_id: &str,
    matching_input_digest: Option<&str>,
    saved_acc: &mut AccountRecord,
) -> CliResult<()> {
    let _ =
        tx.cleanup_idle_superseded_reauth_pendings_in_tx(Some(primary_pending_id), saved_acc)?;
    let candidates: Vec<String> = repo
        .list_valid_pending_auth_lossy()
        .into_iter()
        .filter(|p| {
            matches!(p.flow, PendingAuthFlow::AddToken)
                && !p.email_mismatch
                && p.id != primary_pending_id
                && is_pending_superseded_by_account(p.auth_seq, saved_acc.auth_generation)
        })
        .map(|p| p.id)
        .collect();
    for dup_id in candidates {
        let Ok(Some(_held)) = try_acquire_pending_auth_lock_nonblocking(tx.paths(), &dup_id) else {
            continue;
        };
        let Some(live_dup) = tx.load_pending_auth_opt(&dup_id)? else {
            continue;
        };
        if live_dup.email_mismatch
            || !is_pending_superseded_by_account(live_dup.auth_seq, saved_acc.auth_generation)
        {
            continue;
        }
        let dup_rt = live_dup.token.refresh_token.trim();
        let same_inp = matching_input_digest
            .is_some_and(|dig| live_dup.input_rt_digest.as_deref() == Some(dig));
        let already_recorded = same_inp
            || dup_rt == saved_acc.token.refresh_token.trim()
            || tx.account_has_superseded_rt_in_tx(saved_acc, dup_rt)?.0;
        if already_recorded {
            let Ok(lin) = tx.load_pending_lineage_digests(&dup_id) else {
                continue;
            };
            let mut dirty = false;
            if let Some(ref inp) = live_dup.input_rt_digest {
                saved_acc.record_superseded_digest(inp);
                dirty = true;
            }
            if !dup_rt.is_empty() && dup_rt != saved_acc.token.refresh_token.trim() {
                saved_acc.record_superseded_digest(&token_digest(dup_rt));
                dirty = true;
            }
            for d in lin {
                saved_acc.record_superseded_digest(&d);
                dirty = true;
            }
            if dirty {
                tx.save_account(saved_acc)?;
            }
            let _ = tx.remove_pending_auth_cas(&dup_id, &live_dup.cas_fingerprint());
        }
    }
    Ok(())
}

enum BindPendingOutcome {
    Bound {
        account: AccountRecord,
        created: bool,
    },
    SupersededAbsorbed {
        latest_account: AccountRecord,
    },
}

enum ExistingBindStep {
    Done(Box<BindPendingOutcome>),
    TargetRemovedRetry(Box<AccountRecord>),
}

#[allow(clippy::too_many_arguments)]
async fn bind_verified_account_from_pending_inner(
    repo: &StoreRepository,
    pending_id: &str,
    expected_pending_fp: &str,
    matching_input_digest: Option<&str>,
    extra_superseded_digests: &[String],
    token: TokenRecord,
    user_info: &UserInfo,
    custom_label: Option<&str>,
    missing_scopes: &[String],
    now_unix: i64,
) -> CliResult<BindPendingOutcome> {
    let mut record = AccountRecord::new(
        format!("acc-{}", Uuid::new_v4().simple()),
        user_info.email.clone(),
        token,
        now_unix,
    );
    if let Some(inp) = matching_input_digest {
        record.record_superseded_digest(inp);
    }
    for sup in extra_superseded_digests {
        record.record_superseded_digest(sup);
    }
    record.name = user_info.display_name();
    record.custom_label = custom_label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if !missing_scopes.is_empty() {
        record.disabled = true;
        record.disabled_code = Some(DisableReasonCode::ScopeReauthRequired);
        record.disabled_detail = Some(format!(
            "Authorization missing required scope(s): {}",
            missing_scopes.join(", ")
        ));
        record.disabled_at = Some(now_unix);
    }

    enum BindFastPath {
        Done(Box<(AccountRecord, bool)>),
        RetryUnderL2(String, Box<AccountRecord>),
    }

    let mut candidate_eid = repo.find_matching_account_id_for_import_readonly(
        None,
        &record.token.refresh_token,
        &record.email,
        record.token.oauth_client_key.as_deref(),
    )?;

    for _ in 0..4 {
        if let Some(eid) = candidate_eid.take() {
            match bind_pending_onto_existing_under_l2(
                repo,
                &eid,
                pending_id,
                expected_pending_fp,
                matching_input_digest,
                extra_superseded_digests,
                record,
                now_unix,
            )
            .await?
            {
                ExistingBindStep::Done(outcome) => return Ok(*outcome),
                ExistingBindStep::TargetRemovedRetry(rec_box) => {
                    record = *rec_box;
                }
            }
        }

        let first_try = repo.with_write_lock(|tx| {
            let live_p = tx.verify_pending_auth_cas(pending_id, expected_pending_fp)?;
            let index = tx.load_index_or_init(now_unix)?;
            for existing_id in &index.account_order {
                if let Some(acc) = tx.load_account_opt(existing_id)? {
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
                    if same_rt || same_email {
                        return Ok(BindFastPath::RetryUnderL2(acc.id, Box::new(record)));
                    }
                }
            }
            for d in tx.load_pending_lineage_digests(pending_id)? {
                record.record_superseded_digest(&d);
            }
            record.auth_generation = live_p.auth_seq.max(1);
            let (mut saved, created) = tx.upsert_account(record, true, now_unix)?;
            cleanup_superseded_duplicate_pendings(
                repo,
                tx,
                pending_id,
                matching_input_digest,
                &mut saved,
            )?;
            tx.remove_pending_auth_cas(pending_id, expected_pending_fp)?;
            Ok(BindFastPath::Done(Box::new((saved, created))))
        })?;

        match first_try {
            BindFastPath::Done(res) => {
                let (account, created) = *res;
                return Ok(BindPendingOutcome::Bound { account, created });
            }
            BindFastPath::RetryUnderL2(new_eid, rec_box) => {
                candidate_eid = Some(new_eid);
                record = *rec_box;
            }
        }
    }

    Err(CliError::conflict(
        "concurrent_account_churn",
        "Target account changed repeatedly during concurrent pending authorization bind; retry `auth pending --resume`.",
    ))
}

#[allow(clippy::too_many_arguments)]
async fn bind_pending_onto_existing_under_l2(
    repo: &StoreRepository,
    eid: &str,
    pending_id: &str,
    expected_pending_fp: &str,
    matching_input_digest: Option<&str>,
    extra_superseded_digests: &[String],
    mut record: AccountRecord,
    now_unix: i64,
) -> CliResult<ExistingBindStep> {
    with_account_refresh_lock(repo.paths(), eid, Duration::from_secs(20), || async {
        // Check #1 immediately after acquiring L2: detect if a newer authorization committed onto `eid` while waiting!
        if let (Ok(Some(live_p_l2)), Ok(acc_l2)) = (
            repo.read_pending_auth_opt_readonly(pending_id),
            repo.read_account_unchecked(eid),
        ) {
            if !live_p_l2.email_mismatch
                && is_pending_superseded_by_account(live_p_l2.auth_seq, acc_l2.auth_generation)
            {
                if let Some(latest_account) = repo.with_write_lock(|tx| {
                    tx.absorb_superseded_pending_into_account_cas(
                        pending_id,
                        expected_pending_fp,
                        eid,
                        matching_input_digest,
                        extra_superseded_digests,
                    )
                })? {
                    return Ok(ExistingBindStep::Done(Box::new(
                        BindPendingOutcome::SupersededAbsorbed { latest_account },
                    )));
                }
            }
        }

        // Check #2 inside L3 right before committing `upsert_account`!
        repo.with_write_lock(|tx| {
            let live_p = tx.verify_pending_auth_cas(pending_id, expected_pending_fp)?;
            let index = tx.load_index_or_init(now_unix)?;
            let eid_still_present = index.account_order.iter().any(|id| id == eid)
                && tx.load_account_opt(eid)?.is_some();
            if !eid_still_present {
                return Ok(ExistingBindStep::TargetRemovedRetry(Box::new(record)));
            }
            if let Some(latest_account) = tx.absorb_superseded_pending_into_account_cas(
                pending_id,
                expected_pending_fp,
                eid,
                matching_input_digest,
                extra_superseded_digests,
            )? {
                return Ok(ExistingBindStep::Done(Box::new(
                    BindPendingOutcome::SupersededAbsorbed { latest_account },
                )));
            }
            for d in tx.load_pending_lineage_digests(pending_id)? {
                record.record_superseded_digest(&d);
            }
            record.auth_generation = live_p.auth_seq.max(1);
            let (mut saved, created) = tx.upsert_account(record, true, now_unix)?;
            cleanup_superseded_duplicate_pendings(
                repo,
                tx,
                pending_id,
                matching_input_digest,
                &mut saved,
            )?;
            tx.remove_pending_auth_cas(pending_id, expected_pending_fp)?;
            Ok(ExistingBindStep::Done(Box::new(
                BindPendingOutcome::Bound {
                    account: saved,
                    created,
                },
            )))
        })
    })
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn bind_verified_account_from_pending(
    repo: &StoreRepository,
    pending_id: &str,
    expected_pending_fp: &str,
    matching_input_digest: Option<&str>,
    extra_superseded_digests: &[String],
    token: TokenRecord,
    user_info: &UserInfo,
    custom_label: Option<&str>,
    missing_scopes: &[String],
    now_unix: i64,
) -> CliResult<(AccountRecord, bool)> {
    match bind_verified_account_from_pending_inner(
        repo,
        pending_id,
        expected_pending_fp,
        matching_input_digest,
        extra_superseded_digests,
        token,
        user_info,
        custom_label,
        missing_scopes,
        now_unix,
    )
    .await?
    {
        BindPendingOutcome::Bound { account, created } => Ok((account, created)),
        BindPendingOutcome::SupersededAbsorbed { latest_account } => Err(CliError::conflict(
            "superseded_authorization",
            format!(
                "A newer authorization (generation {}) already completed for account '{}'; stale staged token was recorded as superseded without overwriting the newer token.",
                latest_account.auth_generation, latest_account.id
            ),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn refresh_existing_account_for_add(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    existing_id: &str,
    rt_trimmed: &str,
    explicit_client_key: Option<&str>,
    custom_label: Option<&str>,
    clock: &AnchoredClock,
) -> CliResult<(AccountRecord, bool)> {
    with_account_refresh_lock(
        repo.paths(),
        existing_id,
        Duration::from_secs(20),
        || async {
            let current_acc = repo.read_account_unchecked(existing_id)?;
            // If a concurrent holder rotated `rt_trimmed` WHILE we waited for L2, use the latest RT on disk!
            let effective_rt = if repo.account_has_superseded_rt(&current_acc, rt_trimmed)? {
                current_acc.token.refresh_token.clone()
            } else {
                rt_trimmed.to_string()
            };

            // Preflight local store directory & target file writeability BEFORE calling `/token` over the network!
            repo.with_write_lock(|tx| tx.preflight_account_refresh_staging(existing_id))?;

            // Enforce RFC 6749 single-client binding on already-bound accounts!
            let refresh_res = if let Some(ref bound_key) = current_acc.token.oauth_client_key {
                if let Some(exp_key) = explicit_client_key {
                    let norm_exp = crate::oauth::registry::normalize_client_key(exp_key);
                    if !norm_exp.is_empty() && norm_exp != *bound_key {
                        return Err(CliError::auth(
                            "oauth_client_mismatch",
                            format!(
                                "Account '{}' is already bound to OAuth client '{}' (cannot refresh under a different `--client` key).",
                                current_acc.id,
                                crate::oauth::registry::sanitize_key_for_log(bound_key)
                            ),
                        ));
                    }
                }
                let client = registry.require_bound_client(bound_key)?;
                refresh_raw_with_client(transport, endpoints, user_agent, &client, &effective_rt)
                    .await
                    .map(|raw| (raw, client.key))
            } else if let Some(key) = explicit_client_key {
                let client = registry.select_for_login(Some(key))?;
                refresh_raw_with_client(transport, endpoints, user_agent, &client, &effective_rt)
                    .await
                    .map(|raw| (raw, client.key))
            } else {
                probe_refresh_unknown_client(
                    transport,
                    endpoints,
                    registry,
                    user_agent,
                    &effective_rt,
                )
                .await
            };

            let (raw, used_client_key) = match refresh_res {
                Ok(pair) => pair,
                Err(err) => {
                    let post_now = clock.now_unix();
                    let cli_err = err.clone().into_cli_error();
                    return match err.kind {
                        OAuthErrorKind::InvalidGrant => Err(persist_disable_or_report_io_error(
                            repo,
                            existing_id,
                            DisableReasonCode::RevokedOrExpiredGrant,
                            "OAuth refresh returned invalid_grant.".into(),
                            post_now,
                            cli_err,
                        )),
                        OAuthErrorKind::InsufficientScope => {
                            Err(persist_disable_or_report_io_error(
                                repo,
                                existing_id,
                                DisableReasonCode::ScopeReauthRequired,
                                "OAuth refresh rejected due to insufficient scopes.".into(),
                                post_now,
                                cli_err,
                            ))
                        }
                        _ => Err(cli_err),
                    };
                }
            };

            let post_now = clock.now_unix();
            let rotated_rt = raw
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| effective_rt.clone());
            let was_rotated = rotated_rt != effective_rt;
            let expires_in = raw.expires_in.max(60);
            let new_token = TokenRecord {
                access_token: raw.access_token.trim().to_string(),
                refresh_token: rotated_rt,
                expires_in,
                expiry_timestamp: post_now.saturating_add(expires_in).max(1),
                token_type: if raw.token_type.trim().is_empty() {
                    "Bearer".into()
                } else {
                    raw.token_type
                },
                id_token: raw
                    .id_token
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| current_acc.token.id_token.clone()),
                oauth_client_key: Some(used_client_key),
                granted_scopes: parse_scope_string(raw.scope.as_deref())
                    .or_else(|| current_acc.token.granted_scopes.clone()),
                project_id: current_acc.token.project_id.clone(),
                is_gcp_tos: current_acc.token.is_gcp_tos,
            };

            // CRITICAL: Persist rotated token IMMEDIATELY under L3 with ZERO `.await` points before `fetch_userinfo`!
            let mut saved_acc = repo
                .with_write_lock(|tx| {
                    let merged = tx.merge_refreshed_token(existing_id, new_token, None, post_now)?;
                    if custom_label.is_some_and(|l| !l.trim().is_empty()) {
                        tx.update_account_identity_metadata(existing_id, None, None, custom_label)
                    } else {
                        Ok(merged)
                    }
                })
                .map_err(|e| wrap_unpersisted_token_exchange_error(e, was_rotated))?;

            let missing = registry.missing_required_scopes(&saved_acc.token);
            if !missing.is_empty() {
                let scope_err = CliError::auth(
                    "scope_reauth_required",
                    format!(
                        "Account '{}' ({}) lacks required OAuth scope(s) ({}). Refreshing a token cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize {}`.",
                        saved_acc.id,
                        saved_acc.email,
                        missing.join(", "),
                        saved_acc.id
                    ),
                );
                return Err(persist_disable_or_report_io_error(
                    repo,
                    existing_id,
                    DisableReasonCode::ScopeReauthRequired,
                    format!(
                        "Known granted_scopes missing required scope(s): {}",
                        missing.join(", ")
                    ),
                    post_now,
                    scope_err,
                ));
            }

            // Auxiliary `userinfo` AFTER rotated token is already durably saved on disk!
            match fetch_userinfo(
                transport,
                endpoints,
                user_agent,
                &saved_acc.token.access_token,
            )
            .await
            {
                Ok(u) => {
                    saved_acc = repo.with_write_lock(|tx| {
                        tx.update_account_identity_metadata(
                            existing_id,
                            Some(&u.email),
                            u.display_name().as_deref(),
                            custom_label,
                        )
                    })?;
                }
                Err(err) if err.error_code == "scope_reauth_required" => {
                    return Err(persist_disable_or_report_io_error(
                        repo,
                        existing_id,
                        DisableReasonCode::ScopeReauthRequired,
                        "Userinfo endpoint rejected token due to insufficient scopes.".into(),
                        clock.now_unix(),
                        err,
                    ));
                }
                Err(err) => return Err(err),
            }

            Ok((saved_acc, false))
        },
    )
    .await
}

fn wrap_unpersisted_token_exchange_error(
    persist_err: CliError,
    refresh_token_rotated: bool,
) -> CliError {
    // Only pass through `LockBusyOrConflict` when a durable copy on disk is PROVEN to exist
    // (`save_pending_auth_cas` already saved `pend-alt-*`, or `merge_refreshed_token` proved
    // a newer generation already supersedes this token). Post-issuance `L3` `lock_busy` timeouts
    // have NO durable backup and MUST return exit code 7 (`issued_token_unpersisted`).
    if persist_err.exit_code == crate::error::ExitCode::LockBusyOrConflict
        && matches!(
            persist_err.error_code.as_str(),
            "pending_auth_version_conflict" | "stale_rotated_refresh_token"
        )
    {
        return persist_err;
    }
    let rot_note = if refresh_token_rotated {
        "Google OAuth rotated the refresh token during exchange; re-authenticate via `agy-switch-cli auth login` after resolving local storage permissions or disk space."
    } else {
        "The refresh token was not rotated by the server; resolve local storage permissions or disk space and retry."
    };
    CliError::partial_commit(
        "issued_token_unpersisted",
        format!(
            "OAuth token exchange succeeded, but persisting local 0600 staging record failed ({}). {rot_note}",
            persist_err.error_code
        ),
    )
    .with_details(serde_json::json!({
        "state": "issued_token_unpersisted",
        "refresh_token_rotated": refresh_token_rotated,
        "storage_error_code": persist_err.error_code,
    }))
}

/// Exchange and durably persist a `refresh_token` during `accounts add`:
/// 1. If `refresh_token` already matches an existing account in `repo`, rejects already-superseded historical
///    tokens immediately; otherwise acquires `L2` FIRST, enforces bound client key, exchanges `/token`, and
///    **IMMEDIATELY** persists the rotated token to `accounts/<id>.json` under `L3` BEFORE awaiting `fetch_userinfo`!
/// 2. If `refresh_token` is unknown (or resumes an interrupted `PendingAuthRecord` for the same input digest),
///    acquires `PendingAuthLock` (`L1 -> PendingAuthLock -> L2 -> L3`), re-reads latest pending state, exchanges `/token`,
///    and **IMMEDIATELY** persists a `0600` durable `PendingAuthRecord` via CAS BEFORE awaiting `fetch_userinfo`,
///    then binds the verified account and CAS-deletes `PendingAuthRecord`!
/// 3. Never drops issued/rotated tokens even if `missing_required_scopes` is non-empty!
#[allow(clippy::too_many_arguments)]
pub async fn bootstrap_and_persist_refresh_token(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    refresh_token: &str,
    explicit_client_key: Option<&str>,
    custom_label: Option<&str>,
    now_unix: i64,
) -> CliResult<(AccountRecord, bool)> {
    let rt_trimmed = refresh_token.trim();
    if rt_trimmed.is_empty() {
        return Err(CliError::usage("Refresh token cannot be empty."));
    }
    let clock = AnchoredClock::new(now_unix);

    // Case 1: Input refresh_token matches an existing account in `repo` (current or superseded rotation history)!
    if let Some(existing_acc) = repo.find_account_by_refresh_token_readonly(rt_trimmed)? {
        if existing_acc.token.refresh_token.trim() != rt_trimmed
            && repo.account_has_superseded_rt(&existing_acc, rt_trimmed)?
        {
            return Err(CliError::conflict(
                "stale_rotated_refresh_token",
                format!(
                    "Refusing to add a previously superseded (rotated-away) refresh_token for account '{}'.",
                    existing_acc.id
                ),
            ));
        }
        return refresh_existing_account_for_add(
            repo,
            transport,
            endpoints,
            registry,
            user_agent,
            &existing_acc.id,
            rt_trimmed,
            explicit_client_key,
            custom_label,
            &clock,
        )
        .await;
    }

    // Case 2: Unknown refresh_token (or resuming from an interrupted `PendingAuthRecord`!)
    // Derive deterministic lock ID from any existing matching pending record or `pend-<input_digest[..32]>`.
    let input_digest = token_digest(rt_trimmed);
    let lock_pending_id = repo
        .list_valid_pending_auth_lossy()
        .into_iter()
        .rfind(|p| pending_matches_add_digest(repo, p, &input_digest))
        .map(|p| p.id)
        .unwrap_or_else(|| format!("pend-{}", &input_digest[..32]));

    with_pending_auth_lock(
        repo.paths(),
        &lock_pending_id,
        Duration::from_secs(20),
        || async {
            // Re-check inside `PendingAuthLock` whether a concurrent caller already bound `rt_trimmed` into `accounts/`!
            if let Some(existing_acc) = repo.find_account_by_refresh_token_readonly(rt_trimmed)? {
                if existing_acc.token.refresh_token.trim() != rt_trimmed
                    && repo.account_has_superseded_rt(&existing_acc, rt_trimmed)?
                {
                    return Err(CliError::conflict(
                        "stale_rotated_refresh_token",
                        format!(
                            "Refusing to add a previously superseded (rotated-away) refresh_token for account '{}'.",
                            existing_acc.id
                        ),
                    ));
                }
                return refresh_existing_account_for_add(
                    repo,
                    transport,
                    endpoints,
                    registry,
                    user_agent,
                    &existing_acc.id,
                    rt_trimmed,
                    explicit_client_key,
                    custom_label,
                    &clock,
                )
                .await;
            }

            let existing_pending = match repo.read_pending_auth_opt_readonly(&lock_pending_id)? {
                Some(p) => Some(p),
                None => repo
                    .list_valid_pending_auth_lossy()
                    .into_iter()
                    .rfind(|p| pending_matches_add_digest(repo, p, &input_digest)),
            };

            let mut effective_input_digest = input_digest.clone();
            let mut superseded_digests = vec![input_digest.clone()];
            let (pending_id, expected_fp, token) = if let Some(prev_p) = existing_pending {
                if prev_p.token.refresh_token_fingerprint() != input_digest
                    && prev_p.input_rt_digest.as_deref() != Some(input_digest.as_str())
                {
                    return Err(CliError::conflict(
                        "stale_rotated_refresh_token",
                        format!(
                            "Refusing to add an intermediate superseded refresh_token for pending auth record '{}'. Run `agy-switch-cli auth pending --resume` instead.",
                            prev_p.id
                        ),
                    ));
                }
                if let Some(ref orig_inp) = prev_p.input_rt_digest {
                    effective_input_digest = orig_inp.clone();
                    superseded_digests.push(orig_inp.clone());
                }
                superseded_digests.push(token_digest(&prev_p.token.refresh_token));
                if !prev_p
                    .token
                    .is_expiring_within(clock.now_unix(), TOKEN_REFRESH_SKEW_SECONDS)
                {
                    let fp = prev_p.cas_fingerprint();
                    (prev_p.id, fp, prev_p.token)
                } else {
                    let prev_id_for_preflight = prev_p.id.clone();
                    if let Some(ref bound_key) = prev_p.token.oauth_client_key {
                        let _ = registry.require_bound_client(bound_key)?;
                    } else if let Some(key) = explicit_client_key {
                        let _ = registry.select_for_login(Some(key))?;
                    }
                    repo.with_write_lock(|tx| {
                        tx.preflight_pending_auth_staging(&prev_id_for_preflight, false)
                    })?;
                    let prev_fp = prev_p.cas_fingerprint();
                    let effective_rt = prev_p.token.refresh_token.clone();
                    let (raw, used_client_key) =
                        if let Some(ref bound_key) = prev_p.token.oauth_client_key {
                            let client = registry.require_bound_client(bound_key)?;
                            let raw = refresh_raw_with_client(
                                transport,
                                endpoints,
                                user_agent,
                                &client,
                                &effective_rt,
                            )
                            .await
                            .map_err(StructuredOAuthError::into_cli_error)?;
                            (raw, client.key)
                        } else if let Some(key) = explicit_client_key {
                            let client = registry.select_for_login(Some(key))?;
                            let raw = refresh_raw_with_client(
                                transport,
                                endpoints,
                                user_agent,
                                &client,
                                &effective_rt,
                            )
                            .await
                            .map_err(StructuredOAuthError::into_cli_error)?;
                            (raw, client.key)
                        } else {
                            probe_refresh_unknown_client(
                                transport,
                                endpoints,
                                registry,
                                user_agent,
                                &effective_rt,
                            )
                            .await
                            .map_err(StructuredOAuthError::into_cli_error)?
                        };
                    let post_now = clock.now_unix();
                    let rotated_rt = raw
                        .refresh_token
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| effective_rt.clone());
                    let was_rotated = rotated_rt != effective_rt;
                    let expires_in = raw.expires_in.max(60);
                    let next_tok = TokenRecord {
                        access_token: raw.access_token.trim().to_string(),
                        refresh_token: rotated_rt,
                        expires_in,
                        expiry_timestamp: post_now.saturating_add(expires_in).max(1),
                        token_type: if raw.token_type.trim().is_empty() {
                            "Bearer".into()
                        } else {
                            raw.token_type
                        },
                        id_token: raw
                            .id_token
                            .filter(|s| !s.trim().is_empty())
                            .or_else(|| prev_p.token.id_token.clone()),
                        oauth_client_key: Some(used_client_key),
                        granted_scopes: parse_scope_string(raw.scope.as_deref())
                            .or_else(|| prev_p.token.granted_scopes.clone()),
                        project_id: prev_p.token.project_id.clone(),
                        is_gcp_tos: true,
                    };
                    let updated_pending = PendingAuthRecord {
                        flow: PendingAuthFlow::AddToken,
                        email_mismatch: false,
                        token: next_tok.clone(),
                        created_at: post_now,
                        ..prev_p
                    };
                    let new_fp = updated_pending.cas_fingerprint();
                    let saved_id = repo
                        .with_write_lock(|tx| {
                            tx.save_pending_auth_cas(&updated_pending, Some(&prev_fp))
                        })
                        .map_err(|e| wrap_unpersisted_token_exchange_error(e, was_rotated))?;
                    (saved_id, new_fp, next_tok)
                }
            } else {
                let preselected_client = match explicit_client_key {
                    Some(key) => Some(registry.select_for_login(Some(key))?),
                    None => None,
                };
                // Preflight private staging directories, writeability, and reserve `auth_seq` BEFORE `/token` exchange!
                let reserved_seq = repo
                    .with_write_lock(|tx| {
                        tx.preflight_pending_auth_staging(&lock_pending_id, true)
                    })?
                    .unwrap_or(2);
                let (raw, used_client_key) = if let Some(client) = preselected_client {
                    let raw = refresh_raw_with_client(
                        transport, endpoints, user_agent, &client, rt_trimmed,
                    )
                    .await
                    .map_err(StructuredOAuthError::into_cli_error)?;
                    (raw, client.key)
                } else {
                    probe_refresh_unknown_client(
                        transport, endpoints, registry, user_agent, rt_trimmed,
                    )
                    .await
                    .map_err(StructuredOAuthError::into_cli_error)?
                };

                let post_now = clock.now_unix();
                let rotated_rt = raw
                    .refresh_token
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| rt_trimmed.to_string());
                let was_rotated = rotated_rt != rt_trimmed;
                let expires_in = raw.expires_in.max(60);
                let tok = TokenRecord {
                    access_token: raw.access_token.trim().to_string(),
                    refresh_token: rotated_rt,
                    expires_in,
                    expiry_timestamp: post_now.saturating_add(expires_in).max(1),
                    token_type: if raw.token_type.trim().is_empty() {
                        "Bearer".into()
                    } else {
                        raw.token_type
                    },
                    id_token: raw.id_token.filter(|s| !s.trim().is_empty()),
                    oauth_client_key: Some(used_client_key),
                    granted_scopes: parse_scope_string(raw.scope.as_deref()),
                    project_id: None,
                    is_gcp_tos: true,
                };

                // CRITICAL: Immediately write `0600` durable `PendingAuthRecord` with monotonic `auth_seq` BEFORE awaiting `fetch_userinfo`!
                let (saved_id, fp) = repo
                    .with_write_lock(|tx| {
                        let cur_max = tx.current_max_auth_seq()?;
                        let auth_seq = if reserved_seq >= cur_max {
                            tx.ensure_auth_sequence_at_least(reserved_seq)?;
                            reserved_seq
                        } else {
                            tx.allocate_next_auth_seq()?
                        };
                        let pending = PendingAuthRecord {
                            schema_version: STORE_SCHEMA_VERSION,
                            id: lock_pending_id.clone(),
                            flow: PendingAuthFlow::AddToken,
                            token: tok.clone(),
                            auth_seq,
                            email_mismatch: false,
                            input_rt_digest: Some(input_digest.clone()),
                            custom_label: custom_label
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_owned),
                            created_at: post_now,
                        };
                        let fp = pending.cas_fingerprint();
                        let sid = tx.save_pending_auth_cas(&pending, None)?;
                        Ok((sid, fp))
                    })
                    .map_err(|e| wrap_unpersisted_token_exchange_error(e, was_rotated))?;
                (saved_id, fp, tok)
            };

            let missing = registry.missing_required_scopes(&token);
            let userinfo_res =
                fetch_userinfo(transport, endpoints, user_agent, &token.access_token).await;

            match userinfo_res {
                Ok(user_info) => {
                    let bind_now = clock.now_unix();
                    let (saved, created) = bind_verified_account_from_pending(
                        repo,
                        &pending_id,
                        &expected_fp,
                        Some(effective_input_digest.as_str()),
                        &superseded_digests,
                        token,
                        &user_info,
                        custom_label,
                        &missing,
                        bind_now,
                    )
                    .await?;
                    if !missing.is_empty() {
                        return Err(CliError::auth(
                            "scope_reauth_required",
                            format!(
                                "Refresh token for '{}' ({}) lacks required OAuth scope(s) ({}). Token was safely saved in disabled state; run `agy-switch-cli auth reauthorize {}`.",
                                saved.id,
                                saved.email,
                                missing.join(", "),
                                saved.id
                            ),
                        ));
                    }
                    Ok((saved, created))
                }
                Err(u_err) => {
                    // `PendingAuthRecord` (0600) remains durably on disk so the rotated token is NEVER lost!
                    if !missing.is_empty() {
                        return Err(CliError::auth(
                            "scope_reauth_required",
                            format!(
                                "Refresh token lacks required OAuth scope(s) ({}); rotated token was preserved in pending_auth. Run `agy-switch-cli auth login` instead.",
                                missing.join(", ")
                            ),
                        ));
                    }
                    Err(u_err)
                }
            }
        },
    )
    .await
}

/// Complete `auth login` code exchange under `PendingAuthLock` with immediate durable `0600` `PendingAuthRecord`
/// persistence BEFORE `fetch_userinfo` await and CAS verification upon account binding!
#[allow(clippy::too_many_arguments)]
pub async fn complete_login_exchange_locked(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    session: &PreparedAuthSession,
    code: &str,
    custom_label: Option<&str>,
    now_unix: i64,
) -> CliResult<(AccountRecord, bool)> {
    let clock = AnchoredClock::new(now_unix);
    let pending_id = format!("pend-{}", Uuid::new_v4().simple());

    with_pending_auth_lock(
        repo.paths(),
        &pending_id,
        Duration::from_secs(20),
        || async {
            let reserved_seq = repo
                .with_write_lock(|tx| tx.preflight_pending_auth_staging(&pending_id, true))?
                .unwrap_or(2);
            let token = exchange_authorization_code(
                transport, endpoints, user_agent, session, code, now_unix,
            )
            .await?;
            let post_now = clock.now_unix();

            // CRITICAL: Immediately persist `0600` durable `PendingAuthRecord` with monotonic `auth_seq` BEFORE `fetch_userinfo` await!
            let (saved_pending_id, expected_fp) = repo
                .with_write_lock(|tx| {
                    let cur_max = tx.current_max_auth_seq()?;
                    let auth_seq = if reserved_seq >= cur_max {
                        tx.ensure_auth_sequence_at_least(reserved_seq)?;
                        reserved_seq
                    } else {
                        tx.allocate_next_auth_seq()?
                    };
                    let pending = PendingAuthRecord {
                        schema_version: STORE_SCHEMA_VERSION,
                        id: pending_id.clone(),
                        flow: PendingAuthFlow::Login,
                        token: token.clone(),
                        auth_seq,
                        email_mismatch: false,
                        input_rt_digest: None,
                        custom_label: custom_label
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned),
                        created_at: post_now,
                    };
                    let fp = pending.cas_fingerprint();
                    let sid = tx.save_pending_auth_cas(&pending, None)?;
                    Ok((sid, fp))
                })
                .map_err(|e| wrap_unpersisted_token_exchange_error(e, true))?;

            let missing = registry.missing_required_scopes(&token);
            let userinfo_res =
                fetch_userinfo(transport, endpoints, user_agent, &token.access_token).await;

            match userinfo_res {
                Ok(user_info) => {
                    let bind_now = clock.now_unix();
                    let (saved, created) = bind_verified_account_from_pending(
                        repo,
                        &saved_pending_id,
                        &expected_fp,
                        None,
                        &[],
                        token,
                        &user_info,
                        custom_label,
                        &missing,
                        bind_now,
                    )
                    .await?;
                    if !missing.is_empty() {
                        return Err(CliError::auth(
                            "scope_reauth_required",
                            format!(
                                "OAuth consent for '{}' ({}) did not grant required scope(s) ({}). Account was saved in disabled state; run `agy-switch-cli auth reauthorize {}` and approve all scopes.",
                                saved.id,
                                saved.email,
                                missing.join(", "),
                                saved.id
                            ),
                        ));
                    }
                    Ok((saved, created))
                }
                Err(u_err) => {
                    if !missing.is_empty() {
                        return Err(CliError::auth(
                            "scope_reauth_required",
                            format!(
                                "OAuth consent did not grant required scope(s) ({}); issued token was preserved in pending_auth. Approve all requested scopes during `agy-switch-cli auth login`.",
                                missing.join(", ")
                            ),
                        ));
                    }
                    Err(u_err)
                }
            }
        },
    )
    .await
}

async fn refresh_raw_with_client(
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    user_agent: &str,
    client: &OAuthClientConfig,
    refresh_token: &str,
) -> Result<RawTokenResponse, StructuredOAuthError> {
    // RFC 6749 §6: omit `scope` on refresh to inherit original granted scopes without false escalation.
    let form = vec![
        ("client_id".into(), client.client_id.clone()),
        ("client_secret".into(), client.client_secret.clone()),
        ("refresh_token".into(), refresh_token.to_string()),
        ("grant_type".into(), "refresh_token".into()),
    ];
    execute_token_form_with_backoff(transport, endpoints, user_agent, client, form).await
}

async fn probe_refresh_unknown_client(
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    refresh_token: &str,
) -> Result<(RawTokenResponse, String), StructuredOAuthError> {
    let candidates = registry.legacy_probe_candidates();
    let mut last_err: Option<StructuredOAuthError> = None;

    for (idx, client) in candidates.iter().enumerate() {
        let has_more = idx + 1 < candidates.len();
        match refresh_raw_with_client(transport, endpoints, user_agent, client, refresh_token).await
        {
            Ok(raw) => return Ok((raw, client.key.clone())),
            Err(err) => {
                // Controlled probe ONLY continues on explicit `ClientAuthMismatch`!
                // Never continues on InvalidGrant, 429, 5xx, or 403!
                if has_more && err.kind == OAuthErrorKind::ClientAuthMismatch {
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }

    Err(last_err.unwrap_or(StructuredOAuthError {
        kind: OAuthErrorKind::ClientAuthMismatch,
        http_status: None,
        oauth_error_code: None,
        safe_summary: "No OAuth clients configured.".into(),
    }))
}

#[derive(Debug, Clone)]
pub struct RefreshOutcome {
    pub account: AccountRecord,
    pub refreshed_over_network: bool,
    pub refresh_token_rotated: bool,
}

/// Ensure or force-refresh a stored account's token under **L2 (`AccountRefreshLock`) -> L3 (`StoreWriteLock`)**.
/// - Re-reads latest disk state after acquiring L2 so concurrent callers serialize cleanly without stale overwrites;
/// - Enforces RFC 6749 client binding (`oauth_client_key == Some(key)` NEVER falls back to another client);
/// - Persists rotated `refresh_token` IMMEDIATELY under L3 with zero `.await` points after `/token` returns;
/// - Propagates all state persistence errors explicitly (never discarding `Result`).
#[allow(clippy::too_many_arguments)]
pub async fn ensure_account_token_fresh_locked(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    account_id: &str,
    force_refresh: bool,
    now_unix: i64,
) -> CliResult<RefreshOutcome> {
    ensure_account_token_fresh_locked_with_hook(
        repo,
        transport,
        endpoints,
        registry,
        user_agent,
        account_id,
        force_refresh,
        now_unix,
        |_| Ok(()),
    )
    .await
}

/// Same as `ensure_account_token_fresh_locked`, invoking `on_token_persisted` immediately after
/// durable pool token persistence under L3 (`merge_refreshed_token`) and BEFORE any subsequent
/// scope rejection or optional `userinfo` call so decoupled external slots always receive newly
/// rotated tokens even when a post-rotation check returns an early error.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ensure_account_token_fresh_locked_with_hook<F>(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    account_id: &str,
    force_refresh: bool,
    now_unix: i64,
    mut on_token_persisted: F,
) -> CliResult<RefreshOutcome>
where
    F: FnMut(&AccountRecord) -> CliResult<()>,
{
    let clock = AnchoredClock::new(now_unix);
    with_account_refresh_lock(repo.paths(), account_id, Duration::from_secs(20), || async {
        // Re-read latest account snapshot AFTER acquiring L2 lock!
        let current_acc = repo.read_account_unchecked(account_id)?;
        let check_now = clock.now_unix();
        if !force_refresh
            && !current_acc
                .token
                .is_expiring_within(check_now, TOKEN_REFRESH_SKEW_SECONDS)
        {
            let missing = registry.missing_required_scopes(&current_acc.token);
            if !missing.is_empty() {
                let scope_err = CliError::auth(
                    "scope_reauth_required",
                    format!(
                        "Account '{}' ({}) lacks required OAuth scope(s) ({}). Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize {}`.",
                        current_acc.id,
                        current_acc.email,
                        missing.join(", "),
                        current_acc.id
                    ),
                );
                return Err(persist_disable_or_report_io_error(
                    repo,
                    account_id,
                    DisableReasonCode::ScopeReauthRequired,
                    format!(
                        "Known granted_scopes missing required scope(s): {}",
                        missing.join(", ")
                    ),
                    check_now,
                    scope_err,
                ));
            }
            return Ok(RefreshOutcome {
                account: current_acc,
                refreshed_over_network: false,
                refresh_token_rotated: false,
            });
        }

        let bound_client = match current_acc.token.oauth_client_key.as_deref() {
            Some(bound_key) => Some(registry.require_bound_client(bound_key)?),
            None => None,
        };
        // Synchronous `L3` preflight BEFORE calling `/token` over the network (never held across `.await`!)
        repo.with_write_lock(|tx| tx.preflight_account_refresh_staging(account_id))?;

        let refresh_res = if let Some(client) = bound_client {
            refresh_raw_with_client(
                transport,
                endpoints,
                user_agent,
                &client,
                &current_acc.token.refresh_token,
            )
            .await
            .map(|raw| (raw, client.key))
        } else {
            probe_refresh_unknown_client(
                transport,
                endpoints,
                registry,
                user_agent,
                &current_acc.token.refresh_token,
            )
            .await
        };

        let (raw, resolved_client_key) = match refresh_res {
            Ok(pair) => pair,
            Err(err) => {
                let post_now = clock.now_unix();
                let cli_err = err.clone().into_cli_error();
                return match err.kind {
                    OAuthErrorKind::InvalidGrant => Err(persist_disable_or_report_io_error(
                        repo,
                        account_id,
                        DisableReasonCode::RevokedOrExpiredGrant,
                        "OAuth refresh returned invalid_grant.".into(),
                        post_now,
                        cli_err,
                    )),
                    OAuthErrorKind::InsufficientScope => Err(persist_disable_or_report_io_error(
                        repo,
                        account_id,
                        DisableReasonCode::ScopeReauthRequired,
                        "OAuth refresh rejected due to insufficient scopes.".into(),
                        post_now,
                        cli_err,
                    )),
                    _ => Err(cli_err),
                };
            }
        };

        let post_now = clock.now_unix();
        let rotated_refresh_token = raw
            .refresh_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| current_acc.token.refresh_token.clone());

        let refresh_token_rotated = rotated_refresh_token != current_acc.token.refresh_token;
        let expires_in = raw.expires_in.max(60);
        let granted_scopes = parse_scope_string(raw.scope.as_deref())
            .or_else(|| current_acc.token.granted_scopes.clone());

        let new_token = TokenRecord {
            access_token: raw.access_token.trim().to_string(),
            refresh_token: rotated_refresh_token,
            expires_in,
            expiry_timestamp: post_now.saturating_add(expires_in).max(1),
            token_type: if raw.token_type.trim().is_empty() {
                "Bearer".into()
            } else {
                raw.token_type
            },
            id_token: raw
                .id_token
                .filter(|s| !s.trim().is_empty())
                .or_else(|| current_acc.token.id_token.clone()),
            oauth_client_key: Some(resolved_client_key),
            granted_scopes,
            project_id: current_acc.token.project_id.clone(),
            is_gcp_tos: current_acc.token.is_gcp_tos,
        };

        // CRITICAL INVARIANT: Persist `new_token` under L3 StoreWriteLock IMMEDIATELY with ZERO `.await` points
        // between `/token` response parsing and durable disk write, so async cancellation / timeout during
        // optional `userinfo` lookup can NEVER drop a server-rotated `refresh_token`!
        let mut updated_acc = repo
            .with_write_lock(|tx| tx.merge_refreshed_token(account_id, new_token, None, post_now))
            .map_err(|e| wrap_unpersisted_token_exchange_error(e, refresh_token_rotated))?;

        // Notify optional external-slot CAS sync hook IMMEDIATELY after durable pool write and
        // BEFORE any subsequent scope check or optional `userinfo` request can exit early.
        on_token_persisted(&updated_acc)?;

        // Check known `granted_scopes` AFTER rotated `refresh_token` is safely persisted on disk!
        let missing = registry.missing_required_scopes(&updated_acc.token);
        if !missing.is_empty() {
            let scope_err = CliError::auth(
                "scope_reauth_required",
                format!(
                    "Account '{}' ({}) lacks required OAuth scope(s) ({}). Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize {}`.",
                    updated_acc.id,
                    updated_acc.email,
                    missing.join(", "),
                    updated_acc.id
                ),
            );
            return Err(persist_disable_or_report_io_error(
                repo,
                account_id,
                DisableReasonCode::ScopeReauthRequired,
                format!(
                    "Known granted_scopes missing required scope(s): {}",
                    missing.join(", ")
                ),
                post_now,
                scope_err,
            ));
        }

        // Best-effort userinfo fetch ONLY AFTER rotated token is safely fsync'd to disk
        if updated_acc
            .name
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            match fetch_userinfo(transport, endpoints, user_agent, &updated_acc.token.access_token)
                .await
            {
                Ok(u) => {
                    if let Some(name) = u.display_name() {
                        let _ = repo
                            .with_write_lock(|tx| tx.update_account_display_name(account_id, &name));
                        updated_acc.name = Some(name);
                    }
                }
                Err(err) if err.error_code == "scope_reauth_required" => {
                    return Err(persist_disable_or_report_io_error(
                        repo,
                        account_id,
                        DisableReasonCode::ScopeReauthRequired,
                        "Userinfo endpoint rejected token due to insufficient scopes.".into(),
                        clock.now_unix(),
                        err,
                    ));
                }
                Err(_) => {}
            }
        }

        Ok(RefreshOutcome {
            account: updated_acc,
            refreshed_over_network: true,
            refresh_token_rotated,
        })
    })
    .await
}

/// Complete `auth reauthorize <ID|EMAIL>` code exchange under **`PendingAuthLock` -> `L2 (AccountRefreshLock)` -> `L3 (StoreWriteLock)`**:
/// - Acquires `PendingAuthLock` AND `L2` on `existing.id` BEFORE `/token` network exchange;
/// - Immediately saves a `0600` durable `PendingAuthRecord` via CAS upon `/token` success BEFORE awaiting `fetch_userinfo`;
/// - Verifies Google `userinfo` email matches the target account;
/// - Verifies `PendingAuthRecord` CAS under `L3`, merges the newly issued `TokenRecord`, and CAS-deletes the pending record!
#[allow(clippy::too_many_arguments)]
pub async fn complete_reauthorize_exchange_locked(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    existing: &AccountRecord,
    session: &PreparedAuthSession,
    code: &str,
    now_unix: i64,
) -> CliResult<AccountRecord> {
    let clock = AnchoredClock::new(now_unix);
    let target_id = existing.id.clone();
    let pending_id = format!("pend-{}", Uuid::new_v4().simple());

    with_pending_auth_lock(
        repo.paths(),
        &pending_id,
        Duration::from_secs(20),
        || async {
            with_account_refresh_lock(
                repo.paths(),
                &target_id,
                Duration::from_secs(20),
                || async {
                    let current_acc = repo.read_account_unchecked(&target_id)?;
                    let reserved_seq = repo
                        .with_write_lock(|tx| {
                            tx.preflight_reauthorize_staging(&target_id, &pending_id, true)
                        })?
                        .unwrap_or(2);
                    let mut new_token = exchange_authorization_code(
                        transport,
                        endpoints,
                        user_agent,
                        session,
                        code,
                        clock.now_unix(),
                    )
                    .await?;

                    if new_token.project_id.is_none() {
                        new_token.project_id = current_acc.token.project_id.clone();
                    }

                    // CRITICAL: Persist `0600` durable `PendingAuthRecord` with monotonic `auth_seq` IMMEDIATELY upon `/token` return
                    // BEFORE awaiting `fetch_userinfo`, so cancellation or userinfo failure NEVER loses the issued token!
                    let post_now = clock.now_unix();
                    let (saved_pending_id, expected_fp) = repo
                        .with_write_lock(|tx| {
                            let cur_max = tx.current_max_auth_seq()?;
                            let auth_seq = if reserved_seq >= cur_max {
                                tx.ensure_auth_sequence_at_least(reserved_seq)?;
                                reserved_seq
                            } else {
                                tx.allocate_next_auth_seq()?
                            };
                            let pending = PendingAuthRecord {
                                schema_version: STORE_SCHEMA_VERSION,
                                id: pending_id.clone(),
                                flow: PendingAuthFlow::Reauthorize {
                                    target_account_id: target_id.clone(),
                                },
                                token: new_token.clone(),
                                auth_seq,
                                email_mismatch: false,
                                input_rt_digest: None,
                                custom_label: None,
                                created_at: post_now,
                            };
                            let fp = pending.cas_fingerprint();
                            let sid = tx.save_pending_auth_cas(&pending, None)?;
                            Ok((sid, fp))
                        })
                        .map_err(|e| wrap_unpersisted_token_exchange_error(e, true))?;

                    let missing = registry.missing_required_scopes(&new_token);
                    let user_info = match fetch_userinfo(
                        transport,
                        endpoints,
                        user_agent,
                        &new_token.access_token,
                    )
                    .await
                    {
                        Ok(u) => u,
                        Err(err) if err.error_code == "scope_reauth_required" => {
                            return Err(persist_disable_or_report_io_error(
                                repo,
                                &target_id,
                                DisableReasonCode::ScopeReauthRequired,
                                "Userinfo endpoint rejected reauthorized token due to insufficient scopes."
                                    .into(),
                                clock.now_unix(),
                                err,
                            ));
                        }
                        Err(err) => return Err(err),
                    };

                    if !user_info.email.eq_ignore_ascii_case(&current_acc.email) {
                        repo.with_write_lock(|tx| {
                            if let Ok(live_p) =
                                tx.verify_pending_auth_cas(&saved_pending_id, &expected_fp)
                            {
                                let mut marked = live_p;
                                marked.email_mismatch = true;
                                tx.save_pending_auth_cas(&marked, Some(&expected_fp))?;
                            }
                            Ok(())
                        })?;
                        return Err(CliError::auth(
                            "reauthorize_email_mismatch",
                            format!(
                                "Reauthorization completed for '{}', which does not match target account '{}' ({}). Issued token was preserved in pending_auth; use `auth login` to add a new account.",
                                crate::cli::dto::terminal_text(&user_info.email),
                                current_acc.id,
                                current_acc.email
                            ),
                        ));
                    }

                    let commit_now = clock.now_unix();
                    let updated = repo.with_write_lock(|tx| {
                        let live_p = tx.verify_pending_auth_cas(&saved_pending_id, &expected_fp)?;
                        let persisted_lin = tx.load_pending_lineage_digests(&saved_pending_id)?;
                        let mut merged = tx.merge_reauthorized_token_for_pending(
                            &target_id,
                            new_token,
                            user_info.display_name(),
                            &missing,
                            live_p.auth_seq,
                            commit_now,
                        )?;
                        let mut dirty = false;
                        for d in &persisted_lin {
                            merged.record_superseded_digest(d);
                            dirty = true;
                        }
                        if dirty {
                            tx.save_account(&merged)?;
                        }
                        let _ = tx.cleanup_idle_superseded_reauth_pendings_in_tx(
                            Some(&saved_pending_id),
                            &mut merged,
                        )?;
                        tx.remove_pending_auth_cas(&saved_pending_id, &expected_fp)?;
                        Ok(merged)
                    })?;

                    if !missing.is_empty() {
                        return Err(CliError::auth(
                            "scope_reauth_required",
                            format!(
                                "Reauthorization for '{}' ({}) did not grant required OAuth scope(s) ({}). Approve all requested scopes during `agy-switch-cli auth reauthorize {}`.",
                                updated.id,
                                updated.email,
                                missing.join(", "),
                                updated.id
                            ),
                        ));
                    }

                    Ok(updated)
                },
            )
            .await
        },
    )
    .await
}

#[derive(Debug, Clone)]
pub struct PendingResumeReport {
    pub resumed_accounts: Vec<AccountRecord>,
    pub failures: Vec<(String, String)>,
    pub unpersisted_error: Option<CliError>,
}

const PENDING_RESUME_LOCK_TIMEOUT: Duration = Duration::from_millis(250);

#[allow(clippy::too_many_arguments)]
async fn refresh_pending_record_token(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    rec: &PendingAuthRecord,
    expected_prev_fp: &str,
    clock: &AnchoredClock,
) -> CliResult<(String, String, TokenRecord)> {
    let active_token = &rec.token;
    let bound_client = match active_token.oauth_client_key.as_deref() {
        Some(bound_key) => Some(registry.require_bound_client(bound_key)?),
        None => None,
    };
    let pending_id_for_preflight = rec.id.clone();
    repo.with_write_lock(|tx| tx.preflight_pending_auth_staging(&pending_id_for_preflight, false))?;

    let (raw, used_key) = if let Some(client) = bound_client {
        refresh_raw_with_client(
            transport,
            endpoints,
            user_agent,
            &client,
            &active_token.refresh_token,
        )
        .await
        .map(|raw| (raw, client.key))
        .map_err(StructuredOAuthError::into_cli_error)?
    } else {
        probe_refresh_unknown_client(
            transport,
            endpoints,
            registry,
            user_agent,
            &active_token.refresh_token,
        )
        .await
        .map_err(StructuredOAuthError::into_cli_error)?
    };

    let post_now = clock.now_unix();
    let rotated_rt = raw
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| active_token.refresh_token.clone());
    let was_rotated = rotated_rt != active_token.refresh_token;
    let expires_in = raw.expires_in.max(60);
    let next_token = TokenRecord {
        access_token: raw.access_token.trim().to_string(),
        refresh_token: rotated_rt,
        expires_in,
        expiry_timestamp: post_now.saturating_add(expires_in).max(1),
        token_type: if raw.token_type.trim().is_empty() {
            "Bearer".into()
        } else {
            raw.token_type
        },
        id_token: raw
            .id_token
            .filter(|s| !s.trim().is_empty())
            .or_else(|| active_token.id_token.clone()),
        oauth_client_key: Some(used_key),
        granted_scopes: parse_scope_string(raw.scope.as_deref())
            .or_else(|| active_token.granted_scopes.clone()),
        project_id: active_token.project_id.clone(),
        is_gcp_tos: active_token.is_gcp_tos,
    };
    let updated_rec = PendingAuthRecord {
        token: next_token.clone(),
        created_at: post_now,
        ..rec.clone()
    };
    let new_fp = updated_rec.cas_fingerprint();
    let saved_id = repo
        .with_write_lock(|tx| tx.save_pending_auth_cas(&updated_rec, Some(expected_prev_fp)))
        .map_err(|e| wrap_unpersisted_token_exchange_error(e, was_rotated))?;
    Ok((saved_id, new_fp, next_token))
}

/// Complete `userinfo` lookup and bind any interrupted `PendingAuthRecord`s (`AddToken`, `Login`, or `Reauthorize`)
/// stored in `<data_dir>/state/pending_auth/*.json`!
/// - Serializes per-pending lifecycle under `PendingAuthLock` (`L1 -> PendingAuthLock -> L2 -> L3`) and re-reads disk state;
/// - Refreshes any expiring pending token first and persists the updated `PendingAuthRecord` via CAS BEFORE `userinfo`;
/// - Binds `AddToken`/`Login` and `Reauthorize` with strict `L3` CAS verification and compare-and-delete so stale snapshots
///   can NEVER overwrite or discard a newer rotated token!
pub async fn resume_pending_auth_records(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    endpoints: &OAuthEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    now_unix: i64,
) -> CliResult<PendingResumeReport> {
    let clock = AnchoredClock::new(now_unix);
    let listed_raw = repo.list_pending_auth_readonly()?;
    // Process immediately-available records before currently-in-flight (`busy`) records so `resume` never stalls behind
    // an active `auth login`/`reauthorize` before reconciling idle records, and within each group process highest `auth_seq`
    // FIRST so the latest valid authorization binds first and supersedes older attempts!
    let mut listed_with_busy: Vec<(bool, PendingAuthRecord)> = listed_raw
        .into_iter()
        .map(|r| {
            let busy = is_pending_auth_lock_busy(repo.paths(), &r.id).unwrap_or(false);
            (busy, r)
        })
        .collect();
    listed_with_busy.sort_by(|(busy_a, a), (busy_b, b)| {
        busy_a
            .cmp(busy_b)
            .then_with(|| b.auth_seq.cmp(&a.auth_seq))
            .then_with(|| b.created_at.cmp(&a.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    let listed_records: Vec<PendingAuthRecord> =
        listed_with_busy.into_iter().map(|(_, r)| r).collect();
    let mut report = PendingResumeReport {
        resumed_accounts: Vec::new(),
        failures: Vec::new(),
        unpersisted_error: None,
    };

    for listed in listed_records {
        let pid = listed.id.clone();
        let outcome: CliResult<Option<AccountRecord>> = with_pending_auth_lock(
            repo.paths(),
            &pid,
            PENDING_RESUME_LOCK_TIMEOUT,
            || async {
                // Re-read latest `PendingAuthRecord` AFTER acquiring `PendingAuthLock`!
                let Some(rec) = repo.read_pending_auth_opt_readonly(&pid)? else {
                    // Already bound and removed by a concurrent caller!
                    return Ok(None);
                };

                match &rec.flow {
                    PendingAuthFlow::AddToken | PendingAuthFlow::Login => {
                        if matches!(rec.flow, PendingAuthFlow::AddToken) && !rec.email_mismatch {
                            if let Some(acc_pre) =
                                repo.find_account_by_refresh_token_readonly(&rec.token.refresh_token)?
                            {
                                let pre_id = acc_pre.id.clone();
                                let absorbed = with_account_refresh_lock(
                                    repo.paths(),
                                    &pre_id,
                                    Duration::from_secs(20),
                                    || async {
                                        let Some(rec_l2) =
                                            repo.read_pending_auth_opt_readonly(&pid)?
                                        else {
                                            return Ok(true);
                                        };
                                        let Ok(latest_acc) = repo.read_account_unchecked(&pre_id)
                                        else {
                                            return Ok(false);
                                        };
                                        if rec_l2.email_mismatch
                                            || !is_pending_superseded_by_account(
                                                rec_l2.auth_seq,
                                                latest_acc.auth_generation,
                                            )
                                        {
                                            return Ok(false);
                                        }
                                        let fp_l2 = rec_l2.cas_fingerprint();
                                        repo.with_write_lock(|tx| {
                                            Ok(tx
                                                .absorb_superseded_pending_into_account_cas(
                                                    &rec_l2.id,
                                                    &fp_l2,
                                                    &pre_id,
                                                    rec_l2.input_rt_digest.as_deref(),
                                                    &[],
                                                )?
                                                .is_some())
                                        })
                                    },
                                )
                                .await?;
                                if absorbed {
                                    return Ok(None);
                                }
                            }
                        }

                        let mut active_id = rec.id.clone();
                        let mut expected_fp = rec.cas_fingerprint();
                        let mut active_token = rec.token.clone();
                        let mut extra_superseded: Vec<String> = Vec::new();
                        if let Some(ref inp) = rec.input_rt_digest {
                            extra_superseded.push(inp.clone());
                        }

                        if active_token.is_expiring_within(clock.now_unix(), TOKEN_REFRESH_SKEW_SECONDS)
                        {
                            extra_superseded.push(token_digest(&active_token.refresh_token));
                            let (saved_id, new_fp, next_tok) = refresh_pending_record_token(
                                repo,
                                transport,
                                endpoints,
                                registry,
                                user_agent,
                                &rec,
                                &expected_fp,
                                &clock,
                            )
                            .await?;
                            active_id = saved_id;
                            expected_fp = new_fp;
                            active_token = next_tok;
                        }

                        let missing = registry.missing_required_scopes(&active_token);
                        let user_info = fetch_userinfo(
                            transport,
                            endpoints,
                            user_agent,
                            &active_token.access_token,
                        )
                        .await?;

                        let bind_now = clock.now_unix();
                        match bind_verified_account_from_pending_inner(
                            repo,
                            &active_id,
                            &expected_fp,
                            rec.input_rt_digest.as_deref(),
                            &extra_superseded,
                            active_token,
                            &user_info,
                            rec.custom_label.as_deref(),
                            &missing,
                            bind_now,
                        )
                        .await?
                        {
                            BindPendingOutcome::Bound { account, .. } => Ok(Some(account)),
                            BindPendingOutcome::SupersededAbsorbed { .. } => Ok(None),
                        }
                    }
                    PendingAuthFlow::Reauthorize { target_account_id } => {
                        let tid = target_account_id.clone();
                        with_account_refresh_lock(
                            repo.paths(),
                            &tid,
                            Duration::from_secs(20),
                            || async {
                                let Some(rec_l2) = repo.read_pending_auth_opt_readonly(&pid)? else {
                                    return Ok(None);
                                };
                                let mut active_id = rec_l2.id.clone();
                                let mut expected_fp = rec_l2.cas_fingerprint();

                                // Check #1 immediately after acquiring target account `L2` (BEFORE `/token` refresh or `userinfo`!):
                                // If a newer authorization already committed onto `tid` while we waited for `L2`,
                                // absorb this stale pending's digests & lineage and CAS-delete it with ZERO network requests!
                                let pre_acc_l2 = repo.read_account_unchecked(&tid)?;
                                if !rec_l2.email_mismatch
                                    && is_pending_superseded_by_account(
                                        rec_l2.auth_seq,
                                        pre_acc_l2.auth_generation,
                                    )
                                    && repo
                                        .with_write_lock(|tx| {
                                            tx.absorb_superseded_pending_into_account_cas(
                                                &active_id,
                                                &expected_fp,
                                                &tid,
                                                rec_l2.input_rt_digest.as_deref(),
                                                &[],
                                            )
                                        })?
                                        .is_some()
                                {
                                    return Ok(None);
                                }

                                let mut active_token = rec_l2.token.clone();
                                let mut extra_superseded: Vec<String> = Vec::new();

                                if active_token
                                    .is_expiring_within(clock.now_unix(), TOKEN_REFRESH_SKEW_SECONDS)
                                {
                                    extra_superseded
                                        .push(token_digest(&active_token.refresh_token));
                                    let (saved_id, new_fp, next_tok) = refresh_pending_record_token(
                                        repo,
                                        transport,
                                        endpoints,
                                        registry,
                                        user_agent,
                                        &rec_l2,
                                        &expected_fp,
                                        &clock,
                                    )
                                    .await?;
                                    active_id = saved_id;
                                    expected_fp = new_fp;
                                    active_token = next_tok;
                                }

                                let missing = registry.missing_required_scopes(&active_token);
                                let user_info = match fetch_userinfo(
                                    transport,
                                    endpoints,
                                    user_agent,
                                    &active_token.access_token,
                                )
                                .await
                                {
                                    Ok(u) => u,
                                    Err(err) if err.error_code == "scope_reauth_required" => {
                                        if repo
                                            .with_write_lock(|tx| {
                                                tx.absorb_superseded_pending_into_account_cas(
                                                    &active_id,
                                                    &expected_fp,
                                                    &tid,
                                                    rec_l2.input_rt_digest.as_deref(),
                                                    &extra_superseded,
                                                )
                                            })?
                                            .is_some()
                                        {
                                            return Ok(None);
                                        }
                                        return Err(persist_disable_or_report_io_error(
                                            repo,
                                            &tid,
                                            DisableReasonCode::ScopeReauthRequired,
                                            "Userinfo endpoint rejected pending reauthorized token due to insufficient scopes."
                                                .into(),
                                            clock.now_unix(),
                                            err,
                                        ));
                                    }
                                    Err(err) => return Err(err),
                                };

                                let current_acc = repo.read_account_unchecked(&tid)?;
                                if !user_info.email.eq_ignore_ascii_case(&current_acc.email) {
                                    repo.with_write_lock(|tx| {
                                        if let Ok(live_p) =
                                            tx.verify_pending_auth_cas(&active_id, &expected_fp)
                                        {
                                            if !live_p.email_mismatch {
                                                let mut marked = live_p;
                                                marked.email_mismatch = true;
                                                tx.save_pending_auth_cas(
                                                    &marked,
                                                    Some(&expected_fp),
                                                )?;
                                            }
                                        }
                                        Ok(())
                                    })?;
                                    return Err(CliError::auth(
                                        "reauthorize_email_mismatch",
                                        format!(
                                            "Pending reauthorization email '{}' does not match target account '{}' ({}).",
                                            crate::cli::dto::terminal_text(&user_info.email),
                                            current_acc.id,
                                            current_acc.email
                                        ),
                                    ));
                                }

                                let bind_now = clock.now_unix();
                                // Check #2 inside `L3` right before committing `merge_reauthorized_token_for_pending`!
                                repo.with_write_lock(|tx| {
                                    if tx
                                        .absorb_superseded_pending_into_account_cas(
                                            &active_id,
                                            &expected_fp,
                                            &tid,
                                            rec_l2.input_rt_digest.as_deref(),
                                            &extra_superseded,
                                        )?
                                        .is_some()
                                    {
                                        return Ok(None);
                                    }
                                    let live_p =
                                        tx.verify_pending_auth_cas(&active_id, &expected_fp)?;
                                    let persisted_lin =
                                        tx.load_pending_lineage_digests(&active_id)?;
                                    let mut updated = tx.merge_reauthorized_token_for_pending(
                                        &tid,
                                        active_token,
                                        user_info.display_name(),
                                        &missing,
                                        live_p.auth_seq,
                                        bind_now,
                                    )?;
                                    let mut dirty = false;
                                    for d in extra_superseded.iter().chain(persisted_lin.iter()) {
                                        updated.record_superseded_digest(d);
                                        dirty = true;
                                    }
                                    if dirty {
                                        tx.save_account(&updated)?;
                                    }
                                    let _ = tx.cleanup_idle_superseded_reauth_pendings_in_tx(
                                        Some(&active_id),
                                        &mut updated,
                                    )?;
                                    tx.remove_pending_auth_cas(&active_id, &expected_fp)?;
                                    Ok(Some(updated))
                                })
                            },
                        )
                        .await
                    }
                }
            },
        )
        .await;

        match outcome {
            Ok(Some(saved)) => report.resumed_accounts.push(saved),
            Ok(None) => {}
            Err(e) => {
                // If `pid` was actively in flight and finished binding + deleting itself concurrently, do not report a false failure!
                let already_consumed = e.exit_code == crate::error::ExitCode::LockBusyOrConflict
                    && repo
                        .read_pending_auth_opt_readonly(&pid)
                        .is_ok_and(|opt| opt.is_none());
                if !already_consumed {
                    let is_recovery_err =
                        e.exit_code == crate::error::ExitCode::PartialCommitOrRecovery;
                    if is_recovery_err && report.unpersisted_error.is_none() {
                        report.unpersisted_error = Some(e.clone());
                    }
                    report.failures.push((pid, e.message));
                    if is_recovery_err {
                        // Stop immediately upon first unpersisted/recovery error (exit 7) so no
                        // subsequent pending auth records issue further `/token` exchanges!
                        break;
                    }
                }
            }
        }
    }

    Ok(report)
}

pub fn purge_all_pending_auth_records(repo: &StoreRepository) -> CliResult<usize> {
    repo.with_write_lock(|tx| {
        let dir = tx.paths().pending_auth_dir();
        crate::store::fs_atomic::ensure_no_symlink_components_under(&tx.paths().data_dir, &dir)?;
        let entries: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(it) => it.flatten().collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(crate::store::fs_atomic::map_io_error(
                    e,
                    &format!("Cannot inspect pending_auth directory '{}'", dir.display()),
                ))
            }
        };
        let mut held_locks = Vec::new();
        for entry in &entries {
            if let Some(fname) = entry.file_name().to_str() {
                if let Some(id_part) = fname.strip_suffix(".json") {
                    if validate_account_id(id_part).is_ok() {
                        match try_acquire_pending_auth_lock_nonblocking(tx.paths(), id_part)? {
                            Some(guard) => held_locks.push(guard),
                            None => {
                                return Err(CliError::lock_busy(format!(
                                    "Cannot purge pending_auth while record '{id_part}' is actively in flight. Retry shortly."
                                )));
                            }
                        }
                    }
                }
            }
        }
        let mut removed = 0usize;
        for entry in entries {
            let p = entry.path();
            if let Some(fname) = p.file_name().and_then(|n| n.to_str()) {
                if fname.ends_with(".json") && std::fs::remove_file(&p).is_ok() {
                    removed += 1;
                    if let Some(id_part) = fname.strip_suffix(".json") {
                        let _ = tx.remove_pending_lineage(id_part);
                    }
                }
            }
        }
        let p_lin_dir = tx.paths().pending_lineage_dir();
        if std::fs::symlink_metadata(&p_lin_dir)
            .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        {
            if let Ok(lin_entries) = std::fs::read_dir(&p_lin_dir) {
                for ent in lin_entries.flatten() {
                    let lp = ent.path();
                    if lp
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".json"))
                        && std::fs::symlink_metadata(&lp).is_ok_and(|m| m.file_type().is_file())
                    {
                        let _ = std::fs::remove_file(&lp);
                    }
                }
            }
        }
        drop(held_locks);
        Ok(removed)
    })
}
