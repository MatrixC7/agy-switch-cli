use crate::domain::account::{AccountRecord, DisableReasonCode};
use crate::domain::clock::{AnchoredClock, Clock};
use crate::domain::quota::{
    fraction_is_known, ModelQuota, PrimaryModelQuota, QuotaBucket, QuotaGroup, QuotaObservation,
    QuotaSourceEnv,
};
use crate::error::{format_safe_json_error, CliError, CliResult};
use crate::oauth::refresh::{
    ensure_account_token_fresh_locked, persist_disable_or_report_io_error, OAuthEndpoints,
};
use crate::oauth::registry::OAuthClientRegistry;
use crate::quota::fusion::fuse_model_quotas;
use crate::store::repository::StoreRepository;
use crate::transport::client::{HttpRequest, HttpResponse, HttpTransport, TimeoutClass};
use crate::transport::user_agent::SHORT_FALLBACK_USER_AGENT;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

/// Unified Production-first CloudCode environments per Blueprint §5.1.
pub const DEFAULT_CLOUDCODE_ENVIRONMENTS: [(QuotaSourceEnv, &str); 3] = [
    (
        QuotaSourceEnv::Production,
        "https://cloudcode-pa.googleapis.com/v1internal",
    ),
    (
        QuotaSourceEnv::Daily,
        "https://daily-cloudcode-pa.googleapis.com/v1internal",
    ),
    (
        QuotaSourceEnv::Sandbox,
        "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal",
    ),
];

#[derive(Debug, Clone)]
pub struct CloudCodeEndpoints {
    pub environments: Vec<(QuotaSourceEnv, String)>,
    pub fallback_delay: Duration,
}

impl Default for CloudCodeEndpoints {
    fn default() -> Self {
        Self {
            environments: DEFAULT_CLOUDCODE_ENVIRONMENTS
                .iter()
                .map(|(env, url)| (*env, (*url).to_string()))
                .collect(),
            fallback_delay: Duration::from_millis(500),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaApiError {
    /// HTTP 401 -> triggers at most 1 locked forced OAuth token refresh + retry.
    Unauthorized,
    /// Upstream HTTP 403/401 `ACCESS_TOKEN_SCOPE_INSUFFICIENT` / `insufficient_scope` -> marks `ScopeReauthRequired`.
    InsufficientScope(String),
    RateLimited {
        retry_after_secs: Option<u64>,
    },
    ServerOrNetwork(String),
    Protocol(String),
}

impl QuotaApiError {
    pub fn into_cli_error(self) -> CliError {
        match self {
            Self::Unauthorized => CliError::auth(
                "quota_unauthorized",
                "CloudCode API rejected access token (HTTP 401) even after token refresh.",
            ),
            Self::InsufficientScope(_) => CliError::auth(
                "scope_reauth_required",
                "CloudCode API rejected access token due to insufficient OAuth scopes. Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize <ID|EMAIL>`.",
            ),
            Self::RateLimited { .. } => CliError::io(
                "quota_rate_limited",
                "CloudCode quota endpoint rate-limited (HTTP 429). Retry later.",
            ),
            Self::ServerOrNetwork(msg) => CliError::io("quota_network_error", msg),
            Self::Protocol(msg) => CliError::data(msg),
        }
    }
}

fn detect_insufficient_scope_response(resp: &HttpResponse) -> Option<String> {
    if resp.status != 401 && resp.status != 403 {
        return None;
    }
    if resp
        .header("www-authenticate")
        .is_some_and(|h| h.to_ascii_lowercase().contains("insufficient_scope"))
    {
        return Some(format!(
            "CloudCode returned HTTP {} WWW-Authenticate insufficient_scope.",
            resp.status
        ));
    }
    let raw = std::str::from_utf8(&resp.body).ok()?;
    let lower = raw.to_ascii_lowercase();
    if lower.contains("access_token_scope_insufficient")
        || lower.contains("insufficient_scope")
        || lower.contains("insufficient authentication scopes")
        || lower.contains("sign-in update needed")
    {
        return Some(format!(
            "CloudCode returned HTTP {} insufficient authentication scopes.",
            resp.status
        ));
    }
    None
}

#[derive(Debug, Deserialize)]
struct LoadProjectResponse {
    #[serde(rename = "cloudaicompanionProject")]
    project_id: Option<String>,
    #[serde(rename = "currentTier")]
    current_tier: Option<Tier>,
    #[serde(rename = "paidTier")]
    paid_tier: Option<Tier>,
    #[serde(rename = "allowedTiers")]
    allowed_tiers: Option<Vec<Tier>>,
    #[serde(rename = "ineligibleTiers")]
    ineligible_tiers: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct Tier {
    #[serde(rename = "isDefault")]
    is_default: Option<bool>,
    id: Option<String>,
    name: Option<String>,
}

fn tier_label(tier: &Tier) -> Option<String> {
    tier.name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| tier.id.as_deref().map(str::trim).filter(|s| !s.is_empty()))
        .map(str::to_owned)
}

pub fn extract_subscription_tier_from_json(val: &serde_json::Value) -> Option<String> {
    let parsed: LoadProjectResponse = serde_json::from_value(val.clone()).ok()?;
    extract_subscription_tier(&parsed)
}

fn extract_subscription_tier(data: &LoadProjectResponse) -> Option<String> {
    if let Some(paid) = data.paid_tier.as_ref().and_then(tier_label) {
        return Some(paid);
    }
    let is_ineligible = data
        .ineligible_tiers
        .as_ref()
        .is_some_and(|tiers| !tiers.is_empty());
    let default_allowed = data.allowed_tiers.as_ref().and_then(|allowed| {
        allowed
            .iter()
            .find(|t| t.is_default == Some(true))
            .and_then(tier_label)
    });

    if !is_ineligible {
        data.current_tier
            .as_ref()
            .and_then(tier_label)
            .or(default_allowed)
    } else {
        default_allowed
            .or_else(|| data.current_tier.as_ref().and_then(tier_label))
            .map(|label| format!("{label} (Restricted)"))
    }
}

#[derive(Debug, Deserialize)]
struct CatalogResponse {
    models: HashMap<String, RawModelInfo>,
    #[serde(rename = "deprecatedModelIds")]
    deprecated_model_ids: Option<HashMap<String, DeprecatedModelInfo>>,
}

#[derive(Debug, Deserialize)]
struct DeprecatedModelInfo {
    #[serde(rename = "newModelId")]
    new_model_id: String,
}

#[derive(Debug, Deserialize)]
struct RawModelInfo {
    #[serde(rename = "quotaInfo")]
    quota_info: Option<RawQuotaInfo>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "supportsImages")]
    supports_images: Option<bool>,
    #[serde(rename = "supportsThinking")]
    supports_thinking: Option<bool>,
    #[serde(rename = "thinkingBudget")]
    thinking_budget: Option<i32>,
    recommended: Option<bool>,
    #[serde(rename = "maxTokens")]
    max_tokens: Option<i32>,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: Option<i32>,
    #[serde(rename = "supportedMimeTypes")]
    supported_mime_types: Option<HashMap<String, bool>>,
}

#[derive(Debug, Deserialize)]
struct RawQuotaInfo {
    #[serde(rename = "remainingFraction")]
    remaining_fraction: Option<f64>,
    #[serde(rename = "resetTime")]
    reset_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QuotaSummaryResponse {
    groups: Vec<RawSummaryGroup>,
}

#[derive(Debug, Deserialize)]
struct RawSummaryGroup {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    description: Option<String>,
    buckets: Vec<RawSummaryBucket>,
}

#[derive(Debug, Deserialize)]
struct RawSummaryBucket {
    #[serde(rename = "bucketId")]
    bucket_id: Option<String>,
    window: Option<String>,
    #[serde(rename = "remainingFraction")]
    remaining_fraction: Option<f64>,
    #[serde(rename = "resetTime")]
    reset_time: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    description: Option<String>,
}

fn model_from_raw(name: String, info: RawModelInfo) -> Option<ModelQuota> {
    if !["gemini", "claude", "gpt", "image", "imagen"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return None;
    }
    let obs = info.quota_info;
    let fraction = obs
        .as_ref()
        .and_then(|q| q.remaining_fraction)
        .filter(|f| fraction_is_known(Some(*f)));
    let primary_quota = Some(PrimaryModelQuota {
        remaining_fraction: fraction,
        reset_time: obs
            .as_ref()
            .and_then(|q| q.reset_time.clone())
            .unwrap_or_default(),
    });

    Some(ModelQuota {
        name,
        percentage: fraction.map(|f| (f * 100.0).round() as i32).unwrap_or(0),
        percentage_known: Some(fraction.is_some()),
        observed_remaining_fraction: fraction,
        primary_quota,
        quota_bucket_id: None,
        reset_time: obs.and_then(|q| q.reset_time).unwrap_or_default(),
        display_name: info.display_name,
        supports_images: info.supports_images,
        supports_thinking: info.supports_thinking,
        thinking_budget: info.thinking_budget,
        recommended: info.recommended,
        max_tokens: info.max_tokens,
        max_output_tokens: info.max_output_tokens,
        supported_mime_types: info.supported_mime_types,
    })
}

enum EnvLoadOutcome {
    Success {
        project_id: Option<String>,
        subscription_tier: Option<String>,
    },
    ValidationBlocked {
        reason: String,
        validation_url: Option<String>,
    },
    Unavailable,
}

/// Single-environment `:loadCodeAssist` discovery so `Daily` `Free` tiers can NEVER leak into `Production` observations!
async fn fetch_load_code_assist_for_env(
    transport: &dyn HttpTransport,
    base_url: &str,
    user_agent: &str,
    access_token: &str,
) -> Result<EnvLoadOutcome, QuotaApiError> {
    let payload = json!({ "metadata": { "ideType": "ANTIGRAVITY" } });
    let url = format!("{base_url}:loadCodeAssist");
    let req = HttpRequest::post_json(url, payload, TimeoutClass::StandardApi)
        .with_bearer_auth(access_token)
        .with_header("User-Agent", user_agent);

    match transport.execute(req).await {
        Ok(resp) => {
            if let Some(detail) = detect_insufficient_scope_response(&resp) {
                return Err(QuotaApiError::InsufficientScope(detail));
            }
            if resp.status == 401 {
                return Err(QuotaApiError::Unauthorized);
            }
            if resp.status == 403 {
                if let Some((reason, url)) = detect_403_validation_block(&resp.body) {
                    return Ok(EnvLoadOutcome::ValidationBlocked {
                        reason,
                        validation_url: url,
                    });
                }
                return Ok(EnvLoadOutcome::Unavailable);
            }
            if (200..300).contains(&resp.status) {
                if let Ok(parsed) = serde_json::from_slice::<LoadProjectResponse>(&resp.body) {
                    let tier = extract_subscription_tier(&parsed);
                    let pid = parsed
                        .project_id
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    return Ok(EnvLoadOutcome::Success {
                        project_id: pid,
                        subscription_tier: tier,
                    });
                }
            }
            Ok(EnvLoadOutcome::Unavailable)
        }
        Err(_) => Ok(EnvLoadOutcome::Unavailable),
    }
}

#[derive(Debug, Clone)]
pub enum SummaryFetchOutcome {
    Groups(QuotaSourceEnv, Vec<QuotaGroup>),
    ValidationBlocked(String, Option<String>),
    Unavailable,
}

/// Step 3: `:retrieveUserQuotaSummary` on a SINGLE environment (strictly no cross-env merging!).
/// Account-level `InsufficientScope`, `401 Unauthorized`, and `403 VALIDATION_REQUIRED` are classified
/// immediately BEFORE UA/project fallbacks so they are NEVER retried pointlessly or swallowed into `None`!
pub async fn fetch_quota_summary_from_environments(
    transport: &dyn HttpTransport,
    environments: &[(QuotaSourceEnv, String)],
    user_agent: &str,
    access_token: &str,
    project_id: Option<&str>,
) -> Result<SummaryFetchOutcome, QuotaApiError> {
    let default_project = project_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("aicode-consumers");
    let primary_payload = json!({ "project": default_project });

    for (env, base_url) in environments {
        let url = format!("{base_url}:retrieveUserQuotaSummary");
        let attempts = [
            (user_agent, primary_payload.clone()),
            (SHORT_FALLBACK_USER_AGENT, primary_payload.clone()),
            (user_agent, json!({})),
        ];

        for (attempt_idx, (ua, body)) in attempts.iter().enumerate() {
            let req = HttpRequest::post_json(url.clone(), body.clone(), TimeoutClass::StandardApi)
                .with_bearer_auth(access_token)
                .with_header("User-Agent", *ua);

            match transport.execute(req).await {
                Ok(resp) => {
                    if let Some(detail) = detect_insufficient_scope_response(&resp) {
                        return Err(QuotaApiError::InsufficientScope(detail));
                    }
                    if resp.status == 401 {
                        return Err(QuotaApiError::Unauthorized);
                    }
                    if resp.status == 403 {
                        if let Some((reason, vurl)) = detect_403_validation_block(&resp.body) {
                            return Ok(SummaryFetchOutcome::ValidationBlocked(reason, vurl));
                        }
                        if attempt_idx + 1 < attempts.len() {
                            continue;
                        }
                    }
                    if !(200..300).contains(&resp.status) {
                        break;
                    }
                    let Ok(parsed) = serde_json::from_slice::<QuotaSummaryResponse>(&resp.body)
                    else {
                        break;
                    };
                    let groups: Vec<QuotaGroup> = parsed
                        .groups
                        .into_iter()
                        .map(|g| QuotaGroup {
                            display_name: g.display_name.unwrap_or_default(),
                            description: g.description,
                            buckets: g
                                .buckets
                                .into_iter()
                                .map(|b| QuotaBucket {
                                    bucket_id: b.bucket_id.unwrap_or_default(),
                                    window: b.window.unwrap_or_default(),
                                    remaining_fraction: b.remaining_fraction.unwrap_or(0.0),
                                    remaining_fraction_known: Some(fraction_is_known(
                                        b.remaining_fraction,
                                    )),
                                    reset_time: b.reset_time.unwrap_or_default(),
                                    display_name: b.display_name,
                                    description: b.description,
                                })
                                .collect(),
                        })
                        .collect();

                    if groups.is_empty() || groups.iter().all(|g| g.buckets.is_empty()) {
                        break;
                    }
                    return Ok(SummaryFetchOutcome::Groups(*env, groups));
                }
                Err(_) => break,
            }
        }
    }
    Ok(SummaryFetchOutcome::Unavailable)
}

async fn sleep_with_jitter(base: Duration, retry_after_secs: Option<u64>) {
    let raw = match retry_after_secs {
        Some(secs) => Duration::from_secs(secs.min(10)),
        None => base,
    };
    if raw.is_zero() {
        return;
    }
    let jitter = rand::thread_rng().gen_range(85u64..=115u64);
    let ms = (raw.as_millis() as u64 * jitter / 100).max(1);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[derive(Debug, Clone)]
pub struct QuotaFetchOutcome {
    pub observation: QuotaObservation,
    pub discovered_project_id: Option<String>,
    /// Internal-only `(reason, optional_validation_url)` when HTTP 403 indicates `VALIDATION_REQUIRED`.
    pub validation_block: Option<(String, Option<String>)>,
    /// True ONLY when an authoritative primary-environment (`Production`) check succeeded cleanly.
    pub allow_clear_validation_block: bool,
}

fn detect_403_validation_block(body: &[u8]) -> Option<(String, Option<String>)> {
    let raw = std::str::from_utf8(body).ok()?;
    let lower = raw.to_ascii_lowercase();
    let is_validation = lower.contains("validation_required")
        || lower.contains("validation required")
        || lower.contains("verify your account")
        || lower.contains("further action is required")
        || lower.contains("validation_url")
        || lower.contains("appeal_url");
    if !is_validation {
        return None;
    }

    let url = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| find_validation_url_in_json(&v));
    Some((
        "Google CloudCode returned HTTP 403 VALIDATION_REQUIRED.".to_string(),
        url,
    ))
}

fn find_validation_url_in_json(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::Object(map) => {
            for key in ["validation_url", "validationUrl", "appeal_url", "appealUrl"] {
                if let Some(s) = map.get(key).and_then(|v| v.as_str()) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            for child in map.values() {
                if let Some(found) = find_validation_url_in_json(child) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(found) = find_validation_url_in_json(item) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

/// Execute one complete single-environment-isolated 3-step CloudCode quota observation pass:
/// - Each environment (`Production`, then `Daily`, then `Sandbox`) queries its OWN `:loadCodeAssist`,
///   `:fetchAvailableModels`, and `:retrieveUserQuotaSummary` without cross-environment `tier` or `groups` stitching;
/// - Explicit `VALIDATION_REQUIRED` stops immediately without falling back to `Daily` (preserving block evidence);
/// - Generic `is_forbidden` is ONLY recorded when ALL attempted environments returned HTTP 403 (never on `[503, 503, 403]`).
pub async fn fetch_quota_once(
    transport: &dyn HttpTransport,
    endpoints: &CloudCodeEndpoints,
    user_agent: &str,
    access_token: &str,
    cached_project_id: Option<&str>,
    now_unix: i64,
) -> Result<QuotaFetchOutcome, QuotaApiError> {
    let clock = AnchoredClock::new(now_unix);
    let normalized_cached_proj = cached_project_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let mut last_error: Option<QuotaApiError> = None;
    let mut saw_transient_failure = false;
    let mut forbidden_env_count = 0usize;
    let mut last_forbidden_ctx: Option<(QuotaSourceEnv, Option<String>, Option<String>)> = None;

    for (ep_idx, (source_env, base_url)) in endpoints.environments.iter().enumerate() {
        let has_next = ep_idx + 1 < endpoints.environments.len();
        let is_authoritative_primary = ep_idx == 0
            && (*source_env == QuotaSourceEnv::Production || endpoints.environments.len() == 1);

        let (env_project, env_tier) =
            match fetch_load_code_assist_for_env(transport, base_url, user_agent, access_token)
                .await?
            {
                EnvLoadOutcome::Success {
                    project_id,
                    subscription_tier,
                } => (project_id, subscription_tier),
                EnvLoadOutcome::ValidationBlocked {
                    reason,
                    validation_url,
                } => {
                    let obs_now = clock.now_unix();
                    let mut forbidden_obs = QuotaObservation::new(obs_now, *source_env);
                    forbidden_obs.is_forbidden = true;
                    return Ok(QuotaFetchOutcome {
                        observation: forbidden_obs,
                        discovered_project_id: normalized_cached_proj,
                        validation_block: Some((reason, validation_url)),
                        allow_clear_validation_block: false,
                    });
                }
                EnvLoadOutcome::Unavailable => (None, None),
            };

        let effective_project = env_project.or_else(|| normalized_cached_proj.clone());
        let initial_payload = match effective_project {
            Some(ref pid) => json!({ "project": pid }),
            None => json!({}),
        };

        let url = format!("{base_url}:fetchAvailableModels");
        let mut current_payload = initial_payload;
        let mut retried_without_project = false;

        loop {
            let req = HttpRequest::post_json(
                url.clone(),
                current_payload.clone(),
                TimeoutClass::StandardApi,
            )
            .with_bearer_auth(access_token)
            .with_header("User-Agent", user_agent);

            match transport.execute(req).await {
                Ok(resp) => {
                    if let Some(detail) = detect_insufficient_scope_response(&resp) {
                        return Err(QuotaApiError::InsufficientScope(detail));
                    }
                    if resp.status == 401 {
                        return Err(QuotaApiError::Unauthorized);
                    }
                    if resp.status == 403 {
                        // Account-level `VALIDATION_REQUIRED` MUST NOT be masked by stripping `project` or falling back to `Daily`!
                        if let Some((reason, vurl)) = detect_403_validation_block(&resp.body) {
                            let obs_now = clock.now_unix();
                            let mut forbidden_obs = QuotaObservation::new(obs_now, *source_env);
                            forbidden_obs.is_forbidden = true;
                            forbidden_obs.tier_source_env = env_tier.as_ref().map(|_| *source_env);
                            forbidden_obs.subscription_tier = env_tier;
                            return Ok(QuotaFetchOutcome {
                                observation: forbidden_obs,
                                discovered_project_id: effective_project,
                                validation_block: Some((reason, vurl)),
                                allow_clear_validation_block: false,
                            });
                        }
                        if current_payload.get("project").is_some() && !retried_without_project {
                            current_payload = json!({});
                            retried_without_project = true;
                            continue;
                        }
                        forbidden_env_count += 1;
                        last_forbidden_ctx =
                            Some((*source_env, env_tier.clone(), effective_project.clone()));
                        break;
                    }
                    if resp.status == 429 || resp.status >= 500 {
                        saw_transient_failure = true;
                        let retry_after = resp
                            .header("retry-after")
                            .and_then(|v| v.trim().parse::<u64>().ok());
                        last_error = Some(if resp.status == 429 {
                            QuotaApiError::RateLimited {
                                retry_after_secs: retry_after,
                            }
                        } else {
                            QuotaApiError::ServerOrNetwork(format!(
                                "CloudCode endpoint returned HTTP {}.",
                                resp.status
                            ))
                        });
                        if has_next {
                            sleep_with_jitter(endpoints.fallback_delay, retry_after).await;
                            break;
                        }
                        return Err(last_error.unwrap());
                    }
                    if !(200..300).contains(&resp.status) {
                        return Err(QuotaApiError::Protocol(format!(
                            "CloudCode fetchAvailableModels returned unexpected HTTP {}.",
                            resp.status
                        )));
                    }

                    let catalog: CatalogResponse =
                        serde_json::from_slice(&resp.body).map_err(|e| {
                            QuotaApiError::Protocol(format_safe_json_error(
                                "CloudCode fetchAvailableModels response",
                                &e,
                            ))
                        })?;

                    let obs_now = clock.now_unix();
                    let mut obs = QuotaObservation::new(obs_now, *source_env);
                    let mut models_vec = Vec::with_capacity(catalog.models.len());
                    for (name, info) in catalog.models {
                        if let Some(mq) = model_from_raw(name, info) {
                            models_vec.push(mq);
                        }
                    }
                    models_vec.sort_by(|a, b| a.name.cmp(&b.name));
                    obs.models = models_vec;

                    if let Some(deprecated) = catalog.deprecated_model_ids {
                        for (old_id, dep_info) in deprecated {
                            obs.model_forwarding_rules
                                .insert(old_id, dep_info.new_model_id);
                        }
                    }
                    obs.tier_source_env = env_tier.as_ref().map(|_| *source_env);
                    obs.subscription_tier = env_tier;

                    // Strictly query `:retrieveUserQuotaSummary` ONLY on the SAME `source_env`!
                    let same_env_slice = [(*source_env, base_url.clone())];
                    match fetch_quota_summary_from_environments(
                        transport,
                        &same_env_slice,
                        user_agent,
                        access_token,
                        effective_project.as_deref(),
                    )
                    .await?
                    {
                        SummaryFetchOutcome::Groups(sum_env, groups) => {
                            fuse_model_quotas(&mut obs.models, &groups);
                            obs.summary_source_env = Some(sum_env);
                            obs.quota_groups = Some(groups);
                            obs.last_updated = clock.now_unix();
                        }
                        SummaryFetchOutcome::ValidationBlocked(reason, vurl) => {
                            obs.is_forbidden = true;
                            obs.last_updated = clock.now_unix();
                            return Ok(QuotaFetchOutcome {
                                observation: obs,
                                discovered_project_id: effective_project,
                                validation_block: Some((reason, vurl)),
                                allow_clear_validation_block: false,
                            });
                        }
                        SummaryFetchOutcome::Unavailable => {
                            obs.last_updated = clock.now_unix();
                        }
                    }

                    return Ok(QuotaFetchOutcome {
                        observation: obs,
                        discovered_project_id: effective_project,
                        validation_block: None,
                        allow_clear_validation_block: is_authoritative_primary,
                    });
                }
                Err(terr) => {
                    saw_transient_failure = true;
                    last_error = Some(QuotaApiError::ServerOrNetwork(format!(
                        "CloudCode network error: {terr}"
                    )));
                    if has_next {
                        sleep_with_jitter(endpoints.fallback_delay, None).await;
                    }
                    break;
                }
            }
        }
    }

    // Only mark `is_forbidden = true` when EVERY configured environment genuinely returned HTTP 403
    // (NEVER when earlier environments failed transiently with `[503, 503, 403]`!).
    if !saw_transient_failure
        && forbidden_env_count > 0
        && forbidden_env_count == endpoints.environments.len()
    {
        if let Some((f_env, f_tier, f_proj)) = last_forbidden_ctx {
            let obs_now = clock.now_unix();
            let mut forbidden_obs = QuotaObservation::new(obs_now, f_env);
            forbidden_obs.is_forbidden = true;
            forbidden_obs.tier_source_env = f_tier.as_ref().map(|_| f_env);
            forbidden_obs.subscription_tier = f_tier;
            return Ok(QuotaFetchOutcome {
                observation: forbidden_obs,
                discovered_project_id: f_proj,
                validation_block: None,
                allow_clear_validation_block: false,
            });
        }
    }

    Err(last_error.unwrap_or_else(|| {
        QuotaApiError::ServerOrNetwork("All CloudCode quota endpoints failed.".into())
    }))
}

/// High-level locked account quota refresh with closed-loop HTTP 401 forced token renewal:
/// 1. Ensures token is fresh under `L2 (AccountRefreshLock) -> L3 (StoreWriteLock)`.
/// 2. Queries CloudCode (`fetch_quota_once`).
/// 3. On structured `QuotaApiError::Unauthorized` (HTTP 401), performs **at most 1** forced token refresh
///    under `L2 -> L3` (persisting any rotated `refresh_token` immediately!) and replays `fetch_quota_once`.
/// 4. Merges `QuotaObservation` + `project_id` under `L3 (StoreWriteLock)` without clobbering rotated tokens,
///    and explicitly propagates any `mark_account_disabled` storage I/O failures!
#[allow(clippy::too_many_arguments)]
pub async fn refresh_account_quota_locked(
    repo: &StoreRepository,
    transport: &dyn HttpTransport,
    oauth_endpoints: &OAuthEndpoints,
    quota_endpoints: &CloudCodeEndpoints,
    registry: &OAuthClientRegistry,
    user_agent: &str,
    account_id: &str,
    now_unix: i64,
) -> CliResult<AccountRecord> {
    let clock = AnchoredClock::new(now_unix);
    let ensured = ensure_account_token_fresh_locked(
        repo,
        transport,
        oauth_endpoints,
        registry,
        user_agent,
        account_id,
        false,
        clock.now_unix(),
    )
    .await?;

    let first_attempt = fetch_quota_once(
        transport,
        quota_endpoints,
        user_agent,
        &ensured.account.token.access_token,
        ensured.account.token.project_id.as_deref(),
        clock.now_unix(),
    )
    .await;

    let mark_scope_reauth = |detail: String, ts: i64| -> CliError {
        let auth_err = CliError::auth(
            "scope_reauth_required",
            format!(
                "Account '{account_id}' lacks required OAuth scopes for CloudCode. Token refresh cannot upgrade scopes (RFC 6749 §6); run `agy-switch-cli auth reauthorize {account_id}`."
            ),
        );
        persist_disable_or_report_io_error(
            repo,
            account_id,
            DisableReasonCode::ScopeReauthRequired,
            detail,
            ts,
            auth_err,
        )
    };

    let fetched = match first_attempt {
        Ok(ok_outcome) => ok_outcome,
        Err(QuotaApiError::InsufficientScope(detail)) => {
            return Err(mark_scope_reauth(detail, clock.now_unix()))
        }
        Err(QuotaApiError::Unauthorized) => {
            // Single locked forced refresh + single replay!
            let forced = ensure_account_token_fresh_locked(
                repo,
                transport,
                oauth_endpoints,
                registry,
                user_agent,
                account_id,
                true,
                clock.now_unix(),
            )
            .await?;

            match fetch_quota_once(
                transport,
                quota_endpoints,
                user_agent,
                &forced.account.token.access_token,
                forced.account.token.project_id.as_deref(),
                clock.now_unix(),
            )
            .await
            {
                Ok(replayed) => replayed,
                Err(QuotaApiError::InsufficientScope(detail)) => {
                    return Err(mark_scope_reauth(detail, clock.now_unix()));
                }
                Err(other_err) => return Err(other_err.into_cli_error()),
            }
        }
        Err(other_err) => return Err(other_err.into_cli_error()),
    };

    repo.with_write_lock(|tx| {
        tx.merge_quota_observation(
            account_id,
            fetched.observation,
            fetched.discovered_project_id,
            fetched.validation_block,
            fetched.allow_clear_validation_block,
        )
    })
}
