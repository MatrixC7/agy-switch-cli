use crate::domain::account::AccountRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DEFAULT_QUOTA_MAX_AGE_SECS: i64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPool {
    Gemini,
    ThirdParty,
    Argon,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaSourceEnv {
    Production,
    Daily,
    Sandbox,
    #[default]
    LegacyUnknown,
}

/// Canonical bucket IDs take precedence over translated or abbreviated labels.
/// Model-specific unknown `gemini-*` or `3p-*` buckets NEVER fall back into shared pools.
pub fn quota_pool(bucket_id: &str, group_name: &str) -> Option<QuotaPool> {
    let id = bucket_id.trim().to_ascii_lowercase();
    match id.as_str() {
        "gemini-5h" | "gemini-weekly" => return Some(QuotaPool::Gemini),
        "3p-5h" | "3p-weekly" => return Some(QuotaPool::ThirdParty),
        "gemini-argon-wtu-weekly" => return Some(QuotaPool::Argon),
        _ => {}
    }
    if id.starts_with("gemini-argon-") {
        return Some(QuotaPool::Argon);
    }
    if id.starts_with("gemini-") || id.starts_with("3p-") {
        return None;
    }
    match group_name.trim().to_ascii_lowercase().as_str() {
        "gemini" | "gemini models" => Some(QuotaPool::Gemini),
        "claude"
        | "claude / gpt"
        | "claude/gpt"
        | "claude/gpt models"
        | "claude and gpt models" => Some(QuotaPool::ThirdParty),
        "gemini 4 argon" => Some(QuotaPool::Argon),
        _ => None,
    }
}

pub fn model_quota_pool(name: &str, display_name: Option<&str>) -> Option<QuotaPool> {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("gemini") {
        let words = |value: &str| {
            value
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(|w| w.to_ascii_lowercase())
                .collect::<Vec<_>>()
        };
        let labels: Vec<_> = [name, display_name.unwrap_or("")]
            .iter()
            .flat_map(|value| words(value))
            .collect();
        let has = |word: &str| labels.iter().any(|value| value == word);
        if lower.starts_with("gemini-pro-orchestrator") {
            return if has("argon") || lower.contains("g1-pro") {
                Some(QuotaPool::Argon)
            } else {
                None
            };
        }
        if has("carbon") || lower.starts_with("gemini-4-carbon") {
            None
        } else if has("argon") || lower.starts_with("gemini-4-argon") {
            Some(QuotaPool::Argon)
        } else {
            Some(QuotaPool::Gemini)
        }
    } else if lower.starts_with("claude") || lower.starts_with("gpt") {
        Some(QuotaPool::ThirdParty)
    } else {
        None
    }
}

pub fn quota_group_label(name: &str) -> &str {
    match quota_pool("", name) {
        Some(QuotaPool::Gemini) => "Gemini",
        Some(QuotaPool::ThirdParty) => "Claude/GPT",
        _ => name,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaBucket {
    pub bucket_id: String,
    pub window: String,
    pub remaining_fraction: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_fraction_known: Option<bool>,
    pub reset_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaGroup {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub buckets: Vec<QuotaBucket>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrimaryModelQuota {
    pub remaining_fraction: Option<f64>,
    pub reset_time: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelQuota {
    pub name: String,
    pub percentage: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percentage_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_remaining_fraction: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_quota: Option<PrimaryModelQuota>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bucket_id: Option<String>,
    pub reset_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_images: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_thinking: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_budget: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_mime_types: Option<HashMap<String, bool>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaObservation {
    #[serde(default)]
    pub models: Vec<ModelQuota>,
    pub last_updated: i64,
    #[serde(default)]
    pub is_forbidden: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_source_env: Option<QuotaSourceEnv>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub model_forwarding_rules: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_groups: Option<Vec<QuotaGroup>>,
    #[serde(default)]
    pub source_env: QuotaSourceEnv,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_source_env: Option<QuotaSourceEnv>,
}

impl QuotaObservation {
    pub fn new(now_unix: i64, source_env: QuotaSourceEnv) -> Self {
        Self {
            models: Vec::new(),
            last_updated: now_unix,
            is_forbidden: false,
            forbidden_reason: None,
            subscription_tier: None,
            tier_source_env: None,
            model_forwarding_rules: HashMap::new(),
            quota_groups: None,
            source_env,
            summary_source_env: None,
        }
    }
}

pub fn fraction_is_known(value: Option<f64>) -> bool {
    value.is_some_and(|v| v.is_finite() && (0.0..=1.0).contains(&v))
}

pub fn observed_quota_percentage(value: f64, known: Option<bool>) -> Option<i32> {
    (known != Some(false) && (known.is_some() || value != 0.0) && fraction_is_known(Some(value)))
        .then(|| (value * 100.0).round() as i32)
}

/// Four-state quota evaluation result per Blueprint §5.2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QuotaEval {
    Known { remaining_percentage: f64 },
    Unknown { reason: String },
    Stale { reason: String },
    Unavailable { reason: String },
}

impl QuotaEval {
    pub fn known_value(&self) -> Option<f64> {
        match self {
            Self::Known {
                remaining_percentage,
            } => Some(*remaining_percentage),
            _ => None,
        }
    }
}

pub fn evaluate_account_quota(
    account: &AccountRecord,
    monitored_model: &str,
    now_unix: i64,
    max_age_secs: i64,
) -> QuotaEval {
    if account.disabled {
        return QuotaEval::Unavailable {
            reason: "account_disabled".into(),
        };
    }
    if account.is_validation_blocked_at(now_unix) {
        return QuotaEval::Unavailable {
            reason: "validation_blocked".into(),
        };
    }
    let Some(ref q) = account.quota else {
        return QuotaEval::Unknown {
            reason: "no_quota".into(),
        };
    };
    evaluate_quota_observation(q, monitored_model, now_unix, max_age_secs)
}

pub fn evaluate_quota_observation(
    q: &QuotaObservation,
    monitored_model: &str,
    now_unix: i64,
    max_age_secs: i64,
) -> QuotaEval {
    if q.is_forbidden {
        return QuotaEval::Unavailable {
            reason: "quota_forbidden".into(),
        };
    }
    if q.last_updated > now_unix + 30 {
        return QuotaEval::Stale {
            reason: "future_timestamp".into(),
        };
    }
    if now_unix - q.last_updated > max_age_secs {
        return QuotaEval::Stale {
            reason: "stale_quota".into(),
        };
    }

    let trimmed = monitored_model.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        return aggregate_family(q, now_unix, |_| true);
    }
    if trimmed.eq_ignore_ascii_case("gemini") {
        return aggregate_family(q, now_unix, |m| {
            model_quota_pool(&m.name, m.display_name.as_deref()) == Some(QuotaPool::Gemini)
        });
    }
    if trimmed.eq_ignore_ascii_case("argon") {
        return aggregate_family(q, now_unix, |m| {
            model_quota_pool(&m.name, m.display_name.as_deref()) == Some(QuotaPool::Argon)
        });
    }
    if trimmed.eq_ignore_ascii_case("claude")
        || trimmed.eq_ignore_ascii_case("3p")
        || trimmed.eq_ignore_ascii_case("non-gemini")
    {
        return aggregate_family(q, now_unix, |m| {
            let lower = m.name.to_ascii_lowercase();
            lower.starts_with("claude") || lower.starts_with("gpt")
        });
    }

    evaluate_single_model(q, trimmed, now_unix)
}

fn aggregate_family(
    q: &QuotaObservation,
    now_unix: i64,
    predicate: impl Fn(&ModelQuota) -> bool,
) -> QuotaEval {
    let mut min_val: Option<f64> = None;
    let mut saw_stale = false;
    for m in &q.models {
        if !predicate(m) {
            continue;
        }
        match evaluate_single_model(q, &m.name, now_unix) {
            QuotaEval::Known {
                remaining_percentage,
            } => {
                min_val =
                    Some(min_val.map_or(remaining_percentage, |old| old.min(remaining_percentage)));
            }
            QuotaEval::Stale { .. } => {
                saw_stale = true;
            }
            QuotaEval::Unknown { .. } | QuotaEval::Unavailable { .. } => {}
        }
    }
    if saw_stale {
        // Any reset-expired window inside the monitored pool invalidates optimistic min assumptions.
        return QuotaEval::Stale {
            reason: "reset_deadline_passed".into(),
        };
    }
    match min_val {
        Some(v) => QuotaEval::Known {
            remaining_percentage: v,
        },
        None => QuotaEval::Unknown {
            reason: "unknown_pool".into(),
        },
    }
}

enum SingleModelDetail {
    Known {
        effective_pct: f64,
        short_5h: Option<f64>,
        weekly: f64,
    },
    Stale {
        reason: &'static str,
        classified: bool,
    },
    Disabled,
    Unclassified,
    Unknown {
        reason: &'static str,
        classified: bool,
    },
}

fn resolve_forwarded_model<'a>(q: &'a QuotaObservation, model: &'a str) -> &'a str {
    let mut resolved = model;
    for _ in 0..8 {
        if let Some(next) = q.model_forwarding_rules.get(resolved) {
            resolved = next.as_str();
        } else {
            break;
        }
    }
    resolved
}

fn evaluate_single_model_detail(
    q: &QuotaObservation,
    model: &str,
    now_unix: i64,
) -> SingleModelDetail {
    let resolved = resolve_forwarded_model(q, model);

    if resolved.to_ascii_lowercase().ends_with("-disabled") {
        return SingleModelDetail::Disabled;
    }

    let Some(m) = q.models.iter().find(|m| m.name == resolved) else {
        let orig_display = q
            .models
            .iter()
            .find(|cand| cand.name == model)
            .and_then(|cand| cand.display_name.as_deref());
        let classified = model_quota_pool(resolved, None).is_some()
            || model_quota_pool(model, orig_display).is_some();
        return SingleModelDetail::Unknown {
            reason: "model_not_found",
            classified,
        };
    };

    let pool = model_quota_pool(resolved, m.display_name.as_deref());
    let classified = pool.is_some();

    if m.percentage_known == Some(false) || !(0..=100).contains(&m.percentage) {
        return SingleModelDetail::Unknown {
            reason: "model_percentage_unknown",
            classified,
        };
    }

    // Model-endpoint primary quota constraint: when `primary_quota` is present (catalog observation),
    // its own `remaining_fraction` MUST be known — shared summary pools can NEVER promote an unknown
    // per-model primary fraction (`None`) into `Known`!
    let model_primary_pct = if let Some(ref pq) = m.primary_quota {
        match pq.remaining_fraction {
            Some(frac) if fraction_is_known(Some(frac)) => {
                if !pq.reset_time.trim().is_empty() {
                    let Some(parsed_pq_reset_unix) =
                        crate::domain::clock::parse_rfc3339_unix_seconds(&pq.reset_time)
                    else {
                        return SingleModelDetail::Unknown {
                            reason: "invalid_primary_reset_time",
                            classified,
                        };
                    };
                    if parsed_pq_reset_unix <= now_unix {
                        return SingleModelDetail::Stale {
                            reason: "reset_deadline_passed",
                            classified,
                        };
                    }
                }
                (frac * 100.0).min(m.percentage as f64)
            }
            Some(_) => {
                return SingleModelDetail::Unknown {
                    reason: "invalid_primary_fraction",
                    classified,
                }
            }
            None => {
                return SingleModelDetail::Unknown {
                    reason: "missing_primary_fraction",
                    classified,
                }
            }
        }
    } else {
        if !m.reset_time.trim().is_empty() {
            let Some(parsed_m_reset_unix) =
                crate::domain::clock::parse_rfc3339_unix_seconds(&m.reset_time)
            else {
                return SingleModelDetail::Unknown {
                    reason: "invalid_reset_time",
                    classified,
                };
            };
            if parsed_m_reset_unix <= now_unix {
                return SingleModelDetail::Stale {
                    reason: "reset_deadline_passed",
                    classified,
                };
            }
        }
        m.percentage as f64
    };

    let Some(pool) = pool else {
        return SingleModelDetail::Unclassified;
    };
    let Some(ref groups) = q.quota_groups else {
        return SingleModelDetail::Unknown {
            reason: "missing_quota_groups",
            classified: true,
        };
    };

    let mut weekly: Option<f64> = None;
    let mut short_5h: Option<f64> = None;
    let mut argon_observation: Option<(f64, &str)> = None;
    let mut observations: HashMap<String, (f64, &str, &str)> = HashMap::new();

    for group in groups {
        for bucket in &group.buckets {
            let id = bucket.bucket_id.to_ascii_lowercase();
            if quota_pool(&id, &group.display_name) != Some(pool) {
                continue;
            }
            if bucket.remaining_fraction_known == Some(false)
                || (pool == QuotaPool::Argon && bucket.remaining_fraction_known != Some(true))
                || !bucket.remaining_fraction.is_finite()
                || !(0.0..=1.0).contains(&bucket.remaining_fraction)
            {
                return SingleModelDetail::Unknown {
                    reason: "invalid_bucket_fraction",
                    classified: true,
                };
            }

            let Some(parsed_reset_unix) =
                crate::domain::clock::parse_rfc3339_unix_seconds(&bucket.reset_time)
            else {
                return SingleModelDetail::Unknown {
                    reason: "invalid_reset_time",
                    classified: true,
                };
            };
            if parsed_reset_unix <= now_unix {
                return SingleModelDetail::Stale {
                    reason: "reset_deadline_passed",
                    classified: true,
                };
            }

            let window = bucket.window.to_ascii_lowercase();
            let obs = (
                bucket.remaining_fraction,
                bucket.reset_time.as_str(),
                bucket.bucket_id.as_str(),
            );
            if observations
                .insert(window.clone(), obs)
                .is_some_and(|old| old != obs)
            {
                return SingleModelDetail::Unknown {
                    reason: "conflicting_window_buckets",
                    classified: true,
                };
            }

            let value = bucket.remaining_fraction * 100.0;
            if pool == QuotaPool::Argon {
                if window != "weekly" {
                    return SingleModelDetail::Unknown {
                        reason: "unexpected_argon_window",
                        classified: true,
                    };
                }
                let a_obs = (bucket.remaining_fraction, bucket.reset_time.as_str());
                if argon_observation.is_some_and(|old| old != a_obs) {
                    return SingleModelDetail::Unknown {
                        reason: "conflicting_argon_buckets",
                        classified: true,
                    };
                }
                argon_observation = Some(a_obs);
            }

            if id.ends_with("weekly") || window == "weekly" {
                weekly = Some(weekly.map_or(value, |old| old.min(value)));
            } else if id.ends_with("5h") || window == "5h" {
                short_5h = Some(short_5h.map_or(value, |old| old.min(value)));
            } else {
                return SingleModelDetail::Unknown {
                    reason: "unknown_bucket_window",
                    classified: true,
                };
            }
        }
    }

    let Some(weekly_pct) = weekly else {
        return SingleModelDetail::Unknown {
            reason: "missing_weekly_bucket",
            classified: true,
        };
    };

    if pool == QuotaPool::Argon {
        return SingleModelDetail::Known {
            effective_pct: weekly_pct.min(model_primary_pct),
            short_5h: None,
            weekly: weekly_pct,
        };
    }

    let same_env_tier =
        q.source_env != QuotaSourceEnv::LegacyUnknown && q.tier_source_env == Some(q.source_env);
    let tier_lower = q
        .subscription_tier
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_free = same_env_tier && (tier_lower.contains("free") || tier_lower.contains("starter"));

    match short_5h {
        Some(v) => SingleModelDetail::Known {
            effective_pct: weekly_pct.min(v).min(model_primary_pct),
            short_5h: Some(v),
            weekly: weekly_pct,
        },
        None if is_free => SingleModelDetail::Known {
            effective_pct: weekly_pct.min(model_primary_pct),
            short_5h: None,
            weekly: weekly_pct,
        },
        None => SingleModelDetail::Unknown {
            reason: "missing_5h_bucket",
            classified: true,
        },
    }
}

pub fn evaluate_single_model(q: &QuotaObservation, model: &str, now_unix: i64) -> QuotaEval {
    match evaluate_single_model_detail(q, model, now_unix) {
        SingleModelDetail::Known { effective_pct, .. } => QuotaEval::Known {
            remaining_percentage: effective_pct,
        },
        SingleModelDetail::Stale { reason, .. } => QuotaEval::Stale {
            reason: reason.into(),
        },
        SingleModelDetail::Disabled => QuotaEval::Unknown {
            reason: "model_disabled".into(),
        },
        SingleModelDetail::Unclassified => QuotaEval::Unknown {
            reason: "unclassified_model_pool".into(),
        },
        SingleModelDetail::Unknown { reason, .. } => QuotaEval::Unknown {
            reason: reason.into(),
        },
    }
}

/// Effective dual-window remaining quota percentages (`5h` and `Weekly`) across the pools
/// matched by a policy's `monitored_model`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowQuotaSnapshot {
    pub short_5h_pct: Option<u8>,
    pub weekly_pct: Option<u8>,
}

fn round_pct(v: f64) -> u8 {
    v.clamp(0.0, 100.0).round() as u8
}

fn evaluate_family_windows(
    q: &QuotaObservation,
    now_unix: i64,
    predicate: impl Fn(&ModelQuota) -> bool,
) -> WindowQuotaSnapshot {
    let mut min_5h: Option<f64> = None;
    let mut min_weekly: Option<f64> = None;

    for m in &q.models {
        if !predicate(m) {
            continue;
        }
        match evaluate_single_model_detail(q, &m.name, now_unix) {
            SingleModelDetail::Known {
                short_5h, weekly, ..
            } => {
                if let Some(v) = short_5h {
                    min_5h = Some(min_5h.map_or(v, |old| old.min(v)));
                }
                min_weekly = Some(min_weekly.map_or(weekly, |old| old.min(weekly)));
            }
            SingleModelDetail::Disabled
            | SingleModelDetail::Unclassified
            | SingleModelDetail::Stale {
                classified: false, ..
            }
            | SingleModelDetail::Unknown {
                classified: false, ..
            } => {}
            SingleModelDetail::Stale {
                classified: true, ..
            }
            | SingleModelDetail::Unknown {
                classified: true, ..
            } => {
                // Fail closed: do not mask an expired, uncertain, incomplete, or conflicting
                // monitored model/pool with percentages from another pool.
                return WindowQuotaSnapshot::default();
            }
        }
    }

    WindowQuotaSnapshot {
        short_5h_pct: min_5h.map(round_pct),
        weekly_pct: min_weekly.map(round_pct),
    }
}

/// Extract minimum valid `5h` and `Weekly` remaining percentages across all quota pools matched
/// by `monitored_model`, reusing `evaluate_single_model` fail-closed guards and distinguishing
/// legitimate windowless tiers (Argon / same-env Free/Starter) from unavailable or conflicting pools.
pub fn evaluate_account_window_quotas(
    account: &AccountRecord,
    monitored_model: &str,
    now_unix: i64,
    max_age_secs: i64,
) -> WindowQuotaSnapshot {
    if account.disabled || account.is_validation_blocked_at(now_unix) {
        return WindowQuotaSnapshot::default();
    }
    let Some(ref q) = account.quota else {
        return WindowQuotaSnapshot::default();
    };
    if q.is_forbidden || q.last_updated > now_unix + 30 || now_unix - q.last_updated > max_age_secs
    {
        return WindowQuotaSnapshot::default();
    }

    let trimmed = monitored_model.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        return evaluate_family_windows(q, now_unix, |_| true);
    }
    if trimmed.eq_ignore_ascii_case("gemini") {
        return evaluate_family_windows(q, now_unix, |m| {
            model_quota_pool(&m.name, m.display_name.as_deref()) == Some(QuotaPool::Gemini)
        });
    }
    if trimmed.eq_ignore_ascii_case("argon") {
        return evaluate_family_windows(q, now_unix, |m| {
            model_quota_pool(&m.name, m.display_name.as_deref()) == Some(QuotaPool::Argon)
        });
    }
    if trimmed.eq_ignore_ascii_case("claude")
        || trimmed.eq_ignore_ascii_case("3p")
        || trimmed.eq_ignore_ascii_case("non-gemini")
    {
        return evaluate_family_windows(q, now_unix, |m| {
            let lower = m.name.to_ascii_lowercase();
            lower.starts_with("claude") || lower.starts_with("gpt")
        });
    }

    match evaluate_single_model_detail(q, trimmed, now_unix) {
        SingleModelDetail::Known {
            short_5h, weekly, ..
        } => WindowQuotaSnapshot {
            short_5h_pct: short_5h.map(round_pct),
            weekly_pct: Some(round_pct(weekly)),
        },
        _ => WindowQuotaSnapshot::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::token::TokenRecord;

    fn sample_window_account(now: i64) -> AccountRecord {
        let mut acc = AccountRecord::new(
            "acc-win-001".into(),
            "alice@example.com".into(),
            TokenRecord {
                access_token: "at".into(),
                refresh_token: "rt".into(),
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
        let mut obs = QuotaObservation::new(now - 30, QuotaSourceEnv::Daily);
        obs.models = vec![
            ModelQuota {
                name: "gemini-3.8-flash-high".into(),
                percentage: 72,
                percentage_known: Some(true),
                observed_remaining_fraction: Some(0.72),
                primary_quota: None,
                quota_bucket_id: Some("gemini-weekly".into()),
                reset_time: "2099-01-07T00:00:00Z".into(),
                display_name: None,
                supports_images: None,
                supports_thinking: None,
                thinking_budget: None,
                recommended: None,
                max_tokens: None,
                max_output_tokens: None,
                supported_mime_types: None,
            },
            ModelQuota {
                name: "claude-opus-4-6".into(),
                percentage: 2,
                percentage_known: Some(true),
                observed_remaining_fraction: Some(0.02),
                primary_quota: None,
                quota_bucket_id: Some("3p-5h".into()),
                reset_time: "2099-01-01T05:00:00Z".into(),
                display_name: None,
                supports_images: None,
                supports_thinking: None,
                thinking_budget: None,
                recommended: None,
                max_tokens: None,
                max_output_tokens: None,
                supported_mime_types: None,
            },
            ModelQuota {
                name: "gemini-4-argon-high".into(),
                percentage: 60,
                percentage_known: Some(true),
                observed_remaining_fraction: Some(0.60),
                primary_quota: None,
                quota_bucket_id: Some("gemini-argon-wtu-weekly".into()),
                reset_time: "2099-01-07T00:00:00Z".into(),
                display_name: None,
                supports_images: None,
                supports_thinking: None,
                thinking_budget: None,
                recommended: None,
                max_tokens: None,
                max_output_tokens: None,
                supported_mime_types: None,
            },
        ];
        obs.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: None,
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "gemini-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.90,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T05:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "gemini-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.72,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Claude and GPT models".into(),
                description: None,
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "3p-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.02,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T05:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "3p-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.40,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Gemini 4 Argon".into(),
                description: None,
                buckets: vec![QuotaBucket {
                    bucket_id: "gemini-argon-wtu-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.60,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-07T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                }],
            },
        ]);
        acc.quota = Some(obs);
        acc
    }

    #[test]
    fn evaluate_account_window_quotas_tracks_5h_and_weekly_per_policy_scope() {
        let now = 1_800_000_000i64;
        let acc = sample_window_account(now);

        assert_eq!(
            evaluate_account_window_quotas(&acc, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot {
                short_5h_pct: Some(2),
                weekly_pct: Some(40),
            }
        );
        assert_eq!(
            evaluate_account_window_quotas(&acc, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot {
                short_5h_pct: Some(90),
                weekly_pct: Some(72),
            }
        );
        assert_eq!(
            evaluate_account_window_quotas(&acc, "claude", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot {
                short_5h_pct: Some(2),
                weekly_pct: Some(40),
            }
        );
        assert_eq!(
            evaluate_account_window_quotas(&acc, "argon", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot {
                short_5h_pct: None,
                weekly_pct: Some(60),
            }
        );

        // Forwarding rule + single model scope
        let mut forwarded = acc.clone();
        forwarded
            .quota
            .as_mut()
            .unwrap()
            .model_forwarding_rules
            .insert("alias-gemini".into(), "gemini-3.8-flash-high".into());
        assert_eq!(
            evaluate_account_window_quotas(
                &forwarded,
                "alias-gemini",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot {
                short_5h_pct: Some(90),
                weekly_pct: Some(72),
            }
        );

        // Expired reset_time fails closed
        let mut expired = acc.clone();
        expired
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[1]
            .buckets[0]
            .reset_time = "2020-01-01T00:00:00Z".into();
        assert_eq!(
            evaluate_account_window_quotas(&expired, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot::default()
        );

        // Stale observation fails closed
        assert_eq!(
            evaluate_account_window_quotas(&acc, "all", now + 4000, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot::default()
        );

        // Model's own expired reset_time fails closed even while pool buckets remain unexpired
        let mut expired_model = acc.clone();
        expired_model.quota.as_mut().unwrap().models[0].reset_time = "2020-01-01T00:00:00Z".into();
        assert_eq!(
            evaluate_account_window_quotas(
                &expired_model,
                "gemini-3.8-flash-high",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot::default()
        );
        assert_eq!(
            evaluate_account_window_quotas(&expired_model, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot::default()
        );

        // Missing primary_quota.remaining_fraction fails closed on both single-model and `all`
        let mut missing_primary = acc.clone();
        missing_primary.quota.as_mut().unwrap().models[0].primary_quota = Some(PrimaryModelQuota {
            remaining_fraction: None,
            reset_time: "2099-01-07T00:00:00Z".into(),
        });
        assert_eq!(
            evaluate_account_window_quotas(
                &missing_primary,
                "gemini-3.8-flash-high",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot::default()
        );
        assert_eq!(
            evaluate_account_window_quotas(
                &missing_primary,
                "all",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot::default()
        );
        // Unrelated healthy family scope remains readable
        assert_eq!(
            evaluate_account_window_quotas(
                &missing_primary,
                "claude",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot {
                short_5h_pct: Some(2),
                weekly_pct: Some(40),
            }
        );

        // Conflicting bucket in one monitored pool fails closed for `all` instead of masking with other pools
        let mut conflicting = acc.clone();
        conflicting
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[1]
            .buckets
            .push(QuotaBucket {
                bucket_id: "3p-5h".into(),
                window: "5h".into(),
                remaining_fraction: 0.99,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-01T05:00:00Z".into(),
                display_name: None,
                description: None,
            });
        assert_eq!(
            evaluate_account_window_quotas(&conflicting, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot::default()
        );
        assert_eq!(
            evaluate_account_window_quotas(&conflicting, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot {
                short_5h_pct: Some(90),
                weekly_pct: Some(72),
            }
        );

        // Missing 5h bucket on non-Free tier fails closed, while same-env Free/Starter legitimately shows `None` for 5h
        let mut no_5h = acc.clone();
        no_5h.quota.as_mut().unwrap().quota_groups.as_mut().unwrap()[0]
            .buckets
            .retain(|b| b.window != "5h");
        assert_eq!(
            evaluate_account_window_quotas(&no_5h, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot::default()
        );
        no_5h.quota.as_mut().unwrap().subscription_tier = Some("Google AI Free".into());
        no_5h.quota.as_mut().unwrap().tier_source_env = Some(QuotaSourceEnv::Daily);
        assert_eq!(
            evaluate_account_window_quotas(&no_5h, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot {
                short_5h_pct: None,
                weekly_pct: Some(72),
            }
        );

        // Unclassified internal model in `q.models` does not poison valid pools under `all`
        let mut with_unclassified = acc.clone();
        with_unclassified
            .quota
            .as_mut()
            .unwrap()
            .models
            .push(ModelQuota {
                name: "gemini-4-carbon-high".into(),
                percentage: 0,
                percentage_known: Some(false),
                observed_remaining_fraction: None,
                primary_quota: None,
                quota_bucket_id: None,
                reset_time: String::new(),
                display_name: None,
                supports_images: None,
                supports_thinking: None,
                thinking_budget: None,
                recommended: None,
                max_tokens: None,
                max_output_tokens: None,
                supported_mime_types: None,
            });
        assert_eq!(
            evaluate_account_window_quotas(
                &with_unclassified,
                "all",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot {
                short_5h_pct: Some(2),
                weekly_pct: Some(40),
            }
        );

        // Unclassified internal model with KNOWN percentage and EXPIRED reset_time (model or primary_quota)
        // must NOT poison valid pools under `all` in notification display, while keeping `evaluate_single_model` Stale.
        let mut unclassified_stale_model = acc.clone();
        unclassified_stale_model
            .quota
            .as_mut()
            .unwrap()
            .models
            .push(ModelQuota {
                name: "gemini-4-carbon-high".into(),
                percentage: 80,
                percentage_known: Some(true),
                observed_remaining_fraction: Some(0.80),
                primary_quota: None,
                quota_bucket_id: None,
                reset_time: "2020-01-01T00:00:00Z".into(),
                display_name: None,
                supports_images: None,
                supports_thinking: None,
                thinking_budget: None,
                recommended: None,
                max_tokens: None,
                max_output_tokens: None,
                supported_mime_types: None,
            });
        assert!(matches!(
            evaluate_single_model(
                unclassified_stale_model.quota.as_ref().unwrap(),
                "gemini-4-carbon-high",
                now
            ),
            QuotaEval::Stale { .. }
        ));
        assert_eq!(
            evaluate_account_window_quotas(
                &unclassified_stale_model,
                "all",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot {
                short_5h_pct: Some(2),
                weekly_pct: Some(40),
            }
        );

        let mut unclassified_stale_primary = unclassified_stale_model.clone();
        let last_unclassified = unclassified_stale_primary
            .quota
            .as_mut()
            .unwrap()
            .models
            .last_mut()
            .unwrap();
        last_unclassified.reset_time = "2099-01-07T00:00:00Z".into();
        last_unclassified.primary_quota = Some(PrimaryModelQuota {
            remaining_fraction: Some(0.80),
            reset_time: "2020-01-01T00:00:00Z".into(),
        });
        assert!(matches!(
            evaluate_single_model(
                unclassified_stale_primary.quota.as_ref().unwrap(),
                "gemini-4-carbon-high",
                now
            ),
            QuotaEval::Stale { .. }
        ));
        assert_eq!(
            evaluate_account_window_quotas(
                &unclassified_stale_primary,
                "all",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot {
                short_5h_pct: Some(2),
                weekly_pct: Some(40),
            }
        );

        // Control: classified model with expired primary_quota still fails closed under `all`
        let mut classified_stale_primary = acc.clone();
        classified_stale_primary.quota.as_mut().unwrap().models[0].primary_quota =
            Some(PrimaryModelQuota {
                remaining_fraction: Some(0.72),
                reset_time: "2020-01-01T00:00:00Z".into(),
            });
        assert_eq!(
            evaluate_account_window_quotas(
                &classified_stale_primary,
                "all",
                now,
                DEFAULT_QUOTA_MAX_AGE_SECS
            ),
            WindowQuotaSnapshot::default()
        );
    }

    #[test]
    fn pool_identity_matches_shared_fixture() {
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../tests/fixtures/quota-pool-cases.json"))
                .unwrap();
        for case in cases {
            let actual = quota_pool(case["id"].as_str().unwrap(), case["name"].as_str().unwrap());
            let actual = actual.map(|pool| match pool {
                QuotaPool::Gemini => "gemini",
                QuotaPool::ThirdParty => "other",
                QuotaPool::Argon => "argon",
            });
            assert_eq!(actual, case["pool"].as_str(), "{case}");
        }
        assert_eq!(quota_group_label("Gemini 4 Argon"), "Gemini 4 Argon");
        assert_eq!(
            model_quota_pool("gemini-4-argon-high", None),
            Some(QuotaPool::Argon)
        );
        assert_eq!(model_quota_pool("gemini-4-carbon-high", None), None);
        assert_eq!(
            model_quota_pool("gemini-4-hydrogen-xhigh", None),
            Some(QuotaPool::Gemini)
        );
        assert_eq!(model_quota_pool("gemini-pro-orchestrator", None), None);
        assert_eq!(
            model_quota_pool("gemini-pro-orchestrator-argon", None),
            Some(QuotaPool::Argon)
        );
        assert_eq!(
            model_quota_pool("gemini-pro-orchestrator-g1-pro", None),
            Some(QuotaPool::Argon)
        );
        assert_eq!(
            model_quota_pool("gemini-test", Some("Gemini 4 Argon High")),
            Some(QuotaPool::Argon)
        );
    }
}
