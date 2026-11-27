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
    OfficialCli,
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

/// Returns `true` for a full unused quota bucket (`remaining_fraction >= 1.0`) whose reset timer
/// has not started yet (official `agy -p "/usage"` reports `"1970-01-01T00:00:00Z"`, normalized to `""`).
pub fn is_unused_full_bucket_reset_time(
    reset_time: &str,
    remaining_fraction: f64,
    remaining_fraction_known: Option<bool>,
) -> bool {
    if remaining_fraction_known == Some(false)
        || !remaining_fraction.is_finite()
        || remaining_fraction < 1.0
    {
        return false;
    }
    let trimmed = reset_time.trim();
    if trimmed.is_empty() {
        return true;
    }
    crate::domain::clock::parse_rfc3339_unix_seconds(trimmed).is_some_and(|ts| ts <= 0)
}

/// Normalize `"1970-01-01T00:00:00Z"` (Unix `<= 0`) on full unused buckets (`remaining_fraction >= 1.0`)
/// to `""` so downstream evaluators and renderers never treat untouched pools as expired.
pub fn normalize_bucket_reset_time(raw: &str, remaining_fraction: Option<f64>) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if fraction_is_known(remaining_fraction)
        && remaining_fraction.is_some_and(|f| f >= 1.0)
        && crate::domain::clock::parse_rfc3339_unix_seconds(trimmed).is_some_and(|ts| ts <= 0)
    {
        return String::new();
    }
    trimmed.to_string()
}

fn canonical_bucket_window(raw_window: &str, bucket_id_lower: &str) -> String {
    let trimmed = raw_window.trim().to_ascii_lowercase();
    if trimmed == "weekly" || bucket_id_lower.ends_with("weekly") {
        "weekly".to_string()
    } else if trimmed == "5h" || bucket_id_lower.ends_with("5h") {
        "5h".to_string()
    } else {
        trimmed
    }
}

/// Returns `true` when `QuotaObservation` is a metadata-only placeholder (e.g. `user_tier` captured
/// during offline `--from-local` import before any `/usage` quota observation has been recorded).
pub fn is_tier_only_placeholder(q: &QuotaObservation) -> bool {
    q.last_updated <= 0 && q.models.is_empty() && q.quota_groups.is_none() && !q.is_forbidden
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
    if is_tier_only_placeholder(q) {
        return QuotaEval::Unknown {
            reason: "no_quota".into(),
        };
    }
    if q.last_updated > now_unix + 30 {
        return QuotaEval::Stale {
            reason: "future_timestamp".into(),
        };
    }
    if now_unix.saturating_sub(q.last_updated) > max_age_secs {
        return QuotaEval::Stale {
            reason: "stale_quota".into(),
        };
    }

    if use_pure_group_evaluation(q) {
        return evaluate_pure_groups_scope(q, monitored_model, now_unix);
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

fn use_pure_group_evaluation(q: &QuotaObservation) -> bool {
    q.source_env == QuotaSourceEnv::OfficialCli && q.models.is_empty()
}

fn present_pools_in_groups(groups: &[QuotaGroup]) -> Vec<QuotaPool> {
    let mut pools = Vec::new();
    for candidate in [QuotaPool::Gemini, QuotaPool::ThirdParty, QuotaPool::Argon] {
        let has_any = groups.iter().any(|group| {
            group
                .buckets
                .iter()
                .any(|bucket| quota_pool(&bucket.bucket_id, &group.display_name) == Some(candidate))
        });
        if has_any {
            pools.push(candidate);
        }
    }
    pools
}

enum PoolGroupEval {
    Known {
        effective_pct: f64,
        short_5h: Option<f64>,
        weekly: f64,
    },
    Stale {
        reason: &'static str,
    },
    Unknown {
        reason: &'static str,
    },
}

fn evaluate_pool_from_groups(
    q: &QuotaObservation,
    pool: QuotaPool,
    now_unix: i64,
) -> PoolGroupEval {
    evaluate_pool_from_groups_with_empty_reason(q, pool, now_unix, "unknown_pool")
}

fn evaluate_pool_from_groups_with_empty_reason(
    q: &QuotaObservation,
    pool: QuotaPool,
    now_unix: i64,
    empty_pool_reason: &'static str,
) -> PoolGroupEval {
    let Some(ref groups) = q.quota_groups else {
        return PoolGroupEval::Unknown {
            reason: "missing_quota_groups",
        };
    };

    let mut weekly: Option<f64> = None;
    let mut short_5h: Option<f64> = None;
    let mut argon_observation: Option<(f64, &str)> = None;
    let mut observations: HashMap<String, (f64, &str, &str)> = HashMap::new();
    let mut matched_any_bucket = false;

    for group in groups {
        for bucket in &group.buckets {
            let id = bucket.bucket_id.to_ascii_lowercase();
            if quota_pool(&id, &group.display_name) != Some(pool) {
                continue;
            }
            matched_any_bucket = true;
            if bucket.remaining_fraction_known == Some(false)
                || (pool == QuotaPool::Argon && bucket.remaining_fraction_known != Some(true))
                || !bucket.remaining_fraction.is_finite()
                || !(0.0..=1.0).contains(&bucket.remaining_fraction)
            {
                return PoolGroupEval::Unknown {
                    reason: "invalid_bucket_fraction",
                };
            }

            let unused_full = is_unused_full_bucket_reset_time(
                &bucket.reset_time,
                bucket.remaining_fraction,
                bucket.remaining_fraction_known,
            );
            if !unused_full {
                let Some(parsed_reset_unix) =
                    crate::domain::clock::parse_rfc3339_unix_seconds(&bucket.reset_time)
                else {
                    return PoolGroupEval::Unknown {
                        reason: "invalid_reset_time",
                    };
                };
                if parsed_reset_unix <= now_unix {
                    return PoolGroupEval::Stale {
                        reason: "reset_deadline_passed",
                    };
                }
            }

            let window = canonical_bucket_window(&bucket.window, &id);
            let norm_reset_key = if unused_full {
                ""
            } else {
                bucket.reset_time.as_str()
            };
            let obs = (
                bucket.remaining_fraction,
                norm_reset_key,
                bucket.bucket_id.as_str(),
            );
            if observations
                .insert(window.clone(), obs)
                .is_some_and(|old| old != obs)
            {
                return PoolGroupEval::Unknown {
                    reason: "conflicting_window_buckets",
                };
            }

            let value = bucket.remaining_fraction * 100.0;
            if pool == QuotaPool::Argon {
                if window != "weekly" {
                    return PoolGroupEval::Unknown {
                        reason: "unexpected_argon_window",
                    };
                }
                let a_obs = (bucket.remaining_fraction, norm_reset_key);
                if argon_observation.is_some_and(|old| old != a_obs) {
                    return PoolGroupEval::Unknown {
                        reason: "conflicting_argon_buckets",
                    };
                }
                argon_observation = Some(a_obs);
            }

            if window == "weekly" {
                weekly = Some(weekly.map_or(value, |old| old.min(value)));
            } else if window == "5h" {
                short_5h = Some(short_5h.map_or(value, |old| old.min(value)));
            } else {
                return PoolGroupEval::Unknown {
                    reason: "unknown_bucket_window",
                };
            }
        }
    }

    if !matched_any_bucket {
        return PoolGroupEval::Unknown {
            reason: empty_pool_reason,
        };
    }

    let Some(weekly_pct) = weekly else {
        return PoolGroupEval::Unknown {
            reason: "missing_weekly_bucket",
        };
    };

    if pool == QuotaPool::Argon {
        return PoolGroupEval::Known {
            effective_pct: weekly_pct,
            short_5h: None,
            weekly: weekly_pct,
        };
    }

    let same_env_tier = q.source_env != QuotaSourceEnv::LegacyUnknown
        && (q.tier_source_env == Some(q.source_env)
            || (q.source_env == QuotaSourceEnv::Production
                && q.tier_source_env == Some(QuotaSourceEnv::OfficialCli)));
    let tier_lower = q
        .subscription_tier
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_free = same_env_tier && (tier_lower.contains("free") || tier_lower.contains("starter"));

    match short_5h {
        Some(v) => PoolGroupEval::Known {
            effective_pct: weekly_pct.min(v),
            short_5h: Some(v),
            weekly: weekly_pct,
        },
        None if is_free => PoolGroupEval::Known {
            effective_pct: weekly_pct,
            short_5h: None,
            weekly: weekly_pct,
        },
        None => PoolGroupEval::Unknown {
            reason: "missing_5h_bucket",
        },
    }
}

fn target_pools_for_scope(
    monitored_model: &str,
    groups: &[QuotaGroup],
) -> Result<Vec<QuotaPool>, &'static str> {
    let trimmed = monitored_model.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        let present = present_pools_in_groups(groups);
        if present.is_empty() {
            return Err("unknown_pool");
        }
        return Ok(present);
    }
    if trimmed.eq_ignore_ascii_case("gemini") {
        return Ok(vec![QuotaPool::Gemini]);
    }
    if trimmed.eq_ignore_ascii_case("argon") {
        return Ok(vec![QuotaPool::Argon]);
    }
    if trimmed.eq_ignore_ascii_case("claude")
        || trimmed.eq_ignore_ascii_case("3p")
        || trimmed.eq_ignore_ascii_case("non-gemini")
    {
        return Ok(vec![QuotaPool::ThirdParty]);
    }
    if trimmed.to_ascii_lowercase().ends_with("-disabled") {
        return Err("model_disabled");
    }
    match model_quota_pool(trimmed, None) {
        Some(pool) => Ok(vec![pool]),
        None => Err("unclassified_model_pool"),
    }
}

fn evaluate_pure_groups_scope(
    q: &QuotaObservation,
    monitored_model: &str,
    now_unix: i64,
) -> QuotaEval {
    let Some(ref groups) = q.quota_groups else {
        return QuotaEval::Unknown {
            reason: "unknown_pool".into(),
        };
    };
    let pools = match target_pools_for_scope(monitored_model, groups) {
        Ok(p) => p,
        Err(reason) => {
            return QuotaEval::Unknown {
                reason: reason.into(),
            }
        }
    };
    if pools.len() == 1 {
        return match evaluate_pool_from_groups(q, pools[0], now_unix) {
            PoolGroupEval::Known { effective_pct, .. } => QuotaEval::Known {
                remaining_percentage: effective_pct,
            },
            PoolGroupEval::Stale { reason } => QuotaEval::Stale {
                reason: reason.into(),
            },
            PoolGroupEval::Unknown { reason } => QuotaEval::Unknown {
                reason: reason.into(),
            },
        };
    }

    let mut min_val: Option<f64> = None;
    let mut saw_stale = false;
    let mut first_unknown: Option<&'static str> = None;
    for pool in pools {
        match evaluate_pool_from_groups(q, pool, now_unix) {
            PoolGroupEval::Known { effective_pct, .. } => {
                min_val = Some(min_val.map_or(effective_pct, |old| old.min(effective_pct)));
            }
            PoolGroupEval::Stale { .. } => {
                saw_stale = true;
            }
            PoolGroupEval::Unknown { reason } => {
                // Fail closed: every pool in `pools` is an explicitly classified present pool,
                // so a corrupted/incomplete/conflicting pool must not be masked by another pool.
                if first_unknown.is_none() {
                    first_unknown = Some(reason);
                }
            }
        }
    }
    if saw_stale {
        return QuotaEval::Stale {
            reason: "reset_deadline_passed".into(),
        };
    }
    if let Some(reason) = first_unknown {
        return QuotaEval::Unknown {
            reason: reason.into(),
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

fn evaluate_pure_groups_windows(
    q: &QuotaObservation,
    monitored_model: &str,
    now_unix: i64,
) -> WindowQuotaSnapshot {
    let Some(ref groups) = q.quota_groups else {
        return WindowQuotaSnapshot::default();
    };
    let Ok(pools) = target_pools_for_scope(monitored_model, groups) else {
        return WindowQuotaSnapshot::default();
    };
    let mut min_5h: Option<f64> = None;
    let mut min_weekly: Option<f64> = None;
    for pool in pools {
        match evaluate_pool_from_groups(q, pool, now_unix) {
            PoolGroupEval::Known {
                short_5h, weekly, ..
            } => {
                if let Some(v) = short_5h {
                    min_5h = Some(min_5h.map_or(v, |old| old.min(v)));
                }
                min_weekly = Some(min_weekly.map_or(weekly, |old| old.min(weekly)));
            }
            PoolGroupEval::Stale { .. } | PoolGroupEval::Unknown { .. } => {
                return WindowQuotaSnapshot::default();
            }
        }
    }
    WindowQuotaSnapshot {
        short_5h_pct: min_5h.map(round_pct),
        weekly_pct: min_weekly.map(round_pct),
    }
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
    match evaluate_pool_from_groups_with_empty_reason(q, pool, now_unix, "missing_weekly_bucket") {
        PoolGroupEval::Known {
            effective_pct,
            short_5h,
            weekly,
        } => SingleModelDetail::Known {
            effective_pct: effective_pct.min(model_primary_pct),
            short_5h,
            weekly,
        },
        PoolGroupEval::Stale { reason } => SingleModelDetail::Stale {
            reason,
            classified: true,
        },
        PoolGroupEval::Unknown { reason } => SingleModelDetail::Unknown {
            reason,
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
    if q.is_forbidden
        || is_tier_only_placeholder(q)
        || q.last_updated > now_unix + 30
        || now_unix.saturating_sub(q.last_updated) > max_age_secs
    {
        return WindowQuotaSnapshot::default();
    }

    if use_pure_group_evaluation(q) {
        return evaluate_pure_groups_windows(q, monitored_model, now_unix);
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

/// Inspect cached quota observations (independent of `DEFAULT_QUOTA_MAX_AGE_SECS` wall-clock age)
/// to determine whether any monitored window is already known to be strictly below `min_pct`
/// with a reset deadline still in the future (`reset_time > now_unix`).
/// Returns `(min_blocking_pct, blocking_reset_unix)` when such a blocking window exists.
fn find_blocking_low_window_before_reset(
    q: &QuotaObservation,
    monitored_model: &str,
    min_pct: u8,
    now_unix: i64,
) -> Option<(f64, i64)> {
    if q.is_forbidden || is_tier_only_placeholder(q) || q.last_updated > now_unix + 30 {
        return None;
    }

    let min_threshold = min_pct as f64;
    let mut worst: Option<(f64, i64)> = None;

    if let Some(ref groups) = q.quota_groups {
        if let Ok(pools) = target_pools_for_scope(monitored_model, groups) {
            for pool in pools {
                // Collect per-window observations for this pool and ignore conflicting windows.
                type WindowBucketSample<'a> = (f64, Option<i64>, &'a str);
                let mut per_window: HashMap<String, Option<WindowBucketSample<'_>>> =
                    HashMap::new();
                for group in groups {
                    for bucket in &group.buckets {
                        let id = bucket.bucket_id.to_ascii_lowercase();
                        if quota_pool(&id, &group.display_name) != Some(pool) {
                            continue;
                        }
                        if bucket.remaining_fraction_known == Some(false)
                            || (pool == QuotaPool::Argon
                                && bucket.remaining_fraction_known != Some(true))
                            || !fraction_is_known(Some(bucket.remaining_fraction))
                        {
                            continue;
                        }
                        let window = canonical_bucket_window(&bucket.window, &id);
                        let reset_unix = if is_unused_full_bucket_reset_time(
                            &bucket.reset_time,
                            bucket.remaining_fraction,
                            bucket.remaining_fraction_known,
                        ) {
                            None
                        } else {
                            crate::domain::clock::parse_rfc3339_unix_seconds(&bucket.reset_time)
                        };
                        let item = (
                            bucket.remaining_fraction,
                            reset_unix,
                            bucket.bucket_id.as_str(),
                        );
                        match per_window.get_mut(&window) {
                            None => {
                                per_window.insert(window, Some(item));
                            }
                            Some(Some(prev)) if *prev != item => {
                                *per_window.get_mut(&window).unwrap() = None;
                            }
                            _ => {}
                        }
                    }
                }
                for entry in per_window.into_values().flatten() {
                    let pct = entry.0 * 100.0;
                    if pct < min_threshold {
                        if let Some(reset_ts) = entry.1.filter(|&ts| ts > now_unix) {
                            worst = Some(match worst {
                                None => (pct, reset_ts),
                                Some((old_pct, old_ts)) => (old_pct.min(pct), old_ts.max(reset_ts)),
                            });
                        }
                    }
                }
            }
        }
    }

    // Legacy per-model `primary_quota` observations (backward compatibility)
    if !q.models.is_empty() {
        let trimmed = monitored_model.trim();
        for m in &q.models {
            if m.name.to_ascii_lowercase().ends_with("-disabled") {
                continue;
            }
            let matches_scope = if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
                model_quota_pool(&m.name, m.display_name.as_deref()).is_some()
            } else if trimmed.eq_ignore_ascii_case("gemini") {
                model_quota_pool(&m.name, m.display_name.as_deref()) == Some(QuotaPool::Gemini)
            } else if trimmed.eq_ignore_ascii_case("argon") {
                model_quota_pool(&m.name, m.display_name.as_deref()) == Some(QuotaPool::Argon)
            } else if trimmed.eq_ignore_ascii_case("claude")
                || trimmed.eq_ignore_ascii_case("3p")
                || trimmed.eq_ignore_ascii_case("non-gemini")
            {
                let lower = m.name.to_ascii_lowercase();
                lower.starts_with("claude") || lower.starts_with("gpt")
            } else {
                resolve_forwarded_model(q, trimmed) == m.name
            };
            if !matches_scope {
                continue;
            }
            if let Some(ref pq) = m.primary_quota {
                if let Some(frac) = pq
                    .remaining_fraction
                    .filter(|f| fraction_is_known(Some(*f)))
                {
                    let pct = frac * 100.0;
                    if pct < min_threshold {
                        if let Some(reset_ts) =
                            crate::domain::clock::parse_rfc3339_unix_seconds(&pq.reset_time)
                                .filter(|&ts| ts > now_unix)
                        {
                            worst = Some(match worst {
                                None => (pct, reset_ts),
                                Some((old_pct, old_ts)) => (old_pct.min(pct), old_ts.max(reset_ts)),
                            });
                        }
                    }
                }
            }
        }
    }

    worst
}

/// Pure-local cache filter for `daemon` Step-and-Verify:
/// Returns `Some(blocking_reset_unix)` if `account` has cached quota `< min_pct` whose blocking
/// window reset deadline is still in the future (`reset_time > now_unix`), allowing the daemon
/// to skip exhausted dormant candidates locally without switching or invoking `agy -p "/usage"`.
pub fn cached_candidate_known_below_min_before_reset(
    account: &AccountRecord,
    monitored_model: &str,
    min_pct: u8,
    now_unix: i64,
) -> Option<i64> {
    let q = account.quota.as_ref()?;
    find_blocking_low_window_before_reset(q, monitored_model, min_pct, now_unix)
        .map(|(_, reset_ts)| reset_ts)
}

/// Compact summary for the TUI A1 `Last Quota` column.
#[derive(Debug, Clone, PartialEq)]
pub enum LastQuotaStatus {
    NeverRefreshed,
    Forbidden,
    LowBeforeReset {
        percentage: f64,
        reset_unix: i64,
        last_updated: i64,
    },
    ResetPassed {
        last_updated: i64,
    },
    Known {
        percentage: f64,
        last_updated: i64,
    },
    Unknown {
        last_updated: i64,
    },
}

/// Summarize an account's cached quota for display in the TUI A1 `Last Quota` column.
pub fn summarize_last_quota_status(
    account: &AccountRecord,
    monitored_model: &str,
    candidate_min_pct: u8,
    now_unix: i64,
) -> LastQuotaStatus {
    let Some(ref q) = account.quota else {
        return LastQuotaStatus::NeverRefreshed;
    };
    if q.is_forbidden {
        return LastQuotaStatus::Forbidden;
    }
    if is_tier_only_placeholder(q) {
        return LastQuotaStatus::NeverRefreshed;
    }
    if let Some((low_pct, reset_unix)) =
        find_blocking_low_window_before_reset(q, monitored_model, candidate_min_pct, now_unix)
    {
        return LastQuotaStatus::LowBeforeReset {
            percentage: low_pct,
            reset_unix,
            last_updated: q.last_updated,
        };
    }
    match evaluate_quota_observation(q, monitored_model, now_unix, i64::MAX) {
        QuotaEval::Known {
            remaining_percentage,
        } => LastQuotaStatus::Known {
            percentage: remaining_percentage,
            last_updated: q.last_updated,
        },
        QuotaEval::Stale { reason } if reason == "reset_deadline_passed" => {
            LastQuotaStatus::ResetPassed {
                last_updated: q.last_updated,
            }
        }
        QuotaEval::Stale { .. } | QuotaEval::Unknown { .. } | QuotaEval::Unavailable { .. } => {
            LastQuotaStatus::Unknown {
                last_updated: q.last_updated,
            }
        }
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

    #[test]
    fn official_cli_pure_groups_unused_epoch0_and_local_cache_skip() {
        let now = 1_800_000_000i64;
        assert_eq!(
            serde_json::to_string(&QuotaSourceEnv::OfficialCli).unwrap(),
            "\"official_cli\""
        );
        assert_eq!(
            normalize_bucket_reset_time("1970-01-01T00:00:00Z", Some(1.0)),
            ""
        );
        assert_eq!(
            normalize_bucket_reset_time("1970-01-01T00:00:00Z", Some(0.5)),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            normalize_bucket_reset_time("2099-01-01T00:00:00Z", Some(1.0)),
            "2099-01-01T00:00:00Z"
        );

        let mut acc = sample_window_account(now);
        let mut obs = QuotaObservation::new(now - 60, QuotaSourceEnv::OfficialCli);
        obs.subscription_tier = Some("PRO".into());
        obs.tier_source_env = Some(QuotaSourceEnv::OfficialCli);
        obs.summary_source_env = Some(QuotaSourceEnv::OfficialCli);
        obs.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: Some("Models within this group: Gemini 2.5 Pro".into()),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "gemini-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.97,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "gemini-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.95,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T05:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Claude and GPT models".into(),
                description: Some("Models within this group: Claude Sonnet 4".into()),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "3p-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        // Raw Unix Epoch 0 on untouched 100% bucket MUST NOT be treated as Stale!
                        reset_time: "1970-01-01T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "3p-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: String::new(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
        ]);
        acc.quota = Some(obs);

        assert_eq!(
            evaluate_account_quota(&acc, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 95.0
            }
        );
        assert_eq!(
            evaluate_account_quota(&acc, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 95.0
            }
        );
        assert_eq!(
            evaluate_account_quota(&acc, "claude", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 100.0
            }
        );
        assert_eq!(
            evaluate_account_quota(&acc, "3p", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 100.0
            }
        );
        assert_eq!(
            evaluate_account_quota(&acc, "claude-opus-4-6", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 100.0
            }
        );
        assert!(matches!(
            evaluate_account_quota(&acc, "argon", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Unknown { ref reason } if reason == "unknown_pool"
        ));
        assert_eq!(
            evaluate_account_window_quotas(&acc, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot {
                short_5h_pct: Some(95),
                weekly_pct: Some(97),
            }
        );

        // Epoch 0 on a partially consumed bucket (< 1.0) MUST still fail closed as Stale.
        let mut partial_epoch0 = acc.clone();
        partial_epoch0
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[1]
            .buckets[0]
            .remaining_fraction = 0.5;
        assert!(matches!(
            evaluate_account_quota(&partial_epoch0, "claude", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Stale { ref reason } if reason == "reset_deadline_passed"
        ));

        // Local cache skip: low 8% with future reset (even when last_updated is 2 hours old!) skips locally.
        let mut low_acc = acc.clone();
        let future_reset = now + 7200;
        let future_rfc3339 =
            crate::domain::clock::format_unix_rfc3339_micros_utc(future_reset).unwrap();
        low_acc.quota.as_mut().unwrap().last_updated = now - 7200;
        low_acc
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[0]
            .buckets[1]
            .remaining_fraction = 0.08;
        low_acc
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[0]
            .buckets[1]
            .reset_time = future_rfc3339;
        assert_eq!(
            cached_candidate_known_below_min_before_reset(&low_acc, "all", 30, now),
            Some(future_reset)
        );
        // Unmonitored scope (`claude` is 100%) must NOT skip because of low Gemini.
        assert_eq!(
            cached_candidate_known_below_min_before_reset(&low_acc, "claude", 30, now),
            None
        );
        assert!(matches!(
            summarize_last_quota_status(&low_acc, "all", 30, now),
            LastQuotaStatus::LowBeforeReset { reset_unix, .. } if reset_unix == future_reset
        ));

        // Once reset passes (`now_after >= future_reset`), cache skip stops and TUI reports ResetPassed.
        assert_eq!(
            cached_candidate_known_below_min_before_reset(&low_acc, "all", 30, future_reset + 1),
            None
        );
        assert!(matches!(
            summarize_last_quota_status(&low_acc, "all", 30, future_reset + 1),
            LastQuotaStatus::ResetPassed { .. }
        ));

        // Tier-only placeholder (from offline `--from-local`) evaluates to `Unknown("no_quota")` and `NeverRefreshed`.
        let mut tier_only = acc.clone();
        let mut placeholder = QuotaObservation::new(0, QuotaSourceEnv::OfficialCli);
        placeholder.subscription_tier = Some("PRO".into());
        placeholder.tier_source_env = Some(QuotaSourceEnv::OfficialCli);
        tier_only.quota = Some(placeholder);
        assert_eq!(
            evaluate_account_quota(&tier_only, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Unknown {
                reason: "no_quota".into()
            }
        );
        assert_eq!(
            summarize_last_quota_status(&tier_only, "all", 30, now),
            LastQuotaStatus::NeverRefreshed
        );

        // Fail-closed under `all`: if one present pool in `OfficialCli` has conflicting or missing
        // buckets, `evaluate_account_quota` MUST return `Unknown` rather than masking with another pool!
        let mut corrupt_pool = acc.clone();
        corrupt_pool
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[1]
            .buckets
            .retain(|b| b.window != "5h"); // Pro tier missing 5h bucket on Claude/GPT
        assert!(matches!(
            evaluate_account_quota(&corrupt_pool, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Unknown { ref reason } if reason == "missing_5h_bucket"
        ));
        assert_eq!(
            evaluate_account_window_quotas(&corrupt_pool, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot::default()
        );
        // Healthy isolated scope (`gemini`) remains readable.
        assert_eq!(
            evaluate_account_quota(&corrupt_pool, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 95.0
            }
        );

        // Empty `bucket.window` on `gemini-5h` + `gemini-weekly` MUST canonicalize by `bucket_id`
        // rather than colliding under key `""`!
        let mut empty_win = acc.clone();
        for b in &mut empty_win
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[0]
            .buckets
        {
            b.window.clear();
        }
        assert_eq!(
            evaluate_account_quota(&empty_win, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 95.0
            }
        );
        empty_win
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[0]
            .buckets[1]
            .remaining_fraction = 0.05;
        assert!(
            cached_candidate_known_below_min_before_reset(&empty_win, "gemini", 30, now).is_some()
        );

        // Extreme negative `last_updated` must not panic on subtraction overflow.
        let mut extreme_ts = acc.clone();
        extreme_ts.quota.as_mut().unwrap().last_updated = i64::MIN;
        assert_eq!(
            evaluate_account_window_quotas(&extreme_ts, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            WindowQuotaSnapshot::default()
        );
    }
}
