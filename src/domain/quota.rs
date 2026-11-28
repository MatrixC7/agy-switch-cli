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

/// Returns `true` when `QuotaObservation` is a legacy metadata-only placeholder (e.g. written by
/// `v1.2.7` offline `--from-local` before any `/usage` quota observation was recorded).
pub fn is_empty_quota_placeholder(q: &QuotaObservation) -> bool {
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
    if is_empty_quota_placeholder(q) {
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
    Known { effective_pct: f64 },
    Stale { reason: &'static str },
    Unknown { reason: &'static str },
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
        };
    }

    let effective_pct = match short_5h {
        Some(v) => weekly_pct.min(v),
        None => weekly_pct,
    };
    PoolGroupEval::Known { effective_pct }
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
    Known { effective_pct: f64 },
    Stale { reason: &'static str },
    Disabled,
    Unclassified,
    Unknown { reason: &'static str },
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
        return SingleModelDetail::Unknown {
            reason: "model_not_found",
        };
    };

    let pool = model_quota_pool(resolved, m.display_name.as_deref());

    if m.percentage_known == Some(false) || !(0..=100).contains(&m.percentage) {
        return SingleModelDetail::Unknown {
            reason: "model_percentage_unknown",
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
                        };
                    };
                    if parsed_pq_reset_unix <= now_unix {
                        return SingleModelDetail::Stale {
                            reason: "reset_deadline_passed",
                        };
                    }
                }
                (frac * 100.0).min(m.percentage as f64)
            }
            Some(_) => {
                return SingleModelDetail::Unknown {
                    reason: "invalid_primary_fraction",
                }
            }
            None => {
                return SingleModelDetail::Unknown {
                    reason: "missing_primary_fraction",
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
                };
            };
            if parsed_m_reset_unix <= now_unix {
                return SingleModelDetail::Stale {
                    reason: "reset_deadline_passed",
                };
            }
        }
        m.percentage as f64
    };

    let Some(pool) = pool else {
        return SingleModelDetail::Unclassified;
    };
    match evaluate_pool_from_groups_with_empty_reason(q, pool, now_unix, "missing_weekly_bucket") {
        PoolGroupEval::Known { effective_pct } => SingleModelDetail::Known {
            effective_pct: effective_pct.min(model_primary_pct),
        },
        PoolGroupEval::Stale { reason } => SingleModelDetail::Stale { reason },
        PoolGroupEval::Unknown { reason } => SingleModelDetail::Unknown { reason },
    }
}

pub fn evaluate_single_model(q: &QuotaObservation, model: &str, now_unix: i64) -> QuotaEval {
    match evaluate_single_model_detail(q, model, now_unix) {
        SingleModelDetail::Known { effective_pct } => QuotaEval::Known {
            remaining_percentage: effective_pct,
        },
        SingleModelDetail::Stale { reason } => QuotaEval::Stale {
            reason: reason.into(),
        },
        SingleModelDetail::Disabled => QuotaEval::Unknown {
            reason: "model_disabled".into(),
        },
        SingleModelDetail::Unclassified => QuotaEval::Unknown {
            reason: "unclassified_model_pool".into(),
        },
        SingleModelDetail::Unknown { reason } => QuotaEval::Unknown {
            reason: reason.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::token::TokenRecord;

    fn sample_account(now: i64) -> AccountRecord {
        AccountRecord::new(
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
        )
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
    fn official_cli_pure_groups_unused_epoch0_and_weekly_only_buckets() {
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

        let mut acc = sample_account(now);
        let mut obs = QuotaObservation::new(now - 60, QuotaSourceEnv::OfficialCli);
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

        // Weekly-only pool from official `/usage` (e.g. Free/Starter without a `5h` bucket)
        // evaluates directly from the returned weekly bucket without tier inference.
        let mut weekly_only = acc.clone();
        weekly_only
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()[1]
            .buckets
            .retain(|b| b.window != "5h");
        assert_eq!(
            evaluate_account_quota(&weekly_only, "claude", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 100.0
            }
        );
        assert_eq!(
            evaluate_account_quota(&weekly_only, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Known {
                remaining_percentage: 95.0
            }
        );

        // Conflicting buckets in one present pool still fail closed under `all`.
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
                remaining_fraction: 0.40,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-01T05:00:00Z".into(),
                display_name: None,
                description: None,
            });
        assert!(matches!(
            evaluate_account_quota(&conflicting, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Unknown { ref reason } if reason == "conflicting_window_buckets"
        ));

        // Legacy empty placeholder (from v1.2.7 offline `--from-local`) evaluates to `Unknown("no_quota")`.
        let mut placeholder_acc = acc.clone();
        placeholder_acc.quota = Some(QuotaObservation::new(0, QuotaSourceEnv::OfficialCli));
        assert!(is_empty_quota_placeholder(
            placeholder_acc.quota.as_ref().unwrap()
        ));
        assert_eq!(
            evaluate_account_quota(&placeholder_acc, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Unknown {
                reason: "no_quota".into()
            }
        );

        // Empty `bucket.window` on `gemini-5h` + `gemini-weekly` canonicalizes by `bucket_id`.
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
    }
}
