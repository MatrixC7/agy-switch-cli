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

pub fn evaluate_single_model(q: &QuotaObservation, model: &str, now_unix: i64) -> QuotaEval {
    let mut resolved = model;
    for _ in 0..8 {
        if let Some(next) = q.model_forwarding_rules.get(resolved) {
            resolved = next.as_str();
        } else {
            break;
        }
    }

    if resolved.to_ascii_lowercase().ends_with("-disabled") {
        return QuotaEval::Unknown {
            reason: "model_disabled".into(),
        };
    }

    let Some(m) = q.models.iter().find(|m| m.name == resolved) else {
        return QuotaEval::Unknown {
            reason: "model_not_found".into(),
        };
    };

    if m.percentage_known == Some(false) || !(0..=100).contains(&m.percentage) {
        return QuotaEval::Unknown {
            reason: "model_percentage_unknown".into(),
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
                        return QuotaEval::Unknown {
                            reason: "invalid_primary_reset_time".into(),
                        };
                    };
                    if parsed_pq_reset_unix <= now_unix {
                        return QuotaEval::Stale {
                            reason: "reset_deadline_passed".into(),
                        };
                    }
                }
                (frac * 100.0).min(m.percentage as f64)
            }
            Some(_) => {
                return QuotaEval::Unknown {
                    reason: "invalid_primary_fraction".into(),
                }
            }
            None => {
                return QuotaEval::Unknown {
                    reason: "missing_primary_fraction".into(),
                }
            }
        }
    } else {
        if !m.reset_time.trim().is_empty() {
            let Some(parsed_m_reset_unix) =
                crate::domain::clock::parse_rfc3339_unix_seconds(&m.reset_time)
            else {
                return QuotaEval::Unknown {
                    reason: "invalid_reset_time".into(),
                };
            };
            if parsed_m_reset_unix <= now_unix {
                return QuotaEval::Stale {
                    reason: "reset_deadline_passed".into(),
                };
            }
        }
        m.percentage as f64
    };

    let Some(pool) = model_quota_pool(resolved, m.display_name.as_deref()) else {
        return QuotaEval::Unknown {
            reason: "unclassified_model_pool".into(),
        };
    };
    let Some(ref groups) = q.quota_groups else {
        return QuotaEval::Unknown {
            reason: "missing_quota_groups".into(),
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
                return QuotaEval::Unknown {
                    reason: "invalid_bucket_fraction".into(),
                };
            }

            let Some(parsed_reset_unix) =
                crate::domain::clock::parse_rfc3339_unix_seconds(&bucket.reset_time)
            else {
                return QuotaEval::Unknown {
                    reason: "invalid_reset_time".into(),
                };
            };
            if parsed_reset_unix <= now_unix {
                return QuotaEval::Stale {
                    reason: "reset_deadline_passed".into(),
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
                return QuotaEval::Unknown {
                    reason: "conflicting_window_buckets".into(),
                };
            }

            let value = bucket.remaining_fraction * 100.0;
            if pool == QuotaPool::Argon {
                if window != "weekly" {
                    return QuotaEval::Unknown {
                        reason: "unexpected_argon_window".into(),
                    };
                }
                let a_obs = (bucket.remaining_fraction, bucket.reset_time.as_str());
                if argon_observation.is_some_and(|old| old != a_obs) {
                    return QuotaEval::Unknown {
                        reason: "conflicting_argon_buckets".into(),
                    };
                }
                argon_observation = Some(a_obs);
            }

            if id.ends_with("weekly") || window == "weekly" {
                weekly = Some(weekly.map_or(value, |old| old.min(value)));
            } else if id.ends_with("5h") || window == "5h" {
                short_5h = Some(short_5h.map_or(value, |old| old.min(value)));
            } else {
                return QuotaEval::Unknown {
                    reason: "unknown_bucket_window".into(),
                };
            }
        }
    }

    let Some(weekly_pct) = weekly else {
        return QuotaEval::Unknown {
            reason: "missing_weekly_bucket".into(),
        };
    };

    if pool == QuotaPool::Argon {
        return QuotaEval::Known {
            remaining_percentage: weekly_pct.min(model_primary_pct),
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

    let short_pct = match short_5h {
        Some(v) => v,
        None if is_free => 100.0,
        None => {
            return QuotaEval::Unknown {
                reason: "missing_5h_bucket".into(),
            }
        }
    };

    QuotaEval::Known {
        remaining_percentage: weekly_pct.min(short_pct).min(model_primary_pct),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
