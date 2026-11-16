use crate::domain::quota::{
    fraction_is_known, model_quota_pool, quota_pool, ModelQuota, QuotaGroup,
};

/// Fuse grouped `retrieveUserQuotaSummary` windows (`5h` + `weekly`) into model catalog items.
/// - Retains `primary_quota` separately so tighter model-endpoint limits are never lost;
/// - NEVER promotes an unknown per-model `primary_quota` (`remaining_fraction: None`) into `percentage_known = Some(true)`;
/// - Never borrows shared Gemini buckets for Argon, nor Argon buckets for shared Gemini;
/// - Detects conflicting duplicate window buckets and marks `percentage_known = Some(false)`.
pub fn fuse_model_quotas(models: &mut [ModelQuota], groups: &[QuotaGroup]) {
    for model in models {
        let Some(pool) = model_quota_pool(&model.name, model.display_name.as_deref()) else {
            continue;
        };

        // Per-model raw primary knownness MUST NOT be overridden by shared summary pools!
        let primary_is_known = match model.primary_quota {
            Some(ref pq) => fraction_is_known(pq.remaining_fraction),
            None => model.percentage_known != Some(false),
        };
        if !primary_is_known {
            model.percentage_known = Some(false);
            model.observed_remaining_fraction = None;
            model.quota_bucket_id = None;
            continue;
        }

        let buckets: Vec<_> = groups
            .iter()
            .flat_map(|group| {
                group.buckets.iter().filter(move |bucket| {
                    quota_pool(&bucket.bucket_id, &group.display_name) == Some(pool)
                })
            })
            .collect();

        let resolve_window = |window: &str| {
            let matching: Vec<_> = buckets
                .iter()
                .copied()
                .filter(|b| b.window.eq_ignore_ascii_case(window))
                .collect();
            let first = *matching.first()?;
            let conflict = matching.iter().any(|b| {
                b.bucket_id != first.bucket_id
                    || b.remaining_fraction != first.remaining_fraction
                    || b.remaining_fraction_known != first.remaining_fraction_known
                    || b.reset_time != first.reset_time
            });
            let known = !conflict
                && first.remaining_fraction_known != Some(false)
                && fraction_is_known(Some(first.remaining_fraction));
            Some((first, conflict, known))
        };

        let selected = match (resolve_window("5h"), resolve_window("weekly")) {
            (Some(s), Some(w)) => {
                if !s.2 {
                    Some(s)
                } else if !w.2 || w.0.remaining_fraction < s.0.remaining_fraction {
                    Some(w)
                } else {
                    Some(s)
                }
            }
            (Some(s), None) => Some(s),
            (None, Some(w)) => Some(w),
            (None, None) => None,
        };

        let Some((bucket, conflict, known)) = selected else {
            continue;
        };

        // Shared summary must never raise a lower valid primary model observation.
        if known
            && model.percentage_known != Some(false)
            && model.observed_remaining_fraction.is_some_and(|fraction| {
                fraction_is_known(Some(fraction)) && fraction < bucket.remaining_fraction
            })
        {
            model.quota_bucket_id = None;
            continue;
        }

        model.percentage_known = Some(known);
        model.observed_remaining_fraction = known.then_some(bucket.remaining_fraction);
        model.quota_bucket_id =
            (!conflict && !bucket.bucket_id.is_empty()).then(|| bucket.bucket_id.clone());
        if known {
            model.percentage = (bucket.remaining_fraction * 100.0).round() as i32;
        }
        if !bucket.reset_time.is_empty() {
            model.reset_time = bucket.reset_time.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::quota::PrimaryModelQuota;
    use serde_json::json;

    #[test]
    fn argon_fusion_is_isolated_missing_primary_stays_unknown_and_conflicts_mark_unknown() {
        let fixture = |id: &str, fraction: f64| {
            json!({
                "bucket_id": id,
                "window": if id.ends_with("5h") { "5h" } else { "weekly" },
                "remaining_fraction": fraction,
                "remaining_fraction_known": true,
                "reset_time": "2030-01-01T00:00:00Z"
            })
        };
        let mut groups: Vec<QuotaGroup> = serde_json::from_value(json!([
            {"display_name":"Gemini 4 Argon","buckets":[fixture("gemini-argon-wtu-weekly", 0.1)]},
            {"display_name":"Gemini Models","buckets":[fixture("gemini-weekly", 0.9), fixture("gemini-5h", 0.8)]}
        ]))
        .unwrap();
        let mut models: Vec<ModelQuota> = serde_json::from_value(json!([
            {"name":"gemini-4-argon-high","percentage":100,"reset_time":""},
            {"name":"gemini-3.8-flash","percentage":100,"reset_time":""},
            {
                "name":"gemini-missing-primary",
                "percentage":0,
                "percentage_known":false,
                "primary_quota":{"remaining_fraction":null,"reset_time":"2030-01-01T00:00:00Z"},
                "reset_time":"2030-01-01T00:00:00Z"
            }
        ]))
        .unwrap();
        assert_eq!(
            models[2].primary_quota,
            Some(PrimaryModelQuota {
                remaining_fraction: None,
                reset_time: "2030-01-01T00:00:00Z".into(),
            })
        );
        fuse_model_quotas(&mut models, &groups);
        assert_eq!(models[0].percentage, 10);
        assert_eq!(
            models[0].quota_bucket_id.as_deref(),
            Some("gemini-argon-wtu-weekly")
        );
        assert_eq!(models[1].percentage, 80);
        // Missing primary fraction MUST NOT be promoted to Known by shared summary!
        assert_eq!(models[2].percentage_known, Some(false));
        assert_eq!(models[2].observed_remaining_fraction, None);
        assert_eq!(models[2].percentage, 0);

        // Inject conflicting weekly bucket on Gemini
        groups[1]
            .buckets
            .push(serde_json::from_value(fixture("gemini-weekly", 0.2)).unwrap());
        fuse_model_quotas(&mut models, &groups);
        assert_eq!(models[1].percentage_known, Some(false));
        assert_eq!(models[1].observed_remaining_fraction, None);
    }
}
