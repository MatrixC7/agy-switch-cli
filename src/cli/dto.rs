use crate::domain::account::{
    AccountRecord, DisableReasonCode, RuntimeState, SessionIdentity, STORE_SCHEMA_VERSION,
};
use crate::domain::policy::SwitchPolicy;
use crate::domain::quota::{
    observed_quota_percentage, quota_pool, ModelQuota, QuotaBucket, QuotaEval, QuotaGroup,
    QuotaObservation, QuotaPool, QuotaSourceEnv,
};
use serde::Serialize;

/// Strip terminal control characters (including ANSI ESC `\x1b`) from dynamic human-readable strings.
pub fn terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

pub fn format_pct(value: Option<i32>) -> String {
    value
        .map(|v| format!("{v}%"))
        .unwrap_or_else(|| "—".to_string())
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonSuccessEnvelope<T: Serialize> {
    pub schema_version: u32,
    pub ok: bool,
    #[serde(flatten)]
    pub payload: T,
}

impl<T: Serialize> JsonSuccessEnvelope<T> {
    pub fn new(payload: T) -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            ok: true,
            payload,
        }
    }
}

/// Strictly allow-listed account DTO: physically excludes `access_token`, `refresh_token`,
/// `id_token`, `client_secret`, `validation_url`, `disabled_detail`, and `forbidden_reason`.
#[derive(Debug, Clone, Serialize)]
pub struct AccountViewDto {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    pub is_selected: bool,
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_code: Option<DisableReasonCode>,
    pub validation_blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_client_key: Option<String>,
    pub scopes_known: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_scopes: Option<Vec<String>>,
    pub last_used: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<QuotaViewDto>,
}

impl AccountViewDto {
    pub fn from_record(rec: &AccountRecord, is_selected: bool) -> Self {
        Self::from_record_at(rec, is_selected, chrono::Utc::now().timestamp())
    }

    pub fn from_record_at(rec: &AccountRecord, is_selected: bool, now_unix: i64) -> Self {
        Self {
            id: rec.id.clone(),
            email: rec.email.clone(),
            name: rec.name.clone(),
            custom_label: rec.custom_label.clone(),
            is_selected,
            disabled: rec.disabled,
            disabled_code: rec.disabled_code,
            validation_blocked: rec.is_validation_blocked_at(now_unix),
            oauth_client_key: rec.token.oauth_client_key.clone(),
            scopes_known: rec.token.granted_scopes.is_some(),
            granted_scopes: rec.token.granted_scopes.clone(),
            last_used: rec.last_used,
            quota: rec.quota.as_ref().map(QuotaViewDto::from_observation),
        }
    }

    pub fn human_line(&self) -> String {
        let mark = if self.is_selected { "*" } else { " " };
        let label_part = self
            .custom_label
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|l| format!(" ({})", terminal_text(l)))
            .unwrap_or_default();
        let status_part = if self.disabled {
            match self.disabled_code {
                Some(DisableReasonCode::RevokedOrExpiredGrant) => " [disabled: reauth required]",
                Some(DisableReasonCode::ScopeReauthRequired) => " [disabled: scope update needed]",
                _ => " [disabled]",
            }
        } else if self.validation_blocked {
            " [verification required]"
        } else {
            ""
        };
        format!(
            "{mark} {}  {}{}{}",
            terminal_text(&self.id),
            terminal_text(&self.email),
            label_part,
            status_part
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QuotaViewDto {
    pub last_updated: i64,
    pub source_env: QuotaSourceEnv,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_source_env: Option<QuotaSourceEnv>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_tier: Option<String>,
    pub is_forbidden: bool,
    pub models: Vec<ModelViewDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_groups: Option<Vec<GroupViewDto>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelViewDto {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub percentage: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage_known: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_bucket_id: Option<String>,
    pub reset_time: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupViewDto {
    pub display_name: String,
    pub buckets: Vec<BucketViewDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BucketViewDto {
    pub bucket_id: String,
    pub window: String,
    pub remaining_fraction: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_fraction_known: Option<bool>,
    pub reset_time: String,
}

pub fn format_quota_eval_human(eval: &QuotaEval, monitored_model: &str) -> String {
    let safe_model = terminal_text(monitored_model);
    match eval {
        QuotaEval::Known {
            remaining_percentage,
        } => format!("known ({remaining_percentage:.1}% effective on {safe_model})"),
        QuotaEval::Unknown { reason } => {
            format!("unknown ({}, model={safe_model})", terminal_text(reason))
        }
        QuotaEval::Stale { reason } => {
            format!("stale ({}, model={safe_model})", terminal_text(reason))
        }
        QuotaEval::Unavailable { reason } => {
            format!(
                "unavailable ({}, model={safe_model})",
                terminal_text(reason)
            )
        }
    }
}

impl QuotaViewDto {
    pub fn from_observation(obs: &QuotaObservation) -> Self {
        Self {
            last_updated: obs.last_updated,
            source_env: obs.source_env,
            summary_source_env: obs.summary_source_env,
            subscription_tier: obs.subscription_tier.clone(),
            is_forbidden: obs.is_forbidden,
            models: obs.models.iter().map(ModelViewDto::from_model).collect(),
            quota_groups: obs
                .quota_groups
                .as_ref()
                .map(|gs| gs.iter().map(GroupViewDto::from_group).collect()),
        }
    }

    pub fn human_multiline(&self, email: &str) -> String {
        self.human_multiline_at(email, None, chrono::Utc::now().timestamp())
    }

    pub fn human_multiline_with_eval(
        &self,
        email: &str,
        eval: &QuotaEval,
        monitored_model: &str,
    ) -> String {
        self.human_multiline_at(
            email,
            Some((eval, monitored_model)),
            chrono::Utc::now().timestamp(),
        )
    }

    pub fn human_multiline_at(
        &self,
        email: &str,
        eval_ctx: Option<(&QuotaEval, &str)>,
        now_unix: i64,
    ) -> String {
        let plan_str = self
            .subscription_tier
            .as_deref()
            .map(terminal_text)
            .unwrap_or_else(|| "Unknown".into());
        let age_str = format_relative_age(self.last_updated, now_unix);

        let mut lines = vec![format!(
            "Account : {}  [{}]",
            terminal_text(email),
            plan_str
        )];
        if let Some((eval, monitored_model)) = eval_ctx {
            let refresh_hint = if matches!(eval, QuotaEval::Stale { .. }) {
                " — add -r to refresh"
            } else {
                ""
            };
            lines.push(format!(
                "Status  : {} · updated {} (source: {:?}){}",
                format_quota_eval_human(eval, monitored_model),
                age_str,
                self.source_env,
                refresh_hint
            ));
        } else {
            lines.push(format!(
                "Updated : {} (source: {:?})",
                age_str, self.source_env
            ));
        }
        if self.is_forbidden {
            lines.push("Notice  : Quota access is forbidden (HTTP 403).".into());
        }

        struct PoolRow {
            pool_col: String,
            win_col: String,
            bar_col: String,
            reset_col: String,
        }

        let mut rows: Vec<PoolRow> = Vec::new();
        for group in self.quota_groups.iter().flatten() {
            let mut sorted_buckets: Vec<&BucketViewDto> = group.buckets.iter().collect();
            sorted_buckets.sort_by_key(|b| window_sort_rank(&b.window, &b.bucket_id));
            let mut prev_pool = String::new();
            for b in sorted_buckets {
                let pool_name = format_pool_display_name(&b.bucket_id, &group.display_name);
                let pool_col = if pool_name == prev_pool {
                    String::new()
                } else {
                    prev_pool = pool_name.clone();
                    pool_name
                };
                let win_col = format_window_label(&b.window, &b.bucket_id);
                let pct =
                    observed_quota_percentage(b.remaining_fraction, b.remaining_fraction_known);
                let bar_col = format_bar_and_pct(pct);
                let reset_col = format_reset_local(&b.reset_time, now_unix);
                rows.push(PoolRow {
                    pool_col,
                    win_col,
                    bar_col,
                    reset_col,
                });
            }
        }

        if !rows.is_empty() {
            let pool_w = rows
                .iter()
                .map(|r| r.pool_col.chars().count())
                .max()
                .unwrap_or(4)
                .max("Pool".len());
            let win_w = rows
                .iter()
                .map(|r| r.win_col.chars().count())
                .max()
                .unwrap_or(6)
                .max("Window".len());
            let bar_w = 18usize;
            let reset_w = rows
                .iter()
                .map(|r| r.reset_col.chars().count())
                .max()
                .unwrap_or(16)
                .max("Resets (Local)".len());
            let divider_len = pool_w + 3 + win_w + 3 + bar_w + 3 + reset_w;

            lines.push(String::new());
            lines.push(format!(
                "  {}   {}   {}   Resets (Local)",
                pad_right_chars("Pool", pool_w),
                pad_right_chars("Window", win_w),
                pad_right_chars("Remaining", bar_w),
            ));
            lines.push(format!("  {}", "─".repeat(divider_len)));
            for r in &rows {
                lines.push(format!(
                    "  {}   {}   {}   {}",
                    pad_right_chars(&r.pool_col, pool_w),
                    pad_right_chars(&r.win_col, win_w),
                    r.bar_col,
                    r.reset_col
                ));
            }
        } else if !self.is_forbidden {
            lines.push(
                "  No pool quota observations recorded (run `agy-switch-cli quota -r` to refresh)."
                    .into(),
            );
        }

        lines.join("\n")
    }
}

fn pad_right_chars(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

fn window_sort_rank(window: &str, bucket_id: &str) -> u8 {
    let w = window.trim().to_ascii_lowercase();
    let id = bucket_id.trim().to_ascii_lowercase();
    if w == "weekly" || id.ends_with("-weekly") {
        0
    } else if w == "5h" || id.ends_with("-5h") {
        1
    } else {
        2
    }
}

fn format_pool_display_name(bucket_id: &str, group_name: &str) -> String {
    match quota_pool(bucket_id, group_name) {
        Some(QuotaPool::Gemini) => "Gemini".into(),
        Some(QuotaPool::ThirdParty) => "Claude / GPT".into(),
        Some(QuotaPool::Argon) => "Gemini 4 Argon".into(),
        None => {
            let g = terminal_text(group_name.trim());
            if !g.is_empty() {
                g
            } else {
                terminal_text(bucket_id.trim())
            }
        }
    }
}

fn format_window_label(window: &str, bucket_id: &str) -> String {
    let w = window.trim();
    let lower_w = w.to_ascii_lowercase();
    let lower_id = bucket_id.trim().to_ascii_lowercase();
    if lower_w == "weekly" || lower_id.ends_with("-weekly") {
        "Weekly".into()
    } else if lower_w == "5h" || lower_id.ends_with("-5h") {
        "5h".into()
    } else if !w.is_empty() {
        terminal_text(w)
    } else {
        "—".into()
    }
}

fn format_bar_and_pct(pct: Option<i32>) -> String {
    match pct {
        Some(p) => {
            let clamped = p.clamp(0, 100);
            let mut filled = ((clamped + 5) / 10) as usize;
            if clamped > 0 && filled == 0 {
                filled = 1;
            }
            let empty = 10usize.saturating_sub(filled);
            format!(
                "[{}{}]  {:>3}%",
                "█".repeat(filled),
                "░".repeat(empty),
                clamped
            )
        }
        None => "[··········]     —".into(),
    }
}

fn format_relative_age(updated_unix: i64, now_unix: i64) -> String {
    if updated_unix <= 0 {
        return "unknown".into();
    }
    let diff = now_unix - updated_unix;
    if diff <= 2 {
        "just now".into()
    } else if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86_400 {
        format!("{}h {}m ago", diff / 3600, (diff % 3600) / 60)
    } else {
        format!("{}d {}h ago", diff / 86_400, (diff % 86_400) / 3600)
    }
}

pub fn format_rfc3339_local_minute(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "?".into();
    }
    match chrono::DateTime::parse_from_rfc3339(trimmed) {
        Ok(parsed) => parsed
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M")
            .to_string(),
        Err(_) => terminal_text(trimmed),
    }
}

pub fn format_unix_local_minute(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return "unknown".into();
    }
    match chrono::DateTime::from_timestamp(unix_secs, 0) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M")
            .to_string(),
        None => "unknown".into(),
    }
}

fn format_reset_local(reset_rfc3339: &str, now_unix: i64) -> String {
    let trimmed = reset_rfc3339.trim();
    if trimmed.is_empty() {
        return "—".into();
    }
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(trimmed) else {
        return terminal_text(trimmed);
    };
    let local_dt = parsed.with_timezone(&chrono::Local);
    let local_str = local_dt.format("%Y-%m-%d %H:%M").to_string();
    let rem = parsed.timestamp() - now_unix;
    if rem <= 0 {
        format!("{local_str}  (expired)")
    } else if rem >= 86_400 {
        let d = rem / 86_400;
        let h = (rem % 86_400) / 3600;
        format!("{local_str}  (in {d}d {h:02}h)")
    } else if rem >= 3600 {
        let h = rem / 3600;
        let m = (rem % 3600) / 60;
        format!("{local_str}  (in {h}h {m:02}m)")
    } else {
        let m = (rem / 60).max(1);
        format!("{local_str}  (in {m}m)")
    }
}

impl ModelViewDto {
    fn from_model(m: &ModelQuota) -> Self {
        Self {
            name: m.name.clone(),
            display_name: m.display_name.clone(),
            percentage: m.percentage,
            percentage_known: m.percentage_known,
            quota_bucket_id: m.quota_bucket_id.clone(),
            reset_time: m.reset_time.clone(),
        }
    }
}

impl GroupViewDto {
    fn from_group(g: &QuotaGroup) -> Self {
        Self {
            display_name: g.display_name.clone(),
            buckets: g.buckets.iter().map(BucketViewDto::from_bucket).collect(),
        }
    }
}

impl BucketViewDto {
    fn from_bucket(b: &QuotaBucket) -> Self {
        Self {
            bucket_id: b.bucket_id.clone(),
            window: b.window.clone(),
            remaining_fraction: b.remaining_fraction,
            remaining_fraction_known: b.remaining_fraction_known,
            reset_time: b.reset_time.clone(),
        }
    }
}

/// Tri-state status view (`selected_account` + `session_identity` + `runtime_state`) per Blueprint §2.2.
#[derive(Debug, Clone, Serialize)]
pub struct StatusViewDto {
    pub selected_account: Option<SelectedAccountBriefDto>,
    pub session_identity: SessionIdentity,
    pub runtime_state: RuntimeState,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelectedAccountBriefDto {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_tier: Option<String>,
    pub disabled: bool,
    pub validation_blocked: bool,
}

impl SelectedAccountBriefDto {
    pub fn from_record_at(rec: &AccountRecord, now_unix: i64) -> Self {
        Self {
            id: rec.id.clone(),
            email: rec.email.clone(),
            name: rec.name.clone(),
            custom_label: rec.custom_label.clone(),
            subscription_tier: rec.quota.as_ref().and_then(|q| q.subscription_tier.clone()),
            disabled: rec.disabled,
            validation_blocked: rec.is_validation_blocked_at(now_unix),
        }
    }
}

/// Extract active (non-`-disabled`) supported model IDs from a cached `QuotaObservation`.
pub fn extract_supported_models(obs: &QuotaObservation) -> Vec<String> {
    let mut models: Vec<String> = obs
        .models
        .iter()
        .map(|m| m.name.trim())
        .filter(|name| !name.is_empty() && !name.to_ascii_lowercase().ends_with("-disabled"))
        .map(terminal_text)
        .collect();
    models.sort();
    models.dedup();
    models
}

/// Render cached supported models grouped by family (`Gemini`, `Claude/GPT`, `Other`) with clean line wrapping.
pub fn format_supported_models_human(models: Option<&[String]>) -> Vec<String> {
    let Some(list) = models else {
        return vec![
            "Supported models : unknown (run `agy-switch-cli quota -r` to fetch catalog)".into(),
        ];
    };
    if list.is_empty() {
        return vec!["Supported models : none reported".into()];
    }

    let mut gemini = Vec::new();
    let mut third_party = Vec::new();
    let mut other = Vec::new();
    for m in list {
        let lower = m.to_ascii_lowercase();
        if lower.starts_with("gemini") {
            gemini.push(m.as_str());
        } else if lower.starts_with("claude") || lower.starts_with("gpt") {
            third_party.push(m.as_str());
        } else {
            other.push(m.as_str());
        }
    }

    let mut out = vec![format!(
        "Supported models : {} available (cached)",
        list.len()
    )];
    for (family_label, items) in [
        ("Gemini", gemini),
        ("Claude/GPT", third_party),
        ("Other", other),
    ] {
        if items.is_empty() {
            continue;
        }
        let prefix = format!("  {:<10} : ", family_label);
        let indent = " ".repeat(prefix.chars().count());
        let mut cur_line = String::new();
        let mut first = true;
        for item in items {
            let sep = if cur_line.is_empty() { "" } else { ", " };
            if !cur_line.is_empty() && cur_line.chars().count() + sep.len() + item.len() > 74 {
                if first {
                    out.push(format!("{prefix}{cur_line},"));
                    first = false;
                } else {
                    out.push(format!("{indent}{cur_line},"));
                }
                cur_line = item.to_string();
            } else {
                cur_line.push_str(sep);
                cur_line.push_str(item);
            }
        }
        if !cur_line.is_empty() {
            if first {
                out.push(format!("{prefix}{cur_line}"));
            } else {
                out.push(format!("{indent}{cur_line}"));
            }
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvalCandidateDto {
    pub id: String,
    pub email: String,
    pub evaluation: QuotaEval,
    pub qualified: bool,
}

pub fn format_session_identity_human(id: &SessionIdentity) -> String {
    match id {
        SessionIdentity::Matched { email, expiry, .. } => format!(
            "matched ({}, expires {})",
            terminal_text(email),
            format_rfc3339_local_minute(expiry)
        ),
        SessionIdentity::DriftedKnown { email, expiry, .. } => format!(
            "drifted_known ({}, expires {})",
            terminal_text(email),
            format_rfc3339_local_minute(expiry)
        ),
        SessionIdentity::DriftedExternal { email_hint, expiry } => {
            let hint = email_hint
                .as_deref()
                .map(terminal_text)
                .unwrap_or_else(|| "unknown-external".into());
            let exp = expiry
                .as_deref()
                .map(format_rfc3339_local_minute)
                .unwrap_or_else(|| "?".into());
            format!("drifted_external ({hint}, expires {exp})")
        }
        SessionIdentity::Uninitialized => "uninitialized".into(),
        SessionIdentity::Corrupt { detail } => format!("corrupt ({})", terminal_text(detail)),
        SessionIdentity::Unverified { detail } => format!("unverified ({})", terminal_text(detail)),
    }
}

pub fn format_runtime_state_human(rt: &RuntimeState) -> String {
    match rt {
        RuntimeState::Idle => "idle".into(),
        RuntimeState::ManagedRunning {
            count,
            account_ids,
            pids,
        } => {
            let safe_ids: Vec<String> = account_ids.iter().map(|s| terminal_text(s)).collect();
            format!("managed_running (count={count}, accounts={safe_ids:?}, pids={pids:?})")
        }
        RuntimeState::UnmanagedRunning {
            pids,
            managed_account_ids,
            ..
        } => {
            let safe_ids: Vec<String> = managed_account_ids
                .iter()
                .map(|s| terminal_text(s))
                .collect();
            format!(
                "unmanaged_running (identity=unknown, pids={pids:?}, managed_accounts={safe_ids:?})"
            )
        }
        RuntimeState::Unverified { detail } => format!("unverified ({})", terminal_text(detail)),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvalViewDto {
    pub policy: SwitchPolicy,
    pub source_account_id: Option<String>,
    pub source_evaluation: Option<QuotaEval>,
    pub would_switch: bool,
    pub recommended_target_id: Option<String>,
    pub decision_reason: String,
    pub candidates: Vec<PolicyEvalCandidateDto>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_table_hides_model_dump_by_default_and_shows_aligned_weekly_and_5h_bars() {
        let now = 1_794_829_000i64;
        let mut obs = QuotaObservation::new(now - 120, QuotaSourceEnv::Daily);
        obs.subscription_tier = Some("Google AI Pro".into());
        obs.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: None,
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "gemini-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: "2026-11-16T16:34:28Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "gemini-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.72,
                        remaining_fraction_known: Some(true),
                        reset_time: "2026-11-23T11:34:28Z".into(),
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
                        bucket_id: "3p-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.37,
                        remaining_fraction_known: Some(true),
                        reset_time: "2026-11-21T13:22:36Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "3p-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: "2026-11-16T16:34:28Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
        ]);
        obs.models.push(ModelQuota {
            name: "gemini-3.8-flash-high".into(),
            percentage: 72,
            percentage_known: Some(true),
            observed_remaining_fraction: Some(0.72),
            primary_quota: None,
            quota_bucket_id: Some("gemini-weekly".into()),
            reset_time: "2026-11-23T11:34:28Z".into(),
            display_name: None,
            supports_images: None,
            supports_thinking: None,
            thinking_budget: None,
            recommended: None,
            max_tokens: None,
            max_output_tokens: None,
            supported_mime_types: None,
        });

        let dto = QuotaViewDto::from_observation(&obs);
        let eval = QuotaEval::Known {
            remaining_percentage: 37.0,
        };

        let compact = dto.human_multiline_at("user@example.invalid", Some((&eval, "all")), now);
        assert!(compact.contains("Account : user@example.invalid  [Google AI Pro]"));
        assert!(compact.contains("updated 2m ago (source: Daily)"));
        assert!(compact.contains("Gemini"));
        assert!(compact.contains("Claude / GPT"));
        assert!(compact.contains("Weekly"));
        assert!(compact.contains("5h"));
        assert!(compact.contains("[███████░░░]   72%"));
        assert!(compact.contains("[████░░░░░░]   37%"));
        let expected_reset_year_minute =
            chrono::DateTime::parse_from_rfc3339("2026-11-23T11:34:28Z")
                .unwrap()
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string();
        assert!(compact.contains(&expected_reset_year_minute));
        assert!(!compact.contains("gemini-3.8-flash-high"));

        let stale_eval = QuotaEval::Stale {
            reason: "stale_quota".into(),
        };
        let stale_out =
            dto.human_multiline_at("user@example.invalid", Some((&stale_eval, "all")), now);
        assert!(stale_out.contains("add -r to refresh"));

        let models = extract_supported_models(&obs);
        assert_eq!(models, vec!["gemini-3.8-flash-high".to_string()]);
        let status_lines = format_supported_models_human(Some(&models)).join("\n");
        assert!(status_lines.contains("Supported models : 1 available (cached)"));
        assert!(status_lines.contains("gemini-3.8-flash-high"));

        let expected_exp = format_rfc3339_local_minute("2026-11-17T02:26:45.000000Z");
        let matched = format_session_identity_human(&SessionIdentity::Matched {
            account_id: "acc-internal-0001".into(),
            email: "alice@example.com".into(),
            expiry: "2026-11-17T02:26:45.000000Z".into(),
        });
        assert_eq!(
            matched,
            format!("matched (alice@example.com, expires {expected_exp})")
        );
        assert!(!matched.contains("acc-internal-0001"));

        let drifted = format_session_identity_human(&SessionIdentity::DriftedKnown {
            account_id: "acc-internal-0002".into(),
            email: "bob@example.com".into(),
            expiry: "2026-11-17T02:26:45Z".into(),
        });
        assert_eq!(
            drifted,
            format!("drifted_known (bob@example.com, expires {expected_exp})")
        );
        assert!(!drifted.contains("acc-internal-0002"));

        let ext = format_session_identity_human(&SessionIdentity::DriftedExternal {
            email_hint: Some("charlie@example.com".into()),
            expiry: Some("2026-11-17T02:26:45Z".into()),
        });
        assert_eq!(
            ext,
            format!("drifted_external (charlie@example.com, expires {expected_exp})")
        );

        assert_eq!(format_unix_local_minute(0), "unknown");
        assert_eq!(
            format_unix_local_minute(1_794_882_405),
            chrono::DateTime::from_timestamp(1_794_882_405, 0)
                .unwrap()
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        );
    }
}
