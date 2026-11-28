use crate::domain::account::{
    AccountRecord, DisableReasonCode, RuntimeState, SessionIdentity, STORE_SCHEMA_VERSION,
};
use crate::domain::quota::{
    is_unused_full_bucket_reset_time, observed_quota_percentage, quota_pool, ModelQuota,
    QuotaBucket, QuotaEval, QuotaGroup, QuotaObservation, QuotaPool, QuotaSourceEnv,
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
    pub last_switched_in_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_switched_out_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<QuotaViewDto>,
}

impl AccountViewDto {
    pub fn from_record(rec: &AccountRecord, is_selected: bool) -> Self {
        Self::from_record_at(
            rec,
            is_selected,
            crate::domain::clock::current_unix_seconds(),
        )
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
            last_switched_in_at: rec.last_switched_in_at,
            last_switched_out_at: rec.last_switched_out_at,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
            is_forbidden: obs.is_forbidden,
            models: obs.models.iter().map(ModelViewDto::from_model).collect(),
            quota_groups: obs
                .quota_groups
                .as_ref()
                .map(|gs| gs.iter().map(GroupViewDto::from_group).collect()),
        }
    }

    pub fn human_multiline(&self, email: &str) -> String {
        self.human_multiline_at(email, None, crate::domain::clock::current_unix_seconds())
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
            crate::domain::clock::current_unix_seconds(),
        )
    }

    pub fn human_multiline_at(
        &self,
        email: &str,
        eval_ctx: Option<(&QuotaEval, &str)>,
        now_unix: i64,
    ) -> String {
        let age_str = format_relative_age(self.last_updated, now_unix);

        let mut lines = vec![format!("Account : {}", terminal_text(email))];
        if let Some((eval, monitored_model)) = eval_ctx {
            let refresh_hint = if matches!(eval, QuotaEval::Stale { .. }) {
                " — add --refresh to refresh"
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
                let reset_col = if is_unused_full_bucket_reset_time(
                    &b.reset_time,
                    b.remaining_fraction,
                    b.remaining_fraction_known,
                ) {
                    "—".into()
                } else {
                    format_reset_local(&b.reset_time, now_unix)
                };
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
                .map(|r| terminal_display_width(&r.pool_col))
                .max()
                .unwrap_or(4)
                .max("Pool".len());
            let win_w = rows
                .iter()
                .map(|r| terminal_display_width(&r.win_col))
                .max()
                .unwrap_or(6)
                .max("Window".len());
            let bar_w = 18usize;
            let reset_w = rows
                .iter()
                .map(|r| terminal_display_width(&r.reset_col))
                .max()
                .unwrap_or(16)
                .max("Resets (Local)".len());
            let divider_len = pool_w + 3 + win_w + 3 + bar_w + 3 + reset_w;

            lines.push(String::new());
            lines.push(format!(
                "  {}   {}   {}   Resets (Local)",
                pad_right_display_width("Pool", pool_w),
                pad_right_display_width("Window", win_w),
                pad_right_display_width("Remaining", bar_w),
            ));
            lines.push(format!("  {}", "─".repeat(divider_len)));
            for r in &rows {
                lines.push(format!(
                    "  {}   {}   {}   {}",
                    pad_right_display_width(&r.pool_col, pool_w),
                    pad_right_display_width(&r.win_col, win_w),
                    r.bar_col,
                    r.reset_col
                ));
            }
        } else if !self.is_forbidden {
            lines.push(
                "  No pool quota observations recorded (run `agy-switch-cli quota --refresh` to refresh)."
                    .into(),
            );
        }

        lines.join("\n")
    }
}

#[cfg(any(feature = "tui", feature = "stats"))]
fn terminal_display_width(s: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(s)
}

#[cfg(not(any(feature = "tui", feature = "stats")))]
fn char_display_width_fallback(ch: char) -> usize {
    let cp = ch as u32;
    if ch.is_control()
        || matches!(
            cp,
            0x0300..=0x036F
                | 0x1AB0..=0x1AFF
                | 0x1DC0..=0x1DFF
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0x20D0..=0x20FF
                | 0x3099..=0x309A
                | 0xFE00..=0xFE0F
                | 0xFE20..=0xFE2F
                | 0xE0100..=0xE01EF
        )
    {
        return 0;
    }
    if matches!(
        cp,
        0x1100..=0x115F
            | 0x2329..=0x232A
            | 0x2E80..=0x303E
            | 0x3040..=0x33FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0xA4CF
            | 0xA960..=0xA97C
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF01..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1FAFF
            | 0x20000..=0x3FFFD
    ) {
        return 2;
    }
    1
}

#[cfg(not(any(feature = "tui", feature = "stats")))]
fn terminal_display_width(s: &str) -> usize {
    s.chars().map(char_display_width_fallback).sum()
}

fn pad_right_display_width(s: &str, width: usize) -> String {
    let cur = terminal_display_width(s);
    if cur >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - cur))
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

pub(crate) fn format_window_label(window: &str, bucket_id: &str) -> String {
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

pub(crate) fn format_bar_and_pct(pct: Option<i32>) -> String {
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

pub(crate) fn format_relative_age(updated_unix: i64, now_unix: i64) -> String {
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
    match crate::domain::clock::parse_rfc3339_timestamp(trimmed) {
        Some(parsed) => crate::domain::clock::format_timestamp_local_minute(parsed),
        None => terminal_text(trimmed),
    }
}

pub fn format_unix_local_minute(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return "unknown".into();
    }
    match jiff::Timestamp::from_second(unix_secs) {
        Ok(ts) => crate::domain::clock::format_timestamp_local_minute(ts),
        Err(_) => "unknown".into(),
    }
}

pub(crate) fn format_reset_local(reset_rfc3339: &str, now_unix: i64) -> String {
    let trimmed = reset_rfc3339.trim();
    if trimmed.is_empty() {
        return "—".into();
    }
    let Some(parsed) = crate::domain::clock::parse_rfc3339_timestamp(trimmed) else {
        return terminal_text(trimmed);
    };
    let local_str = crate::domain::clock::format_timestamp_local_minute(parsed);
    let rem = crate::domain::clock::timestamp_unix_seconds(parsed) - now_unix;
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
            description: g.description.clone(),
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

const OFFICIAL_GROUP_DESC_PREFIX: &str = "models within this group:";

fn format_group_description_for_display(raw: &str) -> Option<String> {
    let safe = terminal_text(raw);
    let trimmed = safe.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() >= OFFICIAL_GROUP_DESC_PREFIX.len()
        && trimmed.is_char_boundary(OFFICIAL_GROUP_DESC_PREFIX.len())
        && trimmed[..OFFICIAL_GROUP_DESC_PREFIX.len()]
            .eq_ignore_ascii_case(OFFICIAL_GROUP_DESC_PREFIX)
    {
        let rest = trimmed[OFFICIAL_GROUP_DESC_PREFIX.len()..]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        return (!rest.is_empty()).then_some(rest);
    }
    Some(trimmed.to_string())
}

/// Extract `(display_name, description)` pairs from `quota_groups` for `OfficialCli` observations
/// where per-model catalog entries (`models`) are absent. Strips the redundant case-insensitive
/// `"Models within this group:"` prefix at display time while keeping non-prefix descriptions
/// verbatim (after terminal control sanitization) without mutating cached JSON on disk.
pub fn extract_quota_group_descriptions(obs: &QuotaObservation) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for g in obs.quota_groups.iter().flatten() {
        if let Some(desc) = g
            .description
            .as_deref()
            .and_then(format_group_description_for_display)
        {
            let name = terminal_text(g.display_name.trim());
            let label = if name.is_empty() {
                "Group".to_string()
            } else {
                name
            };
            out.push((label, desc));
        }
    }
    out
}

/// Render cached supported models or official `quota_groups` descriptions for `current`,
/// aligning colons across group names by maximum terminal display column width.
pub fn format_supported_models_or_groups_human(
    models: Option<&[String]>,
    group_descriptions: &[(String, String)],
) -> Vec<String> {
    if models.is_some_and(|list| !list.is_empty()) {
        return format_supported_models_human(models);
    }
    if !group_descriptions.is_empty() {
        let max_name_w = group_descriptions
            .iter()
            .map(|(name, _)| terminal_display_width(name))
            .max()
            .unwrap_or(0);
        let mut out = vec![format!(
            "Model groups     : {} group(s) (from official agy /usage)",
            group_descriptions.len()
        )];
        for (name, desc) in group_descriptions {
            out.push(format!(
                "  {} : {desc}",
                pad_right_display_width(name, max_name_w)
            ));
        }
        return out;
    }
    format_supported_models_human(models)
}

/// Render cached supported models grouped by family (`Gemini`, `Claude/GPT`, `Other`) with clean line wrapping.
pub fn format_supported_models_human(models: Option<&[String]>) -> Vec<String> {
    let Some(list) = models else {
        return vec![
            "Supported models : unknown (run `agy-switch-cli quota --refresh` to fetch catalog)"
                .into(),
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
        } => {
            if managed_account_ids.is_empty() {
                format!("unmanaged_running (pids={pids:?})")
            } else {
                let safe_ids: Vec<String> = managed_account_ids
                    .iter()
                    .map(|s| terminal_text(s))
                    .collect();
                format!("unmanaged_running (pids={pids:?}, managed_accounts={safe_ids:?})")
            }
        }
        RuntimeState::Unverified { detail } => format!("unverified ({})", terminal_text(detail)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_table_hides_model_dump_by_default_and_shows_aligned_weekly_and_5h_bars() {
        let now = 1_794_829_000i64;
        let mut obs = QuotaObservation::new(now - 120, QuotaSourceEnv::Daily);
        obs.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: Some(
                    "Models within this group: Gemini 4 Hydrogen, Gemini 3.8 Flash".into(),
                ),
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
                description: Some(
                    "  models WITHIN this GROUP:  Claude Sonnet 4.6, Claude Opus 4.6, GPT-OSS 120B "
                        .into(),
                ),
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
        assert!(compact.contains("Account : user@example.invalid"));
        assert!(!compact.contains("[Unknown]"));
        assert!(!compact.contains("[Google AI Pro]"));
        assert!(compact.contains("updated 2m ago (source: Daily)"));
        assert!(compact.contains("Gemini"));
        assert!(compact.contains("Claude / GPT"));
        assert!(compact.contains("Weekly"));
        assert!(compact.contains("5h"));
        assert!(compact.contains("[███████░░░]   72%"));
        assert!(compact.contains("[████░░░░░░]   37%"));
        let expected_reset_year_minute = "2026-11-23T11:34:28Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::system())
            .strftime("%Y-%m-%d %H:%M")
            .to_string();
        assert!(compact.contains(&expected_reset_year_minute));
        assert!(!compact.contains("gemini-3.8-flash-high"));

        let stale_eval = QuotaEval::Stale {
            reason: "stale_quota".into(),
        };
        let stale_out =
            dto.human_multiline_at("user@example.invalid", Some((&stale_eval, "all")), now);
        assert!(stale_out.contains("add --refresh to refresh"));
        assert!(!stale_out.contains("add -r"));

        // `extract_quota_group_descriptions` strips case-insensitive `"Models within this group:"`
        // while keeping non-matching descriptions verbatim and aligning colons in `current`.
        let group_descs = extract_quota_group_descriptions(&obs);
        assert_eq!(
            group_descs,
            vec![
                (
                    "Gemini Models".into(),
                    "Gemini 4 Hydrogen, Gemini 3.8 Flash".into(),
                ),
                (
                    "Claude and GPT models".into(),
                    "Claude Sonnet 4.6, Claude Opus 4.6, GPT-OSS 120B".into(),
                ),
            ]
        );
        let aligned_lines = format_supported_models_or_groups_human(None, &group_descs);
        assert_eq!(
            aligned_lines,
            vec![
                "Model groups     : 2 group(s) (from official agy /usage)".to_string(),
                "  Gemini Models         : Gemini 4 Hydrogen, Gemini 3.8 Flash".to_string(),
                "  Claude and GPT models : Claude Sonnet 4.6, Claude Opus 4.6, GPT-OSS 120B"
                    .to_string(),
            ]
        );

        let mut custom_obs = QuotaObservation::new(now, QuotaSourceEnv::OfficialCli);
        custom_obs.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Custom Pool".into(),
                description: Some("Shared  double   space  models without prefix".into()),
                buckets: Vec::new(),
            },
            QuotaGroup {
                display_name: "Empty After Prefix".into(),
                description: Some("Models within this group:   ".into()),
                buckets: Vec::new(),
            },
            QuotaGroup {
                display_name: "中文模型组".into(),
                description: Some("Models within this group:   Model-A,   Model-B".into()),
                buckets: Vec::new(),
            },
            QuotaGroup {
                display_name: "カ\u{3099}組".into(),
                description: Some("Decomposed  kana  preserved".into()),
                buckets: Vec::new(),
            },
        ]);
        let custom_descs = extract_quota_group_descriptions(&custom_obs);
        assert_eq!(
            custom_descs,
            vec![
                (
                    "Custom Pool".into(),
                    "Shared  double   space  models without prefix".into(),
                ),
                ("中文模型组".into(), "Model-A, Model-B".into()),
                ("カ\u{3099}組".into(), "Decomposed  kana  preserved".into()),
            ]
        );
        // CJK + decomposed kana (`U+3099`) + ASCII display-width alignment places `:` at the exact same terminal column!
        assert_eq!(terminal_display_width("カ\u{3099}組"), 4);
        let mixed_lines = format_supported_models_or_groups_human(None, &custom_descs);
        let colon_cols: Vec<usize> = mixed_lines[1..]
            .iter()
            .map(|line| {
                let before_colon = line.split(" : ").next().unwrap();
                terminal_display_width(before_colon)
            })
            .collect();
        assert_eq!(colon_cols, vec![13, 13, 13]);

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
            jiff::Timestamp::from_second(1_794_882_405)
                .unwrap()
                .to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M")
                .to_string()
        );

        assert_eq!(format_runtime_state_human(&RuntimeState::Idle), "idle");
        let unm_single = RuntimeState::UnmanagedRunning {
            pids: vec![636233],
            managed_account_ids: Vec::new(),
        };
        assert_eq!(
            format_runtime_state_human(&unm_single),
            "unmanaged_running (pids=[636233])"
        );
        let unm_json = serde_json::to_value(&unm_single).unwrap();
        assert!(
            unm_json.get("identity").is_none(),
            "UnmanagedRunning JSON must omit redundant identity field"
        );
        assert_eq!(
            format_runtime_state_human(&RuntimeState::UnmanagedRunning {
                pids: vec![636233, 636240],
                managed_account_ids: vec!["acc-0001".into()],
            }),
            "unmanaged_running (pids=[636233, 636240], managed_accounts=[\"acc-0001\"])"
        );
    }
}
