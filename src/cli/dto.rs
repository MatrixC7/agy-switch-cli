use crate::domain::account::{
    AccountRecord, DisableReasonCode, RuntimeState, SessionIdentity, STORE_SCHEMA_VERSION,
};
use crate::domain::policy::SwitchPolicy;
use crate::domain::quota::{
    observed_quota_percentage, ModelQuota, QuotaBucket, QuotaEval, QuotaGroup, QuotaObservation,
    QuotaSourceEnv,
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
        self.human_multiline_inner(email, None)
    }

    pub fn human_multiline_with_eval(
        &self,
        email: &str,
        eval: &QuotaEval,
        monitored_model: &str,
    ) -> String {
        self.human_multiline_inner(email, Some((eval, monitored_model)))
    }

    fn human_multiline_inner(&self, email: &str, eval_ctx: Option<(&QuotaEval, &str)>) -> String {
        let mut lines = vec![format!(
            "{}: cached quota (updated Unix {}, source: {:?})",
            terminal_text(email),
            self.last_updated,
            self.source_env
        )];
        if let Some((eval, monitored_model)) = eval_ctx {
            lines.push(format!(
                "Status: {}",
                format_quota_eval_human(eval, monitored_model)
            ));
        }
        lines.push(format!(
            "Plan: {}",
            self.subscription_tier
                .as_deref()
                .map(terminal_text)
                .unwrap_or_else(|| "Unknown".into())
        ));
        if self.is_forbidden {
            lines.push("Quota access is forbidden (HTTP 403).".into());
        }
        for group in self.quota_groups.iter().flatten() {
            lines.push(format!("Group: {}", terminal_text(&group.display_name)));
            for b in &group.buckets {
                lines.push(format!(
                    "  {} ({}): {} remaining; resets {}",
                    terminal_text(&b.bucket_id),
                    terminal_text(&b.window),
                    format_pct(observed_quota_percentage(
                        b.remaining_fraction,
                        b.remaining_fraction_known
                    )),
                    terminal_text(&b.reset_time)
                ));
            }
        }
        for m in &self.models {
            lines.push(format!(
                "  {}: {} remaining; resets {}",
                terminal_text(&m.name),
                format_pct(observed_quota_percentage(
                    m.percentage as f64 / 100.0,
                    m.percentage_known
                )),
                terminal_text(&m.reset_time)
            ));
        }
        lines.join("\n")
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
    pub disabled: bool,
}

impl SelectedAccountBriefDto {
    pub fn from_record(rec: &AccountRecord) -> Self {
        Self {
            id: rec.id.clone(),
            email: rec.email.clone(),
            name: rec.name.clone(),
            custom_label: rec.custom_label.clone(),
            disabled: rec.disabled,
        }
    }
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
        SessionIdentity::Matched {
            account_id,
            email,
            expiry,
        } => format!(
            "matched ({}, {}, expires {})",
            terminal_text(account_id),
            terminal_text(email),
            terminal_text(expiry)
        ),
        SessionIdentity::DriftedKnown {
            account_id,
            email,
            expiry,
        } => format!(
            "drifted_known ({}, {}, expires {})",
            terminal_text(account_id),
            terminal_text(email),
            terminal_text(expiry)
        ),
        SessionIdentity::DriftedExternal { email_hint, expiry } => {
            let hint = email_hint
                .as_deref()
                .map(terminal_text)
                .unwrap_or_else(|| "unknown-external".into());
            let exp = expiry
                .as_deref()
                .map(terminal_text)
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
