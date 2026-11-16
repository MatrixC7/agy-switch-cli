use crate::domain::account::STORE_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    #[default]
    Wait,
    Stop,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStrategy {
    #[default]
    Priority,
    #[serde(alias = "round-robin")]
    RoundRobin,
}

/// Auto-switch policy (`policy.json`, schema_version: 1) per Blueprint §7.3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchPolicy {
    pub schema_version: u32,
    pub revision: u64,
    pub enabled: bool,
    pub mode: PolicyMode,
    pub strategy: PolicyStrategy,
    pub reserve_percentage: u8,
    pub candidate_min_percentage: u8,
    pub monitored_model: String,
    pub candidate_account_ids: Vec<String>,
    pub updated_at: i64,
}

impl Default for SwitchPolicy {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            revision: 0,
            enabled: false,
            mode: PolicyMode::Wait,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "all".to_string(),
            candidate_account_ids: Vec::new(),
            updated_at: 0,
        }
    }
}

impl SwitchPolicy {
    /// Field-level precise validation messages per Blueprint §7.3.
    pub fn validate(&self, known_account_ids: Option<&HashSet<String>>) -> Result<(), String> {
        if !(1..=98).contains(&self.reserve_percentage) {
            return Err("保留阈值 (--reserve) 必须介于 1% 到 98% 之间".to_string());
        }
        if self.candidate_min_percentage <= self.reserve_percentage
            || self.candidate_min_percentage > 100
        {
            return Err("候选最低额度 (--minimum) 必须严格大于保留阈值且不超过 100%".to_string());
        }
        let model = self.monitored_model.trim();
        if model.is_empty()
            || model.len() > 200
            || !model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(
                "监控模型 (--model) 支持 all、gemini、claude、argon 或有效模型 ID（长度 <= 200）"
                    .to_string(),
            );
        }
        if self.candidate_account_ids.len() > 100 {
            return Err("候选账号数量不能超过 100 个".to_string());
        }

        let mut seen = HashSet::new();
        let mut duplicates = Vec::new();
        let mut empty_found = false;
        for id in &self.candidate_account_ids {
            if id.trim().is_empty() {
                empty_found = true;
                continue;
            }
            if crate::domain::account::validate_account_id(id).is_err() {
                return Err("候选账号列表包含非法账号 ID 格式".to_string());
            }
            if !seen.insert(id.as_str()) && !duplicates.contains(&id.as_str()) {
                duplicates.push(id.as_str());
            }
        }
        if empty_found {
            return Err("候选账号列表包含空选择器".to_string());
        }
        if !duplicates.is_empty() {
            return Err(format!("候选账号列表存在重复项: {}", duplicates.join(", ")));
        }

        if let Some(known) = known_account_ids {
            let missing: Vec<&str> = self
                .candidate_account_ids
                .iter()
                .map(String::as_str)
                .filter(|id| !known.contains(*id))
                .collect();
            if !missing.is_empty() {
                return Err(format!(
                    "候选账号不存在于本地账号索引中: {}",
                    missing.join(", ")
                ));
            }
        }

        if self.enabled && self.candidate_account_ids.is_empty() {
            return Err(
                "启用自动切换前，必须通过 --candidates 至少指定 1 个备用候选账号".to_string(),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_validation_reports_precise_field_errors() {
        let mut p = SwitchPolicy {
            reserve_percentage: 0,
            ..SwitchPolicy::default()
        };
        assert!(p.validate(None).unwrap_err().contains("--reserve"));

        p.reserve_percentage = 30;
        p.candidate_min_percentage = 30;
        assert!(p.validate(None).unwrap_err().contains("--minimum"));

        p.candidate_min_percentage = 50;
        p.monitored_model = "bad model name".into();
        assert!(p.validate(None).unwrap_err().contains("--model"));

        p.monitored_model = "argon".into();
        p.enabled = true;
        assert!(p.validate(None).unwrap_err().contains("--candidates"));

        p.candidate_account_ids = vec!["acc-1".into(), "acc-1".into()];
        assert!(p.validate(None).unwrap_err().contains("重复项"));

        p.candidate_account_ids = vec!["acc-1".into(), "acc-missing".into()];
        let known = HashSet::from(["acc-1".to_string()]);
        let err = p.validate(Some(&known)).unwrap_err();
        assert!(err.contains("acc-missing"));
    }
}
