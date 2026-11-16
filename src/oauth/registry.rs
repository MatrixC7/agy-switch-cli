use crate::domain::config::OAuthFileConfig;
use crate::domain::token::TokenRecord;
use crate::error::{CliError, CliResult};
use crate::oauth::flow::BASE_CONSUMER_SCOPES;
use crate::paths::HeadlessPaths;
use crate::store::repository::read_headless_config_readonly;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const BUILTIN_CLIENT_KEY: &str = "antigravity_enterprise";
const BUILTIN_CLIENT_ID: &str =
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const BUILTIN_CLIENT_SECRET: &str = "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";

pub const OAUTH_CLIENTS_ENV: &str = "ANTIGRAVITY_OAUTH_CLIENTS";
pub const ACTIVE_OAUTH_CLIENT_ENV: &str = "ANTIGRAVITY_OAUTH_CLIENT_KEY";
pub const REQUIRED_OAUTH_SCOPES_ENV: &str = "ANTIGRAVITY_REQUIRED_SCOPES";

pub fn default_request_scopes() -> Vec<String> {
    BASE_CONSUMER_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

pub fn default_required_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "https://www.googleapis.com/auth/cloud-platform".to_string(),
    ]
}

#[derive(Clone)]
pub struct OAuthClientConfig {
    pub key: String,
    pub label: String,
    pub client_id: String,
    pub client_secret: String,
    pub is_builtin: bool,
    pub request_scopes: Vec<String>,
    pub required_scopes: Vec<String>,
}

impl fmt::Debug for OAuthClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthClientConfig")
            .field("key", &self.key)
            .field("label", &self.label)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("is_builtin", &self.is_builtin)
            .field("request_scopes", &self.request_scopes)
            .field("required_scopes", &self.required_scopes)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientDescriptor {
    pub key: String,
    pub label: String,
    pub client_id: String,
    pub is_active: bool,
    pub is_builtin: bool,
    pub request_scopes: Vec<String>,
    pub required_scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthClientRegistry {
    clients: Vec<OAuthClientConfig>,
    active_key: String,
    global_required_scopes: Vec<String>,
    warnings: Vec<String>,
}

pub fn normalize_client_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

pub(crate) fn sanitize_key_for_log(raw_key: &str) -> String {
    if crate::error::looks_like_secret_value(raw_key) {
        return "<redacted-key>".to_string();
    }
    let normalized = normalize_client_key(raw_key);
    if !normalized.is_empty()
        && normalized.len() <= 32
        && !normalized.starts_with("gocspx")
        && !normalized.starts_with("ya29")
        && !normalized.starts_with("eyj")
        && !normalized.starts_with("aiza")
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        normalized
    } else {
        "<invalid-key>".to_string()
    }
}

fn parse_scope_list_flexible(raw: &str) -> Vec<String> {
    raw.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn clean_scope_vec(scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn scope_list_satisfies(granted: &[String], required: &str) -> bool {
    let req = required.trim();
    if req.is_empty() {
        return true;
    }
    granted.iter().any(|g| {
        let g = g.trim();
        if g.eq_ignore_ascii_case(req) {
            return true;
        }
        matches!(
            (g, req),
            ("email", "https://www.googleapis.com/auth/userinfo.email")
                | ("https://www.googleapis.com/auth/userinfo.email", "email")
                | (
                    "profile",
                    "https://www.googleapis.com/auth/userinfo.profile"
                )
                | (
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "profile"
                )
        )
    })
}

impl OAuthClientRegistry {
    pub fn from_env() -> Self {
        let raw_extra = std::env::var(OAUTH_CLIENTS_ENV).ok();
        let raw_active = std::env::var(ACTIVE_OAUTH_CLIENT_ENV).ok();
        let raw_req = std::env::var(REQUIRED_OAUTH_SCOPES_ENV).ok();
        Self::from_config_and_raw(
            None,
            raw_extra.as_deref(),
            raw_active.as_deref(),
            raw_req.as_deref(),
            Vec::new(),
        )
    }

    /// Pure read-only load combining `<data_dir>/config.json` (`oauth.*`) + environment variables (`ANTIGRAVITY_*`).
    /// Creates zero files or directories when `config.json` is absent.
    pub fn load(paths: &HeadlessPaths) -> CliResult<Self> {
        let (cfg, cfg_warnings) = read_headless_config_readonly(paths)?;
        let raw_extra = std::env::var(OAUTH_CLIENTS_ENV).ok();
        let raw_active = std::env::var(ACTIVE_OAUTH_CLIENT_ENV).ok();
        let raw_req = std::env::var(REQUIRED_OAUTH_SCOPES_ENV).ok();
        Ok(Self::from_config_and_raw(
            Some(&cfg.oauth),
            raw_extra.as_deref(),
            raw_active.as_deref(),
            raw_req.as_deref(),
            cfg_warnings,
        ))
    }

    /// Parse OAuth client configuration without EVER echoing raw entry text or `client_secret` in warnings!
    pub fn parse_from_raw(raw_extra_clients: Option<&str>, raw_active_key: Option<&str>) -> Self {
        Self::from_config_and_raw(None, raw_extra_clients, raw_active_key, None, Vec::new())
    }

    pub fn from_config_and_raw(
        file_cfg: Option<&OAuthFileConfig>,
        raw_extra_clients: Option<&str>,
        raw_active_key: Option<&str>,
        raw_required_scopes: Option<&str>,
        mut warnings: Vec<String>,
    ) -> Self {
        let env_req = raw_required_scopes
            .map(parse_scope_list_flexible)
            .filter(|v| !v.is_empty());
        let file_req = file_cfg
            .and_then(|c| c.required_scopes.as_deref())
            .map(clean_scope_vec)
            .filter(|v| !v.is_empty());
        let global_required_scopes = env_req.or(file_req).unwrap_or_else(default_required_scopes);

        let mut clients = vec![OAuthClientConfig {
            key: BUILTIN_CLIENT_KEY.to_string(),
            label: "Antigravity Enterprise".to_string(),
            client_id: BUILTIN_CLIENT_ID.to_string(),
            client_secret: BUILTIN_CLIENT_SECRET.to_string(),
            is_builtin: true,
            request_scopes: default_request_scopes(),
            required_scopes: global_required_scopes.clone(),
        }];

        // 1. Apply config.json `oauth.clients` extensions (secret-redacted warnings on malformed entries)
        if let Some(cfg) = file_cfg {
            for (idx, item) in cfg.clients.iter().enumerate() {
                let entry_no = idx + 1;
                let key = normalize_client_key(&item.key);
                let cid = item.client_id.trim();
                let csec = item.client_secret.trim();
                if key.is_empty() || cid.is_empty() || csec.is_empty() {
                    let safe_key = sanitize_key_for_log(&item.key);
                    warnings.push(format!(
                        "Ignored incomplete OAuth client entry #{entry_no} (key={safe_key}) in config.json: empty key, client_id, or client_secret."
                    ));
                    continue;
                }
                let label = item
                    .label
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| key.clone());
                let req_scopes = item
                    .request_scopes
                    .as_deref()
                    .map(clean_scope_vec)
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(default_request_scopes);
                let must_scopes = item
                    .required_scopes
                    .as_deref()
                    .map(clean_scope_vec)
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| global_required_scopes.clone());

                let custom = OAuthClientConfig {
                    key: key.clone(),
                    label,
                    client_id: cid.to_string(),
                    client_secret: csec.to_string(),
                    is_builtin: false,
                    request_scopes: req_scopes,
                    required_scopes: must_scopes,
                };
                if let Some(pos) = clients.iter().position(|c| c.key == key) {
                    clients[pos] = custom;
                } else {
                    clients.push(custom);
                }
            }
        }

        // 2. Apply `ANTIGRAVITY_OAUTH_CLIENTS` env var extensions (higher precedence than config.json)
        if let Some(raw_extra) = raw_extra_clients {
            for (idx, entry) in raw_extra.split(';').enumerate() {
                let entry_no = idx + 1;
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split('|').map(str::trim).collect();
                if parts.len() < 3 {
                    // Never echo `parts[0]` when `|` delimiters are missing — the raw entry may be a pasted secret!
                    warnings.push(format!(
                        "Ignored malformed OAuth client entry #{entry_no} in {OAUTH_CLIENTS_ENV}: expected `key|client_id|client_secret[|label]`."
                    ));
                    continue;
                }

                let key = normalize_client_key(parts[0]);
                if key.is_empty() || parts[1].is_empty() || parts[2].is_empty() {
                    let safe_key = sanitize_key_for_log(parts[0]);
                    warnings.push(format!(
                        "Ignored incomplete OAuth client entry #{entry_no} (key={safe_key}) in {OAUTH_CLIENTS_ENV}: empty key, client_id, or client_secret."
                    ));
                    continue;
                }

                let label = if parts.len() >= 4 && !parts[3].is_empty() {
                    parts[3].to_string()
                } else {
                    key.clone()
                };

                let existing_scopes = clients
                    .iter()
                    .find(|c| c.key == key)
                    .map(|c| (c.request_scopes.clone(), c.required_scopes.clone()));
                let (request_scopes, required_scopes) = existing_scopes
                    .unwrap_or_else(|| (default_request_scopes(), global_required_scopes.clone()));

                let custom = OAuthClientConfig {
                    key: key.clone(),
                    label,
                    client_id: parts[1].to_string(),
                    client_secret: parts[2].to_string(),
                    is_builtin: false,
                    request_scopes,
                    required_scopes,
                };

                if let Some(pos) = clients.iter().position(|c| c.key == key) {
                    clients[pos] = custom;
                } else {
                    clients.push(custom);
                }
            }
        }

        let cfg_active = file_cfg
            .and_then(|c| c.active_client_key.as_deref())
            .map(normalize_client_key)
            .filter(|k| !k.is_empty());
        let env_active = raw_active_key
            .map(normalize_client_key)
            .filter(|k| !k.is_empty());
        let (mut active_key, active_source) = if let Some(ek) = env_active {
            (ek, ACTIVE_OAUTH_CLIENT_ENV)
        } else if let Some(ck) = cfg_active {
            (ck, "config.json oauth.active_client_key")
        } else {
            (BUILTIN_CLIENT_KEY.to_string(), "default")
        };

        if !clients.iter().any(|c| c.key == active_key) {
            warnings.push(format!(
                "Configured {active_source} '{}' is not registered; falling back to '{}'.",
                sanitize_key_for_log(&active_key),
                BUILTIN_CLIENT_KEY
            ));
            active_key = clients
                .first()
                .map(|c| c.key.clone())
                .unwrap_or_else(|| BUILTIN_CLIENT_KEY.to_string());
        }

        Self {
            clients,
            active_key,
            global_required_scopes,
            warnings,
        }
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn descriptors(&self) -> Vec<OAuthClientDescriptor> {
        self.clients
            .iter()
            .map(|c| OAuthClientDescriptor {
                key: c.key.clone(),
                label: c.label.clone(),
                client_id: c.client_id.clone(),
                is_active: c.key == self.active_key,
                is_builtin: c.is_builtin,
                request_scopes: c.request_scopes.clone(),
                required_scopes: c.required_scopes.clone(),
            })
            .collect()
    }

    pub fn get(&self, key: &str) -> Option<&OAuthClientConfig> {
        let norm = normalize_client_key(key);
        self.clients.iter().find(|c| c.key == norm)
    }

    /// Return missing required OAuth scopes when `token.granted_scopes` is known (`Some(...)`).
    /// Per Blueprint §4.1 rule 3: when `granted_scopes` is `None` (`scopes_known == false`),
    /// returns empty Vec without falsely assuming either presence or absence locally.
    pub fn missing_required_scopes(&self, token: &TokenRecord) -> Vec<String> {
        let Some(ref granted) = token.granted_scopes else {
            return Vec::new();
        };
        let required = token
            .oauth_client_key
            .as_deref()
            .and_then(|k| self.get(k))
            .map(|c| c.required_scopes.as_slice())
            .unwrap_or(self.global_required_scopes.as_slice());

        required
            .iter()
            .filter(|req| !scope_list_satisfies(granted, req))
            .cloned()
            .collect()
    }

    /// Strict selection for `auth login` / `auth reauthorize`: uses explicit `--client` or active client.
    /// Never echoes unrecognized `--client` user input back into errors in case a secret was pasted by mistake.
    pub fn select_for_login(&self, requested_key: Option<&str>) -> CliResult<OAuthClientConfig> {
        if let Some(key) = requested_key {
            return self.get(key).cloned().ok_or_else(|| {
                CliError::auth(
                    "unknown_oauth_client",
                    "Specified OAuth client key is not registered. Run `agy-switch-cli auth clients` to inspect registered keys.",
                )
            });
        }
        self.get(&self.active_key)
            .or_else(|| self.clients.first())
            .cloned()
            .ok_or_else(|| CliError::auth("no_oauth_clients", "No OAuth clients configured."))
    }

    /// Strict lookup for bound token refresh (`token.oauth_client_key == Some(key)`).
    /// Per RFC 6749 & Blueprint §4.3: if the bound client key is not registered locally, fail with exit code 6!
    pub fn require_bound_client(&self, bound_key: &str) -> CliResult<OAuthClientConfig> {
        self.get(bound_key).cloned().ok_or_else(|| {
            CliError::auth(
                "bound_oauth_client_missing",
                format!(
                    "Account token is bound to OAuth client '{}', which is not registered locally. Configure `{OAUTH_CLIENTS_ENV}` or `config.json` before refreshing.",
                    sanitize_key_for_log(bound_key)
                ),
            )
        })
    }

    /// Candidate probe list ONLY for legacy accounts with `oauth_client_key == None`.
    pub fn legacy_probe_candidates(&self) -> Vec<OAuthClientConfig> {
        let mut out = Vec::with_capacity(self.clients.len());
        if let Some(active) = self.get(&self.active_key) {
            out.push(active.clone());
        }
        for c in &self.clients {
            if !out.iter().any(|existing| existing.key == c.key) {
                out.push(c.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::config::OAuthClientFileEntry;

    #[test]
    fn malformed_env_and_config_entries_never_leak_client_secrets_in_warnings() {
        let file_cfg = OAuthFileConfig {
            active_client_key: Some("cfg_client".into()),
            required_scopes: Some(vec![
                "openid".into(),
                "https://www.googleapis.com/auth/cloud-platform".into(),
            ]),
            clients: vec![
                OAuthClientFileEntry {
                    key: "bad_cfg".into(),
                    client_id: String::new(),
                    client_secret: "GOCSPX_CFG_BAD_SECRET_777".into(),
                    label: None,
                    request_scopes: None,
                    required_scopes: None,
                },
                OAuthClientFileEntry {
                    key: "cfg_client".into(),
                    client_id: "cid_cfg".into(),
                    client_secret: "GOCSPX_CFG_GOOD_SECRET_888".into(),
                    label: Some("Config Client".into()),
                    request_scopes: None,
                    required_scopes: None,
                },
            ],
        };
        let raw = "bad_entry_with_GOCSPX_SUPER_SECRET_123;GOCSPX-DirectSecret999;mykey|cid|   ;good|cid_ok|GOCSPX_TOP_SECRET_999|Custom";
        let reg = OAuthClientRegistry::from_config_and_raw(
            Some(&file_cfg),
            Some(raw),
            Some("GOCSPX-MissingActiveSecret"),
            None,
            Vec::new(),
        );
        assert!(reg.get("good").is_some());
        assert!(reg.get("cfg_client").is_some());
        for w in reg.warnings() {
            let lower = w.to_ascii_lowercase();
            assert!(!lower.contains("super_secret"), "Leaked in warning: {w}");
            assert!(!lower.contains("directsecret"), "Leaked in warning: {w}");
            assert!(
                !lower.contains("missingactivesecret"),
                "Leaked in warning: {w}"
            );
            assert!(!lower.contains("top_secret"), "Leaked in warning: {w}");
            assert!(!lower.contains("cfg_bad_secret"), "Leaked in warning: {w}");
            assert!(!lower.contains("cfg_good_secret"), "Leaked in warning: {w}");
        }
        let err = reg
            .select_for_login(Some("GOCSPX-AccidentalFlagSecret12345"))
            .unwrap_err();
        assert!(
            !err.message
                .to_ascii_lowercase()
                .contains("accidentalflagsecret"),
            "Leaked in select_for_login error: {}",
            err.message
        );
        let dbg = format!("{:?}", reg.get("good").unwrap());
        assert!(!dbg.contains("TOP_SECRET"));
    }
}
