use crate::domain::account::STORE_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

fn default_config_schema_version() -> u32 {
    STORE_SCHEMA_VERSION
}

/// Optional store-scoped configuration (`<data_dir>/config.json`, `schema_version: 1`)
/// supporting Blueprint §6.2 item 1 (`network.proxy_url`) and §4.3 item 1 (OAuth client extensions).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadlessConfig {
    #[serde(default = "default_config_schema_version")]
    pub schema_version: u32,
    /// Optional credential backend preference (`auto`, `dual`, `file`, or `keyring`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub oauth: OAuthFileConfig,
}

impl Default for HeadlessConfig {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            backend: None,
            network: NetworkConfig::default(),
            oauth: OAuthFileConfig::default(),
        }
    }
}

fn sanitize_backend_for_debug(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => "auto",
        "dual" => "dual",
        "file" => "file",
        "keyring" => "keyring",
        _ => "[INVALID_BACKEND]",
    }
}

impl fmt::Debug for HeadlessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let safe_backend = self.backend.as_deref().map(sanitize_backend_for_debug);
        f.debug_struct("HeadlessConfig")
            .field("schema_version", &self.schema_version)
            .field("backend", &safe_backend)
            .field("network", &self.network)
            .field("oauth", &self.oauth)
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Proxy URL (`http://`, `https://`, `socks5://`, `socks5h://`, or `direct`) per Blueprint §6.2 item 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Optional comma-separated `NO_PROXY` bypass host rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,
}

impl fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let safe_proxy = self.proxy_url.as_deref().map(redact_proxy_url_for_debug);
        f.debug_struct("NetworkConfig")
            .field("proxy_url", &safe_proxy)
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthFileConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_client_key: Option<String>,
    /// Optional required OAuth scopes enforced when `TokenRecord::granted_scopes` is known (`Some(...)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<OAuthClientFileEntry>,
}

impl fmt::Debug for OAuthFileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthFileConfig")
            .field("active_client_key", &self.active_client_key)
            .field("required_scopes", &self.required_scopes)
            .field("clients", &self.clients)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthClientFileEntry {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scopes: Option<Vec<String>>,
}

impl fmt::Debug for OAuthClientFileEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthClientFileEntry")
            .field("key", &self.key)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("label", &self.label)
            .field("request_scopes", &self.request_scopes)
            .field("required_scopes", &self.required_scopes)
            .finish()
    }
}

pub fn redact_proxy_url_for_debug(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("direct")
        || trimmed.eq_ignore_ascii_case("none")
    {
        return trimmed.to_string();
    }
    if let Ok(mut parsed) = Url::parse(trimmed) {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            let _ = parsed.set_username("REDACTED");
            let _ = parsed.set_password(None);
        }
        parsed.set_query(None);
        parsed.set_fragment(None);
        return parsed.to_string();
    }
    "[REDACTED_PROXY_URL]".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_debug_redacts_client_secrets_and_proxy_credentials() {
        let cfg = HeadlessConfig {
            schema_version: 1,
            backend: Some("auto".into()),
            network: NetworkConfig {
                proxy_url: Some("socks5h://proxyuser:PROXY_PASS_SECRET@127.0.0.1:1080".into()),
                no_proxy: Some("internal.corp".into()),
            },
            oauth: OAuthFileConfig {
                active_client_key: Some("custom".into()),
                required_scopes: Some(vec!["openid".into()]),
                clients: vec![OAuthClientFileEntry {
                    key: "custom".into(),
                    client_id: "cid".into(),
                    client_secret: "GOCSPX-CONFIG_SECRET_999".into(),
                    label: Some("Custom".into()),
                    request_scopes: None,
                    required_scopes: None,
                }],
            },
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("PROXY_PASS_SECRET"));
        assert!(!dbg.contains("CONFIG_SECRET_999"));
        assert!(dbg.contains("[REDACTED]"));
    }
}
