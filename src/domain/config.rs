use crate::domain::account::STORE_SCHEMA_VERSION;
use crate::error::{
    has_explicit_secret_marker, path_looks_like_accidental_secret, CliError, CliResult,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use url::Url;

pub const OFFICIAL_TOKEN_FILENAME: &str = "antigravity-oauth-token";

fn default_config_schema_version() -> u32 {
    STORE_SCHEMA_VERSION
}

/// Optional store-scoped configuration (`<data_dir>/config.json`, `schema_version: 1`)
/// supporting Blueprint §6.2 item 1 (`network.proxy_url`), §4.3 item 1 (OAuth client extensions),
/// and named external target application data directories (`targets.<NAME>` -> `.../antigravity-acp`).
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
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub oauth: OAuthFileConfig,
    /// Optional named external target application data directory aliases (`NAME -> /abs/or/~/.../antigravity-acp`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub targets: BTreeMap<String, String>,
}

impl Default for HeadlessConfig {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            backend: None,
            network: NetworkConfig::default(),
            notifications: NotificationsConfig::default(),
            oauth: OAuthFileConfig::default(),
            targets: BTreeMap::new(),
        }
    }
}

pub(crate) fn target_name_looks_like_secret(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    if has_explicit_secret_marker(trimmed) || trimmed.contains("://") {
        return true;
    }
    if trimmed.len() >= 28
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'='))
    {
        let has_upper = trimmed.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = trimmed.bytes().any(|b| b.is_ascii_lowercase());
        let has_digit = trimmed.bytes().any(|b| b.is_ascii_digit());
        if has_upper && has_lower && has_digit {
            return true;
        }
    }
    false
}

pub fn is_valid_target_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 64
        || name.eq_ignore_ascii_case("default")
        || target_name_looks_like_secret(name)
    {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub fn validate_target_config_entry(
    config_path: &Path,
    name: &str,
    raw_path: &str,
) -> CliResult<()> {
    if !is_valid_target_name(name) {
        return Err(CliError::data(format!(
            "Invalid `targets` alias name in '{}'. Names must be 1..=64 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._-]*`, must not be `default`, and must not resemble a credential value.",
            config_path.display()
        )));
    }
    if raw_path.trim().is_empty()
        || raw_path.chars().any(|c| c.is_control())
        || raw_path.contains('\0')
    {
        return Err(CliError::data(format!(
            "Invalid path for `targets.{name}` in '{}': path must be non-empty and must not contain control characters.",
            config_path.display()
        )));
    }
    let path_obj = Path::new(raw_path);
    if path_looks_like_accidental_secret(path_obj) {
        return Err(CliError::data(format!(
            "Invalid path for `targets.{name}` in '{}': expected a filesystem directory path, not a literal credential value (redacted).",
            config_path.display()
        )));
    }
    if !raw_path.starts_with('/') && !raw_path.starts_with("~/") {
        return Err(CliError::data(format!(
            "Invalid path for `targets.{name}` in '{}': target directory path must be an absolute path or start with `~/`.",
            config_path.display()
        )));
    }
    let trimmed_dir = raw_path.trim_end_matches('/');
    if trimmed_dir.is_empty() || trimmed_dir == "~" {
        return Err(CliError::data(format!(
            "Invalid path for `targets.{name}` in '{}': target directory path cannot be root `/` or bare `~/`.",
            config_path.display()
        )));
    }
    if Path::new(trimmed_dir).file_name() == Some(OsStr::new(OFFICIAL_TOKEN_FILENAME)) {
        return Err(CliError::data(format!(
            "Invalid path for `targets.{name}` in '{}': target path must be the directory containing `{OFFICIAL_TOKEN_FILENAME}` (and `conversations/`), not the file path itself; remove the trailing `/{OFFICIAL_TOKEN_FILENAME}`.",
            config_path.display()
        )));
    }
    Ok(())
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
            .field("notifications", &self.notifications)
            .field("oauth", &self.oauth)
            .field("targets_count", &self.targets.len())
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct NotificationsConfig {
    /// Enable or disable Linux desktop notifications (`org.freedesktop.Notifications`) for `daemon`.
    /// Defaults to `true` when omitted (auto-skips silently on headless systems).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Keep `Account Switched` desktop notifications on screen until manually dismissed (`expire_timeout = 0`).
    /// Defaults to `true` when omitted; set to `false` to use the desktop's default auto-dismiss timeout (`-1`).
    /// `Auto-Switch Paused` alerts always remain persistent (`expire_timeout = 0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent: Option<bool>,
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
            notifications: NotificationsConfig {
                enabled: Some(false),
                persistent: Some(true),
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
            targets: BTreeMap::from([
                (
                    "t3".to_string(),
                    "~/.t3/userdata/providers/antigravity/test/antigravity-acp".to_string(),
                ),
                (
                    "GOCSPX-UNVALIDATED_KEY_SECRET_999".to_string(),
                    "1//0gUNVALIDATED_VAL_SECRET_999".to_string(),
                ),
            ]),
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("PROXY_PASS_SECRET"));
        assert!(!dbg.contains("CONFIG_SECRET_999"));
        assert!(!dbg.contains("UNVALIDATED_KEY_SECRET_999"));
        assert!(!dbg.contains("UNVALIDATED_VAL_SECRET_999"));
        assert!(!dbg.contains("antigravity-acp"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("targets_count: 2"));
    }

    #[test]
    fn config_targets_validation_enforces_name_prefix_and_directory_contract() {
        let cfg_path = Path::new("/tmp/config.json");
        assert!(validate_target_config_entry(
            cfg_path,
            "t3",
            "~/.t3/userdata/providers/antigravity/abc/antigravity-acp"
        )
        .is_ok());
        assert!(validate_target_config_entry(
            cfg_path,
            "t3_work-2.acp",
            "/var/lib/custom/antigravity-acp/"
        )
        .is_ok());

        // Reserved, invalid, or secret-like target names (never echoed)
        assert!(
            validate_target_config_entry(cfg_path, "default", "/tmp/x/antigravity-acp").is_err()
        );
        assert!(validate_target_config_entry(cfg_path, "-bad", "/tmp/x/antigravity-acp").is_err());
        assert!(
            validate_target_config_entry(cfg_path, "has space", "/tmp/x/antigravity-acp").is_err()
        );
        let secret_key_err = validate_target_config_entry(
            cfg_path,
            "GOCSPX-SYNTHETIC_KEY_SECRET_777",
            "/tmp/x/antigravity-acp",
        )
        .unwrap_err();
        assert!(!secret_key_err.message.contains("SYNTHETIC_KEY_SECRET_777"));

        // Relative path, literal bare root/home, literal token file path, or secret-like literal rejected
        assert!(validate_target_config_entry(cfg_path, "t3", "relative/antigravity-acp").is_err());
        assert!(validate_target_config_entry(cfg_path, "t3", "/").is_err());
        assert!(validate_target_config_entry(cfg_path, "t3", "~/").is_err());
        assert!(validate_target_config_entry(
            cfg_path,
            "t3",
            "~/.t3/userdata/providers/antigravity/abc/antigravity-acp/antigravity-oauth-token"
        )
        .is_err());
        let secret_err = validate_target_config_entry(
            cfg_path,
            "t3",
            "1//0gFAKE_REFRESH_TOKEN_VALUE_1234567890",
        )
        .unwrap_err();
        assert!(!secret_err.message.contains("FAKE_REFRESH_TOKEN_VALUE"));
    }

    #[test]
    fn config_notifications_deserializes_explicit_and_defaults_to_none() {
        let legacy: HeadlessConfig = serde_json::from_str(r#"{"schema_version":1}"#).unwrap();
        assert_eq!(legacy.notifications.enabled, None);
        assert_eq!(legacy.notifications.persistent, None);

        let disabled: HeadlessConfig =
            serde_json::from_str(r#"{"schema_version":1,"notifications":{"enabled":false}}"#)
                .unwrap();
        assert_eq!(disabled.notifications.enabled, Some(false));
        assert_eq!(disabled.notifications.persistent, None);

        let enabled: HeadlessConfig =
            serde_json::from_str(r#"{"schema_version":1,"notifications":{"enabled":true}}"#)
                .unwrap();
        assert_eq!(enabled.notifications.enabled, Some(true));
        assert_eq!(enabled.notifications.persistent, None);

        let auto_dismiss: HeadlessConfig = serde_json::from_str(
            r#"{"schema_version":1,"notifications":{"enabled":true,"persistent":false}}"#,
        )
        .unwrap();
        assert_eq!(auto_dismiss.notifications.enabled, Some(true));
        assert_eq!(auto_dismiss.notifications.persistent, Some(false));

        let persistent_explicit: HeadlessConfig =
            serde_json::from_str(r#"{"schema_version":1,"notifications":{"persistent":true}}"#)
                .unwrap();
        assert_eq!(persistent_explicit.notifications.enabled, None);
        assert_eq!(persistent_explicit.notifications.persistent, Some(true));
    }
}
