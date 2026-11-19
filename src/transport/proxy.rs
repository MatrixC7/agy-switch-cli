use crate::domain::config::{redact_proxy_url_for_debug, NetworkConfig};
use crate::error::{CliError, CliResult};
use std::fmt;
use url::Url;

/// Parsed headless proxy routing configuration per Blueprint §6.2.
#[derive(Clone, PartialEq, Eq)]
pub enum ProxyMode {
    /// `--proxy direct`: force direct connection, ignoring all proxy env vars.
    Direct,
    /// Explicit proxy URL (`http://`, `https://`, `socks5://`, `socks5h://`) + `NO_PROXY` bypass rules.
    Explicit {
        proxy_url: String,
        no_proxy: Option<String>,
    },
    /// Standard Linux headless environment variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`).
    FromEnv {
        https_proxy: Option<String>,
        http_proxy: Option<String>,
        all_proxy: Option<String>,
        no_proxy: Option<String>,
    },
}

impl fmt::Debug for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::Explicit {
                proxy_url,
                no_proxy,
            } => f
                .debug_struct("Explicit")
                .field("proxy_url", &redact_proxy_url_for_debug(proxy_url))
                .field("no_proxy", no_proxy)
                .finish(),
            Self::FromEnv {
                https_proxy,
                http_proxy,
                all_proxy,
                no_proxy,
            } => f
                .debug_struct("FromEnv")
                .field(
                    "https_proxy",
                    &https_proxy.as_deref().map(redact_proxy_url_for_debug),
                )
                .field(
                    "http_proxy",
                    &http_proxy.as_deref().map(redact_proxy_url_for_debug),
                )
                .field(
                    "all_proxy",
                    &all_proxy.as_deref().map(redact_proxy_url_for_debug),
                )
                .field("no_proxy", no_proxy)
                .finish(),
        }
    }
}

const LOOPBACK_BYPASS: &str = "127.0.0.1,localhost,::1,[::1]";

impl ProxyMode {
    pub fn resolve(cli_proxy: Option<&str>) -> CliResult<Self> {
        Self::resolve_with_config(cli_proxy, None)
    }

    pub fn resolve_with_config(
        cli_proxy: Option<&str>,
        network_cfg: Option<&NetworkConfig>,
    ) -> CliResult<Self> {
        let (mode, _) = Self::resolve_with_config_and_warnings(cli_proxy, network_cfg)?;
        Ok(mode)
    }

    /// Resolve proxy mode and collect secret-free warnings (containing ONLY literal environment
    /// variable names) when malformed ambient proxy variables are ignored.
    pub fn resolve_with_config_and_warnings(
        cli_proxy: Option<&str>,
        network_cfg: Option<&NetworkConfig>,
    ) -> CliResult<(Self, Vec<String>)> {
        let env_override = std::env::var("AGY_SWITCH_CLI_PROXY")
            .ok()
            .map(|s| strip_matching_quotes(s.trim()).to_string())
            .filter(|s| !s.is_empty());
        let cfg_proxy = network_cfg
            .and_then(|c| c.proxy_url.as_deref())
            .map(|s| strip_matching_quotes(s.trim()))
            .filter(|s| !s.is_empty());
        let cli_clean = cli_proxy
            .map(|s| strip_matching_quotes(s.trim()))
            .filter(|s| !s.is_empty());

        let explicit_choice: Option<(&str, &str)> = if let Some(c) = cli_clean {
            Some((c, "`--proxy`"))
        } else if let Some(ref e) = env_override {
            Some((e.as_str(), "`AGY_SWITCH_CLI_PROXY`"))
        } else {
            cfg_proxy.map(|c| (c, "`config.json` (`network.proxy_url`)"))
        };

        let cfg_no_proxy = network_cfg
            .and_then(|c| c.no_proxy.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let raw_no_proxy = first_non_empty_env(&["NO_PROXY", "no_proxy"]).map(|(_, v)| v);
        let merged_no_proxy = Some(merge_no_proxy_sources(
            cfg_no_proxy,
            raw_no_proxy.as_deref(),
        ));

        if let Some((spec, source_name)) = explicit_choice {
            if is_direct_keyword(spec) {
                return Ok((Self::Direct, Vec::new()));
            }
            let normalized = normalize_proxy_url(spec);
            validate_proxy_url_for_source(&normalized, Some(source_name))?;
            return Ok((
                Self::Explicit {
                    proxy_url: normalized,
                    no_proxy: merged_no_proxy,
                },
                Vec::new(),
            ));
        }

        let mut warnings = Vec::new();
        let https_proxy = resolve_ambient_proxy_env(&["HTTPS_PROXY", "https_proxy"], &mut warnings);
        let http_proxy = resolve_ambient_proxy_env(&["HTTP_PROXY", "http_proxy"], &mut warnings);
        let all_proxy = resolve_ambient_proxy_env(&["ALL_PROXY", "all_proxy"], &mut warnings);

        if https_proxy.is_none() && http_proxy.is_none() && all_proxy.is_none() {
            return Ok((Self::Direct, warnings));
        }

        Ok((
            Self::FromEnv {
                https_proxy,
                http_proxy,
                all_proxy,
                no_proxy: merged_no_proxy,
            },
            warnings,
        ))
    }

    /// Determine whether `target_url` must bypass external proxies (loopback or matching `NO_PROXY`).
    pub fn should_bypass(&self, target_url: &Url) -> bool {
        if is_loopback_url(target_url) {
            return true;
        }
        let no_proxy_str = match self {
            Self::Direct => return true,
            Self::Explicit { no_proxy, .. } | Self::FromEnv { no_proxy, .. } => {
                no_proxy.as_deref().unwrap_or(LOOPBACK_BYPASS)
            }
        };
        host_matches_no_proxy(target_url, no_proxy_str)
    }
}

fn is_direct_keyword(raw: &str) -> bool {
    raw.eq_ignore_ascii_case("direct") || raw.eq_ignore_ascii_case("none")
}

fn strip_matching_quotes(raw: &str) -> &str {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        raw[1..raw.len() - 1].trim()
    } else {
        raw
    }
}

/// Normalize common Linux / desktop proxy string formats into canonical `reqwest`-compatible URLs:
/// - Strips surrounding whitespace and matching outer single/double quotes;
/// - Rewrites KDE-style space-separated port (`http://127.0.0.1 2080` -> `http://127.0.0.1:2080`);
/// - Maps `socks://` alias to `socks5h://` (remote DNS over SOCKS5);
/// - Prepends `http://` to scheme-less `host:port` / `localhost:port` / `[::1]:port` specifications.
pub fn normalize_proxy_url(raw: &str) -> String {
    let unquoted = strip_matching_quotes(raw.trim());
    if unquoted.is_empty() || is_direct_keyword(unquoted) {
        return unquoted.to_string();
    }

    let (scheme_prefix, rest) = match unquoted.find("://") {
        Some(idx) => (&unquoted[..idx + 3], &unquoted[idx + 3..]),
        None => ("", unquoted),
    };

    // Convert trailing space-separated port (`host 2080`) when no path/query/fragment is present
    let rest_no_trailing_slash = rest.trim_end_matches('/');
    let host_port_fixed = if !rest_no_trailing_slash.contains(['/', '?', '#']) {
        if let Some((host_part, port_part)) =
            rest_no_trailing_slash.rsplit_once(char::is_whitespace)
        {
            let host_trimmed = host_part.trim();
            let port_trimmed = port_part.trim();
            if !host_trimmed.is_empty()
                && !host_trimmed.contains(char::is_whitespace)
                && port_trimmed.parse::<u16>().is_ok_and(|p| p > 0)
            {
                format!("{host_trimmed}:{port_trimmed}")
            } else {
                rest.to_string()
            }
        } else {
            rest.to_string()
        }
    } else {
        rest.to_string()
    };

    let with_scheme = if scheme_prefix.is_empty() {
        let candidate = host_port_fixed.trim_end_matches('/');
        if !candidate.contains(['/', '?', '#']) {
            if let Some((host_or_auth, port_str)) = candidate.rsplit_once(':') {
                if !host_or_auth.is_empty() && port_str.parse::<u16>().is_ok_and(|p| p > 0) {
                    format!("http://{candidate}")
                } else {
                    host_port_fixed
                }
            } else {
                host_port_fixed
            }
        } else {
            host_port_fixed
        }
    } else if scheme_prefix.eq_ignore_ascii_case("socks://") {
        format!("socks5h://{host_port_fixed}")
    } else {
        format!("{scheme_prefix}{host_port_fixed}")
    };

    with_scheme
}

fn resolve_ambient_proxy_env(names: &[&'static str], warnings: &mut Vec<String>) -> Option<String> {
    let (var_name, raw_val) = first_non_empty_env(names)?;
    let unquoted = strip_matching_quotes(&raw_val);
    if unquoted.is_empty() || is_direct_keyword(unquoted) {
        return None;
    }
    let normalized = normalize_proxy_url(unquoted);
    match validate_proxy_url(&normalized) {
        Ok(_) => Some(normalized),
        Err(_) => {
            tracing::warn!(
                env_var = var_name,
                "Ignoring unsupported or malformed proxy URL in ambient environment variable"
            );
            warnings.push(format!(
                "Ignored unsupported or malformed proxy URL in `{var_name}` environment variable."
            ));
            None
        }
    }
}

pub fn validate_proxy_url(raw: &str) -> CliResult<Url> {
    validate_proxy_url_for_source(raw, None)
}

fn validate_proxy_url_for_source(raw: &str, source_name: Option<&str>) -> CliResult<Url> {
    let ctx = source_name.map(|s| format!(" in {s}")).unwrap_or_default();
    let parsed = Url::parse(raw.trim()).map_err(|_| {
        CliError::usage(format!(
            "Invalid proxy URL format{ctx}. Supported formats: http://host:port, https://host:port, socks5://host:port, socks5h://host:port, host:port, or `direct`."
        ))
    })?;
    match parsed.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        _ => {
            return Err(CliError::usage(format!(
                "Unsupported proxy scheme{ctx}. Supported schemes: http, https, socks5, socks5h (or socks), or `direct`."
            )));
        }
    }
    if parsed.host_str().is_none() {
        return Err(CliError::usage(format!(
            "Proxy URL{ctx} is missing a host."
        )));
    }
    Ok(parsed)
}

pub fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

pub fn host_matches_no_proxy(url: &Url, no_proxy: &str) -> bool {
    let Some(raw_host) = url.host_str() else {
        return false;
    };
    let host = raw_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let port = url.port_or_known_default();

    for rule in no_proxy.split(',') {
        let rule = rule.trim().to_ascii_lowercase();
        if rule.is_empty() {
            continue;
        }
        if rule == "*" {
            return true;
        }
        let (rule_host, rule_port) = if let Some(stripped) = rule.strip_prefix('[') {
            if let Some((h, rest)) = stripped.split_once(']') {
                let p = rest.strip_prefix(':').and_then(|ps| ps.parse::<u16>().ok());
                (h, p)
            } else {
                (rule.as_str(), None)
            }
        } else if rule.matches(':').count() == 1 {
            if let Some((h, ps)) = rule.rsplit_once(':') {
                if let Ok(p) = ps.parse::<u16>() {
                    (h, Some(p))
                } else {
                    (rule.as_str(), None)
                }
            } else {
                (rule.as_str(), None)
            }
        } else {
            (rule.as_str(), None)
        };

        if let Some(rp) = rule_port {
            if port != Some(rp) {
                continue;
            }
        }

        let trimmed_rule = rule_host.trim_start_matches('.');
        if host == trimmed_rule || host.ends_with(&format!(".{trimmed_rule}")) {
            return true;
        }
    }
    false
}

fn merge_no_proxy_sources(cfg_no_proxy: Option<&str>, env_no_proxy: Option<&str>) -> String {
    let mut parts = Vec::with_capacity(3);
    if let Some(c) = cfg_no_proxy.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(c);
    }
    if let Some(e) = env_no_proxy.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(e);
    }
    parts.push(LOOPBACK_BYPASS);
    parts.join(",")
}

fn first_non_empty_env<'a>(names: &'a [&'a str]) -> Option<(&'a str, String)> {
    for &name in names {
        if let Ok(val) = std::env::var(name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some((name, trimmed.to_string()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_schemes_including_socks5h_and_enforces_loopback_bypass() {
        assert!(validate_proxy_url("socks5h://127.0.0.1:1080").is_ok());
        assert!(validate_proxy_url("socks5://proxy.example.com:1080").is_ok());
        assert!(validate_proxy_url("http://proxy.example.com:8080").is_ok());
        assert!(validate_proxy_url("https://proxy.example.com:8443").is_ok());
        assert!(validate_proxy_url("ftp://proxy.example.com:21").is_err());

        let mode = ProxyMode::Explicit {
            proxy_url: "socks5h://10.0.0.2:1080".into(),
            no_proxy: Some("internal.corp,127.0.0.1,localhost,::1".into()),
        };
        assert!(mode.should_bypass(&Url::parse("http://127.0.0.1:43210/oauth-callback").unwrap()));
        assert!(mode.should_bypass(&Url::parse("http://localhost:8080/oauth-callback").unwrap()));
        assert!(mode.should_bypass(&Url::parse("http://[::1]:8080/oauth-callback").unwrap()));
        assert!(mode.should_bypass(&Url::parse("https://api.internal.corp/v1").unwrap()));
        assert!(!mode.should_bypass(&Url::parse("https://oauth2.googleapis.com/token").unwrap()));
    }

    #[test]
    fn normalizes_bare_host_port_space_ports_socks_alias_and_quotes() {
        assert_eq!(
            normalize_proxy_url("127.0.0.1:2080"),
            "http://127.0.0.1:2080"
        );
        assert_eq!(
            normalize_proxy_url("localhost:2080"),
            "http://localhost:2080"
        );
        assert_eq!(normalize_proxy_url("[::1]:2080"), "http://[::1]:2080");
        assert_eq!(
            normalize_proxy_url("http://127.0.0.1 2080"),
            "http://127.0.0.1:2080"
        );
        assert_eq!(
            normalize_proxy_url("socks://127.0.0.1 2080"),
            "socks5h://127.0.0.1:2080"
        );
        assert_eq!(
            normalize_proxy_url("'socks://127.0.0.1:2080'"),
            "socks5h://127.0.0.1:2080"
        );
        assert_eq!(
            normalize_proxy_url("\"http://127.0.0.1:7890\""),
            "http://127.0.0.1:7890"
        );

        // Explicit typos without port must still fail validation cleanly
        assert!(ProxyMode::resolve_with_config(Some("directt"), None).is_err());
        assert!(ProxyMode::resolve_with_config(Some("ftp://127.0.0.1:21"), None).is_err());

        // Explicit bare host:port and socks:// succeed
        assert_eq!(
            ProxyMode::resolve_with_config(Some("127.0.0.1:2080"), None).unwrap(),
            ProxyMode::Explicit {
                proxy_url: "http://127.0.0.1:2080".into(),
                no_proxy: Some(merge_no_proxy_sources(
                    None,
                    first_non_empty_env(&["NO_PROXY", "no_proxy"])
                        .map(|(_, v)| v)
                        .as_deref()
                )),
            }
        );
    }
}
