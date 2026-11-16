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
        let env_override = std::env::var("AGY_SWITCH_CLI_PROXY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let cfg_proxy = network_cfg
            .and_then(|c| c.proxy_url.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let chosen = cli_proxy
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or(env_override.as_deref())
            .or(cfg_proxy);

        let cfg_no_proxy = network_cfg
            .and_then(|c| c.no_proxy.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let raw_no_proxy = first_non_empty_env(&["NO_PROXY", "no_proxy"]);
        let merged_no_proxy = Some(merge_no_proxy_sources(
            cfg_no_proxy,
            raw_no_proxy.as_deref(),
        ));

        if let Some(spec) = chosen {
            if spec.eq_ignore_ascii_case("direct") || spec.eq_ignore_ascii_case("none") {
                return Ok(Self::Direct);
            }
            validate_proxy_url(spec)?;
            return Ok(Self::Explicit {
                proxy_url: spec.to_string(),
                no_proxy: merged_no_proxy,
            });
        }

        let https_proxy = first_non_empty_env(&["HTTPS_PROXY", "https_proxy"]);
        let http_proxy = first_non_empty_env(&["HTTP_PROXY", "http_proxy"]);
        let all_proxy = first_non_empty_env(&["ALL_PROXY", "all_proxy"]);

        for p in [&https_proxy, &http_proxy, &all_proxy]
            .into_iter()
            .flatten()
        {
            validate_proxy_url(p)?;
        }

        if https_proxy.is_none() && http_proxy.is_none() && all_proxy.is_none() {
            return Ok(Self::Direct);
        }

        Ok(Self::FromEnv {
            https_proxy,
            http_proxy,
            all_proxy,
            no_proxy: merged_no_proxy,
        })
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

pub fn validate_proxy_url(raw: &str) -> CliResult<Url> {
    let parsed = Url::parse(raw.trim()).map_err(|_| {
        CliError::usage(
            "Invalid proxy URL format. Supported schemes: http://, https://, socks5://, socks5h://, or `direct`.",
        )
    })?;
    match parsed.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        _ => {
            return Err(CliError::usage(
                "Unsupported proxy scheme. Supported schemes: http, https, socks5, socks5h, or `direct`.",
            ));
        }
    }
    if parsed.host_str().is_none() {
        return Err(CliError::usage("Proxy URL is missing a host."));
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

fn first_non_empty_env(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(val) = std::env::var(name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
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
}
