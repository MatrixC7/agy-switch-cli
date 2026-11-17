use crate::domain::account::STORE_SCHEMA_VERSION;
use crate::paths::HeadlessPaths;
use crate::store::fs_atomic::{
    ensure_no_symlink_components_under, ensure_private_dir, read_regular_file_opt_bounded,
    write_atomic_durable,
};
use crate::transport::client::{HttpRequest, HttpTransport, TimeoutClass};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

/// 1. `agy-switch-cli` own package version (`CARGO_PKG_VERSION`), strictly for `--version` and diagnostics.
pub const CLI_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Verified official `agy` version range from Phase 0 empirical probe (`1.5.7`).
pub const VERIFIED_AGY_VERSIONS: &[&str] = &["1.5.7"];

/// 3. Compile-time floor for `UPSTREAM_UA_VERSION` per Blueprint §6.3.
pub const KNOWN_COMPAT_FLOOR_UA_VERSION: &str = "4.3.0";

pub const REMOTE_UA_VERSION_URL: &str =
    "https://antigravity-auto-updater-974169037036.us-central1.run.app";
pub const UA_CACHE_TTL_SECS: i64 = 86_400; // 24 hours

static VERSION_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d+\.\d+\.\d+").expect("valid semver regex"));

pub fn parse_semver_triplet(text: &str) -> Option<String> {
    VERSION_REGEX.find(text).map(|m| m.as_str().to_string())
}

/// Compare two `X.Y.Z` semantic version strings (`Ordering::Greater` if `v1 > v2`).
pub fn compare_semver(v1: &str, v2: &str) -> Ordering {
    let parse = |v: &str| -> Vec<u32> { v.split('.').filter_map(|s| s.parse().ok()).collect() };
    let p1 = parse(v1);
    let p2 = parse(v2);
    for i in 0..p1.len().max(p2.len()) {
        let a = p1.get(i).copied().unwrap_or(0);
        let b = p2.get(i).copied().unwrap_or(0);
        match a.cmp(&b) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// SemVer upper-bound UA version selector per Blueprint §6.3:
/// returns `max(floor_version, cached_remote_version)` using real `compare_semver`.
pub fn select_ua_version(floor_version: &str, cached_remote_version: Option<&str>) -> String {
    match cached_remote_version {
        Some(remote)
            if parse_semver_triplet(remote).is_some()
                && compare_semver(remote, floor_version).is_gt() =>
        {
            remote.to_string()
        }
        _ => floor_version.to_string(),
    }
}

pub fn format_hub_user_agent_for_target(ua_version: &str, os: &str, arch: &str) -> String {
    let os_type = match os {
        "macos" => "macos",
        "windows" => "windows",
        "linux" => "linux",
        _ => "linux",
    };
    let arch_type = match arch {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    };
    format!("antigravity/hub/{ua_version} (os_type={os_type}; arch={arch_type})")
}

pub fn format_native_oauth_user_agent(ua_version: &str) -> String {
    format_hub_user_agent_for_target(ua_version, std::env::consts::OS, std::env::consts::ARCH)
}

pub const SHORT_FALLBACK_USER_AGENT: &str = "antigravity";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UaVersionCache {
    pub schema_version: u32,
    pub remote_version: String,
    pub fetched_at: i64,
}

pub fn read_cached_ua_version_readonly(paths: &HeadlessPaths, now_unix: i64) -> Option<String> {
    let cache_path = paths.ua_cache_file();
    ensure_no_symlink_components_under(&paths.cache_dir, &cache_path).ok()?;
    let bytes = read_regular_file_opt_bounded(&cache_path, 64 * 1024, "UA cache")
        .ok()
        .flatten()?;
    let cache: UaVersionCache = serde_json::from_slice(&bytes).ok()?;
    if cache.fetched_at <= now_unix + 60 && now_unix - cache.fetched_at <= UA_CACHE_TTL_SECS {
        parse_semver_triplet(&cache.remote_version)
    } else {
        None
    }
}

/// Resolve `NATIVE_OAUTH_USER_AGENT` for network operations.
/// Never blocks fatally; optionally probes remote version if `allow_remote_probe == true` and cache is expired.
pub async fn resolve_native_oauth_user_agent(
    paths: &HeadlessPaths,
    transport: &dyn HttpTransport,
    allow_remote_probe: bool,
    now_unix: i64,
) -> String {
    if let Some(cached) = read_cached_ua_version_readonly(paths, now_unix) {
        let ver = select_ua_version(KNOWN_COMPAT_FLOOR_UA_VERSION, Some(&cached));
        return format_native_oauth_user_agent(&ver);
    }

    if allow_remote_probe {
        let req = HttpRequest::get(REMOTE_UA_VERSION_URL, TimeoutClass::VersionCheck);
        if let Ok(resp) = transport.execute(req).await {
            if (200..300).contains(&resp.status) {
                if let Ok(body_str) = std::str::from_utf8(&resp.body) {
                    if let Some(remote_ver) = parse_semver_triplet(body_str) {
                        if ensure_private_dir(&paths.cache_dir).is_ok() {
                            let cache = UaVersionCache {
                                schema_version: STORE_SCHEMA_VERSION,
                                remote_version: remote_ver.clone(),
                                fetched_at: now_unix,
                            };
                            if let Ok(bytes) = serde_json::to_vec_pretty(&cache) {
                                let _ = write_atomic_durable(&paths.ua_cache_file(), &bytes);
                            }
                        }
                        let ver =
                            select_ua_version(KNOWN_COMPAT_FLOOR_UA_VERSION, Some(&remote_ver));
                        return format_native_oauth_user_agent(&ver);
                    }
                }
            }
        }
    }

    let ver = select_ua_version(KNOWN_COMPAT_FLOOR_UA_VERSION, None);
    format_native_oauth_user_agent(&ver)
}

/// `LOCAL_AGY_VERSION` probe used ONLY when `doctor --verify-agy` is explicitly requested.
///
/// Runs with an isolated empty temporary `HOME` / `XDG_*` / `DBUS_SESSION_BUS_ADDRESS` and 3s timeout,
/// guaranteeing zero access to host user credentials or D-Bus!
pub async fn probe_local_agy_version_isolated() -> Result<(PathBuf, String, bool), String> {
    let bin = resolve_agy_executable()
        .ok_or_else(|| "Official `agy` executable not found in PATH.".to_string())?;
    struct ProbeTempDir(PathBuf);
    impl Drop for ProbeTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let probe_path = std::env::temp_dir().join(format!("agy-probe-{}", uuid::Uuid::new_v4()));
    ensure_private_dir(&probe_path)
        .map_err(|e| format!("Cannot create isolated probe dir: {}", e.message))?;
    let temp = ProbeTempDir(probe_path);
    let run_dir = temp.0.join("run");
    let _ = fs::create_dir_all(&run_dir);

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.arg("--version")
        .env_clear()
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        )
        .env("HOME", &temp.0)
        .env("XDG_CONFIG_HOME", temp.0.join("cfg"))
        .env("XDG_DATA_HOME", temp.0.join("data"))
        .env("XDG_CACHE_HOME", temp.0.join("cache"))
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = tokio::time::timeout(Duration::from_secs(3), cmd.output())
        .await
        .map_err(|_| format!("Timed out running `{} --version`.", bin.display()))?
        .map_err(|e| format!("Failed to execute `{} --version`: {e}", bin.display()))?;

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let version = parse_semver_triplet(&combined).ok_or_else(|| {
        format!(
            "Could not parse version from `{} --version` output.",
            bin.display()
        )
    })?;
    let is_verified = VERIFIED_AGY_VERSIONS.contains(&version.as_str());
    Ok((bin, version, is_verified))
}

pub fn resolve_agy_executable() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("AGY_SWITCH_CLI_AGY_BIN").filter(|v| !v.is_empty()) {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("agy");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_ua_version_computes_true_semver_upper_bound() {
        assert_eq!(select_ua_version("4.3.0", None), "4.3.0");
        // Remote older than floor MUST NOT downgrade floor!
        assert_eq!(select_ua_version("4.3.0", Some("1.15.8")), "4.3.0");
        assert_eq!(select_ua_version("4.3.0", Some("4.2.99")), "4.3.0");
        // Remote newer than floor upgrades UA!
        assert_eq!(select_ua_version("4.3.0", Some("4.10.2")), "4.10.2");
        assert_eq!(
            format_hub_user_agent_for_target(
                &select_ua_version("4.3.0", Some("4.10.2")),
                "linux",
                "x86_64"
            ),
            "antigravity/hub/4.10.2 (os_type=linux; arch=amd64)"
        );
        assert_eq!(
            format_hub_user_agent_for_target("4.3.0", "linux", "aarch64"),
            "antigravity/hub/4.3.0 (os_type=linux; arch=arm64)"
        );
        let native_ua = format_native_oauth_user_agent("4.3.0");
        assert!(native_ua.starts_with("antigravity/hub/4.3.0 (os_type="));
        assert!(native_ua.contains("; arch="));
        assert!(native_ua.ends_with(')'));
    }
}
