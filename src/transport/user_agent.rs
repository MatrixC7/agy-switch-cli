use crate::store::fs_atomic::ensure_private_dir;
use regex::Regex;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

/// `agy-switch-cli` own package version (`CARGO_PKG_VERSION`), strictly for `--version` and diagnostics.
pub const CLI_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

static VERSION_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d+\.\d+\.\d+").expect("valid semver regex"));

pub fn parse_semver_triplet(text: &str) -> Option<String> {
    VERSION_REGEX.find(text).map(|m| m.as_str().to_string())
}

#[derive(Debug, Clone)]
pub enum LocalAgyProbeOutcome {
    NotFound,
    Detected {
        executable: PathBuf,
        version: String,
    },
    Failed {
        executable: PathBuf,
        error: String,
    },
}

/// `LOCAL_AGY_VERSION` probe used by `agy-switch-cli status`.
///
/// Runs the local `agy` executable in its own process group (`process_group(0)`) with isolated
/// environment variables (`HOME`, `XDG_*`, `TMPDIR`, `DBUS_SESSION_BUS_ADDRESS`, `NO_PROXY=*`),
/// an empty private temporary directory, bounded output capture, and a 3s timeout; on timeout,
/// drop, or completion, sends `SIGKILL` to the entire child process group (`-pgid`) and reaps the
/// direct child so derived helper processes cannot outlive the probe.
/// Note: this provides environment/temp-dir/process-group isolation for the local `agy` binary,
/// not an OS-level namespace/filesystem/network container against arbitrary untrusted binaries.
pub async fn probe_local_agy_for_status() -> LocalAgyProbeOutcome {
    use tokio::io::AsyncReadExt;

    const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;

    let Some(bin) = resolve_agy_executable() else {
        return LocalAgyProbeOutcome::NotFound;
    };
    struct ProbeTempDir(PathBuf);
    impl Drop for ProbeTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct ProcessGroupKillGuard(Option<u32>);
    impl ProcessGroupKillGuard {
        fn kill_group_now(&self) {
            if let Some(pid) = self.0 {
                if pid > 1 {
                    unsafe {
                        let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                    }
                }
            }
        }
        fn disarm(&mut self) {
            self.0 = None;
        }
    }
    impl Drop for ProcessGroupKillGuard {
        fn drop(&mut self) {
            self.kill_group_now();
        }
    }

    let probe_path = std::env::temp_dir().join(format!("agy-probe-{}", uuid::Uuid::new_v4()));
    if let Err(e) = ensure_private_dir(&probe_path) {
        return LocalAgyProbeOutcome::Failed {
            executable: bin,
            error: format!("Cannot create isolated probe dir: {}", e.message),
        };
    }
    let temp = ProbeTempDir(probe_path);
    let run_dir = temp.0.join("run");
    let tmp_dir = temp.0.join("tmp");
    for sub in [&run_dir, &tmp_dir] {
        if let Err(e) = ensure_private_dir(sub) {
            return LocalAgyProbeOutcome::Failed {
                executable: bin,
                error: format!("Cannot create isolated probe subdir: {}", e.message),
            };
        }
    }

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.arg("--version")
        .process_group(0)
        .kill_on_drop(true)
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
        .env("TMPDIR", &tmp_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return LocalAgyProbeOutcome::Failed {
                executable: bin.clone(),
                error: format!("Failed to execute `{} --version`: {e}", bin.display()),
            };
        }
    };
    let mut pgid_guard = ProcessGroupKillGuard(child.id());

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let read_capped = |pipe_opt: Option<tokio::process::ChildStdout>| async move {
        let mut buf = Vec::new();
        if let Some(pipe) = pipe_opt {
            let _ = pipe
                .take(MAX_PROBE_OUTPUT_BYTES as u64)
                .read_to_end(&mut buf)
                .await;
        }
        buf
    };
    let read_capped_err = |pipe_opt: Option<tokio::process::ChildStderr>| async move {
        let mut buf = Vec::new();
        if let Some(pipe) = pipe_opt {
            let _ = pipe
                .take(MAX_PROBE_OUTPUT_BYTES as u64)
                .read_to_end(&mut buf)
                .await;
        }
        buf
    };

    let wait_res = tokio::time::timeout(Duration::from_secs(3), async {
        let (status_res, out_bytes, err_bytes) = tokio::join!(
            child.wait(),
            read_capped(stdout_pipe.take()),
            read_capped_err(stderr_pipe.take())
        );
        (status_res, out_bytes, err_bytes)
    })
    .await;

    let (status, out_bytes, err_bytes) = match wait_res {
        Ok((Ok(st), out_b, err_b)) => {
            // Also terminate any lingering background helpers still in the child process group!
            pgid_guard.kill_group_now();
            pgid_guard.disarm();
            (st, out_b, err_b)
        }
        Ok((Err(e), _, _)) => {
            pgid_guard.kill_group_now();
            let _ = child.wait().await;
            pgid_guard.disarm();
            return LocalAgyProbeOutcome::Failed {
                executable: bin.clone(),
                error: format!("Failed waiting for `{} --version`: {e}", bin.display()),
            };
        }
        Err(_) => {
            pgid_guard.kill_group_now();
            let _ = child.wait().await;
            pgid_guard.disarm();
            return LocalAgyProbeOutcome::Failed {
                executable: bin.clone(),
                error: format!("Timed out running `{} --version`.", bin.display()),
            };
        }
    };

    if !status.success() {
        return LocalAgyProbeOutcome::Failed {
            executable: bin.clone(),
            error: format!(
                "`{} --version` exited with status {}.",
                bin.display(),
                status
            ),
        };
    }

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out_bytes),
        String::from_utf8_lossy(&err_bytes)
    );
    let Some(version) = parse_semver_triplet(&combined) else {
        return LocalAgyProbeOutcome::Failed {
            executable: bin.clone(),
            error: format!(
                "Could not parse version from `{} --version` output.",
                bin.display()
            ),
        };
    };
    LocalAgyProbeOutcome::Detected {
        executable: bin,
        version,
    }
}

pub async fn probe_local_agy_version_isolated() -> Result<(PathBuf, String), String> {
    match probe_local_agy_for_status().await {
        LocalAgyProbeOutcome::Detected {
            executable,
            version,
        } => Ok((executable, version)),
        LocalAgyProbeOutcome::NotFound => {
            Err("Official `agy` executable not found in PATH.".to_string())
        }
        LocalAgyProbeOutcome::Failed { error, .. } => Err(error),
    }
}

pub fn resolve_agy_executable() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("AGY_SWITCH_CLI_AGY_BIN").filter(|v| !v.is_empty()) {
        let p = PathBuf::from(explicit);
        return p.is_file().then_some(p);
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

pub const ANTIGRAVITY_APP_DIR_ENV: &str = "AGY_SWITCH_CLI_ANTIGRAVITY_APP_DIR";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAntigravityAppProbeOutcome {
    NotFound,
    Detected { path: PathBuf, version: String },
}

fn open_regular_file_readonly_nonblock(path: &Path) -> Option<(fs::File, u64)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some((file, meta.len()))
}

fn read_json_object_bounded(path: &Path, max_bytes: u64) -> Option<serde_json::Value> {
    let (file, len) = open_regular_file_readonly_nonblock(path)?;
    if len == 0 || len > max_bytes {
        return None;
    }
    let mut buf = Vec::with_capacity(len as usize);
    file.take(max_bytes + 1).read_to_end(&mut buf).ok()?;
    if (buf.len() as u64) > max_bytes {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

fn is_antigravity_app_manifest(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    [
        "name",
        "productName",
        "applicationName",
        "nameShort",
        "nameLong",
        "dataFolderName",
    ]
    .iter()
    .any(|key| {
        obj.get(*key)
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.to_ascii_lowercase().contains("antigravity"))
    })
}

fn extract_manifest_semver(val: &serde_json::Value) -> Option<String> {
    let obj = val.as_object()?;
    if !is_antigravity_app_manifest(val) {
        return None;
    }
    for key in ["antigravityVersion", "ideVersion", "version"] {
        if let Some(raw) = obj.get(key).and_then(|v| v.as_str()) {
            if let Some(ver) = parse_semver_triplet(raw) {
                return Some(ver);
            }
        }
    }
    None
}

/// Strictly read-only, bounded ASAR reader extracting `product.json` / `package.json` from an
/// Electron `resources/app.asar` archive without executing the desktop binary.
pub(crate) fn extract_antigravity_version_from_asar(asar_path: &Path) -> Option<String> {
    const MAX_ASAR_HEADER_BYTES: u32 = 8 * 1024 * 1024;
    const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

    let (mut file, file_len) = open_regular_file_readonly_nonblock(asar_path)?;
    if file_len < 16 {
        return None;
    }
    let mut prefix = [0u8; 16];
    file.read_exact(&mut prefix).ok()?;
    let p1 = u32::from_le_bytes(prefix[0..4].try_into().ok()?);
    let header_size = u32::from_le_bytes(prefix[4..8].try_into().ok()?);
    let inner_size = u32::from_le_bytes(prefix[8..12].try_into().ok()?);
    let json_len = u32::from_le_bytes(prefix[12..16].try_into().ok()?);

    if p1 != 4
        || header_size < 8
        || inner_size < 4
        || inner_size > header_size.saturating_sub(4)
        || json_len == 0
        || json_len > inner_size.saturating_sub(4)
        || json_len > MAX_ASAR_HEADER_BYTES
    {
        return None;
    }
    let data_base = 8u64.checked_add(header_size as u64)?;
    if 16u64.checked_add(json_len as u64)? > data_base || data_base > file_len {
        return None;
    }

    let mut hdr_bytes = vec![0u8; json_len as usize];
    file.read_exact(&mut hdr_bytes).ok()?;
    let header_val: serde_json::Value = serde_json::from_slice(&hdr_bytes).ok()?;
    let files = header_val.get("files")?.as_object()?;

    for name in ["product.json", "package.json"] {
        let Some(entry) = files.get(name).and_then(|v| v.as_object()) else {
            continue;
        };
        let Some(size) = entry.get("size").and_then(|v| v.as_u64()) else {
            continue;
        };
        if size == 0 || size > MAX_MANIFEST_BYTES {
            continue;
        }
        let offset = match entry.get("offset") {
            Some(serde_json::Value::String(s)) => s.parse::<u64>().ok(),
            Some(serde_json::Value::Number(n)) => n.as_u64(),
            _ => None,
        };
        let Some(rel_off) = offset else {
            continue;
        };
        let Some(start) = data_base.checked_add(rel_off) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if end > file_len {
            continue;
        }
        if file.seek(SeekFrom::Start(start)).is_err() {
            continue;
        }
        let mut manifest_bytes = vec![0u8; size as usize];
        if file.read_exact(&mut manifest_bytes).is_err() {
            continue;
        }
        if let Ok(manifest_val) = serde_json::from_slice::<serde_json::Value>(&manifest_bytes) {
            if let Some(ver) = extract_manifest_semver(&manifest_val) {
                return Some(ver);
            }
        }
    }
    None
}

pub(crate) fn probe_antigravity_app_install_dir(install_dir: &Path) -> Option<String> {
    const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
    let resources = install_dir.join("resources");
    if let Some(ver) = extract_antigravity_version_from_asar(&resources.join("app.asar")) {
        return Some(ver);
    }
    for rel in ["app/product.json", "app/package.json"] {
        if let Some(val) = read_json_object_bounded(&resources.join(rel), MAX_MANIFEST_BYTES) {
            if let Some(ver) = extract_manifest_semver(&val) {
                return Some(ver);
            }
        }
    }
    None
}

fn display_path_for_install_dir(dir: &Path) -> PathBuf {
    let bin = dir.join("antigravity");
    if bin.is_file() {
        bin
    } else {
        dir.to_path_buf()
    }
}

/// Purely read-only, zero-subprocess detection of an installed Linux desktop Antigravity App.
/// Never spawns Electron/GUI binaries and never fails `status` if the desktop app is absent.
pub fn probe_local_antigravity_app_for_status() -> LocalAntigravityAppProbeOutcome {
    if let Some(explicit_dir) = std::env::var_os(ANTIGRAVITY_APP_DIR_ENV).filter(|v| !v.is_empty())
    {
        let dir = PathBuf::from(explicit_dir);
        return match probe_antigravity_app_install_dir(&dir) {
            Some(version) => LocalAntigravityAppProbeOutcome::Detected {
                path: display_path_for_install_dir(&dir),
                version,
            },
            None => LocalAntigravityAppProbeOutcome::NotFound,
        };
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("antigravity");
            if !candidate.is_file() {
                continue;
            }
            let resolved = fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
            if let Some(parent) = resolved.parent() {
                if let Some(version) = probe_antigravity_app_install_dir(parent) {
                    return LocalAntigravityAppProbeOutcome::Detected {
                        path: candidate,
                        version,
                    };
                }
                if parent.file_name().and_then(|n| n.to_str()) == Some("bin") {
                    if let Some(grandparent) = parent.parent() {
                        if let Some(version) = probe_antigravity_app_install_dir(grandparent) {
                            return LocalAntigravityAppProbeOutcome::Detected {
                                path: candidate,
                                version,
                            };
                        }
                    }
                }
            }
        }
    }

    for fallback in [
        "/opt/Antigravity",
        "/opt/antigravity",
        "/usr/share/antigravity",
        "/usr/lib/antigravity",
    ] {
        let dir = Path::new(fallback);
        if let Some(version) = probe_antigravity_app_install_dir(dir) {
            return LocalAntigravityAppProbeOutcome::Detected {
                path: display_path_for_install_dir(dir),
                version,
            };
        }
    }

    LocalAntigravityAppProbeOutcome::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synthetic_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut file_map = serde_json::Map::new();
        let mut payload = Vec::new();
        for (name, bytes) in files {
            let offset = payload.len();
            payload.extend_from_slice(bytes);
            file_map.insert(
                (*name).to_string(),
                serde_json::json!({
                    "size": bytes.len(),
                    "offset": offset.to_string(),
                }),
            );
        }
        let header_json = serde_json::to_vec(&serde_json::json!({ "files": file_map })).unwrap();
        let json_len = header_json.len() as u32;
        let pad = (4 - (header_json.len() % 4)) % 4;
        let inner_size = 4u32 + json_len + (pad as u32);
        let header_size = 4u32 + inner_size;

        let mut out = Vec::with_capacity(8 + header_size as usize + payload.len());
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(&inner_size.to_le_bytes());
        out.extend_from_slice(&json_len.to_le_bytes());
        out.extend_from_slice(&header_json);
        out.resize(out.len() + pad, 0);
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn synthetic_antigravity_app_probe_reads_asar_and_unpacked_without_spawning() {
        let tmp = tempfile::tempdir().unwrap();

        // 1. Electron ASAR layout (`/opt/Antigravity/resources/app.asar`) — ignores Electron `version` file (`44.9.1`).
        let asar_dir = tmp.path().join("electron_asar");
        fs::create_dir_all(asar_dir.join("resources")).unwrap();
        fs::write(asar_dir.join("version"), b"44.9.1\n").unwrap();
        let pkg = br#"{"name":"antigravity","productName":"Antigravity","version":"2.33.0"}"#;
        fs::write(
            asar_dir.join("resources/app.asar"),
            build_synthetic_asar(&[("package.json", pkg)]),
        )
        .unwrap();
        assert_eq!(
            probe_antigravity_app_install_dir(&asar_dir).as_deref(),
            Some("2.33.0")
        );

        // 2. Unpacked VS Code-fork layout (`resources/app/product.json` with `ideVersion`).
        let unpacked_dir = tmp.path().join("unpacked_ide");
        fs::create_dir_all(unpacked_dir.join("resources/app")).unwrap();
        fs::write(
            unpacked_dir.join("resources/app/product.json"),
            br#"{"applicationName":"antigravity","ideVersion":"1.19.4","version":"1.99.0"}"#,
        )
        .unwrap();
        assert_eq!(
            probe_antigravity_app_install_dir(&unpacked_dir).as_deref(),
            Some("1.19.4")
        );

        // 3. Unrelated Electron app MUST be rejected even with valid ASAR.
        let other_dir = tmp.path().join("other_electron");
        fs::create_dir_all(other_dir.join("resources")).unwrap();
        let other_pkg = br#"{"name":"some-other-editor","version":"9.9.9"}"#;
        fs::write(
            other_dir.join("resources/app.asar"),
            build_synthetic_asar(&[("package.json", other_pkg)]),
        )
        .unwrap();
        assert_eq!(probe_antigravity_app_install_dir(&other_dir), None);

        // 4. Truncated/corrupt ASAR safely returns `None`.
        let bad_dir = tmp.path().join("corrupt_asar");
        fs::create_dir_all(bad_dir.join("resources")).unwrap();
        fs::write(bad_dir.join("resources/app.asar"), b"\x04\x00\x00\x00\xff").unwrap();
        assert_eq!(probe_antigravity_app_install_dir(&bad_dir), None);
    }
}
