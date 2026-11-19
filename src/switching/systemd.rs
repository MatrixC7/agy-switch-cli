use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::session::backend::BackendChoice;
use crate::store::fs_atomic::{
    ensure_dir_chain_pinned_under, ensure_no_symlink_ancestors, ensure_no_symlink_components_under,
    ensure_private_dir, is_single_normal_filename, map_io_error, open_existing_dir_nofollow,
    stat_dir_fd, unlink_pinned_regular_target_after_wait, verify_dir_still_pinned,
    write_atomic_durable_in_pinned_dir,
};
use crate::switching::daemon::{DEFAULT_DAEMON_COOLDOWN_SECS, DEFAULT_DAEMON_INTERVAL_SECS};
use serde::Serialize;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

pub const SYSTEMD_SERVICE_NAME: &str = "agy-switch-cli.service";
const DEFAULT_SYSTEMD_MARKER_DIR: &str = "/run/systemd/system";
pub const SYSTEMD_MARKER_DIR_ENV: &str = "AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR";
pub const SYSTEMCTL_BIN_ENV: &str = "AGY_SWITCH_CLI_SYSTEMCTL_BIN";
pub const SELF_EXE_OVERRIDE_ENV: &str = "AGY_SWITCH_CLI_SELF_EXE";

const SYSTEMCTL_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEMCTL_ACTION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct DaemonServiceInstallOptions {
    pub explicit_interval_secs: Option<u64>,
    pub explicit_cooldown_secs: Option<i64>,
    pub explicit_backend: Option<BackendChoice>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DaemonServiceInstallOutcome {
    pub action: &'static str,
    pub service_name: &'static str,
    pub unit_path: PathBuf,
    pub executable: PathBuf,
    pub data_dir: PathBuf,
    pub exec_start: String,
    pub interval_secs: u64,
    pub cooldown_secs: i64,
    pub enabled_and_started: bool,
    pub linger_hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct DaemonServiceUninstallOutcome {
    pub action: &'static str,
    pub service_name: &'static str,
    pub unit_path: PathBuf,
    pub removed_unit_file: bool,
}

fn non_empty_env_os(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn is_executable_regular_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

fn resolve_systemd_marker_dir() -> PathBuf {
    non_empty_env_os(SYSTEMD_MARKER_DIR_ENV)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SYSTEMD_MARKER_DIR))
}

fn resolve_systemctl_executable() -> CliResult<PathBuf> {
    if let Some(override_bin) = non_empty_env_os(SYSTEMCTL_BIN_ENV) {
        if is_executable_regular_file(&override_bin) {
            return Ok(override_bin);
        }
        return Err(CliError::env_not_ready(
            "systemd_unavailable",
            "`systemctl` executable specified by AGY_SWITCH_CLI_SYSTEMCTL_BIN was not found or is not executable.",
        ));
    }

    if let Some(path_os) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_os) {
            let cand = dir.join("systemctl");
            if is_executable_regular_file(&cand) {
                return Ok(cand);
            }
        }
    }

    Err(CliError::env_not_ready(
        "systemd_unavailable",
        "`systemctl` command was not found on this system, so the `systemd --user` service cannot be installed or managed here. In Docker containers or non-systemd environments, use `nohup`, `tmux`, `supervisord`, or `cron` (`daemon --once`) in `docs/user-guide.md` §7.2.",
    ))
}

fn ensure_systemd_booted() -> CliResult<()> {
    let marker = resolve_systemd_marker_dir();
    let booted = fs::symlink_metadata(&marker)
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        .unwrap_or(false);
    if !booted {
        return Err(CliError::env_not_ready(
            "systemd_unavailable",
            "This system is not running `systemd` (`/run/systemd/system` not present), so `systemd --user` service management is unavailable. In Docker containers, minimal WSL, or non-systemd Linux distributions, run `agy-switch-cli daemon` in the background via `nohup`, `tmux`, `supervisord`, or `cron` (`daemon --once`) instead (see `docs/user-guide.md` §7.2).",
        ));
    }
    Ok(())
}

fn resolve_current_cli_executable() -> CliResult<PathBuf> {
    let exe = match non_empty_env_os(SELF_EXE_OVERRIDE_ENV) {
        Some(custom) => custom,
        None => std::env::current_exe().map_err(|e| {
            CliError::io(
                "current_exe_failed",
                format!("Cannot determine current `agy-switch-cli` executable path: {e}"),
            )
        })?,
    };
    if !exe.is_absolute() {
        return Err(CliError::data(
            "Current `agy-switch-cli` executable path must be an absolute path.",
        ));
    }
    if !is_executable_regular_file(&exe) {
        return Err(CliError::data(
            "Current `agy-switch-cli` executable path does not point to an existing executable file on disk (reinstall the binary and retry).",
        ));
    }
    Ok(exe)
}

fn validate_no_control_chars(value: &str, label: &str) -> CliResult<()> {
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        return Err(CliError::data(format!(
            "{label} contains empty or control characters and cannot be safely written into a systemd unit file."
        )));
    }
    Ok(())
}

/// Quote a value for non-command systemd settings (`Environment=`, `ReadWritePaths=`),
/// escaping `%` -> `%%` (systemd specifier expansion), `\` -> `\\`, and `"` -> `\"`.
pub fn systemd_quote_setting_value(raw: &str, label: &str) -> CliResult<String> {
    validate_no_control_chars(raw, label)?;
    let mut out = String::with_capacity(raw.len() + 4);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            other => out.push(other),
        }
    }
    out.push('"');
    Ok(out)
}

/// Quote the executable path (`argv[0]`) for `ExecStart=`.
/// Per `systemd.service(5)`, `ExecStart=` applies unit specifier expansion (`%` -> `%%`) and C-unescaping
/// (`\` -> `\\`, `"` -> `\"`) to the executable path, but NEVER performs `$` environment variable expansion
/// on `argv[0]` (`$$` would be passed literally as two dollar signs and fail with `ENOENT`).
pub fn systemd_quote_exec_program(raw: &str, label: &str) -> CliResult<String> {
    validate_no_control_chars(raw, label)?;
    let is_plain_safe = raw.starts_with('/')
        && raw.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b':' | b'=' | b'$')
        });
    if is_plain_safe {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len() + 6);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            other => out.push(other),
        }
    }
    out.push('"');
    Ok(out)
}

/// Quote a non-program argument (`argv[1..]`) for `ExecStart=`, escaping `%` -> `%%` (specifier expansion),
/// `$` -> `$$` (systemd command-line environment expansion), `\` -> `\\`, and `"` -> `\"`.
pub fn systemd_quote_exec_arg(raw: &str, label: &str) -> CliResult<String> {
    validate_no_control_chars(raw, label)?;
    let is_plain_safe = raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b':' | b'='));
    if is_plain_safe {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len() + 6);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            other => out.push(other),
        }
    }
    out.push('"');
    Ok(out)
}

fn path_to_utf8<'a>(p: &'a Path, label: &str) -> CliResult<&'a str> {
    p.to_str().ok_or_else(|| {
        CliError::data(format!(
            "{label} is not valid UTF-8 and cannot be written into a systemd unit file."
        ))
    })
}

fn path_resides_in_system_tmp(p: &Path) -> bool {
    if p.starts_with("/tmp") || p.starts_with("/var/tmp") {
        return true;
    }
    fs::canonicalize(p)
        .map(|canon| canon.starts_with("/tmp") || canon.starts_with("/var/tmp"))
        .unwrap_or(false)
}

/// Render the hardened `agy-switch-cli.service` user unit file matching `deploy/agy-switch-cli.service`.
pub fn render_systemd_user_unit(
    paths: &HeadlessPaths,
    exe_path: &Path,
    opts: &DaemonServiceInstallOptions,
) -> CliResult<(String, String)> {
    if let Some(iv) = opts.explicit_interval_secs {
        if iv == 0 {
            return Err(CliError::usage("`--interval` must be at least 1 second."));
        }
    }
    if let Some(cd) = opts.explicit_cooldown_secs {
        if cd < 0 {
            return Err(CliError::usage("`--cooldown` must be >= 0 seconds."));
        }
    }

    let exe_str = path_to_utf8(exe_path, "Executable path")?;
    let data_str = path_to_utf8(&paths.data_dir, "Data directory path")?;
    let cache_str = path_to_utf8(&paths.cache_dir, "Cache directory path")?;
    let slot_str = path_to_utf8(&paths.active_slot_dir, "Active slot directory path")?;

    let mut exec_tokens = vec![systemd_quote_exec_program(exe_str, "Executable path")?];
    if let Some(choice) = opts.explicit_backend {
        let backend_word = match choice {
            BackendChoice::Auto => "auto",
            BackendChoice::Dual => "dual",
            BackendChoice::File => "file",
            BackendChoice::Keyring => "keyring",
        };
        exec_tokens.push("--backend".to_string());
        exec_tokens.push(systemd_quote_exec_arg(backend_word, "Backend")?);
    }
    exec_tokens.push("daemon".to_string());
    if let Some(iv) = opts.explicit_interval_secs {
        exec_tokens.push("--interval".to_string());
        exec_tokens.push(iv.to_string());
    }
    if let Some(cd) = opts.explicit_cooldown_secs {
        exec_tokens.push("--cooldown".to_string());
        exec_tokens.push(cd.to_string());
    }
    let exec_start_line = exec_tokens.join(" ");

    let data_env_quoted = systemd_quote_setting_value(
        &format!("AGY_SWITCH_CLI_DATA_DIR={data_str}"),
        "AGY_SWITCH_CLI_DATA_DIR",
    )?;
    let default_cache_dir = paths.home_dir.join(".cache").join("agy-switch-cli");
    let custom_cache_env_line = if paths.cache_dir != default_cache_dir {
        if let Some(cache_base) = paths.cache_dir.parent().filter(|_| {
            paths.cache_dir.file_name().and_then(|s| s.to_str()) == Some("agy-switch-cli")
        }) {
            let cache_base_str = path_to_utf8(cache_base, "XDG_CACHE_HOME path")?;
            let quoted = systemd_quote_setting_value(
                &format!("XDG_CACHE_HOME={cache_base_str}"),
                "XDG_CACHE_HOME",
            )?;
            format!("Environment={quoted}\n")
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    // Prefix `active_slot_dir` with `-` per `systemd.exec(5)` so `systemd` starts cleanly even when
    // `~/.gemini/antigravity-cli` has not been created yet (or under `--backend keyring`).
    let rw_slot = format!(
        "-{}",
        systemd_quote_setting_value(slot_str, "Active slot directory")?
    );
    let rw_data = systemd_quote_setting_value(data_str, "Data directory")?;
    let rw_cache = systemd_quote_setting_value(cache_str, "Cache directory")?;

    let use_private_tmp = !path_resides_in_system_tmp(&paths.home_dir)
        && !path_resides_in_system_tmp(&paths.data_dir)
        && !path_resides_in_system_tmp(&paths.cache_dir)
        && !path_resides_in_system_tmp(&paths.active_slot_dir)
        && !path_resides_in_system_tmp(exe_path);
    let private_tmp_line = if use_private_tmp {
        "PrivateTmp=true\n"
    } else {
        ""
    };

    let unit = format!(
        "[Unit]\n\
Description=Antigravity CLI 无头多账号自动切换守护服务 (agy-switch-cli)\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
UMask=0077\n\
Environment=\"RUST_LOG=agy_switch_cli=info\"\n\
Environment={data_env_quoted}\n\
{custom_cache_env_line}\
ExecStart={exec_start_line}\n\
Restart=on-failure\n\
RestartSec=10\n\
\n\
# 文件系统最小权限沙盒边界：保持系统目录只读，仅显式放行官方生效位目录、独立无头数据目录与全局锁/缓存目录的写权限\n\
NoNewPrivileges=true\n\
{private_tmp_line}\
ProtectSystem=strict\n\
ReadWritePaths={rw_slot} {rw_data} {rw_cache}\n\
\n\
[Install]\n\
WantedBy=default.target\n"
    );

    Ok((unit, exec_start_line))
}

async fn run_systemctl_user_raw(
    systemctl_bin: &Path,
    paths: &HeadlessPaths,
    args: &[&str],
    timeout: Duration,
) -> CliResult<(i32, String, String)> {
    let mut cmd = tokio::process::Command::new(systemctl_bin);
    cmd.arg("--user")
        .args(args)
        .env("HOME", &paths.home_dir)
        .env("XDG_CONFIG_HOME", &paths.config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| {
            CliError::env_not_ready(
                "systemctl_timeout",
                format!(
                    "`systemctl --user {}` timed out after {}s.",
                    args.join(" "),
                    timeout.as_secs()
                ),
            )
        })?
        .map_err(|e| {
            CliError::io(
                "systemctl_spawn_failed",
                format!("Failed to invoke `{}`: {e}", systemctl_bin.display()),
            )
        })?;

    let code = output.status.code().unwrap_or(1);
    let stdout_raw = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_clean =
        crate::error::sanitize_error_message(&String::from_utf8_lossy(&output.stderr));
    Ok((code, stdout_raw, stderr_clean))
}

async fn run_systemctl_user(
    systemctl_bin: &Path,
    paths: &HeadlessPaths,
    args: &[&str],
    timeout: Duration,
) -> CliResult<(i32, String)> {
    let (code, stdout_raw, stderr_clean) =
        run_systemctl_user_raw(systemctl_bin, paths, args, timeout).await?;
    let combined = if !stderr_clean.is_empty() {
        stderr_clean
    } else {
        crate::error::sanitize_error_message(&stdout_raw)
    };
    Ok((code, combined))
}

#[derive(Debug, Default)]
struct ManagerUnitShow {
    fragment_path: Option<PathBuf>,
    load_state: Option<String>,
    unit_file_state: Option<String>,
    active_state: Option<String>,
}

async fn query_manager_unit_identity(
    systemctl_bin: &Path,
    paths: &HeadlessPaths,
) -> CliResult<ManagerUnitShow> {
    let (code, stdout_raw, stderr_clean) = run_systemctl_user_raw(
        systemctl_bin,
        paths,
        &[
            "show",
            "-p",
            "FragmentPath",
            "-p",
            "LoadState",
            "-p",
            "UnitFileState",
            "-p",
            "ActiveState",
            SYSTEMD_SERVICE_NAME,
        ],
        SYSTEMCTL_PROBE_TIMEOUT,
    )
    .await?;
    if code != 0 {
        return Err(CliError::io(
            "systemctl_show_failed",
            format!(
                "`systemctl --user show {SYSTEMD_SERVICE_NAME}` failed with exit code {code}{}.",
                if stderr_clean.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr_clean}")
                }
            ),
        ));
    }
    let mut info = ManagerUnitShow::default();
    for line in stdout_raw.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let v_trimmed = v.trim();
        match key {
            // Preserve literal whitespace inside `FragmentPath` (only reject empty values)
            "FragmentPath" if !v.is_empty() => {
                info.fragment_path = Some(PathBuf::from(v));
            }
            "LoadState" if !v_trimmed.is_empty() => {
                info.load_state = Some(v_trimmed.to_string());
            }
            "UnitFileState" if !v_trimmed.is_empty() => {
                info.unit_file_state = Some(v_trimmed.to_string());
            }
            "ActiveState" if !v_trimmed.is_empty() => {
                info.active_state = Some(v_trimmed.to_string());
            }
            _ => {}
        }
    }
    Ok(info)
}

#[allow(clippy::too_many_arguments)]
fn verify_pinned_unit_inode_after_wait(
    dir_fd: &OwnedFd,
    dir_dev: u64,
    dir_ino: u64,
    dir_path: &Path,
    c_unit_name: &CString,
    pinned_unit_fd: &OwnedFd,
    expected_unit_dev: u64,
    expected_unit_ino: u64,
    expected_content: &[u8],
) -> CliResult<()> {
    verify_dir_still_pinned(dir_path, dir_dev, dir_ino)?;
    let unit_full = dir_path.join(SYSTEMD_SERVICE_NAME);

    // 1. Confirm the held pinned FD still points to a linked regular file matching the original inode.
    let mut pinned_st: libc::stat = unsafe { std::mem::zeroed() };
    let pinned_rc = unsafe { libc::fstat(pinned_unit_fd.as_raw_fd(), &mut pinned_st) };
    #[allow(clippy::unnecessary_cast)]
    let pinned_valid = pinned_rc == 0
        && (pinned_st.st_mode & libc::S_IFMT) == libc::S_IFREG
        && (pinned_st.st_nlink as u64) > 0
        && (pinned_st.st_dev as u64) == expected_unit_dev
        && (pinned_st.st_ino as u64) == expected_unit_ino;
    if !pinned_valid {
        return Err(CliError::data(format!(
            "Installed systemd unit '{}' was unlinked or replaced concurrently during installation.",
            unit_full.display()
        )));
    }

    // 2. Open the live directory entry via `openat(O_NOFOLLOW)` and confirm identical inode + exact bytes.
    let raw_live = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c_unit_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw_live < 0 {
        return Err(CliError::data(format!(
            "Installed systemd unit '{}' disappeared or could not be verified after systemctl wait.",
            unit_full.display()
        )));
    }
    let live_file = unsafe { fs::File::from_raw_fd(raw_live) };
    let live_meta = live_file.metadata().map_err(|e| {
        map_io_error(
            e,
            &format!(
                "Cannot stat installed systemd unit '{}'",
                unit_full.display()
            ),
        )
    })?;
    let same = live_meta.file_type().is_file()
        && live_meta.dev() == expected_unit_dev
        && live_meta.ino() == expected_unit_ino;
    if !same {
        return Err(CliError::data(format!(
            "Installed systemd unit '{}' changed inode or type concurrently during installation.",
            unit_full.display()
        )));
    }
    unsafe {
        let fl = libc::fcntl(live_file.as_raw_fd(), libc::F_GETFL);
        if fl >= 0 && (fl & libc::O_NONBLOCK) != 0 {
            let _ = libc::fcntl(live_file.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    let mut actual = Vec::with_capacity(expected_content.len());
    live_file
        .take((expected_content.len() as u64).saturating_add(1))
        .read_to_end(&mut actual)
        .map_err(|e| {
            map_io_error(
                e,
                &format!(
                    "Cannot read back installed systemd unit '{}'",
                    unit_full.display()
                ),
            )
        })?;
    if actual != expected_content {
        return Err(CliError::data(format!(
            "Installed systemd unit '{}' contents were modified concurrently during installation.",
            unit_full.display()
        )));
    }
    Ok(())
}

/// Stat a `FragmentPath` returned by `systemctl --user show` strictly via no-symlink top-down
/// `openat` + `fstatat(AT_SYMLINK_NOFOLLOW)` and return its `(dev, ino)` if it is a regular file.
fn stat_regular_path_nofollow(path: &Path) -> CliResult<Option<(u64, u64)>> {
    if !path.is_absolute() {
        return Err(CliError::data(
            "systemd reported a non-absolute FragmentPath for the unit file.",
        ));
    }
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(None);
    };
    let Some(leaf) = path.file_name() else {
        return Ok(None);
    };
    if !is_single_normal_filename(leaf.as_bytes()) {
        return Err(CliError::data(
            "systemd reported an invalid FragmentPath leaf name.",
        ));
    }
    let c_leaf = CString::new(leaf.as_bytes())
        .map_err(|_| CliError::data("systemd reported a FragmentPath with NUL byte."))?;
    let Some(parent_fd) = open_existing_dir_nofollow(parent)? else {
        return Ok(None);
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(map_io_error(
            err,
            &format!("Cannot stat systemd FragmentPath '{}'", path.display()),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(CliError::data(format!(
            "systemd FragmentPath '{}' is not a regular file.",
            path.display()
        )));
    }
    #[allow(clippy::unnecessary_cast)]
    Ok(Some((st.st_dev as u64, st.st_ino as u64)))
}

async fn verify_user_systemd_manager_active(
    systemctl_bin: &Path,
    paths: &HeadlessPaths,
) -> CliResult<()> {
    let (code, detail) = run_systemctl_user(
        systemctl_bin,
        paths,
        &["show-environment"],
        SYSTEMCTL_PROBE_TIMEOUT,
    )
    .await?;
    if code != 0 {
        let suffix = if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        };
        return Err(CliError::env_not_ready(
            "systemd_user_unavailable",
            format!(
                "No active `systemd --user` service manager is reachable in the current session{suffix}. If you are inside a Docker container, minimal WSL, or `su` session without a PAM login manager, see `docs/user-guide.md` §7.2 for `nohup` / `tmux` / `supervisord` / `cron` background options (or log in via full SSH session and run `sudo loginctl enable-linger $USER`)."
            ),
        ));
    }
    Ok(())
}

pub async fn install_systemd_user_service(
    paths: &HeadlessPaths,
    opts: &DaemonServiceInstallOptions,
) -> CliResult<DaemonServiceInstallOutcome> {
    // Validate parameters first so usage errors return exit code 2 immediately
    let exe_path = resolve_current_cli_executable()?;
    let (unit_body, exec_start_line) = render_systemd_user_unit(paths, &exe_path, opts)?;

    ensure_systemd_booted()?;
    let systemctl_bin = resolve_systemctl_executable()?;
    verify_user_systemd_manager_active(&systemctl_bin, paths).await?;

    paths.ensure_not_legacy_store_dir()?;
    ensure_private_dir(&paths.data_dir)?;
    ensure_private_dir(&paths.cache_dir)?;

    let user_dir = paths.systemd_user_dir();
    let unit_path = paths.systemd_user_unit_file();
    let c_unit_name = CString::new(SYSTEMD_SERVICE_NAME).unwrap();
    let (pinned_user_fd, user_dev, user_ino) =
        ensure_dir_chain_pinned_under(&paths.config_dir, &user_dir)?;

    let (pinned_unit_fd, unit_dev, unit_ino) = write_atomic_durable_in_pinned_dir(
        &pinned_user_fd,
        user_dev,
        user_ino,
        &user_dir,
        SYSTEMD_SERVICE_NAME,
        unit_body.as_bytes(),
    )?;

    let (reload_rc, reload_msg) = run_systemctl_user(
        &systemctl_bin,
        paths,
        &["daemon-reload"],
        SYSTEMCTL_ACTION_TIMEOUT,
    )
    .await?;
    if reload_rc != 0 {
        return Err(CliError::io(
            "systemctl_daemon_reload_failed",
            format!(
                "`systemctl --user daemon-reload` failed with exit code {reload_rc}{}.",
                if reload_msg.is_empty() {
                    String::new()
                } else {
                    format!(": {reload_msg}")
                }
            ),
        ));
    }

    // Re-verify ancestor directory lineage, installed unit inode, AND manager unit identity
    // AFTER `daemon-reload` and BEFORE `enable --now` so a higher-precedence foreign unit
    // can NEVER be enabled or started!
    verify_pinned_unit_inode_after_wait(
        &pinned_user_fd,
        user_dev,
        user_ino,
        &user_dir,
        &c_unit_name,
        &pinned_unit_fd,
        unit_dev,
        unit_ino,
        unit_body.as_bytes(),
    )?;
    let pre_enable_mgr = query_manager_unit_identity(&systemctl_bin, paths).await?;
    let Some(ref pre_frag_path) = pre_enable_mgr.fragment_path else {
        return Err(CliError::io(
            "systemctl_verify_failed",
            "systemd manager did not report FragmentPath after `daemon-reload`; refusing to enable unverified unit.",
        ));
    };
    if stat_regular_path_nofollow(pre_frag_path)? != Some((unit_dev, unit_ino)) {
        return Err(CliError::data(format!(
            "systemd manager resolved `{SYSTEMD_SERVICE_NAME}` to a different unit file ('{}') instead of '{}' after `daemon-reload`; refusing to run `enable --now`.",
            pre_frag_path.display(),
            unit_path.display()
        )));
    }
    if pre_enable_mgr.load_state.as_deref() != Some("loaded") {
        return Err(CliError::io(
            "systemctl_verify_failed",
            format!(
                "systemd manager reported unexpected LoadState `{}` after `daemon-reload` (expected `loaded`).",
                pre_enable_mgr.load_state.as_deref().unwrap_or("unknown")
            ),
        ));
    }

    let (enable_rc, enable_msg) = run_systemctl_user(
        &systemctl_bin,
        paths,
        &["enable", "--now", SYSTEMD_SERVICE_NAME],
        SYSTEMCTL_ACTION_TIMEOUT,
    )
    .await?;
    if enable_rc != 0 {
        return Err(CliError::io(
            "systemctl_enable_failed",
            format!(
                "`systemctl --user enable --now {SYSTEMD_SERVICE_NAME}` failed with exit code {enable_rc}{}.",
                if enable_msg.is_empty() {
                    String::new()
                } else {
                    format!(": {enable_msg}")
                }
            ),
        ));
    }

    // Re-verify pinned dir + unit inode after `enable --now` AND query the manager to prove it
    // actually loaded our exact written unit inode and enabled/started it!
    verify_pinned_unit_inode_after_wait(
        &pinned_user_fd,
        user_dev,
        user_ino,
        &user_dir,
        &c_unit_name,
        &pinned_unit_fd,
        unit_dev,
        unit_ino,
        unit_body.as_bytes(),
    )?;

    let mgr_state = query_manager_unit_identity(&systemctl_bin, paths).await?;
    let Some(ref frag_path) = mgr_state.fragment_path else {
        return Err(CliError::io(
            "systemctl_verify_failed",
            "systemd manager did not report FragmentPath after `enable --now`; cannot verify installed unit identity.",
        ));
    };
    let frag_id = stat_regular_path_nofollow(frag_path)?;
    if frag_id != Some((unit_dev, unit_ino)) {
        return Err(CliError::data(format!(
            "systemd manager loaded a different unit file ('{}') instead of the newly installed '{}' (inode mismatch).",
            frag_path.display(),
            unit_path.display()
        )));
    }
    if mgr_state.load_state.as_deref() != Some("loaded") {
        return Err(CliError::io(
            "systemctl_verify_failed",
            format!(
                "systemd manager reported unexpected LoadState `{}` after installation (expected `loaded`).",
                mgr_state.load_state.as_deref().unwrap_or("unknown")
            ),
        ));
    }
    let is_enabled = matches!(
        mgr_state.unit_file_state.as_deref(),
        Some("enabled" | "enabled-runtime" | "linked")
    );
    let is_active = matches!(
        mgr_state.active_state.as_deref(),
        Some("active" | "activating")
    );
    if !is_enabled || !is_active {
        return Err(CliError::io(
            "systemctl_verify_failed",
            format!(
                "systemd manager did not confirm enabled+active state after `enable --now` (UnitFileState=`{}`, ActiveState=`{}`).",
                mgr_state.unit_file_state.as_deref().unwrap_or("unknown"),
                mgr_state.active_state.as_deref().unwrap_or("unknown"),
            ),
        ));
    }

    verify_pinned_unit_inode_after_wait(
        &pinned_user_fd,
        user_dev,
        user_ino,
        &user_dir,
        &c_unit_name,
        &pinned_unit_fd,
        unit_dev,
        unit_ino,
        unit_body.as_bytes(),
    )?;
    drop(pinned_unit_fd);

    Ok(DaemonServiceInstallOutcome {
        action: "install",
        service_name: SYSTEMD_SERVICE_NAME,
        unit_path,
        executable: exe_path,
        data_dir: paths.data_dir.clone(),
        exec_start: exec_start_line,
        interval_secs: opts
            .explicit_interval_secs
            .unwrap_or(DEFAULT_DAEMON_INTERVAL_SECS),
        cooldown_secs: opts
            .explicit_cooldown_secs
            .unwrap_or(DEFAULT_DAEMON_COOLDOWN_SECS),
        enabled_and_started: true,
        linger_hint: "sudo loginctl enable-linger $USER",
    })
}

pub async fn uninstall_systemd_user_service(
    paths: &HeadlessPaths,
) -> CliResult<DaemonServiceUninstallOutcome> {
    ensure_systemd_booted()?;
    let systemctl_bin = resolve_systemctl_executable()?;
    verify_user_systemd_manager_active(&systemctl_bin, paths).await?;

    ensure_no_symlink_ancestors(&paths.config_dir)?;
    let user_dir = paths.systemd_user_dir();
    let unit_path = paths.systemd_user_unit_file();
    ensure_no_symlink_components_under(&paths.config_dir, &unit_path)?;

    let c_unit_name = CString::new(SYSTEMD_SERVICE_NAME).unwrap();
    let pinned_before_stop = if let Some(dir_fd) = open_existing_dir_nofollow(&user_dir)? {
        let (dir_dev, dir_ino) = stat_dir_fd(&dir_fd, &user_dir)?;
        let raw_unit = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                c_unit_name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw_unit >= 0 {
            let unit_fd = unsafe { OwnedFd::from_raw_fd(raw_unit) };
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstat(unit_fd.as_raw_fd(), &mut st) };
            if rc != 0 {
                return Err(map_io_error(
                    std::io::Error::last_os_error(),
                    &format!("Cannot inspect service unit '{}'", unit_path.display()),
                ));
            }
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(CliError::data(format!(
                    "Refusing to remove non-regular service file '{}' (symlink or directory).",
                    unit_path.display()
                )));
            }
            #[allow(clippy::unnecessary_cast)]
            Some((
                dir_fd,
                dir_dev,
                dir_ino,
                unit_fd,
                st.st_dev as u64,
                st.st_ino as u64,
            ))
        } else {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(c) if c == libc::ENOENT => None,
                Some(c) if c == libc::ELOOP || c == libc::ENOTDIR => {
                    return Err(CliError::data(format!(
                        "Refusing to remove non-regular service file '{}' (symlink or directory).",
                        unit_path.display()
                    )));
                }
                _ => {
                    return Err(map_io_error(
                        err,
                        &format!("Cannot inspect service unit '{}'", unit_path.display()),
                    ));
                }
            }
        }
    } else {
        None
    };
    let unit_existed = pinned_before_stop.is_some();

    // Query manager BEFORE invoking `disable --now` by unit name so we NEVER blindly stop/disable
    // an unrelated unit file loaded from a different directory or replaced ancestor!
    let pre_mgr = query_manager_unit_identity(&systemctl_bin, paths).await?;
    let should_call_disable = match &pinned_before_stop {
        Some((_, _, _, _, target_dev, target_ino)) => {
            if pre_mgr.load_state.as_deref() == Some("masked") {
                return Err(CliError::data(format!(
                    "Refusing to disable `{SYSTEMD_SERVICE_NAME}` because systemd manager reports it as `masked`."
                )));
            }
            if pre_mgr.load_state.as_deref() == Some("not-found") || pre_mgr.fragment_path.is_none()
            {
                true
            } else if let Some(ref frag_path) = pre_mgr.fragment_path {
                let frag_id = stat_regular_path_nofollow(frag_path)?;
                if frag_id != Some((*target_dev, *target_ino)) {
                    return Err(CliError::data(format!(
                        "Refusing to disable `{SYSTEMD_SERVICE_NAME}` because systemd manager loaded a different unit file ('{}') than '{}'.",
                        frag_path.display(),
                        unit_path.display()
                    )));
                }
                true
            } else {
                true
            }
        }
        None => {
            if let Some(ref frag_path) = pre_mgr.fragment_path {
                if pre_mgr.load_state.as_deref() != Some("not-found") {
                    return Err(CliError::data(format!(
                        "Refusing to disable `{SYSTEMD_SERVICE_NAME}` because '{}' does not exist while systemd manager still loads a foreign unit at '{}'.",
                        unit_path.display(),
                        frag_path.display()
                    )));
                }
            }
            let foreign_active = matches!(
                pre_mgr.active_state.as_deref(),
                Some("active" | "activating")
            );
            let foreign_loaded = pre_mgr
                .load_state
                .as_deref()
                .is_some_and(|st| st != "not-found");
            if foreign_active || foreign_loaded {
                return Err(CliError::data(format!(
                    "Refusing to complete uninstall of `{SYSTEMD_SERVICE_NAME}` because '{}' does not exist while systemd manager reports LoadState=`{}` / ActiveState=`{}`.",
                    unit_path.display(),
                    pre_mgr.load_state.as_deref().unwrap_or("unknown"),
                    pre_mgr.active_state.as_deref().unwrap_or("unknown"),
                )));
            }
            false
        }
    };

    if should_call_disable {
        let (disable_rc, disable_msg) = run_systemctl_user(
            &systemctl_bin,
            paths,
            &["disable", "--now", SYSTEMD_SERVICE_NAME],
            SYSTEMCTL_ACTION_TIMEOUT,
        )
        .await?;
        if unit_existed && disable_rc != 0 {
            return Err(CliError::io(
                "systemctl_disable_failed",
                format!(
                    "`systemctl --user disable --now {SYSTEMD_SERVICE_NAME}` failed with exit code {disable_rc}{}.",
                    if disable_msg.is_empty() {
                        String::new()
                    } else {
                        format!(": {disable_msg}")
                    }
                ),
            ));
        }
    }

    let removed_unit_file =
        if let Some((dir_fd, dir_dev, dir_ino, unit_fd, target_dev, target_ino)) =
            pinned_before_stop
        {
            let removed = unlink_pinned_regular_target_after_wait(
                &dir_fd,
                dir_dev,
                dir_ino,
                &user_dir,
                SYSTEMD_SERVICE_NAME,
                target_dev,
                target_ino,
            )?;
            drop(unit_fd);
            removed
        } else {
            ensure_no_symlink_ancestors(&paths.config_dir)?;
            ensure_no_symlink_components_under(&paths.config_dir, &unit_path)?;
            if let Some(check_fd) = open_existing_dir_nofollow(&user_dir)? {
                let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    libc::fstatat(
                        check_fd.as_raw_fd(),
                        c_unit_name.as_ptr(),
                        &mut post_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc == 0 {
                    return Err(CliError::data(format!(
                        "Service unit '{}' appeared concurrently during uninstall; retry.",
                        unit_path.display()
                    )));
                }
            }
            false
        };

    let (reload_rc, reload_msg) = run_systemctl_user(
        &systemctl_bin,
        paths,
        &["daemon-reload"],
        SYSTEMCTL_ACTION_TIMEOUT,
    )
    .await?;
    if reload_rc != 0 {
        return Err(CliError::io(
            "systemctl_daemon_reload_failed",
            format!(
                "`systemctl --user daemon-reload` failed with exit code {reload_rc}{}.",
                if reload_msg.is_empty() {
                    String::new()
                } else {
                    format!(": {reload_msg}")
                }
            ),
        ));
    }

    let post_mgr = query_manager_unit_identity(&systemctl_bin, paths).await?;
    if matches!(
        post_mgr.active_state.as_deref(),
        Some("active" | "activating")
    ) {
        return Err(CliError::io(
            "systemctl_verify_failed",
            format!(
                "systemd manager still reports `{SYSTEMD_SERVICE_NAME}` as `{}` after uninstall.",
                post_mgr.active_state.as_deref().unwrap_or("active")
            ),
        ));
    }
    if post_mgr.fragment_path.as_deref() == Some(unit_path.as_path())
        && post_mgr.load_state.as_deref() == Some("loaded")
    {
        return Err(CliError::io(
            "systemctl_verify_failed",
            "systemd manager still reports the uninstalled unit as loaded after `daemon-reload`.",
        ));
    }

    Ok(DaemonServiceUninstallOutcome {
        action: "uninstall",
        service_name: SYSTEMD_SERVICE_NAME,
        unit_path,
        removed_unit_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_renderer_escapes_specifiers_env_vars_spaces_and_rejects_control_chars() {
        let paths = HeadlessPaths::with_explicit(
            PathBuf::from("/home/alice"),
            PathBuf::from("/home/alice/my data%dir$1"),
            PathBuf::from("/home/alice/.custom cache%dir/agy-switch-cli"),
        );
        let exe = Path::new("/home/alice/bin dir/agy$switch%cli");
        let (unit, exec_line) = render_systemd_user_unit(
            &paths,
            exe,
            &DaemonServiceInstallOptions {
                explicit_interval_secs: Some(7200),
                explicit_cooldown_secs: Some(1800),
                explicit_backend: Some(BackendChoice::Auto),
            },
        )
        .unwrap();

        // `systemd` does NOT expand `$` in `ExecStart` `argv[0]` (`$$` would fail with ENOENT),
        // while `%` specifiers ARE expanded (`%%` -> `%`), and `argv[1..]` DOES expand `$` (`$$` -> `$`).
        assert_eq!(
            exec_line,
            "\"/home/alice/bin dir/agy$switch%%cli\" --backend auto daemon --interval 7200 --cooldown 1800"
        );
        assert_eq!(
            systemd_quote_exec_arg("arg$with%spec", "arg").unwrap(),
            "\"arg$$with%%spec\""
        );
        assert!(unit.contains("Environment=\"AGY_SWITCH_CLI_DATA_DIR=/home/alice/my data%%dir$1\""));
        assert!(unit.contains("Environment=\"XDG_CACHE_HOME=/home/alice/.custom cache%%dir\""));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("PrivateTmp=true"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains(
            "ReadWritePaths=-\"/home/alice/.gemini/antigravity-cli\" \"/home/alice/my data%%dir$1\" \"/home/alice/.custom cache%%dir/agy-switch-cli\""
        ));

        // Verify real `systemd-analyze verify` accepts our rendered unit (including `$`, `%`, and spaces in `argv[0]`)
        // in an isolated tempdir without touching host `~/.config/systemd`!
        let verify_bin = Path::new("/usr/bin/systemd-analyze");
        if verify_bin.is_file() {
            let tmp = tempfile::tempdir().unwrap();
            let sb_home = tmp.path().join("home");
            let sb_cfg = tmp.path().join("cfg");
            let sb_run = tmp.path().join("run");
            let sb_bin_dir = tmp.path().join("bin dir");
            let sb_data = tmp.path().join("data%dir$1");
            let sb_cache = tmp.path().join("custom cache/agy-switch-cli");
            fs::create_dir_all(&sb_home).unwrap();
            fs::create_dir_all(&sb_cfg).unwrap();
            fs::create_dir_all(&sb_run).unwrap();
            fs::create_dir_all(&sb_bin_dir).unwrap();
            fs::create_dir_all(&sb_data).unwrap();
            fs::create_dir_all(&sb_cache).unwrap();

            let real_true = if Path::new("/usr/bin/true").is_file() {
                Path::new("/usr/bin/true")
            } else {
                Path::new("/bin/true")
            };
            let sb_exe = sb_bin_dir.join("agy$switch%cli");
            fs::copy(real_true, &sb_exe).unwrap();
            fs::set_permissions(&sb_exe, fs::Permissions::from_mode(0o755)).unwrap();

            let sb_paths = HeadlessPaths::with_explicit(sb_home.clone(), sb_data, sb_cache);
            let (sb_unit, _) = render_systemd_user_unit(
                &sb_paths,
                &sb_exe,
                &DaemonServiceInstallOptions {
                    explicit_interval_secs: Some(7200),
                    explicit_cooldown_secs: Some(1800),
                    explicit_backend: Some(BackendChoice::File),
                },
            )
            .unwrap();
            assert!(
                !sb_unit.contains("PrivateTmp=true"),
                "Paths under /tmp must omit PrivateTmp=true so ExecStart and ReadWritePaths remain visible"
            );
            let sb_unit_file = tmp.path().join("agy-verify-check.service");
            fs::write(&sb_unit_file, &sb_unit).unwrap();

            let out = std::process::Command::new(verify_bin)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &sb_home)
                .env("XDG_CONFIG_HOME", &sb_cfg)
                .env("XDG_RUNTIME_DIR", &sb_run)
                .args(["verify", sb_unit_file.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "systemd-analyze verify rejected generated unit:\nstdout={}\nstderr={}\nunit=\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                sb_unit
            );
        }

        // Reject newline injection in paths
        let bad_paths = HeadlessPaths::with_explicit(
            PathBuf::from("/home/alice"),
            PathBuf::from("/home/alice/bad\nExecStart=/bin/evil"),
            PathBuf::from("/home/alice/.cache/agy-switch-cli"),
        );
        assert!(render_systemd_user_unit(
            &bad_paths,
            Path::new("/usr/local/bin/agy-switch-cli"),
            &DaemonServiceInstallOptions {
                explicit_interval_secs: None,
                explicit_cooldown_secs: None,
                explicit_backend: None,
            }
        )
        .is_err());
    }
}
