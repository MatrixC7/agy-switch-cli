use crate::error::{CliError, CliResult};
use crate::store::fs_atomic::map_io_error;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicI32, Ordering},
    LazyLock, Mutex,
};

pub const MAX_SECRET_BYTES: usize = 16 * 1024;
pub const MAX_BATCH_SECRET_BYTES: usize = 64 * 1024;
const GUARDED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

static TTY_PROMPT_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static ACTIVE_TERMIOS_FD: AtomicI32 = AtomicI32::new(-1);
static ACTIVE_PROMPT_JSON_MODE: AtomicBool = AtomicBool::new(false);
static mut SAVED_SIGNAL_TERMIOS: libc::termios = unsafe { std::mem::zeroed() };

/// Write human-only interactive prompt/authorization instructions without EVER polluting `stdout`
/// or `--json` `stderr` envelopes:
/// - Normal mode (`json_mode == false`): writes to `stderr` and flushes;
/// - JSON mode (`json_mode == true`): writes directly to `/dev/tty` (`O_WRONLY | O_NOCTTY | O_CLOEXEC`)
///   ONLY when `stdin` is an interactive TTY (`isatty(STDIN_FILENO) == 1`, e.g. `out=$(agy-switch-cli --json ...)`),
///   and stays completely silent when `stdin` is piped or redirected in automation.
pub fn write_interactive_prompt(json_mode: bool, text: &str) {
    if !json_mode {
        let mut stderr = io::stderr();
        let _ = write!(stderr, "{text}");
        let _ = stderr.flush();
        return;
    }
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return;
    }
    let tty_file = fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
        .open("/proc/self/fd/0")
        .or_else(|_| {
            fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
                .open("/dev/tty")
        });
    if let Ok(mut tty) = tty_file {
        let _ = tty.write_all(text.as_bytes());
        let _ = tty.flush();
    }
}

/// Async-signal-safe POSIX handler restoring terminal `ECHO` if the process receives
/// `SIGINT` / `SIGTERM` / `SIGHUP` / `SIGQUIT` while blocked reading a secret token.
extern "C" fn restore_echo_signal_handler(sig: libc::c_int) {
    let fd = ACTIVE_TERMIOS_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &raw const SAVED_SIGNAL_TERMIOS);
            if !ACTIVE_PROMPT_JSON_MODE.load(Ordering::SeqCst) {
                let _ = libc::write(libc::STDERR_FILENO, b"\n".as_ptr().cast(), 1);
            }
        }
    }
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut dfl.sa_mask);
        let _ = libc::sigaction(sig, &dfl, std::ptr::null_mut());
        let _ = libc::raise(sig);
    }
}

/// RAII + POSIX signal guard restoring original `libc::termios` settings on both normal `Drop`
/// (returns, errors, panics) AND terminating signals (`SIGINT`/`SIGTERM`/`SIGHUP`/`SIGQUIT`).
/// Zero dependency on optional `crossterm`/`tui` features so `--no-default-features` builds
/// retain 100% of terminal echo-suppression and restoration protection!
struct TermiosEchoGuard {
    fd: RawFd,
    orig: libc::termios,
    prev_actions: [(libc::c_int, libc::sigaction); 4],
}

impl TermiosEchoGuard {
    fn install(fd: RawFd, orig: libc::termios) -> Self {
        unsafe {
            SAVED_SIGNAL_TERMIOS = orig;
        }
        ACTIVE_TERMIOS_FD.store(fd, Ordering::SeqCst);

        let mut prev_actions: [(libc::c_int, libc::sigaction); 4] = unsafe { std::mem::zeroed() };
        for (slot, &sig) in prev_actions.iter_mut().zip(GUARDED_SIGNALS.iter()) {
            let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
            sa.sa_sigaction = restore_echo_signal_handler as *const () as libc::sighandler_t;
            unsafe {
                libc::sigemptyset(&mut sa.sa_mask);
                sa.sa_flags = libc::SA_RESETHAND;
                let mut old: libc::sigaction = std::mem::zeroed();
                let _ = libc::sigaction(sig, &sa, &mut old);
                *slot = (sig, old);
            }
        }

        Self {
            fd,
            orig,
            prev_actions,
        }
    }
}

impl Drop for TermiosEchoGuard {
    fn drop(&mut self) {
        ACTIVE_TERMIOS_FD.store(-1, Ordering::SeqCst);
        unsafe {
            let _ = libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
            for (sig, prev) in &self.prev_actions {
                let _ = libc::sigaction(*sig, prev, std::ptr::null_mut());
            }
        }
    }
}

/// Read at most `max_bytes + 1` bytes up to `\n`, guaranteeing bounded heap allocation
/// BEFORE checking `max_bytes` even on an infinite newline-free stream!
pub fn read_bounded_line<R: BufRead>(
    reader: R,
    max_bytes: usize,
    label: &str,
) -> CliResult<String> {
    let mut buf = Vec::with_capacity(256.min(max_bytes.saturating_add(1)));
    let mut limited = reader.take((max_bytes as u64).saturating_add(1));
    limited
        .read_until(b'\n', &mut buf)
        .map_err(|e| CliError::io("secret_read_error", format!("Failed reading {label}: {e}")))?;
    if buf.len() > max_bytes {
        return Err(CliError::usage(format!(
            "{label} exceeds maximum allowed size ({max_bytes} bytes)."
        )));
    }
    String::from_utf8(buf).map_err(|_| CliError::usage(format!("{label} is not valid UTF-8.")))
}

/// Read a secret token interactively from a POSIX TTY with `ECHO` disabled.
/// Immediately refuses to proceed if `fd` is not a TTY or if `tcgetattr`/`tcsetattr` cannot disable echo.
pub fn read_secret_from_tty(prompt: &str) -> CliResult<String> {
    read_secret_from_tty_with_mode(prompt, false)
}

pub fn read_secret_from_tty_with_mode(prompt: &str, json_mode: bool) -> CliResult<String> {
    let _serial = TTY_PROMPT_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let stdin_fd: RawFd = libc::STDIN_FILENO;
    if unsafe { libc::isatty(stdin_fd) } != 1 {
        return Err(CliError::usage(
            "Interactive token entry requires a TTY with echo suppression. In non-interactive scripts/pipes, pass `--from-local`, `--stdin`, or `--token-file <PATH>` explicitly.",
        ));
    }

    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(stdin_fd, &mut orig) } != 0 {
        return Err(CliError::io(
            "termios_unavailable",
            "Refusing to read secret: `tcgetattr` failed on terminal.",
        ));
    }

    let mut no_echo = orig;
    no_echo.c_lflag &= !libc::ECHO;
    no_echo.c_lflag |= libc::ECHONL;

    ACTIVE_PROMPT_JSON_MODE.store(json_mode, Ordering::SeqCst);
    let _restore_guard = TermiosEchoGuard::install(stdin_fd, orig);

    if unsafe { libc::tcsetattr(stdin_fd, libc::TCSANOW, &no_echo) } != 0 {
        return Err(CliError::io(
            "termios_echo_disable_failed",
            "Refusing to read secret: `tcsetattr` failed to disable terminal echo.",
        ));
    }

    // Double-check that ECHO bit is genuinely cleared
    let mut check: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(stdin_fd, &mut check) } != 0 || (check.c_lflag & libc::ECHO) != 0 {
        return Err(CliError::io(
            "termios_echo_still_active",
            "Refusing to read secret: terminal refused to clear ECHO flag.",
        ));
    }

    write_interactive_prompt(json_mode, prompt);

    let stdin = io::stdin();
    let line = read_bounded_line(stdin.lock(), MAX_SECRET_BYTES, "Input token")?;

    let secret = line.trim().to_string();
    if secret.is_empty() {
        return Err(CliError::usage("Entered token cannot be empty."));
    }
    Ok(secret)
}

/// Split optional inline `# label` comment ONLY when `#` is preceded by ASCII whitespace,
/// preserving any literal `#` inside custom OAuth tokens that lack preceding whitespace.
fn split_whitespace_comment(trimmed: &str) -> (&str, Option<&str>) {
    let bytes = trimmed.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'#' && idx > 0 && bytes[idx - 1].is_ascii_whitespace() {
            return (trimmed[..idx].trim_end(), Some(trimmed[idx + 1..].trim()));
        }
    }
    (trimmed, None)
}

/// Parse one or more `refresh_token` lines from text (`--stdin` or `--token-file`),
/// skipping blank lines and `#` comment lines, and supporting optional inline `token # custom_label`.
pub fn parse_token_lines_from_text(
    raw: &str,
    source_label: &str,
) -> CliResult<Vec<(String, Option<String>)>> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (tok_part, comment_part) = split_whitespace_comment(trimmed);
        if tok_part.is_empty() {
            continue;
        }
        if tok_part.len() > MAX_SECRET_BYTES {
            return Err(CliError::usage(format!(
                "Refresh token in {source_label} exceeds maximum allowed size ({MAX_SECRET_BYTES} bytes)."
            )));
        }
        let inline_label = comment_part.filter(|s| !s.is_empty()).map(str::to_string);
        entries.push((tok_part.to_string(), inline_label));
    }
    if entries.is_empty() {
        return Err(CliError::usage(format!(
            "No refresh_token found in {source_label}."
        )));
    }
    Ok(entries)
}

pub fn read_secrets_from_stdin() -> CliResult<Vec<(String, Option<String>)>> {
    let stdin = io::stdin();
    let mut buf = Vec::with_capacity(1024);
    stdin
        .lock()
        .take((MAX_SECRET_BYTES as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| {
            CliError::io(
                "secret_read_error",
                format!("Failed reading `--stdin`: {e}"),
            )
        })?;
    if buf.len() > MAX_SECRET_BYTES {
        return Err(CliError::usage(format!(
            "`--stdin` input exceeds maximum allowed size ({MAX_SECRET_BYTES} bytes)."
        )));
    }
    let content = String::from_utf8(buf)
        .map_err(|_| CliError::usage("`--stdin` input is not valid UTF-8."))?;
    parse_token_lines_from_text(&content, "`--stdin`")
}

pub fn read_secret_from_stdin() -> CliResult<String> {
    let mut entries = read_secrets_from_stdin()?;
    Ok(entries.remove(0).0)
}

/// Read raw UTF-8 text from a private (`0600`) regular file up to `max_bytes`, rejecting symlinks,
/// FIFOs, directories, and group/world-accessible files (`mode & 0o077 != 0`) per Blueprint §8.2 rule 1.
fn read_private_file_content(path: &Path, max_bytes: usize) -> CliResult<String> {
    if crate::error::looks_like_secret_value(&path.to_string_lossy()) {
        return Err(CliError::usage(
            "`--token-file` expects a filesystem path to a private `0600` file, not a literal credential value (redacted).",
        ));
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::store::fs_atomic::ensure_no_symlink_ancestors(parent).map_err(|e| {
        if e.error_code == "data_error" {
            CliError::usage(format!(
                "Token file ancestor path must use real directories without symlinks: {}",
                e.message
            ))
        } else {
            e
        }
    })?;

    let pre_meta = fs::symlink_metadata(path).map_err(|e| {
        map_io_error(
            e,
            &format!("Cannot inspect token file '{}'", path.display()),
        )
    })?;
    if !pre_meta.file_type().is_file() {
        return Err(CliError::usage(format!(
            "Token file '{}' must be a regular file, not a symlink, FIFO, or directory.",
            path.display()
        )));
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                CliError::usage(format!(
                    "Token file '{}' must be a regular file, not a symlink.",
                    path.display()
                ))
            } else {
                map_io_error(e, &format!("Cannot open token file '{}'", path.display()))
            }
        })?;

    let meta = file
        .metadata()
        .map_err(|e| map_io_error(e, &format!("Cannot stat token file '{}'", path.display())))?;
    if !meta.file_type().is_file() {
        return Err(CliError::usage(format!(
            "Token file '{}' must be a regular file, not a FIFO, special device, or directory.",
            path.display()
        )));
    }
    crate::store::fs_atomic::verify_opened_regular_file_pinned(path, &meta, "Token file").map_err(
        |e| {
            if e.error_code == "data_error" {
                CliError::usage(e.message)
            } else {
                e
            }
        },
    )?;
    unsafe {
        use std::os::fd::AsRawFd;
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 && (flags & libc::O_NONBLOCK) != 0 {
            let _ = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
    let mode = meta.permissions().mode() & 0o777;
    if (mode & 0o077) != 0 {
        return Err(CliError::usage(format!(
            "Token file '{}' has insecure permissions ({mode:04o}). Run `chmod 600 \"{}\"` first.",
            path.display(),
            path.display()
        )));
    }
    if meta.len() > max_bytes as u64 {
        return Err(CliError::usage(format!(
            "Token file '{}' exceeds maximum allowed size ({max_bytes} bytes).",
            path.display()
        )));
    }

    let mut raw = Vec::with_capacity((meta.len() as usize).min(max_bytes));
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|e| map_io_error(e, &format!("Cannot read token file '{}'", path.display())))?;
    if raw.len() > max_bytes {
        return Err(CliError::usage(format!(
            "Token file '{}' exceeds maximum allowed size ({max_bytes} bytes).",
            path.display()
        )));
    }
    String::from_utf8(raw).map_err(|_| {
        CliError::usage(format!(
            "Token file '{}' is not valid UTF-8.",
            path.display()
        ))
    })
}

/// Read one or more refresh tokens (one per line) from a private (`0600`) regular file.
pub fn read_secrets_from_private_file(path: &Path) -> CliResult<Vec<(String, Option<String>)>> {
    let content = read_private_file_content(path, MAX_BATCH_SECRET_BYTES)?;
    parse_token_lines_from_text(&content, &format!("token file '{}'", path.display()))
}

/// Read a single secret token from a private (`0600`) regular file.
pub fn read_secret_from_private_file(path: &Path) -> CliResult<String> {
    let content = read_private_file_content(path, MAX_SECRET_BYTES)?;
    let secret = content.trim().to_string();
    if secret.is_empty() {
        return Err(CliError::usage(format!(
            "Token file '{}' is empty.",
            path.display()
        )));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_group_readable_and_symlink_token_files() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("tok.txt");
        fs::write(&file, "1//synthetic-token\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let err = read_secret_from_private_file(&file).unwrap_err();
        assert!(err.message.contains("chmod 600"));

        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let link = tmp.path().join("link.txt");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_secret_from_private_file(&link).is_err());

        assert_eq!(
            read_secret_from_private_file(&file).unwrap(),
            "1//synthetic-token"
        );

        // Accidental credential value passed to `--token-file` MUST NOT be echoed!
        let accidental_err =
            read_secret_from_private_file(Path::new("1//0gAccidentalTokenPassedAsPath"))
                .unwrap_err();
        assert!(!accidental_err
            .message
            .contains("AccidentalTokenPassedAsPath"));

        // Grandparent directory symlink MUST also be rejected!
        let real_gp = tmp.path().join("real_gp");
        let real_sub = real_gp.join("sub");
        fs::create_dir_all(&real_sub).unwrap();
        let nested_tok = real_sub.join("tok.txt");
        fs::write(&nested_tok, "1//nested-ok\n").unwrap();
        fs::set_permissions(&nested_tok, fs::Permissions::from_mode(0o600)).unwrap();
        let sym_gp = tmp.path().join("sym_gp");
        std::os::unix::fs::symlink(&real_gp, &sym_gp).unwrap();
        assert!(read_secret_from_private_file(&sym_gp.join("sub/tok.txt")).is_err());
    }

    #[test]
    fn read_bounded_line_caps_allocation_on_infinite_newline_free_stream() {
        let infinite = io::BufReader::new(io::repeat(b'A'));
        let err = read_bounded_line(infinite, MAX_SECRET_BYTES, "Stdin token").unwrap_err();
        assert!(err.message.contains("exceeds maximum allowed size"));

        let exact_ok = io::Cursor::new(format!("{}\n", "B".repeat(MAX_SECRET_BYTES - 1)));
        let line = read_bounded_line(exact_ok, MAX_SECRET_BYTES, "Stdin token").unwrap();
        assert_eq!(line.trim().len(), MAX_SECRET_BYTES - 1);
    }
}
