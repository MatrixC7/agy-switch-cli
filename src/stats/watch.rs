use crate::cli::args::{StatsWindowArgs, MAX_STATS_WATCH_INTERVAL_SECS};
use crate::cli::dto::terminal_text;
use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::stats::{
    collect_token_stats_list_with_now, collect_token_stats_with_now, is_strict_normalized_abs_path,
    resolve_stats_range_spec, truncate_display_width, StatsListViewDto, StatsSource, StatsViewDto,
    APP_DIR_NAME, CLI_DIR_NAME, CONVERSATIONS_DIR, GEMINI_DIR, TOKEN_ARCHIVE_FILE,
};
use crate::store::fs_atomic::{
    is_single_normal_filename, open_child_dir_nofollow, open_existing_dir_nofollow, ChildDirOpen,
};
use std::ffi::{CStr, CString, OsStr};
use std::io::{self, IsTerminal, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use unicode_width::UnicodeWidthStr;

static ACTIVE_WATCH_FD: AtomicI32 = AtomicI32::new(-1);
static mut SAVED_WATCH_TERMIOS: libc::termios = unsafe { std::mem::zeroed() };
const ENTER_ALT_AND_HIDE_CURSOR: &[u8] = b"\x1b[?1049h\x1b[?25l";
const LEAVE_ALT_AND_SHOW_CURSOR: &[u8] = b"\x1b[?25h\x1b[?1049l";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsWatchView {
    Summary,
    List,
}

impl StatsWatchView {
    pub fn toggle(self) -> Self {
        match self {
            Self::Summary => Self::List,
            Self::List => Self::Summary,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::List => "list",
        }
    }

    pub fn other_label(self) -> &'static str {
        match self {
            Self::Summary => "list",
            Self::List => "summary",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchKey {
    Quit,
    ToggleView,
    Refresh,
}

#[derive(Debug, Clone)]
enum CachedStatsSnapshot {
    Summary(Box<StatsViewDto>),
    List(Box<StatsListViewDto>),
}

impl CachedStatsSnapshot {
    fn render_for_width(&self, cols: usize) -> String {
        match self {
            Self::Summary(v) => v.render_human_for_width(Some(cols)),
            Self::List(v) => v.render_human_for_width(Some(cols)),
        }
    }
}

extern "C" fn restore_watch_sigquit_handler(sig: libc::c_int) {
    let fd = ACTIVE_WATCH_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            let _ = libc::write(
                libc::STDOUT_FILENO,
                LEAVE_ALT_AND_SHOW_CURSOR.as_ptr().cast(),
                LEAVE_ALT_AND_SHOW_CURSOR.len(),
            );
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &raw const SAVED_WATCH_TERMIOS);
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

struct WatchTerminalGuard {
    orig_termios: Option<libc::termios>,
    prev_sigquit: Option<libc::sigaction>,
}

impl WatchTerminalGuard {
    fn enter() -> CliResult<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(CliError::usage(
                "`agy-switch-cli stats --watch` requires an interactive terminal (TTY).",
            ));
        }

        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        let has_orig = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut orig) } == 0;
        let prev_sigquit = if has_orig {
            unsafe {
                SAVED_WATCH_TERMIOS = orig;
                ACTIVE_WATCH_FD.store(libc::STDIN_FILENO, Ordering::SeqCst);
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = restore_watch_sigquit_handler as *const () as libc::sighandler_t;
                libc::sigemptyset(&mut sa.sa_mask);
                sa.sa_flags = libc::SA_RESETHAND;
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(libc::SIGQUIT, &sa, &mut old) == 0 {
                    Some(old)
                } else {
                    None
                }
            }
        } else {
            None
        };

        if has_orig {
            let mut raw = orig;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
                let err = io::Error::last_os_error();
                ACTIVE_WATCH_FD.store(-1, Ordering::SeqCst);
                if let Some(ref old_sq) = prev_sigquit {
                    unsafe {
                        let _ = libc::sigaction(libc::SIGQUIT, old_sq, std::ptr::null_mut());
                    }
                }
                return Err(CliError::io(
                    "watch_termios_failed",
                    format!("Cannot configure terminal mode for `stats --watch`: {err}"),
                ));
            }
        }

        let mut out = io::stdout();
        if let Err(err) = out
            .write_all(ENTER_ALT_AND_HIDE_CURSOR)
            .and_then(|_| out.flush())
        {
            if has_orig {
                unsafe {
                    let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &orig);
                }
            }
            ACTIVE_WATCH_FD.store(-1, Ordering::SeqCst);
            if let Some(ref old_sq) = prev_sigquit {
                unsafe {
                    let _ = libc::sigaction(libc::SIGQUIT, old_sq, std::ptr::null_mut());
                }
            }
            return Err(CliError::io(
                "watch_alt_screen_failed",
                format!("Cannot initialize alternate terminal screen: {err}"),
            ));
        }

        Ok(Self {
            orig_termios: has_orig.then_some(orig),
            prev_sigquit,
        })
    }
}

impl Drop for WatchTerminalGuard {
    fn drop(&mut self) {
        // Restore alternate screen and termios while the idempotent SIGQUIT handler is still armed,
        // then disarm ACTIVE_WATCH_FD and restore the previous SIGQUIT disposition.
        let mut out = io::stdout();
        let _ = out.write_all(LEAVE_ALT_AND_SHOW_CURSOR);
        let _ = out.flush();
        if let Some(ref orig) = self.orig_termios {
            unsafe {
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
            }
        }
        ACTIVE_WATCH_FD.store(-1, Ordering::SeqCst);
        if let Some(ref old_sq) = self.prev_sigquit {
            unsafe {
                let _ = libc::sigaction(libc::SIGQUIT, old_sq, std::ptr::null_mut());
            }
        }
    }
}

fn resolve_winsize(ioctl_rc: libc::c_int, ws_col: u16, ws_row: u16) -> (usize, usize) {
    if ioctl_rc == 0 {
        (usize::from(ws_col), usize::from(ws_row))
    } else {
        (120, 24)
    }
}

fn current_terminal_size() -> (usize, usize) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    resolve_winsize(rc, ws.ws_col, ws.ws_row)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollRead {
    Byte(u8),
    Timeout,
    EofOrError,
}

fn poll_read_stdin_byte(timeout_ms: libc::c_int, stop: &AtomicBool) -> PollRead {
    loop {
        if stop.load(Ordering::Relaxed) {
            return PollRead::Timeout;
        }
        let mut pfd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return PollRead::EofOrError;
        }
        if rc == 0 {
            return PollRead::Timeout;
        }
        if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
            && (pfd.revents & libc::POLLIN) == 0
        {
            return PollRead::EofOrError;
        }
        if (pfd.revents & libc::POLLIN) == 0 {
            return PollRead::Timeout;
        }
        let mut byte = 0u8;
        let n = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                (&mut byte as *mut u8).cast::<libc::c_void>(),
                1,
            )
        };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return PollRead::EofOrError;
        }
        return PollRead::Byte(byte);
    }
}

/// Decode one keypress or a single escape sequence without swallowing subsequent keys.
fn decode_next_watch_key<F>(pending_byte: &mut Option<u8>, mut read_byte: F) -> Option<WatchKey>
where
    F: FnMut(libc::c_int) -> PollRead,
{
    let first = if let Some(b) = pending_byte.take() {
        PollRead::Byte(b)
    } else {
        read_byte(50)
    };
    let byte = match first {
        PollRead::Byte(b) => b,
        PollRead::Timeout => return None,
        PollRead::EofOrError => return Some(WatchKey::Quit),
    };

    match byte {
        b'q' | b'Q' | 0x03 => Some(WatchKey::Quit),
        b'\t' => Some(WatchKey::ToggleView),
        b'r' | b'R' => Some(WatchKey::Refresh),
        0x1b => {
            // Distinguish a standalone Esc keypress (15ms timeout) from a single CSI/SS3/OSC/Alt sequence.
            match read_byte(15) {
                PollRead::Timeout | PollRead::EofOrError => Some(WatchKey::Quit),
                PollRead::Byte(b'[') => {
                    // CSI: ESC [ <param 0x30..=0x3F>* <interm 0x20..=0x2F>* <final 0x40..=0x7E>
                    for _ in 0..32 {
                        match read_byte(5) {
                            PollRead::Byte(b) if (0x40..=0x7E).contains(&b) => break,
                            PollRead::Byte(b) if (0x20..=0x3F).contains(&b) => continue,
                            PollRead::Byte(b) => {
                                *pending_byte = Some(b);
                                break;
                            }
                            PollRead::Timeout | PollRead::EofOrError => break,
                        }
                    }
                    None
                }
                PollRead::Byte(b'O') => {
                    // SS3: ESC O <final 0x20..=0x7E>
                    match read_byte(5) {
                        PollRead::Byte(b) if (0x20..=0x7E).contains(&b) => {}
                        PollRead::Byte(b) => {
                            *pending_byte = Some(b);
                        }
                        PollRead::Timeout | PollRead::EofOrError => {}
                    }
                    None
                }
                PollRead::Byte(b'P' | b']' | b'X' | b'^' | b'_') => {
                    // DCS / OSC / SOS / PM / APC terminated by BEL (0x07) or ST (ESC \)
                    for _ in 0..64 {
                        match read_byte(5) {
                            PollRead::Byte(0x07) | PollRead::Timeout | PollRead::EofOrError => {
                                break
                            }
                            PollRead::Byte(0x1b) => match read_byte(5) {
                                PollRead::Byte(b'\\') => break,
                                PollRead::Byte(other) => {
                                    *pending_byte = Some(other);
                                    break;
                                }
                                PollRead::Timeout | PollRead::EofOrError => break,
                            },
                            PollRead::Byte(_) => continue,
                        }
                    }
                    None
                }
                PollRead::Byte(b) if (0x20..=0x7E).contains(&b) => {
                    // Single-byte Alt+<printable> sequence: consume only `b`.
                    None
                }
                PollRead::Byte(b) => {
                    // Control byte immediately following ESC (e.g. Ctrl+C, Tab, another ESC): preserve it.
                    *pending_byte = Some(b);
                    None
                }
            }
        }
        _ => None,
    }
}

fn spawn_stdin_key_listener(
    stop: Arc<AtomicBool>,
) -> (
    mpsc::UnboundedReceiver<WatchKey>,
    Option<std::thread::JoinHandle<()>>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = std::thread::Builder::new()
        .name("agy-stats-watch-keys".into())
        .spawn(move || {
            let mut pending_byte: Option<u8> = None;
            while !stop.load(Ordering::Relaxed) {
                if let Some(key) = decode_next_watch_key(&mut pending_byte, |timeout_ms| {
                    poll_read_stdin_byte(timeout_ms, &stop)
                }) {
                    let is_quit = key == WatchKey::Quit;
                    let _ = tx.send(key);
                    if is_quit {
                        break;
                    }
                }
            }
        })
        .ok();
    (rx, handle)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StatMeta {
    dev: u64,
    ino: u64,
    mode: u32,
    size: i64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatsWatchFingerprint {
    entries: Vec<(String, StatMeta)>,
}

#[allow(clippy::unnecessary_cast)]
fn stat_from_raw(st: &libc::stat) -> StatMeta {
    StatMeta {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        mode: st.st_mode as u32,
        size: st.st_size as i64,
        mtime: st.st_mtime as i64,
        mtime_nsec: st.st_mtime_nsec as i64,
        ctime: st.st_ctime as i64,
        ctime_nsec: st.st_ctime_nsec as i64,
    }
}

#[allow(clippy::unnecessary_cast)]
fn fstat_dir_identity(fd: &OwnedFd) -> Option<StatMeta> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0 {
        // Track directory identity and permissions only so unrelated sibling files
        // do not invalidate the SQLite fingerprint via directory mtime/ctime bumps.
        Some(StatMeta {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mode: st.st_mode as u32,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
        })
    } else {
        None
    }
}

fn fstatat_nofollow(dir_fd: &OwnedFd, name: &OsStr) -> Result<Option<StatMeta>, ()> {
    let Ok(c_name) = CString::new(name.as_bytes()) else {
        return Ok(None);
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            c_name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(Some(stat_from_raw(&st)))
    } else {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ENOENT || errno == libc::ENOTDIR {
            Ok(None)
        } else {
            Err(())
        }
    }
}

fn is_watched_sqlite_filename(raw_name: &[u8]) -> bool {
    (raw_name.ends_with(b".db") && raw_name.len() > 3)
        || (raw_name.ends_with(b".db-wal") && raw_name.len() > 7)
        || (raw_name.ends_with(b".db-shm") && raw_name.len() > 7)
}

fn scan_client_dir_fingerprint(
    gemini_fd: &OwnedFd,
    client_dir_name: &str,
    include_archive: bool,
    entries: &mut Vec<(String, StatMeta)>,
) -> Result<(), ()> {
    let client_fd = match open_child_dir_nofollow(gemini_fd, client_dir_name, false) {
        ChildDirOpen::Opened(fd) => fd,
        ChildDirOpen::Absent | ChildDirOpen::Unsafe => return Ok(()),
        ChildDirOpen::IoError => return Err(()),
    };
    entries.push((
        format!("dir:{client_dir_name}"),
        fstat_dir_identity(&client_fd).ok_or(())?,
    ));

    if include_archive {
        for suffix in ["", "-wal", "-shm"] {
            let fname = format!("{TOKEN_ARCHIVE_FILE}{suffix}");
            if let Some(meta) = fstatat_nofollow(&client_fd, OsStr::new(&fname))? {
                entries.push((format!("file:{client_dir_name}/{fname}"), meta));
            }
        }
    }

    let conv_fd = match open_child_dir_nofollow(&client_fd, CONVERSATIONS_DIR, true) {
        ChildDirOpen::Opened(fd) => fd,
        ChildDirOpen::Absent | ChildDirOpen::Unsafe => return Ok(()),
        ChildDirOpen::IoError => return Err(()),
    };
    entries.push((
        format!("dir:{client_dir_name}/{CONVERSATIONS_DIR}"),
        fstat_dir_identity(&conv_fd).ok_or(())?,
    ));

    let dup_raw = unsafe { libc::fcntl(conv_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_raw < 0 {
        return Err(());
    }
    let dir_ptr = unsafe { libc::fdopendir(dup_raw) };
    if dir_ptr.is_null() {
        unsafe {
            let _ = libc::close(dup_raw);
        }
        return Err(());
    }

    struct DirGuard(*mut libc::DIR);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::closedir(self.0);
            }
        }
    }
    let _guard = DirGuard(dir_ptr);

    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let ent = unsafe { libc::readdir(dir_ptr) };
        if ent.is_null() {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != 0 {
                return Err(());
            }
            break;
        }
        let raw_name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if raw_name == b"." || raw_name == b".." || !is_single_normal_filename(raw_name) {
            continue;
        }
        if !is_watched_sqlite_filename(raw_name) {
            continue;
        }
        let os_name = OsStr::from_bytes(raw_name);
        if let Some(meta) = fstatat_nofollow(&conv_fd, os_name)? {
            entries.push((
                format!(
                    "file:{client_dir_name}/{CONVERSATIONS_DIR}/{}",
                    String::from_utf8_lossy(raw_name)
                ),
                meta,
            ));
        }
    }

    Ok(())
}

/// Pure read-only, zero-symlink-following metadata fingerprint of watched SQLite sources.
/// Returns `None` on transient I/O errors so callers conservatively force a full scan.
pub(crate) fn compute_stats_watch_fingerprint(
    home_dir: &Path,
    source: StatsSource,
) -> Option<StatsWatchFingerprint> {
    if !is_strict_normalized_abs_path(home_dir) {
        return Some(StatsWatchFingerprint {
            entries: Vec::new(),
        });
    }
    let home_fd = match open_existing_dir_nofollow(home_dir) {
        Ok(Some(fd)) => fd,
        Ok(None) => {
            return Some(StatsWatchFingerprint {
                entries: Vec::new(),
            })
        }
        Err(e) if e.error_code == "data_error" => {
            return Some(StatsWatchFingerprint {
                entries: Vec::new(),
            })
        }
        Err(_) => return None,
    };
    let gemini_fd = match open_child_dir_nofollow(&home_fd, GEMINI_DIR, false) {
        ChildDirOpen::Opened(fd) => fd,
        ChildDirOpen::Absent | ChildDirOpen::Unsafe => {
            return Some(StatsWatchFingerprint {
                entries: Vec::new(),
            })
        }
        ChildDirOpen::IoError => return None,
    };

    let mut entries = Vec::new();
    entries.push((format!("dir:{GEMINI_DIR}"), fstat_dir_identity(&gemini_fd)?));

    if matches!(source, StatsSource::Cli | StatsSource::All) {
        scan_client_dir_fingerprint(&gemini_fd, CLI_DIR_NAME, false, &mut entries).ok()?;
    }
    if matches!(source, StatsSource::App | StatsSource::All) {
        scan_client_dir_fingerprint(&gemini_fd, APP_DIR_NAME, true, &mut entries).ok()?;
    }

    entries.sort();
    Some(StatsWatchFingerprint { entries })
}

fn format_watch_footer(
    view: StatsWatchView,
    interval_secs: u64,
    updated_hms: &str,
    cols: usize,
) -> String {
    let full = format!(
        "Live [{}]: every {}s · updated {} · Tab {} · r refresh · q/Esc quit",
        view.label(),
        interval_secs,
        updated_hms,
        view.other_label()
    );
    if UnicodeWidthStr::width(full.as_str()) <= cols {
        return full;
    }
    let medium = format!(
        "Live [{}] {}s · {} · Tab {} · r · q",
        view.label(),
        interval_secs,
        updated_hms,
        view.other_label()
    );
    if UnicodeWidthStr::width(medium.as_str()) <= cols {
        return medium;
    }
    let compact = format!("Live [{}] {}s · Tab · r · q", view.label(), interval_secs);
    truncate_display_width(&compact, cols).0
}

/// Compose a height- and width-bounded frame guaranteed not to wrap or scroll row 0 off-screen.
pub(crate) fn build_watch_frame(
    rendered_body: &str,
    view: StatsWatchView,
    interval_secs: u64,
    updated_hms: &str,
    transient_warning: Option<&str>,
    cols: usize,
    rows: usize,
) -> String {
    if cols == 0 || rows == 0 {
        return String::new();
    }

    let footer = format_watch_footer(view, interval_secs, updated_hms, cols);
    if rows == 1 {
        return footer;
    }

    let mut footer_lines: Vec<String> = Vec::with_capacity(2);
    if let Some(warn) = transient_warning.filter(|w| !w.trim().is_empty()) {
        if rows >= 3 {
            let clean = terminal_text(warn)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let warn_line = format!("Warning: {clean} (retrying)");
            footer_lines.push(truncate_display_width(&warn_line, cols).0);
        }
    }
    footer_lines.push(footer);

    let body_budget = rows.saturating_sub(footer_lines.len());
    let raw_body_lines: Vec<&str> = rendered_body.lines().collect();
    let mut out_lines: Vec<String> = Vec::with_capacity(rows);

    if raw_body_lines.len() <= body_budget {
        for line in &raw_body_lines {
            out_lines.push(truncate_display_width(line, cols).0);
        }
        if !raw_body_lines.is_empty() && raw_body_lines.len() < body_budget {
            out_lines.push(String::new());
        }
    } else if body_budget >= 2 {
        let kept = body_budget - 1;
        let omitted = raw_body_lines.len() - kept;
        for line in raw_body_lines.iter().take(kept) {
            out_lines.push(truncate_display_width(line, cols).0);
        }
        let trunc_note = format!("... ({omitted} more line(s) — resize terminal to view)");
        out_lines.push(truncate_display_width(&trunc_note, cols).0);
    } else if body_budget == 1 {
        if let Some(first) = raw_body_lines.first() {
            out_lines.push(truncate_display_width(first, cols).0);
        }
    }

    out_lines.extend(footer_lines);
    out_lines.truncate(rows);
    out_lines.join("\n")
}

fn write_ansi_watch_frame(frame: &str) -> CliResult<()> {
    let mut buf = String::with_capacity(frame.len() + 128);
    buf.push_str("\x1b[H");
    for (idx, line) in frame.split('\n').enumerate() {
        if idx > 0 {
            buf.push_str("\r\n");
        }
        buf.push_str(line);
        buf.push_str("\x1b[K");
    }
    buf.push_str("\x1b[J");

    let mut out = io::stdout();
    out.write_all(buf.as_bytes())
        .and_then(|_| out.flush())
        .map_err(|e| {
            CliError::io(
                "watch_draw_failed",
                format!("Failed to draw watch frame: {e}"),
            )
        })
}

fn collect_snapshot_sync(
    paths: &HeadlessPaths,
    args: &StatsWindowArgs,
    view: StatsWatchView,
    now: &jiff::Zoned,
) -> CliResult<CachedStatsSnapshot> {
    match view {
        StatsWatchView::Summary => collect_token_stats_with_now(paths, args, now)
            .map(Box::new)
            .map(CachedStatsSnapshot::Summary),
        StatsWatchView::List => collect_token_stats_list_with_now(paths, args, now)
            .map(Box::new)
            .map(CachedStatsSnapshot::List),
    }
}

fn now_local_hms_and_date() -> (String, jiff::civil::Date) {
    let now = jiff::Zoned::now();
    (now.strftime("%H:%M:%S").to_string(), now.date())
}

/// Interactive read-only live monitor for `stats summary --watch` and `stats list --watch`.
/// Preserves zero-write SQLite guarantees, skips full SQLite rescans when metadata fingerprints
/// are unchanged, supports `Tab` view toggling, `r` manual refresh, `SIGWINCH` resize redraw,
/// and signal-safe terminal restoration.
pub async fn run_stats_watch(
    paths: &HeadlessPaths,
    args: &StatsWindowArgs,
    initial_view: StatsWatchView,
    interval_secs: u64,
) -> CliResult<()> {
    if !(1..=MAX_STATS_WATCH_INTERVAL_SECS).contains(&interval_secs) {
        return Err(CliError::usage(format!(
            "`--watch` interval must be between 1 and {MAX_STATS_WATCH_INTERVAL_SECS} seconds."
        )));
    }
    // Fail fast on invalid `--date`/`--from`/`--to`/`--recent` and non-TTY before touching signals or terminal state.
    let _ = resolve_stats_range_spec(args, jiff::Zoned::now().date())?;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(CliError::usage(
            "`agy-switch-cli stats --watch` requires an interactive terminal (TTY).",
        ));
    }

    // Install catchable signal listeners BEFORE mutating termios or entering alternate screen
    // so signals arriving during terminal startup cannot bypass `WatchTerminalGuard::drop`.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();

    let _term_guard = WatchTerminalGuard::enter()?;

    let stop_keys = Arc::new(AtomicBool::new(false));
    let (mut key_rx, key_thread) = spawn_stdin_key_listener(Arc::clone(&stop_keys));

    let source: StatsSource = args.source.into();
    let mut active_view = initial_view;
    let mut cached_snapshot: Option<CachedStatsSnapshot> = None;
    let mut last_fingerprint: Option<StatsWatchFingerprint> = None;
    let mut last_date: Option<jiff::civil::Date> = None;
    let mut transient_warning: Option<String> = None;
    let mut last_updated_hms = now_local_hms_and_date().0;

    let period = Duration::from_secs(interval_secs);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut need_scan = true;
    let mut need_redraw = true;

    loop {
        if need_scan {
            let paths_c = paths.clone();
            let args_c = args.clone();
            let view_c = active_view;
            let home_c = paths.home_dir.clone();

            let mut scan_handle = tokio::task::spawn_blocking(move || {
                let scan_now = jiff::Zoned::now();
                let scan_date = scan_now.date();
                let fp = compute_stats_watch_fingerprint(&home_c, source);
                let res = collect_snapshot_sync(&paths_c, &args_c, view_c, &scan_now);
                (scan_date, fp, res)
            });

            let mut aborted_early = false;
            let mut follow_up_scan = false;
            let scan_outcome = loop {
                tokio::select! {
                    res = &mut scan_handle => {
                        break Some(res);
                    }
                    _ = async {
                        match sigint.as_mut() {
                            Some(s) => { s.recv().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        aborted_early = true;
                        break None;
                    }
                    _ = async {
                        match sigterm.as_mut() {
                            Some(s) => { s.recv().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        aborted_early = true;
                        break None;
                    }
                    _ = async {
                        match sighup.as_mut() {
                            Some(s) => { s.recv().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        aborted_early = true;
                        break None;
                    }
                    maybe_key = key_rx.recv() => {
                        match maybe_key {
                            None | Some(WatchKey::Quit) => {
                                aborted_early = true;
                                break None;
                            }
                            Some(WatchKey::ToggleView) => {
                                active_view = active_view.toggle();
                                follow_up_scan = true;
                            }
                            Some(WatchKey::Refresh) => {
                                follow_up_scan = true;
                            }
                        }
                    }
                }
            };
            if aborted_early {
                break;
            }
            if let Some(join_res) = scan_outcome {
                let (hms, finish_date) = now_local_hms_and_date();
                last_updated_hms = hms;
                match join_res {
                    Ok((scan_date, fp, Ok(snap))) => {
                        cached_snapshot = Some(snap);
                        last_fingerprint = fp;
                        last_date = Some(scan_date);
                        transient_warning = None;
                        if finish_date != scan_date {
                            // Local midnight elapsed mid-scan: rescan immediately for the new day
                            // so stale previous-day `today` rows are never cached as the new date.
                            follow_up_scan = true;
                        }
                    }
                    Ok((_, _, Err(err))) => {
                        transient_warning = Some(err.message);
                    }
                    Err(join_err) => {
                        transient_warning = Some(format!("Stats refresh task failed: {join_err}"));
                    }
                }
            }
            need_scan = follow_up_scan;
            need_redraw = true;
            if follow_up_scan {
                ticker.reset();
                continue;
            }
        }

        if need_redraw {
            let (cols, rows) = current_terminal_size();
            let frame = if cols == 0 || rows == 0 {
                String::new()
            } else {
                let body = cached_snapshot
                    .as_ref()
                    .map(|s| s.render_for_width(cols))
                    .unwrap_or_default();
                build_watch_frame(
                    &body,
                    active_view,
                    interval_secs,
                    &last_updated_hms,
                    transient_warning.as_deref(),
                    cols,
                    rows,
                )
            };
            if write_ansi_watch_frame(&frame).is_err() {
                break;
            }
            need_redraw = false;
        }

        tokio::select! {
            _ = ticker.tick() => {
                let (hms, today) = now_local_hms_and_date();
                let home_c = paths.home_dir.clone();
                let fp_opt = tokio::task::spawn_blocking(move || {
                    compute_stats_watch_fingerprint(&home_c, source)
                })
                .await
                .ok()
                .flatten();

                let date_changed = last_date != Some(today);
                let fp_changed = match (&last_fingerprint, &fp_opt) {
                    (Some(prev), Some(curr)) => prev != curr,
                    _ => true,
                };
                if date_changed || fp_changed || transient_warning.is_some() || cached_snapshot.is_none() {
                    need_scan = true;
                } else {
                    last_updated_hms = hms;
                    need_redraw = true;
                }
            }
            _ = async {
                match sigwinch.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                need_redraw = true;
            }
            _ = async {
                match sigint.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                break;
            }
            _ = async {
                match sigterm.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                break;
            }
            _ = async {
                match sighup.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                break;
            }
            maybe_key = key_rx.recv() => {
                match maybe_key {
                    None | Some(WatchKey::Quit) => break,
                    Some(WatchKey::ToggleView) => {
                        active_view = active_view.toggle();
                        ticker.reset();
                        need_scan = true;
                    }
                    Some(WatchKey::Refresh) => {
                        ticker.reset();
                        need_scan = true;
                    }
                }
            }
        }
    }

    stop_keys.store(true, Ordering::Relaxed);
    if let Some(handle) = key_thread {
        let _ = handle.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn build_watch_frame_respects_height_width_truncation_and_footer_modes() {
        let body =
            "Source : all\nRange  : today\n\nSummary\n  line 1\n  line 2\n  line 3\n  line 4";

        // Generous terminal: full body + blank spacer + full footer
        let full = build_watch_frame(body, StatsWatchView::Summary, 3, "10:52:14", None, 100, 15);
        let lines: Vec<&str> = full.lines().collect();
        assert!(lines.len() <= 15);
        assert!(lines.last().unwrap().contains(
            "Live [summary]: every 3s · updated 10:52:14 · Tab list · r refresh · q/Esc quit"
        ));
        assert!(full.contains("  line 4"));

        // Short terminal: strictly bounded to `rows` with truncation indicator
        let short = build_watch_frame(body, StatsWatchView::List, 3, "10:52:14", None, 80, 5);
        let short_lines: Vec<&str> = short.lines().collect();
        assert_eq!(short_lines.len(), 5);
        assert!(short_lines[3].contains("more line(s)"));
        assert!(short_lines[4].contains("Live [list]:"));
        assert!(short_lines[4].contains("Tab summary"));

        // Narrow terminal + transient warning
        let narrow = build_watch_frame(
            body,
            StatsWatchView::Summary,
            5,
            "10:52:14",
            Some("SQLite busy\x1b[31m"),
            36,
            6,
        );
        let narrow_lines: Vec<&str> = narrow.lines().collect();
        assert!(narrow_lines.len() <= 6);
        for l in &narrow_lines {
            assert!(
                UnicodeWidthStr::width(*l) <= 36,
                "line exceeded 36 cols: `{l}`"
            );
            assert!(!l.contains('\x1b'));
        }
        assert!(narrow.contains("Warning:"));

        // Ultra-tiny terminals: never panic or exceed row/col budgets
        assert_eq!(
            build_watch_frame(body, StatsWatchView::Summary, 3, "10:52:14", None, 0, 10),
            ""
        );
        assert_eq!(
            build_watch_frame(body, StatsWatchView::Summary, 3, "10:52:14", None, 80, 0),
            ""
        );
        let one_row = build_watch_frame(body, StatsWatchView::Summary, 3, "10:52:14", None, 40, 1);
        assert_eq!(one_row.lines().count(), 1);
        assert!(UnicodeWidthStr::width(one_row.as_str()) <= 40);
    }

    #[test]
    fn watch_fingerprint_detects_db_wal_archive_changes_and_ignores_unrelated_files() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        let app_dir = home.join(".gemini/antigravity");
        let app_conv = app_dir.join("conversations");
        fs::create_dir_all(&cli_conv).unwrap();
        fs::create_dir_all(&app_conv).unwrap();

        let fp0_all = compute_stats_watch_fingerprint(home, StatsSource::All).unwrap();
        let fp0_cli = compute_stats_watch_fingerprint(home, StatsSource::Cli).unwrap();

        // Unrelated text file in conversations/ does not alter fingerprint
        fs::write(cli_conv.join("notes.txt"), b"hello").unwrap();
        assert_eq!(
            compute_stats_watch_fingerprint(home, StatsSource::Cli).unwrap(),
            fp0_cli
        );

        // Creating a `.db` changes CLI & All fingerprints
        let db_path = cli_conv.join("conv1.db");
        fs::write(&db_path, b"sqlite-stub").unwrap();
        let fp1_cli = compute_stats_watch_fingerprint(home, StatsSource::Cli).unwrap();
        assert_ne!(fp1_cli, fp0_cli);
        assert_ne!(
            compute_stats_watch_fingerprint(home, StatsSource::All).unwrap(),
            fp0_all
        );

        // Writing WAL sidecar alters fingerprint
        let wal_path = cli_conv.join("conv1.db-wal");
        fs::write(&wal_path, b"wal-frame-1").unwrap();
        let fp2_cli = compute_stats_watch_fingerprint(home, StatsSource::Cli).unwrap();
        assert_ne!(fp2_cli, fp1_cli);

        // Updating app archive affects App & All, NOT Cli
        fs::write(app_dir.join("token_usage_archive.db"), b"arch-v1").unwrap();
        assert_eq!(
            compute_stats_watch_fingerprint(home, StatsSource::Cli).unwrap(),
            fp2_cli
        );
        let fp1_app = compute_stats_watch_fingerprint(home, StatsSource::App).unwrap();
        fs::write(app_dir.join("token_usage_archive.db"), b"arch-v2-longer").unwrap();
        let fp2_app = compute_stats_watch_fingerprint(home, StatsSource::App).unwrap();
        assert_ne!(fp2_app, fp1_app);

        // Symlinked `.gemini` directory is treated safely (empty fingerprint, never followed)
        let sym_tmp = tempfile::tempdir().unwrap();
        symlink(home.join(".gemini"), sym_tmp.path().join(".gemini")).unwrap();
        let sym_fp = compute_stats_watch_fingerprint(sym_tmp.path(), StatsSource::All).unwrap();
        assert!(sym_fp.entries.is_empty());
    }

    #[test]
    fn resolve_winsize_preserves_zero_dimensions_on_ioctl_success_and_falls_back_on_error() {
        assert_eq!(resolve_winsize(0, 100, 24), (100, 24));
        assert_eq!(resolve_winsize(0, 0, 5), (0, 5));
        assert_eq!(resolve_winsize(0, 80, 0), (80, 0));
        assert_eq!(resolve_winsize(0, 0, 0), (0, 0));
        assert_eq!(resolve_winsize(-1, 0, 0), (120, 24));
        assert_eq!(resolve_winsize(-1, 80, 24), (120, 24));
    }

    #[test]
    fn decode_next_watch_key_consumes_single_escape_sequence_without_swallowing_following_keys() {
        let decode_all = |events: Vec<PollRead>| -> Vec<WatchKey> {
            let mut idx = 0usize;
            let mut pending = None;
            let mut keys = Vec::new();
            while idx < events.len() || pending.is_some() {
                if let Some(k) = decode_next_watch_key(&mut pending, |_| {
                    if idx < events.len() {
                        let ev = events[idx];
                        idx += 1;
                        ev
                    } else {
                        PollRead::Timeout
                    }
                }) {
                    keys.push(k);
                }
            }
            keys
        };

        // Standalone Esc followed by 15ms timeout quits cleanly.
        assert_eq!(
            decode_all(vec![PollRead::Byte(0x1b), PollRead::Timeout]),
            vec![WatchKey::Quit]
        );

        // Standalone CSI up-arrow does not quit.
        assert_eq!(
            decode_all(vec![
                PollRead::Byte(0x1b),
                PollRead::Byte(b'['),
                PollRead::Byte(b'A'),
            ]),
            vec![]
        );

        // CSI arrow immediately followed by Tab preserves Tab.
        assert_eq!(
            decode_all(vec![
                PollRead::Byte(0x1b),
                PollRead::Byte(b'['),
                PollRead::Byte(b'A'),
                PollRead::Byte(b'\t'),
            ]),
            vec![WatchKey::ToggleView]
        );

        // Parameterized CSI (Ctrl+Up) + Tab, Function key (F5) + r, SS3 Up + Tab, OSC + Tab.
        let mut seq = Vec::new();
        for b in b"\x1b[1;5A\t\x1b[15~r\x1bOA\t\x1b]0;win\x07\t\x1b]0;st\x1b\\\t" {
            seq.push(PollRead::Byte(*b));
        }
        assert_eq!(
            decode_all(seq),
            vec![
                WatchKey::ToggleView,
                WatchKey::Refresh,
                WatchKey::ToggleView,
                WatchKey::ToggleView,
                WatchKey::ToggleView,
            ]
        );

        // Alt+q is ignored while subsequent plain `q` quits; broken CSI + Ctrl+C preserves Ctrl+C.
        let mut alt_then_q = Vec::new();
        for b in b"\x1bqq" {
            alt_then_q.push(PollRead::Byte(*b));
        }
        assert_eq!(decode_all(alt_then_q), vec![WatchKey::Quit]);
        assert_eq!(
            decode_all(vec![
                PollRead::Byte(0x1b),
                PollRead::Byte(b'['),
                PollRead::Byte(0x03),
            ]),
            vec![WatchKey::Quit]
        );
    }
}
