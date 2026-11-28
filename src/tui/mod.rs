use crate::cli::dto::{
    extract_quota_group_descriptions, extract_supported_models, format_bar_and_pct, format_pct,
    format_relative_age, format_reset_local, format_runtime_state_human,
    format_session_identity_human, format_unix_local_minute, format_window_label, terminal_text,
    AccountViewDto,
};
use crate::domain::account::DisableReasonCode;
use crate::domain::quota::{
    evaluate_account_quota, is_empty_quota_placeholder, is_unused_full_bucket_reset_time,
    observed_quota_percentage, quota_pool, QuotaEval, QuotaPool, DEFAULT_QUOTA_MAX_AGE_SECS,
};
use crate::error::{CliError, CliResult};
use crate::oauth::registry::OAuthClientRegistry;
use crate::quota::official_cli::refresh_active_slot_quota_via_official_cli_with_proxy;
use crate::session::backend::{CredentialBackend, SlotInspectState};
use crate::session::journal::reconcile_pending_journal_before_write;
use crate::session::payload::resolve_session_identity;
use crate::session::process::observe_runtime_state;
use crate::store::repository::StoreRepository;
use crate::store::transfer::export_transfer_bundle_file;
use crate::switching::executor::{
    execute_account_delete, execute_switch, slot_matches_selected_rotated_account, SwitchOptions,
};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, CellAlignment, ContentArrangement, Table};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, Clear, ClearType},
};
use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

static ACTIVE_TUI_FD: AtomicI32 = AtomicI32::new(-1);
static mut SAVED_TUI_TERMIOS: libc::termios = unsafe { std::mem::zeroed() };
const LEAVE_ALT_AND_SHOW_CURSOR: &[u8] = b"\x1b[?25h\x1b[?1049l";

extern "C" fn restore_tui_sigquit_handler(sig: libc::c_int) {
    let fd = ACTIVE_TUI_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            let _ = libc::write(
                libc::STDOUT_FILENO,
                LEAVE_ALT_AND_SHOW_CURSOR.as_ptr().cast(),
                LEAVE_ALT_AND_SHOW_CURSOR.len(),
            );
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &raw const SAVED_TUI_TERMIOS);
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

struct RawModeGuard {
    orig_termios: Option<libc::termios>,
    prev_sigquit: Option<libc::sigaction>,
}

impl RawModeGuard {
    fn enter() -> CliResult<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(CliError::usage(
                "`agy-switch-cli tui` requires an interactive terminal (TTY).",
            ));
        }

        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        let has_orig = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut orig) } == 0;
        let prev_sigquit = if has_orig {
            unsafe {
                SAVED_TUI_TERMIOS = orig;
                ACTIVE_TUI_FD.store(libc::STDIN_FILENO, Ordering::SeqCst);
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = restore_tui_sigquit_handler as *const () as libc::sighandler_t;
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

        if let Err(e) = terminal::enable_raw_mode() {
            ACTIVE_TUI_FD.store(-1, Ordering::SeqCst);
            if let Some(ref old_sq) = prev_sigquit {
                unsafe {
                    let _ = libc::sigaction(libc::SIGQUIT, old_sq, std::ptr::null_mut());
                }
            }
            return Err(CliError::io(
                "tui_raw_mode_failed",
                format!("Cannot enable terminal raw mode: {e}"),
            ));
        }
        let _ = execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide);
        Ok(Self {
            orig_termios: has_orig.then_some(orig),
            prev_sigquit,
        })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        ACTIVE_TUI_FD.store(-1, Ordering::SeqCst);
        let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
        let _ = io::stdout().flush();
        let _ = terminal::disable_raw_mode();
        if let Some(ref orig) = self.orig_termios {
            unsafe {
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
            }
        }
        if let Some(ref old_sq) = self.prev_sigquit {
            unsafe {
                let _ = libc::sigaction(libc::SIGQUIT, old_sq, std::ptr::null_mut());
            }
        }
    }
}

pub const TUI_KEYS_LINE_1: &str =
    "Keys   : ↑/↓ select · g/G top/end · [/] reorder · Space mark · Enter/s switch · i info · q/Esc quit";
pub const TUI_KEYS_LINE_2: &str =
    "Manage : r refresh (on *) · e/E enable · d/D disable · l label · o/O export · x delete";
pub const TUI_KEYS_HELP_LINE: &str =
    "Keys: ↑/↓ select · g/G top/end · [/] reorder · Space mark · Enter/s switch · i info · r refresh (*) · e/E enable · d/D disable · l label · o/O export · x delete · q/Esc quit";
const TUI_DETAIL_KEYS_LINE_ACTIVE: &str =
    "Keys   : ←/→ account · ↑/↓ scroll · Space mark · l label · r refresh · Enter/s switch · i/Esc back · q quit";
const TUI_DETAIL_KEYS_LINE_DORMANT: &str =
    "Keys   : ←/→ account · ↑/↓ scroll · Space mark · l label · Enter/s switch · i/Esc back · q quit";
const TUI_DORMANT_REFRESH_HINT: &str =
    "Switch to this account first (press 's'), then press 'r' to refresh active quota.";
const TRANSIENT_INFO_TTL: Duration = Duration::from_secs(3);
const TRANSIENT_ERROR_TTL: Duration = Duration::from_secs(5);
const MAX_TUI_LABEL_CHARS: usize = 64;
const MAX_TUI_EXPORT_PATH_CHARS: usize = 512;

#[derive(Debug, Clone)]
enum PendingTuiConfirm {
    DeleteAccount {
        account_id: String,
        email: String,
        clear_active_slot: bool,
    },
    DeleteMarked {
        account_ids: Vec<String>,
        includes_active: bool,
    },
    DisableAll {
        enabled_count: usize,
    },
    DisableMarked {
        account_ids: Vec<String>,
    },
    ExportBundle {
        account_ids: Vec<String>,
        output_path: PathBuf,
    },
}

const EXPORT_CONFIRM_MIN_COLS: usize = 23; // `"Status: PLAINTEXT [y/N]"`
const EXPORT_CONFIRM_MIN_ROWS: usize = 2;

fn export_confirm_warning_fits(cols: usize, rows: usize) -> bool {
    cols >= EXPORT_CONFIRM_MIN_COLS && rows >= EXPORT_CONFIRM_MIN_ROWS
}

fn rendered_frame_shows_export_plaintext_warning(frame: &str) -> bool {
    frame
        .lines()
        .any(|line| line.contains("PLAINTEXT") && line.contains("[y/N]"))
}

fn export_path_looks_like_secret(raw: &str, home_dir: &Path) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    if crate::error::path_looks_like_accidental_secret(Path::new(trimmed)) {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix("~/") {
        let rest_clean = rest.trim_start_matches('/');
        if !rest_clean.is_empty()
            && crate::error::path_looks_like_accidental_secret(Path::new(rest_clean))
        {
            return true;
        }
    }
    if let Ok(expanded) = expand_tui_export_path(trimmed, home_dir) {
        if crate::error::path_looks_like_accidental_secret(&expanded) {
            return true;
        }
    }
    false
}

impl PendingTuiConfirm {
    fn prompt_message_for_cols(&self, term_cols: usize) -> String {
        match self {
            Self::DeleteAccount {
                email,
                clear_active_slot,
                ..
            } => {
                if *clear_active_slot {
                    format!(
                        "Delete active account {} and clear active agy slot? Press 'y' to confirm (any other key cancels).",
                        terminal_text(email)
                    )
                } else {
                    format!(
                        "Delete account {}? Press 'y' to confirm (any other key cancels).",
                        terminal_text(email)
                    )
                }
            }
            Self::DeleteMarked {
                account_ids,
                includes_active,
            } => {
                let count = account_ids.len();
                if *includes_active {
                    format!(
                        "Delete {count} marked account(s) (including active agy slot)? Press 'y' to confirm (any other key cancels)."
                    )
                } else {
                    format!(
                        "Delete {count} marked account(s)? Press 'y' to confirm (any other key cancels)."
                    )
                }
            }
            Self::DisableAll { enabled_count } => format!(
                "Disable all {enabled_count} account(s)? Press 'y' to confirm (any other key cancels)."
            ),
            Self::DisableMarked { account_ids } => format!(
                "Disable {} marked account(s)? Press 'y' to confirm (any other key cancels).",
                account_ids.len()
            ),
            Self::ExportBundle {
                account_ids,
                output_path,
            } => {
                let avail_cols = term_cols.saturating_sub("Status: ".len());
                let safe_path = if crate::error::path_looks_like_accidental_secret(output_path) {
                    "[REDACTED]".to_string()
                } else {
                    terminal_text(&output_path.to_string_lossy())
                };
                if avail_cols >= 32 {
                    format!(
                        "PLAINTEXT tokens [y/N]: export {} to {} (0600)",
                        account_ids.len(),
                        safe_path
                    )
                } else if avail_cols >= 22 {
                    "PLAINTEXT tokens [y/N]".to_string()
                } else {
                    "PLAINTEXT [y/N]".to_string()
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum PendingTuiInput {
    ExportPath {
        account_ids: Vec<String>,
        scope_label: String,
        buffer: String,
    },
    EditLabel {
        account_id: String,
        email: String,
        buffer: String,
    },
}

impl PendingTuiInput {
    fn prompt_message(&self, home_dir: &Path) -> String {
        match self {
            Self::ExportPath {
                scope_label,
                buffer,
                ..
            } => {
                if export_path_looks_like_secret(buffer, home_dir) {
                    format!(
                        "Export {} path: [REDACTED]_  (Ctrl+U clear / Esc)",
                        terminal_text(scope_label)
                    )
                } else {
                    format!(
                        "Export {} path: {}_  (Enter/Esc)",
                        terminal_text(scope_label),
                        terminal_text(buffer)
                    )
                }
            }
            Self::EditLabel { email, buffer, .. } => format!(
                "Label for {} (empty clears): {}_  (Enter/Esc)",
                terminal_text(email),
                terminal_text(buffer)
            ),
        }
    }

    fn max_chars(&self) -> usize {
        match self {
            Self::ExportPath { .. } => MAX_TUI_EXPORT_PATH_CHARS,
            Self::EditLabel { .. } => MAX_TUI_LABEL_CHARS,
        }
    }

    fn buffer_mut(&mut self) -> &mut String {
        match self {
            Self::ExportPath { buffer, .. } | Self::EditLabel { buffer, .. } => buffer,
        }
    }

    fn push_char(&mut self, ch: char) {
        if ch.is_control() {
            return;
        }
        let cap = self.max_chars();
        let buf = self.buffer_mut();
        if buf.chars().count() < cap {
            buf.push(ch);
        }
    }

    fn pop_grapheme(&mut self) {
        let buf = self.buffer_mut();
        if let Some((idx, _)) =
            UnicodeSegmentation::grapheme_indices(buf.as_str(), true).next_back()
        {
            buf.truncate(idx);
        }
    }

    fn clear(&mut self) {
        self.buffer_mut().clear();
    }
}

fn default_tui_export_path(cwd: &Path, now_unix: i64) -> String {
    let stamp = jiff::Timestamp::from_second(now_unix)
        .ok()
        .map(|ts| {
            ts.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y%m%d-%H%M%S")
                .to_string()
        })
        .unwrap_or_else(|| now_unix.to_string());
    let base = format!("agy-export-{stamp}");
    let first_name = format!("{base}.json");
    if std::fs::symlink_metadata(cwd.join(&first_name)).is_err() {
        return format!("./{first_name}");
    }
    for n in 2..=999 {
        let cand = format!("{base}-{n}.json");
        if std::fs::symlink_metadata(cwd.join(&cand)).is_err() {
            return format!("./{cand}");
        }
    }
    format!("./{base}-new.json")
}

fn expand_tui_export_path(raw: &str, home_dir: &Path) -> CliResult<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::usage("Export path cannot be empty."));
    }
    if trimmed == "~" {
        return Err(CliError::usage(
            "Export path must point to a file, not a directory.",
        ));
    }
    if let Some(rest) = trimmed.strip_prefix("~/") {
        let rest = rest.trim_start_matches('/');
        if rest.is_empty() {
            return Err(CliError::usage(
                "Export path must point to a file, not a directory.",
            ));
        }
        return Ok(home_dir.join(rest));
    }
    Ok(PathBuf::from(trimmed))
}

#[derive(Debug, Clone, Default)]
struct TransientStatus {
    message: Option<(String, Instant)>,
}

impl TransientStatus {
    fn set_info(&mut self, msg: String, now: Instant) {
        self.message = Some((msg, now + TRANSIENT_INFO_TTL));
    }

    fn set_error(&mut self, msg: String, now: Instant) {
        self.message = Some((msg, now + TRANSIENT_ERROR_TTL));
    }

    /// Clears the transient notice once its deadline has elapsed; returns `true` when state changed.
    fn expire_if_due(&mut self, now: Instant) -> bool {
        if let Some((_, deadline)) = &self.message {
            if now >= *deadline {
                self.message = None;
                return true;
            }
        }
        false
    }

    fn active_text(&self) -> Option<&str> {
        self.message.as_ref().map(|(msg, _)| msg.as_str())
    }
}

fn resolve_tui_targets<'a>(
    accounts: &'a [crate::domain::account::AccountRecord],
    cursor_idx: usize,
    marked_ids: &HashSet<String>,
) -> (Vec<&'a crate::domain::account::AccountRecord>, bool) {
    if !marked_ids.is_empty() {
        let marked: Vec<&crate::domain::account::AccountRecord> = accounts
            .iter()
            .filter(|a| marked_ids.contains(&a.id))
            .collect();
        if !marked.is_empty() {
            return (marked, true);
        }
    }
    match accounts.get(cursor_idx) {
        Some(acc) => (vec![acc], false),
        None => (Vec::new(), false),
    }
}

enum InputKeyOutcome {
    Continue(PendingTuiInput),
    Finished,
}

fn apply_pending_input_key(
    mut inp: PendingTuiInput,
    key: crossterm::event::KeyEvent,
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    pending_confirm: &mut Option<PendingTuiConfirm>,
    export_confirm_warning_rendered: &mut bool,
    transient_status: &mut TransientStatus,
) -> InputKeyOutcome {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        inp.clear();
        return InputKeyOutcome::Continue(inp);
    }
    match key.code {
        KeyCode::Esc => {
            let msg = match inp {
                PendingTuiInput::ExportPath { .. } => "Canceled export.",
                PendingTuiInput::EditLabel { .. } => "Canceled label edit.",
            };
            transient_status.set_info(msg.into(), Instant::now());
            InputKeyOutcome::Finished
        }
        KeyCode::Backspace => {
            inp.pop_grapheme();
            InputKeyOutcome::Continue(inp)
        }
        KeyCode::Enter => {
            match inp {
                PendingTuiInput::ExportPath {
                    account_ids,
                    buffer,
                    ..
                } => {
                    if export_path_looks_like_secret(&buffer, &repo.paths().home_dir) {
                        transient_status.set_error(
                            "Export error: Export path expects a filesystem file path, not a literal credential value (redacted)."
                                .into(),
                            Instant::now(),
                        );
                    } else {
                        match expand_tui_export_path(&buffer, &repo.paths().home_dir) {
                            Ok(output_path) => {
                                let (cols, rows) = current_terminal_size();
                                if !export_confirm_warning_fits(cols as usize, rows as usize) {
                                    transient_status.set_error(
                                        "Export canceled: terminal too small to display PLAINTEXT export warning."
                                            .into(),
                                        Instant::now(),
                                    );
                                } else {
                                    *pending_confirm = Some(PendingTuiConfirm::ExportBundle {
                                        account_ids,
                                        output_path,
                                    });
                                    *export_confirm_warning_rendered = false;
                                }
                            }
                            Err(e) => {
                                transient_status.set_error(
                                    format!("Export error: {}", terminal_text(&e.message)),
                                    Instant::now(),
                                );
                            }
                        }
                    }
                }
                PendingTuiInput::EditLabel {
                    account_id,
                    email,
                    buffer,
                } => {
                    update_label_in_tui(
                        repo,
                        backend,
                        &account_id,
                        &email,
                        &buffer,
                        transient_status,
                    );
                }
            }
            InputKeyOutcome::Finished
        }
        KeyCode::Char(ch)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            inp.push_char(ch);
            InputKeyOutcome::Continue(inp)
        }
        _ => InputKeyOutcome::Continue(inp),
    }
}

/// Optional interactive SSH dashboard (`#[cfg(feature = "tui")]`).
/// Strictly delegates ALL mutations to the application service layer (`execute_switch`,
/// `refresh_active_slot_quota_via_official_cli`, `repo.with_write_lock`,
/// `export_transfer_bundle_file`) and integrates OS signal streams
/// (`SIGTERM`, `SIGINT`, `SIGHUP`, `SIGQUIT`) so terminal `ECHO` and alternate screen are reliably
/// restored even on external signal termination!
pub async fn run_interactive_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    explicit_file_backend: bool,
    proxy_override: Option<String>,
) -> CliResult<()> {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

    let _guard = RawModeGuard::enter()?;
    let mut cursor_idx: usize = 0;
    let mut scroll_offset: usize = 0;
    let mut detail_view = false;
    let mut detail_scroll: usize = 0;
    let mut marked_ids: HashSet<String> = HashSet::new();
    let mut transient_status = TransientStatus::default();
    let mut pending_confirm: Option<PendingTuiConfirm> = None;
    let mut export_confirm_warning_rendered = false;
    let mut pending_input: Option<PendingTuiInput> = None;
    let mut last_redraw = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut force_redraw = true;

    loop {
        if pending_input.is_none()
            && pending_confirm.is_none()
            && transient_status.expire_if_due(Instant::now())
        {
            force_redraw = true;
        }

        if force_redraw || last_redraw.elapsed() >= Duration::from_millis(250) {
            let snap = repo.read_snapshot()?;
            let slot_state = backend.inspect_slot(repo.paths());
            let session_id = resolve_session_identity(&slot_state, &snap);
            let rotated_active_id =
                resolve_rotated_selected_active_id(repo, &snap, &slot_state, &session_id);
            let runtime_st = observe_runtime_state(repo.paths());
            let now_unix = crate::domain::clock::current_unix_seconds();

            marked_ids.retain(|id| snap.accounts.iter().any(|a| &a.id == id));

            if snap.accounts.is_empty() {
                cursor_idx = 0;
                detail_view = false;
                detail_scroll = 0;
                pending_confirm = None;
                pending_input = None;
            } else {
                if cursor_idx >= snap.accounts.len() {
                    cursor_idx = snap.accounts.len() - 1;
                    detail_scroll = 0;
                }
                match &mut pending_input {
                    Some(PendingTuiInput::EditLabel { account_id, .. }) => {
                        if !snap.accounts.iter().any(|a| &a.id == account_id) {
                            pending_input = None;
                        }
                    }
                    Some(PendingTuiInput::ExportPath { account_ids, .. }) => {
                        account_ids.retain(|id| snap.accounts.iter().any(|a| &a.id == id));
                        if account_ids.is_empty() {
                            pending_input = None;
                        }
                    }
                    None => {}
                }
                match &mut pending_confirm {
                    Some(PendingTuiConfirm::DeleteAccount { account_id, .. }) => {
                        if !snap.accounts.iter().any(|a| &a.id == account_id) {
                            pending_confirm = None;
                        }
                    }
                    Some(PendingTuiConfirm::DeleteMarked { account_ids, .. })
                    | Some(PendingTuiConfirm::DisableMarked { account_ids })
                    | Some(PendingTuiConfirm::ExportBundle { account_ids, .. }) => {
                        account_ids.retain(|id| snap.accounts.iter().any(|a| &a.id == id));
                        if account_ids.is_empty() {
                            pending_confirm = None;
                        }
                    }
                    Some(PendingTuiConfirm::DisableAll { enabled_count }) => {
                        let live_enabled = snap.accounts.iter().filter(|a| !a.disabled).count();
                        if live_enabled == 0 {
                            pending_confirm = None;
                        } else {
                            *enabled_count = live_enabled;
                        }
                    }
                    None => {}
                }
            }

            let (term_cols, term_rows) = current_terminal_size();
            let input_msg = pending_input
                .as_ref()
                .map(|inp| inp.prompt_message(&repo.paths().home_dir));
            let confirm_msg = pending_confirm
                .as_ref()
                .map(|c| c.prompt_message_for_cols(term_cols as usize));
            let transient_with_marks = transient_status.active_text().map(|msg| {
                if !marked_ids.is_empty() && !msg.contains("marked") {
                    format!("{msg} ({} marked)", marked_ids.len())
                } else {
                    msg.to_string()
                }
            });
            let notice = input_msg
                .as_deref()
                .or(confirm_msg.as_deref())
                .or(transient_with_marks.as_deref());

            let rendered_frame = render_dashboard_full_with_size(
                &mut TuiFrameView {
                    accounts: &snap.accounts,
                    session_id: &session_id,
                    rotated_active_id: rotated_active_id.as_deref(),
                    runtime_st: &runtime_st,
                    backend_tag: backend.name(),
                    marked_ids: &marked_ids,
                    detail_view,
                    detail_scroll: &mut detail_scroll,
                    cursor_idx,
                    scroll_offset: &mut scroll_offset,
                    transient_notice: notice,
                    now_unix,
                },
                term_cols,
                term_rows,
            )?;
            export_confirm_warning_rendered =
                matches!(
                    pending_confirm,
                    Some(PendingTuiConfirm::ExportBundle { .. })
                ) && export_confirm_warning_fits(term_cols as usize, term_rows as usize)
                    && rendered_frame_shows_export_plaintext_warning(&rendered_frame);
            last_redraw = Instant::now();
            force_redraw = false;
        }

        if !event::poll(Duration::ZERO)
            .map_err(|e| CliError::io("tui_poll_error", format!("TUI event poll error: {e}")))?
        {
            tokio::select! {
                _ = async {
                    if let Some(ref mut s) = sigterm { let _ = s.recv().await; }
                    else { std::future::pending::<()>().await; }
                } => break,
                _ = async {
                    if let Some(ref mut s) = sigint { let _ = s.recv().await; }
                    else { std::future::pending::<()>().await; }
                } => break,
                _ = async {
                    if let Some(ref mut s) = sighup { let _ = s.recv().await; }
                    else { std::future::pending::<()>().await; }
                } => break,
                _ = tokio::time::sleep(Duration::from_millis(20)) => continue,
            }
        }

        let ev = event::read()
            .map_err(|e| CliError::io("tui_read_error", format!("TUI event read error: {e}")))?;
        let key = match ev {
            Event::Resize(_, _) => {
                export_confirm_warning_rendered = false;
                force_redraw = true;
                continue;
            }
            Event::Key(k) if k.kind == KeyEventKind::Press => k,
            _ => continue,
        };

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'C'))
        {
            break;
        }

        if let Some(mut inp) = pending_input.take() {
            force_redraw = true;
            let mut current_key = key;
            let mut drained = 0usize;
            let mut quit_tui = false;
            while let InputKeyOutcome::Continue(next_inp) = apply_pending_input_key(
                inp,
                current_key,
                repo,
                backend,
                &mut pending_confirm,
                &mut export_confirm_warning_rendered,
                &mut transient_status,
            ) {
                inp = next_inp;
                if drained >= 1024 || !event::poll(Duration::ZERO).unwrap_or(false) {
                    pending_input = Some(inp);
                    break;
                }
                match event::read() {
                    Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                        if k.modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(k.code, KeyCode::Char('c' | 'C'))
                        {
                            quit_tui = true;
                            break;
                        }
                        current_key = k;
                        drained += 1;
                    }
                    Ok(Event::Resize(_, _)) => {
                        export_confirm_warning_rendered = false;
                        pending_input = Some(inp);
                        break;
                    }
                    Ok(_) => {
                        pending_input = Some(inp);
                        break;
                    }
                    Err(e) => {
                        return Err(CliError::io(
                            "tui_read_error",
                            format!("TUI event read error: {e}"),
                        ));
                    }
                }
            }
            if quit_tui {
                break;
            }
            continue;
        }

        if let Some(pending) = pending_confirm.take() {
            force_redraw = true;
            let warning_was_visible = export_confirm_warning_rendered;
            export_confirm_warning_rendered = false;
            let confirmed = matches!(key.code, KeyCode::Char('y' | 'Y'))
                && !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
            match pending {
                PendingTuiConfirm::DeleteAccount {
                    account_id,
                    email,
                    clear_active_slot,
                } => {
                    if confirmed {
                        let deleted_ok = delete_account_in_tui(
                            repo,
                            backend,
                            &account_id,
                            &email,
                            clear_active_slot,
                            &mut cursor_idx,
                            &mut transient_status,
                        );
                        if deleted_ok {
                            marked_ids.remove(&account_id);
                        }
                    } else {
                        transient_status
                            .set_info("Canceled account deletion.".into(), Instant::now());
                    }
                }
                PendingTuiConfirm::DeleteMarked { account_ids, .. } => {
                    if confirmed {
                        let deleted_ids = delete_marked_accounts_in_tui(
                            repo,
                            backend,
                            &account_ids,
                            &mut cursor_idx,
                            &mut transient_status,
                        );
                        for id in deleted_ids {
                            marked_ids.remove(&id);
                        }
                    } else {
                        transient_status
                            .set_info("Canceled deleting marked accounts.".into(), Instant::now());
                    }
                }
                PendingTuiConfirm::DisableAll { .. } => {
                    if confirmed {
                        disable_all_accounts_in_tui(repo, backend, &mut transient_status);
                    } else {
                        transient_status
                            .set_info("Canceled disabling all accounts.".into(), Instant::now());
                    }
                }
                PendingTuiConfirm::DisableMarked { account_ids } => {
                    if confirmed {
                        disable_marked_accounts_in_tui(
                            repo,
                            backend,
                            &account_ids,
                            &mut transient_status,
                        );
                    } else {
                        transient_status
                            .set_info("Canceled disabling marked accounts.".into(), Instant::now());
                    }
                }
                PendingTuiConfirm::ExportBundle {
                    account_ids,
                    output_path,
                } => {
                    let (live_cols, live_rows) = current_terminal_size();
                    if confirmed {
                        if !warning_was_visible
                            || !export_confirm_warning_fits(live_cols as usize, live_rows as usize)
                        {
                            transient_status.set_error(
                                "Export canceled: terminal too small to display PLAINTEXT export warning."
                                    .into(),
                                Instant::now(),
                            );
                        } else {
                            export_accounts_in_tui(
                                repo,
                                &output_path,
                                &account_ids,
                                &mut transient_status,
                            );
                        }
                    } else {
                        transient_status.set_info("Canceled export.".into(), Instant::now());
                    }
                }
            }
            continue;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('d' | 'D'))
        {
            break;
        }

        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            continue;
        }

        let snap = repo.read_snapshot()?;
        let slot_state = backend.inspect_slot(repo.paths());
        let session_id = resolve_session_identity(&slot_state, &snap);
        let rotated_active_id =
            resolve_rotated_selected_active_id(repo, &snap, &slot_state, &session_id);
        let runtime_st = observe_runtime_state(repo.paths());
        marked_ids.retain(|id| snap.accounts.iter().any(|a| &a.id == id));
        if snap.accounts.is_empty() {
            cursor_idx = 0;
            detail_view = false;
            detail_scroll = 0;
        } else if cursor_idx >= snap.accounts.len() {
            cursor_idx = snap.accounts.len() - 1;
        }
        force_redraw = true;

        if detail_view {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('i') | KeyCode::Esc => {
                    detail_view = false;
                    detail_scroll = 0;
                }
                KeyCode::Left => {
                    if cursor_idx > 0 {
                        cursor_idx -= 1;
                        detail_scroll = 0;
                    }
                }
                KeyCode::Right => {
                    if !snap.accounts.is_empty() && cursor_idx + 1 < snap.accounts.len() {
                        cursor_idx += 1;
                        detail_scroll = 0;
                    }
                }
                KeyCode::Up => {
                    detail_scroll = detail_scroll.saturating_sub(1);
                }
                KeyCode::Down => {
                    detail_scroll = detail_scroll.saturating_add(1);
                }
                KeyCode::PageUp => {
                    detail_scroll = detail_scroll.saturating_sub(5);
                }
                KeyCode::PageDown => {
                    detail_scroll = detail_scroll.saturating_add(5);
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    detail_scroll = 0;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    detail_scroll = usize::MAX;
                }
                KeyCode::Char(' ') => {
                    if let Some(target) = snap.accounts.get(cursor_idx) {
                        if !marked_ids.remove(&target.id) {
                            marked_ids.insert(target.id.clone());
                        }
                    }
                }
                KeyCode::Char('l') => {
                    if let Some(target) = snap.accounts.get(cursor_idx) {
                        let initial = target
                            .custom_label
                            .as_deref()
                            .map(|s| terminal_text(s).trim().to_string())
                            .unwrap_or_default();
                        pending_input = Some(PendingTuiInput::EditLabel {
                            account_id: target.id.clone(),
                            email: target.email.clone(),
                            buffer: initial,
                        });
                    }
                }
                KeyCode::Enter | KeyCode::Char('s') => {
                    if let Some(target) = snap.accounts.get(cursor_idx) {
                        run_single_switch_in_tui(
                            repo,
                            backend,
                            &snap,
                            &session_id,
                            rotated_active_id.as_deref(),
                            &runtime_st,
                            &marked_ids,
                            true,
                            &mut detail_scroll,
                            cursor_idx,
                            &mut scroll_offset,
                            target,
                            &mut transient_status,
                        );
                    }
                }
                KeyCode::Char('r') => {
                    let interrupted = run_r_refresh_in_tui(
                        repo,
                        backend,
                        explicit_file_backend,
                        proxy_override.as_deref(),
                        &snap,
                        &session_id,
                        rotated_active_id.as_deref(),
                        &runtime_st,
                        &marked_ids,
                        true,
                        &mut detail_scroll,
                        cursor_idx,
                        &mut scroll_offset,
                        &mut transient_status,
                        &mut sigterm,
                        &mut sigint,
                        &mut sighup,
                    )
                    .await;
                    if interrupted {
                        break;
                    }
                }
                _ => {
                    force_redraw = false;
                }
            }
            continue;
        }

        match key.code {
            KeyCode::Char('q') => break,
            KeyCode::Esc => {
                if !marked_ids.is_empty() {
                    marked_ids.clear();
                } else {
                    break;
                }
            }
            KeyCode::Char(' ') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    if !marked_ids.remove(&target.id) {
                        marked_ids.insert(target.id.clone());
                    }
                }
            }
            KeyCode::Char('i') => {
                if snap.accounts.is_empty() {
                    transient_status.set_info("No account to inspect.".into(), Instant::now());
                } else {
                    detail_view = true;
                    detail_scroll = 0;
                }
            }
            KeyCode::Char('l') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    let initial = target
                        .custom_label
                        .as_deref()
                        .map(|s| terminal_text(s).trim().to_string())
                        .unwrap_or_default();
                    pending_input = Some(PendingTuiInput::EditLabel {
                        account_id: target.id.clone(),
                        email: target.email.clone(),
                        buffer: initial,
                    });
                } else {
                    transient_status.set_info("No account to label.".into(), Instant::now());
                }
            }
            KeyCode::Char('o') => {
                let (targets, from_marked) =
                    resolve_tui_targets(&snap.accounts, cursor_idx, &marked_ids);
                if targets.is_empty() {
                    transient_status.set_info("No accounts to export.".into(), Instant::now());
                } else {
                    let cwd =
                        std::env::current_dir().unwrap_or_else(|_| repo.paths().home_dir.clone());
                    let default_path =
                        default_tui_export_path(&cwd, crate::domain::clock::current_unix_seconds());
                    let scope_label = if from_marked {
                        format!("{} marked account(s)", targets.len())
                    } else {
                        terminal_text(&targets[0].email)
                    };
                    let account_ids: Vec<String> = targets.iter().map(|a| a.id.clone()).collect();
                    pending_input = Some(PendingTuiInput::ExportPath {
                        account_ids,
                        scope_label,
                        buffer: default_path,
                    });
                }
            }
            KeyCode::Char('O') => {
                if snap.accounts.is_empty() {
                    transient_status.set_info("No accounts to export.".into(), Instant::now());
                } else {
                    let cwd =
                        std::env::current_dir().unwrap_or_else(|_| repo.paths().home_dir.clone());
                    let default_path =
                        default_tui_export_path(&cwd, crate::domain::clock::current_unix_seconds());
                    let account_ids: Vec<String> =
                        snap.accounts.iter().map(|a| a.id.clone()).collect();
                    pending_input = Some(PendingTuiInput::ExportPath {
                        scope_label: format!("all {} account(s)", account_ids.len()),
                        account_ids,
                        buffer: default_path,
                    });
                }
            }
            KeyCode::Home | KeyCode::Char('g') => {
                cursor_idx = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                if !snap.accounts.is_empty() {
                    cursor_idx = snap.accounts.len() - 1;
                }
            }
            KeyCode::PageUp => {
                cursor_idx = cursor_idx.saturating_sub(5);
            }
            KeyCode::PageDown => {
                if !snap.accounts.is_empty() {
                    cursor_idx = (cursor_idx + 5).min(snap.accounts.len() - 1);
                }
            }
            KeyCode::Char('[') => {
                reorder_selected_in_tui(
                    repo,
                    backend,
                    &snap.accounts,
                    &mut cursor_idx,
                    true,
                    &mut transient_status,
                );
            }
            KeyCode::Char(']') => {
                reorder_selected_in_tui(
                    repo,
                    backend,
                    &snap.accounts,
                    &mut cursor_idx,
                    false,
                    &mut transient_status,
                );
            }
            KeyCode::Up => {
                cursor_idx = cursor_idx.saturating_sub(1);
            }
            KeyCode::Down => {
                if !snap.accounts.is_empty() && cursor_idx + 1 < snap.accounts.len() {
                    cursor_idx += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char('s') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    run_single_switch_in_tui(
                        repo,
                        backend,
                        &snap,
                        &session_id,
                        rotated_active_id.as_deref(),
                        &runtime_st,
                        &marked_ids,
                        false,
                        &mut detail_scroll,
                        cursor_idx,
                        &mut scroll_offset,
                        target,
                        &mut transient_status,
                    );
                }
            }
            KeyCode::Char('r') => {
                let interrupted = run_r_refresh_in_tui(
                    repo,
                    backend,
                    explicit_file_backend,
                    proxy_override.as_deref(),
                    &snap,
                    &session_id,
                    rotated_active_id.as_deref(),
                    &runtime_st,
                    &marked_ids,
                    false,
                    &mut detail_scroll,
                    cursor_idx,
                    &mut scroll_offset,
                    &mut transient_status,
                    &mut sigterm,
                    &mut sigint,
                    &mut sighup,
                )
                .await;
                if interrupted {
                    break;
                }
            }
            KeyCode::Char('e') => {
                let (targets, from_marked) =
                    resolve_tui_targets(&snap.accounts, cursor_idx, &marked_ids);
                if from_marked && targets.len() >= 2 {
                    let ids: Vec<String> = targets.iter().map(|a| a.id.clone()).collect();
                    enable_marked_accounts_in_tui(repo, backend, &ids, &mut transient_status);
                } else if let Some(target) = targets.first().copied() {
                    let now_unix = crate::domain::clock::current_unix_seconds();
                    let res = reconcile_pending_journal_before_write(repo, backend, now_unix)
                        .and_then(|_| {
                            repo.with_write_lock(|tx| tx.mark_account_enabled(&target.id))
                        });
                    let done_at = Instant::now();
                    match res {
                        Ok(_) => transient_status.set_info(
                            format!("Enabled {}.", terminal_text(&target.email)),
                            done_at,
                        ),
                        Err(e) => transient_status
                            .set_error(format!("Error: {}", terminal_text(&e.message)), done_at),
                    }
                }
            }
            KeyCode::Char('E') => {
                if snap.accounts.is_empty() {
                    transient_status.set_info("No accounts to enable.".into(), Instant::now());
                } else {
                    enable_all_accounts_in_tui(repo, backend, &mut transient_status);
                }
            }
            KeyCode::Char('d') => {
                let (targets, from_marked) =
                    resolve_tui_targets(&snap.accounts, cursor_idx, &marked_ids);
                if from_marked && targets.len() >= 2 {
                    let ids: Vec<String> = targets.iter().map(|a| a.id.clone()).collect();
                    pending_confirm = Some(PendingTuiConfirm::DisableMarked { account_ids: ids });
                } else if let Some(target) = targets.first().copied() {
                    let now_unix = crate::domain::clock::current_unix_seconds();
                    let res = reconcile_pending_journal_before_write(repo, backend, now_unix)
                        .and_then(|_| {
                            repo.with_write_lock(|tx| {
                                tx.mark_account_disabled(
                                    &target.id,
                                    crate::domain::account::DisableReasonCode::Manual,
                                    Some("Disabled in TUI".into()),
                                    now_unix,
                                )
                            })
                        });
                    let done_at = Instant::now();
                    match res {
                        Ok(_) => transient_status.set_info(
                            format!("Disabled {}.", terminal_text(&target.email)),
                            done_at,
                        ),
                        Err(e) => transient_status
                            .set_error(format!("Error: {}", terminal_text(&e.message)), done_at),
                    }
                }
            }
            KeyCode::Char('D') => {
                if snap.accounts.is_empty() {
                    transient_status.set_info("No accounts to disable.".into(), Instant::now());
                } else {
                    let enabled_count = snap.accounts.iter().filter(|a| !a.disabled).count();
                    if enabled_count == 0 {
                        transient_status
                            .set_info("All accounts are already disabled.".into(), Instant::now());
                    } else {
                        pending_confirm = Some(PendingTuiConfirm::DisableAll { enabled_count });
                    }
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                let (targets, from_marked) =
                    resolve_tui_targets(&snap.accounts, cursor_idx, &marked_ids);
                if targets.is_empty() {
                    transient_status.set_info("No accounts to delete.".into(), Instant::now());
                } else if from_marked && targets.len() >= 2 {
                    let includes_active = targets.iter().any(|t| {
                        snap.index.selected_account_id.as_deref() == Some(t.id.as_str())
                            || matches!(
                                &session_id,
                                crate::domain::account::SessionIdentity::Matched { account_id, .. }
                                    | crate::domain::account::SessionIdentity::DriftedKnown { account_id, .. }
                                    if account_id == &t.id
                            )
                    });
                    pending_confirm = Some(PendingTuiConfirm::DeleteMarked {
                        account_ids: targets.iter().map(|a| a.id.clone()).collect(),
                        includes_active,
                    });
                } else if let Some(target) = targets.first().copied() {
                    let is_active_or_selected = snap.index.selected_account_id.as_deref()
                        == Some(target.id.as_str())
                        || matches!(
                            &session_id,
                            crate::domain::account::SessionIdentity::Matched { account_id, .. }
                                | crate::domain::account::SessionIdentity::DriftedKnown { account_id, .. }
                                if account_id == &target.id
                        );
                    pending_confirm = Some(PendingTuiConfirm::DeleteAccount {
                        account_id: target.id.clone(),
                        email: target.email.clone(),
                        clear_active_slot: is_active_or_selected,
                    });
                }
            }
            _ => {
                force_redraw = false;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_single_switch_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    snap: &crate::store::repository::StoreSnapshot,
    session_id: &crate::domain::account::SessionIdentity,
    rotated_active_id: Option<&str>,
    runtime_st: &crate::domain::account::RuntimeState,
    marked_ids: &HashSet<String>,
    detail_view: bool,
    detail_scroll: &mut usize,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    target: &crate::domain::account::AccountRecord,
    transient_status: &mut TransientStatus,
) {
    let switching_msg = format!("Switching to {}...", terminal_text(&target.email));
    let _ = render_dashboard_full(&mut TuiFrameView {
        accounts: &snap.accounts,
        session_id,
        rotated_active_id,
        runtime_st,
        backend_tag: backend.name(),
        marked_ids,
        detail_view,
        detail_scroll,
        cursor_idx,
        scroll_offset,
        transient_notice: Some(&switching_msg),
        now_unix: crate::domain::clock::current_unix_seconds(),
    });
    let res = (|| {
        let registry = OAuthClientRegistry::load(repo.paths())?;
        execute_switch(
            repo,
            backend,
            &registry,
            &target.id,
            &SwitchOptions {
                dry_run: false,
                allow_running: false,
            },
            crate::domain::clock::current_unix_seconds(),
        )
    })();
    let done_at = Instant::now();
    match res {
        Ok(out) => {
            let msg = format_tui_switch_status_notice("", &out);
            transient_status.set_info(msg, done_at);
        }
        Err(e) => transient_status.set_error(
            format!("Switch error: {}", terminal_text(&e.message)),
            done_at,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_single_refresh_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    explicit_file_backend: bool,
    proxy_override: Option<&str>,
    snap: &crate::store::repository::StoreSnapshot,
    session_id: &crate::domain::account::SessionIdentity,
    rotated_active_id: Option<&str>,
    runtime_st: &crate::domain::account::RuntimeState,
    marked_ids: &HashSet<String>,
    detail_view: bool,
    detail_scroll: &mut usize,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    target: &crate::domain::account::AccountRecord,
    transient_status: &mut TransientStatus,
    sigterm: &mut Option<tokio::signal::unix::Signal>,
    sigint: &mut Option<tokio::signal::unix::Signal>,
    sighup: &mut Option<tokio::signal::unix::Signal>,
) -> bool {
    let refreshing_msg = format!(
        "Refreshing active quota for {} via official agy...",
        terminal_text(&target.email)
    );
    let _ = render_dashboard_full(&mut TuiFrameView {
        accounts: &snap.accounts,
        session_id,
        rotated_active_id,
        runtime_st,
        backend_tag: backend.name(),
        marked_ids,
        detail_view,
        detail_scroll,
        cursor_idx,
        scroll_offset,
        transient_notice: Some(&refreshing_msg),
        now_unix: crate::domain::clock::current_unix_seconds(),
    });
    let now_unix = crate::domain::clock::current_unix_seconds();
    let proxy_owned = proxy_override.map(str::to_owned);
    let mut refresh_fut = std::pin::pin!(async {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        refresh_active_slot_quota_via_official_cli_with_proxy(
            repo,
            backend,
            explicit_file_backend,
            proxy_owned,
            Some(&target.id),
            crate::domain::clock::current_unix_seconds(),
        )
        .await
    });
    let mut interrupted_r = false;
    let refresh_res = loop {
        tokio::select! {
            _ = async {
                if let Some(ref mut s) = sigterm { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => {
                interrupted_r = true;
                break None;
            }
            _ = async {
                if let Some(ref mut s) = sigint { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => {
                interrupted_r = true;
                break None;
            }
            _ = async {
                if let Some(ref mut s) = sighup { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => {
                interrupted_r = true;
                break None;
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let (should_exit, saw_resize) = poll_raw_tty_interrupt_or_resize();
                if should_exit {
                    interrupted_r = true;
                    break None;
                }
                if saw_resize {
                    let _ = render_dashboard_full(&mut TuiFrameView {
                        accounts: &snap.accounts,
                        session_id,
                        rotated_active_id,
                        runtime_st,
                        backend_tag: backend.name(),
                        marked_ids,
                        detail_view,
                        detail_scroll,
                        cursor_idx,
                        scroll_offset,
                        transient_notice: Some(&refreshing_msg),
                        now_unix: crate::domain::clock::current_unix_seconds(),
                    });
                }
            }
            res = &mut refresh_fut => break Some(res),
        }
    };
    if interrupted_r {
        return true;
    }
    if let Some(res) = refresh_res {
        let done_at = Instant::now();
        match res {
            Ok(outcome) => {
                let msg = format_tui_refresh_status_notice(&outcome);
                if outcome.validation_blocked {
                    transient_status.set_error(msg, done_at);
                } else {
                    transient_status.set_info(msg, done_at);
                }
            }
            Err(e) => transient_status.set_error(
                format!("Refresh error: {}", terminal_text(&e.message)),
                done_at,
            ),
        }
    }
    false
}

fn update_label_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    account_id: &str,
    email: &str,
    raw_label: &str,
    transient_status: &mut TransientStatus,
) {
    let now_unix = crate::domain::clock::current_unix_seconds();
    let res = reconcile_pending_journal_before_write(repo, backend, now_unix).and_then(|_| {
        repo.with_write_lock(|tx| tx.set_account_custom_label(account_id, Some(raw_label)))
    });
    let done_at = Instant::now();
    match res {
        Ok(updated) => {
            if let Some(ref lbl) = updated.custom_label {
                transient_status.set_info(
                    format!(
                        "Updated label for {} to \"{}\".",
                        terminal_text(email),
                        terminal_text(lbl)
                    ),
                    done_at,
                );
            } else {
                transient_status.set_info(
                    format!("Cleared label for {}.", terminal_text(email)),
                    done_at,
                );
            }
        }
        Err(e) => transient_status.set_error(
            format!("Label error: {}", terminal_text(&e.message)),
            done_at,
        ),
    }
}

fn export_accounts_in_tui(
    repo: &StoreRepository,
    output_path: &Path,
    account_ids: &[String],
    transient_status: &mut TransientStatus,
) {
    let res = export_transfer_bundle_file(repo, output_path, true, false, account_ids);
    let done_at = Instant::now();
    match res {
        Ok(count) => transient_status.set_info(
            format!(
                "Exported {count} account(s) to {} (0600).",
                terminal_text(&output_path.to_string_lossy())
            ),
            done_at,
        ),
        Err(e) => transient_status.set_error(
            format!("Export error: {}", terminal_text(&e.message)),
            done_at,
        ),
    }
}

fn enable_marked_accounts_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    account_ids: &[String],
    transient_status: &mut TransientStatus,
) {
    let now_unix = crate::domain::clock::current_unix_seconds();
    let res: CliResult<(usize, usize)> = (|| {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        repo.with_write_lock(|tx| {
            let mut changed = 0usize;
            let mut found = 0usize;
            for id in account_ids {
                if let Some(acc) = tx.load_account_opt(id)? {
                    found += 1;
                    if acc.disabled {
                        tx.mark_account_enabled(id)?;
                        changed += 1;
                    }
                }
            }
            Ok((changed, found))
        })
    })();
    let done_at = Instant::now();
    match res {
        Ok((0, total)) => transient_status.set_info(
            format!("All {total} marked account(s) are already enabled."),
            done_at,
        ),
        Ok((changed, total)) => transient_status.set_info(
            format!("Enabled {changed} of {total} marked account(s)."),
            done_at,
        ),
        Err(e) => {
            transient_status.set_error(format!("Error: {}", terminal_text(&e.message)), done_at)
        }
    }
}

fn disable_marked_accounts_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    account_ids: &[String],
    transient_status: &mut TransientStatus,
) {
    let now_unix = crate::domain::clock::current_unix_seconds();
    let res: CliResult<(usize, usize)> = (|| {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        repo.with_write_lock(|tx| {
            let mut changed = 0usize;
            let mut found = 0usize;
            for id in account_ids {
                if let Some(acc) = tx.load_account_opt(id)? {
                    found += 1;
                    if !acc.disabled {
                        tx.mark_account_disabled(
                            id,
                            crate::domain::account::DisableReasonCode::Manual,
                            Some("Disabled marked in TUI".into()),
                            now_unix,
                        )?;
                        changed += 1;
                    }
                }
            }
            Ok((changed, found))
        })
    })();
    let done_at = Instant::now();
    match res {
        Ok((0, total)) => transient_status.set_info(
            format!("All {total} marked account(s) are already disabled."),
            done_at,
        ),
        Ok((changed, total)) => transient_status.set_info(
            format!("Disabled {changed} of {total} marked account(s)."),
            done_at,
        ),
        Err(e) => {
            transient_status.set_error(format!("Error: {}", terminal_text(&e.message)), done_at)
        }
    }
}

fn delete_marked_accounts_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    account_ids: &[String],
    cursor_idx: &mut usize,
    transient_status: &mut TransientStatus,
) -> Vec<String> {
    let mut deleted_ids = Vec::new();
    let mut cleared_any_slot = false;
    let mut first_error: Option<String> = None;

    for id in account_ids {
        let now_unix = crate::domain::clock::current_unix_seconds();
        let is_active = repo.read_snapshot().ok().is_some_and(|snap| {
            let slot_state = backend.inspect_slot(repo.paths());
            let sess = resolve_session_identity(&slot_state, &snap);
            snap.index.selected_account_id.as_deref() == Some(id.as_str())
                || matches!(
                    &sess,
                    crate::domain::account::SessionIdentity::Matched { account_id, .. }
                        | crate::domain::account::SessionIdentity::DriftedKnown { account_id, .. }
                        if account_id == id
                )
        });
        match execute_account_delete(repo, backend, id, is_active, is_active, now_unix) {
            Ok((_deleted, cleared_slot)) => {
                deleted_ids.push(id.clone());
                if cleared_slot {
                    cleared_any_slot = true;
                }
            }
            Err(e) => {
                first_error = Some(e.message);
                break;
            }
        }
    }

    let remaining = repo.read_snapshot().map(|s| s.accounts.len()).unwrap_or(0);
    *cursor_idx = if remaining == 0 {
        0
    } else {
        (*cursor_idx).min(remaining - 1)
    };
    let done_at = Instant::now();
    if let Some(err_msg) = first_error {
        transient_status.set_error(
            format!(
                "Deleted {}/{} marked account(s); stopped on error: {}",
                deleted_ids.len(),
                account_ids.len(),
                terminal_text(&err_msg)
            ),
            done_at,
        );
    } else {
        transient_status.set_info(
            format!(
                "Deleted {} marked account(s){}.",
                deleted_ids.len(),
                if cleared_any_slot {
                    " and cleared active slot"
                } else {
                    ""
                }
            ),
            done_at,
        );
    }
    deleted_ids
}

fn enable_all_accounts_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transient_status: &mut TransientStatus,
) {
    let now_unix = crate::domain::clock::current_unix_seconds();
    let res: CliResult<usize> = (|| {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let snap = repo.read_snapshot()?;
        let disabled_ids: Vec<String> = snap
            .accounts
            .iter()
            .filter(|a| a.disabled)
            .map(|a| a.id.clone())
            .collect();
        if disabled_ids.is_empty() {
            return Ok(0);
        }
        repo.with_write_lock(|tx| {
            let mut count = 0usize;
            for id in &disabled_ids {
                if tx.load_account_opt(id)?.is_some_and(|a| a.disabled) {
                    tx.mark_account_enabled(id)?;
                    count += 1;
                }
            }
            Ok(count)
        })
    })();
    let done_at = Instant::now();
    match res {
        Ok(0) => transient_status.set_info("All accounts are already enabled.".into(), done_at),
        Ok(n) => {
            transient_status.set_info(format!("Enabled all {n} disabled account(s)."), done_at)
        }
        Err(e) => {
            transient_status.set_error(format!("Error: {}", terminal_text(&e.message)), done_at)
        }
    }
}

fn disable_all_accounts_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transient_status: &mut TransientStatus,
) {
    let now_unix = crate::domain::clock::current_unix_seconds();
    let res: CliResult<usize> = (|| {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let snap = repo.read_snapshot()?;
        let enabled_ids: Vec<String> = snap
            .accounts
            .iter()
            .filter(|a| !a.disabled)
            .map(|a| a.id.clone())
            .collect();
        if enabled_ids.is_empty() {
            return Ok(0);
        }
        repo.with_write_lock(|tx| {
            let mut count = 0usize;
            for id in &enabled_ids {
                if tx.load_account_opt(id)?.is_some_and(|a| !a.disabled) {
                    tx.mark_account_disabled(
                        id,
                        crate::domain::account::DisableReasonCode::Manual,
                        Some("Disabled all in TUI".into()),
                        now_unix,
                    )?;
                    count += 1;
                }
            }
            Ok(count)
        })
    })();
    let done_at = Instant::now();
    match res {
        Ok(0) => transient_status.set_info("All accounts are already disabled.".into(), done_at),
        Ok(n) => transient_status.set_info(format!("Disabled all {n} account(s)."), done_at),
        Err(e) => {
            transient_status.set_error(format!("Error: {}", terminal_text(&e.message)), done_at)
        }
    }
}

fn delete_account_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    account_id: &str,
    _email: &str,
    clear_active_slot: bool,
    cursor_idx: &mut usize,
    transient_status: &mut TransientStatus,
) -> bool {
    let now_unix = crate::domain::clock::current_unix_seconds();
    let res = execute_account_delete(
        repo,
        backend,
        account_id,
        clear_active_slot,
        clear_active_slot,
        now_unix,
    );
    let done_at = Instant::now();
    match res {
        Ok((deleted, cleared_slot)) => {
            let remaining = repo.read_snapshot().map(|s| s.accounts.len()).unwrap_or(0);
            *cursor_idx = if remaining == 0 {
                0
            } else {
                (*cursor_idx).min(remaining - 1)
            };
            transient_status.set_info(
                format!(
                    "Deleted {}{}.",
                    terminal_text(&deleted.email),
                    if cleared_slot {
                        " and cleared active slot"
                    } else {
                        ""
                    }
                ),
                done_at,
            );
            true
        }
        Err(e) => {
            transient_status.set_error(
                format!("Delete error: {}", terminal_text(&e.message)),
                done_at,
            );
            false
        }
    }
}

fn reorder_selected_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    accounts: &[crate::domain::account::AccountRecord],
    cursor_idx: &mut usize,
    move_up: bool,
    transient_status: &mut TransientStatus,
) {
    if accounts.len() < 2 || *cursor_idx >= accounts.len() {
        return;
    }
    let next_idx = if move_up {
        cursor_idx.saturating_sub(1)
    } else {
        (*cursor_idx + 1).min(accounts.len() - 1)
    };
    if next_idx == *cursor_idx {
        return;
    }
    let email = accounts[*cursor_idx].email.clone();
    let mut ids: Vec<String> = accounts.iter().map(|a| a.id.clone()).collect();
    ids.swap(*cursor_idx, next_idx);

    let now_unix = crate::domain::clock::current_unix_seconds();
    let res = reconcile_pending_journal_before_write(repo, backend, now_unix)
        .and_then(|_| repo.with_write_lock(|tx| tx.reorder_accounts(ids, now_unix)));
    let done_at = Instant::now();
    match res {
        Ok(_) => {
            *cursor_idx = next_idx;
            transient_status.set_info(
                format!("Moved {} to #{}.", terminal_text(&email), next_idx + 1),
                done_at,
            );
        }
        Err(e) => {
            transient_status.set_error(
                format!("Reorder error: {}", terminal_text(&e.message)),
                done_at,
            );
        }
    }
}

fn format_pct_padded(value: Option<i32>) -> String {
    match value {
        Some(v) => format!("{:>3}%", v.clamp(0, 100)),
        None => "   —".to_string(),
    }
}

fn format_compact_age(updated_unix: i64, now_unix: i64) -> String {
    if updated_unix <= 0 {
        return "unknown".into();
    }
    let diff = now_unix.saturating_sub(updated_unix);
    if diff < -30 {
        "future".into()
    } else if diff <= 2 {
        "just now".into()
    } else if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86_400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86_400)
    }
}

fn format_compact_reset_duration(reset_unix: i64, now_unix: i64) -> String {
    let rem = reset_unix.saturating_sub(now_unix);
    if rem <= 0 {
        "expired".into()
    } else if rem >= 86_400 {
        format!("{}d{:02}h", rem / 86_400, (rem % 86_400) / 3600)
    } else if rem >= 3600 {
        format!("{}h{:02}m", rem / 3600, (rem % 3600) / 60)
    } else {
        format!("{}m", (rem / 60).max(1))
    }
}

const MAX_DORMANT_DUR_AGE_SECS: i64 = 24 * 3600;
const MAX_DORMANT_SESSION_DUR_SECS: i64 = 12 * 3600;

fn format_compact_duration(secs: i64) -> String {
    if secs < 60 {
        "<1m".into()
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 {
            format!("{h}h")
        } else {
            format!("{h}h{m}m")
        }
    } else {
        let d = secs / 86_400;
        let h = (secs % 86_400) / 3600;
        if h == 0 {
            format!("{d}d")
        } else {
            format!("{d}d{h}h")
        }
    }
}

fn format_last_used_age(ts_unix: i64, now_unix: i64) -> String {
    if ts_unix <= 0 {
        return "never".into();
    }
    let diff = now_unix.saturating_sub(ts_unix);
    if diff <= 2 {
        "just now".into()
    } else if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86_400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86_400)
    }
}

fn format_last_used_cell(
    acc: &crate::domain::account::AccountRecord,
    is_active: bool,
    now_unix: i64,
) -> String {
    if is_active {
        return match acc.last_switched_in_at {
            Some(in_at) if in_at > 0 && now_unix >= in_at => {
                format!("active ({})", format_compact_duration(now_unix - in_at))
            }
            _ => "active".into(),
        };
    }

    if let Some(out_at) = acc.last_switched_out_at.filter(|&ts| ts > 0) {
        if let Some(in_at) = acc.last_switched_in_at.filter(|&ts| ts > out_at) {
            return format_last_used_age(acc.last_used.max(in_at), now_unix);
        }
        let age = now_unix.saturating_sub(out_at);
        let age_str = format_last_used_age(out_at, now_unix);
        if (0..=MAX_DORMANT_DUR_AGE_SECS).contains(&age) {
            if let Some(in_at) = acc.last_switched_in_at.filter(|&ts| ts > 0 && out_at >= ts) {
                let dur = out_at.saturating_sub(in_at);
                if dur <= MAX_DORMANT_SESSION_DUR_SECS {
                    return format!("{age_str} ({})", format_compact_duration(dur));
                }
            }
        }
        return age_str;
    }

    if let Some(in_at) = acc.last_switched_in_at.filter(|&ts| ts > 0) {
        return format_last_used_age(acc.last_used.max(in_at), now_unix);
    }

    if acc.last_used > 0 {
        return format_last_used_age(acc.last_used, now_unix);
    }

    "never".into()
}

struct ActiveQuotaHeader {
    label: String,
    expanded_lines: Vec<String>,
    compact_summary: String,
}

fn resolve_rotated_selected_active_id(
    repo: &StoreRepository,
    snap: &crate::store::repository::StoreSnapshot,
    slot_state: &SlotInspectState,
    session_id: &crate::domain::account::SessionIdentity,
) -> Option<String> {
    if !matches!(
        session_id,
        crate::domain::account::SessionIdentity::DriftedExternal { .. }
    ) {
        return None;
    }
    if let (SlotInspectState::Present(parsed), Some(sel_acc)) =
        (slot_state, snap.selected_account())
    {
        if slot_matches_selected_rotated_account(repo, snap, parsed, sel_acc) {
            return Some(sel_acc.id.clone());
        }
    }
    None
}

fn resolve_active_slot_account_id<'a>(
    session_id: &'a crate::domain::account::SessionIdentity,
    rotated_active_id: Option<&'a str>,
) -> Option<&'a str> {
    match session_id {
        crate::domain::account::SessionIdentity::Matched { account_id, .. }
        | crate::domain::account::SessionIdentity::DriftedKnown { account_id, .. } => {
            Some(account_id.as_str())
        }
        crate::domain::account::SessionIdentity::DriftedExternal { .. } => rotated_active_id,
        _ => None,
    }
}

fn resolve_active_account<'a>(
    accounts: &'a [crate::domain::account::AccountRecord],
    session_id: &crate::domain::account::SessionIdentity,
    rotated_active_id: Option<&str>,
) -> Option<&'a crate::domain::account::AccountRecord> {
    resolve_active_slot_account_id(session_id, rotated_active_id)
        .and_then(|id| accounts.iter().find(|a| a.id == id))
}

fn build_active_quota_header(
    active_acc: Option<&crate::domain::account::AccountRecord>,
    now_unix: i64,
) -> ActiveQuotaHeader {
    let Some(acc) = active_acc else {
        return ActiveQuotaHeader {
            label: "Quota".into(),
            expanded_lines: vec!["— (no active account)".into()],
            compact_summary: "—".into(),
        };
    };
    let Some(ref q) = acc.quota else {
        return ActiveQuotaHeader {
            label: "Quota".into(),
            expanded_lines: vec!["— (press 'r' on * to refresh)".into()],
            compact_summary: "—".into(),
        };
    };
    if is_empty_quota_placeholder(q) {
        return ActiveQuotaHeader {
            label: "Quota".into(),
            expanded_lines: vec!["— (press 'r' on * to refresh)".into()],
            compact_summary: "—".into(),
        };
    }
    let label = format!("Quota ({})", format_compact_age(q.last_updated, now_unix));
    if q.is_forbidden {
        return ActiveQuotaHeader {
            label,
            expanded_lines: vec!["forbidden (HTTP 403)".into()],
            compact_summary: "forbidden".into(),
        };
    }

    struct PoolHeaderBuckets {
        name: &'static str,
        short_tag: &'static str,
        short_5h: Option<(i32, String)>,
        weekly: Option<(i32, String)>,
    }

    let extract_bucket_reset = |b: &crate::domain::quota::QuotaBucket| -> String {
        if is_unused_full_bucket_reset_time(
            &b.reset_time,
            b.remaining_fraction,
            b.remaining_fraction_known,
        ) {
            return "—".into();
        }
        match crate::domain::clock::parse_rfc3339_unix_seconds(&b.reset_time) {
            Some(ts) => format_compact_reset_duration(ts, now_unix),
            None => "—".into(),
        }
    };

    let mut pools: Vec<PoolHeaderBuckets> = Vec::new();
    if let Some(ref groups) = q.quota_groups {
        for (target_pool, name, short_tag) in [
            (QuotaPool::Gemini, "Gemini", "Gem"),
            (QuotaPool::ThirdParty, "Claude/GPT", "3P"),
            (QuotaPool::Argon, "Argon", "Arg"),
        ] {
            let mut short_5h: Option<(i32, String)> = None;
            let mut weekly: Option<(i32, String)> = None;
            let mut has_any = false;
            for g in groups {
                for b in &g.buckets {
                    if quota_pool(&b.bucket_id, &g.display_name) != Some(target_pool) {
                        continue;
                    }
                    has_any = true;
                    let Some(pct) =
                        observed_quota_percentage(b.remaining_fraction, b.remaining_fraction_known)
                    else {
                        continue;
                    };
                    let reset_tag = extract_bucket_reset(b);
                    let w_low = b.window.trim().to_ascii_lowercase();
                    let id_low = b.bucket_id.trim().to_ascii_lowercase();
                    if w_low == "weekly" || id_low.ends_with("-weekly") {
                        if weekly.as_ref().is_none_or(|(old_p, _)| pct < *old_p) {
                            weekly = Some((pct, reset_tag));
                        }
                    } else if (w_low == "5h" || id_low.ends_with("-5h"))
                        && short_5h.as_ref().is_none_or(|(old_p, _)| pct < *old_p)
                    {
                        short_5h = Some((pct, reset_tag));
                    }
                }
            }
            if has_any && (short_5h.is_some() || weekly.is_some()) {
                pools.push(PoolHeaderBuckets {
                    name,
                    short_tag,
                    short_5h,
                    weekly,
                });
            }
        }
    }

    if pools.is_empty() {
        return ActiveQuotaHeader {
            label,
            expanded_lines: vec!["— (no quota buckets cached)".into()],
            compact_summary: "—".into(),
        };
    }

    let max_5h_w = pools
        .iter()
        .filter_map(|p| {
            p.short_5h.as_ref().map(|(pct, rst)| {
                display_width(&format!("5h {} ({rst})", format_pct_padded(Some(*pct))))
            })
        })
        .max()
        .unwrap_or(0);

    let mut expanded_lines = Vec::with_capacity(pools.len());
    let mut compact_parts = Vec::with_capacity(pools.len());
    for p in &pools {
        match (&p.short_5h, &p.weekly) {
            (Some((p5, r5)), Some((pw, rw))) => {
                let s5 = format!("5h {} ({r5})", format_pct_padded(Some(*p5)));
                let pad = max_5h_w.saturating_sub(display_width(&s5));
                expanded_lines.push(format!(
                    "{:<10}  {s5}{}  · Weekly {} ({rw})",
                    p.name,
                    " ".repeat(pad),
                    format_pct_padded(Some(*pw))
                ));
                compact_parts.push(format!(
                    "{} {}/{}",
                    p.short_tag,
                    format_pct(Some(*p5)),
                    format_pct(Some(*pw))
                ));
            }
            (None, Some((pw, rw))) => {
                expanded_lines.push(format!(
                    "{:<10}  Weekly {} ({rw})",
                    p.name,
                    format_pct_padded(Some(*pw))
                ));
                compact_parts.push(format!("{} {}", p.short_tag, format_pct(Some(*pw))));
            }
            (Some((p5, r5)), None) => {
                expanded_lines.push(format!(
                    "{:<10}  5h {} ({r5})",
                    p.name,
                    format_pct_padded(Some(*p5))
                ));
                compact_parts.push(format!("{} {}", p.short_tag, format_pct(Some(*p5))));
            }
            (None, None) => {}
        }
    }

    ActiveQuotaHeader {
        label,
        expanded_lines,
        compact_summary: compact_parts.join(" · "),
    }
}

/// Poll non-blocking raw-mode terminal events while an async refresh (`r`) is in flight.
/// Because `enable_raw_mode()` clears `ISIG`, pressing `Ctrl+C` on the keyboard delivers `0x03`
/// on `stdin` rather than an OS `SIGINT` signal. Returns `(should_exit_tui, saw_resize)`.
fn poll_raw_tty_interrupt_or_resize() -> (bool, bool) {
    let mut saw_resize = false;
    while event::poll(Duration::ZERO).unwrap_or(false) {
        match event::read() {
            Ok(Event::Resize(_, _)) => {
                saw_resize = true;
            }
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                if (k.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(k.code, KeyCode::Char('c' | 'C' | 'd' | 'D')))
                    || (!k
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && k.code == KeyCode::Char('q'))
                    || k.code == KeyCode::Esc
                {
                    return (true, saw_resize);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    (false, saw_resize)
}

/// Interaction T2: `r` is completely decoupled from `Space` multi-select and ONLY refreshes when
/// the cursor is on the currently active (`*`) official-slot account; pressing `r` on a dormant
/// account makes zero requests and shows a gentle status hint to switch with `s` first.
fn resolve_r_refresh_target<'a>(
    accounts: &'a [crate::domain::account::AccountRecord],
    session_id: &crate::domain::account::SessionIdentity,
    rotated_active_id: Option<&str>,
    cursor_idx: usize,
) -> Result<&'a crate::domain::account::AccountRecord, &'static str> {
    let Some(target) = accounts.get(cursor_idx) else {
        return Err("No account selected.");
    };
    if resolve_active_slot_account_id(session_id, rotated_active_id) == Some(target.id.as_str()) {
        Ok(target)
    } else {
        Err(TUI_DORMANT_REFRESH_HINT)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_r_refresh_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    explicit_file_backend: bool,
    proxy_override: Option<&str>,
    snap: &crate::store::repository::StoreSnapshot,
    session_id: &crate::domain::account::SessionIdentity,
    rotated_active_id: Option<&str>,
    runtime_st: &crate::domain::account::RuntimeState,
    marked_ids: &HashSet<String>,
    detail_view: bool,
    detail_scroll: &mut usize,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    transient_status: &mut TransientStatus,
    sigterm: &mut Option<tokio::signal::unix::Signal>,
    sigint: &mut Option<tokio::signal::unix::Signal>,
    sighup: &mut Option<tokio::signal::unix::Signal>,
) -> bool {
    match resolve_r_refresh_target(&snap.accounts, session_id, rotated_active_id, cursor_idx) {
        Ok(target) => {
            run_single_refresh_in_tui(
                repo,
                backend,
                explicit_file_backend,
                proxy_override,
                snap,
                session_id,
                rotated_active_id,
                runtime_st,
                marked_ids,
                detail_view,
                detail_scroll,
                cursor_idx,
                scroll_offset,
                target,
                transient_status,
                sigterm,
                sigint,
                sighup,
            )
            .await
        }
        Err(hint) => {
            transient_status.set_info(hint.to_string(), Instant::now());
            false
        }
    }
}

fn current_terminal_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0
        && ws.ws_col > 0
        && ws.ws_row > 0
    {
        return (ws.ws_col, ws.ws_row);
    }
    terminal::size().unwrap_or((120, 24))
}

struct TuiFrameView<'a> {
    accounts: &'a [crate::domain::account::AccountRecord],
    session_id: &'a crate::domain::account::SessionIdentity,
    rotated_active_id: Option<&'a str>,
    runtime_st: &'a crate::domain::account::RuntimeState,
    backend_tag: &'a str,
    marked_ids: &'a HashSet<String>,
    detail_view: bool,
    detail_scroll: &'a mut usize,
    cursor_idx: usize,
    scroll_offset: &'a mut usize,
    transient_notice: Option<&'a str>,
    now_unix: i64,
}

fn render_dashboard_full(view: &mut TuiFrameView<'_>) -> CliResult<String> {
    let (term_cols, term_rows) = current_terminal_size();
    render_dashboard_full_with_size(view, term_cols, term_rows)
}

fn render_dashboard_full_with_size(
    view: &mut TuiFrameView<'_>,
    term_cols: u16,
    term_rows: u16,
) -> CliResult<String> {
    let rendered = build_dashboard_frame_full(view, term_cols, term_rows);

    let mut out = io::stdout();
    execute!(out, cursor::MoveTo(0, 0), Clear(ClearType::All))
        .map_err(|e| CliError::io("tui_draw_error", format!("TUI draw error: {e}")))?;
    out.write_all(rendered.as_bytes())
        .and_then(|_| out.flush())
        .map_err(|e| CliError::io("tui_write_error", format!("TUI write error: {e}")))?;
    Ok(rendered)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn build_dashboard_frame(
    accounts: &[crate::domain::account::AccountRecord],
    session_id: &crate::domain::account::SessionIdentity,
    runtime_st: &crate::domain::account::RuntimeState,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    transient_notice: Option<&str>,
    term_cols: u16,
    term_rows: u16,
) -> String {
    build_dashboard_frame_with_backend(
        accounts,
        session_id,
        runtime_st,
        "file",
        cursor_idx,
        scroll_offset,
        transient_notice,
        term_cols,
        term_rows,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn build_dashboard_frame_with_backend(
    accounts: &[crate::domain::account::AccountRecord],
    session_id: &crate::domain::account::SessionIdentity,
    runtime_st: &crate::domain::account::RuntimeState,
    backend_tag: &str,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    transient_notice: Option<&str>,
    term_cols: u16,
    term_rows: u16,
) -> String {
    let empty_marks = HashSet::new();
    let mut detail_scroll = 0usize;
    let mut view = TuiFrameView {
        accounts,
        session_id,
        rotated_active_id: None,
        runtime_st,
        backend_tag,
        marked_ids: &empty_marks,
        detail_view: false,
        detail_scroll: &mut detail_scroll,
        cursor_idx,
        scroll_offset,
        transient_notice,
        now_unix: crate::domain::clock::current_unix_seconds(),
    };
    build_dashboard_frame_full(&mut view, term_cols, term_rows)
}

fn format_tui_switch_status_notice(
    proxy_prefix: &str,
    out: &crate::switching::executor::SwitchOutcome,
) -> String {
    let id = terminal_text(&out.target_account_id);
    let email = terminal_text(&out.target_email);
    if out.validation_blocked && out.runtime_warning.is_some() {
        format!("{proxy_prefix}Switched (verify-blocked): open new agy to verify, press r — {email} ({id})")
    } else if out.validation_blocked {
        format!(
            "{proxy_prefix}Switched (verify-blocked): open agy to verify, press r — {email} ({id})"
        )
    } else if out.runtime_warning.is_some() {
        format!(
            "{proxy_prefix}Switched active slot to {id} ({email}) — running `agy` keeps startup login; new `agy` uses this account."
        )
    } else {
        format!("{proxy_prefix}Switched active slot to {id} ({email}).")
    }
}

fn format_tui_refresh_status_notice(
    outcome: &crate::quota::official_cli::ActiveSlotQuotaRefreshOutcome,
) -> String {
    let id = terminal_text(&outcome.account.id);
    let email = terminal_text(&outcome.account.email);
    if outcome.validation_blocked {
        format!("Refresh blocked (verify-blocked): open agy to verify, press r — {email} ({id})")
    } else {
        format!("Refreshed quota for {email}.")
    }
}

fn format_account_email_with_label(acc: &crate::domain::account::AccountRecord) -> String {
    let email = terminal_text(&acc.email);
    if let Some(ref lbl) = acc.custom_label {
        let clean = terminal_text(lbl)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !clean.is_empty() {
            return format!("{email} ({clean})");
        }
    }
    email
}

fn format_marked_footer_summary(
    accounts: &[crate::domain::account::AccountRecord],
    marked_ids: &HashSet<String>,
    max_cols: usize,
) -> Option<String> {
    let marked_emails: Vec<String> = accounts
        .iter()
        .filter(|a| marked_ids.contains(&a.id))
        .map(|a| terminal_text(&a.email))
        .collect();
    let total = marked_emails.len();
    if total == 0 || max_cols == 0 {
        return None;
    }

    let prefix = format!("Marked ({total}): ");
    let suffix = "  [Esc to clear]";
    let overhead = display_width(&prefix) + display_width(suffix);
    if overhead >= max_cols {
        return Some(truncate_to_cols(
            &format!("Marked ({total}) [Esc clears]"),
            max_cols,
        ));
    }

    let budget = max_cols - overhead;
    let mut shown = String::new();
    let mut shown_count = 0usize;
    for (idx, email) in marked_emails.iter().enumerate() {
        let rem_after = total - idx - 1;
        let more_tag = if rem_after > 0 {
            format!(" +{rem_after} more")
        } else {
            String::new()
        };
        let sep = if shown.is_empty() { "" } else { ", " };
        let cand_width = display_width(&shown) + display_width(sep) + display_width(email);
        if cand_width + display_width(&more_tag) <= budget {
            shown.push_str(sep);
            shown.push_str(email);
            shown_count += 1;
        } else {
            break;
        }
    }

    if shown_count == 0 {
        let fallback_more = format!("+{total} account(s)");
        let combined = format!("{prefix}{fallback_more}{suffix}");
        if display_width(&combined) <= max_cols {
            return Some(combined);
        }
        return Some(truncate_to_cols(
            &format!("Marked ({total}) [Esc clears]"),
            max_cols,
        ));
    }

    let remaining = total - shown_count;
    let body = if remaining > 0 {
        format!("{prefix}{shown} +{remaining} more{suffix}")
    } else {
        format!("{prefix}{shown}{suffix}")
    };
    Some(truncate_to_cols(&body, max_cols))
}

fn format_token_expiry_countdown(expiry_unix: i64, now_unix: i64) -> String {
    if expiry_unix <= 0 {
        return "unknown".into();
    }
    let local_str = format_unix_local_minute(expiry_unix);
    let rem = expiry_unix - now_unix;
    if rem <= 0 {
        format!("{local_str} (expired)")
    } else if rem >= 3600 {
        format!("{local_str} (in {}h {:02}m)", rem / 3600, (rem % 3600) / 60)
    } else {
        format!("{local_str} (in {}m)", (rem / 60).max(1))
    }
}

fn split_grapheme_chunks(s: &str, max_cols: usize) -> Vec<String> {
    let budget = max_cols.max(1);
    let mut chunks = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for g in UnicodeSegmentation::graphemes(s, true) {
        let gw = display_width(g);
        if !cur.is_empty() && cur_w + gw > budget {
            chunks.push(std::mem::take(&mut cur));
            cur_w = 0;
        }
        cur.push_str(g);
        cur_w += gw;
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

fn wrap_family_models_lines(family_label: &str, items: &[&str], max_cols: usize) -> Vec<String> {
    if items.is_empty() || max_cols == 0 {
        return Vec::new();
    }
    let inline_prefix = format!("  {:<10} : ", family_label);
    let inline_prefix_w = display_width(&inline_prefix);
    let mut out = Vec::new();
    let (first_prefix, cont_indent, content_budget) = if max_cols >= inline_prefix_w + 8 {
        (
            inline_prefix,
            " ".repeat(inline_prefix_w),
            max_cols - inline_prefix_w,
        )
    } else {
        out.push(truncate_to_cols(&format!("  {family_label}:"), max_cols));
        let indent = if max_cols >= 6 { "    " } else { "" };
        let indent_w = display_width(indent);
        (
            indent.to_string(),
            indent.to_string(),
            max_cols.saturating_sub(indent_w).max(1),
        )
    };

    let mut cur_line = String::new();
    let mut first = true;
    let push_line = |out: &mut Vec<String>, first: &mut bool, text: String| {
        if *first {
            out.push(format!("{first_prefix}{text}"));
            *first = false;
        } else {
            out.push(format!("{cont_indent}{text}"));
        }
    };

    for (idx, item) in items.iter().enumerate() {
        let token = if idx + 1 < items.len() {
            format!("{item},")
        } else {
            (*item).to_string()
        };
        if !cur_line.is_empty()
            && display_width(&cur_line) + 1 + display_width(&token) <= content_budget
        {
            cur_line.push(' ');
            cur_line.push_str(&token);
        } else {
            if !cur_line.is_empty() {
                push_line(&mut out, &mut first, std::mem::take(&mut cur_line));
            }
            if display_width(&token) <= content_budget {
                cur_line = token;
            } else {
                let mut chunks = split_grapheme_chunks(&token, content_budget);
                if let Some(last) = chunks.pop() {
                    for chunk in chunks {
                        push_line(&mut out, &mut first, chunk);
                    }
                    cur_line = last;
                }
            }
        }
    }
    if !cur_line.is_empty() {
        push_line(&mut out, &mut first, cur_line);
    }
    out
}

fn wrap_labeled_text_lines(
    label: &str,
    label_width: usize,
    text: &str,
    max_cols: usize,
) -> Vec<String> {
    let clean_label = terminal_text(label);
    let words: Vec<String> = terminal_text(text)
        .split_whitespace()
        .map(ToString::to_string)
        .collect();
    if words.is_empty() || max_cols == 0 {
        return Vec::new();
    }
    let pad = label_width.saturating_sub(display_width(&clean_label));
    let inline_prefix = format!("  {clean_label}{} : ", " ".repeat(pad));
    let inline_prefix_w = display_width(&inline_prefix);
    let mut out = Vec::new();
    let (first_prefix, cont_indent, content_budget) = if max_cols >= inline_prefix_w + 8 {
        (
            inline_prefix,
            " ".repeat(inline_prefix_w),
            max_cols - inline_prefix_w,
        )
    } else {
        out.push(truncate_to_cols(&format!("  {clean_label}:"), max_cols));
        let indent = if max_cols >= 6 { "    " } else { "" };
        let indent_w = display_width(indent);
        (
            indent.to_string(),
            indent.to_string(),
            max_cols.saturating_sub(indent_w).max(1),
        )
    };

    let mut cur_line = String::new();
    let mut first = true;
    let push_line = |out: &mut Vec<String>, first: &mut bool, line_text: String| {
        if *first {
            out.push(format!("{first_prefix}{line_text}"));
            *first = false;
        } else {
            out.push(format!("{cont_indent}{line_text}"));
        }
    };

    for word in words {
        if !cur_line.is_empty()
            && display_width(&cur_line) + 1 + display_width(&word) <= content_budget
        {
            cur_line.push(' ');
            cur_line.push_str(&word);
        } else {
            if !cur_line.is_empty() {
                push_line(&mut out, &mut first, std::mem::take(&mut cur_line));
            }
            if display_width(&word) <= content_budget {
                cur_line = word;
            } else {
                let mut chunks = split_grapheme_chunks(&word, content_budget);
                if let Some(last) = chunks.pop() {
                    for chunk in chunks {
                        push_line(&mut out, &mut first, chunk);
                    }
                    cur_line = last;
                }
            }
        }
    }
    if !cur_line.is_empty() {
        push_line(&mut out, &mut first, cur_line);
    }
    out
}

fn build_account_detail_lines(
    acc: &crate::domain::account::AccountRecord,
    is_selected: bool,
    is_marked: bool,
    now_unix: i64,
    inner_width: usize,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::with_capacity(24);
    let mut badges = Vec::new();
    if is_selected {
        badges.push("[active]");
    }
    if is_marked {
        badges.push("[marked]");
    }
    let badge_suffix = if badges.is_empty() {
        String::new()
    } else {
        format!("  {}", badges.join(" "))
    };
    lines.push(format!(
        "Account : {}{badge_suffix}",
        format_account_email_with_label(acc)
    ));
    lines.push(format!("ID      : {}", terminal_text(&acc.id)));

    let state_str = if acc.disabled {
        "disabled"
    } else if acc.is_validation_blocked_at(now_unix) {
        "verify-blocked"
    } else {
        "ok"
    };
    let last_used_str = format_last_used_cell(acc, is_selected, now_unix);
    lines.push(format!(
        "State   : {state_str} · Last used: {last_used_str}"
    ));

    if acc.disabled {
        let reason_line = match acc.disabled_code {
            Some(DisableReasonCode::RevokedOrExpiredGrant) => {
                "RevokedOrExpiredGrant (run `auth reauthorize`)"
            }
            Some(DisableReasonCode::ScopeReauthRequired) => {
                "ScopeReauthRequired (run `auth reauthorize`)"
            }
            Some(DisableReasonCode::AccountSuspended) => "AccountSuspended",
            Some(DisableReasonCode::Manual) | None => "Manual (disabled by user)",
        };
        lines.push(format!("Reason  : {reason_line}"));
    } else if acc.is_validation_blocked_at(now_unix) {
        lines.push(
            "Reason  : Google 403 VALIDATION_REQUIRED — switch in, open agy to verify, press r."
                .into(),
        );
    }

    let oauth_client = acc
        .token
        .oauth_client_key
        .as_deref()
        .map(terminal_text)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "antigravity_enterprise".into());
    lines.push(format!(
        "OAuth   : {oauth_client} · Token expires: {}",
        format_token_expiry_countdown(acc.token.expiry_timestamp, now_unix)
    ));

    if let Some(q) = acc
        .quota
        .as_ref()
        .filter(|q| !is_empty_quota_placeholder(q))
    {
        let eval_tag =
            match evaluate_account_quota(acc, "all", now_unix, DEFAULT_QUOTA_MAX_AGE_SECS) {
                QuotaEval::Known {
                    remaining_percentage,
                } => format!("known ({remaining_percentage:.0}% on all)"),
                QuotaEval::Stale { reason } => format!("stale ({})", terminal_text(&reason)),
                QuotaEval::Unknown { reason } => format!("unknown ({})", terminal_text(&reason)),
                QuotaEval::Unavailable { reason } => {
                    format!("unavailable ({})", terminal_text(&reason))
                }
            };
        let used_after_suffix = if !is_selected && q.last_updated > 0 {
            acc.last_switched_out_at
                .filter(|&out_at| {
                    out_at > 0
                        && out_at > q.last_updated.saturating_add(60)
                        && acc.last_switched_in_at.is_none_or(|in_at| out_at >= in_at)
                })
                .map(|out_at| {
                    format!(
                        " (used after snapshot · out {})",
                        format_last_used_age(out_at, now_unix)
                    )
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        lines.push(format!(
            "Updated : {} ({} · source: {:?} · {eval_tag}){used_after_suffix}",
            format_unix_local_minute(q.last_updated),
            format_relative_age(q.last_updated, now_unix),
            q.source_env,
        ));
    } else if is_selected {
        lines.push("Updated : never refreshed (press r to fetch)".into());
    } else {
        lines.push("Updated : never refreshed (switch with s, then press r)".into());
    }

    lines.push(String::new());
    lines.push("Quotas  :".into());
    let mut rendered_any_bucket = false;
    if let Some(ref q) = acc.quota {
        if let Some(ref groups) = q.quota_groups {
            for (target_pool, pool_label) in [
                (QuotaPool::Gemini, "Gemini"),
                (QuotaPool::ThirdParty, "Claude/GPT"),
                (QuotaPool::Argon, "Argon"),
            ] {
                let mut rows_for_pool: Vec<(u8, String, Option<i32>, String)> = Vec::new();
                for g in groups {
                    for b in &g.buckets {
                        if quota_pool(&b.bucket_id, &g.display_name) != Some(target_pool) {
                            continue;
                        }
                        let win = format_window_label(&b.window, &b.bucket_id);
                        let sort_key = if win == "Weekly" {
                            0
                        } else if win == "5h" {
                            1
                        } else {
                            2
                        };
                        let pct = observed_quota_percentage(
                            b.remaining_fraction,
                            b.remaining_fraction_known,
                        );
                        let reset_str = if is_unused_full_bucket_reset_time(
                            &b.reset_time,
                            b.remaining_fraction,
                            b.remaining_fraction_known,
                        ) {
                            "—".into()
                        } else {
                            format_reset_local(&b.reset_time, now_unix)
                        };
                        rows_for_pool.push((sort_key, win, pct, reset_str));
                    }
                }
                rows_for_pool.sort_by_key(|r| r.0);
                for (i, (_, win, pct, reset_str)) in rows_for_pool.into_iter().enumerate() {
                    rendered_any_bucket = true;
                    let prefix = if i == 0 {
                        format!("  {pool_label:<11}")
                    } else {
                        "             ".to_string()
                    };
                    let bar = format_bar_and_pct(pct);
                    lines.push(format!("{prefix}  {win:<6}  {bar}   resets {reset_str}"));
                }
            }
        }
    }
    if !rendered_any_bucket {
        if is_selected {
            lines.push("  (no cached quota buckets — press r to refresh)".into());
        } else {
            lines.push("  (no cached quota buckets — press s to switch, then r to refresh)".into());
        }
    }

    lines.push(String::new());
    match acc
        .quota
        .as_ref()
        .filter(|q| !is_empty_quota_placeholder(q))
    {
        None => {
            if is_selected {
                lines.push("Models  : unknown (press r to refresh)".into());
            } else {
                lines.push("Models  : unknown (switch with s, then press r)".into());
            }
        }
        Some(q) => {
            let models = extract_supported_models(q);
            if !models.is_empty() {
                lines.push(format!("Models ({} available):", models.len()));
                let mut gemini = Vec::new();
                let mut third_party = Vec::new();
                let mut other = Vec::new();
                for m in &models {
                    let lower = m.to_ascii_lowercase();
                    if lower.starts_with("gemini") {
                        gemini.push(m.as_str());
                    } else if lower.starts_with("claude") || lower.starts_with("gpt") {
                        third_party.push(m.as_str());
                    } else {
                        other.push(m.as_str());
                    }
                }
                for (family, items) in [
                    ("Gemini", gemini),
                    ("Claude/GPT", third_party),
                    ("Other", other),
                ] {
                    lines.extend(wrap_family_models_lines(family, &items, inner_width));
                }
            } else {
                let group_descs = extract_quota_group_descriptions(q);
                if !group_descs.is_empty() {
                    lines.push("Groups  :".into());
                    let group_label_w = group_descs
                        .iter()
                        .map(|(name, _)| display_width(name))
                        .max()
                        .unwrap_or(10)
                        .clamp(10, 26);
                    for (group_name, desc) in &group_descs {
                        lines.extend(wrap_labeled_text_lines(
                            group_name,
                            group_label_w,
                            desc,
                            inner_width,
                        ));
                    }
                } else {
                    lines.push("Models  : none reported".into());
                }
            }
        }
    }

    lines
}

struct DetailViewportSlice<'a> {
    visible: &'a [String],
    above: usize,
    below: usize,
}

fn slice_detail_lines_with_scroll<'a>(
    logical_lines: &'a [String],
    detail_scroll: &mut usize,
    inner_rows: usize,
) -> DetailViewportSlice<'a> {
    if inner_rows == 0 || logical_lines.is_empty() {
        *detail_scroll = 0;
        return DetailViewportSlice {
            visible: &[],
            above: 0,
            below: 0,
        };
    }
    let total = logical_lines.len();
    let max_scroll = total.saturating_sub(inner_rows);
    *detail_scroll = (*detail_scroll).min(max_scroll);
    let scroll = *detail_scroll;
    let end = (scroll + inner_rows).min(total);
    DetailViewportSlice {
        visible: &logical_lines[scroll..end],
        above: scroll,
        below: total.saturating_sub(end),
    }
}

fn format_detail_card_border(left: char, right: char, label: Option<&str>, cols: usize) -> String {
    let inner_cols = cols.saturating_sub(2);
    let Some(raw_label) = label else {
        return format!("{left}{}{right}", "─".repeat(inner_cols));
    };
    // Embed `─ <label> ─...─` into the border while guaranteeing total display width == `cols`.
    let decorated_budget = inner_cols.saturating_sub(4);
    if decorated_budget == 0 {
        return format!("{left}{}{right}", "─".repeat(inner_cols));
    }
    let clipped = truncate_to_cols(raw_label, decorated_budget);
    let clipped_w = display_width(&clipped);
    let trailing_dashes = inner_cols.saturating_sub(2 + clipped_w + 1);
    format!("{left}─ {clipped} {}{right}", "─".repeat(trailing_dashes))
}

#[allow(clippy::too_many_arguments)]
fn render_detail_card_lines(
    acc: &crate::domain::account::AccountRecord,
    is_selected: bool,
    is_marked: bool,
    detail_scroll: &mut usize,
    now_unix: i64,
    cols: usize,
    avail_rows: usize,
) -> Vec<String> {
    if avail_rows == 0 || cols == 0 {
        return Vec::new();
    }
    let use_box = cols >= 40 && avail_rows >= 5;
    if use_box {
        let inner_w = cols - 4; // `│ <inner_w> │`
        let inner_rows = avail_rows - 2;
        let logical = build_account_detail_lines(acc, is_selected, is_marked, now_unix, inner_w);
        let slice = slice_detail_lines_with_scroll(&logical, detail_scroll, inner_rows);
        let top_label = (slice.above > 0).then(|| format!("↑ {} more line(s) above", slice.above));
        let bot_label = (slice.below > 0).then(|| format!("↓ {} more line(s) below", slice.below));
        let mut out = Vec::with_capacity(slice.visible.len() + 2);
        out.push(format_detail_card_border(
            '┌',
            '┐',
            top_label.as_deref(),
            cols,
        ));
        for line in slice.visible {
            let clipped = truncate_to_cols(line, inner_w);
            let pad = inner_w.saturating_sub(display_width(&clipped));
            out.push(format!("│ {clipped}{} │", " ".repeat(pad)));
        }
        out.push(format_detail_card_border(
            '└',
            '┘',
            bot_label.as_deref(),
            cols,
        ));
        out
    } else {
        let logical = build_account_detail_lines(acc, is_selected, is_marked, now_unix, cols);
        let slice = slice_detail_lines_with_scroll(&logical, detail_scroll, avail_rows);
        slice
            .visible
            .iter()
            .map(|line| truncate_to_cols(line, cols))
            .collect()
    }
}

fn detail_keys_help_for_width(cols: usize, is_active: bool) -> String {
    let candidate = if is_active {
        if cols >= display_width(TUI_DETAIL_KEYS_LINE_ACTIVE) {
            TUI_DETAIL_KEYS_LINE_ACTIVE
        } else if cols >= 80 {
            "Keys   : ←/→ account · ↑/↓ scroll · Space mark · l lbl · r ref · s sw · i/Esc back"
        } else if cols >= 56 {
            "Keys   : ←/→ acc · ↑/↓ scr · Spc · l · r · s · i/Esc"
        } else {
            "Keys: ←/→ · ↑/↓ · l · r · s · i/Esc back"
        }
    } else if cols >= display_width(TUI_DETAIL_KEYS_LINE_DORMANT) {
        TUI_DETAIL_KEYS_LINE_DORMANT
    } else if cols >= 80 {
        "Keys   : ←/→ account · ↑/↓ scroll · Space mark · l lbl · s sw · i/Esc back"
    } else if cols >= 56 {
        "Keys   : ←/→ acc · ↑/↓ scr · Spc · l · s · i/Esc"
    } else {
        "Keys: ←/→ · ↑/↓ · l · s · i/Esc back"
    };
    truncate_to_cols(candidate, cols)
}

fn build_dashboard_frame_full(
    view: &mut TuiFrameView<'_>,
    term_cols: u16,
    term_rows: u16,
) -> String {
    let accounts = view.accounts;
    let session_id = view.session_id;
    let rotated_active_id = view.rotated_active_id;
    let runtime_st = view.runtime_st;
    let backend_tag = view.backend_tag;
    let marked_ids = view.marked_ids;
    let detail_view = view.detail_view;
    let cursor_idx = view.cursor_idx;
    let transient_notice = view.transient_notice;
    let now_unix = view.now_unix;

    let cols = term_cols as usize;
    let rows = term_rows as usize;
    let cur = if accounts.is_empty() {
        0
    } else {
        cursor_idx.min(accounts.len() - 1)
    };
    if cols == 0 || rows == 0 {
        *view.scroll_offset = cur;
        return String::new();
    }

    let clean_backend_tag = match backend_tag.trim().to_ascii_lowercase().as_str() {
        "dual" | "secret_service_dual" => "dual",
        "keyring" | "secret_service_keyring" => "keyring",
        _ => "file",
    };

    let active_slot_id = resolve_active_slot_account_id(session_id, rotated_active_id);
    let active_acc = resolve_active_account(accounts, session_id, rotated_active_id);
    let quota_hdr = build_active_quota_header(active_acc, now_unix);

    let last_used_cells: Vec<String> = accounts
        .iter()
        .map(|acc| {
            let is_active = active_slot_id == Some(acc.id.as_str());
            format_last_used_cell(acc, is_active, now_unix)
        })
        .collect();
    let show_id_col = cols >= 152;

    let sess_label = format!("Session [{clean_backend_tag}]");
    let use_two_line_header = rows >= 11;
    let use_expanded_quota_header = !detail_view && rows >= 14;
    let show_folded_quota_line = !detail_view && !use_expanded_quota_header && rows >= 7;
    let label_w = if detail_view {
        sess_label.len()
    } else {
        sess_label
            .len()
            .max(quota_hdr.label.len())
            .max("Runtime".len())
    };
    let session_human = format_session_identity_human(session_id);
    let compact_session_line = truncate_to_cols(
        &format!(
            "{sess_label}: {session_human} | Runtime: {}",
            format_runtime_state_human(runtime_st),
        ),
        cols,
    );

    let mut status_header_lines: Vec<String> = if use_two_line_header {
        vec![
            truncate_to_cols(&format!("{sess_label:<label_w$} : {session_human}"), cols),
            truncate_to_cols(
                &format!(
                    "{:<label_w$} : {}",
                    "Runtime",
                    format_runtime_state_human(runtime_st)
                ),
                cols,
            ),
        ]
    } else {
        vec![compact_session_line.clone()]
    };

    if use_expanded_quota_header {
        let indent = " ".repeat(label_w + 3);
        for (idx, qline) in quota_hdr.expanded_lines.iter().enumerate() {
            if idx == 0 {
                status_header_lines.push(truncate_to_cols(
                    &format!("{:<label_w$} : {qline}", quota_hdr.label),
                    cols,
                ));
            } else {
                status_header_lines.push(truncate_to_cols(&format!("{indent}{qline}"), cols));
            }
        }
    } else if show_folded_quota_line {
        if use_two_line_header {
            status_header_lines.push(truncate_to_cols(
                &format!(
                    "{:<label_w$} : {}",
                    quota_hdr.label, quota_hdr.compact_summary
                ),
                cols,
            ));
        } else {
            status_header_lines.push(truncate_to_cols(
                &format!("{}: {}", quota_hdr.label, quota_hdr.compact_summary),
                cols,
            ));
        }
    }

    let detail_is_active =
        !accounts.is_empty() && active_slot_id == Some(accounts[cur].id.as_str());
    let keys_line = keys_help_for_width(cols);
    let footer_help_lines: Vec<String> = if detail_view && !accounts.is_empty() {
        vec![detail_keys_help_for_width(cols, detail_is_active)]
    } else if rows >= 14 {
        keys_help_two_lines_for_width(cols).to_vec()
    } else {
        vec![keys_line.clone()]
    };
    let status_line = match transient_notice {
        Some(msg) if !msg.is_empty() => {
            truncate_to_cols(&format!("Status: {}", terminal_text(msg)), cols)
        }
        _ => match format_marked_footer_summary(
            accounts,
            marked_ids,
            cols.saturating_sub("Status: ".len()),
        ) {
            Some(marked_summary) => truncate_to_cols(&format!("Status: {marked_summary}"), cols),
            None => String::new(),
        },
    };

    let marked_count = accounts
        .iter()
        .filter(|a| marked_ids.contains(&a.id))
        .count();
    let marked_title_part = if marked_count > 0 {
        format!(" · {marked_count} marked")
    } else {
        String::new()
    };

    if detail_view && !accounts.is_empty() {
        let acc = &accounts[cur];
        let is_sel = active_slot_id == Some(acc.id.as_str());
        let is_marked = marked_ids.contains(&acc.id);
        let mut frame_lines: Vec<String> = Vec::with_capacity(rows);
        if rows < 5 {
            let title = truncate_to_cols(
                &format!(
                    "Detail [{}/{}]: {}",
                    cur + 1,
                    accounts.len(),
                    format_account_email_with_label(acc)
                ),
                cols,
            );
            let footer_or_status = if !status_line.is_empty() {
                status_line
            } else {
                detail_keys_help_for_width(cols, is_sel)
            };
            frame_lines.push(title);
            if rows >= 2 {
                let body_rows = rows.saturating_sub(2);
                if body_rows > 0 {
                    frame_lines.extend(render_detail_card_lines(
                        acc,
                        is_sel,
                        is_marked,
                        view.detail_scroll,
                        now_unix,
                        cols,
                        body_rows,
                    ));
                }
                frame_lines.push(footer_or_status);
            }
            frame_lines.truncate(rows);
            return frame_lines.join("\r\n");
        }

        let title = format!(
            "agy-switch-cli Headless SSH Dashboard  [Account Detail {}/{}{marked_title_part} — ←/→ account · ↑/↓ scroll · i/Esc back]",
            cur + 1,
            accounts.len()
        );
        let reserved_status = usize::from(!status_line.is_empty());
        let fixed_chrome =
            1 + status_header_lines.len() + footer_help_lines.len() + reserved_status;
        let avail_rows = rows.saturating_sub(fixed_chrome).max(1);
        frame_lines.push(truncate_to_cols(&title, cols));
        frame_lines.extend(status_header_lines);
        frame_lines.extend(render_detail_card_lines(
            acc,
            is_sel,
            is_marked,
            view.detail_scroll,
            now_unix,
            cols,
            avail_rows,
        ));
        frame_lines.extend(footer_help_lines);
        if !status_line.is_empty() {
            frame_lines.push(status_line);
        }
        frame_lines.truncate(rows);
        return frame_lines.join("\r\n");
    }

    let format_compact_row = |idx: usize| -> String {
        let acc = &accounts[idx];
        let is_sel = active_slot_id == Some(acc.id.as_str());
        let is_marked = marked_ids.contains(&acc.id);
        if cols == 1 {
            return if idx == cur {
                ">".into()
            } else if is_sel {
                "*".into()
            } else if is_marked {
                "+".into()
            } else {
                " ".into()
            };
        }
        let marker = if is_marked {
            match (idx == cur, is_sel) {
                (true, true) => ">*+",
                (true, false) => "> +",
                (false, true) => " *+",
                (false, false) => "  +",
            }
        } else {
            match (idx == cur, is_sel) {
                (true, true) => ">*",
                (true, false) => "> ",
                (false, true) => " *",
                (false, false) => "  ",
            }
        };
        if cols <= 3 {
            return truncate_to_cols(marker.trim_end(), cols);
        }
        let dto = AccountViewDto::from_record_at(acc, is_sel, now_unix);
        let state_tag = if dto.disabled {
            " [disabled]"
        } else if dto.validation_blocked {
            " [verify-blocked]"
        } else {
            ""
        };
        truncate_to_cols(
            &format!(
                "{marker} #{} {}{} | {}",
                idx + 1,
                format_account_email_with_label(acc),
                state_tag,
                last_used_cells[idx],
            ),
            cols,
        )
    };

    // Ultra-short physical terminals (1..=4 rows): stay strictly within `rows` without elevating budget.
    if rows < 5 {
        *view.scroll_offset = cur;
        let mut tiny: Vec<String> = Vec::with_capacity(rows);
        let footer_or_status = if !status_line.is_empty() {
            status_line
        } else {
            keys_line.clone()
        };
        if accounts.is_empty() {
            match rows {
                1 => tiny.push(truncate_to_cols(
                    "agy-switch-cli [0 accounts] (q quit)",
                    cols,
                )),
                2 => {
                    tiny.push(truncate_to_cols(
                        "agy-switch-cli Headless SSH Dashboard  [0 accounts]",
                        cols,
                    ));
                    tiny.push(footer_or_status);
                }
                3 => {
                    tiny.push(truncate_to_cols(
                        "agy-switch-cli Headless SSH Dashboard  [0 accounts]",
                        cols,
                    ));
                    tiny.push(compact_session_line);
                    tiny.push(footer_or_status);
                }
                _ => {
                    tiny.push(truncate_to_cols(
                        "agy-switch-cli Headless SSH Dashboard  [0 accounts]",
                        cols,
                    ));
                    tiny.push(compact_session_line);
                    tiny.push(keys_line);
                    if !footer_or_status.is_empty() && footer_or_status != tiny[2] {
                        tiny.push(footer_or_status);
                    }
                }
            }
        } else {
            let focus_line = format_compact_row(cur);
            let title_line = truncate_to_cols(
                &format!(
                    "agy-switch-cli Headless SSH Dashboard  [{}/{}{marked_title_part}]",
                    cur + 1,
                    accounts.len()
                ),
                cols,
            );
            match rows {
                1 => tiny.push(focus_line),
                2 => {
                    tiny.push(focus_line);
                    tiny.push(footer_or_status);
                }
                3 => {
                    tiny.push(title_line);
                    tiny.push(focus_line);
                    tiny.push(footer_or_status);
                }
                _ => {
                    tiny.push(title_line);
                    tiny.push(focus_line);
                    tiny.push(keys_line);
                    if !footer_or_status.is_empty() && footer_or_status != tiny[2] {
                        tiny.push(footer_or_status);
                    }
                }
            }
        }
        tiny.truncate(rows);
        return tiny.join("\r\n");
    }

    // Pre-compute global single-line column budgets across ALL accounts so bordered table rows NEVER
    // wrap onto multiple physical lines when long emails scroll into the viewport,
    // guaranteeing 100% constant frame height across every cursor position!
    let last_used_hdr = "Last Used (dur)";
    let num_table_cols = 5 + usize::from(show_id_col);
    let table_border_overhead = 3 * num_table_cols + 1;

    let idx_col_w = accounts.len().to_string().len().max(3); // fits `"..."` and `"12"`
    let sel_col_w = 3usize; // `"Sel"` / `">*+"`
    let id_col_w = if show_id_col {
        accounts
            .iter()
            .map(|a| display_width(&terminal_text(&a.id)))
            .max()
            .unwrap_or(2)
            .clamp(2, 36)
    } else {
        0
    };
    let last_used_col_w = last_used_cells
        .iter()
        .map(|s| display_width(s))
        .max()
        .unwrap_or(display_width(last_used_hdr))
        .clamp(display_width(last_used_hdr), 22);
    let state_str_for = |dto: &AccountViewDto| -> &'static str {
        if dto.disabled {
            "disabled"
        } else if dto.validation_blocked {
            "verify-blocked"
        } else {
            "ok"
        }
    };
    let state_col_w = accounts
        .iter()
        .map(|a| {
            let dto =
                AccountViewDto::from_record_at(a, active_slot_id == Some(a.id.as_str()), now_unix);
            display_width(state_str_for(&dto))
        })
        .max()
        .unwrap_or(5)
        .clamp(5, 14);

    let non_email_total =
        table_border_overhead + idx_col_w + sel_col_w + id_col_w + last_used_col_w + state_col_w;
    let email_col_budget = cols.saturating_sub(non_email_total);

    let render_slice =
        |start: usize, end: usize, show_top_dots: bool, show_bottom_dots: bool| -> String {
            let mut headers = vec![
                Cell::new("#").set_alignment(CellAlignment::Right),
                Cell::new("Sel"),
            ];
            if show_id_col {
                headers.push(Cell::new("ID"));
            }
            headers.push(Cell::new("Email"));
            headers.push(Cell::new(last_used_hdr));
            headers.push(Cell::new("State"));

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Disabled)
                .set_header(headers);

            let effective_email_cap = email_col_budget.max(5);
            let make_dots_row = |label: String| -> Vec<Cell> {
                let mut cells = vec![
                    Cell::new("...").set_alignment(CellAlignment::Right),
                    Cell::new(""),
                ];
                if show_id_col {
                    cells.push(Cell::new(""));
                }
                cells.push(Cell::new(truncate_to_cols(&label, effective_email_cap)));
                cells.push(Cell::new(""));
                cells.push(Cell::new(""));
                cells
            };

            if show_top_dots && start > 0 {
                table.add_row(make_dots_row(format!("... ({start} more above)")));
            }

            for idx in start..end {
                let acc = &accounts[idx];
                let dto = AccountViewDto::from_record_at(
                    acc,
                    active_slot_id == Some(acc.id.as_str()),
                    now_unix,
                );
                let is_marked = marked_ids.contains(&acc.id);
                let row_no = format!("{}", idx + 1);
                let pointer = if is_marked {
                    match (idx == cur, dto.is_selected) {
                        (true, true) => ">*+",
                        (true, false) => "> +",
                        (false, true) => " *+",
                        (false, false) => "  +",
                    }
                } else {
                    match (idx == cur, dto.is_selected) {
                        (true, true) => ">* ",
                        (true, false) => ">  ",
                        (false, true) => " * ",
                        (false, false) => "   ",
                    }
                };
                let last_used_str = truncate_to_cols(&last_used_cells[idx], last_used_col_w);
                let state_str = truncate_to_cols(state_str_for(&dto), state_col_w);
                let mut cells = vec![
                    Cell::new(row_no).set_alignment(CellAlignment::Right),
                    Cell::new(pointer),
                ];
                if show_id_col {
                    cells.push(Cell::new(truncate_to_cols(
                        &terminal_text(&dto.id),
                        id_col_w,
                    )));
                }
                cells.push(Cell::new(truncate_to_cols(
                    &format_account_email_with_label(acc),
                    effective_email_cap,
                )));
                cells.push(Cell::new(last_used_str));
                cells.push(Cell::new(state_str));
                table.add_row(cells);
            }

            if show_bottom_dots && end < accounts.len() {
                let below = accounts.len() - end;
                table.add_row(make_dots_row(format!("... ({below} more below)")));
            }

            table.to_string()
        };

    // Fixed chrome: 1 title line + `status_header_lines.len()` + optional blank gap on tall terminals
    // (`rows >= 20`) + `footer_help_lines.len()` + 1 reserved status line.
    let use_table_gap = rows >= 20;
    let fixed_chrome_lines =
        1 + status_header_lines.len() + usize::from(use_table_gap) + footer_help_lines.len() + 1;
    let max_table_lines = rows.saturating_sub(fixed_chrome_lines);
    let can_render_single_line_table = cols >= 64 && email_col_budget >= 8;
    let mut frame_lines: Vec<String> = Vec::with_capacity(rows);

    if accounts.is_empty() {
        *view.scroll_offset = 0;
        frame_lines.push(truncate_to_cols(
            "agy-switch-cli Headless SSH Dashboard  [0 accounts]",
            cols,
        ));
        frame_lines.extend(status_header_lines);
        if use_table_gap {
            frame_lines.push(String::new());
        }
        if can_render_single_line_table {
            let empty_tbl = render_slice(0, 0, false, false);
            if empty_tbl.lines().count() <= max_table_lines
                && empty_tbl.lines().all(|l| display_width(l) <= cols)
            {
                for line in empty_tbl.lines() {
                    frame_lines.push(truncate_to_cols(line, cols));
                }
            } else {
                frame_lines.push(truncate_to_cols("(No accounts saved)", cols));
            }
        } else {
            frame_lines.push(truncate_to_cols("(No accounts saved)", cols));
        }
        frame_lines.extend(footer_help_lines);
        if !status_line.is_empty() {
            frame_lines.push(status_line);
        }
    } else {
        // Attempt bordered table layout ONLY when every header, data row, and `...` row fits
        // strictly on ONE physical line (zero wrapped rows -> 100% constant frame height while scrolling!).
        let mut table_choice: Option<(usize, usize, String)> = None;
        if can_render_single_line_table && max_table_lines >= 5 {
            let max_rows_upper = max_table_lines.saturating_sub(4).max(1);
            let (start, end, show_top, show_bottom) = compute_viewport_with_indicators(
                accounts.len(),
                cur,
                *view.scroll_offset,
                max_rows_upper,
            );
            let expected_visual_rows = (end - start)
                + usize::from(show_top && start > 0)
                + usize::from(show_bottom && end < accounts.len());
            let tbl_str = render_slice(start, end, show_top, show_bottom);
            let actual_lines = tbl_str.lines().count();
            if actual_lines == expected_visual_rows + 4
                && actual_lines <= max_table_lines
                && tbl_str.lines().all(|l| display_width(l) <= cols)
            {
                table_choice = Some((start, end, tbl_str));
            }
        }

        if let Some((start, end, tbl_str)) = table_choice {
            *view.scroll_offset = start;
            let title = if start == 0 && end == accounts.len() {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [{} account(s){marked_title_part}]",
                    accounts.len()
                )
            } else {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [Showing {}-{} of {}{marked_title_part} — ↑/↓ scroll]",
                    start + 1,
                    end,
                    accounts.len()
                )
            };

            frame_lines.push(truncate_to_cols(&title, cols));
            frame_lines.extend(status_header_lines);
            if use_table_gap {
                frame_lines.push(String::new());
            }
            for line in tbl_str.lines() {
                frame_lines.push(truncate_to_cols(line, cols));
            }
            frame_lines.extend(footer_help_lines);
            if !status_line.is_empty() {
                frame_lines.push(status_line);
            }
        } else {
            // Compact focus list viewport: 1 physical row per account (plus constant-height `...` rows
            // when scrolling), guaranteed to keep `cur` visible even on narrow/short split panes.
            let compact_budget = (max_table_lines + usize::from(use_table_gap)).max(1);
            let (start, end, show_top, show_bottom) = compute_viewport_with_indicators(
                accounts.len(),
                cur,
                *view.scroll_offset,
                compact_budget,
            );
            *view.scroll_offset = start;

            let title = if start == 0 && end == accounts.len() {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [{} account(s){marked_title_part}]",
                    accounts.len()
                )
            } else {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [Showing {}-{} of {}{marked_title_part} — ↑/↓ scroll]",
                    start + 1,
                    end,
                    accounts.len()
                )
            };

            let format_compact_dots = |msg: &str| -> String {
                if cols <= 3 {
                    truncate_to_cols("…", cols)
                } else {
                    truncate_to_cols(&format!("   {msg}"), cols)
                }
            };

            frame_lines.push(truncate_to_cols(&title, cols));
            frame_lines.extend(status_header_lines);
            if show_top && start > 0 {
                frame_lines.push(format_compact_dots(&format!("... ({start} more above)")));
            }
            for idx in start..end {
                frame_lines.push(format_compact_row(idx));
            }
            if show_bottom && end < accounts.len() {
                let below = accounts.len() - end;
                frame_lines.push(format_compact_dots(&format!("... ({below} more below)")));
            }
            frame_lines.extend(footer_help_lines);
            if !status_line.is_empty() {
                frame_lines.push(status_line);
            }
        }
    }

    frame_lines.truncate(rows);
    // Join WITHOUT trailing `\r\n` on the final line so the terminal never scrolls row 0 off-screen!
    frame_lines.join("\r\n")
}

fn compute_viewport_with_indicators(
    total: usize,
    cur: usize,
    prev_offset: usize,
    row_budget: usize,
) -> (usize, usize, bool, bool) {
    if total == 0 || row_budget == 0 {
        return (0, 0, false, false);
    }
    let cur = cur.min(total - 1);
    if total <= row_budget {
        return (0, total, false, false);
    }
    if row_budget == 1 {
        return (cur, cur + 1, false, false);
    }
    if row_budget == 2 {
        return if cur == 0 {
            (0, 1, false, true)
        } else if cur + 1 == total {
            (cur, total, true, false)
        } else {
            (cur, cur + 1, false, true)
        };
    }

    // `row_budget >= 3 && total > row_budget`:
    // Top state (`start == 0`): 0 top dots + `(row_budget - 1)` accounts + 1 bottom dots = `row_budget` rows.
    // Middle state (`0 < start < bot_start`): 1 top dots + `(row_budget - 2)` accounts + 1 bottom dots = `row_budget` rows.
    // Bottom state (`end == total`): 1 top dots + `(row_budget - 1)` accounts + 0 bottom dots = `row_budget` rows.
    let edge_cap = row_budget - 1;
    let bot_start = total - edge_cap;
    let mid_cap = row_budget - 2;

    if cur == 0 || (prev_offset == 0 && cur < edge_cap) {
        (0, edge_cap, false, true)
    } else if cur + 1 == total || (prev_offset >= bot_start && cur >= bot_start) {
        (bot_start, total, true, false)
    } else {
        let max_mid_start = total - 1 - mid_cap;
        let mut start = prev_offset.clamp(1, max_mid_start);
        if cur < start {
            start = cur;
        }
        if cur >= start + mid_cap {
            start = cur + 1 - mid_cap;
        }
        start = start.clamp(1, max_mid_start);
        (start, start + mid_cap, true, true)
    }
}

fn keys_help_two_lines_for_width(cols: usize) -> [String; 2] {
    let l1 = if cols >= display_width(TUI_KEYS_LINE_1) {
        TUI_KEYS_LINE_1
    } else if cols >= 80 {
        "Keys   : ↑/↓ select · g/G top/end · [/] reorder · Space · s sw · i info · q quit"
    } else if cols >= 62 {
        "Keys   : ↑/↓ sel · g/G end · [/] ord · Spc · s · i · q quit"
    } else {
        "Keys   : ↑/↓ · g/G · [/] · Spc · s · i · q"
    };
    let l2 = if cols >= display_width(TUI_KEYS_LINE_2) {
        TUI_KEYS_LINE_2
    } else if cols >= 70 {
        "Manage : r ref (*) · e/E en · d/D dis · l lbl · o/O exp · x del"
    } else if cols >= 54 {
        "Manage : r (*) · e/E · d/D · l · o/O · x del"
    } else {
        "Manage : r · e/E · d/D · l · o/O · x"
    };
    [truncate_to_cols(l1, cols), truncate_to_cols(l2, cols)]
}

fn keys_help_for_width(cols: usize) -> String {
    let candidate = if cols >= display_width(TUI_KEYS_HELP_LINE) {
        TUI_KEYS_HELP_LINE
    } else if cols >= 130 {
        "Keys: ↑/↓ sel · g/G top/end · [/] order · Space mark · s sw · i info · r ref (*) · e/E en · d/D dis · l lbl · o/O exp · x del"
    } else if cols >= 100 {
        "Keys: ↑/↓ sel · g/G end · [/] ord · Spc · s sw · i · r ref (*) · e/E en · d/D dis · l · o/O · x del"
    } else if cols >= 80 {
        "Keys: ↑/↓ · g/G end · [/] ord · Spc/s/i · r (*) · e/E en · d/D dis · l/o · x del"
    } else {
        "Keys: ↑/↓ · g/G · [/] · Spc/s/i · r · e/E · d/D · l/o/O · x · q"
    };
    truncate_to_cols(candidate, cols)
}

fn display_width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

fn truncate_to_cols(s: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    if display_width(s) <= max_cols {
        return s.to_string();
    }
    if max_cols == 1 {
        return "…".into();
    }
    let max_cluster_chars = max_cols.saturating_mul(16).max(64);
    let mut buf = String::new();
    let mut best_len = 0usize;
    for g in UnicodeSegmentation::graphemes(s, true) {
        if g.chars().take(max_cluster_chars + 1).count() > max_cluster_chars {
            break;
        }
        buf.push_str(g);
        if display_width(&buf) > max_cols {
            break;
        }
        buf.push('…');
        let with_ellipsis_w = display_width(&buf);
        buf.pop();
        if with_ellipsis_w <= max_cols {
            best_len = buf.len();
        }
    }
    buf.truncate(best_len);
    buf.push('…');
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::account::{AccountRecord, RuntimeState, SessionIdentity};
    use crate::domain::quota::{QuotaBucket, QuotaGroup, QuotaObservation, QuotaSourceEnv};
    use crate::domain::token::TokenRecord;

    fn make_synthetic_account(idx: usize) -> AccountRecord {
        let now = crate::domain::clock::current_unix_seconds();
        let mut acc = AccountRecord::new(
            format!("00000000-0000-4000-8000-{idx:012}"),
            format!("synthetic.user.{idx:02}@example.invalid"),
            TokenRecord {
                access_token: format!("at-{idx}"),
                refresh_token: format!("rt-{idx}"),
                expires_in: 3600,
                expiry_timestamp: 1_900_000_000,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: None,
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now - 300,
        );
        let mut obs = QuotaObservation::new(now - 120, QuotaSourceEnv::OfficialCli);
        obs.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: Some(
                    "Models within this group: gemini-3.1-pro, gemini-3-flash".into(),
                ),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "gemini-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.72,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "gemini-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: "".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Claude and GPT models".into(),
                description: Some(
                    "Models within this group: claude-sonnet-4-6, gpt-oss-120b".into(),
                ),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "3p-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.37,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "3p-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.95,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T05:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
        ]);
        acc.quota = Some(obs);
        acc
    }

    #[test]
    fn transient_status_expires_after_ttl_while_keeping_keys_help_constant() {
        let t0 = Instant::now();
        let mut st = TransientStatus::default();
        assert_eq!(st.active_text(), None);
        assert!(!st.expire_if_due(t0));

        st.set_info("Disabled synthetic@example.invalid.".into(), t0);
        assert_eq!(
            st.active_text(),
            Some("Disabled synthetic@example.invalid.")
        );
        assert!(!st.expire_if_due(t0 + Duration::from_millis(2999)));
        assert_eq!(
            st.active_text(),
            Some("Disabled synthetic@example.invalid.")
        );
        assert!(st.expire_if_due(t0 + Duration::from_secs(3)));
        assert_eq!(st.active_text(), None);

        st.set_error("Switch error: lock busy".into(), t0);
        assert!(!st.expire_if_due(t0 + Duration::from_secs(4)));
        assert!(st.expire_if_due(t0 + Duration::from_secs(5)));
        assert_eq!(st.active_text(), None);
        assert!(TUI_KEYS_HELP_LINE.contains("↑/↓ select"));
        assert!(TUI_KEYS_HELP_LINE.contains("[/] reorder"));
        assert!(TUI_KEYS_HELP_LINE.contains("x delete"));
        assert!(!TUI_KEYS_HELP_LINE.contains("k/j"));
        assert!(!TUI_KEYS_HELP_LINE.contains("K/J"));
        assert!(!TUI_KEYS_HELP_LINE.contains("1-9"));
        assert!(!TUI_KEYS_HELP_LINE.contains("r/R"));
        assert!(!TUI_KEYS_HELP_LINE.contains("c/C"));
        assert!(!TUI_KEYS_HELP_LINE.contains("p policy"));
        assert!(!TUI_KEYS_HELP_LINE.contains("k cd"));
        assert!(TUI_KEYS_HELP_LINE.contains("r refresh (*) · e/E enable · d/D disable"));
        assert!(TUI_KEYS_LINE_2.contains("r refresh (on *)"));
        assert!(!TUI_KEYS_LINE_2.contains("c/C"));
        assert!(!TUI_KEYS_LINE_2.contains("p policy"));
        assert!(!TUI_KEYS_LINE_2.contains("k cd"));
        assert!(!TUI_KEYS_LINE_2.contains("r/R"));
    }

    #[test]
    fn v130_tui_last_used_dur_column_rules_detail_used_after_snapshot_and_external_drift() {
        let now = 1_800_000_000i64;
        let ts_1h04m = jiff::Timestamp::from_second(now + 3_840)
            .unwrap()
            .to_string();
        let ts_5d21h = jiff::Timestamp::from_second(now + 5 * 86_400 + 21 * 3_600)
            .unwrap()
            .to_string();

        // 1. Unit matrix for `format_last_used_cell` covering every locked rule in §6.3.4:
        let base_acc = |id: usize| {
            let mut a = make_synthetic_account(id);
            a.last_used = 0;
            a.last_switched_in_at = None;
            a.last_switched_out_at = None;
            a
        };

        // Active (*) cases: <1m, 42m, 3h15m, 2d4h, upgraded v1.2.7 (no in_at), clock rollback
        let mut a = base_acc(1);
        a.last_switched_in_at = Some(now - 35);
        assert_eq!(format_last_used_cell(&a, true, now), "active (<1m)");
        a.last_switched_in_at = Some(now - 42 * 60);
        assert_eq!(format_last_used_cell(&a, true, now), "active (42m)");
        a.last_switched_in_at = Some(now - (3 * 3600 + 15 * 60));
        assert_eq!(format_last_used_cell(&a, true, now), "active (3h15m)");
        a.last_switched_in_at = Some(now - (2 * 86_400 + 4 * 3600));
        assert_eq!(format_last_used_cell(&a, true, now), "active (2d4h)");
        a.last_switched_in_at = None;
        assert_eq!(format_last_used_cell(&a, true, now), "active");
        a.last_switched_in_at = Some(now + 600); // clock rollback
        assert_eq!(format_last_used_cell(&a, true, now), "active");

        // Dormant within 24h & session duration <= 12h: shows `age (dur)`
        let mut d = base_acc(2);
        d.last_switched_out_at = Some(now - 60);
        d.last_switched_in_at = Some(now - 60 - 40 * 60);
        assert_eq!(format_last_used_cell(&d, false, now), "1m ago (40m)");

        d.last_switched_out_at = Some(now - 12 * 60);
        d.last_switched_in_at = Some(now - 12 * 60 - 20);
        assert_eq!(format_last_used_cell(&d, false, now), "12m ago (<1m)");

        d.last_switched_out_at = Some(now - 6 * 3600);
        d.last_switched_in_at = Some(now - 6 * 3600 - (3600 + 20 * 60));
        assert_eq!(format_last_used_cell(&d, false, now), "6h ago (1h20m)");

        // Dormant session duration > 12h (e.g. overnight idle): omits parens!
        d.last_switched_out_at = Some(now - 60);
        d.last_switched_in_at = Some(now - 60 - (12 * 3600 + 1));
        assert_eq!(format_last_used_cell(&d, false, now), "1m ago");

        // Dormant switched out > 24h ago: omits parens even if session was short!
        d.last_switched_out_at = Some(now - 3 * 86_400);
        d.last_switched_in_at = Some(now - 3 * 86_400 - 1800);
        assert_eq!(format_last_used_cell(&d, false, now), "3d ago");

        // Dormant clock rollback (`now < out_at`): falls back cleanly to `just now`
        d.last_switched_out_at = Some(now + 300);
        d.last_switched_in_at = Some(now - 600);
        assert_eq!(format_last_used_cell(&d, false, now), "just now");

        // Brand-new never-switched-in account -> `never`
        let fresh = base_acc(3);
        assert_eq!(format_last_used_cell(&fresh, false, now), "never");

        // Upgraded v1.2.7 account (no switch timestamps, `last_used > 0`) -> age without parens
        let mut legacy = base_acc(4);
        legacy.last_used = now - 2 * 3600;
        assert_eq!(format_last_used_cell(&legacy, false, now), "2h ago");
        legacy.last_used = now - 5 * 86_400;
        assert_eq!(format_last_used_cell(&legacy, false, now), "5d ago");
        legacy.last_used = now + 500; // clock rollback
        assert_eq!(format_last_used_cell(&legacy, false, now), "just now");

        // 2. Full dashboard rendering with streamlined columns (`# | Sel | Email | Last Used (dur) | State`),
        //    zero `Policy` / `Plan` / `Last Quota`, top aligned `Quota` header, folded `7-13` rows,
        //    degraded `< 7` rows, and `i` detail card `(used after snapshot · out Xm ago)`!
        let mut acc1 = base_acc(1);
        acc1.email = "alice@example.com".into();
        acc1.custom_label = Some("main".into());
        acc1.last_switched_in_at = Some(now - 42 * 60);
        acc1.last_used = now - 42 * 60;
        let mut q1 = QuotaObservation::new(now - 120, QuotaSourceEnv::OfficialCli);
        q1.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: Some(
                    "Models within this group: gemini-3.1-pro, gemini-3-flash".into(),
                ),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "gemini-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.97,
                        remaining_fraction_known: Some(true),
                        reset_time: ts_1h04m,
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "gemini-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.97,
                        remaining_fraction_known: Some(true),
                        reset_time: ts_5d21h,
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Claude and GPT models".into(),
                description: Some(
                    "Models within this group: claude-sonnet-4-6, gpt-oss-120b".into(),
                ),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "3p-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: "1970-01-01T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "3p-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: "1970-01-01T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
        ]);
        acc1.quota = Some(q1);

        // Account 2 (dormant): switched out 10m ago (40m session), snapshot was 50m ago -> `out_at > last_updated + 60s`
        let mut acc2 = base_acc(2);
        acc2.email = "bob@example.com".into();
        acc2.custom_label = Some("bak1".into());
        acc2.last_switched_out_at = Some(now - 10 * 60);
        acc2.last_switched_in_at = Some(now - 50 * 60);
        acc2.last_used = now - 10 * 60;
        let mut q2 = QuotaObservation::new(now - 50 * 60, QuotaSourceEnv::OfficialCli);
        q2.quota_groups = Some(vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: Some("Models within this group: gemini-3.1-pro".into()),
            buckets: vec![
                QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: 0.50,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-01T05:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.70,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-07T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
            ],
        }]);
        acc2.quota = Some(q2);

        // Account 3 (dormant): brand-new never switched in (`never`)
        let mut acc3 = base_acc(3);
        acc3.email = "charlie@example.com".into();
        acc3.quota = None;

        // Account 4 (dormant): upgraded v1.2.7 account (`3d ago`, no parens)
        let mut acc4 = base_acc(4);
        acc4.email = "dave@example.com".into();
        acc4.last_used = now - 3 * 86_400;
        acc4.quota = None;

        let accounts = vec![acc1.clone(), acc2.clone(), acc3.clone(), acc4.clone()];
        let sess = SessionIdentity::Matched {
            account_id: acc1.id.clone(),
            email: acc1.email.clone(),
            expiry: "2099-01-01T00:00:00Z".into(),
        };
        let empty_marks = HashSet::new();
        let mut off = 0usize;
        let mut d_off = 0usize;
        let frame = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: false,
                detail_scroll: &mut d_off,
                cursor_idx: 0,
                scroll_offset: &mut off,
                transient_notice: None,
                now_unix: now,
            },
            120,
            24,
        );

        let hdr_lines: Vec<&str> = frame.split("\r\n").collect();
        assert!(
            hdr_lines[1].starts_with("Session [dual] : matched (alice@example.com")
                && !hdr_lines[1].contains(" · Pro"),
            "Unexpected Session header line: {}",
            hdr_lines[1]
        );
        assert!(!frame.contains("Policy"));
        assert!(!frame.contains("Plan"));
        assert!(!frame.contains("Last Quota"));
        assert!(
            frame.contains("Quota (2m ago) : Gemini      5h  97% (1h04m)  · Weekly  97% (5d21h)")
        );
        assert!(frame.contains("                 Claude/GPT  5h 100% (—)      · Weekly 100% (—)"));
        assert!(frame.contains("Last Used (dur)"));
        assert!(frame.contains("active (42m)"));
        assert!(frame.contains("10m ago (40m)"));
        assert!(frame.contains("never"));
        assert!(frame.contains("3d ago"));
        // Colons align vertically across Session / Runtime / Quota lines!
        let c1 = hdr_lines[1].find(" : ").unwrap();
        assert_eq!(hdr_lines[2].find(" : ").unwrap(), c1);
        assert_eq!(hdr_lines[3].find(" : ").unwrap(), c1);

        // Short terminal (`rows = 13`, folded `7-13` header) folds `Quota` to 1 line and keeps `Last Used (dur)`
        let mut off_short = 0usize;
        let frame_13 = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: false,
                detail_scroll: &mut d_off,
                cursor_idx: 0,
                scroll_offset: &mut off_short,
                transient_notice: None,
                now_unix: now,
            },
            120,
            13,
        );
        let lines_13: Vec<&str> = frame_13.split("\r\n").collect();
        assert!(lines_13.len() <= 13);
        assert!(frame_13.contains("Quota (2m ago) : Gem 97%/97% · 3P 100%/100%"));
        assert!(frame_13.contains("Last Used (dur)"));

        // Degraded `< 7` row terminal (`rows = 6`) shows compact single-line rows with `Last Used (dur)`
        let mut off_6 = 0usize;
        let frame_6 = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: false,
                detail_scroll: &mut d_off,
                cursor_idx: 0,
                scroll_offset: &mut off_6,
                transient_notice: None,
                now_unix: now,
            },
            100,
            6,
        );
        assert!(frame_6.split("\r\n").count() <= 6);
        assert!(frame_6.contains("active (42m)"));
        assert!(!frame_6.contains("Quota ("));

        // External drift (`DriftedExternal` with no rotated match) MUST NOT mark ANY row `*` or `active`!
        let ext_sess = SessionIdentity::DriftedExternal {
            email_hint: Some("stranger@example.com".into()),
            expiry: Some("2099-01-01T00:00:00Z".into()),
        };
        let mut off_ext = 0usize;
        let frame_ext = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &ext_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: false,
                detail_scroll: &mut d_off,
                cursor_idx: 0,
                scroll_offset: &mut off_ext,
                transient_notice: None,
                now_unix: now,
            },
            120,
            24,
        );
        for row in frame_ext.split("\r\n").filter(|l| l.starts_with('│')) {
            assert!(
                !row.contains('*') && !row.contains("active"),
                "External drift must never mark any row `*` or `active`: {row}"
            );
        }
        assert!(frame_ext.contains("— (no active account)"));

        // Interaction T2: `r` ONLY targets active `*` account; dormant/external returns gentle hint
        assert_eq!(
            resolve_r_refresh_target(&accounts, &sess, None, 0)
                .unwrap()
                .id,
            acc1.id
        );
        assert_eq!(
            resolve_r_refresh_target(&accounts, &sess, None, 1).unwrap_err(),
            TUI_DORMANT_REFRESH_HINT
        );
        assert_eq!(
            resolve_r_refresh_target(&accounts, &ext_sess, None, 0).unwrap_err(),
            TUI_DORMANT_REFRESH_HINT
        );
        assert_eq!(
            resolve_r_refresh_target(&accounts, &SessionIdentity::Uninitialized, None, 0)
                .unwrap_err(),
            TUI_DORMANT_REFRESH_HINT
        );

        // `i` detail card: strips `"Models within this group:"`, aligns `Groups` colons, omits `Plan`/`Policy`,
        // shows `r refresh` ONLY for active account, and appends `(used after snapshot · out 10m ago)` on Bob!
        let mut d_active = 0usize;
        let detail_active = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: true,
                detail_scroll: &mut d_active,
                cursor_idx: 0,
                scroll_offset: &mut off,
                transient_notice: None,
                now_unix: now,
            },
            120,
            26,
        );
        assert!(detail_active.contains("Groups  :"));
        assert!(detail_active.contains("gemini-3.1-pro"));
        assert!(!detail_active.contains("Models within this group:"));
        assert!(!detail_active.contains("Plan    :"));
        assert!(!detail_active.contains("Policy:"));
        assert!(detail_active.contains("State   : ok · Last used: active (42m)"));
        assert!(detail_active.contains("resets —"));
        assert!(!detail_active.contains("1970-01-01"));
        assert!(detail_active.contains("r refresh"));
        assert!(!detail_active.contains("used after snapshot"));

        let mut d_dormant = 0usize;
        let detail_dormant = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: true,
                detail_scroll: &mut d_dormant,
                cursor_idx: 1,
                scroll_offset: &mut off,
                transient_notice: None,
                now_unix: now,
            },
            120,
            26,
        );
        assert!(
            detail_dormant.contains("(used after snapshot · out 10m ago)"),
            "expected honest post-snapshot usage notice on Bob's detail card:\n{detail_dormant}"
        );
        assert!(
            !detail_dormant.contains("r refresh"),
            "dormant detail footer must omit `r refresh`: {detail_dormant}"
        );
    }

    #[test]
    fn v130_last_used_exact_boundaries_clock_rollbacks_and_active_detail_card_guards() {
        let now = 1_800_000_000i64;
        let base_acc = |id: usize| {
            let mut a = make_synthetic_account(id);
            a.last_used = 0;
            a.last_switched_in_at = None;
            a.last_switched_out_at = None;
            a
        };

        // 1. Exact 24h (`86_400s` vs `86_401s`) dormant age boundary in `format_last_used_cell`:
        let mut d = base_acc(1);
        d.last_switched_out_at = Some(now - 86_400);
        d.last_switched_in_at = Some(now - 86_400 - 1800);
        assert_eq!(format_last_used_cell(&d, false, now), "1d ago (30m)");
        d.last_switched_out_at = Some(now - 86_401);
        d.last_switched_in_at = Some(now - 86_401 - 1800);
        assert_eq!(format_last_used_cell(&d, false, now), "1d ago");

        // 2. Exact 12h (`43_200s` vs `43_201s`) dormant session duration boundary:
        d.last_switched_out_at = Some(now - 60);
        d.last_switched_in_at = Some(now - 60 - 43_200);
        assert_eq!(format_last_used_cell(&d, false, now), "1m ago (12h)");
        d.last_switched_out_at = Some(now - 60);
        d.last_switched_in_at = Some(now - 60 - 43_201);
        assert_eq!(format_last_used_cell(&d, false, now), "1m ago");

        // 3. Same-second switch-in & switch-out (`age == 0`, `dur == 0`) & clock-rollback edges:
        d.last_switched_out_at = Some(now);
        d.last_switched_in_at = Some(now);
        assert_eq!(format_last_used_cell(&d, false, now), "just now (<1m)");

        // Dormant clock rollback where `now < out_at`:
        d.last_switched_out_at = Some(now + 1);
        d.last_switched_in_at = Some(now - 120);
        assert_eq!(format_last_used_cell(&d, false, now), "just now");

        // Dormant with `in_at > out_at` (clock rolled back or pre-fix re-switch followed by drift):
        d.last_switched_out_at = Some(now - 600);
        d.last_switched_in_at = Some(now - 120);
        d.last_used = now - 120;
        assert_eq!(format_last_used_cell(&d, false, now), "2m ago");
        d.last_switched_in_at = Some(now + 300);
        d.last_used = now + 300;
        assert_eq!(format_last_used_cell(&d, false, now), "just now");

        // Active clock rollback (`now < in_at`) vs exact `now == in_at`:
        let mut active = base_acc(2);
        active.last_switched_in_at = Some(now);
        assert_eq!(format_last_used_cell(&active, true, now), "active (<1m)");
        active.last_switched_in_at = Some(now + 1);
        assert_eq!(format_last_used_cell(&active, true, now), "active");

        // 4. `build_account_detail_lines` guards `(used after snapshot · out ...)`:
        let mk_quota = |ts: i64| {
            let mut q = QuotaObservation::new(ts, QuotaSourceEnv::OfficialCli);
            q.quota_groups = Some(vec![QuotaGroup {
                display_name: "Gemini Models".into(),
                description: Some("Models within this group: gemini-3.1-pro".into()),
                buckets: vec![QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: 0.90,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-01T05:00:00Z".into(),
                    display_name: None,
                    description: None,
                }],
            }]);
            q
        };

        // 4a. Active account (`is_selected == true`) with older snapshot NEVER shows contradictory
        //     `(used after snapshot · out ...)`, even defensively if stale `last_switched_out_at` is set!
        let mut active_re_in = base_acc(3);
        active_re_in.quota = Some(mk_quota(now - 3600));
        active_re_in.last_switched_in_at = Some(now - 300);
        active_re_in.last_switched_out_at = Some(now - 900); // defensive stale legacy field
        let active_lines = build_account_detail_lines(&active_re_in, true, false, now, 110);
        let active_joined = active_lines.join("\n");
        assert!(active_joined.contains("State   : ok · Last used: active (5m)"));
        assert!(
            !active_joined.contains("used after snapshot"),
            "Active detail card must NEVER show contradictory `used after snapshot`: {active_joined}"
        );

        // 4b. Dormant account (`is_selected == false`) with stale `out_at < in_at` omits notice:
        let dormant_stale_out = build_account_detail_lines(&active_re_in, false, false, now, 110);
        assert!(
            !dormant_stale_out.join("\n").contains("used after snapshot"),
            "Dormant detail card with out_at < in_at must omit stale `used after snapshot`"
        );

        // 4c. Dormant account with `out_at >= in_at` enforces exact `> last_updated + 60` threshold:
        let mut dormant_edge = base_acc(4);
        dormant_edge.quota = Some(mk_quota(now - 600));
        dormant_edge.last_switched_in_at = Some(now - 600);
        dormant_edge.last_switched_out_at = Some(now - 540); // exactly +60s -> omitted
        let edge_eq = build_account_detail_lines(&dormant_edge, false, false, now, 110).join("\n");
        assert!(!edge_eq.contains("used after snapshot"));

        dormant_edge.last_switched_out_at = Some(now - 539); // +61s -> shown!
        let edge_gt = build_account_detail_lines(&dormant_edge, false, false, now, 110).join("\n");
        assert!(
            edge_gt.contains("(used after snapshot · out 8m ago)"),
            "expected post-snapshot notice at +61s threshold:\n{edge_gt}"
        );

        // 4d. Dormant account whose quota has unknown/zero `last_updated == 0` (e.g. forbidden)
        //     NEVER appends bogus `(used after snapshot · out ...)`:
        let mut zero_ts_q = QuotaObservation::new(0, QuotaSourceEnv::OfficialCli);
        zero_ts_q.is_forbidden = true;
        let mut dormant_zero_ts = base_acc(5);
        dormant_zero_ts.quota = Some(zero_ts_q);
        dormant_zero_ts.last_switched_in_at = Some(now - 600);
        dormant_zero_ts.last_switched_out_at = Some(now - 300);
        let zero_ts_lines =
            build_account_detail_lines(&dormant_zero_ts, false, false, now, 110).join("\n");
        assert!(zero_ts_lines.contains("Updated : unknown"));
        assert!(
            !zero_ts_lines.contains("used after snapshot"),
            "Zero last_updated snapshot must NEVER append `used after snapshot`: {zero_ts_lines}"
        );
    }

    #[test]
    fn tui_drifted_known_active_slot_aligns_r_target_table_star_detail_card_and_verify_blocked_notice(
    ) {
        let now = 1_800_000_000i64;
        let mut alice = make_synthetic_account(1);
        alice.email = "alice@example.com".into();
        alice.quota = None;
        let mut bob = make_synthetic_account(2);
        bob.email = "bob@example.com".into();
        bob.quota = None;
        let accounts = vec![alice.clone(), bob.clone()];
        let empty_marks = HashSet::new();

        let drifted_sess = SessionIdentity::DriftedKnown {
            account_id: bob.id.clone(),
            email: bob.email.clone(),
            expiry: "2099-01-01T00:00:00Z".into(),
        };

        assert_eq!(
            resolve_active_slot_account_id(&drifted_sess, None),
            Some(bob.id.as_str())
        );
        assert_eq!(
            resolve_active_account(&accounts, &drifted_sess, None).map(|a| a.id.as_str()),
            Some(bob.id.as_str())
        );

        assert_eq!(
            resolve_r_refresh_target(&accounts, &drifted_sess, None, 1)
                .unwrap()
                .id,
            bob.id
        );
        assert_eq!(
            resolve_r_refresh_target(&accounts, &drifted_sess, None, 0).unwrap_err(),
            TUI_DORMANT_REFRESH_HINT
        );

        let mut off = 0usize;
        let mut d_off = 0usize;
        let table_frame = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &drifted_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: false,
                detail_scroll: &mut d_off,
                cursor_idx: 0,
                scroll_offset: &mut off,
                transient_notice: None,
                now_unix: now,
            },
            120,
            24,
        );
        let alice_line = table_frame
            .split("\r\n")
            .find(|l| l.starts_with('│') && l.contains(&alice.email))
            .expect("alice row present");
        let bob_line = table_frame
            .split("\r\n")
            .find(|l| l.starts_with('│') && l.contains(&bob.email))
            .expect("bob row present");
        assert!(
            alice_line.contains(">  ") && !alice_line.contains('*'),
            "stale selected_id row must NOT show `*` when drifted to Bob: {alice_line}"
        );
        assert!(
            bob_line.contains(" * "),
            "DriftedKnown active slot row MUST show `*`: {bob_line}"
        );

        let mut d_bob = 0usize;
        let detail_bob = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &drifted_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: true,
                detail_scroll: &mut d_bob,
                cursor_idx: 1,
                scroll_offset: &mut off,
                transient_notice: None,
                now_unix: now,
            },
            120,
            24,
        );
        let detail_bob_footer = detail_bob.split("\r\n").last().expect("bob detail footer");
        assert!(detail_bob.contains("[active]"));
        assert!(detail_bob_footer.contains("· r refresh ·"));
        assert!(detail_bob.contains("press r to fetch"));

        let mut d_alice = 0usize;
        let detail_alice = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &drifted_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: true,
                detail_scroll: &mut d_alice,
                cursor_idx: 0,
                scroll_offset: &mut off,
                transient_notice: None,
                now_unix: now,
            },
            120,
            24,
        );
        let detail_alice_footer = detail_alice
            .split("\r\n")
            .last()
            .expect("alice detail footer");
        assert!(!detail_alice.contains("[active]"));
        assert!(!detail_alice_footer.contains("r refresh"));
        assert!(detail_alice.contains("switch with s, then press r"));

        let mut blocked_acc = bob.clone();
        blocked_acc.validation_blocked = true;
        blocked_acc.validation_url = Some("https://accounts.google.com/secret-verify-link".into());
        let blocked_notice = format_tui_refresh_status_notice(
            &crate::quota::official_cli::ActiveSlotQuotaRefreshOutcome {
                account: blocked_acc,
                validation_blocked: true,
                token_synced_back: false,
            },
        );
        assert!(
            blocked_notice.contains("verify-blocked")
                && blocked_notice.contains("open agy to verify")
                && blocked_notice.contains(&bob.email)
                && blocked_notice.contains(&bob.id),
        );
        assert!(
            !blocked_notice.contains("https://") && !blocked_notice.contains("secret-verify-link"),
        );

        let ok_notice = format_tui_refresh_status_notice(
            &crate::quota::official_cli::ActiveSlotQuotaRefreshOutcome {
                account: bob.clone(),
                validation_blocked: false,
                token_synced_back: false,
            },
        );
        assert_eq!(ok_notice, format!("Refreshed quota for {}.", bob.email));

        let mut c_off = 0usize;
        let mut c_d = 0usize;
        let narrow_list = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &drifted_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: false,
                detail_scroll: &mut c_d,
                cursor_idx: 0,
                scroll_offset: &mut c_off,
                transient_notice: None,
                now_unix: now,
            },
            44,
            12,
        );
        let narrow_alice = narrow_list
            .split("\r\n")
            .find(|l| l.contains("#1"))
            .expect("compact alice row");
        let narrow_bob = narrow_list
            .split("\r\n")
            .find(|l| l.contains("#2"))
            .expect("compact bob row");
        assert!(narrow_alice.starts_with(">  #1"));
        assert!(narrow_bob.starts_with(" * #2"));

        let mut tiny_off = 0usize;
        let mut tiny_d = 0usize;
        let tiny_bob_row = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &drifted_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: false,
                detail_scroll: &mut tiny_d,
                cursor_idx: 1,
                scroll_offset: &mut tiny_off,
                transient_notice: None,
                now_unix: now,
            },
            44,
            3,
        );
        assert!(tiny_bob_row.split("\r\n").any(|l| l.starts_with(">* #2")));

        let mut tiny_det_bob = 0usize;
        let tiny_detail_bob = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &drifted_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: true,
                detail_scroll: &mut tiny_det_bob,
                cursor_idx: 1,
                scroll_offset: &mut tiny_off,
                transient_notice: None,
                now_unix: now,
            },
            44,
            3,
        );
        assert!(tiny_detail_bob
            .split("\r\n")
            .last()
            .unwrap()
            .contains("· r ·"));

        let mut tiny_det_alice = 0usize;
        let tiny_detail_alice = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &drifted_sess,
                rotated_active_id: None,
                runtime_st: &RuntimeState::Idle,
                backend_tag: "dual",
                marked_ids: &empty_marks,
                detail_view: true,
                detail_scroll: &mut tiny_det_alice,
                cursor_idx: 0,
                scroll_offset: &mut tiny_off,
                transient_notice: None,
                now_unix: now,
            },
            44,
            3,
        );
        assert!(!tiny_detail_alice
            .split("\r\n")
            .last()
            .unwrap()
            .contains("· r ·"));
    }

    #[test]
    fn small_terminal_viewport_scrolls_smoothly_and_never_cuts_off_top_header() {
        let accounts: Vec<AccountRecord> = (1..=10).map(make_synthetic_account).collect();
        let session_id = SessionIdentity::Matched {
            account_id: accounts[0].id.clone(),
            email: accounts[0].email.clone(),
            expiry: "2099-01-01T00:00:00Z".into(),
        };
        let runtime_st = RuntimeState::Idle;
        let mut scroll_offset = 0usize;

        let frame_top = build_dashboard_frame(
            &accounts,
            &session_id,
            &runtime_st,
            0,
            &mut scroll_offset,
            None,
            108,
            16,
        );
        assert!(!frame_top.ends_with("\r\n"));
        let top_lines: Vec<&str> = frame_top.split("\r\n").collect();
        assert!(
            top_lines.len() <= 16,
            "Frame exceeded 16 terminal rows (got {}): {frame_top}",
            top_lines.len()
        );
        assert!(top_lines[0].starts_with("agy-switch-cli Headless SSH Dashboard"));
        assert!(top_lines[0].contains("Showing 1-"));
        assert!(frame_top.contains("synthetic.user.01@example.invalid"));
        assert!(!frame_top.contains("more above)"));
        assert!(frame_top.contains("more below)"));
        assert!(!frame_top.contains("00000000-0000-4000-8000"));
        for line in &top_lines {
            assert!(
                display_width(line) <= 108,
                "Line exceeded 108 cols ({}): {line}",
                display_width(line)
            );
        }

        let frame_mid = build_dashboard_frame(
            &accounts,
            &session_id,
            &runtime_st,
            5,
            &mut scroll_offset,
            None,
            108,
            16,
        );
        let mid_lines: Vec<&str> = frame_mid.split("\r\n").collect();
        assert_eq!(mid_lines.len(), top_lines.len());
        assert!(frame_mid.contains("more above)"));
        assert!(frame_mid.contains("synthetic.user.06@example.invalid"));
        assert!(frame_mid.contains("more below)"));

        let frame_bottom = build_dashboard_frame(
            &accounts,
            &session_id,
            &runtime_st,
            9,
            &mut scroll_offset,
            None,
            108,
            16,
        );
        let bottom_lines: Vec<&str> = frame_bottom.split("\r\n").collect();
        assert_eq!(bottom_lines.len(), top_lines.len());
        assert!(scroll_offset > 0);
        assert!(bottom_lines[0].starts_with("agy-switch-cli Headless SSH Dashboard"));
        assert!(frame_bottom.contains("more above)"));
        assert!(frame_bottom.contains("synthetic.user.10@example.invalid"));
        assert!(!frame_bottom.contains("more below)"));

        let frame_wide = build_dashboard_frame(
            &accounts,
            &session_id,
            &runtime_st,
            9,
            &mut scroll_offset,
            None,
            160,
            30,
        );
        assert_eq!(scroll_offset, 0);
        assert!(frame_wide.contains("[10 account(s)]"));
        assert!(frame_wide.contains("00000000-0000-4000-8000-000000000001"));
        assert!(frame_wide.contains("synthetic.user.01@example.invalid"));
        assert!(frame_wide.contains("synthetic.user.10@example.invalid"));
        assert!(!frame_wide.contains("more above)"));
        assert!(!frame_wide.contains("more below)"));
    }

    #[test]
    fn synthetic_tui_ultra_small_and_narrow_9_row_viewports_respect_physical_bounds_and_show_focus()
    {
        let session_id = SessionIdentity::Uninitialized;
        let runtime_st = RuntimeState::Idle;

        for (cols, rows) in [(0u16, 0u16), (0, 24), (80, 0)] {
            let mut off = 3usize;
            let empty_acc = [make_synthetic_account(1)];
            let rendered = build_dashboard_frame(
                &empty_acc,
                &session_id,
                &runtime_st,
                99,
                &mut off,
                Some("Ready."),
                cols,
                rows,
            );
            assert!(rendered.is_empty());
            assert_eq!(off, 0);
        }

        let mut short_acc = make_synthetic_account(1);
        short_acc.email = "focus.1@example.invalid".into();
        short_acc.quota = None;

        let mut long_acc = make_synthetic_account(2);
        long_acc.email = format!("focus.{}@example.invalid", "segment.".repeat(12));
        long_acc.quota = None;

        for (label, fixture_acc) in [("short_email", &short_acc), ("long_email", &long_acc)] {
            for (cols, rows) in [(40u16, 9u16), (52, 9), (60, 9), (72, 9)] {
                let mut scroll_offset = 0usize;
                let single = std::slice::from_ref(fixture_acc);
                let frame = build_dashboard_frame(
                    single,
                    &session_id,
                    &runtime_st,
                    0,
                    &mut scroll_offset,
                    None,
                    cols,
                    rows,
                );
                assert!(!frame.ends_with("\r\n"));
                let lines: Vec<&str> = frame.split("\r\n").collect();
                assert!(lines.len() <= rows as usize, "{label} {cols}x{rows}");
                for line in &lines {
                    assert!(UnicodeWidthStr::width(*line) <= cols as usize);
                }
                assert!(
                    lines
                        .iter()
                        .any(|l| l.contains('>') && l.contains("focus.")),
                    "{label} {cols}x{rows} hid focused account row:\n{frame}"
                );
            }
        }

        let many_accounts: Vec<AccountRecord> = (1..=12).map(make_synthetic_account).collect();
        let widths = [1u16, 2, 5, 10, 19, 39, 40, 52, 68, 80, 108, 152, 180];
        let heights = [1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 24];
        for count in [0usize, 1, 2, 12] {
            let slice = &many_accounts[..count];
            for &cols in &widths {
                for &rows in &heights {
                    for &cursor in &[0usize, 5, 99] {
                        for notice in [None, Some("Switched account.")] {
                            let mut scroll_offset = 7usize;
                            let frame = build_dashboard_frame(
                                slice,
                                &session_id,
                                &runtime_st,
                                cursor,
                                &mut scroll_offset,
                                notice,
                                cols,
                                rows,
                            );
                            assert!(!frame.ends_with("\r\n"));
                            let lines: Vec<&str> = frame.split("\r\n").collect();
                            assert!(lines.len() <= rows as usize);
                            for line in &lines {
                                assert!(UnicodeWidthStr::width(*line) <= cols as usize);
                            }
                            if count > 0 && cols >= 1 {
                                assert!(lines.iter().any(|l| l.contains('>')));
                            }
                        }
                    }
                }
            }
        }

        let mut argon_acc = make_synthetic_account(1);
        argon_acc.email = "focus.1@example.invalid".into();
        argon_acc
            .quota
            .as_mut()
            .unwrap()
            .quota_groups
            .as_mut()
            .unwrap()
            .push(QuotaGroup {
                display_name: "Gemini 4 Argon".into(),
                description: None,
                buckets: vec![QuotaBucket {
                    bucket_id: "gemini-argon-wtu-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.85,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-07T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                }],
            });
        let matched_argon = SessionIdentity::Matched {
            account_id: argon_acc.id.clone(),
            email: argon_acc.email.clone(),
            expiry: "2099-01-01T00:00:00Z".into(),
        };
        for cols in [40u16, 52, 60, 68, 72, 77, 78, 84, 96] {
            for rows in [9u16, 12, 16, 24] {
                let mut off = 0usize;
                let frame = build_dashboard_frame(
                    std::slice::from_ref(&argon_acc),
                    &matched_argon,
                    &runtime_st,
                    0,
                    &mut off,
                    None,
                    cols,
                    rows,
                );
                let lines: Vec<&str> = frame.split("\r\n").collect();
                assert!(lines.len() <= rows as usize);
                for line in &lines {
                    assert!(UnicodeWidthStr::width(*line) <= cols as usize);
                }
                assert!(lines
                    .iter()
                    .any(|l| l.contains('>') && l.contains("focus.1@")));
            }
        }
        let mut off_compact_argon = 0usize;
        let compact_argon_wide = build_dashboard_frame(
            std::slice::from_ref(&argon_acc),
            &matched_argon,
            &runtime_st,
            0,
            &mut off_compact_argon,
            None,
            100,
            8,
        );
        assert!(
            compact_argon_wide.contains("Arg 85%"),
            "expected folded quota header to include Argon pool when active:\n{compact_argon_wide}"
        );
    }

    #[test]
    fn synthetic_tui_standard_unicode_width_truncates_watch_and_emoji_sequences_within_cols() {
        let watch_notice = "⌚".repeat(70);
        let acc = make_synthetic_account(1);
        let mut scroll_offset = 0usize;
        let frame = build_dashboard_frame(
            std::slice::from_ref(&acc),
            &SessionIdentity::Uninitialized,
            &RuntimeState::Idle,
            0,
            &mut scroll_offset,
            Some(&watch_notice),
            80,
            16,
        );
        for line in frame.split("\r\n") {
            let w = UnicodeWidthStr::width(line);
            assert!(
                w <= 80,
                "status/frame line exceeded 80 standard columns (got {w}): {line}"
            );
        }

        assert_eq!(
            truncate_to_cols("12345678\u{26A0}\u{FE0F}abc", 10),
            "12345678…"
        );
        assert_eq!(
            truncate_to_cols("12345678\u{26A0}\u{FE0F}abc", 11),
            "12345678\u{26A0}\u{FE0F}…"
        );
        assert_eq!(
            truncate_to_cols("123456781\u{FE0F}\u{20E3}abc", 10),
            "12345678…"
        );
        assert_eq!(
            truncate_to_cols("12345678\u{1F468}\u{200D}\u{1F4BB}abc", 10),
            "12345678…"
        );
        assert_eq!(
            truncate_to_cols("12345678\u{1F468}\u{200D}\u{1F4BB}abc", 11),
            "12345678\u{1F468}\u{200D}\u{1F4BB}…"
        );
        assert_eq!(
            truncate_to_cols("1234567\u{1F1FA}\u{1F1F8}\u{1F1EF}\u{1F1F5}", 9),
            "1234567…"
        );
        assert_eq!(
            truncate_to_cols("1234567\u{1F1FA}\u{1F1F8}\u{1F1EF}\u{1F1F5}", 10),
            "1234567\u{1F1FA}\u{1F1F8}…"
        );
        assert_eq!(
            truncate_to_cols("12345678e\u{0301}abc", 10),
            "12345678e\u{0301}…"
        );
        assert_eq!(
            truncate_to_cols("12345678\u{0915}\u{093E}abc", 10),
            "12345678…"
        );
        assert_eq!(
            truncate_to_cols("12345678\u{0915}\u{093E}abc", 11),
            "12345678\u{0915}\u{093E}…"
        );
        let mut devanagari_acc = make_synthetic_account(1);
        devanagari_acc.email = "ab\u{0915}\u{093E}@example.invalid".into();
        let dev_sess = SessionIdentity::Matched {
            account_id: devanagari_acc.id.clone(),
            email: devanagari_acc.email.clone(),
            expiry: "2099-01-01T00:00:00Z".into(),
        };
        let mut off_dev = 0usize;
        let frame_dev = build_dashboard_frame(
            std::slice::from_ref(&devanagari_acc),
            &dev_sess,
            &RuntimeState::Idle,
            0,
            &mut off_dev,
            None,
            10,
            1,
        );
        assert_eq!(frame_dev, ">* #1 ab…");
        assert!(UnicodeWidthStr::width(frame_dev.as_str()) <= 10);

        let warn_seq = "\u{26A0}\u{FE0F}".repeat(50);
        let mixed = format!("Status: {} 汉字 {}", "⌚".repeat(30), warn_seq);
        for max_cols in 0..=85 {
            let truncated = truncate_to_cols(&mixed, max_cols);
            let actual = UnicodeWidthStr::width(truncated.as_str());
            assert!(actual <= max_cols);
        }
    }

    #[test]
    fn tui_two_line_header_backend_tags_short_collapse_and_gg_help_hints() {
        let acc = make_synthetic_account(1);
        let sess = SessionIdentity::Matched {
            account_id: acc.id.clone(),
            email: acc.email.clone(),
            expiry: "2026-11-18T08:00:00Z".into(),
        };
        let runtime = RuntimeState::UnmanagedRunning {
            pids: vec![636233],
            managed_account_ids: Vec::new(),
        };

        assert!(TUI_KEYS_HELP_LINE.contains("g/G top/end"));
        assert!(TUI_KEYS_HELP_LINE.contains("e/E enable · d/D disable"));
        for cols in [140usize, 110, 90, 80] {
            let help = keys_help_for_width(cols);
            assert!(
                help.contains("g/G ")
                    && help.contains("[/] ")
                    && help.contains("e/E ")
                    && help.contains("d/D ")
                    && help.contains("x "),
                "Expected word labels at cols={cols}: {help}"
            );
            assert!(display_width(&help) <= cols);
        }
        let help_74 = keys_help_for_width(74);
        assert!(
            help_74.contains("g/G")
                && help_74.contains("[/]")
                && help_74.contains("e/E")
                && help_74.contains("d/D")
                && help_74.contains("x")
        );
        assert!(display_width(&help_74) <= 74);

        let two_120 = keys_help_two_lines_for_width(120);
        assert_eq!(two_120[0], TUI_KEYS_LINE_1);
        assert_eq!(two_120[1], TUI_KEYS_LINE_2);
        assert_eq!(two_120[0].find(" : "), two_120[1].find(" : "));
        let two_80 = keys_help_two_lines_for_width(80);
        assert!(two_80[0].contains("Keys   : ↑/↓ select · g/G top/end · [/] reorder"));
        assert!(two_80[1].contains("Manage : r ref (*)"));
        assert!(!two_80[1].contains("c/C") && !two_80[1].contains("k cd"));
        for cols in [56usize, 60, 62, 70, 78, 80, 120] {
            let two = keys_help_two_lines_for_width(cols);
            assert_eq!(two[0].find(" : "), two[1].find(" : "));
            assert!(display_width(&two[0]) <= cols && display_width(&two[1]) <= cols);
        }

        // Normal height (`rows >= 11`): 2 separate aligned status lines (`Session [...]`, `Runtime`) + `Quota`
        for tag in ["file", "dual", "keyring"] {
            let mut off = 0usize;
            let frame = build_dashboard_frame_with_backend(
                std::slice::from_ref(&acc),
                &sess,
                &runtime,
                tag,
                0,
                &mut off,
                None,
                120,
                20,
            );
            let lines: Vec<&str> = frame.split("\r\n").collect();
            assert!(lines[1].starts_with(&format!("Session [{tag}] : matched (")));
            assert!(
                lines[2].starts_with("Runtime")
                    && lines[2].contains(": unmanaged_running (pids=[636233])")
            );
            assert!(!frame.contains("Policy"));
            let colon_1 = lines[1].find(" : ").unwrap();
            let colon_2 = lines[2].find(" : ").unwrap();
            let colon_3 = lines[3].find(" : ").unwrap();
            assert_eq!(colon_1, colon_2);
            assert_eq!(colon_2, colon_3);
        }

        // Short height (`rows = 8 < 11`): collapses Session|Runtime onto 1 line while keeping folded Quota
        let mut off_short = 0usize;
        let short_frame = build_dashboard_frame_with_backend(
            std::slice::from_ref(&acc),
            &sess,
            &runtime,
            "dual",
            0,
            &mut off_short,
            None,
            180,
            8,
        );
        let short_lines: Vec<&str> = short_frame.split("\r\n").collect();
        assert!(short_lines.len() <= 8);
        assert!(short_lines[1].starts_with("Session [dual]: "));
        assert!(short_lines[1].contains(" | Runtime: "));
        assert!(!short_lines[1].contains(" | Policy: "));

        // Verify `delete_account_in_tui` clears active slot and clamps `cursor_idx`!
        let tmp = tempfile::tempdir().unwrap();
        let paths = crate::paths::HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        std::fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let backend = crate::session::backend::FileSessionBackend;
        let a1 = make_synthetic_account(1);
        let a2 = make_synthetic_account(2);
        repo.with_write_lock(|tx| {
            tx.upsert_account(a1.clone(), false, 100)?;
            tx.upsert_account(a2.clone(), true, 100)?;
            Ok(())
        })
        .unwrap();
        backend
            .write_slot(
                &paths,
                &crate::session::payload::serialize_session_payload(&a2.token).unwrap(),
            )
            .unwrap();
        assert!(paths.active_slot_file.exists());

        let mut cursor = 1usize;
        let mut st = TransientStatus::default();
        delete_account_in_tui(
            &repo,
            &backend,
            &a2.id,
            &a2.email,
            true,
            &mut cursor,
            &mut st,
        );
        assert_eq!(cursor, 0);
        assert!(!paths.active_slot_file.exists());
        assert_eq!(repo.read_snapshot().unwrap().accounts.len(), 1);

        // 6. Deleting the ONLY remaining account clamps `cursor_idx = 0`; simulated `PartialCommitOrRecovery` (`7`)
        //    during active-slot clearing surfaces `Delete error:` while preserving `switch_journal.json` and the account!
        struct FailingRemoveBackend;
        impl CredentialBackend for FailingRemoveBackend {
            fn name(&self) -> &'static str {
                "dual"
            }
            fn uses_keyring(&self) -> bool {
                true
            }
            fn inspect_slot(
                &self,
                paths: &crate::paths::HeadlessPaths,
            ) -> crate::session::backend::SlotInspectState {
                crate::session::backend::FileSessionBackend.inspect_slot(paths)
            }
            fn inspect_replicas(
                &self,
                paths: &crate::paths::HeadlessPaths,
            ) -> crate::session::backend::BackendReplicaInspection {
                let f = self.inspect_slot(paths);
                let dig = f.raw_digest().map(str::to_string);
                let rt_fp = match &f {
                    crate::session::backend::SlotInspectState::Present(p) => {
                        Some(p.refresh_token_digest.clone())
                    }
                    _ => None,
                };
                crate::session::backend::BackendReplicaInspection {
                    backend_name: "dual",
                    uses_keyring: true,
                    uses_file: true,
                    keyring: Some(f.clone()),
                    keyring_all_collections_uniform: true,
                    keyring_collections: vec![crate::session::backend::KeyringCollectionDigest {
                        path: "/org/freedesktop/secrets/collection/login".into(),
                        present: dig.is_some(),
                        digest: dig,
                        valid_refresh_token_digest: rt_fp,
                    }],
                    file: f,
                }
            }
            fn snapshot_before_write(
                &self,
                paths: &crate::paths::HeadlessPaths,
            ) -> CliResult<Option<Vec<u8>>> {
                crate::session::backend::FileSessionBackend.snapshot_before_write(paths)
            }
            fn snapshot_replicas_before_write(
                &self,
                paths: &crate::paths::HeadlessPaths,
            ) -> CliResult<crate::session::backend::BackendPreWriteSnapshot> {
                let fb = self.snapshot_before_write(paths)?;
                Ok(crate::session::backend::BackendPreWriteSnapshot {
                    backend_name: "dual",
                    uses_keyring: true,
                    uses_file: true,
                    keyring_bytes: Some(fb.clone()),
                    keyring_uniform: true,
                    keyring_collections: vec![(
                        "/org/freedesktop/secrets/collection/login".into(),
                        fb.clone(),
                    )],
                    file_bytes: fb,
                })
            }
            fn write_slot(
                &self,
                paths: &crate::paths::HeadlessPaths,
                payload: &str,
            ) -> CliResult<()> {
                crate::session::backend::FileSessionBackend.write_slot(paths, payload)
            }
            fn remove_slot(&self, _paths: &crate::paths::HeadlessPaths) -> CliResult<()> {
                Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "simulated Secret Service NoReply during clear",
                ))
            }
            fn remove_slot_transactional(
                &self,
                _paths: &crate::paths::HeadlessPaths,
                _prev: &crate::session::backend::BackendPreWriteSnapshot,
            ) -> CliResult<()> {
                Err(CliError::partial_commit(
                    "recovery_incomplete",
                    "simulated Secret Service NoReply during clear",
                ))
            }
        }

        repo.with_write_lock(|tx| tx.commit_selected_account(&a1.id, 101))
            .unwrap();
        backend
            .write_slot(
                &paths,
                &crate::session::payload::serialize_session_payload(&a1.token).unwrap(),
            )
            .unwrap();
        // 5b. Verify `D` prompt message, `disable_all_accounts_in_tui`, and `enable_all_accounts_in_tui`!
        let a3 = make_synthetic_account(3);
        repo.with_write_lock(|tx| tx.upsert_account(a3.clone(), false, 100))
            .unwrap();
        assert_eq!(
            PendingTuiConfirm::DisableAll { enabled_count: 2 }.prompt_message_for_cols(120),
            "Disable all 2 account(s)? Press 'y' to confirm (any other key cancels)."
        );
        let mut st_batch = TransientStatus::default();
        disable_all_accounts_in_tui(&repo, &backend, &mut st_batch);
        assert_eq!(st_batch.active_text(), Some("Disabled all 2 account(s)."));
        assert!(repo
            .read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .all(|a| a.disabled));
        disable_all_accounts_in_tui(&repo, &backend, &mut st_batch);
        assert_eq!(
            st_batch.active_text(),
            Some("All accounts are already disabled.")
        );
        enable_all_accounts_in_tui(&repo, &backend, &mut st_batch);
        assert_eq!(
            st_batch.active_text(),
            Some("Enabled all 2 disabled account(s).")
        );
        assert!(repo
            .read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .all(|a| !a.disabled));
        enable_all_accounts_in_tui(&repo, &backend, &mut st_batch);
        assert_eq!(
            st_batch.active_text(),
            Some("All accounts are already enabled.")
        );
        repo.with_write_lock(|tx| tx.delete_account(&a3.id, true, 100))
            .unwrap();

        let mut cursor_fail = 0usize;
        let mut st_fail = TransientStatus::default();
        delete_account_in_tui(
            &repo,
            &FailingRemoveBackend,
            &a1.id,
            &a1.email,
            true,
            &mut cursor_fail,
            &mut st_fail,
        );
        assert!(
            st_fail
                .active_text()
                .unwrap_or("")
                .contains("Delete error: simulated Secret Service NoReply"),
            "Expected PartialCommitOrRecovery surfaced in status bar, got: {:?}",
            st_fail.active_text()
        );
        assert!(
            paths.switch_journal_file().exists(),
            "switch_journal.json must be preserved on PartialCommitOrRecovery"
        );
        assert!(
            paths.account_file(&a1.id).exists(),
            "account record must NOT be deleted when slot clear returns PartialCommitOrRecovery"
        );

        std::fs::remove_file(paths.switch_journal_file()).unwrap();
        let mut cursor_last = 0usize;
        let mut st_last = TransientStatus::default();
        delete_account_in_tui(
            &repo,
            &backend,
            &a1.id,
            &a1.email,
            true,
            &mut cursor_last,
            &mut st_last,
        );
        assert_eq!(cursor_last, 0);
        assert!(repo.read_snapshot().unwrap().accounts.is_empty());
        assert!(!paths.active_slot_file.exists());
    }

    #[test]
    fn r3_13_scrolling_with_long_email_keeps_constant_frame_height_across_all_cursor_positions() {
        let mut accounts: Vec<AccountRecord> = (0..12).map(make_synthetic_account).collect();
        accounts[5].email =
            "very.long.synthetic.account.identifier.0123456789.abcdef@sub.example.invalid".into();
        assert!(accounts[5].email.len() >= 76);
        accounts[5].disabled = true;
        accounts[5].validation_blocked = true;
        accounts[5].quota = Some(crate::domain::quota::QuotaObservation::new(
            100,
            crate::domain::quota::QuotaSourceEnv::Daily,
        ));
        accounts[9].validation_blocked = true;
        let session_id = SessionIdentity::Matched {
            account_id: accounts[0].id.clone(),
            email: accounts[0].email.clone(),
            expiry: "2026-11-19T12:00:00Z".into(),
        };

        for (cols, rows) in [(78usize, 16usize), (95, 18), (120, 20), (60, 14)] {
            let mut off = 0usize;
            let mut baseline_lines: Option<usize> = None;
            let mut baseline_bordered: Option<bool> = None;
            let positions: Vec<usize> = (0..accounts.len())
                .chain((0..accounts.len()).rev())
                .collect();
            for cur in positions {
                let frame = build_dashboard_frame(
                    &accounts,
                    &session_id,
                    &RuntimeState::Idle,
                    cur,
                    &mut off,
                    None,
                    cols as u16,
                    rows as u16,
                );
                let lines: Vec<&str> = frame.split("\r\n").collect();
                let is_bordered = lines.iter().any(|l| l.contains('┌'));
                assert!(lines.len() <= rows);
                for line in &lines {
                    assert!(display_width(line) <= cols);
                }
                assert!(lines.iter().any(|l| l.contains(">*") || l.contains("> ")));
                if let Some(expected) = baseline_lines {
                    assert_eq!(lines.len(), expected);
                } else {
                    baseline_lines = Some(lines.len());
                }
                if let Some(exp_b) = baseline_bordered {
                    assert_eq!(is_bordered, exp_b);
                } else {
                    baseline_bordered = Some(is_bordered);
                }
            }
        }
    }

    #[test]
    fn v122_tui_verify_blocked_switch_status_fits_80_columns() {
        use crate::domain::account::{AccountRecord, RuntimeState, SessionIdentity};
        use crate::domain::token::TokenRecord;
        use crate::switching::executor::SwitchOutcome;

        let acc = AccountRecord::new(
            "acc-0002".into(),
            "bob@example.com".into(),
            TokenRecord {
                access_token: "ya29.test".into(),
                refresh_token: "1//RT_TEST".into(),
                expires_in: 3600,
                expiry_timestamp: 2_000_000_000,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: None,
                project_id: None,
                is_gcp_tos: false,
                granted_scopes: None,
            },
            1_800_000_000,
        );
        let session_id = SessionIdentity::Matched {
            account_id: "acc-0002".into(),
            email: "bob@example.com".into(),
            expiry: "2099-01-01T00:00:00Z".into(),
        };

        let idle_out = SwitchOutcome {
            dry_run: false,
            previous_selected_id: Some("acc-0001".into()),
            target_account_id: "acc-0002".into(),
            target_email: "bob@example.com".into(),
            token_refreshed: false,
            refresh_token_rotated: false,
            runtime_warning: None,
            validation_blocked: true,
            validation_warning: Some("warning".into()),
        };
        let idle_msg = format_tui_switch_status_notice("", &idle_out);
        let mut scroll = 0usize;
        let frame_idle_80 = build_dashboard_frame_with_backend(
            std::slice::from_ref(&acc),
            &session_id,
            &RuntimeState::Idle,
            "file",
            0,
            &mut scroll,
            Some(&idle_msg),
            80,
            24,
        );
        assert!(frame_idle_80
            .contains("Status: Switched (verify-blocked): open agy to verify, press r"));

        let running_out = SwitchOutcome {
            runtime_warning: Some("running agy".into()),
            ..idle_out
        };
        let running_msg = format_tui_switch_status_notice("", &running_out);
        let frame_running_80 = build_dashboard_frame_with_backend(
            std::slice::from_ref(&acc),
            &session_id,
            &RuntimeState::UnmanagedRunning {
                pids: vec![4242],
                managed_account_ids: vec![],
            },
            "file",
            0,
            &mut scroll,
            Some(&running_msg),
            80,
            24,
        );
        assert!(frame_running_80
            .contains("Status: Switched (verify-blocked): open new agy to verify, press r"));

        let frame_running_160 = build_dashboard_frame_with_backend(
            std::slice::from_ref(&acc),
            &session_id,
            &RuntimeState::UnmanagedRunning {
                pids: vec![4242],
                managed_account_ids: vec![],
            },
            "file",
            0,
            &mut scroll,
            Some(&running_msg),
            160,
            24,
        );
        assert!(frame_running_160.contains(
            "Status: Switched (verify-blocked): open new agy to verify, press r — bob@example.com (acc-0002)"
        ));
    }

    #[test]
    fn synthetic_v124_tui_marked_selection_export_label_and_detail_m2() {
        use crate::domain::account::TransferBundle;
        use crate::domain::quota::ModelQuota;
        use crate::paths::HeadlessPaths;
        use crate::session::backend::FileSessionBackend;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data = tmp.path().join("data");
        let cache = tmp.path().join("cache");
        std::fs::create_dir_all(&home).unwrap();
        let paths = HeadlessPaths::with_explicit(home.clone(), data, cache);
        std::fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let now = 1_800_000_000i64;

        let mut acc1 = make_synthetic_account(1);
        acc1.email = "alice@example.com".into();
        acc1.custom_label = Some("primary".into());
        if let Some(ref mut q) = acc1.quota {
            q.models = (1..=14)
                .map(|m| ModelQuota {
                    name: if m <= 9 {
                        format!("gemini-3.{m}-pro-preview-ultra")
                    } else if m <= 12 {
                        format!("claude-sonnet-4-{m}")
                    } else {
                        format!("other-custom-model-{m}")
                    },
                    percentage: 80,
                    percentage_known: Some(true),
                    observed_remaining_fraction: Some(0.8),
                    primary_quota: None,
                    quota_bucket_id: Some("gemini-weekly".into()),
                    reset_time: "2099-01-01T00:00:00Z".into(),
                    display_name: None,
                    supports_images: None,
                    supports_thinking: None,
                    thinking_budget: None,
                    recommended: None,
                    max_tokens: None,
                    max_output_tokens: None,
                    supported_mime_types: None,
                })
                .collect();
        }
        let mut acc2 = make_synthetic_account(2);
        acc2.email = "bob@example.com".into();
        let mut acc3 = make_synthetic_account(3);
        acc3.email = "charlie@example.com".into();
        acc3.custom_label = Some("backup".into());

        repo.with_write_lock(|tx| {
            tx.upsert_account(acc1.clone(), true, now)?;
            tx.upsert_account(acc2.clone(), false, now)?;
            tx.upsert_account(acc3.clone(), false, now)?;
            Ok(())
        })
        .unwrap();

        let accounts = vec![acc1.clone(), acc2.clone(), acc3.clone()];
        let sess = SessionIdentity::Matched {
            account_id: acc1.id.clone(),
            email: acc1.email.clone(),
            expiry: "2099-01-01T00:00:00Z".into(),
        };
        let runtime = RuntimeState::Idle;

        // 1. Scheme L1 label display + Strategy B persistent marked footer.
        let mut marks = HashSet::new();
        marks.insert(acc1.id.clone());
        marks.insert(acc3.id.clone());
        let mut scroll = 0usize;
        let mut detail_scroll = 0usize;
        let frame_main = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &runtime,
                backend_tag: "dual",
                marked_ids: &marks,
                detail_view: false,
                detail_scroll: &mut detail_scroll,
                cursor_idx: 2,
                scroll_offset: &mut scroll,
                transient_notice: None,
                now_unix: now,
            },
            120,
            22,
        );
        assert!(frame_main.contains("2 marked"));
        assert!(frame_main.contains("alice@example.com (primary)"));
        assert!(frame_main.contains("charlie@example.com (backup)"));
        assert!(frame_main.contains(" *+") && frame_main.contains("> +"));
        assert!(frame_main.contains(
            "Status: Marked (2): alice@example.com, charlie@example.com  [Esc to clear]"
        ));
        for line in frame_main.split("\r\n") {
            assert!(display_width(line) <= 120);
        }

        let narrow_footer = format_marked_footer_summary(&accounts, &marks, 52).unwrap();
        assert!(display_width(&narrow_footer) <= 52);
        assert!(narrow_footer.contains("Marked (2)"));

        // 2. Label editing (multi-byte UTF-8 grapheme Backspace safety) + persistence + clearing.
        let mut inp = PendingTuiInput::EditLabel {
            account_id: acc2.id.clone(),
            email: acc2.email.clone(),
            buffer: "work-mainX".into(),
        };
        inp.pop_grapheme();
        inp.push_char('1');
        inp.push_char('\x1b');
        assert_eq!(inp.buffer_mut().as_str(), "work-main1");

        let mut utf8_inp = PendingTuiInput::EditLabel {
            account_id: acc2.id.clone(),
            email: acc2.email.clone(),
            buffer: "tag-中".into(),
        };
        utf8_inp.pop_grapheme();
        assert_eq!(utf8_inp.buffer_mut().as_str(), "tag-");

        let mut status = TransientStatus::default();
        update_label_in_tui(
            &repo,
            &FileSessionBackend,
            &acc2.id,
            &acc2.email,
            "work-main1",
            &mut status,
        );
        assert_eq!(
            repo.read_snapshot()
                .unwrap()
                .accounts
                .iter()
                .find(|a| a.id == acc2.id)
                .unwrap()
                .custom_label
                .as_deref(),
            Some("work-main1")
        );
        update_label_in_tui(
            &repo,
            &FileSessionBackend,
            &acc2.id,
            &acc2.email,
            "   ",
            &mut status,
        );
        assert_eq!(
            repo.read_snapshot()
                .unwrap()
                .accounts
                .iter()
                .find(|a| a.id == acc2.id)
                .unwrap()
                .custom_label,
            None
        );

        // 3. Export marked subset (`0600`, exact accounts, refuses overwrite, `~/` expands to `home_dir`).
        let expanded = expand_tui_export_path("~/exports/subset.json", &home).unwrap();
        assert_eq!(expanded, home.join("exports/subset.json"));
        assert!(expand_tui_export_path("   ", &home).is_err());
        assert!(expand_tui_export_path("~", &home).is_err());

        let export_ids = vec![acc1.id.clone(), acc3.id.clone()];
        export_accounts_in_tui(&repo, &expanded, &export_ids, &mut status);
        assert!(status
            .active_text()
            .unwrap_or("")
            .contains("Exported 2 account(s)"));
        let mode = std::fs::metadata(&expanded).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let exported_bytes = std::fs::read(&expanded).unwrap();
        let bundle: TransferBundle = serde_json::from_slice(&exported_bytes).unwrap();
        let emails: Vec<&str> = bundle.accounts.iter().map(|a| a.email.as_str()).collect();
        assert_eq!(emails, vec!["alice@example.com", "charlie@example.com"]);

        export_accounts_in_tui(&repo, &expanded, &export_ids, &mut status);
        assert!(status
            .active_text()
            .unwrap_or("")
            .contains("already exists"));
        assert_eq!(std::fs::read(&expanded).unwrap(), exported_bytes);

        // 4. Batch marked disable/enable.
        disable_marked_accounts_in_tui(&repo, &FileSessionBackend, &export_ids, &mut status);
        let snap_dis = repo.read_snapshot().unwrap();
        assert!(
            snap_dis
                .accounts
                .iter()
                .find(|a| a.id == acc1.id)
                .unwrap()
                .disabled
        );
        assert!(
            snap_dis
                .accounts
                .iter()
                .find(|a| a.id == acc3.id)
                .unwrap()
                .disabled
        );
        assert!(
            !snap_dis
                .accounts
                .iter()
                .find(|a| a.id == acc2.id)
                .unwrap()
                .disabled
        );
        enable_marked_accounts_in_tui(&repo, &FileSessionBackend, &export_ids, &mut status);
        let snap_en = repo.read_snapshot().unwrap();
        assert!(
            !snap_en
                .accounts
                .iter()
                .find(|a| a.id == acc1.id)
                .unwrap()
                .disabled
        );
        assert!(
            !snap_en
                .accounts
                .iter()
                .find(|a| a.id == acc3.id)
                .unwrap()
                .disabled
        );

        // 5. Scheme M2 detail view: full wrapped `Models` + top/bottom internal scroll + strict bounds!
        let mut d_scroll = 0usize;
        let top_detail = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &runtime,
                backend_tag: "file",
                marked_ids: &marks,
                detail_view: true,
                detail_scroll: &mut d_scroll,
                cursor_idx: 0,
                scroll_offset: &mut scroll,
                transient_notice: None,
                now_unix: now,
            },
            96,
            18,
        );
        let top_lines: Vec<&str> = top_detail.split("\r\n").collect();
        assert!(top_lines.len() <= 18);
        for l in &top_lines {
            assert!(display_width(l) <= 96);
        }
        assert!(top_detail.contains("Account : alice@example.com (primary)"));
        assert!(top_detail.contains("Quotas  :"));
        assert!(top_detail.contains("resets "));
        let top_border_0 = top_lines
            .iter()
            .copied()
            .find(|l| l.starts_with('┌'))
            .unwrap();
        let bot_border_0 = top_lines
            .iter()
            .copied()
            .find(|l| l.starts_with('└'))
            .unwrap();
        assert_eq!(display_width(top_border_0), 96);
        assert_eq!(display_width(bot_border_0), 96);
        assert!(!top_border_0.contains("more line(s) above"));
        assert!(bot_border_0.contains("└─ ↓ ") && bot_border_0.contains("more line(s) below"));
        let below_0: usize = bot_border_0
            .split("└─ ↓ ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap();
        assert!(below_0 >= 2);
        let body_0: Vec<&str> = top_lines
            .iter()
            .copied()
            .filter(|l| l.starts_with('│'))
            .collect();
        assert!(body_0
            .first()
            .unwrap()
            .contains("Account : alice@example.com (primary)"));

        let mut d_scroll_1 = 1usize;
        let step1_detail = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &runtime,
                backend_tag: "file",
                marked_ids: &marks,
                detail_view: true,
                detail_scroll: &mut d_scroll_1,
                cursor_idx: 0,
                scroll_offset: &mut scroll,
                transient_notice: None,
                now_unix: now,
            },
            96,
            18,
        );
        let step1_lines: Vec<&str> = step1_detail.split("\r\n").collect();
        assert_eq!(top_lines.len(), step1_lines.len());
        let top_border_1 = step1_lines
            .iter()
            .copied()
            .find(|l| l.starts_with('┌'))
            .unwrap();
        let bot_border_1 = step1_lines
            .iter()
            .copied()
            .find(|l| l.starts_with('└'))
            .unwrap();
        assert!(top_border_1.contains("┌─ ↑ 1 more line(s) above "));
        assert!(bot_border_1.contains(&format!("└─ ↓ {} more line(s) below ", below_0 - 1)));
        let body_1: Vec<&str> = step1_lines
            .iter()
            .copied()
            .filter(|l| l.starts_with('│'))
            .collect();
        assert_eq!(body_0.len(), body_1.len());
        assert_eq!(body_1[0], body_0[1]);
        assert_ne!(body_1.last(), body_0.last());

        let mut d_scroll_end = usize::MAX;
        let bot_detail = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &runtime,
                backend_tag: "file",
                marked_ids: &marks,
                detail_view: true,
                detail_scroll: &mut d_scroll_end,
                cursor_idx: 0,
                scroll_offset: &mut scroll,
                transient_notice: None,
                now_unix: now,
            },
            96,
            18,
        );
        let bot_lines: Vec<&str> = bot_detail.split("\r\n").collect();
        let top_border_end = bot_lines
            .iter()
            .copied()
            .find(|l| l.starts_with('┌'))
            .unwrap();
        let bot_border_end = bot_lines
            .iter()
            .copied()
            .find(|l| l.starts_with('└'))
            .unwrap();
        assert!(top_border_end.contains("┌─ ↑ ") && top_border_end.contains("more line(s) above"));
        assert!(!bot_border_end.contains("more line(s) below"));
        assert!(bot_detail.contains("other-custom-model-14"));
        assert_eq!(top_lines.len(), bot_lines.len());

        let mut narrow_box_scroll = 1usize;
        let narrow_box_detail = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &runtime,
                backend_tag: "file",
                marked_ids: &marks,
                detail_view: true,
                detail_scroll: &mut narrow_box_scroll,
                cursor_idx: 0,
                scroll_offset: &mut scroll,
                transient_notice: None,
                now_unix: now,
            },
            40,
            12,
        );
        assert!(narrow_box_detail.split("\r\n").count() <= 12);
        for l in narrow_box_detail.split("\r\n") {
            assert!(display_width(l) <= 40);
        }
        assert!(narrow_box_detail.contains("┌─ ↑ 1 more line(s) above "));
        assert!(narrow_box_detail.contains("└─ ↓ "));

        let mut tiny_scroll = 0usize;
        let tiny_detail = build_dashboard_frame_full(
            &mut TuiFrameView {
                accounts: &accounts,
                session_id: &sess,
                rotated_active_id: None,
                runtime_st: &runtime,
                backend_tag: "file",
                marked_ids: &marks,
                detail_view: true,
                detail_scroll: &mut tiny_scroll,
                cursor_idx: 0,
                scroll_offset: &mut scroll,
                transient_notice: None,
                now_unix: now,
            },
            30,
            4,
        );
        assert!(tiny_detail.split("\r\n").count() <= 4);
        for l in tiny_detail.split("\r\n") {
            assert!(display_width(l) <= 30);
        }

        // 7. P1-01: Accidental credential pasted into export path is masked immediately and rejected pre-confirm.
        let secret_samples = [
            "1//0gSyntheticRefreshSecretTokenValue999",
            "ya29.SyntheticAccessTokenValue999",
            "GOCSPX-SyntheticClientSecret999",
            "https://example.com/callback?code=SyntheticCode999",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            "~/1//0gSyntheticRefreshSecretTokenValue999",
        ];
        for raw_secret in secret_samples {
            let inp = PendingTuiInput::ExportPath {
                account_ids: vec![acc1.id.clone()],
                scope_label: "1 account".into(),
                buffer: raw_secret.into(),
            };
            let edit_prompt = inp.prompt_message(&home);
            assert!(
                edit_prompt.contains("[REDACTED]"),
                "expected [REDACTED] for {raw_secret}, got {edit_prompt}"
            );
            assert!(
                !edit_prompt.contains("Synthetic") && !edit_prompt.contains("AbCdEf"),
                "edit prompt leaked secret: {edit_prompt}"
            );

            let mut confirm_slot: Option<PendingTuiConfirm> = None;
            let mut warn_rendered = false;
            let mut st_secret = TransientStatus::default();
            let outcome = apply_pending_input_key(
                inp,
                crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                &repo,
                &FileSessionBackend,
                &mut confirm_slot,
                &mut warn_rendered,
                &mut st_secret,
            );
            assert!(matches!(outcome, InputKeyOutcome::Finished));
            assert!(
                confirm_slot.is_none(),
                "secret-like path must NEVER enter PendingTuiConfirm"
            );
            let err_msg = st_secret.active_text().unwrap_or("");
            assert!(
                err_msg.contains("redacted"),
                "expected sanitized error, got {err_msg}"
            );
            assert!(
                !err_msg.contains("Synthetic") && !err_msg.contains("AbCdEf"),
                "error leaked secret: {err_msg}"
            );
        }
        // Normal paths keep full editing visibility and normalize `~//` safely under `home`.
        let normal_inp = PendingTuiInput::ExportPath {
            account_ids: vec![acc1.id.clone()],
            scope_label: "1 account".into(),
            buffer: "~/exports/my-backup-2026-11-21.json".into(),
        };
        assert!(normal_inp
            .prompt_message(&home)
            .contains("~/exports/my-backup-2026-11-21.json"));
        assert_eq!(
            expand_tui_export_path("~//exports/subset.json", &home).unwrap(),
            home.join("exports/subset.json")
        );

        // 8. P2-01: Plaintext export warning sits ahead of path and stays visible at 30x16 & 120x24,
        //    while ultra-narrow (<23 cols) or 1-row screens refuse confirmation.
        let confirm_exp = PendingTuiConfirm::ExportBundle {
            account_ids: vec![acc1.id.clone(), acc3.id.clone()],
            output_path: home.join("exports/my-very-long-backup-file-name.json"),
        };
        for (cols, rows, must_show) in [
            (120u16, 24u16, true),
            (80, 24, true),
            (30, 16, true),
            (23, 16, true),
            (22, 16, false),
            (20, 16, false),
            (80, 1, false),
        ] {
            let msg = confirm_exp.prompt_message_for_cols(cols as usize);
            let mut scr = 0usize;
            let mut dscr = 0usize;
            let frame = build_dashboard_frame_full(
                &mut TuiFrameView {
                    accounts: &accounts,
                    session_id: &sess,
                    rotated_active_id: None,
                    runtime_st: &runtime,
                    backend_tag: "file",
                    marked_ids: &marks,
                    detail_view: false,
                    detail_scroll: &mut dscr,
                    cursor_idx: 0,
                    scroll_offset: &mut scr,
                    transient_notice: Some(&msg),
                    now_unix: now,
                },
                cols,
                rows,
            );
            let fits = export_confirm_warning_fits(cols as usize, rows as usize)
                && rendered_frame_shows_export_plaintext_warning(&frame);
            assert_eq!(
                fits, must_show,
                "unexpected plaintext warning visibility for {cols}x{rows}:\n{frame}"
            );
            for line in frame.split("\r\n") {
                assert!(
                    display_width(line) <= cols as usize,
                    "export confirm frame line exceeded {cols} cols: {line}"
                );
            }
        }

        // 9. P2-04: Target resolution when viewing unmarked cursor account with marked set present.
        let (detail_r_targets, from_marked) = resolve_tui_targets(&accounts, 1, &marks);
        assert!(from_marked);
        let detail_r_ids: Vec<&str> = detail_r_targets.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(detail_r_ids, vec![acc1.id.as_str(), acc3.id.as_str()]);

        // 10. P2-05: Narrow-screen single long model name wraps cleanly across lines by grapheme.
        let long_model = "claude-opus-4-6-thinking-preview-superlong";
        for width in [30usize, 20usize] {
            let wrapped = wrap_family_models_lines("Claude/GPT", &[long_model], width);
            assert!(
                wrapped.len() >= 2,
                "expected multi-line wrap at width {width}: {wrapped:?}"
            );
            for l in &wrapped {
                assert!(
                    display_width(l) <= width,
                    "wrapped model line exceeded {width} cols: {l}"
                );
            }
            let joined_tail: String = wrapped
                .iter()
                .map(|l| {
                    l.strip_prefix("  Claude/GPT : ")
                        .or_else(|| l.strip_prefix("  Claude/GPT:"))
                        .unwrap_or(l)
                        .trim()
                })
                .collect();
            assert_eq!(
                joined_tail, long_model,
                "wrapped chunks lost characters at width {width}: {wrapped:?}"
            );
        }
    }
}
