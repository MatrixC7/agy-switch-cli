use crate::cli::dto::{
    format_pct, format_runtime_state_human, format_session_identity_human, terminal_text,
    AccountViewDto,
};
use crate::domain::policy::SwitchPolicy;
use crate::domain::quota::{observed_quota_percentage, quota_pool, QuotaPool};
use crate::error::{CliError, CliResult};
use crate::oauth::refresh::OAuthEndpoints;
use crate::oauth::registry::OAuthClientRegistry;
use crate::quota::client::{refresh_account_quota_locked, CloudCodeEndpoints};
use crate::session::backend::CredentialBackend;
use crate::session::journal::reconcile_pending_journal_before_write;
use crate::session::payload::resolve_session_identity;
use crate::session::process::observe_runtime_state;
use crate::store::repository::StoreRepository;
use crate::switching::daemon::clear_daemon_pause_in_tx;
use crate::switching::executor::{execute_switch, SwitchOptions};
use crate::transport::client::ReqwestTransport;
use crate::transport::proxy::ProxyMode;
use crate::transport::user_agent::resolve_native_oauth_user_agent;
use comfy_table::{
    presets::UTF8_FULL_CONDENSED, Cell, CellAlignment, ColumnConstraint, ContentArrangement, Table,
    Width,
};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, Clear, ClearType},
};
use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
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

pub const TUI_KEYS_HELP_LINE: &str =
    "Keys: ↑/↓/k/j select | K/J(Shift+↑/↓) reorder | Enter/s switch | r/R refresh | c/C cand | p policy | e/d en/dis | q/Esc quit";
const TUI_BATCH_REFRESH_CONCURRENCY: usize = 2;
const TRANSIENT_INFO_TTL: Duration = Duration::from_secs(3);
const TRANSIENT_ERROR_TTL: Duration = Duration::from_secs(5);

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

/// Optional interactive SSH dashboard (`#[cfg(feature = "tui")]`).
/// Strictly delegates ALL mutations to the application service layer (`execute_switch`,
/// `refresh_account_quota_locked`, `repo.with_write_lock`) and integrates OS signal streams
/// (`SIGTERM`, `SIGINT`, `SIGHUP`, `SIGQUIT`) so terminal `ECHO` and alternate screen are
/// reliably restored even on external signal termination!
pub async fn run_interactive_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    cli_proxy: Option<&str>,
) -> CliResult<()> {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

    let _guard = RawModeGuard::enter()?;
    let mut cursor_idx: usize = 0;
    let mut scroll_offset: usize = 0;
    let mut transient_status = TransientStatus::default();
    let mut last_redraw = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut force_redraw = true;

    loop {
        if transient_status.expire_if_due(Instant::now()) {
            force_redraw = true;
        }

        if force_redraw || last_redraw.elapsed() >= Duration::from_millis(250) {
            let snap = repo.read_snapshot()?;
            let policy = repo.read_policy()?;
            let slot_state = backend.inspect_slot(repo.paths());
            let session_id = resolve_session_identity(&slot_state, &snap);
            let runtime_st = observe_runtime_state(repo.paths());

            if !snap.accounts.is_empty() && cursor_idx >= snap.accounts.len() {
                cursor_idx = snap.accounts.len() - 1;
            }

            render_dashboard(
                &snap.accounts,
                snap.index.selected_account_id.as_deref(),
                &policy,
                &session_id,
                &runtime_st,
                cursor_idx,
                &mut scroll_offset,
                transient_status.active_text(),
            )?;
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
                force_redraw = true;
                continue;
            }
            Event::Key(k) if k.kind == KeyEventKind::Press => k,
            _ => continue,
        };

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'C' | 'd' | 'D'))
        {
            break;
        }

        let snap = repo.read_snapshot()?;
        let cur_policy = repo.read_policy()?;
        let slot_state = backend.inspect_slot(repo.paths());
        let session_id = resolve_session_identity(&slot_state, &snap);
        let runtime_st = observe_runtime_state(repo.paths());
        force_redraw = true;

        let has_shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
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
            KeyCode::Char('K') => {
                reorder_selected_in_tui(
                    repo,
                    backend,
                    &snap.accounts,
                    &mut cursor_idx,
                    true,
                    &mut transient_status,
                );
            }
            KeyCode::Char('J') => {
                reorder_selected_in_tui(
                    repo,
                    backend,
                    &snap.accounts,
                    &mut cursor_idx,
                    false,
                    &mut transient_status,
                );
            }
            KeyCode::Up if has_shift => {
                reorder_selected_in_tui(
                    repo,
                    backend,
                    &snap.accounts,
                    &mut cursor_idx,
                    true,
                    &mut transient_status,
                );
            }
            KeyCode::Down if has_shift => {
                reorder_selected_in_tui(
                    repo,
                    backend,
                    &snap.accounts,
                    &mut cursor_idx,
                    false,
                    &mut transient_status,
                );
            }
            KeyCode::Up | KeyCode::Char('k') => {
                cursor_idx = cursor_idx.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !snap.accounts.is_empty() && cursor_idx + 1 < snap.accounts.len() {
                    cursor_idx += 1;
                }
            }
            KeyCode::Enter | KeyCode::Char('s') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    let switching_msg = format!("Switching to {}...", terminal_text(&target.email));
                    let _ = render_dashboard(
                        &snap.accounts,
                        snap.index.selected_account_id.as_deref(),
                        &cur_policy,
                        &session_id,
                        &runtime_st,
                        cursor_idx,
                        &mut scroll_offset,
                        Some(&switching_msg),
                    );
                    let now_unix = chrono::Utc::now().timestamp();
                    let res = async {
                        let cfg = repo.read_config()?;
                        let registry = OAuthClientRegistry::load(repo.paths())?;
                        let transport = ReqwestTransport::build(ProxyMode::resolve_with_config(
                            cli_proxy,
                            Some(&cfg.network),
                        )?)?;
                        let ua = resolve_native_oauth_user_agent(
                            repo.paths(),
                            &transport,
                            false,
                            now_unix,
                        )
                        .await;
                        execute_switch(
                            repo,
                            backend,
                            &transport,
                            &OAuthEndpoints::default(),
                            &registry,
                            &ua,
                            &target.id,
                            &SwitchOptions {
                                dry_run: false,
                                allow_running: false,
                            },
                            chrono::Utc::now().timestamp(),
                        )
                        .await
                    }
                    .await;
                    let done_at = Instant::now();
                    match res {
                        Ok(out) => transient_status.set_info(
                            format!(
                                "Switched active slot to {} ({}).",
                                terminal_text(&out.target_account_id),
                                terminal_text(&out.target_email)
                            ),
                            done_at,
                        ),
                        Err(e) => transient_status.set_error(
                            format!("Switch error: {}", terminal_text(&e.message)),
                            done_at,
                        ),
                    }
                }
            }
            KeyCode::Char('r') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    let refreshing_msg =
                        format!("Refreshing quota for {}...", terminal_text(&target.email));
                    let _ = render_dashboard(
                        &snap.accounts,
                        snap.index.selected_account_id.as_deref(),
                        &cur_policy,
                        &session_id,
                        &runtime_st,
                        cursor_idx,
                        &mut scroll_offset,
                        Some(&refreshing_msg),
                    );
                    let now_unix = chrono::Utc::now().timestamp();
                    let mut refresh_fut = std::pin::pin!(async {
                        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
                        let cfg = repo.read_config()?;
                        let registry = OAuthClientRegistry::load(repo.paths())?;
                        let transport = ReqwestTransport::build(ProxyMode::resolve_with_config(
                            cli_proxy,
                            Some(&cfg.network),
                        )?)?;
                        let ua = resolve_native_oauth_user_agent(
                            repo.paths(),
                            &transport,
                            false,
                            now_unix,
                        )
                        .await;
                        refresh_account_quota_locked(
                            repo,
                            &transport,
                            &OAuthEndpoints::default(),
                            &CloudCodeEndpoints::default(),
                            &registry,
                            &ua,
                            &target.id,
                            chrono::Utc::now().timestamp(),
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
                                    let _ = render_dashboard(
                                        &snap.accounts,
                                        snap.index.selected_account_id.as_deref(),
                                        &cur_policy,
                                        &session_id,
                                        &runtime_st,
                                        cursor_idx,
                                        &mut scroll_offset,
                                        Some(&refreshing_msg),
                                    );
                                }
                            }
                            res = &mut refresh_fut => break Some(res),
                        }
                    };
                    if interrupted_r {
                        break;
                    }
                    if let Some(res) = refresh_res {
                        let done_at = Instant::now();
                        match res {
                            Ok(acc) => transient_status.set_info(
                                format!("Refreshed quota for {}.", terminal_text(&acc.email)),
                                done_at,
                            ),
                            Err(e) => transient_status.set_error(
                                format!("Refresh error: {}", terminal_text(&e.message)),
                                done_at,
                            ),
                        }
                    }
                }
            }
            KeyCode::Char('R') => {
                let targets: Vec<(String, String)> = snap
                    .accounts
                    .iter()
                    .filter(|a| !a.disabled)
                    .map(|a| (a.id.clone(), a.email.clone()))
                    .collect();
                if targets.is_empty() {
                    transient_status
                        .set_info("No enabled accounts to refresh.".into(), Instant::now());
                } else {
                    let total = targets.len();
                    let init_msg = format!("Refreshing {total} enabled account(s) (0/{total})...");
                    let _ = render_dashboard(
                        &snap.accounts,
                        snap.index.selected_account_id.as_deref(),
                        &cur_policy,
                        &session_id,
                        &runtime_st,
                        cursor_idx,
                        &mut scroll_offset,
                        Some(&init_msg),
                    );
                    let interrupted = run_batch_refresh_in_tui(
                        repo,
                        backend,
                        cli_proxy,
                        &targets,
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
            }
            KeyCode::Char('c') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    toggle_policy_candidate_in_tui(repo, backend, target, &mut transient_status);
                }
            }
            KeyCode::Char('C') => {
                toggle_all_enabled_candidates_in_tui(
                    repo,
                    backend,
                    &snap.accounts,
                    &mut transient_status,
                );
            }
            KeyCode::Char('p') => {
                toggle_policy_enabled_in_tui(repo, backend, &mut transient_status);
            }
            KeyCode::Char('e') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    let now_unix = chrono::Utc::now().timestamp();
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
            KeyCode::Char('d') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    let now_unix = chrono::Utc::now().timestamp();
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
            _ => {
                force_redraw = false;
            }
        }
    }

    Ok(())
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

    let now_unix = chrono::Utc::now().timestamp();
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PoolWindowPair {
    weekly: Option<i32>,
    short_5h: Option<i32>,
    has_bucket: bool,
}

impl PoolWindowPair {
    fn format_dual_aligned(&self) -> String {
        if self.short_5h.is_none() && self.weekly.is_none() {
            "—".into()
        } else {
            format!(
                "{} / {}",
                format_pct_padded(self.short_5h),
                format_pct_padded(self.weekly)
            )
        }
    }

    fn format_dual_compact(&self) -> String {
        if self.short_5h.is_none() && self.weekly.is_none() {
            "—".into()
        } else {
            format!(
                "{} / {}",
                format_pct(self.short_5h),
                format_pct(self.weekly)
            )
        }
    }

    fn format_weekly_aligned(&self) -> String {
        format_pct_padded(self.weekly)
    }

    fn format_weekly_compact(&self) -> String {
        format_pct(self.weekly)
    }
}

struct AbortTasksOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortTasksOnDrop {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// Poll non-blocking raw-mode terminal events while an async refresh (`r` / `R`) is in flight.
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
                    || matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
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

fn render_live_batch_progress(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    completed: usize,
    total: usize,
) {
    if let (Ok(live_snap), Ok(live_pol)) = (repo.read_snapshot(), repo.read_policy()) {
        let slot_st = backend.inspect_slot(repo.paths());
        let sess_id = resolve_session_identity(&slot_st, &live_snap);
        let run_st = observe_runtime_state(repo.paths());
        let cur_bounded = if live_snap.accounts.is_empty() {
            0
        } else {
            cursor_idx.min(live_snap.accounts.len() - 1)
        };
        let prog_msg = format!("Refreshing {total} enabled account(s) ({completed}/{total})...");
        let _ = render_dashboard(
            &live_snap.accounts,
            live_snap.index.selected_account_id.as_deref(),
            &live_pol,
            &sess_id,
            &run_st,
            cur_bounded,
            scroll_offset,
            Some(&prog_msg),
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_batch_refresh_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    cli_proxy: Option<&str>,
    targets: &[(String, String)],
    cursor_idx: usize,
    scroll_offset: &mut usize,
    transient_status: &mut TransientStatus,
    sigterm: &mut Option<tokio::signal::unix::Signal>,
    sigint: &mut Option<tokio::signal::unix::Signal>,
    sighup: &mut Option<tokio::signal::unix::Signal>,
) -> bool {
    let now_unix = chrono::Utc::now().timestamp();
    let mut prep = std::pin::pin!(async {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let cfg = repo.read_config()?;
        let registry = OAuthClientRegistry::load(repo.paths())?;
        let transport = ReqwestTransport::build(ProxyMode::resolve_with_config(
            cli_proxy,
            Some(&cfg.network),
        )?)?;
        let ua = resolve_native_oauth_user_agent(repo.paths(), &transport, false, now_unix).await;
        Ok::<_, CliError>((Arc::new(transport), Arc::new(registry), ua))
    });

    let (transport, registry, ua) = loop {
        tokio::select! {
            _ = async {
                if let Some(ref mut s) = sigterm { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => return true,
            _ = async {
                if let Some(ref mut s) = sigint { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => return true,
            _ = async {
                if let Some(ref mut s) = sighup { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => return true,
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let (should_exit, saw_resize) = poll_raw_tty_interrupt_or_resize();
                if should_exit {
                    return true;
                }
                if saw_resize {
                    render_live_batch_progress(
                        repo,
                        backend,
                        cursor_idx,
                        scroll_offset,
                        0,
                        targets.len(),
                    );
                }
            }
            res = &mut prep => break match res {
                Ok(v) => v,
                Err(e) => {
                    transient_status.set_error(
                        format!("Refresh error: {}", terminal_text(&e.message)),
                        Instant::now(),
                    );
                    return false;
                }
            },
        }
    };

    let total = targets.len();
    let oauth_ep = Arc::new(OAuthEndpoints::default());
    let quota_ep = Arc::new(CloudCodeEndpoints::default());
    let sem = Arc::new(Semaphore::new(TUI_BATCH_REFRESH_CONCURRENCY));
    let (tx, mut rx) =
        mpsc::unbounded_channel::<(String, CliResult<crate::domain::account::AccountRecord>)>();

    let mut handles = Vec::with_capacity(total);
    for (id, email) in targets {
        let repo_c = repo.clone();
        let tr_c = transport.clone();
        let reg_c = registry.clone();
        let oe_c = oauth_ep.clone();
        let qe_c = quota_ep.clone();
        let ua_c = ua.clone();
        let sem_c = sem.clone();
        let tx_c = tx.clone();
        let id_c = id.clone();
        let email_c = email.clone();
        handles.push(tokio::spawn(async move {
            let Ok(_permit) = sem_c.acquire_owned().await else {
                return;
            };
            let res = refresh_account_quota_locked(
                &repo_c,
                tr_c.as_ref(),
                &oe_c,
                &qe_c,
                &reg_c,
                &ua_c,
                &id_c,
                chrono::Utc::now().timestamp(),
            )
            .await;
            let _ = tx_c.send((email_c, res));
        }));
    }
    drop(tx);
    let _abort_guard = AbortTasksOnDrop(handles);

    let mut completed = 0usize;
    let mut ok_count = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();

    while completed < total {
        let next_item = tokio::select! {
            _ = async {
                if let Some(ref mut s) = sigterm { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => return true,
            _ = async {
                if let Some(ref mut s) = sigint { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => return true,
            _ = async {
                if let Some(ref mut s) = sighup { let _ = s.recv().await; }
                else { std::future::pending::<()>().await; }
            } => return true,
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let (should_exit, saw_resize) = poll_raw_tty_interrupt_or_resize();
                if should_exit {
                    return true;
                }
                if saw_resize {
                    render_live_batch_progress(
                        repo,
                        backend,
                        cursor_idx,
                        scroll_offset,
                        completed,
                        total,
                    );
                }
                continue;
            }
            item = rx.recv() => item,
        };
        let Some((email, res)) = next_item else {
            break;
        };
        completed += 1;
        match res {
            Ok(_) => ok_count += 1,
            Err(e) => failures.push((email, e.message)),
        }
        if completed < total {
            render_live_batch_progress(repo, backend, cursor_idx, scroll_offset, completed, total);
        }
    }

    let done_at = Instant::now();
    if failures.is_empty() {
        transient_status.set_info(
            format!("Refreshed {ok_count}/{total} enabled account(s)."),
            done_at,
        );
    } else {
        let (first_email, first_err) = &failures[0];
        transient_status.set_error(
            format!(
                "Refreshed {ok_count}/{total} ({} failed; {}: {}).",
                failures.len(),
                terminal_text(first_email),
                terminal_text(first_err)
            ),
            done_at,
        );
    }
    false
}

fn toggle_all_enabled_candidates_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    accounts: &[crate::domain::account::AccountRecord],
    transient_status: &mut TransientStatus,
) {
    let now_unix = chrono::Utc::now().timestamp();
    let res: CliResult<String> = (|| {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let mut policy = repo.read_policy()?;
        let prev_rev = policy.revision;
        let enabled_ids: Vec<String> = accounts
            .iter()
            .filter(|a| !a.disabled)
            .map(|a| a.id.clone())
            .collect();
        if enabled_ids.is_empty() {
            if policy.candidate_account_ids.is_empty() {
                return Err(CliError::usage(
                    "No enabled accounts available to add as policy candidates.",
                ));
            }
            policy.candidate_account_ids.clear();
            let was_enabled = policy.enabled;
            policy.enabled = false;
            repo.with_write_lock(|tx| {
                tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
                clear_daemon_pause_in_tx(tx.paths(), now_unix);
                Ok(())
            })?;
            return Ok(if was_enabled {
                "Cleared all policy candidates (auto-switch turned off).".into()
            } else {
                "Cleared all policy candidates.".into()
            });
        }

        let existing_set: HashSet<&str> = policy
            .candidate_account_ids
            .iter()
            .map(String::as_str)
            .collect();
        let all_enabled_present = enabled_ids
            .iter()
            .all(|id| existing_set.contains(id.as_str()));

        let msg = if all_enabled_present {
            policy.candidate_account_ids.clear();
            let was_enabled = policy.enabled;
            policy.enabled = false;
            if was_enabled {
                "Cleared all policy candidates (auto-switch turned off).".into()
            } else {
                "Cleared all policy candidates.".into()
            }
        } else {
            let count = enabled_ids.len();
            policy.candidate_account_ids = enabled_ids;
            format!("Added all {count} enabled account(s) to policy candidates.")
        };

        repo.with_write_lock(|tx| {
            tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
            clear_daemon_pause_in_tx(tx.paths(), now_unix);
            Ok(())
        })?;
        Ok(msg)
    })();

    let done_at = Instant::now();
    match res {
        Ok(msg) => transient_status.set_info(msg, done_at),
        Err(e) => transient_status.set_error(
            format!("Policy error: {}", terminal_text(&e.message)),
            done_at,
        ),
    }
}

fn toggle_policy_candidate_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    target: &crate::domain::account::AccountRecord,
    transient_status: &mut TransientStatus,
) {
    let now_unix = chrono::Utc::now().timestamp();
    let res: CliResult<String> = (|| {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let mut policy = repo.read_policy()?;
        let prev_rev = policy.revision;
        let msg = if let Some(pos) = policy
            .candidate_account_ids
            .iter()
            .position(|id| id == &target.id)
        {
            policy.candidate_account_ids.remove(pos);
            if policy.candidate_account_ids.is_empty() && policy.enabled {
                policy.enabled = false;
                format!(
                    "Removed {} from candidates (auto-switch turned off: 0 candidates).",
                    terminal_text(&target.email)
                )
            } else {
                format!(
                    "Removed {} from policy candidates.",
                    terminal_text(&target.email)
                )
            }
        } else {
            policy.candidate_account_ids.push(target.id.clone());
            let rank = policy.candidate_account_ids.len();
            format!(
                "Added {} as policy candidate #{rank}.",
                terminal_text(&target.email)
            )
        };
        repo.with_write_lock(|tx| {
            tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
            clear_daemon_pause_in_tx(tx.paths(), now_unix);
            Ok(())
        })?;
        Ok(msg)
    })();

    let done_at = Instant::now();
    match res {
        Ok(msg) => transient_status.set_info(msg, done_at),
        Err(e) => transient_status.set_error(
            format!("Policy error: {}", terminal_text(&e.message)),
            done_at,
        ),
    }
}

fn toggle_policy_enabled_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transient_status: &mut TransientStatus,
) {
    let now_unix = chrono::Utc::now().timestamp();
    let res: CliResult<String> = (|| {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let mut policy = repo.read_policy()?;
        let prev_rev = policy.revision;
        if !policy.enabled && policy.candidate_account_ids.is_empty() {
            return Err(CliError::usage(
                "Press 'c' or 'C' to add policy candidates before enabling auto-switch.",
            ));
        }
        policy.enabled = !policy.enabled;
        let new_state = policy.enabled;
        repo.with_write_lock(|tx| {
            tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
            clear_daemon_pause_in_tx(tx.paths(), now_unix);
            Ok(())
        })?;
        Ok(if new_state {
            format!(
                "Auto-switch policy ENABLED ({} candidate(s)).",
                policy.candidate_account_ids.len()
            )
        } else {
            "Auto-switch policy DISABLED.".into()
        })
    })();

    let done_at = Instant::now();
    match res {
        Ok(msg) => transient_status.set_info(msg, done_at),
        Err(e) => transient_status.set_error(terminal_text(&e.message), done_at),
    }
}

#[derive(Debug, Clone)]
struct AccountPoolSummary {
    plan: String,
    gemini: PoolWindowPair,
    third_party: PoolWindowPair,
    argon: PoolWindowPair,
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

#[allow(clippy::too_many_arguments)]
fn render_dashboard(
    accounts: &[crate::domain::account::AccountRecord],
    selected_id: Option<&str>,
    policy: &SwitchPolicy,
    session_id: &crate::domain::account::SessionIdentity,
    runtime_st: &crate::domain::account::RuntimeState,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    transient_notice: Option<&str>,
) -> CliResult<()> {
    let (term_cols, term_rows) = current_terminal_size();
    let rendered = build_dashboard_frame(
        accounts,
        selected_id,
        policy,
        session_id,
        runtime_st,
        cursor_idx,
        scroll_offset,
        transient_notice,
        term_cols,
        term_rows,
    );

    let mut out = io::stdout();
    execute!(out, cursor::MoveTo(0, 0), Clear(ClearType::All))
        .map_err(|e| CliError::io("tui_draw_error", format!("TUI draw error: {e}")))?;
    out.write_all(rendered.as_bytes())
        .and_then(|_| out.flush())
        .map_err(|e| CliError::io("tui_write_error", format!("TUI write error: {e}")))
}

#[allow(clippy::too_many_arguments)]
fn build_dashboard_frame(
    accounts: &[crate::domain::account::AccountRecord],
    selected_id: Option<&str>,
    policy: &SwitchPolicy,
    session_id: &crate::domain::account::SessionIdentity,
    runtime_st: &crate::domain::account::RuntimeState,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    transient_notice: Option<&str>,
    term_cols: u16,
    term_rows: u16,
) -> String {
    let cols = term_cols as usize;
    let rows = term_rows as usize;
    let cur = if accounts.is_empty() {
        0
    } else {
        cursor_idx.min(accounts.len() - 1)
    };
    if cols == 0 || rows == 0 {
        *scroll_offset = cur;
        return String::new();
    }

    let summaries: Vec<AccountPoolSummary> = accounts.iter().map(summarize_pools).collect();
    let show_argon = summaries.iter().any(|s| s.argon.has_bucket);
    let show_id_col = cols >= 152;
    let compact_cols = cols < 116;

    let policy_header = if policy.enabled {
        format!(
            "ON (reserve {}% / min {}%, {:?}, {:?}, model={})",
            policy.reserve_percentage,
            policy.candidate_min_percentage,
            policy.mode,
            policy.strategy,
            terminal_text(&policy.monitored_model)
        )
    } else {
        format!("off ({} candidates)", policy.candidate_account_ids.len())
    };
    let session_line = truncate_to_cols(
        &format!(
            "Session: {} | Runtime: {} | Policy: {}",
            format_session_identity_human(session_id),
            format_runtime_state_human(runtime_st),
            policy_header
        ),
        cols,
    );
    let keys_line = keys_help_for_width(cols);
    let status_line = match transient_notice {
        Some(msg) if !msg.is_empty() => {
            truncate_to_cols(&format!("Status: {}", terminal_text(msg)), cols)
        }
        _ => String::new(),
    };

    let format_compact_row = |idx: usize| -> String {
        let acc = &accounts[idx];
        let sum = &summaries[idx];
        let is_sel = selected_id == Some(acc.id.as_str());
        if cols == 1 {
            return if idx == cur {
                ">".into()
            } else if is_sel {
                "*".into()
            } else {
                " ".into()
            };
        }
        let marker = match (idx == cur, is_sel) {
            (true, true) => ">*",
            (true, false) => "> ",
            (false, true) => " *",
            (false, false) => "  ",
        };
        if cols <= 3 {
            return truncate_to_cols(marker.trim_end(), cols);
        }
        let dto = AccountViewDto::from_record(acc, is_sel);
        let state_tag = if dto.disabled {
            " [disabled]"
        } else if dto.validation_blocked {
            " [verify-blocked]"
        } else {
            ""
        };
        let argon_tag = if show_argon {
            format!(" | Arg {}", sum.argon.format_weekly_compact())
        } else {
            String::new()
        };
        let cand_tag = policy
            .candidate_account_ids
            .iter()
            .position(|cid| cid == &acc.id)
            .map(|p| {
                if dto.disabled {
                    format!(" | cand #{} (skip)", p + 1)
                } else {
                    format!(" | cand #{}", p + 1)
                }
            })
            .unwrap_or_default();
        truncate_to_cols(
            &format!(
                "{marker} #{} {}{} | Gem {} | 3P {}{}{}",
                idx + 1,
                terminal_text(&acc.email),
                state_tag,
                sum.gemini.format_dual_compact(),
                sum.third_party.format_dual_compact(),
                argon_tag,
                cand_tag
            ),
            cols,
        )
    };

    // Ultra-short physical terminals (1..=4 rows): stay strictly within `rows` without elevating budget.
    if rows < 5 {
        *scroll_offset = cur;
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
                    tiny.push(session_line);
                    tiny.push(footer_or_status);
                }
                _ => {
                    tiny.push(truncate_to_cols(
                        "agy-switch-cli Headless SSH Dashboard  [0 accounts]",
                        cols,
                    ));
                    tiny.push(session_line);
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
                    "agy-switch-cli Headless SSH Dashboard  [{}/{}]",
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

    let render_slice = |start: usize, end: usize| -> String {
        let mut headers = vec![
            Cell::new("#").set_alignment(CellAlignment::Right),
            Cell::new("Sel"),
        ];
        if show_id_col {
            headers.push(Cell::new("ID"));
        }
        headers.push(Cell::new("Email"));
        headers.push(Cell::new("Plan"));
        if compact_cols {
            headers.push(Cell::new("Gemini 5h/W").set_alignment(CellAlignment::Center));
            headers.push(Cell::new("Claude/GPT 5h/W").set_alignment(CellAlignment::Center));
            if show_argon {
                headers.push(Cell::new("Argon W").set_alignment(CellAlignment::Center));
            }
        } else {
            headers.push(Cell::new("Gemini (5h / W)").set_alignment(CellAlignment::Center));
            headers.push(Cell::new("Claude/GPT (5h / W)").set_alignment(CellAlignment::Center));
            if show_argon {
                headers.push(Cell::new("Argon (W)").set_alignment(CellAlignment::Center));
            }
        }
        headers.push(Cell::new("Policy"));
        headers.push(Cell::new("State"));

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_width(cols as u16)
            .set_header(headers);
        if cols >= if show_argon { 104 } else { 92 } {
            let gemini_col_idx = if show_id_col { 5 } else { 4 };
            let (gemini_min_w, claude_min_w) = if compact_cols {
                if cols >= if show_argon { 120 } else { 108 } {
                    (13, 17)
                } else {
                    (13, 13)
                }
            } else {
                (17, 21)
            };
            if let Some(col) = table.column_mut(gemini_col_idx) {
                col.set_constraint(ColumnConstraint::LowerBoundary(Width::Fixed(gemini_min_w)));
            }
            if let Some(col) = table.column_mut(gemini_col_idx + 1) {
                col.set_constraint(ColumnConstraint::LowerBoundary(Width::Fixed(claude_min_w)));
            }
        }

        for idx in start..end {
            let acc = &accounts[idx];
            let sum = &summaries[idx];
            let dto = AccountViewDto::from_record(acc, selected_id == Some(acc.id.as_str()));
            let row_no = format!("{}", idx + 1);
            let pointer = match (idx == cur, dto.is_selected) {
                (true, true) => ">*",
                (true, false) => "> ",
                (false, true) => " *",
                (false, false) => "  ",
            };
            let plan_str = short_plan_label(&sum.plan);
            let policy_str = policy
                .candidate_account_ids
                .iter()
                .position(|cid| cid == &acc.id)
                .map(|p| {
                    if dto.disabled {
                        format!("cand #{} (skip)", p + 1)
                    } else {
                        format!("cand #{}", p + 1)
                    }
                })
                .unwrap_or_else(|| "—".into());
            let state_str = if dto.disabled {
                "disabled"
            } else if dto.validation_blocked {
                "verify-blocked"
            } else {
                "ok"
            };
            let mut cells = vec![
                Cell::new(row_no).set_alignment(CellAlignment::Right),
                Cell::new(pointer),
            ];
            if show_id_col {
                cells.push(Cell::new(terminal_text(&dto.id)));
            }
            cells.push(Cell::new(terminal_text(&dto.email)));
            cells.push(Cell::new(plan_str));
            cells.push(
                Cell::new(sum.gemini.format_dual_aligned()).set_alignment(CellAlignment::Center),
            );
            cells.push(
                Cell::new(sum.third_party.format_dual_aligned())
                    .set_alignment(CellAlignment::Center),
            );
            if show_argon {
                cells.push(
                    Cell::new(sum.argon.format_weekly_aligned())
                        .set_alignment(CellAlignment::Center),
                );
            }
            cells.push(Cell::new(policy_str));
            cells.push(Cell::new(state_str));
            table.add_row(cells);
        }
        table.to_string()
    };

    // 2 header lines + 2 footer lines = 4 fixed lines; remaining rows belong to the viewport (`>= 1`).
    let max_table_lines = rows.saturating_sub(4);
    // Minimum horizontal width to render an 8-column (or 9-column with Argon) bordered table cleanly
    // without shredding `Email` / headers into 2-3 character vertical strips.
    let min_table_cols = if show_argon { 78 } else { 68 };
    let mut frame_lines: Vec<String> = Vec::with_capacity(rows);

    if accounts.is_empty() {
        *scroll_offset = 0;
        frame_lines.push(truncate_to_cols(
            "agy-switch-cli Headless SSH Dashboard  [0 accounts]",
            cols,
        ));
        frame_lines.push(session_line);
        if cols >= min_table_cols {
            let empty_tbl = render_slice(0, 0);
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
        frame_lines.push(keys_line);
        if !status_line.is_empty() {
            frame_lines.push(status_line);
        }
    } else {
        // Attempt bordered table layout only when physical width/height can hold BOTH the header AND
        // at least the focused account row cleanly without clipping, shredding, or overflowing `cols`.
        let mut table_choice: Option<(usize, usize, String)> = None;
        if cols >= min_table_cols && max_table_lines >= 5 {
            let max_rows_upper = max_table_lines.saturating_sub(4).max(1);
            let mut probe_offset = *scroll_offset;
            if probe_offset > cur {
                probe_offset = cur;
            }
            if cur >= probe_offset + max_rows_upper {
                probe_offset = cur + 1 - max_rows_upper;
            }

            let mut start = probe_offset;
            let mut end = (start + max_rows_upper).min(accounts.len()).max(cur + 1);
            let mut tbl_str = render_slice(start, end);

            // Shrink viewport if any wrapped cell caused actual line count to exceed `max_table_lines`,
            // always keeping `cur` inside `start..end`.
            while tbl_str.lines().count() > max_table_lines && end.saturating_sub(start) > 1 {
                if end - 1 > cur {
                    end -= 1;
                } else {
                    start += 1;
                }
                tbl_str = render_slice(start, end);
            }

            // Expand downward if there is still vertical room below `end`.
            while end < accounts.len() {
                let next_tbl = render_slice(start, end + 1);
                if next_tbl.lines().count() <= max_table_lines {
                    end += 1;
                    tbl_str = next_tbl;
                } else {
                    break;
                }
            }

            // Pull `start` upward if terminal grew taller and has spare room at the bottom.
            while start > 0 {
                let prev_tbl = render_slice(start - 1, end);
                if prev_tbl.lines().count() <= max_table_lines {
                    start -= 1;
                    tbl_str = prev_tbl;
                } else {
                    break;
                }
            }

            if tbl_str.lines().count() <= max_table_lines
                && tbl_str.lines().all(|l| display_width(l) <= cols)
            {
                table_choice = Some((start, end, tbl_str));
            }
        }

        if let Some((start, end, tbl_str)) = table_choice {
            *scroll_offset = start;
            let title = if start == 0 && end == accounts.len() {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [{} account(s)]",
                    accounts.len()
                )
            } else {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [Showing {}-{} of {} — ↑/↓ scroll]",
                    start + 1,
                    end,
                    accounts.len()
                )
            };

            frame_lines.push(truncate_to_cols(&title, cols));
            frame_lines.push(session_line);
            for line in tbl_str.lines() {
                frame_lines.push(truncate_to_cols(line, cols));
            }
            frame_lines.push(keys_line);
            if !status_line.is_empty() {
                frame_lines.push(status_line);
            }
        } else {
            // Compact focus list viewport: 1 physical row per account, guaranteed to keep `cur` visible
            // even on narrow/short split panes (e.g. 40x9, 52x9, < 9 rows, or < 40 cols).
            if *scroll_offset > cur {
                *scroll_offset = cur;
            }
            if cur >= *scroll_offset + max_table_lines {
                *scroll_offset = cur + 1 - max_table_lines;
            }
            let mut start = *scroll_offset;
            let end = (start + max_table_lines).min(accounts.len()).max(cur + 1);
            if end.saturating_sub(start) < max_table_lines && start > 0 {
                start = end.saturating_sub(max_table_lines);
            }
            *scroll_offset = start;

            let title = if start == 0 && end == accounts.len() {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [{} account(s)]",
                    accounts.len()
                )
            } else {
                format!(
                    "agy-switch-cli Headless SSH Dashboard  [Showing {}-{} of {} — ↑/↓ scroll]",
                    start + 1,
                    end,
                    accounts.len()
                )
            };

            frame_lines.push(truncate_to_cols(&title, cols));
            frame_lines.push(session_line);
            for idx in start..end {
                frame_lines.push(format_compact_row(idx));
            }
            frame_lines.push(keys_line);
            if !status_line.is_empty() {
                frame_lines.push(status_line);
            }
        }
    }

    frame_lines.truncate(rows);
    // Join WITHOUT trailing `\r\n` on the final line so the terminal never scrolls row 0 off-screen!
    frame_lines.join("\r\n")
}

fn short_plan_label(plan: &str) -> String {
    let trimmed = plan.trim();
    if trimmed.is_empty() || trimmed == "—" {
        return "—".into();
    }
    let (core, restricted_suffix) = match trimmed.strip_suffix(" (Restricted)") {
        Some(base) => (base.trim(), " (Restricted)"),
        None => (trimmed, ""),
    };
    if core.eq_ignore_ascii_case("unknown") {
        return format!("Unknown{restricted_suffix}");
    }
    let stripped = strip_ascii_prefix_ci(core, "google one ai ")
        .or_else(|| strip_ascii_prefix_ci(core, "google ai "))
        .or_else(|| strip_ascii_prefix_ci(core, "google "))
        .or_else(|| strip_ascii_prefix_ci(core, "ai "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(core);
    let normalized = match stripped.to_ascii_lowercase().as_str() {
        "free" | "free tier" | "free-tier" | "free_tier" | "g1-free-tier" | "g1_free_tier"
        | "google-ai-free" | "google_ai_free" => "Free",
        "pro" | "pro tier" | "pro-tier" | "pro_tier" | "g1-pro-tier" | "g1_pro_tier"
        | "google-ai-pro" | "google_ai_pro" => "Pro",
        "ultra" | "ultra tier" | "ultra-tier" | "ultra_tier" | "g1-ultra-tier"
        | "g1_ultra_tier" | "google-ai-ultra" | "google_ai_ultra" => "Ultra",
        _ => stripped,
    };
    format!("{normalized}{restricted_suffix}")
}

fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix_lower: &str) -> Option<&'a str> {
    if s.len() >= prefix_lower.len()
        && s.is_char_boundary(prefix_lower.len())
        && s[..prefix_lower.len()].eq_ignore_ascii_case(prefix_lower)
    {
        Some(&s[prefix_lower.len()..])
    } else {
        None
    }
}

fn keys_help_for_width(cols: usize) -> String {
    let candidate = if cols >= display_width(TUI_KEYS_HELP_LINE) {
        TUI_KEYS_HELP_LINE
    } else if cols >= 102 {
        "Keys: ↑/↓/k/j select | K/J reorder | Enter/s switch | r/R refresh | c/C cand | p policy | e/d | q quit"
    } else {
        "Keys: ↑/↓/k/j | K/J order | s switch | r/R ref | c/C cand | p pol | e/d | q quit"
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

fn summarize_pools(acc: &crate::domain::account::AccountRecord) -> AccountPoolSummary {
    let Some(ref q) = acc.quota else {
        return AccountPoolSummary {
            plan: "—".into(),
            gemini: PoolWindowPair::default(),
            third_party: PoolWindowPair::default(),
            argon: PoolWindowPair::default(),
        };
    };
    let plan = short_plan_label(
        &q.subscription_tier
            .as_deref()
            .map(terminal_text)
            .unwrap_or_else(|| "Unknown".into()),
    );

    let extract_pair = |target_pool: QuotaPool| -> PoolWindowPair {
        let Some(ref groups) = q.quota_groups else {
            return PoolWindowPair::default();
        };
        let mut pair = PoolWindowPair::default();
        for g in groups {
            for b in &g.buckets {
                if quota_pool(&b.bucket_id, &g.display_name) != Some(target_pool) {
                    continue;
                }
                pair.has_bucket = true;
                if let Some(pct) =
                    observed_quota_percentage(b.remaining_fraction, b.remaining_fraction_known)
                {
                    let w_low = b.window.trim().to_ascii_lowercase();
                    let id_low = b.bucket_id.trim().to_ascii_lowercase();
                    if w_low == "weekly" || id_low.ends_with("-weekly") {
                        pair.weekly = Some(pair.weekly.map_or(pct, |old| old.min(pct)));
                    } else if w_low == "5h" || id_low.ends_with("-5h") {
                        pair.short_5h = Some(pair.short_5h.map_or(pct, |old| old.min(pct)));
                    }
                }
            }
        }
        pair
    };

    AccountPoolSummary {
        plan,
        gemini: extract_pair(QuotaPool::Gemini),
        third_party: extract_pair(QuotaPool::ThirdParty),
        argon: extract_pair(QuotaPool::Argon),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::account::{AccountRecord, RuntimeState, SessionIdentity};
    use crate::domain::quota::{QuotaBucket, QuotaGroup, QuotaObservation, QuotaSourceEnv};
    use crate::domain::token::TokenRecord;

    fn make_synthetic_account(idx: usize) -> AccountRecord {
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
            1_800_000_000,
        );
        let mut obs = QuotaObservation::new(1_800_000_000, QuotaSourceEnv::Daily);
        obs.subscription_tier = Some("Google AI Pro".into());
        obs.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: None,
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
                        reset_time: "2099-01-01T05:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Claude and GPT models".into(),
                description: None,
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
        assert!(TUI_KEYS_HELP_LINE.contains("↑/↓/k/j select"));
        assert!(!TUI_KEYS_HELP_LINE.contains("1-9"));
        assert!(TUI_KEYS_HELP_LINE.contains("r/R refresh | c/C cand | p policy"));
    }

    #[test]
    fn summarize_pools_orders_5h_before_weekly_aligns_slashes_and_shortens_plan_labels() {
        let acc1 = make_synthetic_account(1);
        let sum1 = summarize_pools(&acc1);
        assert_eq!(sum1.gemini.format_dual_aligned(), "100% /  72%");
        assert_eq!(sum1.third_party.format_dual_aligned(), " 95% /  37%");
        assert_eq!(sum1.gemini.format_dual_compact(), "100% / 72%");
        assert_eq!(sum1.third_party.format_dual_compact(), "95% / 37%");
        assert!(!sum1.argon.has_bucket);

        assert_eq!(short_plan_label("Google AI Pro"), "Pro");
        assert_eq!(short_plan_label("AI Pro"), "Pro");
        assert_eq!(short_plan_label("g1-pro-tier"), "Pro");
        assert_eq!(short_plan_label("Google AI Ultra"), "Ultra");
        assert_eq!(short_plan_label("AI Ultra"), "Ultra");
        assert_eq!(short_plan_label("Free Tier"), "Free");
        assert_eq!(short_plan_label("Google AI Free"), "Free");
        assert_eq!(
            short_plan_label("Free Tier (Restricted)"),
            "Free (Restricted)"
        );
        assert_eq!(short_plan_label("Google AI Plus"), "Plus");
        assert_eq!(short_plan_label("Enterprise"), "Enterprise");
        assert_eq!(short_plan_label("Unknown"), "Unknown");
        assert_eq!(short_plan_label("—"), "—");

        // Verify character-level vertical alignment of `/` and `%` across rows with 1/2/3-digit % and disabled candidate `(skip)`!
        let mut acc2 = make_synthetic_account(2);
        acc2.quota.as_mut().unwrap().subscription_tier = Some("Google AI Ultra".into());
        acc2.quota.as_mut().unwrap().quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: None,
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "gemini-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.05,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T05:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "gemini-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Claude and GPT models".into(),
                description: None,
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "3p-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 1.0,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T05:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "3p-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.03,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
        ]);
        acc2.disabled = true;

        let mut acc3 = make_synthetic_account(3);
        acc3.quota = None;

        let policy = SwitchPolicy {
            enabled: true,
            candidate_account_ids: vec![acc1.id.clone(), acc2.id.clone()],
            ..SwitchPolicy::default()
        };
        let mut off = 0usize;
        let frame = build_dashboard_frame(
            &[acc1.clone(), acc2.clone(), acc3.clone()],
            Some(&acc1.id),
            &policy,
            &SessionIdentity::Matched {
                account_id: acc1.id.clone(),
                email: acc1.email.clone(),
                expiry: "2026-11-17T02:26:00Z".into(),
            },
            &RuntimeState::Idle,
            0,
            &mut off,
            None,
            136,
            20,
        );
        assert!(frame.contains("Gemini (5h / W)"));
        assert!(frame.contains("Claude/GPT (5h / W)"));
        assert!(!frame.contains("Google AI"));
        assert!(frame.contains("cand #1"));
        assert!(frame.contains("cand #2 (skip)"));
        assert!(!frame.lines().nth(1).unwrap_or("").contains(&acc1.id));

        let row1_line = frame
            .split("\r\n")
            .find(|l| l.starts_with('│') && l.contains("synthetic.user.01@example.invalid"))
            .unwrap();
        let row2_line = frame
            .split("\r\n")
            .find(|l| l.starts_with('│') && l.contains("synthetic.user.02@example.invalid"))
            .unwrap();
        let row3_line = frame
            .split("\r\n")
            .find(|l| l.starts_with('│') && l.contains("synthetic.user.03@example.invalid"))
            .unwrap();

        let slash_cols_1: Vec<usize> = row1_line
            .char_indices()
            .filter(|&(_, c)| c == '/')
            .map(|(i, _)| UnicodeWidthStr::width(&row1_line[..i]))
            .collect();
        let slash_cols_2: Vec<usize> = row2_line
            .char_indices()
            .filter(|&(_, c)| c == '/')
            .map(|(i, _)| UnicodeWidthStr::width(&row2_line[..i]))
            .collect();
        assert_eq!(
            slash_cols_1.len(),
            2,
            "expected 2 slashes on row 1: {row1_line}"
        );
        assert_eq!(
            slash_cols_1, slash_cols_2,
            "slashes must align vertically across rows:\n{row1_line}\n{row2_line}"
        );
        let pct_cols_1: Vec<usize> = row1_line
            .char_indices()
            .filter(|&(_, c)| c == '%')
            .map(|(i, _)| UnicodeWidthStr::width(&row1_line[..i]))
            .collect();
        let pct_cols_2: Vec<usize> = row2_line
            .char_indices()
            .filter(|&(_, c)| c == '%')
            .map(|(i, _)| UnicodeWidthStr::width(&row2_line[..i]))
            .collect();
        assert_eq!(
            pct_cols_1, pct_cols_2,
            "% signs must align vertically across rows:\n{row1_line}\n{row2_line}"
        );
        // Unrefreshed `—` centers directly underneath the `/` columns!
        for &slash_col in &slash_cols_1 {
            let dash_aligned = row3_line
                .char_indices()
                .filter(|&(_, c)| c == '—')
                .any(|(i, _)| UnicodeWidthStr::width(&row3_line[..i]) == slash_col);
            assert!(
                dash_aligned,
                "unrefreshed '—' must align directly under slash col {slash_col}:\n{row1_line}\n{row3_line}"
            );
        }

        // Also verify compact-header widths (`cols = 104` and `114` < 116) keep dual-window quota cells
        // unwrapped and preserve exact vertical `/` and `%` alignment across rows!
        assert_eq!(short_plan_label("google-ai-pro"), "Pro");
        assert_eq!(short_plan_label("g1_ultra_tier"), "Ultra");
        assert_eq!(short_plan_label("free_tier"), "Free");
        let mut off_compact_hdr = 0usize;
        let frame_compact_114 = build_dashboard_frame(
            &[acc1.clone(), acc2.clone(), acc3.clone()],
            Some(&acc1.id),
            &policy,
            &SessionIdentity::Matched {
                account_id: acc1.id.clone(),
                email: acc1.email.clone(),
                expiry: "2026-11-17T02:26:00Z".into(),
            },
            &RuntimeState::Idle,
            0,
            &mut off_compact_hdr,
            None,
            115,
            24,
        );
        assert!(frame_compact_114.contains("Gemini 5h/W"));
        assert!(frame_compact_114.contains("Claude/GPT 5h/W"));

        let mut off_compact = 0usize;
        let frame_compact = build_dashboard_frame(
            &[acc1.clone(), acc2.clone(), acc3.clone()],
            Some(&acc1.id),
            &policy,
            &SessionIdentity::Matched {
                account_id: acc1.id.clone(),
                email: acc1.email.clone(),
                expiry: "2026-11-17T02:26:00Z".into(),
            },
            &RuntimeState::Idle,
            0,
            &mut off_compact,
            None,
            104,
            24,
        );
        assert!(frame_compact.contains("Gemini 5h/W"));
        let c_row1 = frame_compact
            .split("\r\n")
            .find(|l| l.starts_with('│') && l.contains("100% /  72%"))
            .expect("compact table row 1 must keep `100% /  72%` unwrapped");
        let c_row2 = frame_compact
            .split("\r\n")
            .find(|l| l.starts_with('│') && l.contains("  5% / 100%"))
            .expect("compact table row 2 must keep `  5% / 100%` unwrapped");
        let c_slashes_1: Vec<usize> = c_row1
            .char_indices()
            .filter(|&(_, c)| c == '/')
            .map(|(i, _)| UnicodeWidthStr::width(&c_row1[..i]))
            .collect();
        let c_slashes_2: Vec<usize> = c_row2
            .char_indices()
            .filter(|&(_, c)| c == '/')
            .map(|(i, _)| UnicodeWidthStr::width(&c_row2[..i]))
            .collect();
        assert_eq!(c_slashes_1.len(), 2);
        assert_eq!(
            c_slashes_1, c_slashes_2,
            "compact table slashes must align:\n{c_row1}\n{c_row2}"
        );
    }

    #[test]
    fn batch_candidate_toggle_c_adds_all_enabled_in_order_then_clears_and_disables_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = crate::paths::HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        std::fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths);
        let backend = crate::session::backend::FileSessionBackend;

        let a1 = make_synthetic_account(1);
        let mut a2 = make_synthetic_account(2);
        a2.disabled = true;
        let a3 = make_synthetic_account(3);

        repo.with_write_lock(|tx| {
            tx.upsert_account(a1.clone(), true, 100)?;
            tx.upsert_account(a2.clone(), false, 100)?;
            tx.upsert_account(a3.clone(), false, 100)?;
            Ok(())
        })
        .unwrap();

        let snap = repo.read_snapshot().unwrap();
        let mut status = TransientStatus::default();

        // 1st press of `C`: adds all non-disabled accounts (`a1`, `a3`) in list order, skipping disabled `a2`.
        toggle_all_enabled_candidates_in_tui(&repo, &backend, &snap.accounts, &mut status);
        let pol1 = repo.read_policy().unwrap();
        assert_eq!(
            pol1.candidate_account_ids,
            vec![a1.id.clone(), a3.id.clone()]
        );

        // Turn policy ON via `p`
        toggle_policy_enabled_in_tui(&repo, &backend, &mut status);
        assert!(repo.read_policy().unwrap().enabled);

        // 2nd press of `C` (all enabled accounts already in pool): clears candidates AND turns off `policy.enabled`!
        toggle_all_enabled_candidates_in_tui(&repo, &backend, &snap.accounts, &mut status);
        let pol2 = repo.read_policy().unwrap();
        assert!(pol2.candidate_account_ids.is_empty());
        assert!(!pol2.enabled);
    }

    #[test]
    fn small_terminal_viewport_scrolls_smoothly_and_never_cuts_off_top_header() {
        let accounts: Vec<AccountRecord> = (1..=10).map(make_synthetic_account).collect();
        let policy = SwitchPolicy::default();
        let session_id = SessionIdentity::Uninitialized;
        let runtime_st = RuntimeState::Idle;
        let mut scroll_offset = 0usize;

        // 1. Short & narrow terminal (108 cols x 14 rows): must keep top header + column headers intact
        //    and paginate rows without exceeding 14 lines or wrapping `Keys:` onto a second line.
        let frame_top = build_dashboard_frame(
            &accounts,
            Some(&accounts[0].id),
            &policy,
            &session_id,
            &runtime_st,
            0,
            &mut scroll_offset,
            Some("Ready."),
            108,
            14,
        );
        assert!(!frame_top.ends_with("\r\n"));
        let top_lines: Vec<&str> = frame_top.split("\r\n").collect();
        assert!(
            top_lines.len() <= 14,
            "Frame exceeded 14 terminal rows (got {}): {frame_top}",
            top_lines.len()
        );
        assert!(top_lines[0].starts_with("agy-switch-cli Headless SSH Dashboard"));
        assert!(top_lines[0].contains("Showing 1-"));
        assert!(frame_top.contains("synthetic.user.01@example.invalid"));
        assert!(!frame_top.contains("00000000-0000-4000-8000")); // 36-char ID hidden on <152-col screens
        for line in &top_lines {
            assert!(
                display_width(line) <= 108,
                "Line exceeded 108 cols ({}): {line}",
                display_width(line)
            );
        }

        // 2. Move cursor to #10 (`cursor_idx = 9`): viewport scrolls down to include #10 while keeping header pinned!
        let frame_bottom = build_dashboard_frame(
            &accounts,
            Some(&accounts[0].id),
            &policy,
            &session_id,
            &runtime_st,
            9,
            &mut scroll_offset,
            None,
            108,
            14,
        );
        let bottom_lines: Vec<&str> = frame_bottom.split("\r\n").collect();
        assert!(bottom_lines.len() <= 14);
        assert!(scroll_offset > 0);
        assert!(bottom_lines[0].starts_with("agy-switch-cli Headless SSH Dashboard"));
        assert!(frame_bottom.contains("synthetic.user.10@example.invalid"));

        // 3. Resize terminal to wide & tall (160 cols x 30 rows): viewport pulls back to 0 and shows full ID column!
        let frame_wide = build_dashboard_frame(
            &accounts,
            Some(&accounts[0].id),
            &policy,
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
    }

    #[test]
    fn synthetic_tui_ultra_small_and_narrow_9_row_viewports_respect_physical_bounds_and_show_focus()
    {
        let policy = SwitchPolicy::default();
        let session_id = SessionIdentity::Uninitialized;
        let runtime_st = RuntimeState::Idle;

        // Zero-dimension terminals return an empty frame without panicking or inflating budget.
        for (cols, rows) in [(0u16, 0u16), (0, 24), (80, 0)] {
            let mut off = 3usize;
            let empty_acc = [make_synthetic_account(1)];
            let rendered = build_dashboard_frame(
                &empty_acc,
                None,
                &policy,
                &session_id,
                &runtime_st,
                99,
                &mut off,
                Some("Ready."),
                cols,
                rows,
            );
            assert!(
                rendered.is_empty(),
                "expected empty frame for {cols}x{rows}"
            );
            assert_eq!(off, 0);
        }

        // Exact narrow 9-row fixtures (40x9 and 52x9) with 1 account (both short & long email, no quota):
        // must degrade to compact focus view rather than clipping away the focused account row.
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
                    Some(&fixture_acc.id),
                    &policy,
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
                assert!(
                    lines.len() <= rows as usize,
                    "{label} {cols}x{rows} exceeded rows: {} > {rows}",
                    lines.len()
                );
                for line in &lines {
                    assert!(
                        UnicodeWidthStr::width(*line) <= cols as usize,
                        "{label} {cols}x{rows} exceeded cols: {} > {cols} ({line})",
                        UnicodeWidthStr::width(*line)
                    );
                }
                assert!(
                    lines
                        .iter()
                        .any(|l| l.contains('>') && l.contains("focus.")),
                    "{label} {cols}x{rows} hid focused account row:\n{frame}"
                );
            }
        }

        // Matrix sweep across tiny/medium/wide dimensions, 0/1/2/12 accounts, and out-of-bounds cursor_idx.
        let many_accounts: Vec<AccountRecord> = (1..=12).map(make_synthetic_account).collect();
        let widths = [1u16, 2, 5, 10, 19, 39, 40, 52, 68, 80, 108, 152, 180];
        let heights = [1u16, 2, 3, 4, 5, 8, 9, 10, 14, 24];
        for count in [0usize, 1, 2, 12] {
            let slice = &many_accounts[..count];
            let sel_id = slice.first().map(|a| a.id.as_str());
            for &cols in &widths {
                for &rows in &heights {
                    for &cursor in &[0usize, 5, 99] {
                        for notice in [None, Some("Updated policy.")] {
                            let mut scroll_offset = 7usize;
                            let frame = build_dashboard_frame(
                                slice,
                                sel_id,
                                &policy,
                                &session_id,
                                &runtime_st,
                                cursor,
                                &mut scroll_offset,
                                notice,
                                cols,
                                rows,
                            );
                            assert!(
                                !frame.ends_with("\r\n"),
                                "trailing CRLF at {cols}x{rows} count={count}"
                            );
                            let lines: Vec<&str> = frame.split("\r\n").collect();
                            assert!(
                                lines.len() <= rows as usize,
                                "line budget exceeded at {cols}x{rows} count={count}: {} > {rows}",
                                lines.len()
                            );
                            for line in &lines {
                                let w = UnicodeWidthStr::width(*line);
                                assert!(
                                    w <= cols as usize,
                                    "col budget exceeded at {cols}x{rows} count={count}: {w} > {cols} ({line})"
                                );
                            }
                            if count > 0 && cols >= 1 {
                                assert!(
                                    lines.iter().any(|l| l.contains('>')),
                                    "focus marker '>' missing at {cols}x{rows} count={count} cursor={cursor}:\n{frame}"
                                );
                            }
                        }
                    }
                }
            }
        }

        // 9-column Argon pool boundary sweep across narrow & tall split panes (40..=96 cols x 9..=24 rows):
        // must keep `>` and readable `focus.1@` on the same line without shredding into 3-char vertical strips,
        // and include Argon percentage in both compact and table layouts when width permits.
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
        for cols in [40u16, 52, 60, 68, 72, 77, 78, 84, 96] {
            for rows in [9u16, 12, 16, 24] {
                let mut off = 0usize;
                let frame = build_dashboard_frame(
                    std::slice::from_ref(&argon_acc),
                    Some(&argon_acc.id),
                    &policy,
                    &session_id,
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
                assert!(
                    lines
                        .iter()
                        .any(|l| l.contains('>') && l.contains("focus.1@")),
                    "argon {cols}x{rows} shredded or hid focused email:\n{frame}"
                );
            }
        }
        let mut off_compact_argon = 0usize;
        let compact_argon_wide = build_dashboard_frame(
            std::slice::from_ref(&argon_acc),
            Some(&argon_acc.id),
            &policy,
            &session_id,
            &runtime_st,
            0,
            &mut off_compact_argon,
            None,
            100,
            8,
        );
        assert!(
            compact_argon_wide.contains("Arg 85%"),
            "expected compact row to include Argon pool when present:\n{compact_argon_wide}"
        );
    }

    #[test]
    fn synthetic_tui_standard_unicode_width_truncates_watch_and_emoji_sequences_within_cols() {
        // U+231A WATCH ('⌚') has standard Unicode East_Asian_Width = Wide (2 columns).
        let watch_notice = "⌚".repeat(70);
        let acc = make_synthetic_account(1);
        let policy = SwitchPolicy::default();
        let mut scroll_offset = 0usize;
        let frame = build_dashboard_frame(
            std::slice::from_ref(&acc),
            Some(&acc.id),
            &policy,
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

        // Cluster-boundary integrity: never slice mid-cluster before VS16 (`\u{FE0F}`), keycap (`\u{20E3}`),
        // ZWJ (`\u{200D}`), combining marks, or regional-indicator flag pairs.
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
        // Non-zero-width spacing combining marks (UAX #29 SpacingMark `Mc`, e.g. Devanagari `का` U+0915 U+093E):
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
        let mut off_dev = 0usize;
        let frame_dev = build_dashboard_frame(
            std::slice::from_ref(&devanagari_acc),
            Some(&devanagari_acc.id),
            &policy,
            &SessionIdentity::Uninitialized,
            &RuntimeState::Idle,
            0,
            &mut off_dev,
            None,
            10,
            1,
        );
        assert_eq!(frame_dev, ">* #1 ab…");
        assert!(UnicodeWidthStr::width(frame_dev.as_str()) <= 10);

        // Emoji presentation sequences (`\u{26A0}\u{FE0F}`), CJK, and tiny max_cols boundaries.
        let warn_seq = "\u{26A0}\u{FE0F}".repeat(50);
        let mixed = format!("Status: {} 汉字 {}", "⌚".repeat(30), warn_seq);
        for max_cols in 0..=85 {
            let truncated = truncate_to_cols(&mixed, max_cols);
            let actual = UnicodeWidthStr::width(truncated.as_str());
            assert!(
                actual <= max_cols,
                "truncate_to_cols exceeded max_cols={max_cols} (got {actual}): {truncated}"
            );
        }
    }
}
