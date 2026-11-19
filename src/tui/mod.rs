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
use crate::switching::executor::{execute_account_delete, execute_switch, SwitchOptions};
use crate::transport::client::{HttpTransport, ReqwestTransport};
use crate::transport::proxy::ProxyMode;
use crate::transport::user_agent::resolve_native_oauth_user_agent;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, CellAlignment, ContentArrangement, Table};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, Clear, ClearType},
};
use std::collections::{HashSet, VecDeque};
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
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
    "Keys   : ↑/↓ select · g/G top/end · [/] reorder · Enter/s switch · q/Esc quit";
pub const TUI_KEYS_LINE_2: &str =
    "Manage : r/R refresh · c/C cand · p policy · e/E enable · d/D disable · x delete";
pub const TUI_KEYS_HELP_LINE: &str =
    "Keys: ↑/↓ select · g/G top/end · [/] reorder · Enter/s switch · r/R refresh · c/C cand · p policy · e/E enable · d/D disable · x delete · q/Esc quit";
const TUI_BATCH_REFRESH_CONCURRENCY: usize = 2;
const TRANSIENT_INFO_TTL: Duration = Duration::from_secs(3);
const TRANSIENT_ERROR_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
enum PendingTuiConfirm {
    DeleteAccount {
        account_id: String,
        email: String,
        clear_active_slot: bool,
    },
    DisableAll {
        enabled_count: usize,
    },
}

impl PendingTuiConfirm {
    fn prompt_message(&self) -> String {
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
            Self::DisableAll { enabled_count } => format!(
                "Disable all {enabled_count} account(s)? Press 'y' to confirm (any other key cancels)."
            ),
        }
    }
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
    let mut pending_confirm: Option<PendingTuiConfirm> = None;
    let mut last_redraw = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut force_redraw = true;

    loop {
        if pending_confirm.is_none() && transient_status.expire_if_due(Instant::now()) {
            force_redraw = true;
        }

        if force_redraw || last_redraw.elapsed() >= Duration::from_millis(250) {
            let snap = repo.read_snapshot()?;
            let policy = repo.read_policy()?;
            let slot_state = backend.inspect_slot(repo.paths());
            let session_id = resolve_session_identity(&slot_state, &snap);
            let runtime_st = observe_runtime_state(repo.paths());

            if snap.accounts.is_empty() {
                cursor_idx = 0;
                pending_confirm = None;
            } else {
                if cursor_idx >= snap.accounts.len() {
                    cursor_idx = snap.accounts.len() - 1;
                }
                match &mut pending_confirm {
                    Some(PendingTuiConfirm::DeleteAccount { account_id, .. }) => {
                        if !snap.accounts.iter().any(|a| &a.id == account_id) {
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

            let confirm_msg = pending_confirm
                .as_ref()
                .map(PendingTuiConfirm::prompt_message);
            let notice = confirm_msg
                .as_deref()
                .or_else(|| transient_status.active_text());

            render_dashboard(
                &snap.accounts,
                snap.index.selected_account_id.as_deref(),
                &policy,
                &session_id,
                &runtime_st,
                backend.name(),
                cursor_idx,
                &mut scroll_offset,
                notice,
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
            && matches!(key.code, KeyCode::Char('c' | 'C'))
        {
            break;
        }

        if let Some(pending) = pending_confirm.take() {
            force_redraw = true;
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
                        delete_account_in_tui(
                            repo,
                            backend,
                            &account_id,
                            &email,
                            clear_active_slot,
                            &mut cursor_idx,
                            &mut transient_status,
                        );
                    } else {
                        transient_status
                            .set_info("Canceled account deletion.".into(), Instant::now());
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
        let cur_policy = repo.read_policy()?;
        let slot_state = backend.inspect_slot(repo.paths());
        let session_id = resolve_session_identity(&slot_state, &snap);
        let runtime_st = observe_runtime_state(repo.paths());
        force_redraw = true;

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
                    let switching_msg = format!("Switching to {}...", terminal_text(&target.email));
                    let _ = render_dashboard(
                        &snap.accounts,
                        snap.index.selected_account_id.as_deref(),
                        &cur_policy,
                        &session_id,
                        &runtime_st,
                        backend.name(),
                        cursor_idx,
                        &mut scroll_offset,
                        Some(&switching_msg),
                    );
                    let now_unix = crate::domain::clock::current_unix_seconds();
                    let mut proxy_warnings = Vec::new();
                    let res = async {
                        let cfg = repo.read_config()?;
                        let registry = OAuthClientRegistry::load(repo.paths())?;
                        let (proxy_mode, warns) = ProxyMode::resolve_with_config_and_warnings(
                            cli_proxy,
                            Some(&cfg.network),
                        )?;
                        proxy_warnings = warns;
                        let transport = ReqwestTransport::build(proxy_mode)?;
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
                            crate::domain::clock::current_unix_seconds(),
                        )
                        .await
                    }
                    .await;
                    let proxy_prefix = format_tui_proxy_warning_prefix(&proxy_warnings);
                    let done_at = Instant::now();
                    match res {
                        Ok(out) => {
                            let msg = if out.runtime_warning.is_some() {
                                format!(
                                    "{proxy_prefix}Switched active slot to {} ({}) — running `agy` keeps startup login; new `agy` uses this account.",
                                    terminal_text(&out.target_account_id),
                                    terminal_text(&out.target_email)
                                )
                            } else {
                                format!(
                                    "{proxy_prefix}Switched active slot to {} ({}).",
                                    terminal_text(&out.target_account_id),
                                    terminal_text(&out.target_email)
                                )
                            };
                            transient_status.set_info(msg, done_at);
                        }
                        Err(e) => transient_status.set_error(
                            format!("{proxy_prefix}Switch error: {}", terminal_text(&e.message)),
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
                        backend.name(),
                        cursor_idx,
                        &mut scroll_offset,
                        Some(&refreshing_msg),
                    );
                    let now_unix = crate::domain::clock::current_unix_seconds();
                    let proxy_warnings_r = std::sync::Mutex::new(Vec::new());
                    let mut refresh_fut = std::pin::pin!(async {
                        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
                        let cfg = repo.read_config()?;
                        let registry = OAuthClientRegistry::load(repo.paths())?;
                        let (proxy_mode, warns) = ProxyMode::resolve_with_config_and_warnings(
                            cli_proxy,
                            Some(&cfg.network),
                        )?;
                        *proxy_warnings_r.lock().unwrap() = warns;
                        let transport = ReqwestTransport::build(proxy_mode)?;
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
                                    let _ = render_dashboard(
                                        &snap.accounts,
                                        snap.index.selected_account_id.as_deref(),
                                        &cur_policy,
                                        &session_id,
                                        &runtime_st,
                                        backend.name(),
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
                        let proxy_prefix =
                            format_tui_proxy_warning_prefix(&proxy_warnings_r.lock().unwrap());
                        let done_at = Instant::now();
                        match res {
                            Ok(acc) => transient_status.set_info(
                                format!(
                                    "{proxy_prefix}Refreshed quota for {}.",
                                    terminal_text(&acc.email)
                                ),
                                done_at,
                            ),
                            Err(e) => transient_status.set_error(
                                format!(
                                    "{proxy_prefix}Refresh error: {}",
                                    terminal_text(&e.message)
                                ),
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
                        backend.name(),
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
                if let Some(target) = snap.accounts.get(cursor_idx) {
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
                if snap.accounts.is_empty() {
                    transient_status.set_info("No accounts to delete.".into(), Instant::now());
                } else if let Some(target) = snap.accounts.get(cursor_idx) {
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
) {
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
        }
        Err(e) => {
            transient_status.set_error(
                format!("Delete error: {}", terminal_text(&e.message)),
                done_at,
            );
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
            backend.name(),
            cur_bounded,
            scroll_offset,
            Some(&prog_msg),
        );
    }
}

fn format_tui_proxy_warning_prefix(warnings: &[String]) -> String {
    if warnings.is_empty() {
        String::new()
    } else {
        let joined = warnings
            .iter()
            .map(|w| terminal_text(w))
            .collect::<Vec<_>>()
            .join(" ");
        format!("[warning: {joined}] ")
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
    let now_unix = crate::domain::clock::current_unix_seconds();
    let prep_proxy_warnings = std::sync::Mutex::new(Vec::new());
    let mut prep = std::pin::pin!(async {
        reconcile_pending_journal_before_write(repo, backend, now_unix)?;
        let cfg = repo.read_config()?;
        let registry = OAuthClientRegistry::load(repo.paths())?;
        let (proxy_mode, warns) =
            ProxyMode::resolve_with_config_and_warnings(cli_proxy, Some(&cfg.network))?;
        *prep_proxy_warnings.lock().unwrap() = warns;
        let transport = ReqwestTransport::build(proxy_mode)?;
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
                    let proxy_prefix =
                        format_tui_proxy_warning_prefix(&prep_proxy_warnings.lock().unwrap());
                    transient_status.set_error(
                        format!(
                            "{proxy_prefix}Refresh error: {}",
                            terminal_text(&e.message)
                        ),
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
    let transport_dyn: Arc<dyn HttpTransport> = transport;
    let outcome = run_tui_batch_refresh_loop(
        repo,
        backend,
        targets.to_vec(),
        transport_dyn,
        registry,
        oauth_ep,
        quota_ep,
        ua,
        TUI_BATCH_REFRESH_CONCURRENCY,
        cursor_idx,
        scroll_offset,
        true,
        sigterm,
        sigint,
        sighup,
    )
    .await;
    if outcome.interrupted {
        return true;
    }

    let proxy_prefix = format_tui_proxy_warning_prefix(&prep_proxy_warnings.lock().unwrap());
    let done_at = Instant::now();
    if let Some((rec_email, rec_err)) = outcome.recovery_error {
        transient_status.set_error(
            format!(
                "{proxy_prefix}Stopped batch refresh after recovery error on {}: {} ({} ok, {} skipped).",
                terminal_text(&rec_email),
                terminal_text(&rec_err.message),
                outcome.ok_count,
                outcome.skipped_after_recovery,
            ),
            done_at,
        );
    } else if outcome.failures.is_empty() {
        transient_status.set_info(
            format!(
                "{proxy_prefix}Refreshed {}/{total} enabled account(s).",
                outcome.ok_count
            ),
            done_at,
        );
    } else {
        let (first_email, first_err) = &outcome.failures[0];
        transient_status.set_error(
            format!(
                "{proxy_prefix}Refreshed {}/{total} ({} failed; {}: {}).",
                outcome.ok_count,
                outcome.failures.len(),
                terminal_text(first_email),
                terminal_text(first_err)
            ),
            done_at,
        );
    }
    false
}

struct TuiBatchRefreshLoopOutcome {
    interrupted: bool,
    ok_count: usize,
    failures: Vec<(String, String)>,
    recovery_error: Option<(String, CliError)>,
    skipped_after_recovery: usize,
}

#[allow(clippy::too_many_arguments)]
async fn run_tui_batch_refresh_loop(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    targets: Vec<(String, String)>,
    transport: Arc<dyn HttpTransport>,
    registry: Arc<OAuthClientRegistry>,
    oauth_ep: Arc<OAuthEndpoints>,
    quota_ep: Arc<CloudCodeEndpoints>,
    ua: String,
    concurrency: usize,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    render_tty_progress: bool,
    sigterm: &mut Option<tokio::signal::unix::Signal>,
    sigint: &mut Option<tokio::signal::unix::Signal>,
    sighup: &mut Option<tokio::signal::unix::Signal>,
) -> TuiBatchRefreshLoopOutcome {
    let total = targets.len();
    let max_in_flight = concurrency.max(1);
    let (tx, mut rx) =
        mpsc::unbounded_channel::<(String, CliResult<crate::domain::account::AccountRecord>)>();

    let mut queue: VecDeque<(String, String)> = targets.into_iter().collect();
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(total);
    let mut in_flight = 0usize;

    let spawn_next = |queue: &mut VecDeque<(String, String)>,
                      handles: &mut Vec<tokio::task::JoinHandle<()>>,
                      in_flight: &mut usize| {
        if let Some((id_c, email_c)) = queue.pop_front() {
            let repo_c = repo.clone();
            let tr_c = transport.clone();
            let reg_c = registry.clone();
            let oe_c = oauth_ep.clone();
            let qe_c = quota_ep.clone();
            let ua_c = ua.clone();
            let tx_c = tx.clone();
            handles.push(tokio::spawn(async move {
                let res = refresh_account_quota_locked(
                    &repo_c,
                    tr_c.as_ref(),
                    &oe_c,
                    &qe_c,
                    &reg_c,
                    &ua_c,
                    &id_c,
                    crate::domain::clock::current_unix_seconds(),
                )
                .await;
                let _ = tx_c.send((email_c, res));
            }));
            *in_flight += 1;
        }
    };

    // Dispatch ONLY up to `max_in_flight` tasks initially; any `PartialCommitOrRecovery` (`7`)
    // immediately clears `queue` so remaining accounts issue zero further `/token` exchanges while
    // already-in-flight tasks safely finish persisting their responses!
    while in_flight < max_in_flight && !queue.is_empty() {
        spawn_next(&mut queue, &mut handles, &mut in_flight);
    }

    let mut completed = 0usize;
    let mut ok_count = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut recovery_error: Option<(String, CliError)> = None;
    let mut skipped_after_recovery = 0usize;
    let mut interrupted = false;

    while in_flight > 0 {
        let next_item = if render_tty_progress {
            tokio::select! {
                _ = async {
                    if let Some(ref mut s) = sigterm { let _ = s.recv().await; }
                    else { std::future::pending::<()>().await; }
                } => { interrupted = true; break; }
                _ = async {
                    if let Some(ref mut s) = sigint { let _ = s.recv().await; }
                    else { std::future::pending::<()>().await; }
                } => { interrupted = true; break; }
                _ = async {
                    if let Some(ref mut s) = sighup { let _ = s.recv().await; }
                    else { std::future::pending::<()>().await; }
                } => { interrupted = true; break; }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {
                    let (should_exit, saw_resize) = poll_raw_tty_interrupt_or_resize();
                    if should_exit {
                        interrupted = true;
                        break;
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
            }
        } else {
            rx.recv().await
        };

        let Some((email, res)) = next_item else {
            break;
        };
        in_flight = in_flight.saturating_sub(1);
        completed += 1;
        match res {
            Ok(_) => ok_count += 1,
            Err(e) => {
                if e.exit_code == crate::error::ExitCode::PartialCommitOrRecovery {
                    if recovery_error.is_none() {
                        recovery_error = Some((email.clone(), e.clone()));
                    }
                    skipped_after_recovery += queue.len();
                    queue.clear();
                }
                failures.push((email, e.message));
            }
        }
        if recovery_error.is_none() {
            while in_flight < max_in_flight && !queue.is_empty() {
                spawn_next(&mut queue, &mut handles, &mut in_flight);
            }
        }
        if render_tty_progress && completed < total && recovery_error.is_none() {
            render_live_batch_progress(repo, backend, cursor_idx, scroll_offset, completed, total);
        }
    }

    drop(tx);
    if interrupted {
        let _abort_guard = AbortTasksOnDrop(handles);
    } else {
        for h in handles {
            let _ = h.await;
        }
    }

    TuiBatchRefreshLoopOutcome {
        interrupted,
        ok_count,
        failures,
        recovery_error,
        skipped_after_recovery,
    }
}

fn toggle_all_enabled_candidates_in_tui(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    accounts: &[crate::domain::account::AccountRecord],
    transient_status: &mut TransientStatus,
) {
    let now_unix = crate::domain::clock::current_unix_seconds();
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
                clear_daemon_pause_in_tx(tx.paths(), now_unix)?;
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
            clear_daemon_pause_in_tx(tx.paths(), now_unix)?;
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
    let now_unix = crate::domain::clock::current_unix_seconds();
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
            clear_daemon_pause_in_tx(tx.paths(), now_unix)?;
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
    let now_unix = crate::domain::clock::current_unix_seconds();
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
            clear_daemon_pause_in_tx(tx.paths(), now_unix)?;
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
    backend_tag: &str,
    cursor_idx: usize,
    scroll_offset: &mut usize,
    transient_notice: Option<&str>,
) -> CliResult<()> {
    let (term_cols, term_rows) = current_terminal_size();
    let rendered = build_dashboard_frame_with_backend(
        accounts,
        selected_id,
        policy,
        session_id,
        runtime_st,
        backend_tag,
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

#[cfg(test)]
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
    build_dashboard_frame_with_backend(
        accounts,
        selected_id,
        policy,
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

#[allow(clippy::too_many_arguments)]
fn build_dashboard_frame_with_backend(
    accounts: &[crate::domain::account::AccountRecord],
    selected_id: Option<&str>,
    policy: &SwitchPolicy,
    session_id: &crate::domain::account::SessionIdentity,
    runtime_st: &crate::domain::account::RuntimeState,
    backend_tag: &str,
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

    let clean_backend_tag = match backend_tag.trim().to_ascii_lowercase().as_str() {
        "dual" | "secret_service_dual" => "dual",
        "keyring" | "secret_service_keyring" => "keyring",
        _ => "file",
    };

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
    let sess_label = format!("Session [{clean_backend_tag}]");
    let label_w = sess_label.len();
    let compact_session_line = truncate_to_cols(
        &format!(
            "{sess_label}: {} | Runtime: {} | Policy: {}",
            format_session_identity_human(session_id),
            format_runtime_state_human(runtime_st),
            policy_header
        ),
        cols,
    );
    let use_three_line_header = rows >= 11;
    let status_header_lines: Vec<String> = if use_three_line_header {
        vec![
            truncate_to_cols(
                &format!(
                    "{sess_label} : {}",
                    format_session_identity_human(session_id)
                ),
                cols,
            ),
            truncate_to_cols(
                &format!(
                    "{:<label_w$} : {}",
                    "Runtime",
                    format_runtime_state_human(runtime_st)
                ),
                cols,
            ),
            truncate_to_cols(&format!("{:<label_w$} : {policy_header}", "Policy"), cols),
        ]
    } else {
        vec![compact_session_line.clone()]
    };
    let keys_line = keys_help_for_width(cols);
    let footer_help_lines: Vec<String> = if rows >= 14 {
        keys_help_two_lines_for_width(cols).to_vec()
    } else {
        vec![keys_line.clone()]
    };
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

    // Pre-compute global single-line column budgets across ALL accounts so bordered table rows NEVER
    // wrap onto multiple physical lines when long emails or policy labels scroll into the viewport,
    // guaranteeing 100% constant frame height across every cursor position!
    let gemini_hdr = if compact_cols {
        "Gemini 5h/W"
    } else {
        "Gemini (5h / W)"
    };
    let claude_hdr = if compact_cols {
        "Claude/GPT 5h/W"
    } else {
        "Claude/GPT (5h / W)"
    };
    let argon_hdr = if compact_cols { "Argon W" } else { "Argon (W)" };
    let num_table_cols = 8 + usize::from(show_id_col) + usize::from(show_argon);
    let table_border_overhead = 3 * num_table_cols + 1;

    let idx_col_w = accounts.len().to_string().len().max(3); // fits `"..."` and `"12"`
    let sel_col_w = 3usize; // `"Sel"` / `">*"`
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
    let plan_col_w = summaries
        .iter()
        .map(|s| display_width(&short_plan_label(&s.plan)))
        .max()
        .unwrap_or(4)
        .clamp(4, 14);
    let gemini_col_w = summaries
        .iter()
        .map(|s| display_width(&s.gemini.format_dual_aligned()))
        .max()
        .unwrap_or(0)
        .max(display_width(gemini_hdr));
    let claude_col_w = summaries
        .iter()
        .map(|s| display_width(&s.third_party.format_dual_aligned()))
        .max()
        .unwrap_or(0)
        .max(display_width(claude_hdr));
    let argon_col_w = if show_argon {
        summaries
            .iter()
            .map(|s| display_width(&s.argon.format_weekly_aligned()))
            .max()
            .unwrap_or(0)
            .max(display_width(argon_hdr))
    } else {
        0
    };
    let policy_str_for = |acc: &crate::domain::account::AccountRecord| -> String {
        policy
            .candidate_account_ids
            .iter()
            .position(|cid| cid == &acc.id)
            .map(|p| {
                if acc.disabled {
                    format!("cand #{} (skip)", p + 1)
                } else {
                    format!("cand #{}", p + 1)
                }
            })
            .unwrap_or_else(|| "—".into())
    };
    let state_str_for = |dto: &AccountViewDto| -> &'static str {
        if dto.disabled {
            "disabled"
        } else if dto.validation_blocked {
            "verify-blocked"
        } else {
            "ok"
        }
    };
    let policy_col_w = accounts
        .iter()
        .map(|a| display_width(&policy_str_for(a)))
        .max()
        .unwrap_or(6)
        .clamp(6, 18);
    let state_col_w = accounts
        .iter()
        .map(|a| {
            let dto = AccountViewDto::from_record(a, selected_id == Some(a.id.as_str()));
            display_width(state_str_for(&dto))
        })
        .max()
        .unwrap_or(5)
        .clamp(5, 14);

    let non_email_total = table_border_overhead
        + idx_col_w
        + sel_col_w
        + id_col_w
        + plan_col_w
        + gemini_col_w
        + claude_col_w
        + argon_col_w
        + policy_col_w
        + state_col_w;
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
            headers.push(Cell::new("Plan"));
            headers.push(Cell::new(gemini_hdr).set_alignment(CellAlignment::Center));
            headers.push(Cell::new(claude_hdr).set_alignment(CellAlignment::Center));
            if show_argon {
                headers.push(Cell::new(argon_hdr).set_alignment(CellAlignment::Center));
            }
            headers.push(Cell::new("Policy"));
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
                cells.push(Cell::new(""));
                if show_argon {
                    cells.push(Cell::new(""));
                }
                cells.push(Cell::new(""));
                cells.push(Cell::new(""));
                cells
            };

            if show_top_dots && start > 0 {
                table.add_row(make_dots_row(format!("... ({start} more above)")));
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
                let plan_str = truncate_to_cols(&short_plan_label(&sum.plan), plan_col_w);
                let policy_str = truncate_to_cols(&policy_str_for(acc), policy_col_w);
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
                    &terminal_text(&dto.email),
                    effective_email_cap,
                )));
                cells.push(Cell::new(plan_str));
                cells.push(
                    Cell::new(sum.gemini.format_dual_aligned())
                        .set_alignment(CellAlignment::Center),
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

            if show_bottom_dots && end < accounts.len() {
                let below = accounts.len() - end;
                table.add_row(make_dots_row(format!("... ({below} more below)")));
            }

            table.to_string()
        };

    // Fixed chrome: 1 title line + `status_header_lines.len()` (3 on `rows >= 11`, 1 on `5..=10`)
    // + `footer_help_lines.len()` (2 on `rows >= 14`, 1 on `rows < 14`) + 1 reserved status line;
    // remaining rows belong to the account viewport (`>= 1`).
    let fixed_chrome_lines = 1 + status_header_lines.len() + footer_help_lines.len() + 1;
    let max_table_lines = rows.saturating_sub(fixed_chrome_lines);
    // Require enough width so every column (including `Email >= 8` chars) fits strictly on 1 physical line.
    let min_table_cols = if show_argon { 78 } else { 68 };
    let can_render_single_line_table = cols >= min_table_cols && email_col_budget >= 8;
    let mut frame_lines: Vec<String> = Vec::with_capacity(rows);

    if accounts.is_empty() {
        *scroll_offset = 0;
        frame_lines.push(truncate_to_cols(
            "agy-switch-cli Headless SSH Dashboard  [0 accounts]",
            cols,
        ));
        frame_lines.extend(status_header_lines);
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
                *scroll_offset,
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
            frame_lines.extend(status_header_lines);
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
            let (start, end, show_top, show_bottom) = compute_viewport_with_indicators(
                accounts.len(),
                cur,
                *scroll_offset,
                max_table_lines.max(1),
            );
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
        .or_else(|| strip_ascii_prefix_ci(core, "antigravity "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(core);
    let stripped_lower = stripped.to_ascii_lowercase();
    let normalized = match stripped_lower.as_str() {
        "free" | "free tier" | "free-tier" | "free_tier" | "free quota" | "g1-free-tier"
        | "g1_free_tier" | "google-ai-free" | "google_ai_free" | "starter" | "starter quota"
        | "starter tier" | "starter-quota" | "starter_quota" | "starter-tier" | "starter_tier" => {
            "Free"
        }
        "pro" | "pro tier" | "pro-tier" | "pro_tier" | "g1-pro-tier" | "g1_pro_tier"
        | "google-ai-pro" | "google_ai_pro" => "Pro",
        "ultra" | "ultra tier" | "ultra-tier" | "ultra_tier" | "g1-ultra-tier"
        | "g1_ultra_tier" | "google-ai-ultra" | "google_ai_ultra" => "Ultra",
        s if s.contains("starter") => "Free",
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
    } else if cols >= 62 {
        "Keys   : ↑/↓ sel · g/G top/end · [/] order · s switch · q quit"
    } else {
        "Keys   : ↑/↓ sel · g/G end · [/] ord · s sw · q quit"
    };
    let l2 = if cols >= display_width(TUI_KEYS_LINE_2) {
        TUI_KEYS_LINE_2
    } else if cols >= 62 {
        "Manage : r/R ref · c/C cand · p pol · e/E en · d/D dis · x del"
    } else {
        "Manage : r/R · c/C · p pol · e/E · d/D · x del"
    };
    [truncate_to_cols(l1, cols), truncate_to_cols(l2, cols)]
}

fn keys_help_for_width(cols: usize) -> String {
    let candidate = if cols >= display_width(TUI_KEYS_HELP_LINE) {
        TUI_KEYS_HELP_LINE
    } else if cols >= 116 {
        "Keys: ↑/↓ sel · g/G top/end · [/] order · s switch · r/R ref · c/C cand · p pol · e/E en · d/D dis · x del · q quit"
    } else if cols >= 96 {
        "Keys: ↑/↓ sel · g/G end · [/] ord · s sw · r/R ref · c/C · p · e/E en · d/D dis · x del · q quit"
    } else if cols >= 86 {
        "Keys: ↑/↓ · g/G end · [/] ord · s sw · r/R · c/C · p · e/E en · d/D dis · x del · q"
    } else {
        "Keys: ↑/↓ · g/G · [/] · s sw · r/R · c/C · p · e/E · d/D · x del · q quit"
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
        assert!(TUI_KEYS_HELP_LINE.contains("↑/↓ select"));
        assert!(TUI_KEYS_HELP_LINE.contains("[/] reorder"));
        assert!(TUI_KEYS_HELP_LINE.contains("x delete"));
        assert!(!TUI_KEYS_HELP_LINE.contains("k/j"));
        assert!(!TUI_KEYS_HELP_LINE.contains("K/J"));
        assert!(!TUI_KEYS_HELP_LINE.contains("1-9"));
        assert!(TUI_KEYS_HELP_LINE.contains("r/R refresh · c/C cand · p policy"));
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
        assert_eq!(short_plan_label("Antigravity Starter Quota"), "Free");
        assert_eq!(short_plan_label("Starter Tier"), "Free");
        assert_eq!(
            short_plan_label("Antigravity Starter Quota (Restricted)"),
            "Free (Restricted)"
        );
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

        // 1. Short & narrow terminal (108 cols x 14 rows): must keep top header + column headers intact,
        //    embed constant-height `... (<K> more above/below)` rows without frame-height jitter,
        //    and paginate rows without exceeding 14 lines.
        let frame_top = build_dashboard_frame(
            &accounts,
            Some(&accounts[0].id),
            &policy,
            &session_id,
            &runtime_st,
            0,
            &mut scroll_offset,
            None,
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
        assert!(!frame_top.contains("more above)"));
        assert!(frame_top.contains("... (8 more below)"));
        assert!(!frame_top.contains("00000000-0000-4000-8000")); // 36-char ID hidden on <152-col screens
        for line in &top_lines {
            assert!(
                display_width(line) <= 108,
                "Line exceeded 108 cols ({}): {line}",
                display_width(line)
            );
        }

        // 1b. Move cursor to middle (`cursor_idx = 5`, `#6`): BOTH `... (5 more above)` and `... (4 more below)`
        //     appear inside the table while keeping total frame height IDENTICAL (`mid_lines.len() == top_lines.len()`)!
        let frame_mid = build_dashboard_frame(
            &accounts,
            Some(&accounts[0].id),
            &policy,
            &session_id,
            &runtime_st,
            5,
            &mut scroll_offset,
            None,
            108,
            14,
        );
        let mid_lines: Vec<&str> = frame_mid.split("\r\n").collect();
        assert_eq!(
            mid_lines.len(),
            top_lines.len(),
            "Table height must remain constant across top and middle scroll states!"
        );
        assert!(frame_mid.contains("... (5 more above)"));
        assert!(frame_mid.contains("synthetic.user.06@example.invalid"));
        assert!(frame_mid.contains("... (4 more below)"));

        // 2. Move cursor to #10 (`cursor_idx = 9`): viewport scrolls down to include #10 with `... (8 more above)`
        //    and ZERO `more below`, keeping frame height IDENTICAL (`bottom_lines.len() == top_lines.len()`)!
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
        assert_eq!(
            bottom_lines.len(),
            top_lines.len(),
            "Table height must remain constant across top, middle, and bottom scroll states!"
        );
        assert!(scroll_offset > 0);
        assert!(bottom_lines[0].starts_with("agy-switch-cli Headless SSH Dashboard"));
        assert!(frame_bottom.contains("... (8 more above)"));
        assert!(frame_bottom.contains("synthetic.user.10@example.invalid"));
        assert!(!frame_bottom.contains("more below)"));

        // 3. Resize terminal to wide & tall (160 cols x 30 rows): viewport pulls back to 0, shows full ID column,
        //    and omits ALL `...` indicator rows when all accounts fit on screen!
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
        assert!(!frame_wide.contains("more above)"));
        assert!(!frame_wide.contains("more below)"));
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
        let heights = [1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 24];
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

    #[test]
    fn tui_three_line_header_backend_tags_short_collapse_and_gg_help_hints() {
        let acc = make_synthetic_account(1);
        let policy = SwitchPolicy {
            enabled: true,
            reserve_percentage: 15,
            candidate_min_percentage: 35,
            candidate_account_ids: vec![acc.id.clone()],
            ..SwitchPolicy::default()
        };
        let sess = SessionIdentity::Matched {
            account_id: acc.id.clone(),
            email: acc.email.clone(),
            expiry: "2026-11-18T08:00:00Z".into(),
        };
        let runtime = RuntimeState::UnmanagedRunning {
            pids: vec![636233],
            managed_account_ids: Vec::new(),
        };

        // 1. `g/G`, `[/]`, `e/E`, `d/D`, and `x` hints appear with word labels across medium 1-line tiers (`rows < 14`),
        //    and `rows >= 14` renders the 2-line aligned `Keys   :` / `Manage :` footer!
        assert!(TUI_KEYS_HELP_LINE.contains("g/G top/end"));
        assert!(TUI_KEYS_HELP_LINE.contains("e/E enable · d/D disable"));
        for cols in [150usize, 120, 96, 86] {
            let help = keys_help_for_width(cols);
            assert!(
                help.contains("g/G ")
                    && help.contains("[/] ")
                    && help.contains("e/E ")
                    && help.contains("d/D ")
                    && help.contains("x "),
                "Expected word labels for g/G, [/], e/E, d/D, x on 1-line bar at cols={cols}: {help}"
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

        let two_80 = keys_help_two_lines_for_width(80);
        assert_eq!(two_80[0], TUI_KEYS_LINE_1);
        assert_eq!(two_80[1], TUI_KEYS_LINE_2);
        assert_eq!(two_80[0].find(" : "), two_80[1].find(" : "));
        for cols in [56usize, 60, 62, 70, 78, 120] {
            let two = keys_help_two_lines_for_width(cols);
            assert_eq!(
                two[0].find(" : "),
                two[1].find(" : "),
                "Expected aligned colons on 2-line footer at cols={cols}: {two:?}"
            );
            assert!(display_width(&two[0]) <= cols && display_width(&two[1]) <= cols);
        }

        // 2. Normal height (`rows >= 11`): 3 separate aligned status lines (`Session [...]`, `Runtime`, `Policy`)
        for tag in ["file", "dual", "keyring"] {
            let mut off = 0usize;
            let frame = build_dashboard_frame_with_backend(
                std::slice::from_ref(&acc),
                Some(&acc.id),
                &policy,
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
            assert!(
                lines[1].starts_with(&format!("Session [{tag}] : matched (")),
                "Unexpected Session line for {tag}: {}",
                lines[1]
            );
            assert!(
                lines[2].starts_with("Runtime")
                    && lines[2].contains(": unmanaged_running (pids=[636233])"),
                "Unexpected Runtime line for {tag}: {}",
                lines[2]
            );
            assert!(
                lines[3].starts_with("Policy") && lines[3].contains(": ON (reserve 15% / min 35%"),
                "Unexpected Policy line for {tag}: {}",
                lines[3]
            );
            // Colons on lines 1, 2, 3 align vertically!
            let colon_1 = lines[1].find(" : ").unwrap();
            let colon_2 = lines[2].find(" : ").unwrap();
            let colon_3 = lines[3].find(" : ").unwrap();
            assert_eq!(colon_1, colon_2);
            assert_eq!(colon_2, colon_3);
        }

        // 3. Short height (`rows = 8 < 11`): collapses gracefully onto 1 line while preserving `[dual]` tag!
        let mut off_short = 0usize;
        let short_frame = build_dashboard_frame_with_backend(
            std::slice::from_ref(&acc),
            Some(&acc.id),
            &policy,
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
        assert!(short_lines[1].contains(" | Policy: "));

        // 4. Verify TUI proxy warning formatter places variable-name-only diagnostic at front so narrow terminals never clip it
        assert_eq!(format_tui_proxy_warning_prefix(&[]), "");
        assert_eq!(
            format_tui_proxy_warning_prefix(&[
                "Ignored unsupported or malformed proxy URL in `HTTPS_PROXY` environment variable."
                    .into()
            ]),
            "[warning: Ignored unsupported or malformed proxy URL in `HTTPS_PROXY` environment variable.] "
        );

        // 5. Verify `delete_account_in_tui` clears active slot + policy candidates and clamps `cursor_idx`!
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
            let mut pol = SwitchPolicy {
                enabled: true,
                candidate_account_ids: vec![a2.id.clone()],
                ..SwitchPolicy::default()
            };
            tx.save_policy(&mut pol, None, 100)?;
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
        assert_eq!(
            cursor, 0,
            "cursor_idx must clamp to 0 after deleting tail account"
        );
        assert!(
            !paths.active_slot_file.exists(),
            "active slot must be cleared"
        );
        assert_eq!(repo.read_snapshot().unwrap().accounts.len(), 1);
        assert!(repo.read_policy().unwrap().candidate_account_ids.is_empty());
        assert!(!repo.read_policy().unwrap().enabled);

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
            PendingTuiConfirm::DisableAll { enabled_count: 2 }.prompt_message(),
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
        let mut q5 = crate::domain::quota::QuotaObservation::new(
            100,
            crate::domain::quota::QuotaSourceEnv::Daily,
        );
        q5.subscription_tier = Some("Google AI Pro (Restricted)".into());
        accounts[5].quota = Some(q5);
        accounts[9].validation_blocked = true;
        let policy = SwitchPolicy {
            enabled: true,
            candidate_account_ids: accounts.iter().map(|a| a.id.clone()).collect(),
            ..SwitchPolicy::default()
        };
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
                    Some(&accounts[0].id),
                    &policy,
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
                assert!(
                    lines.len() <= rows,
                    "Frame exceeded terminal height {rows} at ({cols}x{rows}, cur={cur}): {} lines",
                    lines.len()
                );
                for line in &lines {
                    assert!(
                        display_width(line) <= cols,
                        "Line exceeded width {cols} at ({cols}x{rows}, cur={cur}): `{line}`"
                    );
                }
                assert!(
                    lines.iter().any(|l| l.contains(">*") || l.contains("> ")),
                    "Focused cursor marker missing at ({cols}x{rows}, cur={cur}):\n{frame}"
                );
                if let Some(expected) = baseline_lines {
                    assert_eq!(
                        lines.len(),
                        expected,
                        "Frame height jittered across scroll at ({cols}x{rows}, cur={cur}): expected {expected}, got {}\n{frame}",
                        lines.len()
                    );
                } else {
                    baseline_lines = Some(lines.len());
                }
                if let Some(exp_b) = baseline_bordered {
                    assert_eq!(
                        is_bordered, exp_b,
                        "Layout flipped between bordered and compact mid-scroll at ({cols}x{rows}, cur={cur}):\n{frame}"
                    );
                } else {
                    baseline_bordered = Some(is_bordered);
                }
            }
        }
    }

    #[tokio::test]
    async fn r3_04_tui_batch_refresh_short_circuits_queued_accounts_on_exit_7() {
        use crate::paths::HeadlessPaths;
        use crate::session::backend::FileSessionBackend;
        use crate::transport::client::MockTransport;
        use std::sync::atomic::AtomicUsize;

        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let repo = StoreRepository::new(paths.clone()).with_lock_timeout(Duration::from_millis(80));
        let now = crate::domain::clock::current_unix_seconds();

        let mut targets = Vec::new();
        for idx in 0..3usize {
            let mut acc = make_synthetic_account(idx);
            acc.token.expiry_timestamp = 1; // force `/token` refresh
            targets.push((acc.id.clone(), acc.email.clone()));
            repo.with_write_lock(|tx| tx.upsert_account(acc.clone(), idx == 0, now))
                .unwrap();
        }

        let token_calls = Arc::new(AtomicUsize::new(0));
        let token_calls_c = token_calls.clone();
        let holder_repo = StoreRepository::new(paths.clone());
        let holder_join: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let holder_join_c = holder_join.clone();

        let transport: Arc<dyn HttpTransport> = Arc::new(MockTransport::from_handler(move |req| {
            if req.url.contains("/token") {
                let call_no = token_calls_c.fetch_add(1, Ordering::SeqCst);
                if call_no == 0 {
                    // Preflight L3 already passed; acquire L3 from another thread so post-`/token`
                    // persistence hits `lock_busy` -> `issued_token_unpersisted` (exit 7)!
                    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
                    let r_hold = holder_repo.clone();
                    let h = std::thread::spawn(move || {
                        let _ = r_hold.with_write_lock(|_| {
                            let _ = ready_tx.send(());
                            std::thread::sleep(Duration::from_millis(250));
                            Ok(())
                        });
                    });
                    let _ = ready_rx.recv_timeout(Duration::from_secs(2));
                    *holder_join_c.lock().unwrap() = Some(h);
                }
                return Ok(MockTransport::json_response(
                    200,
                    serde_json::json!({
                        "access_token": format!("ya29.tui-rot-{call_no}"),
                        "refresh_token": format!("1//tui-rot-rt-{call_no}"),
                        "expires_in": 3600,
                        "token_type": "Bearer"
                    }),
                ));
            }
            Ok(MockTransport::json_response(200, serde_json::json!({})))
        }));

        let registry = Arc::new(OAuthClientRegistry::load(&paths).unwrap());
        let oauth_ep = Arc::new(OAuthEndpoints::default());
        let quota_ep = Arc::new(CloudCodeEndpoints::default());
        let mut scroll_off = 0usize;
        let mut s1 = None;
        let mut s2 = None;
        let mut s3 = None;

        let outcome = run_tui_batch_refresh_loop(
            &repo,
            &FileSessionBackend,
            targets,
            transport,
            registry,
            oauth_ep,
            quota_ep,
            "antigravity/hub/4.3.0 (os_type=linux; arch=amd64)".into(),
            1,
            0,
            &mut scroll_off,
            false,
            &mut s1,
            &mut s2,
            &mut s3,
        )
        .await;

        if let Some(h) = holder_join.lock().unwrap().take() {
            let _ = h.join();
        }

        assert!(
            outcome.recovery_error.is_some(),
            "Expected PartialCommitOrRecovery error to be recorded"
        );
        assert_eq!(
            outcome.recovery_error.as_ref().unwrap().1.exit_code,
            crate::error::ExitCode::PartialCommitOrRecovery
        );
        assert_eq!(
            outcome.skipped_after_recovery, 2,
            "Remaining 2 queued accounts MUST be skipped immediately on first exit 7!"
        );
        assert_eq!(
            token_calls.load(Ordering::SeqCst),
            1,
            "Queued accounts MUST NOT issue `/token` requests after first exit 7!"
        );
    }
}
