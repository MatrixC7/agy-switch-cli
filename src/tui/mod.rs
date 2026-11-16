use crate::cli::dto::{
    format_pct, format_runtime_state_human, format_session_identity_human, terminal_text,
    AccountViewDto,
};
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
use crate::switching::executor::{execute_switch, SwitchOptions};
use crate::transport::client::ReqwestTransport;
use crate::transport::proxy::ProxyMode;
use crate::transport::user_agent::resolve_native_oauth_user_agent;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, ContentArrangement, Table};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, Clear, ClearType},
};
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

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
    let mut status_banner = String::from(
        "Keys: ↑/↓ or j/k or 1-9 move | Enter/s switch | r refresh | e/d enable/disable | q/Esc/Ctrl+C quit",
    );
    let mut last_redraw = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut force_redraw = true;

    loop {
        if force_redraw || last_redraw.elapsed() >= Duration::from_millis(250) {
            let snap = repo.read_snapshot()?;
            let slot_state = backend.inspect_slot(repo.paths());
            let session_id = resolve_session_identity(&slot_state, &snap);
            let runtime_st = observe_runtime_state(repo.paths());

            if !snap.accounts.is_empty() && cursor_idx >= snap.accounts.len() {
                cursor_idx = snap.accounts.len() - 1;
            }

            render_dashboard(
                &snap.accounts,
                snap.index.selected_account_id.as_deref(),
                &session_id,
                &runtime_st,
                cursor_idx,
                &status_banner,
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

        let Event::Key(key) = event::read()
            .map_err(|e| CliError::io("tui_read_error", format!("TUI event read error: {e}")))?
        else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'C' | 'd' | 'D'))
        {
            break;
        }

        let snap = repo.read_snapshot()?;
        let slot_state = backend.inspect_slot(repo.paths());
        let session_id = resolve_session_identity(&slot_state, &snap);
        let runtime_st = observe_runtime_state(repo.paths());
        force_redraw = true;

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Char(digit @ '1'..='9') => {
                let target_idx = (digit as usize) - ('1' as usize);
                if target_idx < snap.accounts.len() {
                    cursor_idx = target_idx;
                }
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
                        &session_id,
                        &runtime_st,
                        cursor_idx,
                        &switching_msg,
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
                    status_banner = match res {
                        Ok(out) => format!(
                            "Switched active slot to {} ({}).",
                            terminal_text(&out.target_account_id),
                            terminal_text(&out.target_email)
                        ),
                        Err(e) => format!("Switch error: {}", terminal_text(&e.message)),
                    };
                }
            }
            KeyCode::Char('r') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    let now_unix = chrono::Utc::now().timestamp();
                    let refresh_fut = async {
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
                    };
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
                        res = refresh_fut => {
                            status_banner = match res {
                                Ok(acc) => format!("Refreshed quota for {}.", terminal_text(&acc.email)),
                                Err(e) => format!("Refresh error: {}", terminal_text(&e.message)),
                            };
                        }
                    }
                }
            }
            KeyCode::Char('e') => {
                if let Some(target) = snap.accounts.get(cursor_idx) {
                    let now_unix = chrono::Utc::now().timestamp();
                    let res = reconcile_pending_journal_before_write(repo, backend, now_unix)
                        .and_then(|_| {
                            repo.with_write_lock(|tx| tx.mark_account_enabled(&target.id))
                        });
                    match res {
                        Ok(_) => {
                            status_banner = format!("Enabled {}.", terminal_text(&target.email));
                        }
                        Err(e) => status_banner = format!("Error: {}", terminal_text(&e.message)),
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
                    match res {
                        Ok(_) => {
                            status_banner = format!("Disabled {}.", terminal_text(&target.email));
                        }
                        Err(e) => status_banner = format!("Error: {}", terminal_text(&e.message)),
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

fn render_dashboard(
    accounts: &[crate::domain::account::AccountRecord],
    selected_id: Option<&str>,
    session_id: &crate::domain::account::SessionIdentity,
    runtime_st: &crate::domain::account::RuntimeState,
    cursor_idx: usize,
    banner: &str,
) -> CliResult<()> {
    let mut out = io::stdout();
    execute!(out, cursor::MoveTo(0, 0), Clear(ClearType::All))
        .map_err(|e| CliError::io("tui_draw_error", format!("TUI draw error: {e}")))?;

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "#",
            "Sel",
            "ID",
            "Email",
            "Plan",
            "Gemini",
            "Claude/GPT",
            "Argon",
            "State",
        ]);

    for (idx, acc) in accounts.iter().enumerate() {
        let dto = AccountViewDto::from_record(acc, selected_id == Some(acc.id.as_str()));
        let row_no = format!("{}", idx + 1);
        let pointer = match (idx == cursor_idx, dto.is_selected) {
            (true, true) => ">*",
            (true, false) => "> ",
            (false, true) => " *",
            (false, false) => "  ",
        };
        let (plan, gem_str, claude_str, argon_str) = summarize_pools(acc);
        let state_str = if dto.disabled {
            "disabled"
        } else if dto.validation_blocked {
            "verify-blocked"
        } else {
            "ok"
        };
        table.add_row(vec![
            Cell::new(row_no),
            Cell::new(pointer),
            Cell::new(terminal_text(&dto.id)),
            Cell::new(terminal_text(&dto.email)),
            Cell::new(plan),
            Cell::new(gem_str),
            Cell::new(claude_str),
            Cell::new(argon_str),
            Cell::new(state_str),
        ]);
    }

    let rendered = format!(
        "agy-switch-cli Headless SSH Dashboard\r\nSession: {} | Runtime: {}\r\n{}\r\n{}\r\n",
        format_session_identity_human(session_id),
        format_runtime_state_human(runtime_st),
        table.to_string().replace('\n', "\r\n"),
        terminal_text(banner)
    );
    out.write_all(rendered.as_bytes())
        .and_then(|_| out.flush())
        .map_err(|e| CliError::io("tui_write_error", format!("TUI write error: {e}")))
}

fn summarize_pools(
    acc: &crate::domain::account::AccountRecord,
) -> (String, String, String, String) {
    let Some(ref q) = acc.quota else {
        return ("—".into(), "—".into(), "—".into(), "—".into());
    };
    let plan = q
        .subscription_tier
        .as_deref()
        .map(terminal_text)
        .unwrap_or_else(|| "Unknown".into());

    let pool_min = |target_pool: QuotaPool| -> Option<i32> {
        let groups = q.quota_groups.as_ref()?;
        let mut min_pct: Option<i32> = None;
        for g in groups {
            for b in &g.buckets {
                if quota_pool(&b.bucket_id, &g.display_name) == Some(target_pool) {
                    let pct = observed_quota_percentage(
                        b.remaining_fraction,
                        b.remaining_fraction_known,
                    )?;
                    min_pct = Some(min_pct.map_or(pct, |old| old.min(pct)));
                }
            }
        }
        min_pct
    };

    (
        plan,
        format_pct(pool_min(QuotaPool::Gemini)),
        format_pct(pool_min(QuotaPool::ThirdParty)),
        format_pct(pool_min(QuotaPool::Argon)),
    )
}
