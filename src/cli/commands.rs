use crate::cli::args::*;
use crate::cli::dto::*;
use crate::cli::secret_input::{
    read_bounded_line, read_secret_from_tty_with_mode, read_secrets_from_private_file,
    read_secrets_from_stdin, write_interactive_prompt, MAX_SECRET_BYTES,
};
use crate::domain::account::{AccountRecord, DisableReasonCode};
use crate::domain::clock::{Clock, SystemClock};
use crate::domain::policy::{PolicyMode, PolicyStrategy};
use crate::domain::quota::{
    evaluate_account_quota, is_tier_only_placeholder, QuotaEval, QuotaObservation, QuotaSourceEnv,
    DEFAULT_QUOTA_MAX_AGE_SECS,
};
use crate::domain::token::TokenRecord;
use crate::error::{CliError, CliResult, ExitCode};
use crate::oauth::flow::{
    bind_loopback_listener, build_authorization_session, validate_callback_url_with_port,
    wait_for_loopback_callback, GOOGLE_AUTH_URL, OAUTH_FLOW_TIMEOUT,
};
use crate::oauth::refresh::{
    bootstrap_and_persist_refresh_token, complete_login_exchange_locked,
    complete_reauthorize_exchange_locked, purge_all_pending_auth_records,
    resume_pending_auth_records, OAuthEndpoints,
};
use crate::oauth::registry::OAuthClientRegistry;
use crate::paths::HeadlessPaths;
use crate::quota::official_cli::{
    refresh_active_slot_quota_via_official_cli_with_proxy, SystemOfficialCliRunner,
};
use crate::session::backend::{
    detect_dbus_session_socket_warning, read_local_active_session_token,
    resolve_credential_backend_with_config, validate_backend_choice, BackendChoice,
    CredentialBackend, FileSessionBackend, SlotInspectState,
};
use crate::session::journal::{
    diagnose_journal_replicas_with_intent, read_journal_full_readonly,
    reconcile_pending_journal_before_write, JournalDiagnosis,
};
use crate::session::payload::{resolve_session_identity, ExtractedSessionToken};
use crate::session::process::observe_runtime_state;
use crate::store::locks::{
    probe_daemon_lock_readonly, with_account_refresh_lock, DaemonInstanceLock,
};
use crate::store::repository::StoreRepository;
use crate::store::transfer::{
    export_transfer_bundle_file, import_from_legacy_dir, import_transfer_bundle_file,
};
use crate::switching::daemon::{
    build_daemon_runtime_status, format_local_ts as format_daemon_local_ts,
    read_daemon_state_readonly, repair_or_clear_daemon_state_in_tx, reset_daemon_cooldown,
    run_foreground_daemon_with_shutdown, spawn_shutdown_signal_watcher, DaemonConfigOverrides,
    DaemonPolicyOverlay, DEFAULT_DAEMON_COOLDOWN_SECS, DEFAULT_DAEMON_INTERVAL_SECS,
};
use crate::switching::executor::{
    execute_account_delete, execute_switch_with_idle_policy, format_validation_blocked_warning,
    preview_switch_dry_run, slot_matches_selected_rotated_account, SwitchOptions,
};
use crate::switching::runner::{ordered_candidate_ids, run_managed_agy};
use crate::switching::systemd::{
    install_systemd_user_service_with_reset, probe_systemd_user_service_readonly,
    uninstall_systemd_user_service, DaemonServiceInstallOptions,
};
use crate::transport::client::{HttpTransport, ReqwestTransport};
use crate::transport::proxy::{ProxyMode, SubprocessProxyOverride};
use crate::transport::user_agent::{
    probe_local_agy_for_status, probe_local_antigravity_app_for_status, LocalAgyProbeOutcome,
    LocalAntigravityAppProbeOutcome, CLI_PKG_VERSION,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

fn command_uses_backend(cmd: &Commands) -> bool {
    match cmd {
        Commands::Auth(AuthCommand::Clients) => false,
        Commands::Auth(AuthCommand::Pending(args)) => args.purge || args.resume,
        Commands::Accounts(AccountsCommand::List(args)) => {
            args.move_target.is_some() || args.order.is_some()
        }
        Commands::Accounts(AccountsCommand::Export(_)) => false,
        Commands::Quota(args) => args.refresh,
        Commands::Policy(PolicyCommand::Show | PolicyCommand::Eval) => false,
        Commands::Daemon(args) => {
            !(args.install || args.uninstall || (args.reset_cooldown && !args.once))
        }
        Commands::Stats(_) => false,
        _ => true,
    }
}

pub async fn dispatch(cli: Cli) -> CliResult<i32> {
    let paths = HeadlessPaths::resolve(cli.data_dir.as_deref())?;
    if cli.backend.is_some() || std::env::var_os("AGY_SWITCH_CLI_BACKEND").is_some() {
        validate_backend_choice(cli.backend.as_deref(), None)?;
    }
    let repo = StoreRepository::new(paths.clone());
    let mut explicit_file_backend = false;
    let backend_box: Box<dyn CredentialBackend> = if matches!(cli.command, Commands::Status) {
        let cfg_backend = repo.read_config().ok().and_then(|c| c.backend);
        resolve_credential_backend_with_config(cli.backend.as_deref(), cfg_backend.as_deref())?
    } else if command_uses_backend(&cli.command) {
        let cfg = repo.read_config()?;
        let choice = validate_backend_choice(cli.backend.as_deref(), cfg.backend.as_deref())?;
        explicit_file_backend = choice == BackendChoice::File;
        resolve_credential_backend_with_config(cli.backend.as_deref(), cfg.backend.as_deref())?
    } else if matches!(cli.command, Commands::Stats(_)) {
        match repo.read_config() {
            Ok(cfg) => {
                validate_backend_choice(cli.backend.as_deref(), cfg.backend.as_deref())?;
            }
            Err(e) if e.message.contains("Unsupported `backend` setting") => {
                return Err(CliError::data(
                    "Unsupported `backend` setting in `config.json`. Supported values: `auto`, `dual`, `file`, `keyring`.",
                ));
            }
            Err(_) => {
                validate_backend_choice(cli.backend.as_deref(), None)?;
            }
        }
        Box::new(FileSessionBackend)
    } else {
        let cfg = repo.read_config()?;
        validate_backend_choice(cli.backend.as_deref(), cfg.backend.as_deref())?;
        Box::new(FileSessionBackend)
    };
    let backend: &dyn CredentialBackend = backend_box.as_ref();
    let now_unix = crate::domain::clock::current_unix_seconds();

    match &cli.command {
        // ==================== 1. STATUS ====================
        Commands::Status => {
            handle_status(&repo, backend, cli.json).await?;
            Ok(ExitCode::Ok.as_i32())
        }

        // ==================== 2. AUTH ====================
        Commands::Auth(AuthCommand::Clients) => {
            // Strictly read-only: zero network, zero file creation
            let reg = OAuthClientRegistry::load(&paths)?;
            let clients = reg.descriptors();
            if cli.json {
                print_json(&serde_json::json!({
                    "clients": clients,
                    "warnings": reg.warnings(),
                }))?;
            } else {
                for c in &clients {
                    let active = if c.is_active { "*" } else { " " };
                    let kind = if c.is_builtin { "builtin" } else { "custom" };
                    println!(
                        "{active} {}  {} ({kind})",
                        terminal_text(&c.key),
                        terminal_text(&c.label)
                    );
                }
                for w in reg.warnings() {
                    eprintln!("warning: {}", terminal_text(w));
                }
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Auth(AuthCommand::Login(args)) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
            handle_auth_login(&repo, backend, &transport, args, cli.json, now_unix).await?;
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Auth(AuthCommand::Reauthorize(args)) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
            handle_auth_reauthorize(&repo, backend, &transport, args, cli.json, now_unix).await?;
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Auth(AuthCommand::Pending(args)) => {
            if args.purge {
                reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
                let removed = purge_all_pending_auth_records(&repo)?;
                if cli.json {
                    print_json(&serde_json::json!({ "purged_count": removed }))?;
                } else {
                    println!("Purged {removed} staged pending_auth record(s).");
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            if args.resume {
                let resume_now = SystemClock.now_unix();
                reconcile_pending_journal_before_write(&repo, backend, resume_now)?;
                let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
                let registry = OAuthClientRegistry::load(&paths)?;
                let report = resume_pending_auth_records(
                    &repo,
                    &transport,
                    &OAuthEndpoints::default(),
                    &registry,
                    SystemClock.now_unix(),
                )
                .await?;
                if let Some(unpersisted_err) = report.unpersisted_error {
                    return Err(unpersisted_err);
                }
                let selected_id = repo.read_snapshot()?.index.selected_account_id;
                let views: Vec<AccountViewDto> = report
                    .resumed_accounts
                    .iter()
                    .map(|a| AccountViewDto::from_record(a, selected_id.as_deref() == Some(&a.id)))
                    .collect();
                let fail_json: Vec<serde_json::Value> = report
                    .failures
                    .iter()
                    .map(|(pid, msg)| serde_json::json!({"pending_id": pid, "reason": msg}))
                    .collect();
                if cli.json {
                    print_json(&serde_json::json!({
                        "resumed_count": views.len(),
                        "accounts": views,
                        "failures": fail_json,
                    }))?;
                } else {
                    println!(
                        "Resumed {} pending auth record(s) ({} failed).",
                        views.len(),
                        report.failures.len()
                    );
                    for (pid, msg) in &report.failures {
                        eprintln!("  {}: {}", terminal_text(pid), terminal_text(msg));
                    }
                }
                if !report.failures.is_empty() {
                    return Ok(ExitCode::GeneralOrDataError.as_i32());
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            // Pure read-only inspection (zero tokens or secrets!)
            let records = repo.list_pending_auth_readonly()?;
            let items: Vec<serde_json::Value> = records
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "flow": r.flow,
                        "auth_seq": r.auth_seq,
                        "email_mismatch": r.email_mismatch,
                        "oauth_client_key": r.token.oauth_client_key,
                        "scopes_known": r.token.granted_scopes.is_some(),
                        "created_at": r.created_at,
                    })
                })
                .collect();
            if cli.json {
                print_json(&serde_json::json!({
                    "pending_count": items.len(),
                    "pending_auth": items,
                }))?;
            } else if items.is_empty() {
                println!("No pending_auth records.");
            } else {
                for r in &records {
                    println!(
                        "{}  flow={:?}  auth_seq={}  created_at={}",
                        terminal_text(&r.id),
                        r.flow,
                        r.auth_seq,
                        format_unix_local_minute(r.created_at)
                    );
                }
            }
            Ok(ExitCode::Ok.as_i32())
        }

        // ==================== 3. ACCOUNTS ====================
        Commands::Accounts(AccountsCommand::List(args)) => {
            if args.move_target.is_none() && args.order.is_none() {
                // Strictly read-only
                let snap = repo.read_snapshot()?;
                let selected_id = snap.index.selected_account_id.as_deref();
                let views: Vec<AccountViewDto> = snap
                    .accounts
                    .iter()
                    .map(|a| {
                        AccountViewDto::from_record_at(
                            a,
                            selected_id == Some(a.id.as_str()),
                            now_unix,
                        )
                    })
                    .collect();
                if cli.json {
                    print_json(&serde_json::json!({
                        "selected_account_id": snap.index.selected_account_id,
                        "account_order": snap.index.account_order,
                        "accounts": views,
                    }))?;
                } else {
                    print_numbered_accounts_human(&snap, now_unix);
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let snap = repo.read_snapshot()?;
            let resolved_ids = if let Some(ref move_sel) = args.move_target {
                let total = snap.accounts.len();
                if total == 0 {
                    return Err(CliError::not_found("No accounts saved to reorder."));
                }
                let pos = args.to.unwrap_or(0);
                if pos == 0 || pos > total {
                    return Err(CliError::usage(format!(
                        "`--to` position must be between 1 and {total} (got {pos})."
                    )));
                }
                let target_id = snap.select(move_sel)?.id.clone();
                let mut ids: Vec<String> = snap.accounts.iter().map(|a| a.id.clone()).collect();
                let cur_idx = ids
                    .iter()
                    .position(|id| id == &target_id)
                    .ok_or_else(|| CliError::not_found("Target account not found in order."))?;
                let moved = ids.remove(cur_idx);
                ids.insert(pos - 1, moved);
                ids
            } else if let Some(ref raw_order) = args.order {
                let mut ids = Vec::with_capacity(raw_order.len());
                for sel in raw_order {
                    ids.push(snap.select(sel)?.id.clone());
                }
                ids
            } else {
                unreachable!()
            };

            let updated = repo.with_write_lock(|tx| tx.reorder_accounts(resolved_ids, now_unix))?;
            let fresh_snap = repo.read_snapshot()?;
            let selected_id = fresh_snap.index.selected_account_id.as_deref();
            let views: Vec<AccountViewDto> = fresh_snap
                .accounts
                .iter()
                .map(|a| {
                    AccountViewDto::from_record_at(a, selected_id == Some(a.id.as_str()), now_unix)
                })
                .collect();
            if cli.json {
                print_json(&serde_json::json!({
                    "revision": updated.revision,
                    "selected_account_id": fresh_snap.index.selected_account_id,
                    "account_order": updated.account_order,
                    "accounts": views,
                }))?;
            } else {
                println!(
                    "Updated account order ({} accounts):",
                    updated.account_order.len()
                );
                print_numbered_accounts_human(&fresh_snap, now_unix);
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Accounts(AccountsCommand::Add(args)) => {
            // Validate explicit path arguments BEFORE any pre-write journal reconciliation!
            if let Some(ref file_path) = args.from_file {
                if crate::error::path_looks_like_accidental_secret(file_path) {
                    return Err(CliError::usage(
                        "`--from-file` expects a filesystem path to a private `0600` file, not a literal credential value (redacted).",
                    ));
                }
            }
            reconcile_pending_journal_before_write(&repo, backend, SystemClock.now_unix())?;

            // Option 1B: `accounts add --from-local` is strictly offline (zero network calls!)
            if args.from_local {
                let (extracted, local_source_tag) =
                    read_local_active_session_token(&paths, backend)?;
                let (saved, created) = import_local_session_offline(
                    &repo,
                    extracted,
                    args.client.as_deref(),
                    args.label.as_deref(),
                    SystemClock.now_unix(),
                )
                .await?;
                let snap = repo.read_snapshot()?;
                let is_sel = snap.index.selected_account_id.as_deref() == Some(saved.id.as_str());
                let dto = AccountViewDto::from_record(&saved, is_sel);
                if cli.json {
                    print_json(&serde_json::json!({
                        "created": created,
                        "account": dto,
                        "local_source": local_source_tag,
                    }))?;
                } else {
                    println!(
                        "{} account {} ({}) from local credential ({local_source_tag})",
                        if created { "Added" } else { "Updated" },
                        terminal_text(&dto.id),
                        terminal_text(&dto.email)
                    );
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            let token_entries: Vec<(String, Option<String>)> = if args.from_stdin {
                read_secrets_from_stdin()?
            } else if let Some(ref file_path) = args.from_file {
                read_secrets_from_private_file(file_path)?
            } else {
                let single = read_secret_from_tty_with_mode(
                    "Enter Google OAuth refresh_token (echo hidden): ",
                    cli.json,
                )?;
                vec![(single, None)]
            };

            let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
            let registry = OAuthClientRegistry::load(&paths)?;
            let endpoints = OAuthEndpoints::default();

            if token_entries.len() == 1 {
                let (secret, inline_label) = &token_entries[0];
                let effective_label = inline_label.as_deref().or(args.label.as_deref());
                reconcile_pending_journal_before_write(&repo, backend, SystemClock.now_unix())?;
                let (saved, created) = bootstrap_and_persist_refresh_token(
                    &repo,
                    &transport,
                    &endpoints,
                    &registry,
                    secret,
                    args.client.as_deref(),
                    effective_label,
                    SystemClock.now_unix(),
                )
                .await?;

                let snap = repo.read_snapshot()?;
                let is_sel = snap.index.selected_account_id.as_deref() == Some(saved.id.as_str());
                let dto = AccountViewDto::from_record(&saved, is_sel);

                if cli.json {
                    print_json(&serde_json::json!({
                        "created": created,
                        "account": dto,
                    }))?;
                } else {
                    println!(
                        "{} account {} ({})",
                        if created { "Added" } else { "Updated" },
                        terminal_text(&dto.id),
                        terminal_text(&dto.email)
                    );
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            let total = token_entries.len();
            let mut added_count = 0usize;
            let mut updated_count = 0usize;
            let mut saved_ids_and_flags: Vec<(String, bool)> = Vec::new();
            let mut failures: Vec<(usize, String)> = Vec::new();

            for (idx, (secret, inline_label)) in token_entries.iter().enumerate() {
                let effective_label = inline_label.as_deref().or(args.label.as_deref());
                reconcile_pending_journal_before_write(&repo, backend, SystemClock.now_unix())?;
                match bootstrap_and_persist_refresh_token(
                    &repo,
                    &transport,
                    &endpoints,
                    &registry,
                    secret,
                    args.client.as_deref(),
                    effective_label,
                    SystemClock.now_unix(),
                )
                .await
                {
                    Ok((saved, created)) => {
                        if created {
                            added_count += 1;
                        } else {
                            updated_count += 1;
                        }
                        if !cli.json {
                            println!(
                                "[{}/{}] {} {} ({})",
                                idx + 1,
                                total,
                                if created { "Added" } else { "Updated" },
                                terminal_text(&saved.id),
                                terminal_text(&saved.email)
                            );
                        }
                        saved_ids_and_flags.push((saved.id, created));
                    }
                    Err(err) => {
                        if err.exit_code == ExitCode::PartialCommitOrRecovery {
                            return Err(err);
                        }
                        if !cli.json {
                            eprintln!(
                                "[{}/{}] Failed: {}",
                                idx + 1,
                                total,
                                terminal_text(&err.message)
                            );
                        }
                        failures.push((idx + 1, err.message));
                    }
                }
            }

            let snap = repo.read_snapshot()?;
            let selected_id = snap.index.selected_account_id.as_deref();
            let accounts_out: Vec<AccountViewDto> = saved_ids_and_flags
                .iter()
                .filter_map(|(sid, _)| {
                    snap.accounts
                        .iter()
                        .find(|a| &a.id == sid)
                        .map(|a| AccountViewDto::from_record(a, selected_id == Some(a.id.as_str())))
                })
                .collect();

            if cli.json {
                let fail_json: Vec<serde_json::Value> = failures
                    .iter()
                    .map(|(line_no, msg)| serde_json::json!({"item": line_no, "reason": msg}))
                    .collect();
                print_json(&serde_json::json!({
                    "total": total,
                    "added_count": added_count,
                    "updated_count": updated_count,
                    "failed_count": failures.len(),
                    "accounts": accounts_out,
                    "failures": fail_json,
                }))?;
            } else {
                println!(
                    "Batch add complete: {added_count} added, {updated_count} updated, {} failed.",
                    failures.len()
                );
            }

            if !failures.is_empty() {
                return Ok(ExitCode::GeneralOrDataError.as_i32());
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Accounts(AccountsCommand::Import(args)) => {
            if args.from_legacy.is_none() && args.from_file.is_none() {
                return Err(CliError::usage(
                    "Specify either `--from-file <FILE>` or `--from-legacy [<LEGACY_DIR>]`.",
                ));
            }
            // Validate explicit path arguments BEFORE any pre-write journal reconciliation!
            if let Some(ref bundle_file) = args.from_file {
                if crate::error::path_looks_like_accidental_secret(bundle_file) {
                    return Err(CliError::usage(
                        "`--from-file` expects a filesystem path to a transfer bundle JSON file, not a literal credential value (redacted).",
                    ));
                }
            }
            if let Some(ref legacy_arg) = args.from_legacy {
                if !legacy_arg.trim().is_empty()
                    && crate::error::path_looks_like_accidental_secret(std::path::Path::new(
                        legacy_arg,
                    ))
                {
                    return Err(CliError::usage(
                        "`--from-legacy` expects a filesystem directory path, not a literal credential value (redacted).",
                    ));
                }
            }
            let import_now = SystemClock.now_unix();
            reconcile_pending_journal_before_write(&repo, backend, import_now)?;
            let report = if let Some(ref legacy_arg) = args.from_legacy {
                let legacy_dir = if legacy_arg.trim().is_empty() {
                    paths.default_legacy_dir()
                } else {
                    PathBuf::from(legacy_arg)
                };
                import_from_legacy_dir(&repo, &legacy_dir, args.overwrite, import_now).await?
            } else if let Some(ref bundle_file) = args.from_file {
                import_transfer_bundle_file(&repo, bundle_file, args.overwrite, import_now).await?
            } else {
                unreachable!()
            };

            if cli.json {
                print_json(&serde_json::json!({ "report": report }))?;
            } else {
                println!(
                    "Import complete from {}: {} imported, {} updated, {} skipped, {} failed.",
                    terminal_text(&report.source),
                    report.imported_count,
                    report.updated_count,
                    report.skipped_count,
                    report.failed_count
                );
                for f in &report.failures {
                    eprintln!(
                        "  item #{} ({}): {}",
                        f.index,
                        f.identifier.as_deref().unwrap_or("?"),
                        terminal_text(&f.reason)
                    );
                }
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Accounts(AccountsCommand::Export(args)) => {
            let Some(ref out_file) = args.output else {
                return Err(CliError::usage(
                    "`accounts export` requires `--output <FILE>` and `--include-secrets` (secrets are never printed to stdout).",
                ));
            };
            let exported_count = export_transfer_bundle_file(
                &repo,
                out_file,
                args.include_secrets,
                args.overwrite,
                &args.accounts,
            )?;
            if cli.json {
                print_json(&serde_json::json!({
                    "exported_count": exported_count,
                    "output_file": out_file,
                }))?;
            } else {
                println!(
                    "Exported {exported_count} account(s) privately (0600) to {}",
                    terminal_text(&out_file.to_string_lossy())
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Accounts(AccountsCommand::Enable { selector }) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let snap = repo.read_snapshot()?;
            let target = snap.select(selector)?;
            let updated = repo.with_write_lock(|tx| tx.mark_account_enabled(&target.id))?;
            let is_sel = snap.index.selected_account_id.as_deref() == Some(updated.id.as_str());
            let dto = AccountViewDto::from_record(&updated, is_sel);
            if cli.json {
                print_json(&serde_json::json!({ "account": dto }))?;
            } else {
                println!(
                    "Enabled account {} ({}).",
                    terminal_text(&dto.id),
                    terminal_text(&dto.email)
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Accounts(AccountsCommand::Disable { selector }) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let snap = repo.read_snapshot()?;
            let target = snap.select(selector)?;
            let updated = repo.with_write_lock(|tx| {
                tx.mark_account_disabled(&target.id, DisableReasonCode::Manual, None, now_unix)
            })?;
            let is_sel = snap.index.selected_account_id.as_deref() == Some(updated.id.as_str());
            let dto = AccountViewDto::from_record(&updated, is_sel);
            if cli.json {
                print_json(&serde_json::json!({ "account": dto }))?;
            } else {
                println!(
                    "Disabled account {} ({}).",
                    terminal_text(&dto.id),
                    terminal_text(&dto.email)
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Accounts(AccountsCommand::Delete(args)) => {
            let (target, cleared_slot) = execute_account_delete(
                &repo,
                backend,
                &args.selector,
                args.force,
                args.clear_active_slot,
                now_unix,
            )?;

            if cli.json {
                print_json(&serde_json::json!({
                    "deleted_account_id": target.id,
                    "cleared_active_slot": cleared_slot,
                }))?;
            } else {
                println!(
                    "Deleted account {} ({}){}.",
                    terminal_text(&target.id),
                    terminal_text(&target.email),
                    if cleared_slot {
                        " and cleared active slot"
                    } else {
                        ""
                    }
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }

        // ==================== 4. CURRENT / SWITCH / RUN ====================
        Commands::Current => {
            handle_current(&repo, backend, cli.json, now_unix)?;
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Switch(args) => {
            let registry = OAuthClientRegistry::load(&paths)?;
            if args.dry_run {
                let outcome = preview_switch_dry_run(
                    &repo,
                    backend,
                    &registry,
                    &args.selector,
                    args.allow_running,
                    args.require_idle,
                    now_unix,
                )?;
                if cli.json {
                    print_json(&serde_json::json!({ "switch": outcome }))?;
                } else {
                    if let Some(ref warn) = outcome.runtime_warning {
                        eprintln!("{}", terminal_text(warn));
                    }
                    if let Some(ref warn) = outcome.validation_warning {
                        eprintln!("{}", terminal_text(warn));
                    }
                    println!(
                        "[dry-run] Ready to switch active slot to {} ({}).",
                        terminal_text(&outcome.target_account_id),
                        terminal_text(&outcome.target_email)
                    );
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            // Option 1B: pure offline local credential switch (with automatic Pre-Switch Sync-Back!)
            let outcome = execute_switch_with_idle_policy(
                &repo,
                backend,
                &registry,
                &args.selector,
                &SwitchOptions {
                    dry_run: false,
                    allow_running: args.allow_running,
                },
                args.require_idle,
                now_unix,
            )?;

            if cli.json {
                print_json(&serde_json::json!({ "switch": outcome }))?;
            } else {
                if let Some(ref warn) = outcome.runtime_warning {
                    eprintln!("{}", terminal_text(warn));
                }
                if let Some(ref warn) = outcome.validation_warning {
                    eprintln!("{}", terminal_text(warn));
                }
                println!(
                    "Switched active agy credential slot to {} ({}). New `agy` invocations will use this account.",
                    terminal_text(&outcome.target_account_id),
                    terminal_text(&outcome.target_email)
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Run(args) => {
            let registry = OAuthClientRegistry::load(&paths)?;
            let code = run_managed_agy(
                &repo,
                backend,
                &registry,
                args.account.as_deref(),
                explicit_file_backend,
                &args.command,
                now_unix,
            )
            .await?;
            Ok(code)
        }

        // ==================== 5. QUOTA (READ-ONLY OR `--refresh`) & REFRESH ====================
        Commands::Quota(args) => {
            let mut effective_now = now_unix;
            let mut refreshed_active_id: Option<String> = None;
            let mut refreshed_validation_blocked = false;
            if args.refresh {
                let cfg = repo.read_config()?;
                let _ = SubprocessProxyOverride::resolve(cli.proxy.as_deref(), Some(&cfg.network))?;
                reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
                let outcome = refresh_active_slot_quota_via_official_cli_with_proxy(
                    &repo,
                    backend,
                    explicit_file_backend,
                    cli.proxy.clone(),
                    None,
                    now_unix,
                )
                .await?;
                refreshed_active_id = Some(outcome.account.id);
                refreshed_validation_blocked = outcome.validation_blocked;
                effective_now = SystemClock.now_unix();
            }

            // Read snapshot (strictly zero network & zero disk writes when `args.refresh == false`)
            let snap = repo.read_snapshot()?;
            let policy = repo.read_policy()?;
            let monitored_model = policy.monitored_model.as_str();
            if args.all {
                let items: Vec<serde_json::Value> = snap
                    .accounts
                    .iter()
                    .map(|acc| {
                        let eval = evaluate_account_quota(
                            acc,
                            monitored_model,
                            effective_now,
                            DEFAULT_QUOTA_MAX_AGE_SECS,
                        );
                        serde_json::json!({
                            "id": acc.id,
                            "email": acc.email,
                            "monitored_model": monitored_model,
                            "evaluation": eval,
                            "quota": acc.quota.as_ref().filter(|q| !is_tier_only_placeholder(q)).map(QuotaViewDto::from_observation),
                        })
                    })
                    .collect();
                if cli.json {
                    print_json(&serde_json::json!({
                        "monitored_model": monitored_model,
                        "accounts": items,
                    }))?;
                } else if snap.accounts.is_empty() {
                    println!("No accounts saved.");
                } else {
                    for (idx, acc) in snap.accounts.iter().enumerate() {
                        if idx > 0 {
                            println!();
                        }
                        let eval = evaluate_account_quota(
                            acc,
                            monitored_model,
                            effective_now,
                            DEFAULT_QUOTA_MAX_AGE_SECS,
                        );
                        match acc.quota.as_ref().filter(|q| !is_tier_only_placeholder(q)) {
                            Some(q) => println!(
                                "{}",
                                QuotaViewDto::from_observation(q).human_multiline_at(
                                    &acc.email,
                                    Some((&eval, monitored_model)),
                                    effective_now,
                                )
                            ),
                            None => println!(
                                "{}: Status: {} — no cached quota.",
                                terminal_text(&acc.email),
                                format_quota_eval_human(&eval, monitored_model)
                            ),
                        }
                    }
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            let target = if let Some(ref active_id) = refreshed_active_id {
                snap.select(active_id)?
            } else {
                match args.selector.as_deref() {
                    Some(sel) => snap.select(sel)?,
                    None => snap.selected_account().ok_or_else(|| {
                        CliError::not_found(
                            "No selected account recorded. Pass `<ID|EMAIL>` or `--all`.",
                        )
                    })?,
                }
            };

            let eval = evaluate_account_quota(
                target,
                monitored_model,
                effective_now,
                DEFAULT_QUOTA_MAX_AGE_SECS,
            );
            let Some(q_obs) = target
                .quota
                .as_ref()
                .filter(|q| !is_tier_only_placeholder(q))
            else {
                return Err(CliError::quota_unavailable(
                    "no_cached_quota",
                    format!(
                        "Account '{}' ({}) has no cached quota. Switch to it and run `agy-switch-cli quota --refresh` first.",
                        target.id, target.email
                    ),
                ));
            };
            let q_dto = QuotaViewDto::from_observation(q_obs);

            // In `--json` mode (or when quota is `Unknown` / `Unavailable`), enforce strict exit code 4.
            // In interactive human mode, if cached quota is merely `Stale` (> 1 hour old), still render
            // the cached quota table cleanly with an inline `--refresh` hint instead of hiding it behind an error!
            let is_human_stale_viewable = !cli.json && matches!(eval, QuotaEval::Stale { .. });
            if !matches!(eval, QuotaEval::Known { .. }) && !is_human_stale_viewable {
                let eval_is_validation_blocked = matches!(
                    eval,
                    QuotaEval::Unavailable { ref reason } if reason == "validation_blocked"
                );
                let message = if eval_is_validation_blocked {
                    format!(
                        "Quota unavailable for '{}' ({}): {}",
                        target.id,
                        target.email,
                        format_validation_blocked_warning(&target.id)
                    )
                } else if args.refresh && refreshed_validation_blocked {
                    format!(
                        "Refreshed quota for '{}' ({}) on model '{}' is {:?}. {}",
                        target.id,
                        target.email,
                        monitored_model,
                        eval,
                        format_validation_blocked_warning(&target.id)
                    )
                } else if args.refresh {
                    format!(
                        "Refreshed quota for '{}' ({}) on model '{}' is {:?}.",
                        target.id, target.email, monitored_model, eval
                    )
                } else {
                    format!(
                        "Cached quota for '{}' ({}) on model '{}' is {:?}. Switch to it and run `agy-switch-cli quota --refresh` for fresh observation.",
                        target.id, target.email, monitored_model, eval
                    )
                };
                return Err(
                    CliError::quota_unavailable("quota_stale_or_unknown", message).with_details(
                        serde_json::json!({
                            "account_id": target.id,
                            "email": target.email,
                            "monitored_model": monitored_model,
                            "evaluation": eval,
                            "quota": q_dto,
                        }),
                    ),
                );
            }

            if cli.json {
                print_json(&serde_json::json!({
                    "account_id": target.id,
                    "email": target.email,
                    "monitored_model": monitored_model,
                    "evaluation": eval,
                    "quota": q_dto,
                }))?;
            } else {
                println!(
                    "{}",
                    q_dto.human_multiline_at(
                        &target.email,
                        Some((&eval, monitored_model)),
                        effective_now,
                    )
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Refresh(args) => {
            let cfg = repo.read_config()?;
            let _ = SubprocessProxyOverride::resolve(cli.proxy.as_deref(), Some(&cfg.network))?;
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let expected_id = if let Some(ref sel) = args.selector {
                let snap = repo.read_snapshot()?;
                let target_id = snap.select(sel)?.id.clone();
                let slot_state = backend.inspect_slot(&paths);
                let session_id = resolve_session_identity(&slot_state, &snap);
                let resolved_active_id = match &session_id {
                    crate::domain::account::SessionIdentity::Matched { account_id, .. }
                    | crate::domain::account::SessionIdentity::DriftedKnown {
                        account_id, ..
                    } => Some(account_id.as_str()),
                    crate::domain::account::SessionIdentity::DriftedExternal { .. } => {
                        match (&slot_state, snap.selected_account()) {
                            (SlotInspectState::Present(parsed), Some(sel_acc))
                                if slot_matches_selected_rotated_account(
                                    &repo, &snap, parsed, sel_acc,
                                ) =>
                            {
                                Some(sel_acc.id.as_str())
                            }
                            _ => None,
                        }
                    }
                    crate::domain::account::SessionIdentity::Uninitialized => {
                        snap.index.selected_account_id.as_deref()
                    }
                    _ => None,
                };
                if let Some(active_id) = resolved_active_id {
                    if active_id != target_id {
                        return Err(CliError::usage(format!(
                            "Account '{target_id}' is not the currently active official `agy` account (active: '{active_id}'). Switch to it first with `agy-switch-cli switch {target_id}`, then run `agy-switch-cli refresh`."
                        )));
                    }
                }
                Some(target_id)
            } else {
                None
            };
            let outcome = refresh_active_slot_quota_via_official_cli_with_proxy(
                &repo,
                backend,
                explicit_file_backend,
                cli.proxy.clone(),
                expected_id.as_deref(),
                now_unix,
            )
            .await?;
            let snap = repo.read_snapshot()?;
            let is_sel =
                snap.index.selected_account_id.as_deref() == Some(outcome.account.id.as_str());
            let dto = AccountViewDto::from_record(&outcome.account, is_sel);

            if cli.json {
                print_json(&serde_json::json!({
                    "refreshed": [dto],
                    "failures": [],
                }))?;
            } else {
                println!(
                    "Refreshed {} ({})",
                    terminal_text(&dto.id),
                    terminal_text(&dto.email)
                );
                if outcome.validation_blocked {
                    eprintln!(
                        "{}",
                        terminal_text(&format_validation_blocked_warning(&dto.id))
                    );
                }
            }
            Ok(ExitCode::Ok.as_i32())
        }

        // ==================== 6. POLICY & DAEMON ====================
        Commands::Policy(PolicyCommand::Show) => {
            // Strictly read-only
            let policy = repo.read_policy()?;
            if cli.json {
                print_json(&serde_json::json!({ "policy": policy }))?;
            } else {
                let snap_opt = repo.read_snapshot().ok();
                println!(
                    "Auto-switch : {}",
                    if policy.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                println!("Mode        : {:?}", policy.mode);
                println!("Strategy    : {:?}", policy.strategy);
                println!(
                    "Thresholds  : reserve {}%  /  candidate minimum {}%",
                    policy.reserve_percentage, policy.candidate_min_percentage
                );
                println!("Model scope : {}", terminal_text(&policy.monitored_model));
                if policy.candidate_account_ids.is_empty() {
                    println!("Candidates  : (none configured)");
                } else {
                    println!(
                        "Candidates  : {} configured",
                        policy.candidate_account_ids.len()
                    );
                    for (idx, cid) in policy.candidate_account_ids.iter().enumerate() {
                        let email_label = snap_opt
                            .as_ref()
                            .and_then(|s| s.accounts.iter().find(|a| &a.id == cid))
                            .map(|a| {
                                format!("{}  ({})", terminal_text(&a.email), terminal_text(cid))
                            })
                            .unwrap_or_else(|| terminal_text(cid));
                        println!("  {}. {}", idx + 1, email_label);
                    }
                }
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Policy(PolicyCommand::Set(args)) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let snap = repo.read_snapshot()?;
            let mut policy = repo.read_policy()?;
            let prev_rev = policy.revision;

            if let Some(en) = args.enabled {
                policy.enabled = en;
            }
            if let Some(st) = args.strategy {
                policy.strategy = match st {
                    CliStrategy::Priority => PolicyStrategy::Priority,
                    CliStrategy::RoundRobin => PolicyStrategy::RoundRobin,
                };
            }
            if let Some(m) = args.mode {
                policy.mode = match m {
                    CliMode::Immediate => PolicyMode::Immediate,
                    CliMode::Wait => PolicyMode::Wait,
                };
            }
            if let Some(r) = args.reserve {
                policy.reserve_percentage = r;
            }
            if let Some(min) = args.minimum {
                policy.candidate_min_percentage = min;
            }
            if let Some(ref model) = args.model {
                policy.monitored_model = model.clone();
            }
            if args.clear_candidates {
                policy.candidate_account_ids.clear();
            } else if args.all_candidates {
                let all_enabled: Vec<String> = snap
                    .accounts
                    .iter()
                    .filter(|a| !a.disabled)
                    .map(|a| a.id.clone())
                    .collect();
                if all_enabled.is_empty() {
                    return Err(CliError::usage(
                        "No enabled accounts available for `--all-candidates`.",
                    ));
                }
                policy.candidate_account_ids = all_enabled;
            } else if let Some(ref raw_cands) = args.candidates {
                let mut resolved = Vec::with_capacity(raw_cands.len());
                for sel in raw_cands {
                    resolved.push(snap.select(sel)?.id.clone());
                }
                policy.candidate_account_ids = resolved;
            }

            let mut daemon_pause_err: Option<CliError> = None;
            let saved = repo.with_write_lock(|tx| {
                let out = tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
                if let Err(err) = repair_or_clear_daemon_state_in_tx(tx.paths(), now_unix) {
                    daemon_pause_err = Some(err);
                }
                Ok(out)
            })?;
            if let Some(pause_err) = daemon_pause_err {
                return Err(CliError::partial_commit(
                    "daemon_pause_clear_failed",
                    format!(
                        "Saved policy (revision {}), but failed to durably clear daemon failure pause in `daemon_state.json` ({}). Daemon remains paused.",
                        saved.revision, pause_err.message
                    ),
                ));
            }

            if cli.json {
                print_json(&serde_json::json!({ "policy": saved }))?;
            } else {
                println!(
                    "Saved policy (revision {}, {} candidate(s)).",
                    saved.revision,
                    saved.candidate_account_ids.len()
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Policy(PolicyCommand::Order { selectors }) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let snap = repo.read_snapshot()?;
            let mut policy = repo.read_policy()?;
            let prev_rev = policy.revision;

            let mut resolved = Vec::with_capacity(selectors.len());
            for sel in selectors {
                resolved.push(snap.select(sel)?.id.clone());
            }

            if resolved.len() != policy.candidate_account_ids.len() {
                return Err(CliError::usage(format!(
                    "`policy order` requires every configured candidate account exactly once (expected {}, got {}).",
                    policy.candidate_account_ids.len(),
                    resolved.len()
                )));
            }
            let existing: HashSet<&str> = policy
                .candidate_account_ids
                .iter()
                .map(String::as_str)
                .collect();
            let mut seen = HashSet::new();
            for id in &resolved {
                if !existing.contains(id.as_str()) {
                    return Err(CliError::usage(format!(
                        "Account '{id}' is not in the current policy candidate list."
                    )));
                }
                if !seen.insert(id.as_str()) {
                    return Err(CliError::usage(format!(
                        "Duplicate candidate '{id}' in `policy order`."
                    )));
                }
            }
            policy.candidate_account_ids = resolved;
            let mut daemon_pause_err: Option<CliError> = None;
            let saved = repo.with_write_lock(|tx| {
                let out = tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
                if let Err(err) = repair_or_clear_daemon_state_in_tx(tx.paths(), now_unix) {
                    daemon_pause_err = Some(err);
                }
                Ok(out)
            })?;
            if let Some(pause_err) = daemon_pause_err {
                return Err(CliError::partial_commit(
                    "daemon_pause_clear_failed",
                    format!(
                        "Saved policy (revision {}), but failed to durably clear daemon failure pause in `daemon_state.json` ({}). Daemon remains paused.",
                        saved.revision, pause_err.message
                    ),
                ));
            }
            if cli.json {
                print_json(&serde_json::json!({ "policy": saved }))?;
            } else {
                println!(
                    "Updated policy candidate order (revision {}).",
                    saved.revision
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Policy(PolicyCommand::Eval) => {
            // Strictly read-only dry-run evaluation
            let snap = repo.read_snapshot()?;
            let policy = repo.read_policy()?;
            let dstate = read_daemon_state_readonly(&paths)?;

            let source_acc = snap.selected_account();
            let source_eval = source_acc.map(|acc| {
                evaluate_account_quota(
                    acc,
                    &policy.monitored_model,
                    now_unix,
                    DEFAULT_QUOTA_MAX_AGE_SECS,
                )
            });

            let src_id_str = source_acc.map(|a| a.id.as_str()).unwrap_or("");
            let ordered = ordered_candidate_ids(
                &policy.candidate_account_ids,
                src_id_str,
                policy.strategy,
                dstate.last_rotated_candidate_id.as_deref(),
            );

            let mut cand_dtos = Vec::new();
            let mut first_qualified: Option<String> = None;

            for cid in ordered {
                if let Some(cacc) = snap.accounts.iter().find(|a| a.id == cid) {
                    let ceval = evaluate_account_quota(
                        cacc,
                        &policy.monitored_model,
                        now_unix,
                        DEFAULT_QUOTA_MAX_AGE_SECS,
                    );
                    let qualified = matches!(
                        ceval,
                        QuotaEval::Known { remaining_percentage } if remaining_percentage >= policy.candidate_min_percentage as f64
                    );
                    if qualified && first_qualified.is_none() {
                        first_qualified = Some(cacc.id.clone());
                    }
                    cand_dtos.push(PolicyEvalCandidateDto {
                        id: cacc.id.clone(),
                        email: cacc.email.clone(),
                        evaluation: ceval,
                        qualified,
                    });
                }
            }

            let (would_switch, recommended_target_id, decision_reason) =
                match (&source_eval, &first_qualified) {
                    (None, _) => (false, None, "no_selected_account".into()),
                    (
                        Some(QuotaEval::Known {
                            remaining_percentage,
                        }),
                        _,
                    ) if *remaining_percentage > policy.reserve_percentage as f64 => {
                        (false, None, "source_quota_above_reserve".into())
                    }
                    (Some(QuotaEval::Known { .. }), Some(tid)) => {
                        if !policy.enabled {
                            (
                                false,
                                Some(tid.clone()),
                                "policy_disabled_would_select_candidate".into(),
                            )
                        } else {
                            (
                                true,
                                Some(tid.clone()),
                                "source_below_reserve_and_candidate_qualified".into(),
                            )
                        }
                    }
                    (Some(QuotaEval::Known { .. }), None) => (
                        false,
                        None,
                        "source_below_reserve_but_no_qualified_candidate".into(),
                    ),
                    (Some(QuotaEval::Stale { reason }), _) => {
                        (false, None, format!("hold_source_stale:{reason}"))
                    }
                    (Some(QuotaEval::Unknown { reason }), _) => {
                        (false, None, format!("hold_source_unknown:{reason}"))
                    }
                    (Some(QuotaEval::Unavailable { reason }), _) => {
                        (false, None, format!("hold_source_unavailable:{reason}"))
                    }
                };

            let eval_view = PolicyEvalViewDto {
                policy,
                source_account_id: source_acc.map(|a| a.id.clone()),
                source_evaluation: source_eval,
                would_switch,
                recommended_target_id,
                decision_reason,
                candidates: cand_dtos,
            };

            if cli.json {
                print_json(&serde_json::json!({ "evaluation": eval_view }))?;
            } else {
                println!(
                    "Policy eval: would_switch={} target={:?} reason={}",
                    eval_view.would_switch,
                    eval_view.recommended_target_id,
                    terminal_text(&eval_view.decision_reason)
                );
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Daemon(args) => {
            let has_temp_policy_flags = args.mode.is_some()
                || args.strategy.is_some()
                || args.reserve.is_some()
                || args.minimum.is_some()
                || args.model.is_some();
            if args.install {
                if has_temp_policy_flags {
                    return Err(CliError::usage(
                        "Policy flags (`--mode`, `--strategy`, `--reserve`, `--minimum`, `--model`) are single-run in-memory overrides; persist them with `agy-switch-cli policy set ...` first, then run `agy-switch-cli daemon --install`.",
                    ));
                }
                if cli.proxy.is_some() {
                    return Err(CliError::usage(
                        "`--proxy` is a single-run override and is not written into the systemd unit file. Persist `network.proxy_url` in `config.json` (0600) first, then run `agy-switch-cli daemon --install`.",
                    ));
                }
                let has_env_backend = std::env::var_os("AGY_SWITCH_CLI_BACKEND").is_some();
                let explicit_backend = if cli.backend.is_some() || has_env_backend {
                    Some(validate_backend_choice(cli.backend.as_deref(), None)?)
                } else {
                    None
                };
                let outcome = install_systemd_user_service_with_reset(
                    &paths,
                    &DaemonServiceInstallOptions {
                        explicit_interval_secs: args.interval,
                        explicit_cooldown_secs: args.cooldown,
                        explicit_backend,
                        explicit_no_notify: args.no_notify,
                    },
                    args.reset_cooldown,
                )
                .await?;
                if cli.json {
                    print_json(&outcome)?;
                } else {
                    if outcome.enabled_and_started {
                        println!(
                            "Installed and started user service `{}`.",
                            outcome.service_name
                        );
                    } else {
                        println!(
                            "Installed and enabled user service `{}` (currently `{}`; inspect progress with `agy-switch-cli status` or `journalctl --user -u {}`).",
                            outcome.service_name,
                            outcome.active_state,
                            outcome.service_name
                        );
                    }
                    println!(
                        "  Unit file : {}",
                        terminal_text(&outcome.unit_path.to_string_lossy())
                    );
                    println!("  ExecStart : {}", terminal_text(&outcome.exec_start));
                    if outcome.cooldown_reset == Some(true) {
                        if outcome.cooldown_was_active == Some(true) {
                            let prev = outcome.previous_cooldown_until.unwrap_or(0);
                            println!(
                                "  Cooldown  : cleared (was active until {})",
                                format_daemon_local_ts(prev)
                            );
                        } else {
                            println!("  Cooldown  : cleared (no active cooldown)");
                        }
                    }
                    println!(
                        "  Status    : systemctl --user status {}",
                        outcome.service_name
                    );
                    println!(
                        "  Logs      : journalctl --user -u {} -f",
                        outcome.service_name
                    );
                    println!(
                        "  SSH note  : Run `{}` on remote servers so the user service stays running after SSH logout.",
                        outcome.linger_hint
                    );
                }
                return Ok(ExitCode::Ok.as_i32());
            }
            if args.uninstall {
                if has_temp_policy_flags
                    || cli.proxy.is_some()
                    || args.no_notify
                    || args.reset_cooldown
                {
                    return Err(CliError::usage(
                        "Policy, `--proxy`, `--no-notify`, or `--reset-cooldown` flags cannot be combined with `daemon --uninstall`.",
                    ));
                }
                let outcome = uninstall_systemd_user_service(&paths).await?;
                if cli.json {
                    print_json(&outcome)?;
                } else if outcome.removed_unit_file {
                    println!(
                        "Removed user service `{}` ({}).",
                        outcome.service_name,
                        terminal_text(&outcome.unit_path.to_string_lossy())
                    );
                } else {
                    println!(
                        "User service `{}` is already uninstalled ({} not present).",
                        outcome.service_name,
                        terminal_text(&outcome.unit_path.to_string_lossy())
                    );
                }
                return Ok(ExitCode::Ok.as_i32());
            }
            if args.reset_cooldown && !args.once {
                let has_explicit_interval = args.interval.is_some() && !args.interval_from_env;
                let has_explicit_cooldown = args.cooldown.is_some() && !args.cooldown_from_env;
                if has_temp_policy_flags
                    || has_explicit_interval
                    || has_explicit_cooldown
                    || args.no_notify
                    || cli.proxy.is_some()
                {
                    return Err(CliError::usage(
                        "Standalone `daemon --reset-cooldown` only clears the persisted cooldown and cannot be combined with runtime override flags (`--interval`, `--cooldown`, `--no-notify`, `--mode`, `--strategy`, `--reserve`, `--minimum`, `--model`, `--proxy`). Add `--once` to run a single tick immediately or `--install` to update the systemd service.",
                    ));
                }
                let outcome = reset_daemon_cooldown(&repo, now_unix)?;
                if cli.json {
                    print_json(&outcome)?;
                } else if outcome.cooldown_was_active {
                    println!(
                        "Cleared active daemon cooldown (was active until {}).",
                        format_daemon_local_ts(outcome.previous_cooldown_until)
                    );
                } else {
                    println!("No active daemon cooldown to clear.");
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            let interval_secs = args.interval.unwrap_or(DEFAULT_DAEMON_INTERVAL_SECS);
            let cooldown_secs = args.cooldown.unwrap_or(DEFAULT_DAEMON_COOLDOWN_SECS);
            if interval_secs == 0 {
                return Err(CliError::usage("`--interval` must be at least 1 second."));
            }
            if cooldown_secs < 0 {
                return Err(CliError::usage("`--cooldown` must be >= 0 seconds."));
            }

            let shutdown_rx = spawn_shutdown_signal_watcher();
            let registry = OAuthClientRegistry::load(&paths)?;
            let policy_overlay = DaemonPolicyOverlay {
                mode: args.mode.map(|m| match m {
                    CliMode::Immediate => PolicyMode::Immediate,
                    CliMode::Wait => PolicyMode::Wait,
                }),
                strategy: args.strategy.map(|s| match s {
                    CliStrategy::Priority => PolicyStrategy::Priority,
                    CliStrategy::RoundRobin => PolicyStrategy::RoundRobin,
                }),
                reserve_percentage: args.reserve,
                candidate_min_percentage: args.minimum,
                monitored_model: args.model.clone(),
            };
            let notify_override = if args.no_notify {
                Some(false)
            } else {
                crate::switching::notify::parse_notify_env_override()?
            };
            let cfg = repo.read_config()?;
            let _ = SubprocessProxyOverride::resolve(cli.proxy.as_deref(), Some(&cfg.network))?;
            let _ =
                crate::switching::daemon::resolve_effective_daemon_policy(&repo, &policy_overlay)?;
            let daemon_lock = DaemonInstanceLock::try_acquire(&paths)?;
            let runner = SystemOfficialCliRunner::with_proxy(cli.proxy.clone());

            run_foreground_daemon_with_shutdown(
                daemon_lock,
                &repo,
                backend,
                &runner,
                &registry,
                DaemonConfigOverrides {
                    interval_secs,
                    cooldown_secs,
                    explicit_file_backend,
                    once: args.once,
                    reset_cooldown: args.reset_cooldown,
                    json_mode: cli.json,
                    notify_override,
                    policy_overlay,
                    ..DaemonConfigOverrides::default()
                },
                shutdown_rx,
            )
            .await?;
            Ok(ExitCode::Ok.as_i32())
        }

        // ==================== 7. READ-ONLY LOCAL STATS ====================
        Commands::Stats(sub) => {
            #[cfg(feature = "stats")]
            {
                match sub {
                    StatsCommand::Summary(args) => {
                        if let Some(interval_secs) = args.watch {
                            if cli.json {
                                return Err(CliError::usage(
                                    "`stats --watch` is an interactive terminal view and cannot be combined with `--json`.",
                                ));
                            }
                            crate::stats::watch::run_stats_watch(
                                &paths,
                                args,
                                crate::stats::watch::StatsWatchView::Summary,
                                interval_secs,
                            )
                            .await?;
                        } else {
                            let view = crate::stats::collect_token_stats(&paths, args)?;
                            if cli.json {
                                print_json(&view)?;
                            } else {
                                println!("{}", view.render_human());
                            }
                        }
                    }
                    StatsCommand::List(args) => {
                        if let Some(interval_secs) = args.watch {
                            if cli.json {
                                return Err(CliError::usage(
                                    "`stats --watch` is an interactive terminal view and cannot be combined with `--json`.",
                                ));
                            }
                            crate::stats::watch::run_stats_watch(
                                &paths,
                                args,
                                crate::stats::watch::StatsWatchView::List,
                                interval_secs,
                            )
                            .await?;
                        } else {
                            let view = crate::stats::collect_token_stats_list(&paths, args)?;
                            if cli.json {
                                print_json(&view)?;
                            } else {
                                println!("{}", view.render_human());
                            }
                        }
                    }
                }
                Ok(ExitCode::Ok.as_i32())
            }
            #[cfg(not(feature = "stats"))]
            {
                let _ = sub;
                Err(CliError::usage(
                    "This `agy-switch-cli` binary was compiled with `--no-default-features` (without `stats`). Rebuild with `--features stats` to inspect local SQLite token usage.",
                ))
            }
        }

        // ==================== 8. OPTIONAL TUI ====================
        Commands::Tui => {
            if cli.json {
                return Err(CliError::usage(
                    "`tui` is an interactive terminal dashboard and cannot be combined with `--json`.",
                ));
            }
            #[cfg(feature = "tui")]
            {
                let cfg = repo.read_config()?;
                let _ = SubprocessProxyOverride::resolve(cli.proxy.as_deref(), Some(&cfg.network))?;
                crate::tui::run_interactive_tui(
                    &repo,
                    backend,
                    explicit_file_backend,
                    cli.proxy.clone(),
                )
                .await?;
                Ok(ExitCode::Ok.as_i32())
            }
            #[cfg(not(feature = "tui"))]
            {
                Err(CliError::usage(
                    "This `agy-switch-cli` binary was compiled with `--no-default-features` (without `tui`). Rebuild with `--features tui` or use subcommands directly.",
                ))
            }
        }
    }
}

fn print_numbered_accounts_human(snap: &crate::store::repository::StoreSnapshot, now_unix: i64) {
    if snap.accounts.is_empty() {
        println!("No accounts saved.");
        return;
    }
    let selected_id = snap.index.selected_account_id.as_deref();
    let email_w = snap
        .accounts
        .iter()
        .map(|a| terminal_text(&a.email).chars().count())
        .max()
        .unwrap_or(10);
    for (idx, acc) in snap.accounts.iter().enumerate() {
        let mark = if selected_id == Some(acc.id.as_str()) {
            "*"
        } else {
            " "
        };
        let plan = acc
            .quota
            .as_ref()
            .and_then(|q| q.subscription_tier.as_deref())
            .map(|p| format!("  [{}]", terminal_text(p)))
            .unwrap_or_default();
        let label = acc
            .custom_label
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|l| format!("  ({})", terminal_text(l)))
            .unwrap_or_default();
        let status_flag = if acc.disabled {
            match acc.disabled_code {
                Some(DisableReasonCode::RevokedOrExpiredGrant) => "  [disabled: reauth required]",
                Some(DisableReasonCode::ScopeReauthRequired) => "  [disabled: scope update needed]",
                _ => "  [disabled]",
            }
        } else if acc.is_validation_blocked_at(now_unix) {
            "  [verification required]"
        } else {
            ""
        };
        let email_clean = terminal_text(&acc.email);
        let pad = " ".repeat(email_w.saturating_sub(email_clean.chars().count()));
        println!(
            "{:>2}. {mark} {email_clean}{pad}{plan}{label}{status_flag}  ({})",
            idx + 1,
            terminal_text(&acc.id)
        );
    }
}

/// Purely offline local credential import (`accounts add --from-local`, Option 1B).
/// Reads full local credential payload (`id_token` JWT email or `agy 1.5+` compact `id_token_email`
/// plus optional `user_tier`), coordinates under `L2 -> L3`, refuses to roll back superseded
/// historical refresh tokens, and preserves any existing cached quota on account updates.
async fn import_local_session_offline(
    repo: &StoreRepository,
    extracted: ExtractedSessionToken,
    explicit_client_key: Option<&str>,
    custom_label: Option<&str>,
    now_unix: i64,
) -> CliResult<(AccountRecord, bool)> {
    let email = extracted.email_hint.clone().ok_or_else(|| {
        CliError::data(
            "Local agy credential does not contain an email address (`id_token` JWT email claim or `id_token_email`). Launch `agy` once to refresh its local session metadata, or add the account via `agy-switch-cli auth login`.",
        )
    })?;

    let explicit_bound_key = match explicit_client_key {
        Some(key) => Some(
            OAuthClientRegistry::load(repo.paths())?
                .select_for_login(Some(key))?
                .key,
        ),
        None => None,
    };

    let clean_label = custom_label
        .map(|s| {
            terminal_text(s)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty());

    let expiry_timestamp = extracted.expiry_unix.filter(|&ts| ts > 0).unwrap_or(1);
    let expires_in = if expiry_timestamp > now_unix {
        expiry_timestamp.saturating_sub(now_unix).max(60)
    } else {
        0
    };
    let token = TokenRecord {
        access_token: extracted.access_token.unwrap_or_default(),
        refresh_token: extracted.refresh_token,
        expires_in,
        expiry_timestamp,
        token_type: "Bearer".into(),
        id_token: extracted.id_token,
        oauth_client_key: explicit_bound_key.clone(),
        granted_scopes: None,
        project_id: None,
        is_gcp_tos: true,
    };
    let user_tier = extracted.user_tier;

    let build_new_record = |tok: TokenRecord, lbl: Option<String>, tier: Option<String>| {
        let mut rec = AccountRecord::new(
            format!("acc-{}", Uuid::new_v4().simple()),
            email.clone(),
            tok,
            now_unix,
        );
        rec.custom_label = lbl;
        if let Some(t) = tier {
            let mut placeholder = QuotaObservation::new(0, QuotaSourceEnv::OfficialCli);
            placeholder.subscription_tier = Some(t);
            placeholder.tier_source_env = Some(QuotaSourceEnv::OfficialCli);
            rec.quota = Some(placeholder);
        }
        rec
    };

    let merge_into_existing_in_tx = |tx: &crate::store::repository::StoreWriteTx<'_>,
                                     existing_id: &str,
                                     tok: &TokenRecord,
                                     lbl: Option<&str>,
                                     tier: Option<&str>|
     -> CliResult<AccountRecord> {
        let mut latest = tx.load_account_opt(existing_id)?.ok_or_else(|| {
            CliError::not_found(format!(
                "Account '{existing_id}' disappeared during import."
            ))
        })?;
        if tx
            .account_has_superseded_rt_in_tx(&latest, &tok.refresh_token)?
            .0
        {
            return Err(CliError::conflict(
                "stale_rotated_refresh_token",
                format!(
                    "Refusing to import a previously superseded (rotated-away) refresh_token for account '{}'.",
                    latest.id
                ),
            ));
        }
        let rt_changed = latest.token.refresh_token.trim() != tok.refresh_token.trim();
        let keep_existing_fresher_access = !rt_changed
            && !latest.token.access_token.trim().is_empty()
            && (tok.access_token.trim().is_empty()
                || tok.expiry_timestamp <= 1
                || latest.token.expiry_timestamp > tok.expiry_timestamp);
        let merged_token = TokenRecord {
            access_token: if keep_existing_fresher_access {
                latest.token.access_token.clone()
            } else {
                tok.access_token.clone()
            },
            refresh_token: tok.refresh_token.clone(),
            expires_in: if keep_existing_fresher_access {
                latest.token.expires_in
            } else {
                tok.expires_in
            },
            expiry_timestamp: if keep_existing_fresher_access {
                latest.token.expiry_timestamp
            } else {
                tok.expiry_timestamp
            },
            token_type: if latest.token.token_type.trim().is_empty() {
                "Bearer".into()
            } else {
                latest.token.token_type.clone()
            },
            id_token: tok
                .id_token
                .clone()
                .or_else(|| latest.token.id_token.clone()),
            oauth_client_key: tok
                .oauth_client_key
                .clone()
                .or_else(|| latest.token.oauth_client_key.clone()),
            granted_scopes: latest.token.granted_scopes.clone(),
            project_id: latest.token.project_id.clone(),
            is_gcp_tos: latest.token.is_gcp_tos || tok.is_gcp_tos,
        };
        latest.record_token_transition(merged_token);
        if rt_changed {
            let next_seq = tx.allocate_next_auth_seq()?;
            latest.auth_generation = latest.auth_generation.saturating_add(1).max(next_seq);
        }
        if let Some(l) = lbl {
            latest.custom_label = Some(l.to_string());
        }
        latest.apply_official_cli_user_tier(tier);
        if latest.disabled
            && matches!(
                latest.disabled_code,
                Some(DisableReasonCode::RevokedOrExpiredGrant)
            )
        {
            latest.disabled = false;
            latest.disabled_code = None;
            latest.disabled_detail = None;
            latest.disabled_at = None;
        }
        tx.save_account(&latest)?;
        Ok(latest)
    };

    let mut candidate_eid = repo.find_matching_account_id_for_import_readonly(
        None,
        &token.refresh_token,
        &email,
        token.oauth_client_key.as_deref(),
    )?;

    for _ in 0..4 {
        if let Some(eid) = candidate_eid.take() {
            let tok_c = token.clone();
            let lbl_c = clean_label.clone();
            let tier_c = user_tier.clone();
            let merged_opt =
                with_account_refresh_lock(repo.paths(), &eid, Duration::from_secs(20), || async {
                    repo.with_write_lock(|tx| {
                        if tx.load_account_opt(&eid)?.is_none() {
                            return Ok(None);
                        }
                        merge_into_existing_in_tx(
                            tx,
                            &eid,
                            &tok_c,
                            lbl_c.as_deref(),
                            tier_c.as_deref(),
                        )
                        .map(Some)
                    })
                })
                .await?;
            if let Some(saved) = merged_opt {
                return Ok((saved, false));
            }
        }

        enum FastPath {
            Created(Box<(AccountRecord, bool)>),
            RetryUnderL2(String),
        }

        let res = repo.with_write_lock(|tx| {
            let index = tx.load_index_or_init(now_unix)?;
            for existing_id in &index.account_order {
                if let Some(acc) = tx.load_account_opt(existing_id)? {
                    let same_rt = acc.token.refresh_token.trim() == token.refresh_token.trim()
                        || tx
                            .account_has_superseded_rt_in_tx(&acc, &token.refresh_token)?
                            .0;
                    let same_email = acc.email.eq_ignore_ascii_case(&email)
                        && (acc.token.oauth_client_key == token.oauth_client_key
                            || acc.token.oauth_client_key.is_none()
                            || token.oauth_client_key.is_none());
                    if same_rt || same_email {
                        return Ok(FastPath::RetryUnderL2(acc.id));
                    }
                }
            }
            let record = build_new_record(token.clone(), clean_label.clone(), user_tier.clone());
            let (saved, created) = tx.upsert_account(record, true, now_unix)?;
            Ok(FastPath::Created(Box::new((saved, created))))
        })?;

        match res {
            FastPath::Created(pair) => return Ok(*pair),
            FastPath::RetryUnderL2(eid) => {
                candidate_eid = Some(eid);
            }
        }
    }

    Err(CliError::conflict(
        "concurrent_account_churn",
        "Account store changed repeatedly during offline local import; retry `accounts add --from-local`.",
    ))
}

fn build_network_transport(
    repo: &StoreRepository,
    cli_proxy: Option<&str>,
    json_mode: bool,
) -> CliResult<ReqwestTransport> {
    let cfg = repo.read_config()?;
    let (proxy_mode, warnings) =
        ProxyMode::resolve_with_config_and_warnings(cli_proxy, Some(&cfg.network))?;
    if !json_mode {
        for w in &warnings {
            eprintln!("warning: {}", terminal_text(w));
        }
    }
    ReqwestTransport::build(proxy_mode)
}

pub fn print_json<T: Serialize>(payload: &T) -> CliResult<()> {
    let envelope = JsonSuccessEnvelope::new(payload);
    let rendered = serde_json::to_string_pretty(&envelope)
        .map_err(|e| CliError::data(format!("JSON serialization error: {e}")))?;
    println!("{rendered}");
    Ok(())
}

struct CurrentDiagnosticView {
    view: StatusViewDto,
    journal_diag: JournalDiagnosis,
    supported_models: Option<Vec<String>>,
    group_descriptions: Vec<(String, String)>,
    has_model_source_acc: bool,
}

fn collect_current_view(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    now_unix: i64,
) -> CliResult<CurrentDiagnosticView> {
    let paths = repo.paths();
    let snap = repo.read_snapshot()?;
    let replica_state = backend.inspect_replicas(paths);
    let slot_state = replica_state.effective_slot_state();
    let session_identity = resolve_session_identity(slot_state, &snap);
    let runtime_state = observe_runtime_state(paths);
    let journal_full = read_journal_full_readonly(paths)?;
    let journal_diag = diagnose_journal_replicas_with_intent(
        journal_full.as_ref().map(|(j, _, _)| j),
        journal_full.as_ref().and_then(|(_, m, _)| m.as_ref()),
        journal_full.as_ref().is_some_and(|(_, _, c)| *c),
        &replica_state,
    );

    let model_source_acc = match &session_identity {
        crate::domain::account::SessionIdentity::Matched { account_id, .. }
        | crate::domain::account::SessionIdentity::DriftedKnown { account_id, .. } => snap
            .accounts
            .iter()
            .find(|a| &a.id == account_id)
            .or_else(|| snap.selected_account()),
        _ => snap.selected_account(),
    };
    let effective_quota = model_source_acc
        .and_then(|a| a.quota.as_ref())
        .filter(|q| !is_tier_only_placeholder(q));
    let supported_models = effective_quota.map(extract_supported_models);
    let group_descriptions = effective_quota
        .map(extract_quota_group_descriptions)
        .unwrap_or_default();
    let has_model_source_acc = model_source_acc.is_some();

    let view = StatusViewDto {
        selected_account: snap
            .selected_account()
            .map(|acc| SelectedAccountBriefDto::from_record_at(acc, now_unix)),
        session_identity,
        runtime_state,
    };

    Ok(CurrentDiagnosticView {
        view,
        journal_diag,
        supported_models,
        group_descriptions,
        has_model_source_acc,
    })
}

fn handle_current(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    json_mode: bool,
    now_unix: i64,
) -> CliResult<()> {
    let current = collect_current_view(repo, backend, now_unix)?;
    if json_mode {
        print_json(&serde_json::json!({
            "selected_account": current.view.selected_account,
            "session_identity": current.view.session_identity,
            "runtime_state": current.view.runtime_state,
            "journal_status": current.journal_diag,
            "supported_models": current.supported_models,
        }))?;
    } else {
        match &current.view.selected_account {
            Some(sel) => {
                let plan_part = sel
                    .subscription_tier
                    .as_deref()
                    .map(|t| format!("  [{}]", terminal_text(t)))
                    .unwrap_or_default();
                let label_part = sel
                    .custom_label
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|l| format!("  ({})", terminal_text(l)))
                    .unwrap_or_default();
                let flag_part = if sel.disabled {
                    "  [disabled]"
                } else if sel.validation_blocked {
                    "  [verification required]"
                } else {
                    ""
                };
                println!(
                    "Selected account : {}{}{}{}  ({})",
                    terminal_text(&sel.email),
                    plan_part,
                    label_part,
                    flag_part,
                    terminal_text(&sel.id)
                );
            }
            None => println!("Selected account : none"),
        }
        println!(
            "Active agy slot  : {}",
            format_session_identity_human(&current.view.session_identity)
        );
        println!(
            "Live agy runtime : {}",
            format_runtime_state_human(&current.view.runtime_state)
        );
        if current.journal_diag != JournalDiagnosis::Clean {
            println!("Pending journal  : {:?}", current.journal_diag);
        }
        if current.has_model_source_acc {
            for line in format_supported_models_or_groups_human(
                current.supported_models.as_deref(),
                &current.group_descriptions,
            ) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

async fn handle_status(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    json_mode: bool,
) -> CliResult<()> {
    let paths = repo.paths();
    let snap_res = repo.read_snapshot();
    let policy_res = repo.read_policy();
    let pending_auth_res = repo.list_pending_auth_readonly();
    let pending_auth_count = pending_auth_res.as_ref().map(|v| v.len()).unwrap_or(0);
    let mut pending_auth_warnings: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(paths.pending_auth_dir()) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".json") && !n.contains(".tmp."))
            {
                if let Ok(m) = fs::symlink_metadata(&p) {
                    let mode = m.permissions().mode() & 0o777;
                    if (mode & 0o077) != 0 {
                        pending_auth_warnings.push(format!(
                            "Pending auth file '{}' has insecure permissions ({mode:04o}); tighten with `chmod 600`.",
                            p.display()
                        ));
                    }
                }
            }
        }
    }
    if let Ok(m) = fs::symlink_metadata(paths.auth_sequence_file()) {
        if m.file_type().is_file() {
            let mode = m.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                pending_auth_warnings.push(format!(
                    "Auth sequence file '{}' has insecure permissions ({mode:04o}); tighten with `chmod 600`.",
                    paths.auth_sequence_file().display()
                ));
            }
        }
    }
    let cfg_res = repo.read_config_with_warnings();
    let lineage_res = repo.validate_all_token_lineage_readonly();
    let replica_state = backend.inspect_replicas(paths);
    let slot_state = replica_state.effective_slot_state();
    let journal_diag = match read_journal_full_readonly(paths) {
        Ok(journal_full) => diagnose_journal_replicas_with_intent(
            journal_full.as_ref().map(|(j, _, _)| j),
            journal_full.as_ref().and_then(|(_, m, _)| m.as_ref()),
            journal_full.as_ref().is_some_and(|(_, _, c)| *c),
            &replica_state,
        ),
        Err(err) if err.exit_code == ExitCode::PartialCommitOrRecovery => {
            JournalDiagnosis::RecoveryIncomplete {
                target_account_id: String::new(),
                reason: err.message,
            }
        }
        Err(err) => return Err(err),
    };
    let dbus_warning = (!backend.uses_keyring())
        .then(detect_dbus_session_socket_warning)
        .flatten();
    let now_unix = SystemClock.now_unix();
    let dstate_res = read_daemon_state_readonly(paths);
    let daemon_lock_probe = probe_daemon_lock_readonly(paths);
    let daemon_systemd_probe = probe_systemd_user_service_readonly(paths).await;
    let daemon_runtime = build_daemon_runtime_status(
        daemon_lock_probe,
        &daemon_systemd_probe,
        dstate_res.as_ref().ok(),
        now_unix,
    );
    let agy_probe = probe_local_agy_for_status().await;
    let app_probe = probe_local_antigravity_app_for_status();

    let agy_json = match &agy_probe {
        LocalAgyProbeOutcome::Detected {
            executable,
            version,
        } => serde_json::json!({
            "checked": true,
            "found": true,
            "executable": executable.to_string_lossy().into_owned(),
            "version": version,
        }),
        LocalAgyProbeOutcome::NotFound => serde_json::json!({
            "checked": true,
            "found": false,
            "error": "Official `agy` executable not found in PATH.",
        }),
        LocalAgyProbeOutcome::Failed { executable, error } => serde_json::json!({
            "checked": true,
            "found": true,
            "executable": executable.to_string_lossy().into_owned(),
            "error": error,
        }),
    };

    let app_json = match &app_probe {
        LocalAntigravityAppProbeOutcome::Detected { path, version } => serde_json::json!({
            "checked": true,
            "found": true,
            "path": path.to_string_lossy().into_owned(),
            "version": version,
        }),
        LocalAntigravityAppProbeOutcome::NotFound => serde_json::json!({
            "checked": true,
            "found": false,
        }),
    };

    let store_ok = snap_res.is_ok();
    let slot_initialized = !matches!(slot_state, SlotInspectState::Uninitialized);
    let slot_corrupt = matches!(slot_state, SlotInspectState::Corrupt(_))
        || (replica_state.uses_file && matches!(replica_state.file, SlotInspectState::Corrupt(_)));

    let config_warnings = cfg_res
        .as_ref()
        .ok()
        .map(|(_, w)| w.clone())
        .unwrap_or_default();

    let dangling_policy_candidates: Vec<String> = match (&snap_res, &policy_res) {
        (Ok(snap), Ok(pol)) => {
            let known: HashSet<&str> = snap
                .index
                .account_order
                .iter()
                .map(String::as_str)
                .collect();
            pol.candidate_account_ids
                .iter()
                .filter(|cid| !known.contains(cid.as_str()))
                .cloned()
                .collect()
        }
        _ => Vec::new(),
    };

    let report = serde_json::json!({
        "cli_version": CLI_PKG_VERSION,
        "backend": backend.name(),
        "store_ok": store_ok,
        "store_error": snap_res.as_ref().err().map(|e| &e.message),
        "policy_ok": policy_res.is_ok() && dangling_policy_candidates.is_empty(),
        "policy_dangling_candidates": dangling_policy_candidates,
        "pending_auth_ok": pending_auth_res.is_ok() && pending_auth_warnings.is_empty(),
        "pending_auth_count": pending_auth_count,
        "pending_auth_error": pending_auth_res.as_ref().err().map(|e| &e.message),
        "pending_auth_warnings": pending_auth_warnings,
        "config_ok": cfg_res.is_ok(),
        "config_error": cfg_res.as_ref().err().map(|e| &e.message),
        "config_warnings": config_warnings,
        "token_lineage_ok": lineage_res.is_ok(),
        "token_lineage_error": lineage_res.as_ref().err().map(|e| &e.message),
        "journal_status": journal_diag,
        "slot_initialized": slot_initialized,
        "slot_corrupt": slot_corrupt,
        "daemon_state_ok": dstate_res.is_ok(),
        "daemon_state_error": dstate_res.as_ref().err().map(|e| &e.message),
        "daemon_paused_on_failure": dstate_res.as_ref().ok().map(|d| d.paused_on_failure),
        "daemon_runtime": daemon_runtime,
        "dbus_keyring_warning": dbus_warning,
        "agy_probe": agy_json,
        "antigravity_app_probe": app_json,
    });

    if matches!(
        journal_diag,
        JournalDiagnosis::CommittedIndexPending { .. }
            | JournalDiagnosis::RecoveryIncomplete { .. }
    ) {
        return Err(CliError::partial_commit(
            "pending_journal_reconciliation",
            format!(
                "Switch journal requires reconciliation ({journal_diag:?}). Run `agy-switch-cli switch <ID|EMAIL>` to reconcile."
            ),
        )
        .with_details(report));
    }

    if let Err(store_err) = snap_res {
        return Err(store_err.with_details(report));
    }

    if let Err(pol_err) = policy_res {
        return Err(pol_err.with_details(report));
    }

    if !dangling_policy_candidates.is_empty() {
        return Err(CliError::data(format!(
            "Policy references non-existent candidate account ID(s): {:?}. Update candidates via `agy-switch-cli policy set`.",
            dangling_policy_candidates
        ))
        .with_details(report));
    }

    if let Err(cfg_err) = cfg_res {
        return Err(cfg_err.with_details(report));
    }

    if let Err(pa_err) = pending_auth_res {
        return Err(pa_err.with_details(report));
    }

    if let Err(lin_err) = lineage_res {
        return Err(lin_err.with_details(report));
    }

    if let Err(ds_err) = dstate_res {
        return Err(ds_err.with_details(report));
    }

    if let SlotInspectState::Corrupt(detail) = slot_state {
        return Err(
            CliError::data(format!("Active agy credential slot is corrupt: {detail}"))
                .with_details(report),
        );
    }

    if replica_state.uses_file {
        if let SlotInspectState::Corrupt(ref detail) = replica_state.file {
            return Err(CliError::data(format!(
                "Active agy credential file replica is corrupt: {detail}"
            ))
            .with_details(report));
        }
    }

    if let LocalAgyProbeOutcome::Failed { ref error, .. } = agy_probe {
        return Err(CliError::env_not_ready("agy_probe_failed", error.clone()).with_details(report));
    }

    if json_mode {
        print_json(&report)?;
    } else {
        println!("agy-switch-cli status (v{CLI_PKG_VERSION})");
        println!("  Backend:           {}", backend.name());
        println!("  Store status:      OK");
        println!("  Journal status:    {:?}", journal_diag);
        println!("  Slot initialized:  {}", slot_initialized);
        if let Ok(ref ds) = dstate_res {
            println!(
                "  Daemon state:      {}",
                daemon_runtime.format_human(Some(ds))
            );
        }
        match &agy_probe {
            LocalAgyProbeOutcome::Detected {
                executable,
                version,
            } => {
                println!(
                    "  Antigravity CLI:   {} v{}",
                    terminal_text(&executable.to_string_lossy()),
                    terminal_text(version)
                );
            }
            LocalAgyProbeOutcome::NotFound => {
                println!("  Antigravity CLI:   not found in PATH");
            }
            LocalAgyProbeOutcome::Failed { .. } => unreachable!(),
        }
        if let LocalAntigravityAppProbeOutcome::Detected { path, version } = &app_probe {
            println!(
                "  Antigravity App:   {} v{}",
                terminal_text(&path.to_string_lossy()),
                terminal_text(version)
            );
        }
        for cw in &config_warnings {
            println!("  Config warning:    {}", terminal_text(cw));
        }
        for pw in &pending_auth_warnings {
            println!("  Security warning:  {}", terminal_text(pw));
        }
        if let Some(ref w) = dbus_warning {
            println!("  D-Bus note:        {}", terminal_text(w));
        }
    }

    Ok(())
}

async fn handle_auth_login(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    args: &AuthLoginArgs,
    json_mode: bool,
    now_unix: i64,
) -> CliResult<()> {
    reconcile_pending_journal_before_write(repo, backend, now_unix)?;
    let registry = OAuthClientRegistry::load(repo.paths())?;
    let client = registry.select_for_login(args.client.as_deref())?;

    let manual_mode = !args.ssh;
    let (session, code) = execute_interactive_oauth_code_flow(
        client,
        args.port,
        manual_mode,
        args.open_browser,
        json_mode,
    )
    .await?;

    let exchange_now = SystemClock.now_unix();
    reconcile_pending_journal_before_write(repo, backend, exchange_now)?;
    let endpoints = OAuthEndpoints::default();
    let (saved, created) = complete_login_exchange_locked(
        repo,
        transport,
        &endpoints,
        &registry,
        &session,
        &code,
        args.label.as_deref(),
        exchange_now,
    )
    .await?;

    let snap = repo.read_snapshot()?;
    let is_sel = snap.index.selected_account_id.as_deref() == Some(saved.id.as_str());
    let dto = AccountViewDto::from_record(&saved, is_sel);

    if json_mode {
        print_json(&serde_json::json!({
            "created": created,
            "account": dto,
        }))?;
    } else {
        println!(
            "Authorized account {} ({}) via client '{}'.",
            terminal_text(&dto.id),
            terminal_text(&dto.email),
            terminal_text(dto.oauth_client_key.as_deref().unwrap_or("default"))
        );
    }
    Ok(())
}

async fn handle_auth_reauthorize(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    transport: &dyn HttpTransport,
    args: &AuthReauthorizeArgs,
    json_mode: bool,
    now_unix: i64,
) -> CliResult<()> {
    reconcile_pending_journal_before_write(repo, backend, now_unix)?;
    let snap = repo.read_snapshot()?;
    let existing = snap.select(&args.selector)?.clone();

    let registry = OAuthClientRegistry::load(repo.paths())?;
    let preferred_key = args
        .client
        .as_deref()
        .or(existing.token.oauth_client_key.as_deref());
    let client = registry.select_for_login(preferred_key)?;

    let manual_mode = !args.ssh;
    let (session, code) = execute_interactive_oauth_code_flow(
        client,
        args.port,
        manual_mode,
        args.open_browser,
        json_mode,
    )
    .await?;

    let exchange_now = SystemClock.now_unix();
    let endpoints = OAuthEndpoints::default();
    reconcile_pending_journal_before_write(repo, backend, exchange_now)?;
    let updated = complete_reauthorize_exchange_locked(
        repo,
        transport,
        &endpoints,
        &registry,
        &existing,
        &session,
        &code,
        exchange_now,
    )
    .await?;

    let post_snap = repo.read_snapshot()?;
    let is_sel = post_snap.index.selected_account_id.as_deref() == Some(updated.id.as_str());
    let dto = AccountViewDto::from_record(&updated, is_sel);

    if json_mode {
        print_json(&serde_json::json!({ "account": dto }))?;
    } else {
        println!(
            "Reauthorized account {} ({}).",
            terminal_text(&dto.id),
            terminal_text(&dto.email)
        );
    }
    Ok(())
}

async fn execute_interactive_oauth_code_flow(
    client: crate::oauth::registry::OAuthClientConfig,
    requested_port: Option<u16>,
    manual: bool,
    open_browser: bool,
    json_mode: bool,
) -> CliResult<(crate::oauth::flow::PreparedAuthSession, String)> {
    if manual {
        let port = requested_port.unwrap_or(54545);
        let session = build_authorization_session(client, port, GOOGLE_AUTH_URL)?;
        write_interactive_prompt(
            json_mode,
            &format!(
                "Open the following URL in your local browser to authenticate:\n\n  {}\n\n",
                session.auth_url
            ),
        );
        if open_browser {
            let _ = std::process::Command::new("xdg-open")
                .arg(&session.auth_url)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
        write_interactive_prompt(
            json_mode,
            &format!(
                "After approving consent, your browser will redirect to `http://127.0.0.1:{port}/oauth-callback?code=...&state=...`.\nPaste the FULL callback URL from the browser address bar: "
            ),
        );

        let pasted = read_bounded_line(io::stdin().lock(), MAX_SECRET_BYTES, "Callback URL")?;
        let code = validate_callback_url_with_port(&pasted, &session.state, Some(port))?;
        return Ok((session, code));
    }

    let (listener, port) = bind_loopback_listener(requested_port).await?;
    let session = build_authorization_session(client, port, GOOGLE_AUTH_URL)?;

    write_interactive_prompt(
        json_mode,
        &format!(
            "Listening for OAuth callback on 127.0.0.1:{port} (timeout: 5m)...\nIf connected over SSH, forward the callback port from your local workstation:\n  ssh -L {port}:127.0.0.1:{port} <user>@<server>\n\nThen open this authorization URL in your browser:\n  {}\n\n",
            session.auth_url
        ),
    );

    if open_browser {
        let _ = std::process::Command::new("xdg-open")
            .arg(&session.auth_url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }

    let code = wait_for_loopback_callback(listener, &session.state, OAUTH_FLOW_TIMEOUT).await?;
    Ok((session, code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::account::{AccountRecord, SessionIdentity};
    use crate::domain::token::TokenRecord;

    fn make_fresh_acc(id: &str, email: &str, now: i64) -> AccountRecord {
        let tok = TokenRecord {
            access_token: format!("ya29.{id}"),
            refresh_token: format!("1//rt-{id}"),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: Some(vec![
                "openid".into(),
                "https://www.googleapis.com/auth/cloud-platform".into(),
            ]),
            project_id: Some("proj-synth".into()),
            is_gcp_tos: true,
        };
        AccountRecord::new(id.into(), email.into(), tok, now)
    }

    #[tokio::test]
    async fn synthetic_a01_readonly_diagnostics_probe_replicas_once_and_preserve_precedence() {
        use crate::session::backend::BackendReplicaInspection;
        use crate::session::payload::{parse_session_payload_bytes, serialize_session_payload};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingBackend {
            backend_name: &'static str,
            uses_keyring_flag: bool,
            uses_file_flag: bool,
            keyring_state: Option<SlotInspectState>,
            inspect_slot_calls: AtomicUsize,
            inspect_replicas_calls: AtomicUsize,
            file_probe_calls: AtomicUsize,
        }

        impl CountingBackend {
            fn file_mode() -> Self {
                Self {
                    backend_name: "file",
                    uses_keyring_flag: false,
                    uses_file_flag: true,
                    keyring_state: None,
                    inspect_slot_calls: AtomicUsize::new(0),
                    inspect_replicas_calls: AtomicUsize::new(0),
                    file_probe_calls: AtomicUsize::new(0),
                }
            }

            fn dual(kr: SlotInspectState) -> Self {
                Self {
                    backend_name: "dual",
                    uses_keyring_flag: true,
                    uses_file_flag: true,
                    keyring_state: Some(kr),
                    inspect_slot_calls: AtomicUsize::new(0),
                    inspect_replicas_calls: AtomicUsize::new(0),
                    file_probe_calls: AtomicUsize::new(0),
                }
            }

            fn keyring_only(kr: SlotInspectState) -> Self {
                Self {
                    backend_name: "keyring",
                    uses_keyring_flag: true,
                    uses_file_flag: false,
                    keyring_state: Some(kr),
                    inspect_slot_calls: AtomicUsize::new(0),
                    inspect_replicas_calls: AtomicUsize::new(0),
                    file_probe_calls: AtomicUsize::new(0),
                }
            }

            fn reset_counts(&self) {
                self.inspect_slot_calls.store(0, Ordering::SeqCst);
                self.inspect_replicas_calls.store(0, Ordering::SeqCst);
                self.file_probe_calls.store(0, Ordering::SeqCst);
            }

            fn counts(&self) -> (usize, usize, usize) {
                (
                    self.inspect_slot_calls.load(Ordering::SeqCst),
                    self.inspect_replicas_calls.load(Ordering::SeqCst),
                    self.file_probe_calls.load(Ordering::SeqCst),
                )
            }
        }

        impl CredentialBackend for CountingBackend {
            fn name(&self) -> &'static str {
                self.backend_name
            }

            fn uses_keyring(&self) -> bool {
                self.uses_keyring_flag
            }

            fn uses_file(&self) -> bool {
                self.uses_file_flag
            }

            fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
                self.inspect_slot_calls.fetch_add(1, Ordering::SeqCst);
                if self.uses_keyring_flag {
                    if let Some(ref kr) = self.keyring_state {
                        if !self.uses_file_flag {
                            return kr.clone();
                        }
                        match kr {
                            SlotInspectState::AbsentInInitializedDir
                            | SlotInspectState::Uninitialized => {
                                self.file_probe_calls.fetch_add(1, Ordering::SeqCst);
                                return FileSessionBackend.inspect_slot(paths);
                            }
                            other => return other.clone(),
                        }
                    }
                }
                self.file_probe_calls.fetch_add(1, Ordering::SeqCst);
                FileSessionBackend.inspect_slot(paths)
            }

            fn inspect_replicas(&self, paths: &HeadlessPaths) -> BackendReplicaInspection {
                self.inspect_replicas_calls.fetch_add(1, Ordering::SeqCst);
                let file = if self.uses_file_flag {
                    self.file_probe_calls.fetch_add(1, Ordering::SeqCst);
                    FileSessionBackend.inspect_slot(paths)
                } else {
                    SlotInspectState::AbsentInInitializedDir
                };
                BackendReplicaInspection {
                    backend_name: self.backend_name,
                    uses_keyring: self.uses_keyring_flag,
                    uses_file: self.uses_file_flag,
                    keyring: self.keyring_state.clone(),
                    keyring_all_collections_uniform: true,
                    keyring_collections: Vec::new(),
                    file,
                }
            }

            fn snapshot_before_write(&self, _paths: &HeadlessPaths) -> CliResult<Option<Vec<u8>>> {
                Err(CliError::data("Unexpected write probe in read-only test"))
            }

            fn write_slot(&self, _paths: &HeadlessPaths, _payload: &str) -> CliResult<()> {
                Err(CliError::data("Unexpected write_slot in read-only test"))
            }

            fn remove_slot(&self, _paths: &HeadlessPaths) -> CliResult<()> {
                Err(CliError::data("Unexpected remove_slot in read-only test"))
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let repo = StoreRepository::new(paths.clone());
        let now = 1_900_000_000i64;
        let acc1 = make_fresh_acc("acc-0001", "alice@example.com", now);
        let acc2 = make_fresh_acc("acc-0002", "bob@example.com", now);
        let acc1_payload = serialize_session_payload(&acc1.token).unwrap();
        let acc1_parsed = parse_session_payload_bytes(acc1_payload.as_bytes()).unwrap();
        let acc2_payload = serialize_session_payload(&acc2.token).unwrap();
        let acc2_parsed = parse_session_payload_bytes(acc2_payload.as_bytes()).unwrap();

        repo.with_write_lock(|tx| {
            tx.upsert_account(acc1.clone(), true, now)?;
            tx.upsert_account(acc2.clone(), false, now)?;
            Ok(())
        })
        .unwrap();

        let registry = OAuthClientRegistry::load(&paths).unwrap();

        // 1. `file` backend before slot dir exists: single probe per command and strictly zero slot dir creation.
        assert!(!paths.active_slot_dir.exists());
        let file_backend = CountingBackend::file_mode();

        let view = collect_current_view(&repo, &file_backend, now).unwrap();
        assert_eq!(file_backend.counts(), (0, 1, 1));
        assert!(matches!(
            view.view.session_identity,
            SessionIdentity::Uninitialized
        ));
        file_backend.reset_counts();

        handle_current(&repo, &file_backend, true, now).unwrap();
        assert_eq!(file_backend.counts(), (0, 1, 1));
        file_backend.reset_counts();

        handle_status(&repo, &file_backend, true).await.unwrap();
        assert_eq!(file_backend.counts(), (0, 1, 1));
        file_backend.reset_counts();

        let uninit_dry_err = preview_switch_dry_run(
            &repo,
            &file_backend,
            &registry,
            "acc-0002",
            true,
            false,
            now,
        )
        .unwrap_err();
        assert_eq!(uninit_dry_err.error_code, "agy_uninitialized");
        assert_eq!(file_backend.counts(), (0, 1, 1));
        assert!(
            !paths.active_slot_dir.exists(),
            "Read-only diagnostics must not create active_slot_dir"
        );

        // Materialize valid `active_slot_file` for `acc-0001`.
        fs::create_dir_all(&paths.active_slot_dir).unwrap();
        fs::write(&paths.active_slot_file, &acc1_payload).unwrap();
        file_backend.reset_counts();

        let view_ok = collect_current_view(&repo, &file_backend, now).unwrap();
        assert_eq!(file_backend.counts(), (0, 1, 1));
        assert!(matches!(
            view_ok.view.session_identity,
            SessionIdentity::Matched { ref account_id, .. } if account_id == "acc-0001"
        ));
        file_backend.reset_counts();

        handle_status(&repo, &file_backend, true).await.unwrap();
        assert_eq!(file_backend.counts(), (0, 1, 1));
        file_backend.reset_counts();

        let dry_ok = preview_switch_dry_run(
            &repo,
            &file_backend,
            &registry,
            "acc-0002",
            true,
            false,
            now,
        )
        .unwrap();
        assert!(dry_ok.dry_run);
        assert_eq!(dry_ok.target_account_id, "acc-0002");
        assert!(!dry_ok.validation_blocked);
        assert_eq!(file_backend.counts(), (0, 1, 1));

        // 2. `dual` backend:
        // (a) Cleanly absent keyring falls back to file replica (`acc-0001`).
        let dual_absent = CountingBackend::dual(SlotInspectState::AbsentInInitializedDir);
        let view_dual_fb = collect_current_view(&repo, &dual_absent, now).unwrap();
        assert_eq!(dual_absent.counts(), (0, 1, 1));
        assert!(matches!(
            view_dual_fb.view.session_identity,
            SessionIdentity::Matched { ref account_id, .. } if account_id == "acc-0001"
        ));
        dual_absent.reset_counts();
        let dry_dual_fb =
            preview_switch_dry_run(&repo, &dual_absent, &registry, "acc-0002", true, false, now)
                .unwrap();
        assert!(dry_dual_fb.dry_run);
        assert_eq!(dual_absent.counts(), (0, 1, 1));

        // (b) Corrupt keyring is NEVER masked by valid file replica.
        let dual_kr_corrupt = CountingBackend::dual(SlotInspectState::Corrupt("kr-corrupt".into()));
        let view_kr_bad = collect_current_view(&repo, &dual_kr_corrupt, now).unwrap();
        assert_eq!(dual_kr_corrupt.counts(), (0, 1, 1));
        assert!(matches!(
            view_kr_bad.view.session_identity,
            SessionIdentity::Corrupt { ref detail } if detail == "kr-corrupt"
        ));
        dual_kr_corrupt.reset_counts();
        let st_kr_bad = handle_status(&repo, &dual_kr_corrupt, true)
            .await
            .unwrap_err();
        assert_eq!(st_kr_bad.exit_code, ExitCode::GeneralOrDataError);
        assert_eq!(st_kr_bad.details.as_ref().unwrap()["slot_corrupt"], true);
        assert_eq!(dual_kr_corrupt.counts(), (0, 1, 1));
        dual_kr_corrupt.reset_counts();
        let dry_kr_bad = preview_switch_dry_run(
            &repo,
            &dual_kr_corrupt,
            &registry,
            "acc-0002",
            true,
            false,
            now,
        )
        .unwrap_err();
        assert_eq!(dry_kr_bad.exit_code, ExitCode::GeneralOrDataError);
        assert_eq!(dual_kr_corrupt.counts(), (0, 1, 1));

        // (c) Unverified keyring fails `switch --dry-run` with `secret_service_unavailable` and shows `Unverified` in `current`.
        let dual_kr_unv = CountingBackend::dual(SlotInspectState::Unverified("kr-locked".into()));
        let view_kr_unv = collect_current_view(&repo, &dual_kr_unv, now).unwrap();
        assert_eq!(dual_kr_unv.counts(), (0, 1, 1));
        assert!(matches!(
            view_kr_unv.view.session_identity,
            SessionIdentity::Unverified { ref detail } if detail == "kr-locked"
        ));
        dual_kr_unv.reset_counts();
        let dry_kr_unv =
            preview_switch_dry_run(&repo, &dual_kr_unv, &registry, "acc-0002", true, false, now)
                .unwrap_err();
        assert_eq!(dry_kr_unv.error_code, "secret_service_unavailable");
        assert_eq!(dual_kr_unv.counts(), (0, 1, 1));

        // (d) Valid keyring (`acc-0002`) + corrupt disk file: `status` & `switch --dry-run` still report corrupt disk!
        fs::write(&paths.active_slot_file, b"{corrupt-disk-replica").unwrap();
        let dual_disk_bad = CountingBackend::dual(SlotInspectState::Present(acc2_parsed.clone()));
        let view_disk_bad = collect_current_view(&repo, &dual_disk_bad, now).unwrap();
        assert_eq!(dual_disk_bad.counts(), (0, 1, 1));
        assert!(matches!(
            view_disk_bad.view.session_identity,
            SessionIdentity::DriftedKnown { ref account_id, .. } if account_id == "acc-0002"
        ));
        dual_disk_bad.reset_counts();
        let st_disk_bad = handle_status(&repo, &dual_disk_bad, true)
            .await
            .unwrap_err();
        assert_eq!(st_disk_bad.exit_code, ExitCode::GeneralOrDataError);
        assert_eq!(st_disk_bad.details.as_ref().unwrap()["slot_corrupt"], true);
        assert_eq!(dual_disk_bad.counts(), (0, 1, 1));
        dual_disk_bad.reset_counts();
        let dry_disk_bad = preview_switch_dry_run(
            &repo,
            &dual_disk_bad,
            &registry,
            "acc-0002",
            true,
            false,
            now,
        )
        .unwrap_err();
        assert_eq!(dry_disk_bad.exit_code, ExitCode::GeneralOrDataError);
        assert_eq!(dual_disk_bad.counts(), (0, 1, 1));

        // 3. `keyring` backend: zero disk probes even when disk file is corrupt (`status`, `current`, `switch --dry-run` all succeed).
        let kr_present = CountingBackend::keyring_only(SlotInspectState::Present(acc1_parsed));
        let view_kr_only = collect_current_view(&repo, &kr_present, now).unwrap();
        assert_eq!(kr_present.counts(), (0, 1, 0));
        assert!(matches!(
            view_kr_only.view.session_identity,
            SessionIdentity::Matched { ref account_id, .. } if account_id == "acc-0001"
        ));
        kr_present.reset_counts();
        handle_current(&repo, &kr_present, true, now).unwrap();
        assert_eq!(kr_present.counts(), (0, 1, 0));
        kr_present.reset_counts();
        handle_status(&repo, &kr_present, true).await.unwrap();
        assert_eq!(kr_present.counts(), (0, 1, 0));
        kr_present.reset_counts();
        let dry_kr_only =
            preview_switch_dry_run(&repo, &kr_present, &registry, "acc-0002", true, false, now)
                .unwrap();
        assert!(dry_kr_only.dry_run);
        assert_eq!(kr_present.counts(), (0, 1, 0));

        // Keyring absent with valid file on disk MUST NOT fall back to file and makes zero disk probes.
        fs::write(&paths.active_slot_file, &acc1_payload).unwrap();
        let kr_absent = CountingBackend::keyring_only(SlotInspectState::AbsentInInitializedDir);
        let view_kr_absent = collect_current_view(&repo, &kr_absent, now).unwrap();
        assert_eq!(kr_absent.counts(), (0, 1, 0));
        assert!(matches!(
            view_kr_absent.view.session_identity,
            SessionIdentity::Uninitialized
        ));
        kr_absent.reset_counts();
        handle_status(&repo, &kr_absent, true).await.unwrap();
        assert_eq!(kr_absent.counts(), (0, 1, 0));
    }

    #[tokio::test]
    async fn synthetic_v127_offline_from_local_import_extracts_email_tier_and_guards_lineage() {
        use crate::domain::quota::{QuotaBucket, QuotaGroup};
        use crate::session::payload::extract_session_token_from_bytes;

        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let repo = StoreRepository::new(paths.clone());
        let now = 1_900_000_000i64;

        // 1. Compact `agy 1.5+` payload (`id_token_email` + `user_tier`, no `id_token` JWT) imports purely offline!
        let compact_bytes = serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.local-v1",
                "token_type": "Bearer",
                "refresh_token": "1//rt-local-v1",
                "expiry": "2099-01-01T00:00:00Z"
            },
            "auth_method": "consumer",
            "id_token_email": "alice@example.com",
            "user_tier": "PRO"
        }))
        .unwrap();
        let ex1 = extract_session_token_from_bytes(&compact_bytes, "local").unwrap();
        let (acc1, created1) = import_local_session_offline(&repo, ex1, None, Some("main"), now)
            .await
            .unwrap();
        assert!(created1);
        assert_eq!(acc1.email, "alice@example.com");
        assert_eq!(acc1.custom_label.as_deref(), Some("main"));
        assert_eq!(acc1.token.access_token, "ya29.local-v1");
        assert_eq!(acc1.token.refresh_token, "1//rt-local-v1");
        assert_eq!(
            acc1.quota
                .as_ref()
                .and_then(|q| q.subscription_tier.as_deref()),
            Some("PRO")
        );
        assert!(is_tier_only_placeholder(acc1.quota.as_ref().unwrap()));
        assert_eq!(
            evaluate_account_quota(&acc1, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
            QuotaEval::Unknown {
                reason: "no_quota".into()
            }
        );

        // Seed real cached quota onto `acc1`, then re-import rotated local token -> preserves cached quota & advances lineage!
        let mut real_q = QuotaObservation::new(now - 30, QuotaSourceEnv::OfficialCli);
        real_q.subscription_tier = Some("PRO".into());
        real_q.tier_source_env = Some(QuotaSourceEnv::OfficialCli);
        real_q.quota_groups = Some(vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: None,
            buckets: vec![
                QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: 0.88,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-01T05:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.92,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-07T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
            ],
        }]);
        repo.with_write_lock(|tx| tx.merge_quota_observation(&acc1.id, real_q, None, None, true))
            .unwrap();

        let rotated_bytes = serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.local-v2",
                "token_type": "Bearer",
                "refresh_token": "1//rt-local-v2",
                "expiry": "2099-01-02T00:00:00Z"
            },
            "id_token_email": "alice@example.com",
            "user_tier": "ULTRA"
        }))
        .unwrap();
        let ex2 = extract_session_token_from_bytes(&rotated_bytes, "local").unwrap();
        let (acc2, created2) = import_local_session_offline(&repo, ex2, None, None, now + 10)
            .await
            .unwrap();
        assert!(!created2);
        assert_eq!(acc2.id, acc1.id);
        assert_eq!(acc2.token.refresh_token, "1//rt-local-v2");
        assert_eq!(acc2.token.access_token, "ya29.local-v2");
        assert!(acc2.quota.as_ref().unwrap().quota_groups.is_some());
        assert_eq!(
            acc2.quota
                .as_ref()
                .and_then(|q| q.subscription_tier.as_deref()),
            Some("ULTRA")
        );

        // 3. Re-importing superseded `1//rt-local-v1` MUST be rejected (`stale_rotated_refresh_token`, exit 5).
        let stale_ex = extract_session_token_from_bytes(&compact_bytes, "local").unwrap();
        let stale_err = import_local_session_offline(&repo, stale_ex, None, None, now + 20)
            .await
            .unwrap_err();
        assert_eq!(stale_err.exit_code, ExitCode::LockBusyOrConflict);
        assert_eq!(stale_err.error_code, "stale_rotated_refresh_token");

        // 4. Local file missing both `id_token` JWT email and `id_token_email` returns clear data error.
        let no_email_bytes = serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.no-email",
                "refresh_token": "1//rt-no-email",
                "expiry": "2099-01-01T00:00:00Z"
            }
        }))
        .unwrap();
        let no_email_ex = extract_session_token_from_bytes(&no_email_bytes, "local").unwrap();
        let err = import_local_session_offline(&repo, no_email_ex, None, None, now + 30)
            .await
            .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::GeneralOrDataError);
        assert!(err.message.contains("email"));
    }
}
