use crate::cli::args::*;
use crate::cli::dto::*;
use crate::cli::secret_input::{
    read_bounded_line, read_secret_from_tty_with_mode, read_secrets_from_private_file,
    read_secrets_from_stdin, write_interactive_prompt, MAX_SECRET_BYTES,
};
use crate::domain::account::{DisableReasonCode, SessionIdentity};
use crate::domain::clock::{Clock, SystemClock};
use crate::domain::policy::{PolicyMode, PolicyStrategy};
use crate::domain::quota::{evaluate_account_quota, QuotaEval, DEFAULT_QUOTA_MAX_AGE_SECS};
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
use crate::quota::client::{refresh_account_quota_locked, CloudCodeEndpoints};
use crate::session::backend::{
    detect_dbus_session_socket_warning, read_local_active_refresh_token,
    resolve_credential_backend_with_config, validate_backend_choice, BackendChoice,
    CredentialBackend, FileSessionBackend, SlotInspectState,
};
use crate::session::journal::{
    diagnose_journal_replicas_with_intent, read_journal_full_readonly,
    reconcile_pending_journal_before_write, JournalDiagnosis,
};
use crate::session::payload::resolve_session_identity;
use crate::session::process::observe_runtime_state;
use crate::store::locks::DaemonInstanceLock;
use crate::store::repository::StoreRepository;
use crate::store::transfer::{
    export_transfer_bundle_file, import_from_legacy_dir, import_transfer_bundle_file,
};
use crate::switching::daemon::{
    read_daemon_state_readonly, repair_or_clear_daemon_state_in_tx,
    run_foreground_daemon_with_shutdown, spawn_shutdown_signal_watcher, DaemonConfigOverrides,
    DaemonPolicyOverlay, DEFAULT_DAEMON_COOLDOWN_SECS, DEFAULT_DAEMON_INTERVAL_SECS,
};
use crate::switching::executor::{
    execute_account_delete, execute_switch_with_idle_policy, SwitchOptions,
};
use crate::switching::runner::{ordered_candidate_ids, run_managed_agy};
use crate::switching::systemd::{
    install_systemd_user_service, uninstall_systemd_user_service, DaemonServiceInstallOptions,
};
use crate::transport::client::{HttpTransport, ReqwestTransport};
use crate::transport::proxy::ProxyMode;
use crate::transport::user_agent::{
    format_native_oauth_user_agent, probe_local_agy_for_status, resolve_native_oauth_user_agent,
    LocalAgyProbeOutcome, CLI_PKG_VERSION, KNOWN_COMPAT_FLOOR_UA_VERSION,
};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

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
        Commands::Daemon(args) => !(args.install || args.uninstall),
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
            let ua = resolve_native_oauth_user_agent(
                &paths,
                &transport,
                !cli.no_remote_version,
                now_unix,
            )
            .await;
            handle_auth_login(&repo, backend, &transport, &ua, args, cli.json, now_unix).await?;
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Auth(AuthCommand::Reauthorize(args)) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
            let ua = resolve_native_oauth_user_agent(
                &paths,
                &transport,
                !cli.no_remote_version,
                now_unix,
            )
            .await;
            handle_auth_reauthorize(&repo, backend, &transport, &ua, args, cli.json, now_unix)
                .await?;
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
                let ua = resolve_native_oauth_user_agent(
                    &paths,
                    &transport,
                    !cli.no_remote_version,
                    resume_now,
                )
                .await;
                let registry = OAuthClientRegistry::load(&paths)?;
                let report = resume_pending_auth_records(
                    &repo,
                    &transport,
                    &OAuthEndpoints::default(),
                    &registry,
                    &ua,
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
            let mut local_source_tag: Option<&'static str> = None;
            let token_entries: Vec<(String, Option<String>)> = if args.from_local {
                let (secret, src_tag) = read_local_active_refresh_token(&paths, backend)?;
                local_source_tag = Some(src_tag);
                vec![(secret, None)]
            } else if args.from_stdin {
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
            let ua = resolve_native_oauth_user_agent(
                &paths,
                &transport,
                !cli.no_remote_version,
                SystemClock.now_unix(),
            )
            .await;
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
                    &ua,
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
                    let mut out_obj = serde_json::json!({
                        "created": created,
                        "account": dto,
                    });
                    if let Some(src_tag) = local_source_tag {
                        out_obj["local_source"] = serde_json::Value::String(src_tag.to_string());
                    }
                    print_json(&out_obj)?;
                } else if let Some(src_tag) = local_source_tag {
                    println!(
                        "{} account {} ({}) from local credential ({src_tag})",
                        if created { "Added" } else { "Updated" },
                        terminal_text(&dto.id),
                        terminal_text(&dto.email)
                    );
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
                    &ua,
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
        Commands::Accounts(AccountsCommand::Disable { selector, reason }) => {
            reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
            let snap = repo.read_snapshot()?;
            let target = snap.select(selector)?;
            let updated = repo.with_write_lock(|tx| {
                tx.mark_account_disabled(
                    &target.id,
                    DisableReasonCode::Manual,
                    reason.clone(),
                    now_unix,
                )
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
                let dummy = crate::transport::client::MockTransport::default();
                let floor_ua = format_native_oauth_user_agent(KNOWN_COMPAT_FLOOR_UA_VERSION);
                let outcome = execute_switch_with_idle_policy(
                    &repo,
                    backend,
                    &dummy,
                    &OAuthEndpoints::default(),
                    &registry,
                    &floor_ua,
                    &args.selector,
                    &SwitchOptions {
                        dry_run: true,
                        allow_running: args.allow_running,
                    },
                    args.require_idle,
                    now_unix,
                )
                .await?;
                if cli.json {
                    print_json(&serde_json::json!({ "switch": outcome }))?;
                } else {
                    if let Some(ref warn) = outcome.runtime_warning {
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

            let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
            let ua = resolve_native_oauth_user_agent(
                &paths,
                &transport,
                !cli.no_remote_version,
                now_unix,
            )
            .await;
            let outcome = execute_switch_with_idle_policy(
                &repo,
                backend,
                &transport,
                &OAuthEndpoints::default(),
                &registry,
                &ua,
                &args.selector,
                &SwitchOptions {
                    dry_run: false,
                    allow_running: args.allow_running,
                },
                args.require_idle,
                now_unix,
            )
            .await?;

            if cli.json {
                print_json(&serde_json::json!({ "switch": outcome }))?;
            } else {
                if let Some(ref warn) = outcome.runtime_warning {
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
            let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
            let ua = resolve_native_oauth_user_agent(
                &paths,
                &transport,
                !cli.no_remote_version,
                now_unix,
            )
            .await;
            let code = run_managed_agy(
                &repo,
                backend,
                &transport,
                &OAuthEndpoints::default(),
                &registry,
                &ua,
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
            let mut refresh_failures: Vec<(String, CliError)> = Vec::new();
            let mut streamed_batch = false;
            let mut streamed_stdout = false;
            if args.refresh {
                let (refreshed_ok, fails, streamed) = execute_quota_refresh_batch(
                    &repo,
                    backend,
                    cli.proxy.as_deref(),
                    cli.json,
                    !cli.no_remote_version,
                    args.selector.as_deref(),
                    args.all,
                    args.concurrency,
                    now_unix,
                )
                .await?;
                streamed_stdout = streamed && !refreshed_ok.is_empty();
                streamed_batch = streamed && (!refreshed_ok.is_empty() || !fails.is_empty());
                refresh_failures = fails;
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
                            "quota": acc.quota.as_ref().map(QuotaViewDto::from_observation),
                        })
                    })
                    .collect();
                if cli.json {
                    let fail_json: Vec<serde_json::Value> = refresh_failures
                        .iter()
                        .map(|(id, e)| {
                            serde_json::json!({
                                "account_id": id,
                                "error_code": e.error_code,
                                "message": e.message,
                            })
                        })
                        .collect();
                    let mut payload = serde_json::json!({
                        "monitored_model": monitored_model,
                        "accounts": items,
                    });
                    if args.refresh {
                        payload["refresh_failures"] = serde_json::Value::Array(fail_json);
                    }
                    print_json(&payload)?;
                } else if snap.accounts.is_empty() {
                    println!("No accounts saved.");
                } else {
                    if streamed_stdout {
                        println!();
                    } else if !streamed_batch {
                        for (id, e) in &refresh_failures {
                            eprintln!(
                                "Refresh failed for {}: {}",
                                terminal_text(id),
                                terminal_text(&e.message)
                            );
                        }
                    }
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
                        match &acc.quota {
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
                if !refresh_failures.is_empty() {
                    return Ok(ExitCode::GeneralOrDataError.as_i32());
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            let target = match args.selector.as_deref() {
                Some(sel) => snap.select(sel)?,
                None => snap.selected_account().ok_or_else(|| {
                    CliError::not_found(
                        "No selected account recorded. Pass `<ID|EMAIL>` or `--all`.",
                    )
                })?,
            };

            let eval = evaluate_account_quota(
                target,
                monitored_model,
                effective_now,
                DEFAULT_QUOTA_MAX_AGE_SECS,
            );
            let Some(ref q_obs) = target.quota else {
                return Err(CliError::quota_unavailable(
                    "no_cached_quota",
                    format!(
                        "Account '{}' ({}) has no cached quota. Run `agy-switch-cli quota --refresh {}` first.",
                        target.id, target.email, target.id
                    ),
                ));
            };
            let q_dto = QuotaViewDto::from_observation(q_obs);

            // In `--json` mode (or when quota is `Unknown` / `Unavailable`), enforce strict exit code 4.
            // In interactive human mode, if cached quota is merely `Stale` (> 1 hour old), still render
            // the cached quota table cleanly with an inline `--refresh` hint instead of hiding it behind an error!
            let is_human_stale_viewable = !cli.json && matches!(eval, QuotaEval::Stale { .. });
            if !matches!(eval, QuotaEval::Known { .. }) && !is_human_stale_viewable {
                return Err(CliError::quota_unavailable(
                    "quota_stale_or_unknown",
                    format!(
                        "Cached quota for '{}' ({}) on model '{}' is {:?}. Run `agy-switch-cli quota --refresh {}` for fresh observation.",
                        target.id, target.email, monitored_model, eval, target.id
                    ),
                )
                .with_details(serde_json::json!({
                    "account_id": target.id,
                    "email": target.email,
                    "monitored_model": monitored_model,
                    "evaluation": eval,
                    "quota": q_dto,
                })));
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
            let (refreshed_views, failures, streamed_batch) = execute_quota_refresh_batch(
                &repo,
                backend,
                cli.proxy.as_deref(),
                cli.json,
                !cli.no_remote_version,
                args.selector.as_deref(),
                args.all,
                args.concurrency,
                now_unix,
            )
            .await?;

            if refreshed_views.is_empty() && failures.is_empty() {
                if cli.json {
                    print_json(&serde_json::json!({ "refreshed": [], "failures": [] }))?;
                } else {
                    println!("No enabled accounts to refresh.");
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            if cli.json {
                let fail_json: Vec<serde_json::Value> = failures
                    .iter()
                    .map(|(id, e)| {
                        serde_json::json!({
                            "account_id": id,
                            "error_code": e.error_code,
                            "message": e.message,
                        })
                    })
                    .collect();
                print_json(&serde_json::json!({
                    "refreshed": refreshed_views,
                    "failures": fail_json,
                }))?;
            } else if streamed_batch {
                if refreshed_views.len() + failures.len() >= 2 {
                    println!(
                        "Batch refresh complete: {} refreshed, {} failed.",
                        refreshed_views.len(),
                        failures.len()
                    );
                }
            } else {
                for v in &refreshed_views {
                    println!(
                        "Refreshed {} ({})",
                        terminal_text(&v.id),
                        terminal_text(&v.email)
                    );
                }
                for (id, e) in &failures {
                    eprintln!(
                        "Failed {}: {}",
                        terminal_text(id),
                        terminal_text(&e.message)
                    );
                }
            }

            if !failures.is_empty() {
                return Ok(ExitCode::GeneralOrDataError.as_i32());
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
                let outcome = install_systemd_user_service(
                    &paths,
                    &DaemonServiceInstallOptions {
                        explicit_interval_secs: args.interval,
                        explicit_cooldown_secs: args.cooldown,
                        explicit_backend,
                    },
                )
                .await?;
                if cli.json {
                    print_json(&outcome)?;
                } else {
                    println!(
                        "Installed and started user service `{}`.",
                        outcome.service_name
                    );
                    println!(
                        "  Unit file : {}",
                        terminal_text(&outcome.unit_path.to_string_lossy())
                    );
                    println!("  ExecStart : {}", terminal_text(&outcome.exec_start));
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
                if has_temp_policy_flags || cli.proxy.is_some() {
                    return Err(CliError::usage(
                        "Policy or `--proxy` flags cannot be combined with `daemon --uninstall`.",
                    ));
                }
                let outcome = uninstall_systemd_user_service(&paths).await?;
                if cli.json {
                    print_json(&outcome)?;
                } else if outcome.removed_unit_file {
                    println!(
                        "Stopped, disabled, and removed user service `{}` ({}).",
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

            let interval_secs = args.interval.unwrap_or(DEFAULT_DAEMON_INTERVAL_SECS);
            let cooldown_secs = args.cooldown.unwrap_or(DEFAULT_DAEMON_COOLDOWN_SECS);
            if interval_secs == 0 {
                return Err(CliError::usage("`--interval` must be at least 1 second."));
            }
            if cooldown_secs < 0 {
                return Err(CliError::usage("`--cooldown` must be >= 0 seconds."));
            }

            let mut shutdown_rx = spawn_shutdown_signal_watcher();
            let registry = OAuthClientRegistry::load(&paths)?;
            let transport = build_network_transport(&repo, cli.proxy.as_deref(), cli.json)?;
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
            // Validate effective policy and acquire single-instance lock eagerly before any remote UA network check
            let _ =
                crate::switching::daemon::resolve_effective_daemon_policy(&repo, &policy_overlay)?;
            let daemon_lock = DaemonInstanceLock::try_acquire(&paths)?;

            let ua = tokio::select! {
                _ = shutdown_rx.changed() => {
                    return Ok(ExitCode::Ok.as_i32());
                }
                resolved = resolve_native_oauth_user_agent(
                    &paths,
                    &transport,
                    !cli.no_remote_version,
                    now_unix,
                ) => resolved,
            };

            run_foreground_daemon_with_shutdown(
                daemon_lock,
                &repo,
                backend,
                &transport,
                &OAuthEndpoints::default(),
                &CloudCodeEndpoints::default(),
                &registry,
                &ua,
                DaemonConfigOverrides {
                    interval_secs,
                    cooldown_secs,
                    once: args.once,
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
                        let view = crate::stats::collect_token_stats(&paths, args)?;
                        if cli.json {
                            print_json(&view)?;
                        } else {
                            println!("{}", view.render_human());
                        }
                    }
                    StatsCommand::List(args) => {
                        let view = crate::stats::collect_token_stats_list(&paths, args)?;
                        if cli.json {
                            print_json(&view)?;
                        } else {
                            println!("{}", view.render_human());
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
                crate::tui::run_interactive_tui(&repo, backend, cli.proxy.as_deref()).await?;
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

#[allow(clippy::too_many_arguments)]
async fn execute_quota_refresh_batch(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    cli_proxy: Option<&str>,
    json_mode: bool,
    allow_remote_version: bool,
    selector: Option<&str>,
    all: bool,
    concurrency: u8,
    now_unix: i64,
) -> CliResult<(Vec<AccountViewDto>, Vec<(String, CliError)>, bool)> {
    reconcile_pending_journal_before_write(repo, backend, now_unix)?;
    let snap = repo.read_snapshot()?;
    let targets: Vec<(usize, String, String)> = if let Some(sel) = selector {
        let acc = snap.select(sel)?;
        vec![(0, acc.id.clone(), acc.email.clone())]
    } else if all {
        snap.accounts
            .iter()
            .filter(|a| !a.disabled)
            .enumerate()
            .map(|(i, a)| (i, a.id.clone(), a.email.clone()))
            .collect()
    } else {
        let cur = snap.selected_account().ok_or_else(|| {
            CliError::not_found("No selected account to refresh. Pass `<ID|EMAIL>` or `--all`.")
        })?;
        vec![(0, cur.id.clone(), cur.email.clone())]
    };

    if targets.is_empty() {
        return Ok((Vec::new(), Vec::new(), false));
    }

    let paths = repo.paths();
    let transport: Arc<dyn HttpTransport> =
        Arc::new(build_network_transport(repo, cli_proxy, json_mode)?);
    let ua =
        resolve_native_oauth_user_agent(paths, transport.as_ref(), allow_remote_version, now_unix)
            .await;
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    execute_quota_refresh_batch_inner(
        repo,
        snap,
        targets,
        all,
        json_mode,
        concurrency,
        now_unix,
        transport,
        ua,
        &mut stdout,
        &mut stderr,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_quota_refresh_batch_inner(
    repo: &StoreRepository,
    snap: crate::store::repository::StoreSnapshot,
    targets: Vec<(usize, String, String)>,
    all: bool,
    json_mode: bool,
    concurrency: u8,
    now_unix: i64,
    transport: Arc<dyn HttpTransport>,
    ua: String,
    human_out: &mut dyn Write,
    human_err: &mut dyn Write,
) -> CliResult<(Vec<AccountViewDto>, Vec<(String, CliError)>, bool)> {
    let total = targets.len();
    let stream_human = !json_mode && (all || total > 1);
    let paths = repo.paths();
    let registry = Arc::new(OAuthClientRegistry::load(paths)?);
    let oauth_ep = Arc::new(OAuthEndpoints::default());
    let quota_ep = Arc::new(CloudCodeEndpoints::default());
    let max_in_flight = (concurrency as usize).max(1);
    let (tx, mut rx) = mpsc::unbounded_channel::<(
        usize,
        String,
        String,
        CliResult<crate::domain::account::AccountRecord>,
    )>();

    let mut queue: VecDeque<(usize, String, String)> = targets.into_iter().collect();
    let mut handles = Vec::with_capacity(total);
    let mut in_flight = 0usize;
    let mut first_recovery_err: Option<CliError> = None;

    let selected_id = snap.index.selected_account_id;
    let mut refreshed_indexed: Vec<(usize, AccountViewDto)> = Vec::with_capacity(total);
    let mut failures_indexed: Vec<(usize, String, CliError)> = Vec::new();
    let mut completed = 0usize;

    let spawn_next = |queue: &mut VecDeque<(usize, String, String)>,
                      handles: &mut Vec<tokio::task::JoinHandle<()>>,
                      in_flight: &mut usize| {
        if let Some((ord, id, email)) = queue.pop_front() {
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
                    &id,
                    now_unix,
                )
                .await;
                let _ = tx_c.send((ord, id, email, res));
            }));
            *in_flight += 1;
        }
    };

    // Dispatch ONLY up to `max_in_flight` tasks initially; queued items are held back until a slot
    // finishes cleanly so any `PartialCommitOrRecovery` (`7`) immediately halts all further dispatch
    // while allowing already-in-flight tasks to safely finish persisting their responses!
    while in_flight < max_in_flight && !queue.is_empty() {
        spawn_next(&mut queue, &mut handles, &mut in_flight);
    }

    while in_flight > 0 {
        let Some((ord, id, email, res)) = rx.recv().await else {
            break;
        };
        in_flight = in_flight.saturating_sub(1);
        completed += 1;
        match res {
            Ok(acc) => {
                if stream_human && first_recovery_err.is_none() {
                    let _ = writeln!(
                        human_out,
                        "[{completed}/{total}] Refreshed {} ({})",
                        terminal_text(&acc.id),
                        terminal_text(&acc.email)
                    );
                    let _ = human_out.flush();
                }
                let is_sel = selected_id.as_deref() == Some(acc.id.as_str());
                refreshed_indexed.push((ord, AccountViewDto::from_record(&acc, is_sel)));
            }
            Err(err) => {
                if err.exit_code == ExitCode::PartialCommitOrRecovery {
                    if first_recovery_err.is_none() {
                        first_recovery_err = Some(err.clone());
                    }
                    // Immediately stop dispatching remaining queued targets!
                    queue.clear();
                } else if stream_human && total >= 2 && first_recovery_err.is_none() {
                    let _ = writeln!(
                        human_err,
                        "[{completed}/{total}] Failed {} ({}): {}",
                        terminal_text(&id),
                        terminal_text(&email),
                        terminal_text(&err.message)
                    );
                    let _ = human_err.flush();
                }
                failures_indexed.push((ord, id, err));
            }
        }
        if first_recovery_err.is_none() {
            while in_flight < max_in_flight && !queue.is_empty() {
                spawn_next(&mut queue, &mut handles, &mut in_flight);
            }
        }
    }
    drop(tx);
    for h in handles {
        let _ = h.await;
    }

    if let Some(rec_err) = first_recovery_err {
        return Err(rec_err);
    }

    refreshed_indexed.sort_by_key(|(ord, _)| *ord);
    failures_indexed.sort_by_key(|(ord, _, _)| *ord);
    let refreshed_views: Vec<AccountViewDto> =
        refreshed_indexed.into_iter().map(|(_, v)| v).collect();
    let mut failures: Vec<(String, CliError)> = failures_indexed
        .into_iter()
        .map(|(_, id, e)| (id, e))
        .collect();

    if refreshed_views.is_empty() && failures.len() == 1 {
        return Err(failures.pop().unwrap().1);
    }

    Ok((refreshed_views, failures, stream_human))
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
        SessionIdentity::Matched { account_id, .. }
        | SessionIdentity::DriftedKnown { account_id, .. } => snap
            .accounts
            .iter()
            .find(|a| &a.id == account_id)
            .or_else(|| snap.selected_account()),
        _ => snap.selected_account(),
    };
    let supported_models = model_source_acc
        .and_then(|a| a.quota.as_ref())
        .map(extract_supported_models);
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
            for line in format_supported_models_human(current.supported_models.as_deref()) {
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
    let dstate_res = read_daemon_state_readonly(paths);
    let agy_probe = probe_local_agy_for_status().await;

    let agy_json = match &agy_probe {
        LocalAgyProbeOutcome::Detected {
            executable,
            version,
        } => serde_json::json!({
            "checked": true,
            "found": true,
            "executable": executable,
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
            "executable": executable,
            "error": error,
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
        "dbus_keyring_warning": dbus_warning,
        "agy_probe": agy_json,
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
                "  Daemon state:      OK (paused_on_failure={})",
                ds.paused_on_failure
            );
        }
        match &agy_probe {
            LocalAgyProbeOutcome::Detected {
                executable,
                version,
            } => {
                println!(
                    "  Official agy:      {} v{}",
                    terminal_text(&executable.to_string_lossy()),
                    terminal_text(version)
                );
            }
            LocalAgyProbeOutcome::NotFound => {
                println!("  Official agy:      not found in PATH");
            }
            LocalAgyProbeOutcome::Failed { .. } => unreachable!(),
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
    user_agent: &str,
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
        user_agent,
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
    user_agent: &str,
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
        user_agent,
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
    use crate::domain::account::AccountRecord;
    use crate::domain::token::TokenRecord;
    use crate::transport::client::{
        BoxFuture, HttpRequest, HttpResponse, MockTransport, TransportError,
    };
    use std::time::Duration;

    struct StaggeredQuotaTransport;

    impl HttpTransport for StaggeredQuotaTransport {
        fn execute<'a>(
            &'a self,
            req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                let auth = req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                if auth.contains("ya29.acc-1") && req.url.contains(":fetchAvailableModels") {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                }
                let body = if req.url.contains(":loadCodeAssist") {
                    serde_json::json!({
                        "cloudaicompanionProject": "proj-synth",
                        "currentTier": { "name": "Antigravity Starter Quota" }
                    })
                } else if req.url.contains(":fetchAvailableModels") {
                    serde_json::json!({ "models": {} })
                } else {
                    serde_json::json!({ "quotaGroups": [] })
                };
                Ok(MockTransport::json_response(200, body))
            })
        }
    }

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
    async fn refresh_batch_streams_completion_order_in_human_mode_and_sorts_json_views() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let repo = StoreRepository::new(paths);
        let now = 1_900_000_000i64;
        let acc1 = make_fresh_acc("acc-1", "alice@example.com", now);
        let acc2 = make_fresh_acc("acc-2", "bob@example.com", now);
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc1, true, now)?;
            tx.upsert_account(acc2, false, now)?;
            Ok(())
        })
        .unwrap();

        let snap = repo.read_snapshot().unwrap();
        let targets: Vec<(usize, String, String)> = snap
            .accounts
            .iter()
            .enumerate()
            .map(|(i, a)| (i, a.id.clone(), a.email.clone()))
            .collect();

        let mut human_out = Vec::new();
        let mut human_err = Vec::new();
        let (views, failures, streamed) = execute_quota_refresh_batch_inner(
            &repo,
            snap.clone(),
            targets.clone(),
            true,
            false,
            2,
            now,
            Arc::new(StaggeredQuotaTransport),
            "antigravity/1.5.9 linux/amd64".into(),
            &mut human_out,
            &mut human_err,
        )
        .await
        .unwrap();

        assert!(streamed);
        assert!(failures.is_empty());
        let streamed_lines: Vec<String> = String::from_utf8(human_out)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(
            streamed_lines,
            vec![
                "[1/2] Refreshed acc-2 (bob@example.com)".to_string(),
                "[2/2] Refreshed acc-1 (alice@example.com)".to_string(),
            ]
        );
        assert!(human_err.is_empty());
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].id, "acc-1");
        assert_eq!(views[1].id, "acc-2");
        assert_eq!(
            views[0]
                .quota
                .as_ref()
                .and_then(|q| q.subscription_tier.as_deref()),
            Some("Antigravity Starter Quota")
        );

        let mut json_out = Vec::new();
        let mut json_err = Vec::new();
        let (json_views, _, json_streamed) = execute_quota_refresh_batch_inner(
            &repo,
            snap,
            targets,
            true,
            true,
            2,
            now,
            Arc::new(StaggeredQuotaTransport),
            "antigravity/1.5.9 linux/amd64".into(),
            &mut json_out,
            &mut json_err,
        )
        .await
        .unwrap();
        assert!(!json_streamed);
        assert!(json_out.is_empty());
        assert!(json_err.is_empty());
        assert_eq!(json_views[0].id, "acc-1");
        assert_eq!(json_views[1].id, "acc-2");
    }

    #[tokio::test]
    async fn r3_04_batch_refresh_stops_dispatching_after_exit_7_for_serial_and_concurrent() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicUsize, Ordering};

        if std::env::var_os("AGY_SUBTEST_R304_BATCH").is_some() {
            struct BatchTokenTransport {
                token_calls: Arc<AtomicUsize>,
                delay_acc2_ms: u64,
            }
            impl HttpTransport for BatchTokenTransport {
                fn execute<'a>(
                    &'a self,
                    req: HttpRequest,
                ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
                    let calls = self.token_calls.clone();
                    let delay_ms = self.delay_acc2_ms;
                    Box::pin(async move {
                        if req.url.contains("/token") {
                            calls.fetch_add(1, Ordering::SeqCst);
                            let rt_val = match &req.body {
                                crate::transport::client::RequestBody::Form(pairs) => pairs
                                    .iter()
                                    .find(|(k, _)| k == "refresh_token")
                                    .map(|(_, v)| v.as_str())
                                    .unwrap_or(""),
                                _ => "",
                            };
                            let is_acc2 = rt_val.contains("acc-2-ok");
                            if is_acc2 && delay_ms > 0 {
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            }
                            let tag = if is_acc2 {
                                "acc-2-ok"
                            } else if rt_val.contains("acc-1-enospc") {
                                "acc-1-enospc"
                            } else {
                                "acc-3-never"
                            };
                            return Ok(MockTransport::json_response(
                                200,
                                serde_json::json!({
                                    "access_token": format!("ya29.new-{tag}"),
                                    "refresh_token": format!("1//rotated-{tag}"),
                                    "expires_in": 3600,
                                    "token_type": "Bearer"
                                }),
                            ));
                        }
                        let body = if req.url.contains(":loadCodeAssist") {
                            serde_json::json!({
                                "cloudaicompanionProject": "proj-synth",
                                "currentTier": { "name": "Antigravity Starter Quota" }
                            })
                        } else if req.url.contains(":fetchAvailableModels") {
                            serde_json::json!({ "models": {} })
                        } else {
                            serde_json::json!({ "quotaGroups": [] })
                        };
                        Ok(MockTransport::json_response(200, body))
                    })
                }
            }

            let now = 1_900_000_000i64;
            let make_expiring = |id: &str, email: &str| {
                let mut acc = make_fresh_acc(id, email, now);
                acc.token.expiry_timestamp = now + 10;
                acc
            };

            let seed_three = |base: &std::path::Path| -> StoreRepository {
                let paths = HeadlessPaths::with_explicit(
                    base.join("home"),
                    base.join("data"),
                    base.join("cache"),
                );
                let repo = StoreRepository::new(paths);
                let a2 = make_expiring("acc-2-ok", "bob@example.com");
                let a3 = make_expiring("acc-3-never", "charlie@example.com");
                repo.with_write_lock(|tx| {
                    tx.upsert_account(a2, false, now)?;
                    tx.upsert_account(a3, false, now)?;
                    Ok(())
                })
                .unwrap();
                // Seed `acc-1-enospc` directly on disk so the fault spec only triggers during batch renewal!
                let a1 = make_expiring("acc-1-enospc", "alice@example.com");
                let a1_path = repo.paths().account_file("acc-1-enospc");
                std::fs::write(&a1_path, serde_json::to_vec_pretty(&a1).unwrap()).unwrap();
                std::fs::set_permissions(&a1_path, std::fs::Permissions::from_mode(0o600)).unwrap();
                let mut idx = repo.read_snapshot().unwrap().index;
                idx.account_order.insert(0, "acc-1-enospc".into());
                std::fs::write(
                    repo.paths().index_file(),
                    serde_json::to_vec_pretty(&idx).unwrap(),
                )
                .unwrap();
                repo
            };

            // Case 1: Serial (`concurrency = 1`) -> ONLY `acc-1-enospc` calls `/token` (`1` call total), returns exit `7`!
            let tmp1 = tempfile::tempdir().unwrap();
            let repo1 = seed_three(tmp1.path());
            let snap1 = repo1.read_snapshot().unwrap();
            let targets1: Vec<(usize, String, String)> = snap1
                .accounts
                .iter()
                .enumerate()
                .map(|(i, a)| (i, a.id.clone(), a.email.clone()))
                .collect();
            let calls1 = Arc::new(AtomicUsize::new(0));
            let mut out1 = Vec::new();
            let mut err1 = Vec::new();
            let res1 = execute_quota_refresh_batch_inner(
                &repo1,
                snap1,
                targets1,
                true,
                true,
                1,
                now,
                Arc::new(BatchTokenTransport {
                    token_calls: calls1.clone(),
                    delay_acc2_ms: 0,
                }),
                "antigravity/1.5.9 linux/amd64".into(),
                &mut out1,
                &mut err1,
            )
            .await
            .unwrap_err();
            assert_eq!(
                res1.exit_code,
                crate::error::ExitCode::PartialCommitOrRecovery
            );
            assert_eq!(res1.error_code, "issued_token_unpersisted");
            assert_eq!(
                calls1.load(Ordering::SeqCst),
                1,
                "Serial batch refresh must stop after first exit-7 without refreshing remaining accounts"
            );

            // Case 2: Concurrent (`concurrency = 2`) -> `acc-1` hits exit 7 while `acc-2` is in-flight;
            // `acc-2` finishes persisting its rotated token cleanly, `acc-3` is NEVER dispatched (`2` calls total)!
            let tmp2 = tempfile::tempdir().unwrap();
            let repo2 = seed_three(tmp2.path());
            let snap2 = repo2.read_snapshot().unwrap();
            let targets2: Vec<(usize, String, String)> = snap2
                .accounts
                .iter()
                .enumerate()
                .map(|(i, a)| (i, a.id.clone(), a.email.clone()))
                .collect();
            let calls2 = Arc::new(AtomicUsize::new(0));
            let mut out2 = Vec::new();
            let mut err2 = Vec::new();
            let res2 = execute_quota_refresh_batch_inner(
                &repo2,
                snap2,
                targets2,
                true,
                true,
                2,
                now,
                Arc::new(BatchTokenTransport {
                    token_calls: calls2.clone(),
                    delay_acc2_ms: 60,
                }),
                "antigravity/1.5.9 linux/amd64".into(),
                &mut out2,
                &mut err2,
            )
            .await
            .unwrap_err();
            assert_eq!(
                res2.exit_code,
                crate::error::ExitCode::PartialCommitOrRecovery
            );
            assert_eq!(res2.error_code, "issued_token_unpersisted");
            assert_eq!(
                calls2.load(Ordering::SeqCst),
                2,
                "Concurrent batch refresh must drain in-flight acc-2 but NEVER dispatch acc-3!"
            );
            let post2 = repo2.read_snapshot().unwrap();
            let acc2_after = post2.accounts.iter().find(|a| a.id == "acc-2-ok").unwrap();
            assert_eq!(
                acc2_after.token.refresh_token, "1//rotated-acc-2-ok",
                "In-flight acc-2 must finish persisting its rotated refresh token cleanly!"
            );
            let acc3_after = post2
                .accounts
                .iter()
                .find(|a| a.id == "acc-3-never")
                .unwrap();
            assert_eq!(
                acc3_after.token.refresh_token, "1//rt-acc-3-never",
                "Undispatched acc-3 must remain untouched!"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", tmp.path())
            .env("AGY_SUBTEST_R304_BATCH", "1")
            .env(
                "AGY_SWITCH_CLI_FAULT_SPEC",
                "before_fsync:acc-1-enospc:enospc",
            )
            .args([
                "--exact",
                "cli::commands::tests::r3_04_batch_refresh_stops_dispatching_after_exit_7_for_serial_and_concurrent",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "R3-04 batch refresh subtest failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
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
        let transport = MockTransport::default();
        let endpoints = OAuthEndpoints::default();
        let dry_opts = SwitchOptions {
            dry_run: true,
            allow_running: true,
        };
        let floor_ua = format_native_oauth_user_agent(KNOWN_COMPAT_FLOOR_UA_VERSION);

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

        let uninit_dry_err = execute_switch_with_idle_policy(
            &repo,
            &file_backend,
            &transport,
            &endpoints,
            &registry,
            &floor_ua,
            "acc-0002",
            &dry_opts,
            false,
            now,
        )
        .await
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

        let dry_ok = execute_switch_with_idle_policy(
            &repo,
            &file_backend,
            &transport,
            &endpoints,
            &registry,
            &floor_ua,
            "acc-0002",
            &dry_opts,
            false,
            now,
        )
        .await
        .unwrap();
        assert!(dry_ok.dry_run);
        assert_eq!(dry_ok.target_account_id, "acc-0002");
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
        let dry_dual_fb = execute_switch_with_idle_policy(
            &repo,
            &dual_absent,
            &transport,
            &endpoints,
            &registry,
            &floor_ua,
            "acc-0002",
            &dry_opts,
            false,
            now,
        )
        .await
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
        let dry_kr_bad = execute_switch_with_idle_policy(
            &repo,
            &dual_kr_corrupt,
            &transport,
            &endpoints,
            &registry,
            &floor_ua,
            "acc-0002",
            &dry_opts,
            false,
            now,
        )
        .await
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
        let dry_kr_unv = execute_switch_with_idle_policy(
            &repo,
            &dual_kr_unv,
            &transport,
            &endpoints,
            &registry,
            &floor_ua,
            "acc-0002",
            &dry_opts,
            false,
            now,
        )
        .await
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
        let dry_disk_bad = execute_switch_with_idle_policy(
            &repo,
            &dual_disk_bad,
            &transport,
            &endpoints,
            &registry,
            &floor_ua,
            "acc-0002",
            &dry_opts,
            false,
            now,
        )
        .await
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
        let dry_kr_only = execute_switch_with_idle_policy(
            &repo,
            &kr_present,
            &transport,
            &endpoints,
            &registry,
            &floor_ua,
            "acc-0002",
            &dry_opts,
            false,
            now,
        )
        .await
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
}
