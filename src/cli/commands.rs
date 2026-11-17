use crate::cli::args::*;
use crate::cli::dto::*;
use crate::cli::secret_input::{
    read_bounded_line, read_secret_from_tty_with_mode, read_secrets_from_private_file,
    read_secrets_from_stdin, write_interactive_prompt, MAX_SECRET_BYTES,
};
use crate::domain::account::{
    validate_account_id, AccountRecord, DisableReasonCode, PendingAuthRecord, SessionIdentity,
    StoreIndex, STORE_SCHEMA_VERSION,
};
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
    resolve_credential_backend_with_config, validate_backend_choice, CredentialBackend,
    FileSessionBackend, SlotInspectState,
};
use crate::session::journal::{
    diagnose_journal, read_journal_readonly, reconcile_journal_locked,
    reconcile_pending_journal_before_write, JournalDiagnosis,
};
use crate::session::payload::resolve_session_identity;
use crate::session::process::{cleanup_stale_leases_under_write_lock, observe_runtime_state};
use crate::store::fs_atomic::{
    cleanup_orphan_temp_files, read_regular_file_opt_bounded, MAX_STORE_FILE_BYTES,
};
use crate::store::locks::{
    try_acquire_pending_auth_lock_nonblocking, ActiveSlotLock, DaemonInstanceLock,
};
use crate::store::repository::StoreRepository;
use crate::store::transfer::{
    export_transfer_bundle_file, import_from_legacy_dir, import_transfer_bundle_file,
};
use crate::switching::daemon::{
    clear_daemon_pause_in_tx, read_daemon_state_readonly, repair_or_clear_daemon_state_in_tx,
    run_foreground_daemon_with_shutdown, spawn_shutdown_signal_watcher, DaemonConfigOverrides,
    DaemonPolicyOverlay,
};
use crate::switching::executor::{execute_switch, SwitchOptions};
use crate::switching::runner::{ordered_candidate_ids, run_managed_agy};
use crate::transport::client::{HttpTransport, ReqwestTransport};
use crate::transport::proxy::ProxyMode;
use crate::transport::user_agent::{
    format_native_oauth_user_agent, probe_local_agy_version_isolated,
    resolve_native_oauth_user_agent, CLI_PKG_VERSION, KNOWN_COMPAT_FLOOR_UA_VERSION,
    VERIFIED_AGY_VERSIONS,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

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
        _ => true,
    }
}

pub async fn dispatch(cli: Cli) -> CliResult<i32> {
    let paths = HeadlessPaths::resolve(cli.data_dir.as_deref())?;
    let repo = StoreRepository::new(paths.clone());
    let backend_box: Box<dyn CredentialBackend> = if matches!(cli.command, Commands::Doctor(_)) {
        let cfg_backend = repo.read_config().ok().and_then(|c| c.backend);
        resolve_credential_backend_with_config(cli.backend.as_deref(), cfg_backend.as_deref())?
    } else if command_uses_backend(&cli.command) {
        let cfg = repo.read_config()?;
        resolve_credential_backend_with_config(cli.backend.as_deref(), cfg.backend.as_deref())?
    } else {
        let cfg_backend = repo.read_config().ok().and_then(|c| c.backend);
        validate_backend_choice(cli.backend.as_deref(), cfg_backend.as_deref())?;
        Box::new(FileSessionBackend)
    };
    let backend: &dyn CredentialBackend = backend_box.as_ref();
    let now_unix = chrono::Utc::now().timestamp();

    match &cli.command {
        // ==================== 1. DOCTOR ====================
        Commands::Doctor(args) => {
            handle_doctor(&repo, backend, args, cli.json, now_unix).await?;
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
            let transport = build_network_transport(&repo, cli.proxy.as_deref())?;
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
            let transport = build_network_transport(&repo, cli.proxy.as_deref())?;
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
                let transport = build_network_transport(&repo, cli.proxy.as_deref())?;
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
            reconcile_pending_journal_before_write(&repo, backend, SystemClock.now_unix())?;
            let mut local_source_tag: Option<&'static str> = None;
            let token_entries: Vec<(String, Option<String>)> = if args.from_local {
                let (secret, src_tag) = read_local_active_refresh_token(&paths, backend)?;
                local_source_tag = Some(src_tag);
                vec![(secret, None)]
            } else if args.stdin {
                read_secrets_from_stdin()?
            } else if let Some(ref file_path) = args.token_file {
                read_secrets_from_private_file(file_path)?
            } else {
                let single = read_secret_from_tty_with_mode(
                    "Enter Google OAuth refresh_token (echo hidden): ",
                    cli.json,
                )?;
                vec![(single, None)]
            };

            let transport = build_network_transport(&repo, cli.proxy.as_deref())?;
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
            if args.from_legacy.is_none() && args.file.is_none() {
                return Err(CliError::usage(
                    "Specify either `<FILE>` or `--from-legacy [<LEGACY_DIR>]`.",
                ));
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
            } else if let Some(ref bundle_file) = args.file {
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
                args.force,
                &args.ids,
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
            let mut cleared_slot = false;
            let target = if args.clear_active_slot {
                // Acquire L1 -> reconcile any pending journal -> re-read fresh snapshot -> L3 delete!
                let slot_lock = ActiveSlotLock::try_acquire(&paths, backend.uses_keyring())?;
                reconcile_journal_locked(&slot_lock, &repo, backend, false, now_unix)?;
                let snap = repo.read_snapshot()?;
                let t = snap.select(&args.selector)?.clone();
                let slot_state = backend.inspect_slot(&paths);
                let should_remove = match &slot_state {
                    SlotInspectState::Present(parsed) => {
                        parsed.refresh_token_digest == t.token.refresh_token_fingerprint()
                    }
                    _ => false,
                };
                repo.with_write_lock(|tx| tx.delete_account(&t.id, args.force, now_unix))?;
                if should_remove {
                    backend.remove_slot(&paths)?;
                    cleared_slot = true;
                }
                t
            } else {
                reconcile_pending_journal_before_write(&repo, backend, now_unix)?;
                let snap = repo.read_snapshot()?;
                let t = snap.select(&args.selector)?.clone();
                repo.with_write_lock(|tx| tx.delete_account(&t.id, args.force, now_unix))?;
                t
            };

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
            // Strictly read-only
            let snap = repo.read_snapshot()?;
            let slot_state = backend.inspect_slot(&paths);
            let session_identity = resolve_session_identity(&slot_state, &snap);
            let runtime_state = observe_runtime_state(&paths);
            let journal = read_journal_readonly(&paths)?;
            let journal_diag = diagnose_journal(journal.as_ref(), &slot_state);

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

            let view = StatusViewDto {
                selected_account: snap
                    .selected_account()
                    .map(|acc| SelectedAccountBriefDto::from_record_at(acc, now_unix)),
                session_identity,
                runtime_state,
            };

            if cli.json {
                print_json(&serde_json::json!({
                    "selected_account": view.selected_account,
                    "session_identity": view.session_identity,
                    "runtime_state": view.runtime_state,
                    "journal_status": journal_diag,
                    "supported_models": supported_models,
                }))?;
            } else {
                match &view.selected_account {
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
                    format_session_identity_human(&view.session_identity)
                );
                println!(
                    "Live agy runtime : {}",
                    format_runtime_state_human(&view.runtime_state)
                );
                if journal_diag != JournalDiagnosis::Clean {
                    println!("Pending journal  : {:?}", journal_diag);
                }
                if model_source_acc.is_some() {
                    for line in format_supported_models_human(supported_models.as_deref()) {
                        println!("{line}");
                    }
                }
            }
            Ok(ExitCode::Ok.as_i32())
        }
        Commands::Switch(args) => {
            let registry = OAuthClientRegistry::load(&paths)?;
            if args.dry_run {
                let dummy = crate::transport::client::MockTransport::default();
                let floor_ua = format_native_oauth_user_agent(KNOWN_COMPAT_FLOOR_UA_VERSION);
                let outcome = execute_switch(
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
                    now_unix,
                )
                .await?;
                if cli.json {
                    print_json(&serde_json::json!({ "switch": outcome }))?;
                } else {
                    println!(
                        "[dry-run] Ready to switch active slot to {} ({}).",
                        terminal_text(&outcome.target_account_id),
                        terminal_text(&outcome.target_email)
                    );
                }
                return Ok(ExitCode::Ok.as_i32());
            }

            let transport = build_network_transport(&repo, cli.proxy.as_deref())?;
            let ua = resolve_native_oauth_user_agent(
                &paths,
                &transport,
                !cli.no_remote_version,
                now_unix,
            )
            .await;
            let outcome = execute_switch(
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
            let transport = build_network_transport(&repo, cli.proxy.as_deref())?;
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
                &CloudCodeEndpoints::default(),
                &registry,
                &ua,
                args.account.as_deref(),
                args.isolate_dbus,
                &args.command,
                now_unix,
            )
            .await?;
            Ok(code)
        }

        // ==================== 5. QUOTA (READ-ONLY OR `-r` REFRESH) & REFRESH ====================
        Commands::Quota(args) => {
            let mut effective_now = now_unix;
            let mut refresh_failures: Vec<(String, CliError)> = Vec::new();
            if args.refresh {
                let (_, fails) = execute_quota_refresh_batch(
                    &repo,
                    backend,
                    cli.proxy.as_deref(),
                    !cli.no_remote_version,
                    args.selector.as_deref(),
                    args.all,
                    args.concurrency,
                    now_unix,
                )
                .await?;
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
                    for (id, e) in &refresh_failures {
                        eprintln!(
                            "Refresh failed for {}: {}",
                            terminal_text(id),
                            terminal_text(&e.message)
                        );
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
                        "Account '{}' ({}) has no cached quota. Run `agy-switch-cli quota -r {}` first.",
                        target.id, target.email, target.id
                    ),
                ));
            };
            let q_dto = QuotaViewDto::from_observation(q_obs);

            // In `--json` mode (or when quota is `Unknown` / `Unavailable`), enforce strict exit code 4.
            // In interactive human mode, if cached quota is merely `Stale` (> 1 hour old), still render
            // the cached quota table cleanly with an inline `-r` hint instead of hiding it behind an error!
            let is_human_stale_viewable = !cli.json && matches!(eval, QuotaEval::Stale { .. });
            if !matches!(eval, QuotaEval::Known { .. }) && !is_human_stale_viewable {
                return Err(CliError::quota_unavailable(
                    "quota_stale_or_unknown",
                    format!(
                        "Cached quota for '{}' ({}) on model '{}' is {:?}. Run `agy-switch-cli quota -r {}` for fresh observation.",
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
            let (refreshed_views, failures) = execute_quota_refresh_batch(
                &repo,
                backend,
                cli.proxy.as_deref(),
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

            let saved = repo.with_write_lock(|tx| {
                let out = tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
                clear_daemon_pause_in_tx(tx.paths(), now_unix);
                Ok(out)
            })?;

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
            let saved = repo.with_write_lock(|tx| {
                let out = tx.save_policy(&mut policy, Some(prev_rev), now_unix)?;
                clear_daemon_pause_in_tx(tx.paths(), now_unix);
                Ok(out)
            })?;
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
            let mut shutdown_rx = spawn_shutdown_signal_watcher();
            let registry = OAuthClientRegistry::load(&paths)?;
            let transport = build_network_transport(&repo, cli.proxy.as_deref())?;
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
                    interval_secs: args.interval,
                    cooldown_secs: args.cooldown,
                    once: args.once,
                    policy_overlay,
                    ..DaemonConfigOverrides::default()
                },
                shutdown_rx,
            )
            .await?;
            Ok(ExitCode::Ok.as_i32())
        }

        // ==================== 7. OPTIONAL TUI ====================
        Commands::Tui => {
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
    allow_remote_version: bool,
    selector: Option<&str>,
    all: bool,
    concurrency: u8,
    now_unix: i64,
) -> CliResult<(Vec<AccountViewDto>, Vec<(String, CliError)>)> {
    reconcile_pending_journal_before_write(repo, backend, now_unix)?;
    let snap = repo.read_snapshot()?;
    let target_ids: Vec<String> = if let Some(sel) = selector {
        vec![snap.select(sel)?.id.clone()]
    } else if all {
        snap.accounts
            .iter()
            .filter(|a| !a.disabled)
            .map(|a| a.id.clone())
            .collect()
    } else {
        let cur = snap.selected_account().ok_or_else(|| {
            CliError::not_found("No selected account to refresh. Pass `<ID|EMAIL>` or `--all`.")
        })?;
        vec![cur.id.clone()]
    };

    if target_ids.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let paths = repo.paths();
    let transport = Arc::new(build_network_transport(repo, cli_proxy)?);
    let ua =
        resolve_native_oauth_user_agent(paths, transport.as_ref(), allow_remote_version, now_unix)
            .await;
    let registry = Arc::new(OAuthClientRegistry::load(paths)?);
    let oauth_ep = Arc::new(OAuthEndpoints::default());
    let quota_ep = Arc::new(CloudCodeEndpoints::default());
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    let mut handles = Vec::with_capacity(target_ids.len());
    for id in target_ids {
        let repo_c = repo.clone();
        let tr_c = transport.clone();
        let reg_c = registry.clone();
        let oe_c = oauth_ep.clone();
        let qe_c = quota_ep.clone();
        let ua_c = ua.clone();
        let sem_c = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem_c.acquire_owned().await.ok();
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
            (id, res)
        }));
    }

    let mut refreshed_views = Vec::new();
    let mut failures = Vec::new();
    let selected_id = repo.read_snapshot()?.index.selected_account_id;

    for h in handles {
        if let Ok((id, res)) = h.await {
            match res {
                Ok(acc) => {
                    let is_sel = selected_id.as_deref() == Some(acc.id.as_str());
                    refreshed_views.push(AccountViewDto::from_record(&acc, is_sel));
                }
                Err(err) => failures.push((id, err)),
            }
        }
    }

    if refreshed_views.is_empty() && failures.len() == 1 {
        return Err(failures.pop().unwrap().1);
    }

    Ok((refreshed_views, failures))
}

fn build_network_transport(
    repo: &StoreRepository,
    cli_proxy: Option<&str>,
) -> CliResult<ReqwestTransport> {
    let cfg = repo.read_config()?;
    let proxy_mode = ProxyMode::resolve_with_config(cli_proxy, Some(&cfg.network))?;
    ReqwestTransport::build(proxy_mode)
}

pub fn print_json<T: Serialize>(payload: &T) -> CliResult<()> {
    let envelope = JsonSuccessEnvelope::new(payload);
    let rendered = serde_json::to_string_pretty(&envelope)
        .map_err(|e| CliError::data(format!("JSON serialization error: {e}")))?;
    println!("{rendered}");
    Ok(())
}

async fn handle_doctor(
    repo: &StoreRepository,
    backend: &dyn CredentialBackend,
    args: &DoctorArgs,
    json_mode: bool,
    now_unix: i64,
) -> CliResult<()> {
    let paths = repo.paths();
    let mut repairs_applied: Vec<String> = Vec::new();

    if args.fix {
        let slot_lock = ActiveSlotLock::try_acquire(paths, backend.uses_keyring())?;
        let diag = reconcile_journal_locked(&slot_lock, repo, backend, true, now_unix)?;
        if diag != JournalDiagnosis::Clean {
            repairs_applied.push(format!("Reconciled switch_journal: {diag:?}"));
        }
        // Clean orphan `*.tmp.*` files in `~/.gemini/antigravity-cli` while holding exclusive L1 `ActiveSlotLock`!
        let cleaned_slot_tmp = cleanup_orphan_temp_files(&paths.active_slot_dir, Duration::ZERO);
        if cleaned_slot_tmp > 0 {
            repairs_applied.push(format!(
                "Removed {cleaned_slot_tmp} orphan temporary file(s) from active slot directory."
            ));
        }

        // Rebuild missing index.json from orphan valid accounts/*.json if needed, fix permissions, clear pause
        repo.with_write_lock(|tx| {
            let _ = fs::set_permissions(&tx.paths().data_dir, fs::Permissions::from_mode(0o700));
            let _ =
                fs::set_permissions(tx.paths().accounts_dir(), fs::Permissions::from_mode(0o700));
            if fs::symlink_metadata(tx.paths().config_file()).is_ok_and(|m| m.file_type().is_file())
            {
                let _ = fs::set_permissions(
                    tx.paths().config_file(),
                    fs::Permissions::from_mode(0o600),
                );
            }
            let is_real_dir = |p: &std::path::Path| {
                fs::symlink_metadata(p)
                    .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
            };
            let cleaned_store_tmp = cleanup_orphan_temp_files(&tx.paths().data_dir, Duration::ZERO)
                + cleanup_orphan_temp_files(&tx.paths().accounts_dir(), Duration::ZERO)
                + cleanup_orphan_temp_files(&tx.paths().state_dir(), Duration::ZERO)
                + cleanup_orphan_temp_files(&tx.paths().pending_auth_dir(), Duration::ZERO)
                + if is_real_dir(&tx.paths().token_lineage_dir()) {
                    cleanup_orphan_temp_files(&tx.paths().token_lineage_dir(), Duration::ZERO)
                } else {
                    0
                }
                + if is_real_dir(&tx.paths().pending_lineage_dir()) {
                    cleanup_orphan_temp_files(&tx.paths().pending_lineage_dir(), Duration::ZERO)
                } else {
                    0
                };
            if cleaned_store_tmp > 0 {
                repairs_applied.push(format!(
                    "Removed {cleaned_store_tmp} orphan temporary file(s) from store directories."
                ));
            }
            cleanup_stale_leases_under_write_lock(tx.paths());
            if let Some(ds_msg) = repair_or_clear_daemon_state_in_tx(tx.paths(), now_unix) {
                repairs_applied.push(ds_msg);
            }

            for l_dir in [tx.paths().token_lineage_dir(), tx.paths().pending_lineage_dir()] {
                if is_real_dir(&l_dir) {
                    let _ = fs::set_permissions(&l_dir, fs::Permissions::from_mode(0o700));
                    if let Ok(entries) = fs::read_dir(&l_dir) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if let Ok(m) = fs::symlink_metadata(&p) {
                                if m.file_type().is_file() && (m.permissions().mode() & 0o077) != 0
                                {
                                    let _ =
                                        fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
                                }
                            }
                        }
                    }
                }
            }

            // Repair permissions on `state/pending_auth/*.json` and remove corrupt/unparseable files
            // (NEVER deleting valid `PendingAuthRecord` files holding live tokens or actively locked in-flight records!)
            let pa_dir = tx.paths().pending_auth_dir();
            if is_real_dir(&pa_dir) {
                let _ = fs::set_permissions(&pa_dir, fs::Permissions::from_mode(0o700));
                if let Ok(entries) = fs::read_dir(&pa_dir) {
                    let mut fixed_pa_perms = 0usize;
                    let mut removed_corrupt_pa = 0usize;
                    for entry in entries.flatten() {
                        let p = entry.path();
                        let Some(fname) = p.file_name().and_then(|n| n.to_str()) else {
                            continue;
                        };
                        if !fname.ends_with(".json") || fname.contains(".tmp.") {
                            continue;
                        };
                        let id_opt = fname.strip_suffix(".json");
                        let _held_pa_lock = match id_opt {
                            Some(id_part) if validate_account_id(id_part).is_ok() => {
                                match try_acquire_pending_auth_lock_nonblocking(tx.paths(), id_part)
                                {
                                    Ok(Some(guard)) => Some(guard),
                                    _ => continue,
                                }
                            }
                            _ => None,
                        };
                        let is_valid = read_regular_file_opt_bounded(
                            &p,
                            MAX_STORE_FILE_BYTES,
                            "Pending auth file",
                        )
                        .ok()
                        .flatten()
                        .and_then(|b| serde_json::from_slice::<PendingAuthRecord>(&b).ok())
                        .is_some_and(|rec| {
                            rec.schema_version == STORE_SCHEMA_VERSION
                                && validate_account_id(&rec.id).is_ok()
                                && fname == format!("{}.json", rec.id)
                        });
                        if is_valid {
                            if let Ok(m) = fs::symlink_metadata(&p) {
                                if m.file_type().is_file() && (m.permissions().mode() & 0o077) != 0
                                {
                                    let _ =
                                        fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
                                    fixed_pa_perms += 1;
                                }
                            }
                        } else if fs::symlink_metadata(&p)
                            .map(|m| m.file_type().is_file())
                            .unwrap_or(false)
                            && fs::remove_file(&p).is_ok()
                        {
                            removed_corrupt_pa += 1;
                            if let Some(id_part) = id_opt {
                                let _ = tx.remove_pending_lineage(id_part);
                            }
                        }
                    }
                    if fixed_pa_perms > 0 {
                        repairs_applied.push(format!(
                            "Tightened permissions to 0600 on {fixed_pa_perms} pending_auth file(s)."
                        ));
                    }
                    if removed_corrupt_pa > 0 {
                        repairs_applied.push(format!(
                            "Removed {removed_corrupt_pa} corrupt pending_auth file(s)."
                        ));
                    }
                }
            }

            if fs::symlink_metadata(tx.paths().index_file())
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                if let Ok(entries) = fs::read_dir(tx.paths().accounts_dir()) {
                    let mut recovered_ids = Vec::new();
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().and_then(|e| e.to_str()) == Some("json") {
                            if let Ok(Some(bytes)) =
                                read_regular_file_opt_bounded(&p, MAX_STORE_FILE_BYTES, "Account")
                            {
                                if let Ok(acc) = serde_json::from_slice::<AccountRecord>(&bytes) {
                                    let _ =
                                        fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
                                    recovered_ids.push(acc.id);
                                }
                            }
                        }
                    }
                    recovered_ids.sort();
                    if !recovered_ids.is_empty() {
                        let mut idx = StoreIndex::new(now_unix);
                        idx.selected_account_id = recovered_ids.first().cloned();
                        idx.account_order = recovered_ids;
                        tx.save_index(&mut idx, now_unix)?;
                        repairs_applied
                            .push("Rebuilt missing index.json from account files.".into());
                    }
                }
            }

            let seq_path = tx.paths().auth_sequence_file();
            if let Ok(m) = fs::symlink_metadata(&seq_path) {
                if m.file_type().is_file() {
                    let orig_mode = m.permissions().mode() & 0o777;
                    if orig_mode != 0o600 {
                        let _ = fs::set_permissions(&seq_path, fs::Permissions::from_mode(0o600));
                    }
                    if let Ok(Some(cur_seq)) = repo.read_auth_sequence_readonly() {
                        if orig_mode != 0o600 {
                            repairs_applied.push(
                                "Repaired permissions to 0600 on auth_sequence.json.".into(),
                            );
                        }
                        let max_obs = repo
                            .max_valid_account_auth_generation_lossy()
                            .unwrap_or(0)
                            .max(
                                repo.list_valid_pending_auth_lossy()
                                    .into_iter()
                                    .map(|p| p.auth_seq)
                                    .max()
                                    .unwrap_or(0),
                            );
                        if cur_seq.last_auth_seq < max_obs
                            && tx.ensure_auth_sequence_at_least(max_obs).is_ok()
                        {
                            repairs_applied.push(
                                "Advanced auth_sequence.json to match live account and pending generations."
                                    .into(),
                            );
                        }
                    } else if let Ok(snap) = repo.read_snapshot() {
                        let pa_dir_clean = match fs::read_dir(tx.paths().pending_auth_dir()) {
                            Ok(entries) => entries.flatten().all(|ent| {
                                let p = ent.path();
                                let Some(fname) = p.file_name().and_then(|n| n.to_str()) else {
                                    return true;
                                };
                                if !fname.ends_with(".json") || fname.contains(".tmp.") {
                                    return true;
                                }
                                read_regular_file_opt_bounded(
                                    &p,
                                    MAX_STORE_FILE_BYTES,
                                    "Pending auth file",
                                )
                                .ok()
                                .flatten()
                                .and_then(|b| serde_json::from_slice::<PendingAuthRecord>(&b).ok())
                                .is_some_and(|rec| {
                                    rec.schema_version == STORE_SCHEMA_VERSION
                                        && validate_account_id(&rec.id).is_ok()
                                        && fname == format!("{}.json", rec.id)
                                })
                            }),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                            Err(_) => false,
                        };
                        if pa_dir_clean {
                            let max_obs = snap
                                .accounts
                                .iter()
                                .map(|a| a.auth_generation)
                                .chain(std::iter::once(
                                    repo.max_valid_account_auth_generation_lossy().unwrap_or(0),
                                ))
                                .chain(
                                    repo.list_valid_pending_auth_lossy()
                                        .into_iter()
                                        .map(|p| p.auth_seq),
                                )
                                .max()
                                .unwrap_or(0);
                            if tx.write_auth_sequence_state(max_obs).is_ok() {
                                repairs_applied.push(
                                    "Rebuilt corrupt auth_sequence.json from live account and pending generations."
                                        .into(),
                                );
                            }
                        }
                    }
                }
            }

            // Reconcile dangling candidate_account_ids in policy.json if any exist
            if fs::symlink_metadata(tx.paths().policy_file())
                .is_ok_and(|m| m.file_type().is_file())
            {
                if let Ok(mut pol) = repo.read_policy() {
                    let idx = tx.load_index_or_init(now_unix)?;
                    let known: HashSet<&str> =
                        idx.account_order.iter().map(String::as_str).collect();
                    let before_len = pol.candidate_account_ids.len();
                    pol.candidate_account_ids
                        .retain(|cid| known.contains(cid.as_str()));
                    let pruned = before_len - pol.candidate_account_ids.len();
                    if pruned > 0 {
                        if pol.candidate_account_ids.is_empty() {
                            pol.enabled = false;
                        }
                        tx.save_policy(&mut pol, None, now_unix)?;
                        repairs_applied.push(format!(
                            "Pruned {pruned} dangling candidate account ID(s) from policy.json."
                        ));
                    }
                }
            }
            Ok(())
        })?;
    }

    // Pure read-only checks after any requested `--fix`
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
                            "Pending auth file '{}' has insecure permissions ({mode:04o}); run `agy-switch-cli doctor --fix`.",
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
                    "Auth sequence file '{}' has insecure permissions ({mode:04o}); run `agy-switch-cli doctor --fix`.",
                    paths.auth_sequence_file().display()
                ));
            }
        }
    }
    let cfg_res = repo.read_config_with_warnings();
    let lineage_res = repo.validate_all_token_lineage_readonly();
    let slot_state = backend.inspect_slot(paths);
    let journal = read_journal_readonly(paths)?;
    let journal_diag = diagnose_journal(journal.as_ref(), &slot_state);
    let dbus_warning = (!backend.uses_keyring())
        .then(detect_dbus_session_socket_warning)
        .flatten();
    let runtime_state = observe_runtime_state(paths);
    let dstate_res = read_daemon_state_readonly(paths);

    let agy_probe = if args.verify_agy {
        Some(probe_local_agy_version_isolated().await)
    } else {
        None
    };

    // Check active slot directory cleanliness (must contain ONLY `antigravity-oauth-token`)
    let mut stray_slot_files = Vec::new();
    if let Ok(entries) = fs::read_dir(&paths.active_slot_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name != "antigravity-oauth-token" {
                    stray_slot_files.push(name.to_string());
                }
            }
        }
    }
    stray_slot_files.sort();

    let agy_json = match &agy_probe {
        Some(Ok((bin, ver, verified))) => serde_json::json!({
            "checked": true,
            "executable": bin,
            "version": ver,
            "is_verified_version": verified,
            "verified_versions": VERIFIED_AGY_VERSIONS,
        }),
        Some(Err(err)) => serde_json::json!({
            "checked": true,
            "error": err,
            "verified_versions": VERIFIED_AGY_VERSIONS,
        }),
        None => serde_json::json!({
            "checked": false,
            "verified_versions": VERIFIED_AGY_VERSIONS,
        }),
    };

    let store_ok = snap_res.is_ok();
    let slot_initialized = !matches!(slot_state, SlotInspectState::Uninitialized);
    let slot_corrupt = matches!(slot_state, SlotInspectState::Corrupt(_));
    let session_identity = snap_res
        .as_ref()
        .ok()
        .map(|snap| resolve_session_identity(&slot_state, snap))
        .unwrap_or(SessionIdentity::Unverified {
            detail: "Store snapshot unreadable.".into(),
        });

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
        "stray_slot_files": stray_slot_files,
        "session_identity": session_identity,
        "runtime_state": runtime_state,
        "daemon_state_ok": dstate_res.is_ok(),
        "daemon_state_error": dstate_res.as_ref().err().map(|e| &e.message),
        "daemon_paused_on_failure": dstate_res.as_ref().ok().map(|d| d.paused_on_failure),
        "dbus_keyring_warning": dbus_warning,
        "agy_probe": agy_json,
        "repairs_applied": repairs_applied,
    });

    // Determine if doctor must exit with a non-zero diagnostic code (7, 1, or 8)
    if matches!(
        journal_diag,
        JournalDiagnosis::CommittedIndexPending { .. }
            | JournalDiagnosis::RecoveryIncomplete { .. }
    ) {
        return Err(CliError::partial_commit(
            "pending_journal_reconciliation",
            format!("Switch journal requires reconciliation ({journal_diag:?}). Run `agy-switch-cli doctor --fix`."),
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
            "Policy references non-existent candidate account ID(s): {:?}. Run `agy-switch-cli doctor --fix`.",
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

    if let Some(Err(ref probe_err)) = agy_probe {
        return Err(
            CliError::env_not_ready("agy_probe_failed", probe_err.clone()).with_details(report),
        );
    }

    if json_mode {
        print_json(&report)?;
    } else {
        println!("agy-switch-cli doctor (v{CLI_PKG_VERSION})");
        println!("  Store status:      OK");
        println!("  Journal status:    {:?}", journal_diag);
        println!("  Slot initialized:  {}", slot_initialized);
        println!(
            "  Session identity:  {}",
            format_session_identity_human(&session_identity)
        );
        println!(
            "  Runtime state:     {}",
            format_runtime_state_human(&runtime_state)
        );
        if let Ok(ref ds) = dstate_res {
            println!(
                "  Daemon state:      OK (paused_on_failure={})",
                ds.paused_on_failure
            );
        }
        if !stray_slot_files.is_empty() {
            let safe_stray: Vec<String> =
                stray_slot_files.iter().map(|s| terminal_text(s)).collect();
            println!(
                "  Stray slot files:  WARNING — unexpected files in active slot dir: {safe_stray:?} (run `doctor --fix` to clean orphan .tmp. files)"
            );
        }
        for cw in &config_warnings {
            println!("  Config warning:    {}", terminal_text(cw));
        }
        if let Some(ref w) = dbus_warning {
            println!("  D-Bus note:        {}", terminal_text(w));
        }
        if let Some(Ok((ref bin, ref ver, verified))) = agy_probe {
            println!(
                "  Official agy:      {} v{} ({})",
                bin.display(),
                ver,
                if verified {
                    "verified"
                } else {
                    "unverified version — consumer contract not yet certified for this release"
                }
            );
        }
        for r in &repairs_applied {
            println!("  Applied fix:       {}", terminal_text(r));
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
