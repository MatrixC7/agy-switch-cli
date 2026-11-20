use agy_switch_cli::domain::account::AccountRecord;
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::error::ExitCode;
use agy_switch_cli::oauth::refresh::OAuthEndpoints;
use agy_switch_cli::oauth::registry::OAuthClientRegistry;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend};
use agy_switch_cli::session::journal::{
    diagnose_journal, read_journal_readonly, reconcile_journal_locked, JournalDiagnosis,
};
use agy_switch_cli::session::payload::serialize_session_payload;
use agy_switch_cli::store::locks::ActiveSlotLock;
use agy_switch_cli::store::repository::StoreRepository;
use agy_switch_cli::switching::executor::{execute_switch, SwitchOptions};
use agy_switch_cli::transport::client::MockTransport;
use serde_json::json;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

static FAULT_ENV_MUTEX: AsyncMutex<()> = AsyncMutex::const_new(());

struct ScopedEnvVar {
    key: &'static str,
    prev: Option<OsString>,
}

impl ScopedEnvVar {
    fn set(key: &'static str, val: impl AsRef<OsStr>) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, val);
        Self { key, prev }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

fn setup_isolated(tmp: &std::path::Path) -> (HeadlessPaths, StoreRepository, ScopedEnvVar) {
    let home = tmp.join("home");
    let data = tmp.join("data");
    let cache = tmp.join("cache").join("agy-switch-cli");
    let proc_dir = tmp.join("empty_proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&proc_dir).unwrap();
    let proc_guard = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir);
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    (paths, repo, proc_guard)
}

fn make_account(
    id: &str,
    email: &str,
    refresh_token: &str,
    expiry: i64,
    now: i64,
) -> AccountRecord {
    let tok = TokenRecord {
        access_token: format!("ya29.{id}"),
        refresh_token: refresh_token.into(),
        expires_in: 3600,
        expiry_timestamp: expiry,
        token_type: "Bearer".into(),
        id_token: None,
        oauth_client_key: Some("antigravity_enterprise".into()),
        granted_scopes: Some(vec![
            "openid".into(),
            "https://www.googleapis.com/auth/cloud-platform".into(),
        ]),
        project_id: None,
        is_gcp_tos: true,
    };
    AccountRecord::new(id.into(), email.into(), tok, now)
}

#[tokio::test]
async fn rotated_refresh_token_is_never_rolled_back_when_slot_write_fails_with_enospc() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    // Seed acc-old in active slot, and acc-target with an expired access_token so switch refreshes it
    let acc_old = make_account(
        "acc-old",
        "old@example.invalid",
        "1//OLD_SLOT_RT",
        now + 7200,
        now,
    );
    let acc_target = make_account(
        "acc-target",
        "target@example.invalid",
        "1//INITIAL_TARGET_RT",
        now + 10,
        now,
    );

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_old.clone(), true, now)?;
        tx.upsert_account(acc_target.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    let initial_slot_payload = serialize_session_payload(&acc_old.token).unwrap();
    backend.write_slot(&paths, &initial_slot_payload).unwrap();

    // Mock Google OAuth returning a ROTATED refresh_token!
    let mock = MockTransport::from_queue([Ok(MockTransport::json_response(
        200,
        json!({
            "access_token": "ya29.NEW_TARGET_AT",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "1//SERVER_ROTATED_NEW_RT",
            "scope": "openid https://www.googleapis.com/auth/cloud-platform"
        }),
    ))]);

    // Inject ENOSPC specifically on `antigravity-oauth-token` write!
    let fault_guard = ScopedEnvVar::set(
        "AGY_SWITCH_CLI_FAULT_SPEC",
        "before_write:antigravity-oauth-token:enospc",
    );

    let res = execute_switch(
        &repo,
        &backend,
        &mock,
        &OAuthEndpoints {
            base_backoff: Duration::from_millis(5),
            ..OAuthEndpoints::default()
        },
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-target",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now,
    )
    .await;

    drop(fault_guard);

    let err = res.unwrap_err();
    assert_eq!(err.error_code, "disk_full_enospc");

    // 1. Active slot retains acc-old untouched
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        initial_slot_payload
    );
    // 2. Local index still selects acc-old
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-old")
    );
    // 3. CRITICAL INVARIANT: `acc-target` on disk MUST retain `1//SERVER_ROTATED_NEW_RT`, NEVER rolled back!
    let saved_target = repo.read_account_unchecked("acc-target").unwrap();
    assert_eq!(saved_target.token.refresh_token, "1//SERVER_ROTATED_NEW_RT");
    assert_eq!(saved_target.token.access_token, "ya29.NEW_TARGET_AT");
}

#[tokio::test]
async fn index_failure_after_slot_commit_returns_exit_7_committed_index_pending_and_reconciles() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    let acc_a = make_account("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_account("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // Inject EROFS right at `before_index_commit` (AFTER `antigravity-oauth-token` has committed!)
    let fault_guard = ScopedEnvVar::set(
        "AGY_SWITCH_CLI_FAULT_SPEC",
        "before_index_commit:index.json:erofs",
    );

    let err = execute_switch(
        &repo,
        &backend,
        &MockTransport::default(),
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-b",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now,
    )
    .await
    .unwrap_err();

    drop(fault_guard);

    assert_eq!(err.exit_code, ExitCode::PartialCommitOrRecovery);
    assert_eq!(err.error_code, "committed_index_pending");
    assert!(err.message.contains("生效位凭据已切换至目标账号"));

    // Active slot IS already acc-b, while index.json is still acc-a!
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_B"));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );

    // Journal diagnosis accurately identifies `CommittedIndexPending`
    let journal = read_journal_readonly(&paths).unwrap();
    let diag = diagnose_journal(journal.as_ref(), &backend.inspect_slot(&paths));
    assert_eq!(
        diag,
        JournalDiagnosis::CommittedIndexPending {
            target_account_id: "acc-b".into()
        }
    );

    // Reconcile completes index.json alignment!
    let l1 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
    let fixed_diag = reconcile_journal_locked(&l1, &repo, &backend, true, now + 10).unwrap();
    drop(l1);
    assert!(matches!(
        fixed_diag,
        JournalDiagnosis::CommittedIndexPending { .. }
    ));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );
    assert!(read_journal_readonly(&paths).unwrap().is_none());
}

#[tokio::test]
async fn failed_slot_readback_and_failed_rollback_records_recovery_incomplete_exit_7() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    let acc_a = make_account("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_account("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // Inject readback corruption on slot write AND failure on slot_rollback!
    let fault_guard = ScopedEnvVar::set(
        "AGY_SWITCH_CLI_FAULT_SPEC",
        "after_rename:antigravity-oauth-token:corrupt_after_rename;slot_rollback:antigravity-oauth-token:io",
    );

    let err = execute_switch(
        &repo,
        &backend,
        &MockTransport::default(),
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-b",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now,
    )
    .await
    .unwrap_err();

    drop(fault_guard);

    assert_eq!(err.exit_code, ExitCode::PartialCommitOrRecovery);
    assert_eq!(err.error_code, "recovery_incomplete");

    // Read-only `status --json` and `switch --dry-run` MUST report exit code 7 (`RecoveryIncomplete`),
    // while manual `switch` self-heals the journal and completes the switch cleanly!
    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    let proc_dir = tmp.path().join("empty_proc");
    let no_agy = tmp.path().join("no-host-agy");

    let status_check = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &paths.home_dir)
        .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
        .env("AGY_SWITCH_CLI_AGY_BIN", &no_agy)
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "status",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(status_check.status.code(), Some(7));

    let dry_blocked = execute_switch(
        &repo,
        &backend,
        &MockTransport::default(),
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-b",
        &SwitchOptions {
            dry_run: true,
            allow_running: false,
        },
        now + 5,
    )
    .await
    .unwrap_err();
    assert_eq!(dry_blocked.exit_code, ExitCode::PartialCommitOrRecovery);

    let sw_healed = execute_switch(
        &repo,
        &backend,
        &MockTransport::default(),
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-b",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now + 6,
    )
    .await
    .unwrap();
    assert_eq!(sw_healed.target_account_id, "acc-b");
    assert!(read_journal_readonly(&paths).unwrap().is_none());
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn subprocess_crash_after_slot_commit_is_detected_by_status_and_reconciled_on_write() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = jiff::Timestamp::now().as_second();
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("empty_proc");
    let no_agy = tmp.path().join("no-host-agy");
    fs::create_dir_all(&run_dir).unwrap();

    let acc_a = make_account("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_account("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // Crash subprocess immediately after `antigravity-oauth-token` rename (`after_slot_commit:index.json:abort`)
    let crashed = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &paths.home_dir)
        .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
        .env("AGY_SWITCH_CLI_AGY_BIN", &no_agy)
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_slot_commit:index.json:abort",
        )
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "switch",
            "acc-b",
        ])
        .output()
        .unwrap();
    assert_eq!(crashed.status.code(), Some(137));

    // Read-only `status` sees `CommittedIndexPending` (exit code 7)
    let st1 = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &paths.home_dir)
        .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
        .env("AGY_SWITCH_CLI_AGY_BIN", &no_agy)
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "status",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(st1.status.code(), Some(7));

    // Subsequent write command reconciles `index.json` to `acc-b`!
    let reconcile_out = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &paths.home_dir)
        .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
        .env("AGY_SWITCH_CLI_AGY_BIN", &no_agy)
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "policy",
            "set",
            "--reserve",
            "10",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(reconcile_out.status.code(), Some(0));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );
}

#[tokio::test]
async fn journal_reconcile_unwedges_recovery_incomplete_with_bare_imported_prev_account_and_deleted_pending_target(
) {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    // `acc-imported` has empty `access_token` (as created by `accounts import` from bare refresh_token)
    let mut acc_imported = make_account("acc-imported", "imp@example.invalid", "1//RT_IMP", 1, now);
    acc_imported.token.access_token.clear();
    // `acc-target` has valid access_token
    let acc_target = make_account(
        "acc-target",
        "t@example.invalid",
        "1//RT_T",
        now + 7200,
        now,
    );

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_imported.clone(), true, now)?;
        tx.upsert_account(acc_target.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    // Inject readback corruption + rollback failure when switching from `acc-imported` (no slot file yet) to `acc-target`
    let fault_guard1 = ScopedEnvVar::set(
        "AGY_SWITCH_CLI_FAULT_SPEC",
        "after_rename:antigravity-oauth-token:corrupt_after_rename;slot_rollback:antigravity-oauth-token:io",
    );
    let err = execute_switch(
        &repo,
        &backend,
        &MockTransport::default(),
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-target",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now,
    )
    .await
    .unwrap_err();
    drop(fault_guard1);
    assert_eq!(err.error_code, "recovery_incomplete");

    // `reconcile_journal_locked` MUST skip unserializable `acc-imported` (`access_token == ""`)
    // and repair cleanly using `acc-target` instead of failing!
    let l1 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
    reconcile_journal_locked(&l1, &repo, &backend, true, now + 5).unwrap();
    drop(l1);
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-target")
    );
    assert!(read_journal_readonly(&paths).unwrap().is_none());

    // Now test `CommittedIndexPending` where `acc-deleted` was deleted before reconciliation!
    let acc_deleted = make_account(
        "acc-deleted",
        "del@example.invalid",
        "1//RT_DEL",
        now + 7200,
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc_deleted, false, now + 6))
        .unwrap();
    let fault_guard2 = ScopedEnvVar::set(
        "AGY_SWITCH_CLI_FAULT_SPEC",
        "before_index_commit:index.json:erofs",
    );
    let err2 = execute_switch(
        &repo,
        &backend,
        &MockTransport::default(),
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-deleted",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now + 7,
    )
    .await
    .unwrap_err();
    drop(fault_guard2);
    assert_eq!(err2.error_code, "committed_index_pending");

    // User forcibly deletes `acc-deleted` before journal reconciliation
    repo.with_write_lock(|tx| tx.delete_account("acc-deleted", true, now + 8))
        .unwrap();

    // `reconcile_journal_locked` MUST clear the stale journal without wedging on `AccountNotFound`!
    let l1 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
    reconcile_journal_locked(&l1, &repo, &backend, true, now + 9).unwrap();
    drop(l1);
    assert!(read_journal_readonly(&paths).unwrap().is_none());
}

#[tokio::test]
async fn write_paths_and_daemon_reconcile_journal_or_pause_and_switch_cleans_slot_tmp_files() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = jiff::Timestamp::now().as_second();
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("empty_proc");
    let no_agy = tmp.path().join("no-host-agy");
    fs::create_dir_all(&run_dir).unwrap();

    let acc_a = make_account("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_account("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    let cli = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &paths.home_dir)
            .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
            .env("AGY_SWITCH_CLI_AGY_BIN", &no_agy)
            .args([
                "--data-dir",
                paths.data_dir.to_str().unwrap(),
                "--no-remote-version",
            ]);
        c
    };

    // 1. Crash switch after slot commit (`CommittedIndexPending`: slot=acc-b, index.json=acc-a)
    let crashed = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_slot_commit:index.json:abort",
        )
        .args(["switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(crashed.status.code(), Some(137));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );

    // `accounts delete acc-b` WITHOUT `--clear-active-slot` and WITHOUT `--force` MUST reconcile
    // `CommittedIndexPending` first (updating index.json to `acc-b`), and therefore refuse to delete
    // the active selected account `acc-b` without `--force`!
    let del_no_force = cli()
        .args(["accounts", "delete", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(del_no_force.status.code(), Some(2));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );
    assert!(read_journal_readonly(&paths).unwrap().is_none());

    // 2. Crash another switch to `acc-a`, then verify `policy set` auto-reconciles `CommittedIndexPending`!
    let crashed2 = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_slot_commit:index.json:abort",
        )
        .args(["switch", "acc-a"])
        .output()
        .unwrap();
    assert_eq!(crashed2.status.code(), Some(137));
    let pol_out = cli()
        .args(["policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(pol_out.status.code(), Some(0));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );
    assert!(read_journal_readonly(&paths).unwrap().is_none());

    // 2b. Crash switch BEFORE slot commit (`AbortedUncommitted`), verify `accounts enable` auto-reconciles it!
    let crashed_pre = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_token_refreshed:antigravity-oauth-token:abort",
        )
        .args(["switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(crashed_pre.status.code(), Some(137));
    assert!(read_journal_readonly(&paths).unwrap().is_some());
    let en_out = cli()
        .args(["accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(en_out.status.code(), Some(0));
    assert!(
        read_journal_readonly(&paths).unwrap().is_none(),
        "AbortedUncommitted journal must be auto-cleared by write commands"
    );
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );

    // 3. R3-15: Create (a) an EXPIRED tool-owned `.tmp.agy-switch-cli.<uuid>` file, (b) a FRESH
    //    tool-owned temp file, and (c) a FOREIGN `.tmp.` file in `active_slot_dir`.
    //    Read-only `status` leaves all untouched; manual `switch` cleans ONLY the expired owned file
    //    and preserves both the fresh owned file and the foreign `.tmp.` file!
    let expired_owned_tmp = paths.active_slot_dir.join(format!(
        "antigravity-oauth-token{}{}",
        agy_switch_cli::store::fs_atomic::OWNED_TMP_MARKER,
        uuid::Uuid::new_v4()
    ));
    let fresh_owned_tmp = paths.active_slot_dir.join(format!(
        "antigravity-oauth-token{}{}",
        agy_switch_cli::store::fs_atomic::OWNED_TMP_MARKER,
        uuid::Uuid::new_v4()
    ));
    let foreign_tmp = paths.active_slot_dir.join("other-tool.tmp.keep-me");
    fs::write(&expired_owned_tmp, b"partial-junk").unwrap();
    fs::write(&fresh_owned_tmp, b"fresh-in-flight").unwrap();
    fs::write(&foreign_tmp, b"foreign-tool-file").unwrap();
    // Backdate `expired_owned_tmp` mtime by 180 seconds via `File::set_modified`
    {
        let old_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(180);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&expired_owned_tmp)
            .unwrap()
            .set_modified(old_mtime)
            .unwrap();
    }
    let st_human = cli().arg("status").output().unwrap();
    assert_eq!(st_human.status.code(), Some(0));
    let st_stdout = String::from_utf8_lossy(&st_human.stdout);
    assert!(
        !st_stdout.contains("Stray slot files:") && !st_stdout.contains("Session identity:"),
        "status human output must omit stray_slot_files and session_identity: {st_stdout}"
    );
    assert!(expired_owned_tmp.exists());
    assert!(fresh_owned_tmp.exists());
    assert!(foreign_tmp.exists());

    let sw_clean_tmp = cli().args(["switch", "acc-a"]).output().unwrap();
    assert_eq!(
        sw_clean_tmp.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sw_clean_tmp.stderr)
    );
    assert!(
        !expired_owned_tmp.exists(),
        "manual switch must remove expired tool-owned temp file under L1"
    );
    assert!(
        fresh_owned_tmp.exists(),
        "manual switch must NOT delete fresh (<60s) tool-owned temp file"
    );
    assert!(
        foreign_tmp.exists(),
        "manual switch must NOT delete foreign `.tmp.` files in shared slot dir"
    );
    fs::remove_file(&fresh_owned_tmp).unwrap();
    fs::remove_file(&foreign_tmp).unwrap();

    // 4. Inject `RecoveryIncomplete`: verify read-only `status` & `switch --dry-run` exit 7,
    //    `daemon --once` enters `PausedOnFailure`, and manual `switch` self-heals & clears pause!
    let rec_inc = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_rename:antigravity-oauth-token:corrupt_after_rename;slot_rollback:antigravity-oauth-token:io",
        )
        .args(["switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(rec_inc.status.code(), Some(7));

    for ro_blocked in [
        vec!["status", "--json"],
        vec!["switch", "--dry-run", "acc-b"],
    ] {
        let out = cli().args(&ro_blocked).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(7),
            "Expected exit 7 on {ro_blocked:?}, got {:?} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // `daemon --once` detects `RecoveryIncomplete` and persists `paused_on_failure = true`!
    let daemon_out = cli().args(["daemon", "--once"]).output().unwrap();
    assert_eq!(daemon_out.status.code(), Some(0));
    let dstate = agy_switch_cli::switching::daemon::read_daemon_state_readonly(&paths).unwrap();
    assert!(
        dstate.paused_on_failure,
        "Daemon must enter PausedOnFailure on RecoveryIncomplete"
    );

    // Manual `switch acc-b` self-heals `RecoveryIncomplete` AND clears `paused_on_failure`!
    let manual_sw = cli().args(["switch", "acc-b"]).output().unwrap();
    assert_eq!(
        manual_sw.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&manual_sw.stderr)
    );
    assert!(read_journal_readonly(&paths).unwrap().is_none());
    let dstate_after =
        agy_switch_cli::switching::daemon::read_daemon_state_readonly(&paths).unwrap();
    assert!(
        !dstate_after.paused_on_failure,
        "Manual switch must clear daemon paused_on_failure!"
    );

    // 5. `clear_slot_intent` `RecoveryIncomplete` + concurrent external `agy` login on disk:
    //    `reconcile_pending_journal_before_write` MUST preserve the external credential without clobbering it
    //    or deleting `acc-b`!
    let ext_acc = make_account(
        "acc-ext",
        "ext@example.invalid",
        "1//RT_EXT",
        now + 7200,
        now,
    );
    let ext_payload = serialize_session_payload(&ext_acc.token).unwrap();
    let prev_b_payload = serialize_session_payload(&acc_b.token).unwrap();
    let clear_inc_j = json!({
        "schema_version": 1,
        "operation_id": "op-clear-inc-ext",
        "phase": "recovery_incomplete",
        "prev_selected_account_id": "acc-b",
        "target_account_id": "acc-b",
        "prev_slot_digest": agy_switch_cli::session::payload::bytes_sha256_hex(prev_b_payload.as_bytes()),
        "token_rotated": false,
        "started_at": now,
        "updated_at": now,
        "clear_slot_intent": true,
        "replica_state": {
            "backend": "file",
            "uses_file": true,
            "file": {
                "prev_present": true,
                "prev_digest": agy_switch_cli::session::payload::bytes_sha256_hex(prev_b_payload.as_bytes()),
                "prev_uniform": true
            }
        }
    });
    fs::write(
        paths.switch_journal_file(),
        serde_json::to_vec_pretty(&clear_inc_j).unwrap(),
    )
    .unwrap();
    fs::write(&paths.active_slot_file, &ext_payload).unwrap();
    let pol_ext_out = cli()
        .args(["policy", "set", "--reserve", "12"])
        .output()
        .unwrap();
    assert_eq!(
        pol_ext_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&pol_ext_out.stderr)
    );
    assert!(read_journal_readonly(&paths).unwrap().is_none());
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_payload,
        "External credential on disk must never be clobbered by clear_slot_intent repair!"
    );
    assert!(
        paths.account_file("acc-b").exists(),
        "Account must not be deleted when external login superseded incomplete clear_slot_intent!"
    );
}

#[tokio::test]
async fn concurrent_non_slot_store_writes_succeed_during_slow_network_switch_without_l1_timeout() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = jiff::Timestamp::now().as_second();
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("empty_proc");
    fs::create_dir_all(&run_dir).unwrap();

    // `acc-a` is active; `acc-b` has an expired token so `execute_switch` awaits slow (450ms) network refresh;
    // `acc-c` is disabled and will be enabled concurrently via subprocess CLI while `switch` holds L1!
    let acc_a = make_account("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_account("acc-b", "b@example.invalid", "1//RT_B_OLD", now - 10, now);
    let mut acc_c = make_account("acc-c", "c@example.invalid", "1//RT_C", now + 7200, now);
    acc_c.disabled = true;

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // Slow OAuth transport taking 450ms (> 250ms!) while `switch_journal.json` is in `Prepared` phase under L1!
    let slow_oauth = MockTransport::from_queue([Ok(MockTransport::json_response(
        200,
        json!({
            "access_token": "ya29.ACC_B_FRESH",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "1//RT_B_ROTATED",
            "scope": "openid https://www.googleapis.com/auth/cloud-platform"
        }),
    ))])
    .with_delay(Duration::from_millis(700));

    let repo_sw = repo.clone();
    let switch_task = tokio::spawn(async move {
        execute_switch(
            &repo_sw,
            &FileSessionBackend,
            &slow_oauth,
            &OAuthEndpoints::default(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "vscode/1.X.X (Antigravity/4.3.0)",
            "acc-b",
            &SwitchOptions {
                dry_run: false,
                allow_running: false,
            },
            now,
        )
        .await
    });

    // Wait until `switch_journal.json` (`Prepared`) is on disk while `switch_task` is mid-network-await
    for _ in 0..40 {
        if paths.switch_journal_file().exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(paths.switch_journal_file().exists());

    let cli = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &paths.home_dir)
            .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
            .args([
                "--data-dir",
                paths.data_dir.to_str().unwrap(),
                "--no-remote-version",
            ]);
        c
    };

    // 1. Concurrent `policy set` and `accounts enable` MUST succeed (exit 0) without L1 timeout!
    let pol_res = cli()
        .args(["policy", "set", "--reserve", "22", "--minimum", "40"])
        .output()
        .unwrap();
    assert_eq!(
        pol_res.status.code(),
        Some(0),
        "policy set failed during slow network switch: stderr={}",
        String::from_utf8_lossy(&pol_res.stderr)
    );
    let enable_res = cli()
        .args(["accounts", "enable", "acc-c"])
        .output()
        .unwrap();
    assert_eq!(
        enable_res.status.code(),
        Some(0),
        "accounts enable failed during slow network switch: stderr={}",
        String::from_utf8_lossy(&enable_res.stderr)
    );

    // 2. Competing `switch` MUST still fail immediately with exit code 5 (`LockBusyOrConflict`)!
    let competing_sw = cli().args(["switch", "acc-c"]).output().unwrap();
    assert_eq!(competing_sw.status.code(), Some(5));

    let sw_outcome = switch_task.await.unwrap().unwrap();
    assert_eq!(sw_outcome.target_account_id, "acc-b");
    assert!(sw_outcome.refresh_token_rotated);

    // Verify all concurrent mutations survived cleanly via field-level merge!
    let final_snap = repo.read_snapshot().unwrap();
    assert_eq!(
        final_snap.index.selected_account_id.as_deref(),
        Some("acc-b")
    );
    assert_eq!(repo.read_policy().unwrap().reserve_percentage, 22);
    assert!(!repo.read_account_unchecked("acc-c").unwrap().disabled);
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_B_ROTATED"
    );
}

#[tokio::test]
async fn synthetic_v120_round3_r301_r302_r315_corrupt_journal_clear_slot_replay_and_pause_clear_failures(
) {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let paths = HeadlessPaths::with_explicit(
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("cache").join("agy-switch-cli"),
    );
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("proc");
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&proc_dir).unwrap();
    fs::create_dir_all(&paths.active_slot_dir).unwrap();
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;
    let now = 1_850_000_000i64;

    let acc_a = make_account("acc-a", "alice@example.com", "1//RT_A", now + 7200, now);
    let acc_b = make_account("acc-b", "bob@example.com", "1//RT_B", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    let payload_a = serialize_session_payload(&acc_a.token).unwrap();
    backend.write_slot(&paths, &payload_a).unwrap();

    let cli = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &paths.home_dir)
            .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
            .env("AGY_SWITCH_CLI_AGY_BIN", tmp.path().join("no-agy"))
            .args([
                "--data-dir",
                paths.data_dir.to_str().unwrap(),
                "--backend",
                "file",
                "--no-remote-version",
            ]);
        c
    };

    // 1. R3-01: Truncated/corrupt `switch_journal.json` in pure `file` env with NO visible D-Bus
    //    MUST NOT be auto-cleared by `policy set` or `switch` (both `status` and `policy set` exit 7 and preserve journal)!
    fs::create_dir_all(paths.state_dir()).unwrap();
    fs::write(
        paths.switch_journal_file(),
        b"{\"schema_version\":1,\"phase\":",
    )
    .unwrap();
    let st_corrupt = cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_corrupt.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());

    let pol_corrupt = cli()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        pol_corrupt.status.code(),
        Some(7),
        "Corrupt journal MUST NOT be cleared under file backend! stderr={}",
        String::from_utf8_lossy(&pol_corrupt.stderr)
    );
    assert!(paths.switch_journal_file().exists());
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        payload_a
    );
    fs::remove_file(paths.switch_journal_file()).unwrap();

    // 2. R3-02 (exact Round-3 reproducer!):
    //    Persistent `before_write:index.json:io` during `accounts delete acc-a --force --clear-active-slot`:
    //    - First `delete` clears active slot, fails `index.json`, preserves journal -> exit 7;
    //    - `status` -> exit 7;
    //    - Under the SAME persistent `index.json` fault, `policy set` MUST exit 7 and PRESERVE journal (NOT clear it!);
    //    - `status` STILL exits 7;
    //    - Once fault is cleared, `policy set` idempotently deletes `acc-a` (policy, index, account file, lineage),
    //      clears journal, and exits 0!
    fs::create_dir_all(paths.token_lineage_dir()).unwrap();
    fs::write(
        paths.token_lineage_file("acc-a"),
        b"{\"schema_version\":1,\"account_id\":\"acc-a\",\"digests\":[],\"truncated\":false}",
    )
    .unwrap();

    let del_fail = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:index.json:io")
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-a",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(del_fail.status.code(), Some(7));
    assert!(!paths.active_slot_file.exists());
    assert!(paths.switch_journal_file().exists());
    assert!(paths.account_file("acc-a").exists());

    let st_after_del = cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_after_del.status.code(), Some(7));

    // Retry under the SAME persistent `index.json` fault -> MUST exit 7 and keep journal!
    let pol_same_fault = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:index.json:io")
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        pol_same_fault.status.code(),
        Some(7),
        "Replay under persistent index.json fault MUST NOT swallow error or clear journal! stdout={} stderr={}",
        String::from_utf8_lossy(&pol_same_fault.stdout),
        String::from_utf8_lossy(&pol_same_fault.stderr)
    );
    assert!(
        paths.switch_journal_file().exists(),
        "clear_slot_intent journal was lost while index.json fault still existed!"
    );
    assert!(paths.account_file("acc-a").exists());
    assert_eq!(
        cli()
            .args(["--json", "status"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );

    // Fault on `accounts/acc-a.json` parent dir fsync ALSO preserves journal (exit 7)!
    let pol_sync_fault = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "sync_parent_dir:acc-a.json:io")
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        pol_sync_fault.status.code(),
        Some(7),
        "Parent dir fsync failure on account removal MUST preserve journal and exit 7!"
    );
    assert!(paths.switch_journal_file().exists());

    // Now clear fault: even though `index.json` ALREADY dropped `acc-a` on the previous attempt,
    // idempotent replay MUST still remove `token_lineage/acc-a.json`, clear journal, and exit 0!
    let pol_ok = cli()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        pol_ok.status.code(),
        Some(0),
        "Idempotent replay after fault cleared must succeed: stderr={}",
        String::from_utf8_lossy(&pol_ok.stderr)
    );
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-a").exists());
    assert!(!paths.token_lineage_file("acc-a").exists());
    assert_eq!(
        cli()
            .args(["--json", "status"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );

    // 3. R3-02 pure file `remove_slot_transactional`: if BOTH `remove_slot` AND restore `write_slot`
    //    fail `sync_parent_dir`, MUST return exit 7 (`recovery_incomplete`), NOT exit 1!
    let payload_b = serialize_session_payload(&acc_b.token).unwrap();
    backend.write_slot(&paths, &payload_b).unwrap();
    let del_sync_fail = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "sync_parent_dir:antigravity-oauth-token:io",
        )
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-b",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(
        del_sync_fail.status.code(),
        Some(7),
        "Unconfirmed file rollback durability MUST return exit 7, stderr={}",
        String::from_utf8_lossy(&del_sync_fail.stderr)
    );
    assert!(paths.switch_journal_file().exists());
    fs::remove_file(paths.switch_journal_file()).unwrap();
    // Re-write slot so `acc-b` is clean for step 4
    backend.write_slot(&paths, &payload_b).unwrap();

    // 4. R3-15: Inject `before_rename:daemon_state.json:io` while daemon is paused -> manual `switch`
    //    MUST NOT return 0 pretending pause cleared (returns exit 7 `daemon_pause_clear_failed`),
    //    and `status` truthfully still reports `daemon_paused_on_failure == true`!
    let paused_state = agy_switch_cli::switching::daemon::DaemonPersistentState {
        paused_on_failure: true,
        paused_reason: Some("synthetic pause".into()),
        consecutive_commit_failures: 3,
        ..agy_switch_cli::switching::daemon::DaemonPersistentState::default()
    };
    repo.with_write_lock(|tx| {
        agy_switch_cli::switching::daemon::save_daemon_state_in_tx(tx.paths(), &paused_state)
    })
    .unwrap();

    let sw_pause_fail = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_rename:daemon_state.json:io",
        )
        .args(["--json", "switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(
        sw_pause_fail.status.code(),
        Some(7),
        "Manual switch must surface daemon_state.json save failure (exit 7): stdout={} stderr={}",
        String::from_utf8_lossy(&sw_pause_fail.stdout),
        String::from_utf8_lossy(&sw_pause_fail.stderr)
    );
    let err_j: serde_json::Value = serde_json::from_slice(&sw_pause_fail.stderr).unwrap();
    assert_eq!(err_j["error_code"], "daemon_pause_clear_failed");
    let st_still_paused = cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_still_paused.status.code(), Some(0));
    let st_j: serde_json::Value = serde_json::from_slice(&st_still_paused.stdout).unwrap();
    assert_eq!(st_j["daemon_paused_on_failure"], true);

    // Clear the pause state cleanly before step 5
    let sw_clear_pause = cli().args(["--json", "switch", "acc-b"]).output().unwrap();
    assert_eq!(sw_clear_pause.status.code(), Some(0));

    // 5. R3-15 (orphan temp cleanup error propagation):
    //    Place an EXPIRED tool-owned temp file in `active_slot_dir` and inject parent-dir fsync
    //    failure specifically on `.tmp.agy-switch-cli.` cleanup -> manual `switch` MUST surface
    //    exit 7 (`slot_temp_cleanup_failed`) instead of silently swallowing it in `write_slot`!
    let expired_tmp_err = paths.active_slot_dir.join(format!(
        "antigravity-oauth-token{}{}",
        agy_switch_cli::store::fs_atomic::OWNED_TMP_MARKER,
        uuid::Uuid::new_v4()
    ));
    fs::write(&expired_tmp_err, b"orphan-needs-fsync").unwrap();
    {
        let old_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(180);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&expired_tmp_err)
            .unwrap()
            .set_modified(old_mtime)
            .unwrap();
    }
    let sw_tmp_sync_fail = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "sync_parent_dir:.tmp.agy-switch-cli.:io",
        )
        .args(["--json", "switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(
        sw_tmp_sync_fail.status.code(),
        Some(7),
        "Orphan temp cleanup parent-dir fsync error MUST be surfaced as exit 7, NOT swallowed! stdout={} stderr={}",
        String::from_utf8_lossy(&sw_tmp_sync_fail.stdout),
        String::from_utf8_lossy(&sw_tmp_sync_fail.stderr)
    );
    let tmp_err_j: serde_json::Value = serde_json::from_slice(&sw_tmp_sync_fail.stderr).unwrap();
    assert_eq!(tmp_err_j["error_code"], "slot_temp_cleanup_failed");

    // 6. R3-01 + R3-02 (`clear_slot_intent` at `CommittedIndexPending` + external credential appearing
    //    before Stage 2 finishes):
    //    - Delete `acc-c` with `--clear-active-slot` while `index.json` fails -> Stage 1 clears slot,
    //      journal persists at `CommittedIndexPending`, `acc-c` remains on disk (exit 7);
    //    - External `agy` writes a brand new credential (`ext@example.com`) into `active_slot_file`;
    //    - While `index.json` fault persists, `policy set` MUST exit 7 and preserve journal + external slot;
    //    - Once fault clears, `policy set` MUST preserve the external slot credential AND complete
    //      Stage 2 deletion of `acc-c` (`accounts/acc-c.json` removed, journal cleared, exit 0)!
    let acc_c = make_account("acc-c", "charlie@example.com", "1//RT_C", now + 7200, now);
    let payload_c = serialize_session_payload(&acc_c.token).unwrap();
    repo.with_write_lock(|tx| tx.upsert_account(acc_c.clone(), true, now))
        .unwrap();
    backend.write_slot(&paths, &payload_c).unwrap();

    let del_c_fail = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:index.json:io")
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-c",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(del_c_fail.status.code(), Some(7));
    assert!(!paths.active_slot_file.exists());
    assert!(paths.switch_journal_file().exists());
    assert!(paths.account_file("acc-c").exists());

    let ext_acc = make_account(
        "acc-ext-only",
        "external@example.com",
        "1//RT_EXT_ONLY",
        now + 7200,
        now,
    );
    let ext_payload = serialize_session_payload(&ext_acc.token).unwrap();
    backend.write_slot(&paths, &ext_payload).unwrap();

    let replay_still_fault = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:index.json:io")
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        replay_still_fault.status.code(),
        Some(7),
        "CommittedIndexPending clear-slot replay with external slot MUST NOT clear journal when Stage 2 still fails!"
    );
    assert!(paths.switch_journal_file().exists());
    assert!(paths.account_file("acc-c").exists());
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_payload
    );

    let replay_ext_ok = cli()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        replay_ext_ok.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&replay_ext_ok.stderr)
    );
    assert!(!paths.switch_journal_file().exists());
    assert!(
        !paths.account_file("acc-c").exists(),
        "Stage 2 deletion of `acc-c` MUST complete even when an external credential appeared in the slot!"
    );
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_payload,
        "External credential in active slot MUST be preserved without overwriting!"
    );

    // 7. R3-02 (`clear_slot_intent` target `auth_generation` mismatch guard):
    //    If target account rotated (`auth_generation` incremented) before replay, replay MUST refuse
    //    to delete the rotated account and preserve journal (exit 7)!
    let acc_d = make_account("acc-d", "dave@example.com", "1//RT_D", now + 7200, now);
    let payload_d = serialize_session_payload(&acc_d.token).unwrap();
    repo.with_write_lock(|tx| tx.upsert_account(acc_d.clone(), true, now))
        .unwrap();
    backend.write_slot(&paths, &payload_d).unwrap();
    let del_d_fail = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:index.json:io")
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-d",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(del_d_fail.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    // Bump `acc-d` `auth_generation` directly on disk to simulate concurrent reauthorization/rotation
    let mut rotated_d = repo.read_account_unchecked("acc-d").unwrap();
    rotated_d.auth_generation = rotated_d.auth_generation.saturating_add(1);
    fs::write(
        paths.account_file("acc-d"),
        serde_json::to_vec_pretty(&rotated_d).unwrap(),
    )
    .unwrap();
    let mismatch_replay = cli()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        mismatch_replay.status.code(),
        Some(7),
        "auth_generation mismatch MUST refuse Stage 2 deletion and preserve journal!"
    );
    assert!(paths.switch_journal_file().exists());
    assert!(paths.account_file("acc-d").exists());
}

#[tokio::test]
async fn synthetic_v120_round4_r402_clear_slot_replay_enforces_stage_and_parent_dir_fsync() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let paths = HeadlessPaths::with_explicit(
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("cache").join("agy-switch-cli"),
    );
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("proc");
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&proc_dir).unwrap();
    fs::create_dir_all(&paths.active_slot_dir).unwrap();
    fs::create_dir_all(paths.token_lineage_dir()).unwrap();
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;
    let now = 1_850_000_000i64;

    let cli = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &paths.home_dir)
            .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
            .env("AGY_SWITCH_CLI_AGY_BIN", tmp.path().join("no-agy"))
            .args([
                "--data-dir",
                paths.data_dir.to_str().unwrap(),
                "--backend",
                "file",
                "--no-remote-version",
            ]);
        c
    };

    let write_lineage = |id: &str| {
        fs::write(
            paths.token_lineage_file(id),
            format!(
                "{{\"schema_version\":1,\"account_id\":\"{id}\",\"digests\":[],\"truncated\":false}}"
            ),
        )
        .unwrap();
    };

    // Keep one permanent account and populate 3 disabled accounts as independent replay controls.
    let acc_keep = make_account(
        "acc-keep",
        "keep@example.com",
        "1//RT_KEEP",
        now + 7200,
        now,
    );
    let acc_clean = make_account(
        "acc-clean",
        "alice@example.com",
        "1//RT_CLEAN",
        now + 7200,
        now,
    );
    let mut acc_dis = make_account("acc-dis", "dis1@example.com", "1//RT_DIS1", now + 7200, now);
    acc_dis.disabled = true;
    acc_dis.disabled_code = Some(agy_switch_cli::domain::account::DisableReasonCode::Manual);
    let mut acc_dis2 = make_account(
        "acc-dis2",
        "dis2@example.com",
        "1//RT_DIS2",
        now + 7200,
        now,
    );
    acc_dis2.disabled = true;
    acc_dis2.disabled_code = Some(agy_switch_cli::domain::account::DisableReasonCode::Manual);
    let mut acc_dis3 = make_account(
        "acc-dis3",
        "dis3@example.com",
        "1//RT_DIS3",
        now + 7200,
        now,
    );
    acc_dis3.disabled = true;
    acc_dis3.disabled_code = Some(agy_switch_cli::domain::account::DisableReasonCode::Manual);

    let mut pol = repo.read_policy().unwrap();
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_keep.clone(), false, now)?;
        tx.upsert_account(acc_dis.clone(), false, now)?;
        tx.upsert_account(acc_dis2.clone(), false, now)?;
        tx.upsert_account(acc_dis3.clone(), false, now)?;
        tx.upsert_account(acc_clean.clone(), true, now)?;
        pol.candidate_account_ids = vec!["acc-clean".into(), "acc-keep".into()];
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    write_lineage("acc-clean");
    backend
        .write_slot(
            &paths,
            &serialize_session_payload(&acc_clean.token).unwrap(),
        )
        .unwrap();

    // 1. Healthy pure `file` clear-slot delete -> exits 0, removes target + references, no journal, keeps others
    let clean_out = cli()
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-clean",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(
        clean_out.status.code(),
        Some(0),
        "Clean clear-slot delete must exit 0: stderr={}",
        String::from_utf8_lossy(&clean_out.stderr)
    );
    assert!(!paths.active_slot_file.exists());
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-clean").exists());
    assert!(!paths.token_lineage_file("acc-clean").exists());
    assert!(!repo
        .read_policy()
        .unwrap()
        .candidate_account_ids
        .iter()
        .any(|id| id == "acc-clean"));
    assert!(!repo
        .read_snapshot()
        .unwrap()
        .index
        .account_order
        .iter()
        .any(|id| id == "acc-clean"));
    assert!(paths.account_file("acc-keep").exists());
    assert!(repo.read_account_unchecked("acc-dis").unwrap().disabled);

    // 2. Persistent `sync_parent_dir:index.json:io` (post-rename fsync failure):
    //    First delete -> exit 7 (`committed_index_pending`);
    //    `accounts enable acc-dis` AND `policy set --reserve 10` under SAME fault -> BOTH exit 7 & preserve journal;
    //    After fault clears & distinct external cred appears -> `accounts enable acc-dis` exits 0, completes
    //    Stage 2 cleanup, removes journal, enables `acc-dis`, and preserves external slot credential!
    let acc_idx = make_account("acc-idx", "bob@example.com", "1//RT_IDX", now + 7200, now);
    let mut pol = repo.read_policy().unwrap();
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_idx.clone(), true, now)?;
        pol.candidate_account_ids = vec!["acc-idx".into(), "acc-keep".into()];
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    write_lineage("acc-idx");
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_idx.token).unwrap())
        .unwrap();

    let idx_del = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "sync_parent_dir:index.json:io")
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-idx",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(idx_del.status.code(), Some(7));
    assert!(!paths.active_slot_file.exists());
    assert!(paths.switch_journal_file().exists());
    assert_eq!(
        read_journal_readonly(&paths).unwrap().unwrap().phase,
        agy_switch_cli::session::journal::JournalPhase::CommittedIndexPending
    );
    // Rename already dropped `acc-idx` from `index.json` even though fsync failed
    assert!(!repo
        .read_snapshot()
        .unwrap()
        .index
        .account_order
        .iter()
        .any(|id| id == "acc-idx"));
    assert!(paths.account_file("acc-idx").exists());

    let idx_replay_enable = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "sync_parent_dir:index.json:io")
        .args(["--json", "accounts", "enable", "acc-dis"])
        .output()
        .unwrap();
    assert_eq!(
        idx_replay_enable.status.code(),
        Some(7),
        "accounts enable under persistent index.json sync_parent_dir MUST exit 7 and preserve journal! stdout={} stderr={}",
        String::from_utf8_lossy(&idx_replay_enable.stdout),
        String::from_utf8_lossy(&idx_replay_enable.stderr)
    );
    assert!(paths.switch_journal_file().exists());
    assert!(repo.read_account_unchecked("acc-dis").unwrap().disabled);

    let idx_replay_policy = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "sync_parent_dir:index.json:io")
        .args(["--json", "policy", "set", "--reserve", "12"])
        .output()
        .unwrap();
    assert_eq!(
        idx_replay_policy.status.code(),
        Some(7),
        "policy set under persistent index.json sync_parent_dir MUST exit 7 and preserve journal!"
    );
    assert!(paths.switch_journal_file().exists());
    assert_eq!(repo.read_policy().unwrap().reserve_percentage, 10);

    let ext_after_stage1 = make_account(
        "acc-ext-stage1",
        "ext@example.com",
        "1//RT_EXT_STAGE1",
        now + 7200,
        now,
    );
    let ext_stage1_payload = serialize_session_payload(&ext_after_stage1.token).unwrap();
    backend.write_slot(&paths, &ext_stage1_payload).unwrap();

    let idx_replay_ok = cli()
        .args(["--json", "accounts", "enable", "acc-dis"])
        .output()
        .unwrap();
    assert_eq!(
        idx_replay_ok.status.code(),
        Some(0),
        "Replay after fault removal must exit 0: stderr={}",
        String::from_utf8_lossy(&idx_replay_ok.stderr)
    );
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-idx").exists());
    assert!(!paths.token_lineage_file("acc-idx").exists());
    assert!(!repo.read_account_unchecked("acc-dis").unwrap().disabled);
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_stage1_payload
    );
    backend.remove_slot(&paths).unwrap();

    // 3. Persistent `sync_parent_dir:policy.json:io` (post-rename fsync failure):
    //    First delete -> exit 7 (`committed_index_pending`);
    //    `accounts enable acc-dis2` AND `policy set --reserve 10` under SAME fault -> BOTH exit 7 (NOT 0 or 1!) & preserve journal;
    //    After fault clears -> `accounts enable acc-dis2` exits 0, completes cleanup, removes journal!
    let acc_pol = make_account(
        "acc-pol",
        "charlie@example.com",
        "1//RT_POL",
        now + 7200,
        now,
    );
    let mut pol = repo.read_policy().unwrap();
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_pol.clone(), true, now)?;
        pol.candidate_account_ids = vec!["acc-pol".into(), "acc-keep".into()];
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    write_lineage("acc-pol");
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_pol.token).unwrap())
        .unwrap();

    let pol_del = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "sync_parent_dir:policy.json:io",
        )
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-pol",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(pol_del.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    // Rename already removed `acc-pol` from `policy.json` even though fsync failed
    assert!(!repo
        .read_policy()
        .unwrap()
        .candidate_account_ids
        .iter()
        .any(|id| id == "acc-pol"));
    assert!(paths.account_file("acc-pol").exists());

    let pol_replay_enable = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "sync_parent_dir:policy.json:io",
        )
        .args(["--json", "accounts", "enable", "acc-dis2"])
        .output()
        .unwrap();
    assert_eq!(
        pol_replay_enable.status.code(),
        Some(7),
        "accounts enable under persistent policy.json sync_parent_dir MUST exit 7 and preserve journal! stdout={} stderr={}",
        String::from_utf8_lossy(&pol_replay_enable.stdout),
        String::from_utf8_lossy(&pol_replay_enable.stderr)
    );
    assert!(paths.switch_journal_file().exists());
    assert!(repo.read_account_unchecked("acc-dis2").unwrap().disabled);

    let pol_replay_policy = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "sync_parent_dir:policy.json:io",
        )
        .args(["--json", "policy", "set", "--reserve", "12"])
        .output()
        .unwrap();
    assert_eq!(
        pol_replay_policy.status.code(),
        Some(7),
        "policy set under persistent policy.json sync_parent_dir MUST exit 7 and preserve journal (NOT exit 1)!"
    );
    assert!(paths.switch_journal_file().exists());
    assert_eq!(repo.read_policy().unwrap().reserve_percentage, 10);

    let pol_replay_ok = cli()
        .args(["--json", "accounts", "enable", "acc-dis2"])
        .output()
        .unwrap();
    assert_eq!(pol_replay_ok.status.code(), Some(0));
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-pol").exists());
    assert!(!paths.token_lineage_file("acc-pol").exists());
    assert!(!repo.read_account_unchecked("acc-dis2").unwrap().disabled);

    // 4. Stage marker `CommittedIndexPending` failure & early `SlotCommitting` replay durability:
    //    - Failure persisting `CommittedIndexPending` MUST prevent Stage 2 local cleanup!
    //    - Replay under `sync_parent_dir:antigravity-oauth-token:io` fails before advancing stage marker;
    //    - Repeated replays under `sync_parent_dir:switch_journal.json:io` stay exit 7 without entering Stage 2;
    //    - Clearing fault allows replay to finish Stage 2 and remove journal!
    let acc_stg = make_account("acc-stg", "eve@example.com", "1//RT_STG", now + 7200, now);
    let mut pol = repo.read_policy().unwrap();
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_stg.clone(), true, now)?;
        pol.candidate_account_ids = vec!["acc-stg".into(), "acc-keep".into()];
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    write_lineage("acc-stg");
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_stg.token).unwrap())
        .unwrap();

    let stg_del = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "stage_clear_slot_committed:switch_journal.json:io",
        )
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-stg",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(stg_del.status.code(), Some(7));
    assert!(!paths.active_slot_file.exists());
    assert!(paths.switch_journal_file().exists());
    assert_eq!(
        read_journal_readonly(&paths).unwrap().unwrap().phase,
        agy_switch_cli::session::journal::JournalPhase::SlotCommitting
    );
    // Stage marker failed -> Stage 2 MUST NOT have run!
    assert!(paths.account_file("acc-stg").exists());
    assert!(paths.token_lineage_file("acc-stg").exists());
    assert!(repo
        .read_policy()
        .unwrap()
        .candidate_account_ids
        .iter()
        .any(|id| id == "acc-stg"));
    assert!(repo
        .read_snapshot()
        .unwrap()
        .index
        .account_order
        .iter()
        .any(|id| id == "acc-stg"));

    let stg_slot_sync_fail = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "sync_parent_dir:antigravity-oauth-token:io",
        )
        .args(["--json", "accounts", "enable", "acc-dis3"])
        .output()
        .unwrap();
    assert_eq!(stg_slot_sync_fail.status.code(), Some(7));
    assert_eq!(
        read_journal_readonly(&paths).unwrap().unwrap().phase,
        agy_switch_cli::session::journal::JournalPhase::SlotCommitting
    );
    assert!(paths.account_file("acc-stg").exists());

    for _ in 0..2 {
        let stg_j_sync_fail = cli()
            .env(
                "AGY_SWITCH_CLI_FAULT_SPEC",
                "sync_parent_dir:switch_journal.json:io",
            )
            .args(["--json", "accounts", "enable", "acc-dis3"])
            .output()
            .unwrap();
        assert_eq!(stg_j_sync_fail.status.code(), Some(7));
        assert!(paths.switch_journal_file().exists());
        assert!(paths.account_file("acc-stg").exists());
        assert!(repo.read_account_unchecked("acc-dis3").unwrap().disabled);
    }

    let stg_ok = cli()
        .args(["--json", "accounts", "enable", "acc-dis3"])
        .output()
        .unwrap();
    assert_eq!(stg_ok.status.code(), Some(0));
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-stg").exists());
    assert!(!paths.token_lineage_file("acc-stg").exists());
    assert!(!repo.read_account_unchecked("acc-dis3").unwrap().disabled);
    assert!(!repo
        .read_policy()
        .unwrap()
        .candidate_account_ids
        .iter()
        .any(|id| id == "acc-stg"));
    assert!(!repo
        .read_snapshot()
        .unwrap()
        .index
        .account_order
        .iter()
        .any(|id| id == "acc-stg"));
}

#[tokio::test]
async fn synthetic_v123_r401_rejects_file_prev_uniform_false_and_allows_omitted_default_recovery() {
    use agy_switch_cli::session::payload::bytes_sha256_hex;

    let _guard = FAULT_ENV_MUTEX.lock().await;

    let setup_fixture = |omit_prev_uniform: bool| {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache").join("agy-switch-cli"),
        );
        let run_dir = tmp.path().join("run");
        let proc_dir = tmp.path().join("proc");
        fs::create_dir_all(&run_dir).unwrap();
        fs::create_dir_all(&proc_dir).unwrap();
        fs::create_dir_all(&paths.active_slot_dir).unwrap();
        let repo = StoreRepository::new(paths.clone());
        let now = 1_850_000_000i64;

        let acc_a = make_account(
            "acc-0001",
            "alice@example.com",
            "1//synthetic-r401-a",
            now + 3600,
            now,
        );
        let acc_b = make_account(
            "acc-0002",
            "bob@example.com",
            "1//synthetic-r401-b",
            now + 3600,
            now,
        );
        let mut pol = repo.read_policy().unwrap();
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, now)?;
            tx.upsert_account(acc_b, false, now)?;
            tx.save_policy(&mut pol, None, now)?;
            Ok(())
        })
        .unwrap();

        let slot_bytes = serialize_session_payload(&acc_a.token).unwrap();
        FileSessionBackend.write_slot(&paths, &slot_bytes).unwrap();
        let prev_digest = bytes_sha256_hex(slot_bytes.as_bytes());

        let file_replica = if omit_prev_uniform {
            json!({
                "prev_present": true,
                "prev_digest": prev_digest
            })
        } else {
            json!({
                "prev_present": true,
                "prev_digest": prev_digest,
                "prev_uniform": false
            })
        };

        let journal_json = json!({
            "schema_version": 1,
            "operation_id": "op-synthetic-r401",
            "phase": "aborted_uncommitted",
            "prev_selected_account_id": "acc-0001",
            "target_account_id": "acc-0002",
            "prev_slot_digest": prev_digest,
            "token_rotated": false,
            "started_at": now,
            "updated_at": now,
            "replica_state": {
                "backend": "file",
                "uses_file": true,
                "file": file_replica
            }
        });
        fs::create_dir_all(paths.state_dir()).unwrap();
        fs::write(
            paths.switch_journal_file(),
            serde_json::to_vec_pretty(&journal_json).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            paths.switch_journal_file(),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        (tmp, paths, repo, run_dir, proc_dir)
    };

    let build_cli = |tmp: &tempfile::TempDir,
                     paths: &HeadlessPaths,
                     run_dir: &std::path::Path,
                     proc_dir: &std::path::Path| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &paths.home_dir)
            .env("XDG_CACHE_HOME", paths.cache_dir.parent().unwrap())
            .env("XDG_RUNTIME_DIR", run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", proc_dir)
            .env("AGY_SWITCH_CLI_AGY_BIN", tmp.path().join("no-agy"))
            .args([
                "--data-dir",
                paths.data_dir.to_str().unwrap(),
                "--backend",
                "file",
                "--no-remote-version",
            ]);
        c
    };

    // 1. Contradictory pure-file record (`file.prev_uniform=false`): BOTH `status` and `policy set`
    //    MUST return exit 7 and preserve journal, slot, and business files byte-for-byte.
    {
        let (tmp, paths, _repo, run_dir, proc_dir) = setup_fixture(false);
        let journal_before = fs::read(paths.switch_journal_file()).unwrap();
        let slot_before = fs::read(&paths.active_slot_file).unwrap();
        let index_before = fs::read(paths.index_file()).unwrap();
        let policy_before = fs::read(paths.policy_file()).unwrap();
        let acc_a_before = fs::read(paths.account_file("acc-0001")).unwrap();

        let status_out = build_cli(&tmp, &paths, &run_dir, &proc_dir)
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(status_out.status.code(), Some(7));
        let status_err: serde_json::Value = serde_json::from_slice(&status_out.stderr).unwrap();
        assert_eq!(status_err["error_code"], "pending_journal_reconciliation");
        assert_eq!(
            fs::read(paths.switch_journal_file()).unwrap(),
            journal_before
        );
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
        assert_eq!(fs::read(paths.index_file()).unwrap(), index_before);
        assert_eq!(fs::read(paths.policy_file()).unwrap(), policy_before);
        assert_eq!(
            fs::read(paths.account_file("acc-0001")).unwrap(),
            acc_a_before
        );

        let policy_out = build_cli(&tmp, &paths, &run_dir, &proc_dir)
            .args([
                "--json",
                "policy",
                "set",
                "--reserve",
                "12",
                "--minimum",
                "35",
            ])
            .output()
            .unwrap();
        assert_eq!(policy_out.status.code(), Some(7));
        let policy_err: serde_json::Value = serde_json::from_slice(&policy_out.stderr).unwrap();
        assert_eq!(policy_err["error_code"], "recovery_incomplete");
        assert_eq!(
            fs::read(paths.switch_journal_file()).unwrap(),
            journal_before
        );
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
        assert_eq!(fs::read(paths.index_file()).unwrap(), index_before);
        assert_eq!(fs::read(paths.policy_file()).unwrap(), policy_before);
        assert_eq!(
            fs::read(paths.account_file("acc-0001")).unwrap(),
            acc_a_before
        );
    }

    // 2. Recoverable positive control omitting `file.prev_uniform` (defaulting to `true`):
    //    `status` stays read-only (exit 0) and `policy set` completes reconciliation & clears journal.
    {
        let (tmp, paths, repo, run_dir, proc_dir) = setup_fixture(true);
        let journal_before = fs::read(paths.switch_journal_file()).unwrap();
        let slot_before = fs::read(&paths.active_slot_file).unwrap();
        let index_before = fs::read(paths.index_file()).unwrap();
        let policy_before = fs::read(paths.policy_file()).unwrap();

        let status_out = build_cli(&tmp, &paths, &run_dir, &proc_dir)
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(status_out.status.code(), Some(0));
        let status_ok: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
        assert_eq!(status_ok["journal_status"]["status"], "aborted_uncommitted");
        assert_eq!(
            fs::read(paths.switch_journal_file()).unwrap(),
            journal_before
        );
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
        assert_eq!(fs::read(paths.index_file()).unwrap(), index_before);
        assert_eq!(fs::read(paths.policy_file()).unwrap(), policy_before);

        let policy_out = build_cli(&tmp, &paths, &run_dir, &proc_dir)
            .args([
                "--json",
                "policy",
                "set",
                "--reserve",
                "12",
                "--minimum",
                "35",
            ])
            .output()
            .unwrap();
        assert_eq!(policy_out.status.code(), Some(0));
        assert!(!paths.switch_journal_file().exists());
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
        let updated_policy = repo.read_policy().unwrap();
        assert_eq!(updated_policy.reserve_percentage, 12);
        assert_eq!(updated_policy.candidate_min_percentage, 35);
    }
}
