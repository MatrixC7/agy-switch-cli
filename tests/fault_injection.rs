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
async fn index_failure_after_slot_commit_returns_exit_7_committed_index_pending_and_doctor_fix_reconciles(
) {
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

    // Reconcile (`doctor --fix` core) completes index.json alignment!
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

    // Subsequent ordinary switch MUST be blocked with exit code 7 until `doctor --fix` runs!
    let blocked = execute_switch(
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
        now + 5,
    )
    .await
    .unwrap_err();
    assert_eq!(blocked.exit_code, ExitCode::PartialCommitOrRecovery);

    // Run `agy-switch-cli doctor` (without --fix) -> exit code 7; then `doctor --fix` -> exit code 0!
    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    let proc_dir = tmp.path().join("empty_proc");

    let doc_check = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
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
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "doctor",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_check.status.code(), Some(7));

    let doc_fix = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
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
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "doctor",
            "--fix",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        doc_fix.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&doc_fix.stderr)
    );
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn subprocess_crash_after_slot_commit_is_detected_and_reconciled_by_doctor() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = chrono::Utc::now().timestamp();
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("empty_proc");
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

    // Restarted `doctor` sees `CommittedIndexPending` (exit code 7)
    let doc1 = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
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
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "doctor",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc1.status.code(), Some(7));

    // `doctor --fix` reconciles `index.json` to `acc-b`!
    let doc_fix = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
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
        .args([
            "--data-dir",
            paths.data_dir.to_str().unwrap(),
            "doctor",
            "--fix",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_fix.status.code(), Some(0));
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
async fn doctor_fix_unwedges_recovery_incomplete_with_bare_imported_prev_account_and_deleted_pending_target(
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

    // `reconcile_journal_locked` (`doctor --fix`) MUST skip unserializable `acc-imported` (`access_token == ""`)
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

    // User forcibly deletes `acc-deleted` before running `doctor --fix`
    repo.with_write_lock(|tx| tx.delete_account("acc-deleted", true, now + 8))
        .unwrap();

    // `reconcile_journal_locked` MUST clear the stale journal without wedging on `AccountNotFound`!
    let l1 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
    reconcile_journal_locked(&l1, &repo, &backend, true, now + 9).unwrap();
    drop(l1);
    assert!(read_journal_readonly(&paths).unwrap().is_none());
}

#[tokio::test]
async fn write_paths_and_daemon_reconcile_journal_or_pause_and_doctor_cleans_slot_tmp_files() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = chrono::Utc::now().timestamp();
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("empty_proc");
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
        .args(["policy", "set", "--reserve", "15"])
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

    // 3. Create orphan `.tmp.` file in active_slot_dir: `doctor` human output warns, `doctor --fix` cleans it under L1!
    let orphan_tmp = paths
        .active_slot_dir
        .join("antigravity-oauth-token.tmp.orphan-test");
    fs::write(&orphan_tmp, b"partial-junk").unwrap();
    let doc_human = cli().arg("doctor").output().unwrap();
    assert_eq!(doc_human.status.code(), Some(0));
    let doc_stdout = String::from_utf8_lossy(&doc_human.stdout);
    assert!(
        doc_stdout.contains("Stray slot files:") && doc_stdout.contains("orphan-test"),
        "doctor human output omitted stray_slot_files warning: {doc_stdout}"
    );
    // Read-only `doctor` did NOT delete orphan file
    assert!(orphan_tmp.exists());

    let doc_fix_tmp = cli().args(["doctor", "--fix"]).output().unwrap();
    assert_eq!(doc_fix_tmp.status.code(), Some(0));
    assert!(
        !orphan_tmp.exists(),
        "doctor --fix must remove orphan .tmp. file under L1"
    );

    // 4. Inject `RecoveryIncomplete`: verify write commands block with exit code 7 AND `daemon` enters `PausedOnFailure`!
    let rec_inc = cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_rename:antigravity-oauth-token:corrupt_after_rename;slot_rollback:antigravity-oauth-token:io",
        )
        .args(["switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(rec_inc.status.code(), Some(7));

    for blocked_args in [
        vec!["policy", "set", "--reserve", "20"],
        vec!["accounts", "disable", "acc-b"],
        vec!["accounts", "delete", "acc-b"],
        vec!["switch", "--dry-run", "acc-b"],
    ] {
        let out = cli().args(&blocked_args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(7),
            "Expected exit 7 on {blocked_args:?}, got {:?} stderr={}",
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
}

#[tokio::test]
async fn concurrent_non_slot_store_writes_succeed_during_slow_network_switch_without_l1_timeout() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, _proc_guard) = setup_isolated(tmp.path());
    let backend = FileSessionBackend;
    let now = chrono::Utc::now().timestamp();
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
        .args(["policy", "set", "--reserve", "22"])
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
