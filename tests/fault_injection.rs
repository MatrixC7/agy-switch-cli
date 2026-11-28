mod common;

use agy_switch_cli::domain::account::AccountRecord;
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::error::ExitCode;
use agy_switch_cli::oauth::registry::OAuthClientRegistry;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend};
use agy_switch_cli::session::journal::{
    diagnose_journal, read_journal_readonly, reconcile_journal_locked, write_journal,
    JournalDiagnosis, SwitchJournal,
};
use agy_switch_cli::session::payload::serialize_session_payload;
use agy_switch_cli::store::locks::ActiveSlotLock;
use agy_switch_cli::store::repository::StoreRepository;
use agy_switch_cli::switching::executor::{execute_switch, SwitchOptions};
use common::{make_synthetic_account, run_isolated_subtest, IsolatedEnv};
use serde_json::json;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::Mutex as AsyncMutex;

static FAULT_ENV_MUTEX: AsyncMutex<()> = AsyncMutex::const_new(());

fn paths_and_repo(tmp: &std::path::Path) -> (HeadlessPaths, StoreRepository, PathBuf) {
    let home = tmp.join("home");
    let data = tmp.join("data");
    let cache = tmp.join("cache").join("agy-switch-cli");
    let proc_dir = tmp.join("empty_proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&proc_dir).unwrap();
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    (paths, repo, proc_dir)
}

fn make_account(
    id: &str,
    email: &str,
    refresh_token: &str,
    expiry: i64,
    now: i64,
) -> AccountRecord {
    make_synthetic_account(id, email, refresh_token, expiry, now)
}

#[tokio::test]
async fn rotated_refresh_token_is_never_rolled_back_when_slot_write_fails_with_enospc() {
    let now = 1_800_000_000i64;
    if let Some(sub_dir) = std::env::var_os("AGY_SUBTEST_FI_ENOSPC_DIR") {
        let (_, repo, _) = paths_and_repo(&PathBuf::from(sub_dir));
        let err = execute_switch(
            &repo,
            &FileSessionBackend,
            &OAuthClientRegistry::parse_from_raw(None, None),
            "acc-target",
            &SwitchOptions {
                dry_run: false,
                allow_running: false,
            },
            now,
        )
        .unwrap_err();
        assert_eq!(err.error_code, "disk_full_enospc");
        return;
    }

    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, proc_dir) = paths_and_repo(tmp.path());
    let backend = FileSessionBackend;

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
    // Official `agy` rotated `acc-old`'s refresh_token and access_token inside the active slot!
    let rotated_old_slot_payload = serde_json::to_string(&json!({
        "access_token": "ya29.NEW_OLD_AT",
        "refresh_token": "1//SERVER_ROTATED_NEW_RT",
        "token_type": "Bearer",
        "expiry": "2099-01-01T00:00:00Z",
        "id_token_email": "old@example.invalid",
    }))
    .unwrap();
    backend
        .write_slot(&paths, &rotated_old_slot_payload)
        .unwrap();

    // Inject ENOSPC specifically on `antigravity-oauth-token` write in an isolated subprocess!
    run_isolated_subtest(
        "rotated_refresh_token_is_never_rolled_back_when_slot_write_fails_with_enospc",
        "AGY_SUBTEST_FI_ENOSPC",
        &[
            ("AGY_SUBTEST_FI_ENOSPC_DIR", tmp.path().as_os_str()),
            ("AGY_SWITCH_CLI_PROC_ROOT", proc_dir.as_os_str()),
            (
                "AGY_SWITCH_CLI_FAULT_SPEC",
                OsStr::new("before_write:antigravity-oauth-token:enospc"),
            ),
        ],
    );

    // 1. Active slot retains acc-old untouched
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        rotated_old_slot_payload
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
    // 3. CRITICAL INVARIANT: Pre-Switch Sync-Back already persisted `1//SERVER_ROTATED_NEW_RT`
    //    into `acc-old` on disk and MUST retain it (NEVER rolled back even when target write fails)!
    let saved_old = repo.read_account_unchecked("acc-old").unwrap();
    assert_eq!(saved_old.token.refresh_token, "1//SERVER_ROTATED_NEW_RT");
    assert_eq!(saved_old.token.access_token, "ya29.NEW_OLD_AT");
}

#[tokio::test]
async fn index_failure_after_slot_commit_returns_exit_7_committed_index_pending_and_reconciles() {
    let now = 1_800_000_000i64;
    if let Some(sub_dir) = std::env::var_os("AGY_SUBTEST_FI_IDX_DIR") {
        let (_, repo, _) = paths_and_repo(&PathBuf::from(sub_dir));
        let target = std::env::var("AGY_SUBTEST_FI_IDX_TARGET").unwrap();
        let ts: i64 = std::env::var("AGY_SUBTEST_FI_IDX_TS")
            .unwrap()
            .parse()
            .unwrap();
        let err = execute_switch(
            &repo,
            &FileSessionBackend,
            &OAuthClientRegistry::parse_from_raw(None, None),
            &target,
            &SwitchOptions {
                dry_run: false,
                allow_running: false,
            },
            ts,
        )
        .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::PartialCommitOrRecovery);
        assert_eq!(err.error_code, "committed_index_pending");
        if target == "acc-b" {
            assert!(err.message.contains("生效位凭据已切换至目标账号"));
        }
        return;
    }

    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, proc_dir) = paths_and_repo(tmp.path());
    let backend = FileSessionBackend;

    let mut acc_a = make_account("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    acc_a.last_switched_in_at = Some(now - 600);
    let mut acc_b = make_account("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    // Give `acc-b` a stale previous session (`last_switched_out_at`) so recovery replay proves
    // `CommittedIndexPending` clears stale `last_switched_out_at` on the target account!
    acc_b.last_switched_in_at = Some(now - 1800);
    acc_b.last_switched_out_at = Some(now - 900);
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
    let ts1_str = now.to_string();
    run_isolated_subtest(
        "index_failure_after_slot_commit_returns_exit_7_committed_index_pending_and_reconciles",
        "AGY_SUBTEST_FI_IDX_1",
        &[
            ("AGY_SUBTEST_FI_IDX_DIR", tmp.path().as_os_str()),
            ("AGY_SUBTEST_FI_IDX_TARGET", OsStr::new("acc-b")),
            ("AGY_SUBTEST_FI_IDX_TS", OsStr::new(&ts1_str)),
            ("AGY_SWITCH_CLI_PROC_ROOT", proc_dir.as_os_str()),
            (
                "AGY_SWITCH_CLI_FAULT_SPEC",
                OsStr::new("before_index_commit:index.json:erofs"),
            ),
        ],
    );

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

    // Reconcile 10s later completes index.json alignment AND preserves verified slot-commit timestamp `now` (P2-01)!
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

    // Normal `CommittedIndexPending` reconciliation MUST stamp `acc-a.last_switched_out_at`,
    // set `acc-b.last_switched_in_at` to the verified commit instant (`now`, not replay `now + 10`),
    // and CLEAR stale `acc-b.last_switched_out_at = None`!
    let a_rec = repo.read_account_unchecked("acc-a").unwrap();
    let b_rec = repo.read_account_unchecked("acc-b").unwrap();
    assert_eq!(a_rec.last_switched_out_at, Some(now));
    assert_eq!(b_rec.last_switched_in_at, Some(now));
    assert_eq!(b_rec.last_switched_out_at, None);

    // Now test `CommittedIndexPending` recovery when active slot had drifted to a FOREIGN external
    // credential (while `selected_account_id == Some("acc-b")`): switching to `acc-a` under
    // `before_index_commit` fault and reconciling MUST clear `acc-a.last_switched_out_at = None`,
    // set `acc-a.last_switched_in_at` to `now + 20`, and NEVER fabricate `acc-b.last_switched_out_at`!
    let foreign_tok = TokenRecord {
        access_token: "ya29.foreign-ext".into(),
        refresh_token: "1//RT_FOREIGN_EXT".into(),
        expires_in: 3600,
        expiry_timestamp: now + 7200,
        token_type: "Bearer".into(),
        id_token: None,
        oauth_client_key: None,
        granted_scopes: None,
        project_id: None,
        is_gcp_tos: true,
    };
    backend
        .write_slot(&paths, &serialize_session_payload(&foreign_tok).unwrap())
        .unwrap();

    let ts2_str = (now + 20).to_string();
    run_isolated_subtest(
        "index_failure_after_slot_commit_returns_exit_7_committed_index_pending_and_reconciles",
        "AGY_SUBTEST_FI_IDX_2",
        &[
            ("AGY_SUBTEST_FI_IDX_DIR", tmp.path().as_os_str()),
            ("AGY_SUBTEST_FI_IDX_TARGET", OsStr::new("acc-a")),
            ("AGY_SUBTEST_FI_IDX_TS", OsStr::new(&ts2_str)),
            ("AGY_SWITCH_CLI_PROC_ROOT", proc_dir.as_os_str()),
            (
                "AGY_SWITCH_CLI_FAULT_SPEC",
                OsStr::new("before_index_commit:index.json:erofs"),
            ),
        ],
    );

    let l1_2 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
    let fixed_diag2 = reconcile_journal_locked(&l1_2, &repo, &backend, true, now + 30).unwrap();
    drop(l1_2);
    assert!(matches!(
        fixed_diag2,
        JournalDiagnosis::CommittedIndexPending { ref target_account_id } if target_account_id == "acc-a"
    ));
    let a_after_drift_rec = repo.read_account_unchecked("acc-a").unwrap();
    let b_after_drift_rec = repo.read_account_unchecked("acc-b").unwrap();
    assert_eq!(a_after_drift_rec.last_switched_in_at, Some(now + 20));
    assert_eq!(a_after_drift_rec.last_switched_out_at, None);
    assert_eq!(
        b_after_drift_rec.last_switched_out_at, None,
        "CommittedIndexPending recovery after external drift MUST NOT fabricate last_switched_out_at on stale selected account"
    );
}

#[tokio::test]
async fn failed_slot_readback_and_failed_rollback_records_recovery_incomplete_exit_7() {
    let now = 1_800_000_000i64;
    if let Some(sub_dir) = std::env::var_os("AGY_SUBTEST_FI_RB_FAULT_DIR") {
        let (_, repo, _) = paths_and_repo(&PathBuf::from(sub_dir));
        let err = execute_switch(
            &repo,
            &FileSessionBackend,
            &OAuthClientRegistry::parse_from_raw(None, None),
            "acc-b",
            &SwitchOptions {
                dry_run: false,
                allow_running: false,
            },
            now,
        )
        .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::PartialCommitOrRecovery);
        assert_eq!(err.error_code, "recovery_incomplete");
        return;
    }
    if std::env::var_os("AGY_SUBTEST_FI_RB_MAIN").is_none() {
        let tmp_proc = tempfile::tempdir().unwrap();
        run_isolated_subtest(
            "failed_slot_readback_and_failed_rollback_records_recovery_incomplete_exit_7",
            "AGY_SUBTEST_FI_RB_MAIN",
            &[("AGY_SWITCH_CLI_PROC_ROOT", tmp_proc.path().as_os_str())],
        );
        return;
    }

    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, proc_dir) = paths_and_repo(tmp.path());
    let backend = FileSessionBackend;

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
    run_isolated_subtest(
        "failed_slot_readback_and_failed_rollback_records_recovery_incomplete_exit_7",
        "AGY_SUBTEST_FI_RB_FAULT",
        &[
            ("AGY_SUBTEST_FI_RB_FAULT_DIR", tmp.path().as_os_str()),
            ("AGY_SWITCH_CLI_PROC_ROOT", proc_dir.as_os_str()),
            (
                "AGY_SWITCH_CLI_FAULT_SPEC",
                OsStr::new("after_rename:antigravity-oauth-token:corrupt_after_rename;slot_rollback:antigravity-oauth-token:io"),
            ),
        ],
    );

    // Read-only `status --json` and `switch --dry-run` MUST report exit code 7 (`RecoveryIncomplete`),
    // while manual `switch` self-heals the journal and completes the switch cleanly!
    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
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
        &OAuthClientRegistry::parse_from_raw(None, None),
        "acc-b",
        &SwitchOptions {
            dry_run: true,
            allow_running: false,
        },
        now + 5,
    )
    .unwrap_err();
    assert_eq!(dry_blocked.exit_code, ExitCode::PartialCommitOrRecovery);

    let sw_healed = execute_switch(
        &repo,
        &backend,
        &OAuthClientRegistry::parse_from_raw(None, None),
        "acc-b",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now + 6,
    )
    .unwrap();
    assert_eq!(sw_healed.target_account_id, "acc-b");
    assert!(read_journal_readonly(&paths).unwrap().is_none());
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn subprocess_crash_after_slot_commit_is_detected_by_status_and_reconciled_on_write() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
    let backend = FileSessionBackend;
    let now = jiff::Timestamp::now().as_second();

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
    let crashed = env
        .cli_cmd()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_slot_commit:index.json:abort",
        )
        .args(["switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(crashed.status.code(), Some(137));

    // Read-only `status` sees `CommittedIndexPending` (exit code 7)
    let st1 = env.cli_cmd().args(["status", "--json"]).output().unwrap();
    assert_eq!(st1.status.code(), Some(7));

    // Subsequent write command reconciles `index.json` to `acc-b`!
    let reconcile_out = env
        .cli_cmd()
        .args(["accounts", "enable", "acc-a", "--json"])
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
    let now = 1_800_000_000i64;
    if let Some(sub_dir) = std::env::var_os("AGY_SUBTEST_FI_UNWEDGE_DIR") {
        let (_, repo, _) = paths_and_repo(&PathBuf::from(sub_dir));
        let target = std::env::var("AGY_SUBTEST_FI_UNWEDGE_TARGET").unwrap();
        let expected_code = std::env::var("AGY_SUBTEST_FI_UNWEDGE_CODE").unwrap();
        let ts: i64 = std::env::var("AGY_SUBTEST_FI_UNWEDGE_TS")
            .unwrap()
            .parse()
            .unwrap();
        let err = execute_switch(
            &repo,
            &FileSessionBackend,
            &OAuthClientRegistry::parse_from_raw(None, None),
            &target,
            &SwitchOptions {
                dry_run: false,
                allow_running: false,
            },
            ts,
        )
        .unwrap_err();
        assert_eq!(err.error_code, expected_code);
        return;
    }

    let _guard = FAULT_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let (paths, repo, proc_dir) = paths_and_repo(tmp.path());
    let backend = FileSessionBackend;

    // `acc-imported` starts as a valid bare imported account (`access_token == ""`, `expiry_timestamp == 1`)
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
    let ts1 = now.to_string();
    run_isolated_subtest(
        "journal_reconcile_unwedges_recovery_incomplete_with_bare_imported_prev_account_and_deleted_pending_target",
        "AGY_SUBTEST_FI_UNWEDGE_1",
        &[
            ("AGY_SUBTEST_FI_UNWEDGE_DIR", tmp.path().as_os_str()),
            ("AGY_SUBTEST_FI_UNWEDGE_TARGET", OsStr::new("acc-target")),
            ("AGY_SUBTEST_FI_UNWEDGE_CODE", OsStr::new("recovery_incomplete")),
            ("AGY_SUBTEST_FI_UNWEDGE_TS", OsStr::new(&ts1)),
            ("AGY_SWITCH_CLI_PROC_ROOT", proc_dir.as_os_str()),
            (
                "AGY_SWITCH_CLI_FAULT_SPEC",
                OsStr::new("after_rename:antigravity-oauth-token:corrupt_after_rename;slot_rollback:antigravity-oauth-token:io"),
            ),
        ],
    );

    // Simulate an unserializable `acc-imported` record on disk (`expiry_timestamp == 0`):
    // `reconcile_journal_locked` MUST skip unserializable `acc-imported`
    // and repair cleanly using `acc-target` instead of failing!
    let mut corrupt_prev = repo.read_account_unchecked("acc-imported").unwrap();
    corrupt_prev.token.expiry_timestamp = 0;
    fs::write(
        paths.account_file("acc-imported"),
        serde_json::to_string_pretty(&corrupt_prev).unwrap(),
    )
    .unwrap();
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
    let ts2 = (now + 7).to_string();
    run_isolated_subtest(
        "journal_reconcile_unwedges_recovery_incomplete_with_bare_imported_prev_account_and_deleted_pending_target",
        "AGY_SUBTEST_FI_UNWEDGE_2",
        &[
            ("AGY_SUBTEST_FI_UNWEDGE_DIR", tmp.path().as_os_str()),
            ("AGY_SUBTEST_FI_UNWEDGE_TARGET", OsStr::new("acc-deleted")),
            ("AGY_SUBTEST_FI_UNWEDGE_CODE", OsStr::new("committed_index_pending")),
            ("AGY_SUBTEST_FI_UNWEDGE_TS", OsStr::new(&ts2)),
            ("AGY_SWITCH_CLI_PROC_ROOT", proc_dir.as_os_str()),
            (
                "AGY_SWITCH_CLI_FAULT_SPEC",
                OsStr::new("before_index_commit:index.json:erofs"),
            ),
        ],
    );

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
async fn write_paths_reconcile_journal_and_switch_cleans_slot_tmp_files() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
    let backend = FileSessionBackend;
    let now = jiff::Timestamp::now().as_second();

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

    // 1. Crash switch after slot commit (`CommittedIndexPending`: slot=acc-b, index.json=acc-a)
    let crashed = env
        .cli_cmd()
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

    // `accounts delete acc-b` WITHOUT `--force` MUST reconcile `CommittedIndexPending` first
    // (updating index.json to `acc-b`), and therefore refuse to delete active `acc-b` without `--force`!
    let del_no_force = env
        .cli_cmd()
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

    // 2. Crash another switch to `acc-a`, then verify `accounts enable` auto-reconciles `CommittedIndexPending`!
    let crashed2 = env
        .cli_cmd()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_slot_commit:index.json:abort",
        )
        .args(["switch", "acc-a"])
        .output()
        .unwrap();
    assert_eq!(crashed2.status.code(), Some(137));
    let en_reconcile = env
        .cli_cmd()
        .args(["accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(en_reconcile.status.code(), Some(0));
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
    let crashed_pre = env
        .cli_cmd()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_token_refreshed:antigravity-oauth-token:abort",
        )
        .args(["switch", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(crashed_pre.status.code(), Some(137));
    assert!(read_journal_readonly(&paths).unwrap().is_some());
    let en_out = env
        .cli_cmd()
        .args(["accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(en_out.status.code(), Some(0));
    assert!(read_journal_readonly(&paths).unwrap().is_none());
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );

    // 3. R3-15: Read-only `status` leaves all temp files untouched; manual `switch` cleans ONLY expired owned temp file!
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
    {
        let old_mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(180);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&expired_owned_tmp)
            .unwrap()
            .set_modified(old_mtime)
            .unwrap();
    }
    let st_human = env.cli_cmd().arg("status").output().unwrap();
    assert_eq!(st_human.status.code(), Some(0));
    let st_stdout = String::from_utf8_lossy(&st_human.stdout);
    assert!(!st_stdout.contains("Stray slot files:") && !st_stdout.contains("Session identity:"));
    assert!(expired_owned_tmp.exists());
    assert!(fresh_owned_tmp.exists());
    assert!(foreign_tmp.exists());

    let sw_clean_tmp = env.cli_cmd().args(["switch", "acc-a"]).output().unwrap();
    assert_eq!(sw_clean_tmp.status.code(), Some(0));
    assert!(!expired_owned_tmp.exists());
    assert!(fresh_owned_tmp.exists());
    assert!(foreign_tmp.exists());
    fs::remove_file(&fresh_owned_tmp).unwrap();
    fs::remove_file(&foreign_tmp).unwrap();

    // 4. Inject `RecoveryIncomplete`: read-only `status` & `switch --dry-run` exit 7, manual `switch` self-heals!
    let rec_inc = env
        .cli_cmd()
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
        let out = env.cli_cmd().args(&ro_blocked).output().unwrap();
        assert_eq!(out.status.code(), Some(7));
    }

    let manual_sw = env.cli_cmd().args(["switch", "acc-b"]).output().unwrap();
    assert_eq!(manual_sw.status.code(), Some(0));
    assert!(read_journal_readonly(&paths).unwrap().is_none());

    // 5. `clear_slot_intent` `RecoveryIncomplete` + concurrent external `agy` login on disk:
    //    `reconcile_pending_journal_before_write` preserves external credential and keeps `acc-b`!
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
    let en_ext_out = env
        .cli_cmd()
        .args(["accounts", "enable", "acc-a"])
        .output()
        .unwrap();
    assert_eq!(en_ext_out.status.code(), Some(0));
    assert!(read_journal_readonly(&paths).unwrap().is_none());
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_payload
    );
    assert!(paths.account_file("acc-b").exists());
}

#[tokio::test]
async fn concurrent_non_slot_store_writes_succeed_during_held_l1_without_timeout() {
    if std::env::var_os("AGY_SUBTEST_FI_CONC_L1").is_none() {
        let tmp_proc = tempfile::tempdir().unwrap();
        run_isolated_subtest(
            "concurrent_non_slot_store_writes_succeed_during_held_l1_without_timeout",
            "AGY_SUBTEST_FI_CONC_L1",
            &[("AGY_SWITCH_CLI_PROC_ROOT", tmp_proc.path().as_os_str())],
        );
        return;
    }
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
    let backend = FileSessionBackend;
    let now = jiff::Timestamp::now().as_second();

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

    // Hold L1 with an active `Prepared` switch journal
    let l1_hold = ActiveSlotLock::try_acquire(&paths, false).unwrap();
    let prepared_journal = SwitchJournal::new_prepared(
        "op-concurrent-l1".into(),
        Some("acc-a".into()),
        "acc-b".into(),
        backend
            .inspect_slot(&paths)
            .raw_digest()
            .map(str::to_string),
        now,
    );
    write_journal(&paths, &prepared_journal).unwrap();
    assert!(paths.switch_journal_file().exists());

    // 1. Concurrent non-slot writes (`accounts list --move` and `accounts enable`) succeed without L1 timeout!
    let move_res = env
        .cli_cmd()
        .args(["accounts", "list", "--move", "acc-c", "--to", "1"])
        .output()
        .unwrap();
    assert_eq!(
        move_res.status.code(),
        Some(0),
        "accounts list --move failed during held L1 Prepared journal: stderr={}",
        String::from_utf8_lossy(&move_res.stderr)
    );
    let enable_res = env
        .cli_cmd()
        .args(["accounts", "enable", "acc-c"])
        .output()
        .unwrap();
    assert_eq!(enable_res.status.code(), Some(0));

    // 2. Competing `switch` fails immediately with exit code 5 (`LockBusyOrConflict`)!
    let competing_sw = env.cli_cmd().args(["switch", "acc-c"]).output().unwrap();
    assert_eq!(competing_sw.status.code(), Some(5));

    // Release L1 and execute offline switch to `acc-b`
    drop(l1_hold);
    let sw_outcome = execute_switch(
        &repo,
        &FileSessionBackend,
        &OAuthClientRegistry::parse_from_raw(None, None),
        "acc-b",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now,
    )
    .unwrap();
    assert_eq!(sw_outcome.target_account_id, "acc-b");

    let final_snap = repo.read_snapshot().unwrap();
    assert_eq!(
        final_snap.index.selected_account_id.as_deref(),
        Some("acc-b")
    );
    assert_eq!(
        final_snap.index.account_order.first().map(String::as_str),
        Some("acc-c")
    );
    assert!(!repo.read_account_unchecked("acc-c").unwrap().disabled);
}

#[tokio::test]
async fn synthetic_v120_round3_r301_r302_corrupt_journal_clear_slot_replay_and_orphan_tmp_cleanup()
{
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
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
        let mut c = env.cli_cmd();
        c.args(["--backend", "file"]);
        c
    };

    // 1. R3-01: Corrupt `switch_journal.json` in pure `file` env MUST NOT be auto-cleared
    fs::create_dir_all(paths.state_dir()).unwrap();
    fs::write(
        paths.switch_journal_file(),
        b"{\"schema_version\":1,\"phase\":",
    )
    .unwrap();
    assert_eq!(
        cli()
            .args(["--json", "status"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );
    assert!(paths.switch_journal_file().exists());

    let en_corrupt = cli()
        .args(["--json", "accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(en_corrupt.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        payload_a
    );
    fs::remove_file(paths.switch_journal_file()).unwrap();

    // 2. R3-02: Persistent `before_write:index.json:io` during `accounts delete acc-a --force --clear-active-slot`
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
    assert_eq!(
        cli()
            .args(["--json", "status"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );

    let replay_same_fault = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:index.json:io")
        .args(["--json", "accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(replay_same_fault.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    assert!(paths.account_file("acc-a").exists());

    let replay_sync_fault = cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "sync_parent_dir:acc-a.json:io")
        .args(["--json", "accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(replay_sync_fault.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());

    let replay_ok = cli()
        .args(["--json", "accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(replay_ok.status.code(), Some(0));
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

    // 3. R3-02 pure file `remove_slot_transactional`: unconfirmed parent-dir fsync returns exit 7
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
    assert_eq!(del_sync_fail.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    fs::remove_file(paths.switch_journal_file()).unwrap();
    backend.write_slot(&paths, &payload_b).unwrap();

    // 4. R3-15 (orphan temp cleanup error propagation): surfaced as exit 7 (`slot_temp_cleanup_failed`)
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
    assert_eq!(sw_tmp_sync_fail.status.code(), Some(7));
    let tmp_err_j: serde_json::Value = serde_json::from_slice(&sw_tmp_sync_fail.stderr).unwrap();
    assert_eq!(tmp_err_j["error_code"], "slot_temp_cleanup_failed");

    // 5. R3-01 + R3-02 (`clear_slot_intent` at `CommittedIndexPending` + external credential appearing)
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
        .args(["--json", "accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(replay_still_fault.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    assert!(paths.account_file("acc-c").exists());
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_payload
    );

    let replay_ext_ok = cli()
        .args(["--json", "accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(replay_ext_ok.status.code(), Some(0));
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-c").exists());
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_payload
    );

    // 6. R3-02 (`clear_slot_intent` target `auth_generation` mismatch guard)
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
    let mut rotated_d = repo.read_account_unchecked("acc-d").unwrap();
    rotated_d.auth_generation = rotated_d.auth_generation.saturating_add(1);
    fs::write(
        paths.account_file("acc-d"),
        serde_json::to_vec_pretty(&rotated_d).unwrap(),
    )
    .unwrap();
    let mismatch_replay = cli()
        .args(["--json", "accounts", "enable", "acc-b"])
        .output()
        .unwrap();
    assert_eq!(mismatch_replay.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    assert!(paths.account_file("acc-d").exists());
}

#[tokio::test]
async fn synthetic_v120_round4_r402_clear_slot_replay_enforces_stage_and_parent_dir_fsync() {
    let _guard = FAULT_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    fs::create_dir_all(paths.token_lineage_dir()).unwrap();
    let repo = env.repo();
    let backend = FileSessionBackend;
    let now = 1_850_000_000i64;

    let cli = || {
        let mut c = env.cli_cmd();
        c.args(["--backend", "file"]);
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
    let mut acc_dis3 = make_account(
        "acc-dis3",
        "dis3@example.com",
        "1//RT_DIS3",
        now + 7200,
        now,
    );
    acc_dis3.disabled = true;
    acc_dis3.disabled_code = Some(agy_switch_cli::domain::account::DisableReasonCode::Manual);

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_keep.clone(), false, now)?;
        tx.upsert_account(acc_dis.clone(), false, now)?;
        tx.upsert_account(acc_dis3.clone(), false, now)?;
        tx.upsert_account(acc_clean.clone(), true, now)?;
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

    // 1. Healthy pure `file` clear-slot delete -> exits 0, removes target + index + lineage, no journal
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
    assert_eq!(clean_out.status.code(), Some(0));
    assert!(!paths.active_slot_file.exists());
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-clean").exists());
    assert!(!paths.token_lineage_file("acc-clean").exists());
    assert!(!repo
        .read_snapshot()
        .unwrap()
        .index
        .account_order
        .iter()
        .any(|id| id == "acc-clean"));
    assert!(paths.account_file("acc-keep").exists());

    // 2. Persistent `sync_parent_dir:index.json:io` (post-rename fsync failure):
    //    replay under SAME fault exits 7 & preserves journal; clearing fault finishes Stage 2 & preserves external slot!
    let acc_idx = make_account("acc-idx", "bob@example.com", "1//RT_IDX", now + 7200, now);
    repo.with_write_lock(|tx| tx.upsert_account(acc_idx.clone(), true, now))
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
    assert_eq!(idx_replay_enable.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    assert!(repo.read_account_unchecked("acc-dis").unwrap().disabled);

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
    assert_eq!(idx_replay_ok.status.code(), Some(0));
    assert!(!paths.switch_journal_file().exists());
    assert!(!paths.account_file("acc-idx").exists());
    assert!(!paths.token_lineage_file("acc-idx").exists());
    assert!(!repo.read_account_unchecked("acc-dis").unwrap().disabled);
    assert_eq!(
        fs::read_to_string(&paths.active_slot_file).unwrap(),
        ext_stage1_payload
    );
    backend.remove_slot(&paths).unwrap();

    // 3. Stage marker `CommittedIndexPending` failure & early `SlotCommitting` replay durability
    let acc_stg = make_account("acc-stg", "eve@example.com", "1//RT_STG", now + 7200, now);
    repo.with_write_lock(|tx| tx.upsert_account(acc_stg.clone(), true, now))
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
        .read_snapshot()
        .unwrap()
        .index
        .account_order
        .iter()
        .any(|id| id == "acc-stg"));
}

#[tokio::test]
async fn p1_01_journal_reconcile_skips_id_mismatched_outgoing_account_without_overwriting_other_account(
) {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    let mut acc1 = make_account("acc-0001", "alice@example.com", "1//RT_A1", now + 7200, now);
    acc1.last_switched_in_at = Some(now - 600);
    let acc2 = make_account("acc-0002", "bob@example.com", "1//RT_B2", now + 7200, now);
    let mut acc3 = make_account(
        "acc-0003",
        "charlie@example.com",
        "1//RT_C3_CURRENT",
        now + 7200,
        now,
    );
    acc3.auth_generation = 31;
    acc3.previous_refresh_token_digests = vec!["11".repeat(32)];

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        tx.upsert_account(acc3.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc1.token).unwrap())
        .unwrap();

    // 1. Switch `acc-0001 -> acc-0002` fails at `before_index_commit` -> exit 7 (`CommittedIndexPending`).
    let sw_fail = env
        .cli_cmd()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_index_commit:index.json:io",
        )
        .args(["--backend", "file", "--json", "switch", "acc-0002"])
        .output()
        .unwrap();
    assert_eq!(sw_fail.status.code(), Some(7));
    assert!(paths.switch_journal_file().exists());
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_B2"));

    // 2. Corrupt/misplace `accounts/acc-0001.json` with a parseable STALE backup of `acc-0003`
    //    (lower `auth_generation = 3`, older RT, empty inline lineage), simulating P1-01!
    let acc3_orig_bytes = fs::read(paths.account_file("acc-0003")).unwrap();
    let mut stale_acc3_backup = make_account(
        "acc-0003",
        "charlie@example.com",
        "1//RT_C3_STALE_OLD",
        now + 3600,
        now - 1000,
    );
    stale_acc3_backup.auth_generation = 3;
    stale_acc3_backup.previous_refresh_token_digests.clear();
    let misplaced_bytes = serde_json::to_vec_pretty(&stale_acc3_backup).unwrap();
    fs::write(paths.account_file("acc-0001"), &misplaced_bytes).unwrap();

    // Direct `load_account_opt` MUST reject ID mismatch with `data_error`!
    let direct_err = repo
        .with_write_lock(|tx| tx.load_account_opt("acc-0001").map(|_| ()))
        .unwrap_err();
    assert_eq!(direct_err.error_code, "data_error");

    // Read-only `status --json` reports exit 7 (`committed_index_pending`) and `store_ok=false`.
    let st = env
        .cli_cmd()
        .args(["--backend", "file", "--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st.status.code(), Some(7));
    let st_j: serde_json::Value = serde_json::from_slice(&st.stderr).unwrap();
    assert_eq!(st_j["details"]["store_ok"], false);

    // 3. Reconcile via `auth pending --purge --json`: MUST exit 0, commit `acc-0002`, clear journal,
    //    leave misplaced `acc-0001.json` bytes untouched, AND NEVER overwrite `acc-0003.json`!
    let purge = env
        .cli_cmd()
        .args(["--backend", "file", "--json", "auth", "pending", "--purge"])
        .output()
        .unwrap();
    assert_eq!(
        purge.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&purge.stderr)
    );
    assert!(!paths.switch_journal_file().exists());
    assert_eq!(
        fs::read(paths.account_file("acc-0001")).unwrap(),
        misplaced_bytes,
        "Misplaced outgoing account file must remain untouched"
    );
    assert_eq!(
        fs::read(paths.account_file("acc-0003")).unwrap(),
        acc3_orig_bytes,
        "P1-01: Unrelated account file bytes MUST remain byte-for-byte unchanged"
    );
    let acc3_after = repo.read_account_unchecked("acc-0003").unwrap();
    assert_eq!(acc3_after.token.refresh_token, "1//RT_C3_CURRENT");
    assert_eq!(acc3_after.auth_generation, 31);
    assert_eq!(acc3_after.previous_refresh_token_digests.len(), 1);
    let acc2_after = repo.read_account_unchecked("acc-0002").unwrap();
    assert!(acc2_after.last_switched_in_at.is_some());
    assert_eq!(acc2_after.last_switched_out_at, None);
    let idx_raw: serde_json::Value =
        serde_json::from_slice(&fs::read(paths.index_file()).unwrap()).unwrap();
    assert_eq!(idx_raw["selected_account_id"], "acc-0002");
}

#[tokio::test]
async fn g01_committed_index_pending_persistent_index_fsync_io_returns_exit_7_until_cleared() {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    let mut acc1 = make_account(
        "acc-0001",
        "alice@example.com",
        "1//RT_G01_A",
        now + 7200,
        now,
    );
    acc1.last_switched_in_at = Some(now - 600);
    let acc2 = make_account(
        "acc-0002",
        "bob@example.com",
        "1//RT_G01_B",
        now + 7200,
        now,
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc1.token).unwrap())
        .unwrap();

    // 1. Switch under persistent `sync_parent_dir:index.json:io` commits slot then fails index fsync -> exit 7.
    let sw_fail = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "sync_parent_dir:index.json:io")
        .args(["--backend", "file", "--json", "switch", "acc-0002"])
        .output()
        .unwrap();
    assert_eq!(sw_fail.status.code(), Some(7));
    let journal_bytes = fs::read(paths.switch_journal_file()).unwrap();
    let slot_bytes = fs::read(&paths.active_slot_file).unwrap();
    let journal_ts = read_journal_readonly(&paths).unwrap().unwrap().updated_at;
    assert!(String::from_utf8_lossy(&slot_bytes).contains("1//RT_G01_B"));

    // 2. Two consecutive write replays under the SAME persistent fault MUST BOTH exit 7
    //    (`committed_index_pending`), preserving exact journal & slot bytes!
    for attempt in 1..=2 {
        let replay = env
            .cli_cmd()
            .env("AGY_SWITCH_CLI_FAULT_SPEC", "sync_parent_dir:index.json:io")
            .args(["--backend", "file", "--json", "auth", "pending", "--purge"])
            .output()
            .unwrap();
        assert_eq!(
            replay.status.code(),
            Some(7),
            "G-01 replay attempt {attempt} under persistent index fsync fault must return exit 7; stderr={}",
            String::from_utf8_lossy(&replay.stderr)
        );
        let err_j: serde_json::Value = serde_json::from_slice(&replay.stderr).unwrap();
        assert_eq!(err_j["exit_code"], 7);
        assert_eq!(err_j["error_code"], "committed_index_pending");
        assert_eq!(
            fs::read(paths.switch_journal_file()).unwrap(),
            journal_bytes
        );
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_bytes);
    }

    // Read-only `status --json` continues reporting exit 7 while fault persists.
    let st = env
        .cli_cmd()
        .args(["--backend", "file", "--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st.status.code(), Some(7));

    // 3. Clearing fault -> replay returns 0, commits `acc-0002`, preserves verified `journal_ts`, clears journal!
    let ok_replay = env
        .cli_cmd()
        .args(["--backend", "file", "--json", "auth", "pending", "--purge"])
        .output()
        .unwrap();
    assert_eq!(
        ok_replay.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&ok_replay.stderr)
    );
    assert!(!paths.switch_journal_file().exists());
    let snap = repo.read_snapshot().unwrap();
    assert_eq!(snap.index.selected_account_id.as_deref(), Some("acc-0002"));
    assert_eq!(
        repo.read_account_unchecked("acc-0001")
            .unwrap()
            .last_switched_out_at,
        Some(journal_ts)
    );
    assert_eq!(
        repo.read_account_unchecked("acc-0002")
            .unwrap()
            .last_switched_in_at,
        Some(journal_ts)
    );
}

#[tokio::test]
async fn r3_01_committed_index_pending_journal_clear_parent_sync_failure_preserves_journal_and_exits_7(
) {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    let mut acc1 = make_account(
        "acc-0001",
        "alice@example.com",
        "1//RT_R301_A",
        now + 7200,
        now,
    );
    acc1.last_switched_in_at = Some(now - 600);
    let acc2 = make_account(
        "acc-0002",
        "bob@example.com",
        "1//RT_R301_B",
        now + 7200,
        now,
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc1.token).unwrap())
        .unwrap();

    // 1. Switch `acc-0001 -> acc-0002` fails at `before_index_commit` -> exit 7 (`CommittedIndexPending`).
    let sw_fail = env
        .cli_cmd()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_index_commit:index.json:io",
        )
        .args(["--backend", "file", "--json", "switch", "acc-0002"])
        .output()
        .unwrap();
    assert_eq!(sw_fail.status.code(), Some(7));
    let journal_path = paths.switch_journal_file();
    let orig_journal_bytes = fs::read(&journal_path).unwrap();
    let slot_bytes = fs::read(&paths.active_slot_file).unwrap();
    let journal_ts = read_journal_readonly(&paths).unwrap().unwrap().updated_at;
    assert!(String::from_utf8_lossy(&slot_bytes).contains("1//RT_R301_B"));

    // 2. Persistent `sync_parent_dir:switch_journal.json:io` during replay:
    //    `clear_journal` unlinks in dcache then fails parent-dir fsync -> MUST restore the
    //    `0600` journal file without overwriting any concurrent file, keep returning exit 7
    //    across repeated retries, AND keep `status --json` returning exit 7!
    for attempt in 1..=2 {
        let replay = env
            .cli_cmd()
            .env(
                "AGY_SWITCH_CLI_FAULT_SPEC",
                "sync_parent_dir:switch_journal.json:io",
            )
            .args(["--backend", "file", "--json", "auth", "pending", "--purge"])
            .output()
            .unwrap();
        assert_eq!(
            replay.status.code(),
            Some(7),
            "R3-01 replay attempt {attempt} must exit 7; stderr={}",
            String::from_utf8_lossy(&replay.stderr)
        );
        let err_j: serde_json::Value = serde_json::from_slice(&replay.stderr).unwrap();
        assert_eq!(err_j["exit_code"], 7);
        assert_eq!(err_j["error_code"], "committed_index_pending");
        assert!(
            journal_path.exists(),
            "R3-01 attempt {attempt}: switch_journal.json must still exist for retry"
        );
        assert_eq!(
            fs::metadata(&journal_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&journal_path).unwrap(), orig_journal_bytes);
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_bytes);

        let st = env
            .cli_cmd()
            .env(
                "AGY_SWITCH_CLI_FAULT_SPEC",
                "sync_parent_dir:switch_journal.json:io",
            )
            .args(["--backend", "file", "--json", "status"])
            .output()
            .unwrap();
        assert_eq!(
            st.status.code(),
            Some(7),
            "R3-01 attempt {attempt}: status --json must still exit 7 while journal-clear durability is unconfirmed"
        );
    }

    // Also verify `restore_regular_file_if_absent_under` (`O_EXCL`) NEVER overwrites an existing file!
    assert!(
        agy_switch_cli::store::fs_atomic::restore_regular_file_if_absent_under(
            &paths.data_dir,
            &journal_path,
            b"{\"must_not_overwrite\":true}",
            "switch journal",
        )
        .unwrap()
    );
    assert_eq!(fs::read(&journal_path).unwrap(), orig_journal_bytes);

    // 3. Clearing the fault -> next write replay returns 0, durably clears journal, preserves `journal_ts`!
    let ok_replay = env
        .cli_cmd()
        .args(["--backend", "file", "--json", "auth", "pending", "--purge"])
        .output()
        .unwrap();
    assert_eq!(
        ok_replay.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&ok_replay.stderr)
    );
    assert!(!journal_path.exists());
    let st_clean = env
        .cli_cmd()
        .args(["--backend", "file", "--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_clean.status.code(), Some(0));
    let snap = repo.read_snapshot().unwrap();
    assert_eq!(snap.index.selected_account_id.as_deref(), Some("acc-0002"));
    assert_eq!(
        repo.read_account_unchecked("acc-0001")
            .unwrap()
            .last_switched_out_at,
        Some(journal_ts)
    );
    assert_eq!(
        repo.read_account_unchecked("acc-0002")
            .unwrap()
            .last_switched_in_at,
        Some(journal_ts)
    );
}

#[tokio::test]
async fn synthetic_v123_r401_rejects_file_prev_uniform_false_and_allows_omitted_default_recovery() {
    use agy_switch_cli::session::payload::bytes_sha256_hex;

    let _guard = FAULT_ENV_MUTEX.lock().await;

    let setup_fixture = |omit_prev_uniform: bool| {
        let env = IsolatedEnv::new();
        env.init_agy_slot_dir();
        let paths = env.paths();
        let repo = env.repo();
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
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, now)?;
            tx.upsert_account(acc_b, false, now)?;
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

        (env, paths, repo)
    };

    // 1. Contradictory pure-file record (`file.prev_uniform=false`): BOTH `status` and `accounts disable`
    //    MUST return exit 7 and preserve journal, slot, index, and account files byte-for-byte.
    {
        let (env, paths, _repo) = setup_fixture(false);
        let journal_before = fs::read(paths.switch_journal_file()).unwrap();
        let slot_before = fs::read(&paths.active_slot_file).unwrap();
        let index_before = fs::read(paths.index_file()).unwrap();
        let acc_a_before = fs::read(paths.account_file("acc-0001")).unwrap();
        let acc_b_before = fs::read(paths.account_file("acc-0002")).unwrap();

        let status_out = env
            .cli_cmd()
            .args(["--backend", "file", "--json", "status"])
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
        assert_eq!(
            fs::read(paths.account_file("acc-0001")).unwrap(),
            acc_a_before
        );
        assert_eq!(
            fs::read(paths.account_file("acc-0002")).unwrap(),
            acc_b_before
        );

        let write_out = env
            .cli_cmd()
            .args([
                "--backend",
                "file",
                "--json",
                "accounts",
                "disable",
                "acc-0002",
            ])
            .output()
            .unwrap();
        assert_eq!(write_out.status.code(), Some(7));
        let write_err: serde_json::Value = serde_json::from_slice(&write_out.stderr).unwrap();
        assert_eq!(write_err["error_code"], "recovery_incomplete");
        assert_eq!(
            fs::read(paths.switch_journal_file()).unwrap(),
            journal_before
        );
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
        assert_eq!(fs::read(paths.index_file()).unwrap(), index_before);
        assert_eq!(
            fs::read(paths.account_file("acc-0001")).unwrap(),
            acc_a_before
        );
        assert_eq!(
            fs::read(paths.account_file("acc-0002")).unwrap(),
            acc_b_before
        );
    }

    // 2. Recoverable positive control omitting `file.prev_uniform` (defaulting to `true`):
    //    `status` stays read-only (exit 0) and `accounts disable` completes reconciliation & clears journal.
    {
        let (env, paths, repo) = setup_fixture(true);
        let journal_before = fs::read(paths.switch_journal_file()).unwrap();
        let slot_before = fs::read(&paths.active_slot_file).unwrap();
        let index_before = fs::read(paths.index_file()).unwrap();

        let status_out = env
            .cli_cmd()
            .args(["--backend", "file", "--json", "status"])
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

        let write_out = env
            .cli_cmd()
            .args([
                "--backend",
                "file",
                "--json",
                "accounts",
                "disable",
                "acc-0002",
            ])
            .output()
            .unwrap();
        assert_eq!(write_out.status.code(), Some(0));
        assert!(!paths.switch_journal_file().exists());
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
        assert!(repo.read_account_unchecked("acc-0002").unwrap().disabled);
    }
}
