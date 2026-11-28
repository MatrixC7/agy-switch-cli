#![cfg(feature = "secret-service-backend")]

mod common;

use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend};
use agy_switch_cli::session::journal::{
    write_journal_with_replicas, JournalCollectionSnapshot, JournalPhase, JournalReplicaRecord,
    JournalReplicaSnapshot, SwitchJournal,
};
use agy_switch_cli::session::payload::{
    bytes_sha256_hex, serialize_session_payload, serialize_session_payload_for_account,
};
use agy_switch_cli::store::locks::ActiveSlotLock;
use agy_switch_cli::store::repository::StoreRepository;
use common::secret_service::{PrivateSecretServiceFixture, SecretServiceLayout};
use common::{make_rich_sample_account, write_fake_agy_script, IsolatedEnv};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn secret_service_backend_fails_cleanly_with_exit_8_in_isolated_dbus_free_env() {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();
    let acc = make_rich_sample_account("acc-ss", "ss@example.invalid", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    for mode in ["dual", "keyring"] {
        let out = env
            .cli_cmd()
            .args(["--backend", mode, "--json", "switch", "acc-ss"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(8),
            "mode={mode} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err_json: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(err_json["exit_code"], 8);

        let cur_out = env
            .cli_cmd()
            .args(["--backend", mode, "--json", "current"])
            .output()
            .unwrap();
        assert_eq!(cur_out.status.code(), Some(0));
        let cur_json: serde_json::Value = serde_json::from_slice(&cur_out.stdout).unwrap();
        assert_eq!(cur_json["session_identity"]["state"], "unverified");

        let st_out = env
            .cli_cmd()
            .args(["--backend", mode, "--json", "status"])
            .output()
            .unwrap();
        assert_eq!(
            st_out.status.code(),
            Some(0),
            "mode={mode} stderr={}",
            String::from_utf8_lossy(&st_out.stderr)
        );
        let st_json: serde_json::Value = serde_json::from_slice(&st_out.stdout).unwrap();
        assert_eq!(st_json["backend"], mode);
        assert_eq!(st_json["store_ok"], true);
        assert!(st_json.get("session_identity").is_none());
    }

    for legacy_alias in ["secret-service", "secret_service", "file_session"] {
        let rej = env
            .cli_cmd()
            .args(["--backend", legacy_alias, "--json", "current"])
            .output()
            .unwrap();
        assert_eq!(
            rej.status.code(),
            Some(2),
            "Expected exit 2 for removed backend alias {legacy_alias}"
        );
    }
}

#[test]
fn secret_service_backend_live_isolated_dbus_never_unlocks_on_readonly_and_tracks_rollback_failure()
{
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();
    let acc1 = make_rich_sample_account("acc-kr1", "alice@example.com", now);
    let acc2 = make_rich_sample_account("acc-kr2", "bob@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    let Some(mut ss) = PrivateSecretServiceFixture::start_bus_only(
        &env,
        "mock",
        SecretServiceLayout::LoginAndDefault,
        serde_json::json!({"login_locked": true, "item_locked": false, "fail_create_from_call": -1}),
    ) else {
        return;
    };

    // 0. Before `org.freedesktop.secrets` is registered on the live session bus, default `--backend`
    //    (`auto`) MUST fall back cleanly to `file` (headless SSH server with systemd user D-Bus).
    let st_headless_bus = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr())
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_headless_bus.status.code(), Some(0));
    let st_hb_j: serde_json::Value = serde_json::from_slice(&st_headless_bus.stdout).unwrap();
    assert_eq!(st_hb_j["backend"], "file");

    ss.start_provider();

    let ss_cli = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr())
            .args(["--backend", "dual"]);
        c
    };

    // 1. Locked collection (`login_locked: true`): read-only `current` & `status` succeed
    //    AND `unlock_calls` MUST remain strictly ZERO!
    let cur_locked = ss_cli().args(["--json", "current"]).output().unwrap();
    assert_eq!(cur_locked.status.code(), Some(0));
    let j: serde_json::Value = serde_json::from_slice(&cur_locked.stdout).unwrap();
    assert_eq!(j["session_identity"]["state"], "unverified");
    assert!(
        j["session_identity"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("keyring is locked"),
        "Expected locked keyring detail, got: {j}"
    );
    let status_locked = ss_cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(status_locked.status.code(), Some(0));
    let sj: serde_json::Value = serde_json::from_slice(&status_locked.stdout).unwrap();
    assert_eq!(sj["backend"], "dual");
    assert_eq!(sj["store_ok"], true);
    assert_eq!(
        ss.stats()["unlock_calls"],
        0,
        "Read-only current/status MUST NEVER call Unlock on locked collection!"
    );

    // 2. Write `switch acc-kr1`: unlocks collection, writes DH-encrypted secret to BOTH `login` + `default` + file!
    let sw1 = ss_cli()
        .args(["--json", "switch", "acc-kr1"])
        .output()
        .unwrap();
    assert_eq!(
        sw1.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sw1.stderr)
    );
    let st2 = ss.stats();
    assert_eq!(st2["unlock_calls"], 1);
    assert_eq!(st2["login_count"], 1);
    assert_eq!(st2["default_count"], 1);
    assert!(st2["login_secrets"][0]
        .as_str()
        .unwrap()
        .contains("SECRET_REFRESH_TOKEN_acc-kr1"));

    // Unlocked `current` now reports `matched` with ZERO additional `Unlock` calls!
    let st_ok = ss_cli().args(["--json", "current"]).output().unwrap();
    assert_eq!(st_ok.status.code(), Some(0));
    let st_ok_j: serde_json::Value = serde_json::from_slice(&st_ok.stdout).unwrap();
    assert_eq!(st_ok_j["session_identity"]["state"], "matched");
    assert_eq!(st_ok_j["session_identity"]["account_id"], "acc-kr1");
    let st3 = ss.stats();
    assert_eq!(st3["unlock_calls"], 1);

    // 2b. S03 + A04: Mixed-backend cross-process L1 contention on live private Secret Service!
    let other_store_dir = env.tmp_path().join("other-file-store");
    let other_paths = HeadlessPaths::with_explicit(
        env.home.clone(),
        other_store_dir.clone(),
        env.cache_dir.join("agy-switch-cli"),
    );
    let other_repo = StoreRepository::new(other_paths.clone());
    other_repo
        .with_write_lock(|tx| tx.upsert_account(acc2.clone(), true, now))
        .unwrap();

    let creates_before_mix = st3["create_calls"].as_i64().unwrap();
    let held_file_l1 = ActiveSlotLock::try_acquire(&other_paths, false).unwrap();
    let blocked_ss_sw = ss_cli()
        .args(["--json", "switch", "acc-kr2"])
        .output()
        .unwrap();
    assert_eq!(
        blocked_ss_sw.status.code(),
        Some(5),
        "File L1 MUST block concurrent secret-service switch with exit 5: stderr={}",
        String::from_utf8_lossy(&blocked_ss_sw.stderr)
    );
    assert_eq!(ss.stats()["create_calls"], creates_before_mix);
    drop(held_file_l1);

    let held_ss_l1 = ActiveSlotLock::try_acquire(&env.paths(), true).unwrap();
    let blocked_file_sw = env
        .cli_cmd_with_data_dir(&other_store_dir)
        .args(["--backend", "file", "--json", "switch", "acc-kr2"])
        .output()
        .unwrap();
    assert_eq!(blocked_file_sw.status.code(), Some(5));
    drop(held_ss_l1);

    // 3. Lock the item itself (`item_locked: true`) while collection stays unlocked:
    //    `current` MUST report `unverified` with ZERO `Unlock` calls (`unlock_calls` stays 1)!
    ss.set_ctrl(serde_json::json!({
        "login_locked": false,
        "item_locked": true,
        "fail_create_from_call": -1
    }));
    let st_item_locked = ss_cli().args(["--json", "current"]).output().unwrap();
    assert_eq!(st_item_locked.status.code(), Some(0));
    let st_il_j: serde_json::Value = serde_json::from_slice(&st_item_locked.stdout).unwrap();
    assert_eq!(st_il_j["session_identity"]["state"], "unverified");
    assert!(
        st_il_j["session_identity"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("keyring is locked"),
        "Expected locked item detail, got: {st_il_j}"
    );
    assert_eq!(
        ss.stats()["unlock_calls"],
        1,
        "Read-only status MUST NEVER call Unlock on a locked item!"
    );

    // 4. Inject conflicting duplicate item in `default` collection -> `status` reports Corrupt (exit code 1)!
    ss.set_ctrl(serde_json::json!({
        "login_locked": false,
        "item_locked": false,
        "inject_conflict": true,
        "fail_create_from_call": -1
    }));
    let st_conflict = ss_cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_conflict.status.code(), Some(1));
    let sw_conflict = ss_cli()
        .args(["--json", "switch", "acc-kr2"])
        .output()
        .unwrap();
    assert_eq!(sw_conflict.status.code(), Some(1));

    // 5. Clear duplicate item in mock keyring and verify `auto` backend behavior
    ss.set_ctrl(serde_json::json!({
        "login_locked": false,
        "item_locked": false,
        "clear_conflict": true,
        "fail_create_from_call": -1
    }));
    let sw_clean = ss_cli()
        .args(["--json", "switch", "acc-kr1"])
        .output()
        .unwrap();
    assert_eq!(sw_clean.status.code(), Some(0));

    {
        let auto_cli = || {
            let mut c = env.cli_cmd();
            c.env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr());
            c
        };

        let st_auto = auto_cli().args(["--json", "status"]).output().unwrap();
        assert_eq!(st_auto.status.code(), Some(0));
        let st_auto_j: serde_json::Value = serde_json::from_slice(&st_auto.stdout).unwrap();
        assert_eq!(st_auto_j["backend"], "dual");
        assert!(st_auto_j["dbus_keyring_warning"].is_null());

        fs::remove_file(&env.paths().active_slot_file).unwrap();
        assert!(!env.paths().active_slot_file.exists());
        let cur_after_rm = auto_cli().args(["--json", "current"]).output().unwrap();
        assert_eq!(cur_after_rm.status.code(), Some(0));
        let cur_rm_j: serde_json::Value = serde_json::from_slice(&cur_after_rm.stdout).unwrap();
        assert_eq!(cur_rm_j["session_identity"]["state"], "matched");
        assert_eq!(cur_rm_j["session_identity"]["account_id"], "acc-kr1");

        let sw_auto = auto_cli()
            .args(["--json", "switch", "acc-kr2"])
            .output()
            .unwrap();
        assert_eq!(sw_auto.status.code(), Some(0));
        assert!(env.paths().active_slot_file.exists());

        // Offline `--from-local` under `auto` reads valid keyring payload BEFORE corrupt disk file,
        // whereas `--backend file` hits disk JSON parse error.
        fs::write(&env.paths().active_slot_file, b"{corrupt-disk-json").unwrap();
        let add_kr = auto_cli()
            .args([
                "--proxy",
                "http://127.0.0.1:9",
                "--json",
                "accounts",
                "add",
                "--from-local",
            ])
            .output()
            .unwrap();
        assert_eq!(
            add_kr.status.code(),
            Some(0),
            "auto --from-local must read valid keyring payload first: stderr={}",
            String::from_utf8_lossy(&add_kr.stderr)
        );
        let add_kr_ok: serde_json::Value = serde_json::from_slice(&add_kr.stdout).unwrap();
        assert_eq!(add_kr_ok["created"], false);
        assert_eq!(add_kr_ok["account"]["id"], "acc-kr2");

        let add_file = auto_cli()
            .args([
                "--backend",
                "file",
                "--proxy",
                "http://127.0.0.1:9",
                "--json",
                "accounts",
                "add",
                "--from-local",
            ])
            .output()
            .unwrap();
        let add_file_err: serde_json::Value = serde_json::from_slice(&add_file.stderr).unwrap();
        assert_eq!(add_file_err["error_code"], "data_error");
        assert!(
            !add_file_err["message"]
                .as_str()
                .unwrap_or("")
                .contains("email"),
            "file --from-local must fail on corrupt disk JSON parse, got: {add_file_err}"
        );

        fs::remove_file(&env.paths().active_slot_file).unwrap();

        fs::write(
            env.paths().config_file(),
            r#"{"schema_version":1,"backend":"file"}"#,
        )
        .unwrap();
        fs::set_permissions(env.paths().config_file(), fs::Permissions::from_mode(0o600)).unwrap();
        let st_cfg_file = auto_cli().args(["--json", "status"]).output().unwrap();
        assert_eq!(st_cfg_file.status.code(), Some(0));
        let st_cf_j: serde_json::Value = serde_json::from_slice(&st_cfg_file.stdout).unwrap();
        assert_eq!(st_cf_j["backend"], "file");
        fs::remove_file(env.paths().config_file()).unwrap();

        let sw_restore = ss_cli()
            .args(["--json", "switch", "acc-kr1"])
            .output()
            .unwrap();
        assert_eq!(sw_restore.status.code(), Some(0));
    }

    // 6. Simulate disk ENOSPC + failing keyring rollback -> exit code 7 (`RecoveryIncomplete`)!
    let base_creates = ss.stats()["create_calls"].as_i64().unwrap();
    ss.set_ctrl(serde_json::json!({
        "login_locked": false,
        "item_locked": false,
        "fail_create_from_call": base_creates + 3
    }));
    let sw_rb_fail = ss_cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_write:antigravity-oauth-token:enospc",
        )
        .args(["--json", "switch", "acc-kr2"])
        .output()
        .unwrap();
    assert_eq!(
        sw_rb_fail.status.code(),
        Some(7),
        "Failed keyring rollback must return exit code 7 (RecoveryIncomplete): stderr={}",
        String::from_utf8_lossy(&sw_rb_fail.stderr)
    );
    let rb_err_j: serde_json::Value = serde_json::from_slice(&sw_rb_fail.stderr).unwrap();
    assert_eq!(rb_err_j["error_code"], "recovery_incomplete");
}

#[test]
fn synthetic_v120_dual_write_replica_divergence_dbus_wall_timeout_and_run_isolate_dbus() {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();
    let acc1 = make_rich_sample_account("acc-dw1", "alice@example.com", now);
    let acc2 = make_rich_sample_account("acc-dw2", "bob@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    // 1. P1-07: Non-local `tcp:` D-Bus address is rejected by `auto` (immediate fallback to `file`)
    //    AND stalling local Unix socket falls back cleanly to `file` within wall-clock cap!
    let tcp_st = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", "tcp:host=127.0.0.1,port=1")
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(tcp_st.status.code(), Some(0));
    let tcp_j: serde_json::Value = serde_json::from_slice(&tcp_st.stdout).unwrap();
    assert_eq!(tcp_j["backend"], "file");

    let stall_sock = env.runtime_dir.join("stall-dbus.sock");
    let listener = std::os::unix::net::UnixListener::bind(&stall_sock).unwrap();
    let stall_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stall_stop_bg = stall_stop.clone();
    let _staller = std::thread::spawn(move || {
        let mut held = Vec::new();
        let _ = listener.set_nonblocking(true);
        while !stall_stop_bg.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok((stream, _)) = listener.accept() {
                held.push(stream);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    });
    let t0 = std::time::Instant::now();
    let stall_st = env
        .cli_cmd()
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", stall_sock.display()),
        )
        .args(["--json", "status"])
        .output()
        .unwrap();
    let elapsed = t0.elapsed();
    stall_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(stall_st.status.code(), Some(0));
    assert!(
        elapsed < std::time::Duration::from_secs(4),
        "Stalling D-Bus probe exceeded wall-clock bound: {elapsed:?}"
    );
    let stall_j: serde_json::Value = serde_json::from_slice(&stall_st.stdout).unwrap();
    assert_eq!(stall_j["backend"], "file");

    // 2. Live isolated Secret Service (`login` only)
    let Some(ss) = PrivateSecretServiceFixture::start(
        &env,
        "dw",
        SecretServiceLayout::SingleLogin,
        serde_json::json!({"fail_create": false, "fail_msg": "SENSITIVE_DBUS_EXCEPTION_PAYLOAD_999"}),
    ) else {
        return;
    };

    let auto_bus = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr());
        c
    };

    let sw1 = auto_bus()
        .args(["--json", "switch", "acc-dw1"])
        .output()
        .unwrap();
    assert_eq!(sw1.status.code(), Some(0));
    assert_eq!(
        ss.stats()["create_calls"],
        1,
        "`auto` must activate `dual` on live isolated D-Bus"
    );

    // 3. P1-07: D-Bus exception text is redacted without echoing raw provider message!
    ss.set_ctrl(serde_json::json!({
        "fail_create": true,
        "fail_msg": "SENSITIVE_DBUS_EXCEPTION_PAYLOAD_999"
    }));
    let dbus_fail_sw = auto_bus()
        .args(["--json", "switch", "acc-dw2"])
        .output()
        .unwrap();
    assert_eq!(dbus_fail_sw.status.code(), Some(8));
    let dbus_fail_stderr = String::from_utf8_lossy(&dbus_fail_sw.stderr);
    assert!(
        !dbus_fail_stderr.contains("SENSITIVE_DBUS_EXCEPTION_PAYLOAD_999"),
        "Leaked raw D-Bus exception payload: {dbus_fail_stderr}"
    );
    ss.set_ctrl(serde_json::json!({"fail_create": false}));

    // 4. Explicit `--backend file` isolates child D-Bus (`unix:path=/dev/null`), whereas `auto` fallback leaves it untouched!
    let fake_bin_dir = env.tmp_path().join("fake_bin");
    fs::create_dir_all(&fake_bin_dir).unwrap();
    let seen_dbus_file = env.tmp_path().join("child_dbus_seen.txt");
    let fake_agy = write_fake_agy_script(
        &fake_bin_dir,
        "agy",
        &format!(
            "#!/bin/sh\nprintf '%s' \"$DBUS_SESSION_BUS_ADDRESS\" > \"{}\"\nexit 0\n",
            seen_dbus_file.display()
        ),
    );

    let removed_flag = auto_bus()
        .args(["run", "--isolate-dbus", "--", fake_agy.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(removed_flag.status.code(), Some(2));

    let creates_before_run = ss.stats()["create_calls"].clone();
    let run_file_flag = auto_bus()
        .args([
            "--backend",
            "file",
            "run",
            "--account",
            "acc-dw2",
            "--",
            fake_agy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        run_file_flag.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&run_file_flag.stderr)
    );
    assert_eq!(
        fs::read_to_string(&seen_dbus_file).unwrap(),
        "unix:path=/dev/null"
    );
    assert_eq!(
        ss.stats()["create_calls"],
        creates_before_run,
        "`--backend file run` must not touch keyring"
    );
    assert!(fs::read_to_string(&env.paths().active_slot_file)
        .unwrap()
        .contains("SECRET_REFRESH_TOKEN_acc-dw2"));

    // Explicit env + config.json `"backend": "file"` ALSO auto-isolate child D-Bus
    let _ = fs::remove_file(&seen_dbus_file);
    assert_eq!(
        auto_bus()
            .env("AGY_SWITCH_CLI_BACKEND", "file")
            .args(["run", "--", fake_agy.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        fs::read_to_string(&seen_dbus_file).unwrap(),
        "unix:path=/dev/null"
    );

    let _ = fs::remove_file(&seen_dbus_file);
    fs::write(
        env.paths().config_file(),
        r#"{"schema_version":1,"backend":"file"}"#,
    )
    .unwrap();
    fs::set_permissions(env.paths().config_file(), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        auto_bus()
            .args(["run", "--", fake_agy.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        fs::read_to_string(&seen_dbus_file).unwrap(),
        "unix:path=/dev/null"
    );
    fs::remove_file(env.paths().config_file()).unwrap();

    // `auto` fallback to `file` leaves child `DBUS_SESSION_BUS_ADDRESS` untouched
    let headless_bus_addr = format!("unix:path={}/no-dbus", env.runtime_dir.display());
    let _ = fs::remove_file(&seen_dbus_file);
    let run_auto_fallback = env
        .cli_cmd()
        .args(["run", "--", fake_agy.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(run_auto_fallback.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(&seen_dbus_file).unwrap(),
        headless_bus_addr
    );

    // Sync both replicas back to `acc-dw1`
    assert_eq!(
        auto_bus()
            .args(["--json", "switch", "acc-dw1"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );

    // 5a. One-shot post-rename disk fault rolls back BOTH keyring AND disk to `acc-dw1`
    let post_rename_rb = auto_bus()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_rename:antigravity-oauth-token:corrupt_once",
        )
        .args(["--json", "switch", "acc-dw2"])
        .output()
        .unwrap();
    assert_eq!(post_rename_rb.status.code(), Some(1));
    assert!(!env.paths().switch_journal_file().exists());
    let disk_after_rb = fs::read_to_string(&env.paths().active_slot_file).unwrap();
    assert!(disk_after_rb.contains("SECRET_REFRESH_TOKEN_acc-dw1"));
    assert!(ss.stats()["secrets"][0]
        .as_str()
        .unwrap()
        .contains("SECRET_REFRESH_TOKEN_acc-dw1"));

    // 5b. Persistent post-rename disk fault preserves journal & exits 7 (`RecoveryIncomplete`)
    let persistent_fault = auto_bus()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_rename:antigravity-oauth-token:corrupt_after_rename",
        )
        .args(["--json", "switch", "acc-dw2"])
        .output()
        .unwrap();
    assert_eq!(persistent_fault.status.code(), Some(7));
    assert!(env.paths().switch_journal_file().exists());
    assert_eq!(
        auto_bus()
            .args(["--json", "accounts", "enable", "acc-dw1"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    assert!(!env.paths().switch_journal_file().exists());
    assert_eq!(
        auto_bus()
            .args(["--json", "switch", "acc-dw1"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );

    // 6. Mid-dual-write crash (`before_write:antigravity-oauth-token:abort`):
    //    diverged replicas block read-only & narrowed `--backend file` with exit 7, then `auto` write heals both!
    let crash_dw = auto_bus()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_write:antigravity-oauth-token:abort",
        )
        .args(["--json", "switch", "acc-dw2"])
        .output()
        .unwrap();
    assert_eq!(crash_dw.status.code(), Some(137));
    assert!(env.paths().switch_journal_file().exists());

    for check_args in [
        vec!["--json", "status"],
        vec!["--json", "switch", "--dry-run", "acc-dw1"],
        vec![
            "--backend",
            "file",
            "--json",
            "accounts",
            "enable",
            "acc-dw1",
        ],
    ] {
        let blocked = auto_bus().args(&check_args).output().unwrap();
        assert_eq!(
            blocked.status.code(),
            Some(7),
            "Expected exit 7 on diverged replicas for {check_args:?}, stderr={}",
            String::from_utf8_lossy(&blocked.stderr)
        );
        assert!(env.paths().switch_journal_file().exists());
    }

    let heal_dw = auto_bus()
        .args(["--json", "accounts", "enable", "acc-dw1"])
        .output()
        .unwrap();
    assert_eq!(
        heal_dw.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&heal_dw.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    let synced_disk = fs::read_to_string(&env.paths().active_slot_file).unwrap();
    assert_eq!(synced_disk, ss.stats()["secrets"][0].as_str().unwrap());
    assert!(synced_disk.contains("SECRET_REFRESH_TOKEN_acc-dw2"));

    // 7. Corrupt local disk replica while keyring holds valid item -> `status` exits 1 with `slot_corrupt: true`
    fs::write(&env.paths().active_slot_file, b"{corrupt-disk-replica").unwrap();
    let corrupt_st = auto_bus().args(["--json", "status"]).output().unwrap();
    assert_eq!(corrupt_st.status.code(), Some(1));
    let corrupt_err: serde_json::Value = serde_json::from_slice(&corrupt_st.stderr).unwrap();
    assert_eq!(corrupt_err["details"]["slot_corrupt"], true);
}

#[test]
fn synthetic_v120_multicollection_asymmetric_keyring_rollback_swap_and_external_sync() {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();
    let acc1 = make_rich_sample_account("acc-mc1", "alice@example.com", now);
    let acc2 = make_rich_sample_account("acc-mc2", "bob@example.com", now);
    let acc_ext = make_rich_sample_account("acc-ext", "charlie@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    let payload_1 = serialize_session_payload(&acc1.token).unwrap();
    let payload_ext = serialize_session_payload(&acc_ext.token).unwrap();
    FileSessionBackend
        .write_slot(&env.paths(), &payload_1)
        .unwrap();

    let Some(ss) = PrivateSecretServiceFixture::start(
        &env,
        "mc",
        SecretServiceLayout::LoginAndCustomDefault,
        serde_json::json!({
            "reseed": true,
            "login": payload_1,
            "default": serde_json::Value::Null,
        }),
    ) else {
        return;
    };

    let auto_bus = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr());
        c
    };

    // 1. Asymmetric pre-switch collections (`login = Some(acc1), custom_default = None`) + disk ENOSPC
    let enospc_rb = auto_bus()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_write:antigravity-oauth-token:enospc",
        )
        .args(["--json", "switch", "acc-mc2"])
        .output()
        .unwrap();
    assert_eq!(
        enospc_rb.status.code(),
        Some(1),
        "Asymmetric multi-collection rollback must exit 1: stderr={}",
        String::from_utf8_lossy(&enospc_rb.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    let st1 = ss.stats();
    assert_eq!(st1["login"].as_array().unwrap().len(), 1);
    assert_eq!(st1["default"].as_array().unwrap().len(), 0);

    // 2. Asymmetric pre-switch collections + one-shot post-rename fault (`corrupt_once`)
    let post_rb = auto_bus()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_rename:antigravity-oauth-token:corrupt_once",
        )
        .args(["--json", "switch", "acc-mc2"])
        .output()
        .unwrap();
    assert_eq!(post_rb.status.code(), Some(1));
    assert!(!env.paths().switch_journal_file().exists());
    let st2 = ss.stats();
    assert_eq!(st2["login"].as_array().unwrap().len(), 1);
    assert_eq!(st2["default"].as_array().unwrap().len(), 0);

    // 3. Abort before `write_slot` then swap collections (`login=None, default=acc1`) -> exit 7 (`RecoveryIncomplete`)
    let crash_pre = auto_bus()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "after_token_refreshed:*:abort")
        .args(["--json", "switch", "acc-mc2"])
        .output()
        .unwrap();
    assert_eq!(crash_pre.status.code(), Some(137));
    assert!(env.paths().switch_journal_file().exists());

    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": serde_json::Value::Null,
        "default": payload_1,
    }));
    let swap_st = auto_bus().args(["--json", "status"]).output().unwrap();
    assert_eq!(swap_st.status.code(), Some(7));

    // 4. External `agy` logs into a 3rd account (`acc_ext`) in `login` only -> write self-healing preserves & syncs!
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_ext,
        "default": serde_json::Value::Null,
    }));
    let fix_ext = auto_bus()
        .args(["--json", "accounts", "enable", "acc-mc1"])
        .output()
        .unwrap();
    assert_eq!(
        fix_ext.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&fix_ext.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    let disk_ext = fs::read_to_string(&env.paths().active_slot_file).unwrap();
    let st_ext = ss.stats();
    assert!(disk_ext.contains("SECRET_REFRESH_TOKEN_acc-ext"));
    assert_eq!(st_ext["login"][0].as_str().unwrap(), disk_ext);
    assert_eq!(st_ext["default"][0].as_str().unwrap(), disk_ext);
}

#[test]
fn synthetic_v120_keyring_only_backend_never_creates_modifies_or_requires_local_file() {
    let env = IsolatedEnv::new();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();
    let acc1 = make_rich_sample_account("acc-ko1", "alice@example.com", now);
    let acc2 = make_rich_sample_account("acc-ko2", "bob@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    let Some(ss) = PrivateSecretServiceFixture::start(
        &env,
        "ko",
        SecretServiceLayout::SingleLogin,
        serde_json::json!({}),
    ) else {
        return;
    };

    let kr_cli = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr())
            .args(["--backend", "keyring"]);
        c
    };

    // 1. Keyring empty + local file exists -> `--backend keyring accounts add --from-local` returns exit 3
    env.init_agy_slot_dir();
    FileSessionBackend
        .write_slot(
            &env.paths(),
            &serialize_session_payload(&acc1.token).unwrap(),
        )
        .unwrap();
    let add_empty_kr = kr_cli()
        .args(["--json", "accounts", "add", "--from-local"])
        .output()
        .unwrap();
    assert_eq!(add_empty_kr.status.code(), Some(3));
    fs::remove_dir_all(&env.paths().active_slot_dir).unwrap();
    assert!(!env.paths().active_slot_dir.exists());

    // 2. `switch --dry-run` & `switch` succeed with ZERO local directory/file created!
    let dry_ko = kr_cli()
        .args(["--json", "switch", "--dry-run", "acc-ko2"])
        .output()
        .unwrap();
    assert_eq!(dry_ko.status.code(), Some(0));
    let sw_ko = kr_cli()
        .args(["--json", "switch", "acc-ko2"])
        .output()
        .unwrap();
    assert_eq!(sw_ko.status.code(), Some(0));
    assert!(!env.paths().active_slot_dir.exists());
    assert!(!env.paths().active_slot_file.exists());

    // 3. Corrupt local file is ignored and untouched by `--backend keyring`
    env.init_agy_slot_dir();
    fs::write(
        &env.paths().active_slot_file,
        b"{corrupt-local-file-ignored-by-keyring",
    )
    .unwrap();
    let cur_ko = kr_cli().args(["--json", "current"]).output().unwrap();
    assert_eq!(cur_ko.status.code(), Some(0));
    let cur_ko_j: serde_json::Value = serde_json::from_slice(&cur_ko.stdout).unwrap();
    assert_eq!(cur_ko_j["session_identity"]["state"], "matched");
    assert_eq!(cur_ko_j["session_identity"]["email"], "bob@example.com");

    let st_ko = kr_cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_ko.status.code(), Some(0));
    let st_ko_j: serde_json::Value = serde_json::from_slice(&st_ko.stdout).unwrap();
    assert_eq!(st_ko_j["backend"], "keyring");
    assert_eq!(st_ko_j["store_ok"], true);
    assert_eq!(st_ko_j["slot_initialized"], true);
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        "{corrupt-local-file-ignored-by-keyring"
    );

    // 4. `accounts delete --force --clear-active-slot` clears keyring ONLY, leaving local file untouched
    let del_ko = kr_cli()
        .args([
            "--json",
            "accounts",
            "delete",
            "acc-ko2",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(del_ko.status.code(), Some(0));
    assert_eq!(ss.stats()["secrets"].as_array().unwrap().len(), 0);
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        "{corrupt-local-file-ignored-by-keyring"
    );

    // 5a. Cross-backend journal scoping: `keyring`-only RecoveryIncomplete repaired under `auto` without creating local dir
    fs::remove_dir_all(&env.paths().active_slot_dir).unwrap();
    let mut ko_incomplete = SwitchJournal::new_prepared(
        "op-ko-inc".into(),
        Some("acc-ko1".into()),
        "acc-ko1".into(),
        None,
        now,
    );
    ko_incomplete.phase = JournalPhase::RecoveryIncomplete;
    ko_incomplete.note = Some("Simulated keyring rollback interruption.".into());
    let ko_meta = JournalReplicaRecord {
        backend: "keyring".into(),
        uses_file: false,
        keyring: Some(JournalReplicaSnapshot {
            prev_present: false,
            prev_digest: None,
            prev_uniform: true,
            collections: vec![JournalCollectionSnapshot {
                path: "/org/freedesktop/secrets/collection/login".into(),
                prev_present: false,
                prev_digest: None,
            }],
        }),
        file: JournalReplicaSnapshot {
            prev_present: false,
            prev_digest: None,
            prev_uniform: true,
            collections: Vec::new(),
        },
    };
    repo.with_write_lock(|_| {
        write_journal_with_replicas(&env.paths(), &ko_incomplete, Some(&ko_meta))
    })
    .unwrap();

    let auto_fix_ko = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr())
        .args(["--json", "accounts", "enable", "acc-ko1"])
        .output()
        .unwrap();
    assert_eq!(
        auto_fix_ko.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&auto_fix_ko.stderr)
    );
    assert!(!env.paths().active_slot_dir.exists());
    assert!(!env.paths().switch_journal_file().exists());
    assert!(ss.stats()["secrets"][0]
        .as_str()
        .unwrap()
        .contains("SECRET_REFRESH_TOKEN_acc-ko1"));

    // 5b. `CommittedSlot` keyring journal for deleted target MUST NOT delete unrelated local file
    let acc3 = make_rich_sample_account("acc-ko3", "charlie@example.com", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc3.clone(), false, now))
        .unwrap();
    env.init_agy_slot_dir();
    let payload_ko1 = serialize_session_payload_for_account(&acc1).unwrap();
    FileSessionBackend
        .write_slot(&env.paths(), &payload_ko1)
        .unwrap();

    let crash_ko3 = kr_cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "after_slot_commit:*:abort")
        .args(["--json", "switch", "acc-ko3"])
        .output()
        .unwrap();
    assert_eq!(crash_ko3.status.code(), Some(137));
    repo.with_write_lock(|tx| tx.delete_account("acc-ko3", true, now))
        .unwrap();

    let rec_del_ko3 = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr())
        .args(["--json", "accounts", "enable", "acc-ko1"])
        .output()
        .unwrap();
    assert_eq!(rec_del_ko3.status.code(), Some(0));
    assert!(!env.paths().switch_journal_file().exists());
    assert_eq!(ss.stats()["secrets"].as_array().unwrap().len(), 0);
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        payload_ko1
    );

    // 5c. Reverse: `file`-only RecoveryIncomplete repaired under `auto` MUST preserve keyring untouched
    let acc4 = make_rich_sample_account("acc-ko4", "dave@example.com", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc4.clone(), false, now))
        .unwrap();
    assert_eq!(
        kr_cli()
            .args(["--json", "switch", "acc-ko4"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    fs::write(&env.paths().active_slot_file, b"{corrupt-file-replica").unwrap();
    let mut file_inc = SwitchJournal::new_prepared(
        "op-file-inc".into(),
        Some("acc-ko1".into()),
        "acc-ko1".into(),
        None,
        now,
    );
    file_inc.phase = JournalPhase::RecoveryIncomplete;
    file_inc.note = Some("Simulated file rollback failure.".into());
    let file_meta = JournalReplicaRecord {
        backend: "file".into(),
        uses_file: true,
        keyring: None,
        file: JournalReplicaSnapshot {
            prev_present: true,
            prev_digest: Some(bytes_sha256_hex(payload_ko1.as_bytes())),
            prev_uniform: true,
            collections: Vec::new(),
        },
    };
    repo.with_write_lock(|_| {
        write_journal_with_replicas(&env.paths(), &file_inc, Some(&file_meta))
    })
    .unwrap();

    let rec_file_only = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr())
        .args(["--json", "accounts", "enable", "acc-ko1"])
        .output()
        .unwrap();
    assert_eq!(rec_file_only.status.code(), Some(0));
    assert!(!env.paths().switch_journal_file().exists());
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        payload_ko1
    );
    assert!(ss.stats()["secrets"][0]
        .as_str()
        .unwrap()
        .contains("SECRET_REFRESH_TOKEN_acc-ko4"));
}

#[test]
fn synthetic_v120_signoff_round2_disk_external_cas_alias_err_missing_col_delete_tx_and_cross_scope()
{
    let env = IsolatedEnv::new();
    let now = agy_switch_cli::domain::clock::current_unix_seconds();
    let repo = env.repo();
    let acc1 = make_rich_sample_account("acc-s1", "alice@example.com", now);
    let acc2 = make_rich_sample_account("acc-s2", "bob@example.com", now);
    let acc_ext_disk = make_rich_sample_account("acc-ext-disk", "charlie@example.com", now);
    let acc_ext_kr = make_rich_sample_account("acc-ext-kr", "dana@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    let payload_1 = serialize_session_payload(&acc1.token).unwrap();
    let payload_2 = serialize_session_payload(&acc2.token).unwrap();
    let payload_ext_disk = serialize_session_payload(&acc_ext_disk.token).unwrap();
    let payload_ext_kr = serialize_session_payload(&acc_ext_kr.token).unwrap();

    env.init_agy_slot_dir();
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    // 0. Stalling local socket respects tight `< 2300ms` wall-clock cap
    let stall_sock = env.runtime_dir.join("r2-stall.sock");
    let listener = std::os::unix::net::UnixListener::bind(&stall_sock).unwrap();
    let stall_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stall_stop_bg = stall_stop.clone();
    let _staller = std::thread::spawn(move || {
        let mut held = Vec::new();
        let _ = listener.set_nonblocking(true);
        while !stall_stop_bg.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok((stream, _)) = listener.accept() {
                held.push(stream);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    });
    let t0 = std::time::Instant::now();
    let stall_out = env
        .cli_cmd()
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", stall_sock.display()),
        )
        .args(["--json", "current"])
        .output()
        .unwrap();
    let stall_elapsed = t0.elapsed();
    stall_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(stall_out.status.code(), Some(0));
    assert!(
        stall_elapsed < std::time::Duration::from_millis(2300),
        "Auto D-Bus probe exceeded 2300ms budget: {stall_elapsed:?}"
    );

    let Some(mut ss) = PrivateSecretServiceFixture::start(
        &env,
        "r2",
        SecretServiceLayout::LoginAndCustomDefault,
        serde_json::json!({
            "reseed": true,
            "login": payload_1,
            "default": payload_1,
        }),
    ) else {
        return;
    };

    let bus_addr = ss.bus_addr().to_string();
    let dbus_pid = ss.dbus_pid();
    let bus_cmd = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", &bus_addr);
        c
    };

    // Non-canonical `..` D-Bus socket path MUST be rejected by `auto` (falls back to `file`)!
    let dotdot_bus = format!(
        "unix:path={}/../{}/r2-secrets.sock",
        env.runtime_dir.display(),
        env.runtime_dir.file_name().unwrap().to_string_lossy()
    );
    let dotdot_st = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &dotdot_bus)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(dotdot_st.status.code(), Some(0));
    let dd_j: serde_json::Value = serde_json::from_slice(&dotdot_st.stdout).unwrap();
    assert_eq!(dd_j["backend"], "file");

    // 1. F0-02a/b/c: Abort dual-write at `SlotCommitting`, place external 3rd credential on disk
    let crash_sw = bus_cmd()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_write:antigravity-oauth-token:abort",
        )
        .args(["--json", "switch", "acc-s2"])
        .output()
        .unwrap();
    assert_eq!(crash_sw.status.code(), Some(137));
    assert!(env.paths().switch_journal_file().exists());

    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
    }));
    fs::write(&env.paths().active_slot_file, &payload_ext_disk).unwrap();

    assert_eq!(
        bus_cmd()
            .args(["--json", "status"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );

    // F0-02b: ReadAlias failure preserves journal & exits 7
    ss.set_ctrl(serde_json::json!({
        "reseed": false,
        "fail_read_alias": true,
    }));
    assert_eq!(
        bus_cmd()
            .args(["--json", "accounts", "enable", "acc-s2"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );
    assert!(env.paths().switch_journal_file().exists());

    // F0-02c: Missing recorded collection preserves journal & exits 7
    ss.set_ctrl(serde_json::json!({
        "reseed": false,
        "fail_read_alias": false,
        "hide_default": true,
    }));
    assert_eq!(
        bus_cmd()
            .args(["--json", "accounts", "enable", "acc-s2"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );
    assert!(env.paths().switch_journal_file().exists());

    // F0-02a conflict: distinct external credentials on disk vs keyring -> refuses overwrite, exits 7
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_ext_kr,
    }));
    assert_eq!(
        bus_cmd()
            .args(["--json", "accounts", "enable", "acc-s2"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );
    assert!(env.paths().switch_journal_file().exists());
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        payload_ext_disk
    );

    // Restore keyring to `acc-s1` while disk has `acc-ext-disk` -> self-healing preserves `acc-ext-disk` across ALL replicas!
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
    }));
    let disk_ext_fix = bus_cmd()
        .args(["--json", "accounts", "enable", "acc-s2"])
        .output()
        .unwrap();
    assert_eq!(
        disk_ext_fix.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&disk_ext_fix.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        payload_ext_disk
    );
    let st_after_ext = ss.stats();
    assert_eq!(st_after_ext["login"][0].as_str().unwrap(), payload_ext_disk);
    assert_eq!(
        st_after_ext["default"][0].as_str().unwrap(),
        payload_ext_disk
    );

    // 2. F0-02d: Legacy journal without `replica_state` refused under `file` & `keyring`, repaired under `dual`
    let legacy_j = serde_json::json!({
        "schema_version": 1,
        "operation_id": "op-legacy-dual",
        "phase": "slot_committing",
        "prev_selected_account_id": "acc-s1",
        "target_account_id": "acc-s2",
        "prev_slot_digest": bytes_sha256_hex(payload_1.as_bytes()),
        "target_slot_digest": bytes_sha256_hex(payload_1.as_bytes()),
        "token_rotated": false,
        "started_at": now,
        "updated_at": now,
    });
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": serde_json::Value::Null,
    }));
    fs::write(
        env.paths().switch_journal_file(),
        serde_json::to_vec_pretty(&legacy_j).unwrap(),
    )
    .unwrap();

    for narrow in ["file", "keyring"] {
        assert_eq!(
            bus_cmd()
                .args([
                    "--backend",
                    narrow,
                    "--json",
                    "accounts",
                    "enable",
                    "acc-s2"
                ])
                .output()
                .unwrap()
                .status
                .code(),
            Some(7)
        );
    }
    assert!(env.paths().switch_journal_file().exists());
    assert_eq!(
        bus_cmd()
            .args([
                "--backend",
                "dual",
                "--json",
                "accounts",
                "enable",
                "acc-s2"
            ])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    assert!(!env.paths().switch_journal_file().exists());

    // 3. F0-02f: Repairing keyring-only journal under `auto` leaves local `.tmp.` & corrupt file untouched
    let stray_tmp = env
        .paths()
        .active_slot_dir
        .join("antigravity-oauth-token.tmp.keep-me");
    fs::write(&stray_tmp, b"partial-local").unwrap();
    fs::write(&env.paths().active_slot_file, b"{corrupt-local-disk-json").unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": serde_json::Value::Null,
    }));
    let kr_only_j = serde_json::json!({
        "schema_version": 1,
        "operation_id": "op-kr-scope",
        "phase": "recovery_incomplete",
        "prev_selected_account_id": "acc-s1",
        "target_account_id": "acc-s1",
        "token_rotated": false,
        "started_at": now,
        "updated_at": now,
        "replica_state": {
            "backend": "keyring",
            "uses_file": false,
            "keyring": {
                "prev_present": true,
                "prev_digest": bytes_sha256_hex(payload_1.as_bytes()),
                "prev_uniform": true,
                "collections": [
                    {
                        "path": "/org/freedesktop/secrets/collection/login",
                        "prev_present": true,
                        "prev_digest": bytes_sha256_hex(payload_1.as_bytes())
                    },
                    {
                        "path": "/org/freedesktop/secrets/collection/custom_default",
                        "prev_present": true,
                        "prev_digest": bytes_sha256_hex(payload_1.as_bytes())
                    }
                ]
            },
            "file": {"prev_present": false, "prev_uniform": true}
        }
    });
    fs::write(
        env.paths().switch_journal_file(),
        serde_json::to_vec_pretty(&kr_only_j).unwrap(),
    )
    .unwrap();
    let scoped_fix = bus_cmd()
        .args(["--json", "accounts", "enable", "acc-s2"])
        .output()
        .unwrap();
    assert_eq!(scoped_fix.status.code(), Some(0));
    assert!(stray_tmp.exists());
    assert_eq!(
        fs::read(&env.paths().active_slot_file).unwrap(),
        b"{corrupt-local-disk-json"
    );

    // 4. F1-07: `--backend keyring accounts delete acc-s1 --force --clear-active-slot` multi-collection tx
    fs::remove_dir_all(env.home.join(".gemini")).unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
        "fail_delete_from_call": 2,
    }));

    // 4a. Second Delete fails, rollback CreateItem succeeds -> exit 8, restores login, keeps acc-s1
    let del_rb = bus_cmd()
        .args([
            "--backend",
            "keyring",
            "--json",
            "accounts",
            "delete",
            "acc-s1",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(del_rb.status.code(), Some(8));
    assert!(!env.paths().switch_journal_file().exists());
    assert!(env.paths().account_file("acc-s1").exists());
    assert!(!env.home.join(".gemini").exists());
    let st_del_rb = ss.stats();
    assert_eq!(st_del_rb["login"].as_array().unwrap().len(), 1);
    assert_eq!(st_del_rb["default"].as_array().unwrap().len(), 1);

    // 4b. Second Delete fails AND rollback fails -> exit 7, preserves journal, subsequent write completes delete
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
        "fail_delete_from_call": 2,
        "fail_create_from_call": 1,
    }));
    let del_partial = bus_cmd()
        .args([
            "--backend",
            "keyring",
            "--json",
            "accounts",
            "delete",
            "acc-s1",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(del_partial.status.code(), Some(7));
    assert!(env.paths().switch_journal_file().exists());
    assert!(!env.home.join(".gemini").exists());

    ss.set_ctrl(serde_json::json!({
        "reseed": false,
        "fail_delete_from_call": -1,
        "fail_create_from_call": -1,
    }));
    let fix_del = bus_cmd()
        .args([
            "--backend",
            "keyring",
            "--json",
            "accounts",
            "enable",
            "acc-s2",
        ])
        .output()
        .unwrap();
    assert_eq!(fix_del.status.code(), Some(0));
    assert!(!env.paths().switch_journal_file().exists());
    assert!(!env.paths().account_file("acc-s1").exists());
    assert!(!env.home.join(".gemini").exists());
    let st_del_done = ss.stats();
    assert_eq!(st_del_done["login"].as_array().unwrap().len(), 0);
    assert_eq!(st_del_done["default"].as_array().unwrap().len(), 0);

    // 4c. R3-01: Corrupt `switch_journal.json` MUST NEVER be auto-cleared under `file` or `dual`
    let acc_s1_re = make_rich_sample_account("acc-s1", "alice@example.com", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc_s1_re.clone(), false, now))
        .unwrap();
    env.init_agy_slot_dir();
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_2,
        "default": payload_2,
    }));
    fs::write(env.paths().switch_journal_file(), b"{corrupt-journal-json").unwrap();
    for backend_name in ["file", "dual"] {
        let corrupt_j_fix = bus_cmd()
            .args([
                "--backend",
                backend_name,
                "--json",
                "accounts",
                "enable",
                "acc-s2",
            ])
            .output()
            .unwrap();
        assert_eq!(corrupt_j_fix.status.code(), Some(7));
        assert!(env.paths().switch_journal_file().exists());
    }
    fs::remove_file(env.paths().switch_journal_file()).unwrap();

    // 4c-bis. Dual multi-collection `clear_slot_intent` at `CommittedIndexPending` + external disk credential (Case B)
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
    }));
    let dual_del_stage2_fail = bus_cmd()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:index.json:io")
        .args([
            "--backend",
            "dual",
            "--json",
            "accounts",
            "delete",
            "acc-s1",
            "--force",
            "--clear-active-slot",
        ])
        .output()
        .unwrap();
    assert_eq!(dual_del_stage2_fail.status.code(), Some(7));
    assert!(!env.paths().active_slot_file.exists());
    assert!(env.paths().switch_journal_file().exists());
    assert!(env.paths().account_file("acc-s1").exists());

    let ext_acc = make_rich_sample_account("acc-ext-dbus", "external-dbus@example.com", now);
    let ext_payload = serialize_session_payload(&ext_acc.token).unwrap();
    fs::write(&env.paths().active_slot_file, &ext_payload).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let dual_case_b_fix = bus_cmd()
        .args([
            "--backend",
            "dual",
            "--json",
            "accounts",
            "enable",
            "acc-s2",
        ])
        .output()
        .unwrap();
    assert_eq!(
        dual_case_b_fix.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&dual_case_b_fix.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    assert!(!env.paths().account_file("acc-s1").exists());
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        ext_payload
    );
    let st_case_b = ss.stats();
    assert_eq!(st_case_b["login"].as_array().unwrap().len(), 1);
    assert_eq!(st_case_b["default"].as_array().unwrap().len(), 1);

    // 4d. `switch --dry-run` with CommittedIndexPending `clear_slot_intent` passes (exit 0)
    repo.with_write_lock(|tx| tx.upsert_account(acc_s1_re.clone(), false, now))
        .unwrap();
    fs::remove_dir_all(env.home.join(".gemini")).unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": serde_json::Value::Null,
        "default": serde_json::Value::Null,
    }));
    let clear_pending_j = serde_json::json!({
        "schema_version": 1,
        "operation_id": "op-clear-pending",
        "phase": "committed_index_pending",
        "prev_selected_account_id": "acc-s1",
        "target_account_id": "acc-s1",
        "token_rotated": false,
        "started_at": now,
        "updated_at": now,
        "clear_slot_intent": true,
        "replica_state": {
            "backend": "keyring",
            "uses_file": false,
            "keyring": {
                "prev_present": true,
                "prev_digest": bytes_sha256_hex(payload_1.as_bytes()),
                "prev_uniform": true,
                "collections": [
                    {
                        "path": "/org/freedesktop/secrets/collection/login",
                        "prev_present": true,
                        "prev_digest": bytes_sha256_hex(payload_1.as_bytes())
                    },
                    {
                        "path": "/org/freedesktop/secrets/collection/custom_default",
                        "prev_present": true,
                        "prev_digest": bytes_sha256_hex(payload_1.as_bytes())
                    }
                ]
            },
            "file": {"prev_present": false, "prev_uniform": true}
        }
    });
    fs::write(
        env.paths().switch_journal_file(),
        serde_json::to_vec_pretty(&clear_pending_j).unwrap(),
    )
    .unwrap();
    let dry_clear = bus_cmd()
        .args([
            "--backend",
            "keyring",
            "--json",
            "switch",
            "acc-s2",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert_eq!(dry_clear.status.code(), Some(0));
    fs::remove_file(env.paths().switch_journal_file()).unwrap();

    // 5a. Provider crashing (`os._exit(1)`) mid-CreateItem -> preserves journal & exits 7
    ss.set_ctrl(serde_json::json!({
        "reseed": false,
        "exit_provider_on_create": true,
    }));
    let noreply_sw = bus_cmd()
        .args(["--backend", "keyring", "--json", "switch", "acc-s2"])
        .output()
        .unwrap();
    assert_eq!(noreply_sw.status.code(), Some(7));
    assert!(env.paths().switch_journal_file().exists());
    fs::remove_file(env.paths().switch_journal_file()).unwrap();

    // 5b. Respawn provider and test full bus socket drop (`kill -9 dbus-daemon`) mid-CreateItem -> exit 7
    ss.restart_provider(serde_json::json!({
        "reseed": true,
        "login": serde_json::Value::Null,
        "default": serde_json::Value::Null,
        "exit_provider_on_create": false,
    }));
    ss.set_ctrl(serde_json::json!({
        "reseed": false,
        "kill_dbus_on_create_pid": dbus_pid,
    }));
    let drop_sw = bus_cmd()
        .args(["--backend", "keyring", "--json", "switch", "acc-s2"])
        .output()
        .unwrap();
    assert_eq!(drop_sw.status.code(), Some(7));
    assert!(env.paths().switch_journal_file().exists());
}

#[test]
fn dual_backend_single_replica_keyring_drift_never_fabricates_last_switched_out_while_f01_rotation_does(
) {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();

    let mut acc_a = make_rich_sample_account("acc-dual-a", "alice@example.com", now);
    acc_a.token.refresh_token = "1//rt-dual-a-cur".into();
    acc_a.record_superseded_digest(&agy_switch_cli::domain::token::token_digest(
        "1//rt-dual-a-old",
    ));
    let mut acc_b = make_rich_sample_account("acc-dual-b", "bob@example.com", now);
    acc_b.token.refresh_token = "1//rt-dual-b-cur".into();
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    let Some(ss) = PrivateSecretServiceFixture::start(
        &env,
        "dual_drift",
        SecretServiceLayout::LoginAndDefault,
        serde_json::json!({"login_locked": false, "item_locked": false}),
    ) else {
        return;
    };

    let dual_cli = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", ss.bus_addr())
            .args(["--backend", "dual"]);
        c
    };

    // 1. Seed `acc-dual-a` cleanly into both replicas via `dual switch`.
    let sw_a = dual_cli()
        .args(["--json", "switch", "acc-dual-a"])
        .output()
        .unwrap();
    assert_eq!(
        sw_a.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sw_a.stderr)
    );
    let a_initial = repo.read_account_unchecked("acc-dual-a").unwrap();
    assert!(a_initial.last_switched_in_at.is_some());
    assert_eq!(a_initial.last_switched_out_at, None);

    // 2. Single-replica external drift on keyring (`keyring = foreign`, `file = stale saved A`):
    //    switching to `acc-dual-b` MUST NOT fabricate `acc-dual-a.last_switched_out_at`!
    let foreign_payload = serde_json::to_string(&serde_json::json!({
        "token": {
            "access_token": "ya29.foreign-kr",
            "token_type": "Bearer",
            "refresh_token": "1//rt-foreign-kr",
            "expiry": "2099-01-01T00:00:00Z"
        },
        "id_token_email": "stranger@example.com"
    }))
    .unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": foreign_payload,
        "default": foreign_payload,
    }));
    let sw_b_drift = dual_cli()
        .args(["--json", "switch", "acc-dual-b"])
        .output()
        .unwrap();
    assert_eq!(
        sw_b_drift.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sw_b_drift.stderr)
    );
    let a_after_drift = repo.read_account_unchecked("acc-dual-a").unwrap();
    let b_after_drift = repo.read_account_unchecked("acc-dual-b").unwrap();
    assert_eq!(
        a_after_drift.last_switched_out_at, None,
        "dual single-replica keyring drift MUST NOT stamp last_switched_out_at on stale file replica"
    );
    assert!(b_after_drift.last_switched_in_at.is_some());
    assert_eq!(b_after_drift.last_switched_out_at, None);

    // 3. Contrast with F-01 single-sided disk rotation: switch cleanly back into `acc-dual-a`,
    //    then place `acc-dual-a`'s SUPERSEDED RT in keyring while disk file holds its newly
    //    ROTATED RT. Switching to `acc-dual-b` MUST sync back the rotated RT AND stamp
    //    `acc-dual-a.last_switched_out_at = Some(...)`!
    let sw_a2 = dual_cli()
        .args(["--json", "switch", "acc-dual-a"])
        .output()
        .unwrap();
    assert_eq!(sw_a2.status.code(), Some(0));

    let old_kr_payload = serde_json::to_string(&serde_json::json!({
        "token": {
            "access_token": "ya29.dual-a-old",
            "token_type": "Bearer",
            "refresh_token": "1//rt-dual-a-old",
            "expiry": "2099-01-01T00:00:00Z"
        },
        "id_token_email": "alice@example.com"
    }))
    .unwrap();
    let rot_file_payload = serde_json::to_string(&serde_json::json!({
        "token": {
            "access_token": "ya29.dual-a-rot",
            "token_type": "Bearer",
            "refresh_token": "1//rt-dual-a-rot",
            "expiry": "2099-01-02T00:00:00Z"
        },
        "id_token_email": "alice@example.com"
    }))
    .unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": old_kr_payload,
        "default": old_kr_payload,
    }));
    fs::write(&env.paths().active_slot_file, &rot_file_payload).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let sw_b_f01 = dual_cli()
        .args(["--json", "switch", "acc-dual-b"])
        .output()
        .unwrap();
    assert_eq!(
        sw_b_f01.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sw_b_f01.stderr)
    );
    let a_after_f01 = repo.read_account_unchecked("acc-dual-a").unwrap();
    assert_eq!(a_after_f01.token.refresh_token, "1//rt-dual-a-rot");
    assert!(
        a_after_f01.last_switched_out_at.is_some(),
        "F-01 superseded keyring + rotated file MUST stamp last_switched_out_at on acc-dual-a"
    );

    // 4. Switching back into `acc-dual-a` clears its stale `last_switched_out_at`!
    let sw_a3 = dual_cli()
        .args(["--json", "switch", "acc-dual-a"])
        .output()
        .unwrap();
    assert_eq!(sw_a3.status.code(), Some(0));
    let a_re_in = repo.read_account_unchecked("acc-dual-a").unwrap();
    assert_eq!(a_re_in.last_switched_out_at, None);
    assert!(a_re_in.last_switched_in_at.is_some());

    // 5. Diverged `dual` replicas across two saved accounts (`selected = acc-dual-a`, `file = stale acc-dual-a`,
    //    `keyring = saved acc-dual-b` with a fresher `access_token`): switching to `acc-dual-a` MUST
    //    sync back `acc-dual-b`'s fresher `access_token` from keyring AND stamp `acc-dual-b.last_switched_out_at`
    //    without fabricating `acc-dual-a.last_switched_out_at`!
    let b_fresh_kr_payload = serde_json::to_string(&serde_json::json!({
        "token": {
            "access_token": "ya29.dual-b-fresh-kr",
            "token_type": "Bearer",
            "refresh_token": "1//rt-dual-b-cur",
            "expiry": "2099-06-01T00:00:00Z"
        },
        "id_token_email": "bob@example.com"
    }))
    .unwrap();
    ss.set_ctrl(serde_json::json!({
        "reseed": true,
        "login": b_fresh_kr_payload,
        "default": b_fresh_kr_payload,
    }));

    let sw_a4 = dual_cli()
        .args(["--json", "switch", "acc-dual-a"])
        .output()
        .unwrap();
    assert_eq!(
        sw_a4.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sw_a4.stderr)
    );
    let b_after_div = repo.read_account_unchecked("acc-dual-b").unwrap();
    let a_after_div = repo.read_account_unchecked("acc-dual-a").unwrap();
    assert_eq!(
        b_after_div.token.access_token, "ya29.dual-b-fresh-kr",
        "diverged dual pre-switch sync-back MUST preserve effective keyring account's fresher AT"
    );
    assert!(
        b_after_div.last_switched_out_at.is_some(),
        "diverged dual switch-out MUST stamp last_switched_out_at on effective keyring owner acc-dual-b"
    );
    assert_eq!(a_after_div.last_switched_out_at, None);
    assert!(a_after_div.last_switched_in_at.is_some());
}
