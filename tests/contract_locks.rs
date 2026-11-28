mod common;

use agy_switch_cli::domain::account::StoreIndex;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend};
use agy_switch_cli::session::payload::serialize_session_payload;
use agy_switch_cli::store::locks::ActiveSlotLock;
use agy_switch_cli::store::repository::StoreRepository;
use common::{make_rich_sample_account as sample_account, IsolatedEnv};
#[cfg(feature = "tui")]
use common::{write_fake_agy_script, PtyChild};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

#[test]
fn cross_process_different_data_dir_same_home_slot_lock_returns_exit_5_and_keeps_slot_clean() {
    let env = IsolatedEnv::new();
    let slot_dir = env.init_agy_slot_dir();
    let _ = &slot_dir;
    let now = jiff::Timestamp::now().as_second();

    // Populate Store A and Store B in completely separate directories
    let store_a_dir = env._tmp.path().join("store-a");
    let store_b_dir = env._tmp.path().join("store-b");
    let paths_a = HeadlessPaths::with_explicit(
        env.home.clone(),
        store_a_dir.clone(),
        env.cache_dir.join("agy-switch-cli"),
    );
    let paths_b = HeadlessPaths::with_explicit(
        env.home.clone(),
        store_b_dir.clone(),
        env.cache_dir.join("agy-switch-cli"),
    );

    let repo_a = StoreRepository::new(paths_a.clone());
    let repo_b = StoreRepository::new(paths_b.clone());

    let acc_a = sample_account("acc-a", "a@example.invalid", now);
    let acc_b = sample_account("acc-b", "b@example.invalid", now);
    repo_a
        .with_write_lock(|tx| tx.upsert_account(acc_a.clone(), true, now))
        .unwrap();
    repo_b
        .with_write_lock(|tx| tx.upsert_account(acc_b.clone(), true, now))
        .unwrap();

    // Write initial active slot for acc_a
    let backend = FileSessionBackend;
    backend
        .write_slot(&paths_a, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // Parent process holds L1 ActiveSlotLock via paths_a
    let held_lock = ActiveSlotLock::try_acquire(&paths_a, false).unwrap();

    // Spawn a real separate OS process targeting `--data-dir store-b` and the SAME `$HOME`!
    let mut cmd = env.cli_cmd_with_data_dir(&store_b_dir);
    let out = cmd.args(["switch", "acc-b", "--json"]).output().unwrap();

    assert_eq!(
        out.status.code(),
        Some(5),
        "Competing process with different --data-dir MUST fail with exit code 5: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err_json: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err_json["schema_version"], 1);
    assert_eq!(err_json["ok"], false);
    assert_eq!(err_json["exit_code"], 5);

    // Active slot file still contains acc-a's credential!
    let slot_content = fs::read_to_string(slot_dir.join("antigravity-oauth-token")).unwrap();
    assert!(slot_content.contains("SECRET_REFRESH_TOKEN_acc-a"));

    // `~/.gemini/antigravity-cli/` contains ONLY `antigravity-oauth-token` (100% pure, zero lock/tmp files!)
    let slot_entries: Vec<String> = fs::read_dir(&slot_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(slot_entries, vec!["antigravity-oauth-token".to_string()]);

    // Release lock -> now child process targeting store-b succeeds cleanly!
    let lock_file_path = held_lock.path().to_path_buf();
    drop(held_lock);
    assert!(
        lock_file_path.exists(),
        "Lock file must NEVER be unlinked on release"
    );

    let out_after = env
        .cli_cmd_with_data_dir(&store_b_dir)
        .args(["switch", "acc-b", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        out_after.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out_after.stderr)
    );
    let slot_after = fs::read_to_string(slot_dir.join("antigravity-oauth-token")).unwrap();
    assert!(slot_after.contains("SECRET_REFRESH_TOKEN_acc-b"));
    let slot_entries_after: Vec<String> = fs::read_dir(&slot_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        slot_entries_after,
        vec!["antigravity-oauth-token".to_string()]
    );
}

#[test]
fn readonly_commands_have_zero_filesystem_side_effects_and_zero_secret_or_ansi_leaks() {
    let env = IsolatedEnv::new();

    // Part 1: Completely non-existent directories -> zero directories or files created!
    let absent_data = env._tmp.path().join("absent_data");
    let absent_cache = env._tmp.path().join("absent_cache");
    for args in [
        vec!["accounts", "list", "--json"],
        vec!["current", "--json"],
        vec!["quota", "--all", "--json"],
        vec!["auth", "clients", "--json"],
        vec!["status", "--json"],
    ] {
        let out = env
            .cli_cmd_with_data_dir(&absent_data)
            .env("XDG_CACHE_HOME", &absent_cache)
            .args(&args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "args={args:?} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !absent_data.exists(),
            "Read-only command {args:?} created data_dir!"
        );
        assert!(
            !absent_cache.exists(),
            "Read-only command {args:?} created cache_dir!"
        );
        assert!(
            !env.home.join(".gemini").exists(),
            "Read-only command {args:?} created .gemini!"
        );
    }

    // Part 2: Populated store with secret sentinels & ANSI control chars -> zero leaks, zero byte changes
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-1", "one@example.invalid", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc1, true, now))
        .unwrap();

    let snapshot_tree = |root: &Path| -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            if let Ok(entries) = fs::read_dir(dir) {
                let mut v: Vec<_> = entries.flatten().collect();
                v.sort_by_key(|e| e.path());
                for e in v {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else if p.is_file() {
                        out.push((p.clone(), fs::read(&p).unwrap()));
                    }
                }
            }
        }
        walk(root, &mut files);
        files
    };

    let before_files = snapshot_tree(&env.data_dir);

    for args in [
        vec!["accounts", "list"],
        vec!["accounts", "list", "--json"],
        vec!["current"],
        vec!["current", "--json"],
        vec!["quota"],
        vec!["quota", "--json"],
        vec!["status"],
        vec!["status", "--json"],
    ] {
        let out = env.cli_cmd().args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "args={args:?} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !combined.contains("SECRET_"),
            "Secret sentinel leaked in {args:?}: {combined}"
        );
        if !args.contains(&"--json") {
            assert!(
                !combined.contains('\x1b'),
                "Raw ANSI escape sequence leaked in human output of {args:?}!"
            );
        }
    }

    let after_files = snapshot_tree(&env.data_dir);
    assert_eq!(before_files, after_files);
}

#[test]
fn secret_input_export_and_legacy_import_guards_work_end_to_end() {
    let env = IsolatedEnv::new();
    let now = jiff::Timestamp::now().as_second();

    // 1. Positional token argument on `accounts add` is strictly rejected (exit code 2)
    //    AND NEVER echoes the secret token in either `--json` OR plain-text stderr —
    //    including interleaved global flags (`accounts --json add <TOKEN>`) and `4/...` OAuth codes!
    for argv in [
        vec!["accounts", "add", "1//positional-secret-token"],
        vec!["accounts", "add", "1//positional-secret-token", "--json"],
        vec!["accounts", "--json", "add", "short-interleaved-secret"],
        vec!["auth", "login", "4/0AanPositionalAuthCodeSecret"],
    ] {
        let out_pos = env.cli_cmd().args(&argv).output().unwrap();
        assert_eq!(out_pos.status.code(), Some(2), "argv={argv:?}");
        let stderr_str = String::from_utf8_lossy(&out_pos.stderr);
        let stdout_str = String::from_utf8_lossy(&out_pos.stdout);
        for sentinel in [
            "positional-secret-token",
            "short-interleaved-secret",
            "0AanPositionalAuthCodeSecret",
        ] {
            assert!(
                !stderr_str.contains(sentinel) && !stdout_str.contains(sentinel),
                "CRITICAL: secret leaked for {argv:?}: stderr={stderr_str} stdout={stdout_str}"
            );
        }
    }

    // 1b. Oversized `--from-stdin` (> 16 KiB) fails cleanly with exit code 2 via bounded reader
    let mut big_child = env
        .cli_cmd()
        .args(["accounts", "add", "--from-stdin", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = big_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&vec![b'Z'; 20 * 1024]);
    let big_out = big_child.wait_with_output().unwrap();
    assert_eq!(big_out.status.code(), Some(2));

    // 2. Pipe without `--from-stdin` refuses interactive secret entry when stdin is not a TTY
    let mut child = env
        .cli_cmd()
        .args(["accounts", "add", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"1//piped-without-flag\n")
        .unwrap();
    let out_notty = child.wait_with_output().unwrap();
    assert_eq!(out_notty.status.code(), Some(2));

    // 3. Legacy desktop directory migration (`--from-legacy`) is 100% read-only on source
    //    and pointing `--data-dir` at legacy directory refuses in-place overwrite!
    let legacy_dir = env._tmp.path().join("legacy_antigravity_tools");
    fs::create_dir_all(legacy_dir.join("accounts")).unwrap();
    let legacy_idx = r#"{"version":"2.0","current_account_id":"leg-1","current_target_ide":"ide","accounts":[{"id":"leg-1","email":"legacy1@example.invalid","created_at":100,"last_used":200},{"id":"leg-bad","email":"bad@example.invalid","created_at":100,"last_used":200}]}"#;
    fs::write(legacy_dir.join("accounts.json"), legacy_idx).unwrap();
    fs::write(
        legacy_dir.join("accounts/leg-1.json"),
        r#"{"id":"leg-1","email":"legacy1@example.invalid","token":{"access_token":"ya29.leg","refresh_token":"1//leg-rt-1","expires_in":3600,"expiry_timestamp":0},"created_at":100,"last_used":200}"#,
    )
    .unwrap();
    fs::write(legacy_dir.join("accounts/leg-bad.json"), b"not-json").unwrap();

    // Pointing --data-dir directly at legacy_dir must fail without writing index.json!
    let overwrite_attempt = env
        .cli_cmd_with_data_dir(&legacy_dir)
        .args(["accounts", "enable", "leg-1"])
        .output()
        .unwrap();
    assert_eq!(overwrite_attempt.status.code(), Some(1));
    assert!(!legacy_dir.join("index.json").exists());

    // `--from-legacy` imports valid account AND independently reports malformed `leg-bad`
    let import_out = env
        .cli_cmd()
        .args([
            "accounts",
            "import",
            "--from-legacy",
            legacy_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(import_out.status.code(), Some(0));
    let imp_json: serde_json::Value = serde_json::from_slice(&import_out.stdout).unwrap();
    assert_eq!(imp_json["report"]["imported_count"], 1);
    assert_eq!(imp_json["report"]["failed_count"], 1);
    assert_eq!(
        fs::read_to_string(legacy_dir.join("accounts.json")).unwrap(),
        legacy_idx
    );

    // 4. `accounts export` requires `--include-secrets` and `--output`, writes 0600, and round-trips
    let export_path = env._tmp.path().join("backup.json");
    let exp_missing_flag = env
        .cli_cmd()
        .args([
            "accounts",
            "export",
            "--output",
            export_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(exp_missing_flag.status.code(), Some(2));
    assert!(!export_path.exists());

    let exp_ok = env
        .cli_cmd()
        .args([
            "accounts",
            "export",
            "--output",
            export_path.to_str().unwrap(),
            "--include-secrets",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(exp_ok.status.code(), Some(0));
    assert_eq!(
        fs::metadata(&export_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Refuses to overwrite existing export file without `--overwrite`
    let exp_no_overwrite = env
        .cli_cmd()
        .args([
            "accounts",
            "export",
            "--output",
            export_path.to_str().unwrap(),
            "--include-secrets",
        ])
        .output()
        .unwrap();
    assert_eq!(exp_no_overwrite.status.code(), Some(2));

    // Overwrites cleanly with `--overwrite` and `--accounts`
    let exp_overwrite = env
        .cli_cmd()
        .args([
            "accounts",
            "export",
            "--output",
            export_path.to_str().unwrap(),
            "--include-secrets",
            "--accounts",
            "legacy1@example.invalid",
            "--overwrite",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(exp_overwrite.status.code(), Some(0));

    let _ = now;
    let _ = StoreIndex::new(0);
}

#[test]
fn real_pty_termios_secret_input_suppresses_echo_and_restores_terminal() {
    use std::os::fd::{AsRawFd, FromRawFd};

    let env = IsolatedEnv::new();

    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");

    let inspect_slave_fd = unsafe { libc::dup(slave_fd) };
    assert!(inspect_slave_fd >= 0);

    let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
    let mut master = unsafe { fs::File::from_raw_fd(master_fd) };
    let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_slave_fd) };

    // Spawn `accounts add` connected to the real PTY slave stdin!
    // Use `--proxy http://127.0.0.1:9` so after reading the secret it immediately fails fast offline without hitting real network.
    let child = env
        .cli_cmd()
        .args(["--proxy", "http://127.0.0.1:9", "accounts", "add"])
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Poll deterministically until child disables ECHO via `tcsetattr` (no blind sleep!)
    let mut echo_cleared = false;
    for _ in 0..80 {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut t) } == 0
            && (t.c_lflag & libc::ECHO) == 0
        {
            echo_cleared = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        echo_cleared,
        "Child did not disable ECHO on PTY before prompt"
    );

    master
        .write_all(b"1//PTY_TOP_SECRET_NEVER_ECHOED\n")
        .unwrap();
    master.flush().unwrap();

    let output = child.wait_with_output().unwrap();

    // Verify normal exit ALSO restored terminal ECHO on the PTY!
    let mut post_termios: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post_termios) },
        0
    );
    assert_ne!(
        post_termios.c_lflag & libc::ECHO,
        0,
        "Terminal ECHO must be restored after normal exit from secret prompt!"
    );

    // Set master non-blocking and drain everything echoed back by the PTY line discipline!
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        let _ = libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    use std::io::Read;
    let mut echoed = Vec::new();
    let mut buf = [0u8; 512];
    while let Ok(n) = master.read(&mut buf) {
        if n == 0 {
            break;
        }
        echoed.extend_from_slice(&buf[..n]);
    }
    let echoed_str = String::from_utf8_lossy(&echoed);
    assert!(
        !echoed_str.contains("PTY_TOP_SECRET_NEVER_ECHOED"),
        "CRITICAL: PTY echoed secret back to terminal: {echoed_str:?}"
    );
    let combined_out = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined_out.contains("PTY_TOP_SECRET_NEVER_ECHOED"),
        "Secret leaked in stdout/stderr: {combined_out}"
    );
}

#[test]
fn real_pty_sigint_during_secret_prompt_restores_terminal_echo() {
    use std::os::fd::FromRawFd;

    let env = IsolatedEnv::new();

    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");

    // Duplicate slave_fd so parent can inspect `tcgetattr` after child takes one fd
    let inspect_slave_fd = unsafe { libc::dup(slave_fd) };
    assert!(inspect_slave_fd >= 0);

    let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
    let _master = unsafe { fs::File::from_raw_fd(master_fd) };
    let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_slave_fd) };

    let mut child = env
        .cli_cmd()
        .args(["accounts", "add"])
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Poll until child disables ECHO on the PTY
    use std::os::fd::AsRawFd;
    let mut echo_was_cleared = false;
    for _ in 0..40 {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut t) } == 0
            && (t.c_lflag & libc::ECHO) == 0
        {
            echo_was_cleared = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    assert!(
        echo_was_cleared,
        "Child never cleared ECHO on PTY before SIGINT"
    );

    // Send SIGINT while child is blocked inside `read_line`!
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let _ = child.wait().unwrap();

    // Verify `restore_echo_signal_handler` restored `ECHO` on the PTY!
    let mut post: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post) },
        0
    );
    assert_ne!(
        post.c_lflag & libc::ECHO,
        0,
        "CRITICAL: Terminal ECHO remained disabled after SIGINT!"
    );
}

#[cfg(feature = "tui")]
#[test]
fn real_pty_tui_dashboard_renders_switches_slot_and_exits_cleanly_on_ctrl_c() {
    let env = IsolatedEnv::new();
    let slot_dir = env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();
    let acc1 = sample_account("acc-1", "one@example.invalid", now);
    let acc2 = sample_account("acc-2", "two@example.invalid", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(
            &env.paths(),
            &serialize_session_payload(&acc1.token).unwrap(),
        )
        .unwrap();

    let mut cmd = env.cli_cmd();
    cmd.arg("tui");
    let mut pty = PtyChild::spawn(cmd, 52, 16, false);
    let mut rendered = Vec::new();
    assert!(
        pty.wait_for_text(&mut rendered, "Headless SSH Dashboard", 40)
            .contains("Headless SSH Dashboard"),
        "TUI did not render dashboard frame"
    );

    // Down arrow (`\x1b[B`, move cursor -> acc-2), 's' (switch to acc-2), then Ctrl+C (`\x03`) to quit
    pty.send(b"\x1b[B");
    std::thread::sleep(std::time::Duration::from_millis(50));
    pty.send(b"s");
    std::thread::sleep(std::time::Duration::from_millis(80));
    pty.send(b"\x03");

    let status = pty.child.wait().unwrap();
    pty.drain(&mut rendered);
    assert_eq!(status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&rendered).contains("SECRET_"));
    let slot_after = fs::read_to_string(slot_dir.join("antigravity-oauth-token")).unwrap();
    assert!(slot_after.contains("SECRET_REFRESH_TOKEN_acc-2"));
    assert!(pty.echo_enabled());
}

#[test]
fn synthetic_human_timestamps_session_id_strip_and_pty_tui_batch_shortcuts_work_end_to_end() {
    use agy_switch_cli::cli::dto::{format_rfc3339_local_minute, format_unix_local_minute};
    use agy_switch_cli::domain::account::{PendingAuthFlow, PendingAuthRecord};
    use agy_switch_cli::domain::quota::{QuotaBucket, QuotaGroup};

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());

    let mut acc1 = sample_account("acc-ts-1", "alice@example.invalid", now);
    acc1.last_switched_in_at = Some(now - 900);
    acc1.quota.as_mut().unwrap().quota_groups = Some(vec![
        QuotaGroup {
            display_name: "Gemini Models".into(),
            description: None,
            buckets: vec![
                QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: 1.0,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-11-17T08:30:00Z".into(),
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.75,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-11-23T14:45:00Z".into(),
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
                    remaining_fraction: 0.95,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-11-17T08:30:00Z".into(),
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "3p-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.40,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-11-23T14:45:00Z".into(),
                    display_name: None,
                    description: None,
                },
            ],
        },
    ]);
    let acc2 = sample_account("acc-ts-2", "bob@example.invalid", now);

    let pending_created_at = 1_794_882_360i64;
    let pending_rec = PendingAuthRecord {
        schema_version: 1,
        id: "pend-ts-1".into(),
        flow: PendingAuthFlow::Login,
        token: acc2.token.clone(),
        auth_seq: 2,
        email_mismatch: false,
        input_rt_digest: None,
        custom_label: None,
        created_at: pending_created_at,
    };

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        tx.save_pending_auth(&pending_rec)?;
        Ok(())
    })
    .unwrap();

    let payload_str = serialize_session_payload(&acc1.token).unwrap();
    FileSessionBackend
        .write_slot(&env.paths(), &payload_str)
        .unwrap();

    // Official `agy` slot file keeps exact RFC3339 microsecond UTC string!
    let slot_json: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
    let raw_expiry = slot_json["token"]["expiry"].as_str().unwrap();
    assert!(raw_expiry.ends_with('Z') && raw_expiry.contains('T'));
    let expected_exp_local = format_rfc3339_local_minute(raw_expiry);

    // 1. `current` human vs `--json`: human removes internal ID and shows `YYYY-MM-DD HH:MM`, `--json` keeps both!
    let cur_human = env.cli_cmd().arg("current").output().unwrap();
    assert_eq!(cur_human.status.code(), Some(0));
    let cur_txt = String::from_utf8_lossy(&cur_human.stdout);
    let slot_line = cur_txt
        .lines()
        .find(|l| l.starts_with("Active agy slot"))
        .unwrap();
    assert_eq!(
        slot_line,
        format!("Active agy slot  : matched (alice@example.invalid, expires {expected_exp_local})")
    );
    assert!(!slot_line.contains("acc-ts-1"));
    assert!(!cur_txt.contains("Plan"));

    let cur_json_out = env.cli_cmd().args(["--json", "current"]).output().unwrap();
    let cur_json: serde_json::Value = serde_json::from_slice(&cur_json_out.stdout).unwrap();
    assert_eq!(cur_json["session_identity"]["account_id"], "acc-ts-1");
    assert_eq!(cur_json["session_identity"]["expiry"], raw_expiry);

    // 2. `status` human output reports Backend/Store/Journal/Slot/Antigravity CLI and omits Daemon/Policy/Session/Runtime/Stray.
    let status_human = env.cli_cmd().arg("status").output().unwrap();
    assert_eq!(status_human.status.code(), Some(0));
    let status_txt = String::from_utf8_lossy(&status_human.stdout);
    assert!(status_txt.contains("Backend:"));
    assert!(status_txt.contains("Store status:"));
    assert!(status_txt.contains("Journal status:"));
    assert!(status_txt.contains("Slot initialized:"));
    assert!(status_txt.contains("Antigravity CLI:"));
    assert!(!status_txt.contains("Daemon state:"));
    assert!(!status_txt.contains("Policy status:"));
    assert!(!status_txt.contains("Session identity:"));
    assert!(!status_txt.contains("Runtime state:"));
    assert!(!status_txt.contains("Stray slot files:"));

    // 3. `quota` human output formats `Resets (Local)` with 4-digit year `YYYY-MM-DD HH:MM` while `--json` keeps RFC3339.
    let q_human = env.cli_cmd().arg("quota").output().unwrap();
    assert_eq!(q_human.status.code(), Some(0));
    let q_txt = String::from_utf8_lossy(&q_human.stdout);
    let expected_reset = format_rfc3339_local_minute("2099-11-23T14:45:00Z");
    assert!(q_txt.contains(&expected_reset));
    assert!(!q_txt.contains("Plan"));
    let q_json_out = env.cli_cmd().args(["--json", "quota"]).output().unwrap();
    let q_json: serde_json::Value = serde_json::from_slice(&q_json_out.stdout).unwrap();
    assert_eq!(
        q_json["quota"]["quota_groups"][0]["buckets"][1]["reset_time"],
        "2099-11-23T14:45:00Z"
    );
    assert!(q_json["quota"].get("subscription_tier").is_none());

    // 4. `auth pending` human list formats `created_at=YYYY-MM-DD HH:MM` while `--json` preserves integer `created_at`.
    let pend_human = env.cli_cmd().args(["auth", "pending"]).output().unwrap();
    assert_eq!(pend_human.status.code(), Some(0));
    let pend_txt = String::from_utf8_lossy(&pend_human.stdout);
    let expected_created = format_unix_local_minute(pending_created_at);
    assert!(pend_txt.contains(&format!("created_at={expected_created}")));
    let pend_json_out = env
        .cli_cmd()
        .args(["--json", "auth", "pending"])
        .output()
        .unwrap();
    let pend_json: serde_json::Value = serde_json::from_slice(&pend_json_out.stdout).unwrap();
    assert_eq!(
        pend_json["pending_auth"][0]["created_at"],
        pending_created_at
    );

    // 5. Real PTY TUI v1.3.0 end-to-end verification (`Last Used (dur)`, active/never, no Policy/Plan/Last Quota, T2 `r` + `d`/`e` + `SIGTERM`/`Ctrl+C`)!
    #[cfg(feature = "tui")]
    {
        use std::time::Duration;

        let mut cmd1 = env.cli_cmd();
        cmd1.arg("tui");
        let mut pty1 = PtyChild::spawn(cmd1, 136, 24, true);
        let mut screen = Vec::new();
        let initial_txt = pty1.wait_for_text(&mut screen, "Last Used (dur)", 50);
        assert!(initial_txt.contains("Last Used (dur)"));
        assert!(initial_txt.contains("active (15m)"));
        assert!(initial_txt.contains("never"));
        assert!(initial_txt.contains("Quota ("));
        assert!(initial_txt.contains(&format!(
            "matched (alice@example.invalid, expires {expected_exp_local})"
        )));
        assert!(!initial_txt.contains("Last Quota"));
        assert!(!initial_txt.contains("Policy"));
        assert!(!initial_txt.contains("Plan"));
        assert!(initial_txt.contains("Keys   : ↑/↓ select · g/G top/end · [/] reorder"));
        assert!(initial_txt.contains("Manage : r refresh (on *) · e/E enable · d/D disable"));

        // Down arrow (`\x1b[B`) -> dormant row #2 (`acc-ts-2`): `c`/`C`/`p`/`k` no-ops, `r` shows gentle switch-first hint!
        screen.clear();
        pty1.send(b"\x1b[BcCpk");
        std::thread::sleep(Duration::from_millis(60));
        pty1.send(b"r");
        assert!(pty1
            .wait_for_text(&mut screen, "Switch to this account first", 50)
            .contains("Switch to this account first"));

        pty1.send(b"d");
        for _ in 0..50 {
            if repo
                .read_account_unchecked("acc-ts-2")
                .is_ok_and(|a| a.disabled)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(repo.read_account_unchecked("acc-ts-2").unwrap().disabled);

        pty1.send(b"eq");
        assert_eq!(pty1.child.wait().unwrap().code(), Some(0));
        assert!(!repo.read_account_unchecked("acc-ts-2").unwrap().disabled);
        assert!(pty1.echo_enabled());

        // 6 & 7. Slow synthetic `agy` during 'r' refresh: verify bottom-bar status + clean ECHO restore on BOTH `SIGTERM` and raw-mode `Ctrl+C` (`\x03`)!
        let slow_agy_hit = env._tmp.path().join("slow-tui-agy-hit");
        let slow_agy = write_fake_agy_script(
            env._tmp.path(),
            "slow-tui-agy",
            &format!(
                "#!/bin/sh\necho hit > \"{}\"\nsleep 30\n",
                slow_agy_hit.display()
            ),
        );

        for use_sigterm in [true, false] {
            let _ = fs::remove_file(&slow_agy_hit);
            let mut cmd = env.cli_cmd();
            cmd.env("AGY_SWITCH_CLI_AGY_BIN", &slow_agy).arg("tui");
            let mut pty = PtyChild::spawn(cmd, 136, 24, true);
            let mut buf = Vec::new();
            pty.wait_for_text(&mut buf, "Headless SSH Dashboard", 50);
            buf.clear();
            pty.send(b"r");
            for _ in 0..60 {
                pty.drain(&mut buf);
                if slow_agy_hit.exists()
                    && String::from_utf8_lossy(&buf).contains("Refreshing active quota")
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(String::from_utf8_lossy(&buf).contains("Refreshing active quota"));
            assert!(slow_agy_hit.exists());
            if use_sigterm {
                unsafe {
                    libc::kill(pty.child.id() as i32, libc::SIGTERM);
                }
            } else {
                pty.send(b"\x03");
            }
            assert_eq!(pty.child.wait().unwrap().code(), Some(0));
            assert!(pty.echo_enabled());
        }
    }
}

#[test]
fn synthetic_v120_audit_fixes_relative_home_closed_wal_zero_write_and_unknown_flag_redaction() {
    let env = IsolatedEnv::new();

    // 1. P0-01: Non-empty relative `HOME` MUST be rejected (`exit 8`, `invalid_home`), never accepted via `dirs` fallback!
    let rel_cwd = env._tmp.path().join("cwd_box");
    fs::create_dir_all(&rel_cwd).unwrap();
    let rel_out = env
        .cli_cmd()
        .current_dir(&rel_cwd)
        .env("HOME", "relative_home_subdir")
        .args(["--json", "current"])
        .output()
        .unwrap();
    assert_eq!(rel_out.status.code(), Some(8));
    let rel_err: serde_json::Value = serde_json::from_slice(&rel_out.stderr).unwrap();
    assert_eq!(rel_err["error_code"], "invalid_home");
    assert!(!rel_cwd.join("relative_home_subdir").exists());

    // 2. P1-05: Unknown flag-shaped or placeholder-shaped tokens MUST be unconditionally redacted
    for secret_arg in [
        "--custom-secret-flag-token-xyz",
        "<SECRET_PLACEHOLDER_TOKEN_XYZ>",
        "[SECRET_BRACKET_TOKEN_XYZ]",
    ] {
        let out = env
            .cli_cmd()
            .args(["--json", "current", secret_arg])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        let stderr_str = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr_str.contains("token-xyz") && !stderr_str.contains("TOKEN_XYZ"),
            "Leaked unknown argument token in error: {stderr_str}"
        );
        assert!(stderr_str.contains("[REDACTED]"), "{stderr_str}");
    }

    #[cfg(feature = "stats")]
    {
        let vi = |mut v: u64| -> Vec<u8> {
            let mut b = Vec::new();
            loop {
                let n = (v & 0x7f) as u8;
                v >>= 7;
                b.push(if v == 0 { n } else { n | 0x80 });
                if v == 0 {
                    return b;
                }
            }
        };
        let pb_v = |num: u32, v: u64| -> Vec<u8> { [vi(u64::from(num) << 3), vi(v)].concat() };
        let pb_b = |num: u32, v: &[u8]| -> Vec<u8> {
            [
                vi((u64::from(num) << 3) | 2),
                vi(v.len() as u64),
                v.to_vec(),
            ]
            .concat()
        };
        let ts = "2026-11-15T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let usage = [pb_v(1, 50), pb_v(2, 150), pb_v(3, 40), pb_v(5, 100)].concat();
        let timing = pb_b(4, &pb_v(1, ts));
        let wrapped = [
            pb_b(4, &usage),
            pb_b(9, &timing),
            pb_b(19, b"gemini-4-carbon"),
            pb_b(21, b"Gemini 4 Carbon (High)"),
        ]
        .concat();
        let blob = pb_b(1, &wrapped);

        // 3. P1-01: Closed WAL database (only `closed.db` in `conversations/`) -> subprocess `stats --json`
        //    MUST NOT create `closed.db-wal` or `closed.db-shm`!
        let conv_dir = env.home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&conv_dir).unwrap();
        let closed_db = conv_dir.join("closed.db");
        let wconn = rusqlite::Connection::open(&closed_db).unwrap();
        wconn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        wconn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![blob],
            )
            .unwrap();
        drop(wconn);

        assert!(!conv_dir.join("closed.db-wal").exists());
        assert!(!conv_dir.join("closed.db-shm").exists());
        let db_before = fs::read(&closed_db).unwrap();

        let st_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--date", "2026-11-15"])
            .output()
            .unwrap();
        assert_eq!(st_out.status.code(), Some(0));
        let st_json: serde_json::Value = serde_json::from_slice(&st_out.stdout).unwrap();
        assert_eq!(st_json["databases_scanned"], 1);
        assert_eq!(st_json["summary"]["request_count"], 1);
        assert_eq!(st_json["summary"]["total_output_tokens"], 40);

        let dir_names: Vec<String> = fs::read_dir(&conv_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            dir_names,
            vec!["closed.db".to_string()],
            "stats created unexpected companion files on closed WAL DB: {dir_names:?}"
        );
        assert_eq!(fs::read(&closed_db).unwrap(), db_before);

        // 4. P1-01: Active open WAL database with `-shm` -> `stats --json` MUST NOT mutate `-shm` bytes (`aReadMark[]`)!
        let live_env = IsolatedEnv::new();
        let live_conv = live_env.home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&live_conv).unwrap();
        let live_db = live_conv.join("active.db");
        let live_writer = rusqlite::Connection::open(&live_db).unwrap();
        live_writer
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        live_writer
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![blob],
            )
            .unwrap();

        let shm_path = live_conv.join("active.db-shm");
        let wal_path = live_conv.join("active.db-wal");
        let shm_before = fs::read(&shm_path).unwrap();
        let wal_before = fs::read(&wal_path).unwrap();

        let live_out = live_env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--date", "2026-11-15"])
            .output()
            .unwrap();
        assert_eq!(live_out.status.code(), Some(0));
        let live_json: serde_json::Value = serde_json::from_slice(&live_out.stdout).unwrap();
        assert_eq!(live_json["summary"]["request_count"], 1);
        assert_eq!(
            fs::read(&shm_path).unwrap(),
            shm_before,
            "stats must not mutate -shm read marks during read-only scan"
        );
        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
        drop(live_writer);
    }
}

#[test]
fn synthetic_v120_switch_running_guard_modes() {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-sw1", "alice@example.com", now);
    let acc2 = sample_account("acc-sw2", "bob@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(
            &env.paths(),
            &serialize_session_payload(&acc1.token).unwrap(),
        )
        .unwrap();

    // `switch` default `AllowVerifiedRunning` vs `--require-idle` vs `Unverified`
    let fake_bin = env._tmp.path().join("bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let fake_agy = fake_bin.join("agy");
    fs::write(&fake_agy, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let pid_dir = env.proc_dir.join("636233");
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        "636233 (agy) S 1 636233 636233 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 987654 1000 10",
    )
    .unwrap();
    fs::write(pid_dir.join("comm"), "agy\n").unwrap();
    std::os::unix::fs::symlink(&fake_agy, pid_dir.join("exe")).unwrap();

    let cur_human = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["current"])
        .output()
        .unwrap();
    assert_eq!(cur_human.status.code(), Some(0));
    let cur_stdout = String::from_utf8_lossy(&cur_human.stdout);
    assert!(cur_stdout.contains("Live agy runtime : unmanaged_running (pids=[636233])"));
    assert!(!cur_stdout.contains("identity="));
    assert!(!cur_stdout.contains("managed_accounts=[]"));

    let cur_json_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "current"])
        .output()
        .unwrap();
    assert_eq!(cur_json_out.status.code(), Some(0));
    let cur_j: serde_json::Value = serde_json::from_slice(&cur_json_out.stdout).unwrap();
    assert_eq!(cur_j["runtime_state"]["state"], "unmanaged_running");
    assert!(cur_j["runtime_state"].get("identity").is_none());

    // 1. Conflicting `--allow-running` + `--require-idle` -> exit 2
    let conflict_sw = env
        .cli_cmd()
        .args([
            "--json",
            "switch",
            "acc-sw2",
            "--allow-running",
            "--require-idle",
        ])
        .output()
        .unwrap();
    assert_eq!(conflict_sw.status.code(), Some(2));

    // 2. `--require-idle` while verified `agy` is running -> exit 8 (`active_agy_running`)
    let req_idle_sw = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "switch", "acc-sw2", "--require-idle"])
        .output()
        .unwrap();
    assert_eq!(req_idle_sw.status.code(), Some(8));
    let req_idle_err: serde_json::Value = serde_json::from_slice(&req_idle_sw.stderr).unwrap();
    assert_eq!(req_idle_err["error_code"], "active_agy_running");

    // 3. Default `switch` while verified `agy` is running -> succeeds (`0`) AND emits `runtime_warning`!
    let ok_running_sw = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "switch", "acc-sw2"])
        .output()
        .unwrap();
    assert_eq!(ok_running_sw.status.code(), Some(0));
    let ok_sw_j: serde_json::Value = serde_json::from_slice(&ok_running_sw.stdout).unwrap();
    assert!(ok_sw_j["switch"]["runtime_warning"]
        .as_str()
        .unwrap_or("")
        .contains("636233"));

    // 4. `Unverified` `/proc`: default `switch` fails closed with exit 8 (`runtime_state_unverified`),
    //    while `switch --allow-running` overrides cleanly!
    let missing_proc = env._tmp.path().join("missing-proc-root");
    let unv_sw = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_PROC_ROOT", &missing_proc)
        .args(["--json", "switch", "acc-sw1"])
        .output()
        .unwrap();
    assert_eq!(unv_sw.status.code(), Some(8));
    let unv_err: serde_json::Value = serde_json::from_slice(&unv_sw.stderr).unwrap();
    assert_eq!(unv_err["error_code"], "runtime_state_unverified");

    let force_sw = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_PROC_ROOT", &missing_proc)
        .args(["--json", "switch", "acc-sw1", "--allow-running"])
        .output()
        .unwrap();
    assert_eq!(force_sw.status.code(), Some(0));
}

#[test]
fn synthetic_v120_signoff_round2_exact_backend_literals_tui_json_rollback_and_proxy_redaction() {
    let env = IsolatedEnv::new();
    let now = agy_switch_cli::domain::clock::current_unix_seconds();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-r2a", "alice@example.com", now);
    let acc2 = sample_account("acc-r2b", "bob@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    // 1. F2-01: `--backend`, `AGY_SWITCH_CLI_BACKEND`, and `config.json` `backend` reject `" FILE "`, `""`, and case variants
    for bad in [" FILE ", "", " ", "FILE", "AUTO", "DUAL", "KEYRING"] {
        let cli_res = env
            .cli_cmd()
            .args(["--backend", bad, "--json", "current"])
            .output()
            .unwrap();
        assert_eq!(
            cli_res.status.code(),
            Some(2),
            "CLI --backend {bad:?} must exit 2"
        );

        let env_res = env
            .cli_cmd()
            .env("AGY_SWITCH_CLI_BACKEND", bad)
            .args(["--json", "current"])
            .output()
            .unwrap();
        assert_eq!(
            env_res.status.code(),
            Some(2),
            "ENV AGY_SWITCH_CLI_BACKEND={bad:?} must exit 2"
        );

        fs::create_dir_all(&env.data_dir).unwrap();
        fs::write(
            env.paths().config_file(),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "backend": bad,
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(env.paths().config_file(), fs::Permissions::from_mode(0o600)).unwrap();

        let cfg_res = env.cli_cmd().args(["--json", "current"]).output().unwrap();
        assert_eq!(
            cfg_res.status.code(),
            Some(1),
            "config.json backend={bad:?} must exit 1"
        );
        let cfg_list = env
            .cli_cmd()
            .args(["--json", "accounts", "list"])
            .output()
            .unwrap();
        assert_eq!(
            cfg_list.status.code(),
            Some(1),
            "accounts list with config.json backend={bad:?} must exit 1"
        );
        #[cfg(feature = "stats")]
        {
            for sub in ["summary", "list"] {
                let cfg_stats = env
                    .cli_cmd()
                    .args(["--json", "stats", sub])
                    .output()
                    .unwrap();
                assert_eq!(
                    cfg_stats.status.code(),
                    Some(1),
                    "stats {sub} with config.json backend={bad:?} must exit 1"
                );
                let stats_err = String::from_utf8_lossy(&cfg_stats.stderr);
                assert!(
                    !stats_err.contains(&env.data_dir.to_string_lossy().to_string()),
                    "stats config error must never echo absolute path: {stats_err}"
                );
            }
        }
        let cfg_st = env.cli_cmd().args(["--json", "status"]).output().unwrap();
        assert_eq!(
            cfg_st.status.code(),
            Some(1),
            "status with config.json backend={bad:?} must exit 1"
        );
        let _ = fs::remove_file(env.paths().config_file());
    }

    // 2. F2-03: `--json tui` is rejected consistently across all feature tiers with exit code 2 + JSON envelope
    let tui_json = env.cli_cmd().args(["--json", "tui"]).output().unwrap();
    assert_eq!(tui_json.status.code(), Some(2));
    let tui_err: serde_json::Value = serde_json::from_slice(&tui_json.stderr).unwrap();
    assert_eq!(tui_err["ok"], false);
    assert_eq!(tui_err["exit_code"], 2);

    // 3. F0-02e: Initially absent active slot file (`prev_file == None`) where rollback `remove_slot`
    //    encounters a parent-directory `fsync` failure MUST preserve `switch_journal.json` and exit 7!
    fs::create_dir_all(&env.paths().active_slot_dir).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_dir,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(!env.paths().active_slot_file.exists());

    let sync_fail_sw = env
        .cli_cmd()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_rename:antigravity-oauth-token:enospc;sync_parent_dir:antigravity-oauth-token:io",
        )
        .args(["--backend", "file", "--json", "switch", "acc-r2b"])
        .output()
        .unwrap();
    assert_eq!(
        sync_fail_sw.status.code(),
        Some(7),
        "Parent dir fsync failure during absent-file rollback MUST exit 7: stderr={}",
        String::from_utf8_lossy(&sync_fail_sw.stderr)
    );
    assert!(
        env.paths().switch_journal_file().exists(),
        "Journal must remain on disk when parent dir fsync fails during rollback"
    );

    let fix_sync = env
        .cli_cmd()
        .args([
            "--backend",
            "file",
            "--json",
            "accounts",
            "enable",
            "acc-r2a",
        ])
        .output()
        .unwrap();
    assert_eq!(fix_sync.status.code(), Some(0));
    assert!(!env.paths().switch_journal_file().exists());

    // 4. F0-02d: Legacy `switch_journal.json` WITHOUT `"replica_state"` MUST NOT be auto-cleared or
    //    repaired from `--backend file` (preserves journal and exits 7)!
    let legacy_raw_json = serde_json::json!({
        "schema_version": 1,
        "operation_id": "op-legacy-v111",
        "phase": "prepared",
        "prev_selected_account_id": "acc-r2a",
        "target_account_id": "acc-r2b",
        "prev_slot_digest": agy_switch_cli::session::payload::bytes_sha256_hex(
            fs::read(&env.paths().active_slot_file).unwrap().as_slice()
        ),
        "token_rotated": false,
        "started_at": now,
        "updated_at": now,
    });
    fs::create_dir_all(env.paths().state_dir()).unwrap();
    fs::write(
        env.paths().switch_journal_file(),
        serde_json::to_vec_pretty(&legacy_raw_json).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        env.paths().switch_journal_file(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    for subcmd in [
        vec!["--backend", "file", "--json", "status"],
        vec!["--backend", "file", "--json", "switch", "acc-r2b"],
        vec![
            "--backend",
            "file",
            "--json",
            "accounts",
            "enable",
            "acc-r2a",
        ],
    ] {
        let out = env.cli_cmd().args(&subcmd).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(7),
            "Legacy journal without replica_state must exit 7 under {subcmd:?}: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            env.paths().switch_journal_file().exists(),
            "Legacy journal WAS WRONGLY CLEARED by {subcmd:?}!"
        );
    }
    fs::remove_file(env.paths().switch_journal_file()).unwrap();

    // 5. F2-02: Real PTY `tui` displays variable-name-only warning in status bar when ambient `HTTPS_PROXY` is malformed!
    #[cfg(feature = "tui")]
    {
        let mut tui_cmd = env.cli_cmd();
        tui_cmd
            .env_remove("AGY_SWITCH_CLI_PROXY")
            .env_remove("NO_PROXY")
            .env(
                "HTTPS_PROXY",
                "badscheme://TUI_PROXY_SECRET_777@example.invalid:8080",
            )
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .arg("tui");
        let mut pty = PtyChild::spawn(tui_cmd, 140, 24, false);
        let mut pty_buf = Vec::new();
        pty.wait_for_text(&mut pty_buf, "Headless SSH Dashboard", 40);
        pty.send(b"r");
        for _ in 0..60 {
            pty.drain(&mut pty_buf);
            let txt = String::from_utf8_lossy(&pty_buf);
            if txt.contains("Refresh error:") || txt.contains("Refreshed quota") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        pty.send(b"q");
        assert_eq!(pty.child.wait().unwrap().code(), Some(0));
        pty.drain(&mut pty_buf);
        assert!(!String::from_utf8_lossy(&pty_buf).contains("TUI_PROXY_SECRET_777"));
        // Verify malformed `HTTPS_PROXY` on an OAuth CLI path emits variable-name-only warning without leaking secret!
        let mut add_proxy_child = env
            .cli_cmd()
            .env_remove("AGY_SWITCH_CLI_PROXY")
            .env_remove("NO_PROXY")
            .env(
                "HTTPS_PROXY",
                "badscheme://TUI_PROXY_SECRET_777@example.invalid:8080",
            )
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .args(["accounts", "add", "--from-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        add_proxy_child
            .stdin
            .take()
            .unwrap()
            .write_all(b"1//SYNTHETIC_RT_PROXY_TEST\n")
            .unwrap();
        let add_proxy_out = add_proxy_child.wait_with_output().unwrap();
        let add_proxy_err = String::from_utf8_lossy(&add_proxy_out.stderr);
        assert!(
            add_proxy_err.contains("HTTPS_PROXY"),
            "Expected variable-name-only proxy warning on OAuth path, got: {add_proxy_err}"
        );
        assert!(
            !add_proxy_err.contains("TUI_PROXY_SECRET_777"),
            "Leaked malformed proxy secret in stderr: {add_proxy_err}"
        );
    }
}

#[test]
fn synthetic_v120_status_probe_stats_list_single_slot_refresh_and_tui_reorder_delete() {
    use agy_switch_cli::domain::quota::{PrimaryModelQuota, QuotaBucket, QuotaGroup};

    let env = IsolatedEnv::new();
    let slot_dir = env.init_agy_slot_dir();
    let _ = &slot_dir;
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());

    // Seed 2 accounts:
    // - `acc-starter` (`alice@example.com`): weekly-only bucket WITHOUT a `5h` bucket
    // - `acc-pro` (`bob@example.com`): WITH both `weekly` and `5h` buckets
    let mut acc_starter = sample_account("acc-starter", "alice@example.com", now);
    acc_starter.custom_label = None;
    {
        let qs = acc_starter.quota.as_mut().unwrap();
        qs.forbidden_reason = None;
        qs.models[0].primary_quota = Some(PrimaryModelQuota {
            remaining_fraction: Some(0.75),
            reset_time: "2099-11-23T14:45:00Z".into(),
        });
        qs.models[0].quota_bucket_id = Some("gemini-weekly".into());
        qs.quota_groups = Some(vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: None,
            buckets: vec![QuotaBucket {
                bucket_id: "gemini-weekly".into(),
                window: "weekly".into(),
                remaining_fraction: 0.75,
                remaining_fraction_known: Some(true),
                reset_time: "2099-11-23T14:45:00Z".into(),
                display_name: None,
                description: None,
            }],
        }]);
    }

    let mut acc_pro = sample_account("acc-pro", "bob@example.com", now);
    acc_pro.custom_label = None;
    {
        let qp = acc_pro.quota.as_mut().unwrap();
        qp.forbidden_reason = None;
        qp.models[0].primary_quota = Some(PrimaryModelQuota {
            remaining_fraction: Some(0.85),
            reset_time: "2099-11-23T14:45:00Z".into(),
        });
    }

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_starter.clone(), true, now)?;
        tx.upsert_account(acc_pro.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(
            &env.paths(),
            &serialize_session_payload(&acc_starter.token).unwrap(),
        )
        .unwrap();

    // 1. `status` & `status --json` official `agy` probe matrix (`not found`, `1.5.7`/`1.5.9`/`1.6.0` clean version output without `verified` allowlist, failure exit 8)
    let st_missing = env.cli_cmd().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_missing.status.code(), Some(0));
    let st_missing_j: serde_json::Value = serde_json::from_slice(&st_missing.stdout).unwrap();
    assert_eq!(st_missing_j["agy_probe"]["found"], false);
    assert!(st_missing_j["agy_probe"]
        .get("is_verified_version")
        .is_none());
    assert!(st_missing_j["agy_probe"].get("verified_versions").is_none());
    assert!(st_missing_j.get("session_identity").is_none());
    assert!(st_missing_j.get("runtime_state").is_none());
    assert!(st_missing_j.get("stray_slot_files").is_none());

    let fake_agy = env._tmp.path().join("fake-agy");
    let probe_env_dump = env._tmp.path().join("probe-env.txt");
    for ver in ["1.5.7", "1.5.9", "1.6.0"] {
        fs::write(
            &fake_agy,
            format!(
                "#!/bin/sh\nprintf '%s\\n%s' \"$HOME\" \"$DBUS_SESSION_BUS_ADDRESS\" > \"{}\"\necho \"Antigravity CLI {ver}\"\n",
                probe_env_dump.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();
        let st_v = env
            .cli_cmd()
            .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(st_v.status.code(), Some(0), "ver={ver}");
        let j: serde_json::Value = serde_json::from_slice(&st_v.stdout).unwrap();
        assert_eq!(j["agy_probe"]["found"], true);
        assert_eq!(j["agy_probe"]["version"], ver);
        assert!(j["agy_probe"].get("is_verified_version").is_none());
        assert!(j["agy_probe"].get("verified_versions").is_none());
        let dumped = fs::read_to_string(&probe_env_dump).unwrap();
        let mut lines = dumped.lines();
        let seen_home = lines.next().unwrap_or("");
        let seen_dbus = lines.next().unwrap_or("");
        assert_ne!(
            Path::new(seen_home),
            env.home.as_path(),
            "status agy probe must run in an isolated temp HOME!"
        );
        assert!(
            seen_dbus.starts_with("unix:path=") && seen_dbus.ends_with("/no-dbus"),
            "status agy probe must isolate DBUS_SESSION_BUS_ADDRESS, got: {seen_dbus}"
        );
    }

    let st_human = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(st_human.status.code(), Some(0));
    let st_txt = String::from_utf8_lossy(&st_human.stdout);
    assert!(
        st_txt.contains("Antigravity CLI:")
            && st_txt.contains("v1.6.0")
            && !st_txt.contains("verified"),
        "{st_txt}"
    );

    fs::write(&fake_agy, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();
    let st_fail = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_fail.status.code(), Some(8));

    // Verify accidental credentials passed to `--from-file`, `--from-legacy`, `--output`, and `--data-dir`
    // exit 2 without echoing the secret or creating `./1/...` directories, and `AGY_SWITCH_CLI_STRATEGY=round_robin` is rejected!
    let pasted_tok = "1//0gPastedSecretInPathOption99999";
    for bad_path_args in [
        vec!["--json", "accounts", "import", "--from-file", pasted_tok],
        vec!["--json", "accounts", "import", "--from-legacy", pasted_tok],
        vec![
            "--json",
            "accounts",
            "export",
            "--include-secrets",
            "--output",
            pasted_tok,
        ],
        vec!["--json", "--data-dir", pasted_tok, "accounts", "list"],
    ] {
        let bad_out = env
            .cli_cmd()
            .current_dir(env._tmp.path())
            .args(&bad_path_args)
            .output()
            .unwrap();
        assert_eq!(
            bad_out.status.code(),
            Some(2),
            "Expected exit 2 for {bad_path_args:?}, got {:?} stderr={}",
            bad_out.status.code(),
            String::from_utf8_lossy(&bad_out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&bad_out.stdout),
            String::from_utf8_lossy(&bad_out.stderr)
        );
        assert!(
            !combined.contains("PastedSecretInPathOption99999"),
            "Leaked secret in {bad_path_args:?}: {combined}"
        );
        assert!(
            !env._tmp.path().join("1").exists(),
            "Must never create `./1` directory from `1//...` secret in {bad_path_args:?}"
        );
    }
    // 2. Plan display removed in v1.3.0: `accounts list`, `current`, `quota` omit `Plan`/`subscription_tier`,
    //    AND `quota --json` evaluates weekly-only bucket directly to `known` (75.0%) without tier inference!
    for cmd_args in [
        vec!["accounts", "list"],
        vec!["current"],
        vec!["quota"],
        vec!["--json", "accounts", "list"],
        vec!["--json", "current"],
        vec!["--json", "quota"],
    ] {
        let out = env.cli_cmd().args(&cmd_args).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "cmd={cmd_args:?}");
        let txt = String::from_utf8_lossy(&out.stdout);
        assert!(
            !txt.contains("subscription_tier") && !txt.contains("Plan"),
            "Expected no Plan/subscription_tier in {cmd_args:?}, got:\n{txt}"
        );
    }
    let eval_out = env.cli_cmd().args(["--json", "quota"]).output().unwrap();
    assert_eq!(eval_out.status.code(), Some(0));
    let eval_j: serde_json::Value = serde_json::from_slice(&eval_out.stdout).unwrap();
    assert_eq!(eval_j["evaluation"]["status"], "known");
    assert_eq!(eval_j["evaluation"]["remaining_percentage"], 75.0);

    // 3. `stats summary --recent` + `stats list` (live + archive rows, 99% Hit% cap, zero path/email leaks)
    #[cfg(feature = "stats")]
    {
        use common::stats_fixture::{
            make_gen_blob, open_archive_db, open_live_conv_db, pb_b, pb_v,
        };

        let cli_conv = env.home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cli_conv).unwrap();
        let ts_arch = "2026-11-18T22:14:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let ts_live = "2026-11-19T08:25:28Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        let lconn = open_live_conv_db(&cli_conv.join("live_conv.db"));
        let step_done = pb_b(20, &[pb_b(1, b"done"), pb_v(12, 2)].concat());
        lconn
            .execute(
                "INSERT INTO steps VALUES (1, 15, ?1, 3, ?2)",
                rusqlite::params![pb_b(1, &pb_v(1, ts_live)), &step_done],
            )
            .unwrap();
        lconn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(
                    3_000,
                    584_100,
                    3_432,
                    ts_live,
                    15,
                    44,
                    b"gemini-4-carbon",
                    b"Gemini 4 Carbon (High)",
                )],
            )
            .unwrap();
        drop(lconn);

        let app_dir = env.home.join(".gemini/antigravity");
        fs::create_dir_all(&app_dir).unwrap();
        let aconn = open_archive_db(&app_dir.join("token_usage_archive.db"));
        aconn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/deleted_conv.db', 7, 0, 'Gemini 4 Carbon (High)', '10000', '200', '0', '10200', ?1, 1, 0)",
                rusqlite::params![ts_arch as i64],
            )
            .unwrap();
        drop(aconn);

        let list_human = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["stats", "list"])
            .output()
            .unwrap();
        assert_eq!(list_human.status.code(), Some(0));
        let lh_txt = String::from_utf8_lossy(&list_human.stdout);
        assert!(
            lh_txt.contains("Range  : recent 10 (2026-11-18 22:14 .. 2026-11-19 08:25)"),
            "{lh_txt}"
        );
        assert!(
            lh_txt.contains("Time")
                && lh_txt.contains("Hit%")
                && lh_txt.contains("Dur")
                && lh_txt.contains("St"),
            "{lh_txt}"
        );
        assert!(lh_txt.contains("587.1K  584.1K  99.5%"), "{lh_txt}");
        assert!(lh_txt.contains(" 10.0K       0   0.0%"), "{lh_txt}");
        assert!(lh_txt.contains("  78  ok"), "{lh_txt}");
        assert!(lh_txt.contains("arch"), "{lh_txt}");
        assert!(!lh_txt.contains("t/s"), "{lh_txt}");

        let list_json_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "list", "--recent", "2"])
            .output()
            .unwrap();
        assert_eq!(list_json_out.status.code(), Some(0));
        let lj_str = String::from_utf8_lossy(&list_json_out.stdout);
        assert!(
            !lj_str.contains(&env.home.to_string_lossy().to_string())
                && !lj_str.contains("alice@example.com"),
            "stats list --json must never leak local paths or emails: {lj_str}"
        );
        let lj: serde_json::Value = serde_json::from_slice(&list_json_out.stdout).unwrap();
        assert_eq!(lj["range"]["kind"], "recent");
        assert_eq!(lj["range"]["recent"], 2);
        assert_eq!(lj["items"][0]["cache_hit_percent"], 99.5);
        assert_eq!(lj["items"][1]["cache_hit_percent"], 0.0);
        assert_eq!(lj["items"][0]["status"], "ok");
        assert_eq!(lj["items"][1]["status"], "archived");

        let sum_rec_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--recent", "1"])
            .output()
            .unwrap();
        assert_eq!(sum_rec_out.status.code(), Some(0));
        let sr_j: serde_json::Value = serde_json::from_slice(&sum_rec_out.stdout).unwrap();
        assert_eq!(sr_j["range"]["kind"], "recent");
        assert_eq!(sr_j["summary"]["request_count"], 1);
        assert_eq!(sr_j["summary"]["total_output_tokens"], 3_432);
    }

    // 4. Option 3A single-slot refresh guards: removed batch/non-active refresh flags exit 2!
    {
        let guard_env = IsolatedEnv::new();
        let guard_repo = StoreRepository::new(guard_env.paths());
        let s1 = sample_account("acc-active", "alice@example.com", now);
        let s2 = sample_account("acc-dormant", "bob@example.com", now);
        guard_repo
            .with_write_lock(|tx| {
                tx.upsert_account(s1, true, now)?;
                tx.upsert_account(s2, false, now)
            })
            .unwrap();
        for bad_args in [
            vec!["refresh", "--all"],
            vec!["refresh", "--concurrency", "2"],
            vec!["refresh", "acc-dormant"],
            vec!["quota", "--refresh", "--all"],
            vec!["quota", "acc-active", "--refresh"],
            vec!["quota", "--refresh", "--concurrency", "2"],
        ] {
            let out = guard_env.cli_cmd().args(&bad_args).output().unwrap();
            assert_eq!(
                out.status.code(),
                Some(2),
                "expected exit 2 for {:?}, got {:?}, stderr={}",
                bad_args,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // 5. Real PTY TUI: `Last Used (dur)`, `↑/↓` select, `[/]` reorder, `k/j/K/J` no-op,
    //    `D`/`E` batch disable/enable, `x` + `Esc` cancel, and `x` + `y` active deletion + slot clear!
    #[cfg(feature = "tui")]
    {
        use std::time::Duration;

        let mut tui_cmd = env.cli_cmd();
        tui_cmd.arg("tui");
        let mut pty = PtyChild::spawn(tui_cmd, 120, 20, false);
        let mut screen = Vec::new();
        let init_screen = pty.wait_for_text(&mut screen, "Manage : r refresh (on *)", 50);
        assert!(init_screen.contains("Last Used (dur)"));
        assert!(!init_screen.contains("Plan"));
        assert!(!init_screen.contains("Policy"));
        assert!(init_screen.contains("Keys   : ↑/↓ select · g/G top/end · [/] reorder"));
        assert!(init_screen.contains("e/E enable · d/D disable · l label · o/O export · x delete"));

        screen.clear();
        pty.send(b"D");
        assert!(pty
            .wait_for_text(&mut screen, "Disable all 2 account(s)?", 40)
            .contains("Disable all 2 account(s)?"));

        screen.clear();
        pty.send(b"\x1b");
        pty.wait_for_text(&mut screen, "Canceled disabling all accounts.", 40);
        assert!(repo
            .read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .all(|a| !a.disabled));

        pty.send(b"Dy");
        for _ in 0..50 {
            if repo
                .read_snapshot()
                .is_ok_and(|s| s.accounts.iter().all(|a| a.disabled))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(repo
            .read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .all(|a| a.disabled));

        pty.send(b"E");
        for _ in 0..50 {
            if repo
                .read_snapshot()
                .is_ok_and(|s| s.accounts.iter().all(|a| !a.disabled))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(repo
            .read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .all(|a| !a.disabled));

        // Verify removed `j`/`k`/`J`/`K` + modifier sequences (`Alt+d`) do NOT mutate; `]` moves `acc-starter` down
        pty.send(b"\x1bd");
        std::thread::sleep(Duration::from_millis(60));
        pty.send(b"Jk]");
        for _ in 0..50 {
            if repo.read_snapshot().is_ok_and(|s| {
                s.index.account_order == vec!["acc-pro".to_string(), "acc-starter".to_string()]
            }) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            repo.read_snapshot().unwrap().index.account_order,
            vec!["acc-pro".to_string(), "acc-starter".to_string()]
        );

        screen.clear();
        pty.send(b"x");
        assert!(pty
            .wait_for_text(&mut screen, "clear active agy slot", 40)
            .contains("clear active agy slot"));

        screen.clear();
        pty.send(b"\x1b");
        assert!(pty
            .wait_for_text(&mut screen, "Canceled account deletion.", 40)
            .contains("Canceled account deletion."));
        assert!(repo.paths().account_file("acc-starter").exists());
        assert!(slot_dir.join("antigravity-oauth-token").exists());
        assert!(
            !repo.read_account_unchecked("acc-starter").unwrap().disabled,
            "Canceling deletion via Esc must leave account enabled"
        );

        pty.send(b"xy");
        for _ in 0..50 {
            if !repo.paths().account_file("acc-starter").exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!repo.paths().account_file("acc-starter").exists());
        assert!(!slot_dir.join("antigravity-oauth-token").exists());
        let snap_after_del = repo.read_snapshot().unwrap();
        assert_eq!(snap_after_del.index.selected_account_id, None);
        assert_eq!(snap_after_del.accounts.len(), 1);
        assert_eq!(snap_after_del.accounts[0].id, "acc-pro");

        pty.send(b"q");
        assert_eq!(pty.child.wait().unwrap().code(), Some(0));
        assert!(pty.echo_enabled());
    }
}

#[test]
fn synthetic_v120_round3_status_pgid_path_secret_order_and_tui_ctrl_d() {
    let env = IsolatedEnv::new();
    let _slot_dir = env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-r3a", "alice@example.com", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc1.clone(), true, now))
        .unwrap();

    // 1. R3-12: Legitimate new extensionless single-segment filename >= 28 chars MUST be accepted as `--output` (`0`),
    //    while literal credentials on `--from-file` / `--from-legacy` MUST fail with exit 2 BEFORE touching a pending journal!
    let long_out_name = "my-accounts-export-backup-2026-11-19";
    assert!(long_out_name.len() >= 28);
    let work_dir = env._tmp.path().join("export_cwd");
    fs::create_dir_all(&work_dir).unwrap();
    let exp_ok = env
        .cli_cmd()
        .current_dir(&work_dir)
        .args([
            "--json",
            "accounts",
            "export",
            "--output",
            long_out_name,
            "--include-secrets",
        ])
        .output()
        .unwrap();
    assert_eq!(
        exp_ok.status.code(),
        Some(0),
        "Legitimate >=28-char extensionless filename must succeed: stderr={}",
        String::from_utf8_lossy(&exp_ok.stderr)
    );
    assert!(work_dir.join(long_out_name).is_file());

    // Place a pending journal on disk and pass an accidental token to `accounts add --from-file` and
    // `accounts import --from-file`: both MUST reject with exit 2 without echo and leave journal untouched!
    fs::create_dir_all(env.paths().state_dir()).unwrap();
    let sentinel_j = env.paths().switch_journal_file();
    fs::write(&sentinel_j, b"{truncated-pending-journal").unwrap();
    for bad_args in [
        vec![
            "--json",
            "accounts",
            "add",
            "--from-file",
            "1//0gSyntheticSecretTokenShouldNeverEcho",
        ],
        vec![
            "--json",
            "accounts",
            "import",
            "--from-file",
            "1//0gSyntheticSecretTokenShouldNeverEcho",
        ],
        vec![
            "--json",
            "accounts",
            "import",
            "--from-legacy",
            "1//0gSyntheticSecretTokenShouldNeverEcho",
        ],
    ] {
        let out = env.cli_cmd().args(&bad_args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "Expected exit 2 before journal reconcile for {bad_args:?}, stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("SyntheticSecretTokenShouldNeverEcho"));
        assert!(
            sentinel_j.exists(),
            "Path validation must run BEFORE journal reconciliation!"
        );
    }
    fs::remove_file(&sentinel_j).unwrap();

    // 2. R3-10: `status --json` timeout on a hanging mock `agy --version` that spawns a background
    //    helper MUST terminate the entire child process group (both direct child and helper dead!).
    let helper_pid_file = env._tmp.path().join("agy_helper.pid");
    let hang_agy = env._tmp.path().join("hang-agy");
    fs::write(
        &hang_agy,
        format!(
            "#!/bin/sh\nsleep 30 &\necho $! > \"{}\"\nwait\n",
            helper_pid_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hang_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let st_timeout = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &hang_agy)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_timeout.status.code(), Some(8));
    let helper_pid: i32 = fs::read_to_string(&helper_pid_file)
        .expect("helper should have recorded its PID before 3s timeout")
        .trim()
        .parse()
        .unwrap();
    // Wait briefly for kernel reap after SIGKILL(-pgid)
    let mut alive = true;
    for _ in 0..40 {
        let rc = unsafe { libc::kill(helper_pid, 0) };
        if rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            alive = false;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if alive {
        unsafe {
            let _ = libc::kill(helper_pid, libc::SIGKILL);
        }
    }
    assert!(
        !alive,
        "Derived background helper PID {helper_pid} survived `status` probe timeout!"
    );

    // 3. R3-13: Real PTY test verifying `Ctrl+D` (`\x04`) cancels inline `x` (delete) and `D`
    //    (disable all) confirmations WITHOUT exiting the TUI, then exits cleanly when no
    //    confirmation is active!
    #[cfg(feature = "tui")]
    {
        use std::time::Duration;

        let acc2 = sample_account("acc-r3b", "bob@example.com", now);
        repo.with_write_lock(|tx| tx.upsert_account(acc2.clone(), false, now))
            .unwrap();

        let mut tui_cmd = env.cli_cmd();
        tui_cmd.arg("tui");
        let mut pty = PtyChild::spawn(tui_cmd, 100, 20, false);
        let mut screen = Vec::new();
        assert!(pty
            .wait_for_text(&mut screen, "alice@example.com", 80)
            .contains("alice@example.com"));

        // `x` + `Ctrl+D` cancels delete and keeps TUI alive
        screen.clear();
        pty.send(b"x");
        assert!(pty
            .wait_for_text(&mut screen, "Delete ", 40)
            .contains("Delete "));
        screen.clear();
        pty.send(b"\x04");
        assert!(pty
            .wait_for_text(&mut screen, "Canceled account deletion.", 40)
            .contains("Canceled account deletion."));
        assert!(pty.child.try_wait().unwrap().is_none());
        assert!(env.paths().account_file("acc-r3a").exists());

        // `D` + `Ctrl+D` cancels disable-all and keeps TUI alive
        screen.clear();
        pty.send(b"D");
        assert!(pty
            .wait_for_text(&mut screen, "Disable all", 40)
            .contains("Disable all"));
        screen.clear();
        pty.send(b"\x04");
        assert!(pty
            .wait_for_text(&mut screen, "Canceled disabling all accounts.", 40)
            .contains("Canceled disabling all accounts."));
        assert!(pty.child.try_wait().unwrap().is_none());
        assert!(repo
            .read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .all(|a| !a.disabled));

        // `Ctrl+D` with no active confirmation exits cleanly with ECHO restored
        pty.send(b"\x04");
        let exit_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            pty.drain(&mut screen);
            if let Some(st) = pty.child.try_wait().unwrap() {
                break st;
            }
            assert!(std::time::Instant::now() < exit_deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(0));
        assert!(pty.echo_enabled());
    }
}

#[cfg(feature = "tui")]
#[test]
fn synthetic_v124_tui_pty_mark_export_label_and_detail_m2() {
    use agy_switch_cli::domain::account::TransferBundle;
    use std::time::Duration;

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = env.repo();
    let now = jiff::Timestamp::now().as_second();

    let mut acc1 = sample_account("acc-a", "alice@example.com", now);
    acc1.custom_label = Some("Main".into());
    acc1.last_switched_in_at = Some(now - 600);
    let mut acc2 = sample_account("acc-b", "bob@example.com", now);
    acc2.custom_label = None;
    let mut acc3 = sample_account("acc-c", "charlie@example.com", now - 1200);
    acc3.custom_label = Some("Backup".into());
    acc3.last_switched_in_at = Some(now - 2400);
    acc3.last_switched_out_at = Some(now - 600);

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        tx.upsert_account(acc3.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc1.token).unwrap())
        .unwrap();

    let mut tui_cmd = env.cli_cmd();
    tui_cmd.args(["--backend", "file", "tui"]);
    let mut pty = PtyChild::spawn(tui_cmd, 120, 24, false);
    let mut screen = Vec::new();
    let init = pty.wait_for_text(&mut screen, "Manage : r refresh (on *)", 60);
    assert!(init.contains("alice@example.com (Main)"));
    assert!(
        init.contains("Last Used (dur)")
            && init.contains("active (10m)")
            && init.contains("10m ago (30m)")
    );
    assert!(!init.contains("cooldown") && !init.contains("Policy") && !init.contains("Plan"));

    // 1. Mark row #1 (`alice`) and row #3 (`charlie`) via Space + Down + Down + Space.
    screen.clear();
    pty.send(b" \x1b[B\x1b[B ");
    assert!(pty
        .wait_for_text(
            &mut screen,
            "Marked (2): alice@example.com, charlie@example.com",
            50
        )
        .contains("Marked (2): alice@example.com, charlie@example.com  [Esc to clear]"));

    // 2. Press `o` -> clear default path (`Ctrl+U`) -> type `~/tui-export.json` -> Enter -> `y`.
    screen.clear();
    pty.send(b"o\x15~/tui-export.json\r");
    assert!(pty
        .wait_for_text(&mut screen, "PLAINTEXT tokens [y/N]", 50)
        .contains("PLAINTEXT tokens [y/N]"));
    let exported_path = env.home.join("tui-export.json");
    assert!(!exported_path.exists());

    screen.clear();
    pty.send(b"y");
    for _ in 0..60 {
        pty.drain(&mut screen);
        if exported_path.exists() && String::from_utf8_lossy(&screen).contains("2 marked") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(exported_path.exists());
    assert_eq!(
        fs::metadata(&exported_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bundle: TransferBundle =
        serde_json::from_slice(&fs::read(&exported_path).unwrap()).unwrap();
    let exported_emails: Vec<&str> = bundle.accounts.iter().map(|a| a.email.as_str()).collect();
    assert_eq!(
        exported_emails,
        vec!["alice@example.com", "charlie@example.com"]
    );
    assert!(String::from_utf8_lossy(&screen).contains("2 marked"));

    // 2b. P1-01 real PTY regression: pasting a synthetic credential into export path masks immediately as `[REDACTED]`
    let sentinel_secret = "1//0gSyntheticPtyExportSentinel98765";
    screen.clear();
    pty.send(b"o");
    pty.wait_for_text(&mut screen, "Export 2 marked path:", 50);
    screen.clear();
    pty.send(format!("\x15{sentinel_secret}").as_bytes());
    let masked_edit = pty.wait_for_text(&mut screen, "[REDACTED]", 50);
    assert!(masked_edit.contains("[REDACTED]"));
    assert!(!masked_edit.contains("SyntheticPtyExportSentinel"));
    screen.clear();
    pty.send(b"\r");
    let rejected_screen = pty.wait_for_text(&mut screen, "redacted", 50);
    assert!(rejected_screen.contains("redacted"));
    assert!(!rejected_screen.contains("PLAINTEXT"));
    assert!(!rejected_screen.contains("SyntheticPtyExportSentinel"));

    // 3. Press `l` on row #3 (`charlie`) -> `Ctrl+U` -> type `NewTag` -> Enter -> persists
    screen.clear();
    pty.send(b"l\x15NewTag\r");
    for _ in 0..50 {
        pty.drain(&mut screen);
        if repo
            .read_account_unchecked("acc-c")
            .is_ok_and(|a| a.custom_label.as_deref() == Some("NewTag"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        repo.read_account_unchecked("acc-c")
            .unwrap()
            .custom_label
            .as_deref(),
        Some("NewTag")
    );

    // 4. Press `i` -> opens M2 Account Detail card (with used-after-snapshot hint & no Plan) -> `i` -> `Esc` -> `q`
    screen.clear();
    pty.send(b"i");
    let detail_scr = pty.wait_for_text(&mut screen, "Account Detail 3/3", 50);
    assert!(detail_scr.contains("Account Detail 3/3"));
    assert!(detail_scr.contains("charlie@example.com (NewTag)"));
    assert!(detail_scr.contains("used after snapshot"));
    assert!(!detail_scr.contains("Plan"));
    assert!(detail_scr.contains("Quotas  :"));
    assert!(detail_scr.contains("Models ("));

    screen.clear();
    pty.send(b"i\x1b");
    std::thread::sleep(Duration::from_millis(120));
    assert!(pty.child.try_wait().unwrap().is_none());

    pty.send(b"q");
    let mut exit_status = None;
    for _ in 0..60 {
        pty.drain(&mut screen);
        if let Some(st) = pty.child.try_wait().unwrap() {
            exit_status = Some(st);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        exit_status.expect("TUI did not exit after q").code(),
        Some(0)
    );
    assert!(pty.echo_enabled());

    // 5. P2-01 real narrow PTY checks: 30x16 allows export after explicit `y`, 20x16 refuses confirmation
    for (ws_col, ws_row, rel_file, expect_created) in [
        (30u16, 16u16, "narrow-30x16-export.json", true),
        (20u16, 16u16, "tiny-20x16-export.json", false),
    ] {
        let mut c = env.cli_cmd();
        c.args(["--backend", "file", "tui"]);
        let mut npty = PtyChild::spawn(c, ws_col, ws_row, false);
        let mut buf = Vec::new();
        npty.wait_for_text(&mut buf, "Manage :", 60);

        buf.clear();
        let target_file = env.home.join(rel_file);
        npty.send(format!("O\x15~/{rel_file}\r").as_bytes());
        for _ in 0..50 {
            npty.drain(&mut buf);
            let txt = String::from_utf8_lossy(&buf);
            if expect_created && txt.contains("PLAINTEXT") && txt.contains("[y/N]") {
                break;
            }
            if !expect_created && txt.contains("Status: Export") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let after_enter = String::from_utf8_lossy(&buf).into_owned();
        assert!(!target_file.exists());
        if expect_created {
            assert!(after_enter.contains("PLAINTEXT") && after_enter.contains("[y/N]"));
        }

        npty.send(b"y");
        if expect_created {
            for _ in 0..60 {
                npty.drain(&mut buf);
                if target_file.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(target_file.exists());
            assert_eq!(
                fs::metadata(&target_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        } else {
            std::thread::sleep(Duration::from_millis(120));
            npty.drain(&mut buf);
            assert!(!target_file.exists());
        }

        npty.send(b"q");
        let mut exited = None;
        for _ in 0..60 {
            npty.drain(&mut buf);
            if let Some(st) = npty.child.try_wait().unwrap() {
                exited = Some(st);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(exited.expect("narrow PTY did not exit").code(), Some(0));
    }
}

#[test]
fn synthetic_v124_status_app_probe_concurrent_export_and_disable_without_reason() {
    use agy_switch_cli::transport::user_agent::ANTIGRAVITY_APP_DIR_ENV;

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = jiff::Timestamp::now().as_second();
    let acc1 = sample_account("acc-stat-1", "alice@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc1.token).unwrap())
        .unwrap();

    // 4. Desktop Antigravity App detection via pure read-only ASAR parsing (proves binary is NEVER executed!).
    let fake_app_dir = env._tmp.path().join("fake-antigravity-app");
    fs::create_dir_all(fake_app_dir.join("resources")).unwrap();
    let trap_marker = env._tmp.path().join("app-was-executed.marker");
    let fake_app_bin = fake_app_dir.join("antigravity");
    fs::write(
        &fake_app_bin,
        format!("#!/bin/sh\necho executed > \"{}\"\n", trap_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&fake_app_bin, fs::Permissions::from_mode(0o755)).unwrap();
    // Electron runtime `version` file (`44.9.1`) must NOT be mistaken for App version (`2.33.0`)!
    fs::write(fake_app_dir.join("version"), b"44.9.1\n").unwrap();
    let pkg_bytes = br#"{"name":"antigravity","productName":"Antigravity","version":"2.33.0"}"#;
    let hdr_json = serde_json::to_vec(&serde_json::json!({
        "files": {
            "package.json": { "size": pkg_bytes.len(), "offset": "0" }
        }
    }))
    .unwrap();
    let json_len = hdr_json.len() as u32;
    let pad = (4 - (hdr_json.len() % 4)) % 4;
    let inner_size = 4u32 + json_len + (pad as u32);
    let header_size = 4u32 + inner_size;
    let mut asar = Vec::new();
    asar.extend_from_slice(&4u32.to_le_bytes());
    asar.extend_from_slice(&header_size.to_le_bytes());
    asar.extend_from_slice(&inner_size.to_le_bytes());
    asar.extend_from_slice(&json_len.to_le_bytes());
    asar.extend_from_slice(&hdr_json);
    asar.resize(asar.len() + pad, 0);
    asar.extend_from_slice(pkg_bytes);
    fs::write(fake_app_dir.join("resources/app.asar"), &asar).unwrap();

    let st_app = env
        .cli_cmd()
        .env(ANTIGRAVITY_APP_DIR_ENV, &fake_app_dir)
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(st_app.status.code(), Some(0));
    let app_txt = String::from_utf8_lossy(&st_app.stdout);
    assert!(
        app_txt.contains("Antigravity App:") && app_txt.contains("v2.33.0"),
        "expected detected Antigravity App line:\n{app_txt}"
    );
    assert!(
        !trap_marker.exists(),
        "status MUST NOT execute desktop Antigravity binary!"
    );

    let st_app_json = env
        .cli_cmd()
        .env(ANTIGRAVITY_APP_DIR_ENV, &fake_app_dir)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_app_json.status.code(), Some(0));
    let app_j: serde_json::Value = serde_json::from_slice(&st_app_json.stdout).unwrap();
    assert_eq!(app_j["antigravity_app_probe"]["found"], true);
    assert_eq!(app_j["antigravity_app_probe"]["version"], "2.33.0");

    // 4b. P2-03 regression: valid Linux non-UTF-8 install directory must NOT panic (exit 101)
    //     in either human or `--json` mode, and must still never execute desktop binary!
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let mut non_utf8_bytes = env._tmp.path().as_os_str().as_encoded_bytes().to_vec();
        non_utf8_bytes.extend_from_slice(b"/app-\xff\xfe-nonutf8");
        let non_utf8_app_dir = PathBuf::from(OsString::from_vec(non_utf8_bytes));
        fs::create_dir_all(non_utf8_app_dir.join("resources")).unwrap();
        let non_utf8_trap = env._tmp.path().join("nonutf8-app-trap.marker");
        let non_utf8_bin = non_utf8_app_dir.join("antigravity");
        fs::write(
            &non_utf8_bin,
            format!(
                "#!/bin/sh\necho executed > \"{}\"\n",
                non_utf8_trap.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&non_utf8_bin, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(non_utf8_app_dir.join("resources/app.asar"), &asar).unwrap();

        let st_nonutf8_txt = env
            .cli_cmd()
            .env(ANTIGRAVITY_APP_DIR_ENV, &non_utf8_app_dir)
            .arg("status")
            .output()
            .unwrap();
        assert_eq!(
            st_nonutf8_txt.status.code(),
            Some(0),
            "non-UTF-8 desktop app dir failed human status: stderr={}",
            String::from_utf8_lossy(&st_nonutf8_txt.stderr)
        );
        assert!(String::from_utf8_lossy(&st_nonutf8_txt.stdout).contains("v2.33.0"));

        let st_nonutf8_json = env
            .cli_cmd()
            .env(ANTIGRAVITY_APP_DIR_ENV, &non_utf8_app_dir)
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(
            st_nonutf8_json.status.code(),
            Some(0),
            "non-UTF-8 desktop app dir failed JSON status: stderr={}",
            String::from_utf8_lossy(&st_nonutf8_json.stderr)
        );
        let nonutf8_j: serde_json::Value = serde_json::from_slice(&st_nonutf8_json.stdout).unwrap();
        assert_eq!(nonutf8_j["antigravity_app_probe"]["found"], true);
        assert_eq!(nonutf8_j["antigravity_app_probe"]["version"], "2.33.0");
        assert!(
            !non_utf8_trap.exists(),
            "status must never execute non-UTF-8 desktop Antigravity binary"
        );
    }

    // 4c. P1-02 regression: concurrent `export_transfer_bundle_file(..., overwrite = false)` with
    //     distinct account subsets toward the same path permits strictly ONE writer to succeed
    //     and guarantees the loser never modifies committed bytes.
    {
        use agy_switch_cli::domain::account::TransferBundle;
        use agy_switch_cli::store::transfer::export_transfer_bundle_file;
        use std::sync::{Arc, Barrier};

        let acc2 = sample_account("acc-stat-2", "bob@example.com", now);
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc2.clone(), false, now)?;
            Ok(())
        })
        .unwrap();

        for round in 0..12 {
            let target = env
                ._tmp
                .path()
                .join(format!("concurrent-bundle-{round}.json"));
            let barrier = Arc::new(Barrier::new(2));
            let r1 = repo.clone();
            let t1 = target.clone();
            let b1 = Arc::clone(&barrier);
            let h1 = std::thread::spawn(move || {
                b1.wait();
                export_transfer_bundle_file(&r1, &t1, true, false, &["acc-stat-1".to_string()])
            });
            let r2 = repo.clone();
            let t2 = target.clone();
            let b2 = Arc::clone(&barrier);
            let h2 = std::thread::spawn(move || {
                b2.wait();
                export_transfer_bundle_file(&r2, &t2, true, false, &["acc-stat-2".to_string()])
            });

            let res1 = h1.join().unwrap();
            let res2 = h2.join().unwrap();
            let bundle: TransferBundle =
                serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let emails: Vec<&str> = bundle.accounts.iter().map(|a| a.email.as_str()).collect();
            match (res1, res2) {
                (Ok(1), Err(e)) => {
                    assert_eq!(e.error_code, "invalid_usage");
                    assert!(e.message.contains("already exists"));
                    assert_eq!(emails, vec!["alice@example.com"]);
                }
                (Err(e), Ok(1)) => {
                    assert_eq!(e.error_code, "invalid_usage");
                    assert!(e.message.contains("already exists"));
                    assert_eq!(emails, vec!["bob@example.com"]);
                }
                other => panic!("unexpected concurrent export outcome on round {round}: {other:?}"),
            }
        }
    }

    // 5. `accounts disable` works without `--reason`, and removed `--reason` is rejected with exit code 2.
    let dis_bad = env
        .cli_cmd()
        .args(["accounts", "disable", "acc-stat-1", "--reason", "manual"])
        .output()
        .unwrap();
    assert_eq!(
        dis_bad.status.code(),
        Some(2),
        "removed --reason flag must exit 2"
    );
    let dis_ok = env
        .cli_cmd()
        .args(["accounts", "disable", "acc-stat-1"])
        .output()
        .unwrap();
    assert_eq!(dis_ok.status.code(), Some(0));
    assert!(
        repo.read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .find(|a| a.id == "acc-stat-1")
            .unwrap()
            .disabled
    );
}

#[test]
fn synthetic_v127_official_cli_usage_delegation_offline_switch_sync_back_and_from_local() {
    use agy_switch_cli::domain::account::AccountRecord;
    use agy_switch_cli::domain::token::TokenRecord;
    use agy_switch_cli::store::repository::StoreRepository;
    use std::os::unix::fs::PermissionsExt;

    let env = IsolatedEnv::new();
    let paths = env.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = agy_switch_cli::domain::clock::current_unix_seconds();

    fs::create_dir_all(&paths.active_slot_dir).unwrap();
    fs::create_dir_all(&paths.data_dir).unwrap();

    // 1. Legacy `config.json` containing `"targets"` MUST be silently ignored without breaking CLI!
    let legacy_cfg = serde_json::json!({
        "schema_version": 1,
        "targets": {
            "legacy_alias": "~/.legacy-removed/slot"
        }
    });
    fs::write(
        paths.config_file(),
        serde_json::to_vec_pretty(&legacy_cfg).unwrap(),
    )
    .unwrap();
    let st_legacy = env.cli_cmd().args(["--json", "status"]).output().unwrap();
    assert_eq!(
        st_legacy.status.code(),
        Some(0),
        "legacy config with `targets` must be silently ignored: stderr={}",
        String::from_utf8_lossy(&st_legacy.stderr)
    );

    // 2. Pure-offline `accounts add --from-local`: reads compact `id_token_email` + `user_tier`
    //    with zero network even when proxy points to an unreachable port!
    let local_slot_a = serde_json::json!({
        "access_token": "ya29.LOCAL_A_INIT",
        "refresh_token": "1//LOCAL_A_RT_1",
        "token_type": "Bearer",
        "expiry": "2099-01-01T00:00:00Z",
        "id_token_email": "alice@example.com",
        "user_tier": "g1-pro-tier"
    });
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&local_slot_a).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&paths.active_slot_file, fs::Permissions::from_mode(0o600)).unwrap();

    let add_local = env
        .cli_cmd()
        .args([
            "--proxy",
            "http://127.0.0.1:1",
            "--json",
            "accounts",
            "add",
            "--from-local",
        ])
        .output()
        .unwrap();
    assert_eq!(
        add_local.status.code(),
        Some(0),
        "offline --from-local failed: stderr={}",
        String::from_utf8_lossy(&add_local.stderr)
    );
    let add_json: serde_json::Value = serde_json::from_slice(&add_local.stdout).unwrap();
    let acc_a_id = add_json["account"]["id"].as_str().unwrap().to_string();
    assert_eq!(add_json["account"]["email"], "alice@example.com");
    let rec_a = repo.read_account_unchecked(&acc_a_id).unwrap();
    assert!(rec_a.quota.is_none());
    assert!(rec_a.last_switched_in_at.is_some());

    // 3. Create synthetic `agy` executable script to test real subprocess `agy -p "/usage" --output-format json`!
    let fake_agy = env._tmp.path().join("fake-agy");
    let mode_file = env._tmp.path().join("fake-agy-mode");
    let env_dump = env._tmp.path().join("fake-agy-dbus-env");
    let script = format!(
        r#"#!/bin/sh
printf '%s' "$DBUS_SESSION_BUS_ADDRESS" > "{env_dump}"
MODE="$(cat "{mode_file}" 2>/dev/null || echo ok)"
SLOT="{slot_file}"
case "$MODE" in
  ok)
    # Simulate official agy rotating refresh_token + fresher access_token during /usage!
    cat > "$SLOT" <<'EOF_SLOT'
{{"access_token":"ya29.AGY_REFRESHED_A","refresh_token":"1//AGY_ROTATED_A_2","token_type":"Bearer","expiry":"2099-06-01T00:00:00Z","id_token_email":"alice@example.com","user_tier":"g1-ultra-tier"}}
EOF_SLOT
    cat <<'EOF_JSON'
{{"conversation_id":"","status":"SUCCESS","response":"usage ok","duration_seconds":0,"num_turns":0,"usage":{{"input_tokens":0,"output_tokens":0,"thinking_tokens":0,"cache_read_tokens":0,"total_tokens":0}},"command":{{"name":"usage","data":{{"description":"Usage summary","groups":[{{"name":"Gemini Models","description":"Models within this group: gemini-3.1-pro, gemini-3-flash","buckets":[{{"id":"gemini-weekly","name":"Weekly Limit Remaining","window":"weekly","remaining_fraction":0.97,"reset_time":"2099-12-03T07:17:01Z"}},{{"id":"gemini-5h","name":"Five Hour Limit Remaining","window":"5h","remaining_fraction":0.96,"reset_time":"2099-11-27T11:18:26Z"}}]}},{{"name":"Claude and GPT models","description":"Models within this group: claude-sonnet-4-6, gpt-oss-120b","buckets":[{{"id":"3p-weekly","name":"Weekly Limit Remaining","window":"weekly","remaining_fraction":1.0,"reset_time":"1970-01-01T00:00:00Z"}},{{"id":"3p-5h","name":"Five Hour Limit Remaining","window":"5h","remaining_fraction":1.0,"reset_time":"1970-01-01T00:00:00Z"}}]}}]}}}}}}
EOF_JSON
    exit 0
    ;;
  auth_hang)
    echo "Authentication required. Please visit the URL to log in: https://accounts.google.com/o/oauth2/auth?client_id=synthetic" >&2
    sleep 30
    exit 1
    ;;
  validation_blocked)
    echo '{{"status":"ERROR","error":"403 VALIDATION_REQUIRED: account requires verification","command":{{"name":"usage"}}}}'
    exit 1
    ;;
esac
"#,
        env_dump = env_dump.display(),
        mode_file = mode_file.display(),
        slot_file = paths.active_slot_file.display(),
    );
    fs::write(&fake_agy, script).unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&mode_file, "ok").unwrap();

    // 3a. `quota --refresh --json` with explicit `--backend file` and live dummy DBUS_SESSION_BUS_ADDRESS:
    //     must normalize epoch-0 full unused buckets, sync back rotated RT + user_tier, AND mask D-Bus!
    let q_ref = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/tmp/synthetic-desktop-bus",
        )
        .args(["--backend", "file", "--json", "quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(
        q_ref.status.code(),
        Some(0),
        "quota --refresh failed: stderr={}",
        String::from_utf8_lossy(&q_ref.stderr)
    );
    assert_eq!(
        fs::read_to_string(&env_dump).unwrap(),
        "unix:path=/dev/null",
        "explicit --backend file MUST mask DBUS_SESSION_BUS_ADDRESS when invoking agy"
    );
    let q_json: serde_json::Value = serde_json::from_slice(&q_ref.stdout).unwrap();
    assert_eq!(q_json["quota"]["source_env"], "official_cli");
    assert!(q_json["quota"].get("subscription_tier").is_none());
    assert_eq!(
        q_json["quota"]["quota_groups"][1]["buckets"][0]["reset_time"],
        ""
    );
    assert_eq!(
        q_json["quota"]["quota_groups"][0]["description"],
        "Models within this group: gemini-3.1-pro, gemini-3-flash"
    );
    let synced_a = repo.read_account_unchecked(&acc_a_id).unwrap();
    assert_eq!(synced_a.token.refresh_token, "1//AGY_ROTATED_A_2");
    assert_eq!(synced_a.token.access_token, "ya29.AGY_REFRESHED_A");

    // 3b. Early stderr abort on interactive login prompt -> structured exit 6 (`auth_required`) in < 5s!
    fs::write(&mode_file, "auth_hang").unwrap();
    let t0 = std::time::Instant::now();
    let auth_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "refresh"])
        .output()
        .unwrap();
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(5),
        "auth prompt abort should complete promptly without waiting 30s timeout"
    );
    assert_eq!(auth_out.status.code(), Some(6));
    let auth_err: serde_json::Value = serde_json::from_slice(&auth_out.stderr).unwrap();
    assert_eq!(auth_err["error_code"], "official_cli_auth_required");

    // 3c. ValidationBlocked persists `validation_blocked = true` & `is_forbidden = true`,
    //     then clean `/usage` clears `validation_blocked = false`!
    fs::write(&mode_file, "validation_blocked").unwrap();
    let vb_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "refresh"])
        .output()
        .unwrap();
    assert_eq!(vb_out.status.code(), Some(0));
    let vb_json: serde_json::Value = serde_json::from_slice(&vb_out.stdout).unwrap();
    assert_eq!(vb_json["refreshed"][0]["validation_blocked"], true);
    assert!(
        repo.read_account_unchecked(&acc_a_id)
            .unwrap()
            .validation_blocked
    );

    fs::write(&mode_file, "ok").unwrap();
    let cleared_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "refresh"])
        .output()
        .unwrap();
    assert_eq!(cleared_out.status.code(), Some(0));
    assert!(
        !repo
            .read_account_unchecked(&acc_a_id)
            .unwrap()
            .validation_blocked
    );

    // 4. Offline `switch` onto transfer-bundle account (`access_token == ""`, `expiry_timestamp == 1`)
    //    with unreachable proxy + Pre-Switch Sync-Back of fresher slot credentials!
    let mut acc_b = AccountRecord::new(
        "acc-0002".into(),
        "bob@example.com".into(),
        TokenRecord {
            access_token: String::new(), // transfer-bundle empty access_token
            refresh_token: "1//BOB_RT_BARE".into(),
            expires_in: 0,
            expiry_timestamp: 1,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: None,
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    acc_b.custom_label = Some("bak".into());
    repo.with_write_lock(|tx| tx.upsert_account(acc_b.clone(), false, now))
        .unwrap();

    // Official `agy` wrote a rotated token for Alice into the active slot before we switch to Bob
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "access_token": "ya29.ALICE_PRE_SWITCH_FRESH",
            "refresh_token": "1//ALICE_RT_3_SYNCED",
            "token_type": "Bearer",
            "expiry": "2099-09-01T00:00:00Z",
            "id_token_email": "alice@example.com"
        }))
        .unwrap(),
    )
    .unwrap();

    let sw_out = env
        .cli_cmd()
        .args([
            "--proxy",
            "http://127.0.0.1:1",
            "--json",
            "switch",
            "acc-0002",
        ])
        .output()
        .unwrap();
    assert_eq!(
        sw_out.status.code(),
        Some(0),
        "offline switch to bare transfer-bundle account failed: stderr={}",
        String::from_utf8_lossy(&sw_out.stderr)
    );
    let alice_after = repo.read_account_unchecked(&acc_a_id).unwrap();
    assert_eq!(alice_after.token.refresh_token, "1//ALICE_RT_3_SYNCED");
    assert_eq!(
        alice_after.token.access_token,
        "ya29.ALICE_PRE_SWITCH_FRESH"
    );
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//BOB_RT_BARE"));

    // 5. All removed v1.2.6 / batch / remote-version flags strictly exit 2!
    for bad in [
        vec!["--no-remote-version", "status"],
        vec!["switch", "acc-0002", "--target", "t3"],
        vec!["switch", "acc-0002", "--target-dir", "/tmp/x"],
        vec!["current", "--target", "t3"],
        vec!["quota", "--target", "t3"],
        vec!["quota", "--refresh", "--all"],
        vec!["quota", "acc-0002", "--refresh"],
        vec!["refresh", "--all"],
        vec!["refresh", "--concurrency", "2"],
        vec!["refresh", &acc_a_id], // non-active account rejected!
        vec!["accounts", "add", "--from-local", "--target", "t3"],
        vec!["stats", "summary", "--target", "t3"],
        vec!["stats", "list", "--target-dir", "/tmp/x"],
    ] {
        let out = env.cli_cmd().args(&bad).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 for removed flag/combo {:?}, got {:?}, stderr={}",
            bad,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // 6. Adversarial v1.2.7 regressions:
    //    Build a second fake `agy` binary that does NOT overwrite `$SLOT` with an older RT.
    let proxy_dump = env._tmp.path().join("fake-agy-proxy-env");
    let adv_agy = env._tmp.path().join("adv-fake-agy");
    let adv_mode = env._tmp.path().join("adv-fake-agy-mode");
    let adv_script = format!(
        r#"#!/bin/sh
printf '%s' "$HTTPS_PROXY" > "{proxy_dump}"
MODE="$(cat "{adv_mode}" 2>/dev/null || echo ok)"
case "$MODE" in
  ok)
    cat <<'EOF_JSON'
Warning: non-JSON preamble line
{{"status":"SUCCESS","response":"ok","command":{{"name":"usage","data":{{"groups":[{{"name":"Gemini Models","buckets":[{{"id":"gemini-weekly","window":"weekly","remaining_fraction":0.91,"reset_time":"2099-12-03T07:17:01Z"}},{{"id":"gemini-5h","window":"5h","remaining_fraction":0.90,"reset_time":"2099-11-27T11:18:26Z"}}]}}]}}}}}}
EOF_JSON
    exit 0
    ;;
  validation_blocked)
    echo '{{"status":"ERROR","error":"403 VALIDATION_REQUIRED: account requires verification","command":{{"name":"usage"}}}}'
    exit 1
    ;;
  overflow_hang)
    trap '' PIPE
    dd if=/dev/zero bs=4096 count=160 2>/dev/null | tr '\0' 'A'
    sleep 20
    exit 0
    ;;
  stdout_auth_hang)
    echo "Please visit the URL to log in: https://accounts.google.com/o/oauth2/auth?client_id=synth"
    sleep 20
    exit 1
    ;;
esac
"#,
        proxy_dump = proxy_dump.display(),
        adv_mode = adv_mode.display(),
    );
    fs::write(&adv_agy, adv_script).unwrap();
    fs::set_permissions(&adv_agy, fs::Permissions::from_mode(0o755)).unwrap();

    //    6a. `refresh <drifted_active_id>` succeeds when actual slot holds Alice (`acc_a_id`) while
    //        `index.selected_account_id` is Bob (`acc-0002`), AND `refresh acc-0002` exits 2!
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.ALICE_DRIFT_AT",
                "token_type": "Bearer",
                "refresh_token": "1//ALICE_RT_3_SYNCED",
                "expiry": "2099-09-01T00:00:00Z"
            },
            "id_token_email": "alice@example.com",
            "user_tier": "g1-ultra-tier"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&adv_mode, "ok").unwrap();
    let drift_wrong = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["refresh", "acc-0002"])
        .output()
        .unwrap();
    assert_eq!(drift_wrong.status.code(), Some(2));
    let drift_ok = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["refresh", &acc_a_id])
        .output()
        .unwrap();
    assert_eq!(
        drift_ok.status.code(),
        Some(0),
        "refresh on drifted active slot account must succeed: stderr={}",
        String::from_utf8_lossy(&drift_ok.stderr)
    );

    //    6b. Human `refresh` on `VALIDATION_REQUIRED` emits `verify-blocked` note on stderr!
    fs::write(&adv_mode, "validation_blocked").unwrap();
    let vb_human = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["refresh"])
        .output()
        .unwrap();
    assert_eq!(
        vb_human.status.code(),
        Some(0),
        "human refresh validation_blocked failed: stderr={}",
        String::from_utf8_lossy(&vb_human.stderr)
    );
    assert!(
        String::from_utf8_lossy(&vb_human.stderr).contains("verify-blocked"),
        "expected verify-blocked warning on human refresh stderr: {}",
        String::from_utf8_lossy(&vb_human.stderr)
    );

    //    6b-2. `quota --refresh` (both human and `--json`) and cached `quota` on `VALIDATION_REQUIRED`
    //          must exit with code 4, emit clear verify-blocked guidance (not "Cached quota ... Switch to it"),
    //          preserve `--json` `details` contract, and never expose `validation_url`!
    let vb_quota_human = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(vb_quota_human.status.code(), Some(4));
    let vb_quota_stderr = String::from_utf8_lossy(&vb_quota_human.stderr);
    assert!(
        vb_quota_stderr.contains("verify-blocked")
            && vb_quota_stderr.contains("complete Google verification"),
        "quota --refresh on validation_blocked must guide user to verify in agy: {vb_quota_stderr}"
    );
    assert!(
        !vb_quota_stderr.contains("Cached quota")
            && !vb_quota_stderr.contains("Switch to it and run"),
        "quota --refresh on validation_blocked must NOT fall through to cached switch hint: {vb_quota_stderr}"
    );
    assert!(
        !vb_quota_stderr.contains("https://"),
        "quota --refresh must never leak validation_url: {vb_quota_stderr}"
    );

    let vb_quota_json = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--json", "quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(vb_quota_json.status.code(), Some(4));
    assert!(
        vb_quota_json.stdout.is_empty(),
        "failed --json quota --refresh must keep stdout empty"
    );
    let vb_q_err: serde_json::Value = serde_json::from_slice(&vb_quota_json.stderr).unwrap();
    assert_eq!(vb_q_err["ok"], false);
    assert_eq!(vb_q_err["exit_code"], 4);
    assert_eq!(vb_q_err["error_code"], "quota_stale_or_unknown");
    assert!(vb_q_err["message"]
        .as_str()
        .unwrap()
        .contains("verify-blocked"));
    assert_eq!(vb_q_err["details"]["account_id"], acc_a_id);
    assert_eq!(vb_q_err["details"]["email"], "alice@example.com");
    assert_eq!(vb_q_err["details"]["evaluation"]["status"], "unavailable");
    assert_eq!(
        vb_q_err["details"]["evaluation"]["reason"],
        "validation_blocked"
    );
    assert!(vb_q_err["details"]["quota"].is_object());

    // Cached `quota <ID>` (without `--refresh`) on the validation-blocked account also gives
    // accurate verify-blocked guidance and exit code 4 (with backwards-compatible error_code).
    let vb_quota_cached = env
        .cli_cmd()
        .args(["--json", "quota", &acc_a_id])
        .output()
        .unwrap();
    assert_eq!(vb_quota_cached.status.code(), Some(4));
    let vb_cached_err: serde_json::Value = serde_json::from_slice(&vb_quota_cached.stderr).unwrap();
    assert_eq!(vb_cached_err["error_code"], "quota_stale_or_unknown");
    assert_eq!(
        vb_cached_err["details"]["evaluation"]["reason"],
        "validation_blocked"
    );
    assert!(vb_cached_err["message"]
        .as_str()
        .unwrap()
        .contains("verify-blocked"));

    // Account that is BOTH `disabled == true` AND receives `validation_blocked` from `quota --refresh`:
    // MUST preserve `details.evaluation.reason == "account_disabled"` with consistent `error_code`,
    // while ALSO surfacing the `verify-blocked` warning in `message` (and never leaking URLs).
    assert_eq!(
        env.cli_cmd()
            .args(["accounts", "disable", &acc_a_id])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let dis_vb_json = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--json", "quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(dis_vb_json.status.code(), Some(4));
    let dis_vb_err: serde_json::Value = serde_json::from_slice(&dis_vb_json.stderr).unwrap();
    assert_eq!(dis_vb_err["error_code"], "quota_stale_or_unknown");
    assert_eq!(
        dis_vb_err["details"]["evaluation"]["reason"],
        "account_disabled"
    );
    let dis_vb_msg = dis_vb_err["message"].as_str().unwrap();
    assert!(
        dis_vb_msg.contains("account_disabled") && dis_vb_msg.contains("verify-blocked"),
        "disabled + validation_blocked quota --refresh must report both causes: {dis_vb_msg}"
    );
    assert!(
        !dis_vb_msg.contains("https://"),
        "disabled + validation_blocked must never leak URLs: {dis_vb_msg}"
    );
    assert_eq!(
        env.cli_cmd()
            .args(["accounts", "enable", &acc_a_id])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );

    //    6c. Proxy propagation (`--proxy` & `config.json` `network.proxy_url`) into official `agy`
    //        subprocess, plus fast fail on >512 KiB stdout overflow and stdout auth prompt!
    fs::write(&adv_mode, "ok").unwrap();
    let proxy_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--proxy", "http://127.0.0.1:7890", "--json", "refresh"])
        .output()
        .unwrap();
    assert_eq!(
        proxy_out.status.code(),
        Some(0),
        "refresh with --proxy failed: stderr={}",
        String::from_utf8_lossy(&proxy_out.stderr)
    );
    assert_eq!(
        fs::read_to_string(&proxy_dump).unwrap(),
        "http://127.0.0.1:7890"
    );

    // `config.json` `network.proxy_url` ALSO propagates when AGY_SWITCH_CLI_PROXY is unset!
    fs::write(
        paths.config_file(),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "network": { "proxy_url": "http://127.0.0.1:8899" }
        }))
        .unwrap(),
    )
    .unwrap();
    let cfg_proxy_out = env
        .cli_cmd()
        .env_remove("AGY_SWITCH_CLI_PROXY")
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--json", "refresh"])
        .output()
        .unwrap();
    assert_eq!(
        cfg_proxy_out.status.code(),
        Some(0),
        "refresh with config.json proxy failed: stderr={}",
        String::from_utf8_lossy(&cfg_proxy_out.stderr)
    );
    assert_eq!(
        fs::read_to_string(&proxy_dump).unwrap(),
        "http://127.0.0.1:8899"
    );
    let _ = fs::remove_file(paths.config_file());

    // Invalid `--proxy` fails immediately with exit 2!
    let bad_proxy = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--proxy", "ftp://127.0.0.1:21", "refresh"])
        .output()
        .unwrap();
    assert_eq!(bad_proxy.status.code(), Some(2));

    // >512 KiB stdout overflow with SIGPIPE ignored aborts immediately (< 5s, NOT 30s timeout) with exit 1!
    fs::write(&adv_mode, "overflow_hang").unwrap();
    let t_ov = std::time::Instant::now();
    let ov_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--json", "refresh"])
        .output()
        .unwrap();
    assert!(
        t_ov.elapsed() < std::time::Duration::from_secs(5),
        "stdout overflow must abort immediately instead of hanging until timeout: {:?}",
        t_ov.elapsed()
    );
    assert_eq!(ov_out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&ov_out.stderr).contains("512 KiB"));

    // Interactive login prompt on stdout also aborts immediately (< 5s) with exit 6!
    fs::write(&adv_mode, "stdout_auth_hang").unwrap();
    let t_sa = std::time::Instant::now();
    let sa_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--json", "refresh"])
        .output()
        .unwrap();
    assert!(
        t_sa.elapsed() < std::time::Duration::from_secs(5),
        "stdout auth prompt must abort immediately: {:?}",
        t_sa.elapsed()
    );
    assert_eq!(sa_out.status.code(), Some(6));
    let sa_err: serde_json::Value = serde_json::from_slice(&sa_out.stderr).unwrap();
    assert_eq!(sa_err["error_code"], "official_cli_auth_required");

    //    6d. Offline `--from-local` preserves fresher `access_token` when local slot has same RT
    //        with an older expired `access_token`!
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.OLDER_STALE_ACCESS",
                "token_type": "Bearer",
                "refresh_token": "1//ALICE_RT_3_SYNCED",
                "expiry": "2020-01-01T00:00:00Z"
            },
            "id_token_email": "alice@example.com"
        }))
        .unwrap(),
    )
    .unwrap();
    let fl_preserve = env
        .cli_cmd()
        .args(["--json", "accounts", "add", "--from-local"])
        .output()
        .unwrap();
    assert_eq!(
        fl_preserve.status.code(),
        Some(0),
        "offline --from-local preserve failed: stderr={}",
        String::from_utf8_lossy(&fl_preserve.stderr)
    );
    let alice_preserved = repo.read_account_unchecked(&acc_a_id).unwrap();
    assert_ne!(
        alice_preserved.token.access_token, "ya29.OLDER_STALE_ACCESS",
        "offline --from-local must not regress fresher stored access_token to an older slot token"
    );

    //    6e. Pre-Switch Sync-Back persists fresher token written by official `agy` AND updates switch timestamps!
    let _ = env.cli_cmd().args(["switch", "acc-0002"]).output().unwrap();
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.BOB_FRESH_BY_AGY",
                "token_type": "Bearer",
                "refresh_token": "1//BOB_RT_BARE",
                "expiry": "2099-09-01T00:00:00Z"
            },
            "id_token_email": "bob@example.com",
            "user_tier": "g1-pro-tier"
        }))
        .unwrap(),
    )
    .unwrap();
    let sw_back = env.cli_cmd().args(["switch", &acc_a_id]).output().unwrap();
    assert_eq!(sw_back.status.code(), Some(0));
    let bob_synced = repo.read_account_unchecked("acc-0002").unwrap();
    assert_eq!(bob_synced.token.access_token, "ya29.BOB_FRESH_BY_AGY");
    assert!(bob_synced.last_switched_out_at.is_some());

    //    6f. Weekly-only `/usage` buckets (no `5h` bucket) evaluate directly to `Known` (exit 0)
    //        without any `subscription_tier` / `Plan` inference!
    let free_weekly_only_agy = env.home.join("fake-agy-free-weekly.sh");
    fs::write(
        &free_weekly_only_agy,
        r#"#!/bin/sh
cat <<'EOF'
{"conversation_id":"","status":"SUCCESS","response":"ok","duration_seconds":0,"num_turns":0,"usage":{"input_tokens":0,"output_tokens":0,"thinking_tokens":0,"cache_read_tokens":0,"total_tokens":0},"command":{"name":"usage","data":{"description":"Weekly-only summary","groups":[{"name":"Gemini Models","description":"Models within this group: Gemini 3.8 Flash","buckets":[{"id":"gemini-weekly","name":"Weekly Limit Remaining","window":"weekly","remaining_fraction":0.84,"reset_time":"2099-12-03T07:17:01Z"}]}]}}}
EOF
exit 0
"#,
    )
    .unwrap();
    fs::set_permissions(&free_weekly_only_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let slot_file = paths.active_slot_file.clone();
    assert_eq!(
        env.cli_cmd()
            .args(["switch", "acc-0002"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let free_q = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &free_weekly_only_agy)
        .args(["--json", "quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(
        free_q.status.code(),
        Some(0),
        "weekly-only buckets must evaluate Known (exit 0): stderr={}",
        String::from_utf8_lossy(&free_q.stderr)
    );
    let free_q_json: serde_json::Value = serde_json::from_slice(&free_q.stdout).unwrap();
    assert_eq!(free_q_json["evaluation"]["status"], "known");
    assert!(free_q_json["quota"].get("subscription_tier").is_none());

    // 7. S4 compact 1.5+ payload round-trip (`accounts add --from-local` -> `switch` ->
    //    `accounts add --from-local` again, offline, zero network) + S3 AT/expiry pairing +
    //    S6 empty-groups SUCCESS benign stderr isolation:
    //    7a. S4: compact payload with `id_token_email` and NO `id_token` survives `switch`
    //        and remains directly re-importable offline (ignoring legacy `user_tier`)!
    let compact_slot = serde_json::json!({
        "token": {
            "access_token": "ya29.s4_compact",
            "token_type": "Bearer",
            "refresh_token": "1//RT_S4_COMPACT",
            "expiry": "2050-01-01T00:00:00Z"
        },
        "auth_method": "consumer",
        "id_token_email": "compact-rt@example.com",
        "user_tier": "PRO"
    });
    fs::write(&slot_file, serde_json::to_vec(&compact_slot).unwrap()).unwrap();
    let imp1 = env
        .cli_cmd()
        .args(["--json", "accounts", "add", "--from-local"])
        .output()
        .unwrap();
    assert_eq!(
        imp1.status.code(),
        Some(0),
        "S4 initial compact import failed: {}",
        String::from_utf8_lossy(&imp1.stderr)
    );
    let imp1_json: serde_json::Value = serde_json::from_slice(&imp1.stdout).unwrap();
    let s4_id = imp1_json["account"]["id"].as_str().unwrap().to_string();
    assert!(imp1_json["account"]["last_switched_in_at"]
        .as_i64()
        .is_some());

    assert_eq!(
        env.cli_cmd()
            .args(["switch", &s4_id])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let rewritten_slot: serde_json::Value =
        serde_json::from_slice(&fs::read(&slot_file).unwrap()).unwrap();
    assert_eq!(rewritten_slot["id_token_email"], "compact-rt@example.com");
    assert!(rewritten_slot.get("user_tier").is_none());

    let imp2 = env
        .cli_cmd()
        .args(["--json", "accounts", "add", "--from-local"])
        .output()
        .unwrap();
    assert_eq!(
        imp2.status.code(),
        Some(0),
        "S4 second offline --from-local after switch must succeed: {}",
        String::from_utf8_lossy(&imp2.stderr)
    );
    let imp2_json: serde_json::Value = serde_json::from_slice(&imp2.stdout).unwrap();
    assert_eq!(imp2_json["created"], false);
    assert_eq!(imp2_json["account"]["id"], s4_id);

    //    7b. S3 + S5 CLI regression: same RT, fresher stored AT/expiry (`2050000000`), older slot AT
    //        (`1700000000`) + newly added synthetic `id_token` -> `switch` MUST keep fresher stored
    //        AT & expiry AND preserve non-default cached quota `Production` `source_env`/`last_updated`
    //        while merging `id_token`!
    let seeded_quota_ts = 1_700_000_123i64;
    repo.with_write_lock(|tx| {
        let mut r = tx.load_account_opt(&s4_id)?.unwrap();
        r.token.access_token = "ya29.s3_fresher_store".into();
        r.token.expiry_timestamp = 2_050_000_000;
        r.token.id_token = None;
        r.quota = Some(agy_switch_cli::domain::quota::QuotaObservation::new(
            seeded_quota_ts,
            agy_switch_cli::domain::quota::QuotaSourceEnv::Production,
        ));
        tx.save_account(&r)?;
        Ok(())
    })
    .unwrap();
    let s3_jwt_payload = <base64::engine::GeneralPurpose as base64::Engine>::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        br#"{"email":"compact-rt@example.com"}"#,
    );
    let s3_jwt = format!("eyJhbGciOiJub25lIn0.{s3_jwt_payload}.sig");
    fs::write(
        &slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.s3_older_slot",
                "token_type": "Bearer",
                "refresh_token": "1//RT_S4_COMPACT",
                "expiry": "2023-11-14T22:13:20Z"
            },
            "auth_method": "consumer",
            "id_token": s3_jwt,
            "id_token_email": "compact-rt@example.com"
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        env.cli_cmd()
            .args(["switch", "acc-0002"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let s4_after_s3 = repo.read_account_unchecked(&s4_id).unwrap();
    assert_eq!(s4_after_s3.token.access_token, "ya29.s3_fresher_store");
    assert_eq!(s4_after_s3.token.expiry_timestamp, 2_050_000_000);
    assert_eq!(s4_after_s3.token.id_token.as_deref(), Some(s3_jwt.as_str()));
    let s4_q = s4_after_s3.quota.as_ref().unwrap();
    assert_eq!(
        s4_q.source_env,
        agy_switch_cli::domain::quota::QuotaSourceEnv::Production
    );
    assert_eq!(s4_q.last_updated, seeded_quota_ts);

    // Switch back to `s4_id` before step 7d
    assert_eq!(
        env.cli_cmd()
            .args(["switch", &s4_id])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );

    //    7d. S6 CLI regression: structured `SUCCESS` with `groups: []` + benign stderr containing
    //        `validation_url` MUST return `Unknown(unknown_pool)` and keep `validation_blocked=false`!
    let empty_groups_agy = env.home.join("fake-agy-empty-groups-benign-stderr.sh");
    fs::write(
        &empty_groups_agy,
        r#"#!/bin/sh
echo "debug: validation_url check passed" >&2
cat <<'EOF'
{"conversation_id":"","status":"SUCCESS","response":"ok","duration_seconds":0,"num_turns":0,"usage":{"input_tokens":0,"output_tokens":0,"thinking_tokens":0,"cache_read_tokens":0,"total_tokens":0},"command":{"name":"usage","data":{"description":"Empty","groups":[]}}}
EOF
exit 0
"#,
    )
    .unwrap();
    fs::set_permissions(&empty_groups_agy, fs::Permissions::from_mode(0o755)).unwrap();
    let s6_q = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &empty_groups_agy)
        .args(["--json", "quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(s6_q.status.code(), Some(4));
    let s6_json: serde_json::Value = serde_json::from_slice(&s6_q.stderr).unwrap();
    assert_eq!(s6_json["error_code"], "quota_stale_or_unknown");
    assert_eq!(s6_json["details"]["evaluation"]["status"], "unknown");
    assert_eq!(s6_json["details"]["evaluation"]["reason"], "unknown_pool");
    assert!(
        !repo
            .read_account_unchecked(&s4_id)
            .unwrap()
            .validation_blocked
    );

    //    7e. R2-02 CLI regression: rotated RT + non-empty new AT + MISSING `expiry` in active slot
    //        MUST NOT borrow the old AT's future `expiry_timestamp` (`2050000000`) on `switch` out;
    //        both `switch` sync-back and offline `accounts add --from-local` must persist `(1, 0)`!
    let r202_slot_missing_expiry = serde_json::json!({
        "token": {
            "access_token": "ya29.r202_new_at_no_expiry",
            "token_type": "Bearer",
            "refresh_token": "1//RT_R202_ROTATED_1"
        },
        "auth_method": "consumer",
        "id_token_email": "compact-rt@example.com"
    });
    repo.with_write_lock(|tx| {
        let mut r = tx.load_account_opt(&s4_id)?.unwrap();
        r.token.access_token = "ya29.r202_old_at".into();
        r.token.refresh_token = "1//RT_R202_OLD_1".into();
        r.token.expiry_timestamp = 2_050_000_000;
        r.token.expires_in = 3600;
        tx.save_account(&r)?;
        tx.commit_selected_account(&s4_id, 1_900_000_000)?;
        Ok(())
    })
    .unwrap();
    fs::write(
        &slot_file,
        serde_json::to_vec(&r202_slot_missing_expiry).unwrap(),
    )
    .unwrap();
    assert_eq!(
        env.cli_cmd()
            .args(["switch", "acc-0002"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let r202_after_sw = repo.read_account_unchecked(&s4_id).unwrap();
    assert_eq!(r202_after_sw.token.refresh_token, "1//RT_R202_ROTATED_1");
    assert_eq!(
        r202_after_sw.token.access_token,
        "ya29.r202_new_at_no_expiry"
    );
    assert_eq!(r202_after_sw.token.expiry_timestamp, 1);
    assert_eq!(r202_after_sw.token.expires_in, 0);
    assert!(r202_after_sw.has_superseded_refresh_token("1//RT_R202_OLD_1"));

    // Switching back to `s4_id` must serialize epoch-1 expiry, NOT the old 2034-12-17 future date!
    assert_eq!(
        env.cli_cmd()
            .args(["switch", &s4_id])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let r202_rewritten: serde_json::Value =
        serde_json::from_slice(&fs::read(&slot_file).unwrap()).unwrap();
    assert_eq!(
        r202_rewritten["token"]["expiry"],
        "1970-01-01T00:00:01.000000Z"
    );

    // Parity check via `accounts add --from-local` from identical initial state: persists (1, 0)
    // AND preserves non-default cached `Production` quota `source_env` and fixed `last_updated`!
    let r202_slot_missing_expiry_2 = serde_json::json!({
        "token": {
            "access_token": "ya29.r202_new_at_no_expiry_2",
            "token_type": "Bearer",
            "refresh_token": "1//RT_R202_ROTATED_2"
        },
        "auth_method": "consumer",
        "id_token_email": "compact-rt@example.com"
    });
    let seeded_reimport_quota_ts = 1_700_000_456i64;
    repo.with_write_lock(|tx| {
        let mut r = tx.load_account_opt(&s4_id)?.unwrap();
        r.token.access_token = "ya29.r202_old_at_2".into();
        r.token.expiry_timestamp = 2_050_000_000;
        r.token.expires_in = 3600;
        r.quota = Some(agy_switch_cli::domain::quota::QuotaObservation::new(
            seeded_reimport_quota_ts,
            agy_switch_cli::domain::quota::QuotaSourceEnv::Production,
        ));
        tx.save_account(&r)?;
        Ok(())
    })
    .unwrap();
    fs::write(
        &slot_file,
        serde_json::to_vec(&r202_slot_missing_expiry_2).unwrap(),
    )
    .unwrap();
    let imp_r202 = env
        .cli_cmd()
        .args(["--json", "accounts", "add", "--from-local"])
        .output()
        .unwrap();
    assert_eq!(imp_r202.status.code(), Some(0));
    let r202_after_imp = repo.read_account_unchecked(&s4_id).unwrap();
    assert_eq!(r202_after_imp.token.refresh_token, "1//RT_R202_ROTATED_2");
    assert_eq!(
        r202_after_imp.token.access_token,
        "ya29.r202_new_at_no_expiry_2"
    );
    assert_eq!(r202_after_imp.token.expiry_timestamp, 1);
    assert_eq!(r202_after_imp.token.expires_in, 0);
    let q_imp = r202_after_imp.quota.as_ref().unwrap();
    assert_eq!(
        q_imp.source_env,
        agy_switch_cli::domain::quota::QuotaSourceEnv::Production
    );
    assert_eq!(q_imp.last_updated, seeded_reimport_quota_ts);
}
