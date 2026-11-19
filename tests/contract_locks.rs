use agy_switch_cli::domain::account::{AccountRecord, StoreIndex};
use agy_switch_cli::domain::quota::{
    ModelQuota, QuotaBucket, QuotaGroup, QuotaObservation, QuotaSourceEnv,
};
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend};
use agy_switch_cli::session::payload::serialize_session_payload;
use agy_switch_cli::store::locks::ActiveSlotLock;
use agy_switch_cli::store::repository::StoreRepository;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

struct IsolatedEnv {
    _tmp: TempDir,
    pub home: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub proc_dir: PathBuf,
}

impl IsolatedEnv {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data_dir = tmp.path().join("data");
        let cache_dir = tmp.path().join("cache");
        let runtime_dir = tmp.path().join("run");
        let proc_dir = tmp.path().join("empty_proc");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::create_dir_all(&proc_dir).unwrap();
        Self {
            _tmp: tmp,
            home,
            data_dir,
            cache_dir,
            runtime_dir,
            proc_dir,
        }
    }

    fn init_agy_slot_dir(&self) -> PathBuf {
        let slot_dir = self.home.join(".gemini").join("antigravity-cli");
        fs::create_dir_all(&slot_dir).unwrap();
        fs::set_permissions(&slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
        slot_dir
    }

    fn paths(&self) -> HeadlessPaths {
        HeadlessPaths::with_explicit(
            self.home.clone(),
            self.data_dir.clone(),
            self.cache_dir.join("agy-switch-cli"),
        )
    }

    fn cli_cmd(&self) -> Command {
        self.cli_cmd_with_data_dir(&self.data_dir)
    }

    fn cli_cmd_with_data_dir(&self, data_dir: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self._tmp.path().join("xdg_data"))
            .env("XDG_CACHE_HOME", &self.cache_dir)
            .env("XDG_CONFIG_HOME", self._tmp.path().join("xdg_cfg"))
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", self.runtime_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &self.proc_dir)
            .env(
                "AGY_SWITCH_CLI_AGY_BIN",
                self._tmp.path().join("no-host-agy"),
            )
            .args([
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-remote-version",
            ]);
        cmd
    }
}

fn sample_account(id: &str, email: &str, now: i64) -> AccountRecord {
    let token = TokenRecord {
        access_token: format!("SECRET_ACCESS_TOKEN_{id}"),
        refresh_token: format!("SECRET_REFRESH_TOKEN_{id}"),
        expires_in: 7200,
        expiry_timestamp: now + 7200,
        token_type: "Bearer".into(),
        id_token: Some(format!("SECRET_ID_TOKEN_{id}")),
        oauth_client_key: Some("antigravity_enterprise".into()),
        granted_scopes: Some(vec![
            "openid".into(),
            "https://www.googleapis.com/auth/cloud-platform".into(),
        ]),
        project_id: Some("proj-synth".into()),
        is_gcp_tos: true,
    };
    let mut rec = AccountRecord::new(id.into(), email.into(), token, now);
    rec.custom_label = Some("label-\x1b[31mANSI\x1b[0m".into());
    rec.disabled_detail = Some(format!("SECRET_DISABLED_DETAIL_{id}"));
    rec.validation_url = Some(format!(
        "https://example.invalid/SECRET_VALIDATION_URL_{id}"
    ));
    let mut q = QuotaObservation::new(now, QuotaSourceEnv::Production);
    q.subscription_tier = Some("Google AI Pro".into());
    q.forbidden_reason = Some(format!("SECRET_FORBIDDEN_REASON_{id}"));
    q.models.push(ModelQuota {
        name: "gemini-3.8-flash".into(),
        percentage: 75,
        percentage_known: Some(true),
        observed_remaining_fraction: Some(0.75),
        primary_quota: None,
        quota_bucket_id: Some("gemini-5h".into()),
        reset_time: "2099-01-01T00:00:00Z".into(),
        display_name: Some("Gemini 3.8 Flash".into()),
        supports_images: None,
        supports_thinking: None,
        thinking_budget: None,
        recommended: None,
        max_tokens: None,
        max_output_tokens: None,
        supported_mime_types: None,
    });
    q.quota_groups = Some(vec![QuotaGroup {
        display_name: "Gemini Models".into(),
        description: None,
        buckets: vec![
            QuotaBucket {
                bucket_id: "gemini-5h".into(),
                window: "5h".into(),
                remaining_fraction: 0.75,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-01T00:00:00Z".into(),
                display_name: None,
                description: None,
            },
            QuotaBucket {
                bucket_id: "gemini-weekly".into(),
                window: "weekly".into(),
                remaining_fraction: 0.80,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-07T00:00:00Z".into(),
                display_name: None,
                description: None,
            },
        ],
    }]);
    rec.quota = Some(q);
    rec
}

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
        vec!["policy", "show", "--json"],
        vec!["policy", "eval", "--json"],
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
        vec!["policy", "show"],
        vec!["policy", "eval", "--json"],
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
        .args(["policy", "set", "--reserve", "10"])
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
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};

    let env = IsolatedEnv::new();
    let slot_dir = env.init_agy_slot_dir();
    let _ = &slot_dir;
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
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

    let win = libc::winsize {
        ws_row: 16,
        ws_col: 52, // Narrow SSH terminal layout
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &win,
        )
    };
    assert_eq!(rc, 0, "openpty failed");

    let slave_out_fd = unsafe { libc::dup(slave_fd) };
    let inspect_fd = unsafe { libc::dup(slave_fd) };
    let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
    let slave_out = unsafe { fs::File::from_raw_fd(slave_out_fd) };
    let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_fd) };
    let mut master = unsafe { fs::File::from_raw_fd(master_fd) };

    let mut child = env
        .cli_cmd()
        .arg("tui")
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        let _ = libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let drain_master = |m: &mut fs::File, acc_buf: &mut Vec<u8>| {
        let mut chunk = [0u8; 2048];
        while let Ok(n) = m.read(&mut chunk) {
            if n == 0 {
                break;
            }
            acc_buf.extend_from_slice(&chunk[..n]);
        }
    };

    let mut rendered = Vec::new();
    for _ in 0..40 {
        drain_master(&mut master, &mut rendered);
        if String::from_utf8_lossy(&rendered).contains("Headless SSH Dashboard") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        String::from_utf8_lossy(&rendered).contains("Headless SSH Dashboard"),
        "TUI did not render dashboard frame"
    );

    // Send Down arrow (`\x1b[B`, move cursor down -> acc-2), 's' (switch to acc-2), then Ctrl+C (`\x03`) to quit!
    master.write_all(b"\x1b[B").unwrap();
    master.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    master.write_all(b"s").unwrap();
    master.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(80));
    master.write_all(b"\x03").unwrap();
    master.flush().unwrap();

    let status = child.wait().unwrap();
    drain_master(&mut master, &mut rendered);
    assert_eq!(status.code(), Some(0));

    let full_screen_stream = String::from_utf8_lossy(&rendered);
    assert!(!full_screen_stream.contains("SECRET_"));

    // Active slot switched to `acc-2` via TUI!
    let slot_after = fs::read_to_string(slot_dir.join("antigravity-oauth-token")).unwrap();
    assert!(slot_after.contains("SECRET_REFRESH_TOKEN_acc-2"));

    // RawModeGuard restored canonical ECHO mode on exit!
    let mut post: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post) },
        0
    );
    assert_ne!(post.c_lflag & libc::ECHO, 0);
}

#[cfg(feature = "secret-service-backend")]
#[test]
fn secret_service_backend_fails_cleanly_with_exit_8_in_isolated_dbus_free_env() {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc = sample_account("acc-ss", "ss@example.invalid", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    // IsolatedEnv points DBUS_SESSION_BUS_ADDRESS to `<tmp>/run/no-dbus` (unreachable),
    // guaranteeing zero contact with the host's real D-Bus session while exercising `dual` & `keyring` backends!
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

        // Read-only `current` and `status` with `--backend dual` / `--backend keyring` must succeed (exit code 0)
        // without unlocking/mutating keyring or creating files!
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

    // Legacy `--backend secret-service` and `secret_service` aliases MUST be rejected with exit code 2!
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

#[cfg(feature = "secret-service-backend")]
#[test]
fn secret_service_backend_live_isolated_dbus_never_unlocks_on_readonly_and_tracks_rollback_failure()
{
    let allow_skip = std::env::var("AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let has_bins =
        Path::new("/usr/bin/dbus-daemon").is_file() && Path::new("/usr/bin/python3").is_file();
    let has_py_deps = has_bins
        && Command::new("/usr/bin/python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                "import dbus, dbus.service, dbus.mainloop.glib; from gi.repository import GLib; from cryptography.hazmat.primitives.kdf.hkdf import HKDF",
            ])
            .status()
            .is_ok_and(|s| s.success());
    if !has_py_deps {
        if allow_skip {
            eprintln!("[SKIPPED] live isolated D-Bus test skipped via AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST=1");
            return;
        }
        panic!(
            "Live isolated D-Bus test requires `/usr/bin/dbus-daemon` and Python `dbus` + `gi` + `cryptography` (set AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST=1 to explicitly skip)."
        );
    }

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-kr1", "kr1@example.invalid", now);
    let acc2 = sample_account("acc-kr2", "kr2@example.invalid", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    // Start a 100% isolated private `dbus-daemon` listening ONLY on `<tmp>/run/mock-secrets.sock`
    let bus_sock = env.runtime_dir.join("mock-secrets.sock");
    let bus_addr = format!("unix:path={}", bus_sock.display());
    let dbus_proc = Command::new("/usr/bin/dbus-daemon")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--session",
            &format!("--address={bus_addr}"),
            "--nofork",
            "--nopidfile",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    for _ in 0..50 {
        if bus_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        bus_sock.exists(),
        "Isolated dbus-daemon socket did not appear"
    );

    // 0. Before `org.freedesktop.secrets` is registered on `bus_addr`, default `--backend` (`auto`)
    //    MUST fall back cleanly to `file` (simulating a headless SSH server with systemd user D-Bus)!
    let st_headless_bus = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_headless_bus.status.code(), Some(0));
    let st_hb_j: serde_json::Value = serde_json::from_slice(&st_headless_bus.stdout).unwrap();
    assert_eq!(st_hb_j["backend"], "file");

    let ctrl_file = env._tmp.path().join("ss_ctrl.json");
    let stats_file = env._tmp.path().join("ss_stats.json");
    let ready_file = env._tmp.path().join("ss_ready");
    let mock_py = env._tmp.path().join("mock_secret_service.py");

    fs::write(
        &ctrl_file,
        r#"{"login_locked": true, "item_locked": false, "fail_create_from_call": -1}"#,
    )
    .unwrap();

    let py_code = r#"
import json, os, sys
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CTRL_PATH, STATS_PATH, READY_PATH = sys.argv[1], sys.argv[2], sys.argv[3]
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)

state = {
    "sessions": {},
    "unlock_calls": 0,
    "create_calls": 0,
    "collections": {
        "login": {"locked": True, "items": {}},
        "default": {"locked": False, "items": {}},
    },
    "items": {},
    "next_id": 1,
}

def sync_ctrl():
    with open(CTRL_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if "login_locked" in cfg and cfg["login_locked"] is not None:
        state["collections"]["login"]["locked"] = bool(cfg["login_locked"])
    if "item_locked" in cfg and cfg["item_locked"] is not None:
        for it in state["items"].values():
            it["locked"] = bool(cfg["item_locked"])
    if cfg.get("inject_conflict"):
        # Clear flag after one-shot injection
        cfg["inject_conflict"] = False
        with open(CTRL_PATH, "w", encoding="utf-8") as fw:
            json.dump(cfg, fw)
        p = "/org/freedesktop/secrets/collection/default/iconflict"
        if p not in state["items"]:
            obj = ItemObj(bus, p)
            state["items"][p] = {
                "obj": obj,
                "col": "default",
                "attrs": {"service": "gemini", "username": "antigravity"},
                "secret": b'{"conflicting":true}',
                "locked": False,
            }
            state["collections"]["default"]["items"][p] = True
    if cfg.get("clear_conflict"):
        cfg["clear_conflict"] = False
        with open(CTRL_PATH, "w", encoding="utf-8") as fw:
            json.dump(cfg, fw)
        p = "/org/freedesktop/secrets/collection/default/iconflict"
        it = state["items"].pop(p, None)
        if it:
            state["collections"]["default"]["items"].pop(p, None)
            it["obj"].remove_from_connection()
    return cfg

def dump_stats():
    out = {
        "unlock_calls": state["unlock_calls"],
        "create_calls": state["create_calls"],
        "login_count": len(state["collections"]["login"]["items"]),
        "default_count": len(state["collections"]["default"]["items"]),
        "login_secrets": [
            state["items"][p]["secret"].decode("utf-8", "replace")
            for p in state["collections"]["login"]["items"]
        ],
        "default_secrets": [
            state["items"][p]["secret"].decode("utf-8", "replace")
            for p in state["collections"]["default"]["items"]
        ],
    }
    with open(STATS_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f)

def aes_encrypt(key, data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv, ct

def aes_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

class SessionObj(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Session", in_signature="", out_signature="")
    def Close(self):
        pass

class ItemObj(dbus.service.Object):
    def __init__(self, conn, path):
        super().__init__(conn, path)
        self.path = path

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        sync_ctrl()
        it = state["items"][self.path]
        if prop == "Locked":
            return dbus.Boolean(it["locked"], variant_level=1)
        if prop == "Attributes":
            return dbus.Dictionary(it["attrs"], signature="ss", variant_level=1)
        if prop == "Label":
            return dbus.String("Antigravity", variant_level=1)
        return dbus.UInt64(0, variant_level=1)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        sync_ctrl()
        it = state["items"][self.path]
        return dbus.Dictionary({
            "Locked": dbus.Boolean(it["locked"], variant_level=1),
            "Attributes": dbus.Dictionary(it["attrs"], signature="ss", variant_level=1),
            "Label": dbus.String("Antigravity", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")

    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session):
        sync_ctrl()
        it = state["items"][self.path]
        key = state["sessions"][str(session)]
        iv, ct = aes_encrypt(key, it["secret"])
        dump_stats()
        return (session, dbus.ByteArray(iv), dbus.ByteArray(ct), "text/plain")

    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="", out_signature="o")
    def Delete(self):
        it = state["items"].pop(self.path, None)
        if it:
            state["collections"][it["col"]]["items"].pop(self.path, None)
            self.remove_from_connection()
        dump_stats()
        return dbus.ObjectPath("/")

class CollectionObj(dbus.service.Object):
    def __init__(self, conn, cname):
        self.cname = cname
        self.path = f"/org/freedesktop/secrets/collection/{cname}"
        super().__init__(conn, self.path)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        sync_ctrl()
        col = state["collections"][self.cname]
        if prop == "Locked":
            return dbus.Boolean(col["locked"], variant_level=1)
        if prop == "Items":
            return dbus.Array([dbus.ObjectPath(p) for p in col["items"]], signature="o", variant_level=1)
        if prop == "Label":
            return dbus.String(self.cname, variant_level=1)
        return dbus.UInt64(0, variant_level=1)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        sync_ctrl()
        col = state["collections"][self.cname]
        return dbus.Dictionary({
            "Locked": dbus.Boolean(col["locked"], variant_level=1),
            "Items": dbus.Array([dbus.ObjectPath(p) for p in col["items"]], signature="o", variant_level=1),
            "Label": dbus.String(self.cname, variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")

    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        sync_ctrl()
        req = {str(k): str(v) for k, v in attrs.items()}
        matched = []
        for p in list(state["collections"][self.cname]["items"].keys()):
            it = state["items"][p]
            if all(it["attrs"].get(k) == v for k, v in req.items()):
                matched.append(dbus.ObjectPath(p))
        dump_stats()
        return matched

    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        cfg = sync_ctrl()
        state["create_calls"] += 1
        fail_from = int(cfg.get("fail_create_from_call", -1))
        if fail_from >= 0 and state["create_calls"] >= fail_from:
            dump_stats()
            raise dbus.DBusException("simulated keyring CreateItem failure")

        raw_attrs = props.get("org.freedesktop.Secret.Item.Attributes", {})
        attrs = {str(k): str(v) for k, v in raw_attrs.items()}
        sess_path = str(secret[0])
        key = state["sessions"][sess_path]
        pt = aes_decrypt(key, bytes(secret[1]), bytes(secret[2]))

        if bool(replace):
            for p in list(state["collections"][self.cname]["items"].keys()):
                if state["items"][p]["attrs"] == attrs:
                    state["items"][p]["secret"] = pt
                    dump_stats()
                    return (dbus.ObjectPath(p), dbus.ObjectPath("/"))

        iid = state["next_id"]
        state["next_id"] += 1
        ipath = f"{self.path}/i{iid}"
        obj = ItemObj(bus, ipath)
        state["items"][ipath] = {
            "obj": obj,
            "col": self.cname,
            "attrs": attrs,
            "secret": pt,
            "locked": False,
        }
        state["collections"][self.cname]["items"][ipath] = True
        dump_stats()
        return (dbus.ObjectPath(ipath), dbus.ObjectPath("/"))

class ServiceObj(dbus.service.Object):
    def __init__(self, conn):
        super().__init__(conn, "/org/freedesktop/secrets")
        self.s_idx = 0

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        sync_ctrl()
        if prop == "Collections":
            return dbus.Array([
                dbus.ObjectPath("/org/freedesktop/secrets/collection/login"),
                dbus.ObjectPath("/org/freedesktop/secrets/collection/default"),
            ], signature="o", variant_level=1)
        raise dbus.DBusException("unknown prop")

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        sync_ctrl()
        return dbus.Dictionary({
            "Collections": dbus.Array([
                dbus.ObjectPath("/org/freedesktop/secrets/collection/login"),
                dbus.ObjectPath("/org/freedesktop/secrets/collection/default"),
            ], signature="o", variant_level=1),
        }, signature="sv")

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algo, inp):
        sync_ctrl()
        self.s_idx += 1
        spath = f"/org/freedesktop/secrets/session/s{self.s_idx}"
        SessionObj(bus, spath)
        client_pub = int.from_bytes(bytes(inp), "big")
        priv = int.from_bytes(os.urandom(128), "big")
        srv_pub = pow(2, priv, DH_PRIME)
        shared = pow(client_pub, priv, DH_PRIME).to_bytes(128, "big")
        key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"").derive(shared)
        state["sessions"][spath] = key
        srv_bytes = srv_pub.to_bytes(max(1, (srv_pub.bit_length() + 7) // 8), "big")
        return (dbus.ByteArray(srv_bytes, variant_level=1), dbus.ObjectPath(spath))

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        if str(name) == "default":
            return dbus.ObjectPath("/org/freedesktop/secrets/collection/default")
        return dbus.ObjectPath("/")

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        state["unlock_calls"] += 1
        for o in objects:
            s = str(o)
            if s.endswith("/login"):
                state["collections"]["login"]["locked"] = False
            elif s.endswith("/default"):
                state["collections"]["default"]["locked"] = False
            elif s in state["items"]:
                state["items"][s]["locked"] = False
        # Persist unlocked state into CTRL_PATH so subsequent Get(Locked) reflects Unlock
        with open(CTRL_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["login_locked"] = state["collections"]["login"]["locked"]
        cfg["item_locked"] = False
        with open(CTRL_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        dump_stats()
        return (objects, dbus.ObjectPath("/"))

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus_name = dbus.service.BusName("org.freedesktop.secrets", bus)
svc = ServiceObj(bus)
col_login = CollectionObj(bus, "login")
col_default = CollectionObj(bus, "default")
dump_stats()
with open(READY_PATH, "w", encoding="utf-8") as rf:
    rf.write("ready")
GLib.MainLoop().run()
"#;
    fs::write(&mock_py, py_code).unwrap();

    let py_proc = Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args([
            mock_py.to_str().unwrap(),
            ctrl_file.to_str().unwrap(),
            stats_file.to_str().unwrap(),
            ready_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    struct ProcCleanup(std::process::Child, std::process::Child);
    impl Drop for ProcCleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = self.1.kill();
            let _ = self.1.wait();
        }
    }
    let _cleanup = ProcCleanup(py_proc, dbus_proc);

    for _ in 0..80 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(
        ready_file.exists(),
        "Mock org.freedesktop.secrets service did not become ready"
    );

    let ss_cli = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
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
    let st1: serde_json::Value = serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(
        st1["unlock_calls"], 0,
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
    let st2: serde_json::Value = serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
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
    let st3: serde_json::Value = serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st3["unlock_calls"], 1);

    // 2b. S03 + A04: Mixed-backend cross-process L1 contention on live private Secret Service!
    // Holding a `file`-backend L1 lock from a separate `--data-dir` MUST block `--backend secret-service switch` (exit 5)
    // with ZERO Secret Service `CreateItem` calls; and holding a `secret-service` L1 lock MUST block `--backend file switch`!
    let other_store_dir = env._tmp.path().join("other-file-store");
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
    let st_after_blocked: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st_after_blocked["create_calls"], creates_before_mix);
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
    fs::write(
        &ctrl_file,
        r#"{"login_locked": false, "item_locked": true, "fail_create_from_call": -1}"#,
    )
    .unwrap();
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
    let st4: serde_json::Value = serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(
        st4["unlock_calls"], 1,
        "Read-only status MUST NEVER call Unlock on a locked item!"
    );

    // 4. Inject conflicting duplicate item in `default` collection -> `status` reports Corrupt (exit code 1)!
    fs::write(
        &ctrl_file,
        r#"{"login_locked": false, "item_locked": false, "inject_conflict": true, "fail_create_from_call": -1}"#,
    )
    .unwrap();
    let st_conflict = ss_cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_conflict.status.code(), Some(1));

    let sw_conflict = ss_cli()
        .args(["--json", "switch", "acc-kr2"])
        .output()
        .unwrap();
    assert_eq!(sw_conflict.status.code(), Some(1));

    // 5. Clear duplicate item in mock keyring, then simulate `write_slot` failing on `antigravity-oauth-token` (ENOSPC)
    //    AFTER updating both keyring collections AND keyring rollback failing (`fail_create_from_call`) ->
    //    MUST return exit code 7 (`RecoveryIncomplete`)!
    fs::write(
        &ctrl_file,
        r#"{"login_locked": false, "item_locked": false, "clear_conflict": true, "fail_create_from_call": -1}"#,
    )
    .unwrap();
    let sw_clean = ss_cli()
        .args(["--json", "switch", "acc-kr1"])
        .output()
        .unwrap();
    assert_eq!(sw_clean.status.code(), Some(0));

    // 4b. Default `--backend` (`auto`, zero `--backend` flag!) with live `org.freedesktop.secrets`:
    //     - Automatically selects `secret_service_dual` and suppresses false-positive `dbus_keyring_warning`;
    //     - Continues reporting `matched` from keyring even when disk `antigravity-oauth-token` file is deleted
    //       (while keeping `~/.gemini/antigravity-cli/` directory);
    //     - Dual-writes keyring + recreates disk `antigravity-oauth-token` on `switch`;
    //     - Prioritizes keyring over disk file in `accounts add --from-local` (pure child-process env);
    //     - Honors `config.json` `"backend": "file"` override when configured!
    {
        let auto_cli = || {
            let mut c = env.cli_cmd();
            c.env("DBUS_SESSION_BUS_ADDRESS", &bus_addr);
            c
        };

        let st_auto = auto_cli().args(["--json", "status"]).output().unwrap();
        assert_eq!(st_auto.status.code(), Some(0));
        let st_auto_j: serde_json::Value = serde_json::from_slice(&st_auto.stdout).unwrap();
        assert_eq!(st_auto_j["backend"], "dual");
        assert!(st_auto_j["dbus_keyring_warning"].is_null());

        // Delete disk `antigravity-oauth-token` file while keeping `~/.gemini/antigravity-cli/` directory
        fs::remove_file(&env.paths().active_slot_file).unwrap();
        assert!(!env.paths().active_slot_file.exists());
        let cur_after_rm = auto_cli().args(["--json", "current"]).output().unwrap();
        assert_eq!(cur_after_rm.status.code(), Some(0));
        let cur_rm_j: serde_json::Value = serde_json::from_slice(&cur_after_rm.stdout).unwrap();
        assert_eq!(cur_rm_j["session_identity"]["state"], "matched");
        assert_eq!(cur_rm_j["session_identity"]["account_id"], "acc-kr1");

        // Switch via default `auto` -> updates keyring AND recreates `antigravity-oauth-token`
        let sw_auto = auto_cli()
            .args(["--json", "switch", "acc-kr2"])
            .output()
            .unwrap();
        assert_eq!(sw_auto.status.code(), Some(0));
        assert!(env.paths().active_slot_file.exists());

        // Put invalid JSON in disk `antigravity-oauth-token` while keyring holds valid `acc-kr2` payload:
        // `auto_cli() accounts add --from-local` MUST read from keyring first (advancing past local parse to OAuth transport),
        // whereas `--backend file` hits `data_error` on the corrupt disk file!
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
        let add_kr_err: serde_json::Value = serde_json::from_slice(&add_kr.stderr).unwrap();
        assert_eq!(add_kr_err["error_code"], "oauth_network_error");

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

        // Remove corrupt disk file before restoring synced `acc-kr1`
        fs::remove_file(&env.paths().active_slot_file).unwrap();

        // `config.json` `"backend": "file"` overrides `auto`
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

        // Restore clean `acc-kr1` synced state before step 5
        let sw_restore = ss_cli()
            .args(["--json", "switch", "acc-kr1"])
            .output()
            .unwrap();
        assert_eq!(sw_restore.status.code(), Some(0));
    }

    let cur_stats: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    let base_creates = cur_stats["create_calls"].as_i64().unwrap();
    // Next `switch acc-kr2` does 2 forward CreateItem calls (`base_creates + 1`, `base_creates + 2`),
    // hits injected `enospc` on `antigravity-oauth-token`, then attempts rollback CreateItem (`base_creates + 3`) -> FAIL!
    fs::write(
        &ctrl_file,
        serde_json::to_vec(&serde_json::json!({
            "login_locked": false,
            "item_locked": false,
            "fail_create_from_call": base_creates + 3
        }))
        .unwrap(),
    )
    .unwrap();

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
fn synthetic_human_timestamps_session_id_strip_and_pty_tui_batch_shortcuts_work_end_to_end() {
    use agy_switch_cli::cli::dto::{format_rfc3339_local_minute, format_unix_local_minute};
    use agy_switch_cli::domain::account::{PendingAuthFlow, PendingAuthRecord};

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());

    let mut acc1 = sample_account("acc-ts-1", "alice@example.invalid", now);
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
    let mut acc2 = sample_account("acc-ts-2", "bob@example.invalid", now);
    acc2.quota.as_mut().unwrap().subscription_tier = Some("Free Tier".into());

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

    let cur_json_out = env.cli_cmd().args(["--json", "current"]).output().unwrap();
    let cur_json: serde_json::Value = serde_json::from_slice(&cur_json_out.stdout).unwrap();
    assert_eq!(cur_json["session_identity"]["account_id"], "acc-ts-1");
    assert_eq!(cur_json["session_identity"]["expiry"], raw_expiry);

    // 2. `status` human output reports Backend/Store/Journal/Slot/Daemon/Official agy and omits Session identity, Runtime state, and Stray slot files.
    let status_human = env.cli_cmd().arg("status").output().unwrap();
    assert_eq!(status_human.status.code(), Some(0));
    let status_txt = String::from_utf8_lossy(&status_human.stdout);
    assert!(status_txt.contains("Backend:"));
    assert!(status_txt.contains("Store status:"));
    assert!(status_txt.contains("Journal status:"));
    assert!(status_txt.contains("Slot initialized:"));
    assert!(status_txt.contains("Daemon state:"));
    assert!(status_txt.contains("Official agy:"));
    assert!(!status_txt.contains("Session identity:"));
    assert!(!status_txt.contains("Runtime state:"));
    assert!(!status_txt.contains("Stray slot files:"));

    // 3. `quota` human output formats `Resets (Local)` with 4-digit year `YYYY-MM-DD HH:MM` while `--json` keeps RFC3339.
    let q_human = env.cli_cmd().arg("quota").output().unwrap();
    assert_eq!(q_human.status.code(), Some(0));
    let q_txt = String::from_utf8_lossy(&q_human.stdout);
    let expected_reset = format_rfc3339_local_minute("2099-11-23T14:45:00Z");
    assert!(
        q_txt.contains(&expected_reset),
        "Expected {expected_reset} in quota output:\n{q_txt}"
    );
    let q_json_out = env.cli_cmd().args(["--json", "quota"]).output().unwrap();
    let q_json: serde_json::Value = serde_json::from_slice(&q_json_out.stdout).unwrap();
    assert_eq!(
        q_json["quota"]["quota_groups"][0]["buckets"][1]["reset_time"],
        "2099-11-23T14:45:00Z"
    );

    // 4. `auth pending` human list formats `created_at=YYYY-MM-DD HH:MM` while `--json` preserves integer `created_at`.
    let pend_human = env.cli_cmd().args(["auth", "pending"]).output().unwrap();
    assert_eq!(pend_human.status.code(), Some(0));
    let pend_txt = String::from_utf8_lossy(&pend_human.stdout);
    let expected_created = format_unix_local_minute(pending_created_at);
    assert!(
        pend_txt.contains(&format!("created_at={expected_created}")),
        "Expected formatted created_at={expected_created}, got: {pend_txt}"
    );
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

    // 5. Real PTY TUI end-to-end verification (`C` add all / clear+disable, `cand #2 (skip)`, `5h / W`, `Plan` short, `R` + `SIGTERM`)!
    #[cfg(feature = "tui")]
    {
        use std::io::Read;
        use std::net::TcpListener;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::process::CommandExt;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use std::time::Duration;

        let win = libc::winsize {
            ws_row: 24,
            ws_col: 136,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &win,
                )
            },
            0
        );
        let slave_out_fd = unsafe { libc::dup(slave_fd) };
        let inspect_fd = unsafe { libc::dup(slave_fd) };
        let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
        let slave_out = unsafe { fs::File::from_raw_fd(slave_out_fd) };
        let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_fd) };
        let mut master = unsafe { fs::File::from_raw_fd(master_fd) };

        let mut cmd1 = env.cli_cmd();
        cmd1.arg("tui")
            .stdin(Stdio::from(slave_in))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::piped());
        unsafe {
            cmd1.pre_exec(|| {
                libc::setsid();
                let _ = libc::ioctl(0, libc::TIOCSCTTY, 0);
                Ok(())
            });
        }
        let mut child = cmd1.spawn().unwrap();

        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            let _ = libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let drain = |m: &mut fs::File, buf: &mut Vec<u8>| {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = m.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        };

        let mut screen = Vec::new();
        for _ in 0..50 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Gemini (5h / W)") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let initial_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(initial_txt.contains("Gemini (5h / W)"));
        assert!(initial_txt.contains("Claude/GPT (5h / W)"));
        assert!(initial_txt.contains(&format!(
            "matched (alice@example.invalid, expires {expected_exp_local})"
        )));
        assert!(!initial_txt.contains("Google AI"));
        assert!(initial_txt.contains("Keys   : ↑/↓ select · g/G top/end · [/] reorder"));
        assert!(initial_txt.contains("Manage : r/R refresh · c/C cand"));

        // Press 'C' -> adds both enabled accounts (`acc-ts-1`, `acc-ts-2`) in list order; then 'p' -> enables policy!
        master.write_all(b"Cp").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            if repo.read_policy().is_ok_and(|p| p.enabled) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let pol_after_cp = repo.read_policy().unwrap();
        assert!(pol_after_cp.enabled);
        assert_eq!(
            pol_after_cp.candidate_account_ids,
            vec!["acc-ts-1".to_string(), "acc-ts-2".to_string()]
        );

        // Press Down arrow (`\x1b[B`) then 'd' to disable `acc-ts-2` -> TUI renders `cand #2 (skip)`!
        screen.clear();
        master.write_all(b"\x1b[Bd").unwrap();
        master.flush().unwrap();
        for _ in 0..50 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("cand #2 (skip)") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("cand #2 (skip)"),
            "Expected `cand #2 (skip)` after disabling candidate #2"
        );

        // Re-enable `acc-ts-2` ('e'), then press 'C' when all enabled accounts are already in pool -> clears pool & disables policy!
        master.write_all(b"eC").unwrap();
        master.flush().unwrap();
        for _ in 0..50 {
            if repo
                .read_policy()
                .is_ok_and(|p| p.candidate_account_ids.is_empty() && !p.enabled)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let pol_cleared = repo.read_policy().unwrap();
        assert!(pol_cleared.candidate_account_ids.is_empty());
        assert!(!pol_cleared.enabled);

        // Boundary check: disable BOTH accounts (`d`, Up arrow `\x1b[A`, `d`), then press 'R' and 'C' -> clean status notices with 0 network calls!
        screen.clear();
        master.write_all(b"d\x1b[AdR").unwrap();
        master.flush().unwrap();
        for _ in 0..50 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("No enabled accounts to refresh.") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(String::from_utf8_lossy(&screen).contains("No enabled accounts to refresh."));

        screen.clear();
        master.write_all(b"C").unwrap();
        master.flush().unwrap();
        for _ in 0..50 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen)
                .contains("No enabled accounts available to add as policy candidates.")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(String::from_utf8_lossy(&screen)
            .contains("No enabled accounts available to add as policy candidates."));

        // Re-enable both accounts (`e`, Down arrow `\x1b[B`, `e`) and quit cleanly with 'q'
        master.write_all(b"e\x1b[Beq").unwrap();
        master.flush().unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(0));
        let mut post_q: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post_q) },
            0
        );
        assert_ne!(post_q.c_lflag & libc::ECHO, 0);

        // 6. Launch TUI pointed at a local hanging proxy, press 'R' (batch refresh), verify bottom-bar progress
        //    AND verify `SIGTERM` interrupts batch refresh cleanly and restores PTY `ECHO`!
        let hold_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = hold_listener.local_addr().unwrap().port();
        let proxy_hit = Arc::new(AtomicBool::new(false));
        let proxy_hit_bg = proxy_hit.clone();
        let _proxy_thread = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((sock, _)) = hold_listener.accept() {
                proxy_hit_bg.store(true, Ordering::SeqCst);
                held.push(sock);
            }
        });

        let mut master2_fd: libc::c_int = -1;
        let mut slave2_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master2_fd,
                    &mut slave2_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &win,
                )
            },
            0
        );
        let slave2_out_fd = unsafe { libc::dup(slave2_fd) };
        let inspect2_fd = unsafe { libc::dup(slave2_fd) };
        let slave2_in = unsafe { fs::File::from_raw_fd(slave2_fd) };
        let slave2_out = unsafe { fs::File::from_raw_fd(slave2_out_fd) };
        let inspect2_slave = unsafe { fs::File::from_raw_fd(inspect2_fd) };
        let mut master2 = unsafe { fs::File::from_raw_fd(master2_fd) };

        let mut cmd2 = env.cli_cmd();
        cmd2.env_remove("NO_PROXY")
            .env_remove("AGY_SWITCH_CLI_PROXY")
            .args(["--proxy", &format!("http://127.0.0.1:{proxy_port}"), "tui"])
            .stdin(Stdio::from(slave2_in))
            .stdout(Stdio::from(slave2_out))
            .stderr(Stdio::piped());
        unsafe {
            cmd2.pre_exec(|| {
                libc::setsid();
                let _ = libc::ioctl(0, libc::TIOCSCTTY, 0);
                Ok(())
            });
        }
        let mut child2 = cmd2.spawn().unwrap();
        unsafe {
            let flags = libc::fcntl(master2.as_raw_fd(), libc::F_GETFL);
            let _ = libc::fcntl(master2.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let mut screen2 = Vec::new();
        for _ in 0..50 {
            drain(&mut master2, &mut screen2);
            if String::from_utf8_lossy(&screen2).contains("Headless SSH Dashboard") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        screen2.clear();
        master2.write_all(b"R").unwrap();
        master2.flush().unwrap();
        for _ in 0..60 {
            drain(&mut master2, &mut screen2);
            if proxy_hit.load(Ordering::SeqCst)
                && String::from_utf8_lossy(&screen2).contains("Refreshing 2 enabled account(s)")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            String::from_utf8_lossy(&screen2).contains("Refreshing 2 enabled account(s)"),
            "Expected real-time bottom-bar batch refresh status on 'R'"
        );
        assert!(
            proxy_hit.load(Ordering::SeqCst),
            "Expected 'R' to initiate bounded network refresh against local mock proxy"
        );

        unsafe {
            libc::kill(child2.id() as i32, libc::SIGTERM);
        }
        let st2 = child2.wait().unwrap();
        assert_eq!(st2.code(), Some(0));

        let mut post2: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect2_slave.as_raw_fd(), &mut post2) },
            0
        );
        assert_ne!(
            post2.c_lflag & libc::ECHO,
            0,
            "SIGTERM during 'R' batch refresh MUST restore PTY ECHO!"
        );

        // 7. Also verify raw-mode keyboard Ctrl+C (`\x03` on PTY master, where `ISIG` is disabled)
        //    immediately aborts in-flight 'R' batch refresh, exits 0, and restores PTY `ECHO`!
        proxy_hit.store(false, Ordering::SeqCst);
        let mut master3_fd: libc::c_int = -1;
        let mut slave3_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master3_fd,
                    &mut slave3_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &win,
                )
            },
            0
        );
        let slave3_out_fd = unsafe { libc::dup(slave3_fd) };
        let inspect3_fd = unsafe { libc::dup(slave3_fd) };
        let slave3_in = unsafe { fs::File::from_raw_fd(slave3_fd) };
        let slave3_out = unsafe { fs::File::from_raw_fd(slave3_out_fd) };
        let inspect3_slave = unsafe { fs::File::from_raw_fd(inspect3_fd) };
        let mut master3 = unsafe { fs::File::from_raw_fd(master3_fd) };

        let mut cmd3 = env.cli_cmd();
        cmd3.env_remove("NO_PROXY")
            .env_remove("AGY_SWITCH_CLI_PROXY")
            .args(["--proxy", &format!("http://127.0.0.1:{proxy_port}"), "tui"])
            .stdin(Stdio::from(slave3_in))
            .stdout(Stdio::from(slave3_out))
            .stderr(Stdio::piped());
        unsafe {
            cmd3.pre_exec(|| {
                libc::setsid();
                let _ = libc::ioctl(0, libc::TIOCSCTTY, 0);
                Ok(())
            });
        }
        let mut child3 = cmd3.spawn().unwrap();
        unsafe {
            let flags = libc::fcntl(master3.as_raw_fd(), libc::F_GETFL);
            let _ = libc::fcntl(master3.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let mut screen3 = Vec::new();
        for _ in 0..50 {
            drain(&mut master3, &mut screen3);
            if String::from_utf8_lossy(&screen3).contains("Headless SSH Dashboard") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        screen3.clear();
        master3.write_all(b"R").unwrap();
        master3.flush().unwrap();
        for _ in 0..60 {
            drain(&mut master3, &mut screen3);
            if proxy_hit.load(Ordering::SeqCst)
                && String::from_utf8_lossy(&screen3).contains("Refreshing 2 enabled account(s)")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(proxy_hit.load(Ordering::SeqCst));

        // Send raw `\x03` (`Ctrl+C`) over PTY master (no external `kill` signal!)
        master3.write_all(b"\x03").unwrap();
        master3.flush().unwrap();
        let st3 = child3.wait().unwrap();
        assert_eq!(st3.code(), Some(0));

        let mut post3: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect3_slave.as_raw_fd(), &mut post3) },
            0
        );
        assert_ne!(
            post3.c_lflag & libc::ECHO,
            0,
            "Raw-mode Ctrl+C (`\\x03`) during 'R' batch refresh MUST restore PTY ECHO!"
        );
    }
}

#[test]
fn synthetic_stats_cli_contract_covering_sources_dates_json_fifo_symlink_and_readonly() {
    let env = IsolatedEnv::new();

    // 1. Bare `stats` (no subcommand), mutually exclusive window flags, `--to` without `--from`, & invalid `<N>d` / `--recent` bounds MUST fail with exit code 2 across all feature tiers
    for bad_args in [
        vec!["stats"],
        vec![
            "stats",
            "summary",
            "--range",
            "today",
            "--date",
            "2026-11-17",
        ],
        vec!["stats", "summary", "--range", "7d", "--from", "2026-11-01"],
        vec![
            "stats",
            "summary",
            "--date",
            "2026-11-17",
            "--from",
            "2026-11-01",
        ],
        vec!["stats", "summary", "--range", "today", "--recent", "10"],
        vec!["stats", "list", "--date", "2026-11-17", "--recent", "10"],
        vec!["stats", "summary", "--to", "2026-11-17"],
        vec!["stats", "summary", "--range", "0d"],
        vec!["stats", "summary", "--range", "03d"],
        vec!["stats", "summary", "--range", "36501d"],
        vec!["stats", "list", "--recent", "0"],
        vec!["stats", "list", "--recent", "501"],
    ] {
        let out = env.cli_cmd().args(&bad_args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "Expected exit code 2 for {bad_args:?}"
        );
    }

    #[cfg(not(feature = "stats"))]
    {
        for sub in ["summary", "list"] {
            let out = env
                .cli_cmd()
                .args(["--json", "stats", sub])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2));
            let err_json: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
            assert_eq!(err_json["ok"], false);
            assert_eq!(err_json["exit_code"], 2);
            assert!(!env.data_dir.exists(), "`stats` must never create data_dir");
        }
    }

    #[cfg(feature = "stats")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

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
        let pb_v = |num: u32, v: u64| -> Vec<u8> { [vi(u64::from(num << 3)), vi(v)].concat() };
        let pb_b = |num: u32, v: &[u8]| -> Vec<u8> {
            [vi(u64::from(num << 3 | 2)), vi(v.len() as u64), v.to_vec()].concat()
        };

        // Empty fresh sandbox (`~/.gemini` absent): pure read-only, exit 0, zero files created
        let empty_out = env
            .cli_cmd()
            .args(["--json", "stats", "summary"])
            .output()
            .unwrap();
        assert_eq!(empty_out.status.code(), Some(0));
        assert!(
            !env.data_dir.exists() && !env.home.join(".gemini").exists(),
            "Read-only `stats` must NEVER create `data_dir` or `~/.gemini`"
        );
        let empty_json: serde_json::Value = serde_json::from_slice(&empty_out.stdout).unwrap();
        assert_eq!(empty_json["schema_version"], 1);
        assert_eq!(empty_json["ok"], true);
        assert_eq!(empty_json["source"], "all");
        assert_eq!(empty_json["databases_scanned"], 0);
        assert_eq!(empty_json["summary"]["request_count"], 0);
        assert!(empty_json["summary"]["cache_hit_ratio"].is_null());
        assert!(empty_json["performance"].is_null());

        // Empty fresh sandbox with `--range all` (JSON + human)
        let empty_all_out = env
            .cli_cmd()
            .args(["--json", "stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(empty_all_out.status.code(), Some(0));
        let empty_all_json: serde_json::Value =
            serde_json::from_slice(&empty_all_out.stdout).unwrap();
        assert_eq!(empty_all_json["range"]["kind"], "preset");
        assert_eq!(empty_all_json["range"]["preset"], "all");
        assert!(empty_all_json["range"]["from"].is_null());
        assert!(empty_all_json["range"]["to"].is_null());

        let empty_all_human = env
            .cli_cmd()
            .args(["stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(empty_all_human.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&empty_all_human.stdout).contains("\nRange  : all\n"));

        // Populate synthetic SQLite databases under isolated `$HOME/.gemini`
        let cli_conv = env.home.join(".gemini/antigravity-cli/conversations");
        let app_conv = env.home.join(".gemini/antigravity/conversations");
        fs::create_dir_all(&cli_conv).unwrap();
        fs::create_dir_all(&app_conv).unwrap();

        // Fixed UTC date `2026-11-15T10:00:00Z` via `TZ=UTC0` on child command
        let ts_nov15 = "2026-11-15T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let ts_nov10 = "2026-11-10T08:30:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        let cli_db = cli_conv.join("session_a.db");
        let conn = rusqlite::Connection::open(&cli_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();

        let step_done_text = pb_b(
            20,
            &[pb_b(1, b"synthetic completed text"), pb_v(12, 2)].concat(),
        );

        let make_blob =
            |sys_in: u64, usr_in: u64, out_t: u64, cache_t: u64, ts: u64, label: &str| -> Vec<u8> {
                let usage = [
                    pb_v(1, sys_in),
                    pb_v(2, usr_in),
                    pb_v(3, out_t),
                    pb_v(5, cache_t),
                    pb_v(10, out_t),
                ]
                .concat();
                let timing = pb_b(4, &pb_v(1, ts));
                let ttft_dur = [pb_v(1, 2), pb_v(2, 500_000_000)].concat(); // 2.5s
                let stream_dur = pb_v(1, 10); // 10.0s
                let wrapped = [
                    pb_b(4, &usage),
                    pb_b(9, &timing),
                    pb_b(11, &ttft_dur),
                    pb_b(12, &stream_dur),
                    pb_b(19, b"gemini-4-carbon"),
                    pb_b(21, label.as_bytes()),
                ]
                .concat();
                pb_b(1, &wrapped)
            };

        conn.execute(
            "INSERT INTO steps VALUES (1, 15, ?1, 3, ?2)",
            rusqlite::params![pb_b(1, &pb_v(1, ts_nov15)), &step_done_text],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![make_blob(
                1_000,
                9_000,
                500,
                40_000,
                ts_nov15,
                "Gemini 4 Carbon (High)"
            )],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO steps VALUES (2, 15, ?1, 3, ?2)",
            rusqlite::params![pb_b(1, &pb_v(1, ts_nov10)), &step_done_text],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (2, ?1)",
            rusqlite::params![make_blob(
                500,
                1_500,
                200,
                8_000,
                ts_nov10,
                "Gemini 4 Hydrogen (XHigh)"
            )],
        )
        .unwrap();
        drop(conn);

        // Adversarial FIFO `.db` AND regular `.db` with FIFO `-wal` companion: MUST NOT hang!
        let fifo_db = cli_conv.join("trap_fifo.db");
        let c_fifo_db = CString::new(fifo_db.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo_db.as_ptr(), 0o600) }, 0);

        let wal_trap_db = cli_conv.join("wal_trap.db");
        let wconn = rusqlite::Connection::open(&wal_trap_db).unwrap();
        wconn
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        drop(wconn);
        let wal_fifo = cli_conv.join("wal_trap.db-wal");
        let c_wal_fifo = CString::new(wal_fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_wal_fifo.as_ptr(), 0o600) }, 0);

        // App DB on `2026-11-15`
        let app_db = app_conv.join("app_session.db");
        let aconn = rusqlite::Connection::open(&app_db).unwrap();
        aconn
            .execute_batch(
                "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        aconn
            .execute(
                "INSERT INTO steps VALUES (1, 15, ?1, 3, NULL)",
                rusqlite::params![pb_b(1, &pb_v(1, ts_nov15 + 60))],
            )
            .unwrap();
        aconn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_blob(
                    2_000,
                    3_000,
                    600,
                    15_000,
                    ts_nov15 + 60,
                    "Claude Opus 4.6"
                )],
            )
            .unwrap();
        drop(aconn);

        // Query default `stats summary --date 2026-11-15` (defaults to `--source all`: scans both CLI + App!)
        let default_d_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["stats", "summary", "--date", "2026-11-15"])
            .output()
            .unwrap();
        assert_eq!(default_d_out.status.code(), Some(0));
        let default_d_txt = String::from_utf8_lossy(&default_d_out.stdout);
        assert!(
            default_d_txt.contains(
                "Source : all (~/.gemini/antigravity-cli + ~/.gemini/antigravity) · 2 db(s) · latest 2026-11-15 10:01"
            ),
            "{default_d_txt}"
        );
        assert!(
            default_d_txt.contains("Gemini 4 Carbon (High)"),
            "{default_d_txt}"
        );
        assert!(default_d_txt.contains("Claude Opus 4.6"), "{default_d_txt}");

        // Query explicit `--source cli --date 2026-11-15`
        let d_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args([
                "stats",
                "summary",
                "--source",
                "cli",
                "--date",
                "2026-11-15",
            ])
            .output()
            .unwrap();
        assert_eq!(d_out.status.code(), Some(0));
        let d_txt = String::from_utf8_lossy(&d_out.stdout);
        assert!(
            d_txt.contains(
                "Source : cli (~/.gemini/antigravity-cli) · 1 db(s) · latest 2026-11-15 10:00"
            ),
            "{d_txt}"
        );
        assert!(d_txt.contains("Range  : 2026-11-15"), "{d_txt}");
        assert!(
            d_txt.contains("Total input        : 50.0K (50,000)"),
            "{d_txt}"
        );
        assert!(d_txt.contains("Cache hit          : 80.0%"), "{d_txt}");
        assert!(
            d_txt.contains("TTFT (P10/P50/P90) : 2.5 / 2.5 / 2.5 s"),
            "{d_txt}"
        );
        assert!(
            d_txt.contains("TPS (P10/P50/P90) : 50.0 / 50.0 / 50.0 t/s"),
            "{d_txt}"
        );
        assert!(!d_txt.contains("Duration"), "{d_txt}");
        assert!(!d_txt.contains("In TPS"), "{d_txt}");
        assert!(d_txt.contains("Gemini 4 Carbon (High)"), "{d_txt}");
        assert!(!d_txt.contains("Gemini 4 Hydrogen"), "{d_txt}");

        // Query `--source all --from 2026-11-10 --to 2026-11-15 --json`
        let all_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args([
                "--json",
                "stats",
                "summary",
                "--source",
                "all",
                "--from",
                "2026-11-10",
                "--to",
                "2026-11-15",
            ])
            .output()
            .unwrap();
        assert_eq!(all_out.status.code(), Some(0));
        let all_json: serde_json::Value = serde_json::from_slice(&all_out.stdout).unwrap();
        assert_eq!(all_json["source"], "all");
        assert_eq!(all_json["databases_scanned"], 2);
        assert_eq!(all_json["summary"]["request_count"], 3);
        assert_eq!(all_json["summary"]["uncached_input_tokens"], 17_000);
        assert_eq!(all_json["summary"]["cached_input_tokens"], 63_000);
        assert_eq!(all_json["summary"]["total_input_tokens"], 80_000);
        assert_eq!(all_json["summary"]["total_output_tokens"], 1_300);
        assert_eq!(all_json["performance"]["sample_count"], 3);
        assert_eq!(all_json["performance"]["model_count"], 3);
        assert_eq!(all_json["performance"]["source_count"], 2);
        assert_eq!(all_json["performance"]["ttft_seconds"]["p50"], 2.5);
        assert_eq!(all_json["performance"]["output_tps"]["p10"], 26.0);
        assert_eq!(all_json["performance"]["output_tps"]["p50"], 50.0);
        assert_eq!(all_json["performance"]["output_tps"]["p90"], 58.0);

        // Inverted `--from > --to` and secret `--date` redaction
        let inv_out = env
            .cli_cmd()
            .args([
                "--json",
                "stats",
                "summary",
                "--from",
                "2026-11-16",
                "--to",
                "2026-11-15",
            ])
            .output()
            .unwrap();
        assert_eq!(inv_out.status.code(), Some(2));

        let sec_out = env
            .cli_cmd()
            .args([
                "--json",
                "stats",
                "summary",
                "--date",
                "1//0gSECRET_DATE_LEAK_12345",
            ])
            .output()
            .unwrap();
        assert_eq!(sec_out.status.code(), Some(2));
        let sec_err = String::from_utf8_lossy(&sec_out.stderr);
        assert!(!sec_err.contains("SECRET_DATE_LEAK_12345"), "{sec_err}");

        // Arbitrary `<N>d` preset (`--range 14d` & `--range 1d`) and `--range` secret redaction
        let nd_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--range", "14d"])
            .output()
            .unwrap();
        assert_eq!(nd_out.status.code(), Some(0));
        let nd_json: serde_json::Value = serde_json::from_slice(&nd_out.stdout).unwrap();
        assert_eq!(nd_json["range"]["kind"], "preset");
        assert_eq!(nd_json["range"]["preset"], "14d");

        let d1_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--range", "1d"])
            .output()
            .unwrap();
        assert_eq!(d1_out.status.code(), Some(0));
        let d1_json: serde_json::Value = serde_json::from_slice(&d1_out.stdout).unwrap();
        assert_eq!(d1_json["range"]["preset"], "1d");
        assert_eq!(d1_json["range"]["from"], d1_json["range"]["to"]);

        // `--range all` across historical DBs (`2026-11-10 .. 2026-11-15` observed span)
        let r_all_json_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(r_all_json_out.status.code(), Some(0));
        let r_all_j: serde_json::Value = serde_json::from_slice(&r_all_json_out.stdout).unwrap();
        assert_eq!(r_all_j["range"]["kind"], "preset");
        assert_eq!(r_all_j["range"]["preset"], "all");
        assert_eq!(r_all_j["range"]["from"], "2026-11-10");
        assert_eq!(r_all_j["range"]["to"], "2026-11-15");
        assert_eq!(r_all_j["summary"]["request_count"], 3);
        assert_eq!(r_all_j["performance"]["sample_count"], 3);

        let r_all_human_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(r_all_human_out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&r_all_human_out.stdout)
            .contains("Range  : all (2026-11-10 .. 2026-11-15)"));

        let rng_sec_out = env
            .cli_cmd()
            .args([
                "--json",
                "stats",
                "summary",
                "--range",
                "1//0gSECRET_RANGE_LEAK_54321",
            ])
            .output()
            .unwrap();
        assert_eq!(rng_sec_out.status.code(), Some(2));
        let rng_sec_err = String::from_utf8_lossy(&rng_sec_out.stderr);
        assert!(
            !rng_sec_err.contains("SECRET_RANGE_LEAK_54321"),
            "{rng_sec_err}"
        );
        assert!(!env.data_dir.exists(), "`stats` must remain 100% read-only");

        // Concurrent active SQLite WAL writer holding an open uncheckpointed transaction +
        // 150 live `.db`s under tight `RLIMIT_NOFILE = 256` (`O(1)` FD scan regression lock!)
        let scale_env = IsolatedEnv::new();
        let scale_conv = scale_env.home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&scale_conv).unwrap();

        for i in 0..149_u64 {
            let p = scale_conv.join(format!("conv_{i:03}.db"));
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
                .unwrap();
            c.execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_blob(10, 90, 20, 0, ts_nov15, "Gemini 4 Carbon (High)")],
            )
            .unwrap();
        }

        // 150th DB held open by an active in-process WAL writer with `wal_autocheckpoint = 0`!
        let active_wal_path = scale_conv.join("conv_149_wal.db");
        let active_wal_conn = rusqlite::Connection::open(&active_wal_path).unwrap();
        active_wal_conn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        active_wal_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_blob(10, 90, 20, 0, ts_nov15, "Gemini 4 Carbon (High)")],
            )
            .unwrap();

        // Also place a corrupt `.db` (and if non-root, an unreadable `0000` `.db`) to verify `unreadable_databases` accounting
        let corrupt_db = scale_conv.join("corrupt_header.db");
        fs::write(&corrupt_db, b"not-a-valid-sqlite-header-at-all").unwrap();
        let expected_unreadable = if unsafe { libc::geteuid() } != 0 {
            let locked_db = scale_conv.join("no_perm.db");
            fs::write(&locked_db, b"").unwrap();
            fs::set_permissions(&locked_db, fs::Permissions::from_mode(0o000)).unwrap();
            2_u64
        } else {
            1_u64
        };

        use std::os::unix::process::CommandExt;
        let mut scale_cmd = scale_env.cli_cmd();
        scale_cmd
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--date", "2026-11-15"]);
        unsafe {
            scale_cmd.pre_exec(|| {
                let lim = libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: 256,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let scale_out = scale_cmd.output().unwrap();
        if unsafe { libc::geteuid() } != 0 {
            let _ = fs::set_permissions(
                scale_conv.join("no_perm.db"),
                fs::Permissions::from_mode(0o600),
            );
        }
        drop(active_wal_conn);

        assert_eq!(scale_out.status.code(), Some(0));
        let scale_json: serde_json::Value = serde_json::from_slice(&scale_out.stdout).unwrap();
        assert_eq!(scale_json["databases_scanned"], 150);
        assert_eq!(scale_json["unreadable_databases"], expected_unreadable);
        assert_eq!(scale_json["summary"]["request_count"], 150);
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

#[cfg(feature = "secret-service-backend")]
#[test]
fn synthetic_v120_dual_write_replica_divergence_dbus_wall_timeout_and_run_isolate_dbus() {
    let allow_skip = std::env::var("AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let has_bins =
        Path::new("/usr/bin/dbus-daemon").is_file() && Path::new("/usr/bin/python3").is_file();
    let has_py_deps = has_bins
        && Command::new("/usr/bin/python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                "import dbus, dbus.service, dbus.mainloop.glib; from gi.repository import GLib; from cryptography.hazmat.primitives.kdf.hkdf import HKDF",
            ])
            .status()
            .is_ok_and(|s| s.success());
    if !has_py_deps {
        if allow_skip {
            return;
        }
        panic!("Live isolated D-Bus test requires `/usr/bin/dbus-daemon` and Python `dbus` + `gi` + `cryptography`.");
    }

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-dw1", "dw1@example.invalid", now);
    let acc2 = sample_account("acc-dw2", "dw2@example.invalid", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    // 1. P1-07: Non-local `tcp:` D-Bus address is rejected by `auto` (immediate fallback to `file`)
    //    AND stalling local Unix socket enforces `1500ms` wall-clock cap!
    let tcp_st = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", "tcp:host=127.0.0.1,port=1")
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(tcp_st.status.code(), Some(0));
    let tcp_j: serde_json::Value = serde_json::from_slice(&tcp_st.stdout).unwrap();
    assert_eq!(tcp_j["backend"], "file");

    let stall_sock = env.runtime_dir.join("stall.sock");
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

    // 2. Launch isolated `dbus-daemon` + `mock_secret_service.py`
    let bus_sock = env.runtime_dir.join("dw-secrets.sock");
    let bus_addr = format!("unix:path={}", bus_sock.display());
    let dbus_proc = Command::new("/usr/bin/dbus-daemon")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--session",
            &format!("--address={bus_addr}"),
            "--nofork",
            "--nopidfile",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if bus_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(bus_sock.exists());

    let ctrl_file = env._tmp.path().join("dw_ctrl.json");
    let stats_file = env._tmp.path().join("dw_stats.json");
    let ready_file = env._tmp.path().join("dw_ready");
    let mock_py = env._tmp.path().join("dw_mock_ss.py");
    fs::write(
        &ctrl_file,
        r#"{"fail_create": false, "fail_msg": "SENSITIVE_DBUS_EXCEPTION_PAYLOAD_999"}"#,
    )
    .unwrap();

    let py_code = r#"
import json, os, sys
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CTRL_PATH, STATS_PATH, READY_PATH = sys.argv[1], sys.argv[2], sys.argv[3]
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
state = {"sessions": {}, "create_calls": 0, "items": {}, "next_id": 1}

def dump_stats():
    secrets = [it["secret"].decode("utf-8", "replace") for it in state["items"].values()]
    with open(STATS_PATH, "w", encoding="utf-8") as f:
        json.dump({"create_calls": state["create_calls"], "secrets": secrets}, f)

def aes_encrypt(key, data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, enc.update(padded) + enc.finalize()

def aes_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

class SessionObj(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Session", in_signature="", out_signature="")
    def Close(self):
        pass

class ItemObj(dbus.service.Object):
    def __init__(self, conn, path):
        super().__init__(conn, path)
        self.path = path
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        it = state["items"][self.path]
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Attributes":
            return dbus.Dictionary(it["attrs"], signature="ss", variant_level=1)
        return dbus.String("item", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        it = state["items"][self.path]
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Attributes": dbus.Dictionary(it["attrs"], signature="ss", variant_level=1),
            "Label": dbus.String("Antigravity", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session_path):
        key = state["sessions"][str(session_path)]
        iv, ct = aes_encrypt(key, state["items"][self.path]["secret"])
        return (session_path, dbus.ByteArray(iv), dbus.ByteArray(ct), "text/plain")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="", out_signature="o")
    def Delete(self):
        state["items"].pop(self.path, None)
        self.remove_from_connection()
        dump_stats()
        return dbus.ObjectPath("/")

class CollectionObj(dbus.service.Object):
    def __init__(self, conn):
        self.path = "/org/freedesktop/secrets/collection/login"
        super().__init__(conn, self.path)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Items":
            return dbus.Array([dbus.ObjectPath(p) for p in state["items"]], signature="o", variant_level=1)
        return dbus.String("login", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Items": dbus.Array([dbus.ObjectPath(p) for p in state["items"]], signature="o", variant_level=1),
            "Label": dbus.String("login", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        req = {str(k): str(v) for k, v in attrs.items()}
        return [dbus.ObjectPath(p) for p, it in state["items"].items() if all(it["attrs"].get(k) == v for k, v in req.items())]
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        with open(CTRL_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        state["create_calls"] += 1
        if cfg.get("fail_create"):
            dump_stats()
            raise dbus.DBusException(cfg.get("fail_msg", "err"))
        sess_path, iv, ct, _ = secret
        key = state["sessions"][str(sess_path)]
        raw = aes_decrypt(key, bytes(iv), bytes(ct))
        attrs = {str(k): str(v) for k, v in props.get("org.freedesktop.Secret.Item.Attributes", {}).items()}
        if bool(replace):
            for p, it in list(state["items"].items()):
                if it["attrs"] == attrs:
                    it["secret"] = raw
                    dump_stats()
                    return (dbus.ObjectPath(p), dbus.ObjectPath("/"))
        iid = state["next_id"]
        state["next_id"] += 1
        ipath = f"{self.path}/i{iid}"
        obj = ItemObj(bus, ipath)
        state["items"][ipath] = {"obj": obj, "attrs": attrs, "secret": raw}
        dump_stats()
        return (dbus.ObjectPath(ipath), dbus.ObjectPath("/"))

class ServiceObj(dbus.service.Object):
    def __init__(self, conn):
        super().__init__(conn, "/org/freedesktop/secrets")
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        if prop == "Collections":
            return dbus.Array([dbus.ObjectPath("/org/freedesktop/secrets/collection/login")], signature="o", variant_level=1)
        return dbus.Array([], signature="o", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return dbus.Dictionary({
            "Collections": dbus.Array([dbus.ObjectPath("/org/freedesktop/secrets/collection/login")], signature="o", variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algo, inp):
        sid = len(state["sessions"]) + 1
        spath = f"/org/freedesktop/secrets/session/s{sid}"
        SessionObj(bus, spath)
        peer_pub = int.from_bytes(bytes(inp), "big")
        priv = int.from_bytes(os.urandom(32), "big") | 1
        pub = pow(2, priv, DH_PRIME)
        shared = pow(peer_pub, priv, DH_PRIME)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"").derive(shared.to_bytes(128, "big"))
        state["sessions"][spath] = aes_key
        return (dbus.ByteArray(pub.to_bytes(128, "big")), dbus.ObjectPath(spath))
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        if name in ("default", "login"):
            return dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
        return dbus.ObjectPath("/")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        return (objects, dbus.ObjectPath("/"))

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus_name = dbus.service.BusName("org.freedesktop.secrets", bus)
svc = ServiceObj(bus)
col = CollectionObj(bus)
dump_stats()
with open(READY_PATH, "w", encoding="utf-8") as rf:
    rf.write("ready")
GLib.MainLoop().run()
"#;
    fs::write(&mock_py, py_code).unwrap();

    let py_proc = Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args([
            mock_py.to_str().unwrap(),
            ctrl_file.to_str().unwrap(),
            stats_file.to_str().unwrap(),
            ready_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    struct Cleanup(std::process::Child, std::process::Child);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = self.1.kill();
            let _ = self.1.wait();
        }
    }
    let _guard = Cleanup(py_proc, dbus_proc);

    for _ in 0..80 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(ready_file.exists());

    let auto_bus = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", &bus_addr);
        c
    };

    // Initial dual-write switch to `acc-dw1` under default `auto`
    let sw1 = auto_bus()
        .args(["--json", "switch", "acc-dw1"])
        .output()
        .unwrap();
    assert_eq!(sw1.status.code(), Some(0));
    let st_init: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(
        st_init["create_calls"], 1,
        "`auto` must activate `secret_service_dual` on live isolated D-Bus"
    );

    // 3. P1-07: D-Bus exception text is redacted to fixed category without echoing external message!
    fs::write(
        &ctrl_file,
        r#"{"fail_create": true, "fail_msg": "SENSITIVE_DBUS_EXCEPTION_PAYLOAD_999"}"#,
    )
    .unwrap();
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
    fs::write(&ctrl_file, r#"{"fail_create": false}"#).unwrap();

    // 4. P1-08 (v1.2.0 normalized): removed `--isolate-dbus` fails with exit 2;
    //    explicit `--backend file` (flag, env, or config.json) auto-sets child `DBUS_SESSION_BUS_ADDRESS=unix:path=/dev/null`
    //    while `auto` fallback on a headless D-Bus bus leaves child `DBUS_SESSION_BUS_ADDRESS` untouched!
    let fake_bin_dir = env._tmp.path().join("fake_bin");
    fs::create_dir_all(&fake_bin_dir).unwrap();
    let fake_agy = fake_bin_dir.join("agy");
    let seen_dbus_file = env._tmp.path().join("child_dbus_seen.txt");
    fs::write(
        &fake_agy,
        format!(
            "#!/bin/sh\nprintf '%s' \"$DBUS_SESSION_BUS_ADDRESS\" > \"{}\"\nexit 0\n",
            seen_dbus_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let removed_flag = auto_bus()
        .args(["run", "--isolate-dbus", "--", fake_agy.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(removed_flag.status.code(), Some(2));

    // Explicit `--backend file` + `run --account acc-dw2` MUST use `FileSessionBackend`
    // (leaving keyring at `acc-dw1` while updating file slot to `acc-dw2` AND setting child DBUS to `unix:path=/dev/null`!)
    let st_before_run: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
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
    let st_after_run: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(
        st_after_run["create_calls"], st_before_run["create_calls"],
        "`--backend file run` must not touch keyring"
    );
    assert!(fs::read_to_string(&env.paths().active_slot_file)
        .unwrap()
        .contains("SECRET_REFRESH_TOKEN_acc-dw2"));

    // Explicit `AGY_SWITCH_CLI_BACKEND=file` AND `config.json` `"backend": "file"` ALSO auto-isolate child D-Bus!
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

    // Conversely, default `--backend auto` falling back to `file` (when D-Bus has NO `org.freedesktop.secrets`)
    // MUST leave child `DBUS_SESSION_BUS_ADDRESS` untouched so `systemctl --user` inside `agy` is unaffected!
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

    // Sync both replicas cleanly back to `acc-dw1` via `switch acc-dw1`
    assert_eq!(
        auto_bus()
            .args(["--json", "switch", "acc-dw1"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );

    // 5. P0-02 (a): One-shot post-rename disk fault (`after_rename:antigravity-oauth-token:corrupt_once`)
    //    during dual-write MUST roll back BOTH keyring AND disk file to `acc-dw1`!
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
    let st_after_rb: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert!(
        disk_after_rb.contains("SECRET_REFRESH_TOKEN_acc-dw1"),
        "Disk replica was not rolled back after post-rename fault: {disk_after_rb}"
    );
    assert!(
        st_after_rb["secrets"][0]
            .as_str()
            .unwrap()
            .contains("SECRET_REFRESH_TOKEN_acc-dw1"),
        "Keyring replica was not rolled back: {st_after_rb}"
    );

    // 5b. P0-02 (b): Persistent post-rename disk fault (`after_rename:antigravity-oauth-token:corrupt_after_rename`)
    //     where disk rollback ALSO fails while keyring rollback succeeds MUST NOT clear journal or return exit 1 —
    //     it MUST preserve `switch_journal.json` and return exit code 7 (`RecoveryIncomplete`)!
    let persistent_fault = auto_bus()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_rename:antigravity-oauth-token:corrupt_after_rename",
        )
        .args(["--json", "switch", "acc-dw2"])
        .output()
        .unwrap();
    assert_eq!(persistent_fault.status.code(), Some(7));
    assert!(
        env.paths().switch_journal_file().exists(),
        "Journal MUST be preserved when disk replica remains corrupted after keyring rollback!"
    );
    assert_eq!(
        auto_bus()
            .args(["--json", "policy", "set", "--reserve", "10"])
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

    // 6. P0-02 (b): Mid-dual-write crash (`before_write:antigravity-oauth-token:abort`) AFTER keyring
    //    updated to `acc-dw2` and BEFORE disk updated (so keyring=`acc-dw2`, disk=`acc-dw1`)!
    //    Read-only `status` / `switch --dry-run` AND narrowed `--backend file` write commands MUST return exit code 7 and preserve `switch_journal.json`!
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
            "policy",
            "set",
            "--reserve",
            "10",
        ],
    ] {
        let blocked = auto_bus().args(&check_args).output().unwrap();
        assert_eq!(
            blocked.status.code(),
            Some(7),
            "Expected exit code 7 on diverged dual-write replicas for {check_args:?}, stderr={}",
            String::from_utf8_lossy(&blocked.stderr)
        );
        assert!(
            env.paths().switch_journal_file().exists(),
            "Journal was prematurely cleared despite diverged replicas on {check_args:?}"
        );
    }

    // Subsequent interactive write command under `auto` (`secret_service_dual`) synchronizes BOTH replicas and clears journal!
    let heal_dw = auto_bus()
        .args(["--json", "policy", "set", "--reserve", "10"])
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
    let synced_kr: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(synced_disk, synced_kr["secrets"][0].as_str().unwrap());
    assert!(synced_disk.contains("SECRET_REFRESH_TOKEN_acc-dw2"));

    // 7. Corrupt local disk file replica while keyring still holds a valid item (and no journal exists):
    //    `status --json` MUST report `"slot_corrupt": true` and exit 1 instead of silently passing!
    fs::write(&env.paths().active_slot_file, b"{corrupt-disk-replica").unwrap();
    let corrupt_st = auto_bus().args(["--json", "status"]).output().unwrap();
    assert_eq!(
        corrupt_st.status.code(),
        Some(1),
        "status must fail when disk credential file replica is corrupt even if keyring is valid"
    );
    let corrupt_err: serde_json::Value = serde_json::from_slice(&corrupt_st.stderr).unwrap();
    assert_eq!(corrupt_err["details"]["slot_corrupt"], true);
}

#[cfg(feature = "secret-service-backend")]
#[test]
fn synthetic_v120_multicollection_asymmetric_keyring_rollback_swap_and_external_sync() {
    let allow_skip = std::env::var("AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let has_bins =
        Path::new("/usr/bin/dbus-daemon").is_file() && Path::new("/usr/bin/python3").is_file();
    let has_py_deps = has_bins
        && Command::new("/usr/bin/python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                "import dbus, dbus.service, dbus.mainloop.glib; from gi.repository import GLib; from cryptography.hazmat.primitives.kdf.hkdf import HKDF",
            ])
            .status()
            .is_ok_and(|s| s.success());
    if !has_py_deps {
        if allow_skip {
            return;
        }
        panic!("Live isolated D-Bus test requires `/usr/bin/dbus-daemon` and Python `dbus` + `gi` + `cryptography`.");
    }

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-mc1", "alice@example.com", now);
    let acc2 = sample_account("acc-mc2", "bob@example.com", now);
    let acc_ext = sample_account("acc-ext", "charlie@example.com", now);
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

    let bus_sock = env.runtime_dir.join("mc-secrets.sock");
    let bus_addr = format!("unix:path={}", bus_sock.display());
    let dbus_proc = Command::new("/usr/bin/dbus-daemon")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--session",
            &format!("--address={bus_addr}"),
            "--nofork",
            "--nopidfile",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if bus_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(bus_sock.exists());

    let seed_file = env._tmp.path().join("mc_seed.json");
    let stats_file = env._tmp.path().join("mc_stats.json");
    let ready_file = env._tmp.path().join("mc_ready");
    let mock_py = env._tmp.path().join("mc_mock_ss.py");
    fs::write(
        &seed_file,
        serde_json::to_vec(&serde_json::json!({
            "login": payload_1,
            "default": serde_json::Value::Null,
        }))
        .unwrap(),
    )
    .unwrap();

    let py_code = r#"
import json, os, sys
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SEED_PATH, STATS_PATH, READY_PATH = sys.argv[1], sys.argv[2], sys.argv[3]
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
LOGIN_PATH = "/org/freedesktop/secrets/collection/login"
DEFAULT_PATH = "/org/freedesktop/secrets/collection/custom_default"

state = {"sessions": {}, "items": {}, "next_id": 1, "seed_mtime": 0.0}

def dump_stats():
    by_col = {"login": [], "default": []}
    for p, it in state["items"].items():
        s = it["secret"].decode("utf-8", "replace")
        if it["col"] == LOGIN_PATH:
            by_col["login"].append(s)
        else:
            by_col["default"].append(s)
    with open(STATS_PATH, "w", encoding="utf-8") as f:
        json.dump(by_col, f)

def maybe_reload_seed():
    st = os.stat(SEED_PATH)
    if st.st_mtime <= state["seed_mtime"]:
        return
    state["seed_mtime"] = st.st_mtime
    with open(SEED_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for p, it in list(state["items"].items()):
        it["obj"].remove_from_connection()
        state["items"].pop(p, None)
    attrs = {"service": "gemini", "username": "antigravity"}
    for key, cpath in [("login", LOGIN_PATH), ("default", DEFAULT_PATH)]:
        val = cfg.get(key)
        if val is not None:
            iid = state["next_id"]
            state["next_id"] += 1
            ipath = f"{cpath}/i{iid}"
            obj = ItemObj(bus, ipath)
            state["items"][ipath] = {"obj": obj, "col": cpath, "attrs": dict(attrs), "secret": val.encode("utf-8")}
    dump_stats()

def aes_encrypt(key, data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, enc.update(padded) + enc.finalize()

def aes_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

class SessionObj(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Session", in_signature="", out_signature="")
    def Close(self):
        pass

class ItemObj(dbus.service.Object):
    def __init__(self, conn, path):
        super().__init__(conn, path)
        self.path = path
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        maybe_reload_seed()
        it = state["items"][self.path]
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Attributes":
            return dbus.Dictionary(it["attrs"], signature="ss", variant_level=1)
        return dbus.String("item", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        maybe_reload_seed()
        it = state["items"][self.path]
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Attributes": dbus.Dictionary(it["attrs"], signature="ss", variant_level=1),
            "Label": dbus.String("Antigravity", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session_path):
        maybe_reload_seed()
        key = state["sessions"][str(session_path)]
        iv, ct = aes_encrypt(key, state["items"][self.path]["secret"])
        return (session_path, dbus.ByteArray(iv), dbus.ByteArray(ct), "text/plain")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="", out_signature="o")
    def Delete(self):
        state["items"].pop(self.path, None)
        self.remove_from_connection()
        dump_stats()
        return dbus.ObjectPath("/")

class CollectionObj(dbus.service.Object):
    def __init__(self, conn, path, label):
        self.path = path
        self.label = label
        super().__init__(conn, self.path)
    def my_items(self):
        return [p for p, it in state["items"].items() if it["col"] == self.path]
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        maybe_reload_seed()
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Items":
            return dbus.Array([dbus.ObjectPath(p) for p in self.my_items()], signature="o", variant_level=1)
        return dbus.String(self.label, variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        maybe_reload_seed()
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Items": dbus.Array([dbus.ObjectPath(p) for p in self.my_items()], signature="o", variant_level=1),
            "Label": dbus.String(self.label, variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        maybe_reload_seed()
        req = {str(k): str(v) for k, v in attrs.items()}
        return [
            dbus.ObjectPath(p)
            for p, it in state["items"].items()
            if it["col"] == self.path and all(it["attrs"].get(k) == v for k, v in req.items())
        ]
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        maybe_reload_seed()
        sess_path, iv, ct, _ = secret
        key = state["sessions"][str(sess_path)]
        raw = aes_decrypt(key, bytes(iv), bytes(ct))
        attrs = {str(k): str(v) for k, v in props.get("org.freedesktop.Secret.Item.Attributes", {}).items()}
        if bool(replace):
            for p, it in list(state["items"].items()):
                if it["col"] == self.path and it["attrs"] == attrs:
                    it["secret"] = raw
                    dump_stats()
                    return (dbus.ObjectPath(p), dbus.ObjectPath("/"))
        iid = state["next_id"]
        state["next_id"] += 1
        ipath = f"{self.path}/i{iid}"
        obj = ItemObj(bus, ipath)
        state["items"][ipath] = {"obj": obj, "col": self.path, "attrs": attrs, "secret": raw}
        dump_stats()
        return (dbus.ObjectPath(ipath), dbus.ObjectPath("/"))

class ServiceObj(dbus.service.Object):
    def __init__(self, conn):
        super().__init__(conn, "/org/freedesktop/secrets")
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        if prop == "Collections":
            return dbus.Array([dbus.ObjectPath(LOGIN_PATH), dbus.ObjectPath(DEFAULT_PATH)], signature="o", variant_level=1)
        return dbus.Array([], signature="o", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return dbus.Dictionary({
            "Collections": dbus.Array([dbus.ObjectPath(LOGIN_PATH), dbus.ObjectPath(DEFAULT_PATH)], signature="o", variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algo, inp):
        sid = len(state["sessions"]) + 1
        spath = f"/org/freedesktop/secrets/session/s{sid}"
        SessionObj(bus, spath)
        peer_pub = int.from_bytes(bytes(inp), "big")
        priv = int.from_bytes(os.urandom(32), "big") | 1
        pub = pow(2, priv, DH_PRIME)
        shared = pow(peer_pub, priv, DH_PRIME)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"").derive(shared.to_bytes(128, "big"))
        state["sessions"][spath] = aes_key
        return (dbus.ByteArray(pub.to_bytes(128, "big")), dbus.ObjectPath(spath))
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        if name == "login":
            return dbus.ObjectPath(LOGIN_PATH)
        if name == "default":
            return dbus.ObjectPath(DEFAULT_PATH)
        return dbus.ObjectPath("/")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        return (objects, dbus.ObjectPath("/"))

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus_name = dbus.service.BusName("org.freedesktop.secrets", bus)
svc = ServiceObj(bus)
col_login = CollectionObj(bus, LOGIN_PATH, "login")
col_default = CollectionObj(bus, DEFAULT_PATH, "custom_default")
maybe_reload_seed()
with open(READY_PATH, "w", encoding="utf-8") as rf:
    rf.write("ready")
GLib.MainLoop().run()
"#;
    fs::write(&mock_py, py_code).unwrap();

    let py_proc = Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args([
            mock_py.to_str().unwrap(),
            seed_file.to_str().unwrap(),
            stats_file.to_str().unwrap(),
            ready_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    struct Cleanup(std::process::Child, std::process::Child);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = self.1.kill();
            let _ = self.1.wait();
        }
    }
    let _guard = Cleanup(py_proc, dbus_proc);

    for _ in 0..80 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(ready_file.exists());

    let auto_bus = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", &bus_addr);
        c
    };

    // 1. Asymmetric pre-switch collections (`login = Some(acc1), custom_default = None`) + disk ENOSPC:
    //    MUST restore `login = Some(acc1)` & `custom_default = None`, clear journal, and exit 1 (NOT exit 7!)
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
        "Asymmetric multi-collection rollback must exit 1 (clean rollback), stderr={}",
        String::from_utf8_lossy(&enospc_rb.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    let st1: serde_json::Value = serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st1["login"].as_array().unwrap().len(), 1);
    assert_eq!(st1["default"].as_array().unwrap().len(), 0);

    // 2. Asymmetric pre-switch collections + one-shot post-rename fault (`corrupt_once`):
    //    MUST restore `login = Some(acc1)`, `custom_default = None`, and `disk = acc1`, exiting 1!
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
    let st2: serde_json::Value = serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st2["login"].as_array().unwrap().len(), 1);
    assert_eq!(st2["default"].as_array().unwrap().len(), 0);

    // 3. Abort before `write_slot` (`after_token_refreshed` / `before_write` journal left at `SlotCommitting`
    //    with `login=Some(acc1), default=None` recorded in `replica_state.keyring.collections`),
    //    then swap items (`login = None, default = Some(acc1)`):
    //    `status` MUST detect asymmetric collection swap as `RecoveryIncomplete` (exit 7), NEVER `AbortedUncommitted`!
    let crash_pre = auto_bus()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "after_token_refreshed:*:abort")
        .args(["--json", "switch", "acc-mc2"])
        .output()
        .unwrap();
    assert_eq!(crash_pre.status.code(), Some(137));
    assert!(env.paths().switch_journal_file().exists());

    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(
        &seed_file,
        serde_json::to_vec(&serde_json::json!({
            "login": serde_json::Value::Null,
            "default": payload_1,
        }))
        .unwrap(),
    )
    .unwrap();

    let swap_st = auto_bus().args(["--json", "status"]).output().unwrap();
    assert_eq!(
        swap_st.status.code(),
        Some(7),
        "Collection swap (`login=None, default=Some(acc1)`) must be flagged as RecoveryIncomplete (exit 7)!"
    );

    // 4. External `agy` logs into a 3rd account (`acc_ext`) ONLY in `login` (`default = None`, `uniform == false`)
    //    before next write command: pre-write journal self-healing MUST preserve `acc_ext` and sync ALL replicas to `acc_ext`!
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(
        &seed_file,
        serde_json::to_vec(&serde_json::json!({
            "login": payload_ext,
            "default": serde_json::Value::Null,
        }))
        .unwrap(),
    )
    .unwrap();

    let fix_ext = auto_bus()
        .args(["--json", "policy", "set", "--reserve", "10"])
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
    let st_ext: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert!(
        disk_ext.contains("SECRET_REFRESH_TOKEN_acc-ext"),
        "External keyring credential was clobbered instead of preserved: {disk_ext}"
    );
    assert_eq!(st_ext["login"][0].as_str().unwrap(), disk_ext);
    assert_eq!(st_ext["default"][0].as_str().unwrap(), disk_ext);
}

#[cfg(feature = "secret-service-backend")]
#[test]
fn synthetic_v120_keyring_only_backend_never_creates_modifies_or_requires_local_file() {
    let allow_skip = std::env::var("AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let has_bins =
        Path::new("/usr/bin/dbus-daemon").is_file() && Path::new("/usr/bin/python3").is_file();
    let has_py_deps = has_bins
        && Command::new("/usr/bin/python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                "import dbus, dbus.service, dbus.mainloop.glib; from gi.repository import GLib; from cryptography.hazmat.primitives.kdf.hkdf import HKDF",
            ])
            .status()
            .is_ok_and(|s| s.success());
    if !has_py_deps {
        if allow_skip {
            return;
        }
        panic!("Live isolated D-Bus test requires `/usr/bin/dbus-daemon` and Python `dbus` + `gi` + `cryptography`.");
    }

    // Notice we intentionally DO NOT call `env.init_agy_slot_dir()` here:
    // `~/.gemini/antigravity-cli` does NOT exist at all!
    let env = IsolatedEnv::new();
    assert!(!env.paths().active_slot_dir.exists());
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-ko1", "alice@example.com", now);
    let acc2 = sample_account("acc-ko2", "bob@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    let bus_sock = env.runtime_dir.join("ko-secrets.sock");
    let bus_addr = format!("unix:path={}", bus_sock.display());
    let dbus_proc = Command::new("/usr/bin/dbus-daemon")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--session",
            &format!("--address={bus_addr}"),
            "--nofork",
            "--nopidfile",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if bus_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(bus_sock.exists());

    let stats_file = env._tmp.path().join("ko_stats.json");
    let ready_file = env._tmp.path().join("ko_ready");
    let mock_py = env._tmp.path().join("ko_mock_ss.py");
    let py_code = r#"
import json, os, sys
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

STATS_PATH, READY_PATH = sys.argv[1], sys.argv[2]
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
state = {"sessions": {}, "items": {}, "next_id": 1}

def dump_stats():
    secrets = [it["secret"].decode("utf-8", "replace") for it in state["items"].values()]
    with open(STATS_PATH, "w", encoding="utf-8") as f:
        json.dump({"secrets": secrets}, f)

def aes_encrypt(key, data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, enc.update(padded) + enc.finalize()

def aes_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

class SessionObj(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Session", in_signature="", out_signature="")
    def Close(self):
        pass

class ItemObj(dbus.service.Object):
    def __init__(self, conn, path):
        super().__init__(conn, path)
        self.path = path
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        it = state["items"][self.path]
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Attributes":
            return dbus.Dictionary(it["attrs"], signature="ss", variant_level=1)
        return dbus.String("item", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        it = state["items"][self.path]
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Attributes": dbus.Dictionary(it["attrs"], signature="ss", variant_level=1),
            "Label": dbus.String("Antigravity", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session_path):
        key = state["sessions"][str(session_path)]
        iv, ct = aes_encrypt(key, state["items"][self.path]["secret"])
        return (session_path, dbus.ByteArray(iv), dbus.ByteArray(ct), "text/plain")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="", out_signature="o")
    def Delete(self):
        state["items"].pop(self.path, None)
        self.remove_from_connection()
        dump_stats()
        return dbus.ObjectPath("/")

class CollectionObj(dbus.service.Object):
    def __init__(self, conn):
        self.path = "/org/freedesktop/secrets/collection/login"
        super().__init__(conn, self.path)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Items":
            return dbus.Array([dbus.ObjectPath(p) for p in state["items"]], signature="o", variant_level=1)
        return dbus.String("login", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Items": dbus.Array([dbus.ObjectPath(p) for p in state["items"]], signature="o", variant_level=1),
            "Label": dbus.String("login", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        req = {str(k): str(v) for k, v in attrs.items()}
        return [dbus.ObjectPath(p) for p, it in state["items"].items() if all(it["attrs"].get(k) == v for k, v in req.items())]
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        sess_path, iv, ct, _ = secret
        key = state["sessions"][str(sess_path)]
        raw = aes_decrypt(key, bytes(iv), bytes(ct))
        attrs = {str(k): str(v) for k, v in props.get("org.freedesktop.Secret.Item.Attributes", {}).items()}
        if bool(replace):
            for p, it in list(state["items"].items()):
                if it["attrs"] == attrs:
                    it["secret"] = raw
                    dump_stats()
                    return (dbus.ObjectPath(p), dbus.ObjectPath("/"))
        iid = state["next_id"]
        state["next_id"] += 1
        ipath = f"{self.path}/i{iid}"
        obj = ItemObj(bus, ipath)
        state["items"][ipath] = {"obj": obj, "attrs": attrs, "secret": raw}
        dump_stats()
        return (dbus.ObjectPath(ipath), dbus.ObjectPath("/"))

class ServiceObj(dbus.service.Object):
    def __init__(self, conn):
        super().__init__(conn, "/org/freedesktop/secrets")
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        if prop == "Collections":
            return dbus.Array([dbus.ObjectPath("/org/freedesktop/secrets/collection/login")], signature="o", variant_level=1)
        return dbus.Array([], signature="o", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return dbus.Dictionary({
            "Collections": dbus.Array([dbus.ObjectPath("/org/freedesktop/secrets/collection/login")], signature="o", variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algo, inp):
        sid = len(state["sessions"]) + 1
        spath = f"/org/freedesktop/secrets/session/s{sid}"
        SessionObj(bus, spath)
        peer_pub = int.from_bytes(bytes(inp), "big")
        priv = int.from_bytes(os.urandom(32), "big") | 1
        pub = pow(2, priv, DH_PRIME)
        shared = pow(peer_pub, priv, DH_PRIME)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"").derive(shared.to_bytes(128, "big"))
        state["sessions"][spath] = aes_key
        return (dbus.ByteArray(pub.to_bytes(128, "big")), dbus.ObjectPath(spath))
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        if name in ("default", "login"):
            return dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
        return dbus.ObjectPath("/")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        return (objects, dbus.ObjectPath("/"))

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus_name = dbus.service.BusName("org.freedesktop.secrets", bus)
svc = ServiceObj(bus)
col = CollectionObj(bus)
dump_stats()
with open(READY_PATH, "w", encoding="utf-8") as rf:
    rf.write("ready")
GLib.MainLoop().run()
"#;
    fs::write(&mock_py, py_code).unwrap();
    let py_proc = Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args([
            mock_py.to_str().unwrap(),
            stats_file.to_str().unwrap(),
            ready_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    struct Cleanup(std::process::Child, std::process::Child);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = self.1.kill();
            let _ = self.1.wait();
        }
    }
    let _guard = Cleanup(py_proc, dbus_proc);

    for _ in 0..80 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(ready_file.exists());

    let kr_cli = || {
        let mut c = env.cli_cmd();
        c.env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
            .args(["--backend", "keyring"]);
        c
    };

    // 1. When keyring is empty and local file EXISTS (`acc1`), `--backend keyring` `accounts add --from-local`
    //    MUST NOT fall back to reading the local file (`not_found` exit 3)!
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
    // Now delete `~/.gemini/antigravity-cli` completely to prove `--backend keyring` NEVER requires or creates it!
    fs::remove_dir_all(&env.paths().active_slot_dir).unwrap();
    assert!(!env.paths().active_slot_dir.exists());

    // 2. `switch --dry-run` and real `switch` under `--backend keyring` succeed with ZERO local directory/file!
    let dry_ko = kr_cli()
        .args(["--json", "switch", "--dry-run", "acc-ko2"])
        .output()
        .unwrap();
    assert_eq!(
        dry_ko.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&dry_ko.stderr)
    );
    let sw_ko = kr_cli()
        .args(["--json", "switch", "acc-ko2"])
        .output()
        .unwrap();
    assert_eq!(
        sw_ko.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sw_ko.stderr)
    );
    assert!(
        !env.paths().active_slot_dir.exists(),
        "`--backend keyring` MUST NEVER create `~/.gemini/antigravity-cli`!"
    );
    assert!(
        !env.paths().active_slot_file.exists(),
        "`--backend keyring` MUST NEVER create `antigravity-oauth-token`!"
    );

    // 3. `current` and `status` under `--backend keyring` report `matched` (`bob@example.com`) and `"backend": "keyring"`,
    //    even if a corrupt `antigravity-oauth-token` file is placed on disk!
    env.init_agy_slot_dir();
    fs::write(
        &env.paths().active_slot_file,
        b"{corrupt-local-file-ignored-by-keyring",
    )
    .unwrap();
    let cur_ko = kr_cli().args(["--json", "current"]).output().unwrap();
    assert_eq!(
        cur_ko.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&cur_ko.stderr)
    );
    let cur_ko_j: serde_json::Value = serde_json::from_slice(&cur_ko.stdout).unwrap();
    assert_eq!(cur_ko_j["session_identity"]["state"], "matched");
    assert_eq!(cur_ko_j["session_identity"]["email"], "bob@example.com");

    let st_ko = kr_cli().args(["--json", "status"]).output().unwrap();
    assert_eq!(
        st_ko.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&st_ko.stderr)
    );
    let st_ko_j: serde_json::Value = serde_json::from_slice(&st_ko.stdout).unwrap();
    assert_eq!(st_ko_j["backend"], "keyring");
    assert_eq!(st_ko_j["store_ok"], true);
    assert_eq!(st_ko_j["slot_initialized"], true);
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        "{corrupt-local-file-ignored-by-keyring",
        "`--backend keyring` MUST NEVER modify local `antigravity-oauth-token`!"
    );

    // 4. `accounts delete --force --clear-active-slot` under `--backend keyring` clears keyring item ONLY,
    //    leaving local disk file completely untouched!
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
    let st_after_del: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st_after_del["secrets"].as_array().unwrap().len(), 0);
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        "{corrupt-local-file-ignored-by-keyring"
    );

    // 5. Cross-backend journal scoping:
    //    (a) A `RecoveryIncomplete` journal recorded by `--backend keyring` while `~/.gemini/antigravity-cli`
    //        does NOT exist MUST be repaired cleanly by bare write command (`auto` -> `dual`)
    //        WITHOUT requiring or creating `~/.gemini/antigravity-cli`!
    fs::remove_dir_all(&env.paths().active_slot_dir).unwrap();
    assert!(!env.paths().active_slot_dir.exists());
    let mut ko_incomplete = agy_switch_cli::session::journal::SwitchJournal::new_prepared(
        "op-ko-inc".into(),
        Some("acc-ko1".into()),
        "acc-ko1".into(),
        None,
        now,
    );
    ko_incomplete.phase = agy_switch_cli::session::journal::JournalPhase::RecoveryIncomplete;
    ko_incomplete.note = Some("Simulated keyring rollback interruption.".into());
    let ko_meta = agy_switch_cli::session::journal::JournalReplicaRecord {
        backend: "keyring".into(),
        uses_file: false,
        keyring: Some(agy_switch_cli::session::journal::JournalReplicaSnapshot {
            prev_present: false,
            prev_digest: None,
            prev_uniform: true,
            collections: vec![
                agy_switch_cli::session::journal::JournalCollectionSnapshot {
                    path: "/org/freedesktop/secrets/collection/login".into(),
                    prev_present: false,
                    prev_digest: None,
                },
            ],
        }),
        file: agy_switch_cli::session::journal::JournalReplicaSnapshot {
            prev_present: false,
            prev_digest: None,
            prev_uniform: true,
            collections: Vec::new(),
        },
    };
    repo.with_write_lock(|_| {
        agy_switch_cli::session::journal::write_journal_with_replicas(
            &env.paths(),
            &ko_incomplete,
            Some(&ko_meta),
        )
    })
    .unwrap();

    let auto_fix_ko = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        auto_fix_ko.status.code(),
        Some(0),
        "Bare write command (`auto` -> `dual`) must repair `keyring`-only RecoveryIncomplete journal cleanly: stderr={}",
        String::from_utf8_lossy(&auto_fix_ko.stderr)
    );
    assert!(
        !env.paths().active_slot_dir.exists(),
        "Repairing a `keyring`-only journal under `auto` MUST NOT create `~/.gemini/antigravity-cli`!"
    );
    assert!(!env.paths().switch_journal_file().exists());
    let st_after_ko_fix: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert!(st_after_ko_fix["secrets"][0]
        .as_str()
        .unwrap()
        .contains("SECRET_REFRESH_TOKEN_acc-ko1"));

    //    (b) `CommittedSlot` journal recorded by `--backend keyring` for a subsequently removed target account (`acc-ko3`)
    //        MUST NOT delete an unrelated local `antigravity-oauth-token` (`acc-ko1`) when reconciled under `auto` (`dual`)!
    let acc3 = sample_account("acc-ko3", "charlie@example.com", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc3.clone(), false, now))
        .unwrap();
    env.init_agy_slot_dir();
    let payload_ko1 = serialize_session_payload(&acc1.token).unwrap();
    FileSessionBackend
        .write_slot(&env.paths(), &payload_ko1)
        .unwrap();

    let crash_ko3 = kr_cli()
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "after_slot_commit:*:abort")
        .args(["--json", "switch", "acc-ko3"])
        .output()
        .unwrap();
    assert_eq!(crash_ko3.status.code(), Some(137));
    assert!(env.paths().switch_journal_file().exists());
    // Remove `acc-ko3` from store directly under write lock to simulate deleted target before reconciliation
    repo.with_write_lock(|tx| tx.delete_account("acc-ko3", true, now))
        .unwrap();

    let rec_del_ko3 = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        rec_del_ko3.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&rec_del_ko3.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    let st_after_ko3: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(
        st_after_ko3["secrets"].as_array().unwrap().len(),
        0,
        "Deleted target must be cleared from keyring"
    );
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        payload_ko1,
        "Reconciling a `keyring`-only journal under `auto` MUST preserve untouched local `antigravity-oauth-token`!"
    );

    //    (c) Reverse direction: a `file`-only `RecoveryIncomplete` journal reconciled under `auto` (`dual`)
    //        MUST repair ONLY the local file replica without overwriting or clearing the desktop keyring!
    let acc4 = sample_account("acc-ko4", "dave@example.com", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc4.clone(), false, now))
        .unwrap();
    // Put `acc-ko4` into the keyring via `--backend keyring switch`
    assert_eq!(
        kr_cli()
            .args(["--json", "switch", "acc-ko4"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    // Corrupt the local file and write a `file`-only `RecoveryIncomplete` journal for `acc-ko1`
    fs::write(&env.paths().active_slot_file, b"{corrupt-file-replica").unwrap();
    let mut file_inc = agy_switch_cli::session::journal::SwitchJournal::new_prepared(
        "op-file-inc".into(),
        Some("acc-ko1".into()),
        "acc-ko1".into(),
        None,
        now,
    );
    file_inc.phase = agy_switch_cli::session::journal::JournalPhase::RecoveryIncomplete;
    file_inc.note = Some("Simulated file rollback failure.".into());
    let file_meta = agy_switch_cli::session::journal::JournalReplicaRecord {
        backend: "file".into(),
        uses_file: true,
        keyring: None,
        file: agy_switch_cli::session::journal::JournalReplicaSnapshot {
            prev_present: true,
            prev_digest: Some(agy_switch_cli::session::payload::bytes_sha256_hex(
                payload_ko1.as_bytes(),
            )),
            prev_uniform: true,
            collections: Vec::new(),
        },
    };
    repo.with_write_lock(|_| {
        agy_switch_cli::session::journal::write_journal_with_replicas(
            &env.paths(),
            &file_inc,
            Some(&file_meta),
        )
    })
    .unwrap();

    let rec_file_only = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        rec_file_only.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&rec_file_only.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    // Local file was repaired to `acc-ko1`, while keyring STILL holds `acc-ko4` untouched!
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        payload_ko1
    );
    let st_after_file_fix: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert!(
        st_after_file_fix["secrets"][0]
            .as_str()
            .unwrap()
            .contains("SECRET_REFRESH_TOKEN_acc-ko4"),
        "Repairing a `file`-only journal under `auto` MUST NOT overwrite the desktop keyring!"
    );
}

#[test]
fn synthetic_v120_daemon_install_uninstall_and_switch_running_guard_modes() {
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

    // =========================================================================
    // Part A: `switch` default `AllowVerifiedRunning` vs `--require-idle` vs `Unverified`
    // =========================================================================
    let fake_bin = env._tmp.path().join("bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let fake_agy = fake_bin.join("agy");
    fs::write(&fake_agy, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    // Seed a verified running `agy` process (PID 636233) inside `env.proc_dir`
    let pid_dir = env.proc_dir.join("636233");
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        "636233 (agy) S 1 636233 636233 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 987654 1000 10",
    )
    .unwrap();
    fs::write(pid_dir.join("comm"), "agy\n").unwrap();
    std::os::unix::fs::symlink(&fake_agy, pid_dir.join("exe")).unwrap();

    // 0. `current` human & JSON output omits redundant `identity` AND omits `, managed_accounts=[]` when empty!
    let cur_human = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["current"])
        .output()
        .unwrap();
    assert_eq!(cur_human.status.code(), Some(0));
    let cur_stdout = String::from_utf8_lossy(&cur_human.stdout);
    assert!(
        cur_stdout.contains("Live agy runtime : unmanaged_running (pids=[636233])"),
        "Expected clean runtime line without identity or empty managed_accounts, got:\n{cur_stdout}"
    );
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

    // 3. Default `switch` (no flags) while verified `agy` is running -> succeeds (`0`) AND emits `runtime_warning`!
    let ok_running_sw = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["--json", "switch", "acc-sw2"])
        .output()
        .unwrap();
    assert_eq!(
        ok_running_sw.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&ok_running_sw.stderr)
    );
    let ok_sw_j: serde_json::Value = serde_json::from_slice(&ok_running_sw.stdout).unwrap();
    assert!(ok_sw_j["switch"]["runtime_warning"]
        .as_str()
        .unwrap_or("")
        .contains("636233"));

    // 4. `Unverified` `/proc` (missing proc root): default `switch` STILL fails closed with exit 8 (`runtime_state_unverified`),
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

    // =========================================================================
    // Part B: `daemon --install` & `daemon --uninstall` in 100% isolated `/tmp` sandbox
    // =========================================================================
    let no_systemd_dir = env._tmp.path().join("no-systemd");
    let systemd_marker_dir = env._tmp.path().join("run-systemd-system");
    let systemctl_log = env._tmp.path().join("systemctl_calls.log");
    let systemctl_fail_env = env._tmp.path().join("fail_show_env");
    let mock_systemctl = fake_bin.join("systemctl");
    let systemctl_state_file = env._tmp.path().join("systemctl_enabled.state");
    fs::write(
        &mock_systemctl,
        format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{}\"\n\
             if [ \"$2\" = \"show-environment\" ] && [ -f \"{}\" ]; then\n\
               echo 'Failed to connect to bus: No medium found' >&2\n\
               exit 1\n\
             fi\n\
             UNIT_FILE=\"$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"\n\
             if [ \"$2\" = \"enable\" ]; then\n\
               echo \"enabled\" > \"{}\"\n\
             elif [ \"$2\" = \"disable\" ]; then\n\
               rm -f \"{}\"\n\
             elif [ \"$2\" = \"show\" ]; then\n\
               if [ -f \"$UNIT_FILE\" ]; then\n\
                 printf 'FragmentPath=%s\\n' \"$UNIT_FILE\"\n\
                 printf 'LoadState=loaded\\n'\n\
                 if [ -f \"{}\" ]; then\n\
                   printf 'UnitFileState=enabled\\nActiveState=active\\n'\n\
                 else\n\
                   printf 'UnitFileState=disabled\\nActiveState=inactive\\n'\n\
                 fi\n\
               else\n\
                 printf 'FragmentPath=\\nLoadState=not-found\\nUnitFileState=\\nActiveState=inactive\\n'\n\
               fi\n\
             fi\n\
             exit 0\n",
            systemctl_log.display(),
            systemctl_fail_env.display(),
            systemctl_state_file.display(),
            systemctl_state_file.display(),
            systemctl_state_file.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&mock_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    // 1. Mutual exclusion (`--install` + `--uninstall`, `--install` + `--once`, `--install` + `--reserve`, `--install` + `--proxy`) -> exit 2
    for bad_daemon_args in [
        vec!["--json", "daemon", "--install", "--uninstall"],
        vec!["--json", "daemon", "--install", "--once"],
        vec!["--json", "daemon", "--uninstall", "--once"],
        vec!["--json", "daemon", "--install", "--reserve", "20"],
        vec![
            "--json",
            "--proxy",
            "http://127.0.0.1:7890",
            "daemon",
            "--install",
        ],
        vec![
            "--json",
            "--proxy",
            "http://127.0.0.1:7890",
            "daemon",
            "--uninstall",
        ],
    ] {
        let bad = env.cli_cmd().args(&bad_daemon_args).output().unwrap();
        assert_eq!(
            bad.status.code(),
            Some(2),
            "Expected exit 2 for {bad_daemon_args:?}"
        );
    }

    let xdg_cfg_dir = env._tmp.path().join("xdg_cfg");
    let expected_unit = xdg_cfg_dir.join("systemd/user/agy-switch-cli.service");

    // 2. Non-systemd container/distro (`AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR` missing) -> friendly exit 8 (`systemd_unavailable`)
    let no_sd = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &no_systemd_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(no_sd.status.code(), Some(8));
    let no_sd_err: serde_json::Value = serde_json::from_slice(&no_sd.stderr).unwrap();
    assert_eq!(no_sd_err["error_code"], "systemd_unavailable");
    assert!(no_sd_err["message"]
        .as_str()
        .unwrap_or("")
        .contains("docs/user-guide.md"));
    assert!(!expected_unit.exists());

    // 3. Systemd booted, but `systemctl --user show-environment` fails -> exit 8 BEFORE writing unit file!
    fs::create_dir_all(&systemd_marker_dir).unwrap();
    fs::write(&systemctl_fail_env, "1").unwrap();
    let no_mgr = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(no_mgr.status.code(), Some(8));
    let no_mgr_err: serde_json::Value = serde_json::from_slice(&no_mgr.stderr).unwrap();
    assert_eq!(no_mgr_err["error_code"], "systemd_user_unavailable");
    assert!(!expected_unit.exists());
    fs::remove_file(&systemctl_fail_env).unwrap();
    let _ = fs::remove_file(&systemctl_log);

    // 4. `daemon --install --interval 7200 --cooldown 1800 --json` with `AGY_SWITCH_CLI_BACKEND=file` + custom `XDG_CACHE_HOME`:
    //    writes unit file inside isolated XDG_CONFIG_HOME (`<tmp>/xdg_cfg/systemd/user/agy-switch-cli.service`),
    //    persists `AGY_SWITCH_CLI_BACKEND` and custom `XDG_CACHE_HOME`, preserves hardening directives,
    //    and runs `show-environment` -> `daemon-reload` -> `enable --now`!
    let custom_xdg_cache = env._tmp.path().join("custom_xdg_cache");
    let inst_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .env("AGY_SWITCH_CLI_BACKEND", "file")
        .env("XDG_CACHE_HOME", &custom_xdg_cache)
        .args([
            "--json",
            "daemon",
            "--install",
            "--interval",
            "7200",
            "--cooldown",
            "1800",
        ])
        .output()
        .unwrap();
    assert_eq!(
        inst_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&inst_out.stderr)
    );
    let inst_j: serde_json::Value = serde_json::from_slice(&inst_out.stdout).unwrap();
    assert_eq!(inst_j["action"], "install");
    assert_eq!(inst_j["interval_secs"], 7200);
    assert_eq!(inst_j["cooldown_secs"], 1800);

    let unit_path = PathBuf::from(inst_j["unit_path"].as_str().unwrap());
    assert_eq!(unit_path, expected_unit);
    assert!(unit_path.exists());
    let unit_text = fs::read_to_string(&unit_path).unwrap();
    assert!(unit_text.contains("--backend file daemon --interval 7200 --cooldown 1800"));
    assert!(unit_text.contains(&format!(
        "Environment=\"XDG_CACHE_HOME={}\"",
        custom_xdg_cache.display()
    )));
    assert!(unit_text.contains("NoNewPrivileges=true"));
    assert!(unit_text.contains("ProtectSystem=strict"));
    assert!(unit_text.contains("ReadWritePaths=-"));

    let calls_after_install = fs::read_to_string(&systemctl_log).unwrap();
    let call_lines: Vec<&str> = calls_after_install.lines().collect();
    assert_eq!(
        call_lines,
        vec![
            "--user show-environment",
            "--user daemon-reload",
            "--user show -p FragmentPath -p LoadState -p UnitFileState -p ActiveState agy-switch-cli.service",
            "--user enable --now agy-switch-cli.service",
            "--user show -p FragmentPath -p LoadState -p UnitFileState -p ActiveState agy-switch-cli.service",
        ]
    );

    // 5. Symlink protection on `--uninstall`: replacing unit file with a symlink MUST fail without following it!
    let innocent_target = env._tmp.path().join("do_not_delete.txt");
    fs::write(&innocent_target, "keep").unwrap();
    fs::remove_file(&unit_path).unwrap();
    std::os::unix::fs::symlink(&innocent_target, &unit_path).unwrap();
    let sym_uninst = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(sym_uninst.status.code(), Some(1));
    assert!(innocent_target.exists());
    fs::remove_file(&unit_path).unwrap();

    // Re-install human output check, then `--uninstall` (and second idempotent `--uninstall`)!
    let inst_human = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(inst_human.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&inst_human.stdout).contains("loginctl enable-linger"));
    assert!(unit_path.exists());
    let _ = fs::remove_file(&systemctl_log);

    let uninst_1 = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(uninst_1.status.code(), Some(0));
    let uninst_1_j: serde_json::Value = serde_json::from_slice(&uninst_1.stdout).unwrap();
    assert_eq!(uninst_1_j["removed_unit_file"], true);
    assert!(!unit_path.exists());
    let uninst_calls: Vec<String> = fs::read_to_string(&systemctl_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(
        uninst_calls,
        vec![
            "--user show-environment",
            "--user show -p FragmentPath -p LoadState -p UnitFileState -p ActiveState agy-switch-cli.service",
            "--user disable --now agy-switch-cli.service",
            "--user daemon-reload",
            "--user show -p FragmentPath -p LoadState -p UnitFileState -p ActiveState agy-switch-cli.service",
        ]
    );

    let uninst_2 = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(uninst_2.status.code(), Some(0));
    let uninst_2_j: serde_json::Value = serde_json::from_slice(&uninst_2.stdout).unwrap();
    assert_eq!(uninst_2_j["removed_unit_file"], false);
}

#[test]
fn synthetic_v120_signoff_round2_exact_backend_literals_tui_json_and_uninstall_dir_swap_guard() {
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
            "policy",
            "set",
            "--reserve",
            "10",
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
            "policy",
            "set",
            "--reserve",
            "10",
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

    // 5. F1-09: `daemon --uninstall` concurrent ancestor directory replacement with a symlink during
    //    `systemctl --user disable --now` MUST refuse to unlink through the new symlink!
    let marker_dir = env._tmp.path().join("systemd_marker");
    fs::create_dir_all(&marker_dir).unwrap();
    let victim_dir = env._tmp.path().join("victim_systemd_user");
    fs::create_dir_all(&victim_dir).unwrap();
    let victim_unit = victim_dir.join("agy-switch-cli.service");
    fs::write(&victim_unit, "[Unit]\nDescription=VictimMustSurvive\n").unwrap();

    let cfg_home = env._tmp.path().join("cfg_swap");
    let real_user_dir = cfg_home.join("systemd/user");
    fs::create_dir_all(&real_user_dir).unwrap();
    let real_unit = real_user_dir.join("agy-switch-cli.service");
    fs::write(&real_unit, "[Unit]\nDescription=InstalledUnit\n").unwrap();

    let swap_systemctl = env._tmp.path().join("swap_systemctl.sh");
    let script = format!(
        "#!/bin/sh\nif [ \"$2\" = \"disable\" ]; then\n  mv \"{real}\" \"{real}.moved\"\n  ln -s \"{victim}\" \"{real}\"\nfi\nexit 0\n",
        real = real_user_dir.display(),
        victim = victim_dir.display(),
    );
    fs::write(&swap_systemctl, script).unwrap();
    fs::set_permissions(&swap_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    let swap_uninst = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &swap_systemctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(
        swap_uninst.status.code(),
        Some(1),
        "Directory-to-symlink swap during disable --now MUST fail with exit 1: stdout={} stderr={}",
        String::from_utf8_lossy(&swap_uninst.stdout),
        String::from_utf8_lossy(&swap_uninst.stderr)
    );
    assert!(
        victim_unit.exists(),
        "CRITICAL: `daemon --uninstall` deleted victim file through swapped symlink!"
    );

    // 6. F2-02: Real PTY `tui` displays variable-name-only warning in status bar when ambient `HTTPS_PROXY` is malformed!
    #[cfg(feature = "tui")]
    {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::process::Stdio;

        let win = libc::winsize {
            ws_row: 24,
            ws_col: 140,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &win,
                )
            },
            0
        );
        let slave_out_fd = unsafe { libc::dup(slave_fd) };
        let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
        let slave_out = unsafe { fs::File::from_raw_fd(slave_out_fd) };
        let mut master = unsafe { fs::File::from_raw_fd(master_fd) };

        let mut tui_cmd = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        tui_cmd
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &env.home)
            .env("XDG_CACHE_HOME", &env.cache_dir)
            .env("XDG_RUNTIME_DIR", &env.runtime_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-bus", env.runtime_dir.display()),
            )
            .env(
                "HTTPS_PROXY",
                "badscheme://TUI_PROXY_SECRET_777@example.invalid:8080",
            )
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .args(["--data-dir", env.data_dir.to_str().unwrap(), "tui"])
            .stdin(Stdio::from(slave_in))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::piped());
        let mut child = tui_cmd.spawn().unwrap();
        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            let _ = libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let drain_pty = |m: &mut fs::File, acc_buf: &mut Vec<u8>| {
            let mut chunk = [0u8; 2048];
            while let Ok(n) = m.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                acc_buf.extend_from_slice(&chunk[..n]);
            }
        };
        let mut pty_buf = Vec::new();
        for _ in 0..40 {
            drain_pty(&mut master, &mut pty_buf);
            if String::from_utf8_lossy(&pty_buf).contains("Headless SSH Dashboard") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        master.write_all(b"r").unwrap();
        for _ in 0..60 {
            drain_pty(&mut master, &mut pty_buf);
            if String::from_utf8_lossy(&pty_buf).contains("HTTPS_PROXY") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        master.write_all(b"q").unwrap();
        let st = child.wait().unwrap();
        assert_eq!(st.code(), Some(0));
        drain_pty(&mut master, &mut pty_buf);
        let pty_txt = String::from_utf8_lossy(&pty_buf);
        assert!(
            pty_txt.contains("HTTPS_PROXY"),
            "Expected TUI status bar to surface variable-name-only proxy warning, got:\n{pty_txt}"
        );
        assert!(
            !pty_txt.contains("TUI_PROXY_SECRET_777"),
            "Leaked malformed proxy secret in TUI output!"
        );
    }
}

#[cfg(feature = "secret-service-backend")]
#[test]
fn synthetic_v120_signoff_round2_disk_external_cas_alias_err_missing_col_delete_tx_and_cross_scope()
{
    use std::process::Stdio;

    if !std::path::Path::new("/usr/bin/dbus-daemon").exists()
        || !std::path::Path::new("/usr/bin/python3").exists()
    {
        return;
    }
    let probe_py = Command::new("/usr/bin/python3")
        .args(["-c", "import dbus, gi, cryptography"])
        .status();
    if !probe_py.is_ok_and(|s| s.success()) {
        return;
    }

    let env = IsolatedEnv::new();
    let now = agy_switch_cli::domain::clock::current_unix_seconds();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-s1", "alice@example.com", now);
    let acc2 = sample_account("acc-s2", "bob@example.com", now);
    let acc_ext_disk = sample_account("acc-ext-disk", "charlie@example.com", now);
    let acc_ext_kr = sample_account("acc-ext-kr", "dana@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    let payload_1 =
        agy_switch_cli::session::payload::serialize_session_payload(&acc1.token).unwrap();
    let payload_ext_disk =
        agy_switch_cli::session::payload::serialize_session_payload(&acc_ext_disk.token).unwrap();
    let payload_ext_kr =
        agy_switch_cli::session::payload::serialize_session_payload(&acc_ext_kr.token).unwrap();

    fs::create_dir_all(&env.paths().active_slot_dir).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_dir,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    // 0. F1-05: Stalling local socket respects tight `< 2300ms` wall-clock cap; non-canonical `..` path falls back to `file`!
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
        "Auto D-Bus probe exceeded 1500ms+spawn budget: {stall_elapsed:?}"
    );

    let bus_sock = env.runtime_dir.join("r2-secrets.sock");
    let bus_addr = format!("unix:path={}", bus_sock.display());
    let dbus_proc = Command::new("/usr/bin/dbus-daemon")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--session",
            &format!("--address={bus_addr}"),
            "--nofork",
            "--nopidfile",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let dbus_pid = dbus_proc.id();
    for _ in 0..50 {
        if bus_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(bus_sock.exists());

    let ctrl_file = env._tmp.path().join("r2_ctrl.json");
    let stats_file = env._tmp.path().join("r2_stats.json");
    let ready_file = env._tmp.path().join("r2_ready");
    let mock_py = env._tmp.path().join("r2_mock_ss.py");

    let write_ctrl = |val: serde_json::Value| {
        std::thread::sleep(std::time::Duration::from_millis(15));
        fs::write(&ctrl_file, serde_json::to_vec(&val).unwrap()).unwrap();
    };
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
    }));

    let py_code = r#"
import json, os, sys
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CTRL_PATH, STATS_PATH, READY_PATH = sys.argv[1], sys.argv[2], sys.argv[3]
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
LOGIN_PATH = "/org/freedesktop/secrets/collection/login"
DEFAULT_PATH = "/org/freedesktop/secrets/collection/custom_default"

state = {"sessions": {}, "items": {}, "next_id": 1, "ctrl_mtime": 0.0, "delete_calls": 0, "create_calls": 0}

def dump_stats():
    by_col = {"login": [], "default": [], "delete_calls": state["delete_calls"], "create_calls": state["create_calls"]}
    for p, it in state["items"].items():
        s = it["secret"].decode("utf-8", "replace")
        if it["col"] == LOGIN_PATH:
            by_col["login"].append(s)
        else:
            by_col["default"].append(s)
    with open(STATS_PATH, "w", encoding="utf-8") as f:
        json.dump(by_col, f)

def load_ctrl():
    st = os.stat(CTRL_PATH)
    with open(CTRL_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if st.st_mtime > state["ctrl_mtime"]:
        state["ctrl_mtime"] = st.st_mtime
        if cfg.get("reseed"):
            state["delete_calls"] = 0
            state["create_calls"] = 0
            for p, it in list(state["items"].items()):
                it["obj"].remove_from_connection()
                state["items"].pop(p, None)
            attrs = {"service": "gemini", "username": "antigravity"}
            for key, cpath in [("login", LOGIN_PATH), ("default", DEFAULT_PATH)]:
                val = cfg.get(key)
                if val is not None:
                    iid = state["next_id"]
                    state["next_id"] += 1
                    ipath = f"{cpath}/i{iid}"
                    obj = ItemObj(bus, ipath)
                    state["items"][ipath] = {"obj": obj, "col": cpath, "attrs": dict(attrs), "secret": val.encode("utf-8")}
            dump_stats()
    return cfg

def aes_encrypt(key, data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, enc.update(padded) + enc.finalize()

def aes_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

class SessionObj(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Session", in_signature="", out_signature="")
    def Close(self):
        pass

class ItemObj(dbus.service.Object):
    def __init__(self, conn, path):
        super().__init__(conn, path)
        self.path = path
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        load_ctrl()
        it = state["items"][self.path]
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Attributes":
            return dbus.Dictionary(it["attrs"], signature="ss", variant_level=1)
        return dbus.String("item", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        load_ctrl()
        it = state["items"][self.path]
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Attributes": dbus.Dictionary(it["attrs"], signature="ss", variant_level=1),
            "Label": dbus.String("Antigravity", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session_path):
        load_ctrl()
        key = state["sessions"][str(session_path)]
        iv, ct = aes_encrypt(key, state["items"][self.path]["secret"])
        return (session_path, dbus.ByteArray(iv), dbus.ByteArray(ct), "text/plain")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="", out_signature="o")
    def Delete(self):
        cfg = load_ctrl()
        state["delete_calls"] += 1
        fail_del = int(cfg.get("fail_delete_from_call", -1))
        if fail_del >= 0 and state["delete_calls"] >= fail_del:
            dump_stats()
            raise dbus.DBusException("simulated Delete failure on second collection")
        state["items"].pop(self.path, None)
        self.remove_from_connection()
        dump_stats()
        return dbus.ObjectPath("/")

class CollectionObj(dbus.service.Object):
    def __init__(self, conn, path, label):
        self.path = path
        self.label = label
        super().__init__(conn, self.path)
    def my_items(self):
        return [p for p, it in state["items"].items() if it["col"] == self.path]
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        load_ctrl()
        if prop == "Locked":
            return dbus.Boolean(False, variant_level=1)
        if prop == "Items":
            return dbus.Array([dbus.ObjectPath(p) for p in self.my_items()], signature="o", variant_level=1)
        return dbus.String(self.label, variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        load_ctrl()
        return dbus.Dictionary({
            "Locked": dbus.Boolean(False, variant_level=1),
            "Items": dbus.Array([dbus.ObjectPath(p) for p in self.my_items()], signature="o", variant_level=1),
            "Label": dbus.String(self.label, variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        load_ctrl()
        req = {str(k): str(v) for k, v in attrs.items()}
        return [
            dbus.ObjectPath(p)
            for p, it in state["items"].items()
            if it["col"] == self.path and all(it["attrs"].get(k) == v for k, v in req.items())
        ]
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        cfg = load_ctrl()
        state["create_calls"] += 1
        if cfg.get("exit_provider_on_create"):
            os._exit(1)
        kill_pid = int(cfg.get("kill_dbus_on_create_pid", 0))
        if kill_pid > 0:
            os.kill(kill_pid, 9)
            os._exit(1)
        fail_cr = int(cfg.get("fail_create_from_call", -1))
        if fail_cr >= 0 and state["create_calls"] >= fail_cr:
            dump_stats()
            raise dbus.DBusException("simulated CreateItem failure")
        sess_path, iv, ct, _ = secret
        key = state["sessions"][str(sess_path)]
        raw = aes_decrypt(key, bytes(iv), bytes(ct))
        attrs = {str(k): str(v) for k, v in props.get("org.freedesktop.Secret.Item.Attributes", {}).items()}
        if bool(replace):
            for p, it in list(state["items"].items()):
                if it["col"] == self.path and it["attrs"] == attrs:
                    it["secret"] = raw
                    dump_stats()
                    return (dbus.ObjectPath(p), dbus.ObjectPath("/"))
        iid = state["next_id"]
        state["next_id"] += 1
        ipath = f"{self.path}/i{iid}"
        obj = ItemObj(bus, ipath)
        state["items"][ipath] = {"obj": obj, "col": self.path, "attrs": attrs, "secret": raw}
        dump_stats()
        return (dbus.ObjectPath(ipath), dbus.ObjectPath("/"))

class ServiceObj(dbus.service.Object):
    def __init__(self, conn):
        super().__init__(conn, "/org/freedesktop/secrets")
    def visible_cols(self):
        cfg = load_ctrl()
        if cfg.get("hide_default"):
            return [dbus.ObjectPath(LOGIN_PATH)]
        return [dbus.ObjectPath(LOGIN_PATH), dbus.ObjectPath(DEFAULT_PATH)]
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        if prop == "Collections":
            return dbus.Array(self.visible_cols(), signature="o", variant_level=1)
        return dbus.Array([], signature="o", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return dbus.Dictionary({
            "Collections": dbus.Array(self.visible_cols(), signature="o", variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algo, inp):
        load_ctrl()
        sid = len(state["sessions"]) + 1
        spath = f"/org/freedesktop/secrets/session/s{sid}"
        SessionObj(bus, spath)
        peer_pub = int.from_bytes(bytes(inp), "big")
        priv = int.from_bytes(os.urandom(32), "big") | 1
        pub = pow(2, priv, DH_PRIME)
        shared = pow(peer_pub, priv, DH_PRIME)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"").derive(shared.to_bytes(128, "big"))
        state["sessions"][spath] = aes_key
        return (dbus.ByteArray(pub.to_bytes(128, "big")), dbus.ObjectPath(spath))
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        cfg = load_ctrl()
        if name == "default" and cfg.get("fail_read_alias"):
            raise dbus.DBusException("simulated ReadAlias D-Bus failure")
        if name == "default" and cfg.get("hide_default"):
            return dbus.ObjectPath("/")
        if name == "login":
            return dbus.ObjectPath(LOGIN_PATH)
        if name == "default":
            return dbus.ObjectPath(DEFAULT_PATH)
        return dbus.ObjectPath("/")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        return (objects, dbus.ObjectPath("/"))

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus_name = dbus.service.BusName("org.freedesktop.secrets", bus)
svc = ServiceObj(bus)
col_login = CollectionObj(bus, LOGIN_PATH, "login")
col_default = CollectionObj(bus, DEFAULT_PATH, "custom_default")
load_ctrl()
with open(READY_PATH, "w", encoding="utf-8") as rf:
    rf.write("ready")
GLib.MainLoop().run()
"#;
    fs::write(&mock_py, py_code).unwrap();

    let py_proc = Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args([
            mock_py.to_str().unwrap(),
            ctrl_file.to_str().unwrap(),
            stats_file.to_str().unwrap(),
            ready_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    struct CleanupR2(std::process::Child, std::process::Child);
    impl Drop for CleanupR2 {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = self.1.kill();
            let _ = self.1.wait();
        }
    }
    let _guard = CleanupR2(py_proc, dbus_proc);

    for _ in 0..80 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(ready_file.exists());

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

    // 1. F0-02a (exact reviewer reproducer!):
    //    Abort dual-write at `SlotCommitting` (`before_write:antigravity-oauth-token:abort` after keyring updated?
    //    No: abort at `after_token_refreshed:*:abort` or `before_write:antigravity-oauth-token:abort` while resetting keyring to `acc-s1`!),
    //    place valid un-stored 3rd credential `acc-ext-disk` ON DISK while keyring holds `acc-s1`!
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

    // Keyring is reset to old state (`acc-s1`), while disk gets external 3rd credential (`acc-ext-disk`)!
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
    }));
    fs::write(&env.paths().active_slot_file, &payload_ext_disk).unwrap();

    // Read-only `status` MUST exit 7
    let ro_st = bus_cmd().args(["--json", "status"]).output().unwrap();
    assert_eq!(ro_st.status.code(), Some(7));

    // F0-02b: Inject `ReadAlias("default")` error -> BOTH `status` and write self-healing MUST preserve journal and exit 7!
    write_ctrl(serde_json::json!({
        "reseed": false,
        "fail_read_alias": true,
    }));
    let alias_fix = bus_cmd()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(alias_fix.status.code(), Some(7));
    assert!(env.paths().switch_journal_file().exists());

    // F0-02c: Hide `custom_default` collection -> BOTH `status` and write self-healing MUST detect missing recorded collection and exit 7!
    write_ctrl(serde_json::json!({
        "reseed": false,
        "fail_read_alias": false,
        "hide_default": true,
    }));
    let hide_fix = bus_cmd()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(hide_fix.status.code(), Some(7));
    assert!(env.paths().switch_journal_file().exists());

    // F0-02a conflict: Distinct external credentials (`acc-ext-disk` on disk AND `acc-ext-kr` in `custom_default`!)
    // -> write self-healing MUST refuse automatic overwrite, preserve journal, and exit 7!
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_ext_kr,
    }));
    let conflict_fix = bus_cmd()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        conflict_fix.status.code(),
        Some(7),
        "Conflicting external credentials MUST NOT be overwritten automatically!"
    );
    assert!(env.paths().switch_journal_file().exists());
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        payload_ext_disk
    );

    // Now restore keyring to old state (`acc-s1` in both collections) while disk has `acc-ext-disk`:
    // pre-write self-healing MUST exit 0 and PRESERVE `acc-ext-disk` across disk AND both keyring collections!
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
    }));
    let disk_ext_fix = bus_cmd()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        disk_ext_fix.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&disk_ext_fix.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    let final_disk = fs::read_to_string(&env.paths().active_slot_file).unwrap();
    assert_eq!(
        final_disk, payload_ext_disk,
        "CRITICAL: pre-write self-healing clobbered valid external disk credential!"
    );
    let st_after_ext: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st_after_ext["login"][0].as_str().unwrap(), payload_ext_disk);
    assert_eq!(
        st_after_ext["default"][0].as_str().unwrap(),
        payload_ext_disk
    );

    // 2. F0-02d: Legacy journal without `"replica_state"` refused under `file` and `keyring`, repaired under `dual`!
    let legacy_j = serde_json::json!({
        "schema_version": 1,
        "operation_id": "op-legacy-dual",
        "phase": "slot_committing",
        "prev_selected_account_id": "acc-s1",
        "target_account_id": "acc-s2",
        "prev_slot_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes()),
        "target_slot_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes()),
        "token_rotated": false,
        "started_at": now,
        "updated_at": now,
    });
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": serde_json::Value::Null,
    }));
    fs::write(
        env.paths().switch_journal_file(),
        serde_json::to_vec_pretty(&legacy_j).unwrap(),
    )
    .unwrap();

    assert_eq!(
        bus_cmd()
            .args([
                "--backend",
                "file",
                "--json",
                "policy",
                "set",
                "--reserve",
                "10"
            ])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );
    assert_eq!(
        bus_cmd()
            .args([
                "--backend",
                "keyring",
                "--json",
                "policy",
                "set",
                "--reserve",
                "10"
            ])
            .output()
            .unwrap()
            .status
            .code(),
        Some(7)
    );
    assert!(env.paths().switch_journal_file().exists());

    let dual_legacy_fix = bus_cmd()
        .args([
            "--backend",
            "dual",
            "--json",
            "policy",
            "set",
            "--reserve",
            "10",
        ])
        .output()
        .unwrap();
    assert_eq!(dual_legacy_fix.status.code(), Some(0));
    assert!(!env.paths().switch_journal_file().exists());

    // 3. F0-02f: `auto` (`dual`) write self-healing repairing a `keyring`-only journal MUST NOT delete
    //    local `.tmp.` files or read/fail on a corrupt local `antigravity-oauth-token`!
    let stray_tmp = env
        .paths()
        .active_slot_dir
        .join("antigravity-oauth-token.tmp.keep-me");
    fs::write(&stray_tmp, b"partial-local").unwrap();
    fs::write(&env.paths().active_slot_file, b"{corrupt-local-disk-json").unwrap();
    write_ctrl(serde_json::json!({
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
                "prev_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes()),
                "prev_uniform": true,
                "collections": [
                    {
                        "path": "/org/freedesktop/secrets/collection/login",
                        "prev_present": true,
                        "prev_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes())
                    },
                    {
                        "path": "/org/freedesktop/secrets/collection/custom_default",
                        "prev_present": true,
                        "prev_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes())
                    }
                ]
            },
            "file": {
                "prev_present": false,
                "prev_uniform": true
            }
        }
    });
    fs::write(
        env.paths().switch_journal_file(),
        serde_json::to_vec_pretty(&kr_only_j).unwrap(),
    )
    .unwrap();

    let scoped_fix = bus_cmd()
        .args(["--json", "policy", "set", "--reserve", "10"])
        .output()
        .unwrap();
    assert_eq!(
        scoped_fix.status.code(),
        Some(0),
        "Repairing keyring-only journal under auto/dual MUST NOT fail on corrupt local file: stderr={}",
        String::from_utf8_lossy(&scoped_fix.stderr)
    );
    assert!(
        stray_tmp.exists(),
        "Repairing keyring-only journal MUST NOT delete local slot .tmp. files!"
    );
    assert_eq!(
        fs::read(&env.paths().active_slot_file).unwrap(),
        b"{corrupt-local-disk-json"
    );

    // 4. F1-07: `--backend keyring accounts delete acc-s1 --force --clear-active-slot` multi-collection transaction!
    fs::remove_dir_all(env.home.join(".gemini")).unwrap();
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": payload_1,
        "default": payload_1,
        "fail_delete_from_call": 2,
    }));

    // 4a. Second collection `Delete` fails, rollback `CreateItem` succeeds -> exits 8, restores `login`, keeps `acc-s1`, zero local files!
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
    let st_del_rb: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st_del_rb["login"].as_array().unwrap().len(), 1);
    assert_eq!(st_del_rb["default"].as_array().unwrap().len(), 1);

    // 4b. Second collection `Delete` fails AND rollback `CreateItem` fails -> preserves journal (`RecoveryIncomplete`), exits 7!
    write_ctrl(serde_json::json!({
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
    assert_eq!(
        del_partial.status.code(),
        Some(7),
        "Partial multi-collection delete failure MUST preserve journal and exit 7: stderr={}",
        String::from_utf8_lossy(&del_partial.stderr)
    );
    assert!(env.paths().switch_journal_file().exists());
    assert!(!env.home.join(".gemini").exists());

    // Clear fault and run `--backend keyring policy set`: completes clearing both collections + deleting `acc-s1` with zero local file access!
    write_ctrl(serde_json::json!({
        "reseed": false,
        "fail_delete_from_call": -1,
        "fail_create_from_call": -1,
    }));
    let fix_del = bus_cmd()
        .args([
            "--backend",
            "keyring",
            "--json",
            "policy",
            "set",
            "--reserve",
            "10",
        ])
        .output()
        .unwrap();
    assert_eq!(
        fix_del.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&fix_del.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    assert!(!env.paths().account_file("acc-s1").exists());
    assert!(!env.home.join(".gemini").exists());
    let st_del_done: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st_del_done["login"].as_array().unwrap().len(), 0);
    assert_eq!(st_del_done["default"].as_array().unwrap().len(), 0);

    // 4c. R3-01: Corrupt `switch_journal.json` has unknown backend/collection/intent scope and MUST NEVER
    //     be auto-cleared under `file` OR `dual` (preserves journal and returns exit 7)!
    let acc_s1_re = sample_account("acc-s1", "alice@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_s1_re.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    let payload_2 =
        agy_switch_cli::session::payload::serialize_session_payload(&acc2.token).unwrap();
    fs::create_dir_all(&env.paths().active_slot_dir).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_dir,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    fs::set_permissions(
        &env.paths().active_slot_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    write_ctrl(serde_json::json!({
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
                "policy",
                "set",
                "--reserve",
                "10",
            ])
            .output()
            .unwrap();
        assert_eq!(
            corrupt_j_fix.status.code(),
            Some(7),
            "Corrupt journal MUST preserve journal and exit 7 under `{backend_name}`: stderr={}",
            String::from_utf8_lossy(&corrupt_j_fix.stderr)
        );
        assert!(
            env.paths().switch_journal_file().exists(),
            "Corrupt journal was wrongly cleared under `{backend_name}`!"
        );
    }
    fs::remove_file(env.paths().switch_journal_file()).unwrap();

    // 4c-bis. Live dual multi-collection `clear_slot_intent` at `CommittedIndexPending` + external
    //         credential appearing on disk ONLY (Case B): replay MUST sync the external credential
    //         across both keyring collections via CAS AND finish Stage 2 deletion of `acc-s1`!
    fs::write(&env.paths().active_slot_file, &payload_1).unwrap();
    write_ctrl(serde_json::json!({
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
    // External credential written to disk only while keyring collections stay empty -> Case B!
    let ext_acc = sample_account("acc-ext-dbus", "external-dbus@example.com", now);
    let ext_payload =
        agy_switch_cli::session::payload::serialize_session_payload(&ext_acc.token).unwrap();
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
            "policy",
            "set",
            "--reserve",
            "10",
        ])
        .output()
        .unwrap();
    assert_eq!(
        dual_case_b_fix.status.code(),
        Some(0),
        "Dual Case B clear-slot replay with external disk credential must succeed: stderr={}",
        String::from_utf8_lossy(&dual_case_b_fix.stderr)
    );
    assert!(!env.paths().switch_journal_file().exists());
    assert!(
        !env.paths().account_file("acc-s1").exists(),
        "Dual Case B replay MUST finish Stage 2 deletion of `acc-s1`!"
    );
    assert_eq!(
        fs::read_to_string(&env.paths().active_slot_file).unwrap(),
        ext_payload
    );
    let st_case_b: serde_json::Value =
        serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(st_case_b["login"].as_array().unwrap().len(), 1);
    assert_eq!(st_case_b["default"].as_array().unwrap().len(), 1);
    // Re-seed `acc-s1` for step 4d below
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_s1_re.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    fs::remove_dir_all(env.home.join(".gemini")).unwrap();
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": serde_json::Value::Null,
        "default": serde_json::Value::Null,
    }));

    // 4d. `switch --dry-run` with a `CommittedIndexPending` `clear_slot_intent` journal MUST pass (`0`), not exit 7!
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
                "prev_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes()),
                "prev_uniform": true,
                "collections": [
                    {
                        "path": "/org/freedesktop/secrets/collection/login",
                        "prev_present": true,
                        "prev_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes())
                    },
                    {
                        "path": "/org/freedesktop/secrets/collection/custom_default",
                        "prev_present": true,
                        "prev_digest": agy_switch_cli::session::payload::bytes_sha256_hex(payload_1.as_bytes())
                    }
                ]
            },
            "file": {
                "prev_present": false,
                "prev_uniform": true
            }
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
    assert_eq!(
        dry_clear.status.code(),
        Some(0),
        "switch --dry-run on CommittedIndexPending clear_slot_intent must exit 0: stderr={}",
        String::from_utf8_lossy(&dry_clear.stderr)
    );
    fs::remove_file(env.paths().switch_journal_file()).unwrap();

    // 5a. F1-05: Secret Service provider crashing (`os._exit(1)`) mid-`CreateItem` while `dbus-daemon` stays alive
    //     (`org.freedesktop.DBus.Error.NoReply`!) MUST preserve journal (`RecoveryIncomplete`) and exit 7!
    write_ctrl(serde_json::json!({
        "reseed": false,
        "exit_provider_on_create": true,
    }));
    let noreply_sw = bus_cmd()
        .args(["--backend", "keyring", "--json", "switch", "acc-s2"])
        .output()
        .unwrap();
    assert_eq!(
        noreply_sw.status.code(),
        Some(7),
        "Provider crash (`NoReply` with live dbus-daemon) mid-CreateItem MUST exit 7: stderr={}",
        String::from_utf8_lossy(&noreply_sw.stderr)
    );
    assert!(
        env.paths().switch_journal_file().exists(),
        "Journal MUST be preserved when Secret Service provider crashes with NoReply mid-CreateItem!"
    );
    fs::remove_file(env.paths().switch_journal_file()).unwrap();

    // Respawn `mock_py` on the still-live `dbus-daemon` and also test full bus socket drop (`InputOutput`)!
    let _ = fs::remove_file(&ready_file);
    write_ctrl(serde_json::json!({
        "reseed": true,
        "login": serde_json::Value::Null,
        "default": serde_json::Value::Null,
        "exit_provider_on_create": false,
    }));
    let mut py_proc2 = Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args([
            mock_py.to_str().unwrap(),
            ctrl_file.to_str().unwrap(),
            stats_file.to_str().unwrap(),
            ready_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..80 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(ready_file.exists());

    // 5b. F1-05: Transport drop mid-`CreateItem` (uncertain write outcome!) MUST preserve journal (`RecoveryIncomplete`) and exit 7!
    write_ctrl(serde_json::json!({
        "reseed": false,
        "kill_dbus_on_create_pid": dbus_pid,
    }));
    let drop_sw = bus_cmd()
        .args(["--backend", "keyring", "--json", "switch", "acc-s2"])
        .output()
        .unwrap();
    let _ = py_proc2.kill();
    let _ = py_proc2.wait();
    assert_eq!(
        drop_sw.status.code(),
        Some(7),
        "Uncertain D-Bus transport drop mid-CreateItem MUST exit 7 (NOT rolled-back exit 8): stderr={}",
        String::from_utf8_lossy(&drop_sw.stderr)
    );
    assert!(
        env.paths().switch_journal_file().exists(),
        "Journal MUST be preserved when D-Bus transport drops mid-write!"
    );
}

#[test]
fn synthetic_v120_status_probe_stats_list_streaming_refresh_and_tui_reorder_delete() {
    use agy_switch_cli::domain::quota::{PrimaryModelQuota, QuotaBucket, QuotaGroup};

    let env = IsolatedEnv::new();
    let slot_dir = env.init_agy_slot_dir();
    let _ = &slot_dir;
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());

    // Seed 2 accounts:
    // - `acc-starter` (`alice@example.com`): Free tier `"Antigravity Starter Quota"` WITHOUT a `5h` bucket
    // - `acc-pro` (`bob@example.com`): `"Google AI Pro"` WITH both `weekly` and `5h` buckets
    let mut acc_starter = sample_account("acc-starter", "alice@example.com", now);
    acc_starter.custom_label = None;
    {
        let qs = acc_starter.quota.as_mut().unwrap();
        qs.forbidden_reason = None;
        qs.subscription_tier = Some("Antigravity Starter Quota".into());
        qs.tier_source_env = Some(QuotaSourceEnv::Production);
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
        qp.subscription_tier = Some("Google AI Pro".into());
        qp.tier_source_env = Some(QuotaSourceEnv::Production);
        qp.models[0].primary_quota = Some(PrimaryModelQuota {
            remaining_fraction: Some(0.85),
            reset_time: "2099-11-23T14:45:00Z".into(),
        });
    }

    let mut pol = repo.read_policy().unwrap();
    let prev = pol.revision;
    pol.candidate_account_ids = vec!["acc-starter".into(), "acc-pro".into()];
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_starter.clone(), true, now)?;
        tx.upsert_account(acc_pro.clone(), false, now)?;
        tx.save_policy(&mut pol, Some(prev), now)?;
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
        st_txt.contains("Official agy:")
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
    let bad_env_strat = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_STRATEGY", "round_robin")
        .args(["--json", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(bad_env_strat.status.code(), Some(2));

    // 2. Plan display scope: `accounts list`, `current`, `quota` preserve `"Antigravity Starter Quota"` verbatim,
    //    AND `policy eval --json` treats `"Antigravity Starter Quota"` without a `5h` bucket as `eligible`!
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
            txt.contains("Antigravity Starter Quota"),
            "Expected verbatim `Antigravity Starter Quota` in {cmd_args:?}, got:\n{txt}"
        );
    }
    let eval_out = env
        .cli_cmd()
        .args(["--json", "policy", "eval"])
        .output()
        .unwrap();
    assert_eq!(eval_out.status.code(), Some(0));
    let eval_j: serde_json::Value = serde_json::from_slice(&eval_out.stdout).unwrap();
    assert_eq!(eval_j["evaluation"]["source_evaluation"]["status"], "known");
    assert_eq!(
        eval_j["evaluation"]["source_evaluation"]["remaining_percentage"],
        75.0
    );

    // 3. `stats summary --recent` + `stats list` (live + archive rows, 99% Hit% cap, zero path/email leaks)
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

        let make_blob = |in_t: u64, cache_t: u64, out_t: u64, ts: u64| -> Vec<u8> {
            let usage = [
                pb_v(1, in_t),
                pb_v(3, out_t),
                pb_v(5, cache_t),
                pb_v(10, out_t),
            ]
            .concat();
            let timing = pb_b(4, &pb_v(1, ts));
            let ttft = pb_v(1, 15);
            let stream = pb_v(1, 44);
            let wrapped = [
                pb_b(4, &usage),
                pb_b(9, &timing),
                pb_b(11, &ttft),
                pb_b(12, &stream),
                pb_b(19, b"gemini-4-carbon"),
                pb_b(21, b"Gemini 4 Carbon (High)"),
            ]
            .concat();
            pb_b(1, &wrapped)
        };

        let live_db = cli_conv.join("live_conv.db");
        let lconn = rusqlite::Connection::open(&live_db).unwrap();
        lconn
            .execute_batch(
                "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        let step_done = pb_b(20, &[pb_b(1, b"done"), pb_v(12, 2)].concat());
        lconn
            .execute(
                "INSERT INTO steps VALUES (1, 15, ?1, 3, ?2)",
                rusqlite::params![pb_b(1, &pb_v(1, ts_live)), &step_done],
            )
            .unwrap();
        // 3_000 uncached + 584_100 cached = 99.489% -> MUST cap at `99%`, never `100%`!
        lconn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_blob(3_000, 584_100, 3_432, ts_live)],
            )
            .unwrap();
        drop(lconn);

        let app_dir = env.home.join(".gemini/antigravity");
        fs::create_dir_all(&app_dir).unwrap();
        let arch_db = app_dir.join("token_usage_archive.db");
        let aconn = rusqlite::Connection::open(&arch_db).unwrap();
        aconn
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                    model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                    total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER
                 );",
            )
            .unwrap();
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

    // 4. Real-time subprocess streaming `refresh --all`: `[1/2]` flushes BEFORE connection #1 finishes!
    {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        };

        let stream_env = IsolatedEnv::new();
        let stream_repo = StoreRepository::new(stream_env.paths());
        let mut s1 = sample_account("acc-slow", "alice@example.com", now);
        s1.token.expiry_timestamp = 1;
        let mut s2 = sample_account("acc-fast", "bob@example.com", now);
        s2.token.expiry_timestamp = 1;
        stream_repo
            .with_write_lock(|tx| {
                tx.upsert_account(s1, true, now)?;
                tx.upsert_account(s2, false, now)
            })
            .unwrap();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let conn_seq = Arc::new(AtomicUsize::new(0));
        let release_first = Arc::new(Barrier::new(2));
        let seq_bg = conn_seq.clone();
        let rel_bg = release_first.clone();

        let proxy_thread = std::thread::spawn(move || {
            let mut held_first = None;
            for stream_res in proxy_listener.incoming() {
                let Ok(mut stream) = stream_res else {
                    break;
                };
                let idx = seq_bg.fetch_add(1, Ordering::SeqCst);
                if idx == 0 {
                    // Hold connection #1 open until main thread reads `[1/2]` from child stderr!
                    let mut hold_thread_stream = stream;
                    let rel_c = rel_bg.clone();
                    held_first = Some(std::thread::spawn(move || {
                        rel_c.wait();
                        let _ = hold_thread_stream.write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }));
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
                if idx >= 3 {
                    break;
                }
            }
            if let Some(h) = held_first {
                let _ = h.join();
            }
        });

        let mut child = stream_env
            .cli_cmd()
            .args([
                "--proxy",
                &format!("http://127.0.0.1:{proxy_port}"),
                "refresh",
                "--all",
                "--concurrency",
                "2",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stderr_reader = BufReader::new(child.stderr.take().unwrap());
        let mut first_progress_line = String::new();
        stderr_reader.read_line(&mut first_progress_line).unwrap();
        assert!(
            first_progress_line.starts_with("[1/2] Failed "),
            "Expected `[1/2]` progress line BEFORE releasing blocked connection #1, got: {first_progress_line:?}"
        );
        // Release blocked connection #1 only AFTER `[1/2]` has already streamed!
        release_first.wait();

        let mut rest_stderr = String::new();
        std::io::Read::read_to_string(&mut stderr_reader, &mut rest_stderr).unwrap();
        let wait_st = child.wait().unwrap();
        assert_eq!(wait_st.code(), Some(1));
        assert!(
            rest_stderr.contains("[2/2] Failed "),
            "Expected `[2/2]` progress line after releasing connection #1, got: {rest_stderr:?}"
        );
        drop(proxy_thread);
    }

    // 5. Real PTY TUI: `Free` abbreviation for `Antigravity Starter Quota`, `↑/↓` select, `[/]` reorder,
    //    `k/j/K/J` no-op, `x` + `Esc` cancel, and `x` + `y` active-account deletion + slot clear!
    #[cfg(feature = "tui")]
    {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::time::Duration;

        let win = libc::winsize {
            ws_row: 20,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &win,
                )
            },
            0
        );
        let slave_out_fd = unsafe { libc::dup(slave_fd) };
        let inspect_fd = unsafe { libc::dup(slave_fd) };
        let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
        let slave_out = unsafe { fs::File::from_raw_fd(slave_out_fd) };
        let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_fd) };
        let mut master = unsafe { fs::File::from_raw_fd(master_fd) };

        let mut child = env
            .cli_cmd()
            .arg("tui")
            .stdin(Stdio::from(slave_in))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            let _ = libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let drain = |m: &mut fs::File, buf: &mut Vec<u8>| {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = m.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        };

        let mut screen = Vec::new();
        for _ in 0..50 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Manage : r/R refresh") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let init_screen = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            init_screen.contains("Free") && !init_screen.contains("Antigravity Starter Quota"),
            "TUI must abbreviate `Antigravity Starter Quota` to `Free`:\n{init_screen}"
        );
        assert!(init_screen.contains("Keys   : ↑/↓ select · g/G top/end · [/] reorder"));
        assert!(init_screen.contains("e/E enable · d/D disable · x delete"));

        // Verify `D` + `Esc` cancels disabling all accounts without quitting TUI,
        // `D` + `y` disables all 2 accounts, and `E` re-enables all 2 accounts immediately!
        screen.clear();
        master.write_all(b"D").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Disable all 2 account(s)?") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(String::from_utf8_lossy(&screen).contains("Disable all 2 account(s)?"));

        screen.clear();
        master.write_all(b"\x1b").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Canceled disabling all accounts.") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            repo.read_snapshot()
                .unwrap()
                .accounts
                .iter()
                .all(|a| !a.disabled),
            "Esc must cancel `D` without disabling any account"
        );

        master.write_all(b"Dy").unwrap();
        master.flush().unwrap();
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

        master.write_all(b"E").unwrap();
        master.flush().unwrap();
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

        // Verify removed `j`/`k`/`J`/`K` AND modifier sequences (`Alt+[` `\x1b[`, `Alt+d` `\x1bd`)
        // do NOT reorder, move cursor, or disable accounts, then press `]` to move `acc-starter` down!
        master.write_all(b"\x1bd").unwrap();
        master.flush().unwrap();
        std::thread::sleep(Duration::from_millis(60));
        master.write_all(b"Jk]").unwrap();
        master.flush().unwrap();
        for _ in 0..50 {
            if repo.read_snapshot().is_ok_and(|s| {
                s.index.account_order == vec!["acc-pro".to_string(), "acc-starter".to_string()]
            }) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let ids_after_right_bracket = repo.read_snapshot().unwrap().index.account_order;
        assert_eq!(
            ids_after_right_bracket,
            vec!["acc-pro".to_string(), "acc-starter".to_string()]
        );

        // Cursor followed `acc-starter` (the active `*` account!) to row #2.
        // Press `x` then `Esc` (`\x1b`) -> cancels delete without quitting TUI or deleting `acc-starter`!
        screen.clear();
        master.write_all(b"x").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("clear active agy slot") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(String::from_utf8_lossy(&screen).contains("clear active agy slot"));

        screen.clear();
        master.write_all(b"\x1b").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Canceled account deletion.") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("Canceled account deletion."),
            "Expected cancel notice on Esc, got:\n{}",
            String::from_utf8_lossy(&screen)
        );
        assert!(!repo.read_account_unchecked("acc-starter").unwrap().disabled);
        assert!(repo.paths().account_file("acc-starter").exists());
        assert!(slot_dir.join("antigravity-oauth-token").exists());

        // Now press `x` then `y` -> deletes active `acc-starter`, clears active slot, removes from policy candidates, then `q` quits!
        master.write_all(b"xy").unwrap();
        master.flush().unwrap();
        for _ in 0..50 {
            if !repo.paths().account_file("acc-starter").exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!repo.paths().account_file("acc-starter").exists());
        assert!(
            !slot_dir.join("antigravity-oauth-token").exists(),
            "Deleting active account in TUI must clear active slot!"
        );
        let snap_after_del = repo.read_snapshot().unwrap();
        assert_eq!(snap_after_del.index.selected_account_id, None);
        assert_eq!(snap_after_del.accounts.len(), 1);
        assert_eq!(snap_after_del.accounts[0].id, "acc-pro");
        assert_eq!(
            repo.read_policy().unwrap().candidate_account_ids,
            vec!["acc-pro".to_string()]
        );

        master.write_all(b"q").unwrap();
        master.flush().unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(0));
        let mut post_term: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post_term) },
            0
        );
        assert_ne!(post_term.c_lflag & libc::ECHO, 0);
    }
}

#[test]
fn synthetic_v120_round3_systemd_identity_status_pgid_and_path_secret_order() {
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

    // 3. R3-05: `daemon --install` & `--uninstall` manager identity & mid-wait unit swap checks!
    let marker_dir = env._tmp.path().join("r3_sd_marker");
    fs::create_dir_all(&marker_dir).unwrap();
    let cfg_home = env._tmp.path().join("r3_xdg_cfg");
    fs::create_dir_all(&cfg_home).unwrap();
    let foreign_unit = env._tmp.path().join("foreign_agy.service");
    fs::write(&foreign_unit, "[Unit]\nDescription=Foreign\n").unwrap();

    // 3a. Swapping unit inode during `daemon-reload` -> `daemon --install` MUST fail (never report enabled_and_started=true)!
    let swap_install_ctl = env._tmp.path().join("systemctl_swap_install");
    fs::write(
        &swap_install_ctl,
        "#!/bin/sh\n\
         UNIT_FILE=\"$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"\n\
         if [ \"$2\" = \"daemon-reload\" ] && [ -f \"$UNIT_FILE\" ]; then\n\
           rm -f \"$UNIT_FILE\"\n\
           printf '[Unit]\\nDescription=Swapped\\n' > \"$UNIT_FILE\"\n\
         elif [ \"$2\" = \"show\" ]; then\n\
           printf 'FragmentPath=%s\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=active\\n' \"$UNIT_FILE\"\n\
         fi\n\
         exit 0\n",
    )
    .unwrap();
    fs::set_permissions(&swap_install_ctl, fs::Permissions::from_mode(0o755)).unwrap();

    let swapped_inst = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &swap_install_ctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(
        swapped_inst.status.code(),
        Some(1),
        "Unit inode swap during daemon-reload MUST fail install: stdout={} stderr={}",
        String::from_utf8_lossy(&swapped_inst.stdout),
        String::from_utf8_lossy(&swapped_inst.stderr)
    );

    // 3a-2. Overwriting unit file contents in-place (preserving inode) during `daemon-reload` MUST ALSO fail install!
    let overwrite_install_ctl = env._tmp.path().join("systemctl_overwrite_install");
    fs::write(
        &overwrite_install_ctl,
        "#!/bin/sh\n\
         UNIT_FILE=\"$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"\n\
         if [ \"$2\" = \"daemon-reload\" ] && [ -f \"$UNIT_FILE\" ]; then\n\
           printf '[Unit]\\nDescription=TamperedInPlace\\n' > \"$UNIT_FILE\"\n\
         elif [ \"$2\" = \"show\" ]; then\n\
           printf 'FragmentPath=%s\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=active\\n' \"$UNIT_FILE\"\n\
         fi\n\
         exit 0\n",
    )
    .unwrap();
    fs::set_permissions(&overwrite_install_ctl, fs::Permissions::from_mode(0o755)).unwrap();

    let overwritten_inst = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &overwrite_install_ctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(
        overwritten_inst.status.code(),
        Some(1),
        "In-place unit overwrite during daemon-reload MUST fail install: stdout={} stderr={}",
        String::from_utf8_lossy(&overwritten_inst.stdout),
        String::from_utf8_lossy(&overwritten_inst.stderr)
    );

    // 3b. Manager reports foreign FragmentPath on `show` -> `daemon --install` MUST fail
    //     BEFORE calling `enable --now` on the foreign shadowing unit!
    let enable_marker = env._tmp.path().join("enable_was_called");
    let foreign_show_ctl = env._tmp.path().join("systemctl_foreign_show");
    fs::write(
        &foreign_show_ctl,
        format!(
            "#!/bin/sh\n\
             if [ \"$2\" = \"enable\" ]; then\n\
               echo called > \"{}\"\n\
             elif [ \"$2\" = \"show\" ]; then\n\
               printf 'FragmentPath={}\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=active\\n'\n\
             fi\n\
             exit 0\n",
            enable_marker.display(),
            foreign_unit.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&foreign_show_ctl, fs::Permissions::from_mode(0o755)).unwrap();

    let foreign_inst = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &foreign_show_ctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(
        foreign_inst.status.code(),
        Some(1),
        "Foreign FragmentPath reported by manager MUST fail install"
    );
    assert!(
        !enable_marker.exists(),
        "Install MUST abort BEFORE calling `enable --now` when a foreign unit shadows our unit!"
    );

    // 3c. `daemon --uninstall` when local unit is ABSENT but manager reports a foreign loaded unit
    //     (with FragmentPath OR active/loaded with empty FragmentPath) MUST refuse to run `disable --now` and exit 1!
    let _ = fs::remove_file(cfg_home.join("systemd/user/agy-switch-cli.service"));
    let disable_marker = env._tmp.path().join("disable_was_called");
    let foreign_uninst_ctl = env._tmp.path().join("systemctl_foreign_uninst");
    fs::write(
        &foreign_uninst_ctl,
        format!(
            "#!/bin/sh\n\
             if [ \"$2\" = \"disable\" ]; then\n\
               echo called > \"{}\"\n\
             elif [ \"$2\" = \"show\" ]; then\n\
               printf 'FragmentPath={}\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=active\\n'\n\
             fi\n\
             exit 0\n",
            disable_marker.display(),
            foreign_unit.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&foreign_uninst_ctl, fs::Permissions::from_mode(0o755)).unwrap();

    let foreign_uninst = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &foreign_uninst_ctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(
        foreign_uninst.status.code(),
        Some(1),
        "Uninstall must refuse when local unit is absent but manager loads a foreign unit"
    );
    assert!(
        !disable_marker.exists(),
        "Uninstall must NOT call `disable --now` on a foreign unit!"
    );

    let active_no_frag_ctl = env._tmp.path().join("systemctl_active_no_frag");
    fs::write(
        &active_no_frag_ctl,
        "#!/bin/sh\n\
         if [ \"$2\" = \"show\" ]; then\n\
           printf 'FragmentPath=\\nLoadState=loaded\\nUnitFileState=\\nActiveState=active\\n'\n\
         fi\n\
         exit 0\n",
    )
    .unwrap();
    fs::set_permissions(&active_no_frag_ctl, fs::Permissions::from_mode(0o755)).unwrap();
    let active_no_frag = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &active_no_frag_ctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(
        active_no_frag.status.code(),
        Some(1),
        "Uninstall must refuse when local unit is absent but manager still reports ActiveState=active"
    );

    // 3d. `FragmentPath` containing spaces works cleanly across install and uninstall!
    let space_cfg_home = env._tmp.path().join("r3 xdg cfg with spaces");
    fs::create_dir_all(&space_cfg_home).unwrap();
    let space_state = env._tmp.path().join("space_sd_enabled.state");
    let space_ctl = env._tmp.path().join("systemctl_space_ok");
    fs::write(
        &space_ctl,
        format!(
            "#!/bin/sh\n\
             UNIT_FILE=\"$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"\n\
             if [ \"$2\" = \"enable\" ]; then\n\
               echo enabled > \"{}\"\n\
             elif [ \"$2\" = \"disable\" ]; then\n\
               rm -f \"{}\"\n\
             elif [ \"$2\" = \"show\" ]; then\n\
               if [ -f \"$UNIT_FILE\" ]; then\n\
                 printf 'FragmentPath=%s\\nLoadState=loaded\\n' \"$UNIT_FILE\"\n\
                 if [ -f \"{}\" ]; then\n\
                   printf 'UnitFileState=enabled\\nActiveState=active\\n'\n\
                 else\n\
                   printf 'UnitFileState=disabled\\nActiveState=inactive\\n'\n\
                 fi\n\
               else\n\
                 printf 'FragmentPath=\\nLoadState=not-found\\nUnitFileState=\\nActiveState=inactive\\n'\n\
               fi\n\
             fi\n\
             exit 0\n",
            space_state.display(),
            space_state.display(),
            space_state.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&space_ctl, fs::Permissions::from_mode(0o755)).unwrap();
    let sp_inst = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &space_cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &space_ctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(
        sp_inst.status.code(),
        Some(0),
        "Install with spaces in XDG_CONFIG_HOME must succeed: stderr={}",
        String::from_utf8_lossy(&sp_inst.stderr)
    );
    let sp_uninst = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &space_cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &space_ctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(
        sp_uninst.status.code(),
        Some(0),
        "Uninstall with spaces in XDG_CONFIG_HOME must succeed: stderr={}",
        String::from_utf8_lossy(&sp_uninst.stderr)
    );

    // 4. R3-14: `daemon --once --json` with disabled policy returns exit 0 with empty stdout/stderr!
    let d_once = env
        .cli_cmd()
        .args(["--json", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(d_once.status.code(), Some(0));
    assert!(d_once.stdout.is_empty());
    assert!(d_once.stderr.is_empty());

    // 5. R3-13: Real PTY test verifying `Ctrl+D` (`\x04`) cancels inline `x` (delete) and `D`
    //    (disable all) confirmations WITHOUT exiting the TUI, then exits cleanly when no
    //    confirmation is active!
    #[cfg(feature = "tui")]
    {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::process::Stdio;
        use std::time::Duration;

        let acc2 = sample_account("acc-r3b", "bob@example.com", now);
        repo.with_write_lock(|tx| tx.upsert_account(acc2.clone(), false, now))
            .unwrap();

        let win = libc::winsize {
            ws_row: 20,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &win as *const libc::winsize as *mut libc::winsize,
                )
            },
            0
        );
        let mut master = unsafe { fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { fs::File::from_raw_fd(slave_fd) };
        let inspect_slave = slave.try_clone().unwrap();
        unsafe {
            let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }

        let mut child = env
            .cli_cmd()
            .arg("tui")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap();

        let drain = |m: &mut fs::File, buf: &mut Vec<u8>| {
            let mut chunk = [0u8; 4096];
            loop {
                match m.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        };

        let mut screen = Vec::new();
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("alice@example.com") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(String::from_utf8_lossy(&screen).contains("alice@example.com"));

        // Press `x` then `Ctrl+D` (`\x04`) -> MUST cancel deletion and keep TUI running!
        screen.clear();
        master.write_all(b"x").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Delete ") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(String::from_utf8_lossy(&screen).contains("Delete "));

        screen.clear();
        master.write_all(b"\x04").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Canceled account deletion.") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("Canceled account deletion."),
            "Ctrl+D during delete confirm must cancel without exiting, got:\n{}",
            String::from_utf8_lossy(&screen)
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "TUI MUST stay alive after Ctrl+D cancels delete confirmation!"
        );
        assert!(env.paths().account_file("acc-r3a").exists());

        // Press `D` then `Ctrl+D` (`\x04`) -> MUST cancel disable-all and keep TUI running!
        screen.clear();
        master.write_all(b"D").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Disable all") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(String::from_utf8_lossy(&screen).contains("Disable all"));

        screen.clear();
        master.write_all(b"\x04").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Canceled disabling all accounts.") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("Canceled disabling all accounts."),
            "Ctrl+D during disable-all confirm must cancel without exiting, got:\n{}",
            String::from_utf8_lossy(&screen)
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "TUI MUST stay alive after Ctrl+D cancels disable-all confirmation!"
        );
        assert!(repo
            .read_snapshot()
            .unwrap()
            .accounts
            .iter()
            .all(|a| !a.disabled));

        // Now send `Ctrl+D` (`\x04`) with NO active confirmation -> exits cleanly with code 0!
        master.write_all(b"\x04").unwrap();
        master.flush().unwrap();
        let exit_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            drain(&mut master, &mut screen);
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            assert!(
                std::time::Instant::now() < exit_deadline,
                "TUI did not exit on Ctrl+D when no confirmation was active"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(0));
        let mut post_term: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post_term) },
            0
        );
        assert_ne!(post_term.c_lflag & libc::ECHO, 0);
    }
}
