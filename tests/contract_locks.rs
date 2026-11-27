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
            .env(
                "AGY_SWITCH_CLI_ANTIGRAVITY_APP_DIR",
                self._tmp.path().join("no-host-antigravity-app"),
            )
            .args(["--data-dir", data_dir.to_str().unwrap()]);
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
        // Under v1.2.7 Option 1B (`--from-local` is strictly offline) + S4 metadata preservation,
        // `auto` MUST read the valid keyring payload FIRST (including `id_token_email` preserved by
        // `switch`) and succeed offline with exit 0, whereas `--backend file` hits disk JSON parse
        // error on the corrupt file!
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
            "auto --from-local must read valid keyring payload first (not corrupt disk JSON), stderr={}",
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

    // 2. `status` human output reports Backend/Store/Journal/Slot/Daemon/Antigravity CLI and omits Session identity, Runtime state, and Stray slot files.
    let status_human = env.cli_cmd().arg("status").output().unwrap();
    assert_eq!(status_human.status.code(), Some(0));
    let status_txt = String::from_utf8_lossy(&status_human.stdout);
    assert!(status_txt.contains("Backend:"));
    assert!(status_txt.contains("Store status:"));
    assert!(status_txt.contains("Journal status:"));
    assert!(status_txt.contains("Slot initialized:"));
    assert!(status_txt.contains("Daemon state:"));
    assert!(status_txt.contains("Antigravity CLI:"));
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

    // 5. Real PTY TUI end-to-end verification (`C` add all / clear+disable, `cand #2 (skip)`, Layout A1, Interaction T2, `r` + `SIGTERM`/`Ctrl+C`)!
    #[cfg(feature = "tui")]
    {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::process::CommandExt;
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
            if String::from_utf8_lossy(&screen).contains("Last Quota") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let initial_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(initial_txt.contains("Last Quota"));
        assert!(initial_txt.contains("Quota ("));
        assert!(initial_txt.contains(&format!(
            "matched (alice@example.invalid, expires {expected_exp_local})"
        )));
        assert!(!initial_txt.contains("Google AI"));
        assert!(initial_txt.contains("Keys   : ↑/↓ select · g/G top/end · [/] reorder"));
        assert!(initial_txt.contains("Manage : r refresh (on *) · c/C cand"));

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

        // Interaction T2 check: cursor is on dormant row #2 (`acc-ts-2`), so pressing `r` makes
        // zero requests and shows the gentle switch-first status hint; `R` is a no-op!
        screen.clear();
        master.write_all(b"r").unwrap();
        master.flush().unwrap();
        for _ in 0..50 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Switch to this account first") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(String::from_utf8_lossy(&screen).contains("Switch to this account first"));

        // Boundary check: disable BOTH accounts (`d`, Up arrow `\x1b[A`, `d`), then press 'C' -> clean status notice!
        screen.clear();
        master.write_all(b"d\x1b[AdC").unwrap();
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

        // 6. Launch TUI pointed at a slow synthetic `agy`, press 'r' on active `*` account, verify
        //    bottom-bar progress AND verify `SIGTERM` interrupts cleanly and restores PTY `ECHO`!
        let slow_agy = env._tmp.path().join("slow-tui-agy");
        let slow_agy_hit = env._tmp.path().join("slow-tui-agy-hit");
        fs::write(
            &slow_agy,
            format!(
                "#!/bin/sh\necho hit > \"{}\"\nsleep 30\n",
                slow_agy_hit.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&slow_agy, fs::Permissions::from_mode(0o755)).unwrap();

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
        cmd2.env("AGY_SWITCH_CLI_AGY_BIN", &slow_agy)
            .args(["tui"])
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
        master2.write_all(b"r").unwrap();
        master2.flush().unwrap();
        for _ in 0..60 {
            drain(&mut master2, &mut screen2);
            if slow_agy_hit.exists()
                && String::from_utf8_lossy(&screen2).contains("Refreshing active quota")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            String::from_utf8_lossy(&screen2).contains("Refreshing active quota"),
            "Expected bottom-bar active refresh status on 'r'"
        );
        assert!(
            slow_agy_hit.exists(),
            "Expected 'r' on active '*' account to spawn synthetic `agy -p \"/usage\"`"
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
            "SIGTERM during 'r' refresh MUST restore PTY ECHO!"
        );

        // 7. Also verify raw-mode keyboard Ctrl+C (`\x03` on PTY master, where `ISIG` is disabled)
        //    immediately aborts in-flight 'r' refresh, exits 0, and restores PTY `ECHO`!
        let _ = fs::remove_file(&slow_agy_hit);
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
        cmd3.env("AGY_SWITCH_CLI_AGY_BIN", &slow_agy)
            .args(["tui"])
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
        master3.write_all(b"r").unwrap();
        master3.flush().unwrap();
        for _ in 0..60 {
            drain(&mut master3, &mut screen3);
            if slow_agy_hit.exists()
                && String::from_utf8_lossy(&screen3).contains("Refreshing active quota")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(slow_agy_hit.exists());

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
            "Raw-mode Ctrl+C (`\\x03`) during 'r' refresh MUST restore PTY ECHO!"
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

        let make_blob = |sys_in: u64,
                         usr_in: u64,
                         out_t: u64,
                         cache_t: u64,
                         ts: u64,
                         model_id: &str,
                         label: &str|
         -> Vec<u8> {
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
                pb_b(19, model_id.as_bytes()),
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
                "gemini-4-carbon",
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
                "gemini-4-hydrogen-xhigh",
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
                    "claude-opus-4-6",
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
                rusqlite::params![make_blob(
                    10,
                    90,
                    20,
                    0,
                    ts_nov15,
                    "gemini-4-carbon",
                    "Gemini 4 Carbon (High)"
                )],
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
                rusqlite::params![make_blob(
                    10,
                    90,
                    20,
                    0,
                    ts_nov15,
                    "gemini-4-carbon",
                    "Gemini 4 Carbon (High)"
                )],
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
    let payload_ko1 =
        agy_switch_cli::session::payload::serialize_session_payload_for_account(&acc1).unwrap();
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
        "#!/bin/sh\nif [ \"$2\" = \"show\" ]; then\n  printf 'FragmentPath={unit}\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=active\\n'\nelif [ \"$2\" = \"disable\" ]; then\n  mv \"{real}\" \"{real}.moved\"\n  ln -s \"{victim}\" \"{real}\"\nfi\nexit 0\n",
        unit = real_unit.display(),
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
        cfg_home.join("systemd/user.moved").exists(),
        "Expected mock `disable` step to execute and perform the directory swap before unlink guard ran"
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
            if String::from_utf8_lossy(&pty_buf).contains("Refresh error:")
                || String::from_utf8_lossy(&pty_buf).contains("Refreshed quota")
            {
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
            !pty_txt.contains("TUI_PROXY_SECRET_777"),
            "Leaked malformed proxy secret in TUI output!"
        );
        // Verify malformed `HTTPS_PROXY` on an OAuth CLI path emits variable-name-only warning without leaking secret!
        let mut add_proxy_child = env
            .cli_cmd()
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
        assert!(init_screen.contains("e/E enable · d/D disable · l label · o/O export · x delete"));

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

    // 4. J1 (`v1.2.2`): `daemon --once --json` with disabled policy returns exit 0 with valid JSON envelope & empty stderr!
    let d_once = env
        .cli_cmd()
        .args(["--json", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(d_once.status.code(), Some(0));
    assert!(
        d_once.stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&d_once.stderr)
    );
    let d_once_j: serde_json::Value = serde_json::from_slice(&d_once.stdout).unwrap();
    assert_eq!(d_once_j["schema_version"], 1);
    assert_eq!(d_once_j["ok"], true);
    assert_eq!(d_once_j["daemon"]["phase"], "disabled");
    assert_eq!(d_once_j["daemon"]["outcome"], "disabled");

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

#[test]
fn daemon_no_notify_install_flag_and_invalid_env_redaction() {
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let now = jiff::Timestamp::now().as_second();
    let repo = StoreRepository::new(env.paths());
    let acc1 = sample_account("acc-a", "alice@example.com", now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        Ok(())
    })
    .unwrap();

    // 1. Invalid `AGY_SWITCH_CLI_NOTIFY` must return exit code 2 without echoing raw env secret.
    let bad_env_out = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_NOTIFY", "bad_notify_secret_999")
        .args(["--json", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(bad_env_out.status.code(), Some(2));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&bad_env_out.stdout),
        String::from_utf8_lossy(&bad_env_out.stderr)
    );
    assert!(combined.contains("AGY_SWITCH_CLI_NOTIFY"));
    assert!(!combined.contains("bad_notify_secret_999"));

    // 1b. Explicit `--no-notify` takes precedence over an invalid `AGY_SWITCH_CLI_NOTIFY` value.
    let cli_overrides_bad_env = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_NOTIFY", "bad_notify_secret_999")
        .args(["--backend", "file", "daemon", "--once", "--no-notify"])
        .output()
        .unwrap();
    assert_eq!(
        cli_overrides_bad_env.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&cli_overrides_bad_env.stderr)
    );

    // 2. `--no-notify` + `--uninstall` is rejected by clap with exit code 2.
    let conflict_out = env
        .cli_cmd()
        .args(["daemon", "--uninstall", "--no-notify"])
        .output()
        .unwrap();
    assert_eq!(conflict_out.status.code(), Some(2));

    // 3. `daemon --install --no-notify` persists `--no-notify` into rendered systemd user unit.
    let systemd_marker_dir = env._tmp.path().join("systemd_marker");
    fs::create_dir_all(&systemd_marker_dir).unwrap();
    let mock_systemctl = env._tmp.path().join("mock-systemctl");
    let script = "#!/bin/sh\n\
        if [ \"$1\" = \"--user\" ]; then shift; fi\n\
        case \"$1\" in\n\
          show-environment) exit 0 ;;\n\
          daemon-reload) exit 0 ;;\n\
          enable) exit 0 ;;\n\
          show) echo \"FragmentPath=$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"; echo \"LoadState=loaded\"; echo \"UnitFileState=enabled\"; echo \"ActiveState=active\"; exit 0 ;;\n\
          *) exit 0 ;;\n\
        esac\n";
    fs::write(&mock_systemctl, script).unwrap();
    fs::set_permissions(&mock_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    let inst = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["--json", "daemon", "--install", "--no-notify"])
        .output()
        .unwrap();
    assert_eq!(
        inst.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&inst.stderr)
    );
    let inst_j: serde_json::Value = serde_json::from_slice(&inst.stdout).unwrap();
    let unit_path = PathBuf::from(inst_j["unit_path"].as_str().unwrap());
    let unit_text = fs::read_to_string(&unit_path).unwrap();
    assert!(
        unit_text.contains(" daemon --no-notify"),
        "unit missing --no-notify:\n{unit_text}"
    );
}

#[test]
fn synthetic_v124_daemon_reset_cooldown_boundary_2a_standalone_once_and_install() {
    use agy_switch_cli::store::locks::DaemonInstanceLock;
    use agy_switch_cli::switching::daemon::{
        read_daemon_state_readonly, save_daemon_state_in_tx, DaemonPersistentState,
    };

    let make_acc = |id: &str, email: &str, pct: f64, now: i64| -> AccountRecord {
        let mut rec = sample_account(id, email, now);
        if let Some(ref mut q) = rec.quota {
            for m in &mut q.models {
                m.percentage = (pct * 100.0).round() as i32;
                m.observed_remaining_fraction = Some(pct);
            }
            if let Some(ref mut groups) = q.quota_groups {
                for g in groups {
                    for b in &mut g.buckets {
                        b.remaining_fraction = pct;
                    }
                }
            }
        }
        rec
    };

    let seed_cooldown_store = |env: &IsolatedEnv, now: i64, cooldown_until: i64, paused: bool| {
        env.init_agy_slot_dir();
        let paths = env.paths();
        let repo = StoreRepository::new(paths.clone());
        let acc_a = make_acc("acc-a", "alice@example.com", 0.02, now);
        let acc_b = make_acc("acc-b", "bob@example.com", 0.90, now);
        let fake_agy = env._tmp.path().join("no-host-agy");
        let agy_script = format!(
            r#"#!/bin/sh
if grep -q "SECRET_REFRESH_TOKEN_acc-b" "{slot}" 2>/dev/null; then
  printf '%s\n' '{{"conversation_id":"","status":"SUCCESS","command":{{"name":"usage","data":{{"groups":[{{"name":"Gemini Models","buckets":[{{"id":"gemini-weekly","window":"weekly","remaining_fraction":0.90,"reset_time":"2099-01-07T00:00:00Z"}},{{"id":"gemini-5h","window":"5h","remaining_fraction":0.90,"reset_time":"2099-01-01T05:00:00Z"}}]}}]}}}}}}'
else
  printf '%s\n' '{{"conversation_id":"","status":"SUCCESS","command":{{"name":"usage","data":{{"groups":[{{"name":"Gemini Models","buckets":[{{"id":"gemini-weekly","window":"weekly","remaining_fraction":0.02,"reset_time":"2099-01-07T00:00:00Z"}},{{"id":"gemini-5h","window":"5h","remaining_fraction":0.02,"reset_time":"2099-01-01T05:00:00Z"}}]}}]}}}}}}'
fi
"#,
            slot = paths.active_slot_file.display()
        );
        fs::write(&fake_agy, agy_script).unwrap();
        fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, now)?;
            tx.upsert_account(acc_b.clone(), false, now)?;
            let mut pol = agy_switch_cli::domain::policy::SwitchPolicy {
                enabled: true,
                reserve_percentage: 10,
                candidate_min_percentage: 30,
                candidate_account_ids: vec!["acc-b".into()],
                ..agy_switch_cli::domain::policy::SwitchPolicy::default()
            };
            tx.save_policy(&mut pol, None, now)?;
            let dstate = DaemonPersistentState {
                cooldown_until,
                last_rotated_candidate_id: Some("acc-a".into()),
                consecutive_commit_failures: if paused { 2 } else { 0 },
                paused_on_failure: paused,
                paused_reason: paused.then(|| "commit_failed: io_error".into()),
                last_phase: if paused {
                    "paused_on_failure".into()
                } else {
                    "cooldown".into()
                },
                last_reason: Some(if paused {
                    "commit_failed: io_error".into()
                } else {
                    "switch_committed".into()
                }),
                last_checked_at: Some(now - 30),
                ..DaemonPersistentState::default()
            };
            save_daemon_state_in_tx(tx.paths(), &dstate)?;
            Ok(())
        })
        .unwrap();
        FileSessionBackend
            .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
            .unwrap();
    };

    let now = jiff::Timestamp::now().as_second();
    let future_cd = now + 3_600;

    // 1. Standalone `daemon --reset-cooldown` rejects foreground runtime override flags with exit 2
    //    AND leaves existing cooldown_until untouched on disk.
    let env_flags = IsolatedEnv::new();
    seed_cooldown_store(&env_flags, now, future_cd, false);
    for invalid_args in [
        vec!["daemon", "--reset-cooldown", "--interval", "300"],
        vec!["daemon", "--reset-cooldown", "--cooldown", "600"],
        vec!["daemon", "--reset-cooldown", "--no-notify"],
        vec!["daemon", "--reset-cooldown", "--mode", "wait"],
        vec!["daemon", "--reset-cooldown", "--strategy", "priority"],
        vec!["daemon", "--reset-cooldown", "--reserve", "15"],
        vec!["daemon", "--reset-cooldown", "--minimum", "40"],
        vec!["daemon", "--reset-cooldown", "--model", "claude"],
        vec![
            "--proxy",
            "http://127.0.0.1:7890",
            "daemon",
            "--reset-cooldown",
        ],
        vec!["daemon", "--uninstall", "--reset-cooldown"],
    ] {
        let out = env_flags.cli_cmd().args(&invalid_args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "Expected exit 2 for {invalid_args:?}, got {:?} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(
        read_daemon_state_readonly(&env_flags.paths())
            .unwrap()
            .cooldown_until,
        future_cd,
        "Rejected standalone flag combinations must not mutate daemon_state.json"
    );

    // 2. Standalone `daemon --reset-cooldown` succeeds with exit 0 EVEN WHILE `DaemonInstanceLock`
    //    is actively held (simulating live `systemd --user` or foreground daemon) AND EVEN WHEN
    //    `AGY_SWITCH_CLI_INTERVAL` / `AGY_SWITCH_CLI_COOLDOWN` env vars are exported in shell!
    let env_live = IsolatedEnv::new();
    seed_cooldown_store(&env_live, now, future_cd, true);
    let _running_daemon_lock = DaemonInstanceLock::try_acquire(&env_live.paths()).unwrap();
    let reset_json_out = env_live
        .cli_cmd()
        .env("AGY_SWITCH_CLI_INTERVAL", "300")
        .env("AGY_SWITCH_CLI_COOLDOWN", "1800")
        .args(["--json", "daemon", "--reset-cooldown"])
        .output()
        .unwrap();
    assert_eq!(
        reset_json_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&reset_json_out.stderr)
    );
    let rj: serde_json::Value = serde_json::from_slice(&reset_json_out.stdout).unwrap();
    assert_eq!(rj["schema_version"], 1);
    assert_eq!(rj["ok"], true);
    assert_eq!(rj["cooldown_reset"], true);
    assert_eq!(rj["cooldown_was_active"], true);
    assert_eq!(rj["previous_cooldown_until"], future_cd);

    let after_live = read_daemon_state_readonly(&env_live.paths()).unwrap();
    assert_eq!(after_live.cooldown_until, 0);
    assert_eq!(
        after_live.last_rotated_candidate_id.as_deref(),
        Some("acc-a")
    );
    assert!(after_live.paused_on_failure);
    assert_eq!(after_live.consecutive_commit_failures, 2);
    assert_eq!(
        after_live.paused_reason.as_deref(),
        Some("commit_failed: io_error")
    );

    // Idempotent second call while lock still held
    let reset_again = env_live
        .cli_cmd()
        .args(["daemon", "--reset-cooldown"])
        .output()
        .unwrap();
    assert_eq!(reset_again.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&reset_again.stdout).contains("No active daemon cooldown"),
        "stdout={}",
        String::from_utf8_lossy(&reset_again.stdout)
    );
    drop(_running_daemon_lock);

    // 3. `daemon --once --reset-cooldown` breaks immediately out of active cooldown and switches,
    //    whereas control `daemon --once` stays in cooldown.
    let env_once = IsolatedEnv::new();
    seed_cooldown_store(&env_once, now, future_cd, false);
    let ctrl_once = env_once
        .cli_cmd()
        .args([
            "--backend",
            "file",
            "--json",
            "daemon",
            "--once",
            "--no-notify",
        ])
        .output()
        .unwrap();
    assert_eq!(ctrl_once.status.code(), Some(0));
    let ctrl_j: serde_json::Value = serde_json::from_slice(&ctrl_once.stdout).unwrap();
    assert_eq!(ctrl_j["daemon"]["phase"], "cooldown");
    assert_eq!(
        StoreRepository::new(env_once.paths())
            .read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );

    let break_once = env_once
        .cli_cmd()
        .args([
            "--backend",
            "file",
            "--json",
            "daemon",
            "--once",
            "--reset-cooldown",
            "--no-notify",
        ])
        .output()
        .unwrap();
    assert_eq!(
        break_once.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&break_once.stderr)
    );
    let break_j: serde_json::Value = serde_json::from_slice(&break_once.stdout).unwrap();
    assert_eq!(break_j["daemon"]["reason"], "switch_committed");
    assert_eq!(
        StoreRepository::new(env_once.paths())
            .read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );

    // 4. `daemon --install --reset-cooldown` clears active cooldown once BEFORE starting systemd unit
    //    and NEVER persists `--reset-cooldown` into `ExecStart`.
    let env_inst = IsolatedEnv::new();
    seed_cooldown_store(&env_inst, now, future_cd, false);
    let systemd_marker_dir = env_inst._tmp.path().join("systemd_marker");
    fs::create_dir_all(&systemd_marker_dir).unwrap();
    let mock_systemctl = env_inst._tmp.path().join("mock-systemctl");
    let script = "#!/bin/sh\n\
        if [ \"$1\" = \"--user\" ]; then shift; fi\n\
        case \"$1\" in\n\
          show-environment) exit 0 ;;\n\
          daemon-reload) exit 0 ;;\n\
          enable) exit 0 ;;\n\
          show) echo \"FragmentPath=$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"; echo \"LoadState=loaded\"; echo \"UnitFileState=enabled\"; echo \"ActiveState=active\"; exit 0 ;;\n\
          *) exit 0 ;;\n\
        esac\n";
    fs::write(&mock_systemctl, script).unwrap();
    fs::set_permissions(&mock_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    // 4a. Invalid `--interval 0` with `--install --reset-cooldown` must exit 2 without clearing cooldown!
    let bad_inst = env_inst
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["daemon", "--install", "--reset-cooldown", "--interval", "0"])
        .output()
        .unwrap();
    assert_eq!(bad_inst.status.code(), Some(2));
    assert_eq!(
        read_daemon_state_readonly(&env_inst.paths())
            .unwrap()
            .cooldown_until,
        future_cd
    );

    // 4b. Target unit dir preflight failure (`XDG_CONFIG_HOME/systemd/user` is a regular file) must
    //     exit 1 (`data_error`) WITHOUT clearing cooldown or modifying `daemon_state.json` bytes!
    let ds_before_dir_err = fs::read(env_inst.paths().daemon_state_file()).unwrap();
    let systemd_parent = env_inst
        ._tmp
        .path()
        .join("xdg_cfg")
        .join("systemd")
        .join("user");
    fs::create_dir_all(systemd_parent.parent().unwrap()).unwrap();
    fs::write(&systemd_parent, b"not-a-directory").unwrap();
    let dir_err_inst = env_inst
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args(["--json", "daemon", "--install", "--reset-cooldown"])
        .output()
        .unwrap();
    assert_eq!(dir_err_inst.status.code(), Some(1));
    let dir_err_j: serde_json::Value = serde_json::from_slice(&dir_err_inst.stderr).unwrap();
    assert_eq!(dir_err_j["error_code"], "data_error");
    assert_eq!(
        fs::read(env_inst.paths().daemon_state_file()).unwrap(),
        ds_before_dir_err,
        "Unit directory preflight failure must leave daemon_state.json byte-for-byte untouched"
    );
    fs::remove_file(&systemd_parent).unwrap();

    // 4c. Valid `--install --reset-cooldown --interval 300 --cooldown 1800` clears cooldown and omits flag from ExecStart.
    let ok_inst = env_inst
        .cli_cmd()
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &systemd_marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &mock_systemctl)
        .args([
            "--json",
            "daemon",
            "--install",
            "--reset-cooldown",
            "--interval",
            "300",
            "--cooldown",
            "1800",
        ])
        .output()
        .unwrap();
    assert_eq!(
        ok_inst.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&ok_inst.stderr)
    );
    let ok_j: serde_json::Value = serde_json::from_slice(&ok_inst.stdout).unwrap();
    assert_eq!(ok_j["cooldown_reset"], true);
    assert_eq!(ok_j["cooldown_was_active"], true);
    assert_eq!(ok_j["previous_cooldown_until"], future_cd);
    let unit_path = PathBuf::from(ok_j["unit_path"].as_str().unwrap());
    let unit_text = fs::read_to_string(&unit_path).unwrap();
    assert!(
        unit_text.contains(" daemon --interval 300 --cooldown 1800"),
        "unit missing interval/cooldown:\n{unit_text}"
    );
    assert!(
        !unit_text.contains("--reset-cooldown"),
        "systemd unit ExecStart MUST NEVER persist --reset-cooldown:\n{unit_text}"
    );
    assert_eq!(
        read_daemon_state_readonly(&env_inst.paths())
            .unwrap()
            .cooldown_until,
        0
    );
}

#[cfg(feature = "secret-service-backend")]
#[test]
fn daemon_desktop_notifications_dbus_lifecycle_headless_optout_pause_dedup_and_timeout() {
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
                "import dbus, dbus.service, dbus.mainloop.glib; from gi.repository import GLib",
            ])
            .status()
            .is_ok_and(|s| s.success());
    if !has_py_deps {
        if allow_skip {
            eprintln!("[SKIPPED] live isolated D-Bus notification test skipped via AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST=1");
            return;
        }
        panic!(
            "Live isolated D-Bus notification test requires `/usr/bin/dbus-daemon` and Python `dbus` + `gi` (set AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST=1 to explicitly skip)."
        );
    }

    let make_dual_window_acc =
        |id: &str, email: &str, short_5h: f64, weekly: f64, now: i64| -> AccountRecord {
            let mut rec = sample_account(id, email, now);
            let min_pct = short_5h.min(weekly);
            if let Some(ref mut q) = rec.quota {
                for m in &mut q.models {
                    m.percentage = (min_pct * 100.0).round() as i32;
                    m.observed_remaining_fraction = Some(min_pct);
                }
                if let Some(ref mut groups) = q.quota_groups {
                    for g in groups {
                        for b in &mut g.buckets {
                            if b.window.eq_ignore_ascii_case("5h") || b.bucket_id.ends_with("-5h") {
                                b.remaining_fraction = short_5h;
                            } else {
                                b.remaining_fraction = weekly;
                            }
                        }
                    }
                }
            }
            rec
        };

    let setup_switchable_store = |env: &IsolatedEnv, now: i64| {
        env.init_agy_slot_dir();
        let paths = env.paths();
        let repo = StoreRepository::new(paths.clone());
        let acc_a = make_dual_window_acc("acc-a", "alice@example.com", 0.02, 0.40, now);
        let acc_b = make_dual_window_acc("acc-b", "bob@example.com", 1.00, 0.85, now);
        let fake_agy = env._tmp.path().join("no-host-agy");
        let agy_script = format!(
            r#"#!/bin/sh
if grep -q "SECRET_REFRESH_TOKEN_acc-b" "{slot}" 2>/dev/null; then
  printf '%s\n' '{{"conversation_id":"","status":"SUCCESS","command":{{"name":"usage","data":{{"groups":[{{"name":"Gemini Models","buckets":[{{"id":"gemini-weekly","window":"weekly","remaining_fraction":0.85,"reset_time":"2099-01-07T00:00:00Z"}},{{"id":"gemini-5h","window":"5h","remaining_fraction":1.00,"reset_time":"1970-01-01T00:00:00Z"}}]}}]}}}}}}'
else
  printf '%s\n' '{{"conversation_id":"","status":"SUCCESS","command":{{"name":"usage","data":{{"groups":[{{"name":"Gemini Models","buckets":[{{"id":"gemini-weekly","window":"weekly","remaining_fraction":0.40,"reset_time":"2099-01-07T00:00:00Z"}},{{"id":"gemini-5h","window":"5h","remaining_fraction":0.02,"reset_time":"2099-01-01T05:00:00Z"}}]}}]}}}}}}'
fi
"#,
            slot = paths.active_slot_file.display()
        );
        fs::write(&fake_agy, agy_script).unwrap();
        fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, now)?;
            tx.upsert_account(acc_b.clone(), false, now)?;
            let mut pol = agy_switch_cli::domain::policy::SwitchPolicy {
                enabled: true,
                reserve_percentage: 5,
                candidate_min_percentage: 15,
                candidate_account_ids: vec!["acc-b".into()],
                ..agy_switch_cli::domain::policy::SwitchPolicy::default()
            };
            tx.save_policy(&mut pol, None, now)?;
            Ok(())
        })
        .unwrap();
        FileSessionBackend
            .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
            .unwrap();
    };

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // Start private isolated dbus-daemon with an activatable synthetic Notifications `.service`
    // so both headless no-owner and mid-flight owner-vanish verify zero D-Bus auto-activation.
    let bus_env = IsolatedEnv::new();
    let bus_sock = bus_env.runtime_dir.join("mock-notify.sock");
    let bus_addr = format!("unix:path={}", bus_sock.display());
    let service_dir = bus_env._tmp.path().join("dbus-services");
    fs::create_dir_all(&service_dir).unwrap();
    let activated_sentinel = bus_env._tmp.path().join("dbus_auto_activated");
    let fake_activator = bus_env._tmp.path().join("fake_notify_activator.sh");
    fs::write(
        &fake_activator,
        format!(
            "#!/bin/sh\necho activated > \"{}\"\n",
            activated_sentinel.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_activator, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        service_dir.join("org.freedesktop.Notifications.service"),
        format!(
            "[D-BUS Service]\nName=org.freedesktop.Notifications\nExec={}\n",
            fake_activator.display()
        ),
    )
    .unwrap();
    let bus_conf = bus_env._tmp.path().join("private-bus.conf");
    fs::write(
        &bus_conf,
        format!(
            "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n\
             \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n\
             <busconfig>\n\
               <type>session</type>\n\
               <listen>{bus_addr}</listen>\n\
               <servicedir>{}</servicedir>\n\
               <policy context=\"default\">\n\
                 <allow send_destination=\"*\" eavesdrop=\"true\"/>\n\
                 <allow eavesdrop=\"true\"/>\n\
                 <allow own=\"*\"/>\n\
               </policy>\n\
             </busconfig>\n",
            service_dir.display()
        ),
    )
    .unwrap();
    let _dbus_guard = ChildGuard(
        Command::new("/usr/bin/dbus-daemon")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                &format!("--config-file={}", bus_conf.display()),
                "--nofork",
                "--nopidfile",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if bus_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(bus_sock.exists(), "Isolated dbus-daemon socket missing");

    // 1. Live D-Bus bus with NO org.freedesktop.Notifications owner (e.g. headless server with linger):
    //    `daemon --once` switches cleanly with exit 0 and NEVER triggers D-Bus auto-activation.
    let now = jiff::Timestamp::now().as_second();
    let headless_env = IsolatedEnv::new();
    setup_switchable_store(&headless_env, now);
    let headless_out = headless_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(
        headless_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&headless_out.stderr)
    );
    assert!(
        !activated_sentinel.exists(),
        "Headless daemon --once unexpectedly triggered D-Bus service auto-activation"
    );
    assert_eq!(
        StoreRepository::new(headless_env.paths())
            .read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );

    // 2. Spawn mock org.freedesktop.Notifications Python D-Bus service on the isolated bus
    let ctrl_file = bus_env._tmp.path().join("notify_ctrl.json");
    let log_file = bus_env._tmp.path().join("notify_log.json");
    let ready_file = bus_env._tmp.path().join("notify_ready");
    let mock_py = bus_env._tmp.path().join("mock_notifications.py");
    fs::write(
        &ctrl_file,
        r#"{"delay_ms": 0, "capabilities": ["body", "body-markup"]}"#,
    )
    .unwrap();
    fs::write(&log_file, "[]").unwrap();

    let py_code = r#"
import json, sys
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

CTRL_PATH, LOG_PATH, READY_PATH = sys.argv[1], sys.argv[2], sys.argv[3]

class NotificationsObj(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, "/org/freedesktop/Notifications")
        self.bus = bus
        self.next_id = 1

    @dbus.service.method(
        "org.freedesktop.Notifications",
        in_signature="",
        out_signature="as",
    )
    def GetCapabilities(self):
        with open(CTRL_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        caps = cfg.get("capabilities", ["body"])
        if cfg.get("release_on_caps"):
            self.bus.release_name("org.freedesktop.Notifications")
        return dbus.Array([dbus.String(c) for c in caps], signature="s")

    @dbus.service.method(
        "org.freedesktop.Notifications",
        in_signature="susssasa{sv}i",
        out_signature="u",
        async_callbacks=("ok_cb", "err_cb"),
    )
    def Notify(self, app_name, replaces_id, app_icon, summary, body, actions, hints, expire_timeout, ok_cb, err_cb):
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            items = json.load(f)
        urgency = int(hints.get("urgency", 1)) if "urgency" in hints else 1
        transient = bool(hints["transient"]) if "transient" in hints else None
        resident = bool(hints["resident"]) if "resident" in hints else None
        items.append({
            "app_name": str(app_name),
            "app_icon": str(app_icon),
            "summary": str(summary),
            "body": str(body),
            "urgency": urgency,
            "transient": transient,
            "resident": resident,
            "expire_timeout": int(expire_timeout),
        })
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(items, f)
        nid = self.next_id
        self.next_id += 1
        with open(CTRL_PATH, "r", encoding="utf-8") as f:
            delay_ms = int(json.load(f).get("delay_ms", 0))
        if delay_ms > 0:
            def finish():
                ok_cb(dbus.UInt32(nid))
                return False
            GLib.timeout_add(delay_ms, finish)
        else:
            ok_cb(dbus.UInt32(nid))

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus_name = dbus.service.BusName("org.freedesktop.Notifications", bus)
svc = NotificationsObj(bus)
with open(READY_PATH, "w", encoding="utf-8") as rf:
    rf.write("ready")
GLib.MainLoop().run()
"#;
    fs::write(&mock_py, py_code).unwrap();
    let _py_guard = ChildGuard(
        Command::new("/usr/bin/python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
            .args([
                mock_py.to_str().unwrap(),
                ctrl_file.to_str().unwrap(),
                log_file.to_str().unwrap(),
                ready_file.to_str().unwrap(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );

    for _ in 0..80 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(ready_file.exists(), "Mock notifications service not ready");

    let read_notifications = || -> Vec<serde_json::Value> {
        serde_json::from_slice(&fs::read(&log_file).unwrap()).unwrap()
    };

    // 2a. Successful auto-switch emits markup-formatted desktop notification when `body-markup` is advertised
    let sw_env = IsolatedEnv::new();
    setup_switchable_store(&sw_env, now);
    let sw_out = sw_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(sw_out.status.code(), Some(0));
    let notes = read_notifications();
    assert_eq!(notes.len(), 1, "Expected 1 switch notification: {notes:?}");
    assert_eq!(notes[0]["app_name"], "agy-switch-cli");
    assert_eq!(notes[0]["summary"], "Account Switched");
    assert_eq!(notes[0]["urgency"], 1);
    assert_eq!(notes[0]["transient"], false);
    assert_eq!(notes[0]["resident"], true);
    assert_eq!(notes[0]["expire_timeout"], 0);
    let body0 = notes[0]["body"].as_str().unwrap();
    assert_eq!(
        body0,
        "<b>↑ bob@example.com (label- [31mANSI [0m)</b>\n<b>5h 100% · Weekly 85%</b>\n↓ alice@example.com (label- [31mANSI [0m)\n5h 2% · Weekly 40%",
        "body={body0}"
    );
    assert!(!body0.contains('\x1b'), "ANSI leaked into body={body0}");
    assert!(
        !body0.contains("Restart"),
        "Unexpected restart hint in body={body0}"
    );

    // 2a-plain. When desktop does NOT advertise `body-markup`, notification degrades cleanly to plain text
    fs::write(&ctrl_file, r#"{"delay_ms": 0, "capabilities": ["body"]}"#).unwrap();
    let plain_env = IsolatedEnv::new();
    setup_switchable_store(&plain_env, now);
    let plain_out = plain_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(plain_out.status.code(), Some(0));
    let notes_plain = read_notifications();
    assert_eq!(notes_plain.len(), 2);
    assert_eq!(notes_plain[1]["summary"], "Account Switched");
    assert_eq!(notes_plain[1]["urgency"], 1);
    assert_eq!(notes_plain[1]["transient"], false);
    assert_eq!(notes_plain[1]["resident"], true);
    assert_eq!(notes_plain[1]["expire_timeout"], 0);
    assert_eq!(
        notes_plain[1]["body"].as_str().unwrap(),
        "↑ bob@example.com (label- [31mANSI [0m)\n5h 100% · Weekly 85%\n↓ alice@example.com (label- [31mANSI [0m)\n5h 2% · Weekly 40%"
    );
    // Restore markup capability for subsequent checks
    fs::write(
        &ctrl_file,
        r#"{"delay_ms": 0, "capabilities": ["body", "body-markup"]}"#,
    )
    .unwrap();

    // 2a-auto-dismiss. When `config.json` sets `notifications.persistent = false`, `Account Switched`
    // uses `expire_timeout = -1` (server default auto-dismiss) while still setting transient=false, resident=true.
    let autodismiss_env = IsolatedEnv::new();
    setup_switchable_store(&autodismiss_env, now);
    fs::write(
        autodismiss_env.paths().config_file(),
        br#"{"schema_version":1,"notifications":{"persistent":false}}"#,
    )
    .unwrap();
    fs::set_permissions(
        autodismiss_env.paths().config_file(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let ad_out = autodismiss_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(ad_out.status.code(), Some(0));
    let notes_ad = read_notifications();
    assert_eq!(notes_ad.len(), 3);
    assert_eq!(notes_ad[2]["summary"], "Account Switched");
    assert_eq!(notes_ad[2]["urgency"], 1);
    assert_eq!(notes_ad[2]["transient"], false);
    assert_eq!(notes_ad[2]["resident"], true);
    assert_eq!(notes_ad[2]["expire_timeout"], -1);

    // 2b. Opt-outs: `--no-notify`, `AGY_SWITCH_CLI_NOTIFY=0`, and `config.json` `notifications.enabled = false`
    for mode in ["cli", "env", "config"] {
        let opt_env = IsolatedEnv::new();
        setup_switchable_store(&opt_env, now);
        let mut cmd = opt_env.cli_cmd();
        cmd.env("DBUS_SESSION_BUS_ADDRESS", &bus_addr).args([
            "--backend",
            "file",
            "daemon",
            "--once",
        ]);
        match mode {
            "cli" => {
                cmd.arg("--no-notify");
            }
            "env" => {
                cmd.env("AGY_SWITCH_CLI_NOTIFY", "0");
            }
            "config" => {
                fs::write(
                    opt_env.paths().config_file(),
                    br#"{"schema_version":1,"notifications":{"enabled":false}}"#,
                )
                .unwrap();
                fs::set_permissions(
                    opt_env.paths().config_file(),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            StoreRepository::new(opt_env.paths())
                .read_snapshot()
                .unwrap()
                .index
                .selected_account_id
                .as_deref(),
            Some("acc-b")
        );
        assert_eq!(
            read_notifications().len(),
            3,
            "Opt-out `{mode}` must suppress notification"
        );
    }

    // 2c. PausedOnFailure notifies ONCE on transition (urgency=2, persistent expire_timeout=0 even when
    //     `notifications.persistent = false`) and does NOT spam on subsequent ticks
    let pause_env = IsolatedEnv::new();
    setup_switchable_store(&pause_env, now);
    fs::write(
        pause_env.paths().config_file(),
        br#"{"schema_version":1,"notifications":{"persistent":false}}"#,
    )
    .unwrap();
    fs::set_permissions(
        pause_env.paths().config_file(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::create_dir_all(pause_env.paths().state_dir()).unwrap();
    fs::write(pause_env.paths().switch_journal_file(), b"{not-valid-json").unwrap();
    let pause_out_1 = pause_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(pause_out_1.status.code(), Some(0));
    let notes_after_pause1 = read_notifications();
    assert_eq!(notes_after_pause1.len(), 4);
    assert_eq!(notes_after_pause1[3]["summary"], "Auto-Switch Paused");
    assert_eq!(notes_after_pause1[3]["urgency"], 2);
    assert_eq!(notes_after_pause1[3]["transient"], false);
    assert_eq!(notes_after_pause1[3]["resident"], true);
    assert_eq!(notes_after_pause1[3]["expire_timeout"], 0);
    let pause_body = notes_after_pause1[3]["body"].as_str().unwrap();
    let pause_lines: Vec<&str> = pause_body.lines().collect();
    assert_eq!(pause_lines.len(), 3, "pause_body={pause_body}");
    assert_eq!(pause_lines[0], "■ <b>Journal check</b> · 1/3 failed");
    assert!(
        !pause_lines[1].contains("Paused due to"),
        "reason should not duplicate Paused prefix: {pause_body}"
    );
    assert!(
        !pause_body.contains(pause_env.paths().data_dir.to_str().unwrap()),
        "PausedOnFailure notification must not leak local filesystem paths: {pause_body}"
    );
    assert_eq!(
        pause_lines[2],
        "<i>Run agy-switch-cli status to inspect.</i>"
    );

    // Second run while already paused_on_failure MUST NOT emit another notification
    let pause_out_2 = pause_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(pause_out_2.status.code(), Some(0));
    assert_eq!(
        read_notifications().len(),
        4,
        "Already-paused tick must not spam duplicate notifications"
    );

    // 2d. Slow notification daemon (4s delay > 2s timeout) must NOT hang `daemon --once` or block switch commit
    fs::write(
        &ctrl_file,
        r#"{"delay_ms": 4000, "capabilities": ["body", "body-markup"]}"#,
    )
    .unwrap();
    let slow_env = IsolatedEnv::new();
    setup_switchable_store(&slow_env, now);
    let t0 = std::time::Instant::now();
    let slow_out = slow_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    let elapsed = t0.elapsed();
    assert_eq!(slow_out.status.code(), Some(0));
    assert!(
        elapsed < std::time::Duration::from_millis(3500),
        "Slow notification service blocked daemon --once for {elapsed:?}"
    );
    assert_eq!(
        StoreRepository::new(slow_env.paths())
            .read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );

    // 2e. Owner vanishes right after `GetCapabilities` (before `Notify`): `MethodFlags::NoAutoStart`
    //     prevents D-Bus from auto-activating the synthetic `.service` file, and switch still succeeds.
    fs::write(
        &ctrl_file,
        r#"{"delay_ms": 0, "capabilities": ["body"], "release_on_caps": true}"#,
    )
    .unwrap();
    let vanish_env = IsolatedEnv::new();
    setup_switchable_store(&vanish_env, now);
    let vanish_out = vanish_env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--backend", "file", "daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(
        vanish_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&vanish_out.stderr)
    );
    assert!(
        !activated_sentinel.exists(),
        "Notify without owner unexpectedly triggered D-Bus auto-activation despite NoAutoStart"
    );
    assert_eq!(
        StoreRepository::new(vanish_env.paths())
            .read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );
}

#[test]
fn stats_watch_cli_validation_and_live_pty_lifecycle() {
    let env = IsolatedEnv::new();

    // 1. Invalid `--watch` values are rejected with exit code 2 across all feature tiers
    for bad in ["0", "3601", "notanumber"] {
        let out = env
            .cli_cmd()
            .args(["stats", "summary", "--watch", bad])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 for --watch {bad}, got {:?}",
            out.status.code()
        );
    }

    // 2. `--watch` combined with `--json` is rejected with exit code 2
    let json_out = env
        .cli_cmd()
        .args(["--json", "stats", "summary", "--watch"])
        .output()
        .unwrap();
    assert_eq!(json_out.status.code(), Some(2));

    // 3. Non-TTY stdin/stdout is rejected cleanly with exit code 2
    let non_tty_out = env
        .cli_cmd()
        .args(["stats", "list", "--watch", "3"])
        .output()
        .unwrap();
    assert_eq!(non_tty_out.status.code(), Some(2));

    #[cfg(feature = "stats")]
    {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::time::Duration;

        let env = IsolatedEnv::new();
        let cli_conv = env.home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cli_conv).unwrap();

        let win = libc::winsize {
            ws_row: 24,
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
            .args(["stats", "summary", "--watch", "1"])
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

        // 4. Initial live render shows Summary view & `Live [summary]: every 1s`
        let mut screen = Vec::new();
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            let txt = String::from_utf8_lossy(&screen);
            if txt.contains("Live [summary]: every 1s") && txt.contains("Summary") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let initial_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            initial_txt.contains("Live [summary]: every 1s"),
            "initial screen missing summary live bar:\n{initial_txt}"
        );

        // 5. Write a live synthetic SQLite DB while `--watch 1` is open -> auto-refreshes without restart!
        let enc_v = |mut n: u64| -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let mut b = (n & 0x7f) as u8;
                n >>= 7;
                if n != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if n == 0 {
                    break;
                }
            }
            out
        };
        let pb_v = |field: u64, val: u64| -> Vec<u8> {
            let mut out = enc_v(field << 3);
            out.extend_from_slice(&enc_v(val));
            out
        };
        let pb_b = |field: u64, bytes: &[u8]| -> Vec<u8> {
            let mut out = enc_v((field << 3) | 2);
            out.extend_from_slice(&enc_v(bytes.len() as u64));
            out.extend_from_slice(bytes);
            out
        };
        let now_ts = jiff::Timestamp::now().as_second() as u64;
        let usage = [
            pb_v(1, 500),
            pb_v(2, 1_500),
            pb_v(3, 400),
            pb_v(5, 8_000),
            pb_v(10, 400),
        ]
        .concat();
        let timing = pb_b(4, &pb_v(1, now_ts));
        let wrapped = [
            pb_b(4, &usage),
            pb_b(9, &timing),
            pb_b(19, b"gemini-4-carbon"),
            pb_b(21, b"Gemini 4 Carbon"),
        ]
        .concat();
        let blob = pb_b(1, &wrapped);

        let live_db = cli_conv.join("live_watch.db");
        let conn = rusqlite::Connection::open(&live_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO steps VALUES (1, 15, ?1, 3, NULL)",
            rusqlite::params![pb_b(1, &pb_v(1, now_ts))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![blob],
        )
        .unwrap();
        drop(conn);

        screen.clear();
        for _ in 0..120 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Gemini 4 Carbon") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("Gemini 4 Carbon"),
            "watch mode did not detect live SQLite write:\n{}",
            String::from_utf8_lossy(&screen)
        );

        // 6. Press Tab -> switches live to `List` view (`Live [list]:`)
        screen.clear();
        master.write_all(b"\t").unwrap();
        master.flush().unwrap();
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            let txt = String::from_utf8_lossy(&screen);
            if txt.contains("Live [list]: every 1s") && txt.contains("Requests (newest first") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let list_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            list_txt.contains("Live [list]: every 1s")
                && list_txt.contains("Requests (newest first"),
            "Tab did not toggle to list view:\n{list_txt}"
        );

        // 7. Arrow key CSI sequence (`\x1b[A`) alone must NOT quit watch mode,
        //    and `\x1b[A\t` sent together must still dispatch `Tab` back to `summary`.
        master.write_all(b"\x1b[A").unwrap();
        master.flush().unwrap();
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            child.try_wait().unwrap().is_none(),
            "Escape sequence accidentally exited `stats --watch`"
        );
        screen.clear();
        master.write_all(b"\x1b[A\t").unwrap();
        master.flush().unwrap();
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            let txt = String::from_utf8_lossy(&screen);
            if txt.contains("Live [summary]: every 1s") && txt.contains("Summary") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let back_to_summary = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            back_to_summary.contains("Live [summary]: every 1s")
                && back_to_summary.contains("Summary"),
            "Arrow key followed by Tab swallowed Tab:\n{back_to_summary}"
        );

        // 7b. Resizing PTY to `5x0` (valid non-zero rows, zero cols) must NOT fall back to 120x24
        //     or emit body text; restoring to `24x100` redraws cleanly.
        screen.clear();
        let zero_col_win = libc::winsize {
            ws_row: 5,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &zero_col_win) },
            0
        );
        std::thread::sleep(Duration::from_millis(150));
        drain(&mut master, &mut screen);
        let zero_col_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            !zero_col_txt.contains("Live [") && !zero_col_txt.contains("Summary"),
            "5x0 zero-col resize unexpectedly rendered body/footer:\n{zero_col_txt}"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "5x0 resize unexpectedly exited watch mode"
        );
        screen.clear();
        assert_eq!(
            unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &win) },
            0
        );
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Live [summary]: every 1s") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("Live [summary]: every 1s"),
            "restoring PTY from 5x0 to 24x100 did not redraw frame"
        );

        // 8. Press `q` -> clean exit 0, alt screen exited, and ECHO/ICANON restored
        screen.clear();
        master.write_all(b"q").unwrap();
        master.flush().unwrap();
        let mut status_opt = None;
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            if let Some(st) = child.try_wait().unwrap() {
                status_opt = Some(st);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        drain(&mut master, &mut screen);
        let status = status_opt.expect("stats --watch did not exit after pressing q");
        assert_eq!(status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&screen).contains("\x1b[?1049l"),
            "alt-screen restore sequence missing on exit"
        );
        let mut final_tio: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut final_tio) },
            0
        );
        assert_ne!(
            final_tio.c_lflag & libc::ECHO,
            0,
            "ECHO was not restored after stats --watch exit"
        );
        assert_ne!(
            final_tio.c_lflag & libc::ICANON,
            0,
            "ICANON was not restored after stats --watch exit"
        );
    }
}

#[cfg(feature = "tui")]
#[test]
fn synthetic_v124_tui_pty_mark_export_label_cooldown_and_detail_m2() {
    use agy_switch_cli::domain::account::{TransferBundle, STORE_SCHEMA_VERSION};
    use agy_switch_cli::store::locks::DaemonInstanceLock;
    use agy_switch_cli::switching::daemon::{
        read_daemon_state_readonly, save_daemon_state_in_tx, DaemonPersistentState,
    };
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::Duration;

    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let paths = env.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = jiff::Timestamp::now().as_second();

    let mut acc1 = sample_account("acc-a", "alice@example.com", now);
    acc1.custom_label = Some("Main".into());
    let mut acc2 = sample_account("acc-b", "bob@example.com", now);
    acc2.custom_label = None;
    let mut acc3 = sample_account("acc-c", "charlie@example.com", now);
    acc3.custom_label = Some("Backup".into());

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        tx.upsert_account(acc3.clone(), false, now)?;
        let mut pol = agy_switch_cli::domain::policy::SwitchPolicy {
            enabled: true,
            candidate_account_ids: vec!["acc-a".into()],
            ..agy_switch_cli::domain::policy::SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        let dstate = DaemonPersistentState {
            schema_version: STORE_SCHEMA_VERSION,
            cooldown_until: now + 3_600,
            last_phase: "cooldown".into(),
            last_reason: Some("switch_committed".into()),
            ..DaemonPersistentState::default()
        };
        save_daemon_state_in_tx(tx.paths(), &dstate)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc1.token).unwrap())
        .unwrap();

    // Hold DaemonInstanceLock throughout the PTY session so `k` proves concurrent cooldown clear!
    let _daemon_lock = DaemonInstanceLock::try_acquire(&paths).unwrap();

    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let win = libc::winsize {
        ws_row: 24,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
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
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        let _ = libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let mut child = env
        .cli_cmd()
        .args(["--backend", "file", "tui"])
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

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
    for _ in 0..60 {
        drain(&mut master, &mut screen);
        if String::from_utf8_lossy(&screen).contains("Manage : r/R refresh") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let init = String::from_utf8_lossy(&screen).into_owned();
    assert!(
        init.contains("alice@example.com (Main)"),
        "Scheme L1 label missing on initial TUI screen:\n{init}"
    );
    assert!(
        init.contains("· cooldown "),
        "Daemon cooldown suffix missing on initial TUI header:\n{init}"
    );

    // 1. Mark row #1 (`alice`) and row #3 (`charlie`) via Space + Down + Down + Space.
    screen.clear();
    master.write_all(b" \x1b[B\x1b[B ").unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
        if String::from_utf8_lossy(&screen)
            .contains("Marked (2): alice@example.com, charlie@example.com")
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        String::from_utf8_lossy(&screen)
            .contains("Marked (2): alice@example.com, charlie@example.com  [Esc to clear]"),
        "Strategy B persistent marked footer missing:\n{}",
        String::from_utf8_lossy(&screen)
    );

    // 2. Press `o` -> clear default path (`Ctrl+U`) -> type `~/tui-export.json` -> Enter -> `y`.
    screen.clear();
    master.write_all(b"o\x15~/tui-export.json\r").unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
        let s = String::from_utf8_lossy(&screen);
        if s.contains("PLAINTEXT tokens [y/N]") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let exp_prompt_screen = String::from_utf8_lossy(&screen).into_owned();
    assert!(
        exp_prompt_screen.contains("PLAINTEXT tokens [y/N]"),
        "expected risk-first plaintext confirm prompt:\n{exp_prompt_screen}"
    );
    let exported_path = env.home.join("tui-export.json");
    assert!(
        !exported_path.exists(),
        "Enter alone must not write export file before explicit 'y'"
    );

    screen.clear();
    master.write_all(b"y").unwrap();
    master.flush().unwrap();
    for _ in 0..60 {
        drain(&mut master, &mut screen);
        if exported_path.exists() && String::from_utf8_lossy(&screen).contains("2 marked") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(exported_path.exists(), "TUI export file was not created");
    let exp_mode = fs::metadata(&exported_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(exp_mode, 0o600);
    let bundle: TransferBundle =
        serde_json::from_slice(&fs::read(&exported_path).unwrap()).unwrap();
    let exported_emails: Vec<&str> = bundle.accounts.iter().map(|a| a.email.as_str()).collect();
    assert_eq!(
        exported_emails,
        vec!["alice@example.com", "charlie@example.com"]
    );

    // Strategy B: after export, marks are STILL retained (`2 marked`)!
    assert!(
        String::from_utf8_lossy(&screen).contains("2 marked"),
        "Strategy B must keep marked accounts after export:\n{}",
        String::from_utf8_lossy(&screen)
    );

    // 2b. P1-01 real PTY regression: accidentally pasting a synthetic credential into the export
    //     path edit bar masks immediately as `[REDACTED]`, rejects BEFORE entering confirmation,
    //     never echoes any substring of the synthetic credential, and writes zero files!
    let sentinel_secret = "1//0gSyntheticPtyExportSentinel98765";
    screen.clear();
    master.write_all(b"o").unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
        if String::from_utf8_lossy(&screen).contains("Export 2 marked path:") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    screen.clear();
    let paste_cmd = format!("\x15{sentinel_secret}");
    master.write_all(paste_cmd.as_bytes()).unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
        if String::from_utf8_lossy(&screen).contains("[REDACTED]") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let masked_edit = String::from_utf8_lossy(&screen).into_owned();
    assert!(
        masked_edit.contains("[REDACTED]"),
        "expected [REDACTED] in PTY export edit bar:\n{masked_edit}"
    );
    assert!(
        !masked_edit.contains("SyntheticPtyExportSentinel"),
        "PTY export edit bar leaked pasted credential:\n{masked_edit}"
    );
    screen.clear();
    master.write_all(b"\r").unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
        if String::from_utf8_lossy(&screen).contains("redacted") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let rejected_screen = String::from_utf8_lossy(&screen).into_owned();
    assert!(
        rejected_screen.contains("redacted"),
        "expected sanitized rejection error after pressing Enter on credential:\n{rejected_screen}"
    );
    assert!(
        !rejected_screen.contains("PLAINTEXT"),
        "secret-like export path must not enter confirmation:\n{rejected_screen}"
    );
    assert!(
        !rejected_screen.contains("SyntheticPtyExportSentinel"),
        "PTY error output leaked pasted credential:\n{rejected_screen}"
    );

    // 3. Press `k` -> clears active cooldown concurrently while `_daemon_lock` is held!
    screen.clear();
    master.write_all(b"k").unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
        if read_daemon_state_readonly(&paths).is_ok_and(|d| d.cooldown_until == 0) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        read_daemon_state_readonly(&paths).unwrap().cooldown_until,
        0
    );

    // 4. Press `l` on row #3 (`charlie`) -> `Ctrl+U` -> type `NewTag` -> Enter -> persists & renders!
    screen.clear();
    master.write_all(b"l\x15NewTag\r").unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
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

    // 5. Press `i` -> opens M2 Account Detail card -> `i` returns -> `Esc` clears marks (stays open) -> `q` exits cleanly!
    screen.clear();
    master.write_all(b"i").unwrap();
    master.flush().unwrap();
    for _ in 0..50 {
        drain(&mut master, &mut screen);
        if String::from_utf8_lossy(&screen).contains("Account Detail 3/3") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let detail_scr = String::from_utf8_lossy(&screen).into_owned();
    assert!(detail_scr.contains("Account Detail 3/3"));
    assert!(detail_scr.contains("charlie@example.com (NewTag)"));
    assert!(detail_scr.contains("Quotas  :"));
    assert!(detail_scr.contains("Models ("));

    // Exit detail (`i`), press `Esc` once to clear marks (must NOT quit TUI), then press `q` to quit!
    screen.clear();
    master.write_all(b"i\x1b").unwrap();
    master.flush().unwrap();
    std::thread::sleep(Duration::from_millis(120));
    assert!(
        child.try_wait().unwrap().is_none(),
        "Esc while marked must clear marks without quitting TUI"
    );

    master.write_all(b"q").unwrap();
    master.flush().unwrap();
    let mut exit_status = None;
    for _ in 0..60 {
        drain(&mut master, &mut screen);
        if let Some(st) = child.try_wait().unwrap() {
            exit_status = Some(st);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let st = exit_status.expect("TUI did not exit cleanly after pressing q");
    assert_eq!(st.code(), Some(0));

    let mut post_tio: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post_tio) },
        0
    );
    assert_ne!(post_tio.c_lflag & libc::ECHO, 0);

    // 6. P2-01 real narrow PTY checks:
    //    (a) 30x16 displays `PLAINTEXT` + `[y/N]`, writes nothing before `y`, and writes `0600` v2 on `y`.
    //    (b) 20x16 cannot fit `PLAINTEXT [y/N]` and refuses confirmation even when `y` is pressed!
    for (ws_col, ws_row, rel_file, expect_created) in [
        (30u16, 16u16, "narrow-30x16-export.json", true),
        (20u16, 16u16, "tiny-20x16-export.json", false),
    ] {
        let mut m_fd: libc::c_int = -1;
        let mut s_fd: libc::c_int = -1;
        let ws = libc::winsize {
            ws_row,
            ws_col,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut m_fd,
                    &mut s_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &ws,
                )
            },
            0
        );
        let s_out_fd = unsafe { libc::dup(s_fd) };
        let s_in = unsafe { fs::File::from_raw_fd(s_fd) };
        let s_out = unsafe { fs::File::from_raw_fd(s_out_fd) };
        let mut m_file = unsafe { fs::File::from_raw_fd(m_fd) };
        unsafe {
            let flags = libc::fcntl(m_file.as_raw_fd(), libc::F_GETFL);
            let _ = libc::fcntl(m_file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut c = env
            .cli_cmd()
            .args(["--backend", "file", "tui"])
            .stdin(Stdio::from(s_in))
            .stdout(Stdio::from(s_out))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut buf = Vec::new();
        for _ in 0..60 {
            drain(&mut m_file, &mut buf);
            if String::from_utf8_lossy(&buf).contains("Manage :") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        buf.clear();
        let target_file = env.home.join(rel_file);
        let cmd_str = format!("O\x15~/{rel_file}\r");
        m_file.write_all(cmd_str.as_bytes()).unwrap();
        m_file.flush().unwrap();
        for _ in 0..50 {
            drain(&mut m_file, &mut buf);
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
        assert!(
            !target_file.exists(),
            "file must not exist before 'y' at {ws_col}x{ws_row}"
        );
        if expect_created {
            assert!(
                after_enter.contains("PLAINTEXT") && after_enter.contains("[y/N]"),
                "30x16 confirmation must visibly display PLAINTEXT + [y/N]:\n{after_enter}"
            );
        }

        m_file.write_all(b"y").unwrap();
        m_file.flush().unwrap();
        if expect_created {
            for _ in 0..60 {
                drain(&mut m_file, &mut buf);
                if target_file.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(target_file.exists(), "30x16 export failed after pressing y");
            assert_eq!(
                fs::metadata(&target_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        } else {
            std::thread::sleep(Duration::from_millis(120));
            drain(&mut m_file, &mut buf);
            assert!(
                !target_file.exists(),
                "20x16 must refuse export confirmation when PLAINTEXT warning cannot fit"
            );
        }

        m_file.write_all(b"q").unwrap();
        m_file.flush().unwrap();
        let mut exited = None;
        for _ in 0..60 {
            drain(&mut m_file, &mut buf);
            if let Some(st) = c.try_wait().unwrap() {
                exited = Some(st);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(exited.expect("narrow PTY did not exit").code(), Some(0));
    }
}

#[test]
fn synthetic_v124_status_daemon_runtime_app_probe_and_disable_without_reason() {
    use agy_switch_cli::domain::account::STORE_SCHEMA_VERSION;
    use agy_switch_cli::store::locks::DaemonInstanceLock;
    use agy_switch_cli::switching::daemon::{save_daemon_state_in_tx, DaemonPersistentState};
    use agy_switch_cli::switching::systemd::{
        render_systemd_user_unit, DaemonServiceInstallOptions, SYSTEMCTL_BIN_ENV,
        SYSTEMD_MARKER_DIR_ENV,
    };
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

    // 1. Default status: no daemon running, no systemd service, no desktop app -> clean idle output, zero `daemon.lock` creation!
    let st_idle = env.cli_cmd().arg("status").output().unwrap();
    assert_eq!(st_idle.status.code(), Some(0));
    let idle_txt = String::from_utf8_lossy(&st_idle.stdout);
    assert!(
        idle_txt.contains("Daemon state:      not running (no service; ready for daemon / --once)"),
        "unexpected idle status:\n{idle_txt}"
    );
    assert!(
        !idle_txt.contains("Antigravity App:"),
        "absent desktop app must be omitted from human status:\n{idle_txt}"
    );
    assert!(
        !paths.daemon_lock_file().exists(),
        "read-only status must never create daemon.lock"
    );

    let st_idle_json = env.cli_cmd().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_idle_json.status.code(), Some(0));
    let idle_j: serde_json::Value = serde_json::from_slice(&st_idle_json.stdout).unwrap();
    assert_eq!(idle_j["daemon_state_ok"], true);
    assert_eq!(idle_j["daemon_paused_on_failure"], false);
    assert_eq!(idle_j["daemon_runtime"]["mode"], "not_running");
    assert_eq!(idle_j["daemon_runtime"]["running"], false);
    assert_eq!(idle_j["antigravity_app_probe"]["found"], false);

    // 2. Live manual daemon lock held -> reports `running (manual/foreground...)` in both human and JSON.
    let held_lock = DaemonInstanceLock::try_acquire(&paths).unwrap();
    let st_manual = env.cli_cmd().arg("status").output().unwrap();
    assert_eq!(st_manual.status.code(), Some(0));
    let manual_txt = String::from_utf8_lossy(&st_manual.stdout);
    assert!(
        manual_txt.contains("Daemon state:      running (manual/foreground"),
        "expected manual daemon state:\n{manual_txt}"
    );
    let st_manual_json = env.cli_cmd().args(["--json", "status"]).output().unwrap();
    assert_eq!(st_manual_json.status.code(), Some(0));
    let manual_j: serde_json::Value = serde_json::from_slice(&st_manual_json.stdout).unwrap();
    assert_eq!(manual_j["daemon_runtime"]["mode"], "manual");
    assert_eq!(manual_j["daemon_runtime"]["running"], true);
    drop(held_lock);

    // 3. Installed systemd user unit (active with cooldown + stopped/inactive) using fake systemd marker & stub `systemctl`.
    let fake_marker = env._tmp.path().join("fake-systemd-marker");
    fs::create_dir_all(&fake_marker).unwrap();
    let unit_dir = env._tmp.path().join("xdg_cfg/systemd/user");
    fs::create_dir_all(&unit_dir).unwrap();
    let unit_file = unit_dir.join("agy-switch-cli.service");
    let (unit_body, _) = render_systemd_user_unit(
        &paths,
        Path::new("/usr/bin/agy-switch-cli"),
        &DaemonServiceInstallOptions::default(),
    )
    .unwrap();
    fs::write(&unit_file, &unit_body).unwrap();

    let fake_systemctl = env._tmp.path().join("fake-systemctl");
    let state_flag = env._tmp.path().join("systemctl-active-state.txt");
    let current_pid = std::process::id();
    fs::write(
        &state_flag,
        format!("active\n{current_pid}\n{}\n", unit_file.display()),
    )
    .unwrap();
    let systemctl_call_marker = env._tmp.path().join("systemctl-invoked.marker");
    fs::write(
        &fake_systemctl,
        format!(
            "#!/bin/sh\necho called >> \"{}\"\nSTATE=$(sed -n '1p' \"{}\")\nPID=$(sed -n '2p' \"{}\")\nFRAG=$(sed -n '3p' \"{}\")\nprintf 'FragmentPath=%s\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=%s\\nMainPID=%s\\n' \"$FRAG\" \"$STATE\" \"$PID\"\n",
            systemctl_call_marker.display(),
            state_flag.display(),
            state_flag.display(),
            state_flag.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    // Seed active cooldown so status prints `· cooldown ...`.
    let cd_state = DaemonPersistentState {
        schema_version: STORE_SCHEMA_VERSION,
        cooldown_until: now + 2_520,
        last_phase: "cooldown".into(),
        ..DaemonPersistentState::default()
    };
    repo.with_write_lock(|tx| save_daemon_state_in_tx(tx.paths(), &cd_state))
        .unwrap();

    // 3a. Same-directory live lock held by `MainPID` (verified via synthetic `proc/locks`)
    //     -> `running (systemd service, pid=<current_pid>)`.
    use std::os::unix::fs::MetadataExt;
    let held_svc_lock = DaemonInstanceLock::try_acquire(&paths).unwrap();
    let lock_meta = fs::metadata(paths.daemon_lock_file()).unwrap();
    #[allow(clippy::unnecessary_cast)]
    let lock_maj = libc::major(lock_meta.dev() as libc::dev_t);
    #[allow(clippy::unnecessary_cast)]
    let lock_min = libc::minor(lock_meta.dev() as libc::dev_t);
    let proc_locks_path = env.proc_dir.join("locks");
    fs::write(
        &proc_locks_path,
        format!(
            "1: FLOCK  ADVISORY  WRITE {current_pid} {:02x}:{:02x}:{} 0 EOF\n",
            lock_maj,
            lock_min,
            lock_meta.ino()
        ),
    )
    .unwrap();
    let st_svc = env
        .cli_cmd()
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(st_svc.status.code(), Some(0));
    let svc_txt = String::from_utf8_lossy(&st_svc.stdout);
    assert!(
        svc_txt.contains(&format!(
            "Daemon state:      running (systemd service, pid={current_pid}) · cooldown "
        )),
        "expected active systemd service + cooldown:\n{svc_txt}"
    );
    // When `/proc/locks` cannot confirm lock holder PID, live lock still reports `running=true`
    // without attributing unverified `MainPID`!
    let _ = fs::remove_file(&proc_locks_path);
    let st_svc_nopid = env
        .cli_cmd()
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_svc_nopid.status.code(), Some(0));
    let nopid_j: serde_json::Value = serde_json::from_slice(&st_svc_nopid.stdout).unwrap();
    assert_eq!(nopid_j["daemon_runtime"]["mode"], "manual");
    assert_eq!(nopid_j["daemon_runtime"]["running"], true);
    assert_eq!(nopid_j["daemon_runtime"]["pid"], serde_json::Value::Null);
    drop(held_svc_lock);

    // 3b. P2-02 A->B regression: unit overwritten to point to data dir B while old process on A
    //     keeps A's lock and systemd still reports `ActiveState=active` + `MainPID=<A's PID>`,
    //     but data dir B holds NO lock -> B must report `systemd_stopped`, `running=false`, `pid=null`!
    let data_dir_b = env._tmp.path().join("data_dir_b");
    fs::create_dir_all(&data_dir_b).unwrap();
    let paths_b = HeadlessPaths::with_explicit(
        env.home.clone(),
        data_dir_b.clone(),
        env._tmp.path().join("xdg_cache/agy-switch-cli"),
    );
    // Keep A's lock held while unit still points to A -> B excludes A cleanly.
    let held_a_lock = DaemonInstanceLock::try_acquire(&paths).unwrap();
    let st_b_excl = env
        .cli_cmd_with_data_dir(&data_dir_b)
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_b_excl.status.code(), Some(0));
    let b_excl_j: serde_json::Value = serde_json::from_slice(&st_b_excl.stdout).unwrap();
    assert_eq!(b_excl_j["daemon_runtime"]["mode"], "not_running");
    assert_eq!(b_excl_j["daemon_runtime"]["running"], false);
    assert_eq!(b_excl_j["daemon_runtime"]["systemd_unit_installed"], false);

    // Now overwrite unit to point to B (like `daemon --install` without restart): B still has NO lock!
    let (unit_body_b, _) = render_systemd_user_unit(
        &paths_b,
        Path::new("/usr/bin/agy-switch-cli"),
        &DaemonServiceInstallOptions::default(),
    )
    .unwrap();
    fs::write(&unit_file, &unit_body_b).unwrap();
    let st_b_after_reinstall = env
        .cli_cmd_with_data_dir(&data_dir_b)
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_b_after_reinstall.status.code(), Some(0));
    let b_j: serde_json::Value = serde_json::from_slice(&st_b_after_reinstall.stdout).unwrap();
    assert_eq!(b_j["daemon_runtime"]["mode"], "systemd_stopped");
    assert_eq!(b_j["daemon_runtime"]["running"], false);
    assert_eq!(b_j["daemon_runtime"]["pid"], serde_json::Value::Null);
    assert_eq!(b_j["daemon_runtime"]["systemd_unit_installed"], true);
    assert_eq!(b_j["daemon_runtime"]["systemd_active_state"], "active");
    let st_b_human = env
        .cli_cmd_with_data_dir(&data_dir_b)
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(st_b_human.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&st_b_human.stdout).contains(
            "Daemon state:      stopped (systemd service active, no lock held here; ready for --once)"
        ),
        "unexpected A->B human status:\n{}",
        String::from_utf8_lossy(&st_b_human.stdout)
    );

    // 3c. P2-02 FragmentPath pointing to a non-existent file must degrade cleanly (`manager unreachable`),
    //     never reporting running=true!
    fs::write(
        &state_flag,
        format!(
            "active\n{current_pid}\n{}/nonexistent.service\n",
            unit_dir.display()
        ),
    )
    .unwrap();
    let st_b_missing_frag = env
        .cli_cmd_with_data_dir(&data_dir_b)
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_b_missing_frag.status.code(), Some(0));
    let mf_j: serde_json::Value = serde_json::from_slice(&st_b_missing_frag.stdout).unwrap();
    assert_eq!(mf_j["daemon_runtime"]["mode"], "systemd_stopped");
    assert_eq!(mf_j["daemon_runtime"]["running"], false);
    assert_eq!(
        mf_j["daemon_runtime"]["systemd_active_state"],
        serde_json::Value::Null
    );

    // 3d. P2-02 Disk unit missing `AGY_SWITCH_CLI_DATA_DIR=` must NOT claim ownership and must NOT invoke systemctl!
    let _ = fs::remove_file(&systemctl_call_marker);
    fs::write(
        &unit_file,
        "[Unit]\nDescription=Foreign\n[Service]\nExecStart=/bin/true\n",
    )
    .unwrap();
    let st_b_foreign = env
        .cli_cmd_with_data_dir(&data_dir_b)
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_b_foreign.status.code(), Some(0));
    let foreign_j: serde_json::Value = serde_json::from_slice(&st_b_foreign.stdout).unwrap();
    assert_eq!(foreign_j["daemon_runtime"]["mode"], "not_running");
    assert_eq!(foreign_j["daemon_runtime"]["systemd_unit_installed"], false);
    assert!(
        !systemctl_call_marker.exists(),
        "unowned unit without AGY_SWITCH_CLI_DATA_DIR must not invoke systemctl"
    );
    drop(held_a_lock);

    // Restore unit for A and switch stub to `inactive` -> reports `stopped (systemd service inactive; ready for --once)`.
    fs::write(&unit_file, &unit_body).unwrap();
    fs::write(
        &state_flag,
        format!("inactive\n0\n{}\n", unit_file.display()),
    )
    .unwrap();
    let st_stopped = env
        .cli_cmd()
        .env(SYSTEMD_MARKER_DIR_ENV, &fake_marker)
        .env(SYSTEMCTL_BIN_ENV, &fake_systemctl)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(st_stopped.status.code(), Some(0));
    let stopped_j: serde_json::Value = serde_json::from_slice(&st_stopped.stdout).unwrap();
    assert_eq!(stopped_j["daemon_runtime"]["mode"], "systemd_stopped");
    assert_eq!(stopped_j["daemon_runtime"]["running"], false);
    assert_eq!(stopped_j["daemon_runtime"]["systemd_unit_installed"], true);
    assert_eq!(
        stopped_j["daemon_runtime"]["systemd_active_state"],
        "inactive"
    );

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
fn synthetic_v125_r405_systemd_edge_states_and_install_active_state() {
    use std::os::unix::fs::PermissionsExt;

    let env = IsolatedEnv::new();
    let marker_dir = env._tmp.path().join("r405_run_systemd_system");
    let cfg_home = env._tmp.path().join("r405_xdg_cfg");
    fs::create_dir_all(&marker_dir).unwrap();
    fs::create_dir_all(&cfg_home).unwrap();
    let unit_file = cfg_home.join("systemd/user/agy-switch-cli.service");

    let write_mock_ctl = |name: &str, script: String| -> PathBuf {
        let path = env._tmp.path().join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    };

    // 1. Install reporting `UnitFileState=linked` + `ActiveState=active` MUST fail closed (`systemctl_verify_failed`).
    let linked_ctl = write_mock_ctl(
        "systemctl_linked",
        "#!/bin/sh\n\
         UNIT_FILE=\"$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"\n\
         if [ \"$2\" = \"show\" ]; then\n\
           printf 'FragmentPath=%s\\nLoadState=loaded\\nUnitFileState=linked\\nActiveState=active\\n' \"$UNIT_FILE\"\n\
         fi\n\
         exit 0\n"
            .into(),
    );
    let linked_out = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &linked_ctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(
        linked_out.status.code(),
        Some(1),
        "UnitFileState=linked must be rejected; stdout={} stderr={}",
        String::from_utf8_lossy(&linked_out.stdout),
        String::from_utf8_lossy(&linked_out.stderr)
    );
    let linked_err: serde_json::Value = serde_json::from_slice(&linked_out.stderr).unwrap();
    assert_eq!(linked_err["error_code"], "systemctl_verify_failed");

    // 2. Install reporting `UnitFileState=enabled` + `ActiveState=activating` succeeds cleanly
    //    WITHOUT falsely reporting `enabled_and_started=true`, distinguishing `activating` in JSON & text.
    let activating_ctl = write_mock_ctl(
        "systemctl_activating",
        "#!/bin/sh\n\
         UNIT_FILE=\"$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"\n\
         if [ \"$2\" = \"show\" ]; then\n\
           printf 'FragmentPath=%s\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=activating\\n' \"$UNIT_FILE\"\n\
         fi\n\
         exit 0\n"
            .into(),
    );
    let act_json = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &activating_ctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(
        act_json.status.code(),
        Some(0),
        "activating install json failed: stderr={}",
        String::from_utf8_lossy(&act_json.stderr)
    );
    let act_v: serde_json::Value = serde_json::from_slice(&act_json.stdout).unwrap();
    assert_eq!(act_v["enabled_and_started"], false);
    assert_eq!(act_v["active_state"], "activating");

    let act_text = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &activating_ctl)
        .args(["daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(act_text.status.code(), Some(0));
    let act_stdout = String::from_utf8_lossy(&act_text.stdout);
    assert!(
        !act_stdout.contains("Installed and started"),
        "activating human output must not claim started: {act_stdout}"
    );
    assert!(
        act_stdout.contains("Installed and enabled")
            && act_stdout.contains("currently `activating`"),
        "activating human output must clarify starting state: {act_stdout}"
    );

    // 3. Normal `UnitFileState=enabled` + `ActiveState=active` keeps `enabled_and_started=true` & `active_state="active"`.
    let active_ctl = write_mock_ctl(
        "systemctl_active_ok",
        "#!/bin/sh\n\
         UNIT_FILE=\"$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service\"\n\
         if [ \"$2\" = \"show\" ]; then\n\
           printf 'FragmentPath=%s\\nLoadState=loaded\\nUnitFileState=enabled\\nActiveState=active\\n' \"$UNIT_FILE\"\n\
         fi\n\
         exit 0\n"
            .into(),
    );
    let ok_json = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &active_ctl)
        .args(["--json", "daemon", "--install"])
        .output()
        .unwrap();
    assert_eq!(ok_json.status.code(), Some(0));
    let ok_v: serde_json::Value = serde_json::from_slice(&ok_json.stdout).unwrap();
    assert_eq!(ok_v["enabled_and_started"], true);
    assert_eq!(ok_v["active_state"], "active");
    assert!(unit_file.exists());

    // 4. Uninstall with local unit PRESENT, `LoadState=not-found`, empty `FragmentPath`, and `ActiveState=active`/`activating`
    //    MUST refuse without invoking `disable --now` or deleting the local unit file.
    for (tag, load_state, active_state) in [
        ("notfound_active", "not-found", "active"),
        ("notfound_activating", "not-found", "activating"),
        ("loaded_nofrag_inactive", "loaded", "inactive"),
        ("empty_show_output", "", ""),
    ] {
        let disable_marker = env._tmp.path().join(format!("r405_disable_called_{tag}"));
        let ctl = write_mock_ctl(
            &format!("systemctl_uninst_{tag}"),
            format!(
                "#!/bin/sh\n\
                 if [ \"$2\" = \"disable\" ]; then\n\
                   echo called > \"{}\"\n\
                 elif [ \"$2\" = \"show\" ]; then\n\
                   printf 'FragmentPath=\\nLoadState={load_state}\\nUnitFileState=\\nActiveState={active_state}\\n'\n\
                 fi\n\
                 exit 0\n",
                disable_marker.display()
            ),
        );
        let res = env
            .cli_cmd()
            .env("XDG_CONFIG_HOME", &cfg_home)
            .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
            .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &ctl)
            .args(["--json", "daemon", "--uninstall"])
            .output()
            .unwrap();
        assert_eq!(
            res.status.code(),
            Some(1),
            "uninstall ({tag}) must fail closed when unit identity is unverified; stdout={} stderr={}",
            String::from_utf8_lossy(&res.stdout),
            String::from_utf8_lossy(&res.stderr)
        );
        assert!(
            !disable_marker.exists(),
            "uninstall ({tag}) must NEVER invoke `disable --now` on an unverified unit"
        );
        assert!(
            unit_file.exists(),
            "uninstall ({tag}) must keep local unit file intact on refusal"
        );
    }

    // 5. Uninstall with local unit PRESENT, `LoadState=not-found`, empty `FragmentPath`, and `ActiveState=inactive`
    //    skips blind `disable --now`, safely removes the pinned local unit file, and runs `daemon-reload`.
    let cleanup_log = env._tmp.path().join("r405_cleanup_calls.log");
    let cleanup_ctl = write_mock_ctl(
        "systemctl_uninst_notfound_inactive",
        format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{}\"\n\
             if [ \"$2\" = \"show\" ]; then\n\
               printf 'FragmentPath=\\nLoadState=not-found\\nUnitFileState=\\nActiveState=inactive\\n'\n\
             fi\n\
             exit 0\n",
            cleanup_log.display()
        ),
    );
    let clean_out = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &cleanup_ctl)
        .args(["--json", "daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(
        clean_out.status.code(),
        Some(0),
        "idempotent uninstall of inactive not-found unit failed: stderr={}",
        String::from_utf8_lossy(&clean_out.stderr)
    );
    let clean_v: serde_json::Value = serde_json::from_slice(&clean_out.stdout).unwrap();
    assert_eq!(clean_v["removed_unit_file"], true);
    assert!(!unit_file.exists());
    let calls = fs::read_to_string(&cleanup_log).unwrap();
    assert!(
        !calls.contains("disable --now"),
        "not-found+inactive uninstall must skip blind `disable --now`: {calls}"
    );
    assert!(
        calls.contains("--user daemon-reload"),
        "not-found+inactive uninstall must still run `daemon-reload`: {calls}"
    );

    // Human text mode for `not-found + inactive` states factual removal without claiming stop/disable ran.
    fs::write(&unit_file, "[Unit]\nDescription=SyntheticLeftover\n").unwrap();
    let clean_human = env
        .cli_cmd()
        .env("XDG_CONFIG_HOME", &cfg_home)
        .env("AGY_SWITCH_CLI_SYSTEMD_MARKER_DIR", &marker_dir)
        .env("AGY_SWITCH_CLI_SYSTEMCTL_BIN", &cleanup_ctl)
        .args(["daemon", "--uninstall"])
        .output()
        .unwrap();
    assert_eq!(clean_human.status.code(), Some(0));
    let clean_stdout = String::from_utf8_lossy(&clean_human.stdout);
    assert!(
        clean_stdout.contains("Removed user service `agy-switch-cli.service`")
            && !clean_stdout.contains("Stopped, disabled"),
        "human uninstall output must state factual removal without claiming stop/disable: {clean_stdout}"
    );
    assert!(!unit_file.exists());
}

#[cfg(feature = "stats")]
#[test]
fn synthetic_v125_stats_cleared_canceled_interrupted_cli_contract() {
    let env = IsolatedEnv::new();
    let cli_conv = env.home.join(".gemini/antigravity-cli/conversations");
    fs::create_dir_all(&cli_conv).unwrap();

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

    let make_blob =
        |out_tok: u64, ttft_s: u64, stream_s: u64, ts: u64, err: Option<&[u8]>| -> Vec<u8> {
            let usage = [pb_v(1, 300), pb_v(2, 200), pb_v(3, out_tok), pb_v(5, 1_500)].concat();
            let timing = pb_b(4, &pb_v(1, ts));
            let wrapped = [
                pb_b(4, &usage),
                pb_b(9, &timing),
                pb_b(11, &pb_v(1, ttft_s)),
                pb_b(12, &pb_v(1, stream_s)),
                pb_b(19, b"gemini-3.1-pro"),
                pb_b(21, b"Gemini 3.1 Pro (High)"),
            ]
            .concat();
            let mut outer = pb_b(1, &wrapped);
            if let Some(e) = err {
                outer.extend(pb_b(5, e));
            }
            outer
        };

    let t0 = "2026-11-21T09:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second() as u64;
    let valid_payload = pb_b(20, &pb_b(1, b"done"));
    let db_path = cli_conv.join("status_split.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
         CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
    )
    .unwrap();
    for (idx, status, out_tok, err) in [
        (1i64, 12i64, 400u64, None),
        (2, 6, 400, None),
        (3, 5, 400, Some(&b"upstream_failed"[..])),
        (4, 5, 480, None),
        (5, 3, 240, None),
    ] {
        conn.execute(
            "INSERT INTO steps VALUES (?1, 15, NULL, ?2, ?3)",
            rusqlite::params![idx, status, &valid_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (?1, ?2)",
            rusqlite::params![idx, make_blob(out_tok, 2, 4, t0 + (idx as u64) * 10, err)],
        )
        .unwrap();
    }
    drop(conn);

    // 1. `stats list --range all --json`
    let list_json = env
        .cli_cmd()
        .args(["--json", "stats", "list", "--range", "all"])
        .output()
        .unwrap();
    assert_eq!(
        list_json.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&list_json.stderr)
    );
    let lj: serde_json::Value = serde_json::from_slice(&list_json.stdout).unwrap();
    let items = lj["items"].as_array().unwrap();
    assert_eq!(items.len(), 5);
    assert_eq!(items[0]["status"], "ok");
    assert_eq!(items[0]["output_tps"].as_f64().unwrap().round() as u64, 60);
    assert_eq!(items[1]["status"], "cleared");
    assert_eq!(items[1]["output_tps"].as_f64().unwrap().round() as u64, 120);
    assert_eq!(items[2]["status"], "error");
    assert!(items[2]["output_tps"].is_null());
    assert_eq!(items[3]["status"], "canceled");
    assert!(items[3]["output_tps"].is_null());
    assert_eq!(items[4]["status"], "interrupted");
    assert!(items[4]["output_tps"].is_null());

    // 2. `stats summary --range all --json` shares the exact 2 eligible TPS samples (`3` and clean `5`)
    let sum_json = env
        .cli_cmd()
        .args(["--json", "stats", "summary", "--range", "all"])
        .output()
        .unwrap();
    assert_eq!(sum_json.status.code(), Some(0));
    let sj: serde_json::Value = serde_json::from_slice(&sum_json.stdout).unwrap();
    assert_eq!(sj["performance"]["sample_count"], 2);
    assert_eq!(
        sj["performance"]["output_tps"]["p50"]
            .as_f64()
            .unwrap()
            .round() as u64,
        90
    );

    // 3. Human `stats list --range all` shows `ok`, `clr`, `err`, `canc`, `intr`
    let list_text = env
        .cli_cmd()
        .args(["stats", "list", "--range", "all"])
        .output()
        .unwrap();
    assert_eq!(list_text.status.code(), Some(0));
    let txt = String::from_utf8_lossy(&list_text.stdout);
    for tok in [" ok", " clr", " err", " canc", " intr", " 120 ", " 60 "] {
        assert!(txt.contains(tok), "missing `{tok}` in stats list:\n{txt}");
    }
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
    assert_eq!(
        rec_a
            .quota
            .as_ref()
            .and_then(|q| q.subscription_tier.as_deref()),
        Some("g1-pro-tier")
    );

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
    assert_eq!(q_json["quota"]["subscription_tier"], "g1-ultra-tier");
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

    //    6e. Pre-Switch Sync-Back preserves `user_tier` written by official `agy` onto outgoing account!
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
    assert_eq!(
        bob_synced
            .quota
            .as_ref()
            .and_then(|q| q.subscription_tier.as_deref()),
        Some("g1-pro-tier")
    );

    //    6f. Upgrade from v1.2.6 (`tier_source_env == Some(Production)`) across `switch` (which
    //        serializes without `user_tier`) + `quota --refresh` (`OfficialCli`):
    //        - Upgraded Pro account retains its `Plan` / `subscription_tier`;
    //        - Upgraded Free account with weekly-only `/usage` buckets (no `5h` bucket) retains its
    //          Free tier and evaluates to `Known` (exit 0) instead of `Unknown("missing_5h_bucket")`!
    let free_weekly_only_agy = env.home.join("fake-agy-free-weekly.sh");
    fs::write(
        &free_weekly_only_agy,
        r#"#!/bin/sh
cat <<'EOF'
{"conversation_id":"","status":"SUCCESS","response":"ok","duration_seconds":0,"num_turns":0,"usage":{"input_tokens":0,"output_tokens":0,"thinking_tokens":0,"cache_read_tokens":0,"total_tokens":0},"command":{"name":"usage","data":{"description":"Free tier summary","groups":[{"name":"Gemini Models","description":"Gemini family","buckets":[{"id":"gemini-weekly","name":"Weekly Limit Remaining","window":"weekly","remaining_fraction":0.84,"reset_time":"2099-12-03T07:17:01Z"}]}]}}}
EOF
exit 0
"#,
    )
    .unwrap();
    fs::set_permissions(&free_weekly_only_agy, fs::Permissions::from_mode(0o755)).unwrap();

    // Seed Bob as a v1.2.6 Production Free account and Alice as a v1.2.6 Production Pro account.
    repo.with_write_lock(|tx| {
        let mut bob_rec = tx.load_account_opt("acc-0002")?.unwrap();
        let mut v126_free = agy_switch_cli::domain::quota::QuotaObservation::new(
            1_700_000_000,
            agy_switch_cli::domain::quota::QuotaSourceEnv::Production,
        );
        v126_free.subscription_tier = Some("FREE".into());
        v126_free.tier_source_env = Some(agy_switch_cli::domain::quota::QuotaSourceEnv::Production);
        bob_rec.quota = Some(v126_free);
        tx.save_account(&bob_rec)?;

        let mut alice_rec = tx.load_account_opt(&acc_a_id)?.unwrap();
        let mut v126_pro = agy_switch_cli::domain::quota::QuotaObservation::new(
            1_700_000_000,
            agy_switch_cli::domain::quota::QuotaSourceEnv::Production,
        );
        v126_pro.subscription_tier = Some("PRO".into());
        v126_pro.tier_source_env = Some(agy_switch_cli::domain::quota::QuotaSourceEnv::Production);
        alice_rec.quota = Some(v126_pro);
        tx.save_account(&alice_rec)?;
        Ok(())
    })
    .unwrap();

    let slot_file = paths.active_slot_file.clone();
    // Simulate a legacy v1.2.6 slot (no `user_tier`) before switching out of Alice so Pre-Switch
    // Sync-Back does not carry step 6e's older `"g1-ultra-tier"` over onto the freshly seeded v1.2.6 record.
    let mut alice_pre_slot_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&slot_file).unwrap()).unwrap();
    alice_pre_slot_json
        .as_object_mut()
        .unwrap()
        .remove("user_tier");
    fs::write(
        &slot_file,
        serde_json::to_vec(&alice_pre_slot_json).unwrap(),
    )
    .unwrap();
    // Switch to Bob, then strip `user_tier` from the slot to verify pure Production->OfficialCli
    // inheritance even when the slot carries no `user_tier`, and run `quota --refresh` with weekly-only buckets.
    assert_eq!(
        env.cli_cmd()
            .args(["switch", "acc-0002"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let mut bob_slot_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&slot_file).unwrap()).unwrap();
    bob_slot_json.as_object_mut().unwrap().remove("user_tier");
    fs::write(&slot_file, serde_json::to_vec(&bob_slot_json).unwrap()).unwrap();
    let free_q = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &free_weekly_only_agy)
        .args(["--json", "quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(
        free_q.status.code(),
        Some(0),
        "upgraded Free account with weekly-only buckets must evaluate Known (exit 0), stderr={}",
        String::from_utf8_lossy(&free_q.stderr)
    );
    let free_q_json: serde_json::Value = serde_json::from_slice(&free_q.stdout).unwrap();
    assert_eq!(free_q_json["evaluation"]["status"], "known");
    assert_eq!(free_q_json["quota"]["subscription_tier"], "FREE");

    // Switch to Alice, strip `user_tier` to test pure Production->OfficialCli inheritance, and run `quota --refresh`: Pro Plan preserved!
    assert_eq!(
        env.cli_cmd()
            .args(["switch", &acc_a_id])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let mut alice_slot_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&slot_file).unwrap()).unwrap();
    alice_slot_json.as_object_mut().unwrap().remove("user_tier");
    fs::write(&slot_file, serde_json::to_vec(&alice_slot_json).unwrap()).unwrap();
    fs::write(&adv_mode, "ok").unwrap();
    let pro_q = env
        .cli_cmd()
        .env("AGY_SWITCH_CLI_AGY_BIN", &adv_agy)
        .args(["--json", "quota", "--refresh"])
        .output()
        .unwrap();
    assert_eq!(
        pro_q.status.code(),
        Some(0),
        "upgraded Pro account quota --refresh failed, stderr={}",
        String::from_utf8_lossy(&pro_q.stderr)
    );
    let pro_q_json: serde_json::Value = serde_json::from_slice(&pro_q.stdout).unwrap();
    assert_eq!(pro_q_json["quota"]["subscription_tier"], "PRO");

    // 7. S4 compact 1.5+ payload round-trip (`accounts add --from-local` -> `switch` ->
    //    `accounts add --from-local` again, offline, zero network) + S3 AT/expiry pairing +
    //    S5 Production->PRO tier upgrade + S6 empty-groups SUCCESS benign stderr isolation:
    //    7a. S4: compact payload with `id_token_email` & `user_tier` and NO `id_token` survives `switch`
    //        and remains directly re-importable offline!
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
    assert_eq!(imp1_json["account"]["quota"]["subscription_tier"], "PRO");

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
    assert_eq!(rewritten_slot["user_tier"], "PRO");

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

    //    7b. S3 CLI regression: same RT, fresher stored AT/expiry (`2050000000`), older slot AT
    //        (`1700000000`) + newly added synthetic `id_token` -> `switch` MUST keep fresher stored
    //        AT & expiry while merging `id_token`!
    repo.with_write_lock(|tx| {
        let mut r = tx.load_account_opt(&s4_id)?.unwrap();
        r.token.access_token = "ya29.s3_fresher_store".into();
        r.token.expiry_timestamp = 2_050_000_000;
        r.token.id_token = None;
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

    //    7c. S5 CLI regression: v1.2.6 `Production/FREE` account whose active slot carries `PRO`
    //        updates to `PRO` / `OfficialCli` on `switch` out AND on `accounts add --from-local`
    //        WITHOUT altering `source_env` or `last_updated`!
    repo.with_write_lock(|tx| {
        let mut r = tx.load_account_opt(&s4_id)?.unwrap();
        let mut prod_free = agy_switch_cli::domain::quota::QuotaObservation::new(
            1_700_000_123,
            agy_switch_cli::domain::quota::QuotaSourceEnv::Production,
        );
        prod_free.subscription_tier = Some("FREE".into());
        prod_free.tier_source_env = Some(agy_switch_cli::domain::quota::QuotaSourceEnv::Production);
        r.quota = Some(prod_free);
        tx.save_account(&r)?;
        Ok(())
    })
    .unwrap();
    fs::write(&slot_file, serde_json::to_vec(&compact_slot).unwrap()).unwrap();
    assert_eq!(
        env.cli_cmd()
            .args(["switch", "acc-0002"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let s4_after_s5 = repo.read_account_unchecked(&s4_id).unwrap();
    let q_s5 = s4_after_s5.quota.as_ref().unwrap();
    assert_eq!(q_s5.subscription_tier.as_deref(), Some("PRO"));
    assert_eq!(
        q_s5.tier_source_env,
        Some(agy_switch_cli::domain::quota::QuotaSourceEnv::OfficialCli)
    );
    assert_eq!(
        q_s5.source_env,
        agy_switch_cli::domain::quota::QuotaSourceEnv::Production
    );
    assert_eq!(q_s5.last_updated, 1_700_000_123);

    // Also verify `accounts add --from-local` overrides stale `Production/FREE` -> `PRO`.
    repo.with_write_lock(|tx| {
        let mut r = tx.load_account_opt(&s4_id)?.unwrap();
        let mut prod_free = agy_switch_cli::domain::quota::QuotaObservation::new(
            1_700_000_456,
            agy_switch_cli::domain::quota::QuotaSourceEnv::Production,
        );
        prod_free.subscription_tier = Some("FREE".into());
        prod_free.tier_source_env = Some(agy_switch_cli::domain::quota::QuotaSourceEnv::Production);
        r.quota = Some(prod_free);
        tx.save_account(&r)?;
        Ok(())
    })
    .unwrap();
    fs::write(&slot_file, serde_json::to_vec(&compact_slot).unwrap()).unwrap();
    assert_eq!(
        env.cli_cmd()
            .args(["accounts", "add", "--from-local"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let s4_after_imp_s5 = repo.read_account_unchecked(&s4_id).unwrap();
    let q_imp_s5 = s4_after_imp_s5.quota.as_ref().unwrap();
    assert_eq!(q_imp_s5.subscription_tier.as_deref(), Some("PRO"));
    assert_eq!(
        q_imp_s5.tier_source_env,
        Some(agy_switch_cli::domain::quota::QuotaSourceEnv::OfficialCli)
    );
    assert_eq!(
        q_imp_s5.source_env,
        agy_switch_cli::domain::quota::QuotaSourceEnv::Production
    );
    assert_eq!(q_imp_s5.last_updated, 1_700_000_456);

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

    // Parity check via `accounts add --from-local` from identical initial state: also persists (1, 0).
    let r202_slot_missing_expiry_2 = serde_json::json!({
        "token": {
            "access_token": "ya29.r202_new_at_no_expiry_2",
            "token_type": "Bearer",
            "refresh_token": "1//RT_R202_ROTATED_2"
        },
        "auth_method": "consumer",
        "id_token_email": "compact-rt@example.com"
    });
    repo.with_write_lock(|tx| {
        let mut r = tx.load_account_opt(&s4_id)?.unwrap();
        r.token.access_token = "ya29.r202_old_at_2".into();
        r.token.expiry_timestamp = 2_050_000_000;
        r.token.expires_in = 3600;
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
}
