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
    let now = chrono::Utc::now().timestamp();

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
        vec!["doctor", "--json"],
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
    let now = chrono::Utc::now().timestamp();
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
        vec!["doctor", "--json"],
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
    let now = chrono::Utc::now().timestamp();

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

    // 1b. Oversized `--stdin` (> 16 KiB) fails cleanly with exit code 2 via bounded reader
    let mut big_child = env
        .cli_cmd()
        .args(["accounts", "add", "--stdin", "--json"])
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

    // 2. Pipe without `--stdin` refuses interactive secret entry when stdin is not a TTY
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
        .args(["policy", "set", "--reserve", "15"])
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

    // Refuses to overwrite existing export file without `--force`
    let exp_no_force = env
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
    assert_eq!(exp_no_force.status.code(), Some(2));

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
    let now = chrono::Utc::now().timestamp();
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

    // Send 'j' (move cursor down -> acc-2), 's' (switch to acc-2), then Ctrl+C (`\x03`) to quit!
    master.write_all(b"j").unwrap();
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
    let now = chrono::Utc::now().timestamp();
    let repo = StoreRepository::new(env.paths());
    let acc = sample_account("acc-ss", "ss@example.invalid", now);
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    // IsolatedEnv points DBUS_SESSION_BUS_ADDRESS to `<tmp>/run/no-dbus` (unreachable),
    // guaranteeing zero contact with the host's real D-Bus session while exercising `SecretServiceSessionBackend`!
    let out = env
        .cli_cmd()
        .args(["--backend", "secret-service", "--json", "switch", "acc-ss"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(8),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err_json: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err_json["exit_code"], 8);

    // Read-only `status` and `doctor` with `--backend secret-service` must succeed (exit code 0)
    // reporting `unverified` session identity without unlocking/mutating keyring or creating files!
    for ro_args in [
        vec!["--backend", "secret-service", "--json", "current"],
        vec!["--backend", "secret-service", "--json", "doctor"],
    ] {
        let ro_out = env.cli_cmd().args(&ro_args).output().unwrap();
        assert_eq!(
            ro_out.status.code(),
            Some(0),
            "ro_args={ro_args:?} stderr={}",
            String::from_utf8_lossy(&ro_out.stderr)
        );
        let ro_json: serde_json::Value = serde_json::from_slice(&ro_out.stdout).unwrap();
        assert_eq!(ro_json["session_identity"]["state"], "unverified");
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
    let now = chrono::Utc::now().timestamp();
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
    //    MUST fall back cleanly to `file_session` (simulating a headless SSH server with systemd user D-Bus)!
    let doc_headless_bus = env
        .cli_cmd()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .args(["--json", "doctor"])
        .output()
        .unwrap();
    assert_eq!(doc_headless_bus.status.code(), Some(0));
    let doc_hb_j: serde_json::Value = serde_json::from_slice(&doc_headless_bus.stdout).unwrap();
    assert_eq!(doc_hb_j["backend"], "file_session");

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
            .args(["--backend", "secret-service"]);
        c
    };

    // 1. Locked collection (`login_locked: true`): read-only `status` & `doctor` report `unverified`
    //    AND `unlock_calls` MUST remain strictly ZERO!
    for ro_sub in ["current", "doctor"] {
        let out = ss_cli().args(["--json", ro_sub]).output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(j["session_identity"]["state"], "unverified");
        assert!(
            j["session_identity"]["detail"]
                .as_str()
                .unwrap_or("")
                .contains("keyring is locked"),
            "Expected locked keyring detail, got: {j}"
        );
    }
    let st1: serde_json::Value = serde_json::from_slice(&fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(
        st1["unlock_calls"], 0,
        "Read-only status/doctor MUST NEVER call Unlock on locked collection!"
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
    //    `status` & `doctor` MUST report `unverified` with ZERO `Unlock` calls (`unlock_calls` stays 1)!
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

    // 4. Inject conflicting duplicate item in `default` collection -> `doctor` reports Corrupt (exit code 1)!
    fs::write(
        &ctrl_file,
        r#"{"login_locked": false, "item_locked": false, "inject_conflict": true, "fail_create_from_call": -1}"#,
    )
    .unwrap();
    let doc_conflict = ss_cli().args(["--json", "doctor"]).output().unwrap();
    assert_eq!(doc_conflict.status.code(), Some(1));

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

        let doc_auto = auto_cli().args(["--json", "doctor"]).output().unwrap();
        assert_eq!(doc_auto.status.code(), Some(0));
        let doc_auto_j: serde_json::Value = serde_json::from_slice(&doc_auto.stdout).unwrap();
        assert_eq!(doc_auto_j["backend"], "secret_service_dual");
        assert!(doc_auto_j["dbus_keyring_warning"].is_null());

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
        let doc_cfg_file = auto_cli().args(["--json", "doctor"]).output().unwrap();
        assert_eq!(doc_cfg_file.status.code(), Some(0));
        let doc_cf_j: serde_json::Value = serde_json::from_slice(&doc_cfg_file.stdout).unwrap();
        assert_eq!(doc_cf_j["backend"], "file_session");
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
    let now = chrono::Utc::now().timestamp();
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

    // 2. `doctor` human output similarly omits internal ID on `Session identity:` and formats `YYYY-MM-DD HH:MM`.
    let doc_human = env.cli_cmd().arg("doctor").output().unwrap();
    assert_eq!(doc_human.status.code(), Some(0));
    let doc_txt = String::from_utf8_lossy(&doc_human.stdout);
    assert!(doc_txt.contains(&format!(
        "Session identity:  matched (alice@example.invalid, expires {expected_exp_local})"
    )));

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
        assert!(initial_txt.contains("r/R refresh | c/C cand"));

        // Press 'C' -> adds both enabled accounts (`acc-ts-1`, `acc-ts-2`) in list order; then 'p' -> enables policy!
        master.write_all(b"Cp").unwrap();
        master.flush().unwrap();
        for _ in 0..40 {
            if repo.read_policy().unwrap().enabled {
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

        // Press 'j' then 'd' to disable `acc-ts-2` -> TUI renders `cand #2 (skip)`!
        screen.clear();
        master.write_all(b"jd").unwrap();
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
            let p = repo.read_policy().unwrap();
            if p.candidate_account_ids.is_empty() && !p.enabled {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let pol_cleared = repo.read_policy().unwrap();
        assert!(pol_cleared.candidate_account_ids.is_empty());
        assert!(!pol_cleared.enabled);

        // Boundary check: disable BOTH accounts ('dkd'), then press 'R' and 'C' -> clean status notices with 0 network calls!
        screen.clear();
        master.write_all(b"dkdR").unwrap();
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

        // Re-enable both accounts ('eje') and quit cleanly with 'q'
        master.write_all(b"ejeq").unwrap();
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
