use agy_switch_cli::domain::account::{AccountRecord, DisableReasonCode};
use agy_switch_cli::domain::clock::ManualClock;
use agy_switch_cli::domain::policy::{PolicyMode, PolicyStrategy, SwitchPolicy};
use agy_switch_cli::domain::quota::{
    evaluate_quota_observation, QuotaObservation, QuotaSourceEnv, DEFAULT_QUOTA_MAX_AGE_SECS,
};
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::error::ExitCode;
use agy_switch_cli::oauth::flow::{
    build_authorization_session, validate_callback_url, validate_callback_url_with_port,
    GOOGLE_AUTH_URL,
};
use agy_switch_cli::oauth::refresh::{
    bootstrap_and_persist_refresh_token, complete_login_exchange_locked,
    complete_reauthorize_exchange_locked, ensure_account_token_fresh_locked, OAuthEndpoints,
};
use agy_switch_cli::oauth::registry::OAuthClientRegistry;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::quota::official_cli::{
    refresh_active_slot_quota_with_runner, OfficialCliQuotaError, OfficialCliQuotaRunner,
    OfficialCliUsageOutcome,
};
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend, SlotInspectState};
use agy_switch_cli::session::journal::{read_journal_readonly, reconcile_journal_locked};
use agy_switch_cli::session::payload::serialize_session_payload;
use agy_switch_cli::session::process::observe_runtime_state;
use agy_switch_cli::store::locks::{
    with_account_refresh_lock, with_store_write_lock, ActiveSlotLock,
};
use agy_switch_cli::store::repository::StoreRepository;
use agy_switch_cli::store::transfer::{export_transfer_bundle_file, import_transfer_bundle_file};
use agy_switch_cli::switching::daemon::{DaemonConfigOverrides, DaemonEngine, TickStageOutcome};
use agy_switch_cli::switching::executor::execute_switch_with_slot_lock;
use agy_switch_cli::transport::client::{
    BoxFuture, HttpRequest, HttpResponse, HttpTransport, MockTransport, TimeoutClass,
    TransportError,
};
use agy_switch_cli::transport::proxy::ProxyMode;
use serde_json::json;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use url::Url;

static ENV_MUTEX: AsyncMutex<()> = AsyncMutex::const_new(());

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

struct KillChildOnDrop(Option<std::process::Child>);

impl KillChildOnDrop {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    fn as_mut(&mut self) -> &mut std::process::Child {
        self.0.as_mut().expect("child active")
    }

    fn take(&mut self) -> std::process::Child {
        self.0.take().expect("child active")
    }
}

impl Drop for KillChildOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct IsolatedHarness {
    pub tmp: TempDir,
    pub home: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub proc_dir: PathBuf,
}

impl IsolatedHarness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data_dir = tmp.path().join("data");
        let cache_dir = tmp.path().join("cache");
        let runtime_dir = tmp.path().join("run");
        let proc_dir = tmp.path().join("proc");
        fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
        fs::set_permissions(
            home.join(".gemini/antigravity-cli"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::create_dir_all(&proc_dir).unwrap();
        Self {
            tmp,
            home,
            data_dir,
            cache_dir,
            runtime_dir,
            proc_dir,
        }
    }

    fn paths(&self) -> HeadlessPaths {
        HeadlessPaths::with_explicit(
            self.home.clone(),
            self.data_dir.clone(),
            self.cache_dir.join("agy-switch-cli"),
        )
    }

    fn cli(&self) -> Command {
        self.cli_for_data_dir(&self.data_dir)
    }

    fn cli_for_data_dir(&self, data_dir: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self.tmp.path().join("xdg_data"))
            .env("XDG_CACHE_HOME", &self.cache_dir)
            .env("XDG_CONFIG_HOME", self.tmp.path().join("xdg_cfg"))
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", self.runtime_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &self.proc_dir)
            .env(
                "AGY_SWITCH_CLI_AGY_BIN",
                self.tmp.path().join("no-host-agy"),
            )
            .env("NO_PROXY", "*")
            .env("AGY_SWITCH_CLI_PROXY", "direct")
            .args(["--data-dir", data_dir.to_str().unwrap()]);
        c
    }
}

fn make_acc(id: &str, email: &str, rt: &str, expiry: i64, now: i64) -> AccountRecord {
    AccountRecord::new(
        id.into(),
        email.into(),
        TokenRecord {
            access_token: format!("ya29.AT_{id}"),
            refresh_token: rt.into(),
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
        },
        now,
    )
}

fn fast_oauth() -> OAuthEndpoints {
    OAuthEndpoints {
        base_backoff: Duration::from_millis(5),
        ..OAuthEndpoints::default()
    }
}

type AuditSlotUsageFn = dyn Fn(&HeadlessPaths, bool, &str) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError>
    + Send
    + Sync;

struct AuditSlotQuotaRunner {
    handler: Arc<AuditSlotUsageFn>,
}

impl AuditSlotQuotaRunner {
    fn from_handler<F>(f: F) -> Self
    where
        F: Fn(&HeadlessPaths, bool, &str) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            handler: Arc::new(f),
        }
    }
}

impl OfficialCliQuotaRunner for AuditSlotQuotaRunner {
    fn query_active_usage<'a>(
        &'a self,
        paths: &'a HeadlessPaths,
        explicit_file_backend: bool,
    ) -> BoxFuture<'a, Result<OfficialCliUsageOutcome, OfficialCliQuotaError>> {
        Box::pin(async move {
            let slot_text = fs::read_to_string(&paths.active_slot_file).unwrap_or_default();
            (self.handler)(paths, explicit_file_backend, &slot_text)
        })
    }
}

fn audit_quota_outcome(frac: f64, reset_str: &str) -> OfficialCliUsageOutcome {
    OfficialCliUsageOutcome::Quota {
        description: None,
        groups: vec![agy_switch_cli::domain::quota::QuotaGroup {
            display_name: "Gemini Models".into(),
            description: Some("Models within this group: gemini-3.1-pro".into()),
            buckets: vec![
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: frac,
                    remaining_fraction_known: Some(true),
                    reset_time: reset_str.into(),
                    display_name: None,
                    description: None,
                },
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: frac,
                    remaining_fraction_known: Some(true),
                    reset_time: reset_str.into(),
                    display_name: None,
                    description: None,
                },
            ],
        }],
    }
}

// ============================================================================
// A01: Old backup import NEVER overwrites a rotated refresh_token
// ============================================================================
#[tokio::test]
async fn a01_old_backup_import_never_rolls_back_rotated_refresh_token_concurrently_or_serially() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let now = 1_800_000_000i64;

    // Seed account with `name = None` so `ensure_account_token_fresh_locked` enters `fetch_userinfo` while holding L2!
    let acc = make_acc(
        "acc-1",
        "alice@example.invalid",
        "1//OLD_BACKUP_RT_V1",
        now + 10,
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    let bundle_path = h.tmp.path().join("old_bundle.json");
    export_transfer_bundle_file(&repo, &bundle_path, true, true, &[]).unwrap();

    let entered_userinfo = Arc::new(Notify::new());
    let release_userinfo = Arc::new(Notify::new());

    struct PauseUserinfoTransport {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }
    impl HttpTransport for PauseUserinfoTransport {
        fn execute<'a>(
            &'a self,
            req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                if req.url.contains("userinfo") {
                    self.entered.notify_one();
                    self.release.notified().await;
                    return Ok(MockTransport::json_response(
                        200,
                        json!({"email": "alice@example.invalid", "name": "Alice"}),
                    ));
                }
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "access_token": "ya29.ROTATED_AT_V2",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "refresh_token": "1//ROTATED_NEW_RT_V2",
                        "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                    }),
                ))
            })
        }
    }

    let tr = PauseUserinfoTransport {
        entered: entered_userinfo.clone(),
        release: release_userinfo.clone(),
    };
    let repo_refresh = repo.clone();
    let refresh_task = tokio::spawn(async move {
        ensure_account_token_fresh_locked(
            &repo_refresh,
            &tr,
            &fast_oauth(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "acc-1",
            true,
            now,
        )
        .await
    });

    entered_userinfo.notified().await;
    // Confirm rotated token is already persisted on disk BEFORE import starts, while L2 is held by refresh_task
    assert_eq!(
        repo.read_account_unchecked("acc-1")
            .unwrap()
            .token
            .refresh_token,
        "1//ROTATED_NEW_RT_V2"
    );

    let repo_imp = repo.clone();
    let bp = bundle_path.clone();
    let import_started = Arc::new(Notify::new());
    let import_started_c = import_started.clone();
    let import_task = tokio::spawn(async move {
        import_started_c.notify_one();
        import_transfer_bundle_file(&repo_imp, &bp, false, now + 1).await
    });
    import_started.notified().await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    // Import MUST wait on L2 while refresh_task is still in userinfo!
    assert!(!import_task.is_finished());

    release_userinfo.notify_one();
    let refresh_out = refresh_task.await.unwrap().unwrap();
    assert_eq!(
        refresh_out.account.token.refresh_token,
        "1//ROTATED_NEW_RT_V2"
    );

    let imp_report = import_task.await.unwrap().unwrap();
    assert_eq!(imp_report.updated_count, 0);
    assert_eq!(imp_report.skipped_count, 1);
    assert_eq!(imp_report.failed_count, 0);

    // Disk MUST retain `1//ROTATED_NEW_RT_V2` and positive expiry > now (NEVER rolled back to V1 / expiry=1)!
    let after_default_imp = repo.read_account_unchecked("acc-1").unwrap();
    assert_eq!(
        after_default_imp.token.refresh_token,
        "1//ROTATED_NEW_RT_V2"
    );
    assert!(after_default_imp.token.expiry_timestamp >= now + 3600);

    // Even with explicit `overwrite = true` (`--overwrite` / `--force`), stale superseded V1 backup MUST be rejected!
    let forced_report = import_transfer_bundle_file(&repo, &bundle_path, true, now + 2)
        .await
        .unwrap();
    assert_eq!(forced_report.updated_count, 0);
    assert_eq!(forced_report.failed_count, 1);
    let after_forced_imp = repo.read_account_unchecked("acc-1").unwrap();
    assert_eq!(after_forced_imp.token.refresh_token, "1//ROTATED_NEW_RT_V2");
    assert!(after_forced_imp.token.expiry_timestamp >= now + 3600);
}

// ============================================================================
// A02: bootstrap / login / reauthorize durable token persistence before userinfo
// ============================================================================
#[tokio::test]
async fn a02_bootstrap_login_and_reauthorize_persist_tokens_durably_before_cancelled_userinfo() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let oauth_ep = fast_oauth();
    let now = 1_800_000_000i64;

    struct CancelAtUserinfoTransport {
        rotated_rt: String,
        entered_userinfo: Arc<Notify>,
    }
    impl HttpTransport for CancelAtUserinfoTransport {
        fn execute<'a>(
            &'a self,
            req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            let rt = self.rotated_rt.clone();
            let n = self.entered_userinfo.clone();
            Box::pin(async move {
                if req.url.contains("userinfo") {
                    n.notify_one();
                    std::future::pending::<()>().await;
                    unreachable!()
                }
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "access_token": "ya29.NEW_ISSUED_AT",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "refresh_token": rt,
                        "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                    }),
                ))
            })
        }
    }

    // 1. Existing RT passed to `bootstrap_and_persist_refresh_token` (`accounts add` duplicate path):
    let existing = make_acc(
        "acc-existing",
        "ex@example.invalid",
        "1//EXISTING_BEFORE_ADD",
        now + 100,
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(existing, true, now))
        .unwrap();

    let n1 = Arc::new(Notify::new());
    let tr1 = CancelAtUserinfoTransport {
        rotated_rt: "1//ROTATED_BY_BOOTSTRAP_ADD".into(),
        entered_userinfo: n1.clone(),
    };
    {
        let mut fut = Box::pin(bootstrap_and_persist_refresh_token(
            &repo,
            &tr1,
            &oauth_ep,
            &reg,
            "1//EXISTING_BEFORE_ADD",
            None,
            None,
            now,
        ));
        tokio::select! {
            _ = &mut fut => panic!("should suspend in userinfo"),
            _ = n1.notified() => {}
        }
        // Drop `fut` immediately inside `userinfo`!
    }
    assert_eq!(
        repo.read_account_unchecked("acc-existing")
            .unwrap()
            .token
            .refresh_token,
        "1//ROTATED_BY_BOOTSTRAP_ADD",
        "Existing account MUST immediately save rotated RT before userinfo!"
    );

    // 2. Unknown RT passed to `bootstrap_and_persist_refresh_token` -> saved in `0600` `pending_auth` AND resumable!
    let n2 = Arc::new(Notify::new());
    let tr2 = CancelAtUserinfoTransport {
        rotated_rt: "1//UNKNOWN_ADD_PENDING_SAVED".into(),
        entered_userinfo: n2.clone(),
    };
    {
        let mut fut = Box::pin(bootstrap_and_persist_refresh_token(
            &repo,
            &tr2,
            &oauth_ep,
            &reg,
            "1//BRAND_NEW_INPUT_RT",
            None,
            Some("My Label"),
            now,
        ));
        tokio::select! {
            _ = &mut fut => panic!("should suspend in userinfo"),
            _ = n2.notified() => {}
        }
    }
    let pendings = repo.list_pending_auth_readonly().unwrap();
    assert_eq!(pendings.len(), 1);
    assert_eq!(
        pendings[0].token.refresh_token,
        "1//UNKNOWN_ADD_PENDING_SAVED"
    );
    let pfile = h.paths().pending_auth_file(&pendings[0].id);
    assert_eq!(
        fs::metadata(&pfile).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Retrying with the original `1//BRAND_NEW_INPUT_RT` resumes from `pending_auth` WITHOUT hitting `/token` again!
    let resume_mock = MockTransport::from_queue([Ok(MockTransport::json_response(
        200,
        json!({"email": "newuser@example.invalid", "name": "New User"}),
    ))]);
    let (resumed_acc, created) = bootstrap_and_persist_refresh_token(
        &repo,
        &resume_mock,
        &fast_oauth(),
        &reg,
        "1//BRAND_NEW_INPUT_RT",
        None,
        Some("My Label"),
        now + 5,
    )
    .await
    .unwrap();
    assert!(created);
    assert_eq!(
        resumed_acc.token.refresh_token,
        "1//UNKNOWN_ADD_PENDING_SAVED"
    );
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());

    // 3. `complete_reauthorize_exchange_locked` holds L2 BEFORE `/token` AND saves `0600` `pending_auth` before `userinfo`!
    let client = reg.select_for_login(None).unwrap();
    let session = build_authorization_session(client, 54545, GOOGLE_AUTH_URL).unwrap();
    let target_before_reauth = repo.read_account_unchecked("acc-existing").unwrap();

    let n3 = Arc::new(Notify::new());
    let tr3 = CancelAtUserinfoTransport {
        rotated_rt: "1//REAUTH_ISSUED_SURVIVES_CANCEL".into(),
        entered_userinfo: n3.clone(),
    };
    {
        let mut fut = Box::pin(complete_reauthorize_exchange_locked(
            &repo,
            &tr3,
            &oauth_ep,
            &reg,
            &target_before_reauth,
            &session,
            "4/reauth-code",
            now + 10,
        ));
        tokio::select! {
            _ = &mut fut => panic!("should suspend in userinfo"),
            _ = n3.notified() => {
                // Verify L2 IS held on `acc-existing` while `reauthorize` is still in flight!
                let l2_busy = with_account_refresh_lock(
                    repo.paths(),
                    "acc-existing",
                    Duration::from_millis(30),
                    || async { Ok(()) },
                )
                .await;
                assert_eq!(l2_busy.unwrap_err().exit_code, ExitCode::LockBusyOrConflict);
            }
        }
    }
    let pendings_after_reauth = repo.list_pending_auth_readonly().unwrap();
    assert!(pendings_after_reauth
        .iter()
        .any(|p| p.token.refresh_token == "1//REAUTH_ISSUED_SURVIVES_CANCEL"));

    // 4. `complete_login_exchange_locked` ALSO persists `0600` `pending_auth` before `userinfo`!
    let n4 = Arc::new(Notify::new());
    let tr4 = CancelAtUserinfoTransport {
        rotated_rt: "1//LOGIN_ISSUED_SURVIVES_CANCEL".into(),
        entered_userinfo: n4.clone(),
    };
    {
        let mut fut = Box::pin(complete_login_exchange_locked(
            &repo,
            &tr4,
            &oauth_ep,
            &reg,
            &session,
            "4/login-code",
            None,
            now + 15,
        ));
        tokio::select! {
            _ = &mut fut => panic!("should suspend in userinfo"),
            _ = n4.notified() => {}
        }
    }
    assert!(repo
        .list_pending_auth_readonly()
        .unwrap()
        .iter()
        .any(|p| p.token.refresh_token == "1//LOGIN_ISSUED_SURVIVES_CANCEL"));
}

// ============================================================================
// A03 + A20: Closed secret redaction across non-UTF-8 argv, OAuth errors, serde_json, selectors & Debug
// ============================================================================
#[tokio::test]
async fn a03_and_a20_error_channels_non_utf8_argv_and_http_debug_never_reflect_secrets() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let now = 1_800_000_000i64;

    // 1. Non-UTF-8 argv (`b"1//AUDIT_NONUTF8_SECRET_12345\xff"`) in both normal and `--json` modes!
    let bad_arg = OsStr::from_bytes(b"1//AUDIT_NONUTF8_SECRET_12345\xff");
    for use_json in [false, true] {
        let mut cmd = h.cli();
        if use_json {
            cmd.arg("--json");
        }
        cmd.arg("accounts").arg("add").arg(bad_arg);
        let out = cmd.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "Non-UTF-8 argv must exit 2 (never 101 panic!): stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let combined_bytes = [out.stdout.as_slice(), out.stderr.as_slice()].concat();
        let combined_lossy = String::from_utf8_lossy(&combined_bytes);
        assert!(
            !combined_lossy.contains("AUDIT_NONUTF8_SECRET"),
            "Non-UTF-8 secret leaked: {combined_lossy}"
        );
        if use_json {
            let env_json: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
            assert_eq!(env_json["schema_version"], 1);
            assert_eq!(env_json["ok"], false);
            assert_eq!(env_json["exit_code"], 2);
        }
    }

    // 2. Unknown OAuth `error` field containing lowercase secret + ESC control char
    let acc = make_acc("acc-err", "err@example.invalid", "1//RT_ERR", now - 10, now);
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();
    let mock_unknown_oauth = MockTransport::from_queue([Ok(MockTransport::json_response(
        400,
        json!({"error": "1//lowercase_oauth_secret_98765\x1b[31m"}),
    ))]);
    let oauth_err = ensure_account_token_fresh_locked(
        &repo,
        &mock_unknown_oauth,
        &fast_oauth(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "acc-err",
        true,
        now,
    )
    .await
    .unwrap_err();
    assert!(!oauth_err.message.contains("lowercase_oauth_secret"));
    assert!(!oauth_err.message.contains('\x1b'));
    assert!(oauth_err.message.contains("unrecognized_oauth_error"));

    // Callback `?error=` unknown tag also never reflects secret
    let cb_err = validate_callback_url(
        "http://127.0.0.1:54545/oauth-callback?error=1//cb_secret_xyz&state=s1",
        "s1",
    )
    .unwrap_err();
    assert!(!cb_err.message.contains("cb_secret_xyz"));

    // 3. Accidental secret passed as selector (`switch`, `quota`, `accounts enable`)
    for secret_sel in [
        "1//ACCIDENTAL_RT_SELECTOR_999",
        "ya29.ACCIDENTAL_AT_SELECTOR_888",
        "GOCSPX-ACCIDENTAL_ALNUM_777",
    ] {
        let out = h
            .cli()
            .args(["--json", "quota", secret_sel])
            .output()
            .unwrap();
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !all.contains("ACCIDENTAL_"),
            "Selector leaked secret '{secret_sel}': {all}"
        );
    }

    // 4. Corrupted account JSON with access-token string inside integer field `expiry_timestamp`
    let acc_file = h.paths().account_file("acc-err");
    fs::write(
        &acc_file,
        br#"{"schema_version":1,"id":"acc-err","email":"err@example.invalid","token":{"access_token":"ok","refresh_token":"ok","expires_in":3600,"expiry_timestamp":"ya29.CORRUPT_TYPE_SECRET_555"},"created_at":1,"last_used":1}"#,
    )
    .unwrap();
    let list_out = h
        .cli()
        .args(["accounts", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(list_out.status.code(), Some(1));
    let list_err_str = String::from_utf8_lossy(&list_out.stderr);
    assert!(
        !list_err_str.contains("CORRUPT_TYPE_SECRET_555"),
        "serde_json type error leaked embedded secret literal: {list_err_str}"
    );
    let parsed_err: serde_json::Value = serde_json::from_slice(&list_out.stderr).unwrap();
    assert_eq!(parsed_err["exit_code"], 1);

    // 5. A20: `HttpRequest` Debug redacts URL userinfo, query, fragment, and sensitive headers
    let req = HttpRequest::get(
        "https://u_sec:PASS_SEC_123@example.com/oauth-callback?code=CODE_SEC_456&access_token=AT_SEC_789#FRAG_SEC_000",
        TimeoutClass::StandardApi,
    )
    .with_bearer_auth("BEARER_SEC_999");
    let dbg = format!("{req:?}");
    for sentinel in [
        "u_sec",
        "PASS_SEC_123",
        "CODE_SEC_456",
        "AT_SEC_789",
        "FRAG_SEC_000",
        "BEARER_SEC_999",
    ] {
        assert!(
            !dbg.contains(sentinel),
            "HttpRequest Debug leaked '{sentinel}': {dbg}"
        );
    }
    assert!(dbg.contains("https://example.com/oauth-callback"));
}

// ============================================================================
// A04 + A05 + §4.2 #11: Mixed-backend L1 lock + External journal drift CAS
// ============================================================================
#[tokio::test]
async fn a04_a05_mixed_l1_lock_and_external_slot_drift_blocks_stale_reconcile() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let now = 1_800_000_000i64;

    let store_a_dir = h.tmp.path().join("store-a");
    let store_b_dir = h.tmp.path().join("store-b");
    let paths_a = HeadlessPaths::with_explicit(
        h.home.clone(),
        store_a_dir.clone(),
        h.cache_dir.join("agy-switch-cli"),
    );
    let paths_b = HeadlessPaths::with_explicit(
        h.home.clone(),
        store_b_dir.clone(),
        h.cache_dir.join("agy-switch-cli"),
    );

    // A04: Holding file L1 blocks secret-service L1 (`include_keyring_scope = true`) and vice versa!
    let l1_file = ActiveSlotLock::try_acquire(&paths_a, false).unwrap();
    assert_eq!(
        ActiveSlotLock::try_acquire(&paths_b, true)
            .err()
            .unwrap()
            .exit_code,
        ExitCode::LockBusyOrConflict
    );
    drop(l1_file);

    // A05 + §4.2 #11:
    // 1. Store A has `acc-a` (selected) and `acc-b`; Store B has `acc-c`.
    let repo_a = StoreRepository::new(paths_a.clone());
    let repo_b = StoreRepository::new(paths_b.clone());
    let backend = FileSessionBackend;

    let acc_a = make_acc("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_acc("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    let acc_c = make_acc("acc-c", "c@example.invalid", "1//RT_C", now + 7200, now);
    repo_a
        .with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, now)?;
            tx.upsert_account(acc_b.clone(), false, now)?;
            Ok(())
        })
        .unwrap();
    repo_b
        .with_write_lock(|tx| tx.upsert_account(acc_c.clone(), true, now))
        .unwrap();
    backend
        .write_slot(&paths_a, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // 2. Store A switches to `acc-b` and injects `after_slot_commit:index.json:io` -> MUST exit 7 (`CommittedIndexPending`)!
    let sw_a = h
        .cli_for_data_dir(&store_a_dir)
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "after_slot_commit:index.json:io",
        )
        .args(["switch", "acc-b", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        sw_a.status.code(),
        Some(7),
        "after_slot_commit:index.json:io MUST return exit 7: stderr={}",
        String::from_utf8_lossy(&sw_a.stderr)
    );

    // 3. Store B legitimately switches shared HOME active slot to `acc-c`!
    let sw_b = h
        .cli_for_data_dir(&store_b_dir)
        .args(["switch", "acc-c", "--json"])
        .output()
        .unwrap();
    assert_eq!(sw_b.status.code(), Some(0));
    assert!(fs::read_to_string(&paths_b.active_slot_file)
        .unwrap()
        .contains("1//RT_C"));

    // 4. Non-fix reconciliation on Store A MUST detect external slot digest drift -> exit 7 (`RecoveryIncomplete`),
    //    NOT overwrite Store A `selected_account_id` to `acc-b`, and NOT clear the journal!
    let l1 = ActiveSlotLock::try_acquire(&paths_a, false).unwrap();
    let rec_err = reconcile_journal_locked(&l1, &repo_a, &backend, false, now + 5).unwrap_err();
    assert_eq!(rec_err.exit_code, ExitCode::PartialCommitOrRecovery);
    assert_eq!(
        repo_a
            .read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );
    assert!(read_journal_readonly(&paths_a).unwrap().is_some());

    // 5. Full repair reconciliation on Store A preserves Store B's valid live slot `acc-c`, keeps `acc-a` (not `acc-b`!), and clears journal!
    reconcile_journal_locked(&l1, &repo_a, &backend, true, now + 6).unwrap();
    drop(l1);
    assert!(fs::read_to_string(&paths_b.active_slot_file)
        .unwrap()
        .contains("1//RT_C"));
    assert_eq!(
        repo_a
            .read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-a")
    );
    assert!(read_journal_readonly(&paths_a).unwrap().is_none());
}

// ============================================================================
// A06: Lock hierarchy invariants on single-thread runtime without cross-task false positives
// ============================================================================
#[tokio::test(flavor = "current_thread")]
async fn a06_lock_hierarchy_invariants_hold_on_current_thread_executor() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let paths_t1 = paths.clone();
    let paths_t2 = paths.clone();

    let entered_l2 = Arc::new(Notify::new());
    let entered_l2_c = entered_l2.clone();
    let release_l2 = Arc::new(Notify::new());
    let release_l2_c = release_l2.clone();

    let t1 = tokio::spawn(async move {
        with_account_refresh_lock(&paths_t1, "acc-1", Duration::from_secs(2), || async {
            entered_l2_c.notify_one();
            tokio::task::yield_now().await;
            // Attempting L1 inside L2 is ALWAYS rejected!
            let e = ActiveSlotLock::try_acquire(&paths_t1, false).err().unwrap();
            assert_eq!(e.error_code, "lock_order_violation");
            release_l2_c.notified().await;
            Ok(())
        })
        .await
        .unwrap();
    });

    entered_l2.notified().await;
    // Unrelated task on the SAME single-threaded executor can acquire L1 or L3 without false thread-local error!
    let independent_l1 = ActiveSlotLock::try_acquire(&paths_t2, false).unwrap();
    with_store_write_lock(&paths_t2, Duration::from_millis(200), |_| Ok(())).unwrap();
    drop(independent_l1);

    release_l2.notify_one();
    t1.await.unwrap();
}

// ============================================================================
// A07 + A08: Daemon Prepare in-flight policy reorder & real commit-time clock revalidation
// ============================================================================
#[tokio::test]
async fn a07_and_a08_daemon_cancels_on_prepare_policy_reorder_and_clock_reset_expiration() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let _pg = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir);
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_800_000_000i64;

    let make_q = |pct: f64, reset_unix: i64| -> QuotaObservation {
        let reset_str = jiff::Timestamp::from_second(reset_unix)
            .unwrap()
            .to_string();
        let mut q = QuotaObservation::new(now, QuotaSourceEnv::Production);
        q.subscription_tier = Some("Google AI Pro".into());
        q.tier_source_env = Some(QuotaSourceEnv::Production);
        q.models.push(agy_switch_cli::domain::quota::ModelQuota {
            name: "gemini-3.8-flash".into(),
            percentage: (pct * 100.0).round() as i32,
            percentage_known: Some(true),
            observed_remaining_fraction: Some(pct),
            primary_quota: Some(agy_switch_cli::domain::quota::PrimaryModelQuota {
                remaining_fraction: Some(pct),
                reset_time: reset_str.clone(),
            }),
            quota_bucket_id: Some("gemini-weekly".into()),
            reset_time: reset_str.clone(),
            display_name: None,
            supports_images: None,
            supports_thinking: None,
            thinking_budget: None,
            recommended: None,
            max_tokens: None,
            max_output_tokens: None,
            supported_mime_types: None,
        });
        q.quota_groups = Some(vec![agy_switch_cli::domain::quota::QuotaGroup {
            display_name: "Gemini Models".into(),
            description: None,
            buckets: vec![
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: pct,
                    remaining_fraction_known: Some(true),
                    reset_time: reset_str.clone(),
                    display_name: None,
                    description: None,
                },
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: pct,
                    remaining_fraction_known: Some(true),
                    reset_time: reset_str,
                    display_name: None,
                    description: None,
                },
            ],
        }]);
        q
    };

    let mut src = make_acc("src", "src@example.invalid", "1//RT_SRC", now + 7200, now);
    src.quota = Some(make_q(0.05, now + 3600));
    // `c1` has near-expiry token (`now + 10`) so Stage 3 `Prepare` calls `/token`!
    let mut c1 = make_acc("c1", "c1@example.invalid", "1//RT_C1", now + 10, now);
    c1.name = Some("C1".into());
    c1.quota = Some(make_q(0.80, now + 3600));
    let mut c2 = make_acc("c2", "c2@example.invalid", "1//RT_C2", now + 7200, now);
    c2.name = Some("C2".into());
    c2.quota = Some(make_q(0.90, now + 3600));

    repo.with_write_lock(|tx| {
        tx.upsert_account(src.clone(), true, now)?;
        tx.upsert_account(c1, false, now)?;
        tx.upsert_account(c2, false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Wait,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "gemini".into(),
            candidate_account_ids: vec!["c1".into(), "c2".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&src.token).unwrap())
        .unwrap();

    // A07: User reorders policy to `[c2, c1]` right before Stage 5 Revalidate -> MUST cancel stale plan!
    let repo_in_revalidate = repo.clone();
    let reordered_flag = Arc::new(AtomicBool::new(false));
    let rf = reordered_flag.clone();
    let mut engine = DaemonEngine::new();
    engine.before_revalidate_hook = Some(Arc::new(move || {
        if !rf.swap(true, Ordering::SeqCst) {
            repo_in_revalidate
                .with_write_lock(|tx| {
                    let mut pol = repo_in_revalidate.read_policy()?;
                    let prev = pol.revision;
                    pol.candidate_account_ids = vec!["c2".into(), "c1".into()];
                    tx.save_policy(&mut pol, Some(prev), now + 1)?;
                    Ok(())
                })
                .unwrap();
        }
    }));

    let runner_a07 = AuditSlotQuotaRunner::from_handler(|_, _, _| {
        Ok(audit_quota_outcome(0.85, "2099-01-01T00:00:00Z"))
    });
    let out_a07 = engine
        .run_single_tick(
            &repo,
            &backend,
            &runner_a07,
            &reg,
            &DaemonConfigOverrides {
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now,
        )
        .await
        .unwrap();
    engine.before_revalidate_hook = None;
    assert_eq!(
        out_a07,
        TickStageOutcome::CancelledStalePlan {
            reason: "policy_revision_changed_or_disabled".into()
        },
        "In-flight policy reorder MUST cancel stale plan!"
    );
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("src")
    );

    // A08: Candidate `c2` live `/usage` returns `reset = now + 1s`, while `ManualClock` advances by 2s
    //      during the probe (`now + 2 > reset`) -> evaluated as `Stale` (NOT qualified) and NOT landed!
    let clock = Arc::new(ManualClock::new(now));
    let reset_plus_1 = jiff::Timestamp::from_second(now + 1).unwrap().to_string();
    let clock_in_probe = clock.clone();
    let reset_for_c2 = reset_plus_1.clone();
    let runner_a08 = AuditSlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_C2") {
            clock_in_probe.advance(2);
            Ok(audit_quota_outcome(0.90, &reset_for_c2))
        } else {
            Ok(audit_quota_outcome(0.05, "2099-01-01T00:00:00Z"))
        }
    });
    repo.with_write_lock(|tx| {
        let mut pol = repo.read_policy()?;
        let prev = pol.revision;
        pol.candidate_account_ids = vec!["c2".into()];
        tx.save_policy(&mut pol, Some(prev), now + 2)?;
        Ok(())
    })
    .unwrap();

    let mut engine_clock = DaemonEngine::with_clock(clock.clone());
    let out_a08 = engine_clock
        .run_single_tick(
            &repo,
            &backend,
            &runner_a08,
            &reg,
            &DaemonConfigOverrides {
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now,
        )
        .await
        .unwrap();
    assert!(
        matches!(out_a08, TickStageOutcome::NoQualifiedCandidate { .. }),
        "Candidate whose reset_time passed during probe MUST NOT land: got {out_a08:?}"
    );
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("src")
    );
}

// ============================================================================
// A09 + A10: Single-env tier guard, missing primary fraction, and OfficialCli validation-block isolation
// ============================================================================
#[tokio::test]
async fn a09_and_a10_quota_single_env_missing_primary_and_error_evidence_chains() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    let acc = make_acc("acc-q", "q@example.invalid", "1//RT_Q", now + 7200, now);
    repo.with_write_lock(|tx| tx.upsert_account(acc.clone(), true, now))
        .unwrap();
    backend
        .write_slot(&h.paths(), &serialize_session_payload(&acc.token).unwrap())
        .unwrap();

    // 1. A09(A): Cross-env `tier_source_env != source_env` Free tier without 5h bucket MUST stay Unknown!
    let mut obs_cross = QuotaObservation::new(now, QuotaSourceEnv::Daily);
    obs_cross.subscription_tier = Some("Free Tier".into());
    obs_cross.tier_source_env = Some(QuotaSourceEnv::Sandbox);
    obs_cross
        .models
        .push(agy_switch_cli::domain::quota::ModelQuota {
            name: "gemini-3.8-flash".into(),
            percentage: 80,
            percentage_known: Some(true),
            observed_remaining_fraction: Some(0.80),
            primary_quota: Some(agy_switch_cli::domain::quota::PrimaryModelQuota {
                remaining_fraction: Some(0.80),
                reset_time: "2099-01-01T00:00:00Z".into(),
            }),
            quota_bucket_id: Some("gemini-weekly".into()),
            reset_time: "2099-01-01T00:00:00Z".into(),
            display_name: None,
            supports_images: None,
            supports_thinking: None,
            thinking_budget: None,
            recommended: None,
            max_tokens: None,
            max_output_tokens: None,
            supported_mime_types: None,
        });
    obs_cross.quota_groups = Some(vec![agy_switch_cli::domain::quota::QuotaGroup {
        display_name: "Gemini Models".into(),
        description: None,
        buckets: vec![agy_switch_cli::domain::quota::QuotaBucket {
            bucket_id: "gemini-weekly".into(),
            window: "weekly".into(),
            remaining_fraction: 0.80,
            remaining_fraction_known: Some(true),
            reset_time: "2099-01-07T00:00:00Z".into(),
            display_name: None,
            description: None,
        }],
    }]);
    assert!(matches!(
        evaluate_quota_observation(&obs_cross, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Unknown { .. }
    ));

    // 2. A09(B): Model `primary_quota.remaining_fraction == None` MUST remain Unknown even with complete summary!
    let mut obs_mp = obs_cross.clone();
    obs_mp.tier_source_env = Some(QuotaSourceEnv::Daily);
    obs_mp.subscription_tier = Some("Google AI Pro".into());
    obs_mp.models[0].primary_quota = Some(agy_switch_cli::domain::quota::PrimaryModelQuota {
        remaining_fraction: None,
        reset_time: "2099-01-01T00:00:00Z".into(),
    });
    obs_mp.quota_groups.as_mut().unwrap()[0].buckets.push(
        agy_switch_cli::domain::quota::QuotaBucket {
            bucket_id: "gemini-5h".into(),
            window: "5h".into(),
            remaining_fraction: 0.80,
            remaining_fraction_known: Some(true),
            reset_time: "2099-01-01T05:00:00Z".into(),
            display_name: None,
            description: None,
        },
    );
    assert!(matches!(
        evaluate_quota_observation(&obs_mp, "gemini", now + 1, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Unknown { .. }
    ));

    // 3. A10: Official CLI `ValidationBlocked` marks `validation_blocked = true`, transient failure preserves it,
    //    and a clean Official CLI `/usage` clears `validation_blocked = false`!
    let runner_val = AuditSlotQuotaRunner::from_handler(|_, _, _| {
        Ok(OfficialCliUsageOutcome::ValidationBlocked {
            reason: "VALIDATION_REQUIRED".into(),
        })
    });
    let blocked = refresh_active_slot_quota_with_runner(
        &repo,
        &backend,
        &runner_val,
        true,
        Some("acc-q"),
        now + 2,
    )
    .await
    .unwrap()
    .account;
    assert!(blocked.validation_blocked);

    let runner_fail = AuditSlotQuotaRunner::from_handler(|_, _, _| {
        Err(OfficialCliQuotaError::CommandFailed("transient 503".into()))
    });
    assert!(refresh_active_slot_quota_with_runner(
        &repo,
        &backend,
        &runner_fail,
        true,
        Some("acc-q"),
        now + 3,
    )
    .await
    .is_err());
    assert!(
        repo.read_account_unchecked("acc-q")
            .unwrap()
            .validation_blocked,
        "Transient Official CLI error must never clear validation_blocked"
    );

    let runner_ok = AuditSlotQuotaRunner::from_handler(|_, _, _| {
        Ok(audit_quota_outcome(0.85, "2099-01-01T00:00:00Z"))
    });
    let cleared = refresh_active_slot_quota_with_runner(
        &repo,
        &backend,
        &runner_ok,
        true,
        Some("acc-q"),
        now + 4,
    )
    .await
    .unwrap()
    .account;
    assert!(!cleared.validation_blocked);
}

// ============================================================================
// A11: reauthorize preserves concurrent Manual disable & propagates EROFS on state write
// ============================================================================
#[tokio::test]
async fn a11_reauthorize_preserves_manual_disable_and_propagates_state_write_erofs() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_800_000_000i64;

    let mut acc = make_acc(
        "acc-m",
        "manual@example.invalid",
        "1//RT_M0",
        now + 7200,
        now,
    );
    acc.disabled = true;
    acc.disabled_code = Some(DisableReasonCode::ScopeReauthRequired);
    repo.with_write_lock(|tx| tx.upsert_account(acc.clone(), true, now))
        .unwrap();

    let client = reg.select_for_login(None).unwrap();
    let session = build_authorization_session(client, 54545, GOOGLE_AUTH_URL).unwrap();

    // Concurrent `Manual` disable occurs while `reauthorize` is awaiting `userinfo`!
    let repo_concurrent = repo.clone();
    let mock_reauth = MockTransport::from_handler(move |req| {
        if req.url.contains("userinfo") {
            repo_concurrent
                .with_write_lock(|tx| {
                    tx.mark_account_disabled(
                        "acc-m",
                        DisableReasonCode::Manual,
                        Some("Operator manually disabled".into()),
                        now + 1,
                    )
                })
                .unwrap();
            return Ok(MockTransport::json_response(
                200,
                json!({"email": "manual@example.invalid", "name": "Manual User"}),
            ));
        }
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.REAUTH_M1",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "1//RT_M1_NEW",
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        ))
    });

    let updated = complete_reauthorize_exchange_locked(
        &repo,
        &mock_reauth,
        &fast_oauth(),
        &reg,
        &acc,
        &session,
        "4/ok-code",
        now + 2,
    )
    .await
    .unwrap();

    assert_eq!(updated.token.refresh_token, "1//RT_M1_NEW");
    assert!(
        updated.disabled,
        "Concurrent Manual disable MUST NOT be cleared by reauthorize!"
    );
    assert_eq!(updated.disabled_code, Some(DisableReasonCode::Manual));

    // Part 2: Missing scope + EROFS injected on account write -> MUST return exit 1 (`read_only_fs_erofs`), NOT exit 6!
    let mut acc_erofs = make_acc(
        "acc-erofs",
        "erofs@example.invalid",
        "1//RT_EROFS",
        now + 7200,
        now,
    );
    acc_erofs.token.granted_scopes = Some(vec!["openid".into()]); // Missing cloud-platform!
    repo.with_write_lock(|tx| tx.upsert_account(acc_erofs, false, now))
        .unwrap();

    let fault = ScopedEnvVar::set(
        "AGY_SWITCH_CLI_FAULT_SPEC",
        "before_write:acc-erofs.json:erofs",
    );
    let erofs_err = ensure_account_token_fresh_locked(
        &repo,
        &MockTransport::default(),
        &fast_oauth(),
        &reg,
        "acc-erofs",
        false,
        now,
    )
    .await
    .unwrap_err();
    drop(fault);

    assert_eq!(erofs_err.exit_code, ExitCode::GeneralOrDataError);
    assert_eq!(erofs_err.error_code, "read_only_fs_erofs");
}

// ============================================================================
// A12 + A13 + A14 + A15 + A21: Fail-closed proc, 127.attacker host, FIFOs, manual --json, delete policy I/O
// ============================================================================
#[tokio::test]
async fn a12_a13_a14_a15_a21_proc_fail_closed_loopback_host_fifo_json_and_delete_policy() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = 1_800_000_000i64;

    // A13: `127.attacker.invalid` is NOT loopback!
    assert_eq!(
        validate_callback_url_with_port(
            "http://127.attacker.invalid:54545/oauth-callback?code=c&state=s",
            "s",
            Some(54545)
        )
        .unwrap_err()
        .error_code,
        "invalid_callback_host"
    );
    let pmode = ProxyMode::Explicit {
        proxy_url: "socks5h://127.0.0.1:1080".into(),
        no_proxy: None,
    };
    assert!(!pmode
        .should_bypass(&Url::parse("http://127.attacker.invalid:54545/oauth-callback").unwrap()));
    assert!(pmode.should_bypass(&Url::parse("http://127.0.0.1:54545/oauth-callback").unwrap()));

    // A12: `mode 000` `/proc` (assuming non-root or without DAC_READ_SEARCH; also verify unreadable same-UID stat!)
    fs::set_permissions(&h.proc_dir, fs::Permissions::from_mode(0o000)).unwrap();
    let proc_open_failed = fs::read_dir(&h.proc_dir).is_err();
    if proc_open_failed {
        let _pg = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir);
        assert!(matches!(
            observe_runtime_state(&paths),
            agy_switch_cli::domain::account::RuntimeState::Unverified { .. }
        ));
    }
    fs::set_permissions(&h.proc_dir, fs::Permissions::from_mode(0o700)).unwrap();
    // Also test a live numeric PID dir with malformed/empty `stat` (works even if container root has DAC_OVERRIDE!)
    fs::create_dir_all(h.proc_dir.join("9999")).unwrap();
    fs::write(h.proc_dir.join("9999/stat"), b"corrupt-stat").unwrap();
    {
        let _pg = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir);
        assert!(matches!(
            observe_runtime_state(&paths),
            agy_switch_cli::domain::account::RuntimeState::Unverified { .. }
        ));
    }
    fs::remove_dir_all(h.proc_dir.join("9999")).unwrap();

    // A15: `auth login --json` (default manual paste mode) with 20 KiB stdin -> stderr MUST be a single valid JSON line!
    let mut manual_child = h
        .cli()
        .args(["auth", "login", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = manual_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&vec![b'X'; 20 * 1024]);
    let manual_out = manual_child.wait_with_output().unwrap();
    assert_eq!(manual_out.status.code(), Some(2));
    assert!(manual_out.stdout.is_empty());
    let stderr_text = String::from_utf8(manual_out.stderr).unwrap();
    assert_eq!(
        stderr_text.trim().lines().count(),
        1,
        "auth login --json stderr must be single-line JSON, got: {stderr_text}"
    );
    let err_env: serde_json::Value = serde_json::from_str(stderr_text.trim()).unwrap();
    assert_eq!(err_env["schema_version"], 1);
    assert_eq!(err_env["ok"], false);
    assert_eq!(err_env["exit_code"], 2);

    // Seed accounts + policy for A21 and A14 tests
    let acc_a = make_acc("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_acc("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a, true, now)?;
        tx.upsert_account(acc_b, false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            candidate_account_ids: vec!["acc-b".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();

    // A21: `before_write:policy.json:enospc` on `accounts delete acc-b` MUST fail (exit 1), NOT exit 0!
    let del_fail = h
        .cli()
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_write:policy.json:enospc",
        )
        .args(["accounts", "delete", "acc-b", "--json"])
        .output()
        .unwrap();
    assert_eq!(del_fail.status.code(), Some(1));
    assert!(repo.read_account_unchecked("acc-b").is_ok());

    // Without fault, `accounts delete acc-b` cleans both account AND policy!
    let del_ok = h
        .cli()
        .args(["accounts", "delete", "acc-b", "--json"])
        .output()
        .unwrap();
    assert_eq!(del_ok.status.code(), Some(0));
    assert!(repo.read_policy().unwrap().candidate_account_ids.is_empty());

    // A14: Replace `policy.json`, `state/switch_journal.json`, `accounts/acc-a.json`, `index.json` with 0600 FIFOs
    // and assert commands fail fast (< 500ms) instead of blocking forever!
    let make_fifo = |p: &Path| {
        if p.exists() {
            fs::remove_file(p).unwrap();
        }
        let c = CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    };

    for (fifo_target, args) in [
        (
            paths.policy_file(),
            vec!["policy", "set", "--reserve", "10"],
        ),
        (
            paths.switch_journal_file(),
            vec!["accounts", "enable", "acc-a"],
        ),
        (
            paths.account_file("acc-a"),
            vec!["accounts", "enable", "acc-a"],
        ),
        (paths.index_file(), vec!["accounts", "enable", "acc-a"]),
    ] {
        let backup = fs::read(&fifo_target).ok();
        make_fifo(&fifo_target);
        let started = Instant::now();
        let out = h.cli().args(&args).output().unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(800),
            "FIFO at '{}' blocked {:?}!",
            fifo_target.display(),
            started.elapsed()
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "FIFO at '{}' must exit 1",
            fifo_target.display()
        );
        fs::remove_file(&fifo_target).unwrap();
        if let Some(orig) = backup {
            fs::write(&fifo_target, orig).unwrap();
            fs::set_permissions(&fifo_target, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

// ============================================================================
// A16 + A17: External SIGTERM on TUI restores PTY ECHO & `daemon --once` exits 0 on SIGTERM
// ============================================================================
#[tokio::test]
async fn a16_and_a17_sigterm_graceful_daemon_once_and_pty_tui_echo_restore() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = jiff::Timestamp::now().as_second();

    // Seed low-quota source account + slow synthetic `agy` binary so `daemon --once` blocks in Stage 1 `/usage`!
    let slow_agy = h.tmp.path().join("slow-daemon-once-agy");
    let started_marker = h.tmp.path().join("daemon-once-agy-started");
    fs::write(
        &slow_agy,
        format!(
            "#!/bin/sh\necho started > \"{}\"\nsleep 30\n",
            started_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&slow_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let mut acc = make_acc("acc-d", "d@example.invalid", "1//RT_D", now + 7200, now);
    acc.quota = None; // Unknown -> Stage 1 triggers official CLI probe!
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc.clone(), true, now)?;
        let acc2 = make_acc("acc-d2", "d2@example.invalid", "1//RT_D2", now + 7200, now);
        tx.upsert_account(acc2, false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            candidate_account_ids: vec!["acc-d2".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc.token).unwrap())
        .unwrap();

    let mut d_once = h
        .cli()
        .env("AGY_SWITCH_CLI_AGY_BIN", &slow_agy)
        .args(["daemon", "--once"])
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if started_marker.exists() {
            break;
        }
        ::tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        started_marker.exists(),
        "daemon --once did not invoke synthetic `agy`"
    );
    unsafe {
        libc::kill(d_once.id() as i32, libc::SIGTERM);
    }
    let st = d_once.wait().unwrap();
    assert_eq!(
        st.code(),
        Some(0),
        "`daemon --once` MUST exit gracefully with code 0 on SIGTERM (got status {st:?})"
    );

    // A16 (`#[cfg(feature = "tui")]`): External SIGTERM while TUI is in raw mode MUST restore PTY ECHO!
    #[cfg(feature = "tui")]
    {
        use std::os::fd::{AsRawFd, FromRawFd};

        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let slave_out_fd = unsafe { libc::dup(slave_fd) };
        let inspect_fd = unsafe { libc::dup(slave_fd) };
        let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
        let slave_out = unsafe { fs::File::from_raw_fd(slave_out_fd) };
        let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_fd) };
        let _master = unsafe { fs::File::from_raw_fd(master_fd) };

        let mut tui_child = h
            .cli()
            .arg("tui")
            .stdin(Stdio::from(slave_in))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut raw_active = false;
        for _ in 0..60 {
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut t) } == 0
                && (t.c_lflag & libc::ECHO) == 0
            {
                raw_active = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(raw_active, "TUI did not disable ECHO in raw mode");

        unsafe {
            libc::kill(tui_child.id() as i32, libc::SIGTERM);
        }
        let _ = tui_child.wait().unwrap();

        let mut post_t: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut post_t) },
            0
        );
        assert_ne!(
            post_t.c_lflag & libc::ECHO,
            0,
            "CRITICAL (A16): External SIGTERM on TUI left terminal ECHO disabled!"
        );
    }
}

// ============================================================================
// §4.2 #8: Real `libc::SIGKILL` (-9) crash recovery at slot commit boundary
// ============================================================================
#[test]
fn real_sigkill_signal_9_after_slot_commit_recovers_cleanly_via_status_and_write() {
    let _g = ENV_MUTEX.blocking_lock();
    if std::env::var("AGY_TEST_SIGKILL_CHILD_MODE").as_deref() == Ok("1") {
        let home = PathBuf::from(std::env::var("AGY_CHILD_HOME").unwrap());
        let data = PathBuf::from(std::env::var("AGY_CHILD_DATA").unwrap());
        let cache = PathBuf::from(std::env::var("AGY_CHILD_CACHE").unwrap());
        let marker = PathBuf::from(std::env::var("AGY_CHILD_READY_MARKER").unwrap());
        let paths = HeadlessPaths::with_explicit(home, data, cache);
        let repo = StoreRepository::new(paths.clone());

        struct PauseAfterSlotWriteBackend {
            marker: PathBuf,
        }
        impl CredentialBackend for PauseAfterSlotWriteBackend {
            fn name(&self) -> &'static str {
                "file_session"
            }
            fn uses_keyring(&self) -> bool {
                false
            }
            fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
                FileSessionBackend.inspect_slot(paths)
            }
            fn snapshot_before_write(
                &self,
                paths: &HeadlessPaths,
            ) -> agy_switch_cli::error::CliResult<Option<Vec<u8>>> {
                FileSessionBackend.snapshot_before_write(paths)
            }
            fn write_slot(
                &self,
                paths: &HeadlessPaths,
                payload: &str,
            ) -> agy_switch_cli::error::CliResult<()> {
                FileSessionBackend.write_slot(paths, payload)?;
                fs::write(&self.marker, b"committed").unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            fn remove_slot(&self, paths: &HeadlessPaths) -> agy_switch_cli::error::CliResult<()> {
                FileSessionBackend.remove_slot(paths)
            }
        }

        let l1 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
        let _ = execute_switch_with_slot_lock(
            &l1,
            &repo,
            &PauseAfterSlotWriteBackend { marker },
            &OAuthClientRegistry::parse_from_raw(None, None),
            "acc-b",
            false,
            1_800_000_000,
        );
        return;
    }

    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = 1_800_000_000i64;
    let acc_a = make_acc("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
    let acc_b = make_acc("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b, false, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    let marker = h.tmp.path().join("slot_committed_marker");
    let current_test_exe = std::env::current_exe().unwrap();
    let mut child_guard = KillChildOnDrop::new(
        Command::new(current_test_exe)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &h.home)
            .env("TMPDIR", h.tmp.path())
            .env("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir)
            .env("AGY_TEST_SIGKILL_CHILD_MODE", "1")
            .env("AGY_CHILD_HOME", &paths.home_dir)
            .env("AGY_CHILD_DATA", &paths.data_dir)
            .env("AGY_CHILD_CACHE", &paths.cache_dir)
            .env("AGY_CHILD_READY_MARKER", &marker)
            .args([
                "--exact",
                "real_sigkill_signal_9_after_slot_commit_recovers_cleanly_via_status_and_write",
                "--nocapture",
            ])
            .spawn()
            .unwrap(),
    );

    for _ in 0..400 {
        if marker.exists() {
            break;
        }
        if let Some(status) = child_guard.as_mut().try_wait().unwrap() {
            if !marker.exists() {
                panic!("Child exited prematurely ({status}) before reaching slot commit point");
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(marker.exists(), "Child did not reach slot commit point");

    // Deliver genuine kernel SIGKILL (-9)!
    let mut child = child_guard.take();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGKILL);
    }
    let wait_st = child.wait().unwrap();
    assert_eq!(wait_st.signal(), Some(libc::SIGKILL));

    // `status` reports exit code 7 (`CommittedIndexPending`); subsequent write command reconciles cleanly to `acc-b`!
    let st = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st.status.code(), Some(7));

    let fix = h
        .cli()
        .args(["policy", "set", "--reserve", "10", "--json"])
        .output()
        .unwrap();
    assert_eq!(fix.status.code(), Some(0));
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

// ============================================================================
// §4.2 #5: Daemon candidate probe budget <= 3 cancels lower-priority while preserving rotated RT
// ============================================================================
#[tokio::test]
async fn daemon_candidate_budget_cancels_lower_priority_probe_while_preserving_its_rotated_rt() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let _pg = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir);
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_800_000_000i64;

    let mut src = make_acc("src", "src@example.invalid", "1//RT_SRC", now + 7200, now);
    let mut sq = QuotaObservation::new(now, QuotaSourceEnv::Production);
    sq.subscription_tier = Some("Google AI Pro".into());
    sq.tier_source_env = Some(QuotaSourceEnv::Production);
    sq.models.push(agy_switch_cli::domain::quota::ModelQuota {
        name: "gemini-3.8-flash".into(),
        percentage: 5,
        percentage_known: Some(true),
        observed_remaining_fraction: Some(0.05),
        primary_quota: Some(agy_switch_cli::domain::quota::PrimaryModelQuota {
            remaining_fraction: Some(0.05),
            reset_time: "2099-01-01T00:00:00Z".into(),
        }),
        quota_bucket_id: Some("gemini-weekly".into()),
        reset_time: "2099-01-01T00:00:00Z".into(),
        display_name: None,
        supports_images: None,
        supports_thinking: None,
        thinking_budget: None,
        recommended: None,
        max_tokens: None,
        max_output_tokens: None,
        supported_mime_types: None,
    });
    sq.quota_groups = Some(vec![agy_switch_cli::domain::quota::QuotaGroup {
        display_name: "Gemini Models".into(),
        description: None,
        buckets: vec![
            agy_switch_cli::domain::quota::QuotaBucket {
                bucket_id: "gemini-weekly".into(),
                window: "weekly".into(),
                remaining_fraction: 0.05,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-01T00:00:00Z".into(),
                display_name: None,
                description: None,
            },
            agy_switch_cli::domain::quota::QuotaBucket {
                bucket_id: "gemini-5h".into(),
                window: "5h".into(),
                remaining_fraction: 0.05,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-01T00:00:00Z".into(),
                display_name: None,
                description: None,
            },
        ],
    }]);
    src.quota = Some(sq);

    // c1: fresh token, missing quota -> wins with 85%!
    let mut c1 = make_acc("c1", "c1@example.invalid", "1//RT_C1", now + 7200, now);
    c1.name = Some("C1".into());
    // c2: expired token -> rotates to `1//C2_ROTATED_SURVIVES_DROP`, then blocks in `:loadCodeAssist`!
    let mut c2 = make_acc("c2", "c2@example.invalid", "1//RT_C2_OLD", now + 10, now);
    c2.name = Some("C2".into());
    // c3, c4, c5: also missing quota
    let mut c3 = make_acc("c3", "c3@example.invalid", "1//RT_C3", now + 7200, now);
    c3.name = Some("C3".into());
    let c4 = make_acc("c4", "c4@example.invalid", "1//RT_C4", now + 7200, now);
    let c5 = make_acc("c5", "c5@example.invalid", "1//RT_C5", now + 7200, now);

    repo.with_write_lock(|tx| {
        tx.upsert_account(src.clone(), true, now)?;
        for c in [&c1, &c2, &c3, &c4, &c5] {
            tx.upsert_account(c.clone(), false, now)?;
        }
        let mut pol = SwitchPolicy {
            enabled: true,
            reserve_percentage: 10,
            candidate_min_percentage: 50,
            monitored_model: "gemini".into(),
            candidate_account_ids: vec![
                "c1".into(),
                "c2".into(),
                "c3".into(),
                "c4".into(),
                "c5".into(),
            ],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&src.token).unwrap())
        .unwrap();

    // Step-and-Verify probes candidates sequentially ONE AT A TIME (`peak == 1`):
    // `c1` returns 20% (< 50%) AND rotates its refresh_token inside the slot during `/usage` ->
    // rotated RT is synced back and SURVIVES when Step-and-Verify advances to `c2` (85% winner)!
    // `c3`, `c4`, `c5` are NEVER probed!
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let active_c = active.clone();
    let peak_c = peak.clone();
    let runner = AuditSlotQuotaRunner::from_handler(move |p, _, slot| {
        let cur = active_c.fetch_add(1, Ordering::SeqCst) + 1;
        peak_c.fetch_max(cur, Ordering::SeqCst);
        let res = if slot.contains("1//RT_C1") {
            // Simulate official `agy` rotating c1's refresh_token during `/usage`!
            fs::write(
                &p.active_slot_file,
                serde_json::to_vec(&json!({
                    "access_token": "ya29.AT_c1_NEW",
                    "refresh_token": "1//C1_ROTATED_SURVIVES_HOP",
                    "token_type": "Bearer",
                    "expiry": "2099-01-01T00:00:00Z",
                    "id_token_email": "c1@example.invalid"
                }))
                .unwrap(),
            )
            .unwrap();
            Ok(audit_quota_outcome(0.20, "2099-01-01T00:00:00Z"))
        } else if slot.contains("1//RT_C2_OLD") {
            Ok(audit_quota_outcome(0.85, "2099-01-01T00:00:00Z"))
        } else {
            panic!("Candidates c3/c4/c5 must NEVER be probed after c2 lands! slot={slot}");
        };
        active_c.fetch_sub(1, Ordering::SeqCst);
        res
    });

    let mut engine = DaemonEngine::new();
    let out = engine
        .run_single_tick(
            &repo,
            &backend,
            &runner,
            &reg,
            &DaemonConfigOverrides {
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now,
        )
        .await
        .unwrap();

    assert_eq!(
        out,
        TickStageOutcome::CommittedSwitch {
            source_id: "src".into(),
            target_id: "c2".into()
        }
    );
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    // `c1`'s rotated refresh_token MUST survive advancing to `c2`!
    assert_eq!(
        repo.read_account_unchecked("c1")
            .unwrap()
            .token
            .refresh_token,
        "1//C1_ROTATED_SURVIVES_HOP"
    );
}

// ============================================================================
// Review R1 (A12 / D3): `run -- agy` fails closed on unreadable `/proc` & >15-char non-dumpable `comm`
// ============================================================================
#[tokio::test]
async fn review_r1_run_managed_agy_fails_closed_on_unreadable_proc_and_truncated_dumpable_comm() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = 1_800_000_000i64;

    let acc = make_acc(
        "acc-run",
        "run@example.invalid",
        "1//RT_RUN",
        now + 7200,
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    let marker = h.tmp.path().join("agy_spawned_marker");
    let fake_agy_dir = h.tmp.path().join("bin");
    fs::create_dir_all(&fake_agy_dir).unwrap();
    let fake_agy = fake_agy_dir.join("agy");
    fs::write(
        &fake_agy,
        format!("#!/bin/sh\necho spawned > '{}'\nexit 0\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    // 1. `mode 000` `/proc` (when non-root / without DAC_READ_SEARCH): `run -- agy` MUST exit 8 without touching slot or spawning child!
    fs::set_permissions(&h.proc_dir, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&h.proc_dir).is_err() {
        let out = h
            .cli()
            .args(["--json", "run", "--", fake_agy.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(8),
            "`run -- agy` MUST fail closed with exit 8 when `/proc` is unreadable: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !paths.active_slot_file.exists(),
            "Active slot MUST NOT be written when `/proc` is unverified!"
        );
        assert!(!marker.exists(), "Child `agy` MUST NOT be spawned!");
    }
    fs::set_permissions(&h.proc_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // 2. Same-UID process with unreadable `/proc/<pid>/exe` (`PR_SET_DUMPABLE=0`) and 15-byte truncated `comm`
    //    matching a >15-char `AGY_SWITCH_CLI_AGY_BIN` basename MUST ALSO fail closed (`Unverified` -> exit 8)!
    let long_agy = fake_agy_dir.join("custom-agy-wrapper-longname");
    fs::write(&long_agy, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&long_agy, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(h.proc_dir.join("4242")).unwrap();
    // Kernel truncates `comm` to 15 bytes: `"custom-agy-wrap"`
    fs::write(
        h.proc_dir.join("4242/stat"),
        "4242 (custom-agy-wrap) S 1 4242 4242 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 123456 1000 10",
    )
    .unwrap();
    fs::write(h.proc_dir.join("4242/comm"), "custom-agy-wrap\n").unwrap();

    {
        let _pg = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir);
        let _bg = ScopedEnvVar::set("AGY_SWITCH_CLI_AGY_BIN", &long_agy);
        assert!(
            matches!(
                observe_runtime_state(&paths),
                agy_switch_cli::domain::account::RuntimeState::Unverified { .. }
            ),
            "15-byte truncated comm on non-dumpable candidate must return Unverified!"
        );
    }

    let out_trunc = h
        .cli()
        .env("AGY_SWITCH_CLI_AGY_BIN", &long_agy)
        .args(["--json", "run", "--", fake_agy.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out_trunc.status.code(), Some(8));
    assert!(!paths.active_slot_file.exists());
    assert!(!marker.exists());
}

// ============================================================================
// Review R2 (A09 / A10 / §4.2 #2): `pool-0` group-named buckets, untagged Free rejection, prod project_id, summary 401
// ============================================================================
#[tokio::test]
async fn review_r2_quota_eval_supports_group_named_pool0_buckets_rejects_untagged_free_and_protects_prod_project(
) {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let backend = FileSessionBackend;
    let now = 1_800_000_000i64;

    // 1. Official CLI `pool-0`, `pool-1`, `pool-2` buckets (classified via `group.display_name`) evaluate to `Known`!
    let mut acc = make_acc("acc-p0", "p0@example.invalid", "1//RT_P0", now + 7200, now);
    acc.token.project_id = Some("prod-proj-1".into());
    repo.with_write_lock(|tx| tx.upsert_account(acc.clone(), true, now))
        .unwrap();
    backend
        .write_slot(&h.paths(), &serialize_session_payload(&acc.token).unwrap())
        .unwrap();

    let runner_pool0 = AuditSlotQuotaRunner::from_handler(|p, _, _| {
        // Official `agy` writes `user_tier` + rotated RT into slot during `/usage`
        fs::write(
            &p.active_slot_file,
            serde_json::to_vec(&json!({
                "access_token": "ya29.SUM_RENEWED",
                "refresh_token": "1//RT_P0_ROTATED_IN_AGY",
                "token_type": "Bearer",
                "expiry": "2099-01-01T00:00:00Z",
                "id_token_email": "p0@example.invalid",
                "user_tier": "Google AI Pro"
            }))
            .unwrap(),
        )
        .unwrap();
        Ok(OfficialCliUsageOutcome::Quota {
            description: None,
            groups: vec![
                agy_switch_cli::domain::quota::QuotaGroup {
                    display_name: "Gemini Models".into(),
                    description: None,
                    buckets: vec![
                        agy_switch_cli::domain::quota::QuotaBucket {
                            bucket_id: "pool-0".into(),
                            window: "weekly".into(),
                            remaining_fraction: 0.75,
                            remaining_fraction_known: Some(true),
                            reset_time: "2099-01-07T00:00:00Z".into(),
                            display_name: None,
                            description: None,
                        },
                        agy_switch_cli::domain::quota::QuotaBucket {
                            bucket_id: "pool-0".into(),
                            window: "5h".into(),
                            remaining_fraction: 0.60,
                            remaining_fraction_known: Some(true),
                            reset_time: "2099-01-01T05:00:00Z".into(),
                            display_name: None,
                            description: None,
                        },
                    ],
                },
                agy_switch_cli::domain::quota::QuotaGroup {
                    display_name: "Claude / GPT".into(),
                    description: None,
                    buckets: vec![
                        agy_switch_cli::domain::quota::QuotaBucket {
                            bucket_id: "pool-1".into(),
                            window: "weekly".into(),
                            remaining_fraction: 0.55,
                            remaining_fraction_known: Some(true),
                            reset_time: "2099-01-07T00:00:00Z".into(),
                            display_name: None,
                            description: None,
                        },
                        agy_switch_cli::domain::quota::QuotaBucket {
                            bucket_id: "pool-1".into(),
                            window: "5h".into(),
                            remaining_fraction: 0.50,
                            remaining_fraction_known: Some(true),
                            reset_time: "2099-01-01T05:00:00Z".into(),
                            display_name: None,
                            description: None,
                        },
                    ],
                },
                agy_switch_cli::domain::quota::QuotaGroup {
                    display_name: "Gemini 4 Argon".into(),
                    description: None,
                    buckets: vec![agy_switch_cli::domain::quota::QuotaBucket {
                        bucket_id: "pool-2".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.40,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    }],
                },
            ],
        })
    });

    let updated = refresh_active_slot_quota_with_runner(
        &repo,
        &backend,
        &runner_pool0,
        true,
        Some("acc-p0"),
        now,
    )
    .await
    .unwrap()
    .account;
    let obs = updated.quota.as_ref().unwrap();
    assert_eq!(updated.token.project_id.as_deref(), Some("prod-proj-1"));
    assert_eq!(updated.token.refresh_token, "1//RT_P0_ROTATED_IN_AGY");
    assert_eq!(
        evaluate_quota_observation(obs, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Known {
            remaining_percentage: 60.0
        }
    );
    assert_eq!(
        evaluate_quota_observation(obs, "claude", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Known {
            remaining_percentage: 50.0
        }
    );
    assert_eq!(
        evaluate_quota_observation(obs, "argon", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Known {
            remaining_percentage: 40.0
        }
    );

    // Expired `pool-0` 5h bucket MUST mark observation `Stale(reset_deadline_passed)` even on a Free account!
    let mut expired_pool0 = obs.clone();
    expired_pool0.subscription_tier = Some("Free Tier".into());
    expired_pool0.tier_source_env = Some(obs.source_env);
    expired_pool0.quota_groups.as_mut().unwrap()[0].buckets[1].reset_time =
        "2020-01-01T00:00:00Z".into();
    assert_eq!(
        evaluate_quota_observation(&expired_pool0, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Stale {
            reason: "reset_deadline_passed".into()
        }
    );

    // 2. Untagged `tier_source_env: None` with `"Free Tier"` and missing 5h MUST remain `Unknown`!
    let mut untagged_free = obs.clone();
    untagged_free.subscription_tier = Some("Free Tier".into());
    untagged_free.tier_source_env = None;
    untagged_free.quota_groups.as_mut().unwrap()[0]
        .buckets
        .retain(|b| b.window == "weekly");
    assert!(matches!(
        evaluate_quota_observation(&untagged_free, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Unknown { .. }
    ));
}

// ============================================================================
// Review R3 (A15 / E2): PTY `--json` channel isolation on `accounts add --json` & `/dev/tty` OAuth URL delivery
// ============================================================================
#[test]
fn review_r3_pty_json_channel_isolation_for_accounts_add_and_oauth_manual_tty_delivery() {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;

    let _g = ENV_MUTEX.blocking_lock();
    let h = IsolatedHarness::new();

    // 1. `accounts add --json` on a PTY with empty input MUST emit pure single-line JSON on `stderr`!
    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let inspect_fd = unsafe { libc::dup(slave_fd) };
    let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
    let mut master = unsafe { fs::File::from_raw_fd(master_fd) };
    let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_fd) };

    let child = h
        .cli()
        .args(["--json", "accounts", "add"])
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    for _ in 0..80 {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut t) } == 0
            && (t.c_lflag & libc::ECHO) == 0
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    master.write_all(b"\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let parsed_err: serde_json::Value = serde_json::from_slice(&out.stderr).expect(
        "`accounts add --json` on PTY MUST produce valid single-line JSON on stderr without prompt prefix!",
    );
    assert_eq!(parsed_err["schema_version"], 1);
    assert_eq!(parsed_err["ok"], false);
    assert_eq!(parsed_err["exit_code"], 2);

    // 2. `auth login --json` with a controlling PTY (`/dev/tty`) delivers the authorization URL
    //    to `/dev/tty` while keeping `stderr` 100% pure single-line JSON!
    let mut m2_fd: libc::c_int = -1;
    let mut s2_fd: libc::c_int = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut m2_fd,
                &mut s2_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let ctty_fd = s2_fd;
    let slave2_in = unsafe { fs::File::from_raw_fd(s2_fd) };
    let mut master2 = unsafe { fs::File::from_raw_fd(m2_fd) };

    let mut login_cmd = h.cli();
    login_cmd
        .args(["--json", "auth", "login"])
        .stdin(Stdio::from(slave2_in))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        login_cmd.pre_exec(move || {
            let _ = libc::setsid();
            let _ = libc::ioctl(ctty_fd, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let login_child = login_cmd.spawn().unwrap();

    unsafe {
        let flags = libc::fcntl(master2.as_raw_fd(), libc::F_GETFL);
        let _ = libc::fcntl(master2.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut tty_banner = Vec::new();
    for _ in 0..80 {
        let mut buf = [0u8; 2048];
        if let Ok(n) = master2.read(&mut buf) {
            if n > 0 {
                tty_banner.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&tty_banner).contains("Paste the FULL callback URL") {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let tty_str = String::from_utf8_lossy(&tty_banner);
    assert!(
        tty_str.contains("https://accounts.google.com/o/oauth2/v2/auth")
            && tty_str.contains("state="),
        "Controlling `/dev/tty` MUST receive authorization URL in `--json` mode, got: {tty_str}"
    );

    let _ = master2.write_all(b"\n");
    let login_out = login_child.wait_with_output().unwrap();
    assert_eq!(login_out.status.code(), Some(6));
    assert!(login_out.stdout.is_empty());
    let login_err_json: serde_json::Value = serde_json::from_slice(&login_out.stderr).unwrap();
    assert_eq!(login_err_json["ok"], false);
    assert_eq!(login_err_json["exit_code"], 6);
}

// ============================================================================
// Review R4 (A01 / A02 / S02): Stale RT client-binding guard, `--overwrite` disable clear, & `pending_auth` lifecycle
// ============================================================================
#[tokio::test]
async fn review_r4_stale_rt_client_binding_overwrite_disable_recovery_and_pending_auth_lifecycle() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let reg =
        OAuthClientRegistry::parse_from_raw(Some("other_client|other_cid|other_csec|Other"), None);
    let now = 1_800_000_000i64;

    // 1. Seed account with `RT_V1`, rotate to `RT_V2` so `RT_V1` is in `previous_refresh_token_digests`!
    let mut acc = make_acc(
        "acc-rot",
        "rot@example.invalid",
        "1//RT_V1",
        now + 7200,
        now,
    );
    let mut tok_v2 = acc.token.clone();
    tok_v2.refresh_token = "1//RT_V2".into();
    acc.record_token_transition(tok_v2);
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    // Passing already-superseded `1//RT_V1` to `accounts add` with `--client other_client` MUST fail with exit 5
    // and ZERO network requests (never sending `1//RT_V2` to `other_client`)!
    let zero_net = MockTransport::default();
    let stale_err = bootstrap_and_persist_refresh_token(
        &repo,
        &zero_net,
        &fast_oauth(),
        &reg,
        "1//RT_V1",
        Some("other_client"),
        Some("Hijack Label"),
        now + 1,
    )
    .await
    .unwrap_err();
    assert_eq!(stale_err.exit_code, ExitCode::LockBusyOrConflict);
    assert_eq!(stale_err.error_code, "stale_rotated_refresh_token");
    assert!(zero_net.recorded_requests().is_empty());

    // Passing live `1//RT_V2` with conflicting `--client other_client` MUST fail with `oauth_client_mismatch`!
    let mismatch_err = bootstrap_and_persist_refresh_token(
        &repo,
        &zero_net,
        &fast_oauth(),
        &reg,
        "1//RT_V2",
        Some("other_client"),
        None,
        now + 2,
    )
    .await
    .unwrap_err();
    assert_eq!(mismatch_err.error_code, "oauth_client_mismatch");
    assert!(zero_net.recorded_requests().is_empty());

    // 2. `accounts import --overwrite` with a genuinely new RT clears `RevokedOrExpiredGrant` while preserving `Manual`!
    repo.with_write_lock(|tx| {
        tx.mark_account_disabled(
            "acc-rot",
            DisableReasonCode::RevokedOrExpiredGrant,
            Some("revoked".into()),
            now + 3,
        )?;
        let mut man = make_acc(
            "acc-man",
            "man@example.invalid",
            "1//RT_MAN_1",
            now + 7200,
            now,
        );
        man.disabled = true;
        man.disabled_code = Some(DisableReasonCode::Manual);
        tx.upsert_account(man, false, now)?;
        Ok(())
    })
    .unwrap();

    let fresh_bundle = h.tmp.path().join("fresh_replacement.json");
    fs::write(
        &fresh_bundle,
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "accounts": [
                {"email": "rot@example.invalid", "refresh_token": "1//RT_V3_FRESH_REPLACEMENT", "oauth_client_key": "antigravity_enterprise"},
                {"email": "man@example.invalid", "refresh_token": "1//RT_MAN_2_FRESH_REPLACEMENT", "oauth_client_key": "antigravity_enterprise"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&fresh_bundle, fs::Permissions::from_mode(0o600)).unwrap();

    let ow_rep = import_transfer_bundle_file(&repo, &fresh_bundle, true, now + 4)
        .await
        .unwrap();
    assert_eq!(ow_rep.updated_count, 2);
    assert!(
        !repo.read_account_unchecked("acc-rot").unwrap().disabled,
        "Replacing revoked token via `--overwrite` must clear RevokedOrExpiredGrant!"
    );
    assert!(
        repo.read_account_unchecked("acc-man").unwrap().disabled,
        "`--overwrite` must preserve Manual disablement!"
    );

    // 3. `pending_auth` corrupt file detection (`status` exit 1), `0644` warning detection, and `resume_pending_auth_records`!
    let client = reg.select_for_login(None).unwrap();
    let session = build_authorization_session(client, 54545, GOOGLE_AUTH_URL).unwrap();
    let fail_userinfo = MockTransport::from_handler(|req| {
        if req.url.contains("userinfo") {
            return Err(TransportError {
                is_timeout: true,
                is_connect: false,
                message: "simulated transient userinfo timeout".into(),
            });
        }
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.PENDING_LOGIN_AT",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "1//PENDING_LOGIN_RT_RECOVERED",
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        ))
    });
    assert!(complete_login_exchange_locked(
        &repo,
        &fail_userinfo,
        &fast_oauth(),
        &reg,
        &session,
        "4/one-time-login-code",
        Some("Recovered Login"),
        now + 5,
    )
    .await
    .is_err());

    // Inject a corrupt `pend-corrupt.json` and loosen valid pending file to `0644`
    let valid_pend = repo.list_pending_auth_readonly().unwrap();
    assert_eq!(valid_pend.len(), 1);
    let valid_pend_path = paths.pending_auth_file(&valid_pend[0].id);
    fs::set_permissions(&valid_pend_path, fs::Permissions::from_mode(0o644)).unwrap();
    let corrupt_pend_path = paths.pending_auth_dir().join("pend-corrupt.json");
    fs::write(&corrupt_pend_path, b"{corrupt-json").unwrap();
    fs::set_permissions(&corrupt_pend_path, fs::Permissions::from_mode(0o600)).unwrap();

    // `status` MUST report exit 1 (never swallowing corrupt `pending_auth`!)
    let st_bad = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_bad.status.code(), Some(1));

    // Unrelated `accounts add` MUST still work despite `pend-corrupt.json`!
    let ok_unrelated = MockTransport::from_handler(|req| {
        if req.url.contains("userinfo") {
            return Ok(MockTransport::json_response(
                200,
                json!({"email": "unrelated@example.invalid", "name": "Unrelated"}),
            ));
        }
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.UNREL",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "1//RT_UNRELATED_OK",
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        ))
    });
    bootstrap_and_persist_refresh_token(
        &repo,
        &ok_unrelated,
        &fast_oauth(),
        &reg,
        "1//RT_UNRELATED_INPUT",
        None,
        None,
        now + 6,
    )
    .await
    .unwrap();

    // Remove `pend-corrupt.json`; verify `status --json` reports `pending_auth_ok == false` on `0644`, then `true` after `chmod 600`!
    fs::remove_file(&corrupt_pend_path).unwrap();
    let st_warn = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_warn.status.code(), Some(0));
    let st_warn_j: serde_json::Value = serde_json::from_slice(&st_warn.stdout).unwrap();
    assert_eq!(st_warn_j["pending_auth_ok"], false);
    fs::set_permissions(&valid_pend_path, fs::Permissions::from_mode(0o600)).unwrap();
    let st_clean = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_clean.status.code(), Some(0));
    let st_clean_j: serde_json::Value = serde_json::from_slice(&st_clean.stdout).unwrap();
    assert_eq!(st_clean_j["pending_auth_ok"], true);

    // `auth pending --json` lists metadata without leaking refresh_token!
    let pend_list = h
        .cli()
        .args(["auth", "pending", "--json"])
        .output()
        .unwrap();
    assert_eq!(pend_list.status.code(), Some(0));
    let pend_stdout = String::from_utf8(pend_list.stdout).unwrap();
    assert!(pend_stdout.contains(&valid_pend[0].id));
    assert!(!pend_stdout.contains("PENDING_LOGIN_RT_RECOVERED"));

    // `resume_pending_auth_records` completes `userinfo` and binds the interrupted `auth login` account!
    let ok_resume_userinfo = MockTransport::from_queue([Ok(MockTransport::json_response(
        200,
        json!({"email": "recovered@example.invalid", "name": "Recovered"}),
    ))]);
    let resumed = agy_switch_cli::oauth::refresh::resume_pending_auth_records(
        &repo,
        &ok_resume_userinfo,
        &fast_oauth(),
        &reg,
        now + 7,
    )
    .await
    .unwrap();
    assert_eq!(resumed.resumed_accounts.len(), 1);
    assert_eq!(
        resumed.resumed_accounts[0].email,
        "recovered@example.invalid"
    );
    assert_eq!(
        resumed.resumed_accounts[0].token.refresh_token,
        "1//PENDING_LOGIN_RT_RECOVERED"
    );
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());
}

// ============================================================================
// Review R5 (A05 / A07 / §4.2 #4): Uninitialized journal reconcile, usable repair priority, Wait-mode qualify, foreground loop
// ============================================================================
#[tokio::test]
async fn review_r5_journal_reconcile_uninitialized_slot_usable_priority_wait_qualify_and_foreground_loop(
) {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_800_000_000i64;

    let mut disabled_prev = make_acc(
        "acc-dis",
        "dis@example.invalid",
        "1//RT_DIS",
        now + 7200,
        now,
    );
    disabled_prev.disabled = true;
    disabled_prev.disabled_code = Some(DisableReasonCode::Manual);
    let usable_alt = make_acc("acc-ok", "ok@example.invalid", "1//RT_OK", now + 7200, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(disabled_prev, true, now)?;
        tx.upsert_account(usable_alt.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    // 1. Stuck `RecoveryIncomplete` journal when `~/.gemini/antigravity-cli` is `Uninitialized` (removed)
    //    MUST unwedge cleanly via pre-write journal reconciliation (exit 0)!
    fs::remove_dir_all(h.home.join(".gemini")).unwrap();
    let stuck_j = agy_switch_cli::session::journal::SwitchJournal {
        schema_version: 1,
        operation_id: "op-uninit".into(),
        phase: agy_switch_cli::session::journal::JournalPhase::RecoveryIncomplete,
        prev_selected_account_id: Some("acc-dis".into()),
        target_account_id: "acc-ok".into(),
        prev_slot_digest: Some("abc".into()),
        target_slot_digest: None,
        token_rotated: false,
        started_at: now,
        updated_at: now,
        note: Some("simulated".into()),
    };
    repo.with_write_lock(|tx| {
        agy_switch_cli::session::journal::write_journal(tx.paths(), &stuck_j)
    })
    .unwrap();

    let fix_uninit = h
        .cli()
        .args(["policy", "set", "--reserve", "10", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        fix_uninit.status.code(),
        Some(0),
        "Journal reconciliation MUST succeed when slot dir is Uninitialized: stderr={}",
        String::from_utf8_lossy(&fix_uninit.stderr)
    );
    assert!(read_journal_readonly(&paths).unwrap().is_none());

    // 2. When slot dir IS initialized (`AbsentInInitializedDir`), journal repair prefers usable `acc-ok` over disabled `acc-dis`!
    fs::create_dir_all(&paths.active_slot_dir).unwrap();
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
    repo.with_write_lock(|tx| {
        agy_switch_cli::session::journal::write_journal(tx.paths(), &stuck_j)
    })
    .unwrap();
    let fix_usable = h
        .cli()
        .args(["policy", "set", "--reserve", "12", "--json"])
        .output()
        .unwrap();
    assert_eq!(fix_usable.status.code(), Some(0));
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_OK"));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-ok")
    );

    // 3. `daemon` `PolicyMode::Wait`: higher-priority non-disabled `c1` gains qualified quota while `c2` plan is waiting!
    let make_q = |pct: f64| -> QuotaObservation {
        let mut q = QuotaObservation::new(now, QuotaSourceEnv::Production);
        q.subscription_tier = Some("Google AI Pro".into());
        q.tier_source_env = Some(QuotaSourceEnv::Production);
        q.models.push(agy_switch_cli::domain::quota::ModelQuota {
            name: "gemini-3.8-flash".into(),
            percentage: (pct * 100.0).round() as i32,
            percentage_known: Some(true),
            observed_remaining_fraction: Some(pct),
            primary_quota: Some(agy_switch_cli::domain::quota::PrimaryModelQuota {
                remaining_fraction: Some(pct),
                reset_time: "2099-01-01T00:00:00Z".into(),
            }),
            quota_bucket_id: Some("gemini-weekly".into()),
            reset_time: "2099-01-01T00:00:00Z".into(),
            display_name: None,
            supports_images: None,
            supports_thinking: None,
            thinking_budget: None,
            recommended: None,
            max_tokens: None,
            max_output_tokens: None,
            supported_mime_types: None,
        });
        q.quota_groups = Some(vec![agy_switch_cli::domain::quota::QuotaGroup {
            display_name: "Gemini Models".into(),
            description: None,
            buckets: vec![
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: pct,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-01T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: pct,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-01T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
            ],
        }]);
        q
    };

    let mut c1 = make_acc("c1", "c1@example.invalid", "1//RT_C1", now + 7200, now);
    c1.quota = Some(make_q(0.15)); // Below minimum 50% (NOT disabled!)
    let mut c2 = make_acc("c2", "c2@example.invalid", "1//RT_C2", now + 7200, now);
    c2.quota = Some(make_q(0.80)); // Qualified!
    repo.with_write_lock(|tx| {
        let mut src = tx.load_account_opt("acc-ok")?.unwrap();
        src.quota = Some(make_q(0.05));
        tx.save_account(&src)?;
        tx.upsert_account(c1, false, now)?;
        tx.upsert_account(c2, false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Wait,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 10,
            candidate_min_percentage: 50,
            monitored_model: "gemini".into(),
            candidate_account_ids: vec!["c1".into(), "c2".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();

    // Simulate active `agy` process during Tick 1
    fs::create_dir_all(h.proc_dir.join("8888")).unwrap();
    fs::write(
        h.proc_dir.join("8888/stat"),
        "8888 (agy) S 1 8888 8888 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 777777 1000 10",
    )
    .unwrap();
    fs::write(h.proc_dir.join("8888/comm"), "agy\n").unwrap();

    let clock = Arc::new(ManualClock::new(now));
    let mut engine = DaemonEngine::with_clock(clock.clone());
    let runner_r5 = AuditSlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_C1") {
            Ok(audit_quota_outcome(0.95, "2099-01-01T00:00:00Z"))
        } else if slot.contains("1//RT_C2") {
            Ok(audit_quota_outcome(0.85, "2099-01-01T00:00:00Z"))
        } else {
            Ok(audit_quota_outcome(0.05, "2099-01-01T00:00:00Z"))
        }
    });
    let r5_overrides = DaemonConfigOverrides {
        step_buffer_delay: Duration::ZERO,
        ..DaemonConfigOverrides::default()
    };
    {
        let _pg = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir);
        let t1 = engine
            .run_single_tick(&repo, &backend, &runner_r5, &reg, &r5_overrides, now)
            .await
            .unwrap();
        assert_eq!(
            t1,
            TickStageOutcome::BlockedByActiveProcess {
                target_id: "c2".into()
            }
        );
    }

    // While waiting, `c1` quota refreshes externally to 95%, and `agy` exits!
    fs::remove_dir_all(h.proc_dir.join("8888")).unwrap();
    repo.with_write_lock(|tx| {
        let mut c1_now = tx.load_account_opt("c1")?.unwrap();
        c1_now.quota = Some(make_q(0.95));
        tx.save_account(&c1_now)
    })
    .unwrap();

    {
        let _pg = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir);
        // Under Step-and-Verify, Priority order immediately evaluates `c1` first and lands directly on `c1`!
        let t2 = engine
            .run_single_tick(&repo, &backend, &runner_r5, &reg, &r5_overrides, now + 1)
            .await
            .unwrap();
        assert_eq!(
            t2,
            TickStageOutcome::CommittedSwitch {
                source_id: "acc-ok".into(),
                target_id: "c1".into()
            }
        );
    }

    // 4. Audit §4.2 #4: Actual foreground `daemon` loop never re-enters concurrently under slow `agy -p "/usage"`!
    let slow_agy = h.tmp.path().join("slow-daemon-agy");
    let active_lock_dir = h.tmp.path().join("agy-in-flight-lock");
    let overlap_marker = h.tmp.path().join("agy-overlap-detected");
    let hit_marker = h.tmp.path().join("agy-hit");
    fs::write(
        &slow_agy,
        format!(
            "#!/bin/sh\n\
             if ! mkdir \"{lock}\" 2>/dev/null; then\n\
               echo overlap > \"{ov}\"\n\
               exit 1\n\
             fi\n\
             echo hit > \"{hit}\"\n\
             sleep 0.15\n\
             rmdir \"{lock}\"\n\
             printf '%s\\n' '{{\"conversation_id\":\"\",\"status\":\"SUCCESS\",\"command\":{{\"name\":\"usage\",\"data\":{{\"groups\":[]}}}}}}'\n",
            lock = active_lock_dir.display(),
            ov = overlap_marker.display(),
            hit = hit_marker.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&slow_agy, fs::Permissions::from_mode(0o755)).unwrap();

    repo.with_write_lock(|tx| {
        let mut c1_u = tx.load_account_opt("c1")?.unwrap();
        c1_u.quota = None; // Trigger Stage 1 official CLI probe
        tx.save_account(&c1_u)?;
        let mut dstate = agy_switch_cli::switching::daemon::read_daemon_state_readonly(tx.paths())?;
        dstate.cooldown_until = 0;
        agy_switch_cli::switching::daemon::save_daemon_state_in_tx(tx.paths(), &dstate)
    })
    .unwrap();

    let mut d_loop = h
        .cli()
        .env("AGY_SWITCH_CLI_AGY_BIN", &slow_agy)
        .args(["daemon", "--interval", "1", "--cooldown", "0"])
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if hit_marker.exists() {
            break;
        }
        ::tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ::tokio::time::sleep(Duration::from_millis(200)).await;
    unsafe {
        libc::kill(d_loop.id() as i32, libc::SIGTERM);
    }
    let loop_st = d_loop.wait().unwrap();
    assert_eq!(loop_st.code(), Some(0));
    assert!(
        hit_marker.exists(),
        "Daemon loop must have invoked synthetic agy"
    );
    assert!(
        !overlap_marker.exists(),
        "Foreground daemon loop must NEVER overlap two concurrent ticks!"
    );
}

// ============================================================================
// Review R6 (§4.2 #8): Real `libc::SIGKILL` (-9) at `prepared` and `index_committed` boundaries
// ============================================================================
#[test]
fn review_r6_real_sigkill_signal_9_prepared_and_index_committed_boundaries() {
    let _g = ENV_MUTEX.blocking_lock();
    if let Ok(stage) = std::env::var("AGY_TEST_SIGKILL_STAGE") {
        let home = PathBuf::from(std::env::var("AGY_CHILD_HOME").unwrap());
        let data = PathBuf::from(std::env::var("AGY_CHILD_DATA").unwrap());
        let cache = PathBuf::from(std::env::var("AGY_CHILD_CACHE").unwrap());
        let marker = PathBuf::from(std::env::var("AGY_CHILD_READY_MARKER").unwrap());
        let paths = HeadlessPaths::with_explicit(home, data, cache);
        let repo = StoreRepository::new(paths.clone());

        struct StagePauseBackend {
            stage: String,
            marker: PathBuf,
        }
        impl CredentialBackend for StagePauseBackend {
            fn name(&self) -> &'static str {
                "file_session"
            }
            fn uses_keyring(&self) -> bool {
                false
            }
            fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
                FileSessionBackend.inspect_slot(paths)
            }
            fn snapshot_before_write(
                &self,
                paths: &HeadlessPaths,
            ) -> agy_switch_cli::error::CliResult<Option<Vec<u8>>> {
                FileSessionBackend.snapshot_before_write(paths)
            }
            fn write_slot(
                &self,
                paths: &HeadlessPaths,
                payload: &str,
            ) -> agy_switch_cli::error::CliResult<()> {
                if self.stage == "prepared" {
                    // Journal is written in `SlotCommitting` BEFORE `write_slot` mutates the slot!
                    fs::write(&self.marker, b"ready").unwrap();
                    loop {
                        std::thread::sleep(Duration::from_secs(60));
                    }
                }
                FileSessionBackend.write_slot(paths, payload)
            }
            fn remove_slot(&self, paths: &HeadlessPaths) -> agy_switch_cli::error::CliResult<()> {
                FileSessionBackend.remove_slot(paths)
            }
        }

        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let l1 = ActiveSlotLock::try_acquire(&paths, false).unwrap();
            if stage == "index_committed" {
                // Commit slot + index, leave journal in `CommittedSlot`, then wait for real SIGKILL!
                let acc_b = repo.read_account_unchecked("acc-b").unwrap();
                let payload = serialize_session_payload(&acc_b.token).unwrap();
                let target_dig =
                    agy_switch_cli::session::payload::bytes_sha256_hex(payload.as_bytes());
                FileSessionBackend.write_slot(&paths, &payload).unwrap();
                repo.with_write_lock(|tx| {
                    tx.commit_selected_account("acc-b", 1_800_000_000)?;
                    let j = agy_switch_cli::session::journal::SwitchJournal {
                        schema_version: 1,
                        operation_id: "op-idx".into(),
                        phase: agy_switch_cli::session::journal::JournalPhase::CommittedSlot,
                        prev_selected_account_id: Some("acc-a".into()),
                        target_account_id: "acc-b".into(),
                        prev_slot_digest: None,
                        target_slot_digest: Some(target_dig),
                        token_rotated: false,
                        started_at: 1_800_000_000,
                        updated_at: 1_800_000_000,
                        note: None,
                    };
                    agy_switch_cli::session::journal::write_journal(tx.paths(), &j)
                })
                .unwrap();
                fs::write(&marker, b"ready").unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            } else {
                let _ = execute_switch_with_slot_lock(
                    &l1,
                    &repo,
                    &StagePauseBackend { stage, marker },
                    &OAuthClientRegistry::parse_from_raw(None, None),
                    "acc-b",
                    false,
                    1_800_000_000,
                );
            }
        });
        return;
    }

    for (stage, expected_doc_rc, expected_sel) in
        [("prepared", 0, "acc-a"), ("index_committed", 7, "acc-b")]
    {
        let h = IsolatedHarness::new();
        let paths = h.paths();
        let repo = StoreRepository::new(paths.clone());
        let now = 1_800_000_000i64;
        let acc_a = make_acc("acc-a", "a@example.invalid", "1//RT_A", now + 7200, now);
        let acc_b = make_acc("acc-b", "b@example.invalid", "1//RT_B", now + 7200, now);
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc_a.clone(), true, now)?;
            tx.upsert_account(acc_b, false, now)?;
            Ok(())
        })
        .unwrap();
        FileSessionBackend
            .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
            .unwrap();

        let marker = h.tmp.path().join("sigkill_stage_marker");
        let mut child_guard = KillChildOnDrop::new(
            Command::new(std::env::current_exe().unwrap())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &h.home)
                .env("TMPDIR", h.tmp.path())
                .env("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir)
                .env("AGY_TEST_SIGKILL_STAGE", stage)
                .env("AGY_CHILD_HOME", &paths.home_dir)
                .env("AGY_CHILD_DATA", &paths.data_dir)
                .env("AGY_CHILD_CACHE", &paths.cache_dir)
                .env("AGY_CHILD_READY_MARKER", &marker)
                .args([
                    "--exact",
                    "review_r6_real_sigkill_signal_9_prepared_and_index_committed_boundaries",
                    "--nocapture",
                ])
                .spawn()
                .unwrap(),
        );

        for _ in 0..400 {
            if marker.exists() {
                break;
            }
            if let Some(status) = child_guard.as_mut().try_wait().unwrap() {
                if !marker.exists() {
                    panic!("Child exited prematurely ({status}) before reaching stage {stage}");
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(marker.exists(), "Child did not reach stage {stage}");

        let mut child = child_guard.take();
        unsafe {
            libc::kill(child.id() as i32, libc::SIGKILL);
        }
        let st = child.wait().unwrap();
        assert_eq!(st.signal(), Some(libc::SIGKILL));

        let doc = h.cli().args(["status", "--json"]).output().unwrap();
        assert_eq!(doc.status.code(), Some(expected_doc_rc), "stage={stage}");

        let fix = h
            .cli()
            .args(["policy", "set", "--reserve", "10", "--json"])
            .output()
            .unwrap();
        assert_eq!(fix.status.code(), Some(0), "stage={stage}");
        assert_eq!(
            repo.read_snapshot()
                .unwrap()
                .index
                .selected_account_id
                .as_deref(),
            Some(expected_sel),
            "stage={stage}"
        );
        assert!(read_journal_readonly(&paths).unwrap().is_none());
    }
}

#[tokio::test]
async fn review_r7_single_quote_clap_redaction_client_key_policy_and_daemon_startup_sigterm() {
    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = 1_800_000_000i64;

    // 1. Embedded single quote `'` inside invalid CLI / env options MUST NEVER leak secret suffix!
    for (extra_env, args, forbidden) in [
        (
            None,
            vec!["auth", "login", "4/PART1'LEAKED_OAUTH_SECRET_99999"],
            "leaked_oauth_secret_99999",
        ),
        (
            None,
            vec![
                "--json",
                "auth",
                "login",
                "4/PART1'LEAKED_OAUTH_JSON_SECRET_99999",
            ],
            "leaked_oauth_json_secret_99999",
        ),
        (
            None,
            vec!["daemon", "--interval", "1//PART1'LEAKED_ARGV_SECRET_99999"],
            "leaked_argv_secret_99999",
        ),
        (
            Some((
                "AGY_SWITCH_CLI_INTERVAL",
                "1//PART1'LEAKED_ENV_SECRET_99999",
            )),
            vec!["daemon"],
            "leaked_env_secret_99999",
        ),
    ] {
        let mut cmd = h.cli();
        if let Some((k, v)) = extra_env {
            cmd.env(k, v);
        }
        let out = cmd.args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args={args:?}");
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .to_ascii_lowercase();
        assert!(
            !combined.contains(forbidden),
            "Leaked {forbidden} for {args:?}: {combined}"
        );
        assert!(
            !combined.contains("error: error:"),
            "Double error prefix for {args:?}: {combined}"
        );
    }

    // 2. Malformed `ANTIGRAVITY_OAUTH_CLIENTS`, accidental `--client <SECRET>`, `--from-file <SECRET>`,
    //    `--model <SECRET>`, and corrupted `policy.json` candidate IDs MUST NEVER echo secrets (case-insensitive)!
    let clients_out = h
        .cli()
        .env(
            "ANTIGRAVITY_OAUTH_CLIENTS",
            "GOCSPX-DirectClientSecret77777;bad_entry_GOCSPX_SUPER_SECRET_88888",
        )
        .args(["auth", "clients"])
        .output()
        .unwrap();
    assert_eq!(clients_out.status.code(), Some(0));
    let clients_combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&clients_out.stdout),
        String::from_utf8_lossy(&clients_out.stderr)
    )
    .to_ascii_lowercase();
    assert!(!clients_combined.contains("directclientsecret77777"));
    assert!(!clients_combined.contains("super_secret_88888"));

    let bad_client_flag = h
        .cli()
        .args(["auth", "login", "--client", "GOCSPX-FlagClientSecret66666"])
        .output()
        .unwrap();
    assert_eq!(bad_client_flag.status.code(), Some(6));
    assert!(!String::from_utf8_lossy(&bad_client_flag.stderr)
        .to_ascii_lowercase()
        .contains("flagclientsecret66666"));

    let bad_token_file = h
        .cli()
        .args([
            "accounts",
            "add",
            "--from-file",
            "1//0gLiteralTokenPassedToTokenFile55555",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_token_file.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&bad_token_file.stderr)
        .to_ascii_lowercase()
        .contains("literaltokenpassedtotokenfile55555"));

    // Bound-account `--client <SECRET>` mismatch in `bootstrap_and_persist_refresh_token`
    let acc_bound = make_acc(
        "acc-bound",
        "bound@example.invalid",
        "1//RT_BOUND_1",
        now + 3600,
        now,
    );
    let acc_other = make_acc(
        "acc-other",
        "other@example.invalid",
        "1//RT_OTHER_1",
        now + 3600,
        now,
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_bound, true, now)?;
        tx.upsert_account(acc_other, false, now)?;
        Ok(())
    })
    .unwrap();

    let mismatch_err = bootstrap_and_persist_refresh_token(
        &repo,
        &MockTransport::default(),
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::from_config_and_raw(None, None, None, None, Vec::new()),
        "1//RT_BOUND_1",
        Some("1//0gAccidentalRefreshTokenInClientFlag44444"),
        None,
        now,
    )
    .await
    .unwrap_err();
    assert!(!mismatch_err
        .message
        .to_ascii_lowercase()
        .contains("accidentalrefreshtokeninclientflag44444"));

    // `--model <SECRET>` rejected without echo; corrupted `policy.json` candidate secret rejected without echo
    let bad_model = h
        .cli()
        .args(["policy", "set", "--model", "1//0gModelTokenSecret33333"])
        .output()
        .unwrap();
    assert_eq!(bad_model.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&bad_model.stderr)
        .to_ascii_lowercase()
        .contains("modeltokensecret33333"));

    fs::write(
        paths.policy_file(),
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "revision": 1,
            "enabled": true,
            "mode": "wait",
            "strategy": "priority",
            "reserve_percentage": 10,
            "candidate_min_percentage": 30,
            "monitored_model": "all",
            "candidate_account_ids": ["1//0gDupPolicySecret22222", "1//0gDupPolicySecret22222"],
            "updated_at": now
        }))
        .unwrap(),
    )
    .unwrap();
    let corrupt_pol = h.cli().args(["policy", "show", "--json"]).output().unwrap();
    assert_eq!(corrupt_pol.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&corrupt_pol.stderr)
        .to_ascii_lowercase()
        .contains("duppolicysecret22222"));

    // 3. `accounts delete` succeeds cleanly even when `policy.json` already contains another stale candidate ID
    fs::write(
        paths.policy_file(),
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "revision": 2,
            "enabled": true,
            "mode": "wait",
            "strategy": "priority",
            "reserve_percentage": 10,
            "candidate_min_percentage": 30,
            "monitored_model": "all",
            "candidate_account_ids": ["acc-other", "acc-already-stale"],
            "updated_at": now
        }))
        .unwrap(),
    )
    .unwrap();
    let del_out = h
        .cli()
        .args(["accounts", "delete", "acc-other", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        del_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&del_out.stderr)
    );
    let cleaned_pol = repo.read_policy().unwrap();
    assert!(cleaned_pol.candidate_account_ids.is_empty());
    assert!(!cleaned_pol.enabled);

    // 4. Under v1.2.7, the legacy remote UA version fetcher is completely removed:
    //    `daemon --once` makes ZERO startup HTTP connections even when `--proxy` is set, and
    //    the removed `--no-remote-version` flag exits `2`!
    let daemon_no_http = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &h.home)
        .env("XDG_DATA_HOME", h.tmp.path().join("xdg_data"))
        .env("XDG_CACHE_HOME", &h.cache_dir)
        .env("XDG_CONFIG_HOME", h.tmp.path().join("xdg_cfg"))
        .env("XDG_RUNTIME_DIR", &h.runtime_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", h.runtime_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir)
        .args([
            "--data-dir",
            h.data_dir.to_str().unwrap(),
            "--proxy",
            "http://127.0.0.1:1",
            "daemon",
            "--once",
        ])
        .output()
        .unwrap();
    assert_eq!(daemon_no_http.status.code(), Some(0));

    let removed_flag = h
        .cli()
        .args(["--no-remote-version", "status"])
        .output()
        .unwrap();
    assert_eq!(removed_flag.status.code(), Some(2));
}

#[tokio::test]
async fn r2_01_pending_resume_and_add_interleaving_serializes_and_enforces_cas() {
    use agy_switch_cli::domain::account::{PendingAuthFlow, PendingAuthRecord};
    use agy_switch_cli::oauth::refresh::{
        bind_verified_account_from_pending, purge_all_pending_auth_records,
        resume_pending_auth_records, UserInfo,
    };
    use std::collections::HashMap;

    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let now = 2_000_000_000i64;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let endpoints = OAuthEndpoints {
        token_url: "http://127.0.0.1/token".into(),
        userinfo_url: "http://127.0.0.1/userinfo".into(),
        base_backoff: Duration::from_millis(1),
    };

    // Part A: Exact R2-01 concurrent `resume_pending_auth_records` interleaving!
    // Resumer A rotates R0 -> R1 (expires_in=60), saves R1 to pending, and suspends in `userinfo`.
    // Resumer B runs while A is suspended -> MUST be blocked by `PendingAuthLock` (zero `/token` call, no deadlock),
    // and when A resumes, A binds R1 cleanly!
    let r0 = PendingAuthRecord {
        schema_version: 1,
        id: "pend-race".into(),
        flow: PendingAuthFlow::AddToken,
        token: TokenRecord {
            access_token: "at-0".into(),
            refresh_token: "1//r2-rot-0".into(),
            expires_in: 60,
            expiry_timestamp: now - 1,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        auth_seq: 0,
        email_mismatch: false,
        input_rt_digest: None,
        custom_label: None,
        created_at: now - 100,
    };
    repo.with_write_lock(|tx| tx.save_pending_auth(&r0))
        .unwrap();

    struct StepTransport {
        version: usize,
        token_calls: Arc<AtomicUsize>,
        entered_userinfo: Arc<Notify>,
        release_userinfo: Arc<Notify>,
        fail_userinfo: bool,
    }
    impl HttpTransport for StepTransport {
        fn execute<'a>(
            &'a self,
            req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                if req.url.ends_with("/token") {
                    self.token_calls.fetch_add(1, Ordering::SeqCst);
                    let body = serde_json::to_vec(&json!({
                        "access_token": format!("at-{}", self.version),
                        "refresh_token": format!("1//r2-rot-{}", self.version),
                        "expires_in": if self.version == 1 { 60 } else { 3600 },
                        "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                    }))
                    .unwrap();
                    return Ok(HttpResponse {
                        status: 200,
                        headers: HashMap::new(),
                        body,
                    });
                }
                if self.fail_userinfo {
                    return Ok(HttpResponse {
                        status: 500,
                        headers: HashMap::new(),
                        body: b"{\"error\":\"transient\"}".to_vec(),
                    });
                }
                self.entered_userinfo.notify_one();
                self.release_userinfo.notified().await;
                Ok(HttpResponse {
                    status: 200,
                    headers: HashMap::new(),
                    body: serde_json::to_vec(&json!({"email": "race@example.invalid"})).unwrap(),
                })
            })
        }
    }

    let a_calls = Arc::new(AtomicUsize::new(0));
    let b_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let step_a = StepTransport {
        version: 1,
        token_calls: a_calls.clone(),
        entered_userinfo: entered.clone(),
        release_userinfo: release.clone(),
        fail_userinfo: false,
    };
    let step_b = StepTransport {
        version: 2,
        token_calls: b_calls.clone(),
        entered_userinfo: Arc::new(Notify::new()),
        release_userinfo: Arc::new(Notify::new()),
        fail_userinfo: true,
    };

    let mut fut_a = Box::pin(resume_pending_auth_records(
        &repo, &step_a, &endpoints, &reg, now,
    ));
    tokio::select! {
        _ = entered.notified() => {}
        _ = &mut fut_a => panic!("fut_a finished before userinfo barrier"),
    }
    assert_eq!(a_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        repo.list_pending_auth_readonly().unwrap()[0]
            .token
            .refresh_token,
        "1//r2-rot-1"
    );

    // While `fut_a` holds `PendingAuthLock("pend-race")`, BOTH `purge` AND `resume` B must refuse to clobber it!
    let purge_busy = purge_all_pending_auth_records(&repo).unwrap_err();
    assert_eq!(purge_busy.exit_code, ExitCode::LockBusyOrConflict);

    let rep_b = resume_pending_auth_records(&repo, &step_b, &endpoints, &reg, now)
        .await
        .unwrap();
    assert_eq!(b_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rep_b.resumed_accounts.len(), 0);
    assert_eq!(rep_b.failures.len(), 1);

    release.notify_one();
    let rep_a = fut_a.await.unwrap();
    assert_eq!(rep_a.resumed_accounts.len(), 1);
    assert_eq!(rep_a.resumed_accounts[0].token.refresh_token, "1//r2-rot-1");
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());

    // Part B: Direct `L3` CAS check — if `pend-cas` on disk was rotated from v1 -> v2, a stale binder holding `fp_v1`
    // MUST be rejected BEFORE mutating `accounts/` or deleting `pend-cas` (preserving v2 100% intact)!
    let p_v1 = PendingAuthRecord {
        schema_version: 1,
        id: "pend-cas".into(),
        flow: PendingAuthFlow::AddToken,
        token: TokenRecord {
            access_token: "at-v1".into(),
            refresh_token: "1//cas-v1".into(),
            expires_in: 60,
            expiry_timestamp: now + 60,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: Some(vec![
                "https://www.googleapis.com/auth/cloud-platform".into(),
                "openid".into(),
            ]),
            project_id: None,
            is_gcp_tos: true,
        },
        auth_seq: 0,
        email_mismatch: false,
        input_rt_digest: None,
        custom_label: None,
        created_at: now,
    };
    let stale_fp_v1 = p_v1.cas_fingerprint();
    let p_v2 = PendingAuthRecord {
        token: TokenRecord {
            access_token: "at-v2".into(),
            refresh_token: "1//cas-v2-newest".into(),
            expires_in: 3600,
            expiry_timestamp: now + 3600,
            ..p_v1.token.clone()
        },
        created_at: now + 10,
        ..p_v1.clone()
    };
    repo.with_write_lock(|tx| tx.save_pending_auth(&p_v2))
        .unwrap();

    let uinfo = UserInfo {
        email: "cas@example.invalid".into(),
        name: Some("CAS User".into()),
        given_name: None,
        family_name: None,
    };
    let stale_err = bind_verified_account_from_pending(
        &repo,
        "pend-cas",
        &stale_fp_v1,
        None,
        &[],
        p_v1.token.clone(),
        &uinfo,
        None,
        &[],
        now + 15,
    )
    .await
    .unwrap_err();
    assert_eq!(stale_err.error_code, "pending_auth_version_conflict");
    assert_eq!(stale_err.exit_code, ExitCode::LockBusyOrConflict);

    // Verify `cas@example.invalid` was NOT created with stale v1, AND `pend-cas` STILL holds `1//cas-v2-newest`!
    assert!(repo
        .read_snapshot()
        .unwrap()
        .accounts
        .iter()
        .all(|a| a.email != "cas@example.invalid"));
    let retained = repo.list_pending_auth_readonly().unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].token.refresh_token, "1//cas-v2-newest");

    // Subsequent `resume_pending_auth_records` cleanly binds `1//cas-v2-newest` and removes `pend-cas`!
    let ok_uinfo = MockTransport::from_queue([Ok(MockTransport::json_response(
        200,
        json!({"email": "cas@example.invalid"}),
    ))]);
    let resumed_v2 = resume_pending_auth_records(&repo, &ok_uinfo, &endpoints, &reg, now)
        .await
        .unwrap();
    assert_eq!(resumed_v2.resumed_accounts.len(), 1);
    assert_eq!(
        resumed_v2.resumed_accounts[0].token.refresh_token,
        "1//cas-v2-newest"
    );
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());

    // Part C: `accounts add` reusing pending interleaved with `resume` AND preserving `R0`/`R1` lineage on bound account!
    let add_mock_1 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-add-1",
                "refresh_token": "1//add-rot-1",
                "expires_in": 60,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            500,
            json!({"error": "userinfo_down"}),
        )),
    ]);
    let _ = bootstrap_and_persist_refresh_token(
        &repo,
        &add_mock_1,
        &endpoints,
        &reg,
        "1//add-initial-0",
        Some("antigravity_enterprise"),
        None,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(repo.list_pending_auth_readonly().unwrap().len(), 1);

    let add_entered = Arc::new(Notify::new());
    let add_release = Arc::new(Notify::new());
    let add_step_2 = StepTransport {
        version: 2,
        token_calls: Arc::new(AtomicUsize::new(0)),
        entered_userinfo: add_entered.clone(),
        release_userinfo: add_release.clone(),
        fail_userinfo: false,
    };
    let mut add_fut_2 = Box::pin(bootstrap_and_persist_refresh_token(
        &repo,
        &add_step_2,
        &endpoints,
        &reg,
        "1//add-initial-0",
        Some("antigravity_enterprise"),
        None,
        now,
    ));
    tokio::select! {
        _ = add_entered.notified() => {}
        _ = &mut add_fut_2 => panic!("add_fut_2 ended before barrier"),
    }
    let resume_during_add = resume_pending_auth_records(&repo, &step_b, &endpoints, &reg, now)
        .await
        .unwrap();
    assert_eq!(resume_during_add.failures.len(), 1);
    add_release.notify_one();
    let (bound_add, _) = add_fut_2.await.unwrap();
    assert_eq!(bound_add.token.refresh_token, "1//r2-rot-2");
    assert!(repo
        .account_has_superseded_rt(&bound_add, "1//add-initial-0")
        .unwrap());
    assert!(repo
        .account_has_superseded_rt(&bound_add, "1//add-rot-1")
        .unwrap());
}

#[tokio::test]
async fn r2_02_superseded_lineage_beyond_32_and_overflow_archive_prevent_overwrite_rollback() {
    use agy_switch_cli::domain::account::MAX_PREVIOUS_RT_DIGESTS;
    use agy_switch_cli::store::repository::TokenLineageArchive;

    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = 2_000_000_000i64;

    let initial = make_acc(
        "acc-lin",
        "lineage@example.invalid",
        "1//lineage-rt-0",
        now + 3600,
        now,
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(initial, true, now)?;
        Ok(())
    })
    .unwrap();

    let write_bundle = |name: &str, rt: &str| -> PathBuf {
        let p = h.tmp.path().join(name);
        fs::write(
            &p,
            serde_json::to_vec_pretty(&json!({
                "schema_version": 2,
                "accounts": [{
                    "email": "lineage@example.invalid",
                    "refresh_token": rt,
                    "oauth_client_key": "antigravity_enterprise",
                    "is_gcp_tos": true
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        p
    };

    let bundle_0 = write_bundle("bundle-0.json", "1//lineage-rt-0");
    let bundle_1 = write_bundle("bundle-1.json", "1//lineage-rt-1");

    // Part A: Exact 33 transitions (previously truncated the 0th digest at 32!)
    for i in 1..=33 {
        repo.with_write_lock(|tx| {
            let mut tok = make_acc(
                "acc-lin",
                "lineage@example.invalid",
                &format!("1//lineage-rt-{i}"),
                now + 3600 + i,
                now,
            )
            .token;
            tok.oauth_client_key = Some("antigravity_enterprise".into());
            tx.merge_refreshed_token("acc-lin", tok, None, now)?;
            Ok(())
        })
        .unwrap();
    }

    let after_33 = repo.read_account_unchecked("acc-lin").unwrap();
    assert_eq!(after_33.previous_refresh_token_digests.len(), 33);
    assert_eq!(after_33.token_version, 34);

    // 1) Default import of oldest backup -> skipped_count = 1
    let def_out = h
        .cli()
        .args([
            "accounts",
            "import",
            "--from-file",
            bundle_0.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(def_out.status.code(), Some(0));
    let def_json: serde_json::Value = serde_json::from_slice(&def_out.stdout).unwrap();
    assert_eq!(def_json["report"]["skipped_count"], 1);
    assert_eq!(def_json["report"]["updated_count"], 0);

    // 2) `--overwrite` import of 1st AND 0th (oldest) backups -> BOTH rejected (`failed_count == 1`)!
    for b in [&bundle_1, &bundle_0] {
        let ow_out = h
            .cli()
            .args([
                "accounts",
                "import",
                "--from-file",
                b.to_str().unwrap(),
                "--overwrite",
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(ow_out.status.code(), Some(0));
        let ow_json: serde_json::Value = serde_json::from_slice(&ow_out.stdout).unwrap();
        assert_eq!(ow_json["report"]["updated_count"], 0, "bundle={b:?}");
        assert_eq!(ow_json["report"]["failed_count"], 1, "bundle={b:?}");
    }
    assert_eq!(
        repo.read_account_unchecked("acc-lin")
            .unwrap()
            .token
            .refresh_token,
        "1//lineage-rt-33"
    );

    // Part B: Spill beyond `MAX_PREVIOUS_RT_DIGESTS` (512 -> 550 transitions) into `state/token_lineage/acc-lin.json`!
    for i in 34..=550 {
        repo.with_write_lock(|tx| {
            let mut tok = make_acc(
                "acc-lin",
                "lineage@example.invalid",
                &format!("1//lineage-rt-{i}"),
                now + 3600 + i,
                now,
            )
            .token;
            tok.oauth_client_key = Some("antigravity_enterprise".into());
            tx.merge_refreshed_token("acc-lin", tok, None, now)?;
            Ok(())
        })
        .unwrap();
    }

    let after_550 = repo.read_account_unchecked("acc-lin").unwrap();
    assert_eq!(
        after_550.previous_refresh_token_digests.len(),
        MAX_PREVIOUS_RT_DIGESTS
    );
    let archive = repo
        .read_token_lineage_readonly("acc-lin")
        .unwrap()
        .expect("overflow lineage archive must exist");
    assert_eq!(archive.digests.len(), 550 - MAX_PREVIOUS_RT_DIGESTS);
    assert!(!archive.truncated);

    // Oldest `bundle-0` is now in `state/token_lineage/acc-lin.json` -> `--overwrite` MUST STILL reject it!
    let ow_550 = import_transfer_bundle_file(&repo, &bundle_0, true, now)
        .await
        .unwrap();
    assert_eq!(ow_550.updated_count, 0);
    assert_eq!(ow_550.failed_count, 1);
    assert_eq!(
        repo.read_account_unchecked("acc-lin")
            .unwrap()
            .token
            .refresh_token,
        "1//lineage-rt-550"
    );

    // Genuinely brand-new external token is still accepted by `--overwrite` when lineage is complete (`!truncated`)
    let bundle_new = write_bundle("bundle-new.json", "1//genuinely-new-external-rt");
    let ow_new = import_transfer_bundle_file(&repo, &bundle_new, true, now)
        .await
        .unwrap();
    assert_eq!(ow_new.updated_count, 1);
    assert_eq!(ow_new.failed_count, 0);

    // If `truncated == true` (capacity ceiling reached), `--overwrite` with an unrecognized RT MUST fail closed!
    let mut trunc_arch = repo
        .read_token_lineage_readonly("acc-lin")
        .unwrap()
        .unwrap();
    trunc_arch.truncated = true;
    fs::write(
        paths.token_lineage_file("acc-lin"),
        serde_json::to_vec_pretty(&trunc_arch).unwrap(),
    )
    .unwrap();
    let bundle_unproven = write_bundle("bundle-unproven.json", "1//unproven-after-truncation");
    let ow_trunc = import_transfer_bundle_file(&repo, &bundle_unproven, true, now)
        .await
        .unwrap();
    assert_eq!(ow_trunc.updated_count, 0);
    assert_eq!(ow_trunc.failed_count, 1);
    assert!(ow_trunc.failures[0]
        .reason
        .contains("historical rotation lineage exceeded retention capacity"));

    // Deleting the account cleans up `state/token_lineage/acc-lin.json` too!
    let del_res = h
        .cli()
        .args(["accounts", "delete", "acc-lin", "--force", "--json"])
        .output()
        .unwrap();
    assert_eq!(del_res.status.code(), Some(0));
    assert!(!paths.token_lineage_file("acc-lin").exists());
    let _ = TokenLineageArchive::default();
}

#[test]
fn r2_03_deep_ancestor_symlinks_rejected_across_all_read_write_import_export_and_token_file_paths()
{
    use agy_switch_cli::store::fs_atomic::{
        ensure_private_dir, read_regular_file_bounded, write_atomic_durable, MAX_STORE_FILE_BYTES,
    };

    let _g = ENV_MUTEX.blocking_lock();
    let h = IsolatedHarness::new();
    let real_root = h.tmp.path().join("real");
    let real_deep_data = real_root.join("deep").join("data");
    fs::create_dir_all(&real_deep_data).unwrap();

    // Seed a valid store in `real/deep/data`
    let real_paths =
        HeadlessPaths::with_explicit(h.home.clone(), real_deep_data.clone(), h.cache_dir.clone());
    let real_repo = StoreRepository::new(real_paths);
    let now = 2_000_000_000i64;
    let seeded = make_acc(
        "acc-real",
        "real@example.invalid",
        "1//real-rt-1",
        now + 3600,
        now,
    );
    real_repo
        .with_write_lock(|tx| {
            tx.upsert_account(seeded, true, now)?;
            Ok(())
        })
        .unwrap();
    let orig_acc_bytes = fs::read(real_deep_data.join("accounts").join("acc-real.json")).unwrap();

    // Create symlink `alias -> real` so `alias/deep/data` has REAL immediate parent `deep` and REAL leaf `data`,
    // with symlink ONLY at deep ancestor `alias`!
    let alias_root = h.tmp.path().join("alias");
    std::os::unix::fs::symlink(&real_root, &alias_root).unwrap();
    let aliased_data_dir = alias_root.join("deep").join("data");

    // 1. Store read & write CLI commands via `--data-dir alias/deep/data` MUST reject the deep symlink ancestor!
    for args in [
        vec!["accounts", "list", "--json"],
        vec!["policy", "show", "--json"],
        vec!["status", "--json"],
        vec!["auth", "pending", "--json"],
        vec!["accounts", "disable", "acc-real", "--json"],
        vec!["policy", "set", "--reserve", "10", "--json"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &h.home)
            .env("XDG_CACHE_HOME", &h.cache_dir)
            .env("XDG_RUNTIME_DIR", &h.runtime_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", h.runtime_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &h.proc_dir)
            .arg("--data-dir")
            .arg(&aliased_data_dir)
            .arg("--no-remote-version")
            .args(&args)
            .output()
            .unwrap();
        assert_ne!(
            out.status.code(),
            Some(0),
            "Deep ancestor symlink must be rejected for {args:?}"
        );
    }
    assert_eq!(
        fs::read(real_deep_data.join("accounts").join("acc-real.json")).unwrap(),
        orig_acc_bytes
    );

    // 2. Import, legacy import, export, and `--from-file` through `alias/deep/...` MUST ALSO reject!
    let real_io_dir = real_root.join("deep").join("io");
    fs::create_dir_all(&real_io_dir).unwrap();
    let real_bundle = real_io_dir.join("bundle.json");
    fs::write(
        &real_bundle,
        b"{\"schema_version\":2,\"accounts\":[{\"email\":\"x@example.invalid\",\"refresh_token\":\"1//x\"}]}",
    )
    .unwrap();
    let real_tok = real_io_dir.join("tok.txt");
    fs::write(&real_tok, b"1//tok-secret\n").unwrap();
    fs::set_permissions(&real_tok, fs::Permissions::from_mode(0o600)).unwrap();

    let alias_io_dir = alias_root.join("deep").join("io");
    let imp_out = h
        .cli()
        .args([
            "accounts",
            "import",
            "--from-file",
            alias_io_dir.join("bundle.json").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_ne!(imp_out.status.code(), Some(0));

    let exp_target = alias_io_dir.join("exported.json");
    let exp_out = h
        .cli()
        .args([
            "accounts",
            "export",
            "--include-secrets",
            "--output",
            exp_target.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_ne!(exp_out.status.code(), Some(0));
    assert!(!real_io_dir.join("exported.json").exists());

    let tf_out = h
        .cli()
        .args([
            "accounts",
            "add",
            "--from-file",
            alias_io_dir.join("tok.txt").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(tf_out.status.code(), Some(2));

    // 3. Direct low-level `fs_atomic` primitives reject deep symlink ancestors too
    assert!(write_atomic_durable(&alias_io_dir.join("atomic.json"), b"{}").is_err());
    assert!(!real_io_dir.join("atomic.json").exists());
    assert!(read_regular_file_bounded(
        &alias_io_dir.join("bundle.json"),
        MAX_STORE_FILE_BYTES,
        "B"
    )
    .is_err());
    assert!(ensure_private_dir(&alias_io_dir.join("new_sub")).is_err());
    assert!(!real_io_dir.join("new_sub").exists());
}

#[test]
fn r2_04_status_surfaces_daemon_state_fifo_and_corrupt_errors_honestly() {
    use std::os::unix::fs::FileTypeExt;
    let _g = ENV_MUTEX.blocking_lock();
    let h = IsolatedHarness::new();
    let paths = h.paths();
    fs::create_dir_all(paths.state_dir()).unwrap();
    fs::set_permissions(&paths.data_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(paths.state_dir(), fs::Permissions::from_mode(0o700)).unwrap();

    // 1. Replace `state/daemon_state.json` with a zero-writer `0600` FIFO:
    //    `status --json` MUST NOT block, MUST exit `1`, and MUST report `daemon_state_ok: false` + `daemon_paused_on_failure: null`!
    let ds_path = paths.daemon_state_file();
    let c_fifo = CString::new(ds_path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);

    let t0 = Instant::now();
    let st_fifo = h.cli().args(["status", "--json"]).output().unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert_eq!(st_fifo.status.code(), Some(1));
    assert!(st_fifo.stdout.is_empty());
    let err_json: serde_json::Value = serde_json::from_slice(&st_fifo.stderr).unwrap();
    assert_eq!(err_json["ok"], false);
    assert_eq!(err_json["details"]["daemon_state_ok"], false);
    assert!(err_json["details"]["daemon_state_error"].is_string());
    assert!(err_json["details"]["daemon_paused_on_failure"].is_null());

    // `policy set` (`repair_or_clear_daemon_state_in_tx`) preserves non-regular FIFO without unlinking it!
    let pol_fifo = h
        .cli()
        .args(["policy", "set", "--reserve", "10", "--json"])
        .output()
        .unwrap();
    assert_eq!(pol_fifo.status.code(), Some(0));
    assert!(fs::symlink_metadata(&ds_path)
        .unwrap()
        .file_type()
        .is_fifo());
    fs::remove_file(&ds_path).unwrap();

    // 2. Corrupt regular `daemon_state.json` -> `status` exits `1`, `policy set` resets it so `status` exits `0`!
    fs::write(&ds_path, b"{corrupt-daemon-state").unwrap();
    fs::set_permissions(&ds_path, fs::Permissions::from_mode(0o600)).unwrap();
    let st_corrupt = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_corrupt.status.code(), Some(1));

    let heal_corrupt = h
        .cli()
        .args(["policy", "set", "--reserve", "12", "--json"])
        .output()
        .unwrap();
    assert_eq!(heal_corrupt.status.code(), Some(0));
    let st_healed = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(
        st_healed.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&st_healed.stderr)
    );
    let fixed_json: serde_json::Value = serde_json::from_slice(&st_healed.stdout).unwrap();
    assert_eq!(fixed_json["daemon_state_ok"], true);
    assert_eq!(fixed_json["daemon_paused_on_failure"], false);
}

#[test]
fn r2_05_explicit_help_never_echoes_misconfigured_env_values() {
    let _g = ENV_MUTEX.blocking_lock();
    let h = IsolatedHarness::new();
    let synthetic_interval = "1//synthetic_secret_fixture'equals=tail\nnext_line_0123456789";
    let synthetic_cooldown = "GOCSPX-CooldownHelpSecret987654";

    for args in [vec!["daemon", "--help"], vec!["daemon", "--help", "--json"]] {
        let out = h
            .cli()
            .env("AGY_SWITCH_CLI_INTERVAL", synthetic_interval)
            .env("AGY_SWITCH_CLI_COOLDOWN", synthetic_cooldown)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let lower = combined.to_ascii_lowercase();
        assert!(combined.contains("AGY_SWITCH_CLI_INTERVAL"));
        assert!(combined.contains("AGY_SWITCH_CLI_COOLDOWN"));
        assert!(
            !lower.contains("synthetic_secret_fixture"),
            "Help echoed AGY_SWITCH_CLI_INTERVAL value for {args:?}: {combined}"
        );
        assert!(
            !lower.contains("next_line_0123456789"),
            "Help echoed multiline env tail for {args:?}: {combined}"
        );
        assert!(
            !lower.contains("cooldownhelpsecret987654"),
            "Help echoed AGY_SWITCH_CLI_COOLDOWN value for {args:?}: {combined}"
        );
    }
}

#[tokio::test]
async fn r2_06_multi_step_pending_lineage_reauth_supersede_sigkill_and_corrupt_lineage_guards() {
    use agy_switch_cli::domain::account::MAX_IN_MEMORY_RT_DIGESTS;
    use agy_switch_cli::oauth::flow::PreparedAuthSession;
    use agy_switch_cli::oauth::refresh::{
        purge_all_pending_auth_records, resume_pending_auth_records,
    };
    use agy_switch_cli::store::locks::is_pending_auth_lock_busy;
    use std::io::BufRead;

    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = 2_000_000_000i64;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let endpoints = OAuthEndpoints {
        token_url: "http://127.0.0.1/token".into(),
        userinfo_url: "http://127.0.0.1/userinfo".into(),
        base_backoff: Duration::from_millis(1),
    };

    // 1. Multi-step pending rotation `R0 -> R1 -> R2 -> R3` across failed `userinfo` attempts
    //    MUST persist intermediate `R1` and `R2` digests in `state/pending_lineage/` and block `--overwrite` rollback!
    let t1 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-m1",
                "refresh_token": "1//multi-r1",
                "expires_in": 60,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            500,
            json!({"error": "userinfo_down"}),
        )),
    ]);
    let _ = bootstrap_and_persist_refresh_token(
        &repo,
        &t1,
        &endpoints,
        &reg,
        "1//multi-r0",
        Some("antigravity_enterprise"),
        None,
        now,
    )
    .await
    .unwrap_err();

    let t2 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-m2",
                "refresh_token": "1//multi-r2",
                "expires_in": 60,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            500,
            json!({"error": "userinfo_down"}),
        )),
    ]);
    let rep1 = resume_pending_auth_records(&repo, &t2, &endpoints, &reg, now + 10)
        .await
        .unwrap();
    assert_eq!(rep1.failures.len(), 1);

    // Intermediate rotated `1//multi-r1` MUST be rejected if passed to `accounts add` while pending holds `1//multi-r2`!
    let stale_mid = bootstrap_and_persist_refresh_token(
        &repo,
        &MockTransport::default(),
        &endpoints,
        &reg,
        "1//multi-r1",
        Some("antigravity_enterprise"),
        None,
        now + 15,
    )
    .await
    .unwrap_err();
    assert_eq!(stale_mid.error_code, "stale_rotated_refresh_token");

    // Passing current pending token `1//multi-r2` to `accounts add` coordinates under the same pending record and leaves 0 pendings!
    let t3 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-m3",
                "refresh_token": "1//multi-r3",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "multi@example.invalid"}),
        )),
    ]);
    let (bound_multi, _) = bootstrap_and_persist_refresh_token(
        &repo,
        &t3,
        &endpoints,
        &reg,
        "1//multi-r2",
        Some("antigravity_enterprise"),
        None,
        now + 20,
    )
    .await
    .unwrap();
    assert_eq!(bound_multi.token.refresh_token, "1//multi-r3");
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());
    for sup in ["1//multi-r0", "1//multi-r1", "1//multi-r2"] {
        let b_path = h.tmp.path().join("sup.json");
        fs::write(
            &b_path,
            serde_json::to_vec(&json!({
                "schema_version": 2,
                "accounts": [{
                    "email": "multi@example.invalid",
                    "refresh_token": sup,
                    "oauth_client_key": "antigravity_enterprise",
                    "is_gcp_tos": true
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let ow = import_transfer_bundle_file(&repo, &b_path, true, now + 30)
            .await
            .unwrap();
        assert_eq!(ow.updated_count, 0, "sup={sup}");
        assert_eq!(ow.failed_count, 1, "sup={sup}");
    }

    // 2. Abandoned `Reauthorize` #1 MUST NOT overwrite newer completed `Reauthorize` #2 on subsequent `resume`!
    let client = reg
        .select_for_login(Some("antigravity_enterprise"))
        .unwrap();
    let mk_sess = |port: u16| PreparedAuthSession {
        client: client.clone(),
        redirect_uri: format!("http://127.0.0.1:{port}/oauth-callback"),
        port,
        state: "st".into(),
        code_verifier: "ver".into(),
        code_challenge: "chal".into(),
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
    };
    let tr_re1 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-re1",
                "refresh_token": "1//reauth-abandoned-1",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let _ = complete_reauthorize_exchange_locked(
        &repo,
        &tr_re1,
        &endpoints,
        &reg,
        &bound_multi,
        &mk_sess(14001),
        "c1",
        now + 40,
    )
    .await
    .unwrap_err();

    let tr_re2 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-re2",
                "refresh_token": "1//reauth-newest-2",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "multi@example.invalid"}),
        )),
    ]);
    let re2_acc = complete_reauthorize_exchange_locked(
        &repo,
        &tr_re2,
        &endpoints,
        &reg,
        &bound_multi,
        &mk_sess(14002),
        "c2",
        now + 50,
    )
    .await
    .unwrap();
    assert_eq!(re2_acc.token.refresh_token, "1//reauth-newest-2");
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());
    let _ =
        resume_pending_auth_records(&repo, &MockTransport::default(), &endpoints, &reg, now + 60)
            .await
            .unwrap();
    let post_re = repo.read_account_unchecked(&bound_multi.id).unwrap();
    assert_eq!(post_re.token.refresh_token, "1//reauth-newest-2");
    assert!(repo
        .account_has_superseded_rt(&post_re, "1//reauth-abandoned-1")
        .unwrap());

    // 3. Real cross-process `flock` held on `PendingAuthLock` + `SIGKILL -9` recovery + FIFO lock file rejection!
    let t_pend = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-pk",
                "refresh_token": "1//pk-surviving",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let _ = bootstrap_and_persist_refresh_token(
        &repo,
        &t_pend,
        &endpoints,
        &reg,
        "1//pk-init",
        Some("antigravity_enterprise"),
        None,
        now + 70,
    )
    .await
    .unwrap_err();
    let pk_id = repo.list_pending_auth_readonly().unwrap()[0].id.clone();
    let pk_lock_path = paths.pending_auth_lock_file(&pk_id);

    // Spawn a real child process holding `flock(LOCK_EX)` on `pending-<id>.lock`, verify `resume` sees busy, then `SIGKILL -9` child!
    let mut holder_guard = KillChildOnDrop::new(
        Command::new("python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                "import fcntl, os, sys, time\nfd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\nfcntl.flock(fd, fcntl.LOCK_EX)\nsys.stdout.write('LOCKED\\n')\nsys.stdout.flush()\ntime.sleep(30)\n",
                pk_lock_path.to_str().unwrap(),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut ready_line = String::new();
    std::io::BufReader::new(holder_guard.as_mut().stdout.take().unwrap())
        .read_line(&mut ready_line)
        .unwrap();
    assert_eq!(ready_line.trim(), "LOCKED");
    assert!(is_pending_auth_lock_busy(&paths, &pk_id).unwrap());

    // Kill holder with real SIGKILL (-9) -> kernel closes fd & releases `flock` -> `resume` immediately recovers `1//pk-surviving`!
    let mut holder = holder_guard.take();
    unsafe {
        libc::kill(holder.id() as i32, libc::SIGKILL);
    }
    let _ = holder.wait();
    assert!(!is_pending_auth_lock_busy(&paths, &pk_id).unwrap());
    let ok_pk_uinfo = MockTransport::from_queue([Ok(MockTransport::json_response(
        200,
        json!({"email": "pk@example.invalid"}),
    ))]);
    let pk_resumed = resume_pending_auth_records(&repo, &ok_pk_uinfo, &endpoints, &reg, now + 80)
        .await
        .unwrap();
    assert_eq!(pk_resumed.resumed_accounts.len(), 1);
    assert_eq!(
        pk_resumed.resumed_accounts[0].token.refresh_token,
        "1//pk-surviving"
    );

    // Non-regular FIFO at `pending-<id>.lock` is rejected by `purge_all_pending_auth_records`!
    let _ = bootstrap_and_persist_refresh_token(
        &repo,
        &MockTransport::from_queue([
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": "at-f",
                    "refresh_token": "1//fifo-lock-rt",
                    "expires_in": 3600,
                    "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                }),
            )),
            Ok(MockTransport::json_response(500, json!({"error": "down"}))),
        ]),
        &endpoints,
        &reg,
        "1//fifo-lock-init",
        Some("antigravity_enterprise"),
        None,
        now + 85,
    )
    .await
    .unwrap_err();
    let fifo_pid = repo.list_pending_auth_readonly().unwrap()[0].id.clone();
    let fifo_lock_path = paths.pending_auth_lock_file(&fifo_pid);
    let _ = fs::remove_file(&fifo_lock_path);
    let c_lock_fifo = CString::new(fifo_lock_path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_lock_fifo.as_ptr(), 0o600) }, 0);
    assert!(purge_all_pending_auth_records(&repo).is_err());
    fs::remove_file(&fifo_lock_path).unwrap();
    assert_eq!(purge_all_pending_auth_records(&repo).unwrap(), 1);

    // 4. In-memory transitions exceeding `MAX_IN_MEMORY_RT_DIGESTS` set `archive.truncated = true` & fail closed!
    let mut cap_acc = make_acc(
        "acc-cap",
        "cap@example.invalid",
        "1//cap-pre",
        now + 3600,
        now,
    );
    cap_acc.previous_refresh_token_digests = (0..(MAX_IN_MEMORY_RT_DIGESTS - 1))
        .map(|i| format!("{i:064x}"))
        .collect();
    for suffix in ["1//cap-at-ceiling", "1//cap-past-ceiling"] {
        cap_acc.record_token_transition(
            make_acc("acc-cap", "cap@example.invalid", suffix, now + 3600, now).token,
        );
    }
    repo.with_write_lock(|tx| {
        tx.upsert_account(cap_acc, false, now)?;
        Ok(())
    })
    .unwrap();
    assert!(
        repo.read_token_lineage_readonly("acc-cap")
            .unwrap()
            .unwrap()
            .truncated
    );

    // 5. Corrupt / FIFO / symlink `state/token_lineage/<id>.json` fails closed without blocking on `import`, `add`, and `status`!
    let lin_file = paths.token_lineage_file("acc-cap");
    fs::remove_file(&lin_file).unwrap();
    let c_lin_fifo = CString::new(lin_file.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_lin_fifo.as_ptr(), 0o600) }, 0);

    let cap_bundle = h.tmp.path().join("cap-bundle.json");
    fs::write(
        &cap_bundle,
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "accounts": [{
                "email": "cap@example.invalid",
                "refresh_token": "1//ext-cand",
                "oauth_client_key": "antigravity_enterprise",
                "is_gcp_tos": true
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let t0 = Instant::now();
    let imp_fifo = import_transfer_bundle_file(&repo, &cap_bundle, true, now + 90)
        .await
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert_eq!(imp_fifo.updated_count, 0);
    assert_eq!(imp_fifo.failed_count, 1);

    let st_lin_fifo = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_lin_fifo.status.code(), Some(1));
    fs::remove_file(&lin_file).unwrap();

    // 6. `--data-dir alias_sym/../store` and symlinked `config.json` in `status` & write commands are rejected without chmodding external targets!
    let ext_dir = h.tmp.path().join("ext_victim");
    fs::create_dir_all(ext_dir.join("nested")).unwrap();
    fs::set_permissions(&ext_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let ext_file = ext_dir.join("ext.json");
    fs::write(&ext_file, b"{}").unwrap();
    fs::set_permissions(&ext_file, fs::Permissions::from_mode(0o644)).unwrap();

    let sym_alias = h.tmp.path().join("alias_sym");
    std::os::unix::fs::symlink(ext_dir.join("nested"), &sym_alias).unwrap();
    let traversed_store = sym_alias.join("..").join("store");
    let resolved_traversed = HeadlessPaths::resolve(Some(&traversed_store)).unwrap();
    assert!(StoreRepository::new(resolved_traversed)
        .read_snapshot()
        .is_err());

    std::os::unix::fs::symlink(&ext_file, paths.config_file()).unwrap();
    let st_sym_cfg = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_sym_cfg.status.code(), Some(1));
    assert_eq!(
        fs::metadata(&ext_file).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[tokio::test]
async fn r3_01_busy_old_pending_across_reauthorize_login_add_and_overwrite_never_rolls_back_newer_generation(
) {
    use agy_switch_cli::oauth::flow::PreparedAuthSession;
    use agy_switch_cli::oauth::refresh::{
        complete_login_exchange_locked, ensure_account_token_fresh_locked,
        resume_pending_auth_records,
    };
    use agy_switch_cli::store::locks::is_pending_auth_lock_busy;
    use std::collections::HashMap;
    use std::os::unix::fs::FileTypeExt;

    let _g = ENV_MUTEX.lock().await;
    let h = IsolatedHarness::new();
    let paths = h.paths();
    let repo = StoreRepository::new(paths.clone());
    let now = 2_100_000_000i64;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let client = reg
        .select_for_login(Some("antigravity_enterprise"))
        .unwrap();
    let endpoints = OAuthEndpoints {
        token_url: "http://127.0.0.1/token".into(),
        userinfo_url: "http://127.0.0.1/userinfo".into(),
        base_backoff: Duration::from_millis(1),
    };
    let mk_sess = |port: u16| PreparedAuthSession {
        client: client.clone(),
        redirect_uri: format!("http://127.0.0.1:{port}/oauth-callback"),
        port,
        state: "st".into(),
        code_verifier: "ver".into(),
        code_challenge: "chal".into(),
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
    };

    struct GatedAuthTransport {
        issued_at: String,
        issued_rt: String,
        expires_in: i64,
        email: String,
        token_posts: Arc<AtomicUsize>,
        userinfo_gets: Arc<AtomicUsize>,
        entered_userinfo: Arc<Notify>,
        release_userinfo: Arc<Notify>,
    }
    impl HttpTransport for GatedAuthTransport {
        fn execute<'a>(
            &'a self,
            req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                if req.url.ends_with("/token") {
                    self.token_posts.fetch_add(1, Ordering::SeqCst);
                    let body = serde_json::to_vec(&json!({
                        "access_token": self.issued_at,
                        "refresh_token": self.issued_rt,
                        "expires_in": self.expires_in,
                        "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                    }))
                    .unwrap();
                    return Ok(HttpResponse {
                        status: 200,
                        headers: HashMap::new(),
                        body,
                    });
                }
                self.userinfo_gets.fetch_add(1, Ordering::SeqCst);
                self.entered_userinfo.notify_one();
                self.release_userinfo.notified().await;
                Ok(HttpResponse {
                    status: 200,
                    headers: HashMap::new(),
                    body: serde_json::to_vec(&json!({ "email": self.email })).unwrap(),
                })
            })
        }
    }

    struct CountingResumeTransport {
        issued_rt: String,
        email: String,
        token_posts: Arc<AtomicUsize>,
        userinfo_gets: Arc<AtomicUsize>,
    }
    impl HttpTransport for CountingResumeTransport {
        fn execute<'a>(
            &'a self,
            req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                if req.url.ends_with("/token") {
                    self.token_posts.fetch_add(1, Ordering::SeqCst);
                    let body = serde_json::to_vec(&json!({
                        "access_token": "at-old-resumed-rot",
                        "refresh_token": self.issued_rt,
                        "expires_in": 3600,
                        "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                    }))
                    .unwrap();
                    return Ok(HttpResponse {
                        status: 200,
                        headers: HashMap::new(),
                        body,
                    });
                }
                self.userinfo_gets.fetch_add(1, Ordering::SeqCst);
                Ok(HttpResponse {
                    status: 200,
                    headers: HashMap::new(),
                    body: serde_json::to_vec(&json!({ "email": self.email })).unwrap(),
                })
            })
        }
    }

    // Seed initial account `acc-r3`
    let seeded = make_acc(
        "acc-r3",
        "r3@example.invalid",
        "1//r3-initial-0",
        now + 3600,
        now,
    );
    let (acc_r3, _) = repo
        .with_write_lock(|tx| tx.upsert_account(seeded, true, now))
        .unwrap();

    // =========================================================================
    // 1. Real-source busy-lock race Variant A (`rotate = false`, non-expiring old pending)
    // =========================================================================
    let old_fresh_tr = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-old-fresh",
                "refresh_token": "1//r3-old-fresh",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            500,
            json!({"error": "userinfo_transient"}),
        )),
    ]);
    let _ = complete_reauthorize_exchange_locked(
        &repo,
        &old_fresh_tr,
        &endpoints,
        &reg,
        &acc_r3,
        &mk_sess(15001),
        "code-old-fresh",
        now + 10,
    )
    .await
    .unwrap_err();
    let old_fresh_pid = repo.list_pending_auth_readonly().unwrap()[0].id.clone();

    let entered_a = Arc::new(Notify::new());
    let release_a = Arc::new(Notify::new());
    let new_tr_a = GatedAuthTransport {
        issued_at: "at-new-fresh".into(),
        issued_rt: "1//r3-new-fresh-winner".into(),
        expires_in: 3600,
        email: "r3@example.invalid".into(),
        token_posts: Arc::new(AtomicUsize::new(0)),
        userinfo_gets: Arc::new(AtomicUsize::new(0)),
        entered_userinfo: entered_a.clone(),
        release_userinfo: release_a.clone(),
    };
    let sess_a = mk_sess(15002);
    let mut new_fut_a = Box::pin(complete_reauthorize_exchange_locked(
        &repo,
        &new_tr_a,
        &endpoints,
        &reg,
        &acc_r3,
        &sess_a,
        "code-new-fresh",
        now + 20,
    ));
    tokio::select! {
        _ = entered_a.notified() => {}
        _ = &mut new_fut_a => panic!("new_fut_a finished before userinfo barrier"),
    }
    assert_eq!(repo.list_pending_auth_readonly().unwrap().len(), 2);

    let old_posts_a = Arc::new(AtomicUsize::new(0));
    let old_gets_a = Arc::new(AtomicUsize::new(0));
    let old_resume_tr_a = CountingResumeTransport {
        issued_rt: "1//unused-a".into(),
        email: "r3@example.invalid".into(),
        token_posts: old_posts_a.clone(),
        userinfo_gets: old_gets_a.clone(),
    };
    let mut resume_fut_a = Box::pin(resume_pending_auth_records(
        &repo,
        &old_resume_tr_a,
        &endpoints,
        &reg,
        now + 25,
    ));
    // Poll `resume_fut_a` until it holds `PendingAuthLock(old_fresh_pid)` and waits on `L2("acc-r3")`!
    for _ in 0..20 {
        assert!(
            tokio::time::timeout(Duration::from_millis(15), &mut resume_fut_a)
                .await
                .is_err()
        );
        if is_pending_auth_lock_busy(&paths, &old_fresh_pid).unwrap() {
            break;
        }
    }
    assert!(
        is_pending_auth_lock_busy(&paths, &old_fresh_pid).unwrap(),
        "old_fresh_pid must hold PendingAuthLock while waiting on L2"
    );

    release_a.notify_one();
    let new_saved_a = new_fut_a.await.unwrap();
    assert_eq!(new_saved_a.token.refresh_token, "1//r3-new-fresh-winner");

    let rep_a = resume_fut_a.await.unwrap();
    assert_eq!(old_posts_a.load(Ordering::SeqCst), 0);
    assert_eq!(old_gets_a.load(Ordering::SeqCst), 0);
    assert!(rep_a.resumed_accounts.is_empty());
    assert!(rep_a.failures.is_empty());
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());

    let post_a = repo.read_account_unchecked("acc-r3").unwrap();
    assert_eq!(post_a.token.refresh_token, "1//r3-new-fresh-winner");
    assert!(repo
        .account_has_superseded_rt(&post_a, "1//r3-old-fresh")
        .unwrap());
    assert!(!repo
        .account_has_superseded_rt(&post_a, "1//r3-new-fresh-winner")
        .unwrap());

    // =========================================================================
    // 2. Real-source busy-lock race Variant B (`rotate = true`, expiring old pending + `pending_lineage`)
    // =========================================================================
    let old_exp_tr_0 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-old-exp-0",
                "refresh_token": "1//r3-old-exp-0",
                "expires_in": 60,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let _ = complete_reauthorize_exchange_locked(
        &repo,
        &old_exp_tr_0,
        &endpoints,
        &reg,
        &post_a,
        &mk_sess(15003),
        "code-old-exp-0",
        now + 30,
    )
    .await
    .unwrap_err();
    let old_exp_pid = repo.list_pending_auth_readonly().unwrap()[0].id.clone();
    let old_exp_seq_before_refresh = repo.list_pending_auth_readonly().unwrap()[0].auth_seq;

    // Intermediate pending refresh (`R0 -> R1`, `userinfo` 500) MUST NOT rewrite `auth_seq` and MUST record `R0` in `pending_lineage`!
    let old_exp_tr_1 = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-old-exp-1",
                "refresh_token": "1//r3-old-exp-1",
                "expires_in": 60,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let failed_mid = resume_pending_auth_records(&repo, &old_exp_tr_1, &endpoints, &reg, now + 100)
        .await
        .unwrap();
    assert_eq!(failed_mid.failures.len(), 1);
    let after_mid_pend = &repo.list_pending_auth_readonly().unwrap()[0];
    assert_eq!(after_mid_pend.auth_seq, old_exp_seq_before_refresh);
    assert_eq!(after_mid_pend.token.refresh_token, "1//r3-old-exp-1");
    assert!(paths.pending_lineage_file(&old_exp_pid).exists());

    // Now race busy `old_exp_pid` (expired again at `now + 200`!) against new reauth `1//r3-new-rot-winner`
    let entered_b = Arc::new(Notify::new());
    let release_b = Arc::new(Notify::new());
    let new_tr_b = GatedAuthTransport {
        issued_at: "at-new-rot".into(),
        issued_rt: "1//r3-new-rot-winner".into(),
        expires_in: 3600,
        email: "r3@example.invalid".into(),
        token_posts: Arc::new(AtomicUsize::new(0)),
        userinfo_gets: Arc::new(AtomicUsize::new(0)),
        entered_userinfo: entered_b.clone(),
        release_userinfo: release_b.clone(),
    };
    let sess_b = mk_sess(15004);
    let mut new_fut_b = Box::pin(complete_reauthorize_exchange_locked(
        &repo,
        &new_tr_b,
        &endpoints,
        &reg,
        &post_a,
        &sess_b,
        "code-new-rot",
        now + 190,
    ));
    tokio::select! {
        _ = entered_b.notified() => {}
        _ = &mut new_fut_b => panic!("new_fut_b finished before barrier"),
    }

    let old_posts_b = Arc::new(AtomicUsize::new(0));
    let old_gets_b = Arc::new(AtomicUsize::new(0));
    let old_resume_tr_b = CountingResumeTransport {
        issued_rt: "1//r3-old-exp-2-should-never-issue".into(),
        email: "r3@example.invalid".into(),
        token_posts: old_posts_b.clone(),
        userinfo_gets: old_gets_b.clone(),
    };
    let mut resume_fut_b = Box::pin(resume_pending_auth_records(
        &repo,
        &old_resume_tr_b,
        &endpoints,
        &reg,
        now + 200,
    ));
    for _ in 0..20 {
        assert!(
            tokio::time::timeout(Duration::from_millis(15), &mut resume_fut_b)
                .await
                .is_err()
        );
        if is_pending_auth_lock_busy(&paths, &old_exp_pid).unwrap() {
            break;
        }
    }
    assert!(is_pending_auth_lock_busy(&paths, &old_exp_pid).unwrap());

    release_b.notify_one();
    let new_saved_b = new_fut_b.await.unwrap();
    assert_eq!(new_saved_b.token.refresh_token, "1//r3-new-rot-winner");

    let rep_b = resume_fut_b.await.unwrap();
    assert_eq!(old_posts_b.load(Ordering::SeqCst), 0);
    assert_eq!(old_gets_b.load(Ordering::SeqCst), 0);
    assert!(rep_b.resumed_accounts.is_empty());
    assert!(rep_b.failures.is_empty());
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());
    assert!(!paths.pending_lineage_file(&old_exp_pid).exists());

    let post_b = repo.read_account_unchecked("acc-r3").unwrap();
    assert_eq!(post_b.token.refresh_token, "1//r3-new-rot-winner");
    assert!(repo
        .account_has_superseded_rt(&post_b, "1//r3-old-exp-0")
        .unwrap());
    assert!(repo
        .account_has_superseded_rt(&post_b, "1//r3-old-exp-1")
        .unwrap());

    // =========================================================================
    // 3. Legacy v1 JSON `PendingAuthRecord` without `"auth_seq"` (`auth_seq == 0`):
    //    (a) Sequential upgrade onto legacy account without `"auth_generation"` succeeds (`0 -> 1`);
    //    (b) Busy-lock race against new reauth (`reauth-reproducer-v1`) blocks rollback!
    // =========================================================================
    let leg_acc = make_acc(
        "acc-legacy-v1",
        "legacyv1@example.invalid",
        "1//leg-init-0",
        now + 3600,
        now,
    );
    // Write legacy account JSON omitting `auth_generation` + update index
    repo.with_write_lock(|tx| {
        let mut idx = tx.load_index_or_init(now)?;
        idx.account_order.push("acc-legacy-v1".into());
        tx.save_index(&mut idx, now)?;
        Ok(())
    })
    .unwrap();
    fs::write(
        paths.account_file("acc-legacy-v1"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "acc-legacy-v1",
            "email": "legacyv1@example.invalid",
            "token": leg_acc.token,
            "token_version": 1,
            "created_at": now,
            "last_used": now
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        paths.account_file("acc-legacy-v1"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let write_raw_v1_pending = |pid: &str, rt: &str| {
        let p = paths.pending_auth_file(pid);
        fs::create_dir_all(paths.pending_auth_dir()).unwrap();
        fs::set_permissions(paths.pending_auth_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            &p,
            serde_json::to_vec_pretty(&json!({
                "schema_version": 1,
                "id": pid,
                "flow": { "kind": "reauthorize", "target_account_id": "acc-legacy-v1" },
                "token": {
                    "access_token": "at-v1-raw",
                    "refresh_token": rt,
                    "expires_in": 3600,
                    "expiry_timestamp": now + 7200,
                    "token_type": "Bearer",
                    "oauth_client_key": "antigravity_enterprise",
                    "granted_scopes": ["https://www.googleapis.com/auth/cloud-platform", "openid"],
                    "is_gcp_tos": true
                },
                "created_at": now + 210
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    };

    // 3(a): Legacy pending (`auth_seq == 0`) resumes cleanly onto legacy account (`auth_generation == 0` -> `1`)
    write_raw_v1_pending("pend-leg-seq", "1//leg-upgraded-1");
    let leg_seq_rep = resume_pending_auth_records(
        &repo,
        &MockTransport::from_queue([Ok(MockTransport::json_response(
            200,
            json!({"email": "legacyv1@example.invalid"}),
        ))]),
        &endpoints,
        &reg,
        now + 215,
    )
    .await
    .unwrap();
    assert_eq!(leg_seq_rep.resumed_accounts.len(), 1);
    let leg_after_seq = repo.read_account_unchecked("acc-legacy-v1").unwrap();
    assert_eq!(leg_after_seq.token.refresh_token, "1//leg-upgraded-1");
    assert_eq!(leg_after_seq.auth_generation, 1);

    // 3(b): Exact `reauth-reproducer-v1`: raw v1 pending (`auth_seq == 0`) busy-waiting on L2 during new reauth
    write_raw_v1_pending("pend-leg-race", "1//leg-stale-v1");
    let entered_c = Arc::new(Notify::new());
    let release_c = Arc::new(Notify::new());
    let new_tr_c = GatedAuthTransport {
        issued_at: "at-leg-new".into(),
        issued_rt: "1//leg-new-winner".into(),
        expires_in: 3600,
        email: "legacyv1@example.invalid".into(),
        token_posts: Arc::new(AtomicUsize::new(0)),
        userinfo_gets: Arc::new(AtomicUsize::new(0)),
        entered_userinfo: entered_c.clone(),
        release_userinfo: release_c.clone(),
    };
    let sess_c = mk_sess(15005);
    let mut new_fut_c = Box::pin(complete_reauthorize_exchange_locked(
        &repo,
        &new_tr_c,
        &endpoints,
        &reg,
        &leg_after_seq,
        &sess_c,
        "code-leg-new",
        now + 220,
    ));
    tokio::select! {
        _ = entered_c.notified() => {}
        _ = &mut new_fut_c => panic!("new_fut_c finished early"),
    }
    let old_resume_tr_c = CountingResumeTransport {
        issued_rt: "1//unused-c".into(),
        email: "legacyv1@example.invalid".into(),
        token_posts: Arc::new(AtomicUsize::new(0)),
        userinfo_gets: Arc::new(AtomicUsize::new(0)),
    };
    let mut resume_fut_c = Box::pin(resume_pending_auth_records(
        &repo,
        &old_resume_tr_c,
        &endpoints,
        &reg,
        now + 225,
    ));
    for _ in 0..20 {
        assert!(
            tokio::time::timeout(Duration::from_millis(15), &mut resume_fut_c)
                .await
                .is_err()
        );
        if is_pending_auth_lock_busy(&paths, "pend-leg-race").unwrap() {
            break;
        }
    }
    release_c.notify_one();
    let _ = new_fut_c.await.unwrap();
    let rep_c = resume_fut_c.await.unwrap();
    assert!(rep_c.resumed_accounts.is_empty());
    assert!(rep_c.failures.is_empty());
    assert_eq!(
        repo.read_account_unchecked("acc-legacy-v1")
            .unwrap()
            .token
            .refresh_token,
        "1//leg-new-winner"
    );

    // =========================================================================
    // 4. Cross-flow busy-lock interleavings (`Login` hitting existing account, `import --overwrite`, & routine refresh decoupling)
    // =========================================================================
    // 4(a): Old `Login` pending finishes `userinfo` and blocks on `L2("acc-r3")` while new `reauthorize` commits!
    let login_fail_tr = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-old-login",
                "refresh_token": "1//r3-old-login",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let _ = complete_login_exchange_locked(
        &repo,
        &login_fail_tr,
        &endpoints,
        &reg,
        &mk_sess(15006),
        "code-old-login",
        None,
        now + 240,
    )
    .await
    .unwrap_err();
    let old_login_pid = repo.list_pending_auth_readonly().unwrap()[0].id.clone();

    let entered_d = Arc::new(Notify::new());
    let release_d = Arc::new(Notify::new());
    let new_tr_d = GatedAuthTransport {
        issued_at: "at-new-vs-login".into(),
        issued_rt: "1//r3-winner-over-login".into(),
        expires_in: 3600,
        email: "r3@example.invalid".into(),
        token_posts: Arc::new(AtomicUsize::new(0)),
        userinfo_gets: Arc::new(AtomicUsize::new(0)),
        entered_userinfo: entered_d.clone(),
        release_userinfo: release_d.clone(),
    };
    let sess_d = mk_sess(15007);
    let mut new_fut_d = Box::pin(complete_reauthorize_exchange_locked(
        &repo,
        &new_tr_d,
        &endpoints,
        &reg,
        &post_b,
        &sess_d,
        "code-new-vs-login",
        now + 250,
    ));
    tokio::select! {
        _ = entered_d.notified() => {}
        _ = &mut new_fut_d => panic!("new_fut_d finished early"),
    }

    let old_login_gets = Arc::new(AtomicUsize::new(0));
    let old_login_resume_tr = CountingResumeTransport {
        issued_rt: "1//unused-d".into(),
        email: "r3@example.invalid".into(),
        token_posts: Arc::new(AtomicUsize::new(0)),
        userinfo_gets: old_login_gets.clone(),
    };
    let mut resume_fut_d = Box::pin(resume_pending_auth_records(
        &repo,
        &old_login_resume_tr,
        &endpoints,
        &reg,
        now + 255,
    ));
    for _ in 0..20 {
        assert!(
            tokio::time::timeout(Duration::from_millis(15), &mut resume_fut_d)
                .await
                .is_err()
        );
        if old_login_gets.load(Ordering::SeqCst) == 1
            && is_pending_auth_lock_busy(&paths, &old_login_pid).unwrap()
        {
            break;
        }
    }
    assert_eq!(old_login_gets.load(Ordering::SeqCst), 1);

    release_d.notify_one();
    let _ = new_fut_d.await.unwrap();
    let rep_d = resume_fut_d.await.unwrap();
    assert!(rep_d.resumed_accounts.is_empty());
    assert!(rep_d.failures.is_empty());
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());
    let post_d = repo.read_account_unchecked("acc-r3").unwrap();
    assert_eq!(post_d.token.refresh_token, "1//r3-winner-over-login");
    assert!(repo
        .account_has_superseded_rt(&post_d, "1//r3-old-login")
        .unwrap());

    // 4(b): Old `AddToken` pending superseded by `accounts import --overwrite` with a new external `refresh_token`!
    let add_fail_tr = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-old-add",
                "refresh_token": "1//r3-old-add-rotated",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let _ = bootstrap_and_persist_refresh_token(
        &repo,
        &add_fail_tr,
        &endpoints,
        &reg,
        "1//r3-old-add-input",
        Some("antigravity_enterprise"),
        None,
        now + 260,
    )
    .await
    .unwrap_err();
    assert_eq!(repo.list_pending_auth_readonly().unwrap().len(), 1);

    let ext_bundle = h.tmp.path().join("r3-overwrite-ext.json");
    fs::write(
        &ext_bundle,
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "accounts": [{
                "email": "r3@example.invalid",
                "refresh_token": "1//r3-imported-external-winner",
                "oauth_client_key": "antigravity_enterprise",
                "is_gcp_tos": true
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let imp_rep = import_transfer_bundle_file(&repo, &ext_bundle, true, now + 270)
        .await
        .unwrap();
    assert_eq!(imp_rep.updated_count, 1);

    let rep_after_imp = resume_pending_auth_records(
        &repo,
        &MockTransport::from_queue([Ok(MockTransport::json_response(
            200,
            json!({"email": "r3@example.invalid"}),
        ))]),
        &endpoints,
        &reg,
        now + 275,
    )
    .await
    .unwrap();
    assert!(rep_after_imp.resumed_accounts.is_empty());
    assert!(rep_after_imp.failures.is_empty());
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());
    let post_imp = repo.read_account_unchecked("acc-r3").unwrap();
    assert_eq!(
        post_imp.token.refresh_token,
        "1//r3-imported-external-winner"
    );
    assert!(repo
        .account_has_superseded_rt(&post_imp, "1//r3-old-add-input")
        .unwrap());
    assert!(repo
        .account_has_superseded_rt(&post_imp, "1//r3-old-add-rotated")
        .unwrap());

    // 4(c): Routine `ensure_account_token_fresh_locked` (`merge_refreshed_token`) advances `token_version`
    //       WITHOUT advancing `auth_generation`, so a valid interrupted `reauthorize` STILL resumes cleanly!
    let reauth_valid_tr = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-reauth-after-routine",
                "refresh_token": "1//r3-reauth-survives-routine",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let _ = complete_reauthorize_exchange_locked(
        &repo,
        &reauth_valid_tr,
        &endpoints,
        &reg,
        &post_imp,
        &mk_sess(15008),
        "code-survives-routine",
        now + 280,
    )
    .await
    .unwrap_err();
    let gen_before_routine = repo
        .read_account_unchecked("acc-r3")
        .unwrap()
        .auth_generation;
    let ver_before_routine = repo.read_account_unchecked("acc-r3").unwrap().token_version;

    for idx in 1..=3 {
        let routine_tr = MockTransport::from_queue([
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": format!("at-routine-{idx}"),
                    "refresh_token": format!("1//r3-routine-rot-{idx}"),
                    "expires_in": 3600,
                    "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                }),
            )),
            Ok(MockTransport::json_response(
                200,
                json!({"email": "r3@example.invalid", "name": "R3 User"}),
            )),
        ]);
        let _ = ensure_account_token_fresh_locked(
            &repo,
            &routine_tr,
            &endpoints,
            &reg,
            "acc-r3",
            true,
            now + 280 + idx,
        )
        .await
        .unwrap();
    }
    let after_routine = repo.read_account_unchecked("acc-r3").unwrap();
    assert_eq!(after_routine.auth_generation, gen_before_routine);
    assert_eq!(after_routine.token_version, ver_before_routine + 3);

    let resumed_after_routine = resume_pending_auth_records(
        &repo,
        &MockTransport::from_queue([Ok(MockTransport::json_response(
            200,
            json!({"email": "r3@example.invalid"}),
        ))]),
        &endpoints,
        &reg,
        now + 290,
    )
    .await
    .unwrap();
    assert_eq!(resumed_after_routine.resumed_accounts.len(), 1);
    let post_routine_reauth = repo.read_account_unchecked("acc-r3").unwrap();
    assert_eq!(
        post_routine_reauth.token.refresh_token,
        "1//r3-reauth-survives-routine"
    );
    assert!(post_routine_reauth.auth_generation > gen_before_routine);
    assert!(repo
        .account_has_superseded_rt(&post_routine_reauth, "1//r3-routine-rot-3")
        .unwrap());

    // =========================================================================
    // 5. Multi-failure ordering by monotonic `auth_seq` under backwards wall-clock skew
    //    AND newer `reauthorize_email_mismatch` NOT blocking earlier valid pending (nor being deleted by it)!
    // =========================================================================
    for (idx, skewed_clock) in [(1, now + 900), (2, now + 800), (3, now + 700)] {
        let tr = MockTransport::from_queue([
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": format!("at-skew-{idx}"),
                    "refresh_token": format!("1//r3-skew-rt-{idx}"),
                    "expires_in": 3600,
                    "scope": "openid https://www.googleapis.com/auth/cloud-platform"
                }),
            )),
            Ok(MockTransport::json_response(500, json!({"error": "down"}))),
        ]);
        let _ = complete_reauthorize_exchange_locked(
            &repo,
            &tr,
            &endpoints,
            &reg,
            &post_routine_reauth,
            &mk_sess(15010 + idx as u16),
            &format!("code-skew-{idx}"),
            skewed_clock,
        )
        .await
        .unwrap_err();
    }
    assert_eq!(repo.list_pending_auth_readonly().unwrap().len(), 3);

    // Also add an even newer (`idx=4`, SAME Unix timestamp `now + 700`!) reauthorization that will return `wrong@example.invalid`!
    let tr_mismatch = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-mismatch-4",
                "refresh_token": "1//r3-mismatch-other-user-4",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(500, json!({"error": "down"}))),
    ]);
    let _ = complete_reauthorize_exchange_locked(
        &repo,
        &tr_mismatch,
        &endpoints,
        &reg,
        &post_routine_reauth,
        &mk_sess(15020),
        "code-mismatch-4",
        now + 700,
    )
    .await
    .unwrap_err();
    assert_eq!(repo.list_pending_auth_readonly().unwrap().len(), 4);

    struct MultiOrderTransport {
        userinfo_gets: Arc<AtomicUsize>,
    }
    impl HttpTransport for MultiOrderTransport {
        fn execute<'a>(
            &'a self,
            req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                self.userinfo_gets.fetch_add(1, Ordering::SeqCst);
                let auth = req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                let email = if auth.contains("at-mismatch-4") {
                    "wrong-account@example.invalid"
                } else {
                    "r3@example.invalid"
                };
                Ok(HttpResponse {
                    status: 200,
                    headers: HashMap::new(),
                    body: serde_json::to_vec(&json!({ "email": email })).unwrap(),
                })
            })
        }
    }

    let multi_gets = Arc::new(AtomicUsize::new(0));
    let multi_rep = resume_pending_auth_records(
        &repo,
        &MultiOrderTransport {
            userinfo_gets: multi_gets.clone(),
        },
        &endpoints,
        &reg,
        now + 950,
    )
    .await
    .unwrap();

    // Expect: #4 (mismatch) tried 1st -> fails `reauthorize_email_mismatch` and stays preserved;
    //         #3 (`1//r3-skew-rt-3`, highest valid `auth_seq` despite lowest `created_at`!) tried 2nd -> binds & absorbs #2 and #1!
    //         Total userinfo GETs == 2!
    assert_eq!(multi_gets.load(Ordering::SeqCst), 2);
    assert_eq!(multi_rep.resumed_accounts.len(), 1);
    assert_eq!(multi_rep.failures.len(), 1);
    let post_multi = repo.read_account_unchecked("acc-r3").unwrap();
    assert_eq!(post_multi.token.refresh_token, "1//r3-skew-rt-3");
    assert!(repo
        .account_has_superseded_rt(&post_multi, "1//r3-skew-rt-1")
        .unwrap());
    assert!(repo
        .account_has_superseded_rt(&post_multi, "1//r3-skew-rt-2")
        .unwrap());
    let surviving_pends = repo.list_pending_auth_readonly().unwrap();
    assert_eq!(surviving_pends.len(), 1);
    assert!(surviving_pends[0].email_mismatch);
    assert_eq!(
        surviving_pends[0].token.refresh_token,
        "1//r3-mismatch-other-user-4"
    );

    // Subsequent valid reauthorization of `acc-r3` MUST NOT delete the preserved `email_mismatch` foreign token
    // or poison `acc-r3` with another user's refresh_token digest, AND `accounts add` can still bind that foreign RT!
    let tr_reauth_after_mismatch = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-after-mismatch-5",
                "refresh_token": "1//r3-after-mismatch-5",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "r3@example.invalid"}),
        )),
    ]);
    let post_after_mismatch = complete_reauthorize_exchange_locked(
        &repo,
        &tr_reauth_after_mismatch,
        &endpoints,
        &reg,
        &post_multi,
        &mk_sess(15021),
        "code-after-mismatch-5",
        now + 955,
    )
    .await
    .unwrap();
    assert_eq!(
        post_after_mismatch.token.refresh_token,
        "1//r3-after-mismatch-5"
    );
    assert!(!repo
        .account_has_superseded_rt(&post_after_mismatch, "1//r3-mismatch-other-user-4")
        .unwrap());
    assert_eq!(repo.list_pending_auth_readonly().unwrap().len(), 1);

    let add_foreign_posts = Arc::new(AtomicUsize::new(0));
    let add_foreign_gets = Arc::new(AtomicUsize::new(0));
    let (foreign_acc, foreign_created) = bootstrap_and_persist_refresh_token(
        &repo,
        &CountingResumeTransport {
            issued_rt: "1//unused-foreign".into(),
            email: "wrong-account@example.invalid".into(),
            token_posts: add_foreign_posts.clone(),
            userinfo_gets: add_foreign_gets.clone(),
        },
        &endpoints,
        &reg,
        "1//r3-mismatch-other-user-4",
        None,
        None,
        now + 956,
    )
    .await
    .unwrap();
    assert!(foreign_created);
    assert_eq!(foreign_acc.email, "wrong-account@example.invalid");
    assert_eq!(add_foreign_posts.load(Ordering::SeqCst), 0);
    assert_eq!(add_foreign_gets.load(Ordering::SeqCst), 1);
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());

    // Direct live `reauthorize_email_mismatch` followed by valid `reauthorize` ALSO preserves the foreign token!
    let tr_live_mismatch = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-live-mismatch",
                "refresh_token": "1//r3-live-mismatch-foreign",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "another-user@example.invalid"}),
        )),
    ]);
    let live_mm_err = complete_reauthorize_exchange_locked(
        &repo,
        &tr_live_mismatch,
        &endpoints,
        &reg,
        &post_after_mismatch,
        &mk_sess(15022),
        "code-live-mm",
        now + 957,
    )
    .await
    .unwrap_err();
    assert_eq!(live_mm_err.error_code, "reauthorize_email_mismatch");

    let tr_live_ok = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-live-ok-6",
                "refresh_token": "1//r3-live-ok-6",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "r3@example.invalid"}),
        )),
    ]);
    let post_live_ok = complete_reauthorize_exchange_locked(
        &repo,
        &tr_live_ok,
        &endpoints,
        &reg,
        &post_after_mismatch,
        &mk_sess(15023),
        "code-live-ok-6",
        now + 958,
    )
    .await
    .unwrap();
    assert!(!repo
        .account_has_superseded_rt(&post_live_ok, "1//r3-live-mismatch-foreign")
        .unwrap());
    assert_eq!(repo.list_pending_auth_readonly().unwrap().len(), 1);
    let _ = agy_switch_cli::oauth::refresh::purge_all_pending_auth_records(&repo).unwrap();

    // =========================================================================
    // 6. `state/auth_sequence.json` corrupt / 0644 / FIFO diagnostics in `status`
    // =========================================================================
    let seq_path = paths.auth_sequence_file();
    assert!(seq_path.exists());
    let orig_seq_bytes = fs::read(&seq_path).unwrap();
    fs::write(&seq_path, b"{corrupt-auth-seq").unwrap();
    fs::set_permissions(&seq_path, fs::Permissions::from_mode(0o644)).unwrap();

    let st_bad_seq = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_bad_seq.status.code(), Some(1));

    // Pre-`/token` preflight: corrupt `auth_sequence.json` aborts BEFORE sending `/token` POST (`token_posts == 0`)!
    let preflight_posts = Arc::new(AtomicUsize::new(0));
    let preflight_err = bootstrap_and_persist_refresh_token(
        &repo,
        &CountingResumeTransport {
            issued_rt: "1//should-not-rotate".into(),
            email: "preflight@example.invalid".into(),
            token_posts: preflight_posts.clone(),
            userinfo_gets: Arc::new(AtomicUsize::new(0)),
        },
        &endpoints,
        &reg,
        "1//preflight-input-rt",
        Some("antigravity_enterprise"),
        None,
        now + 959,
    )
    .await
    .unwrap_err();
    assert_eq!(preflight_err.error_code, "data_error");
    assert_eq!(preflight_posts.load(Ordering::SeqCst), 0);

    // Restore valid `auth_sequence.json` with `0644` -> `status` flags `pending_auth_ok: false` + warning!
    fs::write(&seq_path, &orig_seq_bytes).unwrap();
    repo.with_write_lock(|tx| tx.write_auth_sequence_state(900))
        .unwrap();
    fs::set_permissions(&seq_path, fs::Permissions::from_mode(0o644)).unwrap();
    let st_perm_warn = h.cli().args(["status", "--json"]).output().unwrap();
    assert_eq!(st_perm_warn.status.code(), Some(0));
    let st_pw_j: serde_json::Value = serde_json::from_slice(&st_perm_warn.stdout).unwrap();
    assert_eq!(st_pw_j["pending_auth_ok"], false);
    fs::set_permissions(&seq_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        repo.read_auth_sequence_readonly()
            .unwrap()
            .unwrap()
            .last_auth_seq,
        900
    );

    // Zero-writer named pipe at `auth_sequence.json` never blocks and is preserved by `status` (exit 1)
    let saved_seq_bytes = fs::read(&seq_path).unwrap();
    fs::remove_file(&seq_path).unwrap();
    let c_seq_pipe = CString::new(seq_path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_seq_pipe.as_ptr(), 0o600) }, 0);
    let t0 = Instant::now();
    let st_pipe = h.cli().args(["status", "--json"]).output().unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert_eq!(st_pipe.status.code(), Some(1));
    assert!(fs::symlink_metadata(&seq_path)
        .unwrap()
        .file_type()
        .is_fifo());
    fs::remove_file(&seq_path).unwrap();
    fs::write(&seq_path, saved_seq_bytes).unwrap();
    fs::set_permissions(&seq_path, fs::Permissions::from_mode(0o600)).unwrap();

    // =========================================================================
    // 7. Concurrent brand-new `auth login` for same unindexed email (`RetryUnderL2`),
    //    deleted heuristic pre-match resilience, legacy empty-store import protection,
    //    corrupt unrelated account `/token` staging survival, & `save_account` failure guard!
    // =========================================================================
    // 7(a): Two concurrent brand-new `auth login` sessions for previously-unindexed `brandnew@example.invalid`:
    //       lower `auth_seq` suspends in `userinfo`, higher `auth_seq` commits first -> loser hits `RetryUnderL2` & `superseded_authorization`!
    let entered_l1 = Arc::new(Notify::new());
    let release_l1 = Arc::new(Notify::new());
    let tr_login_older = GatedAuthTransport {
        issued_at: "at-brandnew-older".into(),
        issued_rt: "1//r3-brandnew-older".into(),
        expires_in: 3600,
        email: "brandnew@example.invalid".into(),
        token_posts: Arc::new(AtomicUsize::new(0)),
        userinfo_gets: Arc::new(AtomicUsize::new(0)),
        entered_userinfo: entered_l1.clone(),
        release_userinfo: release_l1.clone(),
    };
    let sess_l1 = mk_sess(15030);
    let mut fut_login_older = Box::pin(complete_login_exchange_locked(
        &repo,
        &tr_login_older,
        &endpoints,
        &reg,
        &sess_l1,
        "code-bn-older",
        None,
        now + 960,
    ));
    tokio::select! {
        _ = entered_l1.notified() => {}
        _ = &mut fut_login_older => panic!("fut_login_older finished early"),
    }

    let tr_login_newer = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-brandnew-newer",
                "refresh_token": "1//r3-brandnew-newer-winner",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "brandnew@example.invalid"}),
        )),
    ]);
    let (bn_winner, bn_created) = complete_login_exchange_locked(
        &repo,
        &tr_login_newer,
        &endpoints,
        &reg,
        &mk_sess(15031),
        "code-bn-newer",
        None,
        now + 961,
    )
    .await
    .unwrap();
    assert!(bn_created);
    assert_eq!(bn_winner.token.refresh_token, "1//r3-brandnew-newer-winner");

    release_l1.notify_one();
    let older_err = fut_login_older.await.unwrap_err();
    assert_eq!(older_err.error_code, "superseded_authorization");
    let bn_after = repo.read_account_unchecked(&bn_winner.id).unwrap();
    assert_eq!(bn_after.token.refresh_token, "1//r3-brandnew-newer-winner");
    assert!(repo
        .account_has_superseded_rt(&bn_after, "1//r3-brandnew-older")
        .unwrap());
    assert!(repo.list_pending_auth_readonly().unwrap().is_empty());

    // 7(b): Corrupt unrelated `accounts/<id>.json` NEVER drops a newly issued `/token` credential in memory!
    let saved_foreign_bytes = fs::read(paths.account_file(&foreign_acc.id)).unwrap();
    fs::write(paths.account_file(&foreign_acc.id), b"{corrupt-unrelated").unwrap();
    let tr_survive = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-survive-corrupt-other",
                "refresh_token": "1//r3-survive-corrupt-other",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "survivor@example.invalid"}),
        )),
    ]);
    let survive_res = complete_login_exchange_locked(
        &repo,
        &tr_survive,
        &endpoints,
        &reg,
        &mk_sess(15032),
        "code-survive",
        None,
        now + 970,
    )
    .await;
    assert!(survive_res.is_err());
    assert!(repo
        .list_valid_pending_auth_lossy()
        .iter()
        .any(|p| p.token.refresh_token == "1//r3-survive-corrupt-other"));
    fs::write(paths.account_file(&foreign_acc.id), saved_foreign_bytes).unwrap();
    fs::set_permissions(
        paths.account_file(&foreign_acc.id),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let surv_rep = resume_pending_auth_records(
        &repo,
        &MockTransport::from_queue([Ok(MockTransport::json_response(
            200,
            json!({"email": "survivor@example.invalid"}),
        ))]),
        &endpoints,
        &reg,
        now + 971,
    )
    .await
    .unwrap();
    assert_eq!(surv_rep.resumed_accounts.len(), 1);

    // 7(c): Pre-matched account deleted while `auth login` waits on `L2` cleanly creates a fresh account!
    let del_target_id = surv_rep.resumed_accounts[0].id.clone();
    let l2_entered = Arc::new(Notify::new());
    let l2_release = Arc::new(Notify::new());
    let repo_del = repo.clone();
    let del_tid_clone = del_target_id.clone();
    let l2_ent_c = l2_entered.clone();
    let l2_rel_c = l2_release.clone();
    let del_holder = tokio::spawn(async move {
        agy_switch_cli::store::locks::with_account_refresh_lock(
            repo_del.paths(),
            &del_tid_clone,
            Duration::from_secs(5),
            || async {
                l2_ent_c.notify_one();
                l2_rel_c.notified().await;
                repo_del
                    .with_write_lock(|tx| {
                        let _ = tx.delete_account(&del_tid_clone, true, now + 972)?;
                        Ok(())
                    })
                    .unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();
    });
    l2_entered.notified().await;
    let tr_recreate = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "at-recreated",
                "refresh_token": "1//r3-recreated-after-delete",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "survivor@example.invalid"}),
        )),
    ]);
    let sess_recreate = mk_sess(15033);
    let mut recreate_fut = Box::pin(complete_login_exchange_locked(
        &repo,
        &tr_recreate,
        &endpoints,
        &reg,
        &sess_recreate,
        "code-recreate",
        None,
        now + 973,
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut recreate_fut)
            .await
            .is_err()
    );
    l2_release.notify_one();
    del_holder.await.unwrap();
    let (recreated_acc, recreated_new) = recreate_fut.await.unwrap();
    assert!(recreated_new);
    assert_eq!(
        recreated_acc.token.refresh_token,
        "1//r3-recreated-after-delete"
    );

    // 7(d): Legacy empty-store `auth_seq == 0` pending does NOT overwrite subsequent `accounts import`!
    let h_empty = IsolatedHarness::new();
    let p_empty = h_empty.paths();
    let r_empty = StoreRepository::new(p_empty.clone());
    fs::create_dir_all(p_empty.pending_auth_dir()).unwrap();
    fs::set_permissions(
        p_empty.pending_auth_dir(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let raw_empty_pend = p_empty.pending_auth_file("pend-empty-v1");
    fs::write(
        &raw_empty_pend,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "id": "pend-empty-v1",
            "flow": { "kind": "login" },
            "token": {
                "access_token": "at-empty-v1",
                "refresh_token": "1//empty-v1-stale",
                "expires_in": 3600,
                "expiry_timestamp": now + 7200,
                "token_type": "Bearer",
                "oauth_client_key": "antigravity_enterprise",
                "granted_scopes": ["https://www.googleapis.com/auth/cloud-platform", "openid"],
                "is_gcp_tos": true
            },
            "created_at": now - 50
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&raw_empty_pend, fs::Permissions::from_mode(0o600)).unwrap();

    let empty_bundle = h_empty.tmp.path().join("empty-fresh-import.json");
    fs::write(
        &empty_bundle,
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "accounts": [{
                "email": "emptyupgrade@example.invalid",
                "refresh_token": "1//empty-fresh-imported-winner",
                "oauth_client_key": "antigravity_enterprise",
                "is_gcp_tos": true
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let empty_imp = import_transfer_bundle_file(&r_empty, &empty_bundle, false, now)
        .await
        .unwrap();
    assert_eq!(empty_imp.imported_count, 1);
    let _ = resume_pending_auth_records(
        &r_empty,
        &MockTransport::from_queue([Ok(MockTransport::json_response(
            200,
            json!({"email": "emptyupgrade@example.invalid"}),
        ))]),
        &endpoints,
        &reg,
        now + 5,
    )
    .await
    .unwrap();
    let empty_snap = r_empty.read_snapshot().unwrap();
    assert_eq!(
        empty_snap.accounts[0].token.refresh_token,
        "1//empty-fresh-imported-winner"
    );
    assert!(r_empty
        .account_has_superseded_rt(&empty_snap.accounts[0], "1//empty-v1-stale")
        .unwrap());
    assert!(r_empty.list_pending_auth_readonly().unwrap().is_empty());

    // 7(e): `absorb_superseded_pending_into_account_cas` `save_account` failure NEVER unlinks the `PendingAuthRecord`!
    let mut spill_acc = empty_snap.accounts[0].clone();
    spill_acc.previous_refresh_token_digests = (0
        ..agy_switch_cli::domain::account::MAX_PREVIOUS_RT_DIGESTS)
        .map(|i| format!("{i:064x}"))
        .collect();
    r_empty
        .with_write_lock(|tx| tx.save_account(&spill_acc))
        .unwrap();
    let staged_sup = agy_switch_cli::domain::account::PendingAuthRecord {
        schema_version: 1,
        id: "pend-save-guard".into(),
        flow: agy_switch_cli::domain::account::PendingAuthFlow::Reauthorize {
            target_account_id: spill_acc.id.clone(),
        },
        token: make_acc(
            "tmp",
            "emptyupgrade@example.invalid",
            "1//superseded-must-stay-on-save-err",
            now + 3600,
            now,
        )
        .token,
        auth_seq: 1,
        email_mismatch: false,
        input_rt_digest: None,
        custom_label: None,
        created_at: now,
    };
    let staged_sup_fp = staged_sup.cas_fingerprint();
    r_empty
        .with_write_lock(|tx| tx.save_pending_auth(&staged_sup))
        .unwrap();
    // Obstruct `state/token_lineage` with a regular file so `save_account` spill fails deterministically on all UIDs!
    let _ = fs::remove_dir_all(p_empty.token_lineage_dir());
    fs::write(p_empty.token_lineage_dir(), b"obstruction").unwrap();
    let absorb_err = r_empty.with_write_lock(|tx| {
        tx.absorb_superseded_pending_into_account_cas(
            "pend-save-guard",
            &staged_sup_fp,
            &spill_acc.id,
            None,
            &[],
        )
    });
    assert!(absorb_err.is_err());
    assert!(p_empty.pending_auth_file("pend-save-guard").exists());
    fs::remove_file(p_empty.token_lineage_dir()).unwrap();

    // 7(f): Busy pending record whose file becomes unreadable (`Err`) is NEVER swallowed as `already_consumed`!
    let p_guard_path = p_empty.pending_auth_file("pend-save-guard");
    let hold_ent = Arc::new(Notify::new());
    let hold_rel = Arc::new(Notify::new());
    let p_empty_c = p_empty.clone();
    let he_c = hold_ent.clone();
    let hr_c = hold_rel.clone();
    let pa_holder = tokio::spawn(async move {
        agy_switch_cli::store::locks::with_pending_auth_lock(
            &p_empty_c,
            "pend-save-guard",
            Duration::from_secs(5),
            || async {
                he_c.notify_one();
                hr_c.notified().await;
                Ok(())
            },
        )
        .await
        .unwrap();
    });
    hold_ent.notified().await;
    let p_guard_for_corrupt = p_guard_path.clone();
    let corrupt_during_wait = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        fs::write(&p_guard_for_corrupt, b"{unreadable-while-busy").unwrap();
    });
    let busy_err_rep = resume_pending_auth_records(
        &r_empty,
        &MockTransport::from_queue([]),
        &endpoints,
        &reg,
        now + 10,
    )
    .await
    .unwrap();
    corrupt_during_wait.await.unwrap();
    hold_rel.notify_one();
    pa_holder.await.unwrap();
    assert_eq!(busy_err_rep.failures.len(), 1);
}

#[test]
fn v127_cli_defaults_token_parser_builtin_client_and_order_contract_regressions() {
    let _g = ENV_MUTEX.blocking_lock();
    let h = IsolatedHarness::new();
    let repo = StoreRepository::new(h.paths());
    let now = 1_800_010_000i64;

    assert_eq!(DEFAULT_QUOTA_MAX_AGE_SECS, 3600);
    assert_eq!(
        agy_switch_cli::switching::daemon::DEFAULT_DAEMON_INTERVAL_SECS,
        900
    );
    assert_eq!(
        agy_switch_cli::switching::daemon::CANDIDATE_REFRESH_BACKOFF_SECS,
        900
    );
    assert_eq!(
        agy_switch_cli::switching::daemon::DEFAULT_DAEMON_COOLDOWN_SECS,
        3600
    );

    // 1. Unpooled `gemini-4-carbon-high` and `-disabled` models never pollute shared Gemini or evaluate as Known
    let mut obs = QuotaObservation::new(now, QuotaSourceEnv::OfficialCli);
    obs.subscription_tier = Some("Google AI Pro".into());
    obs.tier_source_env = Some(QuotaSourceEnv::OfficialCli);
    obs.quota_groups = Some(vec![
        agy_switch_cli::domain::quota::QuotaGroup {
            display_name: "Gemini Models".into(),
            description: Some("Models within this group: gemini-3.1-pro".into()),
            buckets: vec![
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.64,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-07T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: 0.90,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-01T05:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
            ],
        },
        agy_switch_cli::domain::quota::QuotaGroup {
            display_name: "Gemini 4 Carbon".into(),
            description: None,
            buckets: vec![
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-carbon-wtu-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.41,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-07T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
                agy_switch_cli::domain::quota::QuotaBucket {
                    bucket_id: "gemini-carbon-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: 0.80,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-01T05:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
            ],
        },
    ]);
    assert_eq!(
        evaluate_quota_observation(&obs, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        agy_switch_cli::domain::quota::QuotaEval::Known {
            remaining_percentage: 64.0
        }
    );
    assert!(matches!(
        evaluate_quota_observation(
            &obs,
            "gemini-4-carbon-high",
            now,
            DEFAULT_QUOTA_MAX_AGE_SECS
        ),
        agy_switch_cli::domain::quota::QuotaEval::Unknown { .. }
    ));
    assert!(matches!(
        evaluate_quota_observation(
            &obs,
            "gemini-4-hydrogen-disabled",
            now,
            DEFAULT_QUOTA_MAX_AGE_SECS
        ),
        agy_switch_cli::domain::quota::QuotaEval::Unknown { .. }
    ));

    // 2. Multi-line batch refresh_token parser with inline `# label` comments AND literal `#` without space
    let parsed_batch = agy_switch_cli::cli::secret_input::parse_token_lines_from_text(
        "\n# comment line\n1//synthetic_tok_a  # Work Account\n1//synthetic#literal_b\n\n",
        "test",
    )
    .unwrap();
    assert_eq!(
        parsed_batch,
        vec![
            (
                "1//synthetic_tok_a".to_string(),
                Some("Work Account".to_string())
            ),
            ("1//synthetic#literal_b".to_string(), None),
        ]
    );

    // 3. Builtin OAuth client key in `config.json` (`antigravity_enterprise`) produces zero warnings,
    //    and incomplete `accounts list --order` reports the unified `accounts list --order` command name.
    let acc1 = make_acc(
        "acc-inc-1",
        "inc1@example.invalid",
        "1//RT_INC_1",
        now + 7200,
        now,
    );
    let acc2 = make_acc(
        "acc-inc-2",
        "inc2@example.invalid",
        "1//RT_INC_2",
        now + 7200,
        now,
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1, true, now)?;
        tx.upsert_account(acc2, false, now)
    })
    .unwrap();

    let cfg_path = h.paths().config_file();
    fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
    fs::write(
        &cfg_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "oauth": {
                "active_client_key": "antigravity_enterprise",
                "required_scopes": ["openid", "https://www.googleapis.com/auth/cloud-platform"],
                "clients": []
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&cfg_path, fs::Permissions::from_mode(0o600)).unwrap();
    let loaded_reg = OAuthClientRegistry::load(&h.paths()).unwrap();
    assert!(
        loaded_reg.warnings().is_empty(),
        "expected zero warnings for antigravity_enterprise, got: {:?}",
        loaded_reg.warnings()
    );

    let order_err = repo
        .with_write_lock(|tx| tx.reorder_accounts(vec!["acc-inc-1".to_string()], now + 3))
        .unwrap_err();
    assert_eq!(order_err.exit_code, ExitCode::InvalidUsageOrAmbiguous);
    assert!(
        order_err
            .message
            .contains("`accounts list --order` requires every saved account exactly once"),
        "unexpected error message: {}",
        order_err.message
    );
    assert!(!order_err.message.contains("`accounts order`"));
}
