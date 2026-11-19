use agy_switch_cli::domain::account::AccountRecord;
use agy_switch_cli::domain::policy::{PolicyMode, PolicyStrategy, SwitchPolicy};
use agy_switch_cli::domain::quota::{
    evaluate_account_quota, evaluate_quota_observation, ModelQuota, PrimaryModelQuota, QuotaBucket,
    QuotaEval, QuotaGroup, QuotaObservation, QuotaSourceEnv, DEFAULT_QUOTA_MAX_AGE_SECS,
};
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::oauth::refresh::OAuthEndpoints;
use agy_switch_cli::oauth::registry::OAuthClientRegistry;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::quota::client::CloudCodeEndpoints;
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend};
use agy_switch_cli::session::payload::serialize_session_payload;
use agy_switch_cli::session::process::ProcessLease;
use agy_switch_cli::store::fs_atomic::ensure_private_dir;
use agy_switch_cli::store::repository::StoreRepository;
use agy_switch_cli::switching::daemon::{
    read_daemon_state_readonly, DaemonConfigOverrides, DaemonEngine, TickStageOutcome,
};
use agy_switch_cli::switching::executor::{execute_switch, SwitchOptions};
use agy_switch_cli::transport::client::MockTransport;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

static PROC_ENV_MUTEX: AsyncMutex<()> = AsyncMutex::const_new(());

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

fn build_quota(
    now: i64,
    tier: Option<&str>,
    primary_frac: f64,
    weekly_frac: f64,
    short_5h_frac: Option<f64>,
    reset_rfc3339: &str,
) -> QuotaObservation {
    let mut q = QuotaObservation::new(now, QuotaSourceEnv::Production);
    q.subscription_tier = tier.map(str::to_owned);
    q.tier_source_env = tier.map(|_| QuotaSourceEnv::Production);
    q.models.push(ModelQuota {
        name: "gemini-3.8-flash".into(),
        percentage: (primary_frac * 100.0).round() as i32,
        percentage_known: Some(true),
        observed_remaining_fraction: Some(primary_frac),
        primary_quota: Some(PrimaryModelQuota {
            remaining_fraction: Some(primary_frac),
            reset_time: reset_rfc3339.into(),
        }),
        quota_bucket_id: Some("gemini-weekly".into()),
        reset_time: reset_rfc3339.into(),
        display_name: Some("Gemini 3.8 Flash".into()),
        supports_images: None,
        supports_thinking: None,
        thinking_budget: None,
        recommended: None,
        max_tokens: None,
        max_output_tokens: None,
        supported_mime_types: None,
    });
    let mut buckets = vec![QuotaBucket {
        bucket_id: "gemini-weekly".into(),
        window: "weekly".into(),
        remaining_fraction: weekly_frac,
        remaining_fraction_known: Some(true),
        reset_time: reset_rfc3339.into(),
        display_name: None,
        description: None,
    }];
    if let Some(s5) = short_5h_frac {
        buckets.push(QuotaBucket {
            bucket_id: "gemini-5h".into(),
            window: "5h".into(),
            remaining_fraction: s5,
            remaining_fraction_known: Some(true),
            reset_time: reset_rfc3339.into(),
            display_name: None,
            description: None,
        });
    }
    q.quota_groups = Some(vec![QuotaGroup {
        display_name: "Gemini Models".into(),
        description: None,
        buckets,
    }]);
    q
}

#[test]
fn quota_eval_enforces_min_triad_free_unknown_tier_argon_8hop_forwarding_and_reset_staleness() {
    let _guard = PROC_ENV_MUTEX.blocking_lock();
    let now = 1_800_000_000i64;
    let future_reset = "2099-01-01T00:00:00Z";
    let past_reset = "2020-01-01T00:00:00Z"; // <= now!

    // 1. min(weekly=60%, 5h=80%, primary=12%) == 12%!
    let q_triad = build_quota(
        now,
        Some("Google AI Pro"),
        0.12,
        0.60,
        Some(0.80),
        future_reset,
    );
    assert_eq!(
        evaluate_quota_observation(&q_triad, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Known {
            remaining_percentage: 12.0
        }
    );

    // 2. Missing 5h bucket: `Free` tier -> min(weekly, primary); `Unknown` (`None`) tier -> `Unknown`!
    let q_free = build_quota(now, Some("Free Tier"), 0.90, 0.45, None, future_reset);
    assert_eq!(
        evaluate_quota_observation(&q_free, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Known {
            remaining_percentage: 45.0
        }
    );
    let q_unknown_tier = build_quota(now, None, 0.90, 0.45, None, future_reset);
    assert!(matches!(
        evaluate_quota_observation(&q_unknown_tier, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Unknown { .. }
    ));

    // 3. `reset_time <= now` MUST evaluate to `Stale`, NEVER 100% recovered!
    let q_expired_reset = build_quota(
        now,
        Some("Google AI Pro"),
        0.90,
        0.90,
        Some(0.90),
        past_reset,
    );
    assert!(matches!(
        evaluate_quota_observation(&q_expired_reset, "all", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Stale { .. }
    ));

    // 4. Independent Argon weekly pool + 8-hop model forwarding
    let mut q_argon = QuotaObservation::new(now, QuotaSourceEnv::Production);
    q_argon.models.push(ModelQuota {
        name: "gemini-4-argon-target".into(),
        percentage: 33,
        percentage_known: Some(true),
        observed_remaining_fraction: Some(0.33),
        primary_quota: None,
        quota_bucket_id: Some("gemini-argon-wtu-weekly".into()),
        reset_time: future_reset.into(),
        display_name: Some("Gemini 4 Argon".into()),
        supports_images: None,
        supports_thinking: None,
        thinking_budget: None,
        recommended: None,
        max_tokens: None,
        max_output_tokens: None,
        supported_mime_types: None,
    });
    q_argon.quota_groups = Some(vec![QuotaGroup {
        display_name: "Gemini 4 Argon".into(),
        description: None,
        buckets: vec![QuotaBucket {
            bucket_id: "gemini-argon-wtu-weekly".into(),
            window: "weekly".into(),
            remaining_fraction: 0.33,
            remaining_fraction_known: Some(true),
            reset_time: future_reset.into(),
            display_name: None,
            description: None,
        }],
    }]);
    let mut rules = HashMap::new();
    for hop in 0..8 {
        let from = format!("alias-{hop}");
        let to = if hop == 7 {
            "gemini-4-argon-target".to_string()
        } else {
            format!("alias-{}", hop + 1)
        };
        rules.insert(from, to);
    }
    q_argon.model_forwarding_rules = rules;

    assert_eq!(
        evaluate_quota_observation(&q_argon, "argon", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Known {
            remaining_percentage: 33.0
        }
    );
    assert_eq!(
        evaluate_quota_observation(&q_argon, "alias-0", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Known {
            remaining_percentage: 33.0
        }
    );
    // Shared `gemini` pool does NOT borrow Argon!
    assert!(matches!(
        evaluate_quota_observation(&q_argon, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Unknown { .. }
    ));
}

#[tokio::test]
async fn managed_run_keeps_selected_without_policy_switch_supports_explicit_account_and_forwards_exit_code(
) {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();

    // Create a synthetic `agy` executable script that:
    // 1. Waits briefly for parent `agy-switch-cli run` to write `<data>/state/leases/$$.json`
    // 2. Reads `$HOME/.gemini/antigravity-cli/antigravity-oauth-token` into a trace file
    // 3. Copies lease JSON into trace dir so we can verify two-factor `pid` + `proc_starttime_ticks`!
    // 4. Exits with distinct exit code 42!
    let fake_agy = bin_dir.join("agy");
    let trace_dir = tmp.path().join("trace");
    fs::create_dir_all(&trace_dir).unwrap();
    let script = format!(
        "#!/bin/sh\n\
         for _i in 1 2 3 4 5 6 7 8 9 10; do\n\
           if [ -f \"{data}/state/leases/$$.json\" ]; then\n\
             cp \"{data}/state/leases/$$.json\" \"{trace}/seen_lease.json\"\n\
             break\n\
           fi\n\
           sleep 0.02\n\
         done\n\
         cp \"$HOME/.gemini/antigravity-cli/antigravity-oauth-token\" \"{trace}/seen_slot.json\"\n\
         exit 42\n",
        data = data.display(),
        trace = trace_dir.display()
    );
    fs::write(&fake_agy, script).unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let now = jiff::Timestamp::now().as_second();
    let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
    let repo = StoreRepository::new(paths.clone());

    let mut acc_low = AccountRecord::new(
        "acc-low".into(),
        "low@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.low".into(),
            refresh_token: "1//RT_LOW".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    acc_low.quota = Some(build_quota(
        now,
        Some("Google AI Pro"),
        0.02,
        0.02,
        Some(0.02),
        "2099-01-01T00:00:00Z",
    ));

    let mut acc_high = AccountRecord::new(
        "acc-high".into(),
        "high@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.high".into(),
            refresh_token: "1//RT_HIGH".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    acc_high.quota = Some(build_quota(
        now,
        Some("Google AI Pro"),
        0.85,
        0.85,
        Some(0.85),
        "2099-01-01T00:00:00Z",
    ));

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_low.clone(), true, now)?;
        tx.upsert_account(acc_high.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            reserve_percentage: 5,
            candidate_min_percentage: 15,
            candidate_account_ids: vec!["acc-high".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_low.token).unwrap())
        .unwrap();

    // 1. Bare `run -- agy`: purely launches with the currently selected account (`acc-low`),
    //    NEVER performing implicit policy quota evaluation or auto-switching to `acc-high`!
    let out_bare = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args([
            "--data-dir",
            data.to_str().unwrap(),
            "--no-remote-version",
            "run",
            "--",
            "agy",
            "-p",
            "hello",
        ])
        .output()
        .unwrap();

    assert_eq!(
        out_bare.status.code(),
        Some(42),
        "Child exit code 42 must be forwarded: stderr={}",
        String::from_utf8_lossy(&out_bare.stderr)
    );
    let seen_slot_bare = fs::read_to_string(trace_dir.join("seen_slot.json")).unwrap();
    assert!(
        seen_slot_bare.contains("1//RT_LOW"),
        "Bare `run` must keep selected `acc-low` without policy auto-switch: {seen_slot_bare}"
    );
    let lease_bare: ProcessLease =
        serde_json::from_slice(&fs::read(trace_dir.join("seen_lease.json")).unwrap()).unwrap();
    assert!(lease_bare.pid > 0);
    assert!(lease_bare.proc_starttime_ticks > 0);
    assert_eq!(lease_bare.account_id, "acc-low");
    assert_eq!(fs::read_dir(paths.leases_dir()).unwrap().count(), 0);

    // 2. Explicit `run --account acc-high -- agy`: deterministically switches slot to `acc-high`,
    //    registers two-factor lease for `acc-high`, and forwards exit code 42!
    let _ = fs::remove_file(trace_dir.join("seen_slot.json"));
    let _ = fs::remove_file(trace_dir.join("seen_lease.json"));
    let out = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args([
            "--data-dir",
            data.to_str().unwrap(),
            "--no-remote-version",
            "run",
            "--account",
            "acc-high",
            "--",
            "agy",
            "-p",
            "hello",
        ])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(42),
        "Child exit code 42 must be forwarded: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Child `agy` received `acc-high`'s switched credential!
    let seen_slot = fs::read_to_string(trace_dir.join("seen_slot.json")).unwrap();
    assert!(seen_slot.contains("1//RT_HIGH"));

    // Lease bound real PID + positive `proc_starttime_ticks` > 0 and was cleaned up after child exit!
    let lease: ProcessLease =
        serde_json::from_slice(&fs::read(trace_dir.join("seen_lease.json")).unwrap()).unwrap();
    assert!(lease.pid > 0);
    assert!(lease.proc_starttime_ticks > 0);
    assert_eq!(lease.account_id, "acc-high");
    assert_eq!(fs::read_dir(paths.leases_dir()).unwrap().count(), 0);
}

#[tokio::test]
async fn daemon_enforces_request_budget_stale_pid_lease_ignore_revalidate_cancel_and_failure_pause()
{
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("fake_proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let now = 1_800_000_000i64;
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;

    let make_acc = |id: &str, pct: f64| -> AccountRecord {
        let mut a = AccountRecord::new(
            id.into(),
            format!("{id}@example.invalid"),
            TokenRecord {
                access_token: format!("ya29.{id}"),
                refresh_token: format!("1//RT_{id}"),
                expires_in: 7200,
                expiry_timestamp: now + 7200,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        );
        a.quota = Some(build_quota(
            now,
            Some("Google AI Pro"),
            pct,
            pct,
            Some(pct),
            "2099-01-01T00:00:00Z",
        ));
        a
    };

    let acc_a = make_acc("acc-a", 0.05); // 5% <= reserve 10%
    let acc_b = make_acc("acc-b", 0.80); // 80% >= minimum 30%
    let acc_c = make_acc("acc-c", 0.90);
    let acc_d = make_acc("acc-d", 0.95);

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        tx.upsert_account(acc_d.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Wait,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "gemini".into(),
            candidate_account_ids: vec!["acc-b".into(), "acc-c".into(), "acc-d".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    let mut engine = DaemonEngine::new();
    let overrides = DaemonConfigOverrides {
        cooldown_secs: 30,
        ..DaemonConfigOverrides::default()
    };
    let fast_oauth = OAuthEndpoints {
        base_backoff: std::time::Duration::from_millis(2),
        ..OAuthEndpoints::default()
    };
    let fast_quota = CloudCodeEndpoints {
        fallback_delay: std::time::Duration::from_millis(2),
        ..CloudCodeEndpoints::default()
    };
    let mock = MockTransport::default();
    let reg = OAuthClientRegistry::parse_from_raw(None, None);

    // Case 1: Active `agy` lease with MATCHING starttime blocks switch in `Mode::Wait`!
    ensure_private_dir(&paths.leases_dir()).unwrap();
    fs::create_dir_all(fake_proc.join("5001")).unwrap();
    fs::write(
        fake_proc.join("5001/stat"),
        "5001 (agy) S 1 5001 5001 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777888 1000 10",
    )
    .unwrap();
    let lease_5001 = ProcessLease {
        schema_version: 1,
        pid: 5001,
        proc_starttime_ticks: 777888,
        exe_basename: Some("agy".into()),
        account_id: "acc-a".into(),
        started_at: now,
    };
    fs::write(
        paths.leases_dir().join("5001.json"),
        serde_json::to_vec(&lease_5001).unwrap(),
    )
    .unwrap();

    let out_blocked = engine
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &reg,
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        out_blocked,
        TickStageOutcome::BlockedByActiveProcess {
            target_id: "acc-b".into()
        }
    );
    // Request budget: cached quotas were fresh -> ZERO network calls!
    assert_eq!(mock.recorded_requests().len(), 0);

    // Case 2: Simulate `SIGKILL` + PID reuse on PID 5001 (starttime changes to 999000, non-agy exe `sleep`)
    // AND inject manual user switch to `acc-c` right before Stage 5 `Revalidate`!
    // Result: Stale lease does NOT block, AND `Revalidate` detects manual switch & CANCELS stale pending plan to `acc-b`!
    fs::write(
        fake_proc.join("5001/stat"),
        "5001 (sleep) S 1 5001 5001 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999000 1000 10",
    )
    .unwrap();

    let repo_hook = repo.clone();
    engine.before_revalidate_hook = Some(Arc::new(move || {
        let r = repo_hook.clone();
        // Simulate concurrent manual switch from another OS thread/process between Stage 4 and Stage 5!
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                execute_switch(
                    &r,
                    &FileSessionBackend,
                    &MockTransport::default(),
                    &OAuthEndpoints::default(),
                    &OAuthClientRegistry::parse_from_raw(None, None),
                    "vscode/1.X.X (Antigravity/4.3.0)",
                    "acc-c",
                    &SwitchOptions {
                        dry_run: false,
                        allow_running: false,
                    },
                    now + 2,
                )
                .await
                .unwrap();
            });
        })
        .join()
        .unwrap();
    }));

    let out_cancelled = engine
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &reg,
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now + 3,
        )
        .await
        .unwrap();
    engine.before_revalidate_hook = None;

    assert!(matches!(
        out_cancelled,
        TickStageOutcome::CancelledStalePlan { .. }
    ));
    // Manual switch to `acc-c` was NOT overwritten by stale `acc-b` plan!
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-c")
    );
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_acc-c"));

    // Case 3: Switch back to low `acc-a`, run clean tick -> commits switch to `acc-b` and enters Cooldown!
    execute_switch(
        &repo,
        &backend,
        &mock,
        &OAuthEndpoints::default(),
        &reg,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now + 4,
    )
    .await
    .unwrap();

    let out_committed = engine
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &reg,
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now + 5,
        )
        .await
        .unwrap();
    assert_eq!(
        out_committed,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-a".into(),
            target_id: "acc-b".into()
        }
    );

    // Next tick within 30s cooldown (`now + 15 < now + 35`) stays in `InCooldown`
    let out_cool = engine
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &fast_oauth,
            &fast_quota,
            &reg,
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now + 15,
        )
        .await
        .unwrap();
    assert!(matches!(out_cool, TickStageOutcome::InCooldown { .. }));

    // Case 4: Unknown / Stale source quota NEVER blind-switches!
    repo.with_write_lock(|tx| {
        let mut b = tx.load_account_opt("acc-b").unwrap().unwrap();
        b.quota = None; // Unknown!
        tx.save_account(&b)?;
        Ok(())
    })
    .unwrap();
    // Backoff `acc-b` refresh so it stays `Unknown`
    engine
        .refresh_backoff_until
        .insert("acc-b".into(), now + 1000);
    let out_hold = engine
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &fast_oauth,
            &fast_quota,
            &reg,
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now + 40,
        )
        .await
        .unwrap();
    assert!(matches!(out_hold, TickStageOutcome::UncertainHold { .. }));

    // Case 5: 3 consecutive commit failures trigger persistent `PausedOnFailure` across restarts!
    execute_switch(
        &repo,
        &backend,
        &mock,
        &fast_oauth,
        &reg,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now + 41,
    )
    .await
    .unwrap();
    // Restore `acc-c` as top candidate
    repo.with_write_lock(|tx| {
        let prev = repo.read_policy()?.revision;
        let mut pol = repo.read_policy()?;
        pol.candidate_account_ids = vec!["acc-c".into()];
        tx.save_policy(&mut pol, Some(prev), now + 42)?;
        Ok(())
    })
    .unwrap();

    // Make slot dir read-only (0500) during commit so all 3 commits fail while quotas remain fresh (< 180s)!
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o500)).unwrap();
    for step in 0..3 {
        let res = engine
            .run_single_tick(
                &repo,
                &backend,
                &mock,
                &fast_oauth,
                &fast_quota,
                &reg,
                "vscode/1.X.X (Antigravity/4.3.0)",
                &overrides,
                now + 50 + step,
            )
            .await
            .unwrap();
        assert!(matches!(res, TickStageOutcome::CommitFailed { .. }));
    }
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let persisted = read_daemon_state_readonly(&paths).unwrap();
    assert!(persisted.paused_on_failure);
    assert_eq!(persisted.consecutive_commit_failures, 3);

    // Brand-new DaemonEngine instance after simulated restart STILL honors `PausedOnFailure`!
    let mut restarted_engine = DaemonEngine::new();
    let post_restart = restarted_engine
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &fast_oauth,
            &fast_quota,
            &reg,
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now + 60,
        )
        .await
        .unwrap();
    assert!(matches!(
        post_restart,
        TickStageOutcome::PausedOnFailure { .. }
    ));

    let _ = evaluate_account_quota(&acc_a, "all", now, 180);
}

#[tokio::test]
async fn foreground_daemon_enforces_single_instance_lock_and_exits_gracefully_on_sigterm() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("proc");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&proc_dir).unwrap();

    struct KillChildOnDrop(Option<std::process::Child>);
    impl Drop for KillChildOnDrop {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    let d1 = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
        .args([
            "--data-dir",
            data.to_str().unwrap(),
            "--no-remote-version",
            "daemon",
            "--interval",
            "60",
        ])
        .spawn()
        .unwrap();
    let mut d1_guard = KillChildOnDrop(Some(d1));

    // Wait up to 5s for `d1` to create and hold `flock(LOCK_EX)` on `locks/daemon.lock`
    let daemon_lock_path = data.join("locks/daemon.lock");
    for _ in 0..250 {
        if let Ok(f) = fs::OpenOptions::new().read(true).open(&daemon_lock_path) {
            use std::os::fd::AsRawFd;
            let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc < 0 {
                break;
            }
            let _ = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // Second daemon instance MUST immediately fail with exit code 5 (`LockBusyOrConflict`)!
    let d2 = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
        .args([
            "--data-dir",
            data.to_str().unwrap(),
            "--no-remote-version",
            "--json",
            "daemon",
            "--once",
        ])
        .output()
        .unwrap();
    assert_eq!(d2.status.code(), Some(5));

    // Send SIGTERM to d1 -> must shut down cleanly with exit code 0!
    let mut d1 = d1_guard.0.take().unwrap();
    unsafe {
        libc::kill(d1.id() as i32, libc::SIGTERM);
    }
    let st1 = d1.wait().unwrap();
    assert_eq!(st1.code(), Some(0));

    // After d1 exits, `daemon --once` succeeds cleanly (exit code 0)!
    let d3 = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
        .args([
            "--data-dir",
            data.to_str().unwrap(),
            "--no-remote-version",
            "daemon",
            "--once",
        ])
        .output()
        .unwrap();
    assert_eq!(d3.status.code(), Some(0));
}

#[tokio::test]
async fn managed_run_refreshes_expired_slot_even_when_refresh_token_unchanged_and_isolates_dbus() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc");
    let bin_dir = tmp.path().join("bin");
    let trace_dir = tmp.path().join("trace");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&trace_dir).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let fake_agy = bin_dir.join("agy");
    let script = format!(
        "#!/bin/sh\n\
         printf '%s' \"$DBUS_SESSION_BUS_ADDRESS\" > \"{trace}/dbus_env.txt\"\n\
         cp \"{slot}\" \"{trace}/slot_seen.json\"\n\
         exit 0\n",
        trace = trace_dir.display(),
        slot = home
            .join(".gemini/antigravity-cli/antigravity-oauth-token")
            .display(),
    );
    fs::write(&fake_agy, script).unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let now = 1_800_000_000i64;
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());

    // Account has an EXPIRED access_token ("ya29.EXPIRED_SLOT_TOKEN") and policy.enabled == false!
    let acc = AccountRecord::new(
        "acc-same-rt".into(),
        "same@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.EXPIRED_SLOT_TOKEN".into(),
            refresh_token: "1//UNCHANGED_REFRESH_TOKEN".into(),
            expires_in: 3600,
            expiry_timestamp: now - 100, // EXPIRED!
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc.clone(), true, now))
        .unwrap();
    // Pre-populate slot with an old payload carrying the SAME refresh_token ("1//UNCHANGED_REFRESH_TOKEN")
    let mut old_tok = acc.token.clone();
    old_tok.expiry_timestamp = now - 100;
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&old_tok).unwrap())
        .unwrap();

    // OAuth refresh returns a brand-new `access_token` WITHOUT rotating `refresh_token`!
    let mock = MockTransport::from_handler(|req| {
        if req.url.contains("userinfo") {
            return Ok(MockTransport::json_response(
                200,
                serde_json::json!({"email": "same@example.invalid", "name": "Same RT"}),
            ));
        }
        Ok(MockTransport::json_response(
            200,
            serde_json::json!({
                "access_token": "ya29.BRAND_NEW_ACCESS_TOKEN",
                "expires_in": 3600,
                "token_type": "Bearer"
                // no `refresh_token` field -> keeps `1//UNCHANGED_REFRESH_TOKEN`!
            }),
        ))
    });

    let _dbus_env = ScopedEnvVar::set(
        "DBUS_SESSION_BUS_ADDRESS",
        format!("unix:path={}/mock-bus", tmp.path().display()),
    );
    let code = agy_switch_cli::switching::runner::run_managed_agy(
        &repo,
        &FileSessionBackend,
        &mock,
        &OAuthEndpoints::default(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        None,
        true, // explicit_file_backend = true
        &[fake_agy.to_string_lossy().into_owned()],
        now,
    )
    .await
    .unwrap();
    assert_eq!(code, 0);

    // Spawned `agy` MUST see `ya29.BRAND_NEW_ACCESS_TOKEN` on disk AND sanitized DBUS_SESSION_BUS_ADDRESS!
    let slot_seen = fs::read_to_string(trace_dir.join("slot_seen.json")).unwrap();
    assert!(
        slot_seen.contains("ya29.BRAND_NEW_ACCESS_TOKEN"),
        "Slot was not updated with fresh access_token when refresh_token stayed unchanged: {slot_seen}"
    );
    let dbus_seen = fs::read_to_string(trace_dir.join("dbus_env.txt")).unwrap();
    assert_eq!(dbus_seen, "unix:path=/dev/null");
}

#[tokio::test]
async fn daemon_concurrent_chunk_budget_zombie_proc_ignore_and_cli_env_policy_overlay() {
    use agy_switch_cli::switching::daemon::{resolve_effective_daemon_policy, DaemonPolicyOverlay};

    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc_zombie");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(fake_proc.join("8888")).unwrap();

    // Seed a ZOMBIE (`Z`) unmanaged `agy` process in `/proc/8888` -> MUST NOT block runtime detection!
    fs::write(
        fake_proc.join("8888/stat"),
        "8888 (agy) Z 1 8888 8888 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 333444 0 0",
    )
    .unwrap();
    fs::write(fake_proc.join("8888/comm"), "agy\n").unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let now = 1_800_000_000i64;
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;

    let make_stale_cand = |id: &str| -> AccountRecord {
        AccountRecord::new(
            id.into(),
            format!("{id}@example.invalid"),
            TokenRecord {
                access_token: format!("ya29.{id}"),
                refresh_token: format!("1//RT_{id}"),
                expires_in: 7200,
                expiry_timestamp: now + 7200,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        )
    };

    let mut src = make_stale_cand("src");
    src.quota = Some(build_quota(
        now,
        Some("Google AI Pro"),
        0.15, // 15% > policy.json's 10%, but <= CLI overlay's 20%!
        0.15,
        Some(0.15),
        "2099-01-01T00:00:00Z",
    ));
    let c1 = make_stale_cand("c1");
    let c2 = make_stale_cand("c2");
    let c3 = make_stale_cand("c3");
    let c4 = make_stale_cand("c4");
    let c5 = make_stale_cand("c5");

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

    // Verify `CLI > env > policy.json` priority WITHOUT mutating `policy.json`!
    let reserve_env = ScopedEnvVar::set("AGY_SWITCH_CLI_RESERVE", "18");
    let cli_overlay = DaemonPolicyOverlay {
        reserve_percentage: Some(20), // CLI 20% overrides env 18% and policy.json 10%!
        ..DaemonPolicyOverlay::default()
    };
    let (eff, _) = resolve_effective_daemon_policy(&repo, &cli_overlay).unwrap();
    assert_eq!(eff.reserve_percentage, 20);
    drop(reserve_env);
    assert_eq!(repo.read_policy().unwrap().reserve_percentage, 10);

    // Mock CloudCode: c1 returns 20% (< 50%), c2 returns 85% (>= 50%), c3 returns 90%,
    // and c4/c5 MUST NEVER BE QUERIED because chunk 1 (`c1..=c3`) already found `c2`!
    let queried_tokens = Arc::new(Mutex::new(Vec::<String>::new()));
    let qt = queried_tokens.clone();
    let mock = MockTransport::from_handler(move |req| {
        let auth = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if req.url.ends_with(":fetchAvailableModels") {
            qt.lock().unwrap().push(auth.clone());
            let frac = if auth.contains("c1") { 0.20 } else { 0.85 };
            return Ok(MockTransport::json_response(
                200,
                serde_json::json!({
                    "models": {
                        "gemini-3.8-flash": {
                            "quotaInfo": {"remainingFraction": frac, "resetTime": "2099-01-01T00:00:00Z"}
                        }
                    }
                }),
            ));
        }
        if req.url.ends_with(":loadCodeAssist") {
            return Ok(MockTransport::json_response(
                200,
                serde_json::json!({"paidTier": {"id": "pro", "name": "Google AI Pro"}}),
            ));
        }
        if req.url.ends_with(":retrieveUserQuotaSummary") {
            let frac = if auth.contains("c1") { 0.20 } else { 0.85 };
            return Ok(MockTransport::json_response(
                200,
                serde_json::json!({
                    "groups": [{
                        "displayName": "Gemini Models",
                        "buckets": [
                            {"bucketId": "gemini-5h", "window": "5h", "remainingFraction": frac, "resetTime": "2099-01-01T05:00:00Z"},
                            {"bucketId": "gemini-weekly", "window": "weekly", "remainingFraction": frac, "resetTime": "2099-01-07T00:00:00Z"}
                        ]
                    }]
                }),
            ));
        }
        panic!("unexpected URL {}", req.url);
    });

    let mut engine = DaemonEngine::new();
    let overrides = DaemonConfigOverrides {
        cooldown_secs: 60,
        policy_overlay: cli_overlay,
        ..DaemonConfigOverrides::default()
    };
    let outcome = engine
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now,
        )
        .await
        .unwrap();

    // Zombie PID 8888 did NOT block, CLI reserve=20% triggered switch from 15% `src` to `c2`,
    // and chunk 2 (`c4`, `c5`) was NEVER queried!
    assert_eq!(
        outcome,
        TickStageOutcome::CommittedSwitch {
            source_id: "src".into(),
            target_id: "c2".into()
        }
    );
    let seen = queried_tokens.lock().unwrap().clone();
    assert!(!seen.iter().any(|h| h.contains("c4") || h.contains("c5")));

    // Verify restarted DaemonEngine STILL honors persisted `cooldown_until` (`now + 60`)!
    let mut restarted = DaemonEngine::new();
    let cool_after_restart = restarted
        .run_single_tick(
            &repo,
            &backend,
            &mock,
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "vscode/1.X.X (Antigravity/4.3.0)",
            &overrides,
            now + 20,
        )
        .await
        .unwrap();
    assert!(matches!(
        cool_after_restart,
        TickStageOutcome::InCooldown { .. }
    ));
}

#[tokio::test]
async fn daemon_cancels_on_policy_set_or_delete_and_never_reenters_on_slow_network() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc_slow");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let now = 1_800_000_000i64;
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;

    let make_acc = |id: &str, pct: f64| -> AccountRecord {
        let mut a = AccountRecord::new(
            id.into(),
            format!("{id}@example.invalid"),
            TokenRecord {
                access_token: format!("ya29.{id}"),
                refresh_token: format!("1//RT_{id}"),
                expires_in: 7200,
                expiry_timestamp: now + 7200,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        );
        a.quota = Some(build_quota(
            now,
            Some("Google AI Pro"),
            pct,
            pct,
            Some(pct),
            "2099-01-01T00:00:00Z",
        ));
        a
    };

    let acc_src = make_acc("acc-src", 0.05);
    let acc_cand1 = make_acc("acc-cand1", 0.80);
    let acc_cand2 = make_acc("acc-cand2", 0.85);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_src.clone(), true, now)?;
        tx.upsert_account(acc_cand1.clone(), false, now)?;
        tx.upsert_account(acc_cand2.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "gemini".into(),
            candidate_account_ids: vec!["acc-cand1".into(), "acc-cand2".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_src.token).unwrap())
        .unwrap();

    // 1. Concurrent `policy set` between Stage 4 and Stage 5 cancels stale pending plan!
    let mut engine = DaemonEngine::new();
    let repo_pol = repo.clone();
    engine.before_revalidate_hook = Some(Arc::new(move || {
        repo_pol
            .with_write_lock(|tx| {
                let mut pol = repo_pol.read_policy()?;
                let rev = pol.revision;
                pol.reserve_percentage = 12;
                tx.save_policy(&mut pol, Some(rev), now + 1)?;
                Ok(())
            })
            .unwrap();
    }));
    let cancel_pol = engine
        .run_single_tick(
            &repo,
            &backend,
            &MockTransport::default(),
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "vscode/1.X.X (Antigravity/4.3.0)",
            &DaemonConfigOverrides::default(),
            now + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        cancel_pol,
        TickStageOutcome::CancelledStalePlan {
            reason: "policy_revision_changed_or_disabled".into()
        }
    );

    // 2. Concurrent `accounts delete` of candidate between Stage 4 and Stage 5 cancels stale pending plan!
    let repo_del = repo.clone();
    engine.before_revalidate_hook = Some(Arc::new(move || {
        repo_del
            .with_write_lock(|tx| tx.delete_account("acc-cand1", false, now + 2))
            .unwrap();
    }));
    let cancel_del = engine
        .run_single_tick(
            &repo,
            &backend,
            &MockTransport::default(),
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "vscode/1.X.X (Antigravity/4.3.0)",
            &DaemonConfigOverrides::default(),
            now + 2,
        )
        .await
        .unwrap();
    engine.before_revalidate_hook = None;
    assert_eq!(
        cancel_del,
        TickStageOutcome::CancelledStalePlan {
            reason: "store_index_revision_changed".into()
        }
    );

    // 3. Slow network exceeding tick interval NEVER causes concurrent tick re-entrancy (`max_active == 1`)!
    repo.with_write_lock(|tx| {
        let mut s = tx.load_account_opt("acc-src")?.unwrap();
        s.quota = None; // Force network fetch in Stage 1
        tx.save_account(&s)
    })
    .unwrap();

    let in_flight_now = Arc::new(AtomicUsize::new(0));
    let peak_in_flight = Arc::new(AtomicUsize::new(0));
    let ifn = in_flight_now.clone();
    let pif = peak_in_flight.clone();

    struct SlowTrackingTransport {
        cur: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }
    impl agy_switch_cli::transport::client::HttpTransport for SlowTrackingTransport {
        fn execute<'a>(
            &'a self,
            _req: agy_switch_cli::transport::client::HttpRequest,
        ) -> agy_switch_cli::transport::client::BoxFuture<
            'a,
            Result<
                agy_switch_cli::transport::client::HttpResponse,
                agy_switch_cli::transport::client::TransportError,
            >,
        > {
            Box::pin(async move {
                let c = self.cur.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(c, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(80)).await;
                self.cur.fetch_sub(1, Ordering::SeqCst);
                Ok(MockTransport::json_response(
                    200,
                    serde_json::json!({"models": {}}),
                ))
            })
        }
    }

    let slow_tr = SlowTrackingTransport {
        cur: ifn,
        peak: pif,
    };
    let mut ticker = tokio::time::interval(Duration::from_millis(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    for step in 0..2 {
        ticker.tick().await;
        engine.refresh_backoff_until.clear();
        let _ = engine
            .run_single_tick(
                &repo,
                &backend,
                &slow_tr,
                &OAuthEndpoints::default(),
                &CloudCodeEndpoints::default(),
                &OAuthClientRegistry::parse_from_raw(None, None),
                "vscode/1.X.X (Antigravity/4.3.0)",
                &DaemonConfigOverrides::default(),
                now + 10 + step,
            )
            .await
            .unwrap();
    }
    assert_eq!(peak_in_flight.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn quota_and_quota_all_respect_policy_monitored_model_and_render_four_state_eval() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("proc");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&proc_dir).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir);

    let now = jiff::Timestamp::now().as_second();
    let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
    let repo = StoreRepository::new(paths);

    // `acc-gem` has Known Gemini quota (80%), NO Argon quota!
    let mut acc_gem = AccountRecord::new(
        "acc-gem".into(),
        "gem@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.gem".into(),
            refresh_token: "1//RT_GEM".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    acc_gem.quota = Some(build_quota(
        now,
        Some("Google AI Pro"),
        0.80,
        0.80,
        Some(0.80),
        "2099-01-01T00:00:00Z",
    ));

    // `acc-stale` has Stale quota (`last_updated` 1000s ago > 180s)
    let mut acc_stale = AccountRecord::new(
        "acc-stale".into(),
        "stale@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.stale".into(),
            refresh_token: "1//RT_STALE".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    acc_stale.quota = Some(build_quota(
        now - DEFAULT_QUOTA_MAX_AGE_SECS - 120,
        Some("Google AI Pro"),
        0.50,
        0.50,
        Some(0.50),
        "2099-01-01T00:00:00Z",
    ));

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_gem, true, now)?;
        tx.upsert_account(acc_stale, false, now)?;
        let mut pol = SwitchPolicy {
            monitored_model: "argon".into(),
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();

    let cli = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
            .args(["--data-dir", data.to_str().unwrap(), "--no-remote-version"]);
        c
    };

    // 1. With `policy.monitored_model == "argon"`, `quota` MUST evaluate Argon -> Unknown -> exit code 4!
    let out_argon = cli().arg("quota").output().unwrap();
    assert_eq!(out_argon.status.code(), Some(4));

    // `quota --all` human text output MUST show four-state `Status  : unknown (..., model=argon)` and `Status  : stale (..., model=argon)`!
    let out_all_argon = cli().args(["quota", "--all"]).output().unwrap();
    assert_eq!(out_all_argon.status.code(), Some(0));
    let txt_all = String::from_utf8_lossy(&out_all_argon.stdout);
    assert!(
        txt_all.contains("Status  : unknown (unknown_pool, model=argon)"),
        "Missing unknown status in quota --all output: {txt_all}"
    );
    assert!(
        txt_all.contains("Status  : stale (stale_quota, model=argon)"),
        "Missing stale status in quota --all output: {txt_all}"
    );
    assert!(
        !txt_all.contains("gemini-3.8-flash"),
        "Default quota output must suppress per-model dump: {txt_all}"
    );

    // 2. Switch `policy.monitored_model` to `"gemini"` -> `quota` now evaluates Gemini -> Known (80%) -> exit code 0!
    let set_gem = cli()
        .args(["policy", "set", "--model", "gemini"])
        .output()
        .unwrap();
    assert_eq!(set_gem.status.code(), Some(0));

    let out_gem = cli().arg("quota").output().unwrap();
    assert_eq!(out_gem.status.code(), Some(0));
    let txt_gem = String::from_utf8_lossy(&out_gem.stdout);
    assert!(txt_gem.contains("Status  : known (80.0% effective on gemini)"));
    assert!(!txt_gem.contains("gemini-3.8-flash"));

    // 3. Stale cached quota in human mode STILL displays the cached quota table cleanly (with `--refresh` hint),
    //    while `--json` preserves strict exit code 4 for machine callers!
    let out_stale_human = cli()
        .args(["quota", "stale@example.invalid"])
        .output()
        .unwrap();
    assert_eq!(out_stale_human.status.code(), Some(0));
    let txt_stale_human = String::from_utf8_lossy(&out_stale_human.stdout);
    assert!(txt_stale_human.contains("Account : stale@example.invalid"));
    assert!(txt_stale_human.contains("add --refresh to refresh"));

    let out_stale_json = cli()
        .args(["--json", "quota", "stale@example.invalid"])
        .output()
        .unwrap();
    assert_eq!(out_stale_json.status.code(), Some(4));

    // 4. `current` displays supported models, `accounts list --move <EMAIL> --to 1` reorders cleanly,
    //    and `policy set --all-candidates` selects all enabled accounts in list order!
    let out_current = cli().arg("current").output().unwrap();
    assert_eq!(out_current.status.code(), Some(0));
    let txt_current = String::from_utf8_lossy(&out_current.stdout);
    assert!(txt_current.contains("Supported models : 1 available (cached)"));
    assert!(txt_current.contains("gemini-3.8-flash"));

    let out_move = cli()
        .args([
            "accounts",
            "list",
            "--move",
            "stale@example.invalid",
            "--to",
            "1",
        ])
        .output()
        .unwrap();
    assert_eq!(out_move.status.code(), Some(0));
    let out_list = cli().args(["accounts", "list"]).output().unwrap();
    let txt_list = String::from_utf8_lossy(&out_list.stdout);
    assert!(txt_list
        .lines()
        .next()
        .unwrap()
        .contains("stale@example.invalid"));

    let out_all_cands = cli()
        .args(["policy", "set", "--all-candidates", "--enabled", "true"])
        .output()
        .unwrap();
    assert_eq!(out_all_cands.status.code(), Some(0));
    let pol_after = repo.read_policy().unwrap();
    assert!(pol_after.enabled);
    assert_eq!(
        pol_after.candidate_account_ids,
        vec!["acc-stale".to_string(), "acc-gem".to_string()]
    );

    // 5. CLI account selectors strictly require `<ID|EMAIL>` (rejecting positional indices like `1` or `2` with exit code 3).
    let out_q_email = cli()
        .args(["quota", "gem@example.invalid"])
        .output()
        .unwrap();
    assert_eq!(out_q_email.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out_q_email.stdout).contains("gem@example.invalid"));

    let out_q_idx_rejected = cli().args(["quota", "2"]).output().unwrap();
    assert_eq!(out_q_idx_rejected.status.code(), Some(3));

    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(proc_dir.join("1")).unwrap();
    fs::write(
        proc_dir.join("1/stat"),
        "1 (systemd) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 1000 10\n",
    )
    .unwrap();
    repo.with_write_lock(|tx| {
        for id in ["acc-stale", "acc-gem"] {
            let mut a = repo.read_account_unchecked(id).unwrap();
            a.token.oauth_client_key = None;
            tx.save_account(&a)?;
        }
        Ok(())
    })
    .unwrap();

    let out_sw_idx_rejected = cli().args(["switch", "1", "--dry-run"]).output().unwrap();
    assert_eq!(out_sw_idx_rejected.status.code(), Some(3));

    let out_sw_live = cli()
        .args(["switch", "stale@example.invalid"])
        .output()
        .unwrap();
    assert_eq!(
        out_sw_live.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out_sw_live.stderr)
    );
    assert!(String::from_utf8_lossy(&out_sw_live.stdout).contains("stale@example.invalid"));

    let out_sw_dry = cli()
        .args(["switch", "acc-gem", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(
        out_sw_dry.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out_sw_dry.stderr)
    );
    assert!(String::from_utf8_lossy(&out_sw_dry.stdout).contains("gem@example.invalid"));
}

#[tokio::test]
async fn managed_run_rejects_disabled_or_unscoped_synced_slot_and_daemon_stage5_pauses_on_corrupt_journal(
) {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let proc_dir = tmp.path().join("proc");
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&proc_dir).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir);

    let spawned_marker = tmp.path().join("should_never_exist");
    let fake_agy = bin_dir.join("agy");
    fs::write(
        &fake_agy,
        format!(
            "#!/bin/sh\ntouch \"{}\"\nexit 0\n",
            spawned_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let now = jiff::Timestamp::now().as_second();
    let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;

    // 1. Seed `acc-slot` ALREADY written into `antigravity-oauth-token` with unexpired token,
    //    then disable `acc-slot` -> BOTH `run --account acc-slot -- agy` AND `run -- agy` MUST reject!
    let acc_slot = AccountRecord::new(
        "acc-slot".into(),
        "slot@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.slot_ok".into(),
            refresh_token: "1//RT_SLOT_OK".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
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
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_slot.clone(), true, now)?;
        tx.mark_account_disabled(
            "acc-slot",
            agy_switch_cli::domain::account::DisableReasonCode::Manual,
            Some("manually disabled".into()),
            now,
        )?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_slot.token).unwrap())
        .unwrap();

    let cli = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &proc_dir)
            .args(["--data-dir", data.to_str().unwrap(), "--no-remote-version"]);
        c
    };

    for run_args in [
        vec!["run", "--account", "acc-slot", "--", "agy"],
        vec!["run", "--", "agy"],
    ] {
        let out = cli().args(&run_args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "Disabled synced slot account must be rejected on {run_args:?}: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !spawned_marker.exists(),
            "`agy` must NEVER spawn when synced slot account is disabled!"
        );
    }

    // 2. Re-enable `acc-slot`, strip `cloud-platform` from `granted_scopes` while keeping slot byte-synced ->
    //    `run -- agy` MUST fail with exit code 6 (`scope_reauth_required`) and mark `ScopeReauthRequired`!
    repo.with_write_lock(|tx| {
        let mut enabled = tx.mark_account_enabled("acc-slot")?;
        enabled.token.granted_scopes = Some(vec!["openid".into()]);
        tx.save_account(&enabled)
    })
    .unwrap();
    let out_scope = cli().args(["run", "--", "agy"]).output().unwrap();
    assert_eq!(out_scope.status.code(), Some(6));
    assert!(!spawned_marker.exists());
    assert_eq!(
        repo.read_account_unchecked("acc-slot")
            .unwrap()
            .disabled_code,
        Some(agy_switch_cli::domain::account::DisableReasonCode::ScopeReauthRequired)
    );

    // 3. Daemon Stage 5 (`Revalidate`) encountering a corrupted `switch_journal.json` transitions to `PausedOnFailure`!
    let mut acc_src = AccountRecord::new(
        "acc-dsrc".into(),
        "dsrc@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.dsrc".into(),
            refresh_token: "1//RT_DSRC".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    acc_src.quota = Some(build_quota(
        now,
        Some("Google AI Pro"),
        0.05,
        0.05,
        Some(0.05),
        "2099-01-01T00:00:00Z",
    ));
    let mut acc_dcand = AccountRecord::new(
        "acc-dcand".into(),
        "dcand@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.dcand".into(),
            refresh_token: "1//RT_DCAND".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    acc_dcand.quota = Some(build_quota(
        now,
        Some("Google AI Pro"),
        0.90,
        0.90,
        Some(0.90),
        "2099-01-01T00:00:00Z",
    ));
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_src.clone(), false, now)?;
        tx.upsert_account(acc_dcand.clone(), false, now)?;
        tx.commit_selected_account("acc-dsrc", now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "gemini".into(),
            candidate_account_ids: vec!["acc-dcand".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_src.token).unwrap())
        .unwrap();

    let mut engine = DaemonEngine::new();
    let jpath = paths.switch_journal_file();
    engine.before_revalidate_hook = Some(Arc::new(move || {
        ensure_private_dir(jpath.parent().unwrap()).unwrap();
        fs::write(&jpath, b"{corrupt-stage5-journal").unwrap();
    }));

    let st5 = engine
        .run_single_tick(
            &repo,
            &backend,
            &MockTransport::default(),
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "vscode/1.X.X (Antigravity/4.3.0)",
            &DaemonConfigOverrides::default(),
            now + 5,
        )
        .await
        .unwrap();
    assert!(
        matches!(st5, TickStageOutcome::PausedOnFailure { .. }),
        "Expected PausedOnFailure on Stage 5 corrupt journal, got {st5:?}"
    );
    assert!(
        read_daemon_state_readonly(&paths)
            .unwrap()
            .paused_on_failure
    );
}

#[tokio::test]
async fn synthetic_immediate_mode_overwrites_slot_with_running_agy_fails_closed_on_unverified_proc_and_rejects_stop(
) {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let fake_proc = tmp.path().join("proc_imm");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let now = 1_800_100_000i64;
    let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;

    // 1. Default policy is `Immediate` + `RoundRobin` (`reserve = 5%`, `minimum = 15%`).
    let default_pol = SwitchPolicy::default();
    assert_eq!(default_pol.mode, PolicyMode::Immediate);
    assert_eq!(default_pol.strategy, PolicyStrategy::RoundRobin);
    assert_eq!(default_pol.reserve_percentage, 5);
    assert_eq!(default_pol.candidate_min_percentage, 15);

    let make_acc = |id: &str, pct: f64| -> AccountRecord {
        let mut a = AccountRecord::new(
            id.into(),
            format!("{id}@example.invalid"),
            TokenRecord {
                access_token: format!("ya29.{id}"),
                refresh_token: format!("1//RT_{id}"),
                expires_in: 7200,
                expiry_timestamp: now + 7200,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        );
        a.quota = Some(build_quota(
            now,
            Some("Google AI Pro"),
            pct,
            pct,
            Some(pct),
            "2099-01-01T00:00:00Z",
        ));
        a
    };

    let acc1 = make_acc("acc-imm-1", 0.05);
    let acc2 = make_acc("acc-imm-2", 0.80);
    let acc3 = make_acc("acc-imm-3", 0.90);

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc1.clone(), true, now)?;
        tx.upsert_account(acc2.clone(), false, now)?;
        tx.upsert_account(acc3.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            monitored_model: "gemini".into(),
            candidate_account_ids: vec!["acc-imm-1".into(), "acc-imm-2".into(), "acc-imm-3".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc1.token).unwrap())
        .unwrap();

    // 2. Simulate an active `agy` process in `/proc`: under default `PolicyMode::Immediate`,
    //    daemon does NOT kill the process and IMMEDIATELY updates the credential slot to `acc-imm-2`!
    let my_uid = unsafe { libc::geteuid() };
    let _ = my_uid; // fake_proc dir entry created by current test process already has current UID!
    fs::create_dir_all(fake_proc.join("6101")).unwrap();
    fs::write(
        fake_proc.join("6101/stat"),
        "6101 (agy) S 1 6101 6101 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 888111 1000 10",
    )
    .unwrap();
    fs::write(fake_proc.join("6101/comm"), "agy\n").unwrap();

    let mut engine = DaemonEngine::new();
    let overrides = DaemonConfigOverrides {
        cooldown_secs: 10,
        ..DaemonConfigOverrides::default()
    };
    let reg = OAuthClientRegistry::parse_from_raw(None, None);

    let t1 = engine
        .run_single_tick(
            &repo,
            &backend,
            &MockTransport::default(),
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &reg,
            "antigravity/hub/1.5.7 (os_type=linux; arch=amd64)",
            &overrides,
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        t1,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-imm-1".into(),
            target_id: "acc-imm-2".into(),
        }
    );
    let slot_after_t1 = fs::read_to_string(&paths.active_slot_file).unwrap();
    assert!(slot_after_t1.contains("1//RT_acc-imm-2"));

    // 3. Default `RoundRobin` strategy: after cooldown, if `acc-imm-2` drops to 5% and `acc-imm-1` recovers to 95%,
    //    next tick rotates forward to `acc-imm-3` rather than jumping back to #1 (`acc-imm-1`)!
    repo.with_write_lock(|tx| {
        let mut a1 = tx.load_account_opt("acc-imm-1")?.unwrap();
        a1.quota = Some(build_quota(
            now + 20,
            Some("Google AI Pro"),
            0.95,
            0.95,
            Some(0.95),
            "2099-01-01T00:00:00Z",
        ));
        tx.save_account(&a1)?;
        let mut a2 = tx.load_account_opt("acc-imm-2")?.unwrap();
        a2.quota = Some(build_quota(
            now + 20,
            Some("Google AI Pro"),
            0.05,
            0.05,
            Some(0.05),
            "2099-01-01T00:00:00Z",
        ));
        tx.save_account(&a2)
    })
    .unwrap();

    let t2 = engine
        .run_single_tick(
            &repo,
            &backend,
            &MockTransport::default(),
            &OAuthEndpoints::default(),
            &CloudCodeEndpoints::default(),
            &reg,
            "antigravity/hub/1.5.7 (os_type=linux; arch=amd64)",
            &overrides,
            now + 20,
        )
        .await
        .unwrap();
    assert_eq!(
        t2,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-imm-2".into(),
            target_id: "acc-imm-3".into(),
        }
    );

    // 4. Fail-closed on `RuntimeState::Unverified` even in `PolicyMode::Immediate` (both Stage 4 AND Stage 5)!
    repo.with_write_lock(|tx| {
        let mut a3 = tx.load_account_opt("acc-imm-3")?.unwrap();
        a3.quota = Some(build_quota(
            now + 40,
            Some("Google AI Pro"),
            0.05,
            0.05,
            Some(0.05),
            "2099-01-01T00:00:00Z",
        ));
        tx.save_account(&a3)
    })
    .unwrap();

    // 4a: Stage 4 `/proc` missing -> `UncertainHold` without blind-writing slot!
    let missing_proc = tmp.path().join("nonexistent_proc_dir");
    {
        let _unver_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &missing_proc);
        let t_unver_s4 = engine
            .run_single_tick(
                &repo,
                &backend,
                &MockTransport::default(),
                &OAuthEndpoints::default(),
                &CloudCodeEndpoints::default(),
                &reg,
                "antigravity/hub/1.5.7 (os_type=linux; arch=amd64)",
                &overrides,
                now + 40,
            )
            .await
            .unwrap();
        assert!(
            matches!(t_unver_s4, TickStageOutcome::UncertainHold { ref reason } if reason.contains("process_state_unverified")),
            "Immediate mode must fail closed on Stage 4 Unverified /proc, got {t_unver_s4:?}"
        );
    }
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_acc-imm-3"));

    // 4b: Stage 4 sees readable `/proc`, then `/proc` becomes unreadable right before Stage 5 `Revalidate`!
    let proc_s5 = tmp.path().join("proc_stage5_race");
    fs::create_dir_all(&proc_s5).unwrap();
    {
        let _s5_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &proc_s5);
        let proc_s5_hook = proc_s5.clone();
        engine.before_revalidate_hook = Some(Arc::new(move || {
            fs::remove_dir_all(&proc_s5_hook).unwrap();
        }));
        let t_unver_s5 = engine
            .run_single_tick(
                &repo,
                &backend,
                &MockTransport::default(),
                &OAuthEndpoints::default(),
                &CloudCodeEndpoints::default(),
                &reg,
                "antigravity/hub/1.5.7 (os_type=linux; arch=amd64)",
                &overrides,
                now + 41,
            )
            .await
            .unwrap();
        engine.before_revalidate_hook = None;
        assert!(
            matches!(t_unver_s5, TickStageOutcome::UncertainHold { ref reason } if reason.contains("process_state_unverified")),
            "Immediate mode must fail closed on Stage 5 Unverified /proc, got {t_unver_s5:?}"
        );
    }
    assert_eq!(
        read_daemon_state_readonly(&paths)
            .unwrap()
            .consecutive_commit_failures,
        0
    );
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_acc-imm-3"));

    // 5. CLI & env & JSON completely reject removed `stop` mode!
    let cli = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc)
            .args(["--data-dir", data.to_str().unwrap(), "--no-remote-version"]);
        c
    };

    let bad_cli_mode = cli()
        .args(["policy", "set", "--mode", "stop"])
        .output()
        .unwrap();
    assert_eq!(bad_cli_mode.status.code(), Some(2));
    let bad_stderr = String::from_utf8_lossy(&bad_cli_mode.stderr);
    assert!(bad_stderr.contains("immediate") && bad_stderr.contains("wait"));
    assert!(!bad_stderr.contains("possible values: stop"));

    let bad_daemon_flag = cli()
        .args(["daemon", "--once", "--mode", "stop"])
        .output()
        .unwrap();
    assert_eq!(bad_daemon_flag.status.code(), Some(2));

    let bad_daemon_env = cli()
        .env("AGY_SWITCH_CLI_MODE", "stop")
        .args(["daemon", "--once"])
        .output()
        .unwrap();
    assert_eq!(bad_daemon_env.status.code(), Some(2));

    let ok_set_wait = cli()
        .args(["policy", "set", "--mode", "wait"])
        .output()
        .unwrap();
    assert_eq!(ok_set_wait.status.code(), Some(0));
    let ok_set_imm = cli()
        .args(["policy", "set", "--mode", "immediate"])
        .output()
        .unwrap();
    assert_eq!(ok_set_imm.status.code(), Some(0));

    // Hand-written `policy.json` with `"mode": "stop"` fails closed with exit 1!
    fs::write(
        paths.policy_file(),
        r#"{"schema_version":1,"revision":9,"enabled":false,"mode":"stop","strategy":"round_robin","reserve_percentage":10,"candidate_min_percentage":30,"monitored_model":"all","candidate_account_ids":[],"updated_at":100}"#,
    )
    .unwrap();
    let bad_disk_pol = cli().args(["policy", "show"]).output().unwrap();
    assert_eq!(bad_disk_pol.status.code(), Some(1));
}
