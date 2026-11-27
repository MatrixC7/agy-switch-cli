use agy_switch_cli::domain::account::AccountRecord;
use agy_switch_cli::domain::policy::{PolicyMode, PolicyStrategy, SwitchPolicy};
use agy_switch_cli::domain::quota::{
    evaluate_account_quota, evaluate_quota_observation, ModelQuota, PrimaryModelQuota, QuotaBucket,
    QuotaEval, QuotaGroup, QuotaObservation, QuotaSourceEnv, DEFAULT_QUOTA_MAX_AGE_SECS,
};
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::oauth::registry::OAuthClientRegistry;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::quota::official_cli::{
    OfficialCliQuotaError, OfficialCliQuotaRunner, OfficialCliUsageOutcome,
};
use agy_switch_cli::session::backend::{CredentialBackend, FileSessionBackend};
use agy_switch_cli::session::payload::serialize_session_payload;
use agy_switch_cli::session::process::ProcessLease;
use agy_switch_cli::store::fs_atomic::ensure_private_dir;
use agy_switch_cli::store::repository::StoreRepository;
use agy_switch_cli::switching::daemon::{
    read_daemon_state_readonly, DaemonConfigOverrides, DaemonEngine, TickStageOutcome,
};
use agy_switch_cli::switching::executor::{execute_switch, SwitchOptions};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

type SlotUsageFn = dyn Fn(&HeadlessPaths, bool, &str) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError>
    + Send
    + Sync;

struct SlotQuotaRunner {
    handler: Arc<SlotUsageFn>,
    probed_slots: Arc<Mutex<Vec<String>>>,
    delay: Duration,
}

impl SlotQuotaRunner {
    fn from_handler<F>(f: F) -> Self
    where
        F: Fn(&HeadlessPaths, bool, &str) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            handler: Arc::new(f),
            probed_slots: Arc::new(Mutex::new(Vec::new())),
            delay: Duration::ZERO,
        }
    }

    fn constant_pct(pct: f64) -> Self {
        Self::from_handler(move |_, _, _| Ok(quota_outcome_for_frac(pct, pct)))
    }

    fn probed_slots(&self) -> Vec<String> {
        self.probed_slots.lock().unwrap().clone()
    }
}

impl OfficialCliQuotaRunner for SlotQuotaRunner {
    fn query_active_usage<'a>(
        &'a self,
        paths: &'a HeadlessPaths,
        explicit_file_backend: bool,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<OfficialCliUsageOutcome, OfficialCliQuotaError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let slot_text = fs::read_to_string(&paths.active_slot_file).unwrap_or_default();
            self.probed_slots.lock().unwrap().push(slot_text.clone());
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            (self.handler)(paths, explicit_file_backend, &slot_text)
        })
    }
}

fn quota_outcome_for_frac(short_5h: f64, weekly: f64) -> OfficialCliUsageOutcome {
    OfficialCliUsageOutcome::Quota {
        description: Some("Usage summary".into()),
        groups: vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: Some("Models within this group: gemini-3.1-pro, gemini-3-flash".into()),
            buckets: vec![
                QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: short_5h,
                    remaining_fraction_known: Some(true),
                    reset_time: if short_5h >= 1.0 {
                        String::new()
                    } else {
                        "2099-01-01T05:00:00Z".into()
                    },
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: weekly,
                    remaining_fraction_known: Some(true),
                    reset_time: if weekly >= 1.0 {
                        String::new()
                    } else {
                        "2099-01-07T00:00:00Z".into()
                    },
                    display_name: None,
                    description: None,
                },
            ],
        }],
    }
}

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
        step_buffer_delay: Duration::ZERO,
        ..DaemonConfigOverrides::default()
    };
    let runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-a") {
            Ok(quota_outcome_for_frac(0.05, 0.05))
        } else {
            Ok(quota_outcome_for_frac(0.85, 0.85))
        }
    });
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
        .run_single_tick(&repo, &backend, &runner, &reg, &overrides, now)
        .await
        .unwrap();
    assert_eq!(
        out_blocked,
        TickStageOutcome::BlockedByActiveProcess {
            target_id: "acc-b".into()
        }
    );
    // Request budget: cached source quota was ultra-fresh low & Wait blocked before probing candidates -> ZERO probes!
    assert_eq!(runner.probed_slots().len(), 0);

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
            execute_switch(
                &r,
                &FileSessionBackend,
                &OAuthClientRegistry::parse_from_raw(None, None),
                "acc-c",
                &SwitchOptions {
                    dry_run: false,
                    allow_running: false,
                },
                now + 2,
            )
            .unwrap();
        })
        .join()
        .unwrap();
    }));

    let out_cancelled = engine
        .run_single_tick(&repo, &backend, &runner, &reg, &overrides, now + 3)
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

    // Case 3: Switch back to low `acc-a`, run clean tick -> Step-and-Verify switches to `acc-b`, probes `acc-b`, and enters Cooldown!
    execute_switch(
        &repo,
        &backend,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now + 4,
    )
    .unwrap();

    let out_committed = engine
        .run_single_tick(&repo, &backend, &runner, &reg, &overrides, now + 5)
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
        .run_single_tick(&repo, &backend, &runner, &reg, &overrides, now + 15)
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
        .run_single_tick(&repo, &backend, &runner, &reg, &overrides, now + 40)
        .await
        .unwrap();
    assert!(matches!(out_hold, TickStageOutcome::UncertainHold { .. }));

    // Case 5: 3 consecutive commit failures trigger persistent `PausedOnFailure` across restarts!
    execute_switch(
        &repo,
        &backend,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: false,
        },
        now + 41,
    )
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

    // Make slot dir read-only (0500) during commit so all 3 commits fail while source quota stays ultra-fresh low!
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o500)).unwrap();
    for step in 0..3 {
        let res = engine
            .run_single_tick(&repo, &backend, &runner, &reg, &overrides, now + 50 + step)
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
        .run_single_tick(&repo, &backend, &runner, &reg, &overrides, now + 60)
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
        .args(["--data-dir", data.to_str().unwrap(), "daemon", "--once"])
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

    // Under v1.2.7 Option 1B, `run` is strictly offline (zero `/token` HTTP calls), keeps the
    // synced slot untouched for official `agy` to refresh lazily on launch, AND masks D-Bus when
    // `--backend file` is explicitly requested!
    let _dbus_env = ScopedEnvVar::set(
        "DBUS_SESSION_BUS_ADDRESS",
        format!("unix:path={}/mock-bus", tmp.path().display()),
    );
    let code = agy_switch_cli::switching::runner::run_managed_agy(
        &repo,
        &FileSessionBackend,
        &OAuthClientRegistry::parse_from_raw(None, None),
        None,
        true, // explicit_file_backend = true
        &[fake_agy.to_string_lossy().into_owned()],
        now,
    )
    .await
    .unwrap();
    assert_eq!(code, 0);

    // Spawned `agy` sees the synced account slot AND sanitized DBUS_SESSION_BUS_ADDRESS!
    let slot_seen = fs::read_to_string(trace_dir.join("slot_seen.json")).unwrap();
    assert!(
        slot_seen.contains("1//UNCHANGED_REFRESH_TOKEN"),
        "Slot must preserve synced account credential offline: {slot_seen}"
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

    // Step-and-Verify official CLI runner: c1 returns 20% (< 50%), c2 returns 85% (>= 50%),
    // and c3/c4/c5 MUST NEVER BE QUERIED because Step-and-Verify lands immediately on c2!
    let runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        let frac = if slot.contains("1//RT_c1") {
            0.20
        } else if slot.contains("1//RT_src") {
            0.15
        } else {
            0.85
        };
        Ok(quota_outcome_for_frac(frac, frac))
    });

    let mut engine = DaemonEngine::new();
    let overrides = DaemonConfigOverrides {
        cooldown_secs: 60,
        step_buffer_delay: Duration::ZERO,
        policy_overlay: cli_overlay,
        ..DaemonConfigOverrides::default()
    };
    let outcome = engine
        .run_single_tick(
            &repo,
            &backend,
            &runner,
            &OAuthClientRegistry::parse_from_raw(None, None),
            &overrides,
            now,
        )
        .await
        .unwrap();

    // Zombie PID 8888 did NOT block, CLI reserve=20% triggered Step-and-Verify from 15% `src` -> `c1` (20%) -> `c2` (85%),
    // and remaining candidates (`c3`, `c4`, `c5`) were NEVER probed!
    assert_eq!(
        outcome,
        TickStageOutcome::CommittedSwitch {
            source_id: "src".into(),
            target_id: "c2".into()
        }
    );
    let seen = runner.probed_slots();
    assert!(seen.iter().any(|s| s.contains("1//RT_c1")));
    assert!(seen.iter().any(|s| s.contains("1//RT_c2")));
    assert!(!seen
        .iter()
        .any(|s| s.contains("1//RT_c3") || s.contains("1//RT_c4") || s.contains("1//RT_c5")));

    // Verify restarted DaemonEngine STILL honors persisted `cooldown_until` (`now + 60`)!
    let mut restarted = DaemonEngine::new();
    let cool_after_restart = restarted
        .run_single_tick(
            &repo,
            &backend,
            &runner,
            &OAuthClientRegistry::parse_from_raw(None, None),
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
            &SlotQuotaRunner::constant_pct(0.85),
            &OAuthClientRegistry::parse_from_raw(None, None),
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
            &SlotQuotaRunner::constant_pct(0.85),
            &OAuthClientRegistry::parse_from_raw(None, None),
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

    // 3. Slow `agy -p "/usage"` exceeding tick interval NEVER causes concurrent tick re-entrancy (`max_active == 1`)!
    repo.with_write_lock(|tx| {
        let mut s = tx.load_account_opt("acc-src")?.unwrap();
        s.quota = None; // Force official CLI probe in Stage 1
        tx.save_account(&s)
    })
    .unwrap();

    let in_flight_now = Arc::new(AtomicUsize::new(0));
    let peak_in_flight = Arc::new(AtomicUsize::new(0));
    let ifn = in_flight_now.clone();
    let pif = peak_in_flight.clone();

    struct SlowTrackingRunner {
        cur: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }
    impl OfficialCliQuotaRunner for SlowTrackingRunner {
        fn query_active_usage<'a>(
            &'a self,
            _paths: &'a HeadlessPaths,
            _explicit_file_backend: bool,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<OfficialCliUsageOutcome, OfficialCliQuotaError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let c = self.cur.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(c, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(80)).await;
                self.cur.fetch_sub(1, Ordering::SeqCst);
                Ok(OfficialCliUsageOutcome::Quota {
                    description: None,
                    groups: Vec::new(),
                })
            })
        }
    }

    let slow_runner = SlowTrackingRunner {
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
                &slow_runner,
                &OAuthClientRegistry::parse_from_raw(None, None),
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
            .args(["--data-dir", data.to_str().unwrap()]);
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
            .args(["--data-dir", data.to_str().unwrap()]);
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
            &SlotQuotaRunner::constant_pct(0.90),
            &OAuthClientRegistry::parse_from_raw(None, None),
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

    // 1. Default policy is `Immediate` + `RoundRobin` (`reserve = 10%`, `minimum = 30%`).
    let default_pol = SwitchPolicy::default();
    assert_eq!(default_pol.mode, PolicyMode::Immediate);
    assert_eq!(default_pol.strategy, PolicyStrategy::RoundRobin);
    assert_eq!(default_pol.reserve_percentage, 10);
    assert_eq!(default_pol.candidate_min_percentage, 30);

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
        step_buffer_delay: Duration::ZERO,
        ..DaemonConfigOverrides::default()
    };
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let imm_runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-imm-1") {
            Ok(quota_outcome_for_frac(0.05, 0.05))
        } else {
            Ok(quota_outcome_for_frac(0.85, 0.85))
        }
    });

    let t1 = engine
        .run_single_tick(&repo, &backend, &imm_runner, &reg, &overrides, now)
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
    let rr_runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-imm-2") {
            Ok(quota_outcome_for_frac(0.05, 0.05))
        } else {
            Ok(quota_outcome_for_frac(0.90, 0.90))
        }
    });

    let t2 = engine
        .run_single_tick(&repo, &backend, &rr_runner, &reg, &overrides, now + 20)
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
    let unv_runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-imm-3") {
            Ok(quota_outcome_for_frac(0.05, 0.05))
        } else {
            Ok(quota_outcome_for_frac(0.90, 0.90))
        }
    });

    // 4a: Stage 4 `/proc` missing -> `UncertainHold` without blind-writing slot!
    let missing_proc = tmp.path().join("nonexistent_proc_dir");
    {
        let _unver_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &missing_proc);
        let t_unver_s4 = engine
            .run_single_tick(&repo, &backend, &unv_runner, &reg, &overrides, now + 40)
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
            .run_single_tick(&repo, &backend, &unv_runner, &reg, &overrides, now + 41)
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
            .args(["--data-dir", data.to_str().unwrap()]);
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

fn make_v122_account(
    id: &str,
    email: &str,
    pct: f64,
    quota_updated_at: i64,
    now: i64,
) -> AccountRecord {
    let mut a = AccountRecord::new(
        id.into(),
        email.into(),
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
        quota_updated_at,
        Some("Google AI Pro"),
        pct,
        pct,
        Some(pct),
        "2099-01-01T00:00:00Z",
    ));
    a
}

#[tokio::test]
async fn v122_validation_blocked_manual_switch_run_dry_run_unlock_and_daemon_triple_guard() {
    use agy_switch_cli::quota::official_cli::refresh_active_slot_quota_with_runner;
    use agy_switch_cli::store::locks::ActiveSlotLock;
    use agy_switch_cli::switching::executor::{
        execute_switch_with_slot_lock, preview_switch_dry_run,
    };

    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let fake_proc = tmp.path().join("proc");
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
    ensure_private_dir(&paths.active_slot_dir).unwrap();
    let repo = StoreRepository::new(paths.clone());
    let now = jiff::Timestamp::now().as_second();

    let acc_a = make_v122_account("acc-v122-a", "alice@example.com", 0.02, now, now);
    let mut acc_b = make_v122_account("acc-v122-b", "bob@example.com", 0.90, now, now);
    acc_b.validation_blocked = true;
    acc_b.validation_blocked_reason =
        Some("Google CloudCode returned HTTP 403 VALIDATION_REQUIRED.".into());
    let mut acc_c = make_v122_account("acc-v122-c", "charlie@example.com", 0.95, now, now);
    acc_c.disabled = true;

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 5,
            candidate_min_percentage: 15,
            monitored_model: "all".into(),
            candidate_account_ids: vec!["acc-v122-b".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();

    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    let reg = OAuthClientRegistry::load(&paths).unwrap();
    let dummy_runner = SlotQuotaRunner::constant_pct(0.90);

    // 1. `daemon` strictly rejects `validation_blocked` candidate even when active account is at 2% <= 5%.
    let mut engine = DaemonEngine::new();
    let daemon_no_cand = engine
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &dummy_runner,
            &reg,
            &DaemonConfigOverrides::default(),
            now,
        )
        .await
        .unwrap();
    assert!(
        matches!(
            daemon_no_cand,
            TickStageOutcome::NoQualifiedCandidate { .. }
        ),
        "Daemon MUST NOT select validation_blocked candidate: got {daemon_no_cand:?}"
    );

    // 2. Low-level L1 `execute_switch_with_slot_lock` (and daemon Stage 6) still strictly rejects `validation_blocked`.
    {
        let slot_lock = ActiveSlotLock::try_acquire(&paths, false).unwrap();
        let locked_err = execute_switch_with_slot_lock(
            &slot_lock,
            &repo,
            &FileSessionBackend,
            &reg,
            "acc-v122-b",
            true,
            now,
        )
        .unwrap_err();
        assert_eq!(locked_err.error_code, "account_validation_blocked");
    }

    // 3. `preview_switch_dry_run` (A12 zero-transport dry-run) allows `validation_blocked` with warning,
    //    and still rejects `disabled` accounts.
    let dry_blocked = preview_switch_dry_run(
        &repo,
        &FileSessionBackend,
        &reg,
        "acc-v122-b",
        true,
        false,
        now,
    )
    .unwrap();
    assert!(dry_blocked.dry_run);
    assert!(dry_blocked.validation_blocked);
    assert!(dry_blocked
        .validation_warning
        .as_deref()
        .is_some_and(|w| w.contains("verify-blocked") && w.contains("agy-switch-cli refresh")));

    let dry_disabled_err = preview_switch_dry_run(
        &repo,
        &FileSessionBackend,
        &reg,
        "acc-v122-c",
        true,
        false,
        now,
    )
    .unwrap_err();
    assert_eq!(
        dry_disabled_err.exit_code,
        agy_switch_cli::error::ExitCode::InvalidUsageOrAmbiguous
    );

    // 4. Manual `execute_switch` (CLI `switch` / TUI `Enter` path) switches into `acc-v122-b`
    //    while PRESERVING `validation_blocked = true` on disk.
    let manual_out = execute_switch(
        &repo,
        &FileSessionBackend,
        &reg,
        "acc-v122-b",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now,
    )
    .unwrap();
    assert!(manual_out.validation_blocked);
    assert!(manual_out.validation_warning.is_some());
    assert!(
        repo.read_account_unchecked("acc-v122-b")
            .unwrap()
            .validation_blocked,
        "Manual switch MUST NOT clear validation_blocked before user verifies in agy"
    );
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_acc-v122-b"));

    // 5. While `acc-v122-b` is selected and `validation_blocked`, `daemon` holds calmly without hijacking slot!
    let hold_out = engine
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &dummy_runner,
            &reg,
            &DaemonConfigOverrides::default(),
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        hold_out,
        TickStageOutcome::UncertainHold {
            reason: "validation_blocked".into()
        }
    );

    // 6. CLI `switch --dry-run --json` and `run` (both already-selected and explicit `--account`) succeed
    //    with clear stderr notice and keep `validation_blocked = true`.
    let fake_agy = bin_dir.join("agy");
    fs::write(&fake_agy, "#!/bin/sh\necho FAKE_AGY_STDOUT\nexit 0\n").unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

    let cli_base = || {
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
            .env("AGY_SWITCH_CLI_PROXY", "direct")
            .env("NO_PROXY", "*")
            .args(["--data-dir", data.to_str().unwrap(), "--backend", "file"]);
        c
    };

    let dry_cli = cli_base()
        .args(["--json", "switch", "acc-v122-b", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(dry_cli.status.code(), Some(0));
    let dry_j: serde_json::Value = serde_json::from_slice(&dry_cli.stdout).unwrap();
    assert_eq!(dry_j["switch"]["validation_blocked"], true);
    assert!(dry_j["switch"]["validation_warning"]
        .as_str()
        .unwrap()
        .contains("verify-blocked"));

    let run_selected = cli_base()
        .args(["run", "--", fake_agy.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(run_selected.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&run_selected.stdout).trim(),
        "FAKE_AGY_STDOUT"
    );
    assert!(String::from_utf8_lossy(&run_selected.stderr).contains("verify-blocked"));

    // Switch back to healthy `acc-v122-a`, then `run --account acc-v122-b` triggers switch + stderr notice.
    let sw_back = cli_base().args(["switch", "acc-v122-a"]).output().unwrap();
    assert_eq!(sw_back.status.code(), Some(0));
    assert!(sw_back.stderr.is_empty());

    let run_explicit = cli_base()
        .args([
            "run",
            "--account",
            "acc-v122-b",
            "--",
            fake_agy.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(run_explicit.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&run_explicit.stdout).trim(),
        "FAKE_AGY_STDOUT"
    );
    assert!(String::from_utf8_lossy(&run_explicit.stderr).contains("agy-switch-cli refresh"));
    assert!(
        repo.read_account_unchecked("acc-v122-b")
            .unwrap()
            .validation_blocked
    );

    // 7. After user completes Google verification in `agy`, clean official CLI `/usage` auto-clears `validation_blocked`!
    let ok_runner = SlotQuotaRunner::constant_pct(0.90);
    let unlocked = refresh_active_slot_quota_with_runner(
        &repo,
        &FileSessionBackend,
        &ok_runner,
        true,
        Some("acc-v122-b"),
        now + 5,
    )
    .await
    .unwrap()
    .account;
    assert!(!unlocked.validation_blocked);
}

#[tokio::test]
async fn v122_daemon_once_live_refresh_180s_max_age_and_human_json_output() {
    use agy_switch_cli::switching::daemon::{
        effective_source_quota_max_age_secs, CANDIDATE_REFRESH_BACKOFF_SECS,
        DEFAULT_DAEMON_COOLDOWN_SECS, DEFAULT_DAEMON_INTERVAL_SECS,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    assert_eq!(DEFAULT_DAEMON_INTERVAL_SECS, 900);
    assert_eq!(CANDIDATE_REFRESH_BACKOFF_SECS, 900);
    assert_eq!(DEFAULT_DAEMON_COOLDOWN_SECS, 3600);
    assert_eq!(effective_source_quota_max_age_secs(180), 144);
    assert_eq!(effective_source_quota_max_age_secs(300), 240);
    assert_eq!(effective_source_quota_max_age_secs(900), 720);
    assert_eq!(effective_source_quota_max_age_secs(3600), 2880);
    assert_eq!(effective_source_quota_max_age_secs(7200), 3600);
    assert_eq!(effective_source_quota_max_age_secs(1), 4);

    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let fake_proc = tmp.path().join("proc");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
    ensure_private_dir(&paths.active_slot_dir).unwrap();
    let repo = StoreRepository::new(paths.clone());
    let now = jiff::Timestamp::now().as_second();

    // Seed `acc-src` with a 41-minute-old cached quota of 26.7% (> 5% reserve, < 3600s old),
    // reproducing the exact live issue where `daemon --once` previously skipped refreshing!
    let acc_src = make_v122_account("acc-src", "alice@example.com", 0.267, now - 2453, now);
    let acc_dst = make_v122_account("acc-dst", "bob@example.com", 1.0, now - 10, now);
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_src.clone(), true, now)?;
        tx.upsert_account(acc_dst.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::RoundRobin,
            reserve_percentage: 5,
            candidate_min_percentage: 15,
            monitored_model: "all".into(),
            candidate_account_ids: vec!["acc-src".into(), "acc-dst".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    fs::create_dir_all(&paths.active_slot_dir).unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_src.token).unwrap())
        .unwrap();

    let reg = OAuthClientRegistry::load(&paths).unwrap();

    // 1. When `--once` attempts live refresh and official `agy` fails, MUST fail closed into `UncertainHold`
    //    instead of trusting the 41-minute-old 26.7% cache!
    let failing_runner = SlotQuotaRunner::from_handler(|_, _, _| {
        Err(OfficialCliQuotaError::CommandFailed(
            "simulated offline".into(),
        ))
    });
    let mut engine = DaemonEngine::new();
    let (_tx, mut dummy_rx) = tokio::sync::watch::channel(false);
    let fail_report = engine
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &failing_runner,
            &reg,
            &DaemonConfigOverrides {
                once: true,
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert!(matches!(
        fail_report.outcome,
        TickStageOutcome::UncertainHold { ref reason } if reason.starts_with("source_refresh_failed:")
    ));
    assert!(!fail_report.source_refreshed);
    assert!(fail_report.format_human_line().contains("daemon: hold"));

    // 2. Fresh engine with live runner returning 0.2% for `acc-src` and 90% for `acc-dst`:
    //    `daemon --once` MUST refresh live, Step-and-Verify switch from `acc-src` to `acc-dst`,
    //    and format a clear switched report!
    let live_hits = Arc::new(AtomicUsize::new(0));
    let live_hits_c = live_hits.clone();
    let zero_runner = SlotQuotaRunner::from_handler(move |_, _, slot| {
        live_hits_c.fetch_add(1, Ordering::SeqCst);
        if slot.contains("1//RT_acc-src") {
            Ok(quota_outcome_for_frac(0.002, 0.30))
        } else {
            Ok(quota_outcome_for_frac(0.90, 0.90))
        }
    });
    let mut engine2 = DaemonEngine::new();
    let sw_report = engine2
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &zero_runner,
            &reg,
            &DaemonConfigOverrides {
                once: true,
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(live_hits.load(Ordering::SeqCst), 2); // 1 source probe + 1 Step-and-Verify candidate probe!
    assert!(sw_report.source_refreshed);
    assert_eq!(
        sw_report.outcome,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-src".into(),
            target_id: "acc-dst".into(),
        }
    );
    let sw_line = sw_report.format_human_line();
    assert!(
        sw_line.contains("daemon: switched")
            && sw_line.contains("acc-src")
            && sw_line.contains("acc-dst"),
        "unexpected human line: {sw_line}"
    );

    // 3. G1: Continuous mode (`once = false`) explicitly refreshes eligible active accounts on
    //    scheduled wake-ups regardless of slow prior tick `last_updated` skew:
    //    - Default `interval = 300s`: prior tick completed at `T+20s` (writing `26.7%`), next
    //      negative-jitter wake-up at `T+270s` (`age = 250s`) or `T+162s` MUST still refresh live!
    //    - Short `interval = 5s`: prior tick at `T`, next negative-jitter wake-up at `T+4s`
    //      (`age = 4s == effective_source_quota_max_age_secs(5)`) MUST still refresh live!
    //    - Active `refresh_backoff_until` still suppresses redundant probes.
    let cont_hits = Arc::new(AtomicUsize::new(0));
    let cont_hits_c = cont_hits.clone();
    let ok_runner = SlotQuotaRunner::from_handler(move |_, _, _| {
        cont_hits_c.fetch_add(1, Ordering::SeqCst);
        Ok(quota_outcome_for_frac(0.376, 0.90))
    });
    // Seed `acc-dst` as if Tick 1 finished slowly at `now + 20` with `26.7%` and clear cooldown.
    repo.with_write_lock(|tx| {
        agy_switch_cli::switching::daemon::clear_daemon_pause_in_tx(tx.paths(), now)?;
        let mut ds = read_daemon_state_readonly(tx.paths())?;
        ds.cooldown_until = 0;
        agy_switch_cli::switching::daemon::save_daemon_state_in_tx(tx.paths(), &ds)?;
        let mut dst = tx.load_account_opt("acc-dst")?.unwrap();
        dst.quota = Some(build_quota(
            now + 20,
            Some("Google AI Pro"),
            0.90,
            0.267,
            Some(0.267),
            "2099-01-01T05:00:00Z",
        ));
        tx.save_account(&dst)
    })
    .unwrap();

    let mut engine3 = DaemonEngine::new();
    let live_skew_rep = engine3
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &ok_runner,
            &reg,
            &DaemonConfigOverrides::default(),
            now + 162,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(live_skew_rep.outcome, TickStageOutcome::IdleSufficientQuota);
    assert!(live_skew_rep.source_refreshed);
    assert_eq!(cont_hits.load(Ordering::SeqCst), 1);
    assert!((live_skew_rep.source_remaining_percentage.unwrap() - 37.6).abs() < 0.05);
    assert!(live_skew_rep.format_human_line().contains("refreshed live"));

    // Short `interval = 5s`: prior update at `now + 162`, next tick at `now + 166` (`age = 4s == 4s` TTL):
    // MUST still refresh live!
    let short_interval_rep = engine3
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &ok_runner,
            &reg,
            &DaemonConfigOverrides {
                interval_secs: 5,
                ..DaemonConfigOverrides::default()
            },
            now + 166,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(
        short_interval_rep.outcome,
        TickStageOutcome::IdleSufficientQuota
    );
    assert!(short_interval_rep.source_refreshed);
    assert_eq!(cont_hits.load(Ordering::SeqCst), 2);
    assert!(short_interval_rep
        .format_human_line()
        .contains("refreshed live"));

    // Active refresh backoff still skips probes cleanly and reports cached status!
    engine3
        .refresh_backoff_until
        .insert("acc-dst".into(), now + 500);
    let backoff_rep = engine3
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &ok_runner,
            &reg,
            &DaemonConfigOverrides::default(),
            now + 170,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(backoff_rep.outcome, TickStageOutcome::IdleSufficientQuota);
    assert!(!backoff_rep.source_refreshed);
    assert_eq!(cont_hits.load(Ordering::SeqCst), 2);
    assert!(backoff_rep.format_human_line().contains("cached"));

    // 4. Real CLI binary `daemon --once` prints human status line, and `daemon --once --json` emits J1 envelope!
    let mut pol = repo.read_policy().unwrap();
    pol.enabled = false;
    repo.with_write_lock(|tx| tx.save_policy(&mut pol, None, now + 200))
        .unwrap();
    let cli_human = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc)
        .args([
            "--data-dir",
            data.to_str().unwrap(),
            "--backend",
            "file",
            "daemon",
            "--once",
        ])
        .output()
        .unwrap();
    assert_eq!(cli_human.status.code(), Some(0));
    assert!(cli_human.stderr.is_empty());
    let human_out = String::from_utf8_lossy(&cli_human.stdout);
    assert!(
        human_out.contains("daemon: disabled"),
        "expected human status line, got: {human_out}"
    );

    let cli_json = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", run_dir.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc)
        .args([
            "--data-dir",
            data.to_str().unwrap(),
            "--backend",
            "file",
            "--json",
            "daemon",
            "--once",
        ])
        .output()
        .unwrap();
    assert_eq!(cli_json.status.code(), Some(0));
    assert!(cli_json.stderr.is_empty());
    let j: serde_json::Value = serde_json::from_slice(&cli_json.stdout).unwrap();
    assert_eq!(j["schema_version"], 1);
    assert_eq!(j["ok"], true);
    assert_eq!(j["daemon"]["phase"], "disabled");
    assert_eq!(j["daemon"]["outcome"], "disabled");
}

#[tokio::test]
async fn v122_round2_g2_summary_503_timeout_and_g3_path_redaction() {
    use agy_switch_cli::switching::daemon::{
        save_daemon_state_in_tx, DaemonPersistentState, DaemonTickReport,
    };
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let _proc_lock = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let run_dir = tmp.path().join("run");
    let fake_proc = tmp.path().join("proc");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&cache).unwrap();
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let now = 1_800_260_000i64;
    let paths = HeadlessPaths::with_explicit(home.clone(), data.clone(), cache.clone());
    let repo = StoreRepository::new(paths.clone());

    let mut acc_src = make_v122_account("acc-g2-src", "alice@example.com", 0.267, now - 3, now);
    acc_src.quota = Some(build_quota(
        now - 3,
        Some("Google AI Pro"),
        0.70,
        0.267,
        Some(0.267),
        "2099-01-01T05:00:00Z",
    ));
    let mut acc_dst = make_v122_account("acc-g2-dst", "bob@example.com", 0.90, now - 3, now);
    acc_dst.quota = Some(build_quota(
        now - 3,
        Some("Google AI Pro"),
        0.90,
        0.90,
        Some(0.90),
        "2099-01-01T05:00:00Z",
    ));

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_src.clone(), true, now)?;
        tx.upsert_account(acc_dst.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::RoundRobin,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "all".into(),
            candidate_account_ids: vec!["acc-g2-src".into(), "acc-g2-dst".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    fs::create_dir_all(&paths.active_slot_dir).unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_src.token).unwrap())
        .unwrap();
    let slot_before = fs::read(&paths.active_slot_file).unwrap();
    let index_before = fs::read(paths.index_file()).unwrap();

    let reg = OAuthClientRegistry::load(&paths).unwrap();
    let (_tx, mut dummy_rx) = tokio::sync::watch::channel(false);

    // G2-a: Official CLI probe failure on `--once` -> `hold` + `source_refresh_failed: official_cli_usage_failed`,
    // `source_refreshed == false`, `source_remaining_percentage == None`, slot & index untouched.
    let err_runner = SlotQuotaRunner::from_handler(|_, _, _| {
        Err(OfficialCliQuotaError::CommandFailed("busy 503".into()))
    });
    let mut eng_503 = DaemonEngine::new();
    let rep_503 = eng_503
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &err_runner,
            &reg,
            &DaemonConfigOverrides {
                once: true,
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(rep_503.phase, "hold");
    assert_eq!(
        rep_503.reason.as_deref(),
        Some("source_refresh_failed: official_cli_usage_failed")
    );
    assert_eq!(
        rep_503.outcome,
        TickStageOutcome::UncertainHold {
            reason: "source_refresh_failed: official_cli_usage_failed".into()
        }
    );
    assert!(!rep_503.source_refreshed);
    assert!(rep_503.source_remaining_percentage.is_none());
    assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
    assert_eq!(fs::read(paths.index_file()).unwrap(), index_before);

    // G2-b: Empty groups returned by Official CLI is NOT a transport failure -> remains `unknown_pool`.
    let empty_runner = SlotQuotaRunner::from_handler(|_, _, _| {
        Ok(OfficialCliUsageOutcome::Quota {
            description: None,
            groups: Vec::new(),
        })
    });
    let mut eng_empty = DaemonEngine::new();
    let rep_empty = eng_empty
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &empty_runner,
            &reg,
            &DaemonConfigOverrides {
                once: true,
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now + 1,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(rep_empty.phase, "hold");
    assert_eq!(rep_empty.reason.as_deref(), Some("unknown_pool"));
    assert!(rep_empty.source_refreshed);

    // Restore 3s-old 26.7% cache before timeout probe.
    repo.with_write_lock(|tx| {
        let mut s = tx.load_account_opt("acc-g2-src")?.unwrap();
        s.quota = Some(build_quota(
            now,
            Some("Google AI Pro"),
            0.70,
            0.267,
            Some(0.267),
            "2099-01-01T05:00:00Z",
        ));
        tx.save_account(&s)
    })
    .unwrap();

    // G2-c: Source refresh stalls past `tick_timeout` on `--once` -> `source_refresh_failed: tick_budget_timeout`!
    struct StallRunner;
    impl OfficialCliQuotaRunner for StallRunner {
        fn query_active_usage<'a>(
            &'a self,
            _paths: &'a HeadlessPaths,
            _explicit_file_backend: bool,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<OfficialCliUsageOutcome, OfficialCliQuotaError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                unreachable!()
            })
        }
    }
    let mut eng_timeout = DaemonEngine::new();
    let rep_src_to = eng_timeout
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &StallRunner,
            &reg,
            &DaemonConfigOverrides {
                once: true,
                tick_timeout: Duration::from_millis(60),
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now + 3,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(rep_src_to.phase, "hold");
    assert_eq!(
        rep_src_to.reason.as_deref(),
        Some("source_refresh_failed: tick_budget_timeout")
    );
    assert!(!rep_src_to.source_refreshed);
    assert!(rep_src_to.source_remaining_percentage.is_none());
    assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before);
    assert_eq!(fs::read(paths.index_file()).unwrap(), index_before);

    // G2-d: Candidate Step-and-Verify stall (source already ultra-fresh low 2%, candidate probe stalls)
    // MUST restore original source cleanly AND report plain `tick_budget_timeout`, NOT `source_refresh_failed`!
    repo.with_write_lock(|tx| {
        let mut s = tx.load_account_opt("acc-g2-src")?.unwrap();
        s.quota = Some(build_quota(
            now + 5,
            Some("Google AI Pro"),
            0.02,
            0.02,
            Some(0.02),
            "2099-01-01T05:00:00Z",
        ));
        tx.save_account(&s)?;
        let mut d = tx.load_account_opt("acc-g2-dst")?.unwrap();
        d.quota = None;
        tx.save_account(&d)
    })
    .unwrap();
    let mut eng_cand_to = DaemonEngine::new();
    let rep_cand_to = eng_cand_to
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &StallRunner,
            &reg,
            &DaemonConfigOverrides {
                once: true,
                tick_timeout: Duration::from_millis(60),
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now + 5,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    assert_eq!(rep_cand_to.phase, "hold");
    assert_eq!(rep_cand_to.reason.as_deref(), Some("tick_budget_timeout"));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-g2-src")
    );

    // G3-c: Missing `/proc` (Stage 4 Unverified) MUST NOT leak filesystem path in human line or JSON!
    repo.with_write_lock(|tx| {
        let mut d = tx.load_account_opt("acc-g2-dst")?.unwrap();
        d.quota = Some(build_quota(
            now + 5,
            Some("Google AI Pro"),
            0.90,
            0.90,
            Some(0.90),
            "2099-01-01T05:00:00Z",
        ));
        tx.save_account(&d)
    })
    .unwrap();
    let missing_proc = tmp.path().join("missing-proc-g3-secret-dir");
    let rep_unver: DaemonTickReport = {
        let _unver = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &missing_proc);
        let mut eng_unver = DaemonEngine::new();
        eng_unver
            .run_single_tick_report_with_shutdown(
                &repo,
                &FileSessionBackend,
                &SlotQuotaRunner::constant_pct(0.90),
                &reg,
                &DaemonConfigOverrides {
                    once: true,
                    step_buffer_delay: Duration::ZERO,
                    ..DaemonConfigOverrides::default()
                },
                now + 5,
                &mut dummy_rx,
            )
            .await
            .unwrap()
    };
    assert_eq!(
        rep_unver.outcome,
        TickStageOutcome::UncertainHold {
            reason: "process_state_unverified".into()
        }
    );
    let unver_human = rep_unver.format_human_line();
    let unver_json = serde_json::to_string(&rep_unver).unwrap();
    assert!(!unver_human.contains("missing-proc-g3-secret-dir"));
    assert!(!unver_json.contains("missing-proc-g3-secret-dir"));
    assert!(unver_human.contains("agy-switch-cli status"));

    // G3-d: Stage 5/6 commit failure (read-only slot dir) MUST emit safe error code without path!
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let mut eng_ro = DaemonEngine::new();
    let rep_ro = eng_ro
        .run_single_tick_report_with_shutdown(
            &repo,
            &FileSessionBackend,
            &SlotQuotaRunner::constant_pct(0.90),
            &reg,
            &DaemonConfigOverrides {
                once: true,
                step_buffer_delay: Duration::ZERO,
                ..DaemonConfigOverrides::default()
            },
            now + 5,
            &mut dummy_rx,
        )
        .await
        .unwrap();
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        rep_ro.outcome,
        TickStageOutcome::CommitFailed { .. }
    ));
    let ro_human = rep_ro.format_human_line();
    let ro_json = serde_json::to_string(&rep_ro).unwrap();
    let tmp_str = tmp.path().to_str().unwrap();
    assert!(
        !ro_human.contains(tmp_str),
        "ro_human leaked path: {ro_human}"
    );
    assert!(!ro_json.contains(tmp_str), "ro_json leaked path: {ro_json}");
    let ds_ro = read_daemon_state_readonly(&paths).unwrap();
    assert!(
        !ds_ro.last_reason.as_deref().unwrap_or("").contains(tmp_str),
        "daemon_state.last_reason leaked path: {:?}",
        ds_ro.last_reason
    );

    // G3-a: Real CLI `daemon --once` and `daemon --once --json` on corrupt truncated journal:
    // zero paths in human line, JSON, or persisted `daemon_state.json`; journal preserved byte-for-byte!
    repo.with_write_lock(|tx| {
        agy_switch_cli::switching::daemon::clear_daemon_pause_in_tx(tx.paths(), now + 6)
    })
    .unwrap();
    let slot_before_g3a = fs::read(&paths.active_slot_file).unwrap();
    let index_before_g3a = fs::read(paths.index_file()).unwrap();
    fs::create_dir_all(paths.state_dir()).unwrap();
    fs::write(paths.switch_journal_file(), b"{").unwrap();
    let run_cli = |extra: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", run_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc)
            .args(["--data-dir", data.to_str().unwrap(), "--backend", "file"]);
        cmd.args(extra);
        cmd.output().unwrap()
    };

    let corrupt_human = run_cli(&["daemon", "--once", "--no-notify"]);
    assert_eq!(corrupt_human.status.code(), Some(0));
    assert!(corrupt_human.stderr.is_empty());
    let corrupt_human_s = String::from_utf8_lossy(&corrupt_human.stdout);
    assert!(corrupt_human_s.contains("daemon: paused"));
    assert!(corrupt_human_s.contains("corrupted_switch_journal"));
    assert!(corrupt_human_s.contains("agy-switch-cli status"));
    assert!(
        !corrupt_human_s.contains(tmp_str) && !corrupt_human_s.contains("switch_journal.json"),
        "human output leaked path: {corrupt_human_s}"
    );
    assert_eq!(fs::read(paths.switch_journal_file()).unwrap(), b"{");
    assert_eq!(fs::read(&paths.active_slot_file).unwrap(), slot_before_g3a);
    assert_eq!(fs::read(paths.index_file()).unwrap(), index_before_g3a);
    let ds_corrupt = read_daemon_state_readonly(&paths).unwrap();
    assert!(ds_corrupt.paused_on_failure);
    assert_eq!(
        ds_corrupt.paused_reason.as_deref(),
        Some("corrupted_switch_journal")
    );

    let corrupt_json = run_cli(&["--json", "daemon", "--once", "--no-notify"]);
    assert_eq!(corrupt_json.status.code(), Some(0));
    assert!(corrupt_json.stderr.is_empty());
    let corrupt_json_s = String::from_utf8_lossy(&corrupt_json.stdout);
    assert!(
        !corrupt_json_s.contains(tmp_str) && !corrupt_json_s.contains("switch_journal.json"),
        "JSON output leaked path: {corrupt_json_s}"
    );
    let cj: serde_json::Value = serde_json::from_str(&corrupt_json_s).unwrap();
    assert_eq!(cj["daemon"]["phase"], "paused_on_failure");
    assert_eq!(cj["daemon"]["reason"], "corrupted_switch_journal");
    assert_eq!(
        cj["daemon"]["outcome"]["paused_on_failure"]["reason"],
        "corrupted_switch_journal"
    );

    // G3-b: Legacy v1.2.1 `daemon_state.json` containing an embedded absolute path in `paused_reason`
    // MUST be sanitized before emitting in both human and JSON reports!
    let legacy_paused = DaemonPersistentState {
        paused_on_failure: true,
        paused_reason: Some(format!(
            "Paused due to corrupted switch journal: Switch journal '{}/state/switch_journal.json' is invalid JSON.",
            data.display()
        )),
        consecutive_commit_failures: 1,
        last_phase: "paused_on_failure".into(),
        ..DaemonPersistentState::default()
    };
    repo.with_write_lock(|tx| save_daemon_state_in_tx(tx.paths(), &legacy_paused))
        .unwrap();
    let leg_human = run_cli(&["daemon", "--once", "--no-notify"]);
    assert_eq!(leg_human.status.code(), Some(0));
    let leg_human_s = String::from_utf8_lossy(&leg_human.stdout);
    assert!(leg_human_s.contains("corrupted_switch_journal"));
    assert!(
        !leg_human_s.contains(tmp_str) && !leg_human_s.contains("switch_journal.json"),
        "legacy human output leaked path: {leg_human_s}"
    );
    let leg_json = run_cli(&["--json", "daemon", "--once", "--no-notify"]);
    assert_eq!(leg_json.status.code(), Some(0));
    let leg_json_s = String::from_utf8_lossy(&leg_json.stdout);
    assert!(
        !leg_json_s.contains(tmp_str) && !leg_json_s.contains("switch_journal.json"),
        "legacy JSON output leaked path: {leg_json_s}"
    );
    let lj: serde_json::Value = serde_json::from_str(&leg_json_s).unwrap();
    assert_eq!(lj["daemon"]["reason"], "corrupted_switch_journal");

    // G3-e (Round-2 signoff closure): Stage 1 journal reconciliation returning non-recovery `Err`
    // (e.g. recoverable `prepared` journal + `locks/store.lock` replaced by a directory) MUST redact
    // all absolute paths & lock filenames in BOTH `daemon --once` human stderr AND `--json daemon --once`
    // JSON error envelope (matching continuous daemon stderr), while preserving non-zero exit code `1`,
    // `error_code = "io_error"`, and disk state (journal, slot, index, and absent `daemon_state.json`)!
    let r2_tmp = tempfile::tempdir().unwrap();
    let r2_home = r2_tmp.path().join("home");
    let r2_data = r2_tmp.path().join("data");
    let r2_cache = r2_tmp.path().join("cache");
    let r2_run = r2_tmp.path().join("run");
    fs::create_dir_all(&r2_home).unwrap();
    fs::create_dir_all(&r2_data).unwrap();
    fs::create_dir_all(&r2_cache).unwrap();
    fs::create_dir_all(&r2_run).unwrap();
    let r2_paths = HeadlessPaths::with_explicit(r2_home.clone(), r2_data.clone(), r2_cache.clone());
    let r2_repo = StoreRepository::new(r2_paths.clone());
    let r2_a1 = make_v122_account("acc-0001", "alice@example.com", 0.50, now, now);
    let r2_a2 = make_v122_account("acc-0002", "bob@example.com", 0.90, now, now);
    r2_repo
        .with_write_lock(|tx| {
            tx.upsert_account(r2_a1.clone(), true, now)?;
            tx.upsert_account(r2_a2.clone(), false, now)?;
            Ok(())
        })
        .unwrap();
    fs::create_dir_all(&r2_paths.active_slot_dir).unwrap();
    FileSessionBackend
        .write_slot(&r2_paths, &serialize_session_payload(&r2_a1.token).unwrap())
        .unwrap();
    let r2_slot_digest = FileSessionBackend
        .inspect_slot(&r2_paths)
        .raw_digest()
        .unwrap()
        .to_string();
    fs::create_dir_all(r2_paths.state_dir()).unwrap();
    let prep_journal = json!({
        "schema_version": 1,
        "operation_id": "synthetic-op-0001",
        "phase": "prepared",
        "prev_selected_account_id": "acc-0001",
        "target_account_id": "acc-0002",
        "prev_slot_digest": r2_slot_digest,
        "token_rotated": false,
        "started_at": now,
        "updated_at": now,
        "replica_state": {
            "backend": "file",
            "uses_file": true,
            "file": {
                "prev_present": true,
                "prev_digest": r2_slot_digest
            }
        }
    });
    fs::write(
        r2_paths.switch_journal_file(),
        serde_json::to_vec_pretty(&prep_journal).unwrap(),
    )
    .unwrap();
    // Replace `locks/store.lock` with a directory so L3 lock open fails with EISDIR (`io_error`)!
    let _ = fs::remove_file(r2_paths.store_lock_file());
    fs::create_dir_all(r2_paths.store_lock_file()).unwrap();

    let r2_slot_before = fs::read(&r2_paths.active_slot_file).unwrap();
    let r2_index_before = fs::read(r2_paths.index_file()).unwrap();
    let r2_journal_before = fs::read(r2_paths.switch_journal_file()).unwrap();
    let r2_tmp_str = r2_tmp.path().to_str().unwrap();

    let run_r2_cli = |extra: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &r2_home)
            .env("XDG_CACHE_HOME", &r2_cache)
            .env("XDG_RUNTIME_DIR", &r2_run)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", r2_run.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc)
            .args(["--data-dir", r2_data.to_str().unwrap(), "--backend", "file"]);
        cmd.args(extra);
        cmd.output().unwrap()
    };

    let once_err_human = run_r2_cli(&["daemon", "--once", "--no-notify"]);
    assert_eq!(once_err_human.status.code(), Some(1));
    assert!(once_err_human.stdout.is_empty());
    let once_err_h_str = String::from_utf8_lossy(&once_err_human.stderr);
    assert!(
        once_err_h_str.contains("code: io_error")
            && once_err_h_str.contains("agy-switch-cli status"),
        "unexpected human stderr: {once_err_h_str}"
    );
    assert!(
        !once_err_h_str.contains(r2_tmp_str) && !once_err_h_str.contains("store.lock"),
        "daemon --once human stderr leaked path or lock filename: {once_err_h_str}"
    );

    let once_err_json = run_r2_cli(&["--json", "daemon", "--once", "--no-notify"]);
    assert_eq!(once_err_json.status.code(), Some(1));
    assert!(once_err_json.stdout.is_empty());
    let once_err_j_str = String::from_utf8_lossy(&once_err_json.stderr);
    assert!(
        !once_err_j_str.contains(r2_tmp_str) && !once_err_j_str.contains("store.lock"),
        "daemon --once --json stderr leaked path or lock filename: {once_err_j_str}"
    );
    let ej: serde_json::Value = serde_json::from_str(&once_err_j_str).unwrap();
    assert_eq!(ej["schema_version"], 1);
    assert_eq!(ej["ok"], false);
    assert_eq!(ej["error_code"], "io_error");
    assert_eq!(ej["exit_code"], 1);
    assert!(ej.get("details").is_none());
    assert!(ej["message"]
        .as_str()
        .unwrap()
        .contains("agy-switch-cli status"));

    // Continuous daemon contrast: emits sanitized stderr line and exits 0 on SIGTERM.
    let mut cont_child = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &r2_home)
        .env("XDG_CACHE_HOME", &r2_cache)
        .env("XDG_RUNTIME_DIR", &r2_run)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", r2_run.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc)
        .args([
            "--data-dir",
            r2_data.to_str().unwrap(),
            "--backend",
            "file",
            "daemon",
            "--no-notify",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut cont_stderr_line = String::new();
    {
        use std::io::BufRead;
        let stderr_pipe = cont_child.stderr.take().unwrap();
        let mut reader = std::io::BufReader::new(stderr_pipe);
        reader.read_line(&mut cont_stderr_line).unwrap();
        unsafe {
            libc::kill(cont_child.id() as libc::pid_t, libc::SIGTERM);
        }
    }
    let cont_out = cont_child.wait_with_output().unwrap();
    assert_eq!(cont_out.status.code(), Some(0));
    assert!(cont_out.stdout.is_empty());
    assert!(
        cont_stderr_line.contains("code: io_error")
            && cont_stderr_line.contains("agy-switch-cli status")
            && !cont_stderr_line.contains(r2_tmp_str)
            && !cont_stderr_line.contains("store.lock"),
        "unexpected continuous daemon stderr line: {cont_stderr_line}"
    );

    assert_eq!(
        fs::read(&r2_paths.active_slot_file).unwrap(),
        r2_slot_before
    );
    assert_eq!(fs::read(r2_paths.index_file()).unwrap(), r2_index_before);
    assert_eq!(
        fs::read(r2_paths.switch_journal_file()).unwrap(),
        r2_journal_before
    );
    assert!(!r2_paths.daemon_state_file().exists());
}

#[tokio::test]
async fn synthetic_v124_daemon_reset_cooldown_wakes_running_engine_and_sanitizes_once_errors() {
    use agy_switch_cli::store::locks::DaemonInstanceLock;
    use agy_switch_cli::switching::daemon::reset_daemon_cooldown;

    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let fake_proc = tmp.path().join("fake_proc");
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let paths = HeadlessPaths::with_explicit(
        tmp.path().join("home"),
        tmp.path().join("data"),
        tmp.path().join("cache"),
    );
    fs::create_dir_all(&paths.active_slot_dir).unwrap();
    let repo = StoreRepository::new(paths.clone());
    let now = 1_800_000_000i64;
    let future_reset = "2099-01-01T00:00:00Z";

    let make_acc = |id: &str, email: &str, pct: f64| -> AccountRecord {
        let mut a = AccountRecord::new(
            id.into(),
            email.into(),
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
            Some("Pro"),
            pct,
            pct,
            Some(pct),
            future_reset,
        ));
        a
    };
    let acc_a = make_acc("acc-a", "alice@example.com", 0.04);
    let acc_b = make_acc("acc-b", "bob@example.com", 0.90);

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            candidate_account_ids: vec!["acc-b".into(), "acc-a".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // Hold `DaemonInstanceLock` across ticks (simulating a long-running foreground / systemd daemon).
    let _daemon_lock = DaemonInstanceLock::try_acquire(&paths).unwrap();
    let mut engine = DaemonEngine::new();
    let runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-a") {
            Ok(quota_outcome_for_frac(0.04, 0.04))
        } else {
            Ok(quota_outcome_for_frac(0.90, 0.90))
        }
    });
    let registry = OAuthClientRegistry::load(&paths).unwrap();
    let overrides = DaemonConfigOverrides {
        interval_secs: 300,
        cooldown_secs: 3600,
        once: true,
        step_buffer_delay: Duration::ZERO,
        notify_override: Some(false),
        ..DaemonConfigOverrides::default()
    };

    // Tick 1: switches `acc-a -> acc-b` and persists `cooldown_until = now + 3600`.
    let t1 = engine
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &runner,
            &registry,
            &overrides,
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        t1,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-a".into(),
            target_id: "acc-b".into(),
        }
    );
    let after_t1 = read_daemon_state_readonly(&paths).unwrap();
    assert_eq!(after_t1.cooldown_until, now + 3600);

    // Tick 2 (10s later): still blocked in cooldown.
    let t2 = engine
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &runner,
            &registry,
            &overrides,
            now + 10,
        )
        .await
        .unwrap();
    assert_eq!(t2, TickStageOutcome::InCooldown { until: now + 3600 });

    // External `reset_daemon_cooldown` runs while `_daemon_lock` is STILL HELD!
    let reset_res = reset_daemon_cooldown(&repo, now + 12).unwrap();
    assert!(reset_res.cooldown_reset);
    assert!(reset_res.cooldown_was_active);
    assert_eq!(reset_res.previous_cooldown_until, now + 3600);

    // Tick 3 (15s later): running daemon immediately wakes up out of cooldown without restart!
    let t3 = engine
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &runner,
            &registry,
            &overrides,
            now + 15,
        )
        .await
        .unwrap();
    assert_eq!(t3, TickStageOutcome::IdleSufficientQuota);
    drop(_daemon_lock);

    // Also verify `daemon --once --reset-cooldown` sanitizes local paths if `daemon_state.json` is corrupt.
    let bad_tmp = tempfile::tempdir().unwrap();
    let bad_home = bad_tmp.path().join("home");
    let bad_data = bad_tmp.path().join("secret_user_data_dir");
    let bad_cache = bad_tmp.path().join("cache");
    let bad_run = bad_tmp.path().join("run");
    fs::create_dir_all(&bad_home).unwrap();
    fs::create_dir_all(bad_data.join("state")).unwrap();
    fs::create_dir_all(&bad_cache).unwrap();
    fs::create_dir_all(&bad_run).unwrap();
    fs::write(bad_data.join("state/daemon_state.json"), b"{bad-json").unwrap();

    let once_err = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &bad_home)
        .env("XDG_CACHE_HOME", &bad_cache)
        .env("XDG_RUNTIME_DIR", &bad_run)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-dbus", bad_run.display()),
        )
        .env("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc)
        .args([
            "--data-dir",
            bad_data.to_str().unwrap(),
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
    assert_eq!(once_err.status.code(), Some(1));
    assert!(once_err.stdout.is_empty());
    let err_str = String::from_utf8_lossy(&once_err.stderr);
    assert!(
        !err_str.contains("secret_user_data_dir") && !err_str.contains("daemon_state.json"),
        "daemon --once --reset-cooldown leaked local path in stderr: {err_str}"
    );
    let ej: serde_json::Value = serde_json::from_str(&err_str).unwrap();
    assert_eq!(ej["schema_version"], 1);
    assert_eq!(ej["ok"], false);
    assert_eq!(ej["error_code"], "data_error");
}

#[tokio::test]
async fn synthetic_v127_daemon_step_and_verify_local_cache_skip_multi_hop_and_exhausted_steady_state(
) {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let now = 1_800_500_000i64;
    let future_reset = "2099-01-01T05:00:00Z";
    let past_reset = jiff::Timestamp::from_second(now - 600).unwrap().to_string();
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);

    let make_cli_acc = |id: &str, email: &str, pct_5h: f64, reset_5h: &str| -> AccountRecord {
        let mut a = AccountRecord::new(
            id.into(),
            email.into(),
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
        let mut obs = QuotaObservation::new(now - 60, QuotaSourceEnv::OfficialCli);
        obs.subscription_tier = Some("Google AI Pro".into());
        obs.tier_source_env = Some(QuotaSourceEnv::OfficialCli);
        obs.quota_groups = Some(vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: Some("Models within this group: gemini-3.1-pro".into()),
            buckets: vec![
                QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: pct_5h,
                    remaining_fraction_known: Some(true),
                    reset_time: reset_5h.into(),
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.90,
                    remaining_fraction_known: Some(true),
                    reset_time: future_reset.into(),
                    display_name: None,
                    description: None,
                },
            ],
        }]);
        a.quota = Some(obs);
        a
    };

    // Scenario A: Local cache skip + multi-hop Step-and-Verify landing!
    // - `acc-a`: active source at 5% (<= reserve 10%)
    // - `acc-c1`: cached 8% (< min 30%) with FUTURE reset_time -> MUST be skipped purely locally!
    // - `acc-c2`: cached 8% (< min 30%) with EXPIRED reset_time -> MUST be probed; live returns 14% (< 30%) -> advance without cooldown!
    // - `acc-c3`: live returns 82% (>= 30%) -> LANDS cleanly with cooldown set!
    let acc_a = make_cli_acc("acc-a", "alice@example.com", 0.05, future_reset);
    let acc_c1 = make_cli_acc("acc-c1", "bob@example.com", 0.08, future_reset);
    let acc_c2 = make_cli_acc("acc-c2", "charlie@example.com", 0.08, &past_reset);
    let acc_c3 = make_cli_acc("acc-c3", "dave@example.com", 0.80, future_reset);

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_c1.clone(), false, now)?;
        tx.upsert_account(acc_c2.clone(), false, now)?;
        tx.upsert_account(acc_c3.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "all".into(),
            candidate_account_ids: vec![
                "acc-c1".into(),
                "acc-c2".into(),
                "acc-c3".into(),
                "acc-a".into(),
            ],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();
    backend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    let runner_a = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-a") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_acc-c1") {
            panic!(
                "acc-c1 (known low before future reset) MUST be skipped locally without probing!"
            );
        } else if slot.contains("1//RT_acc-c2") {
            Ok(quota_outcome_for_frac(0.14, 0.90))
        } else if slot.contains("1//RT_acc-c3") {
            Ok(quota_outcome_for_frac(0.82, 0.90))
        } else {
            panic!("unexpected slot: {slot}");
        }
    });

    let overrides = DaemonConfigOverrides {
        cooldown_secs: 1800,
        step_buffer_delay: Duration::ZERO,
        notify_override: Some(false),
        ..DaemonConfigOverrides::default()
    };
    let mut engine = DaemonEngine::new();
    let res_a = engine
        .run_single_tick(&repo, &backend, &runner_a, &reg, &overrides, now)
        .await
        .unwrap();
    assert_eq!(
        res_a,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-a".into(),
            target_id: "acc-c3".into(),
        }
    );
    let probed_a = runner_a.probed_slots();
    assert!(probed_a.iter().any(|s| s.contains("1//RT_acc-c2")));
    assert!(probed_a.iter().any(|s| s.contains("1//RT_acc-c3")));
    assert!(!probed_a.iter().any(|s| s.contains("1//RT_acc-c1")));
    assert_eq!(
        read_daemon_state_readonly(&paths).unwrap().cooldown_until,
        now + 1800
    );

    // Scenario B: All-exhausted steady-state — stays on highest live-probed candidate > source_rem,
    // sets NO switch cooldown (or holds without ping-pong), and returns to original source when all <= source_rem!
    // Reset cooldown and switch back to `acc-a` (5%), with `acc-c2` (18% < 30%) and `acc-c3` (12% < 30%).
    execute_switch(
        &repo,
        &backend,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 2000,
    )
    .unwrap();
    repo.with_write_lock(|tx| {
        let mut ds = read_daemon_state_readonly(tx.paths())?;
        ds.cooldown_until = 0;
        agy_switch_cli::switching::daemon::save_daemon_state_in_tx(tx.paths(), &ds)?;
        // Clear cached future low on c2/c3 so both are live-probed
        for id in ["acc-c2", "acc-c3"] {
            let mut rec = tx.load_account_opt(id)?.unwrap();
            rec.quota = None;
            tx.save_account(&rec)?;
        }
        Ok(())
    })
    .unwrap();
    let runner_exhausted_best = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-a") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_acc-c2") {
            Ok(quota_outcome_for_frac(0.18, 0.90)) // highest below min (18% > 5%)!
        } else if slot.contains("1//RT_acc-c3") {
            Ok(quota_outcome_for_frac(0.12, 0.90))
        } else {
            panic!("unexpected slot in exhausted best test: {slot}");
        }
    });
    let mut engine_ex = DaemonEngine::new();
    let res_ex = engine_ex
        .run_single_tick(
            &repo,
            &backend,
            &runner_exhausted_best,
            &reg,
            &overrides,
            now + 2010,
        )
        .await
        .unwrap();
    assert!(matches!(
        res_ex,
        TickStageOutcome::NoQualifiedCandidate { .. }
    ));
    // MUST stay on `acc-c2` (18% > original 5%) rather than leaving slot on `acc-c3` (12%) or `acc-a` (5%)!
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-c2")
    );
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_acc-c2"));

    // Next tick when ALL candidates are strictly <= source_rem (`acc-c2` at 18%, `acc-a`/`acc-c3` at 5%/12%)
    // MUST skip cached low candidates locally (zero ping-pong!) and stay on `acc-c2`!
    let runner_no_pingpong = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-c2") {
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else {
            panic!("exhausted candidates with cached future reset MUST NOT be re-probed (no ping-pong!): {slot}");
        }
    });
    let res_nopp = engine_ex
        .run_single_tick(
            &repo,
            &backend,
            &runner_no_pingpong,
            &reg,
            &overrides,
            now + 2400,
        )
        .await
        .unwrap();
    assert_eq!(res_nopp, TickStageOutcome::IdleSufficientQuota);
    assert_eq!(runner_no_pingpong.probed_slots().len(), 1);
}

#[tokio::test]
async fn synthetic_v127_daemon_hold_backoff_settle_failure_wait_midhop_and_rotated_rt_stage1() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let now = 1_800_600_000i64;
    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let backend = FileSessionBackend;
    let reg = OAuthClientRegistry::parse_from_raw(None, None);

    let make_acc = |id: &str, email: &str| -> AccountRecord {
        AccountRecord::new(
            id.into(),
            email.into(),
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
    let acc_a = make_acc("acc-a", "alice@example.com");
    let acc_b = make_acc("acc-b", "bob@example.com");
    let acc_c = make_acc("acc-c", "charlie@example.com");

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        let mut pol = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::Priority,
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            monitored_model: "all".into(),
            candidate_account_ids: vec!["acc-b".into(), "acc-c".into(), "acc-a".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut pol, None, now)?;
        Ok(())
    })
    .unwrap();

    // 1. Stage 1 MUST accept a rotated refresh_token written by official `agy` for the selected
    //    account (`acc-a`) with matching `id_token_email`, sync it back, and proceed without wedging!
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.acc-a-rot",
                "token_type": "Bearer",
                "refresh_token": "1//RT_acc-a_ROTATED_BY_AGY",
                "expiry": "2099-01-01T00:00:00Z"
            },
            "id_token_email": "alice@example.com",
            "user_tier": "PRO"
        }))
        .unwrap(),
    )
    .unwrap();
    let runner_rot =
        SlotQuotaRunner::from_handler(|_, _, _| Ok(quota_outcome_for_frac(0.85, 0.90)));
    let overrides = DaemonConfigOverrides {
        interval_secs: 300,
        cooldown_secs: 3600,
        step_buffer_delay: Duration::ZERO,
        notify_override: Some(false),
        ..DaemonConfigOverrides::default()
    };
    let mut engine = DaemonEngine::new();
    let res_rot = engine
        .run_single_tick(&repo, &backend, &runner_rot, &reg, &overrides, now)
        .await
        .unwrap();
    assert_eq!(res_rot, TickStageOutcome::IdleSufficientQuota);
    assert_eq!(
        repo.read_account_unchecked("acc-a")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_acc-a_ROTATED_BY_AGY"
    );

    // 2. All-below-reserve (`<= 10%`) exhausted steady-state MUST set hold backoff (`>= 2 * interval`)
    //    so the very next tick (`now + 300`) does NOT ping-pong even if cached resets have passed!
    //    Use `reset_time = now + 200` (expires BEFORE next tick at `now + 300`), so ONLY hold backoff
    //    prevents re-hopping!
    let near_reset = jiff::Timestamp::from_second(now + 200).unwrap().to_string();
    let near_reset_c = near_reset.clone();
    let make_near_outcome = move |frac: f64| OfficialCliUsageOutcome::Quota {
        description: None,
        groups: vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: None,
            buckets: vec![
                QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: frac,
                    remaining_fraction_known: Some(true),
                    reset_time: near_reset_c.clone(),
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: 0.90,
                    remaining_fraction_known: Some(true),
                    reset_time: "2099-01-07T00:00:00Z".into(),
                    display_name: None,
                    description: None,
                },
            ],
        }],
    };
    let runner_all_low = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_acc-a_ROTATED_BY_AGY") {
            Ok(make_near_outcome(0.05))
        } else if slot.contains("1//RT_acc-b") {
            Ok(make_near_outcome(0.08)) // best, STILL <= reserve 10%!
        } else if slot.contains("1//RT_acc-c") {
            Ok(make_near_outcome(0.07))
        } else {
            panic!("unexpected slot: {slot}");
        }
    });
    let res_low_1 = engine
        .run_single_tick(&repo, &backend, &runner_all_low, &reg, &overrides, now + 10)
        .await
        .unwrap();
    assert!(matches!(
        res_low_1,
        TickStageOutcome::NoQualifiedCandidate { .. }
    ));
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );

    // Tick 2 at `now + 310` (AFTER `near_reset` = `now + 200` has passed!):
    // `acc-b` is still 8% (<= reserve 10%), but hold backoff MUST prevent hopping to `acc-a` or `acc-c`!
    let near_reset_2 = jiff::Timestamp::from_second(now + 400).unwrap().to_string();
    let runner_hold_check = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_acc-b") {
            Ok(OfficialCliUsageOutcome::Quota {
                description: None,
                groups: vec![QuotaGroup {
                    display_name: "Gemini Models".into(),
                    description: None,
                    buckets: vec![
                        QuotaBucket {
                            bucket_id: "gemini-5h".into(),
                            window: "5h".into(),
                            remaining_fraction: 0.08,
                            remaining_fraction_known: Some(true),
                            reset_time: near_reset_2.clone(),
                            display_name: None,
                            description: None,
                        },
                        QuotaBucket {
                            bucket_id: "gemini-weekly".into(),
                            window: "weekly".into(),
                            remaining_fraction: 0.90,
                            remaining_fraction_known: Some(true),
                            reset_time: "2099-01-07T00:00:00Z".into(),
                            display_name: None,
                            description: None,
                        },
                    ],
                }],
            })
        } else {
            panic!("hold backoff MUST prevent re-probing exhausted dormant candidate: {slot}");
        }
    });
    let res_low_2 = engine
        .run_single_tick(
            &repo,
            &backend,
            &runner_hold_check,
            &reg,
            &overrides,
            now + 310,
        )
        .await
        .unwrap();
    assert!(matches!(
        res_low_2,
        TickStageOutcome::NoQualifiedCandidate { .. }
    ));
    assert_eq!(runner_hold_check.probed_slots().len(), 1);
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );

    // 3. Stage 6 settle-back commit failure MUST NOT be swallowed:
    //    Switch back to `acc-a`, clear caches/backoff, hop `acc-a -> acc-b (18%) -> acc-c (12%)`,
    //    then chmod slot dir 0500 right inside `acc-c` probe so Stage 6 settle-back (`acc-c -> acc-b`)
    //    fails and MUST return `CommitFailed` rather than falsely claiming `NoQualifiedCandidate`!
    execute_switch(
        &repo,
        &backend,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 1000,
    )
    .unwrap();
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        Ok(())
    })
    .unwrap();
    let slot_dir_for_ro = paths.active_slot_dir.clone();
    let runner_settle_fail = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_acc-a_ROTATED_BY_AGY") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_acc-b") {
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if slot.contains("1//RT_acc-c") {
            // Make slot dir read-only BEFORE Stage 6 settles back to `acc-b`!
            fs::set_permissions(&slot_dir_for_ro, fs::Permissions::from_mode(0o500)).unwrap();
            Ok(quota_outcome_for_frac(0.12, 0.90))
        } else {
            panic!("unexpected slot: {slot}");
        }
    });
    let mut engine_sf = DaemonEngine::new();
    let res_sf = engine_sf
        .run_single_tick(
            &repo,
            &backend,
            &runner_settle_fail,
            &reg,
            &overrides,
            now + 1010,
        )
        .await
        .unwrap();
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(res_sf, TickStageOutcome::CommitFailed { .. }),
        "Stage 6 settle-back commit error must return CommitFailed, got {res_sf:?}"
    );
    assert_eq!(
        read_daemon_state_readonly(&paths)
            .unwrap()
            .consecutive_commit_failures,
        1
    );

    // 3b. Once the slot directory is writable again, a subsequent Stage 6 settle-back `Ok(_)`
    //     persisting `no_candidate` MUST reset `consecutive_commit_failures` from `1` back to `0`!
    //     (Start directly from `acc-c` without calling `execute_switch`, which would clear the counter.)
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-c")
    );
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(
        read_daemon_state_readonly(&paths)
            .unwrap()
            .consecutive_commit_failures,
        1,
        "precondition: consecutive_commit_failures must still be 1 before Stage 6 recovery tick"
    );
    let runner_settle_ok = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_acc-c") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_acc-b") {
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if slot.contains("1//RT_acc-a_ROTATED_BY_AGY") {
            Ok(quota_outcome_for_frac(0.12, 0.90))
        } else {
            panic!("unexpected slot: {slot}");
        }
    });
    let mut engine_settle_ok = DaemonEngine::new();
    let res_settle_ok = engine_settle_ok
        .run_single_tick(
            &repo,
            &backend,
            &runner_settle_ok,
            &reg,
            &overrides,
            now + 1050,
        )
        .await
        .unwrap();
    assert_eq!(
        res_settle_ok,
        TickStageOutcome::NoQualifiedCandidate {
            reason: "no_qualified_candidate".into()
        }
    );
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );
    assert_eq!(
        read_daemon_state_readonly(&paths)
            .unwrap()
            .consecutive_commit_failures,
        0,
        "Stage 6 settle-back Ok(_) must reset consecutive_commit_failures to 0"
    );

    // 4. Mid-hop `PolicyMode::Wait` guard: start an active `agy` process AFTER hop 0 (`acc-b`) probes
    //    below min, BEFORE hop 1 (`acc-c`): daemon MUST return `BlockedByActiveProcess("acc-c")`
    //    and MUST NOT switch the slot while `agy` is running!
    execute_switch(
        &repo,
        &backend,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 1100,
    )
    .unwrap();
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        let mut pol = repo.read_policy()?;
        let rev = pol.revision;
        pol.mode = PolicyMode::Wait;
        tx.save_policy(&mut pol, Some(rev), now + 1101)?;
        Ok(())
    })
    .unwrap();
    let proc_for_wait = fake_proc.clone();
    let runner_wait_midhop = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_acc-a_ROTATED_BY_AGY") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_acc-b") {
            // Simulate user launching `agy` during hop 0!
            fs::create_dir_all(proc_for_wait.join("6001")).unwrap();
            fs::write(
                proc_for_wait.join("6001/stat"),
                "6001 (agy) S 1 6001 6001 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 888999 1000 10",
            )
            .unwrap();
            fs::write(proc_for_wait.join("6001/comm"), "agy\n").unwrap();
            Ok(quota_outcome_for_frac(0.03, 0.90)) // lower than acc-a (5%)!
        } else {
            panic!("Wait mode must NOT probe acc-c after agy started: {slot}");
        }
    });
    let mut engine_w = DaemonEngine::new();
    let res_wait = engine_w
        .run_single_tick(
            &repo,
            &backend,
            &runner_wait_midhop,
            &reg,
            &overrides,
            now + 1110,
        )
        .await
        .unwrap();
    assert_eq!(
        res_wait,
        TickStageOutcome::BlockedByActiveProcess {
            target_id: "acc-c".into()
        }
    );
    // Slot MUST remain untouched on `acc-b` (never illegally switched back to `acc-a` while `agy` runs!)
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b")
    );

    // 5. Committed intermediate hop (`hop 0` Ok) MUST reset `consecutive_commit_failures` to 0:
    //    Seed `consecutive_commit_failures = 2` (1 below pause threshold 3), let `hop 0` commit
    //    cleanly (`acc-a -> acc-b`), then fail `hop 1` (`acc-c`) with EACCES -> MUST result in
    //    `CommitFailed` with `consecutive_commit_failures == 1` (NOT `PausedOnFailure` at 3)!
    let _ = fs::remove_dir_all(fake_proc.join("6001"));
    execute_switch(
        &repo,
        &backend,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 1200,
    )
    .unwrap();
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        let mut pol = repo.read_policy()?;
        let rev = pol.revision;
        pol.mode = PolicyMode::Immediate;
        tx.save_policy(&mut pol, Some(rev), now + 1201)?;
        Ok(())
    })
    .unwrap();
    let mut st_seed = read_daemon_state_readonly(&paths).unwrap();
    st_seed.consecutive_commit_failures = 2;
    st_seed.paused_on_failure = false;
    st_seed.cooldown_until = 0;
    fs::write(
        paths.daemon_state_file(),
        serde_json::to_vec(&st_seed).unwrap(),
    )
    .unwrap();
    let slot_dir_mid_fail = paths.active_slot_dir.clone();
    let runner_mid_fail = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_acc-a_ROTATED_BY_AGY") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_acc-b") {
            // Make slot dir read-only AFTER hop 0 committed cleanly so hop 1 fails commit.
            fs::set_permissions(&slot_dir_mid_fail, fs::Permissions::from_mode(0o500)).unwrap();
            Ok(quota_outcome_for_frac(0.10, 0.90))
        } else {
            panic!("unexpected slot after hop 1 EACCES: {slot}");
        }
    });
    let mut engine_mid_fail = DaemonEngine::new();
    let res_mid_fail = engine_mid_fail
        .run_single_tick(
            &repo,
            &backend,
            &runner_mid_fail,
            &reg,
            &overrides,
            now + 1210,
        )
        .await
        .unwrap();
    fs::set_permissions(&paths.active_slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(res_mid_fail, TickStageOutcome::CommitFailed { .. }),
        "hop 0 commit must reset consecutive_commit_failures so hop 1 failure is CommitFailed (1), not PausedOnFailure (3): got {res_mid_fail:?}"
    );
    let st_after_mid = read_daemon_state_readonly(&paths).unwrap();
    assert!(!st_after_mid.paused_on_failure);
    assert_eq!(st_after_mid.consecutive_commit_failures, 1);

    // 6. Stage 6 settle-back MUST detect an external slot overwrite (`agy login`, without bumping
    //    `index.revision`) via `expected_slot_digest` under L1 and cancel instead of clobbering!
    execute_switch(
        &repo,
        &backend,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 1300,
    )
    .unwrap();
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        let mut pol = repo.read_policy()?;
        let rev = pol.revision;
        pol.candidate_account_ids = vec!["acc-a".into(), "acc-b".into()];
        tx.save_policy(&mut pol, Some(rev), now + 1301)?;
        Ok(())
    })
    .unwrap();
    let ext_payload = serde_json::to_vec(&serde_json::json!({
        "token": {
            "access_token": "ya29.EXT_LOGIN",
            "token_type": "Bearer",
            "refresh_token": "1//RT_EXTERNAL_USER",
            "expiry": "2099-05-01T00:00:00Z"
        },
        "id_token_email": "external@example.com"
    }))
    .unwrap();
    let countdown = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    struct CountdownStage6Backend {
        inner: FileSessionBackend,
        countdown: std::sync::Arc<std::sync::Mutex<usize>>,
        ext_bytes: Vec<u8>,
    }
    impl agy_switch_cli::session::backend::CredentialBackend for CountdownStage6Backend {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn uses_keyring(&self) -> bool {
            self.inner.uses_keyring()
        }
        fn inspect_slot(
            &self,
            p: &HeadlessPaths,
        ) -> agy_switch_cli::session::backend::SlotInspectState {
            let st = self.inner.inspect_slot(p);
            let mut guard = self.countdown.lock().unwrap();
            if *guard > 0 {
                *guard -= 1;
                if *guard == 0 {
                    fs::write(&p.active_slot_file, &self.ext_bytes).unwrap();
                }
            }
            st
        }
        fn snapshot_before_write(
            &self,
            p: &HeadlessPaths,
        ) -> agy_switch_cli::error::CliResult<Option<Vec<u8>>> {
            self.inner.snapshot_before_write(p)
        }
        fn write_slot(
            &self,
            p: &HeadlessPaths,
            payload: &str,
        ) -> agy_switch_cli::error::CliResult<()> {
            self.inner.write_slot(p, payload)
        }
        fn remove_slot(&self, p: &HeadlessPaths) -> agy_switch_cli::error::CliResult<()> {
            self.inner.remove_slot(p)
        }
    }
    let cd_backend = CountdownStage6Backend {
        inner: FileSessionBackend,
        countdown: countdown.clone(),
        ext_bytes: ext_payload.clone(),
    };
    let cd_for_runner = countdown.clone();
    let runner_s6_cd = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_acc-a_ROTATED_BY_AGY") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_acc-b") {
            // 1st inspect_slot after this returns = official_cli post-probe guard (countdown 1->0,
            // overwrites slot immediately after verified_slot_digest is captured so Stage 6 catches it!).
            *cd_for_runner.lock().unwrap() = 1;
            Ok(quota_outcome_for_frac(0.03, 0.90))
        } else {
            panic!("unexpected slot in Stage 6 external overwrite test: {slot}");
        }
    });
    let mut engine_s6 = DaemonEngine::new();
    let res_s6_cancel = engine_s6
        .run_single_tick(
            &repo,
            &cd_backend,
            &runner_s6_cd,
            &reg,
            &overrides,
            now + 1310,
        )
        .await
        .unwrap();
    assert_eq!(
        res_s6_cancel,
        TickStageOutcome::CancelledStalePlan {
            reason: "active_slot_digest_changed".into()
        },
        "Stage 6 settle-back must cancel on external slot overwrite instead of clobbering"
    );
    assert_eq!(
        fs::read(&paths.active_slot_file).unwrap(),
        ext_payload,
        "external slot payload must remain intact after Stage 6 cancellation"
    );
}

#[tokio::test]
async fn daemon_s1_pre_probe_external_login_and_s2_stage6_policy_change_cancel_safely() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_920_000_000i64;

    let make_acc = |id: &str, email: &str, rt: &str| {
        AccountRecord::new(
            id.into(),
            email.into(),
            TokenRecord {
                access_token: format!("ya29.{id}"),
                refresh_token: rt.into(),
                expires_in: 3600,
                expiry_timestamp: now + 7200,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: None,
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        )
    };
    let acc_a = make_acc("acc-a", "alice@example.com", "1//RT_S1_A");
    let acc_b = make_acc("acc-b", "bob@example.com", "1//RT_S1_B");
    let acc_c = make_acc("acc-c", "charlie@example.com", "1//RT_S1_C");
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        let mut p = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::Priority,
            monitored_model: "all".into(),
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            candidate_account_ids: vec!["acc-b".into(), "acc-c".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut p, None, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    // S1-a: External `agy login` overwrites active slot with an unsaved foreign account right
    // after Stage 5 switches to `acc-b` and captures its post-switch checkpoint, BEFORE
    // `refresh_active_slot_quota_detailed`'s pre-probe `resolve_active_official_slot_account_id`
    // runs. Daemon MUST cancel without adopting the foreign digest and MUST NOT overwrite the
    // external slot on next hop (`acc-c`) or Stage 6 settle-back!
    let ext_login_payload = serde_json::to_vec(&serde_json::json!({
        "token": {
            "access_token": "ya29.EXT_S1_LOGIN",
            "token_type": "Bearer",
            "refresh_token": "1//RT_EXT_S1_FOREIGN",
            "expiry": "2099-06-01T00:00:00Z"
        },
        "id_token_email": "fresh-login@example.com"
    }))
    .unwrap();

    struct InjectExternalAfterSwitchBackend {
        inner: FileSessionBackend,
        armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
        ext_bytes: Vec<u8>,
    }
    impl agy_switch_cli::session::backend::CredentialBackend for InjectExternalAfterSwitchBackend {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn uses_keyring(&self) -> bool {
            self.inner.uses_keyring()
        }
        fn inspect_slot(
            &self,
            p: &HeadlessPaths,
        ) -> agy_switch_cli::session::backend::SlotInspectState {
            let st = self.inner.inspect_slot(p);
            // When `daemon.rs` captures `post_switch_checkpoint` right after switching to `acc-b`,
            // `armed` was flipped by `write_slot` — immediately simulate an independent `agy login`
            // right after L1 checkpoint capture, before pre-probe `inspect_slot` runs!
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                fs::write(&p.active_slot_file, &self.ext_bytes).unwrap();
            }
            st
        }
        fn snapshot_before_write(
            &self,
            p: &HeadlessPaths,
        ) -> agy_switch_cli::error::CliResult<Option<Vec<u8>>> {
            self.inner.snapshot_before_write(p)
        }
        fn write_slot(
            &self,
            p: &HeadlessPaths,
            payload: &str,
        ) -> agy_switch_cli::error::CliResult<()> {
            self.inner.write_slot(p, payload)?;
            if payload.contains("1//RT_S1_B") {
                self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }
        fn remove_slot(&self, p: &HeadlessPaths) -> agy_switch_cli::error::CliResult<()> {
            self.inner.remove_slot(p)
        }
    }

    let s1_backend = InjectExternalAfterSwitchBackend {
        inner: FileSessionBackend,
        armed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ext_bytes: ext_login_payload.clone(),
    };
    let s1_runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_S1_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else {
            panic!("pre-probe mismatch must abort before probing foreign slot: {slot}");
        }
    });
    let overrides = DaemonConfigOverrides {
        interval_secs: 300,
        cooldown_secs: 3600,
        step_buffer_delay: Duration::ZERO,
        once: true,
        notify_override: Some(false),
        explicit_file_backend: true,
        ..DaemonConfigOverrides::default()
    };
    let mut engine_s1 = DaemonEngine::new();
    let res_s1 = engine_s1
        .run_single_tick(&repo, &s1_backend, &s1_runner, &reg, &overrides, now + 10)
        .await
        .unwrap();
    assert_eq!(
        res_s1,
        TickStageOutcome::CancelledStalePlan {
            reason: "active_slot_digest_changed".into()
        },
        "S1: pre-probe external login must cancel daemon tick instead of adopting foreign digest"
    );
    assert_eq!(
        fs::read(&paths.active_slot_file).unwrap(),
        ext_login_payload,
        "S1: externally logged-in slot must remain completely intact"
    );

    // S1-b: Positive control — same-account legitimate RT rotation by official `agy` during a
    // candidate probe that subsequently returns RateLimited still advances `expected_slot_digest`
    // from `verified_slot_digest` and cleanly advances to `acc-c` (85%).
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();
    repo.with_write_lock(|tx| tx.commit_selected_account("acc-a", now + 20))
        .unwrap();
    let slot_path_rot = paths.active_slot_file.clone();
    let s1_rot_runner = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_S1_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_S1_B") {
            fs::write(
                &slot_path_rot,
                serde_json::to_vec(&serde_json::json!({
                    "token": {
                        "access_token": "ya29.B_ROTATED_AT",
                        "token_type": "Bearer",
                        "refresh_token": "1//RT_S1_B_ROTATED",
                        "expiry": "2099-07-01T00:00:00Z"
                    },
                    "id_token_email": "bob@example.com"
                }))
                .unwrap(),
            )
            .unwrap();
            Err(OfficialCliQuotaError::RateLimited)
        } else if slot.contains("1//RT_S1_C") {
            Ok(quota_outcome_for_frac(0.85, 0.90))
        } else {
            panic!("unexpected slot in S1-b rotation control: {slot}");
        }
    });
    let mut engine_s1_rot = DaemonEngine::new();
    let res_s1_rot = engine_s1_rot
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &s1_rot_runner,
            &reg,
            &overrides,
            now + 30,
        )
        .await
        .unwrap();
    assert_eq!(
        res_s1_rot,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-a".into(),
            target_id: "acc-c".into()
        },
        "S1-b: legitimate same-account RT rotation during failed probe must still advance cleanly"
    );
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_S1_B_ROTATED"
    );

    // S2: A=5%, B=18%, C=9%. While probing `acc-c`, user disables policy (`enabled=false`,
    // revision bumps). Stage 6 settle-back to `acc-b` MUST cancel with
    // `policy_revision_changed_or_disabled`, NOT bump `index.revision`, and leave `acc-c` in slot!
    repo.with_write_lock(|tx| {
        tx.commit_selected_account("acc-a", now + 40)?;
        let mut p = repo.read_policy()?;
        let rev = p.revision;
        p.enabled = true;
        p.candidate_account_ids = vec!["acc-b".into(), "acc-c".into()];
        tx.save_policy(&mut p, Some(rev), now + 40)?;
        // Clear cooldown from S1-b so tick executes immediately
        agy_switch_cli::switching::daemon::reset_daemon_cooldown_in_tx(tx.paths(), now + 40)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();
    let repo_for_s2 = StoreRepository::new(paths.clone());
    let rev_at_c_probe = std::sync::Arc::new(std::sync::Mutex::new(0u64));
    let rev_capture = rev_at_c_probe.clone();
    let s2_runner = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_S1_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_S1_B") {
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if slot.contains("1//RT_S1_C") {
            *rev_capture.lock().unwrap() = repo_for_s2.read_snapshot().unwrap().index.revision;
            repo_for_s2
                .with_write_lock(|tx| {
                    let mut p = repo_for_s2.read_policy()?;
                    let rev = p.revision;
                    p.enabled = false;
                    tx.save_policy(&mut p, Some(rev), now + 50)?;
                    Ok(())
                })
                .unwrap();
            Ok(quota_outcome_for_frac(0.09, 0.90))
        } else {
            panic!("unexpected slot in S2 test: {slot}");
        }
    });
    let mut engine_s2 = DaemonEngine::new();
    let res_s2 = engine_s2
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &s2_runner,
            &reg,
            &overrides,
            now + 60,
        )
        .await
        .unwrap();
    assert_eq!(
        res_s2,
        TickStageOutcome::CancelledStalePlan {
            reason: "policy_revision_changed_or_disabled".into()
        },
        "S2: Stage 6 settle-back must cancel when policy is disabled or revised during last probe"
    );
    let snap_after_s2 = repo.read_snapshot().unwrap();
    assert_eq!(
        snap_after_s2.index.selected_account_id.as_deref(),
        Some("acc-c"),
        "S2: Stage 6 cancellation must leave acc-c selected"
    );
    assert_eq!(
        snap_after_s2.index.revision,
        *rev_at_c_probe.lock().unwrap(),
        "S2: Stage 6 cancellation must NOT bump index.revision"
    );

    // S2 positive control: re-enable policy and clear cached low-quota observations from S2 so
    // Stage 3 probes both candidates freshly without local-cache skip -> settles back on B!
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        tx.commit_selected_account("acc-a", now + 70)?;
        let mut p = repo.read_policy()?;
        let rev = p.revision;
        p.enabled = true;
        p.candidate_account_ids = vec!["acc-b".into(), "acc-c".into()];
        tx.save_policy(&mut p, Some(rev), now + 70)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();
    let s2_ok_runner = SlotQuotaRunner::from_handler(|_, _, slot| {
        if slot.contains("1//RT_S1_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_S1_B") {
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if slot.contains("1//RT_S1_C") {
            Ok(quota_outcome_for_frac(0.09, 0.90))
        } else {
            panic!("unexpected slot in S2 positive control: {slot}");
        }
    });
    let mut engine_s2_ok = DaemonEngine::new();
    let res_s2_ok = engine_s2_ok
        .run_single_tick(
            &repo,
            &FileSessionBackend,
            &s2_ok_runner,
            &reg,
            &overrides,
            now + 80,
        )
        .await
        .unwrap();
    assert_eq!(
        res_s2_ok,
        TickStageOutcome::NoQualifiedCandidate {
            reason: "no_qualified_candidate".into()
        }
    );
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b"),
        "S2 positive control: without policy change, Stage 6 settles back to best candidate acc-b"
    );
}

#[tokio::test]
async fn daemon_r2_01_pre_snap_baseline_handoff_cancels_on_hop_and_stage6_settle_back() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_930_000_000i64;

    let make_acc = |id: &str, email: &str, rt: &str| {
        AccountRecord::new(
            id.into(),
            email.into(),
            TokenRecord {
                access_token: format!("ya29.{id}"),
                refresh_token: rt.into(),
                expires_in: 3600,
                expiry_timestamp: now + 7200,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: None,
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        )
    };
    let acc_a = make_acc("acc-a", "alice@example.com", "1//RT_R201_A");
    let acc_b = make_acc("acc-b", "bob@example.com", "1//RT_R201_B");
    let acc_c = make_acc("acc-c", "charlie@example.com", "1//RT_R201_C");
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        let mut p = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::Priority,
            monitored_model: "all".into(),
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            candidate_account_ids: vec!["acc-b".into(), "acc-c".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut p, None, now)?;
        Ok(())
    })
    .unwrap();

    // Mock backend that lets `daemon.rs`'s `inspect_slot` see the expected slot, then injects an
    // external `agy login` right as `executor.rs` takes `snapshot_before_write` (`pre_snap`) when
    // the slot holds `trigger_rt_substr`!
    struct InjectOnMatchingPreSnapBackend {
        inner: FileSessionBackend,
        trigger_rt_substr: &'static str,
        write_calls_after_inject: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        injected: std::sync::Arc<std::sync::atomic::AtomicBool>,
        ext_bytes: Vec<u8>,
    }
    impl agy_switch_cli::session::backend::CredentialBackend for InjectOnMatchingPreSnapBackend {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn uses_keyring(&self) -> bool {
            self.inner.uses_keyring()
        }
        fn inspect_slot(
            &self,
            p: &HeadlessPaths,
        ) -> agy_switch_cli::session::backend::SlotInspectState {
            self.inner.inspect_slot(p)
        }
        fn snapshot_before_write(
            &self,
            p: &HeadlessPaths,
        ) -> agy_switch_cli::error::CliResult<Option<Vec<u8>>> {
            let cur = self.inner.snapshot_before_write(p)?;
            if !self.injected.load(std::sync::atomic::Ordering::SeqCst)
                && cur
                    .as_deref()
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .is_some_and(|s| s.contains(self.trigger_rt_substr))
            {
                fs::write(&p.active_slot_file, &self.ext_bytes).unwrap();
                self.injected
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return self.inner.snapshot_before_write(p);
            }
            Ok(cur)
        }
        fn write_slot(
            &self,
            p: &HeadlessPaths,
            payload: &str,
        ) -> agy_switch_cli::error::CliResult<()> {
            if self.injected.load(std::sync::atomic::Ordering::SeqCst) {
                self.write_calls_after_inject
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.write_slot(p, payload)
        }
        fn remove_slot(&self, p: &HeadlessPaths) -> agy_switch_cli::error::CliResult<()> {
            self.inner.remove_slot(p)
        }
    }

    let overrides = DaemonConfigOverrides {
        interval_secs: 300,
        cooldown_secs: 3600,
        step_buffer_delay: Duration::ZERO,
        once: true,
        notify_override: Some(false),
        explicit_file_backend: true,
        ..DaemonConfigOverrides::default()
    };

    // 1. R2-01 Stage 5 next-hop boundary:
    //    Hop 0 (A -> B) succeeds normally. On Hop 1 (B -> C), `daemon.rs` line 1847 `inspect_slot`
    //    sees `1//RT_R201_B` and passes; then `executor.rs` calls `snapshot_before_write` (`pre_snap`)
    //    which injects an external login payload! MUST cancel before sync-back, journal, or write_slot!
    FileSessionBackend
        .write_slot(
            &paths,
            &agy_switch_cli::session::payload::serialize_session_payload_for_account(&acc_a)
                .unwrap(),
        )
        .unwrap();
    let ext_hop_payload = serde_json::to_vec(&serde_json::json!({
        "token": {
            "access_token": "ya29.EXT_R201_HOP",
            "token_type": "Bearer",
            "refresh_token": "1//RT_EXT_R201_HOP",
            "expiry": "2099-06-01T00:00:00Z"
        },
        "id_token_email": "fresh-r201-hop@example.com"
    }))
    .unwrap();
    let hop_writes_after = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hop_backend = InjectOnMatchingPreSnapBackend {
        inner: FileSessionBackend,
        trigger_rt_substr: "1//RT_R201_B",
        write_calls_after_inject: hop_writes_after.clone(),
        injected: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ext_bytes: ext_hop_payload.clone(),
    };
    let rev_before_hop1 = std::sync::Arc::new(std::sync::Mutex::new(0u64));
    let rev_hop1_cap = rev_before_hop1.clone();
    let repo_hop1 = StoreRepository::new(paths.clone());
    let runner_hop = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_R201_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_R201_B") {
            *rev_hop1_cap.lock().unwrap() = repo_hop1.read_snapshot().unwrap().index.revision;
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else {
            panic!("R2-01 hop cancellation must never probe acc-c: {slot}");
        }
    });
    let mut eng_hop = DaemonEngine::new();
    let res_hop = eng_hop
        .run_single_tick(&repo, &hop_backend, &runner_hop, &reg, &overrides, now + 10)
        .await
        .unwrap();
    assert_eq!(
        res_hop,
        TickStageOutcome::CancelledStalePlan {
            reason: "active_slot_digest_changed".into()
        },
        "R2-01: mismatched pre_snap on Stage 5 hop must cancel cleanly"
    );
    assert_eq!(
        hop_writes_after.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "R2-01: write_slot must NEVER be called after pre_snap mismatch on Stage 5 hop"
    );
    assert_eq!(
        fs::read(&paths.active_slot_file).unwrap(),
        ext_hop_payload,
        "R2-01: external login slot must stay byte-for-byte intact"
    );
    let snap_after_hop = repo.read_snapshot().unwrap();
    assert_eq!(
        snap_after_hop.index.selected_account_id.as_deref(),
        Some("acc-b")
    );
    assert_eq!(
        snap_after_hop.index.revision,
        *rev_before_hop1.lock().unwrap(),
        "R2-01: index.revision must not advance after Stage 5 pre_snap cancellation"
    );
    assert!(
        !paths.switch_journal_file().exists(),
        "R2-01: no switch_journal.json should be written on pre_snap cancellation"
    );

    // 2. R2-01 Stage 6 settle-back boundary:
    //    Hop 0 (A -> B): calls 1, 2. Hop 1 (B -> C): calls 3, 4.
    //    Stage 6 settle-back (C -> B): call #5 (`pre_snap`) RIGHT AFTER Stage 6 inspect_slot passed!
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        tx.commit_selected_account("acc-a", now + 20)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(
            &paths,
            &agy_switch_cli::session::payload::serialize_session_payload_for_account(&acc_a)
                .unwrap(),
        )
        .unwrap();
    let ext_s6_payload = serde_json::to_vec(&serde_json::json!({
        "token": {
            "access_token": "ya29.EXT_R201_S6",
            "token_type": "Bearer",
            "refresh_token": "1//RT_EXT_R201_S6",
            "expiry": "2099-06-01T00:00:00Z"
        },
        "id_token_email": "fresh-r201-stage6@example.com"
    }))
    .unwrap();
    let s6_writes_after = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let s6_backend = InjectOnMatchingPreSnapBackend {
        inner: FileSessionBackend,
        trigger_rt_substr: "1//RT_R201_C",
        write_calls_after_inject: s6_writes_after.clone(),
        injected: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ext_bytes: ext_s6_payload.clone(),
    };
    let rev_at_c = std::sync::Arc::new(std::sync::Mutex::new(0u64));
    let rev_c_cap = rev_at_c.clone();
    let repo_s6 = StoreRepository::new(paths.clone());
    let runner_s6 = SlotQuotaRunner::from_handler(move |_, _, slot| {
        if slot.contains("1//RT_R201_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if slot.contains("1//RT_R201_B") {
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if slot.contains("1//RT_R201_C") {
            *rev_c_cap.lock().unwrap() = repo_s6.read_snapshot().unwrap().index.revision;
            Ok(quota_outcome_for_frac(0.09, 0.90))
        } else {
            panic!("unexpected slot in R2-01 Stage 6 test: {slot}");
        }
    });
    let mut eng_s6 = DaemonEngine::new();
    let res_s6 = eng_s6
        .run_single_tick(&repo, &s6_backend, &runner_s6, &reg, &overrides, now + 30)
        .await
        .unwrap();
    assert_eq!(
        res_s6,
        TickStageOutcome::CancelledStalePlan {
            reason: "active_slot_digest_changed".into()
        },
        "R2-01: mismatched pre_snap on Stage 6 settle-back must cancel cleanly"
    );
    assert_eq!(
        s6_writes_after.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "R2-01: write_slot must NEVER be called after pre_snap mismatch on Stage 6 settle-back"
    );
    assert_eq!(
        fs::read(&paths.active_slot_file).unwrap(),
        ext_s6_payload,
        "R2-01: external login slot must remain byte-for-byte intact on Stage 6 cancellation"
    );
    let snap_after_s6 = repo.read_snapshot().unwrap();
    assert_eq!(
        snap_after_s6.index.selected_account_id.as_deref(),
        Some("acc-c")
    );
    assert_eq!(
        snap_after_s6.index.revision,
        *rev_at_c.lock().unwrap(),
        "R2-01: index.revision must not advance after Stage 6 pre_snap cancellation"
    );
    assert!(!paths.switch_journal_file().exists());

    // 3. Positive control: matching pre_snap and verified same-account RT rotation during Stage 6
    //    interrupted settle-back still sync-back C's rotated RT and settle back to B!
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        tx.commit_selected_account("acc-a", now + 40)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(
            &paths,
            &agy_switch_cli::session::payload::serialize_session_payload_for_account(&acc_a)
                .unwrap(),
        )
        .unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    struct AsyncShutdownRotateRunner {
        shutdown_tx: tokio::sync::watch::Sender<bool>,
    }
    impl OfficialCliQuotaRunner for AsyncShutdownRotateRunner {
        fn query_active_usage<'a>(
            &'a self,
            paths: &'a HeadlessPaths,
            _explicit_file_backend: bool,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<OfficialCliUsageOutcome, OfficialCliQuotaError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let slot = fs::read_to_string(&paths.active_slot_file).unwrap_or_default();
                if slot.contains("1//RT_R201_A") {
                    Ok(quota_outcome_for_frac(0.05, 0.90))
                } else if slot.contains("1//RT_R201_B") {
                    Ok(quota_outcome_for_frac(0.18, 0.90))
                } else if slot.contains("1//RT_R201_C") {
                    // Official `agy` rotates C's RT in the active slot, then shutdown fires before
                    // `/usage` finishes so Stage 6 runs under `StepLoopExit::Shutdown` and MUST
                    // accept C's verified rotated RT inside `pre_snap` (`DigestOrSameAccountRotation`)!
                    fs::write(
                        &paths.active_slot_file,
                        serde_json::to_vec(&serde_json::json!({
                            "token": {
                                "access_token": "ya29.C_ROT_SHUTDOWN",
                                "token_type": "Bearer",
                                "refresh_token": "1//RT_R201_C_ROTATED",
                                "expiry": "2099-08-01T00:00:00Z"
                            },
                            "id_token_email": "charlie@example.com"
                        }))
                        .unwrap(),
                    )
                    .unwrap();
                    let _ = self.shutdown_tx.send(true);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    unreachable!("shutdown_rx must cancel probe before sleep completes")
                } else {
                    panic!("unexpected slot in R2-01 shutdown rotation positive control: {slot}");
                }
            })
        }
    }
    let shutdown_runner = AsyncShutdownRotateRunner { shutdown_tx };
    let mut eng_pos = DaemonEngine::new();
    let res_pos = eng_pos
        .run_single_tick_with_shutdown(
            &repo,
            &FileSessionBackend,
            &shutdown_runner,
            &reg,
            &overrides,
            now + 50,
            &mut shutdown_rx,
        )
        .await
        .unwrap();
    assert_eq!(
        res_pos,
        TickStageOutcome::UncertainHold {
            reason: "shutdown_signal_received".into()
        }
    );
    assert_eq!(
        repo.read_snapshot()
            .unwrap()
            .index
            .selected_account_id
            .as_deref(),
        Some("acc-b"),
        "R2-01 positive control: verified same-account RT rotation during interrupted Stage 6 still settles back to B"
    );
    assert_eq!(
        repo.read_account_unchecked("acc-c")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_R201_C_ROTATED",
        "R2-01 positive control: C's rotated RT must be synced back before settling to B"
    );
}

#[tokio::test]
async fn daemon_r3_01_dual_backend_protects_file_replica_and_allows_single_sided_same_account_rotation(
) {
    use agy_switch_cli::session::backend::{
        BackendPreWriteSnapshot, BackendReplicaInspection, KeyringCollectionDigest,
        ReplicaCasExpectation, SlotInspectState,
    };
    use agy_switch_cli::session::payload::{
        bytes_sha256_hex, parse_session_payload_bytes, serialize_session_payload_for_account,
    };

    let _guard = PROC_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let data = tmp.path().join("data");
    let cache = tmp.path().join("cache");
    let fake_proc = tmp.path().join("proc");
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    fs::create_dir_all(&fake_proc).unwrap();
    let _proc_env = ScopedEnvVar::set("AGY_SWITCH_CLI_PROC_ROOT", &fake_proc);

    let paths = HeadlessPaths::with_explicit(home, data, cache);
    let repo = StoreRepository::new(paths.clone());
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_940_000_000i64;

    let make_acc = |id: &str, email: &str, rt: &str| {
        AccountRecord::new(
            id.into(),
            email.into(),
            TokenRecord {
                access_token: format!("ya29.{id}"),
                refresh_token: rt.into(),
                expires_in: 3600,
                expiry_timestamp: now + 7200,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: None,
                granted_scopes: None,
                project_id: None,
                is_gcp_tos: true,
            },
            now,
        )
    };
    let acc_a = make_acc("acc-a", "alice@example.com", "1//RT_R301_A");
    let acc_b = make_acc("acc-b", "bob@example.com", "1//RT_R301_B");
    let acc_c = make_acc("acc-c", "charlie@example.com", "1//RT_R301_C");
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        let mut p = SwitchPolicy {
            enabled: true,
            mode: PolicyMode::Immediate,
            strategy: PolicyStrategy::Priority,
            monitored_model: "all".into(),
            reserve_percentage: 10,
            candidate_min_percentage: 30,
            candidate_account_ids: vec!["acc-b".into(), "acc-c".into()],
            ..SwitchPolicy::default()
        };
        tx.save_policy(&mut p, None, now)?;
        Ok(())
    })
    .unwrap();

    /// Synthetic dual (`keyring` + `file`) backend matching production `SecretServiceSessionBackend`
    /// semantics: `inspect_slot` prefers keyring over file, `inspect_replicas` and
    /// `snapshot_replicas_before_write` return BOTH replicas independently, and `write_slot_cas`
    /// verifies per-replica CAS and writes BOTH replicas. Supports injecting a file-only external
    /// login right when `snapshot_replicas_before_write` (`pre_snap`) runs!
    type PreSnapFileInject = Arc<Mutex<Option<(&'static str, Vec<u8>)>>>;
    struct SyntheticDualBackend {
        keyring: Arc<Mutex<Option<Vec<u8>>>>,
        file_writes: Arc<std::sync::atomic::AtomicUsize>,
        kr_writes: Arc<std::sync::atomic::AtomicUsize>,
        pre_snap_file_inject: PreSnapFileInject,
    }

    impl SyntheticDualBackend {
        fn new(initial: &str) -> Self {
            Self {
                keyring: Arc::new(Mutex::new(Some(initial.as_bytes().to_vec()))),
                file_writes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                kr_writes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                pre_snap_file_inject: Arc::new(Mutex::new(None)),
            }
        }
        fn keyring_state(&self) -> SlotInspectState {
            match self.keyring.lock().unwrap().as_deref() {
                None => SlotInspectState::AbsentInInitializedDir,
                Some(b) => match parse_session_payload_bytes(b) {
                    Ok(p) => SlotInspectState::Present(p),
                    Err(e) => SlotInspectState::Corrupt(e),
                },
            }
        }
    }

    impl CredentialBackend for SyntheticDualBackend {
        fn name(&self) -> &'static str {
            "dual"
        }
        fn uses_keyring(&self) -> bool {
            true
        }
        fn uses_file(&self) -> bool {
            true
        }
        fn inspect_slot(&self, paths: &HeadlessPaths) -> SlotInspectState {
            let kr = self.keyring_state();
            if kr.is_absent_clean() {
                FileSessionBackend.inspect_slot(paths)
            } else {
                kr
            }
        }
        fn inspect_replicas(&self, paths: &HeadlessPaths) -> BackendReplicaInspection {
            let kr_bytes = self.keyring.lock().unwrap().clone();
            let kr_state = self.keyring_state();
            let col = KeyringCollectionDigest {
                path: "/org/freedesktop/secrets/collection/login".into(),
                present: kr_bytes.is_some(),
                digest: kr_bytes.as_deref().map(bytes_sha256_hex),
                valid_refresh_token_digest: kr_bytes
                    .as_deref()
                    .and_then(|b| parse_session_payload_bytes(b).ok())
                    .map(|p| p.refresh_token_digest),
            };
            BackendReplicaInspection {
                backend_name: "dual",
                uses_keyring: true,
                uses_file: true,
                keyring: Some(kr_state),
                keyring_all_collections_uniform: true,
                keyring_collections: vec![col],
                file: FileSessionBackend.inspect_slot(paths),
            }
        }
        fn snapshot_before_write(
            &self,
            paths: &HeadlessPaths,
        ) -> agy_switch_cli::error::CliResult<Option<Vec<u8>>> {
            FileSessionBackend.snapshot_before_write(paths)
        }
        fn snapshot_replicas_before_write(
            &self,
            paths: &HeadlessPaths,
        ) -> agy_switch_cli::error::CliResult<BackendPreWriteSnapshot> {
            let mut file_bytes = FileSessionBackend.snapshot_before_write(paths)?;
            // Optionally inject a file-only external login right at `pre_snap` capture
            // (after daemon's L1 `inspect_replicas` already passed!).
            let maybe_inj = {
                let mut g = self.pre_snap_file_inject.lock().unwrap();
                if let Some((substr, _)) = g.as_ref() {
                    if file_bytes
                        .as_deref()
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .is_some_and(|s| s.contains(substr))
                    {
                        g.take().map(|(_, bytes)| bytes)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(ext_bytes) = maybe_inj {
                fs::write(&paths.active_slot_file, &ext_bytes).unwrap();
                file_bytes = Some(ext_bytes);
            }
            let kr_bytes = self.keyring.lock().unwrap().clone();
            Ok(BackendPreWriteSnapshot {
                backend_name: "dual",
                uses_keyring: true,
                uses_file: true,
                keyring_bytes: Some(kr_bytes.clone()),
                keyring_uniform: true,
                keyring_collections: vec![(
                    "/org/freedesktop/secrets/collection/login".into(),
                    kr_bytes,
                )],
                file_bytes,
            })
        }
        fn write_slot(
            &self,
            paths: &HeadlessPaths,
            payload: &str,
        ) -> agy_switch_cli::error::CliResult<()> {
            FileSessionBackend.write_slot(paths, payload)?;
            self.file_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.keyring.lock().unwrap() = Some(payload.as_bytes().to_vec());
            self.kr_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn write_slot_cas(
            &self,
            paths: &HeadlessPaths,
            payload: &str,
            expected: &ReplicaCasExpectation,
        ) -> agy_switch_cli::error::CliResult<()> {
            if let Some(ref exp_file) = expected.file_expected {
                let cur_file = FileSessionBackend.snapshot_before_write(paths)?;
                if !exp_file.matches_bytes(cur_file.as_deref()) {
                    return Err(agy_switch_cli::error::CliError::partial_commit(
                        "recovery_incomplete",
                        "file CAS mismatch",
                    ));
                }
            }
            if let Some(ref exp_cols) = expected.keyring_expected_collections {
                let cur_kr = self.keyring.lock().unwrap().clone();
                if exp_cols
                    .iter()
                    .any(|(_, exp)| !exp.matches_bytes(cur_kr.as_deref()))
                {
                    return Err(agy_switch_cli::error::CliError::partial_commit(
                        "recovery_incomplete",
                        "keyring CAS mismatch",
                    ));
                }
            }
            self.write_slot(paths, payload)
        }
        fn remove_slot(&self, paths: &HeadlessPaths) -> agy_switch_cli::error::CliResult<()> {
            FileSessionBackend.remove_slot(paths)?;
            *self.keyring.lock().unwrap() = None;
            Ok(())
        }
        fn read_raw_keyring_secret(&self) -> agy_switch_cli::error::CliResult<Option<Vec<u8>>> {
            Ok(self.keyring.lock().unwrap().clone())
        }
    }

    let overrides = DaemonConfigOverrides {
        interval_secs: 300,
        cooldown_secs: 3600,
        step_buffer_delay: Duration::ZERO,
        once: true,
        notify_override: Some(false),
        explicit_file_backend: false,
        ..DaemonConfigOverrides::default()
    };

    let payload_a = serialize_session_payload_for_account(&acc_a).unwrap();

    // 1. R3-01 Stage 5 next hop (file-only external login injected right at Hop 1 `pre_snap`
    //    AND separately during B's probe while keyring STILL holds B):
    for inject_during_probe in [true, false] {
        repo.with_write_lock(|tx| {
            for id in ["acc-a", "acc-b", "acc-c"] {
                let mut r = tx.load_account_opt(id)?.unwrap();
                r.quota = None;
                tx.save_account(&r)?;
            }
            tx.commit_selected_account("acc-a", now + 5)?;
            agy_switch_cli::switching::daemon::reset_daemon_cooldown_in_tx(tx.paths(), now + 5)?;
            Ok(())
        })
        .unwrap();
        FileSessionBackend.write_slot(&paths, &payload_a).unwrap();
        let dual_be = SyntheticDualBackend::new(&payload_a);
        let ext_ssh_file = serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.SSH_EXT_HOP",
                "token_type": "Bearer",
                "refresh_token": "1//RT_SSH_EXT_HOP",
                "expiry": "2099-06-01T00:00:00Z"
            },
            "id_token_email": "ssh-hop@example.com"
        }))
        .unwrap();
        if !inject_during_probe {
            *dual_be.pre_snap_file_inject.lock().unwrap() =
                Some(("1//RT_R301_B", ext_ssh_file.clone()));
        }
        let kr_ref = dual_be.keyring.clone();
        let file_path = paths.active_slot_file.clone();
        let ext_for_probe = ext_ssh_file.clone();
        let rev_after_hop0 = Arc::new(Mutex::new(0u64));
        let rev_cap = rev_after_hop0.clone();
        let repo_cap = StoreRepository::new(paths.clone());
        let runner = SlotQuotaRunner::from_handler(move |_, _, _| {
            let kr_str = String::from_utf8(kr_ref.lock().unwrap().clone().unwrap()).unwrap();
            if kr_str.contains("1//RT_R301_A") {
                Ok(quota_outcome_for_frac(0.05, 0.90))
            } else if kr_str.contains("1//RT_R301_B") {
                *rev_cap.lock().unwrap() = repo_cap.read_snapshot().unwrap().index.revision;
                if inject_during_probe {
                    // External SSH `agy login` writes ONLY disk file while keyring stays B!
                    fs::write(&file_path, &ext_for_probe).unwrap();
                }
                Ok(quota_outcome_for_frac(0.18, 0.90))
            } else {
                panic!("R3-01 hop cancellation must never probe acc-c: {kr_str}");
            }
        });
        let mut eng = DaemonEngine::new();
        let res = eng
            .run_single_tick(&repo, &dual_be, &runner, &reg, &overrides, now + 10)
            .await
            .unwrap();
        assert_eq!(
            res,
            TickStageOutcome::CancelledStalePlan {
                reason: "active_slot_digest_changed".into()
            },
            "R3-01 Stage 5 hop (during_probe={inject_during_probe}) must cancel when file replica holds external login"
        );
        // Only Hop 0 (A -> B) wrote once; Hop 1 performed 0 writes to either replica!
        assert_eq!(
            dual_be
                .file_writes
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            dual_be.kr_writes.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(fs::read(&paths.active_slot_file).unwrap(), ext_ssh_file);
        assert!(
            String::from_utf8(dual_be.keyring.lock().unwrap().clone().unwrap())
                .unwrap()
                .contains("1//RT_R301_B")
        );
        let snap_after = repo.read_snapshot().unwrap();
        assert_eq!(
            snap_after.index.selected_account_id.as_deref(),
            Some("acc-b")
        );
        assert_eq!(snap_after.index.revision, *rev_after_hop0.lock().unwrap());
        assert!(!paths.switch_journal_file().exists());
    }

    // 2. R3-01 Stage 6 settle-back (A=5%, B=18%, C=9%): Hop 1 dual-writes C, then external SSH
    //    `agy login` writes ONLY disk file (tested at `pre_snap`) -> MUST cancel with 0 writes!
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        tx.commit_selected_account("acc-a", now + 20)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend.write_slot(&paths, &payload_a).unwrap();
    let dual_s6 = SyntheticDualBackend::new(&payload_a);
    let ext_ssh_s6 = serde_json::to_vec(&serde_json::json!({
        "token": {
            "access_token": "ya29.SSH_EXT_S6",
            "token_type": "Bearer",
            "refresh_token": "1//RT_SSH_EXT_S6",
            "expiry": "2099-06-01T00:00:00Z"
        },
        "id_token_email": "ssh-s6@example.com"
    }))
    .unwrap();
    *dual_s6.pre_snap_file_inject.lock().unwrap() = Some(("1//RT_R301_C", ext_ssh_s6.clone()));
    let kr_s6 = dual_s6.keyring.clone();
    let rev_at_c = Arc::new(Mutex::new(0u64));
    let rev_c_cap = rev_at_c.clone();
    let repo_s6 = StoreRepository::new(paths.clone());
    let runner_s6 = SlotQuotaRunner::from_handler(move |_, _, _| {
        let kr_str = String::from_utf8(kr_s6.lock().unwrap().clone().unwrap()).unwrap();
        if kr_str.contains("1//RT_R301_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if kr_str.contains("1//RT_R301_B") {
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if kr_str.contains("1//RT_R301_C") {
            *rev_c_cap.lock().unwrap() = repo_s6.read_snapshot().unwrap().index.revision;
            Ok(quota_outcome_for_frac(0.09, 0.90))
        } else {
            panic!("unexpected slot in R3-01 Stage 6 test: {kr_str}");
        }
    });
    let mut eng_s6 = DaemonEngine::new();
    let res_s6 = eng_s6
        .run_single_tick(&repo, &dual_s6, &runner_s6, &reg, &overrides, now + 30)
        .await
        .unwrap();
    assert_eq!(
        res_s6,
        TickStageOutcome::CancelledStalePlan {
            reason: "active_slot_digest_changed".into()
        },
        "R3-01 Stage 6 settle-back must cancel when file replica holds external login"
    );
    assert_eq!(
        dual_s6
            .file_writes
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(
        dual_s6.kr_writes.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(fs::read(&paths.active_slot_file).unwrap(), ext_ssh_s6);
    assert!(
        String::from_utf8(dual_s6.keyring.lock().unwrap().clone().unwrap())
            .unwrap()
            .contains("1//RT_R301_C")
    );
    let snap_s6 = repo.read_snapshot().unwrap();
    assert_eq!(snap_s6.index.selected_account_id.as_deref(), Some("acc-c"));
    assert_eq!(snap_s6.index.revision, *rev_at_c.lock().unwrap());
    assert!(!paths.switch_journal_file().exists());

    // 3. R3-01 Stage 1 initial check: keyring holds A while disk file already holds external login
    //    -> daemon MUST hold without overwriting either replica!
    repo.with_write_lock(|tx| tx.commit_selected_account("acc-a", now + 35))
        .unwrap();
    let dual_s1 = SyntheticDualBackend::new(&payload_a);
    fs::write(&paths.active_slot_file, &ext_ssh_s6).unwrap();
    let runner_never = SlotQuotaRunner::from_handler(|_, _, _| {
        panic!("Stage 1 divergent file replica must hold before probing")
    });
    let mut eng_s1 = DaemonEngine::new();
    let res_s1 = eng_s1
        .run_single_tick(&repo, &dual_s1, &runner_never, &reg, &overrides, now + 40)
        .await
        .unwrap();
    assert_eq!(
        res_s1,
        TickStageOutcome::UncertainHold {
            reason: "session_identity_not_matched".into()
        }
    );
    assert_eq!(
        dual_s1
            .file_writes
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(fs::read(&paths.active_slot_file).unwrap(), ext_ssh_s6);

    // 4. Positive control 1: legitimate single-sided same-account RT rotation in KEYRING ONLY
    //    during B's probe (18%) MUST NOT trigger false cancellation -> advances cleanly to C (85%)!
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        tx.commit_selected_account("acc-a", now + 45)?;
        agy_switch_cli::switching::daemon::reset_daemon_cooldown_in_tx(tx.paths(), now + 45)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend.write_slot(&paths, &payload_a).unwrap();
    let dual_kr_rot = SyntheticDualBackend::new(&payload_a);
    let kr_rot_ref = dual_kr_rot.keyring.clone();
    let runner_kr_rot = SlotQuotaRunner::from_handler(move |_, _, _| {
        let kr_str = String::from_utf8(kr_rot_ref.lock().unwrap().clone().unwrap()).unwrap();
        if kr_str.contains("1//RT_R301_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if kr_str.contains("1//RT_R301_B") {
            // Desktop `agy` rotates ONLY keyring for B; disk file stays at Hop 0's `1//RT_R301_B`!
            *kr_rot_ref.lock().unwrap() = Some(
                serde_json::to_vec(&serde_json::json!({
                    "token": {
                        "access_token": "ya29.B_KR_ROT",
                        "token_type": "Bearer",
                        "refresh_token": "1//RT_R301_B_KR_ROT",
                        "expiry": "2099-07-01T00:00:00Z"
                    },
                    "id_token_email": "bob@example.com"
                }))
                .unwrap(),
            );
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if kr_str.contains("1//RT_R301_C") {
            Ok(quota_outcome_for_frac(0.85, 0.90))
        } else {
            panic!("unexpected slot in R3-01 keyring-only rotation control: {kr_str}");
        }
    });
    let mut eng_kr_rot = DaemonEngine::new();
    let res_kr_rot = eng_kr_rot
        .run_single_tick(
            &repo,
            &dual_kr_rot,
            &runner_kr_rot,
            &reg,
            &overrides,
            now + 50,
        )
        .await
        .unwrap();
    assert_eq!(
        res_kr_rot,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-a".into(),
            target_id: "acc-c".into()
        },
        "R3-01 positive control: single-sided keyring rotation for same account must advance to C"
    );
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_R301_B_KR_ROT"
    );

    // 5. Positive control 2: legitimate single-sided same-account RT rotation in FILE ONLY
    //    during B's probe (18%) MUST also advance cleanly to C (85%) and sync B's rotated RT!
    repo.with_write_lock(|tx| {
        for id in ["acc-a", "acc-b", "acc-c"] {
            let mut r = tx.load_account_opt(id)?.unwrap();
            r.quota = None;
            tx.save_account(&r)?;
        }
        tx.commit_selected_account("acc-a", now + 60)?;
        agy_switch_cli::switching::daemon::reset_daemon_cooldown_in_tx(tx.paths(), now + 60)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend.write_slot(&paths, &payload_a).unwrap();
    let dual_file_rot = SyntheticDualBackend::new(&payload_a);
    let kr_file_rot_ref = dual_file_rot.keyring.clone();
    let file_rot_path = paths.active_slot_file.clone();
    let runner_file_rot = SlotQuotaRunner::from_handler(move |_, _, _| {
        let kr_str = String::from_utf8(kr_file_rot_ref.lock().unwrap().clone().unwrap()).unwrap();
        if kr_str.contains("1//RT_R301_A") {
            Ok(quota_outcome_for_frac(0.05, 0.90))
        } else if kr_str.contains("1//RT_R301_B_KR_ROT") {
            // Rotate ONLY disk file for B with fresher expiry; keyring stays at Hop 0's payload!
            fs::write(
                &file_rot_path,
                serde_json::to_vec(&serde_json::json!({
                    "token": {
                        "access_token": "ya29.B_FILE_ROT",
                        "token_type": "Bearer",
                        "refresh_token": "1//RT_R301_B_FILE_ROT",
                        "expiry": "2099-08-01T00:00:00Z"
                    },
                    "id_token_email": "bob@example.com"
                }))
                .unwrap(),
            )
            .unwrap();
            Ok(quota_outcome_for_frac(0.18, 0.90))
        } else if kr_str.contains("1//RT_R301_C") {
            Ok(quota_outcome_for_frac(0.85, 0.90))
        } else {
            panic!("unexpected slot in R3-01 file-only rotation control: {kr_str}");
        }
    });
    let mut eng_file_rot = DaemonEngine::new();
    let res_file_rot = eng_file_rot
        .run_single_tick(
            &repo,
            &dual_file_rot,
            &runner_file_rot,
            &reg,
            &overrides,
            now + 70,
        )
        .await
        .unwrap();
    assert_eq!(
        res_file_rot,
        TickStageOutcome::CommittedSwitch {
            source_id: "acc-a".into(),
            target_id: "acc-c".into()
        },
        "R3-01 positive control: single-sided file rotation for same account must advance to C"
    );
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_R301_B_FILE_ROT"
    );

    // 5b. F-01 regression (exact equal-expiry AND missing-expiry file-only RT rotation):
    //     When B's probe rotates ONLY disk file's RT while keeping the EXACT same AT and expiry
    //     (and separately with MISSING expiry), BOTH `sync_back_active_slot_for_account` AND
    //     `sync_back_pre_switch_snapshot` MUST persist B's new RT into `accounts/acc-b.json`
    //     before dual-writing C (while keyring stayed at old B)!
    for (case_idx, (new_rt, new_at, omit_expiry)) in [
        ("1//RT_F01_B_EQUAL_EXP", "ya29.B_FILE_ROT", false),
        ("1//RT_F01_B_NO_EXP", "ya29.B_NO_EXP_AT", true),
    ]
    .into_iter()
    .enumerate()
    {
        let t_base = now + 100 + (case_idx as i64) * 30;
        let expected_prev_rt = repo
            .read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token;
        let expected_prev_exp = repo
            .read_account_unchecked("acc-b")
            .unwrap()
            .token
            .expiry_timestamp;
        let expected_prev_exp_iso = jiff::Timestamp::from_second(expected_prev_exp)
            .unwrap()
            .to_string();
        repo.with_write_lock(|tx| {
            for id in ["acc-a", "acc-b", "acc-c"] {
                let mut r = tx.load_account_opt(id)?.unwrap();
                r.quota = None;
                tx.save_account(&r)?;
            }
            tx.commit_selected_account("acc-a", t_base)?;
            agy_switch_cli::switching::daemon::reset_daemon_cooldown_in_tx(tx.paths(), t_base)?;
            Ok(())
        })
        .unwrap();
        FileSessionBackend.write_slot(&paths, &payload_a).unwrap();
        let dual_f01 = SyntheticDualBackend::new(&payload_a);
        let kr_f01_ref = dual_f01.keyring.clone();
        let file_f01_path = paths.active_slot_file.clone();
        let new_rt_owned = new_rt.to_string();
        let new_at_owned = new_at.to_string();
        let prev_rt_owned = expected_prev_rt.clone();
        let prev_exp_iso_owned = expected_prev_exp_iso.clone();
        let runner_f01 = SlotQuotaRunner::from_handler(move |_, _, _| {
            let kr_str = String::from_utf8(kr_f01_ref.lock().unwrap().clone().unwrap()).unwrap();
            if kr_str.contains("1//RT_R301_A") {
                Ok(quota_outcome_for_frac(0.05, 0.90))
            } else if kr_str.contains(&prev_rt_owned) {
                // Rotate ONLY disk file's RT with equal (or omitted) expiry; keyring stays old B!
                let mut token_obj = serde_json::json!({
                    "access_token": new_at_owned,
                    "token_type": "Bearer",
                    "refresh_token": new_rt_owned,
                });
                if !omit_expiry {
                    token_obj["expiry"] = serde_json::Value::String(prev_exp_iso_owned.clone());
                }
                fs::write(
                    &file_f01_path,
                    serde_json::to_vec(&serde_json::json!({
                        "token": token_obj,
                        "id_token_email": "bob@example.com"
                    }))
                    .unwrap(),
                )
                .unwrap();
                Ok(quota_outcome_for_frac(0.18, 0.90))
            } else if kr_str.contains("1//RT_R301_C") {
                Ok(quota_outcome_for_frac(0.85, 0.90))
            } else {
                panic!("unexpected slot in F-01 case {case_idx}: {kr_str}");
            }
        });
        let mut eng_f01 = DaemonEngine::new();
        let res_f01 = eng_f01
            .run_single_tick(&repo, &dual_f01, &runner_f01, &reg, &overrides, t_base + 5)
            .await
            .unwrap();
        assert_eq!(
            res_f01,
            TickStageOutcome::CommittedSwitch {
                source_id: "acc-a".into(),
                target_id: "acc-c".into()
            },
            "F-01 case {case_idx}: equal/missing-expiry file-only RT rotation must advance to C"
        );
        let b_after = repo.read_account_unchecked("acc-b").unwrap();
        assert_eq!(
            b_after.token.refresh_token, new_rt,
            "F-01 case {case_idx}: B's rotated disk RT MUST be persisted to accounts/acc-b.json"
        );
        if omit_expiry {
            assert_eq!(
                b_after.token.expiry_timestamp, 1,
                "F-01 + R2-02: rotated RT with missing expiry must fall back conservatively to 1"
            );
            assert_eq!(b_after.token.expires_in, 0);
        }
        assert!(
            fs::read_to_string(&paths.active_slot_file)
                .unwrap()
                .contains("1//RT_R301_C")
                && String::from_utf8(dual_f01.keyring.lock().unwrap().clone().unwrap())
                    .unwrap()
                    .contains("1//RT_R301_C"),
            "F-01 case {case_idx}: both active replicas must hold C after commit"
        );
    }

    // 5c. F-01 mirror & standalone `refresh_active_slot_quota_with_runner` + manual `execute_switch`
    //     controls under `dual`:
    //     - Standalone `quota --refresh` (no switch) saves equal-expiry file-only rotated RT;
    //     - Manual `execute_switch` saves equal-expiry file-only rotated RT AND (mirror) saves
    //       missing-expiry keyring-only rotated RT even when file carries a later expiry with old RT;
    //     - Superseded historical RT in disk file is NEVER rolled back over current keyring RT.
    let b_cur = repo.read_account_unchecked("acc-b").unwrap();
    let payload_b_cur = serialize_session_payload_for_account(&b_cur).unwrap();
    repo.with_write_lock(|tx| {
        tx.commit_selected_account("acc-b", now + 200)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &payload_b_cur)
        .unwrap();
    let dual_direct = SyntheticDualBackend::new(&payload_b_cur);
    let file_direct_path = paths.active_slot_file.clone();
    let runner_direct = SlotQuotaRunner::from_handler(move |_, _, _| {
        fs::write(
            &file_direct_path,
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": "ya29.B_NO_EXP_AT",
                    "token_type": "Bearer",
                    "refresh_token": "1//RT_F01_B_DIRECT_REFRESH",
                    "expiry": "1970-01-01T00:00:01Z"
                },
                "id_token_email": "bob@example.com"
            }))
            .unwrap(),
        )
        .unwrap();
        Ok(quota_outcome_for_frac(0.88, 0.90))
    });
    let direct_out = agy_switch_cli::quota::official_cli::refresh_active_slot_quota_with_runner(
        &repo,
        &dual_direct,
        &runner_direct,
        false,
        Some("acc-b"),
        now + 205,
    )
    .await
    .unwrap();
    assert!(direct_out.token_synced_back);
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_F01_B_DIRECT_REFRESH"
    );

    // Manual `execute_switch` under `dual`: equal-expiry file-only RT rotation is synced before switch.
    let b_for_man = repo.read_account_unchecked("acc-b").unwrap();
    let payload_b_man = serialize_session_payload_for_account(&b_for_man).unwrap();
    let dual_man_f01 = SyntheticDualBackend::new(&payload_b_man);
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": b_for_man.token.access_token,
                "token_type": "Bearer",
                "refresh_token": "1//RT_F01_B_MANUAL_FILE_ROT",
                "expiry": jiff::Timestamp::from_second(b_for_man.token.expiry_timestamp)
                    .unwrap()
                    .to_string()
            },
            "id_token_email": "bob@example.com"
        }))
        .unwrap(),
    )
    .unwrap();
    execute_switch(
        &repo,
        &dual_man_f01,
        &reg,
        "acc-c",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 210,
    )
    .unwrap();
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_F01_B_MANUAL_FILE_ROT"
    );

    // Mirror + superseded check during manual `execute_switch` from B -> C:
    // Keyring rotated RT with missing expiry MUST beat disk file holding stored RT + 2099 expiry;
    // then disk file holding superseded historical RT (`1//RT_R301_B`) MUST NOT roll back B!
    repo.with_write_lock(|tx| {
        tx.commit_selected_account("acc-b", now + 215)?;
        Ok(())
    })
    .unwrap();
    let dual_mirror = SyntheticDualBackend::new(
        &serde_json::to_string(&serde_json::json!({
            "token": {
                "access_token": "ya29.B_KR_MIRROR_NO_EXP",
                "token_type": "Bearer",
                "refresh_token": "1//RT_F01_B_KR_MIRROR"
            },
            "id_token_email": "bob@example.com"
        }))
        .unwrap(),
    );
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.B_STALE_LATER_EXP",
                "token_type": "Bearer",
                "refresh_token": "1//RT_F01_B_MANUAL_FILE_ROT",
                "expiry": "2099-12-01T00:00:00Z"
            },
            "id_token_email": "bob@example.com"
        }))
        .unwrap(),
    )
    .unwrap();
    execute_switch(
        &repo,
        &dual_mirror,
        &reg,
        "acc-c",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 220,
    )
    .unwrap();
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_F01_B_KR_MIRROR"
    );

    // Superseded historical RT in disk file with 2099 expiry MUST NOT roll back B's current RT.
    repo.with_write_lock(|tx| {
        tx.commit_selected_account("acc-b", now + 225)?;
        Ok(())
    })
    .unwrap();
    let b_cur2 = repo.read_account_unchecked("acc-b").unwrap();
    let payload_b_cur2 = serialize_session_payload_for_account(&b_cur2).unwrap();
    let dual_sup = SyntheticDualBackend::new(&payload_b_cur2);
    fs::write(
        &paths.active_slot_file,
        serde_json::to_vec(&serde_json::json!({
            "token": {
                "access_token": "ya29.B_SUPERSEDED",
                "token_type": "Bearer",
                "refresh_token": "1//RT_R301_B",
                "expiry": "2099-12-31T00:00:00Z"
            },
            "id_token_email": "bob@example.com"
        }))
        .unwrap(),
    )
    .unwrap();
    execute_switch(
        &repo,
        &dual_sup,
        &reg,
        "acc-c",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 230,
    )
    .unwrap();
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_F01_B_KR_MIRROR",
        "superseded historical RT in file replica must never roll back B"
    );

    // 6. Positive control 3: explicit manual `execute_switch` under `dual` STILL overrides an
    //    external disk file cleanly (daemon cancellation rules do NOT restrict manual `switch`).
    fs::write(&paths.active_slot_file, &ext_ssh_s6).unwrap();
    let man_res = execute_switch(
        &repo,
        &dual_file_rot,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 240,
    )
    .unwrap();
    assert_eq!(man_res.target_account_id, "acc-a");
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_R301_A"));
}
