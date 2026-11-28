mod common;

use agy_switch_cli::domain::account::{AccountRecord, DisableReasonCode};
use agy_switch_cli::domain::quota::{
    evaluate_quota_observation, ModelQuota, PrimaryModelQuota, QuotaBucket, QuotaEval, QuotaGroup,
    QuotaObservation, QuotaSourceEnv, DEFAULT_QUOTA_MAX_AGE_SECS,
};
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::oauth::registry::OAuthClientRegistry;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::quota::official_cli::refresh_active_slot_quota_with_runner;
use agy_switch_cli::session::backend::{
    BackendPreWriteSnapshot, BackendReplicaInspection, CredentialBackend, FileSessionBackend,
    KeyringCollectionDigest, ReplicaCasExpectation, SlotInspectState,
};
use agy_switch_cli::session::payload::{
    bytes_sha256_hex, parse_session_payload_bytes, serialize_session_payload,
    serialize_session_payload_for_account,
};
use agy_switch_cli::session::process::ProcessLease;
use agy_switch_cli::store::fs_atomic::ensure_private_dir;
use agy_switch_cli::store::locks::ActiveSlotLock;
use agy_switch_cli::switching::executor::{
    execute_switch, execute_switch_with_slot_lock, preview_switch_dry_run, SwitchOptions,
};
use common::{
    make_synthetic_account, make_usage_outcome, run_isolated_subtest, write_fake_agy_script,
    IsolatedEnv, SlotQuotaRunner,
};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

static PROC_ENV_MUTEX: AsyncMutex<()> = AsyncMutex::const_new(());

fn build_quota(
    now: i64,
    primary_frac: f64,
    weekly_frac: f64,
    short_5h_frac: Option<f64>,
    reset_rfc3339: &str,
) -> QuotaObservation {
    let mut q = QuotaObservation::new(now, QuotaSourceEnv::Production);
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
        description: Some("Models within this group: Gemini 3.8 Flash, Gemini 4 Hydrogen".into()),
        buckets,
    }]);
    q
}

#[test]
fn quota_eval_enforces_min_triad_direct_weekly_only_argon_8hop_forwarding_and_reset_staleness() {
    let _guard = PROC_ENV_MUTEX.blocking_lock();
    let now = 1_800_000_000i64;
    let future_reset = "2099-01-01T00:00:00Z";
    let past_reset = "2020-01-01T00:00:00Z";

    // 1. min(weekly=60%, 5h=80%, primary=12%) == 12%!
    let q_triad = build_quota(now, 0.12, 0.60, Some(0.80), future_reset);
    assert_eq!(
        evaluate_quota_observation(&q_triad, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Known {
            remaining_percentage: 12.0
        }
    );

    // 2. Weekly-only bucket (no 5h bucket) evaluates directly without subscription_tier inference!
    let q_weekly_only = build_quota(now, 0.90, 0.45, None, future_reset);
    assert_eq!(
        evaluate_quota_observation(&q_weekly_only, "gemini", now, DEFAULT_QUOTA_MAX_AGE_SECS),
        QuotaEval::Known {
            remaining_percentage: 45.0
        }
    );

    // 3. `reset_time <= now` MUST evaluate to `Stale`, NEVER 100% recovered!
    let q_expired_reset = build_quota(now, 0.90, 0.90, Some(0.90), past_reset);
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
async fn managed_run_keeps_selected_supports_explicit_account_and_forwards_exit_code() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let bin_dir = env.tmp_path().join("bin");
    let trace_dir = env.tmp_path().join("trace");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&trace_dir).unwrap();

    let fake_agy = write_fake_agy_script(
        &bin_dir,
        "agy",
        &format!(
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
            data = env.data_dir.display(),
            trace = trace_dir.display()
        ),
    );

    let now = jiff::Timestamp::now().as_second();
    let paths = env.paths();
    let repo = env.repo();

    let mut acc_low = make_synthetic_account(
        "acc-low",
        "low@example.invalid",
        "1//RT_LOW",
        now + 7200,
        now,
    );
    acc_low.quota = Some(build_quota(
        now,
        0.02,
        0.02,
        Some(0.02),
        "2099-01-01T00:00:00Z",
    ));
    let mut acc_high = make_synthetic_account(
        "acc-high",
        "high@example.invalid",
        "1//RT_HIGH",
        now + 7200,
        now,
    );
    acc_high.quota = Some(build_quota(
        now,
        0.85,
        0.85,
        Some(0.85),
        "2099-01-01T00:00:00Z",
    ));

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_low.clone(), true, now)?;
        tx.upsert_account(acc_high.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    // Seed a legacy v1.2.x policy.json on disk to confirm it is silently ignored
    fs::write(
        env.data_dir.join("policy.json"),
        r#"{"schema_version":1,"enabled":true,"candidate_account_ids":["acc-high"]}"#,
    )
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_low.token).unwrap())
        .unwrap();

    // 1. Bare `run -- agy`: purely launches with selected `acc-low`, binds two-factor lease, forwards exit 42
    let out_bare = env
        .cli_cmd()
        .env_remove("AGY_SWITCH_CLI_PROC_ROOT")
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["run", "--", "agy", "-p", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        out_bare.status.code(),
        Some(42),
        "stderr={}",
        String::from_utf8_lossy(&out_bare.stderr)
    );
    let seen_slot_bare = fs::read_to_string(trace_dir.join("seen_slot.json")).unwrap();
    assert!(seen_slot_bare.contains("1//RT_LOW"));
    let lease_bare: ProcessLease =
        serde_json::from_slice(&fs::read(trace_dir.join("seen_lease.json")).unwrap()).unwrap();
    assert!(lease_bare.pid > 0);
    assert!(lease_bare.proc_starttime_ticks > 0);
    assert_eq!(lease_bare.account_id, "acc-low");
    assert_eq!(fs::read_dir(paths.leases_dir()).unwrap().count(), 0);

    // 2. Explicit `run --account acc-high -- agy`: switches slot to `acc-high`, updates switch timestamps, forwards 42
    let _ = fs::remove_file(trace_dir.join("seen_slot.json"));
    let _ = fs::remove_file(trace_dir.join("seen_lease.json"));
    let out = env
        .cli_cmd()
        .env_remove("AGY_SWITCH_CLI_PROC_ROOT")
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["run", "--account", "acc-high", "--", "agy", "-p", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(42),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen_slot = fs::read_to_string(trace_dir.join("seen_slot.json")).unwrap();
    assert!(seen_slot.contains("1//RT_HIGH"));
    let lease: ProcessLease =
        serde_json::from_slice(&fs::read(trace_dir.join("seen_lease.json")).unwrap()).unwrap();
    assert!(lease.pid > 0);
    assert!(lease.proc_starttime_ticks > 0);
    assert_eq!(lease.account_id, "acc-high");
    assert_eq!(fs::read_dir(paths.leases_dir()).unwrap().count(), 0);

    // Verify atomic switch timestamp updates (`last_switched_out_at` on acc-low, `last_switched_in_at` on acc-high)
    let low_after = repo.read_account_unchecked("acc-low").unwrap();
    let high_after = repo.read_account_unchecked("acc-high").unwrap();
    assert!(low_after.last_switched_out_at.is_some());
    assert!(high_after.last_switched_in_at.is_some());
}

#[tokio::test]
async fn managed_run_keeps_expired_slot_offline_and_isolates_dbus_on_explicit_file() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let bin_dir = env.tmp_path().join("bin");
    let trace_dir = env.tmp_path().join("trace");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&trace_dir).unwrap();

    let fake_agy = write_fake_agy_script(
        &bin_dir,
        "agy",
        &format!(
            "#!/bin/sh\n\
             printf '%s' \"$DBUS_SESSION_BUS_ADDRESS\" > \"{trace}/dbus_env.txt\"\n\
             cp \"{slot}\" \"{trace}/slot_seen.json\"\n\
             exit 0\n",
            trace = trace_dir.display(),
            slot = env.paths().active_slot_file.display(),
        ),
    );

    let now = 1_800_000_000i64;
    let paths = env.paths();
    let repo = env.repo();

    let acc = AccountRecord::new(
        "acc-same-rt".into(),
        "same@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.EXPIRED_SLOT_TOKEN".into(),
            refresh_token: "1//UNCHANGED_REFRESH_TOKEN".into(),
            expires_in: 3600,
            expiry_timestamp: now - 100,
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
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc.token).unwrap())
        .unwrap();

    let out = env
        .cli_cmd()
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/mock-bus", env.tmp_path().display()),
        )
        .args(["--backend", "file", "run", "--", fake_agy.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let slot_seen = fs::read_to_string(trace_dir.join("slot_seen.json")).unwrap();
    assert!(slot_seen.contains("1//UNCHANGED_REFRESH_TOKEN"));
    let dbus_seen = fs::read_to_string(trace_dir.join("dbus_env.txt")).unwrap();
    assert_eq!(dbus_seen, "unix:path=/dev/null");
}

#[tokio::test]
async fn quota_and_quota_all_evaluate_all_pools_without_policy_and_render_four_state_eval() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    let now = jiff::Timestamp::now().as_second();
    let repo = env.repo();

    let mut acc_gem = make_synthetic_account(
        "acc-gem",
        "gem@example.invalid",
        "1//RT_GEM",
        now + 7200,
        now,
    );
    acc_gem.quota = Some(build_quota(
        now,
        0.80,
        0.80,
        Some(0.80),
        "2099-01-01T00:00:00Z",
    ));

    let mut acc_stale = make_synthetic_account(
        "acc-stale",
        "stale@example.invalid",
        "1//RT_STALE",
        now + 7200,
        now,
    );
    acc_stale.quota = Some(build_quota(
        now - DEFAULT_QUOTA_MAX_AGE_SECS - 120,
        0.50,
        0.50,
        Some(0.50),
        "2099-01-01T00:00:00Z",
    ));

    let acc_unfetched = make_synthetic_account(
        "acc-none",
        "none@example.invalid",
        "1//RT_NONE",
        now + 7200,
        now,
    );

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_gem, true, now)?;
        tx.upsert_account(acc_stale, false, now)?;
        tx.upsert_account(acc_unfetched, false, now)?;
        Ok(())
    })
    .unwrap();

    // Seed legacy `policy.json` mentioning `"argon"` — v1.3.0 MUST ignore it and evaluate `"all"` directly!
    fs::write(
        env.data_dir.join("policy.json"),
        r#"{"schema_version":1,"monitored_model":"argon","enabled":true}"#,
    )
    .unwrap();

    // 1. `quota` evaluates `"all"` directly -> Known (80.0% effective on all), no Plan line, no per-model dump
    let out_gem = env.cli_cmd().arg("quota").output().unwrap();
    assert_eq!(out_gem.status.code(), Some(0));
    let txt_gem = String::from_utf8_lossy(&out_gem.stdout);
    assert!(
        txt_gem.contains("Status  : known (80.0% effective on all)"),
        "Unexpected quota output: {txt_gem}"
    );
    assert!(!txt_gem.contains("Plan"));
    assert!(!txt_gem.contains("gemini-3.8-flash"));

    // 2. `quota --all` renders known + stale + unknown without Plan
    let out_all = env.cli_cmd().args(["quota", "--all"]).output().unwrap();
    assert_eq!(out_all.status.code(), Some(0));
    let txt_all = String::from_utf8_lossy(&out_all.stdout);
    assert!(txt_all.contains("Status  : known (80.0% effective on all)"));
    assert!(txt_all.contains("Status  : stale (stale_quota, model=all)"));
    assert!(txt_all.contains("Status: unknown (no_quota, model=all) — no cached quota."));
    assert!(!txt_all.contains("Plan"));

    // 3. Stale cached quota in human mode displays cached table (exit 0 + --refresh hint),
    //    while `--json` preserves strict exit code 4 and omits `subscription_tier`!
    let out_stale_human = env
        .cli_cmd()
        .args(["quota", "stale@example.invalid"])
        .output()
        .unwrap();
    assert_eq!(out_stale_human.status.code(), Some(0));
    let txt_stale_human = String::from_utf8_lossy(&out_stale_human.stdout);
    assert!(txt_stale_human.contains("Account : stale@example.invalid"));
    assert!(txt_stale_human.contains("add --refresh to refresh"));

    let out_stale_json = env
        .cli_cmd()
        .args(["--json", "quota", "stale@example.invalid"])
        .output()
        .unwrap();
    assert_eq!(out_stale_json.status.code(), Some(4));

    let out_gem_json = env.cli_cmd().args(["--json", "quota"]).output().unwrap();
    assert_eq!(out_gem_json.status.code(), Some(0));
    let qj: serde_json::Value = serde_json::from_slice(&out_gem_json.stdout).unwrap();
    assert!(qj["quota"].get("subscription_tier").is_none());

    // 4. `current` displays supported models (no Plan), `accounts list --move` reorders cleanly,
    //    and official `/usage` `quota_groups` strips `"Models within this group:"` prefix with aligned colons!
    let out_current = env.cli_cmd().arg("current").output().unwrap();
    assert_eq!(out_current.status.code(), Some(0));
    let txt_current = String::from_utf8_lossy(&out_current.stdout);
    assert!(!txt_current.contains("Plan"));
    assert!(txt_current.contains("Supported models : 1 available (cached)"));
    assert!(txt_current.contains("gemini-3.8-flash"));

    // Seed official `/usage` quota_groups (empty `models`, 2 groups with redundant prefix) on `acc-gem`
    repo.with_write_lock(|tx| {
        let mut a = tx.load_account_opt("acc-gem")?.unwrap();
        let mut oq = QuotaObservation::new(now, QuotaSourceEnv::OfficialCli);
        oq.quota_groups = Some(vec![
            QuotaGroup {
                display_name: "Gemini Models".into(),
                description: Some(
                    "Models within this group: Gemini 4 Hydrogen, Gemini 3.8 Flash".into(),
                ),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "gemini-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.80,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "gemini-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.85,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
            QuotaGroup {
                display_name: "Claude and GPT models".into(),
                description: Some(
                    "MODELS WITHIN THIS GROUP: Claude Sonnet 4.6, GPT-OSS 120B".into(),
                ),
                buckets: vec![
                    QuotaBucket {
                        bucket_id: "claude-5h".into(),
                        window: "5h".into(),
                        remaining_fraction: 0.70,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-01T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                    QuotaBucket {
                        bucket_id: "claude-weekly".into(),
                        window: "weekly".into(),
                        remaining_fraction: 0.75,
                        remaining_fraction_known: Some(true),
                        reset_time: "2099-01-07T00:00:00Z".into(),
                        display_name: None,
                        description: None,
                    },
                ],
            },
        ]);
        a.quota = Some(oq);
        tx.save_account(&a)?;
        Ok(())
    })
    .unwrap();
    let out_current_groups = env.cli_cmd().arg("current").output().unwrap();
    assert_eq!(out_current_groups.status.code(), Some(0));
    let txt_groups = String::from_utf8_lossy(&out_current_groups.stdout);
    assert!(
        txt_groups.contains("Model groups     : 2 group(s) (from official agy /usage)"),
        "Expected Model groups header: {txt_groups}"
    );
    assert!(
        txt_groups.contains("  Gemini Models         : Gemini 4 Hydrogen, Gemini 3.8 Flash"),
        "Expected aligned Gemini Models line: {txt_groups}"
    );
    assert!(
        txt_groups.contains("  Claude and GPT models : Claude Sonnet 4.6, GPT-OSS 120B"),
        "Expected aligned Claude and GPT models line: {txt_groups}"
    );
    assert!(!txt_groups.contains("Models within this group:"));
    assert!(!txt_groups.contains("MODELS WITHIN THIS GROUP:"));

    let out_move = env
        .cli_cmd()
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
    let out_list = env.cli_cmd().args(["accounts", "list"]).output().unwrap();
    let txt_list = String::from_utf8_lossy(&out_list.stdout);
    assert!(txt_list
        .lines()
        .next()
        .unwrap()
        .contains("stale@example.invalid"));
    assert!(!txt_list.contains("Plan"));

    // 5. CLI account selectors strictly require `<ID|EMAIL>` (rejecting positional indices with exit 3)
    assert_eq!(
        env.cli_cmd()
            .args(["quota", "gem@example.invalid"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        env.cli_cmd()
            .args(["quota", "2"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(3)
    );
    env.init_agy_slot_dir();
    assert_eq!(
        env.cli_cmd()
            .args(["switch", "1", "--dry-run"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(3)
    );
    let out_sw_live = env
        .cli_cmd()
        .args(["switch", "stale@example.invalid"])
        .output()
        .unwrap();
    assert_eq!(out_sw_live.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out_sw_live.stdout).contains("stale@example.invalid"));
    let out_sw_dry = env
        .cli_cmd()
        .args(["switch", "acc-gem", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out_sw_dry.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out_sw_dry.stdout).contains("gem@example.invalid"));
}

#[tokio::test]
async fn managed_run_rejects_disabled_or_unscoped_synced_slot() {
    let _guard = PROC_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();
    let bin_dir = env.tmp_path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let spawned_marker = env.tmp_path().join("should_never_exist");
    let fake_agy = write_fake_agy_script(
        &bin_dir,
        "agy",
        &format!(
            "#!/bin/sh\ntouch \"{}\"\nexit 0\n",
            spawned_marker.display()
        ),
    );

    let now = jiff::Timestamp::now().as_second();
    let paths = env.paths();
    let repo = env.repo();

    let acc_slot = make_synthetic_account(
        "acc-slot",
        "slot@example.invalid",
        "1//RT_SLOT_OK",
        now + 7200,
        now,
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_slot.clone(), true, now)?;
        tx.mark_account_disabled("acc-slot", DisableReasonCode::Manual, None, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_slot.token).unwrap())
        .unwrap();

    for run_args in [
        vec!["run", "--account", "acc-slot", "--", "agy"],
        vec!["run", "--", "agy"],
    ] {
        let out = env
            .cli_cmd()
            .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
            .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
            .args(&run_args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(!spawned_marker.exists());
    }

    // Re-enable, strip `cloud-platform` scope while slot stays synced -> exit 6 + marks ScopeReauthRequired
    repo.with_write_lock(|tx| {
        let mut enabled = tx.mark_account_enabled("acc-slot")?;
        enabled.token.granted_scopes = Some(vec!["openid".into()]);
        tx.save_account(&enabled)
    })
    .unwrap();
    let out_scope = env
        .cli_cmd()
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .env("AGY_SWITCH_CLI_AGY_BIN", &fake_agy)
        .args(["run", "--", "agy"])
        .output()
        .unwrap();
    assert_eq!(out_scope.status.code(), Some(6));
    assert!(!spawned_marker.exists());
    assert_eq!(
        repo.read_account_unchecked("acc-slot")
            .unwrap()
            .disabled_code,
        Some(DisableReasonCode::ScopeReauthRequired)
    );
}

#[tokio::test]
async fn v122_validation_blocked_manual_switch_run_dry_run_and_refresh_unlock() {
    if std::env::var_os("AGY_SUBTEST_V122_PROC").is_none() {
        let tmp_proc = tempfile::tempdir().unwrap();
        run_isolated_subtest(
            "v122_validation_blocked_manual_switch_run_dry_run_and_refresh_unlock",
            "AGY_SUBTEST_V122_PROC",
            &[("AGY_SWITCH_CLI_PROC_ROOT", tmp_proc.path().as_os_str())],
        );
        return;
    }
    let _guard = PROC_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    let paths = env.paths();
    ensure_private_dir(&paths.active_slot_dir).unwrap();
    let repo = env.repo();
    let now = jiff::Timestamp::now().as_second();

    let mut acc_a = make_synthetic_account(
        "acc-v122-a",
        "alice@example.com",
        "1//RT_acc-v122-a",
        now + 7200,
        now,
    );
    acc_a.quota = Some(build_quota(
        now,
        0.02,
        0.02,
        Some(0.02),
        "2099-01-01T00:00:00Z",
    ));
    let mut acc_b = make_synthetic_account(
        "acc-v122-b",
        "bob@example.com",
        "1//RT_acc-v122-b",
        now + 7200,
        now,
    );
    acc_b.quota = Some(build_quota(
        now,
        0.90,
        0.90,
        Some(0.90),
        "2099-01-01T00:00:00Z",
    ));
    acc_b.validation_blocked = true;
    acc_b.validation_blocked_reason =
        Some("Google CloudCode returned HTTP 403 VALIDATION_REQUIRED.".into());
    let mut acc_c = make_synthetic_account(
        "acc-v122-c",
        "charlie@example.com",
        "1//RT_acc-v122-c",
        now + 7200,
        now,
    );
    acc_c.disabled = true;

    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), true, now)?;
        tx.upsert_account(acc_b.clone(), false, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        Ok(())
    })
    .unwrap();
    FileSessionBackend
        .write_slot(&paths, &serialize_session_payload(&acc_a.token).unwrap())
        .unwrap();

    let reg = OAuthClientRegistry::load(&paths).unwrap();

    // 1. Low-level L1 `execute_switch_with_slot_lock` strictly rejects `validation_blocked`
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

    // 2. `preview_switch_dry_run` allows `validation_blocked` with warning, rejects `disabled`
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

    // 3. Manual `execute_switch` switches into `acc-v122-b` while PRESERVING `validation_blocked = true`
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
            .validation_blocked
    );
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_acc-v122-b"));

    // 4. CLI `switch --dry-run --json` and `run` emit stderr notice & keep `validation_blocked = true`
    let bin_dir = env.tmp_path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let fake_agy =
        write_fake_agy_script(&bin_dir, "agy", "#!/bin/sh\necho FAKE_AGY_STDOUT\nexit 0\n");

    let dry_cli = env
        .cli_cmd()
        .args([
            "--backend",
            "file",
            "--json",
            "switch",
            "acc-v122-b",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert_eq!(dry_cli.status.code(), Some(0));
    let dry_j: serde_json::Value = serde_json::from_slice(&dry_cli.stdout).unwrap();
    assert_eq!(dry_j["switch"]["validation_blocked"], true);
    assert!(dry_j["switch"]["validation_warning"]
        .as_str()
        .unwrap()
        .contains("verify-blocked"));

    let run_selected = env
        .cli_cmd()
        .args(["--backend", "file", "run", "--", fake_agy.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(run_selected.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&run_selected.stdout).trim(),
        "FAKE_AGY_STDOUT"
    );
    assert!(String::from_utf8_lossy(&run_selected.stderr).contains("verify-blocked"));

    let sw_back = env
        .cli_cmd()
        .args(["--backend", "file", "switch", "acc-v122-a"])
        .output()
        .unwrap();
    assert_eq!(sw_back.status.code(), Some(0));
    assert!(sw_back.stderr.is_empty());

    let run_explicit = env
        .cli_cmd()
        .args([
            "--backend",
            "file",
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

    // 5. Clean official CLI `/usage` refresh auto-clears `validation_blocked`
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
async fn v127_dual_f01_symmetric_sync_back_and_superseded_rt_guard_for_refresh_and_manual_switch() {
    if std::env::var_os("AGY_SUBTEST_V127_F01").is_none() {
        let tmp_proc = tempfile::tempdir().unwrap();
        run_isolated_subtest(
            "v127_dual_f01_symmetric_sync_back_and_superseded_rt_guard_for_refresh_and_manual_switch",
            "AGY_SUBTEST_V127_F01",
            &[("AGY_SWITCH_CLI_PROC_ROOT", tmp_proc.path().as_os_str())],
        );
        return;
    }
    let _guard = PROC_ENV_MUTEX.lock().await;
    let env = IsolatedEnv::new();
    env.init_agy_slot_dir();

    let paths = env.paths();
    let repo = env.repo();
    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let now = 1_800_000_000i64;

    let acc_a = make_synthetic_account(
        "acc-a",
        "alice@example.com",
        "1//RT_R301_A",
        now + 7200,
        now,
    );
    let acc_b = make_synthetic_account("acc-b", "bob@example.com", "1//RT_R301_B", now + 7200, now);
    let acc_c = make_synthetic_account(
        "acc-c",
        "charlie@example.com",
        "1//RT_R301_C",
        now + 7200,
        now,
    );
    repo.with_write_lock(|tx| {
        tx.upsert_account(acc_a.clone(), false, now)?;
        tx.upsert_account(acc_b.clone(), true, now)?;
        tx.upsert_account(acc_c.clone(), false, now)?;
        Ok(())
    })
    .unwrap();

    struct SyntheticDualBackend {
        keyring: Arc<Mutex<Option<Vec<u8>>>>,
    }
    impl SyntheticDualBackend {
        fn new(initial: &str) -> Self {
            Self {
                keyring: Arc::new(Mutex::new(Some(initial.as_bytes().to_vec()))),
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
                keyring: Some(self.keyring_state()),
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
            let file_bytes = FileSessionBackend.snapshot_before_write(paths)?;
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
            *self.keyring.lock().unwrap() = Some(payload.as_bytes().to_vec());
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

    // 1a. Standalone `refresh_active_slot_quota_with_runner` under `dual` saves equal-AT &
    //     equal-expiry file-only rotated RT (exact baseline equality boundary!)
    let payload_b_init = serialize_session_payload_for_account(&acc_b).unwrap();
    FileSessionBackend
        .write_slot(&paths, &payload_b_init)
        .unwrap();
    let dual_direct_eq = SyntheticDualBackend::new(&payload_b_init);
    let file_direct_eq_path = paths.active_slot_file.clone();
    let eq_at = acc_b.token.access_token.clone();
    let eq_exp_iso = jiff::Timestamp::from_second(acc_b.token.expiry_timestamp)
        .unwrap()
        .to_string();
    let runner_direct_eq = SlotQuotaRunner::from_handler(move |_, _, _| {
        fs::write(
            &file_direct_eq_path,
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": eq_at,
                    "token_type": "Bearer",
                    "refresh_token": "1//RT_F01_B_DIRECT_EQ_REFRESH",
                    "expiry": eq_exp_iso
                },
                "id_token_email": "bob@example.com"
            }))
            .unwrap(),
        )
        .unwrap();
        Ok(make_usage_outcome(0.88, 0.90, "2099-01-01T00:00:00Z"))
    });
    let direct_eq_out = refresh_active_slot_quota_with_runner(
        &repo,
        &dual_direct_eq,
        &runner_direct_eq,
        false,
        Some("acc-b"),
        now + 204,
    )
    .await
    .unwrap();
    assert!(direct_eq_out.token_synced_back);
    assert_eq!(
        repo.read_account_unchecked("acc-b")
            .unwrap()
            .token
            .refresh_token,
        "1//RT_F01_B_DIRECT_EQ_REFRESH"
    );

    // 1b. Standalone `refresh_active_slot_quota_with_runner` under `dual` with OMITTED `expiry`
    //     on file-only rotated RT preserves rotated RT and falls back conservatively to `(1, 0)`!
    let b_after_eq = repo.read_account_unchecked("acc-b").unwrap();
    let payload_b_after_eq = serialize_session_payload_for_account(&b_after_eq).unwrap();
    FileSessionBackend
        .write_slot(&paths, &payload_b_after_eq)
        .unwrap();
    let dual_direct_omit = SyntheticDualBackend::new(&payload_b_after_eq);
    let file_direct_omit_path = paths.active_slot_file.clone();
    let runner_direct_omit = SlotQuotaRunner::from_handler(move |_, _, _| {
        fs::write(
            &file_direct_omit_path,
            serde_json::to_vec(&serde_json::json!({
                "token": {
                    "access_token": "ya29.B_OMIT_EXP_AT",
                    "token_type": "Bearer",
                    "refresh_token": "1//RT_F01_B_DIRECT_REFRESH"
                },
                "id_token_email": "bob@example.com"
            }))
            .unwrap(),
        )
        .unwrap();
        Ok(make_usage_outcome(0.86, 0.89, "2099-01-01T00:00:00Z"))
    });
    let direct_omit_out = refresh_active_slot_quota_with_runner(
        &repo,
        &dual_direct_omit,
        &runner_direct_omit,
        false,
        Some("acc-b"),
        now + 205,
    )
    .await
    .unwrap();
    assert!(direct_omit_out.token_synced_back);
    let b_after_omit = repo.read_account_unchecked("acc-b").unwrap();
    assert_eq!(
        b_after_omit.token.refresh_token,
        "1//RT_F01_B_DIRECT_REFRESH"
    );
    assert_eq!(
        b_after_omit.token.expiry_timestamp, 1,
        "F-01 + R2-02: rotated RT with omitted expiry must fall back conservatively to 1"
    );
    assert_eq!(b_after_omit.token.expires_in, 0);

    // 2. Manual `execute_switch` under `dual` saves equal-expiry file-only RT rotation before switching
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

    // 3. Mirror: keyring-only rotated RT with missing expiry beats file holding stored RT + 2099 expiry
    repo.with_write_lock(|tx| tx.commit_selected_account("acc-b", now + 215))
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

    // 4. Superseded historical RT in disk file with 2099 expiry MUST NOT roll back B's current RT
    repo.with_write_lock(|tx| tx.commit_selected_account("acc-b", now + 225))
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
        "1//RT_F01_B_KR_MIRROR"
    );

    // 5a. File-only external drift (effective keyring still holds saved `acc-c`, disk file drifted
    //     to foreign stranger): manual `execute_switch` cleanly overrides both replicas AND records
    //     `acc-c.last_switched_out_at` because the effective keyring slot genuinely held `acc-c`!
    let c_cur = repo.read_account_unchecked("acc-c").unwrap();
    let c_payload = serialize_session_payload_for_account(&c_cur).unwrap();
    let ext_payload = serde_json::to_string(&serde_json::json!({
        "token": {
            "access_token": "ya29.EXTERNAL",
            "token_type": "Bearer",
            "refresh_token": "1//RT_EXTERNAL_STRANGER",
            "expiry": "2099-01-01T00:00:00Z"
        },
        "id_token_email": "stranger@example.com"
    }))
    .unwrap();
    let dual_file_ext = SyntheticDualBackend::new(&c_payload);
    fs::write(&paths.active_slot_file, &ext_payload).unwrap();
    let man_file_ext = execute_switch(
        &repo,
        &dual_file_ext,
        &reg,
        "acc-a",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 235,
    )
    .unwrap();
    assert_eq!(man_file_ext.target_account_id, "acc-a");
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_R301_A"));
    assert_eq!(
        repo.read_account_unchecked("acc-c")
            .unwrap()
            .last_switched_out_at,
        Some(now + 235)
    );

    // 5b. Both replicas hold foreign external credential -> manual `execute_switch` cleanly overrides
    //     AND does NOT fabricate `last_switched_out_at` on stale selected `acc-a`!
    let a_prev_out = repo
        .read_account_unchecked("acc-a")
        .unwrap()
        .last_switched_out_at;
    let dual_ext = SyntheticDualBackend::new(&ext_payload);
    fs::write(&paths.active_slot_file, &ext_payload).unwrap();
    let man_res = execute_switch(
        &repo,
        &dual_ext,
        &reg,
        "acc-c",
        &SwitchOptions {
            dry_run: false,
            allow_running: true,
        },
        now + 240,
    )
    .unwrap();
    assert_eq!(man_res.target_account_id, "acc-c");
    assert!(fs::read_to_string(&paths.active_slot_file)
        .unwrap()
        .contains("1//RT_R301_C"));
    assert_eq!(
        repo.read_account_unchecked("acc-a")
            .unwrap()
            .last_switched_out_at,
        a_prev_out,
        "External drift switch-away must NOT fabricate last_switched_out_at on stale selected account"
    );
    assert_eq!(
        repo.read_account_unchecked("acc-c")
            .unwrap()
            .last_switched_in_at,
        Some(now + 240)
    );
}
