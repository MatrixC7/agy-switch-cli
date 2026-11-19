use agy_switch_cli::domain::account::{AccountRecord, DisableReasonCode};
use agy_switch_cli::domain::quota::QuotaSourceEnv;
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::error::ExitCode;
use agy_switch_cli::oauth::flow::{
    bind_loopback_listener, build_authorization_session, wait_for_loopback_callback,
    GOOGLE_AUTH_URL,
};
use agy_switch_cli::oauth::refresh::{
    complete_reauthorize_exchange_locked, ensure_account_token_fresh_locked,
    exchange_authorization_code, OAuthEndpoints,
};
use agy_switch_cli::oauth::registry::OAuthClientRegistry;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::quota::client::{refresh_account_quota_locked, CloudCodeEndpoints};
use agy_switch_cli::store::repository::StoreRepository;
use agy_switch_cli::transport::client::{HttpResponse, MockTransport, RequestBody, TransportError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn fast_oauth_endpoints() -> OAuthEndpoints {
    OAuthEndpoints {
        base_backoff: Duration::from_millis(5),
        ..OAuthEndpoints::default()
    }
}

fn fast_quota_endpoints() -> CloudCodeEndpoints {
    CloudCodeEndpoints {
        fallback_delay: Duration::from_millis(5),
        ..CloudCodeEndpoints::default()
    }
}

fn new_repo(tmp: &std::path::Path) -> StoreRepository {
    let paths = HeadlessPaths::with_explicit(tmp.join("home"), tmp.join("data"), tmp.join("cache"));
    StoreRepository::new(paths)
}

static OAUTH_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct ScopedEnv {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl ScopedEnv {
    fn set(key: &'static str, val: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, val);
        Self { key, prev }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

#[tokio::test]
async fn loopback_oauth_ignores_stray_requests_verifies_pkce_s256_and_records_true_scopes() {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let reg = OAuthClientRegistry::parse_from_raw(
        Some("custom_cli|cid-123|csec-456|Custom CLI"),
        Some("custom_cli"),
    );
    let client = reg.select_for_login(Some("custom_cli")).unwrap();
    let (listener, port) = bind_loopback_listener(None).await.unwrap();
    let session = build_authorization_session(client, port, GOOGLE_AUTH_URL).unwrap();
    let expected_state = session.state.clone();

    let driver = tokio::spawn(async move {
        // 1. Idle preconnect EOF -> must be ignored without closing listener
        let s1 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        drop(s1);

        // 2. Unrelated `/favicon.ico` -> 404, listener stays alive
        let mut s2 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s2.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let _ = s2.read(&mut buf).await;

        // 3. Wrong `state` parameter -> 400, listener stays alive for legitimate browser redirect
        let mut s3 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s3.write_all(
            b"GET /oauth-callback?code=wrong&state=spoofed HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await
        .unwrap();
        let _ = s3.read(&mut buf).await;

        // 4. Legitimate callback with matching single `state`
        let mut s4 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = format!(
            "GET /oauth-callback?code=AUTH_CODE_OK&state={expected_state} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        );
        s4.write_all(req.as_bytes()).await.unwrap();
        let n = s4.read(&mut buf).await.unwrap();
        let reply = String::from_utf8_lossy(&buf[..n]);
        assert!(reply.starts_with("HTTP/1.1 200 OK"));
    });

    let code = wait_for_loopback_callback(listener, &session.state, Duration::from_secs(5))
        .await
        .unwrap();
    driver.await.unwrap();
    assert_eq!(code, "AUTH_CODE_OK");

    // Verify `exchange_authorization_code` sends exact PKCE `code_verifier` matching `code_challenge`
    let expected_challenge = session.code_challenge.clone();
    let mock = MockTransport::from_handler(move |req| {
        let RequestBody::Form(ref pairs) = req.body else {
            panic!("expected form body");
        };
        let map: HashMap<_, _> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(map.get("client_id"), Some(&"cid-123"));
        assert_eq!(map.get("code"), Some(&"AUTH_CODE_OK"));
        let verifier = *map
            .get("code_verifier")
            .expect("missing PKCE code_verifier");
        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(computed, expected_challenge);

        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.pkce_ok",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "1//pkce_rt",
                "scope": "openid https://www.googleapis.com/auth/userinfo.email"
            }),
        ))
    });

    let token = exchange_authorization_code(
        &mock,
        &fast_oauth_endpoints(),
        "vscode/1.X.X (Antigravity/4.3.0)",
        &session,
        &code,
        1_800_000_000,
    )
    .await
    .unwrap();

    assert_eq!(token.oauth_client_key.as_deref(), Some("custom_cli"));
    assert_eq!(
        token.granted_scopes,
        Some(vec![
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
            "openid".to_string()
        ])
    );
}

#[tokio::test]
async fn concurrent_same_account_refresh_serializes_cleanly_under_strict_token_rotation() {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let now = 1_800_000_000i64;

    let initial = AccountRecord::new(
        "acc-rot".into(),
        "rot@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.at_0".into(),
            refresh_token: "1//RT_0".into(),
            expires_in: 3600,
            expiry_timestamp: now + 100,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(initial, true, now))
        .unwrap();

    // Strict rotation server: ONLY accepts the latest current `1//RT_<gen>` and rotates to `1//RT_<gen+1>`!
    // If two concurrent callers raced without L2 serialization, the second would send stale `1//RT_0` and fail with `invalid_grant`!
    let server_gen = Arc::new(Mutex::new(0usize));
    let sg = server_gen.clone();
    let mock = MockTransport::from_handler(move |req| {
        if req.url.contains("userinfo") {
            return Ok(MockTransport::json_response(
                200,
                json!({"email": "rot@example.invalid", "name": "Rot User"}),
            ));
        }
        let RequestBody::Form(ref pairs) = req.body else {
            panic!("expected form");
        };
        let rt = pairs
            .iter()
            .find(|(k, _)| k == "refresh_token")
            .unwrap()
            .1
            .as_str();
        let mut g = sg.lock().unwrap();
        let expected_rt = format!("1//RT_{}", *g);
        if rt != expected_rt {
            return Ok(MockTransport::json_response(
                400,
                json!({"error": "invalid_grant", "error_description": "stale rotated token reused!"}),
            ));
        }
        *g += 1;
        let next_rt = format!("1//RT_{}", *g);
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": format!("ya29.at_{}", *g),
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": next_rt,
            }),
        ))
    });

    let reg = OAuthClientRegistry::parse_from_raw(None, None);
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let r = repo.clone();
        let m = mock.clone();
        let rg = reg.clone();
        tasks.push(tokio::spawn(async move {
            ensure_account_token_fresh_locked(
                &r,
                &m,
                &fast_oauth_endpoints(),
                &rg,
                "vscode/1.X.X (Antigravity/4.3.0)",
                "acc-rot",
                true, // force_refresh = true so all 5 hit rotation sequentially!
                now,
            )
            .await
        }));
    }

    for t in tasks {
        t.await.unwrap().unwrap();
    }

    let final_acc = repo.read_account_unchecked("acc-rot").unwrap();
    assert_eq!(final_acc.token.refresh_token, "1//RT_5");
    assert_eq!(final_acc.token.access_token, "ya29.at_5");
    assert!(!final_acc.disabled);
}

#[tokio::test]
async fn client_binding_invalid_grant_single_shot_and_429_5xx_backoff_behave_per_rfc6749() {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let now = 1_800_000_000i64;

    let acc_bound = AccountRecord::new(
        "acc-bound".into(),
        "bound@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.old".into(),
            refresh_token: "1//bound-rt".into(),
            expires_in: 60,
            expiry_timestamp: now + 10,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("missing_custom_client".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc_bound, true, now))
        .unwrap();

    // 1. Missing bound client -> immediate exit code 6, ZERO HTTP calls, account NOT disabled!
    let mock_empty = MockTransport::default();
    let reg_default = OAuthClientRegistry::parse_from_raw(None, None);
    let err_missing = ensure_account_token_fresh_locked(
        &repo,
        &mock_empty,
        &fast_oauth_endpoints(),
        &reg_default,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-bound",
        true,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err_missing.exit_code, ExitCode::AuthOrClientError);
    assert_eq!(mock_empty.recorded_requests().len(), 0);
    assert!(!repo.read_account_unchecked("acc-bound").unwrap().disabled);

    // 2. Register `missing_custom_client` alongside builtin; test `invalid_client` -> NO fallback to builtin, NO disable!
    let reg_two = OAuthClientRegistry::parse_from_raw(
        Some("missing_custom_client|cid-x|sec-x|Custom X"),
        None,
    );
    let mock_mismatch = MockTransport::from_queue([Ok(MockTransport::json_response(
        401,
        json!({"error": "invalid_client"}),
    ))]);
    let err_mismatch = ensure_account_token_fresh_locked(
        &repo,
        &mock_mismatch,
        &fast_oauth_endpoints(),
        &reg_two,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-bound",
        true,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err_mismatch.exit_code, ExitCode::AuthOrClientError);
    assert_eq!(mock_mismatch.recorded_requests().len(), 1);
    assert!(!repo.read_account_unchecked("acc-bound").unwrap().disabled);

    // 3. HTTP 429 + HTTP 503 + Transport timeout -> bounded backoff succeeds on 4th attempt!
    let mut headers_429 = HashMap::new();
    headers_429.insert("retry-after".into(), "0".into());
    let mock_backoff = MockTransport::from_queue([
        Ok(HttpResponse {
            status: 429,
            headers: headers_429,
            body: br#"{"error":"rate_limit_exceeded"}"#.to_vec(),
        }),
        Ok(MockTransport::json_response(
            503,
            json!({"error": "unavailable"}),
        )),
        Err(TransportError {
            is_timeout: true,
            is_connect: false,
            message: "simulated transient timeout".into(),
        }),
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.recovered_after_backoff",
                "expires_in": 3600,
                "token_type": "Bearer"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "bound@example.invalid", "name": "Bound"}),
        )),
    ]);
    let ok_out = ensure_account_token_fresh_locked(
        &repo,
        &mock_backoff,
        &fast_oauth_endpoints(),
        &reg_two,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-bound",
        true,
        now,
    )
    .await
    .unwrap();
    assert_eq!(
        ok_out.account.token.access_token,
        "ya29.recovered_after_backoff"
    );

    // 4. `invalid_grant` -> ZERO retries (exactly 1 request!), marks `disabled = true` + `RevokedOrExpiredGrant`!
    let mock_revoked = MockTransport::from_queue([Ok(MockTransport::json_response(
        400,
        json!({"error": "invalid_grant"}),
    ))]);
    let err_revoked = ensure_account_token_fresh_locked(
        &repo,
        &mock_revoked,
        &fast_oauth_endpoints(),
        &reg_two,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-bound",
        true,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err_revoked.exit_code, ExitCode::AuthOrClientError);
    assert_eq!(mock_revoked.recorded_requests().len(), 1);
    let disabled_acc = repo.read_account_unchecked("acc-bound").unwrap();
    assert!(disabled_acc.disabled);
    assert_eq!(
        disabled_acc.disabled_code,
        Some(DisableReasonCode::RevokedOrExpiredGrant)
    );
}

#[tokio::test]
async fn quota_401_triggers_single_forced_token_refresh_persists_rotation_and_uses_production_first(
) {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let now = 1_800_000_000i64;

    // Account has a seemingly unexpired access_token ("ya29.stale_revoked_at"), so initial pre-check does NOT refresh,
    // forcing CloudCode HTTP 401 to exercise the repaired 401 -> forced refresh -> retry loop!
    let acc = AccountRecord::new(
        "acc-q".into(),
        "q@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.stale_revoked_at".into(),
            refresh_token: "1//initial_q_rt".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: Some("bad-proj".into()),
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    let call_seq = Arc::new(AtomicUsize::new(0));
    let seq = call_seq.clone();
    let mock = MockTransport::from_handler(move |req| {
        let step = seq.fetch_add(1, Ordering::SeqCst);
        match step {
            // Step 0: loadCodeAssist MUST hit Daily first (`daily-cloudcode-pa.googleapis.com`) -> returns 401!
            0 => {
                assert_eq!(
                    req.url,
                    "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
                );
                Ok(MockTransport::json_response(
                    401,
                    json!({"error": "UNAUTHENTICATED"}),
                ))
            }
            // Step 1: Forced OAuth refresh triggered by 401 -> returns rotated RT!
            1 => {
                assert!(req.url.contains("oauth2.googleapis.com/token"));
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "access_token": "ya29.fresh_after_401",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "refresh_token": "1//rotated_after_401"
                    }),
                ))
            }
            // Step 2: Optional userinfo lookup
            2 if req.url.contains("userinfo") => Ok(MockTransport::json_response(
                200,
                json!({"email": "q@example.invalid", "name": "Quota User"}),
            )),
            // Replay loadCodeAssist on Daily
            2 | 3 if req.url.ends_with(":loadCodeAssist") => {
                assert_eq!(
                    req.url,
                    "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
                );
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "cloudaicompanionProject": "proj-restricted",
                        "paidTier": {"id": "g1-pro-tier", "name": "Google AI Pro"}
                    }),
                ))
            }
            // Replay fetchAvailableModels with project -> 403 triggers same-endpoint `{}` strip-project retry!
            n if req.url.ends_with(":fetchAvailableModels") => {
                assert_eq!(
                    req.url,
                    "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels"
                );
                if let RequestBody::Json(ref val) = req.body {
                    if val.get("project").is_some() {
                        return Ok(MockTransport::json_response(403, json!({})));
                    }
                }
                let _ = n;
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "models": {
                            "gemini-3.8-flash": {
                                "displayName": "Gemini 3.8 Flash",
                                "quotaInfo": {"remainingFraction": 0.42, "resetTime": "2099-01-01T02:00:00Z"}
                            }
                        }
                    }),
                ))
            }
            // retrieveUserQuotaSummary on Daily: first 403 retries with short UA `"antigravity"` -> 200!
            _ if req.url.ends_with(":retrieveUserQuotaSummary") => {
                assert_eq!(
                    req.url,
                    "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
                );
                let ua = req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                    .unwrap()
                    .1
                    .as_str();
                if ua != "antigravity" {
                    return Ok(MockTransport::json_response(403, json!({})));
                }
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "groups": [{
                            "displayName": "Gemini Models",
                            "buckets": [
                                {"bucketId": "gemini-5h", "window": "5h", "remainingFraction": 0.80, "resetTime": "2099-01-01T05:00:00Z"},
                                {"bucketId": "gemini-weekly", "window": "weekly", "remainingFraction": 0.60, "resetTime": "2099-01-07T00:00:00Z"}
                            ]
                        }]
                    }),
                ))
            }
            other => panic!("unexpected mock call step {other}: {:?}", req),
        }
    });

    let updated = refresh_account_quota_locked(
        &repo,
        &mock,
        &fast_oauth_endpoints(),
        &fast_quota_endpoints(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "antigravity/hub/4.3.0 (os_type=linux; arch=amd64)",
        "acc-q",
        now,
    )
    .await
    .unwrap();

    // Rotated refresh_token WAS persisted AND NOT clobbered by subsequent quota merge!
    assert_eq!(updated.token.refresh_token, "1//rotated_after_401");
    assert_eq!(updated.token.access_token, "ya29.fresh_after_401");
    let q = updated.quota.unwrap();
    assert_eq!(q.source_env, QuotaSourceEnv::Daily);
    assert_eq!(q.summary_source_env, Some(QuotaSourceEnv::Daily));
    assert_eq!(q.subscription_tier.as_deref(), Some("Google AI Pro"));
    // Primary model fraction (42%) is lower than summary (60%/80%), so primary limit 42% is preserved!
    assert_eq!(q.models[0].percentage, 42);
}

#[tokio::test]
async fn quota_all_endpoints_transport_failure_terminates_cleanly_after_three_environments() {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let now = 1_800_000_000i64;

    let acc = AccountRecord::new(
        "acc-netfail".into(),
        "netfail@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.valid".into(),
            refresh_token: "1//rt_valid".into(),
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
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    // Empty MockTransport returns TransportError on every call
    let mock = MockTransport::default();
    let err = refresh_account_quota_locked(
        &repo,
        &mock,
        &fast_oauth_endpoints(),
        &fast_quota_endpoints(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-netfail",
        now,
    )
    .await
    .unwrap_err();

    assert_eq!(err.error_code, "quota_network_error");
    // 3 loadCodeAssist attempts + 3 fetchAvailableModels attempts = 6 bounded requests!
    assert_eq!(mock.recorded_requests().len(), 6);
}

#[tokio::test]
async fn rotated_refresh_token_is_persisted_immediately_before_slow_or_cancelled_userinfo() {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let now = 1_800_000_000i64;

    // Account has `name: None` so `ensure_account_token_fresh_locked` will attempt `fetch_userinfo` after `/token`
    let acc = AccountRecord::new(
        "acc-cancel".into(),
        "cancel@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.old".into(),
            refresh_token: "1//OLD_BEFORE_CANCEL".into(),
            expires_in: 60,
            expiry_timestamp: now + 10,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc, true, now))
        .unwrap();

    struct SlowUserinfoTransport;
    impl agy_switch_cli::transport::client::HttpTransport for SlowUserinfoTransport {
        fn execute<'a>(
            &'a self,
            req: agy_switch_cli::transport::client::HttpRequest,
        ) -> agy_switch_cli::transport::client::BoxFuture<'a, Result<HttpResponse, TransportError>>
        {
            Box::pin(async move {
                if req.url.contains("userinfo") {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    unreachable!()
                }
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "access_token": "ya29.NEW_SAVED",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "refresh_token": "1//ROTATED_MUST_SURVIVE_CANCEL"
                    }),
                ))
            })
        }
    }

    // Cancel the future at 30ms right inside `fetch_userinfo().await`!
    let timed_out = tokio::time::timeout(
        Duration::from_millis(30),
        ensure_account_token_fresh_locked(
            &repo,
            &SlowUserinfoTransport,
            &fast_oauth_endpoints(),
            &OAuthClientRegistry::parse_from_raw(None, None),
            "vscode/1.X.X (Antigravity/4.3.0)",
            "acc-cancel",
            true,
            now,
        ),
    )
    .await;
    assert!(timed_out.is_err(), "Expected timeout inside slow userinfo");

    // CRITICAL: Rotated refresh_token MUST already be persisted on disk!
    let on_disk = repo.read_account_unchecked("acc-cancel").unwrap();
    assert_eq!(
        on_disk.token.refresh_token,
        "1//ROTATED_MUST_SURVIVE_CANCEL"
    );
    assert_eq!(on_disk.token.access_token, "ya29.NEW_SAVED");
}

#[tokio::test]
async fn validation_required_403_marks_blocked_hides_url_clears_on_200_and_merges_legacy_email() {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let now = 1_800_000_000i64;

    // 1. Legacy account imported with `oauth_client_key: None`, then re-upserted with `Some("antigravity_enterprise")`
    //    and a NEW refresh_token -> MUST merge into existing account rather than creating duplicate email!
    let legacy = AccountRecord::new(
        "acc-leg".into(),
        "user@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.leg".into(),
            refresh_token: "1//OLD_LEG_RT".into(),
            expires_in: 3600,
            expiry_timestamp: now + 3600,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: None,
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    let fresh_login = AccountRecord::new(
        "acc-new-uuid".into(),
        "USER@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.fresh".into(),
            refresh_token: "1//NEW_LOGIN_RT".into(),
            expires_in: 3600,
            expiry_timestamp: now + 3600,
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
        now + 1,
    );
    repo.with_write_lock(|tx| {
        let (_, created1) = tx.upsert_account(legacy, true, now)?;
        assert!(created1);
        let (merged, created2) = tx.upsert_account(fresh_login, true, now + 1)?;
        assert!(
            !created2,
            "Re-login must merge into legacy record instead of duplicating email"
        );
        assert_eq!(merged.id, "acc-leg");
        assert_eq!(merged.token.refresh_token, "1//NEW_LOGIN_RT");
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.read_snapshot().unwrap().accounts.len(), 1);

    // 2. CloudCode 403 `VALIDATION_REQUIRED` sets `validation_blocked = true` and hides `validation_url` from DTOs
    let mock_403 = MockTransport::from_handler(|req| {
        if req.url.ends_with(":loadCodeAssist") {
            return Ok(MockTransport::json_response(200, json!({})));
        }
        Ok(MockTransport::json_response(
            403,
            json!({
                "error": {
                    "status": "PERMISSION_DENIED",
                    "message": "Verify your account to continue (VALIDATION_REQUIRED)",
                    "details": [{"validationUrl": "https://accounts.google.com/SECRET_VERIFY_TOKEN_999"}]
                }
            }),
        ))
    });

    let blocked = refresh_account_quota_locked(
        &repo,
        &mock_403,
        &fast_oauth_endpoints(),
        &fast_quota_endpoints(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-leg",
        now + 2,
    )
    .await
    .unwrap();
    assert!(blocked.validation_blocked);
    assert_eq!(
        blocked.validation_url.as_deref(),
        Some("https://accounts.google.com/SECRET_VERIFY_TOKEN_999")
    );
    let dto_json = serde_json::to_string(
        &agy_switch_cli::cli::dto::AccountViewDto::from_record_at(&blocked, true, now + 2),
    )
    .unwrap();
    assert!(!dto_json.contains("SECRET_VERIFY_TOKEN_999"));

    // 3. Subsequent HTTP 200 quota refresh automatically clears `validation_blocked` and `validation_url`!
    let mock_200 = MockTransport::from_handler(|req| {
        if req.url.ends_with(":loadCodeAssist") {
            return Ok(MockTransport::json_response(200, json!({})));
        }
        if req.url.ends_with(":fetchAvailableModels") {
            return Ok(MockTransport::json_response(
                200,
                json!({"models": {"gemini-3.8-flash": {"quotaInfo": {"remainingFraction": 0.9, "resetTime": "2099-01-01T00:00:00Z"}}}}),
            ));
        }
        Ok(MockTransport::json_response(404, json!({})))
    });
    let cleared = refresh_account_quota_locked(
        &repo,
        &mock_200,
        &fast_oauth_endpoints(),
        &fast_quota_endpoints(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-leg",
        now + 10,
    )
    .await
    .unwrap();
    assert!(!cleared.validation_blocked);
    assert!(cleared.validation_url.is_none());
}

#[tokio::test]
async fn scope_reauth_required_is_set_on_missing_known_scopes_and_upstream_insufficient_scope() {
    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let _c1 = ScopedEnv::set("ANTIGRAVITY_OAUTH_CLIENTS", "");
    let _c2 = ScopedEnv::set("ANTIGRAVITY_OAUTH_CLIENT_KEY", "");
    let _c3 = ScopedEnv::set("ANTIGRAVITY_REQUIRED_SCOPES", "");
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let now = 1_800_000_000i64;

    // 0. Default `OAuthClientRegistry` (with ZERO `config.json`!) MUST require `cloud-platform` when `granted_scopes` is `Some(...)`!
    let default_reg = OAuthClientRegistry::load(repo.paths()).unwrap();
    let acc_missing_cp = AccountRecord::new(
        "acc-missing-cp".into(),
        "nocp@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.only_openid".into(),
            refresh_token: "1//ONLY_OPENID_RT".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: Some(vec![
                "openid".into(),
                "https://www.googleapis.com/auth/userinfo.email".into(),
            ]),
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc_missing_cp, true, now))
        .unwrap();
    let err_default_cp = ensure_account_token_fresh_locked(
        &repo,
        &MockTransport::default(),
        &fast_oauth_endpoints(),
        &default_reg,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-missing-cp",
        false,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err_default_cp.exit_code, ExitCode::AuthOrClientError);
    assert_eq!(err_default_cp.error_code, "scope_reauth_required");
    assert_eq!(
        repo.read_account_unchecked("acc-missing-cp")
            .unwrap()
            .disabled_code,
        Some(DisableReasonCode::ScopeReauthRequired)
    );

    // Write `config.json` requiring `aicode` scope on a custom client profile (Blueprint §4.1)
    std::fs::create_dir_all(&repo.paths().data_dir).unwrap();
    std::fs::write(
        repo.paths().config_file(),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "oauth": {
                "active_client_key": "custom_agy_v2",
                "clients": [{
                    "key": "custom_agy_v2",
                    "client_id": "cid-v2.apps.googleusercontent.com",
                    "client_secret": "GOCSPX-v2-secret-never-leaked",
                    "label": "Custom Agy v2",
                    "request_scopes": [
                        "openid",
                        "https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/aicode"
                    ],
                    "required_scopes": [
                        "openid",
                        "https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/aicode"
                    ]
                }]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let reg = OAuthClientRegistry::load(repo.paths()).unwrap();
    assert_eq!(reg.select_for_login(None).unwrap().key, "custom_agy_v2");

    // 1. Legacy account whose refresh returns a ROTATED refresh_token, but granted `scope` lacks `aicode`!
    //    RFC 6749 §6: refresh cannot upgrade scopes -> MUST save rotated refresh_token AND mark `ScopeReauthRequired`!
    let acc_legacy_scope = AccountRecord::new(
        "acc-scope-known".into(),
        "scope1@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.expired".into(),
            refresh_token: "1//OLD_SCOPE_RT".into(),
            expires_in: 60,
            expiry_timestamp: now - 10,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("custom_agy_v2".into()),
            granted_scopes: None,
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc_legacy_scope, true, now))
        .unwrap();

    let mock_narrow_scope = MockTransport::from_queue([Ok(MockTransport::json_response(
        200,
        json!({
            "access_token": "ya29.new_narrow_at",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "1//ROTATED_SCOPE_RT_PRESERVED",
            "scope": "openid https://www.googleapis.com/auth/cloud-platform"
        }),
    ))]);

    let err_known = ensure_account_token_fresh_locked(
        &repo,
        &mock_narrow_scope,
        &fast_oauth_endpoints(),
        &reg,
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-scope-known",
        false,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err_known.exit_code, ExitCode::AuthOrClientError);
    assert_eq!(err_known.error_code, "scope_reauth_required");
    assert!(err_known
        .message
        .contains("auth reauthorize acc-scope-known"));

    let saved1 = repo.read_account_unchecked("acc-scope-known").unwrap();
    assert_eq!(
        saved1.token.refresh_token, "1//ROTATED_SCOPE_RT_PRESERVED",
        "Rotated refresh_token MUST be preserved even when scopes are insufficient!"
    );
    assert!(saved1.disabled);
    assert_eq!(
        saved1.disabled_code,
        Some(DisableReasonCode::ScopeReauthRequired)
    );

    // 2. Imported bare-token account (`granted_scopes: None`) hitting CloudCode HTTP 403 `ACCESS_TOKEN_SCOPE_INSUFFICIENT`
    let acc_upstream_403 = AccountRecord::new(
        "acc-scope-upstream".into(),
        "scope2@example.invalid".into(),
        TokenRecord {
            access_token: "ya29.valid_at_missing_scope".into(),
            refresh_token: "1//BARE_IMPORT_RT".into(),
            expires_in: 7200,
            expiry_timestamp: now + 7200,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: None, // Unknown locally!
            project_id: None,
            is_gcp_tos: true,
        },
        now,
    );
    repo.with_write_lock(|tx| tx.upsert_account(acc_upstream_403, false, now))
        .unwrap();

    let mock_cloudcode_scope = MockTransport::from_queue([Ok(MockTransport::json_response(
        403,
        json!({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "Request had insufficient authentication scopes.",
                "details": [{"reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]
            }
        }),
    ))]);

    let err_upstream = refresh_account_quota_locked(
        &repo,
        &mock_cloudcode_scope,
        &fast_oauth_endpoints(),
        &fast_quota_endpoints(),
        &OAuthClientRegistry::parse_from_raw(None, None),
        "vscode/1.X.X (Antigravity/4.3.0)",
        "acc-scope-upstream",
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err_upstream.exit_code, ExitCode::AuthOrClientError);
    assert_eq!(err_upstream.error_code, "scope_reauth_required");
    assert!(err_upstream
        .message
        .contains("auth reauthorize acc-scope-upstream"));
    assert_eq!(
        mock_cloudcode_scope.recorded_requests().len(),
        1,
        "Insufficient-scope 403 must fail immediately without cross-endpoint retries"
    );

    let saved2 = repo.read_account_unchecked("acc-scope-upstream").unwrap();
    assert!(saved2.disabled);
    assert_eq!(
        saved2.disabled_code,
        Some(DisableReasonCode::ScopeReauthRequired)
    );

    // 3. `auth reauthorize` (`complete_reauthorize_exchange_locked`):
    //    - If user still leaves required `aicode` unchecked on consent screen, MUST save newly issued
    //      `refresh_token`, keep `disabled = true` + `ScopeReauthRequired`, and fail with exit code 6!
    //    - Once user approves all required scopes, clears `disabled` cleanly!
    let custom_client = reg.select_for_login(Some("custom_agy_v2")).unwrap();
    let reauth_session =
        build_authorization_session(custom_client, 54545, GOOGLE_AUTH_URL).unwrap();
    let existing_scope_acc = repo.read_account_unchecked("acc-scope-known").unwrap();

    let mock_reauth_incomplete = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.reauth_still_narrow",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "1//REAUTH_STILL_NARROW_RT_SAVED",
                "scope": "openid https://www.googleapis.com/auth/cloud-platform"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "scope1@example.invalid", "name": "Scope One"}),
        )),
    ]);

    let reauth_err = complete_reauthorize_exchange_locked(
        &repo,
        &mock_reauth_incomplete,
        &fast_oauth_endpoints(),
        &reg,
        "vscode/1.X.X (Antigravity/4.3.0)",
        &existing_scope_acc,
        &reauth_session,
        "4/reauth-incomplete-code",
        now + 20,
    )
    .await
    .unwrap_err();
    assert_eq!(reauth_err.exit_code, ExitCode::AuthOrClientError);
    assert_eq!(reauth_err.error_code, "scope_reauth_required");
    let still_disabled = repo.read_account_unchecked("acc-scope-known").unwrap();
    assert!(
        still_disabled.disabled,
        "Reauthorization missing required scope MUST NOT re-enable account!"
    );
    assert_eq!(
        still_disabled.disabled_code,
        Some(DisableReasonCode::ScopeReauthRequired)
    );
    assert_eq!(
        still_disabled.token.refresh_token,
        "1//REAUTH_STILL_NARROW_RT_SAVED"
    );

    let mock_reauth_full = MockTransport::from_queue([
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.reauth_full_ok",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "1//REAUTH_FULL_OK_RT",
                "scope": "openid https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/aicode"
            }),
        )),
        Ok(MockTransport::json_response(
            200,
            json!({"email": "scope1@example.invalid", "name": "Scope One"}),
        )),
    ]);

    let reauthed = complete_reauthorize_exchange_locked(
        &repo,
        &mock_reauth_full,
        &fast_oauth_endpoints(),
        &reg,
        "vscode/1.X.X (Antigravity/4.3.0)",
        &still_disabled,
        &reauth_session,
        "4/reauth-full-code",
        now + 30,
    )
    .await
    .unwrap();
    assert!(!reauthed.disabled);
    assert_eq!(reauthed.disabled_code, None);
    assert_eq!(reauthed.token.refresh_token, "1//REAUTH_FULL_OK_RT");
}

#[tokio::test]
async fn socks5h_remote_dns_config_file_proxy_no_proxy_and_loopback_bypass_work_end_to_end() {
    use agy_switch_cli::transport::client::{
        HttpRequest, HttpTransport, ReqwestTransport, TimeoutClass,
    };
    use agy_switch_cli::transport::proxy::ProxyMode;
    use tokio::net::TcpListener;

    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let _clear_https = ScopedEnv::set("HTTPS_PROXY", "");
    let _clear_https_l = ScopedEnv::set("https_proxy", "");
    let _clear_http = ScopedEnv::set("HTTP_PROXY", "");
    let _clear_http_l = ScopedEnv::set("http_proxy", "");
    let _clear_all = ScopedEnv::set("ALL_PROXY", "");
    let _clear_all_l = ScopedEnv::set("all_proxy", "");
    let _clear_np = ScopedEnv::set("NO_PROXY", "");
    let _clear_np_l = ScopedEnv::set("no_proxy", "");
    let _clear_cli = ScopedEnv::set("AGY_SWITCH_CLI_PROXY", "");

    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    std::fs::create_dir_all(&repo.paths().data_dir).unwrap();

    // 1. Spawn a local mock HTTP server on `127.0.0.1:0`
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let http_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = http_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut req_buf = [0u8; 2048];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let first_line = String::from_utf8_lossy(&req_buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let body = format!("{{\"seen\":\"{first_line}\"}}");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });

    // 2. Spawn a local RFC 1928 SOCKS5 server on `127.0.0.1:0` that records `(atyp, target_host, target_port)`
    //    and relays all proxied streams to our local `127.0.0.1:http_port` server!
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = socks_listener.local_addr().unwrap().port();
    let observed_socks: Arc<Mutex<Vec<(u8, String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
    let obs_clone = observed_socks.clone();

    let socks_task = tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = socks_listener.accept().await else {
                break;
            };
            let obs = obs_clone.clone();
            tokio::spawn(async move {
                // Greeting: [VER=0x05, NMETHODS, METHODS...]
                let mut hdr = [0u8; 2];
                if client.read_exact(&mut hdr).await.is_err() || hdr[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; hdr[1] as usize];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                // Reply: [0x05, 0x00 (NO AUTH)]
                if client.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }

                // Request: [VER=0x05, CMD=0x01, RSV=0x00, ATYP]
                let mut req_head = [0u8; 4];
                if client.read_exact(&mut req_head).await.is_err()
                    || req_head[0] != 0x05
                    || req_head[1] != 0x01
                {
                    return;
                }
                let atyp = req_head[3];
                let host = match atyp {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if client.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        if client.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut domain = vec![0u8; len[0] as usize];
                        if client.read_exact(&mut domain).await.is_err() {
                            return;
                        }
                        String::from_utf8_lossy(&domain).into_owned()
                    }
                    0x04 => {
                        let mut ip6 = [0u8; 16];
                        if client.read_exact(&mut ip6).await.is_err() {
                            return;
                        }
                        std::net::Ipv6Addr::from(ip6).to_string()
                    }
                    _ => return,
                };
                let mut port_bytes = [0u8; 2];
                if client.read_exact(&mut port_bytes).await.is_err() {
                    return;
                }
                let dst_port = u16::from_be_bytes(port_bytes);
                obs.lock().unwrap().push((atyp, host, dst_port));

                let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", http_port)).await else {
                    return;
                };
                // Reply SUCCEEDED: [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]
                if client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });

    // 3. Configure `<data_dir>/config.json` with `network.proxy_url = socks5h://...` and `network.no_proxy`!
    std::fs::write(
        repo.paths().config_file(),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "network": {
                "proxy_url": format!("socks5h://127.0.0.1:{socks_port}"),
                "no_proxy": "bypassed-via-config.example.invalid"
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let cfg = repo.read_config().unwrap();
    let proxy_mode = ProxyMode::resolve_with_config(None, Some(&cfg.network)).unwrap();
    let transport = ReqwestTransport::build(proxy_mode).unwrap();

    // A. Request to an unresolvable `.invalid` domain succeeds via `socks5h://` remote DNS (`ATYP == 0x03`)!
    let remote_resp = transport
        .execute(HttpRequest::get(
            format!("http://remote-dns-only.example.invalid:{http_port}/proxied-check"),
            TimeoutClass::VersionCheck,
        ))
        .await
        .unwrap();
    assert_eq!(remote_resp.status, 200);
    {
        let log = observed_socks.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0],
            (
                0x03,
                "remote-dns-only.example.invalid".to_string(),
                http_port
            ),
            "socks5h:// MUST send ATYP=0x03 domain name to proxy without local DNS lookup!"
        );
    }

    // B. Loopback URLs (`127.0.0.1` and `localhost`) MUST bypass SOCKS5 proxy completely!
    for loop_url in [
        format!("http://127.0.0.1:{http_port}/oauth-callback"),
        format!("http://localhost:{http_port}/oauth-callback"),
    ] {
        let loop_resp = transport
            .execute(HttpRequest::get(loop_url, TimeoutClass::VersionCheck))
            .await
            .unwrap();
        assert_eq!(loop_resp.status, 200);
    }
    assert_eq!(
        observed_socks.lock().unwrap().len(),
        1,
        "Loopback requests MUST NEVER traverse the SOCKS5 proxy!"
    );

    // C. Host matching `no_proxy` bypasses the SOCKS5 proxy (fails local DNS for `.invalid` with 0 SOCKS5 hits)
    let bypass_res = transport
        .execute(HttpRequest::get(
            format!("http://bypassed-via-config.example.invalid:{http_port}/direct"),
            TimeoutClass::VersionCheck,
        ))
        .await;
    assert!(bypass_res.is_err());
    assert_eq!(
        observed_socks.lock().unwrap().len(),
        1,
        "NO_PROXY matching host MUST bypass the SOCKS5 proxy!"
    );

    // D. CLI `--proxy direct` overrides `config.json` `network.proxy_url`
    assert_eq!(
        ProxyMode::resolve_with_config(Some("direct"), Some(&cfg.network)).unwrap(),
        ProxyMode::Direct
    );

    // E. Standard `ALL_PROXY=socks5h://...` + `NO_PROXY=env-bypass.example.invalid` env vars
    //    route non-bypassed domains via remote DNS (`ATYP == 0x03`) and bypass `NO_PROXY` hosts!
    {
        let _g5 = ScopedEnv::set("ALL_PROXY", &format!("socks5h://127.0.0.1:{socks_port}"));
        let _g6 = ScopedEnv::set("NO_PROXY", "env-bypass.example.invalid");

        let env_mode = ProxyMode::resolve(None).unwrap();
        let env_transport = ReqwestTransport::build(env_mode).unwrap();

        let ok_env_resp = env_transport
            .execute(HttpRequest::get(
                format!("http://env-proxied.example.invalid:{http_port}/env"),
                TimeoutClass::VersionCheck,
            ))
            .await
            .unwrap();
        assert_eq!(ok_env_resp.status, 200);
        assert_eq!(observed_socks.lock().unwrap().len(), 2);
        assert_eq!(
            observed_socks.lock().unwrap()[1],
            (0x03, "env-proxied.example.invalid".to_string(), http_port)
        );

        let bypass_env_res = env_transport
            .execute(HttpRequest::get(
                format!("http://env-bypass.example.invalid:{http_port}/direct"),
                TimeoutClass::VersionCheck,
            ))
            .await;
        assert!(bypass_env_res.is_err());
        assert_eq!(
            observed_socks.lock().unwrap().len(),
            2,
            "NO_PROXY env host MUST bypass SOCKS5 proxy!"
        );
    }

    // E2. Unnormalized desktop/CLI proxy env formats (`socks://127.0.0.1 <port>`, bare `127.0.0.1:<port>`,
    //     and broken `ALL_PROXY=pac+http://...` alongside valid `HTTPS_PROXY=127.0.0.1:<port>`) work cleanly!
    {
        let _g_socks_kde = ScopedEnv::set("ALL_PROXY", &format!("socks://127.0.0.1 {socks_port}"));
        let kde_mode = ProxyMode::resolve(None).unwrap();
        let kde_transport = ReqwestTransport::build(kde_mode).unwrap();
        let kde_resp = kde_transport
            .execute(HttpRequest::get(
                format!("http://kde-space-proxied.example.invalid:{http_port}/kde"),
                TimeoutClass::VersionCheck,
            ))
            .await
            .unwrap();
        assert_eq!(kde_resp.status, 200);
        assert_eq!(observed_socks.lock().unwrap().len(), 3);
        assert_eq!(
            observed_socks.lock().unwrap()[2],
            (
                0x03,
                "kde-space-proxied.example.invalid".to_string(),
                http_port
            )
        );
    }
    {
        let _g_https_bare = ScopedEnv::set("HTTPS_PROXY", &format!("127.0.0.1:{http_port}"));
        let _g_all_broken = ScopedEnv::set("ALL_PROXY", "pac+http://127.0.0.1/wpad.dat");
        let mixed_mode = ProxyMode::resolve(None).unwrap();
        assert!(ReqwestTransport::build(mixed_mode).is_ok());
    }

    // F. Authenticated RFC 1929 `socks5h://user:pass@127.0.0.1:<port>`:
    //    verifies username/password subnegotiation (`METHOD=0x02`, `VER=0x01`), `ATYP=0x03` remote DNS,
    //    and zero proxy-password leak when auth fails!
    let auth_socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_socks_port = auth_socks_listener.local_addr().unwrap().port();
    type SeenAuthEntry = (String, String, u8, String);
    let seen_auth: Arc<Mutex<Vec<SeenAuthEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_auth_c = seen_auth.clone();
    let auth_socks_task = tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = auth_socks_listener.accept().await else {
                break;
            };
            let sa = seen_auth_c.clone();
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if client.read_exact(&mut hdr).await.is_err() || hdr[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; hdr[1] as usize];
                if client.read_exact(&mut methods).await.is_err() || !methods.contains(&0x02) {
                    let _ = client.write_all(&[0x05, 0xFF]).await;
                    return;
                }
                if client.write_all(&[0x05, 0x02]).await.is_err() {
                    return;
                }
                // RFC 1929: [VER=0x01, ULEN, UNAME..., PLEN, PASSWD...]
                let mut sub_hdr = [0u8; 2];
                if client.read_exact(&mut sub_hdr).await.is_err() || sub_hdr[0] != 0x01 {
                    return;
                }
                let mut uname = vec![0u8; sub_hdr[1] as usize];
                if client.read_exact(&mut uname).await.is_err() {
                    return;
                }
                let mut plen = [0u8; 1];
                if client.read_exact(&mut plen).await.is_err() {
                    return;
                }
                let mut passwd = vec![0u8; plen[0] as usize];
                if client.read_exact(&mut passwd).await.is_err() {
                    return;
                }
                let u_str = String::from_utf8_lossy(&uname).into_owned();
                let p_str = String::from_utf8_lossy(&passwd).into_owned();
                if u_str != "socksuser" || p_str != "PROXY_PASS_SECRET_777" {
                    let _ = client.write_all(&[0x01, 0x01]).await;
                    return;
                }
                if client.write_all(&[0x01, 0x00]).await.is_err() {
                    return;
                }
                let mut req_head = [0u8; 4];
                if client.read_exact(&mut req_head).await.is_err() || req_head[3] != 0x03 {
                    return;
                }
                let mut dlen = [0u8; 1];
                if client.read_exact(&mut dlen).await.is_err() {
                    return;
                }
                let mut dom = vec![0u8; dlen[0] as usize];
                if client.read_exact(&mut dom).await.is_err() {
                    return;
                }
                let mut pbytes = [0u8; 2];
                if client.read_exact(&mut pbytes).await.is_err() {
                    return;
                }
                sa.lock().unwrap().push((
                    u_str,
                    p_str,
                    req_head[3],
                    String::from_utf8_lossy(&dom).into_owned(),
                ));
                let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", http_port)).await else {
                    return;
                };
                if client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });

    let auth_ok_mode = ProxyMode::resolve(Some(&format!(
        "socks5h://socksuser:PROXY_PASS_SECRET_777@127.0.0.1:{auth_socks_port}"
    )))
    .unwrap();
    let auth_ok_transport = ReqwestTransport::build(auth_ok_mode).unwrap();
    let auth_resp = auth_ok_transport
        .execute(HttpRequest::get(
            format!("http://rfc1929-remote.example.invalid:{http_port}/auth-ok"),
            TimeoutClass::VersionCheck,
        ))
        .await
        .unwrap();
    assert_eq!(auth_resp.status, 200);
    assert_eq!(
        seen_auth.lock().unwrap().as_slice(),
        &[(
            "socksuser".to_string(),
            "PROXY_PASS_SECRET_777".to_string(),
            0x03,
            "rfc1929-remote.example.invalid".to_string(),
        )]
    );

    let auth_bad_mode = ProxyMode::resolve(Some(&format!(
        "socks5h://socksuser:WRONG_SECRET_DO_NOT_LEAK@127.0.0.1:{auth_socks_port}"
    )))
    .unwrap();
    let auth_bad_transport = ReqwestTransport::build(auth_bad_mode).unwrap();
    let auth_err = auth_bad_transport
        .execute(HttpRequest::get(
            format!("http://rfc1929-remote.example.invalid:{http_port}/auth-fail"),
            TimeoutClass::VersionCheck,
        ))
        .await
        .unwrap_err();
    assert!(
        !auth_err.message.contains("WRONG_SECRET_DO_NOT_LEAK"),
        "Transport error leaked proxy password: {}",
        auth_err.message
    );

    auth_socks_task.abort();
    socks_task.abort();
    http_task.abort();
}

#[tokio::test]
async fn synthetic_accounts_add_from_local_reads_agy_slot_and_rejects_symlinks() {
    use agy_switch_cli::oauth::refresh::bootstrap_and_persist_refresh_token;
    use agy_switch_cli::session::backend::{read_local_active_refresh_token, FileSessionBackend};
    use base64::engine::general_purpose::STANDARD;
    use std::os::unix::fs::PermissionsExt;

    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let paths = repo.paths().clone();
    let backend = FileSessionBackend;

    // 1. Missing `antigravity-oauth-token` (even if `jetski-standalone-oauth-token` exists) -> AccountNotFound (exit 3)
    let gemini_dir = paths.home_dir.join(".gemini");
    std::fs::create_dir_all(&gemini_dir).unwrap();
    let standalone_path = gemini_dir.join("jetski-standalone-oauth-token");
    std::fs::write(
        &standalone_path,
        r#"{"token":{"refresh_token":"1//ignored"}}"#,
    )
    .unwrap();
    let err_missing = read_local_active_refresh_token(&paths, &backend).unwrap_err();
    assert_eq!(err_missing.exit_code, ExitCode::AccountNotFound);

    // 2. Official `~/.gemini/antigravity-cli/antigravity-oauth-token` (including `go-keyring-base64:` prefix) works
    std::fs::create_dir_all(&paths.active_slot_dir).unwrap();
    let agy_json = r#"{"token":{"access_token":"ya29.agy","token_type":"Bearer","refresh_token":"1//synthetic-agy-local-rt","expiry":"2099-01-01T00:00:00Z"},"auth_method":"consumer"}"#;
    let b64_payload = format!("go-keyring-base64:{}", STANDARD.encode(agy_json));
    std::fs::write(&paths.active_slot_file, b64_payload).unwrap();
    std::fs::set_permissions(
        &paths.active_slot_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let (rt_agy, src_agy) = read_local_active_refresh_token(&paths, &backend).unwrap();
    assert_eq!(src_agy, "agy_session_file");
    assert_eq!(rt_agy, "1//synthetic-agy-local-rt");

    // Verify end-to-end bootstrap + persistence with MockTransport
    let transport = MockTransport::from_handler(|req| {
        if req.url.ends_with("/token") {
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": "ya29.fresh-from-local",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "openid https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"
                }),
            ))
        } else {
            Ok(MockTransport::json_response(
                200,
                json!({
                    "email": "alice@example.com",
                    "name": "Alice Local"
                }),
            ))
        }
    });
    let registry = OAuthClientRegistry::parse_from_raw(None, None);
    let (saved, created) = bootstrap_and_persist_refresh_token(
        &repo,
        &transport,
        &fast_oauth_endpoints(),
        &registry,
        "antigravity/1.5.7 linux/amd64",
        &rt_agy,
        None,
        Some("本机账号"),
        1_800_000_000,
    )
    .await
    .unwrap();
    assert!(created);
    assert_eq!(saved.email, "alice@example.com");
    assert_eq!(saved.custom_label.as_deref(), Some("本机账号"));

    // 3. Symlinked `antigravity-oauth-token` MUST be rejected
    std::fs::remove_file(&paths.active_slot_file).unwrap();
    std::os::unix::fs::symlink(&standalone_path, &paths.active_slot_file).unwrap();
    assert!(read_local_active_refresh_token(&paths, &backend).is_err());
}

#[tokio::test]
async fn synthetic_v120_preflight_blocks_token_exchange_on_unwritable_store_and_warns_bad_env_proxy(
) {
    use agy_switch_cli::oauth::refresh::bootstrap_and_persist_refresh_token;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let _env_guard = OAUTH_ENV_MUTEX.lock().await;
    let registry = OAuthClientRegistry::parse_from_raw(None, None);

    // Child subprocess mode for P1-09 (b) (`before_write:pend-:enospc`):
    if std::env::var_os("AGY_SUBTEST_POST_EXCHANGE_FAULT").is_some() {
        let tmp2 = tempfile::tempdir().unwrap();
        let repo2 = new_repo(tmp2.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"access_token":"ya29.SUBPROC_AT_SECRET","refresh_token":"1//ROTATED_NEW_RT_SECRET_888","expires_in":3600,"token_type":"Bearer","scope":"openid https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let endpoints = agy_switch_cli::oauth::refresh::OAuthEndpoints {
            token_url: format!("http://{addr}/token"),
            userinfo_url: format!("http://{addr}/userinfo"),
            ..fast_oauth_endpoints()
        };
        let real_transport = agy_switch_cli::transport::client::ReqwestTransport::build(
            agy_switch_cli::transport::proxy::ProxyMode::Direct,
        )
        .unwrap();
        let post_err = bootstrap_and_persist_refresh_token(
            &repo2,
            &real_transport,
            &endpoints,
            &registry,
            "antigravity/1.5.7 linux/amd64",
            "1//ORIG_LOCAL_RT_SECRET_777",
            None,
            None,
            1_800_000_000,
        )
        .await
        .unwrap_err();
        let _ = server.await;

        assert_eq!(post_err.exit_code, ExitCode::PartialCommitOrRecovery);
        assert_eq!(post_err.error_code, "issued_token_unpersisted");
        let err_line = post_err.to_json_line();
        assert!(!err_line.contains("ORIG_LOCAL_RT_SECRET_777"));
        assert!(!err_line.contains("ROTATED_NEW_RT_SECRET_888"));
        assert!(!err_line.contains("SUBPROC_AT_SECRET"));
        let parsed_err: serde_json::Value = serde_json::from_str(&err_line).unwrap();
        assert_eq!(parsed_err["exit_code"], 7);
        assert_eq!(parsed_err["details"]["refresh_token_rotated"], true);
        return;
    }

    // 1. P1-09 (a): Obstructed `state/pending_auth` (symlink) MUST fail preflight BEFORE calling `/token`!
    let tmp = tempfile::tempdir().unwrap();
    let repo = new_repo(tmp.path());
    let paths = repo.paths().clone();
    std::fs::create_dir_all(paths.state_dir()).unwrap();
    std::fs::set_permissions(paths.state_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let outside_dir = tmp.path().join("outside_pending");
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::os::unix::fs::symlink(&outside_dir, paths.pending_auth_dir()).unwrap();

    let token_calls = Arc::new(AtomicUsize::new(0));
    let tc_clone = token_calls.clone();
    let transport = MockTransport::from_handler(move |_req| {
        tc_clone.fetch_add(1, Ordering::SeqCst);
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.should-never-be-called",
                "refresh_token": "1//rotated-would-have-been-lost",
                "expires_in": 3600,
                "token_type": "Bearer"
            }),
        ))
    });
    let preflight_err = bootstrap_and_persist_refresh_token(
        &repo,
        &transport,
        &fast_oauth_endpoints(),
        &registry,
        "antigravity/1.5.7 linux/amd64",
        "1//synthetic-unbuilt-local-rt",
        None,
        None,
        1_800_000_000,
    )
    .await
    .unwrap_err();
    assert_eq!(preflight_err.exit_code, ExitCode::GeneralOrDataError);
    assert_eq!(
        token_calls.load(Ordering::SeqCst),
        0,
        "Preflight MUST fail before issuing any `/token` network request!"
    );

    // 2. P1-09 (b): Post-exchange fault (`before_write:pend-:enospc`) after `/token` rotated the token
    //    MUST return exit code 7 (`issued_token_unpersisted`) with `refresh_token_rotated: true` and ZERO secret echo!
    let child_subtest = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", tmp.path())
        .env("AGY_SUBTEST_POST_EXCHANGE_FAULT", "1")
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_write:pend-:enospc")
        .args([
            "--exact",
            "synthetic_v120_preflight_blocks_token_exchange_on_unwritable_store_and_warns_bad_env_proxy",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        child_subtest.status.success(),
        "Post-exchange fault subtest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&child_subtest.stdout),
        String::from_utf8_lossy(&child_subtest.stderr)
    );

    // 3. P2-02: Malformed ambient `HTTPS_PROXY` emits variable-name-only stderr warning in human mode,
    //    while keeping `--json` stderr a pure single-line JSON error envelope!
    let tmp3 = tempfile::tempdir().unwrap();
    let home3 = tmp3.path().join("home");
    let data3 = tmp3.path().join("data");
    let cache3 = tmp3.path().join("cache");
    let run3 = tmp3.path().join("run");
    std::fs::create_dir_all(&home3).unwrap();
    std::fs::create_dir_all(&run3).unwrap();
    let repo3 = StoreRepository::new(agy_switch_cli::paths::HeadlessPaths::with_explicit(
        home3.clone(),
        data3.clone(),
        cache3.join("agy-switch-cli"),
    ));
    let seed_acc = AccountRecord::new(
        "acc-prx".into(),
        "alice@example.com".into(),
        TokenRecord {
            access_token: "ya29.seed".into(),
            refresh_token: "1//seed".into(),
            expires_in: 3600,
            expiry_timestamp: 1_900_000_000,
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
        1_800_000_000,
    );
    repo3
        .with_write_lock(|tx| tx.upsert_account(seed_acc, true, 1_800_000_000))
        .unwrap();

    // Use `ALL_PROXY` = unreachable `http://127.0.0.1:9` so no external traffic ever leaves localhost,
    // plus malformed `HTTPS_PROXY="badscheme://PROXY_SECRET_CRED_555@bad"` to trigger fallback warning!
    let human_out = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home3)
        .env("XDG_CACHE_HOME", &cache3)
        .env("XDG_RUNTIME_DIR", &run3)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-bus", run3.display()),
        )
        .env(
            "HTTPS_PROXY",
            "badscheme://PROXY_SECRET_CRED_555@example.invalid:8080",
        )
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .args([
            "--data-dir",
            data3.to_str().unwrap(),
            "--no-remote-version",
            "refresh",
        ])
        .output()
        .unwrap();
    let human_stderr = String::from_utf8_lossy(&human_out.stderr);
    assert!(
        human_stderr
            .contains("warning: Ignored unsupported or malformed proxy URL in `HTTPS_PROXY`"),
        "Expected variable-name-only proxy warning in human stderr, got: {human_stderr}"
    );
    assert!(
        !human_stderr.contains("PROXY_SECRET_CRED_555"),
        "Leaked proxy secret in human stderr: {human_stderr}"
    );

    let json_out = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home3)
        .env("XDG_CACHE_HOME", &cache3)
        .env("XDG_RUNTIME_DIR", &run3)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-bus", run3.display()),
        )
        .env(
            "HTTPS_PROXY",
            "badscheme://PROXY_SECRET_CRED_555@example.invalid:8080",
        )
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .args([
            "--data-dir",
            data3.to_str().unwrap(),
            "--no-remote-version",
            "--json",
            "refresh",
        ])
        .output()
        .unwrap();
    let json_stderr = String::from_utf8_lossy(&json_out.stderr);
    assert_eq!(
        json_stderr.trim().lines().count(),
        1,
        "`--json` stderr must remain a single structured JSON envelope without mixed warning lines: {json_stderr}"
    );
    let _: serde_json::Value = serde_json::from_str(json_stderr.trim()).unwrap();
    assert!(!json_stderr.contains("PROXY_SECRET_CRED_555"));
}

#[tokio::test]
async fn synthetic_v120_signoff_round2_renewal_preflight_lineage_and_unpersisted_exit_7() {
    use agy_switch_cli::domain::account::{
        PendingAuthFlow, PendingAuthRecord, STORE_SCHEMA_VERSION,
    };
    use agy_switch_cli::error::ExitCode;
    use agy_switch_cli::oauth::refresh::{
        bootstrap_and_persist_refresh_token, ensure_account_token_fresh_locked,
        resume_pending_auth_records,
    };
    use agy_switch_cli::store::locks::with_store_write_lock;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let _env_guard = OAUTH_ENV_MUTEX.lock().await;

    // Child subprocess helper 1: normal renewal hits post-`/token` `ENOSPC` -> MUST return exit 7 (`issued_token_unpersisted`)!
    if std::env::var_os("AGY_SUBTEST_RENEWAL_POST_ENOSPC").is_some() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = new_repo(tmp.path());
        let now = 1_800_000_000_i64;
        let expiring = AccountRecord::new(
            "acc-ren".into(),
            "alice@example.com".into(),
            TokenRecord {
                access_token: "ya29.old-at".into(),
                refresh_token: "1//OLD_RENEWAL_RT_111".into(),
                expires_in: 3600,
                expiry_timestamp: now + 30,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: Some(vec![
                    "openid".into(),
                    "https://www.googleapis.com/auth/cloud-platform".into(),
                    "https://www.googleapis.com/auth/userinfo.email".into(),
                ]),
                project_id: None,
                is_gcp_tos: true,
            },
            now - 100,
        );
        repo.with_write_lock(|tx| tx.upsert_account(expiring, true, now - 100))
            .unwrap();

        // Inject `ENOSPC` ONLY on `state/token_lineage` spill OR use $>512$ digests so `save_account` writes `token_lineage`?
        // Even simpler: `AGY_SWITCH_CLI_FAULT_SPEC` is checked inside `write_atomic_durable`! Because `upsert_account`
        // ran BEFORE we set fault? No, `AGY_SWITCH_CLI_FAULT_SPEC` was set on `acc-fault-post` only!
        let acc_fault = AccountRecord::new(
            "acc-fault-post".into(),
            "bob@example.com".into(),
            TokenRecord {
                access_token: "ya29.old-b".into(),
                refresh_token: "1//OLD_BOB_RT_222".into(),
                expires_in: 3600,
                expiry_timestamp: now + 30,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: Some(vec![
                    "openid".into(),
                    "https://www.googleapis.com/auth/cloud-platform".into(),
                    "https://www.googleapis.com/auth/userinfo.email".into(),
                ]),
                project_id: None,
                is_gcp_tos: true,
            },
            now - 100,
        );
        // Write `acc-fault-post.json` directly before enabling fault? `AGY_SWITCH_CLI_FAULT_SPEC` is set to
        // `after_rename:acc-fault-post:corrupt_once` -> `upsert_account` consumes `corrupt_once`? No: use `before_fsync:acc-target-enospc:enospc`
        // and seed `acc-target-enospc.json` + `index.json` via `std::fs::write`!
        let paths = repo.paths();
        let seeded_path = paths.account_file("acc-target-enospc");
        let mut seeded = acc_fault;
        seeded.id = "acc-target-enospc".into();
        std::fs::write(&seeded_path, serde_json::to_vec_pretty(&seeded).unwrap()).unwrap();
        std::fs::set_permissions(&seeded_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut idx = repo.read_snapshot().unwrap().index;
        idx.account_order.push("acc-target-enospc".into());
        std::fs::write(paths.index_file(), serde_json::to_vec_pretty(&idx).unwrap()).unwrap();

        let registry = OAuthClientRegistry::parse_from_raw(None, None);
        let transport = MockTransport::from_handler(|_req| {
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": "ya29.NEW_ISSUED_AT_SECRET_999",
                    "refresh_token": "1//NEW_ROTATED_RT_SECRET_999",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }),
            ))
        });
        let err = ensure_account_token_fresh_locked(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &registry,
            "antigravity/1.5.7 linux/amd64",
            "acc-target-enospc",
            false,
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::PartialCommitOrRecovery);
        assert_eq!(err.error_code, "issued_token_unpersisted");
        let line = err.to_json_line();
        assert!(!line.contains("NEW_ROTATED_RT_SECRET_999"));
        assert!(!line.contains("NEW_ISSUED_AT_SECRET_999"));
        assert!(!line.contains("OLD_BOB_RT_222"));
        let j: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(j["exit_code"], 7);
        assert_eq!(j["details"]["refresh_token_rotated"], true);

        // Also verify `auth pending --resume` surfaces `unpersisted_error` (`ExitCode::PartialCommitOrRecovery = 7`,
        // NOT downgraded to `1`) when an expiring pending record rotates at `/token` and fails `save_pending_auth_cas`!
        let pend_seeded_path = paths.pending_auth_file("pend-target-enospc");
        std::fs::create_dir_all(paths.pending_auth_dir()).unwrap();
        let pend_seeded = PendingAuthRecord {
            schema_version: STORE_SCHEMA_VERSION,
            id: "pend-target-enospc".into(),
            flow: PendingAuthFlow::AddToken,
            token: TokenRecord {
                access_token: "ya29.old-pend".into(),
                refresh_token: "1//OLD_PEND_RT_333".into(),
                expires_in: 3600,
                expiry_timestamp: now + 10,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: Some(vec![
                    "openid".into(),
                    "https://www.googleapis.com/auth/cloud-platform".into(),
                    "https://www.googleapis.com/auth/userinfo.email".into(),
                ]),
                project_id: None,
                is_gcp_tos: true,
            },
            auth_seq: 5,
            email_mismatch: false,
            input_rt_digest: None,
            custom_label: None,
            created_at: now - 50,
        };
        std::fs::write(
            &pend_seeded_path,
            serde_json::to_vec_pretty(&pend_seeded).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&pend_seeded_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let resume_rep = resume_pending_auth_records(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &registry,
            "antigravity/1.5.7 linux/amd64",
            now,
        )
        .await
        .unwrap();
        let unp = resume_rep
            .unpersisted_error
            .expect("Expected unpersisted_error on post-rotation ENOSPC in pending resume");
        assert_eq!(unp.exit_code, ExitCode::PartialCommitOrRecovery);
        assert_eq!(unp.error_code, "issued_token_unpersisted");
        return;
    }

    // Child subprocess helper 2: holds synchronous `L3 StoreWriteLock` across process boundary so parent's
    // post-`/token` `with_write_lock` times out with `lock_busy` -> MUST map to exit 7 (`issued_token_unpersisted`), NOT exit 5!
    if let Ok(lock_data_dir) = std::env::var("AGY_SUBTEST_HOLD_L3_DATA_DIR") {
        let ready_file = std::env::var("AGY_SUBTEST_HOLD_L3_READY").unwrap();
        let stop_file = std::env::var("AGY_SUBTEST_HOLD_L3_STOP").unwrap();
        let stop_path = std::path::Path::new(&stop_file);
        let paths = agy_switch_cli::paths::HeadlessPaths::with_explicit(
            std::path::PathBuf::from(&lock_data_dir).join("home"),
            std::path::PathBuf::from(&lock_data_dir),
            std::path::PathBuf::from(&lock_data_dir).join("cache"),
        );
        with_store_write_lock(&paths, Duration::from_secs(5), |_| {
            std::fs::write(&ready_file, b"held").unwrap();
            let hold_deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !stop_path.exists()
                && stop_path.parent().is_some_and(std::path::Path::exists)
                && std::time::Instant::now() < hold_deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        })
        .unwrap();
        return;
    }

    // 1. Obstructed `state/token_lineage` (symlink or non-directory) on normal renewal MUST fail preflight
    //    with ZERO `/token` network calls (never rotating & stranding a refresh token)!
    let tmp1 = tempfile::tempdir().unwrap();
    let repo1 = new_repo(tmp1.path());
    let now = 1_800_000_000_i64;
    let acc1 = AccountRecord::new(
        "acc-lin1".into(),
        "alice@example.com".into(),
        TokenRecord {
            access_token: "ya29.expiring".into(),
            refresh_token: "1//SAFE_UNROTATED_RT_001".into(),
            expires_in: 3600,
            expiry_timestamp: now + 10,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: Some(vec![
                "openid".into(),
                "https://www.googleapis.com/auth/cloud-platform".into(),
                "https://www.googleapis.com/auth/userinfo.email".into(),
            ]),
            project_id: None,
            is_gcp_tos: true,
        },
        now - 200,
    );
    repo1
        .with_write_lock(|tx| tx.upsert_account(acc1, true, now - 200))
        .unwrap();

    // Replace `state/token_lineage` with a symlink (rejected by synchronous storage check!)
    let lin_dir = repo1.paths().token_lineage_dir();
    if lin_dir.exists() {
        std::fs::remove_dir_all(&lin_dir).unwrap();
    }
    let outside = tmp1.path().join("outside_lineage");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, &lin_dir).unwrap();

    let calls1 = Arc::new(AtomicUsize::new(0));
    let calls1_c = calls1.clone();
    let transport1 = MockTransport::from_handler(move |_req| {
        calls1_c.fetch_add(1, Ordering::SeqCst);
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.never",
                "refresh_token": "1//ROTATED_WOULD_STRAND",
                "expires_in": 3600,
                "token_type": "Bearer"
            }),
        ))
    });
    let registry = OAuthClientRegistry::parse_from_raw(None, None);
    let err1 = ensure_account_token_fresh_locked(
        &repo1,
        &transport1,
        &fast_oauth_endpoints(),
        &registry,
        "antigravity/1.5.7 linux/amd64",
        "acc-lin1",
        false,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err1.exit_code, ExitCode::GeneralOrDataError);
    assert_eq!(
        calls1.load(Ordering::SeqCst),
        0,
        "Normal renewal MUST fail preflight with 0 `/token` calls when `token_lineage` is obstructed!"
    );

    // 2. Pending auto-renewal (`resume_pending_auth_records`) with obstructed `state/pending_lineage`
    //    MUST ALSO fail preflight with ZERO `/token` calls!
    let tmp_pend = tempfile::tempdir().unwrap();
    let repo_pend = new_repo(tmp_pend.path());
    repo_pend
        .with_write_lock(|tx| {
            let p = PendingAuthRecord {
                schema_version: STORE_SCHEMA_VERSION,
                id: "pend-exp1".into(),
                flow: PendingAuthFlow::AddToken,
                token: TokenRecord {
                    access_token: "ya29.p-exp".into(),
                    refresh_token: "1//PENDING_SAFE_RT".into(),
                    expires_in: 3600,
                    expiry_timestamp: now + 5,
                    token_type: "Bearer".into(),
                    id_token: None,
                    oauth_client_key: Some("antigravity_enterprise".into()),
                    granted_scopes: Some(vec![
                        "openid".into(),
                        "https://www.googleapis.com/auth/cloud-platform".into(),
                        "https://www.googleapis.com/auth/userinfo.email".into(),
                    ]),
                    project_id: None,
                    is_gcp_tos: true,
                },
                auth_seq: 2,
                email_mismatch: false,
                input_rt_digest: None,
                custom_label: None,
                created_at: now - 50,
            };
            let _ = tx.save_pending_auth_cas(&p, None)?;
            Ok(())
        })
        .unwrap();
    let plin_dir = repo_pend.paths().pending_lineage_dir();
    if plin_dir.exists() {
        std::fs::remove_dir_all(&plin_dir).unwrap();
    }
    std::fs::write(&plin_dir, b"not-a-dir").unwrap();

    let calls_p = Arc::new(AtomicUsize::new(0));
    let calls_pc = calls_p.clone();
    let transport_p = MockTransport::from_handler(move |_req| {
        calls_pc.fetch_add(1, Ordering::SeqCst);
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.p-never",
                "refresh_token": "1//P_ROTATED",
                "expires_in": 3600,
                "token_type": "Bearer"
            }),
        ))
    });
    let rep_p = resume_pending_auth_records(
        &repo_pend,
        &transport_p,
        &fast_oauth_endpoints(),
        &registry,
        "antigravity/1.5.7 linux/amd64",
        now,
    )
    .await
    .unwrap();
    assert_eq!(rep_p.resumed_accounts.len(), 0);
    assert_eq!(rep_p.failures.len(), 1);
    assert_eq!(
        calls_p.load(Ordering::SeqCst),
        0,
        "Pending auto-renewal MUST fail preflight with 0 `/token` calls when `pending_lineage` is obstructed!"
    );

    // 3. Run child subprocess helper 1 (`before_fsync:acc-target-enospc:enospc` after `/token` rotation -> exit 7)!
    let sub1 = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", tmp1.path())
        .env("AGY_SUBTEST_RENEWAL_POST_ENOSPC", "1")
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_fsync:target-enospc:enospc",
        )
        .args([
            "--exact",
            "synthetic_v120_signoff_round2_renewal_preflight_lineage_and_unpersisted_exit_7",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        sub1.status.success(),
        "Renewal post-ENOSPC subtest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&sub1.stdout),
        String::from_utf8_lossy(&sub1.stderr)
    );

    // 4. Post-issuance `L3` `lock_busy` timeout (when NO durable backup exists!) MUST return exit 7 (`issued_token_unpersisted`), NOT exit 5!
    struct KillChildOnDrop(Arc<std::sync::Mutex<Option<std::process::Child>>>);
    impl Drop for KillChildOnDrop {
        fn drop(&mut self) {
            if let Ok(mut g) = self.0.lock() {
                if let Some(mut p) = g.take() {
                    let _ = p.kill();
                    let _ = p.wait();
                }
            }
        }
    }

    let tmp_l3 = tempfile::tempdir().unwrap();
    let child_slot: Arc<std::sync::Mutex<Option<std::process::Child>>> =
        Arc::new(std::sync::Mutex::new(None));
    let _child_guard = KillChildOnDrop(child_slot.clone());

    let l3_data = tmp_l3.path().join("store");
    let paths_l3 = agy_switch_cli::paths::HeadlessPaths::with_explicit(
        l3_data.join("home"),
        l3_data.clone(),
        l3_data.join("cache"),
    );
    let repo_l3 = StoreRepository::new(paths_l3).with_lock_timeout(Duration::from_millis(120));
    let ready_f = tmp_l3.path().join("l3.ready");
    let stop_f = tmp_l3.path().join("l3.stop");
    let ready_c = ready_f.clone();
    let stop_c = stop_f.clone();
    let l3_data_c = l3_data.clone();
    let child_slot_c = child_slot.clone();
    let tmp_l3_dir = tmp_l3.path().to_path_buf();

    let transport_l3 = MockTransport::from_handler(move |_req| {
        // Preflight `L3` already succeeded! Now spawn a separate OS process that acquires `L3` BEFORE `/token` returns!
        let ch = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", &tmp_l3_dir)
            .env("AGY_SUBTEST_HOLD_L3_DATA_DIR", &l3_data_c)
            .env("AGY_SUBTEST_HOLD_L3_READY", &ready_c)
            .env("AGY_SUBTEST_HOLD_L3_STOP", &stop_c)
            .args([
                "--exact",
                "synthetic_v120_signoff_round2_renewal_preflight_lineage_and_unpersisted_exit_7",
                "--nocapture",
            ])
            .spawn()
            .unwrap();
        *child_slot_c.lock().unwrap() = Some(ch);
        let ready_deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !ready_c.exists() {
            if let Some(status) = child_slot_c
                .lock()
                .unwrap()
                .as_mut()
                .and_then(|c| c.try_wait().unwrap())
            {
                if !ready_c.exists() {
                    panic!("L3 holder child exited prematurely ({status}) before signaling ready");
                }
                break;
            }
            assert!(
                std::time::Instant::now() < ready_deadline,
                "Timed out waiting for L3 holder child ready marker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(MockTransport::json_response(
            200,
            json!({
                "access_token": "ya29.UNPERSISTED_BUSY_AT_777",
                "refresh_token": "1//UNPERSISTED_BUSY_RT_777",
                "expires_in": 3600,
                "token_type": "Bearer"
            }),
        ))
    });

    let busy_err = bootstrap_and_persist_refresh_token(
        &repo_l3,
        &transport_l3,
        &fast_oauth_endpoints(),
        &registry,
        "antigravity/1.5.7 linux/amd64",
        "1//INPUT_RT_BEFORE_L3_BUSY",
        None,
        None,
        now,
    )
    .await
    .unwrap_err();
    std::fs::write(&stop_f, b"release").unwrap();
    let held_proc = child_slot.lock().unwrap().take();
    if let Some(mut p) = held_proc {
        let _ = p.wait();
    }

    assert_eq!(
        busy_err.exit_code,
        ExitCode::PartialCommitOrRecovery,
        "Post-issuance L3 lock_busy without durable backup MUST return exit 7, got {:?}: {}",
        busy_err.exit_code,
        busy_err.message
    );
    assert_eq!(busy_err.error_code, "issued_token_unpersisted");
    let busy_json = busy_err.to_json_line();
    assert!(!busy_json.contains("UNPERSISTED_BUSY_RT_777"));
    assert!(!busy_json.contains("UNPERSISTED_BUSY_AT_777"));
}

#[tokio::test]
async fn synthetic_v120_round3_r304_pending_resume_short_circuits_on_exit_7_and_preflight_fsync_probe(
) {
    use agy_switch_cli::domain::account::{
        PendingAuthFlow, PendingAuthRecord, STORE_SCHEMA_VERSION,
    };
    use agy_switch_cli::error::ExitCode;
    use agy_switch_cli::oauth::refresh::{
        bootstrap_and_persist_refresh_token, resume_pending_auth_records,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Subprocess 1: preflight parent-dir fsync probe failure (`sync_parent_dir:.write-probe:io`) -> 0 `/token` calls!
    if std::env::var_os("AGY_SUBTEST_R304_PREFLIGHT_FSYNC").is_some() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = new_repo(tmp.path());
        let registry = OAuthClientRegistry::parse_from_raw(None, None);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let transport = MockTransport::from_handler(move |_req| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": "ya29.never",
                    "refresh_token": "1//never-rotated",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }),
            ))
        });
        let err = bootstrap_and_persist_refresh_token(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &registry,
            "antigravity/1.5.7 linux/amd64",
            "1//safe-input-rt",
            None,
            None,
            1_800_000_000,
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::GeneralOrDataError);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Preflight parent-dir fsync probe failure MUST block `/token` with 0 requests!"
        );
        return;
    }

    // Subprocess 2: `resume_pending_auth_records` with 2 expiring records where 1st hits exit 7
    // MUST stop immediately without calling `/token` for the 2nd record!
    if std::env::var_os("AGY_SUBTEST_R304_PENDING_SHORT_CIRCUIT").is_some() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = new_repo(tmp.path());
        let paths = repo.paths();
        let now = 1_800_000_000_i64;
        std::fs::create_dir_all(paths.pending_auth_dir()).unwrap();
        std::fs::set_permissions(
            paths.pending_auth_dir(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        let make_pend = |id: &str, rt: &str| PendingAuthRecord {
            schema_version: STORE_SCHEMA_VERSION,
            id: id.into(),
            flow: PendingAuthFlow::AddToken,
            token: TokenRecord {
                access_token: format!("ya29.old-{id}"),
                refresh_token: rt.into(),
                expires_in: 3600,
                expiry_timestamp: now + 5,
                token_type: "Bearer".into(),
                id_token: None,
                oauth_client_key: Some("antigravity_enterprise".into()),
                granted_scopes: Some(vec![
                    "openid".into(),
                    "https://www.googleapis.com/auth/cloud-platform".into(),
                    "https://www.googleapis.com/auth/userinfo.email".into(),
                ]),
                project_id: None,
                is_gcp_tos: true,
            },
            auth_seq: 1,
            email_mismatch: false,
            input_rt_digest: None,
            custom_label: None,
            created_at: now - 50,
        };
        for (id, rt) in [
            ("pend-01-enospc", "1//PEND_01_RT"),
            ("pend-02-untouched", "1//PEND_02_RT"),
        ] {
            let p = paths.pending_auth_file(id);
            std::fs::write(&p, serde_json::to_vec_pretty(&make_pend(id, rt)).unwrap()).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let transport = MockTransport::from_handler(move |_req| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": "ya29.rot-pend",
                    "refresh_token": "1//ROTATED_PEND_01",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }),
            ))
        });
        let registry = OAuthClientRegistry::parse_from_raw(None, None);
        let rep = resume_pending_auth_records(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &registry,
            "antigravity/1.5.7 linux/amd64",
            now,
        )
        .await
        .unwrap();
        let unp = rep
            .unpersisted_error
            .expect("Expected unpersisted_error from pend-01-enospc");
        assert_eq!(unp.exit_code, ExitCode::PartialCommitOrRecovery);
        assert_eq!(unp.error_code, "issued_token_unpersisted");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "resume_pending_auth_records MUST stop immediately after first exit-7 without touching pend-02!"
        );
        // Verify pend-02-untouched still has its original RT on disk!
        let pend2_raw =
            std::fs::read_to_string(paths.pending_auth_file("pend-02-untouched")).unwrap();
        assert!(pend2_raw.contains("1//PEND_02_RT"));
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let out1 = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", tmp.path())
        .env("AGY_SUBTEST_R304_PREFLIGHT_FSYNC", "1")
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "sync_parent_dir:.write-probe:io",
        )
        .args([
            "--exact",
            "synthetic_v120_round3_r304_pending_resume_short_circuits_on_exit_7_and_preflight_fsync_probe",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out1.status.success(),
        "Preflight fsync probe subtest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );

    let out2 = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", tmp.path())
        .env("AGY_SUBTEST_R304_PENDING_SHORT_CIRCUIT", "1")
        .env(
            "AGY_SWITCH_CLI_FAULT_SPEC",
            "before_fsync:pend-01-enospc:enospc",
        )
        .args([
            "--exact",
            "synthetic_v120_round3_r304_pending_resume_short_circuits_on_exit_7_and_preflight_fsync_probe",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "Pending resume short-circuit subtest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );
}

#[tokio::test]
async fn synthetic_v120_a02a_reauthorize_preflight_blocks_unwritable_dirs_and_preserves_staging_exit_7(
) {
    use agy_switch_cli::oauth::flow::PreparedAuthSession;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let seed_acc = |repo: &StoreRepository,
                    now: i64|
     -> (AccountRecord, PreparedAuthSession, OAuthClientRegistry) {
        let reg = OAuthClientRegistry::parse_from_raw(None, None);
        let client = reg.select_for_login(None).unwrap();
        let session = build_authorization_session(client, 54546, GOOGLE_AUTH_URL).unwrap();
        let tok = TokenRecord {
            access_token: "ya29.orig-a02a".into(),
            refresh_token: "1//ORIG_A02A_RT".into(),
            expires_in: 3600,
            expiry_timestamp: now + 3600,
            token_type: "Bearer".into(),
            id_token: None,
            oauth_client_key: Some("antigravity_enterprise".into()),
            granted_scopes: Some(vec![
                "openid".into(),
                "https://www.googleapis.com/auth/cloud-platform".into(),
                "https://www.googleapis.com/auth/userinfo.email".into(),
            ]),
            project_id: Some("proj-synth".into()),
            is_gcp_tos: true,
        };
        let acc = AccountRecord::new(
            "acc-reauth-a02a".into(),
            "alice@example.com".into(),
            tok,
            now,
        );
        repo.with_write_lock(|tx| {
            tx.upsert_account(acc.clone(), true, now)?;
            Ok(())
        })
        .unwrap();
        (acc, session, reg)
    };

    // Subprocess A: `pending_lineage` durability probe fails -> 0 `/token` HTTP requests!
    // Subprocess B: `token_lineage` durability probe fails -> 0 `/token` HTTP requests!
    if std::env::var_os("AGY_SUBTEST_A02A_DIR_PROBE").is_some() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = new_repo(tmp.path());
        let now = 1_900_000_000i64;
        let (acc, session, reg) = seed_acc(&repo, now);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let transport = MockTransport::from_handler(move |_req| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": "ya29.never",
                    "refresh_token": "1//NEVER_ISSUED",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }),
            ))
        });
        let err = complete_reauthorize_exchange_locked(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &reg,
            "antigravity/1.5.9 linux/amd64",
            &acc,
            &session,
            "4/code-probe-fail",
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::GeneralOrDataError);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Reauthorize preflight durability probe failure MUST block `/token` with 0 HTTP requests!"
        );
        return;
    }

    // Subprocess C: Post-exchange pending staging fails after `/token` -> exit 7 (`issued_token_unpersisted`), zero secret echo!
    if std::env::var_os("AGY_SUBTEST_A02A_STAGE_ENOSP").is_some() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = new_repo(tmp.path());
        let now = 1_900_000_000i64;
        let (acc, session, reg) = seed_acc(&repo, now);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let transport = MockTransport::from_handler(move |req| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            assert!(
                req.url.contains("token"),
                "Unexpected non-token request after staging failed: {}",
                req.url
            );
            Ok(MockTransport::json_response(
                200,
                json!({
                    "access_token": "ya29.A02A_SUBPROC_AT",
                    "refresh_token": "1//A02A_UNPERSISTED_SECRET_RT",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "openid https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"
                }),
            ))
        });
        let err = complete_reauthorize_exchange_locked(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &reg,
            "antigravity/1.5.9 linux/amd64",
            &acc,
            &session,
            "4/code-enospc",
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(err.exit_code, ExitCode::PartialCommitOrRecovery);
        assert_eq!(err.error_code, "issued_token_unpersisted");
        let err_json = err.to_json_line();
        assert!(!err_json.contains("1//A02A_UNPERSISTED_SECRET_RT"));
        assert!(!err_json.contains("ya29.A02A_SUBPROC_AT"));
        return;
    }

    // 1. In-process symlink obstruction on `state/pending_lineage` blocks `/token` with 0 requests!
    {
        let tmp = tempfile::tempdir().unwrap();
        let repo = new_repo(tmp.path());
        let paths = repo.paths().clone();
        let now = 1_900_000_000i64;
        let (acc, session, reg) = seed_acc(&repo, now);
        let outside_dir = tmp.path().join("outside_pending_lineage");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::remove_dir_all(paths.pending_lineage_dir()).unwrap_or(());
        std::os::unix::fs::symlink(&outside_dir, paths.pending_lineage_dir()).unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let transport = MockTransport::from_handler(move |_req| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok(MockTransport::json_response(200, json!({})))
        });
        let err = complete_reauthorize_exchange_locked(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &reg,
            "antigravity/1.5.9 linux/amd64",
            &acc,
            &session,
            "4/code-symlink",
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code, ExitCode::GeneralOrDataError);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    // 2 & 3. Subprocesses testing both pending-only dir probe (`pending_lineage`) and shared dir probe (`token_lineage`).
    let tmp = tempfile::tempdir().unwrap();
    for fault in [
        "sync_parent_dir:pending_lineage/.write-probe:io",
        "sync_parent_dir:token_lineage/.write-probe:io",
    ] {
        let out = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", tmp.path())
            .env("AGY_SUBTEST_A02A_DIR_PROBE", "1")
            .env("AGY_SWITCH_CLI_FAULT_SPEC", fault)
            .args([
                "--exact",
                "synthetic_v120_a02a_reauthorize_preflight_blocks_unwritable_dirs_and_preserves_staging_exit_7",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "Subtest for {fault} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // 4. Happy path: durable `0600` pending file exists BEFORE `userinfo` responds, and final commit rotates RT cleanly.
    {
        let tmp_ok = tempfile::tempdir().unwrap();
        let repo = new_repo(tmp_ok.path());
        let paths = repo.paths().clone();
        let now = 1_900_000_000i64;
        let (acc, session, reg) = seed_acc(&repo, now);
        let saw_staged_before_userinfo = Arc::new(AtomicUsize::new(0));
        let saw_c = saw_staged_before_userinfo.clone();
        let pending_dir = paths.pending_auth_dir();

        let transport = MockTransport::from_handler(move |req| {
            if req.url.contains("token") {
                Ok(MockTransport::json_response(
                    200,
                    json!({
                        "access_token": "ya29.a02a-ok-at",
                        "refresh_token": "1//A02A_ROTATED_RT",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "scope": "openid https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"
                    }),
                ))
            } else {
                let staged_0600 = std::fs::read_dir(&pending_dir)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|e| {
                        let name = e.file_name();
                        let s = name.to_string_lossy();
                        s.starts_with("pend-") && s.ends_with(".json")
                    })
                    .filter(|e| {
                        std::fs::symlink_metadata(e.path())
                            .map(|m| m.is_file() && (m.permissions().mode() & 0o777) == 0o600)
                            .unwrap_or(false)
                    })
                    .count();
                assert_eq!(
                    staged_0600, 1,
                    "Durable 0600 pending_auth file must exist BEFORE fetch_userinfo responds!"
                );
                saw_c.fetch_add(1, Ordering::SeqCst);
                Ok(MockTransport::json_response(
                    200,
                    json!({"email": "alice@example.com", "name": "Alice"}),
                ))
            }
        });

        let updated = complete_reauthorize_exchange_locked(
            &repo,
            &transport,
            &fast_oauth_endpoints(),
            &reg,
            "antigravity/1.5.9 linux/amd64",
            &acc,
            &session,
            "4/code-ok",
            now + 10,
        )
        .await
        .unwrap();
        assert_eq!(saw_staged_before_userinfo.load(Ordering::SeqCst), 1);
        assert_eq!(updated.token.refresh_token, "1//A02A_ROTATED_RT");
        assert!(repo.list_pending_auth_readonly().unwrap().is_empty());
    }

    // 5. Subprocess testing post-exchange staging failure returns exit 7 (`issued_token_unpersisted`).
    let out_enospc = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", tmp.path())
        .env("AGY_SUBTEST_A02A_STAGE_ENOSP", "1")
        .env("AGY_SWITCH_CLI_FAULT_SPEC", "before_fsync:pend-:enospc")
        .args([
            "--exact",
            "synthetic_v120_a02a_reauthorize_preflight_blocks_unwritable_dirs_and_preserves_staging_exit_7",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out_enospc.status.success(),
        "Post-exchange staging exit-7 subtest failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_enospc.stdout),
        String::from_utf8_lossy(&out_enospc.stderr)
    );
}
