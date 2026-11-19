use crate::error::{CliError, CliResult};
use crate::oauth::registry::OAuthClientConfig;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::Instant;
use url::Url;

pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const OAUTH_FLOW_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
pub const BASE_CONSUMER_SCOPES: &[&str] = &[
    "openid",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];

#[derive(Clone)]
pub struct PreparedAuthSession {
    pub client: OAuthClientConfig,
    pub redirect_uri: String,
    pub port: u16,
    pub state: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub auth_url: String,
}

impl fmt::Debug for PreparedAuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedAuthSession")
            .field("client_key", &self.client.key)
            .field("redirect_uri", &self.redirect_uri)
            .field("port", &self.port)
            .field("state", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .finish()
    }
}

pub fn generate_pkce_and_state() -> (String, String, String) {
    let mut state_bytes = [0u8; 32];
    let mut verifier_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut state_bytes);
    rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);

    let state = URL_SAFE_NO_PAD.encode(state_bytes);
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge_digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(challenge_digest);
    (state, code_verifier, code_challenge)
}

pub fn build_authorization_session(
    client: OAuthClientConfig,
    port: u16,
    auth_base_url: &str,
) -> CliResult<PreparedAuthSession> {
    let (state, code_verifier, code_challenge) = generate_pkce_and_state();
    let redirect_uri = format!("http://127.0.0.1:{port}/oauth-callback");
    let scopes = if client.request_scopes.is_empty() {
        BASE_CONSUMER_SCOPES.join(" ")
    } else {
        client.request_scopes.join(" ")
    };

    let params = [
        ("client_id", client.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("scope", scopes.as_str()),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("include_granted_scopes", "true"),
        ("state", state.as_str()),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];

    let auth_url = Url::parse_with_params(auth_base_url, &params)
        .map_err(|e| CliError::data(format!("Failed to build OAuth authorization URL: {e}")))?
        .to_string();

    Ok(PreparedAuthSession {
        client,
        redirect_uri,
        port,
        state,
        code_verifier,
        code_challenge,
        auth_url,
    })
}

/// Shared strict validator used by BOTH the `--ssh` loopback HTTP listener AND pasted callback URLs!
/// Never logs raw URL or authorization code.
pub fn validate_callback_url(raw_url_or_target: &str, expected_state: &str) -> CliResult<String> {
    validate_callback_url_with_port(raw_url_or_target, expected_state, None)
}

pub fn validate_callback_url_with_port(
    raw_url_or_target: &str,
    expected_state: &str,
    expected_port: Option<u16>,
) -> CliResult<String> {
    let trimmed = raw_url_or_target.trim();
    if trimmed.is_empty() {
        return Err(CliError::auth(
            "empty_callback_url",
            "Callback URL cannot be empty. Paste the full `http://127.0.0.1:<port>/oauth-callback?code=...&state=...` URL.",
        ));
    }

    let is_relative_target = trimmed.starts_with('/');
    let parsed = if is_relative_target {
        Url::parse(&format!("http://127.0.0.1{trimmed}"))
    } else {
        Url::parse(trimmed)
    }
    .map_err(|_| {
        CliError::auth(
            "invalid_callback_url",
            "Invalid callback URL format. Paste the full redirect URL including `?code=...&state=...` (bare codes without state are rejected).",
        )
    })?;

    if !matches!(parsed.scheme(), "http") {
        return Err(CliError::auth(
            "invalid_callback_scheme",
            "Callback URL must use http:// loopback redirect.",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::auth(
            "invalid_callback_userinfo",
            "Callback URL must not contain credentials (`user:pass@`).",
        ));
    }
    if !crate::transport::proxy::is_loopback_url(&parsed) {
        return Err(CliError::auth(
            "invalid_callback_host",
            "Callback URL host must be a loopback address (`127.0.0.1`, `localhost`, or `[::1]`).",
        ));
    }
    if !is_relative_target {
        if let Some(exp_port) = expected_port {
            if parsed.port() != Some(exp_port) {
                return Err(CliError::auth(
                    "invalid_callback_port",
                    format!("Callback URL port does not match expected loopback port {exp_port}."),
                ));
            }
        }
    }
    if parsed.path() != "/oauth-callback" {
        return Err(CliError::auth(
            "invalid_callback_path",
            "Callback URL path must be `/oauth-callback`.",
        ));
    }
    if parsed.fragment().is_some() {
        return Err(CliError::auth(
            "callback_has_fragment",
            "Callback URL must not contain a URL fragment (`#...`).",
        ));
    }

    let query_values = |name: &str| -> Vec<String> {
        parsed
            .query_pairs()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .collect()
    };

    let states = query_values("state");
    if states.len() != 1 {
        return Err(CliError::auth(
            "missing_or_duplicate_state",
            "Callback URL must contain exactly one `state` parameter.",
        ));
    }
    if !constant_time_eq(states[0].as_bytes(), expected_state.as_bytes()) {
        return Err(CliError::auth(
            "oauth_state_mismatch",
            "OAuth `state` parameter mismatch. Abort and start a fresh authorization flow.",
        ));
    }

    let errors = query_values("error");
    if !errors.is_empty() {
        let code_tag = sanitize_oauth_token_tag(&errors[0]);
        return Err(CliError::auth(
            "oauth_access_denied",
            format!("OAuth authorization was declined or failed upstream ({code_tag})."),
        ));
    }

    let codes = query_values("code");
    if codes.len() != 1 || codes[0].trim().is_empty() {
        return Err(CliError::auth(
            "missing_authorization_code",
            "Callback URL is missing a valid single `code` parameter.",
        ));
    }

    Ok(codes[0].clone())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn sanitize_oauth_token_tag(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "" => "unspecified",
        "access_denied" => "access_denied",
        "invalid_request" => "invalid_request",
        "unauthorized_client" => "unauthorized_client",
        "unsupported_response_type" => "unsupported_response_type",
        "invalid_scope" => "invalid_scope",
        "server_error" => "server_error",
        "temporarily_unavailable" => "temporarily_unavailable",
        "interaction_required" => "interaction_required",
        "login_required" => "login_required",
        "consent_required" => "consent_required",
        _ => "unrecognized_oauth_error",
    }
}

fn oauth_success_http_response() -> &'static [u8] {
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n\
    <html><body style='font-family:sans-serif;text-align:center;padding:40px;'>\
    <h2 style='color:#15803d;'>Authorization received by agy-switch-cli</h2>\
    <p>You may close this browser tab and return to your SSH terminal.</p>\
    </body></html>"
}

fn oauth_failure_http_response() -> &'static [u8] {
    b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n\
    <html><body style='font-family:sans-serif;text-align:center;padding:40px;'>\
    <h2 style='color:#b91c1c;'>Authorization failed or invalid callback</h2>\
    <p>Return to your terminal and start a new authorization flow.</p>\
    </body></html>"
}

async fn read_single_loopback_connection(
    mut stream: TcpStream,
    expected_state: String,
) -> Option<CliResult<String>> {
    let header_bytes = tokio::time::timeout(Duration::from_secs(3), async {
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 8192 {
                return None;
            }
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return Some(buf);
            }
        }
    })
    .await
    .ok()
    .flatten()?;

    let req_text = std::str::from_utf8(&header_bytes).ok()?;
    let request_line = req_text.lines().next()?;
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "GET" {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            stream.write_all(oauth_failure_http_response()),
        )
        .await;
        return None;
    }
    let target = parts.next()?;
    let version = parts.next()?;
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") || parts.next().is_some() {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            stream.write_all(oauth_failure_http_response()),
        )
        .await;
        return None;
    }

    // Ignore unrelated browser requests (e.g. `/favicon.ico`) without consuming the flow!
    if !target.starts_with("/oauth-callback") {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        )
        .await;
        return None;
    }

    let outcome = validate_callback_url(target, &expected_state);
    // If state itself doesn't match, treat as stray/unrelated request rather than killing legitimate waiter
    if let Err(ref e) = outcome {
        if e.error_code == "oauth_state_mismatch" || e.error_code == "missing_or_duplicate_state" {
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                stream.write_all(oauth_failure_http_response()),
            )
            .await;
            return None;
        }
    }

    let body = if outcome.is_ok() {
        oauth_success_http_response()
    } else {
        oauth_failure_http_response()
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(body)).await;
    Some(outcome)
}

pub async fn bind_loopback_listener(requested_port: Option<u16>) -> CliResult<(TcpListener, u16)> {
    let bind_port = requested_port.unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", bind_port))
        .await
        .map_err(|e| {
            CliError::io(
                "oauth_bind_failed",
                format!("Cannot bind loopback OAuth listener on 127.0.0.1:{bind_port}: {e}"),
            )
        })?;
    let actual_port = listener
        .local_addr()
        .map_err(|e| CliError::io("oauth_bind_failed", format!("Cannot read local port: {e}")))?
        .port();
    Ok((listener, actual_port))
}

/// Wait for `/oauth-callback` on `listener` with 5-minute timeout and `SIGINT`/`SIGTERM` cancellation.
pub async fn wait_for_loopback_callback(
    listener: TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> CliResult<String> {
    let deadline = Instant::now() + timeout;
    let mut connections: JoinSet<Option<CliResult<String>>> = JoinSet::new();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                return Err(CliError::auth("oauth_cancelled", "OAuth authorization cancelled by SIGINT."));
            }
            _ = async {
                if let Some(ref mut s) = sigterm {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                return Err(CliError::auth("oauth_cancelled", "OAuth authorization cancelled by SIGTERM."));
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(CliError::auth("oauth_timeout", "OAuth authorization timed out waiting for callback."));
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Ok(Some(outcome))) = joined {
                    return outcome;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        if connections.len() < 8 {
                            connections.spawn(read_single_loopback_connection(stream, expected_state.to_string()));
                        }
                    }
                    Err(e) => {
                        return Err(CliError::io("oauth_accept_failed", format!("OAuth callback listener failed: {e}")));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_and_callback_validator_enforce_all_security_invariants() {
        let client = OAuthClientConfig {
            key: "test".into(),
            label: "Test".into(),
            client_id: "cid".into(),
            client_secret: "csec".into(),
            is_builtin: false,
            request_scopes: crate::oauth::registry::default_request_scopes(),
            required_scopes: crate::oauth::registry::default_required_scopes(),
        };
        let session = build_authorization_session(client, 54321, GOOGLE_AUTH_URL).unwrap();
        assert!(session.auth_url.contains("code_challenge_method=S256"));
        assert!(session.auth_url.contains("code_challenge="));

        // Valid callback URL
        let ok_url = format!(
            "http://127.0.0.1:54321/oauth-callback?code=4/0AbcDef&state={}",
            session.state
        );
        assert_eq!(
            validate_callback_url(&ok_url, &session.state).unwrap(),
            "4/0AbcDef"
        );

        // Reject bare code without state
        assert!(validate_callback_url("4/0AbcDef", &session.state).is_err());
        // Reject wrong state
        let bad_state = "http://127.0.0.1:54321/oauth-callback?code=4/0AbcDef&state=wrong";
        assert!(validate_callback_url(bad_state, &session.state).is_err());
        // Reject fragment
        let frag_url = format!("{ok_url}#evil");
        assert!(validate_callback_url(&frag_url, &session.state).is_err());
        // Reject duplicate state
        let dup_state = format!("{ok_url}&state={}", session.state);
        assert!(validate_callback_url(&dup_state, &session.state).is_err());
        // Reject non-loopback host
        let evil_host = format!(
            "http://evil.example.com:54321/oauth-callback?code=4/0AbcDef&state={}",
            session.state
        );
        assert_eq!(
            validate_callback_url(&evil_host, &session.state)
                .unwrap_err()
                .error_code,
            "invalid_callback_host"
        );
        // Reject mismatched port when expected_port is specified
        let wrong_port = format!(
            "http://127.0.0.1:9999/oauth-callback?code=4/0AbcDef&state={}",
            session.state
        );
        assert_eq!(
            validate_callback_url_with_port(&wrong_port, &session.state, Some(54321))
                .unwrap_err()
                .error_code,
            "invalid_callback_port"
        );
    }
}
