use crate::error::{CliError, CliResult};
use crate::transport::proxy::ProxyMode;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Timeout classes per Blueprint §6.1:
/// - `StandardApi`: 15s total, 5s connect
/// - `OAuthToken`: 30s total, 5s connect
/// - `VersionCheck`: 3s total, 2s connect
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutClass {
    StandardApi,
    OAuthToken,
    VersionCheck,
}

impl TimeoutClass {
    pub fn durations(self) -> (Duration, Duration) {
        match self {
            Self::StandardApi => (Duration::from_secs(5), Duration::from_secs(15)),
            Self::OAuthToken => (Duration::from_secs(5), Duration::from_secs(30)),
            Self::VersionCheck => (Duration::from_secs(2), Duration::from_secs(3)),
        }
    }
}

#[derive(Clone)]
pub enum RequestBody {
    Empty,
    Form(Vec<(String, String)>),
    Json(serde_json::Value),
}

impl fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::Form(pairs) => {
                let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
                f.debug_struct("Form").field("keys", &keys).finish()
            }
            Self::Json(_) => write!(f, "Json(..)"),
        }
    }
}

#[derive(Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: RequestBody,
    pub timeout_class: TimeoutClass,
}

pub fn redact_url_for_debug(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(mut parsed) = Url::parse(trimmed) {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
        }
        parsed.set_query(None);
        parsed.set_fragment(None);
        return redact_inline_url_userinfo(parsed.as_str());
    }
    let no_query_or_frag = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    redact_inline_url_userinfo(no_query_or_frag)
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let safe_headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| {
                if k.eq_ignore_ascii_case("authorization")
                    || k.eq_ignore_ascii_case("proxy-authorization")
                    || k.eq_ignore_ascii_case("cookie")
                    || k.eq_ignore_ascii_case("set-cookie")
                    || k.eq_ignore_ascii_case("x-goog-api-key")
                {
                    (k.as_str(), "[REDACTED]")
                } else {
                    (k.as_str(), v.as_str())
                }
            })
            .collect();
        let safe_url = redact_url_for_debug(&self.url);
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &safe_url)
            .field("headers", &safe_headers)
            .field("body", &self.body)
            .field("timeout_class", &self.timeout_class)
            .finish()
    }
}

impl HttpRequest {
    pub fn get(url: impl Into<String>, timeout_class: TimeoutClass) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: RequestBody::Empty,
            timeout_class,
        }
    }

    pub fn post_form(
        url: impl Into<String>,
        form: Vec<(String, String)>,
        timeout_class: TimeoutClass,
    ) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            body: RequestBody::Form(form),
            timeout_class,
        }
    }

    pub fn post_json(
        url: impl Into<String>,
        payload: serde_json::Value,
        timeout_class: TimeoutClass,
    ) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            body: RequestBody::Json(payload),
            timeout_class,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_bearer_auth(self, access_token: &str) -> Self {
        self.with_header("Authorization", format!("Bearer {access_token}"))
    }
}

#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers.get(&lower).map(String::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct TransportError {
    pub is_timeout: bool,
    pub is_connect: bool,
    pub message: String,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait HttpTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, TransportError>>;
}

/// Production `reqwest` (`rustls-tls-native-roots` + `socks`) HTTP transport.
/// Strictly verifies TLS certificate chains and hostnames; never disables certificate verification.
pub struct ReqwestTransport {
    proxy_mode: ProxyMode,
    proxied_api: reqwest::Client,
    proxied_oauth: reqwest::Client,
    proxied_version: reqwest::Client,
    direct_api: reqwest::Client,
    direct_oauth: reqwest::Client,
    direct_version: reqwest::Client,
}

impl ReqwestTransport {
    pub fn build(proxy_mode: ProxyMode) -> CliResult<Self> {
        let build_one = |class: TimeoutClass, use_proxy: bool| -> CliResult<reqwest::Client> {
            let (connect_timeout, total_timeout) = class.durations();
            let mut builder = reqwest::Client::builder()
                .connect_timeout(connect_timeout)
                .timeout(total_timeout)
                .tls_built_in_native_certs(true);

            if !use_proxy {
                builder = builder.no_proxy();
            } else {
                match &proxy_mode {
                    ProxyMode::Direct => {
                        builder = builder.no_proxy();
                    }
                    ProxyMode::Explicit {
                        proxy_url,
                        no_proxy,
                    } => {
                        let mut p = reqwest::Proxy::all(proxy_url).map_err(|e| {
                            CliError::usage(format!(
                                "Invalid proxy configuration: {}",
                                sanitize_reqwest_error(&e)
                            ))
                        })?;
                        if let Some(ref np) = no_proxy {
                            p = p.no_proxy(reqwest::NoProxy::from_string(np));
                        }
                        builder = builder.no_proxy().proxy(p);
                    }
                    ProxyMode::FromEnv {
                        https_proxy,
                        http_proxy,
                        all_proxy,
                        no_proxy,
                    } => {
                        builder = builder.no_proxy();
                        let np = no_proxy.as_deref().and_then(reqwest::NoProxy::from_string);
                        if let Some(ref hp) = https_proxy {
                            let mut p = reqwest::Proxy::https(hp).map_err(|e| {
                                CliError::usage(format!(
                                    "Invalid HTTPS_PROXY: {}",
                                    sanitize_reqwest_error(&e)
                                ))
                            })?;
                            p = p.no_proxy(np.clone());
                            builder = builder.proxy(p);
                        }
                        if let Some(ref hp) = http_proxy {
                            let mut p = reqwest::Proxy::http(hp).map_err(|e| {
                                CliError::usage(format!(
                                    "Invalid HTTP_PROXY: {}",
                                    sanitize_reqwest_error(&e)
                                ))
                            })?;
                            p = p.no_proxy(np.clone());
                            builder = builder.proxy(p);
                        }
                        if let Some(ref ap) = all_proxy {
                            let mut p = reqwest::Proxy::all(ap).map_err(|e| {
                                CliError::usage(format!(
                                    "Invalid ALL_PROXY: {}",
                                    sanitize_reqwest_error(&e)
                                ))
                            })?;
                            p = p.no_proxy(np);
                            builder = builder.proxy(p);
                        }
                    }
                }
            }

            builder.build().map_err(|e| {
                CliError::io(
                    "http_client_init_failed",
                    format!(
                        "Cannot initialize HTTP client: {}",
                        sanitize_reqwest_error(&e)
                    ),
                )
            })
        };

        Ok(Self {
            proxied_api: build_one(TimeoutClass::StandardApi, true)?,
            proxied_oauth: build_one(TimeoutClass::OAuthToken, true)?,
            proxied_version: build_one(TimeoutClass::VersionCheck, true)?,
            direct_api: build_one(TimeoutClass::StandardApi, false)?,
            direct_oauth: build_one(TimeoutClass::OAuthToken, false)?,
            direct_version: build_one(TimeoutClass::VersionCheck, false)?,
            proxy_mode,
        })
    }

    fn pick_client(&self, url: &str, class: TimeoutClass) -> &reqwest::Client {
        let bypass = Url::parse(url)
            .map(|u| self.proxy_mode.should_bypass(&u))
            .unwrap_or(false);
        match (bypass, class) {
            (true, TimeoutClass::StandardApi) => &self.direct_api,
            (true, TimeoutClass::OAuthToken) => &self.direct_oauth,
            (true, TimeoutClass::VersionCheck) => &self.direct_version,
            (false, TimeoutClass::StandardApi) => &self.proxied_api,
            (false, TimeoutClass::OAuthToken) => &self.proxied_oauth,
            (false, TimeoutClass::VersionCheck) => &self.proxied_version,
        }
    }
}

impl HttpTransport for ReqwestTransport {
    fn execute<'a>(
        &'a self,
        req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let client = self.pick_client(&req.url, req.timeout_class);
            let mut rb = match req.method {
                HttpMethod::Get => client.get(&req.url),
                HttpMethod::Post => client.post(&req.url),
            };
            for (k, v) in &req.headers {
                rb = rb.header(k, v);
            }
            rb = match &req.body {
                RequestBody::Empty => rb,
                RequestBody::Form(pairs) => rb.form(pairs),
                RequestBody::Json(val) => rb.json(val),
            };

            let resp = rb.send().await.map_err(|e| TransportError {
                is_timeout: e.is_timeout(),
                is_connect: e.is_connect(),
                message: sanitize_reqwest_error(&e),
            })?;

            let status = resp.status().as_u16();
            let mut headers = HashMap::new();
            for (k, v) in resp.headers() {
                if let Ok(val_str) = v.to_str() {
                    headers.insert(k.as_str().to_ascii_lowercase(), val_str.to_string());
                }
            }
            let body = resp
                .bytes()
                .await
                .map_err(|e| TransportError {
                    is_timeout: e.is_timeout(),
                    is_connect: false,
                    message: sanitize_reqwest_error(&e),
                })?
                .to_vec();

            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

fn sanitize_reqwest_error(err: &reqwest::Error) -> String {
    // Strip query strings, fragments, and proxy/URL userinfo (`user:pass@`) from any URL embedded in reqwest error display.
    let mut base = err.to_string();
    if let Some(url) = err.url() {
        let mut clean = url.clone();
        if clean.query().is_some() {
            clean.set_query(None);
        }
        if clean.fragment().is_some() {
            clean.set_fragment(None);
        }
        if !clean.username().is_empty() || clean.password().is_some() {
            let _ = clean.set_username("REDACTED");
            let _ = clean.set_password(None);
        }
        if clean.as_str() != url.as_str() {
            base = base.replace(url.as_str(), clean.as_str());
        }
    }
    redact_inline_url_userinfo(&base)
}

fn redact_inline_url_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(scheme_sep) = rest.find("://") {
        let after_scheme_idx = scheme_sep + 3;
        out.push_str(&rest[..after_scheme_idx]);
        let after_scheme = &rest[after_scheme_idx..];
        let authority_end = after_scheme
            .find(['/', '?', '#', ' ', ')', '\'', '"'])
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];
        if let Some((_userinfo, host_part)) = authority.rsplit_once('@') {
            out.push_str("REDACTED@");
            out.push_str(host_part);
        } else {
            out.push_str(authority);
        }
        rest = &after_scheme[authority_end..];
    }
    out.push_str(rest);
    out
}

pub type MockHandler =
    Arc<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

/// Deterministic offline mock transport for unit and integration tests.
#[derive(Clone, Default)]
pub struct MockTransport {
    queued: Arc<Mutex<VecDeque<Result<HttpResponse, TransportError>>>>,
    handler: Option<MockHandler>,
    recorded: Arc<Mutex<Vec<HttpRequest>>>,
    artificial_delay: Duration,
}

impl MockTransport {
    pub fn from_queue(
        responses: impl IntoIterator<Item = Result<HttpResponse, TransportError>>,
    ) -> Self {
        Self {
            queued: Arc::new(Mutex::new(responses.into_iter().collect())),
            handler: None,
            recorded: Arc::new(Mutex::new(Vec::new())),
            artificial_delay: Duration::ZERO,
        }
    }

    pub fn from_handler(
        f: impl Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            queued: Arc::new(Mutex::new(VecDeque::new())),
            handler: Some(Arc::new(f)),
            recorded: Arc::new(Mutex::new(Vec::new())),
            artificial_delay: Duration::ZERO,
        }
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.artificial_delay = delay;
        self
    }

    pub fn recorded_requests(&self) -> Vec<HttpRequest> {
        self.recorded.lock().unwrap().clone()
    }

    pub fn json_response(status: u16, value: serde_json::Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: HashMap::from([("content-type".into(), "application/json".into())]),
            body: serde_json::to_vec(&value).unwrap(),
        }
    }
}

impl HttpTransport for MockTransport {
    fn execute<'a>(
        &'a self,
        req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            if !self.artificial_delay.is_zero() {
                tokio::time::sleep(self.artificial_delay).await;
            }
            self.recorded.lock().unwrap().push(req.clone());
            if let Some(ref h) = self.handler {
                return h(&req);
            }
            self.queued.lock().unwrap().pop_front().unwrap_or_else(|| {
                Err(TransportError {
                    is_timeout: false,
                    is_connect: true,
                    message: format!(
                        "MockTransport queue exhausted for URL {}",
                        redact_url_for_debug(&req.url)
                    ),
                })
            })
        })
    }
}
