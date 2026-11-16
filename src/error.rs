use serde::Serialize;

/// Stable CLI exit codes per Blueprint §8.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Ok = 0,
    GeneralOrDataError = 1,
    InvalidUsageOrAmbiguous = 2,
    AccountNotFound = 3,
    QuotaUnavailableOrStale = 4,
    LockBusyOrConflict = 5,
    AuthOrClientError = 6,
    PartialCommitOrRecovery = 7,
    EnvironmentNotReady = 8,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as u8 as i32
    }

    pub fn default_error_code(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::GeneralOrDataError => "general_or_data_error",
            Self::InvalidUsageOrAmbiguous => "invalid_usage_or_ambiguous",
            Self::AccountNotFound => "account_not_found",
            Self::QuotaUnavailableOrStale => "quota_unavailable_or_stale",
            Self::LockBusyOrConflict => "lock_busy_or_conflict",
            Self::AuthOrClientError => "auth_or_client_error",
            Self::PartialCommitOrRecovery => "partial_commit_or_recovery",
            Self::EnvironmentNotReady => "environment_not_ready",
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    pub exit_code: ExitCode,
    pub error_code: String,
    pub message: String,
    /// Optional structured safe details (boxed to keep `Result<T, CliError>` compact at 64 bytes)
    pub details: Option<Box<serde_json::Value>>,
}

impl CliError {
    pub fn new(
        exit_code: ExitCode,
        error_code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            exit_code,
            error_code: error_code.into(),
            message: sanitize_error_message(&message.into()),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(Box::new(details));
        self
    }

    pub fn data(message: impl Into<String>) -> Self {
        Self::new(ExitCode::GeneralOrDataError, "data_error", message)
    }

    pub fn io(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ExitCode::GeneralOrDataError, error_code, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ExitCode::InvalidUsageOrAmbiguous, "invalid_usage", message)
    }

    pub fn ambiguous(message: impl Into<String>) -> Self {
        Self::new(
            ExitCode::InvalidUsageOrAmbiguous,
            "ambiguous_selector",
            message,
        )
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ExitCode::AccountNotFound, "account_not_found", message)
    }

    pub fn quota_unavailable(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ExitCode::QuotaUnavailableOrStale, error_code, message)
    }

    pub fn lock_busy(message: impl Into<String>) -> Self {
        Self::new(ExitCode::LockBusyOrConflict, "lock_busy", message)
    }

    pub fn conflict(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ExitCode::LockBusyOrConflict, error_code, message)
    }

    pub fn auth(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ExitCode::AuthOrClientError, error_code, message)
    }

    pub fn partial_commit(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ExitCode::PartialCommitOrRecovery, error_code, message)
    }

    pub fn env_not_ready(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ExitCode::EnvironmentNotReady, error_code, message)
    }

    pub fn to_json_line(&self) -> String {
        #[derive(Serialize)]
        struct ErrorEnvelope<'a> {
            schema_version: u32,
            ok: bool,
            error_code: &'a str,
            exit_code: i32,
            message: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            details: Option<&'a serde_json::Value>,
        }
        serde_json::to_string(&ErrorEnvelope {
            schema_version: 1,
            ok: false,
            error_code: &self.error_code,
            exit_code: self.exit_code.as_i32(),
            message: &self.message,
            details: self.details.as_deref(),
        })
        .unwrap_or_else(|_| {
            format!(
                r#"{{"schema_version":1,"ok":false,"error_code":"internal_serialize_error","exit_code":{},"message":"error serialization failed"}}"#,
                self.exit_code.as_i32()
            )
        })
    }
}

pub type CliResult<T> = Result<T, CliError>;

/// Strip terminal control characters (including ESC / ANSI sequences) from dynamic error strings.
pub fn sanitize_error_message(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Format `serde_json::Error` safely by reporting ONLY category + line + column,
/// NEVER calling `err.to_string()` (which embeds offending string literals from corrupted JSON!).
pub fn format_safe_json_error(context: &str, err: &serde_json::Error) -> String {
    let category = match err.classify() {
        serde_json::error::Category::Io => "I/O error",
        serde_json::error::Category::Syntax => "syntax error",
        serde_json::error::Category::Data => "data/type mismatch",
        serde_json::error::Category::Eof => "unexpected EOF",
    };
    format!(
        "{context} is invalid JSON ({category} at line {}, column {}).",
        err.line(),
        err.column()
    )
}

fn is_safe_public_cli_token(token: &str) -> bool {
    let t = token.trim();
    if t.is_empty() || t.contains('=') {
        return false;
    }
    if let Some(flag_body) = t.strip_prefix("--") {
        return !flag_body.is_empty()
            && flag_body.len() <= 40
            && flag_body
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    }
    if let Some(short_body) = t.strip_prefix('-') {
        return short_body.len() == 1 && short_body.as_bytes()[0].is_ascii_alphabetic();
    }
    matches!(
        t,
        "agy-switch-cli"
            | "doctor"
            | "auth"
            | "login"
            | "reauthorize"
            | "clients"
            | "pending"
            | "accounts"
            | "list"
            | "add"
            | "import"
            | "export"
            | "order"
            | "enable"
            | "disable"
            | "delete"
            | "status"
            | "current"
            | "switch"
            | "run"
            | "quota"
            | "refresh"
            | "policy"
            | "show"
            | "set"
            | "eval"
            | "daemon"
            | "tui"
            | "priority"
            | "round-robin"
            | "round_robin"
            | "wait"
            | "stop"
            | "true"
            | "false"
    ) || (t.starts_with('<') && t.ends_with('>'))
}

fn is_safe_public_option_spec(spec: &str) -> bool {
    // Matches clap option specs such as `--interval <INTERVAL>`, `-h`, `--json`, `<ID|EMAIL>`, `[FILE]`
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.contains('=') {
        return false;
    }
    trimmed.split_whitespace().all(|part| {
        is_safe_public_cli_token(part)
            || (part.starts_with('<')
                && part.ends_with('>')
                && part[1..part.len() - 1]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'|' | b'.')))
            || (part.starts_with('[')
                && part.ends_with(']')
                && part[1..part.len() - 1]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'|' | b'.')))
    })
}

fn format_safe_arg_token(raw_token: &str) -> String {
    let trimmed = raw_token.trim();
    if is_safe_public_option_spec(trimmed) && !looks_like_secret_argument(trimmed) {
        return format!("'{trimmed}'");
    }
    if let Some((lhs, _rhs)) = trimmed.split_once('=') {
        if is_safe_public_cli_token(lhs) {
            return format!("'{lhs}=[REDACTED]'");
        }
    }
    "'[REDACTED]'".to_string()
}

/// Sanitize `clap` argument parse errors STRUCTURALLY using `clap_err.kind()` + `clap_err.context()`
/// so accidental secret positional/flag/env values (`accounts ... add <TOKEN>`, `4/...` OAuth codes,
/// embedded single quotes `'`, callback URLs, `--flag=<SECRET>`, or `AGY_SWITCH_CLI_*=<SECRET>`)
/// are NEVER formatted into strings or echoed back to `stderr` or JSON error envelopes.
pub fn format_safe_clap_error(raw_args: &[String], clap_err: &clap::Error) -> String {
    use clap::error::{ContextKind, ContextValue, ErrorKind};

    let pre_passthrough: Vec<&str> = raw_args
        .iter()
        .skip(1)
        .map(String::as_str)
        .take_while(|a| *a != "--")
        .collect();

    let pos_accounts = pre_passthrough.iter().position(|a| *a == "accounts");
    let pos_add = pre_passthrough.iter().position(|a| *a == "add");
    let is_accounts_add = matches!((pos_accounts, pos_add), (Some(i), Some(j)) if i < j);

    if is_accounts_add
        && matches!(
            clap_err.kind(),
            ErrorKind::UnknownArgument | ErrorKind::TooManyValues | ErrorKind::InvalidValue
        )
    {
        return "Plaintext token positional arguments are forbidden on `accounts add` to prevent process-table and log exposure. Use the hidden-echo TTY prompt, `--stdin`, or `--token-file <PATH>`.".to_string();
    }

    let safe_ctx_arg = |kind: ContextKind| -> Option<String> {
        match clap_err.get(kind)? {
            ContextValue::String(s) => Some(format_safe_arg_token(s)),
            ContextValue::Strings(list) => {
                let items: Vec<String> = list.iter().map(|s| format_safe_arg_token(s)).collect();
                (!items.is_empty()).then(|| items.join(", "))
            }
            _ => None,
        }
    };

    let safe_valid_values = || -> String {
        match clap_err.get(ContextKind::ValidValue) {
            Some(ContextValue::Strings(vals)) => {
                let allowed: Vec<&str> = vals
                    .iter()
                    .map(String::as_str)
                    .filter(|v| is_safe_public_cli_token(v))
                    .collect();
                if allowed.is_empty() {
                    String::new()
                } else {
                    format!(" (possible values: {})", allowed.join(", "))
                }
            }
            _ => String::new(),
        }
    };

    let headline = match clap_err.kind() {
        ErrorKind::UnknownArgument => {
            let arg =
                safe_ctx_arg(ContextKind::InvalidArg).unwrap_or_else(|| "'[REDACTED]'".into());
            format!("unexpected argument {arg} found")
        }
        ErrorKind::InvalidSubcommand => {
            let sub = safe_ctx_arg(ContextKind::InvalidSubcommand)
                .unwrap_or_else(|| "'[REDACTED]'".into());
            format!("unrecognized subcommand {sub}")
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let arg = safe_ctx_arg(ContextKind::InvalidArg).unwrap_or_else(|| "option".into());
            format!(
                "invalid value '[REDACTED]' for {arg}{}",
                safe_valid_values()
            )
        }
        ErrorKind::TooManyValues => {
            let arg = safe_ctx_arg(ContextKind::InvalidArg).unwrap_or_else(|| "option".into());
            format!("unexpected extra value supplied for {arg}")
        }
        ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            let arg = safe_ctx_arg(ContextKind::InvalidArg).unwrap_or_else(|| "option".into());
            format!("insufficient values supplied for {arg}")
        }
        ErrorKind::MissingRequiredArgument => {
            let req = safe_ctx_arg(ContextKind::InvalidArg)
                .unwrap_or_else(|| "required arguments".into());
            format!("the following required arguments were not provided: {req}")
        }
        ErrorKind::MissingSubcommand => {
            "a subcommand is required but one was not provided".to_string()
        }
        ErrorKind::ArgumentConflict => {
            let arg = safe_ctx_arg(ContextKind::InvalidArg).unwrap_or_else(|| "argument".into());
            if let Some(prior) = safe_ctx_arg(ContextKind::PriorArg) {
                format!("the argument {arg} cannot be used with {prior}")
            } else {
                format!("conflicting command-line argument {arg}")
            }
        }
        ErrorKind::NoEquals => {
            let arg = safe_ctx_arg(ContextKind::InvalidArg).unwrap_or_else(|| "option".into());
            format!("equal sign is needed when assigning values to {arg}")
        }
        ErrorKind::InvalidUtf8 => {
            "invalid UTF-8 was detected in one or more arguments or environment options".to_string()
        }
        _ => "invalid command-line arguments".to_string(),
    };

    let usage_tail = match clap_err.get(ContextKind::Usage) {
        Some(ContextValue::StyledStr(u)) => {
            let u_str = u.to_string();
            format!(
                "\n\n{}\n\nFor more information, try '--help'.",
                u_str.trim()
            )
        }
        _ => " (try '--help' for usage)".to_string(),
    };

    format!("{headline}{usage_tail}")
}

fn looks_like_secret_argument(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Some((_, rhs)) = trimmed.split_once('=') {
        if looks_like_secret_value(rhs) {
            return true;
        }
    }
    looks_like_secret_value(trimmed)
}

pub(crate) fn looks_like_secret_value(val: &str) -> bool {
    let trimmed = val.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.starts_with("1//")
        || lower.starts_with("1%2f%2f")
        || trimmed.starts_with("4/")
        || lower.starts_with("4%2f")
        || lower.starts_with("ya29.")
        || lower.starts_with("gocspx-")
        || trimmed.starts_with("eyJ")
        || lower.starts_with("aiza")
        || lower.contains("code=")
        || lower.contains("refresh_token=")
        || lower.contains("access_token=")
        || lower.contains("client_secret=")
        || lower.contains("id_token=")
        || (trimmed.contains("://") && trimmed.contains('@'))
        || (trimmed.contains('|') && trimmed.len() >= 16)
    {
        return true;
    }
    let is_fs_path =
        trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../");
    trimmed.len() >= 28 && !trimmed.starts_with('-') && !is_fs_path && !trimmed.contains('@')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::Cli;
    use clap::Parser;

    #[test]
    fn clap_error_redacts_non_adjacent_accounts_add_and_oauth_auth_codes() {
        let cases: &[(&[&str], &str)] = &[
            (
                &[
                    "agy-switch-cli",
                    "accounts",
                    "--json",
                    "add",
                    "short-secret-tok",
                ],
                "short-secret-tok",
            ),
            (
                &[
                    "agy-switch-cli",
                    "--data-dir",
                    "/tmp/d",
                    "accounts",
                    "--no-remote-version",
                    "add",
                    "1//0gInterleavedSecret",
                ],
                "0gInterleavedSecret",
            ),
            (
                &[
                    "agy-switch-cli",
                    "auth",
                    "login",
                    "4/0AanRRrtSuperSecretAuthCode_123",
                ],
                "0AanRRrtSuperSecretAuthCode_123",
            ),
            (
                &["agy-switch-cli", "auth", "login", "4%2F0AbcShortCode"],
                "0AbcShortCode",
            ),
            (
                &[
                    "agy-switch-cli",
                    "auth",
                    "login",
                    "--manual=http://127.0.0.1:54545/oauth-callback?code=4/0AbcSecret&state=xyz",
                ],
                "0AbcSecret",
            ),
            (
                &[
                    "agy-switch-cli",
                    "--unknown-opt=GOCSPX-FlagInlineSecret999",
                    "status",
                ],
                "FlagInlineSecret999",
            ),
            (
                &[
                    "agy-switch-cli",
                    "--proyx=socks5h://proxyuser:PROXY_PASS_SECRET@127.0.0.1:1080",
                    "status",
                ],
                "PROXY_PASS_SECRET",
            ),
            (
                &[
                    "agy-switch-cli",
                    "auth",
                    "login",
                    "4/PART1'LEAKED_OAUTH_SECRET_99999",
                ],
                "LEAKED_OAUTH_SECRET_99999",
            ),
            (
                &[
                    "agy-switch-cli",
                    "daemon",
                    "--interval",
                    "1//PART1'LEAKED_ARGV_SECRET_99999",
                ],
                "LEAKED_ARGV_SECRET_99999",
            ),
        ];

        for (argv, forbidden) in cases {
            let args: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
            let err = Cli::try_parse_from(&args).unwrap_err();
            let safe = format_safe_clap_error(&args, &err);
            assert!(
                !safe.contains(forbidden),
                "Leaked '{forbidden}' in safe clap error for {argv:?}: {safe}"
            );
            assert!(
                !safe.starts_with("error:"),
                "format_safe_clap_error should not include leading `error:` prefix: {safe}"
            );
        }
    }
}
