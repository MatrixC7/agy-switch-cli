use serde::Serialize;
use std::collections::HashSet;

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

fn is_canonical_nd_range_token(token: &str) -> bool {
    let Some(num_str) = token.strip_suffix('d') else {
        return false;
    };
    !num_str.is_empty()
        && num_str.len() <= 5
        && !num_str.starts_with('0')
        && num_str.bytes().all(|b| b.is_ascii_digit())
        && num_str
            .parse::<u32>()
            .map(|n| (1..=crate::cli::args::MAX_STATS_RANGE_DAYS).contains(&n))
            .unwrap_or(false)
}

#[derive(Debug, PartialEq, Eq)]
struct StaticCliAllowlist {
    flags: HashSet<String>,
    words: HashSet<String>,
    placeholders: HashSet<String>,
}

impl StaticCliAllowlist {
    /// Derive the public CLI token allowlist strictly by borrowing an already-constructed
    /// `clap::Command`'s static metadata — never rebuilding `Cli::command()`, never querying
    /// environment variables, and never reading `argv` or `bin_name`.
    fn from_command(root: &clap::Command) -> Self {
        let mut flags: HashSet<String> = ["--", "-h", "--help", "-V", "--version"]
            .into_iter()
            .map(str::to_string)
            .collect();
        // Public CLI syntax and non-`ValueEnum` custom-parser keywords only (never user argv/env).
        let mut words: HashSet<String> = [
            "help",
            "true",
            "false",
            "today",
            "yesterday",
            "all",
            "auto",
            "dual",
            "file",
            "keyring",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let mut placeholders: HashSet<String> = HashSet::new();

        fn collect_cmd(
            cmd: &clap::Command,
            flags: &mut HashSet<String>,
            words: &mut HashSet<String>,
            placeholders: &mut HashSet<String>,
        ) {
            words.insert(cmd.get_name().to_string());
            for arg in cmd.get_arguments() {
                if let Some(long) = arg.get_long() {
                    flags.insert(format!("--{long}"));
                }
                if let Some(short) = arg.get_short() {
                    flags.insert(format!("-{short}"));
                }
                for pv in arg.get_possible_values() {
                    if !pv.is_hide_set() {
                        words.insert(pv.get_name().to_string());
                    }
                }
                if arg.get_action().takes_values() {
                    let optional_val = arg.get_num_args().is_some_and(|r| r.min_values() == 0);
                    let multi_val =
                        arg.get_num_args().is_some_and(|r| r.max_values() > 1) || arg.is_last_set();
                    let mut insert_vn = |vn: &str| {
                        placeholders.insert(format!("<{vn}>"));
                        if optional_val {
                            placeholders.insert(format!("[<{vn}>]"));
                            placeholders.insert(format!("[{vn}]"));
                        }
                        if multi_val {
                            placeholders.insert(format!("<{vn}>..."));
                            placeholders.insert(format!("[<{vn}>...]"));
                        }
                    };
                    if let Some(vals) = arg.get_value_names() {
                        if !vals.is_empty() {
                            for vn in vals {
                                insert_vn(vn.as_str());
                            }
                        } else {
                            let fallback = arg.get_id().as_str().to_ascii_uppercase();
                            insert_vn(&fallback);
                        }
                    } else {
                        let fallback = arg.get_id().as_str().to_ascii_uppercase();
                        insert_vn(&fallback);
                    }
                }
            }
            for sub in cmd.get_subcommands() {
                collect_cmd(sub, flags, words, placeholders);
            }
        }

        collect_cmd(root, &mut flags, &mut words, &mut placeholders);
        Self {
            flags,
            words,
            placeholders,
        }
    }

    fn is_known_flag(&self, token: &str) -> bool {
        self.flags.contains(token)
    }

    fn is_known_word(&self, token: &str) -> bool {
        self.words.contains(token)
    }

    fn is_known_placeholder(&self, token: &str) -> bool {
        self.placeholders.contains(token)
    }

    fn is_safe_public_token(&self, token: &str) -> bool {
        let t = token.trim();
        if t.is_empty() || t.contains('=') {
            return false;
        }
        self.is_known_flag(t) || self.is_known_word(t) || is_canonical_nd_range_token(t)
    }

    fn is_safe_public_option_spec(&self, spec: &str) -> bool {
        // Strictly allow-lists actual clap option specs built ONLY from registered flags and placeholders
        let trimmed = spec.trim();
        if trimmed.is_empty() || trimmed.len() > 64 || trimmed.contains('=') {
            return false;
        }
        trimmed.split_whitespace().all(|part| {
            self.is_known_flag(part) || self.is_known_word(part) || self.is_known_placeholder(part)
        })
    }

    fn format_safe_unknown_token(&self, raw_token: &str) -> String {
        let trimmed = raw_token.trim();
        if (self.is_known_flag(trimmed) || self.is_known_word(trimmed))
            && !looks_like_secret_argument(trimmed)
        {
            return format!("'{trimmed}'");
        }
        if let Some((lhs, _rhs)) = trimmed.split_once('=') {
            if self.is_known_flag(lhs) {
                return format!("'{lhs}=[REDACTED]'");
            }
        }
        "'[REDACTED]'".to_string()
    }

    fn format_safe_arg_token(&self, raw_token: &str) -> String {
        let trimmed = raw_token.trim();
        if self.is_safe_public_option_spec(trimmed) && !looks_like_secret_argument(trimmed) {
            return format!("'{trimmed}'");
        }
        if let Some((lhs, _rhs)) = trimmed.split_once('=') {
            if self.is_known_flag(lhs) {
                return format!("'{lhs}=[REDACTED]'");
            }
        }
        "'[REDACTED]'".to_string()
    }
}

/// Sanitize `clap` argument parse errors STRUCTURALLY using `clap_err.kind()` + `clap_err.context()`
/// while borrowing static CLI metadata directly from the caller's already-constructed `cmd`
/// (zero secondary `Cli::command()` construction and zero additional environment variable reads),
/// so accidental secret positional/flag/env values (`accounts ... add <TOKEN>`, `4/...` OAuth codes,
/// embedded single quotes `'`, callback URLs, `--flag=<SECRET>`, or `AGY_SWITCH_CLI_*=<SECRET>`)
/// are NEVER formatted into strings or echoed back to `stderr` or JSON error envelopes.
pub fn format_safe_clap_error(
    cmd: &clap::Command,
    raw_args: &[String],
    clap_err: &clap::Error,
) -> String {
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
        return "Plaintext token positional arguments are forbidden on `accounts add` to prevent process-table and log exposure. Use the hidden-echo TTY prompt, `--from-local`, `--from-stdin`, or `--from-file <PATH>`.".to_string();
    }

    let allowlist = StaticCliAllowlist::from_command(cmd);

    let safe_ctx_arg = |kind: ContextKind| -> Option<String> {
        match clap_err.get(kind)? {
            ContextValue::String(s) => Some(allowlist.format_safe_arg_token(s)),
            ContextValue::Strings(list) => {
                let items: Vec<String> = list
                    .iter()
                    .map(|s| allowlist.format_safe_arg_token(s))
                    .collect();
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
                    .filter(|v| allowlist.is_safe_public_token(v))
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

    let safe_unknown_ctx = |kind: ContextKind| -> Option<String> {
        match clap_err.get(kind)? {
            ContextValue::String(s) => Some(allowlist.format_safe_unknown_token(s)),
            ContextValue::Strings(list) => {
                let items: Vec<String> = list
                    .iter()
                    .map(|s| allowlist.format_safe_unknown_token(s))
                    .collect();
                (!items.is_empty()).then(|| items.join(", "))
            }
            _ => None,
        }
    };

    let headline = match clap_err.kind() {
        ErrorKind::UnknownArgument => {
            let arg =
                safe_unknown_ctx(ContextKind::InvalidArg).unwrap_or_else(|| "'[REDACTED]'".into());
            format!("unexpected argument {arg} found")
        }
        ErrorKind::InvalidSubcommand => {
            let sub = safe_unknown_ctx(ContextKind::InvalidSubcommand)
                .unwrap_or_else(|| "'[REDACTED]'".into());
            format!("unrecognized subcommand {sub}")
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let arg = safe_ctx_arg(ContextKind::InvalidArg).unwrap_or_else(|| "option".into());
            let valid_hint = {
                let vals = safe_valid_values();
                if vals.is_empty() && arg == "'--range <RANGE>'" {
                    format!(
                        " (expected: today, yesterday, all, or <N>d with 1 <= N <= {})",
                        crate::cli::args::MAX_STATS_RANGE_DAYS
                    )
                } else if vals.is_empty() && arg == "'--recent <N>'" {
                    format!(
                        " (expected integer 1..={})",
                        crate::cli::args::MAX_STATS_RECENT_LIMIT
                    )
                } else {
                    vals
                }
            };
            format!("invalid value '[REDACTED]' for {arg}{valid_hint}")
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

pub(crate) fn has_explicit_secret_marker(val: &str) -> bool {
    let trimmed = val.trim();
    let lower = trimmed.to_ascii_lowercase();
    trimmed.starts_with("1//")
        || lower.starts_with("1%2f%2f")
        || trimmed.starts_with("4/")
        || lower.starts_with("4%2f")
        || lower.starts_with("ya29.")
        || lower.starts_with("gocspx-")
        || trimmed.starts_with("eyJ")
        || lower.starts_with("aiza")
        || lower.starts_with("sk-")
        || lower.starts_with("ghp_")
        || lower.starts_with("github_pat_")
        || lower.starts_with("glpat-")
        || lower.starts_with("xoxb-")
        || lower.starts_with("xoxp-")
        || lower.starts_with("bearer ")
        || lower.contains("code=")
        || lower.contains("refresh_token=")
        || lower.contains("access_token=")
        || lower.contains("client_secret=")
        || lower.contains("id_token=")
        || (trimmed.contains("://") && trimmed.contains('@'))
        || (trimmed.contains('|') && trimmed.len() >= 16)
}

pub(crate) fn looks_like_secret_value(val: &str) -> bool {
    let trimmed = val.trim();
    if has_explicit_secret_marker(trimmed) {
        return true;
    }
    let is_fs_path =
        trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../");
    trimmed.len() >= 28 && !trimmed.starts_with('-') && !is_fs_path && !trimmed.contains('@')
}

/// Detect accidental credential values (`1//...`, `4/...`, `ya29....`, `GOCSPX-...`, callback URLs,
/// or high-entropy bare opaque tokens) passed to filesystem path options (`--from-file`, `--from-legacy`,
/// `--output`, `--data-dir`) without falsely rejecting legitimate relative paths or new extensionless
/// single-segment filenames such as `my-accounts-backup-2026-11-19` or `production_export_snapshot_v1`.
pub(crate) fn path_looks_like_accidental_secret(path: &std::path::Path) -> bool {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    if has_explicit_secret_marker(trimmed) || trimmed.contains("://") {
        return true;
    }
    // Only treat a non-existent single-segment bare word as an accidental opaque token if it has
    // NO path/word separators (`/`, `\`, `.`, `-`, `_`, whitespace), is >= 28 chars of pure
    // Base64/alphanumeric characters, AND mixes uppercase, lowercase, and digits (high-entropy token shape).
    if trimmed.len() >= 28
        && !trimmed.contains('/')
        && !trimmed.contains('\\')
        && !trimmed.contains('.')
        && !trimmed.contains('-')
        && !trimmed.contains('_')
        && !trimmed.contains('@')
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'='))
    {
        let has_upper = trimmed.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = trimmed.bytes().any(|b| b.is_ascii_lowercase());
        let has_digit = trimmed.bytes().any(|b| b.is_ascii_digit());
        if has_upper && has_lower && has_digit && std::fs::symlink_metadata(path).is_err() {
            return true;
        }
    }
    false
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
                    "current",
                ],
                "FlagInlineSecret999",
            ),
            (
                &[
                    "agy-switch-cli",
                    "--proyx=socks5h://proxyuser:PROXY_PASS_SECRET@127.0.0.1:1080",
                    "current",
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
            (
                &[
                    "agy-switch-cli",
                    "stats",
                    "summary",
                    "--source",
                    "1//0gSTATS_SOURCE_SECRET_777",
                ],
                "STATS_SOURCE_SECRET_777",
            ),
            (
                &[
                    "agy-switch-cli",
                    "stats",
                    "summary",
                    "--range",
                    "1//0gSTATS_RANGE_SECRET_666",
                ],
                "STATS_RANGE_SECRET_666",
            ),
            (
                &[
                    "agy-switch-cli",
                    "stats",
                    "list",
                    "--recent",
                    "1//0gSTATS_RECENT_SECRET_555",
                ],
                "STATS_RECENT_SECRET_555",
            ),
            (
                &["agy-switch-cli", "stats", "4/0ASTATS_POSITIONAL_SECRET_888"],
                "STATS_POSITIONAL_SECRET_888",
            ),
            (
                &[
                    "agy-switch-cli",
                    "accounts",
                    "import",
                    "1//0gIMPORT_POSITIONAL_SECRET_444",
                ],
                "IMPORT_POSITIONAL_SECRET_444",
            ),
            (
                &[
                    "agy-switch-cli",
                    "stats",
                    "summary",
                    "--my-custom-secret-flag-123",
                ],
                "my-custom-secret-flag-123",
            ),
            (
                &["agy-switch-cli", "stats", "<FAKE_PLACEHOLDER_SECRET>"],
                "FAKE_PLACEHOLDER_SECRET",
            ),
            (
                &["agy-switch-cli", "stats", "[FAKE_BRACKET_SECRET]"],
                "FAKE_BRACKET_SECRET",
            ),
            (
                &[
                    "agy-switch-cli",
                    "accounts",
                    "add",
                    "--from-stdin=1//0gSTDIN_EQ_SECRET_333",
                ],
                "STDIN_EQ_SECRET_333",
            ),
            (
                &[
                    "agy-switch-cli",
                    "accounts",
                    "import",
                    "--from-file",
                    "/tmp/b.json",
                    "--overwrite=1//0gOVERWRITE_EQ_SECRET_222",
                ],
                "OVERWRITE_EQ_SECRET_222",
            ),
            (
                &[
                    "agy-switch-cli",
                    "accounts",
                    "export",
                    "--accounts",
                    "1//0gACCOUNTS_SECRET_111",
                    "--unknown-flag",
                ],
                "ACCOUNTS_SECRET_111",
            ),
            (&["agy-switch-cli", "stats", "summary", "-z"], "'-z'"),
        ];

        use clap::CommandFactory;
        let base_cmd = Cli::command();
        for (argv, forbidden) in cases {
            let args: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
            let mut cmd = base_cmd.clone();
            let err = cmd.try_get_matches_from_mut(&args).unwrap_err();
            let safe = format_safe_clap_error(&cmd, &args, &err);
            assert!(
                !safe.contains(forbidden),
                "Leaked '{forbidden}' in safe clap error for {argv:?}: {safe}"
            );
            assert!(
                !safe.starts_with("error:"),
                "format_safe_clap_error should not include leading `error:` prefix: {safe}"
            );
        }

        // Verify whitelisted `stats` enum suggestions, `<N>d` range guidance, and `--recent <N>` bounds remain intact
        let bad_src: Vec<String> = ["agy-switch-cli", "stats", "summary", "--source", "nope"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut src_cmd = base_cmd.clone();
        let src_err = src_cmd.try_get_matches_from_mut(&bad_src).unwrap_err();
        let src_msg = format_safe_clap_error(&src_cmd, &bad_src, &src_err);
        assert!(
            src_msg.contains("possible values: all, cli, app"),
            "{src_msg}"
        );

        let bad_rng: Vec<String> = ["agy-switch-cli", "stats", "summary", "--range", "nope"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut rng_cmd = base_cmd.clone();
        let rng_err = rng_cmd.try_get_matches_from_mut(&bad_rng).unwrap_err();
        let rng_msg = format_safe_clap_error(&rng_cmd, &bad_rng, &rng_err);
        assert!(
            rng_msg.contains("expected: today, yesterday, all, or <N>d with 1 <= N <= 36500"),
            "{rng_msg}"
        );

        let bad_recent: Vec<String> = ["agy-switch-cli", "stats", "list", "--recent", "501"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut rec_cmd = base_cmd.clone();
        let rec_err = rec_cmd.try_get_matches_from_mut(&bad_recent).unwrap_err();
        let rec_msg = format_safe_clap_error(&rec_cmd, &bad_recent, &rec_err);
        assert!(rec_msg.contains("expected integer 1..=500"), "{rec_msg}");

        // Verify removed legacy flags/subcommands/aliases are strictly rejected
        for removed in [
            &["agy-switch-cli", "doctor"][..],
            &["agy-switch-cli", "stats"],
            &["agy-switch-cli", "quota", "-r"],
            &["agy-switch-cli", "accounts", "add", "--stdin"],
            &[
                "agy-switch-cli",
                "accounts",
                "add",
                "--token-file",
                "/tmp/t",
            ],
            &["agy-switch-cli", "accounts", "import", "/tmp/b.json"],
            &[
                "agy-switch-cli",
                "accounts",
                "import",
                "--from-file",
                "/tmp/b.json",
                "--force",
            ],
            &[
                "agy-switch-cli",
                "accounts",
                "export",
                "--output",
                "/tmp/b.json",
                "--include-secrets",
                "--force",
            ],
            &[
                "agy-switch-cli",
                "accounts",
                "export",
                "--output",
                "/tmp/b.json",
                "--include-secrets",
                "--ids",
                "acc-1",
            ],
            &["agy-switch-cli", "run", "--isolate-dbus", "--", "agy"],
            &["agy-switch-cli", "auth", "login", "--manual"],
            &[
                "agy-switch-cli",
                "auth",
                "reauthorize",
                "alice@example.com",
                "--manual",
            ],
            &[
                "agy-switch-cli",
                "policy",
                "set",
                "--strategy",
                "round_robin",
            ],
            &["agy-switch-cli", "stats", "list", "-n", "10"],
        ] {
            assert!(
                Cli::try_parse_from(removed).is_err(),
                "Expected removed CLI syntax {removed:?} to be rejected"
            );
        }
    }

    #[test]
    fn literal_cli_allowlist_covers_all_registered_commands_and_flags() {
        use clap::CommandFactory;
        let unbuilt_cmd = Cli::command();
        let mut built_cmd = unbuilt_cmd.clone();
        built_cmd.build();
        let allowlist = StaticCliAllowlist::from_command(&unbuilt_cmd);
        let built_allowlist = StaticCliAllowlist::from_command(&built_cmd);
        assert_eq!(
            allowlist, built_allowlist,
            "StaticCliAllowlist must derive identical sets from unbuilt and built Commands without rebuilding"
        );

        fn verify_cmd(cmd: &clap::Command, allowlist: &StaticCliAllowlist) {
            assert!(
                allowlist.is_known_word(cmd.get_name()),
                "Missing command '{}' in StaticCliAllowlist::words",
                cmd.get_name()
            );
            for arg in cmd.get_arguments() {
                if let Some(long) = arg.get_long() {
                    let flag = format!("--{long}");
                    assert!(
                        allowlist.is_known_flag(&flag),
                        "Missing long flag '{flag}' in StaticCliAllowlist::flags"
                    );
                }
                if let Some(short) = arg.get_short() {
                    let flag = format!("-{short}");
                    assert!(
                        allowlist.is_known_flag(&flag),
                        "Missing short flag '{flag}' in StaticCliAllowlist::flags"
                    );
                }
                if arg.get_action().takes_values() {
                    if let Some(vals) = arg.get_value_names() {
                        for vn in vals {
                            let angle = format!("<{vn}>");
                            assert!(
                                allowlist.is_known_placeholder(&angle),
                                "Missing placeholder '{angle}' in StaticCliAllowlist::placeholders"
                            );
                        }
                    }
                }
            }
            for sub in cmd.get_subcommands() {
                verify_cmd(sub, allowlist);
            }
        }
        verify_cmd(&built_cmd, &allowlist);

        // Verify derived enum words and multi/optional placeholder variants remain covered.
        for word in [
            "priority",
            "round-robin",
            "immediate",
            "wait",
            "all",
            "cli",
            "app",
            "auto",
            "dual",
            "file",
            "keyring",
            "today",
            "yesterday",
            "true",
            "false",
        ] {
            assert!(
                allowlist.is_known_word(word),
                "Expected public word '{word}'"
            );
        }
        for ph in [
            "<CONCURRENCY>",
            "<ENABLED>",
            "<STRATEGY>",
            "<MODE>",
            "<RESERVE>",
            "<MINIMUM>",
            "<ID|EMAIL>...",
            "[<LEGACY_DIR>]",
            "[LEGACY_DIR]",
            "<AGY_ARGS>...",
            "[<AGY_ARGS>...]",
            "[<SECS>]",
        ] {
            assert!(
                allowlist.is_known_placeholder(ph),
                "Expected derived placeholder '{ph}'"
            );
        }

        // Verify removed/unknown flags, fake placeholders, and secret shapes are strictly excluded.
        for bad_flag in ["--reason", "--manual", "--stdin", "--ids", "-z", "--secret"] {
            assert!(
                !allowlist.is_known_flag(bad_flag),
                "Removed/unknown flag '{bad_flag}' must not be allowlisted"
            );
        }
        for bad_ph in ["<FAKE_PLACEHOLDER_SECRET>", "[FAKE_BRACKET_SECRET]"] {
            assert!(
                !allowlist.is_known_placeholder(bad_ph),
                "Fake placeholder '{bad_ph}' must not be allowlisted"
            );
        }
        for bad_word in ["1//0gSyntheticSecret", "alice@example.com", "doctor"] {
            assert!(
                !allowlist.is_known_word(bad_word),
                "Unknown/secret token '{bad_word}' must not be allowlisted"
            );
        }

        // Prove `format_safe_clap_error` strictly borrows the passed `&clap::Command` without
        // ever calling `Cli::command()` (which would otherwise read `#[arg(env = ...)]` vars):
        let mut isolated_cmd = clap::Command::new("isolated-test-cmd").arg(
            clap::Arg::new("alpha")
                .long("alpha")
                .value_name("VAL")
                .action(clap::ArgAction::Set),
        );
        let isolated_args: Vec<String> = ["isolated-test-cmd", "--data-dir=1//0gSecretValue"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let isolated_err = isolated_cmd
            .try_get_matches_from_mut(&isolated_args)
            .unwrap_err();
        let isolated_msg = format_safe_clap_error(&isolated_cmd, &isolated_args, &isolated_err);
        assert!(
            !isolated_msg.contains("--data-dir") && !isolated_msg.contains("SecretValue"),
            "format_safe_clap_error must borrow only the passed Command (not rebuild Cli::command()): {isolated_msg}"
        );
        assert!(
            isolated_msg.contains("'[REDACTED]'"),
            "expected redacted unknown arg in isolated command test: {isolated_msg}"
        );
    }
}
