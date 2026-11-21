use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "agy-switch-cli",
    version,
    about = "Headless multi-account manager and credential switcher for Antigravity CLI (agy)"
)]
pub struct Cli {
    /// Independent store directory (overrides AGY_SWITCH_CLI_DATA_DIR and XDG_DATA_HOME)
    #[arg(long, global = true, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Explicit proxy URL (http://, https://, socks5://, socks5h://, host:port, or `direct`; overrides AGY_SWITCH_CLI_PROXY)
    #[arg(long, global = true, value_name = "URL")]
    pub proxy: Option<String>,

    /// Credential backend (`auto` [default], `dual`, `file`, or `keyring`; overrides AGY_SWITCH_CLI_BACKEND)
    #[arg(long, global = true, value_name = "BACKEND")]
    pub backend: Option<String>,

    /// Disable optional cached remote User-Agent version lookup on network commands
    #[arg(long, global = true)]
    pub no_remote_version: bool,

    /// Output machine-readable JSON (`schema_version: 1`)
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Read-only environment, store, journal, daemon, and official `agy` status
    Status,

    /// OAuth 2.0 authorization management (manual callback URL paste by default, or `--ssh` local listener)
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Account pool management (secret-safe: zero plaintext token argv!)
    #[command(subcommand)]
    Accounts(AccountsCommand),

    /// Inspect current selected account, active `agy` slot sync, live runtime state, and supported models
    Current,

    /// Switch active `agy` credential slot to the selected account (applies to new `agy` invocations)
    Switch(SwitchArgs),

    /// Optional managed launcher for official `agy` (`--account` / `--backend` credential wrapper)
    Run(RunArgs),

    /// View pool quota table (pure local read by default; pass `--refresh` to fetch live quota first)
    Quota(QuotaArgs),

    /// Refresh OAuth tokens and CloudCode quotas over the network
    Refresh(RefreshArgs),

    /// Auto-switch policy configuration and dry-run evaluation
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Foreground 7-stage auto-switch daemon (managed by systemd --user or container init)
    Daemon(DaemonArgs),

    /// Read-only local SQLite token usage statistics (`summary` and `list`)
    #[command(subcommand)]
    Stats(StatsCommand),

    /// Optional interactive SSH terminal dashboard
    Tui,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Authorize and add a new account via PKCE (`S256`) + `state`
    Login(AuthLoginArgs),
    /// Re-authorize an existing account (e.g. after grant revocation or scope changes)
    Reauthorize(AuthReauthorizeArgs),
    /// List registered OAuth clients (pure read-only)
    Clients,
    /// Inspect, resume, or purge staged `pending_auth` records from interrupted OAuth flows
    Pending(AuthPendingArgs),
}

#[derive(Debug, Args)]
pub struct AuthPendingArgs {
    /// Complete `userinfo` lookup and bind staged `pending_auth` records into saved accounts
    #[arg(long, conflicts_with = "purge")]
    pub resume: bool,

    /// Discard all staged `pending_auth` records in `state/pending_auth/`
    #[arg(long, conflicts_with = "resume")]
    pub purge: bool,
}

#[derive(Debug, Args)]
pub struct AuthLoginArgs {
    /// OAuth client key
    #[arg(long, value_name = "KEY")]
    pub client: Option<String>,

    /// Start local `127.0.0.1` HTTP callback listener (for SSH `-L` port forwarding or local desktop browser)
    #[arg(long)]
    pub ssh: bool,

    /// Fixed loopback callback port on 127.0.0.1 (used in both default paste mode and `--ssh` listener mode)
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    /// Attempt to launch local browser via `xdg-open` (disabled by default in headless mode)
    #[arg(long)]
    pub open_browser: bool,

    /// Optional custom label for the account
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,
}

#[derive(Debug, Args)]
pub struct AuthReauthorizeArgs {
    /// Account ID or case-insensitive Email
    #[arg(value_name = "ID|EMAIL")]
    pub selector: String,

    #[arg(long, value_name = "KEY")]
    pub client: Option<String>,

    /// Start local `127.0.0.1` HTTP callback listener (for SSH `-L` port forwarding or local desktop browser)
    #[arg(long)]
    pub ssh: bool,

    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    #[arg(long)]
    pub open_browser: bool,
}

#[derive(Debug, Subcommand)]
pub enum AccountsCommand {
    /// List saved accounts with plan/status details, or reorder accounts (`--move` / `--order`)
    List(AccountsListArgs),
    /// Add accounts via masked TTY prompt, `--from-local`, `--from-stdin`, or `0600` `--from-file` (no positional token!)
    Add(AccountsAddArgs),
    /// Import accounts from `--from-file` v1/v2 JSON bundle or `--from-legacy` desktop directory
    Import(AccountsImportArgs),
    /// Export accounts to a `0600` private file (requires `--include-secrets`)
    Export(AccountsExportArgs),
    /// Enable a disabled account
    Enable {
        #[arg(value_name = "ID|EMAIL")]
        selector: String,
    },
    /// Manually disable an account
    Disable {
        #[arg(value_name = "ID|EMAIL")]
        selector: String,
    },
    /// Delete an account from the local store
    Delete(AccountsDeleteArgs),
}

#[derive(Debug, Args)]
pub struct AccountsListArgs {
    /// Move a single account (by ID or Email) to `--to <POSITION>`
    #[arg(
        long = "move",
        value_name = "ID|EMAIL",
        requires = "to",
        conflicts_with = "order"
    )]
    pub move_target: Option<String>,

    /// Target 1-based position (`1..=N`) when using `--move`
    #[arg(
        long,
        value_name = "POSITION",
        requires = "move_target",
        conflicts_with = "order"
    )]
    pub to: Option<usize>,

    /// Reorder all accounts at once (pass every account by ID or Email)
    #[arg(long, num_args = 1.., value_name = "ID|EMAIL")]
    pub order: Option<Vec<String>>,
}

#[derive(Debug, Args)]
pub struct AccountsAddArgs {
    /// Import the currently signed-in local Antigravity account (from desktop keyring or `~/.gemini/antigravity-cli/antigravity-oauth-token`)
    #[arg(long, conflicts_with_all = ["from_stdin", "from_file"])]
    pub from_local: bool,

    /// Read one or more refresh tokens (one per line) from standard input pipe
    #[arg(long, conflicts_with_all = ["from_file", "from_local"])]
    pub from_stdin: bool,

    /// Read one or more refresh tokens (one per line; `# label` comments supported) from a `0600` regular file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["from_stdin", "from_local"])]
    pub from_file: Option<PathBuf>,

    /// Optional default custom label
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,

    /// Optional bound OAuth client key
    #[arg(long, value_name = "KEY")]
    pub client: Option<String>,
}

#[derive(Debug, Args)]
pub struct AccountsImportArgs {
    /// Path to v1/v2 transfer bundle JSON file
    #[arg(long, value_name = "FILE", conflicts_with = "from_legacy")]
    pub from_file: Option<PathBuf>,

    /// Read-only migration from legacy desktop directory (defaults to `~/.antigravity_tools` if flag given without path)
    #[arg(long, value_name = "LEGACY_DIR", num_args = 0..=1, default_missing_value = "", conflicts_with = "from_file")]
    pub from_legacy: Option<String>,

    /// Explicitly update existing accounts' tokens (still refuses to roll back known rotated refresh tokens)
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct AccountsExportArgs {
    /// Target output file path (created atomically with `0600` permissions)
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Explicit confirmation required because export contains plaintext `refresh_token`s
    #[arg(long)]
    pub include_secrets: bool,

    /// Optional subset of account IDs or emails to export
    #[arg(long, num_args = 1.., value_name = "ID|EMAIL")]
    pub accounts: Vec<String>,

    /// Overwrite `--output` if it already exists
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct AccountsDeleteArgs {
    #[arg(value_name = "ID|EMAIL")]
    pub selector: String,

    /// Also remove active `~/.gemini/antigravity-cli/antigravity-oauth-token` if it matches this account
    #[arg(long)]
    pub clear_active_slot: bool,

    /// Allow deleting the currently `selected_account` (clears local selection)
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SwitchArgs {
    /// Account ID or case-insensitive Email
    #[arg(value_name = "ID|EMAIL")]
    pub selector: String,

    /// Validate preconditions without modifying any files or making network calls
    #[arg(long)]
    pub dry_run: bool,

    /// Override fail-closed process check even when `/proc` runtime state is unverified
    #[arg(long, conflicts_with = "require_idle")]
    pub allow_running: bool,

    /// Refuse to switch if any running `agy` process is currently active (exit code 8)
    #[arg(long, conflicts_with = "allow_running")]
    pub require_idle: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Explicitly switch to this account before launching `agy`
    #[arg(long, value_name = "ID|EMAIL")]
    pub account: Option<String>,

    /// Official `agy` command and arguments (`-- agy ...`)
    #[arg(last = true, required = true, value_name = "AGY_ARGS")]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct QuotaArgs {
    #[arg(value_name = "ID|EMAIL", conflicts_with = "all")]
    pub selector: Option<String>,

    /// Show quotas for all saved accounts
    #[arg(long)]
    pub all: bool,

    /// Refresh CloudCode quota over the network first before displaying the quota table
    #[arg(long)]
    pub refresh: bool,

    /// Bounded concurrency when refreshing multiple accounts with `--refresh --all` (`1..=5`, default `2`)
    #[arg(long, default_value_t = 2, requires = "refresh", value_parser = clap::value_parser!(u8).range(1..=5))]
    pub concurrency: u8,
}

#[derive(Debug, Args)]
pub struct RefreshArgs {
    #[arg(value_name = "ID|EMAIL", conflicts_with = "all")]
    pub selector: Option<String>,

    /// Refresh all enabled accounts
    #[arg(long)]
    pub all: bool,

    /// Bounded concurrency for multi-account refresh (`1..=5`, default `2`)
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=5))]
    pub concurrency: u8,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Show current auto-switch policy (pure read-only)
    Show,
    /// Validate and persist policy updates
    Set(PolicySetArgs),
    /// Reorder configured policy candidate accounts
    Order {
        #[arg(required = true, num_args = 1.., value_name = "ID|EMAIL")]
        selectors: Vec<String>,
    },
    /// Dry-run evaluate switching decision against local cached quotas (zero writes/network)
    Eval,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliStrategy {
    Priority,
    #[value(name = "round-robin")]
    RoundRobin,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliMode {
    Immediate,
    Wait,
}

#[derive(Debug, Args)]
pub struct PolicySetArgs {
    #[arg(long)]
    pub enabled: Option<bool>,

    #[arg(long, value_enum)]
    pub strategy: Option<CliStrategy>,

    #[arg(long, value_enum)]
    pub mode: Option<CliMode>,

    #[arg(long)]
    pub reserve: Option<u8>,

    #[arg(long)]
    pub minimum: Option<u8>,

    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,

    #[arg(
        long,
        num_args = 1..,
        value_name = "ID|EMAIL",
        conflicts_with_all = ["clear_candidates", "all_candidates"]
    )]
    pub candidates: Option<Vec<String>>,

    /// Automatically add all currently enabled accounts (in `accounts list` order) as candidates
    #[arg(long, conflicts_with_all = ["candidates", "clear_candidates"])]
    pub all_candidates: bool,

    #[arg(long, conflicts_with_all = ["candidates", "all_candidates"])]
    pub clear_candidates: bool,
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Poll interval in seconds (default: 180 / 3 minutes; in-memory unless persisted via `--install` or `AGY_SWITCH_CLI_INTERVAL`)
    #[arg(
        long,
        env = "AGY_SWITCH_CLI_INTERVAL",
        hide_env_values = true,
        value_name = "INTERVAL"
    )]
    pub interval: Option<u64>,

    /// Post-switch cooldown in seconds (default: 3600 / 1 hour; in-memory unless persisted via `--install` or `AGY_SWITCH_CLI_COOLDOWN`)
    #[arg(
        long,
        env = "AGY_SWITCH_CLI_COOLDOWN",
        hide_env_values = true,
        value_name = "COOLDOWN"
    )]
    pub cooldown: Option<i64>,

    /// Run a single 7-stage evaluation/commit tick and exit
    #[arg(long, conflicts_with_all = ["install", "uninstall"])]
    pub once: bool,

    /// Install and start `~/.config/systemd/user/agy-switch-cli.service` via `systemctl --user`
    #[arg(long, conflicts_with_all = ["once", "uninstall"])]
    pub install: bool,

    /// Stop, disable, and remove `~/.config/systemd/user/agy-switch-cli.service` via `systemctl --user`
    #[arg(long, conflicts_with_all = ["once", "install"])]
    pub uninstall: bool,

    /// Disable Linux desktop notifications (`org.freedesktop.Notifications`) for daemon switch/pause events (overrides AGY_SWITCH_CLI_NOTIFY and `config.json`)
    #[arg(long, conflicts_with = "uninstall")]
    pub no_notify: bool,

    /// Clear any active post-switch cooldown in `state/daemon_state.json` (works standalone while a daemon is running, or combined with `--once` / `--install`)
    #[arg(long, conflicts_with = "uninstall")]
    pub reset_cooldown: bool,

    /// In-memory override for active-process guard mode (`immediate` or `wait`; overrides AGY_SWITCH_CLI_MODE and `policy.json`)
    #[arg(long, value_enum)]
    pub mode: Option<CliMode>,

    /// In-memory override for candidate selection strategy (`priority` or `round-robin`; overrides AGY_SWITCH_CLI_STRATEGY and `policy.json`)
    #[arg(long, value_enum)]
    pub strategy: Option<CliStrategy>,

    /// In-memory override for reserve threshold (`1..=98`; overrides AGY_SWITCH_CLI_RESERVE and `policy.json`)
    #[arg(long)]
    pub reserve: Option<u8>,

    /// In-memory override for candidate minimum threshold (`2..=100`; overrides AGY_SWITCH_CLI_MINIMUM and `policy.json`)
    #[arg(long)]
    pub minimum: Option<u8>,

    /// In-memory override for monitored model/pool (`all`, `gemini`, `claude`, `argon`, or `<MODEL_ID>`; overrides AGY_SWITCH_CLI_MODEL and `policy.json`)
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,

    /// Internal marker set by the CLI parser when `--interval` came solely from `AGY_SWITCH_CLI_INTERVAL`
    #[arg(skip)]
    pub interval_from_env: bool,

    /// Internal marker set by the CLI parser when `--cooldown` came solely from `AGY_SWITCH_CLI_COOLDOWN`
    #[arg(skip)]
    pub cooldown_from_env: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum CliStatsSource {
    #[default]
    All,
    Cli,
    App,
}

pub const MAX_STATS_RANGE_DAYS: u32 = 36_500;
pub const MAX_STATS_RECENT_LIMIT: u32 = 500;
pub const DEFAULT_STATS_LIST_RECENT: usize = 10;
pub const DEFAULT_STATS_WATCH_INTERVAL_SECS: u64 = 2;
pub const MAX_STATS_WATCH_INTERVAL_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliStatsRange {
    Today,
    Yesterday,
    All,
    Days(u32),
}

pub fn parse_cli_stats_range(raw: &str) -> Result<CliStatsRange, String> {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "today" => Ok(CliStatsRange::Today),
        "yesterday" => Ok(CliStatsRange::Yesterday),
        "all" => Ok(CliStatsRange::All),
        _ => {
            if let Some(num_str) = lower.strip_suffix('d') {
                if !num_str.is_empty()
                    && !num_str.starts_with('0')
                    && num_str.bytes().all(|b| b.is_ascii_digit())
                {
                    if let Ok(days) = num_str.parse::<u32>() {
                        if (1..=MAX_STATS_RANGE_DAYS).contains(&days) {
                            return Ok(CliStatsRange::Days(days));
                        }
                    }
                }
            }
            Err(format!(
                "expected `today`, `yesterday`, `all`, or `<N>d` (1 <= N <= {MAX_STATS_RANGE_DAYS})"
            ))
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum StatsCommand {
    /// Aggregate token usage summary, cache hit rate, P10/P50/P90 timings, and per-model breakdown (defaults to `--range today`)
    Summary(StatsWindowArgs),
    /// List individual model call records newest-first (defaults to `--recent 10`)
    List(StatsWindowArgs),
}

#[derive(Debug, Clone, Args)]
pub struct StatsWindowArgs {
    /// Conversation database source (`all` [default], `cli`, or `app`)
    #[arg(
        long,
        value_enum,
        default_value_t = CliStatsSource::All,
        value_name = "SOURCE"
    )]
    pub source: CliStatsSource,

    /// Preset local-date range (`today`, `yesterday`, `all`, or `<N>d` such as `1d`, `3d`, `7d`, `30d`)
    #[arg(
        long,
        value_parser = parse_cli_stats_range,
        value_name = "RANGE",
        conflicts_with_all = ["date", "from", "to", "recent"]
    )]
    pub range: Option<CliStatsRange>,

    /// Exact local calendar date (`YYYY-MM-DD`, `00:00:00..=23:59:59`)
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        conflicts_with_all = ["range", "from", "to", "recent"]
    )]
    pub date: Option<String>,

    /// Start date of closed local-date interval (`YYYY-MM-DD`; defaults `--to` to `today` if omitted)
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        conflicts_with_all = ["range", "date", "recent"]
    )]
    pub from: Option<String>,

    /// End date of closed local-date interval (`YYYY-MM-DD`; requires `--from`)
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        requires = "from",
        conflicts_with_all = ["range", "date", "recent"]
    )]
    pub to: Option<String>,

    /// Select the latest `<N>` call records (`1 <= N <= 500`)
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_STATS_RECENT_LIMIT)),
        conflicts_with_all = ["range", "date", "from", "to"]
    )]
    pub recent: Option<u32>,

    /// Stay open in an interactive terminal and refresh live every `<SECS>` seconds (default: 2, range: 1..=3600; press Tab to toggle summary/list, r to refresh, q/Esc to quit)
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "2",
        value_name = "SECS",
        value_parser = clap::value_parser!(u64).range(1..=MAX_STATS_WATCH_INTERVAL_SECS)
    )]
    pub watch: Option<u64>,
}

pub type StatsArgs = StatsWindowArgs;
