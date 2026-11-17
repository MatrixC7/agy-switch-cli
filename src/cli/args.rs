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

    /// Explicit proxy URL (http://, https://, socks5://, socks5h://, or `direct`)
    #[arg(long, global = true, value_name = "URL")]
    pub proxy: Option<String>,

    /// Credential backend (`file` [default] or `secret-service` [requires `secret-service-backend` feature])
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
    /// Environment diagnostics and journal reconciliation
    Doctor(DoctorArgs),

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

    /// Pre-invocation managed wrapper (`agy-switch-cli run -- agy ...`)
    Run(RunArgs),

    /// View pool quota table (pure local read by default; pass `-r/--refresh` to fetch live quota first)
    Quota(QuotaArgs),

    /// Refresh OAuth tokens and CloudCode quotas over the network
    Refresh(RefreshArgs),

    /// Auto-switch policy configuration and dry-run evaluation
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Foreground 7-stage auto-switch daemon (managed by systemd --user or container init)
    Daemon(DaemonArgs),

    /// Optional interactive SSH terminal dashboard
    Tui,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Probe installed `agy --version` in an isolated temporary HOME
    #[arg(long)]
    pub verify_agy: bool,

    /// Reconcile pending `switch_journal.json`, repair permissions, and clear daemon failure pause
    #[arg(long)]
    pub fix: bool,
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

    /// Compatibility alias (manual URL paste mode is now the default when `--ssh` is omitted)
    #[arg(long, hide = true, conflicts_with = "ssh")]
    pub manual: bool,

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

    /// Compatibility alias (manual URL paste mode is now the default when `--ssh` is omitted)
    #[arg(long, hide = true, conflicts_with = "ssh")]
    pub manual: bool,

    #[arg(long)]
    pub open_browser: bool,
}

#[derive(Debug, Subcommand)]
pub enum AccountsCommand {
    /// List saved accounts with plan/status details, or reorder accounts (`--move` / `--order`)
    List(AccountsListArgs),
    /// Add one or more accounts via masked TTY prompt, `--stdin`, or `0600` `--token-file` (no positional token!)
    Add(AccountsAddArgs),
    /// Import accounts from a v1/v2 JSON bundle or `--from-legacy` desktop directory
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
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
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
    /// Read one or more refresh tokens (one per line) from standard input pipe
    #[arg(long, conflicts_with = "token_file")]
    pub stdin: bool,

    /// Read one or more refresh tokens (one per line; `# label` comments supported) from a `0600` regular file
    #[arg(long, value_name = "PATH", conflicts_with = "stdin")]
    pub token_file: Option<PathBuf>,

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
    #[arg(value_name = "FILE", conflicts_with = "from_legacy")]
    pub file: Option<PathBuf>,

    /// Read-only migration from legacy desktop directory (defaults to `~/.antigravity_tools` if flag given without path)
    #[arg(long, value_name = "LEGACY_DIR", num_args = 0..=1, default_missing_value = "")]
    pub from_legacy: Option<String>,

    /// Explicitly update existing accounts' tokens (still refuses to roll back known rotated refresh tokens)
    #[arg(long, alias = "force")]
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
    pub ids: Vec<String>,

    /// Overwrite `--output` if it already exists
    #[arg(long)]
    pub force: bool,
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

    /// Allow updating credential file even when running `agy` processes are detected
    #[arg(long)]
    pub allow_running: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Explicitly switch to this account before launching `agy`
    #[arg(long, value_name = "ID|EMAIL")]
    pub account: Option<String>,

    /// Sanitize `DBUS_SESSION_BUS_ADDRESS` for the spawned `agy` child so desktop keyrings cannot shadow file credentials
    #[arg(long)]
    pub isolate_dbus: bool,

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
    #[arg(short = 'r', long)]
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
    #[value(name = "round-robin", alias = "round_robin")]
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
    /// Poll interval in seconds (default: 3600 / 1 hour)
    #[arg(
        long,
        env = "AGY_SWITCH_CLI_INTERVAL",
        hide_env_values = true,
        default_value_t = 3600
    )]
    pub interval: u64,

    /// Post-switch cooldown in seconds (default: 3600 / 1 hour)
    #[arg(
        long,
        env = "AGY_SWITCH_CLI_COOLDOWN",
        hide_env_values = true,
        default_value_t = 3600
    )]
    pub cooldown: i64,

    /// Run a single 7-stage evaluation/commit tick and exit
    #[arg(long)]
    pub once: bool,

    /// In-memory override for active-process guard mode (`immediate` or `wait`; does not modify `policy.json`)
    #[arg(long, value_enum)]
    pub mode: Option<CliMode>,

    /// In-memory override for candidate selection strategy (`priority` or `round-robin`; does not modify `policy.json`)
    #[arg(long, value_enum)]
    pub strategy: Option<CliStrategy>,

    /// In-memory override for reserve threshold (`1..=98`; does not modify `policy.json`)
    #[arg(long)]
    pub reserve: Option<u8>,

    /// In-memory override for candidate minimum threshold (`2..=100`; does not modify `policy.json`)
    #[arg(long)]
    pub minimum: Option<u8>,

    /// In-memory override for monitored model/pool (`all`, `gemini`, `claude`, `argon`, or `<MODEL_ID>`)
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,
}
