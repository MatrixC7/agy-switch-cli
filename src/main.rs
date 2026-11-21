use agy_switch_cli::cli::args::{Cli, Commands};
use agy_switch_cli::cli::commands::dispatch;
use agy_switch_cli::error::{format_safe_clap_error, CliError, ExitCode};
use clap::{error::ErrorKind, parser::ValueSource, CommandFactory, FromArgMatches};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};

static PANIC_JSON_MODE: AtomicBool = AtomicBool::new(false);

fn install_secret_safe_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        // Never print dynamic panic payload strings — only static code location!
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let err = CliError::new(
            ExitCode::GeneralOrDataError,
            "internal_panic",
            format!("Internal invariant failure at {loc} (payload redacted)."),
        );
        if PANIC_JSON_MODE.load(Ordering::SeqCst) {
            eprintln!("{}", err.to_json_line());
        } else {
            eprintln!("error: {}", err.message);
        }
    }));
}

#[tokio::main]
async fn main() {
    let raw_os_args: Vec<OsString> = std::env::args_os().collect();
    let json_flag_present = raw_os_args
        .iter()
        .skip(1)
        .take_while(|a| a.as_os_str() != "--")
        .any(|a| a.as_os_str() == "--json");

    PANIC_JSON_MODE.store(json_flag_present, Ordering::SeqCst);
    install_secret_safe_panic_hook();

    // Reject non-UTF-8 arguments BEFORE `clap` or `String` formatting without echoing raw bytes!
    let mut raw_args: Vec<String> = Vec::with_capacity(raw_os_args.len());
    for (idx, os_arg) in raw_os_args.into_iter().enumerate() {
        match os_arg.into_string() {
            Ok(s) => raw_args.push(s),
            Err(_) => {
                if idx == 0 {
                    raw_args.push("agy-switch-cli".to_string());
                } else {
                    let err = CliError::usage(
                        "Command-line arguments must be valid UTF-8 (non-UTF-8 byte sequence rejected without echo).",
                    );
                    if json_flag_present {
                        eprintln!("{}", err.to_json_line());
                    } else {
                        eprintln!("error: {}", err.message);
                    }
                    std::process::exit(ExitCode::InvalidUsageOrAmbiguous.as_i32());
                }
            }
        }
    }

    // Initialize optional stderr tracing ONLY when RUST_LOG is explicitly set and `--json` is NOT requested,
    // ensuring read-only commands NEVER create log files and `--json` stderr remains valid single-line JSON!
    if !json_flag_present && std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    }

    let mut cmd = Cli::command();
    let cli = match cmd.try_get_matches_from_mut(&raw_args) {
        Ok(matches) => {
            let mut parsed = match Cli::from_arg_matches(&matches) {
                Ok(p) => p,
                Err(clap_err) => {
                    let safe_msg = format_safe_clap_error(&cmd, &raw_args, &clap_err);
                    if json_flag_present {
                        let structured = CliError::usage(safe_msg);
                        eprintln!("{}", structured.to_json_line());
                    } else {
                        eprintln!("error: {}", safe_msg.trim());
                    }
                    std::process::exit(ExitCode::InvalidUsageOrAmbiguous.as_i32());
                }
            };
            if let Commands::Daemon(ref mut daemon_args) = parsed.command {
                if let Some(sub) = matches.subcommand_matches("daemon") {
                    daemon_args.interval_from_env =
                        sub.value_source("interval") == Some(ValueSource::EnvVariable);
                    daemon_args.cooldown_from_env =
                        sub.value_source("cooldown") == Some(ValueSource::EnvVariable);
                }
            }
            parsed
        }
        Err(clap_err) => match clap_err.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                let _ = clap_err.print();
                std::process::exit(ExitCode::Ok.as_i32());
            }
            _ => {
                let safe_msg = format_safe_clap_error(&cmd, &raw_args, &clap_err);
                if json_flag_present {
                    let structured = CliError::usage(safe_msg);
                    eprintln!("{}", structured.to_json_line());
                } else {
                    eprintln!("error: {}", safe_msg.trim());
                }
                std::process::exit(ExitCode::InvalidUsageOrAmbiguous.as_i32());
            }
        },
    };

    let use_json = cli.json;
    PANIC_JSON_MODE.store(use_json, Ordering::SeqCst);
    match dispatch(cli).await {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(err) => {
            if use_json {
                eprintln!("{}", err.to_json_line());
            } else {
                eprintln!("error: {}", err.message);
            }
            std::process::exit(err.exit_code.as_i32());
        }
    }
}
