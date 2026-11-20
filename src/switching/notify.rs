use crate::cli::dto::terminal_text;
use crate::error::{CliError, CliResult};
use crate::store::repository::StoreRepository;
use std::time::Duration;

pub const NOTIFY_ENV_VAR: &str = "AGY_SWITCH_CLI_NOTIFY";
pub const DESKTOP_NOTIFY_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_NOTIFY_ACCOUNT_CHARS: usize = 120;
const MAX_NOTIFY_SHORT_FIELD_CHARS: usize = 80;
const MAX_NOTIFY_REASON_CHARS: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonNotificationEvent {
    Switched {
        from_account: String,
        to_account: String,
        source_5h_pct: Option<u8>,
        source_weekly_pct: Option<u8>,
        target_5h_pct: Option<u8>,
        target_weekly_pct: Option<u8>,
        running_agy_detected: bool,
    },
    PausedOnFailure {
        stage: String,
        target_account: Option<String>,
        consecutive_failures: u32,
        max_failures: u32,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationPayload {
    pub summary: String,
    pub body: String,
    pub icon: &'static str,
    pub urgency: u8,
}

/// Parse `raw` as an optional boolean notification toggle without echoing raw values on error.
pub fn parse_notify_override_str(raw: &str) -> CliResult<Option<bool>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(CliError::usage(
            "Invalid AGY_SWITCH_CLI_NOTIFY value (expected `true`/`false` or `1`/`0`).",
        )),
    }
}

/// Read `AGY_SWITCH_CLI_NOTIFY` from the process environment, returning `Err` without echoing raw values if invalid.
pub fn parse_notify_env_override() -> CliResult<Option<bool>> {
    let Some(raw_os) = std::env::var_os(NOTIFY_ENV_VAR) else {
        return Ok(None);
    };
    if raw_os.is_empty() {
        return Ok(None);
    }
    let Some(raw_str) = raw_os.to_str() else {
        return Err(CliError::usage(
            "Invalid AGY_SWITCH_CLI_NOTIFY value (expected `true`/`false` or `1`/`0`).",
        ));
    };
    parse_notify_override_str(raw_str)
}

/// Resolve effective desktop notification enablement:
/// `--no-notify` (`false`) > `AGY_SWITCH_CLI_NOTIFY` > `config.json` `notifications.enabled` > `true`.
pub fn resolve_effective_notify_enabled(
    repo: &StoreRepository,
    cli_no_notify: bool,
    env_override: Option<bool>,
) -> bool {
    if cli_no_notify {
        return false;
    }
    if let Some(enabled) = env_override {
        return enabled;
    }
    repo.read_config()
        .ok()
        .and_then(|cfg| cfg.notifications.enabled)
        .unwrap_or(true)
}

fn clean_and_truncate_chars(raw: &str, max_chars: usize) -> String {
    let cleaned = terminal_text(raw);
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::new();
    for (count, ch) in collapsed.chars().enumerate() {
        if count >= max_chars {
            out.pop();
            out.push('…');
            return out;
        }
        out.push(ch);
    }
    out
}

fn escape_notification_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

fn sanitize_notify_field(raw: &str, max_chars: usize, supports_markup: bool) -> String {
    let clean = clean_and_truncate_chars(raw, max_chars);
    if supports_markup {
        escape_notification_markup(&clean)
    } else {
        clean
    }
}

fn format_window_line(short_5h_pct: Option<u8>, weekly_pct: Option<u8>) -> String {
    let p5 = short_5h_pct
        .map(|v| format!("{v}%"))
        .unwrap_or_else(|| "—".to_string());
    let pw = weekly_pct
        .map(|v| format!("{v}%"))
        .unwrap_or_else(|| "—".to_string());
    format!("5h {p5} · Weekly {pw}")
}

/// Format an English FreeDesktop notification payload.
/// When `supports_markup` is true (verified via `GetCapabilities` containing `"body-markup"`),
/// applies per-line `<b>`/`<i>` hierarchy and XML-escapes dynamic fields; otherwise emits pure plain text.
pub fn format_notification_payload(
    event: &DaemonNotificationEvent,
    supports_markup: bool,
) -> NotificationPayload {
    match event {
        DaemonNotificationEvent::Switched {
            from_account,
            to_account,
            source_5h_pct,
            source_weekly_pct,
            target_5h_pct,
            target_weekly_pct,
            running_agy_detected,
        } => {
            let from_clean =
                sanitize_notify_field(from_account, MAX_NOTIFY_ACCOUNT_CHARS, supports_markup);
            let to_clean =
                sanitize_notify_field(to_account, MAX_NOTIFY_ACCOUNT_CHARS, supports_markup);
            let to_quota = format_window_line(*target_5h_pct, *target_weekly_pct);
            let from_quota = format_window_line(*source_5h_pct, *source_weekly_pct);

            let mut lines = if supports_markup {
                vec![
                    format!("<b>▶ {to_clean}</b>"),
                    format!("<b>{to_quota}</b>"),
                    format!("– {from_clean}"),
                    from_quota,
                ]
            } else {
                vec![
                    format!("▶ {to_clean}"),
                    to_quota,
                    format!("– {from_clean}"),
                    from_quota,
                ]
            };

            if *running_agy_detected {
                lines.push(if supports_markup {
                    "<i>Restart agy to use the new account.</i>".to_string()
                } else {
                    "Restart agy to use the new account.".to_string()
                });
            }

            NotificationPayload {
                summary: "Account Switched".to_string(),
                body: lines.join("\n"),
                icon: "dialog-information",
                urgency: 1,
            }
        }
        DaemonNotificationEvent::PausedOnFailure {
            stage,
            target_account,
            consecutive_failures,
            max_failures,
            reason,
        } => {
            let stage_clean =
                sanitize_notify_field(stage, MAX_NOTIFY_SHORT_FIELD_CHARS, supports_markup);
            let reason_clean =
                sanitize_notify_field(reason, MAX_NOTIFY_REASON_CHARS, supports_markup);
            let target_clean_opt = target_account
                .as_deref()
                .map(|t| sanitize_notify_field(t, MAX_NOTIFY_ACCOUNT_CHARS, supports_markup))
                .filter(|t| !t.is_empty());

            let action_line = if supports_markup {
                "<i>Run agy-switch-cli status to inspect.</i>".to_string()
            } else {
                "Run agy-switch-cli status to inspect.".to_string()
            };

            let mut lines = Vec::with_capacity(4);
            if let Some(target_clean) = target_clean_opt {
                if supports_markup {
                    lines.push(format!("■ <b>{target_clean}</b>"));
                } else {
                    lines.push(format!("■ {target_clean}"));
                }
                lines.push(format!(
                    "{stage_clean} · {consecutive_failures}/{max_failures} failed"
                ));
            } else if supports_markup {
                lines.push(format!(
                    "■ <b>{stage_clean}</b> · {consecutive_failures}/{max_failures} failed"
                ));
            } else {
                lines.push(format!(
                    "■ {stage_clean} · {consecutive_failures}/{max_failures} failed"
                ));
            }
            lines.push(reason_clean);
            lines.push(action_line);

            NotificationPayload {
                summary: "Auto-Switch Paused".to_string(),
                body: lines.join("\n"),
                icon: "dialog-warning",
                urgency: 2,
            }
        }
    }
}

#[cfg(feature = "secret-service-backend")]
fn is_dbus_no_owner_error(err: &zbus::Error) -> bool {
    match err {
        zbus::Error::MethodError(name, _, _) => matches!(
            name.as_str(),
            "org.freedesktop.DBus.Error.ServiceUnknown"
                | "org.freedesktop.DBus.Error.NameHasNoOwner"
        ),
        zbus::Error::FDO(fdo) => matches!(
            fdo.as_ref(),
            zbus::fdo::Error::ServiceUnknown(_) | zbus::fdo::Error::NameHasNoOwner(_)
        ),
        _ => false,
    }
}

#[cfg(feature = "secret-service-backend")]
async fn send_via_freedesktop_dbus(event: &DaemonNotificationEvent) {
    use std::collections::HashMap;
    use zbus::proxy::{Builder as ProxyBuilder, CacheProperties, MethodFlags};
    use zbus::zvariant::Value;

    let Ok(Some(ep)) =
        tokio::task::spawn_blocking(crate::session::backend::discover_verified_dbus_endpoint).await
    else {
        return;
    };

    let conn =
        match crate::session::backend::connect_verified_session_dbus(&ep, DESKTOP_NOTIFY_TIMEOUT)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    "Skipping desktop notification: D-Bus connect failed: {}",
                    e.message
                );
                return;
            }
        };

    // Read-only NameHasOwner avoids D-Bus auto-activation on headless/linger servers without a desktop daemon.
    let owner_reply = match conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "NameHasOwner",
            &("org.freedesktop.Notifications",),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("Desktop notification NameHasOwner failed (non-fatal): {e}");
            return;
        }
    };

    let has_owner: bool = match owner_reply.body().deserialize() {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("Desktop notification NameHasOwner decode failed (non-fatal): {e}");
            return;
        }
    };
    if !has_owner {
        tracing::debug!(
            "Skipping desktop notification: org.freedesktop.Notifications has no active owner."
        );
        return;
    }

    // Build a zero-I/O proxy (CacheProperties::No) so both GetCapabilities and Notify set
    // `NO_AUTO_START`, preventing activation even if the owner disappears right after NameHasOwner.
    let proxy = match ProxyBuilder::<zbus::Proxy<'_>>::new(&conn)
        .destination("org.freedesktop.Notifications")
        .and_then(|b| b.path("/org/freedesktop/Notifications"))
        .and_then(|b| b.interface("org.freedesktop.Notifications"))
    {
        Ok(builder) => match builder.cache_properties(CacheProperties::No).build().await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("Desktop notification proxy init failed (non-fatal): {e}");
                return;
            }
        },
        Err(e) => {
            tracing::debug!("Desktop notification proxy config failed (non-fatal): {e}");
            return;
        }
    };
    let no_auto_start = MethodFlags::NoAutoStart.into();

    // Read-only GetCapabilities determines whether `<b>`/`<i>` body markup is safe to emit.
    let supports_markup = match proxy
        .call_with_flags::<_, _, Vec<String>>("GetCapabilities", no_auto_start, &())
        .await
    {
        Ok(Some(caps)) => caps.iter().any(|c| c == "body-markup"),
        Ok(None) => false,
        Err(e) if is_dbus_no_owner_error(&e) => {
            tracing::debug!(
                "Skipping desktop notification: org.freedesktop.Notifications owner vanished before GetCapabilities."
            );
            return;
        }
        Err(e) => {
            tracing::debug!(
                "Desktop notification GetCapabilities failed (falling back to plain text): {e}"
            );
            false
        }
    };

    let payload = format_notification_payload(event, supports_markup);
    let actions: Vec<&str> = Vec::new();
    let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
    hints.insert("urgency", Value::U8(payload.urgency));

    if let Err(e) = proxy
        .call_with_flags::<_, _, u32>(
            "Notify",
            no_auto_start,
            &(
                "agy-switch-cli",
                0u32,
                payload.icon,
                payload.summary.as_str(),
                payload.body.as_str(),
                actions,
                hints,
                -1i32,
            ),
        )
        .await
    {
        if is_dbus_no_owner_error(&e) {
            tracing::debug!(
                "Skipping desktop notification: org.freedesktop.Notifications owner vanished before Notify."
            );
        } else {
            tracing::warn!("Desktop notification delivery failed (non-fatal): {e}");
        }
    }
}

/// Best-effort desktop notification dispatch bounded by `DESKTOP_NOTIFY_TIMEOUT` and `shutdown_rx`.
/// Never fails, never blocks shutdown, and skips silently when no desktop notification owner exists.
pub async fn send_daemon_notification_best_effort(
    event: &DaemonNotificationEvent,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    if *shutdown_rx.borrow() {
        return;
    }

    #[cfg(feature = "secret-service-backend")]
    {
        tokio::select! {
            _ = shutdown_rx.changed() => {}
            _ = tokio::time::timeout(DESKTOP_NOTIFY_TIMEOUT, send_via_freedesktop_dbus(event)) => {}
        }
    }

    #[cfg(not(feature = "secret-service-backend"))]
    {
        let _ = (event, shutdown_rx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::config::{HeadlessConfig, NotificationsConfig};
    use crate::paths::HeadlessPaths;
    use std::fs;

    #[test]
    fn parse_notify_override_accepts_booleans_and_redacts_invalid_values() {
        assert_eq!(parse_notify_override_str("").unwrap(), None);
        assert_eq!(parse_notify_override_str("   ").unwrap(), None);
        for truthy in ["1", "true", "TRUE", "yes", "On"] {
            assert_eq!(parse_notify_override_str(truthy).unwrap(), Some(true));
        }
        for falsy in ["0", "false", "FALSE", "no", "Off"] {
            assert_eq!(parse_notify_override_str(falsy).unwrap(), Some(false));
        }
        let err = parse_notify_override_str("SECRET_BAD_NOTIFY_VAL_999").unwrap_err();
        assert!(!err.message.contains("SECRET_BAD_NOTIFY_VAL_999"));
        assert!(err.message.contains("AGY_SWITCH_CLI_NOTIFY"));
    }

    #[test]
    fn resolve_effective_notify_enabled_honors_cli_env_config_precedence() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data = tmp.path().join("data");
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&data).unwrap();
        let paths = HeadlessPaths::with_explicit(home, data, cache);
        let repo = StoreRepository::new(paths.clone());

        assert!(resolve_effective_notify_enabled(&repo, false, None));
        assert!(!resolve_effective_notify_enabled(&repo, false, Some(false)));

        let cfg = HeadlessConfig {
            notifications: NotificationsConfig {
                enabled: Some(false),
            },
            ..HeadlessConfig::default()
        };
        fs::write(paths.config_file(), serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert!(!resolve_effective_notify_enabled(&repo, false, None));
        assert!(resolve_effective_notify_enabled(&repo, false, Some(true)));
        assert!(!resolve_effective_notify_enabled(&repo, true, Some(true)));
    }

    #[test]
    fn format_notification_payload_supports_markup_and_plain_fallback_with_dual_windows() {
        let switched_idle_event = DaemonNotificationEvent::Switched {
            from_account: "alice+1@example.com\n\x1b[31m".into(),
            to_account: "bob&<tag>@example.com".into(),
            source_5h_pct: Some(2),
            source_weekly_pct: Some(40),
            target_5h_pct: Some(100),
            target_weekly_pct: Some(85),
            running_agy_detected: false,
        };

        let markup_idle = format_notification_payload(&switched_idle_event, true);
        assert_eq!(markup_idle.summary, "Account Switched");
        assert_eq!(markup_idle.icon, "dialog-information");
        assert_eq!(markup_idle.urgency, 1);
        assert_eq!(
            markup_idle.body,
            "<b>▶ bob&amp;&lt;tag&gt;@example.com</b>\n\
             <b>5h 100% · Weekly 85%</b>\n\
             – alice+1@example.com [31m\n\
             5h 2% · Weekly 40%"
        );
        assert!(!markup_idle.body.contains('\x1b'));

        let plain_idle = format_notification_payload(&switched_idle_event, false);
        assert_eq!(
            plain_idle.body,
            "▶ bob&<tag>@example.com\n\
             5h 100% · Weekly 85%\n\
             – alice+1@example.com [31m\n\
             5h 2% · Weekly 40%"
        );
        assert!(!plain_idle.body.contains("<b>"));
        assert!(!plain_idle.body.contains("&amp;"));

        let switched_running_event = DaemonNotificationEvent::Switched {
            from_account: "alice@example.com".into(),
            to_account: "bob@example.com".into(),
            source_5h_pct: None,
            source_weekly_pct: Some(10),
            target_5h_pct: None,
            target_weekly_pct: None,
            running_agy_detected: true,
        };
        assert_eq!(
            format_notification_payload(&switched_running_event, true).body,
            "<b>▶ bob@example.com</b>\n\
             <b>5h — · Weekly —</b>\n\
             – alice@example.com\n\
             5h — · Weekly 10%\n\
             <i>Restart agy to use the new account.</i>"
        );
        assert_eq!(
            format_notification_payload(&switched_running_event, false).body,
            "▶ bob@example.com\n\
             5h — · Weekly —\n\
             – alice@example.com\n\
             5h — · Weekly 10%\n\
             Restart agy to use the new account."
        );

        let long_reason = "R".repeat(200) + "<script>";
        let paused_with_target_event = DaemonNotificationEvent::PausedOnFailure {
            stage: "Switch commit".into(),
            target_account: Some("bob@example.com (Work)".into()),
            consecutive_failures: 3,
            max_failures: 3,
            reason: long_reason,
        };
        let paused_markup = format_notification_payload(&paused_with_target_event, true);
        assert_eq!(paused_markup.summary, "Auto-Switch Paused");
        assert_eq!(paused_markup.icon, "dialog-warning");
        assert_eq!(paused_markup.urgency, 2);
        let paused_lines: Vec<&str> = paused_markup.body.lines().collect();
        assert_eq!(paused_lines.len(), 4);
        assert_eq!(paused_lines[0], "■ <b>bob@example.com (Work)</b>");
        assert_eq!(paused_lines[1], "Switch commit · 3/3 failed");
        assert!(paused_lines[2].ends_with('…'));
        assert_eq!(paused_lines[2].chars().count(), MAX_NOTIFY_REASON_CHARS);
        assert!(!paused_lines[2].contains("<script>"));
        assert_eq!(
            paused_lines[3],
            "<i>Run agy-switch-cli status to inspect.</i>"
        );

        let paused_plain = format_notification_payload(&paused_with_target_event, false);
        assert!(paused_plain.body.starts_with("■ bob@example.com (Work)\n"));
        assert!(paused_plain
            .body
            .ends_with("\nRun agy-switch-cli status to inspect."));
        assert!(!paused_plain.body.contains("<b>"));
        assert!(!paused_plain.body.contains("<i>"));

        let paused_no_target_event = DaemonNotificationEvent::PausedOnFailure {
            stage: "Journal check".into(),
            target_account: None,
            consecutive_failures: 1,
            max_failures: 3,
            reason: "Corrupt switch journal <raw>".into(),
        };
        assert_eq!(
            format_notification_payload(&paused_no_target_event, true).body,
            "■ <b>Journal check</b> · 1/3 failed\n\
             Corrupt switch journal &lt;raw&gt;\n\
             <i>Run agy-switch-cli status to inspect.</i>"
        );
        assert_eq!(
            format_notification_payload(&paused_no_target_event, false).body,
            "■ Journal check · 1/3 failed\n\
             Corrupt switch journal <raw>\n\
             Run agy-switch-cli status to inspect."
        );
    }
}
