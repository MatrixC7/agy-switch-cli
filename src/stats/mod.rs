mod readonly_vfs;
pub mod watch;

use crate::cli::args::{
    CliStatsRange, CliStatsSource, StatsArgs, DEFAULT_STATS_LIST_RECENT, MAX_STATS_RECENT_LIMIT,
};
use crate::cli::dto::terminal_text;
use crate::domain::clock::parse_strict_ymd_date;
use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::stats::readonly_vfs::{
    is_transient_sqlite_err, open_pinned_readonly_sqlite, PinnedSqliteConnection, PinnedSqliteOpen,
};
use crate::store::fs_atomic::{
    is_single_normal_filename, open_child_dir_nofollow, open_existing_dir_nofollow, ChildDirOpen,
};
use rusqlite::Connection;
use serde::Serialize;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::ffi::{CStr, OsStr, OsString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

const GEMINI_DIR: &str = ".gemini";
const CLI_DIR_NAME: &str = "antigravity-cli";
const APP_DIR_NAME: &str = "antigravity";
const CONVERSATIONS_DIR: &str = "conversations";
const TOKEN_ARCHIVE_FILE: &str = "token_usage_archive.db";
const MAX_GENERATION_BLOB_BYTES: i64 = 64 * 1024 * 1024;
const GENERATION_STEP_TYPE: i64 = 15;
const MAX_MODEL_NAME_BYTES: usize = 128;
const MAX_PROTOBUF_FIELD_NUMBER: u64 = (1 << 29) - 1;
const MIN_HUMAN_MODEL_COL_WIDTH: usize = 32;
const MAX_HUMAN_MODEL_COL_WIDTH: usize = 48;
const WIDE_TERM_MIN_COLS: usize = 90;
const WIDE_LIST_MIN_COLS: usize = 95;
const MIN_PERF_STREAMING_SECONDS: f64 = 1.0;
const TRANSIENT_DB_RETRY_LIMIT: usize = 24;
/// Explicit row-count budget for abnormal/unindexed SQLite tables (`steps`, `gen_metadata`, or
/// `archived_generations` lacking a primary key / index) to prevent unbounded memory growth.
const MAX_UNINDEXED_TABLE_ROWS: usize = 50_000;

#[cfg(test)]
thread_local! {
    static TEST_UNINDEXED_ROW_BUDGET_OVERRIDE: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

fn effective_unindexed_row_budget() -> usize {
    #[cfg(test)]
    {
        let ov = TEST_UNINDEXED_ROW_BUDGET_OVERRIDE.with(std::cell::Cell::get);
        if ov > 0 {
            return ov;
        }
    }
    MAX_UNINDEXED_TABLE_ROWS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StatsSource {
    Cli,
    App,
    All,
}

impl From<CliStatsSource> for StatsSource {
    fn from(value: CliStatsSource) -> Self {
        match value {
            CliStatsSource::Cli => Self::Cli,
            CliStatsSource::App => Self::App,
            CliStatsSource::All => Self::All,
        }
    }
}

impl StatsSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::App => "app",
            Self::All => "all",
        }
    }

    pub fn human_header_label(self) -> &'static str {
        match self {
            Self::Cli => "cli (~/.gemini/antigravity-cli)",
            Self::App => "app (~/.gemini/antigravity)",
            Self::All => "all (~/.gemini/antigravity-cli + ~/.gemini/antigravity)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsPresetRange {
    Today,
    Yesterday,
    All,
    Days(u32),
}

impl Serialize for StatsPresetRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.label())
    }
}

impl From<CliStatsRange> for StatsPresetRange {
    fn from(value: CliStatsRange) -> Self {
        match value {
            CliStatsRange::Today => Self::Today,
            CliStatsRange::Yesterday => Self::Yesterday,
            CliStatsRange::All => Self::All,
            CliStatsRange::Days(n) => Self::Days(n),
        }
    }
}

impl StatsPresetRange {
    pub fn label(self) -> Cow<'static, str> {
        match self {
            Self::Today => Cow::Borrowed("today"),
            Self::Yesterday => Cow::Borrowed("yesterday"),
            Self::All => Cow::Borrowed("all"),
            Self::Days(n) => Cow::Owned(format!("{n}d")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsRangeSpec {
    AllTime,
    Recent {
        limit: usize,
    },
    Preset {
        preset: StatsPresetRange,
        from: jiff::civil::Date,
        to: jiff::civil::Date,
    },
    SingleDate {
        date: jiff::civil::Date,
    },
    CustomInterval {
        from: jiff::civil::Date,
        to: jiff::civil::Date,
    },
}

impl StatsRangeSpec {
    pub fn start_date(&self) -> Option<jiff::civil::Date> {
        match self {
            Self::AllTime | Self::Recent { .. } => None,
            Self::Preset { from, .. } | Self::CustomInterval { from, .. } => Some(*from),
            Self::SingleDate { date } => Some(*date),
        }
    }

    pub fn end_date(&self) -> Option<jiff::civil::Date> {
        match self {
            Self::AllTime | Self::Recent { .. } => None,
            Self::Preset { to, .. } | Self::CustomInterval { to, .. } => Some(*to),
            Self::SingleDate { date } => Some(*date),
        }
    }

    pub fn contains_date(&self, date: jiff::civil::Date) -> bool {
        match self {
            Self::AllTime | Self::Recent { .. } => true,
            Self::Preset { from, to, .. } | Self::CustomInterval { from, to } => {
                date >= *from && date <= *to
            }
            Self::SingleDate { date: target } => date == *target,
        }
    }

    pub fn human_label(&self) -> String {
        self.human_label_with_observed(None)
    }

    pub fn human_label_with_observed(
        &self,
        observed_bounds: Option<(jiff::civil::Date, jiff::civil::Date)>,
    ) -> String {
        match self {
            Self::AllTime => match observed_bounds {
                None => "all".to_string(),
                Some((from, to)) if from == to => format!("all ({from})"),
                Some((from, to)) => format!("all ({from} .. {to})"),
            },
            Self::Recent { limit } => match observed_bounds {
                None => format!("recent {limit}"),
                Some((from, to)) if from == to => format!("recent {limit} ({from})"),
                Some((from, to)) => format!("recent {limit} ({from} .. {to})"),
            },
            Self::Preset { preset, from, to } => {
                if from == to {
                    format!("{} ({from})", preset.label())
                } else {
                    format!("{} ({from} .. {to})", preset.label())
                }
            }
            Self::SingleDate { date } => date.to_string(),
            Self::CustomInterval { from, to } => format!("{from} .. {to}"),
        }
    }

    pub fn human_label_with_observed_activity(
        &self,
        observed_bounds: Option<(jiff::civil::Date, jiff::civil::Date)>,
        observed_timestamps: Option<(i64, i64)>,
        tz: &jiff::tz::TimeZone,
    ) -> String {
        if let Self::Recent { limit } = self {
            if let Some((first_sec, last_sec)) = observed_timestamps {
                if let (Ok(t1), Ok(t2)) = (
                    jiff::Timestamp::from_second(first_sec),
                    jiff::Timestamp::from_second(last_sec),
                ) {
                    let s1 = t1
                        .to_zoned(tz.clone())
                        .strftime("%Y-%m-%d %H:%M")
                        .to_string();
                    let s2 = t2
                        .to_zoned(tz.clone())
                        .strftime("%Y-%m-%d %H:%M")
                        .to_string();
                    return if s1 == s2 {
                        format!("recent {limit} ({s1})")
                    } else {
                        format!("recent {limit} ({s1} .. {s2})")
                    };
                }
            }
            return format!("recent {limit}");
        }
        self.human_label_with_observed(observed_bounds)
    }

    pub fn to_dto(&self) -> StatsRangeDto {
        self.to_dto_with_observed(None)
    }

    pub fn to_dto_with_observed(
        &self,
        observed_bounds: Option<(jiff::civil::Date, jiff::civil::Date)>,
    ) -> StatsRangeDto {
        match self {
            Self::AllTime => StatsRangeDto {
                kind: "preset",
                preset: Some(StatsPresetRange::All),
                recent: None,
                from: observed_bounds.map(|(f, _)| f.to_string()),
                to: observed_bounds.map(|(_, t)| t.to_string()),
            },
            Self::Recent { limit } => StatsRangeDto {
                kind: "recent",
                preset: None,
                recent: Some(*limit),
                from: observed_bounds.map(|(f, _)| f.to_string()),
                to: observed_bounds.map(|(_, t)| t.to_string()),
            },
            Self::Preset { preset, from, to } => StatsRangeDto {
                kind: "preset",
                preset: Some(*preset),
                recent: None,
                from: Some(from.to_string()),
                to: Some(to.to_string()),
            },
            Self::SingleDate { date } => StatsRangeDto {
                kind: "date",
                preset: None,
                recent: None,
                from: Some(date.to_string()),
                to: Some(date.to_string()),
            },
            Self::CustomInterval { from, to } => StatsRangeDto {
                kind: "custom",
                preset: None,
                recent: None,
                from: Some(from.to_string()),
                to: Some(date_str(*to)),
            },
        }
    }
}

fn date_str(d: jiff::civil::Date) -> String {
    d.to_string()
}

pub fn resolve_stats_range_spec(
    args: &StatsArgs,
    today: jiff::civil::Date,
) -> CliResult<StatsRangeSpec> {
    if let Some(n) = args.recent {
        if !(1..=MAX_STATS_RECENT_LIMIT).contains(&n) {
            return Err(CliError::usage(format!(
                "Invalid value for `--recent`: expected integer 1..={MAX_STATS_RECENT_LIMIT}."
            )));
        }
        return Ok(StatsRangeSpec::Recent { limit: n as usize });
    }

    if let Some(ref raw_date) = args.date {
        let date = parse_strict_ymd_date(raw_date).ok_or_else(|| {
            CliError::usage(
                "Invalid value for `--date`: expected strict `YYYY-MM-DD` calendar date.",
            )
        })?;
        return Ok(StatsRangeSpec::SingleDate { date });
    }

    if let Some(ref raw_from) = args.from {
        let from = parse_strict_ymd_date(raw_from).ok_or_else(|| {
            CliError::usage(
                "Invalid value for `--from`: expected strict `YYYY-MM-DD` calendar date.",
            )
        })?;
        let to = match args.to {
            Some(ref raw_to) => parse_strict_ymd_date(raw_to).ok_or_else(|| {
                CliError::usage(
                    "Invalid value for `--to`: expected strict `YYYY-MM-DD` calendar date.",
                )
            })?,
            None => today,
        };
        if from > to {
            return Err(CliError::usage(format!(
                "Invalid date range: `--from` ({from}) must not be after `--to` ({to})."
            )));
        }
        return Ok(StatsRangeSpec::CustomInterval { from, to });
    }

    let preset = args
        .range
        .map(StatsPresetRange::from)
        .unwrap_or(StatsPresetRange::Today);
    if preset == StatsPresetRange::All {
        return Ok(StatsRangeSpec::AllTime);
    }
    let sub_days = |d: jiff::civil::Date, days: i64| -> CliResult<jiff::civil::Date> {
        d.checked_sub(jiff::Span::new().days(days))
            .map_err(|_| CliError::usage("Resolved date range underflowed calendar bounds."))
    };
    let (from, to) = match preset {
        StatsPresetRange::Today => (today, today),
        StatsPresetRange::Yesterday => {
            let y = sub_days(today, 1)?;
            (y, y)
        }
        StatsPresetRange::All => unreachable!(),
        StatsPresetRange::Days(n) => {
            if !(1..=crate::cli::args::MAX_STATS_RANGE_DAYS).contains(&n) {
                return Err(CliError::usage(format!(
                    "Invalid value for `--range`: expected `today`, `yesterday`, `all`, or `<N>d` (1 <= N <= {}).",
                    crate::cli::args::MAX_STATS_RANGE_DAYS
                )));
            }
            let span_back = i64::from(n - 1);
            (sub_days(today, span_back)?, today)
        }
    };
    Ok(StatsRangeSpec::Preset { preset, from, to })
}

pub fn resolve_stats_list_range_spec(
    args: &StatsArgs,
    today: jiff::civil::Date,
) -> CliResult<StatsRangeSpec> {
    if args.recent.is_none()
        && args.range.is_none()
        && args.date.is_none()
        && args.from.is_none()
        && args.to.is_none()
    {
        return Ok(StatsRangeSpec::Recent {
            limit: DEFAULT_STATS_LIST_RECENT,
        });
    }
    resolve_stats_range_spec(args, today)
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsRangeDto {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<StatsPresetRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent: Option<usize>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StatsSummaryDto {
    pub total_input_tokens: u64,
    pub uncached_input_tokens: u64,
    pub cached_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub cache_hit_ratio: Option<f64>,
    pub request_count: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct StatsQuantilesDto {
    pub p10: f64,
    pub p50: f64,
    pub p90: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsPerformanceDto {
    pub sample_count: u64,
    pub model_count: u64,
    pub source_count: u64,
    pub ttft_seconds: StatsQuantilesDto,
    pub output_tps: StatsQuantilesDto,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsModelDto {
    pub model: String,
    pub request_count: u64,
    pub total_input_tokens: u64,
    pub uncached_input_tokens: u64,
    pub cached_input_tokens: u64,
    pub cache_hit_ratio: Option<f64>,
    pub cache_hit_percent: Option<f64>,
    pub output_tokens: u64,
    pub total_tokens: u64,
    #[serde(skip)]
    hit_tenths: Option<u16>,
}

/// Structurally allow-listed DTO for `agy-switch-cli stats [--json]`.
/// Excludes local filesystem paths, account emails, and conversation message payloads;
/// `models[].model` is additionally validated and normalized (falling back to `"Unknown"`
/// if a database record contains untrusted path, email, URL, or credential-like text).
#[derive(Debug, Clone, Serialize)]
pub struct StatsViewDto {
    pub source: StatsSource,
    pub range: StatsRangeDto,
    pub databases_scanned: u64,
    pub generations_scanned: u64,
    pub skipped_large_records: u64,
    pub unreadable_databases: u64,
    pub last_activity: Option<i64>,
    pub range_last_activity: Option<i64>,
    pub generated_at: i64,
    pub summary: StatsSummaryDto,
    pub performance: Option<StatsPerformanceDto>,
    pub models: Vec<StatsModelDto>,
    #[serde(skip)]
    range_human: String,
    #[serde(skip)]
    tz: jiff::tz::TimeZone,
}

fn detect_stdout_terminal_cols() -> Option<usize> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return None;
    }
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            Some(usize::from(ws.ws_col))
        } else {
            None
        }
    }
}

impl StatsViewDto {
    pub fn render_human(&self) -> String {
        self.render_human_for_width(detect_stdout_terminal_cols())
    }

    pub fn render_human_for_width(&self, max_cols: Option<usize>) -> String {
        let latest_str = self
            .last_activity
            .and_then(|sec| jiff::Timestamp::from_second(sec).ok())
            .map(|ts| {
                ts.to_zoned(self.tz.clone())
                    .strftime("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_else(|| "—".to_string());

        let db_count_str = format_u64_commas(self.databases_scanned);
        let full_source_line = format!(
            "Source : {} · {} db(s) · latest {}",
            self.source.human_header_label(),
            db_count_str,
            latest_str
        );
        let source_line = if max_cols
            .is_some_and(|cols| UnicodeWidthStr::width(full_source_line.as_str()) > cols)
        {
            format!(
                "Source : {} · {} db(s) · latest {}",
                self.source.as_str(),
                db_count_str,
                latest_str
            )
        } else {
            full_source_line
        };

        let mut lines = Vec::new();
        lines.push(source_line);
        lines.push(format!("Range  : {}", self.range_human));
        lines.push(String::new());
        lines.push("Summary".to_string());

        let left_total_in = format_compact_tokens(self.summary.total_input_tokens);
        let right_total_out = format_compact_tokens(self.summary.total_output_tokens);
        let left_cached_in = format_compact_tokens(self.summary.cached_input_tokens);
        let right_uncached_in = format_compact_tokens(self.summary.uncached_input_tokens);
        let left_cache_hit = format_hit_tenths(compute_capped_hit_tenths(
            self.summary.uncached_input_tokens,
            self.summary.cached_input_tokens,
        ));
        let right_requests = format_u64_commas(self.summary.request_count);
        let (left_ttft, right_tps) = match self.performance.as_ref() {
            Some(perf) => (
                format!(
                    "{:.1} / {:.1} / {:.1} s",
                    perf.ttft_seconds.p10, perf.ttft_seconds.p50, perf.ttft_seconds.p90
                ),
                format!(
                    "{:.1} / {:.1} / {:.1} t/s",
                    perf.output_tps.p10, perf.output_tps.p50, perf.output_tps.p90
                ),
            ),
            None => ("—".to_string(), "—".to_string()),
        };

        let max_left_val = [&left_total_in, &left_cached_in, &left_cache_hit, &left_ttft]
            .iter()
            .map(|s| UnicodeWidthStr::width(s.as_str()))
            .max()
            .unwrap_or(0)
            .max(20);
        let left_col_w = max_left_val + 3;

        let summary_pairs = [
            (
                "Total input",
                left_total_in,
                "Total output",
                right_total_out,
            ),
            (
                "Input (cached)",
                left_cached_in,
                "Input (uncached)",
                right_uncached_in,
            ),
            ("Cache hit", left_cache_hit, "Requests", right_requests),
            (
                "TTFT (P10/P50/P90)",
                left_ttft,
                "TPS (P10/P50/P90)",
                right_tps,
            ),
        ];

        let dual_summary_lines: Vec<String> = summary_pairs
            .iter()
            .map(|(ll, lv, rl, rv)| {
                let pad =
                    " ".repeat(left_col_w.saturating_sub(UnicodeWidthStr::width(lv.as_str())));
                format!("  {ll:<18} : {lv}{pad}{rl:<17} : {rv}")
            })
            .collect();

        let use_single_col_summary = match max_cols {
            None => false,
            Some(cols) => {
                cols < WIDE_TERM_MIN_COLS
                    || dual_summary_lines
                        .iter()
                        .any(|line| UnicodeWidthStr::width(line.as_str()) > cols)
            }
        };

        if use_single_col_summary {
            for (ll, lv, rl, rv) in summary_pairs {
                lines.push(format!("  {ll:<18} : {lv}"));
                lines.push(format!("  {rl:<18} : {rv}"));
            }
        } else {
            lines.extend(dual_summary_lines);
        }

        lines.push(String::new());
        lines.push("Models (sorted by total tokens)".to_string());

        if self.models.is_empty() {
            lines.push("  (no token usage recorded in selected range)".to_string());
        } else {
            struct RawModelRow {
                clean_name: String,
                reqs_comma: String,
                in_comma: String,
                cached_comma: String,
                hit_s: String,
                out_comma: String,
                tot_comma: String,
                in_short: String,
                cached_short: String,
                out_short: String,
                tot_short: String,
            }

            let raw_rows: Vec<RawModelRow> = self
                .models
                .iter()
                .map(|m| RawModelRow {
                    clean_name: terminal_text(&m.model),
                    reqs_comma: format_u64_commas(m.request_count),
                    in_comma: format_u64_commas(m.total_input_tokens),
                    cached_comma: format_u64_commas(m.cached_input_tokens),
                    hit_s: format_hit_tenths(m.hit_tenths),
                    out_comma: format_u64_commas(m.output_tokens),
                    tot_comma: format_u64_commas(m.total_tokens),
                    in_short: format_short_tokens(m.total_input_tokens),
                    cached_short: format_short_tokens(m.cached_input_tokens),
                    out_short: format_short_tokens(m.output_tokens),
                    tot_short: format_short_tokens(m.total_tokens),
                })
                .collect();

            let (use_short_nums, max_model_cap, min_model_floor, min_reqs_w, min_tok_w, min_hit_w) =
                match max_cols {
                    None => (
                        false,
                        MAX_HUMAN_MODEL_COL_WIDTH,
                        MIN_HUMAN_MODEL_COL_WIDTH,
                        6usize,
                        11usize,
                        6usize,
                    ),
                    Some(cols) => {
                        let reqs_min = if cols >= 106 { 6 } else { 4 };
                        let tok_min = if cols >= 106 { 11 } else { 8 };
                        let hit_min = if cols >= 106 { 6 } else { "Hit%".len() };
                        let reqs_c = raw_rows
                            .iter()
                            .map(|r| r.reqs_comma.len())
                            .max()
                            .unwrap_or(0)
                            .max(reqs_min);
                        let in_c = raw_rows
                            .iter()
                            .map(|r| r.in_comma.len())
                            .max()
                            .unwrap_or(0)
                            .max(tok_min);
                        let cached_c = raw_rows
                            .iter()
                            .map(|r| r.cached_comma.len())
                            .max()
                            .unwrap_or(0)
                            .max(tok_min);
                        let hit_c = raw_rows
                            .iter()
                            .map(|r| UnicodeWidthStr::width(r.hit_s.as_str()))
                            .max()
                            .unwrap_or(0)
                            .max(hit_min);
                        let out_c = raw_rows
                            .iter()
                            .map(|r| r.out_comma.len())
                            .max()
                            .unwrap_or(0)
                            .max(tok_min);
                        let tot_c = raw_rows
                            .iter()
                            .map(|r| r.tot_comma.len())
                            .max()
                            .unwrap_or(0)
                            .max(tok_min);
                        let comma_fixed = 14 + reqs_c + in_c + cached_c + hit_c + out_c + tot_c;

                        if cols >= WIDE_TERM_MIN_COLS && cols >= comma_fixed + 20 {
                            let cap = (cols - comma_fixed).min(MAX_HUMAN_MODEL_COL_WIDTH);
                            let floor = MIN_HUMAN_MODEL_COL_WIDTH.min(cap);
                            (false, cap, floor, reqs_min, tok_min, hit_min)
                        } else {
                            let reqs_s = raw_rows
                                .iter()
                                .map(|r| r.reqs_comma.len())
                                .max()
                                .unwrap_or(0)
                                .max(4);
                            let in_s = raw_rows
                                .iter()
                                .map(|r| r.in_short.len())
                                .max()
                                .unwrap_or(0)
                                .max(7);
                            let cached_s = raw_rows
                                .iter()
                                .map(|r| r.cached_short.len())
                                .max()
                                .unwrap_or(0)
                                .max(7);
                            let hit_s = raw_rows
                                .iter()
                                .map(|r| UnicodeWidthStr::width(r.hit_s.as_str()))
                                .max()
                                .unwrap_or(0)
                                .max("Hit%".len());
                            let out_s = raw_rows
                                .iter()
                                .map(|r| r.out_short.len())
                                .max()
                                .unwrap_or(0)
                                .max(7);
                            let tot_s = raw_rows
                                .iter()
                                .map(|r| r.tot_short.len())
                                .max()
                                .unwrap_or(0)
                                .max(7);
                            let short_fixed = 14 + reqs_s + in_s + cached_s + hit_s + out_s + tot_s;
                            let cap = cols
                                .saturating_sub(short_fixed)
                                .clamp(8, MAX_HUMAN_MODEL_COL_WIDTH);
                            let floor = 16usize.min(cap);
                            (true, cap, floor, 4usize, 7usize, "Hit%".len())
                        }
                    }
                };

            struct RenderedModelRow {
                name: String,
                name_width: usize,
                reqs: String,
                input: String,
                cached: String,
                hit: String,
                output: String,
                total: String,
            }

            let rows: Vec<RenderedModelRow> = raw_rows
                .into_iter()
                .map(|r| {
                    let (bounded_name, name_width) =
                        truncate_display_width(&r.clean_name, max_model_cap);
                    if use_short_nums {
                        RenderedModelRow {
                            name: bounded_name,
                            name_width,
                            reqs: r.reqs_comma,
                            input: r.in_short,
                            cached: r.cached_short,
                            hit: r.hit_s,
                            output: r.out_short,
                            total: r.tot_short,
                        }
                    } else {
                        RenderedModelRow {
                            name: bounded_name,
                            name_width,
                            reqs: r.reqs_comma,
                            input: r.in_comma,
                            cached: r.cached_comma,
                            hit: r.hit_s,
                            output: r.out_comma,
                            total: r.tot_comma,
                        }
                    }
                })
                .collect();

            let model_w = rows
                .iter()
                .map(|r| r.name_width)
                .max()
                .unwrap_or(0)
                .max(min_model_floor);
            let reqs_w = rows
                .iter()
                .map(|r| r.reqs.len())
                .max()
                .unwrap_or(0)
                .max(min_reqs_w);
            let in_w = rows
                .iter()
                .map(|r| r.input.len())
                .max()
                .unwrap_or(0)
                .max(min_tok_w);
            let cached_w = rows
                .iter()
                .map(|r| r.cached.len())
                .max()
                .unwrap_or(0)
                .max(min_tok_w);
            let hit_w = rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.hit.as_str()))
                .max()
                .unwrap_or(0)
                .max(min_hit_w);
            let out_w = rows
                .iter()
                .map(|r| r.output.len())
                .max()
                .unwrap_or(0)
                .max(min_tok_w);
            let tot_w = rows
                .iter()
                .map(|r| r.total.len())
                .max()
                .unwrap_or(0)
                .max(min_tok_w);

            let pad_left_w = |s: &str, w: usize| -> String {
                let sw = UnicodeWidthStr::width(s);
                if sw >= w {
                    s.to_string()
                } else {
                    format!("{}{s}", " ".repeat(w - sw))
                }
            };

            let header_model_pad = " ".repeat(model_w.saturating_sub("Model".len()));
            lines.push(format!(
                "  Model{header_model_pad}  {:>reqs_w$}  {:>in_w$}  {:>cached_w$}  {}  {:>out_w$}  {:>tot_w$}",
                "Reqs",
                "Input",
                "Cached",
                pad_left_w("Hit%", hit_w),
                "Output",
                "Total",
                reqs_w = reqs_w,
                in_w = in_w,
                cached_w = cached_w,
                out_w = out_w,
                tot_w = tot_w,
            ));
            let rule_len =
                model_w + 2 + reqs_w + 2 + in_w + 2 + cached_w + 2 + hit_w + 2 + out_w + 2 + tot_w;
            lines.push(format!("  {}", "─".repeat(rule_len)));

            for r in &rows {
                let model_pad = " ".repeat(model_w.saturating_sub(r.name_width));
                lines.push(format!(
                    "  {}{model_pad}  {:>reqs_w$}  {:>in_w$}  {:>cached_w$}  {}  {:>out_w$}  {:>tot_w$}",
                    r.name,
                    r.reqs,
                    r.input,
                    r.cached,
                    pad_left_w(&r.hit, hit_w),
                    r.output,
                    r.total,
                    reqs_w = reqs_w,
                    in_w = in_w,
                    cached_w = cached_w,
                    out_w = out_w,
                    tot_w = tot_w,
                ));
            }
        }

        if let Some(cols) = max_cols {
            for line in &mut lines {
                if UnicodeWidthStr::width(line.as_str()) > cols {
                    let (clipped, _) = truncate_display_width(line, cols);
                    *line = clipped;
                }
            }
        }

        lines.join("\n")
    }
}

fn is_strict_normalized_abs_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

fn verify_stats_root_dir_no_path_echo(dir: &Path, category: &str) -> CliResult<()> {
    if !is_strict_normalized_abs_path(dir) {
        return Err(CliError::data(format!(
            "{category} path must be a normalized absolute directory without symlink components."
        )));
    }
    match open_existing_dir_nofollow(dir) {
        Ok(_) => Ok(()),
        Err(e) if e.error_code == "data_error" => Err(CliError::data(format!(
            "{category} path must be a real directory without symlink components."
        ))),
        Err(e) => Err(CliError::io(
            e.error_code,
            format!("Cannot inspect {category} directory hierarchy for local statistics."),
        )),
    }
}

pub(crate) fn collect_token_stats_with_now(
    paths: &HeadlessPaths,
    args: &StatsArgs,
    now: &jiff::Zoned,
) -> CliResult<StatsViewDto> {
    verify_stats_root_dir_no_path_echo(&paths.home_dir, "Home")?;
    let range_spec = resolve_stats_range_spec(args, now.date())?;
    let source = StatsSource::from(args.source);
    Ok(collect_token_stats_at(
        &paths.home_dir,
        source,
        &range_spec,
        now,
    ))
}

pub fn collect_token_stats(paths: &HeadlessPaths, args: &StatsArgs) -> CliResult<StatsViewDto> {
    let now = jiff::Zoned::now();
    collect_token_stats_with_now(paths, args, &now)
}

pub(crate) fn collect_token_stats_list_with_now(
    paths: &HeadlessPaths,
    args: &StatsArgs,
    now: &jiff::Zoned,
) -> CliResult<StatsListViewDto> {
    verify_stats_root_dir_no_path_echo(&paths.home_dir, "Home")?;
    let range_spec = resolve_stats_list_range_spec(args, now.date())?;
    let source = StatsSource::from(args.source);
    Ok(collect_token_stats_list_at(
        &paths.home_dir,
        source,
        &range_spec,
        now,
    ))
}

pub fn collect_token_stats_list(
    paths: &HeadlessPaths,
    args: &StatsArgs,
) -> CliResult<StatsListViewDto> {
    let now = jiff::Zoned::now();
    collect_token_stats_list_with_now(paths, args, &now)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StatsCallStatus {
    Ok,
    Cleared,
    Error,
    Canceled,
    Interrupted,
    Running,
    Archived,
    Unknown,
}

impl StatsCallStatus {
    pub fn short_label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Cleared => "clr",
            Self::Error => "err",
            Self::Canceled => "canc",
            Self::Interrupted => "intr",
            Self::Running => "run",
            Self::Archived => "arch",
            Self::Unknown => "unk",
        }
    }
}

pub fn compute_capped_hit_tenths(uncached_in: u64, cached_in: u64) -> Option<u16> {
    let total_in = uncached_in.saturating_add(cached_in);
    if total_in == 0 {
        None
    } else if cached_in == 0 {
        Some(0)
    } else if uncached_in == 0 {
        Some(1000)
    } else {
        let tenths = ((cached_in as f64 / total_in as f64) * 1000.0).round() as u64;
        Some(tenths.min(999) as u16)
    }
}

pub fn format_hit_tenths(tenths: Option<u16>) -> String {
    match tenths {
        Some(t) => format!("{}.{}%", t / 10, t % 10),
        None => "—".to_string(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsCallRecordDto {
    pub timestamp: i64,
    pub local_time: String,
    pub model: String,
    pub uncached_input_tokens: u64,
    pub cached_input_tokens: u64,
    pub total_input_tokens: u64,
    pub cache_hit_ratio: Option<f64>,
    pub cache_hit_percent: Option<f64>,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub ttft_seconds: Option<f64>,
    pub duration_seconds: Option<f64>,
    pub output_tps: Option<f64>,
    pub status: StatsCallStatus,
    #[serde(skip)]
    hit_tenths: Option<u16>,
}

/// Structurally allow-listed DTO for `agy-switch-cli stats list [--json]`.
/// Excludes local filesystem paths (`source_key`), account emails, and message payloads;
/// `items[].model` is strictly normalized via `classify_model_name` (`"Unknown"` fallback).
#[derive(Debug, Clone, Serialize)]
pub struct StatsListViewDto {
    pub source: StatsSource,
    pub range: StatsRangeDto,
    pub databases_scanned: u64,
    pub generations_scanned: u64,
    pub skipped_large_records: u64,
    pub unreadable_databases: u64,
    pub last_activity: Option<i64>,
    pub range_last_activity: Option<i64>,
    pub generated_at: i64,
    pub total_matching: u64,
    pub shown_count: usize,
    pub truncated: bool,
    pub items: Vec<StatsCallRecordDto>,
    #[serde(skip)]
    range_human: String,
    #[serde(skip)]
    tz: jiff::tz::TimeZone,
}

fn format_list_duration_cell(secs_opt: Option<f64>) -> String {
    match secs_opt {
        None => "—".to_string(),
        Some(sec) if sec < 1000.0 => format!("{sec:.1}s"),
        Some(sec) if sec < 10_000.0 => format!("{sec:.0}s"),
        Some(sec) => format!("{:.1}h", sec / 3600.0),
    }
}

impl StatsListViewDto {
    pub fn render_human(&self) -> String {
        self.render_human_for_width(detect_stdout_terminal_cols())
    }

    pub fn render_human_for_width(&self, max_cols: Option<usize>) -> String {
        let latest_str = self
            .last_activity
            .and_then(|sec| jiff::Timestamp::from_second(sec).ok())
            .map(|ts| {
                ts.to_zoned(self.tz.clone())
                    .strftime("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_else(|| "—".to_string());

        let db_count_str = format_u64_commas(self.databases_scanned);
        let full_source_line = format!(
            "Source : {} · {} db(s) · latest {}",
            self.source.human_header_label(),
            db_count_str,
            latest_str
        );
        let source_line = if max_cols
            .is_some_and(|cols| UnicodeWidthStr::width(full_source_line.as_str()) > cols)
        {
            format!(
                "Source : {} · {} db(s) · latest {}",
                self.source.as_str(),
                db_count_str,
                latest_str
            )
        } else {
            full_source_line
        };

        let mut lines = Vec::new();
        lines.push(source_line);
        lines.push(format!("Range  : {}", self.range_human));
        lines.push(String::new());
        if self.truncated {
            lines.push(format!(
                "Requests (newest first, showing {} of {} — capped at {}; narrow with --date/--from or --recent)",
                self.shown_count,
                format_u64_commas(self.total_matching),
                MAX_STATS_RECENT_LIMIT
            ));
        } else {
            lines.push(format!(
                "Requests (newest first, showing {})",
                self.shown_count
            ));
        }

        if self.items.is_empty() {
            lines.push("  (no token usage recorded in selected range)".to_string());
        } else {
            let now_year = jiff::Timestamp::from_second(self.generated_at)
                .ok()
                .map(|ts| ts.to_zoned(self.tz.clone()).year());
            let cross_year = self.items.iter().any(|it| {
                jiff::Timestamp::from_second(it.timestamp)
                    .ok()
                    .map(|ts| ts.to_zoned(self.tz.clone()).year())
                    != now_year
            });
            let is_wide = max_cols.is_none_or(|cols| cols >= WIDE_LIST_MIN_COLS);
            let time_fmt = if is_wide {
                if cross_year {
                    "%Y-%m-%d %H:%M:%S"
                } else {
                    "%m-%d %H:%M:%S"
                }
            } else {
                "%m-%d %H:%M"
            };

            struct RawCallRow {
                time_s: String,
                clean_model: String,
                in_s: String,
                cache_s: String,
                hit_s: String,
                out_s: String,
                ttft_s: String,
                dur_s: String,
                tps_s: String,
                st_s: &'static str,
            }

            let raw_rows: Vec<RawCallRow> = self
                .items
                .iter()
                .map(|it| {
                    let time_s = jiff::Timestamp::from_second(it.timestamp)
                        .ok()
                        .map(|ts| ts.to_zoned(self.tz.clone()).strftime(time_fmt).to_string())
                        .unwrap_or_else(|| "—".to_string());
                    let hit_s = format_hit_tenths(it.hit_tenths);
                    let tps_s = match it.output_tps {
                        Some(tps) => (tps.round() as u64).to_string(),
                        None => "—".to_string(),
                    };
                    RawCallRow {
                        time_s,
                        clean_model: terminal_text(&it.model),
                        in_s: format_short_tokens(it.total_input_tokens),
                        cache_s: format_short_tokens(it.cached_input_tokens),
                        hit_s,
                        out_s: format_short_tokens(it.output_tokens),
                        ttft_s: format_list_duration_cell(it.ttft_seconds),
                        dur_s: format_list_duration_cell(it.duration_seconds),
                        tps_s,
                        st_s: it.status.short_label(),
                    }
                })
                .collect();

            let time_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.time_s.as_str()))
                .max()
                .unwrap_or(0)
                .max("Time".len());
            let in_min = if is_wide { 6 } else { "In".len() };
            let cache_min = if is_wide { 6 } else { "Cache".len() };
            let hit_min = "Hit%".len();
            let out_min = if is_wide { 5 } else { "Out".len() };
            let ttft_min = if is_wide { 5 } else { "TTFT".len() };
            let dur_min = if is_wide { 5 } else { "Dur".len() };
            let tps_min = "TPS".len();
            let st_min = "St".len();

            let in_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.in_s.as_str()))
                .max()
                .unwrap_or(0)
                .max(in_min);
            let cache_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.cache_s.as_str()))
                .max()
                .unwrap_or(0)
                .max(cache_min);
            let hit_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.hit_s.as_str()))
                .max()
                .unwrap_or(0)
                .max(hit_min);
            let out_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.out_s.as_str()))
                .max()
                .unwrap_or(0)
                .max(out_min);
            let ttft_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.ttft_s.as_str()))
                .max()
                .unwrap_or(0)
                .max(ttft_min);
            let dur_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.dur_s.as_str()))
                .max()
                .unwrap_or(0)
                .max(dur_min);
            let tps_w = raw_rows
                .iter()
                .map(|r| UnicodeWidthStr::width(r.tps_s.as_str()))
                .max()
                .unwrap_or(0)
                .max(tps_min);
            let st_w = raw_rows
                .iter()
                .map(|r| r.st_s.len())
                .max()
                .unwrap_or(0)
                .max(st_min);

            let non_model_cells =
                time_w + in_w + cache_w + hit_w + out_w + ttft_w + dur_w + tps_w + st_w;
            let min_10col_width = 2 + non_model_cells + "Model".len() + 9;
            let use_ultra_narrow_blocks = max_cols.is_some_and(|cols| cols < min_10col_width);

            if use_ultra_narrow_blocks {
                let cols = max_cols.unwrap();
                for r in &raw_rows {
                    let prefix = format!("  {} [{}] ", r.time_s, r.st_s);
                    let prefix_w = UnicodeWidthStr::width(prefix.as_str());
                    let model_budget = cols.saturating_sub(prefix_w);
                    if model_budget >= 5 {
                        let (m_trunc, _) = truncate_display_width(&r.clean_model, model_budget);
                        lines.push(format!("{prefix}{m_trunc}"));
                    } else {
                        lines.push(prefix.trim_end().to_string());
                        let (m_trunc, _) =
                            truncate_display_width(&r.clean_model, cols.saturating_sub(4));
                        lines.push(format!("    {m_trunc}"));
                    }
                    let tok_long = format!(
                        "    In:{} Cache:{} ({}) Out:{}",
                        r.in_s, r.cache_s, r.hit_s, r.out_s
                    );
                    if UnicodeWidthStr::width(tok_long.as_str()) <= cols {
                        lines.push(tok_long);
                    } else {
                        let tok_short = format!(
                            "    In:{} C:{}({}) Out:{}",
                            r.in_s, r.cache_s, r.hit_s, r.out_s
                        );
                        if UnicodeWidthStr::width(tok_short.as_str()) <= cols {
                            lines.push(tok_short);
                        } else {
                            lines.push(format!("    In:{} Out:{}", r.in_s, r.out_s));
                            lines.push(format!("    Cache:{} ({})", r.cache_s, r.hit_s));
                        }
                    }
                    let timing_line =
                        format!("    TTFT:{} Dur:{} TPS:{}", r.ttft_s, r.dur_s, r.tps_s);
                    if UnicodeWidthStr::width(timing_line.as_str()) <= cols {
                        lines.push(timing_line);
                    } else {
                        lines.push(format!("    TTFT:{} Dur:{}", r.ttft_s, r.dur_s));
                        lines.push(format!("    TPS:{} St:{}", r.tps_s, r.st_s));
                    }
                }
            } else {
                let (gap, max_model_cap, min_model_floor) = match max_cols {
                    None => ("  ", 40usize, 25usize),
                    Some(cols) if is_wide => {
                        let fixed = 2 + 18 + non_model_cells;
                        if cols >= fixed + "Model".len() {
                            let cap = (cols - fixed).clamp(5, 44);
                            let floor = 25usize.min(cap);
                            ("  ", cap, floor)
                        } else {
                            let fixed_1sp = 2 + 9 + non_model_cells;
                            let cap = cols.saturating_sub(fixed_1sp).clamp(5, 44);
                            let floor = "Model".len().min(cap);
                            (" ", cap, floor)
                        }
                    }
                    Some(cols) => {
                        let fixed_2sp = 2 + 18 + non_model_cells;
                        if cols >= fixed_2sp + 10 {
                            let cap = (cols - fixed_2sp).min(36);
                            let floor = "Model".len().min(cap);
                            ("  ", cap, floor)
                        } else {
                            let fixed_1sp = 2 + 9 + non_model_cells;
                            let cap = cols.saturating_sub(fixed_1sp).clamp(5, 36);
                            let floor = "Model".len().min(cap);
                            (" ", cap, floor)
                        }
                    }
                };

                let truncated_models: Vec<(String, usize)> = raw_rows
                    .iter()
                    .map(|r| truncate_display_width(&r.clean_model, max_model_cap))
                    .collect();
                let model_w = truncated_models
                    .iter()
                    .map(|(_, w)| *w)
                    .max()
                    .unwrap_or(0)
                    .max(min_model_floor);

                let pad_left_w = |s: &str, w: usize| -> String {
                    let sw = UnicodeWidthStr::width(s);
                    if sw >= w {
                        s.to_string()
                    } else {
                        format!("{}{s}", " ".repeat(w - sw))
                    }
                };
                let pad_right_w = |s: &str, w: usize| -> String {
                    let sw = UnicodeWidthStr::width(s);
                    if sw >= w {
                        s.to_string()
                    } else {
                        format!("{s}{}", " ".repeat(w - sw))
                    }
                };

                let header_line = format!(
                    "  {}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}",
                    pad_right_w("Time", time_w),
                    pad_right_w("Model", model_w),
                    pad_left_w("In", in_w),
                    pad_left_w("Cache", cache_w),
                    pad_left_w("Hit%", hit_w),
                    pad_left_w("Out", out_w),
                    pad_left_w("TTFT", ttft_w),
                    pad_left_w("Dur", dur_w),
                    pad_left_w("TPS", tps_w),
                    "St",
                );
                let rule_len = non_model_cells + model_w + 9 * gap.len();
                lines.push(header_line);
                lines.push(format!("  {}", "─".repeat(rule_len)));

                for (r, (m_name, m_w)) in raw_rows.iter().zip(truncated_models.iter()) {
                    let m_pad = " ".repeat(model_w.saturating_sub(*m_w));
                    lines.push(format!(
                        "  {}{gap}{}{m_pad}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}",
                        pad_right_w(&r.time_s, time_w),
                        m_name,
                        pad_left_w(&r.in_s, in_w),
                        pad_left_w(&r.cache_s, cache_w),
                        pad_left_w(&r.hit_s, hit_w),
                        pad_left_w(&r.out_s, out_w),
                        pad_left_w(&r.ttft_s, ttft_w),
                        pad_left_w(&r.dur_s, dur_w),
                        pad_left_w(&r.tps_s, tps_w),
                        r.st_s,
                    ));
                }
            }
        }

        if let Some(cols) = max_cols {
            for line in &mut lines {
                if UnicodeWidthStr::width(line.as_str()) > cols {
                    let (clipped, _) = truncate_display_width(line, cols);
                    *line = clipped;
                }
            }
        }

        lines.join("\n")
    }
}

#[derive(Debug, Clone)]
struct InternalCallRecord {
    source_key: String,
    generation_idx: i64,
    timestamp_seconds: i64,
    model: String,
    uncached_input_tokens: u64,
    cached_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    ttft_seconds: Option<f64>,
    duration_seconds: Option<f64>,
    output_tps: Option<f64>,
    status: StatsCallStatus,
}

fn cmp_newest_first(a: &InternalCallRecord, b: &InternalCallRecord) -> Ordering {
    b.timestamp_seconds
        .cmp(&a.timestamp_seconds)
        .then_with(|| b.generation_idx.cmp(&a.generation_idx))
        .then_with(|| a.source_key.cmp(&b.source_key))
}

#[derive(Debug, Clone)]
struct OldestAtTop(InternalCallRecord);

impl PartialEq for OldestAtTop {
    fn eq(&self, other: &Self) -> bool {
        cmp_newest_first(&self.0, &other.0) == Ordering::Equal
    }
}
impl Eq for OldestAtTop {}
impl PartialOrd for OldestAtTop {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OldestAtTop {
    fn cmp(&self, other: &Self) -> Ordering {
        // Larger `cmp_newest_first` means OLDER, so `BinaryHeap` max-heap puts the OLDEST item at `.peek()`!
        cmp_newest_first(&self.0, &other.0)
    }
}

#[derive(Debug, Clone)]
struct BoundedRecordSink {
    cap: usize,
    total_matching: u64,
    range_first_activity: Option<i64>,
    range_last_activity: Option<i64>,
    heap: BinaryHeap<OldestAtTop>,
}

impl BoundedRecordSink {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            total_matching: 0,
            range_first_activity: None,
            range_last_activity: None,
            heap: BinaryHeap::with_capacity(cap.min(512) + 1),
        }
    }

    fn push_matching(&mut self, rec: InternalCallRecord) {
        self.total_matching = self.total_matching.saturating_add(1);
        let ts = rec.timestamp_seconds;
        self.range_first_activity = Some(self.range_first_activity.map_or(ts, |c| c.min(ts)));
        self.range_last_activity = Some(self.range_last_activity.map_or(ts, |c| c.max(ts)));
        if self.heap.len() < self.cap {
            self.heap.push(OldestAtTop(rec));
        } else if let Some(oldest) = self.heap.peek() {
            if cmp_newest_first(&rec, &oldest.0) == Ordering::Less {
                self.heap.pop();
                self.heap.push(OldestAtTop(rec));
            }
        }
    }

    fn merge_from(&mut self, other: BoundedRecordSink) {
        self.total_matching = self.total_matching.saturating_add(other.total_matching);
        if let Some(f) = other.range_first_activity {
            self.range_first_activity = Some(self.range_first_activity.map_or(f, |c| c.min(f)));
        }
        if let Some(l) = other.range_last_activity {
            self.range_last_activity = Some(self.range_last_activity.map_or(l, |c| c.max(l)));
        }
        for OldestAtTop(rec) in other.heap {
            if self.heap.len() < self.cap {
                self.heap.push(OldestAtTop(rec));
            } else if let Some(oldest) = self.heap.peek() {
                if cmp_newest_first(&rec, &oldest.0) == Ordering::Less {
                    self.heap.pop();
                    self.heap.push(OldestAtTop(rec));
                }
            }
        }
    }

    fn into_newest_first_vec(self) -> Vec<InternalCallRecord> {
        let mut out: Vec<InternalCallRecord> = self.heap.into_iter().map(|w| w.0).collect();
        out.sort_by(cmp_newest_first);
        out
    }
}

#[derive(Default)]
struct ModelAccum {
    request_count: u64,
    uncached_input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
}

#[derive(Default)]
struct StatsAggregator {
    uncached_input: u64,
    cached_input: u64,
    total_output: u64,
    request_count: u64,
    last_activity: Option<i64>,
    range_first_activity: Option<i64>,
    range_last_activity: Option<i64>,
    by_model: BTreeMap<String, ModelAccum>,
    perf_ttft_samples: Vec<f64>,
    perf_tps_samples: Vec<f64>,
    perf_models: HashSet<String>,
    perf_sources: HashSet<String>,
    record_sink: Option<BoundedRecordSink>,
}

impl StatsAggregator {
    fn with_sink_cap(cap: Option<usize>) -> Self {
        Self {
            record_sink: cap.map(BoundedRecordSink::new),
            ..Self::default()
        }
    }

    fn spawn_local(&self) -> Self {
        Self {
            record_sink: self
                .record_sink
                .as_ref()
                .map(|s| BoundedRecordSink::new(s.cap)),
            ..Self::default()
        }
    }
    fn observe_timestamp(&mut self, timestamp_seconds: i64) {
        self.last_activity = Some(
            self.last_activity
                .map_or(timestamp_seconds, |cur| cur.max(timestamp_seconds)),
        );
    }

    fn observe_range_timestamp(&mut self, timestamp_seconds: i64) {
        self.range_first_activity = Some(
            self.range_first_activity
                .map_or(timestamp_seconds, |cur| cur.min(timestamp_seconds)),
        );
        self.range_last_activity = Some(
            self.range_last_activity
                .map_or(timestamp_seconds, |cur| cur.max(timestamp_seconds)),
        );
    }

    fn record_in_range_event(&mut self, ev: GenerationEvent) {
        self.uncached_input = self.uncached_input.saturating_add(ev.uncached_input_tokens);
        self.cached_input = self.cached_input.saturating_add(ev.cached_tokens);
        self.total_output = self.total_output.saturating_add(ev.output_tokens);
        self.request_count = self.request_count.saturating_add(1);
        self.observe_range_timestamp(ev.timestamp_seconds);

        let entry = self.by_model.entry(ev.model).or_default();
        entry.request_count = entry.request_count.saturating_add(1);
        entry.uncached_input_tokens = entry
            .uncached_input_tokens
            .saturating_add(ev.uncached_input_tokens);
        entry.cached_input_tokens = entry.cached_input_tokens.saturating_add(ev.cached_tokens);
        entry.output_tokens = entry.output_tokens.saturating_add(ev.output_tokens);
        entry.total_tokens = entry.total_tokens.saturating_add(ev.total_tokens);
    }

    fn record_perf_sample(&mut self, sample: PerfSample, source_key: &str) {
        self.observe_range_timestamp(sample.timestamp_seconds);
        self.perf_ttft_samples.push(sample.ttft_seconds);
        self.perf_tps_samples.push(sample.output_tps);
        self.perf_models.insert(sample.model);
        if !self.perf_sources.contains(source_key) {
            self.perf_sources.insert(source_key.to_string());
        }
    }
}

struct CandidateDb {
    source_key: String,
    conv_dir_fd: Arc<OwnedFd>,
    file_name: OsString,
}

struct RawScanResult {
    scanned_sources: HashSet<String>,
    generations_scanned: u64,
    skipped_large_records: u64,
    unreadable_databases: u64,
    agg: StatsAggregator,
}

enum RawScanEarly {
    Empty { unreadable_databases: u64 },
    Scanned(Box<RawScanResult>),
}

fn execute_stats_scan_core(
    home_dir: &Path,
    source: StatsSource,
    range_spec: &StatsRangeSpec,
    tz: &jiff::tz::TimeZone,
    sink_cap: Option<usize>,
) -> RawScanEarly {
    if !is_strict_normalized_abs_path(home_dir) {
        return RawScanEarly::Empty {
            unreadable_databases: 0,
        };
    }

    let home_fd = match open_existing_dir_nofollow(home_dir) {
        Ok(Some(fd)) => fd,
        Ok(None) => {
            return RawScanEarly::Empty {
                unreadable_databases: 0,
            }
        }
        Err(e) if e.error_code == "data_error" => {
            return RawScanEarly::Empty {
                unreadable_databases: 0,
            }
        }
        Err(_) => {
            return RawScanEarly::Empty {
                unreadable_databases: 1,
            }
        }
    };

    let gemini_fd = match open_child_dir_nofollow(&home_fd, GEMINI_DIR, false) {
        ChildDirOpen::Opened(fd) => fd,
        ChildDirOpen::Absent | ChildDirOpen::Unsafe => {
            return RawScanEarly::Empty {
                unreadable_databases: 0,
            };
        }
        ChildDirOpen::IoError => {
            return RawScanEarly::Empty {
                unreadable_databases: 1,
            };
        }
    };
    drop(home_fd);

    let mut seen_inodes: HashSet<(u64, u64)> = HashSet::new();
    let mut candidate_dbs: Vec<CandidateDb> = Vec::new();
    let mut unreadable_databases = 0_u64;
    let mut app_dir_fd_opt: Option<OwnedFd> = None;

    if matches!(source, StatsSource::Cli | StatsSource::All) {
        if let Some(cli_fd) = open_client_dir(&gemini_fd, CLI_DIR_NAME, &mut unreadable_databases) {
            discover_client_db_candidates_in_fd(
                &cli_fd,
                CLI_DIR_NAME,
                &mut candidate_dbs,
                &mut unreadable_databases,
            );
        }
    }
    if matches!(source, StatsSource::App | StatsSource::All) {
        if let Some(app_fd) = open_client_dir(&gemini_fd, APP_DIR_NAME, &mut unreadable_databases) {
            discover_client_db_candidates_in_fd(
                &app_fd,
                APP_DIR_NAME,
                &mut candidate_dbs,
                &mut unreadable_databases,
            );
            app_dir_fd_opt = Some(app_fd);
        }
    }
    drop(gemini_fd);

    let live_source_keys: HashSet<String> =
        candidate_dbs.iter().map(|d| d.source_key.clone()).collect();

    let mut scanned_sources: HashSet<String> = HashSet::new();
    let mut generations_scanned = 0_u64;
    let mut skipped_large_records = 0_u64;
    let mut agg = StatsAggregator::with_sink_cap(sink_cap);

    // Check if `token_usage_archive.db` exists and has an index on `(source_key, generation_idx)`.
    // On indexed official archives, stream live + archive in O(1) dedup memory with at most 2 open DBs;
    // on unindexed/abnormal archive schemas, use an explicit row-budgeted fallback!
    let mut handled_via_indexed_archive = false;
    let mut archived = ArchivedScanMeta::default();

    if let Some(ref app_fd) = app_dir_fd_opt {
        let indexed_outcome = scan_with_bounded_retry(
            app_fd,
            OsStr::new(TOKEN_ARCHIVE_FILE),
            &mut seen_inodes,
            |arch_conn| {
                scan_with_archive_connection(
                    arch_conn,
                    source,
                    range_spec,
                    tz,
                    &candidate_dbs,
                    &live_source_keys,
                    &mut agg,
                )
            },
        );
        match indexed_outcome {
            RetryScanOutcome::Absent | RetryScanOutcome::SkippedUnsafeOrDuplicate => {}
            RetryScanOutcome::Unreadable => {
                unreadable_databases = unreadable_databases.saturating_add(1);
            }
            RetryScanOutcome::Scanned(ArchiveDispatchResult::IndexedComplete(res)) => {
                handled_via_indexed_archive = true;
                scanned_sources.extend(res.scanned_sources);
                generations_scanned = generations_scanned.saturating_add(res.generations_scanned);
                skipped_large_records =
                    skipped_large_records.saturating_add(res.skipped_large_records);
                unreadable_databases =
                    unreadable_databases.saturating_add(res.unreadable_databases);
            }
            RetryScanOutcome::Scanned(ArchiveDispatchResult::UnindexedMeta(meta)) => {
                archived = meta;
            }
        }
    }
    drop(app_dir_fd_opt);

    if handled_via_indexed_archive {
        return RawScanEarly::Scanned(Box::new(RawScanResult {
            scanned_sources,
            generations_scanned,
            skipped_large_records,
            unreadable_databases,
            agg,
        }));
    }

    scanned_sources.extend(archived.source_keys.iter().cloned());
    generations_scanned = generations_scanned.saturating_add(archived.generations_scanned);
    skipped_large_records = skipped_large_records.saturating_add(archived.skipped_large_records);

    let flush_unmatched_archive_events =
        |src_key: &str,
         events_map: HashMap<i64, GenerationEvent>,
         range_spec: &StatsRangeSpec,
         tz: &jiff::tz::TimeZone,
         agg: &mut StatsAggregator| {
            if let Some(ref mut sink) = agg.record_sink {
                for (gen_idx, ev) in events_map {
                    if let Ok(ts) = jiff::Timestamp::from_second(ev.timestamp_seconds) {
                        let d = ts.to_zoned(tz.clone()).date();
                        if range_spec.contains_date(d) {
                            sink.push_matching(InternalCallRecord {
                                source_key: src_key.to_string(),
                                generation_idx: gen_idx,
                                timestamp_seconds: ev.timestamp_seconds,
                                model: ev.model,
                                uncached_input_tokens: ev.uncached_input_tokens,
                                cached_tokens: ev.cached_tokens,
                                output_tokens: ev.output_tokens,
                                total_tokens: ev.total_tokens,
                                ttft_seconds: None,
                                duration_seconds: None,
                                output_tps: None,
                                status: StatsCallStatus::Archived,
                            });
                        }
                    }
                }
            }
        };

    // Open, scan within a single consistent read transaction, and close ONE live `.db` at a time (`O(1)` FDs).
    for candidate in &candidate_dbs {
        let valid_archived_ids = archived
            .valid_generation_ids_by_source
            .get(&candidate.source_key);
        let mut pending_valid_events = archived
            .valid_events_by_source
            .remove(&candidate.source_key)
            .unwrap_or_default();
        let mut pending_invalid_for_src = archived
            .pending_invalid_by_source
            .remove(&candidate.source_key)
            .unwrap_or_default();
        let track_live_ids =
            !pending_valid_events.is_empty() || !pending_invalid_for_src.is_empty();

        match scan_with_bounded_retry(
            &candidate.conv_dir_fd,
            &candidate.file_name,
            &mut seen_inodes,
            |conn| {
                scan_database_streaming(
                    conn,
                    &candidate.source_key,
                    range_spec,
                    tz,
                    ArchiveLookup::Unindexed {
                        valid_archived_ids,
                        valid_archived_events: Some(&pending_valid_events),
                        pending_invalid_ids: Some(&pending_invalid_for_src),
                    },
                    track_live_ids,
                    &mut agg,
                )
            },
        ) {
            RetryScanOutcome::Absent | RetryScanOutcome::SkippedUnsafeOrDuplicate => {
                for (_gen_idx, was_oversized) in pending_invalid_for_src {
                    generations_scanned = generations_scanned.saturating_add(1);
                    if was_oversized {
                        skipped_large_records = skipped_large_records.saturating_add(1);
                    }
                }
                flush_unmatched_archive_events(
                    &candidate.source_key,
                    pending_valid_events,
                    range_spec,
                    tz,
                    &mut agg,
                );
            }
            RetryScanOutcome::Unreadable => {
                unreadable_databases = unreadable_databases.saturating_add(1);
                for (_gen_idx, was_oversized) in pending_invalid_for_src {
                    generations_scanned = generations_scanned.saturating_add(1);
                    if was_oversized {
                        skipped_large_records = skipped_large_records.saturating_add(1);
                    }
                }
                flush_unmatched_archive_events(
                    &candidate.source_key,
                    pending_valid_events,
                    range_spec,
                    tz,
                    &mut agg,
                );
            }
            RetryScanOutcome::Scanned(res) => {
                scanned_sources.insert(candidate.source_key.clone());
                generations_scanned = generations_scanned.saturating_add(res.generations_scanned);
                skipped_large_records =
                    skipped_large_records.saturating_add(res.skipped_large_records);
                for seen_live_id in &res.live_generation_ids_seen {
                    pending_invalid_for_src.remove(seen_live_id);
                    pending_valid_events.remove(seen_live_id);
                }
                for (_gen_idx, was_oversized) in pending_invalid_for_src {
                    generations_scanned = generations_scanned.saturating_add(1);
                    if was_oversized {
                        skipped_large_records = skipped_large_records.saturating_add(1);
                    }
                }
                flush_unmatched_archive_events(
                    &candidate.source_key,
                    pending_valid_events,
                    range_spec,
                    tz,
                    &mut agg,
                );
            }
        }
    }

    for (_src, leftover) in archived.pending_invalid_by_source {
        for (_gen_idx, was_oversized) in leftover {
            generations_scanned = generations_scanned.saturating_add(1);
            if was_oversized {
                skipped_large_records = skipped_large_records.saturating_add(1);
            }
        }
    }
    for (src_key, leftover_events) in archived.valid_events_by_source {
        flush_unmatched_archive_events(&src_key, leftover_events, range_spec, tz, &mut agg);
    }

    RawScanEarly::Scanned(Box::new(RawScanResult {
        scanned_sources,
        generations_scanned,
        skipped_large_records,
        unreadable_databases,
        agg,
    }))
}

pub fn collect_token_stats_at(
    home_dir: &Path,
    source: StatsSource,
    range_spec: &StatsRangeSpec,
    now: &jiff::Zoned,
) -> StatsViewDto {
    let tz = now.time_zone().clone();
    let generated_at = now.timestamp().as_second();
    let sink_cap = match range_spec {
        StatsRangeSpec::Recent { limit } => Some(*limit),
        _ => None,
    };

    let RawScanResult {
        scanned_sources,
        generations_scanned,
        skipped_large_records,
        unreadable_databases,
        mut agg,
    } = match execute_stats_scan_core(home_dir, source, range_spec, &tz, sink_cap) {
        RawScanEarly::Empty {
            unreadable_databases,
        } => {
            return empty_stats_view(source, range_spec, generated_at, unreadable_databases, tz);
        }
        RawScanEarly::Scanned(res) => *res,
    };

    if let Some(sink) = agg.record_sink.take() {
        let recent_records = sink.into_newest_first_vec();
        for rec in recent_records {
            if let (Some(ttft), Some(tps)) = (rec.ttft_seconds, rec.output_tps) {
                agg.record_perf_sample(
                    PerfSample {
                        model: rec.model.clone(),
                        timestamp_seconds: rec.timestamp_seconds,
                        ttft_seconds: ttft,
                        output_tps: tps,
                    },
                    &rec.source_key,
                );
            }
            agg.record_in_range_event(GenerationEvent {
                model: rec.model,
                uncached_input_tokens: rec.uncached_input_tokens,
                output_tokens: rec.output_tokens,
                cached_tokens: rec.cached_tokens,
                total_tokens: rec.total_tokens,
                timestamp_seconds: rec.timestamp_seconds,
            });
        }
    }

    let total_input = agg.uncached_input.saturating_add(agg.cached_input);
    let total_tokens = total_input.saturating_add(agg.total_output);
    let cache_hit_ratio = if total_input > 0 {
        Some(agg.cached_input as f64 / total_input as f64)
    } else {
        None
    };

    let mut models: Vec<StatsModelDto> = agg
        .by_model
        .into_iter()
        .map(|(model, acc)| {
            let model_total_in = acc
                .uncached_input_tokens
                .saturating_add(acc.cached_input_tokens);
            let model_hit_ratio = if model_total_in > 0 {
                Some(acc.cached_input_tokens as f64 / model_total_in as f64)
            } else {
                None
            };
            let hit_tenths =
                compute_capped_hit_tenths(acc.uncached_input_tokens, acc.cached_input_tokens);
            let cache_hit_percent = hit_tenths.map(|t| f64::from(t) / 10.0);
            StatsModelDto {
                model,
                request_count: acc.request_count,
                total_input_tokens: model_total_in,
                uncached_input_tokens: acc.uncached_input_tokens,
                cached_input_tokens: acc.cached_input_tokens,
                cache_hit_ratio: model_hit_ratio,
                cache_hit_percent,
                output_tokens: acc.output_tokens,
                total_tokens: acc.total_tokens,
                hit_tenths,
            }
        })
        .collect();
    models.sort_by(|left, right| {
        right
            .total_tokens
            .cmp(&left.total_tokens)
            .then_with(|| left.model.cmp(&right.model))
    });

    let performance = build_performance_dto(
        agg.perf_ttft_samples,
        agg.perf_tps_samples,
        agg.perf_models.len(),
        agg.perf_sources.len(),
    );

    let observed_timestamps = agg.range_first_activity.zip(agg.range_last_activity);
    let observed_bounds = match observed_timestamps {
        Some((first_sec, last_sec)) => {
            match (
                jiff::Timestamp::from_second(first_sec),
                jiff::Timestamp::from_second(last_sec),
            ) {
                (Ok(t1), Ok(t2)) => {
                    let d1 = t1.to_zoned(tz.clone()).date();
                    let d2 = t2.to_zoned(tz.clone()).date();
                    Some((d1.min(d2), d1.max(d2)))
                }
                _ => None,
            }
        }
        None => None,
    };

    StatsViewDto {
        source,
        range: range_spec.to_dto_with_observed(observed_bounds),
        databases_scanned: scanned_sources.len() as u64,
        generations_scanned,
        skipped_large_records,
        unreadable_databases,
        last_activity: agg.last_activity,
        range_last_activity: agg.range_last_activity,
        generated_at,
        summary: StatsSummaryDto {
            total_input_tokens: total_input,
            uncached_input_tokens: agg.uncached_input,
            cached_input_tokens: agg.cached_input,
            total_output_tokens: agg.total_output,
            total_tokens,
            cache_hit_ratio,
            request_count: agg.request_count,
        },
        performance,
        models,
        range_human: range_spec.human_label_with_observed_activity(
            observed_bounds,
            observed_timestamps,
            &tz,
        ),
        tz,
    }
}

pub fn collect_token_stats_list_at(
    home_dir: &Path,
    source: StatsSource,
    range_spec: &StatsRangeSpec,
    now: &jiff::Zoned,
) -> StatsListViewDto {
    let tz = now.time_zone().clone();
    let generated_at = now.timestamp().as_second();
    let cap = match range_spec {
        StatsRangeSpec::Recent { limit } => *limit,
        _ => MAX_STATS_RECENT_LIMIT as usize,
    };

    let RawScanResult {
        scanned_sources,
        generations_scanned,
        skipped_large_records,
        unreadable_databases,
        mut agg,
    } = match execute_stats_scan_core(home_dir, source, range_spec, &tz, Some(cap)) {
        RawScanEarly::Empty {
            unreadable_databases,
        } => {
            return StatsListViewDto {
                source,
                range: range_spec.to_dto(),
                databases_scanned: 0,
                generations_scanned: 0,
                skipped_large_records: 0,
                unreadable_databases,
                last_activity: None,
                range_last_activity: None,
                generated_at,
                total_matching: 0,
                shown_count: 0,
                truncated: false,
                items: Vec::new(),
                range_human: range_spec.human_label(),
                tz,
            };
        }
        RawScanEarly::Scanned(res) => *res,
    };

    let sink = agg
        .record_sink
        .take()
        .unwrap_or_else(|| BoundedRecordSink::new(cap));
    let raw_total_matching = sink.total_matching;
    let full_range_first = sink.range_first_activity;
    let full_range_last = sink.range_last_activity;
    let records = sink.into_newest_first_vec();

    let is_recent_spec = matches!(range_spec, StatsRangeSpec::Recent { .. });
    let (total_matching, truncated, obs_first, obs_last) = if is_recent_spec {
        let f = records.last().map(|r| r.timestamp_seconds);
        let l = records.first().map(|r| r.timestamp_seconds);
        (records.len() as u64, false, f, l)
    } else {
        let trunc = raw_total_matching > records.len() as u64;
        (raw_total_matching, trunc, full_range_first, full_range_last)
    };

    let observed_timestamps = obs_first.zip(obs_last);
    let observed_bounds = match observed_timestamps {
        Some((first_sec, last_sec)) => {
            match (
                jiff::Timestamp::from_second(first_sec),
                jiff::Timestamp::from_second(last_sec),
            ) {
                (Ok(t1), Ok(t2)) => {
                    let d1 = t1.to_zoned(tz.clone()).date();
                    let d2 = t2.to_zoned(tz.clone()).date();
                    Some((d1.min(d2), d1.max(d2)))
                }
                _ => None,
            }
        }
        None => None,
    };

    let items: Vec<StatsCallRecordDto> = records
        .into_iter()
        .map(|r| {
            let total_in = r.uncached_input_tokens.saturating_add(r.cached_tokens);
            let cache_hit_ratio = if total_in > 0 {
                Some(r.cached_tokens as f64 / total_in as f64)
            } else {
                None
            };
            let hit_tenths = compute_capped_hit_tenths(r.uncached_input_tokens, r.cached_tokens);
            let cache_hit_percent = hit_tenths.map(|t| f64::from(t) / 10.0);
            let local_time = jiff::Timestamp::from_second(r.timestamp_seconds)
                .ok()
                .map(|ts| {
                    ts.to_zoned(tz.clone())
                        .strftime("%Y-%m-%d %H:%M:%S")
                        .to_string()
                })
                .unwrap_or_else(|| "unknown".to_string());
            StatsCallRecordDto {
                timestamp: r.timestamp_seconds,
                local_time,
                model: r.model,
                uncached_input_tokens: r.uncached_input_tokens,
                cached_input_tokens: r.cached_tokens,
                total_input_tokens: total_in,
                cache_hit_ratio,
                cache_hit_percent,
                output_tokens: r.output_tokens,
                total_tokens: r.total_tokens,
                ttft_seconds: r.ttft_seconds,
                duration_seconds: r.duration_seconds,
                output_tps: r.output_tps,
                status: r.status,
                hit_tenths,
            }
        })
        .collect();
    let shown_count = items.len();

    StatsListViewDto {
        source,
        range: range_spec.to_dto_with_observed(observed_bounds),
        databases_scanned: scanned_sources.len() as u64,
        generations_scanned,
        skipped_large_records,
        unreadable_databases,
        last_activity: agg.last_activity,
        range_last_activity: obs_last,
        generated_at,
        total_matching,
        shown_count,
        truncated,
        items,
        range_human: range_spec.human_label_with_observed_activity(
            observed_bounds,
            observed_timestamps,
            &tz,
        ),
        tz,
    }
}

fn empty_stats_view(
    source: StatsSource,
    range_spec: &StatsRangeSpec,
    generated_at: i64,
    unreadable_databases: u64,
    tz: jiff::tz::TimeZone,
) -> StatsViewDto {
    StatsViewDto {
        source,
        range: range_spec.to_dto(),
        databases_scanned: 0,
        generations_scanned: 0,
        skipped_large_records: 0,
        unreadable_databases,
        last_activity: None,
        range_last_activity: None,
        generated_at,
        summary: StatsSummaryDto::default(),
        performance: None,
        models: Vec::new(),
        range_human: range_spec.human_label(),
        tz,
    }
}

enum RetryScanOutcome<T> {
    Absent,
    SkippedUnsafeOrDuplicate,
    Unreadable,
    Scanned(T),
}

fn transient_retry_backoff(attempt: usize) -> Duration {
    const BACKOFF_MS: [u64; 8] = [1, 2, 3, 5, 7, 10, 13, 16];
    let idx = attempt.min(BACKOFF_MS.len() - 1);
    Duration::from_millis(BACKOFF_MS[idx])
}

fn scan_with_bounded_retry<T, F>(
    dir_fd: &OwnedFd,
    leaf_name: &OsStr,
    seen_inodes: &mut HashSet<(u64, u64)>,
    mut scan_fn: F,
) -> RetryScanOutcome<T>
where
    F: FnMut(&PinnedSqliteConnection) -> Result<T, rusqlite::Error>,
{
    for attempt in 0..TRANSIENT_DB_RETRY_LIMIT {
        match open_pinned_readonly_sqlite(dir_fd, leaf_name, seen_inodes) {
            PinnedSqliteOpen::Absent => return RetryScanOutcome::Absent,
            PinnedSqliteOpen::SkippedUnsafeOrDuplicate => {
                return RetryScanOutcome::SkippedUnsafeOrDuplicate;
            }
            PinnedSqliteOpen::TransientRetry => {
                if attempt + 1 < TRANSIENT_DB_RETRY_LIMIT {
                    std::thread::sleep(transient_retry_backoff(attempt));
                    continue;
                }
                return RetryScanOutcome::Unreadable;
            }
            PinnedSqliteOpen::Unreadable => return RetryScanOutcome::Unreadable,
            PinnedSqliteOpen::Opened(pinned) => {
                let opened_id = pinned.main_file_id();
                match scan_fn(&pinned) {
                    Ok(val) => {
                        seen_inodes.insert(opened_id);
                        return RetryScanOutcome::Scanned(val);
                    }
                    Err(err) => {
                        // Verify cohort & file consistency on error too: if an unshmed/closing WAL cohort
                        // changed mid-query and caused SQLite to return `SQLITE_CORRUPT` / `SQLITE_IOERR`
                        // before `scan_fn` reached its end-of-tx `verify_snapshot_consistent()`, mark
                        // `saw_cohort_change` / `saw_unsafe_companion` so we retry cleanly!
                        let _ = pinned.verify_snapshot_consistent();
                        if pinned.saw_unsafe_companion() {
                            seen_inodes.insert(opened_id);
                            return RetryScanOutcome::SkippedUnsafeOrDuplicate;
                        }
                        if attempt + 1 < TRANSIENT_DB_RETRY_LIMIT
                            && (pinned.saw_cohort_change() || is_transient_sqlite_err(&err))
                        {
                            drop(pinned);
                            std::thread::sleep(transient_retry_backoff(attempt));
                            continue;
                        }
                        seen_inodes.insert(opened_id);
                        return RetryScanOutcome::Unreadable;
                    }
                }
            }
        }
    }
    RetryScanOutcome::Unreadable
}

fn open_client_dir(
    gemini_fd: &OwnedFd,
    client_dir_name: &str,
    unreadable_databases: &mut u64,
) -> Option<OwnedFd> {
    match open_child_dir_nofollow(gemini_fd, client_dir_name, false) {
        ChildDirOpen::Opened(fd) => Some(fd),
        ChildDirOpen::Absent | ChildDirOpen::Unsafe => None,
        ChildDirOpen::IoError => {
            *unreadable_databases = unreadable_databases.saturating_add(1);
            None
        }
    }
}

/// Enumerate `.db` entries strictly inside the already-opened `conv_dir_fd` via `fdopendir` + `readdir`,
/// counting any OS directory-read or `readdir` I/O errors in `unreadable_databases`.
fn discover_client_db_candidates_in_fd(
    client_fd: &OwnedFd,
    client_dir_name: &'static str,
    out: &mut Vec<CandidateDb>,
    unreadable_databases: &mut u64,
) {
    let conv_fd = match open_child_dir_nofollow(client_fd, CONVERSATIONS_DIR, true) {
        ChildDirOpen::Opened(fd) => Arc::new(fd),
        ChildDirOpen::Absent | ChildDirOpen::Unsafe => return,
        ChildDirOpen::IoError => {
            *unreadable_databases = unreadable_databases.saturating_add(1);
            return;
        }
    };

    let dup_raw = unsafe { libc::fcntl(conv_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_raw < 0 {
        *unreadable_databases = unreadable_databases.saturating_add(1);
        return;
    }
    let dir_ptr = unsafe { libc::fdopendir(dup_raw) };
    if dir_ptr.is_null() {
        unsafe {
            let _ = libc::close(dup_raw);
        }
        *unreadable_databases = unreadable_databases.saturating_add(1);
        return;
    }

    struct DirStreamGuard(*mut libc::DIR);
    impl Drop for DirStreamGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::closedir(self.0);
            }
        }
    }
    let _guard = DirStreamGuard(dir_ptr);

    let mut entries: Vec<(String, OsString)> = Vec::new();
    loop {
        let ent = unsafe { read_next_dir_entry(dir_ptr) };
        if ent.is_null() {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error().unwrap_or(0) != 0 {
                *unreadable_databases = unreadable_databases.saturating_add(1);
            }
            break;
        }
        let raw_name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if raw_name == b"." || raw_name == b".." || !is_single_normal_filename(raw_name) {
            continue;
        }
        if !raw_name.ends_with(b".db") || raw_name.len() <= 3 {
            continue;
        }
        let os_name = OsStr::from_bytes(raw_name).to_os_string();
        let sort_key = String::from_utf8_lossy(raw_name).into_owned();
        entries.push((sort_key, os_name));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (display_name, file_name) in entries {
        out.push(CandidateDb {
            source_key: format!("{client_dir_name}/{CONVERSATIONS_DIR}/{display_name}"),
            conv_dir_fd: Arc::clone(&conv_fd),
            file_name,
        });
    }
}

#[cfg(test)]
thread_local! {
    static TEST_INJECT_READDIR_ERRNO: std::cell::Cell<libc::c_int> =
        const { std::cell::Cell::new(0) };
}

unsafe fn read_next_dir_entry(dir_ptr: *mut libc::DIR) -> *mut libc::dirent {
    #[cfg(test)]
    {
        let injected = TEST_INJECT_READDIR_ERRNO.with(|c| c.replace(0));
        if injected != 0 {
            set_errno_value(injected);
            return std::ptr::null_mut();
        }
    }
    set_errno_value(0);
    libc::readdir(dir_ptr)
}

#[cfg(target_env = "gnu")]
unsafe fn set_errno_value(val: libc::c_int) {
    *libc::__errno_location() = val;
}

#[cfg(not(target_env = "gnu"))]
unsafe fn set_errno_value(val: libc::c_int) {
    *libc::__errno_location() = val;
}

fn archive_key_matches_source(source_key: &str, source: StatsSource) -> bool {
    match source {
        StatsSource::Cli => false,
        StatsSource::App => source_key.starts_with("antigravity/"),
        StatsSource::All => {
            source_key.starts_with("antigravity/") || source_key.starts_with("antigravity-cli/")
        }
    }
}

#[derive(Debug, Clone)]
struct GenerationEvent {
    model: String,
    uncached_input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
    total_tokens: u64,
    timestamp_seconds: i64,
}

#[derive(Default)]
struct ArchivedScanMeta {
    source_keys: HashSet<String>,
    valid_generation_ids_by_source: HashMap<String, HashSet<i64>>,
    valid_events_by_source: HashMap<String, HashMap<i64, GenerationEvent>>,
    /// Generations present in `archived_generations` that were NOT valid (`valid != 1` or malformed fields)
    /// for sources that also exist as live `.db` candidates (`generation_idx -> was_oversized`).
    /// Live `.db` rows are allowed to supply valid events for these without being shadowed!
    pending_invalid_by_source: HashMap<String, HashMap<i64, bool>>,
    generations_scanned: u64,
    skipped_large_records: u64,
}

#[derive(Default)]
struct DatabaseScanMeta {
    generations_scanned: u64,
    skipped_large_records: u64,
    live_generation_ids_seen: HashSet<i64>,
}

fn row_opt_utf8_string(
    row: &rusqlite::Row<'_>,
    idx: usize,
) -> Result<Option<String>, rusqlite::Error> {
    match row.get_ref(idx)? {
        rusqlite::types::ValueRef::Text(bytes) => {
            Ok(std::str::from_utf8(bytes).ok().map(str::to_owned))
        }
        _ => Ok(None),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SeenArchiveKeyState {
    Valid,
    PendingLive,
    CountedInvalid { oversized: bool },
}

#[derive(Default)]
struct IndexedArchiveCompleteMeta {
    scanned_sources: HashSet<String>,
    generations_scanned: u64,
    skipped_large_records: u64,
    unreadable_databases: u64,
}

enum ArchiveDispatchResult {
    IndexedComplete(IndexedArchiveCompleteMeta),
    UnindexedMeta(ArchivedScanMeta),
}

fn budget_exceeded_sqlite_err() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: rusqlite::ErrorCode::TooBig,
            extended_code: rusqlite::ffi::SQLITE_TOOBIG,
        },
        None,
    )
}

fn query_uses_temp_btree(conn: &Connection, sql: &str) -> Result<bool, rusqlite::Error> {
    let explain = format!("EXPLAIN QUERY PLAN {sql}");
    let mut stmt = conn.prepare(&explain)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if let Some(detail) = row_opt_utf8_string(row, 3)? {
            if detail.to_ascii_uppercase().contains("TEMP B-TREE") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn archive_has_key_index(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "EXPLAIN QUERY PLAN
         SELECT 1
         FROM archived_generations
         WHERE source_key = 'antigravity/conversations/probe.db' AND generation_idx = 1",
    )?;
    let mut rows = stmt.query([])?;
    let mut saw_index_search = false;
    while let Some(row) = rows.next()? {
        if let Some(detail) = row_opt_utf8_string(row, 3)? {
            let up = detail.to_ascii_uppercase();
            if up.contains("SCAN") {
                return Ok(false);
            }
            if up.contains("SEARCH") && up.contains("USING") {
                saw_index_search = true;
            }
        }
    }
    if !saw_index_search {
        return Ok(false);
    }
    // Also require `ORDER BY source_key, generation_idx` to stream via that index without a TEMP B-TREE!
    let order_needs_sort = query_uses_temp_btree(
        conn,
        "SELECT source_key, generation_idx FROM archived_generations ORDER BY source_key, generation_idx",
    )?;
    Ok(!order_needs_sort)
}

const ARCHIVE_ROW_SELECT_COLS: &str = "source_key,
                generation_idx,
                CASE
                    WHEN typeof(model) = 'text' AND octet_length(model) <= 4096
                    THEN model
                    ELSE NULL
                END,
                CASE
                    WHEN typeof(input_tokens) = 'integer' THEN CAST(input_tokens AS TEXT)
                    WHEN typeof(input_tokens) = 'text' AND octet_length(input_tokens) <= 32 THEN input_tokens
                    ELSE NULL
                END,
                CASE
                    WHEN typeof(output_tokens) = 'integer' THEN CAST(output_tokens AS TEXT)
                    WHEN typeof(output_tokens) = 'text' AND octet_length(output_tokens) <= 32 THEN output_tokens
                    ELSE NULL
                END,
                CASE
                    WHEN typeof(cached_tokens) = 'integer' THEN CAST(cached_tokens AS TEXT)
                    WHEN typeof(cached_tokens) = 'text' AND octet_length(cached_tokens) <= 32 THEN cached_tokens
                    ELSE NULL
                END,
                CASE WHEN typeof(timestamp_seconds) = 'integer' THEN timestamp_seconds ELSE NULL END,
                CASE WHEN typeof(valid) = 'integer' THEN valid ELSE 0 END,
                CASE WHEN typeof(oversized) = 'integer' THEN oversized ELSE 0 END";

fn decode_archive_row_fields(
    row: &rusqlite::Row<'_>,
) -> Result<(Option<GenerationEvent>, bool), rusqlite::Error> {
    let valid: i64 = row.get(7)?;
    let oversized: i64 = row.get(8)?;
    if valid != 1 {
        return Ok((None, oversized == 1));
    }
    let model_raw = row_opt_utf8_string(row, 2)?;
    let input_tokens = row_opt_utf8_string(row, 3)?;
    let output_tokens = row_opt_utf8_string(row, 4)?;
    let cached_tokens = row_opt_utf8_string(row, 5)?;
    let timestamp_seconds: Option<i64> = row.get(6)?;

    let decoded = match (
        model_raw.as_deref().map(classify_model_name),
        input_tokens.and_then(|v| v.trim().parse::<u64>().ok()),
        output_tokens.and_then(|v| v.trim().parse::<u64>().ok()),
        cached_tokens.and_then(|v| v.trim().parse::<u64>().ok()),
        timestamp_seconds.filter(|&s| s > 0),
    ) {
        (
            Some(model_cls),
            Some(uncached_input_tokens),
            Some(output_tokens),
            Some(cached_tokens),
            Some(ts_secs),
        ) if !matches!(model_cls, ModelNameClass::Absent) => {
            let model = match model_cls {
                ModelNameClass::Valid(s) => s,
                ModelNameClass::RejectedUntrusted => "Unknown".to_string(),
                ModelNameClass::Absent => unreachable!(),
            };
            uncached_input_tokens
                .checked_add(cached_tokens)
                .and_then(|sum| sum.checked_add(output_tokens))
                .and_then(|computed_total| {
                    jiff::Timestamp::from_second(ts_secs)
                        .ok()
                        .map(|_| GenerationEvent {
                            model,
                            uncached_input_tokens,
                            output_tokens,
                            cached_tokens,
                            total_tokens: computed_total,
                            timestamp_seconds: ts_secs,
                        })
                })
        }
        _ => None,
    };
    Ok((decoded, oversized == 1))
}

fn emit_archive_only_event(
    source_key: &str,
    generation_idx: i64,
    ev: GenerationEvent,
    range_spec: &StatsRangeSpec,
    tz: &jiff::tz::TimeZone,
    local_agg: &mut StatsAggregator,
) {
    local_agg.observe_timestamp(ev.timestamp_seconds);
    if let Ok(ts) = jiff::Timestamp::from_second(ev.timestamp_seconds) {
        let local_date = ts.to_zoned(tz.clone()).date();
        if range_spec.contains_date(local_date) {
            if let Some(ref mut sink) = local_agg.record_sink {
                sink.push_matching(InternalCallRecord {
                    source_key: source_key.to_string(),
                    generation_idx,
                    timestamp_seconds: ev.timestamp_seconds,
                    model: ev.model,
                    uncached_input_tokens: ev.uncached_input_tokens,
                    cached_tokens: ev.cached_tokens,
                    output_tokens: ev.output_tokens,
                    total_tokens: ev.total_tokens,
                    ttft_seconds: None,
                    duration_seconds: None,
                    output_tps: None,
                    status: StatsCallStatus::Archived,
                });
            } else {
                local_agg.record_in_range_event(ev);
            }
        }
    }
}

fn lookup_indexed_archive_event(
    point_stmt: &mut rusqlite::Statement<'_>,
    source_key: &str,
    generation_idx: i64,
) -> Result<Option<GenerationEvent>, rusqlite::Error> {
    let mut rows = point_stmt.query(rusqlite::params![source_key, generation_idx])?;
    while let Some(row) = rows.next()? {
        let (decoded, _) = decode_archive_row_fields(row)?;
        if let Some(ev) = decoded {
            return Ok(Some(ev));
        }
    }
    Ok(None)
}

/// Stream archive rows for a single `source_key` in `O(1)` memory (adjacent dedup by `generation_idx`),
/// skipping any `generation_idx` already handled by a live `.db` row!
#[allow(clippy::too_many_arguments)]
fn stream_unmatched_indexed_archive_for_source<F>(
    source_stmt: &mut rusqlite::Statement<'_>,
    source_key: &str,
    range_spec: &StatsRangeSpec,
    tz: &jiff::tz::TimeZone,
    mut live_has_gen: F,
    local_agg: &mut StatsAggregator,
    generations_scanned: &mut u64,
    skipped_large_records: &mut u64,
) -> Result<bool, rusqlite::Error>
where
    F: FnMut(i64) -> Result<bool, rusqlite::Error>,
{
    let mut saw_any_row = false;
    let mut rows = source_stmt.query([source_key])?;
    let mut cur_gid: Option<i64> = None;
    let mut cur_valid: Option<GenerationEvent> = None;
    let mut cur_invalid_oversized = false;

    let flush_group = |gid: i64,
                       valid_ev: Option<GenerationEvent>,
                       invalid_over: bool,
                       live_has_gen: &mut F,
                       local_agg: &mut StatsAggregator,
                       generations_scanned: &mut u64,
                       skipped_large_records: &mut u64|
     -> Result<(), rusqlite::Error> {
        if live_has_gen(gid)? {
            return Ok(());
        }
        *generations_scanned = generations_scanned.saturating_add(1);
        if let Some(ev) = valid_ev {
            emit_archive_only_event(source_key, gid, ev, range_spec, tz, local_agg);
        } else if invalid_over {
            *skipped_large_records = skipped_large_records.saturating_add(1);
        }
        Ok(())
    };

    while let Some(row) = rows.next()? {
        let Some(gid): Option<i64> = row.get(1)? else {
            continue;
        };
        saw_any_row = true;
        if cur_gid != Some(gid) {
            if let Some(prev_gid) = cur_gid.take() {
                flush_group(
                    prev_gid,
                    cur_valid.take(),
                    cur_invalid_oversized,
                    &mut live_has_gen,
                    local_agg,
                    generations_scanned,
                    skipped_large_records,
                )?;
            }
            cur_gid = Some(gid);
            cur_valid = None;
            cur_invalid_oversized = false;
        }
        if cur_valid.is_some() {
            continue;
        }
        let (decoded, was_over) = decode_archive_row_fields(row)?;
        if let Some(ev) = decoded {
            cur_valid = Some(ev);
        } else {
            cur_invalid_oversized = cur_invalid_oversized || was_over;
        }
    }
    if let Some(prev_gid) = cur_gid.take() {
        flush_group(
            prev_gid,
            cur_valid.take(),
            cur_invalid_oversized,
            &mut live_has_gen,
            local_agg,
            generations_scanned,
            skipped_large_records,
        )?;
    }
    Ok(saw_any_row)
}

fn scan_with_archive_connection(
    arch_pinned: &PinnedSqliteConnection,
    source_filter: StatsSource,
    range_spec: &StatsRangeSpec,
    tz: &jiff::tz::TimeZone,
    candidate_dbs: &[CandidateDb],
    live_source_keys: &HashSet<String>,
    agg: &mut StatsAggregator,
) -> Result<ArchiveDispatchResult, rusqlite::Error> {
    let tx = arch_pinned.conn().unchecked_transaction()?;
    let tables = list_sqlite_tables(&tx)?;
    if !tables.contains("archived_generations") {
        arch_pinned.verify_snapshot_consistent()?;
        return Ok(ArchiveDispatchResult::UnindexedMeta(
            ArchivedScanMeta::default(),
        ));
    }

    if archive_has_key_index(&tx)? {
        // Fast O(1)-memory indexed archive streaming path: at most 2 open SQLite DBs simultaneously
        // (1 archive + 1 live DB) and ZERO unbounded archive dedup maps or live ID sets!
        let mut local_agg = agg.spawn_local();
        let mut meta = IndexedArchiveCompleteMeta::default();

        if tables.contains("archived_sources") {
            let mut source_stmt = tx.prepare(
                "SELECT source_key
                 FROM archived_sources
                 WHERE typeof(source_key) = 'text' AND octet_length(source_key) <= 1024",
            )?;
            let mut source_rows = source_stmt.query([])?;
            while let Some(srow) = source_rows.next()? {
                if let Some(key) = row_opt_utf8_string(srow, 0)? {
                    if archive_key_matches_source(&key, source_filter) {
                        meta.scanned_sources.insert(key);
                    }
                }
            }
        }

        let point_sql = format!(
            "SELECT {ARCHIVE_ROW_SELECT_COLS}
             FROM archived_generations
             WHERE source_key = ?1 AND generation_idx = ?2"
        );
        let mut point_stmt = tx.prepare(&point_sql)?;

        let per_src_sql = format!(
            "SELECT {ARCHIVE_ROW_SELECT_COLS}
             FROM archived_generations
             WHERE source_key = ?1 AND typeof(generation_idx) = 'integer'
             ORDER BY generation_idx"
        );
        let mut per_src_stmt = tx.prepare(&per_src_sql)?;

        let mut live_seen_inodes: HashSet<(u64, u64)> = HashSet::new();
        for candidate in candidate_dbs {
            let arch_matches_filter =
                archive_key_matches_source(&candidate.source_key, source_filter);
            match scan_with_bounded_retry(
                &candidate.conv_dir_fd,
                &candidate.file_name,
                &mut live_seen_inodes,
                |live_conn| {
                    scan_database_streaming(
                        live_conn,
                        &candidate.source_key,
                        range_spec,
                        tz,
                        if arch_matches_filter {
                            ArchiveLookup::Indexed {
                                point_stmt: &mut point_stmt,
                                per_src_stmt: &mut per_src_stmt,
                            }
                        } else {
                            ArchiveLookup::None
                        },
                        false,
                        &mut local_agg,
                    )
                },
            ) {
                RetryScanOutcome::Scanned(res) => {
                    meta.scanned_sources.insert(candidate.source_key.clone());
                    meta.generations_scanned = meta
                        .generations_scanned
                        .saturating_add(res.generations_scanned);
                    meta.skipped_large_records = meta
                        .skipped_large_records
                        .saturating_add(res.skipped_large_records);
                }
                RetryScanOutcome::Unreadable => {
                    meta.unreadable_databases = meta.unreadable_databases.saturating_add(1);
                    if arch_matches_filter {
                        let saw_arch = stream_unmatched_indexed_archive_for_source(
                            &mut per_src_stmt,
                            &candidate.source_key,
                            range_spec,
                            tz,
                            |_| Ok(false),
                            &mut local_agg,
                            &mut meta.generations_scanned,
                            &mut meta.skipped_large_records,
                        )?;
                        if saw_arch {
                            meta.scanned_sources.insert(candidate.source_key.clone());
                        }
                    }
                }
                RetryScanOutcome::Absent | RetryScanOutcome::SkippedUnsafeOrDuplicate => {
                    if arch_matches_filter {
                        let saw_arch = stream_unmatched_indexed_archive_for_source(
                            &mut per_src_stmt,
                            &candidate.source_key,
                            range_spec,
                            tz,
                            |_| Ok(false),
                            &mut local_agg,
                            &mut meta.generations_scanned,
                            &mut meta.skipped_large_records,
                        )?;
                        if saw_arch {
                            meta.scanned_sources.insert(candidate.source_key.clone());
                        }
                    }
                }
            }
        }
        drop(per_src_stmt);
        drop(point_stmt);

        // Stream archive-only sources (`!live_source_keys.contains(source_key)`) in index order
        // with strictly O(1) adjacent key deduplication!
        let all_sql = format!(
            "SELECT {ARCHIVE_ROW_SELECT_COLS}
             FROM archived_generations
             WHERE typeof(source_key) = 'text'
               AND octet_length(source_key) <= 1024
               AND typeof(generation_idx) = 'integer'
             ORDER BY source_key, generation_idx"
        );
        let mut all_stmt = tx.prepare(&all_sql)?;
        let mut rows = all_stmt.query([])?;
        let mut cur_key: Option<(String, i64)> = None;
        let mut cur_valid: Option<GenerationEvent> = None;
        let mut cur_invalid_over = false;

        let flush_arch_only =
            |key: (String, i64),
             valid_ev: Option<GenerationEvent>,
             invalid_over: bool,
             local_agg: &mut StatsAggregator,
             meta: &mut IndexedArchiveCompleteMeta| {
                let (src_key, gid) = key;
                meta.scanned_sources.insert(src_key.clone());
                meta.generations_scanned = meta.generations_scanned.saturating_add(1);
                if let Some(ev) = valid_ev {
                    emit_archive_only_event(&src_key, gid, ev, range_spec, tz, local_agg);
                } else if invalid_over {
                    meta.skipped_large_records = meta.skipped_large_records.saturating_add(1);
                }
            };

        while let Some(row) = rows.next()? {
            let Some(source_key) = row_opt_utf8_string(row, 0)? else {
                continue;
            };
            if !archive_key_matches_source(&source_key, source_filter)
                || live_source_keys.contains(&source_key)
            {
                continue;
            }
            let Some(gid): Option<i64> = row.get(1)? else {
                continue;
            };
            let is_same = cur_key
                .as_ref()
                .is_some_and(|(s, g)| s == &source_key && *g == gid);
            if !is_same {
                if let Some(prev) = cur_key.take() {
                    flush_arch_only(
                        prev,
                        cur_valid.take(),
                        cur_invalid_over,
                        &mut local_agg,
                        &mut meta,
                    );
                }
                cur_key = Some((source_key, gid));
                cur_valid = None;
                cur_invalid_over = false;
            }
            if cur_valid.is_some() {
                continue;
            }
            let (decoded, was_over) = decode_archive_row_fields(row)?;
            if let Some(ev) = decoded {
                cur_valid = Some(ev);
            } else {
                cur_invalid_over = cur_invalid_over || was_over;
            }
        }
        if let Some(prev) = cur_key.take() {
            flush_arch_only(
                prev,
                cur_valid.take(),
                cur_invalid_over,
                &mut local_agg,
                &mut meta,
            );
        }

        drop(rows);
        drop(all_stmt);
        arch_pinned.verify_snapshot_consistent()?;
        drop(tx);
        merge_aggregator_into(agg, local_agg);
        return Ok(ArchiveDispatchResult::IndexedComplete(meta));
    }

    // Fallback for abnormal/unindexed `archived_generations` schema: enforce explicit bounded row
    // budget (`effective_unindexed_row_budget`) and never retain out-of-window events in memory!
    drop(tx);
    let meta = scan_unindexed_archive_budgeted(
        arch_pinned,
        source_filter,
        range_spec,
        tz,
        live_source_keys,
        agg,
    )?;
    Ok(ArchiveDispatchResult::UnindexedMeta(meta))
}

fn scan_unindexed_archive_budgeted(
    pinned: &PinnedSqliteConnection,
    source_filter: StatsSource,
    range_spec: &StatsRangeSpec,
    tz: &jiff::tz::TimeZone,
    live_source_keys: &HashSet<String>,
    agg: &mut StatsAggregator,
) -> Result<ArchivedScanMeta, rusqlite::Error> {
    let row_budget = effective_unindexed_row_budget();
    let mut local_agg = agg.spawn_local();
    let tx = pinned.conn().unchecked_transaction()?;

    let tables = list_sqlite_tables(&tx)?;
    if !tables.contains("archived_generations") {
        pinned.verify_snapshot_consistent()?;
        return Ok(ArchivedScanMeta::default());
    }

    let mut result = ArchivedScanMeta::default();
    if tables.contains("archived_sources") {
        let mut source_stmt = tx.prepare(
            "SELECT source_key
             FROM archived_sources
             WHERE typeof(source_key) = 'text' AND octet_length(source_key) <= 1024",
        )?;
        let mut source_rows = source_stmt.query([])?;
        while let Some(srow) = source_rows.next()? {
            if let Some(key) = row_opt_utf8_string(srow, 0)? {
                if archive_key_matches_source(&key, source_filter) {
                    result.source_keys.insert(key);
                }
            }
        }
    }

    let sql = format!(
        "SELECT {ARCHIVE_ROW_SELECT_COLS}
         FROM archived_generations
         WHERE typeof(source_key) = 'text'
           AND octet_length(source_key) <= 1024
           AND typeof(generation_idx) = 'integer'"
    );
    let mut stmt = tx.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut seen_archive_keys: HashMap<(String, i64), SeenArchiveKeyState> = HashMap::new();
    let mut rows_inspected = 0usize;

    while let Some(row) = rows.next()? {
        rows_inspected = rows_inspected.saturating_add(1);
        if rows_inspected > row_budget {
            return Err(budget_exceeded_sqlite_err());
        }
        let Some(source_key) = row_opt_utf8_string(row, 0)? else {
            continue;
        };
        if !archive_key_matches_source(&source_key, source_filter) {
            continue;
        }
        let Some(generation_idx): Option<i64> = row.get(1)? else {
            continue;
        };
        let key_tuple = (source_key.clone(), generation_idx);
        if seen_archive_keys.get(&key_tuple) == Some(&SeenArchiveKeyState::Valid) {
            continue;
        }
        if !seen_archive_keys.contains_key(&key_tuple) && seen_archive_keys.len() >= row_budget {
            return Err(budget_exceeded_sqlite_err());
        }

        result.source_keys.insert(source_key.clone());

        let (decoded_archive_ev, was_oversized) = decode_archive_row_fields(row)?;

        if let Some(ev) = decoded_archive_ev {
            match seen_archive_keys.insert(key_tuple, SeenArchiveKeyState::Valid) {
                Some(SeenArchiveKeyState::PendingLive) => {
                    if let Some(map) = result.pending_invalid_by_source.get_mut(&source_key) {
                        map.remove(&generation_idx);
                    }
                }
                Some(SeenArchiveKeyState::CountedInvalid {
                    oversized: prev_over,
                }) => {
                    result.generations_scanned = result.generations_scanned.saturating_sub(1);
                    if prev_over {
                        result.skipped_large_records =
                            result.skipped_large_records.saturating_sub(1);
                    }
                }
                Some(SeenArchiveKeyState::Valid) | None => {}
            }
            if live_source_keys.contains(&source_key) {
                result
                    .valid_generation_ids_by_source
                    .entry(source_key.clone())
                    .or_default()
                    .insert(generation_idx);
            }
            result.generations_scanned = result.generations_scanned.saturating_add(1);
            local_agg.observe_timestamp(ev.timestamp_seconds);
            let ts = jiff::Timestamp::from_second(ev.timestamp_seconds).unwrap();
            let local_date = ts.to_zoned(tz.clone()).date();
            let in_window = range_spec.contains_date(local_date);
            if local_agg.record_sink.is_some() {
                if in_window {
                    if live_source_keys.contains(&source_key) {
                        result
                            .valid_events_by_source
                            .entry(source_key)
                            .or_default()
                            .insert(generation_idx, ev);
                    } else if let Some(ref mut sink) = local_agg.record_sink {
                        sink.push_matching(InternalCallRecord {
                            source_key,
                            generation_idx,
                            timestamp_seconds: ev.timestamp_seconds,
                            model: ev.model,
                            uncached_input_tokens: ev.uncached_input_tokens,
                            cached_tokens: ev.cached_tokens,
                            output_tokens: ev.output_tokens,
                            total_tokens: ev.total_tokens,
                            ttft_seconds: None,
                            duration_seconds: None,
                            output_tps: None,
                            status: StatsCallStatus::Archived,
                        });
                    }
                }
            } else if in_window {
                // Record tokens in summary immediately; if a live `.db` also exists for this source,
                // retain ONLY in-window `ev` so `scan_database_streaming` enriches live TPS under the
                // exact same archived timestamp & model!
                if live_source_keys.contains(&source_key) {
                    result
                        .valid_events_by_source
                        .entry(source_key)
                        .or_default()
                        .insert(generation_idx, ev.clone());
                }
                local_agg.record_in_range_event(ev);
            }
        } else if let std::collections::hash_map::Entry::Vacant(vacant) =
            seen_archive_keys.entry(key_tuple)
        {
            if live_source_keys.contains(&source_key) {
                vacant.insert(SeenArchiveKeyState::PendingLive);
                result
                    .pending_invalid_by_source
                    .entry(source_key)
                    .or_default()
                    .insert(generation_idx, was_oversized);
            } else {
                vacant.insert(SeenArchiveKeyState::CountedInvalid {
                    oversized: was_oversized,
                });
                result.generations_scanned = result.generations_scanned.saturating_add(1);
                if was_oversized {
                    result.skipped_large_records = result.skipped_large_records.saturating_add(1);
                }
            }
        }
    }

    drop(rows);
    drop(stmt);
    pinned.verify_snapshot_consistent()?;
    drop(tx);

    merge_aggregator_into(agg, local_agg);
    Ok(result)
}

fn merge_aggregator_into(dst: &mut StatsAggregator, src: StatsAggregator) {
    if let Some(la) = src.last_activity {
        dst.observe_timestamp(la);
    }
    if let Some(rfa) = src.range_first_activity {
        dst.range_first_activity = Some(dst.range_first_activity.map_or(rfa, |c| c.min(rfa)));
    }
    if let Some(rla) = src.range_last_activity {
        dst.range_last_activity = Some(dst.range_last_activity.map_or(rla, |c| c.max(rla)));
    }
    dst.uncached_input = dst.uncached_input.saturating_add(src.uncached_input);
    dst.cached_input = dst.cached_input.saturating_add(src.cached_input);
    dst.total_output = dst.total_output.saturating_add(src.total_output);
    dst.request_count = dst.request_count.saturating_add(src.request_count);
    for (model, m) in src.by_model {
        let e = dst.by_model.entry(model).or_default();
        e.request_count = e.request_count.saturating_add(m.request_count);
        e.uncached_input_tokens = e
            .uncached_input_tokens
            .saturating_add(m.uncached_input_tokens);
        e.cached_input_tokens = e.cached_input_tokens.saturating_add(m.cached_input_tokens);
        e.output_tokens = e.output_tokens.saturating_add(m.output_tokens);
        e.total_tokens = e.total_tokens.saturating_add(m.total_tokens);
    }
    dst.perf_ttft_samples.extend(src.perf_ttft_samples);
    dst.perf_tps_samples.extend(src.perf_tps_samples);
    dst.perf_models.extend(src.perf_models);
    dst.perf_sources.extend(src.perf_sources);
    if let (Some(dst_sink), Some(src_sink)) = (&mut dst.record_sink, src.record_sink) {
        dst_sink.merge_from(src_sink);
    }
}

fn list_sqlite_tables(connection: &Connection) -> Result<HashSet<String>, rusqlite::Error> {
    let mut stmt = connection.prepare(
        "SELECT name
         FROM sqlite_master
         WHERE type = 'table' AND typeof(name) = 'text' AND octet_length(name) <= 256",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = HashSet::new();
    while let Some(row) = rows.next()? {
        if let Some(n) = row_opt_utf8_string(row, 0)? {
            out.insert(n);
        }
    }
    Ok(out)
}

enum ArchiveLookup<'a, 'tx> {
    None,
    Indexed {
        point_stmt: &'a mut rusqlite::Statement<'tx>,
        per_src_stmt: &'a mut rusqlite::Statement<'tx>,
    },
    Unindexed {
        valid_archived_ids: Option<&'a HashSet<i64>>,
        valid_archived_events: Option<&'a HashMap<i64, GenerationEvent>>,
        pending_invalid_ids: Option<&'a HashMap<i64, bool>>,
    },
}

fn decode_step_row(row: &rusqlite::Row<'_>) -> Result<StepGenInfo, rusqlite::Error> {
    let metadata: Option<Vec<u8>> = row.get(0)?;
    let status_kind: i64 = row.get(1)?;
    let status_val: Option<i64> = row.get(2)?;
    let payload_kind: i64 = row.get(3)?;
    let payload: Option<Vec<u8>> = row.get(4)?;

    let status = match (status_kind, status_val) {
        (0, _) => StepStatusValue::Absent,
        (1, Some(v)) => StepStatusValue::Known(v),
        _ => StepStatusValue::InvalidType,
    };
    let payload_state = match (payload_kind, payload.as_deref()) {
        (0, _) => StepPayloadState::Absent,
        (1, Some(p)) if is_valid_step_payload_framing(p) => StepPayloadState::Valid,
        _ => StepPayloadState::Invalid,
    };
    Ok(StepGenInfo {
        timestamp: metadata.as_deref().and_then(step_timestamp),
        status,
        payload_state,
    })
}

fn build_step_select_exprs(step_columns: &HashSet<String>) -> Option<String> {
    if !step_columns.contains("idx") || !step_columns.contains("step_type") {
        return None;
    }
    let has_meta = step_columns.contains("metadata");
    let has_status = step_columns.contains("status");
    let has_payload = step_columns.contains("step_payload");
    if !has_meta && !has_status && !has_payload {
        return None;
    }
    let meta_expr = if has_meta {
        "CASE WHEN typeof(metadata) = 'blob' AND octet_length(metadata) <= 65536 THEN metadata ELSE NULL END"
    } else {
        "NULL"
    };
    let status_kind_expr = if has_status {
        "CASE WHEN status IS NULL THEN 0 WHEN typeof(status) = 'integer' THEN 1 ELSE 2 END"
    } else {
        "0"
    };
    let status_val_expr = if has_status {
        "CASE WHEN typeof(status) = 'integer' THEN status ELSE NULL END"
    } else {
        "NULL"
    };
    let payload_kind_expr = if has_payload {
        "CASE WHEN step_payload IS NULL THEN 0 WHEN typeof(step_payload) = 'blob' AND octet_length(step_payload) <= 1048576 THEN 1 ELSE 2 END"
    } else {
        "0"
    };
    let payload_blob_expr = if has_payload {
        "CASE WHEN typeof(step_payload) = 'blob' AND octet_length(step_payload) <= 1048576 THEN step_payload ELSE NULL END"
    } else {
        "NULL"
    };
    Some(format!(
        "{meta_expr}, {status_kind_expr}, {status_val_expr}, {payload_kind_expr}, {payload_blob_expr}"
    ))
}

fn scan_database_streaming(
    pinned: &PinnedSqliteConnection,
    source_key: &str,
    range_spec: &StatsRangeSpec,
    tz: &jiff::tz::TimeZone,
    mut archive_lookup: ArchiveLookup<'_, '_>,
    track_live_ids: bool,
    agg: &mut StatsAggregator,
) -> Result<DatabaseScanMeta, rusqlite::Error> {
    let row_budget = effective_unindexed_row_budget();
    let mut local_agg = agg.spawn_local();
    // Hold a single consistent read transaction across `sqlite_master`, `steps`, and `gen_metadata`!
    let tx = pinned.conn().unchecked_transaction()?;

    let tables = list_sqlite_tables(&tx)?;
    if !tables.contains("gen_metadata") {
        let mut result = DatabaseScanMeta::default();
        if let ArchiveLookup::Indexed { per_src_stmt, .. } = &mut archive_lookup {
            let _ = stream_unmatched_indexed_archive_for_source(
                per_src_stmt,
                source_key,
                range_spec,
                tz,
                |_| Ok(false),
                &mut local_agg,
                &mut result.generations_scanned,
                &mut result.skipped_large_records,
            )?;
        }
        pinned.verify_snapshot_consistent()?;
        drop(tx);
        merge_aggregator_into(agg, local_agg);
        return Ok(result);
    }

    // 1. Inspect `steps` schema & prepare either a zero-allocation streaming cursor (indexed `idx`)
    //    or a rowid-only sorted index under `row_budget` (NEVER sorting BLOBs in SQLite temp memory!).
    let step_select_opt = if tables.contains("steps") {
        let mut cols_stmt = tx.prepare("SELECT name FROM pragma_table_info('steps')")?;
        let mut col_rows = cols_stmt.query([])?;
        let mut step_columns = HashSet::new();
        while let Some(crow) = col_rows.next()? {
            if let Some(cname) = row_opt_utf8_string(crow, 0)? {
                step_columns.insert(cname);
            }
        }
        drop(col_rows);
        drop(cols_stmt);
        build_step_select_exprs(&step_columns)
    } else {
        None
    };

    let (step_uses_temp_sort, step_rowids) = if step_select_opt.is_some() {
        let needs_sort = query_uses_temp_btree(
            &tx,
            "SELECT idx FROM steps WHERE step_type = 15 AND typeof(idx) = 'integer' ORDER BY idx",
        )?;
        if needs_sort {
            let mut id_stmt = tx.prepare(
                "SELECT rowid FROM steps WHERE step_type = ?1 AND typeof(idx) = 'integer' ORDER BY idx LIMIT ?2",
            )?;
            let mut id_rows = id_stmt.query(rusqlite::params![
                GENERATION_STEP_TYPE,
                (row_budget + 1) as i64
            ])?;
            let mut rids = Vec::new();
            while let Some(r) = id_rows.next()? {
                rids.push(r.get::<_, i64>(0)?);
                if rids.len() > row_budget {
                    return Err(budget_exceeded_sqlite_err());
                }
            }
            (true, Some(rids))
        } else {
            (false, None)
        }
    } else {
        (false, None)
    };

    let mut step_stream_stmt = if !step_uses_temp_sort {
        if let Some(ref exprs) = step_select_opt {
            Some(tx.prepare(&format!(
                "SELECT {exprs} FROM steps WHERE step_type = ?1 AND typeof(idx) = 'integer' ORDER BY idx"
            ))?)
        } else {
            None
        }
    } else {
        None
    };
    let mut step_stream_rows = match step_stream_stmt.as_mut() {
        Some(st) => Some(st.query([GENERATION_STEP_TYPE])?),
        None => None,
    };
    let mut step_by_rowid_stmt = if step_uses_temp_sort {
        if let Some(ref exprs) = step_select_opt {
            Some(tx.prepare(&format!("SELECT {exprs} FROM steps WHERE rowid = ?1"))?)
        } else {
            None
        }
    } else {
        None
    };
    let mut step_rowid_pos = 0usize;

    let mut next_step_info = || -> Result<StepGenInfo, rusqlite::Error> {
        if let Some(ref mut rows) = step_stream_rows {
            return match rows.next()? {
                Some(row) => decode_step_row(row),
                None => Ok(StepGenInfo::default()),
            };
        }
        if let (Some(ref rids), Some(ref mut stmt)) = (&step_rowids, step_by_rowid_stmt.as_mut()) {
            if let Some(&rid) = rids.get(step_rowid_pos) {
                step_rowid_pos += 1;
                let mut rows = stmt.query([rid])?;
                return match rows.next()? {
                    Some(row) => decode_step_row(row),
                    None => Ok(StepGenInfo::default()),
                };
            }
        }
        Ok(StepGenInfo::default())
    };

    // 2. Inspect `gen_metadata` query plan: stream directly when indexed, or sort ONLY `(rowid, idx)`
    //    under `row_budget` and fetch each BLOB individually by `rowid` when unindexed!
    let gen_needs_sort = query_uses_temp_btree(
        &tx,
        "SELECT idx FROM gen_metadata WHERE typeof(idx) = 'integer' ORDER BY idx",
    )?;
    let unindexed_gen_rowids: Option<Vec<(i64, i64)>> = if gen_needs_sort {
        let mut id_stmt = tx.prepare(
            "SELECT rowid, idx FROM gen_metadata WHERE typeof(idx) = 'integer' ORDER BY idx LIMIT ?1",
        )?;
        let mut id_rows = id_stmt.query([(row_budget + 1) as i64])?;
        let mut pairs = Vec::new();
        while let Some(r) = id_rows.next()? {
            pairs.push((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?));
            if pairs.len() > row_budget {
                return Err(budget_exceeded_sqlite_err());
            }
        }
        Some(pairs)
    } else {
        None
    };

    let mut result = DatabaseScanMeta::default();
    let mut unindexed_non_null_live_ids: Option<HashSet<i64>> = (gen_needs_sort
        && matches!(archive_lookup, ArchiveLookup::Indexed { .. }))
    .then(HashSet::new);
    let mut last_archived_emitted_gid: Option<i64> = None;

    let mut process_row = |generation_idx: i64,
                           blob_opt: Option<Vec<u8>>,
                           blob_size_opt: Option<i64>,
                           step_info: StepGenInfo,
                           archive_lookup: &mut ArchiveLookup<'_, '_>|
     -> Result<(), rusqlite::Error> {
        let Some(blob_size) = blob_size_opt else {
            // `data IS NULL`: ordinal slot was preserved by advancing `next_step_info()`; skip null payload.
            return Ok(());
        };
        if track_live_ids {
            let needed_for_unindexed_reconcile = match archive_lookup {
                ArchiveLookup::Unindexed {
                    valid_archived_events,
                    pending_invalid_ids,
                    ..
                } => {
                    valid_archived_events.is_some_and(|m| m.contains_key(&generation_idx))
                        || pending_invalid_ids.is_some_and(|m| m.contains_key(&generation_idx))
                }
                _ => false,
            };
            if needed_for_unindexed_reconcile {
                result.live_generation_ids_seen.insert(generation_idx);
            }
        }
        if let Some(ref mut set) = unindexed_non_null_live_ids {
            set.insert(generation_idx);
        }

        let live_blob_ref = if blob_size <= MAX_GENERATION_BLOB_BYTES {
            blob_opt.as_deref()
        } else {
            None
        };

        // Check archive status for `(source_key, generation_idx)`
        enum RowArchiveMatch {
            NotArchived,
            IndexedValid(GenerationEvent),
            UnindexedValid(Option<GenerationEvent>),
        }
        let arch_match = match archive_lookup {
            ArchiveLookup::None => RowArchiveMatch::NotArchived,
            ArchiveLookup::Indexed { point_stmt, .. } => {
                match lookup_indexed_archive_event(point_stmt, source_key, generation_idx)? {
                    Some(ev) => RowArchiveMatch::IndexedValid(ev),
                    None => RowArchiveMatch::NotArchived,
                }
            }
            ArchiveLookup::Unindexed {
                valid_archived_ids,
                valid_archived_events,
                ..
            } => {
                if valid_archived_ids.is_some_and(|set| set.contains(&generation_idx)) {
                    RowArchiveMatch::UnindexedValid(
                        valid_archived_events
                            .and_then(|m| m.get(&generation_idx))
                            .cloned(),
                    )
                } else {
                    RowArchiveMatch::NotArchived
                }
            }
        };

        match arch_match {
            RowArchiveMatch::IndexedValid(arch_ev) => {
                // Prevent duplicate emission if an unindexed `gen_metadata` table repeats `idx`!
                if last_archived_emitted_gid == Some(generation_idx) {
                    return Ok(());
                }
                last_archived_emitted_gid = Some(generation_idx);
                result.generations_scanned = result.generations_scanned.saturating_add(1);
                local_agg.observe_timestamp(arch_ev.timestamp_seconds);
                if let Some(rec) = decode_live_record(
                    source_key,
                    generation_idx,
                    live_blob_ref,
                    step_info,
                    Some(&arch_ev),
                ) {
                    let ts = jiff::Timestamp::from_second(rec.timestamp_seconds).unwrap();
                    let d = ts.to_zoned(tz.clone()).date();
                    if range_spec.contains_date(d) {
                        if let Some(ref mut sink) = local_agg.record_sink {
                            sink.push_matching(rec);
                        } else {
                            if let (Some(ttft), Some(tps)) = (rec.ttft_seconds, rec.output_tps) {
                                local_agg.record_perf_sample(
                                    PerfSample {
                                        model: rec.model.clone(),
                                        timestamp_seconds: rec.timestamp_seconds,
                                        ttft_seconds: ttft,
                                        output_tps: tps,
                                    },
                                    source_key,
                                );
                            }
                            local_agg.record_in_range_event(arch_ev);
                        }
                    }
                }
            }
            RowArchiveMatch::UnindexedValid(arch_ev_opt) => {
                if last_archived_emitted_gid == Some(generation_idx) {
                    return Ok(());
                }
                last_archived_emitted_gid = Some(generation_idx);
                // Tokens & `generations_scanned` were already accounted for in `scan_unindexed_archive_budgeted`.
                // Only in-window archived rows are retained in `arch_ev_opt`.
                if let Some(arch_ev) = arch_ev_opt {
                    if let Some(rec) = decode_live_record(
                        source_key,
                        generation_idx,
                        live_blob_ref,
                        step_info,
                        Some(&arch_ev),
                    ) {
                        let ts = jiff::Timestamp::from_second(rec.timestamp_seconds).unwrap();
                        let d = ts.to_zoned(tz.clone()).date();
                        if range_spec.contains_date(d) {
                            if let Some(ref mut sink) = local_agg.record_sink {
                                sink.push_matching(rec);
                            } else if let (Some(ttft), Some(tps)) =
                                (rec.ttft_seconds, rec.output_tps)
                            {
                                local_agg.record_perf_sample(
                                    PerfSample {
                                        model: rec.model,
                                        timestamp_seconds: rec.timestamp_seconds,
                                        ttft_seconds: ttft,
                                        output_tps: tps,
                                    },
                                    source_key,
                                );
                            }
                        }
                    }
                }
            }
            RowArchiveMatch::NotArchived => {
                result.generations_scanned = result.generations_scanned.saturating_add(1);
                if blob_size > MAX_GENERATION_BLOB_BYTES {
                    result.skipped_large_records = result.skipped_large_records.saturating_add(1);
                    return Ok(());
                }
                let Some(blob) = live_blob_ref else {
                    return Ok(());
                };
                let Some(rec) =
                    decode_live_record(source_key, generation_idx, Some(blob), step_info, None)
                else {
                    return Ok(());
                };
                local_agg.observe_timestamp(rec.timestamp_seconds);
                let ts = jiff::Timestamp::from_second(rec.timestamp_seconds).unwrap();
                let d = ts.to_zoned(tz.clone()).date();
                if range_spec.contains_date(d) {
                    if let Some(ref mut sink) = local_agg.record_sink {
                        sink.push_matching(rec);
                    } else {
                        if let (Some(ttft), Some(tps)) = (rec.ttft_seconds, rec.output_tps) {
                            local_agg.record_perf_sample(
                                PerfSample {
                                    model: rec.model.clone(),
                                    timestamp_seconds: rec.timestamp_seconds,
                                    ttft_seconds: ttft,
                                    output_tps: tps,
                                },
                                source_key,
                            );
                        }
                        local_agg.record_in_range_event(GenerationEvent {
                            model: rec.model,
                            uncached_input_tokens: rec.uncached_input_tokens,
                            output_tokens: rec.output_tokens,
                            cached_tokens: rec.cached_tokens,
                            total_tokens: rec.total_tokens,
                            timestamp_seconds: rec.timestamp_seconds,
                        });
                    }
                }
            }
        }
        Ok(())
    };

    if let Some(pairs) = unindexed_gen_rowids {
        let mut by_rid = tx.prepare(
            "SELECT CASE
                        WHEN typeof(data) = 'blob' AND octet_length(data) <= ?1
                        THEN data
                        ELSE NULL
                    END,
                    octet_length(data)
             FROM gen_metadata
             WHERE rowid = ?2",
        )?;
        for (rid, generation_idx) in pairs {
            let step_info = next_step_info()?;
            let mut r = by_rid.query(rusqlite::params![MAX_GENERATION_BLOB_BYTES, rid])?;
            let Some(row) = r.next()? else {
                continue;
            };
            let blob_size: Option<i64> = row.get(1)?;
            let blob_opt: Option<Vec<u8>> = if blob_size.is_some() {
                row.get(0)?
            } else {
                None
            };
            drop(r);
            process_row(
                generation_idx,
                blob_opt,
                blob_size,
                step_info,
                &mut archive_lookup,
            )?;
        }
    } else {
        let mut stmt = tx.prepare(
            "SELECT idx,
                    CASE
                        WHEN typeof(data) = 'blob' AND octet_length(data) <= ?1
                        THEN data
                        ELSE NULL
                    END,
                    octet_length(data)
             FROM gen_metadata
             WHERE typeof(idx) = 'integer'
             ORDER BY idx",
        )?;
        let mut rows = stmt.query([MAX_GENERATION_BLOB_BYTES])?;
        while let Some(row) = rows.next()? {
            let step_info = next_step_info()?;
            let Some(generation_idx): Option<i64> = row.get(0)? else {
                continue;
            };
            let blob_size: Option<i64> = row.get(2)?;
            let blob_opt: Option<Vec<u8>> = if blob_size.is_some() {
                row.get(1)?
            } else {
                None
            };
            process_row(
                generation_idx,
                blob_opt,
                blob_size,
                step_info,
                &mut archive_lookup,
            )?;
        }
    }

    drop(step_stream_rows);
    drop(step_stream_stmt);
    drop(step_by_rowid_stmt);

    // For indexed archives, stream any archived rows belonging to THIS `source_key` that were NOT
    // present (with non-NULL `data`) in this live `.db`!
    if let ArchiveLookup::Indexed { per_src_stmt, .. } = &mut archive_lookup {
        if let Some(ref seen_set) = unindexed_non_null_live_ids {
            let _ = stream_unmatched_indexed_archive_for_source(
                per_src_stmt,
                source_key,
                range_spec,
                tz,
                |gid| Ok(seen_set.contains(&gid)),
                &mut local_agg,
                &mut result.generations_scanned,
                &mut result.skipped_large_records,
            )?;
        } else {
            let mut live_exists_stmt = tx.prepare(
                "SELECT 1 FROM gen_metadata WHERE idx = ?1 AND data IS NOT NULL LIMIT 1",
            )?;
            let _ = stream_unmatched_indexed_archive_for_source(
                per_src_stmt,
                source_key,
                range_spec,
                tz,
                |gid| {
                    let mut r = live_exists_stmt.query([gid])?;
                    Ok(r.next()?.is_some())
                },
                &mut local_agg,
                &mut result.generations_scanned,
                &mut result.skipped_large_records,
            )?;
        }
    }

    pinned.verify_snapshot_consistent()?;
    drop(tx);

    merge_aggregator_into(agg, local_agg);
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
enum WireValue<'a> {
    Varint(u64),
    Fixed,
    Bytes(&'a [u8]),
}

#[derive(Debug, Clone, Copy)]
struct WireError;

fn decode_varint(bytes: &[u8], offset: usize) -> Result<(u64, usize), WireError> {
    if offset >= bytes.len() {
        return Err(WireError);
    }
    let mut value = 0_u64;
    for byte_index in 0..10 {
        let pos = offset.checked_add(byte_index).ok_or(WireError)?;
        let byte = *bytes.get(pos).ok_or(WireError)?;
        let payload = u64::from(byte & 0x7f);
        if byte_index == 9 && payload > 1 {
            return Err(WireError);
        }
        value |= payload << (byte_index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, pos + 1));
        }
    }
    Err(WireError)
}

/// Walk the entire Protobuf message buffer validating wire framing AND the 29-bit Protobuf
/// field-number bound (`1..=536_870_911`) so malformed bytes or out-of-range tags fail closed.
fn visit_wire_fields<'a, F>(bytes: &'a [u8], mut on_field: F) -> Result<(), WireError>
where
    F: FnMut(u32, WireValue<'a>) -> Result<(), WireError>,
{
    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_end) = decode_varint(bytes, offset)?;
        let raw_number = tag >> 3;
        if raw_number == 0 || raw_number > MAX_PROTOBUF_FIELD_NUMBER {
            return Err(WireError);
        }
        let number = raw_number as u32;
        match tag & 0x7 {
            0 => {
                let (value, value_end) = decode_varint(bytes, tag_end)?;
                on_field(number, WireValue::Varint(value))?;
                offset = value_end;
            }
            1 | 5 => {
                let width = if tag & 0x7 == 1 { 8 } else { 4 };
                let end = tag_end.checked_add(width).ok_or(WireError)?;
                if end > bytes.len() {
                    return Err(WireError);
                }
                on_field(number, WireValue::Fixed)?;
                offset = end;
            }
            2 => {
                let (length, length_end) = decode_varint(bytes, tag_end)?;
                let length = usize::try_from(length).map_err(|_| WireError)?;
                let end = length_end.checked_add(length).ok_or(WireError)?;
                if end > bytes.len() {
                    return Err(WireError);
                }
                on_field(number, WireValue::Bytes(&bytes[length_end..end]))?;
                offset = end;
            }
            _ => return Err(WireError),
        }
    }
    Ok(())
}

fn validate_wire_framing(bytes: &[u8]) -> Result<(), WireError> {
    visit_wire_fields(bytes, |_, _| Ok(()))
}

/// Canonical Protobuf embedded-message reader:
/// - Validates EACH submessage occurrence's own wire framing independently BEFORE concatenating,
///   so two half-broken fragments can NEVER synthesize a valid frame across their boundary;
/// - Distinguishes absent field (`Ok(None)`) from corrupt wire data (`Err(WireError)`).
fn merged_message_field<'a>(
    requested: u32,
    bytes: &'a [u8],
) -> Result<Option<Cow<'a, [u8]>>, WireError> {
    let mut first: Option<&'a [u8]> = None;
    let mut merged: Option<Vec<u8>> = None;
    visit_wire_fields(bytes, |num, val| {
        if num == requested {
            let WireValue::Bytes(slice) = val else {
                return Err(WireError);
            };
            validate_wire_framing(slice)?;
            if let Some(ref mut buf) = merged {
                buf.extend_from_slice(slice);
            } else if let Some(prev) = first.take() {
                let mut buf = Vec::with_capacity(prev.len().saturating_add(slice.len()));
                buf.extend_from_slice(prev);
                buf.extend_from_slice(slice);
                merged = Some(buf);
            } else {
                first = Some(slice);
            }
        }
        Ok(())
    })?;
    if let Some(buf) = merged {
        Ok(Some(Cow::Owned(buf)))
    } else {
        Ok(first.map(Cow::Borrowed))
    }
}

/// Canonical Protobuf non-repeated varint reader (Last-One-Wins; separates `Ok(None)` missing from `Err` corrupt).
fn varint_field(requested: u32, bytes: &[u8]) -> Result<Option<u64>, WireError> {
    let mut last: Option<u64> = None;
    visit_wire_fields(bytes, |num, val| {
        if num == requested {
            let WireValue::Varint(v) = val else {
                return Err(WireError);
            };
            last = Some(v);
        }
        Ok(())
    })?;
    Ok(last)
}

/// Canonical Protobuf non-repeated UTF-8 string reader (Last-One-Wins; separates `Ok(None)` missing from `Err` corrupt).
fn string_field(requested: u32, bytes: &[u8]) -> Result<Option<String>, WireError> {
    let mut last: Option<&str> = None;
    visit_wire_fields(bytes, |num, val| {
        if num == requested {
            let WireValue::Bytes(raw) = val else {
                return Err(WireError);
            };
            let s = std::str::from_utf8(raw).map_err(|_| WireError)?;
            last = Some(s);
        }
        Ok(())
    })?;
    let Some(s) = last else {
        return Ok(None);
    };
    let trimmed = s.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ModelNameClass {
    Absent,
    Valid(String),
    RejectedUntrusted,
}

fn is_model_version_or_size_token(tok: &str) -> bool {
    let b = tok.as_bytes();
    if b.is_empty() || b.len() > 10 {
        return false;
    }
    // Pure integer version or date stamp (`3`, `4`, `001`, `20250219`)
    if b.len() <= 8 && b.iter().all(u8::is_ascii_digit) {
        return true;
    }
    // Major.Minor version (`2.5`, `3.8`, `4.6`)
    if let Some((left, right)) = tok.split_once('.') {
        return !left.is_empty()
            && left.len() <= 3
            && !right.is_empty()
            && right.len() <= 3
            && left.bytes().all(|c| c.is_ascii_digit())
            && right.bytes().all(|c| c.is_ascii_digit());
    }
    // Parameter/context size or short suffix (`120b`, `70b`, `4o`, `1m`, `200k`, `8x`)
    if b.len() >= 2
        && b.len() <= 5
        && b[..b.len() - 1].iter().all(u8::is_ascii_digit)
        && matches!(
            b[b.len() - 1].to_ascii_lowercase(),
            b'b' | b'k' | b'm' | b'o' | b'x'
        )
    {
        return true;
    }
    // Prefixed version/slot (`v1`, `v2.5`, `r1`, `m18`, `g1`)
    if b.len() >= 2
        && matches!(b[0].to_ascii_lowercase(), b'v' | b'r' | b'm' | b'g')
        && (b[1..].iter().all(u8::is_ascii_digit)
            || tok[1..].split_once('.').is_some_and(|(l, r)| {
                !l.is_empty()
                    && l.len() <= 3
                    && !r.is_empty()
                    && r.len() <= 3
                    && l.bytes().all(|c| c.is_ascii_digit())
                    && r.bytes().all(|c| c.is_ascii_digit())
            }))
    {
        return true;
    }
    false
}

fn is_known_public_model_family(lower: &str) -> bool {
    matches!(
        lower,
        "gemini"
            | "claude"
            | "gpt"
            | "gemma"
            | "deepseek"
            | "qwen"
            | "llama"
            | "mistral"
            | "grok"
            | "o1"
            | "o3"
            | "o4"
    )
}

fn is_known_public_model_variant_token(lower: &str) -> bool {
    is_model_version_or_size_token(lower)
        || matches!(
            lower,
            "pro"
                | "flash"
                | "lite"
                | "ultra"
                | "nano"
                | "exp"
                | "experimental"
                | "preview"
                | "latest"
                | "thinking"
                | "think"
                | "high"
                | "medium"
                | "med"
                | "low"
                | "xhigh"
                | "minimal"
                | "max"
                | "fast"
                | "standard"
                | "orchestrator"
                | "carbon"
                | "hydrogen"
                | "argon"
                | "helium"
                | "lithium"
                | "neon"
                | "xenon"
                | "krypton"
                | "oxygen"
                | "nitrogen"
                | "titanium"
                | "cobalt"
                | "silicon"
                | "boron"
                | "barium"
                | "radon"
                | "iron"
                | "gold"
                | "silver"
                | "mercury"
                | "platinum"
                | "sonnet"
                | "opus"
                | "haiku"
                | "instant"
                | "extended"
                | "oss"
                | "mini"
                | "turbo"
                | "omni"
                | "codex"
                | "chat"
                | "code"
                | "coder"
                | "instruct"
                | "reasoning"
                | "vision"
                | "audio"
                | "image"
                | "live"
                | "tts"
                | "embedding"
                | "disabled"
                | "vl"
                | "plus"
                | "large"
                | "small"
                | "tiny"
                | "base"
                | "distill"
                | "scout"
                | "maverick"
                | "versatile"
                | "next"
                | "zero"
                | "heavy"
                | "wtu"
                | "math"
        )
}

/// Strictly accept ONLY known public model IDs (`gemini-4-carbon`, `claude-opus-4-6-thinking`,
/// `gpt-oss-120b-medium`, `MODEL_PLACEHOLDER_M18`, `MODEL_CLAUDE_4_5_SONNET`, ...) and structured
/// public family display labels (`Gemini 4 Carbon (High)`, `Claude Sonnet 4.6`, ...).
/// Any non-public local prose, extensionless filename, path, IPv4, email, URL, or arbitrary text
/// is rejected and mapped to `"Unknown"`.
fn is_allowed_public_model_syntax(cleaned: &str) -> bool {
    if cleaned.is_empty() || cleaned.len() > MAX_MODEL_NAME_BYTES || !cleaned.is_ascii() {
        return false;
    }
    if cleaned == "Unknown" {
        return true;
    }

    // 1. Official CloudCode uppercase enum IDs (`MODEL_PLACEHOLDER_M18`, `MODEL_OPENAI_GPT_OSS_120B_MEDIUM`, ...)
    if let Some(rest) = cleaned.strip_prefix("MODEL_") {
        if let Some(m_id) = rest.strip_prefix("PLACEHOLDER_M") {
            return !m_id.is_empty() && m_id.len() <= 6 && m_id.bytes().all(|b| b.is_ascii_digit());
        }
        let parts: Vec<&str> = rest.split('_').collect();
        if parts.len() < 2 || parts.len() > 10 || parts.iter().any(|p| p.is_empty()) {
            return false;
        }
        if !rest
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return false;
        }
        let first_low = parts[0].to_ascii_lowercase();
        let valid_vendor_or_family = is_known_public_model_family(&first_low)
            || matches!(
                first_low.as_str(),
                "google" | "anthropic" | "openai" | "vertex"
            );
        if !valid_vendor_or_family {
            return false;
        }
        return parts[1..].iter().all(|p| {
            let low = p.to_ascii_lowercase();
            is_known_public_model_family(&low) || is_known_public_model_variant_token(&low)
        });
    }

    // 2. Public model ID (`gemini-4-carbon`) or display label (`Gemini 4 Carbon (High)`)
    let (main_part, paren_part) = if let Some(open_idx) = cleaned.find('(') {
        if !cleaned.ends_with(')') {
            return false;
        }
        let inner = &cleaned[open_idx + 1..cleaned.len() - 1];
        if inner.is_empty() || inner.contains('(') || inner.contains(')') {
            return false;
        }
        (cleaned[..open_idx].trim_end(), Some(inner.trim()))
    } else {
        if cleaned.contains(')') {
            return false;
        }
        (cleaned, None)
    };

    if main_part.is_empty() {
        return false;
    }
    if !main_part
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'.'))
    {
        return false;
    }
    if main_part.starts_with('-')
        || main_part.ends_with('-')
        || main_part.contains("--")
        || main_part.contains("- ")
        || main_part.contains(" -")
    {
        return false;
    }

    let main_tokens: Vec<&str> = main_part
        .split([' ', '-'])
        .filter(|t| !t.is_empty())
        .collect();
    // Require family token + at least 1 valid version/variant token (prevents bare words)
    if main_tokens.len() < 2 || main_tokens.len() > 10 {
        return false;
    }
    let family_low = main_tokens[0].to_ascii_lowercase();
    if !is_known_public_model_family(&family_low) {
        return false;
    }
    if !main_tokens[1..]
        .iter()
        .all(|t| is_known_public_model_variant_token(&t.to_ascii_lowercase()))
    {
        return false;
    }

    if let Some(inner) = paren_part {
        if !inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b',' | b'.'))
        {
            return false;
        }
        let paren_tokens: Vec<&str> = inner
            .split([' ', '-', ','])
            .filter(|t| !t.is_empty())
            .collect();
        if paren_tokens.is_empty() || paren_tokens.len() > 4 {
            return false;
        }
        if !paren_tokens
            .iter()
            .all(|t| is_known_public_model_variant_token(&t.to_ascii_lowercase()))
        {
            return false;
        }
    }

    true
}

/// Normalize control characters and runs of whitespace, then enforce a strict public model ID/label
/// grammar so paths (absolute or relative), filenames, emails, URLs, and credentials map to `"Unknown"`.
fn classify_model_name(raw: &str) -> ModelNameClass {
    if raw.trim().is_empty() {
        return ModelNameClass::Absent;
    }
    if raw.len() > MAX_MODEL_NAME_BYTES * 2 {
        return ModelNameClass::RejectedUntrusted;
    }
    let cleaned = terminal_text(raw);
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return ModelNameClass::Absent;
    }
    if !is_allowed_public_model_syntax(&collapsed) {
        return ModelNameClass::RejectedUntrusted;
    }
    ModelNameClass::Valid(collapsed)
}

fn model_field_class(requested: u32, bytes: &[u8]) -> Result<ModelNameClass, WireError> {
    match string_field(requested, bytes)? {
        None => Ok(ModelNameClass::Absent),
        Some(s) => Ok(classify_model_name(&s)),
    }
}

fn truncate_display_width(value: &str, max_cols: usize) -> (String, usize) {
    let full_w = UnicodeWidthStr::width(value);
    if full_w <= max_cols {
        return (value.to_string(), full_w);
    }
    if max_cols == 0 {
        return (String::new(), 0);
    }
    let budget = max_cols.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0usize;
    for g in UnicodeSegmentation::graphemes(value, true) {
        let gw = UnicodeWidthStr::width(g);
        if used.saturating_add(gw) > budget {
            break;
        }
        out.push_str(g);
        used += gw;
    }
    out.push('…');
    (out, used + 1)
}

fn timestamp_seconds(message: &[u8]) -> Result<Option<i64>, WireError> {
    let Some(secs) = varint_field(1, message)? else {
        return Ok(None);
    };
    let secs = i64::try_from(secs).map_err(|_| WireError)?;
    Ok((secs > 0).then_some(secs))
}

fn step_timestamp(step_metadata: &[u8]) -> Option<i64> {
    let inner = merged_message_field(1, step_metadata).ok()??;
    timestamp_seconds(&inner).ok()?
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum StepStatusValue {
    #[default]
    Absent,
    Known(i64),
    InvalidType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum StepPayloadState {
    #[default]
    Absent,
    Valid,
    Invalid,
}

#[derive(Clone, Copy, Default)]
struct StepGenInfo {
    timestamp: Option<i64>,
    status: StepStatusValue,
    payload_state: StepPayloadState,
}

/// Validates that an optional `step_payload` blob has intact Protobuf wire framing
/// (including per-fragment submessage framing on `CortexStepPlannerResponse` field 20 if present).
/// Tool-call turns (`field 7`) and non-`STOP_PATTERN` stop reasons are allowed.
fn is_valid_step_payload_framing(payload: &[u8]) -> bool {
    merged_message_field(20, payload).is_ok()
}

/// Single authoritative TPS completion predicate shared across `stats list`, `stats summary --date/--range`,
/// and `stats summary --recent`:
/// - Accepts explicitly completed (`steps.status == 3`, `CORTEX_STEP_STATUS_DONE`) and compacted/cleared
///   history steps (`steps.status == 5`, `CORTEX_STEP_STATUS_CLEARED`), while strictly excluding
///   `6` (`CANCELED`), `12` (`INTERRUPTED`), errors, running/queued steps, and absent/unknown statuses
/// - Rejects any non-NULL oversized, non-BLOB, or corrupt-wire `step_payload`
/// - Rejects error string (`field 5`) or corrupt wire framing on `gen_metadata.data`
fn is_tps_eligible_step(step_info: StepGenInfo, blob: &[u8]) -> bool {
    matches!(step_info.status, StepStatusValue::Known(3 | 5))
        && step_info.payload_state != StepPayloadState::Invalid
        && matches!(string_field(5, blob), Ok(None))
}

fn decode_pb_duration_seconds(message: &[u8]) -> Result<Option<f64>, WireError> {
    let seconds = varint_field(1, message)?.unwrap_or(0);
    let nanos = varint_field(2, message)?.unwrap_or(0);
    // Negative protobuf int64 durations decode as > i64::MAX unsigned varints; nanos must be in 0..1_000_000_000.
    if seconds > i64::MAX as u64 || nanos >= 1_000_000_000 {
        return Ok(None);
    }
    let value = seconds as f64 + nanos as f64 / 1_000_000_000.0;
    Ok((value > 0.0 && value.is_finite()).then_some(value))
}

fn classify_live_step_status(step_status: StepStatusValue, blob: &[u8]) -> StatsCallStatus {
    if matches!(string_field(5, blob), Ok(Some(_)) | Err(_)) {
        return StatsCallStatus::Error;
    }
    match step_status {
        StepStatusValue::Known(3) => StatsCallStatus::Ok,
        StepStatusValue::Known(5) => StatsCallStatus::Cleared,
        StepStatusValue::Known(4 | 7) => StatsCallStatus::Error,
        StepStatusValue::Known(6) => StatsCallStatus::Canceled,
        StepStatusValue::Known(12) => StatsCallStatus::Interrupted,
        StepStatusValue::Known(1 | 2 | 8 | 9 | 11) => StatsCallStatus::Running,
        StepStatusValue::Absent | StepStatusValue::InvalidType | StepStatusValue::Known(_) => {
            StatsCallStatus::Unknown
        }
    }
}

fn decode_live_timings(blob: &[u8], step_ok: bool) -> (Option<f64>, Option<f64>, Option<f64>) {
    let Ok(Some(wrapped)) = merged_message_field(1, blob) else {
        return (None, None, None);
    };
    let ttft_seconds = match merged_message_field(11, &wrapped) {
        Ok(Some(msg)) => match decode_pb_duration_seconds(&msg) {
            Ok(v) => v,
            Err(_) => return (None, None, None),
        },
        Ok(None) => None,
        Err(_) => return (None, None, None),
    };
    let streaming_seconds = match merged_message_field(12, &wrapped) {
        Ok(Some(msg)) => match decode_pb_duration_seconds(&msg) {
            Ok(v) => v,
            Err(_) => return (None, None, None),
        },
        Ok(None) => None,
        Err(_) => return (None, None, None),
    };
    let duration_seconds = match (ttft_seconds, streaming_seconds) {
        (Some(t), Some(s)) if (t + s).is_finite() => Some(t + s),
        (Some(t), None) => Some(t),
        _ => None,
    };

    let output_tps = if step_ok && ttft_seconds.is_some() {
        let retries_ok = matches!(varint_field(14, &wrapped), Ok(None | Some(0)));
        let output_tokens = merged_message_field(4, &wrapped)
            .ok()
            .flatten()
            .and_then(|u| varint_field(3, &u).ok().flatten());
        match (retries_ok, output_tokens, streaming_seconds) {
            (true, Some(out_tok), Some(ss)) if out_tok > 0 && ss >= MIN_PERF_STREAMING_SECONDS => {
                let tps = out_tok as f64 / ss;
                (tps.is_finite() && tps > 0.0).then_some(tps)
            }
            _ => None,
        }
    } else {
        None
    };

    (ttft_seconds, duration_seconds, output_tps)
}

#[derive(Debug, Clone)]
struct PerfSample {
    model: String,
    timestamp_seconds: i64,
    ttft_seconds: f64,
    output_tps: f64,
}

/// Single authoritative decoder producing an `InternalCallRecord` for BOTH `stats list` and
/// `stats summary` (across `--date`, `--range`, `--from`, and `--recent`), guaranteeing 100%
/// identical event timestamp, model name, status, and TTFT/TPS eligibility!
fn decode_live_record(
    source_key: &str,
    generation_idx: i64,
    blob: Option<&[u8]>,
    step_info: StepGenInfo,
    archived_override: Option<&GenerationEvent>,
) -> Option<InternalCallRecord> {
    let base_ev = match archived_override {
        Some(arch) => arch.clone(),
        None => decode_generation_event(blob?, step_info.timestamp)?,
    };
    if jiff::Timestamp::from_second(base_ev.timestamp_seconds).is_err() {
        return None;
    }
    let (ttft_seconds, duration_seconds, output_tps, status) = match blob {
        Some(b) => {
            let st = classify_live_step_status(step_info.status, b);
            let step_ok = is_tps_eligible_step(step_info, b);
            let (t, dur, tps) = decode_live_timings(b, step_ok);
            (t, dur, tps, st)
        }
        None => (None, None, None, StatsCallStatus::Archived),
    };
    Some(InternalCallRecord {
        source_key: source_key.to_string(),
        generation_idx,
        timestamp_seconds: base_ev.timestamp_seconds,
        model: base_ev.model,
        uncached_input_tokens: base_ev.uncached_input_tokens,
        cached_tokens: base_ev.cached_tokens,
        output_tokens: base_ev.output_tokens,
        total_tokens: base_ev.total_tokens,
        ttft_seconds,
        duration_seconds,
        output_tps,
        status,
    })
}

fn quantile_sorted(sorted: &[f64], q: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let pos = q * (n - 1) as f64;
    let lower = pos.floor() as usize;
    let upper = pos.ceil() as usize;
    if lower >= upper {
        sorted[lower]
    } else {
        let weight = pos - lower as f64;
        sorted[lower] + (sorted[upper] - sorted[lower]) * weight
    }
}

fn compute_quantiles(sorted: &[f64]) -> StatsQuantilesDto {
    let p10 = quantile_sorted(sorted, 0.10);
    let p50 = quantile_sorted(sorted, 0.50).max(p10);
    let p90 = quantile_sorted(sorted, 0.90).max(p50);
    StatsQuantilesDto { p10, p50, p90 }
}

fn build_performance_dto(
    mut ttft_samples: Vec<f64>,
    mut tps_samples: Vec<f64>,
    model_count: usize,
    source_count: usize,
) -> Option<StatsPerformanceDto> {
    if ttft_samples.is_empty() || ttft_samples.len() != tps_samples.len() {
        return None;
    }
    ttft_samples.sort_by(f64::total_cmp);
    tps_samples.sort_by(f64::total_cmp);
    Some(StatsPerformanceDto {
        sample_count: ttft_samples.len() as u64,
        model_count: model_count as u64,
        source_count: source_count as u64,
        ttft_seconds: compute_quantiles(&ttft_samples),
        output_tps: compute_quantiles(&tps_samples),
    })
}

fn decode_generation_event(blob: &[u8], step_ts: Option<i64>) -> Option<GenerationEvent> {
    let wrapped = merged_message_field(1, blob).ok()??;
    let model_id_cls = model_field_class(19, &wrapped).ok()?;
    let label_cls = model_field_class(21, &wrapped).ok()?;
    let usage = merged_message_field(4, &wrapped).ok()??;

    let system_prompt_tokens = varint_field(1, &usage).ok()?.unwrap_or(0);
    let raw_input_tokens = varint_field(2, &usage).ok()?.unwrap_or(0);
    let output_tokens = varint_field(3, &usage).ok()?.unwrap_or(0);
    let cached_tokens = varint_field(5, &usage).ok()?.unwrap_or(0);
    let uncached_input_tokens = system_prompt_tokens.checked_add(raw_input_tokens)?;
    let generated = raw_input_tokens != 0 || output_tokens != 0 || cached_tokens != 0;
    let has_model = !matches!(model_id_cls, ModelNameClass::Absent)
        || !matches!(label_cls, ModelNameClass::Absent);

    if !generated && (!has_model || uncached_input_tokens == 0) {
        return None;
    }

    let embedded_ts = match merged_message_field(9, &wrapped).ok()? {
        Some(timing) => match merged_message_field(4, &timing).ok()? {
            Some(ts_msg) => timestamp_seconds(&ts_msg).ok()?,
            None => None,
        },
        None => None,
    };
    let timestamp_seconds = embedded_ts.or(step_ts)?;
    let total_tokens = uncached_input_tokens
        .checked_add(cached_tokens)?
        .checked_add(output_tokens)?;

    let model = match (label_cls, model_id_cls) {
        (ModelNameClass::Valid(lbl), _) => lbl,
        (_, ModelNameClass::Valid(mid)) => mid,
        _ => "Unknown".to_string(),
    };

    Some(GenerationEvent {
        model,
        uncached_input_tokens,
        output_tokens,
        cached_tokens,
        total_tokens,
        timestamp_seconds,
    })
}

pub fn format_u64_commas(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (idx, ch) in digits.chars().enumerate() {
        if idx > 0 && (digits.len() - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub fn format_compact_tokens(value: u64) -> String {
    let exact = format_u64_commas(value);
    if value >= 999_950_000 {
        format!("{:.1}B ({exact})", value as f64 / 1_000_000_000.0)
    } else if value >= 999_950 {
        format!("{:.1}M ({exact})", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}K ({exact})", value as f64 / 1_000.0)
    } else {
        exact
    }
}

fn format_short_tokens(value: u64) -> String {
    if value >= 999_950_000 {
        format!("{:.1}B", value as f64 / 1_000_000_000.0)
    } else if value >= 999_950 {
        format!("{:.1}M", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}K", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn vi(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let next = (value & 0x7f) as u8;
            value >>= 7;
            bytes.push(if value == 0 { next } else { next | 0x80 });
            if value == 0 {
                return bytes;
            }
        }
    }

    fn pb_varint(number: u32, value: u64) -> Vec<u8> {
        [vi(u64::from(number) << 3), vi(value)].concat()
    }

    fn pb_bytes(number: u32, value: &[u8]) -> Vec<u8> {
        [
            vi((u64::from(number) << 3) | 2),
            vi(value.len() as u64),
            value.to_vec(),
        ]
        .concat()
    }

    fn make_gen_blob(
        sys_in: u64,
        user_in: u64,
        out_tok: u64,
        cached_tok: u64,
        embedded_ts: Option<u64>,
        model_id: &str,
        label: Option<&str>,
    ) -> Vec<u8> {
        let mut usage = Vec::new();
        usage.extend(pb_varint(1, sys_in));
        usage.extend(pb_varint(2, user_in));
        usage.extend(pb_varint(3, out_tok));
        usage.extend(pb_varint(5, cached_tok));

        let mut wrapped = pb_bytes(4, &usage);
        if let Some(ts) = embedded_ts {
            let ts_msg = pb_varint(1, ts);
            let timing = pb_bytes(4, &ts_msg);
            wrapped.extend(pb_bytes(9, &timing));
        }
        if !model_id.is_empty() {
            wrapped.extend(pb_bytes(19, model_id.as_bytes()));
        }
        if let Some(lbl) = label {
            wrapped.extend(pb_bytes(21, lbl.as_bytes()));
        }
        pb_bytes(1, &wrapped)
    }

    #[test]
    fn compact_token_formatting_handles_rounding_boundaries_and_commas() {
        assert_eq!(format_compact_tokens(0), "0");
        assert_eq!(format_compact_tokens(999), "999");
        assert_eq!(format_compact_tokens(1_000), "1.0K (1,000)");
        assert_eq!(format_compact_tokens(999_949), "999.9K (999,949)");
        assert_eq!(format_compact_tokens(999_950), "1.0M (999,950)");
        assert_eq!(format_compact_tokens(241_693_282), "241.7M (241,693,282)");
        assert_eq!(format_compact_tokens(999_950_000), "1.0B (999,950,000)");
    }

    #[test]
    fn date_range_resolution_validates_strict_ymd_and_rejects_inverted_bounds_without_echo() {
        let today: jiff::civil::Date = "2026-11-17".parse().unwrap();

        let bad_date = StatsArgs {
            source: CliStatsSource::Cli,
            range: None,
            date: Some("1//0gSUPER_SECRET_DATE_TOKEN".into()),
            from: None,
            to: None,
            recent: None,
            watch: None,
        };
        let err = resolve_stats_range_spec(&bad_date, today).unwrap_err();
        assert_eq!(err.exit_code.as_i32(), 2);
        assert!(!err.message.contains("SUPER_SECRET_DATE_TOKEN"));

        // Reject non-zero-padded or compact dates
        for invalid in ["2026-1-7", "20261117", "2026-02-29"] {
            let args = StatsArgs {
                source: CliStatsSource::Cli,
                range: None,
                date: Some(invalid.into()),
                from: None,
                to: None,
                recent: None,
                watch: None,
            };
            assert!(resolve_stats_range_spec(&args, today).is_err());
        }

        // Inverted `--from > --to` returns exit code 2
        let inverted = StatsArgs {
            source: CliStatsSource::Cli,
            range: None,
            date: None,
            from: Some("2026-11-18".into()),
            to: Some("2026-11-17".into()),
            recent: None,
            watch: None,
        };
        let inv_err = resolve_stats_range_spec(&inverted, today).unwrap_err();
        assert_eq!(inv_err.exit_code.as_i32(), 2);

        // Omitting `--to` defaults to `today`
        let open_to = StatsArgs {
            source: CliStatsSource::Cli,
            range: None,
            date: None,
            from: Some("2026-10-01".into()),
            to: None,
            recent: None,
            watch: None,
        };
        let resolved = resolve_stats_range_spec(&open_to, today).unwrap();
        assert_eq!(resolved.start_date().unwrap().to_string(), "2026-10-01");
        assert_eq!(resolved.end_date().unwrap().to_string(), "2026-11-17");

        // `--range all`: unbounded `AllTime` preset (`start_date`/`end_date` = `None`, dynamic observed span)
        let parsed_all = crate::cli::args::parse_cli_stats_range("all").unwrap();
        let all_spec = resolve_stats_range_spec(
            &StatsArgs {
                source: CliStatsSource::All,
                range: Some(parsed_all),
                date: None,
                from: None,
                to: None,
                recent: None,
                watch: None,
            },
            today,
        )
        .unwrap();
        assert_eq!(all_spec, StatsRangeSpec::AllTime);
        assert!(all_spec.start_date().is_none());
        assert!(all_spec.end_date().is_none());
        assert_eq!(all_spec.human_label(), "all");
        let empty_all_dto = serde_json::to_value(all_spec.to_dto()).unwrap();
        assert_eq!(empty_all_dto["kind"], "preset");
        assert_eq!(empty_all_dto["preset"], "all");
        assert!(empty_all_dto["from"].is_null());
        assert!(empty_all_dto["to"].is_null());
        let span_d1: jiff::civil::Date = "2026-09-03".parse().unwrap();
        assert_eq!(
            all_spec.human_label_with_observed(Some((span_d1, today))),
            "all (2026-09-03 .. 2026-11-17)"
        );
        assert_eq!(
            all_spec.human_label_with_observed(Some((today, today))),
            "all (2026-11-17)"
        );

        // Scheme A `<N>d` natural-day resolution (`1 <= N <= 36500`, inclusive of `today`):
        // - `1d` == `today` (`2026-11-17`)
        // - `2d` == `2026-11-16 .. 2026-11-17`
        // - `3d` == `2026-11-15 .. 2026-11-17`
        // - `14d` == `2026-11-04 .. 2026-11-17`
        for (raw, exp_from, exp_to, exp_human, exp_preset) in [
            (
                "today",
                "2026-11-17",
                "2026-11-17",
                "today (2026-11-17)",
                "today",
            ),
            (
                "yesterday",
                "2026-11-16",
                "2026-11-16",
                "yesterday (2026-11-16)",
                "yesterday",
            ),
            ("1d", "2026-11-17", "2026-11-17", "1d (2026-11-17)", "1d"),
            (
                "2d",
                "2026-11-16",
                "2026-11-17",
                "2d (2026-11-16 .. 2026-11-17)",
                "2d",
            ),
            (
                "3d",
                "2026-11-15",
                "2026-11-17",
                "3d (2026-11-15 .. 2026-11-17)",
                "3d",
            ),
            (
                "14d",
                "2026-11-04",
                "2026-11-17",
                "14d (2026-11-04 .. 2026-11-17)",
                "14d",
            ),
            (
                "365d",
                "2025-11-18",
                "2026-11-17",
                "365d (2025-11-18 .. 2026-11-17)",
                "365d",
            ),
        ] {
            let parsed = crate::cli::args::parse_cli_stats_range(raw).unwrap();
            let spec = resolve_stats_range_spec(
                &StatsArgs {
                    source: CliStatsSource::Cli,
                    range: Some(parsed),
                    date: None,
                    from: None,
                    to: None,
                    recent: None,
                    watch: None,
                },
                today,
            )
            .unwrap();
            assert_eq!(spec.start_date().unwrap().to_string(), exp_from);
            assert_eq!(spec.end_date().unwrap().to_string(), exp_to);
            assert_eq!(spec.human_label(), exp_human);
            let dto_val = serde_json::to_value(spec.to_dto()).unwrap();
            assert_eq!(dto_val["preset"], exp_preset);
        }

        for bad_range in ["", "0d", "03d", "-3d", "+3d", "36501d", "7w", "nope"] {
            assert!(
                crate::cli::args::parse_cli_stats_range(bad_range).is_err(),
                "expected {bad_range:?} to be rejected"
            );
        }
    }

    #[test]
    fn synthetic_sqlite_stats_aggregates_tokens_dedupes_archive_and_skips_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        let app_conv = home.join(".gemini/antigravity/conversations");
        fs::create_dir_all(&cli_conv).unwrap();
        fs::create_dir_all(&app_conv).unwrap();

        let tz = jiff::tz::TimeZone::UTC;
        let now = "2026-11-17T18:34:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(tz.clone());
        let ts_today = "2026-11-17T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let ts_yesterday = "2026-11-16T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        // 1. Populate CLI conversation DB with 12 generations using embedded timestamp,
        // 1 generation relying on `steps.metadata` fallback timestamp, and 1 yesterday generation.
        let cli_db_path = cli_conv.join("conv1.db");
        let cli_conn = Connection::open(&cli_db_path).unwrap();
        cli_conn
            .execute_batch(
                "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();

        for i in 1..=12_u64 {
            let out_tok = if i <= 6 { 200 * i } else { 400 * i };
            let step_meta = pb_bytes(1, &pb_varint(1, ts_today + i));
            cli_conn
                .execute(
                    "INSERT INTO steps VALUES (?1, 15, ?2)",
                    rusqlite::params![i as i64, step_meta],
                )
                .unwrap();
            let blob = make_gen_blob(
                100,
                900,
                out_tok,
                4000,
                Some(ts_today + i),
                "gemini-4-carbon-high",
                Some("Gemini 4 Carbon (High)"),
            );
            cli_conn
                .execute(
                    "INSERT INTO gen_metadata VALUES (?1, ?2)",
                    rusqlite::params![i as i64, blob],
                )
                .unwrap();
        }

        // Generation without embedded timing field: falls back cleanly to `steps.metadata` timestamp!
        let step_meta_fallback = pb_bytes(1, &pb_varint(1, ts_today + 50));
        cli_conn
            .execute(
                "INSERT INTO steps VALUES (100, 15, ?1)",
                rusqlite::params![step_meta_fallback],
            )
            .unwrap();
        let fallback_blob = make_gen_blob(
            50,
            150,
            500,
            800,
            None,
            "claude-sonnet-4-6",
            Some("Claude Sonnet 4.6"),
        );
        cli_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (100, ?1)",
                rusqlite::params![fallback_blob],
            )
            .unwrap();

        // Yesterday generation: excluded from `today`, included in `3d`
        let step_meta_yest = pb_bytes(1, &pb_varint(1, ts_yesterday));
        cli_conn
            .execute(
                "INSERT INTO steps VALUES (200, 15, ?1)",
                rusqlite::params![step_meta_yest],
            )
            .unwrap();
        let yest_blob = make_gen_blob(
            10,
            90,
            300,
            500,
            Some(ts_yesterday),
            "gemini-4-carbon-high",
            Some("Gemini 4 Carbon (High)"),
        );
        cli_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (200, ?1)",
                rusqlite::params![yest_blob],
            )
            .unwrap();
        drop(cli_conn);

        // Place a symlink `.db` in CLI conversations pointing to an external DB — MUST be skipped!
        let ext_db = tmp.path().join("external.db");
        let ext_conn = Connection::open(&ext_db).unwrap();
        ext_conn
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        ext_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(
                    999_999,
                    999_999,
                    999_999,
                    0,
                    Some(ts_today),
                    "evil-symlink-model",
                    None
                )],
            )
            .unwrap();
        drop(ext_conn);
        std::os::unix::fs::symlink(&ext_db, cli_conv.join("symlinked.db")).unwrap();

        // 2. Populate App live DB + `token_usage_archive.db` with overlapping `(source_key, generation_idx = 7)`
        let app_db_path = app_conv.join("app1.db");
        let app_conn = Connection::open(&app_db_path).unwrap();
        app_conn
            .execute_batch(
                "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        let app_blob = make_gen_blob(
            200,
            300,
            40,
            500,
            Some(ts_today + 100),
            "gemini-app-model",
            Some("Gemini App Model"),
        );
        app_conn
            .execute("INSERT INTO steps VALUES (1, 15, NULL)", [])
            .unwrap();
        app_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (7, ?1)",
                rusqlite::params![app_blob],
            )
            .unwrap();
        drop(app_conn);

        let archive_path = home.join(".gemini/antigravity/token_usage_archive.db");
        let arch_conn = Connection::open(&archive_path).unwrap();
        arch_conn
            .execute_batch(
                "CREATE TABLE archived_sources (source_key TEXT PRIMARY KEY, archived_at INTEGER NOT NULL, generation_count INTEGER NOT NULL);
                 CREATE TABLE archived_generations (
                    source_key TEXT NOT NULL,
                    generation_idx INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    model TEXT,
                    input_tokens TEXT,
                    output_tokens TEXT,
                    cached_tokens TEXT,
                    total_tokens TEXT,
                    timestamp_seconds INTEGER,
                    valid INTEGER NOT NULL,
                    oversized INTEGER NOT NULL,
                    PRIMARY KEY (source_key, generation_idx)
                 );",
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_sources VALUES ('antigravity/conversations/app1.db', 1, 1)",
                [],
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/app1.db', 7, 0, 'Gemini App Model', '500', '40', '500', '1040', ?1, 1, 0)",
                rusqlite::params![(ts_today + 100) as i64],
            )
            .unwrap();
        // Also insert an archived CLI entry into archive.db to verify `--source app` ignores `antigravity-cli/*`!
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity-cli/conversations/conv1.db', 1, 0, 'Gemini 4 Carbon (High)', '1000', '200', '4000', '5200', ?1, 1, 0)",
                rusqlite::params![(ts_today + 1) as i64],
            )
            .unwrap();
        drop(arch_conn);

        let today_spec = StatsRangeSpec::Preset {
            preset: StatsPresetRange::Today,
            from: now.date(),
            to: now.date(),
        };

        // Verify `--source cli`
        let cli_stats = collect_token_stats_at(&home, StatsSource::Cli, &today_spec, &now);
        assert_eq!(cli_stats.databases_scanned, 1);
        assert_eq!(cli_stats.summary.request_count, 13); // 12 embedded-ts + 1 step-ts fallback today (yesterday & symlink excluded!)
        assert_eq!(cli_stats.models.len(), 2);
        assert_eq!(cli_stats.models[0].model, "Gemini 4 Carbon (High)");
        assert_eq!(cli_stats.models[1].model, "Claude Sonnet 4.6");

        let human = cli_stats.render_human_for_width(None);
        assert!(human.contains("Source : cli (~/.gemini/antigravity-cli) · 1 db(s)"));
        assert!(human.contains("Range  : today (2026-11-17)"));
        assert!(human.contains("Total input        :"));
        assert!(human.contains("Cache hit          :"));
        assert!(human.contains("TTFT (P10/P50/P90) : —"));
        assert!(human.contains("TPS (P10/P50/P90) : —"));
        assert!(!human.contains("evil-symlink-model"));

        // Verify `--source app` deduplicates `(antigravity/conversations/app1.db, 7)` AND excludes `antigravity-cli/*` from archive
        let app_stats = collect_token_stats_at(&home, StatsSource::App, &today_spec, &now);
        assert_eq!(app_stats.databases_scanned, 1);
        assert_eq!(app_stats.summary.request_count, 1);
        assert_eq!(app_stats.summary.uncached_input_tokens, 500);
        assert_eq!(app_stats.summary.cached_input_tokens, 500);
        assert_eq!(app_stats.summary.total_output_tokens, 40);

        // Verify `--source all` combines both and deduplicates archive vs live for both cli and app!
        let all_stats = collect_token_stats_at(&home, StatsSource::All, &today_spec, &now);
        assert_eq!(all_stats.databases_scanned, 2);
        assert_eq!(all_stats.summary.request_count, 14); // 13 cli + 1 app (zero duplicate counting!)
    }

    #[test]
    fn synthetic_protobuf_merge_last_one_wins_model_dedup_and_wide_truncation() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        let app_dir = home.join(".gemini/antigravity");
        fs::create_dir_all(&cli_conv).unwrap();
        fs::create_dir_all(&app_dir).unwrap();

        let tz = jiff::tz::TimeZone::UTC;
        let now = "2026-11-17T18:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(tz);
        let ts = "2026-11-17T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        // 1. Corrupt trailing wire tag after valid fields MUST be rejected
        let mut corrupt_blob = make_gen_blob(10, 20, 30, 0, Some(ts), "m1", Some("Model One"));
        corrupt_blob.push(0x80); // unterminated varint
        assert!(decode_generation_event(&corrupt_blob, None).is_none());

        // 2. Concatenated `usage` (first fragment `out=0`, second fragment `out=500`) + `"Model\nOne"` vs `"Model One"`
        let db_path = cli_conv.join("merge.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();

        let timing = pb_bytes(4, &pb_varint(1, ts));
        let wrapped_concat = [
            pb_bytes(4, &[pb_varint(2, 100), pb_varint(3, 0)].concat()),
            pb_bytes(4, &pb_varint(3, 500)),
            pb_bytes(9, &timing),
            pb_bytes(21, b"Gemini\n2.5\tPro"),
        ]
        .concat();
        conn.execute(
            "INSERT INTO steps VALUES (1, 15, ?1)",
            rusqlite::params![pb_bytes(1, &pb_varint(1, ts))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![pb_bytes(1, &wrapped_concat)],
        )
        .unwrap();

        let second_blob = make_gen_blob(
            0,
            100,
            300,
            0,
            Some(ts + 1),
            "gemini-2.5-pro",
            Some("Gemini 2.5 Pro"),
        );
        conn.execute(
            "INSERT INTO steps VALUES (2, 15, ?1)",
            rusqlite::params![pb_bytes(1, &pb_varint(1, ts + 1))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (2, ?1)",
            rusqlite::params![second_blob],
        )
        .unwrap();

        // Long valid public model name (> 48 cols) exercises column width truncation (`…`)
        let long_model_name =
            "Gemini 4 Experimental Preview Ultra Thinking Carbon (XHigh, Extended)";
        let wide_blob = make_gen_blob(
            0,
            50,
            25,
            0,
            Some(ts + 2),
            "gemini-4-experimental-preview-ultra",
            Some(long_model_name),
        );
        conn.execute("INSERT INTO steps VALUES (3, 15, NULL)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (3, ?1)",
            rusqlite::params![wide_blob],
        )
        .unwrap();
        drop(conn);

        // Archive row with mismatched `total_tokens` column & unrelated `antigravity-insiders/*` row
        let arch_conn = Connection::open(app_dir.join("token_usage_archive.db")).unwrap();
        arch_conn
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT NOT NULL,
                    generation_idx INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    model TEXT,
                    input_tokens TEXT,
                    output_tokens TEXT,
                    cached_tokens TEXT,
                    total_tokens TEXT,
                    timestamp_seconds INTEGER,
                    valid INTEGER NOT NULL,
                    oversized INTEGER NOT NULL,
                    PRIMARY KEY (source_key, generation_idx)
                 );",
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/old.db', 1, 0, 'Gemini\t2.5 Pro', '200', '50', '100', '999999', ?1, 1, 0)",
                rusqlite::params![ts as i64],
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity-insiders/conversations/ignore.db', 1, 0, 'Gemini 4', '999', '999', '999', '2997', ?1, 1, 0)",
                rusqlite::params![ts as i64],
            )
            .unwrap();
        drop(arch_conn);

        let spec = StatsRangeSpec::SingleDate { date: now.date() };
        let stats = collect_token_stats_at(&home, StatsSource::All, &spec, &now);
        assert_eq!(stats.databases_scanned, 2); // `merge.db` + `antigravity/conversations/old.db` (`insiders` excluded!)
        assert_eq!(stats.summary.total_output_tokens, 500 + 300 + 25 + 50);
        // `"Gemini\n2.5\tPro"`, `"Gemini 2.5 Pro"`, and `"Gemini\t2.5 Pro"` MUST all merge into a single `"Gemini 2.5 Pro"` row!
        let model_one_rows: Vec<_> = stats
            .models
            .iter()
            .filter(|m| m.model == "Gemini 2.5 Pro")
            .collect();
        assert_eq!(model_one_rows.len(), 1);
        assert_eq!(model_one_rows[0].request_count, 3);
        assert_eq!(
            model_one_rows[0].total_tokens,
            model_one_rows[0].uncached_input_tokens
                + model_one_rows[0].cached_input_tokens
                + model_one_rows[0].output_tokens
        );

        let rendered = stats.render_human();
        assert!(rendered.contains("…"));
        for line in rendered.lines().skip(7) {
            assert!(
                UnicodeWidthStr::width(line) <= 120,
                "Human table line exceeded expected width: {line}"
            );
        }
    }

    #[test]
    fn synthetic_dst_natural_day_boundaries_transition_cleanly_at_local_midnight() {
        let Ok(ny_tz) = jiff::tz::TimeZone::get("America/New_York") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cli_conv).unwrap();

        // 2026-11-01 is Fall-Back DST day in America/New_York (25-hour local day: 04:00:00Z ..= 2026-11-02T04:59:59Z)
        let conn = Connection::open(cli_conv.join("dst.db")).unwrap();
        conn.execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        let instants = [
            ("2026-11-01T03:59:59Z", 10_u64), // 2026-10-31 23:59:59 EDT -> excluded
            ("2026-11-01T04:00:00Z", 20_u64), // 2026-11-01 00:00:00 EDT -> included
            ("2026-11-01T05:30:00Z", 30_u64), // 2026-11-01 01:30:00 EDT -> included
            ("2026-11-01T06:30:00Z", 40_u64), // 2026-11-01 01:30:00 EST -> included
            ("2026-11-02T04:59:59Z", 50_u64), // 2026-11-01 23:59:59 EST -> included
            ("2026-11-02T05:00:00Z", 60_u64), // 2026-11-02 00:00:00 EST -> excluded
        ];
        for (idx, (iso, out_tok)) in instants.iter().enumerate() {
            let secs = iso.parse::<jiff::Timestamp>().unwrap().as_second() as u64;
            let blob = make_gen_blob(0, 100, *out_tok, 0, Some(secs), "m-dst", None);
            conn.execute(
                "INSERT INTO gen_metadata VALUES (?1, ?2)",
                rusqlite::params![(idx + 1) as i64, blob],
            )
            .unwrap();
        }
        drop(conn);

        let now = "2026-11-01T15:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(ny_tz);
        let spec = StatsRangeSpec::SingleDate {
            date: "2026-11-01".parse().unwrap(),
        };
        let stats = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
        assert_eq!(stats.summary.request_count, 4);
        assert_eq!(stats.summary.total_output_tokens, 20 + 30 + 40 + 50);
    }

    #[test]
    fn closed_wal_db_and_live_wal_db_produce_zero_companion_writes_or_mutations() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cli_conv).unwrap();

        let ts = "2026-11-17T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let now = "2026-11-17T18:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::UTC);
        let spec = StatsRangeSpec::SingleDate { date: now.date() };

        // 1. Create a WAL-mode database and cleanly close the writer so ONLY `closed_wal.db` remains in `conversations/`
        let closed_wal_db = cli_conv.join("closed_wal.db");
        let wconn = Connection::open(&closed_wal_db).unwrap();
        wconn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        wconn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(
                    10,
                    90,
                    25,
                    0,
                    Some(ts),
                    "m-wal",
                    Some("WAL Model")
                )],
            )
            .unwrap();
        drop(wconn);

        assert!(!cli_conv.join("closed_wal.db-wal").exists());
        assert!(!cli_conv.join("closed_wal.db-shm").exists());
        let before_bytes = fs::read(&closed_wal_db).unwrap();

        let stats = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
        assert_eq!(stats.databases_scanned, 1);
        assert_eq!(stats.unreadable_databases, 0);
        assert_eq!(stats.summary.request_count, 1);
        assert_eq!(stats.summary.total_output_tokens, 25);

        // Zero `-wal` or `-shm` companion files created, and main `.db` bytes untouched!
        assert!(
            !cli_conv.join("closed_wal.db-wal").exists(),
            "stats must NEVER create -wal companion file on closed WAL database"
        );
        assert!(
            !cli_conv.join("closed_wal.db-shm").exists(),
            "stats must NEVER create -shm companion file on closed WAL database"
        );
        assert_eq!(fs::read(&closed_wal_db).unwrap(), before_bytes);

        // 2. Also test orphaned `-wal` WITHOUT `-shm` (simulated crashed writer): reads WAL frames with zero `-shm` creation!
        let orphan_db = cli_conv.join("orphan_wal.db");
        let oconn = Connection::open(&orphan_db).unwrap();
        oconn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        oconn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(5, 45, 75, 0, Some(ts), "m-orphan", None)],
            )
            .unwrap();
        // Copy `.db` and `-wal` without `-shm` into a second clean directory to simulate post-crash state
        let crash_home = tmp.path().join("crash_home");
        let crash_conv = crash_home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&crash_conv).unwrap();
        fs::copy(&orphan_db, crash_conv.join("crashed.db")).unwrap();
        fs::copy(
            cli_conv.join("orphan_wal.db-wal"),
            crash_conv.join("crashed.db-wal"),
        )
        .unwrap();
        drop(oconn);

        assert!(!crash_conv.join("crashed.db-shm").exists());
        let crash_stats = collect_token_stats_at(&crash_home, StatsSource::Cli, &spec, &now);
        assert_eq!(crash_stats.databases_scanned, 1);
        assert_eq!(crash_stats.summary.request_count, 1);
        assert_eq!(crash_stats.summary.total_output_tokens, 75);
        assert!(
            !crash_conv.join("crashed.db-shm").exists(),
            "stats must NEVER create -shm when reading orphaned -wal"
        );
    }

    #[test]
    fn invalid_archive_falls_back_to_live_and_null_total_tokens_still_recomputes() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let app_conv = home.join(".gemini/antigravity/conversations");
        fs::create_dir_all(&app_conv).unwrap();

        let ts = "2026-11-17T11:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let now = "2026-11-17T18:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::UTC);
        let spec = StatsRangeSpec::SingleDate { date: now.date() };

        // Live `app_live.db` has valid generation `idx = 1` (output = 120)
        let live_conn = Connection::open(app_conv.join("app_live.db")).unwrap();
        live_conn
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        live_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(
                    10,
                    90,
                    120,
                    200,
                    Some(ts),
                    "m-live",
                    Some("Live Fallback Model")
                )],
            )
            .unwrap();
        drop(live_conn);

        // Archive has:
        // (a) INVALID row (`valid = 0`) for `('antigravity/conversations/app_live.db', 1)` -> MUST NOT shadow valid live row!
        // (b) VALID row for `('antigravity/conversations/archived_only.db', 2)` with `total_tokens = NULL` -> MUST still recompute!
        let arch_conn =
            Connection::open(home.join(".gemini/antigravity/token_usage_archive.db")).unwrap();
        arch_conn
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT NOT NULL,
                    generation_idx INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    model TEXT,
                    input_tokens TEXT,
                    output_tokens TEXT,
                    cached_tokens TEXT,
                    total_tokens TEXT,
                    timestamp_seconds INTEGER,
                    valid INTEGER NOT NULL,
                    oversized INTEGER NOT NULL,
                    PRIMARY KEY (source_key, generation_idx)
                 );",
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/app_live.db', 1, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0)",
                [],
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/archived_only.db', 2, 0, 'Archived Model', '300', '80', '100', NULL, ?1, 1, 0)",
                rusqlite::params![ts as i64],
            )
            .unwrap();
        drop(arch_conn);

        let stats = collect_token_stats_at(&home, StatsSource::App, &spec, &now);
        assert_eq!(stats.databases_scanned, 2);
        assert_eq!(stats.generations_scanned, 2); // Unique count: 1 from live + 1 from archive
        assert_eq!(stats.summary.request_count, 2);
        assert_eq!(stats.summary.total_output_tokens, 120 + 80);
        assert_eq!(stats.summary.uncached_input_tokens, 100 + 300);
        assert_eq!(stats.summary.cached_input_tokens, 200 + 100);
    }

    #[test]
    fn protobuf_rejects_split_corrupt_submessages_29bit_overflow_and_redacts_untrusted_models() {
        let ts = "2026-11-17T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        // 1. Two `usage` fragments that individually have broken wire framing (`[0x08]` + `[0x64]`)
        //    MUST be rejected even though concatenating `[0x08, 0x64]` would form a valid varint!
        let timing = pb_bytes(4, &pb_varint(1, ts));
        let split_corrupt_wrapped = [
            pb_bytes(4, &[0x08]), // field 1 varint tag with missing value byte!
            pb_bytes(4, &[0x64]), // stray continuation byte that would have completed `[0x08, 0x64]`
            pb_bytes(9, &timing),
            pb_bytes(21, b"Safe Model"),
        ]
        .concat();
        assert!(
            decode_generation_event(&pb_bytes(1, &split_corrupt_wrapped), Some(ts as i64))
                .is_none()
        );

        // 2. Corrupt UTF-8 in `label` (field 21) MUST fail the record instead of silently falling back to `model_id` (field 19)
        let bad_utf8_label = [
            pb_bytes(4, &pb_varint(2, 50)),
            pb_bytes(9, &timing),
            pb_bytes(19, b"valid-fallback-id"),
            pb_bytes(21, &[0xff, 0xfe]),
        ]
        .concat();
        assert!(decode_generation_event(&pb_bytes(1, &bad_utf8_label), None).is_none());

        // 3. Field number exceeding Protobuf's 29-bit max (`(1 << 29)`) MUST be rejected
        let over_29bit_tag = [vi((1_u64 << 29) << 3), vi(1)].concat();
        let mut with_bad_tag = make_gen_blob(10, 20, 30, 0, Some(ts), "m1", Some("Model"));
        with_bad_tag.extend(over_29bit_tag);
        assert!(decode_generation_event(&with_bad_tag, None).is_none());

        // 4. Untrusted model strings (emails, paths, URLs, OAuth tokens) normalize to `"Unknown"`
        for sensitive_model in [
            "alice@example.com",
            "/home/alice/.gemini/secret.db",
            "https://example.com/oauth?code=4/abc",
            "1//0gSuperSecretRefreshTokenValue",
            "ya29.a0AfH6SMBxSecretAccessToken",
        ] {
            let blob = make_gen_blob(
                10,
                20,
                30,
                0,
                Some(ts),
                sensitive_model,
                Some(sensitive_model),
            );
            let ev = decode_generation_event(&blob, None).unwrap();
            assert_eq!(
                ev.model, "Unknown",
                "leaked untrusted model string: {sensitive_model}"
            );
        }

        // 5. `collect_token_stats` error on symlinked home_dir MUST NOT echo local filesystem path
        let tmp = tempfile::tempdir().unwrap();
        let real_home = tmp.path().join("real_secret_home_dir_name");
        fs::create_dir_all(&real_home).unwrap();
        let sym_home = tmp.path().join("sym_home_secret_name");
        std::os::unix::fs::symlink(&real_home, &sym_home).unwrap();
        let paths = HeadlessPaths::with_explicit(
            sym_home,
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let err = collect_token_stats(
            &paths,
            &StatsArgs {
                source: CliStatsSource::Cli,
                range: None,
                date: None,
                from: None,
                to: None,
                recent: None,
                watch: None,
            },
        )
        .unwrap_err();
        assert!(
            !err.message.contains("sym_home_secret_name"),
            "{}",
            err.message
        );
        assert!(
            !err.message.contains("real_secret_home_dir_name"),
            "{}",
            err.message
        );

        for extra_untrusted in [
            "model /root/.gemini/antigravity-oauth-token",
            "go-keyring-base64:eyJ0b2tlbiI6MTIzfQ",
            "file:/tmp/secret-path.db",
            "unix:/run/user/1000/bus",
        ] {
            let b = make_gen_blob(
                10,
                20,
                30,
                0,
                Some(ts),
                extra_untrusted,
                Some(extra_untrusted),
            );
            let ev = decode_generation_event(&b, None).unwrap();
            assert_eq!(ev.model, "Unknown", "leaked {extra_untrusted}");
        }
    }

    #[test]
    fn concurrent_wal_checkpoint_truncation_and_multipage_shm_remain_zero_write_and_consistent() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cli_conv).unwrap();

        let ts = "2026-11-17T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let now = "2026-11-17T18:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::UTC);
        let spec = StatsRangeSpec::SingleDate { date: now.date() };

        // 1. Multi-page `-shm` WAL (`page_size = 512` + >4,200 frames -> forces `i_pg = 1` in `walHashGet`)
        let multipg_db = cli_conv.join("multipage_shm.db");
        let mp_conn = Connection::open(&multipg_db).unwrap();
        mp_conn
            .execute_batch(
                "PRAGMA page_size = 512;
                 PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE filler (id INTEGER PRIMARY KEY, pad BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        mp_conn.execute_batch("BEGIN;").unwrap();
        let pad_480 = vec![0xAB_u8; 480];
        for i in 1..=4300_i64 {
            mp_conn
                .execute(
                    "INSERT INTO filler VALUES (?1, ?2)",
                    rusqlite::params![i, &pad_480],
                )
                .unwrap();
        }
        mp_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(
                    15,
                    85,
                    55,
                    100,
                    Some(ts),
                    "m-mp",
                    Some("MultiPage SHM Model")
                )],
            )
            .unwrap();
        mp_conn.execute_batch("COMMIT;").unwrap();

        let mp_shm_path = cli_conv.join("multipage_shm.db-shm");
        assert!(
            fs::metadata(&mp_shm_path).unwrap().len() >= 65_536,
            "Expected >= 2 SHM regions (64 KiB)"
        );
        let mp_shm_before = fs::read(&mp_shm_path).unwrap();

        let mp_stats = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
        assert_eq!(mp_stats.unreadable_databases, 0);
        assert_eq!(mp_stats.summary.request_count, 1);
        assert_eq!(mp_stats.summary.total_output_tokens, 55);
        assert_eq!(fs::read(&mp_shm_path).unwrap(), mp_shm_before);
        drop(mp_conn);
        fs::remove_file(&multipg_db).unwrap();

        // 2. Concurrent writer + checkpointer + close/reopen race loop against `"agy_pinned_ro"` reader
        let race_db = cli_conv.join("race.db");
        {
            let init = Connection::open(&race_db).unwrap();
            init.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
            let init_step = pb_bytes(1, &pb_varint(1, ts));
            init.execute(
                "INSERT INTO steps VALUES (1, 15, ?1)",
                rusqlite::params![init_step],
            )
            .unwrap();
            init.execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(10, 40, 20, 0, None, "m-race", None)],
            )
            .unwrap();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = Arc::clone(&stop);
        let race_db_w = race_db.clone();
        let writer = std::thread::spawn(move || {
            let mut next_idx = 2_i64;
            while !stop_w.load(Ordering::Relaxed) {
                let conn = Connection::open(&race_db_w).unwrap();
                conn.busy_timeout(Duration::from_secs(2)).unwrap();
                let _ = conn.execute_batch("PRAGMA wal_autocheckpoint = 0;");
                for sub in 0..8 {
                    if stop_w.load(Ordering::Relaxed) {
                        break;
                    }
                    let step_meta = pb_bytes(1, &pb_varint(1, ts + next_idx as u64));
                    let gen_blob = make_gen_blob(10, 40, 20, 0, None, "m-race", None);
                    conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
                    conn.execute(
                        "INSERT INTO steps VALUES (?1, 15, ?2)",
                        rusqlite::params![next_idx, step_meta],
                    )
                    .unwrap();
                    conn.execute(
                        "INSERT INTO gen_metadata VALUES (?1, ?2)",
                        rusqlite::params![next_idx, gen_blob],
                    )
                    .unwrap();
                    conn.execute_batch("COMMIT;").unwrap();
                    next_idx += 1;
                    if sub == 3 {
                        let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
                    } else if sub == 7 {
                        let _ = conn.execute_batch("PRAGMA wal_checkpoint(RESTART);");
                    }
                }
                drop(conn);
            }
            next_idx - 1
        });

        let mut prev_reqs = 1_u64;
        for iter_i in 0..60 {
            let s = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
            if s.unreadable_databases != 0 || s.summary.request_count < prev_reqs {
                stop.store(true, Ordering::Relaxed);
                let _ = writer.join();
                panic!(
                    "iter={iter_i}: unreadable={} dbs={} gens={} reqs={} prev_reqs={}",
                    s.unreadable_databases,
                    s.databases_scanned,
                    s.generations_scanned,
                    s.summary.request_count,
                    prev_reqs
                );
            }
            assert_eq!(s.summary.total_output_tokens, s.summary.request_count * 20);
            prev_reqs = s.summary.request_count;
        }
        stop.store(true, Ordering::Relaxed);
        let final_committed = writer.join().unwrap() as u64;

        let final_stats = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
        assert_eq!(final_stats.unreadable_databases, 0);
        assert_eq!(final_stats.summary.request_count, final_committed);
        assert!(!cli_conv.join("race.db-wal").exists());
        assert!(!cli_conv.join("race.db-shm").exists());
    }

    #[test]
    fn performance_quantiles_filter_retries_tool_calls_corrupt_frames_and_archived_live_timings() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        let app_conv = home.join(".gemini/antigravity/conversations");
        fs::create_dir_all(&cli_conv).unwrap();
        fs::create_dir_all(&app_conv).unwrap();

        let tz = jiff::tz::TimeZone::UTC;
        let now = "2026-11-18T16:45:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(tz);
        let ts_today = "2026-11-18T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let ts_old = "2026-11-01T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        let make_text_step_payload = |stop: u64, with_tool: bool| -> Vec<u8> {
            let mut resp = [pb_bytes(1, b"synthetic response body"), pb_varint(12, stop)].concat();
            if with_tool {
                resp.extend(pb_bytes(7, b""));
            }
            pb_bytes(20, &resp)
        };

        let make_perf_blob = |out_tok: u64,
                              ttft_ms: u64,
                              stream_ms: u64,
                              retries: Option<u64>,
                              ts: u64,
                              label: &str|
         -> Vec<u8> {
            let usage = [
                pb_varint(1, 500),
                pb_varint(2, 1_500),
                pb_varint(3, out_tok),
                pb_varint(5, 8_000),
                pb_varint(9, 300),
                pb_varint(10, 0), // Even with 0 prose body tokens (pure thinking + tool_calls), `usage.3` drives TPS!
            ]
            .concat();
            let ttft_dur = [
                pb_varint(1, ttft_ms / 1000),
                pb_varint(2, (ttft_ms % 1000) * 1_000_000),
            ]
            .concat();
            let stream_dur = [
                pb_varint(1, stream_ms / 1000),
                pb_varint(2, (stream_ms % 1000) * 1_000_000),
            ]
            .concat();
            let timing = pb_bytes(4, &pb_varint(1, ts));
            let mut wrapped = [
                pb_bytes(4, &usage),
                pb_bytes(9, &timing),
                pb_bytes(11, &ttft_dur),
                pb_bytes(12, &stream_dur),
                pb_bytes(19, b"gemini-4-carbon"),
                pb_bytes(21, label.as_bytes()),
            ]
            .concat();
            if let Some(r) = retries {
                wrapped.extend(pb_varint(14, r));
            }
            pb_bytes(1, &wrapped)
        };

        // 1. Direct unit checks on `is_valid_step_payload_framing`, `is_tps_eligible_step`, and corrupt submessage frames
        assert!(is_valid_step_payload_framing(&make_text_step_payload(
            2, false
        )));
        assert!(is_valid_step_payload_framing(&make_text_step_payload(
            1, true
        )));
        let mut corrupt_payload = make_text_step_payload(2, false);
        corrupt_payload.push(0x80);
        assert!(!is_valid_step_payload_framing(&corrupt_payload));

        // Split corrupt `response` fragments (`[0x08]` + `[0x01]`) MUST fail closed
        let split_bad_step = [pb_bytes(20, &[0x08]), pb_bytes(20, &[0x01])].concat();
        assert!(!is_valid_step_payload_framing(&split_bad_step));

        let sample_ok_blob = make_perf_blob(100, 1_000, 1_000, None, ts_today, "Gemini 4");
        let step_with_status = |st: StepStatusValue, ps: StepPayloadState| StepGenInfo {
            timestamp: None,
            status: st,
            payload_state: ps,
        };
        assert!(is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(3), StepPayloadState::Valid),
            &sample_ok_blob
        ));
        assert!(is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(3), StepPayloadState::Absent),
            &sample_ok_blob
        ));
        assert!(is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(5), StepPayloadState::Valid),
            &sample_ok_blob
        ));
        assert!(is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(5), StepPayloadState::Absent),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(5), StepPayloadState::Invalid),
            &sample_ok_blob
        ));
        let mut sample_err_blob = sample_ok_blob.clone();
        sample_err_blob.extend(pb_bytes(5, b"synthetic upstream error"));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(5), StepPayloadState::Valid),
            &sample_err_blob
        ));
        assert_eq!(
            classify_live_step_status(StepStatusValue::Known(5), &sample_ok_blob),
            StatsCallStatus::Cleared
        );
        assert_eq!(
            classify_live_step_status(StepStatusValue::Known(5), &sample_err_blob),
            StatsCallStatus::Error
        );
        assert_eq!(
            classify_live_step_status(StepStatusValue::Known(6), &sample_ok_blob),
            StatsCallStatus::Canceled
        );
        assert_eq!(
            classify_live_step_status(StepStatusValue::Known(12), &sample_ok_blob),
            StatsCallStatus::Interrupted
        );
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(3), StepPayloadState::Invalid),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Absent, StepPayloadState::Absent),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(99), StepPayloadState::Valid),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::InvalidType, StepPayloadState::Valid),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(1), StepPayloadState::Valid),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(6), StepPayloadState::Valid),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(12), StepPayloadState::Valid),
            &sample_ok_blob
        ));
        assert!(!is_tps_eligible_step(
            step_with_status(StepStatusValue::Known(7), StepPayloadState::Valid),
            &sample_ok_blob
        ));

        // 2. Populate CLI live DB with 9 eligible samples (`i = 1..=9`, including short replies & tool-call steps!),
        //    PLUS excluded rows:
        //    - `retries = 2` (backoff-polluted TTFT = 999s) -> MUST be excluded!
        //    - `streaming_duration = 200ms < 300ms` -> MUST be excluded!
        //    - `status = 7` (error step) -> MUST be excluded!
        //    - corrupt `step_payload` framing -> MUST be excluded!
        //    - out-of-range old date (`2026-11-01`) -> MUST be excluded!
        let cli_conn = Connection::open(cli_conv.join("perf_cli.db")).unwrap();
        cli_conn
            .execute_batch(
                "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();

        // Insert 9 eligible CLI samples: TTFT = 1.0s..=9.0s, TPS = 10.0..=90.0 t/s
        // (`i = 1` tests short reply `out = 10, stream = 1_000ms -> 10.0 t/s`; `i = 2` tests tool-call step with `stop = 1`!)
        for i in 1..=9_u64 {
            let step_meta = pb_bytes(1, &pb_varint(1, ts_today + i));
            let payload = if i == 2 {
                make_text_step_payload(1, true)
            } else {
                make_text_step_payload(2, false)
            };
            cli_conn
                .execute(
                    "INSERT INTO steps VALUES (?1, 15, ?2, 3, ?3)",
                    rusqlite::params![i as i64, step_meta, payload],
                )
                .unwrap();
            let (out_tok, stream_ms) = if i == 1 {
                (10, 1_000) // 10 tokens / 1.0s (>= 1.0s) == 10.0 t/s!
            } else {
                (200 * i, 20_000)
            };
            let blob = make_perf_blob(
                out_tok,
                i * 1000,
                stream_ms,
                Some(0),
                ts_today + i,
                "Gemini 4 Carbon (High)",
            );
            cli_conn
                .execute(
                    "INSERT INTO gen_metadata VALUES (?1, ?2)",
                    rusqlite::params![i as i64, blob],
                )
                .unwrap();
        }

        // Excluded row A: `retries = 2` with 999s TTFT
        cli_conn
            .execute(
                "INSERT INTO steps VALUES (20, 15, NULL, 3, ?1)",
                rusqlite::params![make_text_step_payload(2, false)],
            )
            .unwrap();
        cli_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (20, ?1)",
                rusqlite::params![make_perf_blob(
                    500,
                    999_000,
                    5_000,
                    Some(2),
                    ts_today + 20,
                    "Gemini 4 Carbon (High)"
                )],
            )
            .unwrap();

        // Excluded row B: error status (`status = 7`)
        cli_conn
            .execute(
                "INSERT INTO steps VALUES (21, 15, NULL, 7, ?1)",
                rusqlite::params![make_text_step_payload(2, false)],
            )
            .unwrap();
        cli_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (21, ?1)",
                rusqlite::params![make_perf_blob(
                    500,
                    888_000,
                    5_000,
                    None,
                    ts_today + 21,
                    "Gemini 4 Carbon (High)"
                )],
            )
            .unwrap();

        // Excluded row C: corrupt `step_payload` wire frame
        cli_conn
            .execute(
                "INSERT INTO steps VALUES (22, 15, NULL, 3, ?1)",
                rusqlite::params![&corrupt_payload],
            )
            .unwrap();
        cli_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (22, ?1)",
                rusqlite::params![make_perf_blob(
                    80,
                    777_000,
                    5_000,
                    None,
                    ts_today + 22,
                    "Gemini 4 Carbon (High)"
                )],
            )
            .unwrap();

        // Excluded row D: `streaming_duration = 800ms < 1.0s`
        cli_conn
            .execute(
                "INSERT INTO steps VALUES (23, 15, NULL, 3, ?1)",
                rusqlite::params![make_text_step_payload(2, false)],
            )
            .unwrap();
        cli_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (23, ?1)",
                rusqlite::params![make_perf_blob(
                    500,
                    666_000,
                    800,
                    None,
                    ts_today + 23,
                    "Gemini 4 Carbon (High)"
                )],
            )
            .unwrap();

        // Excluded row E: outside selected 7d range (`2026-11-01`)
        cli_conn
            .execute(
                "INSERT INTO steps VALUES (24, 15, NULL, 3, ?1)",
                rusqlite::params![make_text_step_payload(2, false)],
            )
            .unwrap();
        cli_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (24, ?1)",
                rusqlite::params![make_perf_blob(
                    500,
                    555_000,
                    5_000,
                    None,
                    ts_old,
                    "Gemini 4 Carbon (High)"
                )],
            )
            .unwrap();
        drop(cli_conn);

        // 3. Populate App live DB + `token_usage_archive.db` for 10th sample (`TTFT = 10.0s`, `TPS = 100.0 t/s`):
        //    Token usage IS archived in `token_usage_archive.db`, yet live `.db` MUST still contribute the 10th timing sample
        //    without double-counting tokens!
        let app_conn = Connection::open(app_conv.join("perf_app.db")).unwrap();
        app_conn
            .execute_batch(
                "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        app_conn
            .execute(
                "INSERT INTO steps VALUES (1, 15, NULL, 3, ?1)",
                rusqlite::params![make_text_step_payload(2, false)],
            )
            .unwrap();
        app_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (7, ?1)",
                rusqlite::params![make_perf_blob(
                    2_000,
                    10_000,
                    20_000,
                    None,
                    ts_today + 30,
                    "Gemini 4 Hydrogen (XHigh)"
                )],
            )
            .unwrap();
        drop(app_conn);

        let arch_conn =
            Connection::open(home.join(".gemini/antigravity/token_usage_archive.db")).unwrap();
        arch_conn
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT NOT NULL,
                    generation_idx INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL,
                    model TEXT,
                    input_tokens TEXT,
                    output_tokens TEXT,
                    cached_tokens TEXT,
                    total_tokens TEXT,
                    timestamp_seconds INTEGER,
                    valid INTEGER NOT NULL,
                    oversized INTEGER NOT NULL,
                    PRIMARY KEY (source_key, generation_idx)
                 );",
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/perf_app.db', 7, 0, 'Gemini 4 Hydrogen (XHigh)', '2000', '2300', '8000', '12300', ?1, 1, 0)",
                rusqlite::params![(ts_today + 30) as i64],
            )
            .unwrap();
        drop(arch_conn);

        let range_7d = StatsRangeSpec::Preset {
            preset: StatsPresetRange::Days(7),
            from: "2026-11-12".parse().unwrap(),
            to: "2026-11-18".parse().unwrap(),
        };
        let all_view = collect_token_stats_at(&home, StatsSource::All, &range_7d, &now);
        assert_eq!(all_view.databases_scanned, 2);
        // 9 eligible CLI + 4 excluded-perf CLI today + 1 archived App today = 14 requests in range (no double-count!)
        assert_eq!(all_view.summary.request_count, 14);

        let perf = all_view
            .performance
            .as_ref()
            .expect("Expected 10 eligible perf samples");
        assert_eq!(perf.sample_count, 10);
        assert_eq!(perf.model_count, 2);
        assert_eq!(perf.source_count, 2);
        // Samples TTFT = [1.0, 2.0, ..., 10.0] -> P10 = 1.9, P50 = 5.5, P90 = 9.1
        assert!((perf.ttft_seconds.p10 - 1.9).abs() < 1e-9);
        assert!((perf.ttft_seconds.p50 - 5.5).abs() < 1e-9);
        assert!((perf.ttft_seconds.p90 - 9.1).abs() < 1e-9);
        // Samples TPS = [10.0, 20.0, ..., 100.0] -> P10 = 19.0, P50 = 55.0, P90 = 91.0
        assert!((perf.output_tps.p10 - 19.0).abs() < 1e-9);
        assert!((perf.output_tps.p50 - 55.0).abs() < 1e-9);
        assert!((perf.output_tps.p90 - 91.0).abs() < 1e-9);

        // 4. Verify responsive rendering across wide (`120`, `90`) and narrow (`80`, `68`, `48`) terminal widths!
        let wide_120 = all_view.render_human_for_width(Some(120));
        assert!(
            wide_120.contains("Source : all (~/.gemini/antigravity-cli + ~/.gemini/antigravity)")
        );
        assert!(wide_120.contains("TTFT (P10/P50/P90) : 1.9 / 5.5 / 9.1 s"));
        assert!(wide_120.contains("TPS (P10/P50/P90) : 19.0 / 55.0 / 91.0 t/s"));
        // Models table renders 7 columns (`Model`, `Reqs`, `Input` [Total Input], `Cached`, `Hit%`, `Output`, `Total`)!
        assert!(wide_120.contains("Cached") && wide_120.contains("Hit%"));
        let hdr_line = wide_120
            .lines()
            .find(|l| l.trim_start().starts_with("Model "))
            .unwrap();
        assert!(hdr_line.find("Cached").unwrap() < hdr_line.find("Hit%").unwrap());
        assert!(hdr_line.find("Hit%").unwrap() < hdr_line.find("Output").unwrap());
        // Each row in `perf_cli` has `2,000` uncached + `8,000` cached = `10,000` total input (13 rows = `130,000` Input, `104,000` Cached, `80.0%` Hit%)!
        assert!(wide_120.contains("130,000") && wide_120.contains("80.0%"));
        assert!(!wide_120.contains("Duration"));
        assert!(!wide_120.contains("In TPS"));

        let narrow_80 = all_view.render_human_for_width(Some(80));
        assert!(narrow_80.contains("Source : all · 2 db(s)"));
        assert!(narrow_80.contains("\n  Total input        : "));
        assert!(narrow_80.contains("\n  Total output       : "));
        assert!(narrow_80.contains("\n  TTFT (P10/P50/P90) : 1.9 / 5.5 / 9.1 s\n"));
        assert!(narrow_80.contains("\n  TPS (P10/P50/P90)  : 19.0 / 55.0 / 91.0 t/s\n"));
        assert!(narrow_80.contains("K")); // compact K/M units in narrow Models table

        for cols in [120usize, 90, 80, 68, 48] {
            let out = all_view.render_human_for_width(Some(cols));
            for line in out.lines() {
                assert!(
                    UnicodeWidthStr::width(line) <= cols,
                    "Line exceeded {cols} cols ({} > {cols}): {line}",
                    UnicodeWidthStr::width(line)
                );
            }
        }
    }

    #[test]
    fn bad_utf8_archive_row_preserves_sibling_history_and_live_fallback_while_rejecting_relative_paths_and_null_gen_mispair(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let app_conv = home.join(".gemini/antigravity/conversations");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&app_conv).unwrap();
        fs::create_dir_all(&cli_conv).unwrap();

        let tz = jiff::tz::TimeZone::UTC;
        let now = "2026-11-18T16:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(tz);
        let ts = "2026-11-18T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let spec = StatsRangeSpec::SingleDate { date: now.date() };

        // 1. Live `app_live.db` has 5 valid requests (`idx = 1..=5`), including `idx = 5` that will have
        //    invalid UTF-8 `TEXT` in `token_usage_archive.db` -> live fallback MUST rescue `idx = 5`!
        let live_conn = Connection::open(app_conv.join("app_live.db")).unwrap();
        live_conn
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        for idx in 1..=5_i64 {
            live_conn
                .execute(
                    "INSERT INTO gen_metadata VALUES (?1, ?2)",
                    rusqlite::params![
                        idx,
                        make_gen_blob(
                            10,
                            40,
                            20,
                            0,
                            Some(ts),
                            "gemini-4-carbon",
                            Some("Gemini 4 Carbon")
                        )
                    ],
                )
                .unwrap();
        }
        drop(live_conn);

        // 2. Archive has:
        //    - Valid archived-only row (`idx = 1` on `old_only.db`, `total_tokens = NULL`) with relative-path model `fixtures/private.db` -> MUST count as 1 request with model `"Unknown"`!
        //    - Invalid-UTF8 `TEXT` (`CAST(X'FFFE' AS TEXT)`) on `app_live.db` `idx = 5` AND on `bad_src.db` -> MUST NOT abort query, MUST keep `unreadable_databases == 0`, and MUST preserve `old_only.db` + live `idx = 5` (total 6 requests)!
        //    - Oversized raw `source_key` in an unindexed archive table -> MUST be filtered in `WHERE` without blowing up memory sorter!
        let arch_conn =
            Connection::open(home.join(".gemini/antigravity/token_usage_archive.db")).unwrap();
        arch_conn
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT,
                    generation_idx INTEGER,
                    ordinal INTEGER,
                    model TEXT,
                    input_tokens TEXT,
                    output_tokens TEXT,
                    cached_tokens TEXT,
                    total_tokens TEXT,
                    timestamp_seconds INTEGER,
                    valid INTEGER,
                    oversized INTEGER
                 );",
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/old_only.db', 1, 0, 'fixtures/private.db', '100', '30', '50', NULL, ?1, 1, 0)",
                rusqlite::params![ts as i64],
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/app_live.db', 5, 0, CAST(X'FFFE' AS TEXT), '100', '30', '50', NULL, ?1, 1, 0)",
                rusqlite::params![ts as i64],
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES (CAST(X'80FF' AS TEXT), 9, 0, 'Gemini 4', '10', '10', '0', NULL, ?1, 1, 0)",
                rusqlite::params![ts as i64],
            )
            .unwrap();
        let huge_key = "a".repeat(4096);
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES (?1, 10, 0, 'Gemini 4', '10', '10', '0', NULL, ?2, 1, 0)",
                rusqlite::params![huge_key, ts as i64],
            )
            .unwrap();
        drop(arch_conn);

        let app_stats = collect_token_stats_at(&home, StatsSource::App, &spec, &now);
        assert_eq!(app_stats.unreadable_databases, 0);
        assert_eq!(app_stats.summary.request_count, 6);
        assert!(
            app_stats
                .models
                .iter()
                .any(|m| m.model == "Unknown" && m.request_count == 1),
            "Relative path `fixtures/private.db` MUST map to `Unknown`, got {:?}",
            app_stats.models
        );
        assert!(
            !app_stats
                .models
                .iter()
                .any(|m| m.model.contains("private") || m.model.contains('/')),
            "Leaked path-shaped model name: {:?}",
            app_stats.models
        );

        // Additional relative-path, full-width, IPv4, & filename syntax checks for `classify_model_name`
        for untrusted in [
            "fixtures/private.db",
            "fixtures／private",
            "alice＠example",
            "192.168.1.1",
            "123456",
            "sub/dir/secret",
            "private.db",
            "config.json",
            ".env",
            "--secret-flag",
            "C:\\Users\\alice\\token",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ] {
            assert_eq!(
                classify_model_name(untrusted),
                ModelNameClass::RejectedUntrusted,
                "Expected `{untrusted}` to be rejected as untrusted"
            );
        }

        // 3. Explicit `NULL` `gen_metadata.data` at ordinal 0 (and non-integer `idx` garbage in untyped table)
        //    MUST NOT pair ordinal 1's perf metadata with step 0!
        let step_done_payload = pb_bytes(
            20,
            &[pb_bytes(1, b"completed body"), pb_varint(12, 2)].concat(),
        );
        let perf_usage = [
            pb_varint(1, 100),
            pb_varint(2, 200),
            pb_varint(3, 250),
            pb_varint(5, 0),
            pb_varint(10, 200),
        ]
        .concat();
        let perf_wrapped = [
            pb_bytes(4, &perf_usage),
            pb_bytes(9, &pb_bytes(4, &pb_varint(1, ts))),
            pb_bytes(11, &pb_varint(1, 2)),
            pb_bytes(12, &pb_varint(1, 5)),
            pb_bytes(19, b"gemini-4-carbon"),
            pb_bytes(21, b"Gemini 4 Carbon"),
        ]
        .concat();
        let perf_blob = pb_bytes(1, &perf_wrapped);

        let null_db = cli_conv.join("null_ordinal.db");
        let nconn = Connection::open(&null_db).unwrap();
        nconn
            .execute_batch(
                "CREATE TABLE steps (idx, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
                 CREATE TABLE gen_metadata (idx, data BLOB);",
            )
            .unwrap();
        // Step 1 (`ordinal = 0`) is completed (`status = 3`), Step 2 (`ordinal = 1`) is incomplete (`status = 1`)!
        nconn
            .execute(
                "INSERT INTO steps VALUES (1, 15, ?1, 3, ?2)",
                rusqlite::params![pb_bytes(1, &pb_varint(1, ts)), &step_done_payload],
            )
            .unwrap();
        nconn
            .execute(
                "INSERT INTO steps VALUES (2, 15, ?1, 1, ?2)",
                rusqlite::params![pb_bytes(1, &pb_varint(1, ts + 1)), &step_done_payload],
            )
            .unwrap();
        // Non-integer `idx` row MUST be ignored without shifting `generation_ordinal`!
        nconn
            .execute("INSERT INTO gen_metadata VALUES ('bad-idx', NULL)", [])
            .unwrap();
        // `gen_metadata` row 1 (`ordinal = 0`) has `data = NULL`, row 2 (`ordinal = 1`) has `perf_blob`!
        nconn
            .execute("INSERT INTO gen_metadata VALUES (1, NULL)", [])
            .unwrap();
        nconn
            .execute(
                "INSERT INTO gen_metadata VALUES (2, ?1)",
                rusqlite::params![&perf_blob],
            )
            .unwrap();
        drop(nconn);

        let cli_null_stats = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
        assert_eq!(cli_null_stats.summary.request_count, 1);
        assert!(
            cli_null_stats.performance.is_none(),
            "NULL gen_metadata.data at ordinal 0 MUST NOT mispair ordinal 1 with completed step 0: {:?}",
            cli_null_stats.performance
        );

        // Replacing row 1's `NULL` with empty BLOB `X''` produces the exact same 1 request and `None` performance!
        let nconn2 = Connection::open(&null_db).unwrap();
        nconn2
            .execute("UPDATE gen_metadata SET data = X'' WHERE idx = 1", [])
            .unwrap();
        drop(nconn2);
        let cli_empty_stats = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
        assert_eq!(cli_empty_stats.summary.request_count, 1);
        assert!(cli_empty_stats.performance.is_none());

        // 4. Two 36 MiB valid blobs (`72 MiB > 64 MiB` `MemoryTemp` cap!) in `INTEGER PRIMARY KEY` `gen_metadata`
        //    stream directly via primary-key scan without spilling to `MemoryTemp` (`unreadable_databases == 0`)!
        let big_home = tmp.path().join("big_home");
        let big_conv = big_home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&big_conv).unwrap();
        let big_conn = Connection::open(big_conv.join("two_36m.db")).unwrap();
        big_conn
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        let mut big_blob = make_gen_blob(
            10,
            40,
            25,
            0,
            Some(ts),
            "gemini-4-carbon",
            Some("Gemini 4 Carbon"),
        );
        big_blob.extend(pb_bytes(99, &vec![0x41_u8; 36 * 1024 * 1024]));
        big_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![&big_blob],
            )
            .unwrap();
        big_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (2, ?1)",
                rusqlite::params![&big_blob],
            )
            .unwrap();
        drop(big_conn);
        let big_stats = collect_token_stats_at(&big_home, StatsSource::Cli, &spec, &now);
        assert_eq!(
            big_stats.unreadable_databases, 0,
            "Primary-key `ORDER BY idx` must stream two 36 MiB blobs without temp-sorter SQLITE_FULL!"
        );
        assert_eq!(big_stats.summary.request_count, 2);

        // 5. Deterministic thread-local `readdir` I/O error injection increments `unreadable_databases`
        //    without ever leaking to concurrent reader threads!
        struct ResetReaddirErrno;
        impl Drop for ResetReaddirErrno {
            fn drop(&mut self) {
                TEST_INJECT_READDIR_ERRNO.with(|c| c.set(0));
            }
        }
        let _reset_errno = ResetReaddirErrno;
        TEST_INJECT_READDIR_ERRNO.with(|c| c.set(libc::EIO));

        let big_home_bg = big_home.clone();
        let spec_bg = spec.clone();
        let now_bg = now.clone();
        let sibling_reader = std::thread::spawn(move || {
            let s = collect_token_stats_at(&big_home_bg, StatsSource::Cli, &spec_bg, &now_bg);
            assert_eq!(s.unreadable_databases, 0);
            assert_eq!(s.summary.request_count, 2);
        });
        sibling_reader.join().unwrap();

        let eio_stats = collect_token_stats_at(&home, StatsSource::Cli, &spec, &now);
        assert_eq!(eio_stats.unreadable_databases, 1);
    }

    #[test]
    fn mid_query_cohort_change_corrupt_err_retries_cleanly_while_static_corrupt_fails_immediately()
    {
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("conv");
        fs::create_dir_all(&dir).unwrap();

        // 1. Mid-query torn-read simulation: if `scan_fn` returns `SQLITE_CORRUPT` BEFORE reaching its
        //    end-of-tx `verify_snapshot_consistent()` because a concurrent writer modified/checkpointed
        //    the cohort, `scan_with_bounded_retry` MUST run `verify_snapshot_consistent()` on the `Err`
        //    path, detect `saw_cohort_change()`, and retry cleanly to `100`!
        let db_path = dir.join("torn_mid_scan.db");
        {
            let wconn = Connection::open(&db_path).unwrap();
            wconn
                .execute_batch(
                    "PRAGMA journal_mode = WAL;
                     CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);
                     INSERT INTO items VALUES (1, 88);",
                )
                .unwrap();
        }

        let dir_fd = open_existing_dir_nofollow(&dir).unwrap().unwrap();
        let mut seen = HashSet::new();
        let mut calls = 0usize;
        let outcome =
            scan_with_bounded_retry(&dir_fd, OsStr::new("torn_mid_scan.db"), &mut seen, |p| {
                calls += 1;
                if calls == 1 {
                    let tx = p.conn().unchecked_transaction()?;
                    let _first: i64 =
                        tx.query_row("SELECT val FROM items WHERE id = 1", [], |r| r.get(0))?;
                    drop(tx);
                    // Concurrent writer commits row 2 and checkpoints `torn_mid_scan.db` mid-scan,
                    // and query fails with `SQLITE_CORRUPT` before `scan_fn` reaches `verify_snapshot_consistent()`!
                    let live_w = Connection::open(&db_path).unwrap();
                    live_w
                        .execute("INSERT INTO items VALUES (2, 12)", [])
                        .unwrap();
                    drop(live_w);
                    return Err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error {
                            code: rusqlite::ErrorCode::DatabaseCorrupt,
                            extended_code: rusqlite::ffi::SQLITE_CORRUPT,
                        },
                        None,
                    ));
                }
                let sum: i64 = p
                    .conn()
                    .query_row("SELECT SUM(val) FROM items", [], |r| r.get(0))?;
                p.verify_snapshot_consistent()?;
                Ok(sum)
            });
        let RetryScanOutcome::Scanned(sum) = outcome else {
            panic!("expected mid-query cohort-change SQLITE_CORRUPT to retry and succeed");
        };
        assert_eq!(calls, 2);
        assert_eq!(sum, 100);

        // 2. Static unchanged database returning `SQLITE_CORRUPT` MUST fail immediately on attempt 0
        //    (`static_calls == 1`, zero retry spin)!
        let mut seen_static = HashSet::new();
        let mut static_calls = 0usize;
        let static_outcome: RetryScanOutcome<()> = scan_with_bounded_retry(
            &dir_fd,
            OsStr::new("torn_mid_scan.db"),
            &mut seen_static,
            |_p| {
                static_calls += 1;
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::DatabaseCorrupt,
                        extended_code: rusqlite::ffi::SQLITE_CORRUPT,
                    },
                    None,
                ))
            },
        );
        assert!(matches!(static_outcome, RetryScanOutcome::Unreadable));
        assert_eq!(static_calls, 1);

        // 3. Multi-reader (4 reader threads) + active WAL writer close/reopen/checkpoint contention
        let storm_home = tmp.path().join("storm_home");
        let storm_conv = storm_home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&storm_conv).unwrap();
        let ts = "2026-11-18T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let now = "2026-11-18T18:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::UTC);
        let spec = StatsRangeSpec::SingleDate { date: now.date() };

        let storm_db = storm_conv.join("storm.db");
        {
            let init = Connection::open(&storm_db).unwrap();
            init.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
            init.execute(
                "INSERT INTO steps VALUES (1, 15, ?1)",
                rusqlite::params![pb_bytes(1, &pb_varint(1, ts))],
            )
            .unwrap();
            init.execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_gen_blob(10, 40, 20, 0, None, "m-storm", None)],
            )
            .unwrap();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = Arc::clone(&stop);
        let storm_db_w = storm_db.clone();
        let writer = std::thread::spawn(move || {
            let mut next_idx = 2_i64;
            while !stop_w.load(Ordering::Relaxed) {
                let conn = Connection::open(&storm_db_w).unwrap();
                conn.busy_timeout(Duration::from_secs(2)).unwrap();
                let _ = conn.execute_batch("PRAGMA wal_autocheckpoint = 0;");
                for sub in 0..6 {
                    if stop_w.load(Ordering::Relaxed) {
                        break;
                    }
                    let step_meta = pb_bytes(1, &pb_varint(1, ts + next_idx as u64));
                    let gen_blob = make_gen_blob(10, 40, 20, 0, None, "m-storm", None);
                    conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
                    conn.execute(
                        "INSERT INTO steps VALUES (?1, 15, ?2)",
                        rusqlite::params![next_idx, step_meta],
                    )
                    .unwrap();
                    conn.execute(
                        "INSERT INTO gen_metadata VALUES (?1, ?2)",
                        rusqlite::params![next_idx, gen_blob],
                    )
                    .unwrap();
                    conn.execute_batch("COMMIT;").unwrap();
                    next_idx += 1;
                    if sub == 2 {
                        let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
                    } else if sub == 5 {
                        let _ = conn.execute_batch("PRAGMA wal_checkpoint(RESTART);");
                    }
                }
                drop(conn);
            }
        });

        let mut readers = Vec::new();
        for _ in 0..4 {
            let h = storm_home.clone();
            let sp = spec.clone();
            let nw = now.clone();
            readers.push(std::thread::spawn(move || {
                let mut prev = 1_u64;
                for _ in 0..35 {
                    let s = collect_token_stats_at(&h, StatsSource::Cli, &sp, &nw);
                    assert_eq!(s.unreadable_databases, 0);
                    assert!(s.summary.request_count >= prev);
                    assert_eq!(s.summary.total_output_tokens, s.summary.request_count * 20);
                    prev = s.summary.request_count;
                }
            }));
        }
        for r in readers {
            r.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
    }

    #[test]
    fn stats_list_and_summary_recent_render_10_cols_cap_99_9_pct_hit_and_truncate_at_500() {
        // 1. 1-decimal `Hit%`: `99.9%` cap whenever `uncached_in > 0 && cached_in > 0`
        assert_eq!(compute_capped_hit_tenths(0, 0), None);
        assert_eq!(format_hit_tenths(None), "—");
        assert_eq!(compute_capped_hit_tenths(10_000, 0), Some(0));
        assert_eq!(format_hit_tenths(Some(0)), "0.0%");
        assert_eq!(compute_capped_hit_tenths(0, 50_000), Some(1000));
        assert_eq!(format_hit_tenths(Some(1000)), "100.0%");
        assert_eq!(compute_capped_hit_tenths(3_000, 584_100), Some(995)); // 99.489% -> 99.5%
        assert_eq!(format_hit_tenths(Some(995)), "99.5%");
        assert_eq!(compute_capped_hit_tenths(1, 1_000_000), Some(999)); // 99.9999% -> capped at 99.9%
        assert_eq!(format_hit_tenths(Some(999)), "99.9%");

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        let app_conv = home.join(".gemini/antigravity/conversations");
        fs::create_dir_all(&cli_conv).unwrap();
        fs::create_dir_all(&app_conv).unwrap();

        let tz = jiff::tz::TimeZone::UTC;
        let now = "2026-11-19T09:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(tz);

        let make_text_step_payload = |with_tool: bool| -> Vec<u8> {
            let mut resp = [pb_bytes(1, b"synthetic response body"), pb_varint(12, 2)].concat();
            if with_tool {
                resp.extend(pb_bytes(7, b""));
            }
            pb_bytes(20, &resp)
        };
        let make_timed_blob = |uncached: u64,
                               cached: u64,
                               out_tok: u64,
                               body_tok: u64,
                               ttft_ms: u64,
                               stream_ms: Option<u64>,
                               ts: u64,
                               model_id: &str,
                               label: &str|
         -> Vec<u8> {
            let usage = [
                pb_varint(1, 0),
                pb_varint(2, uncached),
                pb_varint(3, out_tok),
                pb_varint(5, cached),
                pb_varint(10, body_tok),
            ]
            .concat();
            let ttft_dur = [
                pb_varint(1, ttft_ms / 1000),
                pb_varint(2, (ttft_ms % 1000) * 1_000_000),
            ]
            .concat();
            let timing = pb_bytes(4, &pb_varint(1, ts));
            let mut wrapped = [
                pb_bytes(4, &usage),
                pb_bytes(9, &timing),
                pb_bytes(11, &ttft_dur),
                pb_bytes(19, model_id.as_bytes()),
                pb_bytes(21, label.as_bytes()),
            ]
            .concat();
            if let Some(sm) = stream_ms {
                let stream_dur = [
                    pb_varint(1, sm / 1000),
                    pb_varint(2, (sm % 1000) * 1_000_000),
                ]
                .concat();
                wrapped.extend(pb_bytes(12, &stream_dur));
            }
            pb_bytes(1, &wrapped)
        };

        let conn = Connection::open(cli_conv.join("list1.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();

        let t1 = "2026-11-18T22:14:10Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let t2 = "2026-11-19T00:10:05Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let t3 = "2026-11-19T01:58:23Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let t4 = "2026-11-19T08:25:28Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        // Row idx=1 (`t1`): canceled (`status = 6` -> `canc`), no streaming duration (`Dur == TTFT`)
        conn.execute("INSERT INTO steps VALUES (1, 15, NULL, 6, NULL)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![make_timed_blob(
                1_000,
                0,
                50,
                50,
                4_200,
                None,
                t1,
                "claude-sonnet-4-6",
                "Claude Sonnet 4.6"
            )],
        )
        .unwrap();

        // Row idx=2 (`t2`): error (`status = 7` -> `err`)
        conn.execute("INSERT INTO steps VALUES (2, 15, NULL, 7, NULL)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (2, ?1)",
            rusqlite::params![make_timed_blob(
                500,
                500,
                10,
                10,
                1_500,
                Some(500),
                t2,
                "claude-sonnet-4-6",
                "Claude Sonnet 4.6"
            )],
        )
        .unwrap();

        // Row idx=3 (`t3`): tool-call step (`status = 3` -> `ok`), 99.49% cache hit -> `99.5%`, `TPS = 78` (`3432 / 44.0s`)
        conn.execute(
            "INSERT INTO steps VALUES (3, 15, NULL, 3, ?1)",
            rusqlite::params![make_text_step_payload(true)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (3, ?1)",
            rusqlite::params![make_timed_blob(
                3_000,
                584_100,
                3_432,
                0,
                15_000,
                Some(44_000),
                t3,
                "gemini-pro-orchestrator-neon",
                "Gemini 4 Carbon (High)"
            )],
        )
        .unwrap();

        // Row idx=4 (`t4`): sub-second buffered arrival (`stream_ms = 800ms < 1000ms` -> `Dur = 36.9s`, `TPS = —`)
        conn.execute(
            "INSERT INTO steps VALUES (4, 15, NULL, 3, ?1)",
            rusqlite::params![make_text_step_payload(true)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (4, ?1)",
            rusqlite::params![make_timed_blob(
                591_200,
                0,
                209,
                209,
                36_100,
                Some(800),
                t4,
                "gemini-pro-orchestrator-neon",
                "Gemini 4 Carbon (High)"
            )],
        )
        .unwrap();
        drop(conn);

        // Archive-only row (`t0` on absent `old_app.db` -> `St = arch`)
        let t0 = "2026-11-18T20:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second();
        let arch_conn =
            Connection::open(home.join(".gemini/antigravity/token_usage_archive.db")).unwrap();
        arch_conn
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                    model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                    total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER
                 );",
            )
            .unwrap();
        arch_conn
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/old_app.db', 1, 0, 'Gemini 4 Carbon (High)', '0', '120', '4000', '4120', ?1, 1, 0)",
                rusqlite::params![t0],
            )
            .unwrap();
        drop(arch_conn);

        let recent_5 = StatsRangeSpec::Recent { limit: 5 };
        let list_view = collect_token_stats_list_at(&home, StatsSource::All, &recent_5, &now);
        assert_eq!(list_view.shown_count, 5);
        assert!(!list_view.truncated);
        assert_eq!(list_view.items[0].status, StatsCallStatus::Ok);
        assert_eq!(list_view.items[0].output_tps, None);
        assert_eq!(list_view.items[0].cache_hit_percent, Some(0.0));
        assert_eq!(list_view.items[1].cache_hit_percent, Some(99.5));
        assert_eq!(
            list_view.items[1].output_tps.map(|v| v.round() as u64),
            Some(78)
        );
        assert_eq!(list_view.items[2].status, StatsCallStatus::Error);
        assert_eq!(list_view.items[3].status, StatsCallStatus::Canceled);
        assert_eq!(list_view.items[4].status, StatsCallStatus::Archived);
        assert_eq!(list_view.items[4].cache_hit_percent, Some(100.0));

        // Verify wide (`95` and `120` cols) AND narrow (`80` and `72` cols) keep ALL 10 columns without overflow,
        // and `In` displays `total_input_tokens` (`3_000 + 584_100 = 587.1K`, `0 + 4_000 = 4.0K`)!
        let wide_120 = list_view.render_human_for_width(Some(120));
        assert!(
            wide_120.contains("11-19 08:25:28  Gemini 4 Carbon (High)"),
            "{wide_120}"
        );
        assert!(
            wide_120.contains("587.1K  584.1K   99.5%"),
            "Expected Total Input `587.1K` in `In` column:\n{wide_120}"
        );
        assert!(
            wide_120.contains("4.0K    4.0K  100.0%"),
            "Expected Total Input `4.0K` in `In` column for 100% cached row:\n{wide_120}"
        );
        let wide_95 = list_view.render_human_for_width(Some(95));
        assert!(
            wide_95.contains("Range  : recent 5 (2026-11-18 20:00 .. 2026-11-19 08:25)"),
            "{wide_95}"
        );
        assert!(wide_95.contains("Requests (newest first, showing 5)"));
        assert!(
            wide_95.contains("11-19 08:25:28  Gemini 4 Carbon (Hig"),
            "{wide_95}"
        );
        for line in wide_95.lines() {
            assert!(UnicodeWidthStr::width(line) <= 95, "{line}");
        }
        assert!(wide_95.contains("0.0%"), "{wide_95}");
        assert!(wide_95.contains("99.5%"), "{wide_95}");
        assert!(wide_95.contains("100.0%"), "{wide_95}");
        assert!(wide_95.contains("arch"), "{wide_95}");
        assert!(!wide_95.contains("t/s"));

        for narrow_cols in [94usize, 80, 72] {
            let narrow = list_view.render_human_for_width(Some(narrow_cols));
            for col_hdr in [
                "Time", "Model", "In", "Cache", "Hit%", "Out", "TTFT", "Dur", "TPS", "St",
            ] {
                assert!(
                    narrow.contains(col_hdr),
                    "Narrow list ({narrow_cols} cols) dropped column `{col_hdr}`:\n{narrow}"
                );
            }
            assert!(narrow.contains("11-19 08:25"), "{narrow}");
            assert!(!narrow.contains("11-19 08:25:28"), "{narrow}");
            for line in narrow.lines() {
                assert!(
                    UnicodeWidthStr::width(line) <= narrow_cols,
                    "Line exceeded {narrow_cols} cols ({}): {line}",
                    UnicodeWidthStr::width(line)
                );
            }
        }

        // Verify `stats summary --recent 2` aggregates strictly over the latest 2 calls (`idx = 4` and `idx = 3`)!
        let sum_recent_2 = collect_token_stats_at(
            &home,
            StatsSource::All,
            &StatsRangeSpec::Recent { limit: 2 },
            &now,
        );
        assert_eq!(sum_recent_2.summary.request_count, 2);
        assert_eq!(sum_recent_2.summary.uncached_input_tokens, 591_200 + 3_000);
        assert_eq!(sum_recent_2.summary.cached_input_tokens, 584_100);
        assert_eq!(sum_recent_2.summary.total_output_tokens, 209 + 3_432);
        assert_eq!(sum_recent_2.performance.as_ref().unwrap().sample_count, 1);

        // Verify date-range `stats list` caps at 500 rows with `truncated: true` when > 500 calls match!
        let cap_home = tmp.path().join("cap_home");
        let cap_conv = cap_home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cap_conv).unwrap();
        let cap_conn = Connection::open(cap_conv.join("many.db")).unwrap();
        cap_conn
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        cap_conn.execute_batch("BEGIN;").unwrap();
        for idx in 1..=505_i64 {
            let b = make_gen_blob(
                1,
                9,
                5,
                0,
                Some(t3 + idx as u64),
                "m-cap",
                Some("Cap Model"),
            );
            cap_conn
                .execute(
                    "INSERT INTO gen_metadata VALUES (?1, ?2)",
                    rusqlite::params![idx, b],
                )
                .unwrap();
        }
        cap_conn.execute_batch("COMMIT;").unwrap();
        drop(cap_conn);

        let capped_list = collect_token_stats_list_at(
            &cap_home,
            StatsSource::Cli,
            &StatsRangeSpec::AllTime,
            &now,
        );
        assert_eq!(capped_list.total_matching, 505);
        assert_eq!(capped_list.shown_count, 500);
        assert!(capped_list.truncated);
        assert_eq!(capped_list.items[0].timestamp, (t3 + 505) as i64);
        assert_eq!(capped_list.items[499].timestamp, (t3 + 6) as i64);
        let capped_human = capped_list.render_human_for_width(Some(120));
        assert!(
            capped_human.contains("showing 500 of 505 — capped at 500"),
            "{capped_human}"
        );

        let default_list_spec = resolve_stats_list_range_spec(
            &StatsArgs {
                source: CliStatsSource::Cli,
                range: None,
                date: None,
                from: None,
                to: None,
                recent: None,
                watch: None,
            },
            now.date(),
        )
        .unwrap();
        assert_eq!(default_list_spec, StatsRangeSpec::Recent { limit: 10 });
        let default_list =
            collect_token_stats_list_at(&cap_home, StatsSource::Cli, &default_list_spec, &now);
        assert_eq!(default_list.range.recent, Some(10));
        assert_eq!(default_list.shown_count, 10);
        assert_eq!(default_list.total_matching, 10);
        assert!(!default_list.truncated);
        assert_eq!(default_list.items[0].timestamp, (t3 + 505) as i64);
        assert_eq!(default_list.items[9].timestamp, (t3 + 496) as i64);

        // Verify deterministic tie-breaking and deduplication across multiple DBs (`cli` + `app` + archive)
        // when all rows share the exact same `timestamp_seconds`, and exact agreement between
        // `stats list --recent 2` and `stats summary --recent 2`!
        let tie_home = tmp.path().join("tie_home");
        let tie_cli_conv = tie_home.join(".gemini/antigravity-cli/conversations");
        let tie_app_dir = tie_home.join(".gemini/antigravity");
        let tie_app_conv = tie_app_dir.join("conversations");
        fs::create_dir_all(&tie_cli_conv).unwrap();
        fs::create_dir_all(&tie_app_conv).unwrap();
        let same_ts = t3 + 999;

        // DB 1 (`antigravity-cli/conversations/a.db`): idx=2 (out=20), idx=5 (out=50)
        let c1 = Connection::open(tie_cli_conv.join("a.db")).unwrap();
        c1.execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        c1.execute(
            "INSERT INTO gen_metadata VALUES (2, ?1)",
            rusqlite::params![make_gen_blob(10, 0, 20, 0, Some(same_ts), "m1", Some("M1"))],
        )
        .unwrap();
        c1.execute(
            "INSERT INTO gen_metadata VALUES (5, ?1)",
            rusqlite::params![make_gen_blob(10, 0, 50, 0, Some(same_ts), "m1", Some("M1"))],
        )
        .unwrap();
        drop(c1);

        // DB 2 (`antigravity/conversations/b.db`): idx=5 (also in archive -> must deduplicate to 1 row with live status `ok`!)
        let c2 = Connection::open(tie_app_conv.join("b.db")).unwrap();
        c2.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, status INTEGER);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        c2.execute("INSERT INTO steps VALUES (1, 15, 3)", [])
            .unwrap();
        c2.execute(
            "INSERT INTO gen_metadata VALUES (5, ?1)",
            rusqlite::params![make_gen_blob(10, 0, 70, 0, Some(same_ts), "m2", Some("M2"))],
        )
        .unwrap();
        drop(c2);

        // Archive DB: duplicate `(antigravity/conversations/b.db, idx=5, out=70)` + archive-only `(antigravity/conversations/z.db, idx=5, out=90)`
        let ca = Connection::open(tie_app_dir.join("token_usage_archive.db")).unwrap();
        ca.execute_batch(
            "CREATE TABLE archived_generations (
                source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER
             );",
        )
        .unwrap();
        ca.execute(
            "INSERT INTO archived_generations VALUES ('antigravity/conversations/b.db', 5, 0, 'M2', '10', '70', '0', '80', ?1, 1, 0)",
            rusqlite::params![same_ts as i64],
        )
        .unwrap();
        ca.execute(
            "INSERT INTO archived_generations VALUES ('antigravity/conversations/z.db', 5, 0, 'M3', '10', '90', '0', '100', ?1, 1, 0)",
            rusqlite::params![same_ts as i64],
        )
        .unwrap();
        drop(ca);

        let tie_all = collect_token_stats_list_at(
            &tie_home,
            StatsSource::All,
            &StatsRangeSpec::AllTime,
            &now,
        );
        assert_eq!(
            tie_all.total_matching, 4,
            "duplicate live+archive row must count once"
        );
        assert!(!tie_all.truncated);
        // Same timestamp, idx=5 ties broken deterministically by `source_key` ASC:
        // 1. `antigravity-cli/conversations/a.db` (idx=5, out=50? Wait: 'antigravity/' < 'antigravity-cli/' because '/' (0x2f) > '-' (0x2d): '-' is 45, '/' is 47 -> `antigravity-cli/...` comes FIRST!)
        // 2. `antigravity/conversations/b.db` (idx=5, out=70, status=Ok)
        // 3. `antigravity/conversations/z.db` (idx=5, out=90, status=Archived)
        // 4. `antigravity-cli/conversations/a.db` (idx=2, out=20)
        assert_eq!(tie_all.items[0].output_tokens, 50);
        assert_eq!(tie_all.items[1].output_tokens, 70);
        assert_eq!(tie_all.items[1].status, StatsCallStatus::Ok);
        assert_eq!(tie_all.items[2].output_tokens, 90);
        assert_eq!(tie_all.items[2].status, StatsCallStatus::Archived);
        assert_eq!(tie_all.items[3].output_tokens, 20);

        let tie_list_2 = collect_token_stats_list_at(
            &tie_home,
            StatsSource::All,
            &StatsRangeSpec::Recent { limit: 2 },
            &now,
        );
        let tie_sum_2 = collect_token_stats_at(
            &tie_home,
            StatsSource::All,
            &StatsRangeSpec::Recent { limit: 2 },
            &now,
        );
        assert_eq!(tie_list_2.shown_count, 2);
        assert!(!tie_list_2.truncated);
        assert_eq!(
            tie_sum_2.summary.total_output_tokens,
            tie_list_2.items[0].output_tokens + tie_list_2.items[1].output_tokens
        );
    }

    #[test]
    fn r3_07_r3_08_r3_09_r3_11_model_allowlist_unindexed_budget_tps_consistency_and_50col_blocks() {
        struct UnindexedBudgetGuard;
        impl Drop for UnindexedBudgetGuard {
            fn drop(&mut self) {
                TEST_UNINDEXED_ROW_BUDGET_OVERRIDE.with(|c| c.set(0));
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let tz = jiff::tz::TimeZone::UTC;
        let now = "2026-11-19T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(tz.clone());
        let ts_base = "2026-11-19T08:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        // 1. R3-07: Strict public model allowlist across BOTH live DB and archive DB (`summary` + `list`)
        let h_model = tmp.path().join("r307_home");
        let conv_m = h_model.join(".gemini/antigravity-cli/conversations");
        let app_m = h_model.join(".gemini/antigravity");
        fs::create_dir_all(&conv_m).unwrap();
        fs::create_dir_all(&app_m).unwrap();
        let cm = Connection::open(conv_m.join("models.db")).unwrap();
        cm.execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        let rejected_labels = [
            "neutral description text",
            "Gemini internal memo",
            "Makefile",
            "notes_draft",
            "/home/alice/secret.rs",
            "192.168.1.50",
            "本地模型说明",
        ];
        for (i, bad) in rejected_labels.iter().enumerate() {
            let b = make_gen_blob(10, 20, 5, 0, Some(ts_base + i as u64), bad, Some(bad));
            cm.execute(
                "INSERT INTO gen_metadata VALUES (?1, ?2)",
                rusqlite::params![(i + 1) as i64, b],
            )
            .unwrap();
        }
        let valid_labels = [
            ("gemini-4-carbon", Some("Gemini 4 Carbon (High)")),
            ("gpt-oss-120b-medium", None),
            ("MODEL_PLACEHOLDER_M18", None),
        ];
        for (j, (mid, lbl)) in valid_labels.iter().enumerate() {
            let idx = (rejected_labels.len() + j + 1) as i64;
            let b = make_gen_blob(10, 20, 5, 0, Some(ts_base + idx as u64), mid, *lbl);
            cm.execute(
                "INSERT INTO gen_metadata VALUES (?1, ?2)",
                rusqlite::params![idx, b],
            )
            .unwrap();
        }
        drop(cm);

        let ca_m = Connection::open(app_m.join("token_usage_archive.db")).unwrap();
        ca_m.execute_batch(
            "CREATE TABLE archived_generations (
                source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER
             );",
        )
        .unwrap();
        ca_m.execute(
            "INSERT INTO archived_generations VALUES ('antigravity/conversations/old.db', 1, 0, 'neutral description text', '10', '5', '0', '15', ?1, 1, 0)",
            rusqlite::params![(ts_base + 50) as i64],
        )
        .unwrap();
        ca_m.execute(
            "INSERT INTO archived_generations VALUES ('antigravity/conversations/old.db', 2, 0, 'Makefile', '10', '5', '0', '15', ?1, 1, 0)",
            rusqlite::params![(ts_base + 51) as i64],
        )
        .unwrap();
        drop(ca_m);

        let sum_m =
            collect_token_stats_at(&h_model, StatsSource::All, &StatsRangeSpec::AllTime, &now);
        let list_m =
            collect_token_stats_list_at(&h_model, StatsSource::All, &StatsRangeSpec::AllTime, &now);
        let model_names: HashSet<&str> = sum_m.models.iter().map(|m| m.model.as_str()).collect();
        assert_eq!(
            model_names,
            HashSet::from([
                "Gemini 4 Carbon (High)",
                "gpt-oss-120b-medium",
                "MODEL_PLACEHOLDER_M18",
                "Unknown",
            ]),
            "Untrusted labels leaked into summary models: {model_names:?}"
        );
        let unk_count = sum_m
            .models
            .iter()
            .find(|m| m.model == "Unknown")
            .unwrap()
            .request_count;
        assert_eq!(unk_count, (rejected_labels.len() + 2) as u64);
        assert!(list_m.items.iter().all(|it| matches!(
            it.model.as_str(),
            "Gemini 4 Carbon (High)" | "gpt-oss-120b-medium" | "MODEL_PLACEHOLDER_M18" | "Unknown"
        )));

        // 2. R3-08 (a): Unindexed `gen_metadata` with two 36 MiB BLOBs (combined 72 MiB > 64 MiB temp limit)
        //    MUST succeed without spilling BLOBs into SQLite's memory temp B-tree!
        let h_big = tmp.path().join("r308_big");
        let conv_big = h_big.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&conv_big).unwrap();
        let c_big = Connection::open(conv_big.join("big_unindexed.db")).unwrap();
        c_big
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER, data BLOB);")
            .unwrap();
        let base_blob = make_gen_blob(
            10,
            20,
            5,
            0,
            Some(ts_base + 1),
            "gemini-4-carbon",
            Some("Gemini 4 Carbon (High)"),
        );
        let mut big_blob = base_blob;
        // Pad valid unknown protobuf bytes field #99 to reach 36 MiB (each < 64 MiB, two = 72 MiB > 64 MiB!)
        let pad_len = 36 * 1024 * 1024usize;
        big_blob.extend(vi((99_u64 << 3) | 2));
        big_blob.extend(vi(pad_len as u64));
        big_blob.resize(big_blob.len() + pad_len, b'A');
        c_big
            .execute(
                "INSERT INTO gen_metadata VALUES (2, ?1)",
                rusqlite::params![&big_blob],
            )
            .unwrap();
        c_big
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![&big_blob],
            )
            .unwrap();
        drop(c_big);

        let sum_big =
            collect_token_stats_at(&h_big, StatsSource::Cli, &StatsRangeSpec::AllTime, &now);
        assert_eq!(sum_big.unreadable_databases, 0);
        assert_eq!(sum_big.summary.request_count, 2);

        // 2. R3-08 (b): Unindexed `gen_metadata` and unindexed `archived_generations` exceeding row budget degrade cleanly!
        TEST_UNINDEXED_ROW_BUDGET_OVERRIDE.with(|c| c.set(5));
        let _budget_guard = UnindexedBudgetGuard;
        let h_over = tmp.path().join("r308_over");
        let conv_over = h_over.join(".gemini/antigravity-cli/conversations");
        let app_over = h_over.join(".gemini/antigravity");
        fs::create_dir_all(&conv_over).unwrap();
        fs::create_dir_all(&app_over).unwrap();
        let c_over = Connection::open(conv_over.join("over_unindexed.db")).unwrap();
        c_over
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER, data BLOB);")
            .unwrap();
        for idx in 1..=6_i64 {
            let b = make_gen_blob(
                10,
                0,
                5,
                0,
                Some(ts_base + idx as u64),
                "gemini-4-carbon",
                None,
            );
            c_over
                .execute(
                    "INSERT INTO gen_metadata VALUES (?1, ?2)",
                    rusqlite::params![idx, b],
                )
                .unwrap();
        }
        drop(c_over);
        let sum_over_live =
            collect_token_stats_at(&h_over, StatsSource::Cli, &StatsRangeSpec::AllTime, &now);
        assert_eq!(sum_over_live.unreadable_databases, 1);
        assert_eq!(sum_over_live.summary.request_count, 0);

        let ca_over = Connection::open(app_over.join("token_usage_archive.db")).unwrap();
        ca_over
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                    model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                    total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER
                 );",
            )
            .unwrap();
        for idx in 1..=6_i64 {
            ca_over
                .execute(
                    "INSERT INTO archived_generations VALUES ('antigravity/conversations/a.db', ?1, 0, 'Gemini 4 Carbon (High)', '10', '5', '0', '15', ?2, 1, 0)",
                    rusqlite::params![idx, (ts_base + idx as u64) as i64],
                )
                .unwrap();
        }
        drop(ca_over);
        let sum_over_arch =
            collect_token_stats_at(&h_over, StatsSource::App, &StatsRangeSpec::AllTime, &now);
        assert_eq!(sum_over_arch.unreadable_databases, 1);
        assert_eq!(sum_over_arch.summary.request_count, 0);
        drop(_budget_guard);

        // 3. R3-09: Exact Round-3 reproducer (status=3, no model field, step_payload=NULL, TTFT=2s, stream=4s, out=100)
        //    + cross-midnight archive override + non-integer/unknown status & non-BLOB payload exclusion!
        let make_timed_no_model = |out_tok: u64, ttft_s: u64, stream_s: u64, ts: u64| -> Vec<u8> {
            let mut usage = Vec::new();
            usage.extend(pb_varint(1, 50));
            usage.extend(pb_varint(2, 50));
            usage.extend(pb_varint(3, out_tok));
            let timing = pb_bytes(4, &pb_varint(1, ts));
            let wrapped = [
                pb_bytes(4, &usage),
                pb_bytes(9, &timing),
                pb_bytes(11, &pb_varint(1, ttft_s)),
                pb_bytes(12, &pb_varint(1, stream_s)),
            ]
            .concat();
            pb_bytes(1, &wrapped)
        };
        let h_r09 = tmp.path().join("r309_home");
        let conv_r09 = h_r09.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&conv_r09).unwrap();
        let c09 = Connection::open(conv_r09.join("repro.db")).unwrap();
        c09.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status ANY, step_payload ANY);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        // idx=1: exact R3-09 reproducer -> 100 / 4.0 = 25.0 t/s
        c09.execute("INSERT INTO steps VALUES (1, 15, NULL, 3, NULL)", [])
            .unwrap();
        c09.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![make_timed_no_model(100, 2, 4, ts_base + 10)],
        )
        .unwrap();
        // idx=2: non-integer status `'completed'` -> StatsCallStatus::Unknown (`unk`), excluded from TPS
        c09.execute(
            "INSERT INTO steps VALUES (2, 15, NULL, 'completed', NULL)",
            [],
        )
        .unwrap();
        c09.execute(
            "INSERT INTO gen_metadata VALUES (2, ?1)",
            rusqlite::params![make_timed_no_model(200, 2, 4, ts_base + 5)],
        )
        .unwrap();
        // idx=3: unknown integer status `99` -> StatsCallStatus::Unknown (`unk`), excluded from TPS
        c09.execute("INSERT INTO steps VALUES (3, 15, NULL, 99, NULL)", [])
            .unwrap();
        c09.execute(
            "INSERT INTO gen_metadata VALUES (3, ?1)",
            rusqlite::params![make_timed_no_model(200, 2, 4, ts_base + 4)],
        )
        .unwrap();
        // idx=4: status=3 with non-BLOB `step_payload` text -> excluded from TPS
        c09.execute(
            "INSERT INTO steps VALUES (4, 15, NULL, 3, 'invalid-non-blob')",
            [],
        )
        .unwrap();
        c09.execute(
            "INSERT INTO gen_metadata VALUES (4, ?1)",
            rusqlite::params![make_timed_no_model(200, 2, 4, ts_base + 3)],
        )
        .unwrap();
        drop(c09);

        let d_today = StatsRangeSpec::SingleDate {
            date: "2026-11-19".parse().unwrap(),
        };
        let list_d = collect_token_stats_list_at(&h_r09, StatsSource::Cli, &d_today, &now);
        let sum_d = collect_token_stats_at(&h_r09, StatsSource::Cli, &d_today, &now);
        let sum_r1 = collect_token_stats_at(
            &h_r09,
            StatsSource::Cli,
            &StatsRangeSpec::Recent { limit: 1 },
            &now,
        );
        assert_eq!(list_d.items.len(), 4);
        assert_eq!(list_d.items[0].model, "Unknown");
        assert_eq!(list_d.items[0].status, StatsCallStatus::Ok);
        assert_eq!(list_d.items[0].output_tps, Some(25.0));
        assert_eq!(list_d.items[1].status, StatsCallStatus::Unknown);
        assert_eq!(list_d.items[1].status.short_label(), "unk");
        assert_eq!(list_d.items[1].output_tps, None);
        assert_eq!(list_d.items[2].status, StatsCallStatus::Unknown);
        assert_eq!(list_d.items[2].output_tps, None);
        assert_eq!(list_d.items[3].status, StatsCallStatus::Ok);
        assert_eq!(list_d.items[3].output_tps, None);
        assert_eq!(sum_d.performance.as_ref().unwrap().sample_count, 1);
        assert_eq!(sum_d.performance.as_ref().unwrap().output_tps.p50, 25.0);
        assert_eq!(sum_r1.performance.as_ref().unwrap().sample_count, 1);
        assert_eq!(sum_r1.performance.as_ref().unwrap().output_tps.p50, 25.0);

        // Cross-midnight archive override vs live timestamp MUST agree across `list --date`, `summary --date`, `summary --recent`!
        let h_mid = tmp.path().join("r309_mid");
        let app_mid = h_mid.join(".gemini/antigravity");
        let conv_mid = app_mid.join("conversations");
        fs::create_dir_all(&conv_mid).unwrap();
        let ts_day1 = "2026-11-18T23:59:50Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let ts_day2 = "2026-11-19T00:00:10Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let cmid = Connection::open(conv_mid.join("cross.db")).unwrap();
        cmid.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        cmid.execute("INSERT INTO steps VALUES (1, 15, NULL, 3, NULL)", [])
            .unwrap();
        cmid.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![make_timed_no_model(100, 2, 4, ts_day2)],
        )
        .unwrap();
        drop(cmid);
        let camid = Connection::open(app_mid.join("token_usage_archive.db")).unwrap();
        camid
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                    model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                    total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER,
                    PRIMARY KEY (source_key, generation_idx, ordinal)
                 );",
            )
            .unwrap();
        camid
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/cross.db', 1, 0, 'Gemini 4 Carbon (High)', '100', '100', '0', '200', ?1, 1, 0)",
                rusqlite::params![ts_day1 as i64],
            )
            .unwrap();
        drop(camid);

        let d_day1 = StatsRangeSpec::SingleDate {
            date: "2026-11-18".parse().unwrap(),
        };
        let sum_day1 = collect_token_stats_at(&h_mid, StatsSource::App, &d_day1, &now);
        let list_day1 = collect_token_stats_list_at(&h_mid, StatsSource::App, &d_day1, &now);
        let sum_day2 = collect_token_stats_at(&h_mid, StatsSource::App, &d_today, &now);
        let sum_recent_mid = collect_token_stats_at(
            &h_mid,
            StatsSource::App,
            &StatsRangeSpec::Recent { limit: 1 },
            &now,
        );
        assert_eq!(sum_day1.summary.request_count, 1);
        assert_eq!(list_day1.items.len(), 1);
        assert_eq!(sum_day2.summary.request_count, 0);
        assert_eq!(sum_day1.performance.as_ref().unwrap().output_tps.p50, 25.0);
        assert_eq!(list_day1.items[0].output_tps, Some(25.0));
        assert_eq!(
            sum_recent_mid.performance.as_ref().unwrap().output_tps.p50,
            25.0
        );

        // 4. R3-11: Ultra-narrow terminals (`50` and `40` cols) switch to compact multi-line block layout
        //    preserving ALL 10 fields (`Time`, `St`, `Model`, `In`, `Cache`, `Hit%`, `Out`, `TTFT`, `Dur`, `TPS`) without overflow!
        for ultra_cols in [50usize, 40] {
            let rendered = list_d.render_human_for_width(Some(ultra_cols));
            for line in rendered.lines() {
                assert!(
                    UnicodeWidthStr::width(line) <= ultra_cols,
                    "Compact block line exceeded {ultra_cols} cols ({}): {line}",
                    UnicodeWidthStr::width(line)
                );
            }
            for token in [
                "[ok]",
                "[unk]",
                "TPS:25",
                "TPS:—",
                "In:100",
                "Cache:0",
                "(0.0%)",
                "Out:100",
                "TTFT:2.0s",
                "Dur:6.0s",
            ] {
                assert!(
                    rendered.contains(token),
                    "Compact block layout ({ultra_cols} cols) missing `{token}`:\n{rendered}"
                );
            }
        }

        // 5. R3-08 additional edge cases:
        //    (a) Duplicate `idx` rows in unindexed `gen_metadata` overlapping a valid archived row
        //        MUST NOT double-count tokens, requests, or list items;
        let h_dup = tmp.path().join("r308_dup");
        let app_dup = h_dup.join(".gemini/antigravity");
        let conv_dup = app_dup.join("conversations");
        fs::create_dir_all(&conv_dup).unwrap();
        let c_dup = Connection::open(conv_dup.join("dup.db")).unwrap();
        c_dup
            .execute_batch(
                "CREATE TABLE steps (step_type INTEGER, metadata BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER, data BLOB);",
            )
            .unwrap();
        // `steps` intentionally lacks `idx` column -> must gracefully skip step metadata without failing DB!
        let dup_blob = make_gen_blob(
            10,
            20,
            5,
            0,
            Some(ts_base + 50),
            "gemini-4-carbon",
            Some("Gemini 4 Carbon (High)"),
        );
        c_dup
            .execute(
                "INSERT INTO gen_metadata VALUES (7, ?1)",
                rusqlite::params![&dup_blob],
            )
            .unwrap();
        c_dup
            .execute(
                "INSERT INTO gen_metadata VALUES (7, ?1)",
                rusqlite::params![&dup_blob],
            )
            .unwrap();
        drop(c_dup);
        let ca_dup = Connection::open(app_dup.join("token_usage_archive.db")).unwrap();
        ca_dup
            .execute_batch(
                "CREATE TABLE archived_generations (
                    source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                    model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                    total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER,
                    PRIMARY KEY (source_key, generation_idx, ordinal)
                 );",
            )
            .unwrap();
        ca_dup
            .execute(
                "INSERT INTO archived_generations VALUES ('antigravity/conversations/dup.db', 7, 0, 'Gemini 4 Carbon (High)', '30', '5', '0', '35', ?1, 1, 0)",
                rusqlite::params![(ts_base + 50) as i64],
            )
            .unwrap();
        drop(ca_dup);

        let sum_dup =
            collect_token_stats_at(&h_dup, StatsSource::App, &StatsRangeSpec::AllTime, &now);
        let list_dup =
            collect_token_stats_list_at(&h_dup, StatsSource::App, &StatsRangeSpec::AllTime, &now);
        assert_eq!(sum_dup.unreadable_databases, 0);
        assert_eq!(
            sum_dup.summary.request_count, 1,
            "Duplicate live idx overlapping valid archive row MUST NOT double-count!"
        );
        assert_eq!(list_dup.items.len(), 1);

        //    (b) `WITHOUT ROWID` unindexed `gen_metadata` MUST degrade cleanly to `unreadable_databases == 1`!
        let h_wrid = tmp.path().join("r308_wrid");
        let conv_wrid = h_wrid.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&conv_wrid).unwrap();
        let c_wrid = Connection::open(conv_wrid.join("wrid.db")).unwrap();
        c_wrid
            .execute_batch(
                "CREATE TABLE gen_metadata (other TEXT, idx INTEGER, data BLOB, PRIMARY KEY (other, idx)) WITHOUT ROWID;",
            )
            .unwrap();
        c_wrid
            .execute(
                "INSERT INTO gen_metadata VALUES ('k1', 1, ?1)",
                rusqlite::params![&dup_blob],
            )
            .unwrap();
        drop(c_wrid);
        let sum_wrid =
            collect_token_stats_at(&h_wrid, StatsSource::Cli, &StatsRangeSpec::AllTime, &now);
        assert_eq!(sum_wrid.unreadable_databases, 1);
        assert_eq!(sum_wrid.summary.request_count, 0);
    }

    #[test]
    fn a08a_scan_with_bounded_retry_dedups_hardlinks_and_preserves_transient_retry_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let db_a = tmp.path().join("a.db");
        let db_a_link = tmp.path().join("a_hardlink.db");
        let conn_a = Connection::open(&db_a).unwrap();
        conn_a
            .execute_batch("CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (42);")
            .unwrap();
        drop(conn_a);
        fs::hard_link(&db_a, &db_a_link).unwrap();

        let db_b = tmp.path().join("b.db");
        let db_b_link = tmp.path().join("b_hardlink.db");
        let conn_b = Connection::open(&db_b).unwrap();
        conn_b
            .execute_batch("CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (7);")
            .unwrap();
        drop(conn_b);
        fs::hard_link(&db_b, &db_b_link).unwrap();

        let dir_fd = open_existing_dir_nofollow(tmp.path()).unwrap().unwrap();
        let mut seen = HashSet::new();

        // 1. Attempt 0 returns a transient `SQLITE_BUSY` error -> MUST NOT mark inode as seen yet;
        //    attempt 1 re-opens the exact same inode, succeeds, and records the inode once.
        let mut attempts = 0usize;
        let res_a = scan_with_bounded_retry(&dir_fd, OsStr::new("a.db"), &mut seen, |pinned| {
            attempts += 1;
            if attempts == 1 {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    None,
                ));
            }
            pinned
                .conn()
                .query_row("SELECT v FROM t", [], |r| r.get::<_, i64>(0))
        });
        assert!(matches!(res_a, RetryScanOutcome::Scanned(42)));
        assert_eq!(attempts, 2);
        assert_eq!(seen.len(), 1);

        // 2. Hardlink to `a.db` is immediately skipped as duplicate without invoking `scan_fn`.
        let mut link_a_called = false;
        let res_a_dup =
            scan_with_bounded_retry(&dir_fd, OsStr::new("a_hardlink.db"), &mut seen, |_| {
                link_a_called = true;
                Ok(0i64)
            });
        assert!(matches!(
            res_a_dup,
            RetryScanOutcome::SkippedUnsafeOrDuplicate
        ));
        assert!(!link_a_called);

        // 3. Final non-transient error returns `Unreadable` and records inode so its hardlink is not double-counted.
        let res_b = scan_with_bounded_retry(&dir_fd, OsStr::new("b.db"), &mut seen, |_| {
            Err::<i64, _>(rusqlite::Error::QueryReturnedNoRows)
        });
        assert!(matches!(res_b, RetryScanOutcome::Unreadable));
        assert_eq!(seen.len(), 2);

        let res_b_dup =
            scan_with_bounded_retry(&dir_fd, OsStr::new("b_hardlink.db"), &mut seen, |_| {
                Ok(0i64)
            });
        assert!(matches!(
            res_b_dup,
            RetryScanOutcome::SkippedUnsafeOrDuplicate
        ));
    }

    #[test]
    fn synthetic_v125_stats_cleared_canceled_interrupted_and_tps_parity() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let cli_conv = home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cli_conv).unwrap();

        let tz = jiff::tz::TimeZone::UTC;
        let now = "2026-11-21T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .to_zoned(tz);
        let t_base = "2026-11-21T08:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        let make_blob = |out_tok: u64,
                         ttft_secs: u64,
                         stream_secs: u64,
                         ts: u64,
                         err_str: Option<&[u8]>|
         -> Vec<u8> {
            let usage = [
                pb_varint(1, 200),
                pb_varint(2, 100),
                pb_varint(3, out_tok),
                pb_varint(5, 700),
            ]
            .concat();
            let timing = pb_bytes(4, &pb_varint(1, ts));
            let ttft = pb_varint(1, ttft_secs);
            let stream = pb_varint(1, stream_secs);
            let wrapped = [
                pb_bytes(4, &usage),
                pb_bytes(9, &timing),
                pb_bytes(11, &ttft),
                pb_bytes(12, &stream),
                pb_bytes(19, b"gemini-3.1-pro"),
                pb_bytes(21, b"Gemini 3.1 Pro (High)"),
            ]
            .concat();
            let mut outer = pb_bytes(1, &wrapped);
            if let Some(err) = err_str {
                outer.extend(pb_bytes(5, err));
            }
            outer
        };

        let valid_payload = pb_bytes(20, &pb_bytes(1, b"ok"));
        let corrupt_payload = vec![0x80u8];

        let conn = Connection::open(cli_conv.join("cleared_split.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();

        // idx=1 (oldest): status=12 (`INTERRUPTED` -> `intr`, excluded from TPS)
        conn.execute(
            "INSERT INTO steps VALUES (1, 15, NULL, 12, ?1)",
            rusqlite::params![&valid_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![make_blob(400, 2, 4, t_base + 10, None)],
        )
        .unwrap();

        // idx=2: status=6 (`CANCELED` -> `canc`, excluded from TPS)
        conn.execute(
            "INSERT INTO steps VALUES (2, 15, NULL, 6, ?1)",
            rusqlite::params![&valid_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (2, ?1)",
            rusqlite::params![make_blob(300, 2, 3, t_base + 20, None)],
        )
        .unwrap();

        // idx=3: status=5 (`CLEARED`) with corrupt step_payload -> `clr`, excluded from TPS
        conn.execute(
            "INSERT INTO steps VALUES (3, 15, NULL, 5, ?1)",
            rusqlite::params![&corrupt_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (3, ?1)",
            rusqlite::params![make_blob(500, 2, 5, t_base + 30, None)],
        )
        .unwrap();

        // idx=4: status=5 (`CLEARED`) with error field 5 -> `err`, excluded from TPS
        conn.execute(
            "INSERT INTO steps VALUES (4, 15, NULL, 5, ?1)",
            rusqlite::params![&valid_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (4, ?1)",
            rusqlite::params![make_blob(600, 2, 6, t_base + 40, Some(b"synthetic_err"))],
        )
        .unwrap();

        // idx=5: status=5 (`CLEARED`) clean & valid nonempty payload -> `clr`, TPS = 400 / 4.0s = 100
        conn.execute(
            "INSERT INTO steps VALUES (5, 15, NULL, 5, ?1)",
            rusqlite::params![&valid_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (5, ?1)",
            rusqlite::params![make_blob(400, 2, 4, t_base + 50, None)],
        )
        .unwrap();

        // idx=6 (newest): status=3 (`DONE`) -> `ok`, TPS = 200 / 4.0s = 50
        conn.execute(
            "INSERT INTO steps VALUES (6, 15, NULL, 3, ?1)",
            rusqlite::params![&valid_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (6, ?1)",
            rusqlite::params![make_blob(200, 1, 4, t_base + 60, None)],
        )
        .unwrap();
        drop(conn);

        let all_spec = StatsRangeSpec::AllTime;
        let list_view = collect_token_stats_list_at(&home, StatsSource::All, &all_spec, &now);
        assert_eq!(list_view.items.len(), 6);
        // Newest-first order: idx 6, 5, 4, 3, 2, 1
        assert_eq!(list_view.items[0].status, StatsCallStatus::Ok);
        assert_eq!(
            list_view.items[0].output_tps.map(|v| v.round() as u64),
            Some(50)
        );
        assert_eq!(list_view.items[1].status, StatsCallStatus::Cleared);
        assert_eq!(
            list_view.items[1].output_tps.map(|v| v.round() as u64),
            Some(100)
        );
        assert_eq!(list_view.items[2].status, StatsCallStatus::Error);
        assert_eq!(list_view.items[2].output_tps, None);
        assert_eq!(list_view.items[3].status, StatsCallStatus::Cleared);
        assert_eq!(list_view.items[3].output_tps, None);
        assert_eq!(list_view.items[4].status, StatsCallStatus::Canceled);
        assert_eq!(list_view.items[4].output_tps, None);
        assert_eq!(list_view.items[5].status, StatsCallStatus::Interrupted);
        assert_eq!(list_view.items[5].output_tps, None);

        // Verify `stats summary` agrees on exact `sample_count == 2` across `--range all` and `--recent 6`.
        for spec in [StatsRangeSpec::AllTime, StatsRangeSpec::Recent { limit: 6 }] {
            let summary = collect_token_stats_at(&home, StatsSource::All, &spec, &now);
            let perf = summary
                .performance
                .as_ref()
                .expect("expected 2 eligible perf samples");
            assert_eq!(perf.sample_count, 2);
            assert!((perf.output_tps.p50 - 75.0).abs() < 1e-6);
            assert!((perf.ttft_seconds.p50 - 1.5).abs() < 1e-6);
        }

        // Verify human rendering displays `ok`, `clr`, `err`, `canc`, `intr` without overflowing 100 cols.
        let rendered = list_view.render_human_for_width(Some(100));
        for label in [" ok", " clr", " err", " canc", " intr"] {
            assert!(
                rendered.contains(label),
                "expected status label `{label}` in rendered list:\n{rendered}"
            );
        }
        for line in rendered.lines() {
            assert!(
                UnicodeWidthStr::width(line) <= 100,
                "rendered line > 100 cols: {line}"
            );
        }
    }
}
