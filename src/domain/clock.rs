use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

/// Current Unix timestamp in whole seconds (`jiff::Timestamp::now().as_second()`).
pub fn current_unix_seconds() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// Convert a `jiff::Timestamp` to floor Unix epoch seconds (matching RFC3339 / `DateTime::timestamp()`).
pub fn timestamp_unix_seconds(ts: jiff::Timestamp) -> i64 {
    if ts.subsec_nanosecond() < 0 {
        ts.as_second() - 1
    } else {
        ts.as_second()
    }
}

fn parse_2digits(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }
    Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

fn parse_4digits(bytes: &[u8]) -> Option<i16> {
    if bytes.len() != 4 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        i16::from(bytes[0] - b'0') * 1000
            + i16::from(bytes[1] - b'0') * 100
            + i16::from(bytes[2] - b'0') * 10
            + i16::from(bytes[3] - b'0'),
    )
}

/// Strictly parse an RFC 3339 §5.6 timestamp (`YYYY-MM-DD[Tt]HH:MM:SS[.frac](Z|z|[+-]HH:MM)`):
/// - Rejects surrounding whitespace, compact ISO 8601 forms, comma decimal separators, space separators,
///   bare hour offsets, out-of-range offsets (`>= 24:00` or minutes `>= 60`), and IXDTF `[Zone]` suffixes;
/// - Validates all fractional digits (`"." 1*DIGIT`) and truncates sub-nanosecond digits without rounding.
pub fn parse_rfc3339_timestamp(raw: &str) -> Option<jiff::Timestamp> {
    let b = raw.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let year = parse_4digits(&b[0..4])?;
    let month = parse_2digits(&b[5..7])? as i8;
    let day = parse_2digits(&b[8..10])? as i8;
    let date = jiff::civil::Date::new(year, month, day).ok()?;

    let hour_u8 = parse_2digits(&b[11..13])?;
    let min_u8 = parse_2digits(&b[14..16])?;
    let sec_u8 = parse_2digits(&b[17..19])?;
    if hour_u8 > 23 || min_u8 > 59 || sec_u8 > 60 {
        return None;
    }

    let (offset, offset_start) = if matches!(b[b.len() - 1], b'Z' | b'z') {
        (jiff::tz::Offset::UTC, b.len() - 1)
    } else if b.len() >= 25 {
        let off_pos = b.len() - 6;
        let off = &b[off_pos..];
        let sign: i32 = match off[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let off_h = i32::from(parse_2digits(&off[1..3])?);
        if off[3] != b':' || off_h > 23 {
            return None;
        }
        let off_m = i32::from(parse_2digits(&off[4..6])?);
        if off_m > 59 {
            return None;
        }
        let parsed_off = jiff::tz::Offset::from_seconds(sign * (off_h * 3600 + off_m * 60)).ok()?;
        (parsed_off, off_pos)
    } else {
        return None;
    };

    let frac = &b[19..offset_start];
    let raw_nanos: i32 = if frac.is_empty() {
        0
    } else {
        if frac[0] != b'.' || frac.len() < 2 || !frac[1..].iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut acc = 0_i32;
        let digits = &frac[1..];
        for i in 0..9 {
            let d = digits.get(i).map(|c| i32::from(c - b'0')).unwrap_or(0);
            acc = acc * 10 + d;
        }
        acc
    };

    let (sec_i8, nanos_i32) = if sec_u8 == 60 {
        (59_i8, 999_999_999_i32)
    } else {
        (sec_u8 as i8, raw_nanos)
    };
    let time = jiff::civil::Time::new(hour_u8 as i8, min_u8 as i8, sec_i8, nanos_i32).ok()?;
    let dt = jiff::civil::DateTime::from_parts(date, time);
    offset.to_timestamp(dt).ok()
}

/// Parse an RFC 3339 timestamp directly into floor Unix epoch seconds.
pub fn parse_rfc3339_unix_seconds(raw: &str) -> Option<i64> {
    parse_rfc3339_timestamp(raw).map(timestamp_unix_seconds)
}

/// Format positive Unix seconds as UTC RFC 3339 with microsecond precision (`YYYY-MM-DDTHH:MM:SS.000000Z`).
pub fn format_unix_rfc3339_micros_utc(unix_secs: i64) -> Option<String> {
    jiff::Timestamp::from_second(unix_secs)
        .ok()
        .map(|ts| format!("{ts:.6}"))
}

/// Format a `jiff::Timestamp` in the system local timezone as `YYYY-MM-DD HH:MM`.
pub fn format_timestamp_local_minute(ts: jiff::Timestamp) -> String {
    ts.to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d %H:%M")
        .to_string()
}

/// Strictly parse a calendar date in `YYYY-MM-DD` format (4-digit year, 2-digit month, 2-digit day).
pub fn parse_strict_ymd_date(raw: &str) -> Option<jiff::civil::Date> {
    let b = raw.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let year = parse_4digits(&b[0..4])?;
    let month = parse_2digits(&b[5..7])? as i8;
    let day = parse_2digits(&b[8..10])? as i8;
    jiff::civil::Date::new(year, month, day).ok()
}

/// Injectable Unix-seconds clock abstraction for deterministic and real-time freshness checks.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
}

/// Real system wall clock (`jiff::Timestamp::now().as_second()`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        current_unix_seconds()
    }
}

/// Monotonic clock anchored at `base_unix` when created, advancing naturally with `Instant::elapsed()`.
/// Guarantees that even callers passing a synthetic `now_unix` anchor observe real elapsed network/prepare time!
#[derive(Debug, Clone)]
pub struct AnchoredClock {
    base_unix: i64,
    anchor: Instant,
}

impl AnchoredClock {
    pub fn new(base_unix: i64) -> Self {
        Self {
            base_unix,
            anchor: Instant::now(),
        }
    }
}

impl Clock for AnchoredClock {
    fn now_unix(&self) -> i64 {
        self.base_unix
            .saturating_add(self.anchor.elapsed().as_secs() as i64)
    }
}

/// Explicitly controllable deterministic clock for instant time-progression unit and integration tests.
#[derive(Debug)]
pub struct ManualClock {
    current: AtomicI64,
}

impl ManualClock {
    pub fn new(initial_unix: i64) -> Self {
        Self {
            current: AtomicI64::new(initial_unix),
        }
    }

    pub fn set(&self, unix_secs: i64) {
        self.current.store(unix_secs, Ordering::SeqCst);
    }

    pub fn advance(&self, delta_secs: i64) -> i64 {
        self.current
            .fetch_add(delta_secs, Ordering::SeqCst)
            .saturating_add(delta_secs)
    }
}

impl Clock for ManualClock {
    fn now_unix(&self) -> i64 {
        self.current.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_and_strict_date_helpers_preserve_exact_semantics() {
        assert_eq!(
            parse_rfc3339_unix_seconds("2026-11-23T11:34:28Z"),
            Some(1_795_433_668)
        );
        assert_eq!(
            parse_rfc3339_unix_seconds("2026-11-23T19:34:28+08:00"),
            Some(1_795_433_668)
        );
        assert_eq!(
            parse_rfc3339_unix_seconds("2026-11-23t11:34:28.250000z"),
            Some(1_795_433_668)
        );
        assert_eq!(
            parse_rfc3339_unix_seconds("2026-11-23T11:34:28-00:00"),
            Some(1_795_433_668)
        );
        assert_eq!(
            parse_rfc3339_unix_seconds("1969-12-31T23:59:59.500Z"),
            Some(-1)
        );
        assert_eq!(
            parse_rfc3339_unix_seconds("1969-12-31T23:59:59.0000000001Z"),
            Some(-1)
        );
        // Sub-nanosecond precision (>9 digits) MUST truncate without rounding into the next second
        assert_eq!(
            parse_rfc3339_unix_seconds("2026-11-15T10:00:00.1234567890Z"),
            Some(1_794_736_800)
        );
        let trunc_ts = parse_rfc3339_timestamp("2026-11-15T10:00:00.999999999999Z").unwrap();
        assert_eq!(timestamp_unix_seconds(trunc_ts), 1_794_736_800);
        assert_eq!(trunc_ts.subsec_nanosecond(), 999_999_999);
        assert!(parse_rfc3339_timestamp("2026-11-15T10:00:00+23:59").is_some());
        assert!(parse_rfc3339_timestamp("2026-11-15T10:00:00-23:59").is_some());
        // Reject non-RFC3339 forms (including >=24h offsets, invalid trailing fraction bytes, and surrounding whitespace)
        for bad in [
            "",
            "2026-11-23",
            "2026-11-23 11:34:28Z",
            " 2026-11-23T11:34:28Z",
            "2026-11-23T11:34:28Z ",
            "20261123T113428Z",
            "2026-11-23T11:34:28",
            "2026-11-23T11:34:28+08",
            "2026-11-15T10:00:00+24:00",
            "2026-11-15T10:00:00-24:00",
            "2026-11-15T10:00:00+00:60",
            "2026-11-15T10:00:00.123456789xZ",
            "2026-11-23T11:34:28,500Z",
            "2026-11-23T11:34:28.Z",
            "2026-11-23T19:34:28+08:00[Asia/Shanghai]",
        ] {
            assert_eq!(parse_rfc3339_timestamp(bad), None, "should reject {bad:?}");
        }

        assert_eq!(
            format_unix_rfc3339_micros_utc(1_700_000_000).as_deref(),
            Some("2023-11-14T22:13:20.000000Z")
        );
        assert_eq!(format_unix_rfc3339_micros_utc(i64::MAX), None);

        assert!(parse_strict_ymd_date("2026-11-17").is_some());
        assert!(parse_strict_ymd_date("2024-02-29").is_some());
        for bad_date in ["2026-02-29", "2026-1-7", "20261117", "2026-11-17T00:00:00Z"] {
            assert_eq!(parse_strict_ymd_date(bad_date), None);
        }
    }
}
