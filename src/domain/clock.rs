use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

/// Injectable Unix-seconds clock abstraction for deterministic and real-time freshness checks.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
}

/// Real system wall clock (`chrono::Utc::now().timestamp()`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        chrono::Utc::now().timestamp()
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
