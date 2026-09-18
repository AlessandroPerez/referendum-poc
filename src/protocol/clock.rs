//! Clocks for artifact timestamps: a deterministic logical clock for the
//! reproducible test suite and a wall clock for real runs.
//!
//! Every timestamp in a signed artifact (WBB entries, ballot-box receipts,
//! tau delays) is read from a [`Clock`]. In [`ClockMode::Logical`] the value is
//! a fixed base plus a tick counter that the driver advances, so WBB
//! checkpoints, receipts, and tau delays are reproducible across runs. In
//! [`ClockMode::Wall`] the value is the current Unix time in milliseconds, and
//! the WBB's freshness window (+/- 5 minutes) is enforced.

use std::time::{SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::configuration::ClockSettings;

/// Which time source a service stamps its artifacts with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ClockMode {
    /// `base_ms + tick * tick_ms`, advanced by the driver (reproducible).
    #[default]
    Logical,
    /// Real Unix time in milliseconds.
    Wall,
}

/// Deterministic logical clock.
///
/// `now()` returns `base_ms + tick * tick_ms`, where `tick` is advanced by the
/// driver. The clock intentionally does not advance automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalClock {
    base_ms: u64,
    tick_ms: u64,
    tick: u64,
}

impl LogicalClock {
    /// Create a clock starting at `base_ms` with `tick_ms` granularity.
    pub fn new(base_ms: u64, tick_ms: u64) -> Self {
        Self {
            base_ms,
            tick_ms,
            tick: 0,
        }
    }

    /// Current logical timestamp in milliseconds.
    pub fn now_ms(&self) -> u64 {
        self.base_ms + self.tick * self.tick_ms
    }

    /// Advance the clock by one tick.
    pub fn advance(&mut self) {
        self.tick += 1;
    }

    /// Advance by `n` ticks.
    pub fn advance_by(&mut self, n: u64) {
        self.tick += n;
    }

    /// Current tick number.
    pub fn tick(&self) -> u64 {
        self.tick
    }
}

/// The clock every actor stamps its artifacts with.
///
/// `Copy` on purpose: actors that hand out one timestamp per artifact keep a
/// mutable copy and call [`Clock::advance`] between artifacts; on the wall
/// clock that is a no-op because real time moves by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    /// Deterministic logical clock (test suite, golden artifacts).
    Logical(LogicalClock),
    /// Real Unix time (demo and deployments).
    Wall,
}

impl Clock {
    /// Build the clock selected by the configuration.
    pub fn from_settings(settings: &ClockSettings) -> Self {
        match settings.mode {
            ClockMode::Logical => {
                Self::Logical(LogicalClock::new(settings.base_ms, settings.tick_ms))
            }
            ClockMode::Wall => Self::Wall,
        }
    }

    /// Deterministic logical clock starting at `base_ms` with `tick_ms` steps.
    pub fn logical(base_ms: u64, tick_ms: u64) -> Self {
        Self::Logical(LogicalClock::new(base_ms, tick_ms))
    }

    /// The mode this clock runs in.
    pub fn mode(&self) -> ClockMode {
        match self {
            Self::Logical(_) => ClockMode::Logical,
            Self::Wall => ClockMode::Wall,
        }
    }

    /// Current timestamp in milliseconds (logical or Unix time).
    pub fn now_ms(&self) -> u64 {
        match self {
            Self::Logical(clock) => clock.now_ms(),
            Self::Wall => unix_now_ms(),
        }
    }

    /// Advance the logical clock by one tick; no-op on the wall clock.
    pub fn advance(&mut self) {
        if let Self::Logical(clock) = self {
            clock.advance();
        }
    }

    /// Advance the logical clock by `n` ticks; no-op on the wall clock.
    pub fn advance_by(&mut self, n: u64) {
        if let Self::Logical(clock) = self {
            clock.advance_by(n);
        }
    }

    /// Sample a tau delay (in ticks) from `{min..=max}` using the provided RNG.
    ///
    /// tau is drawn from {2..5} ticks for PIN-request notifications.
    pub fn sample_tau<R: Rng>(&self, rng: &mut R, min: u64, max: u64) -> u64 {
        assert!(min <= max, "tau range must be non-empty");
        rng.gen_range(min..=max)
    }
}

/// Current Unix time in milliseconds.
fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn clock_advances_deterministically() {
        let mut clock = LogicalClock::new(1_700_000_000_000, 1_000);
        assert_eq!(clock.now_ms(), 1_700_000_000_000);
        clock.advance();
        assert_eq!(clock.now_ms(), 1_700_000_001_000);
        clock.advance_by(3);
        assert_eq!(clock.tick(), 4);
        assert_eq!(clock.now_ms(), 1_700_000_004_000);
    }

    #[test]
    fn logical_clock_wrapper_advances_and_reports_mode() {
        let mut clock = Clock::logical(1_700_000_000_000, 1_000);
        assert_eq!(clock.mode(), ClockMode::Logical);
        assert_eq!(clock.now_ms(), 1_700_000_000_000);
        clock.advance();
        clock.advance_by(2);
        assert_eq!(clock.now_ms(), 1_700_000_003_000);
    }

    #[test]
    fn wall_clock_tracks_real_time_and_ignores_ticks() {
        let mut clock = Clock::Wall;
        assert_eq!(clock.mode(), ClockMode::Wall);
        let before = unix_now_ms();
        let now = clock.now_ms();
        clock.advance();
        clock.advance_by(1_000_000);
        let after = clock.now_ms();
        // Real time: between the surrounding readings, and ticks do not jump it.
        assert!(now >= before);
        assert!(after >= now);
        assert!(
            after - now < 60_000,
            "ticks must not advance the wall clock"
        );
        // Sanity: a 2020+ date, so nobody mistakes it for a logical value.
        assert!(now > 1_577_836_800_000);
    }

    #[test]
    fn from_settings_honours_the_mode() {
        let logical = ClockSettings {
            mode: ClockMode::Logical,
            base_ms: 42,
            tick_ms: 7,
        };
        assert_eq!(Clock::from_settings(&logical), Clock::logical(42, 7));
        let wall = ClockSettings {
            mode: ClockMode::Wall,
            ..logical
        };
        assert_eq!(Clock::from_settings(&wall), Clock::Wall);
    }

    #[test]
    fn tau_sampling_is_reproducible() {
        let clock = Clock::logical(0, 1);
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let tau = clock.sample_tau(&mut rng, 2, 5);
        assert!((2..=5).contains(&tau));

        let mut rng2 = ChaCha20Rng::from_seed([7u8; 32]);
        assert_eq!(clock.sample_tau(&mut rng2, 2, 5), tau);
    }
}
