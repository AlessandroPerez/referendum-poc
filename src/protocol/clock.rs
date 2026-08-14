//! Logical clock for deterministic timestamps (roadmap §9).
//!
//! The PoC avoids wall-clock time in artifact paths. Instead, every timestamp
//! is derived from a fixed base plus a tick counter that the driver advances.
//! This makes WBB checkpoints, receipts, and τ delays reproducible across runs.

use rand::Rng;

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

    /// Sample a τ delay (in ticks) from `{min..=max}` using the provided RNG.
    ///
    /// Roadmap §9: τ is drawn from {2..5} ticks for PIN-request notifications.
    pub fn sample_tau<R: Rng>(&self, rng: &mut R, min: u64, max: u64) -> u64 {
        assert!(min <= max, "tau range must be non-empty");
        rng.gen_range(min..=max)
    }
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
    fn tau_sampling_is_reproducible() {
        let clock = LogicalClock::new(0, 1);
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let tau = clock.sample_tau(&mut rng, 2, 5);
        assert!((2..=5).contains(&tau));

        let mut rng2 = ChaCha20Rng::from_seed([7u8; 32]);
        assert_eq!(clock.sample_tau(&mut rng2, 2, 5), tau);
    }
}
