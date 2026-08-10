//! Shared e2e harness (spawn cluster, seeded determinism, WBB process).
//! Grows per roadmap milestones M2+.

/// Initialize test telemetry exactly once per test process.
pub fn init() {
    referendum_poc::telemetry::init_test_tracing();
}
