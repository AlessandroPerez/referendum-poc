//! End-to-end test suite entrypoint (one test binary per
//! `tests/` subdirectory, helpers in a sibling module).

mod credential_generation;
mod enrollment;
mod golden;
mod happy_path;
mod hardening;
mod helpers;
mod pin_management;
mod protocol_flows;
mod setup_ceremony;
mod tally_audit;
mod tamper;
mod voting;
mod wbb_smoke;

#[test]
fn harness_loads() {
    helpers::init();
}
