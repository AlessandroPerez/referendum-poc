//! End-to-end test suite entrypoint (style guide §05: one test binary per
//! `tests/` subdirectory, helpers in a sibling module).

mod helpers;
mod m2_smoke;
mod m3_integration;
mod m4_integration;
mod m5_integration;
mod m6_integration;

#[test]
fn harness_loads() {
    helpers::init();
}
