//! End-to-end test suite entrypoint (style guide §05: one test binary per
//! `tests/` subdirectory, helpers in a sibling module).

mod helpers;

#[test]
fn harness_loads() {
    helpers::init();
}
