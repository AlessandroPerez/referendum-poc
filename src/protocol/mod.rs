//! Protocol orchestration over `evoting-rs` - framework-free (
//! no web types in this module tree).
//!
//! Modules: `rng`/`clock`, `tls`, `setup`, `merkle`, `acc`, `voting`, `tally`.

pub mod acc;
pub mod cat;
pub mod clock;
pub mod merkle;
pub mod rng;
pub mod setup;
pub mod tally;
pub mod tlog;
pub mod tls;
pub mod validators;
pub mod voting;
