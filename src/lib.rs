//! Referendum PoC — Vote App protocol (PhD thesis ch. 3 + §3.11 referendum
//! optimization) implemented on the `evoting-rs` cryptographic library.
//!
//! Style guide §01: slim binaries, fat library. All business logic lives here;
//! the binaries in `src/bin/` only parse configuration and delegate.
//!
//! See `resources/ROADMAP.md` for the binding implementation contract.

pub mod actors;
pub mod clients;
pub mod configuration;
pub mod domain;
pub mod error;
pub mod protocol;
pub mod telemetry;
