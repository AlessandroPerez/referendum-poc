//! Referendum PoC - Vote App protocol (PhD thesis ch. 3 + Sec. 3.11 referendum
//! optimization) implemented on the `evoting-rs` cryptographic library.
//!
//! Style guide Sec. 01: slim binaries, fat library. All business logic lives here;
//! the binaries in `src/bin/` only parse configuration and delegate.
//!
//! Requirements trace to the PhD thesis: Ch. 3 (Vote App protocol, Sec. 3.11
//! referendum optimization) and Ch. 5 (Commitment Access Tokens).

pub mod actors;
pub mod clients;
pub mod configuration;
pub mod domain;
pub mod error;
pub mod protocol;
pub mod telemetry;
