//! Protocol orchestration over `evoting-rs` — framework-free (style guide §06:
//! no web types in this module tree).
//!
//! Implemented per roadmap: `rng`/`clock` (M2), `tls` (M2), `setup` (M3),
//! `merkle` (M3), `enrollment` (M5), `cat`/`voting` (M6), `pin_management`
//! (M7), `tally`/`audit` (M8).

pub mod clock;
pub mod merkle;
pub mod rng;
pub mod setup;
pub mod tls;
