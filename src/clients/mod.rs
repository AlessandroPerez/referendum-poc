//! Typed HTTP clients for peer services (style guide §11): one struct per
//! peer, mandatory timeouts, strongly-typed bodies.
//!
//! Implemented per roadmap: `wbb` (M2), `er`/`dip`/`ns` (M3), `rt`/`tt` (M4),
//! `bb`/`voter` (M5–M6).

pub mod bb;
pub mod dip;
pub mod er;
pub mod ns;
pub mod rt;
pub mod tt;
pub mod wbb;
