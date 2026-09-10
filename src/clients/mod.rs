//! Typed HTTP clients for peer services : one struct per
//! peer, mandatory timeouts, strongly-typed bodies.
//!
//! Clients: `wbb`, `er`, `dip`, `ns`, `rt`, `tt`, `bb`.

pub mod bb;
pub mod dip;
pub mod er;
pub mod ns;
pub mod rt;
pub mod tt;
pub mod wbb;
