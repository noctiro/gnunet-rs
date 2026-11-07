//! Bounded actual REST handlers over original official native client owners.
//! Consuming request futures own their native MQs. Dropping a request physically
//! releases those original sources; it never replays an exposed mutation.
#![forbid(unsafe_code)]
pub mod config;
mod consume;
pub use consume::{ConsumeFailure, ConsumeProfile, ConsumeStatus};
pub mod gns;
mod handlers;
pub mod http;
mod identity;
mod namestore;
#[cfg(feature = "oidc")]
pub mod oidc;
mod output;
mod reclaim;
pub use handlers::{Context, Instances, Limits, OwnedRequest, Response, ResponseHeader, Sources};
pub use output::{Error, OAuthChallenge};
#[cfg(test)]
mod test_support;
