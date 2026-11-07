//! Actual caller-polled official ABD SERVICE, GNS and private NAMESTORE owners.
//! No background task, private protocol, implicit Resolver or fake proof exists.
#![forbid(unsafe_code)]
mod run;
mod server;
mod types;
pub use server::Server;
pub use types::{ClientReport, Error, Event, Limits, Progress, Report, Sources};
