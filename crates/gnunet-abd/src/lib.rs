//! Official ABD signed credentials and bounded conjunctive/linked delegation.
//! Native GNS authenticity, clocks, lookup sources and physical cancellation
//! belong to explicit caller owners. A wire found word is never a proof here.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod credential;
#[cfg(feature = "alloc")]
mod resolver;
#[cfg(feature = "alloc")]
mod resource;
#[cfg(feature = "alloc")]
pub use credential::{Credential, Principal, Time, issue};
#[cfg(feature = "alloc")]
pub use resolver::{Action, Edges, Effect, Instance, Limits, LookupId, Outcome, Query, Record};

#[cfg(all(test, feature = "alloc"))]
mod tests;
