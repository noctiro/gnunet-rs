//! Bounded official GNUnet scalarproduct ECC arithmetic and computation owner.
//!
//! Native source authentication, clocks and physical I/O belong to the host.
//! An effect's local whole-write never proves remote acceptance or processing.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod crypto;
#[cfg(feature = "alloc")]
mod dlog;
#[cfg(feature = "alloc")]
mod session;
#[cfg(all(test, feature = "alloc"))]
mod tests;
#[cfg(feature = "alloc")]
mod vector;

#[cfg(feature = "alloc")]
pub use crypto::{AliceKey, PointPair, aggregate, unblind, validate_point};
#[cfg(feature = "alloc")]
pub use dlog::{Dlog, DlogLimits, DlogProgress};
#[cfg(feature = "alloc")]
pub use session::{
    Action, Completion, Computation, Effect, EffectId, Failure, InputId, Instance, IntersectionId,
    Limits, Outcome, PeerOutput, PeerSource, ResultValue, Role, Stage,
};
#[cfg(feature = "alloc")]
pub use vector::{HashOrder, Value, Vector};
