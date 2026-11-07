//! The installed Paillier scalarproduct profile, distinct from the ECC protocol.
//! Caller-owned SETI and CADET sources retain all physical IO and original causes.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod alice;
#[cfg(feature = "alloc")]
mod bob;
mod error;
mod math;
#[cfg(feature = "alloc")]
mod support;
#[cfg(feature = "alloc")]
mod vector;

#[cfg(feature = "alloc")]
pub use alice::Alice;
#[cfg(feature = "alloc")]
pub use bob::Bob;
pub use error::Error;
#[cfg(feature = "alloc")]
pub use gnunet_scalarproduct::{HashOrder, Value};
pub use math::{AliceMath, BobSums, Mpi, Product, alice_value, bob_left, bob_right};
#[cfg(feature = "alloc")]
pub use support::{Binding, Frame, Instance, Limits, OutputId, RejectedFrame, Terminal};
#[cfg(feature = "alloc")]
pub use vector::MatchedVector;

/// A finite supported coefficient count. Even the largest i64 products and
/// signed32 masks then fit the checked256-bit intermediate arithmetic.
pub const MAX_ROWS: usize = 1 << 20;

#[cfg(all(test, feature = "alloc"))]
mod tests;
