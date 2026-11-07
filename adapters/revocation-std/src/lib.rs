//! Actual REVOCATION service composition. Durable accepted facts, fresh actual
//! proof checks, native IPC replies and CORE/SETU local writes remain distinct.
#![forbid(unsafe_code)]
mod inventory;
pub mod server;
pub mod verification;
pub use inventory::{Inventory, StoredFact};
