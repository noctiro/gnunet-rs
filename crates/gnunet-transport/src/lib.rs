//! Owned, event-driven current GNUnet TRANSPORT protocol.
//!
//! Peer authentication, flow control and IPC ownership are kept apart from OS
//! sockets and durable identity/storage. This crate is not a C scheduler clone.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
pub mod addresses;
pub mod application;
pub mod communicator;
/// Official DV framing, real signature checks and bounded caller-storage routing.
pub mod dv;
#[cfg(feature = "alloc")]
mod engine;
#[cfg(feature = "alloc")]
mod fragment;
#[cfg(feature = "alloc")]
pub mod monotime;
#[cfg(feature = "alloc")]
mod outbound;
#[cfg(feature = "alloc")]
pub mod own;
#[cfg(feature = "alloc")]
pub mod own_hello;
pub mod own_wire;
pub mod p2p;
/// Independent local scheduling and GNUnet absolute-time coordinates.
pub mod time;
pub use time::Times;
#[cfg(feature = "alloc")]
pub mod signing;
#[cfg(feature = "alloc")]
pub use engine::burst;
#[cfg(feature = "alloc")]
pub use engine::dv_bridge;
#[cfg(feature = "alloc")]
pub use engine::monitor;
#[cfg(feature = "alloc")]
pub use engine::{
    ClientId, Engine, Limits, Output, QueueRejection, ReceiveOutcome, RemoteDrop, Signer, Snapshot,
    WorkDeferral, WorkStatus,
};
pub use gnunet_client::transport::PeerId;
