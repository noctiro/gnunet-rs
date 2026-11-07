//! Shared bounded business core of GNUnet v0.29.1's STATISTICS service.
//!
//! [`Statistics`] implements the official SET, GET and WATCH behavior. Its
//! capacities bound stored rows, bytes per row, connections, watches and queued
//! notifications. Admission checks all affected capacities before committing.
//! Notifications remain queued until the transport consumes them; a full queue
//! refuses a change instead of silently losing an intermediate value.
//!
//! Default features preserve allocation-free fixed tables and const construction.
//! The optional `alloc` feature adds an initially empty, explicitly limited
//! deployment backing and owned GET metadata, using the same protocol commits.
//!
//! This crate provides neither a socket daemon nor a filesystem. Persistent
//! records use the official concatenated SET format through [`Statistics::persistent`]
//! and [`Statistics::restore`]. The application owns durable storage and shutdown.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod protocol;
mod service;
mod storage;

pub use gnunet_client::statistics::{
    PERSIST_BIT, SET_PERSISTENT, SET_RELATIVE, Selector, Set, Statistic,
};
pub use protocol::{Notification, Reply, Request, encode_disconnect_confirmation};
#[cfg(feature = "alloc")]
pub use service::{AllocatedStatistics, PersistentSnapshot, SnapshotId};
pub use service::{ClientId, Get, Persistent, ResourceLimits, SetOutcome, Statistics};
