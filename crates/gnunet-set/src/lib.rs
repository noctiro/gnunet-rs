//! Official generic SET public semantics and bounded original-operation owners.
//!
//! Generic SET is a distinct active contrib protocol. Its native ABI, old IBF,
//! Bloom messages and lazy-copy/iteration IPC are not SETI/SETU message aliases.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod owner;
mod types;
pub use gnunet_wire::official::set as wire;
#[cfg(feature = "alloc")]
pub use owner::{Client, EffectId, Incoming, Instance, Operation, PeerOwner};
pub use types::{OperationFailure, OperationType, ResultMode, Status};
#[cfg(feature = "alloc")]
mod allocation;
#[cfg(feature = "alloc")]
mod content;
#[cfg(feature = "alloc")]
pub use content::{Content, ContentLimits, Snapshot};

#[cfg(feature = "alloc")]
mod effect;
#[cfg(feature = "alloc")]
pub use effect::{
    Action, CompletedEffect, Completion, Effect, EffectScan, EffectScanStep, Terminal,
};
#[cfg(feature = "alloc")]
mod ports;
pub use gnunet_types::Error;
#[cfg(feature = "alloc")]
pub use ports::{Compression, Ports, Random};

#[cfg(feature = "alloc")]
mod limits;
#[cfg(feature = "alloc")]
pub use limits::Limits;

#[cfg(feature = "alloc")]
mod engine;
#[cfg(feature = "alloc")]
mod ibf;
#[cfg(feature = "alloc")]
mod intersection;
#[cfg(feature = "alloc")]
mod service;
#[cfg(feature = "alloc")]
mod strata;
#[cfg(feature = "alloc")]
mod union;
#[cfg(feature = "alloc")]
pub use service::Service;
