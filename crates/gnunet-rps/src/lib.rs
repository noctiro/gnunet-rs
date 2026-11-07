//! GNUnet RPS: bounded Brahms gossip and client min-wise sampling.
//!
//! Transport authenticates the peer and subgroup. This core never treats a
//! local write as a remote liveliness proof, nor manufactures a peer ACK.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod sampler;
#[cfg(feature = "alloc")]
mod service;
#[cfg(feature = "alloc")]
pub use sampler::{ClientSampler, Random, Rank, SampleInfo, Sampler};
#[cfg(feature = "alloc")]
pub use service::{
    Action, Client, Completion, Config, Effect, EffectId, GroupId, Instance, Limits, PeerOutput,
    Service, Terminal,
};

/// Authenticated GNUnet EdDSA peer identity, never a hostname.
pub type Peer = [u8; 32];
/// Actual SHA-512 CADET port/subgroup hash, supplied by the host.
pub type Group = [u8; 64];
