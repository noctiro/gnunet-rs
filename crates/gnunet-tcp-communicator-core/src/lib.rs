//! Source-derived v0.29.1 TCP communicator record/identity component.
//! Caller-buffer sessions, exact local service bytes and bounded registry metadata.
//! Native effects are supplied by the separate host; no implicit RNG or private handshake.
#![no_std]
#![forbid(unsafe_code)]
/// Exact initial Elligator confirmation composition; no queue admission.
pub mod initial;
/// Actual official TCP statistics coordinates; no wire or native owner.
pub mod metrics;
/// Exact NAT IPC sockaddr profiles and official TCP reversal preamble.
pub mod nat;
pub mod record;
/// Scope-branded bounded physical-session and NAT-reversal metadata.
pub mod registry;
/// Exact local PEERSTORE/PILS/TRANSPORT IPC bytes with explicit effect ownership.
pub mod services;
/// Bounded source-shaped session owner with explicit leased external effects.
pub mod session;
pub mod wire;

#[cfg(test)]
extern crate std;
