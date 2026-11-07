//! Allocation-free official CADET channel ownership and local flow control.
//!
//! The host owns the original physical MQ, immutable outgoing frame copies and
//! partial native cursors. This crate schedules no I/O, clock or background task.
//! A complete IPC write is never remote application delivery. A service ACK is
//! only one additional local send credit. No Rust token is serialized on wire.
#![no_std]
#![forbid(unsafe_code)]

pub mod client;
pub mod connection;
pub mod peer;
pub mod service;
/// Caller-storage CADET Axolotl mechanism and explicit KX/rekey controller.
pub mod tunnel;

/// Actual bounded official non-DHT event observations.
pub mod statistics;
