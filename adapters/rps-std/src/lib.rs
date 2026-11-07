//! Actual caller-driven RPS SERVICE and subgroup CADET channel ownership.
//! No background task, private protocol, sampler-result frame or peer ACK.
#![forbid(unsafe_code)]
/// Concrete explicit cryptographic-randomness/ranking and standard port helpers.
pub mod ports;
/// Real bounded application sockets and shared native CADET reactor.
pub mod server;
