//! Actual caller-driven generic SET SERVICE and original CADET ownership.
//! The old SET protocol is distinct from SETI and SETU. No hidden worker or RPC.
#![forbid(unsafe_code)]
/// Explicit native randomness and bounded standard zlib provider.
pub mod ports;
/// Real bounded application sockets and shared native CADET reactor.
pub mod server;
