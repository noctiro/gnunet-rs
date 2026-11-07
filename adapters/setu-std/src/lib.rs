//! Caller-driven official SETU app service and one actual shared CADET client.
//! No peer, ACK, identity, thread, protocol credit or native callback is invented.
#![forbid(unsafe_code)]
/// Bounded native app/CADET ownership and real foreground scheduling.
pub mod server;
