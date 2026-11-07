//! Native TCP communicator foreground resources with original session ownership.
//! The enclosing foreground/identity/configuration owner is being composed here;
//! this crate does not implement a replacement TRANSPORT or PEERSTORE service.
#![forbid(unsafe_code)]
/// Real bounded interface/NAT candidate publication on the original TCP Pool.
pub mod addresses;
/// Real shared Resolver hostname prebinding before USERNAME.
pub mod bind_resolution;
/// Explicit canonical/signed-time source and original native error ownership.
pub mod clock;
/// Retained service acquisition before any protocol effect.
pub mod dial;
/// Original fenced backend epoch and signed-time persistence.
pub mod epoch;
/// Actual numeric/inherited and shared-Resolver-prebound TCP listener owners.
pub mod listeners;
mod native;
mod pool;
/// Original-socket ordinary/probe classification and real connectback writer.
pub mod preamble;
/// Official communicator configuration and bounded BINDTO targets.
pub mod settings;
/// Explicit verified-local-capability foreground entry.
pub mod startup;
/// App-supplied statistics on the same original Resolver and process clock.
pub mod statistics;
pub use native::NativeConnect;
pub use pool::{AdmissionError, Pool, PoolProgress, Reversal, Setup};

/// Original ClockPort plus actual single-worker replay history composition.
pub mod process_ports;
/// Qualified durable replay floors and recovery catalog.
pub use gnunet_tcp_replay_host as replay;
