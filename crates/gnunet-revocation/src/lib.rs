//! Official GNUnet revocation certificates, IPC and caller-scheduled work.
//! Structural decoding is not signature/PoW validation or a service receipt.
#![no_std]
#![forbid(unsafe_code)]
pub mod ipc;
mod mining;
mod proof;
mod validation;
pub use gnunet_block::plugins::{Clock, RevocationConfig};
pub use gnunet_block::pow;
pub use gnunet_block::revocation::Verification;
pub use mining::{Miner, MiningProgress};
pub use proof::*;
pub use validation::{Check, CheckedCertificate};
/// Current installed WORKBITS. A different network value changes acceptance.
pub const DEFAULT_WORKBITS: u32 = 22;
/// Current installed EPOCH_DURATION365days, in microseconds.
pub const DEFAULT_EPOCH_MICROS: u64 = 365 * 24 * 60 * 60 * 1_000_000;
/// Official fixed timestamp predating used by the signing initializer: one week.
pub const PREDATE_MICROS: u64 = 7 * 24 * 60 * 60 * 1_000_000;
/// Installed revocation policy; TTL inside the certificate remains informational.
pub const DEFAULT_POLICY: RevocationConfig = RevocationConfig {
    matching_bits: DEFAULT_WORKBITS,
    epoch_duration: DEFAULT_EPOCH_MICROS,
};
