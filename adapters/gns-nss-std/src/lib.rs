//! GNU libc NSS host-address integration using actual official GNS IPC.
//!
//! Every call owns a bounded joined worker, current-thread runtime, clock,
//! shared Resolver driver and original with-TLD lookup. There is no permanent
//! worker, CLI child, hidden DNS fallback, libgnunet FFI or cached private key.
//! GNU Linux exports the nine official gns/gns4/gns6 host-address hooks; ordinary
//! Unix builds retain the safe Rust host API without pretending to export an OS
//! NSS ABI for a different libc.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[expect(
    unsafe_code,
    reason = "GNU NSS requires raw C pointers and unmangled OS symbols; the checked boundary is isolated in this module"
)]
pub mod abi;
#[cfg(unix)]
mod bootstrap;
#[cfg(unix)]
mod lookup;
mod types;
#[cfg(unix)]
mod worker;
pub use types::{Completion, Error, Family, Limits, Outcome, Report};
#[cfg(unix)]
pub use worker::lookup;
