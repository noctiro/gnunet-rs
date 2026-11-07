//! Caller-driven ECC/Paillier scalarproduct SERVICE with one SETI/CADET reactor.
//! No spawned task, replacement computation epoch or private protocol exists.
#![forbid(unsafe_code)]
mod backend;
mod input;
mod profile;
mod run;
mod server;
mod types;
pub use backend::{Failure, Outcome, PaillierOutcome};
/// Actual pure Paillier resource policy for explicit native profile selection.
pub use gnunet_scalarproduct_paillier::Limits as PaillierLimits;
pub use profile::Profile;
pub use server::Server;
pub use types::{Error, Event, Limits, Progress, Report, Role, SessionReport, Sources};

fn buffer(len: usize) -> Result<Vec<u8>, gnunet_types::Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    bytes.resize(len, 0);
    Ok(bytes)
}
