//! Windows Filtering Platform control and device transport for DNS interception.
//!
//! This adapter provisions persistent callout metadata and owns the service's
//! local device channel. The kernel driver owns capture filters and packet I/O.

#[cfg(windows)]
mod contract;
#[cfg(all(windows, feature = "operator-cli"))]
pub mod deployment;
#[cfg(windows)]
pub mod device;
#[cfg(windows)]
mod error;
#[cfg(windows)]
mod sdk;
#[cfg(windows)]
pub use contract::{
    CLOSURE_V4, CLOSURE_V6, Callout, DATAGRAM_V4, DATAGRAM_V6, DRIVER_PROVIDER, FLOW_V4, FLOW_V6,
};
#[cfg(windows)]
pub use error::{Cleanup, NativeFailure};
#[cfg(windows)]
pub use sdk::provision::{
    ChangeFailure as ProvisionFailure, Error as ProvisionError, InstallationReceipt, Installed,
    Object as MetadataObject, Outcome as ProvisionOutcome, Problem as ProvisionProblem,
    ProvisionLimits, Provisioner,
};

#[cfg(windows)]
pub mod upstream;
