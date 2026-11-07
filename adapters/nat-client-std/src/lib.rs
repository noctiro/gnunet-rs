//! Real original-MQ NAT registration and NATauto query clients. No wire RID,
//! ACK/CANCEL, implicit Resolver/task, mutation replay or fabricated NAT truth.
#![cfg(unix)]
#![forbid(unsafe_code)]
pub use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
pub use gnunet_wire::official::{nat as ipc, nat_auto as auto_ipc};
use std::{
    fmt,
    future::poll_fn,
    io as stdio,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
mod types;
pub use types::*;
mod io;
mod registration;
pub use registration::{
    Notification, OwnedNotification, Progress, Registration, RegistrationRequest,
};
mod auto;
pub use auto::{AutoProgress, AutoQuery, AutoResult};
/// Actual constructor/admission/access failure, distinct from local source end
/// or raw NATauto status. Read/write errors travel in the original End cause.
#[derive(Debug)]
pub enum Error {
    /// Original codec/resource/ownership refusal.
    Protocol(Fault),
    /// Exact caller configuration serialization failure.
    Configuration(gnunet_config::Error),
    /// Original canonical clock error.
    Clock(Fault),
    /// Exact shared CLIENT/configuration/Resolver failure.
    Ports(gnunet_client_host::ConnectError),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Ports(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NAT client: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Explicit ordinary NAT selector, reusing caller's existing configuration/ports.
pub fn nat_source(
    live: LiveConfiguration,
    resolution: resolution::SharedResolution,
) -> EndpointSource {
    EndpointSource::live(live, b"nat", resolution)
}
/// Correct actual NATauto selector. The pinned C API's erroneous `nat` target
/// is intentionally not copied into this default constructor path.
pub fn auto_source(
    live: LiveConfiguration,
    resolution: resolution::SharedResolution,
) -> EndpointSource {
    EndpointSource::live(live, b"nat-auto", resolution)
}
/// Explicit local build ABI helper; constructors still require Profiles. Other
/// platforms are Unsupported rather than guessed from address data.
pub fn native_profile() -> Result<ipc::Profile, Error> {
    let order = if cfg!(target_endian = "little") {
        ipc::Endian::Little
    } else {
        ipc::Endian::Big
    };
    if cfg!(target_os = "linux") {
        Ok(ipc::Profile::linux(order))
    } else if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        Ok(ipc::Profile::darwin(order))
    } else if cfg!(target_os = "freebsd") {
        Ok(ipc::Profile::freebsd(order))
    } else {
        Err(Fault::Unsupported.into())
    }
}
fn encoded(request: ipc::Request<'_>, profile: ipc::Profile) -> Result<OwnedFrame, Error> {
    let n = request.encoded_len(profile)?;
    let mut b = Vec::new();
    b.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    b.resize(n, 0);
    request.encode(profile, &mut b)?;
    Ok(OwnedFrame::new(b))
}
