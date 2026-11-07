//! Caller-owned process-shared official Resolver MQ, request FIFO and driver.
//!
//! Sharing Context clones shares one core and one physical owner. No per-query
//! resolver connection, host DNS substitution, private wire or background task.
#![forbid(unsafe_code)]
mod clock;
mod driver;
mod lookup;
mod profile;
pub use profile::{check_config, native_profile};
mod shared;
pub use clock::{AbsoluteTime, ClockSample, ClockSubscription, RuntimeClock, SystemClock};
pub use driver::{Driver, DriverEvent, Progress};
pub use gnunet_client::resolver::{Family, FamilyProfile};
pub use gnunet_client::resolver_handle::{Completion, Hostname};
use gnunet_client_host::ConnectError as IpcError;
pub use gnunet_client_host::LiveConfiguration;
use gnunet_types::Error;
pub use shared::{Context, Delivery, Drain, Query, Reply, Token};
use std::{fmt, io, sync::Arc};
/// Declared bounded host resources, independent of official configuration keys.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete type4/5 frame capacity, from8 through65535.
    pub max_frame_bytes: usize,
    /// Fairness bound for each actual read/write system call; nonzero.
    pub io_chunk_bytes: usize,
    /// Immutable MQ credits: live remote requests plus orphan envelopes still
    /// awaiting physical transfer. Reserved before admission, so queue pressure
    /// cannot consume a core submission then prevent transport progress.
    pub max_queued_frames: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 65535,
            io_chunk_bytes: 65535,
            max_queued_frames: 8,
        }
    }
}
/// Actual boundary or caller resource failure, never a fabricated DNS result.
#[derive(Debug)]
pub enum BrokerError {
    /// Core rejection or explicit resource bound.
    Core(Error),
    /// Actual endpoint/configuration/socket failure.
    Ipc(IpcError),
    /// Actual OS failure outside endpoint resolution.
    Io(io::Error),
    /// The unique driver was dropped; outstanding callbacks are suppressed.
    OwnerLost,
    /// A private synchronization invariant was poisoned by a panic.
    Poisoned,
}
impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "resolver broker core: {e}"),
            Self::Ipc(e) => write!(f, "resolver broker endpoint: {e}"),
            Self::Io(e) => write!(f, "resolver broker IO: {e}"),
            Self::OwnerLost => f.write_str("resolver broker driver was dropped"),
            Self::Poisoned => f.write_str("resolver broker state poisoned"),
        }
    }
}
impl std::error::Error for BrokerError {}
impl From<Error> for BrokerError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
impl From<IpcError> for BrokerError {
    fn from(e: IpcError) -> Self {
        Self::Ipc(e)
    }
}
impl From<io::Error> for BrokerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
/// Construct one shared process context and its uniquely owned reactor.
/// R bounds all core slots including one reserved for the driver's own TCP
/// address lookup; R and MQ credits must each be at least2. N bounds owned
/// forward names. External requests cannot consume the last internal credit.
/// Construction does no I/O and spawns no task. Caller drives the returned owner.
pub fn broker<const R: usize, const N: usize>(
    configuration: LiveConfiguration,
    limits: Limits,
    profile: FamilyProfile,
    clock: Arc<dyn RuntimeClock>,
) -> Result<(Context<R, N>, Driver<R, N>), BrokerError> {
    if !(8..=65535).contains(&limits.max_frame_bytes)
        || limits.io_chunk_bytes == 0
        || limits.max_queued_frames < 2
        || R < 2
    {
        return Err(Error::InvalidInput.into());
    }
    let context = Context::build(configuration, limits, profile, clock)?;
    let driver = Driver::build(context.clone(), limits)?;
    Ok((context, driver))
}

/// Native synchronous FQDN helper, preserving the audited normal getaddrinfo
/// profile. It can consult NSS/mDNS/DNS and is never used for ordinary shared
/// forward queries. The returned OS string is owned and freed by Rust Drop.
pub fn local_fqdn_get() -> Result<std::ffi::OsString, gnunet_native::NativeError> {
    gnunet_native::local_fqdn()
}
