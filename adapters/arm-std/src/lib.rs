//! Official ARM operation owners with persistent real Unix/TCP and local launch.
//! The shared public CLIENT transport façade preserves native endpoint selection.
//! No libgnunet production FFI or private wire exists.
#![deny(unsafe_code, missing_docs)]
#![cfg(unix)]
use gnunet_client_host::ConnectError as IpcError;
/// Shared caller configuration with no implicit reconnect or callback authority.
pub use gnunet_client_host::LiveConfiguration;
mod control;
mod endpoint;
pub mod launch;
mod monitor_host;
mod mq;
pub use control::{CallbackContext, ClientHost};
/// Shared native process owner; ARM-specific launch remains in [`launch`].
pub use gnunet_service_runtime::process;
use gnunet_types::{AbsoluteTime, Error};
pub use launch::{ChildRegistry, LaunchLimits, LocalLauncher};
pub use monitor_host::{MonitorContext, MonitorEvent, MonitorHost};
use std::{fmt, io};
/// One caller-owned logical scheduler clock subscription. Each independently
/// waiting control/monitor owner requires its own subscription; callback ports
/// only sample it. An adjustment never changes an already registered deadline.
pub struct Clock {
    source: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    subscription: Option<Box<dyn gnunet_service_runtime::clock::ClockSubscription>>,
}
impl Clock {
    /// Select the native absolute wall-clock profile without a process offset.
    pub fn system() -> Result<Self, HostError> {
        Self::new(std::sync::Arc::new(
            gnunet_service_runtime::clock::SystemClock,
        ))
    }
    /// Attach an original caller-owned PROGRAM/shared-clock subscription.
    pub fn new(
        source: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    ) -> Result<Self, HostError> {
        let subscription = source.subscribe()?;
        Ok(Self {
            source,
            subscription: Some(subscription),
        })
    }
    fn retire(&mut self) {
        self.subscription = None;
    }
    /// Sample current logical source microseconds; backwards adjustments are valid.
    /// Sampling remains available after the enclosing host closes its waiter.
    pub fn now(&self) -> Result<AbsoluteTime, HostError> {
        Ok(self.source.sample()?.now)
    }
}
/// Explicit bounded host resources; these are not GNUnet configuration keys.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum full official u16 frame width, from4 through65535.
    pub max_frame_bytes: usize,
    /// Maximum bytes offered per actual read/write poll; nonzero.
    pub io_slice_bytes: usize,
    /// Maximum simultaneous original startup-signal resource slots.
    pub max_startup_signals: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 65535,
            io_slice_bytes: 65535,
            max_startup_signals: 64,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), HostError> {
        if !(4..=65535).contains(&self.max_frame_bytes)
            || self.io_slice_bytes == 0
            || self.max_startup_signals == 0
        {
            Err(Error::InvalidInput.into())
        } else {
            Ok(())
        }
    }
}
/// A real boundary failure; refused finite resources do not invent peer success.
#[derive(Debug)]
pub enum HostError {
    /// Core admission/ownership or explicit finite host capacity failed.
    Core(Error),
    /// Actual GNUNET_CLIENT-compatible endpoint/MQ configuration failure.
    Endpoint(IpcError),
    /// Actual local command/pipe/spawn/reap failure.
    Launch(launch::LaunchError),
    /// Actual reactor/socket boundary failure.
    Io(io::Error),
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "ARM core: {e}"),
            Self::Endpoint(e) => write!(f, "ARM MQ: {e}"),
            Self::Launch(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "ARM I/O: {e}"),
        }
    }
}
impl std::error::Error for HostError {}
impl From<Error> for HostError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
impl From<gnunet_config::Error> for HostError {
    fn from(e: gnunet_config::Error) -> Self {
        Self::Endpoint(IpcError::Configuration(e))
    }
}
impl From<IpcError> for HostError {
    fn from(e: IpcError) -> Self {
        Self::Endpoint(e)
    }
}
impl From<launch::LaunchError> for HostError {
    fn from(e: launch::LaunchError) -> Self {
        Self::Launch(e)
    }
}
impl From<io::Error> for HostError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
/// One completed drive step, independent from original operation completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// A genuine I/O, timer, effect or synchronous callback step occurred.
    Activity,
    /// Only this call's wait budget expired; original state/cursors remain.
    WaitDeadline,
    /// The logical owner and all its original signal/socket resources retired.
    Closed,
}
