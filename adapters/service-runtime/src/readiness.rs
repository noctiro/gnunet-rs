//! Owned readiness registration with native nonconsuming level confirmation.
#[cfg(unix)]
mod descriptor;
#[cfg(unix)]
pub use descriptor::{RegisterError, RegisteredReadiness};
#[cfg(unix)]
mod io;
#[cfg(unix)]
pub use io::RegisteredIo;
mod listener;
pub use gnunet_native::network::{SocketEvents, SocketInterest};
pub use listener::RegisteredListener;
/// Actual level-ready flags, preserved independently rather than inferred from a hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Readiness {
    /// Kernel reports readable data/listener backlog.
    pub readable: bool,
    /// Kernel reports hangup; the caller chooses its source-specific EOF policy.
    pub hangup: bool,
    /// Kernel reports an exceptional socket/pipe error.
    pub error: bool,
}
