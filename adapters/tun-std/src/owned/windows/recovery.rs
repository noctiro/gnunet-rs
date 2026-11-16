//! Caller-owned original-adapter restart, with no packet/configuration replay.
use super::*;
use crate::AsyncTun;
use gnunet_native::wintun::{Adapter, RingCapacity};
use std::{fmt, net::Ipv4Addr};
mod reopen;
pub use reopen::{
    WintunReopen, WintunReopenError, WintunReopenStage, WintunReplacement, WintunReplacementKind,
    WintunScopeRetirement,
};

/// The original adapter after its packet source and native session retired.
/// It keeps original creation/removal responsibility without retaining packets,
/// callbacks or native session rings. Drop releases only that original adapter.
#[derive(Debug)]
pub struct WintunRecovery {
    adapter: Adapter,
    original: Epoch,
    capacity: RingCapacity,
    limits: Limits,
    ipv4: Option<Ipv4Addr>,
}
/// Exact stage at which an explicit restart was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WintunRestartStage {
    /// Observe original physical-interface loss before releasing its adapter.
    Detach,
    /// Open a fresh packet handle on the unchanged original interface scope.
    Reopen,
    /// Original-interface check or native session start.
    Start,
    /// Qualification after the original provider admitted the new session.
    Qualify,
    /// Buffer or read-event/reactor preparation.
    Register,
}
/// Restart refusal returns the original adapter and the actual stage/error.
#[derive(Debug)]
pub struct WintunRestartError {
    recovery: Box<WintunRecovery>,
    stage: WintunRestartStage,
    error: io::Error,
}
impl WintunRestartError {
    /// Recover the same original adapter for explicit retry or close.
    pub fn into_parts(self) -> (WintunRecovery, WintunRestartStage, io::Error) {
        (*self.recovery, self.stage, self.error)
    }
}
impl fmt::Display for WintunRestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wintun restart {:?}: {}", self.stage, self.error)
    }
}
impl std::error::Error for WintunRestartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl OwnedTun {
    /// Retire this packet epoch and end its session while preserving the actual
    /// adapter. Any reactor read-event registration must already be retired.
    pub fn retain_wintun(self) -> WintunRecovery {
        let Self {
            retirement,
            session,
            epoch,
            limits,
            ipv4,
            ..
        } = self;
        drop(retirement);
        let capacity = session.capacity();
        WintunRecovery {
            adapter: session.end(),
            original: epoch,
            capacity,
            limits,
            ipv4,
        }
    }
}
impl WintunRecovery {
    /// Transfer the same retained adapter for explicit native administration or
    /// a caller-selected ring profile. The retired packet epoch stays retired.
    pub fn into_adapter(self) -> Adapter {
        self.adapter
    }
    /// Retired packet-source identity. It never becomes current again.
    pub fn original_epoch(&self) -> &Epoch {
        &self.original
    }
    /// The retained actual adapter; metadata/administration keep its own native
    /// identity checks. This grants no completed packet-source restart.
    pub fn adapter(&self) -> &Adapter {
        &self.adapter
    }
    /// Release the retained original adapter without opening a replacement.
    pub fn close(self) {
        drop(self);
    }
    /// Start the same ring profile on the same original adapter and register a
    /// fresh packet epoch. The caller owns the entered I/O runtime and excludes
    /// concurrent interface mutation. No old packet, deadline, address or route
    /// operation is replayed. Link, route and DAD readiness must be observed anew.
    pub fn restart(self) -> Result<AsyncTun, WintunRestartError> {
        self.resume(false)
    }
    /// Refresh the provider packet handle on the unchanged original interface.
    /// Exact GUID/LUID/index/compartment qualification and retained creator
    /// lifetime precede a fresh session and packet epoch. This claims neither
    /// old-route absence nor new configuration readiness.
    ///
    /// # Errors
    /// Returns the original scope owner and actual stage on every returned
    /// refusal, including native handle, session and registration failures.
    pub fn refresh_scope(self) -> Result<AsyncTun, WintunRestartError> {
        self.resume(true)
    }
    fn resume(self, refresh: bool) -> Result<AsyncTun, WintunRestartError> {
        let Self {
            adapter,
            original,
            capacity,
            limits,
            ipv4,
        } = self;
        let refused = |adapter, stage, error| WintunRestartError {
            recovery: Box::new(Self {
                adapter,
                original: original.clone(),
                capacity,
                limits,
                ipv4,
            }),
            stage,
            error,
        };
        let adapter = if refresh {
            match adapter.reopen_retained() {
                Ok(adapter) => adapter,
                Err(failure) => {
                    let (adapter, error) = failure.into_parts();
                    return Err(refused(adapter, WintunRestartStage::Reopen, error));
                }
            }
        } else {
            adapter
        };
        let session = match adapter.start(capacity) {
            Ok(session) => session,
            Err(failure) => {
                let (adapter, error) = failure.into_parts();
                return Err(refused(adapter, WintunRestartStage::Start, error));
            }
        };
        let mut owner = match OwnedTun::try_from_wintun(session, limits) {
            Ok(owner) => owner,
            Err(failure) => {
                let (session, error) = failure.into_parts();
                return Err(refused(session.end(), WintunRestartStage::Qualify, error));
            }
        };
        // This is only the original exact-address observation selector, not an
        // address creation/deletion receipt or permission to replay mutation.
        owner.ipv4 = ipv4;
        match AsyncTun::try_new(owner) {
            Ok(io) => Ok(io),
            Err(failure) => {
                let (owner, error) = failure.into_parts();
                let adapter = owner.retain_wintun().adapter;
                Err(refused(adapter, WintunRestartStage::Register, error))
            }
        }
    }
}
