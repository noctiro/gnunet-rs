//! Shared route effects and explicitly distinct native completion evidence.
use crate::{Action, EffectId, Info, Timing};
use std::io;
use tokio::time::Instant;
/// Original request exposure, independent of kernel acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSubmission {
    /// No mutation request was admitted.
    Unsent,
    /// The synchronous native administrative path was entered. It can fail
    /// qualification before mutation; it has no socket frame or ACK sequence.
    NativeCall,
    /// One whole original native request was written.
    Whole {
        /// Complete actual native frame bytes.
        bytes: usize,
    },
    /// Unexpected positive partial write; never resume its suffix.
    Partial {
        /// Actual exposed native bytes.
        bytes: usize,
    },
    /// A native write error may have followed synchronous processing.
    Unknown,
}
/// Actual kernel response or explicit uncertainty/local unsent retirement.
#[derive(Debug)]
pub enum RouteOutcome {
    /// Correlated native ACK: Ok is actual kernel success,
    /// Err preserves the kernel's actual rejection errno.
    KernelAck(io::Result<()>),
    /// Actual synchronous native return, including an original qualification
    /// error before mutation. It is never represented as a socket ACK.
    NativeReturn(io::Result<()>),
    /// No request was written before cancellation/source/deadline.
    Unsent(io::Error),
    /// Request may have changed the kernel; no success/rejection is invented.
    Uncertain(io::Error),
}
impl RouteOutcome {
    /// Actual successful socket ACK or synchronous native return.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::KernelAck(Ok(())) | Self::NativeReturn(Ok(())))
    }
    /// Original native rejection, independent of its transport/provenance.
    #[must_use]
    pub fn native_error(&self) -> Option<&io::Error> {
        match self {
            Self::KernelAck(Err(error)) | Self::NativeReturn(Err(error)) => Some(error),
            _ => None,
        }
    }
    /// This actual native rejection permits a read-only reconciliation attempt,
    /// never acceptance or absence credit. Windows missing scope/family errors
    /// require a fresh original-interface/family-qualified getter.
    #[must_use]
    pub fn is_reconcilable_rejection(&self, removing: bool) -> bool {
        match self {
            Self::KernelAck(Err(error)) => {
                if removing {
                    self.is_missing_route_rejection()
                } else {
                    error.kind() == io::ErrorKind::AlreadyExists
                }
            }
            #[cfg(windows)]
            Self::NativeReturn(Err(error)) => {
                gnunet_native::wintun::route_error_kind(error)
                    == if removing {
                        io::ErrorKind::NotFound
                    } else {
                        io::ErrorKind::AlreadyExists
                    }
            }
            _ => false,
        }
    }
    /// A correlated Unix ACK rejected this mutation because its route was
    /// missing. Windows ERROR_NOT_FOUND can also denote an unavailable interface
    /// or family and is not promoted to a missing-route classification.
    #[must_use]
    pub fn is_missing_route_rejection(&self) -> bool {
        match self {
            Self::KernelAck(Err(error)) => {
                #[cfg(unix)]
                {
                    error.kind() == io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(libc::ESRCH)
                }
                #[cfg(not(unix))]
                {
                    error.kind() == io::ErrorKind::NotFound
                }
            }
            _ => false,
        }
    }
}
/// Terminal original route observation. It contains no reusable Effect authority.
#[derive(Debug)]
pub struct RouteCompletion {
    /// Original device/effect authority.
    pub id: EffectId,
    /// Exact requested action.
    pub action: Action,
    /// Original interface snapshot, never rebound to a replacement.
    pub interface: Info,
    /// Original Linux table or FreeBSD FIB; macOS uses interface-scoped routes.
    pub table: Option<u32>,
    /// Original absolute transaction deadline.
    pub deadline: Instant,
    /// Actual exposure fact.
    pub submission: RouteSubmission,
    /// Real ACK or honest local uncertainty.
    pub outcome: RouteOutcome,
    /// Source/deadline state when observed.
    pub timing: Timing,
    /// Independent native control-socket close error; never retried.
    pub close_error: Option<io::Error>,
    /// Original native write error, retained even if a later ACK/deadline settles it.
    pub write_error: Option<io::Error>,
}
/// One bounded caller-driven native transaction step.
#[derive(Debug)]
pub enum RouteProgress {
    /// Whole original request entered the kernel;
    /// this is not an ACK or proof of route installation.
    Submitted {
        /// Exact original effect.
        id: EffectId,
        /// Actual native bytes written.
        bytes: usize,
    },
    /// Actual native write returned an error; a synchronous kernel may still
    /// emit its correlated reply. The original errno remains on this owner.
    WriteError {
        /// Exact original effect.
        id: EffectId,
    },
    /// One bounded unrelated kernel message was consumed.
    Activity {
        /// Actual native bytes read.
        bytes: usize,
    },
    /// Correlated actual terminal result/local retirement.
    Complete(RouteCompletion),
    /// This caller wait ended; original socket/deadline remain.
    WaitDeadline,
    /// Terminal result was already consumed.
    Finished,
}
