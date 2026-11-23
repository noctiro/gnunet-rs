//! Native output observations and original source retirement receipts.
#[cfg(any(target_os = "macos", target_os = "ios"))]
use super::FlowRetirement;
#[cfg(target_os = "linux")]
use super::TransparentRetirement;
use super::input::{InputRefusal, OriginalInput};
#[cfg(windows)]
use super::{CaptureRetirement, WfpRetirement};
use crate::{Error, core, transport::HelperExit};
use gnunet_tun_host::{Loss, LossCause};
use std::io;

/// Local write facts, without conflating helper pipe acceptance and device I/O.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Write {
    /// Positive local pipe prefix; whole framing is separate from TUN delivery.
    Pipe {
        /// Positive bytes accepted by the original local pipe.
        bytes: usize,
        /// The entire immutable helper frame was accepted locally.
        complete: bool,
    },
    /// The native boundary accepted one whole packet, including Wintun ring submission.
    Device {
        /// Raw IP extent accepted by this original native device boundary.
        bytes: usize,
    },
    /// Linux accepted one complete transparent UDP payload for output.
    #[cfg(target_os = "linux")]
    Datagram { bytes: usize },
    /// Original asynchronous injection completed with the whole packet length.
    #[cfg(windows)]
    Injection { bytes: usize },
    /// Completed native WFP injection and its original receive verdict.
    #[cfg(windows)]
    Wfp {
        bytes: usize,
        native_status: i32,
        authorized: bool,
    },
    /// Original application-flow write and its callback loans completed.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    Flow,
}
impl Write {
    pub(crate) fn exposed(self) -> bool {
        match self {
            Self::Pipe { bytes, .. } | Self::Device { bytes } => bytes != 0,
            #[cfg(target_os = "linux")]
            Self::Datagram { bytes } => bytes != 0,
            #[cfg(windows)]
            Self::Injection { bytes } | Self::Wfp { bytes, .. } => bytes != 0,
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Self::Flow => true,
        }
    }
    pub(crate) fn complete(self) -> bool {
        match self {
            Self::Pipe { complete, .. } => complete,
            Self::Device { .. } => true,
            #[cfg(target_os = "linux")]
            Self::Datagram { .. } => true,
            #[cfg(windows)]
            Self::Injection { .. } => true,
            #[cfg(windows)]
            Self::Wfp {
                native_status,
                authorized,
                ..
            } => native_status >= 0 && authorized,
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Self::Flow => true,
        }
    }
}
/// Original process/device retirement or native application callback disposal.
#[derive(Debug)]
#[non_exhaustive]
pub enum Retirement {
    /// Complete native process exit and independent stop/wait errors.
    Helper(HelperExit),
    /// Native source loss/close; a void provider close is not a removal ACK.
    Device(Loss),
    /// Transparent sockets released and original bypass-mark restoration observed.
    #[cfg(target_os = "linux")]
    Transparent(TransparentRetirement),
    /// A transparent capture generation closed while upstream marks stayed leased.
    #[cfg(target_os = "linux")]
    TransparentGeneration,
    /// Native filter close and original outstanding capture/injection loans.
    #[cfg(windows)]
    Capture(CaptureRetirement),
    /// Original WFP device stop and submitted injection discharge.
    #[cfg(windows)]
    Wfp(WfpRetirement),
    /// Application close requested and original callback loans retired.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    Flows(FlowRetirement),
}
impl Retirement {
    /// Whether this receipt contains an observed stop, wait, exit or device fault.
    pub fn has_failure(&self) -> bool {
        match self {
            Self::Helper(exit) => {
                !exit.status.success()
                    || exit.forced
                    || exit.signal_error.is_some()
                    || exit.wait_error.is_some()
            }
            #[cfg(windows)]
            Self::Capture(report) => report.has_failure(),
            #[cfg(windows)]
            Self::Wfp(report) => report.has_failure(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Self::Flows(report) => report.has_failure(),
            Self::Device(loss) => {
                loss.close_error.is_some() || !matches!(loss.cause, LossCause::Closed)
            }
            #[cfg(target_os = "linux")]
            Self::Transparent(report) => {
                report.mark_error.is_some() || report.probe_error.is_some()
            }
            #[cfg(target_os = "linux")]
            Self::TransparentGeneration => false,
        }
    }
}
/// One source step, preserving the kind of its physical write and retirement.
#[derive(Debug)]
pub(crate) enum SourceEvent<'id> {
    /// Exact DNS storage and its original reply owner, or source decoding refusal.
    Input(Result<OriginalInput, InputRefusal>),
    /// Original core effect received a local write observation.
    Written {
        /// Exact original outbound core operation.
        effect: core::Effect<'id>,
        /// Observed pipe prefix or native whole-packet submission.
        observation: Write,
    },
    /// One packet's native operation retired without a timely success claim.
    OutputStopped {
        effect: core::Effect<'id>,
        exposure: PacketExposure,
        total: usize,
        reason: Error,
    },
    /// One query or return route was refused; the source remains usable.
    #[cfg(any(windows, target_os = "macos", target_os = "ios", target_os = "linux"))]
    Refused(Error),
    /// Only this original application flow stopped; the source remains usable.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    FlowStopped {
        flow: gnunet_native::dns_proxy::FlowId,
        reason: Error,
    },
    /// One or more original Linux ingress observations were revoked.
    #[cfg(target_os = "linux")]
    IngressRetired,
    /// A complete interface refresh failed; the previous views remain intact.
    #[cfg(windows)]
    RouteObservationFailed(io::Error),
    /// Original source admission was revoked; suspend its resolver/effect work.
    #[cfg(any(windows, target_os = "linux"))]
    Suspended(io::Error),
    /// The old physical source closed; its original effects must be detached.
    #[cfg(any(windows, target_os = "linux"))]
    Detached {
        retirement: Retirement,
        pending: Option<PendingOutput<'id>>,
    },
    /// A replacement physical source actually attached before any new input.
    #[cfg(any(windows, target_os = "linux"))]
    Attached,
    /// A bounded read, reject or stop transition without packet delivery.
    Activity,
    /// Original transport failed; it must be retired without replay.
    Failed(io::Error),
    /// Original process/device retirement or application callback disposal.
    Retired(Retirement),
}
/// Local exposure observed when the original output is abandoned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketExposure {
    /// Bytes accepted by the original helper pipe, not delivery to its TUN.
    PipePrefix(usize),
    /// Native packet remained queued without submission at the device boundary.
    UnsubmittedPacket,
    /// Native injection was admitted; completion and delivery remain unknown.
    InjectionPending,
    /// Whole native injection completed after its original deadline or cancellation.
    InjectionAccepted,
    /// The kernel accepted a whole transparent UDP message after its deadline.
    #[cfg(target_os = "linux")]
    DatagramAccepted,
    /// The kernel returned an unexpected nonzero UDP send extent.
    #[cfg(target_os = "linux")]
    DatagramPrefix(usize),
    /// WFP provided the original NBL status and independent gate observation.
    #[cfg(windows)]
    WfpCompleted {
        /// Original native WFP completion status.
        native_status: i32,
        /// The original reply passed the active receive gate.
        authorized: bool,
    },
    /// An application-flow write awaits its original completion.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    FlowWritePending,
    /// A flow write completed after cancellation or its original deadline.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    FlowWriteAccepted,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingOutput<'id> {
    pub effect: core::Effect<'id>,
    pub exposure: PacketExposure,
    pub total: usize,
}
pub(crate) enum OutputStop {
    Requested,
    SourceRequired,
}
