//! Packet transport independent of helper process and native device ownership.
mod device;
#[cfg(windows)]
mod divert;
use crate::{
    Error, core,
    transport::{Helper, HelperEvent, HelperExit},
};
use device::Device;
#[cfg(windows)]
use divert::Capture;
#[cfg(windows)]
pub use divert::CaptureRetirement;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_tun_host::{AsyncTun, Loss, LossCause, Received};
use std::{
    fmt, io,
    task::{Context, Poll},
};
use tokio::time::Instant;

/// Captured raw IP packet retaining its original transport allocation.
pub(super) struct Packet {
    storage: OwnedFrame,
    layout: Layout,
    route: Route,
}
#[derive(Debug, Default)]
pub(super) enum Route {
    #[default]
    None,
    #[cfg(windows)]
    Captured(gnunet_native::windivert::ReplyAddress),
}
enum Layout {
    Helper,
    Native { prefix: usize },
}
impl Packet {
    /// Borrow normalized raw IP without copying native or helper framing.
    pub fn bytes(&self) -> Result<&[u8], gnunet_types::Error> {
        match self.layout {
            Layout::Helper => core::helper_packet(self.storage.bytes()),
            Layout::Native { prefix } => self
                .storage
                .bytes()
                .get(prefix..)
                .ok_or(gnunet_types::Error::Malformed),
        }
    }
    pub fn into_route(self) -> Route {
        self.route
    }
    #[cfg(windows)]
    fn captured(packet: Vec<u8>, route: gnunet_native::windivert::ReplyAddress) -> Self {
        Self {
            storage: OwnedFrame::new(packet),
            layout: Layout::Native { prefix: 0 },
            route: Route::Captured(route),
        }
    }
    fn helper(frame: OwnedFrame) -> Self {
        Self {
            storage: frame,
            layout: Layout::Helper,
            route: Route::None,
        }
    }
    fn device(packet: Received) -> Self {
        let prefix = packet.native_bytes().len() - packet.bytes().len();
        Self {
            storage: OwnedFrame::new(packet.into_native_bytes()),
            layout: Layout::Native { prefix },
            route: Route::None,
        }
    }
}
impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsPacket")
            .field("bytes", &self.bytes().map(<[u8]>::len))
            .finish()
    }
}
/// Local write facts, without conflating helper pipe acceptance and device I/O.
#[derive(Clone, Copy, Debug)]
pub(super) enum Write {
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
    /// Original asynchronous injection completed with the whole packet length.
    #[cfg(windows)]
    Injection { bytes: usize },
}
impl Write {
    pub(crate) fn exposed(self) -> bool {
        match self {
            Self::Pipe { bytes, .. } | Self::Device { bytes } => bytes != 0,
            #[cfg(windows)]
            Self::Injection { bytes } => bytes != 0,
        }
    }
    pub(crate) fn complete(self) -> bool {
        match self {
            Self::Pipe { complete, .. } => complete,
            Self::Device { .. } => true,
            #[cfg(windows)]
            Self::Injection { .. } => true,
        }
    }
}
/// Original process retirement or native device-close observation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Retirement {
    /// Complete native process exit and independent stop/wait errors.
    Helper(HelperExit),
    /// Native source loss/close; a void provider close is not a removal ACK.
    Device(Loss),
    /// Native filter close and original outstanding capture/injection loans.
    #[cfg(windows)]
    Capture(CaptureRetirement),
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
            Self::Device(loss) => {
                loss.close_error.is_some() || !matches!(loss.cause, LossCause::Closed)
            }
        }
    }
}
/// One source step, preserving the kind of its physical write and retirement.
#[derive(Debug)]
pub(super) enum SourceEvent<'id> {
    /// One original raw IP packet.
    Packet(Packet),
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
    /// One captured route could not be qualified; the filter remains usable.
    #[cfg(windows)]
    Refused(Error),
    /// A complete interface refresh failed; the previous views remain intact.
    #[cfg(windows)]
    RouteObservationFailed(io::Error),
    /// A bounded read, reject or stop transition without packet delivery.
    Activity,
    /// Original transport failed; it must be retired without replay.
    Failed(io::Error),
    /// Actual original process/device retirement.
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
}
pub(super) struct PendingOutput<'id> {
    pub effect: core::Effect<'id>,
    pub exposure: PacketExposure,
    pub total: usize,
}
pub(super) enum OutputStop {
    Requested,
    SourceRequired,
}
pub(super) fn route_refusal(error: &Error) -> bool {
    #[cfg(windows)]
    if let Error::Io(error) = error {
        return error
            .get_ref()
            .is_some_and(|cause| cause.is::<gnunet_native::windivert::RouteUnavailable>());
    }
    let _ = error;
    false
}
enum Backend<'id> {
    Helper(Box<Helper<'id>>),
    Device(Box<Device<'id>>),
    #[cfg(windows)]
    Capture(Box<Capture<'id>>),
}
/// One explicit packet source with a single original outbound operation.
/// The caller retains this owner across canceled waits and drives retirement.
pub struct PacketSource<'id>(Backend<'id>);
impl fmt::Debug for PacketSource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsPacketSource")
            .field("helper", &matches!(self.0, Backend::Helper(_)))
            .finish_non_exhaustive()
    }
}
impl<'id> PacketSource<'id> {
    /// Adopt the original helper, including any post-spawn startup error.
    pub fn helper(helper: Helper<'id>) -> Self {
        Self(Backend::Helper(Box::new(helper)))
    }
    /// Adopt an already configured native TUN. Its original owner controls
    /// device provenance and administrative effects; this port does not rebind it.
    ///
    /// # Panics
    /// Requires an entered Tokio runtime with time enabled for native deadlines.
    pub fn device(device: AsyncTun) -> Self {
        Self(Backend::Device(Box::new(Device::new(device))))
    }
    /// Open an explicit installed WinDivert provider with the original bound
    /// upstream sockets excluded from capture for the lifetime of this source.
    ///
    /// # Panics
    /// Requires an entered Tokio runtime with time enabled.
    #[cfg(windows)]
    pub fn capture(
        driver: &gnunet_native::windivert::Driver,
        reservations: gnunet_dnsstub_host::SocketReservations,
        limits: gnunet_native::windivert::Limits,
    ) -> io::Result<Self> {
        Ok(Self(Backend::Capture(Box::new(Capture::open(
            driver,
            reservations,
            limits,
        )?))))
    }
    pub(crate) fn matches_upstream(&self, stub: &crate::Upstream) -> bool {
        match &self.0 {
            #[cfg(windows)]
            Backend::Capture(capture) => capture.matches(stub),
            _ => {
                let _ = stub;
                true
            }
        }
    }
    pub(crate) fn initialized(&self) -> bool {
        match &self.0 {
            Backend::Helper(helper) => helper.initialized(),
            Backend::Device(device) => device.initialized(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.initialized(),
        }
    }
    pub(crate) fn take_startup_error(&mut self) -> Option<io::Error> {
        match &mut self.0 {
            Backend::Helper(helper) => helper.take_startup_error(),
            Backend::Device(_) => None,
            #[cfg(windows)]
            Backend::Capture(_) => None,
        }
    }
    pub(crate) fn writable(&self) -> bool {
        match &self.0 {
            Backend::Helper(helper) => helper.writable(),
            Backend::Device(device) => device.writable(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.writable(),
        }
    }
    pub(crate) fn prepare(
        &self,
        engine: &mut core::Engine<'id>,
        request: core::Request<'id>,
        scratch: &mut [u8],
    ) -> Result<(core::Effect<'id>, usize), gnunet_types::Error> {
        match self.0 {
            Backend::Helper(_) => engine.prepare_helper(request, scratch),
            Backend::Device(_) => engine.prepare_packet(request, scratch),
            #[cfg(windows)]
            Backend::Capture(_) => engine.prepare_packet(request, scratch),
        }
    }
    pub(crate) fn queue(
        &mut self,
        effect: core::Effect<'id>,
        frame: OwnedFrame,
        until: Instant,
        route: &Route,
    ) -> Result<(), (Error, OwnedFrame)> {
        let _ = route;
        match &mut self.0 {
            Backend::Helper(helper) => helper.queue(effect, frame, until),
            Backend::Device(device) => device.queue(effect, frame, until),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.queue(effect, frame, until, route),
        }
    }
    pub(crate) fn cancel_output(
        &mut self,
        request: core::Request<'id>,
    ) -> Result<OutputStop, Error> {
        match &mut self.0 {
            Backend::Helper(_) => Ok(OutputStop::SourceRequired),
            Backend::Device(device) => {
                device.cancel_output(request)?;
                Ok(OutputStop::Requested)
            }
            #[cfg(windows)]
            Backend::Capture(capture) => {
                capture.cancel_output(request)?;
                Ok(OutputStop::Requested)
            }
        }
    }
    pub(crate) fn pending(&self) -> Option<PendingOutput<'id>> {
        match &self.0 {
            Backend::Helper(helper) => {
                helper
                    .pending()
                    .map(|(effect, written, total)| PendingOutput {
                        effect,
                        exposure: PacketExposure::PipePrefix(written),
                        total,
                    })
            }
            Backend::Device(device) => device.pending().map(|(effect, _, total)| PendingOutput {
                effect,
                exposure: PacketExposure::UnsubmittedPacket,
                total,
            }),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.pending(),
        }
    }
    /// Close admission and request physical retirement of this original source.
    /// Helper stop retains its process; native device close retains its receipt.
    pub fn request_stop(&mut self) {
        match &mut self.0 {
            Backend::Helper(helper) => helper.request_stop(),
            Backend::Device(device) => device.close(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.close(),
        }
    }
    pub(crate) fn take_immediate_retirement(&mut self) -> Option<Retirement> {
        match &mut self.0 {
            Backend::Helper(_) => None,
            #[cfg(windows)]
            Backend::Capture(capture) => capture.take_retirement(),
            Backend::Device(device) => match device.poll_retirement() {
                Poll::Ready(retired) => Some(retired),
                Poll::Pending => None,
            },
        }
    }
    /// Drive only retirement; no new read, write, provider or source is admitted.
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<Retirement> {
        match &mut self.0 {
            Backend::Helper(helper) => helper.poll_exit(cx).map(Retirement::Helper),
            Backend::Device(device) => device.poll_retirement(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.poll_retirement(cx),
        }
    }
    pub(crate) fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        match &mut self.0 {
            Backend::Helper(helper) => helper.poll_native_guard(cx).map(convert),
            Backend::Device(device) => device.poll_guard(cx),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.poll_guard(cx),
        }
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        match &mut self.0 {
            Backend::Helper(helper) => helper.poll(cx).map(convert),
            Backend::Device(device) => device.poll(cx),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.poll(cx),
        }
    }
}
fn convert(event: HelperEvent<'_>) -> SourceEvent<'_> {
    match event {
        HelperEvent::Frame(frame) => SourceEvent::Packet(Packet::helper(frame)),
        HelperEvent::Written {
            effect,
            bytes,
            complete,
        } => SourceEvent::Written {
            effect,
            observation: Write::Pipe { bytes, complete },
        },
        HelperEvent::Read(_) | HelperEvent::Stopping => SourceEvent::Activity,
        HelperEvent::Failed(error) => SourceEvent::Failed(error),
        HelperEvent::Exited(exit) => SourceEvent::Retired(Retirement::Helper(exit)),
    }
}
