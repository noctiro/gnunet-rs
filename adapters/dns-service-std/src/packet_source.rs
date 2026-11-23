//! Packet transport independent of helper process and native device ownership.
mod device;
mod events;
pub(super) use events::{OutputStop, PendingOutput, SourceEvent, Write};
pub use events::{PacketExposure, Retirement};
mod input;
use input::ReplyOwner;
pub(super) use input::{OriginalInput, ReplyPermit};
mod raw;
use raw::Route;
#[cfg(target_os = "linux")]
mod transparent;
#[cfg(target_os = "linux")]
pub use gnunet_native::transparent_dns::TransparentPort;
#[cfg(target_os = "linux")]
pub use transparent::{TransparentFamilies, TransparentInterfaces, TransparentRetirement};
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod flows;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use flows::{FlowLimits, FlowRetirement, RejectedFlow};
#[cfg(windows)]
mod divert;
#[cfg(windows)]
mod wfp;
use crate::{
    Error, core,
    transport::{Helper, HelperEvent},
};
use device::Device;
#[cfg(windows)]
use divert::Capture;
#[cfg(windows)]
pub use divert::CaptureRetirement;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_tun_host::AsyncTun;
use std::{
    fmt, io,
    task::{Context, Poll},
};
use tokio::time::Instant;
#[cfg(windows)]
pub use wfp::{WfpLimits, WfpRetirement};

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
    #[cfg(target_os = "linux")]
    Transparent(Box<transparent::Transparent<'id>>),
    #[cfg(windows)]
    Capture(Box<Capture<'id>>),
    #[cfg(windows)]
    Wfp(Box<wfp::Wfp<'id>>),
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    Flows(Box<flows::Flows<'id>>),
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
    /// Create bounded, explicitly adopted application flows. The provider host
    /// owns admission and upstream exclusion; no system DNS policy is installed.
    ///
    /// # Errors
    /// Refuses invalid bounds or allocation failure.
    ///
    /// # Panics
    /// Requires an entered Tokio runtime with time enabled.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn application_flows(limits: FlowLimits) -> Result<Self, gnunet_types::Error> {
        Ok(Self(Backend::Flows(Box::new(flows::Flows::new(limits)?))))
    }
    /// Adopt an original provider flow on its owning thread. Refusal preserves
    /// the original owner for explicit close and callback retirement.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the original native flow without requiring a fallible error allocation"
    )]
    pub fn admit_flow(
        &mut self,
        flow: gnunet_native::dns_proxy::UdpFlow,
    ) -> Result<(), RejectedFlow> {
        match &mut self.0 {
            Backend::Flows(flows) => flows.insert(flow),
            _ => Err(RejectedFlow {
                error: io::ErrorKind::Unsupported.into(),
                flow,
            }),
        }
    }
    pub(crate) fn defers_settlement(&self) -> bool {
        #[cfg(windows)]
        if matches!(&self.0, Backend::Wfp(_)) {
            return true;
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if matches!(&self.0, Backend::Flows(_)) {
            return true;
        }
        false
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
    /// Start the installed Windows WFP driver with the exact original bound
    /// DNSSTUB UDP sockets. Capture starts only after native START succeeds.
    ///
    /// # Errors
    /// Returns a startup timeout, original device or socket admission error.
    ///
    /// # Panics
    /// Requires an entered Tokio runtime with time enabled.
    #[cfg(windows)]
    pub async fn wfp(
        reservations: gnunet_dnsstub_host::SocketReservations,
        limits: WfpLimits,
    ) -> io::Result<Self> {
        Ok(Self(Backend::Wfp(Box::new(
            wfp::Wfp::open(reservations, limits).await?,
        ))))
    }
    /// Open transparent UDP DNS on explicit Linux ingress interfaces.
    /// The deployment supplies PREROUTING interception and mark exclusion.
    /// Every selected ingress family must bind the distinct capture port
    /// before capture starts.
    ///
    /// # Errors
    /// Returns native listener, ingress or bypass-mark preparation errors.
    ///
    /// # Panics
    /// Requires an entered Tokio runtime with I/O and time enabled.
    #[cfg(target_os = "linux")]
    pub async fn transparent(
        reservations: gnunet_dnsstub_host::SocketReservations,
        families: TransparentFamilies,
        port: TransparentPort,
        bypass_mark: std::num::NonZeroU32,
        interfaces: TransparentInterfaces,
    ) -> io::Result<Self> {
        Ok(Self(Backend::Transparent(Box::new(
            transparent::Transparent::open(reservations, families, port, bypass_mark, interfaces)
                .await?,
        ))))
    }
    pub(crate) fn matches_upstream(&self, stub: &crate::Upstream) -> bool {
        match &self.0 {
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.matches(stub),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.matches(stub),
            #[cfg(windows)]
            Backend::Wfp(source) => source.matches(stub),
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
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.initialized(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.initialized(),
            #[cfg(windows)]
            Backend::Wfp(source) => source.initialized(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => flows.initialized(),
        }
    }
    pub(crate) fn take_startup_error(&mut self) -> Option<io::Error> {
        match &mut self.0 {
            Backend::Helper(helper) => helper.take_startup_error(),
            Backend::Device(_) => None,
            #[cfg(target_os = "linux")]
            Backend::Transparent(_) => None,
            #[cfg(windows)]
            Backend::Capture(_) => None,
            #[cfg(windows)]
            Backend::Wfp(source) => source.take_startup_error(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(_) => None,
        }
    }
    pub(crate) fn writable(&self) -> bool {
        match &self.0 {
            Backend::Helper(helper) => helper.writable(),
            Backend::Device(device) => device.writable(),
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.writable(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.writable(),
            #[cfg(windows)]
            Backend::Wfp(source) => source.writable(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => flows.writable(),
        }
    }
    pub(crate) fn prepare(
        &self,
        engine: &mut core::Engine<'id>,
        request: core::Request<'id>,
        permit: &ReplyPermit<'id>,
    ) -> Result<(core::Effect<'id>, OwnedFrame), gnunet_types::Error> {
        match (&self.0, &permit.owner) {
            (Backend::Helper(helper), ReplyOwner::Raw(reply))
                if matches!(reply.route, Route::None) =>
            {
                permit.prepare_with(engine, request, |dns| {
                    reply.helper(dns, helper.frame_capacity())
                })
            }
            (Backend::Device(device), ReplyOwner::Raw(reply))
                if matches!(reply.route, Route::None) =>
            {
                permit.prepare_with(engine, request, |dns| {
                    reply.packet(dns, device.packet_capacity())
                })
            }
            #[cfg(target_os = "linux")]
            (Backend::Transparent(source), ReplyOwner::Transparent(endpoint))
                if source.accepts(endpoint) =>
            {
                if !source.writable() {
                    return Err(gnunet_types::Error::WouldBlock);
                }
                permit.prepare_with(engine, request, OwnedFrame::copy_from)
            }
            #[cfg(windows)]
            (Backend::Capture(_), ReplyOwner::Raw(reply))
                if matches!(reply.route, Route::Captured(_)) =>
            {
                permit.prepare_with(engine, request, |dns| {
                    reply.packet(dns, usize::from(u16::MAX) + 40)
                })
            }
            #[cfg(windows)]
            (Backend::Wfp(source), ReplyOwner::Wfp(endpoint)) if source.accepts(endpoint) => {
                if !source.writable() {
                    return Err(gnunet_types::Error::WouldBlock);
                }
                permit.prepare_with(engine, request, OwnedFrame::copy_from)
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            (Backend::Flows(flows), ReplyOwner::Flow(endpoint)) if flows.accepts(endpoint) => {
                if !flows.write_available(endpoint) {
                    return Err(gnunet_types::Error::WouldBlock);
                }
                permit.prepare_with(engine, request, OwnedFrame::copy_from)
            }
            _ => Err(gnunet_types::Error::StaleGeneration),
        }
    }
    fn accepts(&self, owner: &ReplyOwner) -> bool {
        match &self.0 {
            Backend::Helper(_) | Backend::Device(_) => {
                matches!(owner, ReplyOwner::Raw(reply) if matches!(reply.route, Route::None))
            }
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => {
                matches!(owner, ReplyOwner::Transparent(endpoint) if source.accepts(endpoint))
            }
            #[cfg(windows)]
            Backend::Capture(_) => {
                matches!(owner, ReplyOwner::Raw(reply) if matches!(reply.route, Route::Captured(_)))
            }
            #[cfg(windows)]
            Backend::Wfp(source) => {
                matches!(owner, ReplyOwner::Wfp(endpoint) if source.accepts(endpoint))
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => {
                matches!(owner, ReplyOwner::Flow(endpoint) if flows.accepts(endpoint))
            }
        }
    }
    #[cfg_attr(
        target_pointer_width = "64",
        expect(
            clippy::result_large_err,
            reason = "Pre-admission failure returns the frame and unique reply permit without another allocation"
        )
    )]
    pub(crate) fn queue(
        &mut self,
        effect: core::Effect<'id>,
        frame: OwnedFrame,
        until: Instant,
        permit: ReplyPermit<'id>,
    ) -> Result<(), (Error, OwnedFrame, ReplyPermit<'id>)> {
        if let Err(error) = permit.check(effect) {
            return Err((error.into(), frame, permit));
        }
        if !self.accepts(&permit.owner) {
            return Err((gnunet_types::Error::StaleGeneration.into(), frame, permit));
        }
        match &mut self.0 {
            Backend::Helper(helper) => helper
                .queue(effect, frame, until)
                .map_err(|(e, f)| (e, f, permit)),
            Backend::Device(device) => device
                .queue(effect, frame, until)
                .map_err(|(e, f)| (e, f, permit)),
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.queue(effect, frame, until, permit),
            #[cfg(windows)]
            Backend::Capture(capture) => {
                let ReplyOwner::Raw(reply) = &permit.owner else {
                    return Err((gnunet_types::Error::StaleGeneration.into(), frame, permit));
                };
                capture
                    .queue(effect, frame, until, &reply.route)
                    .map_err(|(e, f)| (e, f, permit))
            }
            #[cfg(windows)]
            Backend::Wfp(source) => source.queue(effect, frame, until, permit),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => flows.queue(effect, frame, until, permit),
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
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => {
                source.cancel_output(request)?;
                Ok(OutputStop::Requested)
            }
            #[cfg(windows)]
            Backend::Capture(capture) => {
                capture.cancel_output(request)?;
                Ok(OutputStop::Requested)
            }
            #[cfg(windows)]
            Backend::Wfp(source) => {
                source.cancel_output(request)?;
                Ok(OutputStop::Requested)
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => {
                flows.cancel_output(request)?;
                Ok(OutputStop::Requested)
            }
        }
    }
    pub(crate) fn pending_capacity(&self) -> usize {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let Backend::Flows(flows) = &self.0 {
            return flows.pending_capacity();
        }
        1
    }
    pub(crate) fn pending_at(&self, index: usize) -> Option<PendingOutput<'id>> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let Backend::Flows(flows) = &self.0 {
            return flows.pending_at(index);
        }
        if index != 0 {
            return None;
        }
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
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.pending(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.pending(),
            #[cfg(windows)]
            Backend::Wfp(source) => source.pending(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(_) => None,
        }
    }
    /// Close admission and request physical retirement of this original source.
    /// Helper stop retains its process; native device close retains its receipt.
    pub fn request_stop(&mut self) {
        match &mut self.0 {
            Backend::Helper(helper) => helper.request_stop(),
            Backend::Device(device) => device.close(),
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.close(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.close(),
            #[cfg(windows)]
            Backend::Wfp(source) => source.close(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => flows.close(),
        }
    }
    pub(crate) fn take_immediate_retirement(&mut self) -> Option<Retirement> {
        match &mut self.0 {
            Backend::Helper(_) => None,
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.take_retirement(),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.take_retirement(),
            #[cfg(windows)]
            Backend::Wfp(source) => source.take_retirement(),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(_) => None,
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
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.poll_retirement(cx),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.poll_retirement(cx),
            #[cfg(windows)]
            Backend::Wfp(source) => source.poll_retirement(cx),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => flows.poll_retirement(cx),
        }
    }
    pub(crate) fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        match &mut self.0 {
            Backend::Helper(helper) => helper.poll_native_guard(cx).map(convert),
            Backend::Device(device) => device.poll_guard(cx),
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.poll_guard(cx),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.poll_guard(cx),
            #[cfg(windows)]
            Backend::Wfp(source) => source.poll_guard(cx),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => flows.poll_guard(cx),
        }
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>, admit: bool) -> Poll<SourceEvent<'id>> {
        let _ = admit;
        match &mut self.0 {
            Backend::Helper(helper) => helper.poll(cx).map(convert),
            Backend::Device(device) => device.poll(cx),
            #[cfg(target_os = "linux")]
            Backend::Transparent(source) => source.poll(cx, admit),
            #[cfg(windows)]
            Backend::Capture(capture) => capture.poll(cx),
            #[cfg(windows)]
            Backend::Wfp(source) => source.poll(cx, admit),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Backend::Flows(flows) => flows.poll(cx, admit),
        }
    }
}
fn convert(event: HelperEvent<'_>) -> SourceEvent<'_> {
    match event {
        HelperEvent::Frame(frame) => SourceEvent::Input(raw::helper(frame)),
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
