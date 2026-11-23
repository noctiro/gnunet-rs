//! Caller-driven composition of the actual local SERVICE, one CADET MQ and one
//! verified TUN. All packet storage belongs to the caller's pure engine pools.
//! Native writes, control receipts and processing credit remain distinct facts.
use crate::server;
use gnunet_cadet_host as cadet;
use gnunet_service_runtime::{
    clock::RuntimeClock,
    service::{Listener, ShutdownMode},
};
use gnunet_tun_host as tun;
use gnunet_types::Error as Fault;
use gnunet_vpn::{self as core, PeerProfiles};
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod types;
pub use types::*;
mod device;
use device::Provenance;
pub use device::{Device, PacketIo};
/// Bounded application VPN mailbox and controller.
pub mod application;
mod control;
mod packets;
mod peer;
/// Application packet and routing provider boundary.
pub mod provider;
#[cfg(any(windows, target_os = "freebsd"))]
mod recovery;
#[cfg(windows)]
pub use recovery::{WintunPhysicalFailure, WintunRecoveryFailure};

struct Input<'cadet, 'id> {
    frame: cadet::Received<'cadet>,
    offset: usize,
    processing: Option<(core::Delivery<'id>, usize)>,
    until: Instant,
}
#[derive(Clone, Copy)]
struct Discovery<'id> {
    request: core::DiscoveryRequest<'id>,
    queued: bool,
}
#[derive(Clone, Copy)]
struct PeerRoute {
    identity: [u8; 32],
    af: core::AfProfile,
}
impl PeerRoute {
    fn for_open(
        selected: Option<Self>,
        identity: [u8; 32],
        profiles: &PeerProfiles,
    ) -> Result<Self, Fault> {
        match selected {
            Some(route) if route.identity == identity => Ok(route),
            Some(_) => Err(Fault::Authentication),
            None => Ok(Self {
                identity,
                af: profiles.profile(&identity),
            }),
        }
    }
}

#[cfg(test)]
mod peer_route_tests {
    use super::*;

    #[test]
    fn known_peer_and_fixed_exit_keep_their_own_profile() -> Result<(), Fault> {
        let identity = [1; 32];
        let profiles = PeerProfiles::new(
            core::AfProfile::LINUX,
            [(identity, core::AfProfile::DARWIN)],
        )?;
        let named = PeerRoute::for_open(None, identity, &profiles)?;
        let fallback = PeerRoute::for_open(None, [2; 32], &profiles)?;
        let fixed = PeerRoute {
            identity,
            af: core::AfProfile::FREEBSD,
        };
        let selected = PeerRoute::for_open(Some(fixed), identity, &profiles)?;
        if named.af != core::AfProfile::DARWIN
            || fallback.af != core::AfProfile::LINUX
            || selected.af != core::AfProfile::FREEBSD
            || !matches!(
                PeerRoute::for_open(Some(fixed), [2; 32], &profiles),
                Err(Fault::Authentication)
            )
        {
            return Err(Fault::Conflict);
        }
        Ok(())
    }
}
struct Link<'id, 'cadet> {
    flow: core::Flow<'id>,
    selected_route: Option<PeerRoute>,
    attachment: Option<Attachment<'id, 'cadet>>,
    input: Option<Input<'cadet, 'id>>,
    discovery: Option<Discovery<'id>>,
}
impl<'id, 'cadet> Link<'id, 'cadet> {
    fn peer(&self) -> Option<core::Peer<'id>> {
        match self.attachment.as_ref()?.state {
            AttachmentState::Bound(peer) => Some(peer),
            AttachmentState::Opening { .. } => None,
        }
    }

    fn remote_closed(&self) -> bool {
        self.attachment.as_ref().is_some_and(|a| a.remote_closed)
    }
}
struct Attachment<'id, 'cadet> {
    channel: cadet::Channel<'cadet>,
    state: AttachmentState<'id>,
    remote_closed: bool,
}
enum AttachmentState<'id> {
    Opening {
        open: core::Open<'id>,
        route: PeerRoute,
        progress: OpeningProgress,
    },
    Bound(core::Peer<'id>),
}
enum OpeningProgress {
    WritingCreate { until: Instant },
    WaitingForCredit { until: Instant },
    Expired,
}
impl AttachmentState<'_> {
    fn open_deadline(&self) -> Option<Instant> {
        match self {
            Self::Opening {
                progress:
                    OpeningProgress::WritingCreate { until }
                    | OpeningProgress::WaitingForCredit { until },
                ..
            } => Some(*until),
            _ => None,
        }
    }
}
#[derive(Clone, Copy)]
enum Action<'id> {
    Open(usize),
    Data {
        link: usize,
        effect: core::Effect<'id>,
        retired: bool,
    },
    Ack(usize),
    Destroy(usize),
    Auxiliary,
}
impl Action<'_> {
    fn link(self) -> Option<usize> {
        match self {
            Self::Open(i) | Self::Ack(i) | Self::Destroy(i) | Self::Data { link: i, .. } => Some(i),
            Self::Auxiliary => None,
        }
    }
}
struct Pending<'id, 'cadet> {
    transmit: cadet::Transmit<'cadet>,
    action: Action<'id>,
    until: Instant,
}
enum PacketWrite {
    Native(tun::WriteId),
    Provider {
        request: provider::PacketRequest,
        bytes: usize,
    },
}
impl PacketWrite {
    fn native(&self) -> Option<&tun::WriteId> {
        match self {
            Self::Native(id) => Some(id),
            Self::Provider { .. } => None,
        }
    }
}
struct TunOutput<'id> {
    write: PacketWrite,
    effect: core::Effect<'id>,
}
enum IncomingPacket {
    Native(tun::Received),
    Provider(Vec<u8>),
}
impl IncomingPacket {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Native(packet) => packet.bytes(),
            Self::Provider(packet) => packet,
        }
    }
}
struct TunInput {
    packet: IncomingPacket,
    until: Instant,
}
/// Actual bounded VPN runtime. It creates no hidden worker, task or discovery
/// connection. The caller owns the runtime and repeatedly drives this owner.
pub struct Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy> {
    server: server::Server<'id, 'store, 'bytes>,
    cadet: cadet::Client<'cadet, 'cstore>,
    device: Device,
    policies: &'policy [ConfiguredExit],
    profiles: &'policy PeerProfiles,
    limits: Limits,
    links: Vec<Option<Link<'id, 'cadet>>>,
    cursor: usize,
    receive_cursor: usize,
    native: Option<Pending<'id, 'cadet>>,
    output: Option<TunOutput<'id>>,
    input: Option<TunInput>,
    source: Option<core::Tun<'id>>,
    control: control::Control<'id>,
    ipc_stopped: bool,
    stopping: Option<Instant>,
    closed: Option<Close<'cadet>>,
    timer: Option<Pin<Box<Sleep>>>,
    timer_at: Option<Instant>,
    report: Report,
    #[cfg(any(windows, target_os = "freebsd"))]
    recovery: recovery::Recovery,
}
impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    /// Validate and allocate only bounded native metadata. All original physical
    /// owners are returned on refusal. No configuration is changed here.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns every original physical owner for explicit independent cleanup"
    )]
    pub fn new(
        parts: Parts<'id, 'store, 'bytes, 'cadet, 'cstore>,
        policies: &'policy [ConfiguredExit],
        profiles: &'policy PeerProfiles,
        limits: Limits,
    ) -> Result<Self, BuildFailure<Parts<'id, 'store, 'bytes, 'cadet, 'cstore>>> {
        let validate = || -> Result<(), Error> {
            if limits.flows == 0
                || !(68..=65535).contains(&limits.mtu)
                || !parts.device.io.current()
                || parts.cadet.pending_transmit().is_some()
                || parts.server.engine().has_tun_source()
                || parts.server.engine().flows().next().is_some()
                || parts.server.engine().buffers().next().is_some()
                || !Arc::ptr_eq(&parts.server.clock(), &parts.cadet.clock())
            {
                return Err(Fault::InvalidInput.into());
            }
            for d in [
                limits.control_timeout,
                limits.input_timeout,
                limits.tun_send_timeout,
                limits.cadet_send_timeout,
                limits.shutdown_grace,
                limits.monitor_timeout,
            ] {
                if d.is_zero() || Instant::now().checked_add(d).is_none() {
                    return Err(Fault::InvalidInput.into());
                }
            }
            for p in policies {
                p.af.validate()?;
                if let Some(n) = p.network {
                    n.validate()?;
                }
                if p.ports.0 > p.ports.1 {
                    return Err(Fault::InvalidInput.into());
                }
            }
            Ok(())
        };
        if let Err(error) = validate() {
            return Err(BuildFailure { error, parts });
        }
        let mut links = Vec::new();
        if links.try_reserve_exact(limits.flows).is_err() {
            return Err(BuildFailure {
                error: Fault::Capacity.into(),
                parts,
            });
        }
        links.resize_with(limits.flows, || None);
        Ok(Self {
            server: parts.server,
            cadet: parts.cadet,
            device: parts.device,
            policies,
            profiles,
            limits,
            links,
            cursor: 0,
            receive_cursor: 0,
            native: None,
            output: None,
            input: None,
            source: None,
            control: control::Control::new(),
            ipc_stopped: false,
            stopping: None,
            closed: None,
            timer: None,
            timer_at: None,
            report: Report::default(),
            #[cfg(any(windows, target_os = "freebsd"))]
            recovery: recovery::Recovery::default(),
        })
    }
    /// The original packet source is live and actual native configuration,
    /// route and DAD observations/receipts were accepted. Helper observations
    /// do not prove child ownership of the interface; allocation alone is false.
    pub fn tun_ready(&self) -> Result<bool, Fault> {
        self.source
            .map_or(Ok(false), |source| self.server.engine().tun_ready(source))
    }

    pub(crate) fn startup_ready(&self) -> Result<bool, Fault> {
        Ok(!self.retiring() && self.cadet.epoch().is_some() && self.tun_ready()?)
    }

    pub(crate) const fn retiring(&self) -> bool {
        self.stopping.is_some() || self.closed.is_some()
    }
    /// Consume the first independent cleanup failure, retaining the permanent
    /// closed state and all original physical reports. Repeated calls cannot
    /// reopen the owner or close a reused descriptor. Local IPC cleanup remains
    /// a distinct original error rather than being silently lost.
    pub fn take_cleanup_failure(&mut self) -> Option<Error> {
        self.closed.as_mut().and_then(|closed| {
            closed
                .failure
                .take()
                .or_else(|| closed.ipc.failure.take().map(Error::Ipc))
        })
    }
    /// Transfer all independently retained original cleanup error objects once.
    /// The closed report, permanent closed latch, epochs, actual source outcomes,
    /// unconfirmed-control count and route/flow/buffer/debt metadata stay intact.
    /// No clock sample or descriptor operation occurs here. Repeated calls are
    /// empty and can never reopen or re-close an original/reused descriptor.
    #[must_use]
    pub fn take_cleanup_errors(&mut self) -> CleanupErrors {
        self.closed
            .as_mut()
            .map_or_else(CleanupErrors::default, |closed| CleanupErrors {
                failure: closed.failure.take(),
                ipc: closed.ipc.failure.take(),
                prior_tun: closed.prior_tun_close_error.take(),
                control: closed.control_close_error.take(),
                tun: closed.tun.as_mut().and_then(|loss| loss.close_error.take()),
                provider: closed
                    .provider
                    .as_mut()
                    .and_then(|closed| closed.error.take()),
            })
    }
    /// Original canonical clock, shared with both actual MQ owners.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.server.clock()
    }
    /// Inspect pure facts without granting a replacement source capability.
    #[must_use]
    pub fn engine(&self) -> &core::Engine<'id, 'store, 'bytes> {
        self.server.engine()
    }
    /// Actual cumulative local observations only.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Current remaining original resource/job debt, including after close.
    #[must_use]
    pub fn debt(&self) -> Debt {
        Debt {
            unconfirmed_control_closes: self.control.unconfirmed_control_closes,
            routes: self
                .source
                .and_then(|s| self.server.engine().route_state(s).ok())
                .unwrap_or(core::RouteState::Absent),
            flows: self.server.engine().flows().count(),
            buffers: self.server.engine().buffers().count(),
            discoveries: self
                .links
                .iter()
                .flatten()
                .filter(|l| l.discovery.is_some_and(|d| d.queued))
                .count(),
        }
    }
    /// Original packet-source scope; it confers neither helper interface ownership
    /// nor administrative routing authority.
    #[must_use]
    pub fn device_epoch(&self) -> Option<tun::Epoch> {
        self.device.epoch()
    }
    /// Inspect a completed hard-stop report. Unknown routes and external jobs are
    /// retained; local source close does not prove downstream processing.
    #[must_use]
    pub const fn close_report(&self) -> Option<&Close<'cadet>> {
        self.closed.as_ref()
    }
    /// Actual current packet source metadata, without claiming helper ownership.
    #[must_use]
    pub fn device_info(&self) -> Option<&tun::Info> {
        self.device.info()
    }
    /// Whether the actual packet owner is the original helper child/pipes.
    #[must_use]
    pub fn uses_helper(&self) -> bool {
        self.device.io.is_helper()
    }
    /// Mandatory original helper wait after physical packet/MQ shutdown.
    #[cfg(unix)]
    pub async fn reap_helper(&mut self) -> Option<tun::helper::Report> {
        self.device.io.reap_helper().await
    }
    /// Original helper stream/write hard checks before any canonical clock wait.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        match self.device.io.poll_native_guard(cx) {
            Some(tun::ReadEvent::Lost(loss)) => {
                self.tun_lost(loss, observe)?;
                Ok(true)
            }
            Some(tun::ReadEvent::WriteExpired(write)) => {
                let p = self.output.take().ok_or(Fault::StaleGeneration)?;
                if p.write.native() != Some(&write) {
                    self.output = Some(p);
                    return Err(Fault::StaleGeneration.into());
                }
                self.server.engine_mut().unsent(p.effect, Fault::Deadline)?;
                Ok(true)
            }
            None => Ok(false),
            _ => Err(Fault::Conflict.into()),
        }
    }
    fn deadline(d: Duration) -> Result<Instant, Error> {
        Instant::now()
            .checked_add(d)
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn again(cx: &Context<'_>) {
        cx.waker().wake_by_ref();
    }
    fn find(&self, channel: cadet::Channel<'cadet>) -> Option<usize> {
        self.links.iter().position(|l| {
            l.as_ref()
                .and_then(|l| l.attachment.as_ref())
                .is_some_and(|a| a.channel == channel)
        })
    }
    fn flow_index(&self, flow: core::Flow<'id>) -> Option<usize> {
        self.links
            .iter()
            .position(|l| l.as_ref().is_some_and(|l| l.flow == flow))
    }
    fn insert(&mut self, flow: core::Flow<'id>) -> Result<usize, Error> {
        if let Some(i) = self.flow_index(flow) {
            return Ok(i);
        }
        let i = self
            .links
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        self.links[i] = Some(Link {
            flow,
            selected_route: None,
            attachment: None,
            input: None,
            discovery: None,
        });
        Ok(i)
    }
    fn fail_flow(&mut self, i: usize, reason: Fault) -> Result<(), Error> {
        let flow = self
            .links
            .get(i)
            .and_then(Option::as_ref)
            .ok_or(Fault::StaleGeneration)?
            .flow;
        self.server.engine_mut().close_flow(flow, reason)?;
        self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = None;
        Ok(())
    }
    /// Original external discovery actually admitted. Merely observing Discovery
    /// does not admit a job; the original token must be retained through retirement.
    pub fn discovery_queued(&mut self, d: core::Discovery<'id>) -> Result<(), Error> {
        let i = self.discovery_index(d)?;
        if self.stopping.is_some() || self.closed.is_some() {
            return Err(Fault::Closed.into());
        }
        self.server.engine_mut().discovery_queued(d)?;
        self.links[i]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .discovery
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .queued = true;
        Ok(())
    }
    fn discovery_index(&self, d: core::Discovery<'id>) -> Result<usize, Error> {
        self.links
            .iter()
            .position(|l| {
                l.as_ref()
                    .and_then(|l| l.discovery)
                    .is_some_and(|x| x.request.discovery == d)
            })
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    /// Apply one result from the original Internet gateway discovery.
    /// Fix the candidate's transmit profile before CADET binds the selected peer.
    /// The caller still owns the discovery job and its result frame.
    pub fn select_exit(
        &mut self,
        d: core::Discovery<'id>,
        peer: [u8; 32],
    ) -> Result<core::AfProfile, Error> {
        let i = self.discovery_index(d)?;
        if self.stopping.is_some() || self.closed.is_some() {
            return Err(Fault::Closed.into());
        }
        let discovery = self.links[i]
            .as_ref()
            .and_then(|link| link.discovery)
            .ok_or(Fault::StaleGeneration)?;
        if !discovery.queued
            || self.server.engine().flow_info(d.flow())?.phase != core::Phase::Discovering
        {
            return Err(Fault::StaleGeneration.into());
        }
        let af = self.profiles.gateway_profile(&peer);
        self.server.engine_mut().select_exit(d, peer)?;
        self.links[i]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .selected_route = Some(PeerRoute { identity: peer, af });
        Ok(af)
    }
    /// Record a genuine original discovery failure without claiming retirement.
    pub fn discovery_failed(
        &mut self,
        d: core::Discovery<'id>,
        reason: Fault,
    ) -> Result<(), Error> {
        self.discovery_index(d)?;
        self.server.engine_mut().discovery_failed(d, reason)?;
        Ok(())
    }
    /// Actual original external provider job settled, even after local shutdown.
    pub fn retire_discovery(&mut self, d: core::Discovery<'id>) -> Result<(), Error> {
        let i = self.discovery_index(d)?;
        self.server.engine_mut().retire_discovery(d)?;
        self.links[i]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .discovery = None;
        if self.closed.is_some() {
            let budget = self
                .server
                .engine()
                .buffers()
                .count()
                .saturating_add(self.links.len())
                .saturating_add(1);
            for _ in 0..budget {
                if !self.release_finished()? {
                    break;
                }
            }
        }
        Ok(())
    }
    /// Stop new input and admission under one original finite shutdown grace.
    /// Existing immutable physical attempts retain their original owners.
    pub fn request_shutdown(&mut self) {
        #[cfg(any(windows, target_os = "freebsd"))]
        {
            self.recovery.hard = None;
        }
        #[cfg(target_os = "freebsd")]
        {
            self.recovery.retry_at = None;
        }
        if self.stopping.is_none() && self.closed.is_none() {
            self.stopping = Some(
                Instant::now()
                    .checked_add(self.limits.shutdown_grace)
                    .unwrap_or_else(Instant::now),
            );
            self.server.request_shutdown(ShutdownMode::Soft);
        }
    }
    fn release_finished(&mut self) -> Result<bool, Error> {
        // At most one row per pass. Never recycle a buffer held by a real native
        // attempt, even after its logical peer was destroyed on the same MQ.
        let keep_peer = self.native.as_ref().and_then(|p| match p.action {
            Action::Data { effect, .. } => effect.buffer(),
            _ => None,
        });
        let keep_tun = self.output.as_ref().and_then(|p| p.effect.buffer());
        let candidate = self.server.engine().buffers().find(|b| {
            Some(*b) != keep_peer
                && Some(*b) != keep_tun
                && self.server.engine().buffer_outcome(*b).is_ok_and(|o| {
                    matches!(
                        o,
                        core::Outcome::Written
                            | core::Outcome::Unsent
                            | core::Outcome::Canceled
                            | core::Outcome::Lost { .. }
                    )
                })
        });
        if let Some(b) = candidate {
            match self.server.engine_mut().release_buffer(b) {
                Ok(()) => return Ok(true),
                Err(Fault::WouldBlock) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for i in 0..self.links.len() {
            if self
                .native
                .as_ref()
                .is_some_and(|p| p.action.link() == Some(i))
            {
                continue;
            }
            let Some(l) = self.links[i].as_ref() else {
                continue;
            };
            if l.attachment.is_none()
                && l.input.is_none()
                && l.discovery.is_none()
                && self.server.engine().flow_info(l.flow)?.phase == core::Phase::Closing
            {
                match self.server.engine_mut().retire_flow(l.flow) {
                    Ok(()) => {
                        self.links[i] = None;
                        return Ok(true);
                    }
                    Err(Fault::WouldBlock) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(false)
    }
    fn arm(&mut self, cx: &mut Context<'_>, at: Option<Instant>) -> bool {
        if self.timer_at != at {
            self.timer = at.map(|t| Box::pin(tokio::time::sleep_until(t)));
            self.timer_at = at;
        }
        self.timer
            .as_mut()
            .is_some_and(|s| s.as_mut().poll(cx).is_ready())
    }
    fn next_deadline(&self, caller: Option<Instant>) -> Option<Instant> {
        let mut at = caller;
        let mut put = |t: Instant| {
            at = Some(at.map_or(t, |a| a.min(t)));
        };
        if let Some(t) = self.stopping {
            put(t);
        }
        if let Some(p) = self.native.as_ref() {
            put(p.until);
        }
        if let Some(p) = self.output.as_ref()
            && let PacketWrite::Provider { request, .. } = &p.write
        {
            put(request.deadline);
        }
        if let Some(p) = self.input.as_ref() {
            put(p.until);
        }
        for l in self.links.iter().flatten() {
            if let Some(p) = l.input.as_ref() {
                put(p.until);
            }
            if let Some(t) = l.attachment.as_ref().and_then(|a| a.state.open_deadline()) {
                put(t);
            }
        }
        if let Some(t) = self.control_deadline() {
            put(t);
        }
        #[cfg(any(windows, target_os = "freebsd"))]
        if let Some(hard) = self.recovery.hard {
            put(hard);
        }
        #[cfg(target_os = "freebsd")]
        if let Some(retry) = self.recovery.retry_at {
            put(retry);
        }
        at
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Poll<Result<Progress, Error>> {
        if self.closed.is_some() {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        #[cfg(any(windows, target_os = "freebsd"))]
        if let Some(deadline) = self.recovery.hard
            && Instant::now() >= deadline
        {
            #[cfg(target_os = "freebsd")]
            observe(Event::FreeBsdRecoveryExpired { deadline });
            self.request_shutdown();
        }
        if self.stopping.is_some_and(|t| Instant::now() >= t) {
            self.close(observe);
            return Poll::Ready(Ok(Progress::Stopped));
        }
        let mut activity = self.poll_native_guard(cx, observe)?;
        let application = self.device.provenance == Provenance::Provider;
        if application {
            // A reported provider revocation fences new local leases before
            // the IPC owner can observe or commit another request.
            activity |= self.poll_control(cx, observe)?;
        }
        // Each class is polled once, regardless of activity on another class.
        if !self.ipc_stopped {
            match self
                .server
                .poll(cx, listeners, None, &mut |e| observe(Event::Ipc(e)))
            {
                Poll::Ready(Ok(server::Progress::Stopped)) => {
                    self.ipc_stopped = true;
                    activity = true
                }
                Poll::Ready(Ok(server::Progress::Activity)) => activity = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                _ => {}
            }
        }
        match if application {
            Ok(false)
        } else {
            self.poll_control(cx, observe)
        } {
            Ok(progress) => activity |= progress,
            Err(error) => {
                #[cfg(any(windows, target_os = "freebsd"))]
                if matches!(&error, Error::Admin(_) | Error::Native(_)) {
                    match self.retire_missing_interface(observe) {
                        Ok(true) => {
                            observe(Event::RecoveryError(error));
                            activity = true;
                        }
                        Ok(false) => return Poll::Ready(Err(error)),
                        Err(probe) => {
                            observe(Event::RecoveryError(probe));
                            return Poll::Ready(Err(error));
                        }
                    }
                } else {
                    return Poll::Ready(Err(error));
                }
                #[cfg(all(unix, not(target_os = "freebsd")))]
                return Poll::Ready(Err(error));
            }
        }
        #[cfg(any(windows, target_os = "freebsd"))]
        self.observe_recovery()?;
        activity |= self.poll_backend(cx, observe)?;
        activity |= self.poll_tun_output(cx, observe)?;
        if self.stopping.is_none() {
            activity |= self.poll_tun_input(cx, observe)?;
        }
        activity |= self.advance_input(observe)?;
        activity |= self.work(observe)?;
        activity |= self.release_finished()?;
        #[cfg(target_os = "freebsd")]
        {
            activity |= self.poll_freebsd_recovery(cx, observe)?;
        }
        if self.stopping.is_some()
            && self.control_released()
            && self.server.ipc_quiescent()
            && self.native.is_none()
            && self.output.is_none()
            && self
                .links
                .iter()
                .flatten()
                .all(|l| l.attachment.is_none() && l.input.is_none() && l.discovery.is_none())
        {
            self.close(observe);
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if activity {
            Self::again(cx);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if wait.is_some_and(|t| Instant::now() >= t) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        let at = self.next_deadline(wait);
        if self.arm(cx, at) {
            Self::again(cx);
        }
        Poll::Pending
    }
    /// Drive all classes fairly. Canceling this wait preserves native cursors,
    /// original immutable frames, processing permissions and absolute deadlines.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Poll<Result<Progress, Error>> {
        match self.poll_inner(cx, listeners, wait, observe) {
            Poll::Ready(Err(e)) => {
                self.close(observe);
                Poll::Ready(Err(e))
            }
            x => x,
        }
    }
    /// Await one fair progress result on the caller's existing runtime.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id, 'cadet>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
}
