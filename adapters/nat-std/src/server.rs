//! Actual official NAT/NAT-auto/test SERVICE framing and original-source IO.
//! There is no invented ACK/RID/CANCEL; only real notifications/config results.
use crate::{
    deadline::Bounds,
    manager::{Failure, Manager},
    settings::Settings,
};
use gnunet_client_host::resolution::SharedResolution;
use gnunet_config::Configuration;
use gnunet_nat::state::{self, EventKind, Source};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    nat::{self, Endian, Profile},
    nat_auto,
};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Actual producing ABI, selected from the built target and never guessed from
/// incoming socket bytes. Other ABIs require an explicit validated implementation.
pub fn native_profile() -> Result<Profile, Fault> {
    let endian = if cfg!(target_endian = "little") {
        Endian::Little
    } else {
        Endian::Big
    };
    if cfg!(target_os = "linux") {
        Ok(Profile::linux(endian))
    } else if cfg!(target_os = "macos") {
        Ok(Profile::darwin(endian))
    } else if cfg!(target_os = "freebsd") {
        Ok(Profile::freebsd(endian))
    } else {
        Err(Fault::Unsupported)
    }
}
/// This physical listener's actual official protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Address registration/observations/reversal IPC.
    Nat,
    /// Configuration proposal IPC, not a NAT reachability test.
    Auto,
    /// Public gnunet-nat-server opaque challenge sender.
    Test,
}
impl Mode {
    /// Actual official configuration service name.
    pub const fn service(self) -> &'static [u8] {
        match self {
            Self::Nat => b"nat",
            Self::Auto => b"nat-auto",
            Self::Test => b"gnunet-nat-server",
        }
    }
}
/// Process-shared canonical ports and listener credential policy.
pub struct Ports {
    /// Actual SERVICE policy.
    pub options: ServiceOptions,
    /// Actual kernel Unix-credential policy.
    pub unix: UnixAccess,
    /// Same process clock used by Resolver/Manager.
    pub clock: Arc<dyn RuntimeClock>,
    /// Actual process-shared official Resolver.
    pub resolver: SharedResolution,
}
/// Finite source/frame/queue/cursor lifetimes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum accepted original MQs.
    pub clients: usize,
    /// Maximum complete official frame.
    pub frame_bytes: usize,
    /// Per-source retained immutable TX records.
    pub output_frames: usize,
    /// Per-source retained immutable TX bytes.
    pub output_bytes: usize,
    /// Native IO slice bytes.
    pub io_slice_bytes: usize,
    /// Original first-complete-frame native deadline.
    pub first_input: Duration,
    /// Original first-byte to complete/consume deadline.
    pub input_lifetime: Duration,
    /// Each original output's maximum native residence.
    pub output_lifetime: Duration,
    /// Original finite public test/auto connection lifetime.
    pub transient_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 128,
            frame_bytes: 65535,
            output_frames: 64,
            output_bytes: 64 * 65535,
            io_slice_bytes: 65535,
            first_input: Duration::from_secs(30),
            input_lifetime: Duration::from_secs(30),
            output_lifetime: Duration::from_secs(30),
            transient_lifetime: Duration::from_secs(30),
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: self.output_frames,
                bytes: self.output_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn validate(self) -> Result<(), Fault> {
        self.framing().validate()?;
        if self.clients == 0
            || self.clients > 4096
            || self.frame_bytes < 40
            || self.output_bytes < self.frame_bytes
            || self.output_frames > 4096
        {
            return Err(Fault::Capacity);
        }
        for d in [
            self.first_input,
            self.input_lifetime,
            self.output_lifetime,
            self.transient_lifetime,
        ] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput);
            }
        }
        Ok(())
    }
}
/// Exact original physical closure cause.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual peer EOF.
    Eof,
    /// Actual original IO error.
    Io(std::io::Error),
    /// Actual malformed source/unsupported semantic/resource failure.
    Protocol(Failure),
    /// Original first/input/output/session bound elapsed.
    Deadline,
    /// Source's actual forwarding interface vanished.
    InterfaceGone,
    /// Actual SERVICE shutdown/finite drain completion.
    Shutdown,
}
/// Actual observable native source facts, with no payload/key logging.
#[derive(Debug)]
pub enum Event {
    /// Actual native accept/socket-option diagnostic.
    Socket(SocketEvent),
    /// Actual access-policy rejection.
    Rejected(PeerAddress),
    /// Actual admission/configuration/source-allocation failure.
    AdmissionFailed {
        /// Original peer.
        peer: PeerAddress,
        /// Original cause.
        error: Failure,
    },
    /// Actual accepted original MQ.
    Accepted(Source),
    /// Physical retirement of only this original MQ.
    Closed {
        /// Original source.
        source: Source,
        /// Actual cause.
        cause: CloseCause,
    },
    /// Actual original provider/process/router observation.
    Discovery(crate::manager::Event),
    /// Notification/config frame actually queued to its original source.
    Queued {
        /// Original source.
        source: Source,
        /// Original local output serial.
        write: u64,
    },
    /// Whole original frame actually written (not peer processing).
    Written {
        /// Original source.
        source: Source,
        /// Original local output serial.
        write: u64,
    },
}
/// Actual bounded drive progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual finite source/provider/native activity.
    Activity,
    /// All original MQs and actual provider/cleanup debts completed.
    Stopped,
    /// Caller original native bound reached; no cleanup success inferred.
    WaitDeadline,
}
/// Actual accumulated source facts. A failed/unresolved cleanup is never clean.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual physical admissions.
    pub accepted: u64,
    /// Actual physical closures.
    pub closed: u64,
    /// Actual whole output writes.
    pub written: u64,
    /// Actual provider/cleanup failure observations.
    pub failures: u64,
    /// Current original source/provider/child debt at report time.
    pub pending: usize,
    /// Actual cleanup outcomes still unestablished.
    pub unresolved: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Origin {
    source: Source,
    write: u64,
    until: Instant,
    advertised: Option<state::Advertised>,
}
struct Peer {
    source: Source,
    io: Framed<Origin>,
    next: u64,
    first: bool,
    first_until: Instant,
    input_until: Option<Instant>,
    session: Option<Bounds>,
    outputs: VecDeque<Origin>,
    reply: Option<OwnedFrame>,
    auto_done: bool,
    read_first: bool,
}
/// A caller-driven actual native service. No executor, process or socket opens
/// in the constructor; the caller supplies actual BoundListeners/Resolver driver.
pub struct Server {
    manager: Manager,
    template: Configuration,
    mode: Mode,
    profile: Profile,
    limits: Limits,
    ports: Ports,
    peers: Vec<Option<Peer>>,
    accept: AcceptState,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    timer: Pin<Box<Sleep>>,
    cursor: usize,
    listener_cursor: usize,
    manager_first: bool,
    blocked: Option<state::Event>,
    shutdown: Option<ShutdownMode>,
    manager_stopped: bool,
    report: Report,
    yield_due: bool,
}
fn bytes(n: usize) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    out.resize(n, 0);
    Ok(out)
}
impl Server {
    /// Set up actual bounded owners with the original shared time/Resolver.
    pub fn new(
        config: Configuration,
        mut settings: Settings,
        core: state::Limits,
        limits: Limits,
        ports: Ports,
        mode: Mode,
    ) -> Result<Self, Failure> {
        limits.validate()?;
        if core.sources < limits.clients || !Arc::ptr_eq(&ports.resolver.clock(), &ports.clock) {
            return Err(Fault::InvalidInput.into());
        }
        if mode != Mode::Nat {
            settings.enable_ipscan = false;
            settings.enable_upnp = false;
            settings.use_stun = false;
        }
        let subscription = ports.clock.subscribe()?;
        let revision = ports.clock.sample()?.revision;
        let profile = native_profile()?;
        let template = config.duplicate()?;
        let manager = Manager::new(
            config,
            settings,
            core,
            ports.resolver.clone(),
            ports.clock.clone(),
        )?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        peers.resize_with(limits.clients, || None);
        Ok(Self {
            manager,
            template,
            mode,
            profile,
            limits,
            ports,
            peers,
            accept: AcceptState::default(),
            subscription,
            revision,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            cursor: 0,
            listener_cursor: 0,
            manager_first: false,
            blocked: None,
            shutdown: None,
            manager_stopped: false,
            report: Report::default(),
            yield_due: false,
        })
    }
    /// Actual metadata/cleanup state; no router state is inferred from counters.
    pub fn report(&self) -> Report {
        Report {
            pending: self.manager.pending() + self.peers.iter().flatten().count(),
            unresolved: self.manager.unresolved(),
            ..self.report
        }
    }
    /// Admit an actually accepted/initialized stream after real access checks.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<Source>, Failure> {
        let (connection, peer, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(d)));
        }
        let allowed = match peer {
            PeerAddress::Tcp(p) => self.ports.options.access.allows(p.ip()),
            PeerAddress::Unix => match self.ports.unix.allows(&connection) {
                Ok(allowed) => allowed,
                Err(error) => {
                    drop(connection);
                    observe(Event::AdmissionFailed {
                        peer,
                        error: error.into(),
                    });
                    return Ok(None);
                }
            },
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(peer));
            return Ok(None);
        }
        let Some(index) = self
            .peers
            .iter()
            .position(Option::is_none)
            .filter(|_| self.shutdown.is_none())
        else {
            drop(connection);
            observe(Event::AdmissionFailed {
                peer,
                error: Fault::Capacity.into(),
            });
            return Ok(None);
        };
        let first_until = Instant::now()
            .checked_add(self.limits.first_input)
            .ok_or(Fault::Overflow)?;
        let session = if self.mode == Mode::Nat {
            None
        } else {
            Some(Bounds::after(
                &*self.ports.clock,
                self.limits.transient_lifetime,
            )?)
        };
        let io = Framed::new(connection, self.limits.framing())?;
        let source = self.manager.source_attached()?;
        self.peers[index] = Some(Peer {
            source,
            io,
            next: 1,
            first: true,
            first_until,
            input_until: None,
            session,
            outputs: VecDeque::new(),
            reply: None,
            auto_done: false,
            read_first: false,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(source));
        Ok(Some(source))
    }
    fn close_index(&mut self, i: usize, cause: CloseCause, observe: &mut impl FnMut(Event)) {
        if let Some(mut peer) = self.peers[i].take() {
            peer.io.retire();
            self.accept.client_closed();
            if self.blocked.is_some_and(|e| e.source == peer.source) {
                self.blocked = None;
            }
            if let Err(error) = self.manager.source_stopped(peer.source, &mut |e| {
                if matches!(
                    &e,
                    crate::manager::Event::Failed { .. }
                        | crate::manager::Event::MappingUnknown { .. }
                ) {
                    self.report.failures = self.report.failures.saturating_add(1);
                }
                observe(Event::Discovery(e))
            }) {
                self.report.failures = self.report.failures.saturating_add(1);
                observe(Event::Discovery(crate::manager::Event::Failed {
                    job: 0,
                    source: Some(peer.source),
                    error,
                }));
            }
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed {
                source: peer.source,
                cause,
            });
        }
    }
    /// Physically stop only this original source; there is no wire cancel.
    pub fn close(
        &mut self,
        source: Source,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        let i = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.source == source))
            .ok_or(Fault::StaleGeneration)?;
        self.close_index(i, CloseCause::Shutdown, observe);
        Ok(())
    }
    /// Request a finite caller-controlled drain; repeated calls do not move its bound.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
    }
    /// Physical emergency stop independent of clock/Resolver health. Any router
    /// mutation uncertainty remains in actual report/events, not a delete ACK.
    pub fn abort(&mut self, observe: &mut impl FnMut(Event)) {
        self.shutdown = Some(ShutdownMode::Immediate);
        for i in 0..self.peers.len() {
            self.close_index(i, CloseCause::Shutdown, observe);
        }
        self.manager.abort(&mut |e| {
            if matches!(
                &e,
                crate::manager::Event::Failed { .. } | crate::manager::Event::MappingUnknown { .. }
            ) {
                self.report.failures = self.report.failures.saturating_add(1);
            }
            observe(Event::Discovery(e))
        });
        self.manager_stopped = true;
    }
    fn enqueue(
        &mut self,
        index: usize,
        frame: OwnedFrame,
        advertised: Option<state::Advertised>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        let origin = Origin {
            source: p.source,
            write: p.next,
            advertised,
            until: Instant::now()
                .checked_add(self.limits.output_lifetime)
                .ok_or(Fault::Overflow)?,
        };
        let next = p.next.checked_add(1).ok_or(Fault::Overflow)?;
        p.outputs.try_reserve(1).map_err(|_| Fault::Capacity)?;
        p.io.reserve(frame.len(), Class::Ordinary)?;
        p.io.enqueue_owned(frame, origin, Class::Ordinary)
            .map_err(|e| e.reason)?;
        p.outputs.push_back(origin);
        p.next = next;
        observe(Event::Queued {
            source: p.source,
            write: origin.write,
        });
        Ok(())
    }
    fn notification(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Failure> {
        let event = match self
            .blocked
            .take()
            .or_else(|| self.manager.take_notification())
        {
            Some(e) => e,
            None => return Ok(false),
        };
        if let EventKind::AddressChange { added: true, value } = event.kind
            && !self.manager.advertised(event.source, value)
        {
            return Ok(true);
        }
        let Some(index) = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.source == event.source))
        else {
            return Ok(true);
        };
        let mut address = [0u8; 28];
        let n = match event.kind {
            EventKind::AddressChange { value, .. } => {
                value.address.wire().encode(self.profile, &mut address)?
            }
            EventKind::Reverse { remote } => remote.wire().encode(self.profile, &mut address)?,
        };
        let raw = nat::RawAddress::decode(&address[..n], self.profile)?;
        let response = match event.kind {
            EventKind::AddressChange { added, value } => nat::Response::AddressChange {
                add_remove: i32::from(added),
                class: value.class,
                address: raw,
            },
            EventKind::Reverse { .. } => nat::Response::Reverse { remote: raw },
        };
        let n = response.encoded_len(self.profile)?;
        if !self.peers[index]
            .as_ref()
            .ok_or(Fault::Stale)?
            .io
            .capacity(n, Class::Ordinary)
        {
            self.blocked = Some(event);
            return Ok(false);
        }
        let mut out = bytes(n)?;
        response.encode(self.profile, &mut out)?;
        self.enqueue(
            index,
            OwnedFrame::new(out),
            match event.kind {
                EventKind::AddressChange { added: true, value } => Some(value),
                _ => None,
            },
            observe,
        )?;
        Ok(true)
    }
    fn process(&mut self, index: usize, observe: &mut impl FnMut(Event)) -> Result<bool, Failure> {
        let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        let source = p.source;
        let input = p.io.frame().ok_or(Fault::NotReady)?;
        match self.mode {
            Mode::Nat => {
                let request = match nat::Request::decode(input, self.profile) {
                    Ok(r) => r,
                    Err(Fault::Unsupported) if self.ports.options.tolerant => {
                        p.io.release_frame();
                        p.input_until = None;
                        return Ok(true);
                    }
                    Err(e) => return Err(e.into()),
                };
                let registering = matches!(request, nat::Request::Register { .. });
                match self.manager.request(source, request, &mut |e| {
                    if matches!(
                        &e,
                        crate::manager::Event::Failed { .. }
                            | crate::manager::Event::MappingUnknown { .. }
                    ) {
                        self.report.failures = self.report.failures.saturating_add(1);
                    }
                    observe(Event::Discovery(e))
                }) {
                    Err(error)
                        if error.downcast_ref::<Fault>() == Some(&Fault::WouldBlock)
                            && !registering =>
                    {
                        return Ok(false);
                    }
                    result => result?,
                }
            }
            Mode::Auto => {
                if p.auto_done {
                    return Err(Fault::Conflict.into());
                }
                if p.reply.is_none() {
                    let request = nat_auto::Request::decode(input)?;
                    let proposal = crate::auto::propose(&self.template, request.configuration)?;
                    let response = nat_auto::Response {
                        status: proposal.status,
                        nat_type: proposal.nat_type,
                        configuration_diff: &proposal.configuration_diff,
                    };
                    let mut out = bytes(response.encoded_len()?)?;
                    response.encode(&mut out)?;
                    p.reply = Some(OwnedFrame::new(out));
                }
                let needed = p.reply.as_ref().ok_or(Fault::Stale)?.len();
                if !p.io.capacity(needed, Class::Ordinary) {
                    return Ok(false);
                }
                let frame = p.reply.take().ok_or(Fault::Stale)?;
                self.enqueue(index, frame, None, observe)?;
                self.peers[index].as_mut().ok_or(Fault::Stale)?.auto_done = true;
            }
            Mode::Test => {
                let request = nat::TestRequest::decode(input)?;
                self.manager.test(source, request)?;
                self.peers[index].as_mut().ok_or(Fault::Stale)?.auto_done = true;
            }
        }
        let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        if !p.io.release_frame() {
            return Err(Fault::Stale.into());
        }
        p.first = false;
        p.input_until = None;
        Ok(true)
    }
    fn native(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        let now = Instant::now();
        for i in 0..self.peers.len() {
            if let Some(p) = &self.peers[i]
                && (p.first && now >= p.first_until
                    || p.input_until.is_some_and(|t| now >= t)
                    || p.outputs.front().is_some_and(|o| now >= o.until)
                    || p.session.is_some_and(|b| now >= b.hard))
            {
                self.close_index(i, CloseCause::Deadline, observe);
            }
        }
        self.manager.poll_native(cx, &mut |e| {
            if matches!(
                &e,
                crate::manager::Event::Failed { .. } | crate::manager::Event::MappingUnknown { .. }
            ) {
                self.report.failures = self.report.failures.saturating_add(1);
            }
            observe(Event::Discovery(e))
        })?;
        let due = self
            .peers
            .iter()
            .flatten()
            .flat_map(|p| {
                p.first
                    .then_some(p.first_until)
                    .into_iter()
                    .chain(p.input_until)
                    .chain(p.outputs.front().map(|o| o.until))
                    .chain(p.session.map(|b| b.hard))
            })
            .chain(until)
            .filter(|t| *t > now)
            .min();
        if let Some(due) = due {
            self.timer.as_mut().reset(due);
            let _wake = self.timer.as_mut().poll(cx);
        }
        Ok(())
    }
    fn clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Failure>> {
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.ports.clock.sample()?;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => {
                self.revision = sample.revision;
                Poll::Ready(Ok(sample.now.as_micros()))
            }
        }
    }
    fn stale_output(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        let p = self.peers[index].as_ref().ok_or(Fault::Stale)?;
        let mut stale = Vec::new();
        stale
            .try_reserve_exact(p.outputs.len())
            .map_err(|_| Fault::Capacity)?;
        for origin in &p.outputs {
            if origin
                .advertised
                .is_some_and(|v| !self.manager.advertised(origin.source, v))
            {
                stale.push(*origin);
            }
        }
        if stale.is_empty() {
            return Ok(false);
        }
        let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        let (outputs, io) = (&mut p.outputs, &mut p.io);
        io.remove_unwritten(
            |origin, _| stale.contains(&origin),
            |origin, _| outputs.retain(|o| *o != origin),
        );
        if p.outputs.iter().any(|o| stale.contains(o)) {
            self.close_index(index, CloseCause::Deadline, observe);
        }
        Ok(true)
    }
    fn peer(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Failure>> {
        let p = self.peers[index].as_ref().ok_or(Fault::Stale)?;
        if (self.shutdown.is_some() || p.auto_done)
            && p.io.frame().is_none()
            && p.io.queued_frames() == 0
        {
            self.close_index(index, CloseCause::Shutdown, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        let read_first = p.read_first;
        for n in 0..2 {
            let reading = (n == 0) == read_first;
            if reading {
                if self.peers[index]
                    .as_ref()
                    .is_some_and(|p| p.io.frame().is_some())
                {
                    match self.process(index, observe) {
                        Ok(true) => return Poll::Ready(Ok(Progress::Activity)),
                        Ok(false) => {}
                        Err(error) => {
                            self.close_index(index, CloseCause::Protocol(error), observe);
                            return Poll::Ready(Ok(Progress::Activity));
                        }
                    }
                } else if self.shutdown.is_none()
                    && !self.peers[index].as_ref().ok_or(Fault::Stale)?.auto_done
                {
                    match self.peers[index]
                        .as_mut()
                        .ok_or(Fault::Stale)?
                        .io
                        .poll_read(cx)
                    {
                        Poll::Pending => {}
                        Poll::Ready(Err(e)) => {
                            self.close_index(index, CloseCause::Io(e), observe);
                            return Poll::Ready(Ok(Progress::Activity));
                        }
                        Poll::Ready(Ok(ReadStep::Eof)) => {
                            self.close_index(index, CloseCause::Eof, observe);
                            return Poll::Ready(Ok(Progress::Activity));
                        }
                        Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                            let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
                            if p.input_until.is_none() {
                                p.input_until = Some(
                                    Instant::now()
                                        .checked_add(self.limits.input_lifetime)
                                        .ok_or(Fault::Overflow)?,
                                );
                            }
                            p.read_first = false;
                            return Poll::Ready(Ok(Progress::Activity));
                        }
                    }
                }
            } else {
                let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
                match p.io.poll_write(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(e)) => {
                        self.close_index(index, CloseCause::Io(e), observe);
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Poll::Ready(Ok(progress)) => {
                        if progress.origin.source != p.source
                            || p.outputs.front() != Some(&progress.origin)
                        {
                            return Poll::Ready(Err(Fault::StaleGeneration.into()));
                        }
                        if progress.complete {
                            p.outputs.pop_front();
                            self.report.written = self.report.written.saturating_add(1);
                            observe(Event::Written {
                                source: p.source,
                                write: progress.origin.write,
                            });
                        }
                        p.read_first = true;
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                }
            }
        }
        Poll::Pending
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Failure>> {
        self.native(cx, until, observe)?;
        if self.shutdown == Some(ShutdownMode::Immediate) {
            for i in 0..self.peers.len() {
                self.close_index(i, CloseCause::Shutdown, observe);
            }
        }
        if until.is_some_and(|t| Instant::now() >= t) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        let now = match self.clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => n,
        };
        self.manager.maintain(now)?;
        for index in 0..self.peers.len() {
            if self.peers[index].is_some() && self.stale_output(index, observe)? {
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        for i in 0..self.peers.len() {
            if self.peers[i]
                .as_ref()
                .is_some_and(|p| p.session.is_some_and(|b| now >= b.expires))
            {
                self.close_index(i, CloseCause::Deadline, observe);
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        if let Some(source) = self.manager.take_retirement() {
            if let Some(index) = self
                .peers
                .iter()
                .position(|p| p.as_ref().is_some_and(|p| p.source == source))
            {
                self.close_index(index, CloseCause::InterfaceGone, observe);
            }
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown.is_some()
            && self.peers.iter().all(Option::is_none)
            && !self.manager_stopped
        {
            self.manager.shutdown(&mut |e| {
                if matches!(
                    &e,
                    crate::manager::Event::Failed { .. }
                        | crate::manager::Event::MappingUnknown { .. }
                ) {
                    self.report.failures = self.report.failures.saturating_add(1);
                }
                observe(Event::Discovery(e))
            })?;
            self.manager_stopped = true;
        }
        if self.manager_stopped && self.manager.pending() == 0 {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if self.mode == Mode::Nat && self.shutdown.is_none() && self.notification(observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        for n in 0..2 {
            let managing = (n == 0) == self.manager_first;
            if managing {
                if let Poll::Ready(result) = self.manager.poll(cx, &mut |e| {
                    if matches!(
                        e,
                        crate::manager::Event::Failed { .. }
                            | crate::manager::Event::MappingUnknown { .. }
                    ) {
                        self.report.failures = self.report.failures.saturating_add(1);
                    }
                    observe(Event::Discovery(e))
                }) {
                    self.manager_first = false;
                    return Poll::Ready(result.map(|()| Progress::Activity));
                }
            } else {
                for n in 0..self.peers.len() {
                    let i = (self.cursor + n) % self.peers.len();
                    if self.peers[i].is_some() {
                        let result = self.peer(cx, i, observe);
                        if result.is_ready() {
                            self.cursor = (i + 1) % self.peers.len();
                            self.manager_first = true;
                            return result;
                        }
                    }
                }
            }
        }
        if self.shutdown.is_none() && self.accept.ready() && self.peers.iter().any(Option::is_none)
        {
            for n in 0..listeners.len() {
                let i = (self.listener_cursor + n) % listeners.len();
                match listeners[i].poll_canonical_connection(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(e)) => {
                        observe(Event::Socket(self.accept.failed(e)));
                        self.listener_cursor = (i + 1) % listeners.len();
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Poll::Ready(Ok(accepted)) => {
                        self.listener_cursor = (i + 1) % listeners.len();
                        self.admit(accepted, observe)?;
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                }
            }
        }
        Poll::Pending
    }
    /// Cancellation-safe bounded actual native/service turn. Errors close every
    /// original socket before returning the actual process-port failure.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Failure>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.poll_inner(cx, listeners, until, observe);
        if matches!(result, Poll::Ready(Err(_))) {
            self.abort(observe);
        }
        if matches!(result, Poll::Ready(Ok(Progress::Activity))) {
            self.yield_due = true;
        }
        result
    }
    /// Dropping this borrowed future retains all original RX/TX/provider cursors.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Failure> {
        poll_fn(|cx| self.poll(cx, listeners, until, &mut observe)).await
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.abort(&mut |_| {});
    }
}
