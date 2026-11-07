//! Actual finite GNUnet NAT-auto reachability test caller. A matched public
//! two-byte challenge is an unauthenticated network-path observation, not peer
//! identity or a cryptographic proof. No test-server ACK/cancel message exists.
#![cfg(unix)]
#![forbid(unsafe_code)]
use gnunet_client_host::channel::{Channel, ConnectionStep};
pub use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution};
/// Actual native-client PROGRAM command-line implementations.
#[cfg(feature = "program")]
pub mod cli;
use gnunet_nat_client_host::{
    self as client, Deadlines, End as NatEnd, Progress as NatProgress, Registration,
    RegistrationRequest,
};
pub use gnunet_nat_client_host::{AddressId, Epoch, Instance, Profiles, Session};
use gnunet_nat_host::deadline::{Bounds, Gate};
use gnunet_service_runtime::{
    clock::RuntimeClock,
    framing::{Accounting, Budget, Class, Limits as FrameLimits},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::nat::{self, Address, AddressWriter, RawAddress};
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Instant, Sleep},
};
/// Actual failure without fabricated NAT status or network success.
pub type Failure = Box<dyn std::error::Error>;
/// Which actual standardized test path is requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Actual TCP challenge listener.
    Tcp,
    /// Actual UDP challenge listener.
    Udp,
    /// Official dummy-ICMP reversal technique; original protocol still explicit.
    Reversal {
        /// Original TCP6/UDP17 selector used in registration/test.
        protocol: u8,
    },
}
impl Transport {
    fn protocol(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Reversal { protocol } => protocol,
        }
    }
}
/// Explicit original resources. Targets/tombstones are never reused in one test.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum total original advertised-address targets, including retired ones.
    pub targets: usize,
    /// Maximum simultaneous accepted TCP challenge streams.
    pub incoming: usize,
    /// Maximum total accepted streams/datagrams in the original test.
    pub network_events: usize,
    /// Original accepted TCP input lifetime, capped by test hard bound.
    pub incoming_lifetime: Duration,
    /// Actual NAT client resources.
    pub registration: client::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            targets: 256,
            incoming: 32,
            network_events: 1024,
            incoming_lifetime: Duration::from_secs(5),
            registration: client::Limits::default(),
        }
    }
}
/// Original endpoints frozen coherently by a caller's LiveConfiguration owner.
pub struct Sources {
    /// Actual ordinary NAT service selector.
    pub nat: EndpointSource,
    /// Actual public gnunet-nat-server selector.
    pub test_server: EndpointSource,
}
/// Test inputs, before any native socket is opened.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// Actual TCP/UDP/reversal test path.
    pub transport: Transport,
    /// Actual configured local test port (zero requests ephemeral bind).
    pub port: u16,
    /// Original NAT configuration section, without NUL.
    pub section: &'a [u8],
    /// Actual producer/consumer sockaddr ABIs.
    pub profiles: Profiles,
    /// Original absolute/native finite test bounds.
    pub bounds: Bounds,
}
/// Sealed matched original challenge observation. It proves no remote identity
/// and is never produced from a local write, EOF, timeout, or service hint alone.
#[derive(Clone, Copy, Debug)]
pub struct Observation<'id> {
    session: Session<'id>,
    epoch: Epoch<'id>,
    address: AddressId<'id>,
    target: u64,
    transport: Transport,
    remote: SocketAddr,
}
impl<'id> Observation<'id> {
    /// Original registration session.
    pub const fn session(self) -> Session<'id> {
        self.session
    }
    /// Original live physical NAT source.
    pub const fn epoch(self) -> Epoch<'id> {
        self.epoch
    }
    /// Original still-live advertised address allocation.
    pub const fn address(self) -> AddressId<'id> {
        self.address
    }
    /// Original target serial, never a wire RID.
    pub const fn target(self) -> u64 {
        self.target
    }
    /// Actual path used for this observation.
    pub const fn transport(self) -> Transport {
        self.transport
    }
    /// Actual packet/accepted-stream source, without authentication claim.
    pub const fn remote(self) -> SocketAddr {
        self.remote
    }
}
/// Actual finite result, retaining exact local/provider failure causes.
#[derive(Debug)]
pub enum Outcome<'id> {
    /// Actual original challenge received on actual listener/NAT MQ.
    Received(Observation<'id>),
    /// Original canonical or independent native deadline elapsed.
    Timeout,
    /// Explicit local cancellation; no wire cancellation is inferred.
    Cancelled,
    /// Actual original setup/provider/native failure.
    Failed(Failure),
}
/// Original terminal owner. NAT app contexts/callback are transferred instead
/// of discarded or rebound to a later session. Targets retain actual byte facts.
#[derive(Debug)]
pub struct End<'id> {
    /// Actual finite result.
    pub outcome: Outcome<'id>,
    /// Original registration physical-close outcome.
    pub registration: Option<NatEnd<'id>>,
    /// Original request send/retirement facts.
    pub targets: Vec<TargetEnd<'id>>,
}
/// One actual original test-server request's retained exposure.
#[derive(Clone, Copy, Debug)]
pub struct TargetEnd<'id> {
    /// Original target serial.
    pub target: u64,
    /// Original advertised address id.
    pub address: AddressId<'id>,
    /// Original actual NAT source epoch.
    pub epoch: Epoch<'id>,
    /// Actual whole/partial/no local frame bytes.
    pub bytes: usize,
    /// Whether all16 original bytes were locally written.
    pub written: bool,
    /// Whether this original address/source was retired before a result.
    pub retired: bool,
}
/// One actual caller-driven test step.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Actual terminal metadata and native callback/cache owners transfer without allocating after physical close"
)]
pub enum Progress<'id> {
    /// Actual bounded native/provider activity.
    Activity,
    /// Original16-byte request was completely locally written; no ACK/remote success.
    RequestWritten {
        /// Original target.
        target: u64,
        /// Original NAT address allocation.
        address: AddressId<'id>,
    },
    /// One original native/source failure while other original targets can continue.
    TargetFailed {
        /// Original target.
        target: u64,
        /// Actual cause.
        error: Failure,
    },
    /// Actual terminal test result and original cleanup ownership.
    Ended(End<'id>),
    /// Caller observation bound only, independent of original test expiry.
    WaitDeadline,
    /// Terminal result already delivered.
    Closed,
}
#[derive(Clone, Copy)]
struct Tag {
    target: u64,
}
enum State {
    Prepared,
    Attached,
    Queued,
    Written,
    Failed,
    Retired,
}
struct Target<'id> {
    serial: u64,
    address: AddressId<'id>,
    epoch: Epoch<'id>,
    challenge: [u8; 2],
    channel: Option<Channel<Tag>>,
    packet: [u8; 16],
    state: State,
    bytes: usize,
}
struct Incoming {
    stream: TcpStream,
    peer: SocketAddr,
    bytes: [u8; 2],
    used: usize,
    until: Instant,
}
/// Retained original registration, real challenge listener, target MQ cursors,
/// accepted streams and hard timers. No task or implicit Resolver is created.
pub struct Test<'id> {
    registration: Registration<'id>,
    source: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
    gate: Gate,
    transport: Transport,
    profiles: Profiles,
    port: u16,
    tcp: Option<TcpListener>,
    udp: Option<UdpSocket>,
    targets: Vec<Target<'id>>,
    incoming: Vec<Incoming>,
    limits: Limits,
    next: u64,
    challenge: u16,
    network_events: usize,
    timer: Pin<Box<Sleep>>,
    wait: Pin<Box<Sleep>>,
    cursor: usize,
    nat_first: bool,
    ended: bool,
    end_targets: Vec<TargetEnd<'id>>,
    yield_due: bool,
}
impl<'id> Test<'id> {
    /// Bind a real listener/socket before registering its actual local endpoint.
    /// Reversal mode also owns a real binding of the requested TCP/UDP protocol, avoiding the pinned
    /// C test's empty registration/no-NAT-flag and zero-challenge bugs.
    pub async fn start(
        instance: &'id Instance,
        sources: Sources,
        request: Request<'_>,
        limits: Limits,
    ) -> Result<Self, Failure> {
        if !matches!(request.transport.protocol(), 6 | 17)
            || request.section.contains(&0)
            || limits.targets == 0
            || limits.targets > 65535
            || limits.incoming == 0
            || limits.network_events == 0
            || limits.incoming_lifetime.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        let register_len = 27usize
            .checked_add(request.section.len())
            .ok_or(Fault::Overflow)?;
        if register_len > 65535
            || register_len > limits.registration.frame_bytes
            || register_len > limits.registration.source_bytes
        {
            return Err(Fault::TooLarge.into());
        }
        let [nat_source, server_source] =
            EndpointSource::snapshot_all([&sources.nat, &sources.test_server])?;
        let clock = nat_source.clock();
        if !Arc::ptr_eq(&clock, &server_source.clock()) {
            return Err(Fault::InvalidInput.into());
        }
        let mut gate = Gate::new(clock.clone(), request.bounds)?;
        let local = SocketAddr::from(([0, 0, 0, 0], request.port));
        let (tcp, udp, port) = if request.transport == Transport::Tcp
            || matches!(request.transport, Transport::Reversal { protocol: 6 })
        {
            let listener = gate.run(TcpListener::bind(local)).await?;
            let port = listener.local_addr()?.port();
            (Some(listener), None, port)
        } else {
            let socket = gate.run(UdpSocket::bind(local)).await?;
            let port = socket.local_addr()?.port();
            (None, Some(socket), port)
        };
        let mut storage = [0; 16];
        let mut addresses = AddressWriter::new(&mut storage, request.profiles.request);
        addresses.push(Address::V4 { ip: [0; 4], port })?;
        let flags = nat::ADDRESSES
            | if matches!(request.transport, Transport::Reversal { .. }) {
                nat::REVERSAL
            } else {
                0
            };
        let registration = Registration::new(
            instance,
            nat_source,
            RegistrationRequest {
                flags,
                protocol: request.transport.protocol(),
                addresses: addresses.addresses(),
                section: request.section,
            },
            request.profiles,
            Deadlines {
                send_until: request.bounds.expires,
                first_input_until: None,
                until: request.bounds.expires,
            },
            limits.registration,
        )?;
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(limits.targets)
            .map_err(|_| Fault::Capacity)?;
        let mut end_targets = Vec::new();
        end_targets
            .try_reserve_exact(limits.targets)
            .map_err(|_| Fault::Capacity)?;
        let mut incoming = Vec::new();
        incoming
            .try_reserve_exact(limits.incoming)
            .map_err(|_| Fault::Capacity)?;
        let mut seed = [0; 2];
        getrandom::fill(&mut seed)?;
        let challenge = u16::from_be_bytes(seed);
        Ok(Self {
            registration,
            source: server_source,
            clock,
            gate,
            transport: request.transport,
            profiles: request.profiles,
            port,
            tcp,
            udp,
            targets,
            incoming,
            limits,
            next: 1,
            challenge,
            network_events: 0,
            timer: Box::pin(tokio::time::sleep_until(request.bounds.hard)),
            wait: Box::pin(tokio::time::sleep_until(request.bounds.hard)),
            cursor: 0,
            nat_first: false,
            ended: false,
            end_targets,
            yield_due: false,
        })
    }
    /// Original actual binding port; it is not asserted to be the mapped port.
    pub const fn local_port(&self) -> u16 {
        self.port
    }
    /// Original actual NAT source and address cache, without caller mutation.
    pub fn registration(&self) -> &Registration<'id> {
        &self.registration
    }
    /// Exact original shared clock source, with no new waiter or native IO.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Original explicit native sockaddr producer/consumer profiles.
    pub const fn profiles(&self) -> Profiles {
        self.profiles
    }
    /// Start the official adapter-configured PORT test (PORT0 selects reversal),
    /// freezing NAT/test-server endpoints coherently from one actual config.
    pub async fn from_configuration(
        instance: &'id Instance,
        configuration: &gnunet_config::Configuration,
        resolution: client::resolution::SharedResolution,
        section: &[u8],
        protocol: u8,
        timeout: Duration,
        limits: Limits,
    ) -> Result<Self, Failure> {
        if !matches!(protocol, 6 | 17) {
            return Err(Fault::Unsupported.into());
        }
        let port = u16::try_from(configuration.get_number(section, b"PORT")?)
            .map_err(|_| Fault::InvalidInput)?;
        let clock = resolution.clock();
        let bounds = Bounds::after(&*clock, timeout)?;
        let live = client::LiveConfiguration::new(configuration.duplicate()?);
        let sources = Sources {
            nat: EndpointSource::live(live.clone(), b"nat", resolution.clone()),
            test_server: EndpointSource::live(live, b"gnunet-nat-server", resolution),
        };
        let profile = client::native_profile()?;
        let transport = if port == 0 {
            Transport::Reversal { protocol }
        } else if protocol == 6 {
            Transport::Tcp
        } else {
            Transport::Udp
        };
        Self::start(
            instance,
            sources,
            Request {
                transport,
                port,
                section,
                profiles: Profiles::same(profile),
                bounds,
            },
            limits,
        )
        .await
    }
    fn nonce(&mut self) -> Result<[u8; 2], Fault> {
        for _ in 0..=self.limits.targets {
            self.challenge = self.challenge.wrapping_add(1);
            if self.challenge != 0 {
                let n = self.challenge.to_be_bytes();
                if !self.targets.iter().any(|t| t.challenge == n) {
                    return Ok(n);
                }
            }
        }
        Err(Fault::Capacity)
    }
    fn framing() -> FrameLimits {
        FrameLimits {
            frame_bytes: 16,
            ordinary: Budget {
                frames: 1,
                bytes: 16,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: 16,
        }
    }
    fn add(
        &mut self,
        address: AddressId<'id>,
        epoch: Epoch<'id>,
        raw: RawAddress<'_>,
    ) -> Result<(), Failure> {
        let Address::V4 { ip, port } = raw.address() else {
            return Ok(());
        };
        if self.targets.len() >= self.limits.targets {
            return Err(Fault::Capacity.into());
        }
        self.gate.check()?;
        let challenge = self.nonce()?;
        let dport = if matches!(self.transport, Transport::Reversal { .. }) {
            0
        } else if port == 0 {
            self.port
        } else {
            port
        };
        let packet = nat::TestRequest {
            destination: ip,
            port: dport,
            data: challenge,
            is_tcp: i32::from(self.transport.protocol() == 6),
        };
        let mut bytes = [0; 16];
        packet.encode(&mut bytes)?;
        let source = self.source.duplicate()?;
        let channel = Channel::new(source, Self::framing())?;
        let serial = self.next;
        self.next = serial.checked_add(1).ok_or(Fault::Overflow)?;
        self.targets.push(Target {
            serial,
            address,
            epoch,
            challenge,
            channel: Some(channel),
            packet: bytes,
            state: State::Prepared,
            bytes: 0,
        });
        Ok(())
    }
    fn live(&self, target: &Target<'id>) -> bool {
        self.registration.is_current(target.epoch)
            && self.registration.address(target.address).is_ok()
            && !matches!(target.state, State::Retired | State::Failed)
    }
    fn matched(&self, challenge: [u8; 2], remote: SocketAddr) -> Option<Observation<'id>> {
        self.targets
            .iter()
            .find(|t| t.challenge == challenge && matches!(t.state, State::Written) && self.live(t))
            .map(|t| Observation {
                session: self.registration.session(),
                epoch: t.epoch,
                address: t.address,
                target: t.serial,
                transport: self.transport,
                remote,
            })
    }
    fn finish(&mut self, outcome: Outcome<'id>) -> End<'id> {
        self.ended = true;
        self.tcp = None;
        self.udp = None;
        self.incoming.clear();
        for mut t in self.targets.drain(..) {
            if let Some(mut channel) = t.channel.take() {
                channel.detach();
            }
            self.end_targets.push(TargetEnd {
                target: t.serial,
                address: t.address,
                epoch: t.epoch,
                bytes: t.bytes,
                written: t.bytes == 16,
                retired: matches!(t.state, State::Retired),
            });
        }
        End {
            outcome,
            registration: self.registration.close(),
            targets: core::mem::take(&mut self.end_targets),
        }
    }
    /// Physically cancel actual original sockets/MQs. No CANCEL packet or
    /// impossible remote rollback is implied by this local terminal outcome.
    pub fn cancel(&mut self) -> Option<End<'id>> {
        if self.ended {
            None
        } else {
            Some(self.finish(Outcome::Cancelled))
        }
    }
    fn native(&mut self, cx: &mut Context<'_>, until: Option<Instant>) -> Result<(), Failure> {
        if Instant::now() >= self.gate.bounds().hard {
            return Err(Fault::Deadline.into());
        }
        let _alarm = self.timer.as_mut().poll(cx);
        let now = Instant::now();
        self.incoming.retain(|r| now < r.until);
        if let Some(due) = self.incoming.iter().map(|r| r.until).chain(until).min() {
            self.wait.as_mut().reset(due.min(self.gate.bounds().hard));
            let _alarm = self.wait.as_mut().poll(cx);
        }
        Ok(())
    }
    fn nat(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'id>, Failure>> {
        match self.registration.poll(cx, None) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(NatProgress::Ended(end))) => {
                let outcome = if matches!(
                    &end.source.cause,
                    client::Cause::Deadline
                        | client::Cause::WriteDeadline
                        | client::Cause::FirstInputDeadline
                ) {
                    Outcome::Timeout
                } else {
                    Outcome::Failed("original NAT registration source ended; actual cause retained in terminal owner".into())
                };
                let mut finished = self.finish(outcome);
                finished.registration = Some(end);
                Poll::Ready(Ok(Progress::Ended(finished)))
            }
            Poll::Ready(Ok(NatProgress::Notification { epoch, .. })) => {
                enum Change<'id> {
                    Add(AddressId<'id>, [u8; 28], usize, nat::Profile),
                    Remove(AddressId<'id>),
                    Reverse([u8; 4], u16),
                    None,
                }
                let change = {
                    let notice = self.registration.notification()?.ok_or(Fault::Stale)?;
                    if notice.epoch != epoch || notice.session != self.registration.session() {
                        return Poll::Ready(Err(Fault::StaleGeneration.into()));
                    }
                    match notice.response {
                        nat::Response::AddressChange {
                            add_remove: 1,
                            address,
                            ..
                        } => {
                            if let Some(id) = notice.address_id {
                                let mut b = [0; 28];
                                let n = address.as_bytes().len();
                                b[..n].copy_from_slice(address.as_bytes());
                                Change::Add(id, b, n, address.profile())
                            } else {
                                Change::None
                            }
                        }
                        nat::Response::AddressChange { .. } => {
                            notice.address_id.map_or(Change::None, Change::Remove)
                        }
                        nat::Response::Reverse { remote } => match remote.address() {
                            Address::V4 { ip, port } => Change::Reverse(ip, port),
                            _ => Change::None,
                        },
                    }
                };
                self.registration.release_notification()?;
                match change {
                    Change::Add(id, raw, n, profile) => {
                        self.add(id, epoch, RawAddress::decode(&raw[..n], profile)?)?
                    }
                    Change::Remove(id) => {
                        for t in &mut self.targets {
                            if t.address == id && t.epoch == epoch {
                                if let Some(mut c) = t.channel.take() {
                                    c.detach();
                                }
                                t.state = State::Retired;
                            }
                        }
                    }
                    Change::Reverse(ip, port) => {
                        if matches!(self.transport, Transport::Reversal { .. })
                            && let Some(o) =
                                self.matched(port.to_be_bytes(), SocketAddr::from((ip, port)))
                        {
                            return Poll::Ready(Ok(Progress::Ended(
                                self.finish(Outcome::Received(o)),
                            )));
                        }
                    }
                    Change::None => {}
                }
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(NatProgress::Closed)) => Poll::Ready(Err(Fault::Closed.into())),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Progress::Activity)),
        }
    }
    fn target(&mut self, cx: &mut Context<'_>, i: usize) -> Poll<Result<Progress<'id>, Failure>> {
        if !self.live(&self.targets[i]) {
            let t = &mut self.targets[i];
            if let Some(mut c) = t.channel.take() {
                c.detach();
            }
            t.state = State::Retired;
            return Poll::Pending;
        }
        let t = &mut self.targets[i];
        if matches!(t.state, State::Written | State::Failed | State::Retired) {
            return Poll::Pending;
        }
        let channel = t.channel.as_mut().ok_or(Fault::Stale)?;
        match channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(())) => {}
        }
        if matches!(t.state, State::Prepared) {
            match channel.poll_connect(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(ConnectionStep::Attached)) => t.state = State::Attached,
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    return Poll::Ready(Ok(Progress::TargetFailed {
                        target: t.serial,
                        error: error.into(),
                    }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(Progress::TargetFailed {
                        target: t.serial,
                        error: error.into(),
                    }));
                }
            }
        }
        if matches!(t.state, State::Attached) {
            channel.framing_mut().ok_or(Fault::NotReady)?.enqueue_copy(
                &t.packet,
                Tag { target: t.serial },
                Class::Ordinary,
            )?;
            t.state = State::Queued;
            return Poll::Ready(Ok(Progress::Activity));
        }
        match channel.framing_mut().ok_or(Fault::NotReady)?.poll_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                channel.detach();
                t.channel = None;
                t.state = State::Failed;
                Poll::Ready(Ok(Progress::TargetFailed {
                    target: t.serial,
                    error: error.into(),
                }))
            }
            Poll::Ready(Ok(progress)) => {
                if progress.origin.target != t.serial {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                t.bytes = t.bytes.checked_add(progress.bytes).ok_or(Fault::Overflow)?;
                if progress.complete {
                    channel.detach();
                    t.channel = None;
                    t.state = State::Written;
                    Poll::Ready(Ok(Progress::RequestWritten {
                        target: t.serial,
                        address: t.address,
                    }))
                } else {
                    Poll::Ready(Ok(Progress::Activity))
                }
            }
        }
    }
    fn receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'id>, Failure>> {
        if matches!(self.transport, Transport::Reversal { .. }) {
            return Poll::Pending;
        }
        if let Some(socket) = &self.udp
            && !matches!(self.transport, Transport::Reversal { .. })
        {
            let mut bytes = [0; 3];
            let mut buf = ReadBuf::new(&mut bytes);
            match socket.poll_recv_from(cx, &mut buf) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(peer)) => {
                    self.network_events += 1;
                    if self.network_events > self.limits.network_events {
                        return Poll::Ready(Err(Fault::Capacity.into()));
                    }
                    if buf.filled().len() == 2
                        && let Some(o) = self.matched([buf.filled()[0], buf.filled()[1]], peer)
                    {
                        let end = self.finish(Outcome::Received(o));
                        return Poll::Ready(Ok(Progress::Ended(end)));
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        for i in 0..self.incoming.len() {
            let r = &mut self.incoming[i];
            let mut buf = ReadBuf::new(&mut r.bytes[r.used..]);
            match Pin::new(&mut r.stream).poll_read(cx, &mut buf) {
                Poll::Pending => {}
                Poll::Ready(Err(_)) => {
                    self.incoming.swap_remove(i);
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len();
                    if n == 0 {
                        self.incoming.swap_remove(i);
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    r.used += n;
                    if r.used == 2 {
                        let r = self.incoming.swap_remove(i);
                        if let Some(o) = self.matched(r.bytes, r.peer) {
                            let end = self.finish(Outcome::Received(o));
                            return Poll::Ready(Ok(Progress::Ended(end)));
                        }
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        if let Some(listener) = &self.tcp {
            match listener.poll_accept(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok((stream, peer))) => {
                    self.network_events += 1;
                    if self.network_events > self.limits.network_events {
                        return Poll::Ready(Err(Fault::Capacity.into()));
                    }
                    if self.incoming.len() < self.limits.incoming {
                        let until = Instant::now()
                            .checked_add(self.limits.incoming_lifetime)
                            .ok_or(Fault::Overflow)?
                            .min(self.gate.bounds().hard);
                        self.incoming.push(Incoming {
                            stream,
                            peer,
                            bytes: [0; 2],
                            used: 0,
                            until,
                        });
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Failure>> {
        if self.ended {
            return Poll::Ready(Ok(Progress::Closed));
        }
        self.native(cx, until)?;
        if until.is_some_and(|t| Instant::now() >= t) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        let _now = match self.gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(now)) => now,
        };
        if until.is_some_and(|t| Instant::now() >= t) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for n in 0..2 {
            if (n == 0) == self.nat_first {
                if let Poll::Ready(r) = self.nat(cx) {
                    self.nat_first = false;
                    return Poll::Ready(r);
                }
            } else {
                if let Poll::Ready(r) = self.receive(cx) {
                    self.nat_first = true;
                    return Poll::Ready(r);
                }
                for n in 0..self.targets.len() {
                    let i = (self.cursor + n) % self.targets.len();
                    if let Poll::Ready(r) = self.target(cx, i) {
                        self.cursor = (i + 1) % self.targets.len();
                        self.nat_first = true;
                        return Poll::Ready(r);
                    }
                }
            }
        }
        Poll::Pending
    }
    /// One cancellation-safe original test turn; independent native timeout is
    /// checked/armed before any canonical clock wait and physically closes all
    /// original listeners/MQs before its terminal timeout/failure is returned.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Failure>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.poll_inner(cx, until);
        match result {
            Poll::Ready(Err(error)) => {
                let deadline = error.downcast_ref::<Fault>() == Some(&Fault::Deadline)
                    || error
                        .downcast_ref::<gnunet_nat_host::Error>()
                        .is_some_and(|e| {
                            matches!(e, gnunet_nat_host::Error::Protocol(Fault::Deadline))
                        });
                let outcome = if deadline {
                    Outcome::Timeout
                } else {
                    Outcome::Failed(error)
                };
                Poll::Ready(Ok(Progress::Ended(self.finish(outcome))))
            }
            other => {
                if matches!(
                    other,
                    Poll::Ready(Ok(Progress::Activity
                        | Progress::RequestWritten { .. }
                        | Progress::TargetFailed { .. }))
                ) {
                    self.yield_due = true;
                }
                other
            }
        }
    }
    /// Dropping the wait future retains all actual original partial cursors.
    pub async fn drive(&mut self, until: Option<Instant>) -> Result<Progress<'id>, Failure> {
        poll_fn(|cx| self.poll(cx, until)).await
    }
}
impl Drop for Test<'_> {
    fn drop(&mut self) {
        let _end = self.cancel();
    }
}
