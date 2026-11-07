//! Owned Rust CORE service: official application IPC over authenticated CAKE
//! sessions and the real TRANSPORT360..366 boundary. No C backend is launched.
#![forbid(unsafe_code)]
mod application;
mod io;
/// Real PILS identity feed and foreground configuration assembly.
pub mod startup;
#[cfg(test)]
mod tests;

use application::{Applications, PeerState};
use gnunet_client::transport::{
    self as tr, Request as TransportRequest, Response as TransportResponse,
};
use gnunet_client_host::{ConnectionAttempt, Endpoint};
use gnunet_core::{
    record::ReceiveError,
    session::{Event as CryptoEvent, Identity, Phase, Session},
    wire::WordOrder,
};
use gnunet_crypto::{EddsaPublicKey, Entropy};
/// Actual native accept diagnostics from the shared Unix/TCP listener adapter.
pub use gnunet_service_runtime::accepted::SocketEvent;
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock, SystemClock};
use gnunet_service_runtime::credentials::UnixAccess;
use gnunet_service_runtime::service::{Listener, PeerAddress, ServiceOptions};
use gnunet_service_runtime::{accepted::AcceptState, connection::Connection};
use gnunet_types::Error;
use gnunet_wire::official::core::{ClassOrder, Direction, PeerClass, PeerId};
use io::Link;
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::{Future, poll_fn},
    io as stdio,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;

/// Explicit finite host capacities, separate from official protocol fields.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneous physical application and monitor connections.
    pub max_clients: usize,
    /// Simultaneous actual TRANSPORT peers and requests per application.
    pub max_peers: usize,
    /// Retained FIFO bytes per physical link and per peer ciphertext queue.
    pub max_pending_bytes: usize,
    /// Retained frame metadata per FIFO and pending application submission queue.
    pub max_pending_frames: usize,
    /// Total solicited application body reservations plus queued plaintext.
    pub max_reserved_bytes: usize,
    /// Maximum bytes offered in one actual socket syscall, at least one.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_clients: 128,
            max_peers: 128,
            max_pending_bytes: 1024 * 1024,
            max_pending_frames: 256,
            max_reserved_bytes: 8 * 1024 * 1024,
            io_slice_bytes: 65535,
        }
    }
}
/// Actual owned host failure, without secret or plaintext logging.
#[derive(Debug)]
pub enum HostError {
    /// Protocol or explicit capacity error.
    Protocol(Error),
    /// Original canonical clock read/subscription failure; never FOREVER.
    Clock(Error),
    /// Native I/O or clock failure.
    Io(stdio::Error),
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Clock(e) => write!(f, "CORE clock: {e}"),
            Self::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for HostError {}
impl From<Error> for HostError {
    fn from(v: Error) -> Self {
        Self::Protocol(v)
    }
}
impl From<stdio::Error> for HostError {
    fn from(v: stdio::Error) -> Self {
        Self::Io(v)
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(out).map_err(|_| Error::Entropy)
    }
}
struct Ciphertext {
    priority: u32,
    bytes: Vec<u8>,
}
struct Peer<'a> {
    session: Session<'a, 1024>,
    credits: u32,
    ciphertexts: VecDeque<Ciphertext>,
    bytes: usize,
    state: u32,
    timeout: u64,
}
impl Peer<'_> {
    fn control_capacity(&self, limits: Limits) -> bool {
        self.ciphertexts.len() < limits.max_pending_frames.saturating_add(4)
            && 1024
                <= limits
                    .max_pending_bytes
                    .saturating_add(4096)
                    .saturating_sub(self.bytes)
    }
    fn loss(&self, peer: PeerId, origin: PeerLossOrigin, now: u64) -> PeerLoss {
        PeerLoss {
            origin,
            peer,
            phase: self.session.phase(),
            established: self.session.established(),
            next_deadline: self.session.next_deadline(),
            observed_at: now,
            send_credits: self.credits,
            queued_ciphertexts: self.ciphertexts.len(),
            queued_ciphertext_bytes: self.bytes,
        }
    }
    fn enqueue(&mut self, frame: Vec<u8>, priority: u32) {
        self.bytes += frame.len();
        self.ciphertexts.push_back(Ciphertext {
            priority,
            bytes: frame,
        });
    }
}
/// Actual original boundary that retired one confirmed peer association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerLossOrigin {
    /// Official TRANSPORT DISCONNECT for a known authenticated peer.
    TransportDisconnected,
    /// The original Session tick actually returned Lost.
    AssociationExpired,
}
/// Fixed pre-retirement facts for one original confirmed peer. This is not a
/// packet, native-write, application callback or remote-completion receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerLoss {
    /// Exact selected original loss boundary.
    pub origin: PeerLossOrigin,
    /// Original authenticated peer being retired.
    pub peer: PeerId,
    /// Original handshake phase before removal or the expiring tick.
    pub phase: Phase,
    /// Original association's confirmation fact before this transition.
    pub established: bool,
    /// Original Session scheduling target before the transition, including
    /// FOREVER. It is in the Session's logical sample coordinate, not native IO.
    pub next_deadline: u64,
    /// This host turn's existing canonical logical clock sample in microseconds.
    /// It is not a native deadline or a fresh diagnostic clock observation.
    pub observed_at: u64,
    /// Actual original per-peer TRANSPORT send credit before retirement.
    pub send_credits: u32,
    /// Actual original locally queued ciphertext count before retirement.
    pub queued_ciphertexts: usize,
    /// Actual original queued ciphertext byte charge before retirement.
    pub queued_ciphertext_bytes: usize,
}
/// Public counters describe actual owner transitions, never remote delivery.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual admitted application/monitor streams.
    pub accepted: u64,
    /// Actual retired application/monitor streams.
    pub closed: u64,
    /// Complete accepted application/monitor requests.
    pub requests: u64,
    /// Completed authenticated peer associations.
    pub authenticated: u64,
    /// Authenticated application records processed under the bounded app policy.
    pub payloads: u64,
    /// Ciphertexts admitted to the actual TRANSPORT stream FIFO.
    pub transport_sends: u64,
    /// Explicit receive credits admitted after processing a real TRANSPORT RECV.
    pub receive_credits: u64,
    /// Rejected unauthenticated/replayed peer records.
    pub rejected_records: u64,
    /// Original receive-boundary RejectedEpoch refusals, before authentication.
    pub rejected_epoch: u64,
    /// Discarded original receive failures classified as Authentication.
    pub rejected_authentication: u64,
    /// Discarded original receive failures classified as Replay.
    pub rejected_replay: u64,
    /// Discarded original receive failures classified as Truncated.
    pub rejected_truncated: u64,
    /// Discarded original receive failures classified as Malformed.
    pub rejected_malformed: u64,
    /// Discarded original receive failures classified as InvalidInput.
    pub rejected_invalid_input: u64,
    /// Discarded original receive failures classified as Unsupported.
    pub rejected_unsupported: u64,
    /// Failed original TRANSPORT MQs, with all their peer state retired.
    pub transport_losses: u64,
    /// Actual TRANSPORT disconnects of known authenticated peer associations.
    pub transport_disconnections: u64,
    /// Original Session ticks that actually expired a confirmed association.
    pub association_expirations: u64,
    /// First selected peer loss, retained without a queue or later replacement.
    /// Full physical TRANSPORT loss remains the separate transport_losses fact.
    pub first_peer_loss: Option<PeerLoss>,
    /// Late returned credits consumed for retired/absent peer generations.
    pub late_send_credits: u64,
}
fn inc(v: &mut u64) {
    *v = v.saturating_add(1);
}

/// Persistent CORE host. Key and service-info owners outlive it; replacing the
/// identity requires closing/dropping this host before importing a new identity.
/// Canceling `drive` retains all original sockets, partial cursors and queues.
pub struct Host<'a> {
    identity: &'a Identity,
    info: &'a [u8],
    class: PeerClass,
    order: WordOrder,
    limits: Limits,
    options: ServiceOptions,
    unix_access: UnixAccess,
    clock: Arc<dyn RuntimeClock>,
    clock_subscription: Option<Box<dyn ClockSubscription>>,
    clock_revision: u64,
    applications: Applications,
    clients: BTreeMap<u64, Link>,
    next_client: u64,
    accept: AcceptState,
    endpoint: Endpoint,
    connecting: Option<ConnectionAttempt>,
    transport: Option<Link>,
    retry_at: u64,
    connect_now: bool,
    round: u64,
    peers: BTreeMap<PeerId, Peer<'a>>,
    retired_credits: BTreeMap<PeerId, u32>,
    timer: Option<Pin<Box<Sleep>>>,
    output: Vec<u8>,
    plain: Zeroizing<Vec<u8>>,
    stopped: bool,
    report: Report,
}
impl<'a> Host<'a> {
    /// Construct a service with an actual initialized identity and a reusable
    /// official CLIENT endpoint. This starts no process and performs no I/O.
    pub fn new(
        identity: &'a Identity,
        info: &'a [u8],
        class: PeerClass,
        endpoint: Endpoint,
        limits: Limits,
        options: ServiceOptions,
    ) -> Result<Self, HostError> {
        Self::with_clock(
            identity,
            info,
            class,
            endpoint,
            limits,
            options,
            Arc::new(SystemClock),
        )
    }
    /// Join the caller's canonical process time source. This owner reserves one
    /// independent adjustment waiter. Original absolute protocol deadlines are
    /// preserved across clock rollback, revision and canceled drive futures.
    pub fn with_clock(
        identity: &'a Identity,
        info: &'a [u8],
        class: PeerClass,
        endpoint: Endpoint,
        limits: Limits,
        options: ServiceOptions,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, HostError> {
        if info.contains(&0) {
            return Err(Error::InvalidInput.into());
        }
        if limits.max_clients == 0
            || limits.max_peers == 0
            || limits.max_pending_bytes < 65535
            || limits.max_pending_frames == 0
            || limits.max_reserved_bytes < 65535
            || limits.io_slice_bytes == 0
            || info.len() > 830
            || class.0 > u32::from(u16::MAX)
        {
            return Err(Error::Capacity.into());
        }
        let order = if cfg!(target_endian = "little") {
            WordOrder::Little
        } else {
            WordOrder::Big
        };
        let class_order = if cfg!(target_endian = "little") {
            ClassOrder::Little
        } else {
            ClassOrder::Big
        };
        let clock_subscription = clock.subscribe().map_err(HostError::Clock)?;
        let sample = clock.sample().map_err(HostError::Clock)?;
        Ok(Self {
            identity,
            info,
            class,
            order,
            limits,
            options,
            unix_access: UnixAccess::default(),
            clock,
            clock_subscription: Some(clock_subscription),
            clock_revision: sample.revision,
            applications: Applications::new(
                PeerId(*identity.public_key().as_bytes()),
                class,
                class_order,
                limits,
            ),
            clients: BTreeMap::new(),
            next_client: 0,
            accept: AcceptState::default(),
            endpoint,
            connecting: None,
            transport: None,
            retry_at: sample.now.as_micros(),
            connect_now: true,
            round: 0,
            peers: BTreeMap::new(),
            retired_credits: BTreeMap::new(),
            timer: None,
            output: vec![0; 65535],
            plain: Zeroizing::new(vec![0; 65535]),
            stopped: false,
            report: Report::default(),
        })
    }
    /// Exact public initialized identity; this never exports a private seed.
    #[must_use]
    pub fn identity(&self) -> PeerId {
        PeerId(*self.identity.public_key().as_bytes())
    }
    /// Copy public cumulative counters.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Set the Unix credential policy before the first application or monitor
    /// admission. Constructors default to neither UID nor GID matching. The
    /// policy cannot change after any client was admitted, even after it closes.
    /// UID matching takes precedence over GID and supplementary group matching.
    pub fn set_unix_access(&mut self, access: UnixAccess) -> Result<(), HostError> {
        if self.stopped {
            return Err(Error::Closed.into());
        }
        if self.next_client != 0 {
            return Err(Error::Conflict.into());
        }
        self.unix_access = access;
        Ok(())
    }
    /// Attach an already accepted, initialized physical client stream. Configured
    /// Unix credential matching is enforced on this original connection; a
    /// mismatch closes it and returns PermissionDenied. Native credential or
    /// group lookup errors remain original I/O errors. For TCP embedding, the
    /// caller supplies address ACL policy before transferring the connection.
    pub fn attach_client(&mut self, connection: Connection) -> Result<u64, HostError> {
        if self.stopped {
            return Err(Error::Closed.into());
        }
        if (self.unix_access.match_uid || self.unix_access.match_gid)
            && connection.is_unix()
            && !self.unix_access.allows(&connection)?
        {
            return Err(Error::PermissionDenied.into());
        }
        self.attach_admitted_client(connection)
    }
    // Only the original connection which passed this host's Unix policy or the
    // canonical listener's address policy reaches the application router.
    fn attach_admitted_client(&mut self, connection: Connection) -> Result<u64, HostError> {
        let id = self.next_client.checked_add(1).ok_or(Error::Capacity)?;
        let link = Link::new(
            connection,
            self.limits.max_pending_bytes,
            self.limits.max_pending_frames,
            self.limits.io_slice_bytes,
        )?;
        self.applications.attach(id)?;
        self.clients.insert(id, link);
        self.next_client = id;
        inc(&mut self.report.accepted);
        Ok(id)
    }
    /// Adopt one original connected TRANSPORT MQ and admit its official START.
    /// This establishes no peer authentication. Duplicate attachment is refused;
    /// the refused newly supplied descriptor closes without replacing the owner.
    pub fn attach_transport(&mut self, connection: Connection) -> Result<(), HostError> {
        if self.stopped {
            return Err(Error::Closed.into());
        }
        if self.transport.is_some() || self.connecting.is_some() {
            return Err(Error::Conflict.into());
        }
        let mut link = Link::new(
            connection,
            self.limits.max_pending_bytes,
            self.limits.max_pending_frames,
            self.limits.io_slice_bytes,
        )?;
        link.control_reserve(
            self.limits
                .max_peers
                .checked_mul(tr::RECEIVE_WINDOW)
                .and_then(|n| n.checked_add(2))
                .ok_or(Error::Capacity)?,
        )?;
        let n = TransportRequest::Start(tr::Start::new(Some(tr::PeerId(self.identity().0)), true))
            .encode(&mut self.output)?;
        link.enqueue(self.output[..n].to_vec())?;
        self.transport = Some(link);
        Ok(())
    }
    /// Immediately close all original streams, discard pending work and drop all
    /// peer session keys. Repeated shutdown does not create completion events.
    pub fn shutdown(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.connecting = None;
        self.transport = None;
        self.timer = None;
        self.clock_subscription = None;
        self.peers.clear();
        self.retired_credits.clear();
        self.plain.fill(0);
        self.output.fill(0);
        self.report.closed = self.report.closed.saturating_add(self.clients.len() as u64);
        self.clients.clear();
        self.applications.clear();
    }
    fn lose_transport(&mut self, now: u64) {
        self.transport = None;
        self.connecting = None;
        self.retry_at = now.saturating_add(1_000_000);
        self.connect_now = false;
        inc(&mut self.report.transport_losses);
        for peer in self.peers.keys().copied().collect::<Vec<_>>() {
            self.applications.remove_peer(peer);
        }
        self.peers.clear();
        self.retired_credits.clear();
    }
    fn peer_loss(&mut self, loss: PeerLoss) {
        match loss.origin {
            PeerLossOrigin::TransportDisconnected => inc(&mut self.report.transport_disconnections),
            PeerLossOrigin::AssociationExpired => inc(&mut self.report.association_expirations),
        }
        if self.report.first_peer_loss.is_none() {
            self.report.first_peer_loss = Some(loss);
        }
    }
    fn peer_state(&mut self, id: PeerId) {
        let p = &self.peers[&id];
        let state = match p.session.phase() {
            Phase::Ready => 0,
            Phase::AwaitInitiator => 2,
            Phase::InitiatorHelloSent => 1,
            Phase::ResponderHelloSent => 4,
            Phase::InitiatorDoneSent => 6,
            Phase::Established => {
                if gnunet_core::wire::is_initiator(
                    self.identity.public_key().as_bytes(),
                    &id.0,
                    self.order,
                ) {
                    7
                } else {
                    8
                }
            }
        };
        let deadline = p.session.next_deadline();
        let class = p
            .session
            .peer_class()
            .map_or(PeerClass::UNKNOWN, |c| PeerClass(u32::from(c)));
        let established = p.session.established();
        let changed = p.state != state || p.timeout != deadline;
        let timeout = deadline;
        if changed {
            if let Some(p) = self.peers.get_mut(&id) {
                p.state = state;
                p.timeout = deadline;
            }
            self.applications.set_peer(
                id,
                PeerState {
                    class,
                    state,
                    timeout,
                    established,
                },
            );
        }
    }
    fn crypto_event(&mut self, id: PeerId, event: CryptoEvent) -> Result<(), HostError> {
        let outgoing = match event {
            CryptoEvent::Send(n) | CryptoEvent::Established(n) => n,
            _ => 0,
        };
        if outgoing != 0 {
            self.peers
                .get_mut(&id)
                .ok_or(Error::Stale)?
                .enqueue(self.output[..outgoing].to_vec(), 0);
        }
        match event {
            CryptoEvent::Established(_) => inc(&mut self.report.authenticated),
            CryptoEvent::Payload(n) => {
                self.applications
                    .traffic(Direction::Inbound, id, &self.plain[..n])?;
                inc(&mut self.report.payloads);
            }
            CryptoEvent::Lost => {
                let peer = self.peers.get_mut(&id).ok_or(Error::Stale)?;
                peer.ciphertexts.clear();
                peer.bytes = 0;
            }
            _ => {}
        }
        self.peer_state(id);
        Ok(())
    }
    fn transport_frame(&mut self, bytes: &[u8], now: u64) -> Result<bool, HostError> {
        match TransportResponse::decode(bytes)? {
            TransportResponse::Connected(tr::PeerId(id)) => {
                let id = PeerId(id);
                if id == self.identity() || self.peers.contains_key(&id) {
                    return Err(Error::Malformed.into());
                }
                if self.peers.len() >= self.limits.max_peers {
                    return Err(Error::Capacity.into());
                }
                let session = Session::with_class(
                    self.identity,
                    EddsaPublicKey::from_bytes(id.0),
                    self.order,
                    self.info,
                    self.class.0 as u16,
                )?;
                self.peers.insert(
                    id,
                    Peer {
                        session,
                        credits: tr::SEND_WINDOW,
                        ciphertexts: VecDeque::new(),
                        bytes: 0,
                        state: u32::MAX,
                        timeout: 0,
                    },
                );
                self.peer_state(id);
            }
            TransportResponse::Disconnected(tr::PeerId(id)) => {
                let id = PeerId(id);
                if let Some(peer) = self.peers.get(&id)
                    && peer.session.established()
                {
                    let loss = peer.loss(id, PeerLossOrigin::TransportDisconnected, now);
                    self.peer_loss(loss);
                }
                self.applications.remove_peer(id);
                if let Some(peer) = self.peers.remove(&id) {
                    let cancelled=self.transport.as_mut().map_or(0,|link|link.cancel_unwritten(|bytes|matches!(TransportRequest::decode(bytes),Ok(TransportRequest::Send {peer,..}) if peer.0==id.0)));
                    let owed = tr::SEND_WINDOW
                        .checked_sub(peer.credits)
                        .and_then(|n| n.checked_sub(u32::try_from(cancelled).ok()?))
                        .ok_or(Error::Malformed)?;
                    if owed > 0 {
                        if !self.retired_credits.contains_key(&id)
                            && self.retired_credits.len() >= self.limits.max_pending_frames
                        {
                            return Err(Error::Capacity.into());
                        }
                        let debt = self.retired_credits.entry(id).or_default();
                        *debt = debt.checked_add(owed).ok_or(Error::Capacity)?;
                    }
                }
            }
            TransportResponse::SendCredit(tr::PeerId(id)) => {
                let id = PeerId(id);
                if let Some(debt) = self.retired_credits.get_mut(&id) {
                    *debt -= 1;
                    if *debt == 0 {
                        self.retired_credits.remove(&id);
                    }
                    inc(&mut self.report.late_send_credits);
                    return Ok(true);
                }
                let Some(peer) = self.peers.get_mut(&id) else {
                    inc(&mut self.report.late_send_credits);
                    return Ok(true);
                };
                if peer.credits >= tr::SEND_WINDOW {
                    return Err(Error::Malformed.into());
                }
                peer.credits += 1;
            }
            TransportResponse::Received {
                peer: tr::PeerId(id),
                message,
            } => {
                let id = PeerId(id);
                let peer = self.peers.get_mut(&id).ok_or(Error::Malformed)?;
                // Data cannot exhaust all response storage. If even the bounded
                // control reserve is exhausted, retire this MQ rather than hold
                // a RECV forever in front of its own later SEND_OK credits.
                if !peer.control_capacity(self.limits)
                    || !self
                        .transport
                        .as_ref()
                        .is_some_and(|t| t.control_capacity(40))
                {
                    return Err(Error::Capacity.into());
                }
                self.transport
                    .as_mut()
                    .ok_or(Error::Closed)?
                    .reserve(40, true)?;
                match peer.session.receive_classified(
                    now,
                    message,
                    &mut Random,
                    &mut self.output,
                    &mut self.plain,
                ) {
                    Ok(event) => self.crypto_event(id, event)?,
                    // The plaintext epoch is not AEAD-protected. Only an
                    // explicit rejection from its record-policy boundary joins
                    // this discard path; a local Stale/TooLarge stays a failure.
                    Err(ReceiveError::RejectedEpoch(_)) => {
                        inc(&mut self.report.rejected_records);
                        inc(&mut self.report.rejected_epoch);
                    }
                    Err(ReceiveError::Failed(Error::Authentication)) => {
                        inc(&mut self.report.rejected_records);
                        inc(&mut self.report.rejected_authentication);
                    }
                    Err(ReceiveError::Failed(Error::Replay)) => {
                        inc(&mut self.report.rejected_records);
                        inc(&mut self.report.rejected_replay);
                    }
                    Err(ReceiveError::Failed(Error::Truncated)) => {
                        inc(&mut self.report.rejected_records);
                        inc(&mut self.report.rejected_truncated);
                    }
                    Err(ReceiveError::Failed(Error::Malformed)) => {
                        inc(&mut self.report.rejected_records);
                        inc(&mut self.report.rejected_malformed);
                    }
                    Err(ReceiveError::Failed(Error::InvalidInput)) => {
                        inc(&mut self.report.rejected_records);
                        inc(&mut self.report.rejected_invalid_input);
                    }
                    Err(ReceiveError::Failed(Error::Unsupported)) => {
                        inc(&mut self.report.rejected_records);
                        inc(&mut self.report.rejected_unsupported);
                    }
                    Err(ReceiveError::Failed(e)) => return Err(e.into()),
                }
                self.plain.fill(0);
                let n = TransportRequest::ReceiveContinue {
                    peer: tr::PeerId(id.0),
                    increase: 1,
                }
                .encode(&mut self.output)?;
                self.transport
                    .as_mut()
                    .ok_or(Error::Closed)?
                    .enqueue_control(self.output[..n].to_vec())?;
                inc(&mut self.report.receive_credits);
            }
        }
        Ok(true)
    }
    fn maintenance(&mut self, now: u64) -> Result<bool, HostError> {
        let mut work = false;
        self.applications.solicit()?;
        for id in self.peers.keys().copied().collect::<Vec<_>>() {
            let p = self.peers.get_mut(&id).ok_or(Error::Stale)?;
            if (p.session.phase() == Phase::Ready
                || (p.session.next_deadline() != u64::MAX && now >= p.session.next_deadline()))
                && p.control_capacity(self.limits)
            {
                let loss = p.loss(id, PeerLossOrigin::AssociationExpired, now);
                let event = p.session.tick(now, &mut Random, &mut self.output)?;
                if event == CryptoEvent::Lost {
                    self.peer_loss(loss);
                }
                self.crypto_event(id, event)?;
                work = true;
            }
        }
        let peers = &self.peers;
        let transport = &self.transport;
        let index = self.applications.find_submission(|s| {
            peers.get(&s.peer).is_some_and(|p| {
                p.session.established() && p.ciphertexts.is_empty() && p.credits > 0
            }) && transport
                .as_ref()
                .is_some_and(|t| t.capacity(s.messages.len() + 76))
        });
        if let Some(index) = index
            && let Some(s) = self.applications.submission(index)
        {
            let id = s.peer;
            let size = s.messages.len() + 76;
            // Reserve both immutable frame storage and the actual FIFO metadata
            // before consuming any sender nonce. Plaintext stays queued while a
            // peer lacks real TRANSPORT credit; no old-key ciphertext backlog.
            let mut frame = Vec::new();
            frame.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
            frame.resize(size, 0);
            self.transport
                .as_mut()
                .ok_or(Error::Closed)?
                .reserve(size, false)?;
            let p = self.peers.get_mut(&id).ok_or(Error::Stale)?;
            let n = p.session.send(now, &s.messages, &mut self.output)?;
            let n = TransportRequest::Send {
                peer: tr::PeerId(id.0),
                priority: s.priority,
                message: &self.output[..n],
            }
            .encode(&mut frame)?;
            frame.truncate(n);
            self.transport
                .as_mut()
                .ok_or(Error::Closed)?
                .enqueue(frame)?;
            p.credits -= 1;
            inc(&mut self.report.transport_sends);
            let accepted = self
                .applications
                .take_submission(index)
                .ok_or(Error::Stale)?;
            self.applications
                .traffic(Direction::Outbound, id, &accepted.messages)?;
            self.applications.solicit()?;
            work = true;
        }
        for id in self.peers.keys().copied().collect::<Vec<_>>() {
            let p = self.peers.get_mut(&id).ok_or(Error::Stale)?;
            let Some(cipher) = p.ciphertexts.front() else {
                continue;
            };
            if p.credits == 0
                || !self
                    .transport
                    .as_ref()
                    .is_some_and(|t| t.capacity(cipher.bytes.len() + 40))
            {
                continue;
            }
            let n = TransportRequest::Send {
                peer: tr::PeerId(id.0),
                priority: cipher.priority,
                message: &cipher.bytes,
            }
            .encode(&mut self.output)?;
            self.transport
                .as_mut()
                .ok_or(Error::Closed)?
                .enqueue(self.output[..n].to_vec())?;
            let sent = p.ciphertexts.pop_front().ok_or(Error::Stale)?;
            p.bytes -= sent.bytes.len();
            p.credits -= 1;
            inc(&mut self.report.transport_sends);
            work = true;
        }
        Ok(work)
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
    ) -> Poll<Result<(), HostError>> {
        if self.stopped {
            return Poll::Ready(Ok(()));
        }
        let Some(subscription) = &mut self.clock_subscription else {
            return Poll::Ready(Err(Error::Closed.into()));
        };
        match subscription.poll_changed(cx, self.clock_revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(HostError::Clock(e))),
            Poll::Ready(Ok(sample)) => self.clock_revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = match self.clock.sample() {
            Ok(s) => s,
            Err(e) => return Poll::Ready(Err(HostError::Clock(e))),
        };
        self.clock_revision = sample.revision;
        match subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(HostError::Clock(e))),
            Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
            Poll::Pending => {}
        }
        let now = sample.now.as_micros();
        let mut work = false;
        if self.transport.is_none()
            && self.connecting.is_none()
            && (self.connect_now || (self.retry_at != u64::MAX && now >= self.retry_at))
        {
            self.connecting = Some(self.endpoint.attempt(self.round));
            self.connect_now = false;
        }
        if let Some(attempt) = &mut self.connecting
            && let Poll::Ready(result) = Pin::new(attempt).poll(cx)
        {
            self.connecting = None;
            self.round = match self.round.checked_add(1) {
                Some(v) => v,
                None => return Poll::Ready(Err(Error::Capacity.into())),
            };
            match result {
                Ok(connection) => {
                    if let Err(e) = self.attach_transport(connection) {
                        return Poll::Ready(Err(e));
                    }
                    work = true;
                }
                Err(_) => {
                    self.retry_at = now.saturating_add(1_000_000);
                    self.connect_now = false;
                }
            }
        }
        if self.accept.ready() {
            for listener in listeners {
                match listener.poll_canonical_connection(cx) {
                    Poll::Ready(Ok(accepted)) => {
                        let (connection, address, diagnostics) = accepted.into_parts();
                        for d in diagnostics {
                            observe(SocketEvent::Diagnostic(d));
                        }
                        let allowed = match address {
                            PeerAddress::Tcp(a) => self.options.access.allows(a.ip()),
                            PeerAddress::Unix => match self.unix_access.allows(&connection) {
                                Ok(allowed) => allowed,
                                Err(error) => {
                                    // Close this original, still unadmitted socket.
                                    // Preserve the native cause without passing a
                                    // credential lookup through accept backoff.
                                    drop(connection);
                                    return Poll::Ready(Err(error.into()));
                                }
                            },
                        };
                        if !allowed {
                            drop(connection);
                        } else if self.attach_admitted_client(connection).is_err() {
                            // Resource refusal before application ownership.
                        }
                        work = true;
                    }
                    Poll::Ready(Err(e)) => {
                        observe(self.accept.failed(e));
                    }
                    Poll::Pending => {}
                }
            }
        }
        if let Some(link) = &mut self.transport {
            let tx = link.poll_tx(cx);
            let rx = link.poll_rx(cx);
            if matches!(tx, Poll::Ready(Err(_))) || matches!(rx, Poll::Ready(Err(_))) {
                self.lose_transport(now);
                work = true;
            } else {
                work |= tx.is_ready() || rx.is_ready();
            }
        }
        if let Some(bytes) = self
            .transport
            .as_ref()
            .and_then(Link::frame)
            .map(<[u8]>::to_vec)
        {
            match self.transport_frame(&bytes, now) {
                Ok(true) => {
                    if let Some(t) = &mut self.transport {
                        t.release();
                    }
                    work = true;
                }
                Ok(false) => {}
                Err(_) => {
                    self.lose_transport(now);
                    work = true;
                }
            }
        }
        match self.maintenance(now) {
            Ok(w) => work |= w,
            Err(e) => return Poll::Ready(Err(e)),
        };
        for id in self.clients.keys().copied().collect::<Vec<_>>() {
            if !self.applications.alive(id) {
                self.close_client(id);
                work = true;
                continue;
            }
            let mut failed = false;
            if let Some(link) = self.clients.get_mut(&id) {
                if let Some(bytes) = self.applications.output(id)
                    && link.capacity(bytes.len())
                {
                    if let Some(bytes) = self.applications.take_output(id)
                        && link.enqueue(bytes).is_err()
                    {
                        failed = true;
                    }
                    work = true;
                }
                let tx = link.poll_tx(cx);
                let rx = link.poll_rx(cx);
                failed |= matches!(tx, Poll::Ready(Err(_))) || matches!(rx, Poll::Ready(Err(_)));
                work |= tx.is_ready() || rx.is_ready();
            }
            if failed {
                self.close_client(id);
                continue;
            }
            // Applications borrow the original complete frame from the disjoint
            // client link. Backpressure retains that frame without another copy.
            if let Some(bytes) = self.clients.get(&id).and_then(Link::frame) {
                match self.applications.request(id, bytes) {
                    Ok(()) => {
                        if let Some(link) = self.clients.get_mut(&id) {
                            link.release();
                        }
                        inc(&mut self.report.requests);
                        work = true;
                    }
                    Err(Error::WouldBlock) => {}
                    Err(Error::Unsupported) if self.options.tolerant && unknown_request(bytes) => {
                        if let Some(link) = self.clients.get_mut(&id) {
                            link.release();
                        }
                        work = true;
                    }
                    Err(_) => {
                        self.close_client(id);
                        work = true;
                    }
                }
            }
        }
        let mut target = u64::MAX;
        if self.transport.is_none() && self.connecting.is_none() {
            target = target.min(self.retry_at);
        }
        for p in self.peers.values() {
            if p.control_capacity(self.limits) {
                target = target.min(p.session.next_deadline());
            }
        }
        let wait = if target == u64::MAX {
            Duration::from_secs(60)
        } else {
            Duration::from_micros(target.saturating_sub(now)).min(Duration::from_secs(60))
        };
        let deadline = match Instant::now().checked_add(wait) {
            Some(at) => at,
            None => return Poll::Ready(Err(Error::Overflow.into())),
        };
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        timer.as_mut().reset(deadline);
        if timer.as_mut().poll(cx).is_ready() || work {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    fn close_client(&mut self, id: u64) {
        if self.clients.remove(&id).is_some() {
            self.applications.remove(id);
            self.accept.client_closed();
            inc(&mut self.report.closed);
        }
    }
    /// Drive the original owner until explicit shutdown or a terminal local
    /// failure. Dropping this future cancels only the wait, preserving all I/O.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        mut observe: impl FnMut(SocketEvent),
    ) -> Result<(), HostError> {
        poll_fn(|cx| self.poll(cx, listeners, &mut observe)).await
    }
}
fn unknown_request(bytes: &[u8]) -> bool {
    gnunet_wire::official::Frame::decode(bytes)
        .is_ok_and(|f| !matches!(f.header().message_type().value(), 64 | 74 | 76 | 78))
}
