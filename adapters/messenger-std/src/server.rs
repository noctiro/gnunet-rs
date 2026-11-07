//! Actual accepted IPC, CADET room transports and original PILS purpose12 jobs.
use crate::{EndpointSource, cadet, carrier, core};
use core::wire::{self, Request, Response, body::Body, envelope::Kind, padding};
use core::{Binding, Core, Hash, OwnedBytes, PublicKey, ReceiveMeta, Room, Source, SourceRole};
use gnunet_crypto::Entropy;
use gnunet_pils::client as pc;
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as Fault;
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod application;
mod identity;
mod lifecycle;
mod persistence;
mod relay;
mod rooms;
mod signer;
mod statistics;
mod types;
pub use statistics::Statistics;
pub use types::*;
#[derive(Clone, Copy, Eq, PartialEq)]
struct Origin {
    client: u64,
    sequence: u64,
}
#[derive(Clone, Copy)]
enum WrittenAction<'c> {
    None,
    Detach(Source<'c>),
}
struct Output<'c> {
    sequence: u64,
    total: usize,
    sent: usize,
    until: Instant,
    action: WrittenAction<'c>,
    task: Option<u64>,
}
struct Notice<'c> {
    frame: OwnedFrame,
    action: WrittenAction<'c>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum LeasePhase {
    Opening,
    Entering,
    Active,
    Closing,
}
#[derive(Clone, Copy)]
struct EntryInput {
    key: Hash,
    door: [u8; 32],
    target: Option<EntryTarget>,
    until: Instant,
}
#[derive(Clone, Copy)]
enum EntryTarget {
    Local,
    Remote([u8; 32]),
}
impl EntryTarget {
    fn door(self, local: [u8; 32]) -> [u8; 32] {
        match self {
            Self::Local => local,
            Self::Remote(peer) => peer,
        }
    }
}
#[derive(Clone, Copy)]
struct OpenInput {
    key: Hash,
    until: Instant,
}
#[derive(Clone, Copy)]
struct PendingOpen<'c> {
    request: OpenInput,
    port: Option<cadet::Port<'c>>,
}
#[derive(Clone, Copy)]
struct PendingEntry<'c> {
    request: EntryInput,
    target: EntryTarget,
    // Core Source includes its original generation, unlike a reusable tunnel row.
    source: Option<Source<'c>>,
}
struct Lease<'c> {
    room: Room<'c>,
    source: Source<'c>,
    phase: LeasePhase,
    door: [u8; 32],
    entry_local: bool,
    entry: Option<Source<'c>>,
    pending_entry: Option<PendingEntry<'c>>,
    pending_open: Option<PendingOpen<'c>>,
    id_written: bool,
    counted: bool,
    bootstrap: usize,
    proposed_id: Option<core::ShortHash>,
    proposal_until: Option<Instant>,
    sync_until: Option<Instant>,
    until: Instant,
}
struct App<'c> {
    client: Client,
    io: Framed<Origin>,
    // Initial-idle bound ends at the first decoded request; CREATE grants no authority.
    has_request: bool,
    public: Option<PublicKey>,
    rooms: Vec<Lease<'c>>,
    controls: VecDeque<Notice<'c>>,
    output: Option<Output<'c>>,
    until: Instant,
    input_until: Option<Instant>,
    entry_input: Option<EntryInput>,
    open_input: Option<OpenInput>,
    entry_cursor: usize,
    read_first: bool,
}
struct RoomEntry<'c> {
    room: Room<'c>,
    key: Hash,
    signer: Source<'c>,
    port: Option<cadet::Port<'c>>,
    hosting: bool,
    closing: bool,
    announcement: Option<rooms::Announcement<'c>>,
    connections: Option<u32>,
}
struct Tunnel<'c> {
    room: Room<'c>,
    source: Source<'c>,
    channel: cadet::Channel<'c>,
    peer: [u8; 32],
    compatible: bool,
    info_queued: bool,
    // Local room/error/timeout revocation, distinct from physical remote loss.
    closing: bool,
    remote_closed: bool,
    bootstrap: usize,
    until: Instant,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Destination<'c> {
    App { client: u64, source: Source<'c> },
    Peer(cadet::Channel<'c>),
}
struct Task<'c> {
    sequence: u64,
    room: Room<'c>,
    hash: Hash,
    destination: Destination<'c>,
    recent: bool,
    requested: bool,
    queued: bool,
    until: Instant,
}
struct MessageWork<'c> {
    room: Room<'c>,
    hash: Hash,
    exclude: Option<cadet::Channel<'c>>,
    recent: bool,
    fanned: bool,
}
struct MissingPeer<'c> {
    room: Room<'c>,
    peer: [u8; 32],
}
struct Retrieval<'c> {
    room: Room<'c>,
    hash: Hash,
    until: Instant,
}
struct Receive<'c> {
    input: cadet::Received<'c>,
    // Original DATA admission attribution; a replacement tunnel never owns it.
    room: Room<'c>,
    source: Source<'c>,
    offset: usize,
    until: Instant,
}
struct PeerOutput<'c> {
    transmit: cadet::Transmit<'c>,
    sequence: u64,
    task: Option<u64>,
    retire: Option<cadet::Channel<'c>>,
    until: Instant,
}
struct ControlBudget<'c> {
    room: Room<'c>,
    kind: Kind,
    operation: core::Operation<'c>,
    until: Instant,
}
#[derive(Clone, Copy)]
struct OriginalSign<'p> {
    operation: pc::OperationId<'p>,
    identity: pc::Identity<'p>,
}
#[derive(Clone, Copy)]
enum SignPhase<'p> {
    Draft,
    Pending(OriginalSign<'p>),
    Verified(OriginalSign<'p>),
    PreparedCore(OriginalSign<'p>),
    Committed {
        original: OriginalSign<'p>,
        hash: Hash,
    },
    Cancelling(OriginalSign<'p>),
}
impl<'p> SignPhase<'p> {
    fn original(self) -> Option<OriginalSign<'p>> {
        match self {
            Self::Draft => None,
            Self::Pending(original)
            | Self::Verified(original)
            | Self::PreparedCore(original)
            | Self::Committed { original, .. }
            | Self::Cancelling(original) => Some(original),
        }
    }
}
struct Sign<'c, 'p> {
    room: Room<'c>,
    binding: Binding<'c>,
    peer: [u8; 32],
    frame: OwnedBytes,
    phase: SignPhase<'p>,
    until: Instant,
    hard: Instant,
}
/// One caller-driven daemon. All app, channel, output and signing capacities are
/// fixed metadata pools; variable frames allocate only their actual lengths.
/// External CADET and PILS are dependencies, not a claim of a complete GNUnet node.
pub struct Server<'c, 'slots, 'p, E: Entropy, const O: usize = 16> {
    core: Core<'c>,
    history: Option<crate::history::History>,
    layouts: crate::layout::Policy,
    limits: Limits,
    ports: Ports,
    entropy: E,
    cadet: cadet::Client<'c, 'slots>,
    pils: pils::Client<'p, O>,
    apps: Vec<Option<App<'c>>>,
    rooms: Vec<Option<RoomEntry<'c>>>,
    tunnels: Vec<Option<Tunnel<'c>>>,
    tasks: Vec<Option<Task<'c>>>,
    messages: Vec<Option<MessageWork<'c>>>,
    retrievals: Vec<Option<Retrieval<'c>>>,
    misses: Vec<Option<MissingPeer<'c>>>,
    signs: Vec<Option<Sign<'c, 'p>>>,
    control_budgets: Vec<Option<ControlBudget<'c>>>,
    received: Vec<Option<Receive<'c>>>,
    receive_cursor: usize,
    peer_output: Option<PeerOutput<'c>>,
    cadet_pending: Option<(cadet::Transmit<'c>, Instant)>,
    identity: identity::LocalIdentity<'p>,
    domain: Rc<()>,
    next_client: u64,
    next_sequence: u64,
    accept: AcceptState,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    last_now: u64,
    timer: Pin<Box<Sleep>>,
    class: usize,
    app_cursor: usize,
    task_cursor: usize,
    room_cursor: usize,
    listener_cursor: usize,
    shutdown: Option<ShutdownMode>,
    cleanup: Option<Error>,
    closed: bool,
    yield_due: bool,
    report: Report,
    statistics: Statistics,
}
fn slots<T>(n: usize) -> Result<Vec<Option<T>>, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    v.resize_with(n, || None);
    Ok(v)
}
fn vector(n: usize) -> Result<Vec<u8>, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    v.resize(n, 0);
    Ok(v)
}
fn busy(e: &Error) -> bool {
    matches!(
        e,
        Error::Protocol(Fault::Capacity | Fault::WouldBlock | Fault::NotReady)
            | Error::Core(core::Error::Protocol(
                Fault::Capacity | Fault::WouldBlock | Fault::NotReady
            ))
    )
}
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    /// Borrow caller-owned CADET metadata/identity brands and the one shared PILS
    /// identity domain. Construction creates no socket/task/resolver. Entropy is
    /// an explicitly supplied real provider, never a seed file.
    /// The independent caller-owned core instance outlives all retained room,
    /// source and provider bindings; no global atomic identity is required.
    #[expect(
        clippy::too_many_arguments,
        reason = "Independent caller storage and original provider identity brands must remain explicit"
    )]
    pub fn new(
        core_instance: &'c mut core::Instance,
        cadet_instance: &'c mut cadet::Instance,
        pils_instance: &'p mut pc::Instance,
        port_slots: &'slots mut [cadet::PortSlot],
        channel_slots: &'slots mut [cadet::ChannelSlot],
        core_limits: core::Limits,
        limits: Limits,
        ports: Ports,
        entropy: E,
    ) -> Result<Self, Error> {
        limits.validate(O)?;
        if port_slots.len() < limits.rooms
            || channel_slots.len() < limits.tunnels
            || core_limits.rooms < limits.rooms
            || !Arc::ptr_eq(&ports.clock, &ports.cadet.clock())
            || !Arc::ptr_eq(&ports.clock, &ports.pils.clock())
        {
            return Err(Fault::Conflict.into());
        }
        let subscription = ports.clock.subscribe()?;
        let core = Core::new(
            core_instance,
            core::Mode::Service,
            core_limits,
            limits.profile,
        )?;
        let cadet = cadet::Client::new(
            cadet_instance,
            ports.cadet.duplicate()?,
            port_slots,
            channel_slots,
            cadet::Limits {
                frame_bytes: 65535,
                io_slice_bytes: limits.io_slice_bytes,
                max_payload_bytes: 65523,
                max_send_credit: 8,
            },
        )?;
        let pils = pils::Client::new(
            pils_instance,
            ports.pils.duplicate()?,
            limits.pils_profile,
            pils::Limits {
                pending_operations: limits.signatures,
                frame_bytes: 65535,
                io_slice_bytes: limits.io_slice_bytes,
            },
            gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 4096,
            },
        )?;
        let layouts = crate::layout::Policy::new(
            core_limits
                .contacts
                .checked_add(core_limits.rooms)
                .and_then(|n| n.checked_add(limits.tunnels))
                .ok_or(Fault::Overflow)?,
            limits.peer_profile,
            limits.profile,
            Some(limits.profile),
        )?;
        Ok(Self {
            core,
            history: None,
            layouts,
            limits,
            ports,
            entropy,
            cadet,
            pils,
            apps: slots(limits.clients)?,
            rooms: slots(limits.rooms)?,
            tunnels: slots(limits.tunnels)?,
            tasks: slots(limits.deliveries)?,
            messages: slots(limits.deliveries)?,
            retrievals: slots(limits.deliveries)?,
            misses: slots(limits.tunnels)?,
            signs: slots(limits.signatures)?,
            control_budgets: slots(limits.signatures)?,
            received: slots(limits.tunnels)?,
            receive_cursor: 0,
            peer_output: None,
            cadet_pending: None,
            identity: identity::LocalIdentity::Awaiting { observed: None },
            domain: Rc::new(()),
            next_client: 0,
            next_sequence: 0,
            accept: AcceptState::default(),
            subscription,
            revision: 0,
            last_now: 0,
            timer: Box::pin(tokio::time::sleep(Duration::from_secs(3600))),
            class: 0,
            app_cursor: 0,
            task_cursor: 0,
            room_cursor: 0,
            listener_cursor: 0,
            shutdown: None,
            cleanup: None,
            closed: false,
            yield_due: false,
            report: Report::default(),
            statistics: Statistics::default(),
        })
    }
    /// Actual current local public identity, only after verified original PILS HELLO.
    #[must_use]
    pub fn local_peer(&self) -> Option<[u8; 32]> {
        self.current_peer()
    }
    /// Actual shared CADET native MQ attachment, no end-to-end channel claim.
    #[must_use]
    pub fn transport_ready(&self) -> bool {
        self.cadet.epoch().is_some()
    }
    /// Current local outcomes; no remote delivery/persistent history claim.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    fn room_index(&self, room: Room<'c>) -> Result<usize, Fault> {
        self.rooms
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.room == room))
            .ok_or(Fault::StaleGeneration)
    }
    fn until(&self) -> Result<Instant, Fault> {
        Instant::now()
            .checked_add(self.limits.operation_lifetime)
            .ok_or(Fault::Overflow)
    }
    fn sequence(&mut self) -> Result<u64, Fault> {
        self.next_sequence = self.next_sequence.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(self.next_sequence)
    }
    fn deadline(&self) -> Result<u64, Fault> {
        self.last_now
            .checked_add(
                u64::try_from(self.limits.operation_lifetime.as_micros())
                    .map_err(|_| Fault::Overflow)?,
            )
            .ok_or(Fault::Overflow)
    }
    fn response(&self, r: Response<'_>) -> Result<OwnedFrame, Error> {
        let mut bytes = vector(r.encoded_len()?)?;
        r.encode(self.limits.profile, &mut bytes)?;
        Ok(OwnedFrame::new(bytes))
    }
    fn notice(
        &mut self,
        row: usize,
        r: Response<'_>,
        action: WrittenAction<'c>,
    ) -> Result<(), Error> {
        self.notice_before(row, r, action, None)
    }
    fn notice_before(
        &mut self,
        row: usize,
        r: Response<'_>,
        action: WrittenAction<'c>,
        until: Option<Instant>,
    ) -> Result<(), Error> {
        let frame = self.response(r)?;
        if until.is_some_and(|until| Instant::now() >= until) {
            return Err(Fault::Deadline.into());
        }
        let app = self.apps[row].as_mut().ok_or(Fault::StaleGeneration)?;
        if app.controls.len() == self.limits.controls {
            return Err(Fault::Capacity.into());
        }
        app.controls.push_back(Notice { frame, action });
        Ok(())
    }
    fn room_fields(
        &self,
        room: Room<'c>,
        door: &[u8; 32],
    ) -> Result<(Hash, Hash, Hash, [u8; 32]), Error> {
        let r = self.rooms[self.room_index(room)?]
            .as_ref()
            .ok_or(Fault::Stale)?;
        let s = self.core.service_state(room)?;
        Ok((r.key, s.previous, s.epoch, *door))
    }
    fn track(
        &mut self,
        room: Room<'c>,
        hash: Hash,
        exclude: Option<cadet::Channel<'c>>,
        recent: bool,
    ) -> Result<(), Fault> {
        if self
            .messages
            .iter()
            .flatten()
            .any(|m| m.room == room && m.hash == hash)
        {
            return Ok(());
        }
        let row = self
            .messages
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        self.messages[row] = Some(MessageWork {
            room,
            hash,
            exclude,
            recent,
            fanned: false,
        });
        Ok(())
    }
    fn drain_events(&mut self) {
        while let Some(event) = self.core.pop_event() {
            if matches!(
                event,
                core::Event::RoomChanged(..)
                    | core::Event::MemberChanged(..)
                    | core::Event::ContactChanged(..)
                    | core::Event::MessageChanged(..)
                    | core::Event::EpochChanged(..)
                    | core::Event::SubscriptionChanged(..)
            ) && let Some(history) = &mut self.history
                && let Err(e) = history.changed()
            {
                self.remember(e.into());
            }
        }
    }
}
