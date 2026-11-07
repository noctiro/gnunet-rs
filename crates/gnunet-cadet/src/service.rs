//! Actual application-facing CADET service state, separate from the CLIENT SDK.
//!
//! Accepted MQ generations, logical channels, shared retained payloads and real
//! output effects have different opaque tokens. No peer connection, port proof,
//! peer DATA_ACK or physical write is synthesized by this service owner.
use crate::peer;
use core::{fmt, ptr};
use gnunet_types::Error;
use gnunet_wire::official::cadet::{CLIENT_CHANNEL_BOUNDARY, Request, Response};

/// Distinct exclusively borrowed service identity, without allocation.
#[derive(Default)]
pub struct Instance {
    marker: u8,
}
impl Instance {
    /// Empty owner identity.
    #[must_use]
    pub const fn new() -> Self {
        Self { marker: 0 }
    }
}
#[derive(Clone, Copy)]
struct Brand<'a>(&'a Instance);
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0, other.0)
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _marker = self.0.marker;
        f.write_str("CadetApplicationService")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientRef {
    slot: usize,
    serial: u64,
}
/// One actual accepted original application MQ generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Client<'a> {
    brand: Brand<'a>,
    reference: ClientRef,
}
impl Client<'_> {
    /// Diagnostic original MQ generation, never a protocol field.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.reference.serial
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChannelRef {
    slot: usize,
    serial: u64,
    client: ClientRef,
    wire: u32,
}
/// One original local application channel on one exact accepted MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel<'a> {
    brand: Brand<'a>,
    reference: ChannelRef,
}
impl<'a> Channel<'a> {
    /// Actual local channel integer, not generation authority.
    #[must_use]
    pub const fn wire_id(self) -> u32 {
        self.reference.wire
    }
    /// Original accepted application MQ.
    #[must_use]
    pub const fn client(self) -> Client<'a> {
        Client {
            brand: self.brand,
            reference: self.reference.client,
        }
    }
}
/// Logical port registration owned by one actual accepted application MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Port<'a> {
    brand: Brand<'a>,
    slot: usize,
    serial: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MessageRef {
    slot: usize,
    serial: u64,
}
/// One original shared-pool payload generation, not a wire request identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    brand: Brand<'a>,
    reference: MessageRef,
}
/// Actual local output kind; all use the ordinary official IPC structures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputKind {
    /// Announce a real incoming application channel.
    Incoming,
    /// Notify actual channel retirement.
    Destroy,
    /// Grant exactly one local source capacity credit.
    Credit,
    /// One original complete application-message string.
    Data,
}
/// Original immutable frame token, including its exact target MQ generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output<'a> {
    brand: Brand<'a>,
    client: ClientRef,
    serial: u64,
    channel: ChannelRef,
    kind: OutputKind,
}
impl<'a> Output<'a> {
    /// Original exact native MQ target.
    #[must_use]
    pub const fn client(self) -> Client<'a> {
        Client {
            brand: self.brand,
            reference: self.client,
        }
    }
    /// Original channel generation represented by these frozen bytes.
    #[must_use]
    pub const fn channel(self) -> Channel<'a> {
        Channel {
            brand: self.brand,
            reference: self.channel,
        }
    }
    /// Original actual wire-message class, not remote-delivery evidence.
    #[must_use]
    pub const fn kind(self) -> OutputKind {
        self.kind
    }
}
/// Encoded original output borrowed from preallocated final native frame storage.
/// Freeze these exact bytes before any later service call can reuse that storage.
pub struct Prepared<'id, 'bytes> {
    output: Output<'id>,
    bytes: &'bytes [u8],
}
impl<'id, 'bytes> Prepared<'id, 'bytes> {
    /// Original physical output token.
    #[must_use]
    pub const fn output(&self) -> Output<'id> {
        self.output
    }
    /// Exact ordinary service-to-application IPC frame.
    #[must_use]
    pub const fn bytes(&self) -> &'bytes [u8] {
        self.bytes
    }
}
/// Actual original accepted-MQ loss facts; no output is replayed to another MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Loss<'id> {
    /// Original detached application source.
    pub client: Client<'id>,
    /// Original channel endpoints retired.
    pub channels: usize,
    /// Original pending immutable output, if any.
    pub pending: Option<Output<'id>>,
    /// Whether that original output was exposed.
    pub exposed: bool,
}
/// Explicit bounded service policy. It adds no private channel protocol flags.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// At most four locally granted pending application sends.
    pub window: u8,
    /// Largest complete loopback message string, at most 65523 bytes.
    pub loop_payload_bytes: usize,
    /// Largest whole remote channel payload, at most 64348 bytes.
    pub remote_payload_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            window: 4,
            loop_payload_bytes: 65523,
            remote_payload_bytes: 64348,
        }
    }
}
#[derive(Clone, Copy)]
struct ClientRecord<'id> {
    serial: u64,
    next_incoming: Option<u32>,
    pending: Option<Pending<'id>>,
    cursor: usize,
}
/// Caller-owned accepted-MQ metadata; no native transport is created here.
#[derive(Clone, Copy)]
pub struct ClientSlot<'id> {
    record: Option<ClientRecord<'id>>,
}
impl ClientSlot<'_> {
    /// Empty fixed metadata.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl Default for ClientSlot<'_> {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
struct PortRecord {
    serial: u64,
    client: ClientRef,
    hash: [u8; 64],
    // Current local identity projection. The logical registration and its
    // serial survive an identity cut; only this derived challenge changes.
    challenge: [u8; 64],
}
/// Caller-owned logical registration. Different clients may share a port;
/// duplicate registration within one MQ is refused as in the official service.
#[derive(Clone, Copy, Default)]
pub struct PortSlot {
    record: Option<PortRecord>,
}
impl PortSlot {
    /// Empty logical port metadata.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
/// Internal application-channel establishment/retirement state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Waiting for a real local listener or actual peer OPEN proof.
    Opening,
    /// Real local pair or actual claimed ready peer channel.
    Ready,
    /// Actual retirement; old output/peer-close intents still drain.
    Closing,
}
#[derive(Clone, Copy)]
enum Side {
    LocalWaiting,
    Loop(ChannelRef),
    Remote {
        started: bool,
        binding: u64,
        close_started: bool,
    },
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum AppReceive {
    Ready,
    Writing(u64),
    Waiting(u64),
}
#[derive(Clone, Copy)]
enum TxState {
    LoopQueued,
    LoopWriting,
    RemoteQueued,
    RemoteAdmitted(u64),
}
#[derive(Clone, Copy)]
struct Tx {
    serial: u64,
    state: TxState,
}
#[derive(Clone, Copy)]
struct PeerReceive {
    serial: u64,
    done_due: bool,
}
#[derive(Clone, Copy)]
struct ChannelRecord {
    serial: u64,
    client: ClientRef,
    wire: u32,
    peer: [u8; 32],
    port: [u8; 64],
    phase: Phase,
    side: Side,
    incoming: bool,
    create_due: bool,
    announced: bool,
    destroy_due: bool,
    draining: bool,
    allowance: u8,
    credit_due: u8,
    source_slots: u8,
    tx: [Option<Tx>; 4],
    receive: AppReceive,
    peer_receive: Option<PeerReceive>,
    peer_last_send: u64,
    payload_limit: usize,
    drop_type_bytes: Option<[u8; 2]>,
}
/// Caller-owned small channel metadata. Payload bytes are never embedded here.
#[derive(Clone, Copy, Default)]
pub struct ChannelSlot {
    record: Option<ChannelRecord>,
}
impl ChannelSlot {
    /// Empty fixed endpoint metadata.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
#[derive(Clone, Copy)]
enum MessageKind {
    Credit {
        source: ChannelRef,
        granted: bool,
    },
    Loop {
        source: ChannelRef,
        tx: u8,
        work: u64,
        target: ChannelRef,
    },
    Remote {
        source: ChannelRef,
        tx: u8,
        work: u64,
    },
    Peer {
        target: ChannelRef,
        work: u64,
    },
}
#[derive(Clone, Copy)]
struct MessageRecord {
    serial: u64,
    length: usize,
    order: u64,
    priority: u32,
    kind: MessageKind,
}
/// One caller-provided shared payload buffer. First client_slots.len() slots
/// reserve one remote-ingress staging buffer per MQ; the remainder share all
/// locally granted source credits and accepted outgoing application strings.
pub struct MessageSlot<'bytes> {
    bytes: &'bytes mut [u8],
    record: Option<MessageRecord>,
}
impl<'bytes> MessageSlot<'bytes> {
    /// Wrap empty fixed storage without allocation.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self {
            bytes,
            record: None,
        }
    }
}
#[derive(Clone, Copy)]
enum Action {
    Incoming(ChannelRef),
    Destroy,
    Credit {
        channel: ChannelRef,
        reservation: MessageRef,
    },
    Data {
        channel: ChannelRef,
        source: Option<(ChannelRef, u8, u64)>,
    },
}
#[derive(Clone, Copy)]
struct Pending<'id> {
    output: Output<'id>,
    action: Action,
    exposed: bool,
}
#[derive(Clone, Copy)]
enum Choice {
    Incoming(ChannelRef),
    Destroy(ChannelRef),
    Credit {
        channel: ChannelRef,
        slot: usize,
    },
    Data {
        channel: ChannelRef,
        message: MessageRef,
    },
}
/// Actual application-side protocol input result; no peer/physical fact is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// Actual registration on this original accepted source.
    PortOpened(Port<'a>),
    /// Actual original registration withdrawn; existing channels survive.
    PortClosed,
    /// Original outgoing request exists, possibly still waiting for a real peer/listener.
    ChannelCreated(Channel<'a>),
    /// Original payload retained under an actually granted source credit.
    DataQueued(Message<'a>),
    /// Empty valid inner-string batch consumed/recycled local capacity only.
    Empty(Channel<'a>),
    /// Actual application receive_done freed its original local handoff.
    ReceiveDone(Channel<'a>),
    /// Actual source requested channel retirement.
    ChannelClosed,
    /// Explicit Destroy retained original TX; its native owner supplies a fixed
    /// finite drain bound and must expire/abort it on actual source failure.
    ChannelDraining(Channel<'a>),
    /// Whole payload permanently exceeds this actual channel's transport policy.
    Rejected {
        /// Original application channel being retired.
        channel: Channel<'a>,
        /// Actual permanent policy refusal, never resource Pending.
        reason: Error,
    },
    /// This original channel now carries its explicit one-shot diagnostic selector.
    DropConfigured(Channel<'a>),
    /// Valid late unknown channel/duplicate receive_done changed no state.
    Ignored,
}
/// Current original application endpoint observations; credit is local permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelInfo {
    /// Actual local wire number.
    pub wire_id: u32,
    /// Expected peer identity, not a fabricated tunnel receipt.
    pub peer: [u8; 32],
    /// Original application port hash.
    pub port: [u8; 64],
    /// Actual local phase.
    pub phase: Phase,
    /// Source credit actually written to this MQ and unconsumed.
    pub allowance: u8,
    /// Local application still owes receive_done.
    pub receive_pending: bool,
    /// Actual complete-payload policy for this endpoint.
    pub payload_limit: usize,
    /// Explicit local Destroy waits only for previously admitted outgoing TX.
    /// New DATA/credits/incoming delivery stop; this is not peer acceptance.
    pub draining: bool,
}
/// Original actual remote-open request, bound to this service channel generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Open<'a> {
    channel: Channel<'a>,
}
impl<'a> Open<'a> {
    /// Original application endpoint.
    #[must_use]
    pub const fn channel(self) -> Channel<'a> {
        self.channel
    }
}
/// Actual one-to-one peer application claim, held by the external port rather
/// than stored as a foreign lifetime inside this service's recyclable tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding<'id, 'peer> {
    channel: Channel<'id>,
    serial: u64,
    application: peer::Application<'peer>,
}
impl<'id, 'peer> Binding<'id, 'peer> {
    /// Original application channel.
    #[must_use]
    pub const fn channel(self) -> Channel<'id> {
        self.channel
    }
    /// Original actual peer-channel claim, not a raw CTN match.
    #[must_use]
    pub const fn application(self) -> peer::Application<'peer> {
        self.application
    }
}
/// Original retained outgoing remote payload effect; caller must copy/admit its
/// exact bytes on the real peer owner before committing association here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Send<'id> {
    channel: Channel<'id>,
    message: MessageRef,
    tx: u8,
    work: u64,
}
impl<'id> Send<'id> {
    /// Original application endpoint whose explicit peer port must admit this payload.
    #[must_use]
    pub const fn channel(self) -> Channel<'id> {
        self.channel
    }
}
/// Borrowed actual effect payload, before a fallible peer-side copy/admission.
pub struct Sending<'id, 'bytes> {
    /// Original exact service effect.
    pub effect: Send<'id>,
    /// Actual complete inner-message string.
    pub payload: &'bytes [u8],
    /// Original raw local MQ priority/preferences.
    pub priority: u32,
}
/// Original peer send association, held externally until actual peer completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admitted<'id, 'peer> {
    binding: Binding<'id, 'peer>,
    tx: u8,
    work: u64,
    send: peer::Send<'peer>,
}
impl<'id, 'peer> Admitted<'id, 'peer> {
    /// Original application endpoint for the retained actual peer send association.
    #[must_use]
    pub const fn channel(self) -> Channel<'id> {
        self.binding.channel
    }
    /// Actual original peer send, not a caller-supplied outcome label.
    #[must_use]
    pub const fn send(self) -> peer::Send<'peer> {
        self.send
    }
}
/// Actual original peer-to-local handoff retained by the external port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerDelivery<'id, 'peer> {
    binding: Binding<'id, 'peer>,
    work: u64,
    delivery: peer::Delivery<'peer>,
}
impl<'id> PeerDelivery<'id, '_> {
    /// Original application endpoint that must actually acknowledge this delivery.
    #[must_use]
    pub const fn channel(self) -> Channel<'id> {
        self.binding.channel
    }
}
/// Original explicit application receive_done effect for its real peer handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveDone<'id> {
    channel: Channel<'id>,
    binding: u64,
    work: u64,
}
impl<'id> ReceiveDone<'id> {
    /// Original application endpoint whose actual peer delivery must be released.
    #[must_use]
    pub const fn channel(self) -> Channel<'id> {
        self.channel
    }
}
/// Original real peer channel must retire; its port retains this binding lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Close<'id> {
    channel: Channel<'id>,
    binding: u64,
}
impl<'id> Close<'id> {
    /// Original application endpoint whose actual peer port must retire.
    #[must_use]
    pub const fn channel(self) -> Channel<'id> {
        self.channel
    }
}

/// One pure server-side application service with a global shared payload pool.
/// Native transports, immutable output copies and actual peer/tunnel owners are
/// explicit callers; no SDK, allocator, hidden callback task or resolver is used.
pub struct Service<'id, 'slots, 'bytes> {
    brand: Brand<'id>,
    local: [u8; 32],
    clients: &'slots mut [ClientSlot<'id>],
    ports: &'slots mut [PortSlot],
    channels: &'slots mut [ChannelSlot],
    messages: &'slots mut [MessageSlot<'bytes>],
    limits: Limits,
    next_client: u64,
    next_channel: u64,
    next_port: u64,
    next_message: u64,
    next_work: u64,
    next_output: u64,
    next_binding: u64,
    funded: usize,
    statistics: crate::statistics::OwnedStore,
}
impl<'id, 'slots, 'bytes> Service<'id, 'slots, 'bytes> {
    /// Borrow all finite resources. One max-sized source slot per possible local
    /// endpoint guarantees baseline credit without idle-credit starvation; extra
    /// source capacity is shared up to window 4. Per-MQ ingress reserves prevent
    /// one blocked application socket from monopolizing every remote receiver.
    pub fn new(
        instance: &'id mut Instance,
        local: [u8; 32],
        clients: &'slots mut [ClientSlot<'id>],
        ports: &'slots mut [PortSlot],
        channels: &'slots mut [ChannelSlot],
        messages: &'slots mut [MessageSlot<'bytes>],
        limits: Limits,
    ) -> Result<Self, Error> {
        let maximum = limits.loop_payload_bytes.max(limits.remote_payload_bytes);
        if clients.is_empty()
            || channels.is_empty()
            || !(1..=4).contains(&limits.window)
            || !(4..=65523).contains(&limits.loop_payload_bytes)
            || !(4..=64348).contains(&limits.remote_payload_bytes)
            || messages.len() < clients.len()
        {
            return Err(Error::InvalidInput);
        }
        if messages[..clients.len()]
            .iter()
            .any(|slot| slot.bytes.len() < limits.remote_payload_bytes)
            || messages[clients.len()..]
                .iter()
                .filter(|slot| slot.bytes.len() >= maximum)
                .count()
                < channels.len()
        {
            return Err(Error::Capacity);
        }
        if clients.iter().any(|slot| slot.record.is_some())
            || ports.iter().any(|slot| slot.record.is_some())
            || channels.iter().any(|slot| slot.record.is_some())
            || messages.iter().any(|slot| slot.record.is_some())
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            brand: Brand(instance),
            local,
            clients,
            ports,
            channels,
            messages,
            limits,
            next_client: 0,
            next_channel: 0,
            next_port: 0,
            next_message: 0,
            next_work: 0,
            next_output: 0,
            next_binding: 0,
            funded: 0,
            statistics: crate::statistics::OwnedStore::new(),
        })
    }
    fn client(&self, reference: ClientRef) -> Client<'id> {
        Client {
            brand: self.brand,
            reference,
        }
    }
    fn channel(&self, reference: ChannelRef) -> Channel<'id> {
        Channel {
            brand: self.brand,
            reference,
        }
    }
    fn channel_ref(slot: usize, record: ChannelRecord) -> ChannelRef {
        ChannelRef {
            slot,
            serial: record.serial,
            client: record.client,
            wire: record.wire,
        }
    }
    fn client_record(&self, client: Client<'id>) -> Result<&ClientRecord<'id>, Error> {
        if client.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        self.clients
            .get(client.reference.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| record.serial == client.reference.serial)
            .ok_or(Error::StaleGeneration)
    }
    fn channel_record(&self, channel: Channel<'id>) -> Result<&ChannelRecord, Error> {
        if channel.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        self.channel_ref_record(channel.reference)
    }
    fn channel_ref_record(&self, reference: ChannelRef) -> Result<&ChannelRecord, Error> {
        self.channels
            .get(reference.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| {
                record.serial == reference.serial
                    && record.client == reference.client
                    && record.wire == reference.wire
            })
            .ok_or(Error::StaleGeneration)
    }
    fn message_record(&self, reference: MessageRef) -> Result<&MessageRecord, Error> {
        self.messages
            .get(reference.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| record.serial == reference.serial)
            .ok_or(Error::StaleGeneration)
    }
    fn find_channel(&self, client: ClientRef, wire: u32) -> Option<ChannelRef> {
        self.channels
            .iter()
            .enumerate()
            .find_map(|(slot, channel)| {
                channel
                    .record
                    .filter(|record| {
                        record.client == client
                            && record.wire == wire
                            && record.phase != Phase::Closing
                            && !record.draining
                    })
                    .map(|record| Self::channel_ref(slot, record))
            })
    }
    fn listener(&self, hash: [u8; 64]) -> Option<PortRecord> {
        self.ports
            .iter()
            .filter_map(|slot| slot.record)
            .filter(|port| {
                port.hash == hash && self.client_record(self.client(port.client)).is_ok()
            })
            .min_by_key(|port| port.serial)
    }
    /// Commit an actual newly accepted native application MQ; no private INIT.
    pub fn attach(&mut self) -> Result<Client<'id>, Error> {
        let slot = self
            .clients
            .iter()
            .position(|slot| slot.record.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.next_client.checked_add(1).ok_or(Error::Overflow)?;
        let reference = ClientRef { slot, serial };
        self.clients[slot].record = Some(ClientRecord {
            serial,
            next_incoming: Some(0),
            pending: None,
            cursor: 0,
        });
        self.next_client = serial;
        Ok(self.client(reference))
    }
    /// Original-domain statistics, including currently attached application or management MQs.
    #[must_use]
    pub fn statistics(&self) -> crate::statistics::Snapshot {
        let mut snapshot = self.statistics.snapshot();
        snapshot.set(
            crate::statistics::Metric::Clients,
            self.clients.iter().filter(|s| s.record.is_some()).count(),
        );
        snapshot
    }
    /// Current local peer identity supplied by the identity owner.
    #[must_use]
    pub const fn local_peer(&self) -> [u8; 32] {
        self.local
    }
    /// Retire identity-bound endpoints while retaining application sources,
    /// logical ports and already established own-peer pairs. Real dispatched
    /// opens and peer bindings keep their original cancellation/close debts;
    /// this method cannot manufacture their completion.
    pub fn retire_identity_channels(&mut self) -> Result<(), Error> {
        for slot in 0..self.channels.len() {
            if let Some(record) = self.channels[slot].record
                && !matches!(record.side, Side::Loop(_))
            {
                self.close_channel(Self::channel_ref(slot, record), true)?;
            }
        }
        Ok(())
    }
    /// Apply a newly verified host identity after all old peer effects have
    /// actually retired. The complete preflight precedes mutation. Registered
    /// ports retain their handles and MQ owners; existing loop pairs and frozen
    /// output retain their original peer observations. This grants no identity
    /// authentication, peer connectivity or write-completion receipt.
    pub fn rebind_local_peer(&mut self, local: [u8; 32]) -> Result<(), Error> {
        if local == self.local {
            return Ok(());
        }
        if !self.identity_channels_retired() {
            return Err(Error::WouldBlock);
        }
        for port in self
            .ports
            .iter_mut()
            .filter_map(|slot| slot.record.as_mut())
        {
            port.challenge = peer::hash_port(&port.hash, &local);
        }
        self.local = local;
        Ok(())
    }
    /// Observe the exact application-side identity-cut barrier without taking
    /// an open/close effect. Native providers must independently retire their
    /// actual operations; this predicate alone cannot certify their quiescence.
    #[must_use]
    pub fn identity_channels_retired(&self) -> bool {
        !self
            .channels
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| match record.side {
                Side::Loop(_) => false,
                Side::LocalWaiting => record.phase != Phase::Closing,
                Side::Remote {
                    started, binding, ..
                } => record.phase != Phase::Closing || started || binding != 0,
            })
    }
    /// Copy current original channel observations without granting credit.
    pub fn channel_info(&self, channel: Channel<'id>) -> Result<ChannelInfo, Error> {
        let record = self.channel_record(channel)?;
        Ok(ChannelInfo {
            wire_id: record.wire,
            peer: record.peer,
            port: record.port,
            phase: record.phase,
            allowance: record.allowance,
            receive_pending: record.receive != AppReceive::Ready,
            payload_limit: record.payload_limit,
            draining: record.draining,
        })
    }
    /// Actual currently owned logical port bytes; stale owner handles refuse.
    /// Resolve only a currently registered application listener's official
    /// SHA512(port || local-peer) challenge. Unknown hashes grant no owner/ACK.
    #[must_use]
    pub fn resolve_port_challenge(&self, challenge: &[u8; 64]) -> Option<[u8; 64]> {
        self.ports
            .iter()
            .filter_map(|slot| slot.record)
            .find(|port| port.challenge == *challenge)
            .map(|port| port.hash)
    }
    /// Actual currently owned logical port bytes; stale owner handles refuse.
    pub fn port_hash(&self, port: Port<'id>) -> Result<[u8; 64], Error> {
        if port.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        self.ports
            .get(port.slot)
            .and_then(|slot| slot.record)
            .filter(|record| record.serial == port.serial)
            .map(|record| record.hash)
            .ok_or(Error::StaleGeneration)
    }
    /// Borrow the original still-retained source payload; stale pool generations refuse.
    /// Preparing native DATA or admitting a real peer send transfers that retention.
    pub fn message_bytes(&self, message: Message<'id>) -> Result<&[u8], Error> {
        if message.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        let record = self.message_record(message.reference)?;
        Ok(&self.messages[message.reference.slot].bytes[..record.length])
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Small channel metadata is built from explicit original MQ, wire identity, phase and resource policy"
    )]
    fn new_channel(
        &self,
        serial: u64,
        client: ClientRef,
        wire: u32,
        peer: [u8; 32],
        port: [u8; 64],
        side: Side,
        phase: Phase,
        incoming: bool,
        payload_limit: usize,
    ) -> ChannelRecord {
        ChannelRecord {
            serial,
            client,
            wire,
            peer,
            port,
            phase,
            side,
            incoming,
            create_due: incoming,
            announced: !incoming,
            destroy_due: false,
            draining: false,
            allowance: 0,
            credit_due: if phase == Phase::Ready {
                self.limits.window
            } else {
                0
            },
            source_slots: 0,
            tx: [None; 4],
            receive: AppReceive::Ready,
            peer_receive: None,
            peer_last_send: 0,
            payload_limit,
            drop_type_bytes: None,
        }
    }
    /// Consume one decoded original CLIENT request. Capacity refuses before
    /// application acceptance; permanent oversized data retires only its channel.
    pub fn receive(
        &mut self,
        client: Client<'id>,
        request: Request<'_>,
    ) -> Result<Event<'id>, Error> {
        self.client_record(client)?;
        request.encoded_len()?;
        match request {
            Request::PortOpen { port: hash } => {
                if self.ports.iter().any(|slot| {
                    slot.record
                        .is_some_and(|port| port.client == client.reference && port.hash == hash)
                }) {
                    return Err(Error::Conflict);
                }
                let slot = self
                    .ports
                    .iter()
                    .position(|slot| slot.record.is_none())
                    .ok_or(Error::Capacity)?;
                let serial = self.next_port.checked_add(1).ok_or(Error::Overflow)?;
                self.ports[slot].record = Some(PortRecord {
                    serial,
                    client: client.reference,
                    hash,
                    challenge: peer::hash_port(&hash, &self.local),
                });
                self.next_port = serial;
                Ok(Event::PortOpened(Port {
                    brand: self.brand,
                    slot,
                    serial,
                }))
            }
            Request::PortClose { port: hash } => {
                let slot = self
                    .ports
                    .iter()
                    .position(|slot| {
                        slot.record.is_some_and(|port| {
                            port.client == client.reference && port.hash == hash
                        })
                    })
                    .ok_or(Error::NotFound)?;
                self.ports[slot].record = None;
                Ok(Event::PortClosed)
            }
            Request::ChannelCreate {
                channel: wire,
                peer,
                port,
                ..
            } => {
                if wire < CLIENT_CHANNEL_BOUNDARY {
                    return Err(Error::Malformed);
                }
                // The C API immediately releases and reuses its current raw
                // number on local Destroy. A retained peer close/drain is a
                // different original owner, not a live application binding.
                let same_wire = |record: ChannelRecord| {
                    record.client == client.reference && record.wire == wire
                };
                if self.channels.iter().any(|slot| {
                    slot.record.is_some_and(|record| {
                        same_wire(record) && record.phase != Phase::Closing && !record.draining
                    })
                }) {
                    return Err(Error::Conflict);
                }
                // Old raw controls must actually settle before that number
                // can name a new endpoint. This is transient native pressure,
                // not a duplicate live binding that should fence the MQ.
                if self
                    .client_record(client)?
                    .pending
                    .is_some_and(|pending| pending.output.channel.wire == wire)
                    || self.channels.iter().any(|slot| {
                        slot.record
                            .is_some_and(|record| same_wire(record) && record.destroy_due)
                    })
                {
                    return Err(Error::WouldBlock);
                }
                let slot = self
                    .channels
                    .iter()
                    .position(|slot| slot.record.is_none())
                    .ok_or(Error::Capacity)?;
                let serial = self.next_channel.checked_add(1).ok_or(Error::Overflow)?;
                let local = peer == self.local;
                let side = if local {
                    Side::LocalWaiting
                } else {
                    Side::Remote {
                        started: false,
                        binding: 0,
                        close_started: false,
                    }
                };
                let limit = if local {
                    self.limits.loop_payload_bytes
                } else {
                    self.limits.remote_payload_bytes
                };
                let record = self.new_channel(
                    serial,
                    client.reference,
                    wire,
                    peer,
                    port,
                    side,
                    Phase::Opening,
                    false,
                    limit,
                );
                self.channels[slot].record = Some(record);
                self.next_channel = serial;
                self.statistics.add(crate::statistics::Metric::Channels, 1);
                Ok(Event::ChannelCreated(
                    self.channel(Self::channel_ref(slot, record)),
                ))
            }
            Request::ChannelDestroy { channel: wire } => {
                let channel = self.find_channel(client.reference, wire).or_else(|| {
                    // An explicit local close can race an unissued remote
                    // notification. Remove that local intent without dropping
                    // any original immutable output already prepared for it.
                    self.channels.iter().enumerate().find_map(|(slot, row)| {
                        row.record
                            .filter(|record| {
                                record.client == client.reference
                                    && record.wire == wire
                                    && record.phase == Phase::Closing
                                    && record.destroy_due
                            })
                            .map(|record| Self::channel_ref(slot, record))
                    })
                });
                let Some(channel) = channel else {
                    return Ok(Event::Ignored);
                };
                let record = *self.channel_ref_record(channel)?;
                if record.phase == Phase::Closing {
                    self.channels[channel.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?
                        .destroy_due = false;
                    self.cleanup(channel);
                    return Ok(Event::ChannelClosed);
                }
                if record.phase == Phase::Ready && record.tx.iter().any(Option::is_some) {
                    let record = self.channels[channel.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?;
                    record.draining = true;
                    record.allowance = 0;
                    record.credit_due = 0;
                    return Ok(Event::ChannelDraining(self.channel(channel)));
                }
                self.close_channel(channel, false)?;
                Ok(Event::ChannelClosed)
            }
            Request::Data {
                channel: wire,
                priority,
                messages,
            } => {
                let Some(channel) = self.find_channel(client.reference, wire) else {
                    return Ok(Event::Ignored);
                };
                let result = self.data(channel, priority, messages);
                if !matches!(result, Err(Error::Capacity | Error::WouldBlock)) {
                    self.statistics
                        .bytes(crate::statistics::Metric::Payload, messages.len());
                }
                result
            }
            Request::Ack { channel: wire } => {
                let Some(channel) = self.find_channel(client.reference, wire) else {
                    return Ok(Event::Ignored);
                };
                let record = self.channels[channel.slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                if !matches!(record.receive, AppReceive::Waiting(serial) if serial != 0) {
                    return Ok(Event::Ignored);
                }
                record.receive = AppReceive::Ready;
                if let Some(received) = record.peer_receive.as_mut() {
                    received.done_due = true;
                }
                Ok(Event::ReceiveDone(self.channel(channel)))
            }
            Request::DropMessage {
                channel: wire,
                message_type_bytes,
            } => {
                let Some(reference) = self.find_channel(client.reference, wire) else {
                    return Ok(Event::Ignored);
                };
                let record = self.channels[reference.slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                // The fixed daemon compares these two opaque C bytes directly
                // with the encoded peer header. Preserve them without a cast.
                record.drop_type_bytes =
                    (message_type_bytes != [0; 2]).then_some(message_type_bytes);
                Ok(Event::DropConfigured(self.channel(reference)))
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Consume only a matching prepared peer packet's one-shot selector. Raw
    /// local wire IDs cannot select another channel generation/client/domain.
    /// Loopback never passes this tunnel boundary and is therefore not dropped.
    pub fn consume_peer_drop(
        &mut self,
        channel: Channel<'id>,
        message_type_bytes: [u8; 2],
    ) -> Result<bool, Error> {
        self.channel_record(channel)?;
        let record = self.channels[channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if record.drop_type_bytes == Some(message_type_bytes) {
            record.drop_type_bytes = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    /// Bind one actual local loopback pair to a currently registered real port.
    /// No peer/tunnel is constructed for own-peer traffic. Repeated calls progress
    /// bounded waiting channels; closing a port never destroys an existing pair.
    pub fn progress(&mut self) -> Result<Option<Channel<'id>>, Error> {
        for slot in 0..self.channels.len() {
            let Some(mut source) = self.channels[slot].record else {
                continue;
            };
            if source.phase != Phase::Opening || !matches!(source.side, Side::LocalWaiting) {
                continue;
            }
            let Some(port) = self.listener(source.port) else {
                continue;
            };
            let target_slot = self
                .channels
                .iter()
                .position(|slot| slot.record.is_none())
                .ok_or(Error::Capacity)?;
            let target_client = self.client(port.client);
            let wire = self
                .client_record(target_client)?
                .next_incoming
                .ok_or(Error::Capacity)?;
            if wire >= CLIENT_CHANNEL_BOUNDARY {
                return Err(Error::Capacity);
            }
            let serial = self.next_channel.checked_add(1).ok_or(Error::Overflow)?;
            let source_ref = Self::channel_ref(slot, source);
            let target = self.new_channel(
                serial,
                port.client,
                wire,
                source.peer,
                source.port,
                Side::Loop(source_ref),
                Phase::Ready,
                true,
                self.limits.loop_payload_bytes,
            );
            let target_ref = Self::channel_ref(target_slot, target);
            source.phase = Phase::Ready;
            source.side = Side::Loop(target_ref);
            source.credit_due = self.limits.window;
            self.channels[slot].record = Some(source);
            self.channels[target_slot].record = Some(target);
            self.next_channel = serial;
            self.clients[port.client.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .next_incoming = wire
                .checked_add(1)
                .filter(|next| *next < CLIENT_CHANNEL_BOUNDARY);
            return Ok(Some(self.channel(target_ref)));
        }
        Ok(None)
    }
    fn source_acquire(&mut self, channel: ChannelRef) -> Result<(), Error> {
        let record = self.channel_ref_record(channel)?;
        let count = record.source_slots.checked_add(1).ok_or(Error::Overflow)?;
        if record.source_slots == 0 {
            self.funded += 1;
        }
        self.channels[channel.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .source_slots = count;
        Ok(())
    }
    fn free_message(&mut self, message: MessageRef) {
        let Some(record) = self
            .messages
            .get(message.slot)
            .and_then(|slot| slot.record)
            .filter(|record| record.serial == message.serial)
        else {
            return;
        };
        self.messages[message.slot].record = None;
        self.messages[message.slot].bytes[..record.length].fill(0);
        let source = match record.kind {
            MessageKind::Credit { source, .. }
            | MessageKind::Loop { source, .. }
            | MessageKind::Remote { source, .. } => Some(source),
            MessageKind::Peer { .. } => None,
        };
        if let Some(source) = source
            && self.channel_ref_record(source).is_ok()
            && let Some(channel) = self.channels[source.slot].record.as_mut()
        {
            channel.source_slots = channel.source_slots.saturating_sub(1);
            if channel.source_slots == 0 {
                self.funded = self.funded.saturating_sub(1);
            }
        }
    }
    fn data(
        &mut self,
        channel: ChannelRef,
        priority: u32,
        payload: &[u8],
    ) -> Result<Event<'id>, Error> {
        let record = *self.channel_ref_record(channel)?;
        if record.draining {
            return Ok(Event::Ignored);
        }
        if record.phase != Phase::Ready || record.allowance == 0 {
            return Err(Error::PermissionDenied);
        }
        if payload.len() > record.payload_limit {
            self.close_channel(channel, true)?;
            return Ok(Event::Rejected {
                channel: self.channel(channel),
                reason: Error::TooLarge,
            });
        }
        let slot = self.messages.iter().position(|slot| slot.record.is_some_and(|message| matches!(message.kind, MessageKind::Credit { source, granted: true } if source == channel))).ok_or(Error::Conflict)?;
        let message = self.messages[slot].record.ok_or(Error::StaleGeneration)?;
        let reference = MessageRef {
            slot,
            serial: message.serial,
        };
        if payload.is_empty() {
            self.channels[channel.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .allowance -= 1;
            self.channels[channel.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .credit_due += 1;
            self.free_message(reference);
            return Ok(Event::Empty(self.channel(channel)));
        }
        let tx_slot = record
            .tx
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Conflict)?;
        let work = self.next_work.checked_add(1).ok_or(Error::Overflow)?;
        let (kind, state) = match record.side {
            Side::Loop(target) => (
                MessageKind::Loop {
                    source: channel,
                    tx: tx_slot as u8,
                    work,
                    target,
                },
                TxState::LoopQueued,
            ),
            Side::Remote { binding, .. } if binding != 0 => (
                MessageKind::Remote {
                    source: channel,
                    tx: tx_slot as u8,
                    work,
                },
                TxState::RemoteQueued,
            ),
            _ => return Err(Error::NotReady),
        };
        self.messages[slot].bytes[..payload.len()].copy_from_slice(payload);
        self.messages[slot].record = Some(MessageRecord {
            serial: message.serial,
            length: payload.len(),
            order: work,
            priority,
            kind,
        });
        let active = self.channels[channel.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        active.allowance -= 1;
        active.tx[tx_slot] = Some(Tx {
            serial: work,
            state,
        });
        self.next_work = work;
        Ok(Event::DataQueued(Message {
            brand: self.brand,
            reference,
        }))
    }
    fn reserve_slot(&self, channel: ChannelRef) -> Option<usize> {
        let record = self.channel_ref_record(channel).ok()?;
        let maximum = self
            .limits
            .loop_payload_bytes
            .max(self.limits.remote_payload_bytes);
        let free_big = self.messages[self.clients.len()..]
            .iter()
            .filter(|slot| slot.record.is_none() && slot.bytes.len() >= maximum)
            .count();
        let missing = self
            .channels
            .len()
            .saturating_sub(self.funded + usize::from(record.source_slots == 0));
        self.messages
            .iter()
            .enumerate()
            .skip(self.clients.len())
            .filter(|(_, slot)| slot.record.is_none() && slot.bytes.len() >= record.payload_limit)
            .filter(|(_, slot)| {
                free_big.saturating_sub(usize::from(slot.bytes.len() >= maximum)) >= missing
            })
            .min_by_key(|(_, slot)| slot.bytes.len())
            .map(|(slot, _)| slot)
    }
    fn choice(&self, client: ClientRef) -> Option<Choice> {
        let current = self.clients.get(client.slot)?.record?;
        if current.serial != client.serial || current.pending.is_some() {
            return None;
        }
        for (slot, channel) in self.channels.iter().enumerate() {
            let Some(record) = channel.record.filter(|record| record.client == client) else {
                continue;
            };
            let reference = Self::channel_ref(slot, record);
            if record.create_due && record.phase == Phase::Ready {
                return Some(Choice::Incoming(reference));
            }
            if record.destroy_due {
                return Some(Choice::Destroy(reference));
            }
        }
        for offset in 0..self.channels.len() {
            let slot = (current.cursor + offset) % self.channels.len();
            let Some(record) = self.channels[slot].record.filter(|record| {
                record.client == client
                    && record.phase == Phase::Ready
                    && record.announced
                    && !record.draining
                    && record.credit_due != 0
            }) else {
                continue;
            };
            let reference = Self::channel_ref(slot, record);
            if let Some(slot) = self.reserve_slot(reference) {
                return Some(Choice::Credit {
                    channel: reference,
                    slot,
                });
            }
        }
        self.messages
            .iter()
            .enumerate()
            .filter_map(|(slot, message)| {
                let record = message.record?;
                let target = match record.kind {
                    MessageKind::Loop { target, .. } | MessageKind::Peer { target, .. } => target,
                    _ => return None,
                };
                let channel = self.channel_ref_record(target).ok()?;
                if channel.client != client
                    || channel.phase != Phase::Ready
                    || !channel.announced
                    || channel.draining
                    || channel.receive != AppReceive::Ready
                {
                    return None;
                }
                Some((
                    record.order,
                    Choice::Data {
                        channel: target,
                        message: MessageRef {
                            slot,
                            serial: record.serial,
                        },
                    },
                ))
            })
            .min_by_key(|(order, _)| *order)
            .map(|(_, choice)| choice)
    }
    fn response(&self, choice: Choice) -> Result<Response<'_>, Error> {
        Ok(match choice {
            Choice::Incoming(channel) => {
                let record = self.channel_ref_record(channel)?;
                Response::ChannelCreate {
                    channel: channel.wire,
                    peer: record.peer,
                    port: record.port,
                    options: 0,
                }
            }
            Choice::Destroy(channel) => Response::ChannelDestroy {
                channel: channel.wire,
            },
            Choice::Credit { channel, .. } => Response::Ack {
                channel: channel.wire,
            },
            Choice::Data { channel, message } => {
                let record = self.message_record(message)?;
                Response::Data {
                    channel: channel.wire,
                    priority: record.priority,
                    messages: &self.messages[message.slot].bytes[..record.length],
                }
            }
        })
    }
    /// Required final immutable native output length, before fallible allocation.
    pub fn next_output_len(&self, client: Client<'id>) -> Result<Option<usize>, Error> {
        self.client_record(client)?;
        self.choice(client.reference)
            .map(|choice| self.response(choice)?.encoded_len())
            .transpose()
    }
    /// Encode into already preflighted final native frame storage. One original
    /// output per MQ remains pending until actual full write or physical detach.
    /// No waiting-future cancellation rolls this operation back or regenerates it.
    pub fn prepare_output<'output>(
        &mut self,
        client: Client<'id>,
        output: &'output mut [u8],
    ) -> Result<Option<Prepared<'id, 'output>>, Error> {
        let current = *self.client_record(client)?;
        if current.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let Some(choice) = self.choice(client.reference) else {
            return Ok(None);
        };
        let serial = self.next_output.checked_add(1).ok_or(Error::Overflow)?;
        let reserve_serial = if matches!(choice, Choice::Credit { .. }) {
            Some(self.next_message.checked_add(1).ok_or(Error::Overflow)?)
        } else {
            None
        };
        let length = self.response(choice)?.encode(output)?;
        let (channel, kind, action) = match choice {
            Choice::Incoming(channel) => {
                self.channels[channel.slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .create_due = false;
                (channel, OutputKind::Incoming, Action::Incoming(channel))
            }
            Choice::Destroy(channel) => {
                self.channels[channel.slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .destroy_due = false;
                (channel, OutputKind::Destroy, Action::Destroy)
            }
            Choice::Credit { channel, slot } => {
                let generation = reserve_serial.ok_or(Error::Conflict)?;
                let reservation = MessageRef {
                    slot,
                    serial: generation,
                };
                self.messages[slot].record = Some(MessageRecord {
                    serial: generation,
                    length: 0,
                    order: 0,
                    priority: 0,
                    kind: MessageKind::Credit {
                        source: channel,
                        granted: false,
                    },
                });
                self.source_acquire(channel)?;
                self.next_message = generation;
                (
                    channel,
                    OutputKind::Credit,
                    Action::Credit {
                        channel,
                        reservation,
                    },
                )
            }
            Choice::Data { channel, message } => {
                let record = *self.message_record(message)?;
                let source = match record.kind {
                    MessageKind::Loop {
                        source, tx, work, ..
                    } => {
                        if let Some(record) = self
                            .channels
                            .get_mut(source.slot)
                            .and_then(|slot| slot.record.as_mut())
                            .filter(|record| record.serial == source.serial)
                            && let Some(pending) = record.tx[usize::from(tx)]
                                .as_mut()
                                .filter(|pending| pending.serial == work)
                        {
                            pending.state = TxState::LoopWriting;
                        }
                        Some((source, tx, work))
                    }
                    MessageKind::Peer { work, .. } => {
                        if self
                            .channel_ref_record(channel)?
                            .peer_receive
                            .is_none_or(|received| received.serial != work)
                        {
                            return Err(Error::StaleGeneration);
                        }
                        None
                    }
                    _ => return Err(Error::Conflict),
                };
                self.channels[channel.slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .receive = AppReceive::Writing(serial);
                self.free_message(message);
                (channel, OutputKind::Data, Action::Data { channel, source })
            }
        };
        let token = Output {
            brand: self.brand,
            client: client.reference,
            serial,
            channel,
            kind,
        };
        self.clients[client.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .pending = Some(Pending {
            output: token,
            action,
            exposed: false,
        });
        self.clients[client.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .cursor = (channel.slot + 1) % self.channels.len();
        self.next_output = serial;
        self.cleanup(channel);
        Ok(Some(Prepared {
            output: token,
            bytes: &output[..length],
        }))
    }
    /// Record only positive actual native output on its original accepted MQ.
    pub fn exposed(&mut self, output: Output<'id>) -> Result<(), Error> {
        self.client_record(output.client())?;
        let pending = self.clients[output.client.slot]
            .record
            .as_mut()
            .and_then(|record| record.pending.as_mut())
            .filter(|pending| pending.output == output)
            .ok_or(Error::StaleGeneration)?;
        pending.exposed = true;
        Ok(())
    }
    /// Commit only an actual complete original native frame write. ACK credit
    /// becomes usable here; DATA write frees sender capacity without asserting
    /// application processing. receive_done remains separately required.
    pub fn written(&mut self, output: Output<'id>) -> Result<(), Error> {
        let pending = self
            .client_record(output.client())?
            .pending
            .filter(|pending| pending.output == output)
            .ok_or(Error::StaleGeneration)?;
        if !pending.exposed {
            return Err(Error::NotReady);
        }
        let mut drained_source = None;
        match pending.action {
            Action::Incoming(channel) => {
                if self.channel_ref_record(channel).is_ok()
                    && let Some(record) = self.channels[channel.slot].record.as_mut()
                    && record.phase == Phase::Ready
                {
                    record.announced = true;
                }
            }
            Action::Destroy => {}
            Action::Credit {
                channel,
                reservation,
            } => {
                if self
                    .channel_ref_record(channel)
                    .is_ok_and(|record| record.phase == Phase::Ready && !record.draining)
                    && self.message_record(reservation).is_ok()
                {
                    if let Some(record) = self.messages[reservation.slot].record.as_mut() {
                        record.kind = MessageKind::Credit {
                            source: channel,
                            granted: true,
                        };
                    }
                    let record = self.channels[channel.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?;
                    record.credit_due = record.credit_due.checked_sub(1).ok_or(Error::Conflict)?;
                    record.allowance = record.allowance.checked_add(1).ok_or(Error::Overflow)?;
                } else {
                    self.free_message(reservation);
                }
            }
            Action::Data { channel, source } => {
                if self.channel_ref_record(channel).is_ok()
                    && let Some(record) = self.channels[channel.slot].record.as_mut()
                    && record.receive == AppReceive::Writing(output.serial)
                    && record.phase == Phase::Ready
                {
                    record.receive = AppReceive::Waiting(output.serial);
                }
                if let Some((source, tx, work)) = source
                    && self.channel_ref_record(source).is_ok()
                    && let Some(record) = self.channels[source.slot].record.as_mut()
                    && record.phase == Phase::Ready
                    && record.tx[usize::from(tx)].is_some_and(|pending| {
                        pending.serial == work && matches!(pending.state, TxState::LoopWriting)
                    })
                {
                    record.tx[usize::from(tx)] = None;
                    if !record.draining {
                        record.credit_due =
                            record.credit_due.checked_add(1).ok_or(Error::Overflow)?;
                    }
                    drained_source = Some(source);
                }
            }
        }
        self.clients[output.client.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .pending = None;
        if let Some(source) = drained_source {
            self.finish_draining(source)?;
        }
        self.cleanup(output.channel);
        Ok(())
    }
    /// Bounded metadata needed by a physical owner before any socket admission.
    #[must_use]
    pub fn channel_capacity(&self) -> usize {
        self.channels.len()
    }
    /// Retire an actual expired original explicit Destroy drain. This grants no
    /// peer ACK or successful send result; queued/admitted work is cancelled.
    pub fn expire_destroy(&mut self, channel: Channel<'id>) -> Result<(), Error> {
        if !self.channel_record(channel)?.draining {
            return Err(Error::StaleGeneration);
        }
        self.close_channel(channel.reference, false)
    }
    fn finish_draining(&mut self, channel: ChannelRef) -> Result<(), Error> {
        if self
            .channel_ref_record(channel)
            .is_ok_and(|record| record.draining && record.tx.iter().all(Option::is_none))
        {
            self.close_channel(channel, false)?;
        }
        Ok(())
    }
    fn known(&self, channel: ChannelRef) -> bool {
        self.channel_ref_record(channel).is_ok_and(|record| !record.incoming || record.announced) || self.clients.get(channel.client.slot).and_then(|slot| slot.record).filter(|record| record.serial == channel.client.serial).and_then(|record| record.pending).is_some_and(|pending| matches!(pending.action, Action::Incoming(original) if original == channel))
    }
    fn close_channel(&mut self, channel: ChannelRef, notify: bool) -> Result<(), Error> {
        let record = *self.channel_ref_record(channel)?;
        if record.phase == Phase::Closing {
            return Ok(());
        }
        let other = match record.side {
            Side::Loop(other) => Some(other),
            _ => None,
        };
        self.close_one(channel, notify);
        if let Some(other) = other
            && self.channel_ref_record(other).is_ok()
        {
            self.close_one(other, true);
        }
        self.cleanup(channel);
        if let Some(other) = other {
            self.cleanup(other);
        }
        Ok(())
    }
    fn close_one(&mut self, channel: ChannelRef, notify: bool) {
        let known = self.known(channel);
        if let Some(record) = self
            .channels
            .get_mut(channel.slot)
            .and_then(|slot| slot.record.as_mut())
            .filter(|record| record.serial == channel.serial && record.client == channel.client)
        {
            // The local application already detached this raw name when it
            // requested a drain. A late peer failure must not send an old raw
            // Destroy to a replacement endpoint using the same number.
            let notify = notify && !record.draining;
            record.phase = Phase::Closing;
            record.draining = false;
            record.destroy_due = notify
                && known
                && self
                    .clients
                    .get(channel.client.slot)
                    .and_then(|slot| slot.record)
                    .is_some_and(|client| client.serial == channel.client.serial);
            record.create_due = false;
            record.credit_due = 0;
            record.allowance = 0;
            record.tx = [None; 4];
            record.receive = AppReceive::Ready;
            record.peer_receive = None;
        }
        for slot in 0..self.messages.len() {
            if let Some(record) = self.messages[slot].record {
                let related = match record.kind {
                    MessageKind::Credit { source, .. } | MessageKind::Remote { source, .. } => {
                        source == channel
                    }
                    MessageKind::Loop { source, target, .. } => {
                        source == channel || target == channel
                    }
                    MessageKind::Peer { target, .. } => target == channel,
                };
                if related {
                    self.free_message(MessageRef {
                        slot,
                        serial: record.serial,
                    });
                }
            }
        }
    }
    fn cleanup(&mut self, channel: ChannelRef) {
        let Ok(record) = self.channel_ref_record(channel) else {
            return;
        };
        let remote = matches!(
            record.side,
            Side::Remote { started: true, .. } | Side::Remote { binding: 1.., .. }
        );
        let pending_output = self
            .clients
            .get(channel.client.slot)
            .and_then(|slot| slot.record)
            .filter(|client| client.serial == channel.client.serial)
            .and_then(|client| client.pending)
            .is_some_and(|pending| pending.output.channel == channel);
        // Keep the typed peer/output owner until its original debts retire.
        // Raw-number reuse is checked separately: a detached local name does
        // not keep a live binding merely because peer teardown is pending.
        if record.phase == Phase::Closing && !record.destroy_due && !remote && !pending_output {
            self.channels[channel.slot].record = None;
        }
    }
    /// Retire only after this exact native MQ and its original immutable cursor
    /// stopped. Ports revoke, loop partners get real destroy intents, and remote
    /// close/cancel effects remain explicit. No old output reaches a new epoch.
    pub fn detach(&mut self, client: Client<'id>) -> Result<Loss<'id>, Error> {
        let original = *self.client_record(client)?;
        self.clients[client.reference.slot].record = None;
        for port in self.ports.iter_mut() {
            if port
                .record
                .is_some_and(|port| port.client == client.reference)
            {
                port.record = None;
            }
        }
        let channels = self
            .channels
            .iter()
            .filter(|slot| {
                slot.record
                    .is_some_and(|record| record.client == client.reference)
            })
            .count();
        for slot in 0..self.channels.len() {
            if let Some(record) = self.channels[slot].record
                && record.client == client.reference
            {
                let channel = Self::channel_ref(slot, record);
                if record.phase == Phase::Closing {
                    // Old destroy output has stopped with this exact MQ too.
                    self.close_one(channel, false);
                } else {
                    self.close_channel(channel, false)?;
                }
                self.cleanup(channel);
            }
        }
        Ok(Loss {
            client,
            channels,
            pending: original.pending.map(|pending| pending.output),
            exposed: original.pending.is_some_and(|pending| pending.exposed),
        })
    }
    /// Dispatch one actual remote-open intent. It grants no local credit; only a
    /// correctly bound actual peer owner's OPEN proof can finish it.
    pub fn next_open(&mut self) -> Option<Open<'id>> {
        for slot in 0..self.channels.len() {
            if let Some(record) = self.channels[slot].record
                && record.phase == Phase::Opening
                && matches!(
                    record.side,
                    Side::Remote {
                        started: false,
                        binding: 0,
                        ..
                    }
                )
            {
                let channel = self.channel(Self::channel_ref(slot, record));
                if let Some(record) = self.channels[slot].record.as_mut() {
                    record.side = Side::Remote {
                        started: true,
                        binding: 0,
                        close_started: false,
                    };
                }
                return Some(Open { channel });
            }
        }
        None
    }
    fn peer_check<'peer>(
        &self,
        binding: Binding<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<&ChannelRecord, Error> {
        let record = self.channel_record(binding.channel)?;
        if !matches!(record.side, Side::Remote { binding: serial, .. } if serial == binding.serial && serial != 0)
            || !owner.application_matches(binding.application)
        {
            return Err(Error::StaleGeneration);
        }
        let address = owner.address();
        if address.local_peer != self.local
            || address.remote_peer != record.peer
            || address.port != record.port
        {
            return Err(Error::Authentication);
        }
        Ok(record)
    }
    /// Bind an actual completed outgoing peer channel, including exact local,
    /// expected remote and port. No supplied bool/outcome can forge OPEN success.
    pub fn peer_opened<'peer>(
        &mut self,
        open: Open<'id>,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<Binding<'id, 'peer>, Error> {
        let record = *self.channel_record(open.channel)?;
        if record.phase != Phase::Opening
            || !matches!(
                record.side,
                Side::Remote {
                    started: true,
                    binding: 0,
                    ..
                }
            )
        {
            return Err(Error::StaleGeneration);
        }
        let address = owner.address();
        if owner.phase() != peer::Phase::Ready {
            return Err(Error::NotReady);
        }
        if owner.is_listener()
            || address.local_peer != self.local
            || address.remote_peer != record.peer
            || address.port != record.port
        {
            return Err(Error::Authentication);
        }
        let limit = self.limits.remote_payload_bytes.min(owner.send_capacity());
        if limit < 4 || owner.receive_capacity() < 4 {
            return Err(Error::TooLarge);
        }
        let serial = self.next_binding.checked_add(1).ok_or(Error::Overflow)?;
        let application = owner.claim_application()?;
        let active = self.channels[open.channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        active.phase = Phase::Ready;
        active.side = Side::Remote {
            started: false,
            binding: serial,
            close_started: false,
        };
        active.credit_due = self.limits.window;
        active.payload_limit = limit;
        self.next_binding = serial;
        Ok(Binding {
            channel: open.channel,
            serial,
            application,
        })
    }
    /// Attach an actual incoming ready peer endpoint to a real registered local
    /// application port, then retain its ordinary incoming low-half announcement.
    pub fn accept_peer<'peer>(
        &mut self,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<Binding<'id, 'peer>, Error> {
        let address = owner.address();
        if owner.phase() != peer::Phase::Ready || !owner.is_listener() {
            return Err(Error::NotReady);
        }
        if address.local_peer != self.local {
            return Err(Error::Authentication);
        }
        let port = self.listener(address.port).ok_or(Error::NotFound)?;
        let slot = self
            .channels
            .iter()
            .position(|slot| slot.record.is_none())
            .ok_or(Error::Capacity)?;
        let wire = self
            .client_record(self.client(port.client))?
            .next_incoming
            .ok_or(Error::Capacity)?;
        let serial = self.next_channel.checked_add(1).ok_or(Error::Overflow)?;
        let binding = self.next_binding.checked_add(1).ok_or(Error::Overflow)?;
        let limit = self.limits.remote_payload_bytes.min(owner.send_capacity());
        if limit < 4 || owner.receive_capacity() < 4 {
            return Err(Error::TooLarge);
        }
        let application = owner.claim_application()?;
        let record = self.new_channel(
            serial,
            port.client,
            wire,
            address.remote_peer,
            address.port,
            Side::Remote {
                started: false,
                binding,
                close_started: false,
            },
            Phase::Ready,
            true,
            limit,
        );
        let channel = self.channel(Self::channel_ref(slot, record));
        self.channels[slot].record = Some(record);
        self.clients[port.client.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .next_incoming = wire
            .checked_add(1)
            .filter(|next| *next < CLIENT_CHANNEL_BOUNDARY);
        self.next_channel = serial;
        self.next_binding = binding;
        self.statistics.add(crate::statistics::Metric::Channels, 1);
        Ok(Binding {
            channel,
            serial: binding,
            application,
        })
    }
    /// One original dispatched open whose application source closed before
    /// binding. The external port cancels/stops that actual job, then calls
    /// open_failed; repeated observation is the same original cancellation intent.
    #[must_use]
    pub fn canceling_open(&self) -> Option<Open<'id>> {
        self.channels
            .iter()
            .enumerate()
            .find_map(|(slot, channel)| {
                channel
                    .record
                    .filter(|record| {
                        record.phase == Phase::Closing
                            && matches!(
                                record.side,
                                Side::Remote {
                                    started: true,
                                    binding: 0,
                                    ..
                                }
                            )
                    })
                    .map(|record| Open {
                        channel: self.channel(Self::channel_ref(slot, record)),
                    })
            })
    }
    /// Actual failed/canceled external open has stopped its original peer work.
    /// This produces a real local destroy intent, never synthetic initial credits.
    pub fn open_failed(&mut self, open: Open<'id>) -> Result<(), Error> {
        let record = *self.channel_record(open.channel)?;
        if !matches!(
            record.side,
            Side::Remote {
                started: true,
                binding: 0,
                ..
            }
        ) {
            return Err(Error::StaleGeneration);
        }
        self.channels[open.channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .side = Side::Remote {
            started: false,
            binding: 0,
            close_started: false,
        };
        if record.phase != Phase::Closing {
            self.close_channel(open.channel.reference, true)?;
        }
        self.cleanup(open.channel.reference);
        Ok(())
    }
    fn queued_remote_head(channel: &ChannelRecord) -> Option<u64> {
        channel
            .tx
            .iter()
            .flatten()
            .filter(|pending| matches!(pending.state, TxState::RemoteQueued))
            .map(|pending| pending.serial)
            .min()
    }
    /// One original retained remote payload, without changing peer ownership.
    #[must_use]
    pub fn next_send(&self) -> Option<Sending<'id, '_>> {
        self.next_send_where(|_| true)
    }
    /// Select among each ready channel's oldest unadmitted payload. Eligibility
    /// cannot bypass an earlier queued payload on the SAME channel. A blocked
    /// channel need not hold unrelated channels; accepted candidates retain the
    /// original global order. The four existing TX slots supply the head check,
    /// with no new queue, cursor, allocation or peer-admission authority.
    #[must_use]
    pub fn next_send_where(
        &self,
        mut eligible: impl FnMut(&Sending<'id, '_>) -> bool,
    ) -> Option<Sending<'id, '_>> {
        self.messages
            .iter()
            .enumerate()
            .filter_map(|(slot, message)| {
                let record = message.record?;
                let MessageKind::Remote { source, tx, work } = record.kind else {
                    return None;
                };
                let channel = self.channel_ref_record(source).ok()?;
                if channel.phase != Phase::Ready || Self::queued_remote_head(channel) != Some(work)
                {
                    return None;
                }
                Some((
                    record.order,
                    Sending {
                        effect: Send {
                            channel: self.channel(source),
                            message: MessageRef {
                                slot,
                                serial: record.serial,
                            },
                            tx,
                            work,
                        },
                        payload: &message.bytes[..record.length],
                        priority: record.priority,
                    },
                ))
            })
            .filter(|(_, sending)| eligible(sending))
            .min_by_key(|(order, _)| *order)
            .map(|(_, sending)| sending)
    }
    /// Commit only a new actual peer Send whose original stored payload matches
    /// byte-for-byte. Shared service storage frees only after that real copy owns it.
    pub fn send_admitted<'peer>(
        &mut self,
        effect: Send<'id>,
        binding: Binding<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
        send: peer::Send<'peer>,
    ) -> Result<Admitted<'id, 'peer>, Error> {
        let channel = *self.peer_check(binding, owner)?;
        if effect.channel != binding.channel
            || channel.phase != Phase::Ready
            || send.scope() != binding.application.scope()
            || send.value() <= channel.peer_last_send
            || Self::queued_remote_head(&channel) != Some(effect.work)
        {
            return Err(Error::StaleGeneration);
        }
        let pending = channel.tx[usize::from(effect.tx)]
            .filter(|pending| {
                pending.serial == effect.work && matches!(pending.state, TxState::RemoteQueued)
            })
            .ok_or(Error::StaleGeneration)?;
        let message = self.message_record(effect.message)?;
        if !matches!(message.kind, MessageKind::Remote { source, tx, work } if source == effect.channel.reference && tx == effect.tx && work == effect.work)
            || owner.send_payload(send)?
                != &self.messages[effect.message.slot].bytes[..message.length]
        {
            return Err(Error::Authentication);
        }
        self.channels[effect.channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .tx[usize::from(effect.tx)] = Some(Tx {
            serial: pending.serial,
            state: TxState::RemoteAdmitted(send.value()),
        });
        self.channels[effect.channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .peer_last_send = send.value();
        self.free_message(effect.message);
        Ok(Admitted {
            binding,
            tx: effect.tx,
            work: effect.work,
            send,
        })
    }
    /// Observe the actual current original peer owner's terminal state. A public
    /// caller-constructed Completion/outcome label is never accepted as evidence.
    pub fn send_completed<'peer>(
        &mut self,
        admitted: Admitted<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<peer::Outcome, Error> {
        let record = *self.peer_check(admitted.binding, owner)?;
        if record.phase != Phase::Ready || record.tx[usize::from(admitted.tx)].is_none_or(|pending| pending.serial != admitted.work || !matches!(pending.state, TxState::RemoteAdmitted(value) if value == admitted.send.value())) { return Err(Error::StaleGeneration); }
        let outcome = owner.completion_for(admitted.send)?.outcome;
        if outcome == peer::Outcome::PeerAccepted {
            let record = self.channels[admitted.binding.channel.reference.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?;
            record.tx[usize::from(admitted.tx)] = None;
            if !record.draining {
                record.credit_due = record.credit_due.checked_add(1).ok_or(Error::Overflow)?;
            }
            self.finish_draining(admitted.binding.channel.reference)?;
        } else {
            self.close_channel(admitted.binding.channel.reference, true)?;
        }
        Ok(outcome)
    }
    /// Copy one actual peer-owned next in-order packet before committing that
    /// peer owner's local handoff. The external port retains the returned delivery.
    pub fn receive_peer<'peer>(
        &mut self,
        binding: Binding<'id, 'peer>,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<PeerDelivery<'id, 'peer>, Error> {
        let channel = *self.peer_check(binding, owner)?;
        if owner.phase() == peer::Phase::Closed {
            self.close_channel(binding.channel.reference, true)?;
            return Err(Error::Closed);
        }
        if channel.phase != Phase::Ready || channel.draining || channel.peer_receive.is_some() {
            return Err(Error::WouldBlock);
        }
        let incoming = owner.peek_delivery().ok_or(Error::WouldBlock)?;
        let payload = incoming.payload;
        if payload.len() > self.limits.remote_payload_bytes {
            self.close_channel(binding.channel.reference, true)?;
            return Err(Error::TooLarge);
        }
        if (Response::Data {
            channel: channel.wire,
            priority: 0,
            messages: payload,
        })
        .encoded_len()
        .is_err()
        {
            self.close_channel(binding.channel.reference, true)?;
            return Err(Error::Malformed);
        }
        let slot = channel.client.slot;
        if self.messages[slot].record.is_some() {
            return Err(Error::Capacity);
        }
        if self.messages[slot].bytes.len() < payload.len() {
            return Err(Error::TooLarge);
        }
        let serial = self.next_message.checked_add(1).ok_or(Error::Overflow)?;
        let work = self.next_work.checked_add(1).ok_or(Error::Overflow)?;
        let length = payload.len();
        self.messages[slot].bytes[..length].copy_from_slice(payload);
        let received = incoming.received;
        let delivery = match owner.deliver(received) {
            Ok(delivery) => delivery,
            Err(error) => {
                self.messages[slot].bytes[..length].fill(0);
                return Err(error);
            }
        };
        self.messages[slot].record = Some(MessageRecord {
            serial,
            length,
            order: work,
            priority: 0,
            kind: MessageKind::Peer {
                target: binding.channel.reference,
                work,
            },
        });
        self.channels[binding.channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .peer_receive = Some(PeerReceive {
            serial: work,
            done_due: false,
        });
        self.next_message = serial;
        self.next_work = work;
        Ok(PeerDelivery {
            binding,
            work,
            delivery,
        })
    }
    /// One real application's receive_done awaiting its original peer handoff.
    #[must_use]
    pub fn next_receive_done(&self) -> Option<ReceiveDone<'id>> {
        self.channels
            .iter()
            .enumerate()
            .find_map(|(slot, channel)| {
                let record = channel.record?;
                let received = record.peer_receive.filter(|received| received.done_due)?;
                let Side::Remote { binding, .. } = record.side else {
                    return None;
                };
                Some(ReceiveDone {
                    channel: self.channel(Self::channel_ref(slot, record)),
                    binding,
                    work: received.serial,
                })
            })
    }
    /// Release only the actual original peer delivery after actual local app ACK.
    pub fn peer_receive_done<'peer>(
        &mut self,
        effect: ReceiveDone<'id>,
        delivery: PeerDelivery<'id, 'peer>,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<(), Error> {
        let record = self.peer_check(delivery.binding, owner)?;
        if effect.channel != delivery.binding.channel
            || effect.binding != delivery.binding.serial
            || effect.work != delivery.work
            || record
                .peer_receive
                .is_none_or(|received| received.serial != effect.work || !received.done_due)
        {
            return Err(Error::StaleGeneration);
        }
        owner.receive_done(delivery.delivery)?;
        self.channels[effect.channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .peer_receive = None;
        Ok(())
    }
    /// Dispatch one actual remote-close intent. The original Binding remains
    /// outside service tables until its peer owner and physical attempts retire.
    pub fn next_close(&mut self) -> Option<Close<'id>> {
        for slot in 0..self.channels.len() {
            let Some(record) = self.channels[slot].record else {
                continue;
            };
            if record.phase != Phase::Closing {
                continue;
            }
            let Side::Remote {
                started,
                binding,
                close_started: false,
            } = record.side
            else {
                continue;
            };
            if binding == 0 {
                continue;
            }
            if let Some(active) = self.channels[slot].record.as_mut() {
                active.side = Side::Remote {
                    started,
                    binding,
                    close_started: true,
                };
            }
            return Some(Close {
                channel: self.channel(Self::channel_ref(slot, record)),
                binding,
            });
        }
        None
    }
    /// Commit only actual original peer retirement, with no pending physical
    /// attempt and the same exclusive application claim/expected peer identity.
    pub fn peer_closed<'peer>(
        &mut self,
        effect: Close<'id>,
        binding: Binding<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<(), Error> {
        let record = self.peer_check(binding, owner)?;
        if effect.channel != binding.channel
            || effect.binding != binding.serial
            || record.phase != Phase::Closing
            || !matches!(
                record.side,
                Side::Remote {
                    close_started: true,
                    ..
                }
            )
        {
            return Err(Error::StaleGeneration);
        }
        if owner.phase() != peer::Phase::Closed || owner.pending().is_some() {
            return Err(Error::NotReady);
        }
        self.channels[effect.channel.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .side = Side::Remote {
            started: false,
            binding: 0,
            close_started: false,
        };
        self.cleanup(effect.channel.reference);
        Ok(())
    }
    /// Actual remote channel disappeared; preserve real local destroy output and
    /// then drive next_close/peer_closed using its original claimed peer owner.
    pub fn peer_lost<'peer>(
        &mut self,
        binding: Binding<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<(), Error> {
        self.peer_check(binding, owner)?;
        if owner.phase() != peer::Phase::Closed {
            return Err(Error::NotReady);
        }
        self.close_channel(binding.channel.reference, true)
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service/identity_tests.rs"]
mod identity_tests;
