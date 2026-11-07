//! Caller-storage channel/port state for GNUnet v0.29.1's ordinary CADET CLIENT MQ.
//! Physical loss retires every channel and never replays application data. Open
//! logical ports remain available for explicit announcement on the next MQ.

use core::{fmt, ptr};
use gnunet_types::Error;
use gnunet_wire::official::cadet::{
    CLIENT_CHANNEL_BOUNDARY, MAX_APPLICATION_MESSAGE_SIZE, Request, Response,
};

/// Distinct nonzero-sized identity exclusively borrowed by one client lifetime.
/// Moving the client is safe; copied channel/operation tokens retain this owner.
#[derive(Default)]
pub struct Instance {
    marker: u8,
}
impl Instance {
    /// Reserve one identity without a global counter or allocation.
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
        f.write_str("Instance")
    }
}

/// One original physical MQ generation; numeric equality is diagnostic only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch<'a> {
    brand: Brand<'a>,
    serial: u64,
}
impl Epoch<'_> {
    /// Diagnostic source generation, never an official CADET field.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// Logical listening port, retaining its identity across physical reconnects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Port<'a> {
    brand: Brand<'a>,
    slot: usize,
    serial: u64,
}
impl Port<'_> {
    /// Diagnostic allocation generation, not a wire port hash or authority.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// Original channel generation. Wire identifiers alone cannot select a new
/// channel which later occupies the same caller storage slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel<'a> {
    epoch: Epoch<'a>,
    slot: usize,
    serial: u64,
    wire: u32,
}
impl<'a> Channel<'a> {
    /// Actual channel number used by the original service MQ.
    #[must_use]
    pub const fn wire_id(self) -> u32 {
        self.wire
    }
    /// Diagnostic Rust allocation generation; never sent to the service.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
    /// Original physical MQ which owns this channel.
    #[must_use]
    pub const fn epoch(self) -> Epoch<'a> {
        self.epoch
    }
}
/// One received outer LOCAL_DATA packet, requiring exactly one receive_done.
/// A token cannot acknowledge a subsequent packet or another channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery<'a> {
    channel: Channel<'a>,
    serial: u64,
}
impl<'a> Delivery<'a> {
    /// Original channel of the unacknowledged application packet.
    #[must_use]
    pub const fn channel(self) -> Channel<'a> {
        self.channel
    }
}
/// Diagnostic kind of one original encoded outgoing frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransmitKind {
    /// Announce an original logical port on the current MQ.
    PortOpen,
    /// Withdraw one logical listening port.
    PortClose,
    /// Request an outbound channel; no create-confirmation exists on IPC.
    ChannelCreate,
    /// Retire a local or outbound channel in ordered MQ traffic.
    ChannelDestroy,
    /// Application bytes using one original service-granted local credit.
    Data,
    /// Confirm application processing of exactly one original received packet.
    ReceiveDone,
    /// Configure the original channel's explicit one-shot peer-message drop.
    DropMessage,
    /// Reject an incoming channel whose logical port is no longer open.
    RejectIncoming,
}
/// One original copied outgoing frame, scoped to this exact pending transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmit<'a> {
    epoch: Epoch<'a>,
    serial: u64,
    kind: TransmitKind,
}
impl<'a> Transmit<'a> {
    /// Diagnostic serial, not an acknowledgement or on-wire request number.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
    /// Original local operation represented by these immutable bytes.
    #[must_use]
    pub const fn kind(self) -> TransmitKind {
        self.kind
    }
    /// Original physical MQ; only that host owner may complete this frame.
    #[must_use]
    pub const fn epoch(self) -> Epoch<'a> {
        self.epoch
    }
}
/// Exact encoded frame lent from caller output. Copy it immutably before any
/// later preparation reuses that storage. Exactly one preparation may be pending.
pub struct Prepared<'a, 'bytes> {
    transmit: Transmit<'a>,
    bytes: &'bytes [u8],
}
impl<'a, 'bytes> Prepared<'a, 'bytes> {
    /// Original host write token.
    #[must_use]
    pub const fn transmit(&self) -> Transmit<'a> {
        self.transmit
    }
    /// Complete official IPC bytes, with no Rust generation field.
    #[must_use]
    pub const fn bytes(&self) -> &'bytes [u8] {
        self.bytes
    }
}

/// Local direction of a channel number, not a message-delivery direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Client-assigned number at or above 0x80000000.
    Outbound,
    /// Service-assigned number strictly below 0x80000000, including 0.
    Incoming,
}
/// Current local channel observations. None asserts end-to-end delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelInfo {
    /// Actual original wire channel number.
    pub wire_id: u32,
    /// Peer identity supplied to/by the original service MQ.
    pub peer: [u8; 32],
    /// Original channel port hash.
    pub port: [u8; 64],
    /// Raw incoming options; current official outbound creation always uses 0.
    pub options: u32,
    /// Number assignment direction.
    pub direction: Direction,
    /// Actual service ACK credits not yet reserved by a prepared outgoing frame.
    pub send_credit: u32,
    /// Application still owes receive_done for an original outer packet.
    pub receive_pending: bool,
    /// Ordered local destruction is prepared but not yet written.
    pub closing: bool,
}
#[derive(Clone, Copy)]
struct PortRecord {
    hash: [u8; 64],
    serial: u64,
    announced: Option<u64>,
    closing: bool,
}
/// Caller-owned slot for one logical port. Empty slots may be safely reused;
/// every new allocation receives a different checked generation.
#[derive(Clone, Copy)]
pub struct PortSlot {
    record: Option<PortRecord>,
}
impl PortSlot {
    /// Empty fixed storage without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl Default for PortSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
struct ChannelRecord {
    wire: u32,
    serial: u64,
    peer: [u8; 32],
    port: [u8; 64],
    options: u32,
    direction: Direction,
    credit: u32,
    receive: Option<u64>,
    ready: bool,
    closing: bool,
}
/// Caller-owned bounded channel metadata. Payload bytes remain with the host's
/// original received frame, never an implicit heap queue in this owner.
#[derive(Clone, Copy)]
pub struct ChannelSlot {
    record: Option<ChannelRecord>,
}
impl ChannelSlot {
    /// Empty fixed storage without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl Default for ChannelSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Explicit local resource policy. It does not impose invented protocol bits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum raw sum of nested application frames in one LOCAL_DATA envelope.
    /// The official per-inner-message 64348-byte bound is enforced by the codec.
    pub max_payload_bytes: usize,
    /// Maximum unreserved local send credits retained for any channel.
    pub max_send_credit: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 65535 - 12,
            max_send_credit: u32::MAX,
        }
    }
}
/// Reason a valid late/irrelevant service notification changed no state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ignored {
    /// Destroy/ACK/DATA for a channel which was already retired.
    UnknownChannel,
    /// A service creation used the client-assigned number range.
    InvalidIncomingNumber,
    /// A closing channel does not receive additional application callbacks.
    ClosingChannel,
}
/// Borrowed original service event. Retain the original raw frame while using
/// Data.messages; call receive_done only after handling all its inner messages.
pub enum Inbound<'a, 'bytes> {
    /// Actual incoming channel on one currently announced logical port.
    Incoming {
        /// Original new channel token.
        channel: Channel<'a>,
        /// Original listening port token.
        port: Port<'a>,
    },
    /// Actual service destruction of a known original channel.
    Destroyed(Channel<'a>),
    /// Exactly one actual LOCAL_ACK increased the local send window.
    Credit {
        /// Original channel.
        channel: Channel<'a>,
        /// Current unreserved local send credits.
        available: u32,
    },
    /// Original unacknowledged service packet; no data copy is made.
    Data {
        /// Original per-packet processing token.
        delivery: Delivery<'a>,
        /// Raw priority/preference bits from the service.
        priority: u32,
        /// Actual complete nested application frames.
        messages: &'bytes [u8],
    },
    /// Native host must send ordered ChannelDestroy when output becomes free.
    RejectedIncoming {
        /// Actual service-assigned raw channel number.
        channel: u32,
    },
    /// Valid late notification which does not select a current object.
    Ignored(Ignored),
}
/// One actual full local IPC write; it proves neither peer receipt nor processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Written<'a> {
    /// Original immutable frame token.
    pub transmit: Transmit<'a>,
}
/// Original pending-frame exposure retained through physical MQ loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredTransmit<'a> {
    /// Original frame token.
    pub transmit: Transmit<'a>,
    /// At least one original byte was physically exposed.
    pub exposed: bool,
}
/// Retired physical source facts. All old channels/deliveries are now stale;
/// logical open ports may be announced again, application data may not replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Loss<'a> {
    /// Original retired MQ generation.
    pub epoch: Epoch<'a>,
    /// Original channels retired, including unfinished creation.
    pub channels: usize,
    /// Original pending frame and its actual exposure prefix.
    pub pending: Option<RetiredTransmit<'a>>,
}

#[derive(Clone, Copy)]
enum Action<'a> {
    PortOpen { port: Port<'a>, fresh: bool },
    PortClose(Port<'a>),
    ChannelCreate(Channel<'a>),
    ChannelDestroy(Channel<'a>),
    DropMessage,
    Data(Channel<'a>),
    Ack(Delivery<'a>),
    Reject,
}
#[derive(Clone, Copy)]
struct Pending<'a> {
    transmit: Transmit<'a>,
    action: Action<'a>,
    exposed: bool,
}

/// One pure CADET CLIENT owner. Exactly one immutable frame may be prepared for
/// the original physical MQ at a time. This bounds pending state and preserves
/// ordered full-write/cancellation semantics without hiding application queues.
pub struct Client<'id, 'slots> {
    brand: Brand<'id>,
    ports: &'slots mut [PortSlot],
    channels: &'slots mut [ChannelSlot],
    limits: Limits,
    epoch: Option<Epoch<'id>>,
    next_epoch: u64,
    next_object: u64,
    next_transmit: u64,
    next_delivery: u64,
    next_outbound: Option<u32>,
    pending: Option<Pending<'id>>,
}
impl<'id, 'slots> Client<'id, 'slots> {
    /// Borrow distinct owner identity and empty caller storage. This constructor
    /// performs no native connection and does not mint any service credit.
    pub fn new(
        instance: &'id mut Instance,
        ports: &'slots mut [PortSlot],
        channels: &'slots mut [ChannelSlot],
        limits: Limits,
    ) -> Result<Self, Error> {
        if channels.is_empty()
            || limits.max_payload_bytes > 65535 - 12
            || limits.max_send_credit == 0
        {
            return Err(Error::InvalidInput);
        }
        if ports.iter().any(|p| p.record.is_some()) || channels.iter().any(|c| c.record.is_some()) {
            return Err(Error::Conflict);
        }
        Ok(Self {
            brand: Brand(instance),
            ports,
            channels,
            limits,
            epoch: None,
            next_epoch: 0,
            next_object: 0,
            next_transmit: 0,
            next_delivery: 0,
            next_outbound: Some(CLIENT_CHANNEL_BOUNDARY),
            pending: None,
        })
    }
    /// Commit the host's newly connected original MQ. No protocol handshake or
    /// private INIT is emitted. Enumerate pending_port and announce each port.
    pub fn connected(&mut self) -> Result<Epoch<'id>, Error> {
        if self.epoch.is_some() || self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let serial = self.next_epoch.checked_add(1).ok_or(Error::Overflow)?;
        let epoch = Epoch {
            brand: self.brand,
            serial,
        };
        self.next_epoch = serial;
        self.epoch = Some(epoch);
        Ok(epoch)
    }
    /// Current original physical source, absent until connected or after loss.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.epoch
    }
    /// Whether an immutable outgoing frame still awaits full write/discard/loss.
    #[must_use]
    pub const fn pending_transmit(&self) -> Option<Transmit<'id>> {
        match self.pending {
            Some(p) => Some(p.transmit),
            None => None,
        }
    }
    /// One desired logical port not yet announced on this MQ. Scan is bounded
    /// by caller port storage and is needed only during initial/reconnection setup.
    #[must_use]
    pub fn pending_port(&self) -> Option<Port<'id>> {
        let epoch = self.epoch?;
        self.ports.iter().enumerate().find_map(|(slot, p)| {
            p.record
                .filter(|p| !p.closing && p.announced != Some(epoch.serial))
                .map(|p| Port {
                    brand: self.brand,
                    slot,
                    serial: p.serial,
                })
        })
    }
    /// Copy a current original channel's local state without changing credit.
    pub fn channel_info(&self, channel: Channel<'id>) -> Result<ChannelInfo, Error> {
        let r = self.channel_record(channel)?;
        Ok(ChannelInfo {
            wire_id: r.wire,
            peer: r.peer,
            port: r.port,
            options: r.options,
            direction: r.direction,
            send_credit: r.credit,
            receive_pending: r.receive.is_some(),
            closing: r.closing,
        })
    }
    /// Original immutable hash of a still-open logical port.
    pub fn port_hash(&self, port: Port<'id>) -> Result<[u8; 64], Error> {
        Ok(self.port_record(port)?.hash)
    }
    /// Whether this logical port was announced on the exact current MQ.
    pub fn port_announced(&self, port: Port<'id>) -> Result<bool, Error> {
        let announced = self.port_record(port)?.announced;
        Ok(self
            .epoch
            .is_some_and(|epoch| announced == Some(epoch.serial)))
    }
    /// Remove a desired port that has not been announced on the current MQ.
    /// This is useful while disconnected or before reconnect restoration. An
    /// announced port needs ordered prepare_port_close, since closing a port
    /// unknown to the service would cause the official service to drop the MQ.
    pub fn retire_unannounced_port(&mut self, port: Port<'id>) -> Result<(), Error> {
        let record = self.port_record(port)?;
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        if record.announced.is_some() {
            return Err(Error::Conflict);
        }
        self.ports[port.slot].record = None;
        Ok(())
    }
    fn port_record(&self, port: Port<'id>) -> Result<&PortRecord, Error> {
        if port.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        self.ports
            .get(port.slot)
            .and_then(|p| p.record.as_ref())
            .filter(|p| p.serial == port.serial)
            .ok_or(Error::StaleGeneration)
    }
    fn channel_record(&self, channel: Channel<'id>) -> Result<&ChannelRecord, Error> {
        if Some(channel.epoch) != self.epoch {
            return Err(Error::StaleGeneration);
        }
        self.channels
            .get(channel.slot)
            .and_then(|c| c.record.as_ref())
            .filter(|c| c.serial == channel.serial && c.wire == channel.wire)
            .ok_or(Error::StaleGeneration)
    }
    fn original(&self) -> Result<Epoch<'id>, Error> {
        self.epoch.ok_or(Error::Closed)
    }
    fn ready(&self) -> Result<Epoch<'id>, Error> {
        let epoch = self.original()?;
        if self.pending.is_some() {
            Err(Error::WouldBlock)
        } else {
            Ok(epoch)
        }
    }
    fn tx(&self, epoch: Epoch<'id>, kind: TransmitKind) -> Result<Transmit<'id>, Error> {
        Ok(Transmit {
            epoch,
            serial: self.next_transmit.checked_add(1).ok_or(Error::Overflow)?,
            kind,
        })
    }
    fn prepare<'bytes>(
        &mut self,
        request: Request<'_>,
        transmit: Transmit<'id>,
        action: Action<'id>,
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let size = request.encode(output)?;
        self.next_transmit = transmit.serial;
        self.pending = Some(Pending {
            transmit,
            action,
            exposed: false,
        });
        Ok(Prepared {
            transmit,
            bytes: &output[..size],
        })
    }
    /// Reserve a new logical port and encode its original announcement. No
    /// service success ACK exists for this operation; written is local only.
    pub fn prepare_port_open<'bytes>(
        &mut self,
        hash: [u8; 64],
        output: &'bytes mut [u8],
    ) -> Result<(Port<'id>, Prepared<'id, 'bytes>), Error> {
        let epoch = self.ready()?;
        if self
            .ports
            .iter()
            .any(|p| p.record.is_some_and(|p| p.hash == hash))
        {
            return Err(Error::Conflict);
        }
        let slot = self
            .ports
            .iter()
            .position(|p| p.record.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.next_object.checked_add(1).ok_or(Error::Overflow)?;
        let port = Port {
            brand: self.brand,
            slot,
            serial,
        };
        let tx = self.tx(epoch, TransmitKind::PortOpen)?;
        // Encode before changing either slot or sequence. Refusal is atomic.
        let size = Request::PortOpen { port: hash }.encode(output)?;
        self.ports[slot].record = Some(PortRecord {
            hash,
            serial,
            announced: None,
            closing: false,
        });
        self.next_object = serial;
        self.next_transmit = tx.serial;
        self.pending = Some(Pending {
            transmit: tx,
            action: Action::PortOpen { port, fresh: true },
            exposed: false,
        });
        Ok((
            port,
            Prepared {
                transmit: tx,
                bytes: &output[..size],
            },
        ))
    }
    /// Reannounce an existing desired logical port after physical reconnect.
    /// This does not restore any old channel or replay application payload.
    pub fn prepare_announce<'bytes>(
        &mut self,
        port: Port<'id>,
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let epoch = self.ready()?;
        let r = *self.port_record(port)?;
        if r.closing || r.announced == Some(epoch.serial) {
            return Err(Error::Conflict);
        }
        let tx = self.tx(epoch, TransmitKind::PortOpen)?;
        self.prepare(
            Request::PortOpen { port: r.hash },
            tx,
            Action::PortOpen { port, fresh: false },
            output,
        )
    }
    /// Begin ordered withdrawal. Incoming creations for this port are rejected
    /// immediately; existing channels remain alive, matching official behavior.
    pub fn prepare_port_close<'bytes>(
        &mut self,
        port: Port<'id>,
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let epoch = self.ready()?;
        let r = *self.port_record(port)?;
        if r.closing {
            return Err(Error::Conflict);
        }
        if r.announced != Some(epoch.serial) {
            return Err(Error::NotReady);
        }
        let tx = self.tx(epoch, TransmitKind::PortClose)?;
        let prepared = self.prepare(
            Request::PortClose { port: r.hash },
            tx,
            Action::PortClose(port),
            output,
        )?;
        self.ports[port.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .closing = true;
        Ok(prepared)
    }
    /// Reserve an outbound channel using the official high number range and
    /// options 0. It starts with zero credit; CREATE write is not remote acceptance.
    pub fn prepare_channel<'bytes>(
        &mut self,
        peer: [u8; 32],
        port: [u8; 64],
        output: &'bytes mut [u8],
    ) -> Result<(Channel<'id>, Prepared<'id, 'bytes>), Error> {
        let epoch = self.ready()?;
        let wire = self.next_outbound.ok_or(Error::Capacity)?;
        let slot = self
            .channels
            .iter()
            .position(|c| c.record.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.next_object.checked_add(1).ok_or(Error::Overflow)?;
        let channel = Channel {
            epoch,
            slot,
            serial,
            wire,
        };
        let tx = self.tx(epoch, TransmitKind::ChannelCreate)?;
        let size = Request::ChannelCreate {
            channel: wire,
            peer,
            port,
            options: 0,
        }
        .encode(output)?;
        self.channels[slot].record = Some(ChannelRecord {
            wire,
            serial,
            peer,
            port,
            options: 0,
            direction: Direction::Outbound,
            credit: 0,
            receive: None,
            ready: false,
            closing: false,
        });
        self.next_object = serial;
        self.next_outbound = wire.checked_add(1);
        self.next_transmit = tx.serial;
        self.pending = Some(Pending {
            transmit: tx,
            action: Action::ChannelCreate(channel),
            exposed: false,
        });
        Ok((
            channel,
            Prepared {
                transmit: tx,
                bytes: &output[..size],
            },
        ))
    }
    /// Queue local destruction only after earlier prepared frame ordering is
    /// settled. Already written application bytes are not rolled back.
    pub fn prepare_destroy<'bytes>(
        &mut self,
        channel: Channel<'id>,
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let epoch = self.ready()?;
        if self.channel_record(channel)?.closing {
            return Err(Error::Conflict);
        }
        let tx = self.tx(epoch, TransmitKind::ChannelDestroy)?;
        let prepared = self.prepare(
            Request::ChannelDestroy {
                channel: channel.wire,
            },
            tx,
            Action::ChannelDestroy(channel),
            output,
        )?;
        self.channels[channel.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .closing = true;
        Ok(prepared)
    }
    /// Configure the standard diagnostic drop on one original channel, without
    /// consuming send credit. The fixed C daemon compares the two opaque bytes
    /// directly with the outgoing peer header; callers supply that exact selector.
    /// `[0,0]` clears it. A whole IPC write acknowledges no actual future drop.
    pub fn prepare_drop_message<'bytes>(
        &mut self,
        channel: Channel<'id>,
        message_type_bytes: [u8; 2],
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let epoch = self.ready()?;
        let record = self.channel_record(channel)?;
        if record.closing {
            return Err(Error::Closed);
        }
        let tx = self.tx(epoch, TransmitKind::DropMessage)?;
        self.prepare(
            Request::DropMessage {
                channel: channel.wire,
                message_type_bytes,
            },
            tx,
            Action::DropMessage,
            output,
        )
    }
    /// Reserve one actual service ACK credit and encode one complete message.
    /// The public C client injects one nested message per packet; accepting only
    /// one outgoing message avoids silently dropping a concatenated tail there.
    /// Raw per-message priority/preference bits are preserved, including official
    /// unreliable preferences; no invented channel reliability flags are used.
    pub fn prepare_send<'bytes>(
        &mut self,
        channel: Channel<'id>,
        priority: u32,
        messages: &[u8],
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let epoch = self.ready()?;
        let r = self.channel_record(channel)?;
        if !r.ready || r.closing || r.credit == 0 {
            return Err(Error::WouldBlock);
        }
        if messages.len() > self.limits.max_payload_bytes {
            return Err(Error::Capacity);
        }
        if messages.len() < 4 || messages.len() > MAX_APPLICATION_MESSAGE_SIZE {
            return Err(Error::Malformed);
        }
        if usize::from(u16::from_be_bytes([messages[0], messages[1]])) != messages.len() {
            return Err(Error::Malformed);
        }
        let tx = self.tx(epoch, TransmitKind::Data)?;
        let prepared = self.prepare(
            Request::Data {
                channel: channel.wire,
                priority,
                messages,
            },
            tx,
            Action::Data(channel),
            output,
        )?;
        self.channels[channel.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .credit -= 1;
        Ok(prepared)
    }
    /// Release exactly the original outer packet after all nested messages have
    /// been handled. This is local processing credit, not remote delivery proof.
    pub fn prepare_receive_done<'bytes>(
        &mut self,
        delivery: Delivery<'id>,
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let epoch = self.ready()?;
        let r = self.channel_record(delivery.channel)?;
        if r.closing || r.receive != Some(delivery.serial) {
            return Err(Error::StaleGeneration);
        }
        let tx = self.tx(epoch, TransmitKind::ReceiveDone)?;
        self.prepare(
            Request::Ack {
                channel: delivery.channel.wire,
            },
            tx,
            Action::Ack(delivery),
            output,
        )
    }
    /// Reject an original incoming creation on an unregistered/closing port.
    /// Native hosts retain that received frame until this control can be queued.
    pub fn prepare_reject<'bytes>(
        &mut self,
        wire: u32,
        output: &'bytes mut [u8],
    ) -> Result<Prepared<'id, 'bytes>, Error> {
        let epoch = self.ready()?;
        if wire >= CLIENT_CHANNEL_BOUNDARY {
            return Err(Error::InvalidInput);
        }
        if self
            .channels
            .iter()
            .any(|c| c.record.is_some_and(|c| c.wire == wire))
        {
            return Err(Error::Conflict);
        }
        let tx = self.tx(epoch, TransmitKind::RejectIncoming)?;
        self.prepare(
            Request::ChannelDestroy { channel: wire },
            tx,
            Action::Reject,
            output,
        )
    }
    /// Record the first actual physical output prefix on the original MQ.
    /// Merely preparing or enqueueing immutable bytes must not call this method.
    pub fn exposed(&mut self, transmit: Transmit<'id>) -> Result<(), Error> {
        let pending = self
            .pending
            .as_mut()
            .filter(|p| p.transmit == transmit)
            .ok_or(Error::StaleGeneration)?;
        pending.exposed = true;
        Ok(())
    }
    /// Commit only an actual full original frame write. No Data state here is a
    /// remote application acknowledgement; send credit comes only from on_response.
    pub fn written(&mut self, transmit: Transmit<'id>) -> Result<Written<'id>, Error> {
        let pending = self
            .pending
            .filter(|p| p.transmit == transmit)
            .ok_or(Error::StaleGeneration)?;
        match pending.action {
            Action::PortOpen { port, .. } => {
                if self.port_record(port).is_ok() {
                    self.ports[port.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?
                        .announced = Some(transmit.epoch.serial);
                }
            }
            Action::PortClose(port) => {
                if self.port_record(port).is_ok() {
                    self.ports[port.slot].record = None;
                }
            }
            Action::ChannelCreate(channel) => {
                if self.channel_record(channel).is_ok() {
                    self.channels[channel.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?
                        .ready = true;
                }
            }
            Action::ChannelDestroy(channel) => {
                if self.channel_record(channel).is_ok() {
                    self.channels[channel.slot].record = None;
                }
            }
            Action::Ack(delivery) => {
                if self.channel_record(delivery.channel).is_ok() {
                    let r = self.channels[delivery.channel.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?;
                    if r.receive == Some(delivery.serial) {
                        r.receive = None;
                    }
                }
            }
            Action::Data(_) | Action::DropMessage | Action::Reject => {}
        }
        self.pending = None;
        Ok(Written { transmit })
    }
    /// Explicitly discard a frame only when its original host proves no byte was
    /// exposed. This rolls back its reservation; exposed data requires MQ loss
    /// or completion and can never be retried as known-unsent by this method.
    pub fn discard(&mut self, transmit: Transmit<'id>) -> Result<(), Error> {
        let pending = self
            .pending
            .filter(|p| p.transmit == transmit)
            .ok_or(Error::StaleGeneration)?;
        if pending.exposed {
            return Err(Error::OutcomeUnknown);
        }
        if let Action::Data(channel) = pending.action
            && let Ok(r) = self.channel_record(channel)
            && r.credit >= self.limits.max_send_credit
        {
            return Err(Error::Overflow);
        }
        match pending.action {
            Action::PortOpen { port, fresh: true } => {
                if self.port_record(port).is_ok() {
                    self.ports[port.slot].record = None;
                }
            }
            Action::PortClose(port) => {
                if self.port_record(port).is_ok() {
                    self.ports[port.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?
                        .closing = false;
                }
            }
            Action::ChannelCreate(channel) => {
                if self.channel_record(channel).is_ok() {
                    self.channels[channel.slot].record = None;
                }
            }
            Action::ChannelDestroy(channel) => {
                if self.channel_record(channel).is_ok() {
                    self.channels[channel.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?
                        .closing = false;
                }
            }
            Action::Data(channel) => {
                if self.channel_record(channel).is_ok() {
                    self.channels[channel.slot]
                        .record
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?
                        .credit += 1;
                }
            }
            Action::PortOpen { fresh: false, .. }
            | Action::Ack(_)
            | Action::DropMessage
            | Action::Reject => {}
        }
        self.pending = None;
        Ok(())
    }
    /// Apply one actual decoded response from exactly the supplied original MQ.
    /// A stale or foreign physical source refuses before examining wire IDs. Unknown
    /// late channel packets are ignored; duplicate live creation or receive-flow
    /// violations refuse atomically. Host must retain unaccepted bytes on refusal.
    pub fn on_response<'bytes>(
        &mut self,
        source: Epoch<'id>,
        response: Response<'bytes>,
    ) -> Result<Inbound<'id, 'bytes>, Error> {
        if Some(source) != self.epoch {
            return Err(Error::StaleGeneration);
        }
        let epoch = source;
        match response {
            Response::ChannelCreate {
                channel: wire,
                peer,
                port,
                options,
            } => {
                if wire >= CLIENT_CHANNEL_BOUNDARY {
                    return Ok(Inbound::Ignored(Ignored::InvalidIncomingNumber));
                }
                if self
                    .channels
                    .iter()
                    .any(|c| c.record.is_some_and(|c| c.wire == wire))
                {
                    return Err(Error::Conflict);
                }
                let Some((port_slot, p)) = self.ports.iter().enumerate().find_map(|(slot, p)| {
                    p.record
                        .filter(|p| {
                            p.hash == port && !p.closing && p.announced == Some(epoch.serial)
                        })
                        .map(|p| (slot, p))
                }) else {
                    return Ok(Inbound::RejectedIncoming { channel: wire });
                };
                let slot = self
                    .channels
                    .iter()
                    .position(|c| c.record.is_none())
                    .ok_or(Error::Capacity)?;
                let serial = self.next_object.checked_add(1).ok_or(Error::Overflow)?;
                let channel = Channel {
                    epoch,
                    slot,
                    serial,
                    wire,
                };
                self.channels[slot].record = Some(ChannelRecord {
                    wire,
                    serial,
                    peer,
                    port,
                    options,
                    direction: Direction::Incoming,
                    credit: 0,
                    receive: None,
                    ready: true,
                    closing: false,
                });
                self.next_object = serial;
                Ok(Inbound::Incoming {
                    channel,
                    port: Port {
                        brand: self.brand,
                        slot: port_slot,
                        serial: p.serial,
                    },
                })
            }
            Response::ChannelDestroy { channel: wire } => {
                let Some(slot) = self
                    .channels
                    .iter()
                    .position(|c| c.record.is_some_and(|c| c.wire == wire))
                else {
                    return Ok(Inbound::Ignored(Ignored::UnknownChannel));
                };
                let r = self.channels[slot].record.ok_or(Error::StaleGeneration)?;
                let channel = Channel {
                    epoch,
                    slot,
                    serial: r.serial,
                    wire,
                };
                self.channels[slot].record = None;
                Ok(Inbound::Destroyed(channel))
            }
            Response::Ack { channel: wire } => {
                let Some(slot) = self
                    .channels
                    .iter()
                    .position(|c| c.record.is_some_and(|c| c.wire == wire))
                else {
                    return Ok(Inbound::Ignored(Ignored::UnknownChannel));
                };
                let r = self.channels[slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                if r.closing {
                    return Ok(Inbound::Ignored(Ignored::ClosingChannel));
                }
                if !r.ready {
                    return Err(Error::NotReady);
                }
                if r.credit >= self.limits.max_send_credit {
                    return Err(Error::Capacity);
                }
                r.credit = r.credit.checked_add(1).ok_or(Error::Overflow)?;
                Ok(Inbound::Credit {
                    channel: Channel {
                        epoch,
                        slot,
                        serial: r.serial,
                        wire,
                    },
                    available: r.credit,
                })
            }
            Response::Data {
                channel: wire,
                priority,
                messages,
            } => {
                let Some(slot) = self
                    .channels
                    .iter()
                    .position(|c| c.record.is_some_and(|c| c.wire == wire))
                else {
                    return Ok(Inbound::Ignored(Ignored::UnknownChannel));
                };
                let r = self.channels[slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                if r.closing {
                    return Ok(Inbound::Ignored(Ignored::ClosingChannel));
                }
                if !r.ready {
                    return Err(Error::NotReady);
                }
                if r.receive.is_some() {
                    return Err(Error::WouldBlock);
                }
                if messages.len() > self.limits.max_payload_bytes {
                    return Err(Error::Capacity);
                }
                let serial = self.next_delivery.checked_add(1).ok_or(Error::Overflow)?;
                let channel = Channel {
                    epoch,
                    slot,
                    serial: r.serial,
                    wire,
                };
                r.receive = Some(serial);
                self.next_delivery = serial;
                Ok(Inbound::Data {
                    delivery: Delivery { channel, serial },
                    priority,
                    messages,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Commit actual physical retirement of this MQ. Call only after the host
    /// has closed/retired its original transport and immutable pending cursor.
    /// Old channels/deliveries/tokens become stale. Desired ports are retained,
    /// while an already requested local port close stays closed.
    pub fn lost(&mut self, source: Epoch<'id>) -> Result<Loss<'id>, Error> {
        if Some(source) != self.epoch {
            return Err(Error::StaleGeneration);
        }
        let epoch = source;
        let pending = self.pending.take();
        if let Some(Pending {
            action: Action::PortClose(port),
            ..
        }) = pending
            && self.port_record(port).is_ok()
        {
            self.ports[port.slot].record = None;
        }
        let mut channels = 0;
        for slot in self.channels.iter_mut() {
            if slot.record.take().is_some() {
                channels += 1;
            }
        }
        for slot in self.ports.iter_mut() {
            if let Some(port) = slot.record.as_mut() {
                port.announced = None;
                port.closing = false;
            }
        }
        self.epoch = None;
        Ok(Loss {
            epoch,
            channels,
            pending: pending.map(|p| RetiredTransmit {
                transmit: p.transmit,
                exposed: p.exposed,
            }),
        })
    }
}
