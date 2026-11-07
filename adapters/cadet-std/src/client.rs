use crate::{
    Channel, ChannelInfo, ChannelSlot, Delivery, Epoch, Error, Ignored, Instance, Loss, OwnedFrame,
    Port, PortSlot, Transmit, Written,
};
use gnunet_cadet::client::{Client as PureClient, Inbound as PureInbound, Limits as PureLimits};
use gnunet_client_host::{
    ConnectGuard, EndpointSource,
    channel::{Channel as NativeChannel, ConnectionStep},
};
use gnunet_service_runtime::{
    clock::RuntimeClock,
    framing::{Accounting, Budget, Class, Limits as FrameLimits, ReadStep, WriteProgress},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::cadet::{MAX_APPLICATION_MESSAGE_SIZE, Response};
use std::{
    future::poll_fn,
    io,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

/// Explicit resources for the native stream and its pure channel owner.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete ordinary IPC frame, from 108 through 65535 bytes.
    pub frame_bytes: usize,
    /// Maximum bytes offered to one actual read/write syscall, nonzero.
    pub io_slice_bytes: usize,
    /// Maximum complete inner-message string retained in one received envelope.
    /// Outgoing public API sends exactly one inner message, at most 64348 bytes.
    pub max_payload_bytes: usize,
    /// Maximum unreserved service-granted local send credit per channel.
    pub max_send_credit: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            max_payload_bytes: 65535 - 12,
            max_send_credit: u32::MAX,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), ProtocolError> {
        if !(108..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.max_payload_bytes > self.frame_bytes - 12
            || self.max_send_credit == 0
        {
            return Err(ProtocolError::Capacity);
        }
        Ok(())
    }
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn pure(self) -> PureLimits {
        PureLimits {
            max_payload_bytes: self.max_payload_bytes,
            max_send_credit: self.max_send_credit,
        }
    }
}

/// One actual received DATA frame and its original processing token.
/// Owning/dropping these bytes does not send receive_done or grant service credit.
pub struct Received<'id> {
    delivery: Delivery<'id>,
    priority: u32,
    frame: OwnedFrame,
}
impl<'id> Received<'id> {
    /// Original application-processing receipt; acknowledge it at most once.
    #[must_use]
    pub const fn delivery(&self) -> Delivery<'id> {
        self.delivery
    }
    /// Original channel selected by the exact physical source and wire number.
    #[must_use]
    pub const fn channel(&self) -> Channel<'id> {
        self.delivery.channel()
    }
    /// Raw service priority/preference field.
    #[must_use]
    pub const fn priority(&self) -> u32 {
        self.priority
    }
    /// Complete original nested application-message string, without a copy.
    #[must_use]
    pub fn messages(&self) -> &[u8] {
        &self.frame.bytes()[12..]
    }
    /// Complete original official IPC frame, including its DATA header.
    #[must_use]
    pub const fn frame(&self) -> &OwnedFrame {
        &self.frame
    }
}

/// Why this exact physical MQ was detached before retiring its pure epoch.
#[derive(Debug)]
pub enum LossCause {
    /// Clean native EOF between frames.
    Eof,
    /// Original native error, including partial-frame EOF.
    Io(io::Error),
    /// Original invalid/unsupported service response.
    Protocol(ProtocolError),
    /// Caller explicitly requested physical retirement and reconnect.
    Requested,
}
/// One original domain or physical event. None proves remote application receipt.
pub enum Step<'id> {
    /// Actual native stream attached; no private handshake is sent.
    Connected(Epoch<'id>),
    /// One exact immutable frame physically finished writing on its original MQ.
    Written(Written<'id>),
    /// Actual incoming channel accepted on an announced original logical port.
    Incoming {
        /// Original channel generation.
        channel: Channel<'id>,
        /// Original logical listening port.
        port: Port<'id>,
    },
    /// Actual service destruction of an original known channel.
    Destroyed(Channel<'id>),
    /// One actual service ACK granted local send credit.
    Credit {
        /// Original channel.
        channel: Channel<'id>,
        /// Current unreserved local send window.
        available: u32,
    },
    /// Actual owned application packet; receive_done remains explicitly owed.
    Data(Received<'id>),
    /// Incoming unregistered/closing-port channel has an ordered rejection queued.
    /// This event describes queue admission; only Written proves the local write.
    RejectedIncoming {
        /// Original physical source.
        source: Epoch<'id>,
        /// Raw original incoming channel number.
        channel: u32,
        /// Original queued destruction token.
        transmit: Transmit<'id>,
    },
    /// Valid late or irrelevant service input was consumed without new authority.
    Ignored {
        /// Original physical source.
        source: Epoch<'id>,
        /// Reason no current object was selected.
        reason: Ignored,
    },
    /// Resource/flow refusal changed no application state. Retry after freeing
    /// resources, or explicitly reconnect to retire this original input and MQ.
    Blocked {
        /// Original physical source.
        source: Epoch<'id>,
        /// Actual resource/flow refusal.
        reason: ProtocolError,
        /// The original complete received frame is retained.
        input_retained: bool,
    },
    /// Physical owner was detached before every old channel was retired.
    /// Open logical ports will be announced on the next actual attachment.
    Lost {
        /// Original pure epoch/pending-frame exposure facts.
        report: Loss<'id>,
        /// Original physical/protocol retirement cause.
        cause: LossCause,
        /// Retry selected by the original CLIENT source owner.
        retry_after: Duration,
    },
    /// Original socket connection attempt failed; source-domain retry is pending.
    ConnectRetry {
        /// Actual original attempt cause.
        error: io::Error,
        /// Actual selected delay.
        retry_after: Duration,
    },
    /// Current endpoint configuration could not be selected.
    Unavailable(Error),
    /// One actual native positive transfer, with no synthetic protocol result.
    Activity {
        /// Original physical source.
        source: Epoch<'id>,
        /// Actual native input bytes.
        read_bytes: usize,
        /// Actual native output bytes.
        written_bytes: usize,
    },
    /// Only this caller's observation wait elapsed; all owned work remains live.
    WaitDeadline,
    /// Explicit permanent closure; no subsequent native attempt is created.
    Closed,
}

enum Dispatch<'id> {
    Event(Step<'id>),
    Reject(u32),
}
fn decode<'id>(
    core: &mut PureClient<'id, '_>,
    source: Epoch<'id>,
    bytes: &[u8],
) -> Result<Dispatch<'id>, ProtocolError> {
    let response = Response::decode(bytes)?;
    // Freeze the exact actual frame before advancing any pure receive state.
    let owned = if matches!(response, Response::Data { .. }) {
        Some(OwnedFrame::copy_from(bytes)?)
    } else {
        None
    };
    let event = match core.on_response(source, response)? {
        PureInbound::Incoming { channel, port } => Step::Incoming { channel, port },
        PureInbound::Destroyed(channel) => Step::Destroyed(channel),
        PureInbound::Credit { channel, available } => Step::Credit { channel, available },
        PureInbound::Data {
            delivery, priority, ..
        } => Step::Data(Received {
            delivery,
            priority,
            frame: owned.ok_or(ProtocolError::Malformed)?,
        }),
        PureInbound::RejectedIncoming { channel } => return Ok(Dispatch::Reject(channel)),
        PureInbound::Ignored(reason) => Step::Ignored { source, reason },
    };
    Ok(Dispatch::Event(event))
}
fn allocate(length: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::Capacity)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn retryable(reason: ProtocolError) -> bool {
    matches!(
        reason,
        ProtocolError::Capacity | ProtocolError::WouldBlock | ProtocolError::Overflow
    )
}

/// One caller-driven native CADET client with explicitly borrowed pure storage.
/// Canceled drive futures retain original connection attempts and RX/TX cursors.
/// No resolver, task, channel payload queue or private wire INIT is created here.
pub struct Client<'id, 'slots> {
    physical: NativeChannel<Transmit<'id>>,
    clock: Arc<dyn RuntimeClock>,
    core: PureClient<'id, 'slots>,
    limits: Limits,
    closed: bool,
}
impl<'id, 'slots> Client<'id, 'slots> {
    /// Borrow original identity and empty bounded metadata, and subscribe to the
    /// explicit source clock. Creates no socket and grants no service credit.
    pub fn new(
        instance: &'id mut Instance,
        source: EndpointSource,
        ports: &'slots mut [PortSlot],
        channels: &'slots mut [ChannelSlot],
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new_inner(instance, source, ports, channels, limits, None)
    }
    /// Same original owner with an owned gate retained through actual CLIENT
    /// Resolver/probe/connect polls. Dynamic call effects still need poll_guarded.
    pub fn new_guarded(
        instance: &'id mut Instance,
        source: EndpointSource,
        ports: &'slots mut [PortSlot],
        channels: &'slots mut [ChannelSlot],
        limits: Limits,
        guard: ConnectGuard,
    ) -> Result<Self, Error> {
        Self::new_inner(instance, source, ports, channels, limits, Some(guard))
    }
    fn new_inner(
        instance: &'id mut Instance,
        source: EndpointSource,
        ports: &'slots mut [PortSlot],
        channels: &'slots mut [ChannelSlot],
        limits: Limits,
        guard: Option<ConnectGuard>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = source.clock();
        let core = PureClient::new(instance, ports, channels, limits.pure())?;
        let physical = match guard {
            Some(guard) => NativeChannel::new_guarded(source, limits.framing(), guard)?,
            None => NativeChannel::new(source, limits.framing())?,
        };
        Ok(Self {
            physical,
            clock,
            core,
            limits,
            closed: false,
        })
    }
    /// Clone the actual canonical source clock without creating another listener.
    /// Containing protocol owners derive all their deadlines from this same port.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Original attached physical source, absent before attachment or after loss.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.core.epoch()
    }
    /// Current pending exact frame; an empty value conveys no remote outcome.
    #[must_use]
    pub const fn pending_transmit(&self) -> Option<Transmit<'id>> {
        self.core.pending_transmit()
    }
    /// Copy bounded current channel metadata without granting any credit.
    pub fn channel_info(&self, channel: Channel<'id>) -> Result<ChannelInfo, Error> {
        Ok(self.core.channel_info(channel)?)
    }
    /// Copy the original logical port's unchanged on-wire hash.
    pub fn port_hash(&self, port: Port<'id>) -> Result<[u8; 64], Error> {
        Ok(self.core.port_hash(port)?)
    }
    /// Whether the exact current MQ has fully written this logical announcement.
    pub fn port_announced(&self, port: Port<'id>) -> Result<bool, Error> {
        Ok(self.core.port_announced(port)?)
    }
    fn output(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.core.epoch().is_none() {
            return Err(ProtocolError::NotReady.into());
        }
        if self.core.pending_transmit().is_some() {
            return Err(ProtocolError::WouldBlock.into());
        }
        if length > self.limits.frame_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        self.physical
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .reserve(length, Class::Ordinary)?;
        Ok(allocate(length)?)
    }
    fn admit(&mut self, bytes: Vec<u8>, transmit: Transmit<'id>) -> Result<(), Error> {
        let result = self
            .physical
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .enqueue_owned(OwnedFrame::new(bytes), transmit, Class::Ordinary);
        if let Err(rejected) = result {
            // No native poll occurred between reservation and admission. Failure
            // returns and securely drops the original zero-written immutable body.
            self.core.discard(transmit)?;
            return Err(rejected.reason.into());
        }
        Ok(())
    }
    /// Announce a new logical listening port on the current physical MQ.
    /// Its handle survives later physical loss and automatic reannouncement.
    pub fn listen(&mut self, hash: [u8; 64]) -> Result<Port<'id>, Error> {
        let mut bytes = self.output(68)?;
        let (port, prepared) = self.core.prepare_port_open(hash, &mut bytes)?;
        let transmit = prepared.transmit();
        self.admit(bytes, transmit)?;
        Ok(port)
    }
    /// Withdraw a logical port, preserving every existing accepted channel.
    /// Unannounced desired ports retire locally and return no outgoing token.
    pub fn close_port(&mut self, port: Port<'id>) -> Result<Option<Transmit<'id>>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if !self.core.port_announced(port)? {
            self.core.retire_unannounced_port(port)?;
            return Ok(None);
        }
        let mut bytes = self.output(68)?;
        let transmit = self.core.prepare_port_close(port, &mut bytes)?.transmit();
        self.admit(bytes, transmit)?;
        Ok(Some(transmit))
    }
    /// Request an outbound channel with official options zero and zero initial
    /// credit. Full CREATE write is not a remote application acceptance event.
    pub fn open(&mut self, peer: [u8; 32], port: [u8; 64]) -> Result<Channel<'id>, Error> {
        let mut bytes = self.output(108)?;
        let (channel, prepared) = self.core.prepare_channel(peer, port, &mut bytes)?;
        let transmit = prepared.transmit();
        self.admit(bytes, transmit)?;
        Ok(channel)
    }
    /// Copy exactly one complete inner message into an immutable original frame.
    /// Fallible allocation/queue reservation precedes consuming real send credit.
    /// The caller may retry a refused call; an admitted frame stays on this MQ.
    pub fn send(
        &mut self,
        channel: Channel<'id>,
        priority: u32,
        message: &[u8],
    ) -> Result<Transmit<'id>, Error> {
        let info = self.core.channel_info(channel)?;
        if info.closing || info.send_credit == 0 {
            return Err(ProtocolError::WouldBlock.into());
        }
        if message.len() > self.limits.max_payload_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        if !(4..=MAX_APPLICATION_MESSAGE_SIZE).contains(&message.len())
            || usize::from(u16::from_be_bytes([message[0], message[1]])) != message.len()
        {
            return Err(ProtocolError::Malformed.into());
        }
        let length = message
            .len()
            .checked_add(12)
            .ok_or(ProtocolError::Overflow)?;
        let mut bytes = self.output(length)?;
        let transmit = self
            .core
            .prepare_send(channel, priority, message, &mut bytes)?
            .transmit();
        self.admit(bytes, transmit)?;
        Ok(transmit)
    }
    /// Queue the standard one-shot diagnostic selector on this original MQ.
    /// Its bytes match the encoded peer header exactly, as in the fixed C daemon;
    /// `[0,0]` clears it. This returns local admission, not a drop/service ACK.
    pub fn drop_next_peer_message(
        &mut self,
        channel: Channel<'id>,
        message_type_bytes: [u8; 2],
    ) -> Result<Transmit<'id>, Error> {
        let mut bytes = self.output(10)?;
        let transmit = self
            .core
            .prepare_drop_message(channel, message_type_bytes, &mut bytes)?
            .transmit();
        self.admit(bytes, transmit)?;
        Ok(transmit)
    }
    /// Queue ordered channel destruction after the preceding original frame.
    pub fn destroy(&mut self, channel: Channel<'id>) -> Result<Transmit<'id>, Error> {
        let mut bytes = self.output(8)?;
        let transmit = self.core.prepare_destroy(channel, &mut bytes)?.transmit();
        self.admit(bytes, transmit)?;
        Ok(transmit)
    }
    /// Acknowledge application processing of exactly this original outer DATA.
    /// Dropping Received or canceling a wait never calls this method implicitly.
    pub fn receive_done(&mut self, delivery: Delivery<'id>) -> Result<Transmit<'id>, Error> {
        let mut bytes = self.output(8)?;
        let transmit = self
            .core
            .prepare_receive_done(delivery, &mut bytes)?
            .transmit();
        self.admit(bytes, transmit)?;
        Ok(transmit)
    }
    fn announce(&mut self, port: Port<'id>) -> Result<(), Error> {
        let mut bytes = self.output(68)?;
        let transmit = self.core.prepare_announce(port, &mut bytes)?.transmit();
        self.admit(bytes, transmit)
    }
    fn reject(&mut self, channel: u32) -> Result<Transmit<'id>, Error> {
        let mut bytes = self.output(8)?;
        let transmit = self.core.prepare_reject(channel, &mut bytes)?.transmit();
        self.admit(bytes, transmit)?;
        Ok(transmit)
    }
    fn release(&mut self) -> Result<(), Error> {
        if !self
            .physical
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .release_frame()
        {
            return Err(ProtocolError::NotReady.into());
        }
        Ok(())
    }
    fn dispatch(&mut self, source: Epoch<'id>) -> Result<Step<'id>, Error> {
        let result = {
            let bytes = self
                .physical
                .framing()
                .and_then(|framed| framed.frame())
                .ok_or(ProtocolError::NotReady)?;
            decode(&mut self.core, source, bytes)
        };
        match result {
            Ok(Dispatch::Event(event)) => {
                self.release()?;
                Ok(event)
            }
            Ok(Dispatch::Reject(channel)) => match self.reject(channel) {
                Ok(transmit) => {
                    self.release()?;
                    Ok(Step::RejectedIncoming {
                        source,
                        channel,
                        transmit,
                    })
                }
                Err(Error::Protocol(reason)) if retryable(reason) => Ok(Step::Blocked {
                    source,
                    reason,
                    input_retained: true,
                }),
                Err(error) => Err(error),
            },
            Err(reason) if retryable(reason) => Ok(Step::Blocked {
                source,
                reason,
                input_retained: true,
            }),
            Err(reason) => self.retire(LossCause::Protocol(reason)),
        }
    }
    fn retire(&mut self, cause: LossCause) -> Result<Step<'id>, Error> {
        let source = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        // Original native cursor/socket must disappear before its pure tokens.
        self.physical.detach();
        let report = self.core.lost(source)?;
        let retry_after = self.physical.schedule_retry()?;
        Ok(Step::Lost {
            report,
            cause,
            retry_after,
        })
    }
    /// Explicitly retire this exact MQ and retained blocked/partial input before
    /// reconnect. Open ports restore; every old channel and payload is retired.
    pub fn reconnect(&mut self) -> Result<Step<'id>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.retire(LossCause::Requested)
    }
    /// Recover an explicit CLIENT clock/time/Resolver-port refusal. This retains
    /// original attached RX/TX and grants no synthetic callback or operation.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        self.physical.recover_ports()
    }
    /// Permanently detach original physical IO before retiring old channels.
    /// Returns old epoch/exposure facts once, without scheduling another attempt.
    pub fn close(&mut self) -> Result<Option<Loss<'id>>, Error> {
        self.physical.close();
        self.closed = true;
        self.core
            .epoch()
            .map(|source| self.core.lost(source))
            .transpose()
            .map_err(Into::into)
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        source: Epoch<'id>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
    ) -> Poll<Result<Step<'id>, Error>> {
        before_io()?;
        let result = self
            .physical
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(WriteProgress {
                origin,
                bytes,
                complete,
            })) => {
                // poll_write reports a strictly positive original syscall.
                if let Err(reason) = self.core.exposed(origin) {
                    return Poll::Ready(self.retire(LossCause::Protocol(reason)));
                }
                if complete {
                    match self.core.written(origin) {
                        Ok(written) => Poll::Ready(Ok(Step::Written(written))),
                        Err(reason) => Poll::Ready(self.retire(LossCause::Protocol(reason))),
                    }
                } else {
                    Poll::Ready(Ok(Step::Activity {
                        source,
                        read_bytes: 0,
                        written_bytes: bytes,
                    }))
                }
            }
        }
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        source: Epoch<'id>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
    ) -> Poll<Result<Step<'id>, Error>> {
        before_io()?;
        let result = self
            .physical
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.retire(LossCause::Eof)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                if complete {
                    Poll::Ready(self.dispatch(source))
                } else {
                    Poll::Ready(Ok(Step::Activity {
                        source,
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    fn wait(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'id>, Error>> {
        self.physical
            .poll_wait(cx, deadline)
            .map(|result| result.map(|()| Step::WaitDeadline))
    }
    /// Poll one original event without constructing a task or canceling any
    /// retained attempt/cursor. The deadline limits only this observation wait.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'id>, Error>> {
        self.poll_guarded(cx, deadline, &mut || Ok(()))
    }
    /// Poll original cursors with a caller's current source/cancellation gate
    /// after provider work and before every driver-level connect/read/write.
    /// Refusal performs no subsequent native IO, replacement or hidden close;
    /// the caller retains and must physically retire the original owner/debts.
    pub fn poll_guarded(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
    ) -> Poll<Result<Step<'id>, Error>> {
        self.poll_guarded_inner(cx, deadline, before_io, true)
    }
    /// Poll only the original pending output with the same source, clock and
    /// cancellation gates as `poll_guarded`. No buffered service frame is
    /// dispatched and no read, connection or automatic port announcement is
    /// started. A caller holding a DATA delivery can finish its processing and
    /// actual receive credit before accepting a later service event.
    /// The original MQ must already be attached; this never reconnects it.
    pub fn poll_output_guarded(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
    ) -> Poll<Result<Step<'id>, Error>> {
        self.poll_guarded_inner(cx, deadline, before_io, false)
    }
    fn poll_guarded_inner(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
        allow_input: bool,
    ) -> Poll<Result<Step<'id>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Step::Closed));
        }
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        before_io()?;
        match self.physical.poll_clock(cx) {
            Poll::Pending => return self.wait(cx, deadline),
            Poll::Ready(result) => result?,
        }
        before_io()?;
        if self.core.epoch().is_none() {
            if !allow_input {
                return Poll::Ready(Err(ProtocolError::NotReady.into()));
            }
            match self.physical.poll_connect(cx) {
                Poll::Pending => return self.wait(cx, deadline),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Step::ConnectRetry { error, retry_after }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(Step::Unavailable(error)));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => match self.core.connected() {
                    Ok(source) => return Poll::Ready(Ok(Step::Connected(source))),
                    Err(reason) => {
                        self.physical.detach();
                        return Poll::Ready(Err(reason.into()));
                    }
                },
            }
        }
        let source = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        // Always settle actual pending write progress before accepting service
        // input generated by that completed original frame.
        if let Poll::Ready(event) = self.write(cx, source, before_io) {
            return Poll::Ready(event);
        }
        if !allow_input {
            return self.wait(cx, deadline);
        }
        if self
            .physical
            .framing()
            .is_some_and(|framed| framed.frame().is_some())
        {
            return Poll::Ready(self.dispatch(source));
        }
        if self.core.pending_transmit().is_none()
            && let Some(port) = self.core.pending_port()
        {
            match self.announce(port) {
                Ok(()) => {
                    if let Poll::Ready(event) = self.write(cx, source, before_io) {
                        return Poll::Ready(event);
                    }
                }
                Err(Error::Protocol(reason)) if retryable(reason) => {
                    return Poll::Ready(Ok(Step::Blocked {
                        source,
                        reason,
                        input_retained: false,
                    }));
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        if let Poll::Ready(event) = self.read(cx, source, before_io) {
            return Poll::Ready(event);
        }
        self.wait(cx, deadline)
    }
    /// Drive one actual event. Native deadlines limit only this observation wait;
    /// dropping this future never cancels original IO, frames, ports or channels.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Step<'id>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
}
impl Drop for Client<'_, '_> {
    fn drop(&mut self) {
        self.physical.close();
        if let Some(source) = self.core.epoch() {
            let _retired = self.core.lost(source);
        }
    }
}
