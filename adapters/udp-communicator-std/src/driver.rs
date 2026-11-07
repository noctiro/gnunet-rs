//! One explicit peer/address native UDP session on one original TRANSPORT MQ.
//! Shared multi-peer routing, endpoint acquisition and NAT discovery belong to an
//! enclosing communicator. No substitute TRANSPORT, PILS or service is created.
use crate::{
    replay::{Journal, JournalError},
    socket::{DatagramSocket, Receipt, SocketError},
    transport::{self, Event, Queue},
};
use gnunet_crypto::Entropy;
use gnunet_service_runtime::{
    connection::Connection,
    framing::{Accounting, Budget, Class, Framed, Limits, OwnedFrame, ReadStep},
};
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity, PeerId,
    receive::{Policy as RxPolicy, Receiver},
    send::{Grant, Mode, Policy as TxPolicy, Sender},
};
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    task::{Context, Poll},
};
use zeroize::Zeroizing;
/// Actual original failure; no IO error is translated to a successful callback.
#[derive(Debug)]
pub enum DriverError {
    /// Protocol/resource/clock or current-key refusal.
    Core(Error),
    /// Original native UDP socket cause.
    Native(SocketError),
    /// Original TRANSPORT MQ cause.
    Transport(io::Error),
    /// Original synchronous replay/monotime cause.
    History(JournalError),
}
impl From<Error> for DriverError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
impl From<SocketError> for DriverError {
    fn from(e: SocketError) -> Self {
        Self::Native(e)
    }
}
impl From<JournalError> for DriverError {
    fn from(e: JournalError) -> Self {
        Self::History(e)
    }
}
impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DriverError {}
/// Explicit persistent resources. These are local policy, not wire negotiation.
#[derive(Clone, Copy, Debug)]
pub struct Capacity {
    /// Retained domain-effect frames, excluding one original MQ write cursor.
    pub frames: usize,
    /// Retained domain-effect wire bytes, including both preallocated alternatives
    /// of a held local send receipt. Native RX/scratch and staging are separate.
    pub bytes: usize,
    /// Maximum bytes offered by each native IPC read/write.
    pub io_slice: usize,
}
impl Default for Capacity {
    fn default() -> Self {
        Self {
            frames: 32,
            bytes: 128 * 1024,
            io_slice: 65535,
        }
    }
}
/// One actual progress observation. Neither native IO nor a physical IPC write
/// supplies remote delivery, service admission, KID or queue credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activity {
    /// Actual native/IPC bytes transferred.
    Io,
    /// One complete atomic UDP syscall transferred the original prepared packet.
    NativeSent {
        /// Cryptographic mode of that same original packet owner.
        mode: Mode,
        /// Complete native datagram extent, never a delivery receipt.
        bytes: usize,
    },
    /// One exact original service command was consumed.
    Command,
    /// One authenticated peer datagram was admitted to bounded IPC effects.
    Incoming {
        /// Whether an original cached KID authenticated this packet as BOX.
        boxed: bool,
        /// Whether a leading authenticated ordinary rekey was accepted.
        rekey: bool,
        /// Exact original native ciphertext extent.
        bytes: usize,
    },
    /// One invalid/unusable datagram was explicitly consumed without ACK/payload.
    Discarded(Error),
    /// One immutable effect entered the original MQ's retained output queue.
    Admitted,
    /// The original service/native owners are now retired.
    Closed,
}
/// Explicit peer/address and resource choices for one physical session.
#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    /// Current local public peer, checked against every supplied key/history owner.
    pub local: PeerId,
    /// Remote destination public peer.
    pub peer: PeerId,
    /// Actual numeric UDP destination.
    pub target: SocketAddr,
    /// Caller network classifier result.
    pub network: u32,
    /// Explicit bounded IPC resources.
    pub capacity: Capacity,
    /// Explicit outgoing crypto/rotation/liveness resources.
    pub transmit: TxPolicy,
}
/// Independent clock values for one native PILS-bound polling step. Signed UDP
/// monotime is reserved separately in the durable journal and is never this UTC.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    /// Caller scheduler time in microseconds.
    pub now: u64,
    /// Trusted current UTC for the actual verified PILS HELLO's expiry.
    pub utc: gnunet_wire::official::AbsoluteTime,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Lifecycle {
    Active,
    Retiring,
    Draining,
    Closed,
}
struct Completion {
    mode: Mode,
    success: OwnedFrame,
    failure: OwnedFrame,
}
fn frozen(
    size: usize,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
) -> Result<OwnedFrame, Error> {
    freeze(buffer(size)?, encode)
}
fn buffer(size: usize) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    b.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
    b.resize(size, 0);
    Ok(b)
}
fn freeze(
    mut b: Vec<u8>,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
) -> Result<OwnedFrame, Error> {
    let size = encode(&mut b)?;
    if size > b.len() {
        return Err(Error::Malformed);
    }
    b.truncate(size);
    Ok(OwnedFrame::new(b))
}
/// Retained peer/address session. All actual sockets, prepared packets, pending
/// original local send receipt and partial MQ cursors survive waiting cancellation.
/// Caller must supply a current key and canonical clock at every polling step.
pub struct Driver {
    local: PeerId,
    peer: PeerId,
    target: SocketAddr,
    address: String,
    network: u32,
    socket: DatagramSocket,
    io: Framed<()>,
    sender: Sender,
    receiver: Receiver,
    capacity: Capacity,
    effects: VecDeque<OwnedFrame>,
    effect_bytes: usize,
    completion: Option<Completion>,
    box_queue: Option<u32>,
    next_queue: u32,
    scratch: Zeroizing<Vec<u8>>,
    last_clock: u64,
    last_ack: u64,
    ack_timeout: u64,
    turn: u8,
    lifecycle: Lifecycle,
}
impl Driver {
    /// Adopt one real socket/connected MQ and explicit peer target. No hidden
    /// connections, resolver, RNG, clock, PILS service or replay store is created.
    /// The KX queue is advertised only through the real original MQ.
    pub fn new(
        connection: Connection,
        socket: DatagramSocket,
        configuration: Configuration,
        now: u64,
    ) -> Result<Self, DriverError> {
        let Configuration {
            local,
            peer,
            target,
            network,
            capacity,
            transmit: policy,
        } = configuration;
        if capacity.frames < 4
            || capacity.bytes < 65535
            || capacity.io_slice == 0
            || socket.local_address().is_ipv4() != target.is_ipv4()
            || policy.datagram_bytes != socket.profile().datagram_bytes()
        {
            return Err(Error::InvalidInput.into());
        }
        let sender = Sender::new(local, peer, policy, now)?;
        let receiver = Receiver::new(
            local,
            peer,
            RxPolicy {
                secrets: policy.secrets,
                maximum_secret_bytes: policy.maximum_secret_bytes,
            },
        )?;
        let io = Framed::new(
            connection,
            Limits {
                frame_bytes: 65535,
                ordinary: Budget {
                    frames: 1,
                    bytes: 65535,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: capacity.io_slice,
            },
        )?;
        let mut effects = VecDeque::new();
        effects
            .try_reserve_exact(capacity.frames)
            .map_err(|_| Error::Capacity)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(65536)
            .map_err(|_| Error::Capacity)?;
        scratch.resize(65536, 0);
        let mut owner = Self {
            local,
            peer,
            target,
            address: transport::address(target),
            network,
            socket,
            io,
            sender,
            receiver,
            capacity,
            effects,
            effect_bytes: 0,
            completion: None,
            box_queue: None,
            next_queue: 2,
            scratch: Zeroizing::new(scratch),
            last_clock: now,
            last_ack: now,
            ack_timeout: policy.acknowledgement_timeout_us,
            turn: 0,
            lifecycle: Lifecycle::Active,
        };
        owner.push(frozen(16, |out| transport::register(false, out))?)?;
        let queue = owner.queue(1, u64::MAX, false)?;
        owner.push(frozen(65 + owner.address.len(), |out| {
            queue.setup(owner.address.as_bytes(), out)
        })?)?;
        Ok(owner)
    }
    fn queue(&self, id: u32, length: u64, boxed: bool) -> Result<Queue, Error> {
        Ok(Queue {
            id,
            peer: self.peer,
            network: self.network,
            mtu: u32::try_from(if boxed {
                self.sender.boxed_mtu()
            } else {
                self.sender.initial_mtu()
            })
            .map_err(|_| Error::TooLarge)?,
            length,
            priority: u32::from(boxed),
        })
    }
    fn room(&self, frames: usize, bytes: usize) -> bool {
        // Both frozen success/failure alternatives occupy physical memory until
        // the original native attempt settles, although only one can be emitted.
        let held = usize::from(self.completion.is_some()) * 2;
        self.effects
            .len()
            .checked_add(held)
            .and_then(|n| n.checked_add(frames))
            .is_some_and(|n| n <= self.capacity.frames)
            && self
                .effect_bytes
                .checked_add(held * 52)
                .and_then(|n| n.checked_add(bytes))
                .is_some_and(|n| n <= self.capacity.bytes)
    }
    fn push(&mut self, frame: OwnedFrame) -> Result<(), Error> {
        if !self.room(1, frame.len()) {
            return Err(Error::WouldBlock);
        }
        self.effect_bytes += frame.len();
        self.effects.push_back(frame);
        Ok(())
    }
    fn fail_send(&mut self, failure: OwnedFrame) -> Result<(), Error> {
        // TRANSPORT discards a QID after its negative result. This fixed session
        // cannot recreate that generation: preserve the exact result, then stop
        // all sender/receiver work until both original queues have drained.
        self.push(failure)?;
        self.lifecycle = Lifecycle::Retiring;
        Ok(())
    }
    fn admit_effect(&mut self) -> Result<Option<Activity>, Error> {
        let Some(frame) = self.effects.front() else {
            return Ok(None);
        };
        if !self.io.capacity(frame.len(), Class::Ordinary) {
            return Ok(None);
        }
        self.io.reserve(frame.len(), Class::Ordinary)?;
        let frame = self.effects.pop_front().ok_or(Error::Stale)?;
        self.effect_bytes -= frame.len();
        self.io
            .enqueue_owned(frame, (), Class::Ordinary)
            .map_err(|rejected| rejected.reason)?;
        Ok(Some(Activity::Admitted))
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Activity, DriverError>> {
        match self.io.poll_write(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Activity::Io)),
            Poll::Ready(Err(error)) => {
                self.close();
                Poll::Ready(Err(DriverError::Transport(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<Result<Activity, DriverError>> {
        // WouldBlock retains the same retirement intent. Existing FIFO writes
        // make room without reading commands, granting keys or polling sendto.
        match self.finish() {
            Ok(()) | Err(Error::WouldBlock) => {}
            Err(error) => return Poll::Ready(Err(error.into())),
        }
        for offset in 0..2 {
            let step = (self.turn + offset) % 2;
            let activity = if step == 0 {
                self.admit_effect()?
            } else {
                match self.write(cx) {
                    Poll::Ready(result) => Some(result?),
                    Poll::Pending => None,
                }
            };
            if let Some(activity) = activity {
                self.turn = (step + 1) % 2;
                return Poll::Ready(Ok(activity));
            }
        }
        if self.lifecycle == Lifecycle::Draining
            && self.effects.is_empty()
            && self.io.queued_frames() == 0
            && self.completion.is_none()
        {
            self.io.retire();
            self.lifecycle = Lifecycle::Closed;
            return Poll::Ready(Ok(Activity::Closed));
        }
        Poll::Pending
    }
    fn grant_buffer(&self) -> Result<Vec<u8>, Error> {
        if self.box_queue.is_none() {
            self.next_queue.checked_add(1).ok_or(Error::Overflow)?;
        }
        buffer(if self.box_queue.is_some() {
            64
        } else {
            65 + self.address.len()
        })
    }
    fn grant(&mut self, grant: Grant, now: u64, b: Vec<u8>) -> Result<(), Error> {
        if grant != Grant::Unknown {
            self.last_ack = now;
        }
        let Grant::Increased { delta, .. } = grant else {
            return Ok(());
        };
        if let Some(id) = self.box_queue {
            let queue = self.queue(id, u64::from(delta), true)?;
            self.push(freeze(b, |out| queue.update(out))?)?;
        } else {
            let id = self.next_queue;
            let next = id.checked_add(1).ok_or(Error::Overflow)?;
            let queue = self.queue(id, u64::from(delta), true)?;
            self.push(freeze(b, |out| queue.setup(self.address.as_bytes(), out))?)?;
            self.box_queue = Some(id);
            self.next_queue = next;
        }
        Ok(())
    }
    fn command(
        &mut self,
        identity: &Identity,
        journal: &mut Journal,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Option<Activity>, DriverError> {
        let Some(bytes) = self.io.frame() else {
            return Ok(None);
        };
        // Complete input stays in the original Framed owner if pressure prevents
        // admission. Copy only after bounded command/effect preflight.
        if !self.room(3, 1024) || self.completion.is_some() {
            return Ok(None);
        }
        let frame = OwnedFrame::copy_from(bytes)?;
        match Event::decode(frame.bytes())? {
            Event::Create {
                request,
                peer,
                address,
            } => {
                let accepted = peer == self.peer
                    && transport::parse_address(address).is_ok_and(|target| target == self.target);
                self.push(frozen(8, |out| transport::created(request, accepted, out))?)?;
            }
            Event::Send {
                qid,
                mid,
                peer,
                message,
            } => {
                let success = frozen(52, |out| transport::sent(qid, mid, peer, true, out))?;
                let failure = frozen(52, |out| transport::sent(qid, mid, peer, false, out))?;
                if peer != self.peer || (qid != 1 && Some(qid) != self.box_queue) {
                    self.push(failure)?;
                } else {
                    let prepared = if qid == 1 {
                        let (stamp, _) = journal.reserve_monotime(1, 1)?;
                        self.sender.initial(identity, message, stamp, now, entropy)
                    } else {
                        match self.sender.boxed(identity, message, now, entropy) {
                            Err(Error::NotReady) if message.len() <= self.sender.initial_mtu() => {
                                let (stamp, _) = journal.reserve_monotime(1, 1)?;
                                self.sender.initial(identity, message, stamp, now, entropy)
                            }
                            result => result,
                        }
                    };
                    match prepared {
                        Ok(packet) => {
                            let mode = packet.mode();
                            match self.socket.queue(self.target, packet) {
                                Ok(()) => {
                                    self.completion = Some(Completion {
                                        mode,
                                        success,
                                        failure,
                                    })
                                }
                                Err(rejected) => {
                                    drop(rejected.value);
                                    self.fail_send(failure)?;
                                }
                            }
                        }
                        Err(
                            Error::TooLarge
                            | Error::NotReady
                            | Error::Capacity
                            | Error::Entropy
                            | Error::Timeout,
                        ) => self.fail_send(failure)?,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            Event::Backchannel { peer, ack } => {
                if peer == self.peer {
                    let b = self.grant_buffer()?;
                    let grant = self.sender.acknowledge(peer, ack, now)?;
                    self.grant(grant, now, b)?;
                }
            }
            Event::IncomingCompleted { .. } | Event::Burst { .. } | Event::Unknown(_) => {}
        }
        if !self.io.release_frame() {
            return Err(Error::Stale.into());
        }
        Ok(Some(Activity::Command))
    }
    fn incoming(
        &mut self,
        identity: &Identity,
        journal: &mut Journal,
        receipt: Receipt,
    ) -> Result<Option<Activity>, DriverError> {
        // Every accepted payload must also fit its official incoming88 wrapper.
        // Reject impossible extents before authentication/replay/KID consumption.
        let payload_bound = receipt.len().saturating_sub(48);
        let incoming_bound = 88 + payload_bound;
        if incoming_bound > 65535 {
            self.socket.consume(receipt)?;
            return Ok(Some(Activity::Discarded(Error::TooLarge)));
        }
        let frames = 4;
        let bytes = incoming_bound + 232 + 128;
        // A datagram that cannot fit even an empty configured effect budget
        // must not occupy the original RX slot forever. Only transient pressure
        // retains that receipt while existing original effects drain.
        if frames > self.capacity.frames || bytes > self.capacity.bytes {
            self.socket.consume(receipt)?;
            return Ok(Some(Activity::Discarded(Error::Capacity)));
        }
        if !self.room(frames, bytes) {
            return Ok(None);
        }
        // Reserve every possible outgoing frame before any crypto/replay commit.
        // Freezing these original buffers performs no later heap allocation.
        let ack_buffers = [buffer(116)?, buffer(116)?];
        let message_buffer = buffer(incoming_bound)?;
        let grant_buffer = self.grant_buffer()?;
        // The original socket receipt remains owned until all effects are staged.
        let packet = self.socket.bytes(receipt)?;
        let (boxed, received) = match self.receiver.boxed(identity, packet, &mut self.scratch) {
            Err(Error::NotFound) => (
                false,
                self.receiver
                    .initial(identity, packet, &mut self.scratch, journal),
            ),
            result => (true, result),
        };
        let received = match received {
            Ok(received) => received,
            Err(error) => {
                self.socket.consume(receipt)?;
                return if matches!(error, Error::Storage | Error::OutcomeUnknown) {
                    if let Some(failure) = journal.take_failure() {
                        Err(DriverError::History(JournalError::Native(failure)))
                    } else {
                        Err(error.into())
                    }
                } else {
                    Ok(Some(Activity::Discarded(error)))
                };
            }
        };
        let mut staged: [Option<OwnedFrame>; 3] = [None, None, None];
        let rekey = received.acknowledgements[1].is_some();
        for (index, (ack, b)) in received
            .acknowledgements
            .into_iter()
            .zip(ack_buffers)
            .enumerate()
        {
            if let Some(ack) = ack {
                staged[index] = Some(freeze(b, |out| transport::notify(self.peer, ack, out))?);
            }
        }
        if let Some(message) = received.message() {
            staged[2] = Some(freeze(message_buffer, |out| {
                transport::incoming(self.peer, message, out)
            })?);
        }
        if let Some(ack) = received.incoming_ack {
            let grant = self.sender.acknowledge(self.peer, ack, self.last_clock)?;
            self.grant(grant, self.last_clock, grant_buffer)?;
        }
        for frame in staged.into_iter().flatten() {
            self.push(frame)?;
        }
        self.socket.consume(receipt)?;
        Ok(Some(Activity::Incoming {
            boxed,
            rekey,
            bytes: receipt.len(),
        }))
    }
    /// Poll one bounded rotating work item using a currently authorized identity.
    /// Cancellation of the caller's wait retains every native/MQ/effect owner.
    /// An unsettled journal outcome stops this entire session before another IO.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        identity: &Identity,
        journal: &mut Journal,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Activity, DriverError>> {
        if self.lifecycle == Lifecycle::Closed {
            return Poll::Ready(Err(Error::Closed.into()));
        }
        if identity.peer() != self.local || journal.local_peer() != self.local {
            self.close();
            return Poll::Ready(Err(Error::Authentication.into()));
        }
        match journal.quiescent() {
            Ok(true) => {}
            Ok(false) => return Poll::Ready(Err(Error::OutcomeUnknown.into())),
            Err(error) => return Poll::Ready(Err(error.into())),
        }
        if self.lifecycle != Lifecycle::Active {
            return self.poll_retirement(cx);
        }
        if now < self.last_clock {
            return Poll::Ready(Err(Error::TimeUncertain.into()));
        }
        self.last_clock = now;
        if now.saturating_sub(self.last_ack) >= self.ack_timeout {
            self.close();
            return Poll::Ready(Err(Error::Timeout.into()));
        }
        for offset in 0..5 {
            let step = (self.turn + offset) % 5;
            let progress = match step {
                0 => {
                    if self.completion.is_some() {
                        match self.socket.poll_send(cx) {
                            Poll::Pending => None,
                            Poll::Ready(result) => {
                                let completion = self.completion.take().ok_or(Error::Stale)?;
                                match result {
                                    Ok(sent) => {
                                        let mode = completion.mode;
                                        self.push(completion.success)?;
                                        self.turn = (step + 1) % 5;
                                        return Poll::Ready(Ok(Activity::NativeSent {
                                            mode,
                                            bytes: sent.bytes,
                                        }));
                                    }
                                    Err(error) => {
                                        drop(self.socket.cancel_send());
                                        self.fail_send(completion.failure)?;
                                        return Poll::Ready(Err(error.into()));
                                    }
                                }
                            }
                        }
                    } else {
                        None
                    }
                }
                1 => self.admit_effect()?,
                2 => match self.write(cx) {
                    Poll::Ready(result) => Some(result?),
                    Poll::Pending => None,
                },
                3 => {
                    if self.io.frame().is_some() {
                        self.command(identity, journal, now, entropy)?
                    } else {
                        match self.io.poll_read(cx) {
                            Poll::Ready(Ok(ReadStep::Progress { .. })) => Some(Activity::Io),
                            Poll::Ready(Ok(ReadStep::Eof)) => {
                                self.close();
                                return Poll::Ready(Ok(Activity::Closed));
                            }
                            Poll::Ready(Err(error)) => {
                                self.close();
                                return Poll::Ready(Err(DriverError::Transport(error)));
                            }
                            Poll::Pending => None,
                        }
                    }
                }
                _ => match self.socket.poll_receive(cx) {
                    Poll::Pending => None,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(receipt)) => self.incoming(identity, journal, receipt)?,
                },
            };
            if let Some(progress) = progress {
                self.turn = (step + 1) % 5;
                return Poll::Ready(Ok(progress));
            }
        }
        Poll::Pending
    }
    /// Drive through the actual matched native PILS key guard. Identity loss,
    /// revision replacement, key disable or expiration retires this original MQ
    /// and native socket before any further use of cached keys or output bytes.
    #[cfg(feature = "pils-client")]
    pub fn poll_bound<'a, const O: usize>(
        &mut self,
        cx: &mut Context<'_>,
        binding: &crate::identity::IdentityEpoch<'a>,
        source: &gnunet_pils_host::client::Client<'a, O>,
        journal: &mut Journal,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Activity, DriverError>> {
        let identity = match binding.current_native(source, time.utc) {
            Ok(key) => key,
            Err(error) => {
                self.close();
                return Poll::Ready(Err(error.into()));
            }
        };
        self.poll_step(cx, identity, journal, time.now, entropy)
    }
    /// Begin explicit original-queue teardown. An admitted unsent native attempt
    /// gets its preallocated failure callback; no packet or remote grant is made up.
    /// WouldBlock retains the terminal intent: subsequent poll_step calls drain
    /// the same original FIFO and retry teardown, without new payload/key work.
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.lifecycle == Lifecycle::Closed {
            return Err(Error::Closed);
        }
        if self.lifecycle == Lifecycle::Draining {
            return Ok(());
        }
        self.lifecycle = Lifecycle::Retiring;
        let frames = 1 + usize::from(self.box_queue.is_some());
        if !self.room(frames, frames * 40) {
            return Err(Error::WouldBlock);
        }
        // Reserve every teardown buffer before changing the original native
        // attempt or publishing the first queue teardown. Allocator refusal must
        // leave that attempt and its FIFO effects intact for an explicit retry.
        let initial = self.queue(1, 0, false)?;
        let initial = frozen(40, |out| initial.down(out))?;
        let boxed = self
            .box_queue
            .map(|id| {
                let queue = self.queue(id, 0, true)?;
                frozen(40, |out| queue.down(out))
            })
            .transpose()?;
        if let Some(completion) = self.completion.take() {
            drop(self.socket.cancel_send());
            self.push(completion.failure)?;
        }
        self.push(initial)?;
        if let Some(boxed) = boxed {
            self.push(boxed)?;
        }
        self.sender.close();
        self.receiver.close();
        self.socket.close();
        self.lifecycle = Lifecycle::Draining;
        Ok(())
    }
    /// Retire this exact physical MQ/native owner immediately. This is loss, never
    /// successful draining, local send completion or a cryptographic ACK refund.
    pub fn close(&mut self) {
        self.io.retire();
        self.socket.close();
        self.sender.close();
        self.receiver.close();
        self.effects.clear();
        self.effect_bytes = 0;
        self.completion = None;
        self.lifecycle = Lifecycle::Closed;
    }
    /// All original local wire effects and native attempts have drained/retired.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.lifecycle == Lifecycle::Closed
            && self.effects.is_empty()
            && self.io.queued_frames() == 0
            && self.completion.is_none()
            && self.socket.is_quiescent()
    }
    /// Next finite caller scheduler deadline. The enclosing process owns the
    /// canonical clock listener/timer; this method creates no waiter or task.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<u64> {
        if self.lifecycle != Lifecycle::Active {
            return None;
        }
        self.last_ack
            .checked_add(self.ack_timeout)
            .filter(|deadline| *deadline != u64::MAX)
    }
    /// Actual original native local endpoint for explicit parent-owned publication.
    #[must_use]
    pub fn local_address(&self) -> SocketAddr {
        self.socket.local_address()
    }
}
