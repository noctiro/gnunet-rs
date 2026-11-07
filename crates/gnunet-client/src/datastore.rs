//! Bounded caller-driven local DATASTORE client. No socket, task or allocation.
//! The protocol has no request ID: one request owns the physical connection until
//! its single STATUS/DATA/DATA_END. Native I/O must retain the original send token
//! through partial writes and retire the physical connection before `retire`.
use gnunet_types::{Duration, Error, MonoInstant};
pub use gnunet_wire::official::datastore::{Data, Request, Response, Status};
use gnunet_wire::official::{AbsoluteTime, Frame, MAX_MESSAGE_SIZE, message_type as mt};

/// Exclusive nonzero-sized identity storage for one client lifetime.
#[derive(Debug, Default)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Create identity storage; no global counter or wire field is introduced.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
/// Original physical connection identity.
#[derive(Clone, Copy, Debug)]
pub struct Epoch<'a> {
    owner: &'a Instance,
    serial: u64,
}
impl PartialEq for Epoch<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for Epoch<'_> {}
/// Local operation identity, never sent on the wire.
#[derive(Clone, Copy, Debug)]
pub struct Operation<'a> {
    owner: &'a Instance,
    serial: u64,
}
impl PartialEq for Operation<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for Operation<'_> {}
/// Positive reservation from the actual RESERVE reply on this original MQ.
/// The owner separately tracks remaining bytes/items and release/loss state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation<'a> {
    epoch: Epoch<'a>,
    operation: Operation<'a>,
    rid: u32,
}
impl Reservation<'_> {
    /// Original protocol number. This alone grants no owner authority.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.rid
    }
}
/// Identity for one leased immutable original request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmission<'a> {
    epoch: Epoch<'a>,
    operation: Operation<'a>,
}
impl<'a> Transmission<'a> {
    /// Actual original local operation, for host progress/cancellation routing.
    #[must_use]
    pub const fn operation(self) -> Operation<'a> {
        self.operation
    }
    /// Actual original physical connection, never a wire request ID.
    #[must_use]
    pub const fn epoch(self) -> Epoch<'a> {
        self.epoch
    }
}
/// Borrowed exact original bytes. Dropping this does not make a partially written
/// request safe to regenerate, cancel on wire, or send on another connection.
#[must_use = "write this original request or retire its physical connection"]
pub struct Send<'a, 'b> {
    token: Transmission<'a>,
    bytes: &'b [u8],
}
impl<'a> Send<'a, '_> {
    /// Preserve this token through all partial native writes.
    #[must_use]
    pub const fn token(&self) -> Transmission<'a> {
        self.token
    }
    /// Exact official frame, borrowing caller slot storage.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}
/// Actual service operation, retaining keyed/unkeyed query distinction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Reserve connection-scoped capacity.
    Reserve,
    /// Release connection-scoped capacity.
    Release,
    /// Insert/update, potentially summing existing counters.
    Put,
    /// Unkeyed selection.
    Get,
    /// Keyed selection.
    GetKey,
    /// Selection with a replication-score side effect.
    Replication,
    /// Nonzero-type zero-anonymity selection.
    ZeroAnonymity,
    /// Exact key/value removal.
    Remove,
    /// Unacknowledged service drop-on-shutdown request.
    Drop,
}
impl Kind {
    fn request(request: Request<'_>) -> Self {
        match request {
            Request::Reserve { .. } => Self::Reserve,
            Request::Release { .. } => Self::Release,
            Request::Put(_) => Self::Put,
            Request::Get { key: None, .. } => Self::Get,
            Request::Get { key: Some(_), .. } => Self::GetKey,
            Request::Replication => Self::Replication,
            Request::ZeroAnonymity { .. } => Self::ZeroAnonymity,
            Request::Remove { .. } => Self::Remove,
            Request::Drop => Self::Drop,
        }
    }
    fn status(self) -> bool {
        matches!(
            self,
            Self::Reserve | Self::Release | Self::Put | Self::Remove
        )
    }
    fn lost(self) -> Outcome {
        match self {
            Self::Put | Self::Remove | Self::Replication | Self::Drop => Outcome::Unknown,
            Self::Reserve | Self::Release => Outcome::ReservationLost,
            Self::Get | Self::GetKey | Self::ZeroAnonymity => Outcome::Interrupted,
        }
    }
}
/// Caller interruption is separate from an eventual actual service result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interruption {
    /// Caller requested cancellation.
    Cancelled,
    /// Original monotonic deadline elapsed.
    TimedOut,
}
/// Native proof that an original leased frame transferred exactly zero bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnwrittenCause {
    /// Explicit cancellation before the first physical write.
    Cancelled,
    /// Original deadline elapsed before the first physical write.
    TimedOut,
    /// The physical connection or final local admission failed before any write.
    ConnectionLost,
}
/// Terminal outcome. Only a real reply establishes service success/absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Raw STATUS fields; meaning depends on Kind. Diagnostic bytes are lent in Reply.
    Status {
        /// Exact signed service value.
        code: i32,
        /// Service expiration admission hint.
        min_expiration: AbsoluteTime,
    },
    /// A DATA reply was delivered in Reply; content authenticity remains external.
    Data {
        /// Actual backend UID.
        uid: u64,
    },
    /// DATA_END: no value, possibly also a C backend error.
    NotFound,
    /// Canceled before any send was leased; no request bytes were exposed.
    Cancelled,
    /// Expired before any send was leased.
    TimedOut,
    /// Original leased bytes were actually removed before any physical write.
    NotSent,
    /// Read-only operation lost with its retired physical connection.
    Interrupted,
    /// PUT/REMOVE/replication/DROP may have taken effect. Never auto-replay.
    Unknown,
    /// Reservation was lost with the actual connection or a queued token became stale.
    ReservationLost,
    /// DROP was fully written; there is no protocol acknowledgment of execution.
    DropUnconfirmed,
}
/// Retained terminal state, released explicitly with take().
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion<'a> {
    /// Original local operation.
    pub operation: Operation<'a>,
    /// Original requested operation kind.
    pub kind: Kind,
    /// Actual terminal certainty.
    pub outcome: Outcome,
    /// An active cancellation/timeout does not erase a later actual reply.
    pub interruption: Option<Interruption>,
    /// Actual newly granted reservation, if this was a successful RESERVE.
    pub reservation: Option<Reservation<'a>>,
}
/// One borrowed actual reply. There is no additional END after DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply<'a, 'b> {
    /// Matching retained completion.
    pub completion: Completion<'a>,
    /// Exact reply fields and original value/diagnostic bytes.
    pub response: Response<'b>,
}
/// Explicit queue/frame/time policy, in addition to actual caller storage.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum queued plus active operations; completed slots still occupy storage until take.
    pub max_pending: usize,
    /// Maximum complete outbound/inbound frame, no larger than u16::MAX.
    pub max_frame_bytes: usize,
    /// Largest admitted finite per-operation deadline interval.
    pub max_lifetime: Duration,
    /// Maximum wait to drain an already written interrupted request before closing.
    pub drain_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pending: 16,
            max_frame_bytes: MAX_MESSAGE_SIZE,
            max_lifetime: Duration(300_000_000),
            drain_timeout: Duration(5_000_000),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Free,
    Queued,
    Leased,
    Waiting,
    Done(Outcome),
}
/// One caller-owned frame buffer plus bounded operation metadata.
pub struct Slot<'a> {
    bytes: &'a mut [u8],
    length: usize,
    serial: u64,
    kind: Kind,
    state: State,
    deadline: MonoInstant,
    drain: Option<MonoInstant>,
    interruption: Option<Interruption>,
    reservation: Option<usize>,
    charged: u64,
}
impl<'a> Slot<'a> {
    /// Supply a reusable buffer; requests never retain a borrow of caller payloads.
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes,
            length: 0,
            serial: 0,
            kind: Kind::Get,
            state: State::Free,
            deadline: MonoInstant(0),
            drain: None,
            interruption: None,
            reservation: None,
            charged: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ReservationState {
    #[default]
    Free,
    Pending,
    Live,
    Closing,
}
/// Caller-owned reservation accounting slot, including queued PUT consumption.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReservationSlot {
    state: ReservationState,
    operation: u64,
    epoch: u64,
    rid: u32,
    amount: u64,
    entries: u32,
}
/// FIFO request owner. Caller slots/frame buffers and reservation slots bound all
/// memory; only one request can be exposed to a physical MQ. Unsent requests can
/// survive reconnect, while every exposed mutation receives an explicit unknown
/// outcome on loss. Reservation-dependent queued work cannot migrate epochs.
pub struct Client<'a, 's, 'b> {
    owner: &'a Instance,
    slots: &'s mut [Slot<'b>],
    reservations: &'s mut [ReservationSlot],
    limits: Limits,
    epoch: Option<Epoch<'a>>,
    connection_serial: u64,
    operation_serial: u64,
    active: Option<usize>,
    queued: usize,
    pending: usize,
    now: MonoInstant,
    poisoned: bool,
    dropping: bool,
    closed: bool,
}
impl<'a, 's, 'b> Client<'a, 's, 'b> {
    /// Construct over initialized caller storage. No connection or I/O is implicit.
    pub fn new(
        instance: &'a mut Instance,
        slots: &'s mut [Slot<'b>],
        reservations: &'s mut [ReservationSlot],
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.max_pending == 0
            || limits.max_pending > slots.len()
            || !(4..=MAX_MESSAGE_SIZE).contains(&limits.max_frame_bytes)
            || limits.max_lifetime.0 == 0
            || limits.drain_timeout.0 == 0
        {
            return Err(Error::InvalidInput);
        }
        for slot in &mut *slots {
            slot.state = State::Free;
            slot.length = 0;
            slot.reservation = None;
        }
        reservations.fill(ReservationSlot::default());
        Ok(Self {
            owner: instance,
            slots,
            reservations,
            limits,
            epoch: None,
            connection_serial: 0,
            operation_serial: 0,
            active: None,
            queued: 0,
            pending: 0,
            now: MonoInstant(0),
            poisoned: false,
            dropping: false,
            closed: false,
        })
    }
    fn operation(&self, serial: u64) -> Operation<'a> {
        Operation {
            owner: self.owner,
            serial,
        }
    }
    fn index(&self, operation: Operation<'a>) -> Result<usize, Error> {
        if !core::ptr::eq(operation.owner, self.owner) {
            return Err(Error::Stale);
        }
        self.slots
            .iter()
            .position(|slot| slot.state != State::Free && slot.serial == operation.serial)
            .ok_or(Error::Stale)
    }
    fn check_epoch(&self, epoch: Epoch<'a>) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.epoch != Some(epoch) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn clock(&mut self, now: MonoInstant) -> Result<(), Error> {
        now.duration_since(self.now)?;
        self.now = now;
        Ok(())
    }
    /// Whether the host may create another physical connection.
    #[must_use]
    pub fn connection_needed(&self) -> bool {
        self.epoch.is_none() && !self.closed
    }
    /// Whether the original connection must be physically retired before progress.
    #[must_use]
    pub const fn needs_retire(&self) -> bool {
        self.poisoned
    }
    /// Number of queued/active operations, excluding retained completions.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.pending
    }
    /// Original admission/frame/time policy, for native preflight before leasing.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    /// Oldest queued operation's exact frame length and original deadline.
    /// This lends no send authority; the host must advance time and preflight
    /// all frame/queue allocations before calling next_send on the same owner.
    #[must_use]
    pub fn next_request(&self) -> Option<(Operation<'a>, usize, MonoInstant)> {
        if self.active.is_some() || self.queued == 0 || self.poisoned || self.closed {
            return None;
        }
        self.slots
            .iter()
            .filter(|slot| slot.state == State::Queued)
            .min_by_key(|slot| slot.serial)
            .map(|slot| (self.operation(slot.serial), slot.length, slot.deadline))
    }
    /// Attach one genuinely new physical connection. There is no START message.
    pub fn begin_connection(&mut self, now: MonoInstant) -> Result<Epoch<'a>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if !self.connection_needed() {
            return Err(Error::NotReady);
        }
        self.advance(now)?;
        self.connection_serial = self
            .connection_serial
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let epoch = Epoch {
            owner: self.owner,
            serial: self.connection_serial,
        };
        self.epoch = Some(epoch);
        Ok(epoch)
    }
    fn reservation_index(&self, token: Reservation<'a>) -> Result<usize, Error> {
        if self.epoch != Some(token.epoch) || !core::ptr::eq(token.operation.owner, self.owner) {
            return Err(Error::Stale);
        }
        self.reservations
            .iter()
            .position(|r| {
                r.state == ReservationState::Live
                    && r.epoch == token.epoch.serial
                    && r.operation == token.operation.serial
                    && r.rid == token.rid
            })
            .ok_or(Error::Stale)
    }
    /// Encode/copy one original request into a fitting free slot. FIFO order is
    /// deliberate local scheduling, not a wire change. A nonzero PUT/release rid
    /// requires its actual current Reservation; queued PUTs reserve bytes/items
    /// immediately, so an overdraw is refused before exposing any request bytes.
    pub fn submit(
        &mut self,
        request: Request<'_>,
        authorization: Option<Reservation<'a>>,
        now: MonoInstant,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.dropping {
            return Err(Error::NotReady);
        }
        self.advance(now)?;
        if timeout.0 == 0 || timeout.0 > self.limits.max_lifetime.0 {
            return Err(Error::InvalidInput);
        }
        let deadline = now.after(timeout)?;
        let length = request.encoded_len()?;
        if length > self.limits.max_frame_bytes {
            return Err(Error::TooLarge);
        }
        if self.pending >= self.limits.max_pending {
            return Err(Error::Capacity);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.state == State::Free && slot.bytes.len() >= length)
            .ok_or(Error::Capacity)?;
        let kind = Kind::request(request);
        if kind == Kind::Drop && self.pending != 0 {
            return Err(Error::NotReady);
        }
        let mut reservation = None;
        let mut charge = 0;
        match request {
            Request::Reserve { .. } => {
                if authorization.is_some() {
                    return Err(Error::InvalidInput);
                }
                reservation = Some(
                    self.reservations
                        .iter()
                        .position(|r| r.state == ReservationState::Free)
                        .ok_or(Error::Capacity)?,
                );
            }
            Request::Put(data) if data.reservation != 0 => {
                let token = authorization.ok_or(Error::PermissionDenied)?;
                if token.rid != data.reservation {
                    return Err(Error::PermissionDenied);
                }
                let r = self.reservation_index(token)?;
                charge = u64::try_from(data.value.len()).map_err(|_| Error::TooLarge)?;
                if self.reservations[r].entries == 0 || self.reservations[r].amount < charge {
                    return Err(Error::Capacity);
                }
                reservation = Some(r);
            }
            Request::Release { reservation: rid } => {
                let token = authorization.ok_or(Error::PermissionDenied)?;
                if token.rid != rid {
                    return Err(Error::PermissionDenied);
                }
                reservation = Some(self.reservation_index(token)?);
            }
            _ if authorization.is_some() => return Err(Error::InvalidInput),
            _ => {}
        }
        let serial = self
            .operation_serial
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        request.encode(self.slots[index].bytes)?;
        if let Some(r) = reservation {
            match request {
                Request::Reserve { amount, entries } => {
                    self.reservations[r] = ReservationSlot {
                        state: ReservationState::Pending,
                        operation: serial,
                        epoch: 0,
                        rid: 0,
                        amount,
                        entries,
                    };
                }
                Request::Put(_) => {
                    self.reservations[r].amount -= charge;
                    self.reservations[r].entries -= 1;
                }
                Request::Release { .. } => self.reservations[r].state = ReservationState::Closing,
                _ => {}
            }
        }
        let slot = &mut self.slots[index];
        slot.length = length;
        slot.serial = serial;
        slot.kind = kind;
        slot.state = State::Queued;
        slot.deadline = deadline;
        slot.drain = None;
        slot.interruption = None;
        slot.reservation = reservation;
        slot.charged = charge;
        self.operation_serial = serial;
        self.pending += 1;
        self.queued += 1;
        self.dropping = kind == Kind::Drop;
        Ok(self.operation(serial))
    }
    fn finish(&mut self, index: usize, outcome: Outcome) {
        if self.slots[index].state == State::Queued {
            self.queued -= 1;
        }
        if self.active == Some(index) {
            self.active = None;
        }
        self.pending -= 1;
        self.slots[index].state = State::Done(outcome);
    }
    fn undo_queued(&mut self, index: usize) -> Result<(), Error> {
        if let Some(r) = self.slots[index].reservation {
            match self.slots[index].kind {
                Kind::Reserve => self.reservations[r] = ReservationSlot::default(),
                Kind::Put => {
                    let amount = self.reservations[r]
                        .amount
                        .checked_add(self.slots[index].charged)
                        .ok_or(Error::Overflow)?;
                    let entries = self.reservations[r]
                        .entries
                        .checked_add(1)
                        .ok_or(Error::Overflow)?;
                    self.reservations[r].amount = amount;
                    self.reservations[r].entries = entries;
                }
                Kind::Release => self.reservations[r].state = ReservationState::Live,
                _ => {}
            }
        }
        if self.slots[index].kind == Kind::Drop {
            self.dropping = false;
        }
        Ok(())
    }
    fn interrupt(
        &mut self,
        index: usize,
        why: Interruption,
        now: MonoInstant,
    ) -> Result<(), Error> {
        if self.slots[index].interruption.is_some() {
            return Ok(());
        }
        match self.slots[index].state {
            State::Queued => {
                self.undo_queued(index)?;
                self.slots[index].interruption = Some(why);
                self.finish(
                    index,
                    if why == Interruption::Cancelled {
                        Outcome::Cancelled
                    } else {
                        Outcome::TimedOut
                    },
                );
            }
            State::Leased => {
                self.slots[index].interruption = Some(why);
                self.poisoned = true;
            }
            State::Waiting => {
                self.slots[index].interruption = Some(why);
                match now.after(self.limits.drain_timeout) {
                    Ok(deadline) => self.slots[index].drain = Some(deadline),
                    Err(_) => self.poisoned = true,
                }
            }
            State::Free | State::Done(_) => return Err(Error::Stale),
        }
        Ok(())
    }
    /// Expire queued requests locally; drain written ones for a bounded interval.
    /// A leased partial write must be retired immediately on interruption.
    pub fn advance(&mut self, now: MonoInstant) -> Result<(), Error> {
        self.clock(now)?;
        if self.pending == 0 {
            return Ok(());
        }
        for index in 0..self.slots.len() {
            if matches!(
                self.slots[index].state,
                State::Queued | State::Leased | State::Waiting
            ) && self.slots[index].deadline <= now
                && self.slots[index].interruption.is_none()
            {
                self.interrupt(index, Interruption::TimedOut, now)?;
            }
        }
        if let Some(active) = self.active
            && self.slots[active]
                .drain
                .is_some_and(|deadline| deadline <= now)
        {
            self.poisoned = true;
        }
        Ok(())
    }
    /// Original monotonic wake-up time for expiration/drain, if one remains.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        self.slots
            .iter()
            .filter_map(|slot| match slot.state {
                State::Queued | State::Leased | State::Waiting => {
                    if slot.interruption.is_some() {
                        slot.drain
                    } else {
                        Some(slot.deadline)
                    }
                }
                _ => None,
            })
            .min()
    }
    /// Lease the oldest queued exact frame. While active/draining there is no
    /// second send; a reply cannot be assigned to a later query accidentally.
    pub fn next_send(
        &mut self,
        epoch: Epoch<'a>,
        now: MonoInstant,
    ) -> Result<Option<Send<'a, '_>>, Error> {
        self.check_epoch(epoch)?;
        self.advance(now)?;
        if self.poisoned {
            return Err(Error::NotReady);
        }
        if self.active.is_some() || self.queued == 0 {
            return Ok(None);
        }
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.state == State::Queued)
            .min_by_key(|(_, slot)| slot.serial)
            .map(|(index, _)| index)
            .ok_or(Error::NotReady)?;
        let operation = self.operation(self.slots[index].serial);
        if self.slots[index].kind == Kind::Reserve
            && let Some(r) = self.slots[index].reservation
        {
            self.reservations[r].epoch = epoch.serial;
        }
        self.slots[index].state = State::Leased;
        self.active = Some(index);
        self.queued -= 1;
        Ok(Some(Send {
            token: Transmission { epoch, operation },
            bytes: &self.slots[index].bytes[..self.slots[index].length],
        }))
    }
    /// Confirm full original physical write. This is not a service commit.
    /// DROP has no reply: keep an unconfirmed result and require physical close.
    pub fn written(&mut self, token: Transmission<'a>) -> Result<(), Error> {
        self.check_epoch(token.epoch)?;
        if self.poisoned {
            return Err(Error::NotReady);
        }
        let index = self.index(token.operation)?;
        if self.active != Some(index) || self.slots[index].state != State::Leased {
            return Err(Error::Stale);
        }
        if self.slots[index].kind == Kind::Drop {
            self.finish(index, Outcome::DropUnconfirmed);
            self.poisoned = true;
        } else {
            self.slots[index].state = State::Waiting;
        }
        Ok(())
    }
    /// Settle a leased original only after its native owner has removed that
    /// exact zero-written frame (or rejected its final admission without IO).
    /// Dropping a Send alone is insufficient. A partial write must instead
    /// retire the original connection and retain the normal unknown outcome.
    pub fn discard_unwritten(
        &mut self,
        token: Transmission<'a>,
        now: MonoInstant,
        cause: UnwrittenCause,
    ) -> Result<(), Error> {
        self.check_epoch(token.epoch)?;
        self.clock(now)?;
        let index = self.index(token.operation)?;
        if self.active != Some(index) || self.slots[index].state != State::Leased {
            return Err(Error::Stale);
        }
        let interruption = self.slots[index].interruption.or_else(|| {
            if now >= self.slots[index].deadline {
                Some(Interruption::TimedOut)
            } else {
                match cause {
                    UnwrittenCause::Cancelled => Some(Interruption::Cancelled),
                    UnwrittenCause::TimedOut => Some(Interruption::TimedOut),
                    UnwrittenCause::ConnectionLost => None,
                }
            }
        });
        self.undo_queued(index)?;
        self.slots[index].interruption = interruption;
        self.finish(
            index,
            match interruption {
                Some(Interruption::Cancelled) => Outcome::Cancelled,
                Some(Interruption::TimedOut) => Outcome::TimedOut,
                None => Outcome::NotSent,
            },
        );
        Ok(())
    }
    /// Cancel unsent work or retain ownership to drain its single actual reply.
    /// No private cancel frame or guessed request ID is transmitted.
    pub fn cancel(&mut self, operation: Operation<'a>, now: MonoInstant) -> Result<(), Error> {
        self.advance(now)?;
        let index = self.index(operation)?;
        self.interrupt(index, Interruption::Cancelled, now)
    }
    fn completion(&self, index: usize) -> Result<Completion<'a>, Error> {
        let slot = &self.slots[index];
        let State::Done(outcome) = slot.state else {
            return Err(Error::NotReady);
        };
        let reservation = if slot.kind == Kind::Reserve {
            slot.reservation.and_then(|r| {
                let r = self.reservations[r];
                if r.state == ReservationState::Live && r.operation == slot.serial {
                    self.epoch
                        .filter(|epoch| epoch.serial == r.epoch)
                        .map(|epoch| Reservation {
                            epoch,
                            operation: self.operation(r.operation),
                            rid: r.rid,
                        })
                } else {
                    None
                }
            })
        } else {
            None
        };
        Ok(Completion {
            operation: self.operation(slot.serial),
            kind: slot.kind,
            outcome,
            interruption: slot.interruption,
            reservation,
        })
    }
    /// Release one retained completion and its frame slot. The returned reservation
    /// remains independently accounted until release or physical connection loss.
    pub fn take(&mut self, operation: Operation<'a>) -> Result<Completion<'a>, Error> {
        let index = self.index(operation)?;
        let completion = self.completion(index)?;
        self.slots[index].state = State::Free;
        self.slots[index].length = 0;
        self.slots[index].reservation = None;
        Ok(completion)
    }
    /// Consume one exact original-MQ response. Valid unknown message types are
    /// ignored like MQ; malformed or mismatched known input poisons the original
    /// connection, preserving pending work until actual physical retirement.
    pub fn receive<'r>(
        &mut self,
        epoch: Epoch<'a>,
        input: &'r [u8],
        now: MonoInstant,
    ) -> Result<Option<Reply<'a, 'r>>, Error> {
        self.check_epoch(epoch)?;
        self.advance(now)?;
        if self.poisoned {
            return Err(Error::NotReady);
        }
        let result = self.receive_inner(epoch, input);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn receive_inner<'r>(
        &mut self,
        epoch: Epoch<'a>,
        input: &'r [u8],
    ) -> Result<Option<Reply<'a, 'r>>, Error> {
        if input.len() > self.limits.max_frame_bytes {
            return Err(Error::TooLarge);
        }
        let frame = Frame::decode(input)?;
        if !matches!(
            frame.header().message_type(),
            mt::DATASTORE_STATUS | mt::DATASTORE_DATA | mt::DATASTORE_DATA_END
        ) {
            return Ok(None);
        }
        let response = Response::decode(input)?;
        let index = self.active.ok_or(Error::Malformed)?;
        if self.slots[index].state != State::Waiting {
            return Err(Error::NotReady);
        }
        let kind = self.slots[index].kind;
        if kind.status() != matches!(response, Response::Status(_)) {
            return Err(Error::Malformed);
        }
        if let Response::Data(data) = response {
            match Request::decode(&self.slots[index].bytes[..self.slots[index].length])? {
                Request::Get { key, kind, .. }
                    if (kind != 0 && kind != data.kind)
                        || key.is_some_and(|key| key != data.key) =>
                {
                    return Err(Error::Malformed);
                }
                Request::ZeroAnonymity { kind, .. } if kind != data.kind || data.anonymity != 0 => {
                    return Err(Error::Malformed);
                }
                _ => {}
            }
        }
        if let Some(r) = self.slots[index].reservation {
            match (kind, response) {
                (Kind::Reserve, Response::Status(status)) if status.code > 0 => {
                    self.reservations[r].state = ReservationState::Live;
                    self.reservations[r].rid = status.code as u32;
                    self.reservations[r].epoch = epoch.serial;
                }
                (Kind::Reserve | Kind::Release, _) => {
                    self.reservations[r] = ReservationSlot::default()
                }
                _ => {}
            }
        }
        let outcome = match response {
            Response::Status(status) => Outcome::Status {
                code: status.code,
                min_expiration: status.min_expiration,
            },
            Response::Data(data) => Outcome::Data { uid: data.uid },
            Response::End => Outcome::NotFound,
        };
        self.finish(index, outcome);
        Ok(Some(Reply {
            completion: self.completion(index)?,
            response,
        }))
    }
    /// Report that the original physical connection and all partial I/O owners
    /// have actually been destroyed. Exposed mutations are never replayed;
    /// only still-unsent, reservation-independent requests remain queued.
    pub fn retire(&mut self, epoch: Epoch<'a>, now: MonoInstant) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        self.clock(now)?;
        for index in 0..self.slots.len() {
            match self.slots[index].state {
                State::Leased | State::Waiting => self.finish(index, self.slots[index].kind.lost()),
                State::Queued
                    if self.slots[index]
                        .reservation
                        .is_some_and(|r| self.reservations[r].epoch == epoch.serial) =>
                {
                    self.finish(index, Outcome::ReservationLost)
                }
                _ => {}
            }
        }
        for reservation in &mut *self.reservations {
            if reservation.epoch == epoch.serial {
                *reservation = ReservationSlot::default();
            }
        }
        self.epoch = None;
        self.poisoned = false;
        self.active = None;
        if self.dropping {
            self.closed = true;
        }
        Ok(())
    }
    /// Close after any physical connection has been retired. No pending operation
    /// becomes successful; unsent work receives a local cancelled completion.
    pub fn close(&mut self, now: MonoInstant) -> Result<(), Error> {
        if self.epoch.is_some() {
            return Err(Error::NotReady);
        }
        self.advance(now)?;
        for index in 0..self.slots.len() {
            if self.slots[index].state == State::Queued {
                self.interrupt(index, Interruption::Cancelled, now)?;
            }
        }
        self.closed = true;
        Ok(())
    }
}
