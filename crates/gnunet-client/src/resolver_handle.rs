//! Bounded owner for v0.29.1 resolver FIFO, fast tasks and callback lifetimes.
//!
//! IDs are valid only in the owner that issued them. Same-owner stale generations
//! are checked; there is no claim of foreign-owner identity or global atomics.
//! Scheduler coordinates are logical absolute time and may regress; relative
//! backoff and registered-ready tasks retain their original source policy.
use crate::resolver::{Family, FamilyProfile, MAX_HOSTNAME_LEN, Request, Response, WireId};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use gnunet_types::{AbsoluteTime, Duration, Error, GenerationalId};
use gnunet_wire::official::Frame;

const INITIAL_BACKOFF: Duration = Duration(1_000);
const MAX_BACKOFF: Duration = Duration(900_000_000);
/// A local capability, checked for stale generations only in its original owner.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(GenerationalId);
impl RequestId {
    /// Local slot/generation, never serialized in resolver messages.
    #[must_use]
    pub const fn resource_id(self) -> GenerationalId {
        self.0
    }
}
/// One virtual MQ lifetime; physical socket retries can remain inside this epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionEpoch(u64);
impl ConnectionEpoch {
    /// Local epoch counter, never a wire field.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}
/// Why the public callback stream ended. These are local facts, not wire status fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// Normal type-5 END was received, or a local task completed.
    End,
    /// The original caller deadline elapsed, including queue/reconnect time.
    Timeout,
    /// An identified response had an invalid payload; the connection was retired.
    Malformed,
}
/// One reverse callback value. Numeric formatting belongs to the host adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hostname<'a> {
    /// Borrowed bytes visible to the C-string callback, without its NUL terminator.
    Resolved(&'a [u8]),
    /// Canonical numeric-address fallback, with no fabricated DNS name.
    Numeric(IpAddr),
}
/// One callback effect. Consume one event, allow cancellation, then request the next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// One address value; the token remains pending during the callback.
    Address {
        /// Original owner token.
        request: RequestId,
        /// Zero-port raw address.
        address: IpAddr,
    },
    /// One reverse name/fallback; the token remains pending during the callback.
    Hostname {
        /// Original owner token.
        request: RequestId,
        /// Borrowed name or owned numeric fallback.
        hostname: Hostname<'a>,
    },
    /// Terminal callback. The token was invalidated before this event was returned.
    Complete {
        /// Original token, now retired.
        request: RequestId,
        /// Local terminal reason.
        reason: Completion,
    },
}
/// One admitted immutable MQ envelope. The host must copy/retain exactly these bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outbound {
    /// Virtual MQ lifetime.
    pub epoch: ConnectionEpoch,
    /// Logical owner token.
    pub request: RequestId,
    /// Exact echoed four-byte wire ID.
    pub wire_id: WireId,
    /// Bytes encoded into caller storage.
    pub len: usize,
}
#[derive(Clone, Copy)]
enum Kind {
    Forward(Family),
    Reverse(IpAddr),
}
#[derive(Clone, Copy)]
struct Local {
    first: IpAddr,
    second: Option<IpAddr>,
    reverse: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Local(u8),
    Queued,
    Submitted,
    Cancelled,
    Finishing { reason: Completion, fallback: bool },
}
#[derive(Clone, Copy)]
struct State<const N: usize> {
    name: [u8; N],
    name_len: usize,
    kind: Kind,
    local: Option<Local>,
    wire: WireId,
    phase: Phase,
    next: Option<usize>,
    remote: bool,
    deadline: AbsoluteTime,
    // Registration can put a timeout on the ready queue before a later rollback.
    // Keep the original absolute deadline separately for queries and retries.
    registered_ready: bool,
    order: u64,
    received_name: bool,
    finish_sequence: u64,
}
#[derive(Clone, Copy)]
struct Slot<const N: usize> {
    generation: u32,
    retired: bool,
    state: Option<State<N>>,
}
impl<const N: usize> Slot<N> {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        state: None,
    };
}
/// Allocation-free resolver owner. R bounds all live/draining/event slots; N
/// bounds each owned forward name. No completion queue can overflow after admission.
/// Native hostname/getaddrinfo helpers are deliberately outside this pure core.
pub struct ResolverHandle<const R: usize, const N: usize> {
    slots: [Slot<N>; R],
    head: Option<usize>,
    tail: Option<usize>,
    profile: FamilyProfile,
    configured: bool,
    last_wire: u32,
    order: u64,
    connection: Option<ConnectionEpoch>,
    last_epoch: u64,
    retry_at: Option<AbsoluteTime>,
    backoff: Duration,
    idle_at: Option<AbsoluteTime>,
    continuation: Option<RequestId>,
    finish_sequence: u64,
}
impl<const R: usize, const N: usize> ResolverHandle<R, N> {
    /// Equivalent to storing a resolver configuration via connect; no network I/O.
    /// configured is the host's actual check_config result, not service reachability.
    pub fn new(profile: FamilyProfile, configured: bool) -> Result<Self, Error> {
        if R > u32::MAX as usize {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            slots: [Slot::EMPTY; R],
            head: None,
            tail: None,
            profile,
            configured,
            last_wire: 0,
            order: 0,
            connection: None,
            last_epoch: 0,
            retry_at: None,
            backoff: INITIAL_BACKOFF,
            idle_at: None,
            continuation: None,
            finish_sequence: 0,
        })
    }
    /// Store a new check_config result and reset the next backoff, as C connect does.
    /// The host retains the actual configuration and endpoint ownership.
    pub fn connect(&mut self, configured: bool) {
        self.configured = configured;
        self.backoff = INITIAL_BACKOFF;
    }
    /// Store the host's current admission-time check_config result without
    /// reconnecting, resetting backoff or changing any existing request/epoch.
    /// Unlike [`Self::connect`], this samples a retained mutable configuration.
    pub fn update_configuration_admissibility(&mut self, configured: bool) {
        self.configured = configured;
    }
    fn index(&self, id: RequestId) -> Result<usize, Error> {
        let index = usize::try_from(id.0.index).map_err(|_| Error::StaleGeneration)?;
        if self
            .slots
            .get(index)
            .is_some_and(|slot| slot.generation == id.0.generation && slot.state.is_some())
        {
            Ok(index)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn id(&self, index: usize) -> RequestId {
        RequestId(GenerationalId {
            index: index as u32,
            generation: self.slots[index].generation,
        })
    }
    fn free(&mut self, index: usize) {
        if self
            .continuation
            .is_some_and(|id| id.resource_id().index == index as u32)
        {
            self.continuation = None;
        }
        self.slots[index].state = None;
        if let Some(next) = self.slots[index].generation.checked_add(1) {
            self.slots[index].generation = next;
        } else {
            self.slots[index].retired = true;
        }
    }
    fn unlink(&mut self, index: usize) {
        let mut current = self.head;
        let mut previous: Option<usize> = None;
        for _ in 0..R {
            let Some(position) = current else {
                return;
            };
            let Some(state) = self.slots[position].state else {
                return;
            };
            if position == index {
                if let Some(prev) = previous {
                    if let Some(s) = self.slots[prev].state.as_mut() {
                        s.next = state.next;
                    }
                } else {
                    self.head = state.next;
                }
                if self.tail == Some(index) {
                    self.tail = previous;
                }
                if let Some(s) = self.slots[index].state.as_mut() {
                    s.next = None;
                }
                return;
            }
            previous = Some(position);
            current = state.next;
        }
    }
    fn live_remote(&self) -> bool {
        self.slots.iter().any(|slot| {
            slot.state
                .is_some_and(|s| s.remote && matches!(s.phase, Phase::Queued | Phase::Submitted))
        })
    }
    fn soon(now: AbsoluteTime, delay: Duration) -> AbsoluteTime {
        AbsoluteTime::from_micros(now.as_micros().saturating_add(delay.0))
    }
    fn schedule_retry(&mut self, now: AbsoluteTime) {
        if self.connection.is_none() && self.retry_at.is_none() && self.live_remote() {
            self.retry_at = Some(Self::soon(now, self.backoff));
            self.backoff = Duration(self.backoff.0.saturating_mul(2).min(MAX_BACKOFF.0));
        }
    }
    fn check_idle(&mut self, now: AbsoluteTime) {
        if self.live_remote() {
            return;
        }
        self.retry_at = None;
        if self.idle_at.is_none() {
            self.idle_at = Some(Self::soon(now, INITIAL_BACKOFF));
        }
    }
    fn admit(
        &mut self,
        kind: Kind,
        name: &[u8],
        local: Option<Local>,
        timeout: Duration,
        now: AbsoluteTime,
    ) -> Result<RequestId, Error> {
        // Official relative_to_absolute treats FOREVER and finite overflow as FOREVER.
        let deadline = AbsoluteTime::from_micros(now.as_micros().saturating_add(timeout.0));
        if name.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if name.len() > MAX_HOSTNAME_LEN {
            return Err(Error::TooLarge);
        }
        if name.len() > N {
            return Err(Error::Capacity);
        }
        let index = self
            .slots
            .iter()
            .position(|s| !s.retired && s.state.is_none())
            .ok_or(Error::Capacity)?;
        let order = self.order.checked_add(1).ok_or(Error::Overflow)?;
        let mut wire = self.last_wire;
        let mut selected = None;
        for _ in 0..=R {
            wire = wire.wrapping_add(1);
            let candidate = WireId::from_native(wire);
            if !self
                .slots
                .iter()
                .any(|slot| slot.state.is_some_and(|s| s.wire == candidate))
            {
                selected = Some(candidate);
                break;
            }
        }
        let wire = selected.ok_or(Error::Capacity)?;
        let mut bytes = [0; N];
        bytes[..name.len()].copy_from_slice(name);
        let remote = local.is_none();
        let phase = if remote {
            Phase::Queued
        } else {
            Phase::Local(0)
        };
        let state = State {
            name: bytes,
            name_len: name.len(),
            kind,
            local,
            wire,
            phase,
            next: None,
            remote,
            deadline,
            registered_ready: !remote || (timeout.0 == 0 && deadline.as_micros() != u64::MAX),
            order,
            received_name: false,
            finish_sequence: 0,
        };
        // All fallible validation precedes this commit; rejection consumes no ID/slot.
        self.slots[index].state = Some(state);
        self.last_wire = u32::from_ne_bytes(wire.0);
        self.order = order;
        if remote {
            if let Some(tail) = self.tail {
                if let Some(s) = self.slots[tail].state.as_mut() {
                    s.next = Some(index);
                }
            } else {
                self.head = Some(index);
            }
            self.tail = Some(index);
            self.idle_at = None;
            self.schedule_retry(now);
        }
        Ok(self.id(index))
    }
    /// Admit a public forward request. Numeric/loopback results are deferred even
    /// at timeout zero and bypass resolver configuration checks, matching C.
    pub fn ip_get(
        &mut self,
        hostname: &[u8],
        family: Family,
        timeout: Duration,
        now: AbsoluteTime,
    ) -> Result<RequestId, Error> {
        let local = local_address(hostname, family);
        if local.is_none() && !self.configured {
            return Err(Error::Unavailable);
        }
        self.admit(Kind::Forward(family), hostname, local, timeout, now)
    }
    /// Admit reverse numeric or resolving lookup. Configuration is required even
    /// when resolve is false; native sockaddr length validation belongs to the host.
    pub fn hostname_get(
        &mut self,
        address: IpAddr,
        resolve: bool,
        timeout: Duration,
        now: AbsoluteTime,
    ) -> Result<RequestId, Error> {
        if !self.configured {
            return Err(Error::Unavailable);
        }
        let local = (!resolve).then_some(Local {
            first: address,
            second: None,
            reverse: true,
        });
        self.admit(Kind::Reverse(address), &[], local, timeout, now)
    }
    /// Cancel a pending original-owner token. Sent requests remain drainable until
    /// END/error/idle close. No cancel message or callback is invented.
    pub fn request_cancel(&mut self, id: RequestId, now: AbsoluteTime) -> Result<(), Error> {
        let index = self.index(id)?;
        let state = self.slots[index].state.ok_or(Error::StaleGeneration)?;
        if state.phase == Phase::Cancelled {
            return Err(Error::StaleGeneration);
        }
        if state.phase == Phase::Submitted {
            if let Some(s) = self.slots[index].state.as_mut() {
                s.phase = Phase::Cancelled;
            }
        } else {
            if state.remote {
                self.unlink(index);
            }
            self.free(index);
        }
        self.check_idle(now);
        Ok(())
    }
    fn ready(&self, index: usize, now: AbsoluteTime) -> Option<(AbsoluteTime, u64)> {
        let state = self.slots[index].state?;
        match state.phase {
            // add_now and an in-progress synchronous callback stack are already
            // runnable. Ready tasks retain FIFO even when their admission times
            // were observed on opposite sides of a wall-clock adjustment.
            Phase::Local(_) | Phase::Finishing { .. } => {
                Some((AbsoluteTime::from_micros(0), state.order))
            }
            Phase::Queued | Phase::Submitted if state.registered_ready => {
                Some((AbsoluteTime::from_micros(0), state.order))
            }
            Phase::Queued | Phase::Submitted => (state.deadline.as_micros() != u64::MAX
                && state.deadline <= now)
                .then_some((state.deadline, state.order)),
            Phase::Cancelled => None,
        }
    }
    fn event_due(&self, now: AbsoluteTime) -> bool {
        (0..R).any(|i| self.ready(i, now).is_some())
    }
    fn finish(&mut self, index: usize, reason: Completion) {
        self.unlink(index);
        // Each admitted remote request can finish only once. The admission
        // order bound therefore also bounds this counter, including cancellation.
        self.finish_sequence = self.finish_sequence.saturating_add(1);
        if let Some(s) = self.slots[index].state.as_mut() {
            s.phase = Phase::Finishing {
                reason,
                fallback: matches!(s.kind, Kind::Reverse(_))
                    && !s.received_name
                    && reason != Completion::Malformed,
            };
            s.finish_sequence = self.finish_sequence;
        }
    }
    /// Return exactly one deferred value/terminal effect. The caller may cancel
    /// its still-pending token before requesting the next event. Completion retires
    /// the token before returning, eliminating callback reentrancy reclamation bugs.
    pub fn next_event(&mut self, now: AbsoluteTime) -> Option<Event<'static>> {
        // A C handler resumes its own local/fallback callback stack before
        // returning to the scheduler, even if a callback changed logical time.
        let continuation = self.continuation.and_then(|id| self.index(id).ok());
        let finishing = (0..R)
            .filter_map(|i| {
                self.slots[i].state.and_then(|s| {
                    matches!(s.phase, Phase::Finishing { .. }).then_some((s.finish_sequence, i))
                })
            })
            .min_by_key(|(sequence, _)| *sequence)
            .map(|(_, i)| i);
        let index = continuation.or(finishing).or_else(|| {
            (0..R)
                .filter_map(|i| self.ready(i, now).map(|key| (key, i)))
                .min_by_key(|(key, _)| *key)
                .map(|(_, i)| i)
        })?;
        let mut state = self.slots[index].state?;
        if matches!(state.phase, Phase::Queued | Phase::Submitted) {
            self.finish(index, Completion::Timeout);
            state = self.slots[index].state?;
        }
        let id = self.id(index);
        match state.phase {
            Phase::Local(cursor) => {
                let local = state.local?;
                if cursor == 0 {
                    if let Some(s) = self.slots[index].state.as_mut() {
                        s.phase = Phase::Local(1);
                    }
                    self.continuation = Some(id);
                    return Some(if local.reverse {
                        Event::Hostname {
                            request: id,
                            hostname: Hostname::Numeric(local.first),
                        }
                    } else {
                        Event::Address {
                            request: id,
                            address: local.first,
                        }
                    });
                }
                if cursor == 1
                    && let Some(second) = local.second
                {
                    if let Some(s) = self.slots[index].state.as_mut() {
                        s.phase = Phase::Local(2);
                    }
                    self.continuation = Some(id);
                    return Some(Event::Address {
                        request: id,
                        address: second,
                    });
                }
                self.free(index);
                Some(Event::Complete {
                    request: id,
                    reason: Completion::End,
                })
            }
            Phase::Finishing { reason, fallback } => {
                if fallback && let Kind::Reverse(address) = state.kind {
                    if let Some(s) = self.slots[index].state.as_mut() {
                        s.phase = Phase::Finishing {
                            reason,
                            fallback: false,
                        };
                    }
                    self.continuation = Some(id);
                    return Some(Event::Hostname {
                        request: id,
                        hostname: Hostname::Numeric(address),
                    });
                }
                self.free(index);
                self.check_idle(now);
                self.schedule_retry(now);
                Some(Event::Complete {
                    request: id,
                    reason,
                })
            }
            Phase::Queued | Phase::Submitted | Phase::Cancelled => None,
        }
    }
    /// Whether the next lazy MQ creation may start now. Drain ready callback effects first.
    #[must_use]
    pub fn connection_needed(&self, now: AbsoluteTime) -> bool {
        self.connection.is_none()
            && self.live_remote()
            && !self.event_due(now)
            && self
                .retry_at
                .is_some_and(|at| at.as_micros() != u64::MAX && at <= now)
    }
    /// Create a new virtual MQ epoch after its scheduled backoff. The host owns
    /// actual socket establishment and keeps the same epoch for its socket retries.
    pub fn begin_connection(&mut self, now: AbsoluteTime) -> Result<ConnectionEpoch, Error> {
        if !self.connection_needed(now) {
            return Err(Error::WouldBlock);
        }
        let next = self.last_epoch.checked_add(1).ok_or(Error::Overflow)?;
        let epoch = ConnectionEpoch(next);
        self.last_epoch = next;
        self.connection = Some(epoch);
        self.retry_at = None;
        Ok(epoch)
    }
    /// MQ configuration prevented creation before an epoch existed. Retry with
    /// the same original request deadlines and the next resolver-owner backoff.
    pub fn connection_unavailable(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        if !self.connection_needed(now) {
            return Err(Error::WouldBlock);
        }
        self.retry_at = None;
        self.schedule_retry(now);
        Ok(())
    }
    /// Source process_requests/reconnect continuation while no MQ exists. C
    /// retains this scheduled retry even after the final head was removed; a
    /// query admitted before the 1ms idle shutdown must reuse its original time.
    pub fn reconnect_inline(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        if self.connection.is_some() {
            return Err(Error::NotReady);
        }
        if self.retry_at.is_none() {
            self.retry_at = Some(Self::soon(now, self.backoff));
            self.backoff = Duration(self.backoff.0.saturating_mul(2).min(MAX_BACKOFF.0));
        }
        Ok(())
    }
    /// Whether this exact original request owns the current synchronous local
    /// or fallback callback continuation. It grants no authority over any other
    /// ready task; the host must return the previous callback first.
    #[must_use]
    pub fn callback_continuation_is(&self, request: RequestId) -> bool {
        self.continuation == Some(request) && self.owns_request(request)
    }
    /// A remote handler's fallback/terminal callbacks must return before its
    /// source process_requests continuation can advance the actual MQ head.
    #[must_use]
    pub fn terminal_callbacks_pending(&self) -> bool {
        self.slots.iter().any(|slot| {
            slot.state
                .is_some_and(|state| state.remote && matches!(state.phase, Phase::Finishing { .. }))
        })
    }
    fn epoch(&self, epoch: ConnectionEpoch) -> Result<(), Error> {
        if self.connection == Some(epoch) {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    /// Encode/admit only the FIFO head to the immutable host MQ. A capacity error
    /// leaves it unsent; success marks it submitted even before physical write,
    /// exactly like GNUNET_MQ_send in resolver_api.c.
    pub fn next_request(
        &mut self,
        epoch: ConnectionEpoch,
        output: &mut [u8],
        now: AbsoluteTime,
    ) -> Result<Outbound, Error> {
        self.encode_head(epoch, output, Some(now))
    }
    /// Copy a head at the source's synchronous process_requests boundary. This
    /// does not dispatch unrelated due scheduler tasks before MQ admission.
    /// The host must already own immutable output capacity/credit; callbacks
    /// still complete before the caller invokes this continuation after END.
    pub fn next_request_inline(
        &mut self,
        epoch: ConnectionEpoch,
        output: &mut [u8],
    ) -> Result<Outbound, Error> {
        self.encode_head(epoch, output, None)
    }
    fn encode_head(
        &mut self,
        epoch: ConnectionEpoch,
        output: &mut [u8],
        now: Option<AbsoluteTime>,
    ) -> Result<Outbound, Error> {
        self.epoch(epoch)?;
        if now.is_some_and(|now| self.event_due(now)) {
            return Err(Error::WouldBlock);
        }
        let index = self.head.ok_or(Error::WouldBlock)?;
        let state = self.slots[index].state.as_ref().ok_or(Error::Stale)?;
        if state.phase != Phase::Queued {
            return Err(Error::WouldBlock);
        }
        let request = match state.kind {
            Kind::Forward(family) => {
                Request::forward(state.wire, family, &state.name[..state.name_len])?
            }
            Kind::Reverse(address) => Request::reverse(state.wire, address),
        };
        let len = request.encode(self.profile, output)?;
        let wire_id = state.wire;
        let id = self.id(index);
        if let Some(s) = self.slots[index].state.as_mut() {
            s.phase = Phase::Submitted;
        }
        Ok(Outbound {
            epoch,
            request: id,
            wire_id,
            len,
        })
    }
    /// Retire a failed virtual connection, retrying the same head ID and original
    /// deadline. Already delivered reverse-name state is retained across retries.
    pub fn connection_lost(
        &mut self,
        epoch: ConnectionEpoch,
        now: AbsoluteTime,
    ) -> Result<(), Error> {
        self.epoch(epoch)?;
        self.connection = None;
        if let Some(head) = self.head
            && let Some(state) = self.slots[head].state
        {
            match state.phase {
                Phase::Submitted => {
                    if let Some(s) = self.slots[head].state.as_mut() {
                        s.phase = Phase::Queued;
                    }
                }
                Phase::Cancelled => {
                    self.unlink(head);
                    self.free(head);
                }
                _ => {}
            }
        }
        if self.live_remote() {
            self.schedule_retry(now);
        } else {
            self.check_idle(now);
        }
        Ok(())
    }
    /// Process one complete response. Values borrow only the frame, so the owner
    /// can be mutated/canceled before the next buffered response is delivered.
    /// Protocol errors retire the epoch; malformed identified payloads also queue
    /// the offending request's terminal event. END callbacks come from next_event.
    pub fn receive<'a>(
        &mut self,
        epoch: ConnectionEpoch,
        frame: Frame<'a>,
        now: AbsoluteTime,
    ) -> Result<Option<Event<'a>>, Error> {
        self.epoch(epoch)?;
        let response = match Response::decode(frame) {
            Ok(r) => r,
            Err(error) => {
                self.connection_lost(epoch, now)?;
                return Err(error);
            }
        };
        let Some(index) = self.slots.iter().position(|slot| {
            slot.state.is_some_and(|s| {
                s.remote
                    && s.wire == response.id()
                    && matches!(s.phase, Phase::Queued | Phase::Submitted | Phase::Cancelled)
            })
        }) else {
            self.connection_lost(epoch, now)?;
            return Err(Error::Malformed);
        };
        let state = self.slots[index].state.ok_or(Error::Stale)?;
        let id = self.id(index);
        if state.phase != Phase::Cancelled
            && state.deadline.as_micros() != u64::MAX
            && now >= state.deadline
        {
            self.finish(index, Completion::Timeout);
            self.connection_lost(epoch, now)?;
            return Err(Error::Deadline);
        }
        if response.is_end() {
            if state.phase == Phase::Cancelled {
                self.unlink(index);
                self.free(index);
                self.check_idle(now);
            } else {
                self.finish(index, Completion::End);
            }
            return Ok(None);
        }
        let event = match state.kind {
            Kind::Forward(_) => response.address().and_then(|address| {
                address
                    .map(|address| Event::Address {
                        request: id,
                        address,
                    })
                    .ok_or(Error::Malformed)
            }),
            Kind::Reverse(_) => response.hostname().and_then(|hostname| {
                hostname
                    .map(|hostname| Event::Hostname {
                        request: id,
                        hostname: Hostname::Resolved(hostname),
                    })
                    .ok_or(Error::Malformed)
            }),
        };
        let event = match event {
            Ok(value) => value,
            Err(error) => {
                if state.phase == Phase::Cancelled {
                    self.unlink(index);
                    self.free(index);
                } else {
                    self.finish(index, Completion::Malformed);
                }
                self.connection_lost(epoch, now)?;
                return Err(error);
            }
        };
        if let Some(s) = self.slots[index].state.as_mut()
            && matches!(s.kind, Kind::Reverse(_))
        {
            s.received_name = true;
        }
        if state.phase == Phase::Cancelled {
            Ok(None)
        } else {
            Ok(Some(event))
        }
    }
    /// Perform the source's 1 ms idle close when no remote requests remain live.
    /// Return the actual epoch for the host to close; even None reclaims canceled
    /// tombstones and resets backoff. This is not permanent owner destruction.
    pub fn poll_idle_close(&mut self, now: AbsoluteTime) -> Option<ConnectionEpoch> {
        if self
            .idle_at
            .is_none_or(|at| at.as_micros() == u64::MAX || at > now)
            || self.live_remote()
        {
            return None;
        }
        self.idle_at = None;
        self.retry_at = None;
        self.backoff = INITIAL_BACKOFF;
        for index in 0..R {
            if self.slots[index]
                .state
                .is_some_and(|s| s.phase == Phase::Cancelled)
            {
                self.unlink(index);
                self.free(index);
            }
        }
        self.connection.take()
    }
    /// Official disconnect precondition: every queued remote request must already
    /// be canceled/completed. Deferred numeric tasks are independent, like C.
    /// Returns the epoch whose MQ the host must destroy, retaining no socket itself.
    pub fn disconnect(&mut self) -> Result<Option<ConnectionEpoch>, Error> {
        if self.slots.iter().any(|slot| {
            slot.state
                .is_some_and(|s| s.remote && s.phase != Phase::Cancelled)
        }) {
            return Err(Error::WouldBlock);
        }
        for index in 0..R {
            if self.slots[index]
                .state
                .is_some_and(|s| s.phase == Phase::Cancelled)
            {
                self.unlink(index);
                self.free(index);
            }
        }
        self.retry_at = None;
        self.idle_at = None;
        Ok(self.connection.take())
    }
    /// Earliest timer/task wakeup. Host I/O can wake earlier. Already queued
    /// ready tasks use ZERO_ABS; this hint does not rewrite request_deadline.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<AbsoluteTime> {
        self.slots
            .iter()
            .filter_map(|slot| {
                slot.state.and_then(|s| match s.phase {
                    Phase::Local(_) | Phase::Finishing { .. } => Some(AbsoluteTime::from_micros(0)),
                    Phase::Queued | Phase::Submitted if s.registered_ready => {
                        Some(AbsoluteTime::from_micros(0))
                    }
                    Phase::Queued | Phase::Submitted => {
                        (s.deadline.as_micros() != u64::MAX).then_some(s.deadline)
                    }
                    Phase::Cancelled => None,
                })
            })
            .chain(self.retry_at.filter(|at| at.as_micros() != u64::MAX))
            .chain(self.idle_at.filter(|at| at.as_micros() != u64::MAX))
            .min()
    }
    /// Current virtual connection, for host cleanup and stale-epoch protection.
    #[must_use]
    pub const fn connection_epoch(&self) -> Option<ConnectionEpoch> {
        self.connection
    }
    /// Whether this original-owner generation is still pending, including drains.
    #[must_use]
    pub fn owns_request(&self, id: RequestId) -> bool {
        self.index(id).is_ok()
    }
    /// Whether callbacks remain enabled for this pending original-owner generation.
    #[must_use]
    pub fn callbacks_enabled(&self, id: RequestId) -> bool {
        self.index(id)
            .ok()
            .and_then(|i| self.slots[i].state)
            .is_some_and(|s| s.phase != Phase::Cancelled)
    }
    /// Count all reserved slots, including sent-cancel drains and pending terminal events.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.slots.iter().filter(|s| s.state.is_some()).count()
    }
    /// Original absolute request deadline, never restarted by transport retries.
    /// u64::MAX means FOREVER, including saturation on finite addition overflow.
    pub fn request_deadline(&self, id: RequestId) -> Result<AbsoluteTime, Error> {
        let index = self.index(id)?;
        self.slots[index]
            .state
            .map(|s| s.deadline)
            .ok_or(Error::StaleGeneration)
    }
}
fn local_address(hostname: &[u8], family: Family) -> Option<Local> {
    if let Ok(text) = core::str::from_utf8(hostname)
        && let Ok(address) = text.parse::<IpAddr>()
        && family.accepts(address)
    {
        return Some(Local {
            first: address,
            second: None,
            reverse: false,
        });
    }
    if !hostname.eq_ignore_ascii_case(b"localhost")
        && !hostname.eq_ignore_ascii_case(b"ip6-localnet")
    {
        return None;
    }
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    Some(match family {
        Family::Any => Local {
            first: v6,
            second: Some(v4),
            reverse: false,
        },
        Family::V4 => Local {
            first: v4,
            second: None,
            reverse: false,
        },
        Family::V6 => Local {
            first: v6,
            second: None,
            reverse: false,
        },
    })
}

#[cfg(test)]
mod boundaries {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Private exhaustion boundaries must fail without generation or timer reuse."
    )]
    use super::*;
    #[test]
    fn exhausted_slot_generation_is_retired_instead_of_wrapping() -> Result<(), Error> {
        let mut h = ResolverHandle::<1, 16>::new(FamilyProfile::LINUX, true)?;
        h.slots[0].generation = u32::MAX;
        let id = h.ip_get(
            b"127.0.0.1",
            Family::Any,
            Duration(0),
            AbsoluteTime::from_micros(0),
        )?;
        assert_eq!(id.resource_id().generation, u32::MAX);
        assert!(matches!(
            h.next_event(AbsoluteTime::from_micros(0)),
            Some(Event::Address { .. })
        ));
        assert!(matches!(
            h.next_event(AbsoluteTime::from_micros(0)),
            Some(Event::Complete { .. })
        ));
        assert!(h.slots[0].retired);
        assert_eq!(
            h.ip_get(
                b"127.0.0.1",
                Family::Any,
                Duration(0),
                AbsoluteTime::from_micros(0)
            ),
            Err(Error::Capacity)
        );
        assert_eq!(
            h.request_cancel(id, AbsoluteTime::from_micros(0)),
            Err(Error::StaleGeneration)
        );
        Ok(())
    }
    #[test]
    fn wire_counter_wraps_but_never_collides_with_a_live_local_or_remote_slot() -> Result<(), Error>
    {
        let mut h = ResolverHandle::<2, 16>::new(FamilyProfile::LINUX, true)?;
        let first = h.ip_get(
            b"127.0.0.1",
            Family::Any,
            Duration(0),
            AbsoluteTime::from_micros(0),
        )?;
        h.last_wire = u32::MAX;
        let zero = h.ip_get(
            b"a.invalid",
            Family::Any,
            Duration(100_000),
            AbsoluteTime::from_micros(0),
        )?;
        let index = h.index(zero)?;
        assert_eq!(
            h.slots[index].state.ok_or(Error::Stale)?.wire,
            WireId::from_native(0)
        );
        h.request_cancel(zero, AbsoluteTime::from_micros(0))?;
        h.last_wire = 0;
        let second = h.ip_get(
            b"b.invalid",
            Family::Any,
            Duration(100_000),
            AbsoluteTime::from_micros(0),
        )?;
        assert_eq!(
            h.slots[h.index(second)?].state.ok_or(Error::Stale)?.wire,
            WireId::from_native(2)
        );
        assert!(h.owns_request(first));
        Ok(())
    }
    #[test]
    fn exponential_backoff_caps_at_fifteen_minutes_and_idle_close_resets_it() -> Result<(), Error> {
        let mut h = ResolverHandle::<1, 16>::new(FamilyProfile::LINUX, true)?;
        let id = h.ip_get(
            b"a.invalid",
            Family::Any,
            Duration(u64::MAX),
            AbsoluteTime::from_micros(0),
        )?;
        let mut now = AbsoluteTime::from_micros(0);
        let mut expected = 1_000;
        let mut bytes = [0; 64];
        for _ in 0..32 {
            let at = h.retry_at.ok_or(Error::NotReady)?;
            assert_eq!(at.as_micros() - now.as_micros(), expected);
            let e = h.begin_connection(at)?;
            h.next_request(e, &mut bytes, at)?;
            h.connection_lost(e, at)?;
            now = at;
            expected = expected.saturating_mul(2).min(MAX_BACKOFF.0);
        }
        assert_eq!(expected, MAX_BACKOFF.0);
        h.request_cancel(id, now)?;
        assert_eq!(h.poll_idle_close(SelfClock::after(now, 1_000)), None);
        let later = SelfClock::after(now, 2_000);
        h.ip_get(b"b.invalid", Family::Any, Duration(100_000), later)?;
        assert_eq!(h.retry_at, Some(SelfClock::after(later, 1_000)));
        Ok(())
    }
    #[test]
    fn admission_configuration_updates_preserve_original_retry_and_live_request()
    -> Result<(), Error> {
        let mut h = ResolverHandle::<2, 16>::new(FamilyProfile::LINUX, true)?;
        let first = h.ip_get(
            b"a.invalid",
            Family::Any,
            Duration(u64::MAX),
            AbsoluteTime::from_micros(0),
        )?;
        let at = h.retry_at.ok_or(Error::NotReady)?;
        let epoch = h.begin_connection(at)?;
        h.next_request(epoch, &mut [0; 64], at)?;
        h.connection_lost(epoch, at)?;
        let retry = h.retry_at;
        let backoff = h.backoff;
        let sequence = (h.last_wire, h.order, h.last_epoch);
        h.update_configuration_admissibility(false);
        assert_eq!(h.retry_at, retry);
        assert_eq!(h.backoff, backoff);
        assert!(h.owns_request(first));
        assert_eq!(
            h.ip_get(b"b.invalid", Family::Any, Duration(10_000), at),
            Err(Error::Unavailable)
        );
        assert_eq!((h.last_wire, h.order, h.last_epoch), sequence);
        h.update_configuration_admissibility(true);
        let second = h.ip_get(b"b.invalid", Family::Any, Duration(10_000), at)?;
        assert!(h.owns_request(first));
        assert!(h.owns_request(second));
        assert_eq!(h.retry_at, retry);
        assert_eq!(h.backoff, backoff);
        Ok(())
    }
    struct SelfClock;
    impl SelfClock {
        fn after(now: AbsoluteTime, n: u64) -> AbsoluteTime {
            AbsoluteTime::from_micros(now.as_micros() + n)
        }
    }
    #[test]
    fn order_and_epoch_exhaustion_reject_before_committing() -> Result<(), Error> {
        let mut h = ResolverHandle::<1, 16>::new(FamilyProfile::LINUX, true)?;
        h.order = u64::MAX;
        assert_eq!(
            h.ip_get(
                b"a.invalid",
                Family::Any,
                Duration(10_000),
                AbsoluteTime::from_micros(0)
            ),
            Err(Error::Overflow)
        );
        assert_eq!(h.pending_requests(), 0);
        assert_eq!(h.last_wire, 0);
        h.order = 0;
        h.ip_get(
            b"a.invalid",
            Family::Any,
            Duration(10_000),
            AbsoluteTime::from_micros(0),
        )?;
        h.last_epoch = u64::MAX;
        assert_eq!(
            h.begin_connection(AbsoluteTime::from_micros(1_000)),
            Err(Error::Overflow)
        );
        assert_eq!(h.connection_epoch(), None);
        assert_eq!(h.retry_at, Some(AbsoluteTime::from_micros(1_000)));
        assert_eq!(h.pending_requests(), 1);
        Ok(())
    }
}
