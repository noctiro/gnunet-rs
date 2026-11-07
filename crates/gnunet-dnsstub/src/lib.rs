//! Bounded v0.29.1 DNSSTUB operation owner, with caller-provided I/O and RNG.
//!
//! This raw UDP transfer layer does not validate DNS ID/QR or terminate after a
//! response. Callers receive explicitly unverified datagrams and must cancel
//! after their own validation. Retry is independent of any caller deadline.
#![no_std]
#![forbid(unsafe_code)]

use core::net::{IpAddr, SocketAddr};
use gnunet_types::{Duration, Error, GenerationalId, MonoInstant};

/// Actual `DNS_RETRANSMIT_DELAY`, in microseconds.
pub const DEFAULT_RETRY: Duration = Duration(250_000);
/// Maximum random slot probes before replacing the last occupied choice.
pub const SELECTION_ATTEMPTS: usize = 256;
/// DNS header length required by the original raw receive handler.
pub const MINIMUM_RESPONSE_LEN: usize = 12;

/// Request identity scoped to its original stub owner; never serialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RequestId(GenerationalId);
impl RequestId {
    /// Local slot/generation, not a DNS transaction ID.
    #[must_use]
    pub const fn resource_id(self) -> GenerationalId {
        self.0
    }
}
/// Local stable configured server entry, including duplicate addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServerId(u32);
/// Native socket family, never an extra DNS field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Family {
    /// IPv4 datagrams.
    V4,
    /// IPv6 datagrams.
    V6,
}
impl Family {
    const fn index(self) -> usize {
        match self {
            Self::V4 => 0,
            Self::V6 => 1,
        }
    }
    const fn of(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(_) => Self::V4,
            SocketAddr::V6(_) => Self::V6,
        }
    }
}
/// Cached socket identity, distinct from the request currently using that slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SocketId {
    slot: u32,
    family: Family,
    generation: u64,
}
impl SocketId {
    /// Zero-based request-pool slot whose socket is cached.
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.slot
    }
    /// Actual socket address family.
    #[must_use]
    pub const fn family(self) -> Family {
        self.family
    }
    /// Nonreused local socket generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}
/// One immutable send attempt identity; a stale result cannot finish a later one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AttemptId(u64);
/// Resolve returns both the new request and the old request's failure, when full.
/// The evicted token was retired before return and corresponds to C's NULL
/// callback. It never means a successful response or silent cancellation.
#[must_use = "Inspect evicted to notify the replaced request of failure"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    /// Newly admitted copied request.
    pub request: RequestId,
    /// Replaced request requiring its explicit failure notification.
    pub evicted: Option<RequestId>,
}
/// Actual work for the host. Socket opening must report its real result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Bind an ephemeral wildcard UDP socket for this family.
    OpenSocket {
        /// Newly issued cache token, not proof a socket exists yet.
        socket: SocketId,
    },
    /// Attempt one raw DNS datagram send and report `sent` even on syscall error.
    Send {
        /// Original local attempt.
        attempt: AttemptId,
        /// Original request, whose bytes are available from `query`.
        request: RequestId,
        /// An actually opened cache token.
        socket: SocketId,
        /// Exact configured destination, including native IPv6 scope/flow.
        destination: SocketAddr,
        /// Copied original request length.
        len: usize,
    },
}
/// Raw callback data. Neither the request token nor matching peer authenticates
/// the DNS contents, and a cached socket can receive a previous query's reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedDatagram<'a> {
    /// Active callback owner at arrival, not a DNS-ID match.
    pub request: RequestId,
    /// Actual sender supplied by the host.
    pub source: SocketAddr,
    /// Exact datagram bytes, borrowing only the host's receive buffer.
    pub bytes: &'a [u8],
}
/// Why a raw datagram was ignored; no terminal callback is manufactured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    /// Socket belongs to a retired or unknown generation.
    StaleSocket,
    /// Host supplied a source address from a different native socket family.
    WrongFamily,
    /// Receive interest was canceled or never scheduled.
    NotReading,
    /// No active request/callback remains in this slot.
    Cancelled,
    /// Sender IP/port is not in the current configured list.
    UnknownPeer,
    /// Fewer than twelve DNS header bytes.
    ShortPacket,
}
/// Logical stop facts. The host must also close all its actual socket owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stopped {
    /// Active requests retired without synthetic callbacks.
    pub requests: usize,
    /// Open/opening cached socket tokens invalidated.
    pub socket_tokens: usize,
}
#[derive(Clone, Copy)]
struct Server {
    address: SocketAddr,
    next: Option<usize>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum SocketState {
    Closed,
    Opening,
    Open,
}
#[derive(Clone, Copy)]
struct Cache {
    generation: u64,
    state: SocketState,
}
impl Cache {
    const EMPTY: Self = Self {
        generation: 0,
        state: SocketState::Closed,
    };
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    AwaitSocket,
    Ready,
    Emitted,
}
#[derive(Clone, Copy)]
struct Pending {
    attempt: AttemptId,
    request: RequestId,
    socket: SocketId,
    destination: SocketAddr,
    phase: Phase,
    at: MonoInstant,
}
struct Slot<const N: usize> {
    query: [u8; N],
    len: usize,
    current: u32,
    next_generation: u32,
    retired: bool,
    active: bool,
    next_server: Option<usize>,
    retry_at: Option<MonoInstant>,
    order: u64,
    reading: [bool; 2],
    sockets: [Cache; 2],
    pending: Option<Pending>,
}
impl<const N: usize> Slot<N> {
    const EMPTY: Self = Self {
        query: [0; N],
        len: 0,
        current: 0,
        next_generation: 0,
        retired: false,
        active: false,
        next_server: None,
        retry_at: None,
        order: 0,
        reading: [false; 2],
        sockets: [Cache::EMPTY; 2],
        pending: None,
    };
}
/// All seven DNSSTUB operations with explicit request, byte and server bounds.
/// R limits request-pool slots (up to two cached sockets each), N copied query
/// bytes and S configured server entries. No allocator, global RNG or clock.
pub struct DnsStub<const R: usize, const N: usize, const S: usize> {
    slots: [Slot<N>; R],
    count: usize,
    servers: [Option<Server>; S],
    head: Option<usize>,
    retry: Duration,
    order: u64,
    closed: bool,
}
impl<const R: usize, const N: usize, const S: usize> DnsStub<R, N, S> {
    /// Start using the full compile-time request-pool capacity.
    pub fn new() -> Result<Self, Error> {
        Self::start(R)
    }
    /// Runtime `GNUNET_DNSSTUB_start` count within the explicit caller profile.
    pub fn start(num_sockets: usize) -> Result<Self, Error> {
        if num_sockets == 0 || num_sockets > R {
            return Err(Error::Capacity);
        }
        if R > u32::MAX as usize || S > u32::MAX as usize {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            slots: core::array::from_fn(|_| Slot::EMPTY),
            count: num_sockets,
            servers: [None; S],
            head: None,
            retry: DEFAULT_RETRY,
            order: 0,
            closed: false,
        })
    }
    fn open(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    /// Add a literal numeric IP at port53. No hostname or OS resolution occurs.
    pub fn add_dns_ip(&mut self, address: &str) -> Result<ServerId, Error> {
        self.open()?;
        let ip: IpAddr = address.parse().map_err(|_| Error::InvalidInput)?;
        self.add_dns_sa(SocketAddr::new(ip, 53))
    }
    /// Add a copied endpoint at the head, as the official DLL insert does.
    /// Duplicate addresses and port0 remain representable; I/O errors are real
    /// host results, not fabricated configuration success/failure guesses.
    pub fn add_dns_sa(&mut self, address: SocketAddr) -> Result<ServerId, Error> {
        self.open()?;
        let index = self
            .servers
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.servers[index] = Some(Server {
            address,
            next: self.head,
        });
        self.head = Some(index);
        Ok(ServerId(index as u32))
    }
    /// Change subsequent retry periods, including for existing requests. A
    /// previously scheduled wakeup is not moved. FOREVER stops later retries.
    pub fn set_retry(&mut self, retry: Duration) -> Result<(), Error> {
        self.open()?;
        self.retry = retry;
        Ok(())
    }
    /// Original retry period; separate from higher-layer DNS query deadlines.
    #[must_use]
    pub const fn retry(&self) -> Duration {
        self.retry
    }
    fn id(&self, index: usize) -> RequestId {
        RequestId(GenerationalId {
            index: index as u32,
            generation: self.slots[index].current,
        })
    }
    fn request_index(&self, id: RequestId) -> Result<usize, Error> {
        let i = id.0.index as usize;
        if !self.closed
            && i < self.count
            && self.slots[i].active
            && self.slots[i].current == id.0.generation
        {
            Ok(i)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    /// Copy and admit a request using up to256 caller-generated random indices.
    /// If all sampled slots are occupied, replace the final choice and return
    /// its failure token. Every fallible preflight precedes business mutation.
    pub fn resolve(
        &mut self,
        request: &[u8],
        now: MonoInstant,
        mut random_index: impl FnMut(u32) -> Result<u32, Error>,
    ) -> Result<Admission, Error> {
        self.open()?;
        let head = self.head.ok_or(Error::Unavailable)?;
        if request.len() > N {
            return Err(Error::Capacity);
        }
        let order = self.order.checked_add(1).ok_or(Error::Overflow)?;
        let mut selected = None;
        for _ in 0..SELECTION_ATTEMPTS {
            let i = random_index(self.count as u32)? as usize;
            if i >= self.count {
                return Err(Error::InvalidInput);
            }
            if self.slots[i].retired {
                continue;
            }
            selected = Some(i);
            if !self.slots[i].active {
                break;
            }
        }
        let i = selected.ok_or(Error::Capacity)?;
        let evicted = self.slots[i].active.then(|| self.id(i));
        let slot = &mut self.slots[i];
        slot.current = slot.next_generation;
        if let Some(next) = slot.next_generation.checked_add(1) {
            slot.next_generation = next;
        } else {
            slot.retired = true;
        }
        slot.query[..request.len()].copy_from_slice(request);
        slot.len = request.len();
        slot.active = true;
        slot.next_server = Some(head);
        slot.retry_at = Some(now);
        slot.order = order;
        slot.reading = [false; 2];
        slot.pending = None;
        self.order = order;
        Ok(Admission {
            request: self.id(i),
            evicted,
        })
    }
    /// Cancel without callback or wire message, retaining copied bytes/sockets
    /// until that slot is reused or the context stops.
    pub fn resolve_cancel(&mut self, id: RequestId) -> Result<(), Error> {
        let i = self.request_index(id)?;
        let s = &mut self.slots[i];
        s.active = false;
        s.retry_at = None;
        s.pending = None;
        s.reading = [false; 2];
        Ok(())
    }
    /// Borrow the exact owned original bytes, not a rebuilt DNS packet.
    pub fn query(&self, id: RequestId) -> Result<&[u8], Error> {
        let i = self.request_index(id)?;
        Ok(&self.slots[i].query[..self.slots[i].len])
    }
    fn socket_index(&self, socket: SocketId) -> Result<(usize, usize), Error> {
        let i = socket.slot as usize;
        let family = socket.family.index();
        if self.closed || i >= self.count {
            return Err(Error::StaleGeneration);
        }
        let cache = self.slots[i].sockets[family];
        if cache.generation != socket.generation || cache.state == SocketState::Closed {
            return Err(Error::StaleGeneration);
        }
        Ok((i, family))
    }
    /// Report an actual socket bind result. A late result cannot resurrect a
    /// closed token or send data for a retired request.
    pub fn socket_opened(&mut self, socket: SocketId, success: bool) -> Result<(), Error> {
        let (i, family) = self.socket_index(socket)?;
        if self.slots[i].sockets[family].state != SocketState::Opening {
            return Err(Error::StaleGeneration);
        }
        let slot = &mut self.slots[i];
        slot.sockets[family].state = if success {
            SocketState::Open
        } else {
            SocketState::Closed
        };
        if let Some(p) = slot.pending.as_mut()
            && p.socket == socket
            && p.phase == Phase::AwaitSocket
        {
            if success {
                p.phase = Phase::Ready;
            } else {
                slot.pending = None;
            }
        }
        Ok(())
    }
    fn send_action(&self, i: usize, pending: Pending) -> Action {
        Action::Send {
            attempt: pending.attempt,
            request: pending.request,
            socket: pending.socket,
            destination: pending.destination,
            len: self.slots[i].len,
        }
    }
    /// Produce one lazy open/send effect in due-time/insertion order. The next
    /// retry and round-robin cursor advance before I/O, including on bind failure.
    pub fn next_action(&mut self, now: MonoInstant) -> Result<Option<Action>, Error> {
        self.open()?;
        if let Some((i, mut pending)) = self.slots[..self.count]
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                s.pending
                    .filter(|p| p.phase == Phase::Ready)
                    .map(|p| (i, p))
            })
            .min_by_key(|(_, p)| p.attempt.0)
        {
            pending.phase = Phase::Emitted;
            self.slots[i].pending = Some(pending);
            return Ok(Some(self.send_action(i, pending)));
        }
        let Some(i) = self.slots[..self.count]
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                if !s.active || s.pending.is_some() {
                    return None;
                }
                s.retry_at
                    .filter(|at| at.0 != u64::MAX && *at <= now)
                    .map(|at| ((at, s.order), i))
            })
            .min_by_key(|(key, _)| *key)
            .map(|(_, i)| i)
        else {
            return Ok(None);
        };
        let order = self.order.checked_add(1).ok_or(Error::Overflow)?;
        let server = self.servers[self.slots[i].next_server.ok_or(Error::NotReady)?]
            .ok_or(Error::NotReady)?;
        let family = Family::of(server.address);
        let fi = family.index();
        let cache = self.slots[i].sockets[fi];
        let generation = if cache.state == SocketState::Closed {
            cache.generation.checked_add(1).ok_or(Error::Overflow)?
        } else {
            cache.generation
        };
        let socket = SocketId {
            slot: i as u32,
            family,
            generation,
        };
        let phase = match cache.state {
            SocketState::Closed | SocketState::Opening => Phase::AwaitSocket,
            SocketState::Open => Phase::Emitted,
        };
        let pending = Pending {
            attempt: AttemptId(order),
            request: self.id(i),
            socket,
            destination: server.address,
            phase,
            at: now,
        };
        let retry = now.0.saturating_add(self.retry.0);
        let slot = &mut self.slots[i];
        slot.next_server = server.next.or(self.head);
        slot.retry_at = (retry != u64::MAX).then_some(MonoInstant(retry));
        slot.order = order;
        slot.pending = Some(pending);
        self.order = order;
        if cache.state == SocketState::Closed {
            slot.sockets[fi] = Cache {
                generation,
                state: SocketState::Opening,
            };
            Ok(Some(Action::OpenSocket { socket }))
        } else if cache.state == SocketState::Open {
            Ok(Some(self.send_action(i, pending)))
        } else {
            Ok(None)
        }
    }
    /// Record that a real send syscall was attempted, including its failures.
    /// No send outcome is a response; retry remains scheduled in every case.
    /// Cached sockets in both families become readable, matching schedule_read.
    pub fn sent(&mut self, attempt: AttemptId) -> Result<(), Error> {
        self.open()?;
        let i = self.slots[..self.count]
            .iter()
            .position(|s| {
                s.pending
                    .is_some_and(|p| p.attempt == attempt && p.phase == Phase::Emitted)
            })
            .ok_or(Error::StaleGeneration)?;
        self.slots[i].pending = None;
        self.slots[i].reading = self.slots[i]
            .sockets
            .map(|cache| cache.state == SocketState::Open);
        Ok(())
    }
    /// A receive failure invalidates only that actual socket token; the request
    /// and periodic retry remain live, and a future retry can reopen its family.
    pub fn socket_failed(&mut self, socket: SocketId) -> Result<(), Error> {
        let (i, family) = self.socket_index(socket)?;
        self.slots[i].sockets[family].state = SocketState::Closed;
        self.slots[i].reading[family] = false;
        if self.slots[i].pending.is_some_and(|p| p.socket == socket) {
            self.slots[i].pending = None;
        }
        Ok(())
    }
    /// Check only actual raw-stub receive conditions. DNS ID, QR, source scope
    /// and payload content are not validated by C's handler. IPv4 native padding
    /// is replaced with its intended IP/port comparison; no padding is read.
    pub fn receive<'a>(
        &self,
        socket: SocketId,
        source: SocketAddr,
        bytes: &'a [u8],
    ) -> Result<UnverifiedDatagram<'a>, DropReason> {
        let (i, fi) = self
            .socket_index(socket)
            .map_err(|_| DropReason::StaleSocket)?;
        let slot = &self.slots[i];
        if Family::of(source) != socket.family {
            return Err(DropReason::WrongFamily);
        }
        if !slot.active {
            return Err(DropReason::Cancelled);
        }
        if !slot.reading[fi] || slot.sockets[fi].state != SocketState::Open {
            return Err(DropReason::NotReading);
        }
        if !self
            .servers
            .iter()
            .flatten()
            .any(|s| s.address.ip() == source.ip() && s.address.port() == source.port())
        {
            return Err(DropReason::UnknownPeer);
        }
        if bytes.len() < MINIMUM_RESPONSE_LEN {
            return Err(DropReason::ShortPacket);
        }
        Ok(UnverifiedDatagram {
            request: self.id(i),
            source,
            bytes,
        })
    }
    /// Earliest scheduler work, excluding outstanding host effects and FOREVER.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<MonoInstant> {
        if self.closed {
            return None;
        }
        self.slots[..self.count]
            .iter()
            .filter_map(|s| {
                if !s.active {
                    return None;
                }
                match s.pending {
                    Some(p) if p.phase == Phase::Ready => Some(p.at),
                    Some(_) => None,
                    None => s.retry_at,
                }
            })
            .min()
    }
    /// Actual opened sockets with active read interest; no fake bind completion.
    pub fn readable_sockets(&self) -> impl Iterator<Item = SocketId> + '_ {
        self.slots[..self.count]
            .iter()
            .enumerate()
            .flat_map(move |(i, s)| {
                [Family::V4, Family::V6]
                    .into_iter()
                    .filter_map(move |family| {
                        let c = s.sockets[family.index()];
                        (!self.closed
                            && s.active
                            && s.reading[family.index()]
                            && c.state == SocketState::Open)
                            .then_some(SocketId {
                                slot: i as u32,
                                family,
                                generation: c.generation,
                            })
                    })
            })
    }
    /// Stop logically, invalidate every token and emit no response callbacks.
    /// Host owners must close all cached sockets, including canceled slots.
    pub fn stop(&mut self) -> Stopped {
        let requests = self.slots.iter().filter(|s| s.active).count();
        let socket_tokens = self
            .slots
            .iter()
            .flat_map(|s| s.sockets)
            .filter(|s| s.state != SocketState::Closed)
            .count();
        for s in &mut self.slots {
            s.active = false;
            s.pending = None;
            s.retry_at = None;
            s.reading = [false; 2];
            for c in &mut s.sockets {
                c.state = SocketState::Closed;
            }
        }
        self.servers.fill(None);
        self.head = None;
        self.closed = true;
        Stopped {
            requests,
            socket_tokens,
        }
    }
    /// Number of active original callbacks, not received datagrams.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.slots.iter().filter(|s| s.active).count()
    }
    /// Whether an original-owner request token is still live.
    #[must_use]
    pub fn owns_request(&self, id: RequestId) -> bool {
        self.request_index(id).is_ok()
    }
    /// Configured request-pool size, within the caller's fixed capacity.
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.count
    }
    /// Whether stop invalidated this context permanently.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        self.closed
    }
    /// Copy one socket's actual current read interest without borrowing an
    /// iterator across the host's subsequent socket-result update.
    #[must_use]
    pub fn readable_socket_at(&self, slot: usize, family: Family) -> Option<SocketId> {
        let state = self.slots.get(slot)?;
        let cache = state.sockets[family.index()];
        (!self.closed
            && slot < self.count
            && state.active
            && state.reading[family.index()]
            && cache.state == SocketState::Open)
            .then_some(SocketId {
                slot: slot as u32,
                family,
                generation: cache.generation,
            })
    }
}

#[cfg(test)]
mod tests;
