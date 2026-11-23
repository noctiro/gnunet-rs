//! Official local DATASTORE semantics over Rust backend ports.
//! The allocation-free owner starts no service, socket or task.
#![no_std]
#![forbid(unsafe_code)]
pub mod backend;
mod work;
use backend::{
    Backend, BackendError, ENTRY_OVERHEAD, Failure, Lifecycle, Maintenance, MaintenancePolicy,
    Usage,
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, MAX_MESSAGE_SIZE,
    datastore::{MAX_VALUE_BYTES, Request, Response, Status},
};
pub use work::{Command, Completion, Dispatch, WorkId};

/// Minimum caller buffer for any status request, including all bounded diagnostics.
pub const STATUS_BUFFER_BYTES: usize = 128;
/// Caller query buffer, preflighted before selection/replication side effects.
pub const QUERY_BUFFER_BYTES: usize = MAX_MESSAGE_SIZE;
/// Native-worker reply storage needed before any backend/reservation effect.
/// A previously decoded request remains borrowed; no payload copy or fill occurs.
#[must_use]
pub const fn required_output(request: Request<'_>) -> usize {
    match request {
        Request::Drop => 0,
        Request::Get { .. } | Request::ZeroAnonymity { .. } | Request::Replication => {
            QUERY_BUFFER_BYTES
        }
        _ => STATUS_BUFFER_BYTES,
    }
}
/// Exclusive nonzero-sized identity storage for one service owner lifetime.
#[derive(Debug, Default)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Fresh identity storage; it introduces no field on the official wire.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
/// Original local physical client identity, never a peer identity or request RID.
#[derive(Clone, Copy, Debug)]
pub struct ClientId<'a> {
    owner: &'a Instance,
    serial: u64,
}
impl PartialEq for ClientId<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for ClientId<'_> {}
/// Caller-owned active-connection slot; stale IDs cannot alias a replacement.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientSlot {
    serial: u64,
    active: bool,
}
impl ClientSlot {
    /// Unused storage for one original local connection.
    pub const EMPTY: Self = Self {
        serial: 0,
        active: false,
    };
}
/// Caller-owned connection-scoped storage reservation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReservationSlot {
    client: u64,
    rid: u32,
    // One quota guarantee covers content and per-entry storage overhead.
    // Entry counts are sizing inputs, not a separate PUT permission counter.
    remaining: u64,
}
impl ReservationSlot {
    /// Unused storage for one connection-scoped reservation.
    pub const EMPTY: Self = Self {
        client: 0,
        rid: 0,
        remaining: 0,
    };
}
/// Service policy. Cache space follows the official quota/8 policy.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Logical value bytes plus the official 256-byte entry charge.
    pub quota_bytes: u64,
    /// Local accepted PUT payload limit, at most the u16 IPC payload limit.
    pub max_value_bytes: usize,
    /// Finite reclamation work in each atomic PUT transaction.
    pub max_put_evictions: usize,
    /// Finite reclamation work in each explicit maintenance slice.
    pub max_maintenance_evictions: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            quota_bytes: 1024 * 1024 * 1024,
            max_value_bytes: MAX_VALUE_BYTES,
            max_put_evictions: 4096,
            max_maintenance_evictions: 64,
        }
    }
}
/// Caller-supplied entropy, acquired before backend mutation. No private random
/// wire field is introduced and no process-global RNG is hidden in this owner.
pub trait Entropy {
    /// Actual fresh random bits, or the original source refusal.
    fn next_u64(&mut self) -> Result<u64, Error>;
}
/// Preserved native/backend cause, independent of the intentionally small wire diagnostic.
#[derive(Debug)]
pub enum Fault<E> {
    /// Original backend error, including its commit stage and certainty.
    Backend(E),
    /// Original random-source refusal.
    Entropy(Error),
}
/// Explicit maintenance refusal versus the original backend cause.
#[derive(Debug)]
pub enum WorkError<E> {
    /// Closed/fenced owner or invalid local quota accounting.
    Protocol(Error),
    /// Actual backend error, preserving commit certainty and original cause.
    Backend(E),
}
/// A complete retained response, an actual no-response DROP, or an uncertain
/// backend commit requiring physical close rather than a false failure STATUS.
#[derive(Debug)]
pub enum ReplyAction<E> {
    /// Send exactly this prefix of the caller-owned reply buffer.
    Reply {
        /// Actual encoded official frame bytes.
        bytes: usize,
        /// Actual local cause if the service returned a negative/empty reply.
        fault: Option<Fault<E>>,
    },
    /// DROP only marks drop-on-shutdown; it neither sends ACK nor immediately clears data.
    NoReply,
    /// Do not send a fabricated STATUS/DATA_END; retire the physical connection.
    /// Every later request is refused until external backend recovery and a new owner.
    Close {
        /// Original uncertain backend cause.
        fault: Fault<E>,
    },
}
/// Observable service accounting, distinct from disk pages and private journal files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    /// Configured hard logical quota.
    pub quota_bytes: u64,
    /// Official quota/8 cache margin.
    pub cache_bytes: u64,
    /// Bytes plus entry overhead still held by actual client reservations.
    pub reserved_bytes: u64,
    /// Current authoritative backend logical charge.
    pub used_bytes: u64,
    /// Current public admission hint; no time freshness is implied.
    pub min_expiration: AbsoluteTime,
    /// A prior DROP requires clearing the backend at service shutdown.
    pub drop_on_shutdown: bool,
    /// An actual uncertain backend commit forbids further ordinary replies.
    pub fenced: bool,
}
/// Allocation-free complete service owner. The host must serialize this owner
/// with one matching backend in a dedicated worker, and physically close each
/// actual connection before disconnect. Backend recovery must retire all old
/// connections and reconstruct the owner; no unsafe fence-clear API exists.
pub struct Service<'id, 'slots> {
    owner: &'id Instance,
    clients: &'slots mut [ClientSlot],
    reservations: &'slots mut [ReservationSlot],
    config: Config,
    client_serial: u64,
    reservation_serial: u32,
    work_serial: u64,
    work: Option<work::Pending>,
    reserved: u64,
    min_expiration: AbsoluteTime,
    drop_on_shutdown: bool,
    fenced: bool,
    closed: bool,
}
impl<'id, 'slots> Service<'id, 'slots> {
    /// Bind initialized caller slots. The caller supplies a ready/recovered backend
    /// for all later calls; changing datasets under an active owner is invalid.
    pub fn new(
        instance: &'id mut Instance,
        clients: &'slots mut [ClientSlot],
        reservations: &'slots mut [ReservationSlot],
        config: Config,
    ) -> Result<Self, Error> {
        if clients.is_empty() || config.max_value_bytes > MAX_VALUE_BYTES {
            return Err(Error::InvalidInput);
        }
        clients.fill(ClientSlot::default());
        reservations.fill(ReservationSlot::default());
        Ok(Self {
            owner: instance,
            clients,
            reservations,
            config,
            client_serial: 0,
            reservation_serial: 0,
            work_serial: 0,
            work: None,
            reserved: 0,
            min_expiration: AbsoluteTime::from_micros(0),
            drop_on_shutdown: false,
            fenced: false,
            closed: false,
        })
    }
    fn index(&self, client: ClientId<'id>) -> Result<usize, Error> {
        if !core::ptr::eq(client.owner, self.owner) {
            return Err(Error::Stale);
        }
        self.clients
            .iter()
            .position(|slot| slot.active && slot.serial == client.serial)
            .ok_or(Error::Stale)
    }
    /// Attach one actually accepted local connection, without a START handshake.
    pub fn connect(&mut self) -> Result<ClientId<'id>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.fenced {
            return Err(Error::OutcomeUnknown);
        }
        let index = self
            .clients
            .iter()
            .position(|slot| !slot.active)
            .ok_or(Error::Capacity)?;
        let serial = self.client_serial.checked_add(1).ok_or(Error::Overflow)?;
        self.clients[index] = ClientSlot {
            serial,
            active: true,
        };
        self.client_serial = serial;
        Ok(ClientId {
            owner: self.owner,
            serial,
        })
    }
    /// Release all remaining quota of this actual retired connection.
    /// This remains available while fenced; it sends no fabricated service ACK.
    pub fn disconnect(&mut self, client: ClientId<'id>) -> Result<u64, Error> {
        let index = self.index(client)?;
        if self
            .work
            .as_ref()
            .is_some_and(|work| work.client == client.serial)
        {
            return Err(Error::WouldBlock);
        }
        let mut released = 0_u64;
        for slot in &*self.reservations {
            if slot.rid != 0 && slot.client == client.serial {
                released = released
                    .checked_add(slot.remaining)
                    .ok_or(Error::Overflow)?;
            }
        }
        let remaining = self
            .reserved
            .checked_sub(released)
            .ok_or(Error::InvalidInput)?;
        for slot in &mut *self.reservations {
            if slot.rid != 0 && slot.client == client.serial {
                *slot = ReservationSlot::default();
            }
        }
        self.reserved = remaining;
        self.clients[index].active = false;
        Ok(released)
    }
    /// Current accounting. When fenced, backend usage is only its last known
    /// value and cannot be interpreted as authority to acknowledge new work.
    pub fn accounting(&self, backend: &impl Lifecycle) -> Result<Accounting, Error> {
        Ok(Accounting {
            quota_bytes: self.config.quota_bytes,
            cache_bytes: self.config.quota_bytes / 8,
            reserved_bytes: self.reserved,
            used_bytes: backend.usage().charged()?,
            min_expiration: self.min_expiration,
            drop_on_shutdown: self.drop_on_shutdown,
            fenced: self.fenced,
        })
    }
    fn policy(
        &self,
        now: AbsoluteTime,
        reserved: u64,
        maximum: usize,
    ) -> Result<MaintenancePolicy, Error> {
        let ceiling = self
            .config
            .quota_bytes
            .checked_sub(reserved)
            .ok_or(Error::InvalidInput)?;
        Ok(MaintenancePolicy {
            now,
            ceiling_bytes: ceiling,
            target_bytes: ceiling.saturating_sub(self.config.quota_bytes / 8),
            max_evictions: maximum,
        })
    }
    fn record_hint(&mut self, maintenance: Maintenance) {
        if let Some(expiration) = maintenance.min_expiration {
            self.min_expiration = expiration;
        }
    }
    fn status<E>(
        &self,
        output: &mut [u8],
        code: i32,
        message: Option<&[u8]>,
        hint: AbsoluteTime,
        fault: Option<Fault<E>>,
    ) -> Result<ReplyAction<E>, Error> {
        let bytes = Response::Status(Status {
            code,
            min_expiration: hint,
            message,
        })
        .encode(output)?;
        Ok(ReplyAction::Reply { bytes, fault })
    }
    fn empty<E>(
        &self,
        output: &mut [u8],
        fault: Option<Fault<E>>,
    ) -> Result<ReplyAction<E>, Error> {
        Ok(ReplyAction::Reply {
            bytes: Response::End.encode(output)?,
            fault,
        })
    }
    fn backend_failure<E: BackendError>(
        &mut self,
        error: E,
        output: &mut [u8],
        status: Option<i32>,
        hint: AbsoluteTime,
    ) -> Result<ReplyAction<E>, Error> {
        if error.certainty() == Failure::Unknown {
            self.fenced = true;
            return Ok(ReplyAction::Close {
                fault: Fault::Backend(error),
            });
        }
        match status {
            Some(code) => self.status(
                output,
                code,
                Some(b"Datastore backend operation failed\0"),
                hint,
                Some(Fault::Backend(error)),
            ),
            None => self.empty(output, Some(Fault::Backend(error))),
        }
    }
    fn reserve<E>(
        &mut self,
        client: ClientId<'id>,
        amount: u64,
        entries: u32,
        usage: Usage,
        output: &mut [u8],
    ) -> Result<ReplyAction<E>, Error> {
        let cost = amount.checked_add(u64::from(entries) * ENTRY_OVERHEAD);
        let used = usage.charged()?;
        let fits = cost.is_some_and(|cost| {
            u128::from(used) + u128::from(self.reserved) + u128::from(cost)
                <= u128::from(self.config.quota_bytes)
        });
        if !fits {
            return self.status(
                output,
                0,
                Some(b"Insufficient space to satisfy request\0"),
                self.min_expiration,
                None,
            );
        }
        let Some(index) = self.reservations.iter().position(|slot| slot.rid == 0) else {
            return self.status(
                output,
                -1,
                Some(b"Reservation capacity exhausted\0"),
                self.min_expiration,
                None,
            );
        };
        let Some(rid) = self
            .reservation_serial
            .checked_add(1)
            .filter(|rid| *rid <= i32::MAX as u32)
        else {
            return self.status(
                output,
                -1,
                Some(b"Reservation identifiers exhausted\0"),
                self.min_expiration,
                None,
            );
        };
        let cost = cost.ok_or(Error::Overflow)?;
        let total = self.reserved.checked_add(cost).ok_or(Error::Overflow)?;
        self.reservations[index] = ReservationSlot {
            client: client.serial,
            rid,
            remaining: cost,
        };
        self.reserved = total;
        self.reservation_serial = rid;
        self.status(output, rid as i32, None, self.min_expiration, None)
    }
    fn reservation(&self, client: ClientId<'id>, rid: u32) -> Option<usize> {
        self.reservations
            .iter()
            .position(|slot| slot.rid == rid && rid != 0 && slot.client == client.serial)
    }
    /// Process one complete typed official request. Capacity and framing refusal
    /// occur before reservation/backend side effects. Query buffers cover the
    /// largest legal DATA before a replication decrement can commit.
    pub fn handle<B: Backend>(
        &mut self,
        client: ClientId<'id>,
        request: Request<'_>,
        backend: &mut B,
        output: &mut [u8],
        now: AbsoluteTime,
        entropy: &mut impl Entropy,
    ) -> Result<ReplyAction<B::Error>, Error> {
        match self.begin(client, request, || backend.usage(), output, now, entropy)? {
            Dispatch::Reply(reply) => Ok(reply),
            Dispatch::Run { id, command } => self.finish(&id, command.execute(backend), output),
        }
    }
    /// Run one explicit bounded expiry/cache slice on the dedicated backend
    /// worker. Any uncertain commit fences every subsequent ordinary request.
    pub fn maintain<B: Lifecycle>(
        &mut self,
        backend: &mut B,
        now: AbsoluteTime,
    ) -> Result<Maintenance, WorkError<B::Error>> {
        if self.closed {
            return Err(WorkError::Protocol(Error::Closed));
        }
        if self.fenced {
            return Err(WorkError::Protocol(Error::OutcomeUnknown));
        }
        if self.work.is_some() {
            return Err(WorkError::Protocol(Error::WouldBlock));
        }
        let policy = self
            .policy(now, self.reserved, self.config.max_maintenance_evictions)
            .map_err(WorkError::Protocol)?;
        let result = backend.maintain(policy);
        match result {
            Ok(report) => {
                self.record_hint(report);
                Ok(report)
            }
            Err(error) => {
                if error.certainty() == Failure::Unknown {
                    self.fenced = true;
                }
                Err(WorkError::Backend(error))
            }
        }
    }
    /// Permanently stop this owner and release connection accounting. Only an
    /// actual prior DROP clears a healthy backend, without a wire ACK. Recovery
    /// is required before another mutation if the original outcome is unknown.
    pub fn shutdown<B: Lifecycle>(&mut self, backend: &mut B) -> Result<bool, WorkError<B::Error>> {
        if self.work.is_some() {
            return Err(WorkError::Protocol(Error::WouldBlock));
        }
        self.closed = true;
        self.clients.fill(ClientSlot::default());
        self.reservations.fill(ReservationSlot::default());
        self.reserved = 0;
        if !self.drop_on_shutdown {
            return Ok(false);
        }
        if self.fenced {
            return Err(WorkError::Protocol(Error::OutcomeUnknown));
        }
        match backend.drop_all() {
            Ok(()) => {
                self.drop_on_shutdown = false;
                Ok(true)
            }
            Err(error) => {
                if error.certainty() == Failure::Unknown {
                    self.fenced = true;
                }
                Err(WorkError::Backend(error))
            }
        }
    }
}
