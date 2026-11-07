//! Bounded real FS cache writes, replication selections and peer migration pauses.
//! Storage ACKs, native write completion and remote storage are distinct facts.
use super::{Entropy, Neighbor, Path, SendRetired};
use core::{cell::Cell, fmt, ptr};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, RelativeTime,
    datastore::Data,
    fs::BlockType,
    fs_gap::{MigrationStop, Put},
};
/// Official active incoming cache lifetime cap: one GNUnet year (365 days).
pub const YEAR_US: u64 = 365 * 24 * 60 * 60 * 1_000_000;
/// Active C avoids pushing blocks with less than thirty minutes remaining.
pub const MIN_PUSH_LIFETIME_US: u64 = 30 * 60 * 1_000_000;
/// Stable external identity for original local storage/control operations.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Empty caller-owned identity; no process-global identifiers are used.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
}
/// Exact original local operation; never a wire identifier.
#[derive(Clone, Copy)]
pub struct Token<'id> {
    owner: &'id Instance,
    serial: u64,
}
impl PartialEq for Token<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for Token<'_> {}
impl fmt::Debug for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FsStorageOperation")
            .field(&self.serial)
            .finish()
    }
}
impl Token<'_> {
    /// Local diagnostic label, without new operation authority.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
#[derive(Clone, Copy)]
enum Until {
    At(u64),
    Forever,
}
impl Until {
    fn active(self, now: u64) -> bool {
        match self {
            Self::At(end) => now < end,
            Self::Forever => true,
        }
    }
    fn duration(self, now: u64) -> RelativeTime {
        match self {
            Self::At(end) => RelativeTime::from_micros(end.saturating_sub(now)),
            Self::Forever => RelativeTime::FOREVER,
        }
    }
    fn from_duration(duration: RelativeTime, now: u64) -> Self {
        if duration.is_forever() {
            Self::Forever
        } else {
            Self::At(now.saturating_add(duration.as_micros()))
        }
    }
    fn later(self, other: Self) -> bool {
        match (self, other) {
            (Self::Forever, Self::At(_)) => true,
            (Self::At(a), Self::At(b)) => a > b,
            _ => false,
        }
    }
}
#[derive(Clone, Copy)]
struct Stop<'id> {
    token: Token<'id>,
    until: Until,
}
#[derive(Clone, Copy)]
struct Peer<'id> {
    neighbor: Neighbor<'id>,
    live: bool,
    identity: [u8; 32],
    paused: Until,
    wanted: Option<Until>,
    sent: Option<Until>,
    pending: Option<Stop<'id>>,
    backoff: u32,
}
/// One actual current connected remote CORE neighbor generation.
#[derive(Clone, Copy, Default)]
pub struct PeerSlot<'id> {
    record: Option<Peer<'id>>,
}
impl PeerSlot<'_> {
    /// Empty peer/pause/control ownership.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
#[derive(Clone, Copy)]
struct Cached<'id> {
    token: Token<'id>,
    origin: Neighbor<'id>,
    key: [u8; 64],
    priority: u32,
    requested: bool,
    length: usize,
    expiration: AbsoluteTime,
    running: bool,
}
/// Caller-owned original peer138 bytes retained until actual PUT terminal.
pub struct CacheSlot<'id, 'bytes> {
    record: Option<Cached<'id>>,
    bytes: &'bytes mut [u8],
}
impl<'id, 'bytes> CacheSlot<'id, 'bytes> {
    /// Borrow finite cache admission storage, without admitting IO.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self {
            record: None,
            bytes,
        }
    }
}
/// Actual original selected DATA metadata; replication is the score returned
/// before the service's already-committed selection decrement, never a target ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    /// Original stable DATA UID.
    pub uid: u64,
    /// Original DATA key, validated against the transferable block.
    pub key: [u8; 64],
    /// Actual transferable type; resolved type6 becomes DBLOCK while raw DATA is retained by host.
    pub kind: BlockType,
    /// Exact original selected DATA type, including descriptor type6.
    pub original_kind: u32,
    /// Actual original local DATA anonymity, not inferred from PUT.
    pub anonymity: u32,
    /// Actual original DATA priority.
    pub priority: u32,
    /// Original returned replication score before the selection decrement.
    pub replication: u32,
    /// Actual original DATA expiration.
    pub expiration: AbsoluteTime,
}
#[derive(Clone, Copy)]
struct Ready<'id> {
    token: Token<'id>,
    meta: Metadata,
    length: usize,
    targets: [[u8; 32]; 3],
    used: usize,
    path: Option<Path<'id>>,
    target: Option<Neighbor<'id>>,
}
/// One actual selected replication block, retaining bounded canonical138 bytes.
pub struct MigrationSlot<'id, 'bytes> {
    record: Option<Ready<'id>>,
    bytes: &'bytes mut [u8],
}
impl<'id, 'bytes> MigrationSlot<'id, 'bytes> {
    /// Borrow one selected-block buffer. No selection/decrement is performed.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self {
            record: None,
            bytes,
        }
    }
}
/// Explicit service-local caching/pushing policy, separate from peer source facts.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Official FS CONTENT_CACHING selection.
    pub caching: bool,
    /// Official FS CONTENT_PUSHING selection.
    pub pushing: bool,
    /// Minimum interval between actual GET_REPLICATION admissions.
    pub selection_interval_us: u64,
    /// Finite pause requested when local bounded cache capacity is unavailable.
    pub busy_pause_us: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            caching: true,
            pushing: true,
            selection_interval_us: 100_000,
            busy_pause_us: 5_000_000,
        }
    }
}
/// Explicit non-admission of an optional local cache write; no peer result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Declined {
    /// Service disabled incoming caching.
    Disabled,
    /// Actual bounded cache rows are all owned.
    Capacity,
    /// Actual received expiration is already elapsed.
    Expired,
    /// Valid peer block exceeds the native DATASTORE PUT payload bound.
    TooLarge,
}
/// Result of copied local cache admission, independent of routing the same block.
#[derive(Clone, Copy, Debug)]
pub enum CacheAdmission<'id> {
    /// Original bytes copied and an original local PUT is queued.
    Queued(Token<'id>),
    /// No PUT admitted; genuine GAP delivery is unaffected.
    Declined(Declined),
}
/// One exact local cache PUT input, with explicit C-compatible local policy.
pub struct CacheWrite<'a, 'id> {
    /// Original operation to retire with its actual STATUS.
    pub token: Token<'id>,
    /// Original received block and explicit local metadata.
    pub data: Data<'a>,
}
/// One real serialized storage request. A rejected admission must retire this token.
pub enum Command<'a, 'id> {
    /// Submit one original DATASTORE PUT; keep original138 until terminal.
    Put(CacheWrite<'a, 'id>),
    /// Select through actual GET_REPLICATION, including its score side effect.
    Replication(Token<'id>),
}
#[derive(Clone, Copy)]
enum Active<'id> {
    Cache(Token<'id>),
    Replication(Token<'id>),
}
/// Original selected migration candidate; no wire QUERY was received or invented.
pub struct Push<'a, 'id> {
    /// Original selected replication allocation.
    pub token: Token<'id>,
    /// Exact already-connected unpaused destination generation.
    pub neighbor: Neighbor<'id>,
    /// Canonical138 from actual selected DATA/value.
    pub frame: &'a [u8],
    /// Actual original local source fields, retained without anonymity downgrade.
    pub metadata: Metadata,
}
/// One original16-byte STOP to hand to CORE. It acknowledges no PUT.
#[derive(Clone, Copy, Debug)]
pub struct StopOffer<'id> {
    /// Original local control operation.
    pub token: Token<'id>,
    /// Original actual connected neighbor generation.
    pub neighbor: Neighbor<'id>,
    /// Exact official relative pause, including forever.
    pub message: MigrationStop,
}
/// Actual bounded local observations; no field claims remote storage completion.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Copied optional incoming cache requests.
    pub cache_admitted: u64,
    /// Actual local DATASTORE STATUS1 receipts.
    pub cache_stored: u64,
    /// Actual non1 cache STATUS receipts.
    pub cache_refused: u64,
    /// Explicit optional cache non-admissions.
    pub cache_declined: u64,
    /// Actual original GET_REPLICATION DATA receipts accepted.
    pub selected: u64,
    /// Actual DATA_END selection terminals; not network absence.
    pub storage_ends: u64,
    /// Original selections rejected by validity/lifetime policy.
    pub selected_rejected: u64,
    /// Original exposed/unknown storage effects; permanently fences this owner.
    pub unknown: u64,
    /// Original non-STATUS/non-DATA retirement observations, without an invented ACK.
    pub operations_retired: u64,
    /// Completed local CORE PUT handoffs, not remote-store ACKs.
    pub push_written: u64,
    /// Failed or uncertain original push handoffs, not replayed to same target.
    pub push_retired: u64,
    /// Original metadata for the most recent selected row.
    pub last_selected: Option<Metadata>,
    /// Actual official incoming pause controls.
    pub stops_received: u64,
    /// Actual completed local CORE STOP handoffs.
    pub stops_written: u64,
    /// Actual original STOP failures/retirements.
    pub stops_retired: u64,
}
/// Caller-driven fixed-storage cache/replication owner. All IO and resolution
/// are explicit host ports; it has no private database, task, clock or resolver.
pub struct Owner<'id, 'slots, 'bytes> {
    owner: &'id Instance,
    peers: &'slots mut [PeerSlot<'id>],
    cache: &'slots mut [CacheSlot<'id, 'bytes>],
    blocks: &'slots mut [MigrationSlot<'id, 'bytes>],
    limits: Limits,
    active: Option<Active<'id>>,
    next_selection: u64,
    peer_cursor: usize,
    after_cache: bool,
    stopping: bool,
    fenced: bool,
    report: Report,
}
impl<'id, 'slots, 'bytes> Owner<'id, 'slots, 'bytes> {
    /// Borrow fixed empty buffers before opening service ports.
    pub fn new(
        instance: &'id mut Instance,
        peers: &'slots mut [PeerSlot<'id>],
        cache: &'slots mut [CacheSlot<'id, 'bytes>],
        blocks: &'slots mut [MigrationSlot<'id, 'bytes>],
        limits: Limits,
    ) -> Result<Self, Error> {
        if peers.is_empty()
            || limits.caching && cache.is_empty()
            || limits.pushing && blocks.is_empty()
            || limits.selection_interval_us == 0
            || limits.busy_pause_us == 0
        {
            return Err(Error::InvalidInput);
        }
        if peers.iter().any(|p| p.record.is_some())
            || cache.iter().any(|p| p.record.is_some())
            || blocks.iter().any(|p| p.record.is_some())
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            owner: instance,
            peers,
            cache,
            blocks,
            limits,
            active: None,
            next_selection: 0,
            peer_cursor: 0,
            after_cache: false,
            stopping: false,
            fenced: false,
            report: Report::default(),
        })
    }
    fn token(&self) -> Result<Token<'id>, Error> {
        let serial = self
            .owner
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.owner.next.set(serial);
        Ok(Token {
            owner: self.owner,
            serial,
        })
    }
    fn peer(&self, n: Neighbor<'id>) -> Result<usize, Error> {
        self.peers
            .iter()
            .position(|p| p.record.is_some_and(|p| p.neighbor == n))
            .ok_or(Error::StaleGeneration)
    }
    /// Announce only an actual connected remote CORE generation.
    pub fn attach(&mut self, n: Neighbor<'id>, identity: [u8; 32]) -> Result<(), Error> {
        if let Ok(i) = self.peer(n) {
            return if self.peers[i].record.is_some_and(|p| p.live) {
                Ok(())
            } else {
                Err(Error::StaleGeneration)
            };
        }
        let slot = self
            .peers
            .iter()
            .position(|p| p.record.is_none())
            .ok_or(Error::Capacity)?;
        self.peers[slot].record = Some(Peer {
            neighbor: n,
            live: true,
            identity,
            paused: Until::At(0),
            wanted: None,
            sent: None,
            pending: None,
            backoff: 1_000_000,
        });
        Ok(())
    }
    /// Retire exactly this old generation. Original cache/selection/write work
    /// still needs its original terminal and cannot bind to a replacement peer.
    pub fn disconnect(&mut self, n: Neighbor<'id>) -> Result<(), Error> {
        let i = self.peer(n)?;
        if let Some(peer) = &mut self.peers[i].record {
            peer.live = false;
            peer.wanted = None;
            if peer.pending.is_none() {
                self.peers[i].record = None;
            }
        }
        Ok(())
    }
    fn request_stop(&mut self, n: Neighbor<'id>, until: Until) {
        if let Ok(i) = self.peer(n)
            && let Some(p) = &mut self.peers[i].record
            && p.live
            && p.wanted.is_none_or(|old| until.later(old))
        {
            p.wanted = Some(until)
        }
    }
    /// Apply the exact relative pause only to unsolicited migration. Later
    /// controls replace the deadline just like active C, including duration0.
    pub fn pause(
        &mut self,
        n: Neighbor<'id>,
        duration: RelativeTime,
        now: u64,
    ) -> Result<(), Error> {
        let i = self.peer(n)?;
        if !self.peers[i].record.is_some_and(|p| p.live) {
            return Err(Error::StaleGeneration);
        }
        self.peers[i]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .paused = Until::from_duration(duration, now);
        self.report.stops_received = self.report.stops_received.saturating_add(1);
        Ok(())
    }
    /// Whether this original unsolicited target is currently blocked/retired.
    #[must_use]
    pub fn blocked(&self, n: Neighbor<'id>, now: u64) -> bool {
        self.peer(n)
            .ok()
            .and_then(|i| self.peers[i].record)
            .is_none_or(|p| !p.live || p.paused.active(now))
    }
    /// Validate/copy one actual received138 as optional local cache work. The
    /// local anonymity1/replication0 policy is explicit, never peer metadata.
    pub fn receive(
        &mut self,
        n: Neighbor<'id>,
        frame: &[u8],
        priority: u32,
        requested: bool,
        now: u64,
    ) -> Result<CacheAdmission<'id>, Error> {
        self.receive_checked(
            n,
            super::CheckedPut::decode(frame)?,
            priority,
            requested,
            now,
        )
    }
    /// Copy a block already authenticated by the shared original input owner.
    pub fn receive_checked(
        &mut self,
        n: Neighbor<'id>,
        checked: super::CheckedPut<'_>,
        priority: u32,
        requested: bool,
        now: u64,
    ) -> Result<CacheAdmission<'id>, Error> {
        let peer = self.peer(n)?;
        if !self.peers[peer].record.is_some_and(|p| p.live) {
            return Err(Error::StaleGeneration);
        }
        let frame = checked.bytes();
        let put = checked.put();
        let key = checked.key();
        let declined = if self.stopping || self.fenced || !self.limits.caching {
            Some(Declined::Disabled)
        } else if put.block.len() > gnunet_wire::official::datastore::MAX_VALUE_BYTES {
            Some(Declined::TooLarge)
        } else if put.expiration.as_micros() <= now {
            Some(Declined::Expired)
        } else if self.cache.iter().all(|p| p.record.is_some()) {
            Some(Declined::Capacity)
        } else {
            None
        };
        if let Some(reason) = declined {
            self.report.cache_declined = self.report.cache_declined.saturating_add(1);
            if !requested {
                self.request_stop(n, Until::At(now.saturating_add(self.limits.busy_pause_us)))
            }
            return Ok(CacheAdmission::Declined(reason));
        }
        let slot = self
            .cache
            .iter()
            .position(|p| p.record.is_none())
            .ok_or(Error::Capacity)?;
        if self.cache[slot].bytes.len() < frame.len() {
            return Err(Error::Capacity);
        }
        let token = self.token()?;
        let expiration =
            AbsoluteTime::from_micros(put.expiration.as_micros().min(now.saturating_add(YEAR_US)));
        self.cache[slot].bytes[..frame.len()].copy_from_slice(frame);
        self.cache[slot].record = Some(Cached {
            token,
            origin: n,
            key,
            priority,
            requested,
            length: frame.len(),
            expiration,
            running: false,
        });
        self.report.cache_admitted = self.report.cache_admitted.saturating_add(1);
        Ok(CacheAdmission::Queued(token))
    }
    /// Admit at most one original storage request, with cache/selection alternation
    /// bounded by the real minimum selection interval and fixed block capacity.
    pub fn next_command(&mut self, now: u64) -> Result<Option<Command<'_, 'id>>, Error> {
        if self.stopping || self.fenced || self.active.is_some() {
            return Ok(None);
        }
        let selection_ready = self.limits.pushing
            && now >= self.next_selection
            && self.blocks.iter().any(|b| b.record.is_none())
            && self
                .peers
                .iter()
                .any(|p| p.record.is_some_and(|p| p.live && !p.paused.active(now)));
        if selection_ready && self.after_cache {
            let token = self.token()?;
            self.active = Some(Active::Replication(token));
            self.after_cache = false;
            return Ok(Some(Command::Replication(token)));
        }
        if let Some(i) = self
            .cache
            .iter()
            .position(|p| p.record.is_some_and(|c| !c.running))
        {
            let c = self.cache[i].record.as_mut().ok_or(Error::Conflict)?;
            c.running = true;
            let c = *c;
            self.active = Some(Active::Cache(c.token));
            self.after_cache = true;
            let put = Put::decode(&self.cache[i].bytes[..c.length])?;
            return Ok(Some(Command::Put(CacheWrite {
                token: c.token,
                data: Data {
                    reservation: 0,
                    kind: put.block_type.value(),
                    priority: c.priority,
                    anonymity: 1,
                    replication: 0,
                    uid: 0,
                    expiration: c.expiration,
                    key: &self.cache[i].record.as_ref().ok_or(Error::Conflict)?.key,
                    value: put.block,
                },
            })));
        }
        if selection_ready {
            let token = self.token()?;
            self.active = Some(Active::Replication(token));
            self.after_cache = false;
            return Ok(Some(Command::Replication(token)));
        }
        Ok(None)
    }
    /// Observe only the actual original local STATUS. No replay follows refusal.
    pub fn cache_status(
        &mut self,
        token: Token<'id>,
        code: i32,
        min_expiration: AbsoluteTime,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        if !matches!(self.active,Some(Active::Cache(t)) if t==token) {
            return Err(Error::StaleGeneration);
        }
        let i = self
            .cache
            .iter()
            .position(|p| p.record.is_some_and(|c| c.token == token && c.running))
            .ok_or(Error::StaleGeneration)?;
        let c = self.cache[i].record.ok_or(Error::Conflict)?;
        let pause = if code == 1 || c.requested {
            None
        } else if min_expiration.is_never() {
            Some(Until::Forever)
        } else if min_expiration.as_micros() > now {
            Some(Until::At(min_expiration.as_micros()))
        } else {
            let b = self
                .peer(c.origin)
                .ok()
                .and_then(|i| self.peers[i].record)
                .map_or(1_000_000, |p| p.backoff);
            let draw = entropy.uniform(b)?;
            if draw >= b {
                return Err(Error::InvalidInput);
            }
            Some(Until::At(now.saturating_add(u64::from(draw))))
        };
        self.cache[i].record = None;
        self.cache[i].bytes[..c.length].fill(0);
        self.active = None;
        if code == 1 {
            self.report.cache_stored = self.report.cache_stored.saturating_add(1);
            if let Ok(i) = self.peer(c.origin)
                && let Some(p) = &mut self.peers[i].record
            {
                p.backoff = (p.backoff / 2).max(1_000_000)
            }
        } else {
            self.report.cache_refused = self.report.cache_refused.saturating_add(1);
            if let Ok(i) = self.peer(c.origin)
                && let Some(p) = &mut self.peers[i].record
            {
                p.backoff = p.backoff.saturating_mul(2).min(3_600_000_000)
            }
            if let Some(until) = pause {
                self.request_stop(c.origin, until)
            }
        }
        Ok(())
    }
    /// Finish only an actual GET_REPLICATION DATA/END, after optional real type6
    /// resolution. Metadata is copied from the actual row; decrement is not repeated.
    pub fn selected(
        &mut self,
        token: Token<'id>,
        data: Option<Data<'_>>,
        now: u64,
    ) -> Result<(), Error> {
        let original_kind = data.map_or(0, |d| d.kind);
        self.selected_source(token, data, original_kind, now)
    }
    /// Settle the original selected type6 row using the real shared resolver's
    /// output. Original UID/score/anonymity/type remain separate from wire type1.
    pub fn selected_resolved(
        &mut self,
        token: Token<'id>,
        original: Data<'_>,
        value: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        if original.kind != 6 || original.value.len() != 72 {
            return Err(Error::Malformed);
        }
        self.selected_source(
            token,
            Some(Data {
                kind: 1,
                value,
                ..original
            }),
            6,
            now,
        )
    }
    fn selected_source(
        &mut self,
        token: Token<'id>,
        data: Option<Data<'_>>,
        original_kind: u32,
        now: u64,
    ) -> Result<(), Error> {
        if !matches!(self.active,Some(Active::Replication(t)) if t==token) {
            return Err(Error::StaleGeneration);
        }
        let interval = if data.is_none() {
            self.limits.selection_interval_us.max(5_000_000)
        } else {
            self.limits.selection_interval_us
        };
        let next_selection = now.checked_add(interval).ok_or(Error::Overflow)?;
        if let Some(data) = data {
            let put = Put {
                block_type: BlockType::new(data.kind),
                expiration: data.expiration,
                block: data.value,
            };
            let key = super::validate_put(put)?;
            if key != *data.key {
                return Err(Error::Authentication);
            }
            let meta = Metadata {
                uid: data.uid,
                key,
                kind: put.block_type,
                original_kind,
                anonymity: data.anonymity,
                priority: data.priority,
                replication: data.replication,
                expiration: data.expiration,
            };
            self.report.last_selected = Some(meta);
            if data.expiration.as_micros().saturating_sub(now) < MIN_PUSH_LIFETIME_US {
                self.report.selected_rejected = self.report.selected_rejected.saturating_add(1)
            } else {
                let i = self
                    .blocks
                    .iter()
                    .position(|b| b.record.is_none())
                    .ok_or(Error::Capacity)?;
                let n = put.encode(self.blocks[i].bytes)?;
                self.blocks[i].record = Some(Ready {
                    token,
                    meta,
                    length: n,
                    targets: [[0; 32]; 3],
                    used: 0,
                    path: None,
                    target: None,
                });
                self.report.selected = self.report.selected.saturating_add(1)
            }
        } else {
            self.report.storage_ends = self.report.storage_ends.saturating_add(1)
        }
        self.active = None;
        self.next_selection = next_selection;
        Ok(())
    }
    /// Explicit actual operation failure/no-effect admission refusal. Unknown
    /// permanently fences future mutations/selections and is never replayed.
    pub fn failed(&mut self, token: Token<'id>, unknown: bool, now: u64) -> Result<(), Error> {
        let matching =
            matches!(self.active,Some(Active::Cache(t)|Active::Replication(t)) if t==token);
        if !matching {
            return Err(Error::StaleGeneration);
        }
        for slot in &mut *self.cache {
            if slot.record.is_some_and(|c| c.token == token)
                && let Some(c) = slot.record.take()
            {
                slot.bytes[..c.length].fill(0)
            }
        }
        self.active = None;
        self.next_selection = now.saturating_add(self.limits.selection_interval_us.max(5_000_000));
        if unknown {
            self.fenced = true;
            self.report.unknown = self.report.unknown.saturating_add(1)
        }
        self.report.operations_retired = self.report.operations_retired.saturating_add(1);
        Ok(())
    }
    /// Select a real unpaused connected target, never discovery or ownpeer.
    pub fn next_push(&mut self, now: u64) -> Result<Option<Push<'_, 'id>>, Error> {
        if self.stopping || self.fenced {
            return Ok(None);
        }
        for i in 0..self.blocks.len() {
            let Some(b) = self.blocks[i].record else {
                continue;
            };
            if b.path.is_some() {
                continue;
            }
            if b.used >= 3
                || b.meta.expiration.as_micros().saturating_sub(now) < MIN_PUSH_LIFETIME_US
            {
                self.blocks[i].record = None;
                self.blocks[i].bytes[..b.length].fill(0);
                continue;
            }
            for off in 0..self.peers.len() {
                let j = (self.peer_cursor + off) % self.peers.len();
                let Some(p) = self.peers[j].record else {
                    continue;
                };
                if !p.live || p.paused.active(now) || b.targets[..b.used].contains(&p.identity) {
                    continue;
                }
                self.peer_cursor = (j + 1) % self.peers.len();
                return Ok(Some(Push {
                    token: b.token,
                    neighbor: p.neighbor,
                    frame: &self.blocks[i].bytes[..b.length],
                    metadata: b.meta,
                }));
            }
        }
        Ok(None)
    }
    /// Bind only the real dedicated GAP unsolicited path. Target attempts are
    /// reserved once; exposed or uncertain work cannot be replayed to that peer.
    pub fn bind_push(
        &mut self,
        token: Token<'id>,
        n: Neighbor<'id>,
        path: Path<'id>,
    ) -> Result<(), Error> {
        let peer = self.peers[self.peer(n)?]
            .record
            .ok_or(Error::StaleGeneration)?;
        if !peer.live {
            return Err(Error::StaleGeneration);
        }
        let identity = peer.identity;
        let slot = self
            .blocks
            .iter_mut()
            .find(|b| b.record.is_some_and(|b| b.token == token))
            .ok_or(Error::StaleGeneration)?;
        let b = slot.record.as_mut().ok_or(Error::Conflict)?;
        if b.path.is_some() || b.used >= 3 || b.targets[..b.used].contains(&identity) {
            return Err(Error::Conflict);
        }
        b.targets[b.used] = identity;
        b.used += 1;
        b.path = Some(path);
        b.target = Some(n);
        Ok(())
    }
    /// Actual original CORE handoff outcome; no remote storage is inferred.
    pub fn sent(&mut self, fact: SendRetired<'id>, confirmed_written: bool) -> Result<(), Error> {
        let Some(path) = fact.path else { return Ok(()) };
        let Some(slot) = self
            .blocks
            .iter_mut()
            .find(|b| b.record.is_some_and(|b| b.path == Some(path)))
        else {
            return Ok(());
        };
        let b = slot.record.as_mut().ok_or(Error::Conflict)?;
        if b.target != Some(fact.neighbor) {
            return Err(Error::Authentication);
        }
        b.path = None;
        b.target = None;
        if confirmed_written && fact.written {
            self.report.push_written = self.report.push_written.saturating_add(1)
        } else {
            self.report.push_retired = self.report.push_retired.saturating_add(1)
        }
        Ok(())
    }
    /// Original paths still owned for pause/cancel/drain coordination.
    pub fn paths(&self) -> impl Iterator<Item = (Path<'id>, Neighbor<'id>)> + '_ {
        self.blocks
            .iter()
            .filter_map(|b| b.record.and_then(|b| Some((b.path?, b.target?))))
    }
    /// Original selected row metadata still bound to this unsolicited path.
    #[must_use]
    pub fn path_metadata(&self, path: Path<'id>) -> Option<Metadata> {
        self.blocks
            .iter()
            .find_map(|slot| slot.record.filter(|b| b.path == Some(path)).map(|b| b.meta))
    }
    /// Read every original selected allocation and its attempted-target count.
    /// Counts are local attempts, never a remote replication acknowledgment.
    pub fn ready(
        &self,
    ) -> impl Iterator<Item = (Token<'id>, Metadata, usize, Option<Path<'id>>)> + '_ {
        self.blocks
            .iter()
            .filter_map(|slot| slot.record.map(|b| (b.token, b.meta, b.used, b.path)))
    }
    /// Retire an unadmitted original path only after its owner reports it done.
    pub fn retire_path(&mut self, path: Path<'id>) -> Result<(), Error> {
        let b = self
            .blocks
            .iter_mut()
            .find_map(|b| b.record.as_mut().filter(|b| b.path == Some(path)))
            .ok_or(Error::StaleGeneration)?;
        b.path = None;
        b.target = None;
        self.report.push_retired = self.report.push_retired.saturating_add(1);
        Ok(())
    }
    /// Prepare one actual official pressure control; pending originals cannot be
    /// replaced by newer durations or rebound to a new peer allocation.
    pub fn next_stop(&mut self, now: u64) -> Result<Option<StopOffer<'id>>, Error> {
        if self.stopping {
            return Ok(None);
        }
        for i in 0..self.peers.len() {
            let Some(p) = self.peers[i].record else {
                continue;
            };
            if !p.live {
                continue;
            }
            let Some(until) = p.wanted.filter(|t| t.active(now)) else {
                continue;
            };
            if p.pending.is_some() || p.sent.is_some_and(|old| !until.later(old)) {
                continue;
            }
            let token = self.token()?;
            self.peers[i]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .pending = Some(Stop { token, until });
            return Ok(Some(StopOffer {
                token,
                neighbor: p.neighbor,
                message: MigrationStop {
                    reserved: 0,
                    duration: until.duration(now),
                },
            }));
        }
        Ok(None)
    }
    /// Original local CORE STOP completion; it is not peer compliance or ACK.
    pub fn stop_sent(&mut self, token: Token<'id>, written: bool) -> Result<(), Error> {
        for p in &mut *self.peers {
            if let Some(peer) = &mut p.record
                && peer.pending.is_some_and(|s| s.token == token)
            {
                let stop = peer.pending.take().ok_or(Error::Conflict)?;
                peer.sent = Some(stop.until);
                if written {
                    self.report.stops_written = self.report.stops_written.saturating_add(1)
                } else {
                    self.report.stops_retired = self.report.stops_retired.saturating_add(1)
                }
                if !peer.live {
                    p.record = None;
                }
                return Ok(());
            }
        }
        Err(Error::StaleGeneration)
    }
    /// Earliest original peer-pause/selection deadline requiring a caller wake.
    #[must_use]
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        if self.stopping || self.fenced {
            return None;
        }
        self.peers
            .iter()
            .filter_map(|p| {
                p.record.and_then(|p| match p.paused {
                    Until::At(end) if end > now => Some(end),
                    _ => None,
                })
            })
            .chain(
                (self.limits.pushing
                    && self.active.is_none()
                    && self.next_selection > now
                    && self.blocks.iter().any(|b| b.record.is_none()))
                .then_some(self.next_selection),
            )
            .min()
    }
    /// Exact current original storage operation.
    #[must_use]
    pub fn active(&self) -> Option<Token<'id>> {
        match self.active {
            Some(Active::Cache(t) | Active::Replication(t)) => Some(t),
            None => None,
        }
    }
    /// Explicit local original-IO fence state, not a cache miss.
    #[must_use]
    pub const fn fenced(&self) -> bool {
        self.fenced
    }
    /// Read actual local receipts and policy decisions.
    #[must_use]
    pub const fn report(&self) -> &Report {
        &self.report
    }
    /// Stop unadmitted work while leaving original storage/control/path owners
    /// to drain explicitly. No DS ACK, native completion or END is manufactured.
    pub fn request_shutdown(&mut self) {
        self.stopping = true;
        for c in &mut *self.cache {
            if c.record.is_some_and(|c| !c.running)
                && let Some(old) = c.record.take()
            {
                c.bytes[..old.length].fill(0)
            }
        }
        for b in &mut *self.blocks {
            if b.record.is_some_and(|b| b.path.is_none())
                && let Some(old) = b.record.take()
            {
                b.bytes[..old.length].fill(0)
            }
        }
    }
    /// Only local metadata/buffers have quiesced; not remote effects.
    #[must_use]
    pub fn quiesced(&self) -> bool {
        self.stopping
            && self.active.is_none()
            && self
                .blocks
                .iter()
                .all(|b| b.record.is_none_or(|b| b.path.is_none()))
            && self
                .peers
                .iter()
                .all(|p| p.record.is_none_or(|p| p.pending.is_none()))
    }
}
