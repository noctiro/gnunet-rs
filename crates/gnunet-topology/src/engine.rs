use super::*;
use alloc::{rc::Rc, vec::Vec};
#[derive(Debug)]
struct Domain;
/// Original peer-row allocation, distinct across eviction/reuse.
#[derive(Clone, Debug)]
pub struct Node {
    domain: Rc<Domain>,
    row: usize,
    serial: u64,
}
impl PartialEq for Node {
    fn eq(&self, o: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &o.domain) && self.row == o.row && self.serial == o.serial
    }
}
impl Eq for Node {}
impl Node {
    /// Diagnostic allocation value; cannot reconstruct authority.
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
/// Original immutable full HELLO advertisement intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Gossip {
    target: Node,
    source: Node,
    revision: u64,
    connection: u64,
    serial: u64,
}
impl Gossip {
    /// Original recipient allocation.
    pub const fn target(&self) -> &Node {
        &self.target
    }
    /// Original advertised peer allocation.
    pub const fn source(&self) -> &Node {
        &self.source
    }
    /// Original HELLO revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}
/// Prepared borrowed bytes; failure to copy/admit changes no policy state.
pub struct Advertisement<'a> {
    /// Original immutable intent.
    pub job: Gossip,
    /// Exact full official HELLO message.
    pub bytes: &'a [u8],
}
/// Original connection-hint change. Completion proves only actual local writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control {
    node: Node,
    serial: u64,
    before: u32,
    after: u32,
}
impl Control {
    /// Original peer row.
    pub const fn node(&self) -> &Node {
        &self.node
    }
    /// Previous whole-written local hint strength.
    pub const fn before(&self) -> u32 {
        self.before
    }
    /// New desired hint strength (zero cancels).
    pub const fn after(&self) -> u32 {
        self.after
    }
}
struct HelloRow {
    bytes: Vec<u8>,
    expiration: u64,
    addresses: usize,
    revision: u64,
    suppression_until: u64,
}
struct Row {
    node: Node,
    peer: Peer,
    hello: Option<HelloRow>,
    connected: bool,
    connection: u64,
    next: u64,
    cursor: usize,
    gossip: Option<Gossip>,
    strength: u32,
    control: Option<Control>,
    control_retry: u64,
}
/// Alloc-enabled bounded topology engine. The default crate remains noalloc.
/// One bit per configured source/recipient records the current HELLO suppression
/// window. No cryptographic hash or per-pair timestamp is needed.
pub struct Engine {
    limits: Limits,
    domain: Rc<Domain>,
    rows: Vec<Option<Row>>,
    stamps: Vec<u64>,
    words: usize,
    next: u64,
    bytes: usize,
    local: Option<Peer>,
    cursor: usize,
    control_cursor: usize,
    reconsider: u64,
}
fn plus(now: u64, d: u64) -> Result<u64, Error> {
    now.checked_add(d)
        .filter(|n| *n < u64::MAX)
        .ok_or(Error::Overflow)
}
impl Engine {
    /// Allocate only the configured fixed metadata and exact suppression matrix.
    pub fn new(limits: Limits, now: u64) -> Result<Self, Error> {
        limits.validate()?;
        let words = limits.peers.div_ceil(64);
        let count = limits.peers.checked_mul(words).ok_or(Error::Overflow)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.peers)
            .map_err(|_| Error::Capacity)?;
        rows.resize_with(limits.peers, || None);
        let mut stamps = Vec::new();
        stamps
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        stamps.resize(count, 0);
        Ok(Self {
            limits,
            domain: Rc::new(Domain),
            rows,
            stamps,
            words,
            next: 0,
            bytes: 0,
            local: None,
            cursor: 0,
            control_cursor: 0,
            reconsider: now,
        })
    }
    fn clear_marks(&mut self, source: usize) {
        let start = source * self.words;
        self.stamps[start..start + self.words].fill(0);
    }
    /// Actual retained deduplication word capacity, excluding peer/HELLO rows.
    pub fn suppression_bytes(&self) -> usize {
        self.stamps.capacity() * core::mem::size_of::<u64>()
    }
    fn index(&self, node: &Node) -> Result<usize, Error> {
        if !Rc::ptr_eq(&self.domain, &node.domain) {
            return Err(Error::Stale);
        }
        self.rows
            .get(node.row)
            .and_then(Option::as_ref)
            .filter(|r| r.node == *node)
            .map(|_| node.row)
            .ok_or(Error::Stale)
    }
    /// Actual current own identity from the original PILS observation.
    pub fn set_local(&mut self, peer: Peer, now: u64) -> bool {
        let changed = self.local != Some(peer);
        self.local = Some(peer);
        if changed {
            self.reconsider = now;
        }
        changed
    }
    /// Forget source authority on actual PILS loss, without inventing a replacement.
    pub fn local_lost(&mut self, now: u64) {
        self.local = None;
        self.reconsider = now;
    }
    /// Current actual public identity if one is available.
    pub const fn local(&self) -> Option<Peer> {
        self.local
    }
    /// Current exact original row for this public peer.
    pub fn find(&self, peer: Peer) -> Option<Node> {
        self.rows
            .iter()
            .flatten()
            .find(|r| r.peer == peer)
            .map(|r| r.node.clone())
    }
    /// Public identity for one original row.
    pub fn peer(&self, node: &Node) -> Result<Peer, Error> {
        Ok(self.rows[self.index(node)?]
            .as_ref()
            .ok_or(Error::Stale)?
            .peer)
    }
    fn ensure(&mut self, peer: Peer) -> Result<Node, Error> {
        if let Some(node) = self.find(peer) {
            return Ok(node);
        }
        let i = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self.next.checked_add(1).ok_or(Error::Overflow)?;
        let node = Node {
            domain: self.domain.clone(),
            row: i,
            serial,
        };
        self.rows[i] = Some(Row {
            node: node.clone(),
            peer,
            hello: None,
            connected: false,
            connection: 0,
            next: 0,
            cursor: 0,
            gossip: None,
            strength: 0,
            control: None,
            control_retry: 0,
        });
        self.clear_marks(i);
        for n in 0..self.limits.peers {
            self.stamps[n * self.words + i / 64] &= !(1u64 << (i % 64));
        }
        self.next = serial;
        Ok(node)
    }
    /// Admit only an actual verified original frame. A byte-identical duplicate
    /// never resets suppression; an accepted new revision resets only that source.
    pub fn learn(&mut self, frame: VerifiedFrame<'_>, now: u64) -> Result<Option<Node>, Error> {
        let verified = frame.verified();
        let hello = verified.hello();
        if now < verified.checked_at().as_micros()
            || hello.expiration().as_micros() <= now
            || hello.address_count() == 0
        {
            return Ok(None);
        }
        if frame.bytes().len() > self.limits.frame_bytes {
            return Err(Error::Capacity);
        }
        let peer = *hello.peer().as_bytes();
        let old = self.find(peer);
        let old_size = old
            .as_ref()
            .and_then(|n| self.rows[n.row].as_ref()?.hello.as_ref())
            .map_or(0, |h| h.bytes.len());
        if let Some(node) = &old
            && let Some(prior) = &self.rows[node.row].as_ref().ok_or(Error::Stale)?.hello
            && (prior.bytes == frame.bytes()
                || !(hello.expiration().as_micros() > prior.expiration
                    || hello.address_count() > prior.addresses))
        {
            return Ok(Some(node.clone()));
        }
        let bytes = self
            .bytes
            .checked_sub(old_size)
            .and_then(|n| n.checked_add(frame.bytes().len()))
            .ok_or(Error::Overflow)?;
        if bytes > self.limits.hello_bytes {
            return Err(Error::Capacity);
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(frame.bytes().len())
            .map_err(|_| Error::Capacity)?;
        copy.extend_from_slice(frame.bytes());
        let revision = old
            .as_ref()
            .and_then(|n| self.rows[n.row].as_ref()?.hello.as_ref())
            .map_or(Ok(1), |h| h.revision.checked_add(1).ok_or(Error::Overflow))?;
        let suppression_until = plus(now, self.limits.repeat_interval)?;
        let node = self.ensure(peer)?;
        self.rows[node.row].as_mut().ok_or(Error::Stale)?.hello = Some(HelloRow {
            bytes: copy,
            expiration: hello.expiration().as_micros(),
            addresses: hello.address_count(),
            revision,
            suppression_until,
        });
        self.clear_marks(node.row);
        self.bytes = bytes;
        self.reconsider = now;
        Ok(Some(node))
    }
    /// Actual monitor removal; an active original send keeps its own copied bytes.
    pub fn remove_hello(&mut self, peer: Peer, now: u64) {
        if let Some(node) = self.find(peer)
            && let Some(row) = &mut self.rows[node.row]
        {
            if let Some(hello) = row.hello.take() {
                self.bytes -= hello.bytes.len();
            }
            self.reconsider = now;
        }
    }
    /// Actual CORE connection announcement, never a suggestion result.
    pub fn connected(&mut self, peer: Peer, now: u64) -> Result<Node, Error> {
        let node = self.ensure(peer)?;
        let row = self.rows[node.row].as_mut().ok_or(Error::Stale)?;
        if !row.connected {
            if row.gossip.is_some() {
                return Err(Error::WouldBlock);
            }
            row.connection = row.connection.checked_add(1).ok_or(Error::Overflow)?;
            row.connected = true;
            row.next = row.next.max(now);
            self.reconsider = now;
        }
        Ok(node)
    }
    /// Actual CORE disconnection. Old pending gossip is retired only by its
    /// matching original completion/loss receipt, never retagged onto a new peer.
    pub fn disconnected(&mut self, node: &Node, now: u64) -> Result<(), Error> {
        let i = self.index(node)?;
        self.rows[i].as_mut().ok_or(Error::Stale)?.connected = false;
        self.reconsider = now;
        Ok(())
    }
    /// Physical CORE MQ retired; original send receipts remain separately owned.
    pub fn connections_lost(&mut self, now: u64) {
        for row in self.rows.iter_mut().flatten() {
            row.connected = false;
        }
        self.reconsider = now;
    }
    /// Number of current remote actual connections.
    pub fn connections(&self) -> usize {
        self.rows
            .iter()
            .flatten()
            .filter(|r| r.connected && Some(r.peer) != self.local)
            .count()
    }
    /// Fair immutable candidate. Merely preparing does not consume dedup/rate state.
    pub fn advertisement(&mut self, now: u64) -> Result<Option<Advertisement<'_>>, Error> {
        for i in 0..self.rows.len() {
            let expired = self.rows[i]
                .as_ref()
                .and_then(|r| r.hello.as_ref())
                .is_some_and(|h| h.expiration > now && h.suppression_until <= now);
            if expired {
                let until = plus(now, self.limits.repeat_interval)?;
                self.clear_marks(i);
                if let Some(hello) = self.rows[i].as_mut().and_then(|r| r.hello.as_mut()) {
                    hello.suppression_until = until;
                }
            }
        }
        if self.local.is_none() {
            return Ok(None);
        }
        for off in 0..self.rows.len() {
            let ti = (self.cursor + off) % self.rows.len();
            let Some(target) = &self.rows[ti] else {
                continue;
            };
            if !target.connected
                || Some(target.peer) == self.local
                || target.gossip.is_some()
                || now < target.next
            {
                continue;
            }
            for off in 0..self.rows.len() {
                let si = (target.cursor + off) % self.rows.len();
                let Some(source) = &self.rows[si] else {
                    continue;
                };
                let Some(hello) = &source.hello else { continue };
                if source.peer == target.peer || hello.expiration <= now {
                    continue;
                }
                if self.stamps[si * self.words + ti / 64] & (1u64 << (ti % 64)) != 0 {
                    continue;
                }
                let serial = self.next.checked_add(1).ok_or(Error::Overflow)?;
                return Ok(Some(Advertisement {
                    job: Gossip {
                        target: target.node.clone(),
                        source: source.node.clone(),
                        revision: hello.revision,
                        connection: target.connection,
                        serial,
                    },
                    bytes: &hello.bytes,
                }));
            }
        }
        Ok(None)
    }
    /// Actual immutable native send admission, after fallible copying succeeded.
    pub fn gossip_queued(&mut self, job: &Gossip) -> Result<(), Error> {
        let ti = self.index(&job.target)?;
        let si = self.index(&job.source)?;
        let t = self.rows[ti].as_ref().ok_or(Error::Stale)?;
        let h = self.rows[si]
            .as_ref()
            .and_then(|s| s.hello.as_ref())
            .ok_or(Error::Stale)?;
        if job.serial != self.next.checked_add(1).ok_or(Error::Overflow)?
            || t.gossip.is_some()
            || !t.connected
            || t.connection != job.connection
            || h.revision != job.revision
        {
            return Err(Error::Stale);
        }
        self.next = job.serial;
        self.rows[ti].as_mut().ok_or(Error::Stale)?.gossip = Some(job.clone());
        self.cursor = (ti + 1) % self.rows.len();
        Ok(())
    }
    /// Original send terminal observation. `whole` must come from actual complete
    /// CORE payload bytes; it proves no remote delivery or address authentication.
    pub fn gossip_finished(&mut self, job: &Gossip, whole: bool, now: u64) -> Result<(), Error> {
        let ti = self.index(&job.target)?;
        self.index(&job.source)?;
        let row = self.rows[ti].as_ref().ok_or(Error::Stale)?;
        if row.gossip.as_ref() != Some(job) {
            return Err(Error::Stale);
        }
        let next = plus(
            now,
            if whole {
                self.limits.advertisement_interval
            } else {
                self.limits.retry_interval
            },
        )?;
        let row = self.rows[ti].as_mut().ok_or(Error::Stale)?;
        row.gossip = None;
        row.next = next;
        row.cursor = (job.source.row + 1) % self.limits.peers;
        if whole
            && self.rows[job.source.row]
                .as_ref()
                .and_then(|r| r.hello.as_ref())
                .is_some_and(|h| h.revision == job.revision)
        {
            self.stamps[job.source.row * self.words + ti / 64] |= 1u64 << (ti % 64);
        }
        Ok(())
    }
    /// Actual original native cancellation/retirement, without sampling a clock.
    pub fn gossip_retired(&mut self, job: &Gossip) -> Result<(), Error> {
        let i = self.index(&job.target)?;
        let row = self.rows[i].as_mut().ok_or(Error::Stale)?;
        if row.gossip.as_ref() != Some(job) {
            return Err(Error::Stale);
        }
        row.gossip = None;
        row.next = 0;
        Ok(())
    }
    /// Fresh desired hint policy; unchanged actual strength produces no repeated
    /// suggestion and therefore cannot reset TRANSPORT's retry state.
    pub fn control(&mut self, now: u64) -> Result<Option<Control>, Error> {
        if now < self.reconsider {
            return Ok(None);
        }
        let below = self.local.is_some() && self.connections() < self.limits.target;
        for off in 0..self.rows.len() {
            let i = (self.control_cursor + off) % self.rows.len();
            let Some(row) = &self.rows[i] else { continue };
            if row.control.is_some() || now < row.control_retry {
                continue;
            }
            // TRANSPORT may already have current addresses for a public peer,
            // including a disconnected CORE neighbour with no local HELLO row.
            let desired = if below && Some(row.peer) != self.local {
                if row.connected { 2 } else { 1 }
            } else {
                0
            };
            if desired != row.strength {
                return Ok(Some(Control {
                    node: row.node.clone(),
                    serial: self.next.checked_add(1).ok_or(Error::Overflow)?,
                    before: row.strength,
                    after: desired,
                }));
            }
        }
        if now >= self.reconsider {
            self.reconsider = plus(now, self.limits.reconsider_interval)?;
        }
        Ok(None)
    }
    /// Actual bounded native control admission, not connection success.
    pub fn control_queued(&mut self, job: &Control) -> Result<(), Error> {
        let i = self.index(&job.node)?;
        let row = self.rows[i].as_mut().ok_or(Error::Stale)?;
        if row.control.is_some()
            || row.strength != job.before
            || job.serial != self.next.checked_add(1).ok_or(Error::Overflow)?
        {
            return Err(Error::Stale);
        }
        self.next = job.serial;
        row.control = Some(job.clone());
        self.control_cursor = (i + 1) % self.limits.peers;
        Ok(())
    }
    /// Both original cancellation/new suggestion frames completely locally written.
    pub fn control_written(&mut self, job: &Control) -> Result<(), Error> {
        let i = self.index(&job.node)?;
        let row = self.rows[i].as_mut().ok_or(Error::Stale)?;
        if row.control.as_ref() != Some(job) {
            return Err(Error::Stale);
        }
        row.control = None;
        row.strength = job.after;
        Ok(())
    }
    /// Original application MQ physically closed. Its hints are gone; new desired
    /// intent may later be created, with new native source/effect authority.
    pub fn controls_lost(&mut self, now: u64) -> Result<(), Error> {
        let retry = plus(now, self.limits.retry_interval)?;
        for row in self.rows.iter_mut().flatten() {
            row.strength = 0;
            row.control = None;
            row.control_retry = retry;
        }
        Ok(())
    }
    /// Actual original TRANSPORT source physically retired, independent of clock.
    pub fn controls_retired(&mut self) {
        self.reconsider = 0;
        for row in self.rows.iter_mut().flatten() {
            row.strength = 0;
            row.control = None;
            row.control_retry = 0;
        }
    }
    /// Remove stale bytes and unused rows, never evict an original active debt.
    pub fn expire(&mut self, now: u64) {
        for row in self.rows.iter_mut().flatten() {
            if row.hello.as_ref().is_some_and(|h| h.expiration <= now)
                && let Some(h) = row.hello.take()
            {
                self.bytes -= h.bytes.len();
            }
        }
        for i in 0..self.rows.len() {
            if self.rows[i].as_ref().is_some_and(|r| {
                !r.connected
                    && r.hello.is_none()
                    && r.gossip.is_none()
                    && r.control.is_none()
                    && r.strength == 0
                    && !self.rows.iter().flatten().any(|other| {
                        other
                            .gossip
                            .as_ref()
                            .is_some_and(|job| job.source == r.node)
                    })
            }) {
                self.rows[i] = None;
            }
        }
    }
    /// Earliest meaningful policy wake; finite host ticks may also observe source IO.
    pub fn next_deadline(&self, now: u64) -> u64 {
        self.rows
            .iter()
            .flatten()
            .flat_map(|r| {
                r.hello
                    .as_ref()
                    .into_iter()
                    .flat_map(|h| {
                        core::iter::once(h.expiration)
                            .chain((h.suppression_until > now).then_some(h.suppression_until))
                    })
                    .chain((r.connected && r.gossip.is_none() && r.next > now).then_some(r.next))
                    .chain((r.control_retry > now).then_some(r.control_retry))
            })
            .chain(core::iter::once(
                self.reconsider
                    .max(now.saturating_add(self.limits.retry_interval)),
            ))
            .min()
            .unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod window_model {
    use super::*;
    use alloc::vec;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Public scheduling metadata with fallible bounded setup"
    )]
    fn old_revision_write_cannot_suppress_new_hello_window() -> Result<(), Error> {
        let mut engine = Engine::new(
            Limits {
                peers: 3,
                target: 2,
                advertisement_interval: 5,
                repeat_interval: 100,
                ..Limits::default()
            },
            10,
        )?;
        engine.set_local([4; 32], 10);
        let source = engine.ensure([1; 32])?;
        engine.connected([2; 32], 10)?;
        engine.connected([3; 32], 10)?;
        // Mock retention metadata only. This one-byte marker creates no
        // VerifiedFrame, signature, hash, key, native write or provider receipt.
        engine.rows[source.row].as_mut().ok_or(Error::Stale)?.hello = Some(HelloRow {
            bytes: vec![0],
            expiration: 1000,
            addresses: 1,
            revision: 1,
            suppression_until: 110,
        });
        engine.bytes = 1;
        let first = engine.advertisement(10)?.ok_or(Error::NotReady)?.job;
        engine.gossip_queued(&first)?;
        engine.gossip_finished(&first, true, 10)?;
        let old = engine.advertisement(11)?.ok_or(Error::NotReady)?.job;
        engine.gossip_queued(&old)?;
        let hello = engine.rows[source.row]
            .as_mut()
            .and_then(|r| r.hello.as_mut())
            .ok_or(Error::Stale)?;
        hello.revision = 2;
        hello.suppression_until = 112;
        engine.clear_marks(source.row);
        engine.gossip_finished(&old, true, 12)?;
        for now in [16, 17] {
            let current = engine.advertisement(now)?.ok_or(Error::NotReady)?.job;
            assert_eq!(current.revision(), 2);
            engine.gossip_queued(&current)?;
            engine.gossip_finished(&current, true, now)?;
        }
        assert!(engine.advertisement(30)?.is_none());
        assert!(engine.advertisement(112)?.is_some());
        Ok(())
    }
}
