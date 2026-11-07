//! Actual old generic SET count/Bloom/DONE reconciliation, independent of SETI.
use crate::{
    Limits, Ports, ResultMode, Snapshot, Status,
    engine::{Output, Role},
    wire::{Options, Order, PeerMessage},
};
use alloc::{rc::Rc, vec::Vec};
use gnunet_block::{
    BlockType,
    bloom::{BloomGroup, NativeEndian},
};
use gnunet_types::Error;

// One bounded algorithm turn. The advertised filter can span many such turns.
const MEMBERS_PER_STEP: usize = 32;
const ZERO_BYTES_PER_STEP: usize = 4096;
const BLOOM_PREFIX: usize = 84;
const BLOOM_MESSAGE_BYTES: usize = 60 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Initialize,
    Choose,
    SendInfo,
    WaitInitial,
    WaitFilter,
    ReceiveFilter,
    Reduce,
    Build,
    ZeroFilter,
    FillFilter,
    SendFilter,
    ClearForEmptyPeer,
    ClearForDone,
    Results,
    SendDone,
    WaitClose,
    Close,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilterHeader {
    count: u32,
    xor: [u8; 64],
    salt: u32,
    k: u32,
    total: usize,
}
struct Filter {
    header: FilterHeader,
    bytes: Vec<u8>,
}

/// One original immutable membership and its real peer-protocol state. No method
/// reports final client DONE: the containing owner gates that on original IO and
/// actual peer retirement after all real results were transferred.
pub(crate) struct Intersection {
    snapshot: Option<Snapshot>,
    membership_bytes: usize,
    role: Role,
    mode: ResultMode,
    limits: Limits,
    phase: Phase,
    activated: bool,
    active: Vec<u8>,
    count: u32,
    xor: [u8; 64],
    remote_count: u32,
    remote_known: bool,
    cursor: usize,
    tx: Option<Filter>,
    rx: Option<Filter>,
    sent_filters: u16,
    received_filters: u16,
    received_records: usize,
    send_done: bool,
    result: Option<Result<(), Error>>,
    pub(crate) out: Output,
}
fn native(order: Order) -> NativeEndian {
    match order {
        Order::Little => NativeEndian::Little,
        Order::Big => NativeEndian::Big,
    }
}
fn xor_into(value: &mut [u8; 64], hash: &[u8; 64]) {
    for (out, byte) in value.iter_mut().zip(hash) {
        *out ^= byte;
    }
}
fn reserved(size: usize, limit: usize) -> Result<Vec<u8>, Error> {
    if size > limit {
        return Err(Error::Capacity);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
    if bytes.capacity() > limit {
        return Err(Error::Capacity);
    }
    Ok(bytes)
}
// Filter length is carried on the wire and is not a canonical encoding of a
// cardinality. Integer k matches the actual C rule without its zero/NaN casts;
// an integer approximation chooses an ordinary ~50% occupied positive filter.
fn parameters(local: u32, remote: u32) -> Result<(usize, u32), Error> {
    if local == 0 {
        return Ok((8, 1));
    }
    let k = if remote <= local {
        if remote == 0 || u64::from(local) >= u64::from(remote) * 2 {
            1
        } else {
            2
        }
    } else {
        let mut scaled = u64::from(local);
        let mut exponent = 0;
        while scaled < u64::from(remote) {
            scaled *= 2;
            exponent += 1;
        }
        2 + exponent
    };
    let n = u128::from(local) * u128::from(k);
    let bytes = (n * 14_426_950_408_889_634_u128).div_ceil(10_000_000_000_000_000_u128);
    Ok((
        usize::try_from(bytes.max(1)).map_err(|_| Error::TooLarge)?,
        k,
    ))
}
fn pressure(error: Error) -> bool {
    matches!(error, Error::WouldBlock | Error::NotReady)
}

impl Intersection {
    pub(crate) fn new(
        snapshot: Snapshot,
        role: Role,
        remote_count: u32,
        mode: ResultMode,
        _options: Options,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        snapshot.abi().validate()?;
        if !matches!(mode, ResultMode::Full | ResultMode::Removed) {
            return Err(Error::Unsupported);
        }
        let _count = u32::try_from(snapshot.len()).map_err(|_| Error::Capacity)?;
        let membership_bytes = snapshot.metadata_bytes()?;
        let body_charge = snapshot.ledger.charged_bytes()?;
        let active = reserved(snapshot.len(), snapshot.len())?;
        if membership_bytes
            .checked_add(active.capacity())
            .and_then(|n| n.checked_add(body_charge))
            .is_none_or(|n| n > limits.retained_bytes)
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            snapshot: Some(snapshot),
            membership_bytes,
            role,
            mode,
            limits,
            phase: Phase::Initialize,
            activated: false,
            active,
            count: 0,
            xor: [0; 64],
            remote_count,
            remote_known: role == Role::Acceptor,
            cursor: 0,
            tx: None,
            rx: None,
            sent_filters: 0,
            received_filters: 0,
            received_records: 0,
            send_done: false,
            result: None,
            out: Output::new(limits),
        })
    }
    /// Open only after original OperationRequest Written / actual local Adopt.
    pub(crate) fn activate(&mut self) {
        self.activated = true;
    }
    fn snapshot(&self) -> Result<&Snapshot, Error> {
        self.snapshot.as_ref().ok_or(Error::Closed)
    }
    fn body(&self, index: usize) -> Result<Rc<crate::content::Body>, Error> {
        let body = self.snapshot()?.members.get(index).ok_or(Error::Stale)?;
        if Rc::strong_count(body) >= usize::MAX / 2 {
            return Err(Error::Overflow);
        }
        Ok(body.clone())
    }
    fn remove(&mut self, index: usize) -> Result<(), Error> {
        if self.active.get(index) != Some(&1) {
            return Err(Error::Stale);
        }
        let count = self.count.checked_sub(1).ok_or(Error::Stale)?;
        let hash = *self.snapshot()?.hash(index).ok_or(Error::Stale)?;
        // Output reservation is the last fallible step before modifying this
        // exact membership/counter/XOR/cursor. Refusal leaves it intact.
        if self.mode == ResultMode::Removed {
            let body = self.body(index)?;
            self.out.result(Status::Ok, Some(body), u64::from(count))?;
        }
        self.active[index] = 0;
        self.count = count;
        xor_into(&mut self.xor, &hash);
        Ok(())
    }
    fn initialize(&mut self) -> Result<bool, Error> {
        let total = self.snapshot()?.len();
        let end = self.cursor.saturating_add(MEMBERS_PER_STEP).min(total);
        for index in self.cursor..end {
            let hash = *self.snapshot()?.hash(index).ok_or(Error::Stale)?;
            self.active.push(1); // capacity was reserved before original admission
            self.count = self.count.checked_add(1).ok_or(Error::Overflow)?;
            xor_into(&mut self.xor, &hash);
        }
        self.cursor = end;
        if end == total {
            self.phase = Phase::Choose;
            self.cursor = 0;
        }
        Ok(true)
    }
    fn build(&mut self, ports: &mut impl Ports) -> Result<bool, Error> {
        let sent = self.sent_filters.checked_add(1).ok_or(Error::Overflow)?;
        if sent > self.limits.rounds {
            return Err(Error::Capacity);
        }
        let (size, k) = parameters(self.count, self.remote_count)?;
        if k > self.limits.bloom_hashes || u32::try_from(size).is_err() {
            return Err(Error::Capacity);
        }
        let bytes = reserved(size, self.limits.bloom_bytes)?;
        if self
            .retained_bytes()?
            .checked_add(bytes.capacity())
            .is_none_or(|n| n > self.limits.retained_bytes)
        {
            return Err(Error::Capacity);
        }
        let mut raw = [0u8; 4];
        ports.fill(&mut raw)?;
        // Every u32 mutator has exactly the same standard mingle format. A
        // uniform full-width draw is permitted; no entropy fallback is used.
        let salt = u32::from_be_bytes(raw);
        self.tx = Some(Filter {
            header: FilterHeader {
                count: self.count,
                xor: self.xor,
                salt,
                k,
                total: size,
            },
            bytes,
        });
        self.sent_filters = sent;
        self.phase = Phase::ZeroFilter;
        self.cursor = 0;
        Ok(true)
    }
    fn zero_filter(&mut self) -> Result<bool, Error> {
        let tx = self.tx.as_mut().ok_or(Error::Stale)?;
        let end = tx
            .bytes
            .len()
            .saturating_add(ZERO_BYTES_PER_STEP)
            .min(tx.header.total);
        tx.bytes.resize(end, 0); // actual reserve done; no per-turn maximum allocation
        if end == tx.header.total {
            self.phase = Phase::FillFilter;
            self.cursor = 0;
        }
        Ok(true)
    }
    fn fill_filter(&mut self) -> Result<bool, Error> {
        let snapshot = self.snapshot.as_ref().ok_or(Error::Closed)?;
        let end = self
            .cursor
            .saturating_add(MEMBERS_PER_STEP)
            .min(snapshot.len());
        let tx = self.tx.as_mut().ok_or(Error::Stale)?;
        let mut group = BloomGroup::borrow_existing(
            &mut tx.bytes,
            BlockType::SET_TEST,
            tx.header.k,
            tx.header.salt,
            native(snapshot.abi().order),
        )?;
        for index in self.cursor..end {
            if self.active[index] == 1 {
                group.test_and_set(snapshot.hash(index).ok_or(Error::Stale)?);
            }
        }
        self.cursor = end;
        if end == snapshot.len() {
            self.phase = Phase::SendFilter;
            self.cursor = 0;
        }
        Ok(true)
    }
    fn send_filter(&mut self) -> Result<bool, Error> {
        let tx = self.tx.as_ref().ok_or(Error::Stale)?;
        let max = BLOOM_MESSAGE_BYTES
            .min(gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE)
            .min(self.limits.output_bytes)
            .checked_sub(BLOOM_PREFIX)
            .ok_or(Error::Capacity)?;
        let end = self
            .cursor
            .checked_add(max)
            .ok_or(Error::Overflow)?
            .min(tx.header.total);
        let abi = self.snapshot()?.abi();
        self.out.peer(
            PeerMessage::IntersectionBloom {
                element_count: tx.header.count,
                xor: tx.header.xor,
                mutator: tx.header.salt,
                total_length: u32::try_from(tx.header.total).map_err(|_| Error::TooLarge)?,
                bits_per_element: tx.header.k,
                data: tx.bytes.get(self.cursor..end).ok_or(Error::Stale)?,
            },
            abi,
        )?;
        self.cursor = end;
        if end == tx.header.total {
            self.tx = None;
            self.cursor = 0;
            self.phase = Phase::WaitFilter;
        }
        Ok(true)
    }
    fn reduce(&mut self) -> Result<bool, Error> {
        let total = self.snapshot()?.len();
        let end = self.cursor.saturating_add(MEMBERS_PER_STEP).min(total);
        let mut changed = false;
        while self.cursor < end {
            let index = self.cursor;
            if self.active[index] == 1 {
                let snapshot = self.snapshot.as_ref().ok_or(Error::Closed)?;
                let rx = self.rx.as_mut().ok_or(Error::Stale)?;
                let filter = BloomGroup::borrow_existing(
                    &mut rx.bytes,
                    BlockType::SET_TEST,
                    rx.header.k,
                    rx.header.salt,
                    native(snapshot.abi().order),
                )?;
                if !filter.contains(snapshot.hash(index).ok_or(Error::Stale)?) {
                    match self.remove(index) {
                        Ok(()) => {}
                        Err(error) if pressure(error) => return Ok(changed),
                        Err(error) => return Err(error),
                    }
                }
            }
            self.cursor += 1;
            changed = true;
        }
        if self.cursor == total {
            let header = self.rx.as_ref().ok_or(Error::Stale)?.header;
            self.rx = None;
            self.cursor = 0;
            if self.count == 0 || (self.count == header.count && self.xor == header.xor) {
                self.send_done = true;
                self.phase = Phase::Results;
            } else {
                self.phase = Phase::Build;
            }
            return Ok(true);
        }
        Ok(changed)
    }
    fn clear(&mut self) -> Result<bool, Error> {
        let total = self.snapshot()?.len();
        let end = self.cursor.saturating_add(MEMBERS_PER_STEP).min(total);
        let mut changed = false;
        while self.cursor < end {
            if self.active[self.cursor] == 1 {
                match self.remove(self.cursor) {
                    Ok(()) => {}
                    Err(error) if pressure(error) => return Ok(changed),
                    Err(error) => return Err(error),
                }
            }
            self.cursor += 1;
            changed = true;
        }
        if self.cursor == total {
            if self.count != 0 || self.xor != [0; 64] {
                return Err(Error::Stale);
            }
            self.cursor = 0;
            if self.phase == Phase::ClearForEmptyPeer {
                self.phase = Phase::Build;
            } else {
                self.send_done = false;
                self.phase = Phase::Results;
            }
            return Ok(true);
        }
        Ok(changed)
    }
    fn results(&mut self) -> Result<bool, Error> {
        let total = self.snapshot()?.len();
        if self.mode == ResultMode::Full {
            let end = self.cursor.saturating_add(MEMBERS_PER_STEP).min(total);
            let mut changed = false;
            while self.cursor < end {
                if self.active[self.cursor] == 1 {
                    let body = self.body(self.cursor)?;
                    match self
                        .out
                        .result(Status::Ok, Some(body), u64::from(self.count))
                    {
                        Ok(()) => {}
                        Err(error) if pressure(error) => return Ok(changed),
                        Err(error) => return Err(error),
                    }
                }
                self.cursor += 1;
                changed = true;
            }
            if self.cursor != total {
                return Ok(changed);
            }
        }
        self.cursor = 0;
        if self.send_done {
            self.phase = Phase::SendDone;
        } else {
            self.phase = Phase::Close;
            self.result = Some(Ok(()));
        }
        Ok(true)
    }
    fn advance(&mut self, ports: &mut impl Ports) -> Result<bool, Error> {
        if !self.activated {
            return Ok(false);
        }
        match self.phase {
            Phase::Initialize => self.initialize(),
            Phase::Choose => {
                self.phase = match self.role {
                    Role::Initiator => Phase::WaitInitial,
                    Role::Acceptor if self.remote_count == 0 => Phase::ClearForEmptyPeer,
                    Role::Acceptor if self.remote_count < self.count => Phase::SendInfo,
                    Role::Acceptor => Phase::Build,
                };
                Ok(true)
            }
            Phase::SendInfo => {
                let abi = self.snapshot()?.abi();
                self.out.peer(
                    PeerMessage::IntersectionInfo {
                        element_count: self.count,
                    },
                    abi,
                )?;
                self.phase = Phase::WaitFilter;
                Ok(true)
            }
            Phase::Build => self.build(ports),
            Phase::ZeroFilter => self.zero_filter(),
            Phase::FillFilter => self.fill_filter(),
            Phase::SendFilter => self.send_filter(),
            Phase::Reduce => self.reduce(),
            Phase::ClearForEmptyPeer | Phase::ClearForDone => self.clear(),
            Phase::Results => self.results(),
            Phase::SendDone => {
                let abi = self.snapshot()?.abi();
                self.out.peer(
                    PeerMessage::IntersectionDone {
                        element_count: self.count,
                        xor: self.xor,
                    },
                    abi,
                )?;
                self.result = Some(Ok(()));
                self.phase = Phase::WaitClose;
                Ok(true)
            }
            Phase::WaitInitial
            | Phase::WaitFilter
            | Phase::ReceiveFilter
            | Phase::WaitClose
            | Phase::Close
            | Phase::Failed => Ok(false),
        }
    }
    /// Fair CPU-only work. Ordinary output pressure changes no unrecoverable
    /// membership/cursor. Genuine failure is retained on this original operation.
    pub(crate) fn progress(&mut self, ports: &mut impl Ports) -> Result<bool, Error> {
        match self.advance(ports) {
            Ok(progress) => Ok(progress),
            Err(error) if pressure(error) => Ok(false),
            Err(error) => {
                self.fail(error);
                if error == Error::Entropy {
                    Err(error)
                } else {
                    Ok(true)
                }
            }
        }
    }
    fn bloom(&mut self, header: FilterHeader, data: &[u8]) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::WaitInitial | Phase::WaitFilter | Phase::ReceiveFilter
        ) {
            return Err(Error::Malformed);
        }
        if header.total == 0
            || header.total > self.limits.bloom_bytes
            || header.k == 0
            || header.k > self.limits.bloom_hashes
            || data.is_empty()
            || data.len() > header.total
        {
            return Err(Error::Malformed);
        }
        if self.phase == Phase::WaitInitial && header.count > self.count {
            return Err(Error::Malformed);
        }
        if header.count == 0 && header.xor != [0; 64] {
            return Err(Error::Authentication);
        }
        if self.remote_known && header.count > self.remote_count {
            return Err(Error::Malformed);
        }
        let offset = self.rx.as_ref().map_or(0, |rx| rx.bytes.len());
        let end = offset.checked_add(data.len()).ok_or(Error::Overflow)?;
        if end > header.total || self.rx.as_ref().is_some_and(|rx| rx.header != header) {
            return Err(Error::Malformed);
        }
        let complete = end == header.total;
        let received = self
            .received_filters
            .checked_add(u16::from(complete))
            .ok_or(Error::Overflow)?;
        if received > self.limits.rounds {
            return Err(Error::Capacity);
        }
        if self.phase == Phase::ReceiveFilter && self.rx.is_none() {
            return Err(Error::Stale);
        }
        if self.rx.is_none() {
            let mut bytes = reserved(header.total, self.limits.bloom_bytes)?;
            if self
                .retained_bytes()?
                .checked_add(bytes.capacity())
                .is_none_or(|n| n > self.limits.retained_bytes)
            {
                return Err(Error::Capacity);
            }
            bytes.extend_from_slice(data);
            self.rx = Some(Filter { header, bytes });
        } else {
            self.rx
                .as_mut()
                .ok_or(Error::Stale)?
                .bytes
                .extend_from_slice(data);
        }
        if complete {
            self.received_filters = received;
            self.remote_count = header.count;
            self.remote_known = true;
            self.cursor = 0;
            self.phase = Phase::Reduce;
        } else {
            self.phase = Phase::ReceiveFilter;
        }
        Ok(())
    }
    pub(crate) fn receive(
        &mut self,
        message: PeerMessage<'_>,
        _ports: &mut impl Ports,
    ) -> Result<(), Error> {
        if !self.activated {
            return Err(Error::NotReady);
        }
        if matches!(
            self.phase,
            Phase::Initialize
                | Phase::Choose
                | Phase::SendInfo
                | Phase::Reduce
                | Phase::Build
                | Phase::ZeroFilter
                | Phase::FillFilter
                | Phase::SendFilter
                | Phase::ClearForEmptyPeer
                | Phase::ClearForDone
                | Phase::Results
                | Phase::SendDone
        ) {
            return Err(Error::NotReady);
        }
        let records = self
            .received_records
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if records > self.limits.received_records {
            return Err(Error::Capacity);
        }
        match message {
            PeerMessage::IntersectionInfo { element_count } => {
                if self.phase != Phase::WaitInitial {
                    return Err(Error::Malformed);
                }
                // A declared empty peer is still answered with a real empty BF,
                // not a fabricated DONE. Nonempty cardinality follows the role.
                if self.count > element_count && element_count != 0 {
                    return Err(Error::Malformed);
                }
                self.remote_count = element_count;
                self.remote_known = true;
                self.cursor = 0;
                self.phase = if element_count == 0 {
                    Phase::ClearForEmptyPeer
                } else {
                    Phase::Build
                };
            }
            PeerMessage::IntersectionBloom {
                element_count,
                xor,
                mutator,
                total_length,
                bits_per_element,
                data,
            } => {
                self.bloom(
                    FilterHeader {
                        count: element_count,
                        xor,
                        salt: mutator,
                        k: bits_per_element,
                        total: usize::try_from(total_length).map_err(|_| Error::TooLarge)?,
                    },
                    data,
                )?;
            }
            PeerMessage::IntersectionDone { element_count, xor } => {
                if self.phase != Phase::WaitFilter || self.sent_filters == 0 || self.rx.is_some() {
                    return Err(Error::Malformed);
                }
                if element_count == 0 {
                    if xor != [0; 64] {
                        return Err(Error::Authentication);
                    }
                    self.phase = Phase::ClearForDone;
                    self.cursor = 0;
                } else {
                    if element_count != self.count || xor != self.xor {
                        return Err(Error::Authentication);
                    }
                    self.send_done = false;
                    self.cursor = 0;
                    self.phase = Phase::Results;
                }
            }
            _ => return Err(Error::Unsupported),
        }
        self.received_records = records;
        Ok(())
    }
    /// Failure releases all unadmitted work/scratch, preserving the count of
    /// original transferred peer frames whose real terminal still belongs here.
    pub(crate) fn fail(&mut self, reason: Error) {
        if !matches!(self.result, Some(Err(_))) {
            self.result = Some(Err(reason));
        }
        self.phase = Phase::Failed;
        self.tx = None;
        self.rx = None;
        self.active = Vec::new();
        self.snapshot = None;
        self.membership_bytes = 0;
        self.out.clear_unadmitted();
    }
    /// Actual current active intersection cardinality, not original membership
    /// size or a remote declaration. Service uses this for its final receipt.
    pub(crate) fn size(&self) -> u64 {
        u64::from(self.count)
    }
    pub(crate) fn outcome(&self) -> Option<Result<(), Error>> {
        self.result
    }
    pub(crate) fn wants_close(&self) -> bool {
        matches!(self.phase, Phase::Close | Phase::Failed)
    }
    /// Only real normal channel retirement in an already completed protocol
    /// phase is expected. Deadline/IO/cancel and early death remain failure.
    pub(crate) fn peer_retired(&mut self, reason: Error) {
        if reason == Error::Closed
            && matches!(self.phase, Phase::WaitClose | Phase::Close)
            && self.result == Some(Ok(()))
            && self.out.drained()
        {
            return;
        }
        self.fail(reason);
    }
    pub(crate) fn charged_bytes(&self) -> Result<usize, Error> {
        let output = self.out.charged()?;
        // Body allocations belong to their shared ledger; only view/scratch
        // metadata is owned here. Cached immutable membership avoids rescans.
        self.membership_bytes
            .checked_add(self.active.capacity())
            .and_then(|n| n.checked_add(self.tx.as_ref().map_or(0, |f| f.bytes.capacity())))
            .and_then(|n| n.checked_add(self.rx.as_ref().map_or(0, |f| f.bytes.capacity())))
            .and_then(|n| n.checked_add(output))
            .ok_or(Error::Overflow)
    }
    fn retained_bytes(&self) -> Result<usize, Error> {
        let bodies = match &self.snapshot {
            Some(snapshot) => snapshot.ledger.charged_bytes()?,
            None => 0,
        };
        self.charged_bytes()?
            .checked_add(bodies)
            .ok_or(Error::Overflow)
    }
}

#[cfg(test)]
mod tests {
    // Pure owner-transition source cases only. Injected settlement here is not
    // evidence of a native write, C execution, authentication or interoperability.
    use super::*;
    use crate::{
        Compression, Content, ContentLimits, Random,
        wire::{Abi, Element},
    };
    struct Deterministic;
    impl Random for Deterministic {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
            bytes.fill(0);
            Ok(())
        }
    }
    impl Compression for Deterministic {
        fn compress(&mut self, _input: &[u8], _limit: usize) -> Result<Vec<u8>, Error> {
            Err(Error::Unsupported)
        }
        fn decompress_exact(
            &mut self,
            _input: &[u8],
            _expected: usize,
            _limit: usize,
        ) -> Result<Vec<u8>, Error> {
            Err(Error::Unsupported)
        }
    }
    fn membership(values: &[u8]) -> Result<Snapshot, Error> {
        let mut content = Content::new(ContentLimits::default(), Abi::native())?;
        for value in values {
            content.add(Element {
                element_type: u16::from(*value),
                data: core::slice::from_ref(value),
            })?;
        }
        content.snapshot()
    }
    fn until(engine: &mut Intersection, target: Phase) -> Result<(), Error> {
        for _ in 0..4096 {
            if engine.phase == target {
                return Ok(());
            }
            if !engine.progress(&mut Deterministic)? {
                return Err(Error::NotReady);
            }
        }
        Err(Error::Capacity)
    }
    #[expect(
        clippy::panic_in_result_fn,
        reason = "unit source assertions compare independent protocol results; fallible API calls propagate their original errors"
    )]
    fn check_empty_filter(engine: &mut Intersection) -> Result<(), Error> {
        until(engine, Phase::WaitFilter)?;
        assert_eq!(engine.outcome(), None);
        let frame = engine.out.transfer()?;
        let PeerMessage::IntersectionBloom {
            element_count,
            xor,
            total_length,
            bits_per_element,
            data,
            ..
        } = PeerMessage::decode(&frame, Abi::native())?
        else {
            return Err(Error::Malformed);
        };
        assert_eq!(element_count, 0);
        assert_eq!(xor, [0; 64]);
        assert_eq!(total_length, 8);
        assert_eq!(bits_per_element, 1);
        assert!(data.iter().all(|b| *b == 0));
        // Explicit pure injected original write settlement, not a real IO fact.
        engine.out.settled()?;
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "unit source assertions compare independent protocol results; fallible API calls propagate their original errors"
    )]
    fn empty_initiator_actual_request_keeps_removed_snapshot_and_waits_done() -> Result<(), Error> {
        for mode in [ResultMode::Full, ResultMode::Removed] {
            let snapshot = membership(&[1, 2])?;
            let mut engine = Intersection::new(
                snapshot,
                Role::Acceptor,
                0,
                mode,
                Options::default(),
                Limits::default(),
            )?;
            assert!(!engine.progress(&mut Deterministic)?);
            engine.activate();
            check_empty_filter(&mut engine)?;
            assert_eq!(engine.snapshot()?.len(), 2);
            assert_eq!(
                engine.out.results.len(),
                if mode == ResultMode::Removed { 2 } else { 0 }
            );
            assert!(!engine.out.results.iter().any(|r| r.status.terminal()));
            engine.receive(
                PeerMessage::IntersectionDone {
                    element_count: 0,
                    xor: [0; 64],
                },
                &mut Deterministic,
            )?;
            until(&mut engine, Phase::Close)?;
            assert_eq!(engine.outcome(), Some(Ok(())));
            assert!(engine.wants_close());
            engine.peer_retired(Error::Closed);
            assert_eq!(engine.outcome(), Some(Ok(())));
        }
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "unit source assertions compare independent protocol results; fallible API calls propagate their original errors"
    )]
    fn empty_local_initiator_answers_real_nonempty_info_without_fake_done() -> Result<(), Error> {
        for mode in [ResultMode::Full, ResultMode::Removed] {
            let mut engine = Intersection::new(
                membership(&[])?,
                Role::Initiator,
                0,
                mode,
                Options::default(),
                Limits::default(),
            )?;
            engine.activate();
            until(&mut engine, Phase::WaitInitial)?;
            engine.receive(
                PeerMessage::IntersectionInfo { element_count: 3 },
                &mut Deterministic,
            )?;
            check_empty_filter(&mut engine)?;
            assert_eq!(engine.outcome(), None);
            engine.receive(
                PeerMessage::IntersectionDone {
                    element_count: 0,
                    xor: [0; 64],
                },
                &mut Deterministic,
            )?;
            until(&mut engine, Phase::Close)?;
            assert_eq!(engine.outcome(), Some(Ok(())));
            assert!(engine.out.results.is_empty());
        }
        Ok(())
    }
    fn fragment(xor: [u8; 64], data: &[u8]) -> PeerMessage<'_> {
        PeerMessage::IntersectionBloom {
            element_count: 1,
            xor,
            mutator: 0,
            total_length: 2,
            bits_per_element: 1,
            data,
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "unit source assertions compare independent protocol results; fallible API calls propagate their original errors"
    )]
    fn fragments_and_removed_output_pressure_preserve_original_cursor() -> Result<(), Error> {
        // COUNT_SENT (ElementInfo only) has not yet sent any Bloom. A peer
        // cannot skip that exchange and manufacture an accepted DONE0.
        let mut count_sent = Intersection::new(
            membership(&[1, 2])?,
            Role::Acceptor,
            1,
            ResultMode::Removed,
            Options::default(),
            Limits::default(),
        )?;
        count_sent.activate();
        until(&mut count_sent, Phase::WaitFilter)?;
        assert_eq!(count_sent.sent_filters, 0);
        assert_eq!(
            count_sent.receive(
                PeerMessage::IntersectionDone {
                    element_count: 0,
                    xor: [0; 64]
                },
                &mut Deterministic
            ),
            Err(Error::Malformed)
        );
        assert_eq!(count_sent.outcome(), None);
        assert_eq!(count_sent.count, 2);
        let limits = Limits {
            output_frames: 1,
            ..Limits::default()
        };
        let snapshot = membership(&[7])?;
        let hash = *snapshot.hash(0).ok_or(Error::Stale)?;
        let mut engine = Intersection::new(
            snapshot,
            Role::Initiator,
            0,
            ResultMode::Removed,
            Options::default(),
            limits,
        )?;
        engine.activate();
        until(&mut engine, Phase::WaitInitial)?;
        engine.receive(fragment(hash, &[0]), &mut Deterministic)?;
        assert_eq!(engine.phase, Phase::ReceiveFilter);
        let original_records = engine.received_records;
        assert_eq!(
            engine.receive(fragment([0; 64], &[0]), &mut Deterministic),
            Err(Error::Malformed)
        );
        assert_eq!(engine.received_records, original_records);
        assert_eq!(engine.rx.as_ref().ok_or(Error::Stale)?.bytes.len(), 1);
        engine.receive(fragment(hash, &[0]), &mut Deterministic)?;
        engine.out.result(Status::Ok, None, 0)?;
        assert!(!engine.progress(&mut Deterministic)?);
        assert_eq!(engine.cursor, 0);
        assert_eq!(engine.count, 1);
        assert_eq!(engine.active, [1]);
        let _original = engine.out.results.pop_front().ok_or(Error::Stale)?;
        until(&mut engine, Phase::WaitClose)?;
        assert_eq!(engine.count, 0);
        assert_eq!(engine.out.results.len(), 1);
        assert_eq!(engine.outcome(), Some(Ok(())));
        assert!(!engine.wants_close());
        assert!(!engine.out.drained());
        // Protocol outcome is still gated by original write/retirement debt.
        let frame = engine.out.transfer()?;
        assert!(
            matches!(PeerMessage::decode(&frame, Abi::native())?, PeerMessage::IntersectionDone { element_count: 0, xor } if xor == [0; 64])
        );
        engine.out.settled()?;
        engine.peer_retired(Error::Closed);
        assert_eq!(engine.outcome(), Some(Ok(())));
        engine.fail(Error::Capacity);
        engine.peer_retired(Error::Closed);
        assert_eq!(engine.outcome(), Some(Err(Error::Capacity)));
        Ok(())
    }
}
