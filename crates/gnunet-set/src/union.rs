//! Old generic SET union: native 13-byte IBF, collisions, strata and full transfer.
use crate::{
    Limits, Ports, ResultMode, Snapshot, Status,
    allocation::Growth,
    content::{Body, hash},
    engine::{Output, Role},
    ibf::{self, Ibf, Peel},
    strata::Strata,
    wire::{self, PeerMessage},
};
use alloc::{rc::Rc, vec::Vec};
use gnunet_types::Error;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Starting,
    ExpectStrata,
    ExpectIbf,
    Passive,
    Active,
    FinishWait,
    FinishClose,
    // Own delta DONE is sent, but the active peer may still demand our data.
    PassiveDone,
    FullFirst,
    FullReturn,
    FullWaiting,
    // One request in each direction; original full-set debts are independent.
    FullCounterReceive,
    FullCounterReturn,
    FullMutualFirst,
    FullMutualWaiting,
    FullMutualResults,
    Done,
}
struct Entry {
    body: Rc<Body>,
    key: u64,
    remote: bool,
}
struct Build {
    filter: Ibf,
    keys: Vec<u64>,
    order: u8,
    salt: u32,
    cursor: usize,
    offset: usize,
    decode: bool,
    scan: usize,
    nonzero: bool,
}
pub(crate) struct Union {
    pub out: Output,
    snapshot: Snapshot,
    limits: Limits,
    mode: ResultMode,
    options: wire::Options,
    role: Role,
    phase: Phase,
    active: bool,
    first_error: Option<Error>,
    retired: bool,
    protocol: bool,
    entries: Vec<Entry>,
    payload: usize,
    demands: Vec<[u8; 64]>,
    strata: Option<Strata>,
    strata_ready: bool,
    remote_strata: Option<Vec<u8>>,
    estimate_stratum: usize,
    estimate: u64,
    remote_size: u64,
    build: Option<Build>,
    remote_ibf: Option<Ibf>,
    remote_offset: usize,
    remote_salt: u32,
    input: Option<(Vec<u8>, usize)>,
    completed_input: Option<Vec<u8>>,
    offers: Option<(u64, usize)>,
    peel_pending: Option<(u64, i8)>,
    full_cursor: usize,
    full_request_sent: bool,
    full_peer_done: bool,
    full_local_done: bool,
    salt_send: u32,
    rounds: u16,
    received: usize,
    peeled: usize,
    last_key: Option<u64>,
    membership_bytes: usize,
    growth: Growth,
}
impl Union {
    #[cfg(test)]
    pub fn new(
        snapshot: Snapshot,
        role: Role,
        mode: ResultMode,
        options: wire::Options,
        limits: Limits,
    ) -> Result<Self, Error> {
        let allowance = limits
            .retained_bytes
            .checked_sub(snapshot.ledger.charged_bytes()?)
            .ok_or(Error::Capacity)?;
        Self::new_bounded(snapshot, role, mode, options, limits, allowance)
    }
    pub fn new_bounded(
        snapshot: Snapshot,
        role: Role,
        mode: ResultMode,
        options: wire::Options,
        limits: Limits,
        allowance: usize,
    ) -> Result<Self, Error> {
        mode.validate(crate::OperationType::Union)?;
        if options.force_delta != 0 && options.force_full != 0 {
            return Err(Error::InvalidInput);
        }
        let membership_bytes = snapshot.metadata_bytes()?;
        let mut growth = Growth::new(allowance);
        growth.claim(membership_bytes)?;
        let mut entries = growth.vector(snapshot.len())?;
        let mut payload = 0usize;
        for body in &snapshot.members {
            if Rc::strong_count(body) >= usize::MAX / 2 {
                return Err(Error::Overflow);
            }
            payload = payload
                .checked_add(body.data.capacity())
                .ok_or(Error::Overflow)?;
            entries.push(Entry {
                key: ibf::element_key(&body.hash, snapshot.abi().order)?,
                body: body.clone(),
                remote: false,
            });
        }
        if payload > limits.union_bytes || snapshot.len() > limits.union_elements {
            return Err(Error::Capacity);
        }
        // The ledger already owns these immutable bodies. Cloned entry/snapshot
        // references allocate only their own metadata, never another payload.
        growth.claim(Strata::allocation_peak()?)?;
        let strata = Some(Strata::new(&snapshot)?);
        Ok(Self {
            out: Output::new(limits),
            snapshot,
            limits,
            mode,
            options,
            role,
            phase: Phase::Starting,
            active: false,
            first_error: None,
            retired: false,
            protocol: false,
            entries,
            payload,
            demands: Vec::new(),
            strata,
            strata_ready: false,
            remote_strata: None,
            estimate_stratum: 31,
            estimate: 0,
            remote_size: 0,
            build: None,
            remote_ibf: None,
            remote_offset: 0,
            remote_salt: 0,
            input: None,
            completed_input: None,
            offers: None,
            peel_pending: None,
            full_cursor: 0,
            full_request_sent: false,
            full_peer_done: false,
            full_local_done: false,
            salt_send: 42,
            rounds: 0,
            received: 0,
            peeled: 0,
            last_key: None,
            membership_bytes,
            growth,
        })
    }
    pub fn size(&self) -> u64 {
        self.entries.len() as u64
    }
    pub fn activate(&mut self) {
        self.active = true;
    }
    pub fn fail(&mut self, reason: Error) {
        if self.first_error.is_none() {
            self.first_error = Some(reason);
        }
        self.out.clear_unadmitted();
        self.input = None;
        self.completed_input = None;
        self.build = None;
        self.remote_ibf = None;
        self.strata = None;
        self.remote_strata = None;
        self.offers = None;
        self.peel_pending = None;
    }
    pub fn outcome(&self) -> Option<Result<(), Error>> {
        if let Some(e) = self.first_error {
            Some(Err(e))
        } else if self.protocol {
            Some(Ok(()))
        } else {
            None
        }
    }
    pub fn wants_close(&self) -> bool {
        self.first_error.is_some()
            || (self.protocol && self.phase != Phase::PassiveDone && self.out.drained())
    }
    /// Only bounded local result enumeration remains: no input/peer effects or
    /// deferred algorithm work, and every original send is actually settled.
    pub fn can_finish_locally(&self) -> bool {
        self.phase == Phase::FullMutualResults
            && self.first_error.is_none()
            && self.full_request_sent
            && self.full_peer_done
            && self.full_local_done
            && self.out.drained()
            && self.input.is_none()
            && self.completed_input.is_none()
            && self.demands.is_empty()
            && self.offers.is_none()
            && self.build.is_none()
            && self.remote_ibf.is_none()
            && self.remote_strata.is_none()
            && self.strata.is_none()
            && self.peel_pending.is_none()
    }
    pub fn peer_retired(&mut self, reason: Error) {
        let local_only = reason == Error::Closed && self.can_finish_locally();
        self.retired = true;
        if !(local_only
            || self.protocol
                && self.out.drained()
                && self.input.is_none()
                && self.demands.is_empty()
                && reason == Error::Closed)
        {
            self.fail(reason);
        }
    }
    #[cfg(test)]
    pub fn receive(
        &mut self,
        message: PeerMessage<'_>,
        ports: &mut impl Ports,
    ) -> Result<(), Error> {
        let bodies = self.snapshot.ledger.charged_bytes()?;
        let additional = self
            .limits
            .retained_bytes
            .checked_sub(self.charged_bytes()?)
            .and_then(|n| n.checked_sub(bodies))
            .ok_or(Error::Capacity)?;
        self.receive_bounded(message, ports, additional)
    }
    pub fn receive_bounded(
        &mut self,
        message: PeerMessage<'_>,
        ports: &mut impl Ports,
        additional: usize,
    ) -> Result<(), Error> {
        self.growth = Growth::new(additional);
        if !self.active || self.retired || self.first_error.is_some() {
            return Err(Error::Closed);
        }
        // Single bounded messages, including terminal controls, are classified
        // before acknowledging their original native Delivery. An immediate
        // legal peer close cannot race a merely queued DONE classification.
        if !matches!(
            message,
            PeerMessage::UnionInquiry { .. }
                | PeerMessage::UnionOffer { .. }
                | PeerMessage::UnionDemand { .. }
        ) {
            if self.input.is_some() || self.completed_input.is_some() {
                return Err(Error::NotReady);
            }
            if !self.strata_ready {
                return Err(Error::NotReady);
            }
            let len = message.encoded_len(self.snapshot.abi())?;
            let mut bytes = self.growth.vector(len)?;
            bytes.resize(len, 0);
            message.encode(&mut bytes, self.snapshot.abi())?;
            let mut cursor = 0;
            let done = self.input_step(&bytes, &mut cursor, ports)?;
            return if done { Ok(()) } else { Err(Error::Stale) };
        }
        let len = message.encoded_len(self.snapshot.abi())?;
        let mut bytes = self.growth.vector(len)?;
        bytes.resize(len, 0);
        message.encode(&mut bytes, self.snapshot.abi())?;
        if let Some(done) = &self.completed_input {
            if *done != bytes {
                return Err(Error::Conflict);
            }
            self.completed_input = None;
            return Ok(());
        }
        if let Some((original, _)) = &self.input {
            if *original != bytes {
                return Err(Error::Conflict);
            }
            return Err(Error::NotReady);
        }
        self.input = Some((bytes, 0));
        Err(Error::NotReady)
    }
    fn lookup(&self, h: &[u8; 64]) -> Result<usize, usize> {
        self.entries.binary_search_by(|e| e.body.hash.cmp(h))
    }
    fn new_ibf(&mut self, order: u8, salt: u32, decode: bool) -> Result<(), Error> {
        if self.rounds >= self.limits.rounds {
            return Err(Error::Capacity);
        }
        let count = 1usize
            .checked_shl(u32::from(order))
            .ok_or(Error::TooLarge)?;
        self.growth.claim(
            count
                .checked_mul(core::mem::size_of::<ibf::Cell>())
                .ok_or(Error::Overflow)?,
        )?;
        let filter = Ibf::sparse(count, self.limits.ibf_buckets, self.snapshot.abi().order)?;
        let mut keys = self.growth.vector(self.entries.len())?;
        keys.extend(self.entries.iter().map(|e| e.key));
        self.build = Some(Build {
            filter,
            keys,
            order,
            salt,
            cursor: 0,
            offset: 0,
            decode,
            scan: 0,
            nonzero: false,
        });
        self.rounds += 1;
        self.peeled = 0;
        self.last_key = None;
        Ok(())
    }
    fn offer_key(&mut self, key: u64) -> Result<bool, Error> {
        let start = match self.offers {
            Some((k, at)) if k == key => at,
            _ => 0,
        };
        let end = (start + 32).min(self.entries.len());
        for i in start..end {
            if self.entries[i].key == key {
                if !self.out.room() {
                    self.offers = Some((key, i));
                    return Ok(false);
                }
                self.out.peer_bounded(
                    PeerMessage::UnionOffer {
                        hashes: core::slice::from_ref(&self.entries[i].body.hash),
                    },
                    self.snapshot.abi(),
                    &mut self.growth,
                )?;
            }
            self.offers = Some((key, i + 1));
        }
        if end == self.entries.len() {
            self.offers = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn add_remote(&mut self, element: wire::Element<'_>, full: bool) -> Result<(), Error> {
        let h = hash(element, self.snapshot.abi())?;
        let demanded = self.demands.iter().position(|x| x == &h);
        if !full && demanded.is_none() {
            return Err(Error::Malformed);
        }
        let known = self.lookup(&h);
        if let Ok(i) = known {
            if self.entries[i].body.kind != element.element_type
                || self.entries[i].body.data != element.data
            {
                return Err(Error::Malformed);
            }
            // A shared original element is legal on its first remote receipt.
            // Its existing per-operation bit also proves an exact full-leg
            // replay, independently of overlap, output pressure or record cap.
            if full && self.options.byzantine != 0 && self.entries[i].remote {
                return Err(Error::Replay);
            }
        }
        if self.received >= self.limits.received_records {
            return Err(Error::Capacity);
        }
        if let Ok(i) = known {
            self.entries[i].remote = true;
        } else {
            if !self.out.room() {
                return Err(Error::WouldBlock);
            }
            if self.entries.len() >= self.limits.union_elements
                || element.data.len() > self.limits.content.element_bytes
            {
                return Err(Error::Capacity);
            }
            let mut data = self.growth.vector(element.data.len())?;
            let payload = self
                .payload
                .checked_add(data.capacity())
                .ok_or(Error::Overflow)?;
            if payload > self.limits.union_bytes {
                return Err(Error::Capacity);
            }
            data.extend_from_slice(element.data);
            self.growth.grow_vec(&mut self.entries, 1)?;
            let key = ibf::element_key(&h, self.snapshot.abi().order)?;
            self.growth.claim(Body::allocation_overhead())?;
            let body = Body::new(element.element_type, data, h, &self.snapshot.ledger)?;
            let status = if self.mode == ResultMode::Symmetric {
                Status::AddLocal
            } else {
                Status::Ok
            };
            self.out.result_bounded(
                status,
                Some(body.clone()),
                (self.entries.len() + 1) as u64,
                &mut self.growth,
            )?;
            let at = self.lookup(&h).unwrap_or_else(|i| i);
            self.entries.insert(
                at,
                Entry {
                    body,
                    key,
                    remote: true,
                },
            );
            self.payload = payload;
        }
        if let Some(i) = demanded {
            self.demands.swap_remove(i);
        }
        self.received += 1;
        Ok(())
    }
    fn input_step(
        &mut self,
        bytes: &[u8],
        at: &mut usize,
        ports: &mut impl Ports,
    ) -> Result<bool, Error> {
        let message = PeerMessage::decode(bytes, self.snapshot.abi())?;
        match message {
            PeerMessage::UnionStrata {
                compressed,
                set_size,
                data,
            } if self.phase == Phase::ExpectStrata => {
                if self.options.byzantine != 0
                    && set_size < u64::from(self.options.byzantine_lower_bound)
                {
                    return Err(Error::Malformed);
                }
                let remote = if compressed {
                    self.growth.claim(ibf::STRATA_BYTES)?;
                    ports.decompress_exact(data, ibf::STRATA_BYTES, ibf::STRATA_BYTES)?
                } else {
                    self.growth.copy(data)?
                };
                if remote.capacity() > ibf::STRATA_BYTES {
                    return Err(Error::Capacity);
                }
                if remote.len() != ibf::STRATA_BYTES {
                    return Err(Error::Malformed);
                }
                self.remote_strata = Some(remote);
                self.remote_size = set_size;
                self.estimate = 0;
                self.estimate_stratum = 31;
                Ok(true)
            }
            PeerMessage::UnionIbf {
                order,
                offset,
                salt,
                buckets,
                ..
            } if matches!(self.phase, Phase::ExpectIbf | Phase::Passive) => {
                if self.options.force_full != 0 {
                    return Err(Error::Unsupported);
                }
                if self.build.is_some() || self.offers.is_some() {
                    return Err(Error::NotReady);
                }
                if self.remote_ibf.is_none() {
                    if offset != 0 {
                        return Err(Error::Malformed);
                    }
                    let count = 1usize
                        .checked_shl(u32::from(order))
                        .ok_or(Error::TooLarge)?;
                    self.growth.claim(
                        count
                            .checked_mul(core::mem::size_of::<ibf::Cell>())
                            .ok_or(Error::Overflow)?,
                    )?;
                    self.remote_ibf = Some(Ibf::sparse(
                        count,
                        self.limits.ibf_buckets,
                        self.snapshot.abi().order,
                    )?);
                    self.remote_offset = 0;
                    self.remote_salt = salt;
                }
                let filter = self.remote_ibf.as_mut().ok_or(Error::Stale)?;
                if offset as usize != self.remote_offset
                    || filter.len()
                        != 1usize
                            .checked_shl(u32::from(order))
                            .ok_or(Error::TooLarge)?
                    || salt != self.remote_salt
                {
                    return Err(Error::Malformed);
                }
                filter.receive_slice(self.remote_offset, buckets)?;
                self.remote_offset += buckets.len();
                if self.remote_offset == filter.len() {
                    self.new_ibf(order, salt, true)?;
                    self.phase = Phase::Active;
                }
                Ok(true)
            }
            PeerMessage::UnionInquiry { salt, keys, .. } if self.phase == Phase::Passive => {
                if *at == keys.len() {
                    return Ok(true);
                }
                let key = ibf::unsalt(self.snapshot.abi().order.read64(keys[*at]), salt);
                if self.offer_key(key)? {
                    *at += 1;
                }
                Ok(*at == keys.len())
            }
            PeerMessage::UnionOffer { hashes }
                if matches!(self.phase, Phase::Active | Phase::Passive) =>
            {
                if *at == hashes.len() {
                    return Ok(true);
                }
                let h = hashes[*at];
                if self.lookup(&h).is_err() && !self.demands.contains(&h) {
                    if !self.out.room() {
                        return Err(Error::WouldBlock);
                    }
                    if self.demands.len() >= self.limits.union_elements {
                        return Err(Error::Capacity);
                    }
                    self.growth.grow_vec(&mut self.demands, 1)?;
                    self.out.peer_bounded(
                        PeerMessage::UnionDemand {
                            hashes: core::slice::from_ref(&h),
                        },
                        self.snapshot.abi(),
                        &mut self.growth,
                    )?;
                    self.demands.push(h);
                }
                *at += 1;
                Ok(*at == hashes.len())
            }
            PeerMessage::UnionDemand { hashes }
                if matches!(
                    self.phase,
                    Phase::Active
                        | Phase::Passive
                        | Phase::FinishWait
                        | Phase::FinishClose
                        | Phase::PassiveDone
                        | Phase::Done
                ) =>
            {
                if *at == hashes.len() {
                    return Ok(true);
                }
                if !self.out.room() {
                    return Err(Error::WouldBlock);
                }
                let index = self
                    .snapshot
                    .find_hash(&hashes[*at])
                    .ok_or(Error::Malformed)?;
                let body = &self.snapshot.members[index];
                self.out.peer_bounded(
                    PeerMessage::UnionElements {
                        element: body.element(),
                    },
                    self.snapshot.abi(),
                    &mut self.growth,
                )?;
                if self.mode == ResultMode::Symmetric {
                    self.out.result_bounded(
                        Status::AddRemote,
                        Some(body.clone()),
                        self.entries.len() as u64,
                        &mut self.growth,
                    )?;
                }
                *at += 1;
                Ok(*at == hashes.len())
            }
            PeerMessage::UnionElements { element }
                if matches!(
                    self.phase,
                    Phase::Active | Phase::Passive | Phase::FinishWait | Phase::FinishClose
                ) =>
            {
                self.add_remote(element, false)?;
                Ok(true)
            }
            PeerMessage::UnionFullElement { element }
                if matches!(
                    self.phase,
                    Phase::ExpectIbf
                        | Phase::FullFirst
                        | Phase::FullWaiting
                        | Phase::FullCounterReceive
                        | Phase::FullMutualFirst
                        | Phase::FullMutualWaiting
                ) =>
            {
                if self.options.force_delta != 0 {
                    return Err(Error::Unsupported);
                }
                if self.full_peer_done {
                    return Err(Error::Malformed);
                }
                self.add_remote(element, true)?;
                Ok(true)
            }
            PeerMessage::UnionRequestFull if self.phase == Phase::ExpectIbf => {
                if self.options.force_delta != 0 {
                    return Err(Error::Unsupported);
                }
                if self.full_request_sent {
                    // The peer has independently requested our original set.
                    // Fulfil it once, retaining our earlier request for its full
                    // set instead of reinterpreting that response as missing-only.
                    self.phase = Phase::FullMutualFirst;
                    self.full_cursor = 0;
                } else if self.mode == ResultMode::Symmetric {
                    // Exactly one reciprocal request while the evaluator is
                    // still EXPECT_IBF. Receive its full set before fulfilling
                    // the original requested set, so C cannot close on our DONE
                    // while its own first-leg data is merely queued.
                    self.out.peer_bounded(
                        PeerMessage::UnionRequestFull,
                        self.snapshot.abi(),
                        &mut self.growth,
                    )?;
                    self.full_request_sent = true;
                    self.phase = Phase::FullCounterReceive;
                } else {
                    self.phase = Phase::FullFirst;
                    self.full_cursor = 0;
                }
                Ok(true)
            }
            PeerMessage::UnionFullDone if self.phase == Phase::ExpectIbf => {
                if self.options.force_delta != 0 {
                    return Err(Error::Unsupported);
                }
                if self.full_peer_done {
                    return Err(Error::Malformed);
                }
                self.full_peer_done = true;
                self.phase = Phase::FullReturn;
                self.full_cursor = 0;
                Ok(true)
            }
            PeerMessage::UnionFullDone if self.phase == Phase::FullCounterReceive => {
                if self.full_peer_done {
                    return Err(Error::Malformed);
                }
                self.full_peer_done = true;
                self.phase = Phase::FullCounterReturn;
                self.full_cursor = 0;
                Ok(true)
            }
            PeerMessage::UnionFullDone if self.phase == Phase::FullMutualFirst => {
                if self.full_peer_done {
                    return Err(Error::Malformed);
                }
                // Record complete original peer data, but our independent full
                // response may still be unsent/partial. No protocol success yet.
                self.full_peer_done = true;
                Ok(true)
            }
            PeerMessage::UnionFullDone if self.phase == Phase::FullMutualWaiting => {
                if self.full_peer_done {
                    return Err(Error::Malformed);
                }
                self.full_peer_done = true;
                self.phase = Phase::FullMutualResults;
                self.full_cursor = 0;
                Ok(true)
            }
            PeerMessage::UnionFullDone if self.phase == Phase::FullWaiting => {
                if self.full_peer_done {
                    return Err(Error::Malformed);
                }
                self.full_peer_done = true;
                // Actual original output debt remains separate from peer DONE.
                self.phase = Phase::Done;
                self.protocol = true;
                Ok(true)
            }
            PeerMessage::UnionDone if self.phase == Phase::Passive => {
                self.phase = Phase::FinishWait;
                Ok(true)
            }
            PeerMessage::UnionDone if self.phase == Phase::Active => {
                if self.demands.is_empty() {
                    self.phase = Phase::Done;
                    self.protocol = true;
                } else {
                    self.phase = Phase::FinishClose;
                }
                Ok(true)
            }
            PeerMessage::UnionOver if matches!(self.phase, Phase::Done | Phase::PassiveDone) => {
                self.phase = Phase::Done;
                self.protocol = true;
                Ok(true)
            }
            _ => Err(Error::Malformed),
        }
    }
    #[cfg(test)]
    pub fn progress(&mut self, ports: &mut impl Ports) -> Result<bool, Error> {
        let bodies = self.snapshot.ledger.charged_bytes()?;
        let additional = self
            .limits
            .retained_bytes
            .checked_sub(self.charged_bytes()?)
            .and_then(|n| n.checked_sub(bodies))
            .ok_or(Error::Capacity)?;
        self.progress_bounded(ports, additional)
    }
    pub fn progress_bounded(
        &mut self,
        ports: &mut impl Ports,
        additional: usize,
    ) -> Result<bool, Error> {
        self.growth = Growth::new(additional);
        if !self.active || self.first_error.is_some() || self.retired && !self.can_finish_locally()
        {
            return Ok(false);
        }
        if !self.strata_ready {
            let strata = self.strata.as_mut().ok_or(Error::Stale)?;
            self.strata_ready = strata.build(&self.snapshot)?;
            if self.strata_ready {
                if self.role == Role::Acceptor {
                    self.growth.claim(
                        ibf::STRATA_BYTES
                            .checked_add(ibf::STRATUM_BYTES)
                            .ok_or(Error::Overflow)?,
                    )?;
                    let data = strata.encode()?;
                    self.out.peer_bounded(
                        PeerMessage::UnionStrata {
                            compressed: false,
                            set_size: self.snapshot.len() as u64,
                            data: &data,
                        },
                        self.snapshot.abi(),
                        &mut self.growth,
                    )?;
                    self.phase = Phase::ExpectIbf;
                } else {
                    self.phase = Phase::ExpectStrata;
                }
            }
            return Ok(true);
        }
        if let Some((bytes, mut at)) = self.input.take() {
            let before = (
                at,
                self.offers,
                self.out.frames.len(),
                self.out.results.len(),
            );
            match self.input_step(&bytes, &mut at, ports) {
                Ok(done) => {
                    if !done {
                        self.input = Some((bytes, at));
                    } else {
                        self.completed_input = Some(bytes);
                    }
                    let changed = done
                        || before
                            != (
                                at,
                                self.offers,
                                self.out.frames.len(),
                                self.out.results.len(),
                            );
                    if changed {
                        return Ok(true);
                    }
                }
                Err(Error::WouldBlock | Error::NotReady) => {
                    self.input = Some((bytes, at));
                }
                Err(e) => return Err(e),
            }
        }
        if let Some(remote) = self.remote_strata.as_ref() {
            self.growth.claim(
                ibf::STRATUM_BUCKETS
                    .checked_mul(core::mem::size_of::<ibf::Cell>())
                    .ok_or(Error::Overflow)?,
            )?;
            let (n, done) = self.strata.as_ref().ok_or(Error::Stale)?.difference(
                remote,
                self.estimate_stratum,
                self.estimate,
            )?;
            self.estimate = n;
            if done {
                self.remote_strata = None;
                self.strata = None;
                let full = self.options.force_full != 0
                    || (self.options.force_delta == 0
                        && self.mode != ResultMode::Symmetric
                        && (n > self.snapshot.len() as u64 / 4 || self.remote_size == 0));
                if full {
                    if self.mode == ResultMode::Symmetric
                        || (self.snapshot.len() as u64 > self.remote_size && self.remote_size != 0)
                    {
                        // The initiator may legally request the full set from
                        // an EXPECT_IBF acceptor regardless of relative sizes.
                        // Receiving its complete first leg proves both result
                        // directions without changing the official exchange.
                        self.out.peer_bounded(
                            PeerMessage::UnionRequestFull,
                            self.snapshot.abi(),
                            &mut self.growth,
                        )?;
                        self.full_request_sent = true;
                        self.phase = Phase::ExpectIbf;
                    } else {
                        self.phase = Phase::FullFirst;
                        self.full_cursor = 0;
                    }
                } else {
                    let target = n.saturating_mul(4).max(4);
                    let mut order = 2u8;
                    while (1u64 << order) < target && (1usize << order) < self.limits.ibf_buckets {
                        order += 1;
                    }
                    if (1usize << order) < self.limits.ibf_buckets {
                        order += 1;
                    }
                    self.new_ibf(order, self.salt_send, false)?;
                }
            } else {
                self.estimate_stratum -= 1;
            }
            return Ok(true);
        }
        if let Some(mut b) = self.build.take() {
            if !b.filter.initialized() {
                b.filter.initialize_step();
                self.build = Some(b);
                return Ok(true);
            }
            if b.cursor < b.keys.len() {
                let end = (b.cursor + 32).min(b.keys.len());
                for key in &b.keys[b.cursor..end] {
                    b.filter.add(ibf::salt(*key, b.salt), 1)?;
                }
                b.cursor = end;
                self.build = Some(b);
                return Ok(true);
            }
            if b.decode {
                if let Some(remote) = self.remote_ibf.take() {
                    b.filter.subtract(&remote)?;
                }
                if let Some((key, side)) = self.peel_pending {
                    if !self.out.room() {
                        self.build = Some(b);
                        return Ok(false);
                    }
                    if side == 1 {
                        if !self.offer_key(ibf::unsalt(key, b.salt))? {
                            self.build = Some(b);
                            return Ok(true);
                        }
                    } else {
                        let key = self.snapshot.abi().order.u64(key);
                        self.out.peer_bounded(
                            PeerMessage::UnionInquiry {
                                salt: b.salt,
                                reserved: 0,
                                keys: core::slice::from_ref(&key),
                            },
                            self.snapshot.abi(),
                            &mut self.growth,
                        )?;
                    }
                    self.peel_pending = None;
                    self.build = Some(b);
                    return Ok(true);
                }
                match b.filter.peel_step(&mut b.scan, &mut b.nonzero)? {
                    Peel::Item { key, side }
                        if self.peeled < b.filter.cells.len() && self.last_key != Some(key) =>
                    {
                        self.peeled += 1;
                        self.last_key = Some(key);
                        self.peel_pending = Some((key, side));
                        self.build = Some(b);
                    }
                    Peel::Pending => {
                        self.build = Some(b);
                    }
                    Peel::Empty => {
                        if !self.out.room() {
                            self.build = Some(b);
                            return Ok(false);
                        }
                        self.out.peer_bounded(
                            PeerMessage::UnionDone,
                            self.snapshot.abi(),
                            &mut self.growth,
                        )?;
                        self.phase = Phase::Active;
                    }
                    _ => {
                        let order = b.order.checked_add(1).ok_or(Error::Overflow)?;
                        self.salt_send = self.salt_send.checked_add(1).ok_or(Error::Overflow)?;
                        self.new_ibf(order, self.salt_send, false)?;
                    }
                }
                return Ok(true);
            }
            if !self.out.room() {
                self.build = Some(b);
                return Ok(false);
            }
            let cap = self.limits.output_bytes.min(32768).saturating_sub(16) / 13;
            if cap == 0 {
                return Err(Error::Capacity);
            }
            let count = (b.filter.cells.len() - b.offset).min(cap);
            self.growth
                .claim(count.checked_mul(13).ok_or(Error::Overflow)?)?;
            let data = b.filter.encode_slice(b.offset, count)?;
            self.out.peer_bounded(
                PeerMessage::UnionIbf {
                    order: b.order,
                    reserved1: 0,
                    reserved2: 0,
                    offset: u32::try_from(b.offset).map_err(|_| Error::TooLarge)?,
                    salt: b.salt,
                    buckets: wire::IbfSlice::decode(&data)?,
                },
                self.snapshot.abi(),
                &mut self.growth,
            )?;
            b.offset += count;
            if b.offset < b.filter.cells.len() {
                self.build = Some(b);
            } else {
                self.phase = Phase::Passive;
            }
            return Ok(true);
        }
        if self.phase == Phase::FullMutualResults {
            if self.mode != ResultMode::Symmetric {
                self.phase = Phase::Done;
                self.protocol = true;
                return Ok(true);
            }
            if !self.out.room() {
                return Ok(false);
            }
            if self.full_cursor < self.snapshot.members.len() {
                let body = &self.snapshot.members[self.full_cursor];
                let index = self.lookup(&body.hash).map_err(|_| Error::Stale)?;
                if self.mode == ResultMode::Symmetric && !self.entries[index].remote {
                    self.out.result_bounded(
                        Status::AddRemote,
                        Some(body.clone()),
                        self.entries.len() as u64,
                        &mut self.growth,
                    )?;
                }
                self.full_cursor += 1;
            } else {
                self.phase = Phase::Done;
                self.protocol = true;
            }
            return Ok(true);
        }
        if matches!(
            self.phase,
            Phase::FullFirst
                | Phase::FullReturn
                | Phase::FullCounterReturn
                | Phase::FullMutualFirst
        ) {
            if !self.out.room() {
                return Ok(false);
            }
            // The retained union can grow/reorder while full peer data arrives.
            // Only the immutable original snapshot is owed to its requester.
            if self.full_cursor < self.snapshot.members.len() {
                let body = &self.snapshot.members[self.full_cursor];
                let index = self.lookup(&body.hash).map_err(|_| Error::Stale)?;
                let missing = !self.entries[index].remote;
                if self.phase != Phase::FullReturn || missing {
                    self.out.peer_bounded(
                        PeerMessage::UnionFullElement {
                            element: body.element(),
                        },
                        self.snapshot.abi(),
                        &mut self.growth,
                    )?;
                    if matches!(self.phase, Phase::FullReturn | Phase::FullCounterReturn)
                        && self.mode == ResultMode::Symmetric
                        && missing
                    {
                        self.out.result_bounded(
                            Status::AddRemote,
                            Some(body.clone()),
                            self.entries.len() as u64,
                            &mut self.growth,
                        )?;
                    }
                }
                self.full_cursor += 1;
            } else {
                self.out.peer_bounded(
                    PeerMessage::UnionFullDone,
                    self.snapshot.abi(),
                    &mut self.growth,
                )?;
                self.full_local_done = true;
                match self.phase {
                    Phase::FullReturn | Phase::FullCounterReturn => {
                        self.phase = Phase::Done;
                        self.protocol = true;
                    }
                    Phase::FullMutualFirst => {
                        self.phase = if self.full_peer_done {
                            Phase::FullMutualResults
                        } else {
                            Phase::FullMutualWaiting
                        };
                        self.full_cursor = 0;
                    }
                    _ => self.phase = Phase::FullWaiting,
                }
            }
            return Ok(true);
        }
        if self.demands.is_empty() {
            if self.phase == Phase::FinishWait {
                if !self.out.room() {
                    return Ok(false);
                }
                self.out.peer_bounded(
                    PeerMessage::UnionDone,
                    self.snapshot.abi(),
                    &mut self.growth,
                )?;
                // DONE completes our receive side. It does not grant the
                // passive endpoint authority to destroy the ordered channel:
                // an earlier inquiry can still produce a late peer demand.
                self.phase = Phase::PassiveDone;
                self.protocol = true;
                return Ok(true);
            }
            if self.phase == Phase::FinishClose {
                self.phase = Phase::Done;
                self.protocol = true;
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Actual engine-owned metadata/scratch/output. Body allocations are held
    /// once by snapshot.ledger even when entries/results share the same body.
    pub fn charged_bytes(&self) -> Result<usize, Error> {
        let mut n = self
            .membership_bytes
            .checked_add(self.out.charged()?)
            .ok_or(Error::Overflow)?;
        for v in [
            self.entries
                .capacity()
                .checked_mul(core::mem::size_of::<Entry>())
                .ok_or(Error::Overflow)?,
            self.demands
                .capacity()
                .checked_mul(64)
                .ok_or(Error::Overflow)?,
        ] {
            n = n.checked_add(v).ok_or(Error::Overflow)?;
        }
        if let Some(s) = &self.strata {
            n = n.checked_add(s.charged()?).ok_or(Error::Overflow)?;
        }
        for f in [
            self.build.as_ref().map(|b| &b.filter),
            self.remote_ibf.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            n = n
                .checked_add(
                    f.cells
                        .capacity()
                        .checked_mul(core::mem::size_of::<ibf::Cell>())
                        .ok_or(Error::Overflow)?,
                )
                .ok_or(Error::Overflow)?;
        }
        if let Some(b) = &self.build {
            n = n
                .checked_add(b.keys.capacity().checked_mul(8).ok_or(Error::Overflow)?)
                .ok_or(Error::Overflow)?;
        }
        if let Some(v) = &self.remote_strata {
            n = n.checked_add(v.capacity()).ok_or(Error::Overflow)?;
        }
        if let Some(v) = &self.completed_input {
            n = n.checked_add(v.capacity()).ok_or(Error::Overflow)?;
        }
        if let Some((v, _)) = &self.input {
            n = n.checked_add(v.capacity()).ok_or(Error::Overflow)?;
        }
        Ok(n)
    }
}

#[cfg(test)]
#[path = "union_tests.rs"]
mod tests;
