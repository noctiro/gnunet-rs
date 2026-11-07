//! One actual pure union protocol. Physical IO and its truthful completion live
//! at the caller port; encoded output alone never reports protocol DONE.
use crate::{
    Codec,
    ibf::{Cell, Decode, Ibf, Key, Order},
    set::{Element, Snapshot},
    strata::{self, Strata},
    wire::{Abi, Element as Borrowed, Options, Peer, Status},
};
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use gnunet_types::Error;
mod work;
pub use work::{Choice, choose};
/// Explicit operation memory/work/Byzantine limits, independent of wire fields.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum unique original+received union elements.
    pub elements: usize,
    /// Maximum received fresh opaque payload bytes.
    pub received_bytes: usize,
    /// Maximum IBF buckets, bounded by reference1048576.
    pub ibf_buckets: usize,
    /// Maximum active/passive retry rounds.
    pub rounds: u16,
    /// Maximum immutable output frames retained per operation.
    pub output_frames: usize,
    /// Maximum immutable output bytes retained.
    pub output_bytes: usize,
    /// Maximum retained ADD_LOCAL/ADD_REMOTE reports.
    pub results: usize,
    /// Maximum actual full/delta element inputs, including repeats.
    pub received_records: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            elements: 8192,
            received_bytes: 32 * 1024 * 1024,
            ibf_buckets: 1_048_576,
            rounds: 32,
            output_frames: 1024,
            output_bytes: 8 * 1024 * 1024,
            results: 8192,
            received_records: 16384,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.elements == 0
            || self.ibf_buckets < 37
            || self.ibf_buckets > 1_048_576
            || self.rounds == 0
            || self.output_frames == 0
            || self.output_bytes < 50573
            || self.results == 0
            || self.received_records == 0
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}
/// Original pure protocol state, not an assertion about remote native processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Initiator awaiting responder strata.
    ExpectStrata,
    /// Original bounded local strata estimate is being computed.
    Estimating,
    /// Responder awaiting original IBF/full decision.
    ExpectIbf,
    /// Ordered continuation of one original IBF.
    ReceivingIbf,
    /// This peer is decoding a differential filter.
    Active,
    /// Remote peer is decoding our original filter.
    Passive,
    /// Receive the complete remote set first.
    FullReceiving,
    /// Send our full original set first, then receive missing elements.
    FullSending,
    /// Passive side has received DONE and waits for its demands/output.
    WaitDone,
    /// Final response sent; wait for actual peer OVER/physical close.
    WaitOver,
    /// Final local response drains before caller closes original channel.
    Closing,
    /// Actual original channel retired after protocol success.
    Finished,
    /// Original operation failed and requires actual source retirement.
    Failed,
}
#[derive(Debug)]
struct Stamp {
    _nonzero: u8,
}
/// Original immutable transmission capability; another union cannot settle it.
#[derive(Clone, Debug)]
pub struct Transmission {
    owner: Rc<Stamp>,
    serial: u64,
}
impl PartialEq for Transmission {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner) && self.serial == other.serial
    }
}
impl Eq for Transmission {}
impl Transmission {
    /// Diagnostic serial, never serialized or accepted without its original brand.
    #[must_use]
    pub const fn diagnostic(&self) -> u64 {
        self.serial
    }
}
/// Borrowed original immutable peer bytes and their exact local write capability.
pub struct Outbound<'a> {
    /// Actual original transmission capability.
    pub transmission: Transmission,
    /// Immutable complete original peer frame.
    pub bytes: &'a [u8],
}
/// Original result element/status. It can be encoded as the official RESULT;
/// data remains immutable and no underlying local set is silently mutated.
pub struct ResultEntry {
    /// Official status.
    pub status: Status,
    /// Original immutable element for nonterminal results.
    pub element: Option<Rc<Element>>,
    /// Actual union cardinality known so far.
    pub current_size: u64,
    /// Original local cause for failure, if any.
    pub error: Option<Error>,
}
struct Output {
    serial: u64,
    bytes: Vec<u8>,
    leased: bool,
}
struct Known {
    element: Rc<Element>,
    remote_seen: bool,
}
enum IbfStage {
    Build,
    Send,
    Peel,
}
enum Work {
    Strata {
        cells: Vec<Cell>,
        cursor: usize,
        remote: Option<(u8, Vec<u8>)>,
    },
    Ibf {
        cells: Vec<Cell>,
        keys: Vec<Key>,
        cursor: usize,
        offset: usize,
        salt: u32,
        stage: IbfStage,
        remote: Option<Vec<Cell>>,
        decoded: usize,
        last: Option<Key>,
        pending: Option<(Key, i8)>,
    },
    Full {
        cursor: usize,
        missing_only: bool,
    },
}
struct Receiving {
    cells: Vec<Cell>,
    received: usize,
    salt: u32,
    bits: u8,
}
/// Bounded no_std/alloc union owner. Rc shares only immutable elements and local
/// brands; no network/thread/runtime, private key or peer authority is created.
pub struct Union {
    snapshot: Snapshot,
    known: Vec<Known>,
    abi: Abi,
    order: Order,
    options: Options,
    limits: Limits,
    phase: Phase,
    work: Option<Work>,
    receiving: Option<Receiving>,
    remote_size: u64,
    remote_size_known: bool,
    remote_diff: u64,
    local_diff: u64,
    outputs: VecDeque<Output>,
    output_bytes: usize,
    next_tx: u64,
    stamp: Rc<Stamp>,
    results: VecDeque<ResultEntry>,
    demands: Vec<[u8; 64]>,
    offered: Vec<[u8; 64]>,
    sent: Vec<[u8; 64]>,
    received_bytes: usize,
    received_total: usize,
    retries: u16,
    over_queued: bool,
    success_pending: bool,
    retired: bool,
    cancelled: bool,
    failure: Option<Error>,
    terminal_reported: bool,
}
fn vector<T>(capacity: usize) -> Result<Vec<T>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    Ok(value)
}
fn cells(n: usize) -> Result<Vec<Cell>, Error> {
    let mut value = vector(n)?;
    value.resize(n, Cell::default());
    Ok(value)
}
fn bytes(n: usize) -> Result<Vec<u8>, Error> {
    let mut value = vector(n)?;
    value.resize(n, 0);
    Ok(value)
}
fn insert_hash(values: &mut Vec<[u8; 64]>, hash: [u8; 64], limit: usize) -> Result<bool, Error> {
    match values.binary_search(&hash) {
        Ok(_) => Ok(false),
        Err(index) => {
            if values.len() == limit {
                return Err(Error::Capacity);
            }
            values.try_reserve(1).map_err(|_| Error::Capacity)?;
            values.insert(index, hash);
            Ok(true)
        }
    }
}
pub(crate) fn validate_options(options: Options) -> Result<(), Error> {
    if options.force_delta != 0 && options.force_full != 0
        || options.hashes == 0
        || options.hashes > 255
        || options.bucket_factor == 0
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
impl Union {
    fn new(
        snapshot: Snapshot,
        options: Options,
        limits: Limits,
        phase: Phase,
    ) -> Result<Self, Error> {
        limits.validate()?;
        snapshot.abi.validate()?;
        validate_options(options)?;
        if snapshot.len() > limits.elements {
            return Err(Error::InvalidInput);
        }
        let abi = snapshot.abi;
        let order = match abi.order {
            crate::wire::Order::Little => Order::Little,
            crate::wire::Order::Big => Order::Big,
        };
        let mut known = vector(snapshot.len())?;
        known.extend(snapshot.elements.iter().cloned().map(|element| Known {
            element,
            remote_seen: false,
        }));
        let mut outputs = VecDeque::new();
        outputs
            .try_reserve(limits.output_frames)
            .map_err(|_| Error::Capacity)?;
        let mut results = VecDeque::new();
        results
            .try_reserve(limits.results)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            snapshot,
            known,
            abi,
            order,
            options,
            limits,
            phase,
            work: None,
            receiving: None,
            remote_size: 0,
            remote_size_known: false,
            remote_diff: 0,
            local_diff: 0,
            outputs,
            output_bytes: 0,
            next_tx: 0,
            stamp: Rc::new(Stamp { _nonzero: 0 }),
            results,
            demands: Vec::new(),
            offered: Vec::new(),
            sent: Vec::new(),
            received_bytes: 0,
            received_total: 0,
            retries: 0,
            over_queued: false,
            success_pending: false,
            retired: false,
            cancelled: false,
            failure: None,
            terminal_reported: false,
        })
    }
    /// Original initiator snapshot and operation request. Host must send it on
    /// the actual channel opened to `app`; context is an exact nested message.
    pub fn initiate(
        snapshot: Snapshot,
        options: Options,
        limits: Limits,
        app: [u8; 64],
        context: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let count = u32::try_from(snapshot.len()).map_err(|_| Error::TooLarge)?;
        let mut union = Self::new(snapshot, options, limits, Phase::ExpectStrata)?;
        union.queue(Peer::Operation {
            count,
            app,
            context,
        })?;
        Ok(union)
    }
    /// Accept the actual original incoming operation. Strata generation advances
    /// incrementally against this immutable local snapshot, never a later set.
    pub fn accept(
        snapshot: Snapshot,
        options: Options,
        limits: Limits,
        remote_size: u32,
    ) -> Result<Self, Error> {
        let mut union = Self::new(snapshot, options, limits, Phase::ExpectIbf)?;
        union.remote_size = u64::from(remote_size);
        union.work = Some(Work::Strata {
            cells: cells(strata::ALL_CELLS)?,
            cursor: 0,
            remote: None,
        });
        Ok(union)
    }
    /// Actual pure state, independent of host queue/write completion.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    /// Whether the actual original source retirement callback was consumed.
    #[must_use]
    pub const fn is_retired(&self) -> bool {
        self.retired
    }
    /// Actual known original+fresh remote union cardinality.
    #[must_use]
    pub fn size(&self) -> usize {
        self.known.len()
    }
    /// Actual IBF active/passive rounds, bounded by Limits.rounds.
    #[must_use]
    pub const fn rounds(&self) -> u16 {
        self.retries
    }
    /// Whether the first original frame has not yet been handed to the host.
    /// An issued lease remains owned by that host until sent/retired callbacks.
    #[must_use]
    pub fn has_unleased_output(&self) -> bool {
        self.outputs.front().is_some_and(|output| !output.leased)
    }
    /// Immutable first original output. Repeated borrows retain the same token;
    /// dropping a waiting host future never mints a replacement transmission.
    pub fn outbound(&mut self) -> Option<Outbound<'_>> {
        let front = self.outputs.front_mut()?;
        front.leased = true;
        Some(Outbound {
            transmission: Transmission {
                owner: self.stamp.clone(),
                serial: front.serial,
            },
            bytes: &front.bytes,
        })
    }
    /// Report actual complete local writing of this exact original frame. It
    /// grants no peer processing/union success by itself.
    pub fn sent(&mut self, transmission: &Transmission) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.stamp, &transmission.owner) {
            return Err(Error::Stale);
        }
        let front = self.outputs.front().ok_or(Error::Stale)?;
        if front.serial != transmission.serial || !front.leased {
            return Err(Error::Stale);
        }
        let old = self.outputs.pop_front().ok_or(Error::Stale)?;
        self.output_bytes -= old.bytes.len();
        self.finish_progress()?;
        Ok(())
    }
    /// Whether the caller must physically close this original channel. This is
    /// a request, not evidence that any real source has already quiesced.
    #[must_use]
    pub fn close_needed(&self) -> bool {
        self.phase == Phase::Failed
            || self.cancelled
            || (self.phase == Phase::Closing
                && self.over_queued
                && self.outputs.is_empty()
                && self.work.is_none()
                && self.demands.is_empty())
    }
    /// Actual original peer-channel close/retirement callback. Success requires
    /// the real protocol end and all original queued output/demands settled.
    pub fn retired(&mut self) {
        if self.retired {
            return;
        }
        let success = !self.cancelled
            && self.failure.is_none()
            && self.outputs.is_empty()
            && self.work.is_none()
            && self.demands.is_empty()
            && (self.success_pending || self.phase == Phase::WaitOver);
        self.retired = true;
        self.work = None;
        self.receiving = None;
        self.outputs.clear();
        self.output_bytes = 0;
        if success {
            self.phase = Phase::Finished
        } else {
            self.phase = Phase::Failed;
            if !self.cancelled && self.failure.is_none() {
                self.failure = Some(Error::Io)
            }
        }
    }
    /// Fail original logical work with its actual host/core cause and retain
    /// original leased output until truthful send/physical retirement callbacks.
    pub fn abort(&mut self, error: Error) {
        self.fail(error);
    }
    /// Cancel logical callbacks and request actual original channel retirement.
    /// A leased immutable frame is retained until sent/retired, never replaced.
    pub fn cancel(&mut self) {
        if self.retired {
            return;
        }
        self.cancelled = true;
        self.work = None;
        self.receiving = None;
        self.retain_leased();
        self.results.clear();
    }
    fn retain_leased(&mut self) {
        let keep = self.outputs.front().is_some_and(|frame| frame.leased);
        while self.outputs.len() > usize::from(keep) {
            if let Some(frame) = self.outputs.pop_back() {
                self.output_bytes -= frame.bytes.len()
            }
        }
    }
    fn fail(&mut self, error: Error) {
        if self.retired {
            return;
        }
        self.failure.get_or_insert(error);
        self.phase = Phase::Failed;
        self.work = None;
        self.receiving = None;
        self.retain_leased();
    }
    /// Consume original result observations. Terminal DONE/FAILURE occurs only
    /// after actual source retirement; cancellation suppresses terminal callback.
    pub fn next_result(&mut self) -> Option<ResultEntry> {
        if let Some(result) = self.results.pop_front() {
            return Some(result);
        }
        if !self.retired || self.cancelled || self.terminal_reported {
            return None;
        }
        self.terminal_reported = true;
        Some(ResultEntry {
            status: if self.phase == Phase::Finished {
                Status::Done
            } else {
                Status::Failure
            },
            element: None,
            current_size: self.known.len() as u64,
            error: self.failure,
        })
    }
    fn reserve_output(&mut self, frames: usize, bytes: usize) -> Result<(), Error> {
        if frames > self.limits.output_frames || bytes > self.limits.output_bytes {
            return Err(Error::Capacity);
        }
        if self
            .outputs
            .len()
            .checked_add(frames)
            .is_none_or(|n| n > self.limits.output_frames)
            || self
                .output_bytes
                .checked_add(bytes)
                .is_none_or(|n| n > self.limits.output_bytes)
        {
            return Err(Error::WouldBlock);
        }
        self.outputs
            .try_reserve(frames)
            .map_err(|_| Error::Capacity)?;
        Ok(())
    }
    fn queue(&mut self, peer: Peer<'_>) -> Result<(), Error> {
        let n = peer.encoded_len()?;
        self.reserve_output(1, n)?;
        let serial = self.next_tx.checked_add(1).ok_or(Error::Overflow)?;
        let mut output = bytes(n)?;
        peer.encode(self.abi, &mut output)?;
        self.outputs.push_back(Output {
            serial,
            bytes: output,
            leased: false,
        });
        self.output_bytes += n;
        self.next_tx = serial;
        Ok(())
    }
    fn result(&mut self, status: Status, element: Rc<Element>) -> Result<(), Error> {
        if self.results.len() == self.limits.results {
            return Err(Error::Capacity);
        }
        self.results.try_reserve(1).map_err(|_| Error::Capacity)?;
        self.results.push_back(ResultEntry {
            status,
            element: Some(element),
            current_size: self.known.len() as u64,
            error: None,
        });
        Ok(())
    }
    fn find(&self, hash: &[u8; 64]) -> Result<usize, usize> {
        self.known
            .binary_search_by_key(hash, |entry| *entry.element.hash())
    }
    fn check_bounds(&self) -> Result<(), Error> {
        if self.remote_size_known && self.remote_size > self.options.upper_bound {
            return Err(Error::PermissionDenied);
        }
        if self.options.byzantine == 1
            && self.remote_size_known
            && (self.remote_size < u64::from(self.options.lower_bound)
                || self
                    .remote_size
                    .checked_add(self.remote_diff)
                    .is_none_or(|n| n > self.options.upper_bound)
                || (self.snapshot.len() as u64)
                    .checked_add(self.local_diff)
                    .is_none_or(|n| n > self.options.upper_bound))
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    fn finish_progress(&mut self) -> Result<(), Error> {
        if self.cancelled
            || self.phase == Phase::Failed
            || self.retired
            || self.work.is_some()
            || !self.demands.is_empty()
            || self.offered.iter().any(|hash| !self.sent.contains(hash))
            || !self.outputs.is_empty()
        {
            return Ok(());
        }
        match self.phase {
            Phase::WaitDone => {
                self.queue(Peer::Done)?;
                self.phase = Phase::WaitOver
            }
            Phase::Closing if !self.over_queued => {
                self.queue(Peer::Over)?;
                self.over_queued = true;
                self.success_pending = true
            }
            _ => {}
        }
        Ok(())
    }
    fn begin_ibf(
        &mut self,
        size: usize,
        remote: Option<Vec<Cell>>,
        salt: u32,
    ) -> Result<(), Error> {
        if size < 37 || size > self.limits.ibf_buckets || size < self.options.hashes as usize {
            return Err(Error::Capacity);
        }
        self.retries = self.retries.checked_add(1).ok_or(Error::Overflow)?;
        if self.retries > self.limits.rounds {
            return Err(Error::Capacity);
        }
        let mut keys = vector(self.known.len())?;
        keys.extend(
            self.known
                .iter()
                .map(|entry| entry.element.key().salted(salt)),
        );
        self.work = Some(Work::Ibf {
            cells: cells(size)?,
            keys,
            cursor: 0,
            offset: 0,
            salt,
            stage: IbfStage::Build,
            remote,
            decoded: 0,
            last: None,
            pending: None,
        });
        Ok(())
    }
    fn offer_key(&mut self, key: Key) -> Result<(), Error> {
        if !self.known.iter().any(|entry| entry.element.key() == key) {
            return Err(Error::Authentication);
        }
        let mut hashes = Vec::new();
        for entry in &self.known {
            if entry.element.key() == key && !self.offered.contains(entry.element.hash()) {
                hashes.try_reserve(1).map_err(|_| Error::Capacity)?;
                hashes.push(*entry.element.hash())
            }
        }
        self.reserve_output(
            hashes.len(),
            hashes.len().checked_mul(68).ok_or(Error::Capacity)?,
        )?;
        self.offered
            .try_reserve(hashes.len())
            .map_err(|_| Error::Capacity)?;
        for hash in hashes {
            self.queue(Peer::Offer(&hash))?;
            insert_hash(&mut self.offered, hash, self.limits.elements)?;
        }
        Ok(())
    }
    fn received_element(&mut self, element: Borrowed<'_>, full: bool) -> Result<(), Error> {
        let owned = Element::new(element, self.abi)?;
        let hash = *owned.hash();
        if !full {
            let position = self
                .demands
                .binary_search(&hash)
                .map_err(|_| Error::Authentication)?;
            self.demands.remove(position);
        }
        let received = self.received_total.checked_add(1).ok_or(Error::Overflow)?;
        if received > self.limits.received_records {
            return Err(Error::Capacity);
        }
        if full && self.options.byzantine == 1 && received as u64 > self.remote_size {
            return Err(Error::Authentication);
        }
        match self.find(&hash) {
            Ok(index) => {
                if self.known[index].remote_seen {
                    return Err(Error::Replay);
                }
                if self.known[index].element.borrowed() != element {
                    return Err(Error::Authentication);
                }
                self.known[index].remote_seen = true
            }
            Err(index) => {
                let size = self
                    .received_bytes
                    .checked_add(element.data.len())
                    .ok_or(Error::Capacity)?;
                if self.known.len() == self.limits.elements || size > self.limits.received_bytes {
                    return Err(Error::Capacity);
                }
                self.known.try_reserve(1).map_err(|_| Error::Capacity)?;
                let owned = Rc::new(owned);
                self.known.insert(
                    index,
                    Known {
                        element: owned.clone(),
                        remote_seen: true,
                    },
                );
                self.received_bytes = size;
                self.result(Status::AddLocal, owned)?;
            }
        }
        self.received_total = received;
        Ok(())
    }
    /// Process one complete actual peer frame. WouldBlock preserves the input
    /// for retry; other failures request original physical retirement. No result
    /// or peer acceptance is manufactured from an encoded output.
    pub fn receive(&mut self, bytes: &[u8], codec: &mut impl Codec) -> Result<(), Error> {
        if self.retired || self.cancelled || self.phase == Phase::Failed {
            return Err(Error::Closed);
        }
        let result = self.receive_inner(bytes, codec);
        if let Err(error) = result
            && error != Error::WouldBlock
        {
            self.fail(error)
        }
        result
    }
    /// Advance at most `budget` bounded work actions. One action handles one
    /// element, one IBF peel/slice, or the fixed bounded estimator calculation.
    pub fn advance(&mut self, codec: &mut impl Codec, budget: usize) -> Result<usize, Error> {
        let mut count = 0;
        while count < budget && !self.retired && !self.cancelled && self.phase != Phase::Failed {
            let Some(mut work) = self.work.take() else {
                self.finish_progress()?;
                break;
            };
            let step = self.step_work(&mut work, codec);
            match step {
                Ok(done) => {
                    count += 1;
                    if !done {
                        self.work = Some(work)
                    }
                }
                Err(Error::WouldBlock) => {
                    self.work = Some(work);
                    break;
                }
                Err(error) => {
                    self.fail(error);
                    return Err(error);
                }
            }
        }
        self.finish_progress()?;
        Ok(count)
    }
}
