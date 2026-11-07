//! Bounded incremental estimator/filter/full-set work and validated peer input.
use super::*;
/// Internal source cost alternatives; no new wire negotiation field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Choice {
    /// Actual delta protocol.
    Differential,
    /// Local full set goes first.
    SendFull,
    /// Request remote full set first.
    RequestFull,
}
/// Source's byte/RTT mode model with checked finite Rust arithmetic. An undefined
/// negative C float-to-u64 counter estimate conservatively selects valid delta.
pub fn choose(
    avg: u64,
    local: u64,
    remote: u64,
    remote_diff: u64,
    local_diff: u64,
    options: Options,
) -> Result<Choice, Error> {
    super::validate_options(options)?;
    if options.force_delta == 1 {
        return Ok(Choice::Differential);
    }
    if local == 0 {
        return Ok(Choice::RequestFull);
    }
    if remote == 0 {
        return Ok(Choice::SendFull);
    }
    let diff = remote_diff.checked_add(local_diff).ok_or(Error::Overflow)?;
    let full_local = (avg.checked_add(8).ok_or(Error::Overflow)? as f64)
        * (remote_diff.checked_add(local).ok_or(Error::Overflow)? as f64)
        + 8.0
        + 2.0 * (options.bandwidth_latency_tradeoff as f64);
    let full_remote = (avg.checked_add(8).ok_or(Error::Overflow)? as f64)
        * (local_diff.checked_add(remote).ok_or(Error::Overflow)? as f64)
        + 12.0
        + 2.5 * (options.bandwidth_latency_tradeoff as f64);
    let buckets = libm::fmax(37.0, (diff as f64) * (options.bucket_factor as f64));
    let counter = libm::fmin(
        2.0 * libm::log2((local as f64) / buckets),
        libm::log2(local as f64),
    );
    if counter < 0.0 && options.force_full != 1 {
        return Ok(Choice::Differential);
    }
    let ibf = (16.0 * libm::ceil(buckets / 3276.0)
        + buckets * (12.0 + libm::ceil(libm::fmax(counter, 0.0)) / 8.0))
        * 1.2;
    let differential = ((avg + 8) as f64) * (diff as f64)
        + 4.0
        + 152.0 * (diff as f64)
        + libm::ceil(ibf)
        + 3.65145 * (options.bandwidth_latency_tradeoff as f64);
    if options.force_full == 1 || libm::fmin(full_local, full_remote) < differential {
        Ok(if full_local < full_remote {
            Choice::SendFull
        } else {
            Choice::RequestFull
        })
    } else {
        Ok(Choice::Differential)
    }
}
impl Union {
    pub(super) fn receive_inner(
        &mut self,
        bytes: &[u8],
        codec: &mut impl Codec,
    ) -> Result<(), Error> {
        let peer = Peer::decode(bytes, self.abi)?;
        match peer {
            Peer::Strata {
                compressed,
                count,
                set_size,
                data,
            } => {
                if self.phase != Phase::ExpectStrata || self.work.is_some() {
                    return Err(Error::Malformed);
                }
                self.remote_size = set_size;
                self.remote_size_known = true;
                self.check_bounds()?;
                let raw_len = Strata::wire_len(count)?;
                let mut raw = super::bytes(raw_len)?;
                if compressed {
                    if codec.decompress(data, &mut raw)? != raw_len {
                        return Err(Error::Malformed);
                    }
                } else {
                    if data.len() != raw_len {
                        return Err(Error::Malformed);
                    }
                    raw.copy_from_slice(data)
                }
                self.phase = Phase::Estimating;
                self.work = Some(Work::Strata {
                    cells: cells(strata::ALL_CELLS)?,
                    cursor: 0,
                    remote: Some((count, raw)),
                });
            }
            Peer::Ibf {
                size,
                offset,
                salt_field,
                counter_bits,
                data,
            } => {
                if self.options.force_full == 1 {
                    return Err(Error::Unsupported);
                }
                if !matches!(
                    self.phase,
                    Phase::ExpectIbf | Phase::Passive | Phase::ReceivingIbf
                ) || self.work.is_some()
                {
                    return Err(Error::Malformed);
                }
                let size = size as usize;
                let offset = offset as usize;
                let count = data.len() / 20;
                if size < 37
                    || size > self.limits.ibf_buckets
                    || size < self.options.hashes as usize
                    || counter_bits == 0
                    || counter_bits > 64
                {
                    return Err(Error::Capacity);
                }
                let salt = self.abi.effective_salt(salt_field);
                let bits = counter_bits as u8;
                if self.receiving.is_none() {
                    if offset != 0 {
                        return Err(Error::Malformed);
                    }
                    self.receiving = Some(Receiving {
                        cells: cells(size)?,
                        received: 0,
                        salt,
                        bits,
                    });
                    self.phase = Phase::ReceivingIbf;
                }
                let incoming = self.receiving.as_mut().ok_or(Error::Stale)?;
                if incoming.cells.len() != size
                    || incoming.received != offset
                    || incoming.salt != salt
                    || incoming.bits != bits
                    || offset.checked_add(count).is_none_or(|end| end > size)
                {
                    return Err(Error::Malformed);
                }
                Ibf::view(&mut incoming.cells, self.options.hashes as u8, self.order)?
                    .read_slice(offset, count, bits, data)?;
                incoming.received += count;
                if incoming.received == size {
                    let incoming = self.receiving.take().ok_or(Error::Stale)?;
                    self.phase = Phase::Active;
                    self.begin_ibf(size, Some(incoming.cells), salt)?;
                }
            }
            Peer::Full {
                request,
                remote_difference,
                remote_size,
                local_difference,
                ..
            } => {
                if self.options.force_delta == 1 {
                    return Err(Error::Unsupported);
                }
                if self.phase != Phase::ExpectIbf || self.work.is_some() {
                    return Err(Error::Malformed);
                }
                self.remote_size = u64::from(remote_size);
                self.remote_size_known = true;
                self.remote_diff = u64::from(remote_difference);
                self.local_diff = u64::from(local_difference);
                self.check_bounds()?;
                if request {
                    self.phase = Phase::FullSending;
                    self.work = Some(Work::Full {
                        cursor: 0,
                        missing_only: false,
                    })
                } else {
                    self.phase = Phase::FullReceiving
                }
            }
            Peer::Inquiry { salt, keys } => {
                if !matches!(self.phase, Phase::Active | Phase::Passive) {
                    return Err(Error::Malformed);
                }
                // Preflight the complete frame before any response-side mutation.
                let mut offers = Vec::new();
                for raw in keys.as_chunks::<8>().0 {
                    let key = Key(self.order.read_u64(*raw)).unsalted(salt);
                    for known in &self.known {
                        let hash = *known.element.hash();
                        if known.element.key() == key
                            && !self.offered.contains(&hash)
                            && !offers.contains(&hash)
                        {
                            offers.try_reserve(1).map_err(|_| Error::Capacity)?;
                            offers.push(hash)
                        }
                    }
                }
                self.reserve_output(
                    offers.len(),
                    offers.len().checked_mul(68).ok_or(Error::Capacity)?,
                )?;
                self.offered
                    .try_reserve(offers.len())
                    .map_err(|_| Error::Capacity)?;
                for hash in offers {
                    self.queue(Peer::Offer(&hash))?;
                    insert_hash(&mut self.offered, hash, self.limits.elements)?;
                }
            }
            Peer::Offer(hashes) => {
                if !matches!(self.phase, Phase::Active | Phase::Passive) {
                    return Err(Error::Malformed);
                }
                let mut requests = Vec::new();
                for raw in hashes.as_chunks::<64>().0 {
                    let hash: [u8; 64] = *raw;
                    if self.find(&hash).is_err()
                        && !self.demands.contains(&hash)
                        && !requests.contains(&hash)
                    {
                        requests.try_reserve(1).map_err(|_| Error::Capacity)?;
                        requests.push(hash)
                    }
                }
                self.reserve_output(
                    requests.len(),
                    requests.len().checked_mul(68).ok_or(Error::Capacity)?,
                )?;
                self.demands
                    .try_reserve(requests.len())
                    .map_err(|_| Error::Capacity)?;
                if self
                    .demands
                    .len()
                    .checked_add(requests.len())
                    .is_none_or(|len| len > self.limits.elements)
                {
                    return Err(Error::Capacity);
                }
                for hash in requests {
                    self.queue(Peer::Demand(&hash))?;
                    insert_hash(&mut self.demands, hash, self.limits.elements)?;
                }
            }
            Peer::Demand(hashes) => {
                if !matches!(self.phase, Phase::Active | Phase::Passive | Phase::WaitDone) {
                    return Err(Error::Malformed);
                }
                let mut indexes = Vec::new();
                let mut total = 0usize;
                for raw in hashes.as_chunks::<64>().0 {
                    let hash: [u8; 64] = *raw;
                    if self.sent.contains(&hash) || !self.offered.contains(&hash) {
                        return Err(Error::Replay);
                    }
                    let index = self.find(&hash).map_err(|_| Error::NotFound)?;
                    if indexes.contains(&index) {
                        return Err(Error::Replay);
                    }
                    total = total
                        .checked_add(8 + self.known[index].element.borrowed().data.len())
                        .ok_or(Error::Capacity)?;
                    indexes.try_reserve(1).map_err(|_| Error::Capacity)?;
                    indexes.push(index)
                }
                self.reserve_output(indexes.len(), total)?;
                if self.options.symmetric != 0
                    && self
                        .results
                        .len()
                        .checked_add(indexes.len())
                        .is_none_or(|count| count > self.limits.results)
                {
                    return Err(Error::Capacity);
                }
                self.sent
                    .try_reserve(indexes.len())
                    .map_err(|_| Error::Capacity)?;
                for index in indexes {
                    let element = self.known[index].element.clone();
                    self.queue(Peer::Element(element.borrowed()))?;
                    insert_hash(&mut self.sent, *element.hash(), self.limits.elements)?;
                    if self.options.symmetric != 0 {
                        self.result(Status::AddRemote, element)?;
                    }
                }
            }
            Peer::Element(element) => {
                if !matches!(
                    self.phase,
                    Phase::Active | Phase::Passive | Phase::WaitDone | Phase::Closing
                ) {
                    return Err(Error::Malformed);
                }
                self.received_element(element, false)?;
            }
            Peer::FullElement(element) => {
                if !matches!(self.phase, Phase::FullReceiving | Phase::FullSending) {
                    return Err(Error::Malformed);
                }
                self.received_element(element, true)?;
            }
            Peer::Done => match self.phase {
                Phase::Passive => self.phase = Phase::WaitDone,
                Phase::Active if self.work.is_none() => self.phase = Phase::Closing,
                _ => return Err(Error::Malformed),
            },
            Peer::FullDone => match self.phase {
                Phase::FullReceiving => {
                    if self.options.byzantine == 1 && self.received_total as u64 != self.remote_size
                    {
                        return Err(Error::Authentication);
                    }
                    self.phase = Phase::WaitOver;
                    self.work = Some(Work::Full {
                        cursor: 0,
                        missing_only: true,
                    })
                }
                Phase::FullSending if self.work.is_none() => self.phase = Phase::Closing,
                _ => return Err(Error::Malformed),
            },
            Peer::Over => {
                if self.phase != Phase::WaitOver || self.work.is_some() || !self.demands.is_empty()
                {
                    return Err(Error::Malformed);
                }
                self.phase = Phase::Closing;
                self.over_queued = true;
                self.success_pending = true;
            }
            Peer::Operation { .. } => return Err(Error::Replay),
        }
        self.finish_progress()
    }
    pub(super) fn step_work(
        &mut self,
        work: &mut Work,
        codec: &mut impl Codec,
    ) -> Result<bool, Error> {
        match work {
            Work::Strata {
                cells: storage,
                cursor,
                remote,
            } => {
                if *cursor < self.snapshot.elements.len() {
                    Strata::view(storage, 8, self.order)?
                        .insert(self.snapshot.elements[*cursor].key())?;
                    *cursor += 1;
                    return Ok(false);
                }
                if let Some((count, raw)) = remote {
                    let mut remote_cells = cells(Strata::cell_count(*count)?)?;
                    let mut other = Strata::view(&mut remote_cells, *count, self.order)?;
                    other.read_raw(*count, raw)?;
                    let mut scratch = cells(strata::BUCKETS)?;
                    let local = Strata::view(storage, 8, self.order)?;
                    let estimate = other.estimate_difference(&local, *count, &mut scratch)?;
                    self.remote_diff = estimate.positive;
                    self.local_diff = estimate.negative;
                    if self.remote_size == 0 {
                        self.remote_diff = 0;
                        self.local_diff = self.snapshot.len() as u64
                    }
                    if self.snapshot.is_empty() {
                        self.local_diff = 0;
                        self.remote_diff = self.remote_size
                    }
                    self.check_bounds()?;
                    let average = if self.snapshot.is_empty() {
                        0
                    } else {
                        self.snapshot.bytes as u64 / self.snapshot.len() as u64
                    };
                    let choice = choose(
                        average,
                        self.snapshot.len() as u64,
                        self.remote_size,
                        self.remote_diff,
                        self.local_diff,
                        self.options,
                    )?;
                    match choice {
                        Choice::Differential => {
                            let diff = self
                                .remote_diff
                                .checked_add(self.local_diff)
                                .ok_or(Error::Overflow)?;
                            let size = diff
                                .checked_mul(self.options.bucket_factor)
                                .ok_or(Error::Overflow)?
                                | 1;
                            let size =
                                usize::try_from(size.max(37)).map_err(|_| Error::Capacity)?;
                            self.phase = Phase::Passive;
                            self.begin_ibf(size, None, 0)?;
                        }
                        Choice::SendFull | Choice::RequestFull => {
                            let remote_difference =
                                u32::try_from(self.local_diff).map_err(|_| Error::TooLarge)?;
                            let local_difference =
                                u32::try_from(self.remote_diff).map_err(|_| Error::TooLarge)?;
                            let remote_size =
                                u32::try_from(self.snapshot.len()).map_err(|_| Error::TooLarge)?;
                            self.queue(Peer::Full {
                                request: choice == Choice::RequestFull,
                                remote_difference,
                                remote_size,
                                local_difference,
                                padding: &[0; 16],
                            })?;
                            if choice == Choice::SendFull {
                                self.phase = Phase::FullSending;
                                self.work = Some(Work::Full {
                                    cursor: 0,
                                    missing_only: false,
                                })
                            } else {
                                self.phase = Phase::FullReceiving
                            }
                        }
                    }
                    Ok(true)
                } else {
                    let mut raw = super::bytes(Strata::wire_len(1)?)?;
                    Strata::view(storage, 8, self.order)?.write_raw(1, &mut raw)?;
                    let mut compressed = super::bytes(65535 - 13)?;
                    let len = codec.compress(&raw, &mut compressed)?;
                    compressed.truncate(len);
                    self.queue(Peer::Strata {
                        compressed: true,
                        count: 1,
                        set_size: self.snapshot.len() as u64,
                        data: &compressed,
                    })?;
                    Ok(true)
                }
            }
            Work::Ibf {
                cells: storage,
                keys,
                cursor,
                offset,
                salt,
                stage,
                remote,
                decoded,
                last,
                pending,
            } => match stage {
                IbfStage::Build => {
                    if *cursor < keys.len() {
                        Ibf::view(storage, self.options.hashes as u8, self.order)?
                            .insert(keys[*cursor])?;
                        *cursor += 1;
                        return Ok(false);
                    }
                    keys.clear();
                    if let Some(other) = remote.take() {
                        Ibf::view(storage, self.options.hashes as u8, self.order)?
                            .subtract_cells(&other)?;
                        *stage = IbfStage::Peel;
                    } else {
                        *stage = IbfStage::Send;
                    }
                    Ok(false)
                }
                IbfStage::Send => {
                    if *offset == storage.len() {
                        return Ok(true);
                    }
                    let count = (storage.len() - *offset).min(
                        (gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE - 16) / 20,
                    );
                    let mut data = super::bytes(count * 20)?;
                    let filter = Ibf::view(storage, self.options.hashes as u8, self.order)?;
                    let bits = filter.max_counter_bits()?;
                    filter.encode_slice(*offset, count, bits, &mut data)?;
                    self.queue(Peer::Ibf {
                        size: storage.len() as u32,
                        offset: *offset as u32,
                        salt_field: self.abi.salt_field(*salt),
                        counter_bits: u16::from(bits),
                        data: &data,
                    })?;
                    *offset += count;
                    Ok(*offset == storage.len())
                }
                IbfStage::Peel => {
                    let fresh = pending.is_none();
                    let outcome = if let Some((key, side)) = *pending {
                        Decode::Item { key, side }
                    } else {
                        Ibf::view(storage, self.options.hashes as u8, self.order)?.peel()?
                    };
                    match outcome {
                        Decode::Empty => {
                            self.queue(Peer::Done)?;
                            Ok(true)
                        }
                        Decode::Item { key, side } => {
                            if fresh {
                                *decoded += 1;
                            }
                            if fresh
                                && (*decoded > storage.len()
                                    || (*decoded > 1 && *last == Some(key)))
                            {
                                return self.retry_work(
                                    storage, keys, cursor, offset, salt, stage, remote, decoded,
                                    last, pending,
                                );
                            }
                            *last = Some(key);
                            *pending = Some((key, side));
                            if side == 1 {
                                self.offer_key(key.unsalted(*salt))?;
                            } else if side == -1 {
                                let key = self.order.u64(key.0);
                                self.queue(Peer::Inquiry {
                                    salt: *salt,
                                    keys: &key,
                                })?;
                            } else {
                                return Err(Error::Malformed);
                            }
                            *pending = None;
                            Ok(false)
                        }
                        Decode::Stalled => self.retry_work(
                            storage, keys, cursor, offset, salt, stage, remote, decoded, last,
                            pending,
                        ),
                    }
                }
            },
            Work::Full {
                cursor,
                missing_only,
            } => {
                if *cursor < self.snapshot.elements.len() {
                    let element = self.snapshot.elements[*cursor].clone();
                    let remote_seen = if *missing_only {
                        self.find(element.hash())
                            .ok()
                            .map(|index| self.known[index].remote_seen)
                    } else {
                        None
                    };
                    if remote_seen == Some(true) {
                        *cursor += 1;
                        return Ok(false);
                    }
                    // Only the return leg proves this local element is missing
                    // remotely. Initial full transmission also includes common
                    // elements and cannot make that claim from this protocol.
                    let notify = remote_seen == Some(false) && self.options.symmetric != 0;
                    if notify {
                        self.reserve_output(
                            1,
                            Peer::FullElement(element.borrowed()).encoded_len()?,
                        )?;
                        if self.results.len() == self.limits.results {
                            return Err(Error::Capacity);
                        }
                        self.results.try_reserve(1).map_err(|_| Error::Capacity)?;
                    }
                    self.queue(Peer::FullElement(element.borrowed()))?;
                    if notify {
                        self.result(Status::AddRemote, element)?;
                    }
                    *cursor += 1;
                    return Ok(false);
                }
                self.queue(Peer::FullDone)?;
                Ok(true)
            }
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "All original incremental IBF fields move together without reallocating another maximum-sized state"
    )]
    fn retry_work(
        &mut self,
        storage: &mut Vec<Cell>,
        keys: &mut Vec<Key>,
        cursor: &mut usize,
        offset: &mut usize,
        salt: &mut u32,
        stage: &mut IbfStage,
        remote: &mut Option<Vec<Cell>>,
        decoded: &mut usize,
        last: &mut Option<Key>,
        pending: &mut Option<(Key, i8)>,
    ) -> Result<bool, Error> {
        let previous = storage.len();
        let removed = usize::try_from(self.options.bucket_factor)
            .map_err(|_| Error::Overflow)?
            .checked_mul(*decoded)
            .ok_or(Error::Overflow)?;
        let next = previous
            .checked_mul(2)
            .ok_or(Error::Overflow)?
            .saturating_sub(removed)
            .max(previous.checked_add(2).ok_or(Error::Overflow)?)
            .max(37)
            | 1;
        if next > self.limits.ibf_buckets {
            return Err(Error::Capacity);
        }
        self.retries = self.retries.checked_add(1).ok_or(Error::Overflow)?;
        if self.retries > self.limits.rounds {
            return Err(Error::Capacity);
        }
        storage.clear();
        storage
            .try_reserve_exact(next)
            .map_err(|_| Error::Capacity)?;
        storage.resize(next, Cell::default());
        keys.clear();
        keys.try_reserve_exact(self.known.len())
            .map_err(|_| Error::Capacity)?;
        // Source little-endian salt truncation cannot communicate small nonzero
        // salts. Keep actual effective salt0 and make checked bucket progress;
        // this is still the official IBF exchange, not an invented wire field.
        *salt = 0;
        keys.extend(self.known.iter().map(|known| known.element.key()));
        *cursor = 0;
        *offset = 0;
        *decoded = 0;
        *last = None;
        *pending = None;
        *remote = None;
        *stage = IbfStage::Build;
        self.phase = Phase::Passive;
        Ok(false)
    }
}
