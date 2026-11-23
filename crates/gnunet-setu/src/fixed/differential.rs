//! One bounded original SETU differential exchange.

use super::{Buffers, Config, ElementSource, LocalEntry, Phase, Session, element_hash};
use crate::{
    ibf::{BUCKET_WIRE_BYTES, Decode, Ibf, Key, Order},
    wire::{Element, Peer},
};
use gnunet_types::Error;

const MIN_BUCKETS: usize = 37;
const IBF_PREFIX: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Offer {
    Idle,
    Pending,
    Sent,
    Requested,
    Delivered,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Demand {
    Pending,
    Sent,
    Received,
}

/// Original peer hash record. The index tracks full-set uniqueness or the
/// exact differential demand until its matching element is admitted.
#[derive(Clone, Copy)]
pub struct RemoteEntry {
    pub(super) hash: [u8; 64],
    key: Key,
    demand: Demand,
}

impl RemoteEntry {
    /// Empty entry for caller-owned static memory.
    pub const EMPTY: Self = Self::full([0; 64]);

    pub(super) const fn full(hash: [u8; 64]) -> Self {
        Self {
            hash,
            key: Key(0),
            demand: Demand::Received,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Round {
    AwaitFilter,
    Receiving,
    Sending,
    Passive,
    Peeling,
    AwaitDone,
    ReturningDone,
    AwaitClose,
    Closing,
}

#[derive(Clone, Copy)]
struct Filter {
    size: usize,
    cursor: usize,
    salt: u32,
    bits: u8,
}

#[derive(Clone, Copy)]
enum Inquiry {
    Idle,
    Awaiting(Key),
}

#[derive(Clone, Copy)]
enum Admit {
    Slice(usize),
    Inquiry(Key),
    Offer(usize),
    Demand(usize),
    Element(usize),
    ActiveDone,
    PassiveDone,
    Over,
}

/// Optional caller-owned differential state. Filter cells are reused from
/// the completed strata negotiation. Distinct peer hashes are bounded by
/// the configured original element and remote-index capacity.
pub struct Differential {
    max_buckets: usize,
    max_rounds: u8,
    rounds: u8,
    round: Round,
    filter: Filter,
    decoded: usize,
    last: Option<Key>,
    remote_count: usize,
    inquiry: Inquiry,
    pending: Option<Admit>,
}

impl Differential {
    /// Initialize a bounded workspace. Both limits must fit the actual caller
    /// arena. Each complete incoming or outgoing IBF consumes one round.
    pub const fn new(max_buckets: usize, max_rounds: u8) -> Self {
        Self {
            max_buckets,
            max_rounds,
            rounds: 0,
            round: Round::AwaitFilter,
            filter: Filter {
                size: 0,
                cursor: 0,
                salt: 0,
                bits: 0,
            },
            decoded: 0,
            last: None,
            remote_count: 0,
            inquiry: Inquiry::Idle,
            pending: None,
        }
    }

    pub(super) fn reset(&mut self, cells: usize) -> Result<(), Error> {
        if self.max_buckets < MIN_BUCKETS || self.max_buckets > cells || self.max_rounds == 0 {
            return Err(Error::Capacity);
        }
        *self = Self::new(self.max_buckets, self.max_rounds);
        Ok(())
    }

    pub(super) const fn awaiting_close(&self) -> bool {
        matches!(self.round, Round::AwaitClose)
    }

    pub(super) const fn staged_element(&self) -> bool {
        matches!(self.pending, Some(Admit::Element(_)))
    }

    fn start_round(&mut self, size: usize, hashes: u8) -> Result<(), Error> {
        if !(MIN_BUCKETS..=self.max_buckets).contains(&size) || size < usize::from(hashes) {
            return Err(Error::Capacity);
        }
        self.rounds = self.rounds.checked_add(1).ok_or(Error::Overflow)?;
        if self.rounds > self.max_rounds {
            return Err(Error::Capacity);
        }
        self.decoded = 0;
        self.last = None;
        Ok(())
    }

    fn build_filter(&mut self, io: &mut Io<'_>, size: usize) -> Result<(), Error> {
        self.start_round(size, io.hashes())?;
        // The reference 32-to-16-bit native salt field loses small nonzero
        // salts on little-endian peers. An interoperable retry grows the IBF
        // while using the same effective and encoded zero salt.
        let hashes = io.hashes();
        let mut filter = Ibf::clear(&mut io.cells[..size], hashes, io.order)?;
        for key in io
            .local
            .iter()
            .map(|entry| entry.key)
            .chain(self.learned(io.remote))
        {
            filter.insert(key)?;
        }
        self.filter = Filter {
            size,
            cursor: 0,
            salt: 0,
            bits: filter.max_counter_bits()?,
        };
        self.round = Round::Sending;
        Ok(())
    }

    fn receive_filter(
        &mut self,
        io: &mut Io<'_>,
        offered: Filter,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if matches!(self.round, Round::AwaitFilter | Round::Passive) {
            if offered.cursor != 0 {
                return Err(Error::Malformed);
            }
            self.start_round(offered.size, io.hashes())?;
            self.filter = offered;
            self.round = Round::Receiving;
        }
        let count = bytes.len() / BUCKET_WIRE_BYTES;
        let end = offered.cursor.checked_add(count).ok_or(Error::Overflow)?;
        if self.round != Round::Receiving
            || self.filter.size != offered.size
            || self.filter.cursor != offered.cursor
            || self.filter.salt != offered.salt
            || self.filter.bits != offered.bits
            || end > offered.size
        {
            return Err(Error::Malformed);
        }
        let hashes = io.hashes();
        let mut filter = Ibf::view(&mut io.cells[..offered.size], hashes, io.order)?;
        filter.read_slice(offered.cursor, count, offered.bits, bytes)?;
        self.filter.cursor = end;
        if end == offered.size {
            // In-place remote minus local. This is the opposite sign to the
            // C peer's local-minus-remote temporary, with the same two sides.
            for key in io
                .local
                .iter()
                .map(|entry| entry.key)
                .chain(self.learned(io.remote))
            {
                filter.remove(key.salted(offered.salt))?;
            }
            self.round = Round::Peeling;
        }
        Ok(())
    }

    fn learned<'a>(&self, entries: &'a [RemoteEntry]) -> impl Iterator<Item = Key> + use<'a> {
        entries[..self.remote_count]
            .iter()
            .filter(|entry| entry.demand == Demand::Received)
            .map(|entry| entry.key)
    }

    fn settled(&self, io: &Io<'_>) -> bool {
        matches!(self.inquiry, Inquiry::Idle)
            && !io
                .local
                .iter()
                .any(|entry| matches!(entry.offer, Offer::Pending | Offer::Sent | Offer::Requested))
            && io.remote[..self.remote_count]
                .iter()
                .all(|entry| entry.demand == Demand::Received)
    }

    fn offers(&mut self, io: &mut Io<'_>, hashes: &[[u8; 64]]) -> Result<(), Error> {
        for hash in hashes {
            if io.local_index(hash).is_some()
                || io.remote[..self.remote_count]
                    .iter()
                    .any(|entry| &entry.hash == hash)
            {
                continue;
            }
            if self.remote_count >= io.remote_limit {
                return Err(Error::Capacity);
            }
            let key = Key::from_element_hash(hash, io.order)?;
            if matches!(self.inquiry, Inquiry::Awaiting(expected) if expected == key) {
                self.inquiry = Inquiry::Idle;
            }
            io.remote[self.remote_count] = RemoteEntry {
                hash: *hash,
                key,
                demand: Demand::Pending,
            };
            self.remote_count += 1;
        }
        Ok(())
    }

    fn demands(io: &mut Io<'_>, hashes: &[[u8; 64]]) -> Result<(), Error> {
        for hash in hashes {
            let index = io.local_index(hash).ok_or(Error::Authentication)?;
            let entry = &mut io.local[index];
            if entry.offer != Offer::Sent {
                return Err(Error::Replay);
            }
            entry.offer = Offer::Requested;
        }
        Ok(())
    }

    fn element(
        &self,
        io: &mut Io<'_>,
        element: Element<'_>,
        learn: impl FnOnce(Element<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if element.data.len() > io.config.limits.element_bytes {
            return Err(Error::TooLarge);
        }
        let hash = element_hash(element, io.config.abi)?;
        let original = io.remote[..self.remote_count]
            .iter_mut()
            .find(|entry| entry.hash == hash)
            .ok_or(Error::Authentication)?;
        if original.demand != Demand::Sent {
            return Err(Error::Replay);
        }
        learn(element)?;
        original.demand = Demand::Received;
        Ok(())
    }

    fn receive(
        &mut self,
        io: &mut Io<'_>,
        peer: Peer<'_>,
        learn: impl FnOnce(Element<'_>) -> Result<(), Error>,
    ) -> Result<Option<Phase>, Error> {
        let decoding = matches!(
            self.round,
            Round::Peeling | Round::Sending | Round::Passive | Round::AwaitDone
        );
        match peer {
            Peer::Ibf {
                size,
                offset,
                salt_field,
                counter_bits,
                data,
            } => {
                let offered = Filter {
                    size: usize::try_from(size).map_err(|_| Error::Capacity)?,
                    cursor: usize::try_from(offset).map_err(|_| Error::Capacity)?,
                    salt: io.config.abi.effective_salt(salt_field),
                    bits: u8::try_from(counter_bits).map_err(|_| Error::Malformed)?,
                };
                self.receive_filter(io, offered, data)?;
            }
            Peer::Inquiry { salt, keys } if decoding => {
                for key in keys.as_chunks::<8>().0 {
                    io.offer(Key(io.order.read_u64(*key)).unsalted(salt));
                }
            }
            Peer::Offer(hashes) if decoding => self.offers(io, hashes.as_chunks::<64>().0)?,
            Peer::Demand(hashes) if decoding || self.round == Round::ReturningDone => {
                Self::demands(io, hashes.as_chunks::<64>().0)?;
            }
            Peer::Element(element)
                if decoding || matches!(self.round, Round::ReturningDone | Round::Closing) =>
            {
                self.element(io, element, learn)?;
            }
            Peer::Done if self.round == Round::Passive => self.round = Round::ReturningDone,
            Peer::Done if self.round == Round::AwaitDone => self.round = Round::Closing,
            Peer::Over if self.awaiting_close() => {
                return Ok(Some(Phase::Complete {
                    request_close: true,
                }));
            }
            Peer::Operation { .. } => return Err(Error::Replay),
            _ => return Err(Error::Malformed),
        }
        Ok(None)
    }

    fn prepare(
        &mut self,
        io: &mut Io<'_>,
        output: &mut Output<'_>,
        source: &(impl ElementSource + ?Sized),
    ) -> Result<Option<(usize, Phase)>, Error> {
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        if self.round == Round::Sending {
            return self.filter_slice(io, output).map(Some);
        }
        loop {
            if let Some(index) = io
                .local
                .iter()
                .position(|entry| entry.offer == Offer::Requested)
            {
                let entry = &io.local[index];
                let element = source.element(entry.index, output.element)?;
                if element_hash(element, io.config.abi)? != entry.hash {
                    return Err(Error::Authentication);
                }
                return self
                    .stage(
                        io,
                        output.frame,
                        Peer::Element(element),
                        Admit::Element(index),
                    )
                    .map(Some);
            }
            if let Some(index) = io.remote[..self.remote_count]
                .iter()
                .position(|entry| entry.demand == Demand::Pending)
            {
                let hash = &io.remote[index].hash;
                return self
                    .stage(io, output.frame, Peer::Demand(hash), Admit::Demand(index))
                    .map(Some);
            }
            if let Some(index) = io
                .local
                .iter()
                .position(|entry| entry.offer == Offer::Pending)
            {
                let hash = &io.local[index].hash;
                return self
                    .stage(io, output.frame, Peer::Offer(hash), Admit::Offer(index))
                    .map(Some);
            }
            match self.round {
                Round::Peeling if matches!(self.inquiry, Inquiry::Idle) => {
                    if let Some(frame) = self.peel(io, output)? {
                        return Ok(Some(frame));
                    }
                }
                Round::ReturningDone if self.settled(io) => {
                    return self
                        .stage(io, output.frame, Peer::Done, Admit::PassiveDone)
                        .map(Some);
                }
                Round::Closing if self.settled(io) => {
                    return self
                        .stage(io, output.frame, Peer::Over, Admit::Over)
                        .map(Some);
                }
                _ => return Ok(None),
            }
        }
    }

    fn peel(
        &mut self,
        io: &mut Io<'_>,
        output: &mut Output<'_>,
    ) -> Result<Option<(usize, Phase)>, Error> {
        let hashes = io.hashes();
        let mut filter = Ibf::view(&mut io.cells[..self.filter.size], hashes, io.order)?;
        let (key, side) = match filter.peel()? {
            Decode::Empty => {
                return self
                    .stage(io, output.frame, Peer::Done, Admit::ActiveDone)
                    .map(Some);
            }
            Decode::Stalled => return self.retry(io, output).map(Some),
            Decode::Item { key, side } => (key, side),
        };
        self.decoded += 1;
        let possible = io.local.len().saturating_add(io.remote_limit);
        if self.decoded > self.filter.size.min(possible) || self.last == Some(key) {
            return self.retry(io, output).map(Some);
        }
        self.last = Some(key);
        let original = key.unsalted(self.filter.salt);
        match side {
            -1 if io.offer(original) => Ok(None),
            1 if io.remote[..self.remote_count]
                .iter()
                .any(|entry| entry.key == original) =>
            {
                Ok(None)
            }
            1 => {
                let key = io.order.u64(key.0);
                let message = Peer::Inquiry {
                    salt: self.filter.salt,
                    keys: &key,
                };
                self.stage(io, output.frame, message, Admit::Inquiry(original))
                    .map(Some)
            }
            _ => Err(Error::Authentication),
        }
    }

    fn retry(&mut self, io: &mut Io<'_>, output: &mut Output<'_>) -> Result<(usize, Phase), Error> {
        let size = crate::mode::retry_buckets(
            self.filter.size,
            self.decoded,
            io.config.options.bucket_factor,
        )?;
        self.build_filter(io, size)?;
        self.filter_slice(io, output)
    }

    fn filter_slice(
        &mut self,
        io: &mut Io<'_>,
        output: &mut Output<'_>,
    ) -> Result<(usize, Phase), Error> {
        let available = output
            .frame
            .len()
            .min(usize::from(u16::MAX))
            .saturating_sub(IBF_PREFIX)
            .min(output.raw.len());
        let count = (self.filter.size - self.filter.cursor).min(available / BUCKET_WIRE_BYTES);
        if count == 0 {
            return Err(Error::Capacity);
        }
        let width = Ibf::wire_len(count)?;
        let hashes = io.hashes();
        let filter = Ibf::view(&mut io.cells[..self.filter.size], hashes, io.order)?;
        filter.encode_slice(
            self.filter.cursor,
            count,
            self.filter.bits,
            &mut output.raw[..width],
        )?;
        let message = Peer::Ibf {
            size: u32::try_from(self.filter.size).map_err(|_| Error::Capacity)?,
            offset: u32::try_from(self.filter.cursor).map_err(|_| Error::Capacity)?,
            salt_field: io.config.abi.salt_field(self.filter.salt),
            counter_bits: u16::from(self.filter.bits),
            data: &output.raw[..width],
        };
        self.stage(
            io,
            output.frame,
            message,
            Admit::Slice(self.filter.cursor + count),
        )
    }

    fn stage(
        &mut self,
        io: &Io<'_>,
        frame: &mut [u8],
        message: Peer<'_>,
        after: Admit,
    ) -> Result<(usize, Phase), Error> {
        let bytes = message.encode(io.config.abi, frame)?;
        self.pending = Some(after);
        let next = if matches!(after, Admit::Over) {
            Phase::Complete {
                request_close: true,
            }
        } else {
            Phase::Differential
        };
        Ok((bytes, next))
    }

    fn admitted(&mut self, io: &mut Io<'_>) -> Result<(), Error> {
        match self.pending.take().ok_or(Error::Conflict)? {
            Admit::Slice(end) => {
                self.filter.cursor = end;
                if end == self.filter.size {
                    self.round = Round::Passive;
                }
            }
            Admit::Inquiry(key) => {
                if !io.remote[..self.remote_count]
                    .iter()
                    .any(|entry| entry.key == key)
                {
                    self.inquiry = Inquiry::Awaiting(key);
                }
            }
            Admit::Offer(index) => io.local[index].offer = Offer::Sent,
            Admit::Demand(index) => io.remote[index].demand = Demand::Sent,
            Admit::Element(index) => io.local[index].offer = Offer::Delivered,
            Admit::ActiveDone => self.round = Round::AwaitDone,
            Admit::PassiveDone => self.round = Round::AwaitClose,
            Admit::Over => {}
        }
        Ok(())
    }
}

struct Io<'a> {
    config: Config,
    order: Order,
    remote_limit: usize,
    local: &'a mut [LocalEntry],
    remote: &'a mut [RemoteEntry],
    cells: &'a mut [crate::ibf::Cell],
}

struct Output<'a> {
    frame: &'a mut [u8],
    raw: &'a mut [u8],
    element: &'a mut [u8],
}

impl Io<'_> {
    fn hashes(&self) -> u8 {
        self.config.options.hashes as u8
    }

    fn offer(&mut self, key: Key) -> bool {
        let mut known = false;
        for entry in self.local.iter_mut().filter(|entry| entry.key == key) {
            known = true;
            if entry.offer == Offer::Idle {
                entry.offer = Offer::Pending;
            }
        }
        known
    }

    fn local_index(&self, hash: &[u8; 64]) -> Option<usize> {
        self.local
            .binary_search_by_key(hash, |entry| entry.hash)
            .ok()
    }
}

fn parts<'view>(
    buffers: &'view mut Buffers<'_>,
    config: Config,
    order: Order,
    size: usize,
    peer_count: Option<u32>,
) -> Result<(&'view mut Differential, Io<'view>, Output<'view>), Error> {
    let delta = buffers
        .differential
        .as_deref_mut()
        .ok_or(Error::Unsupported)?;
    let mut remote_limit = peer_count.map_or(config.limits.remote_elements, |count| count as usize);
    if config.options.byzantine == 1 {
        remote_limit =
            remote_limit.min(usize::try_from(config.options.upper_bound).unwrap_or(usize::MAX));
    }
    Ok((
        delta,
        Io {
            config,
            order,
            remote_limit,
            local: &mut buffers.local[..size],
            remote: buffers.remote,
            cells: buffers.estimator,
        },
        Output {
            frame: buffers.frame,
            raw: buffers.raw,
            element: buffers.element,
        },
    ))
}

impl<S: ElementSource> Session<'_, '_, S> {
    pub(super) fn start_differential(&mut self, remote: u64, local: u64) -> Result<(), Error> {
        let size = crate::mode::initial_buckets(remote, local, self.config.options.bucket_factor)?;
        let (delta, mut io, _) = parts(
            &mut self.buffers,
            self.config,
            self.order,
            self.size as usize,
            self.peer_count,
        )?;
        delta.build_filter(&mut io, size)?;
        self.phase = Phase::Differential;
        Ok(())
    }

    pub(super) fn receive_differential(
        &mut self,
        peer: Peer<'_>,
        learn: impl FnOnce(Element<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let (delta, mut io, _) = parts(
            &mut self.buffers,
            self.config,
            self.order,
            self.size as usize,
            self.peer_count,
        )?;
        if let Some(next) = delta.receive(&mut io, peer, learn)? {
            self.phase = next;
        }
        Ok(())
    }

    pub(super) fn build_differential(&mut self) -> Result<Option<(u16, Phase)>, Error> {
        let (delta, mut io, mut output) = parts(
            &mut self.buffers,
            self.config,
            self.order,
            self.size as usize,
            self.peer_count,
        )?;
        delta
            .prepare(&mut io, &mut output, &self.source)?
            .map(|(bytes, next)| Ok((u16::try_from(bytes).map_err(|_| Error::TooLarge)?, next)))
            .transpose()
    }

    pub(super) fn admit_differential(&mut self) -> Result<(), Error> {
        let (delta, mut io, _) = parts(
            &mut self.buffers,
            self.config,
            self.order,
            self.size as usize,
            self.peer_count,
        )?;
        delta.admitted(&mut io)
    }
}
