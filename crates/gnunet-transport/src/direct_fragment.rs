//! Bounded TRANSPORT fragment receipt for one original authenticated carrier.
//!
//! The caller provides one frame buffer per lane and one bit of coverage per
//! byte. Each original remains owned here until its consumer releases it.
//! ACKs describe accepted fragment transmissions and use the carrier's
//! independent control admission path.

use crate::p2p::{Fragment, encode_acknowledgements};
use core::fmt;
use gnunet_types::{Duration, Error, MonoInstant};
use gnunet_wire::official::{Frame, HEADER_LEN, message_type as mt};
use zeroize::Zeroize;

pub(crate) const REASSEMBLY_LIFETIME: Duration = Duration(4 * 60 * 1_000_000);
const ACK_CAPACITY: usize = 16;
const ACK_HEADER_LEN: usize = 8;
const ACK_ENTRY_LEN: usize = 24;

/// The accepted fragment's effect on the original message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Receive {
    /// New bytes were accepted, with more original bytes still missing.
    Partial,
    /// The complete original frame became available exactly once.
    Complete,
    /// Every supplied byte matched retained bytes. This is still an ACK cause.
    Duplicate,
}

#[derive(Clone, Copy)]
struct Original {
    id: [u8; 8],
    total: usize,
    expires: MonoInstant,
}

#[derive(Clone, Copy)]
struct Retired {
    id: [u8; 8],
    expires: MonoInstant,
}

#[derive(Clone, Copy)]
enum Slot {
    Empty,
    Assembling { original: Original, missing: usize },
    Complete(Original),
    Retained(Original),
}

impl Slot {
    fn original(self) -> Option<Original> {
        match self {
            Self::Empty => None,
            Self::Assembling { original, .. }
            | Self::Complete(original)
            | Self::Retained(original) => Some(original),
        }
    }
}

/// Exclusive receive and coverage storage for one reassembly original.
pub struct FragmentLane<'a> {
    body: &'a mut [u8],
    coverage: &'a mut [u8],
}

impl<'a> FragmentLane<'a> {
    /// Lend one lane whose byte limit is the size of its body buffer.
    ///
    /// # Errors
    /// Rejects an invalid frame width or a coverage buffer smaller than one
    /// bit per byte.
    pub fn new(body: &'a mut [u8], coverage: &'a mut [u8]) -> Result<Self, Error> {
        if !(HEADER_LEN..=usize::from(u16::MAX)).contains(&body.len()) {
            return Err(Error::InvalidInput);
        }
        let coverage = coverage
            .get_mut(..body.len().div_ceil(8))
            .ok_or(Error::Capacity)?;
        Ok(Self { body, coverage })
    }

    /// Partition two packed buffers into `N` same-size lanes. Each lane's
    /// coverage starts at a whole byte.
    ///
    /// # Errors
    /// Rejects zero lanes, an invalid frame width or insufficient storage.
    pub fn partition<const N: usize>(
        frame_bytes: usize,
        body: &'a mut [u8],
        coverage: &'a mut [u8],
    ) -> Result<[Self; N], Error> {
        if N == 0 || !(HEADER_LEN..=usize::from(u16::MAX)).contains(&frame_bytes) {
            return Err(Error::InvalidInput);
        }
        let coverage_bytes = frame_bytes.div_ceil(8);
        let mut body = body
            .get_mut(..N.checked_mul(frame_bytes).ok_or(Error::Overflow)?)
            .ok_or(Error::Capacity)?;
        let mut coverage = coverage
            .get_mut(..N.checked_mul(coverage_bytes).ok_or(Error::Overflow)?)
            .ok_or(Error::Capacity)?;
        Ok(core::array::from_fn(|_| {
            let (lane_body, remaining_body) = core::mem::take(&mut body).split_at_mut(frame_bytes);
            let (lane_coverage, remaining_coverage) =
                core::mem::take(&mut coverage).split_at_mut(coverage_bytes);
            body = remaining_body;
            coverage = remaining_coverage;
            Self {
                body: lane_body,
                coverage: lane_coverage,
            }
        }))
    }
}

/// Bounded concurrent reassembly and one ACK FIFO for the original carrier.
pub struct Reassembly<'storage, const N: usize> {
    lanes: [FragmentLane<'storage>; N],
    max_payload: usize,
    slots: [Slot; N],
    retired: [Option<Retired>; N],
    ready: [usize; N],
    ready_len: usize,
    acks: Acks,
}

impl<const N: usize> fmt::Debug for Reassembly<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reassembly")
            .field("lanes", &N)
            .field("max_payload", &self.max_payload)
            .field("ready_count", &self.ready_len)
            .field("expiry", &self.expiry())
            .field("ack_count", &self.acks.len)
            .finish_non_exhaustive()
    }
}

impl<'storage, const N: usize> Reassembly<'storage, N> {
    /// Borrow separately sized lanes, with at least one covering the link's
    /// complete frame limit.
    pub fn new(max_payload: usize, lanes: [FragmentLane<'storage>; N]) -> Result<Self, Error> {
        if N == 0 || !(HEADER_LEN..=usize::from(u16::MAX)).contains(&max_payload) {
            return Err(Error::InvalidInput);
        }
        if !lanes.iter().any(|lane| lane.body.len() >= max_payload) {
            return Err(Error::Capacity);
        }
        Ok(Self {
            lanes,
            max_payload,
            slots: [Slot::Empty; N],
            retired: [None; N],
            ready: [0; N],
            ready_len: 0,
            acks: Acks::new(),
        })
    }

    /// Admit bytes and their original attempt receipt at a monotonic instant.
    ///
    /// Matching overlap extends coverage only for genuinely new bytes. A
    /// duplicate can produce a new transmission ACK while the exact bytes are
    /// retained. Once its lane is reused, one of `N` recent retired IDs still
    /// prevents another delivery. `accept` checks the just-completed frame
    /// once, before it becomes available to its consumer or queues the final
    /// receipt.
    ///
    /// # Errors
    /// `Capacity` rejects a competing message when all lanes are still live,
    /// so the carrier can continue reading the existing originals. Receipt
    /// overflow retires the oldest advisory ACK after accepting the new bytes.
    /// Excess size, ambiguous overlap, stale IDs and invalid completed frames
    /// are rejected without queuing their attempt IDs.
    pub fn receive(
        &mut self,
        now: MonoInstant,
        fragment: Fragment<'_>,
        accept: impl FnOnce(Frame<'_>, &[u8]) -> Result<(), Error>,
    ) -> Result<Receive, Error> {
        let start = usize::from(fragment.offset);
        let stop = start
            .checked_add(fragment.body.len())
            .ok_or(Error::Overflow)?;
        let total = usize::from(fragment.total);
        if total < HEADER_LEN || start == stop || stop > total {
            return Err(Error::Malformed);
        }
        if total > self.max_payload {
            return Err(Error::TooLarge);
        }
        self.expire(now);
        if self
            .retired
            .iter()
            .flatten()
            .any(|old| old.id == fragment.message_id)
        {
            return Err(Error::Replay);
        }
        let index = match self.slots.iter().position(|slot| {
            slot.original()
                .is_some_and(|old| old.id == fragment.message_id)
        }) {
            Some(index) => index,
            None => self.begin(now, fragment.message_id, total)?,
        };
        let original = self.slots[index].original().ok_or(Error::Conflict)?;
        if original.total != total {
            return Err(Error::Malformed);
        }
        let missing = match self.slots[index] {
            Slot::Assembling { missing, .. } => missing,
            _ => 0,
        };
        let added = self.insert(index, start, fragment.body)?;
        let remaining = missing - added;
        let progress = if added == 0 {
            Receive::Duplicate
        } else if remaining > 0 {
            self.slots[index] = Slot::Assembling {
                original,
                missing: remaining,
            };
            Receive::Partial
        } else {
            if let Err(error) = self.complete(index, original, now, accept) {
                self.clear_body(index);
                return Err(error);
            }
            Receive::Complete
        };
        self.acks.push(PendingAck {
            id: fragment.ack,
            received: now,
        });
        Ok(progress)
    }

    /// Borrow the next frame in completion order until the consumer releases it.
    #[must_use]
    pub fn frame(&self) -> Option<&[u8]> {
        if self.ready_len == 0 {
            return None;
        }
        let index = self.ready[0];
        match self.slots[index] {
            Slot::Complete(original) => Some(self.frame_bytes(index, original.total)),
            _ => None,
        }
    }

    /// Release the oldest completed frame. Until expiry or replacement, its
    /// bytes are retained privately so late retransmissions can be checked.
    pub fn clear_completed(&mut self) {
        if self.ready_len == 0 {
            return;
        }
        let index = self.ready[0];
        if let Slot::Complete(original) = self.slots[index] {
            self.slots[index] = Slot::Retained(original);
        }
        self.ready[..self.ready_len].rotate_left(1);
        self.ready_len -= 1;
    }

    /// Next expiry of incomplete input or the recent duplicate window.
    /// Originals awaiting their consumer are held until release or retirement.
    #[must_use]
    pub fn expiry(&self) -> Option<MonoInstant> {
        let live = self.slots.iter().filter_map(|slot| match slot {
            Slot::Assembling { original, .. } | Slot::Retained(original) => Some(original.expires),
            _ => None,
        });
        live.chain(
            self.retired
                .iter()
                .flatten()
                .map(|original| original.expires),
        )
        .min()
    }

    /// Release expired incomplete or retired originals and age out their ACKs.
    /// Completed frames currently awaiting delivery keep their ownership.
    pub fn expire(&mut self, now: MonoInstant) -> bool {
        let mut expired = false;
        for index in 0..N {
            if matches!(self.slots[index], Slot::Assembling { original, .. } | Slot::Retained(original) if original.expires <= now)
            {
                self.clear_body(index);
                expired = true;
            }
        }
        for retired in &mut self.retired {
            if retired.is_some_and(|original| original.expires <= now) {
                *retired = None;
                expired = true;
            }
        }
        self.acks.expire(now);
        expired
    }

    /// Pending receipts are immediately eligible for cumulative ACK admission.
    #[must_use]
    pub fn ack_deadline(&self) -> Option<MonoInstant> {
        self.acks.front().map(|pending| pending.received)
    }

    /// Offer at most one cumulative ACK containing as many pending original
    /// receipts as fit. Each entry's delay is measured from actual receipt.
    ///
    /// # Errors
    /// A too-small scratch buffer or failed carrier admission leaves the
    /// offered receipts and counter pending. An empty FIFO returns `Ok(None)`.
    pub fn poll_ack<T>(
        &mut self,
        now: MonoInstant,
        scratch: &mut [u8],
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        self.acks.expire(now);
        if self.acks.len == 0 {
            return Ok(None);
        }
        let count = self
            .acks
            .len
            .min(scratch.len().saturating_sub(ACK_HEADER_LEN) / ACK_ENTRY_LEN);
        if count == 0 {
            return Err(Error::Capacity);
        }
        let mut entries = [(0, [0; 16]); ACK_CAPACITY];
        for (offset, entry) in entries[..count].iter_mut().enumerate() {
            let pending = self.acks.entries[self.acks.index(offset)];
            *entry = (now.0.saturating_sub(pending.received.0), pending.id);
        }
        let counter = self.acks.counter.wrapping_add(count as u32);
        let size = encode_acknowledgements(counter, &entries[..count], scratch)?;
        let admitted = admit(&scratch[..size])?;
        self.acks.remove(count);
        self.acks.counter = counter;
        Ok(Some(admitted))
    }

    /// Retire all receive state and erase the borrowed buffers' used extents.
    pub fn clear(&mut self) {
        for index in 0..N {
            self.clear_body(index);
        }
        self.retired.fill(None);
        self.ready_len = 0;
        self.acks.head = 0;
        self.acks.len = 0;
    }

    fn begin(&mut self, now: MonoInstant, id: [u8; 8], total: usize) -> Result<usize, Error> {
        let index = self
            .slots
            .iter()
            .zip(&self.lanes)
            .enumerate()
            .filter(|(_, (_, lane))| total <= lane.body.len())
            .filter_map(|(index, (slot, lane))| {
                let (retained, expires) = match slot {
                    Slot::Empty => (false, MonoInstant(0)),
                    Slot::Retained(original) => (true, original.expires),
                    _ => return None,
                };
                Some((lane.body.len(), retained, expires, index))
            })
            .min()
            .map(|(_, _, _, index)| index)
            .ok_or(Error::Capacity)?;
        let original = Original {
            id,
            total,
            expires: now.after(REASSEMBLY_LIFETIME)?,
        };
        if let Slot::Retained(previous) = self.slots[index] {
            self.remember(previous);
            self.clear_body(index);
        }
        self.lanes[index].coverage[..total.div_ceil(8)].fill(0);
        self.slots[index] = Slot::Assembling {
            original,
            missing: total,
        };
        Ok(index)
    }

    fn insert(&mut self, index: usize, start: usize, bytes: &[u8]) -> Result<usize, Error> {
        let FragmentLane { body, coverage } = &mut self.lanes[index];
        for (offset, &byte) in (start..).zip(bytes) {
            let bit = 1 << (offset % 8);
            if coverage[offset / 8] & bit != 0 && body[offset] != byte {
                return Err(Error::Malformed);
            }
        }
        let mut added = 0;
        for (offset, &byte) in (start..).zip(bytes) {
            let seen = &mut coverage[offset / 8];
            let bit = 1 << (offset % 8);
            if *seen & bit == 0 {
                body[offset] = byte;
                *seen |= bit;
                added += 1;
            }
        }
        Ok(added)
    }

    fn complete(
        &mut self,
        index: usize,
        mut original: Original,
        now: MonoInstant,
        accept: impl FnOnce(Frame<'_>, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let bytes = self.frame_bytes(index, original.total);
        let frame = Frame::decode(bytes)?;
        if matches!(
            frame.header().message_type(),
            mt::TRANSPORT_FRAGMENT | mt::TRANSPORT_RELIABILITY_BOX
        ) {
            return Err(Error::Unsupported);
        }
        original.expires = now.after(REASSEMBLY_LIFETIME)?;
        accept(frame, bytes)?;
        self.slots[index] = Slot::Complete(original);
        self.ready[self.ready_len] = index;
        self.ready_len += 1;
        Ok(())
    }

    fn remember(&mut self, original: Original) {
        if let Some(retired) = self
            .retired
            .iter_mut()
            .min_by_key(|entry| entry.as_ref().map(|retired| retired.expires))
        {
            *retired = Some(Retired {
                id: original.id,
                expires: original.expires,
            });
        }
    }

    fn frame_bytes(&self, index: usize, total: usize) -> &[u8] {
        &self.lanes[index].body[..total]
    }

    fn clear_body(&mut self, index: usize) {
        if let Some(original) = self.slots[index].original() {
            let lane = &mut self.lanes[index];
            lane.body[..original.total].zeroize();
            lane.coverage[..original.total.div_ceil(8)].fill(0);
        }
        self.slots[index] = Slot::Empty;
    }
}

impl<const N: usize> Drop for Reassembly<'_, N> {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy)]
struct PendingAck {
    received: MonoInstant,
    id: [u8; 16],
}

impl PendingAck {
    const EMPTY: Self = Self {
        received: MonoInstant(0),
        id: [0; 16],
    };
}

struct Acks {
    entries: [PendingAck; ACK_CAPACITY],
    head: usize,
    len: usize,
    counter: u32,
}

impl Acks {
    const fn new() -> Self {
        Self {
            entries: [PendingAck::EMPTY; ACK_CAPACITY],
            head: 0,
            len: 0,
            counter: 0,
        }
    }

    fn index(&self, offset: usize) -> usize {
        (self.head + offset) % ACK_CAPACITY
    }

    fn front(&self) -> Option<PendingAck> {
        (self.len != 0).then(|| self.entries[self.head])
    }

    fn push(&mut self, pending: PendingAck) {
        if self.len == ACK_CAPACITY {
            self.remove(1);
        }
        let tail = self.index(self.len);
        self.entries[tail] = pending;
        self.len += 1;
    }

    fn remove(&mut self, count: usize) {
        self.head = self.index(count);
        self.len -= count;
    }

    fn expire(&mut self, now: MonoInstant) {
        while self.front().is_some_and(|pending| {
            now.0.saturating_sub(pending.received.0) >= REASSEMBLY_LIFETIME.0
        }) {
            self.remove(1);
        }
    }
}

#[cfg(test)]
mod tests;
