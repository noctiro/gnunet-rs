use crate::{Error, MAX_ROWS};
use alloc::vec::Vec;
use core::{cell::Cell, mem::size_of};
use gnunet_paillier::Limits as PrimitiveLimits;
use gnunet_types::Error as CoreError;
use gnunet_wire::official::{cadet::MAX_APPLICATION_MESSAGE_SIZE, scalarproduct::PeerMessage};
use zeroize::Zeroize;

/// Explicit finite per-original-session resources and work policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual original private vector rows, maximum2^20.
    pub max_rows: usize,
    /// Actual allocation capacities, fixed session state and reported native
    /// buffers; not a promise that all independent maxima fit simultaneously.
    pub max_retained_bytes: usize,
    /// Maximum encoded peer frame, from1040 to the actual CADET64348-byte cap.
    pub frame_bytes: usize,
    /// One original lifetime across setup, SETI, crypto, output and loss.
    pub lifetime_micros: u64,
    /// Real primitive candidate/entropy/advance limits, without implicit RNG.
    pub primitive: PrimitiveLimits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 65536,
            max_retained_bytes: 64 * 1024 * 1024,
            frame_bytes: MAX_APPLICATION_MESSAGE_SIZE,
            lifetime_micros: 300_000_000,
            primitive: PrimitiveLimits::default(),
        }
    }
}
impl Limits {
    /// Fail configuration before any key, channel or entropy acquisition.
    pub fn validate(self) -> Result<(), Error> {
        self.primitive.validate()?;
        if self.max_rows == 0
            || self.max_rows > MAX_ROWS
            || self.frame_bytes < 8 + 2 * 516
            || self.frame_bytes > MAX_APPLICATION_MESSAGE_SIZE
            || self.max_retained_bytes == 0
            || self.max_retained_bytes > 1usize << 31
            || self.lifetime_micros == 0
            || self.lifetime_micros > 86_400_000_000
        {
            return Err(CoreError::InvalidInput.into());
        }
        Ok(())
    }
    pub(crate) fn ciphers(self) -> usize {
        (self.frame_bytes - 8) / 516
    }
    pub(crate) fn bob_pairs(self, first: bool) -> usize {
        (self.ciphers() - if first { 2 } else { 0 }) / 2
    }
    pub(crate) fn units(self, units: u16) -> Result<usize, Error> {
        if units == 0 || units > self.primitive.units_per_turn {
            return Err(CoreError::InvalidInput.into());
        }
        Ok(usize::from(units))
    }
}

/// A caller-owned stable domain. Every new session consumes a non-reused
/// generation; recreating the same wire session hash does not revive old tokens.
#[derive(Debug, Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// New local domain; no random identity or wire data is generated.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    pub(crate) fn allocate(&self) -> Result<u64, Error> {
        let next = self.next.get().checked_add(1).ok_or(CoreError::Overflow)?;
        self.next.set(next);
        Ok(next)
    }
}
/// Original retained output identity. Only its actual original native owner
/// may report its whole write, loss or absence of exposure.
#[derive(Clone, Copy, Debug)]
pub struct OutputId<'id> {
    instance: &'id Instance,
    generation: u64,
    serial: u64,
}
impl PartialEq for OutputId<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.instance, other.instance)
            && self.generation == other.generation
            && self.serial == other.serial
    }
}
impl Eq for OutputId<'_> {}

/// Original native/SETI callback owner. Reusing the same wire session hash does
/// not permit an old channel, subscription or callback to enter a new session.
#[derive(Clone, Copy, Debug)]
pub struct Binding<'id> {
    instance: &'id Instance,
    generation: u64,
}
impl PartialEq for Binding<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.instance, other.instance) && self.generation == other.generation
    }
}
impl Eq for Binding<'_> {}

/// Actual original native output disposition. Written is a local whole-frame
/// handoff, never a peer computation or durable/publication acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// Every original frame byte was given to the original native MQ.
    Written,
    /// No original byte was exposed, with the exact pure classification.
    Unsent(Error),
    /// Original partial/unknown exposure or original source loss.
    Lost(Error),
}
/// One actual admitted frame allocation, counted until its original terminal.
/// Additional native copies must be charged through the session external budget.
pub struct Frame<'id> {
    id: OutputId<'id>,
    bytes: Vec<u8>,
}
impl<'id> Frame<'id> {
    /// Original effect identity, stable across native partial writes.
    #[must_use]
    pub const fn id(&self) -> OutputId<'id> {
        self.id
    }
    /// Complete immutable official frame, not a replacement on reconnect.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for Frame<'_> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Completion was rejected before the original retained owner was consumed.
/// The native caller can recover its exact frame for original-source cleanup.
pub struct RejectedFrame<'id> {
    error: Error,
    frame: Frame<'id>,
}
impl<'id> RejectedFrame<'id> {
    pub(crate) fn new(error: Error, frame: Frame<'id>) -> Self {
        Self { error, frame }
    }
    /// Exact refusal, without pretending the real IO disposition was undone.
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }
    /// Recover the same original allocation and identity; no new intent is made.
    #[must_use]
    pub fn into_frame(self) -> Frame<'id> {
        self.frame
    }
}
impl core::fmt::Debug for RejectedFrame<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RejectedFrame")
            .field("error", &self.error)
            .field("id", &self.frame.id)
            .finish_non_exhaustive()
    }
}
impl core::fmt::Display for RejectedFrame<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.error, f)
    }
}
impl core::error::Error for RejectedFrame<'_> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Introduction,
    Alice(usize),
    Bob {
        first: bool,
        count: usize,
        last: bool,
    },
}
pub(crate) struct Outbox<'id> {
    instance: &'id Instance,
    generation: u64,
    serial: u64,
    kind: Option<Kind>,
    prepared: Vec<u8>,
    capacity: usize,
    admitted: bool,
}
impl<'id> Outbox<'id> {
    pub(crate) fn new(instance: &'id Instance) -> Result<Self, Error> {
        Ok(Self {
            instance,
            generation: instance.allocate()?,
            serial: 0,
            kind: None,
            prepared: Vec::new(),
            capacity: 0,
            admitted: false,
        })
    }
    pub(crate) fn queue(
        &mut self,
        message: PeerMessage<'_>,
        kind: Kind,
        budget: usize,
        limit: usize,
    ) -> Result<(), Error> {
        if self.kind.is_some() {
            return Err(CoreError::WouldBlock.into());
        }
        let length = message.encoded_len()?;
        if length > limit || length > budget {
            return Err(CoreError::Capacity.into());
        }
        let serial = self.serial.checked_add(1).ok_or(CoreError::Overflow)?;
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(length)
            .map_err(|_| CoreError::Capacity)?;
        if prepared.capacity() > budget {
            return Err(CoreError::Capacity.into());
        }
        prepared.resize(length, 0);
        message.encode(&mut prepared)?;
        self.capacity = prepared.capacity();
        self.prepared = prepared;
        self.serial = serial;
        self.kind = Some(kind);
        Ok(())
    }
    pub(crate) fn output(&self) -> Option<OutputId<'id>> {
        if self.kind.is_none() || self.admitted {
            None
        } else {
            Some(self.id())
        }
    }
    pub(crate) fn binding(&self) -> Binding<'id> {
        Binding {
            instance: self.instance,
            generation: self.generation,
        }
    }
    pub(crate) fn validate_binding(&self, binding: Binding<'id>) -> Result<(), Error> {
        if binding == self.binding() {
            Ok(())
        } else {
            Err(Error::Finished)
        }
    }
    fn id(&self) -> OutputId<'id> {
        OutputId {
            instance: self.instance,
            generation: self.generation,
            serial: self.serial,
        }
    }
    pub(crate) fn admit(&mut self, id: OutputId<'id>) -> Result<Frame<'id>, Error> {
        if self.output() != Some(id) {
            return Err(Error::Finished);
        }
        self.admitted = true;
        Ok(Frame {
            id,
            bytes: core::mem::take(&mut self.prepared),
        })
    }
    pub(crate) fn check(&self, id: OutputId<'id>) -> Result<Kind, Error> {
        if !self.admitted || self.id() != id {
            return Err(Error::Finished);
        }
        self.kind.ok_or(Error::Finished)
    }
    pub(crate) fn complete(&mut self, id: OutputId<'id>) -> Result<Kind, Error> {
        let kind = self.check(id)?;
        self.kind = None;
        self.admitted = false;
        self.capacity = 0;
        Ok(kind)
    }
    pub(crate) fn clear_unadmitted(&mut self) {
        if !self.admitted {
            self.prepared.zeroize();
            self.prepared = Vec::new();
            self.capacity = 0;
            self.kind = None;
        }
    }
    pub(crate) fn bytes(&self) -> usize {
        self.capacity
    }
    pub(crate) fn busy(&self) -> bool {
        self.kind.is_some()
    }
    pub(crate) fn admitted(&self) -> bool {
        self.admitted
    }
}
impl Drop for Outbox<'_> {
    fn drop(&mut self) {
        self.prepared.zeroize();
    }
}

pub(crate) fn reserve<T>(count: usize, budget: usize) -> Result<Vec<T>, Error> {
    if count
        .checked_mul(size_of::<T>())
        .ok_or(CoreError::Overflow)?
        > budget
    {
        return Err(CoreError::Capacity.into());
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| CoreError::Capacity)?;
    if bytes(&values)? > budget {
        return Err(CoreError::Capacity.into());
    }
    Ok(values)
}
pub(crate) fn bytes<T>(values: &Vec<T>) -> Result<usize, Error> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or_else(|| CoreError::Overflow.into())
}
pub(crate) fn sum(values: &[usize]) -> Result<usize, Error> {
    values.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .ok_or_else(|| CoreError::Overflow.into())
    })
}
pub(crate) fn available(total: usize, limit: usize) -> Result<usize, Error> {
    limit
        .checked_sub(total)
        .ok_or_else(|| CoreError::Capacity.into())
}
pub(crate) struct Clock {
    last: u64,
    deadline: u64,
}
impl Clock {
    pub(crate) fn new(now: u64, lifetime: u64) -> Result<Self, Error> {
        Ok(Self {
            last: now,
            deadline: now.checked_add(lifetime).ok_or(CoreError::Overflow)?,
        })
    }
    pub(crate) fn observe(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last {
            return Err(Error::Clock);
        }
        self.last = now;
        if now >= self.deadline {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    pub(crate) fn deadline(&self) -> u64 {
        self.deadline
    }
}
