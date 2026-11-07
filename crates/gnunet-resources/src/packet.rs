//! Owned packet backing, borrowed packet views and checked encapsulation.
use crate::queue::BoundedQueue;
use gnunet_types::Error;

/// Coarse resource selection; feature unification never changes an associated packet layout.
pub trait ResourceSet {
    /// Maximum active packet length. Inline and external backing are accounted separately.
    const PACKET_CAPACITY: usize;
    /// Maximum external backing a managed packet may retain, excluding its inline descriptor.
    /// Allocator bookkeeping and caller construction peaks require separate profile evidence.
    const MAX_EXTERNAL_PACKET_BYTES: usize;
    /// Owned packet transferred between state machine owners.
    type Packet: AsRef<[u8]>;
    /// Quote the actual external allocation retained by this immutable packet, not its payload
    /// length. Reject backing beyond this profile's declared maximum without changing ownership.
    /// The quote must stay valid while the packet is held without mutation by its protocol owner.
    fn packet_external_bytes(packet: &Self::Packet) -> Result<usize, Error>;
}

/// A no-allocator resource profile with fixed packet capacity.
#[derive(Debug, Default)]
pub struct FixedResources<const N: usize>;

impl<const N: usize> ResourceSet for FixedResources<N> {
    const PACKET_CAPACITY: usize = N;
    const MAX_EXTERNAL_PACKET_BYTES: usize = 0;
    type Packet = Frame<N>;
    fn packet_external_bytes(_packet: &Self::Packet) -> Result<usize, Error> {
        Ok(0)
    }
}

/// An explicitly bounded heap-backed host profile, available only when allocation is enabled.
#[cfg(feature = "alloc")]
#[derive(Debug, Default)]
pub struct HostResources<const N: usize>;

#[cfg(feature = "alloc")]
impl<const N: usize> ResourceSet for HostResources<N> {
    const PACKET_CAPACITY: usize = N;
    const MAX_EXTERNAL_PACKET_BYTES: usize = N;
    type Packet = HostPacket<N>;
    fn packet_external_bytes(packet: &Self::Packet) -> Result<usize, Error> {
        let capacity = packet.bytes.capacity();
        if packet.bytes.len() > N || capacity > N {
            return Err(Error::Capacity);
        }
        Ok(capacity)
    }
}

/// Owned host packet with bounded active length. Managed admission separately validates its actual
/// allocation capacity through `ResourceSet::packet_external_bytes`; allocator overhead is separate.
#[cfg(feature = "alloc")]
#[derive(Debug)]
#[must_use]
pub struct HostPacket<const N: usize> {
    bytes: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl<const N: usize> HostPacket<N> {
    /// Allocate at most one finite packet; allocation failure is reported as capacity backpressure.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > N {
            return Err(Error::Capacity);
        }
        let mut storage = alloc::vec::Vec::new();
        storage
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Capacity)?;
        storage.extend_from_slice(bytes);
        Ok(Self { bytes: storage })
    }

    /// Extend within the declared hard packet limit; failure preserves the active bytes.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::Overflow)?;
        if len > N {
            return Err(Error::Capacity);
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Capacity)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> AsRef<[u8]> for HostPacket<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// An exclusively owned fixed packet. Only its active range is exposed as protocol bytes.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Frame<const N: usize> {
    storage: [u8; N],
    start: usize,
    end: usize,
}

impl<const N: usize> Default for Frame<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Frame<N> {
    /// Create an empty frame without allocation or reserved headroom.
    pub const fn new() -> Self {
        Self {
            storage: [0; N],
            start: 0,
            end: 0,
        }
    }

    /// Create an empty frame with explicit headroom, preserving full physical capacity.
    pub fn with_headroom(headroom: usize) -> Result<Self, Error> {
        if headroom > N {
            return Err(Error::Capacity);
        }
        Ok(Self {
            storage: [0; N],
            start: headroom,
            end: headroom,
        })
    }

    /// Copy bytes into a new owned fixed packet, charging the caller for this copy.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut frame = Self::new();
        frame.append(bytes)?;
        Ok(frame)
    }

    /// Current immutable packet bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }

    /// Current mutable packet bytes; the caller has exclusive ownership.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.start..self.end]
    }

    /// Length of the active byte range.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether no active bytes exist.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Maximum physical storage size.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Unused bytes available before the current packet.
    #[must_use]
    pub const fn headroom(&self) -> usize {
        self.start
    }

    /// Unused bytes available after the current packet.
    #[must_use]
    pub const fn tailroom(&self) -> usize {
        N - self.end
    }

    /// Append in place. Failure leaves bytes and offsets unchanged.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.end.checked_add(bytes.len()).ok_or(Error::Overflow)?;
        let target = self.storage.get_mut(self.end..end).ok_or(Error::Capacity)?;
        target.copy_from_slice(bytes);
        self.end = end;
        Ok(())
    }

    /// Prepend in place using already reserved headroom. No hidden copy or reallocation occurs.
    pub fn prepend(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let start = self.start.checked_sub(bytes.len()).ok_or(Error::Capacity)?;
        self.storage[start..self.start].copy_from_slice(bytes);
        self.start = start;
        Ok(())
    }

    /// Retain a validated prefix; failure leaves the frame intact.
    pub fn truncate(&mut self, len: usize) -> Result<(), Error> {
        if len > self.len() {
            return Err(Error::InvalidInput);
        }
        self.end = self.start.checked_add(len).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Remove a prefix without copying, converting it into headroom.
    pub fn consume_prefix(&mut self, len: usize) -> Result<(), Error> {
        if len > self.len() {
            return Err(Error::Truncated);
        }
        self.start = self.start.checked_add(len).ok_or(Error::Overflow)?;
        Ok(())
    }
}

impl<const N: usize> AsRef<[u8]> for Frame<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A short exclusive view into externally owned storage, never a DMA ownership guarantee.
pub struct FrameMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> FrameMut<'a> {
    /// Borrow exclusive bytes for a single call's in-place processing.
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
    /// Borrow the active bytes immutably.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes
    }
    /// Borrow the active bytes exclusively.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes
    }
}

/// A non-owning immutable view that cannot extend a packet's lifetime.
pub type FrameView<'a> = &'a [u8];

/// Complete encapsulation arithmetic checked before moving bytes or consuming a device permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealPlan {
    /// Existing inner canonical bytes, which encapsulation must preserve unchanged.
    pub payload: usize,
    /// New outer header size.
    pub headroom: usize,
    /// New authentication tag or trailer size.
    pub tailroom: usize,
    /// Complete size after encapsulation.
    pub total: usize,
}

impl SealPlan {
    /// Check total encapsulation arithmetic without touching the payload or nonce state.
    pub fn new(payload: usize, headroom: usize, tailroom: usize) -> Result<Self, Error> {
        let total = payload
            .checked_add(headroom)
            .and_then(|size| size.checked_add(tailroom))
            .ok_or(Error::Overflow)?;
        Ok(Self {
            payload,
            headroom,
            tailroom,
            total,
        })
    }

    /// Require sufficient pre-reserved physical room; this never performs a hidden coalescing copy.
    pub fn check<const N: usize>(&self, frame: &Frame<N>) -> Result<(), Error> {
        if frame.len() != self.payload {
            return Err(Error::InvalidInput);
        }
        if frame.headroom() < self.headroom || frame.tailroom() < self.tailroom || self.total > N {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// A bounded scatter/gather view. Neither segment count nor byte total can grow implicitly.
pub struct PacketChain<'a, const N: usize> {
    segments: BoundedQueue<&'a [u8], N>,
    len: usize,
}

impl<'a, const N: usize> Default for PacketChain<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, const N: usize> PacketChain<'a, N> {
    /// Create an empty finite segment list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            segments: BoundedQueue::new(),
            len: 0,
        }
    }
    /// Add a borrowed segment after checking both byte arithmetic and segment capacity.
    pub fn push(&mut self, bytes: &'a [u8]) -> Result<(), Error> {
        let len = self.len.checked_add(bytes.len()).ok_or(Error::Overflow)?;
        self.segments
            .try_push(bytes)
            .map_err(|rejected| rejected.reason)?;
        self.len = len;
        Ok(())
    }
    /// Total bytes requiring transfer or explicit coalescing.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Whether no bytes are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Coalesce into a caller-provided destination after validating its full capacity.
    pub fn copy_into(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.len {
            return Err(Error::Capacity);
        }
        let mut offset = 0_usize;
        for segment in self.segments.iter() {
            let end = offset.checked_add(segment.len()).ok_or(Error::Overflow)?;
            output[offset..end].copy_from_slice(segment);
            offset = end;
        }
        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_packet_external_quote_is_zero_even_for_reserved_inline_capacity() -> Result<(), Error>
    {
        let empty = Frame::<0>::try_from_slice(b"")?;
        let reserved = Frame::<64>::new();
        let packet = Frame::<64>::try_from_slice(b"x")?;
        if FixedResources::<0>::MAX_EXTERNAL_PACKET_BYTES != 0
            || FixedResources::<64>::MAX_EXTERNAL_PACKET_BYTES != 0
            || FixedResources::<0>::packet_external_bytes(&empty)? != 0
            || FixedResources::<64>::packet_external_bytes(&reserved)? != 0
            || FixedResources::<64>::packet_external_bytes(&packet)? != 0
            || reserved.capacity() != 64
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn host_external_quote_charges_capacity_of_zero_or_short_payload() -> Result<(), Error> {
        let empty = HostPacket::<0>::try_from_slice(b"")?;
        if HostResources::<0>::MAX_EXTERNAL_PACKET_BYTES != 0
            || HostResources::<0>::packet_external_bytes(&empty)? != 0
        {
            return Err(Error::Conflict);
        }
        // The deliberately large type-level ceiling does not allocate that ceiling. Reserve one
        // small actual Vec, so this oracle does not assume the allocator returns an exact capacity.
        let mut bytes = alloc::vec::Vec::new();
        bytes.try_reserve_exact(32).map_err(|_| Error::Capacity)?;
        let mut packet = HostPacket::<{ usize::MAX }> { bytes };
        let capacity = packet.bytes.capacity();
        if capacity < 32
            || !packet.as_ref().is_empty()
            || HostResources::<{ usize::MAX }>::packet_external_bytes(&packet)? != capacity
        {
            return Err(Error::Conflict);
        }
        packet.append(b"x")?;
        if packet.as_ref() != b"x"
            || packet.bytes.capacity() != capacity
            || HostResources::<{ usize::MAX }>::packet_external_bytes(&packet)? != capacity
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn host_quote_rejects_oversized_backing_or_active_length_without_taking_packet()
    -> Result<(), Error> {
        let mut bytes = alloc::vec::Vec::new();
        bytes.try_reserve_exact(32).map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(b"x");
        let packet = HostPacket::<4> { bytes };
        let capacity = packet.bytes.capacity();
        if HostResources::<4>::MAX_EXTERNAL_PACKET_BYTES != 4
            || HostResources::<4>::packet_external_bytes(&packet) != Err(Error::Capacity)
            || packet.as_ref() != b"x"
            || packet.bytes.capacity() != capacity
        {
            return Err(Error::Conflict);
        }
        // Private malformed fixture: public constructors already reject active length > N.
        let oversized = HostPacket::<0> {
            bytes: alloc::vec![1],
        };
        if HostResources::<0>::packet_external_bytes(&oversized) != Err(Error::Capacity)
            || oversized.as_ref() != [1]
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn host_length_refusal_preserves_existing_packet_and_quote() -> Result<(), Error> {
        if HostPacket::<0>::try_from_slice(b"x").is_ok()
            || HostPacket::<4>::try_from_slice(b"12345").is_ok()
        {
            return Err(Error::Conflict);
        }
        let mut packet = HostPacket::<4>::try_from_slice(b"ab")?;
        packet.append(b"cd")?;
        let capacity = packet.bytes.capacity();
        let quote = HostResources::<4>::packet_external_bytes(&packet);
        let expected = if capacity <= 4 {
            Ok(capacity)
        } else {
            Err(Error::Capacity)
        };
        if quote != expected
            || packet.append(b"e") != Err(Error::Capacity)
            || packet.as_ref() != b"abcd"
            || packet.bytes.capacity() != capacity
            || HostResources::<4>::packet_external_bytes(&packet) != quote
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    #[test]
    fn encapsulation_failure_preserves_inner_packet() -> Result<(), Error> {
        let mut frame = Frame::<8>::with_headroom(2)?;
        frame.append(b"data")?;
        let plan = SealPlan::new(4, 3, 1)?;
        if plan.check(&frame) != Err(Error::Capacity)
            || frame.prepend(b"123").is_ok()
            || frame.as_slice() != b"data"
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
