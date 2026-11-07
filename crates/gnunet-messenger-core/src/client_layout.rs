//! Explicit client plaintext and identifier provenance. Outer relay padding is
//! deliberately separate from authenticated short-message plaintext padding.
use crate::*;
/// Explicit original short-body and immutable short-padding encoders.
pub use wire::message::ShortProfiles as ShortLayout;
use wire::profile::{Endian, Profile};
/// Explicit original signed body, encrypted/transcript short and identifier
/// creator facts. None of these are inferred from the current service socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientLayout {
    /// Signed original body and outer padding provenance.
    pub original: OriginalLayout,
    /// Producer of an encrypted PRIVATE/SECRET or TRANSCRIPT short payload.
    pub plaintext: ShortLayout,
    /// Independently encoded unpadded short carried inside TRANSCRIPT. An own
    /// encrypted transcript envelope may differ from its recipient's payload.
    pub transcript: ShortLayout,
    /// Creator order for a newly introduced raw group identifier. Later users
    /// of an existing identifier inherit its retained order, not their own ABI.
    pub identifier_order: Option<Endian>,
}
impl ClientLayout {
    /// Explicit homogeneous producer contract, preserving the existing API's
    /// original one-profile choice. Mixed callers supply independent facts.
    pub const fn same(profile: Profile) -> Self {
        Self {
            original: OriginalLayout::same(profile),
            plaintext: ShortLayout::same(profile),
            transcript: ShortLayout::same(profile),
            identifier_order: Some(profile.endian),
        }
    }
    /// Validate declarations without asserting the signer, AEAD or key authority.
    pub fn validate(self) -> Result<(), Error> {
        self.original.validate()?;
        self.plaintext.validate()?;
        self.transcript.validate()?;
        Ok(())
    }
}
/// Exact key-record lookup target and independent raw identifier creator order.
/// This is parsing metadata, not a membership/key or storage-success proof.
#[derive(Clone, Copy)]
pub struct EpochRecordTarget {
    /// Actual original epoch capability hash.
    pub epoch: Hash,
    /// Exact original binary identifier, never byte-swapped for a recipient.
    pub identifier: ShortHash,
    /// Known creator of a brand-new identifier; None requires retained knowledge.
    pub identifier_order: Option<Endian>,
}
impl core::fmt::Debug for EpochRecordTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EpochRecordTarget([REDACTED])")
    }
}
impl<'id> Core<'id> {
    /// Exact attached source's original room generation. This read-only lookup
    /// never grants a source, binding or membership to a caller.
    pub fn source_room(&self, source: Source<'id>) -> Result<Room<'id>, Error> {
        self.check_source(source)?;
        Ok(self.event_room(source.room))
    }

    /// Retained actual raw identifier creator order, independent from any new
    /// sender's profile. Absence is not a claim of a default host order.
    pub fn group_identifier_order(
        &self,
        room: Room<'id>,
        id: &ShortHash,
    ) -> Result<Option<Endian>, Error> {
        self.known_identifier_order(self.check_room(room)?, id)
    }
}
