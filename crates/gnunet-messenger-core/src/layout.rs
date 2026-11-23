//! Explicit original producer layout, independent from the current relay.
use crate::{Error, PublicKey, wire};
use gnunet_types::Error as Fault;
use wire::profile::Profile;
/// Actual configured original signing principal. The declaration is checked
/// against real signature admission; by itself it grants no source authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OriginalSigner {
    /// Ordinary member's exact tagged public key.
    Member(PublicKey),
    /// Original peer control signer, independent from a forwarding peer.
    Peer([u8; 32]),
}
impl core::fmt::Debug for OriginalSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OriginalSigner([REDACTED])")
    }
}
/// Original signed-body grammar: explicit producer fields, or the proven
/// profile-independent non-FILE wire grammar used for opaque SERVICE forwarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyLayout {
    /// Original producer profile explicitly configured/retained for this signer/hash.
    Explicit(Profile),
    /// All typed fields are network-order/opaque and no FILE NAME_MAX is present.
    /// This does not claim knowledge of the original machine's native byte order.
    Portable,
}
/// Explicit signed-body versus this envelope's padding encoder profiles.
/// Both must originate in a configured/retained producer policy, never Detect
/// inference or the claim that every relay socket originated every message.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OriginalLayout {
    /// Original signed-body producer layout.
    pub body: BodyLayout,
    /// Encoder of this unsigned outer padding, possibly a later relay.
    pub padding: Profile,
    /// Optional expected original signer, validated after actual cryptography.
    pub signer: Option<OriginalSigner>,
}
impl core::fmt::Debug for OriginalLayout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OriginalLayout")
            .field("body", &self.body)
            .field("padding", &self.padding)
            .field("signer_declared", &self.signer.is_some())
            .finish()
    }
}
impl OriginalLayout {
    /// Existing caller's explicit same-producer profile. No discovery/guess occurs.
    pub const fn same(profile: Profile) -> Self {
        Self {
            body: BodyLayout::Explicit(profile),
            padding: profile,
            signer: None,
        }
    }
    pub(crate) fn validate(self) -> Result<(), Error> {
        if let BodyLayout::Explicit(profile) = self.body {
            profile.validate()?;
        }
        self.padding.validate()?;
        if let Some(OriginalSigner::Member(public)) = self.signer {
            wire::PublicKey::new(&public)?;
        }
        Ok(())
    }
    /// Resolve only a declared grammar, never infer original layout from bytes.
    pub fn body_profile(self, kind: wire::envelope::Kind) -> Result<Profile, Error> {
        match self.body {
            BodyLayout::Explicit(profile) => {
                profile.validate()?;
                Ok(profile)
            }
            BodyLayout::Portable if kind != wire::envelope::Kind::FILE && kind.is_known() => {
                Ok(Profile::LITTLE_255)
            }
            BodyLayout::Portable => Err(Fault::Unavailable.into()),
        }
    }
    pub(crate) fn check_signer(
        self,
        public: PublicKey,
        peer: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        match self.signer {
            None => Ok(()),
            Some(OriginalSigner::Member(expected)) if expected == public && peer.is_none() => {
                Ok(())
            }
            Some(OriginalSigner::Peer(expected)) if peer == Some(expected) => Ok(()),
            _ => Err(Fault::Authentication.into()),
        }
    }
}
