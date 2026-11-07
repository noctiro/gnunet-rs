//! Immutable recipient facts, separate from signature/sender authorization.
use crate::{
    state::{Owner, RecipientKey, RecipientKeyOrigin, RoomRow},
    *,
};

/// Evidence for a private message's recipient. This never grants current
/// membership, sender attribution, signing or decryption authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientEvidence {
    /// The actual successful key was retained for an authenticated local member.
    LocalMember,
    /// The actual successful key came from an authorized private-zone record.
    RecoveredZone,
    /// An accepted own transcript recorded the original target identity.
    OwnTranscript,
    /// The same real encryption key was bound to distinct recipient identities.
    AmbiguousKey,
}
#[derive(Clone, Copy)]
enum Fact<'id> {
    Member {
        owner: Owner<'id>,
        public: PublicKey,
    },
    Zone {
        public: PublicKey,
        hpke: [u8; 32],
    },
    Transcript {
        public: PublicKey,
    },
    Ambiguous,
}
/// Original recipient identity/evidence snapshot. A historical zone record may
/// have no corresponding authenticated member yet; that is explicitly distinct
/// from a resolved Contact and never substitutes the current selected identity.
#[derive(Clone, Copy)]
pub struct RecipientAttribution<'id> {
    fact: Fact<'id>,
}
impl core::fmt::Debug for RecipientAttribution<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecipientAttribution([REDACTED])")
            .field("evidence", &self.evidence())
            .finish()
    }
}
impl<'id> RecipientAttribution<'id> {
    pub(crate) fn member(owner: Owner<'id>, public: PublicKey) -> Self {
        Self {
            fact: Fact::Member { owner, public },
        }
    }
    pub(crate) fn transcript(public: PublicKey) -> Self {
        Self {
            fact: Fact::Transcript { public },
        }
    }
    pub(crate) fn from_key(key: &RecipientKey<'id>) -> Self {
        match key.origin {
            RecipientKeyOrigin::Member { owner, public } => Self::member(owner, public),
            RecipientKeyOrigin::Zone(public) => Self {
                fact: Fact::Zone {
                    public,
                    hpke: *key.secret.public_key().as_bytes(),
                },
            },
            RecipientKeyOrigin::Ambiguous => Self {
                fact: Fact::Ambiguous,
            },
        }
    }
    /// Exact original typed recipient identity, retained across key rotation.
    /// Ambiguous reuse of the same encryption key yields no guessed identity.
    pub const fn public_key(&self) -> Option<&PublicKey> {
        match &self.fact {
            Fact::Member { public, .. }
            | Fact::Zone { public, .. }
            | Fact::Transcript { public } => Some(public),
            Fact::Ambiguous => None,
        }
    }
    /// Original evidence class; a zone record is not a live member assertion.
    pub const fn evidence(&self) -> RecipientEvidence {
        match self.fact {
            Fact::Member { .. } => RecipientEvidence::LocalMember,
            Fact::Zone { .. } => RecipientEvidence::RecoveredZone,
            Fact::Transcript { .. } => RecipientEvidence::OwnTranscript,
            Fact::Ambiguous => RecipientEvidence::AmbiguousKey,
        }
    }
    /// Original local member lineage/generation when that exact association was
    /// present at key retention or outgoing admission. Not a current capability.
    pub const fn member_lineage(&self) -> Option<(u64, u64)> {
        match self.fact {
            Fact::Member { owner, .. } => Some((owner.lineage, owner.generation)),
            _ => None,
        }
    }
    pub(crate) fn contact(&self, room: &RoomRow<'id>) -> Option<Contact<'id>> {
        match self.fact {
            Fact::Member { owner, .. } => return Some(owner.contact),
            Fact::Ambiguous => return None,
            _ => {}
        }
        let mut contact = None;
        for (_, session) in room.sessions.iter() {
            let matches = match self.fact {
                Fact::Zone { public, hpke } => {
                    session.public == public && session.hpke[4..] == hpke
                }
                Fact::Transcript { public } => session.public == public,
                Fact::Member { .. } | Fact::Ambiguous => false,
            };
            if !matches {
                continue;
            }
            if contact.is_some_and(|old| old != session.contact) {
                // Reused/anonymous keys without a unique original association
                // do not identify one Contact merely because bytes match.
                return None;
            }
            contact = Some(session.contact);
        }
        contact
    }
}
impl<'id> RecipientKey<'id> {
    /// A key reused across distinct real identities has no unique recipient in
    /// the PRIVATE ciphertext. Preserve decryption without guessing an owner.
    pub(crate) fn merge_origin(&mut self, incoming: RecipientKeyOrigin<'id>) {
        let next = match (self.origin, incoming) {
            (
                RecipientKeyOrigin::Member { owner, public },
                RecipientKeyOrigin::Member {
                    owner: other,
                    public: other_public,
                },
            ) if owner.contact == other.contact && public == other_public => return,
            (RecipientKeyOrigin::Member { public, .. }, RecipientKeyOrigin::Zone(other))
                if public == other =>
            {
                return;
            }
            (
                RecipientKeyOrigin::Zone(public),
                RecipientKeyOrigin::Member {
                    owner,
                    public: other,
                },
            ) if public == other => RecipientKeyOrigin::Member {
                owner,
                public: other,
            },
            (RecipientKeyOrigin::Zone(public), RecipientKeyOrigin::Zone(other))
                if public == other =>
            {
                return;
            }
            (RecipientKeyOrigin::Ambiguous, _) => return,
            _ => RecipientKeyOrigin::Ambiguous,
        };
        self.origin = next;
    }
}

#[cfg(test)]
mod tests;
