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
/// Original member identity shared by key evidence and prepared PRIVATE work.
#[derive(Clone, Copy)]
pub(crate) struct MemberRecipient {
    owner: Owner,
    public: PublicKey,
}

impl MemberRecipient {
    pub(crate) const fn new(owner: Owner, public: PublicKey) -> Self {
        Self { owner, public }
    }
}

#[derive(Clone, Copy)]
enum Fact {
    Member(MemberRecipient),
    Zone { public: PublicKey, hpke: [u8; 32] },
    Transcript { public: PublicKey },
    Ambiguous,
}
/// Original recipient identity/evidence snapshot. A historical zone record may
/// have no corresponding authenticated member yet; that is explicitly distinct
/// from a resolved Contact and never substitutes the current selected identity.
#[derive(Clone, Copy)]
pub struct RecipientAttribution {
    fact: Fact,
}
impl core::fmt::Debug for RecipientAttribution {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecipientAttribution([REDACTED])")
            .field("evidence", &self.evidence())
            .finish()
    }
}
impl RecipientAttribution {
    pub(crate) const fn member(member: MemberRecipient) -> Self {
        Self {
            fact: Fact::Member(member),
        }
    }
    pub(crate) fn transcript(public: PublicKey) -> Self {
        Self {
            fact: Fact::Transcript { public },
        }
    }
    pub(crate) fn from_key(key: &RecipientKey) -> Self {
        match key.origin {
            RecipientKeyOrigin::Member(member) => Self::member(member),
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
            Fact::Member(MemberRecipient { public, .. })
            | Fact::Zone { public, .. }
            | Fact::Transcript { public } => Some(public),
            Fact::Ambiguous => None,
        }
    }
    /// Original evidence class; a zone record is not a live member assertion.
    pub const fn evidence(&self) -> RecipientEvidence {
        match self.fact {
            Fact::Member(_) => RecipientEvidence::LocalMember,
            Fact::Zone { .. } => RecipientEvidence::RecoveredZone,
            Fact::Transcript { .. } => RecipientEvidence::OwnTranscript,
            Fact::Ambiguous => RecipientEvidence::AmbiguousKey,
        }
    }
    /// Original local member lineage/generation when that exact association was
    /// present at key retention or outgoing admission. Not a current capability.
    pub const fn member_lineage(&self) -> Option<(u64, u64)> {
        match self.fact {
            Fact::Member(MemberRecipient { owner, .. }) => Some((owner.lineage, owner.generation)),
            _ => None,
        }
    }
    pub(crate) fn contact_slot(&self, room: &RoomRow<'_>) -> Option<Slot> {
        match self.fact {
            Fact::Member(MemberRecipient { owner, .. }) => return Some(owner.contact),
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
                Fact::Member(_) | Fact::Ambiguous => false,
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
impl RecipientKey {
    /// A key reused across distinct real identities has no unique recipient in
    /// the PRIVATE ciphertext. Preserve decryption without guessing an owner.
    pub(crate) fn merge_origin(&mut self, incoming: RecipientKeyOrigin) {
        let next = match (self.origin, incoming) {
            (RecipientKeyOrigin::Member(member), RecipientKeyOrigin::Member(other))
                if member.owner.contact == other.owner.contact && member.public == other.public =>
            {
                return;
            }
            (RecipientKeyOrigin::Member(member), RecipientKeyOrigin::Zone(public))
                if member.public == public =>
            {
                return;
            }
            (RecipientKeyOrigin::Zone(public), RecipientKeyOrigin::Member(member))
                if member.public == public =>
            {
                RecipientKeyOrigin::Member(member)
            }
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
