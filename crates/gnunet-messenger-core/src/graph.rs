//! Actual message links/frontier, owned history rights and resumable session
//! completion. Tombstones preserve links while encrypted/plain payload is erased.
use crate::{
    archive::{ArchiveOriginalRange, CommittedRoomHistory},
    room_history::{HistoryEntry, HistoryRead, HistorySnapshot},
    state::{FrameStore, Node, Owner, RoomRow, SessionRow},
    *,
};
use core::{fmt, num::NonZeroU64};
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind};
mod ancestry;
pub(crate) mod completion;
mod history_workspace;
#[cfg(feature = "alloc")]
pub(crate) mod synchronization;
pub(crate) use ancestry::has_signed_ancestor;
pub use history_workspace::{HistoryCell, HistoryWorkspace};
pub(crate) const fn epoch_kind(kind: Kind) -> bool {
    matches!(kind, Kind::JOIN | Kind::LEAVE | Kind::MERGE)
}
/// Original TALK/SUBSCRIPTION content is transient in the SERVICE store.
pub(crate) const fn discourse_kind(kind: Kind) -> bool {
    matches!(kind, Kind::TALK | Kind::SUBSCRIPTION)
}
pub(crate) const fn peer_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::INFO | Kind::PEER | Kind::MISS | Kind::MERGE | Kind::CONNECTION
    )
}
pub(crate) const fn session_bound(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::JOIN | Kind::LEAVE | Kind::NAME | Kind::KEY | Kind::ID
    )
}
pub(crate) fn owner(session: &SessionRow) -> Owner {
    Owner {
        contact: session.contact,
        lineage: session.lineage,
        generation: session.generation,
    }
}
pub(crate) fn owns(session: &SessionRow, node: &Node) -> bool {
    owns_author(session, node.auth.and_then(|auth| auth.owner))
}
pub(crate) fn owns_author(session: &SessionRow, author: Option<Owner>) -> bool {
    author.is_some_and(|o| {
        o.contact == session.contact
            && o.lineage == session.lineage
            && o.generation <= session.generation
    })
}
pub(crate) fn known(session: &SessionRow, node: &Node) -> bool {
    node.auth.is_some() && knows_sequence(session, node.sequence)
}
pub(crate) fn knows_sequence(session: &SessionRow, sequence: u64) -> bool {
    sequence >= session.known_from && session.completed_at.is_none_or(|until| sequence <= until)
}

impl<'id> RoomRow<'id> {
    /// Actual update frontier observation or bounded operation.
    pub fn update_frontier(&mut self, slot: Slot, mode: Mode) -> Result<(), Error> {
        let n = self.nodes.get(slot)?;
        let exclude = match mode {
            Mode::Service => n.requested,
            #[cfg(feature = "alloc")]
            Mode::Client => !n.frontier_recent,
        };
        if n.auth.is_none()
            || exclude
            || n.hash == [0; 64]
            || matches!(n.kind, Kind::INFO | Kind::REQUEST)
            || discourse_kind(n.kind)
            || n.discourse.is_some()
        {
            return Ok(());
        }
        let (parents, hash, epoch) = (n.parents, n.hash, n.epoch);
        let version = self
            .frontier_version
            .checked_add(1)
            .ok_or(Fault::Overflow)?;
        self.queues
            .frontier
            .retain(|h| *h != parents[0] && *h != parents[1] && *h != hash);

        self.queues.frontier.push(hash)?;
        // The outgoing predecessor and its carried epoch are one observation.
        // The first surviving frontier may be an older concurrent branch with
        // a different epoch; combining that predecessor with the latest key
        // snapshot produces valid signatures for undecryptable messages.
        self.last_message = hash;
        self.current_epoch = epoch;
        self.frontier_version = version;
        self.nodes.get_mut(slot)?.frontier_applied = true;
        Ok(())
    }
    /// Check the exact signed links. Any working observation shadows the page,
    /// including one still awaiting authentication.
    pub fn graph_complete(
        &self,
        slot: Slot,
        history: Option<&CommittedRoomHistory<'_, '_>>,
    ) -> Result<bool, Error> {
        let n = self.nodes.get(slot)?;
        if n.auth.is_none() {
            return Ok(false);
        }
        for hash in n.parents.iter().filter(|&hash| *hash != [0; 64]) {
            if hash == &n.hash {
                return Err(Fault::Malformed.into());
            }
            let complete = if let Some(parent) = self.find_node(hash) {
                let parent = self.nodes.get(parent)?;
                parent.auth.is_some() && parent.complete
            } else if let Some(history) = history {
                history.detached_parent(hash)?.is_some_and(|p| p.complete)
            } else {
                false
            };
            if !complete {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Actual queue node observation or bounded operation.
    pub fn queue_node(&mut self, slot: Slot) -> Result<(), Error> {
        let n = self.nodes.get_mut(slot)?;
        if n.queued
            // Settled archived nodes retain all graph facts. An epoch or
            // dependency observation cannot reopen their body application.
            || n.original_is_archived()
            || matches!(n.phase, MessagePhase::Rejected | MessagePhase::Deleted) && n.complete
        {
            return Ok(());
        }
        self.ready.push_back(slot)?;
        n.queued = true;
        Ok(())
    }
    /// Release the queue membership only when the exact slot is popped.
    pub fn take_ready(&mut self) -> Result<Option<Slot>, Error> {
        let Some(slot) = self.ready.pop_front() else {
            return Ok(None);
        };
        self.nodes.get_mut(slot)?.queued = false;
        Ok(Some(slot))
    }
    /// Actual queue dependants observation or bounded operation.
    pub fn queue_dependants(&mut self, hash: &Hash) -> Result<(), Error> {
        // Fixed slot scan, no recursive task chain or payload clone. Every row is
        // queued at most once; per-turn drain is independently bounded by Core.
        for index in 0..self.index.len() {
            let slot = self.index[index];
            let n = self.nodes.get(slot)?;
            if n.parents.contains(hash) || n.references.contains(hash) || n.epoch == *hash {
                self.queue_node(slot)?;
            }
        }
        for i in 0..self.sessions.limit() {
            if let Some(s) = self.sessions.slot_at(i)
                && self.sessions.get(s)?.needs_completion()
            {
                self.schedule_completion(s)?;
            }
        }
        Ok(())
    }
    /// Actual erase message observation or bounded operation.
    pub fn erase_message(
        &mut self,
        frames: &mut FrameStore<'id>,
        slot: Slot,
        by: Option<Hash>,
    ) -> Result<usize, Error> {
        let n = self.nodes.get(slot)?;
        if n.auth.is_none() {
            return Err(Fault::Authentication.into());
        }
        let transient = discourse_kind(n.kind);
        let hash = n.hash;
        n.original(frames)?;
        // Preflight/count consistency precedes erasure. Cluster repair neither
        // allocates nor drops another original first-write association.
        if transient {
            self.remove_alias(&hash)?;
        }
        let n = self.nodes.get_mut(slot)?;
        let bytes = n.payload_bytes();
        #[cfg(feature = "alloc")]
        {
            n.recipient = None;
        }
        if !transient && n.phase == MessagePhase::Deleted {
            return Ok(0);
        }
        if let Some(frame) = n.frame.take() {
            frames.remove(frame)?;
        }
        if transient {
            n.epoch = [0; 64];
            n.meta.epoch = [0; 64];
            n.meta.flags = 0;
            n.frontier_recent = false;
            n.meta.requested = false;
            n.meta.sender_hash = None;
            n.meta.context = None;
            n.discourse = None;
            n.delete_at = None;
            n.deleted_by = None;
            n.transcript = None;
            n.private_recipient = None;
            n.local_sent = false;
            n.requested = false;
            n.references = [[0; 64]; 3];
            n.cipher_layout = None;
            n.plain_layout = None;
            n.transcript_layout = None;
            n.identifier_order = None;
            n.frontier_applied = true;
        }
        #[cfg(feature = "alloc")]
        {
            n.plaintext = None;
        }
        n.phase = MessagePhase::Deleted;
        if !transient {
            n.deleted_by = by;
        }
        // Preserve original author/hash/parents/order for historical ancestry,
        // never payload or a live source reconstructed from an archive.
        n.semantic_applied = true;
        Ok(bytes)
    }
    /// Actual subscription covers observation or bounded operation.
    pub fn subscription_covers(&self, lineage: u64, discourse: &ShortHash, timestamp: u64) -> bool {
        self.subscriptions.iter().any(|(_, s)| {
            s.lineage == lineage
                && s.discourse == *discourse
                && s.start <= timestamp
                && timestamp <= s.end
        })
    }
    /// Actual discourse cutoff observation or bounded operation.
    pub fn discourse_cutoff(&self, discourse: &ShortHash) -> u64 {
        self.subscriptions
            .iter()
            .filter(|(_, s)| s.discourse == *discourse)
            .map(|(_, s)| s.start)
            .min()
            .unwrap_or(u64::MAX)
    }
}
/// One archived original selected by an authenticated SERVICE history read.
/// Its bytes are lent by the exact native checkpoint and grant no current
/// source, membership, or signing authority.
pub struct CommittedServiceOriginal<'archive> {
    pub(crate) hash: Hash,
    pub(crate) kind: Kind,
    pub(crate) layout: OriginalLayout,
    pub(crate) padding: wire::padding::Decode,
    pub(crate) bytes: &'archive [u8],
    pub(crate) generation: NonZeroU64,
}

impl<'archive> CommittedServiceOriginal<'archive> {
    /// Exact signed message hash.
    pub const fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Signed outer envelope kind.
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Admitted signed-body and outer-padding layouts.
    pub const fn layout(&self) -> OriginalLayout {
        self.layout
    }

    /// The original transport padding policy used for these bytes.
    pub const fn padding(&self) -> wire::padding::Decode {
        self.padding
    }

    /// Exact signed Messenger bytes, including stored outer padding.
    pub const fn bytes(&self) -> &'archive [u8] {
        self.bytes
    }

    /// The selected checkpoint generation, local to its original store.
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }
}

/// Immutable actual stored message. Debug and accessors never label it as a
/// newly verified sender, storage receipt or remote delivery confirmation.
pub struct MessageRef<'a, 'id> {
    row: &'a Node,
    #[cfg(feature = "alloc")]
    room: &'a RoomRow<'id>,
    original: Option<&'a [u8]>,
    brand: Brand<'id>,
}
impl fmt::Debug for MessageRef<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageRef([REDACTED])")
            .field("phase", &self.row.phase)
            .field("kind", &self.row.semantic_kind)
            .finish()
    }
}
impl<'a, 'id> MessageRef<'a, 'id> {
    pub(crate) fn new(
        row: &'a Node,
        #[cfg(feature = "alloc")] room: &'a RoomRow<'id>,
        #[cfg(not(feature = "alloc"))] _room: &'a RoomRow<'id>,
        frames: &'a FrameStore<'id>,
        brand: Brand<'id>,
    ) -> Result<Self, Error> {
        Ok(Self {
            row,
            #[cfg(feature = "alloc")]
            room,
            original: row.original(frames)?,
            brand,
        })
    }

    /// Exact original message hash; explicit access may reveal private-room metadata.
    pub const fn hash(&self) -> &Hash {
        &self.row.hash
    }
    /// Exact original epoch hash; its presence alone grants no authority.
    pub const fn epoch(&self) -> &Hash {
        &self.row.epoch
    }
    /// Current original room lifecycle observation.
    pub const fn phase(&self) -> MessagePhase {
        self.row.phase
    }
    /// Signed outer envelope kind, available without loading the body.
    pub const fn kind(&self) -> Kind {
        self.row.kind
    }
    /// Original outer transport padding policy retained with these bytes.
    /// Guessing Detect can truncate a valid binary IPC tail resembling a footer.
    pub const fn padding(&self) -> wire::padding::Decode {
        self.row.padding
    }
    /// Original signed graph predecessors retained through payload deletion.
    /// These read-only links grant no history/signature or membership authority.
    pub const fn parents(&self) -> &[Hash; 2] {
        &self.row.parents
    }
    /// Original declared signed-body and outer-padding encoder layouts.
    /// These metadata do not prove the producer's identity.
    pub const fn layout(&self) -> OriginalLayout {
        self.row.layout
    }
    /// Actual immutable encrypted/transcript short producer declaration.
    pub const fn cipher_layout(&self) -> Option<ShortLayout> {
        self.row.cipher_layout
    }
    /// Producer layout of installed plaintext, or the original declaration
    /// before plaintext is available. An accepted TRANSCRIPT can differ.
    pub const fn plaintext_layout(&self) -> Option<ShortLayout> {
        #[cfg(feature = "alloc")]
        if let Some(plain) = self.row.plaintext.as_ref() {
            return Some(plain.layout);
        }
        self.row.plain_layout
    }
    /// Independently retained short layout of nested TRANSCRIPT data.
    pub const fn transcript_layout(&self) -> Option<ShortLayout> {
        self.row.transcript_layout
    }
    /// Historical original actual source facts; this is not a live capability.
    pub const fn provenance(&self) -> SourceObservation {
        self.row.origin.provenance()
    }
    /// Original actual signer snapshot, including trusted archived acceptance.
    /// This metadata is not a newly minted network-signature/source proof.
    pub fn original_signer(&self) -> Option<OriginalSigner> {
        self.row.auth.map(|a| match a.peer {
            Some(peer) => OriginalSigner::Peer(peer),
            None => OriginalSigner::Member(a.public),
        })
    }
    /// Original input fact, kept separate from trusted archive recovery.
    pub const fn origin(&self) -> MessageOrigin<'id> {
        self.row.origin.view(self.brand)
    }
    /// Original matching local whole-write fact, independent of carried flags.
    pub const fn local_sent(&self) -> bool {
        self.row.local_sent
    }
    /// The original PRIVATE envelope or its accepted own transcript identifies
    /// private content even when its recipient Contact remains unresolved.
    pub fn is_private(&self) -> bool {
        self.row.kind == wire::envelope::Kind::PRIVATE || self.row.private_recipient.is_some()
    }
    /// Whether the typed semantic transition has actually been applied.
    pub const fn semantic_applied(&self) -> bool {
        self.row.semantic_applied
    }
    /// Whether all admitted original ancestor links are complete.
    pub const fn history_complete(&self) -> bool {
        self.row.complete
    }
    /// Whether this original is retained as history rather than live ingress.
    pub const fn requested(&self) -> bool {
        self.row.requested
    }
    /// Original unmodified wire flags, separate from actual local-send facts.
    pub const fn flags(&self) -> u32 {
        self.row.meta.flags
    }
    /// Actual signature-attributed contact, when member authentication succeeded.
    pub fn sender(&self) -> Option<Contact<'id>> {
        self.row
            .auth
            .and_then(|a| a.owner)
            .map(|o| self.brand.contact_id(o.contact))
    }
    /// Borrow resident typed original or authenticated decrypted content.
    /// Archived originals must be read through the owning checkpoint store.
    pub fn body(&self) -> Result<Body<'a>, Error> {
        #[cfg(feature = "alloc")]
        if let Some(plain) = &self.row.plaintext {
            return plain.body();
        }
        let original = self.original.ok_or(Fault::NotReady)?;
        Ok(self.row.decode_original(original)?.body())
    }
    /// Actual transcript link, with its original authority checks retained.
    pub fn transcript(&self) -> Option<&'a Hash> {
        self.row.transcript.as_ref()
    }
    /// Original recipient-key evidence, independent from the sender's signature
    /// and the currently selected local identity. A zone-only fact may still
    /// need the real matching historical JOIN/key advertisement to name a contact.
    #[cfg(feature = "alloc")]
    pub const fn recipient_attribution(&self) -> Option<&'a RecipientAttribution> {
        self.row.recipient.as_ref()
    }
    /// Actual completed private recipient, including an original identity whose
    /// signing key has since changed. No contact is synthesized for unresolved
    /// zone records, ambiguous anonymous identities, deleted or incomplete data.
    #[cfg(feature = "alloc")]
    pub fn recipient(&self) -> Option<Contact<'id>> {
        if !self.row.complete
            || !self.row.semantic_applied
            || matches!(
                self.row.phase,
                MessagePhase::Deleted | MessagePhase::Rejected
            )
        {
            return None;
        }
        self.row
            .recipient
            .as_ref()
            .and_then(|recipient| recipient.contact_slot(self.room))
            .map(|slot| self.brand.contact_id(slot))
    }
    /// Actual original recipient identity from successful PRIVATE decryption,
    /// its own outgoing intent, or an accepted own transcript. This is not a
    /// current membership/signing capability.
    pub fn private_recipient(&self) -> Option<&'a PublicKey> {
        #[cfg(feature = "alloc")]
        if let Some(recipient) = self
            .row
            .recipient
            .as_ref()
            .and_then(RecipientAttribution::public_key)
        {
            return Some(recipient);
        }
        self.row.private_recipient.as_ref()
    }
    /// Borrow the resident signed original, if it is in memory.
    pub const fn original(&self) -> Option<&'a [u8]> {
        self.original
    }
    /// Whether a signed original exists, regardless of its current storage.
    pub const fn has_original(&self) -> bool {
        self.row.has_original()
    }
    /// Exact signed bytes in the current committed checkpoint, if not resident.
    /// Resolve this range only through the matching store receipt.
    pub const fn archived_original(&self) -> Option<ArchiveOriginalRange> {
        self.row.archived_original()
    }
}
/// One actual member-authorized history walk. Deleted nodes follow preserved
/// links; live epoch JOIN/LEAVE/MERGE bootstrap messages are separately public.
pub struct History<'a, 'w, 'id> {
    room: &'a RoomRow<'id>,
    session: &'a SessionRow,
    frames: &'a FrameStore<'id>,
    brand: Brand<'id>,
    work: history_workspace::HistoryWalk<'w, HistorySnapshot<'a, 'id>>,
}
impl<'a, 'w, 'id> History<'a, 'w, 'id> {
    pub(crate) fn start(
        room: &'a RoomRow<'id>,
        session: &'a SessionRow,
        frames: &'a FrameStore<'id>,
        brand: Brand<'id>,
        hash: &Hash,
        workspace: &'w mut HistoryWorkspace<'_>,
    ) -> Result<Self, Error> {
        let mut history = room.history_snapshot();
        let root = history.locate(hash)?.ok_or(Fault::NotFound)?;
        Ok(Self {
            room,
            session,
            frames,
            brand,
            work: workspace.start_history(history, root)?,
        })
    }
}
impl<'a, 'id> History<'a, '_, 'id> {
    /// Advance the bounded original history walk without payload copying.
    pub fn try_next(&mut self) -> Result<Option<MessageRef<'a, 'id>>, Error> {
        while let Some((id, entry)) = self.work.pop()? {
            let HistoryEntry::Accepted(n) = entry else {
                return Err(Fault::NotReady.into());
            };
            if n.phase == MessagePhase::Deleted {
                for h in n.parents {
                    if h == [0; 64] {
                        continue;
                    }
                    let Some(p) = self.work.locate(&h)? else {
                        return Err(Fault::NotFound.into());
                    };
                    self.work.schedule(p)?;
                }
                continue;
            }
            if !n.semantic_applied {
                return Err(Fault::NotReady.into());
            }
            if !epoch_kind(n.kind) && !knows_sequence(self.session, n.sequence) {
                return Err(Error::Permission);
            }
            return self
                .room
                .history_message(id, self.frames, self.brand)
                .map(Some);
        }
        Ok(None)
    }
}
