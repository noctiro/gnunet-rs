//! Actual message links/frontier, owned history rights and resumable session
//! completion. Tombstones preserve links while encrypted/plain payload is erased.
use crate::{
    state::{Node, Owner, RoomRow, SessionRow},
    *,
};
use alloc::vec::Vec;
use core::fmt;
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind, profile::Profile};
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
pub(crate) fn owner<'id>(session: &SessionRow<'id>) -> Owner<'id> {
    Owner {
        contact: session.contact,
        lineage: session.lineage,
        generation: session.generation,
    }
}
pub(crate) fn owns(session: &SessionRow<'_>, node: &Node<'_>) -> bool {
    node.auth.and_then(|a| a.owner).is_some_and(|o| {
        o.contact == session.contact
            && o.lineage == session.lineage
            && o.generation <= session.generation
    })
}
pub(crate) fn known(session: &SessionRow<'_>, node: &Node<'_>) -> bool {
    node.auth.is_some()
        && node.sequence >= session.known_from
        && session
            .completed_at
            .is_none_or(|until| node.sequence <= until)
}
impl<'id> RoomRow<'id> {
    /// Actual update frontier observation or bounded operation.
    pub fn update_frontier(&mut self, slot: Slot) -> Result<(), Error> {
        let n = self.nodes.get(slot)?;
        if n.requested
            || n.hash == [0; 64]
            || matches!(n.kind, Kind::INFO | Kind::REQUEST)
            || discourse_kind(n.kind)
            || n.discourse.is_some()
        {
            return Ok(());
        }
        let (parents, hash) = (n.parents, n.hash);
        self.frontier
            .retain(|h| *h != parents[0] && *h != parents[1] && *h != hash);
        if self.frontier.len() == self.frontier.capacity() {
            return Err(Fault::Capacity.into());
        }
        self.frontier.push(hash);
        self.last_message = self.frontier[0];
        Ok(())
    }
    /// Actual graph complete observation or bounded operation.
    pub fn graph_complete(&self, slot: Slot) -> Result<bool, Error> {
        let n = self.nodes.get(slot)?;
        if n.auth.is_none() {
            return Ok(false);
        }
        for parent in n.parents {
            if parent == [0; 64] {
                continue;
            }
            if parent == n.hash {
                return Err(Fault::Malformed.into());
            }
            let Some(p) = self.find_node(&parent) else {
                return Ok(false);
            };
            if !self.nodes.get(p)?.complete {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Actual queue node observation or bounded operation.
    pub fn queue_node(&mut self, slot: Slot) -> Result<(), Error> {
        let n = self.nodes.get_mut(slot)?;
        if n.queued
            || matches!(n.phase, MessagePhase::Rejected | MessagePhase::Deleted) && n.complete
        {
            return Ok(());
        }
        if self.ready.len() == self.ready.capacity() {
            return Err(Fault::Capacity.into());
        }
        n.queued = true;
        self.ready.push_back(slot);
        Ok(())
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
    /// Actual schedule completion observation or bounded operation.
    pub fn schedule_completion(&mut self, session: Slot) -> Result<(), Error> {
        if !self.sessions.get(session)?.needs_completion()
            || self.completion_session == Some(session)
            || self.completion_queue.contains(&session)
        {
            return Ok(());
        }
        if self.completion_queue.len() == self.completion_queue.capacity() {
            return Err(Fault::Capacity.into());
        }
        self.completion_queue.push_back(session);
        Ok(())
    }
    // One graph step. Finding the opening bound on the closing message's
    // ancestry completes the original session, as in the active C algorithm.
    /// Actual completion step observation or bounded operation.
    pub fn completion_step(&mut self) -> Result<Option<Slot>, Error> {
        if self.completion_session.is_none() {
            let Some(session) = self.completion_queue.pop_front() else {
                return Ok(None);
            };
            let row = self.sessions.get(session)?;
            if !row.needs_completion() {
                return Ok(None);
            }
            self.completion_target = row.first_bound;
            let last = row.last_bound;
            self.visit = self.visit.checked_add(1).ok_or(Fault::Overflow)?;
            self.completion_stack.clear();
            if let Some(slot) = self.find_node(&last) {
                self.completion_stack.push(slot);
            }
            self.completion_session = Some(session);
        }
        let session = self.completion_session.ok_or(Fault::Conflict)?;
        let Some(slot) = self.completion_stack.pop() else {
            self.completion_session = None;
            return Ok(None);
        };
        let n = self.nodes.get_mut(slot)?;
        if n.visit == self.visit {
            return Ok(None);
        }
        n.visit = self.visit;
        if n.hash == self.completion_target {
            self.completion_session = None;
            self.completion_stack.clear();
            let row = self.sessions.get_mut(session)?;
            row.phase = SessionPhase::Completed;
            row.historical_phase = SessionPhase::Completed;
            row.completed_at = Some(self.sequence);
            return Ok(Some(session));
        }
        let parents = n.parents;
        for h in parents {
            if h == [0; 64] {
                continue;
            }
            if let Some(p) = self.find_node(&h)
                && self.nodes.get(p)?.visit != self.visit
                && !self.completion_stack.contains(&p)
            {
                if self.completion_stack.len() == self.completion_stack.capacity() {
                    return Err(Fault::Capacity.into());
                }
                self.completion_stack.push(p);
            }
        }
        Ok(None)
    }
    /// Actual erase message observation or bounded operation.
    pub fn erase_message(&mut self, slot: Slot, by: Option<Hash>) -> Result<usize, Error> {
        let n = self.nodes.get(slot)?;
        let transient = discourse_kind(n.kind);
        let hash = n.hash;
        // Preflight/count consistency precedes erasure. Cluster repair neither
        // allocates nor drops another original first-write association.
        if transient {
            self.remove_alias(&hash)?;
        }
        let n = self.nodes.get_mut(slot)?;
        let bytes = n.payload_bytes();
        n.recipient = None;
        if transient {
            n.epoch = [0; 64];
            n.meta.epoch = [0; 64];
            n.meta.flags = 0;
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
        } else if n.phase == MessagePhase::Deleted {
            return Ok(0);
        }
        n.frame = None;
        n.plaintext = None;
        n.phase = MessagePhase::Deleted;
        if !transient {
            n.deleted_by = by;
        }
        // Preserve original author/hash/parents/order for historical ancestry,
        // never payload or a live source reconstructed from an archive.
        n.semantic_applied = true;
        n.queued = false;
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
/// Bounded caller-owned history traversal storage; no allocation in next().
pub struct HistoryWorkspace {
    stack: Vec<Slot>,
    visited: Vec<Slot>,
    limit: usize,
}
impl HistoryWorkspace {
    /// Construct finite caller-owned state without hidden native I/O.
    pub fn new(limit: usize) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        let mut visited = Vec::new();
        visited
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            stack,
            visited,
            limit,
        })
    }
    pub(crate) fn reset(&mut self, slot: Slot) {
        self.stack.clear();
        self.visited.clear();
        self.stack.push(slot);
    }
}
/// Immutable actual stored message. Debug and accessors never label it as a
/// newly verified sender, storage receipt or remote delivery confirmation.
pub struct MessageRef<'a, 'id> {
    pub(crate) row: &'a Node<'id>,
    pub(crate) room: &'a RoomRow<'id>,
    pub(crate) profile: Profile,
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
    /// Actual authenticated installed plaintext declaration, possibly from a
    /// linked own TRANSCRIPT with a different short producer.
    pub const fn plaintext_layout(&self) -> Option<ShortLayout> {
        self.row.plain_layout
    }
    /// Independently retained short layout of nested TRANSCRIPT data.
    pub const fn transcript_layout(&self) -> Option<ShortLayout> {
        self.row.transcript_layout
    }
    /// Historical original actual source facts; this is not a live capability.
    pub const fn provenance(&self) -> SourceObservation {
        self.row.provenance
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
        self.row.origin
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
    /// Original unmodified wire flags, separate from actual local-send facts.
    pub const fn flags(&self) -> u32 {
        self.row.meta.flags
    }
    /// Actual signature-attributed contact, when member authentication succeeded.
    pub fn sender(&self) -> Option<Contact<'id>> {
        self.row.auth.and_then(|a| a.owner).map(|o| o.contact)
    }
    /// Borrow actual typed original or authenticated decrypted content.
    pub fn body(&self) -> Result<Body<'a>, Error> {
        self.row.body(self.profile)
    }
    /// Actual transcript link, with its original authority checks retained.
    pub fn transcript(&self) -> Option<&'a Hash> {
        self.row.transcript.as_ref()
    }
    /// Original recipient-key evidence, independent from the sender's signature
    /// and the currently selected local identity. A zone-only fact may still
    /// need the real matching historical JOIN/key advertisement to name a contact.
    pub const fn recipient_attribution(&self) -> Option<&'a RecipientAttribution<'id>> {
        self.row.recipient.as_ref()
    }
    /// Actual completed private recipient, including an original identity whose
    /// signing key has since changed. No contact is synthesized for unresolved
    /// zone records, ambiguous anonymous identities, deleted or incomplete data.
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
            .and_then(|recipient| recipient.contact(self.room))
    }
    /// Actual original recipient identity from successful PRIVATE decryption,
    /// its own outgoing intent, or an accepted own transcript. This is not a
    /// current membership/signing capability.
    pub fn private_recipient(&self) -> Option<&'a PublicKey> {
        self.row
            .recipient
            .as_ref()
            .and_then(RecipientAttribution::public_key)
            .or(self.row.private_recipient.as_ref())
    }
    /// Borrow the actual retained signed original bytes, absent after deletion.
    pub fn original(&self) -> Option<&'a [u8]> {
        self.row.frame.as_ref().map(OwnedBytes::expose)
    }
}
/// One actual member-authorized history walk. Deleted nodes follow preserved
/// links; live epoch JOIN/LEAVE/MERGE bootstrap messages are separately public.
pub struct History<'a, 'w, 'id> {
    pub(crate) room: &'a RoomRow<'id>,
    pub(crate) session: &'a SessionRow<'id>,
    pub(crate) profile: Profile,
    pub(crate) work: &'w mut HistoryWorkspace,
}
impl<'a, 'id> History<'a, '_, 'id> {
    /// Advance the bounded original history walk without payload copying.
    pub fn try_next(&mut self) -> Result<Option<MessageRef<'a, 'id>>, Error> {
        while let Some(slot) = self.work.stack.pop() {
            if self.work.visited.contains(&slot) {
                continue;
            }
            if self.work.visited.len() == self.work.limit {
                return Err(Fault::Capacity.into());
            }
            self.work.visited.push(slot);
            let n = self.room.nodes.get(slot)?;
            if n.phase == MessagePhase::Deleted {
                for h in n.parents {
                    if h == [0; 64] {
                        continue;
                    }
                    let Some(p) = self.room.find_node(&h) else {
                        return Err(Fault::NotFound.into());
                    };
                    if !self.work.visited.contains(&p) && !self.work.stack.contains(&p) {
                        if self.work.stack.len() == self.work.limit {
                            return Err(Fault::Capacity.into());
                        }
                        self.work.stack.push(p);
                    }
                }
                continue;
            }
            if n.auth.is_none() || !n.semantic_applied {
                return Err(Fault::NotReady.into());
            }
            if !epoch_kind(n.kind) && !known(self.session, n) {
                return Err(Error::Permission);
            }
            return Ok(Some(MessageRef {
                row: n,
                room: self.room,
                profile: self.profile,
            }));
        }
        Ok(None)
    }
}
