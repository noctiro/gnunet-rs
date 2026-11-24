//! Explicit trusted Rust-owned committed snapshot boundary. It is never called
//! by IPC/CADET ingress. A checksum is storage integrity, not a peer signature.
use crate::{engine::Core, state::*, *};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use gnunet_types::Error as Fault;
#[cfg(feature = "alloc")]
use zeroize::Zeroizing;
mod codec;
mod detach;
mod history;
mod originals;
mod page;
mod read;
mod resume;
mod rows;
mod validate;
mod write;
use codec::*;
pub use detach::GraphDetachment;
use detach::Selection;
pub(crate) use history::ArchivedLocalOriginal;
pub use history::{ArchiveHistoryCell, CommittedGraphSequence, CommittedRoomHistory};
pub use originals::{ArchiveOriginalCell, ArchiveOriginalRange, ArchiveOriginals};
pub(crate) use page::DetachedKind;
pub use page::{
    CommittedGraphPage, CommittedGraphPageBytes, DetachedDeletion, GraphPageIdentity,
    GraphPageMessage, PreparedGraphPageRef, maximum_graph_page_rows,
};
use rows::*;
use validate::DagWorkspace;
pub use validate::{ArchiveGraphCell, CommittedGraphPages};
pub use write::maximum_service_bytes;
const MAGIC: &[u8; 8] = b"GMSHIS06";

fn read_header<'archive>(
    r: &mut Decoder<'archive>,
    limits: Limits,
) -> Result<(Option<ShortHash>, &'archive [ShortHash]), Error> {
    if r.raw(MAGIC.len())? != MAGIC {
        return Err(Fault::Authentication.into());
    }
    let _original_local = r.profile()?;
    let historical_peer = r.opt_array()?;
    let count = r.size(limits.own_signers)?;
    let encoded = r.raw(SignerTable::required_bytes(count)?)?;
    Ok((historical_peer, encoded.as_chunks::<32>().0))
}

enum RecoveryOriginals {
    Resident,
    Paged,
}
/// An owned complete serialized service checkpoint. This grants neither durable
/// acceptance nor a live source until the actual storage worker commits it.
#[cfg(feature = "alloc")]
pub struct PreparedArchive {
    body: Zeroizing<Vec<u8>>,
    peer: Option<[u8; 32]>,
}
#[cfg(feature = "alloc")]
impl core::fmt::Debug for PreparedArchive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedArchive([REDACTED], not committed)")
            .field("bytes", &self.body.len())
            .finish()
    }
}
#[cfg(feature = "alloc")]
impl PreparedArchive {
    /// Transfer the exact original sensitive image to the actual storage worker.
    pub fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
    /// Last observed local peer encoded as historical metadata, not a new
    /// process's current authority or proof of a shared private master.
    pub const fn historical_peer(&self) -> Option<[u8; 32]> {
        self.peer
    }
    /// Original serialized byte count, not a durable receipt.
    pub fn len(&self) -> usize {
        self.body.len()
    }
    /// Whether the encoded body is empty (valid checkpoints have a fixed prefix).
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

/// A complete prepared checkpoint in caller-owned storage. Only the encoded
/// prefix is borrowed for publication and that prefix is erased on drop. The
/// guard grants neither a durable receipt nor a live source.
pub struct PreparedArchiveRef<'output> {
    body: SliceSink<'output>,
    peer: Option<[u8; 32]>,
}

impl core::fmt::Debug for PreparedArchiveRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedArchiveRef([REDACTED], not committed)")
            .field("bytes", &self.body.expose().len())
            .finish()
    }
}

impl PreparedArchiveRef<'_> {
    /// Borrow the exact complete sensitive image while the original storage
    /// port uses it. The bytes do not outlive this guard.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.body.expose()
    }

    /// Last observed local peer encoded as historical metadata, not a current
    /// process identity or proof of a shared private master.
    #[must_use]
    pub const fn historical_peer(&self) -> Option<[u8; 32]> {
        self.peer
    }

    /// Transfer the encoded prefix to its existing storage scratch owner and
    /// return its length. That owner must erase the original bytes on every
    /// outcome and on drop. Use [`Self::expose`] when the prepared guard should
    /// retain responsibility for erasing the output.
    #[must_use]
    pub fn into_len_for_storage(self) -> usize {
        self.body.into_len_for_storage()
    }
}

/// Source-free restoration outcome. All old physical scopes/operations/keys are
/// absent. Historical session eligibility is retained separately from current
/// phase, and peers are unannounced. A new actual transport plus verified in-scope
/// signature is needed to activate eligible historical Active lineage.
pub struct Recovered<'id, const ROOMS: usize = 0> {
    /// Actual source-free Core containing accepted historical facts.
    core: Core<'id, ROOMS>,
    /// Original committed owned-store generation.
    generation: u64,
    /// Last stored local peer, with no live authorization or master-key claim.
    historical_peer: Option<[u8; 32]>,
}
impl<'id, const ROOMS: usize> Recovered<'id, ROOMS> {
    /// Consume the exact validated historical owner without creating a live source.
    pub fn into_parts(self) -> (Core<'id, ROOMS>, u64, Option<[u8; 32]>) {
        (self.core, self.generation, self.historical_peer)
    }
}
impl<const ROOMS: usize> core::fmt::Debug for Recovered<'_, ROOMS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveredHistory(no live source)")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Explicit local codec choice. Original retained message layouts remain separate.
    pub const fn local_profile(&self) -> wire::profile::Profile {
        self.profile
    }

    /// Serialize authenticated SERVICE history and metadata; this is preparation,
    /// not commit/publication. No secret key, current IO job, live source or private
    /// crypto capability is serialized. Capacity refusal does not mutate Core.
    #[cfg(feature = "alloc")]
    pub fn prepare_archive(&self, maximum: usize) -> Result<PreparedArchive, Error> {
        let mut writer = Encoder::new(OwnedSink::new(maximum));
        self.encode_archive(&mut writer)?;
        Ok(PreparedArchive {
            body: writer.finish().into_body(),
            peer: self.local_peer,
        })
    }

    /// Serialize the same SERVICE checkpoint into bounded caller storage with
    /// no encoder allocation. The storage owner must separately publish the
    /// prepared bytes and observe the outcome. This leaves Core unchanged.
    ///
    /// # Errors
    /// Requires service mode and authenticated, indexed history without client
    /// secrets. If the output is too short or encoding fails, erase all bytes
    /// written during this attempt. Unwritten bytes are left untouched.
    pub fn prepare_archive_into<'output>(
        &self,
        output: &'output mut [u8],
    ) -> Result<PreparedArchiveRef<'output>, Error> {
        let mut writer = Encoder::new(SliceSink::new(output));
        self.encode_archive(&mut writer)?;
        Ok(PreparedArchiveRef {
            body: writer.finish(),
            peer: self.local_peer,
        })
    }

    /// Prepare the original archive format and its next index. Load any cold
    /// frames directly into the output through the current committed image's
    /// range reader. The complete frame is checked against its stored digest.
    ///
    /// # Errors
    /// Refuses an invalid checkpoint, too little storage or an unavailable or
    /// altered original. An error clears the attempted index and output prefix.
    pub fn prepare_paged_archive_into<'output>(
        &self,
        output: &'output mut [u8],
        index: &mut ArchiveOriginals<'_>,
        read: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
    ) -> Result<PreparedArchiveRef<'output>, Error> {
        self.prepare_projected_archive_into(output, index, read, None)
    }

    fn prepare_projected_archive_into<'output>(
        &self,
        output: &'output mut [u8],
        index: &mut ArchiveOriginals<'_>,
        read: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
        selection: Option<Selection<'_>>,
    ) -> Result<PreparedArchiveRef<'output>, Error> {
        index.clear();
        let mut writer = Encoder::new(originals::IndexedSink::new(output, index, read));
        if let Err(error) = self.encode_archive_projected(&mut writer, selection) {
            drop(writer);
            index.clear();
            return Err(error);
        }
        Ok(PreparedArchiveRef {
            body: writer.finish().finish(),
            peer: self.local_peer,
        })
    }

    fn encode_archive(&self, w: &mut Encoder<impl ArchiveSink>) -> Result<(), Error> {
        self.encode_archive_projected(w, None)
    }

    fn encode_archive_projected(
        &self,
        w: &mut Encoder<impl ArchiveSink>,
        selection: Option<Selection<'_>>,
    ) -> Result<(), Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let own_signers = self.own_signers.peers();
        if self.local_peer.is_none()
            && (!own_signers.is_empty() || self.rooms.len() != 0 || self.contacts.len() != 0)
        {
            return Err(Fault::NotReady.into());
        }
        w.raw(MAGIC)?;
        w.profile(self.profile)?;
        w.opt_array(self.local_peer.as_ref())?;
        w.size(own_signers.len())?;
        for peer in own_signers {
            w.raw(peer)?;
        }
        self.write_archive(w, selection)
    }
}

#[cfg(feature = "alloc")]
impl<'id> Core<'id> {
    /// Recover only through an explicit committed owned-store provider. Production
    /// native callers cannot manufacture this boundary from a network frame: they
    /// privately hold the actual namespace-qualified Loaded owner. Full retained
    /// raw frames are cryptographically rechecked; deleted payloads remain trusted
    /// durable acceptance facts with structural checks, never new signature proof.
    pub fn recover_archive(
        instance: &'id mut Instance,
        store: &impl CommittedArchive,
        limits: Limits,
        local_profile: wire::profile::Profile,
        maximum: usize,
    ) -> Result<Recovered<'id>, Error> {
        Self::recover_archive_using(
            store,
            limits,
            maximum,
            DagWorkspace::owned(limits),
            RecoveryOriginals::Resident,
            CommittedGraphPages::EMPTY,
            || Self::new(instance, Mode::Service, limits, local_profile),
        )
    }

    /// Recover through the same committed owned-store boundary, retaining
    /// original signed frames in the supplied caller-owned pool. Checkpoint
    /// format, validation and source-free authority are identical to
    /// [`Self::recover_archive`]. Room metadata still uses the core's tables.
    ///
    /// # Errors
    /// Uses the same validation errors as [`Self::recover_archive`]. Recovery
    /// can also fail if the supplied frame pool cannot hold the retained
    /// originals. On failure the attempted pool owner is dropped and erased.
    pub fn recover_archive_with_frame_pool(
        instance: &'id mut Instance,
        store: &impl CommittedArchive,
        limits: Limits,
        local_profile: wire::profile::Profile,
        maximum: usize,
        pool: OriginalPool<'id, 'id>,
        workspace: &'id mut [u8],
    ) -> Result<Recovered<'id>, Error> {
        Self::recover_archive_using(
            store,
            limits,
            maximum,
            DagWorkspace::owned(limits),
            RecoveryOriginals::Resident,
            CommittedGraphPages::EMPTY,
            || Self::with_frame_pool(instance, limits, local_profile, pool, workspace),
        )
    }

    /// Recover a committed service archive into caller-owned room history and
    /// signed-frame storage. The retained room indices select the same fixed
    /// partitions used by [`Self::with_fixed_history`]. The checkpoint format,
    /// validation and source-free authority match [`Self::recover_archive`].
    ///
    /// # Errors
    /// Uses the same validation errors as [`Self::recover_archive`]. Recovery
    /// also fails if the supplied history partitions or frame pool cannot hold
    /// the retained state. Failure drops the staged owner and erases its frames.
    #[expect(
        clippy::too_many_arguments,
        reason = "The fixed history constructor inputs are followed by the archive provider and its byte bound"
    )]
    pub fn recover_archive_with_fixed_history(
        instance: &'id mut Instance,
        limits: Limits,
        local_profile: wire::profile::Profile,
        pool: OriginalPool<'id, 'id>,
        workspace: &'id mut [u8],
        storage: RoomHistoryStorage<'id>,
        store: &impl CommittedArchive,
        maximum: usize,
    ) -> Result<Recovered<'id>, Error> {
        Self::recover_archive_using(
            store,
            limits,
            maximum,
            DagWorkspace::owned(limits),
            RecoveryOriginals::Resident,
            CommittedGraphPages::EMPTY,
            || Self::with_fixed_history(instance, limits, local_profile, pool, workspace, storage),
        )
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Recover a committed archive using the caller-owned storage supplied to
    /// [`Self::with_service_buffers`]. Recovered history uses the original
    /// format and restores no live sources, work or signing authority.
    ///
    /// # Errors
    /// Rejects malformed or unauthenticated history. The supplied buffers
    /// must meet the service constructor's capacity requirements and hold
    /// the retained state. The graph workspace needs one cell per slot in
    /// the larger of the message and epoch tables. A rejected recovery drops
    /// the staged state.
    pub fn recover_archive_with_service_buffers(
        instance: &'id mut Instance,
        store: &impl CommittedArchive,
        limits: Limits,
        local_profile: wire::profile::Profile,
        maximum: usize,
        buffers: ServiceBuffers<'id, ROOMS>,
        graph: &mut [ArchiveGraphCell],
    ) -> Result<Recovered<'id, ROOMS>, Error> {
        let graph = DagWorkspace::with_cells(graph, limits)?;
        Self::recover_archive_using(
            store,
            limits,
            maximum,
            graph,
            RecoveryOriginals::Resident,
            CommittedGraphPages::EMPTY,
            || Self::with_service_buffers(instance, limits, local_profile, buffers),
        )
    }

    /// Recover fixed service history with settled content left in the verified
    /// checkpoint. Verify the exact signed frame in place before exposing the
    /// recovered core; only frames required in memory use the resident pool.
    /// The owner must keep the original committed image readable by range.
    ///
    /// # Errors
    /// Uses the same authority, signature, graph and capacity checks as
    /// [`Self::recover_archive_with_service_buffers`].
    pub fn recover_paged_archive_with_service_buffers(
        instance: &'id mut Instance,
        store: &impl CommittedArchive,
        limits: Limits,
        local_profile: wire::profile::Profile,
        maximum: usize,
        buffers: ServiceBuffers<'id, ROOMS>,
        graph: &mut [ArchiveGraphCell],
    ) -> Result<Recovered<'id, ROOMS>, Error> {
        let graph = DagWorkspace::with_cells(graph, limits)?;
        Self::recover_archive_using(
            store,
            limits,
            maximum,
            graph,
            RecoveryOriginals::Paged,
            CommittedGraphPages::EMPTY,
            || Self::with_service_buffers(instance, limits, local_profile, buffers),
        )
    }

    /// Recover the exact working checkpoint and detached graph pages selected
    /// by one pinned native root. The complete durable graph and retained
    /// signatures are verified before returning. Detached originals remain on
    /// their pages and do not consume working slots or original frame storage.
    ///
    /// # Errors
    /// Refuses malformed, mixed or unauthenticated history and insufficient
    /// workspace. Size the graph cells for the maximum detached rows in one
    /// room using [`ArchiveGraphCell::required_cells_with_detached`].
    #[expect(
        clippy::too_many_arguments,
        reason = "fixed storage input retains separate buffers, graph scratch and pinned pages"
    )]
    pub fn recover_rooted_archive_with_service_buffers(
        instance: &'id mut Instance,
        store: &impl CommittedArchive,
        limits: Limits,
        local_profile: wire::profile::Profile,
        maximum: usize,
        buffers: ServiceBuffers<'id, ROOMS>,
        graph: &mut [ArchiveGraphCell],
        pages: CommittedGraphPages<'_, '_>,
    ) -> Result<Recovered<'id, ROOMS>, Error> {
        Self::recover_archive_using(
            store,
            limits,
            maximum,
            DagWorkspace::with_cells(graph, limits)?,
            RecoveryOriginals::Paged,
            pages,
            || Self::with_service_buffers(instance, limits, local_profile, buffers),
        )
    }

    fn recover_archive_using(
        store: &impl CommittedArchive,
        limits: Limits,
        maximum: usize,
        graph: DagWorkspace<'_>,
        originals: RecoveryOriginals,
        pages: CommittedGraphPages<'_, '_>,
        new_core: impl FnOnce() -> Result<Self, Error>,
    ) -> Result<Recovered<'id, ROOMS>, Error> {
        let generation = store.generation();
        let archive = store.expose_committed();
        if generation == 0 || archive.len() > maximum {
            return Err(Fault::InvalidInput.into());
        }
        let mut r = Decoder::new(archive);
        let (historical_peer, signers) = read_header(&mut r, limits)?;
        let mut core = new_core()?;
        let budget = core.remaining_bytes();
        core.used += core.own_signers.restore(signers, budget)?;
        core.read_archive(&mut r, generation, originals)?;
        r.end()?;
        core.validate_archive_using(historical_peer, graph, archive, pages)?;
        if historical_peer.is_none() && (core.rooms.len() != 0 || core.contacts.len() != 0) {
            return Err(Fault::Malformed.into());
        }
        // Own signer lineage is historical provenance, never a restored write
        // capability. The actual current PILS observation is configured later
        // and need not claim any cryptographic relation to historical peers.
        core.local_peer = None;
        Ok(Recovered {
            core,
            generation,
            historical_peer,
        })
    }
    /// Borrow accepted original rows from a retained room without constructing
    /// sources or replaying signed data through live ingress. Each item reports
    /// any error resolving its retained original frame.
    pub fn retained_messages(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = Result<MessageRef<'_, 'id>, Error>> + '_, Error> {
        let r = self.check_room(room)?;
        let room = self.rooms.get(r)?;
        Ok(room
            .nodes
            .iter()
            .map(|(_, row)| MessageRef::new(row, room, &self.frames, self.instance)))
    }
    /// Enumerate actual retained room generations to populate a runtime directory.
    /// This read does not announce ports or construct live Peer/app sources.
    pub fn retained_rooms(&self) -> impl Iterator<Item = Room<'id>> + '_ {
        self.rooms.iter().map(|(slot, _)| self.event_room(slot))
    }
}

fn has_client_message_state(node: &Node) -> bool {
    #[cfg(feature = "alloc")]
    {
        node.plaintext.is_some() || node.recipient.is_some()
    }
    #[cfg(not(feature = "alloc"))]
    {
        let _ = node;
        false
    }
}

#[cfg(all(test, feature = "alloc"))]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check trusted archive projection, signed frames and custody invariants"
)]
mod transient_tests;
