//! Explicit trusted Rust-owned committed snapshot boundary. It is never called
//! by IPC/CADET ingress. A checksum is storage integrity, not a peer signature.
use crate::{engine::Core, slots::Slots, state::*, *};
use alloc::vec::Vec;
use gnunet_types::Error as Fault;
use zeroize::Zeroizing;
mod codec;
mod read;
mod resume;
mod validate;
mod write;
use codec::*;
const MAGIC: &[u8; 8] = b"GMSHIS06";
/// Explicit trusted provider contract, analogous to the original source/entropy
/// ports. Implement only for a successfully loaded committed, namespace-qualified
/// Rust-owned store. Never implement it over network/IPC bytes or a user payload.
/// The production adapter's implementation privately owns Snapshot::Loaded and
/// checks Namespace::Messenger before exposing the zeroizing body.
pub trait CommittedArchive {
    /// Actual committed storage generation, nonzero for a nonempty image.
    fn generation(&self) -> u64;
    /// Integrity-checked body from the actual owned store. This is sensitive data.
    fn expose_committed(&self) -> &[u8];
}
/// An owned complete serialized service checkpoint. This grants neither durable
/// acceptance nor a live source until the actual storage worker commits it.
pub struct PreparedArchive {
    body: Zeroizing<Vec<u8>>,
    peer: Option<[u8; 32]>,
}
impl core::fmt::Debug for PreparedArchive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedArchive([REDACTED], not committed)")
            .field("bytes", &self.body.len())
            .finish()
    }
}
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
/// Source-free restoration outcome. All old physical scopes/operations/keys are
/// absent. Historical session eligibility is retained separately from current
/// phase, and peers are unannounced. A new actual transport plus verified in-scope
/// signature is needed to activate eligible historical Active lineage.
pub struct Recovered<'id> {
    /// Actual source-free Core containing accepted historical facts.
    core: Core<'id>,
    /// Original committed owned-store generation.
    generation: u64,
    /// Last stored local peer, with no live authorization or master-key claim.
    historical_peer: Option<[u8; 32]>,
}
impl<'id> Recovered<'id> {
    /// Consume the exact validated historical owner without creating a live source.
    pub fn into_parts(self) -> (Core<'id>, u64, Option<[u8; 32]>) {
        (self.core, self.generation, self.historical_peer)
    }
}
impl core::fmt::Debug for Recovered<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveredHistory(no live source)")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl<'id> Core<'id> {
    /// Explicit local codec choice. Original retained message layouts remain separate.
    pub const fn local_profile(&self) -> wire::profile::Profile {
        self.profile
    }
    /// Serialize authenticated SERVICE history and metadata; this is preparation,
    /// not commit/publication. No secret key, current IO job, live source or private
    /// crypto capability is serialized. Capacity refusal does not mutate Core.
    pub fn prepare_archive(&self, maximum: usize) -> Result<PreparedArchive, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        if self.local_peer.is_none()
            && (!self.own_signers.is_empty() || self.rooms.len() != 0 || self.contacts.len() != 0)
        {
            return Err(Fault::NotReady.into());
        }
        let mut w = Encoder::new(maximum);
        w.raw(MAGIC)?;
        w.profile(self.profile)?;
        w.opt_array(self.local_peer.as_ref())?;
        w.size(self.own_signers.len())?;
        for peer in &self.own_signers {
            w.raw(peer)?;
        }
        self.write_archive(&mut w)?;
        Ok(PreparedArchive {
            body: w.data,
            peer: self.local_peer,
        })
    }
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
        if store.generation() == 0 || store.expose_committed().len() > maximum {
            return Err(Fault::InvalidInput.into());
        }
        let mut r = Decoder::new(store.expose_committed());
        if r.raw(8)? != MAGIC {
            return Err(Fault::Authentication.into());
        }
        let _original_local = r.profile()?;
        let historical_peer = r.opt_array()?;
        let mut core = Core::new(instance, Mode::Service, limits, local_profile)?;
        let count = r.size(limits.own_signers)?;
        let requested = count
            .checked_mul(core::mem::size_of::<[u8; 32]>())
            .ok_or(Fault::Overflow)?;
        if requested > core.remaining_bytes() {
            return Err(Fault::Capacity.into());
        }
        let mut own_signers = Vec::new();
        own_signers
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        let bytes = own_signers
            .capacity()
            .checked_mul(core::mem::size_of::<[u8; 32]>())
            .ok_or(Fault::Overflow)?;
        core.charge(bytes)?;
        for _ in 0..count {
            let peer = r.array()?;
            if own_signers.last().is_some_and(|p| p >= &peer) {
                return Err(Fault::Malformed.into());
            }
            own_signers.push(peer);
        }
        core.own_signers = own_signers;
        core.read_archive(&mut r, store.generation())?;
        r.end()?;
        core.validate_archive(historical_peer)?;
        if historical_peer.is_none() && (core.rooms.len() != 0 || core.contacts.len() != 0) {
            return Err(Fault::Malformed.into());
        }
        // Own signer lineage is historical provenance, never a restored write
        // capability. The actual current PILS observation is configured later
        // and need not claim any cryptographic relation to historical peers.
        core.local_peer = None;
        Ok(Recovered {
            core,
            generation: store.generation(),
            historical_peer,
        })
    }
    /// Borrow accepted original rows from a retained room without constructing
    /// sources or replaying signed data through live ingress.
    pub fn retained_messages(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = MessageRef<'_, 'id>> + '_, Error> {
        let r = self.check_room(room)?;
        let room = self.rooms.get(r)?;
        Ok(room.nodes.iter().map(|(_, row)| MessageRef {
            row,
            room,
            profile: self.profile,
        }))
    }
    /// Enumerate actual retained room generations to populate a runtime directory.
    /// This read does not announce ports or construct live Peer/app sources.
    pub fn retained_rooms(&self) -> impl Iterator<Item = Room<'id>> + '_ {
        self.rooms.iter().map(|(slot, _)| self.event_room(slot))
    }
    /// Signed historical PEER candidates may seed a fresh actual connection
    /// attempt; no candidate is a live announcement, routing grant or source.
    pub fn service_peer_candidates(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = &[u8; 32]> + '_, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        Ok(row
            .peers
            .iter()
            .filter(|p| p.announced || p.historical_candidate)
            .map(|p| &p.peer))
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure source cases assert trusted synthetic archive projection and original slot/graph invariants, never actual signature or native proof"
)]
mod transient_tests;
