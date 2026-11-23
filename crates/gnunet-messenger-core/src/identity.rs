//! Current local write authority and bounded historical signer provenance.
//! Only actual local identity observations call these APIs; remote messages do
//! not establish own lineage. No source is stopped or rebranded by a transition.
use crate::{engine::Core, state::*, *};
use gnunet_types::Error as Fault;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Whether this peer was explicitly observed as a local signer or restored
    /// as such from trusted owned history. This is historical provenance only;
    /// it does not authorize a live source or signing with an old private key.
    pub fn is_own_signer(&self, peer: &[u8; 32]) -> bool {
        self.own_signers.peers().binary_search(peer).is_ok()
    }
    /// Bind an actual current service PILS identity. After archive restoration
    /// this grants fresh local authority, without claiming that the historical
    /// signers and this peer share a master key. No secret or live source is
    /// reconstructed from stored history. A live different identity must use
    /// `rotate_local_peer` after its original signing work has settled.
    pub fn configure_local_peer(&mut self, peer: [u8; 32]) -> Result<(), Error> {
        if self.mode != Mode::Service || self.local_peer.is_some_and(|p| p != peer) {
            return Err(Error::Permission);
        }
        self.remember_own_signer(peer)?;
        self.local_peer = Some(peer);
        Ok(())
    }

    /// Atomically replace a healthy service's current identity and each live
    /// room signer lease, retaining their original source tokens. The caller
    /// must first settle actual provider work. A signature awaiting local commit
    /// is still original work and prevents the transition. Historical signed
    /// frames, authentication and provenance are never rewritten.
    pub fn rotate_local_peer(&mut self, peer: [u8; 32]) -> Result<bool, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let old = self.local_peer.ok_or(Fault::NotReady)?;
        if old == peer {
            return Ok(false);
        }
        for (_, room) in self.rooms.iter() {
            for (_, source) in room.sources.iter() {
                if let SourceRole::ServiceSigner(p) = source.role
                    && (!source.attached || p != old)
                {
                    return Err(Error::Permission);
                }
            }
            for (_, op) in room.operations.iter() {
                if matches!(
                    op.phase,
                    OperationPhase::Complete | OperationPhase::Cancelled | OperationPhase::Failed
                ) {
                    continue;
                }
                let own_lease = matches!(
                    room.sources.get(op.binding.source)?.role,
                    SourceRole::ServiceSigner(_)
                );
                let old_sign = matches!(&op.job, Job::Sign { public, .. } if public[4..] == old);
                if own_lease || old_sign {
                    return Err(Fault::NotReady.into());
                }
            }
        }
        // This is the last fallible step. Refusal keeps the current identity
        // and all original signer leases intact.
        self.remember_own_signer(peer)?;
        for (_, room) in self.rooms.iter_mut() {
            for (_, source) in room.sources.iter_mut() {
                if matches!(source.role, SourceRole::ServiceSigner(_)) {
                    source.role = SourceRole::ServiceSigner(peer);
                }
            }
        }
        self.local_peer = Some(peer);
        Ok(true)
    }

    pub(crate) fn remember_own_signer(&mut self, peer: [u8; 32]) -> Result<(), Error> {
        let budget = self.remaining_bytes();
        self.used += self
            .own_signers
            .remember(peer, self.limits.own_signers, budget)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests;
