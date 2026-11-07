//! Local PILS identity changes preserve business ownership and original native
//! debt. A carrier's actual local identity is a separate, per-source fact.
use super::*;
use gnunet_crypto::EddsaSignature;
use gnunet_wire::official::dht::{GetMessage, PutMessage, ResultMessage, RouteOptions};

impl<'id> Server<'id> {
    /// Called only for the actual validated PILS Identity observation. The public
    /// bytes do not reconstruct a PILS capability or authorize a SIGN operation.
    pub(super) fn observe_identity(&mut self, peer: [u8; 32], anchor: Anchor) -> Result<(), Error> {
        if self.routing_identity == Some(peer) {
            return Ok(());
        }
        // A formerly remote peer can become the new local PID. Remove its
        // logical route before changing the owner; actual admitted sends retain
        // their independent original endpoint and terminal accounting.
        while let Some(native) = self
            .peers
            .iter()
            .find(|row| row.native.identity().0 == peer)
            .map(|row| row.native)
        {
            self.disconnect_native(native)?;
        }
        if let Some(owner) = self.owner.as_mut() {
            owner.update_identity(peer)?;
        }
        if self.routing_identity.is_some() {
            self.own_hello.identity_changed()?;
        }
        self.routing_identity = Some(peer);
        if let Some(ip) = self.ip.as_mut() {
            // This actually retires every old IP endpoint. Do not select those
            // already-retiring endpoints for new business before their later
            // physical Disconnected observations drain the original IO debt.
            ip.set_identity(peer)?;
            self.ip_input = None;
            while let Some(native) = self
                .peers
                .iter()
                .find(|row| matches!(row.native, NativePeer::Ip(_)))
                .map(|row| row.native)
            {
                self.disconnect_native(native)?;
            }
        }
        self.sync_jobs(anchor)?;
        self.hello_refresh = self.ip.is_some();
        self.own_hello_pending = true;
        // A routing-key change can unblock neighbour choice without changing
        // queue credit. Resume the original round, never replace its bound.
        self.neighbours.resume();
        for row in &mut self.peers {
            row.hello_pending = true;
        }
        Ok(())
    }

    /// Purpose6 signatures and keyless P2P HELLOs must identify the actual local
    /// sender of the selected carrier. Ordinary untracked DHT traffic can keep
    /// using a still-live CORE MQ whose initial PID predates a PILS update.
    pub(super) fn native_identity_matches(&self, native: NativePeer<'id>) -> bool {
        let actual = match native {
            NativePeer::Core(_) => self
                .core
                .as_ref()
                .and_then(|source| source.phase.local_identity()),
            NativePeer::Ip(_) => self.ip.as_ref().and_then(crate::ip::Client::identity),
        };
        self.routing_identity.is_some() && actual == self.routing_identity
    }

    /// A real, quiescent callback first settles its original issued tombstone.
    /// A later canonical key cannot invalidate the fact that the old operation
    /// finished, nor authorize sending the old identity's frame.
    pub(super) fn complete_path_signature(
        &mut self,
        job: Job<'id>,
        original_peer: EddsaPublicKey,
        result: Result<(EddsaPublicKey, EddsaSignature), gnunet_pils::client::Failure>,
    ) -> Result<Option<Cause>, Error> {
        let owner = self.owner.as_mut().ok_or(Fault::NotReady)?;
        let retiring = owner.job_info(job).ok_or(Fault::Stale)?.retiring;
        if retiring {
            owner.retired(job)?;
            self.jobs.retain(|row| row.job != job);
            return Ok(match result {
                Ok((peer, _)) if peer != original_peer => Some(Cause::Identity),
                Ok(_) => None,
                Err(reason) => Some(Cause::Signature(reason)),
            });
        }
        match result {
            Ok((peer, signature)) => {
                if peer != original_peer || Some(*peer.as_bytes()) != self.routing_identity {
                    owner.signing_failed(job)?;
                    self.jobs.retain(|row| row.job != job);
                    return Err(Error(Arc::new(Cause::Identity)));
                }
                match owner.signed(job, *signature.as_bytes()) {
                    Ok(network::Signed::Ready) => {}
                    Ok(network::Signed::Retired) => self.jobs.retain(|row| row.job != job),
                    Err(reason) => {
                        owner.signing_failed(job)?;
                        self.jobs.retain(|row| row.job != job);
                        return Err(reason.into());
                    }
                }
                Ok(None)
            }
            Err(reason) => {
                owner.signing_failed(job)?;
                self.jobs.retain(|row| row.job != job);
                Ok(Some(Cause::Signature(reason)))
            }
        }
    }
}

/// Inspect the original standard frame, including GET (which has no local SIGN
/// job). No option is inferred from job kind or a remembered peer identity.
pub(super) fn tracked(wire: &[u8]) -> Result<bool, Fault> {
    let options = match Frame::decode(wire)?.header().message_type() {
        mt::DHT_P2P_GET => GetMessage::decode(wire)?.options,
        mt::DHT_P2P_PUT => PutMessage::decode(wire)?.options,
        mt::DHT_P2P_RESULT => ResultMessage::decode(wire)?.options,
        _ => return Ok(false),
    };
    Ok(options.contains(RouteOptions::RECORD_ROUTE))
}
