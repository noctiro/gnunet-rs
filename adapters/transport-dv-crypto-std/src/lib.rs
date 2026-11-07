//! Real caller-owned PILS operation glue for DV boxed payload material. This
//! module creates no MQ, thread, timer, hidden queue or default crypto provider.
//! Caller drives its existing PILS Client and original hard/cancel/source bounds.
#![cfg(unix)]
#![forbid(unsafe_code)]
/// Actual original PILS jobs for fixed reusable material caches.
pub mod cache;
/// Original actual PILS jobs for learning initiation and per-hop forwarding.
pub mod learn;
use gnunet_pils::client::{Completion, Identity, KeyTarget, OperationId};
use gnunet_pils_host::client::Client;
use gnunet_transport::PeerId;
use gnunet_transport_dv_crypto::{OpenRequest, Opened, PreparedSeal, Sealed, Token};
use gnunet_types::Error as Protocol;
use zeroize::Zeroize;
/// Exact admission/completion error. No secret result has Debug formatting.
#[derive(Debug)]
pub enum Error {
    /// Actual core/binding/expiry/authentication/resource failure.
    Protocol(Protocol),
    /// Actual original PILS/CLIENT admission or cancellation failure.
    Client(gnunet_client_host::ConnectError),
    /// Actual source-matching PILS refusal.
    Rejected(gnunet_pils::client::Failure),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DV PILS: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<Protocol> for Error {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}
fn current<'pils, const N: usize>(
    client: &Client<'pils, N>,
    identity: Identity<'pils>,
    local: PeerId,
    now: u64,
) -> Result<Identity<'pils>, Error> {
    let actual = client.identity().ok_or(Protocol::Stale)?;
    if identity.expiration().as_micros() <= now || actual.expiration().as_micros() <= now {
        return Err(Protocol::NotReady.into());
    }
    if client.epoch() != Some(identity.epoch())
        || actual.epoch() != identity.epoch()
        || actual.peer() != identity.peer()
        || actual.address_hash() != identity.address_hash()
        || actual.coverage() != identity.coverage()
        || identity.peer().as_bytes() != &local.0
    {
        return Err(Protocol::Stale.into());
    }
    // Only the new Exact admission uses the latest announcement token. The
    // caller's original identity remains the job's material/expiry anchor.
    Ok(actual)
}
fn context(actual: Identity<'_>, original: Identity<'_>, now: u64) -> Result<(), Error> {
    if actual.expiration().as_micros() <= now || original.expiration().as_micros() <= now {
        return Err(Protocol::NotReady.into());
    }
    if actual.epoch() != original.epoch() || actual.peer() != original.peer() {
        return Err(Protocol::Stale.into());
    }
    Ok(())
}
/// Retained actual original purpose30 PILS signing job. Source/task material is
/// immutable while waiting. Drop wipes its KEM key; the outer owner must cancel
/// or physically close its original PILS debt, rather than dropping that debt.
#[must_use = "retain original PILS operation, or explicitly cancel/retire its original source"]
pub struct SealJob<'source, 'id, 'pils> {
    prepared: PreparedSeal<'source, 'id>,
    identity: Identity<'pils>,
    operation: OperationId<'pils>,
}
impl<'source, 'id, 'pils> SealJob<'source, 'id, 'pils> {
    /// Actually admit the exact signed80-byte region to the existing original
    /// Client, targeted to its actual current identity. No local write/ACK occurs
    /// merely because this function returns the actual typed operation id.
    pub fn begin<const N: usize>(
        prepared: PreparedSeal<'source, 'id>,
        client: &mut Client<'pils, N>,
        identity: Identity<'pils>,
        now: u64,
    ) -> Result<Self, Error> {
        prepared.check(now)?;
        let target = current(client, identity, prepared.local(), now)?;
        let operation = client.sign(&prepared.region(), KeyTarget::Exact(target))?;
        Ok(Self {
            prepared,
            identity,
            operation,
        })
    }
    /// Original DV source/task token for the surrounding Engine effect map.
    pub fn token(&self) -> Token<'id> {
        self.prepared.token()
    }
    /// Original ultimate recipient, for bounded same-target construction admission.
    /// This is immutable metadata, not a completed signature or key-cache grant.
    pub const fn target(&self) -> PeerId {
        self.prepared.target()
    }
    /// Actual original PILS operation; never regenerate a private request id.
    pub const fn operation(&self) -> OperationId<'pils> {
        self.operation
    }
    /// Finish only the actual original signature response and signer context.
    /// Completion is borrowed, so rejecting another job's result cannot consume
    /// or erase that unrelated result. Real EdDSA verification then AEAD happens
    /// in the pure layer. Caller enforces native hard before/after CPU work.
    pub fn complete(
        self,
        completion: &Completion<'pils>,
        now: u64,
        packet: gnunet_transport_dv_crypto::cache::Packet<'_>,
        scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Sealed<'id>, Error> {
        let work = Wipe(scratch);
        if completion.operation() != self.operation {
            return Err(Protocol::Stale.into());
        }
        match completion {
            Completion::Signature {
                peer,
                signature,
                announced,
                ..
            } => {
                if peer.as_bytes() != &self.prepared.local().0 {
                    return Err(Protocol::Authentication.into());
                }
                context(announced.ok_or(Protocol::Stale)?, self.identity, now)?;
                Ok(self
                    .prepared
                    .seal(signature, now, packet, &mut *work.0, out)?)
            }
            Completion::Failed { reason, .. } => Err(Error::Rejected(*reason)),
            _ => Err(Protocol::Malformed.into()),
        }
    }
    /// Cancel only this actual original PILS operation. PILS has no wire CANCEL;
    /// its client suppresses completion while retaining its physical FIFO debt.
    /// Owner must still drive/close original Client under the original hard bound.
    pub fn cancel<const N: usize>(
        self,
        client: &mut Client<'pils, N>,
    ) -> Result<Token<'id>, Error> {
        if client.epoch() != Some(self.identity.epoch()) {
            return Err(Protocol::Stale.into());
        }
        let token = self.token();
        client.cancel(self.operation)?;
        Ok(token)
    }
}
/// One actual original decapsulation job. It borrows the original immutable box
/// for the whole provider operation, without ciphertext/path clones or selfrefs.
#[must_use = "retain original PILS operation, or explicitly cancel/retire its original source"]
pub struct OpenJob<'source, 'id, 'packet, 'pils> {
    request: OpenRequest<'source, 'id, 'packet>,
    identity: Identity<'pils>,
    operation: OperationId<'pils>,
}
impl<'source, 'id, 'packet, 'pils> OpenJob<'source, 'id, 'packet, 'pils> {
    /// Admit the exact original enc32 to actual PILS, binding original source and
    /// current verified identity. Never ask a new identity to service old material.
    pub fn begin<const N: usize>(
        request: OpenRequest<'source, 'id, 'packet>,
        client: &mut Client<'pils, N>,
        identity: Identity<'pils>,
        now: u64,
    ) -> Result<Self, Error> {
        request.check(now)?;
        let target = current(client, identity, request.local(), now)?;
        let operation = client.decapsulate(request.encapsulation()?, KeyTarget::Exact(target))?;
        Ok(Self {
            request,
            identity,
            operation,
        })
    }
    /// Original surrounding DV task token.
    pub fn token(&self) -> Token<'id> {
        self.request.token()
    }
    /// Actual original PILS operation, not a native write or result receipt.
    pub const fn operation(&self) -> OperationId<'pils> {
        self.operation
    }
    /// Require the actual source-matching KEM secret32, then perform actual AEAD
    /// and purpose30 checks. Only Opened releases plaintext, erased on drop.
    /// This is no replay/durable/Engine admission receipt. Caller keeps the
    /// original actual PILS source live and checks its own native hard bound.
    pub fn complete<'out>(
        self,
        completion: &Completion<'pils>,
        now: u64,
        scratch: &mut [u8],
        out: &'out mut [u8],
    ) -> Result<Opened<'source, 'id, 'out>, Error> {
        let work = Wipe(scratch);
        if completion.operation() != self.operation {
            return Err(Protocol::Stale.into());
        }
        match completion {
            Completion::Decapsulated { identity, key, .. } => {
                context(*identity, self.identity, now)?;
                Ok(self
                    .request
                    .open_with_shared_secret(key.as_bytes(), now, &mut *work.0, out)?)
            }
            Completion::Failed { reason, .. } => Err(Error::Rejected(*reason)),
            _ => Err(Protocol::Malformed.into()),
        }
    }
    /// Cancel the actual original KEM operation, retaining any original physical
    /// FIFO debt inside Client until its actual completion/loss/close.
    pub fn cancel<const N: usize>(
        self,
        client: &mut Client<'pils, N>,
    ) -> Result<Token<'id>, Error> {
        if client.epoch() != Some(self.identity.epoch()) {
            return Err(Protocol::Stale.into());
        }
        let token = self.token();
        client.cancel(self.operation)?;
        Ok(token)
    }
}

struct Wipe<'a>(&'a mut [u8]);
impl Drop for Wipe<'_> {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}
