//! Actual original PILS jobs for bounded reusable DV material. Caller retains
//! provider/native/cancel debt and fixed cache storage; no new Client is created.
use super::{Error, SealJob as PacketSealJob, context, current};
use gnunet_pils::client::{Completion, Identity, KeyTarget, OperationId};
use gnunet_pils_host::client::Client;
use gnunet_transport_dv_crypto::{
    Task, Token,
    cache::{ReceiveMaterial, SendMaterial},
};
use gnunet_types::Error as Protocol;
use std::time::Instant;
/// Original caller operation deadlines, independent of a reusable material
/// epoch's lease. These immutable values grant no source or crypto authority.
/// The caller still owns alarms, cancellation and copied native FIFO debt.
#[derive(Clone, Copy, Debug)]
pub struct OperationBounds {
    until: u64,
    hard: Instant,
}
impl OperationBounds {
    /// Capture the SAME original operation's canonical and native targets.
    /// This constructs no fresh relative lifetime, clock, timer or provider.
    /// Admission and completion check the actual targets with their supplied
    /// fresh logical sample and the current native instant.
    pub const fn new(until: u64, hard: Instant) -> Self {
        Self { until, hard }
    }
    fn check(self, now: u64) -> Result<(), Protocol> {
        if self.until == u64::MAX {
            return Err(Protocol::InvalidInput);
        }
        if Instant::now() >= self.hard || now >= self.until {
            return Err(Protocol::Deadline);
        }
        Ok(())
    }
}
/// Original actual cached-material signing job, with an independent immutable
/// operation budget. The inner one-shot signer preserves its real operation,
/// prepared key, original PILS identity and copied-MQ cancellation semantics.
/// Wrapping it allocates no queue, task, timer or extra key/payload owner.
#[must_use = "retain or explicitly cancel the original signing job and native FIFO debt"]
pub struct SealJob<'source, 'id, 'pils> {
    inner: PacketSealJob<'source, 'id, 'pils>,
    operation_bounds: OperationBounds,
}
impl<'source, 'id, 'pils> SealJob<'source, 'id, 'pils> {
    /// Admit the material's actual purpose30 statement under this operation's
    /// separate original budget. A long material lease cannot extend the PILS
    /// request or authorize completing a canceled/expired original packet.
    pub fn begin<const N: usize>(
        prepared: gnunet_transport_dv_crypto::PreparedSeal<'source, 'id>,
        client: &mut Client<'pils, N>,
        identity: Identity<'pils>,
        now: u64,
        operation_bounds: OperationBounds,
    ) -> Result<Self, Error> {
        operation_bounds.check(now)?;
        if prepared.until() > identity.expiration().as_micros() {
            return Err(Protocol::InvalidInput.into());
        }
        let inner = PacketSealJob::begin(prepared, client, identity, now)?;
        Ok(Self {
            inner,
            operation_bounds,
        })
    }
    /// Exact original material/derivation token; not per-packet replay authority.
    pub fn token(&self) -> Token<'id> {
        self.inner.token()
    }
    /// Immutable ultimate target for original same-target signing serialization.
    pub const fn target(&self) -> gnunet_transport::PeerId {
        self.inner.target()
    }
    /// Actual original PILS operation, retaining its original native source.
    pub const fn operation(&self) -> OperationId<'pils> {
        self.inner.operation()
    }
    /// Complete the real original signer job into a bounded reusable epoch. The
    /// actual original OperationId/signer/identity/MQ, material lease and
    /// separate operation bounds are checked before purpose30 verification.
    /// Subsequent packet seals use AEAD and
    /// unique nonces without generating another PILS signing request.
    pub fn certify(
        self,
        completion: &Completion<'pils>,
        now: u64,
        messages: u32,
    ) -> Result<SendMaterial<'source, 'id>, Error> {
        let Self {
            inner,
            operation_bounds,
        } = self;
        if completion.operation() != inner.operation {
            return Err(Protocol::Stale.into());
        }
        operation_bounds.check(now)?;
        if inner.prepared.until() > inner.identity.expiration().as_micros() {
            return Err(Protocol::InvalidInput.into());
        }
        match completion {
            Completion::Signature {
                peer,
                signature,
                announced,
                ..
            } => {
                if peer.as_bytes() != &inner.prepared.local().0 {
                    return Err(Protocol::Authentication.into());
                }
                context(announced.ok_or(Protocol::Stale)?, inner.identity, now)?;
                let material = inner.prepared.certify(signature, now, messages)?;
                operation_bounds.check(now)?;
                Ok(material)
            }
            Completion::Failed { reason, .. } => Err(Error::Rejected(*reason)),
            _ => Err(Protocol::Malformed.into()),
        }
    }
    /// Cancel the same actual operation even after its original budget expires.
    /// No wire CANCEL or completed native FIFO retirement is fabricated.
    pub fn cancel<const N: usize>(
        self,
        client: &mut Client<'pils, N>,
    ) -> Result<Token<'id>, Error> {
        self.inner.cancel(client)
    }
}
/// One actual original PILS recipient KEM job, before cache installation. It
/// binds the exact encapsulation and source Task, with no plaintext/key clones.
/// Drop does not pretend to cancel/retire native Client FIFO debt.
#[must_use = "retain or explicitly cancel the original PILS KEM job/source"]
pub struct ReceiveJob<'source, 'id, 'pils> {
    task: Task<'source, 'id>,
    operation_bounds: OperationBounds,
    encapsulation: [u8; 32],
    identity: Identity<'pils>,
    operation: OperationId<'pils>,
}
impl<'source, 'id, 'pils> ReceiveJob<'source, 'id, 'pils> {
    /// Admit the exact original encapsulation to the actual existing PILS Client.
    /// Task retains the fixed material lease; operation_bounds captures this
    /// initiating packet's separate original deadlines. Caller owns the mapping
    /// and native debt; no write or crypto success is fabricated by admission.
    pub fn begin<const N: usize>(
        task: Task<'source, 'id>,
        encapsulation: [u8; 32],
        client: &mut Client<'pils, N>,
        identity: Identity<'pils>,
        now: u64,
        operation_bounds: OperationBounds,
    ) -> Result<Self, Error> {
        operation_bounds.check(now)?;
        task.check(now)?;
        if task.until() > identity.expiration().as_micros() {
            return Err(Protocol::InvalidInput.into());
        }
        let target = current(client, identity, task.local(), now)?;
        let operation = client.decapsulate(encapsulation, KeyTarget::Exact(target))?;
        Ok(Self {
            task,
            operation_bounds,
            encapsulation,
            identity,
            operation,
        })
    }
    /// Original material/provider task token, distinct from each packet task.
    pub fn token(&self) -> Token<'id> {
        self.task.token()
    }
    /// Actual original PILS operation, not an invented public/private RID.
    pub const fn operation(&self) -> OperationId<'pils> {
        self.operation
    }
    /// Accept only the actual original secret/recipient source. This copies32
    /// bytes once into the erased cache key owner. Signature proof starts empty;
    /// first/changed plaintext still requires actual AEAD + purpose30 checking.
    pub fn complete(
        self,
        completion: &Completion<'pils>,
        now: u64,
    ) -> Result<ReceiveMaterial<'source, 'id>, Error> {
        if completion.operation() != self.operation {
            return Err(Protocol::Stale.into());
        }
        self.operation_bounds.check(now)?;
        match completion {
            Completion::Decapsulated { identity, key, .. } => {
                context(*identity, self.identity, now)?;
                let material = ReceiveMaterial::from_shared_secret(
                    self.task,
                    self.encapsulation,
                    key.as_bytes(),
                    now,
                )?;
                self.operation_bounds.check(now)?;
                Ok(material)
            }
            Completion::Failed { reason, .. } => Err(Error::Rejected(*reason)),
            _ => Err(Protocol::Malformed.into()),
        }
    }
    /// Cancel only original actual PILS operation; no wire CANCEL or foreign MQ.
    /// The outer original native owner retains finite FIFO/source cleanup debt.
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

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Assertions distinguish independent real Source/Task and operation guards"
    )]
    use super::*;
    use gnunet_transport::PeerId;
    use gnunet_transport_dv_crypto::Instance;
    use std::time::Duration;

    #[test]
    fn long_material_lease_does_not_override_operation_or_source_guards() -> Result<(), Protocol> {
        let instance = Instance::new();
        let source = instance.source(PeerId([0x71; 32]), 10, 1000)?;
        let material = source.task(77, 10, 300)?;
        let hard = Instant::now() + Duration::from_secs(60);
        let original = OperationBounds::new(20, hard);
        let later = OperationBounds::new(40, hard);
        assert!(material.check(20).is_ok());
        assert_eq!(original.check(20), Err(Protocol::Deadline));
        assert!(later.check(20).is_ok());
        // Sharing a live material task with a newer operation neither revives
        // the original logical deadline nor changes its native target.
        assert_eq!(original.until, 20);
        assert_eq!(original.hard, hard);
        assert_eq!(material.until(), 300);
        let native_expired = OperationBounds::new(40, Instant::now());
        assert_eq!(native_expired.check(10), Err(Protocol::Deadline));
        assert!(material.check(10).is_ok());
        source.retire();
        assert_eq!(material.check(10), Err(Protocol::Closed));
        // Operation bounds alone are never a Source/identity authority.
        assert!(later.check(10).is_ok());
        Ok(())
    }
}
