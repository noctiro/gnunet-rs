//! Actual PILS jobs for DV learning initiator and forwarding signatures.
//! The surrounding owner retains original network, replay, persistence and
//! native deadline obligations. A signed packet is never a delivery receipt.
use super::{Error, context, current};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, Entropy};
use gnunet_pils::client::{Completion, Identity, KeyTarget, OperationId};
use gnunet_pils_host::client::Client;
use gnunet_transport::{PeerId, dv};
use gnunet_transport_dv_crypto::{Task, Token};
use gnunet_types::Error as Protocol;
use std::time::Instant;
use zeroize::Zeroizing;

fn signature<'result>(
    completion: &'result Completion<'_>,
    operation: OperationId<'_>,
    original: Identity<'_>,
    local: PeerId,
    now: u64,
) -> Result<&'result EddsaSignature, Error> {
    if completion.operation() != operation {
        return Err(Protocol::Stale.into());
    }
    match completion {
        Completion::Signature {
            peer,
            signature,
            announced,
            ..
        } => {
            if peer.as_bytes() != &local.0 {
                return Err(Protocol::Authentication.into());
            }
            context(announced.ok_or(Protocol::Stale)?, original, now)?;
            Ok(signature)
        }
        Completion::Failed { reason, .. } => Err(Error::Rejected(*reason)),
        _ => Err(Protocol::Malformed.into()),
    }
}

/// Actually signed immutable learning bytes, valid only in the original task.
/// This proves no probe write, route validation, replay admission or remote ACK.
pub struct Signed<'source, 'id, 'out> {
    task: Task<'source, 'id>,
    bytes: &'out [u8],
    successor: Option<PeerId>,
}
impl<'id> Signed<'_, 'id, '_> {
    /// Original source/task identity for the caller's output and probe map.
    pub fn token(&self) -> Token<'id> {
        self.task.token()
    }
    /// A forwarded statement binds this exact next recipient. Initiator frames
    /// have no signed recipient and may be submitted to multiple actual peers.
    pub const fn successor(&self) -> Option<PeerId> {
        self.successor
    }
    /// Borrow the actual signed frame while its original source/task is live.
    /// Caller additionally enforces its immutable native bound before IO.
    pub fn bytes(&self, now: u64) -> Result<&[u8], Error> {
        self.task.check(now)?;
        Ok(self.bytes)
    }
}

/// One real original purpose37 signing operation and fresh public challenge.
#[must_use = "retain or cancel the original PILS job and its physical FIFO debt"]
pub struct InitiateJob<'source, 'id, 'pils> {
    task: Task<'source, 'id>,
    challenge: [u8; 32],
    identity: Identity<'pils>,
    operation: OperationId<'pils>,
}
impl<'source, 'id, 'pils> InitiateJob<'source, 'id, 'pils> {
    /// Generate the real challenge using caller entropy and actually admit its
    /// exact purpose37 statement to the existing source-matching PILS client.
    /// The task stamp comes from the caller's actual durable monotime authority;
    /// this method neither reserves a stamp nor pretends that a probe was sent.
    pub fn begin<const N: usize>(
        task: Task<'source, 'id>,
        client: &mut Client<'pils, N>,
        identity: Identity<'pils>,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        task.check(now)?;
        let target = current(client, identity, task.local(), now)?;
        let mut challenge = Zeroizing::new([0; 32]);
        entropy
            .fill(challenge.as_mut())
            .map_err(|_| Protocol::Entropy)?;
        let region = dv::init_region(task.stamp(), &challenge);
        let operation = client.sign(&region, KeyTarget::Exact(target))?;
        Ok(Self {
            task,
            challenge: *challenge,
            identity,
            operation,
        })
    }
    /// Actual original provider operation, never a wire request id replacement.
    pub const fn operation(&self) -> OperationId<'pils> {
        self.operation
    }
    /// Original immutable source/task token.
    pub fn token(&self) -> Token<'id> {
        self.task.token()
    }
    /// Real independently checked purpose37 completion before any output change.
    /// A wholly written probe must be recorded separately against this challenge.
    pub fn complete<'out>(
        self,
        completion: &Completion<'pils>,
        now: u64,
        out: &'out mut [u8],
    ) -> Result<Signed<'source, 'id, 'out>, Error> {
        self.task.check(now)?;
        if out.len() < dv::LEARN_PREFIX {
            return Err(Protocol::Capacity.into());
        }
        let signature = signature(
            completion,
            self.operation,
            self.identity,
            self.task.local(),
            now,
        )?;
        EddsaPublicKey::from_bytes(self.task.local().0).verify(
            dv::INIT_PURPOSE,
            &dv::init_region(self.task.stamp(), &self.challenge),
            signature,
        )?;
        out[..dv::LEARN_PREFIX].copy_from_slice(&dv::initiate(
            self.task.local(),
            self.task.stamp(),
            &self.challenge,
            signature.as_bytes(),
        ));
        Ok(Signed {
            task: self.task,
            bytes: &out[..dv::LEARN_PREFIX],
            successor: None,
        })
    }
    /// Suppress the original typed operation; physical copied/FIFO bytes still
    /// belong to the original client and must actually drain or be closed.
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

/// Immutable actual learning input and selected real next-hop context.
pub struct Forward<'packet> {
    /// Original exact packet with real initiator and every hop verified.
    pub verified: dv::VerifiedLearn<'packet>,
    /// Exact successor covered by the new purpose36 signature.
    pub successor: PeerId,
    /// Actual caller-observed reverse-link availability.
    pub reverse_link: bool,
    /// Original native receive instant, retained across provider queueing.
    /// Sender signed monotime and recipient UTC are not elapsed-time inputs.
    pub received_at: Instant,
}
/// One real original purpose36 operation retaining the exact received frame.
#[must_use = "retain or cancel the original PILS job and its physical FIFO debt"]
pub struct ForwardJob<'source, 'id, 'packet, 'pils> {
    task: Task<'source, 'id>,
    input: Forward<'packet>,
    identity: Identity<'pils>,
    operation: OperationId<'pils>,
}
impl<'source, 'id, 'packet, 'pils> ForwardJob<'source, 'id, 'packet, 'pils> {
    /// Actually admit the exact previous/next/challenge statement. The caller
    /// must already have checked native source, original replay/store admission
    /// and live forwarding intent; VerifiedLearn itself proves signatures only.
    pub fn begin<const N: usize>(
        task: Task<'source, 'id>,
        input: Forward<'packet>,
        client: &mut Client<'pils, N>,
        identity: Identity<'pils>,
        now: u64,
    ) -> Result<Self, Error> {
        task.check(now)?;
        let packet = input.verified.packet();
        if input.verified.local() != task.local() || input.successor == task.local() {
            return Err(Protocol::Authentication.into());
        }
        if packet.hop_count() >= dv::MAX_HOPS {
            return Err(Protocol::TooLarge.into());
        }
        for i in 0..packet.hop_count() {
            if packet.hop(i)?.peer == input.successor {
                return Err(Protocol::Malformed.into());
            }
        }
        if Instant::now()
            .checked_duration_since(input.received_at)
            .is_none()
        {
            return Err(Protocol::InvalidInput.into());
        }
        let target = current(client, identity, task.local(), now)?;
        let region = dv::hop_region(
            input.verified.predecessor(),
            input.successor,
            &packet.challenge()?,
        );
        let operation = client.sign(&region, KeyTarget::Exact(target))?;
        Ok(Self {
            task,
            input,
            identity,
            operation,
        })
    }
    /// Actual original provider operation.
    pub const fn operation(&self) -> OperationId<'pils> {
        self.operation
    }
    /// Original immutable forwarding task identity.
    pub fn token(&self) -> Token<'id> {
        self.task.token()
    }
    /// Verify the actual original purpose36 signature, then append precisely
    /// this hop with native elapsed residence. Output exposure is atomic on error.
    pub fn complete<'out>(
        self,
        completion: &Completion<'pils>,
        now: u64,
        out: &'out mut [u8],
    ) -> Result<Signed<'source, 'id, 'out>, Error> {
        self.task.check(now)?;
        let packet = self.input.verified.packet();
        let size = packet.bytes().len() + dv::HOP_BYTES;
        if out.len() < size {
            return Err(Protocol::Capacity.into());
        }
        let signature = signature(
            completion,
            self.operation,
            self.identity,
            self.task.local(),
            now,
        )?;
        EddsaPublicKey::from_bytes(self.task.local().0).verify(
            dv::HOP_PURPOSE,
            &dv::hop_region(
                self.input.verified.predecessor(),
                self.input.successor,
                &packet.challenge()?,
            ),
            signature,
        )?;
        let elapsed = Instant::now()
            .checked_duration_since(self.input.received_at)
            .ok_or(Protocol::InvalidInput)?;
        let residence = u64::try_from(elapsed.as_micros()).map_err(|_| Protocol::Overflow)?;
        let bytes = packet.forward(
            dv::Hop {
                peer: self.task.local(),
                signature: *signature.as_bytes(),
            },
            self.input.reverse_link,
            residence,
            out,
        )?;
        Ok(Signed {
            task: self.task,
            bytes: &out[..bytes],
            successor: Some(self.input.successor),
        })
    }
    /// Cancel only the actual original typed operation on its original client.
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
