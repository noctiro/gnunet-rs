//! Actual caller-driven PILS signing for one original REGEX signing job.
//!
//! No private key is opened, derived or retained here. One real PILS operation
//! is bound to the exact current announcement and its original REGEX job. A
//! result remains held until the original copied frame is quiescent. Canceling
//! a wait future preserves that operation, result and partial native cursor.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_pils::{
    HelloLimits, Profile,
    client::{Completion, Failure, Inbound, Instance, KeyTarget, OperationId},
};
use gnunet_pils_host::client::{Client, EndpointSource, Error, Progress};
use gnunet_types::Error as ProtocolError;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;

/// Actual public signature bytes from the matching original PILS completion.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// Actual returned signer; never relabeled as a newer announcement.
    pub peer: EddsaPublicKey,
    /// Signature over the exact original eighty-byte purpose region.
    pub signature: EddsaSignature,
}
/// One actual signer observation; these are local API events, never REGEX wire
/// acknowledgements, publication receipts or search completion frames.
#[must_use = "original results and retirement coordinates must be settled"]
#[expect(
    clippy::large_enum_variant,
    reason = "Return the bounded original PILS loss/completion owner without allocating after native response consumption or retirement"
)]
pub enum Event<'a, T> {
    /// Actual verified PILS identity update. An outer coordinator must update
    /// the REGEX identity generation once for this event, not once per poll.
    Identity {
        /// Actual public peer identity.
        peer: EddsaPublicKey,
        /// Whether the public key differs from the previous observation.
        changed: bool,
    },
    /// Exact original result and native quiescence have both been observed.
    Complete {
        /// Original caller token moved out of the retained operation.
        job: T,
        /// Real signature or the original PILS crypto refusal.
        result: Result<Signature, Failure>,
    },
    /// Canceled original work is now locally quiescent. This does not revoke a
    /// signature already produced by the peer or promise any remote erasure.
    Retired(T),
    /// A real response was consumed and retained while its original copied
    /// request cursor is still draining. No completion is exposed yet.
    ResultHeld,
    /// Original physical-MQ progress, retry or error observation. Connected/Lost
    /// must invalidate the outer REGEX identity observation before new jobs.
    Transport(Progress<'a, 1>),
}
struct Pending<'a, T> {
    job: T,
    operation: OperationId<'a>,
    cancelled: bool,
    result: Option<Result<Signature, Failure>>,
}
/// One explicitly owned native PILS client and one original REGEX signing job.
/// Tokens may be opaque branded REGEX JobIds; equality never uses numeric ids.
/// No detached task, hidden Resolver, persisted key or local signing fallback is
/// created. The caller drives the same owner through cancellation and shutdown.
pub struct Signer<'a, T> {
    client: Client<'a, 1>,
    pending: Option<Pending<'a, T>>,
    closed: bool,
}
impl<'a, T: Eq> Signer<'a, T> {
    /// Construct the actual PILS owner using the caller's source, process clock,
    /// profile and bounded HELLO parser. No socket or product code runs until
    /// this owner is driven by its caller.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        profile: Profile,
        hello: HelloLimits,
    ) -> Result<Self, Error> {
        let limits = gnunet_pils_host::client::Limits {
            pending_operations: 1,
            ..Default::default()
        };
        Ok(Self {
            client: Client::new(instance, source, profile, limits, hello)?,
            pending: None,
            closed: false,
        })
    }
    /// Same actual process clock used by this original PILS client. Cloning the
    /// Arc reserves no new waiter or native source.
    #[must_use]
    pub fn clock(&self) -> std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.client.clock()
    }
    /// Latest actual verified public observation, available only while current
    /// on this original PILS MQ. It is not global key or service authorization.
    #[must_use]
    pub fn peer(&self) -> Option<EddsaPublicKey> {
        self.client.identity().map(|identity| identity.peer())
    }
    /// Whether a REGEX signing job is retained, including cancellation/result
    /// debt that still owns an original native copied frame.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.pending.is_some()
    }
    /// Submit exactly one original purpose18/size80 region under the exact
    /// current PILS identity. Refusal does not consume the caller's token.
    pub fn submit(
        &mut self,
        job: T,
        peer: EddsaPublicKey,
        material: &[u8; 80],
    ) -> Result<(), (T, Error)> {
        let admitted = (|| {
            if self.closed {
                return Err(ProtocolError::Closed.into());
            }
            if self.pending.is_some() || !self.client.is_idle() {
                return Err(ProtocolError::NotReady.into());
            }
            if material[..4] != 80_u32.to_be_bytes() || material[4..8] != 18_u32.to_be_bytes() {
                return Err(ProtocolError::InvalidInput.into());
            }
            let identity = self.client.identity().ok_or(ProtocolError::NotReady)?;
            if identity.peer() != peer {
                return Err(ProtocolError::Stale.into());
            }
            self.client.sign(material, KeyTarget::Exact(identity))
        })();
        match admitted {
            Ok(operation) => {
                self.pending = Some(Pending {
                    job,
                    operation,
                    cancelled: false,
                    result: None,
                });
                Ok(())
            }
            Err(error) => Err((job, error)),
        }
    }
    /// Suppress only this exact original job. Already copied native bytes remain
    /// owned until drive observes quiescence or close retires the actual MQ.
    pub fn cancel(&mut self, job: &T) -> Result<(), Error> {
        let pending = self.pending.as_mut().ok_or(ProtocolError::Stale)?;
        if &pending.job != job {
            return Err(ProtocolError::Stale.into());
        }
        if !pending.cancelled {
            if pending.result.is_none() {
                self.client.cancel(pending.operation)?;
            }
            pending.cancelled = true;
            pending.result = None;
        }
        Ok(())
    }
    fn completed(&mut self) -> Result<Option<Event<'a, T>>, Error> {
        let Some(pending) = &self.pending else {
            return Ok(None);
        };
        if (!pending.cancelled && pending.result.is_none())
            || !self.client.operation_quiescent(pending.operation)?
        {
            return Ok(None);
        }
        let pending = self.pending.take().ok_or(ProtocolError::Stale)?;
        Ok(Some(if pending.cancelled {
            Event::Retired(pending.job)
        } else {
            Event::Complete {
                job: pending.job,
                result: pending.result.ok_or(ProtocolError::NotReady)?,
            }
        }))
    }
    /// Poll the same actual owner, preserving all native cursors across a
    /// pending observation. The wait deadline does not cancel the original job.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Event<'a, T>, Error>> {
        match self.completed() {
            Ok(Some(event)) => return Poll::Ready(Ok(event)),
            Ok(None) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        let progress = {
            let original = self.client.drive(deadline);
            std::pin::pin!(original).poll(cx)
        };
        match progress {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(progress)) => Poll::Ready(self.observe(progress)),
        }
    }
    /// Wait on that same polled client; dropping this wait changes no operation
    /// ownership, original target, result retention or native partial cursor.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Event<'a, T>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
    fn observe(&mut self, progress: Progress<'a, 1>) -> Result<Event<'a, T>, Error> {
        match progress {
            Progress::Inbound(Inbound::Identity {
                identity,
                identity_changed,
                ..
            }) => Ok(Event::Identity {
                peer: identity.peer(),
                changed: identity_changed,
            }),
            Progress::Inbound(Inbound::Complete(completion)) => {
                let pending = self.pending.as_mut().ok_or(ProtocolError::Stale)?;
                if completion.operation() != pending.operation || pending.result.is_some() {
                    return Err(ProtocolError::Stale.into());
                }
                let result = match completion {
                    Completion::Signature {
                        peer, signature, ..
                    } => Ok(Signature { peer, signature }),
                    Completion::Failed { reason, .. } => Err(reason),
                    Completion::Decapsulated { .. } | Completion::Ecdh { .. } => {
                        return Err(ProtocolError::Malformed.into());
                    }
                };
                if !pending.cancelled {
                    pending.result = Some(result);
                }
                Ok(self.completed()?.unwrap_or(Event::ResultHeld))
            }
            progress => Ok(Event::Transport(progress)),
        }
    }
    /// Close original native attempts/stream/cursors before retiring this one
    /// retained caller token. No kernel-close errno or remote cancel is claimed.
    pub fn close(&mut self) -> Option<T> {
        let _original_operations = self.client.close();
        self.closed = true;
        self.pending.take().map(|pending| pending.job)
    }
}
impl<T> Drop for Signer<'_, T> {
    fn drop(&mut self) {
        let _original_operations = self.client.close();
    }
}
