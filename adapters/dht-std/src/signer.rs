//! One original PILS signature and its actual copied-frame retirement debt.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_dht::network::Job;
use gnunet_pils::{
    HelloLimits, Profile,
    client::{Completion, Failure, Identity, Inbound, Instance, KeyTarget, OperationId},
};
use gnunet_pils_host::client::{Client, EndpointSource, Error, Limits, Progress};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// One original user of the shared PILS queue; a HELLO has no DHT path job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Target<'id> {
    Path(Job<'id>),
    OwnHello(u64),
}
pub(crate) enum Guard<'id> {
    Cancel(Target<'id>),
    Retired(Target<'id>),
    SourceEnd(Option<Target<'id>>),
}
pub(crate) enum Event<'id> {
    Identity {
        identity: Identity<'id>,
    },
    Complete {
        target: Target<'id>,
        operation: OperationId<'id>,
        identity: Identity<'id>,
        result: Result<(EddsaPublicKey, EddsaSignature), Failure>,
    },
    Retired(Target<'id>),
    Held,
    Source(Progress<'id, 1>),
}
struct Input {
    until: u64,
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
struct Pending<'id> {
    target: Target<'id>,
    identity: Identity<'id>,
    operation: OperationId<'id>,
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
    cancelled: bool,
    retirement: Option<Instant>,
    result: Option<Result<(EddsaPublicKey, EddsaSignature), Failure>>,
}
pub(crate) struct Signer<'id> {
    client: Client<'id, 1>,
    pending: Option<Pending<'id>>,
    closed: bool,
    grace: Duration,
    input_life: Duration,
    input: Option<Input>,
}
impl<'id> Signer<'id> {
    pub fn new(
        instance: &'id mut Instance,
        source: EndpointSource,
        profile: Profile,
        mut limits: Limits,
        hello: HelloLimits,
        grace: Duration,
        input_life: Duration,
    ) -> Result<Self, Error> {
        limits.pending_operations = 1;
        Ok(Self {
            client: Client::new(instance, source, profile, limits, hello)?,
            pending: None,
            closed: false,
            grace,
            input_life,
            input: None,
        })
    }
    pub fn identity(&self) -> Option<Identity<'id>> {
        self.client.identity()
    }
    pub fn announcement(&self) -> Option<&[u8]> {
        self.client.announcement()
    }
    pub fn idle(&self) -> bool {
        !self.closed && self.pending.is_none() && self.client.is_idle()
    }
    pub fn start(
        &mut self,
        job: Job<'id>,
        peer: EddsaPublicKey,
        material: &[u8; gnunet_dht::path::SIGNED_LEN],
        hard: Instant,
    ) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if !self.idle() {
            return Err(Fault::WouldBlock.into());
        }
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        if material[..4] != (gnunet_dht::path::SIGNED_LEN as u32).to_be_bytes()
            || material[4..8] != gnunet_dht::path::PURPOSE.to_be_bytes()
        {
            return Err(Fault::InvalidInput.into());
        }
        let identity = self.client.identity().ok_or(Fault::NotReady)?;
        if identity.peer() != peer {
            return Err(Fault::Authentication.into());
        }
        // Native/clock setup may consume time; the same hard is checked again
        // immediately before the actual original operation is admitted.
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let operation = self.client.sign(material, KeyTarget::Exact(identity))?;
        self.pending = Some(Pending {
            target: Target::Path(job),
            identity,
            operation,
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
            cancelled: false,
            retirement: None,
            result: None,
        });
        Ok(())
    }
    pub fn start_hello(
        &mut self,
        revision: u64,
        identity: Identity<'id>,
        builder: &gnunet_hello::HelloBuilder<'_>,
        expiration: AbsoluteTime,
        hard: Instant,
    ) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if !self.idle() {
            return Err(Fault::WouldBlock.into());
        }
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        if revision == 0 || self.client.identity() != Some(identity) {
            return Err(Fault::StaleGeneration.into());
        }
        // This is a real purpose7 request on the same original PILS client.
        // No FEED/global identity change or second signing client is involved.
        let operation = self
            .client
            .sign_hello(builder, expiration, KeyTarget::Exact(identity))?;
        self.pending = Some(Pending {
            target: Target::OwnHello(revision),
            identity,
            operation,
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
            cancelled: false,
            retirement: None,
            result: None,
        });
        Ok(())
    }
    pub fn cancel(&mut self, target: Target<'id>) -> Result<(), Error> {
        let pending = self.pending.as_mut().ok_or(Fault::Stale)?;
        if pending.target != target {
            return Err(Fault::Stale.into());
        }
        if !pending.cancelled {
            // A result already held still owns its old copied frame. It needs
            // quiescence, not a second cancel of a completed logical operation.
            if pending.result.is_none() {
                self.client.cancel(pending.operation)?;
            }
            pending.cancelled = true;
            let until = Instant::now()
                .checked_add(self.grace)
                .ok_or(Fault::Overflow)?;
            pending.retirement = Some(until);
            pending.alarm.as_mut().reset(until);
            pending.result = None;
        }
        Ok(())
    }
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Guard<'id>> {
        if self.closed {
            return None;
        }
        if self
            .input
            .as_mut()
            .is_some_and(|i| Instant::now() >= i.hard || i.alarm.as_mut().poll(cx).is_ready())
        {
            return Some(Guard::SourceEnd(self.close()));
        }
        let pending = self.pending.as_mut()?;
        if pending.cancelled {
            if pending
                .retirement
                .is_some_and(|hard| Instant::now() >= hard)
                || pending.alarm.as_mut().poll(cx).is_ready()
            {
                return self.close().map(Guard::Retired);
            }
            return None;
        }
        if Instant::now() >= pending.hard || pending.alarm.as_mut().poll(cx).is_ready() {
            return Some(Guard::Cancel(pending.target));
        }
        None
    }
    fn completed(&mut self) -> Result<Option<Event<'id>>, Error> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(None);
        };
        if (!pending.cancelled && pending.result.is_none())
            || !self.client.operation_quiescent(pending.operation)?
        {
            return Ok(None);
        }
        let pending = self.pending.take().ok_or(Fault::Stale)?;
        Ok(Some(if pending.cancelled {
            Event::Retired(pending.target)
        } else {
            Event::Complete {
                target: pending.target,
                operation: pending.operation,
                identity: pending.identity,
                result: pending.result.ok_or(Fault::NotReady)?,
            }
        }))
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Event<'id>, Error>> {
        if let Some(event) = self.completed()? {
            return Poll::Ready(Ok(event));
        }
        if let Some(input) = self.input.as_ref()
            && (Instant::now() >= input.hard
                || self.client.clock().sample()?.now.as_micros() >= input.until)
        {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        let started = Instant::now();
        let event = {
            let mut driving = std::pin::pin!(self.client.drive(wait));
            match driving.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
        };
        if matches!(&event, Progress::Inbound(_) | Progress::Lost { .. }) {
            self.input = None;
        }
        if matches!(&event,Progress::Activity{read_bytes,..} if *read_bytes>0)
            && self.input.is_none()
        {
            let hard = started
                .checked_add(self.input_life)
                .ok_or(Fault::Overflow)?;
            let delta = u64::try_from(self.input_life.as_micros()).map_err(|_| Fault::Overflow)?;
            let until = self
                .client
                .clock()
                .sample()?
                .now
                .as_micros()
                .checked_add(delta)
                .filter(|n| *n != u64::MAX)
                .ok_or(Fault::Overflow)?;
            self.input = Some(Input {
                hard,
                until,
                alarm: Box::pin(tokio::time::sleep_until(hard)),
            });
        }
        match event {
            Progress::Inbound(Inbound::Identity { identity, .. }) => {
                Poll::Ready(Ok(Event::Identity { identity }))
            }
            Progress::Inbound(Inbound::Complete(completion)) => {
                let pending = self.pending.as_mut().ok_or(Fault::Stale)?;
                if completion.operation() != pending.operation || pending.result.is_some() {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                let result = match completion {
                    Completion::Signature {
                        peer, signature, ..
                    } => Ok((peer, signature)),
                    Completion::Failed { reason, .. } => Err(reason),
                    Completion::Decapsulated { .. } | Completion::Ecdh { .. } => {
                        return Poll::Ready(Err(Fault::Malformed.into()));
                    }
                };
                if !pending.cancelled {
                    pending.result = Some(result);
                }
                Poll::Ready(self.completed().map(|event| event.unwrap_or(Event::Held)))
            }
            other => Poll::Ready(Ok(Event::Source(other))),
        }
    }
    /// Physical close first, then release the exact original pending token.
    /// This does not assert that a remote signature was never produced.
    pub fn close(&mut self) -> Option<Target<'id>> {
        let _original = self.client.close();
        self.closed = true;
        self.input = None;
        self.pending.take().map(|p| p.target)
    }
}
