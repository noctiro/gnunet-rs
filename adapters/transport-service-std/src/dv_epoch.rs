//! Actual PILS bootstrap for one independent DV actor source. The enclosing
//! session must drive Owner/Resolver/signals fairly while polling this owner.
//! No local key, FEED reset, crypto substitute or storage worker is constructed.
use crate::{Failure, owner::Owner, sender::DvScope, settings::Settings, time::Bounds};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::Entropy;
use gnunet_pils::client::{Identity, Instance};
use gnunet_pils_host::client::{Client, Progress};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

#[derive(Debug)]
struct SourceLoss(gnunet_pils_host::client::LossCause);
impl std::fmt::Display for SourceLoss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DV original PILS source lost: {:?}", self.0)
    }
}
impl std::error::Error for SourceLoss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use gnunet_pils_host::client::LossCause;
        match &self.0 {
            LossCause::Io(error) => Some(error),
            LossCause::Protocol(error) | LossCause::Resource(error) => Some(error),
            LossCause::Setup(error) => Some(error),
            LossCause::Eof | LossCause::Requested => None,
        }
    }
}

/// One actual ready native source, its matching original Engine scope and
/// unchanged source targets. Private construction requires real announcements.
pub struct Ready<'pils, 'owner> {
    client: Client<'pils, 32>,
    identity: Identity<'pils>,
    scope: DvScope<'owner>,
    source: Bounds,
}
impl<'pils, 'owner> Ready<'pils, 'owner> {
    /// Actual independent PILS source observation, not the Owner's MQ epoch.
    pub fn identity(&self) -> Identity<'pils> {
        self.identity
    }
    /// Actual Engine allocation checked at ready admission.
    pub fn scope(&self) -> &DvScope<'owner> {
        &self.scope
    }
    /// Original source targets, including time spent connecting and waiting.
    pub fn source_bounds(&self) -> Bounds {
        self.source
    }
    /// Transfer the original actual client once. Runtime construction must
    /// retain these source targets and recheck the current exact Owner scope.
    pub fn into_parts(self) -> (Client<'pils, 32>, DvScope<'owner>, Bounds) {
        (self.client, self.scope, self.source)
    }
}

/// Explicitly polled actual source attachment and initial public announcement.
/// It owns one native client, never an MQ per neighbour or an autonomous task.
#[must_use = "poll or close the original source; dropping it cannot yield Ready"]
pub struct Bootstrap<'pils> {
    client: Option<Client<'pils, 32>>,
    clock: Arc<dyn RuntimeClock>,
    source: Bounds,
    initial: Bounds,
    partial: Option<Instant>,
    input: Duration,
    alarm: Option<Pin<Box<Sleep>>>,
}
fn original_bounds(start: Instant, now: u64, duration: Duration) -> Result<Bounds, Error> {
    let us = u64::try_from(duration.as_micros()).map_err(|_| Error::Overflow)?;
    if us == 0 {
        return Err(Error::InvalidInput);
    }
    Ok(Bounds {
        expires: now
            .checked_add(us)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Overflow)?,
        hard: start.checked_add(duration).ok_or(Error::Overflow)?,
    })
}
impl<'pils> Bootstrap<'pils> {
    /// Capture both original budgets before client construction. Only the real
    /// supplied CLIENT source and explicit configured PILS profile are used.
    pub fn new(
        instance: &'pils mut Instance,
        endpoint: EndpointSource,
        settings: &Settings,
    ) -> Result<Self, Failure> {
        let start = Instant::now();
        let clock = endpoint.clock();
        let now = clock.sample()?.now.as_micros();
        let source = original_bounds(start, now, settings.pils.source)?;
        let mut initial = original_bounds(start, now, settings.pils.initial)?;
        initial.expires = initial.expires.min(source.expires);
        initial.hard = initial.hard.min(source.hard);
        if !initial.live(now) || settings.pils.input.is_zero() {
            return Err(Error::Deadline.into());
        }
        let mut client = Client::new(
            instance,
            endpoint,
            settings.profile,
            settings.pils.client,
            settings.publication.hello,
        )?;
        if Instant::now() >= initial.hard {
            let _original = client.close();
            return Err(Error::Deadline.into());
        }
        Ok(Self {
            client: Some(client),
            clock,
            source,
            initial,
            partial: None,
            input: settings.pils.input,
            alarm: None,
        })
    }
    fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        let hard = self
            .partial
            .map_or(self.initial.hard, |at| at.min(self.initial.hard));
        if Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(hard)));
        alarm.as_mut().reset(hard);
        let _registered = alarm.as_mut().poll(cx);
        Ok(())
    }
    fn ready<'owner, E: Entropy>(
        &mut self,
        owner: &Owner<'owner, E>,
    ) -> Result<Option<Ready<'pils, 'owner>>, Failure> {
        let Some(client) = self.client.as_ref() else {
            return Err(Error::Closed.into());
        };
        // A previously observed identity does not make the next partially
        // received frame quiescent. Keep its original first-byte deadline
        // here instead of handing it to a Runtime with an empty partial timer.
        if self.partial.is_some() {
            return Ok(None);
        }
        let Some(identity) = client.identity() else {
            return Ok(None);
        };
        let (Some(scope), Some(current)) = (owner.dv_scope(), owner.dv_identity()) else {
            return Ok(None);
        };
        if !Arc::ptr_eq(&self.clock, &owner.dv_clock()) {
            return Err(Error::InvalidInput.into());
        }
        if identity.peer() != current.peer() || !client.is_idle() {
            return Ok(None);
        }
        // These are DIFFERENT actual MQs. Compare peer identity, never equate
        // their epochs, revisions or operation ledgers merely from peer bytes.
        if client.epoch() != Some(identity.epoch()) {
            return Err(Error::Stale.into());
        }
        if Instant::now() >= self.initial.hard {
            return Err(Error::Deadline.into());
        }
        let now = self.clock.sample()?.now.as_micros();
        if !self.initial.live(now)
            || !self.source.live(now)
            || now >= identity.expiration().as_micros()
            || now >= current.expiration().as_micros()
        {
            return Err(Error::Deadline.into());
        }
        // The ready PILS observer alone cannot move a native partial frame
        // into a new Actor allocation. Keep this same bootstrap/client and its
        // original initial/source/input targets while Owner fairly drives that
        // original input to a complete ordinary frame or physical retirement.
        if !owner.dv_source_attach_ready(&scope)? {
            return Ok(None);
        }
        let client = self.client.take().ok_or(Error::Closed)?;
        self.alarm = None;
        Ok(Some(Ready {
            client,
            identity,
            scope,
            source: self.source,
        }))
    }
    /// Drive at most one real native progress item. Call after the enclosing
    /// Owner/Resolver guards; native deadlines always precede logical sampling.
    pub fn poll<'owner, E: Entropy>(
        &mut self,
        cx: &mut Context<'_>,
        owner: &Owner<'owner, E>,
    ) -> Poll<Result<Ready<'pils, 'owner>, Failure>> {
        let result = (|| {
            if self.client.is_none() {
                return Err(Error::Closed.into());
            }
            self.native_guard(cx)?;
            let now = self.clock.sample()?.now.as_micros();
            if !self.initial.live(now) || !self.source.live(now) {
                return Err(Error::Deadline.into());
            }
            if let Some(ready) = self.ready(owner)? {
                return Ok(Some(ready));
            }
            let progress = {
                let client = self.client.as_mut().ok_or(Error::Closed)?;
                let wait = client.drive(None);
                let mut wait = std::pin::pin!(wait);
                wait.as_mut().poll(cx)
            };
            match progress {
                Poll::Pending => return Ok(None),
                Poll::Ready(Err(error)) => return Err(Box::new(error) as Failure),
                Poll::Ready(Ok(Progress::Lost { cause, .. })) => {
                    return Err(Box::new(SourceLoss(cause)));
                }
                Poll::Ready(Ok(Progress::ConnectRetry { error, .. })) => return Err(error.into()),
                Poll::Ready(Ok(Progress::Unavailable(error))) => return Err(Box::new(error)),
                Poll::Ready(Ok(Progress::Closed)) => return Err(Error::Closed.into()),
                Poll::Ready(Ok(Progress::Activity { read_bytes, .. })) => {
                    if read_bytes != 0 && self.partial.is_none() {
                        self.partial = Some(
                            Instant::now()
                                .checked_add(self.input)
                                .ok_or(Error::Overflow)?
                                .min(self.initial.hard),
                        );
                    }
                }
                Poll::Ready(Ok(Progress::Inbound(_))) => self.partial = None,
                Poll::Ready(Ok(_)) => {}
            }
            self.native_guard(cx)?;
            if let Some(ready) = self.ready(owner)? {
                return Ok(Some(ready));
            }
            // Actual consumed progress may leave another buffered native item;
            // register a continuation without spinning on an idle port.
            cx.waker().wake_by_ref();
            Ok(None)
        })();
        match result {
            Ok(Some(ready)) => Poll::Ready(Ok(ready)),
            Ok(None) => Poll::Pending,
            Err(error) => {
                self.close();
                Poll::Ready(Err(error))
            }
        }
    }
    /// Physically close this original client without sampling a clock. No
    /// admitted crypto mutation or worker debt is hidden in bootstrap.
    pub fn close(&mut self) {
        if let Some(mut client) = self.client.take() {
            let _original = client.close();
        }
        self.alarm = None;
        self.partial = None;
    }
}
