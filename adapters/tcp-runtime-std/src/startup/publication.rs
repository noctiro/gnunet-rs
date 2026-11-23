//! Linear startup composition; it owns no second Pool, FIFO, clock or driver.
use crate::{
    Pool,
    addresses::{self, NatSource, PublishedPool},
    listeners::Listeners,
};
use gnunet_client_host::{EndpointSource, resolution::SharedResolution};
use gnunet_config::Configuration;
use gnunet_nat_client_host as nat;
use gnunet_resolver_broker::LiveConfiguration;
use gnunet_service_runtime::{clock::RuntimeClock, network_change::NetworkChanges};
use gnunet_types::Error;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

pub(super) fn configured_nat_source<'id>(
    instance: &'id nat::Instance,
    live: &LiveConfiguration,
    resolution: SharedResolution,
) -> Result<Option<NatSource<'id>>, addresses::Failure> {
    let config = live.snapshot().map_err(nat::Error::from)?;
    if !has_nat_endpoint(&config) {
        return Ok(None);
    }
    Ok(Some(NatSource {
        instance,
        endpoint: EndpointSource::configuration(config, b"nat", resolution),
    }))
}

fn has_nat_endpoint(config: &Configuration) -> bool {
    let section = b"nat";
    config.get(section, b"UNIXPATH").is_some()
        || (config.get(section, b"HOSTNAME").is_some()
            && config.get(section, b"PORT").is_some()
            && !matches!(config.get_number(section, b"PORT"), Ok(0)))
}

pub(super) struct Owner<'id, 'pool, 'listen> {
    published: Option<PublishedPool<'id, 'pool, 'listen>>,
    returned: Option<Box<Pool<'pool>>>,
    retiring: bool,
    retry_at: Option<Instant>,
    retry_delay: Duration,
    retry: Option<Pin<Box<Sleep>>>,
    retry_failure: Option<addresses::Failure>,
}
impl<'id, 'pool, 'listen> Owner<'id, 'pool, 'listen> {
    pub(super) fn retain_identity_resources(
        self,
    ) -> Result<(Owner<'id, 'static, 'listen>, crate::epoch::Quiescent), addresses::Failure> {
        let Self {
            published,
            returned,
            retiring,
            retry_at,
            retry_delay,
            retry,
            retry_failure,
        } = self;
        if returned.is_some()
            || retiring
            || published.as_ref().is_none_or(PublishedPool::is_retiring)
        {
            return Err(Error::NotReady.into());
        }
        let (published, proof) = published
            .ok_or(Error::NotReady)?
            .retain_identity_resources()
            .map_err(|rejected| rejected.reason)?;
        Ok((
            Owner {
                published: Some(published),
                returned: None,
                retiring,
                retry_at,
                retry_delay,
                retry,
                retry_failure,
            },
            proof,
        ))
    }
    pub(super) fn try_adopt(
        original: &mut Option<Pool<'pool>>,
        listeners: &'listen Listeners,
        nat: Option<NatSource<'id>>,
        clock: Arc<dyn RuntimeClock>,
        disable_v6: bool,
    ) -> Result<Self, addresses::Failure> {
        let published = PublishedPool::try_adopt_with_nat(
            original,
            listeners,
            nat,
            clock,
            addresses::Options {
                until: u64::MAX,
                send_timeout: Duration::from_secs(30),
                scan_interval: Duration::from_secs(30),
                freshness: Duration::from_secs(90),
                retirement: Duration::from_secs(30),
                disable_v6,
            },
            addresses::Limits::default(),
        )?;
        Ok(Self {
            published: Some(published),
            returned: None,
            retiring: false,
            retry_at: None,
            retry_delay: Duration::from_secs(1),
            retry: None,
            retry_failure: None,
        })
    }
    /// Failed adoption leaves exactly this original Pool available for cleanup.
    pub(super) fn unpublished(original: Pool<'pool>) -> Self {
        Self {
            published: None,
            returned: Some(Box::new(original)),
            retiring: true,
            retry_at: None,
            retry_delay: Duration::from_secs(1),
            retry: None,
            retry_failure: None,
        }
    }
    pub(super) fn pool_mut(&mut self) -> Option<&mut Pool<'pool>> {
        match &mut self.published {
            Some(owner) => owner.pool_mut(),
            None => self.returned.as_deref_mut(),
        }
    }
    pub(super) fn published_mut(&mut self) -> Option<&mut PublishedPool<'id, 'pool, 'listen>> {
        self.published.as_mut()
    }
    pub(super) fn has_addresses(&self) -> bool {
        self.published.is_some()
    }
    pub(super) fn has_pool(&mut self) -> bool {
        self.pool_mut().is_some()
    }
    pub(super) fn retained_input_idle(&self) -> bool {
        self.published
            .as_ref()
            .is_some_and(PublishedPool::retained_input_idle)
    }
    pub(super) fn is_retiring(&self) -> bool {
        self.retiring
            || self
                .published
                .as_ref()
                .is_some_and(PublishedPool::is_retiring)
    }
    pub(super) fn is_returned(&self) -> bool {
        self.published.is_none() && self.returned.is_some()
    }
    pub(super) fn begin_close(&mut self) {
        self.retiring = true;
        self.retry_at = None;
        self.retry = None;
        if let Some(owner) = &mut self.published {
            owner.begin_close();
        }
    }
    pub(super) fn abort(&mut self) {
        self.begin_close();
        if let Some(owner) = &mut self.published {
            owner.abort();
        } else {
            self.returned = None;
        }
    }
    pub(super) fn take_pool(&mut self) -> Option<Pool<'pool>> {
        if self.published.is_some() {
            return None;
        }
        self.returned.take().map(|pool| *pool)
    }
    fn later(&mut self) {
        self.retry_at = Instant::now().checked_add(self.retry_delay);
        self.retry_delay = self
            .retry_delay
            .saturating_mul(2)
            .min(Duration::from_secs(60));
        if self.retry_at.is_none() {
            self.retry_failure = Some(addresses::Failure::Protocol(Error::Overflow));
        }
    }
    /// The caller supplies the existing permanent Stop/Logger fence. No retry
    /// after that fence can create another NAT source or inherit an old WriteId.
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        allow_restart: bool,
        changes: &mut NetworkChanges,
    ) -> Poll<addresses::Event<'id>> {
        if !allow_restart {
            self.begin_close();
        }
        if let Some(error) = self.retry_failure.take() {
            self.begin_close();
            return Poll::Ready(addresses::Event::Failed(error));
        }
        if let Some(at) = self.retry_at
            && !self.is_retiring()
            && allow_restart
        {
            let timer = self
                .retry
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            timer.as_mut().reset(at);
            if timer.as_mut().poll(cx).is_ready() {
                self.retry_at = None;
                if let Some(owner) = &mut self.published {
                    match owner.restart_nat() {
                        Ok(()) => {}
                        Err(addresses::Failure::Protocol(Error::Conflict)) => self.later(),
                        Err(error) => {
                            self.begin_close();
                            return Poll::Ready(addresses::Event::Failed(error));
                        }
                    }
                }
            }
        }
        let Some(owner) = &mut self.published else {
            return Poll::Pending;
        };
        let event = match owner.poll(cx, changes) {
            Poll::Ready(event) => event,
            Poll::Pending => return Poll::Pending,
        };
        match &event {
            addresses::Event::Nat(nat::Progress::Ended(_))
                if !owner.is_retiring() && allow_restart =>
            {
                // poll has consumed the exact old End. The owner's restart
                // gate also requires every unsupported old row's actual DEL
                // admission before a fresh registration can be constructed.
                self.later();
            }
            addresses::Event::Nat(nat::Progress::Connected(..)) => {
                self.retry_delay = Duration::from_secs(1)
            }
            addresses::Event::Closed => {
                let pool = match owner.take_pool() {
                    Ok(pool) => pool,
                    Err(error) => {
                        owner.abort();
                        self.retiring = true;
                        self.retry_at = None;
                        return Poll::Ready(addresses::Event::Failed(error.into()));
                    }
                };
                self.returned = Some(Box::new(pool));
                self.published = None;
                self.retiring = true;
                self.retry_at = None;
            }
            _ => {}
        }
        Poll::Ready(event)
    }
}

impl<'id, 'listen> Owner<'id, 'static, 'listen> {
    pub(super) fn resume_identity<'next>(
        self,
        setup: crate::Setup<'next, ()>,
    ) -> Result<Owner<'id, 'next, 'listen>, addresses::Failure> {
        let Self {
            published,
            returned,
            retiring,
            retry_at,
            retry_delay,
            retry,
            retry_failure,
        } = self;
        if returned.is_some()
            || retiring
            || published.as_ref().is_none_or(PublishedPool::is_retiring)
        {
            return Err(Error::NotReady.into());
        }
        let published = published.ok_or(Error::NotReady)?.resume_identity(setup)?;
        Ok(Owner {
            published: Some(published),
            returned: None,
            retiring,
            retry_at,
            retry_delay,
            retry,
            retry_failure,
        })
    }
}

pub(super) fn poll_retained<'id>(
    retained: &mut Option<Owner<'id, 'static, '_>>,
    cx: &mut Context<'_>,
    changes: &mut NetworkChanges,
    observe: &mut dyn FnMut(&addresses::Event<'id>),
) -> Result<bool, super::Failure> {
    let Some(owner) = retained else {
        return Ok(false);
    };
    let Poll::Ready(event) = owner.poll(cx, true, changes) else {
        return Ok(false);
    };
    observe(&event);
    match event {
        addresses::Event::Failed(error) => Err(Box::new(error)),
        addresses::Event::Aborted | addresses::Event::Closed => Err(Error::Closed.into()),
        addresses::Event::Nat(nat::Progress::Ended(end))
            if matches!(
                &end.source.cause,
                nat::Cause::Clock(_) | nat::Cause::Error(nat::Error::Clock(_))
            ) =>
        {
            Err(Box::new(super::generation::NatClockFailure(
                end.source.cause,
            )))
        }
        addresses::Event::ReverseReady(notification) => {
            owner
                .published_mut()
                .ok_or(Error::NotReady)?
                .release_reverse(&notification)?;
            Ok(true)
        }
        _ => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_endpoint_skips_nat_and_a_configured_endpoint_keeps_validation()
    -> Result<(), gnunet_config::Error> {
        let mut config = Configuration::default();
        let section = b"nat";
        let mut observed = vec![has_nat_endpoint(&config)];
        config.set_value(section, b"HOSTNAME", Some(b"localhost"))?;
        observed.push(has_nat_endpoint(&config));
        config.set_number(section, b"PORT", 0)?;
        observed.push(has_nat_endpoint(&config));
        config.set_number(section, b"PORT", 2086)?;
        observed.push(has_nat_endpoint(&config));
        config.set_value(section, b"PORT", Some(b"invalid"))?;
        observed.push(has_nat_endpoint(&config));
        config.set_value(section, b"HOSTNAME", None)?;
        observed.push(has_nat_endpoint(&config));
        config.set_value(section, b"UNIXPATH", Some(b""))?;
        observed.push(has_nat_endpoint(&config));
        if observed != [false, false, false, true, true, false, true] {
            return Err(gnunet_config::Error::InvalidValue);
        }
        Ok(())
    }
}
