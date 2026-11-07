//! Linear startup composition; it owns no second Pool, FIFO, clock or driver.
use crate::{
    Pool,
    addresses::{self, PublishedPool},
    listeners::Listeners,
};
use gnunet_client_host::EndpointSource;
use gnunet_nat_client_host as nat;
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

pub(super) struct Owner<'id, 'pool, 'listen> {
    published: Option<PublishedPool<'id, 'pool, 'listen>>,
    returned: Option<Pool<'pool>>,
    retiring: bool,
    retry_at: Option<Instant>,
    retry_delay: Duration,
    retry: Pin<Box<Sleep>>,
    retry_failure: Option<addresses::Failure>,
}
impl<'id, 'pool, 'listen> Owner<'id, 'pool, 'listen> {
    pub(super) fn try_adopt(
        original: &mut Option<Pool<'pool>>,
        listeners: &'listen Listeners,
        instance: &'id nat::Instance,
        source: EndpointSource,
        clock: Arc<dyn RuntimeClock>,
        disable_v6: bool,
    ) -> Result<Self, addresses::Failure> {
        // Empty timers/metadata are reserved before the linear original take.
        let retry = Box::pin(tokio::time::sleep(Duration::from_secs(1)));
        let published = PublishedPool::try_adopt(
            original,
            listeners,
            instance,
            source,
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
            retry,
            retry_failure: None,
        })
    }
    /// Failed adoption leaves exactly this original Pool available for cleanup.
    pub(super) fn unpublished(original: Pool<'pool>) -> Self {
        Self {
            published: None,
            returned: Some(original),
            retiring: true,
            retry_at: None,
            retry_delay: Duration::from_secs(1),
            retry: Box::pin(tokio::time::sleep(Duration::from_secs(1))),
            retry_failure: None,
        }
    }
    pub(super) fn pool_mut(&mut self) -> Option<&mut Pool<'pool>> {
        match &mut self.published {
            Some(owner) => owner.pool_mut(),
            None => self.returned.as_mut(),
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
        self.returned.take()
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
            self.retry.as_mut().reset(at);
            if self.retry.as_mut().poll(cx).is_ready() {
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
        let event = match owner.poll(cx) {
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
                self.returned = Some(pool);
                self.published = None;
                self.retiring = true;
                self.retry_at = None;
            }
            _ => {}
        }
        Poll::Ready(event)
    }
}
