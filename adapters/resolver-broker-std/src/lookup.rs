//! Official CLIENT resolution port, sharing this core and retained DNS lifetime.
use crate::{BrokerError, Context, Query};
use gnunet_client_host::resolution::{
    AddressLookup, ResolutionContext, ResolutionTimer, SharedResolution,
};
use gnunet_types::{Duration as CoreDuration, Error};
use std::{
    io,
    net::IpAddr,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
struct Provider<const R: usize, const N: usize> {
    context: Context<R, N>,
    inline: bool,
}
impl<const R: usize, const N: usize> Context<R, N> {
    /// Use the same actual shared process broker for generic CLIENT MQ lookups.
    /// All service endpoints in this process domain must reuse this context.
    #[must_use]
    pub fn resolution_context(&self) -> SharedResolution {
        Arc::new(Provider {
            context: self.clone(),
            inline: false,
        })
    }
    pub(crate) fn inline_resolution(&self) -> SharedResolution {
        Arc::new(Provider {
            context: self.clone(),
            inline: true,
        })
    }
}
struct Lookup<const R: usize, const N: usize> {
    callback: Option<crate::shared::ClientCallback<R, N>>,
    query: Query<R, N>,
}
fn native_duration(duration: Duration) -> CoreDuration {
    CoreDuration(u64::try_from(duration.as_micros()).unwrap_or(u64::MAX))
}
fn io_error(error: BrokerError) -> io::Error {
    let kind = match &error {
        BrokerError::Core(Error::Capacity) => io::ErrorKind::OutOfMemory,
        BrokerError::OwnerLost => io::ErrorKind::BrokenPipe,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}
impl<const R: usize, const N: usize> ResolutionContext for Provider<R, N> {
    fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.context.shared.clock.clone()
    }
    fn lookup(&self, name: &[u8], timeout: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        match self
            .context
            .client_query(name, native_duration(timeout), self.inline)
        {
            Ok(query) => Ok(Some(Box::new(Lookup {
                callback: None,
                query,
            }))),
            Err(BrokerError::Core(Error::Unavailable | Error::TooLarge)) => Ok(None),
            Err(error) => Err(io_error(error)),
        }
    }
    fn lookup_ipv4(
        &self,
        name: &[u8],
        timeout: Duration,
    ) -> io::Result<Option<Box<dyn AddressLookup>>> {
        match self.context.client_query_family(
            name,
            native_duration(timeout),
            self.inline,
            crate::Family::V4,
        ) {
            Ok(query) => Ok(Some(Box::new(Lookup {
                callback: None,
                query,
            }))),
            Err(BrokerError::Core(Error::Unavailable | Error::TooLarge)) => Ok(None),
            Err(error) => Err(io_error(error)),
        }
    }
    fn timer(&self, duration: Duration) -> io::Result<ResolutionTimer> {
        let timer = gnunet_service_runtime::clock::Deadline::after(
            self.context.shared.clock.clone(),
            duration,
        )
        .map_err(|error| io_error(error.into()))?;
        Ok(Box::pin(async move {
            timer.await.map_err(|error| io_error(error.into()))
        }))
    }
}
impl<const R: usize, const N: usize> AddressLookup for Lookup<R, N> {
    fn poll_next(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<Option<IpAddr>>> {
        if self.callback.is_some() {
            return Poll::Ready(Err(io_error(Error::NotReady.into())));
        }
        let callback = match self.query.poll_client_callback(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(io_error(error))),
            Poll::Ready(Ok(None)) => return Poll::Ready(Ok(None)),
            Poll::Ready(Ok(Some(callback))) => callback,
        };
        match callback.address() {
            Ok(Some(address)) => {
                self.callback = Some(callback);
                Poll::Ready(Ok(Some(address)))
            }
            Ok(None) => {
                drop(callback);
                Poll::Ready(Ok(None))
            }
            Err(error) => Poll::Ready(Err(io_error(error.into()))),
        }
    }
    fn address_effect_done(&mut self) -> io::Result<()> {
        let callback = self
            .callback
            .take()
            .ok_or_else(|| io_error(Error::NotReady.into()))?;
        drop(callback);
        Ok(())
    }
    fn connected(
        self: Box<Self>,
    ) -> io::Result<Box<dyn gnunet_service_runtime::connection::ConnectionLease>> {
        if self.callback.is_some() {
            return Err(io_error(Error::NotReady.into()));
        }
        Ok(Box::new(self.query.into_drain().map_err(io_error)?))
    }
}
