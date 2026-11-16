//! A bounded client for official STATISTICS WATCH subscriptions.
use crate::{
    IpcError,
    framing::{check_deadline, read_frame, write_all_until},
};
use gnunet_client::statistics::{Instance, Selector, WatchId, WatchSession, WatchUpdate};
use gnunet_service_runtime::local::Stream;
use gnunet_types::Error;
use std::{fmt, path::Path};
use tokio::time::{Instant, timeout_at};

/// A dedicated WATCH connection with at most N requests in its lifetime. It
/// holds caller-borrowed selectors and receives only official WATCH_VALUE frames.
/// GET/SET use a separate [`crate::StatisticsClient`], keeping their untagged terminal
/// messages out of this subscription stream.
pub struct StatisticsWatchClient<'a, const N: usize> {
    stream: Option<Stream>,
    session: WatchSession<'a, N>,
}
impl<const N: usize> fmt::Debug for StatisticsWatchClient<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatisticsWatchClient")
            .field("closed", &self.is_closed())
            .field("watch_capacity", &N)
            .finish_non_exhaustive()
    }
}
impl<'a, const N: usize> StatisticsWatchClient<'a, N> {
    /// Connect within the caller's original deadline. Local socket authority and
    /// official configuration resolution remain the caller's responsibility.
    pub async fn connect(
        instance: &'a mut Instance,
        path: impl AsRef<Path>,
        deadline: Instant,
    ) -> Result<Self, IpcError> {
        let stream = crate::client::connect_stream(path, deadline).await?;
        Ok(Self {
            stream: Some(stream),
            session: WatchSession::new(instance),
        })
    }
    /// Whether an admitted I/O error, timeout, cancellation or explicit close
    /// retired this connection and all further callback authority.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
    /// Send one WATCH. Success establishes only successful local submission:
    /// upstream has no WATCH acknowledgement and zero values need not produce
    /// an initial notification. The returned WID follows connection order.
    /// Dropping this admitted future closes the stream; it cannot be resumed on
    /// another connection with the same watch IDs.
    pub async fn watch(
        &mut self,
        selector: Selector<'a>,
        scratch: &mut [u8],
        deadline: Instant,
    ) -> Result<WatchId<'a>, IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        let (id, size) = self.session.start(selector, scratch)?;
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let result = timeout_at(
            deadline,
            write_all_until(&mut stream, &scratch[..size], deadline),
        )
        .await
        .map_err(|_| IpcError::Deadline)
        .and_then(|value| value)
        .and_then(|()| check_deadline(deadline));
        match result {
            Ok(()) => {
                self.stream = Some(stream);
                Ok(id)
            }
            Err(error) => {
                self.session.close();
                Err(error)
            }
        }
    }
    /// Wait for the next still-active watch within this call's absolute
    /// deadline. Suppressed notifications for cancelled WIDs are consumed under
    /// the same deadline. No synthetic initial value or END is generated.
    /// Dropping an admitted wait retires the connection to avoid losing a
    /// partially consumed frame and assigning its suffix to another operation.
    pub async fn next(
        &mut self,
        scratch: &mut [u8],
        deadline: Instant,
    ) -> Result<WatchUpdate<'a>, IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        if scratch.len() < 24 {
            return Err(Error::Capacity.into());
        }
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let result = timeout_at(deadline, async {
            loop {
                let size = read_frame(&mut stream, scratch, deadline).await?;
                if let Some(update) = self.session.receive(&scratch[..size])? {
                    check_deadline(deadline)?;
                    return Ok::<_, IpcError>(update);
                }
            }
        })
        .await
        .map_err(|_| IpcError::Deadline)
        .and_then(|value| value)
        .and_then(|value| {
            check_deadline(deadline)?;
            Ok(value)
        });
        match result {
            Ok(update) => {
                self.stream = Some(stream);
                Ok(update)
            }
            Err(error) => {
                self.session.close();
                Err(error)
            }
        }
    }
    /// Suppress future local notifications for this ID. No wire unwatch exists;
    /// the service retains its watch until this connection actually closes.
    /// `id` must have been issued by this same client instance. IDs from another
    /// connection, including a replacement connection, are not interchangeable.
    pub fn cancel(&mut self, id: WatchId<'a>) -> Result<(), IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        self.session.cancel(id)?;
        Ok(())
    }
    /// Close the actual socket and revoke all local watches immediately.
    pub fn close(&mut self) {
        self.stream.take();
        self.session.close();
    }
}

#[cfg(all(test, unix))]
mod unix_tests;
