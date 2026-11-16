//! Deadline-bounded one-shot STATISTICS operations over original local streams.
use crate::{
    IpcError,
    framing::{check_deadline, read_frame, write_all_until},
};
use gnunet_client::statistics::{self, GetSession, Response, Selector, Set, Statistic};
use gnunet_service_runtime::local::Stream;
use gnunet_types::Error;
use std::{
    future::{Future, poll_fn},
    path::Path,
    task::Poll,
};
use tokio::time::{Instant, timeout_at};
/// Official statistics connection; there is at most one original operation.
#[derive(Debug)]
pub struct StatisticsClient {
    stream: Option<Stream>,
}
impl StatisticsClient {
    /// Connect before the original deadline, without submitting an expired connect.
    /// Socket ownership and configuration-file resolution belong to the caller.
    pub async fn connect(path: impl AsRef<Path>, deadline: Instant) -> Result<Self, IpcError> {
        Ok(Self {
            stream: Some(connect_stream(path, deadline).await?),
        })
    }
    /// Whether an admitted operation's error or cancellation retired the stream.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
    /// GET until its exact END, within the original deadline and value/byte capacities.
    /// Each callback only borrows this frame. Callback errors retire the connection.
    /// An unpolled future submits no request; dropping an admitted future closes it.
    pub async fn get(
        &mut self,
        selector: Selector<'_>,
        maximum_values: usize,
        scratch: &mut [u8],
        deadline: Instant,
        mut accept: impl FnMut(Statistic<'_>) -> Result<(), Error>,
    ) -> Result<usize, IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        let mut session = GetSession::new(maximum_values);
        let size = session.start(selector, scratch)?;
        check_deadline(deadline)?;
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let operation = async {
            write_all_until(&mut stream, &scratch[..size], deadline).await?;
            let mut count = 0usize;
            loop {
                let size = read_frame(&mut stream, scratch, deadline).await?;
                match session.receive(&scratch[..size])? {
                    Response::Value(value) => {
                        check_deadline(deadline)?;
                        accept(value)?;
                        check_deadline(deadline)?;
                        count = count.checked_add(1).ok_or(Error::Overflow)?;
                    }
                    Response::End => {
                        check_deadline(deadline)?;
                        return Ok::<usize, IpcError>(count);
                    }
                }
            }
        };
        let result = timeout_at(deadline, operation)
            .await
            .map_err(|_| IpcError::Deadline)?;
        if result.is_ok() {
            check_deadline(deadline)?;
            self.stream = Some(stream);
        }
        result
    }
    /// SET followed by the official DISCONNECT confirmation, closing this connection.
    /// A lost confirmation never reports success; an update may already have taken effect.
    /// No automatic retry is performed for such an ambiguous outcome.
    pub async fn set_and_disconnect(
        &mut self,
        update: Set<'_>,
        scratch: &mut [u8],
        deadline: Instant,
    ) -> Result<(), IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        let size = update.encode(scratch)?;
        check_deadline(deadline)?;
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let result = timeout_at(deadline, async {
            write_all_until(&mut stream, &scratch[..size], deadline).await?;
            let size = statistics::encode_disconnect(scratch)?;
            write_all_until(&mut stream, &scratch[..size], deadline).await?;
            let size = read_frame(&mut stream, scratch, deadline).await?;
            statistics::confirm_disconnect(&scratch[..size])?;
            check_deadline(deadline)?;
            Ok::<(), IpcError>(())
        })
        .await
        .map_err(|_| IpcError::Deadline)?;
        if result.is_ok() {
            check_deadline(deadline)?;
        }
        result
    }
}

pub(crate) async fn connect_stream(
    path: impl AsRef<Path>,
    deadline: Instant,
) -> Result<Stream, IpcError> {
    check_deadline(deadline)?;
    let operation = async {
        check_deadline(deadline)?;
        let connection = Stream::connect(path);
        tokio::pin!(connection);
        let stream = poll_fn(|context| {
            if let Err(error) = check_deadline(deadline) {
                return Poll::Ready(Err(error));
            }
            connection
                .as_mut()
                .poll(context)
                .map(|result| result.map_err(IpcError::Io))
        })
        .await?;
        check_deadline(deadline)?;
        Ok::<_, IpcError>(stream)
    };
    let stream = timeout_at(deadline, operation)
        .await
        .map_err(|_| IpcError::Deadline)??;
    check_deadline(deadline)?;
    Ok(stream)
}

#[cfg(all(test, unix))]
mod unix_tests;
