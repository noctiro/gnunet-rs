//! Exact frame cursors, interruption retry and unchanged absolute deadlines.
use crate::IpcError;
use gnunet_types::Error;
use gnunet_wire::official::MessageHeader;
use std::{future::poll_fn, io, pin::Pin, task::Poll};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
pub(crate) fn check_deadline(deadline: Instant) -> Result<(), IpcError> {
    if Instant::now() >= deadline {
        Err(IpcError::Deadline)
    } else {
        Ok(())
    }
}
async fn read_exact_until(
    stream: &mut (impl AsyncRead + Unpin),
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), IpcError> {
    let mut position = 0;
    check_deadline(deadline)?;
    while position < output.len() {
        // Check at every actual I/O poll: timeout_at polls the inner future first,
        // even when a previously pending socket becomes Ready after the deadline.
        let count = poll_fn(|context| {
            if let Err(error) = check_deadline(deadline) {
                return Poll::Ready(Err(error));
            }
            let mut buffer = ReadBuf::new(&mut output[position..]);
            match retry_interrupted(
                Pin::new(&mut *stream).poll_read(context, &mut buffer),
                context,
            ) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(IpcError::Io(error))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        check_deadline(deadline)?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        position = position.checked_add(count).ok_or(Error::Overflow)?;
    }
    check_deadline(deadline)
}
pub(crate) async fn write_all_until(
    stream: &mut (impl AsyncWrite + Unpin),
    input: &[u8],
    deadline: Instant,
) -> Result<(), IpcError> {
    let mut position = 0;
    check_deadline(deadline)?;
    while position < input.len() {
        let count = poll_fn(|context| {
            if let Err(error) = check_deadline(deadline) {
                return Poll::Ready(Err(error));
            }
            match retry_interrupted(
                Pin::new(&mut *stream).poll_write(context, &input[position..]),
                context,
            ) {
                Poll::Ready(Ok(count)) => Poll::Ready(Ok(count)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(IpcError::Io(error))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        check_deadline(deadline)?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero).into());
        }
        position = position.checked_add(count).ok_or(Error::Overflow)?;
    }
    check_deadline(deadline)
}
pub(crate) async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin),
    scratch: &mut [u8],
    deadline: Instant,
) -> Result<usize, IpcError> {
    check_deadline(deadline)?;
    if scratch.len() < 4 {
        return Err(Error::Capacity.into());
    }
    read_exact_until(stream, &mut scratch[..4], deadline).await?;
    let header = MessageHeader::decode(&scratch[..4])?;
    if header.size() > scratch.len() {
        return Err(Error::Capacity.into());
    }
    read_exact_until(stream, &mut scratch[4..header.size()], deadline).await?;
    check_deadline(deadline)?;
    Ok(header.size())
}

fn retry_interrupted<T>(
    result: Poll<io::Result<T>>,
    cx: &std::task::Context<'_>,
) -> Poll<io::Result<T>> {
    match result {
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        result => result,
    }
}

#[cfg(test)]
mod tests;
