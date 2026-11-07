//! Bounded persistent official-IPC framing; partial I/O belongs to this owner.
use crate::ServiceCause;
use gnunet_service_runtime::connection::Connection;
use gnunet_types::Error;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
struct Out {
    bytes: Vec<u8>,
    position: usize,
    tag: Option<u32>,
}
pub(crate) struct Link {
    connection: Option<Connection>,
    input: Vec<u8>,
    filled: usize,
    need: usize,
    ready: bool,
    // A rejected header or terminal native observation cannot read this same
    // original stream again; only an actual replacement attachment resets it.
    rx_ended: bool,
    tx: VecDeque<Out>,
    tx_bytes: usize,
    max_bytes: usize,
    max_frames: usize,
}
impl Link {
    pub(crate) fn new(
        connection: Connection,
        max_bytes: usize,
        max_frames: usize,
    ) -> Result<Self, Error> {
        if max_frames == 0 || max_bytes < 65535 || max_bytes.checked_add(128).is_none() {
            return Err(Error::Capacity);
        }
        let mut input = Vec::new();
        input
            .try_reserve_exact(65535)
            .map_err(|_| Error::Capacity)?;
        input.resize(65535, 0);
        let mut tx = VecDeque::new();
        tx.try_reserve_exact(max_frames.checked_add(4).ok_or(Error::Overflow)?)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            connection: Some(connection),
            input,
            filled: 0,
            need: 4,
            ready: false,
            rx_ended: false,
            tx,
            tx_bytes: 0,
            max_bytes,
            max_frames,
        })
    }
    pub(crate) fn empty(&self) -> bool {
        self.tx.is_empty()
    }
    pub(crate) fn online(&self) -> bool {
        self.connection.is_some()
    }
    pub(crate) fn disconnect(&mut self) {
        self.connection = None;
        self.tx.clear();
        self.tx_bytes = 0;
        self.release();
        self.rx_ended = true;
    }
    pub(crate) fn attach(
        &mut self,
        connection: Connection,
    ) -> Result<(), gnunet_types::Rejected<Connection>> {
        if self.connection.is_some() {
            return Err(gnunet_types::Rejected {
                reason: Error::Conflict,
                value: connection,
            });
        }
        self.connection = Some(connection);
        self.rx_ended = false;
        Ok(())
    }
    pub(crate) fn cleanup(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.online() {
            return Ok(());
        }
        self.enqueue_bound(
            bytes,
            None,
            self.max_frames + 4,
            self.max_bytes.checked_add(128).ok_or(Error::Overflow)?,
        )
    }
    pub(crate) fn enqueue(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.enqueue_bound(bytes, None, self.max_frames, self.max_bytes)
    }
    pub(crate) fn tagged(&mut self, bytes: &[u8], tag: u32) -> Result<(), Error> {
        self.enqueue_bound(bytes, Some(tag), self.max_frames, self.max_bytes)
    }
    pub(crate) fn cancel_offline(&mut self, tag: u32) {
        if self.online() {
            return;
        }
        let removed: usize = self
            .tx
            .iter()
            .filter(|m| m.tag == Some(tag))
            .map(|m| m.bytes.len())
            .sum();
        self.tx.retain(|m| m.tag != Some(tag));
        self.tx_bytes -= removed;
    }
    fn enqueue_bound(
        &mut self,
        bytes: &[u8],
        tag: Option<u32>,
        frames: usize,
        limit: usize,
    ) -> Result<(), Error> {
        if self.tx.len() >= frames || bytes.len() > limit.saturating_sub(self.tx_bytes) {
            return Err(Error::WouldBlock);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Capacity)?;
        owned.extend_from_slice(bytes);
        self.tx.push_back(Out {
            bytes: owned,
            position: 0,
            tag,
        });
        self.tx_bytes += bytes.len();
        Ok(())
    }
    pub(crate) fn frame(&self) -> Option<&[u8]> {
        self.ready.then_some(&self.input[..self.need])
    }
    pub(crate) fn release(&mut self) {
        self.input[..self.filled].fill(0);
        self.filled = 0;
        self.need = 4;
        self.ready = false;
    }
    pub(crate) fn poll_tx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(connection) = self.connection.as_ref() else {
            return Poll::Pending;
        };
        let Some(front) = self.tx.front_mut() else {
            return Poll::Pending;
        };
        match connection.poll_write_ready(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        match connection.try_write(&front.bytes[front.position..]) {
            Ok(0) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Ok(n) => {
                front.position += n;
                if front.position == front.bytes.len() {
                    self.tx_bytes -= front.bytes.len();
                    self.tx.pop_front();
                }
                Poll::Ready(Ok(()))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
    pub(crate) fn poll_rx(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ServiceCause>> {
        if self.ready || self.rx_ended {
            return Poll::Pending;
        }
        let Some(connection) = self.connection.as_mut() else {
            return Poll::Pending;
        };
        let mut buf = ReadBuf::new(&mut self.input[self.filled..self.need]);
        match Pin::new(connection).poll_read(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.rx_ended = true;
                Poll::Ready(Err(ServiceCause::Io(error)))
            }
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len();
                if n == 0 {
                    self.rx_ended = true;
                    return Poll::Ready(Err(ServiceCause::Io(io::ErrorKind::UnexpectedEof.into())));
                }
                self.filled += n;
                if self.filled == 4 && self.need == 4 {
                    self.need = match frame_size([self.input[0], self.input[1]]) {
                        Ok(size) => size,
                        Err(error) => {
                            self.rx_ended = true;
                            return Poll::Ready(Err(error));
                        }
                    };
                }
                if self.filled == self.need {
                    self.ready = true;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

fn frame_size(prefix: [u8; 2]) -> Result<usize, ServiceCause> {
    let size = usize::from(u16::from_be_bytes(prefix));
    if size < 4 {
        Err(ServiceCause::Protocol(Error::Malformed))
    } else {
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::{ServiceCause, frame_size};
    use gnunet_types::Error;

    #[test]
    fn malformed_frame_size_is_protocol_rejection_at_the_header_boundary() {
        for size in 0_u16..4 {
            assert!(matches!(
                frame_size(size.to_be_bytes()),
                Err(ServiceCause::Protocol(Error::Malformed))
            ));
        }
        assert!(matches!(frame_size(4_u16.to_be_bytes()), Ok(4)));
        assert!(matches!(frame_size(u16::MAX.to_be_bytes()), Ok(65535)));
    }
}
