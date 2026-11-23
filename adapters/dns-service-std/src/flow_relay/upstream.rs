//! Closed upstream choices; native provider traffic uses Network.framework.
use gnunet_native::dns_proxy::{Connection, ConnectionRetirement, MAX_DATAGRAM_BYTES, TcpFlow};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use zeroize::Zeroizing;

/// A qualified original connected socket or native provider connection.
/// Socket construction does not establish provider recursion exclusion.
pub struct TcpUpstream(Backend);
enum Backend {
    Socket(Option<TcpStream>),
    Native(Box<Native>),
}
struct Native {
    connection: Connection,
    read: ReadState,
    write: WriteState,
    closing: bool,
}
enum ReadState {
    Idle,
    Pending,
    Buffered(Received),
    End,
    Failed(Option<io::Error>),
}
#[derive(Clone, Copy)]
enum WriteState {
    Idle,
    Pending(usize),
    Finishing,
    Finished,
    Failed,
}
struct Received {
    bytes: Zeroizing<Vec<u8>>,
    read: usize,
    after: ReadEnd,
}
enum ReadEnd {
    More,
    Eof,
    Error(io::Error),
}
impl From<ReadEnd> for ReadState {
    fn from(end: ReadEnd) -> Self {
        match end {
            ReadEnd::More => Self::Idle,
            ReadEnd::Eof => Self::End,
            ReadEnd::Error(error) => Self::Failed(Some(error)),
        }
    }
}
impl TcpUpstream {
    /// Adopt a connected socket qualified by the caller for this deployment.
    pub fn socket(stream: TcpStream) -> Self {
        Self(Backend::Socket(Some(stream)))
    }
    /// Adopt the original Network.framework TCP connection for provider traffic.
    pub fn native(connection: Connection) -> Self {
        Self(Backend::Native(Box::new(Native {
            connection,
            read: ReadState::Idle,
            write: WriteState::Idle,
            closing: false,
        })))
    }
    /// Native connections retain the exact original flow and SDK endpoint.
    /// An explicitly supplied socket instead needs a numeric endpoint match.
    pub(super) fn matches_flow(&self, flow: &TcpFlow) -> io::Result<bool> {
        match &self.0 {
            Backend::Socket(Some(stream)) => Ok(super::same_endpoint(
                flow.remote_addr()?,
                stream.peer_addr()?,
            )),
            Backend::Socket(None) => Err(closed()),
            Backend::Native(native) => Ok(native.connection.matches_tcp_flow(flow)),
        }
    }
    /// Original peer observations, preserving native scoped address identity.
    /// # Errors
    /// A supplied socket's original native peer lookup can fail.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match &self.0 {
            Backend::Socket(Some(stream)) => stream.peer_addr(),
            Backend::Socket(None) => Err(closed()),
            Backend::Native(native) => {
                if !native.connection.is_tcp() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TCP relay received a datagram upstream",
                    ));
                }
                native.connection.peer_addr()
            }
        }
    }
    pub(super) fn pending_send(&self) -> Option<usize> {
        match &self.0 {
            Backend::Socket(_) => None,
            Backend::Native(native) => match native.write {
                WriteState::Pending(bytes) => Some(bytes),
                _ => None,
            },
        }
    }
    pub(super) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.0 {
            Backend::Socket(Some(_)) => Poll::Ready(Ok(())),
            Backend::Socket(None) => Poll::Ready(Err(closed())),
            Backend::Native(native) => native.connection.poll_ready(cx),
        }
    }
    pub(super) fn close(&mut self) {
        match &mut self.0 {
            Backend::Socket(stream) => {
                *stream = None;
            }
            Backend::Native(native) => {
                native.closing = true;
                native.connection.request_cancel();
                native.read = ReadState::End;
            }
        }
    }
    pub(super) fn poll_retirement(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ConnectionRetirement>> {
        match &mut self.0 {
            Backend::Socket(_) => Poll::Ready(None),
            Backend::Native(native) => native.connection.poll_retirement(cx).map(Some),
        }
    }
}
impl std::fmt::Debug for TcpUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpUpstream")
            .field("native", &matches!(self.0, Backend::Native(_)))
            .finish_non_exhaustive()
    }
}
impl TcpUpstream {
    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.0 {
            Backend::Socket(Some(stream)) => Pin::new(stream).poll_read(cx, buffer),
            Backend::Socket(None) => Poll::Ready(Err(closed())),
            Backend::Native(native) => native.poll_read(cx, buffer),
        }
    }
}
impl TcpUpstream {
    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.0 {
            Backend::Socket(Some(stream)) => Pin::new(stream).poll_write(cx, bytes),
            Backend::Socket(None) => Poll::Ready(Err(closed())),
            Backend::Native(native) => native.poll_write(cx, bytes),
        }
    }
    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.0 {
            Backend::Socket(Some(stream)) => Pin::new(stream).poll_shutdown(cx),
            Backend::Socket(None) => Poll::Ready(Err(closed())),
            Backend::Native(native) => native.poll_shutdown(cx),
        }
    }
}
impl Native {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.closing {
            return Poll::Ready(Err(closed()));
        }
        if matches!(self.read, ReadState::Idle) {
            match self.connection.poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            self.connection
                .begin_receive(buffer.remaining().min(MAX_DATAGRAM_BYTES))?;
            self.read = ReadState::Pending;
        }
        if matches!(self.read, ReadState::Pending) {
            // A final data prefix may arrive with an error after the connection
            // has left Ready. Only new reads depend on current readiness.
            let result = match self.connection.poll_receive(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(result)) => result,
                Poll::Ready(None) => Err(missing_completion()),
            };
            self.read = match result {
                Ok(received) => {
                    let (bytes, eof, error) = received.into_parts();
                    ReadState::received(bytes, eof, error)
                }
                Err(error) => ReadState::Failed(Some(error)),
            };
            if matches!(self.read, ReadState::Idle) {
                // An empty non-final native result is not EOF.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        self.read.deliver(buffer)
    }
    fn poll_write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if self.closing {
            return Poll::Ready(Err(closed()));
        }
        let count = match self.write {
            WriteState::Idle => {
                if bytes.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                match self.connection.poll_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                }
                let count = bytes.len().min(MAX_DATAGRAM_BYTES);
                self.connection.begin_send(&bytes[..count])?;
                self.write = WriteState::Pending(count);
                count
            }
            WriteState::Pending(count) => count,
            _ => return Poll::Ready(Err(closed())),
        };
        self.poll_completion(cx, WriteState::Idle)
            .map(|result| result.map(|()| count))
    }
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closing {
            return Poll::Ready(Err(closed()));
        }
        match self.write {
            WriteState::Idle => {
                match self.connection.poll_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                }
                self.connection.begin_finish()?;
                self.write = WriteState::Finishing;
            }
            WriteState::Finishing => {}
            WriteState::Finished => return Poll::Ready(Ok(())),
            WriteState::Pending(_) => return Poll::Ready(Err(io::ErrorKind::WouldBlock.into())),
            WriteState::Failed => return Poll::Ready(Err(closed())),
        }
        self.poll_completion(cx, WriteState::Finished)
    }
    fn poll_completion(
        &mut self,
        cx: &mut Context<'_>,
        success: WriteState,
    ) -> Poll<io::Result<()>> {
        let result = match self.connection.poll_send(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(result)) => result,
            Poll::Ready(None) => Err(missing_completion()),
        };
        self.write = if result.is_ok() {
            success
        } else {
            WriteState::Failed
        };
        Poll::Ready(result)
    }
}
impl ReadState {
    fn received(bytes: Vec<u8>, eof: bool, error: Option<io::Error>) -> Self {
        let after = match error {
            Some(error) => ReadEnd::Error(error),
            None if eof => ReadEnd::Eof,
            None => ReadEnd::More,
        };
        if bytes.is_empty() {
            after.into()
        } else {
            Self::Buffered(Received {
                bytes: Zeroizing::new(bytes),
                read: 0,
                after,
            })
        }
    }
    fn deliver(&mut self, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Buffered(chunk) => {
                let remaining = &chunk.bytes[chunk.read..];
                let count = buffer.remaining().min(remaining.len());
                buffer.put_slice(&remaining[..count]);
                chunk.read += count;
                if chunk.read == chunk.bytes.len() {
                    *self = std::mem::replace(&mut chunk.after, ReadEnd::More).into();
                }
                Poll::Ready(Ok(()))
            }
            Self::End => Poll::Ready(Ok(())),
            Self::Failed(error) => Poll::Ready(Err(error.take().unwrap_or_else(closed))),
            Self::Idle | Self::Pending => Poll::Pending,
        }
    }
}
impl Drop for TcpUpstream {
    fn drop(&mut self) {
        self.close();
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "original TCP upstream closed")
}
fn missing_completion() -> io::Error {
    io::Error::other("original Network.framework operation lost its completion")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_receive_delivers_its_retained_prefix_before_the_error() -> io::Result<()> {
        let mut read = ReadState::received(
            b"abc".to_vec(),
            true,
            Some(io::ErrorKind::ConnectionReset.into()),
        );
        let mut bytes = [0; 2];
        for expected in [b"ab".as_slice(), b"c".as_slice()] {
            let mut buffer = ReadBuf::new(&mut bytes);
            match read.deliver(&mut buffer) {
                Poll::Ready(Ok(())) if buffer.filled() == expected => {}
                _ => return Err(io::Error::other("received prefix was lost or reordered")),
            }
        }
        let mut buffer = ReadBuf::new(&mut bytes);
        match read.deliver(&mut buffer) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset => Ok(()),
            _ => Err(io::Error::other("the terminal receive error was lost")),
        }
    }
}
