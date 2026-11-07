//! Shared owned official service streams; framing is identical on Unix and TCP.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, UnixStream},
};

pub(crate) enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}
// EINTR transfers no bytes. Preserve the caller's original cursor and deadline,
// schedule another poll, and yield instead of spinning under a signal storm.
pub(crate) fn retry_interrupted<T>(
    result: Poll<io::Result<T>>,
    cx: &Context<'_>,
) -> Poll<io::Result<T>> {
    match result {
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        result => result,
    }
}
impl Stream {
    pub(crate) fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Unix(s) => s.poll_write_ready(cx),
            Self::Tcp(s) => s.poll_write_ready(cx),
        }
    }
    pub(crate) fn try_write_vectored(&self, slices: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.try_write_vectored(slices),
            Self::Tcp(s) => s.try_write_vectored(slices),
        }
    }
    pub(crate) fn try_write(&self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.try_write(bytes),
            Self::Tcp(s) => s.try_write(bytes),
        }
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = match self.get_mut() {
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        };
        retry_interrupted(result, cx)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = self.get_mut();
        loop {
            match retry_interrupted(stream.poll_write_ready(cx), cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            match stream.try_write(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return retry_interrupted(Poll::Ready(result), cx),
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
