//! Original-task DNS-over-TCP fallback; no resolver, task, retry or TLS layer.
use std::{
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Instant, Sleep},
};
use zeroize::{Zeroize, Zeroizing};

/// Actual stages of this original numeric-upstream connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// The original connect future has not completed.
    Connect,
    /// Original length-prefixed query bytes remain.
    Write,
    /// Reading the original two-byte response length.
    Length,
    /// Reading the advertised original response bytes.
    Body,
    /// Physical owner has been closed; no further IO is admitted.
    Closed,
}
/// Physical byte observations, not a DNS or database acknowledgement.
#[derive(Clone, Copy, Debug)]
pub struct Report {
    /// Original upstream selected from the actual validated TC datagram source.
    pub server: SocketAddr,
    /// Last actual phase, before physical retirement.
    pub stage: Stage,
    /// Actual length-prefix plus query bytes written.
    pub written: usize,
    /// Actual two-byte prefix plus response bytes read.
    pub read: usize,
}
/// An actual bounded transfer failure with only public attribution metadata.
#[derive(Debug)]
pub struct Failure {
    /// Original phase/server/byte counters.
    pub report: Report,
    /// Native cause; not a DNS result or an empty record set.
    pub cause: io::Error,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original DNS TCP {:?}: {}", self.report, self.cause)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

type Connecting = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
/// One original fallback under the UDP query's fixed native hard target.
/// The caller must retain its task/id/question association until terminal poll
/// or actual cancel. Starting this fallback never renews that original target.
/// Completed bytes remain unverified until the caller's actual DNS inspector.
/// Drop closes this one physical source; it does not manufacture a response.
pub struct Exchange {
    server: SocketAddr,
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
    connecting: Option<Connecting>,
    stream: Option<TcpStream>,
    query: Zeroizing<Vec<u8>>,
    written: usize,
    prefix: [u8; 2],
    prefix_used: usize,
    body: Zeroizing<Vec<u8>>,
    body_used: usize,
    maximum: usize,
    quantum: usize,
    stage: Stage,
}
impl Exchange {
    /// Prepare one numeric connect future and bounded buffers without polling it.
    /// `hard` must be the original query's already established native deadline.
    pub fn new(
        server: SocketAddr,
        query: &[u8],
        hard: Instant,
        maximum: usize,
        quantum: usize,
    ) -> io::Result<Self> {
        if server.port() == 0
            || !(12..=65535).contains(&query.len())
            || !(12..=65535).contains(&maximum)
            || quantum == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS TCP bounds",
            ));
        }
        if Instant::now() >= hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original DNS query expired before TCP fallback",
            ));
        }
        let mut framed = Zeroizing::new(Vec::new());
        framed
            .try_reserve_exact(query.len() + 2)
            .map_err(io::Error::other)?;
        framed.extend_from_slice(
            &u16::try_from(query.len())
                .map_err(io::Error::other)?
                .to_be_bytes(),
        );
        framed.extend_from_slice(query);
        let mut body = Zeroizing::new(Vec::new());
        body.try_reserve_exact(maximum).map_err(io::Error::other)?;
        // SocketAddr's Tokio conversion is already numeric; no hidden DNS or
        // getaddrinfo task is involved. Only poll may perform this connect.
        let connecting = Some(Box::pin(TcpStream::connect(server)) as Connecting);
        Ok(Self {
            server,
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
            connecting,
            stream: None,
            query: framed,
            written: 0,
            prefix: [0; 2],
            prefix_used: 0,
            body,
            body_used: 0,
            maximum,
            quantum,
            stage: Stage::Connect,
        })
    }
    /// Actual transfer metadata; it confers no completion authority.
    pub fn report(&self) -> Report {
        Report {
            server: self.server,
            stage: self.stage,
            written: self.written,
            read: self.prefix_used + self.body_used,
        }
    }
    /// Check/register only the original native hard; no canonical clock or IO.
    pub fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if self.stage == Stage::Closed {
            return Err(self.fail(io::Error::new(
                io::ErrorKind::NotConnected,
                "original TCP fallback already closed",
            )));
        }
        if Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready() {
            return Err(self.fail(io::Error::new(
                io::ErrorKind::TimedOut,
                "original UDP/TCP DNS query deadline",
            )));
        }
        Ok(())
    }
    fn fail(&mut self, cause: io::Error) -> Failure {
        let report = self.report();
        self.close();
        Failure { report, cause }
    }
    fn close(&mut self) {
        drop(self.connecting.take());
        drop(self.stream.take());
        self.query.zeroize();
        self.stage = Stage::Closed;
    }
    /// Actual one-way physical retirement, without a new time sample or retry.
    pub fn cancel(&mut self) -> Report {
        let report = self.report();
        self.close();
        report
    }
    /// One bounded syscall/connect turn. Partial writes/reads stay on this exact
    /// source and immutable query. A complete packet is returned exactly once.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Zeroizing<Vec<u8>>, Failure>> {
        if let Err(error) = self.guard(cx) {
            return Poll::Ready(Err(error));
        }
        match self.stage {
            Stage::Connect => {
                let Some(connecting) = &mut self.connecting else {
                    return Poll::Ready(Err(
                        self.fail(io::Error::other("missing original DNS TCP connect"))
                    ));
                };
                match connecting.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(error))),
                    Poll::Ready(Ok(stream)) => {
                        self.connecting = None;
                        self.stream = Some(stream);
                        self.stage = Stage::Write;
                    }
                }
            }
            Stage::Write => {
                let end = self
                    .query
                    .len()
                    .min(self.written.saturating_add(self.quantum));
                let result = match &mut self.stream {
                    Some(stream) => Pin::new(stream).poll_write(cx, &self.query[self.written..end]),
                    None => Poll::Ready(Err(io::Error::other("missing original DNS TCP socket"))),
                };
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(error))),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(self.fail(io::ErrorKind::WriteZero.into())));
                    }
                    Poll::Ready(Ok(written)) => {
                        self.written += written;
                        if self.written == self.query.len() {
                            self.stage = Stage::Length;
                        }
                    }
                }
            }
            Stage::Length => {
                let (result, read) = {
                    let mut buffer = ReadBuf::new(&mut self.prefix[self.prefix_used..]);
                    let result = match &mut self.stream {
                        Some(stream) => Pin::new(stream).poll_read(cx, &mut buffer),
                        None => {
                            Poll::Ready(Err(io::Error::other("missing original DNS TCP socket")))
                        }
                    };
                    (result, buffer.filled().len())
                };
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(error))),
                    Poll::Ready(Ok(())) if read == 0 => {
                        return Poll::Ready(Err(self.fail(io::ErrorKind::UnexpectedEof.into())));
                    }
                    Poll::Ready(Ok(())) => self.prefix_used += read,
                }
                if self.prefix_used == 2 {
                    let len = usize::from(u16::from_be_bytes(self.prefix));
                    if len < 12 || len > self.maximum {
                        return Poll::Ready(Err(self.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "DNS TCP advertised response exceeds original complete-packet bound",
                        ))));
                    }
                    self.body.resize(len, 0);
                    self.stage = Stage::Body;
                }
            }
            Stage::Body => {
                let end = self
                    .body
                    .len()
                    .min(self.body_used.saturating_add(self.quantum));
                let (result, read) = {
                    let mut buffer = ReadBuf::new(&mut self.body[self.body_used..end]);
                    let result = match &mut self.stream {
                        Some(stream) => Pin::new(stream).poll_read(cx, &mut buffer),
                        None => {
                            Poll::Ready(Err(io::Error::other("missing original DNS TCP socket")))
                        }
                    };
                    (result, buffer.filled().len())
                };
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(error))),
                    Poll::Ready(Ok(())) if read == 0 => {
                        return Poll::Ready(Err(self.fail(io::ErrorKind::UnexpectedEof.into())));
                    }
                    Poll::Ready(Ok(())) => self.body_used += read,
                }
                if self.body_used == self.body.len() {
                    if Instant::now() >= self.hard {
                        return Poll::Ready(Err(self.fail(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original DNS query expired during the final TCP read",
                        ))));
                    }
                    self.close();
                    return Poll::Ready(Ok(std::mem::replace(
                        &mut self.body,
                        Zeroizing::new(Vec::new()),
                    )));
                }
            }
            Stage::Closed => {
                return Poll::Ready(Err(self.fail(io::ErrorKind::NotConnected.into())));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        self.close();
    }
}
