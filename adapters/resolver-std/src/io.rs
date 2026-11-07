//! Persistent bounded stream cursors. No submitted byte is owned by a future.
use crate::{HostError, Limits};
use gnunet_resolver_service_core::owner::ClientId;
pub(crate) use gnunet_service_runtime::connection::Connection as Stream;
use gnunet_types::Error;
use gnunet_wire::official::MessageHeader;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
fn interrupted<T>(p: Poll<io::Result<T>>, cx: &Context<'_>) -> Poll<io::Result<T>> {
    match p {
        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        p => p,
    }
}
pub(crate) fn bytes(n: usize, initialize: bool) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    if initialize {
        v.resize(n, 0)
    }
    Ok(v)
}
pub(crate) enum Step {
    Activity,
    Frame,
    Eof,
}
pub(crate) struct Session {
    pub stream: Stream,
    pub client: ClientId,
    pub rx: Vec<u8>,
    pub used: usize,
    pub expected: usize,
    pub tx: Vec<u8>,
    pub sent: usize,
    pub idle: Option<Instant>,
}
impl Session {
    pub fn new(stream: Stream, client: ClientId, l: Limits) -> Result<Self, Error> {
        Ok(Self {
            stream,
            client,
            rx: bytes(l.max_frame_bytes, true)?,
            used: 0,
            expected: 4,
            tx: bytes(l.max_pending_bytes, false)?,
            sent: 0,
            idle: deadline(l.idle_timeout)?,
        })
    }
    pub fn pending(&self) -> usize {
        self.tx.len() - self.sent
    }
    pub fn queue(&mut self, b: &[u8], max: usize) -> bool {
        let left = self.pending();
        if b.len() > max.saturating_sub(left) {
            return false;
        }
        if self.sent != 0 {
            self.tx.copy_within(self.sent.., 0);
            self.tx.truncate(left);
            self.sent = 0;
        }
        self.tx.extend_from_slice(b);
        true
    }
    pub fn reset(&mut self) {
        self.used = 0;
        self.expected = 4;
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        l: Limits,
        dispatch: bool,
    ) -> Poll<Result<Step, HostError>> {
        if self.idle.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Err(Error::Timeout.into()));
        }
        if self.pending() != 0 {
            let end = self
                .tx
                .len()
                .min(self.sent.saturating_add(l.io_slice_bytes));
            match interrupted(
                Pin::new(&mut self.stream).poll_write(cx, &self.tx[self.sent..end]),
                cx,
            ) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    self.sent += n;
                    if self.sent == self.tx.len() {
                        self.tx.clear();
                        self.sent = 0;
                    }
                    self.idle = deadline(l.idle_timeout)?;
                    return Poll::Ready(Ok(Step::Activity));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => {}
            }
        }
        if self.used == self.expected {
            return if dispatch {
                Poll::Ready(Ok(Step::Frame))
            } else {
                Poll::Pending
            };
        }
        let end = self
            .expected
            .min(self.used.saturating_add(l.io_slice_bytes));
        let mut b = ReadBuf::new(&mut self.rx[self.used..end]);
        match interrupted(Pin::new(&mut self.stream).poll_read(cx, &mut b), cx) {
            Poll::Ready(Ok(())) => {
                let n = b.filled().len();
                if n == 0 {
                    return if self.used == 0 {
                        Poll::Ready(Ok(Step::Eof))
                    } else {
                        Poll::Ready(Err(Error::Truncated.into()))
                    };
                }
                self.used += n;
                self.idle = deadline(l.idle_timeout)?;
                if self.used == 4 {
                    let h = MessageHeader::decode(&self.rx[..4])?;
                    if h.size() > self.rx.len() {
                        return Poll::Ready(Err(Error::Capacity.into()));
                    }
                    self.expected = h.size();
                }
                Poll::Ready(Ok(if self.used == self.expected && dispatch {
                    Step::Frame
                } else {
                    Step::Activity
                }))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
fn deadline(d: Duration) -> Result<Option<Instant>, Error> {
    if d == Duration::MAX {
        Ok(None)
    } else {
        Instant::now()
            .checked_add(d)
            .map(Some)
            .ok_or(Error::Overflow)
    }
}
