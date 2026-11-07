//! Persistent official4-byte framing and exact service MQ send-attempt ownership.
//! No service operation or processing confirmation is inferred from socket bytes.
use gnunet_service_runtime::connection::Connection;
use std::{
    collections::VecDeque,
    fmt, io,
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
/// Explicit transport frame/queue failure, independent of service semantics.
#[derive(Debug)]
pub enum Error {
    /// Native stream operation failed.
    Io(io::Error),
    /// Wire size is below the official4-byte header.
    Malformed,
    /// Earlier terminal framing/IO failure; no new socket read is attempted.
    Closed,
    /// Explicit caller frame/queue resource maximum was exceeded.
    Capacity,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Malformed => f.write_str("invalid official frame size"),
            Self::Capacity => f.write_str("bounded stream capacity"),
            Self::Closed => f.write_str("retired framed stream"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
/// Complete borrowed incoming frame or actual stream EOF.
#[derive(Debug)]
pub enum Received<'a> {
    /// This exact immutable complete frame remains pending until consume_frame.
    Frame(&'a [u8]),
    /// Actual native EOF; partial records whether an incomplete frame was present.
    Eof {
        /// Whether an original header/body was truncated.
        partial: bool,
    },
}
struct Envelope {
    bytes: Vec<u8>,
    offset: usize,
    in_flight: bool,
}
/// Owned accepted connection with bounded original RX and durable FIFO TX state.
/// Dropping a pending receive/send future never swaps this descriptor or cursor.
pub struct FramedConnection {
    stream: Connection,
    rx: Vec<u8>,
    used: usize,
    expected: usize,
    complete: bool,
    failed: bool,
    tx: VecDeque<Envelope>,
    pending_bytes: usize,
    max_pending_bytes: usize,
    max_frames: usize,
    io_slice: usize,
}
impl FramedConnection {
    /// Allocate bounded byte/metadata storage. Accepted peer/socket options/core
    /// admission are the caller's responsibility; no request is sent here.
    pub fn new(
        stream: Connection,
        max_frame: usize,
        max_pending_bytes: usize,
        max_frames: usize,
        io_slice: usize,
    ) -> Result<Self, Error> {
        if !(4..=65535).contains(&max_frame)
            || max_pending_bytes < 4
            || max_frames == 0
            || io_slice == 0
        {
            return Err(Error::Capacity);
        }
        let mut rx = Vec::new();
        rx.try_reserve_exact(max_frame)
            .map_err(|_| Error::Capacity)?;
        rx.resize(max_frame, 0);
        let mut tx = VecDeque::new();
        tx.try_reserve_exact(max_frames)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            stream,
            rx,
            used: 0,
            expected: 4,
            complete: false,
            failed: false,
            tx,
            pending_bytes: 0,
            max_pending_bytes,
            max_frames,
            io_slice,
        })
    }
    /// Copy one exact complete official envelope into durable ownership before
    /// the producer releases its borrowed frame ticket. Rejection is atomic.
    pub fn enqueue(&mut self, frame: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if frame.len() < 4 || usize::from(u16::from_be_bytes([frame[0], frame[1]])) != frame.len() {
            return Err(Error::Malformed);
        }
        if self.tx.len() == self.max_frames
            || self
                .pending_bytes
                .checked_add(frame.len())
                .is_none_or(|n| n > self.max_pending_bytes)
        {
            return Err(Error::Capacity);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(frame.len())
            .map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(frame);
        self.pending_bytes += bytes.len();
        self.tx.push_back(Envelope {
            bytes,
            offset: 0,
            in_flight: false,
        });
        Ok(())
    }
    /// Transfer only this original socket; queued metadata/buffers are dropped.
    /// Used for official persisted clients whose descriptor closes at owner drop.
    pub fn into_connection(self) -> Connection {
        self.stream
    }
    /// Bytes physically retained in the current incomplete/complete RX frame.
    /// A changed cursor after Pending is real ordinary work, before IDLE timers.
    pub fn buffered_bytes(&self) -> usize {
        self.used
    }
    /// Actual durable unsent byte count, including the remaining partial head.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }
    /// Logical source MQ length. Only the actual in-flight head is excluded;
    /// readiness without an eligible write attempt never changes this count.
    pub fn mq_length(&self) -> usize {
        self.tx.len() - usize::from(self.tx.front().is_some_and(|head| head.in_flight))
    }
    /// Whether no durable envelope remains to write.
    pub fn tx_empty(&self) -> bool {
        self.tx.is_empty()
    }
    /// Consume a fully dispatched original RX frame and erase only its used bytes.
    pub fn consume_frame(&mut self) -> Result<(), Error> {
        if !self.complete {
            return Err(Error::Malformed);
        }
        self.rx[..self.used].fill(0);
        self.used = 0;
        self.expected = 4;
        self.complete = false;
        Ok(())
    }
    /// Nonconsuming actual readiness for enabled ordinary RX/TX tasks. Empty TX
    /// does not request POLLOUT, so idle writable sockets cannot starve IDLE.
    pub fn ordinary_ready(&self) -> io::Result<bool> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        let mut interest = if self.complete || self.failed {
            PollFlags::empty()
        } else {
            PollFlags::POLLIN
        };
        if !self.tx.is_empty() && !self.failed {
            interest |= PollFlags::POLLOUT;
        }
        if interest.is_empty() {
            return Ok(false);
        }
        let mut descriptors = [PollFd::new(self.stream.as_fd(), interest)];
        poll(&mut descriptors, PollTimeout::ZERO).map_err(io::Error::from)?;
        let flags = descriptors[0].revents().unwrap_or(PollFlags::empty());
        if flags.contains(PollFlags::POLLNVAL) {
            return Err(io::Error::from_raw_os_error(
                nix::errno::Errno::EBADF as i32,
            ));
        }
        Ok(flags.intersects(interest | PollFlags::POLLHUP | PollFlags::POLLERR))
    }
    /// A borrowed frame cannot remain live while its RX storage is consumed:
    ///
    /// ```compile_fail,E0499
    /// use gnunet_arm_service_host::framed::{FramedConnection,Received,Error};
    /// use std::task::{Context,Poll};
    /// fn invalid(connection:&mut FramedConnection,cx:&mut Context<'_>)->Result<(),Error> {
    ///     if let Poll::Ready(Ok(Received::Frame(bytes)))=connection.poll_receive(cx) {
    ///         connection.consume_frame()?;
    ///         assert!(!bytes.is_empty());
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// Copying into independently owned output before consuming is valid:
    ///
    /// ```
    /// use gnunet_arm_service_host::framed::{FramedConnection,Received,Error};
    /// use std::task::{Context,Poll};
    /// fn retain(connection:&mut FramedConnection,cx:&mut Context<'_>)->Result<Option<Vec<u8>>,Error> {
    ///     if let Poll::Ready(Ok(Received::Frame(bytes)))=connection.poll_receive(cx) {
    ///         let owned=bytes.to_vec();
    ///         connection.consume_frame()?;
    ///         return Ok(Some(owned));
    ///     }
    ///     Ok(None)
    /// }
    /// ```
    ///
    /// Poll one original header/body. Partial data is retained. A complete frame
    /// is returned repeatedly until explicit consumption, so canceled dispatch
    /// cannot overwrite bytes or silently advance to the next operation.
    pub fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<Received<'_>, Error>> {
        if self.failed {
            return Poll::Ready(Err(Error::Closed));
        }
        if self.complete {
            return Poll::Ready(Ok(Received::Frame(&self.rx[..self.used])));
        }
        let end = self.expected.min(self.used.saturating_add(self.io_slice));
        let mut buffer = ReadBuf::new(&mut self.rx[self.used..end]);
        match Pin::new(&mut self.stream).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.failed = true;
                Poll::Ready(Err(Error::Io(error)))
            }
            Poll::Ready(Ok(())) => {
                let n = buffer.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(Received::Eof {
                        partial: self.used != 0,
                    }));
                }
                self.used += n;
                if self.used == 4 && self.expected == 4 {
                    let size = usize::from(u16::from_be_bytes([self.rx[0], self.rx[1]]));
                    if size < 4 {
                        self.failed = true;
                        return Poll::Ready(Err(Error::Malformed));
                    }
                    if size > self.rx.len() {
                        self.failed = true;
                        return Poll::Ready(Err(Error::Capacity));
                    }
                    self.expected = size;
                }
                if self.used == self.expected {
                    self.complete = true;
                    Poll::Ready(Ok(Received::Frame(&self.rx[..self.used])))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
    /// Perform at most one actual eligible write syscall. Positive, EAGAIN and
    /// EINTR first attempts mark the head in-flight; zero/fatal returns do not.
    /// True reports actual transfer/attempt work, never application processing.
    pub fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Error>> {
        if self.failed {
            return Poll::Ready(Err(Error::Closed));
        }
        let Some(head) = self.tx.front_mut() else {
            return Poll::Ready(Ok(false));
        };
        match self.stream.poll_write_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.failed = true;
                return Poll::Ready(Err(Error::Io(error)));
            }
            Poll::Ready(Ok(())) => {}
        }
        let end = head
            .bytes
            .len()
            .min(head.offset.saturating_add(self.io_slice));
        let sent = match self.stream.try_write(&head.bytes[head.offset..end]) {
            Ok(0) => {
                self.failed = true;
                return Poll::Ready(Err(Error::Io(io::ErrorKind::WriteZero.into())));
            }
            Ok(n) => n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                head.in_flight = true;
                cx.waker().wake_by_ref();
                return Poll::Ready(Ok(true));
            }
            Err(error) => {
                self.failed = true;
                return Poll::Ready(Err(Error::Io(error)));
            }
        };
        head.in_flight = true;
        head.offset += sent;
        self.pending_bytes -= sent;
        if head.offset == head.bytes.len() {
            drop(self.tx.pop_front());
        }
        Poll::Ready(Ok(true))
    }
}
