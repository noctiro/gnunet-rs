//! Independent, caller-driven CADET management streams.
//!
//! Each inspector owns a separate actual CLIENT MQ because the official
//! protocol has no query IDs. Only an actual matching END completes a stream.
//! Transport loss retains partial counts and never silently starts a new list.
use gnunet_client_host::{
    ConnectError as Error, EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{
    Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep,
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::cadet::{Request, Response};
use std::{
    future::poll_fn,
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

/// One real management operation on its own physical MQ.
/// GetChannel is omitted: the pinned official service registers no handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Query {
    /// List currently known peers, ending with the actual PeersEnd record.
    Peers,
    /// List currently known tunnels, ending with the actual TunnelsEnd record.
    Tunnels,
    /// List the paths to this peer, ending with the actual PathsEnd record.
    Paths([u8; 32]),
}
impl Query {
    fn request(self) -> Request<'static> {
        match self {
            Self::Peers => Request::ListPeers,
            Self::Tunnels => Request::ListTunnels,
            Self::Paths(peer) => Request::GetPath { peer },
        }
    }
    fn classify(self, response: Response<'_>) -> Result<bool, ProtocolError> {
        match (self, response) {
            (Self::Peers, Response::PeerInfo { .. })
            | (Self::Tunnels, Response::TunnelInfo { .. })
            | (Self::Paths(_), Response::PathInfo { .. }) => Ok(false),
            (Self::Peers, Response::PeersEnd)
            | (Self::Tunnels, Response::TunnelsEnd)
            | (Self::Paths(_), Response::PathsEnd) => Ok(true),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Explicit management-stream resource limits, independent of list length.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Largest complete IPC frame retained, from four through 65535 bytes.
    pub frame_bytes: usize,
    /// Maximum bytes in one native read or write action.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            io_slice_bytes: self.io_slice_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
        }
    }
}

/// Actual local terminal state; socket EOF is always Interrupted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// The current operation has no actual matching END yet.
    Pending,
    /// A matching official END was actually received.
    Complete,
    /// The original MQ or its protocol failed before END.
    Interrupted,
    /// The caller explicitly closed the original operation before END.
    Closed,
}
/// Actual partial-stream observations, with no inferred remote snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Exact original operation kind.
    pub query: Query,
    /// Actual positive written query bytes, never merely queued bytes.
    pub written_bytes: usize,
    /// Whether the entire original query frame was actually written.
    pub query_written: bool,
    /// Actual accepted nonterminal records delivered to the caller.
    pub entries: u64,
    /// Original operation terminal classification.
    pub terminal: Terminal,
}

/// One unchanged original received management record.
pub struct Entry(OwnedFrame);
impl Entry {
    /// Original complete official IPC bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
    /// Borrow fields from this exact original frame.
    pub fn response(&self) -> Result<Response<'_>, ProtocolError> {
        Response::decode(self.bytes())
    }
}

/// One actual bounded operation observation.
pub enum Step {
    /// The real physical connection attached; no handshake frame was fabricated.
    Connected,
    /// The query was retained for physical output; it is not yet exposed.
    Queued,
    /// Actual original-query native write progress.
    Written {
        /// Positive bytes from this actual write action.
        bytes: usize,
        /// Whether this write finished the complete original query frame.
        complete: bool,
    },
    /// Actual original nonterminal record, without an implicit list allocation.
    Entry(Entry),
    /// Actual matching END, retained unchanged after closing the original MQ.
    Complete(Entry),
    /// Actual positive input before its complete record was accepted.
    Activity,
    /// A connection attempt failed before any query MQ attached.
    Retry {
        /// Original native attempt cause.
        cause: io::Error,
        /// Source-selected delay before the next physical attempt.
        retry_after: Duration,
    },
    /// Explicit source refusal; recover_ports is required for a refused port.
    Unavailable(Error),
    /// Original MQ/protocol retirement, preserving partial-stream observations.
    Interrupted {
        /// Original physical or protocol failure.
        cause: Error,
        /// Partial progress of this exact operation.
        report: Report,
    },
    /// Only the caller's observation wait expired; original work remains live.
    WaitDeadline,
    /// This original inspector is terminal and owns no native MQ.
    Closed,
}

/// One streaming management operation over an explicit endpoint/clock source.
/// No background task, unbounded list, Resolver or automatic query replay exists.
pub struct Inspector {
    physical: Channel<()>,
    query: Query,
    report: Report,
    attached: bool,
    queued: bool,
}
impl Inspector {
    /// Reserve bounded transport storage/subscription without connecting yet.
    pub fn new(source: EndpointSource, query: Query, limits: Limits) -> Result<Self, Error> {
        limits.framing().validate()?;
        if query.request().encoded_len()? > limits.frame_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        Ok(Self {
            physical: Channel::new(source, limits.framing())?,
            query,
            report: Report {
                query,
                written_bytes: 0,
                query_written: false,
                entries: 0,
                terminal: Terminal::Pending,
            },
            attached: false,
            queued: false,
        })
    }
    /// Current observations from this exact operation, without native effects.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Explicitly recover this source's refused clock/Resolver/configuration port.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        self.physical.recover_ports()
    }
    /// Physically close this original MQ; never create a successful END.
    pub fn close(&mut self) -> Report {
        self.physical.close();
        if self.report.terminal == Terminal::Pending {
            self.report.terminal = Terminal::Closed;
        }
        self.report
    }
    fn interrupted(&mut self, cause: Error) -> Step {
        self.physical.close();
        self.report.terminal = Terminal::Interrupted;
        Step::Interrupted {
            cause,
            report: self.report,
        }
    }
    fn queue(&mut self) -> Result<(), Error> {
        let mut output = [0_u8; 40];
        let length = self.query.request().encode(&mut output)?;
        let framed = self.physical.framing_mut().ok_or(ProtocolError::NotReady)?;
        framed.enqueue_copy(&output[..length], (), Class::Ordinary)?;
        self.queued = true;
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Step>, Error> {
        let Some(frame) = self.physical.framing().and_then(|mq| mq.frame()) else {
            return Ok(None);
        };
        let is_end = match Response::decode(frame).and_then(|r| self.query.classify(r)) {
            Ok(is_end) => is_end,
            Err(error) => return Ok(Some(self.interrupted(error.into()))),
        };
        // Refuse allocation before accepting/releasing this original input.
        let owned = Entry(OwnedFrame::copy_from(frame)?);
        let entries = if is_end {
            self.report.entries
        } else {
            self.report
                .entries
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?
        };
        let _released = self
            .physical
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .release_frame();
        self.report.entries = entries;
        if is_end {
            self.physical.close();
            self.report.terminal = Terminal::Complete;
            Ok(Some(Step::Complete(owned)))
        } else {
            Ok(Some(Step::Entry(owned)))
        }
    }
    /// Drive one actual observation. Dropping a wait preserves partial cursors.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step, Error>> {
        if self.report.terminal != Terminal::Pending {
            return Poll::Ready(Ok(Step::Closed));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        match self.physical.poll_clock(cx) {
            Poll::Pending => {
                return self
                    .physical
                    .poll_wait(cx, deadline)
                    .map(|result| result.map(|()| Step::WaitDeadline));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Ok(Step::Unavailable(error))),
            Poll::Ready(Ok(())) => {}
        }
        if !self.attached {
            match self.physical.poll_connect(cx) {
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.attached = true;
                    return Poll::Ready(Ok(Step::Connected));
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Step::Retry {
                        cause: error,
                        retry_after,
                    }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) | Poll::Ready(Err(error)) => {
                    return Poll::Ready(Ok(Step::Unavailable(error)));
                }
                Poll::Pending => {}
            }
        } else if !self.queued {
            self.queue()?;
            return Poll::Ready(Ok(Step::Queued));
        } else if !self.report.query_written {
            let framed = self.physical.framing_mut().ok_or(ProtocolError::NotReady)?;
            match framed.poll_write(cx) {
                Poll::Ready(Ok(write)) => {
                    self.report.written_bytes = self
                        .report
                        .written_bytes
                        .checked_add(write.bytes)
                        .ok_or(ProtocolError::Overflow)?;
                    self.report.query_written = write.complete;
                    return Poll::Ready(Ok(Step::Written {
                        bytes: write.bytes,
                        complete: write.complete,
                    }));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Ok(self.interrupted(error.into())));
                }
                Poll::Pending => {}
            }
        } else {
            if let Some(step) = self.receive()? {
                return Poll::Ready(Ok(step));
            }
            let framed = self.physical.framing_mut().ok_or(ProtocolError::NotReady)?;
            match framed.poll_read(cx) {
                Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                    return Poll::Ready(Ok(Step::Activity));
                }
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    return Poll::Ready(Ok(self.interrupted(
                        io::Error::new(io::ErrorKind::UnexpectedEof, "CADET list ended before END")
                            .into(),
                    )));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Ok(self.interrupted(error.into())));
                }
                Poll::Pending => {}
            }
        }
        self.physical
            .poll_wait(cx, deadline)
            .map(|result| result.map(|()| Step::WaitDeadline))
    }
    /// Wait only for the next actual observation from this original inspector.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Step, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
}
impl Drop for Inspector {
    fn drop(&mut self) {
        self.physical.close();
    }
}
