//! Original native GNS queries over shared CLIENT, clock and retained framing.
//! No GNS service, background task, Resolver broker or cryptographic backend is
//! created. The selected service interprets names and authenticates zone records.
#![forbid(unsafe_code)]
/// Ordinary user-name routing through zTLD/configuration/ego suffixes.
pub use gnunet_client::gns::{
    AttemptId, Epoch, Instance, LocalOptions, Lookup, LookupResult, MAX_NAME_BYTES, Parameters,
    QueryId, WireId,
};
use gnunet_client::gns::{Client as Core, Received};
use gnunet_client_host::channel::{Channel, ConnectionStep};
pub use gnunet_client_host::{
    ConnectError as Error, EndpointSource, LiveConfiguration, resolution,
};
pub use gnunet_gnsrecord::{RecordData, RecordFlags, RecordSet, RecordType, ZoneKey, ZoneKeyType};
/// Canonical process time and independent waiter traits.
pub use gnunet_service_runtime::clock;
use gnunet_service_runtime::framing::{
    Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep,
};
use gnunet_types::Error as ProtocolError;
use std::{
    future::poll_fn,
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

/// Explicit native resource policy, independent of protocol field values.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum single incoming reply, from 12 through 65535 bytes.
    pub frame_bytes: usize,
    /// Maximum records accepted as an observation. A larger valid reply locally
    /// refuses only its original query; no record table is allocated.
    pub records: usize,
    /// Retained original outgoing request frames and bytes.
    pub output: Budget,
    /// Maximum bytes offered to one native read/write syscall; nonzero.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            records: 2048,
            output: Budget {
                frames: 64,
                bytes: 65535,
            },
            io_slice_bytes: 65535,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: self.output,
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn validate(self) -> Result<(), ProtocolError> {
        self.framing().validate()?;
        if self.frame_bytes < 12 {
            return Err(ProtocolError::Capacity);
        }
        Ok(())
    }
}
/// Actual cause for retiring the original physical service connection.
#[derive(Debug)]
pub enum LossCause {
    /// Clean EOF between complete frames.
    Eof,
    /// Actual IO error, including EOF in a partial frame.
    Io(io::Error),
    /// Invalid message/framing, without synthesizing a name resolution result.
    Protocol(ProtocolError),
    /// Explicit local resource limit/refusal.
    Resource(ProtocolError),
    /// Caller requested a physical reconnect while retaining lookup intent.
    Requested,
    /// Permanent close retired this original connection.
    Closed,
}
/// Retained structural service observation. Public records remain readable after
/// MQ loss without granting an old query or epoch authority over a replacement.
pub struct Answer<'a> {
    epoch: Epoch<'a>,
    query: QueryId<'a>,
    frame: OwnedFrame,
    maximum_records: usize,
}
impl<'a> Answer<'a> {
    /// Original physical connection on which the reply arrived.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'a> {
        self.epoch
    }
    /// Original query, already retired before this observation was returned.
    #[must_use]
    pub const fn query(&self) -> QueryId<'a> {
        self.query
    }
    /// The exact immutable official response bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
    /// Borrow the already structurally validated reply. No allocation, lookup,
    /// block authentication or record normalization occurs here.
    pub fn result(&self) -> Result<LookupResult<'_>, ProtocolError> {
        LookupResult::decode(self.frame.bytes(), self.maximum_records)
    }
}
/// One bounded original observation. Full writing is not name resolution.
pub enum Progress<'a> {
    /// Actual service socket attached; no peer/zone identity is implied.
    Connected(Epoch<'a>),
    /// Structurally validated original reply, owning its immutable storage.
    Answer(Answer<'a>),
    /// Valid reply for no currently submitted original query.
    Ignored(Epoch<'a>),
    /// The valid original reply exceeded local delivery policy. That query is
    /// retired with its actual local cause; other queries keep the same MQ.
    Refused {
        /// Original service connection.
        epoch: Epoch<'a>,
        /// Original query, retired before returning this local failure.
        query: QueryId<'a>,
        /// Actual local refusal, not a wire NXDOMAIN answer.
        reason: ProtocolError,
    },
    /// Complete local writing, including a canceled request's retained debt.
    Written {
        /// Original physical MQ.
        epoch: Epoch<'a>,
        /// Original logical request, possibly already canceled.
        query: QueryId<'a>,
    },
    /// Actual positive native IO, without processing/acceptance assertions.
    Activity {
        /// Original physical MQ.
        epoch: Epoch<'a>,
        /// Actual positive bytes read.
        read_bytes: usize,
        /// Actual positive bytes written.
        written_bytes: usize,
    },
    /// Original physical owner was retired before safe logical restoration.
    Lost {
        /// Original retired connection.
        epoch: Epoch<'a>,
        /// Actual local reason; not an NXDOMAIN response.
        cause: LossCause,
        /// Original live lookup intent retained for the next connection.
        retained_queries: usize,
    },
    /// Original syscall failure and source-domain next retry.
    ConnectRetry {
        /// Actual connection error.
        error: io::Error,
        /// Original selected delay, not a query timeout.
        retry_after: Duration,
    },
    /// Current endpoint selection failed; not an empty lookup answer.
    Unavailable(Error),
    /// A complete frame is retained unchanged while fallible observation storage
    /// cannot be acquired; no logical query has been settled.
    Capacity(Epoch<'a>),
    /// Only the caller's observation wait budget ended.
    WaitDeadline,
    /// Permanently closed, with its clock subscription released.
    Closed,
}
#[derive(Clone, Copy)]
struct Origin<'a> {
    epoch: Epoch<'a>,
    query: QueryId<'a>,
    attempt: AttemptId<'a>,
}
/// Standard native GNS client: 64 pending logical/debt slots, full 252-byte names.
pub type Client<'a> = BoundedClient<'a, 64, MAX_NAME_BYTES>;
/// Caller-driven client with explicit independent logical/name capacities.
pub struct BoundedClient<'a, const R: usize, const N: usize> {
    core: Core<'a, R, N>,
    channel: Channel<Origin<'a>>,
    limits: Limits,
    read_first: bool,
    yield_due: bool,
    closed: bool,
}
impl<'a, const R: usize, const N: usize> BoundedClient<'a, R, N> {
    /// Reserve logical slots, native framing policy and one canonical clock
    /// subscription. No socket, query, background task or Resolver is created.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let core = Core::new(instance)?;
        let maximum_request =
            gnunet_client::gns::LOOKUP_HEADER_LEN + gnunet_gnsrecord::ZONE_WIRE_LEN + N + 1;
        if limits.frame_bytes < maximum_request || limits.output.bytes < maximum_request {
            return Err(ProtocolError::Capacity.into());
        }
        let channel = Channel::new(source, limits.framing())?;
        Ok(Self {
            core,
            channel,
            limits,
            read_first: false,
            yield_due: false,
            closed: false,
        })
    }
    /// Admit an original lookup, including while the service is unavailable.
    pub fn lookup(&mut self, parameters: Parameters, name: &[u8]) -> Result<QueryId<'a>, Error> {
        Ok(self.core.lookup(parameters, name)?)
    }
    /// Suppress the original callback. An admitted immutable frame drains on
    /// its original MQ or is discarded only with that MQ's retirement.
    pub fn cancel(&mut self, query: QueryId<'_>) -> Result<(), Error> {
        Ok(self.core.cancel(query)?)
    }
    /// Whether this exact original logical lookup is still pending.
    #[must_use]
    pub fn live(&self, query: QueryId<'_>) -> bool {
        self.core.live(query)
    }
    /// Original outstanding logical query count, excluding canceled write debt.
    #[must_use]
    pub fn pending_queries(&self) -> usize {
        self.core.pending_queries()
    }
    /// Original admitted frames awaiting full writing or MQ retirement.
    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.core.pending_writes()
    }
    fn retire(&mut self, cause: LossCause) -> Result<Progress<'a>, Error> {
        let epoch = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        self.channel.detach();
        self.core.lost(epoch)?;
        self.channel.schedule_retry()?;
        Ok(Progress::Lost {
            epoch,
            cause,
            retained_queries: self.core.pending_queries(),
        })
    }
    /// Explicit physical reconnect, preserving only safe lookup intent.
    pub fn reconnect(&mut self) -> Result<Progress<'a>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.retire(LossCause::Requested)
    }
    /// Permanently retire original IO and logical requests, releasing the clock
    /// subscription. A closed client cannot recover or reconnect.
    pub fn close(&mut self) -> Option<Progress<'a>> {
        if self.closed {
            return None;
        }
        let epoch = self.core.epoch();
        self.channel.close();
        self.core.close();
        self.closed = true;
        epoch.map(|epoch| Progress::Lost {
            epoch,
            cause: LossCause::Closed,
            retained_queries: 0,
        })
    }
    /// Explicit recovery of an original source clock/timer/Resolver refusal.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.channel.recover_ports()
    }
    fn prepare(&mut self, epoch: Epoch<'a>) -> Result<Option<Progress<'a>>, Error> {
        let Some(size) = self.core.next_size() else {
            return Ok(None);
        };
        let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        if !framed.capacity(size, Class::Ordinary) {
            return Ok(None);
        }
        framed.reserve(size, Class::Ordinary)?;
        // All fallible backing allocation precedes the pure original lease.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| ProtocolError::Capacity)?;
        let original = self.core.outbound(epoch)?.ok_or(ProtocolError::Stale)?;
        bytes.extend_from_slice(original.bytes());
        let origin = Origin {
            epoch,
            query: original.query(),
            attempt: original.attempt(),
        };
        if let Err(rejected) = framed.enqueue_owned(OwnedFrame::new(bytes), origin, Class::Ordinary)
        {
            return self.retire(LossCause::Resource(rejected.reason)).map(Some);
        }
        Ok(None)
    }
    fn dispatch(&mut self, epoch: Epoch<'a>) -> Result<Progress<'a>, Error> {
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(ProtocolError::NotReady)?;
        let frame = match OwnedFrame::copy_from(input) {
            Ok(frame) => frame,
            Err(ProtocolError::Capacity) => return Ok(Progress::Capacity(epoch)),
            Err(error) => return Err(error.into()),
        };
        // A type 501 frame can contain at most 4095 complete 16-byte headers. Full
        // structural validation stays bounded by the official 65535-byte frame;
        // the caller's delivery policy cannot retire unrelated queries.
        let received = match self.core.receive(epoch, frame.bytes(), (65535 - 12) / 16) {
            Ok(Received::Answer { query, result }) => Some((query, result.records().len())),
            Ok(Received::Unmatched) => None,
            Err(error) => return self.retire(LossCause::Protocol(error)),
        };
        if !self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .release_frame()
        {
            return Err(ProtocolError::Stale.into());
        }
        Ok(match received {
            Some((query, count)) if count > self.limits.records => Progress::Refused {
                epoch,
                query,
                reason: ProtocolError::Capacity,
            },
            Some((query, _)) => Progress::Answer(Answer {
                epoch,
                query,
                frame,
                maximum_records: self.limits.records,
            }),
            None => Progress::Ignored(epoch),
        })
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(progress)) => {
                self.read_first = true;
                if progress.complete {
                    if progress.origin.epoch != epoch {
                        return Poll::Ready(Err(ProtocolError::Stale.into()));
                    }
                    self.core.written(progress.origin.attempt)?;
                    Poll::Ready(Ok(Progress::Written {
                        epoch,
                        query: progress.origin.query,
                    }))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        epoch,
                        read_bytes: 0,
                        written_bytes: progress.bytes,
                    }))
                }
            }
        }
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.retire(LossCause::Eof)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    Poll::Ready(self.dispatch(epoch))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        epoch,
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        match self.channel.poll_clock(cx) {
            // The caller's fixed native observation target remains live even
            // while the canonical clock is waiting for a consistent revision.
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, deadline)
                    .map(|result| result.map(|()| Progress::WaitDeadline));
            }
            Poll::Ready(result) => result?,
        }
        if self.channel.framing().is_none() {
            match self.channel.poll_connect(cx) {
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = match self.core.begin_connection() {
                        Ok(epoch) => epoch,
                        Err(error) => {
                            self.channel.detach();
                            return Poll::Ready(Err(error.into()));
                        }
                    };
                    return Poll::Ready(Ok(Progress::Connected(epoch)));
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Progress::ConnectRetry { error, retry_after }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(Progress::Unavailable(error)));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    return self
                        .channel
                        .poll_wait(cx, deadline)
                        .map_ok(|()| Progress::WaitDeadline);
                }
            }
        }
        let epoch = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        if self.channel.framing().is_some_and(|f| f.frame().is_some()) {
            return Poll::Ready(self.dispatch(epoch));
        }
        if let Some(progress) = self.prepare(epoch)? {
            return Poll::Ready(Ok(progress));
        }
        if self.read_first {
            if let Poll::Ready(progress) = self.read(cx, epoch) {
                return Poll::Ready(progress);
            }
            if let Poll::Ready(progress) = self.write(cx, epoch) {
                return Poll::Ready(progress);
            }
        } else {
            if let Poll::Ready(progress) = self.write(cx, epoch) {
                return Poll::Ready(progress);
            }
            if let Poll::Ready(progress) = self.read(cx, epoch) {
                return Poll::Ready(progress);
            }
        }
        self.channel
            .poll_wait(cx, deadline)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Poll the same retained original connection/query owner. The optional
    /// deadline is an observation wait, never an implicit cancellation.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if !self.closed && self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.poll_step(cx, deadline);
        if result.is_ready() && !self.closed {
            self.yield_due = true;
        }
        result
    }
    /// Wait for one bounded original step. Dropping this future retains native
    /// connection attempts, partial frames, source timers and query/write debt.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
}
impl<const R: usize, const N: usize> Drop for BoundedClient<'_, R, N> {
    fn drop(&mut self) {
        self.channel.close();
        self.core.close();
    }
}
