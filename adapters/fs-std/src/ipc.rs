//! Caller-driven official FS service operations on one dedicated CLIENT MQ.
//!
//! The operation deadline uses the endpoint source's logical clock. A clock
//! regression is an explicit TimeUncertain refusal. An observation deadline or
//! dropping `drive()` only stops that wait: the original connection, request,
//! partial input/output and operation deadline remain in this owner.
use gnunet_client_host::channel::{Channel, ConnectionStep};
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_fs::client::{Instance, Limits as ProtocolLimits, SeenReplay};
use gnunet_fs::{
    Location,
    client::{Client as PureClient, Epoch, Event, Failure, Transmission},
};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::SEARCH_PREFIX;
pub use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Search};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

/// Per-connection native bounds, independent of the protocol's seen-set bound.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Largest complete accepted or outgoing frame, at most 65535 bytes.
    pub frame_bytes: usize,
    /// Maximum bytes transferred in one native I/O step; must be nonzero.
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
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}

enum Kind {
    Block {
        block_type: BlockType,
        expiration: AbsoluteTime,
        last_transmission: AbsoluteTime,
        num_transmissions: u32,
        respect_offered: u32,
    },
    Location(Location),
    IndexStarted,
    IndexFailed(usize),
    IndexEntry {
        file_id: [u8; 64],
        length: usize,
    },
    IndexEnd,
    Unindexed,
}
impl Kind {
    fn from_event(event: Event<'_>) -> Option<Self> {
        Some(match event {
            Event::Ignored => return None,
            Event::Block(result) => Self::Block {
                block_type: result.block_type,
                expiration: result.expiration,
                last_transmission: result.last_transmission,
                num_transmissions: result.num_transmissions,
                respect_offered: result.respect_offered,
            },
            Event::Location(location) => Self::Location(location),
            Event::IndexStarted => Self::IndexStarted,
            Event::IndexFailed(message) => Self::IndexFailed(message.len()),
            Event::IndexEntry { file_id, filename } => Self::IndexEntry {
                file_id,
                length: filename.len(),
            },
            Event::IndexEnd => Self::IndexEnd,
            Event::Unindexed => Self::Unindexed,
        })
    }
}

/// One accepted service event with its bounded owned original frame. Allocation
/// occurs before protocol acceptance, so an allocation refusal loses no result.
/// A D/I event authenticates the encrypted block's query, not a whole file tree.
pub struct Received {
    frame: OwnedFrame,
    kind: Kind,
}
impl Received {
    #[cfg(feature = "network")]
    /// Exact original accepted service frame, without re-encoding or copying.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
    /// Borrow the accepted event without copying its block or raw path bytes.
    #[must_use]
    pub fn event(&self) -> Event<'_> {
        match self.kind {
            Kind::Block {
                block_type,
                expiration,
                last_transmission,
                num_transmissions,
                respect_offered,
            } => Event::Block(ClientPut {
                block_type,
                expiration,
                last_transmission,
                num_transmissions,
                respect_offered,
                block: &self.frame.bytes()[gnunet_wire::official::fs::CLIENT_PUT_PREFIX..],
            }),
            Kind::Location(location) => Event::Location(location),
            Kind::IndexStarted => Event::IndexStarted,
            Kind::IndexFailed(length) => Event::IndexFailed(&self.frame.bytes()[4..4 + length]),
            Kind::IndexEntry { file_id, length } => Event::IndexEntry {
                file_id,
                filename: &self.frame.bytes()[72..72 + length],
            },
            Kind::IndexEnd => Event::IndexEnd,
            Kind::Unindexed => Event::Unindexed,
        }
    }
}

/// One actual native step or accepted service event. Call drive again to proceed.
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded inline event avoids another fallible allocation after protocol acceptance"
)]
pub enum Step {
    /// The original native connection attached; no service reply is implied.
    Connected,
    /// Actual request bytes written on their original MQ.
    Written {
        /// Positive byte count in this physical step.
        bytes: usize,
        /// Whether the original whole request fragment completed its write.
        complete: bool,
    },
    /// Actual input bytes retained by the framing owner.
    Read {
        /// Positive byte count in this physical step.
        bytes: usize,
    },
    /// Accepted query-bound block, verified LOC, or actual management reply.
    Event(Received),
    /// An unknown well-framed message or previously accepted duplicate result.
    Ignored,
    /// Actual connection selection/loss; a search retains its original deadline.
    Retry {
        /// Original configuration or native error, not a synthetic FS response.
        cause: Error,
        /// Existing CLIENT backoff selected after this loss.
        retry_after: Duration,
    },
    /// Current configuration could not select an endpoint. The CLIENT channel
    /// retains its scheduled retry; no service-negative response is inferred.
    Unavailable(Error),
    /// This wait's observation budget ended; the operation is still retained.
    WaitDeadline,
    /// The operation completed and its dedicated MQ has physically closed.
    Finished,
}

/// One FS operation. No task is spawned and no background service is created.
/// Searches may reconnect; an uncertain index mutation is never replayed.
/// KNOWN bounds the complete local whole-block deduplication set.
pub struct Client<'id, 'request, const KNOWN: usize> {
    core: PureClient<'id, 'request, KNOWN>,
    channel: Channel<Transmission<'id>>,
    epoch: Option<Epoch<'id>>,
    clock: Arc<dyn RuntimeClock>,
    timer: Option<Deadline>,
    now: AbsoluteTime,
    deadline: AbsoluteTime,
    prepare_bytes: usize,
    searching: bool,
    ublock_results: bool,
    filter_expired_ublocks: bool,
    closed: bool,
}
impl<'id, 'request, const KNOWN: usize> Client<'id, 'request, KNOWN> {
    /// Admit an operation. `deadline` is an absolute target in source.clock(),
    /// not a fresh per-reconnect timeout. Construction opens no socket.
    pub fn new(
        identity: &'id mut Instance,
        request: Request<'request>,
        source: EndpointSource,
        protocol: ProtocolLimits,
        native: Limits,
        deadline: AbsoluteTime,
    ) -> Result<Self, Error> {
        Self::new_with_identity(|| Ok(identity), request, source, protocol, native, deadline)
    }

    /// Prepare fallible native resources before acquiring a caller's identity
    /// slot. Used by a bounded multi-query search so a transient clock-listener
    /// refusal does not consume an otherwise reusable identity capability.
    pub(crate) fn new_with_identity<I>(
        identity: I,
        request: Request<'request>,
        source: EndpointSource,
        protocol: ProtocolLimits,
        native: Limits,
        deadline: AbsoluteTime,
    ) -> Result<Self, Error>
    where
        I: FnOnce() -> Result<&'id mut Instance, ProtocolError>,
    {
        let framing = native.framing();
        framing.validate()?;
        request.encoded_len()?;
        if let Request::Search(search) = request {
            if search.options & gnunet_wire::official::fs::SEARCH_CONTINUED != 0 {
                return Err(ProtocolError::InvalidInput.into());
            }
            if !matches!(
                search.block_type,
                BlockType::ANY | BlockType::DBLOCK | BlockType::IBLOCK | BlockType::UBLOCK
            ) {
                return Err(ProtocolError::Unsupported.into());
            }
            let hashes = search.seen.as_chunks::<64>().0;
            let mut unique = 0_usize;
            for (index, hash) in hashes.iter().enumerate() {
                if !hashes[..index].contains(hash) {
                    unique += 1;
                    if unique > KNOWN {
                        return Err(ProtocolError::Capacity.into());
                    }
                }
            }
        }
        let searching = matches!(request, Request::Search(_));
        let ublock_results = matches!(request, Request::Search(search)
            if search.block_type == BlockType::UBLOCK || search.block_type == BlockType::ANY);
        let prepare_bytes = if searching {
            let slots = native
                .frame_bytes
                .checked_sub(SEARCH_PREFIX)
                .ok_or(ProtocolError::Capacity)?
                / 64;
            SEARCH_PREFIX
                + 64 * KNOWN
                    .min(slots)
                    .min(gnunet_wire::official::fs::MAX_SEEN_PER_FRAME)
        } else {
            request.encoded_len()?
        };
        if prepare_bytes > native.frame_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        let clock = source.clock();
        let now = clock.sample()?.now;
        if now >= deadline {
            return Err(ProtocolError::Deadline.into());
        }
        let timer = Deadline::at(clock.clone(), deadline)?;
        let channel = Channel::new(source, framing)?;
        // Every fallible native resource is now retained locally. The protocol
        // admission above has already checked every PureClient::new refusal.
        let core = PureClient::new(identity()?, request, protocol, now, deadline)?;
        Ok(Self {
            core,
            channel,
            epoch: None,
            clock,
            timer: Some(timer),
            now,
            deadline,
            prepare_bytes,
            searching,
            ublock_results,
            filter_expired_ublocks: false,
            closed: false,
        })
    }

    /// Select the official search UTC expiry policy before attaching an MQ.
    /// The caller explicitly asserts that this source's clock values are GNUnet
    /// absolute UTC microseconds (for example RuntimeClock::SystemClock), not a
    /// generic monotonic origin. Only UBLOCK replies are filtered, before the
    /// pure owner remembers their whole-block digest. Raw clients default off;
    /// D/I ciphertext is never filtered by this policy.
    pub fn filter_expired_ublocks_using_source_absolute_time(
        &mut self,
    ) -> Result<(), ProtocolError> {
        if !self.ublock_results {
            return Err(ProtocolError::InvalidInput);
        }
        if self.epoch.is_some() || self.closed {
            return Err(ProtocolError::NotReady);
        }
        self.filter_expired_ublocks = true;
        Ok(())
    }

    /// Exact native time most recently sampled by this owner, including the
    /// acceptance time used by its outer UBLOCK freshness filter. Reading this
    /// does not sample a different clock or progress/replay the operation.
    pub(crate) fn observed_time(&self) -> AbsoluteTime {
        self.now
    }

    /// Terminal protocol cause and potential uncertain mutation, if any. Native
    /// errors returned by drive retain their actual OS/configuration cause too.
    #[must_use]
    pub fn failure(&self) -> Option<Failure> {
        self.core.failure()
    }
    /// Full bounded local accepted-result set, independently of wire replay size.
    #[must_use]
    pub fn known_results(&self) -> &[[u8; 64]] {
        self.core.known_results()
    }
    /// Whether an actual terminal response completed this operation.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.core.completed()
    }

    /// Cancel and physically close this dedicated MQ. A partially written index
    /// mutation keeps OutcomeUnknown. There is no private cancel wire message.
    pub fn cancel(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        match self.clock.sample() {
            Ok(sample) => self.now = sample.now,
            Err(cause) => {
                self.stop(cause)?;
                return Err(cause.into());
            }
        }
        self.stop(ProtocolError::Cancelled)?;
        Ok(())
    }

    /// Stop this original operation with its actual caller-observed cause and
    /// physically retire its dedicated MQ without sampling the clock again.
    /// Already closed owners return success; existing protocol failure facts
    /// remain available through `failure()`. No new request is submitted.
    pub fn abort_with_cause(&mut self, cause: ProtocolError) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.stop(cause).map_err(Into::into)
    }

    /// Progress the retained operation. Dropping this future or receiving
    /// WaitDeadline leaves the physical connection and all partial I/O intact.
    pub async fn drive(&mut self, observation_deadline: Option<Instant>) -> Result<Step, Error> {
        poll_fn(|cx| self.poll_drive(cx, observation_deadline)).await
    }

    fn retire(&mut self) -> Result<(), ProtocolError> {
        self.channel.detach();
        if let Some(epoch) = self.epoch.take() {
            // The exact MQ has closed first; this owner alone holds its epoch.
            self.core.retire(epoch, self.now)?;
        }
        Ok(())
    }
    fn close(&mut self) -> Result<(), ProtocolError> {
        let result = self.retire();
        self.channel.close();
        self.timer = None;
        self.closed = true;
        result
    }
    fn stop(&mut self, cause: ProtocolError) -> Result<(), ProtocolError> {
        let mut unwritten = None;
        if let Some(framed) = self.channel.framing_mut() {
            framed.remove_unwritten(|_, _| true, |tag, _| unwritten = Some(tag));
        }
        let cancellation = if let Some(tag) = unwritten {
            self.core.cancel_unwritten(tag, self.now, cause)
        } else {
            self.core.abort(self.now, cause)
        };
        let retirement = self.close();
        cancellation.and(retirement)
    }
    fn protocol_error(&mut self, cause: ProtocolError) -> Poll<Result<Step, Error>> {
        if self.core.failure().is_some() {
            self.close()?;
        }
        Poll::Ready(Err(cause.into()))
    }

    fn queue_request(&mut self) -> Result<(), ProtocolError> {
        let prepare_bytes = if self.searching {
            SEARCH_PREFIX
                + 64 * self
                    .core
                    .known_results()
                    .len()
                    .min((self.prepare_bytes - SEARCH_PREFIX) / 64)
        } else {
            self.prepare_bytes
        };
        let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        framed.reserve(prepare_bytes, Class::Ordinary)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(prepare_bytes)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(prepare_bytes, 0);
        let (tag, length) = {
            let prepared = self.core.prepare(
                self.epoch.ok_or(ProtocolError::NotReady)?,
                self.now,
                &mut bytes,
            )?;
            (prepared.tag(), prepared.bytes().len())
        };
        bytes.truncate(length);
        framed
            .enqueue_owned(OwnedFrame::new(bytes), tag, Class::Ordinary)
            .map_err(|rejected| rejected.reason)
    }

    fn lost(&mut self, cause: io::Error) -> Poll<Result<Step, Error>> {
        if !self.searching {
            self.stop(ProtocolError::Io)?;
            return Poll::Ready(Err(cause.into()));
        }
        self.retire()?;
        if let Some(failure) = self.core.failure() {
            self.close()?;
            return Poll::Ready(Err(failure.outcome.into()));
        }
        let retry_after = self.channel.schedule_retry()?;
        Poll::Ready(Ok(Step::Retry {
            cause: cause.into(),
            retry_after,
        }))
    }

    fn dispatch(&mut self) -> Result<Option<Received>, Error> {
        let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        let bytes = framed.frame().ok_or(ProtocolError::NotReady)?;
        if self.filter_expired_ublocks
            && let Ok(gnunet_wire::official::fs::Response::Put(result)) =
                gnunet_wire::official::fs::Response::decode(bytes)
            && result.block_type == BlockType::UBLOCK
            && !result.expiration.is_never()
            && result.expiration.as_micros() < self.now.as_micros()
        {
            framed.release_frame();
            return Ok(None);
        }
        // Allocate before receive: receive may irreversibly remember a result or
        // accept a terminal reply. Capacity refusal retains the original frame.
        let frame = OwnedFrame::copy_from(bytes)?;
        let kind = Kind::from_event(self.core.receive(
            self.epoch.ok_or(ProtocolError::NotReady)?,
            self.now,
            frame.bytes(),
        )?);
        framed.release_frame();
        let result = kind.map(|kind| Received { frame, kind });
        if self.core.retirement_needed() {
            self.close()?;
        }
        Ok(result)
    }

    pub(crate) fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        observation_deadline: Option<Instant>,
    ) -> Poll<Result<Step, Error>> {
        if self.closed {
            return match self.core.failure() {
                Some(failure) => Poll::Ready(Err(failure.outcome.into())),
                None => Poll::Ready(Ok(Step::Finished)),
            };
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(cause)) => {
                self.stop(ProtocolError::Io)?;
                return Poll::Ready(Err(cause));
            }
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now,
            Err(cause) => {
                self.stop(cause)?;
                return Poll::Ready(Err(cause.into()));
            }
        };
        let time_refusal = if now < self.now {
            Some(ProtocolError::TimeUncertain)
        } else if now >= self.deadline {
            Some(ProtocolError::Deadline)
        } else {
            None
        };
        self.now = now;
        if let Some(cause) = time_refusal {
            self.stop(cause)?;
            return Poll::Ready(Err(cause.into()));
        }
        if let Err(cause) = self.core.poll(self.now) {
            self.close()?;
            return Poll::Ready(Err(cause.into()));
        }
        if let Some(timer) = &mut self.timer {
            match Pin::new(timer).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    self.timer = None;
                    let cause = result.err().unwrap_or(ProtocolError::Deadline);
                    self.stop(cause)?;
                    return Poll::Ready(Err(cause.into()));
                }
            }
        }
        if self.core.connection_needed() {
            match self.channel.poll_connect(cx) {
                Poll::Pending => return self.wait(cx, observation_deadline),
                Poll::Ready(Err(cause)) => {
                    self.stop(ProtocolError::Io)?;
                    return Poll::Ready(Err(cause));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    match self.core.begin_connection(self.now) {
                        Ok(epoch) => self.epoch = Some(epoch),
                        Err(cause) => {
                            self.stop(cause)?;
                            return Poll::Ready(Err(cause.into()));
                        }
                    }
                    return Poll::Ready(Ok(Step::Connected));
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Step::Retry {
                        cause: error.into(),
                        retry_after,
                    }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(cause))) => {
                    return Poll::Ready(Ok(Step::Unavailable(cause)));
                }
            }
        }
        if self.core.request_needed()
            && let Err(cause) = self.queue_request()
        {
            if !self.core.request_needed() {
                // A lease escaped preparation; it cannot be regenerated after
                // an unexpected final queue refusal, even with no bytes sent.
                self.stop(cause)?;
            }
            return self.protocol_error(cause);
        }
        let Some(framed) = self.channel.framing_mut() else {
            return Poll::Ready(Err(ProtocolError::NotReady.into()));
        };
        match framed.poll_write(cx) {
            Poll::Ready(Err(cause)) => return self.lost(cause),
            Poll::Ready(Ok(progress)) => {
                if progress.complete
                    && let Err(cause) = self.core.written_tag(progress.origin, self.now)
                {
                    return self.protocol_error(cause);
                }
                return Poll::Ready(Ok(Step::Written {
                    bytes: progress.bytes,
                    complete: progress.complete,
                }));
            }
            Poll::Pending => {}
        }
        // Do not dispatch early replies before all original CONTINUED fragments
        // complete. Full RX remains retained while the original TX makes progress.
        if framed.queued_frames() != 0 {
            return self.wait(cx, observation_deadline);
        }
        if framed.frame().is_some() {
            return match self.dispatch() {
                Ok(Some(event)) => Poll::Ready(Ok(Step::Event(event))),
                Ok(None) => Poll::Ready(Ok(Step::Ignored)),
                Err(Error::Protocol(cause)) => self.protocol_error(cause),
                Err(cause) => Poll::Ready(Err(cause)),
            };
        }
        match framed.poll_read(cx) {
            Poll::Ready(Err(cause)) => self.lost(cause),
            Poll::Ready(Ok(ReadStep::Eof)) => self.lost(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "FS service MQ closed",
            )),
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                Poll::Ready(Ok(Step::Read { bytes }))
            }
            Poll::Pending => self.wait(cx, observation_deadline),
        }
    }
    fn wait(
        &mut self,
        cx: &mut Context<'_>,
        observation_deadline: Option<Instant>,
    ) -> Poll<Result<Step, Error>> {
        self.channel
            .poll_wait(cx, observation_deadline)
            .map(|result| result.map(|()| Step::WaitDeadline))
    }
}
