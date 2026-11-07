use crate::{Bounds, Cause, Epoch, Error, Limits, Loss, Observation, Progress, Query};
use crate::{
    budget::Bound,
    ports::{HmacRank, NativeRandom},
};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_rps::ClientSampler;
use gnunet_service_runtime::framing::{Class, OwnedFrame, ReadStep};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    RelativeTime,
    rps::{ClientRequest, ClientResponse},
};
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

#[derive(Clone, Copy)]
enum Mode {
    Sample,
    View(u32),
    Stream,
    Seed,
}
#[derive(Clone, Copy, PartialEq)]
enum WriteKind {
    Group,
    Query,
    Cancel,
    Stop,
}
#[derive(Clone, Copy)]
struct Origin {
    kind: WriteKind,
}
fn encode(request: ClientRequest<'_>) -> Result<Vec<u8>, Error> {
    let size = request.encoded_len()?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
    bytes.resize(size, 0);
    request.encode(&mut bytes)?;
    Ok(bytes)
}
/// One original operation, actual source, retained cursor and independent sampler.
/// Canceling a `progress()` future does not cancel or replay this owner.
pub struct Client {
    source: EndpointSource,
    channel: Option<Channel<Origin>>,
    request: Option<Vec<u8>>,
    group: Option<Vec<u8>>,
    group_id: Option<[u8; 64]>,
    mode: Mode,
    limits: Limits,
    overall: Bound,
    initial: Option<Bound>,
    input: Option<Bound>,
    epoch: Option<Epoch>,
    written: usize,
    request_written: bool,
    group_bytes: usize,
    group_written: bool,
    input_bytes: usize,
    records: u64,
    samples: usize,
    sampler: Option<ClientSampler>,
    random: NativeRandom,
    batch: bool,
    peer_cursor: usize,
    cancelling: bool,
    cancel_queued: bool,
    cancellation_written: bool,
    cancellation_bytes: usize,
    stopping_group: bool,
    group_stop_written: bool,
    group_stop_bytes: usize,
    pending: Option<Progress>,
    closed: bool,
}
impl Client {
    /// Prepare one normal query, with no native IO or background task.
    /// A positive sample count creates the actual independent random sampler.
    pub fn new(
        source: EndpointSource,
        query: Query<'_>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        Self::prepare(source, None, query, limits, original)
    }
    /// Join and observe/sample the subgroup on the very same original MQ.
    /// Whole SubStart precedes the query and every read. Closing this owner
    /// closes that original membership; no fresh-MQ SubStop is fabricated.
    pub fn new_in_group(
        source: EndpointSource,
        group: [u8; 64],
        round_interval: RelativeTime,
        query: Query<'_>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        if round_interval.as_micros() == 0 || round_interval.is_forever() {
            return Err(Fault::InvalidInput.into());
        }
        if matches!(query, Query::Seed { .. }) {
            return Err(Fault::Unsupported.into());
        }
        Self::prepare(
            source,
            Some((group, round_interval)),
            query,
            limits,
            original,
        )
    }
    fn prepare(
        source: EndpointSource,
        group: Option<([u8; 64], RelativeTime)>,
        query: Query<'_>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        let overall = Bound::targets(original);
        overall.check(source.clock().as_ref())?;
        let (mode, request, count) = match query {
            Query::Sample { count } => {
                if count > limits.max_sample_peers {
                    return Err(Fault::TooLarge.into());
                }
                (Mode::Sample, ClientRequest::StreamRequest, Some(count))
            }
            Query::View { updates } => (
                Mode::View(updates),
                ClientRequest::ViewRequest { updates },
                None,
            ),
            Query::Stream => (Mode::Stream, ClientRequest::StreamRequest, None),
            Query::Seed { peers } => (Mode::Seed, ClientRequest::Seed { peers }, None),
        };
        let group_id = group.map(|(id, _)| id);
        let size = request.encoded_len()?;
        let framing = limits.framing(if group.is_some() { size.max(80) } else { size })?;
        let local_empty = count == Some(0);
        let mut random = NativeRandom::default();
        let sampler = if let Some(n) = count.filter(|n| *n > 0) {
            let now = source.clock().sample()?.now.as_micros();
            let result = ClientSampler::new(n, now, &mut random);
            match result {
                Ok(sampler) => Some(sampler),
                Err(e) => {
                    return Err(random
                        .take_error()
                        .map_or_else(|| Error::from(e), Error::Entropy));
                }
            }
        } else {
            None
        };
        overall.check(source.clock().as_ref())?;
        let (channel, initial, request, group) = if local_empty {
            (None, None, None, None)
        } else {
            let initial = Bound::new(source.clock().as_ref(), limits.initial_timeout)?;
            let request = encode(request)?;
            let group = group
                .map(|(group, round_interval)| {
                    encode(ClientRequest::SubStart {
                        reserved: [0; 4],
                        round_interval,
                        group,
                    })
                })
                .transpose()?;
            let channel = Channel::new(source.duplicate()?, framing)?;
            (Some(channel), Some(initial), Some(request), group)
        };
        Ok(Self {
            source,
            channel,
            request,
            group,
            group_id,
            mode,
            limits,
            overall,
            initial,
            input: None,
            epoch: None,
            written: 0,
            request_written: false,
            group_bytes: 0,
            group_written: false,
            input_bytes: 0,
            records: 0,
            samples: 0,
            sampler,
            random,
            batch: false,
            peer_cursor: 0,
            cancelling: false,
            cancel_queued: false,
            cancellation_written: false,
            cancellation_bytes: 0,
            stopping_group: false,
            group_stop_written: false,
            group_stop_bytes: 0,
            pending: local_empty.then_some(Progress::Complete {
                epoch: None,
                records: 0,
            }),
            closed: local_empty,
        })
    }
    fn physical_close(&mut self) {
        if let Some(mut channel) = self.channel.take() {
            channel.close();
        }
        self.request = None;
        self.group = None;
        self.sampler = None;
        self.initial = None;
        self.input = None;
        self.batch = false;
        self.closed = true;
    }
    fn retire(&mut self, cause: Cause) -> Loss {
        let entropy_error = self.random.take_error();
        let loss = Loss {
            epoch: self.epoch.clone(),
            cause,
            written: self.written,
            request_written: self.request_written,
            group_bytes: self.group_bytes,
            group_written: self.group_written,
            records: self.records,
            samples: self.samples,
            partial_input: self.input_bytes,
            cancellation_written: self.cancellation_written,
            cancellation_bytes: self.cancellation_bytes,
            group_stop_written: self.group_stop_written,
            group_stop_bytes: self.group_stop_bytes,
            entropy_error,
        };
        self.physical_close();
        loss
    }
    /// Close the original native attempt/MQ before returning its real facts.
    /// This does not claim that a remote cancel or subgroup stop was processed.
    pub fn close(&mut self) -> Loss {
        self.pending = None;
        self.retire(Cause::Cancelled)
    }
    /// Cancel this original subscription with its legal same-source packet.
    /// A partially written original query or a seed is closed physically instead
    /// of appending a packet in the middle of its immutable original bytes.
    pub fn cancel(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if !self.request_written || matches!(self.mode, Mode::Seed) {
            let loss = self.retire(Cause::Cancelled);
            self.pending = Some(Progress::Cancelled(loss));
        } else {
            self.sampler = None;
            self.cancelling = true;
        }
        Ok(())
    }
    /// Stop only this owner's original subgroup on its actual MQ. A whole
    /// query is first canceled with the matching standard packet, followed by
    /// SubStop for the original group, then real source close. Partial startup
    /// is physically closed instead of splicing bytes. Local write facts never
    /// claim that either remote instruction was processed.
    pub fn stop_sub(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.group_id.is_none() {
            return Err(Fault::Unsupported.into());
        }
        self.stopping_group = true;
        self.cancel()
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if self.overall.poll_native(cx)
            || self.initial.as_mut().is_some_and(|b| b.poll_native(cx))
            || self.input.as_mut().is_some_and(|b| b.poll_native(cx))
        {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn check(&self) -> Result<(), Error> {
        self.overall.check(self.source.clock().as_ref())?;
        if let Some(b) = &self.initial {
            b.check(self.source.clock().as_ref())?;
        }
        if let Some(b) = &self.input {
            b.check(self.source.clock().as_ref())?;
        }
        Ok(())
    }
    /// Earliest unchanged phase/overall native target, including during output.
    #[must_use]
    pub fn native_deadline(&self) -> Instant {
        self.initial
            .as_ref()
            .map_or(self.overall.targets.hard, |b| {
                b.targets.hard.min(self.overall.targets.hard)
            })
            .min(
                self.input
                    .as_ref()
                    .map_or(self.overall.targets.hard, |b| b.targets.hard),
            )
    }
    /// Clock-free bound check with no new IO, usable while output is blocked.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Loss> {
        if self.closed {
            return None;
        }
        match self.guard(cx) {
            Ok(()) => None,
            Err(e) => Some(self.retire(Cause::Failure(e))),
        }
    }
    fn enqueue(&mut self, bytes: Vec<u8>, kind: WriteKind) -> Result<(), Error> {
        let framing = self
            .channel
            .as_mut()
            .and_then(Channel::framing_mut)
            .ok_or(Fault::NotReady)?;
        framing.reserve(bytes.len(), Class::Ordinary)?;
        framing
            .enqueue_owned(OwnedFrame::new(bytes), Origin { kind }, Class::Ordinary)
            .map_err(|e| e.reason)?;
        Ok(())
    }
    fn release_input(&mut self) -> Result<(), Error> {
        self.channel
            .as_mut()
            .and_then(Channel::framing_mut)
            .ok_or(Fault::NotReady)?
            .release_frame();
        self.input = None;
        self.input_bytes = 0;
        self.batch = false;
        self.peer_cursor = 0;
        Ok(())
    }
    fn complete(&mut self) {
        let progress = Progress::Complete {
            epoch: self.epoch.clone(),
            records: self.records,
        };
        self.physical_close();
        self.pending = Some(progress);
    }
    fn sample_next(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress>, Error> {
        if self.batch || self.sampler.is_none() {
            return Ok(None);
        }
        self.guard(cx)?;
        self.check()?;
        let now = self.source.clock().sample()?.now.as_micros();
        let result = self
            .sampler
            .as_mut()
            .ok_or(Fault::NotReady)?
            .next(now, &mut self.random)?;
        self.guard(cx)?;
        self.check()?;
        let Some(info) = result else {
            return Ok(None);
        };
        self.samples = self.samples.checked_add(1).ok_or(Fault::Overflow)?;
        let epoch = self.epoch.clone().ok_or(Fault::StaleGeneration)?;
        if self.sampler.as_ref().is_some_and(|s| s.remaining() == 0) {
            self.complete();
        }
        Ok(Some(Progress::Sample {
            epoch,
            ordinal: self.samples,
            info,
        }))
    }
    fn frame(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress>, Error> {
        let Some(bytes) = self
            .channel
            .as_ref()
            .and_then(Channel::framing)
            .and_then(|f| f.frame())
        else {
            return Ok(None);
        };
        let response = ClientResponse::decode(bytes, self.limits.reply_profile)?;
        match (self.mode, response) {
            (Mode::View(_), ClientResponse::View { .. })
            | (Mode::Stream | Mode::Sample, ClientResponse::Stream { .. }) => {}
            _ => return Err(Fault::Malformed.into()),
        }
        if matches!(self.mode, Mode::Sample) {
            if !self.batch {
                self.records = self.records.checked_add(1).ok_or(Fault::Overflow)?;
                self.batch = true;
                self.peer_cursor = 0;
                self.input = None;
            }
            let peers = response.peers();
            if let Some(peer) = peers.get(self.peer_cursor).copied() {
                self.sampler
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .observe(&[peer], &mut HmacRank)?;
                self.peer_cursor = self.peer_cursor.checked_add(1).ok_or(Fault::Overflow)?;
            }
            let finished = self.peer_cursor == peers.len();
            self.guard(cx)?;
            self.check()?;
            if finished {
                self.release_input()?;
            }
            return Ok(Some(Progress::Activity));
        }
        let epoch = self.epoch.clone().ok_or(Fault::StaleGeneration)?;
        let next = self.records.checked_add(1).ok_or(Fault::Overflow)?;
        let frame = OwnedFrame::copy_from(bytes)?;
        self.guard(cx)?;
        self.check()?;
        self.release_input()?;
        self.records = next;
        let record = Observation {
            epoch,
            ordinal: next,
            frame,
            profile: self.limits.reply_profile,
        };
        if let Mode::View(limit) = self.mode
            && limit != 0
            && next == u64::from(limit)
        {
            self.complete();
        }
        Ok(Some(Progress::Record(record)))
    }
    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.guard(cx)?;
        match self.channel.as_mut().ok_or(Fault::Closed)?.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        }
        self.check()?;
        if self.epoch.is_none() {
            return match self.channel.as_mut().ok_or(Fault::Closed)?.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    Poll::Ready(Ok(Progress::Retry { error }))
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.guard(cx)?;
                    self.check()?;
                    let (bytes, kind) = if let Some(bytes) = self.group.take() {
                        (bytes, WriteKind::Group)
                    } else {
                        (
                            self.request.take().ok_or(Fault::NotReady)?,
                            WriteKind::Query,
                        )
                    };
                    self.enqueue(bytes, kind)?;
                    let epoch = Epoch(Arc::new(()));
                    self.epoch = Some(epoch.clone());
                    Poll::Ready(Ok(Progress::Attached(epoch)))
                }
            };
        }
        if !self.request_written || self.cancelling {
            if self.cancelling && !self.cancel_queued {
                // No old read frame is accepted after this local cancellation.
                let request = match self.mode {
                    Mode::View(_) => ClientRequest::ViewCancel,
                    Mode::Sample | Mode::Stream => ClientRequest::StreamCancel,
                    Mode::Seed => return Poll::Ready(Err(Fault::Unsupported.into())),
                };
                self.enqueue(encode(request)?, WriteKind::Cancel)?;
                // Local admission is separate from the later physical write.
                self.cancel_queued = true;
            }
            let step = match self
                .channel
                .as_mut()
                .and_then(Channel::framing_mut)
                .ok_or(Fault::NotReady)?
                .poll_write(cx)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(p)) => p,
            };
            match step.origin.kind {
                WriteKind::Group => {
                    self.group_bytes = self
                        .group_bytes
                        .checked_add(step.bytes)
                        .ok_or(Fault::Overflow)?;
                    if step.complete {
                        self.group_written = true;
                        let bytes = self.request.take().ok_or(Fault::NotReady)?;
                        self.guard(cx)?;
                        self.check()?;
                        self.enqueue(bytes, WriteKind::Query)?;
                        return Poll::Ready(Ok(Progress::GroupWritten {
                            epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                            bytes: self.group_bytes,
                        }));
                    }
                }
                WriteKind::Query => {
                    self.written = self
                        .written
                        .checked_add(step.bytes)
                        .ok_or(Fault::Overflow)?;
                    if step.complete {
                        self.request_written = true;
                        self.guard(cx)?;
                        self.check()?;
                        self.initial = None;
                        return Poll::Ready(Ok(Progress::Written {
                            epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                            bytes: self.written,
                        }));
                    }
                }
                WriteKind::Cancel => {
                    self.cancellation_bytes = self
                        .cancellation_bytes
                        .checked_add(step.bytes)
                        .ok_or(Fault::Overflow)?;
                    if step.complete {
                        self.cancellation_written = true;
                        self.guard(cx)?;
                        self.check()?;
                        if self.stopping_group {
                            if !self.group_written {
                                return Poll::Ready(Err(Fault::NotReady.into()));
                            }
                            let group = self.group_id.ok_or(Fault::NotReady)?;
                            self.enqueue(
                                encode(ClientRequest::SubStop { group })?,
                                WriteKind::Stop,
                            )?;
                        } else {
                            return Poll::Ready(Ok(Progress::Cancelled(
                                self.retire(Cause::Cancelled),
                            )));
                        }
                    }
                }
                WriteKind::Stop => {
                    self.group_stop_bytes = self
                        .group_stop_bytes
                        .checked_add(step.bytes)
                        .ok_or(Fault::Overflow)?;
                    if step.complete {
                        self.group_stop_written = true;
                        self.guard(cx)?;
                        self.check()?;
                        return Poll::Ready(Ok(Progress::Cancelled(self.retire(Cause::Cancelled))));
                    }
                }
            }
            self.guard(cx)?;
            self.check()?;
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Some(progress) = self.sample_next(cx)? {
            return Poll::Ready(Ok(progress));
        }
        if let Some(progress) = self.frame(cx)? {
            return Poll::Ready(Ok(progress));
        }
        match self
            .channel
            .as_mut()
            .and_then(Channel::framing_mut)
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                Poll::Ready(Ok(Progress::Lost(self.retire(Cause::Eof))))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                if bytes > 0 && self.input.is_none() {
                    self.input = Some(Bound::new(
                        self.source.clock().as_ref(),
                        self.limits.input_timeout,
                    )?);
                }
                self.input_bytes = self.input_bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
                self.guard(cx)?;
                self.check()?;
                Poll::Ready(Ok(self.frame(cx)?.unwrap_or(Progress::Activity)))
            }
        }
    }
    /// Drive only this original owner. All failures physically close before loss
    /// exposure. No request bytes or partial sampler are replayed on another MQ.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if let Some(progress) = self.pending.take() {
            return Poll::Ready(Ok(progress));
        }
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        match self.poll_inner(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Ok(Progress::Lost(self.retire(Cause::Failure(e))))),
            other => other,
        }
    }
    /// Wait on this retained original owner; dropping the wait preserves state.
    pub async fn progress(&mut self) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
