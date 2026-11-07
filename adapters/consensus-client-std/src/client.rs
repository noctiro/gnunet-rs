//! Retained original JOIN/INSERT/CONCLUDE FIFO and actual523/525 receive owner.
use crate::{
    Bounds, Cause, Epoch, Error, InsertId, Kind, Limits, Loss, Observation, Pending, Progress,
    Receipt, budget::Bound, types::Tag,
};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{Class, OwnedFrame, ReadStep};
use gnunet_types::Error as Fault;
use gnunet_wire::official::consensus::{ClientRequest, ClientResponse, Join, USER_TYPE_MAX};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    mem::size_of,
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::{Context, Poll},
    time::Instant,
};
/// One native original session. Waiting future cancellation preserves all cursors;
/// explicit close destroys this exact MQ, with no private cancel frame or replay.
pub struct Client {
    source: EndpointSource,
    source_bytes: usize,
    channel: Channel<Tag>,
    limits: Limits,
    owner: Arc<()>,
    next: Option<u64>,
    epoch: Option<Epoch>,
    overall: Bound,
    initial: Option<Bound>,
    input: Option<Bound>,
    queue: VecDeque<Pending>,
    queue_bytes: usize,
    queue_capacity_bytes: usize,
    local: Vec<[u8; 64]>,
    joined: bool,
    conclude_queued: bool,
    concluded: bool,
    inserts_written: u64,
    elements: u64,
    partial_input: usize,
    closed: bool,
    io_class: u8,
    alarm: Option<Pin<Box<tokio::time::Sleep>>>,
}
#[derive(Clone, Copy)]
enum DriveMode {
    Duplex,
    Transmit,
}
fn encode(request: ClientRequest<'_>) -> Result<Vec<u8>, Error> {
    let n = request.encoded_len()?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    bytes.resize(n, 0);
    request.encode(&mut bytes)?;
    Ok(bytes)
}
impl Client {
    /// Prepare one original configured MQ and official JOIN. No socket, service,
    /// entropy, hidden Resolver or worker is started during construction.
    pub fn new(
        source: EndpointSource,
        join: Join<'_>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        let source = source.fixed_endpoint()?;
        let source_bytes = source
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::NotReady)?;
        if source_bytes > limits.retained_bytes {
            return Err(Fault::Capacity.into());
        }
        let framing = limits.framing()?;
        let overall = original.clamp(source.clock().as_ref(), join.deadline)?;
        if join.start >= join.deadline {
            return Err(Fault::InvalidInput.into());
        }
        let initial = Bound::phase(source.clock().as_ref(), limits.initial_timeout, overall)?;
        let request = encode(ClientRequest::Join(join))?;
        let channel = Channel::new(source.duplicate()?, framing)?;
        let mut this = Self {
            source,
            source_bytes,
            channel,
            limits,
            owner: Arc::new(()),
            next: Some(1),
            epoch: None,
            overall: Bound::new(overall),
            initial: Some(initial),
            input: None,
            queue: VecDeque::new(),
            queue_bytes: 0,
            queue_capacity_bytes: 0,
            local: Vec::new(),
            joined: false,
            conclude_queued: false,
            concluded: false,
            inserts_written: 0,
            elements: 0,
            partial_input: 0,
            closed: false,
            io_class: 0,
            alarm: None,
        };
        this.admit(request, Kind::Join, Tag::Join)?;
        Ok(this)
    }
    fn retained(&self) -> Result<usize, Error> {
        self.queue
            .capacity()
            .checked_mul(size_of::<Pending>())
            .and_then(|n| {
                self.local
                    .capacity()
                    .checked_mul(64)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(self.queue_capacity_bytes))
            .and_then(|n| n.checked_add(self.source_bytes))
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn reserve_queue(&mut self) -> Result<(), Error> {
        if self.queue.len() >= self.limits.queued_frames {
            return Err(Fault::WouldBlock.into());
        }
        if self.queue.len() < self.queue.capacity() {
            return Ok(());
        }
        let target = self
            .queue
            .capacity()
            .max(2)
            .checked_mul(2)
            .ok_or(Fault::Overflow)?
            .min(self.limits.queued_frames);
        let free = self
            .limits
            .retained_bytes
            .checked_sub(self.retained()?)
            .ok_or(Fault::Capacity)?;
        let want = target
            .checked_mul(size_of::<Pending>())
            .ok_or(Fault::Overflow)?;
        if want > free {
            return Err(Fault::Capacity.into());
        }
        let mut next = VecDeque::new();
        next.try_reserve_exact(target)
            .map_err(|_| Fault::Capacity)?;
        let actual = next
            .capacity()
            .checked_mul(size_of::<Pending>())
            .ok_or(Fault::Overflow)?;
        if actual > free {
            return Err(Fault::Capacity.into());
        }
        next.append(&mut self.queue);
        self.queue = next;
        Ok(())
    }
    fn reserve_local(&mut self) -> Result<(), Error> {
        if self.local.len() >= self.limits.local_elements {
            return Err(Fault::Capacity.into());
        }
        if self.local.len() < self.local.capacity() {
            return Ok(());
        }
        let target = self
            .local
            .capacity()
            .max(2)
            .checked_mul(2)
            .ok_or(Fault::Overflow)?
            .min(self.limits.local_elements);
        let free = self
            .limits
            .retained_bytes
            .checked_sub(self.retained()?)
            .ok_or(Fault::Capacity)?;
        if target.checked_mul(64).ok_or(Fault::Overflow)? > free {
            return Err(Fault::Capacity.into());
        }
        let mut next = Vec::new();
        next.try_reserve_exact(target)
            .map_err(|_| Fault::Capacity)?;
        if next.capacity().checked_mul(64).ok_or(Fault::Overflow)? > free {
            return Err(Fault::Capacity.into());
        }
        next.append(&mut self.local);
        self.local = next;
        Ok(())
    }
    fn admit(&mut self, bytes: Vec<u8>, kind: Kind, tag: Tag) -> Result<(), Error> {
        self.check()?;
        if bytes.len() > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        let total = self
            .queue_bytes
            .checked_add(bytes.len())
            .ok_or(Fault::Overflow)?;
        if total > self.limits.queued_bytes {
            return Err(Fault::WouldBlock.into());
        }
        self.reserve_queue()?;
        let charged = self
            .queue_capacity_bytes
            .checked_add(bytes.capacity())
            .ok_or(Fault::Overflow)?;
        if self
            .retained()?
            .checked_add(bytes.capacity())
            .ok_or(Fault::Overflow)?
            > self.limits.retained_bytes
        {
            return Err(Fault::Capacity.into());
        }
        let bound = Bound::phase(
            self.source.clock().as_ref(),
            self.limits.write_timeout,
            self.overall.target,
        )?;
        let original = bound.target;
        let length = bytes.len();
        let capacity = bytes.capacity();
        self.queue.push_back(Pending {
            kind,
            length,
            written: 0,
            whole: false,
            original,
            tag,
            bytes: Some(bytes),
            bound: Some(bound),
            capacity,
        });
        self.queue_bytes = total;
        self.queue_capacity_bytes = charged;
        Ok(())
    }
    fn fingerprint(kind: u16, data: &[u8]) -> [u8; 64] {
        gnunet_crypto::hash512_parts(&[&kind.to_be_bytes(), data])
    }
    /// Admit an original insertion before CONCLUDE, including before JOIN writes.
    /// The returned continuation has no service/peer processing acknowledgement.
    pub fn insert(&mut self, element_type: u16, data: &[u8]) -> Result<InsertId, Error> {
        self.check()?;
        if self.conclude_queued {
            return Err(Fault::Closed.into());
        }
        if element_type > USER_TYPE_MAX {
            return Err(Fault::InvalidInput.into());
        }
        let request = ClientRequest::Insert { element_type, data };
        let size = request.encoded_len()?;
        if size > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        let next = self.next.ok_or(Fault::Overflow)?;
        let hash = Self::fingerprint(element_type, data);
        let position = self.local.binary_search(&hash).err();
        if position.is_some() {
            self.reserve_local()?;
        }
        let bytes = encode(ClientRequest::Insert { element_type, data })?;
        let id = InsertId {
            owner: self.owner.clone(),
            serial: next,
        };
        self.admit(bytes, Kind::Insert(id.clone()), Tag::Insert(next))?;
        if let Some(at) = position {
            self.local.insert(at, hash);
        }
        self.next = next.checked_add(1);
        Ok(id)
    }
    /// Queue exactly one official524 after all original insertions. Only a later
    /// matching actual525 is completion; there is no processing ACK for524.
    pub fn conclude(&mut self) -> Result<(), Error> {
        self.check()?;
        if self.conclude_queued {
            return Err(Fault::Conflict.into());
        }
        let bytes = encode(ClientRequest::Conclude)?;
        self.admit(bytes, Kind::Conclude, Tag::Conclude)?;
        self.conclude_queued = true;
        Ok(())
    }
    fn physical_close(&mut self) {
        self.channel.close();
        if let Some(epoch) = &self.epoch {
            epoch.retire();
        }
        self.initial = None;
        self.input = None;
        self.closed = true;
        self.alarm = None;
    }
    fn retire(&mut self, cause: Cause) -> Loss {
        // A malformed header can fail after Framed retained its actual input
        // bytes but before it returned ReadStep::Progress. Preserve that exact
        // original prefix before physical close releases the framing owner.
        if let Some(framing) = self.channel.framing() {
            self.partial_input = self.partial_input.max(framing.read_progress_bytes());
        }
        self.physical_close();
        for pending in &mut self.queue {
            pending.bytes = None;
            pending.bound = None;
        }
        self.queue_bytes = 0;
        self.queue_capacity_bytes = 0;
        self.local = Vec::new();
        Loss {
            epoch: self.epoch.clone(),
            cause,
            joined: self.joined,
            concluded: self.concluded,
            inserts_written: self.inserts_written,
            elements: self.elements,
            partial_input: self.partial_input,
            pending: std::mem::take(&mut self.queue),
        }
    }
    /// Physically destroy the original MQ/attempt before returning its facts.
    /// This clock-free operation never emits a private cancel/acknowledgement.
    pub fn close(&mut self) -> Loss {
        self.retire(Cause::Cancelled)
    }
    fn check(&self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        let hard = self.native_deadline();
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let mut expires = self.overall.target.expires;
        for b in [self.initial.as_ref(), self.input.as_ref()]
            .into_iter()
            .flatten()
        {
            expires = expires.min(b.target.expires);
        }
        for p in &self.queue {
            expires = expires.min(p.original.expires);
        }
        let now = self.source.clock().sample()?.now.as_micros();
        if now >= expires || Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn native(&mut self, cx: &mut Context<'_>) -> bool {
        let at = self.native_deadline();
        if Instant::now() >= at {
            return true;
        }
        let timer = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at.into())));
        timer.as_mut().reset(at.into());
        timer.as_mut().poll(cx).is_ready()
    }
    /// Earliest original native target, usable while external output is blocked.
    #[must_use]
    pub fn native_deadline(&self) -> Instant {
        let mut at = self.overall.target.hard;
        for b in [self.initial.as_ref(), self.input.as_ref()]
            .into_iter()
            .flatten()
        {
            at = at.min(b.target.hard);
        }
        for p in &self.queue {
            at = at.min(p.original.hard);
        }
        at
    }
    /// Clock-free hard fence; returns a real physical retirement before loss.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Loss> {
        if !self.closed && self.native(cx) {
            Some(self.retire(Cause::Failure(Fault::Deadline.into())))
        } else {
            None
        }
    }
    fn frame(&mut self) -> Result<Option<Progress>, Error> {
        let Some(bytes) = self.channel.framing().and_then(|f| f.frame()) else {
            return Ok(None);
        };
        if !self.joined {
            return Err(Fault::Malformed.into());
        }
        match ClientResponse::decode(bytes)? {
            ClientResponse::Done => {
                // Elements can arrive while the local producer is still
                // working; only525 requires the original whole524 write.
                if !self.concluded {
                    return Err(Fault::Malformed.into());
                }
                self.check()?;
                let epoch = self.epoch.clone().ok_or(Fault::StaleGeneration)?;
                self.channel
                    .framing_mut()
                    .ok_or(Fault::NotReady)?
                    .release_frame();
                self.physical_close();
                self.local = Vec::new();
                Ok(Some(Progress::Done {
                    epoch,
                    elements: self.elements,
                }))
            }
            ClientResponse::Element { element_type, data } => {
                if element_type > USER_TYPE_MAX {
                    return Err(Fault::Malformed.into());
                }
                let own = self
                    .local
                    .binary_search(&Self::fingerprint(element_type, data))
                    .is_ok();
                let frame = if own {
                    None
                } else {
                    Some(OwnedFrame::copy_from(bytes)?)
                };
                self.check()?;
                self.channel
                    .framing_mut()
                    .ok_or(Fault::NotReady)?
                    .release_frame();
                self.input = None;
                self.partial_input = 0;
                if let Some(frame) = frame {
                    self.elements = self.elements.checked_add(1).ok_or(Fault::Overflow)?;
                    Ok(Some(Progress::Element(Observation {
                        epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                        ordinal: self.elements,
                        frame,
                    })))
                } else {
                    Ok(Some(Progress::Activity))
                }
            }
        }
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        mode: DriveMode,
    ) -> Poll<Result<Progress, Error>> {
        if self.native(cx) {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        }
        self.check()?;
        if self.epoch.is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    Poll::Ready(Ok(Progress::Retry(error)))
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = Epoch(Arc::new(AtomicBool::new(true)));
                    self.epoch = Some(epoch.clone());
                    Poll::Ready(Ok(Progress::Attached(epoch)))
                }
            };
        }
        if matches!(mode, DriveMode::Transmit) {
            return self.poll_output(cx);
        }
        // Alternate ready classes, but poll both when one is pending. A full
        // original TX queue or a caller paused before CONCLUDE cannot suppress
        // native RX/EOF/error observation on the same actual MQ.
        for _ in 0..2 {
            let class = self.io_class;
            self.io_class = (self.io_class + 1) % 2;
            let progress = if class == 0 {
                self.poll_output(cx)
            } else {
                self.poll_input(cx)
            };
            if progress.is_ready() {
                return progress;
            }
        }
        Poll::Pending
    }
    fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.check()?;
        if let Some(front) = self.queue.front_mut() {
            if let Some(bytes) = front.bytes.take() {
                let framing = self.channel.framing_mut().ok_or(Fault::NotReady)?;
                if let Err(e) = framing.reserve(bytes.len(), Class::Ordinary) {
                    front.bytes = Some(bytes);
                    return Poll::Ready(Err(e.into()));
                }
                if let Err(e) =
                    framing.enqueue_owned(OwnedFrame::new(bytes), front.tag, Class::Ordinary)
                {
                    return Poll::Ready(Err(e.reason.into()));
                }
            }
            let step = match self
                .channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .poll_write(cx)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r?,
            };
            if front.tag != step.origin {
                return Poll::Ready(Err(Fault::StaleGeneration.into()));
            }
            front.written = front
                .written
                .checked_add(step.bytes)
                .ok_or(Fault::Overflow)?;
            if step.complete {
                let mut p = self.queue.pop_front().ok_or(Fault::NotReady)?;
                p.whole = true;
                self.queue_bytes = self
                    .queue_bytes
                    .checked_sub(p.length)
                    .ok_or(Fault::Conflict)?;
                self.queue_capacity_bytes = self
                    .queue_capacity_bytes
                    .checked_sub(p.capacity)
                    .ok_or(Fault::Conflict)?;
                match p.tag {
                    Tag::Join => {
                        self.joined = true;
                        self.initial = None;
                    }
                    Tag::Insert(_) => {
                        self.inserts_written =
                            self.inserts_written.checked_add(1).ok_or(Fault::Overflow)?
                    }
                    Tag::Conclude => self.concluded = true,
                }
                return Poll::Ready(Ok(Progress::Written(Receipt {
                    epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                    kind: p.kind,
                    written: p.written,
                    original: p.original,
                })));
            }
            return Poll::Ready(Ok(Progress::Activity));
        }
        Poll::Pending
    }
    fn poll_input(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.check()?;
        if let Some(frame) = self.frame()? {
            return Poll::Ready(Ok(frame));
        }
        match self
            .channel
            .framing_mut()
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
                    self.input = Some(Bound::phase(
                        self.source.clock().as_ref(),
                        self.limits.input_timeout,
                        self.overall.target,
                    )?);
                }
                self.partial_input = self
                    .partial_input
                    .checked_add(bytes)
                    .ok_or(Fault::Overflow)?;
                self.check()?;
                Poll::Ready(Ok(self.frame()?.unwrap_or(Progress::Activity)))
            }
        }
    }
    /// Drive one bounded original native step. Failure closes real IO first and
    /// returns Lost with original cause and every unfinished request; no replay.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.poll_mode(cx, DriveMode::Duplex)
    }
    /// Progress actual connection/TX under the same original guards without
    /// reading or consuming another remote element. A caller holding one
    /// observation can finish bounded validation without starving its own
    /// INSERT/CONCLUDE writes or allocating an extra observation queue.
    pub fn poll_transmit(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.poll_mode(cx, DriveMode::Transmit)
    }
    fn poll_mode(
        &mut self,
        cx: &mut Context<'_>,
        mode: DriveMode,
    ) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        match self.poll_inner(cx, mode) {
            Poll::Ready(Err(e)) => Poll::Ready(Ok(Progress::Lost(self.retire(Cause::Failure(e))))),
            other => other,
        }
    }
    /// Cancel-safe wait on this retained original owner.
    pub async fn progress(&mut self) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Exact physical-source liveness survives in caller-held Epoch and
        // receipt/observation clones. Retire it before native Channel drop;
        // destruction produces no successful result, callback or replacement.
        self.physical_close();
    }
}

#[cfg(all(test, unix))]
mod tests;
