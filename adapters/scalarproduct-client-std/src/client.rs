//! One original computation MQ, streamed multipart input and exact raw response.
use crate::{
    Bounds, Cause, ELEMENT_BYTES, Epoch, Error, Limits, Loss, Progress, Receipt, Response,
    ResponseStatus, Role, budget::Bound,
};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{self, Class, OwnedFrame, ReadStep};
use gnunet_types::Error as Fault;
use gnunet_wire::official::scalarproduct::{ClientRequest, ClientResponse};
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
#[derive(Clone, Copy, Eq, PartialEq)]
struct Chunk {
    start: u32,
    count: u32,
}
/// Actual one-source computation; dropping progress futures preserves its cursors.
/// Construct/drive from an entered Tokio IO/time runtime; no task is spawned.
pub struct Client {
    source: EndpointSource,
    channel: Channel<Chunk>,
    role: Role,
    limits: Limits,
    overall: Bound,
    initial: Option<Bound>,
    write: Option<Bound>,
    input: Option<Bound>,
    elements: Vec<[u8; ELEMENT_BYTES]>,
    total: u32,
    offset: u32,
    pending: Option<Chunk>,
    epoch: Option<Epoch>,
    frames: u64,
    written: u64,
    partial: usize,
    input_bytes: usize,
    read_first: bool,
    closed: bool,
}
impl Client {
    /// Adopt the exact encoded vector. Keys must be unique; zero values are kept.
    /// Only one encoded multipart frame is retained alongside this vector.
    pub fn new(
        source: EndpointSource,
        role: Role,
        elements: Vec<[u8; ELEMENT_BYTES]>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        limits.validate()?;
        original.check(source.clock().as_ref())?;
        let initial = Bound::phase(source.clock().as_ref(), limits.initial_timeout, original)?;
        let total = u32::try_from(elements.len()).map_err(|_| Fault::TooLarge)?;
        if elements.is_empty() || elements.len() > limits.elements {
            return Err(Fault::InvalidInput.into());
        }
        let vector_bytes = elements
            .capacity()
            .checked_mul(ELEMENT_BYTES)
            .ok_or(Fault::Overflow)?;
        if vector_bytes > limits.vector_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut order = Vec::new();
        order
            .try_reserve_exact(elements.len())
            .map_err(|_| Fault::Capacity)?;
        let temporary = order
            .capacity()
            .checked_mul(std::mem::size_of::<usize>())
            .and_then(|n| n.checked_add(vector_bytes))
            .ok_or(Fault::Overflow)?;
        if temporary > limits.vector_bytes {
            return Err(Fault::Capacity.into());
        }
        order.extend(0..elements.len());
        order.sort_unstable_by(|a, b| elements[*a][..64].cmp(&elements[*b][..64]));
        if order
            .windows(2)
            .any(|w| elements[w[0]][..64] == elements[w[1]][..64])
        {
            return Err(Fault::Conflict.into());
        }
        drop(order);
        original.check(source.clock().as_ref())?;
        let native = framing::Limits {
            frame_bytes: limits.frame_bytes,
            ordinary: framing::Budget {
                frames: 1,
                bytes: limits.frame_bytes,
            },
            reserved: framing::Budget::default(),
            accounting: framing::Accounting::Retained,
            io_slice_bytes: limits.io_slice_bytes,
        };
        let channel = Channel::new(source.duplicate()?, native)?;
        Ok(Self {
            source,
            channel,
            role,
            limits,
            overall: Bound::targets(original),
            initial: Some(initial),
            write: None,
            input: None,
            elements,
            total,
            offset: 0,
            pending: None,
            epoch: None,
            frames: 0,
            written: 0,
            partial: 0,
            input_bytes: 0,
            read_first: false,
            closed: false,
        })
    }
    /// Original computation role and service section, not current peer authority.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
    /// Original shared source clock for bounded caller work/output.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.source.clock()
    }
    /// Actual source/input exposure; no local count implies service processing.
    #[must_use]
    pub fn receipt(&self) -> Receipt {
        Receipt {
            epoch: self.epoch.clone(),
            elements: self.total,
            elements_written: self.offset,
            frames_written: self.frames,
            written_bytes: self.written,
            partial_frame_bytes: self.partial,
            all_input_written: self.offset == self.total,
            partial_response_bytes: self.input_bytes,
        }
    }
    /// Original native overall target, never renewed by multipart progress.
    #[must_use]
    pub fn native_deadline(&self) -> Instant {
        self.overall.targets.hard
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.overall.native(cx)
            || self.initial.as_mut().is_some_and(|b| b.native(cx))
            || self.write.as_mut().is_some_and(|b| b.native(cx))
            || self.input.as_mut().is_some_and(|b| b.native(cx))
    }
    fn check(&self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        // A known native expiration fences even a failing/custom canonical
        // provider. Check again after its sample, without renewing any target.
        let native = Instant::now();
        let expired = |b: &Bound| native >= b.targets.hard;
        if expired(&self.overall)
            || self.initial.as_ref().is_some_and(expired)
            || self.write.as_ref().is_some_and(expired)
            || self.input.as_ref().is_some_and(expired)
        {
            return Err(Fault::Deadline.into());
        }
        let now = self.source.clock().sample()?.now.as_micros();
        let native = Instant::now();
        let bad = |b: &Bound| native >= b.targets.hard || now >= b.targets.expires;
        if bad(&self.overall)
            || self.initial.as_ref().is_some_and(bad)
            || self.write.as_ref().is_some_and(bad)
            || self.input.as_ref().is_some_and(bad)
        {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn physical_close(&mut self) {
        self.channel.close();
        self.closed = true;
        self.initial = None;
        self.write = None;
        self.input = None;
        self.pending = None;
        self.elements = Vec::new();
    }
    fn lost(&mut self, cause: Cause) -> Loss {
        let receipt = self.receipt();
        self.physical_close();
        Loss { receipt, cause }
    }
    /// Clock-free cancellation closes the original MQ. No wire CANCEL/ACK exists.
    pub fn close(&mut self) -> Loss {
        self.lost(Cause::Cancelled)
    }
    /// Retire at known native expiration before any further canonical/native IO.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Loss> {
        if !self.closed && self.expired(cx) {
            Some(self.lost(Cause::Deadline))
        } else {
            None
        }
    }
    fn queue(&mut self) -> Result<(), Error> {
        if self.pending.is_some() || self.offset == self.total {
            return Ok(());
        }
        self.check()?;
        let first = self.offset == 0;
        let prefix = if first {
            match self.role {
                Role::Alice { .. } => 112,
                Role::Bob { .. } => 80,
            }
        } else {
            8
        };
        let capacity = (self.limits.frame_bytes - prefix) / ELEMENT_BYTES;
        let start = usize::try_from(self.offset).map_err(|_| Fault::TooLarge)?;
        let left = usize::try_from(self.total - self.offset).map_err(|_| Fault::TooLarge)?;
        let count = left.min(capacity);
        if count == 0 {
            return Err(Fault::Capacity.into());
        }
        let end = start.checked_add(count).ok_or(Fault::Overflow)?;
        let values = self.elements.get(start..end).ok_or(Fault::Stale)?;
        let request = match (first, &self.role) {
            (true, Role::Alice { session, peer }) => ClientRequest::Alice {
                total: self.total,
                reserved: 0,
                session,
                peer,
                elements: values,
            },
            (true, Role::Bob { session }) => ClientRequest::Bob {
                total: self.total,
                reserved: 0,
                session,
                elements: values,
            },
            (false, Role::Alice { .. }) => ClientRequest::AlicePart { elements: values },
            (false, Role::Bob { .. }) => ClientRequest::BobPart { elements: values },
        };
        let size = request.encoded_len()?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
        bytes.resize(size, 0);
        request.encode(&mut bytes)?;
        if bytes.capacity() > self.limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        let phase = Bound::phase(
            self.source.clock().as_ref(),
            self.limits.write_timeout,
            self.overall.targets,
        )?;
        let chunk = Chunk {
            start: self.offset,
            count: u32::try_from(count).map_err(|_| Fault::TooLarge)?,
        };
        self.channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .enqueue_owned(OwnedFrame::new(bytes), chunk, Class::Ordinary)
            .map_err(|e| e.reason)?;
        self.pending = Some(chunk);
        self.write = Some(phase);
        self.partial = 0;
        Ok(())
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.queue()?;
        if self.pending.is_none() {
            return Poll::Pending;
        }
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(w)) => {
                if self.pending != Some(w.origin) {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                self.partial = self.partial.checked_add(w.bytes).ok_or(Fault::Overflow)?;
                self.written = self
                    .written
                    .checked_add(u64::try_from(w.bytes).map_err(|_| Fault::Overflow)?)
                    .ok_or(Fault::Overflow)?;
                if w.complete {
                    self.offset = self
                        .offset
                        .checked_add(w.origin.count)
                        .filter(|n| *n <= self.total)
                        .ok_or(Fault::Overflow)?;
                    self.frames = self.frames.checked_add(1).ok_or(Fault::Overflow)?;
                    self.pending = None;
                    self.write = None;
                    self.initial = None;
                    self.partial = 0;
                    if self.offset == self.total {
                        self.elements = Vec::new();
                    }
                }
                self.read_first = true;
                Poll::Ready(Ok(Progress::Written {
                    epoch: self.epoch.clone().ok_or(Fault::Stale)?,
                    bytes: w.bytes,
                    complete: w.complete,
                    receipt: self.receipt(),
                }))
            }
        }
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.frames == 0 {
            return Poll::Pending;
        }
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if let Some(frame) = framed.frame() {
            let raw = ClientResponse::decode(frame)?;
            if raw.product.len() > self.limits.result_bytes {
                return Poll::Ready(Err(Fault::Capacity.into()));
            }
            if raw.status == ResponseStatus::SUCCESS && self.offset != self.total {
                return Poll::Ready(Err(Fault::Malformed.into()));
            }
            let mut product = Vec::new();
            product
                .try_reserve_exact(raw.product.len())
                .map_err(|_| Fault::Capacity)?;
            if product.capacity() > self.limits.result_bytes {
                return Poll::Ready(Err(Fault::Capacity.into()));
            }
            product.extend_from_slice(raw.product);
            let response = Response {
                status: raw.status,
                range: raw.range,
                product,
            };
            let receipt = self.receipt();
            self.physical_close();
            return Poll::Ready(Ok(Progress::Result { response, receipt }));
        }
        match framed.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Eof))))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                if bytes > 0 && self.input.is_none() {
                    self.input = Some(Bound::phase(
                        self.source.clock().as_ref(),
                        self.limits.input_timeout,
                        self.overall.targets,
                    )?);
                }
                self.input_bytes = self.input_bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
                if self.expired(cx) {
                    return Poll::Ready(Err(Fault::Deadline.into()));
                }
                self.check()?;
                self.read_first = false;
                Poll::Ready(Ok(Progress::Activity))
            }
        }
    }
    fn inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.check()?;
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
                    if self.expired(cx) {
                        return Poll::Ready(Err(Fault::Deadline.into()));
                    }
                    self.check()?;
                    let epoch = Epoch(Arc::new(()));
                    self.epoch = Some(epoch.clone());
                    self.queue()?;
                    Poll::Ready(Ok(Progress::Attached(epoch)))
                }
            };
        }
        if self.channel.framing().is_some_and(|f| f.frame().is_some()) {
            return self.read(cx);
        }
        for offset in 0..2 {
            if self.expired(cx) {
                return Poll::Ready(Err(Fault::Deadline.into()));
            }
            self.check()?;
            let p = if self.read_first == (offset == 0) {
                self.read(cx)
            } else {
                self.write(cx)
            };
            if p.is_ready() {
                return p;
            }
        }
        Poll::Pending
    }
    /// Poll the original owner. All errors close it before exposing typed loss.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if let Some(loss) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        match self.inner(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Failure(e))))),
            p => p,
        }
    }
    /// Await only this original owner; canceling this future does not replay input.
    pub async fn progress(&mut self) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.physical_close();
    }
}
