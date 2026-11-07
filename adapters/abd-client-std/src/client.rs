use crate::{
    Bounds, Cause, Epoch, Error, Kind, Limits, Loss, Observation, Progress, Receipt, budget::Bound,
    ipc,
};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{Class, OwnedFrame, ReadStep};
use gnunet_types::Error as Fault;
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::Zeroizing;

/// One original official request MQ. Call only from an entered Tokio IO/time
/// runtime. No task is spawned. Canceling an observation future preserves every
/// original native cursor; dropping/closing the owner physically retires them.
pub struct Client {
    source: EndpointSource,
    channel: Channel<u32>,
    limits: Limits,
    overall: Bound,
    initial: Option<Bound>,
    write: Option<Bound>,
    input: Option<Bound>,
    original: Option<OwnedFrame>,
    kind: Kind,
    rid: u32,
    total: usize,
    epoch: Option<Epoch>,
    queued: bool,
    written: usize,
    whole: bool,
    input_bytes: usize,
    intermediates: u64,
    closed: bool,
    io_class: u8,
}
impl Client {
    /// Freeze exactly one supplied official request in zeroizing storage. No
    /// socket or request is created implicitly. The collector private-key bytes
    /// are erased on write completion, refusal/cancel/loss and every drop path.
    pub fn new(
        source: EndpointSource,
        request: &ipc::Request<'_>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        limits.validate()?;
        original.check(source.clock().as_ref())?;
        let (kind, rid) = match request {
            ipc::Request::Collect { id, .. } => (Kind::Collect, *id),
            ipc::Request::Verify { id, .. } => (Kind::Verify, *id),
        };
        let n = request.encoded_len()?;
        if n > limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
        if bytes.capacity() > limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        bytes.resize(n, 0);
        request.encode(&mut bytes)?;
        let initial = Bound::phase(source.clock().as_ref(), limits.initial_timeout, original)?;
        let channel = Channel::new(source.duplicate()?, limits.framing())?;
        Ok(Self {
            source,
            channel,
            limits,
            overall: Bound::new(original),
            initial: Some(initial),
            write: None,
            input: None,
            original: Some(OwnedFrame::new(std::mem::take(&mut *bytes))),
            kind,
            rid,
            total: n,
            epoch: None,
            queued: false,
            written: 0,
            whole: false,
            input_bytes: 0,
            intermediates: 0,
            closed: false,
            io_class: 0,
        })
    }
    /// Actual original partial/whole facts, before any physical retirement.
    #[must_use]
    pub fn receipt(&self) -> Receipt {
        Receipt {
            epoch: self.epoch.clone(),
            kind: self.kind,
            request_id: self.rid,
            request_bytes: self.total,
            written_bytes: self.written,
            request_written: self.whole,
            intermediates: self.intermediates,
            response_bytes: self.input_bytes,
        }
    }
    /// Original canonical/native operation targets, never renewed by observation.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.overall.targets
    }
    /// Earliest actual original native target, for caller output-wait guards.
    #[must_use]
    pub fn native_deadline(&self) -> Instant {
        Some(self.overall.targets.hard)
            .into_iter()
            .chain(self.initial.as_ref().map(|b| b.targets.hard))
            .chain(self.write.as_ref().map(|b| b.targets.hard))
            .chain(self.input.as_ref().map(|b| b.targets.hard))
            .min()
            .unwrap_or(self.overall.targets.hard)
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.overall.native(cx)
            || self.initial.as_mut().is_some_and(|b| b.native(cx))
            || self.write.as_mut().is_some_and(|b| b.native(cx))
            || self.input.as_mut().is_some_and(|b| b.native(cx))
    }
    fn check(&self) -> Result<(), Error> {
        self.overall.targets.check(self.source.clock().as_ref())?;
        for b in [&self.initial, &self.write, &self.input]
            .into_iter()
            .flatten()
        {
            b.targets.check(self.source.clock().as_ref())?;
        }
        Ok(())
    }
    fn physical_close(&mut self) {
        self.channel.close();
        self.closed = true;
        self.original = None;
        self.initial = None;
        self.write = None;
        self.input = None;
    }
    fn lost(&mut self, cause: Cause) -> Loss {
        // Framed may retain a malformed header before returning a native error
        // without ReadStep::Progress. Capture its actual original prefix first.
        if let Some(framed) = self.channel.framing() {
            self.input_bytes = self.input_bytes.max(framed.read_progress_bytes());
        }
        let receipt = self.receipt();
        self.physical_close();
        Loss { receipt, cause }
    }
    /// Clock-free actual original-source cancellation. It suppresses callbacks;
    /// no wire cancel/ACK exists and no old request is replayed elsewhere.
    pub fn close(&mut self) -> Option<Loss> {
        if self.closed {
            None
        } else {
            Some(self.lost(Cause::Cancelled))
        }
    }
    /// Native/clock-free deadline gate before any caller's output or future wait.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Loss> {
        if !self.closed && self.expired(cx) {
            Some(self.lost(Cause::Deadline))
        } else {
            None
        }
    }
    fn queue(&mut self) -> Result<(), Error> {
        if self.queued {
            return Ok(());
        }
        self.check()?;
        let bound = Bound::phase(
            self.source.clock().as_ref(),
            self.limits.write_timeout,
            self.overall.targets,
        )?;
        let original = self.original.take().ok_or(Fault::Conflict)?;
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .enqueue_owned(original, self.rid, Class::Ordinary)
        {
            Ok(()) => {
                self.queued = true;
                self.write = Some(bound);
                Ok(())
            }
            Err(rejected) => {
                self.original = Some(rejected.value.0);
                Err(rejected.reason.into())
            }
        }
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.expired(cx) {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        self.check()?;
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if let Some(frame) = framed.frame() {
            if !self.whole {
                return Poll::Ready(Err(Fault::Malformed.into()));
            }
            let (rid, terminal, records) = match ipc::Response::decode(frame)? {
                ipc::Response::Result {
                    id,
                    chain,
                    delegates,
                    ..
                } => (
                    id,
                    true,
                    usize::try_from(chain.count())
                        .map_err(|_| Fault::TooLarge)?
                        .checked_add(
                            usize::try_from(delegates.count()).map_err(|_| Fault::TooLarge)?,
                        )
                        .ok_or(Fault::Overflow)?,
                ),
                ipc::Response::Intermediate { id, .. } => (id, false, 1),
            };
            if rid != self.rid {
                return Poll::Ready(Err(Fault::Malformed.into()));
            }
            if records > self.limits.records
                || (!terminal && self.intermediates >= self.limits.intermediates)
            {
                return Poll::Ready(Err(Fault::Capacity.into()));
            }
            let mut owned = Zeroizing::new(Vec::new());
            owned
                .try_reserve_exact(frame.len())
                .map_err(|_| Fault::Capacity)?;
            if owned.capacity() > self.limits.frame_bytes {
                return Poll::Ready(Err(Fault::Capacity.into()));
            }
            owned.extend_from_slice(frame);
            let observation = Observation {
                frame: OwnedFrame::new(std::mem::take(&mut *owned)),
            };
            let released = framed.release_frame();
            if !released {
                return Poll::Ready(Err(Fault::Conflict.into()));
            }
            // Shape validation/allocation cannot grant a later result after a
            // known original native or canonical bound has expired.
            if self.expired(cx) {
                return Poll::Ready(Err(Fault::Deadline.into()));
            }
            self.check()?;
            if terminal {
                let receipt = self.receipt();
                self.physical_close();
                return Poll::Ready(Ok(Progress::Result {
                    observation,
                    receipt,
                }));
            }
            self.intermediates = self.intermediates.checked_add(1).ok_or(Fault::Overflow)?;
            let receipt = self.receipt();
            self.input = None;
            self.input_bytes = 0;
            return Poll::Ready(Ok(Progress::Intermediate {
                observation,
                receipt,
            }));
        }
        match framed.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Eof))))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
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
                // Refuse a complete response at its actual read boundary,
                // before a later TX turn could certify the original request.
                if complete && !self.whole {
                    return Poll::Ready(Err(Fault::Malformed.into()));
                }
                Poll::Ready(Ok(Progress::Activity {
                    epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                    bytes,
                }))
            }
        }
    }
    fn inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.check()?;
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        }
        if self.expired(cx) {
            return Poll::Ready(Err(Fault::Deadline.into()));
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
                    Poll::Ready(Ok(Progress::Attached(epoch)))
                }
            };
        }
        // Both actual directions retain their original owners and targets.
        // A backpressured request must not hide native RX EOF or errors.
        for _ in 0..2 {
            if self.expired(cx) {
                return Poll::Ready(Err(Fault::Deadline.into()));
            }
            self.check()?;
            let class = self.io_class;
            self.io_class = (self.io_class + 1) % 2;
            let progress = if class == 0 {
                self.write(cx)
            } else {
                self.read(cx)
            };
            if progress.is_ready() {
                return progress;
            }
        }
        Poll::Pending
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.whole {
            return Poll::Pending;
        }
        self.queue()?;
        if self.expired(cx) {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        self.check()?;
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(write)) => {
                if write.origin != self.rid {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                self.written = self
                    .written
                    .checked_add(write.bytes)
                    .filter(|n| *n <= self.total)
                    .ok_or(Fault::Overflow)?;
                if write.complete {
                    if self.written != self.total {
                        return Poll::Ready(Err(Fault::Malformed.into()));
                    }
                    self.whole = true;
                    self.write = None;
                    self.initial = None;
                }
                Poll::Ready(Ok(Progress::Written {
                    epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                    bytes: write.bytes,
                    complete: write.complete,
                    receipt: self.receipt(),
                }))
            }
        }
    }

    /// Poll one actual original event. Every failure physically closes the old
    /// owner before exposing loss; nothing is reattached or silently replayed.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if let Some(loss) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        match self.inner(cx) {
            Poll::Ready(Err(error)) => {
                Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Failure(error)))))
            }
            other => other,
        }
    }
    /// Await one event while keeping all original cursors in this owner.
    pub async fn drive(&mut self) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _loss = self.close();
    }
}

#[cfg(all(test, unix))]
mod tests;
