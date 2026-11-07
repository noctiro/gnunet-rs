use crate::{
    Bounds, Cause, Decryption, Epoch, Error, Kind, Limits, Loss, Progress, Receipt, Share,
    budget::Bound, ipc, types::freeze,
};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{Class, OwnedFrame, ReadStep};
use gnunet_types::Error as Fault;
use gnunet_wire::official::Frame;
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::Zeroizing;

/// One official operation on its own original MQ. Use inside an entered Tokio
/// runtime. Explicit polling starts no worker, task, service, crypto or Resolver.
/// Cancelling a drive observation leaves these original native cursors intact.
pub struct Client {
    source: EndpointSource,
    channel: Channel<Kind>,
    limits: Limits,
    overall: Bound,
    initial: Option<Bound>,
    write: Option<Bound>,
    input: Option<Bound>,
    original: Option<OwnedFrame>,
    kind: Kind,
    total: usize,
    epoch: Option<Epoch>,
    queued: bool,
    written: usize,
    whole: bool,
    input_bytes: usize,
    closed: bool,
    io_class: u8,
}
impl Client {
    /// Freeze one request and one actual endpoint selection before native IO.
    /// Share bytes remain exact; no hash, private key, proof or deadline is
    /// normalized/reconstructed. Original bounds cover all constructor work.
    pub fn new(
        source: EndpointSource,
        request: &ipc::Request<'_>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        original.check(source.clock().as_ref())?;
        limits.validate()?;
        let initial = Bound::phase(source.clock().as_ref(), limits.initial_timeout, original)?;
        let source = source.fixed_endpoint()?;
        original.check(source.clock().as_ref())?;
        let kind = match request {
            ipc::Request::Generate(generate) => {
                if generate.peers.len() / 32 > limits.peers {
                    return Err(Fault::Capacity.into());
                }
                Kind::Generate
            }
            ipc::Request::Decrypt { share, .. } => {
                if share.len() > limits.peers {
                    return Err(Fault::Capacity.into());
                }
                Kind::Decrypt
            }
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
        original.check(source.clock().as_ref())?;
        let channel = Channel::new(source.duplicate()?, limits.framing())?;
        let value = Self {
            source,
            channel,
            limits,
            overall: Bound::new(original),
            initial: Some(initial),
            write: None,
            input: None,
            original: Some(OwnedFrame::new(std::mem::take(&mut *bytes))),
            kind,
            total: n,
            epoch: None,
            queued: false,
            written: 0,
            whole: false,
            input_bytes: 0,
            closed: false,
            io_class: 0,
        };
        value.check()?;
        Ok(value)
    }
    /// Exact original local transfer facts. No service processing is inferred.
    #[must_use]
    pub fn receipt(&self) -> Receipt {
        Receipt {
            epoch: self.epoch.clone(),
            kind: self.kind,
            request_bytes: self.total,
            written_bytes: self.written,
            request_written: self.whole,
            response_bytes: self.input_bytes,
        }
    }
    /// Original overall canonical/native targets, never renewed by observation.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.overall.targets
    }
    /// Earliest retained original native target, for caller wait/output guards.
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
        for bound in [&self.initial, &self.write, &self.input]
            .into_iter()
            .flatten()
        {
            bound.targets.check(self.source.clock().as_ref())?;
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
    /// Clock-free cancellation/physical retirement. No wire cancel or ACK exists;
    /// a prior contribution may already be irreversible at the actual service.
    pub fn close(&mut self) -> Option<Loss> {
        if self.closed {
            None
        } else {
            Some(self.lost(Cause::Cancelled))
        }
    }
    /// Arm/check original native deadlines without sampling canonical time or IO.
    /// Any returned loss already physically retired that same original MQ.
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
        self.check()?;
        let frame = self.original.take().ok_or(Fault::Conflict)?;
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .enqueue_owned(frame, self.kind, Class::Ordinary)
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
            // Keep the source response shape separate from mathematical success.
            let success = match (self.kind, ipc::Response::decode(Frame::decode(frame)?)?) {
                (Kind::Generate, ipc::Response::SecretReady(share)) => {
                    if share.len() > self.limits.peers {
                        return Poll::Ready(Err(Fault::Capacity.into()));
                    }
                    None
                }
                (Kind::Decrypt, ipc::Response::DecryptDone { success, .. }) => Some(success),
                _ => return Poll::Ready(Err(Fault::Malformed.into())),
            };
            let storage = freeze(frame, self.limits.frame_bytes)?;
            if !framed.release_frame() {
                return Poll::Ready(Err(Fault::Conflict.into()));
            }
            // Original hard/canonical bounds also fence parsing/allocation; a
            // fully shaped late frame cannot renew authority to deliver a result.
            if self.expired(cx) {
                return Poll::Ready(Err(Fault::Deadline.into()));
            }
            self.check()?;
            let receipt = self.receipt();
            self.physical_close();
            return Poll::Ready(Ok(match success {
                None => Progress::Generated {
                    share: Share { storage, offset: 4 },
                    receipt,
                },
                Some(success) => Progress::Decrypted {
                    result: Decryption { storage, success },
                    receipt,
                },
            }));
        }
        match framed.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Eof))))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.input_bytes = self.input_bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
                if bytes > 0 && self.input.is_none() {
                    self.input = Some(Bound::phase(
                        self.source.clock().as_ref(),
                        self.limits.input_timeout,
                        self.overall.targets,
                    )?);
                }
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
            Poll::Ready(result) => result?,
        }
        if self.expired(cx) {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        self.check()?;
        if self.epoch.is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    Poll::Ready(Err(error.into()))
                }
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
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(progress)) => {
                if progress.origin != self.kind {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                self.written = self
                    .written
                    .checked_add(progress.bytes)
                    .filter(|n| *n <= self.total)
                    .ok_or(Fault::Overflow)?;
                if progress.complete {
                    if self.written != self.total {
                        return Poll::Ready(Err(Fault::Malformed.into()));
                    }
                    self.whole = true;
                    self.write = None;
                    self.initial = None;
                }
                Poll::Ready(Ok(Progress::Written {
                    epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                    bytes: progress.bytes,
                    complete: progress.complete,
                    receipt: self.receipt(),
                }))
            }
        }
    }

    /// Poll the same original owner. Every terminal failure physically closes
    /// before exposure; no replacement epoch or silently replayed request exists.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if let Some(loss) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        match self.inner(cx) {
            Poll::Ready(Err(Error::Protocol(Fault::Deadline))) => {
                Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Deadline))))
            }
            Poll::Ready(Err(error)) => {
                Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Failure(error)))))
            }
            other => other,
        }
    }
    /// Await one observation, retaining original cursors and phase targets here.
    /// Dropping this future does not cancel, replay or restart the operation.
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
