use super::*;
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::framing::Class;

impl Line {
    fn admission(&mut self) -> Result<(), Error> {
        if let Err(error) = self.check() {
            if !self.closed {
                self.pending_loss = Some(self.lost(cause(error)));
            }
            return Err(Fault::Closed.into());
        }
        if !self.initializer.complete {
            return Err(Fault::NotReady.into());
        }
        Ok(())
    }
    fn enqueue(
        &mut self,
        message: ipc::Message<'_>,
        call: &Call,
        kind: Kind,
    ) -> Result<Operation, Error> {
        self.admission()?;
        if self.pending.len() >= self.limits.pending {
            return Err(Fault::WouldBlock.into());
        }
        let next = self.next_operation.checked_add(1).ok_or(Fault::Overflow)?;
        let n = message.encoded_len()?;
        if n > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        if n > self.limits.queued_bytes {
            return Err(Fault::Capacity.into());
        }
        if self.queued_bytes.checked_add(n).ok_or(Fault::Overflow)? > self.limits.queued_bytes {
            return Err(Fault::WouldBlock.into());
        }
        let frame = encode(message, self.limits.frame_bytes)?;
        let capacity = frame.retained_bytes();
        let total = self
            .queued_bytes
            .checked_add(capacity)
            .ok_or(Fault::Overflow)?;
        if total > self.limits.queued_bytes
            || self
                .retained_bytes()?
                .checked_add(capacity)
                .and_then(|n| n.checked_add(size_of::<tokio::time::Sleep>()))
                .ok_or(Fault::Overflow)?
                > self.limits.retained_bytes
        {
            return Err(Fault::WouldBlock.into());
        }
        let bound = match Bound::phase(
            self.source.clock().as_ref(),
            self.limits.write_timeout,
            self.overall.targets,
        ) {
            Ok(b) => b,
            Err(error) => {
                self.pending_loss = Some(self.lost(cause(error)));
                return Err(Fault::Closed.into());
            }
        };
        let operation = Operation {
            domain: self.domain.clone(),
            serial: self.next_operation,
        };
        let receipt = Receipt {
            bounds: bound.targets,
            operation: operation.clone(),
            call: Some(call.clone()),
            kind,
            epoch: self.epoch.clone(),
            total_bytes: n,
            written_bytes: 0,
            complete: false,
        };
        self.pending.push_back(Pending {
            receipt,
            frame: Some(frame),
            capacity,
            bound,
            queued: false,
        });
        self.queued_bytes = total;
        self.next_operation = next;
        Ok(operation)
    }
    fn control(
        &mut self,
        call: &Call,
        action: ipc::ClientControl,
        kind: Kind,
    ) -> Result<Operation, Error> {
        self.admission()?;
        let row = self.row(call)?;
        if row.control.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        let allowed = match kind {
            Kind::PickUp => row.info.role == Role::Incoming && row.info.phase == Phase::Ringing,
            Kind::HangUp => matches!(
                row.info.phase,
                Phase::Calling | Phase::Ringing | Phase::Connected
            ),
            Kind::Suspend => row.info.phase == Phase::Connected && !row.info.suspended_local,
            Kind::Resume => row.info.phase == Phase::Connected && row.info.suspended_local,
            _ => false,
        };
        if !allowed {
            return Err(Fault::NotReady.into());
        }
        let cid = u32::from_be_bytes(row.info.cid.ok_or(Fault::NotReady)?);
        let operation = self.enqueue(ipc::Message::Control { action, cid }, call, kind)?;
        let row = self.row_mut(call)?;
        row.control = Some(kind);
        if kind == Kind::HangUp {
            row.info.phase = Phase::Ending;
        }
        Ok(operation)
    }
    /// Admit original732 for this actual incoming Ring. Whole write permits
    /// local media; it is not proof the remote endpoint received the pickup.
    pub fn pick_up(&mut self, call: &Call) -> Result<Operation, Error> {
        self.control(call, ipc::ClientControl::PickUp, Kind::PickUp)
    }
    /// Admit actual733 behind prior original Line writes. This is a protocol
    /// action, not local cancellation; close() physically cancels the whole MQ.
    /// Before any outgoing CID observation, cancel that Line via close().
    pub fn hang_up(&mut self, call: &Call) -> Result<Operation, Error> {
        self.control(call, ipc::ClientControl::HangUp, Kind::HangUp)
    }
    /// Admit actual736, preserving independent remote/local suspension flags.
    pub fn suspend(&mut self, call: &Call) -> Result<Operation, Error> {
        self.control(call, ipc::ClientControl::Suspend, Kind::Suspend)
    }
    /// Admit actual737 without inventing a remote resume acknowledgement.
    pub fn resume(&mut self, call: &Call) -> Result<Operation, Error> {
        self.control(call, ipc::ClientControl::Resume, Kind::Resume)
    }
    /// Freeze one original compressed739 frame. No data is discarded or
    /// replaced under backpressure: WouldBlock leaves caller-owned bytes intact.
    pub fn audio(&mut self, call: &Call, data: &[u8]) -> Result<Operation, Error> {
        self.admission()?;
        let row = self.row(call)?;
        if row.control.is_some()
            || row.info.phase != Phase::Connected
            || row.info.suspended_local
            || row.info.suspended_remote
        {
            return Err(Fault::NotReady.into());
        }
        if data.len() > self.limits.audio_bytes {
            return Err(Fault::TooLarge.into());
        }
        let cid = u32::from_be_bytes(row.info.cid.ok_or(Fault::NotReady)?);
        self.enqueue(ipc::Message::Audio { cid, data }, call, Kind::Audio)
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        let Some(front) = self.pending.front() else {
            return Poll::Pending;
        };
        let ended = front
            .receipt
            .call
            .as_ref()
            .is_some_and(|c| self.row(c).is_ok_and(|r| r.info.phase == Phase::Ended));
        if ended {
            if front.receipt.written_bytes != 0 {
                return Poll::Ready(Err(Fault::Closed.into()));
            }
            if front.queued {
                let id = front.receipt.operation.serial;
                let mut found = false;
                let removed = self
                    .channel
                    .framing_mut()
                    .ok_or(Fault::NotReady)?
                    .remove_unwritten(|origin, _| origin == id, |_, _| found = true);
                if removed != 1 || !found {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
            }
            let original = self.pending.pop_front().ok_or(Fault::Conflict)?;
            self.queued_bytes -= original.capacity;
            return Poll::Ready(Ok(Progress::Unsent {
                receipt: original.receipt,
            }));
        }
        if !front.queued {
            let p = self.pending.front_mut().ok_or(Fault::Conflict)?;
            let frame = p.frame.take().ok_or(Fault::Conflict)?;
            let id = p.receipt.operation.serial;
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .enqueue_owned(frame, id, Class::Ordinary)
            {
                Ok(()) => p.queued = true,
                Err(rejected) => {
                    p.frame = Some(rejected.value.0);
                    return Poll::Ready(Err(rejected.reason.into()));
                }
            }
        }
        if self.retained_bytes()? > self.limits.retained_bytes {
            return Poll::Ready(Err(Fault::Capacity.into()));
        }
        let write = match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        let p = self.pending.front_mut().ok_or(Fault::Conflict)?;
        if write.origin != p.receipt.operation.serial {
            return Poll::Ready(Err(Fault::StaleGeneration.into()));
        }
        p.receipt.written_bytes = p
            .receipt
            .written_bytes
            .checked_add(write.bytes)
            .filter(|n| *n <= p.receipt.total_bytes)
            .ok_or(Fault::Overflow)?;
        p.receipt.epoch = self.epoch.clone();
        p.receipt.complete = write.complete;
        if p.receipt.operation.serial == 1 {
            self.initializer = p.receipt.clone();
        }
        if write.complete {
            if p.receipt.written_bytes != p.receipt.total_bytes {
                return Poll::Ready(Err(Fault::Malformed.into()));
            }
            let p = self.pending.pop_front().ok_or(Fault::Conflict)?;
            self.queued_bytes -= p.capacity;
            if matches!(p.receipt.kind, Kind::Register | Kind::Call) {
                self.initial = None;
            }
            if let Some(call) = &p.receipt.call {
                let row = self.row_mut(call)?;
                match p.receipt.kind {
                    Kind::PickUp => {
                        row.info.pickup_written = true;
                        if row.info.phase != Phase::Ended {
                            row.info.phase = Phase::Connected;
                        }
                    }
                    Kind::HangUp => {
                        row.info.hangup_written = true;
                        row.info.phase = Phase::Ended;
                    }
                    Kind::Suspend => row.info.suspended_local = true,
                    Kind::Resume => row.info.suspended_local = false,
                    _ => {}
                }
                if row.control == Some(p.receipt.kind) {
                    row.control = None;
                }
            }
            // Return the applied original whole write before another clock,
            // provider or read operation can fail and obscure its receipt.
            Poll::Ready(Ok(Progress::Written {
                receipt: p.receipt,
                bytes: write.bytes,
            }))
        } else {
            Poll::Ready(Ok(Progress::Written {
                receipt: p.receipt.clone(),
                bytes: write.bytes,
            }))
        }
    }
    pub(super) fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
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
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    Poll::Ready(Ok(Progress::Retry { error, retry_after }))
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = Epoch(Arc::new(()));
                    self.epoch = Some(epoch.clone());
                    self.initializer.epoch = Some(epoch.clone());
                    for p in &mut self.pending {
                        p.receipt.epoch = Some(epoch.clone());
                    }
                    for r in self.rows.iter_mut().flatten() {
                        r.info.epoch = Some(epoch.clone());
                    }
                    if self.retained_bytes()? > self.limits.retained_bytes {
                        return Poll::Ready(Err(Fault::Capacity.into()));
                    }
                    self.check()?;
                    Poll::Ready(Ok(Progress::Attached(epoch)))
                }
            };
        }
        if !self.initializer.complete {
            return self.write(cx);
        }
        let read_first = self.read_first;
        self.read_first = !self.read_first;
        for read in [read_first, !read_first] {
            self.check()?;
            let event = if read { self.read(cx) } else { self.write(cx) };
            if event.is_ready() {
                return event;
            }
        }
        Poll::Pending
    }
}
