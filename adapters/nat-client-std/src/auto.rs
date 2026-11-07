use crate::*;
use zeroize::Zeroizing;
/// One actual original NATauto reply, with a single zeroizing raw owner. Raw
/// status/type0 and configuration diff are preserved, never installed implicitly.
pub struct AutoResult<'id> {
    session: Session<'id>,
    epoch: Epoch<'id>,
    frame: OwnedFrame,
}
impl fmt::Debug for AutoResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatAutoResult")
            .field("session", &self.session)
            .field("epoch", &self.epoch)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}
impl<'id> AutoResult<'id> {
    /// Original query allocation.
    pub const fn session(&self) -> Session<'id> {
        self.session
    }
    /// Actual responding MQ.
    pub const fn epoch(&self) -> Epoch<'id> {
        self.epoch
    }
    /// Borrow raw status, NAT type and actual serialized diff once decoded.
    pub fn response(&self) -> Result<auto_ipc::Response<'_>, Error> {
        Ok(auto_ipc::Response::decode(self.frame.bytes())?)
    }
    /// Explicit sensitive borrow of original complete result bytes.
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
}
/// Actual native/query observations; no synthetic IPC-failure status is emitted.
#[derive(Debug)]
pub enum AutoProgress<'id> {
    /// Actual original attachment.
    Connected(Session<'id>, Epoch<'id>),
    /// Immutable original query queued.
    Queued(Session<'id>, Epoch<'id>, WriteId<'id>),
    /// Actual local whole query write only.
    Written(Session<'id>, Epoch<'id>, WriteId<'id>, usize),
    /// Actual byte progress.
    Activity {
        /// Actual bytes read from the original query MQ.
        read: usize,
        /// Actual bytes written to the original query MQ.
        written: usize,
    },
    /// Real result retained; original MQ already physically closed.
    ResultReady(Session<'id>, Epoch<'id>),
    /// Actual original local/physical termination without a result.
    Ended(SourceEnd<'id>),
    /// Actual preattachment connection attempt failure.
    Retry(stdio::Error, Duration),
    /// Actual full result retained while allocation retries finitely.
    Capacity(Session<'id>, Epoch<'id>),
    /// Caller wait timeout, independent of original query bound.
    WaitDeadline,
    /// Original terminal result/end has already been delivered.
    Closed,
}
/// One query on one original MQ, with no replay/reconnect after attachment.
pub struct AutoQuery<'id> {
    io: io::Io<'id>,
    request: OwnedFrame,
    result: Option<AutoResult<'id>>,
    done: bool,
}
impl<'id> AutoQuery<'id> {
    /// Start one actual configuration proposal. It is opaque original GNUnet
    /// serialization, not zlib/JSON, and no caller configuration is changed.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        configuration: &[u8],
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        let wire = auto_ipc::Request { configuration };
        let n = wire.encoded_len()?;
        if n > limits.frame_bytes || n > limits.source_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut b = Zeroizing::new(Vec::new());
        b.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
        b.resize(n, 0);
        wire.encode(&mut b)?;
        let request = OwnedFrame::copy_from(&b)?;
        let first = OwnedFrame::copy_from(&b)?;
        let io = io::Io::new(
            instance,
            source,
            first,
            Command::AutoQuery,
            deadlines,
            limits,
        )?;
        Ok(Self {
            io,
            request,
            result: None,
            done: false,
        })
    }
    /// Default endpoint is actual `nat-auto`. One Live configuration snapshot is
    /// used for both its selector and serialized proposal; no phase re-reads Live.
    pub fn from_live(
        instance: &'id Instance,
        live: LiveConfiguration,
        resolution: resolution::SharedResolution,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        let source = auto_source(live, resolution).snapshot()?;
        let configuration = source.configuration_snapshot()?.ok_or(Fault::NotReady)?;
        let serialized = Zeroizing::new(configuration.serialize().map_err(Error::Configuration)?);
        Self::new(instance, source, &serialized, deadlines, limits)
    }
    /// Explicit caller configuration snapshot, preserving actual serialization error.
    pub fn from_configuration(
        instance: &'id Instance,
        source: EndpointSource,
        configuration: &gnunet_config::Configuration,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        let source = source.snapshot()?;
        let serialized = Zeroizing::new(configuration.serialize().map_err(Error::Configuration)?);
        Self::new(instance, source, &serialized, deadlines, limits)
    }
    /// Exact original query write, never a wire request ID.
    pub fn write_id(&self) -> WriteId<'id> {
        self.io.initial_id()
    }
    /// Original query ID; no bytes from this token enter the protocol.
    pub const fn session(&self) -> Session<'id> {
        self.io.session
    }
    /// Actual historical original source, if attached.
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.io.epoch
    }
    /// Actual current local write state; no classification is inferred.
    pub fn submission(&self) -> Submission {
        self.io.initial()
    }
    /// Exact original configuration request bytes, erased on drop.
    pub fn request_bytes(&self) -> &[u8] {
        self.request.bytes()
    }
    /// Original RuntimeClock.
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.io.clock.clone()
    }
    /// Borrow the actual retained result without copying its sensitive diff.
    pub fn result(&self) -> Option<&AutoResult<'id>> {
        self.result.as_ref()
    }
    /// Transfer the single original result owner; no extra copy or ACK is created.
    pub fn take_result(&mut self) -> Option<AutoResult<'id>> {
        self.result.take()
    }
    /// Physical original cancellation/close; no wire CANCEL or old-query replay.
    pub fn cancel(&mut self) -> Option<SourceEnd<'id>> {
        if self.done {
            return None;
        }
        self.done = true;
        self.io.close(Cause::Cancelled, None)
    }
    /// Physical close without requiring a working clock.
    pub fn close(&mut self) -> Option<SourceEnd<'id>> {
        if self.done {
            return None;
        }
        self.done = true;
        self.io.close(Cause::Closed, None)
    }
    /// Poll original cursors. Only actual Response decode ends with ResultReady;
    /// local writes, EOF and timeouts are never replaced by success/NoNat/status2.
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<tokio::time::Instant>,
    ) -> Poll<Result<AutoProgress<'id>, Error>> {
        if self.done {
            return Poll::Ready(Ok(AutoProgress::Closed));
        }
        let step = match self.io.poll(cx, wait, true) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(step) => step,
        };
        let progress = match step {
            io::Step::Connected(epoch) => AutoProgress::Connected(self.io.session, epoch),
            io::Step::Queued(w, e, _) => AutoProgress::Queued(self.io.session, e, w),
            io::Step::Written(w, e, _, n) => AutoProgress::Written(self.io.session, e, w, n),
            io::Step::Activity(read, written) => AutoProgress::Activity { read, written },
            io::Step::Retry(error, delay) => AutoProgress::Retry(error, delay),
            io::Step::WaitDeadline => AutoProgress::WaitDeadline,
            io::Step::Closed => {
                self.done = true;
                AutoProgress::Closed
            }
            io::Step::Ended(end) => {
                self.done = true;
                AutoProgress::Ended(end)
            }
            io::Step::Retired(_) => {
                let source = self
                    .io
                    .close(Cause::Protocol(Fault::Stale), None)
                    .ok_or(Fault::Stale)?;
                self.done = true;
                AutoProgress::Ended(source)
            }
            io::Step::Input => {
                let result = (|| -> Result<OwnedFrame, Error> {
                    auto_ipc::Response::decode(self.io.frame().ok_or(Fault::Stale)?)?;
                    Ok(self.io.copy_input()?)
                })();
                match result {
                    Ok(frame) => {
                        let epoch = self.io.epoch.ok_or(Fault::Stale)?;
                        let _closed = self.io.close(Cause::Closed, None);
                        self.result = Some(AutoResult {
                            session: self.io.session,
                            epoch,
                            frame,
                        });
                        self.done = true;
                        AutoProgress::ResultReady(self.io.session, epoch)
                    }
                    Err(Error::Protocol(Fault::Capacity)) => {
                        self.io.pause_capacity()?;
                        AutoProgress::Capacity(self.io.session, self.io.epoch.ok_or(Fault::Stale)?)
                    }
                    Err(error) => {
                        let end = self
                            .io
                            .close(Cause::Error(error), None)
                            .ok_or(Fault::Stale)?;
                        self.done = true;
                        AutoProgress::Ended(end)
                    }
                }
            }
        };
        Poll::Ready(Ok(progress))
    }
    /// Every unexpected error stops the original physical query before return.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<tokio::time::Instant>,
    ) -> Poll<Result<AutoProgress<'id>, Error>> {
        match self.poll_inner(cx, wait) {
            Poll::Ready(Err(error)) if !self.io.closed => {
                let end = self
                    .io
                    .close(Cause::Error(error), None)
                    .ok_or(Fault::Stale)?;
                self.done = true;
                Poll::Ready(Ok(AutoProgress::Ended(end)))
            }
            other => other,
        }
    }
    /// Dropping this future preserves the actual query owner and original cursor.
    pub async fn drive(
        &mut self,
        wait: Option<tokio::time::Instant>,
    ) -> Result<AutoProgress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, wait)).await
    }
}
impl Drop for AutoQuery<'_> {
    fn drop(&mut self) {
        let _end = self.io.close(Cause::Closed, None);
    }
}
