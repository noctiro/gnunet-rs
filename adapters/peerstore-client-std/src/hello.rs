//! Actual official HELLO-add composition over one exclusively borrowed idle
//! general Client. Scan/STOP/REPLACE and results remain on their original MQ.
use crate::{
    Cancel, Client, Command, Epoch, Error, Filter, Operation, Outcome, Progress, Reason, Record,
    Submission,
};
use gnunet_hello::{
    AbsoluteTime, Hello, Limits as HelloLimits, SignatureCoverage, SignatureProfile,
};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Actual official PEERSTORE HELLO namespace, not transport address-cache storage.
pub const SUBSYSTEM: &[u8] = b"peerstore";
/// Actual public GNUNET_PEERSTORE_HELLO_KEY.
pub const KEY: &[u8] = b"peerstore-peer-hello-uri";
/// Explicit original caller policies. Crypto is only the admitted public HELLO
/// signature verifier; this helper never accesses or derives a private key.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Explicit original public producer's signature-coverage profile.
    pub profile: SignatureProfile,
    /// Shared bounded canonical public address parser/storage limits.
    pub hello: HelloLimits,
    /// Actual caller UTC observation for incoming HELLO expiry verification.
    pub now: AbsoluteTime,
    /// Original finite service-operation deadline (same clock as Client).
    pub until: u64,
    /// Original independent native hard target.
    pub hard: Instant,
    /// Fixed original STOP/cancellation suffix-drain allowance.
    pub grace: Duration,
}
/// Real terminal result; ExistingNewer is an observation, not a new write ACK.
#[derive(Clone, Copy, Debug)]
pub enum AddOutcome {
    /// Original authoritative STORE_RESULT,1 means GNUNET_OK.
    StoreResult(i32),
    /// A newer signature-checked HELLO was observed; no STORE was admitted.
    ExistingNewer {
        /// Actual original scan retirement, including STOP's lack of ACK.
        scan: Outcome,
    },
    /// Scan failed/expired or original caller cancellation interrupted work.
    Interrupted {
        /// Original local reason, if this helper initiated cancellation.
        reason: Option<Fault>,
        /// Exact original wire/local operation outcome, never recast as saved.
        actual: Outcome,
    },
}
/// Original entire add operation, preserving its exact scan/store/source tokens.
#[derive(Clone, Copy, Debug)]
pub struct Completion<'id> {
    /// Incoming public peer, taken only from verified HELLO metadata.
    pub peer: [u8; 32],
    /// Actual signature coverage; default addresses are not authenticated.
    pub coverage: SignatureCoverage,
    /// Original actual scan operation.
    pub scan: Operation<'id>,
    /// Original actual REPLACE admission, absent when never submitted.
    pub store: Option<Operation<'id>>,
    /// Original observed actual physical source, never a raw RID.
    pub epoch: Option<Epoch<'id>>,
    /// Authoritative/local result.
    pub outcome: AddOutcome,
}
/// Caller-visible real progress. Native observations are not swallowed; a
/// Finished result comes only after matching original provider retirement.
pub enum AddProgress<'id> {
    /// An original unchanged actual client observation.
    Native(Progress<'id>),
    /// Original scan credit or REPLACE was actually admitted locally, not saved.
    Admitted,
    /// Actual terminal correlation, emitted once.
    Finished(Completion<'id>),
    /// Caller wait ended; the original operation remains live.
    WaitDeadline,
    /// Original result already emitted; no new IO is started.
    Closed,
}
#[derive(Clone, Copy)]
enum Stage<'id> {
    Scan(Operation<'id>),
    ReadyStore,
    Store(Operation<'id>),
    Stopping(Operation<'id>),
    Done,
}
/// One reusable public add owner. Start requires Client.is_idle() and holds
/// its exclusive borrow, so close/drop cannot silently cancel another operation.
/// Normal completion releases only this operation; caller can reuse its Client.
/// Cancellation/error can physically close that original MQ; no payload replays.
pub struct HelloAdd<'borrow, 'id> {
    client: &'borrow mut Client<'id>,
    scratch: &'borrow mut [u8],
    frame: Option<OwnedFrame>,
    peer: [u8; 32],
    expiry: u64,
    coverage: SignatureCoverage,
    options: Options,
    scan: Operation<'id>,
    store: Option<Operation<'id>>,
    epoch: Option<Epoch<'id>>,
    stage: Stage<'id>,
    grant: bool,
    newer: bool,
    reason: Option<Fault>,
    stop: Option<Instant>,
    timer: Option<Pin<Box<Sleep>>>,
    finished: Option<Completion<'id>>,
}
fn temporary(error: &Error) -> bool {
    matches!(
        error,
        Error::Protocol(Fault::Capacity | Fault::WouldBlock | Fault::NotReady)
    )
}
impl<'borrow, 'id> HelloAdd<'borrow, 'id> {
    /// Validate/copy first, then admit one real exact-peer iteration. Incoming
    /// cache expiry also caps the original operation deadline; no expired store
    /// can be made successful by waiting in a local queue.
    pub fn start(
        client: &'borrow mut Client<'id>,
        frame: &[u8],
        scratch: &'borrow mut [u8],
        mut options: Options,
    ) -> Result<Self, Error> {
        if !client.is_idle() {
            return Err(Fault::Conflict.into());
        }
        if options.until == u64::MAX
            || options.until <= options.now.as_micros()
            || options.hard <= Instant::now()
            || options.grace.is_zero()
            || options.hard.checked_add(options.grace).is_none()
            || scratch.len() < options.hello.maximum_address_bytes
        {
            return Err(Fault::InvalidInput.into());
        }
        let hello = Hello::parse_message(frame, None, scratch, options.hello)?;
        let checked = hello.verify_at(options.profile, options.now)?;
        let peer = *hello.peer().as_bytes();
        let expiry = hello.expiration().as_micros();
        let coverage = checked.coverage();
        options.until = options.until.min(expiry);
        // Preflight official complete STORE width before even scanning.
        crate::ipc::Request::Store(crate::ipc::Envelope {
            rid: 0,
            options: 1,
            reserved: 0,
            record: Record {
                peer,
                expiry,
                subsystem: Some(SUBSYSTEM),
                key: Some(KEY),
                value: frame,
            },
        })
        .encoded_len()?;
        let frame = OwnedFrame::copy_from(frame)?;
        let epoch = client.epoch();
        let scan = client.iterate(
            Filter {
                peer: Some(peer),
                subsystem: Some(SUBSYSTEM),
                key: Some(KEY),
            },
            options.until,
        )?;
        Ok(Self {
            client,
            scratch,
            frame: Some(frame),
            peer,
            expiry,
            coverage,
            options,
            scan,
            store: None,
            epoch,
            stage: Stage::Scan(scan),
            grant: false,
            newer: false,
            reason: None,
            stop: None,
            timer: None,
            finished: None,
        })
    }
    /// Original scan capability, useful for diagnostics only.
    pub const fn scan(&self) -> Operation<'id> {
        self.scan
    }
    /// Take the already correlated terminal fact without polling a clock/IO.
    /// This is the same once-only result returned by AddProgress::Finished.
    pub fn take_completion(&mut self) -> Option<Completion<'id>> {
        self.finished.take()
    }
    fn operation(&self) -> Option<Operation<'id>> {
        match self.stage {
            Stage::Scan(op) | Stage::Store(op) | Stage::Stopping(op) => Some(op),
            Stage::ReadyStore | Stage::Done => None,
        }
    }
    fn finish(&mut self, outcome: AddOutcome) {
        self.stage = Stage::Done;
        self.finished = Some(Completion {
            peer: self.peer,
            coverage: self.coverage,
            scan: self.scan,
            store: self.store,
            epoch: self.epoch,
            outcome,
        });
    }
    fn original_epoch(&mut self, epoch: Epoch<'id>) -> Result<(), Error> {
        if self.epoch.is_some_and(|old| old != epoch) {
            return Err(Fault::StaleGeneration.into());
        }
        self.epoch = Some(epoch);
        Ok(())
    }
    fn stop_for(&mut self, reason: Option<Fault>) -> Result<Cancel, Error> {
        if matches!(self.stage, Stage::Done) {
            return Err(Fault::Closed.into());
        }
        if let Some(reason) = reason {
            self.reason = Some(reason);
        }
        if let Some(op) = self.operation() {
            let cancel = self.client.cancel(op)?;
            self.stage = Stage::Stopping(op);
            self.stop.get_or_insert(
                Instant::now()
                    .min(self.options.hard)
                    .checked_add(self.options.grace)
                    .ok_or(Fault::Overflow)?,
            );
            Ok(cancel)
        } else {
            self.finish(AddOutcome::Interrupted {
                reason: self.reason,
                actual: Outcome::Local {
                    reason: Reason::Cancelled,
                    submission: Submission::Unsent,
                },
            });
            Ok(Cancel::Unsent)
        }
    }
    /// Cancel only this original intent. STOP/suffix debt remains on that MQ;
    /// poll to its original fixed grace or close the physical source explicitly.
    pub fn cancel(&mut self) -> Result<Cancel, Error> {
        match self.stop_for(Some(Fault::Cancelled)) {
            Ok(cancel) => Ok(cancel),
            Err(error) => Err(self.failure(error)),
        }
    }
    /// Actual immediate physical close, requiring no clock sample. Native/local
    /// terminal observations remain available in the original Client event queue.
    pub fn close(&mut self) -> Result<Option<Progress<'id>>, Error> {
        if matches!(self.stage, Stage::Done) {
            return Ok(None);
        }
        self.stage = Stage::Done;
        self.client.close()
    }
    fn failure(&mut self, original: Error) -> Error {
        match self.close() {
            Ok(_) => original,
            Err(cleanup) => Error::Io(std::io::Error::other(format!(
                "HELLO-add original={original}; independent original MQ close={cleanup}"
            ))),
        }
    }
    fn native(&mut self, event: &Progress<'id>) -> Result<(), Error> {
        match event {
            Progress::Connected(epoch) => self.original_epoch(*epoch)?,
            Progress::Written {
                epoch,
                operation,
                command,
                ..
            } => {
                if *operation != self.scan && Some(*operation) != self.store {
                    return Err(Fault::StaleGeneration.into());
                }
                self.original_epoch(*epoch)?;
                if matches!(command, Command::Stop) {
                    self.grant = false;
                }
            }
            Progress::Record(observation) => {
                if !matches!(self.stage,Stage::Scan(op)if op==observation.operation()) {
                    return Err(Fault::StaleGeneration.into());
                }
                self.original_epoch(observation.epoch())?;
                let row = observation.record()?.record;
                if row.peer != self.peer || row.subsystem != Some(SUBSYSTEM) || row.key != Some(KEY)
                {
                    return Err(Fault::Malformed.into());
                }
                // Unknown/resource-refused cached data cannot authorize replacing
                // a possibly newer original record. Fail without any STORE.
                let cached =
                    Hello::parse_message(row.value, None, self.scratch, self.options.hello)?;
                cached.verify_signature(self.options.profile)?;
                if cached.peer().as_bytes() != &self.peer {
                    return Err(Fault::Authentication.into());
                }
                let newer = cached.expiration().as_micros() > self.expiry;
                if newer {
                    self.newer = true;
                    self.frame = None;
                    self.stop_for(None)?;
                } else {
                    self.grant = true;
                }
            }
            Progress::Completed {
                epoch,
                operation,
                outcome,
                ..
            } => {
                if Some(*operation) != self.operation() {
                    return Err(Fault::StaleGeneration.into());
                }
                if let Some(epoch) = epoch {
                    self.original_epoch(*epoch)?;
                }
                match (self.stage, *outcome) {
                    (Stage::Scan(_), Outcome::IterationEnd(1)) if self.reason.is_none() => {
                        self.stage = Stage::ReadyStore;
                        self.grant = false;
                    }
                    (Stage::Store(_), Outcome::StoreResult(raw)) => {
                        self.finish(AddOutcome::StoreResult(raw))
                    }
                    (Stage::Stopping(_), actual) if self.newer && self.reason.is_none() => {
                        self.finish(AddOutcome::ExistingNewer { scan: actual })
                    }
                    (_, actual) => self.finish(AddOutcome::Interrupted {
                        reason: self.reason,
                        actual,
                    }),
                }
            }
            Progress::Lost { .. } => {
                let _physical = self.client.close()?;
            }
            _ => {}
        }
        Ok(())
    }
    fn maintain(&mut self) -> Result<bool, Error> {
        if self.stop.is_some() {
            return Ok(false);
        }
        match self.stage {
            Stage::Scan(op) if self.grant => match self.client.next(op, 1) {
                Ok(()) => {
                    self.grant = false;
                    Ok(true)
                }
                Err(error) if temporary(&error) => Ok(false),
                Err(error) => Err(error),
            },
            Stage::ReadyStore => {
                if self.epoch.is_none() || self.client.epoch() != self.epoch {
                    return Err(Fault::StaleGeneration.into());
                }
                match self.client.store(
                    Record {
                        peer: self.peer,
                        expiry: self.expiry,
                        subsystem: Some(SUBSYSTEM),
                        key: Some(KEY),
                        value: self.frame.as_ref().ok_or(Fault::StaleGeneration)?.bytes(),
                    },
                    1,
                    self.options.until,
                ) {
                    Ok(op) => {
                        self.store = Some(op);
                        self.stage = Stage::Store(op);
                        // Client now owns the immutable original request bytes.
                        self.frame = None;
                        Ok(true)
                    }
                    Err(error) if temporary(&error) => Ok(false),
                    Err(error) => Err(error),
                }
            }
            _ => Ok(false),
        }
    }
    /// One caller-driven step. Original native hard bounds precede canonical
    /// Client clock waiting. A dropped future retains this exact owner/cursors.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<AddProgress<'id>, Error>> {
        let result = (|| {
            if let Some(done) = self.take_completion() {
                return Poll::Ready(Ok(AddProgress::Finished(done)));
            }
            if matches!(self.stage, Stage::Done) {
                return Poll::Ready(Ok(AddProgress::Closed));
            }
            let now = Instant::now();
            if self.stop.is_some_and(|at| now >= at) {
                let actual = self.client.close()?;
                if let Some(event) = actual {
                    return Poll::Ready(Ok(AddProgress::Native(event)));
                }
            }
            if self.stop.is_none() && now >= self.options.hard {
                self.stop_for(Some(Fault::Deadline))?;
            }
            let hard = self.stop.unwrap_or(self.options.hard);
            if let Some(timer) = self.timer.as_mut() {
                timer.as_mut().reset(hard);
            } else {
                self.timer = Some(Box::pin(tokio::time::sleep_until(hard)));
            }
            if self
                .timer
                .as_mut()
                .ok_or(Fault::Conflict)?
                .as_mut()
                .poll(cx)
                .is_ready()
            {
                cx.waker().wake_by_ref();
            }
            // Actual old terminal observations may drain after clock/source loss.
            if let Some(event) = self.client.next_event() {
                self.native(&event)?;
                return Poll::Ready(Ok(AddProgress::Native(event)));
            }
            if wait.is_some_and(|at| now >= at) {
                return Poll::Ready(Ok(AddProgress::WaitDeadline));
            }
            if self.maintain()? {
                return Poll::Ready(Ok(AddProgress::Admitted));
            }
            let polled = {
                let mut future = std::pin::pin!(self.client.drive(wait));
                future.as_mut().poll(cx)
            };
            match polled {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(event)) => {
                    self.native(&event)?;
                    Poll::Ready(Ok(AddProgress::Native(event)))
                }
            }
        })();
        match result {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.failure(error))),
            other => other,
        }
    }
    /// Wait cancellation alone never cancels the original scan/store/suffix.
    pub async fn drive(&mut self, wait: Option<Instant>) -> Result<AddProgress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, wait)).await
    }
}
impl Drop for HelloAdd<'_, '_> {
    fn drop(&mut self) {
        if !matches!(self.stage, Stage::Done) {
            let _closed = self.client.close();
        }
    }
}
