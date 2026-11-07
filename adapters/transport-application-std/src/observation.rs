//! Actual native TRANSPORT observation owner, independent of traffic/application
//! hints. No request ID, cancellation packet, fake ACK or implicit worker exists.
use crate::budget::Bound;
pub use crate::{Bounds, Error};
pub use gnunet_client_host::EndpointSource;
use gnunet_client_host::channel::{Channel, ConnectionStep};
use gnunet_service_runtime::framing::{
    Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep,
};
use gnunet_types::Error as Fault;
pub use gnunet_wire::official::transport_monitor::{Request as Query, Response};
use std::{
    fmt,
    future::poll_fn,
    io,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

/// Original physical source epoch. Its numeric value is diagnostic only.
#[derive(Clone, Debug)]
pub struct Epoch {
    domain: Arc<()>,
    serial: u64,
}
impl Epoch {
    /// Diagnostic original epoch serial; it is not source authority.
    pub fn value(&self) -> u64 {
        self.serial
    }
}
impl PartialEq for Epoch {
    fn eq(&self, o: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &o.domain) && self.serial == o.serial
    }
}
impl Eq for Epoch {}

/// Explicit native input and initial-source bounds. Overall Bounds are supplied
/// separately once and are never renewed by connect/retry/restart/progress.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum whole standard frame, including header (40..=65535).
    pub frame_bytes: usize,
    /// Maximum bytes offered per actual nonblocking syscall.
    pub io_slice_bytes: usize,
    /// Original connect plus complete40-byte START deadline.
    pub initial_timeout: Duration,
    /// First positive input byte through classification of that same frame.
    pub input_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            initial_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(10),
        }
    }
}
impl Limits {
    fn framing(self) -> Result<FrameLimits, Error> {
        if !(40..=65535).contains(&self.frame_bytes) || self.io_slice_bytes == 0 {
            return Err(Fault::InvalidInput.into());
        }
        for d in [self.initial_timeout, self.input_timeout] {
            if d.is_zero()
                || d.as_micros() >= u128::from(u64::MAX)
                || Instant::now().checked_add(d).is_none()
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        let limits = FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: 40,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }
}
/// Exact terminal source cause. EOF/expiry is never an enumeration END.
#[derive(Debug)]
pub enum Cause {
    /// Explicit local cancellation; this is not a standard END.
    Cancelled,
    /// Actual source EOF; this is not a standard END.
    Eof,
    /// Original clock, protocol, deadline, provider or IO cause.
    Failure(Error),
}
/// Original source facts after real attempt/MQ retirement.
#[derive(Debug)]
pub struct Loss {
    /// Original admitted source epoch, absent when no epoch was established.
    pub epoch: Option<Epoch>,
    /// Original local cancellation, actual EOF, or native/protocol/clock failure.
    pub cause: Cause,
    /// Positive actual native bytes of this original40-byte request.
    pub written: usize,
    /// Whether that complete original request really wrote locally.
    pub request_written: bool,
    /// Selected original records delivered in this one epoch.
    pub records: u64,
    /// Current original input bytes retained before retirement; not proof of absence.
    pub partial_input: usize,
}
impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TRANSPORT observation source {:?} retired after {} records: ",
            self.epoch.as_ref().map(Epoch::value),
            self.records
        )?;
        match &self.cause {
            Cause::Cancelled => f.write_str("cancelled"),
            Cause::Eof => f.write_str("source EOF"),
            Cause::Failure(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for Loss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Cause::Failure(e) => Some(e),
            _ => None,
        }
    }
}

/// One complete actual row, owned independently of later source changes. It is
/// not authenticated routing state or a packet-delivery receipt.
pub struct Observation {
    /// Original admitted source epoch, absent when no epoch was established.
    epoch: Epoch,
    ordinal: u64,
    frame: OwnedFrame,
}
impl Observation {
    /// Borrow the actual original physical source epoch.
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// One-based selected record ordinal within that same epoch.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
    /// Borrow the typed original standard record without re-encoding.
    pub fn response(&self) -> Result<Response<'_>, Fault> {
        Response::decode(self.frame.bytes())
    }
    /// Borrow complete original received bytes.
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
}
/// Caller-visible native facts. Complete requires the matching standard END.
pub enum Progress {
    /// Actual connection attached and its original query was admitted locally.
    Attached(Epoch),
    /// Actual IO or filtered-input progress, without result/completion credit.
    Activity,
    /// An actual failed connection attempt; original bounds remain unchanged.
    Retry {
        /// Actual error from this failed connection attempt.
        error: io::Error,
    },
    /// The complete original40-byte query actually wrote locally.
    Written {
        /// Original source that wrote the query.
        epoch: Epoch,
        /// Positive native bytes written for this query.
        bytes: usize,
    },
    /// One selected actual owned original row.
    Record(Observation),
    /// Matching actual standard END was observed and the same MQ retired.
    Complete {
        /// Original source that supplied the matching END.
        epoch: Epoch,
        /// Selected records received in that same source epoch.
        records: u64,
    },
    /// Original source physically retired with its real cause and partial facts.
    Lost(Loss),
}
#[derive(Clone, Copy)]
struct Origin {
    epoch: u64,
}
/// A single retained original read-only query/subscription. Dropping an await
/// future retains this owner's real connection, buffers, bounds and cursors.
pub struct Client {
    source: EndpointSource,
    channel: Channel<Origin>,
    query: Query,
    limits: Limits,
    overall: Bound,
    initial: Option<Bound>,
    input: Option<Bound>,
    domain: Arc<()>,
    next: u64,
    /// Original admitted source epoch, absent when no epoch was established.
    epoch: Option<Epoch>,
    /// Positive actual native bytes of this original40-byte request.
    written: usize,
    /// Whether that complete original request really wrote locally.
    request_written: bool,
    input_bytes: usize,
    /// Selected original records delivered in this one epoch.
    records: u64,
    closed: bool,
    complete: bool,
}
impl Client {
    /// Reserve the original native owner and bounds; start no socket IO.
    pub fn new(
        source: EndpointSource,
        query: Query,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        let overall = Bound::targets(original);
        overall.check(source.clock().as_ref())?;
        let initial = Some(Bound::new(source.clock().as_ref(), limits.initial_timeout)?);
        let channel = Channel::new(source.duplicate()?, limits.framing()?)?;
        Ok(Self {
            source,
            channel,
            query,
            limits,
            overall,
            initial,
            input: None,
            domain: Arc::new(()),
            next: 0,
            epoch: None,
            written: 0,
            request_written: false,
            input_bytes: 0,
            records: 0,
            closed: false,
            complete: false,
        })
    }
    fn retire(&mut self, cause: Cause) -> Loss {
        self.channel.close();
        self.closed = true;
        self.initial = None;
        self.input = None;
        Loss {
            epoch: self.epoch.clone(),
            cause,
            written: self.written,
            request_written: self.request_written,
            records: self.records,
            partial_input: self.input_bytes,
        }
    }
    /// Physically close the original attempt/MQ before returning local facts.
    /// A previously returned Loss remains owned by its caller, never replaced.
    pub fn close(&mut self) -> Loss {
        self.retire(Cause::Cancelled)
    }
    /// Explicit fresh source only after old retirement. It reuses the original
    /// overall targets, emits a new epoch/START and never combines old rows.
    pub fn restart(&mut self) -> Result<(), Error> {
        if !self.closed || self.complete {
            return Err(Fault::Conflict.into());
        }
        self.overall.check(self.source.clock().as_ref())?;
        let initial = Bound::new(self.source.clock().as_ref(), self.limits.initial_timeout)?;
        let channel = Channel::new(self.source.duplicate()?, self.limits.framing()?)?;
        self.channel = channel;
        self.initial = Some(initial);
        self.input = None;
        self.epoch = None;
        self.written = 0;
        self.request_written = false;
        self.input_bytes = 0;
        self.records = 0;
        self.closed = false;
        Ok(())
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
    /// Earliest unchanged native phase/source target; useful while the caller
    /// lends an owned observation to a bounded output sink.
    pub fn native_deadline(&self) -> Instant {
        let mut hard = self.overall.targets.hard;
        if let Some(b) = &self.initial {
            hard = hard.min(b.targets.hard)
        }
        if let Some(b) = &self.input {
            hard = hard.min(b.targets.hard)
        }
        hard
    }
    /// Clock-free original-source deadline guard. It performs no new source IO
    /// and may be polled while the caller's output sink is blocked.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Loss> {
        if self.closed {
            return None;
        }
        match self.guard(cx) {
            Ok(()) => None,
            Err(e) => Some(self.retire(Cause::Failure(e))),
        }
    }
    fn check(&self) -> Result<(), Error> {
        self.overall.check(self.source.clock().as_ref())?;
        if let Some(b) = &self.initial {
            b.check(self.source.clock().as_ref())?
        }
        if let Some(b) = &self.input {
            b.check(self.source.clock().as_ref())?
        }
        Ok(())
    }
    fn frame(&mut self) -> Result<Option<Progress>, Error> {
        if !self.request_written {
            return Ok(None);
        }
        let Some(bytes) = self.channel.framing().and_then(|f| f.frame()) else {
            return Ok(None);
        };
        let (end, selected) = match (self.query, Response::decode(bytes)?) {
            (Query::Monitor { peer, .. }, Response::Monitor(row)) => {
                (false, peer == [0; 32] || peer == row.peer)
            }
            (
                Query::Links {
                    peer,
                    include_unconfirmed,
                },
                Response::Link(row),
            ) => (
                false,
                (peer == [0; 32] || peer == row.target) && (include_unconfirmed || row.confirmed),
            ),
            (Query::Monitor { one_shot: true, .. }, Response::MonitorEnd)
            | (Query::Links { .. }, Response::LinksEnd) => (true, true),
            _ => return Err(Fault::Malformed.into()),
        };
        let epoch = self.epoch.clone().ok_or(Fault::StaleGeneration)?;
        if end {
            self.channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .release_frame();
            self.input = None;
            self.input_bytes = 0;
            self.initial = None;
            let records = self.records;
            self.channel.close();
            self.closed = true;
            self.complete = true;
            return Ok(Some(Progress::Complete { epoch, records }));
        }
        if !selected {
            self.channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .release_frame();
            self.input = None;
            self.input_bytes = 0;
            return Ok(Some(Progress::Activity));
        }
        let next = self.records.checked_add(1).ok_or(Fault::Overflow)?;
        let mut owned = crate::buffer(bytes.len())?;
        owned.copy_from_slice(bytes);
        self.channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .release_frame();
        self.input = None;
        self.input_bytes = 0;
        self.initial = None;
        self.records = next;
        self.channel.reset_backoff();
        Ok(Some(Progress::Record(Observation {
            epoch,
            ordinal: next,
            frame: OwnedFrame::new(owned),
        })))
    }
    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        self.guard(cx)?;
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        }
        self.check()?;
        if self.epoch.is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    Poll::Ready(Ok(Progress::Retry { error }))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.guard(cx)?;
                    self.check()?;
                    let next = self.next.checked_add(1).ok_or(Fault::Overflow)?;
                    let mut bytes = crate::buffer(40)?;
                    self.query.encode(&mut bytes)?;
                    let framing = self.channel.framing_mut().ok_or(Fault::NotReady)?;
                    framing.reserve(40, Class::Ordinary)?;
                    if Instant::now() >= self.overall.targets.hard
                        || self
                            .initial
                            .as_ref()
                            .is_some_and(|b| Instant::now() >= b.targets.hard)
                    {
                        return Poll::Ready(Err(Fault::Deadline.into()));
                    }
                    framing
                        .enqueue_owned(
                            OwnedFrame::new(bytes),
                            Origin { epoch: next },
                            Class::Ordinary,
                        )
                        .map_err(|e| e.reason)?;
                    let epoch = Epoch {
                        domain: self.domain.clone(),
                        serial: next,
                    };
                    self.next = next;
                    self.epoch = Some(epoch.clone());
                    Poll::Ready(Ok(Progress::Attached(epoch)))
                }
            };
        }
        if !self.request_written {
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .poll_write(cx)
            {
                Poll::Ready(Ok(p)) => {
                    let epoch = self.epoch.as_ref().ok_or(Fault::StaleGeneration)?;
                    if p.origin.epoch != epoch.serial {
                        return Poll::Ready(Err(Fault::StaleGeneration.into()));
                    }
                    self.written = self.written.checked_add(p.bytes).ok_or(Fault::Overflow)?;
                    if p.complete {
                        self.request_written = true;
                        self.initial = None;
                        return Poll::Ready(Ok(Progress::Written {
                            epoch: epoch.clone(),
                            bytes: self.written,
                        }));
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        if let Some(step) = self.frame()? {
            return Poll::Ready(Ok(step));
        }
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(e))),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                Poll::Ready(Ok(Progress::Lost(self.retire(Cause::Eof))))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                if bytes > 0 && self.input.is_none() {
                    self.input = Some(Bound::new(
                        self.source.clock().as_ref(),
                        self.limits.input_timeout,
                    )?)
                }
                self.input_bytes = self.input_bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
                self.guard(cx)?;
                self.check()?;
                if let Some(step) = self.frame()? {
                    Poll::Ready(Ok(step))
                } else {
                    Poll::Ready(Ok(Progress::Activity))
                }
            }
        }
    }
    /// Native deadlines are checked before canonical stabilization and before
    /// each real source effect. Failures close the same source before exposure.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        match self.poll_inner(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Ok(Progress::Lost(self.retire(Cause::Failure(e))))),
            other => other,
        }
    }
    /// Wait on the same retained owner; canceling this wait preserves its real cursors.
    pub async fn progress(&mut self) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
