//! One original registration intent; each physical MQ keeps its own write facts.
use crate::{
    Deadlines, End, EndCause, EndpointSource, Epoch, Error, Instance, Job, Limits, OwnedResult,
    Progress, RelativeTime, ResultView, Submission, WriteId,
    ipc::{Request, SearchResult, StringBytes},
    scope::Scope,
};
use gnunet_client_host::channel::Channel;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Class, OwnedFrame},
};
use gnunet_types::Error as ProtocolError;
use std::{pin::Pin, sync::Arc};
mod io;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Announcement,
    Search,
}
#[derive(Clone, Copy)]
struct Origin<'id> {
    job: Job<'id>,
    epoch: Epoch<'id>,
    write: WriteId<'id>,
}
struct Client<'id> {
    scope: Scope<'id>,
    channel: Channel<Origin<'id>>,
    clock: Arc<dyn RuntimeClock>,
    mode: Mode,
    limits: Limits,
    deadlines: Deadlines,
    request: Option<OwnedFrame>,
    source: Option<OwnedFrame>,
    total: usize,
    sent: usize,
    epoch: Option<Epoch<'id>>,
    queued: bool,
    written: bool,
    first_written: bool,
    ordinal: u64,
    result_at: Option<u64>,
    first_result: bool,
    grace: Option<u64>,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    pending_end: Option<End<'id>>,
    yield_due: bool,
    read_first: bool,
    closed: bool,
}
impl<'id> Client<'id> {
    fn new(
        instance: &'id Instance,
        source: EndpointSource,
        request: Request<'_>,
        mode: Mode,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = source.clock();
        deadlines.validate(clock.sample()?.now.as_micros(), mode == Mode::Search)?;
        let len = request.encoded_len()?;
        if len > limits.frame_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(len, 0);
        request.encode(&mut bytes)?;
        let channel = Channel::new(source, limits.framing())?;
        Ok(Self {
            scope: Scope::new(instance)?,
            channel,
            clock,
            mode,
            limits,
            deadlines,
            request: Some(OwnedFrame::new(bytes)),
            source: None,
            total: len,
            sent: 0,
            epoch: None,
            queued: false,
            written: false,
            first_written: false,
            ordinal: 0,
            result_at: None,
            first_result: false,
            grace: None,
            alarm: None,
            alarm_at: None,
            pending_end: None,
            yield_due: false,
            read_first: false,
            closed: false,
        })
    }
    fn submission(&self) -> Submission {
        if self.written {
            Submission::Written { bytes: self.total }
        } else if self.sent > 0 {
            Submission::Partial {
                bytes: self.sent,
                total: self.total,
            }
        } else {
            Submission::Unsent
        }
    }
    fn end(&mut self, cause: EndCause) -> End<'id> {
        // Independent of every clock/Resolver/deadline port: physically fence the
        // actual original attempt/MQ before dropping bytes or publishing a result.
        let retired_mq = self.channel.framing().is_some();
        self.channel.close();
        self.closed = true;
        self.request = None;
        self.source = None;
        self.alarm = None;
        self.alarm_at = None;
        self.result_at = None;
        End {
            job: self.scope.job(),
            epoch: self.epoch,
            retired_mq,
            queued: self.queued,
            write: self.queued.then(|| self.scope.write()),
            submission: self.submission(),
            cause,
        }
    }
    fn source_lost(&mut self, cause: EndCause) -> Result<Progress<'id>, Error> {
        if self.grace.is_some()
            || matches!(&cause, EndCause::Io(error) if error.kind() == std::io::ErrorKind::InvalidData)
        {
            // Framing's InvalidData is a protocol refusal, not a native loss
            // that may be repaired by registering the same request again.
            return Ok(Progress::Ended(self.end(cause)));
        }
        // Fence the actual old source before releasing its partial TX/RX. The
        // receipt belongs to that source; this is not an ACK or logical DONE.
        let end = End {
            job: self.scope.job(),
            epoch: self.epoch,
            retired_mq: self.channel.framing().is_some(),
            queued: self.queued,
            write: self.queued.then(|| self.scope.write()),
            submission: self.submission(),
            cause,
        };
        self.channel.detach();
        self.source = None;
        // Until another physical attachment actually exists, preserve the last
        // source's queue/write receipt for cancel/deadline/stop observations.
        self.result_at = None;
        self.alarm = None;
        self.alarm_at = None;
        self.read_first = false;
        let retry_after = self.channel.schedule_retry()?;
        Ok(Progress::SourceLost { end, retry_after })
    }
    fn close(&mut self, cause: EndCause) -> Option<End<'id>> {
        if self.closed {
            return self.pending_end.take();
        }
        Some(self.end(cause))
    }
    fn next_deadline(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        let mut next = self.deadlines.until;
        if !self.first_written {
            next = next.min(self.deadlines.send_until);
        }
        if !self.first_result
            && let Some(first) = self.deadlines.first_result_until
        {
            next = next.min(first);
        }
        if let Some(grace) = self.grace {
            next = next.min(grace);
        }
        Some(next)
    }
    fn expire(&mut self, now: u64) -> Option<Progress<'id>> {
        let cause = if now >= self.deadlines.until {
            Some(EndCause::LifetimeDeadline)
        } else if !self.first_written && now >= self.deadlines.send_until {
            Some(EndCause::SendDeadline)
        } else if self.grace.is_some_and(|grace| now >= grace) {
            Some(EndCause::GraceDeadline)
        } else if !self.first_result
            && self
                .deadlines
                .first_result_until
                .is_some_and(|first| now >= first)
        {
            Some(EndCause::FirstResultDeadline)
        } else {
            None
        };
        cause.map(|cause| Progress::Ended(self.end(cause)))
    }
    fn prepare(&mut self) -> Result<Option<Progress<'id>>, Error> {
        if self.queued {
            return Ok(None);
        }
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        if self.source.is_none() {
            self.source = Some(OwnedFrame::copy_from(
                self.request.as_ref().ok_or(ProtocolError::Stale)?.bytes(),
            )?);
        }
        let source = self.source.as_ref().ok_or(ProtocolError::Stale)?;
        let frame = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        frame.reserve(source.len(), Class::Ordinary)?;
        let origin = Origin {
            epoch,
            job: self.scope.job(),
            write: self.scope.write(),
        };
        let bytes = self.source.take().ok_or(ProtocolError::Stale)?;
        if let Err(rejected) = frame.enqueue_owned(bytes, origin, Class::Ordinary) {
            self.source = Some(rejected.value.0);
            return Err(rejected.reason.into());
        }
        self.queued = true;
        Ok(Some(Progress::Queued {
            job: origin.job,
            epoch: origin.epoch,
            write: origin.write,
        }))
    }
    fn result(&self) -> Result<Option<ResultView<'_, 'id>>, Error> {
        let Some(observed_at) = self.result_at else {
            return Ok(None);
        };
        let frame = self
            .channel
            .framing()
            .and_then(|frame| frame.frame())
            .ok_or(ProtocolError::Stale)?;
        Ok(Some(ResultView {
            job: self.scope.job(),
            epoch: self.epoch.ok_or(ProtocolError::Stale)?,
            ordinal: self.ordinal,
            observed_at,
            result: SearchResult::decode(frame)?,
        }))
    }
    fn release_result(&mut self) -> Result<(), Error> {
        if self.result_at.is_none() {
            return Err(ProtocolError::NotReady.into());
        }
        if !self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::Stale)?
            .release_frame()
        {
            return Err(ProtocolError::Stale.into());
        }
        self.result_at = None;
        Ok(())
    }
    fn take_result(&mut self) -> Result<Option<OwnedResult<'id>>, Error> {
        let Some(view) = self.result()? else {
            return Ok(None);
        };
        let len = view
            .result
            .get_path
            .len()
            .checked_add(view.result.put_path.len())
            .ok_or(ProtocolError::Capacity)?;
        let mut path = Vec::new();
        path.try_reserve_exact(len)
            .map_err(|_| ProtocolError::Capacity)?;
        path.extend_from_slice(view.result.get_path);
        path.extend_from_slice(view.result.put_path);
        let owned = OwnedResult {
            job: view.job,
            epoch: view.epoch,
            ordinal: view.ordinal,
            observed_at: view.observed_at,
            peer: view.result.peer,
            path,
            get_len: view.result.get_path.len(),
        };
        // Admission/allocation failure above leaves the original RX untouched.
        self.release_result()?;
        Ok(Some(owned))
    }
    fn stop_after_send(&mut self) -> Result<Option<End<'id>>, Error> {
        if self.closed {
            return Ok(self.pending_end.take());
        }
        if self.channel.framing().is_none() || self.sent == 0 || self.written {
            // No replacement source may be opened just to finish an old suffix.
            return Ok(Some(self.end(EndCause::Graceful)));
        }
        if self.grace.is_none() {
            let now = match self.clock.sample() {
                Ok(sample) => sample.now.as_micros(),
                Err(error) => return Ok(Some(self.end(EndCause::Clock(error)))),
            };
            let cap = if self.first_written {
                self.deadlines.until
            } else {
                self.deadlines.send_until
            };
            let grace = now
                .checked_add(self.limits.retirement_grace_micros)
                .unwrap_or(cap)
                .min(cap)
                .min(self.deadlines.until);
            self.grace = Some(grace);
            // Suppress any already retained callback; no new RX occurs while
            // finishing the original suffix. No wire cancellation exists.
            self.result_at = None;
            self.alarm = None;
            self.alarm_at = None;
        }
        Ok(None)
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.channel.close();
    }
}
/// Canonical announcement fields. Reserved bytes are always exactly zero.
#[derive(Clone, Copy, Debug)]
pub struct AnnouncementRequest<'a> {
    /// Regular expression as actual C-string bytes without the final NUL.
    pub regex: &'a [u8],
    /// Official edge compression value, retained exactly.
    pub compression: u16,
    /// Service refresh policy; not a local acknowledgement deadline.
    pub refresh_delay: RelativeTime,
}
/// One retained announcement registration, restored after physical source loss.
pub struct Announcement<'id>(Client<'id>);
impl<'id> Announcement<'id> {
    /// Reserve/encode one canonical announcement, without opening a socket.
    /// `deadlines.first_result_until` must be None because there is no ACK.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        request: AnnouncementRequest<'_>,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        Client::new(
            instance,
            source,
            Request::Announce {
                compression: request.compression,
                reserved: 0,
                refresh_delay: request.refresh_delay,
                regex: StringBytes::new(request.regex)?,
            },
            Mode::Announcement,
            deadlines,
            limits,
        )
        .map(Self)
    }
}
/// One original continuous search. It has neither a wire RID nor a wire DONE.
pub struct Search<'id>(Client<'id>);
impl<'id> Search<'id> {
    /// Reserve/encode one canonical search, without opening a socket.
    /// A finite first-result deadline is required, independent of send/lifetime.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        string: &[u8],
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        Client::new(
            instance,
            source,
            Request::Search {
                string: StringBytes::new(string)?,
            },
            Mode::Search,
            deadlines,
            limits,
        )
        .map(Self)
    }
    /// Borrow exact retained RESULT bytes with their original source metadata.
    /// This is an observation of that read turn, not a live-provider guarantee.
    pub fn result(&self) -> Result<Option<ResultView<'_, 'id>>, Error> {
        self.0.result()
    }
    /// Copy combined GET/PUT paths once, then release the original RX. On
    /// allocation failure the complete original frame remains available.
    pub fn take_result(&mut self) -> Result<Option<OwnedResult<'id>>, Error> {
        self.0.take_result()
    }
    /// Consume the current result without allocation or a fabricated wire ACK.
    pub fn release_result(&mut self) -> Result<(), Error> {
        self.0.release_result()
    }
}
macro_rules! common {
    ($handle:ident) => {
        impl<'id> $handle<'id> {
            /// Original logical intent; never a reconstructible wire RID.
            #[must_use]
            pub fn job(&self) -> Job<'id> {
                self.0.scope.job()
            }
            /// Last actually attached MQ, including after its physical retirement.
            #[must_use]
            pub const fn epoch(&self) -> Option<Epoch<'id>> {
                self.0.epoch
            }
            /// Exact exposure of the last attached source. Before replacement
            /// attachment this retains the old source facts, not a zeroed rewrite.
            #[must_use]
            pub fn submission(&self) -> Submission {
                self.0.submission()
            }
            /// Earliest remaining original logical deadline.
            #[must_use]
            pub fn next_deadline(&self) -> Option<u64> {
                self.0.next_deadline()
            }
            /// Drive one bounded step. Canceling this wait future preserves the
            /// original connection attempt, RX/TX cursor, identities and deadlines.
            pub async fn drive(
                &mut self,
                until: Option<tokio::time::Instant>,
            ) -> Result<Progress<'id>, Error> {
                self.0.drive(until).await
            }
            /// Physically close the original attempt/MQ immediately, independent
            /// of clock state. A partial request is never moved to another MQ.
            pub fn cancel(&mut self) -> Option<End<'id>> {
                self.0.close(EndCause::Cancelled)
            }
            /// Explicit finite suffix-only grace; does not open a new MQ or send
            /// an unwritten request. Repeated calls retain the first hard bound.
            pub fn stop_after_send(&mut self) -> Result<Option<End<'id>>, Error> {
                self.0.stop_after_send()
            }
            /// Physically close now, without polling any clock/Resolver port.
            pub fn close(&mut self) -> Option<End<'id>> {
                self.0.close(EndCause::Closed)
            }
        }
    };
}
common!(Announcement);
common!(Search);
