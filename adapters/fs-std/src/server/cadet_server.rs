//! Bounded caller-driven official FS CADET block serving.
//!
//! Source jobs retain their original channel/query generation through native
//! loss. Missing or refused lookups grant processing credit without inventing an
//! FS negative or END. Type6 descriptors require the real shared index resolver.
pub mod source;
use gnunet_cadet_host::{
    Channel, Client, Direction, Epoch, Error as NativeError, Loss, LossCause, Port, Received,
    Step as NativeStep, Transmit, TransmitKind,
};
use gnunet_crypto::hash512;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::OwnedFrame,
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::{
    Frame,
    cadet::MAX_APPLICATION_MESSAGE_SIZE,
    fs_cadet::{PORT_LABEL, Query, REPLY_PREFIX, Reply},
};
pub use source::{BlockSource, Selection};
use std::{
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

#[cfg(test)]
mod tests;

/// Original native or local invariant refusal. Source operation failures are
/// returned with their original query as Step::SourceFailed instead.
#[derive(Debug)]
pub enum Error {
    /// Actual native setup, transport or CADET owner cause.
    Native(NativeError),
    /// Actual format, source authority or bounded-resource refusal.
    Protocol(ProtocolError),
}
impl From<NativeError> for Error {
    fn from(error: NativeError) -> Self {
        Self::Native(error)
    }
}
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(error) => write!(f, "FS CADET server native: {error}"),
            Self::Protocol(error) => write!(f, "FS CADET server: {error}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}
/// Explicit local limits. Native Client framing/credit limits remain separate.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum retained accepted channels, packets and candidate replies.
    /// Supply at least channels+1 native ChannelSlots for an overflow rejection.
    pub channels: usize,
    /// Largest encrypted block; configure native max_payload_bytes/frame_bytes
    /// to fit its actual16-byte FS reply prefix and outer12-byte DATA prefix.
    pub block_bytes: usize,
    /// One idle cycle bounded by both source and native time. This is not a
    /// remote content expiry; polls, partial writes and missing credit cannot
    /// renew it. New DATA or a completed live processing receipt may renew it.
    pub idle_timeout: Duration,
    /// Native monotonic bound for one original admitted MQ frame. Partial writes
    /// and canceled observation waits never renew it; expiry retires the MQ.
    pub write_timeout: Duration,
    /// Native bound captured when a channel first closes, and one shared bound
    /// captured by the first shutdown request. Further cleanup does not renew
    /// either bound. Source operations retain actual terminal/explicit close debt.
    pub drain_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            channels: 64,
            block_bytes: MAX_APPLICATION_MESSAGE_SIZE - REPLY_PREFIX,
            idle_timeout: Duration::from_secs(120),
            write_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
        }
    }
}
/// Cumulative actual local observations, with no remote absence/delivery claim.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actually accepted original incoming channels.
    pub accepted: u64,
    /// Channels refused under the explicit local capacity/format policy.
    pub refused: u64,
    /// Original application queries admitted to the source owner.
    pub queries: u64,
    /// Complete actual local reply writes, not peer processing acknowledgements.
    pub replies_written: u64,
    /// Actual source DATA_END observations, emitting no FS wire frame.
    pub not_found: u64,
    /// Original nonterminal row rejections within still-active selections.
    pub records_rejected: u64,
    /// Original source operation failures, returned explicitly to the caller.
    pub source_failures: u64,
    /// Original selections explicitly retired at their actual operation boundary.
    /// This is local cancellation/stop accounting, never remote absence.
    pub retired_queries: u64,
    /// Actual permanently retired source ports; serving is withdrawn immediately.
    pub source_unavailable: u64,
    /// Full native receive_done writes after original query/output processing.
    pub receipts_written: u64,
    /// Actual native MQ retirements.
    pub losses: u64,
    /// Local source/native-clock idle channel expirations.
    pub idle_expirations: u64,
    /// Original frame bounds that caused actual native MQ retirement.
    pub write_timeouts: u64,
    /// Original channel/shutdown cleanup bounds that retired the native MQ.
    /// This never claims completion of a still-owned source query.
    pub drain_timeouts: u64,
    /// Source selections settled after their channel was retired, including
    /// an explicitly unsubmitted continuation boundary.
    pub retired_completions: u64,
}
/// One original serving observation. Query numbers are local ownership labels.
pub enum Step<'id> {
    /// Actual native, source, timer or bounded queue progress.
    Activity,
    /// The desired official port announcement fully wrote on this exact MQ.
    /// This is local listening readiness, not a count of connected peers.
    Listening {
        /// Original physical source.
        source: Epoch<'id>,
        /// Original desired logical port, retained across source reconnects.
        port: Port<'id>,
    },
    /// One original DATA record was rejected while the same query continues.
    /// This neither settles its source job nor grants early receive credit.
    SourceRejectedRecord {
        /// Original local query owner, never a wire request identifier.
        query: u64,
        /// Original channel, possibly already retired while its source finishes.
        channel: Channel<'id>,
        /// Exact original row/selection and its concrete nonterminal cause.
        record: source::RejectedRecord,
    },
    /// Original selection retired locally after its already admitted operation
    /// settled. The exact final observation is retained; no reply is generated.
    SourceRetired {
        /// Original local query owner, never a wire request identifier.
        query: u64,
        /// Original channel generation, possibly already physically retired.
        channel: Channel<'id>,
        /// Original selection plus its actual terminal/unsubmitted observation.
        retired: source::Retired,
    },
    /// Actual source port became permanently unavailable. This server has
    /// already stopped admission and requested port withdrawal. The caller must
    /// retain the original cause and close/rebuild via its supervisor.
    SourceUnavailable {
        /// Original local query owner whose read observed the closed port.
        query: u64,
        /// Original channel generation; never replacement-channel authority.
        channel: Channel<'id>,
        /// Original actual dependency failure and any native uncertainty.
        cause: source::Failure,
    },
    /// One source lookup/resolution failed without an application negative.
    SourceFailed {
        /// Original local query owner, never an FS wire request ID.
        query: u64,
        /// Original channel, possibly already retired by the actual service.
        channel: Channel<'id>,
        /// Original native DATASTORE/index/refusal cause with its uncertainty.
        cause: source::Failure,
    },
    /// One channel was locally refused without an FS negative reply.
    Rejected {
        /// Original channel generation.
        channel: Channel<'id>,
        /// Actual bounded-resource or malformed-query reason.
        reason: ProtocolError,
    },
    /// Actual source loss; old channels/receipts cannot act on a replacement MQ.
    Lost {
        /// Original epoch and pending-write exposure facts.
        report: Loss<'id>,
        /// Actual physical/protocol cause.
        cause: LossCause,
    },
    /// Actual connection-attempt retry chosen by the original CLIENT owner.
    ConnectRetry {
        /// Original native connection failure.
        error: std::io::Error,
        /// Original selected retry delay.
        retry_after: Duration,
    },
    /// Only this caller's observation wait elapsed; original jobs remain owned.
    WaitDeadline,
    /// Desired port, channels and original source work have all drained. The
    /// caller may now close native/source owners and join the one index worker.
    Quiesced,
    /// The owner was explicitly physically closed.
    Closed,
}
/// Results of explicit close; inspect both original independent retirements.
#[must_use]
pub struct Closed<'id> {
    /// Actual native physical retirement and exposure facts.
    pub native: Result<Option<Loss<'id>>, NativeError>,
    /// Original source close result, retaining any DATASTORE uncertainty.
    pub source: Result<(), source::Failure>,
    /// An original read physically retired before an observed source terminal.
    /// None after a successful graceful drain. This is not a GET success/END.
    pub pending_query: Option<RetiredQuery<'id>>,
}
/// Exact local source owner retained when immediate close interrupts its wait.
#[derive(Clone, Copy, Debug)]
pub struct RetiredQuery<'id> {
    /// Original local ownership generation.
    pub query: u64,
    /// Original channel generation, possibly already physically destroyed.
    pub channel: Channel<'id>,
    /// Original immutable source selection.
    pub selection: Selection,
}
struct Packet<'id> {
    original: Received<'id>,
    cursor: usize,
}
#[derive(Clone, Copy)]
enum Write {
    Reply,
    Receipt,
    Destroy,
}
struct Entry<'id> {
    channel: Channel<'id>,
    packet: Option<Packet<'id>>,
    working: bool,
    reply: Option<OwnedFrame>,
    write: Option<(Transmit<'id>, Write)>,
    idle: Option<Deadline>,
    /// Original native idle target while live; exactly one cleanup target after
    /// first closing. Neither provider progress nor repeated cancellation renews it.
    hard: Instant,
    closing: bool,
}
impl Entry<'_> {
    fn retire(&mut self, now: Instant, timeout: Duration) {
        if !self.closing {
            // A late cancel/poll cannot move an already elapsed native idle
            // cycle forward and thereby buy another full cleanup interval.
            let start = now.min(self.hard);
            self.hard = start.checked_add(timeout).unwrap_or(start);
        }
        self.closing = true;
        self.idle = None;
    }
}
struct Job<'id> {
    serial: u64,
    channel: Channel<'id>,
    selection: Selection,
}
struct WriteBound<'id> {
    transmit: Transmit<'id>,
    hard: Instant,
}
/// One original native listener and serialized source owner. No Resolver,
/// blocking worker, backend, Index/WAL or background task is created here.
pub struct Server<'id, 'slots, S: BlockSource> {
    client: Client<'id, 'slots>,
    source: S,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    port: Option<Port<'id>>,
    entries: Vec<Entry<'id>>,
    rejected: Option<(Channel<'id>, Option<Transmit<'id>>)>,
    job: Option<Job<'id>>,
    next_query: u64,
    cursor: usize,
    stopping: bool,
    withdrawal: Option<Transmit<'id>>,
    write_bound: Option<WriteBound<'id>>,
    cleanup: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    native_stopped: bool,
    closed: bool,
    report: Report,
}
impl<'id, 'slots, S: BlockSource> Server<'id, 'slots, S> {
    /// Retain independently configured native/source owners and the native
    /// source's exact clock. No listener or query is exposed by construction.
    pub fn new(client: Client<'id, 'slots>, source: S, limits: Limits) -> Result<Self, Error> {
        if limits.channels == 0
            || limits.block_bytes == 0
            || limits.block_bytes > MAX_APPLICATION_MESSAGE_SIZE - REPLY_PREFIX
            || limits.idle_timeout.is_zero()
            || Instant::now().checked_add(limits.idle_timeout).is_none()
            || limits.write_timeout.is_zero()
            || limits.drain_timeout.is_zero()
            || Instant::now().checked_add(limits.write_timeout).is_none()
            || Instant::now().checked_add(limits.drain_timeout).is_none()
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let clock = client.clock();
        Self::idle_target(clock.as_ref(), limits.idle_timeout)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.channels)
            .map_err(|_| ProtocolError::Capacity)?;
        let write_bound = client.pending_transmit().map(|transmit| WriteBound {
            transmit,
            hard: Self::target(limits.write_timeout),
        });
        Ok(Self {
            clock,
            client,
            source,
            limits,
            port: None,
            entries,
            rejected: None,
            job: None,
            next_query: 0,
            cursor: 0,
            stopping: false,
            withdrawal: None,
            write_bound,
            cleanup: None,
            alarm: None,
            native_stopped: false,
            closed: false,
            report: Report::default(),
        })
    }
    /// Actual local observations without performing IO or granting credit.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Recover the original explicit CLIENT clock/Resolver ports without replay.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        Ok(self.client.recover_ports()?)
    }
    /// Stop new query admission and withdraw the original listening port while
    /// draining every already admitted source operation to its actual terminal.
    /// Unsubmitted continuation GETs/resolutions are retired explicitly.
    /// The first request captures one finite native cleanup bound. Reaching it
    /// physically closes the MQ, but never fabricates a pending source terminal.
    /// Inspect SourceRetired/SourceFailed until Quiesced, then close.
    pub fn request_shutdown(&mut self) {
        if !self.stopping {
            self.cleanup = Some(Self::target(self.limits.drain_timeout));
        }
        self.stopping = true;
        for entry in &mut self.entries {
            entry.retire(Instant::now(), self.limits.drain_timeout);
        }
    }
    /// Original source jobs and native cleanup have drained; no source terminal
    /// was invented. The physical MQ remains owned until explicit close.
    #[must_use]
    pub fn quiesced(&self) -> bool {
        self.stopping
            && self.port.is_none()
            && self.withdrawal.is_none()
            && self.entries.is_empty()
            && self.rejected.is_none()
            && self.job.is_none()
            && self.client.pending_transmit().is_none()
            && self.write_bound.is_none()
    }
    /// Deliberately retire one actual channel after its admitted native write
    /// finishes or that frame's original bound physically retires the MQ.
    /// An active readonly source job continues to its original completion.
    pub fn cancel(&mut self, channel: Channel<'id>) -> Result<(), ProtocolError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.channel == channel)
            .ok_or(ProtocolError::StaleGeneration)?;
        entry.retire(Instant::now(), self.limits.drain_timeout);
        Ok(())
    }
    fn idle_target(
        clock: &dyn RuntimeClock,
        timeout: Duration,
    ) -> Result<AbsoluteTime, ProtocolError> {
        let micros = u64::try_from(timeout.as_micros()).map_err(|_| ProtocolError::InvalidInput)?;
        if micros == 0 || micros == u64::MAX {
            return Err(ProtocolError::InvalidInput);
        }
        let target = clock
            .sample()?
            .now
            .as_micros()
            .checked_add(micros)
            .filter(|target| *target != u64::MAX)
            .ok_or(ProtocolError::Overflow)?;
        Ok(AbsoluteTime::from_micros(target))
    }
    fn idle(clock: Arc<dyn RuntimeClock>, timeout: Duration) -> Result<Deadline, ProtocolError> {
        let target = Self::idle_target(clock.as_ref(), timeout)?;
        Deadline::at(clock, target)
    }
    fn target(timeout: Duration) -> Instant {
        let now = Instant::now();
        // Construction rejects an unrepresentable policy. If the native clock
        // later reaches its representational edge, expire now rather than drop
        // an already admitted frame's bound.
        now.checked_add(timeout).unwrap_or(now)
    }
    fn native_target(&self) -> Option<Instant> {
        if self.native_stopped {
            return None;
        }
        self.write_bound
            .as_ref()
            .map(|bound| bound.hard)
            .into_iter()
            .chain(self.cleanup)
            .chain(self.entries.iter().map(|entry| entry.hard))
            .min()
    }
    fn watch_pending(&mut self, original: Instant) -> Result<(), Error> {
        match (self.client.pending_transmit(), &self.write_bound) {
            (Some(transmit), Some(bound)) if transmit == bound.transmit => {}
            (Some(transmit), None) => {
                self.write_bound = Some(WriteBound {
                    transmit,
                    hard: original,
                });
            }
            (None, None) => {}
            // Only the original Written or a physical Loss may clear/change an
            // admitted token. Never silently give a replacement a fresh lease.
            _ => return Err(ProtocolError::StaleGeneration.into()),
        }
        Ok(())
    }
    fn poll_alarm(&mut self, cx: &mut Context<'_>) {
        let Some(target) = self.native_target() else {
            self.alarm = None;
            return;
        };
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(target);
        } else {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(target)));
        }
        if let Some(alarm) = &mut self.alarm {
            let _ready = alarm.as_mut().poll(cx);
        }
    }
    fn retire_channels(&mut self) {
        self.entries.clear();
        self.rejected = None;
        self.write_bound = None;
        self.alarm = None;
        if self.withdrawal.is_some() || self.native_stopped {
            self.withdrawal = None;
            self.port = None;
        }
        if self.job.is_some() {
            // This original read still owes its actual terminal. Its selection
            // and old channel generation never become a replacement's work.
            self.source.request_retire();
        }
    }
    fn lost(&mut self, report: Loss<'id>, cause: LossCause) -> Step<'id> {
        self.retire_channels();
        self.report.losses = self.report.losses.saturating_add(1);
        Step::Lost { report, cause }
    }
    fn expire_native(&mut self) -> Result<Option<Step<'id>>, Error> {
        if self.native_stopped {
            return Ok(None);
        }
        let now = Instant::now();
        let mut idle_expired = false;
        for entry in &mut self.entries {
            if !entry.closing && now >= entry.hard {
                entry.retire(now, self.limits.drain_timeout);
                self.report.idle_expirations = self.report.idle_expirations.saturating_add(1);
                idle_expired = true;
            }
        }
        let drain_due = self.cleanup.is_some_and(|target| now >= target)
            || self
                .entries
                .iter()
                .any(|entry| entry.closing && now >= entry.hard);
        let write_due = self
            .write_bound
            .as_ref()
            .is_some_and(|bound| now >= bound.hard);
        if !drain_due && !write_due {
            return Ok(idle_expired.then_some(Step::Activity));
        }
        if drain_due {
            self.report.drain_timeouts = self.report.drain_timeouts.saturating_add(1);
        } else {
            self.report.write_timeouts = self.report.write_timeouts.saturating_add(1);
        }
        if self.stopping {
            // Detach the original native cursor before clearing its tokens. A
            // pending source job keeps this Server alive until its real terminal
            // (or explicit close, whose pending_query reports the uncertainty).
            let loss = self.client.close()?;
            self.native_stopped = true;
            self.cleanup = None;
            return Ok(Some(match loss {
                Some(report) => self.lost(report, LossCause::Requested),
                None => {
                    self.retire_channels();
                    Step::Activity
                }
            }));
        }
        // A local serving write timeout is recoverable. Only actual reconnect
        // retires the shared MQ; desired ports restore through the same Client.
        let step = self.client.reconnect()?;
        self.native(step).map(Some)
    }
    fn prepare(&self, job: &Job<'id>, block: &source::Block) -> Result<OwnedFrame, ProtocolError> {
        let data = block.data()?;
        if *data.key != job.selection.query
            || data.kind == 0
            || data.kind == 6
            || (job.selection.block_type.value() != 0
                && job.selection.block_type.value() != data.kind)
        {
            return Err(ProtocolError::Authentication);
        }
        if data.value.len() > self.limits.block_bytes {
            return Err(ProtocolError::TooLarge);
        }
        if matches!(data.kind, 1 | 2) && hash512(data.value) != job.selection.query {
            return Err(ProtocolError::Authentication);
        }
        let reply = Reply {
            block_type: gnunet_wire::official::fs::BlockType::new(data.kind),
            expiration: data.expiration,
            block: data.value,
        };
        let length = reply.encoded_len()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(length, 0);
        reply.encode(&mut bytes)?;
        Ok(OwnedFrame::new(bytes))
    }
    fn poll_source(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<'id>, Error>> {
        let Some(job) = self.job.as_ref() else {
            return Poll::Pending;
        };
        // The original admitted operation still owns its completion. Once its
        // channel is gone/closing, no unsubmitted UID GET or resolver may take
        // ownership on behalf of that retired channel, including during stop.
        if self.stopping
            || !self
                .entries
                .iter()
                .any(|entry| entry.channel == job.channel && !entry.closing)
        {
            self.source.request_retire();
        }
        let result = match self.source.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(source::Progress::Activity)) => return Poll::Ready(Ok(Step::Activity)),
            Poll::Ready(Ok(source::Progress::Skipped(record))) => {
                let job = self.job.as_ref().ok_or(ProtocolError::StaleGeneration)?;
                if record.selection() != job.selection {
                    return Poll::Ready(Err(ProtocolError::Authentication.into()));
                }
                self.report.records_rejected = self.report.records_rejected.saturating_add(1);
                return Poll::Ready(Ok(Step::SourceRejectedRecord {
                    query: job.serial,
                    channel: job.channel,
                    record,
                }));
            }
            Poll::Ready(result) => result,
        };
        let job = self.job.take().ok_or(ProtocolError::StaleGeneration)?;
        let index = self
            .entries
            .iter()
            .position(|entry| entry.channel == job.channel && !entry.closing);
        if index.is_none() {
            self.report.retired_completions = self.report.retired_completions.saturating_add(1);
        }
        // Only this original channel owner may receive the completion. Clear
        // its busy marker even if it is closing, without handing it another job.
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.channel == job.channel)
        {
            entry.working = false;
        }
        let result = match result {
            Ok(source::Progress::Retired(retired)) => {
                if retired.selection != job.selection {
                    return Poll::Ready(Err(ProtocolError::Authentication.into()));
                }
                self.report.retired_queries = self.report.retired_queries.saturating_add(1);
                return Poll::Ready(Ok(Step::SourceRetired {
                    query: job.serial,
                    channel: job.channel,
                    retired,
                }));
            }
            Ok(source::Progress::Unavailable { selection, cause }) => {
                if selection != job.selection {
                    return Poll::Ready(Err(ProtocolError::Authentication.into()));
                }
                self.report.source_unavailable = self.report.source_unavailable.saturating_add(1);
                self.request_shutdown();
                return Poll::Ready(Ok(Step::SourceUnavailable {
                    query: job.serial,
                    channel: job.channel,
                    cause,
                }));
            }
            Ok(source::Progress::Found(block)) => {
                if index.is_some() {
                    self.prepare(&job, &block)
                        .map(Some)
                        .map_err(source::Failure::operation)
                } else {
                    Ok(None)
                }
            }
            Ok(source::Progress::NotFound) => {
                self.report.not_found = self.report.not_found.saturating_add(1);
                Ok(None)
            }
            // This owner deliberately uses one-shot start, never a sweep.
            Ok(
                source::Progress::Activity
                | source::Progress::Skipped(_)
                | source::Progress::Candidate(_),
            ) => {
                return Poll::Ready(Err(ProtocolError::StaleGeneration.into()));
            }
            Err(cause) => Err(cause),
        };
        match result {
            Ok(reply) => {
                if let Some(index) = index {
                    self.entries[index].reply = reply;
                }
                Poll::Ready(Ok(Step::Activity))
            }
            Err(cause) => {
                self.report.source_failures = self.report.source_failures.saturating_add(1);
                Poll::Ready(Ok(Step::SourceFailed {
                    query: job.serial,
                    channel: job.channel,
                    cause,
                }))
            }
        }
    }
    fn expire(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let mut changed = false;
        for entry in &mut self.entries {
            if let Some(idle) = &mut entry.idle
                && let Poll::Ready(result) = Pin::new(idle).poll(cx)
            {
                result?;
                entry.retire(Instant::now(), self.limits.drain_timeout);
                self.report.idle_expirations = self.report.idle_expirations.saturating_add(1);
                changed = true;
            }
        }
        Ok(changed)
    }
    fn advance(&mut self) -> Result<Option<Step<'id>>, Error> {
        if self.client.pending_transmit().is_some() {
            return Ok(None);
        }
        if self.stopping
            && let Some(port) = self.port
            && self.withdrawal.is_none()
        {
            self.withdrawal = self.client.close_port(port)?;
            if self.withdrawal.is_none() {
                self.port = None;
            }
            return Ok(Some(Step::Activity));
        }
        if self.client.epoch().is_none() {
            return Ok(None);
        }
        if !self.stopping && self.port.is_none() {
            self.port = Some(self.client.listen(hash512(PORT_LABEL))?);
            return Ok(Some(Step::Activity));
        }
        if let Some((channel, transmit)) = &mut self.rejected
            && transmit.is_none()
        {
            *transmit = Some(self.client.destroy(*channel)?);
            return Ok(Some(Step::Activity));
        }
        for offset in 0..self.entries.len() {
            let index = (self.cursor + offset) % self.entries.len();
            let entry = &mut self.entries[index];
            if entry.write.is_some() {
                continue;
            }
            if entry.closing {
                entry.packet = None;
                entry.reply = None;
                entry.write = Some((self.client.destroy(entry.channel)?, Write::Destroy));
                self.cursor = (index + 1) % self.entries.len();
                return Ok(Some(Step::Activity));
            }
            if let Some(reply) = &entry.reply {
                if self.client.channel_info(entry.channel)?.send_credit != 0 {
                    let transmit = self.client.send(entry.channel, 0, reply.bytes())?;
                    entry.reply = None;
                    entry.write = Some((transmit, Write::Reply));
                    self.cursor = (index + 1) % self.entries.len();
                    return Ok(Some(Step::Activity));
                }
                continue;
            }
            if entry.working {
                continue;
            }
            let Some(packet) = &entry.packet else {
                continue;
            };
            if packet.cursor == packet.original.messages().len() {
                let transmit = self.client.receive_done(packet.original.delivery())?;
                entry.packet = None;
                entry.write = Some((transmit, Write::Receipt));
                self.cursor = (index + 1) % self.entries.len();
                return Ok(Some(Step::Activity));
            }
        }
        if self.job.is_some() || self.stopping {
            return Ok(None);
        }
        for offset in 0..self.entries.len() {
            let index = (self.cursor + offset) % self.entries.len();
            let entry = &mut self.entries[index];
            if entry.closing || entry.working || entry.reply.is_some() || entry.write.is_some() {
                continue;
            }
            let Some(packet) = &mut entry.packet else {
                continue;
            };
            let parsed = (|| {
                let bytes = &packet.original.messages()[packet.cursor..];
                let (frame, _) = Frame::decode_prefix(bytes)?;
                let query = Query::decode(&bytes[..frame.encoded_len()])?;
                Ok::<_, ProtocolError>((
                    Selection {
                        block_type: query.block_type,
                        query: *query.query,
                    },
                    frame.encoded_len(),
                ))
            })();
            let (selection, length) = match parsed {
                Ok(parsed) => parsed,
                Err(reason) => {
                    entry.retire(Instant::now(), self.limits.drain_timeout);
                    self.report.refused = self.report.refused.saturating_add(1);
                    return Ok(Some(Step::Rejected {
                        channel: entry.channel,
                        reason,
                    }));
                }
            };
            let serial = self
                .next_query
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?;
            packet.cursor = packet
                .cursor
                .checked_add(length)
                .ok_or(ProtocolError::Overflow)?;
            self.next_query = serial;
            self.report.queries = self.report.queries.saturating_add(1);
            match self.source.start(selection) {
                Ok(()) => {
                    entry.working = true;
                    self.job = Some(Job {
                        serial,
                        channel: entry.channel,
                        selection,
                    });
                    self.cursor = (index + 1) % self.entries.len();
                    return Ok(Some(Step::Activity));
                }
                Err(cause) => {
                    let channel = entry.channel;
                    if matches!(
                        self.source.availability(),
                        source::Availability::Unavailable | source::Availability::Closed
                    ) {
                        self.report.source_unavailable =
                            self.report.source_unavailable.saturating_add(1);
                        self.request_shutdown();
                        return Ok(Some(Step::SourceUnavailable {
                            query: serial,
                            channel,
                            cause,
                        }));
                    }
                    self.report.source_failures = self.report.source_failures.saturating_add(1);
                    return Ok(Some(Step::SourceFailed {
                        query: serial,
                        channel,
                        cause,
                    }));
                }
            }
        }
        Ok(None)
    }
    fn written(&mut self, transmit: Transmit<'id>) -> Result<Step<'id>, Error> {
        if !self
            .write_bound
            .as_ref()
            .is_some_and(|bound| bound.transmit == transmit)
        {
            return Err(ProtocolError::StaleGeneration.into());
        }
        self.write_bound = None;
        if self.withdrawal == Some(transmit) {
            self.withdrawal = None;
            self.port = None;
        }
        if self
            .rejected
            .is_some_and(|(_, pending)| pending == Some(transmit))
        {
            self.rejected = None;
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.write.is_some_and(|(pending, _)| pending == transmit))
        {
            let (_, kind) = self.entries[index]
                .write
                .take()
                .ok_or(ProtocolError::StaleGeneration)?;
            match kind {
                Write::Reply => {
                    self.report.replies_written = self.report.replies_written.saturating_add(1);
                }
                Write::Receipt => {
                    self.report.receipts_written = self.report.receipts_written.saturating_add(1);
                    if !self.entries[index].closing {
                        self.entries[index].idle =
                            Some(Self::idle(self.clock.clone(), self.limits.idle_timeout)?);
                        self.entries[index].hard = Self::target(self.limits.idle_timeout);
                    }
                }
                Write::Destroy => {
                    self.entries.swap_remove(index);
                }
            }
        }
        if transmit.kind() == TransmitKind::PortOpen
            && let Some(port) = self.port
            && self.client.port_announced(port)?
        {
            return Ok(Step::Listening {
                source: transmit.epoch(),
                port,
            });
        }
        Ok(Step::Activity)
    }
    fn native(&mut self, step: NativeStep<'id>) -> Result<Step<'id>, Error> {
        match step {
            NativeStep::Written(written) => self.written(written.transmit),
            NativeStep::Incoming { channel, port } => {
                let info = self.client.channel_info(channel)?;
                let wrong_port = Some(port) != self.port
                    || info.port != hash512(PORT_LABEL)
                    || info.direction != Direction::Incoming;
                if self.stopping || wrong_port || self.entries.len() == self.limits.channels {
                    if self.rejected.is_some() {
                        return Err(ProtocolError::Capacity.into());
                    }
                    self.rejected = Some((channel, None));
                    self.report.refused = self.report.refused.saturating_add(1);
                    return Ok(Step::Rejected {
                        channel,
                        reason: if self.stopping {
                            ProtocolError::Cancelled
                        } else if wrong_port {
                            ProtocolError::Authentication
                        } else {
                            ProtocolError::Capacity
                        },
                    });
                }
                let hard = Self::target(self.limits.idle_timeout);
                let idle = Self::idle(self.clock.clone(), self.limits.idle_timeout)?;
                self.entries.push(Entry {
                    channel,
                    packet: None,
                    working: false,
                    reply: None,
                    write: None,
                    idle: Some(idle),
                    hard,
                    closing: false,
                });
                self.report.accepted = self.report.accepted.saturating_add(1);
                Ok(Step::Activity)
            }
            NativeStep::Data(original) => {
                if self
                    .rejected
                    .is_some_and(|(channel, _)| channel == original.channel())
                {
                    // A late packet on an overflow channel is retired by its
                    // ordered destruction, without granting receive_done.
                    return Ok(Step::Activity);
                }
                let entry = self
                    .entries
                    .iter_mut()
                    .find(|entry| entry.channel == original.channel())
                    .ok_or(ProtocolError::StaleGeneration)?;
                if entry.closing {
                    // Idle/caller shutdown can race actual input while another
                    // channel still owns TX. Keep its destruction scheduled;
                    // this packet must not terminate the other serving owners.
                    return Ok(Step::Activity);
                }
                if entry.packet.is_some() {
                    return Err(ProtocolError::Conflict.into());
                }
                let hard = Self::target(self.limits.idle_timeout);
                let idle = Self::idle(self.clock.clone(), self.limits.idle_timeout)?;
                entry.packet = Some(Packet {
                    original,
                    cursor: 0,
                });
                entry.idle = Some(idle);
                entry.hard = hard;
                Ok(Step::Activity)
            }
            NativeStep::Destroyed(channel) => {
                if let Some(index) = self
                    .entries
                    .iter()
                    .position(|entry| entry.channel == channel)
                {
                    self.entries.swap_remove(index);
                }
                if self
                    .rejected
                    .is_some_and(|(original, _)| original == channel)
                {
                    self.rejected = None;
                }
                Ok(Step::Activity)
            }
            NativeStep::Lost { report, cause, .. } => Ok(self.lost(report, cause)),
            NativeStep::ConnectRetry { error, retry_after } => {
                Ok(Step::ConnectRetry { error, retry_after })
            }
            NativeStep::Unavailable(error) => Err(error.into()),
            NativeStep::WaitDeadline => Ok(Step::WaitDeadline),
            NativeStep::Closed => Ok(Step::Closed),
            NativeStep::Connected(_)
            | NativeStep::Credit { .. }
            | NativeStep::RejectedIncoming { .. }
            | NativeStep::Ignored { .. }
            | NativeStep::Activity { .. }
            | NativeStep::Blocked { .. } => Ok(Step::Activity),
        }
    }
    /// Drive actual source/native work. Dropping a wait retains original lookup,
    /// index job, input receipt, output frame and native exposure cursor.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'id>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Step::Closed));
        }
        self.watch_pending(Self::target(self.limits.write_timeout))?;
        if let Some(step) = self.expire_native()? {
            return Poll::Ready(Ok(step));
        }
        self.poll_alarm(cx);
        if self.quiesced() {
            return Poll::Ready(Ok(Step::Quiesced));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        let mut progress = self.expire(cx)?;
        match self.poll_source(cx) {
            Poll::Ready(Ok(Step::Activity)) => progress = true,
            Poll::Ready(event) => return Poll::Ready(event),
            Poll::Pending => {}
        }
        if let Some(step) = self.expire_native()? {
            return Poll::Ready(Ok(step));
        }
        if self.native_stopped {
            return if self.quiesced() {
                Poll::Ready(Ok(Step::Quiesced))
            } else if progress {
                Poll::Ready(Ok(Step::Activity))
            } else {
                Poll::Pending
            };
        }
        match self.advance()? {
            Some(Step::Activity) => progress = true,
            Some(step) => return Poll::Ready(Ok(step)),
            None => {}
        }
        if self.quiesced() {
            return Poll::Ready(Ok(Step::Quiesced));
        }
        // Native Client can generate and immediately write an automatic port
        // announcement in this poll. Capture its prospective budget BEFORE that
        // poll, then bind the actual returned/pending Transmit without renewing
        // it. Other internally queued frames (such as rejection) use the same
        // rule; no guessed token, port generation or successful write is needed.
        let prospective = Self::target(self.limits.write_timeout);
        self.watch_pending(prospective)?;
        self.poll_alarm(cx);
        if let Some(step) = self.expire_native()? {
            return Poll::Ready(Ok(step));
        }
        let hard = self.native_target().unwrap_or(prospective);
        // An idle MQ owes no frame and needs no periodic write-timeout wakeup.
        // A newly generated automatic frame gets its retained alarm immediately
        // after this bounded poll, before returning Pending to the caller.
        let wait = deadline.into_iter().chain(self.native_target()).min();
        let mut gated = false;
        let native = self.client.poll_guarded(cx, wait, &mut || {
            if Instant::now() >= hard {
                gated = true;
                Err(ProtocolError::Deadline.into())
            } else {
                Ok(())
            }
        });
        match native {
            Poll::Ready(Ok(NativeStep::Written(written))) => {
                // This can be a complete automatic announcement: its original
                // budget was already enforced before the first actual syscall.
                if self.write_bound.is_none() {
                    self.write_bound = Some(WriteBound {
                        transmit: written.transmit,
                        hard: prospective,
                    });
                }
                return Poll::Ready(self.native(NativeStep::Written(written)));
            }
            Poll::Ready(Ok(step @ NativeStep::Lost { .. })) => {
                return Poll::Ready(self.native(step));
            }
            Poll::Ready(Err(error)) if !gated => return Poll::Ready(Err(error.into())),
            _ => {}
        }
        self.watch_pending(prospective)?;
        self.poll_alarm(cx);
        if let Some(step) = self.expire_native()? {
            return Poll::Ready(Ok(step));
        }
        if gated {
            // Provider work used this prospective poll's budget without any
            // admitted TX. Nothing is falsely canceled or globally failed; a
            // later bounded poll may continue the same idle native connection.
            cx.waker().wake_by_ref();
            return Poll::Ready(Ok(Step::Activity));
        }
        match native {
            Poll::Pending if progress => Poll::Ready(Ok(Step::Activity)),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(NativeStep::Blocked { .. })) if !progress => Poll::Pending,
            Poll::Ready(Ok(step)) => Poll::Ready(self.native(step)),
        }
    }
    /// Wait for one original caller-driven step; no task or operation replay.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Step<'id>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
    /// Permanently retire both original owners and all local receipts/replies.
    /// Source close may report native uncertainty; neither result is discarded.
    pub fn close(&mut self) -> Closed<'id> {
        let pending_query = self.job.as_ref().map(|job| RetiredQuery {
            query: job.serial,
            channel: job.channel,
            selection: job.selection,
        });
        let native = self.client.close();
        let source = self.source.close();
        self.entries.clear();
        self.rejected = None;
        self.write_bound = None;
        self.cleanup = None;
        self.alarm = None;
        self.native_stopped = true;
        self.job = None;
        self.closed = true;
        Closed {
            native,
            source,
            pending_query,
        }
    }
}
impl<S: BlockSource> Drop for Server<'_, '_, S> {
    fn drop(&mut self) {
        if !self.closed {
            let _native = self.client.close();
            let _source = self.source.close();
        }
    }
}
