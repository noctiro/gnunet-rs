//! Service-owned periodic publication of actual zero-anonymity UBLOCK rows.
//! Selection, DHT local writing and future republication remain different facts.
use super::super::gap::storage::{Port, Progress as StoreProgress, Terminal};
use gnunet_datastore_host::{Interruption, Outcome as StoreOutcome};
use gnunet_dht_client_host::{Cancel, Client, Completion, OperationId, Outcome};
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use gnunet_types::Error;
use gnunet_wire::official::{
    datastore::{Request, Response},
    dht::{RouteOptions, ipc},
    fs::BlockType,
};
use std::{
    error::Error as StdError,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
/// Actual provider/protocol cause, never a fabricated publication ACK.
pub type Failure = Box<dyn StdError + Send + Sync>;
/// Exact caller-owned selection request storage; response storage is separate.
pub const DATASTORE_REQUEST_BYTES: usize = gnunet_wire::official::datastore::ZERO_ANONYMITY_LEN;
/// Explicit local scheduling and original whole selection/PUT bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Upper interval between selected rows while content is present.
    pub maximum_interval: Duration,
    /// Local scheduling floor; a large estimate cannot create a zero-delay loop.
    pub minimum_interval: Duration,
    /// Target time for one pass over the estimated actual zero-anonymity rows.
    pub republish_period: Duration,
    /// Wait after an actual DATA_END pass with no rows.
    pub empty_interval: Duration,
    /// One original canonical/native budget from DATASTORE admission through PUT.
    pub operation_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            maximum_interval: Duration::from_secs(5),
            minimum_interval: Duration::from_millis(1),
            republish_period: Duration::from_secs(3600),
            empty_interval: Duration::from_secs(300),
            operation_timeout: Duration::from_secs(30),
        }
    }
}
/// Actual local interruption, independent of native/remote outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// The original operation bound elapsed; not remote absence.
    Deadline,
    /// The owning service requested shutdown.
    Shutdown,
}
/// Actual one-slot DATASTORE terminal metadata, without retaining another block copy.
#[derive(Debug)]
pub struct Selection {
    /// Original caller token on the dedicated DATASTORE owner.
    pub token: u64,
    /// Original requested UID cursor.
    pub requested_uid: u64,
    /// Actual typed native completion, including interrupted/unknown outcomes.
    pub outcome: StoreOutcome,
    /// Actual interruption, independent of a late reply.
    pub interruption: Option<Interruption>,
    /// Length of the actual retained response, if any.
    pub reply_bytes: Option<usize>,
    /// Actual source cause, independent of the typed completion.
    pub cause: Option<Failure>,
    /// Independent physical cleanup failure.
    pub cleanup: Option<Failure>,
}
/// Original DHT operation observation. It proves neither remote storage nor replication.
#[derive(Clone, Copy, Debug)]
pub struct PutObservation<'id> {
    /// Original private-client operation identity.
    pub operation: OperationId<'id>,
    /// Actual native terminal notice; absent only for actual BeforeIssue removal.
    pub completion: Option<Completion<'id>>,
    /// Actual cancellation disposition, kept separate from completion.
    pub cancellation: Option<Cancel>,
    /// Original caller interruption, kept separate from a late actual write.
    pub stopped: Option<StopReason>,
}
/// Actual selected row that failed its independent FS validation/resource policy.
#[derive(Clone, Copy, Debug)]
pub struct Rejected {
    /// Actual source row UID.
    pub uid: u64,
    /// Actual source key; this is diagnostic, not accepted block authority.
    pub key: [u8; 64],
    /// Actual validation/resource refusal.
    pub cause: Error,
}
/// Bounded counters and last original outcomes; no history is called live state.
#[derive(Debug, Default)]
pub struct Report<'id> {
    /// Actually admitted original DATASTORE selections.
    pub selections: u64,
    /// Actual matching zero-anonymity DATA rows observed.
    pub rows: u64,
    /// Actual DATA_END replies observed; not proof of backend/network absence.
    pub data_ends: u64,
    /// Actual selected UID reached the end of its integer domain.
    pub uid_exhaustions: u64,
    /// Actual selected rows refused by validation/resource policy.
    pub rejected: u64,
    /// Original local native/canonical operation bounds reached.
    pub timeouts: u64,
    /// Original one-shot PUT intents admitted locally.
    pub puts_admitted: u64,
    /// Actual full local PUT writes, including cancelled writes.
    pub puts_written: u64,
    /// Actual original PUT loss notices; never automatically replayed.
    pub puts_lost: u64,
    /// Actual unissued PUT cancellations.
    pub puts_cancelled_before_issue: u64,
    /// Latest original DATASTORE terminal metadata.
    pub last_selection: Option<Selection>,
    /// Latest actual original DHT terminal/cancellation observation.
    pub last_put: Option<PutObservation<'id>>,
    /// Latest actual rejected source row and cause.
    pub last_rejected: Option<Rejected>,
}
#[derive(Clone, Copy)]
struct Bounds {
    until: u64,
    hard: Instant,
}
#[derive(Clone, Copy)]
struct Selecting {
    token: u64,
    cursor: u64,
    bounds: Bounds,
}
struct Selected {
    frame: OwnedFrame,
    uid: u64,
    bounds: Bounds,
}
struct Flight<'id> {
    operation: OperationId<'id>,
    bounds: Bounds,
    cancellation: Option<Cancel>,
    stopped: Option<StopReason>,
}
/// One original explicit DATASTORE source, sharing the enclosing DHT client's
/// actual one-shot slot and native reader. It starts no task, index or worker.
pub(super) struct Publisher<'id> {
    port: Box<dyn Port + 'id>,
    clock: Arc<dyn RuntimeClock>,
    maximum_us: u64,
    minimum_us: u64,
    republish_us: u64,
    empty_us: u64,
    timeout: Duration,
    timeout_us: u64,
    block_bytes: usize,
    serial: u64,
    cursor: u64,
    count: u64,
    estimate: u64,
    next_due: Option<u64>,
    pending_delay: Option<u64>,
    selecting: Option<Selecting>,
    selected: Option<Selected>,
    flight: Option<Flight<'id>>,
    retire_needed: bool,
    stopping: bool,
    closed: bool,
    report: Report<'id>,
}
fn micros(value: Duration) -> Result<u64, Failure> {
    let value = u64::try_from(value.as_micros()).map_err(|_| Error::Overflow)?;
    if value == 0 || value == u64::MAX {
        return Err(Error::InvalidInput.into());
    }
    Ok(value)
}
impl<'id> Publisher<'id> {
    pub(super) fn new(
        port: Box<dyn Port + 'id>,
        clock: Arc<dyn RuntimeClock>,
        block_bytes: usize,
        limits: Limits,
    ) -> Result<Self, Failure> {
        let maximum_us = micros(limits.maximum_interval)?;
        let minimum_us = micros(limits.minimum_interval)?;
        let republish_us = micros(limits.republish_period)?;
        let empty_us = micros(limits.empty_interval)?;
        let timeout_us = micros(limits.operation_timeout)?;
        if minimum_us > maximum_us
            || port.closed()
            || !Arc::ptr_eq(&clock, &port.clock())
            || Instant::now()
                .checked_add(limits.operation_timeout)
                .is_none()
        {
            return Err(Error::InvalidInput.into());
        }
        Ok(Self {
            port,
            clock,
            maximum_us,
            minimum_us,
            republish_us,
            empty_us,
            timeout: limits.operation_timeout,
            timeout_us,
            block_bytes: block_bytes.min(65535 - ipc::PUT_FIXED_LEN),
            serial: 0,
            cursor: 0,
            count: 0,
            estimate: 0,
            next_due: None,
            pending_delay: None,
            selecting: None,
            selected: None,
            flight: None,
            retire_needed: false,
            stopping: false,
            closed: false,
            report: Report::default(),
        })
    }
    pub(super) const fn report(&self) -> &Report<'id> {
        &self.report
    }
    fn row_delay(&self) -> u64 {
        self.republish_us
            .checked_div(self.estimate)
            .map_or(self.maximum_us, |delay| {
                delay.clamp(self.minimum_us, self.maximum_us)
            })
    }
    fn defer(&mut self, delay: u64) {
        self.next_due = None;
        self.pending_delay = (!self.stopping).then_some(delay);
    }
    fn bounds(&self) -> Option<Bounds> {
        self.selecting
            .map(|s| s.bounds)
            .or_else(|| self.selected.as_ref().map(|s| s.bounds))
            .or_else(|| self.flight.as_ref().map(|f| f.bounds))
    }
    pub(super) fn canonical_target(&self) -> Option<u64> {
        self.bounds()
            .map(|b| b.until)
            .or(if self.stopping || self.closed {
                None
            } else {
                self.next_due
            })
    }
    pub(super) fn native_target(&self) -> Option<Instant> {
        self.bounds().map(|b| b.hard)
    }
    pub(super) fn needs_client(&self) -> bool {
        self.selected.is_some() || self.flight.is_some()
    }
    pub(super) fn needs_retirement(&self) -> bool {
        self.retire_needed
    }
    pub(super) fn quiesced(&self) -> bool {
        self.selecting.is_none() && self.selected.is_none() && self.flight.is_none()
    }
    fn selection_summary(
        &mut self,
        mut terminal: Terminal,
        selecting: Selecting,
    ) -> Result<Option<OwnedFrame>, Failure> {
        if terminal.token != selecting.token {
            return Err(Error::StaleGeneration.into());
        }
        let frame = terminal.frame.take();
        self.report.last_selection = Some(Selection {
            token: terminal.token,
            requested_uid: selecting.cursor,
            outcome: terminal.outcome,
            interruption: terminal.interruption,
            reply_bytes: frame.as_ref().map(OwnedFrame::len),
            cause: terminal.cause,
            cleanup: terminal.cleanup,
        });
        Ok(frame)
    }
    fn cancel_write(
        &mut self,
        client: &mut Client<'id>,
        reason: StopReason,
    ) -> Result<(), Failure> {
        let Some(flight) = &mut self.flight else {
            return Ok(());
        };
        if flight.cancellation.is_some() {
            return Ok(());
        }
        let cancellation = client.cancel(flight.operation)?;
        flight.cancellation = Some(cancellation);
        flight.stopped = Some(reason);
        if cancellation == Cancel::BeforeIssue {
            let flight = self.flight.take().ok_or(Error::Stale)?;
            self.report.last_put = Some(PutObservation {
                operation: flight.operation,
                completion: None,
                cancellation: Some(cancellation),
                stopped: flight.stopped,
            });
            self.report.puts_cancelled_before_issue =
                self.report.puts_cancelled_before_issue.saturating_add(1);
            self.retire_needed = false;
            self.defer(self.row_delay());
        }
        Ok(())
    }
    /// Clock-free original native expiry/retirement. `now` is optional because
    /// native guards always run before a caller samples the canonical clock.
    pub(super) fn guard(
        &mut self,
        now: Option<u64>,
        client: &mut Client<'id>,
    ) -> Result<bool, Failure> {
        let Some(bounds) = self.bounds() else {
            return Ok(false);
        };
        if Instant::now() < bounds.hard && now.is_none_or(|now| now < bounds.until) {
            return Ok(false);
        }
        let first_expiry = self
            .flight
            .as_ref()
            .is_none_or(|flight| flight.stopped != Some(StopReason::Deadline));
        if let Some(selecting) = self.selecting {
            let terminal = self.port.cancel_retained(selecting.token)?;
            self.selecting = None;
            let _actual = self.selection_summary(terminal, selecting)?;
            self.defer(self.maximum_us);
        }
        if self.selected.take().is_some() {
            self.defer(self.row_delay());
        }
        self.cancel_write(client, StopReason::Deadline)?;
        if self.flight.is_some() {
            self.retire_needed = true;
        }
        if first_expiry {
            self.report.timeouts = self.report.timeouts.saturating_add(1);
        }
        Ok(first_expiry)
    }
    pub(super) fn completed(&mut self, completion: Completion<'id>) -> Result<(), Failure> {
        let flight = self.flight.take().ok_or(Error::StaleGeneration)?;
        if completion.operation != flight.operation {
            self.flight = Some(flight);
            return Err(Error::StaleGeneration.into());
        }
        match completion.outcome {
            Outcome::Written | Outcome::CanceledWritten => {
                self.report.puts_written = self.report.puts_written.saturating_add(1)
            }
            Outcome::Lost | Outcome::CanceledLost => {
                self.report.puts_lost = self.report.puts_lost.saturating_add(1)
            }
        }
        self.report.last_put = Some(PutObservation {
            operation: flight.operation,
            completion: Some(completion),
            cancellation: flight.cancellation,
            stopped: flight.stopped,
        });
        self.retire_needed = false;
        // A new round is authorized only by its later new actual DS selection;
        // no lost/unknown original PUT is retained for retransmission.
        self.defer(self.row_delay());
        Ok(())
    }
    fn consume_selection(&mut self, terminal: Terminal) -> Result<(), Failure> {
        let selecting = self.selecting.take().ok_or(Error::StaleGeneration)?;
        let outcome = terminal.outcome;
        let interruption = terminal.interruption;
        let frame = self.selection_summary(terminal, selecting)?;
        if self.stopping {
            return Ok(());
        }
        if interruption.is_some()
            || !matches!(outcome, StoreOutcome::Data { .. } | StoreOutcome::NotFound)
        {
            self.defer(self.maximum_us);
            return Ok(());
        }
        let frame = frame.ok_or(Error::Malformed)?;
        match Response::decode(frame.bytes())? {
            Response::End if outcome == StoreOutcome::NotFound => {
                self.report.data_ends = self.report.data_ends.saturating_add(1);
                self.estimate = self.count;
                self.count = 0;
                self.cursor = 0;
                self.defer(if self.estimate == 0 {
                    self.empty_us
                } else {
                    self.row_delay()
                });
            }
            Response::Data(data) if outcome == (StoreOutcome::Data { uid: data.uid }) => {
                if data.kind != BlockType::UBLOCK.value()
                    || data.anonymity != 0
                    || data.uid < selecting.cursor
                {
                    return Err(Error::Authentication.into());
                }
                self.report.rows = self.report.rows.saturating_add(1);
                self.count = self.count.saturating_add(1);
                self.estimate = self.estimate.max(self.count);
                if let Some(next) = data.uid.checked_add(1) {
                    self.cursor = next;
                } else {
                    // Exhausting the UID number space is not a fabricated END.
                    self.report.uid_exhaustions = self.report.uid_exhaustions.saturating_add(1);
                    self.cursor = 0;
                    self.count = 0;
                }
                self.selected = Some(Selected {
                    uid: data.uid,
                    frame,
                    bounds: selecting.bounds,
                });
            }
            _ => return Err(Error::Malformed.into()),
        }
        Ok(())
    }
    fn reject(&mut self, uid: u64, key: [u8; 64], cause: Error) {
        self.report.rejected = self.report.rejected.saturating_add(1);
        self.report.last_rejected = Some(Rejected { uid, key, cause });
        self.selected = None;
        self.defer(self.row_delay());
    }
    fn submit_selected(&mut self, client: &mut Client<'id>) -> Result<bool, Failure> {
        let Some(selected) = &self.selected else {
            return Ok(false);
        };
        if client.epoch().is_none() {
            return Ok(false);
        }
        let Response::Data(data) = Response::decode(selected.frame.bytes())? else {
            return Err(Error::Malformed.into());
        };
        let uid = selected.uid;
        let key = *data.key;
        if data.kind != BlockType::UBLOCK.value() || data.anonymity != 0 {
            return Err(Error::Authentication.into());
        }
        if data.value.len() > self.block_bytes {
            self.reject(uid, key, Error::TooLarge);
            return Ok(true);
        }
        match gnunet_fs::ublock::verify_envelope(data.value, &key) {
            Ok(()) => {}
            Err(cause @ (Error::Malformed | Error::Authentication)) => {
                self.reject(uid, key, cause);
                return Ok(true);
            }
            Err(cause) => return Err(cause.into()),
        }
        let now = self.clock.sample()?.now.as_micros();
        if Instant::now() >= selected.bounds.hard || now >= selected.bounds.until {
            self.selected = None;
            self.report.timeouts = self.report.timeouts.saturating_add(1);
            self.defer(self.row_delay());
            return Ok(true);
        }
        if data.expiration.as_micros() < now {
            self.reject(uid, key, Error::InvalidInput);
            return Ok(true);
        }
        let operation = client.put(ipc::Put {
            block_type: BlockType::UBLOCK.value(),
            options: u32::from(RouteOptions::DEMULTIPLEX_EVERYWHERE.bits()),
            replication: 5,
            expiration: data.expiration,
            key: &key,
            payload: data.value,
        })?;
        let selected = self.selected.take().ok_or(Error::Stale)?;
        self.flight = Some(Flight {
            operation,
            bounds: selected.bounds,
            cancellation: None,
            stopped: None,
        });
        self.report.puts_admitted = self.report.puts_admitted.saturating_add(1);
        Ok(true)
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        client: &mut Client<'id>,
    ) -> Poll<Result<(), Failure>> {
        if self.closed {
            return Poll::Pending;
        }
        if let Some(selecting) = self.selecting {
            return match self.port.poll_until(cx, selecting.bounds.hard) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(cause)) => Poll::Ready(Err(cause)),
                Poll::Ready(Ok(StoreProgress::Activity)) => Poll::Ready(Ok(())),
                Poll::Ready(Ok(StoreProgress::Complete(terminal))) => {
                    self.consume_selection(terminal)?;
                    Poll::Ready(Ok(()))
                }
            };
        }
        if self.stopping || self.flight.is_some() {
            return Poll::Pending;
        }
        if self.selected.is_some() {
            return if self.submit_selected(client)? {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }
        let anchor = Instant::now();
        let now = self.clock.sample()?.now.as_micros();
        if let Some(delay) = self.pending_delay.take() {
            self.next_due = Some(
                now.checked_add(delay)
                    .filter(|n| *n != u64::MAX)
                    .ok_or(Error::Overflow)?,
            );
            return Poll::Ready(Ok(()));
        }
        if self.next_due.is_some_and(|due| now < due) {
            return Poll::Pending;
        }
        let hard = anchor.checked_add(self.timeout).ok_or(Error::Overflow)?;
        if Instant::now() >= hard {
            self.report.timeouts = self.report.timeouts.saturating_add(1);
            self.defer(self.maximum_us);
            return Poll::Ready(Ok(()));
        }
        let until = now
            .checked_add(self.timeout_us)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Overflow)?;
        let token = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.port.start(
            token,
            Request::ZeroAnonymity {
                kind: BlockType::UBLOCK.value(),
                next_uid: self.cursor,
            },
        )?;
        self.serial = token;
        self.selecting = Some(Selecting {
            token,
            cursor: self.cursor,
            bounds: Bounds { until, hard },
        });
        self.next_due = None;
        self.report.selections = self.report.selections.saturating_add(1);
        Poll::Ready(Ok(()))
    }
    pub(super) fn request_shutdown(&mut self, client: &mut Client<'id>) -> Result<(), Failure> {
        if self.stopping || self.closed {
            return Ok(());
        }
        self.stopping = true;
        self.next_due = None;
        self.pending_delay = None;
        self.selected = None;
        // Independent native owners both receive their original cleanup request.
        let port = self.port.request_retire();
        let write = self.cancel_write(client, StopReason::Shutdown);
        match (port.err(), write.err()) {
            (None, None) => Ok(()),
            (Some(cause), None) | (None, Some(cause)) => Err(cause),
            (Some(port), Some(write)) => Err(Box::new(ShutdownFailures { port, write })),
        }
    }
    pub(super) fn close_source(&mut self) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        let result = self.port.close();
        self.closed = true;
        self.stopping = true;
        self.next_due = None;
        self.pending_delay = None;
        self.selected = None;
        match (result, self.selecting.take()) {
            (Ok(Some(terminal)), Some(selecting)) => {
                let _actual = self.selection_summary(terminal, selecting)?;
                Ok(())
            }
            (Ok(None), None) => Ok(()),
            (Ok(Some(_)), None) | (Ok(None), Some(_)) => Err(Error::StaleGeneration.into()),
            (Err(cause), _) => Err(cause),
        }
    }
}

#[derive(Debug)]
struct ShutdownFailures {
    port: Failure,
    write: Failure,
}
impl std::fmt::Display for ShutdownFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FS DHT publication shutdown source: {}; independent PUT cancellation: {}",
            self.port, self.write
        )
    }
}
impl StdError for ShutdownFailures {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.port.as_ref())
    }
}
