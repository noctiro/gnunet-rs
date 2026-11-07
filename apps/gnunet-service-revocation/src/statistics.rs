//! Actual official STATISTICS owner for the six monotonic REVOCATION contributions to five official keys.
//! Connect/disconnect coordinates retain separate positive totals; coordinate1
//! is emitted as a checked negative UPDATE. One pending UPDATE excludes coalescing and other setters. Local whole-write
//! facts are separate from remote processing/replication/storage confirmation.
use gnunet_client::statistics_handle::{
    ConnectionEpoch, DestroyOutcome, DestroyReport, GetFlow, SetterAdmission,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    IpcError,
    handle::{self, StatisticsHandle},
};
use gnunet_revocation_host::server::{METRIC_NAMES, Metrics};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
type Handle<'id> = StatisticsHandle<'id, 2, 128, 1, 1, 2>;
const COUNT: usize = 6;
/// Explicit original native operation and per-frame resource bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Fixed native limit for each original nonpersistent UPDATE.
    pub operation: Duration,
    /// Actual complete native frame capacity, from128 through4096.
    pub max_frame_bytes: usize,
    /// Fair native write quantum, positive and no larger than frame capacity.
    pub write_chunk_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operation: Duration::from_secs(5),
            max_frame_bytes: 256,
            write_chunk_bytes: 256,
        }
    }
}
impl Limits {
    /// Check this finite resource policy without creating any source/socket.
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    pub fn validate(self) -> Result<(), Failure> {
        if self.operation.is_zero()
            || self.operation.as_micros() >= u64::MAX as u128
            || Instant::now().checked_add(self.operation).is_none()
            || !(128..=4096).contains(&self.max_frame_bytes)
            || self.write_chunk_bytes == 0
            || self.write_chunk_bytes > self.max_frame_bytes
        {
            return Err(Failure::new(Cause::InvalidLimits));
        }
        Ok(())
    }
}
/// Original error/fence reason, with no invented wire outcome.
pub enum Cause {
    /// Actual selected STATISTICS owner refusal, possibly after admission.
    Ipc(IpcError),
    /// Original native operation or final-drain hard bound expired.
    Deadline,
    /// Real original connected MQ was retired; no old mutation is replayed.
    ConnectionLost {
        /// Actual retired native epoch, for diagnostics only.
        epoch: u64,
        /// Original native classified cause.
        reason: gnunet_types::Error,
    },
    /// The shared native owner reported a genuine failed/discarding final drain.
    Destroy {
        /// Exact actual report, not a synthesized processing acknowledgement.
        report: DestroyReport,
    },
    /// A caller supplied another service's/reset counters to this original publisher.
    CounterRegression {
        /// Original official counter index in METRIC_NAMES.
        counter: usize,
    },
    /// Source clock was not the same exact Arc as the original service clock.
    ClockIdentity,
    /// Explicit invalid finite configuration.
    InvalidLimits,
    /// The exclusive single-mutation lifecycle was violated.
    Invariant,
}
impl fmt::Debug for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipc(error) => f.debug_tuple("Ipc").field(error).finish(),
            Self::Deadline => f.write_str("Deadline"),
            Self::ConnectionLost { epoch, reason } => f
                .debug_struct("ConnectionLost")
                .field("epoch", epoch)
                .field("reason", reason)
                .finish(),
            Self::Destroy { report } => f.debug_struct("Destroy").field("report", report).finish(),
            Self::CounterRegression { counter } => f
                .debug_struct("CounterRegression")
                .field("counter", counter)
                .finish(),
            Self::ClockIdentity => f.write_str("ClockIdentity"),
            Self::InvalidLimits => f.write_str("InvalidLimits"),
            Self::Invariant => f.write_str("Invariant"),
        }
    }
}
/// Original failure plus independent native/error-after-callback/cleanup facts.
#[derive(Debug)]
pub struct Failure {
    /// First actual refusal or independently reached original native deadline.
    pub cause: Cause,
    /// An additional native error after the original callback/fence reason.
    pub subsequent: Option<IpcError>,
    /// Actual original OS error retained separately by the native owner.
    pub transport: Option<io::Error>,
    /// Independent error beginning actual physical owner retirement.
    pub cleanup: Option<IpcError>,
}
impl Failure {
    fn new(cause: Cause) -> Self {
        Self {
            cause,
            subsequent: None,
            transport: None,
            cleanup: None,
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "REVOCATION statistics original={:?}; subsequent={:?}; transport={:?}; cleanup={:?}",
            self.cause, self.subsequent, self.transport, self.cleanup
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Cause::Ipc(error) => Some(error),
            _ => self
                .subsequent
                .as_ref()
                .map(|e| e as &dyn std::error::Error)
                .or_else(|| self.transport.as_ref().map(|e| e as &dyn std::error::Error))
                .or_else(|| self.cleanup.as_ref().map(|e| e as &dyn std::error::Error)),
        }
    }
}
/// Metadata of the one original mutation. These values confer no remote receipt.
#[derive(Clone, Copy)]
pub struct Pending {
    /// Exact official counter coordinate.
    pub counter: usize,
    /// Positive relative value, already checked to fit signed i64.
    pub delta: u64,
    /// Original unchanged native hard target.
    pub hard: Instant,
    /// Original virtual native epoch if it already exists.
    pub epoch: Option<u64>,
}
impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("counter", &self.counter)
            .field("delta", &self.delta)
            .field("hard", &self.hard)
            .field("epoch", &self.epoch)
            .finish()
    }
}
/// Final/current factual publisher accounting, never remote accepted/durable.
#[derive(Clone, Copy)]
pub struct Report {
    /// Initial Core snapshot deliberately excluded by this new source intent.
    pub baseline: [u64; COUNT],
    /// Latest actual same-service cumulative snapshot supplied by the caller.
    pub observed: [u64; COUNT],
    /// Exact deltas whose original same-epoch native frames were wholly written.
    pub local_written: [u64; COUNT],
    /// Observed deltas never admitted to this owner's pending UPDATE; excludes
    /// both original pending and unknown deltas. Computed without any IO.
    pub unsubmitted: [u64; COUNT],
    /// Retired pending deltas which may or may not have reached the service.
    /// These are not replayed automatically, even on a new native epoch.
    pub unknown: [u64; COUNT],
    /// Original pending mutation, if actual local transfer has not settled.
    pub pending: Option<Pending>,
    /// Last actual connected native epoch, unrelated to a peer identity.
    pub epoch: Option<u64>,
    /// Actual shared native destruction report, if that event was driven.
    pub destroyed: Option<DestroyReport>,
    /// Official statistics.DISABLE prevented creation of a source.
    pub disabled: bool,
    /// Original physical native owner has been retired/dropped, or was disabled.
    pub closed: bool,
    /// An actual failure permanently fenced this publisher allocation.
    pub fenced: bool,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Report")
            .field("baseline", &self.baseline)
            .field("observed", &self.observed)
            .field("local_written", &self.local_written)
            .field("unsubmitted", &self.unsubmitted)
            .field("unknown", &self.unknown)
            .field("pending", &self.pending)
            .field("epoch", &self.epoch)
            .field("destroyed", &self.destroyed)
            .field("disabled", &self.disabled)
            .field("closed", &self.closed)
            .field("fenced", &self.fenced)
            .finish()
    }
}
/// One bounded actual scheduling fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One original native IO/admission/destruction step progressed.
    Activity,
    /// The ONE original pending delta's frame was actually wholly written.
    Written {
        /// Exact official counter index.
        counter: usize,
        /// Unsigned magnitude of its original signed relative UPDATE.
        delta: u64,
    },
    /// Actual original owner is physically retired; not a processing ACK.
    Closed,
}
struct Mutation<'id> {
    info: Pending,
    epoch: Option<ConnectionEpoch<'id>>,
}
#[derive(Default)]
struct Events<'id> {
    connected: Option<ConnectionEpoch<'id>>,
    lost: Option<(ConnectionEpoch<'id>, gnunet_types::Error)>,
    destroyed: Option<DestroyReport>,
}
/// One actual reusable native STATISTICS handle, without a new client or Resolver.
/// There is at most one outstanding UPDATE and no GET/WATCH/other mutation source.
/// A lost/error source is permanently fenced; it is never recreated to replay an
/// uncertain relative delta. Explicit new publishers start from an explicit fresh
/// current baseline, rather than claiming the old delta was delivered.
pub struct Owner<'id> {
    owner: Option<Handle<'id>>,
    limits: Limits,
    position: [u64; COUNT],
    desired: [u64; COUNT],
    cursor: usize,
    pending: Option<Mutation<'id>>,
    connected: Option<ConnectionEpoch<'id>>,
    operation_alarm: Option<Pin<Box<Sleep>>>,
    closing: Option<Instant>,
    close_alarm: Option<Pin<Box<Sleep>>>,
    destroying: bool,
    report: Report,
}
impl<'id> Owner<'id> {
    /// Keep the original live config, Resolver and SAME actual clock Arc.
    /// `initial` belongs to this original service and establishes a non-delivery
    /// baseline, including on an explicit fresh publisher after a prior loss.
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    pub fn new(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        initial: Metrics,
        limits: Limits,
    ) -> Result<Self, Failure> {
        limits.validate()?;
        let source = EndpointSource::live(live.clone(), b"statistics", resolution.clone());
        if !Arc::ptr_eq(&source.clock(), &clock) {
            return Err(Failure::new(Cause::ClockIdentity));
        }
        let owner = Handle::from_live_config(
            instance,
            live,
            resolution,
            b"revocation",
            handle::Limits {
                max_frame_bytes: limits.max_frame_bytes,
                write_chunk_bytes: limits.write_chunk_bytes,
            },
        )
        .map_err(|e| Failure::new(Cause::Ipc(e)))?;
        let baseline = *initial.values();
        let disabled = owner.is_none();
        Ok(Self {
            owner,
            limits,
            position: baseline,
            desired: baseline,
            cursor: 0,
            pending: None,
            connected: None,
            operation_alarm: None,
            closing: None,
            close_alarm: None,
            destroying: false,
            report: Report {
                baseline,
                observed: baseline,
                local_written: [0; COUNT],
                unsubmitted: [0; COUNT],
                unknown: [0; COUNT],
                pending: None,
                epoch: None,
                destroyed: None,
                disabled,
                closed: disabled,
                fenced: false,
            },
        })
    }
    /// Current original factual accounting; no remote execution is inferred.
    #[must_use]
    pub fn report(&self) -> Report {
        let mut report = self.report;
        for (i, value) in report.unsubmitted.iter_mut().enumerate() {
            let pending = report
                .pending
                .filter(|p| p.counter == i)
                .map_or(0, |p| p.delta);
            *value = report.observed[i]
                .saturating_sub(self.position[i])
                .saturating_sub(report.unknown[i])
                .saturating_sub(pending);
        }
        report
    }
    /// True only when no actual native owner remains, including official disable.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.report.closed
    }
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    fn snapshot(&mut self, metrics: Metrics) -> Result<(), Failure> {
        let values = *metrics.values();
        if let Some(counter) = values
            .iter()
            .zip(self.report.observed)
            .position(|(now, old)| *now < old)
        {
            return Err(self.fail(Failure::new(Cause::CounterRegression { counter })));
        }
        self.report.observed = values;
        self.desired = values;
        Ok(())
    }
    /// Supply actual service counters and admit at most ONE nonpersistent
    /// signed delta (negative only for the disconnect contribution). A queued mutation does not advance position/local_written.
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    pub fn refresh(&mut self, metrics: Metrics) -> Result<bool, Failure> {
        if self.report.closed || self.closing.is_some() {
            return Ok(false);
        }
        self.snapshot(metrics)?;
        self.admit()
    }
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    fn admit(&mut self) -> Result<bool, Failure> {
        if self.pending.is_some() || self.destroying || self.report.closed {
            return Ok(false);
        }
        let Some(owner) = &self.owner else {
            return Err(self.fail(Failure::new(Cause::Invariant)));
        };
        if !owner.is_idle() || owner.is_closed() {
            return Err(self.fail(Failure::new(Cause::Invariant)));
        }
        let mut selected = None;
        for offset in 0..COUNT {
            let i = (self.cursor + offset) % COUNT;
            let Some(mut delta) = self.desired[i].checked_sub(self.position[i]) else {
                return Err(self.fail(Failure::new(Cause::Invariant)));
            };
            if i == 1 {
                // The remote gauge is unsigned. Its FIFO must never receive
                // more negative contributions than THIS source has already
                // whole-written as positive contributions, even when newer
                // connects/disconnects arrive while an earlier UPDATE waits.
                let Some(credit) =
                    self.report.local_written[0].checked_sub(self.report.local_written[1])
                else {
                    return Err(self.fail(Failure::new(Cause::Invariant)));
                };
                delta = delta.min(credit);
            }
            if delta != 0 {
                selected = Some((i, delta.min(i64::MAX as u64)));
                break;
            }
        }
        let Some((counter, delta)) = selected else {
            return Ok(false);
        };
        let now = Instant::now();
        if self.closing.is_some_and(|hard| now >= hard) {
            return Err(self.fail(Failure::new(Cause::Deadline)));
        }
        let Some(hard) = now.checked_add(self.limits.operation) else {
            return Err(self.fail(Failure::new(Cause::InvalidLimits)));
        };
        let hard = self.closing.map_or(hard, |closing| hard.min(closing));
        if let Some(alarm) = &mut self.operation_alarm {
            alarm.as_mut().reset(hard);
        } else {
            self.operation_alarm = Some(Box::pin(tokio::time::sleep_until(hard)));
        }
        let epoch = self.owner.as_ref().and_then(Handle::connection_epoch);
        let info = Pending {
            counter,
            delta,
            hard,
            epoch: epoch.map(ConnectionEpoch::value),
        };
        // Retain original intent BEFORE the shared setter: it may fail AFTER
        // admitting an actual envelope, e.g. at a canonical-clock boundary.
        self.pending = Some(Mutation { info, epoch });
        self.report.pending = Some(info);
        let signed = match i64::try_from(delta) {
            Ok(value) => {
                if counter == 1 {
                    -value
                } else {
                    value
                }
            }
            Err(_) => return Err(self.fail(Failure::new(Cause::Invariant))),
        };
        let Some(owner) = self.owner.as_mut() else {
            return Err(self.fail(Failure::new(Cause::Invariant)));
        };
        let result = owner.update(METRIC_NAMES[counter], signed, false);
        match result {
            Ok(SetterAdmission::Queued) => {
                let epoch = self.owner.as_ref().and_then(Handle::connection_epoch);
                if let Some(p) = &mut self.pending {
                    p.epoch = epoch;
                    p.info.epoch = epoch.map(ConnectionEpoch::value);
                    self.report.pending = Some(p.info);
                }
                self.cursor = (counter + 1) % COUNT;
                Ok(true)
            }
            Ok(_) => Err(self.fail(Failure::new(Cause::Invariant))),
            Err(error) => Err(self.fail(Failure::new(Cause::Ipc(error)))),
        }
    }
    /// Original native deadlines FIRST. This registers/checks only local Sleep
    /// owners; no source sampling, Resolver access or socket IO occurs here.
    /// Failure uses immediate destroy(false)+Drop, which physically retires the
    /// original source and does not sample its canonical clock after Core closes.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>> {
        if self.report.closed {
            return Poll::Pending;
        }
        let operation = self.pending.is_some()
            && self
                .operation_alarm
                .as_mut()
                .is_some_and(|a| a.as_mut().poll(cx).is_ready());
        let closing = self
            .close_alarm
            .as_mut()
            .is_some_and(|a| a.as_mut().poll(cx).is_ready());
        if operation || closing {
            Poll::Ready(Err(self.fail(Failure::new(Cause::Deadline))))
        } else {
            Poll::Pending
        }
    }
    /// Poll actual same-source native IO. Lost/error paths fence BEFORE any idle
    /// observation can be interpreted as an original successful whole write.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress, Failure>> {
        if let Poll::Ready(result) = self.poll_native_guard(cx) {
            return Poll::Ready(result);
        }
        if self.report.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        let admitted = match self.admit() {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        // A newly admitted mutation must register its ORIGINAL native hard in
        // this very poll before a canonical-clock/native future can stay Pending.
        if let Poll::Ready(result) = self.poll_native_guard(cx) {
            return Poll::Ready(result);
        }

        if self.closing.is_some()
            && !self.destroying
            && self.pending.is_none()
            && self.desired == self.position
        {
            self.destroying = true;
            if let Some(owner) = &mut self.owner
                && let Err(error) = owner.destroy(true)
            {
                return Poll::Ready(Err(self.fail(Failure::new(Cause::Ipc(error)))));
            }
        }
        if self.pending.is_none() && !self.destroying {
            return if admitted {
                Poll::Ready(Ok(Progress::Activity))
            } else {
                Poll::Pending
            };
        }
        let mut events = Events::default();
        let result = {
            let Some(owner) = &mut self.owner else {
                return Poll::Ready(Err(self.fail(Failure::new(Cause::Invariant))));
            };
            let mut driving = std::pin::pin!(owner.drive(wait, |event, _context| {
                match event {
                    handle::Event::Connected(epoch) => events.connected = Some(epoch),
                    handle::Event::ConnectionLost { epoch, cause } => {
                        events.lost = Some((epoch, cause))
                    }
                    handle::Event::Destroyed(report) => events.destroyed = Some(report),
                    _ => {}
                }
                GetFlow::Continue
            }));
            driving.as_mut().poll(cx)
        };
        if let Some((epoch, reason)) = events.lost {
            let mut failure = Failure::new(Cause::ConnectionLost {
                epoch: epoch.value(),
                reason,
            });
            if let Poll::Ready(Err(error)) = result {
                failure.subsequent = Some(error);
            }
            return Poll::Ready(Err(self.fail(failure)));
        }
        if let Poll::Ready(Err(error)) = result {
            return Poll::Ready(Err(self.fail(Failure::new(Cause::Ipc(error)))));
        }
        if let Some(epoch) = events.connected {
            if self.connected.is_some_and(|old| old != epoch)
                || self
                    .pending
                    .as_ref()
                    .and_then(|p| p.epoch)
                    .is_some_and(|old| old != epoch)
            {
                return Poll::Ready(Err(self.fail(Failure::new(Cause::Invariant))));
            }
            self.connected = Some(epoch);
            self.report.epoch = Some(epoch.value());
            if let Some(p) = &mut self.pending {
                p.epoch = Some(epoch);
                p.info.epoch = Some(epoch.value());
                self.report.pending = Some(p.info);
            }
        }
        if let Some(report) = events.destroyed {
            self.report.destroyed = Some(report);
            // Destroy can clear queues without whole-writing a setter. Never
            // reclassify this as delivery, even if the resulting statistics Core is idle.
            if self.pending.is_some() {
                self.burn_pending();
                self.report.fenced = true;
            }
            if report.queued_mutations_discarded != 0
                || matches!(
                    report.outcome,
                    DestroyOutcome::Deadline | DestroyOutcome::ConnectionLost
                )
            {
                return Poll::Ready(Err(self.fail(Failure::new(Cause::Destroy { report }))));
            }
            self.owner = None;
            self.report.closed = true;
            return Poll::Ready(Ok(Progress::Closed));
        }
        if !self.destroying
            && let Some(p) = &self.pending
        {
            let same =
                self.owner.as_ref().is_some_and(|o| {
                    !o.is_closed() && o.is_idle() && o.connection_epoch() == p.epoch
                }) && p.epoch.is_some()
                    && p.epoch == self.connected;
            if same {
                let counter = p.info.counter;
                let delta = p.info.delta;
                let Some(position) = self.position[counter]
                    .checked_add(delta)
                    .filter(|n| *n <= self.desired[counter])
                else {
                    return Poll::Ready(Err(self.fail(Failure::new(Cause::Invariant))));
                };
                let Some(written) = self.report.local_written[counter].checked_add(delta) else {
                    return Poll::Ready(Err(self.fail(Failure::new(Cause::Invariant))));
                };
                self.position[counter] = position;
                self.report.local_written[counter] = written;
                self.pending = None;
                self.report.pending = None;
                return Poll::Ready(Ok(Progress::Written { counter, delta }));
            }
        }
        match result {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Progress::Activity)),
            Poll::Pending if admitted => Poll::Ready(Ok(Progress::Activity)),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(Failure::new(Cause::Ipc(error))))),
        }
    }
    /// Freeze one final actual service snapshot and one unchanged native drain hard
    /// target. Repeat calls neither replace counters nor extend that grace.
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    pub fn begin_close(&mut self, metrics: Metrics, grace: Duration) -> Result<(), Failure> {
        if self.report.closed || self.closing.is_some() {
            return Ok(());
        }
        if grace.is_zero() || grace.as_micros() >= u64::MAX as u128 {
            return Err(self.fail(Failure::new(Cause::InvalidLimits)));
        }
        let Some(hard) = Instant::now().checked_add(grace) else {
            return Err(self.fail(Failure::new(Cause::InvalidLimits)));
        };
        self.snapshot(metrics)?;
        self.closing = Some(hard);
        self.close_alarm = Some(Box::pin(tokio::time::sleep_until(hard)));
        Ok(())
    }
    /// Explicit clock-free forced retirement when another original source has
    /// already failed. Pending relative work remains Unknown and is never replayed.
    /// Caller retains its independent original failure; this returns only an actual
    /// failure of retiring this same statistics owner, not a fabricated cancellation.
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    pub fn abort(&mut self) -> Result<(), Failure> {
        if self.report.closed {
            return Ok(());
        }
        self.burn_pending();
        self.report.fenced = true;
        let result = if let Some(mut owner) = self.owner.take() {
            let transport = owner.take_io_error();
            if owner.is_closed() {
                Ok(())
            } else {
                match owner.destroy(false) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let mut failure = Failure::new(Cause::Ipc(error));
                        failure.transport = transport;
                        Err(failure)
                    }
                }
            }
        } else {
            Ok(())
        };
        self.report.closed = true;
        result
    }
    fn burn_pending(&mut self) {
        if let Some(p) = self.pending.take() {
            self.report.unknown[p.info.counter] =
                self.report.unknown[p.info.counter].saturating_add(p.info.delta);
        }
        self.report.pending = None;
    }
    fn fail(&mut self, mut failure: Failure) -> Failure {
        self.burn_pending();
        self.report.fenced = true;
        if let Some(mut owner) = self.owner.take() {
            failure.transport = owner.take_io_error();
            if failure.subsequent.is_none() {
                failure.subsequent = owner.take_connect_error();
            }
            if !owner.is_closed() {
                failure.cleanup = owner.destroy(false).err();
            }
        }
        self.report.closed = true;
        failure
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        let _unobserved_retirement = self.abort();
    }
}
