//! Shared bounded original-source STATISTICS counter/gauge producer.
//! Reuses the admitted native handle; no new runtime, task, protocol or recovery owner.
use crate::{
    IpcError,
    handle::{self, StatisticsHandle},
};
use gnunet_client::statistics_handle::{
    ConnectionEpoch, DestroyOutcome, DestroyReport, GetFlow, SetterAdmission,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
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
/// Meaning of one source coordinate; no mutation grants a remote receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A nondecreasing actual source total, emitted as positive signed chunks.
    Counter,
    /// A current inventory value, emitted with an absolute official SET.
    Gauge,
}
/// Fixed official name, operation kind and persistence request of one metric.
#[derive(Clone, Copy, Debug)]
pub struct Metric {
    /// Exact official C-string bytes, without the trailing NUL.
    pub name: &'static [u8],
    /// Source value meaning and official SET/UPDATE selection.
    pub kind: Kind,
    /// Official wire persistence flag, never a storage acknowledgement.
    pub persistent: bool,
}
impl Metric {
    /// Define a cumulative positive counter.
    pub const fn counter(name: &'static [u8], persistent: bool) -> Self {
        Self {
            name,
            kind: Kind::Counter,
            persistent,
        }
    }
    /// Define an absolute current gauge, which may increase or decrease.
    pub const fn gauge(name: &'static [u8], persistent: bool) -> Self {
        Self {
            name,
            kind: Kind::Gauge,
            persistent,
        }
    }
}
/// A diagnostic snapshot supplied by the original business owner.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot<const N: usize> {
    /// Real cumulative totals/current gauge values in the fixed metric order.
    pub values: [u64; N],
    /// The business observer could not represent an actual observation exactly.
    pub overflowed: bool,
}
impl<const N: usize> Snapshot<N> {
    /// Preserve actual source values and their independent overflow observation.
    pub const fn new(values: [u64; N], overflowed: bool) -> Self {
        Self { values, overflowed }
    }
}
/// Once-selected metadata and bounds for this one original producer allocation.
pub struct Configuration<const N: usize> {
    /// Exact official subsystem name.
    pub subsystem: &'static [u8],
    /// Immutable metric definitions; this allocation never retags an index.
    pub metrics: &'static [Metric; N],
    /// Explicit current baseline. Prior counter observations are not replayed;
    /// gauges still emit their actual initial absolute value, including zero.
    pub initial: Snapshot<N>,
    /// Finite native mutation resources and lifetime.
    pub limits: Limits,
}
/// Explicit original native operation and per-frame resource bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Fixed native limit for each original SET or UPDATE.
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
#[derive(Debug)]
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
    /// A caller supplied another Core's/reset counters to this original publisher.
    CounterRegression {
        /// Original official counter index in the fixed metric definitions.
        counter: usize,
    },
    /// Source clock was not the same exact Arc as the original service clock.
    ClockIdentity,
    /// Explicit invalid finite configuration.
    InvalidLimits,
    /// Actual callback counters/time exceeded finite representation.
    ObservationOverflow,
    /// The exclusive single-mutation lifecycle was violated.
    Invariant,
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
    /// Independent original failure while selecting or opening the connection.
    pub connection: Option<IpcError>,
    /// Independent error beginning actual physical owner retirement.
    pub cleanup: Option<IpcError>,
}
impl Failure {
    fn new(cause: Cause) -> Self {
        Self {
            cause,
            subsequent: None,
            transport: None,
            connection: None,
            cleanup: None,
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "STATISTICS original={:?}; subsequent={:?}; transport={:?}; connection={:?}; cleanup={:?}",
            self.cause, self.subsequent, self.transport, self.connection, self.cleanup
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
                .or_else(|| {
                    self.connection
                        .as_ref()
                        .map(|e| e as &dyn std::error::Error)
                })
                .or_else(|| self.cleanup.as_ref().map(|e| e as &dyn std::error::Error)),
        }
    }
}
/// Exact value of one original official setter, fixed at admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value {
    /// Positive relative chunk and the corresponding original source coordinate.
    Delta {
        /// Positive amount no larger than i64::MAX.
        amount: u64,
        /// Baseline/previous source coordinate plus that exact chunk.
        target: u64,
    },
    /// Absolute gauge value; a later snapshot cannot change this frame.
    Absolute(u64),
}
impl Value {
    fn target(self) -> u64 {
        match self {
            Self::Delta { target, .. } | Self::Absolute(target) => target,
        }
    }
}
/// Original one-frame intent. Epoch is diagnostic, never a peer identity.
#[derive(Clone, Copy, Debug)]
pub struct Pending {
    /// Exact immutable metric index.
    pub counter: usize,
    /// Original unchanged wire setter value.
    pub value: Value,
    /// Original fixed native target, intersected with the final drain target.
    pub hard: Instant,
    /// Actual connected native epoch, if it has already been observed.
    pub epoch: Option<u64>,
}
/// Original factual accounting; no field proves remote processing/persistence.
#[derive(Clone, Copy, Debug)]
pub struct Report<const N: usize> {
    /// Actual explicit source baseline; counter history at/before it is excluded.
    pub baseline: [u64; N],
    /// Latest real source snapshot supplied to this allocation.
    pub observed: [u64; N],
    /// Original source coordinate after a same-epoch whole frame write. None
    /// means no setter was wholly written; it does not certify the baseline.
    pub settled: [Option<u64>; N],
    /// One original mutation whose local transfer remains pending.
    pub pending: Option<Pending>,
    /// Retired original mutation with uncertain exposure, permanently not replayed.
    pub unknown: Option<Pending>,
    /// Last actual connected native epoch.
    pub epoch: Option<u64>,
    /// Actual native Destroyed observation, including unconfirmed metadata.
    pub destroyed: Option<DestroyReport>,
    /// Official statistics.DISABLE created no native source.
    pub disabled: bool,
    /// No actual native owner remains.
    pub closed: bool,
    /// An actual failure/abort permanently fenced this allocation.
    pub fenced: bool,
}
/// One bounded actual producer step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Real native/admission/destruction progress, not a remote acknowledgement.
    Activity,
    /// The original same-source frame was actually wholly written locally.
    Written {
        /// Actual immutable metric index.
        counter: usize,
        /// Original unchanged setter value, not the newest observed snapshot.
        value: Value,
    },
    /// Actual original native owner retired, or official disable.
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
/// One reusable actual native STATISTICS producer with constant caller-selected storage.
/// One original setter is outstanding; no GET/WATCH or competing mutation is submitted.
/// A lost/error source is permanently fenced; it is never recreated to replay an
/// uncertain relative delta. Explicit new publishers start from an explicit fresh
/// current baseline, rather than claiming the old delta was delivered.
pub struct Producer<'id, const N: usize> {
    owner: Option<Handle<'id>>,
    limits: Limits,
    metrics: &'static [Metric; N],
    position: [u64; N],
    desired: [u64; N],
    cursor: usize,
    pending: Option<Mutation<'id>>,
    connected: Option<ConnectionEpoch<'id>>,
    operation_alarm: Option<Pin<Box<Sleep>>>,
    closing: Option<Instant>,
    close_alarm: Option<Pin<Box<Sleep>>>,
    destroying: bool,
    report: Report<N>,
}
impl<'id, const N: usize> Producer<'id, N> {
    /// Keep the original live config, Resolver and SAME actual clock Arc.
    /// `initial` belongs to this original Core and establishes a non-delivery
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
        configuration: Configuration<N>,
    ) -> Result<Self, Failure> {
        let Configuration {
            subsystem,
            metrics,
            initial,
            limits,
        } = configuration;
        limits.validate()?;
        if initial.overflowed {
            return Err(Failure::new(Cause::ObservationOverflow));
        }
        if N == 0
            || subsystem.is_empty()
            || subsystem.contains(&0)
            || subsystem.len() >= 128
            || metrics.iter().enumerate().any(|(i, metric)| {
                metric.name.is_empty()
                    || metric.name.contains(&0)
                    || metric.name.len() >= 128
                    || 18usize
                        .checked_add(subsystem.len())
                        .and_then(|n| n.checked_add(metric.name.len()))
                        .is_none_or(|n| n > limits.max_frame_bytes)
                    || metrics[..i].iter().any(|old| old.name == metric.name)
            })
        {
            return Err(Failure::new(Cause::InvalidLimits));
        }
        let source = EndpointSource::live(live.clone(), b"statistics", resolution.clone());
        if !Arc::ptr_eq(&source.clock(), &clock) {
            return Err(Failure::new(Cause::ClockIdentity));
        }
        let owner = Handle::from_live_config(
            instance,
            live,
            resolution,
            subsystem,
            handle::Limits {
                max_frame_bytes: limits.max_frame_bytes,
                write_chunk_bytes: limits.write_chunk_bytes,
            },
        )
        .map_err(|e| Failure::new(Cause::Ipc(e)))?;
        let baseline = initial.values;
        let disabled = owner.is_none();
        Ok(Self {
            owner,
            limits,
            metrics,
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
                settled: [None; N],
                pending: None,
                unknown: None,
                epoch: None,
                destroyed: None,
                disabled,
                closed: disabled,
                fenced: false,
            },
        })
    }
    /// Read metadata only; taking a report never grants retry/delivery authority.
    #[must_use]
    pub fn report(&self) -> Report<N> {
        self.report
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
    fn snapshot(&mut self, snapshot: Snapshot<N>) -> Result<(), Failure> {
        if snapshot.overflowed {
            return Err(self.fail(Failure::new(Cause::ObservationOverflow)));
        }
        if let Some(counter) = snapshot
            .values
            .iter()
            .zip(self.report.observed)
            .enumerate()
            .position(|(i, (now, old))| self.metrics[i].kind == Kind::Counter && *now < old)
        {
            return Err(self.fail(Failure::new(Cause::CounterRegression { counter })));
        }
        self.report.observed = snapshot.values;
        self.desired = snapshot.values;
        Ok(())
    }
    /// Supply real source facts and admit at most one original setter. Queuing
    /// does not advance settled coordinates or prove remote processing.
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual native IO and independent cleanup causes by value after source failure"
    )]
    pub fn refresh(&mut self, snapshot: Snapshot<N>) -> Result<bool, Failure> {
        if self.report.closed || self.closing.is_some() {
            return Ok(false);
        }
        self.snapshot(snapshot)?;
        self.admit()
    }
    fn next_value(&self) -> Option<(usize, Value)> {
        for offset in 0..N {
            let i = (self.cursor + offset) % N;
            match self.metrics[i].kind {
                Kind::Counter => {
                    let amount = self.desired[i]
                        .saturating_sub(self.position[i])
                        .min(i64::MAX as u64);
                    if amount != 0 {
                        return Some((
                            i,
                            Value::Delta {
                                amount,
                                target: self.position[i] + amount,
                            },
                        ));
                    }
                }
                Kind::Gauge if self.report.settled[i] != Some(self.desired[i]) => {
                    return Some((i, Value::Absolute(self.desired[i])));
                }
                Kind::Gauge => {}
            }
        }
        None
    }
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual native IO and independent cleanup causes by value after source failure"
    )]
    fn admit(&mut self) -> Result<bool, Failure> {
        if self.pending.is_some() || self.destroying || self.report.closed {
            return Ok(false);
        }
        let Some(owner) = &self.owner else {
            return Err(self.fail(Failure::new(Cause::Invariant)));
        };
        if owner.is_closed() {
            return Err(self.fail(Failure::new(Cause::Ipc(IpcError::Closed))));
        }
        if !owner.is_idle() {
            return Err(self.fail(Failure::new(Cause::Invariant)));
        }
        let Some((counter, value)) = self.next_value() else {
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
            value,
            hard,
            epoch: epoch.map(ConnectionEpoch::value),
        };
        // Keep intent before the setter, which can fail after actual admission.
        self.pending = Some(Mutation { info, epoch });
        self.report.pending = Some(info);
        let Some(owner) = self.owner.as_mut() else {
            return Err(self.fail(Failure::new(Cause::Invariant)));
        };
        let definition = self.metrics[counter];
        let result = match value {
            Value::Delta { amount, .. } => match i64::try_from(amount) {
                Ok(amount) => owner.update(definition.name, amount, definition.persistent),
                Err(_) => return Err(self.fail(Failure::new(Cause::Invariant))),
            },
            Value::Absolute(value) => owner.set(definition.name, value, definition.persistent),
        };
        match result {
            Ok(SetterAdmission::Queued) => {
                let epoch = self.owner.as_ref().and_then(Handle::connection_epoch);
                if let Some(p) = &mut self.pending {
                    p.epoch = epoch;
                    p.info.epoch = epoch.map(ConnectionEpoch::value);
                    self.report.pending = Some(p.info);
                }
                self.cursor = (counter + 1) % N;
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
            && self.next_value().is_none()
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
        self.report.destroyed = events.destroyed.or(self.report.destroyed);
        if let Some((epoch, reason)) = events.lost {
            self.report.epoch = Some(epoch.value());
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
            // Destroy can clear queues without whole-writing a setter. Never
            // reclassify this as delivery, even if the resulting Core is idle.
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
                let value = p.info.value;
                let target = value.target();
                if let Value::Delta { amount, target } = value
                    && self.position[counter].checked_add(amount) != Some(target)
                {
                    return Poll::Ready(Err(self.fail(Failure::new(Cause::Invariant))));
                }
                self.position[counter] = target;
                self.report.settled[counter] = Some(target);
                self.pending = None;
                self.report.pending = None;
                return Poll::Ready(Ok(Progress::Written { counter, value }));
            }
        }
        match result {
            Poll::Ready(Ok(handle::Progress::Closed)) => {
                Poll::Ready(Err(self.fail(Failure::new(Cause::Ipc(IpcError::Closed)))))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Progress::Activity)),
            Poll::Pending if admitted => Poll::Ready(Ok(Progress::Activity)),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(Failure::new(Cause::Ipc(error))))),
        }
    }
    /// Freeze one final actual Core snapshot and one unchanged native drain hard
    /// target. Repeat calls neither replace counters nor extend that grace.
    #[expect(
        clippy::result_large_err,
        reason = "Retain actual original STATISTICS, native IO and independent cleanup causes without allocating after source failure"
    )]
    pub fn begin_close(&mut self, snapshot: Snapshot<N>, grace: Duration) -> Result<(), Failure> {
        if self.report.closed || self.closing.is_some() {
            return Ok(());
        }
        if grace.is_zero() || grace.as_micros() >= u64::MAX as u128 {
            return Err(self.fail(Failure::new(Cause::InvalidLimits)));
        }
        let Some(hard) = Instant::now().checked_add(grace) else {
            return Err(self.fail(Failure::new(Cause::InvalidLimits)));
        };
        self.snapshot(snapshot)?;
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
            let connection = owner.take_connect_error();
            if owner.is_closed() {
                Ok(())
            } else {
                match owner.destroy(false) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let mut failure = Failure::new(Cause::Ipc(error));
                        failure.transport = transport;
                        failure.connection = connection;
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
            self.report.unknown = Some(p.info);
        }
        self.report.pending = None;
    }
    fn fail(&mut self, mut failure: Failure) -> Failure {
        self.burn_pending();
        self.report.fenced = true;
        if let Some(mut owner) = self.owner.take() {
            failure.transport = owner.take_io_error();
            failure.connection = owner.take_connect_error();
            if !owner.is_closed() {
                failure.cleanup = owner.destroy(false).err();
            }
        }
        self.report.closed = true;
        failure
    }
}
impl<const N: usize> Drop for Producer<'_, N> {
    fn drop(&mut self) {
        let _unobserved_retirement = self.abort();
    }
}
