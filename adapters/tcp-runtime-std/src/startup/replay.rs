//! Original replay bootstrap and unconditional physical worker retirement.
mod namespace;
use super::{Diagnostic, Failure, Report, identity};
use crate::{
    clock::ClockPort,
    epoch,
    process_ports::{ProcessPorts, Resources},
};
use gnunet_config::Configuration;
use gnunet_pils::client::Identity;
use gnunet_pils_host::client as pils;
use gnunet_resolver_broker::{Driver, DriverEvent};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_tcp_replay_host::{self as ledger, Ledger};
use gnunet_types::Error;
pub(super) use namespace::Namespace;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

pub(super) enum Observation<'view, 'task> {
    Poll(&'view mut Context<'task>),
    Abort,
}

pub(super) struct Bootstrap<'run, 'id, S: ?Sized> {
    pub config: &'run Configuration,
    pub namespace: &'run Namespace,
    pub source: Arc<dyn RuntimeClock>,
    pub identity: Identity<'id>,
    pub continuity: &'run mut identity::Continuity<'id>,
    pub pils: &'run mut pils::Client<'id>,
    pub resolver: &'run mut Driver<128, 256>,
    pub shutdown: Pin<&'run mut S>,
    pub observe_pils: &'run mut dyn for<'p> FnMut(&pils::Progress<'p>),
    pub observe_resolver: &'run mut dyn FnMut(DriverEvent),
    pub diagnose: &'run mut dyn FnMut(Diagnostic),
    pub failed: &'run dyn Fn() -> bool,
    pub entries: usize,
    pub poll_observation: &'run mut dyn for<'view, 'task> FnMut(Observation<'view, 'task>) -> bool,
}
struct Budget {
    source: Arc<dyn RuntimeClock>,
    until: u64,
    hard: Instant,
    native: Pin<Box<Sleep>>,
    canonical: Pin<Box<Deadline>>,
}
impl Budget {
    fn new(source: Arc<dyn RuntimeClock>, bounds: Option<(Instant, u64)>) -> Result<Self, Failure> {
        let hard = Instant::now()
            .checked_add(Duration::from_secs(60))
            .ok_or(Error::Overflow)?;
        let until = source
            .sample()?
            .now
            .as_micros()
            .checked_add(60_000_000)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        let (hard, until) = bounds.map_or((hard, until), |(h, u)| (hard.min(h), until.min(u)));
        let canonical = Box::pin(Deadline::at(
            source.clone(),
            gnunet_types::AbsoluteTime::from_micros(until),
        )?);
        let native = Box::pin(tokio::time::sleep_until(hard));
        Ok(Self {
            source,
            until,
            hard,
            native,
            canonical,
        })
    }
    fn timeout() -> Failure {
        Box::new(io::Error::new(
            io::ErrorKind::TimedOut,
            "original TCP replay bootstrap budget expired",
        ))
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if Instant::now() >= self.hard || self.native.as_mut().poll(cx).is_ready() {
            return Err(Self::timeout());
        }
        if let Poll::Ready(result) = self.canonical.as_mut().poll(cx) {
            return Err(match result {
                Ok(()) => Self::timeout(),
                Err(e) => Box::new(e),
            });
        }
        let now = self.source.sample()?.now.as_micros();
        if Instant::now() >= self.hard || now >= self.until {
            return Err(Self::timeout());
        }
        Ok(())
    }
}
fn stop<S: Future<Output = io::Result<()>> + ?Sized>(
    cx: &mut Context<'_>,
    shutdown: Pin<&mut S>,
    failed: &dyn Fn() -> bool,
) -> Result<bool, Failure> {
    if failed() {
        return Ok(true);
    }
    match shutdown.poll(cx) {
        Poll::Ready(result) => result.map(|()| true).map_err(|e| Box::new(e) as Failure),
        Poll::Pending => Ok(false),
    }
}
#[derive(Debug)]
struct BootstrapFailure {
    original: Option<Failure>,
    cleanup: Option<ledger::Shutdown>,
    timeout: Option<io::Error>,
}
impl std::fmt::Display for BootstrapFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TCP replay bootstrap: original={:?}; worker={:?}; timeout={:?}",
            self.original, self.cleanup, self.timeout
        )
    }
}
impl std::error::Error for BootstrapFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.timeout.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
fn ledger_failed(report: &ledger::Shutdown) -> bool {
    report.stopped.is_none() || report.original.is_some() || report.join.is_some()
}
async fn close_ledger(
    ledger: &mut Ledger,
    diagnose: &mut dyn FnMut(Diagnostic),
) -> (ledger::Shutdown, Option<io::Error>) {
    let target = Instant::now() + Duration::from_secs(30);
    let mut timer = std::pin::pin!(tokio::time::sleep_until(target));
    let mut timeout = None;
    let result = {
        let mut closing =
            std::pin::pin!(ledger.shutdown(|event| diagnose(Diagnostic::Replay(event))));
        poll_fn(|cx| {
            if timeout.is_none() && timer.as_mut().poll(cx).is_ready() {
                timeout = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original TCP bootstrap worker retirement exceeded its grace",
                ));
            }
            // A timed-out wait cannot manufacture thread termination. Retain
            // and poll this same original drain/join future to its actual end.
            closing.as_mut().poll(cx)
        })
        .await
    };
    (result, timeout)
}
async fn refuse(
    original: Option<Failure>,
    ledger: Option<&mut Ledger>,
    diagnose: &mut dyn FnMut(Diagnostic),
) -> Result<(), Failure> {
    let (cleanup, timeout) = match ledger {
        Some(ledger) => {
            let (report, timeout) = close_ledger(ledger, diagnose).await;
            (Some(report), timeout)
        }
        None => (None, None),
    };
    if original.is_none() && timeout.is_none() && cleanup.as_ref().is_none_or(|r| !ledger_failed(r))
    {
        Ok(())
    } else {
        Err(Box::new(BootstrapFailure {
            original,
            cleanup,
            timeout,
        }))
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "one original worker owner returned without a fallible wrapper allocation"
)]
pub(super) enum Prepared {
    Ready(ProcessPorts),
    Stop,
    Superseded,
}
enum Done {
    Ready,
    Stop,
    Superseded,
}
pub(super) async fn bootstrap<'id, S: Future<Output = io::Result<()>> + ?Sized>(
    input: Bootstrap<'_, 'id, S>,
) -> Result<Prepared, Failure> {
    let Bootstrap {
        config,
        namespace,
        source,
        identity,
        continuity,
        pils,
        resolver,
        mut shutdown,
        observe_pils,
        observe_resolver,
        diagnose,
        failed,
        entries,
        poll_observation,
    } = input;
    let stopped = poll_fn(|cx| Poll::Ready(stop(cx, shutdown.as_mut(), failed))).await?;
    if stopped {
        poll_observation(Observation::Abort);
        return Ok(Prepared::Stop);
    }
    let mut budget = Budget::new(source.clone(), continuity.bounds())?;
    let stopped = poll_fn(|cx| {
        Poll::Ready(stop(cx, shutdown.as_mut(), failed).and_then(|stopped| {
            if !stopped {
                continuity.guard(cx)?;
                budget.guard(cx)?;
            }
            Ok(stopped)
        }))
    })
    .await?;
    if stopped {
        poll_observation(Observation::Abort);
        return Ok(Prepared::Stop);
    }
    let (frontier, ledger_directory) = namespace.paths(identity.peer())?;
    let mut clock = ClockPort::new(source, frontier.clone())?;
    clock.prepare_replay(identity.peer(), &ledger_directory)?;
    let stopped = poll_fn(|cx| {
        Poll::Ready(stop(cx, shutdown.as_mut(), failed).and_then(|stopped| {
            if !stopped {
                continuity.guard(cx)?;
                budget.guard(cx)?;
            }
            Ok(stopped)
        }))
    })
    .await?;
    if stopped {
        poll_observation(Observation::Abort);
        clock.close();
        return Ok(Prepared::Stop);
    }
    let records = if config
        .get(b"communicator-tcp-rust", b"REPLAY_RECORDS")
        .is_some()
    {
        usize::try_from(config.get_number(b"communicator-tcp-rust", b"REPLAY_RECORDS")?)?
    } else {
        ledger::Limits::default().records
    };
    let mut ledger = match Ledger::open(
        &ledger_directory,
        identity.peer(),
        ledger::Limits { records },
        &frontier,
    ) {
        Ok(ledger) => ledger,
        Err(rejected) => {
            poll_observation(Observation::Abort);
            clock.close();
            let _original = pils.close();
            let ledger::OpenRejected { error, mut owner } = rejected;
            return refuse(Some(Box::new(error)), owner.as_deref_mut(), diagnose)
                .await
                .map(|()| Prepared::Stop);
        }
    };
    let mut binding_started = false;
    let mut cursor = 0usize;
    #[expect(
        clippy::large_enum_variant,
        reason = "Borrow the original PILS callback inline without allocating an event wrapper per turn"
    )]
    enum Turn<'peer> {
        Stop,
        Ledger(ledger::Progress),
        Pils(pils::Progress<'peer>),
        Resolver,
        Observation,
    }
    let outcome = async {
        loop {
            let stopped = poll_fn(|cx| {
                Poll::Ready(stop(cx, shutdown.as_mut(), failed).and_then(|stopped| {
                    if !stopped {
                        budget.guard(cx)?;
                    }
                    Ok(stopped)
                }))
            })
            .await?;
            if stopped {
                return Ok(Done::Stop);
            }
            let current = pils.identity().ok_or(Error::StaleGeneration)?;
            continuity.verify(current, clock.source().as_ref())?;
            if current.peer() != identity.peer() {
                continuity.changing(current, clock.source())?;
                return Ok(Done::Superseded);
            }
            match ledger.catalog() {
                Ok(catalog) => {
                    clock.attach_catalog(&catalog)?;
                    if catalog.is_bound() {
                        let stopped = poll_fn(|cx| {
                            Poll::Ready(stop(cx, shutdown.as_mut(), failed).and_then(|stopped| {
                                if !stopped {
                                    budget.guard(cx)?;
                                }
                                Ok(stopped)
                            }))
                        })
                        .await?;
                        return Ok(if stopped { Done::Stop } else { Done::Ready });
                    }
                    if !binding_started {
                        let stopped = poll_fn(|cx| {
                            Poll::Ready(stop(cx, shutdown.as_mut(), failed).and_then(|stopped| {
                                if !stopped {
                                    budget.guard(cx)?;
                                }
                                Ok(stopped)
                            }))
                        })
                        .await?;
                        if stopped {
                            return Ok(Done::Stop);
                        }
                        let _original = ledger.bind_frontier(&frontier)?;
                        binding_started = true;
                    }
                }
                Err(Error::NotReady | Error::WouldBlock) => {}
                Err(error) => return Err(Box::new(error) as Failure),
            }
            let selected = {
                let mut driving = std::pin::pin!(pils.drive(None));
                let mut resolving =
                    std::pin::pin!(resolver.drive_waiting(None, &mut *observe_resolver));
                poll_fn(|cx| {
                    match stop(cx, shutdown.as_mut(), failed) {
                        Ok(true) => return Poll::Ready(Ok(Turn::Stop)),
                        Err(error) => return Poll::Ready(Err(error)),
                        Ok(false) => {}
                    }
                    let observation = poll_observation(Observation::Poll(cx));
                    if let Err(error) = continuity.guard(cx).and_then(|()| budget.guard(cx)) {
                        return Poll::Ready(Err(error));
                    }
                    for offset in 0..3 {
                        let part = (cursor + offset) % 3;
                        let ready = match part {
                            0 => ledger.poll(cx).map(Turn::Ledger).map(Ok),
                            1 => driving
                                .as_mut()
                                .poll(cx)
                                .map(|r| r.map(Turn::Pils).map_err(|e| Box::new(e) as Failure)),
                            _ => resolving.as_mut().poll(cx).map(|r| {
                                r.map(|_| Turn::Resolver)
                                    .map_err(|e| Box::new(e) as Failure)
                            }),
                        };
                        if ready.is_ready() {
                            cursor = (part + 1) % 3;
                            return ready;
                        }
                        if failed() {
                            return Poll::Ready(Ok(Turn::Stop));
                        }
                    }
                    if observation {
                        Poll::Ready(Ok(Turn::Observation))
                    } else {
                        Poll::Pending
                    }
                })
                .await?
            };
            match selected {
                Turn::Stop => return Ok(Done::Stop),
                Turn::Ledger(event) => {
                    let error = match &event {
                        ledger::Progress::Failed { error, .. } => Some(error.clone()),
                        ledger::Progress::Drained => Some(Arc::new(ledger::Failure {
                            stage: "bootstrap-ended",
                            uncertain: true,
                            cause: ledger::Cause::Protocol(Error::Closed),
                        })),
                        _ => None,
                    };
                    diagnose(Diagnostic::Replay(event));
                    if let Some(error) = error {
                        return Err(Box::new(LedgerCause(error)) as Failure);
                    }
                }
                Turn::Pils(event) => identity::observe(event, observe_pils)?,
                Turn::Resolver | Turn::Observation => {}
            }
            tokio::task::yield_now().await;
        }
    }
    .await;
    match outcome {
        Ok(Done::Ready) => match ProcessPorts::adopt(Resources { clock, ledger }, entries) {
            Ok(ports) => Ok(Prepared::Ready(ports)),
            Err(rejected) => {
                let crate::process_ports::Rejected {
                    error,
                    mut resources,
                } = rejected;
                poll_observation(Observation::Abort);
                resources.clock.close();
                let _original = pils.close();
                refuse(Some(Box::new(error)), Some(&mut resources.ledger), diagnose).await?;
                Ok(Prepared::Stop)
            }
        },
        Ok(done @ (Done::Stop | Done::Superseded)) => {
            clock.close();
            if matches!(done, Done::Stop) {
                poll_observation(Observation::Abort);
                let _original = pils.close();
            }
            refuse(None, Some(&mut ledger), diagnose).await?;
            Ok(match done {
                Done::Superseded => Prepared::Superseded,
                _ => Prepared::Stop,
            })
        }
        Err(error) => {
            poll_observation(Observation::Abort);
            clock.close();
            let _original = pils.close();
            refuse(Some(error), Some(&mut ledger), diagnose).await?;
            Ok(Prepared::Stop)
        }
    }
}
#[derive(Debug)]
struct LedgerCause(Arc<ledger::Failure>);
impl std::fmt::Display for LedgerCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for LedgerCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

#[derive(Debug)]
struct FinishFailure {
    original: Option<Failure>,
    report: Option<Report>,
    shutdown: crate::process_ports::Shutdown,
    frontier: Option<epoch::FinishRejected>,
    timeout: Option<io::Error>,
    missing_proof: bool,
}
impl std::fmt::Display for FinishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TCP original replay retirement: original={:?}; report={:?}; worker={:?}; frontier={:?}; timeout={:?}; missing_epoch_proof={}",
            self.original,
            self.report,
            self.shutdown,
            self.frontier,
            self.timeout,
            self.missing_proof
        )
    }
}
impl std::error::Error for FinishFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| {
                self.frontier
                    .as_ref()
                    .map(|v| &v.error as &dyn std::error::Error)
            })
            .or_else(|| self.timeout.as_ref().map(|v| v as &dyn std::error::Error))
    }
}
pub(super) async fn finish(
    ports: &mut ProcessPorts,
    proof: Option<epoch::Quiescent>,
    epoch_started: bool,
    outcome: Result<Report, Failure>,
    hard: Option<Instant>,
    diagnose: &mut dyn FnMut(Diagnostic),
) -> Result<Report, Failure> {
    let hard = hard.unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
    let mut timer = std::pin::pin!(tokio::time::sleep_until(hard));
    let mut timeout = None;
    let shutdown = {
        let mut closing =
            std::pin::pin!(ports.shutdown(|event| diagnose(Diagnostic::History(event))));
        poll_fn(|cx| {
            if timeout.is_none() && timer.as_mut().poll(cx).is_ready() {
                timeout = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original TCP retirement budget expired before worker join",
                ));
            }
            closing.as_mut().poll(cx)
        })
        .await
    };
    let (mut report, original) = match outcome {
        Ok(report) => (Some(report), None),
        Err(error) => (None, Some(error)),
    };
    // No epoch was ever admitted on a pre-Pool stop. That permits only worker
    // retirement; it never clears a previous dirty state or creates quiescence.
    let has_proof = proof.is_some();
    let missing_proof = epoch_started && !has_proof;
    let frontier = proof.and_then(|proof| ports.finish_epoch(proof).err());
    if has_proof
        && frontier.is_none()
        && let Some(report) = &mut report
    {
        report.clean = true;
    }
    if original.is_none()
        && !missing_proof
        && frontier.is_none()
        && timeout.is_none()
        && shutdown.failures.is_none()
        && shutdown.drain.is_none()
        && !ledger_failed(&shutdown.ledger)
    {
        return report.ok_or_else(|| Box::new(Error::Conflict) as Failure);
    }
    Err(Box::new(FinishFailure {
        original,
        report,
        shutdown,
        frontier,
        timeout,
        missing_proof,
    }))
}
