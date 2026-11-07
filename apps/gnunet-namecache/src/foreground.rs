use crate::{Cause, display, settings::Settings};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_namecache_client_host::{
    Cancellation, Client, Completion, Kind, LocalReason, LossCause, Operation, Outcome, Progress,
    Submission,
};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{BrokerError, Driver};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::Cell,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal, SignalKind},
    time::{Instant, Sleep},
};

#[derive(Debug)]
pub(super) struct ProgramFailure {
    pub original: Option<Cause>,
    pub logging: Option<io::Error>,
}
impl fmt::Display for ProgramFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NAMECACHE original={:?}; independent selected Logger={:?}",
            self.original, self.logging
        )
    }
}
impl std::error::Error for ProgramFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref().or_else(|| {
            self.logging
                .as_ref()
                .map(|error| error as &dyn std::error::Error)
        })
    }
}
#[derive(Debug)]
struct Failure {
    original: Option<Cause>,
    cancel: Option<gnunet_namecache_client_host::Error>,
    drain: Option<Cause>,
    resolver: Option<BrokerError>,
    output: Option<io::Error>,
    report: Report,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NAMECACHE original={:?}; cancel={:?}; completion-drain={:?}; resolver-close={:?}; stdout-flush={:?}; actual-report={:?}",
            self.original, self.cancel, self.drain, self.resolver, self.output, self.report
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cancel.as_ref().map(|e| e as &dyn std::error::Error))
            .or(self.drain.as_deref())
            .or_else(|| self.resolver.as_ref().map(|e| e as &dyn std::error::Error))
            .or_else(|| self.output.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
#[derive(Debug)]
struct SourceLost {
    epoch: Option<u64>,
    operations: usize,
    exposed: usize,
    cause: LossCause,
}
impl fmt::Display for SourceLost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NAMECACHE source {:?} physically lost; operations={}, exposed={}; {:?}",
            self.epoch, self.operations, self.exposed, self.cause
        )
    }
}
impl std::error::Error for SourceLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            LossCause::Io(error) => Some(error),
            LossCause::Ports(error) => Some(error),
            LossCause::Protocol(error) | LossCause::Resource(error) => Some(error),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct Local {
    reason: LocalReason,
    submission: Submission,
}
impl fmt::Display for Local {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original NAMECACHE operation ended locally: {:?}, exposure={:?}; no service result",
            self.reason, self.submission
        )
    }
}
impl std::error::Error for Local {}

#[derive(Debug)]
enum ResultFact {
    Missing,
    Ciphertext {
        bytes: usize,
        expiration: u64,
    },
    Records(display::Records),
    Delete(i32),
    Cache(i32),
    Local {
        reason: LocalReason,
        submission: Submission,
    },
}
impl fmt::Display for ResultFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("actual miss"),
            Self::Ciphertext { bytes, expiration } => write!(
                f,
                "carried-key/query checked ciphertext, bytes={bytes} expiration-us={expiration}; display not completed"
            ),
            Self::Records(records) => write!(
                f,
                "zone/name checked and decrypted records: applicable={} unsupported-or-corrupt={} expiration-us={}",
                records.applicable, records.unsupported_or_corrupt, records.block_expiration
            ),
            Self::Delete(code) => write!(f, "actual delete result={code}"),
            Self::Cache(code) => write!(f, "unexpected actual cache result={code}"),
            Self::Local { reason, submission } => {
                write!(f, "local={reason:?} exposure={submission:?}")
            }
        }
    }
}
struct Receipt {
    operation: u64,
    epoch: Option<u64>,
    rid: u32,
    kind: Kind,
    outcome: ResultFact,
}
impl fmt::Debug for Receipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receipt")
            .field("operation", &self.operation)
            .field("epoch", &self.epoch)
            .field("rid", &self.rid)
            .field("kind", &self.kind)
            .field("outcome", &format_args!("{}", self.outcome))
            .finish()
    }
}
fn receipt(completion: &Completion<'_>) -> Receipt {
    let outcome = match &completion.outcome {
        Outcome::Lookup(None) => ResultFact::Missing,
        Outcome::Lookup(Some(block)) => ResultFact::Ciphertext {
            bytes: block.bytes().len(),
            expiration: block.expiration().as_micros(),
        },
        Outcome::Delete(code) => ResultFact::Delete(*code),
        Outcome::Cache(code) => ResultFact::Cache(*code),
        Outcome::Local { reason, submission } => ResultFact::Local {
            reason: *reason,
            submission: *submission,
        },
    };
    Receipt {
        operation: completion.operation.diagnostic(),
        epoch: completion.epoch.map(|epoch| epoch.diagnostic()),
        rid: completion.request_id,
        kind: completion.kind,
        outcome,
    }
}
#[derive(Default)]
struct Report {
    operation: Option<u64>,
    rid: Option<u32>,
    queued: bool,
    written: bool,
    result: Option<Receipt>,
    cancellation: Option<Cancellation>,
    physical_close: Option<(Option<u64>, usize, usize)>,
    retired: Option<Receipt>,
    resolver_io: Option<io::Error>,
    resolver_connect: Option<BrokerError>,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Report")
            .field("operation", &self.operation)
            .field("rid", &self.rid)
            .field("queued", &self.queued)
            .field("whole_local_write", &self.written)
            .field("actual_result", &self.result)
            .field("cancellation", &self.cancellation)
            .field("physical_close", &self.physical_close)
            .field("retired_original", &self.retired)
            .field("resolver_io", &self.resolver_io)
            .field("resolver_connect", &self.resolver_connect)
            .finish()
    }
}
struct Signals {
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original signal stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    reporter: Reporter,
) -> Result<(), Cause> {
    let live = LiveConfiguration::new(prepared.main().config.duplicate()?);
    let actual: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let (mut context, resolver) = gnunet_resolver_broker::broker::<8, 1024>(
        live.clone(),
        Default::default(),
        gnunet_resolver_broker::native_profile()?,
        actual.clone(),
    )?;
    let source = settings
        .socket
        .clone()
        .map(|path| EndpointSource::unix_with_clock(path, actual.clone()))
        .unwrap_or_else(|| EndpointSource::live(live, b"namecache", context.resolution_context()));
    let stop = Rc::new(Cell::new(false));
    let original = run(source, resolver, actual, settings, reporter, stop.clone());
    let _report =
        gnunet_program_host::foreground::run(prepared, &mut context, clock, stop, original).await?;
    Ok(())
}

async fn run(
    source: EndpointSource,
    mut resolver: Driver<8, 1024>,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    reporter: Reporter,
    stop: Rc<Cell<bool>>,
) -> Result<Report, Cause> {
    let instance = gnunet_namecache_client_host::Instance::new();
    let mut client = None;
    let mut operation = None;
    let mut report = Report::default();
    let mut output = display::Output::new(io::stdout());
    let original: Result<(), Cause> = async {
        let mut signals = Signals::new()?;
        // This exact pre-admission stop gate also protects public-key derivation
        // when PROGRAM itself failed before admitting its original task.
        if stop.get() || reporter.failed() {
            return Err("NAMECACHE stopped before admission".into());
        }
        let hard = Instant::now()
            .checked_add(settings.timeout)
            .ok_or("NAMECACHE native deadline overflow")?;
        let start = clock.sample()?.now.as_micros();
        let until = start
            .checked_add(u64::try_from(settings.timeout.as_micros())?)
            .filter(|at| *at != u64::MAX)
            .ok_or("NAMECACHE logical deadline overflow")?;
        if Instant::now() >= hard {
            return Err("NAMECACHE original deadline elapsed during clock sampling".into());
        }
        let mut scalars = Vec::new();
        scalars.try_reserve_exact(4096)?;
        scalars.resize(4096, '\0');
        let mut normalized = display::bytes(4096)?;
        let label =
            gnunet_gnscrypto::Label::normalize(&settings.name, &mut scalars, &mut normalized)?;
        let query = gnunet_gnscrypto::query(settings.zone, label)?;
        if stop.get() || reporter.failed() || Instant::now() >= hard {
            return Err("NAMECACHE stopped or original deadline elapsed before admission".into());
        }
        client = Some(Client::new(
            &instance,
            source,
            gnunet_namecache_client_host::Limits {
                operations: 1,
                source_bytes: 72,
                block_bytes: gnunet_namecache_client_host::ipc::MAX_WIRE_BLOCK_BYTES,
                reconnect: false,
                ..Default::default()
            },
        )?);
        let active = client.as_mut().ok_or("NAMECACHE client missing")?;
        let token = if settings.delete {
            active.delete(&query, until)?
        } else {
            active.lookup(&query, until)?
        };
        operation = Some(token);
        report.operation = Some(token.diagnostic());
        report.rid = Some(active.request_id(token)?);
        let complete = wait(
            active,
            &mut resolver,
            &mut signals,
            &reporter,
            &stop,
            token,
            hard,
            &mut report,
        )
        .await?;
        report.result = Some(receipt(&complete));
        // The callback is real and the original request has left the client.
        // Close its physical MQ before bounded CPU interpretation or potentially
        // blocking stdout; neither operation needs an idle native connection.
        report.physical_close = active.close().map(|loss| {
            (
                loss.epoch.map(|epoch| epoch.diagnostic()),
                loss.operations,
                loss.exposed,
            )
        });
        match complete.outcome {
            Outcome::Lookup(None) if !settings.delete => {
                display::missing(&mut output, label.as_str())?
            }
            Outcome::Lookup(Some(block)) if !settings.delete => {
                if stop.get() || reporter.failed() {
                    return Err("NAMECACHE stopped before record interpretation".into());
                }
                let facts = display::records(
                    &mut output,
                    &block,
                    settings.zone,
                    label,
                    clock.sample()?.now.as_micros(),
                    settings.profile,
                )?;
                report
                    .result
                    .as_mut()
                    .ok_or("NAMECACHE result missing")?
                    .outcome = ResultFact::Records(facts);
            }
            Outcome::Delete(code) if settings.delete => {
                display::deleted(&mut output, label.as_str(), code)?;
                if code != gnunet_namecache_client_host::ipc::OK
                    && code != gnunet_namecache_client_host::ipc::NO
                {
                    return Err(
                        format!("actual NAMECACHE delete failed with raw result {code}").into(),
                    );
                }
            }
            Outcome::Local { reason, submission } => {
                return Err(Box::new(Local { reason, submission }) as Cause);
            }
            _ => return Err("NAMECACHE result kind does not match original operation".into()),
        }
        Ok(())
    }
    .await;
    let mut cancel = None;
    let mut drain = None;
    if let Some(client) = &mut client {
        if report.result.is_none()
            && let Some(operation) = operation
        {
            match client.cancel(operation) {
                Ok(cancellation) => report.cancellation = Some(cancellation),
                Err(error) => cancel = Some(error),
            }
        }
        if let Some(loss) = client.close() {
            report.physical_close = Some((
                loss.epoch.map(|epoch| epoch.diagnostic()),
                loss.operations,
                loss.exposed,
            ));
        }
        // close() has already physically retired the original MQ, even with a
        // failed clock. These remaining polls consume its bounded local records;
        // they do not send a suffix or infer the remote mutation outcome.
        let hard = Instant::now().checked_add(Duration::from_secs(5));
        if let Some(hard) = hard {
            let mut timer = Box::pin(tokio::time::sleep_until(hard));
            loop {
                let event = poll_fn(|cx| {
                    if timer.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(
                            "closed NAMECACHE completion-drain hard elapsed".into()
                        ));
                    }
                    client
                        .poll(cx, None)
                        .map_err(|error| Box::new(error) as Cause)
                })
                .await;
                match event {
                    Ok(Progress::Closed) => break,
                    Ok(Progress::Completed(completion)) if report.retired.is_none() => {
                        report.retired = Some(receipt(&completion))
                    }
                    Ok(_) => {
                        drain = Some("unexpected closed NAMECACHE completion observation".into());
                        break;
                    }
                    Err(error) => {
                        drain = Some(error);
                        break;
                    }
                }
            }
        } else {
            drain = Some("NAMECACHE completion-drain native deadline overflow".into());
        }
    }
    // Preserve actual Resolver errors independently. No new lookup is admitted
    // after NAMECACHE close, and Drop still physically closes a refused driver.
    drop(client);
    report.resolver_io = resolver.take_io_error();
    report.resolver_connect = resolver.take_connect_error();
    let resolver_error = resolver.disconnect().err();
    drop(resolver);
    let output = output.flush().err();
    reporter.debug("namecache.original.report", format_args!("{report:?}"));
    if original.is_ok()
        && cancel.is_none()
        && drain.is_none()
        && resolver_error.is_none()
        && output.is_none()
        && !reporter.failed()
    {
        Ok(report)
    } else {
        Err(Box::new(Failure {
            original: original.err(),
            cancel,
            drain,
            resolver: resolver_error,
            output,
            report,
        }))
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "One original operation and its caller-owned native, signal, Resolver and report lifetimes"
)]
async fn wait<'id>(
    client: &mut Client<'id>,
    resolver: &mut Driver<8, 1024>,
    signals: &mut Signals,
    reporter: &Reporter,
    stop: &Cell<bool>,
    original: Operation<'id>,
    hard: Instant,
    report: &mut Report,
) -> Result<Completion<'id>, Cause> {
    let mut alarm: Pin<Box<Sleep>> = Box::pin(tokio::time::sleep_until(hard));
    let mut resolver_first = false;
    loop {
        let event = poll_fn(|cx| {
            reporter.register(cx);
            // Original native targets win over canonical Resolver/clock waits.
            if let Some(event) = client.poll_native_guard(cx) {
                return Poll::Ready(Ok(Some(event)));
            }
            if alarm.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(
                    "original NAMECACHE operation native deadline elapsed".into()
                ));
            }
            if stop.get() || reporter.failed() {
                return Poll::Ready(Err("NAMECACHE original task stopped".into()));
            }
            if let Poll::Ready(result) = signals.poll(cx) {
                return Poll::Ready(
                    result
                        .and_then(|()| {
                            Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "NAMECACHE interrupted",
                            ))
                        })
                        .map_err(|error| Box::new(error) as Cause),
                );
            }
            resolver_first = !resolver_first;
            for native in [!resolver_first, resolver_first] {
                if native {
                    if let Poll::Ready(result) = client.poll(cx, None) {
                        return Poll::Ready(
                            result.map(Some).map_err(|error| Box::new(error) as Cause),
                        );
                    }
                } else {
                    let progress = resolver.drive_waiting(None, |event| {
                        reporter.debug("namecache.resolver.activity", format_args!("{event:?}"))
                    });
                    match std::pin::pin!(progress).as_mut().poll(cx) {
                        Poll::Ready(Ok(_)) => return Poll::Ready(Ok(None)),
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(Box::new(error) as Cause));
                        }
                        Poll::Pending => {}
                    }
                    if reporter.failed() {
                        return Poll::Ready(Err("selected NAMECACHE Logger failed".into()));
                    }
                }
            }
            Poll::Pending
        })
        .await?;
        match event {
            Some(Progress::Completed(completion)) if completion.operation == original => {
                return Ok(completion);
            }
            Some(Progress::Queued { operation, .. }) if operation == original => {
                report.queued = true
            }
            Some(Progress::Written { operation, .. }) if operation == original => {
                report.written = true
            }
            Some(Progress::Lost { report, cause }) => {
                return Err(Box::new(SourceLost {
                    epoch: report.epoch.map(|epoch| epoch.diagnostic()),
                    operations: report.operations,
                    exposed: report.exposed,
                    cause,
                }));
            }
            Some(Progress::Unavailable(error)) => return Err(Box::new(error)),
            Some(Progress::ConnectRetry { error, retry_after }) => reporter.debug(
                "namecache.connect.retry",
                format_args!("{error}; actual retry delay {retry_after:?}"),
            ),
            Some(Progress::Completed(_) | Progress::Queued { .. } | Progress::Written { .. }) => {
                return Err("foreign NAMECACHE operation observation".into());
            }
            Some(Progress::Closed) => {
                return Err("NAMECACHE closed without original completion".into());
            }
            Some(
                Progress::Connected(_)
                | Progress::Activity { .. }
                | Progress::Ignored { .. }
                | Progress::WaitDeadline,
            )
            | None => {}
        }
        tokio::task::yield_now().await;
    }
}
