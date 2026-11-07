//! One original client/reply, stream scratch and same Resolver/Clock owner.
use crate::{
    Failure,
    control::Signals,
    format::{self, Record},
    stream::{self, Stream},
};
use gnunet_client::datastore::{Interruption, Kind};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_datastore_host::{
    self as host, Client, Completion, Operation, Outcome, Request, Response,
};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_service_startup::ParentControl;
use gnunet_types::{AbsoluteTime, Duration as Timeout, Error};
use gnunet_wire::official::datastore::MAX_VALUE_BYTES;
use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::{Zeroize, Zeroizing};
const LIFETIME: Duration = Duration::from_secs(30);
const CADENCE: Duration = Duration::from_millis(10);
#[derive(Clone, Copy)]
pub(super) struct Meta {
    kind: Kind,
    outcome: Outcome,
    interruption: Option<Interruption>,
}
impl std::fmt::Debug for Meta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Completion")
            .field("kind", &self.kind)
            .field("outcome", &self.outcome)
            .field("interruption", &self.interruption)
            .finish()
    }
}
impl From<Completion<'_>> for Meta {
    fn from(c: Completion<'_>) -> Self {
        Self {
            kind: c.kind,
            outcome: c.outcome,
            interruption: c.interruption,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Report {
    dumped: u64,
    submitted: u64,
    inserted: u64,
    next_uid: u64,
    last: Option<Meta>,
}
#[derive(Default)]
struct Close {
    native: Option<host::Error>,
    take: Option<host::Error>,
    completion: Option<Meta>,
}
impl std::fmt::Debug for Close {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRetirement")
            .field("native", &self.native)
            .field("take", &self.take)
            .field("completion", &self.completion)
            .finish()
    }
}
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    client: Close,
    resolver: Option<Failure>,
    streams: stream::Cleanup,
    logging: Option<io::Error>,
    report: Report,
}
impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DATASTORE original={:?}; client={:?}; Resolver={:?}; stream cleanup={:?}; logger={:?}; counters={:?}",
            self.original, self.client, self.resolver, self.streams, self.logging, self.report
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| {
                self.client
                    .native
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.client
                    .take
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or(self.resolver.as_deref())
            .or_else(|| {
                self.streams
                    .errors
                    .iter()
                    .flatten()
                    .next()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| self.logging.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
#[derive(Debug)]
struct Interrupted {
    original: Failure,
    client: Close,
    report: Report,
}
impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; original operation retirement={:?}; counters={:?}",
            self.original, self.client, self.report
        )
    }
}
impl std::error::Error for Interrupted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.original)
    }
}
struct Diagnostic(Zeroizing<Vec<u8>>);
impl std::fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Diagnostic")
            .field("length", &self.0.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}
#[derive(Debug)]
struct RejectedStatus {
    code: i32,
    min_expiration: u64,
    diagnostic: Option<Diagnostic>,
}
impl std::fmt::Display for RejectedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "actual DATASTORE STATUS {} min_expiration={} diagnostic={:?}",
            self.code, self.min_expiration, self.diagnostic
        )
    }
}
impl std::error::Error for RejectedStatus {}
#[derive(Debug)]
struct Lost(host::Loss);
impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original DATASTORE source lost: {:?}", self.0)
    }
}
impl std::error::Error for Lost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            host::Loss::Io(e) => Some(e),
            host::Loss::Protocol(e) => Some(e),
            _ => None,
        }
    }
}
pub(super) struct Inputs {
    pub dump: bool,
    pub insert: bool,
    pub path: Option<PathBuf>,
    pub parent: Option<ParentControl>,
    pub live: LiveConfiguration,
    pub resolution: SharedResolution,
    pub source: Arc<dyn RuntimeClock>,
    pub reports: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub resolver: gnunet_resolver_broker::Driver<4, 256>,
}
pub(super) struct Budget {
    until: AbsoluteTime,
    hard: Instant,
    native: Pin<Box<Sleep>>,
    logical: Pin<Box<Deadline>>,
}
impl Budget {
    fn new(source: Arc<dyn RuntimeClock>) -> Result<Self, Failure> {
        let hard = Instant::now()
            .checked_add(LIFETIME)
            .ok_or("native record budget overflow")?;
        let now = source.sample()?.now;
        let until = AbsoluteTime::from_micros(
            now.as_micros()
                .checked_add(u64::try_from(LIFETIME.as_micros())?)
                .filter(|x| *x < u64::MAX)
                .ok_or("logical record budget overflow")?,
        );
        let logical = Box::pin(Deadline::at(source, until)?);
        if Instant::now() >= hard {
            return Err("record preparation exhausted original native budget".into());
        }
        Ok(Self {
            until,
            hard,
            native: Box::pin(tokio::time::sleep_until(hard)),
            logical,
        })
    }
}
pub(super) struct Driver<'r, 'id, 'slots, 'buffers> {
    client: Client<'id, 'slots, 'buffers>,
    resolver: &'r mut gnunet_resolver_broker::Driver<4, 256>,
    signals: Signals,
    source: Arc<dyn RuntimeClock>,
    reports: Reporter,
    stop: Rc<Cell<bool>>,
    pending: Option<Operation<'id>>,
    report: Report,
    cursor: bool,
    closed: bool,
}
impl<'id> Driver<'_, 'id, '_, '_> {
    fn budget(&self) -> Result<Budget, Failure> {
        if self.stop.get() || self.reports.failed() || self.closed {
            return Err("original DATASTORE owner stopped before new record intent".into());
        }
        Budget::new(self.source.clone())
    }

    fn guard(&mut self, cx: &mut Context<'_>, budget: &mut Budget) -> Result<(), Failure> {
        // This original native target is polled BEFORE any logical/Resolver path.
        if budget.native.as_mut().poll(cx).is_ready() || Instant::now() >= budget.hard {
            return Err("original DATASTORE record native deadline".into());
        }
        self.reports.register(cx);
        if self.stop.get() || self.reports.failed() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "original DATASTORE PROGRAM/Logger stopped",
            )
            .into());
        }
        if let Poll::Ready(signal) = self.signals.poll(cx) {
            signal?;
            self.stop.set(true);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "original DATASTORE signal stop",
            )
            .into());
        }
        if let Poll::Ready(result) = budget.logical.as_mut().poll(cx) {
            result?;
            return Err("original DATASTORE record logical deadline".into());
        }
        let now = self.source.sample()?.now;
        if Instant::now() >= budget.hard || now >= budget.until {
            return Err("original DATASTORE record deadline after clock sample".into());
        }
        Ok(())
    }
    pub async fn check(&mut self, budget: &mut Budget) -> Result<(), Failure> {
        poll_fn(|cx| Poll::Ready(self.guard(cx, budget))).await
    }
    fn poll_resolver(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        let reports = self.reports.clone();
        let result = {
            let mut resolving =
                std::pin::pin!(self.resolver.drive_waiting(None, |event| reports.debug(
                    "datastore.resolver",
                    format_args!("DATASTORE Resolver={event:?}")
                )));
            resolving.as_mut().poll(cx)
        };
        result.map(|r| r.map(|_| ()).map_err(|e| Box::new(e) as Failure))
    }
    pub async fn pause(&mut self, budget: &mut Budget) -> Result<(), Failure> {
        let target = Instant::now()
            .checked_add(CADENCE)
            .ok_or("stdio readiness cadence overflow")?
            .min(budget.hard);
        let mut timer = Box::pin(tokio::time::sleep_until(target));
        poll_fn(|cx| {
            self.guard(cx, budget)?;
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
            match self.poll_resolver(cx) {
                Poll::Ready(result) => {
                    result?;
                    self.guard(cx, budget)?;
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
    fn close(&mut self) -> Close {
        let native = self.client.close().err();
        self.closed = true;
        let mut result = Close {
            native,
            ..Default::default()
        };
        if let Some(operation) = self.pending.take() {
            match self.client.take(operation) {
                Ok(taken) => {
                    let meta = Meta::from(taken.completion);
                    self.report.last = Some(meta);
                    result.completion = Some(meta);
                }
                Err(error) => result.take = Some(error),
            }
        }
        result
    }
    fn fail(&mut self, original: Failure) -> Failure {
        let client = self.close();
        Box::new(Interrupted {
            original,
            client,
            report: self.report,
        })
    }
    async fn operation(
        &mut self,
        request: Request<'_>,
        budget: &mut Budget,
    ) -> Result<host::Taken<'id>, Failure> {
        self.check(budget).await?;
        if self.closed || self.pending.is_some() {
            return Err("original DATASTORE operation owner unavailable".into());
        }
        let now = self.source.sample()?.now;
        if now >= budget.until || Instant::now() >= budget.hard {
            return Err("original deadline before DATASTORE submission".into());
        }
        let remaining = Timeout(
            budget
                .until
                .as_micros()
                .checked_sub(now.as_micros())
                .ok_or("record budget exhausted")?,
        );
        let operation = self.client.submit(request, None, remaining)?;
        self.pending = Some(operation);
        if matches!(request, Request::Put(_)) {
            self.report.submitted = self
                .report
                .submitted
                .checked_add(1)
                .ok_or("PUT admission count overflow; actual original is retained")?;
        }
        let result=poll_fn(|cx|{
            if let Err(error)=self.guard(cx,budget){return Poll::Ready(Err(error));}
            match self.client.take(operation){
                Ok(taken)=>return Poll::Ready(Ok(taken)),
                Err(host::Error::Protocol(Error::NotReady))=>{},
                Err(error)=>return Poll::Ready(Err(Box::new(error) as Failure)),
            }
            for offset in 0..2{
                let resolve=(usize::from(self.cursor)+offset)%2==0;
                if resolve{
                    if let Poll::Ready(result)=self.poll_resolver(cx){result?;self.guard(cx,budget)?;self.cursor=false;cx.waker().wake_by_ref();return Poll::Pending;}
                }else{
                    let result={let mut driving=std::pin::pin!(self.client.drive(Some(budget.hard)));driving.as_mut().poll(cx)};
                    if let Poll::Ready(result)=result{
                        let step=result?;
                        match step{
                            host::Step::Lost{cause,..}=>return Poll::Ready(Err(Box::new(Lost(cause)) as Failure)),
                            host::Step::Unavailable(error)=>return Poll::Ready(Err(Box::new(error) as Failure)),
                            host::Step::Closed=>return Poll::Ready(Err("original DATASTORE source closed".into())),
                            host::Step::Capacity=>return Poll::Ready(Err(Box::new(Error::Capacity) as Failure)),
                            host::Step::ConnectRetry{error,..}=>self.reports.warning("datastore.connect.retry",format_args!("original unsent DATASTORE connect: {error}")),
                            host::Step::Written{bytes,complete,..}=>self.reports.debug("datastore.write",format_args!("original native write bytes={bytes} whole={complete}; no service result inferred")),
                            _=>{},
                        }
                        self.cursor=true;cx.waker().wake_by_ref();return Poll::Pending;
                    }
                }
            }
            Poll::Pending
        }).await;
        match result {
            Ok(taken) => {
                self.pending = None;
                self.report.last = Some(Meta::from(taken.completion));
                Ok(taken)
            }
            Err(error) => Err(self.fail(error)),
        }
    }
}
#[derive(Debug)]
struct ResolverCleanup(Option<Failure>);
struct ResolverOwner {
    driver: gnunet_resolver_broker::Driver<4, 256>,
    cleanup: Rc<RefCell<ResolverCleanup>>,
    closed: bool,
}
impl ResolverOwner {
    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            let result = self.driver.disconnect();
            if let Err(error) = result {
                self.cleanup.borrow_mut().0 = Some(Box::new(error));
            }
        }
    }
}
impl Drop for ResolverOwner {
    fn drop(&mut self) {
        self.close();
    }
}
fn buffer(length: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    Ok(Zeroizing::new(bytes))
}
pub(super) async fn command(inputs: Inputs) -> Result<Report, Failure> {
    let Inputs {
        dump,
        insert,
        path,
        parent,
        live,
        resolution,
        source,
        reports,
        stop,
        resolver,
    } = inputs;
    let cleanup = Rc::new(RefCell::new(ResolverCleanup(None)));
    let mut resolver = ResolverOwner {
        driver: resolver,
        cleanup: cleanup.clone(),
        closed: false,
    };
    let streams = Rc::new(RefCell::new(stream::Cleanup::default()));
    let mut report = Report::default();
    let mut client_close = Close::default();
    let result: Result<(), Failure> = async {
        if stop.get() || reports.failed() {
            return Err("DATASTORE stopped before native admission".into());
        }
        let signals = Signals::new(parent)?;
        let mut instance = host::Instance::new();
        let mut storage = buffer(65535)?;
        let mut slots = [host::Slot::new(&mut storage)];
        let mut reservations = [host::ReservationSlot::default()];
        let protocol = host::ProtocolClient::new(
            &mut instance,
            &mut slots,
            &mut reservations,
            host::ProtocolLimits {
                max_pending: 1,
                max_frame_bytes: 65535,
                max_lifetime: Timeout(30_000_000),
                drain_timeout: Timeout(5_000_000),
            },
        )?;
        let endpoint = EndpointSource::live(live, b"datastore", resolution).snapshot()?;
        let client = Client::new(
            protocol,
            endpoint,
            host::Limits {
                frame_bytes: 65535,
                reply_frames: 1,
                reply_bytes: 65535,
                io_slice_bytes: 65535,
            },
        )?;
        let mut driver = Driver {
            client,
            resolver: &mut resolver.driver,
            signals,
            source: source.clone(),
            reports: reports.clone(),
            stop: stop.clone(),
            pending: None,
            report: Report::default(),
            cursor: false,
            closed: false,
        };
        let actual = work(&mut driver, dump, insert, path.as_deref(), streams.clone()).await;
        client_close = driver.close();
        report = driver.report;
        actual
    }
    .await;
    resolver.close();
    let resolver_error = cleanup.borrow_mut().0.take();
    let streams = std::mem::take(&mut *streams.borrow_mut());
    let logging = reports.take_error();
    let source_failed = client_close.native.is_some() || client_close.take.is_some();
    let stream_failed = streams.overflowed || streams.errors.iter().any(Option::is_some);
    if result.is_err()
        || source_failed
        || resolver_error.is_some()
        || stream_failed
        || logging.is_some()
    {
        Err(Box::new(Failed {
            original: result.err(),
            client: client_close,
            resolver: resolver_error,
            streams,
            logging,
            report,
        }))
    } else {
        Ok(report)
    }
}
async fn work(
    driver: &mut Driver<'_, '_, '_, '_>,
    dump: bool,
    insert: bool,
    path: Option<&std::path::Path>,
    retained: stream::Retained,
) -> Result<(), Failure> {
    if dump {
        let mut budget = driver.budget()?;
        driver.check(&mut budget).await?;
        let mut output = Stream::output(path, retained.clone())?;
        output
            .write_all(driver, &mut budget, &format::MAGIC, "dump magic")
            .await?;
        loop {
            let mut budget = driver.budget()?;
            let next_uid = driver.report.next_uid;
            let taken = driver
                .operation(
                    Request::Get {
                        key: None,
                        kind: 0,
                        next_uid,
                        random: false,
                    },
                    &mut budget,
                )
                .await?;
            match (taken.completion.outcome, taken.response()?) {
                (Outcome::Data { uid }, Some(Response::Data(data))) if uid == data.uid => {
                    if uid < next_uid {
                        return Err("actual DATA UID did not advance the original cursor".into());
                    }
                    let next = uid.checked_add(1).ok_or("actual DATA UID overflow")?;
                    let header = Record::from_data(data)?.encode()?;
                    output
                        .write_all(driver, &mut budget, &header, "dump record header")
                        .await?;
                    output
                        .write_all(driver, &mut budget, data.value, "dump record body")
                        .await?;
                    driver.report.dumped = driver
                        .report
                        .dumped
                        .checked_add(1)
                        .ok_or("dumped count overflow")?;
                    driver.report.next_uid = next;
                }
                (Outcome::NotFound, Some(Response::End)) => break,
                _ => {
                    return Err(format!(
                        "original dump operation did not return DATA/END; completion={:?}",
                        driver.report.last
                    )
                    .into());
                }
            }
        }
        output.finish()?;
        driver.reports.message(
            Level::INFO,
            "datastore.dump.complete",
            format_args!("Dumped {} records", driver.report.dumped),
        );
    }
    if insert {
        let mut budget = driver.budget()?;
        driver.check(&mut budget).await?;
        let mut input = Stream::input(path, retained)?;
        let mut magic = [0; 16];
        input
            .read_exact(driver, &mut budget, &mut magic, false, "input magic")
            .await?;
        if magic != format::MAGIC {
            return Err("input is not GNUNETDATASTORE1".into());
        }
        let mut value = buffer(MAX_VALUE_BYTES)?;
        loop {
            let mut budget = driver.budget()?;
            let mut header = [0; format::HEADER];
            if !input
                .read_exact(
                    driver,
                    &mut budget,
                    &mut header,
                    true,
                    "input record header",
                )
                .await?
            {
                break;
            }
            let record = Record::decode(&header)?;
            value.as_mut_slice().zeroize();
            input
                .read_exact(
                    driver,
                    &mut budget,
                    &mut value[..record.size],
                    false,
                    "input record body",
                )
                .await?;
            let taken = driver
                .operation(
                    Request::Put(record.put(&value[..record.size])?),
                    &mut budget,
                )
                .await?;
            match (taken.completion.outcome, taken.response()?) {
                (
                    Outcome::Status {
                        code,
                        min_expiration,
                    },
                    Some(Response::Status(status)),
                ) if code == status.code && min_expiration == status.min_expiration => {
                    if code < 0 {
                        let diagnostic = if let Some(bytes) = status.message {
                            let mut owned = Vec::new();
                            owned.try_reserve_exact(bytes.len())?;
                            owned.extend_from_slice(bytes);
                            Some(Diagnostic(Zeroizing::new(owned)))
                        } else {
                            None
                        };
                        return Err(Box::new(RejectedStatus {
                            code,
                            min_expiration: min_expiration.as_micros(),
                            diagnostic,
                        }));
                    }
                    driver.report.inserted = driver
                        .report
                        .inserted
                        .checked_add(1)
                        .ok_or("insert count overflow after actual successful STATUS")?;
                }
                _ => {
                    return Err(format!(
                        "original PUT has no successful actual STATUS; completion={:?}",
                        driver.report.last
                    )
                    .into());
                }
            }
            value.as_mut_slice().zeroize();
        }
        input.finish()?;
        driver.reports.message(
            Level::INFO,
            "datastore.insert.complete",
            format_args!("Inserted {} records", driver.report.inserted),
        );
    }
    Ok(())
}
pub(super) fn finish(result: Result<Report, Failure>, reports: Reporter) -> Result<(), Failure> {
    if let Ok(report) = &result {
        reports.debug(
            "datastore.completed",
            format_args!("actual DATASTORE counters={report:?}"),
        );
    }
    let logging = reports.take_error();
    let completed = result.as_ref().ok().copied().unwrap_or_default();
    if logging.is_some() {
        Err(Box::new(Failed {
            original: result.err(),
            client: Close::default(),
            resolver: None,
            streams: stream::Cleanup::default(),
            logging,
            report: completed,
        }))
    } else {
        result.map(|_| ())
    }
}
