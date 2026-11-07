//! Ordinary configured RPS command; original PROGRAM/Resolver/source ownership.
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_rps_client_host::{
    Bounds, Client, EndpointSource, Epoch, Limits, Loss, Peer, Progress, Query, ReplyCountProfile,
};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::signal::unix::{Signal, SignalKind};
pub(super) type Failure = Box<dyn std::error::Error>;
#[derive(Clone, Copy)]
pub(super) enum Selection {
    Sample(usize),
    View(u32),
    Stream,
    Seed(Peer),
}
fn number(bytes: &[u8]) -> Result<usize, Failure> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err("RPS count must be a nonnegative decimal integer".into());
    }
    let mut value = 0usize;
    for b in bytes {
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(*b - b'0')))
            .ok_or("RPS count overflow")?;
    }
    Ok(value)
}
impl Selection {
    pub(super) fn read(
        seed: Option<Vec<u8>>,
        view: bool,
        stream: bool,
        args: &[Vec<u8>],
    ) -> Result<Self, Failure> {
        if usize::from(seed.is_some()) + usize::from(view) + usize::from(stream) > 1 {
            return Err("select only one of --seed, --view and --stream".into());
        }
        if seed.is_some() || stream {
            if !args.is_empty() {
                return Err("seed/stream mode accepts no positional count".into());
            }
        } else if args.len() > 1 {
            return Err("RPS accepts at most one positional count".into());
        }
        if let Some(seed) = seed {
            if seed.len() != 52 {
                return Err(
                    "RPS seed requires the full52-character Crockford peer identity".into(),
                );
            }
            let mut cfg = gnunet_config::Configuration::new(Default::default());
            cfg.set_value(b"seed", b"public", Some(&seed))?;
            let mut peer = [0; 32];
            cfg.get_data(b"seed", b"public", &mut peer)?;
            Ok(Self::Seed(peer))
        } else if stream {
            Ok(Self::Stream)
        } else if view {
            Ok(Self::View(
                args.first().map_or(Ok(0), |v| number(v))?.try_into()?,
            ))
        } else {
            Ok(Self::Sample(args.first().map_or(Ok(1), |v| number(v))?))
        }
    }
    fn continuous(self) -> bool {
        matches!(self, Self::View(0) | Self::Stream)
    }
}
#[derive(Clone, Copy)]
pub(super) struct Settings {
    native: Limits,
    total: Duration,
    output: Duration,
    max_output: usize,
    resolver: gnunet_resolver_broker::Limits,
}
fn time(
    c: &gnunet_config::Configuration,
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
    let d = if c.have_value(b"rps-client-rust", key) {
        Duration::from_micros(c.get_time(b"rps-client-rust", key)?)
    } else {
        default
    };
    if d.is_zero()
        || d.as_micros() >= u128::from(u64::MAX)
        || std::time::Instant::now().checked_add(d).is_none()
    {
        return Err("RPS local deadlines must be finite and nonzero".into());
    }
    Ok(d)
}
fn size(c: &gnunet_config::Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(if c.have_value(b"rps-client-rust", key) {
        c.get_size(b"rps-client-rust", key)?.try_into()?
    } else {
        default
    })
}
impl Settings {
    pub(super) fn read(
        c: &gnunet_config::Configuration,
        selection: Selection,
    ) -> Result<Self, Failure> {
        let defaults = Limits::default();
        let native = Limits {
            frame_bytes: size(c, b"MAX_FRAME_BYTES", defaults.frame_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", defaults.io_slice_bytes)?,
            max_sample_peers: size(c, b"MAX_SAMPLE_PEERS", defaults.max_sample_peers)?,
            initial_timeout: time(c, b"INITIAL_TIMEOUT", defaults.initial_timeout)?,
            input_timeout: time(c, b"INPUT_TIMEOUT", defaults.input_timeout)?,
            reply_profile: match c.get(b"rps-client-rust", b"REPLY_COUNT_PROFILE") {
                None | Some(b"native") => ReplyCountProfile::native(),
                Some(b"little") => ReplyCountProfile::CNativeLittle,
                Some(b"big") => ReplyCountProfile::CNativeBig,
                _ => return Err("RPS REPLY_COUNT_PROFILE must be native, little or big".into()),
            },
        };
        let max_output = size(c, b"MAX_OUTPUT_BYTES", 4 * 1024 * 1024)?;
        if !(128..=16 * 1024 * 1024).contains(&max_output) || native.max_sample_peers > 65536 {
            return Err("RPS local output/sample resource limit out of range".into());
        }
        if let Selection::Sample(n) = selection
            && (n > native.max_sample_peers || n.checked_mul(53).is_none_or(|n| n > max_output))
        {
            return Err("RPS sample demand exceeds the explicit local budget".into());
        }
        Ok(Self {
            native,
            max_output,
            resolver: Default::default(),
            total: time(
                c,
                b"TOTAL_TIMEOUT",
                Duration::from_secs(if selection.continuous() { 3600 } else { 60 }),
            )?,
            output: time(c, b"OUTPUT_TIMEOUT", Duration::from_secs(10))?,
        })
    }
}
#[derive(Debug)]
struct Failures {
    original: Option<Failure>,
    cleanup: Vec<Failure>,
    retirement: Option<Loss>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.original {
            write!(f, "RPS: {e}")?;
        }
        if let Some(loss) = &self.retirement {
            write!(f, "; original source cleanup: {loss}")?;
        }
        for e in &self.cleanup {
            write!(f, "; cleanup: {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.first().map(|e| e.as_ref()))
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
                    return Poll::Ready(Err(io::Error::other("RPS signal stream ended")));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
struct Resolver {
    driver: gnunet_resolver_broker::Driver<16, 1024>,
    closed: bool,
    reporter: Reporter,
    dropped: Rc<RefCell<Option<Failure>>>,
}
impl Drop for Resolver {
    fn drop(&mut self) {
        if !self.closed
            && let Err(error) = self.driver.disconnect()
        {
            self.reporter.warning(
                "rps.resolver.drop",
                format_args!("RPS canceled PROGRAM Resolver cleanup: {error}"),
            );
            *self.dropped.borrow_mut() = Some(Box::new(error));
        }
    }
}
struct Native {
    client: Client,
    closed: bool,
    reporter: Reporter,
    dropped: Rc<RefCell<Option<Failure>>>,
}
impl Native {
    fn close(&mut self) -> Loss {
        self.closed = true;
        self.client.close()
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        if !self.closed {
            let loss = self.client.close();
            self.reporter.debug(
                "rps.source.drop",
                format_args!("RPS PROGRAM canceled original owner: {loss}"),
            );
            *self.dropped.borrow_mut() = Some(Box::new(loss));
        }
    }
}
/// Run through the actual prepared PROGRAM and its shared Resolver scheduler.
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
) -> Result<(), Failure> {
    if reporter.failed() {
        return Err("selected RPS Logger failed".into());
    }
    let config = prepared.main().config.duplicate()?;
    let canonical: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = gnunet_resolver_broker::LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<16, 1024>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        canonical.clone(),
    )?;
    let dropped = Rc::new(RefCell::new(None));
    let native_dropped = Rc::new(RefCell::new(None));
    let resolver = Resolver {
        driver: resolver,
        closed: false,
        reporter: reporter.clone(),
        dropped: dropped.clone(),
    };
    let result = Rc::new(RefCell::new(None::<Result<(), Failure>>));
    let receiving = result.clone();
    let receipt = native_dropped.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = receiving.clone();
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                *destination.borrow_mut() = Some(
                    run(
                        resolver, live, canonical, settings, selection, reporter, receipt,
                    )
                    .await,
                );
                if let Err(error) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(error)],
                        retirement: None,
                    })));
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(error)));
                if let Err(error) = scope.shutdown() {
                    let original = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(error)],
                        retirement: None,
                    })));
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without RPS command completion".into()));
    let program: Option<Failure> = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("RPS PROGRAM returned {code}").into()),
        Err(e) => Some(Box::new(e)),
    };
    let mut cleanup: Vec<Failure> = program.into_iter().collect();
    if let Some(error) = dropped.borrow_mut().take() {
        cleanup.push(error);
    }
    if let Some(loss) = native_dropped.borrow_mut().take() {
        cleanup.push(loss);
    }
    match task {
        Ok(()) if cleanup.is_empty() => Ok(()),
        task => Err(Box::new(Failures {
            original: task.err(),
            cleanup,
            retirement: None,
        })),
    }
}
fn same(actual: &Epoch, expected: &Option<Epoch>) -> Result<(), Failure> {
    if expected.as_ref() != Some(actual) {
        return Err("RPS observation from a different physical source".into());
    }
    Ok(())
}
async fn run(
    mut resolver: Resolver,
    live: gnunet_client_host::LiveConfiguration,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
    dropped: Rc<RefCell<Option<Failure>>>,
) -> Result<(), Failure> {
    // Register signals before constructing a sampler or exposing native IO.
    let mut signals = Signals::new()?;
    let bounds = Bounds::new(clock.as_ref(), settings.total)?;
    let source = EndpointSource::live(live, b"rps", resolver.driver.context().resolution_context());
    let seed = match selection {
        Selection::Seed(peer) => Some(peer),
        _ => None,
    };
    let query = match selection {
        Selection::Sample(count) => Query::Sample { count },
        Selection::View(updates) => Query::View { updates },
        Selection::Stream => Query::Stream,
        Selection::Seed(_) => Query::Seed {
            peers: std::slice::from_ref(seed.as_ref().ok_or("RPS seed missing")?),
        },
    };
    let mut native = Native {
        client: Client::new(source, query, settings.native, bounds)?,
        closed: false,
        reporter: reporter.clone(),
        dropped,
    };
    let mut samples = Vec::<Peer>::new();
    if let Selection::Sample(n) = selection {
        samples.try_reserve_exact(n)?;
        if samples.capacity() > settings.native.max_sample_peers {
            return Err("RPS actual sample retention exceeds budget".into());
        }
    }
    let mut output =
        crate::output::Output::new(settings.output, settings.max_output, bounds, clock)?;
    let mut epoch = None::<Epoch>;
    let mut records = 0u64;
    let mut finishing = false;
    let outcome = loop {
        enum Turn {
            Signal,
            Activity,
            Native(Progress),
            Output(bool),
        }
        let result = {
            let mut resolving = std::pin::pin!(resolver.driver.drive_waiting(None, |event| {
                reporter.debug("rps.resolver", format_args!("RPS Resolver: {event:?}"))
            }));
            poll_fn(|cx| {
                reporter.register(cx);
                if let Poll::Ready(result) = signals.poll(cx) {
                    return Poll::Ready(
                        result
                            .map(|()| Turn::Signal)
                            .map_err(|e| Box::new(e) as Failure),
                    );
                }
                if let Some(loss) = native.client.poll_native_guard(cx) {
                    return Poll::Ready(Ok(Turn::Native(Progress::Lost(loss))));
                }
                if reporter.failed() {
                    return Poll::Ready(Err("selected RPS Logger failed".into()));
                }
                let resolving = match resolving.as_mut().poll(cx) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e) as Failure)),
                    Poll::Ready(Ok(_)) => true,
                    Poll::Pending => false,
                };
                if reporter.failed() {
                    return Poll::Ready(Err("selected RPS Logger failed".into()));
                }
                if let Poll::Ready(result) = output.poll(cx) {
                    return Poll::Ready(result.map(Turn::Output));
                }
                if !output.pending()
                    && !finishing
                    && let Poll::Ready(result) = native.client.poll_progress(cx)
                {
                    return Poll::Ready(
                        result.map(Turn::Native).map_err(|e| Box::new(e) as Failure),
                    );
                }
                if resolving {
                    return Poll::Ready(Ok(Turn::Activity));
                }
                Poll::Pending
            })
            .await
        };
        match result {
            Ok(Turn::Signal) => {
                let loss = native.close();
                if !selection.continuous() || output.pending() {
                    break Err(Box::new(loss) as Failure);
                }
                reporter.debug(
                    "rps.cancelled",
                    format_args!("continuous RPS command canceled: {loss}"),
                );
                break Ok(());
            }
            Ok(Turn::Activity | Turn::Output(false)) => {}
            Ok(Turn::Output(true)) => {
                if finishing {
                    break Ok(());
                }
            }
            Ok(Turn::Native(progress)) => match progress {
                Progress::Attached(source) => {
                    if epoch.replace(source).is_some() {
                        break Err("RPS source changed within original request".into());
                    }
                }
                Progress::Written { epoch: source, .. } => {
                    if let Err(e) = same(&source, &epoch) {
                        break Err(e);
                    }
                    if let Selection::Seed(peer) = selection {
                        let loss = native.close();
                        reporter.debug(
                            "rps.seed.close",
                            format_args!(
                                "seed locally whole-written, actual source closed: {loss}"
                            ),
                        );
                        if let Err(e) = output.admit_seed(&peer) {
                            break Err(e);
                        }
                        finishing = true;
                    }
                }
                Progress::Sample {
                    epoch: source,
                    ordinal,
                    info,
                } => {
                    if let Err(e) = same(&source, &epoch) {
                        break Err(e);
                    }
                    let Selection::Sample(count) = selection else {
                        break Err("unexpected RPS sampler result".into());
                    };
                    if ordinal != samples.len() + 1 || samples.len() >= count {
                        break Err("RPS sampler demand/ordinal mismatch".into());
                    }
                    samples.push(info.peer);
                }
                Progress::Record(record) => {
                    if let Err(e) = same(record.epoch(), &epoch) {
                        break Err(e);
                    }
                    let next = match records.checked_add(1) {
                        Some(n) => n,
                        None => break Err("RPS record count overflow".into()),
                    };
                    if record.ordinal() != next {
                        break Err("RPS record ordinal mismatch".into());
                    }
                    let response = match record.response() {
                        Ok(r) => r,
                        Err(e) => break Err(Box::new(e) as Failure),
                    };
                    let biased = match (selection, response) {
                        (
                            Selection::View(_),
                            gnunet_rps_client_host::ClientResponse::View { .. },
                        ) => false,
                        (
                            Selection::Stream,
                            gnunet_rps_client_host::ClientResponse::Stream { .. },
                        ) => true,
                        _ => break Err("unexpected RPS record mode".into()),
                    };
                    if let Err(e) = output.admit_record(response.peers(), biased) {
                        break Err(e);
                    }
                    records = next;
                }
                Progress::Complete { epoch: source, .. } => {
                    if source != epoch {
                        break Err("RPS local completion source mismatch".into());
                    }
                    match selection {
                        Selection::Sample(count) => {
                            if samples.len() != count {
                                break Err("RPS incomplete original sampler request".into());
                            }
                            if let Err(e) = output.admit_samples(&samples) {
                                break Err(e);
                            }
                            finishing = true;
                        }
                        Selection::View(n) if n != 0 && records == u64::from(n) => break Ok(()),
                        _ => break Err("unexpected RPS local quota completion".into()),
                    }
                }
                Progress::Retry { error } => reporter.warning(
                    "rps.source.retry",
                    format_args!("RPS initial attempt: {error}"),
                ),
                Progress::Activity => {}
                Progress::Lost(loss) | Progress::Cancelled(loss) => {
                    break Err(Box::new(loss) as Failure);
                }
                Progress::GroupWritten { .. } => {
                    break Err("unexpected subgroup write in ordinary RPS CLI".into());
                }
            },
            Err(error) => break Err(error),
        }
    };
    let retirement = native.close();
    reporter.debug(
        "rps.source.close",
        format_args!("RPS original source cleanup: {retirement}"),
    );
    drop(native);
    let mut cleanup = Vec::<Failure>::new();
    if let Some(error) = output.abandoned() {
        cleanup.push(error);
    }
    if let Err(error) = resolver.driver.disconnect() {
        cleanup.push(Box::new(error));
    }
    resolver.closed = true;
    match outcome {
        Ok(()) if cleanup.is_empty() => Ok(()),
        outcome => Err(Box::new(Failures {
            original: outcome.err(),
            cleanup,
            retirement: Some(retirement),
        })),
    }
}
