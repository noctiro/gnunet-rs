//! Actual installed gnunet-nse behavior: first estimate or continuous -m.
//! One shared PROGRAM/Resolver/clock, bounded original output, explicit shutdown.
use crate::{Bounds, Cause, EndpointSource, Instance, Limits, Progress, Stop, Subscription};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
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
mod output;
/// Original failure with independent actual cleanup errors.
pub type Failure = Box<dyn std::error::Error>;
#[derive(Debug)]
struct Failures {
    original: Option<Failure>,
    cleanup: Vec<Failure>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.original {
            write!(f, "NSE: {e}")?;
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
/// Explicit local resource policy. Native API/wire has no timeout/CANCEL fields.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Existing native subscription limits.
    pub native: Limits,
    /// First-estimate command's original finite total target.
    pub first_timeout: Duration,
    /// Optional original total monitor lifetime; None runs until actual signal.
    pub monitor_timeout: Option<Duration>,
    /// Original pre-write output target. Synchronous stdio syscall duration
    /// remains an explicit OS blocking boundary, not a cancellable deadline.
    pub output_timeout: Duration,
    /// Existing shared process Resolver resources.
    pub resolver: gnunet_resolver_broker::Limits,
}
fn time(
    c: &gnunet_config::Configuration,
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
    let value = if c.have_value(b"nse-client-rust", key) {
        Duration::from_micros(c.get_time(b"nse-client-rust", key)?)
    } else {
        default
    };
    if value.is_zero()
        || value.as_micros() >= u128::from(u64::MAX)
        || tokio::time::Instant::now().checked_add(value).is_none()
    {
        return Err("NSE command time policy must be finite and nonzero".into());
    }
    Ok(value)
}
impl Settings {
    /// Read only explicit Rust client budgets; NSE server/PoW configuration is
    /// neither interpreted nor opened by this command.
    pub fn read(c: &gnunet_config::Configuration) -> Result<Self, Failure> {
        let mut native = Limits::default();
        native.source_lifetime = time(c, b"SOURCE_LIFETIME", native.source_lifetime)?;
        native.initial_timeout = time(c, b"INITIAL_TIMEOUT", native.initial_timeout)?;
        native.input_timeout = time(c, b"INPUT_TIMEOUT", native.input_timeout)?;
        Ok(Self {
            native,
            first_timeout: time(c, b"FIRST_ESTIMATE_TIMEOUT", Duration::from_secs(60))?,
            monitor_timeout: if c.have_value(b"nse-client-rust", b"MONITOR_TIMEOUT") {
                Some(time(c, b"MONITOR_TIMEOUT", Duration::from_secs(3600))?)
            } else {
                None
            },
            output_timeout: time(c, b"OUTPUT_TIMEOUT", Duration::from_secs(10))?,
            resolver: Default::default(),
        })
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
                    return Poll::Ready(Err(io::Error::other("NSE signal stream ended")));
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
    // One actual Resolver can contribute at most one Drop disconnect error.
    dropped: Rc<RefCell<Option<Failure>>>,
}
impl Drop for Resolver {
    fn drop(&mut self) {
        if !self.closed
            && let Err(error) = self.driver.disconnect()
        {
            self.reporter.warning(
                "nse.resolver.drop",
                format_args!("NSE canceled PROGRAM Resolver cleanup: {error}"),
            );
            *self.dropped.borrow_mut() = Some(Box::new(error));
        }
    }
}
/// Run actual first-estimate/monitor command. True requires a real estimate and
/// its complete original output line; no socket connection counts as an estimate.
/// The caller supplies its selected Reporter using this same SharedClock and
/// takes its original logging error after this function has completed cleanup.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    monitor: bool,
    reporter: Reporter,
) -> Result<bool, Failure> {
    if reporter.failed() {
        return Err("selected NSE Logger failed".into());
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
    // Establish the cleanup owner before offering the future to the scheduler;
    // even a refused/unpolled task retains its real disconnect failure here.
    let resolver = Resolver {
        driver: resolver,
        closed: false,
        reporter: reporter.clone(),
        dropped: dropped.clone(),
    };
    let result = Rc::new(RefCell::new(None::<Result<bool, Failure>>));
    let receiving = result.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = receiving.clone();
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                *destination.borrow_mut() =
                    Some(run(resolver, live, canonical, settings, monitor, reporter).await);
                if let Err(error) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(error)],
                    })));
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(error)));
                if let Err(error) = scope.shutdown() {
                    let original = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(error)],
                    })));
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without NSE command completion".into()));
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("NSE PROGRAM returned {code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    let mut cleanup: Vec<Failure> = program.into_iter().collect();
    if let Some(error) = dropped.borrow_mut().take() {
        cleanup.push(error);
    }
    match task {
        Ok(seen) if cleanup.is_empty() => Ok(seen),
        task => Err(Box::new(Failures {
            original: task.err(),
            cleanup,
        })),
    }
}
fn original<'a>(
    progress: Progress<'a>,
    reporter: &Reporter,
) -> Result<Option<crate::Observation<'a>>, Failure> {
    match progress {
        Progress::Estimate(value) => Ok(Some(value)),
        Progress::Lost { report, cause } => {
            reporter.warning(
                "nse.source.lost",
                format_args!("NSE original source {report:?}: {cause:?}"),
            );
            match cause {
                Cause::Port(error) => Err(Box::new(error)),
                Cause::Clock(error) => Err(Box::new(error)),
                _ => Ok(None),
            }
        }
        Progress::Retry { error, delay } => {
            reporter.warning(
                "nse.source.retry",
                format_args!("NSE connection retry after {delay:?}: {error}"),
            );
            Ok(None)
        }
        Progress::Unavailable(error) => {
            reporter.warning(
                "nse.source.unavailable",
                format_args!("NSE endpoint: {error}"),
            );
            Ok(None)
        }
        Progress::Stopped {
            reason: Stop::Deadline,
            ..
        } => Err("NSE original subscription deadline expired".into()),
        _ => Ok(None),
    }
}
async fn run(
    mut resolver: Resolver,
    live: gnunet_client_host::LiveConfiguration,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    monitor: bool,
    reporter: Reporter,
) -> Result<bool, Failure> {
    let mut signals = Signals::new()?;
    let source = EndpointSource::live(live, b"nse", resolver.driver.context().resolution_context());
    let total = if monitor {
        settings
            .monitor_timeout
            .map(|d| Bounds::after(clock.as_ref(), d))
            .transpose()?
    } else {
        Some(Bounds::after(clock.as_ref(), settings.first_timeout)?)
    };
    let mut instance = Instance::new();
    let mut subscription = Subscription::new(&mut instance, source, total, settings.native)?;
    let mut output = output::Output::new(settings.output_timeout)?;
    let mut delivered = false;
    let mut finishing = false;
    let outcome = loop {
        enum Turn<'a> {
            Signal,
            Activity,
            Native(Progress<'a>),
            Output,
        }
        let result = {
            let mut resolving = std::pin::pin!(resolver.driver.drive_waiting(None, |event| {
                reporter.debug("nse.resolver", format_args!("NSE Resolver: {event:?}"))
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
                // Native original deadlines are checked/registered even if stdout is
                // backpressured or the canonical clock never stabilizes.
                let guard = subscription.poll_native_guard(cx);
                if let Some(result) = guard {
                    return Poll::Ready(
                        result.map(Turn::Native).map_err(|e| Box::new(e) as Failure),
                    );
                }
                if reporter.failed() {
                    return Poll::Ready(Err("selected NSE Logger failed".into()));
                }
                let resolver_ready = match resolving.as_mut().poll(cx) {
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error) as Failure)),
                    Poll::Ready(Ok(_)) => true,
                    Poll::Pending => false,
                };
                if reporter.failed() {
                    return Poll::Ready(Err("selected NSE Logger failed".into()));
                }
                if let Poll::Ready(result) = output.poll(cx) {
                    return Poll::Ready(result.map(|_| Turn::Output));
                }
                if !output.pending()
                    && !finishing
                    && let Poll::Ready(result) = subscription.poll(cx, None)
                {
                    return Poll::Ready(
                        result.map(Turn::Native).map_err(|e| Box::new(e) as Failure),
                    );
                }
                if resolver_ready {
                    return Poll::Ready(Ok(Turn::Activity));
                }
                Poll::Pending
            })
            .await
        };
        match result {
            Ok(Turn::Signal) => {
                if output.pending() {
                    break Err("NSE canceled with an incomplete original stdout line".into());
                }
                break Ok(delivered);
            }
            Ok(Turn::Output) => {
                delivered = true;
                if finishing {
                    break Ok(true);
                }
            }
            Ok(Turn::Activity) => {}
            Ok(Turn::Native(progress)) => match original(progress, &reporter) {
                Ok(Some(observation)) => {
                    if let Err(error) = output.admit(observation.estimate) {
                        break Err(error);
                    }
                    if !monitor {
                        let actual = subscription.close();
                        reporter.debug(
                            "nse.source.close",
                            format_args!("first-estimate original source retired: {actual:?}"),
                        );
                        finishing = true;
                    }
                }
                Ok(None) => {}
                Err(error) => break Err(error),
            },
            Err(error) => break Err(error),
        }
    };
    // Physical original source retirement precedes Resolver shutdown. stdout
    // has an explicit synchronous OS boundary; no descriptor flags changed.
    let actual = subscription.close();
    reporter.debug(
        "nse.source.close",
        format_args!("original source retired: {actual:?}"),
    );
    drop(subscription);
    let mut cleanup: Vec<Failure> = Vec::new();
    if let Err(error) = resolver.driver.disconnect() {
        cleanup.push(Box::new(error));
    }
    resolver.closed = true;
    if cleanup.is_empty() {
        outcome
    } else {
        Err(Box::new(Failures {
            original: outcome.err(),
            cleanup,
        }))
    }
}
