//! RPS execution over the original PROGRAM, Resolver and native source.
use crate::input::{Selection, Settings};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_rps_client_host::{Bounds, Client, EndpointSource, Epoch, Loss, Peer, Progress, Query};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::{ClientStartup, StopSignals};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    rc::Rc,
    sync::Arc,
    task::Poll,
};
pub(super) type Failure = Box<dyn std::error::Error>;
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
    startup: ClientStartup,
) -> Result<(), Failure> {
    if reporter.failed() {
        return Err("selected RPS Logger failed".into());
    }
    let signals = StopSignals::for_client(startup.parent)?;
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
                    run(Inputs {
                        resolver,
                        live,
                        clock: canonical,
                        settings,
                        selection,
                        reporter,
                        dropped: receipt,
                        signals,
                    })
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
struct Inputs {
    resolver: Resolver,
    live: gnunet_client_host::LiveConfiguration,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
    dropped: Rc<RefCell<Option<Failure>>>,
    signals: StopSignals,
}
async fn run(input: Inputs) -> Result<(), Failure> {
    let Inputs {
        mut resolver,
        live,
        clock,
        settings,
        selection,
        reporter,
        dropped,
        mut signals,
    } = input;
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
                if let Poll::Ready(result) = signals.poll_stop(cx) {
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
