//! One caller-owned SERVICE future, original Server/Worker and shared Resolver.
use crate::{
    Failure,
    control::Signals,
    lifecycle::{Grace, Notes, Resolver, Terminal},
    settings::Settings,
};
use gnunet_config::Configuration;
use gnunet_identity_host::{
    backend::{Namespace, Store},
    server::{self, Progress, Server},
    worker::Worker,
};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_resolver_broker::LiveConfiguration;
use gnunet_service_runtime::{
    BoundListeners,
    clock::RuntimeClock,
    service::{Listener, ShutdownMode},
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};

/// Observe already-installed signals without waiting or creating a new task.
async fn before_start(signals: &mut Signals, reports: &Reporter) -> Result<(), Failure> {
    poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Err(io::Error::other(
                "IDENTITY selected Logger failed before readiness; original error retained",
            )
            .into()));
        }
        match signals.poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "IDENTITY stopped before readiness",
            )
            .into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending => Poll::Ready(Ok(())),
        }
    })
    .await
}

enum Turn {
    Signal,
    DiagnosticStop,
    Deadline,
    Resolver,
    Server(Progress),
}

#[expect(
    clippy::too_many_arguments,
    reason = "One original Server, Resolver, stop, native grace, Logger and listener owners are polled explicitly"
)]
async fn turn(
    server: &mut Server<'_>,
    resolver: &mut Resolver,
    signals: &mut Signals,
    listeners: &[Listener<'_>],
    grace: &mut Option<Grace>,
    resolver_first: bool,
    reports: &Reporter,
    notes: &Notes,
) -> Result<Turn, Failure> {
    poll_fn(|cx| {
        reports.register(cx);
        // Original native target is checked before either provider can sample
        // the canonical clock or start another socket/worker effect.
        if grace.as_mut().is_some_and(|guard| guard.poll(cx)) {
            return Poll::Ready(Ok(Turn::Deadline));
        }
        if reports.failed() {
            return Poll::Ready(Ok(Turn::DiagnosticStop));
        }
        if let Poll::Ready(signal) = signals.poll(cx) {
            return Poll::Ready(signal.map(|()| Turn::Signal).map_err(Into::into));
        }
        for n in 0..2 {
            if grace.as_mut().is_some_and(|guard| guard.poll(cx)) {
                return Poll::Ready(Ok(Turn::Deadline));
            }
            // Resolver diagnostics may fail while that class returns Pending.
            // Do not admit new Server IO later in the same turn after failure.
            if reports.failed() {
                return Poll::Ready(Ok(Turn::DiagnosticStop));
            }
            let until = grace.as_ref().map(|guard| guard.hard);
            if (n == 0) == resolver_first {
                if let Poll::Ready(result) = resolver.poll(cx, until, reports) {
                    return Poll::Ready(result.map(|_| Turn::Resolver).map_err(Into::into));
                }
            } else if let Poll::Ready(result) =
                server.poll(cx, listeners, until, &mut |event| notes.observe(event))
            {
                return Poll::Ready(result.map(Turn::Server).map_err(Into::into));
            }
        }
        Poll::Pending
    })
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Readiness and stop retain the original native/Server/listener/Logger owners without another runtime"
)]
async fn serve(
    server: &mut Server<'_>,
    resolver: &mut Resolver,
    signals: &mut Signals,
    bound: &BoundListeners,
    settings: &Settings,
    reports: &Reporter,
    notes: &Notes,
    child: &mut ChildReady,
    generation: u64,
    egos: usize,
    recovered: usize,
) -> (Result<(), Failure>, Option<Grace>) {
    let ready = async {
        before_start(signals, reports).await?;
        reports.message(
            Level::INFO,
            "identity.ready",
            format_args!(
                "IDENTITY actual listeners, recovered inventory and original Server/Worker prepared; generation={generation} egos={egos} recovered-pending={recovered}"
            ),
        );
        if reports.failed() {
            return Err(io::Error::other(
                "IDENTITY readiness diagnostic failed; original logging error retained",
            )
            .into());
        }
        {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "READY identity wire=0.29.1 store=rust-marked-snapshot-v1 generation={generation} egos={egos} recovered-pending={recovered} disk-workers=1"
            )?;
            out.flush()?;
        }
        // Only after real readiness and successful stdout flush is the original
        // daemon child permitted to send its single startup status byte.
        child.ready()?;
        Ok::<(), Failure>(())
    }
    .await;
    if let Err(error) = ready {
        return (Err(error), None);
    }
    let listeners = bound.listeners();
    let mut grace = None;
    let mut resolver_first = false;
    let outcome = loop {
        let next = turn(
            server,
            resolver,
            signals,
            &listeners,
            &mut grace,
            resolver_first,
            reports,
            notes,
        )
        .await;
        resolver_first = !resolver_first;
        match next {
            Ok(Turn::Signal)
                if grace.is_none() && settings.options.shutdown == ShutdownMode::Soft =>
            {
                server.request_shutdown(ShutdownMode::Soft);
                match Grace::new(settings.grace) {
                    Ok(original) => grace = Some(original),
                    Err(error) => break Err(error.into()),
                }
            }
            Ok(
                Turn::Signal
                | Turn::DiagnosticStop
                | Turn::Deadline
                | Turn::Server(Progress::Stopped | Progress::WaitDeadline),
            ) => break Ok(()),
            Ok(Turn::Resolver | Turn::Server(Progress::Activity)) => {}
            Err(error) => break Err(error),
        }
    };
    (outcome, grace)
}

fn retire_resolver(resolver: &mut Resolver, terminal: &mut Terminal) {
    if let Some(error) = resolver.close() {
        terminal.resolver = Some(error);
    }
}

/// A native observation budget may expire while actual filesystem IO is still
/// pending. Record that fact once and keep polling the same original join.
async fn wait_original<F: Future>(
    original: F,
    grace: &mut Option<Grace>,
    terminal: &mut Terminal,
    reports: &Reporter,
) -> F::Output {
    let mut original = std::pin::pin!(original);
    poll_fn(|cx| {
        reports.register(cx);
        if !terminal.grace_elapsed && grace.as_mut().is_some_and(|guard| guard.poll(cx)) {
            terminal.grace_elapsed = true;
            reports.warning(
                "identity.shutdown.wait",
                format_args!(
                    "IDENTITY original native grace elapsed; original disk drain/join remains pending and is not canceled or reported complete"
                ),
            );
        }
        original.as_mut().poll(cx)
    })
    .await
}

fn cleanup_grace(grace: &mut Option<Grace>, terminal: &mut Terminal, settings: &Settings) {
    if grace.is_none() {
        match Grace::new(settings.grace) {
            Ok(original) => *grace = Some(original),
            Err(error) => terminal.deadline = Some(error),
        }
    }
}

pub(super) async fn run(
    config: Configuration,
    settings: Settings,
    bound: BoundListeners,
    parent: Option<ParentControl>,
    clock: Arc<dyn RuntimeClock>,
    reports: Reporter,
    child: &mut ChildReady,
) -> Result<Terminal, Failure> {
    let mut signals = Signals::new(parent)?;
    for error in bound.failures() {
        reports.warning(
            "identity.listener.alternate",
            format_args!("IDENTITY alternate listener: {error}"),
        );
    }
    before_start(&mut signals, &reports).await?;
    let live = LiveConfiguration::new(config);
    let (_context, original_resolver) = gnunet_resolver_broker::broker::<8, 256>(
        live,
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        clock.clone(),
    )?;
    let mut resolver = Resolver::new(original_resolver);
    let notes = Notes::new(reports.clone());
    let mut terminal = Terminal::default();
    // All fallible work after the original Resolver is inside this finally
    // boundary. All fallible work after Worker::start has a second boundary.
    let outcome = async {
        before_start(&mut signals, &reports).await?;
        gnunet_service_runtime::private_parents(&settings.directory)?;
        let (mut store, loaded) =
            Store::open(Namespace::Identity, &settings.directory, settings.backend)?;
        let recovered = loaded.recovered_temporaries();
        let (core, generation) = Server::recover(&mut store, loaded, settings.core)?;
        let egos = core.snapshot().egos().len();
        before_start(&mut signals, &reports).await?;
        let mut worker = Worker::start(store)?;
        let mut grace = None;
        let hosted = async {
            before_start(&mut signals, &reports).await?;
            // Construction only borrows this same explicitly started worker.
            let mut server = Server::new(
                core,
                &mut worker,
                generation,
                settings.native,
                server::Ports {
                    options: settings.options.clone(),
                    unix: settings.unix,
                    clock,
                },
            )?;
            let (operation, original_grace) = serve(
                &mut server,
                &mut resolver,
                &mut signals,
                &bound,
                &settings,
                &reports,
                &notes,
                child,
                generation,
                egos,
                recovered,
            )
            .await;
            terminal.operation = operation.err();
            grace = original_grace;
            cleanup_grace(&mut grace, &mut terminal, &settings);
            // Physical source closure precedes any wait, even with a failed
            // canonical clock or selected Logger. No callback is reconstructed.
            server.close_all(&mut |event| notes.observe(event));
            retire_resolver(&mut resolver, &mut terminal);
            let stopped = wait_original(
                server.shutdown(|event| notes.observe(event)),
                &mut grace,
                &mut terminal,
                &reports,
            )
            .await;
            terminal.server = Some(stopped);
            Ok::<(), Failure>(())
        }
        .await;
        // The completed inner future has released its Server/worker borrow.
        // Constructor failure cannot escape to emergency Drop as a claimed join.
        if let Err(error) = hosted {
            terminal.operation = Some(error);
            retire_resolver(&mut resolver, &mut terminal);
            cleanup_grace(&mut grace, &mut terminal, &settings);
            let stopped = wait_original(
                worker.shutdown(|completion| {
                    let (job, actual) = completion.into_parts();
                    reports.debug(
                        "identity.constructor.worker",
                        format_args!(
                            "IDENTITY original constructor cleanup completion job={} successful={}",
                            job.value(),
                            actual.is_ok()
                        ),
                    );
                    if let Err(error) = actual {
                        notes.observe(server::Event::StorageFailed(error));
                    }
                }),
                &mut grace,
                &mut terminal,
                &reports,
            )
            .await;
            terminal.constructor_worker = Some(stopped.map_err(server::Error::from));
        }
        Ok::<(), Failure>(())
    }
    .await;
    if let Err(error) = outcome {
        terminal.operation = Some(error);
    }
    retire_resolver(&mut resolver, &mut terminal);
    drop(resolver);
    // Same actual listeners close before their original owned paths unlink.
    drop(bound);
    terminal.diagnostics = notes.take();
    if terminal.server.is_some() || terminal.constructor_worker.is_some() {
        reports.debug(
            "identity.stopped",
            format_args!(
                "IDENTITY original shutdown={:?}; constructor-worker={:?}; resolver={:?}; grace-elapsed={}",
                terminal.server,
                terminal.constructor_worker,
                terminal.resolver,
                terminal.grace_elapsed
            ),
        );
        terminal.output = {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "STOPPED identity shutdown={:?} constructor-worker={:?} resolver={:?} grace-elapsed={}",
                terminal.server,
                terminal.constructor_worker,
                terminal.resolver,
                terminal.grace_elapsed
            )
            .and_then(|()| out.flush())
            .err()
        };
    }
    // Do not turn a successful shutdown report into a fabricated startup byte.
    // The outer caller retains this exact Terminal for Logger-only failures too.
    Ok(terminal)
}
