//! Standard Rust PILS SERVICE over the existing actual private authority owner.
#![deny(unsafe_code)]
use gnunet_pils_host::{
    service::{CloseCause, Handled, Limits, Progress},
    startup,
};
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::Environment,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_startup::{
    GroupsProfile, InheritedMode, InheritedResources, apply_privileges, configured_user,
    daemon::{self, Branch},
    resolve_user,
};
use std::{
    cell::RefCell,
    error::Error,
    fmt,
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
    task::{Context, Poll, Waker},
};
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            // Only failures before actual option/logger selection reach here.
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-service-pils: {error}");
            ExitCode::FAILURE
        }
    }
}
fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Fresh process uniquely adopts transferred descriptors before configuration, runtime, workers or private authority preparation"
    )]
    // SAFETY: first initialization operation, before any competing FD owners or
    // tasks exist. Parent declarations are consumed exactly once.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("PILS received the wrong inherited startup route".into());
        }
    };
    let notice = captured.control_notice;
    let parent_control = captured.parent_control;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"pils", std::process::id(), true)?;
    let selected = match service::prepare(
        b"pils",
        &gnunet_config::ProjectData::default(),
        std::env::args_os(),
        &Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )? {
        Preparation::Ready(selected) => selected,
        Preparation::Stopped { successful } => {
            return Ok(if successful {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
    };
    #[expect(
        unsafe_code,
        reason = "Explicit fresh single-threaded daemon phase precedes runtime, NSS, key/root preparation, path guards, tasks and workers; flushed temporary stdio locks have dropped"
    )]
    // SAFETY: only original inherited FD owners, config-free parsed options and
    // the selected Logger/clock exist; no lock or active task is retained.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(parent)) => {
            drop(activation);
            drop(parent_control);
            let result = parent
                .wait()
                .map(|_| ())
                .map_err(|error| Box::new(error) as Failure);
            return complete(result, &mut logger, &clock);
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            return complete(Err(Box::new(error)), &mut logger, &clock);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let diagnostics = Diagnostics::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            diagnostics.message(
                "pils.parent",
                Level::WARNING,
                format_args!("pils parent-control declaration: {notice:?}"),
            )?;
        }
        let config = startup::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let unix = startup::unix_access(&config)?;
        let user = configured_user(&config, b"PILS")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // No service task, private authority or worker exists. Only original
        // activation is adopted or synchronous TCP ports are prebound here.
        let listeners = {
            let _entered = runtime.enter();
            gnunet_service_runtime::BoundListeners::prepare_before_identity(
                &config, b"PILS", activation,
            )?
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            diagnostics.message(
                "pils.identity",
                Level::INFO,
                format_args!("pils configured process identity: {privileges:?}"),
            )?;
        }
        // New Unix inode guards are created by the selected account. The real
        // original activation/TCP sockets are retained, never reopened/chowned.
        let bound = runtime.block_on(listeners.finish_with_access(
            gnunet_service_runtime::UnixListenerAccess {
                match_uid: unix.match_uid,
                match_gid: unix.match_gid,
            },
        ))?;
        // Existing actual raw-root/private provider preparation runs outside
        // polling under the correct identity; no secret algorithm is replaced.
        // This is the same selected SharedClock authority used by logging/skew.
        let prepared = startup::prepare(&config, Arc::new(clock.clone()), Limits::default())?;
        runtime.block_on(async {
            let interrupt_kind = tokio::signal::unix::SignalKind::interrupt();
            let terminate_kind = tokio::signal::unix::SignalKind::terminate();
            let mut interrupt = tokio::signal::unix::signal(interrupt_kind)?;
            let mut terminate = tokio::signal::unix::signal(terminate_kind)?;
            let mut parent_control = parent_control
                .map(|control| control.register().map_err(|error| error.error)).transpose()?;
            let shutdown = std::future::poll_fn(|cx| {
                // A real logging IO failure requests the same normal stop as
                // a process signal; it cannot bypass actual Host close/cleanup.
                if diagnostics.failed(cx) { return Poll::Ready(Ok(())); }
                if let Some(control) = &mut parent_control {
                    match control.poll_signal(cx) {
                        Poll::Ready(Ok(Some(signal)))
                            if i32::from(signal) == interrupt_kind.as_raw_value()
                            || i32::from(signal) == terminate_kind.as_raw_value() => return Poll::Ready(Ok(())),
                        Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                        Poll::Ready(Ok(None)) => parent_control = None,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {},
                    }
                }
                if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready() {
                    Poll::Ready(Ok(()))
                } else { Poll::Pending }
            });
            let report = startup::foreground_listening(
                prepared, bound,
                |bound, peer| {
                    for error in bound.failures() {
                        diagnostics.message("pils.listener.alternate", Level::WARNING,
                            format_args!("pils alternate listener: {error}"))?;
                    }
                    diagnostics.message("pils.ready", Level::INFO,
                        format_args!("PILS prepared authority and original listeners ready"))?;
                    let public: String = peer.iter().map(|byte| format!("{byte:02x}")).collect();
                    let mut output = io::stdout().lock();
                    writeln!(output, "READY {public}")?;
                    output.flush()?;
                    child.ready()
                }, shutdown,
                |event| {
                    if matches!(&event, gnunet_service_runtime::accepted::SocketEvent::Failed(error) if error.is_emfile()) {
                        return;
                    }
                    let (level, site) = if matches!(&event, gnunet_service_runtime::accepted::SocketEvent::Failed(_)) {
                        (Level::WARNING, "pils.socket.failed")
                    } else { (Level::DEBUG, "pils.socket.activity") };
                    diagnostics.observe(site, level, format_args!("pils socket: {event:?}"));
                },
                |progress| {
                    if matches!(progress,
                        Progress::Request { handled: Handled::Reply { crypto_error: Some(_) }, .. }
                        | Progress::AdmissionFailed { .. }
                        | Progress::ClientClosed { cause: CloseCause::Io(_) | CloseCause::Protocol(_) | CloseCause::Output { .. }, .. })
                    {
                        diagnostics.observe("pils.service", Level::WARNING, format_args!("pils service: {progress:?}"));
                    }
                    Ok(())
                },
            ).await;
            let report = service::retain_diagnostic(report, diagnostics.take_failure())?;
            let mut output = io::stdout().lock();
            writeln!(output, "STOPPED {report:?}")?;
            output.flush()?;
            Ok::<_, Failure>(())
        })
    })();
    let result = service::retain_diagnostic(result, diagnostics.take_failure());
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    complete(result, &mut diagnostics.logger.borrow_mut(), &clock)
}
/// Stack-owned explicit selected Logger and one retained original diagnostic
/// failure. No global logger, hidden task or process stderr takeover is used.
struct Diagnostics<'a> {
    logger: RefCell<Logger<'a>>,
    clock: SharedClock,
    failure: RefCell<Option<io::Error>>,
    waker: RefCell<Option<Waker>>,
}
impl<'a> Diagnostics<'a> {
    fn new(logger: Logger<'a>, clock: SharedClock) -> Self {
        Self {
            logger: RefCell::new(logger),
            clock,
            failure: RefCell::new(None),
            waker: RefCell::new(None),
        }
    }
    fn message(
        &self,
        site: &'static str,
        level: Level,
        message: fmt::Arguments<'_>,
    ) -> io::Result<()> {
        service::diagnostic(
            &mut self.logger.borrow_mut(),
            &self.clock,
            site,
            level,
            message,
        )
    }
    fn observe(&self, site: &'static str, level: Level, message: fmt::Arguments<'_>) {
        if self.failure.borrow().is_some() {
            return;
        }
        if let Err(error) = self.message(site, level, message) {
            *self.failure.borrow_mut() = Some(error);
            if let Some(waker) = self.waker.borrow().as_ref() {
                waker.wake_by_ref();
            }
        }
    }
    fn failed(&self, cx: &Context<'_>) -> bool {
        let mut waker = self.waker.borrow_mut();
        if waker.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
            *waker = Some(cx.waker().clone());
        }
        self.failure.borrow().is_some()
    }
    fn take_failure(&self) -> Option<io::Error> {
        self.failure.borrow_mut().take()
    }
}
fn complete(
    result: Result<(), Failure>,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
) -> Result<ExitCode, Failure> {
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            if let Err(diagnostic) = service::diagnostic(
                logger,
                clock,
                "pils.failure",
                Level::ERROR,
                format_args!("gnunet-service-pils: {original}"),
            ) {
                let _reported = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-pils: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
