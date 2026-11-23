//! Unix fresh-process detachment, identity transition and Resolver composition.
use super::{Diagnostics, Failure, complete};
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::Environment,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_resolver_host::startup;
use gnunet_service_startup::{
    GroupsProfile, InheritedMode, InheritedResources, apply_privileges, configured_user,
    daemon::{self, Branch},
    resolve_user,
};
use std::{
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
    task::Poll,
};
pub(super) fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Fresh process uniquely adopts inherited descriptors before configuration, runtime, machine-file reads or competing owners"
    )]
    // SAFETY: this is the first initialization operation in this exec child.
    // Foreign activation/parent-control ownership is transferred exactly once.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("Resolver received the wrong inherited startup route".into());
        }
    };
    let notice = captured.control_notice;
    let parent_control = captured.parent_control;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"resolver", std::process::id(), true)?;
    let selected = match service::prepare(
        b"resolver",
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
        reason = "Explicit once-only detach precedes runtime, account NSS, listening path guards, literal-file reads or active tasks; temporary stdio locks are released"
    )]
    // SAFETY: this fresh single thread holds only original transferred FDs,
    // selected options/logger and clock. No runtime/task/path guard exists.
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
                "resolver.parent",
                Level::WARNING,
                format_args!("resolver parent-control declaration: {notice:?}"),
            )?;
        }
        let config = startup::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let unix = startup::unix_access(&config)?;
        let user = configured_user(&config, b"resolver")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Keep original activation sockets; bind only new TCP endpoints before
        // USERNAME. There is no service task or machine-file read at this point.
        let listeners = {
            let _entered = runtime.enter();
            gnunet_service_runtime::BoundListeners::prepare_before_identity(
                &config,
                b"resolver",
                activation,
            )?
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            diagnostics.message(
                "resolver.identity",
                Level::INFO,
                format_args!("resolver actual configured process identity: {privileges:?}"),
            )?;
        }
        // The actual target account creates new Unix paths. No old inode or
        // parent directory is chowned, and transferred sockets are not reopened.
        let bound = runtime.block_on(listeners.finish_with_access(unix.into()))?;
        runtime.block_on(async {
            let mut termination = gnunet_service_runtime::signals::Termination::new()?;
            let mut parent_control = parent_control.map(|control|control.register().map_err(|error|error.error)).transpose()?;
            let shutdown = std::future::poll_fn(|cx| {
                if diagnostics.failed(cx) { return Poll::Ready(Ok(())); }
                if let Some(control) = &mut parent_control {
                    match control.poll_signal(cx) {
                        Poll::Ready(Ok(Some(2 | 15))) => return Poll::Ready(Ok(())),
                        Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                        Poll::Ready(Ok(None)) => parent_control = None,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {},
                    }
                }
                termination.poll_stop(cx)
            });
            let report = startup::serve_standalone(
                &config, bound, Arc::new(clock.clone()),
                |diagnostic| diagnostics.machine_input(diagnostic),
                |bound| std::future::ready(diagnostics.ready(bound).and_then(|()| child.ready())),
                shutdown,
                |event| {
                    if matches!(&event, gnunet_resolver_host::SocketEvent::Failed(error) if error.is_emfile()) { return; }
                    let (level, site) = if matches!(&event, gnunet_resolver_host::SocketEvent::Failed(_)) {
                        (Level::WARNING, "resolver.socket.failed")
                    } else { (Level::DEBUG, "resolver.socket.activity") };
                    diagnostics.observe(site, level, format_args!("resolver socket: {event:?}"));
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
    let mut logger = diagnostics.logger.into_inner();
    complete(result, &mut logger, &clock)
}
