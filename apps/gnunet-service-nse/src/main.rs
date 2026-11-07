//! Standard SERVICE entry with explicit process detach, official options and logging.
#![deny(unsafe_code)]
use gnunet_nse_host::{Limits, startup};
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::Environment,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_startup::daemon::{self, Branch};
use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
use gnunet_service_startup::{InheritedMode, InheritedResources};
use std::{
    cell::RefCell,
    error::Error,
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
    task::Poll,
};
mod statistics;
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            // Only pre-configuration/parser/logger failures reach this fallback.
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-service-nse: {error}");
            ExitCode::FAILURE
        }
    }
}
fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Activation capture exclusively transfers inherited descriptors as the first initialization operation"
    )]
    // SAFETY: first operation in this fresh exec child; no listener/runtime or
    // competing descriptor owner/thread has been constructed.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("nse foreground received the wrong startup route".into());
        }
    };
    let notice = captured.control_notice;
    let parent_control = captured.parent_control;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"nse", std::process::id(), true)?;
    let selected = match service::prepare(
        b"nse",
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
        reason = "Explicit fresh-process daemon phase follows flushed option/log selection and precedes runtime, account NSS, path guards or active tasks; no lock is held"
    )]
    // SAFETY: once-only inherited capture is complete; parser temporary stdio
    // guards were released and flushed. Only config-free options, the selected
    // logger/clock and original inherited FD owners exist in this one thread.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(parent)) => {
            // These are the parent's copies of pre-bind original resources.
            // No Unix path guard/runtime exists here; only the child continues.
            drop(activation);
            drop(parent_control);
            let result = parent
                .wait()
                .map(|_actual| ())
                .map_err(|error| Box::new(error) as Failure);
            return complete(result, &mut logger, &clock);
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            // A child setup failure may have occurred after fork. Refresh only
            // local metadata, preserving the already selected owned logfile.
            logger.refresh_process_after_fork();
            return complete(Err(Box::new(error)), &mut logger, &clock);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            service::diagnostic(
                &mut logger,
                &clock,
                "nse.parent",
                Level::WARNING,
                format_args!("nse ignored parent-control declaration: {notice:?}"),
            )?;
        }
        let config = startup::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        // Keep the original account resolution/listener preparation/identity
        // order. No proof, entropy, CORE/PILS or signal task runs before it.
        let user = configured_user(&config, b"NSE")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listeners = {
            let _entered = runtime.enter();
            gnunet_service_runtime::BoundListeners::prepare_before_identity(
                &config, b"NSE", activation,
            )?
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            service::diagnostic(
                &mut logger,
                &clock,
                "nse.identity",
                Level::INFO,
                format_args!("nse configured process identity: {privileges:?}"),
            )?;
        }
        runtime.block_on(async {
            let interrupt_kind=tokio::signal::unix::SignalKind::interrupt();
            let terminate_kind=tokio::signal::unix::SignalKind::terminate();
            let mut interrupt=tokio::signal::unix::signal(interrupt_kind)?;
            let mut terminate=tokio::signal::unix::signal(terminate_kind)?;
            let mut parent_control=parent_control.map(|control|control.register().map_err(|error|error.error)).transpose()?;
            let logging_failure=RefCell::new(None);
            let logging_waker=RefCell::new(None::<std::task::Waker>);
            let runtime_logger=RefCell::new(&mut logger);
            let shutdown=std::future::poll_fn(|cx| {
                if logging_waker.borrow().as_ref().is_none_or(|old|!old.will_wake(cx.waker())) {
                    *logging_waker.borrow_mut()=Some(cx.waker().clone());
                }
                // A real diagnostic IO failure requests ordinary host cleanup;
                // it does not cancel/forget native or worker obligations.
                if logging_failure.borrow().is_some(){return Poll::Ready(Ok(()));}
                if let Some(control)=&mut parent_control {
                    match control.poll_signal(cx) {
                        Poll::Ready(Ok(Some(signal))) if i32::from(signal)==interrupt_kind.as_raw_value()
                            || i32::from(signal)==terminate_kind.as_raw_value()=>return Poll::Ready(Ok(())),
                        Poll::Ready(Ok(Some(_)))=>cx.waker().wake_by_ref(),
                        Poll::Ready(Ok(None))=>parent_control=None,
                        Poll::Ready(Err(error))=>return Poll::Ready(Err(error)),
                        Poll::Pending=>{},
                    }
                }
                if interrupt.poll_recv(cx).is_ready()||terminate.poll_recv(cx).is_ready(){Poll::Ready(Ok(()))}else{Poll::Pending}
            });

            let mut statistics_instance=gnunet_ipc_unix::handle::Instance::new();
            let report=startup::foreground_prepared_with_clock(
                &config,listeners,Limits::default(),
                |_,peer|{
                    let public:String=peer.iter().map(|b|format!("{b:02x}")).collect();
                    let mut stdout=io::stdout().lock();writeln!(stdout,"READY {public}")?;stdout.flush()?;child.ready()
                },
                shutdown,
                |event|{
                    if matches!(&event,gnunet_service_runtime::accepted::SocketEvent::Failed(error) if error.is_emfile()){return;}
                    if logging_failure.borrow().is_some(){return;}
                    let (level, site)=if matches!(&event,gnunet_service_runtime::accepted::SocketEvent::Failed(_)){(Level::WARNING,"nse.socket.failed")}else{(Level::DEBUG,"nse.socket.activity")};
                    let actual = runtime_logger.try_borrow_mut()
                        .map_err(|_|io::Error::other("NSE diagnostic logger already borrowed"))
                        .and_then(|mut logger|service::diagnostic(&mut logger,&clock,site,level,format_args!("nse socket: {event:?}")));
                    if let Err(error)=actual {
                        *logging_failure.borrow_mut()=Some(error);
                        if let Some(waker)=logging_waker.borrow().as_ref(){waker.wake_by_ref();}
                    }
                },
                Arc::new(clock.clone()),
                |failure| {
                    let actual=runtime_logger.try_borrow_mut()
                        .map_err(|_|io::Error::other("NSE diagnostic logger already borrowed"))
                        .and_then(|mut logger|service::diagnostic(&mut logger,&clock,
                            "nse.admission",Level::WARNING,
                            format_args!("nse unadmitted subscriber {:?}: {}",failure.peer,failure.error)));
                    match actual {
                        Ok(())=>Ok(()),
                        Err(logging)=>service::retain_diagnostic(
                            Err(Box::new(failure.error) as Failure),Some(logging)),
                    }
                },
                || logging_failure.borrow().is_some(),
                statistics::Factory::new(&mut statistics_instance),
            ).await;
            let report=service::retain_diagnostic(report,logging_failure.into_inner())?;
            writeln!(io::stdout().lock(),"STOPPED {report:?}")?;
            Ok::<_,Failure>(())
        })
    })();
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    complete(result, &mut logger, &clock)
}
fn complete(
    result: Result<(), Failure>,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
) -> Result<ExitCode, Failure> {
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            // The selected level may suppress this message but never turns the
            // actual failed service exit into success. Failed logging retains
            // both causes in a final raw emergency diagnostic.
            if let Err(diagnostic) = service::diagnostic(
                logger,
                clock,
                "nse.failure",
                Level::ERROR,
                format_args!("gnunet-service-nse: {original}"),
            ) {
                let _reported = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-nse: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
