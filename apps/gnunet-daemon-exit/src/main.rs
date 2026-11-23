//! Caller-driven official PROGRAM EXIT daemon with real privileged helper option.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod announcement;
mod dns_advertisement;
mod early;
mod foreground;
mod lifecycle;
mod network;
#[cfg(windows)]
mod readiness;
mod settings;
fn main() -> ExitCode {
    let routed = std::cell::Cell::new(false);
    match run(&routed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !routed.get() {
                let _diagnostic = writeln!(io::stderr().lock(), "gnunet-daemon-exit: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
fn run(routed: &std::cell::Cell<bool>) -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, Preparation, StoppedReason},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    #[cfg(unix)]
    use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
    use std::sync::Arc;
    let inherited = early::capture()?;
    #[cfg(unix)]
    let mut inherited = inherited;
    let clock = SharedClock::native(256)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-daemon-exit", std::process::id(), false)?;
    let prepared=program::prepare_installed(config,Invocation{binary_name:b"gnunet-daemon-exit",help:Some(b"GNUnet EXIT PROGRAM; official CADET VPN protocol and bounded native packet sources."),select_default_filename:true,defaults:Defaults::Native},Default::default(),std::env::args_os(),&program::Environment::capture(),&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) if s.code == 0 && matches!(s.reason, StoppedReason::Options) => {
            return Ok(());
        }
        Preparation::Stopped(s) => {
            return Err(format!("PROGRAM stopped: {:?} code={}", s.reason, s.code).into());
        }
    };
    let reports = Reporter::new(logger, clock.clone());
    routed.set(true);
    let cleanup = lifecycle::Cleanup::default();
    #[cfg(unix)]
    if let Some(notice) = inherited.notice.take() {
        reports.warning(
            "exit.parent.notice",
            format_args!("EXIT original parent-control declaration: {notice:?}"),
        );
    }
    let result = (|| {
        if reports.failed() {
            return Ok(());
        }
        if !prepared.main().arguments.is_empty() {
            return Err("EXIT accepts no positional arguments".into());
        }
        let settings = settings::Settings::read(prepared.main().config)?;
        #[cfg(unix)]
        {
            let user = configured_user(prepared.main().config, b"exit")?
                .map(|u| resolve_user(&u))
                .transpose()?;
            let privilege = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
            if user.is_some() {
                reports.debug(
                    "exit.identity",
                    format_args!("EXIT actual process identity: {privilege:?}"),
                );
            }
        }
        #[cfg(windows)]
        gnunet_service_startup::verify_configured_identity(prepared.main().config, b"exit")?;
        if reports.failed() {
            return Ok(());
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(foreground::scheduled(
                prepared,
                clock,
                settings,
                inherited,
                reports.clone(),
                cleanup.clone(),
            ))
    })();
    if let Some(error) = reports.take_error() {
        cleanup.retain(lifecycle::Stage::Logging, Box::new(error));
    }
    let result = cleanup.finish(result);
    if let Err(error) = &result {
        reports.warning(
            "exit.failed",
            format_args!("EXIT actual original lifecycle failure: {error}"),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
}
