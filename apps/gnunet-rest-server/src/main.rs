//! Bounded REST PROGRAM with one externally retained original foreground future.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod lifecycle;
#[cfg(unix)]
mod settings;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(unix)]
            if error.is::<lifecycle::Reported>() {
                return ExitCode::FAILURE;
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-rest-server: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("native REST foreground requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let inherited = early::capture()?;
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-rest-server", std::process::id(), false)?;
    let prepared = program::prepare(
        config,
        Invocation {
            binary_name: b"gnunet-rest-server",
            help: Some(b"Official bounded HTTP REST routes over original native CLIENT MQs. Common PROGRAM -c/-L/-l options and selected logging environment apply. [rest] controls HTTP_PORT/BIND_TO/BIND_TO6/USERNAME/auth/CORS; [rest-rust] bounds requests, JSON, clients and output. CONFIG and conditional OpenID own real workers; GNS uses the existing configured external query service. Active C and Rust use plain HTTP."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Default::default(), std::env::args_os(), &program::Environment::capture(),
        &mut NlsDisabled, &mut logger, &clock, &mut io::stdout().lock(), &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) {
                return Ok(());
            }
            return Err(format!("PROGRAM stopped: {:?} (source code {})", s.reason, s.code).into());
        }
    };
    let reports = Reporter::new(logger, clock.clone());
    let result = selected(prepared, clock, inherited, reports.clone());
    finish(result, reports)
}
#[cfg(unix)]
fn selected(
    prepared: gnunet_program_host::program::Prepared,
    clock: gnunet_program_host::shared_clock::SharedClock,
    inherited: early::Inherited,
    reports: gnunet_program_host::reporting::Reporter,
) -> Result<foreground::Report, Failure> {
    use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
    if let Some(notice) = &inherited.notice {
        reports.warning(
            "rest.parent",
            format_args!("REST original parent-control declaration: {notice:?}"),
        );
    }
    if reports.failed() {
        return Err("REST selected Logger failed before native setup".into());
    }
    if !prepared.main().arguments.is_empty() {
        return Err("REST accepts no positional arguments".into());
    }
    let settings = settings::Settings::read(prepared.main().config)?;
    let user = configured_user(prepared.main().config, b"rest")?
        .map(|n| resolve_user(&n))
        .transpose()?;
    let privilege = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
    if user.is_some() {
        reports.message(
            gnunet_program_host::policy::Level::INFO,
            "rest.identity",
            format_args!("REST configured process identity: {privilege:?}"),
        );
    }
    if reports.failed() {
        return Err("REST selected Logger failed before runtime setup".into());
    }
    // This remains PROGRAM. No daemon/service listener sequence is invented.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(foreground::scheduled(
            prepared, clock, settings, inherited, reports,
        ))
}
#[cfg(unix)]
#[derive(Debug)]
struct LoggingFailure {
    original: Option<Failure>,
    diagnostic: io::Error,
    completion: Option<foreground::Report>,
}
#[cfg(unix)]
impl std::fmt::Display for LoggingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "REST original={:?}; independent logging={}; actual completion={:?}",
            self.original, self.diagnostic, self.completion
        )
    }
}
#[cfg(unix)]
impl Error for LoggingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref().or(Some(&self.diagnostic))
    }
}
#[cfg(unix)]
fn finish(
    result: Result<foreground::Report, Failure>,
    reports: gnunet_program_host::reporting::Reporter,
) -> Result<(), Failure> {
    match &result {
        Ok(report) => reports.debug(
            "rest.stopped",
            format_args!("REST actual terminal={report:?}"),
        ),
        Err(error) => reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "rest.failed",
            format_args!("REST original failure: {error}"),
        ),
    }
    let result = match (result, reports.take_error()) {
        (result, None) => result,
        (Ok(completion), Some(diagnostic)) => Err(Box::new(LoggingFailure {
            original: None,
            diagnostic,
            completion: Some(completion),
        }) as Failure),
        (Err(original), Some(diagnostic)) => Err(Box::new(LoggingFailure {
            original: Some(original),
            diagnostic,
            completion: None,
        }) as Failure),
    };
    result
        .map(|_| ())
        .map_err(|error| Box::new(lifecycle::Reported(error)) as Failure)
}
