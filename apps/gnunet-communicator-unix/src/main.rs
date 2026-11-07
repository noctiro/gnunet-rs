//! Foreground official UNIX communicator daemon over caller-driven native providers.
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
mod settings;
#[cfg(unix)]
mod statistics;
#[cfg(unix)]
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _report = writeln!(io::stderr().lock(), "{args}");
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _report = writeln!(io::stderr().lock(), "gnunet-communicator-unix: {e}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("native UNIX communicator foreground requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
    use std::sync::Arc;
    let inherited = early::capture()?;
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-communicator-unix", std::process::id(), false)?;
    let prepared = program::prepare(
        config,
        Invocation {
            binary_name: b"gnunet-communicator-unix",
            help: Some(b"GNUnet UNIX datagram communicator for testing."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Default::default(),
        std::env::args_os(),
        &program::Environment::capture(),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            if s.code == 0 && matches!(&s.reason, program::StoppedReason::Options) {
                return Ok(());
            }
            return Err(format!("PROGRAM stopped: {:?} (source code {})", s.reason, s.code).into());
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("UNIX communicator accepts no positional arguments".into());
    }
    let settings = settings::Settings::read(prepared.main().config)?;
    let user = configured_user(prepared.main().config, b"communicator-unix")?
        .map(|n| resolve_user(&n))
        .transpose()?;
    let privilege = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
    if user.is_some() {
        diagnostic(format_args!(
            "communicator-unix process identity: {privilege:?}"
        ));
    }
    // No native owner, runtime or socket opens before privileges.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(foreground::scheduled(prepared, clock, settings, inherited))
}
