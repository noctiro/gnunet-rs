//! Installed official CORE connection status/monitor command using actual IPC.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod bounds;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod output;
#[cfg(unix)]
mod reporting;
#[cfg(unix)]
mod settings;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Selected diagnostics (including filtered or failed writes) have
            // already used their sole Logger. Do not bypass -L/-l on return.
            #[cfg(unix)]
            if reporting::was_reported(&error) {
                return ExitCode::FAILURE;
            }
            let _report = writeln!(io::stderr().lock(), "gnunet-core: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("CORE native CLI requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Target},
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    // A standalone PROGRAM owns no listener/readiness endpoint and no private key.
    let mut inherited = early::capture()?;
    let clock = SharedClock::native(128)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let show = Target::new(0);
    let monitor = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::flag(
        b's',
        b"connection-status",
        b"Show current connections",
        show.clone(),
    ));
    options.add(helpers::flag(
        b'm',
        b"monitor",
        b"provide information about all current connections (continuously)",
        monitor.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-core", std::process::id(), false)?;
    let preparation=program::prepare(config,Invocation{binary_name:b"gnunet-core",help:Some(b"Print actual connected-peer/key-exchange information from the configured CORE service. -s/--connection-status waits for the genuine initial iteration marker; -m/--monitor continues on current typed source generations until SIGINT/SIGTERM or its explicit finite profile. Both flags select continuous monitoring. [core-cli-rust] bounds original operation, snapshot, partial frame, work and resources. No private keys, hidden service or forged snapshot completion."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    if matches!(&preparation, Ok(Preparation::Stopped(s)) if s.code == 0 && matches!(&s.reason, program::StoppedReason::Options))
    {
        return Ok(());
    }
    let reports = reporting::Reports::new(logger, clock.clone());
    let prepared = match preparation {
        Ok(Preparation::Ready(p)) => *p,
        Ok(Preparation::Stopped(s)) => return reports.stopped(s),
        Err(error) => return reports.finish(Err(error.into())),
    };
    if let Some(notice) = inherited.notice.take() {
        reports.warning(
            "core-cli.parent.declaration",
            format_args!("core-cli parent control declaration={notice:?}"),
        );
    }
    let result = (|| {
        if reports.failed() {
            return Ok(());
        }
        if !prepared.main().arguments.is_empty() {
            return Err("CORE accepts no positional arguments".into());
        }
        if show.get()? == 0 && monitor.get()? == 0 {
            return Err("No argument given: select -s or -m".into());
        }
        let settings = settings::Settings::read(prepared.main().config, monitor.get()? != 0)?;
        // The ordinary CLI remains under its calling UID, as the public C client;
        // configuring the CORE daemon's USERNAME is not permission to change it.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(foreground::scheduled(
                prepared,
                clock,
                settings,
                inherited,
                reports.clone(),
            ))
    })();
    reports.finish(result)
}
