//! Foreground official TOPOLOGY daemon over caller-driven native providers.
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
mod reporting;
#[cfg(unix)]
mod settings;
#[cfg(unix)]
mod statistics;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _report = writeln!(io::stderr().lock(), "gnunet-daemon-topology: {e}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("native TOPOLOGY foreground requires Unix".into())
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
    let mut inherited = early::capture()?;
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-daemon-topology", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-daemon-topology",help:Some(b"Official TOPOLOGY HELLO gossip, PEERSTORE hello-add and TRANSPORT connection hints using actual CORE/PILS/PEERSTORE/application sources. [topology] TARGET-CONNECTION-COUNT; [topology-rust] bounded resources, explicit profiles and finite startup/source deadlines. No private key/store file or hidden network task."),select_default_filename:true,defaults:Defaults::Native},Default::default(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            return match s.reason {
                program::StoppedReason::Options if s.code >= 0 => Ok(()),
                program::StoppedReason::Logging(error) => Err(error.into()),
                program::StoppedReason::Malformed(error) => Err(error.into()),
                reason => {
                    Err(format!("PROGRAM stopped: {reason:?} (source code {})", s.code).into())
                }
            };
        }
    };
    let reports = reporting::Reports::new(logger, clock.clone());
    if let Some(notice) = inherited.notice.take() {
        reports.warning(
            "topology.parent.declaration",
            format_args!("topology parent control declaration={notice:?}"),
        );
    }
    let result = (|| {
        if reports.failed() {
            return Ok(());
        }
        if !prepared.main().arguments.is_empty() {
            return Err("TOPOLOGY accepts no positional arguments".into());
        }
        let settings = settings::Settings::read(prepared.main().config)?;
        let user = configured_user(prepared.main().config, b"topology")?
            .map(|n| resolve_user(&n))
            .transpose()?;
        let privilege = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.debug(
                "topology.process.identity",
                format_args!("topology process identity: {privilege:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        // No native owner, runtime or socket opens before privileges.
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
    if let Err(error) = &result {
        reports.warning(
            "topology.program.failed",
            format_args!("gnunet-daemon-topology: {error}"),
        );
    }
    reports.finish(result)
}
