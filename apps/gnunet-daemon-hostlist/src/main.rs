//! Foreground active official HOSTLIST daemon; HTTP/TLS/IPC/store paths are real.
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
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(unix)]
            if error.is::<reporting::SelectedFailure>() {
                return ExitCode::FAILURE;
            }
            let _report = writeln!(io::stderr().lock(), "gnunet-daemon-hostlist: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("native HOSTLIST foreground requires Unix".into())
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
    use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
    use std::sync::Arc;
    let mut inherited = early::capture()?;
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let advertise = Target::new(0);
    let bootstrap = Target::new(0);
    let learning = Target::new(0);
    let provide = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::flag(
        b'a',
        b"advertise",
        b"advertise our actual hostlist endpoint to other peers",
        advertise.clone(),
    ));
    options.add(helpers::flag(
        b'b',
        b"bootstrap",
        b"bootstrap using configured and actually learned hostlists",
        bootstrap.clone(),
    ));
    options.add(helpers::flag(
        b'e',
        b"enable-learning",
        b"test and learn original CORE hostlist advertisements",
        learning.clone(),
    ));
    options.add(helpers::flag(
        b'p',
        b"provide-hostlist",
        b"provide binary/JSON HTTP hostlists from verified PEERSTORE records",
        provide.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-daemon-hostlist", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-daemon-hostlist",help:Some(b"Official HOSTLIST bootstrap, learned advertisements, verified HELLO publication. -a/--advertise -b/--bootstrap -e/--enable-learning -p/--provide-hostlist. HTTP/HTTPS bootstrap uses actual shared Resolver, verified Rustls and bounded original sockets; own qualified metadata store only. URI and proxy authentication are redacted. [hostlist-rust] supplies explicit resource/time profiles."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reports = reporting::Reports::new(logger, clock.clone());
    let result = (|| {
        let prepared = match prepared? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped) => {
                return match stopped.reason {
                    program::StoppedReason::Options if stopped.code >= 0 => Ok(()),
                    program::StoppedReason::Logging(error) => Err(error.into()),
                    program::StoppedReason::Malformed(error) => Err(error.into()),
                    reason => Err(format!(
                        "PROGRAM stopped: {reason:?} (source code {})",
                        stopped.code
                    )
                    .into()),
                };
            }
        };
        if let Some(notice) = inherited.notice.take() {
            reports.warning(
                "hostlist.parent.declaration",
                format_args!("hostlist parent control declaration={notice:?}"),
            );
        }

        if reports.failed() {
            return Ok(());
        }
        if !prepared.main().arguments.is_empty() {
            return Err("HOSTLIST accepts no positional arguments".into());
        }
        let modes = gnunet_hostlist::Modes {
            advertise: advertise.get()? != 0,
            bootstrap: bootstrap.get()? != 0,
            learning: learning.get()? != 0,
            provide: provide.get()? != 0,
        };
        if !modes.bootstrap && !modes.learning && !modes.provide {
            reports.warning(
                "hostlist.roles.disabled",
                format_args!("HOSTLIST has no enabled bootstrap/learning/providing role"),
            );
            return Ok(());
        }
        let settings = settings::Settings::read(prepared.main().config, modes)?;
        let user = configured_user(prepared.main().config, b"hostlist")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let privilege = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.debug(
                "hostlist.process.identity",
                format_args!("hostlist process identity: {privilege:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        // No native owner, HTTP bind, disk worker or runtime before configured UID/GID.
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
