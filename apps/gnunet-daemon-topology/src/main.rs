//! Normal TOPOLOGY PROGRAM over shared native client startup.
#![deny(unsafe_code)]
mod foreground;
mod identity;
mod reporting;
mod settings;
mod statistics;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[expect(
    unsafe_code,
    reason = "Fresh process captures original client inheritance before competing native resources"
)]
fn main() -> ExitCode {
    // SAFETY: first and only initialization in this fresh single-threaded executable.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Failure)
        .and_then(run);
    match result {
        Ok(code) => code,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-daemon-topology: {error}");
            ExitCode::FAILURE
        }
    }
}
fn run(startup: gnunet_service_startup::ClientStartup) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, Preparation},
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-daemon-topology", std::process::id(), false)?;
    let prepared = program::prepare_installed(
        config,
        Invocation {
            binary_name: b"gnunet-daemon-topology",
            help: Some(b"Maintain peer connections and exchange public HELLO announcements using the configured CORE, PILS, PEERSTORE and TRANSPORT services."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Default::default(), std::env::args_os(), &program::Environment::capture(),
        &mut logger, &clock, &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    let reports = reporting::Reports::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reports.warning(
            "topology.parent.declaration",
            format_args!("Original parent-control declaration: {notice:?}"),
        );
    }
    let outcome = (|| -> Result<ExitCode, Failure> {
        let prepared = match prepared? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped) => {
                io::stdout().flush()?;
                return match stopped.reason {
                    program::StoppedReason::Options => Ok(if stopped.code == 0 {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }),
                    program::StoppedReason::Logging(error) => Err(error.into()),
                    program::StoppedReason::Malformed(error) => Err(error.into()),
                    reason => Err(format!(
                        "TOPOLOGY PROGRAM stopped: {reason:?} (code {})",
                        stopped.code
                    )
                    .into()),
                };
            }
        };
        if !prepared.main().arguments.is_empty() {
            return Err("TOPOLOGY accepts no positional arguments".into());
        }
        if reports.failed() {
            return Err("selected TOPOLOGY Logger failed".into());
        }
        let settings = settings::Settings::read(prepared.main().config)?;
        identity::apply(prepared.main().config, &reports)?;
        if reports.failed() {
            return Err("selected TOPOLOGY Logger failed".into());
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(foreground::scheduled(
                prepared,
                clock,
                settings,
                startup,
                reports.clone(),
            ))?;
        Ok(ExitCode::SUCCESS)
    })();
    let outcome = reports.finish(outcome);
    if let Err(error) = &outcome {
        reports.error(
            "topology.program.failed",
            format_args!("gnunet-daemon-topology: {error}"),
        );
    }
    Ok(reports.finish(outcome).unwrap_or(ExitCode::FAILURE))
}
