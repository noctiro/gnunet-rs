//! Standard interactive Messenger PROGRAM over the actual high-level client.
#![deny(unsafe_code)]
mod input;
mod options;
mod output;
mod session;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[expect(
    unsafe_code,
    reason = "Fresh PROGRAM captures original native inheritance before competing owners"
)]
fn main() -> ExitCode {
    // SAFETY: first and only capture in this fresh single-threaded executable.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Failure)
        .and_then(run);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let selected = error.is::<output::ReportedFailure>();
            if !selected {
                let _diagnostic = writeln!(io::stderr().lock(), "gnunet-messenger: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
fn run(startup: gnunet_service_startup::ClientStartup) -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let clock = SharedClock::native(512)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(
        b"gnunet-messenger",
        std::process::id(),
        cfg!(debug_assertions),
    )?;
    let selected = options::Selection::new();
    let preparation=program::prepare_installed(config,Invocation {binary_name:b"gnunet-messenger",help:Some(b"Open or enter a Messenger room and exchange bounded stdin text or binary TALK data."),select_default_filename:true,defaults:Defaults::Native},selected.descriptors(),std::env::args_os(),&program::Environment::capture(),&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reporter.warning(
            "messenger.parent.notice",
            format_args!("parent-control declaration: {notice:?}"),
        );
    }
    let result = (|| -> Result<_, Failure> {
        let prepared = match preparation? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped)
                if stopped.code == 0
                    && matches!(stopped.reason, program::StoppedReason::Options) =>
            {
                return Ok(None);
            }
            Preparation::Stopped(stopped) => {
                return Err(format!(
                    "Messenger PROGRAM stopped: {:?} (source code {})",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        if !prepared.main().arguments.is_empty() {
            return Err("Messenger accepts options, not positional arguments".into());
        }
        let settings = selected.finish(prepared.main().config)?;
        let config = prepared.main().config.duplicate()?;
        Ok(Some((prepared, config, settings)))
    })();
    let result = match result {
        Ok(Some((prepared, config, settings))) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Err(error) => Err(Box::new(error) as Failure),
                Ok(runtime) => runtime.block_on(session::scheduled(
                    prepared,
                    config,
                    settings,
                    clock.clone(),
                    reporter.clone(),
                    startup,
                )),
            }
        }
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = &result {
        reporter.warning(
            "messenger.program.failed",
            format_args!("Messenger: {error}"),
        );
    }
    match (result, reporter.take_error()) {
        (original, Some(logging)) => Err(Box::new(output::DiagnosticFailure {
            original: original.err(),
            logging,
        }) as Failure),
        (original, None) => original,
    }
    .map_err(|original| Box::new(output::ReportedFailure(original)) as Failure)
}
