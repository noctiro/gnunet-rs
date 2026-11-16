//! Standard forward/reverse Resolver PROGRAM over the actual shared client.
#![deny(unsafe_code)]
mod budget;
mod options;
mod output;
mod run;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Cause>,
    logging: Option<io::Error>,
}
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "resolver PROGRAM: {self:?}")
    }
}
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|error| error as _))
    }
}
#[expect(
    unsafe_code,
    reason = "Fresh PROGRAM captures inherited native resources before competing owners"
)]
fn main() -> ExitCode {
    // SAFETY: first and only capture in this fresh single-threaded process.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Cause)
        .and_then(execute);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let selected = error.is::<SelectedFailure>();
            if !selected {
                let _diagnostic = writeln!(io::stderr().lock(), "gnunet-resolver: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
fn execute(startup: gnunet_service_startup::ClientStartup) -> Result<(), Cause> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-resolver", std::process::id(), false)?;
    let selection = options::Selection::new();
    let preparation=program::prepare(config,Invocation {
        binary_name:b"gnunet-resolver",
        help: Some(b"Use the configured GNUnet Resolver for one hostname or -r/--reverse IP. Forward results include actual IPv4 and IPv6 addresses; reverse names are output as returned. Resolver construction and all query/queue/connection/callback/output work share one original five-second budget. Original output close has a separate one-second grace. Standard -c/-L/-l/-h/-v select actual configuration and diagnostics."),
        select_default_filename:true,defaults:Defaults::Native,
    },selection.options(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reporter.warning(
            "resolver.parent.notice",
            format_args!("parent-control: {notice:?}"),
        );
    }
    let selected = (|| -> Result<_, Cause> {
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
                    "resolver PROGRAM stopped: {:?}, code{}",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        let Some(settings) = selection.finish(prepared.main().config, prepared.main().arguments)?
        else {
            return Ok(None);
        };
        let configuration = prepared.main().config.duplicate()?;
        Ok(Some((prepared, settings, configuration)))
    })();
    let result = match selected {
        Ok(None) => Ok(()),
        Err(error) => Err(error),
        Ok(Some((prepared, settings, configuration))) => {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Err(error) => Err(Box::new(error) as Cause),
                Ok(runtime) => runtime.block_on(run::scheduled(
                    prepared,
                    settings,
                    configuration,
                    clock.clone(),
                    reporter.clone(),
                    startup,
                )),
            }
        }
    };
    if let Err(error) = &result {
        reporter.warning("resolver.program.failed", format_args!("{error}"));
    }
    match (result, reporter.take_error()) {
        (Ok(()), None) => Ok(()),
        (original, logging) => Err(Box::new(SelectedFailure {
            original: original.err(),
            logging,
        })),
    }
}
