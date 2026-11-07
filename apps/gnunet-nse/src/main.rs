//! Official installed NSE estimate command; no proof/key/service dependency.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Failure>,
    logging: Option<io::Error>,
    code: u8,
}
#[cfg(unix)]
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(error) = &self.original {
            write!(f, "NSE: {error}")?;
        }
        if let Some(error) = &self.logging {
            write!(f, "; selected logging: {error}")?;
        }
        Ok(())
    }
}
#[cfg(unix)]
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|e| e as _))
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            #[cfg(unix)]
            if let Some(selected) = error.downcast_ref::<SelectedFailure>() {
                return ExitCode::from(selected.code);
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-nse: {error}");
            ExitCode::from(2)
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<u8, Failure> {
    Err("native NSE command requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<u8, Failure> {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Target},
        logging::Logger,
        policy::Level,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let clock = SharedClock::native(256)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let monitor = Target::new(0i32);
    let mut options = Options::new();
    options.add(helpers::flag(
        b'm',
        b"monitor",
        b"Monitor and output current estimates",
        monitor.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-nse", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-nse",help:Some(b"Show network size estimates from NSE service. Default: print first real estimate and disconnect. -m/--monitor: print continuous estimates until signal or optional finite configured monitor target. Values are statistical observations, not authenticated peer counts. No positional arguments."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    let mut failure_code = 2;
    let outcome: Result<u8, Failure> = (|| {
        let prepared = match prepared? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped) => {
                if stopped.code == 0 && matches!(&stopped.reason, program::StoppedReason::Options) {
                    return Ok(0);
                }
                return Err(format!(
                    "NSE PROGRAM stopped {:?} code={}",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        if !prepared.main().arguments.is_empty() {
            return Err("gnunet-nse accepts no positional arguments".into());
        }
        let settings = gnunet_nse_client_host::cli::Settings::read(prepared.main().config)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let monitor = monitor.get()? != 0;
        failure_code = 1;
        runtime
            .block_on(gnunet_nse_client_host::cli::scheduled(
                prepared,
                clock,
                settings,
                monitor,
                reporter.clone(),
            ))
            .map(|delivered| u8::from(!delivered))
    })();
    if let Err(error) = &outcome {
        reporter.message(Level::ERROR, "nse.program.failed", format_args!("{error}"));
    }
    let logging = reporter.take_error();
    match (outcome, logging) {
        (Ok(code), None) => Ok(code),
        (outcome, logging) => Err(Box::new(SelectedFailure {
            code: if outcome.is_err() { failure_code } else { 1 },
            original: outcome.err(),
            logging,
        })),
    }
}
