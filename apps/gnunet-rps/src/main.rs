//! Official installed RPS command using actual stream-fed native sampling.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod output;
#[cfg(unix)]
mod run;
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
            write!(f, "RPS: {error}")?;
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
            let _actual = writeln!(io::stderr().lock(), "gnunet-rps: {error}");
            ExitCode::from(2)
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<u8, Failure> {
    Err("native RPS command requires Unix".into())
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
    let view = Target::new(0i32);
    let stream = Target::new(0i32);
    let seed = Target::new(None::<Vec<u8>>);
    let mut options = Options::new();
    options.add(helpers::flag(
        b'V',
        b"view",
        b"Get view updates; optional positional N, zero continuous",
        view.clone(),
    ));
    options.add(helpers::flag(
        b'S',
        b"stream",
        b"Get the explicitly biased peer stream",
        stream.clone(),
    ));
    options.add(helpers::string(
        b's',
        b"seed",
        b"PEER_ID",
        b"Seed one full52-character public peer identity",
        seed.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-rps", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-rps",help:Some(b"Request random peer identities (optional N, default1). -s/--seed PEER_ID writes one standard seed frame locally, with no service acknowledgement. -V/--view [N] outputs actual view batches (default0, continuous). -S/--stream outputs explicitly biased stream batches. Exactly one mode. Uses selected ordinary rps configuration, shared PROGRAM Resolver/clock and finite original local resource deadlines. No service is spawned."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
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
                    "RPS PROGRAM stopped {:?} code={}",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        let selection = run::Selection::read(
            seed.get()?,
            view.get()? != 0,
            stream.get()? != 0,
            prepared.main().arguments,
        )?;
        let settings = run::Settings::read(prepared.main().config, selection)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        failure_code = 1;
        runtime
            .block_on(run::scheduled(
                prepared,
                clock,
                settings,
                selection,
                reporter.clone(),
            ))
            .map(|()| 0)
    })();
    if let Err(error) = &outcome {
        reporter.message(Level::ERROR, "rps.program.failed", format_args!("{error}"));
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
