//! Official installed SCALARPRODUCT command using actual stream-fed native sampling.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod input;
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
            write!(f, "SCALARPRODUCT: {error}")?;
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
            let _actual = writeln!(io::stderr().lock(), "gnunet-scalarproduct: {error}");
            ExitCode::from(2)
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<u8, Failure> {
    Err("native SCALARPRODUCT command requires Unix".into())
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
    let elements = Target::new(None::<Vec<u8>>);
    let key = Target::new(None::<Vec<u8>>);
    let peer = Target::new(None::<Vec<u8>>);
    let mut options = Options::new();
    options.add(helpers::string(
        b'e',
        b"elements",
        b"key,value;...;",
        b"Original signed-i64 vector entries, each terminated by semicolon",
        elements.clone(),
    ));
    options.add(helpers::string(
        b'k',
        b"key",
        b"TRANSACTION_ID",
        b"Nonempty session identifier shared with the counterpart",
        key.clone(),
    ));
    options.add(helpers::string(
        b'p',
        b"peer",
        b"PEERID",
        b"Optional actual target peer; absence selects responder role",
        peer.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-scalarproduct", std::process::id(), false)?;
    let prepared = program::prepare(config, Invocation { binary_name: b"gnunet-scalarproduct", help: Some(b"Compute an official SCALARPRODUCT using -e 'key1,value1;key2,value2;' -k TRANSACTION_ID [-p PEERID]. With peer: requester/alice; without peer: responder/bob. Original key labels and session identifier are hashed as GNUnet bytes. Requester success prints a signed uppercase hexadecimal scalar product. Uses ordinary role configuration, one shared clock and explicit Resolver; no service is spawned."), select_default_filename: true, defaults: Defaults::Native }, options, std::env::args_os(), &program::Environment::capture(), &mut NlsDisabled, &mut logger, &clock, &mut io::stdout().lock(), &mut io::stderr().lock());
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
                    "SCALARPRODUCT PROGRAM stopped {:?} code={}",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        let settings = input::Settings::read(prepared.main().config)?;
        let selection = input::Selection::read(
            elements.get()?,
            key.get()?,
            peer.get()?,
            prepared.main().arguments,
            settings,
        )?;
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
        reporter.message(
            Level::ERROR,
            "scalarproduct.program.failed",
            format_args!("{error}"),
        );
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
