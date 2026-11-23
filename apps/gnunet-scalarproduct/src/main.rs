//! Official installed SCALARPRODUCT command using actual stream-fed native sampling.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod input;
mod output;
mod run;
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Failure>,
    logging: Option<io::Error>,
    code: u8,
}
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
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|e| e as _))
    }
}
#[expect(
    unsafe_code,
    reason = "Fresh executable captures original client inheritance before any competing native owner"
)]
fn main() -> ExitCode {
    // SAFETY: first and only initialization in this fresh single-threaded process.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Failure)
        .and_then(run);
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if let Some(selected) = error.downcast_ref::<SelectedFailure>() {
                return ExitCode::from(selected.code);
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-scalarproduct: {error}");
            ExitCode::from(2)
        }
    }
}
fn run(startup: gnunet_service_startup::ClientStartup) -> Result<u8, Failure> {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Target},
        logging::Logger,
        policy::Level,
        program::{self, Defaults, Invocation, Preparation},
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
    let prepared = program::prepare_installed(config, Invocation { binary_name: b"gnunet-scalarproduct", help: Some(b"Compute an official SCALARPRODUCT using -e 'key1,value1;key2,value2;' -k TRANSACTION_ID [-p PEERID]. With peer: requester/alice; without peer: responder/bob. Original key labels and session identifier are hashed as GNUnet bytes. Requester success prints a signed uppercase hexadecimal scalar product. Uses ordinary role configuration, one shared clock and explicit Resolver; no service is spawned."), select_default_filename: true, defaults: Defaults::Native }, options, std::env::args_os(), &program::Environment::capture(), &mut logger, &clock, &mut io::stdout().lock(), &mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reporter.warning(
            "client.parent.notice",
            format_args!("Original parent-control declaration: {notice:?}"),
        );
    }
    let mut failure_code = 2;
    let outcome: Result<u8, Failure> = (|| {
        let prepared = match prepared? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped) => return Ok(if stopped.code == 0 { 0 } else { 2 }),
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
                startup,
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
