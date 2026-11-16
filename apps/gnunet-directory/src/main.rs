//! Ordinary offline plaintext GNUnet directory artifact inspection.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod display;
mod input;
mod options;
mod run;
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Failure>,
    logging: Option<io::Error>,
}
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "directory inspection original={:?}; selected Logger={:?}",
            self.original, self.logging
        )
    }
}
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|e| e as _))
    }
}
fn main() -> ExitCode {
    match entry() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !error.is::<SelectedFailure>() {
                let _actual = writeln!(io::stderr().lock(), "gnunet-directory: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
#[expect(
    unsafe_code,
    reason = "Once-only native inheritance capture before logger, runtime or file-input owners"
)]
fn capture() -> Result<gnunet_service_startup::ClientStartup, Failure> {
    // SAFETY: first startup action, before files, logger, runtime or workers.
    Ok(unsafe { gnunet_service_startup::ClientStartup::capture() }?)
}
fn entry() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let captured = capture()?;
    let clock = SharedClock::native(8)?;
    let configuration = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let arguments = options::Arguments::new();
    let mut logger = Logger::new(b"gnunet-directory", std::process::id(), false)?;
    let help: &[u8] = b"Display local plaintext GNUnet directory artifacts: gnunet-directory [OPTIONS] FILE... . Each selected regular file is read incrementally; no repository, CHK, download, service or network is required. Root and entry metadata plus exact URI/name text are escaped safely; binary/embedded values report their actual length. Syntax parsing does not authenticate a source or embedded file. A partial, corrupt, changed or unreadable file makes the final exit nonzero, retaining already written output; independent selected files are still inspected. Standard PROGRAM -c/-L/-l; --timeout DURATION is an optional fixed whole-operation bound (zero/FOREVER unbounded). [directory-rust] resource settings bound records/metadata/URI scratch without a fixed file-size or total-entry cap. Signals and parent stop end the original operation; native file/stdio/codec calls are synchronous and cannot be preempted.";
    let prepared = program::prepare(
        configuration,
        Invocation {
            binary_name: b"gnunet-directory",
            help: Some(help),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        arguments.options(),
        std::env::args_os(),
        &program::Environment::capture(),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = captured.notice {
        reporter.debug(
            "directory.parent.notice",
            format_args!("original parent-control declaration: {notice:?}"),
        );
    }
    let outcome: Result<(), Failure> = (|| {
        let prepared = match prepared? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s)
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) =>
            {
                return Ok(());
            }
            Preparation::Stopped(s) => {
                return Err(format!(
                    "directory inspection PROGRAM stopped {:?}, source code {}",
                    s.reason, s.code
                )
                .into());
            }
        };
        let settings = arguments.select(prepared.main().config, prepared.main().arguments)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let canonical: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = Arc::new(clock);
        runtime.block_on(run::run(
            settings,
            canonical,
            reporter.clone(),
            captured.parent,
        ))
    })();
    if let Err(error) = &outcome {
        reporter.message(
            Level::ERROR,
            "directory.command.failed",
            format_args!("{error}"),
        );
    }
    let logging = reporter.take_error();
    match (outcome, logging) {
        (Ok(()), None) => Ok(()),
        (outcome, logging) => Err(Box::new(SelectedFailure {
            original: outcome.err(),
            logging,
        })),
    }
}
