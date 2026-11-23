//! Ordinary offline raw32 peer-key utility; no implicit key/service/network work.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod keys;
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
            "ECC original={:?}; selected Logger={:?}",
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
                let _actual = writeln!(io::stderr().lock(), "gnunet-ecc: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
#[expect(
    unsafe_code,
    reason = "Once-only native inheritance capture before logger, runtime, entropy or key-file owners"
)]
fn capture() -> Result<gnunet_service_startup::ClientStartup, Failure> {
    // SAFETY: first startup action, before files, logger, runtime or workers.
    Ok(unsafe { gnunet_service_startup::ClientStartup::capture() }?)
}
fn entry() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::{self, Defaults, Invocation, Preparation},
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
    let mut logger = Logger::new(b"gnunet-ecc", std::process::id(), false)?;
    let help: &[u8] = b"Offline GNUnet raw32 Ed25519 seed files. -p public Base32; -x public HEX::; explicit -P private Base32. -g COUNT FILE [VANITY_PREFIX] streams fresh seeds through a private sibling and atomically publishes the complete flat file. Existing regular empty/raw32 files may be replaced after metadata recheck; symlinks and partial records are refused. -i [-e COUNT] lists on stderr. -E prints actual ECDHE private/public and SHA512(X25519) examples, with no key-file access. C operation precedence E/i/g>0/x/p/P applies. Standard PROGRAM -c/-L/-l; optional --timeout DURATION and --max-attempts COUNT. Signals and parent stop retire the original operation; synchronous filesystem/entropy/stdio/crypto calls are not OS-preemptible.";
    let prepared = program::prepare_installed(
        configuration,
        Invocation {
            binary_name: b"gnunet-ecc",
            help: Some(help),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        arguments.options(),
        std::env::args_os(),
        &program::Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = captured.notice {
        reporter.debug(
            "ecc.parent.notice",
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
                return Err(
                    format!("ECC PROGRAM stopped {:?}, source code {}", s.reason, s.code).into(),
                );
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
        reporter.message(Level::ERROR, "ecc.command.failed", format_args!("{error}"));
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
