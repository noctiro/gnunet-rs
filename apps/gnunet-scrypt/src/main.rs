//! Ordinary offline NSE proof utility, reusing exact GNUnet Argon2id13 work.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod options;
#[cfg(unix)]
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
            "NSE proof original={:?}; selected Logger={:?}",
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
                let _actual = writeln!(io::stderr().lock(), "gnunet-scrypt: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn entry() -> Result<(), Failure> {
    Err("this ordinary NSE proof file/PROGRAM profile requires Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Unique first-exec inherited descriptor transfer before any logger, runtime, entropy or key-file owner"
)]
fn capture() -> Result<gnunet_service_startup::CapturedStartup, Failure> {
    // SAFETY: the first operation of this fresh executable, before any competing
    // descriptor/env capture, thread, runtime, logger, entropy or file operation.
    Ok(unsafe {
        gnunet_service_startup::capture_from_environment(
            gnunet_service_startup::InheritedMode::CloseAfterConfiguredBind,
        )?
    })
}
#[cfg(unix)]
fn entry() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use gnunet_service_startup::InheritedResources;
    use std::sync::Arc;
    let captured = capture()?;
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let offered = !hold.is_empty();
            let closed = hold.abort();
            if offered {
                return Err(format!(
                    "NSE proof has no listener; original offered descriptors retired: {closed:?}"
                )
                .into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected NSE proof activation mode".into());
        }
    }
    let clock = SharedClock::native(8)?;
    let configuration = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let arguments = options::Arguments::new();
    let mut logger = Logger::new(b"gnunet-scrypt", std::process::id(), false)?;
    let help: &[u8] = b"Offline GNUnet NSE proof work (historical name scrypt, actual Argon2id13). -k/--keyfile FILE defaults to [PEER] PRIVATE_KEY; -o/--outfile FILE defaults to [NSE] PROOFFILE; -b/--bits BITS (zero selects [NSE] WORKBITS); -t/--timeout DURATION is the delay between ten-candidate rounds, never a whole timeout. Missing raw32 keys may be durably created; existing malformed keys/proofs are refused. Proof artifact is exactly native-endian raw8. Standard PROGRAM -c/-L/-l; optional --total-timeout DURATION and --max-hashes COUNT. Signals/parent stop checkpoint the original cursor, with independent persistence errors retained. No service or network is started.";
    let prepared = program::prepare(
        configuration,
        Invocation {
            binary_name: b"gnunet-scrypt",
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
    if let Some(notice) = captured.control_notice {
        reporter.debug(
            "scrypt.parent.notice",
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
                    "NSE proof PROGRAM stopped {:?}, source code {}",
                    s.reason, s.code
                )
                .into());
            }
        };
        let settings = arguments.select(prepared.main().config, prepared.main().arguments)?;
        let canonical: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = Arc::new(clock);
        let mut parent = captured.parent_control;
        // Capture the original whole targets before synchronous durable key/store
        // setup. The identity loader's startup contract precedes the runtime.
        let prepared = run::prepare(settings, canonical, reporter.clone(), &mut parent)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(run::run(prepared, parent))
    })();
    if let Err(error) = &outcome {
        reporter.message(
            Level::ERROR,
            "scrypt.command.failed",
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
