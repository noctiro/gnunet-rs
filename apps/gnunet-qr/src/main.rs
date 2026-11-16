//! Normal QR image/camera PROGRAM using actual standard providers and URI owner.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod run;
mod settings;
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Failure>,
    logging: Option<io::Error>,
}
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QR original={:?}; selected Logger={:?}",
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
                let _actual = writeln!(io::stderr().lock(), "gnunet-qr: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
#[expect(
    unsafe_code,
    reason = "Once-only native inheritance capture before logger, runtime or scan/provider owners"
)]
fn capture() -> Result<gnunet_service_startup::ClientStartup, Failure> {
    // SAFETY: first startup action before logger, files, runtime or workers.
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
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let arguments = settings::Arguments::new();
    let mut logger = Logger::new(b"gnunet-qr", std::process::id(), false)?;
    let help: &[u8] = b"Decode a PNG (--png FILE) or selected ZBar camera (--device DEVICE), then run the configured GNUnet URI action. --no-display disables the camera window; --timeout bounds scanning and handler exit. [qr-rust] selects provider paths, device and resource limits. Windows requires explicit LIBPNG/LIBZBAR DLL paths and camera device selection. See README configuration examples.";
    let prepared = program::prepare(
        config,
        Invocation {
            binary_name: b"gnunet-qr",
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
            "qr.parent.notice",
            format_args!("original parent control declaration: {notice:?}"),
        );
    }
    let result = (|| -> Result<(), Failure> {
        let prepared = match prepared? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s)
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) =>
            {
                return Ok(());
            }
            Preparation::Stopped(s) => {
                return Err(
                    format!("QR PROGRAM stopped {:?} with code {}", s.reason, s.code).into(),
                );
            }
        };
        let selection = arguments.select(prepared.main().config, prepared.main().arguments)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let canonical: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = Arc::new(clock);
        runtime.block_on(run::run(
            prepared.main().config,
            canonical,
            selection,
            reporter.clone(),
            captured.parent,
        ))
    })();
    if let Err(error) = &result {
        reporter.message(Level::ERROR, "qr.command.failed", format_args!("{error}"));
    }
    let logging = reporter.take_error();
    match (result, logging) {
        (Ok(()), None) => Ok(()),
        (result, logging) => Err(Box::new(SelectedFailure {
            original: result.err(),
            logging,
        })),
    }
}
