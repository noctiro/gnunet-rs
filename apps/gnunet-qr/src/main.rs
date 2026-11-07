//! Normal QR image/camera PROGRAM using actual standard providers and URI owner.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod run;
#[cfg(unix)]
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
#[cfg(not(unix))]
fn entry() -> Result<(), Failure> {
    Err("native QR provider/URI dispatcher requires Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Unique first-exec inherited descriptor transfer before any logger, runtime, scan/provider or other resource owner"
)]
fn capture() -> Result<gnunet_service_startup::CapturedStartup, Failure> {
    // SAFETY: called only as the first operation of this fresh executable entry;
    // no earlier FD/env capture, thread, runtime or competing descriptor owner.
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
            let actual = hold.abort();
            if offered {
                return Err(format!(
                    "QR PROGRAM has no listener; actual offered descriptors retired: {actual:?}"
                )
                .into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected QR listener activation mode".into());
        }
    }
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let arguments = settings::Arguments::new();
    let mut logger = Logger::new(b"gnunet-qr", std::process::id(), false)?;
    let help: &[u8] = b"Scan actual QR/barcode input then perform the configured [uri] handler action. --png FILE selects bounded PNG; otherwise --device DEVICE selects the actual platform ZBar camera (default /dev/video0), --no-display disables its optional native window. Standard PROGRAM -c/-L/-l and --timeout DURATION. Uses standard libpng1.6/libzbar, no GNUnet C library, shell or decoder fallback. Provider/device absence is a real error. One original whole target covers scan and actual handler; independent physical cleanup remains observable.";
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
    if let Some(notice) = captured.control_notice {
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
            captured.parent_control,
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
