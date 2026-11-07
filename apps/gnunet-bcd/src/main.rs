//! Normal PROGRAM entry for the GNS business-card HTTP product.
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
            "BCD original={:?}; selected Logger={:?}",
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
                let _actual = writeln!(io::stderr().lock(), "gnunet-bcd: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn entry() -> Result<(), Failure> {
    Err("normal BCD renderer ownership requires Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Unique first-exec inherited descriptor ownership transfer before configuration/logger/runtime/listener/child construction"
)]
fn capture() -> Result<gnunet_service_startup::CapturedStartup, Failure> {
    // SAFETY: first action of this fresh executable; no competing FD owner,
    // runtime, logger, environment capture, thread or child exists yet.
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
                return Err(format!("BCD PROGRAM binds its selected TCP listener; unexpected inherited descriptors actually retired: {closed:?}").into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected BCD listener activation mode".into());
        }
    }
    let clock = SharedClock::native(256)?;
    let configuration = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let arguments = settings::Arguments::new();
    let mut logger = Logger::new(b"gnunet-bcd", std::process::id(), false)?;
    let prepared=program::prepare(configuration,Invocation{
        binary_name:b"gnunet-bcd",select_default_filename:true,defaults:Defaults::Native,
        help:Some(b"HTTP GNS business cards. -p/--port PORT selects the listening port (8888). GET / and /full serve forms; /submit/simple and /submit/full validate the typed GNS zone key and generate a real PDF, or QR PNG when gnspng is present. HEAD serves the simple form headers without rendering. [bcd-rust] selects numeric BIND_TO, absolute PDFLATEX/GHOSTSCRIPT/LAUNCHER/TEMP_ROOT, finite connection/job/application-byte and head/whole/output/child cleanup limits. Tool absence fails only that generation request with HTTP500. No shell, shell-escape, arbitrary template, hidden task or provider fallback. Standard PROGRAM -c/-L/-l/-h/-v, original parent control, SIGINT and SIGTERM apply."),
    },arguments.options(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    if let Some(notice) = captured.control_notice {
        reporter.debug(
            "bcd.parent.notice",
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
                    format!("BCD PROGRAM stopped {:?} with code {}", s.reason, s.code).into(),
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
            captured.parent_control,
        ))
    })();
    if let Err(error) = &result {
        reporter.message(Level::ERROR, "bcd.command.failed", format_args!("{error}"));
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
