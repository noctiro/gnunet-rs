//! Normal PROGRAM entry for the GNS business-card HTTP product.
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
#[expect(
    unsafe_code,
    reason = "Once-only native inheritance capture before configuration, logger, runtime or child construction"
)]
fn capture() -> Result<gnunet_service_startup::ClientStartup, Failure> {
    // SAFETY: first startup action before logger, files, runtime or workers.
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
    let clock = SharedClock::native(256)?;
    let configuration = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let arguments = settings::Arguments::new();
    let mut logger = Logger::new(b"gnunet-bcd", std::process::id(), false)?;
    let prepared=program::prepare_installed(configuration,Invocation{
        binary_name:b"gnunet-bcd",select_default_filename:true,defaults:Defaults::Native,
        help:Some(b"Serve GNS business-card forms and generate PDF or QR PNG cards. -p/--port selects the port (8888). [bcd-rust] selects numeric BIND_TO, absolute PDFLATEX/GHOSTSCRIPT paths, private TEMP_ROOT and resource limits. Windows launches tools directly; Unix also selects LAUNCHER. Tools run only on generation requests. See README for routes and configuration."),
    },arguments.options(),std::env::args_os(),&program::Environment::capture(),&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = captured.notice {
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
            captured.parent,
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
