//! Standard GNUnet URI default-action PROGRAM, with one real configured child.
#![deny(unsafe_code)]
use gnunet_uri_host::{Dispatcher, Settings};
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
struct SelectedFailure {
    original: Option<Cause>,
    report: Option<gnunet_uri_host::Report>,
    logging: Option<io::Error>,
}
impl std::fmt::Debug for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UriProgramFailure")
            .field("original", &self.original)
            .field("report", &self.report)
            .field("logging", &self.logging)
            .finish()
    }
}
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "URI PROGRAM")?;
        if let Some(cause) = &self.original {
            write!(f, "; original: {cause}")?;
        }
        if let Some(report) = &self.report {
            write!(f, "; actual child: {report}")?;
        }
        if let Some(cause) = &self.logging {
            write!(f, "; selected logging: {cause}")?;
        }
        Ok(())
    }
}
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|cause| cause as _))
    }
}
#[derive(Debug)]
struct DispatchEnd {
    original: Option<gnunet_uri_host::DispatchFailure>,
    close: gnunet_uri_host::CloseReport,
}
impl std::fmt::Display for DispatchEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original URI dispatch={:?}; independent actual close={:?}",
            self.original, self.close
        )
    }
}
impl Error for DispatchEnd {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_ref().map(|e| e as _).or_else(|| {
            self.close
                .kill
                .as_ref()
                .or(self.close.wait.as_ref())
                .map(|e| e as _)
        })
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(cause) => {
            let selected = cause.is::<SelectedFailure>();
            if !selected {
                let _diagnostic = writeln!(io::stderr().lock(), "gnunet-uri: {cause}");
            }
            ExitCode::FAILURE
        }
    }
}
#[expect(
    unsafe_code,
    reason = "Once-only native inheritance capture before logger, runtime or other resource owners"
)]
fn run() -> Result<(), Cause> {
    use gnunet_program_host::{
        getopt::Options,
        logging::Logger,
        program::{self, Defaults, Invocation, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    // SAFETY: first operation of this fresh exec child, with no earlier fd/env
    // capture, thread, runtime, logger or competing descriptor ownership.
    let captured = unsafe { gnunet_service_startup::ClientStartup::capture()? };
    let clock = SharedClock::native(8)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-uri", std::process::id(), false)?;
    let help: &[u8] = b"Perform the configured default action for one gnunet:// URI. [uri] SUBSYSTEM selects executable and arguments with the shared configured-command tokenizer, without a shell. The complete original URI is appended as one argument; no automatic -- is inserted. Standard -c/-L/-l/-h/-v options select actual configuration and diagnostics.";
    let prepared = program::prepare_installed(
        config,
        Invocation {
            binary_name: b"gnunet-uri",
            help: Some(help),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Options::new(),
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
            "uri.parent.notice",
            format_args!("parent-control declaration: {notice:?}"),
        );
    }
    let result: Result<Option<gnunet_uri_host::Report>, Cause> = (|| {
        let prepared = match prepared? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped)
                if stopped.code == 0
                    && matches!(stopped.reason, program::StoppedReason::Options) =>
            {
                return Ok(None);
            }
            Preparation::Stopped(stopped) => {
                return Err(format!(
                    "URI PROGRAM stopped {:?}, source code {}",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        let settings = Settings::read(prepared.main().config, prepared.main().arguments)?;
        drop(prepared);
        // prepare owns real standard config/log/TESTING skew selection. This
        // operation has no DNS/MQ query, so no fake Resolver port is constructed.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let canonical: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = Arc::new(clock);
            let mut dispatcher =
                Dispatcher::new(captured.parent, reporter.clone(), canonical, None)?;
            dispatcher.start(settings)?;
            let original = dispatcher.drive().await;
            let close = dispatcher.close();
            let clean = close.kill.is_none() && close.wait.is_none() && !close.report.undrained;
            match (original, clean) {
                (Ok(report), true) => Ok(Some(report)),
                (original, _) => Err(Box::new(DispatchEnd {
                    original: original.err(),
                    close,
                }) as Cause),
            }
        })
    })();
    if let Err(cause) = &result {
        reporter.warning("uri.program.failed", format_args!("{cause}"));
    }
    let logging = reporter.take_error();
    match (result, logging) {
        (Ok(_), None) => Ok(()),
        (original, logging) => {
            let (original, report) = match original {
                Ok(report) => (None, report),
                Err(cause) => (Some(cause), None),
            };
            Err(Box::new(SelectedFailure {
                original,
                report,
                logging,
            }))
        }
    }
}
