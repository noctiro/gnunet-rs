//! Standard GNS user-name PROGRAM through the actual with-TLD client owner.
#![deny(unsafe_code)]
mod budget;
mod control;
mod early;
mod options;
mod output;
mod run;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[derive(Debug)]
struct SelectedFailure {
    code: u8,
    original: Option<Cause>,
    logging: Option<io::Error>,
    output: Option<output::Close>,
}
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GNS PROGRAM: {self:?}")
    }
}
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|error| error as _))
            .or_else(|| self.output.as_ref().map(|error| error as _))
    }
}
#[derive(Debug)]
struct PreparationFailure(gnunet_program_host::program::Stopped);
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GNS PROGRAM stopped {:?}, code {}",
            self.0.reason, self.0.code
        )
    }
}
impl Error for PreparationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use gnunet_program_host::program::StoppedReason;
        match &self.0.reason {
            StoppedReason::Logging(error) => Some(error),
            StoppedReason::Malformed(error) => Some(error),
            _ => None,
        }
    }
}
fn main() -> ExitCode {
    match execute() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if let Some(selected) = error.downcast_ref::<SelectedFailure>() {
                return ExitCode::from(selected.code);
            }
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-gns: {error}");
            ExitCode::FAILURE
        }
    }
}
fn execute() -> Result<u8, Cause> {
    use gnunet_program_host::{
        foreground,
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::{cell::Cell, rc::Rc, sync::Arc};
    let early = early::capture()?;
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-gns", std::process::id(), false)?;
    let selection = options::Selection::new();
    let invocation = Invocation {
        binary_name: b"gnunet-gns",
        help: Some(b"Resolve -u/--lookup NAME through GNUnet GNS. -t/--type selects records, -r/--raw prints values, and -T/--timeout bounds the complete operation. -d/--dns validates DNS syntax and IDNA without falling back to DNS. Non-GNS names exit 4; empty GNS answers succeed."),
        select_default_filename: true,
        defaults: Defaults::Native,
    };
    let preparation = program::prepare(
        config,
        invocation,
        selection.options(),
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
    if let Some(notice) = early.notice {
        reporter.debug(
            "gns.parent.notice",
            format_args!("parent-control: {notice:?}"),
        );
    }
    let selected = (|| -> Result<_, Cause> {
        let prepared = match preparation? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped)
                if stopped.code == 0
                    && matches!(stopped.reason, program::StoppedReason::Options) =>
            {
                return Ok(None);
            }
            Preparation::Stopped(stopped) => {
                return Err(Box::new(PreparationFailure(stopped)));
            }
        };
        let settings =
            selection.finish(prepared.main().config, prepared.main().arguments, &reporter)?;
        let configuration = prepared.main().config.duplicate()?;
        Ok(Some((prepared, settings, configuration)))
    })();
    let retired = output::retained();
    let result = match selected {
        Ok(None) => Ok(0),
        Err(error) => Err(error),
        Ok(Some((prepared, settings, configuration))) => {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Err(error) => Err(Box::new(error) as Cause),
                Ok(runtime) => runtime.block_on(async {
                    use gnunet_resolver_broker::{Family, FamilyProfile};
                    use gnunet_service_runtime::clock::RuntimeClock;
                    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
                    let native = gnunet_resolver_broker::native_profile()?;
                    let family =
                        FamilyProfile::new(native.encode(Family::V4), native.encode(Family::V6))?;
                    let live =
                        gnunet_client_host::LiveConfiguration::new(configuration.duplicate()?);
                    let (mut context, resolver) = gnunet_resolver_broker::broker::<16, 64>(
                        live.clone(),
                        Default::default(),
                        family,
                        source.clone(),
                    )?;
                    let stop = Rc::new(Cell::new(false));
                    let product = run::run(run::Inputs {
                        settings,
                        configuration,
                        live,
                        context: context.clone(),
                        resolver,
                        source,
                        reporter: reporter.clone(),
                        stop: stop.clone(),
                        parent: early.parent,
                        retired: retired.clone(),
                    });
                    let result =
                        foreground::run(prepared, &mut context, clock.clone(), stop, product).await;
                    output::settle(&retired).await;
                    result.map(|report| report.code)
                }),
            }
        }
    };
    if let Err(error) = &result {
        reporter.warning("gns.program.failed", format_args!("{error}"));
    }
    let code = result
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<options::NameFailure>())
        .map_or(1, options::NameFailure::code);
    let output = retired.borrow_mut().take();
    match (result, reporter.take_error(), output) {
        (Ok(code), None, None) => Ok(code),
        (original, logging, output) => Err(Box::new(SelectedFailure {
            code,
            original: original.err(),
            logging,
            output,
        })),
    }
}
