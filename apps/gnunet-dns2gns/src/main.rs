//! Standard DNS2GNS PROGRAM through the actual bounded gateway owner.
#![deny(unsafe_code)]
mod control;
mod options;
mod run;
mod settings;
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
}
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNS2GNS PROGRAM: {self:?}")
    }
}
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|error| error as _))
    }
}
#[derive(Debug)]
struct PreparationFailure(gnunet_program_host::program::Stopped);
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DNS2GNS PROGRAM stopped {:?}, code {}",
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
#[expect(
    unsafe_code,
    reason = "First fresh-process capture before competing native owners"
)]
fn main() -> ExitCode {
    // SAFETY: first and only capture in this fresh single-threaded executable.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Cause)
        .and_then(execute);
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if let Some(selected) = error.downcast_ref::<SelectedFailure>() {
                return ExitCode::from(selected.code);
            }
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-dns2gns: {error}");
            ExitCode::FAILURE
        }
    }
}
fn execute(startup: gnunet_service_startup::ClientStartup) -> Result<u8, Cause> {
    use gnunet_program_host::{
        foreground,
        logging::Logger,
        program::{self, Defaults, Invocation, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::{cell::Cell, rc::Rc, sync::Arc};
    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-dns2gns", std::process::id(), false)?;
    let selection = options::Selection::new();
    let preparation=program::prepare_installed(config,Invocation {
        binary_name:b"gnunet-dns2gns",
        help:Some(b"Run the configured DNS2GNS UDP gateway. -d/--dns IP is the required numeric recursive DNS upstream, not a daemon flag. [DNS2GNS] BIND_TO and BIND_TO6 are required numeric listener addresses; PORT defaults to 53 only when absent (installed defaults may configure a different port). Each real query and VPN lease uses the gateway's original fixed bounds. Standard -c/-L/-l/-h/-v select actual configuration and diagnostics. Ctrl-C, TERM and parent control close and drain the same gateway/Resolver owners."),
        select_default_filename:true,defaults:Defaults::Native,
    },selection.options(),std::env::args_os(),&program::Environment::capture(),&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reporter.debug(
            "dns2gns.parent.notice",
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
        let upstream = selection.finish(prepared.main().arguments)?;
        let settings = settings::Settings::read(prepared.main().config, upstream)?;
        #[cfg(windows)]
        gnunet_service_startup::verify_configured_identity(prepared.main().config, b"dns2gns")?;
        let configuration = prepared.main().config.duplicate()?;
        Ok(Some((prepared, settings, configuration)))
    })();
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
                        parent: startup.parent,
                    });
                    foreground::run(prepared, &mut context, clock.clone(), stop, product)
                        .await
                        .map(|_report| 0)
                }),
            }
        }
    };
    if let Err(error) = &result {
        reporter.warning("dns2gns.program.failed", format_args!("{error}"));
    }
    match (result, reporter.take_error()) {
        (Ok(code), None) => Ok(code),
        (original, logging) => Err(Box::new(SelectedFailure {
            code: 1,
            original: original.err(),
            logging,
        })),
    }
}
