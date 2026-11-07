//! Standard online DNS-to-NAMESTORE PROGRAM, using one actual importer owner.
#![deny(unsafe_code)]
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod input;
#[cfg(unix)]
mod run;
#[cfg(unix)]
mod settings;
#[cfg(unix)]
mod statistics;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(unix)]
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Cause>,
    logging: Option<io::Error>,
}
#[cfg(unix)]
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "zoneimport PROGRAM: {self:?}")
    }
}
#[cfg(unix)]
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|error| error as _))
    }
}
fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(unix)]
            let selected = error.is::<SelectedFailure>();
            #[cfg(not(unix))]
            let selected = false;
            if !selected {
                let _diagnostic = writeln!(io::stderr().lock(), "gnunet-zoneimport: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn execute() -> Result<(), Cause> {
    Err("online zoneimport PROGRAM requires Unix".into())
}
#[cfg(unix)]
fn execute() -> Result<(), Cause> {
    use gnunet_program_host::{
        foreground,
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::{cell::Cell, rc::Rc, sync::Arc};
    // Capture first: no logger/runtime/stdio reader or other descriptor owner.
    let early = early::capture()?;
    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-zoneimport", std::process::id(), false)?;
    let selection = settings::Selection::new();
    let preparation=program::prepare(config,Invocation {
        binary_name:b"gnunet-zoneimport",
        help:Some(b"Import newline-separated FQDNs from stdin through existing IDENTITY zones and NAMESTORE; continuously refresh from DNS after EOF. Arguments: DNS-IP... (numeric IPv4/IPv6, port53). -s/--size is an initial Rust name-table hint; -m/--minimum-expiration selects the DNS record minimum lifetime. Standard -c/-L/-l/-h/-v apply to the actual PROGRAM."),
        select_default_filename:true,defaults:Defaults::Native,
    },selection.descriptors(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    if let Some(notice) = early.notice {
        reporter.debug(
            "zoneimport.parent.notice",
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
                return Err(format!(
                    "zoneimport PROGRAM stopped: {:?}, code{}",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        let settings = selection.finish(prepared.main().config, prepared.main().arguments)?;
        let configuration = prepared.main().config.duplicate()?;
        Ok(Some((prepared, settings, configuration)))
    })();
    let result = match selected {
        Ok(None) => Ok(()),
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
                    let live = gnunet_client_host::LiveConfiguration::new(configuration);
                    let (mut context, resolver) = gnunet_resolver_broker::broker::<128, 256>(
                        live.clone(),
                        Default::default(),
                        family,
                        source.clone(),
                    )?;
                    let stop = Rc::new(Cell::new(false));
                    let product = run::run(run::Inputs {
                        settings,
                        live,
                        context: context.clone(),
                        resolver,
                        source,
                        reporter: reporter.clone(),
                        stop: stop.clone(),
                        parent: early.parent,
                        stdin: early.stdin,
                    });
                    foreground::run(prepared, &mut context, clock.clone(), stop, product)
                        .await
                        .map(|_report| ())
                }),
            }
        }
    };
    if let Err(error) = &result {
        reporter.warning("zoneimport.program.failed", format_args!("{error}"));
    }
    match (result, reporter.take_error()) {
        (Ok(()), None) => Ok(()),
        (original, logging) => Err(Box::new(SelectedFailure {
            original: original.err(),
            logging,
        })),
    }
}
