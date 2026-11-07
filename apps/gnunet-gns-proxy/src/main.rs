//! Standard GNS proxy PROGRAM through the actual bounded gateway owner.
#![deny(unsafe_code)]
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod options;
#[cfg(unix)]
mod run;
#[cfg(unix)]
mod settings;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(unix)]
#[derive(Debug)]
struct SelectedFailure {
    code: u8,
    original: Option<Cause>,
    logging: Option<io::Error>,
}
#[cfg(unix)]
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GNS proxy PROGRAM: {self:?}")
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
#[cfg(unix)]
#[derive(Debug)]
struct PreparationFailure(gnunet_program_host::program::Stopped);
#[cfg(unix)]
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GNS proxy PROGRAM stopped {:?}, code {}",
            self.0.reason, self.0.code
        )
    }
}
#[cfg(unix)]
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
            #[cfg(unix)]
            if let Some(selected) = error.downcast_ref::<SelectedFailure>() {
                return ExitCode::from(selected.code);
            }
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-gns-proxy: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn execute() -> Result<u8, Cause> {
    Err("native GNS proxy PROGRAM requires Unix".into())
}
#[cfg(unix)]
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
    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-gns-proxy", std::process::id(), false)?;
    let selection = options::Selection::new();
    let preparation=program::prepare(config,Invocation {
        binary_name:b"gnunet-gns-proxy",
        help:Some(b"Run the GNS SOCKS5 HTTP/HTTPS proxy. -p/--port selects the listener port (default 7777); -a/--authority selects an existing CA certificate/private-key PEM; -6/--disable-ivp6 disables IPv6. [gns-proxy] BIND_TO, BIND_TO6 and PROXY_CACERT use the normal configuration. Optional [gns-proxy-rust] PKIX_ROOTS selects a public root-certificate PEM bundle; bundled public roots are the default. Configure the browser to trust the selected proxy CA. System trust settings are managed separately. Standard -c/-L/-l/-h/-v choose configuration and diagnostics. Ctrl-C, TERM and parent control stop the proxy."),
        select_default_filename:true,defaults:Defaults::Native,
    },selection.options(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    if let Some(notice) = early.notice {
        reporter.debug(
            "gns-proxy.parent.notice",
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
        let chosen = selection.finish(prepared.main().arguments)?;
        let settings = settings::Settings::read(prepared.main().config, chosen)?;
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
                    let (mut context, resolver) = gnunet_resolver_broker::broker::<128, 256>(
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
                    });
                    foreground::run(prepared, &mut context, clock.clone(), stop, product)
                        .await
                        .map(|_report| 0)
                }),
            }
        }
    };
    if let Err(error) = &result {
        reporter.warning("gns-proxy.program.failed", format_args!("{error}"));
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
