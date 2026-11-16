//! Official UDP PROGRAM composed from explicit native protocol owners.
#![deny(unsafe_code)]
mod addresses;
mod bootstrap;
mod control;
mod early;
mod identity;
mod network;
mod run;
mod settings;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[derive(Debug)]
struct ProgramFailure {
    original: Option<Cause>,
    logging: Option<io::Error>,
}
impl std::fmt::Display for ProgramFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDP PROGRAM: {self:?}")
    }
}
impl Error for ProgramFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|error| error as _))
    }
}
fn main() -> ExitCode {
    match execute() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-communicator-udp: {error}");
            ExitCode::FAILURE
        }
    }
}
fn execute() -> Result<u8, Cause> {
    use gnunet_program_host::{
        foreground,
        getopt::Options,
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::{cell::Cell, rc::Rc, sync::Arc};
    let early = early::capture()?;
    let clock = SharedClock::native(128)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-communicator-udp", std::process::id(), false)?;
    let prepared = program::prepare(config, Invocation {
        binary_name:b"gnunet-communicator-udp",
        help:Some(b"GNUnet UDP communicator. Standard -c/-L/-l/-h/-v apply. Reads communicator-udp BINDTO/BINDTO6, DISABLE_V6, DISABLE_BROADCAST, REKEY_INTERVAL and REKEY_MAX_BYTES. Existing peer.PRIVATE_KEY must match verified PILS; no key is created. Rust resource limits and independent replay directory are selected in communicator-udp-rust."),
        select_default_filename:true, defaults:Defaults::Native,
    }, Options::new(), std::env::args_os(), &program::Environment::capture(), &mut NlsDisabled, &mut logger, &clock, &mut io::stdout().lock(), &mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<u8, Cause> {
        let prepared = match prepared? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s)
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) =>
            {
                return Ok(0);
            }
            Preparation::Stopped(s) => return Err(format!("UDP PROGRAM preparation: {s:?}").into()),
        };
        if !prepared.main().arguments.is_empty() {
            return Err("UDP communicator accepts no positional arguments".into());
        }
        clock.testing_skew(prepared.main().config)?;
        #[cfg(unix)]
        if let Some(notice) = early.notice {
            reporter.warning("udp.parent.notice", format_args!("{notice:?}"));
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let stop = Rc::new(Cell::new(false));
                let mut control =
                    control::Control::new(early.parent, stop.clone(), reporter.clone())?;
                let settings = settings::Settings::parse(
                    prepared.main().config,
                    bootstrap::ipv6_supported()?,
                )?;
                let sockets = bootstrap::bind(&settings, &reporter)?;
                if let std::task::Poll::Ready(result) =
                    std::future::poll_fn(|cx| std::task::Poll::Ready(control.poll(cx))).await
                {
                    result?;
                    return Ok(0);
                }
                // Finish identity setup after binds, before workers/private state.
                identity::apply(prepared.main().config)?;
                let live =
                    gnunet_client_host::LiveConfiguration::new(prepared.main().config.duplicate()?);
                let actual: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> =
                    Arc::new(clock.clone());
                let (mut context, resolver) = gnunet_resolver_broker::broker::<8, 64>(
                    live.clone(),
                    Default::default(),
                    gnunet_resolver_broker::native_profile()?,
                    actual.clone(),
                )?;
                let source = |section: &'static [u8]| {
                    gnunet_client_host::EndpointSource::live(
                        live.clone(),
                        section,
                        context.resolution_context(),
                    )
                };
                let inputs = run::Inputs {
                    settings,
                    sockets,
                    control,
                    resolver,
                    clock: actual,
                    reporter: reporter.clone(),
                    pils: source(b"pils"),
                    nat: source(b"nat"),
                    transport: source(b"transport"),
                    application: source(b"transport"),
                };
                foreground::run(
                    prepared,
                    &mut context,
                    clock.clone(),
                    stop,
                    run::run(inputs),
                )
                .await
                .map(|report| report.code)
            })
    })();
    if let Err(error) = &result {
        reporter.warning("udp.program.failed", format_args!("{error}"));
    }
    match (result, reporter.take_error()) {
        (Ok(code), None) => Ok(code),
        (original, logging) => Err(Box::new(ProgramFailure {
            original: original.err(),
            logging,
        })),
    }
}
