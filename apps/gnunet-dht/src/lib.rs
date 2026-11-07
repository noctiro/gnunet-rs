//! Standard DHT commands composed with the existing caller-driven native client.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(unix)]
#[derive(Debug)]
struct ProgramFailure {
    original: Option<Cause>,
    logging: Option<io::Error>,
}
#[cfg(unix)]
impl std::fmt::Display for ProgramFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DHT PROGRAM: {self:?}")
    }
}
#[cfg(unix)]
impl Error for ProgramFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|e| e as _))
    }
}
#[cfg(unix)]
mod budget;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod options;
#[cfg(unix)]
mod output;
#[cfg(unix)]
mod run;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Get,
    Put,
    Monitor,
    Hello,
}
impl Mode {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Get => b"gnunet-dht-get",
            Self::Put => b"gnunet-dht-put",
            Self::Monitor => b"gnunet-dht-monitor",
            Self::Hello => b"gnunet-dht-hello",
        }
    }
}
/// Run the standard GET PROGRAM, retaining the query until its timeout or stop.
pub fn get() -> ExitCode {
    entry(Mode::Get)
}
/// Run the standard PUT PROGRAM. Success reports a complete local MQ write only.
pub fn put() -> ExitCode {
    entry(Mode::Put)
}
/// Monitor actual GET, PUT and RESULT messages through the configured DHT service.
pub fn monitor() -> ExitCode {
    entry(Mode::Monitor)
}
/// Obtain a public HELLO URL or offer the single positional URL for bootstrapping.
pub fn hello() -> ExitCode {
    entry(Mode::Hello)
}
fn entry(mode: Mode) -> ExitCode {
    match execute(mode) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _diagnostic = writeln!(
                io::stderr().lock(),
                "{}: {error}",
                String::from_utf8_lossy(mode.name())
            );
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn execute(_: Mode) -> Result<u8, Cause> {
    Err("native DHT commands require Unix".into())
}
#[cfg(unix)]
fn execute(mode: Mode) -> Result<u8, Cause> {
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
    let mut logger = Logger::new(mode.name(), std::process::id(), false)?;
    let selection = options::Selection::new(mode);
    let preparation = program::prepare(config, Invocation {
        binary_name: mode.name(),
        help: Some(b"Official DHT GET/PUT/MONITOR/HELLO through the configured DHT CLIENT endpoint. MONITOR observes all three message classes, with optional -k key/type filters. HELLO with no argument obtains a public URL; one positional URL offers it for bootstrapping. HELLO waits forever by default; an optional -T bounds it. -k KEY hashes the exact string with GNUnet SHA-512; -K accepts its printed Base32 key. -r replication defaults to 5; -t type defaults to TEST (8), -R records the route and -x demultiplexes everywhere. GET -T timeout defaults to 60 s and prints each actual result. PUT -d DATA requires nonempty bytes, -e expiration defaults to 1 h; PUT -T is an additional total wait budget, default 60 s. -V prints original write/retry/route diagnostics. A completed PUT is only a local IPC write, with no service, replication or durability acknowledgement. Standard -c/-L/-l/-h/-v apply."),
        select_default_filename: true, defaults: Defaults::Native,
    }, selection.options(), std::env::args_os(), &program::Environment::capture(), &mut NlsDisabled, &mut logger, &clock, &mut io::stdout().lock(), &mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<u8, Cause> {
        if let Some(notice) = early.notice {
            reporter.debug("dht.parent.notice", format_args!("{notice:?}"));
        }
        let prepared = match preparation? {
            Preparation::Ready(value) => *value,
            Preparation::Stopped(value)
                if value.code == 0 && matches!(value.reason, program::StoppedReason::Options) =>
            {
                return Ok(0);
            }
            Preparation::Stopped(value) => {
                return Err(format!(
                    "DHT PROGRAM preparation: {:?}, code {}",
                    value.reason, value.code
                )
                .into());
            }
        };
        let settings = selection.finish(prepared.main().arguments)?;
        let live = gnunet_client_host::LiveConfiguration::new(prepared.main().config.duplicate()?);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            use gnunet_service_runtime::clock::RuntimeClock;
            let actual: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
            let (mut context, resolver) = gnunet_resolver_broker::broker::<8, 64>(
                live.clone(),
                Default::default(),
                gnunet_resolver_broker::native_profile()?,
                actual.clone(),
            )?;
            let endpoint = gnunet_client_host::EndpointSource::live(
                live,
                b"dht",
                context.resolution_context(),
            );
            let stop = Rc::new(Cell::new(false));
            let product = run::run(run::Inputs {
                settings,
                endpoint,
                resolver,
                clock: actual,
                reporter: reporter.clone(),
                stop: stop.clone(),
                parent: early.parent,
                stdout: early.output,
            });
            foreground::run(prepared, &mut context, clock.clone(), stop, product)
                .await
                .map(|report| report.code)
        })
    })();
    if let Err(error) = &result {
        reporter.warning("dht.command.failed", format_args!("{error}"));
    }
    match (result, reporter.take_error()) {
        (Ok(code), None) => Ok(code),
        (original, logging) => Err(Box::new(ProgramFailure {
            original: original.err(),
            logging,
        })),
    }
}
