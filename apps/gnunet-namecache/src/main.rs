//! Official NAMECACHE public-zone/name lookup and deletion PROGRAM.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(unix)]
mod display;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod settings;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-namecache: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Cause> {
    Err("NAMECACHE native PROGRAM requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Cause> {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Filename, Target},
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let zone = Target::new(None);
    let name = Target::new(None);
    let delete = Target::new(0);
    let timeout = Target::new(30_000_u32);
    let profile = Target::new(None);
    let socket = Target::new(Filename {
        path: None,
        error: None,
    });
    let mut options = Options::new();
    options.add(helpers::string(
        b'z',
        b"zone",
        b"PKEY",
        b"public PKEY or EDKEY zone identifier",
        zone.clone(),
    ));
    options.add(helpers::string(
        b'n',
        b"name",
        b"NAME",
        b"name whose cached records are displayed or deleted",
        name.clone(),
    ));
    options.add(helpers::flag(
        b'd',
        b"delete",
        b"remove the exact zone/name cached block",
        delete.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"timeout-ms",
        b"MS",
        b"original finite operation window, default 30000 (maximum 3600000)",
        timeout.clone(),
    ));
    options.add(helpers::filename(
        0,
        b"namecache-socket",
        b"PATH",
        b"explicit NAMECACHE Unix endpoint; otherwise use configured CLIENT selection",
        socket.clone(),
    ));
    options.add(helpers::string(
        0,
        b"record-profile",
        b"PROFILE",
        b"native, little, or big original producer layout for Messenger record values",
        profile.clone(),
    ));
    let clock = SharedClock::native(32)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-namecache", std::process::id(), false)?;
    let prepared = program::prepare(config, Invocation {
        binary_name: b"gnunet-namecache",
        help: Some(b"Inspect or delete the configured NAMECACHE's exact public zone/name entry. -z PKEY -n NAME derives the official query, validates the returned block's zone/name signature, decrypts it and displays applicable records. -d sends actual BLOCK_DELETE and preserves its signed result code. No DHT lookup, private-key files, daemon or new protocol. Text and total output are bounded; unsupported record values retain their numeric type and raw bytes."),
        select_default_filename: true,
        defaults: Defaults::Native,
    }, options, std::env::args_os(), &program::Environment::capture(), &mut NlsDisabled, &mut logger, &clock, &mut io::stdout().lock(), &mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(prepared) => *prepared,
        Preparation::Stopped(stopped) => {
            return if stopped.code == 0
                && matches!(&stopped.reason, program::StoppedReason::Options)
            {
                Ok(())
            } else {
                Err(format!(
                    "NAMECACHE PROGRAM stopped {:?}, source code {}",
                    stopped.reason, stopped.code
                )
                .into())
            };
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("NAMECACHE accepts no positional arguments".into());
    }
    let settings = settings::Settings::new(
        zone.get()?,
        name.get()?,
        delete.get()? != 0,
        timeout.get()?,
        socket.get()?,
        profile.get()?,
    )?;
    let reporter = Reporter::new(logger, clock.clone());
    let result: Result<(), Cause> = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| Box::new(error) as Cause)
        .and_then(|runtime| {
            runtime.block_on(foreground::scheduled(
                prepared,
                clock,
                settings,
                reporter.clone(),
            ))
        });
    if let Err(error) = &result {
        reporter.warning("namecache.program.failed", format_args!("{error}"));
    }
    let logging = reporter.take_error();
    match (result, logging) {
        (Ok(()), None) => Ok(()),
        (result, logging) => Err(Box::new(foreground::ProgramFailure {
            original: result.err(),
            logging,
        })),
    }
}
