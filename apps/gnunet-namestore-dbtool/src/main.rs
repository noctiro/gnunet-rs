//! Installed offline NAMESTORE database tool.
#![forbid(unsafe_code)]

use gnunet_config::{Configuration, ProjectData};
use gnunet_namestore_host::database::{Maintenance, Options};
use gnunet_program_host::{
    getopt,
    helpers::{self, Target},
    logging::Logger,
    program::{self, Defaults, Invocation, Preparation, StoppedReason},
    reporting::Reporter,
    shared_clock::SharedClock,
};
use std::{
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
};

const COMMAND: &[u8] = b"gnunet-namestore-dbtool";
type Failure = Box<dyn std::error::Error>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _written = writeln!(io::stderr().lock(), "gnunet-namestore-dbtool: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Failure> {
    let plugin = Target::new(None);
    let reset = Target::new(0);
    let mut switches = getopt::Options::new();
    switches.add(helpers::flag(
        b'i',
        b"init",
        b"initialize or validate the database",
        Target::new(0),
    ));
    switches.add(helpers::flag(
        b'r',
        b"reset",
        b"reset the database, permanently discarding all stored NAMESTORE records",
        reset.clone(),
    ));
    switches.add(helpers::string(
        b'p',
        b"plugin",
        b"PLUGIN",
        b"select the installed NAMESTORE backend (rust)",
        plugin.clone(),
    ));
    let clock = SharedClock::native(64)?;
    let config = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    let mut logger = Logger::new(COMMAND, std::process::id(), false)?;
    let prepared = program::prepare_installed(
        config,
        Invocation {
            binary_name: COMMAND,
            help: Some(b"Initialize or reset the offline Rust NAMESTORE database."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        switches,
        std::env::args_os(),
        &program::Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(prepared) => prepared,
        Preparation::Stopped(stopped) => {
            return match stopped.reason {
                StoppedReason::Options if stopped.code >= 0 => Ok(()),
                StoppedReason::Logging(error) => Err(error.into()),
                StoppedReason::Malformed(error) => Err(error.into()),
                reason => Err(io::Error::other(format!("PROGRAM stopped: {reason:?}")).into()),
            };
        }
    };
    let reports = Reporter::new(logger, clock);
    let main = prepared.main();
    if !main.arguments.is_empty() {
        reports.warning(
            "namestore.dbtool.arguments",
            format_args!("Superfluous command-line arguments ignored"),
        );
        if let Some(error) = reports.take_error() {
            return Err(error.into());
        }
    }
    match plugin.get()?.as_deref() {
        Some(b"rust") => {}
        None => return Err("No plugin given. Select --plugin rust".into()),
        Some(_) => return Err("Unsupported NAMESTORE plugin. Select --plugin rust".into()),
    }
    // Loading the selected backend initializes new storage by default. The
    // official explicit initialization switch has the same non-reset effect.
    let action = if reset.get()? == 0 {
        Maintenance::Initialize
    } else {
        Maintenance::Reset
    };
    Options::read(main.config)?.open()?.maintain(action)?;
    Ok(())
}
