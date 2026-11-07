//! Standard datastore binary dump/import PROGRAM; no private key or FS repository.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod format;
#[cfg(unix)]
mod stream;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _reported = writeln!(io::stderr().lock(), "gnunet-datastore: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("DATASTORE native PROGRAM requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Filename, Target},
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::{cell::Cell, rc::Rc, sync::Arc};
    let inherited = early::capture()?;
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let dump = Target::new(0);
    let insert = Target::new(0);
    let filename = Target::new(Filename {
        path: None,
        error: None,
    });
    let mut options = Options::new();
    options.add(helpers::flag(
        b'd',
        b"dump",
        b"Dump all records from the datastore",
        dump.clone(),
    ));
    options.add(helpers::flag(
        b'i',
        b"insert",
        b"Insert records into the datastore",
        insert.clone(),
    ));
    options.add(helpers::filename(
        b'f',
        b"file",
        b"FILENAME",
        b"File to dump or insert",
        filename.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-datastore", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-datastore",help:Some(b"Manipulate GNUnet datastore. -d writes the official binary format to stdout; -i reads it from stdin. -f selects a file. Both flags dump first, then insert. No FS repository semantics or automatic mutation replay."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) {
                return Ok(());
            }
            return Err(format!(
                "DATASTORE PROGRAM stopped: {:?} (source code {})",
                s.reason, s.code
            )
            .into());
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("DATASTORE accepts no positional arguments".into());
    }
    let dump = dump.get()? != 0;
    let insert = insert.get()? != 0;
    if !dump && !insert {
        return Err("choose at least one operation: --dump or --insert".into());
    }
    let filename = filename.get()?;
    if let Some(error) = filename.error {
        return Err(Box::new(FilenameFailure(error)));
    }
    let reports = Reporter::new(logger, clock.clone());
    if let Some(notice) = inherited.notice.as_ref() {
        reports.warning("datastore.parent", format_args!("{notice}"));
    }
    if reports.failed() {
        return Err(reports.take_error().map_or_else(
            || Box::<dyn Error>::from("selected DATASTORE Logger failed"),
            |error| Box::new(error) as Failure,
        ));
    }
    let stop = Rc::new(Cell::new(false));
    // Create the reactor before acquiring the one Resolver owner, so a
    // builder error cannot drop a never-polled product future with that owner.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let source: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = Arc::new(clock.clone());
    let live = gnunet_client_host::LiveConfiguration::new(prepared.main().config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<4, 256>(
        live.clone(),
        gnunet_resolver_broker::Limits {
            max_frame_bytes: 4096,
            io_chunk_bytes: 4096,
            max_queued_frames: 4,
        },
        gnunet_resolver_broker::native_profile()?,
        source.clone(),
    )?;
    let resolution = context.resolution_context();
    let original = foreground::command(foreground::Inputs {
        dump,
        insert,
        path: filename.path,
        parent: inherited.parent,
        live,
        resolution,
        source,
        reports: reports.clone(),
        stop: stop.clone(),
        resolver,
    });
    let result = runtime.block_on(gnunet_program_host::foreground::run(
        prepared,
        &mut context,
        clock,
        stop,
        original,
    ));
    foreground::finish(result, reports)
}
#[cfg(unix)]
#[derive(Debug)]
struct FilenameFailure(std::rc::Rc<gnunet_config::Error>);
#[cfg(unix)]
impl std::fmt::Display for FilenameFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
#[cfg(unix)]
impl Error for FilenameFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.0)
    }
}
