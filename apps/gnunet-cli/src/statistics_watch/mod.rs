//! Shared normal STATISTICS PROGRAM/configuration/Resolver entry point.
mod driver;
mod finite;
mod output;
mod standalone;
mod testbed;
use gnunet_program_host::{
    logging::Logger,
    program::{self, Defaults, Invocation, Preparation},
    reporting::Reporter,
    shared_clock::SharedClock,
};
use std::{cell::Cell, error::Error, ffi::OsString, io, rc::Rc, sync::Arc};
type Failure = Box<dyn Error>;
const SERVICE: &[u8] = b"statistics";
struct Request {
    selector: driver::Names,
    operation: Operation,
    style: output::Style,
}

enum Operation {
    Watch,
    Finite(finite::Action),
    Testbed(std::path::PathBuf, finite::Action),
}

#[derive(Clone, Copy)]
enum Command {
    Watch,
    Get,
    Set,
}
enum InvocationKind {
    Grouped(Command),
    Standalone(standalone::Arguments),
}

pub(super) fn run(args: &[OsString]) -> Result<(), Failure> {
    let command = match args.first().and_then(|arg| arg.to_str()) {
        Some("watch") => Command::Watch,
        Some("get") => Command::Get,
        Some("set") => Command::Set,
        _ => return Err("expected statistics get|set|watch".into()),
    };
    run_program(InvocationKind::Grouped(command), args[1..].iter().cloned())
}

pub(super) fn run_standalone() -> Result<(), Failure> {
    run_program(
        InvocationKind::Standalone(standalone::Arguments::new()),
        std::env::args_os().skip(1),
    )
}

fn run_program(
    kind: InvocationKind,
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<(), Failure> {
    let inherited = crate::foreground::capture()?;
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let (logger_name, invocation, options) = match &kind {
        InvocationKind::Grouped(_) => (
            b"gnunet-cli.statistics".as_slice(),
            Invocation {
                binary_name: b"gnunet-cli statistics",
                help: Some(GROUPED_HELP),
                select_default_filename: true,
                defaults: Defaults::Native,
            },
            Default::default(),
        ),
        InvocationKind::Standalone(arguments) => (
            b"gnunet-statistics".as_slice(),
            Invocation {
                binary_name: b"gnunet-statistics",
                help: Some(b"Print GNUnet statistics. Use -s SUBSYSTEM and -n NAME to filter, -w to watch, or provide a value to set. -r HOST [-o PORT] selects a remote statistics service."),
                select_default_filename: true,
                defaults: Defaults::Native,
            },
            arguments.options(),
        ),
    };
    let mut logger = Logger::new(logger_name, std::process::id(), false)?;
    let mut environment = program::Environment::capture();
    let binary_name = std::str::from_utf8(invocation.binary_name)?;
    let mut argv = vec![OsString::from(binary_name)];
    if matches!(kind, InvocationKind::Grouped(Command::Get | Command::Set)) {
        // Finite commands interpret GNUNET_ARGS as prefix defaults so its
        // common options cannot become literal selectors after the endpoint.
        // Explicit argv options follow and therefore take precedence.
        argv = gnunet_program_host::getopt::append_environment(
            argv,
            environment.arguments.as_deref(),
        )?;
        environment.arguments = None;
        // Finite positional values include signed numbers and native names.
        // Require common PROGRAM options before the first endpoint; after it
        // only this command's explicit SET suffix flags are interpreted.
        environment.posixly_correct = true;
    }
    argv.extend(arguments);
    let prepared = program::prepare_installed(
        config,
        invocation,
        options,
        argv,
        &environment,
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) {
                return Ok(());
            }
            return Err(format!(
                "STATISTICS PROGRAM stopped: {:?}, source code{}",
                s.reason, s.code
            )
            .into());
        }
    };
    let reports = Reporter::new(logger, clock.clone());
    let result = run_selected(kind, prepared, inherited, clock, reports.clone());
    driver::finish(result, reports).map_err(|error| Box::new(Selected(error)) as Failure)
}

const GROUPED_HELP: &[u8] = b"Official STATISTICS get|set|watch. Finite syntax: get [common options] <UNIXPATH|-> [subsystem [name]]; set [common options] <UNIXPATH|-> <subsystem> <name> <u64|signed i64> [--relative] [--persistent]. Common -c/-L/-l precede the endpoint for GET/SET; -- explicitly ends PROGRAM options. '-' uses configured official Unix/TCP. GET streams until real END; SET requires the original processing confirmation (not disk sync). Relative zero reports a no-op. Watch arguments: <UNIXPATH|-> <subsystem> <name>; SIGINT/SIGTERM retires the original source.";

// Only STATISTICS failures after PROGRAM selected its logger carry this marker.
// Main keeps its existing fallback for early setup/other command failures.
#[derive(Debug)]
struct Selected(Failure);
impl std::fmt::Display for Selected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl Error for Selected {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
pub(super) fn selected(error: &(dyn Error + 'static)) -> bool {
    error.is::<Selected>()
}
fn grouped_request(
    command: Command,
    args: &[Vec<u8>],
    config: &mut gnunet_config::Configuration,
) -> Result<Request, Failure> {
    let (selector, operation) = match command {
        Command::Watch => {
            if args.len() != 3 {
                return Err(
                    "expected statistics watch [common options] <UNIXPATH|-> <subsystem> <name>"
                        .into(),
                );
            }
            let selector = driver::Names {
                subsystem: args[1].clone(),
                name: args[2].clone(),
            };
            (selector, Operation::Watch)
        }
        Command::Get => {
            if !(1..=3).contains(&args.len()) {
                return Err(
                    "expected statistics get [common options] <UNIXPATH|-> [subsystem [name]]"
                        .into(),
                );
            }
            let selector = driver::Names {
                subsystem: args.get(1).cloned().unwrap_or_default(),
                name: args.get(2).cloned().unwrap_or_default(),
            };
            (selector, Operation::Finite(finite::Action::Get))
        }
        Command::Set => {
            if args.len() < 4 {
                return Err("expected statistics set [common options] <UNIXPATH|-> <subsystem> <name> <value> [--relative] [--persistent]".into());
            }
            let mut relative = false;
            let mut persistent = false;
            for flag in &args[4..] {
                match flag.as_slice() {
                    b"--relative" => relative = true,
                    b"--persistent" => persistent = true,
                    _ => return Err("unknown STATISTICS SET suffix option; common PROGRAM options must precede endpoint".into()),
                }
            }
            let value = std::str::from_utf8(&args[3])?;
            let value = if relative {
                finite::Mutation::Relative(value.parse::<i64>()?)
            } else {
                finite::Mutation::Absolute(value.parse::<u64>()?)
            };
            let selector = driver::Names {
                subsystem: args[1].clone(),
                name: args[2].clone(),
            };
            (
                selector,
                Operation::Finite(finite::Action::Set { value, persistent }),
            )
        }
    };
    if args[0] != b"-" {
        config.set_value(SERVICE, b"UNIXPATH", Some(&args[0]))?;
        // Explicit socket mode must not fall back to another configured service.
        config.set_value(SERVICE, b"HOSTNAME", Some(b"localhost"))?;
        config.set_number(SERVICE, b"PORT", 0)?;
    }
    Ok(Request {
        selector,
        operation,
        style: output::Style::Json,
    })
}

fn run_selected(
    kind: InvocationKind,
    prepared: program::Prepared,
    inherited: crate::foreground::Inherited,
    clock: SharedClock,
    reports: Reporter,
) -> Result<driver::Report, Failure> {
    let args = prepared.main().arguments;
    let mut config = prepared.main().config.duplicate()?;
    let Request {
        selector,
        operation,
        style,
    } = match kind {
        InvocationKind::Grouped(command) => grouped_request(command, args, &mut config)?,
        InvocationKind::Standalone(arguments) => arguments.request(args, &mut config)?,
    };
    let (capacity, prefix) = match operation {
        Operation::Watch => (512, 8),
        Operation::Finite(finite::Action::Get) | Operation::Testbed(_, finite::Action::Get) => {
            (65535, 4)
        }
        Operation::Finite(finite::Action::Set { .. })
        | Operation::Testbed(_, finite::Action::Set { .. }) => (65535, 16),
    };
    validate_names(&selector, capacity, prefix)?;
    if let Some(notice) = inherited.notice {
        reports.warning("statistics.parent", format_args!("{notice}"));
    }
    if reports.failed() {
        return Err(reports.take_error().map_or_else(
            || Box::<dyn Error>::from("selected STATISTICS Logger failed"),
            |e| Box::new(e) as Failure,
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let source: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = Arc::new(clock.clone());
    let live = gnunet_client_host::LiveConfiguration::new(config);
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
    let stop = Rc::new(Cell::new(false));
    let inputs = driver::Inputs {
        selector,
        style,
        parent: inherited.parent,
        connection: driver::Connection {
            live,
            resolution,
            source,
            reports,
            stop: stop.clone(),
        },
        resolver,
    };
    let original = async move {
        match operation {
            Operation::Watch => driver::command(inputs).await,
            Operation::Finite(action) => finite::command(inputs, action).await,
            Operation::Testbed(path, action) => testbed::command(inputs, &path, action).await,
        }
    };
    let result = runtime.block_on(gnunet_program_host::foreground::run(
        prepared,
        &mut context,
        clock,
        stop,
        original,
    ));
    // Windows stdio uses a blocking OS worker. An unfinished write is reported
    // as such above; runtime destruction must not wait indefinitely for a reader.
    // This normal command then exits its process; no background worker is
    // certified canceled or physically drained by this nonwaiting shutdown.
    #[cfg(windows)]
    runtime.shutdown_background();
    result
}

fn validate_names(names: &driver::Names, capacity: usize, prefix: usize) -> Result<(), Failure> {
    #[cfg(windows)]
    {
        // PROGRAM preserves native path bytes. Protocol names require Unicode
        // on Windows rather than publishing local isolated-surrogate encodings.
        std::str::from_utf8(&names.subsystem)?;
        std::str::from_utf8(&names.name)?;
    }
    let bytes = names
        .subsystem
        .len()
        .checked_add(names.name.len())
        .and_then(|n| n.checked_add(2))
        .ok_or("STATISTICS selector length overflow")?;
    if bytes > capacity
        || bytes.checked_add(prefix).is_none_or(|n| n > 65535)
        || names.subsystem.contains(&0)
        || names.name.contains(&0)
    {
        return Err(
            "STATISTICS selector contains NUL or exceeds the original frame capacity".into(),
        );
    }
    Ok(())
}
