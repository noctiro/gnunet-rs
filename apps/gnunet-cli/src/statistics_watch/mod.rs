//! Shared normal STATISTICS PROGRAM/configuration/Resolver entry point.
mod control;
mod driver;
mod early;
mod finite;
mod output;
use gnunet_program_host::{
    logging::Logger,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation},
    reporting::Reporter,
    shared_clock::SharedClock,
};
use std::{
    cell::Cell, error::Error, ffi::OsString, io, os::unix::ffi::OsStrExt, rc::Rc, sync::Arc,
};
type Failure = Box<dyn Error>;
#[derive(Clone, Copy)]
enum Command {
    Watch,
    Get,
    Set,
}
pub(super) fn run(args: &[OsString]) -> Result<(), Failure> {
    let command = match args.first().map(|arg| arg.as_os_str().as_bytes()) {
        Some(b"watch") => Command::Watch,
        Some(b"get") => Command::Get,
        Some(b"set") => Command::Set,
        _ => return Err("expected statistics get|set|watch".into()),
    };
    let inherited = early::capture()?;
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-cli.statistics", std::process::id(), false)?;
    let mut environment = program::Environment::capture();
    let mut argv = vec![OsString::from("gnunet-cli statistics")];
    if !matches!(command, Command::Watch) {
        // Finite commands interpret GNUNET_ARGS as prefix defaults so its
        // common options cannot become literal selectors after the endpoint.
        // Explicit argv options follow and therefore take precedence.
        argv =
            gnunet_program_host::getopt::append_environment(argv, environment.arguments.as_deref());
        environment.arguments = None;
    }
    argv.extend(args[1..].iter().cloned());
    if !matches!(command, Command::Watch) {
        // Finite positional values include signed numbers and native names.
        // Require common PROGRAM options before the first endpoint; after it
        // only this command's explicit SET suffix flags are interpreted.
        environment.posixly_correct = true;
    }
    let prepared = program::prepare(
        config,
        Invocation {
            binary_name: b"gnunet-cli statistics",
            help: Some(b"Official STATISTICS get|set|watch. Finite syntax: get [common options] <UNIXPATH|-> [subsystem [name]]; set [common options] <UNIXPATH|-> <subsystem> <name> <u64|signed i64> [--relative] [--persistent]. Common -c/-L/-l precede the endpoint for GET/SET; -- explicitly ends PROGRAM options. '-' uses configured official Unix/TCP. GET streams until real END; SET requires the original processing confirmation (not disk sync). Relative zero reports a no-op. Watch arguments: <UNIXPATH|-> <subsystem> <name>; SIGINT/SIGTERM retires the original source."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Default::default(),
        argv,
        &environment,
        &mut NlsDisabled,
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
    let result = run_selected(command, prepared, inherited, clock, reports.clone());
    driver::finish(result, reports).map_err(|error| Box::new(Selected(error)) as Failure)
}

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
fn run_selected(
    command: Command,
    prepared: program::Prepared,
    inherited: early::Inherited,
    clock: SharedClock,
    reports: Reporter,
) -> Result<driver::Report, Failure> {
    let args = prepared.main().arguments;
    let (selector, action) = match command {
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
            validate_names(&selector, 512, 8)?;
            (selector, None)
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
            validate_names(&selector, 65535, 4)?;
            (selector, Some(finite::Action::Get))
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
            validate_names(&selector, 65535, 16)?;
            (selector, Some(finite::Action::Set { value, persistent }))
        }
    };
    let mut config = prepared.main().config.duplicate()?;
    if args[0] != b"-" {
        config.set_value(b"statistics", b"UNIXPATH", Some(&args[0]))?;
        // Explicit socket mode must not fall back to another configured service.
        config.set_value(b"statistics", b"HOSTNAME", Some(b"localhost"))?;
        config.set_number(b"statistics", b"PORT", 0)?;
    }
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
        parent: inherited.parent,
        live,
        resolution,
        source,
        reports,
        stop: stop.clone(),
        resolver,
    };
    let original = async move {
        if let Some(action) = action {
            finite::command(inputs, action).await
        } else {
            driver::command(inputs).await
        }
    };
    runtime.block_on(gnunet_program_host::foreground::run(
        prepared,
        &mut context,
        clock,
        stop,
        original,
    ))
}

fn validate_names(names: &driver::Names, capacity: usize, prefix: usize) -> Result<(), Failure> {
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
