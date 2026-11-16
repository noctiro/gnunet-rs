//! ARM option metadata on the shared byte-preserving PROGRAM/GETOPT engine.
use crate::locale::Locale;
use gnunet_native::os_bytes;
use gnunet_program_host::{format::Argument as Value, getopt, helpers};
use std::{
    cell::RefCell,
    ffi::{OsStr, OsString},
    io,
    rc::Rc,
};
/// Program-specific flags and inherited PROGRAM values.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Stop all services flag, retained until a successful ARM stop callback.
    pub end: bool,
    /// Start defaults flag.
    pub start: bool,
    /// Restart flag that schedules start after stop.
    pub restart: bool,
    /// Explicit delete-on-shutdown flag.
    pub delete: bool,
    /// Initial quiet status-output flag.
    pub quiet: bool,

    /// Show stopped list rows.
    pub all: bool,
    /// Create the independent monitor owner.
    pub monitor: bool,
    /// Request a service list.
    pub list: bool,
    /// Native byte name of the service to start.
    pub init: Option<Vec<u8>>,
    /// Native byte name of the service to stop.
    pub term: Option<Vec<u8>>,

    /// Relative microseconds; zero disables and MAX means forever.
    pub timeout: u64,
    /// Do not inherit stdout when starting ARM.
    pub no_stdout: bool,
    /// Do not inherit stderr when starting ARM.
    pub no_stderr: bool,
    /// Raw filename option before source filename expansion.
    pub config: Option<Vec<u8>>,

    /// Requested generic log level.
    pub log: Option<Vec<u8>>,
    /// Raw generic log filename option.
    pub logfile: Option<Vec<u8>>,
}
/// Completed parser output; an immediate result suppresses program startup.
#[derive(Debug)]
pub struct Parsed {
    /// Parsed official option values.
    pub options: Options,
    /// Immediate help/version bytes already produced by option processors.
    pub stdout: Vec<u8>,
    /// Parser diagnostics in the selected locale.
    pub stderr: Vec<u8>,
    /// Immediate source exit status; None means run the program.
    pub exit: Option<u8>,
    /// Original catalog/format/native-argument failure; no command may start.
    pub failure: Option<io::Error>,
    /// Remaining native positional arguments; gnunet-arm ignores them.
    pub remaining: Vec<OsString>,
}
#[derive(Clone, Copy)]
struct Opt {
    short: u8,
    name: &'static str,
    arg: Option<&'static str>,
    description: &'static str,
}
const FLAGS: [Opt; 16] = [
    Opt {
        short: b'e',
        name: "end",
        arg: None,
        description: "stop all GNUnet services",
    },
    Opt {
        short: b'i',
        name: "init",
        arg: Some("SERVICE"),
        description: "start a particular service",
    },
    Opt {
        short: b'k',
        name: "kill",
        arg: Some("SERVICE"),
        description: "stop a particular service",
    },
    Opt {
        short: b'a',
        name: "all",
        arg: None,
        description: "also show stopped services (used with -I)",
    },
    Opt {
        short: b's',
        name: "start",
        arg: None,
        description: "start all GNUnet default services",
    },
    Opt {
        short: b'r',
        name: "restart",
        arg: None,
        description: "stop and start all GNUnet default services",
    },
    Opt {
        short: b'd',
        name: "delete",
        arg: None,
        description: "delete config file and directory on exit",
    },
    Opt {
        short: b'm',
        name: "monitor",
        arg: None,
        description: "monitor ARM activities",
    },
    Opt {
        short: b'q',
        name: "quiet",
        arg: None,
        description: "don't print status messages",
    },
    Opt {
        short: b'T',
        name: "timeout",
        arg: Some("DELAY"),
        description: "exit with error status if operation does not finish after DELAY",
    },
    Opt {
        short: b'I',
        name: "info",
        arg: None,
        description: "list currently running services",
    },
    Opt {
        short: b'O',
        name: "no-stdout",
        arg: None,
        description: "don't let gnunet-service-arm inherit standard output",
    },
    Opt {
        short: b'E',
        name: "no-stderr",
        arg: None,
        description: "don't let gnunet-service-arm inherit standard error",
    },
    Opt {
        short: b'c',
        name: "config",
        arg: Some("FILENAME"),
        description: "use configuration file FILENAME",
    },
    Opt {
        short: b'L',
        name: "log",
        arg: Some("LOGLEVEL"),
        description: "configure logging to use LOGLEVEL",
    },
    Opt {
        short: b'l',
        name: "logfile",
        arg: Some("FILENAME"),
        description: "configure logging to write logs to FILENAME",
    },
];
/// Standard C-locale help through the same PROGRAM formatter used at runtime.
pub fn help() -> Vec<u8> {
    parse(
        [OsString::from("gnunet-arm"), OsString::from("--help")],
        None,
        false,
        b"0.29.1",
    )
    .stdout
}
fn apply(
    options: &mut Options,
    short: u8,
    name: &[u8],
    value: Option<&[u8]>,
    output: &mut getopt::Output<'_>,
) -> i32 {
    match short {
        b'e' => options.end = true,
        b's' => options.start = true,
        b'r' => options.restart = true,
        b'd' => options.delete = true,
        b'q' => options.quiet = true,
        b'a' => options.all = true,
        b'm' => options.monitor = true,
        b'I' => options.list = true,
        b'O' => options.no_stdout = true,
        b'E' => options.no_stderr = true,
        b'i' => options.init = value.map(<[u8]>::to_vec),
        b'k' => options.term = value.map(<[u8]>::to_vec),
        b'c' => options.config = value.map(<[u8]>::to_vec),
        b'L' => options.log = value.map(<[u8]>::to_vec),
        b'l' => options.logfile = value.map(<[u8]>::to_vec),
        b'T' => match value.and_then(|v| gnunet_config::parse_relative_time(v).ok()) {
            Some(time) => options.timeout = time,
            None => {
                output.error(
                    b"You must pass relative time to the `%s' option.\n",
                    &[Value::Bytes(name)],
                );
                return -1;
            }
        },
        _ => return -1,
    }
    1
}
/// Parse native argv with the explicit disabled-NLS profile. GNUNET_ARGS uses
/// literal spaces, and POSIXLY_CORRECT retains the shared GNU ordering rules.
pub fn parse(
    args: impl IntoIterator<Item = OsString>,
    gnunet_args: Option<&OsStr>,
    posix: bool,
    version: &[u8],
) -> Parsed {
    parse_localized(args, gnunet_args, posix, version, &Locale::disabled())
}
/// Parse with one retained locale for help, option errors and helper callbacks.
/// Catalog/format failures stay in `Parsed::failure` and force exit 255. Raw
/// option values remain data; a translated template never interprets them.
pub fn parse_localized(
    args: impl IntoIterator<Item = OsString>,
    gnunet_args: Option<&OsStr>,
    posix: bool,
    version: &[u8],
    locale: &Locale,
) -> Parsed {
    let arguments = getopt::append_environment(args, gnunet_args.map(os_bytes::encode).as_deref());
    let arguments = match arguments {
        Ok(arguments) => arguments,
        Err(error) => {
            return Parsed {
                options: Options::default(),
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit: Some(255),
                remaining: Vec::new(),
                failure: Some(error),
            };
        }
    };
    let project = gnunet_config::ProjectData::default();
    let values = Rc::new(RefCell::new(Options::default()));
    let mut table = getopt::Options::new();
    table.add(helpers::help(
        &project,
        Some(b"Control services and the Automated Restart Manager (ARM)"),
    ));
    table.add(helpers::version(version));
    for option in FLAGS {
        let short = option.short;
        let values = Rc::clone(&values);
        table.push(
            getopt::Spec {
                short,
                name: option.name.as_bytes(),
                argument_help: option.arg.map(str::as_bytes),
                description: Some(option.description.as_bytes()),
                argument: if option.arg.is_some() {
                    getopt::Argument::Required
                } else {
                    getopt::Argument::None
                },
                mandatory: false,
                exclusive: false,
            },
            move |_: getopt::Context<'_>,
                  name: &[u8],
                  value: Option<&[u8]>,
                  output: &mut getopt::Output<'_>| {
                match values.try_borrow_mut() {
                    Ok(mut values) => apply(&mut values, short, name, value, output),
                    Err(error) => {
                        output.failure = Some(io::Error::other(error));
                        -1
                    }
                }
            },
        );
    }
    table.sort_program();
    let mut run = table.run_translated(b"gnunet-arm", arguments, posix, locale.port());
    let mut remaining = Vec::new();
    if let Some(arguments) = run.remaining() {
        for value in arguments {
            match os_bytes::decode(value) {
                Ok(value) => remaining.push(value.into_owned()),
                Err(error) => {
                    run.output.failure = Some(error);
                    break;
                }
            }
        }
    }
    let options = match Rc::try_unwrap(values) {
        Ok(values) => values.into_inner(),
        Err(_) => {
            run.output.failure = Some(io::Error::other(
                "ARM option callbacks remain owned after GETOPT completion",
            ));
            Options::default()
        }
    };
    Parsed {
        options,
        stdout: run.output.stdout,
        stderr: run.output.stderr,
        exit: if run.output.failure.is_some() || run.code < 0 {
            Some(255)
        } else if run.code == 0 {
            Some(0)
        } else {
            None
        },
        remaining,
        failure: run.output.failure,
    }
}
