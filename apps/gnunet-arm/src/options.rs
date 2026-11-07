//! Byte-preserving source CLI/PROGRAM option processing (C locale).
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
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
    /// Exact C-locale parser diagnostics.
    pub stderr: Vec<u8>,
    /// Immediate source exit status; None means run the program.
    pub exit: Option<u8>,
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
const FLAGS: [Opt; 18] = [
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
        short: b'h',
        name: "help",
        arg: None,
        description: "print this help",
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
    Opt {
        short: b'v',
        name: "version",
        arg: None,
        description: "print the version number",
    },
];
/// Actual English help layout: the original29/31/78 column rules.
pub fn help() -> Vec<u8> {
    let mut out = String::from(
        "gnunet-arm\nControl services and the Automated Restart Manager (ARM)\nArguments mandatory for long options are also mandatory for short options.\n",
    );
    let mut options = FLAGS;
    options.sort_by_key(|o| (o.short.to_ascii_uppercase(), o.short));
    for option in options {
        let mut title = format!("  -{}, --{}", option.short as char, option.name);
        if let Some(arg) = option.arg {
            title.push('=');
            title.push_str(arg);
        }
        let mut column = title.len();
        out.push_str(&title);
        if column > 29 {
            out.push('\n');
            out.push_str(&" ".repeat(29));
            column = 29;
        }
        if column < 29 {
            out.push_str(&" ".repeat(29 - column));
            column = 29;
        }
        let bytes = option.description.as_bytes();
        let mut pos = 0;
        while bytes.len() - pos > 78 - column {
            let split = (pos + 1..=pos + 78 - column)
                .rev()
                .find(|&i| bytes[i].is_ascii_whitespace())
                .unwrap_or(pos + 78 - column);
            out.push_str(&option.description[pos..split]);
            out.push('\n');
            out.push_str(&" ".repeat(31));
            pos = split + 1;
            column = 31;
        }
        out.push_str(&option.description[pos..]);
        out.push('\n');
    }
    out.push_str("\nReport bugs to gnunet-developers@gnu.org.\nHome page: http://www.gnu.org/s/gnunet/\nGeneral help using GNU software: http://www.gnu.org/gethelp/\n");
    out.into_bytes()
}
impl Parsed {
    fn diagnostic(&mut self, binary: &[u8], message: &[u8]) {
        self.stderr.extend_from_slice(binary);
        self.stderr.extend_from_slice(b": ");
        self.stderr.extend_from_slice(message);
        self.stderr
            .extend_from_slice(b"\nUse --help to get a list of options.\n");
        self.exit = Some(255);
    }
    fn apply(&mut self, option: Opt, value: Option<&[u8]>, binary: &[u8], version: &[u8]) {
        if self.exit.is_some() {
            return;
        }
        match option.short {
            b'e' => self.options.end = true,
            b's' => self.options.start = true,
            b'r' => self.options.restart = true,
            b'd' => self.options.delete = true,
            b'q' => self.options.quiet = true,
            b'a' => self.options.all = true,
            b'm' => self.options.monitor = true,
            b'I' => self.options.list = true,
            b'O' => self.options.no_stdout = true,
            b'E' => self.options.no_stderr = true,
            b'i' => self.options.init = value.map(<[u8]>::to_vec),
            b'k' => self.options.term = value.map(<[u8]>::to_vec),
            b'c' => self.options.config = value.map(<[u8]>::to_vec),
            b'L' => self.options.log = value.map(<[u8]>::to_vec),
            b'l' => self.options.logfile = value.map(<[u8]>::to_vec),
            b'T' => match gnunet_config::parse_relative_time(value.unwrap_or_default()) {
                Ok(time) => self.options.timeout = time,
                Err(_) => {
                    self.stderr.extend_from_slice(
                        b"You must pass relative time to the `timeout' option.\n",
                    );
                    self.exit = Some(255);
                }
            },
            b'h' => {
                self.stdout.extend(help());
                self.exit = Some(0);
            }
            b'v' => {
                self.stdout.extend_from_slice(binary);
                self.stdout.extend_from_slice(b" v");
                self.stdout.extend_from_slice(version);
                self.stdout.push(b'\n');
                self.exit = Some(0);
            }
            _ => {}
        }
    }
}
/// Process actual native argv. GNUNET_ARGS appends literal-space-separated tokens,
/// not shell words. POSIXLY_CORRECT stops at the first non-option; otherwise
/// non-options are permuted/ignored by this CLI's run function, as in C.
pub fn parse(
    args: impl IntoIterator<Item = OsString>,
    gnunet_args: Option<&OsStr>,
    posix: bool,
    version: &[u8],
) -> Parsed {
    let mut args: Vec<OsString> = args.into_iter().collect();
    if let Some(extra) = gnunet_args {
        args.extend(
            extra
                .as_bytes()
                .split(|b| *b == b' ')
                .filter(|b| !b.is_empty())
                .map(|b| OsStr::from_bytes(b).to_os_string()),
        );
    }
    let binary = args
        .first()
        .map(|s| s.as_bytes())
        .unwrap_or(b"gnunet-arm")
        .to_vec();
    let mut out = Parsed {
        options: Options::default(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit: None,
        remaining: Vec::new(),
    };
    let mut i = 1;
    let mut matches = 0;
    let mut exclusive = None;
    while i < args.len() {
        let current = args[i].as_bytes().to_vec();
        i += 1;
        if current == b"--" {
            out.remaining.extend_from_slice(&args[i..]);
            break;
        }
        if current.len() < 2 || current[0] != b'-' {
            out.remaining
                .push(OsStr::from_bytes(&current).to_os_string());
            if posix {
                out.remaining.extend_from_slice(&args[i..]);
                break;
            }
            continue;
        }
        if current[1] == b'-' {
            let body = &current[2..];
            let split = body.iter().position(|b| *b == b'=');
            let name = &body[..split.unwrap_or(body.len())];
            let equal = split.map(|n| &body[n + 1..]);
            let exact = FLAGS.iter().find(|o| o.name.as_bytes() == name);
            let candidates: Vec<_> = FLAGS
                .iter()
                .filter(|o| o.name.as_bytes().starts_with(name))
                .collect();
            let option = exact.or_else(|| {
                if candidates.len() == 1 {
                    Some(candidates[0])
                } else {
                    None
                }
            });
            let Some(&option) = option else {
                let mut message = if candidates.len() > 1 {
                    b"option `".to_vec()
                } else {
                    b"unrecognized option `".to_vec()
                };
                message.extend_from_slice(&current);
                message.extend_from_slice(if candidates.len() > 1 {
                    b"' is ambiguous"
                } else {
                    b"'"
                });
                out.diagnostic(&binary, &message);
                continue;
            };
            let value = if option.arg.is_some() {
                if let Some(v) = equal {
                    Some(v.to_vec())
                } else if i < args.len() {
                    let v = args[i].as_bytes().to_vec();
                    i += 1;
                    Some(v)
                } else {
                    let mut message = b"option `".to_vec();
                    message.extend_from_slice(&current);
                    message.extend_from_slice(b"' requires an argument");
                    out.diagnostic(&binary, &message);
                    continue;
                }
            } else {
                if equal.is_some() {
                    let mut message = b"option `--".to_vec();
                    message.extend_from_slice(option.name.as_bytes());
                    message.extend_from_slice(b"' does not allow an argument");
                    out.diagnostic(&binary, &message);
                    continue;
                }
                None
            };
            matches += 1;
            if matches!(option.short, b'h' | b'v') {
                exclusive = Some(option.name);
            }
            out.apply(option, value.as_deref(), &binary, version);
        } else {
            let mut at = 1;
            while at < current.len() {
                let short = current[at];
                at += 1;
                let Some(&option) = FLAGS.iter().find(|o| o.short == short) else {
                    let mut message = b"invalid option -- ".to_vec();
                    message.push(short);
                    out.diagnostic(&binary, &message);
                    continue;
                };
                let value = if option.arg.is_some() {
                    if at < current.len() {
                        let value = current[at..].to_vec();
                        at = current.len();
                        Some(value)
                    } else if i < args.len() {
                        let value = args[i].as_bytes().to_vec();
                        i += 1;
                        Some(value)
                    } else {
                        let mut message = b"option requires an argument -- ".to_vec();
                        message.push(short);
                        out.diagnostic(&binary, &message);
                        continue;
                    }
                } else {
                    None
                };
                matches += 1;
                if matches!(short, b'h' | b'v') {
                    exclusive = Some(option.name);
                }
                out.apply(option, value.as_deref(), &binary, version);
            }
        }
    }
    if let Some(name) = exclusive
        && matches > 1
    {
        out.stderr.extend_from_slice(
            format!("Option `{name}' can't be used with other options.\n").as_bytes(),
        );
        out.exit = Some(255);
    }
    out
}
