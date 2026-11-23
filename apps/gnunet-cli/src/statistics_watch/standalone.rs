//! Options for the standalone STATISTICS command.

use super::{
    Failure, Operation, Request, SERVICE,
    driver::Names,
    finite::{Action, Mutation},
    output::{Style, Text},
};
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Filename, Target},
};

pub(super) struct Arguments {
    name: Target<Option<Vec<u8>>>,
    subsystem: Target<Option<Vec<u8>>>,
    persistent: Target<i32>,
    separator: Target<Option<Vec<u8>>>,
    testbed: Target<Filename>,
    quiet: Target<i32>,
    watch: Target<i32>,
    remote: Target<Option<Vec<u8>>>,
    port: Target<u64>,
}

impl Arguments {
    pub(super) fn new() -> Self {
        Self {
            name: Target::new(None),
            subsystem: Target::new(None),
            persistent: Target::new(0),
            separator: Target::new(None),
            testbed: Target::new(Filename {
                path: None,
                error: None,
            }),
            quiet: Target::new(0),
            watch: Target::new(0),
            remote: Target::new(None),
            port: Target::new(0),
        }
    }

    pub(super) fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::string(
            b'n',
            b"name",
            b"NAME",
            b"Select a statistic name",
            self.name.clone(),
        ));
        options.add(helpers::string(
            b's',
            b"subsystem",
            b"SUBSYSTEM",
            b"Select a subsystem",
            self.subsystem.clone(),
        ));
        options.add(helpers::flag(
            b'p',
            b"persistent",
            b"Make the set value persistent",
            self.persistent.clone(),
        ));
        options.add(helpers::string(
            b'S',
            b"csv-separator",
            b"CSV_SEPARATOR",
            b"Use the given text field separator",
            self.separator.clone(),
        ));
        options.add(helpers::filename(
            b't',
            b"testbed",
            b"TESTBED",
            b"Read statistics from the numbered node configurations in this directory",
            self.testbed.clone(),
        ));
        options.add(helpers::flag(
            b'q',
            b"quiet",
            b"Print only the values",
            self.quiet.clone(),
        ));
        options.add(helpers::flag(
            b'w',
            b"watch",
            b"Watch a value continuously",
            self.watch.clone(),
        ));
        options.add(helpers::string(
            b'r',
            b"remote",
            b"REMOTE",
            b"Connect to a remote host",
            self.remote.clone(),
        ));
        options.add(helpers::ulong(
            b'o',
            b"port",
            b"PORT",
            b"TCP port for the remote host",
            self.port.clone(),
        ));
        options
    }

    pub(super) fn request(
        &self,
        args: &[Vec<u8>],
        config: &mut Configuration,
    ) -> Result<Request, Failure> {
        let Filename {
            path: testbed,
            error,
        } = self.testbed.get()?;
        if let Some(error) = error {
            return Err(format!("expand TESTBED path: {error}").into());
        }
        let name = self.name.get()?;
        let subsystem = self.subsystem.get()?;
        let watch = self.watch.get()? != 0;
        if watch && testbed.is_some() {
            return Err("STATISTICS cannot watch TESTBED nodes".into());
        }
        if (watch || !args.is_empty()) && (subsystem.is_none() || name.is_none()) {
            return Err("STATISTICS WATCH and SET require -s/--subsystem and -n/--name".into());
        }
        let action = match args {
            [] => Action::Get,
            [value] => Action::Set {
                value: Mutation::Absolute(gnunet_config::parse_number(value)?),
                persistent: self.persistent.get()? != 0,
            },
            _ => return Err("expected at most one STATISTICS value".into()),
        };
        if testbed.is_none()
            && let Some(host) = self.remote.get()?
        {
            let specified = self.port.get()?;
            let port = if specified == 0 {
                config.get_number(SERVICE, b"PORT")?
            } else if specified < u64::from(u16::MAX) {
                specified
            } else {
                return Err("STATISTICS -o/--port must be below 65535".into());
            };
            if host.is_empty() || port == 0 || u16::try_from(port).is_err() {
                return Err("remote STATISTICS requires a host and valid TCP port".into());
            }
            config.set_value(SERVICE, b"UNIXPATH", Some(b""))?;
            config.set_value(SERVICE, b"HOSTNAME", Some(&host))?;
            config.set_number(SERVICE, b"PORT", port)?;
        }
        let operation = match testbed {
            Some(path) => Operation::Testbed(path, action),
            None if watch && args.is_empty() => Operation::Watch,
            None => Operation::Finite(action),
        };
        Ok(Request {
            selector: Names {
                subsystem: subsystem.unwrap_or_default(),
                name: name.unwrap_or_default(),
            },
            operation,
            style: Style::Text(Text {
                quiet: self.quiet.get()? != 0,
                separator: self.separator.get()?.unwrap_or_default(),
            }),
        })
    }
}
