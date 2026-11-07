use crate::Failure;
use gnunet_bcd_host::{Limits, provider};
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
pub struct Arguments {
    port: Target<u16>,
}
pub struct Settings {
    pub address: SocketAddr,
    pub renderer: Arc<provider::Settings>,
    pub limits: Limits,
}
impl Arguments {
    pub fn new() -> Self {
        Self {
            port: Target::new(8888),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut o = Options::new();
        o.add(helpers::uint16(
            b'p',
            b"port",
            b"PORT",
            b"HTTP listening port (default 8888)",
            self.port.clone(),
        ));
        o
    }
    pub fn select(&self, c: &Configuration, args: &[Vec<u8>]) -> Result<Settings, Failure> {
        if !args.is_empty() {
            return Err("BCD accepts no positional operands".into());
        }
        let section = b"bcd-rust";
        let number = |key: &[u8], default: u64| -> Result<u64, Failure> {
            Ok(c.get(section, key)
                .map(|_| c.get_number(section, key))
                .transpose()?
                .unwrap_or(default))
        };
        let size = |key: &[u8], default: usize| -> Result<usize, Failure> {
            Ok(usize::try_from(
                c.get(section, key)
                    .map(|_| c.get_size(section, key))
                    .transpose()?
                    .unwrap_or(u64::try_from(default)?),
            )?)
        };
        let time = |key: &[u8], default: Duration| -> Result<Duration, Failure> {
            Ok(Duration::from_micros(
                c.get(section, key)
                    .map(|_| c.get_time(section, key))
                    .transpose()?
                    .unwrap_or(u64::try_from(default.as_micros())?),
            ))
        };
        let path = |key: &[u8], default: PathBuf| -> Result<PathBuf, Failure> {
            Ok(c.get(section, key)
                .map(|_| c.get_filename(section, key, &gnunet_config::ProcessEnvironment))
                .transpose()?
                .unwrap_or(default))
        };
        let d = provider::Limits::default();
        let provider_limits = provider::Limits {
            field_bytes: size(b"FIELD_BYTES", d.field_bytes)?,
            request_bytes: size(b"REQUEST_BYTES", d.request_bytes)?,
            tex_bytes: size(b"TEX_BYTES", d.tex_bytes)?,
            output_bytes: size(b"OUTPUT_BYTES", d.output_bytes)?,
            log_bytes: size(b"LOG_BYTES", d.log_bytes)?,
            work_files: size(b"WORK_FILES", d.work_files)?,
            work_bytes: size(b"WORK_BYTES", d.work_bytes)?,
            poll_interval: time(b"CHILD_POLL", d.poll_interval)?,
            terminate_grace: time(b"TERM_GRACE", d.terminate_grace)?,
            cleanup_grace: time(b"CLEANUP_GRACE", d.cleanup_grace)?,
        };
        let launcher = if c.get(section, b"LAUNCHER").is_some() {
            c.get_filename(section, b"LAUNCHER", &gnunet_config::ProcessEnvironment)?
        } else {
            c.project_data()
                .libexec_binary_path(b"gnunet-arm-spawn-helper")?
        };
        let renderer = Arc::new(provider::Settings {
            pdflatex: path(b"PDFLATEX", PathBuf::from("/usr/bin/pdflatex"))?,
            ghostscript: path(b"GHOSTSCRIPT", PathBuf::from("/usr/bin/gs"))?,
            launcher,
            temp_root: path(b"TEMP_ROOT", std::env::temp_dir())?,
            configuration: Arc::new(c.duplicate()?),
            limits: provider_limits,
        });
        let d = Limits::default();
        let limits = Limits {
            connections: usize::try_from(number(b"CONNECTIONS", u64::try_from(d.connections)?)?)?,
            jobs: usize::try_from(number(b"JOBS", u64::try_from(d.jobs)?)?)?,
            header_bytes: size(b"HEADER_BYTES", d.header_bytes)?,
            headers: usize::try_from(number(b"HEADERS", u64::try_from(d.headers)?)?)?,
            query_bytes: size(b"QUERY_BYTES", d.query_bytes)?,
            field_bytes: size(b"FIELD_BYTES", d.field_bytes)?,
            retained_bytes: size(b"RETAINED_BYTES", d.retained_bytes)?,
            head_timeout: time(b"HEAD_TIMEOUT", d.head_timeout)?,
            whole_timeout: time(b"WHOLE_TIMEOUT", d.whole_timeout)?,
            output_timeout: time(b"OUTPUT_TIMEOUT", d.output_timeout)?,
        };
        limits.validate(&renderer)?;
        let address = c
            .get(section, b"BIND_TO")
            .map(|raw| std::str::from_utf8(raw).map_err(|_| "BIND_TO must be numeric IP"))
            .transpose()?
            .unwrap_or("::")
            .parse::<IpAddr>()?;
        let port = self.port.get()?;
        if port == 0 {
            return Err("BCD port must be nonzero".into());
        }
        Ok(Settings {
            address: SocketAddr::new(address, port),
            renderer,
            limits,
        })
    }
}
