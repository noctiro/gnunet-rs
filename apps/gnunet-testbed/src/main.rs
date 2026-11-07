//! Actual active v0.29.1 TESTBED configuration-generation PROGRAM utility.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _report = writeln!(io::stderr().lock(), "gnunet-testbed: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("TESTBED native configuration generator requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Filename, Target},
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_testbed_host::{self as host, core};
    use std::{
        ffi::OsString,
        path::{Path, PathBuf},
        sync::Arc,
    };
    let number = Target::new(0u32);
    let template = Target::new(Filename {
        path: None,
        error: None,
    });
    let prefix = Target::new(Filename {
        path: None,
        error: None,
    });
    let output = Target::new(Filename {
        path: None,
        error: None,
    });
    let trusted = Target::new(None);
    let hostname = Target::new(None);
    let low = Target::new(core::DEFAULT_LOW_PORT);
    let high = Target::new(core::DEFAULT_HIGH_PORT);
    let mut options = Options::new();
    options.add(helpers::uint(
        b'n',
        b"number",
        b"NUMBER",
        b"number of unique configurations to create",
        number.clone(),
    ));
    options.add(helpers::filename(
        b't',
        b"template",
        b"FILENAME",
        b"configuration template",
        template.clone(),
    ));
    options.add(helpers::filename(
        0,
        b"prefix",
        b"DIRECTORY",
        b"exact new/marked Rust TESTBED root (otherwise GNUNET_TESTBED_PREFIX)",
        prefix.clone(),
    ));
    options.add(helpers::filename(
        0,
        b"output",
        b"DIRECTORY",
        b"existing output directory (default current directory)",
        output.clone(),
    ));
    options.add(helpers::string(
        0,
        b"trusted-ip",
        b"IP/CIDR",
        b"trusted host/network added to generated service ACLs",
        trusted.clone(),
    ));
    options.add(helpers::string(
        0,
        b"hostname",
        b"NAME",
        b"actual generated service hostname (default localhost)",
        hostname.clone(),
    ));
    options.add(helpers::uint16(
        0,
        b"low-port",
        b"PORT",
        b"inclusive native port-probe range low",
        low.clone(),
    ));
    options.add(helpers::uint16(
        0,
        b"high-port",
        b"PORT",
        b"exclusive native port-probe range high",
        high.clone(),
    ));
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let clock = SharedClock::native(4)?;
    let mut logger = Logger::new(b"gnunet-testbed", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-testbed",help:Some(b"Create actual unique GNUnet configurations; active v0.29.1 TESTBED system/port utility. No controller IPC, peer launcher, key importer or topology protocol."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => p,
        Preparation::Stopped(s) => {
            if s.code == 0 {
                return Ok(());
            }
            return Err(format!(
                "PROGRAM stopped before TESTBED invocation: {:?} (source code {})",
                s.reason, s.code
            )
            .into());
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("TESTBED accepts no positional arguments".into());
    }
    let count = usize::try_from(number.get()?)?;
    let template = template.get()?;
    if let Some(error) = template.error {
        return Err(format!("invalid template filename: {error}").into());
    }
    let path = template.path.ok_or("--template is required")?;
    let mut loaded = prepared.main().config.duplicate()?;
    loaded.parse(&path)?;
    let bounds = host::Limits::default();
    if count == 0 || count > bounds.configurations {
        return Err("--number must be between 1 and 4096".into());
    }
    let per_configuration = host::required_ports(&loaded, bounds.ports_per_configuration)?;
    let low = low.get()?;
    let high = high.get()?;
    if low == 0 || low >= high {
        return Err("invalid inclusive/exclusive port range".into());
    }
    let total = count
        .checked_mul(per_configuration)
        .ok_or("port reservation count overflow")?;
    if total > usize::from(high - low) {
        return Err(
            "configuration batch needs more distinct ports than the requested range".into(),
        );
    }
    let mut slots = Vec::new();
    slots.try_reserve_exact(total.max(1))?;
    slots.resize_with(total.max(1), core::PortSlot::empty);
    let instance = core::Instance::new();
    let prefix = prefix.get()?;
    if let Some(error) = prefix.error {
        return Err(format!("invalid prefix filename: {error}").into());
    }
    let prefix = prefix
        .path
        .or_else(|| std::env::var_os("GNUNET_TESTBED_PREFIX").map(PathBuf::from));
    let output = output.get()?;
    if let Some(error) = output.error {
        return Err(format!("invalid output filename: {error}").into());
    }
    let output = output.path.unwrap_or(std::env::current_dir()?);
    let trusted = trusted.get()?.map(String::from_utf8).transpose()?;
    let native = host::Options {
        prefix,
        trusted_ip: trusted,
        hostname: hostname.get()?,
        low_port: low,
        high_port: high,
        limits: bounds,
        ..Default::default()
    };
    let mut system = host::System::create(&instance, &mut slots, native)?;
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "TESTBED root={} configurations={count} port-proof=bind-observation-only peer-ready=unclaimed",
        system.directory().display()
    )?;
    let name = path
        .file_name()
        .filter(|p| !p.is_empty())
        .ok_or("template has no safe basename")?;
    let outcome = (|| -> Result<(), Failure> {
        for n in 0..count {
            let generated = system.configuration_create(&loaded)?;
            // ARM.CONFIG and DEFAULTCONFIG must point to actual bytes, independently of
            // the exported caller-selected filename. Neither write starts a process.
            let canonical = system.write_configuration(
                &generated,
                &generated.default_config(),
                host::Replace::NewOnly,
            )?;
            writeln!(
                stdout,
                "CANONICAL number={n} path={} bytes={} durable=actual-fsync",
                canonical.path().display(),
                canonical.bytes()
            )?;
            let mut output_name = OsString::from(format!("{n:04}-"));
            output_name.push(name);
            let destination = output.join(output_name);
            let published = system.write_configuration(
                &generated,
                Path::new(&destination),
                host::Replace::Allowed,
            )?;
            writeln!(
                stdout,
                "CONFIG number={n} path={} bytes={} logical-ports={} durable=actual-fsync service-ready=unclaimed",
                published.path().display(),
                published.bytes(),
                generated.ports().count()
            )?;
        }
        stdout.flush()?;
        Ok(())
    })();
    let cleanup = system.destroy(false);
    match (outcome, cleanup) {
        (Ok(()), Ok(kept)) => {
            writeln!(stdout, "STOPPED paths={kept:?} processes-started=0")?;
            Ok(())
        }
        (Err(first), Ok(_)) => Err(first),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(first), Err(cleanup)) => {
            Err(format!("{first}; independent TESTBED cleanup failure: {cleanup}").into())
        }
    }
}
