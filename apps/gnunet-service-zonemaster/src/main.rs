//! Official ZONEMASTER foreground; active defaults come from [zonemaster].
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _written = writeln!(io::stderr().lock(), "{args}");
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diagnostic(format_args!("gnunet-service-zonemaster: {e}"));
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("ZONEMASTER native clients/foreground require Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "sole first exec-child operation captures original parent-declared descriptors before any other FD owner or runtime"
)]
fn inherited() -> Result<gnunet_zonemaster_host::foreground::Inherited, Failure> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: sole first startup operation, single-threaded and before config,
    // logs, signals, Resolver, runtime or any competing descriptor ownership.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    if let Some(notice) = captured.control_notice {
        diagnostic(format_args!("ZONEMASTER parent control: {notice:?}"));
    }
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("wrong ZONEMASTER inheritance route".into());
        }
    };
    Ok(gnunet_zonemaster_host::foreground::Inherited {
        activation,
        parent: captured.parent_control,
    })
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
    use std::sync::Arc;
    let inherited = inherited()?;
    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-service-zonemaster", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-service-zonemaster",help:Some(b"Official ZONEMASTER background monitor/inventory, real Rust GNS workers, public-only DHT publishing and private NAMECACHE. No domain IPC requests. Uses one bounded actual DHT client sharing this PROGRAM Resolver/clock. No positional arguments."),select_default_filename:true,defaults:Defaults::Native},Default::default(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            if s.code == 0 {
                return Ok(());
            }
            return Err(format!("ZONEMASTER PROGRAM stopped {:?} code{}", s.reason, s.code).into());
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("ZONEMASTER accepts no positional arguments".into());
    }
    let settings = gnunet_zonemaster_host::settings::Settings::read(prepared.main().config)?;
    let factory: Option<Box<dyn gnunet_zonemaster_host::publish::Factory>> =
        Some(Box::new(gnunet_zonemaster_host::publish::DhtFactory::new()));
    let user = configured_user(prepared.main().config, b"zonemaster")?
        .map(|name| resolve_user(&name))
        .transpose()?;
    let _actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(gnunet_zonemaster_host::foreground::scheduled(
            prepared, clock, settings, inherited, factory,
        ))
        .map(|report| {
            let local_written = report.publications.iter().filter(|notice| matches!(notice, gnunet_zonemaster_host::publish::Event::Submitted { .. })).count();
            diagnostic(format_args!("ZONEMASTER stopped: {} original public notices, {} local submission notices; no remote-storage acknowledgement", report.publications.len(), local_written));
        })
}
