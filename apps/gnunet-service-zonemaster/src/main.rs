//! Official ZONEMASTER foreground; active defaults come from `[zonemaster]`.
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
            if e.downcast_ref::<Reported>().is_some() {
                return ExitCode::FAILURE;
            }
            diagnostic(format_args!("gnunet-service-zonemaster: {e}"));
            ExitCode::FAILURE
        }
    }
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
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, Preparation},
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let inherited = inherited()?;
    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-service-zonemaster", std::process::id(), false)?;
    let prepared=program::prepare_installed(config,Invocation{binary_name:b"gnunet-service-zonemaster",help:Some(b"Official ZONEMASTER background monitor/inventory, real Rust GNS workers, public-only DHT publishing and private NAMECACHE. No domain IPC requests. Uses one bounded actual DHT client sharing this PROGRAM Resolver/clock. No positional arguments."),select_default_filename:true,defaults:Defaults::Native},Default::default(),std::env::args_os(),&program::Environment::capture(),&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
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
    let reports = gnunet_program_host::reporting::Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        let settings = gnunet_zonemaster_host::settings::Settings::read(prepared.main().config)?;
        let factory: Option<Box<dyn gnunet_zonemaster_host::publish::Factory>> =
            Some(Box::new(gnunet_zonemaster_host::publish::DhtFactory::new()));
        #[cfg(unix)]
        {
            use gnunet_service_startup::{
                GroupsProfile, apply_privileges, configured_user, resolve_user,
            };
            let user = configured_user(prepared.main().config, b"zonemaster")?
                .map(|name| resolve_user(&name))
                .transpose()?;
            apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        }
        #[cfg(windows)]
        gnunet_service_startup::verify_configured_identity(prepared.main().config, b"zonemaster")?;
        tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(gnunet_zonemaster_host::foreground::scheduled(
            prepared, clock, settings, inherited, factory, reports.clone(),
        ))
        .map(|report| {
            let local_written = report.publications.iter().filter(|notice| matches!(notice, gnunet_zonemaster_host::publish::Event::Submitted { .. })).count();
            reports.message(gnunet_program_host::policy::Level::INFO, "zonemaster.stopped", format_args!("ZONEMASTER stopped: {} original public notices, {} local submission notices; no remote-storage acknowledgement", report.publications.len(), local_written));
        })
    })();
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "zonemaster.failure",
            format_args!("gnunet-service-zonemaster: {error}"),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
        .map_err(|error| Box::new(Reported(error)) as Failure)
}
#[derive(Debug)]
struct Reported(Failure);
impl std::fmt::Display for Reported {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(out)
    }
}
impl Error for Reported {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Sole fresh-process capture transfers inherited native resources before competing owners"
)]
fn inherited() -> Result<gnunet_zonemaster_host::foreground::Inherited, Failure> {
    // SAFETY: run invokes this first, before logger, runtime, threads or native resource creation.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    let activation = captured
        .activation
        .map(|incoming| gnunet_service_runtime::Activation::from_imported(incoming.materialize()?))
        .transpose()?
        .unwrap_or_default();
    Ok(gnunet_zonemaster_host::foreground::Inherited {
        activation,
        parent: captured.parent_control,
    })
}
