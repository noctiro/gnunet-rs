//! Actual Rust official gnunet-service-nat foreground.
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
            diagnostic(format_args!("gnunet-service-nat: {e}"));
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("native NAT foreground requires Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "first single-threaded exec-child operation exclusively adopts parent-declared descriptors exactly once"
)]
fn inherited() -> Result<gnunet_nat_host::foreground::Inherited, Failure> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: sole first operation before logging/config/runtime or any FD owner.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    if let Some(notice) = captured.control_notice {
        diagnostic(format_args!("NAT parent control: {notice:?}"));
    }
    let activation = match captured.inherited {
        InheritedResources::Listeners(a) => a,
        InheritedResources::CloseAfterBind(_) => {
            return Err("wrong NAT descriptor inheritance route".into());
        }
    };
    Ok(gnunet_nat_host::foreground::Inherited {
        activation,
        parent: captured.parent_control,
    })
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_nat_host::server::Mode;
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
    let mut logger = Logger::new(b"gnunet-service-nat", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-service-nat",help:Some(b"Official GNUnet NAT service, NAT-auto proposal or NAT-test sender over shared SERVICE/PROGRAM. Actual Rust interfaces/STUN/SSDP/IGD/helpers. Foreground local READY is not connectivity or mapping publication. No positional arguments."),select_default_filename:true,defaults:Defaults::Native},Default::default(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            if s.code == 0 {
                return Ok(());
            }
            return Err(format!("PROGRAM stopped: {:?} code{}", s.reason, s.code).into());
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("NAT service accepts no positional arguments".into());
    }
    let mode = Mode::Nat;
    let settings = gnunet_nat_host::foreground::Settings::read(prepared.main().config, mode)?;
    let user = configured_user(prepared.main().config, mode.service())?
        .map(|n| resolve_user(&n))
        .transpose()?;
    let privilege = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
    if user.is_some() {
        diagnostic(format_args!("NAT process identity: {privilege:?}"));
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(gnunet_nat_host::foreground::scheduled(
            prepared, clock, settings, inherited, mode,
        ))
}
