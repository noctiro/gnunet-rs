//! Shared normal NAT, NAT-AUTO and NAT-test PROGRAM process entry.
use super::{Inherited, Settings, scheduled};
use crate::{manager::Failure, server::Mode};
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation},
    reporting::Reporter,
    shared_clock::SharedClock,
};
use std::{
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
};

const fn binary(mode: Mode) -> &'static str {
    match mode {
        Mode::Nat => "gnunet-service-nat",
        Mode::Auto => "gnunet-service-nat-auto",
        Mode::Test => "gnunet-nat-server",
    }
}
/// Enter one normal NAT PROGRAM process with its original inherited resources.
///
/// # Safety
/// Call once as the first initialization of a fresh single-threaded executable,
/// before native resources, runtime, threads or environment mutation can compete
/// with capture. A capture failure ends startup without replaying declarations.
#[expect(
    unsafe_code,
    reason = "Unique executable boundary transfers inherited-resource ownership once"
)]
pub unsafe fn main(mode: Mode) -> ExitCode {
    // SAFETY: caller supplies the fresh-process initialization contract.
    match unsafe { run(mode) } {
        Ok(code) => code,
        Err(error) => {
            let _written = writeln!(io::stderr().lock(), "{}: {error}", binary(mode));
            ExitCode::FAILURE
        }
    }
}
#[expect(
    unsafe_code,
    reason = "Capture precedes every other native process owner"
)]
unsafe fn run(mode: Mode) -> Result<ExitCode, Failure> {
    // SAFETY: main forwards its caller's unique fresh-process contract.
    let inherited = unsafe { capture()? };
    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let name = binary(mode);
    let mut logger = Logger::new(name.as_bytes(), std::process::id(), false)?;
    let prepared = program::prepare(
        config,
        Invocation {
            binary_name: name.as_bytes(),
            help: Some(b"Official NAT registration, automatic configuration or NAT-test service. Local readiness proves listener ownership; traversal and mapping require their own observations. No positional arguments."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Default::default(), std::env::args_os(), &program::Environment::capture(),
        &mut NlsDisabled, &mut logger, &clock,
        &mut io::stdout().lock(), &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(prepared) => *prepared,
        Preparation::Stopped(stopped) => {
            return Ok(if stopped.code == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
    };
    let reports = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if !prepared.main().arguments.is_empty() {
            return Err("NAT service accepts no positional arguments".into());
        }
        let settings = Settings::read(prepared.main().config, mode)?;
        #[cfg(unix)]
        {
            use gnunet_service_startup::{
                GroupsProfile, apply_privileges, configured_user, resolve_user,
            };
            let user = configured_user(prepared.main().config, mode.service())?
                .map(|name| resolve_user(&name))
                .transpose()?;
            let identity = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
            if user.is_some() {
                reports.message(
                    Level::INFO,
                    "nat.identity",
                    format_args!("NAT configured process identity: {identity:?}"),
                );
            }
        }
        #[cfg(windows)]
        gnunet_service_startup::verify_configured_identity(prepared.main().config, mode.service())?;
        if reports.failed() {
            return Err("NAT selected Logger failed during startup".into());
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(scheduled(
                prepared,
                clock,
                settings,
                inherited,
                mode,
                reports.clone(),
            ))
    })();
    if let Err(error) = &result {
        reports.message(Level::ERROR, "nat.failure", format_args!("{name}: {error}"));
    }
    Ok(
        match gnunet_program_host::service::retain_diagnostic(result, reports.take_error()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
    )
}

#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Adopts original parent-declared resources before all other native ownership"
)]
unsafe fn capture() -> Result<Inherited, Failure> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: sole first operation under the public fresh-process contract.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    if let Some(notice) = captured.control_notice {
        let _written = writeln!(io::stderr().lock(), "NAT parent control: {notice:?}");
    }
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => return Err("wrong NAT inheritance route".into()),
    };
    Ok(Inherited {
        activation,
        parent: captured.parent_control,
    })
}
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Adopts original qualified parent and native activation once before other handles"
)]
unsafe fn capture() -> Result<Inherited, Failure> {
    // SAFETY: sole first operation under the public fresh-process contract.
    let captured = unsafe { gnunet_service_startup::capture_from_environment()? };
    let activation = captured
        .activation
        .map(|activation| {
            gnunet_service_runtime::Activation::from_imported(activation.materialize()?)
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Inherited {
        activation,
        parent: captured.parent_control,
    })
}
