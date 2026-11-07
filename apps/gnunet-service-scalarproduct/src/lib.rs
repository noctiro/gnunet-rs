//! Ordinary ECC/Paillier Alice/Bob SERVICE entrypoints over actual SETI/CADET owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod lifecycle;
#[cfg(unix)]
mod settings;
/// Enter the ordinary Alice executable before any user resources exist.
///
/// # Safety
/// The caller must be a fresh single-threaded executable entrypoint and must
/// call exactly once, before adopting descriptors or creating runtime owners.
#[expect(
    unsafe_code,
    reason = "Executable startup contract must remain explicit at the public application-library boundary"
)]
pub unsafe fn alice_main() -> ExitCode {
    entry(Mode::Alice)
}
/// Enter the ordinary Bob executable before any user resources exist.
///
/// # Safety
/// The caller must be a fresh single-threaded executable entrypoint and must
/// call exactly once, before adopting descriptors or creating runtime owners.
#[expect(
    unsafe_code,
    reason = "Executable startup contract must remain explicit at the public application-library boundary"
)]
pub unsafe fn bob_main() -> ExitCode {
    entry(Mode::Bob)
}
/// Enter the ordinary installed Paillier Alice executable.
///
/// # Safety
/// The caller must be a fresh single-threaded executable entrypoint and call
/// exactly once, before adopting descriptors or creating runtime owners.
#[expect(
    unsafe_code,
    reason = "Executable startup contract remains explicit at the public application-library boundary"
)]
pub unsafe fn paillier_alice_main() -> ExitCode {
    entry(Mode::PaillierAlice)
}
/// Enter the ordinary installed Paillier Bob executable.
///
/// # Safety
/// The caller must be a fresh single-threaded executable entrypoint and call
/// exactly once, before adopting descriptors or creating runtime owners.
#[expect(
    unsafe_code,
    reason = "Executable startup contract remains explicit at the public application-library boundary"
)]
pub unsafe fn paillier_bob_main() -> ExitCode {
    entry(Mode::PaillierBob)
}
#[derive(Clone, Copy)]
enum Mode {
    Alice,
    Bob,
    PaillierAlice,
    PaillierBob,
}
impl Mode {
    #[cfg(unix)]
    const fn profile_name(self) -> &'static str {
        match self {
            Self::Alice | Self::Bob => "ecc",
            Self::PaillierAlice | Self::PaillierBob => "paillier",
        }
    }
    #[cfg(unix)]
    fn profile(self) -> gnunet_scalarproduct_host::Profile {
        match self {
            Self::Alice | Self::Bob => gnunet_scalarproduct_host::Profile::Ecc,
            Self::PaillierAlice | Self::PaillierBob => {
                gnunet_scalarproduct_host::Profile::Paillier(
                    gnunet_scalarproduct_paillier::Limits::default(),
                )
            }
        }
    }
    #[cfg(unix)]
    const fn section(self) -> &'static [u8] {
        match self {
            Self::Alice | Self::PaillierAlice => b"scalarproduct-alice",
            Self::Bob | Self::PaillierBob => b"scalarproduct-bob",
        }
    }
    const fn binary(self) -> &'static str {
        match self {
            Self::Alice => "gnunet-service-scalarproduct-ecc-alice",
            Self::Bob => "gnunet-service-scalarproduct-ecc-bob",
            Self::PaillierAlice => "gnunet-service-scalarproduct-alice",
            Self::PaillierBob => "gnunet-service-scalarproduct-bob",
        }
    }
    #[cfg(unix)]
    const fn role(self) -> gnunet_scalarproduct_host::Role {
        match self {
            Self::Alice | Self::PaillierAlice => gnunet_scalarproduct_host::Role::Alice,
            Self::Bob | Self::PaillierBob => gnunet_scalarproduct_host::Role::Bob,
        }
    }
}
fn entry(mode: Mode) -> ExitCode {
    match run(mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(unix)]
            if error.downcast_ref::<lifecycle::Reported>().is_some() {
                return ExitCode::FAILURE;
            }
            let _actual = writeln!(io::stderr().lock(), "{}: {error}", mode.binary());
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run(mode: Mode) -> Result<(), Cause> {
    Err(format!("{} requires Unix", mode.binary()).into())
}
#[cfg(unix)]
fn run(mode: Mode) -> Result<(), Cause> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        reporting::Reporter,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::{BoundListeners, UnixListenerAccess};
    use gnunet_service_startup::{
        GroupsProfile, apply_privileges, configured_user,
        daemon::{self, Branch},
        resolve_user,
    };
    let early::Inherited {
        activation,
        parent,
        notice,
    } = early::capture()?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(mode.section(), std::process::id(), true)?;
    let selected = match service::prepare(
        mode.section(),
        &gnunet_config::ProjectData::default(),
        std::env::args_os(),
        &Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )? {
        Preparation::Ready(selected) => selected,
        Preparation::Stopped { successful } => {
            return if successful {
                Ok(())
            } else {
                Err("SCALARPRODUCT SERVICE options failed".into())
            };
        }
    };
    #[expect(
        unsafe_code,
        reason = "Only fresh single-threaded exec startup after flushed options, before runtime/NSS/path guards/SCALARPRODUCT/native sources; original captured owners remain unique"
    )]
    // SAFETY: sole explicit detach point. No runtime, thread, account lookup,
    // listener path guard, SCALARPRODUCT or CADET owner exists; no Logger/clock borrow
    // is held across fork. Selected logfile was lifted above stdio by setup.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(waiting)) => {
            drop(activation);
            drop(parent);
            let result = waiting
                .wait()
                .map(|_| ())
                .map_err(|error| Box::new(error) as Cause);
            let reports = Reporter::new(logger, clock);
            return finish(result, &reports, mode);
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            let reports = Reporter::new(logger, clock);
            return finish(Err(Box::new(error)), &reports, mode);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let reports = Reporter::new(logger, clock.clone());
    let cleanup = lifecycle::Cleanup::default();
    let result = (|| -> Result<(), Cause> {
        if let Some(notice) = notice {
            reports.warning(
                "scalarproduct.parent.notice",
                format_args!("SCALARPRODUCT parent-control declaration: {notice:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config, mode)?;
        let user = configured_user(&config, mode.section())?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let pending = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, mode.section(), activation)?
        };
        let actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "scalarproduct.identity",
                format_args!("SCALARPRODUCT configured process identity: {actual:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let bound = runtime.block_on(pending.finish_with_access(UnixListenerAccess {
            match_uid: settings.access.match_uid,
            match_gid: settings.access.match_gid,
        }))?;
        for error in bound.failures() {
            reports.warning(
                "scalarproduct.listener.alternate",
                format_args!("SCALARPRODUCT alternate listener: {error}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        runtime.block_on(foreground::run(foreground::Inputs {
            mode,
            config: &config,
            settings: &settings,
            bound: &bound,
            parent,
            clock: clock.clone(),
            reports: reports.clone(),
            child: &mut child,
            cleanup: cleanup.clone(),
        }))
    })();
    let result = service::retain_diagnostic(cleanup.finish(result), reports.take_error());
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Cause);
    finish(result, &reports, mode)
}
#[cfg(unix)]
fn finish(
    result: Result<(), Cause>,
    reports: &gnunet_program_host::reporting::Reporter,
    mode: Mode,
) -> Result<(), Cause> {
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "scalarproduct.failure",
            format_args!("{}: {error}", mode.binary()),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
        .map_err(|error| Box::new(lifecycle::Reported(error)) as Cause)
}
