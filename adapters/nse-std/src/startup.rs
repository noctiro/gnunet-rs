//! Foreground official configuration, listener activation and shared CLIENT process ports.
use crate::{
    Limits,
    statistics::{NoStatistics, StatisticsFactory},
};
use gnunet_config::{Configuration, ProjectData};
use gnunet_nse::{crypto::WorkBits, owner};
use gnunet_service_runtime::{
    Activation, BoundListeners,
    accepted::SocketEvent,
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
};
mod driver;
mod identity;
mod reporting;
use driver::run_foreground;
#[cfg(unix)]
use gnunet_service_runtime::ListenerPreparation;
#[cfg(unix)]
pub use identity::ConfiguredIdentityMismatch;
pub use identity::verify_configured_identity;
pub use reporting::{AdmissionFailure, Report};
use std::{
    error::Error,
    future::Future,
    io::{self, Write},
    path::Path,
    sync::Arc,
};

fn stderr_admission(failure: AdmissionFailure) -> Result<(), Box<dyn Error>> {
    writeln!(
        io::stderr().lock(),
        "nse unadmitted subscriber {:?}: {}",
        failure.peer,
        failure.error
    )?;
    Ok(())
}
/// Load official installation defaults followed by the selected/default user file.
pub fn configuration(selected: Option<&Path>) -> Result<Configuration, Box<dyn Error>> {
    let project = Arc::new(ProjectData::default());
    let mut cfg = Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let selected = selected
        .map(Path::to_path_buf)
        .or_else(|| discovered.filter(|p| p.is_file()));
    cfg.load(selected.as_deref())?;
    Ok(cfg)
}
/// Read exact official NSE INTERVAL, WORKDELAY and WORKBITS values. Installation
/// defaults select1h/5ms/15; missing or invalid required settings are errors.
pub fn settings(config: &Configuration) -> Result<owner::Config, Box<dyn Error>> {
    Ok(owner::Config {
        interval_micros: config.get_time(b"NSE", b"INTERVAL")?,
        work_delay_micros: config.get_time(b"NSE", b"WORKDELAY")?,
        work_bits: WorkBits::new(u16::try_from(config.get_number(b"NSE", b"WORKBITS")?)?)?,
        ..owner::Config::default()
    })
}
// Configured foreground ownership chooses once, before listener/proof/native
// client admission. Direct Host constructors retain their explicit Limits.
fn configured_limits(config: &Configuration, mut limits: Limits) -> Result<Limits, Box<dyn Error>> {
    limits.pils_profile = gnunet_pils::Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
    Ok(limits)
}
/// Read both exact official Unix credential options. The shared UnixAccess
/// implementation applies UID priority; parsing never silently removes a bad
/// configured restriction.
pub fn unix_access(config: &Configuration) -> Result<UnixAccess, gnunet_config::Error> {
    let read = |key: &[u8]| {
        config
            .get(b"NSE", key)
            .map(|_| config.get_yesno(b"NSE", key))
            .transpose()
            .map(|v| v.unwrap_or(false))
    };
    Ok(UnixAccess {
        match_uid: read(b"UNIX_MATCH_UID")?,
        match_gid: read(b"UNIX_MATCH_GID")?,
    })
}
/// Run the actual foreground native NSE service on a shared absolute UTC source.
/// No C service, hidden Resolver task or native DNS replacement is created.
pub async fn foreground(
    config: &Configuration,
    activation: Activation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
) -> Result<Report, Box<dyn Error>> {
    foreground_with_clock(
        config,
        activation,
        limits,
        ready,
        shutdown,
        observe,
        Arc::new(SystemClock),
    )
    .await
}
/// Compose actual CORE/PILS clients and one explicitly driven process Resolver on
/// the caller's canonical absolute UTC clock. The host owns all original effects.
pub async fn foreground_with_clock(
    config: &Configuration,
    activation: Activation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn Error>> {
    verify_configured_identity(config)?;
    let limits = configured_limits(config, limits)?;
    #[cfg(unix)]
    let bound = BoundListeners::bind(config, b"NSE", activation).await?;
    #[cfg(windows)]
    let bound = if activation.is_empty() {
        BoundListeners::bind_configured(config, b"NSE", unix_access(config)?.into()).await?
    } else {
        BoundListeners::from_activation(activation)?
    };
    run_foreground(
        config,
        bound,
        limits,
        ready,
        shutdown,
        observe,
        clock,
        stderr_admission,
        || false,
        NoStatistics,
        std::future::ready(Ok(())),
    )
    .await
}

/// Run with original inherited/prebound TCP listeners prepared before an
/// explicit new-process identity transition. The caller applies USERNAME
/// synchronously; this async entry only verifies the actual selected IDs and
/// finishes the deferred new Unix bind under that identity. It never calls
/// setuid, reopens an inherited/TCP socket or constructs a privilege report.
/// The same entered runtime must own the preparation and this service future.
#[cfg(unix)]
pub async fn foreground_prepared(
    config: &Configuration,
    listeners: ListenerPreparation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
) -> Result<Report, Box<dyn Error>> {
    foreground_prepared_with_clock(
        config,
        listeners,
        limits,
        ready,
        shutdown,
        observe,
        Arc::new(SystemClock),
        stderr_admission,
        || false,
        NoStatistics,
    )
    .await
}

/// Prepared-listener service on the caller's canonical absolute clock. Refusal
/// closes the still-unadmitted original listeners. Actual identity verification
/// and Unix finish precede proof storage and all CORE/PILS/Host work. This keeps
/// native proof/close/first-error behavior in the same shared driver as ordinary
/// [`foreground_with_clock`], without a background task or identity mutation.
/// `diagnostic_failed` observes the caller's original permanent output-failure
/// latch; taking a diagnostic error must not reopen that gate while this future
/// is live. The ordinary no-logger wrappers have no such latch.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit actual prepared listeners, canonical clock and diagnostic owner"
)]
#[cfg(unix)]
pub async fn foreground_prepared_with_clock<F: StatisticsFactory>(
    config: &Configuration,
    listeners: ListenerPreparation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
    diagnostic: impl FnMut(AdmissionFailure) -> Result<(), Box<dyn Error>>,
    diagnostic_failed: impl Fn() -> bool,
    statistics_factory: F,
) -> Result<Report<F::Report>, Box<dyn Error>> {
    verify_configured_identity(config)?;
    let limits = configured_limits(config, limits)?;
    let bound = listeners.finish().await?;
    run_foreground(
        config,
        bound,
        limits,
        ready,
        shutdown,
        observe,
        clock,
        diagnostic,
        diagnostic_failed,
        statistics_factory,
        std::future::ready(Ok(())),
    )
    .await
}

/// Drive caller-owned completed listeners and the actual CORE/PILS/proof owners.
/// The notification is polled once, only after real activation and the synchronous
/// ready observer. Its fixed native deadline observes the same shutdown and
/// diagnostic latch; failure still closes original hosts, statistics and Resolver.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit original listeners, process ports, diagnostics and readiness future"
)]
pub async fn foreground_listening_with_clock<F: StatisticsFactory>(
    config: &Configuration,
    bound: BoundListeners,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    notification: impl Future<Output = Result<(), Box<dyn Error>>>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
    diagnostic: impl FnMut(AdmissionFailure) -> Result<(), Box<dyn Error>>,
    diagnostic_failed: impl Fn() -> bool,
    statistics_factory: F,
) -> Result<Report<F::Report>, Box<dyn Error>> {
    verify_configured_identity(config)?;
    let limits = configured_limits(config, limits)?;
    run_foreground(
        config,
        bound,
        limits,
        ready,
        shutdown,
        observe,
        clock,
        diagnostic,
        diagnostic_failed,
        statistics_factory,
        notification,
    )
    .await
}

#[cfg(test)]
mod tests;
