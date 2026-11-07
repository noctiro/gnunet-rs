//! Foreground official configuration, listener activation and shared CLIENT process ports.
use crate::{
    Host, Instances, Limits, Ports, Progress, Report as HostReport, proof,
    statistics::{NoStatistics, Statistics, StatisticsFactory},
};
use gnunet_client_host::EndpointSource;
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
use gnunet_nse::{crypto::WorkBits, owner};
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, broker};
use gnunet_service_runtime::{
    Activation, BoundListeners, ListenerPreparation,
    accepted::SocketEvent,
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::{PeerAddress, ShutdownMode},
    service_options,
};
use gnunet_service_startup::{Identity as ProcessIdentity, configured_user, resolve_user};
use std::time::Duration;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    path::Path,
    sync::Arc,
    task::Poll,
};

/// Independent real NSE and statistics-source observations. No field is a
/// remote-delivery, proof durability or STATISTICS disk acknowledgement.
#[derive(Clone, Copy, Debug)]
pub struct Report<R = ()> {
    /// Original CORE/PILS, service, proof and subscriber facts.
    pub host: HostReport,
    /// Original producer epoch, local writes, unknowns and actual destruction.
    pub statistics: Option<R>,
}
struct StatisticsErrors<E> {
    first: Option<E>,
    cleanup: Option<E>,
}
impl<E> Default for StatisticsErrors<E> {
    fn default() -> Self {
        Self {
            first: None,
            cleanup: None,
        }
    }
}
impl<E> StatisticsErrors<E> {
    fn record(&mut self, error: E) {
        if self.first.is_none() {
            self.first = Some(error);
        } else if self.cleanup.is_none() {
            self.cleanup = Some(error);
        }
    }
}
fn abort_statistics<D: Statistics>(
    publisher: &mut Option<D>,
    errors: &mut StatisticsErrors<D::Error>,
) {
    if let Some(publisher) = publisher.as_mut()
        && let Err(error) = publisher.abort()
    {
        errors.record(error);
    }
}
#[derive(Debug)]
struct ForegroundFailures<E, R> {
    original: Option<Box<dyn Error>>,
    host_close: Option<crate::Error>,
    statistics: Option<E>,
    statistics_cleanup: Option<E>,
    resolver_drain: Option<gnunet_resolver_broker::BrokerError>,
    resolver_close: Option<gnunet_resolver_broker::BrokerError>,
    resolver_io: Option<io::Error>,
    resolver_connect: Option<gnunet_resolver_broker::BrokerError>,
    report: Report<R>,
}
impl<E: Error + 'static, R: std::fmt::Debug + 'static> ForegroundFailures<E, R> {
    fn finish(self) -> Result<Report<R>, Box<dyn Error>> {
        if self.original.is_none()
            && self.host_close.is_none()
            && self.statistics.is_none()
            && self.statistics_cleanup.is_none()
            && self.resolver_drain.is_none()
            && self.resolver_close.is_none()
            && self.resolver_io.is_none()
            && self.resolver_connect.is_none()
        {
            Ok(self.report)
        } else {
            Err(Box::new(self))
        }
    }
}
impl<E: std::fmt::Debug, R: std::fmt::Debug> std::fmt::Display for ForegroundFailures<E, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NSE original={:?}; original host close={:?}; statistics={:?}; statistics cleanup={:?}; Resolver drain={:?}; close={:?}; IO={:?}; connection={:?}; actual reports={:?}",
            self.original,
            self.host_close,
            self.statistics,
            self.statistics_cleanup,
            self.resolver_drain,
            self.resolver_close,
            self.resolver_io,
            self.resolver_connect,
            self.report
        )
    }
}
impl<E: Error + 'static, R: std::fmt::Debug + 'static> Error for ForegroundFailures<E, R> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.host_close.as_ref().map(|e| e as &dyn Error))
            .or(self.statistics.as_ref().map(|e| e as &dyn Error))
            .or(self.statistics_cleanup.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_drain.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_close.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_io.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_connect.as_ref().map(|e| e as &dyn Error))
    }
}
/// Exact original unadmitted subscriber failure. Its stream is already
/// physically closed; reporting it grants no client/protocol admission.
#[derive(Debug)]
pub struct AdmissionFailure {
    /// Actual original remote socket address.
    pub peer: PeerAddress,
    /// Actual original credential/resource cause, never a fabricated IO error.
    pub error: crate::Error,
}
fn stderr_admission(failure: AdmissionFailure) -> Result<(), Box<dyn Error>> {
    writeln!(
        io::stderr().lock(),
        "nse unadmitted subscriber {:?}: {}",
        failure.peer,
        failure.error
    )?;
    Ok(())
}
fn poll_ports<H, R>(
    cx: &mut std::task::Context<'_>,
    mut driving: std::pin::Pin<&mut H>,
    mut resolving: std::pin::Pin<&mut R>,
) -> Poll<Result<Option<Progress>, Box<dyn Error>>>
where
    H: Future<Output = Result<Progress, crate::Error>>,
    R: Future<
        Output = Result<gnunet_resolver_broker::Progress, gnunet_resolver_broker::BrokerError>,
    >,
{
    // Give the process Resolver one bounded poll even when work/notifications
    // keep the Host ready. Resolver completion starts a new turn after polling
    // the Host; original errors retain their actual cause.
    let resolver_progress = if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
        match result {
            Ok(_) => true,
            Err(error) => return Poll::Ready(Err(Box::new(error) as Box<dyn Error>)),
        }
    } else {
        false
    };
    if let Poll::Ready(result) = driving.as_mut().poll(cx) {
        return Poll::Ready(result.map(Some).map_err(|e| Box::new(e) as Box<dyn Error>));
    }
    // The Host still gets its bounded poll when Resolver work completes. Return
    // to the owner loop so that it replaces the completed Resolver future.
    if resolver_progress {
        Poll::Ready(Ok(Some(Progress::Activity)))
    } else {
        Poll::Pending
    }
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
/// Current process does not have the selected native account's actual primary
/// IDs. This is not a supplementary/saved-ID or capability guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredIdentityMismatch {
    /// Actual UID selected by native account lookup.
    pub expected_uid: u32,
    /// Actual primary GID selected by native account lookup.
    pub expected_gid: u32,
    /// Actual current real/effective process IDs.
    pub actual: ProcessIdentity,
}
impl std::fmt::Display for ConfiguredIdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NSE USERNAME requires uid={} gid={} before deferred Unix/proof/native service initialization; actual={:?}",
            self.expected_uid, self.expected_gid, self.actual
        )
    }
}
impl Error for ConfiguredIdentityMismatch {}
fn require_ids(
    uid: u32,
    gid: u32,
    actual: ProcessIdentity,
) -> Result<(), ConfiguredIdentityMismatch> {
    if actual.uid != uid || actual.euid != uid || actual.gid != gid || actual.egid != gid {
        return Err(ConfiguredIdentityMismatch {
            expected_uid: uid,
            expected_gid: gid,
            actual,
        });
    }
    Ok(())
}
/// Verify that the embedding caller already applied the configured account
/// before proof/workers/native service initialization. This read-only check never
/// changes process identity from an async host. The standard executable can
/// retain its original inherited/prebound TCP listeners before applying the
/// native sequence; new Unix paths and proof/native clients still follow this
/// actual real/effective UID/GID check. Refusal never invents a privilege report.
pub fn verify_configured_identity(config: &Configuration) -> Result<(), Box<dyn Error>> {
    if let Some(name) = configured_user(config, b"NSE")? {
        let plan = resolve_user(&name)?;
        require_ids(plan.uid(), plan.gid(), ProcessIdentity::current())?;
    }
    Ok(())
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
    let bound = BoundListeners::bind(config, b"NSE", activation).await?;
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
    )
    .await
}

/// Run with original inherited/prebound TCP listeners prepared before an
/// explicit new-process identity transition. The caller applies USERNAME
/// synchronously; this async entry only verifies the actual selected IDs and
/// finishes the deferred new Unix bind under that identity. It never calls
/// setuid, reopens an inherited/TCP socket or constructs a privilege report.
/// The same entered runtime must own the preparation and this service future.
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
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit same source ports and actual caller diagnostic, no global logger"
)]
async fn run_foreground<F: StatisticsFactory>(
    config: &Configuration,
    bound: BoundListeners,
    limits: Limits,
    mut ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
    mut diagnostic: impl FnMut(AdmissionFailure) -> Result<(), Box<dyn Error>>,
    diagnostic_failed: impl Fn() -> bool,
    statistics_factory: F,
) -> Result<Report<F::Report>, Box<dyn Error>> {
    let unix = unix_access(config)?;
    let settings = settings(config)?;
    let store =
        proof::Store::open(config.get_filename(b"NSE", b"PROOFFILE", &ProcessEnvironment)?)?;
    let options = service_options(config, b"NSE", ShutdownMode::Immediate)?;
    let native = gnunet_resolver_broker::native_profile()?;
    let family = FamilyProfile::new(
        native.encode(gnunet_resolver_broker::Family::V4),
        native.encode(gnunet_resolver_broker::Family::V6),
    )?;
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, mut resolver) =
        broker::<128, 256>(live.clone(), Default::default(), family, clock.clone())?;
    let core = EndpointSource::live(live.clone(), b"core", context.resolution_context());
    let pils = EndpointSource::live(live.clone(), b"pils", context.resolution_context());
    let mut nse_instance = owner::Instance::new();
    let mut core_instance = gnunet_core_client_host::Instance::new();
    let mut pils_instance = gnunet_pils::client::Instance::new();
    let mut host = Host::<64, 32>::new_with_access(
        Instances {
            nse: &mut nse_instance,
            core: &mut core_instance,
            pils: &mut pils_instance,
        },
        Ports {
            core,
            pils,
            clock: clock.clone(),
        },
        settings,
        limits,
        options,
        unix,
        store,
    )?;
    let mut statistics_errors = StatisticsErrors::default();
    let statistics_grace = Duration::from_secs(5);
    // The caller constructs the concrete publisher on these actual same
    // process sources; the NSE host has no native statistics dependency.
    let mut statistics = match statistics_factory.create(
        live,
        context.resolution_context(),
        clock,
        host.metrics(),
    ) {
        Ok(publisher) => publisher,
        Err(error) => {
            statistics_errors.record(error);
            None
        }
    };
    let listeners = bound.listeners();
    let mut shutdown = std::pin::pin!(shutdown);
    let outcome = loop {
        // Refresh observes real domain coordinates only; it performs no new IO
        // and never extends an already admitted original mutation/hard target.
        if diagnostic_failed() {
            abort_statistics(&mut statistics, &mut statistics_errors);
            break Ok(());
        }
        let observed = host.metrics();
        let selected = {
            let mut driving = std::pin::pin!(host.drive(&listeners, &mut observe, None));
            let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |_| {}));
            poll_fn(|cx| {
                // No canonical wait/IO precedes this original native guard.
                if let Some(publisher) = statistics.as_mut()
                    && !publisher.is_closed()
                    && let Poll::Ready(Err(error)) = publisher.poll_native_guard(cx)
                {
                    statistics_errors.record(error);
                }
                if diagnostic_failed() {
                    abort_statistics(&mut statistics, &mut statistics_errors);
                    return Poll::Ready(Ok(None));
                }
                if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                    return Poll::Ready(
                        result
                            .map(|()| None)
                            .map_err(|e| Box::new(e) as Box<dyn Error>),
                    );
                }
                if let Some(publisher) = statistics.as_mut()
                    && !publisher.is_closed()
                    && let Err(error) = publisher.refresh(observed)
                {
                    statistics_errors.record(error);
                }
                // Give the bounded original publisher a turn even when NSE's
                // proof/round/notification work remains ready. Failure fences
                // this publisher; it does not change NSE history or stop peers.
                let mut stats_progress = false;
                if let Some(publisher) = statistics.as_mut()
                    && !publisher.is_closed()
                {
                    match publisher.poll(cx) {
                        Poll::Ready(Err(error)) => {
                            statistics_errors.record(error);
                            stats_progress = true;
                        }
                        Poll::Ready(Ok(_)) => stats_progress = true,
                        Poll::Pending => {}
                    }
                }
                if diagnostic_failed() {
                    abort_statistics(&mut statistics, &mut statistics_errors);
                    return Poll::Ready(Ok(None));
                }
                let result = poll_ports(cx, driving.as_mut(), resolving.as_mut());
                // The host observer may have failed during this exact poll.
                // Preserve an actual owned admission/error cause before the
                // stop gate, but never run a later class or Ready callback.
                if diagnostic_failed() {
                    abort_statistics(&mut statistics, &mut statistics_errors);
                    return match result {
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Ready(Ok(Some(Progress::AdmissionFailed { error, .. }))) => {
                            Poll::Ready(Err(Box::new(error) as Box<dyn Error>))
                        }
                        _ => Poll::Ready(Ok(None)),
                    };
                }
                match result {
                    Poll::Pending if stats_progress => Poll::Ready(Ok(Some(Progress::Activity))),
                    other => other,
                }
            })
            .await
        };
        match selected {
            Ok(None) => break Ok(()),
            Ok(Some(Progress::Activated(peer))) => {
                if let Err(error) = ready(&bound, peer) {
                    break Err(Box::new(error) as Box<dyn Error>);
                }
            }
            Ok(Some(Progress::AdmissionFailed { peer, error })) => {
                if let Err(output) = diagnostic(AdmissionFailure { peer, error }) {
                    break Err(output);
                }
            }
            Ok(Some(Progress::Closed)) => break Ok(()),
            Ok(Some(Progress::BackendQuiescent)) => {
                break Err("NSE proof backend requires explicit recovery".into());
            }
            Ok(Some(_)) => {}
            Err(error) => break Err(error),
        }
    };
    // Close original physical CORE/PILS/subscribers and perform their exact
    // proof flush before reading final metrics. No ? can bypass another owner.
    let closed = host.close();
    let host_report = host.report();
    let final_metrics = host.metrics();
    let mut resolver_drain = None;
    if outcome.is_err() || closed.is_err() || diagnostic_failed() {
        abort_statistics(&mut statistics, &mut statistics_errors);
    } else if let Some(publisher) = statistics.as_mut()
        && !publisher.is_closed()
    {
        if let Err(error) = publisher.begin_close(final_metrics, statistics_grace) {
            statistics_errors.record(error);
        }
        // Producer retains its own original final hard and all partial cursors.
        // A canceled wait below does not replace/retry an admitted mutation.
        poll_fn(|cx| {
            if let Some(publisher) = statistics.as_mut()
                && !publisher.is_closed()
                && let Poll::Ready(Err(error)) = publisher.poll_native_guard(cx)
            {
                statistics_errors.record(error);
            }
            if diagnostic_failed() {
                abort_statistics(&mut statistics, &mut statistics_errors);
            }
            if statistics.as_ref().is_none_or(Statistics::is_closed) {
                return Poll::Ready(());
            }
            let mut changed = false;
            if let Some(publisher) = statistics.as_mut() {
                match publisher.poll(cx) {
                    Poll::Ready(Err(error)) => {
                        statistics_errors.record(error);
                        changed = true;
                    }
                    Poll::Ready(Ok(_)) => changed = true,
                    Poll::Pending => {}
                }
            }
            if diagnostic_failed() {
                abort_statistics(&mut statistics, &mut statistics_errors);
            }
            if statistics.as_ref().is_none_or(Statistics::is_closed) {
                return Poll::Ready(());
            }
            // End the original drive borrow before any abort or disconnect.
            let result = {
                let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |_| {}));
                resolving.as_mut().poll(cx)
            };
            match result {
                Poll::Ready(Err(error)) => {
                    resolver_drain = Some(error);
                    abort_statistics(&mut statistics, &mut statistics_errors);
                }
                Poll::Ready(Ok(_)) => changed = true,
                Poll::Pending => {}
            }
            if diagnostic_failed() {
                abort_statistics(&mut statistics, &mut statistics_errors);
            }
            if changed {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await;
    }
    abort_statistics(&mut statistics, &mut statistics_errors);
    let statistics_report = statistics.as_ref().map(Statistics::report);
    drop(statistics);
    let resolver_close = resolver.disconnect().err();
    let resolver_io = resolver.take_io_error();
    let resolver_connect = resolver.take_connect_error();
    let report = Report {
        host: host_report,
        statistics: statistics_report,
    };
    let failures = ForegroundFailures {
        original: outcome.err(),
        host_close: closed.err(),
        statistics: statistics_errors.first,
        statistics_cleanup: statistics_errors.cleanup,
        resolver_drain,
        resolver_close,
        resolver_io,
        resolver_connect,
        report,
    };
    failures.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_client::resolver::{Reply, Request, encode_response};
    use gnunet_wire::official::Frame;
    use std::{path::PathBuf, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Selected identity and credential options must fail closed without mutating process IDs"
    )]
    fn configured_admission_and_primary_ids_are_explicit() -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        assert_eq!(
            configured_limits(&config, Limits::default())?.pils_profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            configured_limits(&config, Limits::default())?.pils_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        assert!(configured_limits(&config, Limits::default()).is_err());
        config.set_value(b"PILS", b"PROFILE", None)?;
        let absent = unix_access(&config)?;
        assert!(!absent.match_uid && !absent.match_gid);
        verify_configured_identity(&config)?;
        config.set_value(b"NSE", b"UNIX_MATCH_UID", Some(b"YES"))?;
        config.set_value(b"NSE", b"UNIX_MATCH_GID", Some(b"YES"))?;
        let selected = unix_access(&config)?;
        assert!(selected.match_uid && selected.match_gid);
        for key in [b"UNIX_MATCH_UID".as_slice(), b"UNIX_MATCH_GID".as_slice()] {
            config.set_value(b"NSE", key, Some(b"malformed"))?;
            assert!(unix_access(&config).is_err());
            config.set_value(b"NSE", key, Some(b"YES"))?;
        }
        let matching = ProcessIdentity {
            uid: 41,
            euid: 41,
            gid: 83,
            egid: 83,
        };
        assert_eq!(require_ids(41, 83, matching), Ok(()));
        for actual in [
            ProcessIdentity {
                uid: 42,
                ..matching
            },
            ProcessIdentity {
                euid: 42,
                ..matching
            },
            ProcessIdentity {
                gid: 84,
                ..matching
            },
            ProcessIdentity {
                egid: 84,
                ..matching
            },
        ] {
            assert_eq!(
                require_ids(41, 83, actual),
                Err(ConfiguredIdentityMismatch {
                    expected_uid: 41,
                    expected_gid: 83,
                    actual,
                })
            );
        }
        Ok(())
    }
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _removed = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn continuously_ready_host_does_not_starve_original_shared_resolver_end()
    -> Result<(), Box<dyn Error>> {
        resolver_completion(false)
    }
    #[test]
    fn pending_host_does_not_repoll_completed_original_resolver_future()
    -> Result<(), Box<dyn Error>> {
        resolver_completion(true)
    }
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual Unix Resolver completion must remain driven while the other service future is pending"
    )]
    fn resolver_completion(pending_host: bool) -> Result<(), Box<dyn Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let path = std::env::temp_dir().join(format!(
                "gnrs-nse-resolver-fair-{}-{pending_host}",
                std::process::id()
            ));
            std::fs::create_dir(&path)?;
            let directory = Directory(path);
            let socket = directory.0.join("resolver");
            let listener = UnixListener::bind(&socket)?;
            let native = gnunet_resolver_broker::native_profile()?;
            let family = FamilyProfile::new(
                native.encode(gnunet_resolver_broker::Family::V4),
                native.encode(gnunet_resolver_broker::Family::V6),
            )?;
            let mut config = Configuration::default();
            config.set_value(
                b"resolver",
                b"UNIXPATH",
                Some(socket.as_os_str().as_encoded_bytes()),
            )?;
            let shared = Arc::new(gnunet_program_host::shared_clock::SharedClock::native(8)?);
            let clock: Arc<dyn RuntimeClock> = shared.clone();
            let (context, mut driver) = broker::<4, 64>(
                LiveConfiguration::new(config),
                Default::default(),
                family,
                clock.clone(),
            )?;
            let ports = context.resolution_context();
            assert!(Arc::ptr_eq(&clock, &ports.clock()));
            let mut lookup = ports
                .lookup(b"nse-original-fairness.invalid", Duration::from_secs(2))?
                .ok_or("missing original shared query")?;
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let mut header = [0; 4];
                stream.read_exact(&mut header).await?;
                let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
                let mut bytes = vec![0; len];
                bytes[..4].copy_from_slice(&header);
                stream.read_exact(&mut bytes[4..]).await?;
                let request = Request::decode(Frame::decode(&bytes)?, family)?;
                assert!(matches!(
                    request.query(),
                    gnunet_client::resolver::Query::Forward {
                        hostname: b"nse-original-fairness.invalid",
                        ..
                    }
                ));
                let mut end = [0; 8];
                let n = encode_response(request.id(), Reply::End, &mut end)?;
                stream.write_all(&end[..n]).await?;
                assert_eq!(stream.read(&mut [0]).await?, 0);
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            });
            let until = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                tokio::task::yield_now().await;
                {
                    let driving = async {
                        if pending_host {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                        Ok(Progress::Activity)
                    };
                    let resolving = driver.drive_waiting(None, |_| {});
                    let mut driving = std::pin::pin!(driving);
                    let mut resolving = std::pin::pin!(resolving);
                    assert!(matches!(
                        poll_fn(|cx| poll_ports(cx, driving.as_mut(), resolving.as_mut())).await?,
                        Some(Progress::Activity)
                    ));
                }
                let done = poll_fn(|cx| {
                    Poll::Ready(match lookup.poll_next(cx) {
                        Poll::Ready(result) => Some(result),
                        Poll::Pending => None,
                    })
                })
                .await;
                if let Some(result) = done {
                    assert_eq!(result?, None);
                    break;
                }
                if tokio::time::Instant::now() >= until {
                    return Err(
                        "continuously ready Host starved actual Resolver request/END".into(),
                    );
                }
            }
            assert_eq!(context.pending_requests()?, 0);
            drop(lookup);
            drop(ports);
            drop(driver);
            drop(context);
            peer.await?.map_err(|e| e.to_string())?;
            assert_eq!(shared.listeners()?, 0);
            Ok::<_, Box<dyn Error>>(())
        })
    }
}
