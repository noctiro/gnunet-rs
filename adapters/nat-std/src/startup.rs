//! Host-owned native IPC and lifecycle for the ordinary NAT service.
use crate::{
    helpers::Paths,
    manager::Failure,
    server::{self, Event, Mode, Progress, Report, Server},
};
use gnunet_config::Configuration;
use gnunet_resolver_broker::{BrokerError, Driver, DriverEvent, LiveConfiguration};
use gnunet_service_runtime::{
    BoundListeners,
    clock::RuntimeClock,
    network::SocketPolicy,
    network_change::NetworkChanges,
    service::{Listener, ShutdownMode},
};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;

mod settings;
pub use settings::Settings;

/// Explicit authority to use the installed NAT observer and sender programs.
///
/// The deployment supplies the trusted helper files and keeps their paths
/// under its control throughout service execution. Native authority is
/// established by the deployment and exercised by the original helpers.
#[derive(Debug)]
pub struct HelperPrograms {
    paths: Paths,
}

impl HelperPrograms {
    /// Select the installed observer and sender by separate absolute paths.
    ///
    /// Resolves both paths to regular executables. The deployment owns the
    /// files, their containing directories and the helpers' native permissions.
    pub fn new(server: PathBuf, client: PathBuf) -> io::Result<Self> {
        let server = installed_program(&server)?;
        let client = installed_program(&client)?;
        if server == client {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NAT observer and sender require separate executables",
            ));
        }
        Ok(Self {
            paths: Paths { server, client },
        })
    }
}

fn installed_program(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NAT helper requires an absolute executable path",
        ));
    }
    let path = path.canonicalize()?;
    let metadata = path.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NAT helper requires a regular executable file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "NAT helper requires execute permission",
            ));
        }
    }
    #[cfg(windows)]
    if !path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows NAT helper requires an .exe file",
        ));
    }
    Ok(path)
}

/// Original settings and capabilities for one host-owned NAT service.
pub struct EmbeddedSettings<'a> {
    /// Official configuration and listener namespace.
    pub config: &'a Configuration,
    /// The owning node's runtime clock.
    pub clock: Arc<dyn RuntimeClock>,
    /// Native interface change hints.
    pub changes: NetworkChanges,
    /// Original egress policy for newly allocated Internet sockets.
    pub socket_policy: SocketPolicy,
    /// Optional delegate with the deployment's native reversal authority.
    pub helper_programs: Option<HelperPrograms>,
}

/// Failures observed on the same original service exit.
#[derive(Debug, Default)]
pub struct EmbeddedFailure {
    /// Startup, observer or original service-drive error.
    pub original: Option<Failure>,
    /// Error retiring existing provider work.
    pub retirement: Option<Failure>,
    /// Error disconnecting the original Resolver connection.
    pub resolver: Option<BrokerError>,
    /// Errors closing owned listener paths.
    pub listeners: Vec<io::Error>,
    /// Original report if provider cleanup remains incomplete.
    pub incomplete: Option<Report>,
}

impl fmt::Display for EmbeddedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NAT service retirement {self:?}")
    }
}

impl Error for EmbeddedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.retirement.as_deref())
            .or(self.resolver.as_ref().map(|error| error as &dyn Error))
            .or(self.listeners.first().map(|error| error as &dyn Error))
    }
}

impl EmbeddedFailure {
    fn finish(self, report: Report) -> Result<Report, Failure> {
        if self.source().is_some() || self.incomplete.is_some() {
            Err(Box::new(self))
        } else {
            Ok(report)
        }
    }
}

type Resolver = Driver<64, 1024>;

pub(crate) struct Drive<'a, 's> {
    pub server: &'a mut Server,
    pub resolver: &'a mut Resolver,
    pub listeners: &'a [Listener<'s>],
    pub until: Option<Instant>,
    pub resolver_first: bool,
}

pub(crate) enum Turn {
    Stop,
    Resolver,
    Server(Progress),
}

pub(crate) async fn turn(
    input: Drive<'_, '_>,
    mut should_stop: impl FnMut(&mut Context<'_>) -> Poll<Result<(), Failure>>,
    mut observe: impl FnMut(Event),
    observe_resolver: impl FnMut(DriverEvent),
) -> Result<Turn, Failure> {
    let Drive {
        server,
        resolver,
        listeners,
        until,
        resolver_first,
    } = input;
    let mut resolving = std::pin::pin!(resolver.drive_waiting(until, observe_resolver));
    poll_fn(|cx| {
        for n in 0..2 {
            if let Poll::Ready(result) = should_stop(cx) {
                return Poll::Ready(result.map(|()| Turn::Stop));
            }
            if (n == 0) == resolver_first {
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    return Poll::Ready(result.map(|_| Turn::Resolver).map_err(Into::into));
                }
            } else if let Poll::Ready(result) = server.poll(cx, listeners, until, &mut observe) {
                return Poll::Ready(result.map(Turn::Server));
            }
        }
        Poll::Pending
    })
    .await
}

/// Run official NAT registration and native discovery in the caller's runtime.
/// Interface scans, STUN and UPnP follow the provided egress policy. Privileged
/// reversal uses the explicit helper authority. A protected socket policy and
/// process helpers are incompatible and are rejected before binding.
pub async fn serve_embedded(
    settings: EmbeddedSettings<'_>,
    ready: impl FnOnce(&BoundListeners) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(Event),
) -> Result<Report, Failure> {
    let EmbeddedSettings {
        config,
        clock,
        changes,
        socket_policy,
        helper_programs,
    } = settings;
    let mut stop = std::pin::pin!(stop);
    let bind = async {
        if config.have_value(b"nat", b"USERNAME") {
            return Err("embedded NAT requires the host's current account".into());
        }
        if helper_programs.is_some() && socket_policy.is_protected() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "NAT helper processes cannot apply the application's socket protection",
            )
            .into());
        }
        let settings = Settings::embedded(config, helper_programs)?;
        let listeners =
            BoundListeners::bind_configured(config, b"nat", settings.unix.into()).await?;
        Ok::<_, Failure>((settings, listeners))
    };
    let Some(bound) = until_stop(bind, stop.as_mut()).await? else {
        return Ok(Report::default());
    };
    let (settings, mut bound) = bound?;
    let mut failures = EmbeddedFailure::default();
    let result = serve_listening(
        config,
        settings,
        &bound,
        clock,
        ready,
        stop.as_mut(),
        &mut observe,
        &mut failures,
        changes,
        socket_policy,
    )
    .await;
    failures.listeners = bound.close().err().unwrap_or_default();
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            failures.original = Some(error);
            Report::default()
        }
    };
    failures.finish(report)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Caller ports, borrowed listener owner and independent cleanup results retain separate lifetimes"
)]
async fn serve_listening(
    config: &Configuration,
    settings: Settings,
    bound: &BoundListeners,
    clock: Arc<dyn RuntimeClock>,
    ready: impl FnOnce(&BoundListeners) -> io::Result<()>,
    mut stop: Pin<&mut impl Future<Output = io::Result<()>>>,
    observe: &mut impl FnMut(Event),
    failures: &mut EmbeddedFailure,
    changes: NetworkChanges,
    socket_policy: SocketPolicy,
) -> Result<Report, Failure> {
    if until_stop(std::future::ready(()), stop.as_mut())
        .await?
        .is_none()
    {
        return Ok(Report::default());
    }
    let service_config = config.duplicate()?;
    let live = LiveConfiguration::new(config.duplicate()?);
    let profile = gnunet_resolver_broker::native_profile()?;
    let (context, mut resolver) = gnunet_resolver_broker::broker::<64, 1024>(
        live,
        settings.resolver,
        profile,
        clock.clone(),
    )?;
    let mut server = match Server::new_with_socket_policy(
        service_config,
        settings.discovery,
        settings.core,
        settings.native,
        server::Ports {
            options: settings.options,
            unix: settings.unix,
            clock,
            resolver: context.resolution_context(),
        },
        Mode::Nat,
        changes,
        socket_policy,
    ) {
        Ok(server) => server,
        Err(error) => {
            failures.resolver = resolver.disconnect().err();
            return Err(error);
        }
    };
    let result = async {
        let publish = async { ready(bound) };
        let Some(readiness) = until_stop(publish, stop.as_mut()).await? else {
            return Ok(());
        };
        readiness?;
        let listeners = bound.listeners();
        let mut until = None;
        let mut resolver_first = false;
        loop {
            let check_stop = |cx: &mut Context<'_>| {
                if until.is_some() {
                    Poll::Pending
                } else {
                    stop.as_mut().poll(cx).map_err(Into::into)
                }
            };
            let progress = turn(
                Drive {
                    server: &mut server,
                    resolver: &mut resolver,
                    listeners: &listeners,
                    until,
                    resolver_first,
                },
                check_stop,
                &mut *observe,
                |_| {},
            )
            .await?;
            resolver_first = !resolver_first;
            match progress {
                Turn::Stop => {
                    let deadline = Instant::now()
                        .checked_add(settings.grace)
                        .ok_or("NAT retirement deadline overflow")?;
                    server.request_shutdown(ShutdownMode::Soft);
                    until = Some(deadline);
                }
                Turn::Server(Progress::Stopped | Progress::WaitDeadline) => break Ok(()),
                Turn::Resolver | Turn::Server(Progress::Activity) => {}
            }
        }
    }
    .await;
    server.abort(observe);
    failures.retirement = poll_fn(|cx| server.poll_retirement(cx, observe))
        .await
        .err();
    let report = server.report();
    failures.incomplete = (report.pending != 0 || report.unresolved != 0).then_some(report);
    failures.resolver = resolver.disconnect().err();
    result.map(|()| report)
}

async fn until_stop<T>(
    work: impl Future<Output = T>,
    mut stop: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> io::Result<Option<T>> {
    let mut work = std::pin::pin!(work);
    poll_fn(|cx| {
        if let Poll::Ready(result) = stop.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| None));
        }
        work.as_mut().poll(cx).map(|result| Ok(Some(result)))
    })
    .await
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use gnunet_service_runtime::clock::SystemClock;

    #[test]
    fn helper_authority_requires_absolute_file_paths() -> io::Result<()> {
        let root = std::env::current_dir()?;
        for server in [PathBuf::from("gnunet-helper-nat-server"), root.clone()] {
            let selected = HelperPrograms::new(server, root.join("gnunet-helper-nat-client"));
            if !matches!(selected, Err(error) if error.kind() == io::ErrorKind::InvalidInput) {
                return Err(io::Error::other(
                    "accepted a relative or directory helper path",
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn protected_socket_policy_rejects_helpers_before_binding() -> Result<(), Failure> {
        let config = Configuration::default();
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let result = runtime.block_on(serve_embedded(
            EmbeddedSettings {
                config: &config,
                clock: Arc::new(SystemClock),
                changes: NetworkChanges::default(),
                socket_policy: SocketPolicy::protected(|_| Ok(())),
                // Validation of deployment paths is separate. No executable
                // file or native I/O driver is needed for policy rejection.
                helper_programs: Some(HelperPrograms {
                    paths: Paths {
                        server: "observer".into(),
                        client: "sender".into(),
                    },
                }),
            },
            |_| Err(io::Error::other("protected NAT reached readiness")),
            std::future::pending(),
            |_| {},
        ));
        if !matches!(result, Err(error) if error.downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::Unsupported))
        {
            return Err(
                "NAT helper and protected socket policy were not rejected at startup".into(),
            );
        }
        Ok(())
    }
}
