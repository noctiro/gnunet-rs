//! Private embedded listening on the same native REGEX driver as the daemon.
use crate::{
    Ports, Server, core,
    dht::{Native, Provider},
    driver::{ConstructionFailure, Driver, Failure, Progress},
    pils::Signer,
};
use gnunet_config::Configuration;
use gnunet_pils_host::client::EndpointSource;
use gnunet_service_runtime::{
    BoundListeners, LocalListenerAccess, clock::RuntimeClock, local::qualify_private_endpoints,
};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    pin::{Pin, pin},
    sync::Arc,
    task::Poll,
};
use tokio::time::{Instant, sleep_until, timeout_at};

mod settings;
pub use settings::{Settings, dht_limits, service_options};

/// Distinct literal endpoints in one existing private application directory.
#[derive(Debug)]
pub struct LocalEndpoints {
    /// The official REGEX listener owned by this service.
    pub regex: PathBuf,
    /// The node's original local DHT client endpoint.
    pub dht: PathBuf,
    /// The node's original local PILS endpoint used for accepting-state signatures.
    pub pils: PathBuf,
}

/// Resources for running REGEX on the application's current runtime.
pub struct EmbeddedSettings<'a> {
    /// Canonical REGEX settings and shared PILS profile.
    pub config: &'a Configuration,
    /// The application's selected private endpoint owners.
    pub endpoints: LocalEndpoints,
    /// The same clock as the node's DHT and PILS services.
    pub clock: Arc<dyn RuntimeClock>,
}

/// First readiness after the original DHT connection and PILS identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ready {
    /// The current peer identity supplied by PILS.
    pub peer: [u8; 32],
}

/// Actual observations from the original distributed and native owners.
#[derive(Debug, Default)]
pub struct Report {
    /// Final native listener/client counters.
    pub host: crate::Report,
    /// Final distributed operation counters.
    pub metrics: core::Metrics,
    /// Original DHT transport failures with the driver remaining operational.
    pub dht_source_failures: u64,
    /// Original individual requests that failed after backend retirement.
    pub failed_jobs: u64,
    /// Actual retirement of the constructed Driver and its original owners.
    pub driver_drained: bool,
}

/// Independent original runtime and cleanup failures.
#[derive(Debug, Default)]
pub struct EmbeddedFailure {
    /// Failure constructing, starting, driving or stopping the original service.
    pub original: Option<Failure>,
    /// Original failures initiating host, signer metadata and DHT retirement.
    pub close: [Option<Failure>; 3],
    /// Failure encountered while retiring remaining original work.
    pub retirement: Option<Failure>,
    /// Native cleanup errors from the original listener paths.
    pub listeners: Vec<io::Error>,
    /// Latest observation if the Driver was constructed.
    pub report: Option<Report>,
}

impl fmt::Display for EmbeddedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "embedded REGEX lifecycle failed with {self:?}")
    }
}

impl Error for EmbeddedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.close.iter().flatten().next().map(Box::as_ref))
            .or(self.retirement.as_deref())
            .or_else(|| self.listeners.first().map(|error| error as &dyn Error))
    }
}

impl EmbeddedFailure {
    fn finish(self) -> Result<Report, Failure> {
        if self.source().is_some() {
            Err(Box::new(self))
        } else {
            Ok(self.report.unwrap_or_default())
        }
    }
}

fn startup_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "REGEX startup waited for private IPC, DHT and PILS",
    )
}

/// Run the official REGEX service on the caller's I/O-enabled runtime.
/// The original DHT and PILS endpoints stay live through retirement. Readiness
/// requires a live DHT client connection and the current PILS identity.
/// Resolving additional endpoints and publishing statistics are separate ports.
///
/// # Errors
/// Returns original configuration, startup, driver and independent cleanup errors.
pub async fn serve_embedded(
    input: EmbeddedSettings<'_>,
    stop: impl Future<Output = io::Result<()>>,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
) -> Result<Report, Failure> {
    let EmbeddedSettings {
        config,
        endpoints: LocalEndpoints { regex, dht, pils },
        clock,
    } = input;
    let _directory =
        qualify_private_endpoints([regex.as_path(), dht.as_path(), pils.as_path()].into_iter())?;
    let settings = Settings::read(config)?;
    let options = service_options(config)?;
    let deadline = Instant::now()
        .checked_add(settings.startup)
        .ok_or_else(startup_timeout)?;
    let mut stop = pin!(stop);
    let mut binding = pin!(timeout_at(
        deadline,
        BoundListeners::bind_local(regex, LocalListenerAccess::Owner)
    ));
    let bound = poll_fn(|cx| {
        if let Poll::Ready(result) = stop.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| None));
        }
        binding
            .as_mut()
            .poll(cx)
            .map(|result| result.map_err(|_| startup_timeout())?.map(Some))
    })
    .await?;
    let Some(mut bound) = bound else {
        return Ok(Report::default());
    };
    let mut failure = EmbeddedFailure::default();
    let original = drive(
        Foreground {
            settings: &settings,
            bound: &bound,
            dht: EndpointSource::unix_with_clock(dht, clock.clone()),
            pils: EndpointSource::unix_with_clock(pils, clock.clone()),
            ports: Ports {
                clock,
                options,
                unix: settings.unix,
            },
            deadline,
        },
        stop.as_mut(),
        on_ready,
        &mut failure,
    )
    .await;
    failure.original = original.err();
    failure.listeners = bound.close().err().unwrap_or_default();
    failure.finish()
}

struct Foreground<'a> {
    settings: &'a Settings,
    bound: &'a BoundListeners,
    dht: EndpointSource,
    pils: EndpointSource,
    ports: Ports,
    deadline: Instant,
}

enum Turn {
    Stop,
    Activity,
}

async fn drive(
    foreground: Foreground<'_>,
    mut stop: Pin<&mut impl Future<Output = io::Result<()>>>,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
    failure: &mut EmbeddedFailure,
) -> Result<(), Failure> {
    let Foreground {
        settings,
        bound,
        dht,
        pils,
        ports,
        deadline,
    } = foreground;
    let server = Server::new(core::Core::new(settings.core)?, settings.host, ports)?;
    let mut signer_instance = gnunet_pils::client::Instance::new();
    let signer = Signer::new(
        &mut signer_instance,
        pils,
        settings.pils_profile,
        gnunet_pils::HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 4096,
        },
    )?;
    let mut dht_instance = gnunet_dht_client_host::Instance::new();
    let dht = Native::new(
        &mut dht_instance,
        dht,
        dht_limits(settings.core, settings.host, settings.driver)?,
        deadline,
    )?;
    let mut driver = match Driver::try_new(server, signer, dht, settings.driver) {
        Ok(driver) => driver,
        Err(ConstructionFailure {
            mut server,
            mut signer,
            mut dht,
            error,
        }) => {
            failure.close[0] = server.close_all(|_| {}).err().map(Into::into);
            let _work = signer.close();
            failure.close[2] = dht.close().err();
            return Err(error);
        }
    };
    let listeners = bound.listeners();
    let mut report = Report::default();
    let mut notify = Some(on_ready);
    let mut alarm = pin!(sleep_until(deadline));
    let original = loop {
        let step = poll_fn(|cx| {
            if let Poll::Ready(result) = stop.as_mut().poll(cx) {
                return Poll::Ready(result.map(|()| Turn::Stop).map_err(Into::into));
            }
            if notify.is_some() && alarm.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(startup_timeout().into()));
            }
            let activity = match driver.poll(cx, &listeners, None, |_| {}) {
                Poll::Ready(Ok(Progress::Closed)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe).into()));
                }
                Poll::Ready(Ok(event)) => {
                    record(event, &mut report);
                    true
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => false,
            };
            if notify.is_some()
                && driver.provider().ready()
                && let Some(peer) = driver.peer()
            {
                if let Poll::Ready(result) = stop.as_mut().poll(cx) {
                    return Poll::Ready(result.map(|()| Turn::Stop).map_err(Into::into));
                }
                if Instant::now() >= deadline {
                    return Poll::Ready(Err(startup_timeout().into()));
                }
                let _times = driver.server().sample_times()?;
                if let Some(callback) = notify.take() {
                    callback(Ready {
                        peer: *peer.as_bytes(),
                    })?;
                }
                return Poll::Ready(Ok(Turn::Activity));
            }
            if activity {
                Poll::Ready(Ok(Turn::Activity))
            } else {
                Poll::Pending
            }
        })
        .await;
        match step {
            Err(error) => break Err(error),
            Ok(Turn::Stop) => break Ok(()),
            Ok(Turn::Activity) => {}
        }
        tokio::task::consume_budget().await;
    };

    failure.close = driver.stop(|_| {}).failures;
    while !driver.is_drained() {
        match driver.drive(&[], None, |_| {}).await {
            Ok(progress) => record(progress, &mut report),
            Err(error) => {
                failure.retirement = Some(error);
                break;
            }
        }
    }
    while let Some(progress) = driver.take_observation() {
        record(progress, &mut report);
    }
    report.host = driver.server().report();
    report.metrics = driver.metrics();
    report.driver_drained = driver.is_drained();
    failure.report = Some(report);
    original
}

fn record(progress: Progress<'_>, report: &mut Report) {
    match progress {
        Progress::DhtSourceFailure(_) => {
            report.dht_source_failures = report.dht_source_failures.saturating_add(1);
        }
        Progress::BackendFailure { .. } => {
            report.failed_jobs = report.failed_jobs.saturating_add(1);
        }
        _ => {}
    }
}
