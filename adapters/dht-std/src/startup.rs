//! Shared DHT foreground over official protocol owners and caller-owned listeners.
mod control;
mod foreground;
mod resolver;
mod settings;

pub use settings::Settings;

use self::{
    control::Mode,
    resolver::{Cleanup, Resolver},
};
use crate::{Ports, Report};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_native::filesystem::Directory;
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{LiveConfiguration, broker, native_profile};
use gnunet_service_runtime::{
    BoundListeners, LocalListenerAccess, clock::RuntimeClock, local::qualify_private_endpoints,
    network::SocketPolicy,
};
use gnunet_service_startup::{ControlReceiver, StopSignals};
use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

type Cause = Box<dyn Error>;

/// Original resources retained by the executable's native service shell.
pub struct ProcessSettings<'a> {
    /// Daemon configuration for the original Resolver and service endpoints.
    pub config: &'a Configuration,
    /// Already qualified DHT policy used to plan the listener permissions.
    pub settings: &'a Settings,
    /// Bound or activated listeners held by the process shell.
    pub bound: &'a BoundListeners,
    /// Original registered parent-control stream when managed.
    pub parent: Option<ControlReceiver>,
    /// The same clock used for configuration skew and logging.
    pub clock: SharedClock,
    /// Actual selected executable diagnostics.
    pub reports: &'a Reporter,
}

/// Drive the daemon foreground with its native process and parent controls.
/// The process shell retains listeners through the original driver retirement.
pub async fn serve_process(
    inputs: ProcessSettings<'_>,
    notify_ready: impl Future<Output = Result<(), Box<dyn Error>>>,
) -> Result<(), Box<dyn Error>> {
    let ProcessSettings {
        config,
        settings,
        bound,
        parent,
        clock,
        reports,
    } = inputs;
    let mut notify_ready = std::pin::pin!(notify_ready);
    let mut mode = Mode::Process {
        signals: StopSignals::new(parent)?,
        reports,
        notify: notify_ready.as_mut(),
    };
    if mode.stopping().await? {
        return Ok(());
    }
    let live = LiveConfiguration::new(config.duplicate()?);
    let clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let (context, driver) = broker::<128, 256>(
        live.clone(),
        settings.resolver,
        native_profile()?,
        clock.clone(),
    )?;
    let source = |name: &'static [u8]| {
        EndpointSource::live(live.clone(), name, context.resolution_context())
    };
    let ports = Ports {
        core: source(b"core"),
        pils: source(b"pils"),
        nse: Some(source(b"nse")),
        peerstore: source(b"peerstore"),
        transport: source(b"transport"),
        clock,
        options: settings.options.clone(),
        unix: settings.access,
    };
    let cleanup = Cleanup::default();
    let result = foreground::run(
        settings,
        bound,
        ports,
        Resolver::new(Some(driver), cleanup.clone()),
        &cleanup,
        mode,
        &SocketPolicy::default(),
    )
    .await;
    cleanup.finish(result).map(|_| ())
}

/// Original local endpoints already selected by an embedded node.
/// They are distinct paths in a single existing private IPC directory.
#[derive(Debug)]
pub struct LocalEndpoints {
    /// The DHT local client endpoint created by this service.
    pub dht: PathBuf,
    /// The node's public PILS identity/signing endpoint.
    pub pils: PathBuf,
    /// The node's authenticated CORE underlay endpoint.
    pub core: PathBuf,
    /// The node's PEERSTORE HELLO monitor and writer endpoint.
    pub peerstore: PathBuf,
    /// The node's TRANSPORT application hints endpoint.
    pub transport: PathBuf,
    /// The node's optional live network size estimate endpoint.
    pub nse: Option<PathBuf>,
}

impl LocalEndpoints {
    fn qualify(&self) -> io::Result<Directory> {
        qualify_private_endpoints(
            [
                &self.dht,
                &self.pils,
                &self.core,
                &self.peerstore,
                &self.transport,
            ]
            .map(PathBuf::as_path)
            .into_iter()
            .chain(self.nse.as_deref()),
        )
    }
}

/// Resources for serving the native DHT on an application's runtime.
pub struct EmbeddedSettings<'a> {
    /// DHT resource policy, underlay configuration and the shared PILS profile.
    pub config: &'a Configuration,
    /// Original private local endpoints selected by the node owner.
    pub endpoints: LocalEndpoints,
    /// The same clock as the node's other services.
    pub clock: Arc<dyn RuntimeClock>,
    /// Original application egress policy for every direct DHTU-IP socket.
    pub socket_policy: SocketPolicy,
}

/// Local identity selected by verified PILS and the available native underlay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ready {
    /// The actual DHT peer identity at first readiness.
    pub peer: [u8; 32],
}

#[derive(Debug)]
struct ListenerClose {
    original: Option<Cause>,
    errors: Vec<io::Error>,
}
impl fmt::Display for ListenerClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.original {
            write!(f, "{error}. ")?;
        }
        write!(
            f,
            "DHT could not remove its original IPC endpoint: {:?}",
            self.errors
        )
    }
}
impl Error for ListenerClose {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.errors.first().map(|error| error as &dyn Error))
    }
}

/// Drive the original DHT owner on the caller's I/O-enabled Tokio runtime.
/// Keep the private IPC namespace and upstream services live through retirement.
/// Complete `stop` to begin bounded native drain. The first successful readiness
/// callback identifies the current local peer. Direct local sources create no Resolver.
/// With no explicit NSE endpoint, routing uses its built-in estimate until another
/// configured underlay supplies one. Direct-IP binding follows explicit DHTU policy.
///
/// # Errors
/// Returns the original resource, readiness, control or retirement failure.
pub async fn serve_embedded(
    inputs: EmbeddedSettings<'_>,
    stop: impl Future<Output = io::Result<()>>,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
) -> Result<Report, Box<dyn Error>> {
    let EmbeddedSettings {
        config,
        endpoints,
        clock,
        socket_policy,
    } = inputs;
    let _directory = endpoints.qualify()?;
    let settings = Settings::read(config)?;
    let mut stop = std::pin::pin!(stop);
    let mut bound = tokio::select! {
        biased;
        requested = stop.as_mut() => {
            requested?;
            return Ok(Report::default());
        }
        listener = BoundListeners::bind_local(endpoints.dht.clone(), LocalListenerAccess::Owner) => listener?,
    };
    let source = |path: &Path| EndpointSource::unix_with_clock(path.to_owned(), clock.clone());
    let ports = Ports {
        core: source(&endpoints.core),
        pils: source(&endpoints.pils),
        nse: endpoints.nse.as_deref().map(source),
        peerstore: source(&endpoints.peerstore),
        transport: source(&endpoints.transport),
        clock,
        options: settings.options.clone(),
        unix: settings.access,
    };
    let mut on_ready = Some(on_ready);
    let mut notify = |ready| {
        let callback = on_ready
            .take()
            .ok_or_else(|| io::Error::other("DHT readiness already submitted"))?;
        callback(ready)
    };
    let mode = Mode::Embedded {
        stop: Some(stop.as_mut()),
        notify: &mut notify,
    };
    let cleanup = Cleanup::default();
    let result = foreground::run(
        &settings,
        &bound,
        ports,
        Resolver::new(None, cleanup.clone()),
        &cleanup,
        mode,
        &socket_policy,
    )
    .await;
    match bound.close() {
        Ok(()) => result,
        Err(errors) => Err(Box::new(ListenerClose {
            original: result.err(),
            errors,
        })),
    }
}
