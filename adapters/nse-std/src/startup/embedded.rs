//! Direct local sources and caller-owned lifetime for the in-process NSE service.
use super::{
    Report, configured_limits,
    driver::{Foreground, Sources, run_foreground},
};
use crate::{Limits, statistics::NoStatistics};
use gnunet_config::Configuration;
use gnunet_native::{filesystem::Directory, os_bytes};
use gnunet_nse::{crypto::WorkBits, owner};
use gnunet_service_runtime::{
    BoundListeners, LocalListenerAccess, clock::RuntimeClock, local::qualify_private_endpoints,
};
use std::{
    error::Error,
    fmt,
    future::{Future, Ready as ReadyFuture},
    io,
    path::{Component, PathBuf},
    sync::Arc,
};

/// Local IPC endpoints selected by the owner of an embedded node.
/// All paths are distinct and lie in the same existing private directory.
#[derive(Debug)]
pub struct LocalEndpoints {
    /// The local subscriber endpoint created by this owner.
    pub nse: PathBuf,
    /// The node's CORE identity and flood endpoint.
    pub core: PathBuf,
    /// The node's PILS announcement and signing endpoint.
    pub pils: PathBuf,
}

impl LocalEndpoints {
    fn qualify(&self) -> io::Result<Directory> {
        qualify_private_endpoints(
            [self.nse.as_path(), self.core.as_path(), self.pils.as_path()].into_iter(),
        )
    }
}

/// Resources for serving native NSE on the caller's reactor.
pub struct EmbeddedSettings<'a> {
    /// Optional official NSE work/timing settings and the shared PILS profile.
    pub config: &'a Configuration,
    /// Original node-selected private IPC endpoints.
    pub endpoints: LocalEndpoints,
    /// Absolute raw8 proof filename under the node's private persistent directory.
    pub proof_file: PathBuf,
    /// The same canonical clock as the node's CORE and PILS owners.
    pub clock: Arc<dyn RuntimeClock>,
}

/// The first activated identity after the original CORE and PILS identities agree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ready {
    /// The locally verified peer identity at activation.
    pub peer: [u8; 32],
}

pub(super) fn settings(config: &Configuration) -> Result<owner::Config, Box<dyn Error>> {
    let mut settings = owner::Config::default();
    if config.get(b"NSE", b"INTERVAL").is_some() {
        settings.interval_micros = config.get_time(b"NSE", b"INTERVAL")?;
    }
    if config.get(b"NSE", b"WORKDELAY").is_some() {
        settings.work_delay_micros = config.get_time(b"NSE", b"WORKDELAY")?;
    }
    if config.get(b"NSE", b"WORKBITS").is_some() {
        settings.work_bits =
            WorkBits::new(u16::try_from(config.get_number(b"NSE", b"WORKBITS")?)?)?;
    }
    Ok(settings)
}

#[derive(Debug)]
struct ListenerClose {
    original: Option<Box<dyn Error>>,
    errors: Vec<io::Error>,
}
impl fmt::Display for ListenerClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.original {
            write!(f, "{error}. ")?;
        }
        write!(
            f,
            "NSE could not remove its original IPC endpoint: {:?}",
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

/// Drive NSE on the caller's I/O-enabled Tokio runtime. Readiness requires matching
/// CORE and PILS identities and a usable proof store. Work may continue after readiness.
/// Complete `stop` and keep this future live until proof progress and native sources
/// retire. The local sources need no Resolver, histogram recorder or statistics publisher.
///
/// # Errors
/// Returns the actual configuration, readiness, control, proof or retirement failure.
pub async fn serve_embedded(
    settings: EmbeddedSettings<'_>,
    stop: impl Future<Output = io::Result<()>>,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
) -> Result<Report, Box<dyn Error>> {
    let EmbeddedSettings {
        config,
        endpoints,
        proof_file,
        clock,
    } = settings;
    let _ipc = endpoints.qualify()?;
    if !proof_file.is_absolute()
        || proof_file.file_name().is_none()
        || proof_file
            .components()
            .any(|part| part == Component::ParentDir)
        || os_bytes::encode(proof_file.as_os_str()).contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NSE requires an absolute persistent proof file",
        )
        .into());
    }
    let state = proof_file
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let _state_dir = Directory::open(state)?;
    _state_dir.validate_private()?;
    let limits = configured_limits(config, Limits::default())?;
    let mut stop = std::pin::pin!(stop);
    let mut bound = tokio::select! {
        biased;
        requested = stop.as_mut() => {
            requested?;
            return Ok(Report::default());
        }
        listener = BoundListeners::bind_local(endpoints.nse.clone(), LocalListenerAccess::Owner) => listener?,
    };
    let mut on_ready = Some(on_ready);
    let result = run_foreground(
        Foreground {
            config,
            bound: &bound,
            limits,
            clock,
            sources: Sources::Embedded {
                endpoints: &endpoints,
                proof_file,
            },
        },
        |_, peer| match on_ready.take() {
            Some(callback) => callback(Ready { peer }),
            None => Ok(()),
        },
        stop.as_mut(),
        |_| {},
        |_| Ok(()),
        || false,
        NoStatistics,
        None::<ReadyFuture<Result<(), Box<dyn Error>>>>,
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
