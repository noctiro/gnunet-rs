//! Shared CADET foreground for the native daemon and an embedded GNUnet node.
mod control;
mod foreground;
mod identity;
mod local;
mod peer;
mod readiness;
mod reports;
mod settings;
pub mod statistics;

pub use settings::Settings;

use self::{
    control::{Signals, StopSource},
    foreground::{Failures, Sources, Stage},
    readiness::{Announcement, Destination},
    reports::Reports,
};
use crate::server::Report;
use gnunet_config::Configuration;
use gnunet_native::filesystem::Directory;
use gnunet_program_host::service::native::Context;
use gnunet_service_runtime::{
    BoundListeners, LocalListenerAccess, clock::RuntimeClock, local::qualify_private_endpoints,
};
use std::{
    error::Error,
    future::Future,
    io,
    path::{Component, PathBuf},
    sync::Arc,
};

/// Native process driver clock capacity for the CADET foreground.
pub const PROCESS_CLOCK_SLOTS: usize = 4096;

/// Drive the native executable with its original listener, diagnostics and parent control.
/// Construct the diagnostic publisher with the same configuration, resolver and clock.
pub async fn serve_process<'publisher>(
    context: Context<'_, Settings>,
    publisher: impl FnOnce(
        statistics::PublisherContext,
    ) -> Result<Box<dyn statistics::Publisher + 'publisher>, Box<dyn Error>>
    + 'publisher,
) -> Result<(), Box<dyn Error>> {
    let Context {
        config,
        settings,
        listeners,
        signals,
        clock,
        reports,
        readiness,
    } = context;
    let peers = settings.peer.enabled;
    let reporter = Reports::process(reports.clone());
    let announce = Announcement::new(Destination::Process(readiness, reports), reporter.clone());
    let mut outcome = foreground::run(
        settings,
        listeners,
        Sources::Process {
            config,
            publisher: Box::new(publisher),
        },
        Arc::new(clock),
        Signals::new(StopSource::Process(signals)),
        announce,
        reporter,
    )
    .await?;
    if let Err(error) = foreground::stopped(outcome.report, peers) {
        outcome.failures.record(Stage::Output, Box::new(error));
    }
    outcome.finish().map(|_| ())
}

/// Direct local endpoints selected by the owner of an embedded GNUnet node.
/// They must be distinct paths in the same private directory.
#[derive(Debug)]
pub struct LocalEndpoints {
    /// The local CADET client endpoint owned by this service.
    pub cadet: PathBuf,
    /// The node's local peer identity and signing service.
    pub pils: PathBuf,
    /// The node's local CORE upstream for the peer coordinator.
    pub core: PathBuf,
    /// The node's local TRANSPORT upstream for demand hints.
    pub transport: PathBuf,
    /// The node's local Resolver service.
    pub resolver: PathBuf,
    /// The node's optional local DHT service for remote path discovery.
    pub dht: Option<PathBuf>,
}

impl LocalEndpoints {
    fn qualify(&self) -> io::Result<Directory> {
        qualify_private_endpoints(
            [
                &self.cadet,
                &self.pils,
                &self.core,
                &self.transport,
                &self.resolver,
            ]
            .map(PathBuf::as_path)
            .into_iter()
            .chain(self.dht.as_deref()),
        )
    }
}

/// Resources for running the peer-enabled foreground on an application's runtime.
pub struct EmbeddedSettings<'a> {
    /// CADET/PILS protocol and capacity settings. Endpoint paths are supplied separately.
    pub config: &'a Configuration,
    /// Original node-selected endpoints, without address discovery or process activation.
    pub endpoints: LocalEndpoints,
    /// Absolute file stem under an application-owned persistent state directory.
    pub monotime_file: PathBuf,
    /// The same source clock as the node's existing services.
    pub clock: Arc<dyn RuntimeClock>,
}

/// The identity verified on both original PILS and CORE connections at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ready {
    /// The node's Ed25519 peer identity.
    pub peer: [u8; 32],
}

/// Run on the caller's I/O-enabled Tokio runtime and close all original native owners.
/// The node must keep its private directories and dependencies live until this future
/// returns. Complete `stop` to request retirement. The callback runs once after the
/// local listener and peer identity are ready, before application frames are accepted.
/// With no DHT endpoint, CORE neighbors and TRANSPORT hints remain available.
/// Embedded mode performs no process-wide logging, signal registration or STATISTICS IPC.
///
/// # Errors
/// Returns the actual resource, binding, readiness, control or retirement failure.
pub async fn serve_embedded(
    settings: EmbeddedSettings<'_>,
    stop: impl Future<Output = io::Result<()>>,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
) -> Result<Report, Box<dyn Error>> {
    let EmbeddedSettings {
        config,
        endpoints,
        monotime_file,
        clock,
    } = settings;
    let _directory = endpoints.qualify()?;
    if !monotime_file.is_absolute()
        || monotime_file.file_name().is_none()
        || monotime_file
            .components()
            .any(|part| part == Component::ParentDir)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CADET requires an absolute persistent monotime file",
        )
        .into());
    }
    let settings = Settings::read_with_monotime(config, Some(monotime_file))?;
    if !settings.peer.enabled {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "embedded CADET requires PEER_CORE",
        )
        .into());
    }
    let mut stop = std::pin::pin!(stop);
    let mut listeners = tokio::select! {
        biased;
        requested = stop.as_mut() => {
            requested?;
            return Ok(Report::default());
        }
        listeners = BoundListeners::bind_local(endpoints.cadet.clone(), LocalListenerAccess::Owner) => listeners?,
    };
    let mut on_ready = Some(on_ready);
    let mut notify = |notice| {
        let callback = on_ready
            .take()
            .ok_or_else(|| io::Error::other("CADET readiness already submitted"))?;
        callback(notice)
    };
    let reports = Reports::default();
    let ready = Announcement::new(Destination::Embedded(&mut notify), reports.clone());
    let result = foreground::run(
        settings,
        &listeners,
        Sources::Embedded(&endpoints),
        clock,
        Signals::new(StopSource::Embedded(stop.as_mut())),
        ready,
        reports,
    )
    .await
    .and_then(foreground::Outcome::finish);
    match listeners.close() {
        Ok(()) => result,
        Err(errors) => {
            let mut failures = Failures::new();
            if let Err(error) = result {
                failures.record(Stage::Application, error);
            }
            for error in errors {
                failures.record(Stage::NativeClose, Box::new(error));
            }
            Err(Box::new(failures))
        }
    }
}
