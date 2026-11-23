//! Application-owned setup and control of the original UDP communicator.

use crate::{
    bootstrap,
    control::{ApplicationStop, Stop},
    diagnostics::Silent,
    foreground::Bound,
    run,
    settings::Settings,
};
use gnunet_config::Configuration;
use gnunet_service_runtime::{clock::RuntimeClock, network_change::NetworkChanges};
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    task::Poll,
};

/// Owner of the complete PILS HELLO address set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloPublisher {
    /// TRANSPORT aggregates addresses from every communicator and publishes the HELLO.
    Transport,
    /// UDP has exclusive authority to publish the complete address set to PILS.
    Communicator,
}

/// Explicit configuration and private state paths for an embedded communicator.
pub struct EmbeddedSettings<'a> {
    /// Selected UDP profile and native PILS, NAT, TRANSPORT and RESOLVER endpoints.
    pub config: &'a Configuration,
    /// Existing absolute peer key path. Its key must match the verified PILS identity.
    pub private_key: &'a Path,
    /// Absolute private, independently owned directory for UDP replay state.
    pub replay_directory: &'a Path,
    /// Application clock shared by all normal UDP, discovery and local IPC owners.
    pub clock: Arc<dyn RuntimeClock>,
    /// Select the single service authorized to replace the complete PILS address set.
    pub hello_publisher: HelloPublisher,
    /// Coalesced host hints for the original communicator's interface scan.
    pub network_changes: NetworkChanges,
    /// Native socket preparation before each original default or scan bind.
    pub socket_policy: gnunet_service_runtime::network::SocketPolicy,
}

/// Local facts available after the initial TRANSPORT registration is written.
#[derive(Debug)]
pub struct Ready {
    /// Current peer verified by PILS and matched to the existing private key.
    pub peer: [u8; 32],
    /// Successfully bound original UDP endpoints, with selected ephemeral ports.
    pub addresses: Vec<SocketAddr>,
}

/// Stage reached before the original communicator finished caller-driven shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    /// No initial TRANSPORT registration was published to the caller.
    BeforeReady,
    /// Initial TRANSPORT registration was published before shutdown.
    AfterReady,
}

/// Run the original configured communicator on the caller's Tokio I/O and time driver.
/// The caller supplies the stop future and readiness callback. Startup checks
/// stop before binding. The callback is invoked once after
/// the initial registration write completes on the original local TRANSPORT stream.
/// Requested stop drives the original bounded retirement and propagates cleanup failures.
/// The runtime uses the application's current identity and native interface observations.
pub async fn serve_embedded(
    settings: EmbeddedSettings<'_>,
    ready: impl FnOnce(Ready) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<Exit, Box<dyn std::error::Error>> {
    let mut shutdown = std::pin::pin!(shutdown);
    let mut control = ApplicationStop::new(shutdown.as_mut());
    if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(control.poll(cx))).await {
        result?;
        return Ok(Exit::BeforeReady);
    }
    if settings
        .config
        .get(b"communicator-udp", b"USERNAME")
        .is_some()
    {
        return Err("embedded UDP requires the application to select its process identity".into());
    }

    let reporter = Silent;
    let configured = Settings::parse_embedded(
        settings.config,
        bootstrap::ipv6_supported()?,
        settings.private_key,
        settings.replay_directory,
    )?;
    let bound = Bound::from_settings(
        settings.config,
        configured,
        &reporter,
        &settings.socket_policy,
    )?;
    if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(control.poll(cx))).await {
        result?;
        return Ok(Exit::BeforeReady);
    }

    let (_resolver_context, foreground) = bound.attach(settings.clock)?;
    run::run(
        foreground.inputs(
            control,
            reporter,
            settings.hello_publisher,
            settings.network_changes,
        ),
        Some(ready),
    )
    .await?
    .into_embedded_exit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cause;
    use gnunet_service_runtime::clock::SystemClock;

    #[test]
    fn pre_requested_stop_skips_configuration_and_native_setup() -> Result<(), Cause> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let config = Configuration::default();
        let exit = runtime.block_on(serve_embedded(
            EmbeddedSettings {
                config: &config,
                private_key: Path::new("invalid-relative-key"),
                replay_directory: Path::new("invalid-relative-state"),
                clock: Arc::new(SystemClock),
                hello_publisher: HelloPublisher::Transport,
                network_changes: NetworkChanges::default(),
                socket_policy: Default::default(),
            },
            |_| Err(io::Error::other("unexpected readiness after caller stop")),
            std::future::ready(Ok(())),
        ))?;
        if exit != Exit::BeforeReady {
            return Err("pre-requested stop published readiness".into());
        }
        Ok(())
    }
}
