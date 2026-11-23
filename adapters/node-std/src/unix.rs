//! Attach the UNIX testing communicator to the node's private namespace.
use crate::{Service, lifecycle};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_native::os_bytes;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_unix_communicator_host::{Sources, embedded};
use std::{error::Error, io, num::NonZeroU16, path::Path, sync::Arc};
use tokio::sync::{mpsc, watch};

pub(crate) use embedded::Configured;

pub(crate) fn read(
    config: &Configuration,
    ipc: &Path,
    mut services: impl Iterator<Item = &'static str>,
) -> Result<Option<Configured>, Box<dyn Error>> {
    if config.get(embedded::SECTION, b"UNIXPATH").is_none() {
        return Ok(None);
    }
    let configured = Configured::read(config)?;
    let native_path = os_bytes::decode(configured.path())?;
    let path = Path::new(&native_path);
    let private_leaf = path.file_name().is_some_and(|leaf| {
        path.as_os_str() == ipc.join(leaf).as_os_str() && services.all(|name| leaf != name)
    });
    if !private_leaf {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UNIX communicator requires its own socket in the private IPC directory",
        )
        .into());
    }
    Ok(Some(configured))
}

pub(crate) async fn drive(
    configured: Option<Configured>,
    ipc: &Path,
    clock: &Arc<dyn RuntimeClock>,
    phase: watch::Receiver<lifecycle::Phase>,
    notices: mpsc::Sender<lifecycle::Notice>,
) {
    let Some(configured) = configured else {
        return;
    };
    lifecycle::drive(Service::Unix, phase, notices, async |stop, mut status| {
        let source = |name| EndpointSource::unix_with_clock(ipc.join(name), clock.clone());
        embedded::serve_configured(
            configured,
            Sources {
                transport: source("transport"),
                pils: source("pils"),
            },
            |bound| {
                let mtu = u16::try_from(bound.mtu)
                    .ok()
                    .and_then(NonZeroU16::new)
                    .ok_or_else(|| io::Error::other("invalid UNIX communicator payload MTU"))?;
                status.publish(lifecycle::ReadyNotice::Unix {
                    peer: bound.peer,
                    mtu,
                })
            },
            stop.wait(),
            |_| {},
        )
        .await?;
        Ok(())
    })
    .await;
}
