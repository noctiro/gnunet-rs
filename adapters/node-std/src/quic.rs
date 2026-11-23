//! Attach optional QUIC-family communicators to the original node services.
use crate::{Service, lifecycle};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_quic_communicator_host::{
    Nat, Sources,
    credentials::Profile,
    embedded::{self, Configured},
};
use gnunet_service_runtime::{
    clock::RuntimeClock, network::SocketPolicy, network_change::NetworkChanges,
};
use std::{error::Error, path::Path, sync::Arc};
use tokio::sync::{mpsc, watch};

pub(crate) struct Communicators {
    pub(crate) quic: Option<Configured>,
    pub(crate) http3: Option<Configured>,
}

impl Communicators {
    pub(crate) fn read(config: &Configuration) -> Result<Self, Box<dyn Error>> {
        let read = |profile: Profile| {
            config
                .get(profile.section(), b"BINDTO")
                .map(|_| Configured::read(config, profile))
                .transpose()
        };
        Ok(Self {
            quic: read(Profile::Raw)?,
            http3: read(Profile::Http3)?,
        })
    }
}

pub(crate) struct Local<'node> {
    pub(crate) ipc: &'node Path,
    pub(crate) clock: &'node Arc<dyn RuntimeClock>,
    pub(crate) socket_policy: &'node SocketPolicy,
}

impl Local<'_> {
    pub(crate) async fn drive(
        &self,
        configured: Option<Configured>,
        phase: watch::Receiver<lifecycle::Phase>,
        notices: mpsc::Sender<lifecycle::Notice>,
        network_changes: NetworkChanges,
    ) {
        let Some(configured) = configured else {
            return;
        };
        let profile = configured.profile;
        let service = match profile {
            Profile::Raw => Service::Quic,
            Profile::Http3 => Service::Http3,
        };
        lifecycle::drive(service, phase, notices, async move |stop, mut status| {
            let local =
                |name| EndpointSource::unix_with_clock(self.ipc.join(name), self.clock.clone());
            let sources = Sources {
                transport: local("transport"),
                pils: local("pils"),
                nat: Some(Nat {
                    source: local("nat"),
                    profiles: gnunet_nat_client_host::Profiles::same(
                        gnunet_nat_client_host::native_profile()?,
                    ),
                    section: profile.section().to_vec(),
                    addresses: configured.nat_addresses,
                }),
            };
            embedded::serve_configured(
                configured,
                sources,
                network_changes,
                self.socket_policy.clone(),
                |ready| {
                    let notice = match ready.profile {
                        Profile::Raw => lifecycle::ReadyNotice::Quic {
                            peer: ready.peer,
                            address: ready.address,
                        },
                        Profile::Http3 => lifecycle::ReadyNotice::Http3 {
                            peer: ready.peer,
                            address: ready.address,
                        },
                    };
                    status.publish(notice)
                },
                stop.wait(),
                |_| {},
            )
            .await?;
            Ok(())
        })
        .await;
    }
}
