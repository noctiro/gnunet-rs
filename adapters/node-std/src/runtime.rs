use crate::{Exit, Failure, FailureCause, NetworkChanges, Node, Ready, Service, lifecycle, quic};
use gnunet_cadet_host::startup as cadet;
use gnunet_dht_service_host::startup as dht;
use gnunet_nat_host::startup as nat;
use gnunet_nse_host::startup as nse;
use gnunet_pils_host::startup as pils;
use gnunet_regex_server_host::startup as regex;
use gnunet_resolver_host::startup as resolver;
use gnunet_service_runtime::{Activation, clock::RuntimeClock};
use gnunet_tcp_communicator_runtime::startup as tcp;
use gnunet_transport_runtime::startup as transport;
use gnunet_udp_communicator_runtime as udp;
use gnunet_vpn_host::startup as vpn;
use lifecycle::ReadyNotice;
use std::{
    future::{Future, ready},
    io,
    sync::Arc,
};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

impl Node {
    /// Drive the peer on the caller's Tokio reactor with I/O and timers enabled.
    /// Keep this future alive through retirement by completing `stop` instead
    /// of dropping the driver. No background service tasks are detached.
    /// Host network-change hints wake the original interface scan owners.
    pub async fn run(
        self,
        clock: Arc<dyn RuntimeClock>,
        changes: NetworkChanges,
        stop: impl Future<Output = io::Result<()>>,
        on_ready: impl FnOnce(&Ready) -> io::Result<()>,
    ) -> Result<Exit, Failure> {
        let NetworkChanges {
            tcp: tcp_changes,
            udp: udp_changes,
            nat: nat_changes,
            quic: quic_changes,
            http3: http3_changes,
            resolver: upstream_updates,
        } = changes;
        tokio::runtime::Handle::try_current()
            .map_err(|error| FailureCause::Runtime(io::Error::other(error)))?;
        let deadline = Instant::now()
            .checked_add(self.timing.startup)
            .ok_or_else(|| FailureCause::Runtime(io::ErrorKind::InvalidInput.into()))?;
        let (phase, current) = watch::channel(lifecycle::Phase::Foundation);
        let (notices, events) = mpsc::channel(lifecycle::EVENT_CAPACITY);
        let peer_mode = self.tcp_mode;
        let udp_enabled = matches!(peer_mode, tcp::PeerMode::Listening);
        let config = &self.config;
        let socket_policy = self.socket_policy;
        let resolver_clock = clock.clone();
        let resolver_socket_policy = socket_policy.clone();
        let resolver_dns = match self.resolver {
            crate::ResolverInputs::Datagram(inputs) => resolver::EmbeddedDns::Datagram {
                inputs,
                endpoints: &[],
                updates: upstream_updates,
            },
            crate::ResolverInputs::System(system) => resolver::EmbeddedDns::System(system),
        };
        let transport_state = self.state.join("transport-state");
        let tcp_state = self.state.join("tcp-state");
        let udp_state = self.state.join("udp-state");
        let key = &self.key;
        let transport_drain = self.timing.transport_drain;
        let mut publication_phase = current.clone();
        let publication_start = async move {
            let running = publication_phase
                .wait_for(|phase| *phase >= lifecycle::Phase::Running)
                .await
                .is_ok_and(|phase| *phase == lifecycle::Phase::Running);
            if !running {
                std::future::pending::<()>().await;
            }
        };

        let resolve = lifecycle::drive(
            Service::Resolver,
            current.clone(),
            notices.clone(),
            async move |stop, mut status| {
                resolver::serve_embedded(
                    resolver::EmbeddedSettings {
                        config,
                        dns: resolver_dns,
                        clock: resolver_clock,
                        socket_policy: resolver_socket_policy,
                    },
                    |_| ready(status.publish(ReadyNotice::Resolver)),
                    stop.wait(),
                    |_| {},
                )
                .await?;
                Ok(())
            },
        );
        let sign = lifecycle::drive(
            Service::Pils,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                pils::foreground_embedded(
                    pils::EmbeddedStartup {
                        config,
                        activation: Activation::default(),
                        limits: Default::default(),
                    },
                    clock.clone(),
                    async |_, peer| {
                        status.publish(ReadyNotice::Pils(peer))?;
                        Ok(())
                    },
                    stop.wait(),
                    |_| {},
                    |_| Ok(()),
                )
                .await?;
                Ok(())
            },
        );
        let transport = lifecycle::drive(
            Service::Transport,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                transport::foreground_service_with_lifecycle(
                    transport::ServiceStartup {
                        config,
                        activation: Activation::default(),
                        state_directory: transport_state,
                        included_hellos: self.included_hellos,
                        limits: Default::default(),
                    },
                    async |_, _, peer| status.publish(ReadyNotice::Transport(peer)),
                    transport::ForegroundLifecycle {
                        stop: stop.wait(),
                        drain_budget_micros: transport_drain,
                        publication_start: transport::PublicationStart::After(publication_start),
                    },
                    |_| {},
                    |_| {},
                    |_| {},
                    clock.clone(),
                )
                .await?;
                Ok(())
            },
        );
        let core = lifecycle::drive(
            Service::Core,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                gnunet_core_host::startup::foreground_with_clock(
                    config,
                    Activation::default(),
                    Default::default(),
                    |_, peer| status.publish(ReadyNotice::Core(peer.0)),
                    stop.wait(),
                    |_| {},
                    clock.clone(),
                )
                .await?;
                Ok(())
            },
        );
        let nse = lifecycle::drive(
            Service::Nse,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                nse::serve_embedded(
                    nse::EmbeddedSettings {
                        config,
                        endpoints: nse::LocalEndpoints {
                            nse: self.ipc.join("nse"),
                            core: self.ipc.join("core"),
                            pils: self.ipc.join("pils"),
                        },
                        clock: clock.clone(),
                        proof_file: self.state.join("nse-proof"),
                    },
                    stop.wait(),
                    |ready| status.publish(ReadyNotice::Nse(ready.peer)),
                )
                .await?;
                Ok(())
            },
        );
        let dht = lifecycle::drive(
            Service::Dht,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                dht::serve_embedded(
                    dht::EmbeddedSettings {
                        config,
                        socket_policy: socket_policy.clone(),
                        endpoints: dht::LocalEndpoints {
                            dht: self.ipc.join("dht"),
                            pils: self.ipc.join("pils"),
                            core: self.ipc.join("core"),
                            peerstore: self.ipc.join("peerstore"),
                            transport: self.ipc.join("transport"),
                            nse: Some(self.ipc.join("nse")),
                        },
                        clock: clock.clone(),
                    },
                    stop.wait(),
                    |ready| status.publish(ReadyNotice::Dht(ready.peer)),
                )
                .await?;
                Ok(())
            },
        );
        let cadet = lifecycle::drive(
            Service::Cadet,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                cadet::serve_embedded(
                    cadet::EmbeddedSettings {
                        config,
                        endpoints: cadet::LocalEndpoints {
                            cadet: self.ipc.join("cadet"),
                            pils: self.ipc.join("pils"),
                            core: self.ipc.join("core"),
                            transport: self.ipc.join("transport"),
                            resolver: self.ipc.join("resolver"),
                            dht: Some(self.ipc.join("dht")),
                        },
                        monotime_file: self.state.join("cadet-monotime"),
                        clock: clock.clone(),
                    },
                    stop.wait(),
                    |ready| status.publish(ReadyNotice::Cadet(ready.peer)),
                )
                .await?;
                Ok(())
            },
        );
        let nat = lifecycle::drive(
            Service::Nat,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                nat::serve_embedded(
                    nat::EmbeddedSettings {
                        config,
                        clock: clock.clone(),
                        helper_programs: self.nat_helpers,
                        changes: nat_changes,
                        socket_policy: socket_policy.clone(),
                    },
                    |_| status.publish(ReadyNotice::Nat),
                    stop.wait(),
                    |_| {},
                )
                .await?;
                Ok(())
            },
        );
        let vpn_enabled = self.vpn.is_some();
        let regex_path = self
            .vpn
            .as_ref()
            .and_then(|vpn| match &vpn.endpoints.discovery {
                vpn::DiscoveryEndpoint::Regex(endpoint) => Some(endpoint.clone()),
                vpn::DiscoveryEndpoint::Configured => None,
            });
        let regex_enabled = regex_path.is_some();
        let discover = async {
            if let Some(endpoint) = regex_path {
                lifecycle::drive(
                    Service::Regex,
                    current.clone(),
                    notices.clone(),
                    async |stop, mut status| {
                        regex::serve_embedded(
                            regex::EmbeddedSettings {
                                config,
                                endpoints: regex::LocalEndpoints {
                                    regex: endpoint,
                                    dht: self.ipc.join("dht"),
                                    pils: self.ipc.join("pils"),
                                },
                                clock: clock.clone(),
                            },
                            stop.wait(),
                            |ready| status.publish(ReadyNotice::Regex(ready.peer)),
                        )
                        .await?;
                        Ok(())
                    },
                )
                .await;
            }
        };
        let vpn = async {
            if let Some(application) = self.vpn {
                lifecycle::drive(
                    Service::Vpn,
                    current.clone(),
                    notices.clone(),
                    async |stop, mut status| {
                        vpn::serve_embedded(
                            vpn::EmbeddedSettings {
                                settings: application.settings,
                                endpoints: application.endpoints,
                                clock: clock.clone(),
                                provider: application.provider,
                            },
                            stop.wait(),
                            || status.publish(ReadyNotice::Vpn),
                        )
                        .await?;
                        Ok(())
                    },
                )
                .await;
            }
        };
        let tcp = lifecycle::drive(
            Service::Tcp,
            current.clone(),
            notices.clone(),
            async |stop, mut status| {
                tcp::foreground_local_with_clock(
                    tcp::LocalStartup {
                        config,
                        peer_mode,
                        socket_policy: socket_policy.clone(),
                        activation: Activation::default(),
                        state_directory: tcp_state,
                        local_key: tcp::LocalKeyCapability {
                            ikm_file: key.clone(),
                        },
                        limits: Default::default(),
                        network_changes: tcp_changes,
                    },
                    |listeners, peer| {
                        status.publish(ReadyNotice::Tcp {
                            peer,
                            endpoints: listeners.addresses().to_vec(),
                        })
                    },
                    stop.wait(),
                    |_| {},
                    |_| {},
                    |_| {},
                    clock.clone(),
                )
                .await?;
                Ok(())
            },
        );
        let optional = lifecycle::OptionalServices {
            regex: regex_enabled,
            vpn: vpn_enabled,
            udp: udp_enabled,
            quic: self.quic.quic.is_some(),
            http3: self.quic.http3.is_some(),
            #[cfg(unix)]
            unix: self.unix.is_some(),
            #[cfg(not(unix))]
            unix: false,
        };
        let native = quic::Local {
            ipc: &self.ipc,
            clock: &clock,
            socket_policy: &socket_policy,
        };
        let raw_quic = native.drive(
            self.quic.quic,
            current.clone(),
            notices.clone(),
            quic_changes,
        );
        let http3 = native.drive(
            self.quic.http3,
            current.clone(),
            notices.clone(),
            http3_changes,
        );
        #[cfg(unix)]
        let unix = crate::unix::drive(
            self.unix,
            &self.ipc,
            &clock,
            current.clone(),
            notices.clone(),
        );
        let udp = async {
            if udp_enabled {
                lifecycle::drive(
                    Service::Udp,
                    current.clone(),
                    notices.clone(),
                    async |stop, mut status| {
                        udp::serve_embedded(
                            udp::EmbeddedSettings {
                                config,
                                private_key: key,
                                replay_directory: &udp_state,
                                clock: clock.clone(),
                                hello_publisher: udp::HelloPublisher::Transport,
                                network_changes: udp_changes,
                                socket_policy: socket_policy.clone(),
                            },
                            |ready| {
                                status.publish(ReadyNotice::Udp {
                                    peer: ready.peer,
                                    endpoints: ready.addresses,
                                })
                            },
                            stop.wait(),
                        )
                        .await?;
                        Ok(())
                    },
                )
                .await;
            }
        };
        let supervise = lifecycle::supervise(phase, events, deadline, optional, stop, on_ready);
        let communicators = async {
            #[cfg(unix)]
            tokio::join!(biased; tcp, udp, raw_quic, http3, unix);
            #[cfg(not(unix))]
            tokio::join!(biased; tcp, udp, raw_quic, http3);
        };
        let (result, ..) = tokio::join!(biased; supervise, resolve, sign, transport, nat, core, nse, dht, cadet, discover, vpn, communicators);
        result
    }
}
