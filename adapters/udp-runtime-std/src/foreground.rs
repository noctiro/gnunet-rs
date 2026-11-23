//! Transfer the original bound sockets to the configured foreground owner.

use crate::{
    Cause, Diagnostics, HelloPublisher, Ready, Report, Stop, bootstrap,
    run::{self, Inputs, Services},
    settings::Settings,
};
use gnunet_config::Configuration;
use gnunet_resolver_broker::Context;
use gnunet_service_runtime::{
    clock::RuntimeClock, network::SocketPolicy, network_change::NetworkChanges,
};
use gnunet_udp_communicator_host::socket::DatagramSocket;
use std::{io, sync::Arc};

/// Original numeric UDP sockets with their source configuration. The process
/// may finish its own identity setup before attaching local service clients.
pub struct Bound<'a> {
    config: &'a Configuration,
    settings: Settings,
    sockets: Vec<DatagramSocket>,
}

impl<'a> Bound<'a> {
    /// Parse the standard UDP settings and bind its configured numeric sockets.
    /// The caller enters the Tokio I/O driver and controls native process identity.
    pub fn configured(
        config: &'a Configuration,
        diagnostics: &impl Diagnostics,
    ) -> Result<Self, Cause> {
        let settings = Settings::parse(config, bootstrap::ipv6_supported()?)?;
        Self::from_settings(config, settings, diagnostics, &SocketPolicy::default())
    }

    pub(super) fn from_settings(
        config: &'a Configuration,
        settings: Settings,
        diagnostics: &impl Diagnostics,
        socket_policy: &SocketPolicy,
    ) -> Result<Self, Cause> {
        let sockets = bootstrap::bind(&settings, diagnostics, socket_policy)?;
        Ok(Self {
            config,
            settings,
            sockets,
        })
    }

    /// Transfer the socket owners and attach local services from the same configuration.
    /// The returned Resolver context shares the exact driver in the foreground.
    pub fn attach(
        self,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<(Context<8, 64>, Foreground), Cause> {
        let (context, services) = Services::new(self.config, clock.clone())?;
        let foreground = Foreground {
            settings: self.settings,
            sockets: self.sockets,
            services,
            clock,
        };
        Ok((context, foreground))
    }
}

/// The original configured UDP foreground with its bound sockets and local services.
pub struct Foreground {
    settings: Settings,
    sockets: Vec<DatagramSocket>,
    services: Services,
    clock: Arc<dyn RuntimeClock>,
}

impl Foreground {
    /// Run and retire the original communicator under the caller's stop and diagnostics.
    pub async fn drive(
        self,
        stop: impl Stop,
        diagnostics: impl Diagnostics,
    ) -> Result<Report, Cause> {
        run::run(
            self.inputs(
                stop,
                diagnostics,
                HelloPublisher::Transport,
                NetworkChanges::default(),
            ),
            None::<fn(Ready) -> io::Result<()>>,
        )
        .await
    }

    pub(super) fn inputs<S: Stop, D: Diagnostics>(
        self,
        control: S,
        reporter: D,
        hello_publisher: HelloPublisher,
        changes: NetworkChanges,
    ) -> Inputs<S, D> {
        Inputs {
            settings: self.settings,
            sockets: self.sockets,
            control,
            services: self.services,
            clock: self.clock,
            reporter,
            hello_publisher,
            changes,
        }
    }
}
