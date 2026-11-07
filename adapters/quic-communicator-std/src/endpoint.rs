//! One actual Quinn endpoint, no default detached runtime or implicit DNS.
use crate::{
    credentials::Tls,
    drivers::{Construct, Drivers, Id},
    socket::Gate,
};
use gnunet_types::Error as Protocol;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
/// Caller resource policy for actual QUIC backend allocations/windows.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneous accepting/established/draining connections.
    pub connections: usize,
    /// Per-connection concurrent bidi stream credit.
    pub bidi: u32,
    /// Per-connection receive window bytes.
    pub receive_bytes: u32,
    /// Per-stream receive window bytes.
    pub stream_bytes: u32,
    /// Per-connection provider send window bytes.
    pub send_bytes: u64,
    /// Pending QUIC initial bytes per incoming attempt.
    pub initial_bytes: u64,
    /// Native QUIC idle limit, distinct from source hard.
    pub idle: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 32,
            bidi: 32,
            receive_bytes: 65536,
            stream_bytes: 16384,
            send_bytes: 65536,
            initial_bytes: 4096,
            idle: Duration::from_secs(30),
        }
    }
}
#[derive(Debug)]
pub(crate) enum Failure {
    Protocol(Protocol),
    Io(io::Error),
    Connect(quinn::ConnectError),
    Accept(quinn::ConnectionError),
    BackendInvariant,
}
impl From<Protocol> for Failure {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
pub(crate) struct Connecting {
    pub(crate) driver: Id,
    pub(crate) connecting: quinn::Connecting,
    pub(crate) remote: SocketAddr,
}
/// Actual endpoint/source shutdown observations. Dropped backend handles close
/// their real sockets, but std/Quinn expose no separate kernel close errno API.
#[derive(Clone, Copy, Debug)]
pub struct Closed {
    /// Original backend driver futures force-dropped after grace.
    pub forced_drivers: usize,
    /// Endpoint/socket-owning handles were dropped.
    pub handles_dropped: bool,
}
pub(crate) struct Endpoint {
    inner: Option<quinn::Endpoint>,
    client: quinn::ClientConfig,
    drivers: Drivers,
    endpoint_driver: Id,
    failed_driver: Option<Id>,
    gate: Arc<Gate>,
    hard: Instant,
    local: SocketAddr,
    stopped: bool,
}
impl Endpoint {
    pub(crate) fn bind(
        address: SocketAddr,
        mut tls: Tls,
        limits: Limits,
        hard: Instant,
    ) -> Result<Self, Failure> {
        if limits.connections == 0
            || limits.connections > 65535
            || limits.bidi < 2
            || limits.receive_bytes < limits.stream_bytes
            || limits.stream_bytes < 4096
            || limits.send_bytes < 4096
            || limits.initial_bytes == 0
            || limits.idle.is_zero()
        {
            return Err(Protocol::InvalidInput.into());
        }
        if Instant::now() >= hard {
            return Err(Protocol::Deadline.into());
        }
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(limits.bidi));
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(3));
        transport.receive_window(quinn::VarInt::from_u32(limits.receive_bytes));
        transport.stream_receive_window(quinn::VarInt::from_u32(limits.stream_bytes));
        transport.send_window(limits.send_bytes);
        transport.datagram_receive_buffer_size(None);
        transport.datagram_send_buffer_size(0);
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(limits.idle).map_err(|_| Protocol::InvalidInput)?,
        ));
        let transport = Arc::new(transport);
        tls.client.transport_config(transport.clone());
        tls.server.transport_config(transport);
        tls.server.migration(false);
        tls.server.max_incoming(limits.connections);
        tls.server.incoming_buffer_size(limits.initial_bytes);
        tls.server.incoming_buffer_size_total(
            limits
                .initial_bytes
                .checked_mul(limits.connections as u64)
                .ok_or(Protocol::Overflow)?,
        );
        let gate = Gate::new(hard);
        let mut drivers = Drivers::new(limits.connections, gate.clone())?;
        // No socket is created before all pool/limit reservations and TLS setup.
        let socket = std::net::UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        let driver = drivers.reserve()?;
        let inner = match drivers.construct(&driver, |runtime| {
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(tls.server),
                socket,
                runtime,
            )
        }) {
            Ok(endpoint) => endpoint,
            Err(Construct::Backend(error)) => return Err(error.into()),
            Err(Construct::Protocol(error)) => return Err(error.into()),
            Err(Construct::MissingDriver(endpoint)) => {
                endpoint.close(quinn::VarInt::from_u32(0), b"");
                drop(endpoint);
                gate.close();
                return Err(Failure::BackendInvariant);
            }
            Err(Construct::Spawned { error, .. }) => {
                gate.close();
                let _actual = drivers.force_drop();
                return Err(error.into());
            }
        };
        let local = inner.local_addr()?;
        Ok(Self {
            inner: Some(inner),
            client: tls.client,
            drivers,
            endpoint_driver: driver,
            failed_driver: None,
            gate,
            hard,
            local,
            stopped: false,
        })
    }
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local
    }
    /// A constructor created a real retained driver before returning its error.
    /// The whole source must retire it before another command is admitted.
    pub(crate) fn is_poisoned(&self) -> bool {
        self.failed_driver.is_some()
    }
    pub(crate) fn dial(&mut self, address: SocketAddr) -> Result<Connecting, Failure> {
        if self.stopped || Instant::now() >= self.hard {
            return Err(Protocol::Closed.into());
        }
        let id = self.drivers.reserve()?;
        let endpoint = self.inner.as_ref().ok_or(Protocol::Closed)?;
        let config = self.client.clone();
        match self
            .drivers
            .construct(&id, |_| endpoint.connect_with(config, address, "gnunet"))
        {
            Ok(connecting) => Ok(Connecting {
                driver: id,
                connecting,
                remote: address,
            }),
            Err(Construct::Backend(e)) => Err(Failure::Connect(e)),
            Err(Construct::Protocol(e)) => Err(e.into()),
            Err(Construct::MissingDriver(connecting)) => {
                drop(connecting);
                Err(Failure::BackendInvariant)
            }
            Err(Construct::Spawned { error, id }) => {
                self.failed_driver = Some(id);
                Err(Failure::Connect(error))
            }
        }
    }
    /// Only this owner converts Incoming to Connecting, after a real reserved
    /// backend slot. Excess attempts are refused without a connection driver.
    pub(crate) fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Connecting, Failure>> {
        if self.stopped || Instant::now() >= self.hard {
            return Poll::Ready(Err(Protocol::Closed.into()));
        }
        let endpoint = self.inner.as_ref().ok_or(Protocol::Closed)?;
        let incoming = {
            let accept = endpoint.accept();
            let mut accept = std::pin::pin!(accept);
            match accept.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(Protocol::Closed.into())),
                Poll::Ready(Some(incoming)) => incoming,
            }
        };
        let remote = incoming.remote_address();
        let id = match self.drivers.reserve() {
            Ok(id) => id,
            Err(e) => {
                incoming.refuse();
                return Poll::Ready(Err(e.into()));
            }
        };
        Poll::Ready(match self.drivers.construct(&id, |_| incoming.accept()) {
            Ok(connecting) => Ok(Connecting {
                driver: id,
                connecting,
                remote,
            }),
            Err(Construct::Backend(e)) => Err(Failure::Accept(e)),
            Err(Construct::Protocol(e)) => Err(e.into()),
            Err(Construct::MissingDriver(connecting)) => {
                drop(connecting);
                Err(Failure::BackendInvariant)
            }
            Err(Construct::Spawned { error, id }) => {
                self.failed_driver = Some(id);
                Err(Failure::Accept(error))
            }
        })
    }
    /// Poll all retained backend slots once, outside bookkeeping locks. A native
    /// original hard guard precedes each individual future poll.
    pub(crate) fn poll_drivers(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut progress = false;
        for _ in 0..self.drivers.slots() {
            if let Some(error) = self.gate.take_error() {
                return Err(Failure::Io(error));
            }
            if Instant::now() >= self.hard {
                self.gate.close();
                return Err(Protocol::Deadline.into());
            }
            if matches!(
                self.drivers.poll(cx)?,
                crate::drivers::Progress::Completed(_) | crate::drivers::Progress::Canceled(_)
            ) {
                progress = true
            }
            if let Some(error) = self.gate.take_error() {
                return Err(Failure::Io(error));
            }
        }
        if let Some(error) = self.gate.take_error() {
            return Err(Failure::Io(error));
        }
        Ok(progress)
    }
    pub(crate) fn driver_done(&self, id: &Id) -> Result<bool, Failure> {
        Ok(self.drivers.done(id)?)
    }
    pub(crate) fn release_driver(&mut self, id: &Id) -> Result<(), Failure> {
        Ok(self.drivers.retire_done(id)?)
    }
    pub(crate) fn retire_driver_at(&mut self, id: &Id, at: Instant) -> Result<(), Failure> {
        if id == &self.endpoint_driver {
            return Err(Protocol::InvalidInput.into());
        }
        Ok(self.drivers.retire_at(id, at)?)
    }
    pub(crate) fn driver_was_canceled(&self, id: &Id) -> Result<bool, Failure> {
        Ok(self.drivers.was_canceled(id)?)
    }
    /// The original process endpoint/socket/driver survives a connection cut.
    pub(crate) fn cancel_driver(&mut self, id: &Id) -> Result<bool, Failure> {
        if id == &self.endpoint_driver {
            return Err(Protocol::InvalidInput.into());
        }
        Ok(self.drivers.cancel(id)?)
    }
    pub(crate) fn statistics(&self) -> crate::socket::Statistics {
        self.gate.statistics()
    }
    /// Stops admission and requests real original endpoint/connection closure;
    /// pending backend futures remain caller-driven until final actual teardown.
    pub(crate) fn begin_close(&mut self) {
        self.stopped = true;
        self.drivers.stop_admission();
        if let Some(endpoint) = self.inner.take() {
            endpoint.close(quinn::VarInt::from_u32(0), b"");
            // Healthy EndpointDriver completes only after no application
            // Endpoint refs remain AND all actual connection drivers drain.
            drop(endpoint);
        }
    }
    pub(crate) fn quiescent(&self) -> bool {
        self.drivers.pending() == 0
    }
    /// Call after original app handles/IO debts were retired. No new clock is
    /// needed for hard/clock-failure cleanup; force-drop is reported explicitly.
    pub(crate) fn close(mut self) -> Result<Closed, Failure> {
        self.begin_close();
        self.gate.close();
        drop(self.inner.take());
        let forced_drivers = self.drivers.force_drop()?;
        Ok(Closed {
            forced_drivers,
            handles_dropped: true,
        })
    }
}

#[cfg(all(test, feature = "fresh-tls"))]
mod tests {
    use super::*;
    type Test = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn canceling_original_connection_driver_preserves_endpoint_and_rejects_old_ticket() -> Test {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let tls = Tls::fresh(crate::tls::Profile::Raw, vec!["gnunet".into()])?;
                let mut endpoint = Endpoint::bind(
                    "127.0.0.1:0".parse()?,
                    tls,
                    Limits::default(),
                    Instant::now() + Duration::from_secs(30),
                )
                .map_err(|e| format!("{e:?}"))?;
                let bound = endpoint.local_addr();
                let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let original = endpoint
                    .dial(peer.local_addr()?)
                    .map_err(|e| format!("{e:?}"))?;
                let id = original.driver.clone();
                drop(original);
                if endpoint
                    .cancel_driver(&endpoint.endpoint_driver.clone())
                    .is_ok()
                {
                    return Err("endpoint driver was canceled as a connection".into());
                }
                if !endpoint.cancel_driver(&id).map_err(|e| format!("{e:?}"))?
                    || !endpoint.driver_done(&id).map_err(|e| format!("{e:?}"))?
                {
                    return Err("original driver did not actually retire".into());
                }
                endpoint.release_driver(&id).map_err(|e| format!("{e:?}"))?;
                let fresh = endpoint
                    .dial(peer.local_addr()?)
                    .map_err(|e| format!("{e:?}"))?;
                let next = fresh.driver.clone();
                drop(fresh);
                if next == id
                    || endpoint.cancel_driver(&id).is_ok()
                    || endpoint.local_addr() != bound
                {
                    return Err("driver ticket or native endpoint was reused".into());
                }
                endpoint
                    .cancel_driver(&next)
                    .map_err(|e| format!("{e:?}"))?;
                endpoint
                    .release_driver(&next)
                    .map_err(|e| format!("{e:?}"))?;
                endpoint.close().map_err(|e| format!("{e:?}"))?;
                Ok(())
            })
    }
}
