//! Bounded gateway construction retaining original owners on every refusal.
use super::{
    Error, Gateway, GatewayLimits, GatewayReport, PacketSource, RejectedGateway, ResolveMap,
    Server, Span, UPSTREAM_SOCKETS, Upstream,
};
use crate::core;
use gnunet_types::Error as Fault;
use tokio::time::Instant;

struct Parts<'id> {
    maps: Vec<Option<ResolveMap<'id>>>,
    spans: Vec<Option<Span<'id>>>,
}
impl<'id> Gateway<'id> {
    /// Adopt one original application flow into the existing service. Drive the
    /// same gateway after admission; no detached task or new IPC service starts.
    /// Refusal returns the native owner for explicit callback retirement.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[expect(
        clippy::result_large_err,
        reason = "Refusal preserves the original native flow without a fallible error allocation"
    )]
    pub fn admit_flow(
        &mut self,
        flow: gnunet_native::dns_proxy::UdpFlow,
    ) -> Result<(), crate::packet_source::RejectedFlow> {
        if self.closing {
            return Err(crate::packet_source::RejectedFlow {
                error: std::io::ErrorKind::NotConnected.into(),
                flow,
            });
        }
        self.packets.admit_flow(flow)
    }
    /// Packet source must already own its native resources. Attaching it is not
    /// a routing-setup ACK. Resolver construction alone opens/sends no socket.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected construction retains both original physical owners for explicit no-clock retirement, without a fallible error allocation"
    )]
    pub fn new(
        server: Server<'id>,
        packets: PacketSource<'id>,
        exit: std::net::IpAddr,
        limits: GatewayLimits,
    ) -> Result<Self, RejectedGateway<'id>> {
        let mut stub = match Upstream::start(limits.resolver_sockets, core::MAX_DNS_BYTES) {
            Ok(stub) => stub,
            Err(error) => {
                return Err(RejectedGateway {
                    error: error.into(),
                    server,
                    packets,
                    upstream: None,
                });
            }
        };
        if let Err(error) = stub.add_dns_sa(std::net::SocketAddr::new(exit, 53)) {
            return Err(RejectedGateway {
                error: error.into(),
                server,
                packets,
                upstream: Some(stub),
            });
        }
        Self::with_upstream(server, packets, stub, limits)
    }
    /// Adopt the original configured upstream, including sockets reserved before
    /// capture opened. A mismatched capture exemption refuses construction.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected construction retains original native owners for explicit retirement"
    )]
    pub fn with_upstream(
        mut server: Server<'id>,
        mut packets: PacketSource<'id>,
        stub: Upstream,
        limits: GatewayLimits,
    ) -> Result<Self, RejectedGateway<'id>> {
        if let Some(error) = packets.take_startup_error() {
            return Err(RejectedGateway {
                error: Error::Io(error),
                server,
                packets,
                upstream: Some(stub),
            });
        }
        let prepared = (|| -> Result<Parts<'id>, Error> {
            if !packets.initialized()
                || !packets.matches_upstream(&stub)
                || stub.slot_count() != limits.resolver_sockets
                || stub.is_stopped()
                || !(1..=UPSTREAM_SOCKETS).contains(&limits.resolver_sockets)
                || limits.request_lifetime.is_zero()
                || limits.request_hard_lifetime < limits.request_lifetime
            {
                return Err(Fault::InvalidInput.into());
            }
            for d in [limits.request_lifetime, limits.request_hard_lifetime] {
                if Instant::now().checked_add(d).is_none() || u64::try_from(d.as_micros()).is_err()
                {
                    return Err(Fault::Overflow.into());
                }
            }
            let count = server.engine().request_capacity();
            let mut maps = Vec::new();
            maps.try_reserve_exact(UPSTREAM_SOCKETS)
                .map_err(|_| Fault::Capacity)?;
            maps.resize_with(UPSTREAM_SOCKETS, || None);
            let mut spans = Vec::new();
            spans
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            spans.resize_with(count, || None);
            Ok(Parts { maps, spans })
        })();
        let Parts { maps, spans } = match prepared {
            Ok(p) => p,
            Err(error) => {
                return Err(RejectedGateway {
                    error,
                    server,
                    packets,
                    upstream: Some(stub),
                });
            }
        };
        let source = match server.engine_mut().attach_source() {
            Ok(source) => source,
            Err(error) => {
                return Err(RejectedGateway {
                    error: error.into(),
                    server,
                    packets,
                    upstream: Some(stub),
                });
            }
        };
        Ok(Self {
            server,
            packets,
            source,
            stub,
            maps,
            spans,
            limits,
            held_input: None,
            cursor: 0,
            class: 0,
            closing: false,
            source_done: false,
            upstream_done: false,
            source_settled: false,
            source_attached: true,
            source_suspended: false,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
            report: GatewayReport::default(),
        })
    }
}
