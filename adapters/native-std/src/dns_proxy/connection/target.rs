//! Construction provenance, independently of numeric endpoint observations.
use super::{
    super::{input::FlowId, sdk::Endpoint},
    TcpFlow,
};
use std::{io, net::SocketAddr};

pub(super) enum Target {
    Tcp { flow: FlowId, endpoint: Endpoint },
    Udp(SocketAddr),
}
impl Target {
    pub(super) fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp { endpoint, .. } => endpoint.socket_addr(),
            Self::Udp(peer) => Ok(*peer),
        }
    }
    pub(super) const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp { .. })
    }
    pub(super) fn matches_tcp_flow(&self, original: &TcpFlow) -> bool {
        matches!(self, Self::Tcp { flow, .. } if *flow == original.id())
    }
}
