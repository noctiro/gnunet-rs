//! Original Apple DNS provider flows, connections and bounded SDK operations.
//!
//! Class registration does not install or activate a NetworkExtension provider.
//! The caller drives every pending
//! result through retirement. Dropping a wait or owner never frees storage still
//! retained by an SDK callback.
/// Containing-application identity and the native AppKit event loop.
#[cfg(all(target_os = "macos", feature = "dns-proxy-control"))]
pub mod application;
mod callback;
mod completion;
mod connection;
/// Explicit original system-extension activation and deactivation requests.
#[cfg(all(target_os = "macos", feature = "dns-proxy-control"))]
pub mod extension;
mod flow;
mod input;
mod lifetime;
/// Serialized DNS proxy preference operations and their original completions.
#[cfg(all(target_os = "macos", feature = "dns-proxy-control"))]
pub mod management;
mod multicast;
/// Native provider class, bounded controller and original lifecycle obligations.
pub mod provider;
#[expect(
    unsafe_code,
    reason = "Narrow typed Objective-C and Network SDK boundary; retained native owners and exact selectors are checked before use"
)]
mod sdk;
mod tcp;

pub use connection::{Connection, ConnectionRetirement, Received as ConnectionReceived};
pub use flow::{Retirement, UdpFlow, WriteRejected};
pub use input::{
    Datagram, FlowId, MAX_DATAGRAM_BYTES, Read, ReadBatch, ReadDatagram, ReadLimits, ReplyEndpoint,
};
pub use multicast::{MulticastEvent, MulticastRequest, MulticastRetirement};
pub use sdk::NativeError;
pub use tcp::{MAX_TCP_CHUNK_BYTES, TcpFlow, TcpRead, TcpRetirement};
