//! Caller-driven GNUnet CADET CLIENT MQ with bounded native framing.
//!
//! Actual attachment creates a pure connection epoch. Original immutable writes,
//! partial cursors and complete refused input survive canceled waiting futures.
//! A service ACK is local send credit, never remote application-delivery proof.
#![forbid(unsafe_code)]

mod client;
/// Actual CORE peer/physical-send bridge to the pure CADET connection book.
pub mod connection;
/// Actual owned PILS MQ identity-DH provider; private scoped results only.
pub mod identity_dh;
pub mod inspect;
/// Actual bounded official management SERVICE snapshots/query ownership.
pub mod management;
/// Actual bounded direct-neighbor CORE/KX/channel/application coordinator.
pub mod node;
/// Caller-driven native application SERVICE; remote peer work is an explicit port.
pub mod server;
/// Actual source-bound PILS signing and explicit durable monotime reservations.
pub mod signing;
/// One fixed native scheduling epoch alongside the actual logical absolute source.
pub mod time;
pub use client::{Client, Limits, LossCause, Received, Step};
/// Pure original-owner tokens and caller-provided fixed metadata storage.
pub use gnunet_cadet::client::{
    Channel, ChannelInfo, ChannelSlot, Delivery, Direction, Epoch, Ignored, Instance, Loss, Port,
    PortSlot, RetiredTransmit, Transmit, TransmitKind, Written,
};
/// Original configuration, protocol or native failure.
pub use gnunet_client_host::ConnectError as Error;
/// Actual CLIENT endpoint or explicitly selected configuration/Resolver domain.
pub use gnunet_client_host::EndpointSource;
/// Canonical logical-clock ports shared by the selected CLIENT source.
pub use gnunet_service_runtime::clock;
/// Immutable actual frame storage, securely erased when its final owner drops it.
pub use gnunet_service_runtime::framing::OwnedFrame;
