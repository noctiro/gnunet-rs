//! Official GNUnet wire formats, independently implemented in Rust.
//!
//! The baseline is GNUnet v0.29.1, commit
//! `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. These types use official
//! size/type framing, signature-purpose headers and microsecond timestamps.
//! They add no private protocol magic, network scope or version prefix.
//! A codec does not authenticate its bytes or implement a peer service.

pub mod cadet;
pub mod cadet_peer;
/// Standard communicator IPC independent of a TCP/UDP session implementation.
pub mod communicator;
pub mod core;
pub mod dht;
mod frame;
pub mod fs;
/// Official FS direct block-transfer messages carried inside CADET channels.
pub mod fs_cadet;
pub mod fs_gap;
pub mod hello;
/// Official IDENTITY ego inventory and mutation IPC.
pub mod identity;
pub mod message_type;
/// Official active MESSENGER IPC and encoded envelope framing.
pub mod messenger;
/// Official NAMECACHE encrypted-block client IPC.
pub mod namecache;
pub mod namestore;
/// Official NAT native-address IPC and external test frames.
pub mod nat;
/// Official NAT-auto serialized configuration IPC.
pub mod nat_auto;
pub mod nse;
pub mod peerstore;
pub mod pils;
/// Official REGEX announcement/search client IPC.
pub mod regex;
/// Official active RPS contrib service IPC and CADET peer frames.
pub mod rps;
/// Official scalarproduct IPC and distinct ECC/Paillier CADET profiles.
pub mod scalarproduct;
/// Official active contrib generic SET IPC and peer frames, distinct from SETI/SETU.
pub mod set;
pub mod seti;
pub mod setu;
mod time;
/// Official physical-queue monitoring and virtual-link listing IPC.
pub mod transport_monitor;
pub mod vpn;

pub use frame::{Frame, Frames, MessageHeader, MessageType, SignaturePurpose};
pub use time::{AbsoluteTime, RelativeTime};

/// Exact upstream source commit against which the codecs are validated.
pub const UPSTREAM_REVISION: &str = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165";
/// Official `GNUNET_MessageHeader` size (`gnunet_common.h:323`).
pub const HEADER_LEN: usize = 4;
/// Largest frame expressible by the official 16-bit total-size field.
pub const MAX_MESSAGE_SIZE: usize = u16::MAX as usize;
/// Official `GNUNET_CRYPTO_SignaturePurpose` header size (`gnunet_crypto_lib.h:119`).
pub const SIGNATURE_PURPOSE_LEN: usize = 8;

/// Official DATASTORE service wire/client operations.
pub mod datastore;

/// Official DNS interception IPC, distinct from DNSSTUB.
pub mod dns;

/// Active contrib multi-peer consensus IPC/context and element wrappers.
pub mod consensus;

/// Active official ABD IPC, signed DEL and conjunctive ATTR record layouts.
pub mod abd;

/// Active contrib threshold-share IPC and signed consensus element formats.
pub mod secretsharing;

/// Conditional CONVERSATION local/peer/helper framing and signed ringing context.
pub mod conversation;
