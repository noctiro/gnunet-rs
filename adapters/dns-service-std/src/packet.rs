//! Raw DNS packet and official helper envelopes outside the DNS phase engine.
//!
//! Decoding borrows the original DNS body and checks real IP/UDP bounds,
//! checksums and query port. Reply tuples describe bytes, not native injection
//! authority; the host separately retains the original source and reply permit.
pub(crate) mod address;
mod helper;
mod query;
mod reply;

pub use gnunet_vpn::packet::{Address, Family};
pub(crate) use helper::decode_helper_packet;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub(crate) use helper::encode_checked_helper;
pub use helper::{HELPER_PREFIX, encode_helper, helper_packet};
pub(crate) use query::decode_parsed_query;
pub use query::{ReplyTuple, decode_helper_query, decode_query};
pub use reply::Framing;
