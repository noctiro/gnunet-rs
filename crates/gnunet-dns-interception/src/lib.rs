//! Official DNS interception phases over validated DNS datagrams and original sources.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
use core::fmt;
use gnunet_types::Error;
pub use gnunet_wire::official::dns::{self as wire, Decision};
/// Largest DNS body fitting the official 16-byte client callback/reply prefix.
/// Native packet and socket encoders impose their own transport limits.
pub const MAX_DNS_BYTES: usize = 65_535 - 16;

mod correlation;
pub use correlation::{
    gateway_reply_matches, questioned_reply_matches, response_matches_questions,
    validate_questioned_query,
};

/// Borrowed DNS query with a complete query header and official IPC size bound.
/// This validates neither questions/records nor DNSSEC; consumers parse those
/// fields under their own bounded grammar. It carries no source authority.
#[derive(Clone, Copy)]
pub struct Query<'a> {
    bytes: &'a [u8],
}
impl<'a> Query<'a> {
    /// Validate the original body without allocating, copying or changing it.
    ///
    /// # Errors
    /// Refuses truncated headers, response messages and bodies exceeding the
    /// official interception IPC ceiling.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_DNS_BYTES {
            return Err(Error::TooLarge);
        }
        let header = gnunet_dns::Header::decode(bytes)?;
        if header.flags.bits() & 0x8000 != 0 {
            return Err(Error::Malformed);
        }
        Ok(Self { bytes })
    }
    /// Exact original DNS datagram bytes, with no IP, UDP or helper envelope.
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}
impl fmt::Debug for Query<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
mod engine;
#[cfg(feature = "alloc")]
pub use engine::Engine;
pub use engine::{
    Client, Destination, Effect, FixedEngine, Instance, Limits, OutputPhase, Phase, PreparedReply,
    Request, Resolve, Source, Work,
};

#[cfg(test)]
mod fixed_tests;
#[cfg(all(test, feature = "alloc"))]
mod model;
