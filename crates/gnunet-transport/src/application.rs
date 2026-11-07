//! Official application hints, connection demand and cancellation, independent of native IO.
use crate::{
    PeerId,
    p2p::{bytes, u32_at},
};
use gnunet_types::Error;
use gnunet_wire::official::Frame;

/// A fire-and-forget address hint. This does not authenticate a peer or route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidateAddress<'a> {
    /// Untrusted network category supplied by the caller.
    pub network: u32,
    /// Expected identity whose signed validation is still required.
    pub peer: PeerId,
    /// Original NUL-free communicator address bytes without its wire terminator.
    pub address: &'a [u8],
}
impl<'a> ValidateAddress<'a> {
    /// Decode one complete original RequestHelloValidationMessage1302.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if frame.header().message_type().value() != 1302 {
            return Err(Error::Malformed);
        }
        let field = input.get(40..).ok_or(Error::Truncated)?;
        if field.last() != Some(&0) || field[..field.len() - 1].contains(&0) {
            return Err(Error::Malformed);
        }
        let address = &field[..field.len() - 1];
        Ok(Self {
            network: u32_at(input, 4)?,
            peer: PeerId(bytes(input, 8)?),
            address,
        })
    }
}

#[cfg(feature = "alloc")]
mod demand;
#[cfg(feature = "alloc")]
pub(crate) use demand::Demands;
#[cfg(feature = "alloc")]
pub use demand::Discovery;
/// Original performance/bandwidth preference carried by official1300/1301.
/// Zero bandwidth and background priority still request a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preference {
    /// Raw full-width public priority/preference bits.
    pub priority: u32,
    /// Expected peer identity.
    pub peer: PeerId,
    /// Desired bytes per second, not a delivery or allocation guarantee.
    pub bandwidth: u32,
}
impl Preference {
    /// Decode one exact44-byte suggestion or cancellation.
    pub fn decode(input: &[u8]) -> Result<(Self, bool), Error> {
        let f = Frame::decode(input)?;
        let kind = f.header().message_type().value();
        if !matches!(kind, 1300 | 1301) || input.len() != 44 {
            return Err(Error::Malformed);
        }
        Ok((
            Self {
                priority: u32_at(input, 4)?,
                peer: PeerId(bytes(input, 8)?),
                bandwidth: u32_at(input, 40)?,
            },
            kind == 1301,
        ))
    }
    /// Encode one exact official message, preserving every preference bit.
    pub fn encode(self, cancel: bool, output: &mut [u8]) -> Result<usize, Error> {
        use gnunet_wire::official::{MessageHeader, MessageType};
        if output.len() < 44 {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(MessageType::new(if cancel { 1301 } else { 1300 }), 44)?
            .encode(output)?;
        output[4..8].copy_from_slice(&self.priority.to_be_bytes());
        output[8..40].copy_from_slice(&self.peer.0);
        output[40..44].copy_from_slice(&self.bandwidth.to_be_bytes());
        Ok(44)
    }
}
/// Result of considering an untrusted address for a live original suggestion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressAdmission {
    /// A new immutable1206 request was admitted, with no authentication claim.
    Issued,
    /// Existing original queue/create already covers this address.
    Existing,
    /// No matching communicator, own peer or unsupported address prefix.
    Unsupported,
    /// Permanently incompatible with the current local resource configuration.
    Declined(Error),
    /// Temporary finite control/create/output capacity is unavailable.
    Deferred,
}
