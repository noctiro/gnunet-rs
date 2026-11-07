//! Official NSE_P2P_FLOOD322 fixed layout and purpose14 signed region.
//! These are wire values, without peer admission, signature/PoW verification,
//! round selection, estimator updates or transmit scheduling.
use crate::official::{AbsoluteTime, Frame, MessageHeader, SignaturePurpose, message_type};
use gnunet_types::Error;

/// Exact packed flood message length, including its signature.
pub const MESSAGE_LEN: usize = 132;
/// Exact signed region length, including the purpose header.
pub const SIGNED_LEN: usize = 60;
/// Official GNUNET_SIGNATURE_PURPOSE_NSE_SEND assignment.
pub const SIGNATURE_PURPOSE: u32 = 14;

/// Unauthenticated fixed-width flood fields. The proof is eight opaque bytes:
/// the reference copies its native counter directly and hashes those bytes
/// together with the origin key. Applying a network integer conversion here
/// would change the proof. Hop count lies outside the signed region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fields {
    /// Unsigned hop metadata. Receiving a message grants no forwarding authority.
    pub hops: u32,
    /// Microsecond round timestamp in network byte order on the wire.
    pub timestamp: AbsoluteTime,
    /// Claimed matching-bit count; encoding does not establish its truth.
    pub matching_bits: u32,
    /// Claimed origin Ed25519 public identity bytes.
    pub origin: [u8; 32],
    /// Original proof bytes, not a host- or network-order integer API.
    pub proof: [u8; 8],
    /// Claimed signature over the exact purpose/time/count/origin/proof region.
    pub signature: [u8; 64],
}
impl Fields {
    /// Encode the complete official message, without validating cryptography.
    /// Capacity refusal leaves the entire destination unchanged.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < MESSAGE_LEN {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(message_type::NSE_P2P_FLOOD, MESSAGE_LEN)?.encode(output)?;
        output[4..8].copy_from_slice(&self.hops.to_be_bytes());
        self.encode_signed(&mut output[8..68])?;
        output[68..132].copy_from_slice(&self.signature);
        Ok(MESSAGE_LEN)
    }

    /// Encode the canonical signed region, excluding hop metadata and signature.
    /// The caller must separately authorize signing and bind its actual key.
    /// Capacity refusal leaves the entire destination unchanged.
    pub fn encode_signed(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < SIGNED_LEN {
            return Err(Error::Capacity);
        }
        SignaturePurpose::new(SIGNATURE_PURPOSE, SIGNED_LEN - 8)?.encode(output)?;
        output[8..16].copy_from_slice(&self.timestamp.as_micros().to_be_bytes());
        output[16..20].copy_from_slice(&self.matching_bits.to_be_bytes());
        output[20..52].copy_from_slice(&self.origin);
        output[52..60].copy_from_slice(&self.proof);
        Ok(SIGNED_LEN)
    }
}

/// Borrowed, structurally valid official flood; no authenticated authority.
/// The signed range is borrowed from the original message without re-encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    bytes: &'a [u8; MESSAGE_LEN],
    signed: &'a [u8; SIGNED_LEN],
}
impl<'a> Message<'a> {
    /// Decode one complete official frame and exact purpose14/size60 prefix.
    /// All public field bit patterns remain available for the service verifier;
    /// this codec applies no freshness, work-factor or claimed-distance filter.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != message_type::NSE_P2P_FLOOD
            || input.len() != MESSAGE_LEN
        {
            return Err(Error::InvalidInput);
        }
        let purpose = SignaturePurpose::decode(&input[8..16])?;
        purpose.validate_signed_size(SIGNED_LEN)?;
        if purpose.purpose() != SIGNATURE_PURPOSE {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            bytes: input.try_into().map_err(|_| Error::Truncated)?,
            signed: input[8..68].try_into().map_err(|_| Error::Truncated)?,
        })
    }

    /// Exact original frame, with unauthenticated hop metadata intact.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8; MESSAGE_LEN] {
        self.bytes
    }

    /// Exact original signed bytes; includes the purpose prefix, excludes hops.
    #[must_use]
    pub const fn signed_bytes(self) -> &'a [u8; SIGNED_LEN] {
        self.signed
    }

    /// Copy public fields after structural decoding; cryptography is unchecked.
    pub fn fields(self) -> Result<Fields, Error> {
        Ok(Fields {
            hops: u32::from_be_bytes(self.bytes[4..8].try_into().map_err(|_| Error::Truncated)?),
            timestamp: AbsoluteTime::from_micros(u64::from_be_bytes(
                self.bytes[16..24]
                    .try_into()
                    .map_err(|_| Error::Truncated)?,
            )),
            matching_bits: u32::from_be_bytes(
                self.bytes[24..28]
                    .try_into()
                    .map_err(|_| Error::Truncated)?,
            ),
            origin: self.bytes[28..60]
                .try_into()
                .map_err(|_| Error::Truncated)?,
            proof: self.bytes[60..68]
                .try_into()
                .map_err(|_| Error::Truncated)?,
            signature: self.bytes[68..132]
                .try_into()
                .map_err(|_| Error::Truncated)?,
        })
    }
}
