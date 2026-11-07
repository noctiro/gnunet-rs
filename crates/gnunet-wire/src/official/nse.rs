//! Official network-size-estimation service IPC. Flooding and its authentication
//! are separate peer-service protocols. An estimate is statistical public data,
//! not an authenticated count of all peers.
use super::{AbsoluteTime, Frame, MessageHeader, message_type};
use gnunet_types::Error;

/// Peer flooding wire format; decoding alone authenticates no estimate or proof.
pub mod flood;

/// Exact size of the header-only NSE_START321 subscription.
pub const START_LEN: usize = 4;
/// Exact NSE_ESTIMATE323 size, including the common header and reserved field.
pub const ESTIMATE_LEN: usize = 32;

/// The original binary64 representation of one public estimated quantity.
/// Equality compares wire bits, including NaN payloads and signed zero. The
/// service may report NaN deviation; decoding never replaces it with certainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Double(u64);
impl Double {
    /// Retain a value's IEEE754 binary64 representation.
    #[must_use]
    pub const fn from_value(value: f64) -> Self {
        Self(value.to_bits())
    }
    /// Retain original wire bits without a floating-point calculation.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
    /// Original binary64 bits, not a normalized numeric value.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
    /// Public floating-point value. It can be non-finite or signed zero.
    #[must_use]
    pub const fn value(self) -> f64 {
        f64::from_bits(self.0)
    }
}

/// One source-service observation. The estimate is log2(size), not linear size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Estimate {
    /// Source-service microsecond timestamp; decoding grants no freshness.
    pub timestamp: AbsoluteTime,
    /// Base2 logarithm of the estimated network size.
    pub log2_size: Double,
    /// Source-service deviation, which may legitimately be NaN.
    pub deviation: Double,
}
impl Estimate {
    /// Decode exactly one official estimate. The reference client ignores the
    /// reserved field; all binary64 representations remain unchanged.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != message_type::NSE_ESTIMATE
            || input.len() != ESTIMATE_LEN
        {
            return Err(Error::InvalidInput);
        }
        let field = |at: usize| -> Result<u64, Error> {
            Ok(u64::from_be_bytes(
                input[at..at + 8].try_into().map_err(|_| Error::Truncated)?,
            ))
        };
        Ok(Self {
            timestamp: AbsoluteTime::from_micros(field(8)?),
            log2_size: Double::from_bits(field(16)?),
            deviation: Double::from_bits(field(24)?),
        })
    }
    /// Encode the official fields with zero reserved bits. A capacity refusal
    /// leaves the entire destination unchanged. No finite-value filter applies.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < ESTIMATE_LEN {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(message_type::NSE_ESTIMATE, ESTIMATE_LEN)?.encode(output)?;
        output[4..8].fill(0);
        output[8..16].copy_from_slice(&self.timestamp.as_micros().to_be_bytes());
        output[16..24].copy_from_slice(&self.log2_size.bits().to_be_bytes());
        output[24..32].copy_from_slice(&self.deviation.bits().to_be_bytes());
        Ok(ESTIMATE_LEN)
    }
}

/// Decode the exact header-only subscription, without accepting trailing bytes.
pub fn decode_start(input: &[u8]) -> Result<(), Error> {
    let frame = Frame::decode(input)?;
    if frame.header().message_type() != message_type::NSE_START || input.len() != START_LEN {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Encode one official subscription. This performs no I/O or estimate delivery.
pub fn encode_start(output: &mut [u8]) -> Result<usize, Error> {
    MessageHeader::from_total_size(message_type::NSE_START, START_LEN)?.encode(output)
}
