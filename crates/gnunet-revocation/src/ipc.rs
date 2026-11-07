//! The same REVOKE frame is used by application IPC and peer flooding.
//! There is no RID, wire cancellation, private prefix or invented ACK.
use crate::{KEY_BYTES, PROOF_BYTES, Proof};
use gnunet_gnsrecord::ZoneKey;
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, message_type as mt};
/// Common header4 and carried key/proof length BE32.
pub const PREFIX: usize = 8;
/// Current full public-key query frame size.
pub const QUERY_BYTES: usize = PREFIX + KEY_BYTES;
/// Current full public certificate/revocation frame size.
pub const REVOKE_BYTES: usize = PREFIX + PROOF_BYTES;
/// Exact official response size for both operations.
pub const RESPONSE_BYTES: usize = 8;
/// One original request on its physical source; no correlation id exists.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// Check whether the exact public key is known revoked.
    Query(ZoneKey),
    /// Submit/broadcast the original certificate; structural decoding grants no validity.
    Revoke(Proof<'a>),
}
impl<'a> Request<'a> {
    /// Decode exactly one complete official request.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let carried = u32::from_be_bytes(
            input
                .get(4..8)
                .ok_or(Error::Truncated)?
                .try_into()
                .map_err(|_| Error::Truncated)?,
        );
        match frame.header().message_type() {
            mt::REVOCATION_QUERY if input.len() == QUERY_BYTES && carried == KEY_BYTES as u32 => {
                Ok(Self::Query(ZoneKey::from_wire(&input[PREFIX..])?))
            }
            mt::REVOCATION_REVOKE
                if input.len() == REVOKE_BYTES && carried == PROOF_BYTES as u32 =>
            {
                Ok(Self::Revoke(Proof::parse(&input[PREFIX..])?))
            }
            _ => Err(Error::Malformed),
        }
    }
    /// Full official size, including the existing framing/length words.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Query(_) => QUERY_BYTES,
            Self::Revoke(_) => REVOKE_BYTES,
        }
    }
    /// Encode after complete capacity preflight; refusal leaves output untouched.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        let out = output.get_mut(..n).ok_or(Error::Capacity)?;
        let (kind, size) = match self {
            Self::Query(_) => (mt::REVOCATION_QUERY, KEY_BYTES),
            Self::Revoke(_) => (mt::REVOCATION_REVOKE, PROOF_BYTES),
        };
        MessageHeader::from_total_size(kind, n)?.encode(out)?;
        out[4..8].copy_from_slice(&(size as u32).to_be_bytes());
        match self {
            Self::Query(public) => out[PREFIX..].copy_from_slice(&public.to_wire()),
            Self::Revoke(proof) => out[PREFIX..].copy_from_slice(proof.bytes()),
        }
        Ok(n)
    }
}
/// Preserve actual raw callback words, including unknown future/error values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response {
    /// Official query is_valid word:0 revoked,1 still valid.
    Query(u32),
    /// Actual pinned service word:0 accepted,1 failure; the header comment is reversed.
    Revoke(u32),
}
impl Response {
    /// Decode exactly one complete official response without normalization.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if input.len() != RESPONSE_BYTES {
            return Err(Error::Malformed);
        }
        let raw = u32::from_be_bytes(input[4..8].try_into().map_err(|_| Error::Malformed)?);
        match frame.header().message_type() {
            mt::REVOCATION_QUERY_RESPONSE => Ok(Self::Query(raw)),
            mt::REVOCATION_REVOKE_RESPONSE => Ok(Self::Revoke(raw)),
            _ => Err(Error::Malformed),
        }
    }
    /// Encode the original raw word; no boolean or generic success substitution.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let out = output.get_mut(..RESPONSE_BYTES).ok_or(Error::Capacity)?;
        let (kind, raw) = match self {
            Self::Query(raw) => (mt::REVOCATION_QUERY_RESPONSE, raw),
            Self::Revoke(raw) => (mt::REVOCATION_REVOKE_RESPONSE, raw),
        };
        MessageHeader::from_total_size(kind, RESPONSE_BYTES)?.encode(out)?;
        out[4..8].copy_from_slice(&raw.to_be_bytes());
        Ok(RESPONSE_BYTES)
    }
    /// Actual raw word, never an inferred source/write result.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::Query(v) | Self::Revoke(v) => v,
        }
    }
    /// Query interpretation only; unknown words and other operation return None.
    #[must_use]
    pub const fn revoked(self) -> Option<bool> {
        match self {
            Self::Query(0) => Some(true),
            Self::Query(1) => Some(false),
            _ => None,
        }
    }
    /// Real pinned REVOKE reply interpretation only, not disk/network delivery.
    #[must_use]
    pub const fn accepted(self) -> Option<bool> {
        match self {
            Self::Revoke(0) => Some(true),
            Self::Revoke(1) => Some(false),
            _ => None,
        }
    }
}
