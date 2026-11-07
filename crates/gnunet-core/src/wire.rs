//! v0.29.1 CORE framing, including the reference 64-bit ABI's handshake padding.
//! The padding participates in the transcript. It is not a Rust object layout.
use gnunet_types::Error;

/// Fixed unencrypted InitiatorHello prefix in the normal 64-bit reference build.
pub const INITIATOR_PREFIX: usize = 144;
/// Plaintext identity and peer-class prefix of InitiatorHello.
pub const INITIATOR_PAYLOAD: usize = 34;
/// Fixed unencrypted ResponderHello prefix in the normal 64-bit reference build.
pub const RESPONDER_PREFIX: usize = 48;
/// Plaintext encapsulation and peer-class prefix of ResponderHello.
pub const RESPONDER_PAYLOAD: usize = 34;
/// InitiatorDone prefix, containing Finished ciphertext64 and its tag16.
pub const DONE_PREFIX: usize = 84;
/// Encrypted application record prefix, including the detached authentication tag.
pub const RECORD_PREFIX: usize = 36;
/// Official acknowledgement plaintext.
pub const ACK: [u8; 4] = [0, 4, 0, 85];

/// Which source-native 32-bit word order the reference hash comparison uses.
/// v0.29.1's comparison is not a portable bytewise order; make the profile explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordOrder {
    /// Normal little-endian reference peers, including Darwin arm64/Linux x86_64.
    Little,
    /// Source-native word interpretation of a big-endian reference peer.
    Big,
}

/// Determine the lower SHA512 identity according to the actual reference helper.
#[must_use]
pub fn is_initiator(local: &[u8; 32], peer: &[u8; 32], order: WordOrder) -> bool {
    let local = gnunet_crypto::hash512(local);
    let peer = gnunet_crypto::hash512(peer);
    for (a, b) in local
        .as_chunks::<4>()
        .0
        .iter()
        .zip(peer.as_chunks::<4>().0)
        .rev()
    {
        let (a, b) = match order {
            WordOrder::Little => (u32::from_le_bytes(*a), u32::from_le_bytes(*b)),
            WordOrder::Big => (u32::from_be_bytes(*a), u32::from_be_bytes(*b)),
        };
        if a != b {
            return a < b;
        }
    }
    false
}

/// Check one complete official frame and return its message identifier.
pub fn kind(frame: &[u8]) -> Result<u16, Error> {
    if frame.len() < 4 {
        return Err(Error::Truncated);
    }
    if usize::from(u16::from_be_bytes([frame[0], frame[1]])) != frame.len() {
        return Err(Error::InvalidInput);
    }
    Ok(u16::from_be_bytes([frame[2], frame[3]]))
}

/// Write the checked common header. Rejection writes no bytes.
pub fn header(output: &mut [u8], size: usize, kind: u16) -> Result<(), Error> {
    let size16 = u16::try_from(size).map_err(|_| Error::TooLarge)?;
    if size < 4 || output.len() < size {
        return Err(Error::Capacity);
    }
    output[..2].copy_from_slice(&size16.to_be_bytes());
    output[2..4].copy_from_slice(&kind.to_be_bytes());
    Ok(())
}

pub(crate) fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}

/// Validate a nonempty complete sequence of application messages without truncation.
pub fn messages(mut bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() {
        return Err(Error::InvalidInput);
    }
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(Error::Truncated);
        }
        let size = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if size < 4 {
            return Err(Error::InvalidInput);
        }
        bytes = bytes.get(size..).ok_or(Error::Truncated)?;
    }
    Ok(())
}
