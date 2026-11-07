//! Official CADET_CLI envelope/room-port layout; no transport or crypto success.
use gnunet_messenger_core::wire::{self, padding, profile::Profile};
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, message_type};
use zeroize::Zeroizing;
pub(crate) const VERSION: u32 = 8;
pub(crate) const MAX_RAW: usize = gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE - 4;
/// Actual C port computation hashes the LE major version and adds sixteen
/// producer-native u32 words, rather than XOR or a new service string hash.
pub(crate) fn port(key: &[u8; 64], profile: Profile) -> [u8; 64] {
    let version = gnunet_crypto::hash512(&((VERSION >> 16) & 0xffff).to_le_bytes());
    let mut out = [0; 64];
    for index in 0..16 {
        let at = index * 4;
        let a = profile
            .endian
            .read_u32([key[at], key[at + 1], key[at + 2], key[at + 3]]);
        let b = profile.endian.read_u32([
            version[at],
            version[at + 1],
            version[at + 2],
            version[at + 3],
        ]);
        out[at..at + 4].copy_from_slice(&profile.endian.write_u32(a.wrapping_add(b)));
    }
    out
}
/// Borrow the exact original inner signed data from the official message type.
/// Caller must iterate a complete CADET message string, not strip arbitrary4B.
pub(crate) fn decode(frame: &[u8]) -> Result<&[u8], Error> {
    let frame = Frame::decode(frame)?;
    if frame.header().message_type() != message_type::CADET_CLI {
        return Err(Error::Unsupported);
    }
    Ok(frame.payload())
}
/// Repack actual signed content with a valid official peer padding footer.
/// Hash/signature inputs do not include this padding. Existing C rounding can
/// select65524, above the current public CADET maximum64348; choose the largest
/// legal carrier total instead when it still fits the real content+footer.
/// Permanently oversized content is TooLarge, never a capacity-pending fragment.
pub(crate) fn encode(
    raw: &[u8],
    layout: gnunet_messenger_core::OriginalLayout,
    decode: padding::Decode,
    output_profile: Profile,
    entropy: &mut impl gnunet_crypto::Entropy,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let kind = wire::envelope::Envelope::decode(raw)?.header()?.kind;
    let profile = layout.body_profile(kind).map_err(|_| Error::Unsupported)?;
    let message =
        wire::message::Message::decode_with_profiles(raw, profile, layout.padding, decode)?;
    let unpadded = message
        .hash_input()
        .expose()
        .len()
        .checked_add(68)
        .ok_or(Error::Overflow)?;
    let minimum = unpadded.checked_add(3).ok_or(Error::Overflow)?;
    if minimum > MAX_RAW {
        return Err(Error::TooLarge);
    }
    let preferred = padding::rounded_length(unpadded, 0, output_profile)?;
    let total = preferred.min(MAX_RAW).max(minimum);
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(total + 4)
        .map_err(|_| Error::Capacity)?;
    bytes.resize(total + 4, 0);
    MessageHeader::from_total_size(message_type::CADET_CLI, total + 4)?.encode(&mut bytes[..4])?;
    bytes[4..4 + unpadded].copy_from_slice(raw.get(..unpadded).ok_or(Error::Truncated)?);
    let padding = total - unpadded;
    bytes[4 + unpadded] = 0;
    entropy.fill(&mut bytes[5 + unpadded..4 + total - 2])?;
    bytes[4 + total - 2..].copy_from_slice(
        &output_profile
            .endian
            .write_u16(u16::try_from(padding).map_err(|_| Error::TooLarge)?),
    );
    Ok(bytes)
}
