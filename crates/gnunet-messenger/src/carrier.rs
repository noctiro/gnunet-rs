//! Official room ports and unsigned relay padding over CADET.

use crate::wire::{SensitiveBytes, message::Message, padding, profile::Profile};
use gnunet_crypto::{Entropy, hash512};
use gnunet_types::Error;
use gnunet_wire::official::{Frame, HEADER_LEN, MessageHeader, cadet, message_type};
use zeroize::Zeroize;

/// Messenger version in the official peer INFO message.
pub const VERSION: u32 = 8;

/// Maximum complete Messenger frame carried as one CADET application message.
pub const MAX_FRAME_BYTES: usize = cadet::MAX_APPLICATION_MESSAGE_SIZE;

/// Derive the official CADET room port using the listener's producer byte order.
/// The reference hashes the little-endian major version and adds sixteen
/// native-order `u32` words to the original room key.
#[must_use]
pub fn port(key: &[u8; 64], listener: Profile) -> [u8; 64] {
    let version = hash512(&((VERSION >> 16) & 0xffff).to_le_bytes());
    let mut out = [0; 64];
    for ((dest, key), version) in out
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(key.as_chunks::<4>().0)
        .zip(version.as_chunks::<4>().0)
    {
        let a = listener.endian.read_u32(*key);
        let b = listener.endian.read_u32(*version);
        *dest = listener.endian.write_u32(a.wrapping_add(b));
    }
    out
}

/// Borrow the original bytes carried by an official `CADET_CLI` frame. The
/// caller must still decode the inner message and verify its signature.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a different application message type.
pub fn decode(frame: Frame<'_>) -> Result<SensitiveBytes<'_>, Error> {
    if frame.header().message_type() != message_type::CADET_CLI {
        return Err(Error::Unsupported);
    }
    Ok(SensitiveBytes::new(frame.payload()))
}

fn original_signed_bytes(message: Message<'_>) -> SensitiveBytes<'_> {
    let bytes = message.original().expose_encoded();
    SensitiveBytes::new(&bytes[..bytes.len() - message.padding().len()])
}

/// Smallest complete carrier frame for this original message, including the
/// official header and padding footer. This may exceed [`MAX_FRAME_BYTES`].
#[must_use]
pub fn minimum_frame_len(message: Message<'_>) -> usize {
    HEADER_LEN + original_signed_bytes(message).len() + padding::MIN_PADDING
}

/// Checked carrier framing for an original message. Preparation borrows the
/// signed bytes, performs no writes and does not assert signature validity.
#[derive(Debug)]
pub struct Prepared<'message> {
    original: SensitiveBytes<'message>,
    header: MessageHeader,
    footer: [u8; 2],
}

impl<'message> Prepared<'message> {
    /// Keep the original signed bytes and select an official padding length
    /// under the caller's complete CADET frame limit and [`MAX_FRAME_BYTES`].
    /// The limit and caller's output buffer capacity are independent.
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] if the signed content and minimum footer
    /// cannot fit, or a profile error if the relay's layout is invalid.
    pub fn new(
        message: Message<'message>,
        relay: Profile,
        maximum_frame_bytes: usize,
    ) -> Result<Self, Error> {
        let original = original_signed_bytes(message);
        let minimum = original.len() + padding::MIN_PADDING;
        let maximum = maximum_frame_bytes
            .min(MAX_FRAME_BYTES)
            .checked_sub(HEADER_LEN)
            .ok_or(Error::TooLarge)?;
        if minimum > maximum {
            return Err(Error::TooLarge);
        }
        let preferred = padding::rounded_length(original.len(), 0, relay)?;
        let payload_len = preferred.min(maximum);
        let pad_len = u16::try_from(payload_len - original.len()).map_err(|_| Error::TooLarge)?;
        Ok(Self {
            original,
            header: MessageHeader::new(message_type::CADET_CLI, payload_len)?,
            footer: relay.endian.write_u16(pad_len),
        })
    }

    /// Size of the complete CADET application frame.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.header.size()
    }

    /// Copy the exact original tagged signature and signed content, changing
    /// only the unsigned padding. Return the initialized frame length; the
    /// unused output suffix is untouched. The caller owns the output buffer.
    ///
    /// # Errors
    /// An output shorter than [`Self::encoded_len`] returns [`Error::Capacity`]
    /// without touching the buffer or entropy. An entropy failure erases the
    /// candidate frame prefix before propagation.
    pub fn encode_into(
        &self,
        output: &mut [u8],
        entropy: &mut impl Entropy,
    ) -> Result<usize, Error> {
        let len = self.encoded_len();
        let output = output.get_mut(..len).ok_or(Error::Capacity)?;
        let signed_end = HEADER_LEN + self.original.len();
        let footer_start = len - self.footer.len();
        let noise = &mut output[signed_end + 1..footer_start];
        if !noise.is_empty()
            && let Err(error) = entropy.fill(noise)
        {
            output.zeroize();
            return Err(error);
        }
        self.header.encode(output)?;
        output[HEADER_LEN..signed_end].copy_from_slice(self.original.expose());
        output[signed_end] = 0;
        output[footer_start..].copy_from_slice(&self.footer);
        Ok(len)
    }
}
