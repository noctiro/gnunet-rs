//! Explicit native-order footer profile with canonical bounds. No randomness
//! is generated; callers supply the exact original/desired padding noise.
use super::{SensitiveBytes, profile::Profile};
use gnunet_types::Error;
/// Official zero marker plus trailing native-order u16.
pub const MIN_PADDING: usize = 3;
/// Context-selected padding parsing. Detect is inherently ambiguous for an
/// unpadded binary tail; use Absent/Required when the transport context is known.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decode {
    /// The producer emitted its exact unpadded length (normal client IPC).
    Absent,
    /// A valid canonical footer is mandatory (normal packed peer/short data).
    Required,
    /// Recognize a valid reference footer, otherwise retain all original bytes.
    Detect,
}
/// Caller-selected encoded total and exact filler. This generates no entropy
/// and labels no encoded bytes as authenticated, encrypted or delivered.
#[derive(Clone, Copy, Debug)]
pub enum Encode<'a> {
    /// Emit only the exact typed message bytes.
    Absent,
    /// Pad to the full encoded-message total, with exactly padding-3 noise bytes.
    ToLength {
        /// Entire signed or short encoded message length, including its prefix.
        total: usize,
        /// Caller-supplied filler, excluding zero marker and u16 count.
        noise: SensitiveBytes<'a>,
    },
}
/// Exact original content/footer split; the padding view includes marker,
/// filler and the original endian count, preserving bytes for forwarding.
#[derive(Clone, Copy, Debug)]
pub struct Split<'a> {
    /// Original body bytes before recognized padding.
    pub content: SensitiveBytes<'a>,
    /// Original complete recognized footer, or empty for no padding.
    pub padding: SensitiveBytes<'a>,
}
/// Safely split a raw body tail. Invalid or sub-three-byte footers are never
/// used to underflow/strip a fixed body. Typed decoding must recheck its minimum
/// after splitting, unlike the unsafe reference's pre-padding-only check.
pub fn split<'a>(
    tail: SensitiveBytes<'a>,
    profile: Profile,
    mode: Decode,
) -> Result<Split<'a>, Error> {
    profile.validate()?;
    let bytes = tail.expose();
    let no = || Split {
        content: tail,
        padding: SensitiveBytes::new(&bytes[bytes.len()..]),
    };
    if mode == Decode::Absent {
        return Ok(no());
    }
    let candidate = if bytes.len() >= 2 {
        usize::from(
            profile
                .endian
                .read_u16([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]),
        )
    } else {
        0
    };
    if candidate >= MIN_PADDING && candidate <= bytes.len() && bytes[bytes.len() - candidate] == 0 {
        let end = bytes.len() - candidate;
        return Ok(Split {
            content: SensitiveBytes::new(&bytes[..end]),
            padding: SensitiveBytes::new(&bytes[end..]),
        });
    }
    if mode == Decode::Required {
        Err(Error::Malformed)
    } else {
        Ok(no())
    }
}
/// Actual reference usual-padding calculation: its stale KIND_MAX21 loop only
/// includes fixed body minima, no signature or variable public keys. FILE and
/// MERGE dominate; timestamp8+sender32+previous64+kind4 contribute108.
pub fn usual_minimum(profile: Profile) -> Result<usize, Error> {
    profile.validate()?;
    108usize
        .checked_add(192usize.max(64 + profile.file_name_bytes))
        .and_then(|n| n.checked_add(MIN_PADDING))
        .ok_or(Error::Overflow)
}
/// Rounded reference packet length at512,4096,32768 or65524. overhead is48 for
/// HPKE private short messages and0 for signed/AEAD messages. Returns the total
/// ciphertext/packet length; subtract overhead to obtain padded plaintext.
pub fn rounded_length(unpadded: usize, overhead: usize, profile: Profile) -> Result<usize, Error> {
    let required = unpadded
        .checked_add(overhead)
        .and_then(|n| n.checked_add(MIN_PADDING))
        .ok_or(Error::Overflow)?
        .max(usual_minimum(profile)?);
    [512, 4096, 32768, 65524]
        .into_iter()
        .find(|n| *n >= required)
        .ok_or(Error::TooLarge)
}
/// Preflight the total and filler against an already known unpadded length.
/// No header/body bytes need be written before this can succeed or fail.
pub fn encoded_length(unpadded: usize, padding: Encode<'_>) -> Result<usize, Error> {
    let total = match padding {
        Encode::Absent => unpadded,
        Encode::ToLength { total, noise } => {
            let count = total.checked_sub(unpadded).ok_or(Error::InvalidInput)?;
            if count < MIN_PADDING || count - 3 != noise.len() {
                return Err(Error::InvalidInput);
            }
            total
        }
    };
    u16::try_from(total).map_err(|_| Error::TooLarge)?;
    Ok(total)
}
/// Write only a checked suffix, preserving header/body bytes. All caller
/// shape/capacity checks precede writes; filler is never truncated or invented.
pub fn write(
    unpadded: usize,
    padding: Encode<'_>,
    profile: Profile,
    output: &mut [u8],
) -> Result<usize, Error> {
    profile.validate()?;
    let total = encoded_length(unpadded, padding)?;
    if output.len() < total {
        return Err(Error::Capacity);
    }
    if let Encode::ToLength { noise, .. } = padding {
        let count = total - unpadded;
        let encoded_count = profile
            .endian
            .write_u16(u16::try_from(count).map_err(|_| Error::TooLarge)?);
        output[unpadded] = 0;
        output[unpadded + 1..total - 2].copy_from_slice(noise.expose());
        output[total - 2..total].copy_from_slice(&encoded_count);
    }
    Ok(total)
}
