//! RFC 1952 members over the shared bounded DEFLATE inflater.

use gnunet_crypto::crc32_n;
use gnunet_fs_codec::{DeflateFormat, Inflate};

pub(super) fn decode(
    inflater: &mut Inflate,
    mut input: &[u8],
    mut output: &mut [u8],
) -> Option<usize> {
    if input.is_empty() {
        return None;
    }
    let capacity = output.len();
    while !input.is_empty() {
        let body = header(input)?;
        let progress = inflater
            .inflate_prefix(DeflateFormat::Raw, body, output)
            .ok()?;
        let (trailer, tail) = body.get(progress.consumed..)?.split_first_chunk::<8>()?;
        let (decoded, free) = output.split_at_mut_checked(progress.produced)?;
        let (crc, size) = trailer.split_first_chunk::<4>()?;
        if u32::from_le_bytes(*crc) != crc32_n(decoded)
            || u32::from_le_bytes(*size.first_chunk()?) != progress.produced as u32
        {
            return None;
        }
        input = tail;
        output = free;
    }
    Some(capacity - output.len())
}

fn header(input: &[u8]) -> Option<&[u8]> {
    let (&[0x1f, 0x8b, 8, flags, ..], mut rest) = input.split_first_chunk::<10>()? else {
        return None;
    };
    if flags & 0xe0 != 0 {
        return None;
    }
    if flags & 0x04 != 0 {
        let (length, following) = rest.split_first_chunk::<2>()?;
        rest = following.get(usize::from(u16::from_le_bytes(*length))..)?;
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            let nul = rest.iter().position(|&byte| byte == 0)?;
            rest = rest.get(nul + 1..)?;
        }
    }
    if flags & 0x02 != 0 {
        let (crc, following) = rest.split_first_chunk::<2>()?;
        let header = &input[..input.len() - rest.len()];
        if u16::from_le_bytes(*crc) != crc32_n(header) as u16 {
            return None;
        }
        rest = following;
    }
    Some(rest)
}
