//! Owned byte counterparts of common_logging's temporary string helpers.
//! Two-buffer C variants map to the same reentrant Rust operation; a returned
//! value is never overwritten by a later call on this or another thread.
use crate::logging::base32;
use std::{
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
};
/// GNUNET_b2s: SHA512 arbitrary bytes, then the first eight Crockford characters.
#[must_use]
pub fn bytes_short(bytes: &[u8]) -> Vec<u8> {
    base32(&gnunet_crypto::hash512(bytes))[..8].to_vec()
}
/// GNUNET_h2s/h2s2: first eight characters of the already-computed hash.
#[must_use]
pub fn hash_short(hash: &[u8; 64]) -> Vec<u8> {
    base32(hash)[..8].to_vec()
}
/// GNUNET_h2s_full: complete103-character encoding of a512-bit hash.
#[must_use]
pub fn hash_full(hash: &[u8; 64]) -> Vec<u8> {
    base32(hash)
}
/// GNUNET_p2s/p2s2/e2s/e2s2: hash the complete32-byte public key, then six chars.
#[must_use]
pub fn public_key_short(key: &[u8; 32]) -> Vec<u8> {
    base32(&gnunet_crypto::hash512(key))[..6].to_vec()
}
/// GNUNET_sh2s: first six encoded characters of a256-bit short hash.
#[must_use]
pub fn short_hash_short(hash: &[u8; 32]) -> Vec<u8> {
    base32(hash)[..6].to_vec()
}
/// GNUNET_uuid2s: first six encoded characters of a16-byte UUID.
#[must_use]
pub fn uuid_short(uuid: &[u8; 16]) -> Vec<u8> {
    base32(uuid)[..6].to_vec()
}
/// GNUNET_i2s/i2s2: four characters of the raw peer public key, or literal NULL.
#[must_use]
pub fn peer_short(key: Option<&[u8; 32]>) -> Vec<u8> {
    key.map_or_else(|| b"NULL".to_vec(), |v| base32(v)[..4].to_vec())
}
/// GNUNET_i2s_full: complete52-character raw peer public key encoding. The C
/// pointer must be nonnull; the reference here makes that requirement explicit.
#[must_use]
pub fn peer_full(key: &[u8; 32]) -> Vec<u8> {
    base32(key)
}
/// Safe address view, separate from untrusted native pointer/length validation.
pub enum Address<'a> {
    /// Original null sockaddr pointer.
    Unknown,
    /// Native IPv4 address; valid_size is the exact sockaddr_in length check.
    V4 {
        /// Actual address.
        ip: Ipv4Addr,
        /// Network port converted to host order.
        port: u16,
        /// Native exact struct length validation.
        valid_size: bool,
    },
    /// Native IPv6 address; source ignores flow/scope IDs when printing.
    V6 {
        /// Actual address.
        ip: Ipv6Addr,
        /// Network port converted to host order.
        port: u16,
        /// Native exact struct length validation.
        valid_size: bool,
    },
    /// Full initialized sun_path bytes and original native addrlen. The safe slice
    /// must cover the source's precision; otherwise an explicit error is returned.
    Unix {
        /// Native sun_path region, including any terminator/padding.
        path: &'a [u8],
        /// Original complete native sockaddr length.
        length: usize,
    },
    /// Unrecognized native family.
    Unsupported,
}
/// GNUNET_a2s for the executing libc ABI. No DNS/network or host lookup occurs.
pub fn address(value: Address<'_>) -> Result<Vec<u8>, gnunet_types::Error> {
    use Address::*;
    Ok(match value {
        Unknown => b"unknown address".to_vec(),
        Unsupported => b"invalid address".to_vec(),
        V4 {
            valid_size: false, ..
        } => b"<invalid v4 address>".to_vec(),
        V6 {
            valid_size: false, ..
        } => b"<invalid v6 address>".to_vec(),
        V4 { ip, port, .. } => {
            if port == 0 {
                ip.to_string().into_bytes()
            } else {
                format!("{ip}:{port}").into_bytes()
            }
        }
        V6 { ip, port, .. } => {
            let text = crate::native::ipv6_text(ip.octets())
                .map_err(|_| gnunet_types::Error::Unsupported)?;
            if port == 0 {
                text
            } else {
                let mut output = vec![b'['];
                output.extend_from_slice(&text);
                output.extend_from_slice(b"]:");
                output.extend_from_slice(port.to_string().as_bytes());
                output
            }
        }
        Unix { path, length } => {
            let family = std::mem::size_of::<libc::sa_family_t>();
            if length <= family {
                return Ok(b"<unbound UNIX client>".to_vec());
            }
            let abstract_name = path.first() == Some(&0);
            let offset = usize::from(abstract_name);
            let precision = length
                .checked_sub(family + offset)
                .ok_or(gnunet_types::Error::InvalidInput)?;
            let path = path
                .get(offset..)
                .ok_or(gnunet_types::Error::InvalidInput)?;
            // A C-string terminator may make a larger precision harmless; otherwise the
            // caller must have supplied enough initialized bytes for the whole read.
            let available = path.iter().position(|&v| v == 0).unwrap_or(path.len());
            if precision > path.len() && available == path.len() {
                return Err(gnunet_types::Error::InvalidInput);
            }
            let length = available.min(precision);
            let mut result = Vec::new();
            if abstract_name {
                result.push(b'@');
            }
            result.extend_from_slice(&path[..length]);
            let capacity = (46usize + 8).max(1 + std::mem::size_of::<libc::sockaddr_un>() - family);
            result.truncate(capacity - 1);
            result
        }
    })
}
/// Explicit enabled-NLS address helper. Only the source's two translated labels
/// use the selected backend; native formatting and invalid-size labels retain
/// their original byte behavior. A failed backend never succeeds in English.
pub fn address_translated(
    value: Address<'_>,
    translations: &dyn crate::locale::Translations,
) -> io::Result<Vec<u8>> {
    match value {
        Address::Unknown => translations.gettext(Some(b"gnunet"), b"unknown address"),
        Address::Unsupported => translations.gettext(Some(b"gnunet"), b"invalid address"),
        value => address(value).map_err(io::Error::other),
    }
}
fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
/// GNUNET_hex2b's bounded two-character integer scans. Invalid suffixes stop
/// after prior assignments; inverse writes start at the end of the whole dst.
/// This uses Rust bytes rather than a variadic scanner or unchecked pointer.
pub fn hex_to_bytes(input: &[u8], output: &mut [u8], inverse: bool) -> usize {
    let input = &input[..input.iter().position(|&b| b == 0).unwrap_or(input.len())];
    let mut at = 0;
    let mut count = 0;
    while count < output.len() {
        while input.get(at).is_some_and(|&b| crate::native::whitespace(b)) {
            at += 1;
        }
        let start = at;
        let end = input.len().min(start.saturating_add(2));
        let negative = input.get(at) == Some(&b'-');
        if negative || input.get(at) == Some(&b'+') {
            at += 1;
        }
        let digits = at;
        let mut value = 0u8;
        while at < end {
            let Some(d) = digit(input[at]) else {
                break;
            };
            value = value.wrapping_mul(16).wrapping_add(d);
            at += 1;
        }
        if at == digits {
            break;
        }
        if at < end && input[digits] == b'0' && matches!(input[at], b'x' | b'X') {
            at += 1;
        }
        if negative {
            value = 0u8.wrapping_sub(value);
        }
        let index = if inverse {
            output.len() - 1 - count
        } else {
            count
        };
        output[index] = value;
        count += 1;
    }
    count
}
/// GNUNET_print_bytes with an explicit writer. Fold may be negative as in the C
/// int remainder; in_be reverses byte iteration. Always appends a final newline.
pub fn print_bytes(input: &[u8], fold: i32, in_be: bool, out: &mut impl Write) -> io::Result<()> {
    let period = fold.unsigned_abs() as usize;
    for i in 0..input.len() {
        if i != 0 && period != 0 && i % period == 0 {
            out.write_all(b"\n")?;
        }
        let at = if in_be { input.len() - 1 - i } else { i };
        write!(out, "{:02x}", input[at])?;
    }
    out.write_all(b"\n")
}
/// Explicit fatal operation corresponding to GNUNET_abort_; never used for an
/// ordinary parse/configuration failure and never invoked by candidate tests.
pub fn abort() -> ! {
    std::process::abort()
}

/// Source GNUNET_STRINGS_relative_time_to_string with explicit rounding profile.
/// The output owns its bytes instead of reusing the C thread-local buffer.
#[must_use]
pub fn relative_time(mut value: u64, rounded: bool) -> Vec<u8> {
    if value == u64::MAX {
        return b"forever".to_vec();
    }
    if value == 0 {
        return b"0 ms".to_vec();
    }
    let mut unit = "µs";
    for (divisor, threshold, next) in [
        (1000, 5000, "ms"),
        (1000, 5000, "s"),
        (60, 300, "m"),
        (60, 300, "h"),
        (24, 120, "days"),
    ] {
        if !((rounded && value > threshold) || value.is_multiple_of(divisor)) {
            break;
        }
        value /= divisor;
        unit = next;
    }
    if unit == "days" && value == 1 {
        unit = "day";
    }
    format!("{value} {unit}").into_bytes()
}
