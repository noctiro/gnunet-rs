//! Resolver service name preprocessing, without DNS or native lookup shortcuts.
use core::net::IpAddr;
use gnunet_types::Error;
/// A copied service hostname. Capacity is explicit rather than a private wire limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Name<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Name<N> {
    /// Copy the native C-string prefix; later bytes after an interior NUL have
    /// already passed the service's final-NUL wire check but are not in strdup.
    pub fn from_c_prefix(bytes: &[u8]) -> Result<Self, Error> {
        let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        if len > N {
            return Err(Error::Capacity);
        }
        let mut result = Self { bytes: [0; N], len };
        result.bytes[..len].copy_from_slice(&bytes[..len]);
        Ok(result)
    }
    /// Original owned native name bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
/// Compute the second cache/DNS name after the caller has tried original cache.
/// Match the single entire search suffix, <=253 combined original+suffix bytes,
/// then the source's255-byte formatting capacity (including its final NUL).
/// For unexpanded names >=255, the caller must drop that client as C does.
pub fn expand<const N: usize>(name: &[u8], search: Option<&[u8]>) -> Result<Name<N>, Error> {
    let name_end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    let name = &name[..name_end];
    if let Some(search) = search
        && !name.contains(&b'.')
    {
        let search_end = search.iter().position(|b| *b == 0).unwrap_or(search.len());
        let search = &search[..search_end];
        if name
            .len()
            .checked_add(search.len())
            .is_some_and(|sum| sum <= 253)
        {
            let len = name.len() + search.len() + 1;
            if len > N {
                return Err(Error::Capacity);
            }
            let mut result = Name { bytes: [0; N], len };
            result.bytes[..name.len()].copy_from_slice(name);
            result.bytes[name.len()] = b'.';
            result.bytes[name.len() + 1..len].copy_from_slice(search);
            return Ok(result);
        }
    }
    if name.len() >= 255 {
        return Err(Error::TooLarge);
    }
    Name::from_c_prefix(name)
}
/// Construct the exact native reverse DNS name: reversed octets for V4 or
/// low-nibble then high-nibble of reversed bytes for V6, with no trailing dot.
pub fn reverse_name(address: IpAddr, output: &mut [u8]) -> Result<usize, Error> {
    let mut bytes = [0; 80];
    let mut at = 0;
    match address {
        IpAddr::V4(ip) => {
            for part in ip.octets().into_iter().rev() {
                let mut n = part;
                if n >= 100 {
                    bytes[at] = b'0' + n / 100;
                    at += 1;
                    n %= 100;
                    bytes[at] = b'0' + n / 10;
                    at += 1;
                } else if n >= 10 {
                    bytes[at] = b'0' + n / 10;
                    at += 1;
                }
                bytes[at] = b'0' + n % 10;
                at += 1;
                bytes[at] = b'.';
                at += 1;
            }
            bytes[at..at + 12].copy_from_slice(b"in-addr.arpa");
            at += 12;
        }
        IpAddr::V6(ip) => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for part in ip.octets().into_iter().rev() {
                for nibble in [part & 15, part >> 4] {
                    bytes[at] = HEX[nibble as usize];
                    bytes[at + 1] = b'.';
                    at += 2;
                }
            }
            bytes[at..at + 8].copy_from_slice(b"ip6.arpa");
            at += 8;
        }
    }
    if output.len() < at {
        return Err(Error::Capacity);
    }
    output[..at].copy_from_slice(&bytes[..at]);
    Ok(at)
}
