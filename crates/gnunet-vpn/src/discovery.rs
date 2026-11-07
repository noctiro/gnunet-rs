//! Official byte strings used to discover Internet exits through REGEX.
//! These routines build search terms only; they perform no lookup, grant no
//! peer eligibility and do not substitute configured peers for actual results.
/// Official exit-policy parsing and bounded REGEX expression generation.
pub mod policy;
use crate::Address;
use gnunet_types::Error;

/// Official GNUNET_APPLICATION_TYPE_EXIT_REGEX_PREFIX, including its final dash.
pub const EXIT_PREFIX: &[u8] = b"GNUNET-VPN-VER-0001-";
/// Complete IPv4 exit-search byte count, without its C NUL terminator.
pub const IPV4_SEARCH_LEN: usize = EXIT_PREFIX.len() + 15;
/// Complete IPv6 exit-search byte count, without its C NUL terminator.
pub const IPV6_SEARCH_LEN: usize = EXIT_PREFIX.len() + 39;

/// Required bytes for an official full exit search term, excluding final NUL.
#[must_use]
pub const fn exit_search_len(address: Address) -> usize {
    match address {
        Address::V4(_) => IPV4_SEARCH_LEN,
        Address::V6(_) => IPV6_SEARCH_LEN,
    }
}

/// Build exactly the official VPN's prefix plus `GNUNET_REGEX_ipv[46]toregexsearch`
/// output. Port is host-order semantic input; the string contains four uppercase
/// hex digits followed by network-address hex. The official query has no protocol
/// selector. Port zero remains representable, including the ICMP discovery path.
/// Output has no terminating NUL; REGEX SEARCH encoding adds that wire byte.
/// Capacity failure leaves the destination unchanged.
pub fn exit_search(address: Address, port: u16, output: &mut [u8]) -> Result<usize, Error> {
    let size = exit_search_len(address);
    if output.len() < size {
        return Err(Error::Capacity);
    }
    output[..EXIT_PREFIX.len()].copy_from_slice(EXIT_PREFIX);
    let at = EXIT_PREFIX.len();
    output[at] = match address {
        Address::V4(_) => b'4',
        Address::V6(_) => b'6',
    };
    output[at + 1] = b'-';
    hex(&port.to_be_bytes(), &mut output[at + 2..at + 6]);
    output[at + 6] = b'-';
    hex(address.bytes(), &mut output[at + 7..size]);
    Ok(size)
}
fn hex(bytes: &[u8], output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (byte, pair) in bytes.iter().zip(output.as_chunks_mut::<2>().0.iter_mut()) {
        pair[0] = HEX[usize::from(byte >> 4)];
        pair[1] = HEX[usize::from(byte & 15)];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_wire::official::{
        RelativeTime,
        regex::{Request, SearchResult, StringBytes},
    };

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "One protocol model asserts official byte vectors, C-string validation and borrowed result paths"
    )]
    fn official_regex_layouts_paths_c_strings_and_exit_searches() -> Result<(), Error> {
        let mut buffer = [0; 256];
        let n = exit_search(Address::V4([192, 1, 2, 3]), 2086, &mut buffer)?;
        assert_eq!(&buffer[..n], b"GNUNET-VPN-VER-0001-4-0826-C0010203");
        let n = exit_search(
            Address::V6([0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            8080,
            &mut buffer,
        )?;
        assert_eq!(
            &buffer[..n],
            b"GNUNET-VPN-VER-0001-6-1F90-FFFF0000000000000000000000000001"
        );
        let mut small = [0xa5; 16];
        assert_eq!(
            exit_search(Address::V4([0; 4]), 0, &mut small),
            Err(Error::Capacity)
        );
        assert_eq!(small, [0xa5; 16]);

        let announce = Request::Announce {
            compression: 0x1234,
            reserved: 0,
            refresh_delay: RelativeTime::from_micros(0x0102030405060708),
            regex: StringBytes::new(b"a|b")?,
        };
        let n = announce.encode(&mut buffer)?;
        assert_eq!(
            &buffer[..n],
            &[
                0, 20, 2, 108, 0x12, 0x34, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, b'a', b'|', b'b', 0
            ]
        );
        assert_eq!(Request::decode(&buffer[..n])?, announce);
        buffer[17] = 0;
        assert_eq!(Request::decode(&buffer[..n]), Err(Error::Malformed));
        assert_eq!(announce.encode(&mut small), Err(Error::Capacity));
        assert_eq!(small, [0xa5; 16]);
        let search = Request::Search {
            string: StringBytes::new(b"hello")?,
        };
        let n = search.encode(&mut buffer)?;
        assert_eq!(
            &buffer[..n],
            &[0, 10, 2, 109, b'h', b'e', b'l', b'l', b'o', 0]
        );
        assert_eq!(Request::decode(&buffer[..n])?, search);
        buffer[n - 1] = 1;
        assert!(Request::decode(&buffer[..n]).is_err());
        assert!(StringBytes::new(b"a\0x").is_err());
        let raw = [0, 8, 2, 109, b'a', 0, b'x', 0];
        let decoded = Request::decode(&raw)?;
        let Request::Search { string } = decoded else {
            return Err(Error::Malformed);
        };
        assert!(!string.is_canonical());
        assert_eq!(string.bytes(), b"a");
        assert_eq!(string.wire_bytes(), b"a\0x");
        let n = decoded.encode(&mut buffer)?;
        assert_eq!(&buffer[..n], &raw);

        let get = [[1; 32], [2; 32]];
        let put = [[3; 32]];
        let result = SearchResult {
            peer: [7; 32],
            get_path: &get,
            put_path: &put,
        };
        let n = result.encode(&mut buffer)?;
        assert_eq!(&buffer[..8], &[0, 136, 2, 110, 0, 2, 0, 1]);
        assert_eq!(SearchResult::decode(&buffer[..n])?, result);
        buffer[5] = 3;
        assert_eq!(SearchResult::decode(&buffer[..n]), Err(Error::Malformed));
        Ok(())
    }
}
