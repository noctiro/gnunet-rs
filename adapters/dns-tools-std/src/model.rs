//! One public fixed DNS packet model, prepared source only. No native, crypto,
//! key, entropy, checksum, hash or store operation is present.
use crate::packet::{self, Bounds};
use gnunet_dns::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The single public packet model asserts exact unchanged compression/metadata and bounded failure"
)]
fn original_compressed_wire_equal_width_replacement() -> Result<(), Error> {
    let mut query = vec![
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 1, 1, b'q', 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 0, 0, 1, 0, 1,
    ];
    query.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    let a = query.len();
    query.extend_from_slice(&[192, 0, 2, 9]);
    query.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
    let aaaa = query.len();
    query.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // Additional TXT content is unrelated and must not be parsed/repacked as an address.
    query.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 9, 0, 5, 4, 192, 0, 2, 9]);
    let ip4 = Ipv4Addr::new(198, 51, 100, 7);
    let ip6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xabcd);
    let mut arena = vec![0; packet::ARENA_BYTES];
    let mut output = vec![0x55; packet::MAX_PACKET];
    let (changed, count) = packet::redirect(
        &query,
        Some(ip4),
        Some(ip6),
        &mut arena,
        &mut output,
        Bounds::default(),
    )?;
    let mut expected = query.clone();
    expected[a..a + 4].copy_from_slice(&ip4.octets());
    expected[aaaa..aaaa + 16].copy_from_slice(&ip6.octets());
    assert_eq!(count, 2);
    assert_eq!(changed, expected);
    let before = output.clone();
    assert_eq!(
        packet::redirect(
            &query[..query.len() - 1],
            Some(ip4),
            Some(ip6),
            &mut arena,
            &mut output,
            Bounds::default()
        ),
        Err(Error::Truncated)
    );
    assert_eq!(output, before);
    Ok(())
}
