#![expect(
    clippy::panic_in_result_fn,
    reason = "One packet model checks real checksums, NAT bytes, TCP options and official ICMP quote semantics"
)]
use crate::packet::{self, ICMP, ICMPV6, Packet, Quoted, TCP, UDP};
use crate::{Address, Family};
use gnunet_types::Error;
#[test]
fn actual_transport_checksums_rewrite_cross_family_and_truncated_quote() -> Result<(), Error> {
    let a = Address::V4([10, 0, 0, 2]);
    let b = Address::V4([10, 0, 0, 3]);
    let mut udp = [0; 11];
    udp[..2].copy_from_slice(&1234u16.to_be_bytes());
    udp[2..4].copy_from_slice(&4321u16.to_be_bytes());
    udp[8..].copy_from_slice(b"odd");
    let mut raw = [0; 128];
    let n = packet::build(a, b, UDP, &udp, &mut raw)?;
    assert_eq!(n, 31);
    let p = Packet::parse(&raw[..n])?;
    p.validate_checksums()?;
    assert_eq!(p.ports()?, (1234, 4321));
    assert_eq!(&p.segment()[4..6], &11u16.to_be_bytes());
    assert_eq!(&p.segment()[8..], b"odd");
    let original = raw;
    let v6a = Address::V6([0x20; 16]);
    let v6b = Address::V6([0x30; 16]);
    assert_eq!(
        packet::rewrite(&mut raw[..n], v6a, v6b, None),
        Err(Error::InvalidInput)
    );
    assert_eq!(raw, original);
    raw[n - 1] ^= 1;
    assert_eq!(
        Packet::parse(&raw[..n])?.validate_checksums(),
        Err(Error::Malformed)
    );
    raw = original;
    packet::rewrite(
        &mut raw[..n],
        Address::V4([172, 16, 0, 1]),
        Address::V4([192, 0, 2, 1]),
        Some((9000, 53)),
    )?;
    let p = Packet::parse(&raw[..n])?;
    p.validate_checksums()?;
    assert_eq!(p.ports()?, (9000, 53));
    udp.copy_from_slice(p.segment());
    let mut six = [0; 128];
    let m = packet::build(v6a, v6b, UDP, &udp, &mut six)?;
    Packet::parse(&six[..m])?.validate_checksums()?;
    assert_eq!(m, 51);
    let mut tcp = [0; 27];
    tcp[..2].copy_from_slice(&4000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    tcp[12] = 0x60;
    tcp[13] = 2;
    tcp[20..24].copy_from_slice(&[1, 1, 1, 0]);
    tcp[24..].copy_from_slice(b"tcp");
    let m = packet::build(v6a, v6b, TCP, &tcp, &mut six)?;
    packet::rewrite(&mut six[..m], v6b, v6a, Some((5000, 80)))?;
    let p = Packet::parse(&six[..m])?;
    p.validate_checksums()?;
    assert_eq!(&p.segment()[20..], &[1, 1, 1, 0, b't', b'c', b'p']);
    let mut q = [0; 64];
    let qn = packet::quote(a, b, TCP, Some((1234, 80)), &mut q)?;
    q[2..4].copy_from_slice(&1200u16.to_be_bytes());
    q[10..12].fill(0);
    let c = packet::checksum(&q[..20]);
    q[10..12].copy_from_slice(&c.to_be_bytes());
    assert!(Packet::parse(&q[..qn]).is_err());
    let quoted = Quoted::parse(&q[..qn])?;
    assert_eq!(
        (
            quoted.source,
            quoted.destination,
            quoted.source_port,
            quoted.destination_port
        ),
        (a, b, 1234, 80)
    );
    assert_eq!(
        packet::quoted_tuple(&q[..qn])?,
        (a, b, TCP, Some((1234, 80)))
    );
    let mut echo = [0; 9];
    echo[0] = 128;
    echo[4..6].copy_from_slice(&42u16.to_be_bytes());
    echo[8] = 7;
    let n = packet::build(v6a, v6b, ICMPV6, &echo, &mut six)?;
    Packet::parse(&six[..n])?.validate_checksums()?;
    let h = packet::translate_icmp_header(
        Family::V6,
        Family::V4,
        echo[..8].try_into().map_err(|_| Error::Truncated)?,
    )?;
    assert_eq!(h[0], 8);
    echo[..8].copy_from_slice(&h);
    let n = packet::build(a, b, ICMP, &echo, &mut raw)?;
    Packet::parse(&raw[..n])?.validate_checksums()?;
    assert_eq!(
        packet::translate_icmp_header(Family::V6, Family::V4, [2, 0, 0, 0, 0, 0, 5, 0]),
        Err(Error::Unsupported)
    );
    assert_eq!(
        packet::translate_icmp_header(Family::V4, Family::V6, [4, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::Unsupported)
    );
    Ok(())
}
