//! Independent literal machine-file and lookup-name fixtures; no file/network I/O.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Literal source-profile tests assert exact raw bytes and boundaries."
)]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use gnunet_resolver_service_core::{
    files::{HostsFile, ResolverField, ResolverFile},
    lookup::{Name, expand, reverse_name},
};
use gnunet_types::Error;
#[test]
fn resolver_exact_prefix_suffix_first_search_and_final_line_rules() {
    let bytes=b" nameserver 1.1.1.1\nnameserver\t2.2.2.2\nNAMESERVER 3.3.3.3\nsearch first two #unchanged\nsearch ignored\nnameserver 127.0.0.1 #notstripped\nnameserver ::1\r\nnameserver 127.0.0.2";
    assert_eq!(
        ResolverFile::new(bytes).collect::<Vec<_>>(),
        vec![
            ResolverField::Search(b"first two #unchanged"),
            ResolverField::NameServer(b"127.0.0.1 #notstripped"),
            ResolverField::NameServer(b"::1\r")
        ]
    );
    assert_eq!(
        ResolverFile::new(b"search \nsearch later\n").collect::<Vec<_>>(),
        vec![ResolverField::Search(b"")]
    );
}
#[test]
fn embedded_nul_stops_strchr_line_scanning_without_reading_beyond_input() {
    assert_eq!(
        ResolverFile::new(b"nameserver 127.0.0.1\nnameserver ::1\0\nnameserver 127.0.0.2\n")
            .collect::<Vec<_>>(),
        vec![ResolverField::NameServer(b"127.0.0.1")]
    );
    assert_eq!(
        HostsFile::new(b"127.0.0.1 first\n::1 no\0\n127.0.0.2 later\n")
            .map(|h| h.alias)
            .collect::<Vec<_>>(),
        vec![b"first".as_slice()]
    );
}
#[test]
fn hosts_last_hash_raw_alias_cr_and_only_space_tab_tokenization() {
    let bytes=b" \t127.0.0.1 a A #first middle #last ignored\n::1 a\r\ninvalid bad\n127.0.0.2 finalignored";
    let hosts = HostsFile::new(bytes).collect::<Vec<_>>();
    assert_eq!(
        hosts.iter().map(|h| h.alias).collect::<Vec<_>>(),
        vec![b"a".as_slice(), b"A", b"#first", b"middle", b"a\r"]
    );
    assert_eq!(hosts[0].address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(hosts[4].address, IpAddr::V6(Ipv6Addr::LOCALHOST));
}
#[test]
fn original_native_prefix_and_exact_search_limits() -> Result<(), Error> {
    assert_eq!(
        Name::<255>::from_c_prefix(b"seen\0ignored")?.bytes(),
        b"seen"
    );
    assert_eq!(
        expand::<255>(b"single", Some(b"two domains"))?.bytes(),
        b"single.two domains"
    );
    assert_eq!(
        expand::<255>(b"dotted.name", Some(b"suffix"))?.bytes(),
        b"dotted.name"
    );
    assert_eq!(expand::<255>(b"x", Some(&[b's'; 252]))?.bytes().len(), 254);
    assert_eq!(expand::<255>(b"x", Some(&[b's'; 253]))?.bytes(), b"x");
    assert_eq!(expand::<255>(&[b'x'; 255], None), Err(Error::TooLarge));
    assert_eq!(expand::<8>(b"name", Some(b"suffix")), Err(Error::Capacity));
    Ok(())
}
#[test]
fn reverse_v4_octet_and_v6_nibble_order_with_atomic_output_refusal() -> Result<(), Error> {
    let mut out = [0xa5; 80];
    let n = reverse_name(IpAddr::V4(Ipv4Addr::new(1, 20, 100, 255)), &mut out)?;
    assert_eq!(&out[..n], b"255.100.20.1.in-addr.arpa");
    let n = reverse_name(IpAddr::V6(Ipv6Addr::LOCALHOST), &mut out)?;
    assert_eq!(
        &out[..n],
        b"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
    );
    let mut short = [0xa5; 8];
    assert_eq!(
        reverse_name(IpAddr::V6(Ipv6Addr::LOCALHOST), &mut short),
        Err(Error::Capacity)
    );
    assert_eq!(short, [0xa5; 8]);
    Ok(())
}

#[test]
fn leading_c_vertical_tab_is_whitespace_even_though_not_rust_ascii_whitespace() {
    let hosts = HostsFile::new(b"\x0b127.0.0.1 vertical\n").collect::<Vec<_>>();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].alias, b"vertical");
}
