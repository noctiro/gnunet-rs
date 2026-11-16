//! Numeric-only native Windows address display; no DNS, sockets or interfaces.
#![cfg(windows)]
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "An independent Rust IP parser checks the native byte order and numeric output for IPv6 and embedded IPv4 forms"
)]
fn numeric_ipv6_keeps_exact_address_bytes_without_name_resolution()
-> Result<(), Box<dyn std::error::Error>> {
    let mapped = Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped();
    for address in [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        mapped,
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc000, 0x0201),
    ] {
        let text = gnunet_native::ipv6_text(address.octets())?;
        assert_eq!(std::str::from_utf8(&text)?.parse::<Ipv6Addr>()?, address);
    }
    assert_eq!(
        gnunet_native::ipv6_text(Ipv6Addr::LOCALHOST.octets())?,
        b"::1"
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The native Windows SDK sockaddr_un bounds remain separate from Unix libc typedef assumptions"
)]
fn native_unix_address_display_uses_windows_layout() -> io::Result<()> {
    let layout = gnunet_native::network::unix_address_layout();
    assert_eq!(layout.family_bytes, 2);
    assert_eq!(layout.sockaddr_bytes, 110);
    Ok(())
}
