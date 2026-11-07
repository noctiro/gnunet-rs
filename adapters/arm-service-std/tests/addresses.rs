//! Numeric-only source endpoint collection and complete capacity boundaries.
#![expect(
    clippy::expect_used,
    reason = "Finite local configuration fixtures require setup success"
)]
use gnunet_arm_service_host::addresses::{Address, Addresses, Diagnostic, Error};
use gnunet_config::{Configuration, Environment};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
struct Env;
impl Environment for Env {
    fn variable(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(std::env::temp_dir())
    }
}
fn put(c: &mut Configuration, key: &[u8], value: &[u8]) {
    c.set_value(b"svc", key, Some(value)).expect("config");
}
fn v4() -> Configuration {
    let mut c = Configuration::default();
    put(&mut c, b"DISABLEV6", b"YES");
    c
}
#[test]
fn malformed_port_is_zero_but_range_and_boolean_are_fatal() {
    let mut c = v4();
    put(
        &mut c,
        b"UNIXPATH",
        b"/private/tmp/addresses-only-never-bound",
    );
    put(&mut c, b"PORT", b"not-port");
    let a = Addresses::from_config(&c, b"svc", &Env, 4).expect("Unix survives bad port");
    assert_eq!(a.diagnostics, vec![Diagnostic::InvalidPort]);
    assert_eq!(a.addresses.len(), 1);
    put(&mut c, b"PORT", b"65536");
    assert!(matches!(
        Addresses::from_config(&c, b"svc", &Env, 4),
        Err(Error::Port)
    ));
    put(&mut c, b"PORT", b"42");
    put(&mut c, b"DISABLEV6", b"maybe");
    assert!(matches!(
        Addresses::from_config(&c, b"svc", &Env, 4),
        Err(Error::Configuration(_))
    ));
}
#[test]
fn native_numeric_input_has_exact_family_protocol_and_source_order() {
    let mut c = v4();
    put(&mut c, b"PORT", b"12345");
    put(&mut c, b"BINDTO", b"127.0.0.1");
    put(
        &mut c,
        b"UNIXPATH",
        b"/private/tmp/addresses-only-never-bound",
    );
    let a = Addresses::from_config(&c, b"svc", &Env, 8).expect("numeric native");
    assert!(
        matches!(&a.addresses[0],Address::Unix(path) if path==std::path::Path::new("/private/tmp/addresses-only-never-bound"))
    );
    assert!(
        a.addresses[1..]
            .iter()
            .all(|a| *a == Address::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 12345))))
    );
    assert!(matches!(
        Addresses::from_config(&c, b"svc", &Env, 1),
        Err(Error::Capacity)
    ));
    put(&mut c, b"BINDTO", b"::1");
    assert!(
        matches!(
            Addresses::from_config(&c, b"svc", &Env, 8),
            Err(Error::Resolution(_))
        ),
        "native AF_INET failure rejects entire list including Unix"
    );
}
#[test]
fn no_endpoint_and_zero_port_do_not_invent_ephemeral_listener() {
    let mut c = v4();
    put(&mut c, b"PORT", b"0");
    assert!(matches!(
        Addresses::from_config(&c, b"svc", &Env, 8),
        Err(Error::NoAddress)
    ));
    put(&mut c, b"PORT", b"34567");
    let a = Addresses::from_config(&c, b"svc", &Env, 8).expect("wildcard v4");
    assert_eq!(
        a.addresses,
        vec![Address::Tcp(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            34567
        )))]
    );
    assert!(matches!(
        Addresses::from_config(&c, b"svc", &Env, 0),
        Err(Error::Capacity)
    ));
}
#[test]
fn unix_only_does_not_resolve_an_irrelevant_bindto() {
    let mut c = v4();
    put(
        &mut c,
        b"UNIXPATH",
        b"/private/tmp/addresses-only-never-bound",
    );
    put(&mut c, b"BINDTO", b"\xff\xfe");
    let a = Addresses::from_config(&c, b"svc", &Env, 1).expect("zero port skips native resolver");
    assert_eq!(a.addresses.len(), 1);
}
