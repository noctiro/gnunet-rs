//! Actual native numeric-only calls; no ordinary hostname or external DNS query.
#![expect(
    clippy::expect_used,
    reason = "Finite numeric native calls must succeed before inspecting the actual owned result"
)]
use gnunet_native::addresses::{Error, Hints, resolve};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
#[test]
fn actual_native_ipv4_uses_exact_arm_hints_and_null_service_port() {
    let hints = Hints::arm(true);
    assert_eq!(hints.family, libc::AF_INET);
    assert_eq!(hints.socket_type, 0);
    assert_eq!(hints.protocol, libc::IPPROTO_TCP);
    assert_eq!(hints.flags, 0);
    let addresses = resolve(OsStr::new("127.0.0.1"), hints, 64).expect("actual numeric IPv4");
    assert!(!addresses.is_empty());
    assert!(addresses.iter().all(|a| a.family == libc::AF_INET
        && a.address.is_ipv4()
        && a.address.port() == 0
        && a.address.ip().is_loopback()
        && (a.protocol == 0 || a.protocol == libc::IPPROTO_TCP)
        && (a.socket_type == 0 || a.socket_type == libc::SOCK_STREAM)));
}
#[test]
fn actual_native_family_refusal_does_not_resolve_unspecified_then_filter() {
    assert!(matches!(
        resolve(OsStr::new("::1"), Hints::arm(true), 64),
        Err(Error::Resolution { .. })
    ));
    let addresses = resolve(OsStr::new("::1"), Hints::arm(false), 64).expect("actual IPv6 numeric");
    assert!(addresses.iter().all(|a| a.family == libc::AF_INET6
        && a.address.is_ipv6()
        && a.address.ip().is_loopback()
        && a.address.port() == 0));
}
#[test]
fn raw_invalid_bytes_and_nul_are_classified_without_unicode_rewrite() {
    let numeric = Hints {
        flags: libc::AI_NUMERICHOST,
        ..Hints::arm(false)
    };
    assert!(matches!(
        resolve(OsStr::from_bytes(&[0xFF, 0xFE]), numeric, 64),
        Err(Error::Resolution { .. })
    ));
    assert!(
        matches!(resolve(OsStr::from_bytes(b"127.0.0.1\0tail"),numeric,64),Err(Error::Io(e)) if e.kind()==std::io::ErrorKind::InvalidInput)
    );
    assert!(matches!(
        resolve(OsStr::new("127.0.0.1"), numeric, 0),
        Err(Error::Capacity)
    ));
}
