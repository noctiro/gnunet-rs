//! Actual native numeric-only calls; no ordinary hostname or external DNS query.
#![cfg(any(unix, windows))]
#![expect(
    clippy::expect_used,
    reason = "Finite numeric native calls must succeed before inspecting the actual owned result"
)]
use gnunet_native::addresses::{Error, Families, Hints, resolve};
use std::ffi::OsStr;
#[cfg(unix)]
mod platform {
    pub use libc::{AF_INET, AF_INET6, AI_NUMERICHOST, IPPROTO_TCP, SOCK_STREAM};
    pub fn invalid() -> std::ffi::OsString {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![0xff, 0xfe])
    }
}
#[cfg(windows)]
mod platform {
    use windows_sys::Win32::Networking::WinSock as native;
    pub const AF_INET: i32 = native::AF_INET as i32;
    pub const AF_INET6: i32 = native::AF_INET6 as i32;
    pub use native::{IPPROTO_TCP, SOCK_STREAM};
    pub const AI_NUMERICHOST: i32 = native::AI_NUMERICHOST as i32;
    pub fn invalid() -> std::ffi::OsString {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0xd800])
    }
}
#[test]
fn actual_native_ipv4_uses_exact_arm_hints_and_null_service_port() {
    let hints = Hints::arm(Families::Ipv4Only);
    assert_eq!(hints.family, platform::AF_INET);
    assert_eq!(hints.socket_type, 0);
    assert_eq!(hints.protocol, platform::IPPROTO_TCP);
    assert_eq!(hints.flags, 0);
    let addresses = resolve(OsStr::new("127.0.0.1"), hints, 64).expect("actual numeric IPv4");
    assert!(!addresses.is_empty());
    assert!(addresses.iter().all(|a| a.family == platform::AF_INET
        && a.address.is_ipv4()
        && a.address.port() == 0
        && a.address.ip().is_loopback()
        && (a.protocol == 0 || a.protocol == platform::IPPROTO_TCP)
        && (a.socket_type == 0 || a.socket_type == platform::SOCK_STREAM)));
}
#[test]
fn actual_native_family_refusal_does_not_resolve_unspecified_then_filter() {
    assert!(matches!(
        resolve(OsStr::new("::1"), Hints::arm(Families::Ipv4Only), 64),
        Err(Error::Resolution { .. })
    ));
    let addresses =
        resolve(OsStr::new("::1"), Hints::arm(Families::Any), 64).expect("actual IPv6 numeric");
    assert!(addresses.iter().all(|a| a.family == platform::AF_INET6
        && a.address.is_ipv6()
        && a.address.ip().is_loopback()
        && a.address.port() == 0));
}
#[test]
fn raw_invalid_bytes_and_nul_are_classified_without_unicode_rewrite() {
    let numeric = Hints {
        flags: platform::AI_NUMERICHOST,
        ..Hints::arm(Families::Any)
    };
    assert!(matches!(
        resolve(&platform::invalid(), numeric, 64),
        Err(Error::Resolution { .. })
    ));
    assert!(
        matches!(resolve(OsStr::new("127.0.0.1\0tail"),numeric,64),Err(Error::Io(e)) if e.kind()==std::io::ErrorKind::InvalidInput)
    );
    assert!(matches!(
        resolve(OsStr::new("127.0.0.1"), numeric, 0),
        Err(Error::Capacity)
    ));
}
