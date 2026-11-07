//! Sole foreign descriptor transfer, before any descriptor can be reused.
use crate::Failure;
use gnunet_service_runtime::Activation;
use gnunet_service_startup::{InheritedMode, InheritedResources, ParentControl};
use std::{
    io,
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
};
pub(super) struct Inherited {
    pub tun: Option<OwnedFd>,
    pub activation: Activation,
    pub parent: Option<ParentControl>,
    pub notice: Option<gnunet_service_startup::ControlNotice>,
}
fn unsigned(mut b: &[u8]) -> Option<u32> {
    while b
        .first()
        .is_some_and(|v| *v == b' ' || (9..=13).contains(v))
    {
        b = &b[1..];
    }
    let neg = b.first() == Some(&b'-');
    if neg || b.first() == Some(&b'+') {
        b = &b[1..];
    }
    if b.is_empty() {
        return None;
    }
    let mut n = 0u32;
    for c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u32::from(*c - b'0'))?;
    }
    Some(if neg { 0u32.wrapping_sub(n) } else { n })
}
fn control(mut b: &[u8]) -> Option<u32> {
    while b
        .first()
        .is_some_and(|v| *v == b' ' || (9..=13).contains(v))
    {
        b = &b[1..];
    }
    let neg = b.first() == Some(&b'-');
    if neg || b.first() == Some(&b'+') {
        b = &b[1..];
    }
    if b.len() >= 3 && b[0] == b'0' && matches!(b[1], b'x' | b'X') && b[2].is_ascii_hexdigit() {
        b = &b[2..];
    }
    let mut n = 0u64;
    let mut seen = false;
    for c in b {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        seen = true;
        n = n.checked_mul(16)?.checked_add(u64::from(v))?;
    }
    if !seen {
        return None;
    }
    let n = if neg { 0u64.wrapping_sub(n) } else { n };
    (n < libc::FD_SETSIZE as u64).then_some(n as u32)
}
#[expect(
    unsafe_code,
    reason = "The initial single-threaded process transfers one explicitly parent-owned FD and the shared startup descriptors exactly once"
)]
pub(super) fn capture() -> Result<Inherited, Failure> {
    let hint = std::env::var_os("GNUNET_VPN_TUN_FD");
    let raw = hint
        .as_ref()
        .map(|s| {
            unsigned(s.as_bytes())
                .filter(|n| *n >= 3 && *n <= i32::MAX as u32)
                .ok_or("GNUNET_VPN_TUN_FD must be an exclusively transferred open decimal fd >=3")
        })
        .transpose()?;
    if let Some(raw) = raw {
        if std::env::var_os("LISTEN_FDNAMES").is_some_and(|s| {
            s.as_bytes()
                .split(|c| *c == b':')
                .any(|b| unsigned(b) == Some(raw))
        }) || std::env::var_os("GNUNET_OS_CONTROL_PIPE")
            .is_some_and(|s| control(s.as_bytes()) == Some(raw))
        {
            return Err("preopened TUN aliases a shared startup descriptor".into());
        }
        // SAFETY: F_GETFD only reads integer descriptor state. No other thread,
        // Rust FD owner or descriptor allocation exists yet.
        if unsafe { libc::fcntl(raw as i32, libc::F_GETFD) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    // SAFETY: this function is the first operation in main; hints designate
    // exclusively parent-transferred descriptors and aliases were excluded.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let tun = raw
        .map(|fd| {
            // SAFETY: validated open, stable, foreign-owned FD; startup capture did
            // not adopt it, and this creates its only Rust owner.
            let owned = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            // SAFETY: F_SETFD takes an integer flag and this original FD is owned.
            if unsafe { libc::fcntl(fd as i32, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(owned)
        })
        .transpose()?;
    // SAFETY: still initial single-threaded startup, consuming only our hint.
    unsafe { std::env::remove_var("GNUNET_VPN_TUN_FD") };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("wrong VPN startup descriptor route".into());
        }
    };
    Ok(Inherited {
        tun,
        activation,
        parent: captured.parent_control,
        notice: captured.control_notice,
    })
}
