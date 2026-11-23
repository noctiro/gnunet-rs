//! Owned Unix descriptors that stay unchanged through reactor registration.
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

mod sealed {
    pub trait Sealed {}
}

/// An owned descriptor whose shared reference always borrows its original fd.
///
/// Implementations preserve the descriptor through moves and keep it open
/// until the owner is consumed or dropped. Reactor registrations may lend
/// this owner by shared reference without allowing descriptor replacement.
pub trait StableFd: AsFd + AsRawFd + sealed::Sealed {}

impl sealed::Sealed for OwnedFd {}
impl StableFd for OwnedFd {}

#[cfg(all(
    feature = "socket-io",
    any(target_os = "linux", target_os = "freebsd", target_os = "macos")
))]
impl sealed::Sealed for super::LocalDatagram {}
#[cfg(all(
    feature = "socket-io",
    any(target_os = "linux", target_os = "freebsd", target_os = "macos")
))]
impl StableFd for super::LocalDatagram {}

#[cfg(all(feature = "socket-io", any(target_os = "macos", target_os = "freebsd")))]
impl sealed::Sealed for crate::pf_scope::Monitor {}
#[cfg(all(feature = "socket-io", any(target_os = "macos", target_os = "freebsd")))]
impl StableFd for crate::pf_scope::Monitor {}

#[cfg(target_os = "linux")]
impl sealed::Sealed for crate::transparent_dns::Listener {}
#[cfg(target_os = "linux")]
impl StableFd for crate::transparent_dns::Listener {}

#[cfg(target_os = "linux")]
impl sealed::Sealed for crate::transparent_dns::ReplySocket {}
#[cfg(target_os = "linux")]
impl StableFd for crate::transparent_dns::ReplySocket {}

#[cfg(target_os = "linux")]
impl sealed::Sealed for crate::transparent_dns::link::LinkMonitor {}
#[cfg(target_os = "linux")]
impl StableFd for crate::transparent_dns::link::LinkMonitor {}
