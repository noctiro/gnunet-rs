//! Small native boundaries used by official host APIs.
//!
//! Hostname and socket boundaries use native Unix or Windows APIs. Address and
//! interface snapshots retain their documented platform availability. Locale
//! C-byte contexts are portable; unsupported locale ABIs fail explicitly.
//! This crate never calls libgnunet.

/// Owned explicit locale snapshots and replaceable comparison contexts.
pub mod locale;

/// Native Windows process-token and account SID observations.
#[cfg(windows)]
pub mod identity;

/// Owned native address results with explicit family/type/protocol/flags.
#[cfg(unix)]
pub mod addresses;

/// Native initialization policy for uniquely owned accepted streams.
#[cfg(any(unix, windows))]
pub mod network;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{hostname, hostname_max_length, local_fqdn};

/// Bounded native interface snapshots.
#[cfg(unix)]
pub mod interfaces;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
mod nat_helper_io;

/// Raw NAT-helper descriptors and permanent credential boundary.
#[cfg(target_os = "linux")]
pub mod nat_helper;

/// Darwin/modern FreeBSD raw NAT-helper descriptors and credential boundary.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[path = "nat_helper_bsd.rs"]
pub mod nat_helper;

/// No-replacement publication of an already prepared private directory.
#[cfg(target_os = "macos")]
pub mod directory;

#[cfg(any(unix, windows))]
mod error;
#[cfg(any(unix, windows))]
pub use error::NativeError;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{hostname, hostname_max_length, local_fqdn};
