//! Small native boundaries used by official host APIs.
//!
//! Hostname and socket boundaries use native Unix or Windows APIs. Address and
//! interface snapshots retain their documented platform availability. Locale
//! readers use owned POSIX or Windows UCRT backends and shared C-byte contexts.
//! Unsupported native locale ABIs fail explicitly.
//! This crate never calls libgnunet.

/// Owned explicit locale snapshots and replaceable comparison contexts.
pub mod locale;

/// Lossless local command/path bytes with explicit Unix/Windows decoding.
pub mod os_bytes;

/// Platform cryptographic randomness with complete-buffer failure cleanup.
pub mod entropy;

/// Reentrant native Unix account and group database queries.
#[cfg(unix)]
pub mod accounts;

/// Original directory owners and relative ordinary-file operations.
#[cfg(any(unix, windows))]
pub mod filesystem;

mod directory_sync;
pub use directory_sync::DirectorySync;

/// Native Windows process-token and account SID observations.
#[cfg(windows)]
pub mod identity;

/// Native Windows profile paths, directory access and private file publication.
#[cfg(windows)]
pub mod paths;

/// Original standard output routes and Windows early-startup installation.
#[cfg(any(unix, windows))]
pub mod stdio;

/// Caller-trusted native libraries with original references and explicit close.
#[cfg(any(unix, windows))]
pub mod library;

/// Explicit Windows packet interception provider with original I/O loans.
#[cfg(windows)]
pub mod windivert;

/// Original Windows Wintun driver, adapter, session and whole-packet ownership.
#[cfg(windows)]
pub mod wintun;

/// Caller-polled Windows kernel-event waits with original callback retirement.
#[cfg(windows)]
pub mod event_wait;

/// Native Windows calendar conversion and bounded UTF-16 formatting.
#[cfg(windows)]
pub mod calendar;
#[cfg(any(windows, test))]
mod calendar_fields;
#[cfg(all(test, unix))]
#[path = "calendar/model.rs"]
mod calendar_model;
#[cfg(any(windows, test))]
mod calendar_pattern;

#[cfg(windows)]
mod com;
#[cfg(windows)]
mod windows_crt;
#[cfg(windows)]
pub use windows_crt::{CrtErrnoGuard, CrtError};

/// Owned native address results with explicit family/type/protocol/flags.
#[cfg(any(unix, windows))]
pub mod addresses;

/// Native initialization policy for uniquely owned accepted streams.
#[cfg(any(unix, windows))]
pub mod network;

/// Process-native Internet protocol and service name lookup.
#[cfg(any(unix, windows))]
pub mod internet_registry;

/// Borrowed Windows AF_UNIX address and listener-state observations.
#[cfg(windows)]
pub mod local_socket;

/// Windows local endpoint security and original-node filesystem cleanup.
#[cfg(windows)]
pub mod local_path;

/// Native Windows DNS-server configuration snapshots without DNS traffic.
#[cfg(windows)]
pub mod dns;

/// Original Windows interface, address and route subscriptions with coalesced hints.
#[cfg(windows)]
pub mod network_change;

/// Private Windows process-pipe endpoints and kernel peer observations.
#[cfg(windows)]
pub mod pipe;
/// Native Windows process handles, explicit inheritance and kernel exit waits.
#[cfg(windows)]
pub mod process;
/// Unix command inheritance of original file-description leases.
#[cfg(unix)]
#[path = "process/unix.rs"]
pub mod process;
/// One-shot native listener sharing through sealed read-only startup sections.
#[cfg(windows)]
pub mod socket_activation;
#[cfg(any(windows, test))]
mod windows_command_line;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{hostname, hostname_max_length, local_fqdn};

/// Bounded native interface snapshots.
pub mod interfaces;

/// Original macOS DNS proxy UDP flows with bounded callback and buffer ownership.
#[cfg(all(any(target_os = "macos", target_os = "ios"), feature = "dns-proxy"))]
pub mod dns_proxy;

/// Scoped Darwin PF DNS state retirement under an explicit original deadline.
#[cfg(target_os = "macos")]
pub mod pf;

/// Original FreeBSD PF state retirement by exact state and creator IDs.
#[cfg(target_os = "freebsd")]
pub mod pf_freebsd;

/// Original BSD routing-socket notifications for PF interface scope observation.
#[cfg(all(feature = "socket-io", any(target_os = "macos", target_os = "freebsd")))]
pub mod pf_scope;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
mod nat_helper_io;

/// Raw NAT-helper descriptors and permanent credential boundary.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod nat_helper;

/// Linux transparent UDP DNS metadata and exact-source reply sockets.
#[cfg(target_os = "linux")]
pub mod transparent_dns;

#[cfg(any(
    target_os = "linux",
    all(feature = "socket-io", any(target_os = "macos", target_os = "freebsd"))
))]
mod ancillary_abi;

#[cfg(target_os = "linux")]
mod linux_netlink;

/// Linux routing table operations for exact interface routes.
#[cfg(target_os = "linux")]
pub mod linux_routing;

/// Linux network namespace ownership for isolated TESTING topologies.
#[cfg(target_os = "linux")]
pub mod netjail;

/// Darwin/modern FreeBSD raw NAT-helper descriptors and credential boundary.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[path = "nat_helper_bsd.rs"]
pub mod nat_helper;

/// Windows helper output lifetimes and native stop ownership.
#[cfg(windows)]
#[path = "nat_helper_windows/mod.rs"]
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
pub use windows::{hostname, hostname_max_length, ipv6_text, local_fqdn};

#[cfg(all(test, unix))]
#[path = "wintun/owners.rs"]
mod wintun_owners_model;

#[cfg(all(test, unix))]
#[path = "windivert/observations.rs"]
mod windivert_observations_model;
