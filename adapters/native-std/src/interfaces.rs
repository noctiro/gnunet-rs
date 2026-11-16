//! Actual owned native interface snapshots with finite metadata/address limits.
//! No libgnunet, shell command, DNS, route mutation or background monitor.
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::snapshot;
#[cfg(windows)]
pub use windows::snapshot;
#[cfg(windows)]
mod identity;
#[cfg(any(windows, test))]
mod identity_value;
#[cfg(all(test, unix))]
pub(crate) use identity_value::Identity;
#[cfg(windows)]
mod rename;
#[cfg(windows)]
mod table;
#[cfg(windows)]
pub use identity::Identity;
#[cfg(windows)]
mod retirement;
#[cfg(windows)]
pub(crate) use identity::compartment;
#[cfg(windows)]
pub(crate) use retirement::require_vacant;
#[cfg(windows)]
pub use retirement::{InterfacePresence, RetiredScope, RetirementLimits};
#[cfg(all(test, unix))]
#[path = "interfaces/retirement/selection.rs"]
mod retirement_selection_model;
/// Actual native interface state, keeping platform flag words distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceState {
    /// Original POSIX IFF_* flags.
    #[cfg(unix)]
    UnixFlags(u32),
    /// Original Windows adapter facts; flag bits are not interpreted as POSIX.
    #[cfg(windows)]
    Windows {
        /// Original adapter flags.
        flags: u32,
        /// Native IF_OPER_STATUS value.
        oper_status: i32,
        /// Native NET_IF_ACCESS_TYPE from GetIfEntry2.
        access_type: i32,
        /// Native IANA interface type.
        if_type: u32,
        /// Native per-address duplicate-address-detection state.
        dad_state: i32,
    },
}
/// Explicit snapshot limits; exceeding a limit fails the whole snapshot instead
/// of silently turning an incomplete scan into address removals.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum native linked-list nodes examined, including non-IP entries.
    pub nodes: usize,
    /// Maximum retained IP address rows.
    pub addresses: usize,
    /// Maximum bytes in one native interface name.
    pub name_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            nodes: 4096,
            addresses: 1024,
            name_bytes: 256,
        }
    }
}
/// Actual kernel-provided interface address. Scope/flow/netmask are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceAddress {
    /// Bounded original native interface name, without NUL.
    pub name: Vec<u8>,
    /// Actual native interface index, or0 if unavailable.
    pub index: u32,
    /// Original native interface state.
    pub state: InterfaceState,
    /// Actual interface Internet address.
    pub address: SocketAddr,
    /// Actual netmask when supplied by getifaddrs.
    pub netmask: Option<IpAddr>,
}
impl InterfaceAddress {
    /// Native up-state observation. No remote connectivity is inferred.
    pub fn is_up(&self) -> bool {
        match self.state {
            #[cfg(unix)]
            InterfaceState::UnixFlags(flags) => flags & (libc::IFF_UP as u32) != 0,
            #[cfg(windows)]
            InterfaceState::Windows { oper_status, .. } => {
                oper_status == windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp
            }
        }
    }
    /// Whether captured state permits this address as a unicast source.
    /// Windows additionally requires preferred/deprecated DAD state. POSIX
    /// getifaddrs supplies interface flags but no portable per-address DAD state.
    pub fn is_usable(&self) -> bool {
        if !self.is_up() {
            return false;
        }
        match self.state {
            #[cfg(unix)]
            InterfaceState::UnixFlags(_) => true,
            #[cfg(windows)]
            InterfaceState::Windows { dad_state, .. } => matches!(
                dad_state,
                windows_sys::Win32::Networking::WinSock::IpDadStatePreferred
                    | windows_sys::Win32::Networking::WinSock::IpDadStateDeprecated
            ),
        }
    }
    /// Whether this native interface supports IPv4 broadcast addressing.
    pub fn supports_ipv4_broadcast(&self) -> bool {
        match self.state {
            #[cfg(unix)]
            InterfaceState::UnixFlags(flags) => flags & (libc::IFF_BROADCAST as u32) != 0,
            #[cfg(windows)]
            InterfaceState::Windows { access_type, .. } => {
                access_type == windows_sys::Win32::NetworkManagement::Ndis::NET_IF_ACCESS_BROADCAST
            }
        }
    }
    /// Actual native loopback-interface classification.
    pub fn is_loopback(&self) -> bool {
        match self.state {
            #[cfg(unix)]
            InterfaceState::UnixFlags(flags) => flags & (libc::IFF_LOOPBACK as u32) != 0,
            #[cfg(windows)]
            InterfaceState::Windows { if_type, .. } => {
                if_type
                    == windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK
            }
        }
    }
}
/// Classify an Internet destination against a complete caller-owned interface
/// snapshot, using official NT values: loopback1, local-prefix2, otherwise WAN3.
/// This does not enumerate interfaces, read a clock, authenticate a peer, infer
/// wireless hardware or certify reachability. A caller whose snapshot failed
/// must report that failure instead of supplying an invented empty snapshot.
pub fn classify(rows: &[InterfaceAddress], remote: SocketAddr) -> u32 {
    if remote.ip().is_loopback() {
        return 1;
    }
    let local = rows.iter().any(|row| {
        if row.address.ip().is_loopback() {
            return false;
        }
        match (remote.ip(), row.address.ip(), row.netmask) {
            (IpAddr::V4(remote), IpAddr::V4(local), Some(IpAddr::V4(mask))) => remote
                .octets()
                .into_iter()
                .zip(local.octets())
                .zip(mask.octets())
                .all(|((r, l), m)| r & m == l & m),
            (IpAddr::V6(remote), IpAddr::V6(local), Some(IpAddr::V6(mask))) => remote
                .octets()
                .into_iter()
                .zip(local.octets())
                .zip(mask.octets())
                .all(|((r, l), m)| r & m == l & m),
            _ => false,
        }
    });
    if local { 2 } else { 3 }
}
