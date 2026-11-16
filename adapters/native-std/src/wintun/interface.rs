//! LUID-selected native interface observations and explicit administration.
use super::{Adapter, Guid, InterfaceRetirement, OwnedAdapter, Owners, check};
use std::{cell::Cell, ffi::OsString, io, os::windows::ffi::OsStringExt, rc::Rc};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::{AF_INET, AF_INET6},
};

/// Exact native IP family for interface settings and readiness observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}
impl Family {
    pub(super) const fn native(self) -> u16 {
        match self {
            Self::V4 => AF_INET,
            Self::V6 => AF_INET6,
        }
    }
}
struct Identity {
    alive: Cell<bool>,
    observed: crate::interfaces::Identity,
}
/// Source-bound native administration without retaining the adapter or provider.
/// Only an actual qualified adapter creates this port. Its original GUID/LUID/
/// index are rechecked for each call; retirement is permanent across clones.
#[derive(Clone)]
pub struct InterfacePort(Rc<Identity>);
impl InterfacePort {
    /// Captured original identity, including after physical interface loss.
    /// This metadata grants no liveness, replacement or removal authority.
    pub fn identity(&self) -> &crate::interfaces::Identity {
        &self.0.observed
    }
    pub(super) fn retire(&self) {
        self.0.alive.set(false);
    }
    pub(super) fn luid(&self) -> u64 {
        self.0.observed.luid()
    }
}
/// Native observation of the original adapter. Display names never select a
/// later administrative request and do not grant physical ownership.
#[derive(Clone)]
pub struct Interface {
    /// Original native network compartment; ports reject later thread changes.
    pub compartment: u32,
    /// Original qualified adapter LUID.
    pub luid: u64,
    /// Current index, matched against the original qualification.
    pub index: u32,
    /// Original kernel interface GUID.
    pub guid: Guid,
    /// Actual native display alias, without lossy decoding.
    pub alias: OsString,
    /// Actual interface MTU observation.
    pub mtu: u32,
    /// Original native NET_IF_ADMIN_STATUS value.
    pub admin_status: i32,
    /// Original native IF_OPER_STATUS value.
    pub operational_status: i32,
}
impl Interface {
    /// Actual administrative state only; no operational/address readiness claim.
    pub fn administratively_up(&self) -> bool {
        self.admin_status == MIB_IF_ADMIN_STATUS_UP as i32
    }
}
impl std::fmt::Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("luid", &self.luid)
            .field("index", &self.index)
            .field("alias", &self.alias)
            .field("mtu", &self.mtu)
            .field("admin_status", &self.admin_status)
            .field("operational_status", &self.operational_status)
            .finish_non_exhaustive()
    }
}
/// Actual family-specific native settings, without route/address usability claims.
#[derive(Clone, Copy, Debug)]
pub struct IpInterface {
    /// Queried family.
    pub family: Family,
    /// Actual IP-layer MTU.
    pub mtu: u32,
    /// Interface metric, separate from each route's metric offset.
    pub metric: u32,
    /// Actual native connected flag.
    pub connected: bool,
    /// Actual configured DAD transmission count.
    pub dad_transmits: u32,
}
impl Adapter {
    #[expect(
        unsafe_code,
        reason = "The original Wintun handle/DLL stay owned while the trusted export initializes one SDK LUID record"
    )]
    pub(super) fn qualify(native: OwnedAdapter) -> io::Result<Self> {
        let raw = native.raw;
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: original live adapter and exact writable SDK union storage.
        unsafe { (native.driver.0.luid)(raw.as_ptr(), &mut luid) };
        // SAFETY: Value is the full initialized scalar representation.
        let luid = unsafe { luid.Value };
        if luid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero Wintun interface LUID",
            ));
        }
        let observed = crate::interfaces::Identity::from_luid(luid)?;
        let identity = InterfacePort(Rc::new(Identity {
            alive: Cell::new(true),
            observed,
        }));
        Ok(Self {
            retirement: InterfaceRetirement(identity.clone()),
            owners: Owners::new(native),
            next_session: super::SessionKind::First,
            identity,
        })
    }
}
impl InterfacePort {
    pub(super) fn row(&self) -> io::Result<MIB_IF_ROW2> {
        if !self.0.alive.get() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original Wintun adapter retired",
            ));
        }
        self.0.observed.row()
    }
    /// Query the original GUID/LUID/index and current native interface metadata.
    pub fn interface(&self) -> io::Result<Interface> {
        let row = self.row()?;
        let end = row
            .Alias
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unterminated native interface alias",
                )
            })?;
        Ok(Interface {
            compartment: self.0.observed.compartment(),
            luid: self.0.observed.luid(),
            index: row.InterfaceIndex,
            guid: row.InterfaceGuid,
            alias: OsString::from_wide(&row.Alias[..end]),
            mtu: row.Mtu,
            admin_status: row.AdminStatus,
            operational_status: row.OperStatus,
        })
    }
    #[expect(
        unsafe_code,
        reason = "One initialized SDK IP-interface row is selected by the original qualified LUID; Get fills only that row"
    )]
    fn ip_row(&self, family: Family) -> io::Result<MIB_IPINTERFACE_ROW> {
        self.row()?;
        let mut row = MIB_IPINTERFACE_ROW {
            Family: family.native(),
            InterfaceLuid: NET_LUID_LH {
                Value: self.0.observed.luid(),
            },
            ..Default::default()
        };
        // SAFETY: exact initialized native row with family and original LUID.
        check(unsafe { GetIpInterfaceEntry(&mut row) })?;
        Ok(row)
    }
    /// Query family-specific settings on the original interface.
    pub fn ip_interface(&self, family: Family) -> io::Result<IpInterface> {
        let row = self.ip_row(family)?;
        Ok(IpInterface {
            family,
            mtu: row.NlMtu,
            metric: row.Metric,
            connected: row.Connected,
            dad_transmits: row.DadTransmits,
        })
    }
    /// Change only the selected family's MTU on the original interface. The
    /// caller authorizes and serializes interface administration. Other settings
    /// are read/preserved; IPv4 SitePrefixLength follows the native API contract.
    #[expect(
        unsafe_code,
        reason = "Set receives the same initialized original-interface row after changing only MTU and the documented IPv4 SitePrefixLength field"
    )]
    pub fn set_mtu(&self, family: Family, mtu: u32) -> io::Result<()> {
        if mtu == 0 || mtu > super::MAX_PACKET_BYTES as u32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut row = self.ip_row(family)?;
        row.NlMtu = mtu;
        if family == Family::V4 {
            row.SitePrefixLength = 0;
        }
        // SAFETY: live exact row; caller excludes concurrent administration.
        check(unsafe { SetIpInterfaceEntry(&mut row) })
    }
    /// Request native administrative up/down after checking the original
    /// GUID/LUID/index. This is not operational-link or address readiness.
    /// Caller excludes concurrent destruction/replacement across the native call.
    #[expect(
        unsafe_code,
        reason = "SetIfEntry borrows one initialized SDK row containing the just-qualified original index and explicit administrative status"
    )]
    pub fn set_link_up(&self, up: bool) -> io::Result<()> {
        let actual = self.row()?;
        let row = MIB_IFROW {
            dwIndex: actual.InterfaceIndex,
            dwAdminStatus: if up {
                MIB_IF_ADMIN_STATUS_UP
            } else {
                MIB_IF_ADMIN_STATUS_DOWN
            },
            ..Default::default()
        };
        // SAFETY: exact native record and original index; administration excluded.
        check(unsafe { SetIfEntry(&row) })
    }
}
