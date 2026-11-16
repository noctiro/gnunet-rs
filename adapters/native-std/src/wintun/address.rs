//! Explicit original-interface address calls and independent DAD observations.
use super::{InterfacePort, check};
use std::{io, net::IpAddr};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStateDeprecated as DAD_DEPRECATED, IpDadStateDuplicate as DAD_DUPLICATE,
    IpDadStateInvalid as DAD_INVALID, IpDadStatePreferred as DAD_PREFERRED,
    IpDadStateTentative as DAD_TENTATIVE,
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::*,
};
/// Actual native duplicate-address state; successful creation is not readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DadState {
    /// Native invalid state.
    Invalid,
    /// Duplicate-address detection remains pending.
    Tentative,
    /// Native duplicate detection failure.
    Duplicate,
    /// Address is deprecated.
    Deprecated,
    /// Native preferred state observed.
    Preferred,
    /// Preserved unrecognized native value.
    Other(i32),
}
/// One native address snapshot, without a cleanup lease or restart authority.
#[derive(Clone, Copy, Debug)]
pub struct AddressObservation {
    /// Original requested address.
    pub address: IpAddr,
    /// Actual on-link prefix length.
    pub prefix: u8,
    /// Actual native DAD state.
    pub dad: DadState,
    /// Remaining valid lifetime in native seconds.
    pub valid_seconds: u32,
    /// Remaining preferred lifetime in native seconds.
    pub preferred_seconds: u32,
    /// Native source-selection policy.
    pub skip_as_source: bool,
}
pub(super) fn socket_address(ip: IpAddr, index: u32) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => {
            let mut address = SOCKADDR_IN {
                sin_family: AF_INET,
                ..Default::default()
            };
            address.sin_addr.S_un = IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip.octets()),
            };
            SOCKADDR_INET { Ipv4: address }
        }
        IpAddr::V6(ip) => {
            let mut address = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };
            address.sin6_addr.u = IN6_ADDR_0 { Byte: ip.octets() };
            address.Anonymous = SOCKADDR_IN6_0 {
                sin6_scope_id: if ip.is_unicast_link_local() { index } else { 0 },
            };
            SOCKADDR_INET { Ipv6: address }
        }
    }
}
pub(super) fn validate_prefix(address: IpAddr, prefix: u8) -> io::Result<()> {
    if prefix > if address.is_ipv4() { 32 } else { 128 } {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}
impl InterfacePort {
    fn address_key(&self, address: IpAddr) -> io::Result<MIB_UNICASTIPADDRESS_ROW> {
        let actual = self.row()?;
        Ok(MIB_UNICASTIPADDRESS_ROW {
            Address: socket_address(address, actual.InterfaceIndex),
            InterfaceLuid: NET_LUID_LH { Value: self.luid() },
            ..Default::default()
        })
    }
    #[expect(
        unsafe_code,
        reason = "The native query borrows one exact initialized row selected by original LUID and address"
    )]
    fn address_row(&self, address: IpAddr) -> io::Result<MIB_UNICASTIPADDRESS_ROW> {
        let mut row = self.address_key(address)?;
        // SAFETY: exact initialized SDK record and original interface/address key.
        check(unsafe { GetUnicastIpAddressEntry(&mut row) })?;
        Ok(row)
    }
    /// Observe the actual address and DAD state on this original interface.
    pub fn address(&self, address: IpAddr) -> io::Result<AddressObservation> {
        let row = self.address_row(address)?;
        if row.OnLinkPrefixLength > if address.is_ipv4() { 32 } else { 128 } {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native address prefix overflow",
            ));
        }
        let dad = match row.DadState {
            DAD_INVALID => DadState::Invalid,
            DAD_TENTATIVE => DadState::Tentative,
            DAD_DUPLICATE => DadState::Duplicate,
            DAD_DEPRECATED => DadState::Deprecated,
            DAD_PREFERRED => DadState::Preferred,
            other => DadState::Other(other),
        };
        Ok(AddressObservation {
            address,
            prefix: row.OnLinkPrefixLength,
            dad,
            valid_seconds: row.ValidLifetime,
            preferred_seconds: row.PreferredLifetime,
            skip_as_source: row.SkipAsSource,
        })
    }
    /// Query an exact original-interface address, distinguishing actual absence
    /// from an unavailable interface/family. No enumeration or ownership inference.
    pub fn find_address(&self, address: IpAddr) -> io::Result<Option<AddressObservation>> {
        match self.address(address) {
            Ok(row) => Ok(Some(row)),
            Err(error)
                if error.raw_os_error()
                    == Some(windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32) =>
            {
                let family = if address.is_ipv4() {
                    super::Family::V4
                } else {
                    super::Family::V6
                };
                self.ip_interface(family)?;
                self.row()?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    /// Create one explicit manual address. Existing-address errors remain errors;
    /// Optimistic DAD is not requested; usability is observed separately. The caller authorizes and
    /// serializes address administration and owns any later cleanup intent.
    #[expect(
        unsafe_code,
        reason = "Initialize and Create borrow one exact SDK record, filled with original qualified LUID and explicit address/prefix"
    )]
    pub fn create_address(&self, address: IpAddr, prefix: u8) -> io::Result<()> {
        validate_prefix(address, prefix)?;
        let key = self.address_key(address)?;
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        // SAFETY: exact fully initialized SDK record with no retained pointers.
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.Address = key.Address;
        row.InterfaceLuid = key.InterfaceLuid;
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
        row.OnLinkPrefixLength = prefix;
        row.DadState = IpDadStateTentative;
        // SAFETY: explicit qualified original-interface request; caller owns admin.
        check(unsafe { CreateUnicastIpAddressEntry(&row) })
    }
    /// Update the actual address prefix while preserving its other settings.
    /// This can settle a separate IPv4 netmask intent; no new address is invented.
    #[expect(
        unsafe_code,
        reason = "Set borrows the queried original native address record after changing only its explicit prefix"
    )]
    pub fn set_address_prefix(&self, address: IpAddr, prefix: u8) -> io::Result<()> {
        validate_prefix(address, prefix)?;
        let mut row = self.address_row(address)?;
        row.OnLinkPrefixLength = prefix;
        // SAFETY: original row/address key; caller excludes concurrent admin.
        check(unsafe { SetUnicastIpAddressEntry(&row) })
    }
    /// Delete one caller-authorized address. Absence or native refusal remains
    /// an error. Address snapshots never authorize this mutation by themselves.
    #[expect(
        unsafe_code,
        reason = "Delete borrows one original-interface address record; caller separately authorizes and serializes this administrative action"
    )]
    pub fn delete_address(&self, address: IpAddr) -> io::Result<()> {
        let row = self.address_key(address)?;
        // SAFETY: exact native record selected by the original live interface.
        check(unsafe { DeleteUnicastIpAddressEntry(&row) })
    }
}

/// Complete IPv4 selection on one original interface. Windows has no unique
/// native primary address; multiple rows are never silently reduced to one.
#[derive(Clone, Copy, Debug)]
pub enum Ipv4Addresses {
    /// A complete successful native query found no matching IPv4 address.
    Unassigned,
    /// Exactly one matching address, with its actual native properties.
    Single(AddressObservation),
    /// Several matching rows; none was selected as primary.
    Multiple {
        /// Actual count on this original interface.
        count: usize,
    },
}
struct AddressTable(std::ptr::NonNull<MIB_UNICASTIPADDRESS_TABLE>);
impl Drop for AddressTable {
    #[expect(
        unsafe_code,
        reason = "The unique SDK table owner releases the original successful allocation exactly once with its matching native destructor"
    )]
    fn drop(&mut self) {
        // SAFETY: original table allocation, not accessed after this release.
        unsafe { FreeMibTable(self.0.as_ptr().cast()) };
    }
}
impl InterfacePort {
    /// Read all IPv4 rows for this original interface, without inferring ownership
    /// or choosing an arbitrary primary. Processing is capped at 8192 system-wide
    /// rows; larger native tables fail explicitly. The SDK allocation is always
    /// released before return, including malformed/capacity/error paths.
    #[expect(
        unsafe_code,
        reason = "The successful SDK allocation contains NumEntries exact variable-tail rows; bounded scalar reads remain within that trusted native allocation and the unique guard frees it once"
    )]
    pub fn ipv4_addresses(&self) -> io::Result<Ipv4Addresses> {
        let actual = self.row()?;
        self.ip_interface(super::Family::V4)?;
        let mut table = std::ptr::null_mut();
        // SAFETY: exact writable pointer slot, documented AF_INET allocation.
        check(unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) })?;
        let table = AddressTable(std::ptr::NonNull::new(table).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "null native address table")
        })?);
        // SAFETY: successful SDK table owns this header and its variable tail.
        let length = unsafe { (*table.0.as_ptr()).NumEntries } as usize;
        if length > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "native address table row bound",
            ));
        }
        // SAFETY: addr_of does not reference the one-element SDK tail as a Rust
        // array; each subsequent pointer read uses the SDK's actual row count.
        let rows = unsafe {
            std::ptr::addr_of!((*table.0.as_ptr()).Table).cast::<MIB_UNICASTIPADDRESS_ROW>()
        };
        let mut selected = None;
        let mut count = 0;
        for at in 0..length {
            // SAFETY: at is bounded by the actual SDK variable-tail row count.
            let row = unsafe { rows.add(at).read() };
            // SAFETY: Value covers the complete initialized native LUID union.
            if unsafe { row.InterfaceLuid.Value != actual.InterfaceLuid.Value } {
                continue;
            }
            if row.InterfaceIndex != actual.InterfaceIndex {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native address interface index changed",
                ));
            }
            // SAFETY: the table was requested specifically for AF_INET; verify
            // the family discriminator before reading its IPv4 union member.
            if unsafe { row.Address.si_family } != AF_INET || row.OnLinkPrefixLength > 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native IPv4 table row",
                ));
            }
            // SAFETY: initialized AF_INET row verified immediately above.
            let address = std::net::Ipv4Addr::from(
                unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
            );
            count += 1;
            selected = Some(address);
        }
        drop(table);
        self.row()?;
        match (count, selected) {
            (0, _) => Ok(Ipv4Addresses::Unassigned),
            (1, Some(address)) => self.address(address.into()).map(Ipv4Addresses::Single),
            (count, _) => Ok(Ipv4Addresses::Multiple { count }),
        }
    }
}

#[expect(
    unsafe_code,
    reason = "Only the initialized SDK sockaddr union member selected by its checked family discriminator is read"
)]
pub(super) fn decode_address(address: &SOCKADDR_INET) -> io::Result<IpAddr> {
    // SAFETY: both supported SDK members start with the family discriminator.
    match unsafe { address.si_family } {
        // SAFETY: checked AF_INET selects the initialized IPv4 SDK member.
        AF_INET => Ok(std::net::Ipv4Addr::from(
            unsafe { address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
        )
        .into()),
        // SAFETY: checked AF_INET6 selects the initialized IPv6 SDK member.
        AF_INET6 => Ok(std::net::Ipv6Addr::from(unsafe { address.Ipv6.sin6_addr.u.Byte }).into()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native sockaddr family",
        )),
    }
}
