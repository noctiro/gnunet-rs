//! Complete bounded native snapshots distinguish missing interfaces from stale route debt.
use super::table::Interfaces;
use super::{Identity, compartment, identity::guid_bytes};
mod selection;
pub use selection::InterfacePresence;
use selection::{Key, classify};
use std::{
    io,
    ptr::{self, NonNull},
    time::Instant,
};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2},
    Networking::WinSock::AF_UNSPEC,
};

/// Complete-table work bounds for cold physical-interface reconciliation.
#[derive(Clone, Copy, Debug)]
pub struct RetirementLimits {
    /// Maximum interface rows inspected; overflow is an error, never absence.
    pub interfaces: usize,
    /// Maximum forwarding rows inspected across both IP families.
    pub routes: usize,
}
impl Default for RetirementLimits {
    fn default() -> Self {
        Self {
            interfaces: 4096,
            routes: 16384,
        }
    }
}
/// A time-local native observation that the old LUID and its forwarding rows
/// are absent. It grants no device ownership and does not cancel old provider
/// jobs; the consuming controller must retire those jobs separately and exclude
/// concurrent administration/replacement across observation and admission.
#[derive(Clone, Debug)]
pub struct RetiredScope {
    identity: Identity,
    observed_at: Instant,
}
impl RetiredScope {
    /// Original scope actually queried; it cannot be rebound to another device.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Native monotonic sample after both complete tables and the final recheck.
    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }
}
struct Table<T>(NonNull<T>);
impl<T> Drop for Table<T> {
    #[expect(
        unsafe_code,
        reason = "Each successful SDK table allocation is uniquely retained and freed with its matching native allocator"
    )]
    fn drop(&mut self) {
        // SAFETY: exactly the allocation returned by an IP Helper table getter.
        unsafe { FreeMibTable(self.0.as_ptr().cast()) };
    }
}
fn extent<T>(count: u32, bound: usize) -> io::Result<usize> {
    let count = usize::try_from(count).map_err(io::Error::other)?;
    if bound == 0
        || count > bound
        || count
            .checked_mul(size_of::<T>())
            .is_none_or(|bytes| bytes > isize::MAX as usize)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native reconciliation table exceeds its complete-snapshot bound",
        ));
    }
    Ok(count)
}
impl Identity {
    fn scope_compartment(&self) -> io::Result<()> {
        if compartment() != self.compartment() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original reconciliation compartment changed",
            ));
        }
        Ok(())
    }
    /// Read a complete bounded interface table and match the original full
    /// identity. Native errors and truncated/oversized snapshots stay errors.
    #[expect(
        unsafe_code,
        reason = "The complete original table initializes every full-width native LUID union inspected for identity matching"
    )]
    pub fn presence(&self, limits: RetirementLimits) -> io::Result<InterfacePresence> {
        self.scope_compartment()?;
        let table = Interfaces::capture(limits.interfaces)?;
        let rows = table.rows();
        if rows.iter().any(|row| {
            // SAFETY: SDK initialized the full scalar union in each table row.
            unsafe { row.InterfaceLuid.Value == 0 || row.InterfaceIndex == 0 }
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero identity in complete native interface table",
            ));
        }
        let original = Key {
            luid: self.luid(),
            index: self.index(),
            guid: guid_bytes(self.guid()),
        };
        let result = classify(
            original,
            rows.iter().map(|row| Key {
                // SAFETY: Value spans the completely initialized native scalar union.
                luid: unsafe { row.InterfaceLuid.Value },
                index: row.InterfaceIndex,
                guid: guid_bytes(row.InterfaceGuid),
            }),
        );
        self.scope_compartment()?;
        Ok(result)
    }
    /// Observe absence of the old physical interface and every route on its
    /// original LUID. This performs no deletion and never treats getter errors,
    /// a reused LUID, or an incomplete table as successful cleanup.
    ///
    /// # Errors
    /// Returns WouldBlock while the original interface or routes remain;
    /// replacement, native query and capacity errors preserve uncertainty.
    #[expect(
        unsafe_code,
        reason = "The SDK supplies all initialized forwarding rows; exact original LUID comparison uses the full scalar union after a checked row bound"
    )]
    pub fn retired_scope(&self, limits: RetirementLimits) -> io::Result<RetiredScope> {
        match self.presence(limits)? {
            InterfacePresence::Missing => {}
            InterfacePresence::Present => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "original interface remains present",
                ));
            }
            InterfacePresence::Reused => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "original LUID was reused",
                ));
            }
        }
        let mut raw = ptr::null_mut();
        // SAFETY: both-family getter transfers one complete native table on success.
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut raw) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let table = Table(
            NonNull::<MIB_IPFORWARD_TABLE2>::new(raw)
                .ok_or_else(|| io::Error::other("null native forwarding table"))?,
        );
        // SAFETY: successful getter initialized the header and complete declared trailing array.
        let count = extent::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2>(
            unsafe { table.0.as_ref().NumEntries },
            limits.routes,
        )?;
        // SAFETY: checked complete SDK array, retained by table throughout this borrow.
        let rows = unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!((*table.0.as_ptr()).Table)
                    .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2>(),
                count,
            )
        };
        if rows.iter().any(|row| {
            // SAFETY: SDK initialized this complete full-width union value.
            unsafe {
                row.InterfaceLuid.Value == self.luid()
                    || row.InterfaceLuid.Value == 0
                        && (row.InterfaceIndex == 0 || row.InterfaceIndex == self.index())
            }
        }) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "original forwarding scope remains present or ambiguous",
            ));
        }
        drop(table);
        if self.presence(limits)? != InterfacePresence::Missing {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original interface selection changed during reconciliation",
            ));
        }
        Ok(RetiredScope {
            identity: self.clone(),
            observed_at: Instant::now(),
        })
    }
}

/// A complete time-local absence check. Caller serializes administration across
/// this observation and creation; this does not reserve an alias or GUID.
#[expect(
    unsafe_code,
    reason = "IP Helper supplies the complete initialized table and exact trailing array; bounded UTF-16 spans remain borrowed during native ordinal comparisons"
)]
pub(crate) fn require_vacant(
    alias: &[u16],
    guid: Option<windows_sys::core::GUID>,
) -> io::Result<()> {
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    if alias.len() < 2 || alias.last() != Some(&0) || alias[..alias.len() - 1].contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let table = Interfaces::capture(RetirementLimits::default().interfaces)?;
    for row in table.rows() {
        // SAFETY: Value spans the complete initialized SDK scalar union.
        if unsafe { row.InterfaceLuid.Value == 0 } || row.InterfaceIndex == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero identity in complete interface table",
            ));
        }
        let end = row
            .Alias
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(io::ErrorKind::InvalidData)?;
        // SAFETY: initialized bounded native UTF-16 arrays and checked lengths.
        let same_name = unsafe {
            CompareStringOrdinal(
                row.Alias.as_ptr(),
                end as i32,
                alias.as_ptr(),
                (alias.len() - 1) as i32,
                1,
            )
        };
        if same_name == 0 {
            return Err(io::Error::last_os_error());
        }
        if same_name == CSTR_EQUAL
            || guid.is_some_and(|guid| guid_bytes(row.InterfaceGuid) == guid_bytes(guid))
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "native interface name or GUID is occupied",
            ));
        }
    }
    Ok(())
}
