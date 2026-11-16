//! Immutable native interface selection, separate from device ownership.
pub use super::identity_value::Identity;
use std::io;
use windows_sys::Win32::NetworkManagement::{
    IpHelper::{GetCurrentThreadCompartmentId, GetIfEntry2, MIB_IF_ROW2},
    Ndis::NET_LUID_LH,
};
#[expect(
    unsafe_code,
    reason = "The documented native getter observes only the calling thread's network compartment"
)]
pub(crate) fn compartment() -> u32 {
    // SAFETY: no pointers, allocation or retained state.
    unsafe { GetCurrentThreadCompartmentId() }
}
pub(super) fn guid_bytes(guid: windows_sys::core::GUID) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&guid.data1.to_le_bytes());
    bytes[4..6].copy_from_slice(&guid.data2.to_le_bytes());
    bytes[6..8].copy_from_slice(&guid.data3.to_le_bytes());
    bytes[8..].copy_from_slice(&guid.data4);
    bytes
}
#[expect(
    unsafe_code,
    reason = "GetIfEntry2 borrows one fully initialized SDK row; the full-width LUID union is initialized before reading"
)]
fn query(mut row: MIB_IF_ROW2) -> io::Result<MIB_IF_ROW2> {
    // SAFETY: input rows are fully initialized, including this scalar union.
    let requested_luid = unsafe { row.InterfaceLuid.Value };
    let requested_index = row.InterfaceIndex;
    // SAFETY: exact SDK row remains live for the synchronous call.
    let result = unsafe { GetIfEntry2(&mut row) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    // SAFETY: the native API initialized the complete scalar union.
    if row.InterfaceIndex == 0 || unsafe { row.InterfaceLuid.Value } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero native interface identity",
        ));
    }
    // SAFETY: successful native output initializes the full-width scalar union.
    if (requested_luid != 0 && unsafe { row.InterfaceLuid.Value } != requested_luid)
        || (requested_index != 0 && row.InterfaceIndex != requested_index)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "native interface selection changed",
        ));
    }
    Ok(row)
}
impl Identity {
    /// Observe the current interface behind an index; no ownership is acquired.
    pub fn from_index(index: u32) -> io::Result<Self> {
        if index == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Self::capture(MIB_IF_ROW2 {
            InterfaceIndex: index,
            ..Default::default()
        })
    }
    pub(crate) fn from_luid(luid: u64) -> io::Result<Self> {
        if luid == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Self::capture(MIB_IF_ROW2 {
            InterfaceLuid: NET_LUID_LH { Value: luid },
            ..Default::default()
        })
    }
    #[expect(
        unsafe_code,
        reason = "The query initialized every SDK scalar, including the complete LUID union"
    )]
    fn capture(row: MIB_IF_ROW2) -> io::Result<Self> {
        let compartment = compartment();
        let row = query(row)?;
        // SAFETY: Value spans the initialized complete scalar union.
        let luid = unsafe { row.InterfaceLuid.Value };
        Ok(Self {
            compartment,
            luid,
            index: row.InterfaceIndex,
            guid: guid_bytes(row.InterfaceGuid),
        })
    }
    #[expect(
        unsafe_code,
        reason = "The complete SDK table initialized each full-width LUID union; all retained facts are plain scalar copies"
    )]
    pub(crate) fn snapshot(bound: usize) -> io::Result<Vec<Self>> {
        let original = compartment();
        let table = super::table::Interfaces::capture(bound)?;
        let mut identities = Vec::new();
        identities
            .try_reserve_exact(table.rows().len())
            .map_err(io::Error::other)?;
        for row in table.rows() {
            // SAFETY: Value spans the complete initialized native scalar union.
            let luid = unsafe { row.InterfaceLuid.Value };
            if luid == 0 || row.InterfaceIndex == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "zero native interface identity",
                ));
            }
            identities.push(Self {
                compartment: original,
                luid,
                index: row.InterfaceIndex,
                guid: guid_bytes(row.InterfaceGuid),
            });
        }
        if compartment() != original {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "native interface snapshot compartment changed",
            ));
        }
        Ok(identities)
    }
    /// Original observed interface GUID, without a live query or ownership grant.
    /// This metadata remains available when physical revalidation later fails.
    pub const fn guid(&self) -> windows_sys::core::GUID {
        windows_sys::core::GUID {
            data1: u32::from_le_bytes([self.guid[0], self.guid[1], self.guid[2], self.guid[3]]),
            data2: u16::from_le_bytes([self.guid[4], self.guid[5]]),
            data3: u16::from_le_bytes([self.guid[6], self.guid[7]]),
            data4: [
                self.guid[8],
                self.guid[9],
                self.guid[10],
                self.guid[11],
                self.guid[12],
                self.guid[13],
                self.guid[14],
                self.guid[15],
            ],
        }
    }
    /// Recheck the original interface without updating or replacing its identity.
    pub fn check(&self) -> io::Result<()> {
        self.row().map(|_| ())
    }
    #[expect(
        unsafe_code,
        reason = "The original scalar LUID selects an initialized SDK row; its complete union value is checked after native success"
    )]
    pub(crate) fn row(&self) -> io::Result<MIB_IF_ROW2> {
        if compartment() != self.compartment {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original network compartment changed",
            ));
        }
        let row = query(MIB_IF_ROW2 {
            InterfaceLuid: NET_LUID_LH { Value: self.luid },
            ..Default::default()
        })?;
        // SAFETY: the successful native query initialized the full-width union.
        if unsafe { row.InterfaceLuid.Value } != self.luid
            || row.InterfaceIndex != self.index
            || guid_bytes(row.InterfaceGuid) != self.guid
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original network interface was replaced",
            ));
        }
        Ok(row)
    }
}
