//! Explicit logical selection for borrowed reopen; never inherited cleanup rights.
use super::{Adapter, Driver, Guid, Origin, SessionKind, wide_name};
use std::{
    ffi::{OsStr, OsString},
    fmt, io,
    os::windows::ffi::OsStringExt,
};
/// Same-scope refresh refusal returns the original adapter and its creator lease.
#[derive(Debug)]
pub struct RetainedReopenError {
    adapter: Adapter,
    error: io::Error,
}
impl RetainedReopenError {
    /// Recover the unchanged original owner and actual refusal.
    pub fn into_parts(self) -> (Adapter, io::Error) {
        (self.adapter, self.error)
    }
}
impl fmt::Display for RetainedReopenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wintun retained-scope reopen: {}", self.error)
    }
}
impl std::error::Error for RetainedReopenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Provider name, observed interface GUID and network compartment used for an
/// explicit reopen. It owns no adapter/session and grants no removal authority.
/// A successful reopen qualifies a new physical owner; it does not revive an old
/// LUID, packet epoch, route operation or creator's deletion responsibility.
#[derive(Clone)]
pub struct Selector {
    name: Vec<u16>,
    guid: Guid,
    compartment: u32,
}
impl fmt::Debug for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WintunSelector")
            .field("provider_name", &self.provider_name())
            .field("compartment", &self.compartment)
            .finish_non_exhaustive()
    }
}
impl Selector {
    /// Construct an explicit selection intent, for example from saved local
    /// configuration. These values are selectors, not prior-device proof.
    pub fn new(provider_name: &OsStr, guid: Guid, compartment: u32) -> io::Result<Self> {
        if compartment == 0
            || (guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4 == [0; 8])
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            name: wide_name(provider_name)?,
            guid,
            compartment,
        })
    }
    /// Original Wintun provider name, not the IP Helper display alias.
    pub fn provider_name(&self) -> OsString {
        OsString::from_wide(&self.name[..self.name.len() - 1])
    }
    /// Requested logical interface GUID; reopening verifies actual native output.
    pub const fn guid(&self) -> Guid {
        self.guid
    }
    /// Network compartment in which reopening is allowed.
    pub const fn compartment(&self) -> u32 {
        self.compartment
    }
}
impl Adapter {
    /// Refresh the packet handle while retaining original creation lifetime.
    /// The provider name, GUID, LUID, index and compartment must all still match.
    /// Old administration ports retire permanently; no route cleanup is claimed.
    /// The retained creator is one unique root, so repeated refresh does not
    /// accumulate a chain of native adapter handles. Its release follows the
    /// final packet handle and session. Caller excludes concurrent administration.
    ///
    /// # Errors
    /// Returns this original adapter on selection, qualification or allocation
    /// failure. A provisional borrowed handle closes without removing a device.
    pub fn reopen_retained(self) -> Result<Self, RetainedReopenError> {
        let prepared = (|| -> io::Result<Adapter> {
            self.identity.row()?;
            let original = self.identity.identity();
            let next = self.owners.packet.driver.reopen(&self.selector()?)?;
            if next.identity.identity() != original {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "retained Wintun interface scope changed",
                ));
            }
            self.identity.row()?;
            next.identity.row()?;
            Ok(next)
        })();
        let mut next = match prepared {
            Ok(next) => next,
            Err(error) => {
                return Err(RetainedReopenError {
                    adapter: self,
                    error,
                });
            }
        };
        let Self {
            retirement, owners, ..
        } = self;
        let created = owners.packet.origin == Origin::Created;
        drop(retirement);
        next.owners = owners.refresh(next.owners.packet, created);
        next.next_session = SessionKind::Restarted;
        Ok(next)
    }
    /// Copy the originally observed GUID/compartment and provider name, without
    /// requiring the failed interface to remain queryable. Renaming its IP Helper
    /// alias does not replace this provider-name selector. This is not liveness.
    pub fn selector(&self) -> io::Result<Selector> {
        let actual = self.identity.identity();
        let mut name = Vec::new();
        name.try_reserve_exact(self.owners.packet.name.len())
            .map_err(io::Error::other)?;
        name.extend_from_slice(&self.owners.packet.name);
        Ok(Selector {
            name,
            guid: actual.guid(),
            compartment: actual.compartment(),
        })
    }
}
impl Driver {
    /// Explicitly open the selected surviving logical interface as borrowed.
    /// Reused names with another GUID or a changed network compartment fail.
    /// LUID/index are newly qualified; no old source or removal right is restored.
    /// Caller serializes provider/interface replacement around this native call.
    pub fn reopen(&self, selector: &Selector) -> io::Result<Adapter> {
        if crate::interfaces::compartment() != selector.compartment {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Wintun selector network compartment changed",
            ));
        }
        let mut name = Vec::new();
        name.try_reserve_exact(selector.name.len())
            .map_err(io::Error::other)?;
        name.extend_from_slice(&selector.name);
        let adapter = self.open_name(name)?;
        let actual = adapter.port().interface()?;
        if actual.compartment != selector.compartment || !same_guid(actual.guid, selector.guid) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Wintun provider name now selects another interface",
            ));
        }
        Ok(adapter)
    }
}
pub(super) fn same_guid(left: Guid, right: Guid) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}
