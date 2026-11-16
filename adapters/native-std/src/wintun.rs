//! Explicit caller-trusted Wintun ABI, with no GNUnet or private packet framing.
mod address;
mod api;
mod interface;
mod owners;
mod recreation;
pub use recreation::{Recreation, RecreationError};
mod route;
use owners::Owners;
mod selector;
mod session;
use crate::library::Library;
pub use address::{AddressObservation, DadState, Ipv4Addresses};
use api::Api;
pub use api::LoadFailure;
pub use interface::{Family, Interface, InterfacePort, IpInterface};
pub use route::{Route, RouteLookup, RouteObservation, route_error_kind};
pub use selector::{RetainedReopenError, Selector};
pub use session::{Receive, SendStatus, Session, SessionKind, StartError};
use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt, path::Path, ptr::NonNull, rc::Rc};
pub use windows_sys::core::GUID as Guid;

/// Fixed native ring capacity. Each session allocates receive and send rings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingCapacity(u32);
impl RingCapacity {
    /// Smallest capacity admitted by Wintun (128 KiB per ring).
    pub const MIN: Self = Self(0x20000);
    /// Largest capacity admitted by Wintun (64 MiB per ring).
    pub const MAX: Self = Self(0x4000000);
    /// Validate a power-of-two capacity within the native range.
    pub fn new(bytes: u32) -> io::Result<Self> {
        if !bytes.is_power_of_two() || !(Self::MIN.0..=Self::MAX.0).contains(&bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Wintun ring capacity",
            ));
        }
        Ok(Self(bytes))
    }
    /// Configured bytes per ring, independently of packet/application pools.
    pub const fn bytes(self) -> u32 {
        self.0
    }
}
/// Maximum raw IP extent accepted by the native packet API.
pub const MAX_PACKET_BYTES: usize = 65535;

/// Classify the provider's selected-name lookup refusal from WintunOpenAdapter.
/// This is not interface/route absence or permission to create a replacement.
#[must_use]
pub fn is_adapter_missing(error: &io::Error) -> bool {
    error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32)
}

/// One caller-trusted DLL reference. Clones share that exact export table;
/// adapters and sessions retain it until their original resources are released.
/// The exact module is pinned for process lifetime because the provider can
/// queue cleanup work with no public join API. The original loader reference
/// still closes normally after its last Rust owner; that does not unmap the DLL.
/// This owner stays on its loading thread and changes no global logger callback.
#[derive(Clone)]
pub struct Driver(Rc<Api>);
impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("loaded", &self.0.library.is_open())
            .finish()
    }
}
impl Driver {
    /// Load an explicit absolute official Wintun DLL path and resolve its ABI.
    ///
    /// # Safety
    /// The caller trusts this DLL, its dependencies and initialization/destruction
    /// code, and certifies the official Wintun API calling convention/contracts.
    /// The selected module is irreversibly pinned for process lifetime before
    /// any device/session export runs. No provider search or download occurs.
    #[expect(
        unsafe_code,
        reason = "Caller certifies the exact native provider and ABI; all derived owners retain this loader reference"
    )]
    pub unsafe fn load(path: &Path) -> io::Result<Self> {
        // SAFETY: the caller supplies the library/code trust boundary.
        let library = unsafe { Library::load(path) }?;
        // SAFETY: exports must implement the official Wintun signatures.
        Ok(Self(Rc::new(unsafe { Api::resolve(library) }?)))
    }
    /// Create a fresh adapter. The provider may provision its native driver;
    /// callers authorize that administrative effect separately from DLL loading.
    /// Requested GUID is an input, never proof of the actual interface identity.
    #[expect(
        unsafe_code,
        reason = "The trusted typed export borrows terminated native names and an optional live GUID; success transfers one original adapter"
    )]
    pub fn create(
        &self,
        name: &OsStr,
        tunnel_type: &OsStr,
        requested: Option<&Guid>,
    ) -> io::Result<Adapter> {
        let name = wide_name(name)?;
        let tunnel_type = wide_name(tunnel_type)?;
        let recipe = recreation::Recipe::new(&name, &tunnel_type)?;
        // SAFETY: both bounded native strings and optional GUID remain live;
        // Api is the caller-trusted official export table retained below.
        let raw = unsafe {
            (self.0.create)(
                name.as_ptr(),
                tunnel_type.as_ptr(),
                requested.map_or(std::ptr::null(), |guid| guid),
            )
        };
        let raw = NonNull::new(raw).ok_or_else(io::Error::last_os_error)?;
        Adapter::qualify(OwnedAdapter {
            raw,
            driver: self.clone(),
            origin: Origin::Created,
            name,
            recipe: Some(Box::new(recipe)),
        })
    }
    /// Create only after a complete native table reports a vacant name/GUID.
    /// The caller serializes native administration through the whole call.
    /// This prevents the provider's collision policy from renaming another
    /// interface; it is not an atomic reservation against a foreign administrator.
    ///
    /// # Errors
    /// Preserves complete-table, collision and actual provider errors.
    pub fn create_exclusive(
        &self,
        name: &OsStr,
        tunnel_type: &OsStr,
        requested: Option<&Guid>,
    ) -> io::Result<Adapter> {
        self.create_vacant(name, tunnel_type, requested, None)
    }
    fn create_vacant(
        &self,
        name: &OsStr,
        tunnel_type: &OsStr,
        requested: Option<&Guid>,
        until: Option<std::time::Instant>,
    ) -> io::Result<Adapter> {
        let check = || {
            if until.is_some_and(|until| std::time::Instant::now() >= until) {
                Err(io::Error::from(io::ErrorKind::TimedOut))
            } else {
                Ok(())
            }
        };
        check()?;
        crate::interfaces::require_vacant(&wide_name(name)?, requested.copied())?;
        check()?;
        match self.open(name) {
            Ok(existing) => {
                drop(existing);
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Wintun provider name is occupied",
                ));
            }
            Err(error) if is_adapter_missing(&error) => {}
            Err(error) => return Err(error),
        }
        check()?;
        self.create(name, tunnel_type, requested)
    }
    /// Open an explicitly named existing adapter. Closing this owner does not
    /// request removal of an adapter created by another owner.
    pub fn open(&self, name: &OsStr) -> io::Result<Adapter> {
        let name = wide_name(name)?;
        self.open_name(name)
    }
    #[expect(
        unsafe_code,
        reason = "The private validated terminated provider name stays owned through the exact trusted open export; success transfers one original adapter"
    )]
    fn open_name(&self, name: Vec<u16>) -> io::Result<Adapter> {
        // SAFETY: bounded terminated name and original provider remain live.
        let raw = unsafe { (self.0.open)(name.as_ptr()) };
        let raw = NonNull::new(raw).ok_or_else(io::Error::last_os_error)?;
        Adapter::qualify(OwnedAdapter {
            raw,
            driver: self.clone(),
            origin: Origin::Opened,
            name,
            recipe: None,
        })
    }
}
/// Native origin, retained independently of an adapter's display name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    /// This owner created the adapter; Wintun close requests its removal.
    Created,
    /// This owner opened an existing adapter; its creator owns removal.
    Opened,
}
/// One original adapter. A session consumes and retains this owner, so it cannot
/// be closed before that session ends. There is no raw handle/constructor API.
pub struct Adapter {
    // Retire all old administration ports before native handle release, also
    // when this owner is decomposed during same-scope handle refresh.
    retirement: InterfaceRetirement,
    owners: Owners<OwnedAdapter>,
    identity: InterfacePort,
    next_session: SessionKind,
}
struct InterfaceRetirement(InterfacePort);
impl Drop for InterfaceRetirement {
    fn drop(&mut self) {
        self.0.retire();
    }
}
struct OwnedAdapter {
    raw: NonNull<std::ffi::c_void>,
    driver: Driver,
    origin: Origin,
    // Wintun's DEVPKEY_Wintun_Name, distinct from the mutable IP-interface alias.
    name: Vec<u16>,
    recipe: Option<Box<recreation::Recipe>>,
}
impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter")
            .field("origin", &self.origin())
            .field("packet_handle_origin", &self.owners.packet.origin)
            .finish()
    }
}
impl Adapter {
    /// Retain the exact original provider without a new DLL lookup. This does
    /// not transfer the adapter or its original removal responsibility.
    pub fn driver(&self) -> Driver {
        self.owners.packet.driver.clone()
    }
    /// Original creation/removal responsibility, retained across handle refresh.
    /// An Opened packet handle may retain the same original creator without
    /// acquiring another creator's device or administrative rights.
    pub fn origin(&self) -> Origin {
        self.owners
            .creator()
            .map_or(self.owners.packet.origin, |owner| owner.origin)
    }
    /// Clone an original-interface administration port. It retains identity only,
    /// never the adapter, session or DLL. Adapter retirement invalidates all ports.
    pub fn port(&self) -> InterfacePort {
        self.identity.clone()
    }
    /// Invoke the provider's close once. Its void ABI reports no independent
    /// kernel-close/removal acknowledgement, and none is fabricated.
    pub fn close(self) {
        drop(self);
    }
}
impl Drop for OwnedAdapter {
    #[expect(
        unsafe_code,
        reason = "The unique linear native owner is dropped once, after session retirement, while its original provider remains loaded"
    )]
    fn drop(&mut self) {
        // SAFETY: this linear owner is dropped once, after its session ends;
        // the original adapter's DLL reference remains retained through this call.
        unsafe { (self.driver.0.close)(self.raw.as_ptr()) };
    }
}
fn check(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}
fn wide_name(name: &OsStr) -> io::Result<Vec<u16>> {
    let units = name.encode_wide().count();
    if units == 0 || units > 32767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Wintun native name extent",
        ));
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(units + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for unit in name.encode_wide() {
        if unit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NUL Wintun native name",
            ));
        }
        wide.push(unit);
    }
    wide.push(0);
    Ok(wide)
}
