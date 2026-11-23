//! GUID-selected NetCon rename; occupied aliases are never moved out of the way.
use super::{Identity, identity::guid_bytes};
use crate::com::{self, Apartment};
use std::{ffi::c_void, io, os::windows::ffi::OsStrExt, ptr::NonNull};
use windows_sys::{
    Win32::{
        Globalization::{CSTR_EQUAL, CompareStringOrdinal},
        NetworkManagement::WindowsFirewall::{
            NETCON_PROPERTIES, NcFreeNetconProperties, NcIsValidConnectionName,
        },
        System::Com::{CLSCTX_LOCAL_SERVER, CoCreateInstance},
    },
    core::GUID,
};

const MAX_CONNECTIONS: usize = 4096;
const MAX_NAME_UNITS: usize = 256;
const IID_MANAGER: GUID = GUID::from_u128(0xc08956a2_1cd3_11d1_b1c5_00805fc1270e);

// NetCon.h declares this GUID as static data in the SDK UUID library, not a DLL
// import. Resolve it from the final target's SDK instead of bundling it in the rlib.
#[expect(
    unsafe_code,
    reason = "The Windows SDK declares this immutable class GUID in uuid.lib"
)]
#[link(name = "uuid", kind = "static", modifiers = "-bundle")]
unsafe extern "C" {
    static CLSID_ConnectionManager: GUID;
}
#[repr(C)]
struct Unknown {
    query: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    add: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}
#[repr(C)]
struct Manager {
    unknown: Unknown,
    enumerate: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32,
}
#[repr(C)]
struct Enumeration {
    unknown: Unknown,
    next: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void, *mut u32) -> i32,
    skip: unsafe extern "system" fn(*mut c_void, u32) -> i32,
    reset: unsafe extern "system" fn(*mut c_void) -> i32,
    clone: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
}
#[repr(C)]
struct Connection {
    unknown: Unknown,
    connect: unsafe extern "system" fn(*mut c_void) -> i32,
    disconnect: unsafe extern "system" fn(*mut c_void) -> i32,
    delete: unsafe extern "system" fn(*mut c_void) -> i32,
    duplicate: unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> i32,
    properties: unsafe extern "system" fn(*mut c_void, *mut *mut NETCON_PROPERTIES) -> i32,
    class: unsafe extern "system" fn(*mut c_void, *mut GUID) -> i32,
    rename: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
}
struct Reference<V>(NonNull<*const V>);
impl<V> Reference<V> {
    /// # Safety
    /// The nonnull input must transfer one live COM reference with vtable V.
    #[expect(
        unsafe_code,
        reason = "Private constructor admits only typed original COM outputs"
    )]
    unsafe fn output(raw: *mut c_void) -> io::Result<Self> {
        NonNull::new(raw.cast()).map(Self).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "null successful NetCon interface",
            )
        })
    }
    fn raw(&self) -> *mut c_void {
        self.0.as_ptr().cast()
    }
    #[expect(
        unsafe_code,
        reason = "Only successful typed NetCon outputs construct private references, and every vtable remains live until its matching Release"
    )]
    fn table(&self) -> &V {
        // SAFETY: the original COM reference owns this exact typed vtable.
        unsafe { &**self.0.as_ptr() }
    }
}
impl<V> Drop for Reference<V> {
    #[expect(
        unsafe_code,
        reason = "Every NetCon interface begins with IUnknown and exactly one returned COM reference belongs to this owner"
    )]
    fn drop(&mut self) {
        // SAFETY: SDK IUnknown prefix, live original interface and same apartment.
        unsafe {
            let table = *self.0.as_ptr().cast::<*const Unknown>();
            ((*table).release)(self.raw());
        }
    }
}
struct Properties(NonNull<NETCON_PROPERTIES>);
impl Drop for Properties {
    #[expect(
        unsafe_code,
        reason = "The successful NetCon allocation is released once with its documented matching allocator"
    )]
    fn drop(&mut self) {
        // SAFETY: original GetProperties output; no pointers outlive this owner.
        unsafe { NcFreeNetconProperties(self.0.as_ptr()) };
    }
}
impl Reference<Connection> {
    #[expect(
        unsafe_code,
        reason = "The owned NetCon connection writes its documented properties allocation into exclusive initialized output storage"
    )]
    fn properties(&self) -> io::Result<Properties> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: original typed interface and exact writable output pointer.
        com::result("INetConnection::GetProperties", unsafe {
            (self.table().properties)(self.raw(), &mut raw)
        })?;
        NonNull::new(raw)
            .map(Properties)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "null NetCon properties"))
    }
}
fn occupied() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "network interface alias is occupied",
    )
}
impl Identity {
    /// Rename this exact native interface through its GUID-selected COM object.
    /// The complete bounded connection scan refuses an occupied alias; no other
    /// connection is renamed. The caller excludes concurrent administration.
    ///
    /// # Errors
    /// Preserves COM HRESULTs and native identity errors, and refuses malformed
    /// names, incomplete enumeration and replacement. An error after Rename may
    /// follow an actual rename; it never releases the caller's device ownership.
    #[expect(
        unsafe_code,
        reason = "Documented NetCon COM calls borrow owned references in the same retained apartment, bounded names and exclusive initialized output storage"
    )]
    pub fn rename(&self, name: &std::ffi::OsStr, until: std::time::Instant) -> io::Result<()> {
        let check = || {
            if std::time::Instant::now() >= until {
                Err(io::Error::from(io::ErrorKind::TimedOut))
            } else {
                Ok(())
            }
        };
        check()?;
        self.check()?;
        let mut name: Vec<u16> = name.encode_wide().take(MAX_NAME_UNITS + 1).collect();
        if name.is_empty() || name.len() > MAX_NAME_UNITS || name.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        name.push(0);
        // SAFETY: bounded, nonempty and terminated native name.
        if unsafe { NcIsValidConnectionName(name.as_ptr()) } == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let _apartment = Apartment::acquire()?;
        check()?;
        let mut raw = std::ptr::null_mut();
        // SAFETY: SDK class and IID, no aggregation, exact exclusive output.
        com::result("CoCreateInstance(ConnectionManager)", unsafe {
            CoCreateInstance(
                &CLSID_ConnectionManager,
                std::ptr::null_mut(),
                CLSCTX_LOCAL_SERVER,
                &IID_MANAGER,
                &mut raw,
            )
        })?;
        // SAFETY: CoCreateInstance succeeded for the exact INetConnectionManager IID.
        let manager = unsafe { Reference::<Manager>::output(raw) }?;
        check()?;
        raw = std::ptr::null_mut();
        // SAFETY: original manager, NCME_DEFAULT and exact exclusive output.
        com::result("INetConnectionManager::EnumConnections", unsafe {
            (manager.table().enumerate)(manager.raw(), 0, &mut raw)
        })?;
        // SAFETY: EnumConnections succeeded and transfers one typed enumerator.
        let enumeration = unsafe { Reference::<Enumeration>::output(raw) }?;
        let mut selected: Option<Reference<Connection>> = None;
        for index in 0..=MAX_CONNECTIONS {
            check()?;
            raw = std::ptr::null_mut();
            let mut fetched = 0;
            // SAFETY: original enumerator and capacity for exactly one reference.
            let status =
                unsafe { (enumeration.table().next)(enumeration.raw(), 1, &mut raw, &mut fetched) };
            if status == 1 && fetched == 0 && raw.is_null() {
                break;
            }
            com::result("IEnumNetConnection::Next", status)?;
            // SAFETY: successful Next transfers one typed INetConnection reference.
            let connection = unsafe { Reference::<Connection>::output(raw) }?;
            if fetched != 1 || index == MAX_CONNECTIONS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete NetCon enumeration",
                ));
            }
            let owned_properties = connection.properties()?;
            // SAFETY: original live, successful SDK properties allocation.
            let properties = unsafe { owned_properties.0.as_ref() };
            if guid_bytes(properties.guidId) == guid_bytes(self.guid()) {
                if selected.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate NetCon GUID",
                    ));
                }
                selected = Some(connection);
            } else {
                if properties.pszwName.is_null() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "null NetCon connection name",
                    ));
                }
                // SAFETY: GetProperties guarantees a terminated connection name;
                // CompareStringOrdinal accepts -1 for native terminated input.
                let equal =
                    unsafe { CompareStringOrdinal(properties.pszwName, -1, name.as_ptr(), -1, 1) };
                if equal == 0 {
                    return Err(io::Error::last_os_error());
                }
                if equal == CSTR_EQUAL {
                    return Err(occupied());
                }
            }
        }
        let connection = selected.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "original NetCon connection is absent",
            )
        })?;
        self.check()?;
        check()?;
        // SAFETY: retained exact GUID-selected object and validated terminated name.
        com::result("INetConnection::Rename", unsafe {
            (connection.table().rename)(connection.raw(), name.as_ptr())
        })?;
        check()?;
        let actual = self.row()?;
        let end = actual
            .Alias
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(io::ErrorKind::InvalidData)?;
        if actual.Alias[..end] != name[..name.len() - 1] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native renamed alias differs",
            ));
        }
        Ok(())
    }
}
