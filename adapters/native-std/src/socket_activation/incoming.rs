//! Exclusive fresh-child capture and one-shot native socket reconstruction.
use super::{
    mapping::View,
    record::{
        ACCESS_BYTES, AccessClaim, ENTRY, HEADER, ListenerKind, MAGIC, RECORD, VERSION, WORDS,
        decode_access, ensure_winsock, extent, matches_sid, socket_error,
    },
};
use crate::{
    identity::{self, Sid},
    local_path::{EndpointAccess, EndpointPrincipals, EndpointProtection, ProtectedAccess},
};
use std::{
    fmt, io,
    os::windows::io::{
        AsHandle, AsSocket, BorrowedHandle, FromRawHandle, FromRawSocket, OwnedHandle, OwnedSocket,
    },
    sync::atomic::{AtomicU32, Ordering},
};
use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_PROTECT_FROM_CLOSE,
        INVALID_HANDLE_VALUE, SetHandleInformation,
    },
    Networking::WinSock::{
        FROM_PROTOCOL_INFO, INVALID_SOCKET, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
        WSAPROTOCOL_INFOW, WSASocketW,
    },
    Security::Authorization::SE_KERNEL_OBJECT,
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        Memory::FILE_MAP_READ,
        Threading::GetCurrentProcessId,
    },
};

/// One imported provider descriptor and trusted local listener access evidence.
#[derive(Debug)]
pub struct ImportedSocket {
    socket: OwnedSocket,
    protection: Option<EndpointProtection>,
}
impl ImportedSocket {
    /// Transfer this exact unique descriptor and its verified publisher metadata.
    pub fn into_parts(self) -> (OwnedSocket, Option<EndpointProtection>) {
        (self.socket, self.protection)
    }
}

struct Publisher {
    receiver: OwnedHandle,
    custodian: Sid,
    user: Sid,
    group: Option<Sid>,
}

impl Publisher {
    fn verify(section: &OwnedHandle, route: &Route) -> io::Result<Self> {
        let receiver = identity::primary_token()?;
        let user = identity::token_user(&receiver)?;
        let custodian = match route {
            Route::Inherited => {
                let owner = identity::object_owner(section.as_handle(), SE_KERNEL_OBJECT)?;
                if owner != user {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "inherited protected listeners require a same-account publisher",
                    ));
                }
                owner
            }
            Route::Account { owner } => owner.clone(),
        };
        Ok(Self {
            receiver,
            custodian,
            user,
            group: None,
        })
    }

    fn principals(&mut self, claim: AccessClaim<'_>) -> io::Result<EndpointPrincipals> {
        if !matches_sid(claim.user, &self.user) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pre-listen endpoint user does not match the receiver",
            ));
        }
        let access = match claim.access {
            EndpointAccess::Owner => ProtectedAccess::Owner,
            EndpointAccess::Everyone => ProtectedAccess::Everyone,
            EndpointAccess::PrimaryGroup => {
                if self.group.is_none() {
                    self.group = Some(identity::token_primary_group(&self.receiver)?);
                }
                let group = self.group.as_ref().ok_or(io::ErrorKind::InvalidData)?;
                if !matches_sid(claim.group, group) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pre-listen endpoint group does not match the receiver",
                    ));
                }
                ProtectedAccess::PrimaryGroup(group.clone())
            }
        };
        Ok(EndpointPrincipals {
            custodian: self.custodian.clone(),
            user: self.user.clone(),
            access,
        })
    }
}

/// Original read-only section, captured before unrelated owners.
/// Import, discard or exit the fresh process: Drop closes the mapping but does
/// not settle still-unused provider reservations already installed in this PID.
#[must_use = "materialize/discard activation or exit the fresh process; provider reservations cannot be canceled by closing the section"]
pub struct Incoming {
    // View retires before its section handle.
    view: View,
    handle: OwnedHandle,
    count: usize,
    route: Route,
}
enum Route {
    Inherited,
    Account { owner: Sid },
}

#[derive(Clone, Copy)]
enum Offer<'a> {
    Inherited(Option<&'a str>),
    Bootstrap(&'a [u8]),
}

impl Offer<'_> {
    fn inherits(self) -> bool {
        matches!(self, Self::Inherited(_))
    }

    fn qualify(self, handle: BorrowedHandle<'_>) -> io::Result<Route> {
        if matches!(self, Self::Inherited(None)) {
            return Ok(Route::Inherited);
        }
        let owner = identity::object_owner(handle, SE_KERNEL_OBJECT)?;
        let matches_owner = match self {
            Self::Inherited(publisher) => publisher.is_some_and(|sid| owner.to_string() == sid),
            Self::Bootstrap(publisher) => owner.as_bytes() == publisher,
        };
        if !matches_owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "activation section owner does not match the original publisher",
            ));
        }
        Ok(Route::Account { owner })
    }
}
impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
impl Incoming {
    /// Adopt exactly one exclusively offered inherited section handle. No socket
    /// descriptor is adopted from an integer; actual sockets come from WSASocket.
    ///
    /// # Safety
    /// Fresh single-threaded child before files/runtime/other native owners. The
    /// handle is exclusively transferred foreign ownership, not any Rust/CRT or
    /// cached owner. The handle grants read-only mapping access. The native publisher finished immutable metadata before
    /// resuming this process; it retains no writable aliases. Repeated capture,
    /// concurrent close/reuse and continuing after capture failure are forbidden.
    #[expect(
        unsafe_code,
        reason = "Forward the caller's fresh-process inherited mapping ownership contract"
    )]
    pub unsafe fn capture(raw: usize) -> io::Result<Self> {
        // SAFETY: the caller establishes the inherited mapping's custody.
        unsafe { Self::capture_offer(raw, Offer::Inherited(None)) }
    }

    /// Capture an inherited section for a managed account. The mapping must
    /// admit both read-only mapping and owner query, and its kernel owner SID
    /// must equal the original publisher declared by the supervisor.
    ///
    /// # Safety
    /// The requirements of [`Self::capture`] apply. The expected publisher SID
    /// must be supplied by the original supervisor's controlled launch.
    #[expect(
        unsafe_code,
        reason = "Forward the original supervisor's launch evidence and the exclusive inherited handle"
    )]
    pub unsafe fn capture_inherited_account(raw: usize, publisher: &str) -> io::Result<Self> {
        // SAFETY: the caller establishes the inherited mapping's custody and publisher.
        unsafe { Self::capture_offer(raw, Offer::Inherited(Some(publisher))) }
    }

    /// Capture this process's noninheritable activation handle after authenticating
    /// its one cross-session grant. Both mapping read access and a native owner
    /// query must succeed. The actual owner must equal the signed binary SID.
    ///
    /// # Safety
    /// The original launch's verification key and intended recipient must have
    /// authenticated this exact grant. The original supervisor transferred
    /// exclusive ownership of a sealed, read-only handle into this process,
    /// with no Rust/CRT owner or other code that can close or reuse the raw slot.
    /// Consume once before listener registration. Capture failure or abandonment
    /// requires fresh-process exit to settle the original provider reservations.
    #[expect(
        unsafe_code,
        reason = "Forward the caller's authenticated cross-session grant and exclusive handle custody"
    )]
    pub unsafe fn capture_bootstrap(raw: usize, publisher: &[u8]) -> io::Result<Self> {
        // SAFETY: the caller authenticates the one grant and owns its raw slot.
        unsafe { Self::capture_offer(raw, Offer::Bootstrap(publisher)) }
    }

    #[expect(
        unsafe_code,
        reason = "Native validation of the caller's original mapping precedes unique ownership adoption"
    )]
    unsafe fn capture_offer(raw: usize, offer: Offer<'_>) -> io::Result<Self> {
        let handle = raw as *mut core::ffi::c_void;
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: scalar standard-table queries create no owners.
        let standards = unsafe {
            [
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetStdHandle(STD_ERROR_HANDLE),
            ]
        };
        if standards.contains(&handle) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "activation section aliases a standard route",
            ));
        }
        let mut flags = 0;
        // SAFETY: native validation of a scalar handle; no owner exists yet.
        if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if (flags & HANDLE_FLAG_INHERIT != 0) != offer.inherits()
            || flags & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let (view, count) = Self::published_view(handle)?;
        // SAFETY: the caller retains exclusive custody through this borrow.
        let route = offer.qualify(unsafe { BorrowedHandle::borrow_raw(handle) })?;
        // SAFETY: native section kind/extent validated; transfer is exclusive
        // and complete. Clear inheritance before unrelated child launches.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
        // SAFETY: original owned section, only its inheritance flag is changed.
        if offer.inherits() && unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            view,
            handle: owned,
            count,
            route,
        })
    }

    #[expect(
        unsafe_code,
        reason = "Read one aligned immutable header through its owned bounded native view"
    )]
    fn published_view(handle: HANDLE) -> io::Result<(View, usize)> {
        let mut header = View::new(handle, FILE_MAP_READ, HEADER)?;
        // SAFETY: immutable bounded header, native page alignment and publisher's
        // release ordering. No SDK metadata is consumed before complete validation.
        let magic = unsafe { &*header.pointer().cast::<AtomicU32>() }.load(Ordering::Acquire);
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unpublished native activation section",
            ));
        }
        let mut words = [0u32; 7];
        for (index, value) in words.iter_mut().enumerate() {
            // SAFETY: exact initialized immutable header word.
            *value = unsafe { header.pointer().add(4 + index * 4).cast::<u32>().read() };
        }
        let [version, count, record, target, total, reserved0, reserved1] = words;
        // SAFETY: scalar query with no resource transfer.
        let current = unsafe { GetCurrentProcessId() };
        if version != VERSION
            || record as usize != ENTRY
            || target != current
            || reserved0 != 0
            || reserved1 != 0
            || total as usize != extent(count as usize)?
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let view = View::new(handle, FILE_MAP_READ, total as usize)?;
        header.close()?;
        Ok((view, count as usize))
    }
    /// Materialize every one-shot native record, retaining no section after
    /// success. Failure can leave unused provider reservations: exit this fresh
    /// process rather than replaying or continuing with a partial activation.
    #[expect(
        unsafe_code,
        reason = "Immutable exact native records are copied into aligned initialized storage; only successful WSASocketW descriptors receive fresh unique Rust owners"
    )]
    pub fn materialize(mut self) -> io::Result<Vec<ImportedSocket>> {
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(self.count)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        ensure_winsock()?;
        let mut publisher = None;
        for index in 0..self.count {
            let mut words = [0u32; WORDS];
            // SAFETY: this entry lies within the validated section extent.
            let entry = unsafe { self.view.pointer().add(HEADER + index * ENTRY) };
            // SAFETY: both extents are exactly RECORD initialized bytes, disjoint;
            // u32 arrays preserve every ABI byte without reading Rust padding.
            unsafe {
                std::ptr::copy_nonoverlapping(entry, words.as_mut_ptr().cast::<u8>(), RECORD)
            };
            // SAFETY: compile-time size/alignment checks, all native fields are
            // integer/array/GUID values and accept every initialized bit pattern.
            let info = unsafe { &*words.as_ptr().cast::<WSAPROTOCOL_INFOW>() };
            // SAFETY: the fixed access bytes follow the complete provider
            // record and lie within the immutable view for this entry.
            let access =
                decode_access(unsafe { &*entry.add(RECORD).cast::<[u8; ACCESS_BYTES]>() })?;
            let kind = ListenerKind::from_protocol(info)?;
            if (access.is_some() && kind != ListenerKind::Local)
                || (matches!(self.route, Route::Account { .. })
                    && kind == ListenerKind::Local
                    && access.is_none())
                || !(-1..=7).contains(&info.ProtocolChain.ChainLen)
                || !info.szProtocol.contains(&0)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let access = match access {
                None => None,
                Some(claim) => {
                    let identity = claim.identity;
                    let publisher = match &mut publisher {
                        Some(publisher) => publisher,
                        None => publisher.insert(Publisher::verify(&self.handle, &self.route)?),
                    };
                    Some((identity, publisher.principals(claim)?))
                }
            };
            // SAFETY: complete original one-shot SDK record, no pointer retained.
            // Reuse is refused by Winsock with WSAEINVAL, never adopted twice.
            let raw = unsafe {
                WSASocketW(
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    info,
                    0,
                    WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                )
            };
            if raw == INVALID_SOCKET {
                return Err(socket_error());
            }
            // SAFETY: successful WSASocket returns one new uniquely owned socket.
            let socket = unsafe { OwnedSocket::from_raw_socket(raw as _) };
            let protection = match access {
                None => None,
                Some((identity, principals)) => Some(EndpointProtection::import(
                    socket.as_socket(),
                    identity,
                    principals,
                )?),
            };
            sockets.push(ImportedSocket { socket, protection });
        }
        self.view.close()?;
        Ok(sockets)
    }
    /// Consume and close all imported descriptors without registering/listening
    /// through another owner. Any failure still requires fresh-process exit.
    pub fn discard(self) -> io::Result<()> {
        self.materialize().map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::FileIdentity;
    use crate::socket_activation::{mapping::Writable, record::encode_access};

    #[test]
    fn protected_group_must_match_the_receivers_primary_token() -> io::Result<()> {
        let section = Writable::new(HEADER)?;
        let mut publisher = Publisher::verify(&section.read, &Route::Inherited)?;
        let mut identity = [0; 32];
        identity[0] = 2;
        identity[16] = 1;
        let identity = FileIdentity::from_bytes(identity).map_err(io::Error::other)?;
        let mut principals = EndpointPrincipals::for_current_process(EndpointAccess::PrimaryGroup)?;
        let original = encode_access(Some((&principals, identity)));
        let claim = decode_access(&original)?.ok_or(io::ErrorKind::InvalidData)?;
        if claim.identity != identity {
            return Err(io::Error::other(
                "activation changed the original file identity",
            ));
        }
        let group_authority = std::mem::size_of::<u32>() + claim.user.len() + 7;
        if !matches!(
            publisher.principals(claim)?.access,
            ProtectedAccess::PrimaryGroup(_)
        ) {
            return Err(io::Error::other("activation lost the primary group policy"));
        }
        // Keep the authentic user and group access mode while altering one
        // authority byte of the advertised group SID.
        let mut changed = original;
        changed[group_authority] ^= 1;
        let claim = decode_access(&changed)?.ok_or(io::ErrorKind::InvalidData)?;
        if !matches!(publisher.principals(claim), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        {
            return Err(io::Error::other(
                "activation accepted a different primary group",
            ));
        }
        principals.access = ProtectedAccess::Owner;
        let owner = encode_access(Some((&principals, identity)));
        let claim = decode_access(&owner)?.ok_or(io::ErrorKind::InvalidData)?;
        if !matches!(publisher.principals(claim)?.access, ProtectedAccess::Owner) {
            return Err(io::Error::other("activation lost the owner policy"));
        }
        Ok(())
    }
}
