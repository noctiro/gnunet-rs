//! Bounded native SDK record layout and process-lifetime Winsock initialization.
use crate::{
    filesystem::{FileIdentity, FileIdentityParts},
    identity::Sid,
    local_path::{EndpointAccess, EndpointPrincipals, ProtectedAccess},
};
use std::{
    io,
    mem::{align_of, size_of},
    sync::OnceLock,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNIX, IPPROTO_TCP, SOCK_STREAM, WSADATA, WSAGetLastError,
    WSAPROTOCOL_INFOW, WSAStartup,
};
use windows_sys::Win32::Security::SECURITY_MAX_SID_SIZE;
/// Maximum listeners admitted by one native startup transfer.
pub const MAX_LISTENERS: usize = 4096;
pub(super) const HEADER: usize = 32;
pub(super) const RECORD: usize = size_of::<WSAPROTOCOL_INFOW>();
pub(super) const WORDS: usize = RECORD / size_of::<u32>();
const SID_BYTES: usize = SECURITY_MAX_SID_SIZE as usize;
pub(super) const ACCESS_BYTES: usize = size_of::<u32>() + 2 * SID_BYTES + size_of::<[u8; 32]>();
pub(super) const ENTRY: usize = RECORD + ACCESS_BYTES;
pub(super) const MAGIC: u32 = 0x414e_5247;
pub(super) const VERSION: u32 = 3;
const _: () = assert!(
    RECORD.is_multiple_of(4)
        && ENTRY.is_multiple_of(4)
        && align_of::<WSAPROTOCOL_INFOW>() <= 4
        && cfg!(target_endian = "little")
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ListenerKind {
    Tcp,
    Local,
}

impl ListenerKind {
    pub(super) fn from_protocol(info: &WSAPROTOCOL_INFOW) -> io::Result<Self> {
        if info.iSocketType == SOCK_STREAM {
            if info.iAddressFamily == i32::from(AF_UNIX) {
                return Ok(Self::Local);
            }
            if info.iProtocol == IPPROTO_TCP
                && [i32::from(AF_INET), i32::from(AF_INET6)].contains(&info.iAddressFamily)
            {
                return Ok(Self::Tcp);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "activation requires a TCP or AF_UNIX stream listener",
        ))
    }
}

pub(super) fn extent(count: usize) -> io::Result<usize> {
    if count > MAX_LISTENERS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native activation listener capacity",
        ));
    }
    count
        .checked_mul(ENTRY)
        .and_then(|bytes| bytes.checked_add(HEADER))
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

pub(super) fn encode_access(
    protection: Option<(&EndpointPrincipals, FileIdentity)>,
) -> [u8; ACCESS_BYTES] {
    let mut output = [0; ACCESS_BYTES];
    if let Some((principals, identity)) = protection {
        let (kind, group) = match &principals.access {
            ProtectedAccess::Owner => (1u32, None),
            ProtectedAccess::PrimaryGroup(group) => (2, Some(group)),
            ProtectedAccess::Everyone => (3, None),
        };
        let (tag, retained) = output.split_at_mut(size_of::<u32>());
        let (sids, node) = retained.split_at_mut(2 * SID_BYTES);
        let (user, primary_group) = sids.split_at_mut(SID_BYTES);
        tag.copy_from_slice(&kind.to_ne_bytes());
        node.copy_from_slice(identity.as_bytes());
        write_sid(user, &principals.user);
        if let Some(group) = group {
            write_sid(primary_group, group);
        }
    }
    output
}

fn write_sid(slot: &mut [u8], sid: &Sid) {
    let bytes = sid.as_bytes();
    slot[..bytes.len()].copy_from_slice(bytes);
}

pub(super) struct AccessClaim<'a> {
    pub(super) access: EndpointAccess,
    pub(super) user: &'a [u8],
    pub(super) group: &'a [u8],
    pub(super) identity: FileIdentity,
}

pub(super) fn decode_access(bytes: &[u8; ACCESS_BYTES]) -> io::Result<Option<AccessClaim<'_>>> {
    let (tag, retained) = bytes.split_at(size_of::<u32>());
    let (sids, node) = retained.split_at(2 * SID_BYTES);
    let (user, group) = sids.split_at(SID_BYTES);
    let tag = u32::from_ne_bytes(tag.try_into().map_err(|_| io::ErrorKind::InvalidData)?);
    let access = match tag {
        0 if all_zero(retained) => return Ok(None),
        1 if all_zero(group) => EndpointAccess::Owner,
        2 => EndpointAccess::PrimaryGroup,
        3 if all_zero(group) => EndpointAccess::Everyone,
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    let identity =
        FileIdentity::from_bytes(node.try_into().map_err(|_| io::ErrorKind::InvalidData)?)
            .map_err(|_| io::ErrorKind::InvalidData)?;
    if !matches!(identity.parts(), FileIdentityParts::Windows { .. }) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(AccessClaim {
        access,
        user,
        group,
        identity,
    }))
}

pub(super) fn matches_sid(slot: &[u8], sid: &Sid) -> bool {
    if let Some((value, padding)) = slot.split_at_checked(sid.as_bytes().len()) {
        value == sid.as_bytes() && all_zero(padding)
    } else {
        false
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
#[expect(
    unsafe_code,
    reason = "WSAStartup fills exact writable WSADATA; one successful process-lifetime reference prevents reconstructed socket owners from outliving their Winsock initialization"
)]
pub(super) fn ensure_winsock() -> io::Result<()> {
    static STARTED: OnceLock<Result<(), i32>> = OnceLock::new();
    let result = STARTED.get_or_init(|| {
        let mut data = std::mem::MaybeUninit::<WSADATA>::uninit();
        // SAFETY: exact initialized extent, requested Winsock 2.2; the successful
        // reference is deliberately retained for this process's entire lifetime.
        let code = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
        if code == 0 { Ok(()) } else { Err(code) }
    });
    match result {
        Ok(()) => Ok(()),
        Err(code) => Err(io::Error::from_raw_os_error(*code)),
    }
}
#[expect(
    unsafe_code,
    reason = "WSAGetLastError reads the current thread's original Winsock error before any cleanup/native call"
)]
pub(super) fn socket_error() -> io::Error {
    // SAFETY: scalar observation with no borrowed storage.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
