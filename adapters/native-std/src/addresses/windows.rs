//! Winsock's wide resolver, native hints and bounded complete result ownership.
use super::*;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::windows::ffi::{OsStrExt, OsStringExt},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::{
    ADDRINFOW, AF_INET, AF_INET6, FreeAddrInfoW, GetAddrInfoW, SOCKADDR_IN, SOCKADDR_IN6,
};
const NAME_UNITS: usize = 65_535;

struct AddressInfo(*mut ADDRINFOW);
impl Drop for AddressInfo {
    #[expect(
        unsafe_code,
        reason = "A successful nonnull GetAddrInfoW allocation creates the unique guard; every copied result owns its data before this complete list is freed once"
    )]
    fn drop(&mut self) {
        // SAFETY: uniquely owned complete native allocation, never exposed.
        unsafe { FreeAddrInfoW(self.0) };
    }
}

/// Resolve with the exact supplied native hints and a genuinely NULL service.
/// Ordinary names may consult system DNS; numeric-only tests set AI_NUMERICHOST.
/// Complete addresses and canonical native strings are copied before releasing
/// the original allocation. Capacity errors never return a partial list.
#[expect(
    unsafe_code,
    reason = "Initialized native hints/input/output slots stay live for GetAddrInfoW; the unique guard owns the returned native list through validated sockaddr and bounded wide-string copies"
)]
pub fn resolve(host: &OsStr, hints: Hints, maximum: usize) -> Result<Vec<Address>, Error> {
    if maximum == 0 {
        return Err(Error::Capacity);
    }
    let units = host.encode_wide().take(NAME_UNITS + 1).count();
    if units > NAME_UNITS {
        return Err(Error::Capacity);
    }
    let mut name = Vec::new();
    name.try_reserve_exact(units + 1)
        .map_err(|_| Error::Capacity)?;
    name.extend(host.encode_wide());
    if name.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "BINDTO contains NUL").into());
    }
    name.push(0);
    let _winsock = crate::windows::Winsock::start()?;
    let native = ADDRINFOW {
        ai_family: hints.family,
        ai_socktype: hints.socket_type,
        ai_protocol: hints.protocol,
        ai_flags: hints.flags,
        ..ADDRINFOW::default()
    };
    let mut head = ptr::null_mut();
    // SAFETY: terminated wide input, null service, fully initialized hints and
    // exact writable result slot live until the synchronous lookup returns.
    let code = unsafe { GetAddrInfoW(name.as_ptr(), ptr::null(), &native, &mut head) };
    if code != 0 {
        return Err(Error::Resolution {
            code,
            message: OsString::from(io::Error::from_raw_os_error(code).to_string()),
        });
    }
    if head.is_null() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "empty native addrinfo result").into(),
        );
    }
    let owner = AddressInfo(head);
    let mut cursor = owner.0;
    let mut results = Vec::new();
    while !cursor.is_null() {
        if results.len() == maximum {
            return Err(Error::Capacity);
        }
        // SAFETY: successful GetAddrInfoW owns an initialized acyclic list.
        let record = unsafe { &*cursor };
        if record.ai_addr.is_null() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let address = match record.ai_family {
            family if family == i32::from(AF_INET) => {
                if record.ai_addrlen < size_of::<SOCKADDR_IN>() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                // SAFETY: family and minimum length select the native v4 layout.
                let address = unsafe { ptr::read_unaligned(record.ai_addr.cast::<SOCKADDR_IN>()) };
                // SAFETY: the documented S_addr member holds the v4 bytes.
                let ip = unsafe { address.sin_addr.S_un.S_addr };
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(ip.to_ne_bytes()),
                    u16::from_be(address.sin_port),
                ))
            }
            family if family == i32::from(AF_INET6) => {
                if record.ai_addrlen < size_of::<SOCKADDR_IN6>() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                // SAFETY: family and minimum length select the native v6 layout;
                // the byte and scope-id union members match this socket record.
                let address = unsafe { ptr::read_unaligned(record.ai_addr.cast::<SOCKADDR_IN6>()) };
                // SAFETY: the validated IPv6 record initializes these documented
                // byte-array and scope-id union members.
                let (ip, scope) =
                    unsafe { (address.sin6_addr.u.Byte, address.Anonymous.sin6_scope_id) };
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    u16::from_be(address.sin6_port),
                    address.sin6_flowinfo,
                    scope,
                ))
            }
            family => return Err(Error::Family(family)),
        };
        let canonical = if record.ai_canonname.is_null() {
            None
        } else {
            let mut length = 0;
            // SAFETY: the guarded optional native canonical string is terminated.
            // Stop at the copy bound instead of scanning/allocating without limit.
            while length < NAME_UNITS && unsafe { *record.ai_canonname.add(length) } != 0 {
                length += 1;
            }
            if length == NAME_UNITS {
                return Err(Error::Capacity);
            }
            // SAFETY: the bounded scan established this initialized extent.
            Some(OsString::from_wide(unsafe {
                std::slice::from_raw_parts(record.ai_canonname, length)
            }))
        };
        results.try_reserve(1).map_err(|_| Error::Capacity)?;
        results.push(Address {
            address,
            family: record.ai_family,
            socket_type: record.ai_socktype,
            protocol: record.ai_protocol,
            flags: record.ai_flags,
            canonical,
        });
        cursor = record.ai_next;
    }
    Ok(results)
}
