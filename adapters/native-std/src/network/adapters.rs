//! Original bounded GetAdaptersAddresses allocation and checked SDK views.
use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA},
    NetworkManagement::IpHelper::{GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH},
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
    },
};
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub(crate) struct Block([u8; 16]);
pub(crate) struct Snapshot {
    pub(crate) blocks: Vec<Block>,
    pub(crate) used: usize,
}
pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
impl Snapshot {
    pub(crate) fn new(bytes: usize, maximum: usize) -> io::Result<Self> {
        let count = bytes.div_ceil(size_of::<Block>());
        let capacity = count
            .checked_mul(size_of::<Block>())
            .filter(|n| *n <= maximum && *n <= u32::MAX as usize)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "native adapter snapshot capacity",
                )
            })?;
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(count)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        blocks.resize(count, Block([0; 16]));
        Ok(Self {
            blocks,
            used: capacity,
        })
    }
    pub(crate) fn base(&self) -> *const u8 {
        self.blocks.as_ptr().cast()
    }
    pub(crate) fn contains(&self, pointer: *const u8, bytes: usize) -> io::Result<()> {
        let offset = (pointer as usize)
            .checked_sub(self.base() as usize)
            .ok_or_else(|| invalid("native adapter pointer precedes snapshot"))?;
        if offset.checked_add(bytes).is_none_or(|end| end > self.used) {
            return Err(invalid("native adapter pointer exceeds snapshot"));
        }
        Ok(())
    }
    /// # Safety
    /// T is an all-bit-pattern-valid, destructor-free native scalar/SDK layout.
    /// Callers inspect only complete fields included in `bytes`; a short prefix
    /// leaves the remaining fields at their native zero default.
    #[expect(
        unsafe_code,
        reason = "Private callers select only plain Windows SDK layouts; checked initialized snapshot bytes are copied into an aligned default value"
    )]
    pub(crate) unsafe fn read<T: Default>(&self, pointer: *const T, bytes: usize) -> io::Result<T> {
        self.contains(pointer.cast(), bytes)?;
        let mut value = T::default();
        // SAFETY: the private caller guarantees T's representation and fields;
        // the checked source lives in initialized blocks, independently of value.
        unsafe {
            ptr::copy_nonoverlapping(
                pointer.cast::<u8>(),
                (&mut value as *mut T).cast(),
                bytes.min(size_of::<T>()),
            );
        }
        Ok(value)
    }
    #[expect(
        unsafe_code,
        reason = "Native record Length is a bounded u32 header; callers supply SDK records whose complete declared extent is validated before prefix interpretation"
    )]
    pub(crate) fn record_length(&self, pointer: *const u8, minimum: usize) -> io::Result<usize> {
        // SAFETY: u32 has no invalid bit patterns or destructor.
        let length = unsafe { self.read(pointer.cast::<u32>(), size_of::<u32>())? } as usize;
        if length < minimum {
            return Err(invalid("native adapter record is too short"));
        }
        self.contains(pointer, length)?;
        Ok(length)
    }
    #[expect(
        unsafe_code,
        reason = "Only complete plain SDK socket layouts and initialized scalar unions are read from checked snapshot extents"
    )]
    pub(crate) fn address(
        &self,
        socket: SOCKET_ADDRESS,
        scope_index: u32,
    ) -> io::Result<SocketAddr> {
        let size = usize::try_from(socket.iSockaddrLength)
            .map_err(|_| invalid("negative native adapter socket-address size"))?;
        let pointer = socket.lpSockaddr.cast::<u8>();
        self.contains(pointer, size)?;
        if size < size_of::<u16>() {
            return Err(invalid("native adapter socket address has no family"));
        }
        // SAFETY: u16 is a plain scalar and its complete extent is checked.
        let family = unsafe { self.read(pointer.cast::<u16>(), size_of::<u16>())? };
        let address = match family {
            AF_INET if size >= size_of::<SOCKADDR_IN>() => {
                // SAFETY: the original address contains a complete plain SDK IPv4 layout.
                let value =
                    unsafe { self.read(pointer.cast::<SOCKADDR_IN>(), size_of::<SOCKADDR_IN>())? };
                // SAFETY: the S_addr union member is an initialized plain u32.
                let ip = Ipv4Addr::from(unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes());
                SocketAddr::new(ip.into(), u16::from_be(value.sin_port))
            }
            AF_INET6 if size >= size_of::<SOCKADDR_IN6>() => {
                // SAFETY: the original address contains a complete plain SDK IPv6 layout.
                let value = unsafe {
                    self.read(pointer.cast::<SOCKADDR_IN6>(), size_of::<SOCKADDR_IN6>())?
                };
                // SAFETY: both union members contain initialized address/scalar data.
                let ip = Ipv6Addr::from(unsafe { value.sin6_addr.u.Byte });
                // SAFETY: scope_id is the initialized scalar union member.
                let mut scope = unsafe { value.Anonymous.sin6_scope_id };
                if scope == 0 && ip.is_unicast_link_local() {
                    scope = scope_index;
                }
                if scope == 0 && ip.is_unicast_link_local() {
                    return Err(invalid(
                        "link-local interface address has no interface scope",
                    ));
                }
                SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    u16::from_be(value.sin6_port),
                    value.sin6_flowinfo,
                    scope,
                ))
            }
            _ => {
                return Err(invalid(
                    "unsupported or truncated native adapter socket address",
                ));
            }
        };
        Ok(address)
    }
    #[expect(
        unsafe_code,
        reason = "GetAdaptersAddresses fills one initialized bounded 16-byte-aligned allocation; returned extents are checked before views exist"
    )]
    pub(crate) fn capture(maximum: usize, flags: u32) -> io::Result<Option<Self>> {
        if maximum < size_of::<IP_ADAPTER_ADDRESSES_LH>() || maximum > u32::MAX as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut capacity = (15 * 1024).min(maximum);
        for _ in 0..3 {
            let mut snapshot = Snapshot::new(capacity, maximum)?;
            let mut length = snapshot.used as u32;
            // SAFETY: initialized aligned blocks have precisely the supplied writable
            // extent; the reserved pointer is null and only DNS lists are requested.
            let code = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    ptr::null(),
                    snapshot.blocks.as_mut_ptr().cast(),
                    &mut length,
                )
            };
            if code == 0 {
                if length as usize > snapshot.used {
                    return Err(invalid("native DNS output exceeds its allocation"));
                }
                snapshot.used = length as usize;
                return Ok(Some(snapshot));
            }
            if code == ERROR_NO_DATA {
                return Ok(None);
            }
            if code != ERROR_BUFFER_OVERFLOW
                || length as usize <= snapshot.used
                || length as usize > maximum
            {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            capacity = length as usize;
        }
        Err(io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32))
    }
}
