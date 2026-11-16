//! Bounded owned name/index inventory, including interfaces without IP addresses.
use std::io;
pub(super) const MAXIMUM: usize = 4096;
#[derive(Clone, Copy)]
pub(super) struct Name {
    pub bytes: [u8; 16],
    pub index: u32,
}
struct List(*mut libc::if_nameindex);
impl Drop for List {
    #[expect(
        unsafe_code,
        reason = "Release exactly the live if_nameindex allocation owned by this RAII object"
    )]
    fn drop(&mut self) {
        // SAFETY: successful nonnull allocation, never freed or lent elsewhere.
        unsafe { libc::if_freenameindex(self.0) };
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or oversized native interface name inventory",
    )
}
#[expect(
    unsafe_code,
    reason = "Read one owned libc name/index array and bounded NUL-terminated names; all views end before its owner drops"
)]
pub(super) fn snapshot() -> io::Result<Vec<Name>> {
    // SAFETY: this read-only libc API returns one owned sentinel-terminated array.
    let head = unsafe { libc::if_nameindex() };
    if head.is_null() {
        return Err(io::Error::last_os_error());
    }
    let owner = List(head);
    let mut names = Vec::new();
    for ordinal in 0..=MAXIMUM {
        // SAFETY: the array includes all entries followed by its native sentinel;
        // traversal stops there, or at the explicit retained/traversal bound.
        let row = unsafe { &*owner.0.add(ordinal) };
        if row.if_index == 0 && row.if_name.is_null() {
            return Ok(names);
        }
        if ordinal == MAXIMUM || row.if_index == 0 || row.if_name.is_null() {
            return Err(invalid());
        }
        // SAFETY: the owned array retains this native NUL-terminated name.
        let length = unsafe { libc::strnlen(row.if_name, 16) };
        if length == 0 || length >= 16 {
            return Err(invalid());
        }
        let mut bytes = [0; 16];
        // SAFETY: bounded length before the native terminator, allocation live.
        bytes[..length]
            .copy_from_slice(unsafe { std::slice::from_raw_parts(row.if_name.cast(), length) });
        crate::recovery::read_name(&bytes)?;
        names.try_reserve(1).map_err(io::Error::other)?;
        names.push(Name {
            bytes,
            index: row.if_index,
        });
    }
    Err(invalid())
}
#[expect(
    unsafe_code,
    reason = "if_indextoname writes one initialized IFNAMSIZ buffer; only its original live buffer is read"
)]
pub(super) fn locate(index: u32) -> io::Result<Option<[u8; 16]>> {
    let mut bytes = [0; 16];
    // SAFETY: exact native IFNAMSIZ array; the returned pointer is not dereferenced.
    let returned = unsafe { libc::if_indextoname(index, bytes.as_mut_ptr().cast()) };
    if returned.is_null() {
        let error = io::Error::last_os_error();
        return if matches!(
            error.raw_os_error(),
            Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
        ) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if returned != bytes.as_mut_ptr().cast() {
        return Err(invalid());
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .filter(|end| *end != 0)
        .ok_or_else(invalid)?;
    std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())?;
    // Native C strings promise a terminator, not zero padding after it.
    bytes[end..].fill(0);
    Ok(Some(bytes))
}
