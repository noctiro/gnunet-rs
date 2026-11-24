//! Common control-message fields across the native socket ABIs.
use std::io;

pub(crate) fn extent<T, U>(value: T) -> io::Result<U>
where
    T: TryInto<U>,
{
    value
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid native control extent"))
}

#[expect(
    unsafe_code,
    reason = "cmsghdr has only native integer fields and padding"
)]
pub(crate) fn header(length: usize, level: i32, kind: i32) -> io::Result<libc::cmsghdr> {
    // SAFETY: zero is valid for all fields, including the extra fields in musl.
    let mut header = unsafe { std::mem::zeroed::<libc::cmsghdr>() };
    header.cmsg_len = extent(length)?;
    header.cmsg_level = level;
    header.cmsg_type = kind;
    Ok(header)
}
