//! One bounded native filename, never an intermediate path or alternate stream.
use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt};
use windows_sys::Win32::Foundation::UNICODE_STRING;
pub(super) const MAX_UNITS: usize = 255;
pub(super) struct Leaf {
    units: [u16; MAX_UNITS],
    len: usize,
}
impl Leaf {
    pub(super) fn new(name: &OsStr) -> io::Result<Self> {
        let mut value = Self {
            units: [0; MAX_UNITS],
            len: 0,
        };
        for unit in name.encode_wide() {
            if value.len == MAX_UNITS || matches!(unit, 0 | 0x2f | 0x5c | 0x3a) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected one bounded native file component without streams",
                ));
            }
            value.units[value.len] = unit;
            value.len += 1;
        }
        if value.len == 0 || matches!(value.units(), [0x2e] | [0x2e, 0x2e]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary native file component required",
            ));
        }
        Ok(value)
    }
    pub(super) fn units(&self) -> &[u16] {
        &self.units[..self.len]
    }
    pub(super) fn unicode(&mut self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: (self.len * 2) as u16,
            MaximumLength: (self.len * 2) as u16,
            Buffer: self.units.as_mut_ptr(),
        }
    }
}
