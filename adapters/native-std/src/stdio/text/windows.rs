//! Console classification and wide reading on the retained original handle.
use super::utf16::{Buffer, UNITS};
use std::{
    fs::File,
    io::{self, Read},
    os::windows::io::AsRawHandle,
};
use windows_sys::Win32::{
    Foundation::ERROR_INVALID_HANDLE,
    System::Console::{GetConsoleMode, ReadConsoleW},
};
pub(super) enum Mode {
    Unknown,
    Bytes,
    Console(Box<Buffer>),
}
impl Mode {
    #[expect(
        unsafe_code,
        reason = "Native console calls borrow the retained original handle and exact initialized bounded UTF-16/DWORD output storage"
    )]
    pub(super) fn read(&mut self, file: &mut File, output: &mut [u8]) -> io::Result<usize> {
        if matches!(self, Self::Unknown) {
            let mut mode = 0;
            // SAFETY: original remains owned and the exact DWORD output is live.
            if unsafe { GetConsoleMode(file.as_raw_handle(), &mut mode) } != 0 {
                *self = Self::Console(Box::new(Buffer::new()));
            } else {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_INVALID_HANDLE as i32) {
                    return Err(error);
                }
                *self = Self::Bytes;
            }
        }
        match self {
            Self::Bytes => file.read(output),
            Self::Console(buffer) => loop {
                if let Some(count) = buffer.copy(output)? {
                    return Ok(count);
                }
                let mut units = [0u16; UNITS];
                let mut count = 0;
                // SAFETY: exact initialized UTF-16 extent, live original input
                // handle, DWORD count and no optional console-control structure.
                if unsafe {
                    ReadConsoleW(
                        file.as_raw_handle(),
                        units.as_mut_ptr().cast(),
                        UNITS as u32,
                        &mut count,
                        std::ptr::null(),
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let units = units
                    .get(..count as usize)
                    .ok_or(io::ErrorKind::InvalidData)?;
                buffer.feed(units)?;
            },
            Self::Unknown => Err(io::Error::other("console classification was not retained")),
        }
    }
}
