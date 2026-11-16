//! Original stdout handle writes without acquiring Rust's global stdout lock.
use std::{
    fs::File,
    io::{self, Write},
    os::windows::io::{AsHandle, AsRawHandle},
};
use windows_sys::Win32::{
    Foundation::ERROR_INVALID_HANDLE,
    Storage::FileSystem::{FILE_TYPE_CHAR, GetFileType},
    System::Console::{GetConsoleMode, WriteConsoleW},
};

/// Retained duplicate of the original process stdout route. Console writes use
/// Unicode; file/pipe writes preserve bytes. No process standard route changes.
/// The caller owns exclusive output use and excludes stdio-route mutation while
/// capturing. This writer can block; runtimes must offload it explicitly.
#[derive(Debug)]
pub struct Output {
    file: File,
    console: bool,
}
impl Output {
    /// Consume this original route and return its single native close result.
    pub fn close(self) -> io::Result<()> {
        crate::filesystem::close(self.file)
    }
    /// Duplicate the current native stdout handle before admitting output work.
    ///
    /// # Errors
    /// Preserves handle duplication and native classification errors. Missing
    /// stdout is an error, not a successful sink. NUL remains an actual device.
    pub fn stdout() -> io::Result<Self> {
        Self::from_file(File::from(io::stdout().as_handle().try_clone_to_owned()?))
    }
    /// Duplicate stdout for uninterpreted bytes, including console routes.
    ///
    /// # Errors
    /// Preserves the original handle/descriptor duplication failure.
    pub fn stdout_bytes() -> io::Result<Self> {
        Ok(Self {
            file: File::from(io::stdout().as_handle().try_clone_to_owned()?),
            console: false,
        })
    }
    /// Duplicate the current native stderr handle without changing its route.
    ///
    /// # Errors
    /// Preserves duplication and native classification failures.
    pub fn stderr() -> io::Result<Self> {
        Self::from_file(File::from(io::stderr().as_handle().try_clone_to_owned()?))
    }
    #[expect(
        unsafe_code,
        reason = "Native type/mode queries borrow the owned file and initialized scalar output"
    )]
    fn from_file(file: File) -> io::Result<Self> {
        let mut mode = 0;
        // SAFETY: the retained file keeps the original handle live throughout.
        let character = unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_CHAR;
        let console = if character {
            // SAFETY: mode is one initialized CONSOLE_MODE output.
            if unsafe { GetConsoleMode(file.as_raw_handle(), &mut mode) } != 0 {
                true
            } else {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_INVALID_HANDLE as i32) {
                    return Err(error);
                }
                false
            }
        } else {
            false
        };
        Ok(Self { file, console })
    }
}
impl Write for Output {
    #[expect(
        unsafe_code,
        reason = "WriteConsoleW borrows one original live output handle and initialized bounded UTF-16 input/output for a synchronous call"
    )]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.console {
            return self.file.write(bytes);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let text = &text[..text.floor_char_boundary(4096)];
        if text.is_empty() {
            return Ok(0);
        }
        let mut wide = [0_u16; 4096];
        let mut count = 0;
        for unit in text.encode_utf16() {
            wide[count] = unit;
            count += 1;
        }
        let mut written = 0;
        // SAFETY: count is bounded by UTF-8 bytes <=4096; original file and both
        // buffers remain live and exclusive. Reserved parameter is null.
        if unsafe {
            WriteConsoleW(
                self.file.as_raw_handle(),
                wide.as_ptr(),
                count as u32,
                &mut written,
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut units = 0;
        let mut consumed = 0;
        for character in text.chars() {
            if units == written as usize {
                return Ok(consumed);
            }
            units += character.len_utf16();
            consumed += character.len_utf8();
        }
        if units == written as usize {
            Ok(consumed)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "console write split a Unicode scalar or exceeded its input",
            ))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
