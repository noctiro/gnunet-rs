//! Original-object positional reads without changing the caller's file cursor.
use super::{EntryInfo, file_info};
use std::{fs::File, io};
/// A private read view over an original ordinary file. Unix uses pread; Windows
/// reopens the same held object with an independent native file pointer.
#[derive(Debug)]
pub struct FileReader {
    file: File,
}
impl FileReader {
    /// Retain a read view without resolving the original pathname. Native I/O
    /// can block. Source identity/change fencing remains the caller's task.
    pub fn from_file(file: &File) -> io::Result<Self> {
        if !matches!(file_info(file)?, EntryInfo::File(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary file reader required",
            ));
        }
        #[cfg(unix)]
        let file = file.try_clone()?;
        #[cfg(windows)]
        let file = {
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_DELETE,
                FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            crate::paths::relative::open::reopen(
                file,
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?
        };
        Ok(Self { file })
    }
    /// Fill an exact range while preserving the caller's original file cursor.
    /// Unexpected EOF, offset overflow and native errors remain failures.
    pub fn read_exact_at(&self, mut output: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !output.is_empty() {
            match self.read_at(output, offset) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short original file range",
                    ));
                }
                Ok(n) => {
                    offset = offset
                        .checked_add(u64::try_from(n).map_err(|_| io::ErrorKind::InvalidInput)?)
                        .ok_or(io::ErrorKind::InvalidInput)?;
                    output = &mut output[n..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    /// Read at an absolute byte offset. The caller's source cursor is untouched;
    /// short reads and original native errors are preserved.
    pub fn read_at(&self, output: &mut [u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_at(output, offset)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            self.file.seek_read(output, offset)
        }
    }
}
