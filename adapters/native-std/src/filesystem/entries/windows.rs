use super::record;
use crate::filesystem::Directory;
use std::{
    ffi::OsString,
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
};
use windows_sys::Win32::{
    Foundation::ERROR_NO_MORE_FILES,
    Storage::FileSystem::{
        FILE_FULL_DIR_INFO, FileFullDirectoryInfo, FileFullDirectoryRestartInfo,
        GetFileInformationByHandleEx,
    },
};
const WORDS: usize = 512;
const _: () = {
    assert!(record::NAME == offset_of!(FILE_FULL_DIR_INFO, FileName));
    assert!(record::NAME_LENGTH == offset_of!(FILE_FULL_DIR_INFO, FileNameLength));
    assert!(record::NEXT == offset_of!(FILE_FULL_DIR_INFO, NextEntryOffset));
};
#[derive(Debug)]
enum Cursor {
    Restart,
    More,
    Buffered(usize),
    End,
}
/// Independent original-directory cursor with a reused aligned 4 KiB buffer.
/// Names preserve native UTF-16. EOF requires actual ERROR_NO_MORE_FILES;
/// failed queries and malformed records remain errors.
#[derive(Debug)]
pub struct Entries {
    directory: File,
    bytes: Box<[u64; WORDS]>,
    cursor: Cursor,
}
impl Entries {
    pub(crate) fn open(directory: &File) -> io::Result<Self> {
        // The independent native cursor selects the same held directory
        // without rebuilding its pathname.
        let directory = Directory::from_file(directory)?;
        Ok(Self {
            directory: directory.into_file(),
            bytes: Box::new([0; WORDS]),
            cursor: Cursor::Restart,
        })
    }
    #[expect(
        unsafe_code,
        reason = "A synchronous native query fills one aligned initialized owned buffer while its original directory handle remains live"
    )]
    fn fetch(&mut self) -> io::Result<()> {
        self.bytes.fill(0);
        let class = match self.cursor {
            Cursor::Restart => FileFullDirectoryRestartInfo,
            _ => FileFullDirectoryInfo,
        };
        // SAFETY: live original directory and aligned initialized output remain
        // exclusively owned throughout this synchronous native query.
        if unsafe {
            GetFileInformationByHandleEx(
                self.directory.as_raw_handle(),
                class,
                self.bytes.as_mut_ptr().cast(),
                size_of::<[u64; WORDS]>() as u32,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                self.cursor = Cursor::End;
                return Ok(());
            }
            return Err(error);
        }
        self.cursor = Cursor::Buffered(0);
        Ok(())
    }
    #[expect(
        unsafe_code,
        reason = "The entire u64 backing allocation is initialized before and after native byte writes; all bit patterns are valid and the immutable view cannot outlive its owner"
    )]
    fn buffer(&self) -> &[u8] {
        // SAFETY: complete initialized aligned allocation; immutable borrow.
        unsafe { std::slice::from_raw_parts(self.bytes.as_ptr().cast(), size_of::<[u64; WORDS]>()) }
    }
    fn read_name(&mut self) -> io::Result<Option<OsString>> {
        let mut dots = 0;
        loop {
            match self.cursor {
                Cursor::End => return Ok(None),
                Cursor::Restart | Cursor::More => self.fetch()?,
                Cursor::Buffered(at) => {
                    let record = record::parse(self.buffer(), at)?;
                    let next = record.next;
                    let mut name = [0; 255];
                    let length = record.name.len() / 2;
                    for (unit, pair) in name.iter_mut().zip(record.name.as_chunks::<2>().0) {
                        *unit = u16::from_le_bytes([pair[0], pair[1]]);
                    }
                    self.cursor = next.map_or(Cursor::More, Cursor::Buffered);
                    if matches!(&name[..length], [46] | [46, 46]) {
                        dots += 1;
                        if dots > 2 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "repeated native dot entries",
                            ));
                        }
                        continue;
                    }
                    return Ok(Some(OsString::from_wide(&name[..length])));
                }
            }
        }
    }
}
impl Iterator for Entries {
    type Item = io::Result<OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        let result = self.read_name();
        if result.is_err() {
            self.cursor = Cursor::End;
        }
        result.transpose()
    }
}
