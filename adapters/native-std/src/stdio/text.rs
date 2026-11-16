//! Original text input: native console Unicode, unchanged redirected bytes.
use std::{
    fs::File,
    io::{self, Read},
};
#[cfg(any(windows, test))]
mod utf16;
#[cfg(windows)]
mod windows;

/// One original input file. Windows consoles yield UTF-8 from ReadConsoleW;
/// redirected files/pipes and Unix inputs preserve their original bytes.
/// No shared buffering, console mode or code-page change is introduced.
pub struct TextInput {
    file: File,
    #[cfg(windows)]
    mode: windows::Mode,
}
impl std::fmt::Debug for TextInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextInput").finish_non_exhaustive()
    }
}
impl TextInput {
    /// Consume one original route without reading or probing it. Fallible native
    /// classification occurs on the first read while this owner retains it.
    pub fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(windows)]
            mode: windows::Mode::Unknown,
        }
    }
    /// Attempt consuming native close once. This does not report thread exit or
    /// independently acknowledge cancellation of an earlier blocking read.
    pub fn close(self) -> io::Result<()> {
        crate::filesystem::close(self.file)
    }
}
impl Read for TextInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        #[cfg(unix)]
        {
            self.file.read(output)
        }
        #[cfg(windows)]
        {
            self.mode.read(&mut self.file, output)
        }
    }
}
