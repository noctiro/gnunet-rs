//! Original Unix routes with owned descriptors and unchanged file status flags.
use std::{
    fs::File,
    io::{self, Write},
    os::fd::AsFd,
};
/// Independent descriptor for an original standard route. Writes can block;
/// callers must provide their own bounded execution and retirement policy.
#[derive(Debug)]
pub struct Output(File);
impl Output {
    /// Consume this original route and return its single native close result.
    pub fn close(self) -> io::Result<()> {
        crate::filesystem::close(self.0)
    }
    /// Duplicate stdout without acquiring its global formatting lock.
    ///
    /// # Errors
    /// Preserves the descriptor duplication failure.
    pub fn stdout() -> io::Result<Self> {
        Ok(Self(File::from(io::stdout().as_fd().try_clone_to_owned()?)))
    }
    /// Duplicate stdout for uninterpreted bytes, including console routes.
    ///
    /// # Errors
    /// Preserves the original handle/descriptor duplication failure.
    pub fn stdout_bytes() -> io::Result<Self> {
        Self::stdout()
    }
    /// Duplicate stderr without acquiring its global formatting lock.
    ///
    /// # Errors
    /// Preserves the descriptor duplication failure.
    pub fn stderr() -> io::Result<Self> {
        Ok(Self(File::from(io::stderr().as_fd().try_clone_to_owned()?)))
    }
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
