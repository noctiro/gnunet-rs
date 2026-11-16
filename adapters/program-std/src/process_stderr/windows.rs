//! The native adapter owns all Win32/UCRT handles and partial-installation state.
use std::{fs::File, io};

/// Unique early-startup permission to replace both Windows stderr interfaces.
/// Dropping the permission leaves the installed process destinations live.
/// This capability is deliberately neither Send nor Sync.
pub struct ProcessStderr(gnunet_native::stdio::ProcessStderr);
impl ProcessStderr {
    /// Claim exclusive process standard-error installation authority.
    ///
    /// # Safety
    /// All Rust/foreign standard-stream users and process spawning must be
    /// quiescent during installation; flush buffered writers beforehand. No
    /// cached standard handle may span an installation. Until this capability is
    /// dropped, exclude unrelated stderr closure, replacement or ownership
    /// adoption. GetStdHandle results remain borrowed process-owned handles even
    /// after capability Drop. See the native capability for temporary standard
    /// descriptor preparation and partial-installation contracts.
    #[expect(
        unsafe_code,
        reason = "The caller explicitly establishes process-wide standard-stream exclusivity; the native capability retains that same precondition"
    )]
    pub unsafe fn claim() -> io::Result<Self> {
        // SAFETY: the caller establishes the native capability's full preconditions.
        unsafe { gnunet_native::stdio::ProcessStderr::claim() }.map(Self)
    }
    pub(crate) fn install(&mut self, file: &File) -> io::Result<()> {
        self.0.install(file).map_err(io::Error::other)
    }
}

// Rust Windows Files own Win32 handles, never CRT descriptor numbers. Native
// installation duplicates them without giving any standard slot to this File.
#[expect(
    clippy::unnecessary_wraps,
    reason = "The shared logging interface needs a fallible Unix descriptor lift; Windows handle ownership already excludes standard descriptor slots"
)]
pub(crate) fn lift(file: File) -> io::Result<File> {
    Ok(file)
}
