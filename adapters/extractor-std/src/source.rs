//! Original-object source binding. Platform input lifetimes and cleanup stay
//! below the common identity, extent, cancellation and callback contracts.
#[cfg(unix)]
mod descriptor;
#[cfg(windows)]
mod mapped;
use crate::{Extraction, Failure, NativeError, Provider};
#[cfg(unix)]
use descriptor as platform;
use gnunet_native::filesystem::{EntryInfo, FileInfo, file_info, validate_readonly};
#[cfg(windows)]
use mapped as platform;
use std::fs::File;
/// Original native identity, extent and change fences, independent of the CHK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStamp(FileInfo);
impl SourceStamp {
    fn of(file: &File) -> Result<Self, NativeError> {
        match file_info(file).map_err(|source| NativeError::Io {
            operation: "observe original extraction file",
            source,
        })? {
            EntryInfo::File(info) => Ok(Self(info)),
            _ => Err(NativeError::Invalid("ordinary extraction file")),
        }
    }
    /// Original regular-file extent admitted to extraction.
    #[must_use]
    pub fn bytes(self) -> u64 {
        self.0.bytes
    }
    /// Recheck the same descriptor after actual CHK preparation. The caller
    /// applies its original guard around this native observation.
    pub fn verify(self, file: &File) -> Result<bool, NativeError> {
        Ok(Self::of(file)? == self)
    }
}
/// Actual metadata observation and its same original source fence.
#[derive(Debug)]
pub struct FileExtraction {
    /// Verify this original source again around actual CHK preparation.
    pub source: SourceStamp,
    /// Actual callbacks, never a publication success receipt.
    pub metadata: Extraction,
}
impl Provider {
    /// Extract a held ordinary read-only file without reopening its original
    /// pathname or copying the complete file into a Rust heap buffer. Unix uses
    /// its descriptor namespace; Windows pins a read-only original-file view.
    ///
    /// The caller exclusively owns source positioning during this synchronous
    /// phase, including duplicated handles. Unix restores the original cursor
    /// after success, error or caught Rust panic. Windows never changes it.
    /// Native crashes, in-page exceptions and nonreturning plugins remain native
    /// provider limitations. Source mutation is detected, not made atomic.
    pub fn extract_file<E>(
        &mut self,
        file: &File,
        mut guard: impl FnMut() -> Result<(), E>,
    ) -> Result<FileExtraction, Failure<E>> {
        guard().map_err(Failure::caller)?;
        validate_readonly(file).map_err(|source| {
            Failure::native(NativeError::Io {
                operation: "qualify original read-only extraction handle",
                source,
            })
        })?;
        guard().map_err(Failure::caller)?;
        let stamp = SourceStamp::of(file).map_err(Failure::native)?;
        if stamp.bytes() > self.limits().source_bytes {
            return Err(Failure::native(NativeError::Limit("source file extent")));
        }
        guard().map_err(Failure::caller)?;
        let metadata = platform::extract(self, file, stamp, &mut guard)?;
        guard().map_err(Failure::caller)?;
        if !stamp.verify(file).map_err(Failure::native)? {
            return Err(Failure::native(NativeError::SourceChanged));
        }
        guard().map_err(Failure::caller)?;
        Ok(FileExtraction {
            source: stamp,
            metadata,
        })
    }
}
