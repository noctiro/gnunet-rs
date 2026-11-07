//! Original-descriptor source binding; no mutable input path is reopened and no
//! whole-file Rust input allocation is needed for this ordinary file profile.
use crate::{Extraction, Failure, NativeError, PanicPayload, Provider, native};
use std::{
    ffi::CString,
    fmt::Write,
    fs::{self, File, Metadata},
    io::{Seek, SeekFrom},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    panic::{AssertUnwindSafe, catch_unwind},
};

/// Original regular-file identity/extent/timestamps. This is a source guard, not
/// a new cryptographic identity; the publication must still bind its real CHK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStamp {
    dev: u64,
    ino: u64,
    bytes: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl SourceStamp {
    fn metadata(m: &Metadata) -> Result<Self, NativeError> {
        if !m.is_file() {
            return Err(NativeError::Invalid("regular extraction source"));
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            bytes: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        })
    }
    fn of(file: &File) -> Result<Self, NativeError> {
        Self::metadata(&file.metadata().map_err(|source| NativeError::Io {
            operation: "stat original extraction descriptor",
            source,
        })?)
    }
    /// Exact original file extent admitted to extraction.
    #[must_use]
    pub fn bytes(self) -> u64 {
        self.bytes
    }
    /// Compare this source with the same descriptor after actual CHK preparation.
    /// Caller must apply its original guard before/after this filesystem boundary.
    pub fn verify(self, file: &File) -> Result<bool, NativeError> {
        Ok(Self::of(file)? == self)
    }
}
/// Actual provider observation plus the same original descriptor stamp.
#[derive(Debug)]
pub struct FileExtraction {
    /// Original regular-file source; verify again around the actual CHK plan.
    pub source: SourceStamp,
    /// Actual metadata observations, never a publication success receipt.
    pub metadata: Extraction,
}

fn descriptor_name(file: &File) -> Result<CString, NativeError> {
    let prefix = if cfg!(target_os = "linux") {
        "/proc/self/fd/"
    } else if cfg!(target_os = "macos") {
        "/dev/fd/"
    } else {
        return Err(NativeError::DescriptorProfileUnavailable);
    };
    let mut name = String::new();
    name.try_reserve_exact(64)
        .map_err(|_| NativeError::Limit("descriptor name"))?;
    write!(&mut name, "{prefix}{}", file.as_raw_fd())
        .map_err(|_| NativeError::Limit("descriptor name formatting"))?;
    CString::new(name).map_err(|_| NativeError::Invalid("descriptor name"))
}
impl Provider {
    /// Extract from the actual held read-only regular File through the native
    /// descriptor namespace. No original mutable pathname or whole-file Rust
    /// copy is used; the leaf starts no child. Missing /proc or /dev/fd is an
    /// actual failure, not a fallback to a different file or reduced metadata.
    ///
    /// The caller exclusively owns source positioning for this synchronous
    /// phase (including any duplicated handles). macOS /dev/fd may share the OFD
    /// cursor; this method seeks to zero and restores the original cursor on all
    /// ordinary success/error paths. Restore failure remains an independent
    /// error. Native provider crashes/nonreturning calls cannot be repaired here.
    /// Its filename lacks the original extension; extension-dependent plugins
    /// are a conditional profile limitation, not claimed identical metadata.
    pub fn extract_file<E>(
        &mut self,
        file: &File,
        mut guard: impl FnMut() -> Result<(), E>,
    ) -> Result<FileExtraction, Failure<E>> {
        guard().map_err(Failure::caller)?;
        native::readonly(file).map_err(Failure::native)?;
        guard().map_err(Failure::caller)?;
        let stamp = SourceStamp::of(file).map_err(Failure::native)?;
        if stamp.bytes > self.limits().source_bytes {
            return Err(Failure::native(NativeError::Limit("source file extent")));
        }
        guard().map_err(Failure::caller)?;
        let mut cursor = file;
        let saved = cursor.stream_position().map_err(|source| {
            Failure::native(NativeError::Io {
                operation: "capture original file position",
                source,
            })
        })?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            guard().map_err(Failure::caller)?;
            let path = descriptor_name(file).map_err(Failure::native)?;
            guard().map_err(Failure::caller)?;
            let m = fs::metadata(std::path::Path::new(std::ffi::OsStr::from_bytes(
                path.as_bytes(),
            )))
            .map_err(|source| {
                Failure::native(NativeError::Io {
                    operation: "stat original descriptor namespace",
                    source,
                })
            })?;
            if SourceStamp::metadata(&m).map_err(Failure::native)? != stamp {
                return Err(Failure::native(NativeError::SourceChanged));
            }
            guard().map_err(Failure::caller)?;
            cursor.seek(SeekFrom::Start(0)).map_err(|source| {
                Failure::native(NativeError::Io {
                    operation: "position original extraction source",
                    source,
                })
            })?;
            guard().map_err(Failure::caller)?;
            let metadata = self.extract_filename(&path, &mut guard)?;
            guard().map_err(Failure::caller)?;
            if SourceStamp::of(file).map_err(Failure::native)? != stamp {
                return Err(Failure::native(NativeError::SourceChanged));
            }
            guard().map_err(Failure::caller)?;
            Ok(FileExtraction {
                source: stamp,
                metadata,
            })
        }))
        .unwrap_or_else(|payload| {
            Err(Failure::native(NativeError::CallbackPanicked(
                PanicPayload(payload),
            )))
        });
        // Cleanup must not be blocked by the expired business deadline. Keep an
        // original failure if restoration also fails; do not mask either errno.
        let restored = cursor.seek(SeekFrom::Start(saved));
        match (result, restored) {
            (Ok(value), Ok(_)) => {
                guard().map_err(Failure::caller)?;
                Ok(value)
            }
            (Err(error), Ok(_)) => Err(error),
            (Ok(_), Err(source)) => Err(Failure::native(NativeError::Io {
                operation: "restore original file position",
                source,
            })),
            (Err(mut error), Err(source)) => {
                error.restore = Some(source);
                Err(error)
            }
        }
    }
}

use std::os::unix::ffi::OsStrExt;
