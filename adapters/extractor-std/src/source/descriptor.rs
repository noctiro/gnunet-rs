//! POSIX descriptor-namespace input and original cursor restoration.
use super::{Extraction, Failure, File, NativeError, Provider, SourceStamp};
use crate::PanicPayload;
use gnunet_native::filesystem::{FileIdentity, FileInfo, FileTimes};
use std::{
    ffi::{CString, OsStr},
    fmt::Write,
    fs,
    io::{Seek, SeekFrom},
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};
fn descriptor_name(file: &File) -> Result<CString, NativeError> {
    let prefix = if cfg!(target_os = "linux") || cfg!(target_os = "android") {
        "/proc/self/fd/"
    } else if cfg!(target_os = "macos") || cfg!(target_os = "freebsd") {
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
pub(super) fn extract<E>(
    provider: &mut Provider,
    file: &File,
    stamp: SourceStamp,
    guard: &mut impl FnMut() -> Result<(), E>,
) -> Result<Extraction, Failure<E>> {
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
        let m = fs::metadata(Path::new(OsStr::from_bytes(path.as_bytes()))).map_err(|source| {
            Failure::native(NativeError::Io {
                operation: "observe original descriptor namespace",
                source,
            })
        })?;
        if !m.is_file()
            || SourceStamp(FileInfo {
                identity: FileIdentity::from_metadata(&m),
                bytes: m.len(),
                times: FileTimes::from_metadata(&m),
            }) != stamp
        {
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
        provider.extract_filename(&path, guard)
    }))
    .unwrap_or_else(|payload| {
        Err(Failure::native(NativeError::CallbackPanicked(
            PanicPayload(payload),
        )))
    });
    let restored = cursor.seek(SeekFrom::Start(saved));
    match (result, restored) {
        (Ok(value), Ok(_)) => Ok(value),
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
