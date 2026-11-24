//! Verified byte snapshots of private, single-link files.
use super::{Directory, EntryInfo, FileInfo, private_data_file_info};
use std::{ffi::OsStr, fmt, fs::File, io};

/// Why a held private file could no longer authorize its snapshot.
#[derive(Debug)]
pub enum PrivateSnapshotError {
    /// The held file could not be inspected or no longer satisfies private-file policy.
    Held(io::Error),
    /// The held file changed since its contents were verified.
    Metadata {
        /// Last verified metadata.
        before: FileInfo,
        /// Fresh held-file observation.
        after: Box<FileInfo>,
    },
    /// The selected name did not confirm the same metadata as the held file.
    Name {
        /// Verified held-file metadata.
        held: FileInfo,
        /// Observation of the name or the native failure to inspect it.
        observed: Box<io::Result<EntryInfo>>,
    },
    /// An independent content read did not verify a ctime-only change.
    Readback(io::Error),
}

impl fmt::Display for PrivateSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(error) | Self::Readback(error) => error.fmt(f),
            Self::Metadata { before, after } => write!(
                f,
                "original file snapshot changed: expected={before:?}, held={after:?}"
            ),
            Self::Name { held, observed } => write!(
                f,
                "original file name changed: held={held:?}, named={observed:?}"
            ),
        }
    }
}

impl std::error::Error for PrivateSnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Held(error) | Self::Readback(error) => Some(error),
            Self::Name { observed, .. } => observed.as_ref().as_ref().err().map(|e| e as _),
            Self::Metadata { .. } => None,
        }
    }
}

impl From<PrivateSnapshotError> for io::Error {
    fn from(error: PrivateSnapshotError) -> Self {
        match error {
            PrivateSnapshotError::Held(error) | PrivateSnapshotError::Readback(error) => error,
            error => {
                let kind = match &error {
                    PrivateSnapshotError::Name { observed, .. } => observed
                        .as_ref()
                        .as_ref()
                        .err()
                        .map_or(io::ErrorKind::InvalidData, io::Error::kind),
                    _ => io::ErrorKind::InvalidData,
                };
                Self::new(kind, error)
            }
        }
    }
}

/// A metadata fence for bytes already verified on an original private file.
/// FreeBSD can update ctime after a completed rename or unlink. On that host a
/// ctime-only difference requires a fresh, stable readback of the same bytes.
pub struct PrivateFileSnapshot {
    info: FileInfo,
    #[cfg(target_os = "freebsd")]
    readback: Readback,
}

impl PrivateFileSnapshot {
    /// Capture an original observation and its already verified bytes.
    pub fn new(info: FileInfo, bytes: &[u8]) -> Self {
        #[cfg(target_os = "freebsd")]
        {
            use sha2::{Digest, Sha256};
            Self::with_sha256(info, Sha256::digest(bytes).into())
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            let _ = bytes;
            Self { info }
        }
    }

    /// Capture an original observation with a SHA-256 of its verified bytes.
    pub fn with_sha256(info: FileInfo, digest: [u8; 32]) -> Self {
        #[cfg(not(target_os = "freebsd"))]
        let _ = digest;
        Self {
            info,
            #[cfg(target_os = "freebsd")]
            readback: Readback {
                digest,
                changed: std::sync::Mutex::new(info.times.changed),
            },
        }
    }

    /// Identity and extent captured at the original read or publication.
    #[must_use]
    pub const fn initial(&self) -> FileInfo {
        self.info
    }

    /// Finish capturing a newly read snapshot at the same selected private file.
    /// The initial observation was taken before reading the bytes. FreeBSD may
    /// advance its ctime only after an independent, stable read of the same bytes.
    pub fn confirm_read(
        mut self,
        directory: &Directory,
        name: &OsStr,
        file: &File,
    ) -> io::Result<Self> {
        self.info = self.observe(directory, name, file)?;
        Ok(self)
    }

    /// Require the held exact private file to remain selected by its name.
    /// The fast path observes metadata only; a permitted FreeBSD ctime change
    /// is cached only after bounded readback from the same held file.
    pub fn verify(&self, directory: &Directory, name: &OsStr, file: &File) -> io::Result<()> {
        self.verify_detailed(directory, name, file)
            .map_err(Into::into)
    }

    /// Verify the original, retaining the kind of observation that failed.
    pub fn verify_detailed(
        &self,
        directory: &Directory,
        name: &OsStr,
        file: &File,
    ) -> Result<(), PrivateSnapshotError> {
        self.observe(directory, name, file).map(|_| ())
    }

    fn observe(
        &self,
        directory: &Directory,
        name: &OsStr,
        file: &File,
    ) -> Result<FileInfo, PrivateSnapshotError> {
        let held = private_data_file_info(file).map_err(PrivateSnapshotError::Held)?;
        #[cfg(target_os = "freebsd")]
        let expected = self.readback.current(self.info);
        #[cfg(not(target_os = "freebsd"))]
        let expected = self.info;
        #[cfg(target_os = "freebsd")]
        let same_contents_metadata = same_data(expected, held);
        #[cfg(not(target_os = "freebsd"))]
        let same_contents_metadata = held == expected;
        if !same_contents_metadata {
            return Err(PrivateSnapshotError::Metadata {
                before: expected,
                after: Box::new(held),
            });
        }
        let named = directory.entry_info(name);
        if held == expected && matches!(named, Ok(EntryInfo::File(info)) if info == held) {
            return Ok(held);
        }
        #[cfg(target_os = "freebsd")]
        if matches!(named, Ok(EntryInfo::File(info)) if same_data(expected, info)) {
            return self
                .readback
                .verify(directory, name, file, expected)
                .map_err(PrivateSnapshotError::Readback);
        }
        Err(PrivateSnapshotError::Name {
            held,
            observed: Box::new(named),
        })
    }
}

#[cfg(target_os = "freebsd")]
fn same_data(expected: FileInfo, actual: FileInfo) -> bool {
    expected.identity == actual.identity
        && expected.bytes == actual.bytes
        && expected.times.modified == actual.times.modified
}

#[cfg(target_os = "freebsd")]
struct Readback {
    digest: [u8; 32],
    changed: std::sync::Mutex<i128>,
}

#[cfg(target_os = "freebsd")]
impl Readback {
    fn current(&self, mut original: FileInfo) -> FileInfo {
        original.times.changed = *self
            .changed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        original
    }

    fn verify(
        &self,
        directory: &Directory,
        name: &OsStr,
        file: &File,
        expected: FileInfo,
    ) -> io::Result<FileInfo> {
        use sha2::{Digest, Sha256};
        const ATTEMPTS: usize = 3;
        let invalid =
            || io::Error::new(io::ErrorKind::InvalidData, "original file readback changed");
        let reader = super::FileReader::from_file(file)?;
        let mut block = zeroize::Zeroizing::new([0; 8192]);
        for _ in 0..ATTEMPTS {
            let before = private_data_file_info(file)?;
            if !same_data(expected, before) {
                return Err(invalid());
            }
            let mut hash = Sha256::new();
            let mut at = 0;
            while at < before.bytes {
                let count = (before.bytes - at).min(block.len() as u64) as usize;
                reader.read_exact_at(&mut block[..count], at)?;
                hash.update(&block[..count]);
                at += count as u64;
            }
            if reader.read_at(&mut block[..1], at)? != 0 {
                return Err(invalid());
            }
            let digest: [u8; 32] = hash.finalize().into();
            let after = private_data_file_info(file)?;
            let named = directory.entry_info(name)?;
            if digest != self.digest
                || !same_data(expected, after)
                || !matches!(named, EntryInfo::File(info) if same_data(expected, info))
            {
                return Err(invalid());
            }
            if before == after && named == EntryInfo::File(after) {
                *self
                    .changed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = after.times.changed;
                return Ok(after);
            }
        }
        Err(invalid())
    }
}
