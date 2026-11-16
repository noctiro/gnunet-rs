//! Explicit ownership of an ordinary raw32 Ed25519 namespace seed file.
//!
//! The parent directory is caller-selected. Its original descriptor and current
//! pathname must continue to agree; the final seed name is never followed through
//! a symlink. No key bytes, seed fingerprint or derived secret is printable.
use crate::FileIdentity;
use gnunet_crypto::{gns::EdkeySecret, hash512};
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, FileInfo, FileReader, private_data_file_info},
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::{self, Write},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

/// Actual native phase reached by this invocation, independently of its error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// No seed file descriptor was established by this invocation.
    Unopened,
    /// An existing final descriptor was opened; policy checks can still fail.
    Opened,
    /// This invocation's exclusive creation returned a real descriptor.
    Created,
    /// Exactly 32 seed bytes were successfully written, without a sync claim.
    SeedWritten,
    /// The original created seed descriptor's sync completed.
    FileSynced,
    /// Its selected parent sync completed; final authority checks can still fail.
    ParentSynced,
    /// Complete raw seed bytes were read; original identity checks can still fail.
    SeedRead,
}
/// Typed local refusal. It never contains key bytes or a seed fingerprint.
#[derive(Debug)]
pub enum Cause {
    /// Original native errno, read/write, entropy or naming-barrier error.
    Io(io::Error),
    /// The selected path has no safe ordinary final component.
    Path,
    /// Native private-data qualification failed; the original query error is retained.
    Private(io::Error),
    /// The actual seed length is not exactly 32 bytes.
    Length,
    /// The original file, complete seed, parent or selected name changed.
    Changed,
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Path => f.write_str("namespace key requires an ordinary final filename"),
            Self::Private(error) => write!(f, "namespace key private-file qualification: {error}"),
            Self::Length => f.write_str("namespace key must contain exactly 32 raw seed bytes"),
            Self::Changed => {
                f.write_str("original namespace seed or selected native authority changed")
            }
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) | Self::Private(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for Cause {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
/// Original failure and actual creation/barrier facts. A failed create can leave
/// its own seed name present: no failure path unlinks, replaces or retries it.
#[derive(Debug)]
pub struct Error {
    /// Actual completed phase of this operation.
    pub stage: Stage,
    /// Whether this invocation's exclusive native creation returned success.
    pub created: bool,
    /// Whether the original seed descriptor sync actually succeeded.
    pub file_synced: bool,
    /// Actual selected-parent naming barrier, separate from file synchronization.
    pub directory_sync: Option<DirectorySync>,
    /// Complete original seed identity, if its metadata was available.
    pub identity: Option<FileIdentity>,
    /// Independent original cause; naming uncertainty is not rewritten as absence.
    pub cause: Cause,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS namespace key {:?}: {}", self.stage, self.cause)
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
struct Attempt {
    stage: Stage,
    created: bool,
    file_synced: bool,
    directory_sync: Option<DirectorySync>,
    identity: Option<FileIdentity>,
}
impl Attempt {
    fn new() -> Self {
        Self {
            stage: Stage::Unopened,
            created: false,
            file_synced: false,
            directory_sync: None,
            identity: None,
        }
    }
    fn fail(self, cause: Cause) -> Error {
        Error {
            stage: self.stage,
            created: self.created,
            file_synced: self.file_synced,
            directory_sync: self.directory_sync,
            identity: self.identity,
            cause,
        }
    }
}
fn stamp(file: &File) -> Result<FileInfo, Cause> {
    private_data_file_info(file).map_err(Cause::Private)
}
/// An original raw32 seed and its selected native authority. It deliberately
/// implements neither Debug nor Clone. Secret owners and temporary seed/fingerprint
/// storage erase their memory on drop; no secret enters an ordinary task WAL.
pub struct KeyFile {
    parent: Directory,
    parent_path: PathBuf,
    parent_id: FileIdentity,
    name: OsString,
    file: File,
    stamp: FileInfo,
    reader: FileReader,
    directory_sync: Option<DirectorySync>,
    fingerprint: Zeroizing<[u8; 64]>,
    secret: EdkeySecret,
}
impl KeyFile {
    /// Generate a new random raw32 seed using exclusive private creation. Success
    /// includes file synchronization, the actual parent barrier and final authority checks.
    /// A failed operation leaves any possibly created key intact for inspection.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut attempt = Attempt::new();
        let result = (|| -> Result<Self, Cause> {
            let (parent_path, name) = selected(path.as_ref())?;
            let parent = Directory::open(&parent_path)?;
            let parent_id = FileIdentity::of(parent.as_file())?;
            let mut bytes = Zeroizing::new([0; 32]);
            gnunet_native::entropy::fill(&mut bytes[..])?;
            let mut file = parent.create_private_file(&name)?;
            attempt.created = true;
            attempt.stage = Stage::Created;
            attempt.identity = Some(FileIdentity::of(&file)?);
            let _private = stamp(&file)?;
            file.write_all(&bytes[..])?;
            attempt.stage = Stage::SeedWritten;
            file.sync_all()?;
            attempt.file_synced = true;
            attempt.stage = Stage::FileSynced;
            let stamp = stamp(&file)?;
            if stamp.bytes != 32 {
                return Err(Cause::Length);
            }
            let mut owner = Self {
                parent,
                parent_path,
                parent_id,
                name,
                reader: FileReader::from_file(&file)?,
                directory_sync: None,
                file,
                stamp,
                fingerprint: Zeroizing::new(hash512(bytes.as_ref())),
                secret: EdkeySecret::from_seed(*bytes),
            };
            owner.authority()?;
            let synchronization = owner.parent.sync()?;
            attempt.directory_sync = Some(synchronization);
            owner.directory_sync = Some(synchronization);
            if synchronization == DirectorySync::Synchronized {
                attempt.stage = Stage::ParentSynced;
            }
            owner.authority()?;
            // Re-read the original descriptor too: exact successful writes alone
            // do not exclude an intervening external seed modification.
            owner.check_seed()?;
            owner.authority()?;
            Ok(owner)
        })();
        result.map_err(|cause| attempt.fail(cause))
    }
    /// Read an existing private raw32 regular seed. This grants no new creation
    /// or durability receipt; its original native identity/content are retained.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut attempt = Attempt::new();
        let result = (|| -> Result<Self, Cause> {
            let (parent_path, name) = selected(path.as_ref())?;
            let parent = Directory::open(&parent_path)?;
            let parent_id = FileIdentity::of(parent.as_file())?;
            let file = parent.open_file(&name).map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidInput {
                    Cause::Private(error)
                } else {
                    Cause::Io(error)
                }
            })?;
            attempt.stage = Stage::Opened;
            attempt.identity = Some(FileIdentity::of(&file)?);
            let stamp = stamp(&file)?;
            let reader = FileReader::from_file(&file)?;
            let bytes = read_seed(&file, &reader)?;
            attempt.stage = Stage::SeedRead;
            let owner = Self {
                parent,
                parent_path,
                parent_id,
                name,
                file,
                stamp,
                reader,
                directory_sync: None,
                fingerprint: Zeroizing::new(hash512(bytes.as_ref())),
                secret: EdkeySecret::from_seed(*bytes),
            };
            owner.authority()?;
            Ok(owner)
        })();
        result.map_err(|cause| attempt.fail(cause))
    }
    /// Actual selected-parent naming barrier for this creation, or None on reopen.
    #[must_use]
    pub fn directory_sync(&self) -> Option<DirectorySync> {
        self.directory_sync
    }
    /// Standard Ed25519 public namespace identity, with no path/key disclosure.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.secret.public_key()
    }
    /// Borrow the zeroizing signer. Call revalidate before starting publication;
    /// this accessor neither touches the filesystem nor asserts current authority.
    #[must_use]
    pub fn secret(&self) -> &EdkeySecret {
        &self.secret
    }
    /// Fully re-read the original seed and compare its fingerprint, native stamps,
    /// exact final name and original selected parent before using its signer.
    pub fn revalidate(&self) -> Result<(), Error> {
        let mut attempt = Attempt::new();
        attempt.stage = Stage::Opened;
        attempt.identity = Some(self.stamp.identity);
        let result = (|| -> Result<(), Cause> {
            self.authority()?;
            self.check_seed()?;
            attempt.stage = Stage::SeedRead;
            self.authority()
        })();
        result.map_err(|cause| attempt.fail(cause))
    }
    fn check_seed(&self) -> Result<(), Cause> {
        let seed = read_seed(&self.file, &self.reader)?;
        let fingerprint = Zeroizing::new(hash512(seed.as_ref()));
        // Fixed-size accumulation avoids content-dependent early comparison.
        let mismatch = self
            .fingerprint
            .iter()
            .zip(fingerprint.iter())
            .fold(0u8, |different, (a, b)| different | (a ^ b));
        if mismatch != 0 {
            return Err(Cause::Changed);
        }
        Ok(())
    }
    fn authority(&self) -> Result<(), Cause> {
        if FileIdentity::of(self.parent.as_file())? != self.parent_id
            || stamp(&self.file)? != self.stamp
        {
            return Err(Cause::Changed);
        }
        let selected_parent = Directory::open(&self.parent_path)?;
        if FileIdentity::of(selected_parent.as_file())? != self.parent_id {
            return Err(Cause::Changed);
        }
        let selected_file = self.parent.open_file(&self.name)?;
        if stamp(&selected_file)? != self.stamp {
            return Err(Cause::Changed);
        }
        Ok(())
    }
}
fn selected(path: &Path) -> Result<(PathBuf, OsString), Cause> {
    let encoded = gnunet_native::os_bytes::encode(path.as_os_str());
    let raw_name = encoded
        .rsplit(|byte| *byte == b'/' || cfg!(windows) && *byte == b'\\')
        .next()
        .ok_or(Cause::Path)?;
    if raw_name.is_empty() || matches!(raw_name, b"." | b"..") {
        return Err(Cause::Path);
    }
    let name = path.file_name().ok_or(Cause::Path)?;
    if !matches!(
        Path::new(name).components().next(),
        Some(Component::Normal(_))
    ) || name == OsStr::new(".")
        || name == OsStr::new("..")
    {
        return Err(Cause::Path);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };
    Ok((parent, name.to_owned()))
}
fn read_seed(file: &File, reader: &FileReader) -> Result<Zeroizing<[u8; 32]>, Cause> {
    if stamp(file)?.bytes != 32 {
        return Err(Cause::Length);
    }
    let mut bytes = Zeroizing::new([0; 32]);
    reader.read_exact_at(&mut bytes[..], 0).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Cause::Length
        } else {
            Cause::Io(error)
        }
    })?;
    let mut extra = Zeroizing::new([0; 1]);
    loop {
        match reader.read_at(&mut extra[..], 32) {
            Ok(0) => return Ok(bytes),
            Ok(_) => return Err(Cause::Length),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests;
