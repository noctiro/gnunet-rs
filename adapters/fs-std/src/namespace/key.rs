//! Explicit ownership of an ordinary raw32 Ed25519 namespace seed file.
//!
//! The parent directory is caller-selected. Its original descriptor and current
//! pathname must continue to agree; the final seed name is never followed through
//! a symlink. No key bytes, seed fingerprint or derived secret is printable.
use crate::FileIdentity;
use gnunet_crypto::{gns::EdkeySecret, hash512};
use nix::{
    errno::Errno,
    fcntl::{OFlag, open, openat},
    sys::stat::Mode,
    unistd::geteuid,
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const REGULAR: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC);

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
    /// The actual seed is nonregular, foreign-owned or lacks private permissions.
    Private,
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
            Self::Private => f.write_str(
                "namespace key must be a private regular file owned by the effective user",
            ),
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
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for Cause {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<Errno> for Cause {
    fn from(error: Errno) -> Self {
        Self::Io(error.into())
    }
}
/// Original failure and actual creation/barrier facts. A failed create can leave
/// its own seed name present: no failure path unlinks, replaces or retries it.
#[derive(Debug)]
pub struct Error {
    /// Actual completed phase of this operation.
    pub stage: Stage,
    /// Whether this invocation's own O_EXCL creation returned success.
    pub created: bool,
    /// Whether the original seed descriptor sync actually succeeded.
    pub file_synced: bool,
    /// Whether the original selected parent sync actually succeeded.
    pub parent_synced: bool,
    /// Actual opened seed inode, if its metadata was available.
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
    parent_synced: bool,
    identity: Option<FileIdentity>,
}
impl Attempt {
    fn new() -> Self {
        Self {
            stage: Stage::Unopened,
            created: false,
            file_synced: false,
            parent_synced: false,
            identity: None,
        }
    }
    fn fail(self, cause: Cause) -> Error {
        Error {
            stage: self.stage,
            created: self.created,
            file_synced: self.file_synced,
            parent_synced: self.parent_synced,
            identity: self.identity,
            cause,
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp {
    identity: FileIdentity,
    bytes: u64,
    uid: u32,
    mode: u32,
    modified: i64,
    modified_nanos: i64,
    changed: i64,
    changed_nanos: i64,
}
impl Stamp {
    fn read(metadata: Metadata) -> Result<Self, Cause> {
        let mode = metadata.mode();
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || mode & 0o7177 != 0
            || mode & 0o400 == 0
        {
            return Err(Cause::Private);
        }
        Ok(Self {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            bytes: metadata.len(),
            uid: metadata.uid(),
            mode,
            modified: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        })
    }
    fn file(file: &File) -> Result<Self, Cause> {
        Self::read(file.metadata()?)
    }
}
/// An original raw32 seed and its selected native authority. It deliberately
/// implements neither Debug nor Clone. Secret owners and temporary seed/fingerprint
/// storage erase their memory on drop; no secret enters an ordinary task WAL.
pub struct KeyFile {
    parent: File,
    parent_path: PathBuf,
    parent_id: FileIdentity,
    name: OsString,
    file: File,
    stamp: Stamp,
    fingerprint: Zeroizing<[u8; 64]>,
    secret: EdkeySecret,
}
impl KeyFile {
    /// Generate a new random raw32 seed using exclusive 0600 creation. Success
    /// includes original file and parent syncs plus final name/parent checks.
    /// A failed operation leaves any possibly created key intact for inspection.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut attempt = Attempt::new();
        let result = (|| -> Result<Self, Cause> {
            let (parent_path, name) = selected(path.as_ref())?;
            let parent = File::from(open(&parent_path, DIRECTORY, Mode::empty())?);
            let parent_id = FileIdentity::of(&parent)?;
            let mut bytes = Zeroizing::new([0; 32]);
            File::open("/dev/urandom")?.read_exact(&mut bytes[..])?;
            let mut file = File::from(openat(
                &parent,
                name.as_os_str(),
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_NONBLOCK
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )?);
            attempt.created = true;
            attempt.stage = Stage::Created;
            attempt.identity = Some(FileIdentity::of(&file)?);
            let _private = Stamp::file(&file)?;
            file.write_all(&bytes[..])?;
            attempt.stage = Stage::SeedWritten;
            file.sync_all()?;
            attempt.file_synced = true;
            attempt.stage = Stage::FileSynced;
            let stamp = Stamp::file(&file)?;
            if stamp.bytes != 32 {
                return Err(Cause::Length);
            }
            let owner = Self {
                parent,
                parent_path,
                parent_id,
                name,
                file,
                stamp,
                fingerprint: Zeroizing::new(hash512(bytes.as_ref())),
                secret: EdkeySecret::from_seed(*bytes),
            };
            owner.authority()?;
            owner.parent.sync_all()?;
            attempt.parent_synced = true;
            attempt.stage = Stage::ParentSynced;
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
            let parent = File::from(open(&parent_path, DIRECTORY, Mode::empty())?);
            let parent_id = FileIdentity::of(&parent)?;
            let file = File::from(openat(&parent, name.as_os_str(), REGULAR, Mode::empty())?);
            attempt.stage = Stage::Opened;
            attempt.identity = Some(FileIdentity::of(&file)?);
            let stamp = Stamp::file(&file)?;
            let bytes = read_seed(&file)?;
            attempt.stage = Stage::SeedRead;
            let owner = Self {
                parent,
                parent_path,
                parent_id,
                name,
                file,
                stamp,
                fingerprint: Zeroizing::new(hash512(bytes.as_ref())),
                secret: EdkeySecret::from_seed(*bytes),
            };
            owner.authority()?;
            Ok(owner)
        })();
        result.map_err(|cause| attempt.fail(cause))
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
        let seed = read_seed(&self.file)?;
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
        if FileIdentity::of(&self.parent)? != self.parent_id
            || Stamp::file(&self.file)? != self.stamp
        {
            return Err(Cause::Changed);
        }
        let selected_parent = File::from(open(&self.parent_path, DIRECTORY, Mode::empty())?);
        if FileIdentity::of(&selected_parent)? != self.parent_id {
            return Err(Cause::Changed);
        }
        let selected_file = File::from(openat(
            &self.parent,
            self.name.as_os_str(),
            REGULAR,
            Mode::empty(),
        )?);
        if Stamp::file(&selected_file)? != self.stamp {
            return Err(Cause::Changed);
        }
        Ok(())
    }
}
fn selected(path: &Path) -> Result<(PathBuf, OsString), Cause> {
    let raw_name = path
        .as_os_str()
        .as_bytes()
        .rsplit(|byte| *byte == b'/')
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
fn read_seed(file: &File) -> Result<Zeroizing<[u8; 32]>, Cause> {
    if Stamp::file(file)?.bytes != 32 {
        return Err(Cause::Length);
    }
    let mut bytes = Zeroizing::new([0; 32]);
    let mut offset = 0;
    while offset < 32 {
        match file.read_at(&mut bytes[offset..], offset as u64) {
            Ok(0) => return Err(Cause::Length),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut extra = Zeroizing::new([0; 1]);
    loop {
        match file.read_at(&mut extra[..], 32) {
            Ok(0) => return Ok(bytes),
            Ok(_) => return Err(Cause::Length),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests;
