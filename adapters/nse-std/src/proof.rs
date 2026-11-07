//! One real OS-fenced raw8 proof writer, atomic commit and explicit recovery.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
/// Exact native stage; a successful write alone does not establish durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Original fence acquisition/validation.
    Fence,
    /// Exact raw8 read.
    Read,
    /// New temporary file creation.
    Create,
    /// Exact original bytes written.
    Write,
    /// Original temporary file synchronized.
    FileSync,
    /// Original atomic replacement.
    Rename,
    /// Parent directory synchronized.
    DirectorySync,
    /// Original unknown commit settled by exact readback.
    Recovery,
}
/// Actual commit certainty, independent of local syscall/error classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// No rename committed; the original bytes may be retried explicitly.
    NotCommitted,
    /// Rename succeeded but durability was not established.
    Unknown,
}
/// Original native failure and its actual persistence boundary.
#[derive(Debug)]
pub struct Error {
    /// Failed original stage.
    pub stage: Stage,
    /// Whether the original replacement may have committed.
    pub outcome: Outcome,
    /// Original OS cause.
    pub cause: io::Error,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NSE proof {:?}/{:?}: {}",
            self.stage, self.outcome, self.cause
        )
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn error(stage: Stage, outcome: Outcome, cause: io::Error) -> Error {
    Error {
        stage,
        outcome,
        cause,
    }
}
/// Owned writer fence and original unknown outcome. The persistent guard file is
/// never unlinked; kernel locking releases on process/owner exit rather than PID guessing.
pub struct Store {
    path: PathBuf,
    parent: PathBuf,
    guard_path: PathBuf,
    guard: File,
    identity: (u64, u64),
    unknown: Option<[u8; 8]>,
}
impl Store {
    /// Obtain a real exclusive OS lock, settle prior directory writes, and validate
    /// any existing file as an exact regular raw8 object before it can be used.
    pub fn open(path: PathBuf) -> Result<Self, Error> {
        gnunet_service_runtime::private_parents(&path)
            .map_err(|e| error(Stage::Fence, Outcome::NotCommitted, e))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        let name = path.file_name().ok_or_else(|| {
            error(
                Stage::Fence,
                Outcome::NotCommitted,
                io::Error::other("proof path has no filename"),
            )
        })?;
        let mut guard_name = name.to_os_string();
        guard_name.push(".nse-lock");
        let guard_path = parent.join(guard_name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600);
        let guard = options
            .open(&guard_path)
            .map_err(|e| error(Stage::Fence, Outcome::NotCommitted, e))?;
        guard
            .try_lock()
            .map_err(|e| error(Stage::Fence, Outcome::NotCommitted, e.into()))?;
        let meta = guard
            .metadata()
            .map_err(|e| error(Stage::Fence, Outcome::NotCommitted, e))?;
        if !meta.is_file() {
            return Err(error(
                Stage::Fence,
                Outcome::NotCommitted,
                io::Error::other("proof fence is not regular"),
            ));
        }
        let store = Self {
            path,
            parent,
            guard_path,
            guard,
            identity: (meta.dev(), meta.ino()),
            unknown: None,
        };
        store
            .directory_sync()
            .map_err(|e| error(Stage::DirectorySync, Outcome::Unknown, e))?;
        let _saved = store.read()?;
        Ok(store)
    }
    fn fence(&self) -> Result<(), Error> {
        let actual = fs::symlink_metadata(&self.guard_path)
            .map_err(|e| error(Stage::Fence, Outcome::Unknown, e))?;
        let held = self
            .guard
            .metadata()
            .map_err(|e| error(Stage::Fence, Outcome::Unknown, e))?;
        if !actual.is_file()
            || (actual.dev(), actual.ino()) != self.identity
            || (held.dev(), held.ino()) != self.identity
        {
            return Err(error(
                Stage::Fence,
                Outcome::Unknown,
                io::Error::other("original proof fence path changed"),
            ));
        }
        Ok(())
    }
    fn directory_sync(&self) -> io::Result<()> {
        File::open(&self.parent)?.sync_all()
    }
    fn read(&self) -> Result<Option<[u8; 8]>, Error> {
        self.fence()?;
        let meta = match fs::symlink_metadata(&self.path) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(error(Stage::Read, Outcome::NotCommitted, e)),
        };
        if !meta.is_file() || meta.len() != 8 {
            return Err(error(
                Stage::Read,
                Outcome::NotCommitted,
                io::Error::other("proof is not an exact regular raw8 file"),
            ));
        }
        let mut file =
            File::open(&self.path).map_err(|e| error(Stage::Read, Outcome::NotCommitted, e))?;
        let opened = file
            .metadata()
            .map_err(|e| error(Stage::Read, Outcome::NotCommitted, e))?;
        if (opened.dev(), opened.ino(), opened.len()) != (meta.dev(), meta.ino(), 8) {
            return Err(error(
                Stage::Read,
                Outcome::Unknown,
                io::Error::other("proof changed during read"),
            ));
        }
        let mut bytes = [0; 8];
        file.read_exact(&mut bytes)
            .map_err(|e| error(Stage::Read, Outcome::NotCommitted, e))?;
        Ok(Some(bytes))
    }
    // Once a replacement succeeded, every subsequent readback failure retains
    // its original stage/cause but cannot claim that no replacement committed.
    fn read_after_rename(&self) -> Result<Option<[u8; 8]>, Error> {
        self.read().map_err(|mut failure| {
            failure.outcome = Outcome::Unknown;
            failure
        })
    }
    /// Read an actual saved raw8 file; None means missing and never durability.
    /// An unknown original commit must be settled before any file is adopted.
    pub fn loaded(&self) -> Result<Option<[u8; 8]>, Error> {
        if self.unknown.is_some() {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original commit must be recovered"),
            ));
        }
        self.read()
    }
    /// Check the actual original OS fence as well as any unknown commit before
    /// permitting another identity epoch. Authority loss retains its native cause.
    pub fn quiescent(&self) -> Result<bool, Error> {
        self.fence()?;
        Ok(self.unknown.is_none())
    }
    /// Atomically write this exact raw8 value under the retained original fence.
    /// A post-rename failure quiesces this owner; it never issues a fresh write.
    pub fn commit(&mut self, bytes: [u8; 8]) -> Result<(), Error> {
        self.commit_observed(bytes, || {})
    }
    fn commit_observed(
        &mut self,
        bytes: [u8; 8],
        after_rename: impl FnOnce(),
    ) -> Result<(), Error> {
        if self.unknown.is_some() {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("unsettled original proof commit"),
            ));
        }
        self.fence()?;
        let mut random = [0; 16];
        getrandom::fill(&mut random)
            .map_err(|e| error(Stage::Create, Outcome::NotCommitted, io::Error::other(e)))?;
        let mut name = self
            .path
            .file_name()
            .ok_or_else(|| {
                error(
                    Stage::Create,
                    Outcome::NotCommitted,
                    io::Error::other("no proof filename"),
                )
            })?
            .to_os_string();
        name.push(format!(".new-{:032x}", u128::from_be_bytes(random)));
        let temporary_path = self.parent.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(&temporary_path)
            .map_err(|e| error(Stage::Create, Outcome::NotCommitted, e))?;
        let metadata = file
            .metadata()
            .map_err(|e| error(Stage::Create, Outcome::NotCommitted, e))?;
        let mut temporary = Temporary {
            path: temporary_path,
            identity: (metadata.dev(), metadata.ino()),
            renamed: false,
        };
        file.write_all(&bytes)
            .map_err(|e| error(Stage::Write, Outcome::NotCommitted, e))?;
        file.sync_all()
            .map_err(|e| error(Stage::FileSync, Outcome::NotCommitted, e))?;
        drop(file);
        self.fence()?;
        fs::rename(&temporary.path, &self.path)
            .map_err(|e| error(Stage::Rename, Outcome::NotCommitted, e))?;
        temporary.renamed = true;
        self.unknown = Some(bytes);
        after_rename();
        self.directory_sync()
            .map_err(|e| error(Stage::DirectorySync, Outcome::Unknown, e))?;
        if self.read_after_rename()? != Some(bytes) {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original commit readback differs"),
            ));
        }
        self.unknown = None;
        Ok(())
    }
    /// Settle the same original unknown commit by directory sync and exact readback.
    /// No new raw8 value is written or accepted as a substitute.
    pub fn recover(&mut self) -> Result<Option<[u8; 8]>, Error> {
        let Some(expected) = self.unknown else {
            self.fence()?;
            return Ok(None);
        };
        self.fence()?;
        self.directory_sync()
            .map_err(|e| error(Stage::Recovery, Outcome::Unknown, e))?;
        if self.read_after_rename()? != Some(expected) {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("unknown original proof cannot be reconciled"),
            ));
        }
        self.unknown = None;
        Ok(Some(expected))
    }
}
struct Temporary {
    path: PathBuf,
    identity: (u64, u64),
    renamed: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if self.renamed {
            return;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.is_file()
            && (metadata.dev(), metadata.ino()) == self.identity
        {
            let _removed = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Real filesystem witnesses assert original OS fence, inode and commit boundaries."
    )]
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "nse-proof-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn actual_raw8_is_atomic_and_kernel_fence_releases_without_pid_guessing()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("proof");
        let mut first = Store::open(path.clone())?;
        assert_eq!(first.loaded()?, None);
        assert!(matches!(
            Store::open(path.clone()),
            Err(Error {
                stage: Stage::Fence,
                ..
            })
        ));
        first.commit([0; 8])?;
        assert_eq!(first.loaded()?, Some([0; 8]));
        assert_eq!(fs::read(&path)?, [0; 8]);
        first.commit([3; 8])?;
        assert_eq!(fs::read(&path)?, [3; 8]);
        assert_eq!(fs::metadata(&path)?.len(), 8);
        assert!(first.quiescent()?);
        drop(first);
        assert!(scratch.0.join("proof.nse-lock").is_file());
        let second = Store::open(path)?;
        assert_eq!(second.loaded()?, Some([3; 8]));
        assert!(second.quiescent()?);
        Ok(())
    }
    #[test]
    fn real_postrename_directory_failure_retains_original_unknown_until_readback()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::new()?;
        let live = scratch.0.join("live");
        let moved = scratch.0.join("moved");
        fs::create_dir(&live)?;
        let path = live.join("proof");
        fs::write(&path, [1; 8])?;
        let mut store = Store::open(path)?;
        let result = store.commit_observed([2; 8], || {
            assert!(fs::rename(&live, &moved).is_ok());
        });
        assert!(matches!(
            result,
            Err(Error {
                stage: Stage::DirectorySync,
                outcome: Outcome::Unknown,
                ..
            })
        ));
        assert_eq!(fs::read(moved.join("proof"))?, [2; 8]);
        assert!(store.quiescent().is_err());
        assert!(store.loaded().is_err());
        assert!(matches!(
            store.commit([9; 8]),
            Err(Error {
                stage: Stage::Recovery,
                outcome: Outcome::Unknown,
                ..
            })
        ));
        assert!(store.recover().is_err());
        fs::rename(&moved, &live)?;
        assert!(!store.quiescent()?);
        assert_eq!(store.recover()?, Some([2; 8]));
        assert!(store.quiescent()?);
        assert_eq!(store.loaded()?, Some([2; 8]));
        store.commit([4; 8])?;
        assert_eq!(fs::read(live.join("proof"))?, [4; 8]);
        Ok(())
    }
    #[test]
    fn malformed_file_and_replaced_fence_never_authorize_another_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("proof");
        fs::write(&path, [7; 9])?;
        assert!(matches!(
            Store::open(path.clone()),
            Err(Error {
                stage: Stage::Read,
                ..
            })
        ));
        fs::remove_file(&path)?;
        let mut store = Store::open(path.clone())?;
        fs::rename(scratch.0.join("proof.nse-lock"), scratch.0.join("old-lock"))?;
        fs::write(scratch.0.join("proof.nse-lock"), [])?;
        assert!(store.quiescent().is_err());
        assert!(store.loaded().is_err());
        assert!(matches!(
            store.commit([5; 8]),
            Err(Error {
                stage: Stage::Fence,
                outcome: Outcome::Unknown,
                ..
            })
        ));
        assert!(!path.exists());
        Ok(())
    }
    #[test]
    fn failed_temp_creation_never_deletes_someone_elses_random_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("name");
        fs::write(&path, [7])?;
        let metadata = fs::metadata(&path)?;
        let temporary = Temporary {
            path: path.clone(),
            identity: (metadata.dev(), metadata.ino()),
            renamed: false,
        };
        fs::rename(&path, scratch.0.join("old"))?;
        fs::write(&path, [9])?;
        drop(temporary);
        assert_eq!(fs::read(path)?, [9]);
        Ok(())
    }
    fn postrename_readback_refusal_case(recovery: bool) -> Result<(), Box<dyn std::error::Error>> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("proof");
        let saved = scratch.0.join("original-renamed-proof");
        let mut store = Store::open(path.clone())?;
        store.commit([1; 8])?;
        // The real replacement has already happened and its original bytes were
        // fsynced. Make only the subsequent exact readback fail on an actual
        // non-regular filesystem object, retaining the original replacement.
        let result = store.commit_observed([2; 8], || {
            assert!(fs::rename(&path, &saved).is_ok());
            assert!(fs::create_dir(&path).is_ok());
        });
        let original = result.err().ok_or("readback unexpectedly succeeded")?;
        assert_eq!(store.unknown, Some([2; 8]));
        let failure = if recovery {
            store
                .recover()
                .err()
                .ok_or("recovery adopted wrong object")?
        } else {
            original
        };
        assert_eq!(failure.stage, Stage::Read);
        assert_eq!(failure.outcome, Outcome::Unknown);
        assert!(matches!(
            store.loaded(),
            Err(Error {
                outcome: Outcome::Unknown,
                ..
            })
        ));
        assert!(matches!(
            store.commit([3; 8]),
            Err(Error {
                outcome: Outcome::Unknown,
                ..
            })
        ));
        fs::remove_dir(&path)?;
        fs::rename(&saved, &path)?;
        assert_eq!(store.recover()?, Some([2; 8]));
        assert_eq!(store.loaded()?, Some([2; 8]));
        store.commit([3; 8])?;
        assert_eq!(store.loaded()?, Some([3; 8]));
        Ok(())
    }
    #[test]
    fn postrename_readback_refusal_never_reports_not_committed()
    -> Result<(), Box<dyn std::error::Error>> {
        postrename_readback_refusal_case(false)
    }
    #[test]
    fn postrename_readback_recovery_refusal_never_reports_not_committed()
    -> Result<(), Box<dyn std::error::Error>> {
        postrename_readback_refusal_case(true)
    }
}
