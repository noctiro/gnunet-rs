//! Fixed-size Rust monotime state, one actual writer lock and atomic durability.
use super::{Lease, Range};
use gnunet_crypto::hash256;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
const MAGIC: &[u8; 8] = b"GNCAMT01";
const BYTES: usize = 80;
/// Actual stage of an explicit disk operation; native signer polling never
/// enters any of these stages or submits hidden worker jobs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Original writer lock, directory or path ownership.
    Fence,
    /// Exact versioned state read/checksum/public-peer validation.
    Read,
    /// Checked new high-water/range arithmetic.
    Reserve,
    /// New fixed-size original temporary write and file durability.
    Write,
    /// Atomic replacement attempted; a failed/unknown result returns no range.
    Rename,
    /// Original directory durability barrier.
    DirectorySync,
    /// Exact original uncertain commit readback/reconciliation.
    Recovery,
}
/// Whether the original failed local operation may have changed committed state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// No high-water replacement was attempted; no value was returned.
    NotCommitted,
    /// Original replacement/durability is uncertain; reservations are blocked.
    Unknown,
}
/// Original actual failure and its persistence boundary. A failed reservation
/// never returns a usable timestamp, even if its file replacement happened.
#[derive(Debug)]
pub struct Error {
    /// Actual failed stage.
    pub stage: Stage,
    /// Original commit certainty.
    pub outcome: Outcome,
    /// Original OS or arithmetic cause.
    pub cause: io::Error,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CADET monotime {:?}/{:?}: {}",
            self.stage, self.outcome, self.cause
        )
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn fail(stage: Stage, outcome: Outcome, cause: io::Error) -> Error {
    Error {
        stage,
        outcome,
        cause,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct State {
    local: [u8; 32],
    high: u64,
}
impl State {
    fn bytes(self) -> [u8; BYTES] {
        let mut out = [0; BYTES];
        out[..8].copy_from_slice(MAGIC);
        out[8..40].copy_from_slice(&self.local);
        out[40..48].copy_from_slice(&self.high.to_be_bytes());
        let check = hash256(&out[..48]);
        out[48..].copy_from_slice(&check);
        out
    }
    fn decode(bytes: [u8; BYTES]) -> io::Result<Self> {
        if &bytes[..8] != MAGIC || bytes[48..] != hash256(&bytes[..48]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid CADET monotime version/checksum",
            ));
        }
        let mut local = [0; 32];
        local.copy_from_slice(&bytes[8..40]);
        let mut high = [0; 8];
        high.copy_from_slice(&bytes[40..48]);
        Ok(Self {
            local,
            high: u64::from_be_bytes(high),
        })
    }
}
/// Explicit synchronous durability provider for one public local peer. Keep the
/// original namespace under the caller's exclusive control. The stable lock is
/// never unlinked; its kernel ownership releases when the actual File closes.
/// This is a Rust internal format, not a C database or an on-wire field.
pub struct Store {
    path: PathBuf,
    parent: PathBuf,
    directory: File,
    directory_identity: (u64, u64),
    guard_path: PathBuf,
    guard: Arc<Lease>,
    guard_identity: (u64, u64),
    local: [u8; 32],
    loaded: Option<State>,
    unknown: Option<State>,
    temporary: u64,
}
impl Store {
    /// Open the fixed state namespace for this exact peer below a configured
    /// filename stem. Returning to an earlier PID reopens its own durable floor;
    /// no other identity's record is overwritten, reset or used as authority.
    pub fn open_for_peer(stem: &Path, local: [u8; 32]) -> Result<Self, Error> {
        let mut name = stem
            .file_name()
            .ok_or_else(|| {
                fail(
                    Stage::Fence,
                    Outcome::NotCommitted,
                    io::Error::new(io::ErrorKind::InvalidInput, "monotime stem has no filename"),
                )
            })?
            .to_os_string();
        name.push(".peer-");
        let mut suffix = [0; 64];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (out, byte) in suffix.as_chunks_mut::<2>().0.iter_mut().zip(local) {
            out[0] = HEX[usize::from(byte >> 4)];
            out[1] = HEX[usize::from(byte & 15)];
        }
        // The full public identity is encoded without a collision-prone prefix.
        use std::os::unix::ffi::OsStrExt;
        name.push(std::ffi::OsStr::from_bytes(&suffix));
        Self::open(stem.with_file_name(name), local)
    }
    /// Acquire the actual exclusive OS writer lock and validate exact existing
    /// state before allocating any value. Missing state is distinct from zero.
    /// A changed public peer is refused; identity rotation uses a new state path.
    pub fn open(path: PathBuf, local: [u8; 32]) -> Result<Self, Error> {
        gnunet_service_runtime::private_parents(&path)
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let name = path
            .file_name()
            .ok_or_else(|| {
                fail(
                    Stage::Fence,
                    Outcome::NotCommitted,
                    io::Error::new(io::ErrorKind::InvalidInput, "monotime path has no filename"),
                )
            })?
            .to_os_string();
        let requested_parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(requested_parent)
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let path = parent.join(&name);
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&parent)
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let dm = directory
            .metadata()
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let mut guard_name = name;
        guard_name.push(".cadet-monotime-lock");
        let guard_path = parent.join(guard_name);
        let guard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&guard_path)
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        guard
            .try_lock()
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e.into()))?;
        let gm = guard
            .metadata()
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        if !dm.is_dir() || !gm.is_file() {
            return Err(fail(
                Stage::Fence,
                Outcome::NotCommitted,
                io::Error::other("invalid monotime writer namespace"),
            ));
        }
        let mut store = Self {
            path,
            parent,
            directory,
            directory_identity: (dm.dev(), dm.ino()),
            guard_path,
            guard: Arc::new(Lease {
                guard,
                issued: AtomicU64::new(0),
            }),
            guard_identity: (gm.dev(), gm.ino()),
            local,
            loaded: None,
            unknown: None,
            temporary: 0,
        };
        store.fence()?;
        store
            .directory
            .sync_all()
            .map_err(|e| fail(Stage::DirectorySync, Outcome::Unknown, e))?;
        store.loaded = store.read()?;
        store
            .guard
            .issued
            .store(store.loaded.map_or(0, |state| state.high), Ordering::SeqCst);
        if store.loaded.is_some_and(|state| state.local != local) {
            return Err(fail(
                Stage::Read,
                Outcome::NotCommitted,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "monotime state belongs to a different public peer",
                ),
            ));
        }
        Ok(store)
    }
    /// Original public peer whose durable high-water this owner controls.
    #[must_use]
    pub const fn local(&self) -> [u8; 32] {
        self.local
    }
    /// Highest fully committed reserved value. Unknown is reported as an error;
    /// a caller cannot use a stale low floor while an original commit is pending.
    pub fn high_water(&self) -> Result<Option<u64>, Error> {
        self.fence()?;
        if self.unknown.is_some() {
            return Err(fail(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original monotime reservation unresolved"),
            ));
        }
        Ok(self.loaded.map(|state| state.high))
    }
    fn fence(&self) -> Result<(), Error> {
        let guard = fs::symlink_metadata(&self.guard_path)
            .map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?;
        let held = self
            .guard
            .guard
            .metadata()
            .map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?;
        let directory = fs::symlink_metadata(&self.parent)
            .map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?;
        let held_directory = self
            .directory
            .metadata()
            .map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?;
        if !guard.is_file()
            || (guard.dev(), guard.ino()) != self.guard_identity
            || (held.dev(), held.ino()) != self.guard_identity
            || !directory.is_dir()
            || (directory.dev(), directory.ino()) != self.directory_identity
            || (held_directory.dev(), held_directory.ino()) != self.directory_identity
        {
            return Err(fail(
                Stage::Fence,
                Outcome::Unknown,
                io::Error::other("original monotime writer fence/directory changed"),
            ));
        }
        Ok(())
    }
    fn read(&self) -> Result<Option<State>, Error> {
        self.fence()?;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(fail(Stage::Read, Outcome::NotCommitted, e)),
        };
        let before = file
            .metadata()
            .map_err(|e| fail(Stage::Read, Outcome::NotCommitted, e))?;
        if !before.is_file() || before.len() != BYTES as u64 {
            return Err(fail(
                Stage::Read,
                Outcome::NotCommitted,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "monotime is not an exact regular80byte state",
                ),
            ));
        }
        let mut bytes = [0; BYTES];
        file.read_exact(&mut bytes)
            .map_err(|e| fail(Stage::Read, Outcome::NotCommitted, e))?;
        let after =
            fs::symlink_metadata(&self.path).map_err(|e| fail(Stage::Read, Outcome::Unknown, e))?;
        if !after.is_file()
            || (after.dev(), after.ino(), after.len()) != (before.dev(), before.ino(), BYTES as u64)
        {
            return Err(fail(
                Stage::Read,
                Outcome::Unknown,
                io::Error::other("monotime state changed during read"),
            ));
        }
        State::decode(bytes)
            .map(Some)
            .map_err(|e| fail(Stage::Read, Outcome::NotCommitted, e))
    }
    fn temporary(&mut self) -> Result<(File, Temporary), Error> {
        for _ in 0..64 {
            self.temporary = self.temporary.checked_add(1).ok_or_else(|| {
                fail(
                    Stage::Write,
                    Outcome::NotCommitted,
                    io::Error::other("monotime temporary counter exhausted"),
                )
            })?;
            let mut name = self
                .path
                .file_name()
                .ok_or_else(|| {
                    fail(
                        Stage::Write,
                        Outcome::NotCommitted,
                        io::Error::other("missing monotime state name"),
                    )
                })?
                .to_os_string();
            name.push(format!(
                ".cadet-new-{}-{}",
                std::process::id(),
                self.temporary
            ));
            let path = self.parent.join(name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => {
                    let m = file
                        .metadata()
                        .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?;
                    return Ok((
                        file,
                        Temporary {
                            path,
                            identity: (m.dev(), m.ino()),
                            renamed: false,
                        },
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(fail(Stage::Write, Outcome::NotCommitted, e)),
            }
        }
        Err(fail(
            Stage::Write,
            Outcome::NotCommitted,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "bounded monotime temporary namespace is occupied",
            ),
        ))
    }
    /// Explicitly persist a checked range before exposing any value. The new
    /// start is max(wall_us, previous_high+1), so wall-clock rollback/restart
    /// cannot reuse a value. This method may block on filesystem IO; call it
    /// outside socket polling, then consume the returned Range in memory.
    pub fn reserve(&mut self, wall_us: u64, count: u64) -> Result<Range, Error> {
        self.reserve_observed(wall_us, count, || Ok(()))
    }
    fn reserve_observed(
        &mut self,
        wall_us: u64,
        count: u64,
        after_rename: impl FnOnce() -> io::Result<()>,
    ) -> Result<Range, Error> {
        self.fence()?;
        if self.unknown.is_some() {
            return Err(fail(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original monotime reservation unresolved"),
            ));
        }
        if count == 0 {
            return Err(fail(
                Stage::Reserve,
                Outcome::NotCommitted,
                io::Error::new(io::ErrorKind::InvalidInput, "empty monotime reservation"),
            ));
        }
        if self.read()? != self.loaded {
            return Err(fail(
                Stage::Fence,
                Outcome::Unknown,
                io::Error::other("monotime state changed outside original writer"),
            ));
        }
        let floor = self.loaded.map_or(0, |state| state.high);
        let first = wall_us.max(floor.checked_add(1).ok_or_else(|| {
            fail(
                Stage::Reserve,
                Outcome::NotCommitted,
                io::Error::other("monotime high-water exhausted"),
            )
        })?);
        let high = first.checked_add(count - 1).ok_or_else(|| {
            fail(
                Stage::Reserve,
                Outcome::NotCommitted,
                io::Error::other("monotime range overflow"),
            )
        })?;
        let state = State {
            local: self.local,
            high,
        };
        let (mut file, mut temporary) = self.temporary()?;
        file.write_all(&state.bytes())
            .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?;
        file.sync_all()
            .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?;
        self.fence()?;
        // Even a rename error can be uncertain on a remote filesystem. No range
        // is returned and this owner remains blocked until exact reconciliation.
        self.unknown = Some(state);
        fs::rename(&temporary.path, &self.path)
            .map_err(|e| fail(Stage::Rename, Outcome::Unknown, e))?;
        temporary.renamed = true;
        after_rename().map_err(|e| fail(Stage::DirectorySync, Outcome::Unknown, e))?;
        self.reconcile()?;
        Ok(Range {
            local: self.local,
            next: first,
            left: count,
            lease: Some(self.guard.clone()),
        })
    }
    /// Explicit synchronous one-value convenience. Socket/reactor paths should
    /// use a previously reserved Range instead of doing implicit fsync here.
    pub fn next(&mut self, wall_us: u64) -> Result<u64, Error> {
        let mut range = self.reserve(wall_us, 1)?;
        range
            .take_next()
            .map_err(|reason| fail(Stage::Reserve, Outcome::Unknown, io::Error::other(reason)))
    }
    /// Settle only the original uncertain high-water by actual directory sync
    /// and exact readback. Its entire range remains burned; this does not return
    /// it to a caller or retry an already exposed signature operation.
    pub fn reconcile(&mut self) -> Result<(), Error> {
        self.fence()?;
        let Some(expected) = self.unknown else {
            return Ok(());
        };
        self.directory
            .sync_all()
            .map_err(|e| fail(Stage::Recovery, Outcome::Unknown, e))?;
        let actual = self.read().map_err(|mut e| {
            e.outcome = Outcome::Unknown;
            e
        })?;
        if actual != Some(expected) {
            return Err(fail(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original monotime high-water readback differs"),
            ));
        }
        self.loaded = Some(expected);
        self.unknown = None;
        Ok(())
    }
}
struct Temporary {
    path: PathBuf,
    identity: (u64, u64),
    renamed: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.renamed
            && fs::symlink_metadata(&self.path)
                .is_ok_and(|m| m.is_file() && (m.dev(), m.ino()) == self.identity)
        {
            let _removed = fs::remove_file(&self.path);
        }
    }
}
#[cfg(test)]
mod tests;
