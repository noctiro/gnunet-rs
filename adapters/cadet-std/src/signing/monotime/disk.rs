//! Fixed-size Rust monotime state, one actual writer lock and atomic durability.
use super::{Lease, Range};
use gnunet_crypto::hash256;
mod files;
use super::DirectorySync;
use files::Files;
use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
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
    files: Files,
    local: [u8; 32],
    loaded: Option<State>,
    unknown: Option<State>,
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
        name.push(
            std::str::from_utf8(&suffix).map_err(|error| {
                fail(Stage::Fence, Outcome::NotCommitted, io::Error::other(error))
            })?,
        );
        Self::open(stem.with_file_name(name), local)
    }
    /// Acquire the actual exclusive OS writer lock and validate exact existing
    /// state before allocating any value. Missing state is distinct from zero.
    /// A changed public peer is refused; identity rotation uses a new state path.
    pub fn open(path: PathBuf, local: [u8; 32]) -> Result<Self, Error> {
        let files = Files::open(&path)?;
        let mut store = Self {
            files,
            local,
            loaded: None,
            unknown: None,
        };
        store.loaded = store.read()?;
        store
            .files
            .lease
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
        if self.read()? != self.loaded {
            return Err(fail(
                Stage::Fence,
                Outcome::Unknown,
                io::Error::other("monotime state changed outside original writer"),
            ));
        }
        Ok(self.loaded.map(|state| state.high))
    }
    fn fence(&self) -> Result<(), Error> {
        self.files.fence()
    }
    fn read(&self) -> Result<Option<State>, Error> {
        self.files
            .read()?
            .map(State::decode)
            .transpose()
            .map_err(|error| fail(Stage::Read, Outcome::NotCommitted, error))
    }
    /// Last completed native naming-barrier observation. An active uncertain
    /// replacement has no current observation. No I/O occurs.
    #[must_use]
    pub fn directory_sync(&self) -> Option<DirectorySync> {
        if self.unknown.is_some() {
            None
        } else {
            self.files.directory_sync()
        }
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
        let mut temporary = self.files.temporary()?;
        temporary.write(&state.bytes())?;
        let prepared = self.files.prepare(&mut temporary)?;
        // Replacement may have applied even when native completion fails. Both
        // original images stay pinned and no range is exposed before settlement.
        self.unknown = Some(state);
        prepared.publish()?;
        after_rename().map_err(|e| fail(Stage::DirectorySync, Outcome::Unknown, e))?;
        self.reconcile()?;
        Ok(Range {
            local: self.local,
            next: first,
            left: count,
            lease: Some(self.files.lease.clone()),
            directory_sync: self.files.directory_sync().ok_or_else(|| {
                fail(
                    Stage::Recovery,
                    Outcome::Unknown,
                    io::Error::other("missing monotime naming observation"),
                )
            })?,
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
    /// Settle the original uncertain high-water using native file/metadata
    /// synchronization, an observed directory barrier and exact readback. Its entire range remains burned; this does not return
    /// it to a caller or retry an already exposed signature operation.
    pub fn reconcile(&mut self) -> Result<(), Error> {
        self.fence()?;
        let Some(expected) = self.unknown else {
            return Ok(());
        };
        self.files.settle()?;
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
        self.files.adopt()?;
        self.loaded = Some(expected);
        self.unknown = None;
        Ok(())
    }
}
#[cfg(test)]
mod tests;
