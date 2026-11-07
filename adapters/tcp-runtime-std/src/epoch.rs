//! Fenced TCP process epoch and persistent signed-time frontier. This private
//! Rust format is not a C database and never changes any official wire field.
use gnunet_crypto::EddsaPublicKey;
use gnunet_tcp_replay_host::{CatalogLease, Floor};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
/// Actual native operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Original kernel writer fence/namespace.
    Fence,
    /// Exact persisted state read.
    Read,
    /// Atomic temporary write/fsync/rename.
    Write,
    /// Parent directory durability barrier.
    DirectorySync,
    /// Original uncertain commit readback.
    Recovery,
    /// Prior backend effects lack original quiescence.
    BackendQuarantine,
    /// Bounded frontier arithmetic/admission.
    Reservation,
}
/// Whether this failed local operation may already have changed durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// No durable commit of this operation was admitted.
    NotCommitted,
    /// Original commit/authority may be changed; new stamps are blocked.
    Unknown,
}
/// Original actual cause. Unknown outcomes stay owned until exact reconciliation.
#[derive(Debug)]
pub struct Failure {
    /// Original stage.
    pub stage: Stage,
    /// Original certainty.
    pub outcome: Outcome,
    /// Actual OS/resource cause.
    pub cause: io::Error,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}/{:?}: {}", self.stage, self.outcome, self.cause)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn failure(stage: Stage, outcome: Outcome, cause: io::Error) -> Failure {
    Failure {
        stage,
        outcome,
        cause,
    }
}
/// Exact original persisted state, including a missing-file distinction at open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    /// A process epoch may still have unsettled public backend work.
    pub dirty: bool,
    /// Highest reserved signed timestamp, whether used or abandoned. Replay floors
    /// and their minimum durable generation are independent private V2 fields.
    pub reserved: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    id: [u8; 32],
    local: EddsaPublicKey,
    minimum: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Persisted {
    state: State,
    binding: Binding,
}
impl Persisted {
    fn bytes(self) -> [u8; 89] {
        gnunet_tcp_replay_host::pairing::FrontierImage {
            dirty: self.state.dirty,
            reserved: self.state.reserved,
            ledger: self.binding.id,
            local: self.binding.local,
            minimum: self.binding.minimum,
        }
        .encode()
    }
    fn decode(bytes: [u8; 89]) -> io::Result<Self> {
        let value = gnunet_tcp_replay_host::pairing::FrontierImage::decode(bytes)?;
        Ok(Self {
            state: State {
                dirty: value.dirty,
                reserved: value.reserved,
            },
            binding: Binding {
                id: value.ledger,
                local: value.local,
                minimum: value.minimum,
            },
        })
    }
}
/// Unique original epoch capability. Dropping it cannot make a dirty epoch clean.
#[derive(Debug)]
pub struct Epoch {
    pub(crate) owner: Arc<()>,
    pub(crate) serial: u64,
    pub(crate) peer: EddsaPublicKey,
}
/// Actual original closed-pool proof. Only Pool's consuming quiescent path can
/// produce this public value; no PID, bool or successful reconnect creates it.
#[derive(Debug)]
pub struct Quiescent {
    pub(crate) epoch: Epoch,
}
/// Rejected original finish keeps the same unique proof and actual native cause.
#[derive(Debug)]
pub struct FinishRejected {
    /// Original proof, never a replacement identity.
    pub proof: Quiescent,
    /// Actual failure, including postrename uncertainty.
    pub error: Failure,
}
/// Original floor retained if its frontier durability barrier failed.
#[derive(Debug)]
pub struct ReplayRejected {
    /// Same original actual durable floor.
    pub floor: Floor,
    /// Original frontier failure/uncertainty.
    pub error: Failure,
}
/// Private local permit formed only after actual ledger persistence and the
/// frontier min-generation durability barrier. Not a remote STORE receipt.
#[derive(Debug)]
pub struct ReplayPermit {
    owner: Arc<()>,
    serial: u64,
    local: EddsaPublicKey,
    floor: Floor,
}
impl ReplayPermit {
    /// Same original persisted peer/kind/stamp/token, without rebranding.
    #[must_use]
    pub const fn floor(&self) -> &Floor {
        &self.floor
    }
    /// Require the actual same active process epoch and live ledger authority.
    pub fn validate(&self, epoch: &Epoch) -> Result<(), gnunet_types::Error> {
        self.floor.validate()?;
        if !Arc::ptr_eq(&self.owner, &epoch.owner)
            || self.serial != epoch.serial
            || self.local != epoch.peer
        {
            return Err(gnunet_types::Error::Stale);
        }
        Ok(())
    }
}
/// One original OS lock and original pending uncertain state. The guard path is
/// persistent state ownership, never a PID-file lock. Dirty recovery requires
/// the actual same initialized replay ledger, not remote backend quiescence.
pub struct Store {
    path: PathBuf,
    parent: PathBuf,
    guard_path: PathBuf,
    guard: File,
    guard_identity: (u64, u64),
    parent_identity: (u64, u64),
    brand: Arc<()>,
    serial: u64,
    active: Option<(u64, EddsaPublicKey)>,
    loaded: Option<Persisted>,
    unknown: Option<Persisted>,
    catalog: Option<CatalogLease>,
}
impl Store {
    /// Lock and read only the V2/89byte frontier. V1 and unknown formats are
    /// explicitly refused; no empty replay ledger can migrate an old dirty epoch.
    pub fn open(path: PathBuf) -> Result<Self, Failure> {
        gnunet_service_runtime::private_parents(&path)
            .map_err(|e| failure(Stage::Fence, Outcome::NotCommitted, e))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        let mut name = path
            .file_name()
            .ok_or_else(|| {
                failure(
                    Stage::Fence,
                    Outcome::NotCommitted,
                    io::Error::other("missing frontier name"),
                )
            })?
            .to_os_string();
        name.push(".tcp-lock");
        let guard_path = parent.join(name);
        let guard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&guard_path)
            .map_err(|e| failure(Stage::Fence, Outcome::NotCommitted, e))?;
        guard
            .try_lock()
            .map_err(|e| failure(Stage::Fence, Outcome::NotCommitted, e.into()))?;
        let meta = guard
            .metadata()
            .map_err(|e| failure(Stage::Fence, Outcome::NotCommitted, e))?;
        let dir =
            fs::metadata(&parent).map_err(|e| failure(Stage::Fence, Outcome::NotCommitted, e))?;
        if !meta.is_file() || !dir.is_dir() {
            return Err(failure(
                Stage::Fence,
                Outcome::NotCommitted,
                io::Error::other("invalid frontier namespace"),
            ));
        }
        let mut store = Self {
            path,
            parent,
            guard_path,
            guard,
            guard_identity: (meta.dev(), meta.ino()),
            parent_identity: (dir.dev(), dir.ino()),
            brand: Arc::new(()),
            serial: 0,
            active: None,
            loaded: None,
            unknown: None,
            catalog: None,
        };
        store
            .directory_sync()
            .map_err(|e| failure(Stage::DirectorySync, Outcome::Unknown, e))?;
        store.loaded = store.read()?;
        Ok(store)
    }
    fn fence(&self) -> Result<(), Failure> {
        let actual = fs::symlink_metadata(&self.guard_path)
            .map_err(|e| failure(Stage::Fence, Outcome::Unknown, e))?;
        let held = self
            .guard
            .metadata()
            .map_err(|e| failure(Stage::Fence, Outcome::Unknown, e))?;
        let dir =
            fs::metadata(&self.parent).map_err(|e| failure(Stage::Fence, Outcome::Unknown, e))?;
        if !actual.is_file()
            || (actual.dev(), actual.ino()) != self.guard_identity
            || (held.dev(), held.ino()) != self.guard_identity
            || !dir.is_dir()
            || (dir.dev(), dir.ino()) != self.parent_identity
        {
            return Err(failure(
                Stage::Fence,
                Outcome::Unknown,
                io::Error::other("original TCP frontier fence/namespace changed"),
            ));
        }
        Ok(())
    }
    fn directory_sync(&self) -> io::Result<()> {
        File::open(&self.parent)?.sync_all()
    }
    fn read(&self) -> Result<Option<Persisted>, Failure> {
        self.fence()?;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(failure(Stage::Read, Outcome::NotCommitted, e)),
        };
        let meta = file
            .metadata()
            .map_err(|e| failure(Stage::Read, Outcome::NotCommitted, e))?;
        if !meta.is_file() || meta.len() != 89 {
            return Err(failure(
                Stage::Read,
                Outcome::NotCommitted,
                io::Error::other(
                    "frontier is not exact regular V2/89byte state; legacy V1 is not recoverable",
                ),
            ));
        }
        let mut bytes = [0; 89];
        file.read_exact(&mut bytes)
            .map_err(|e| failure(Stage::Read, Outcome::NotCommitted, e))?;
        Persisted::decode(bytes)
            .map(Some)
            .map_err(|e| failure(Stage::Read, Outcome::NotCommitted, e))
    }
    /// Actual loaded state. A missing file remains None, distinct from clean zero.
    pub fn loaded(&self) -> Result<Option<State>, Failure> {
        self.fence()?;
        if self.unknown.is_some() {
            return Err(failure(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original frontier commit uncertain"),
            ));
        }
        if self.active.is_some() {
            self.catalog
                .as_ref()
                .ok_or_else(|| {
                    failure(
                        Stage::BackendQuarantine,
                        Outcome::Unknown,
                        io::Error::other("missing original ledger authority"),
                    )
                })?
                .validate()
                .map_err(|error| {
                    failure(
                        Stage::BackendQuarantine,
                        Outcome::Unknown,
                        io::Error::other(error),
                    )
                })?;
        }
        Ok(self.loaded.map(|value| value.state))
    }
    /// Persist the original local/public LedgerId bootstrap intent before any
    /// replay ledger directory/marker creation. min0 can never begin an epoch,
    /// reserve signed time, or authorize a floor. Existing V2 identity and all
    /// burned time are retained; old V1 was already rejected by open.
    pub fn prepare_replay(
        &mut self,
        peer: EddsaPublicKey,
        ledger_directory: &Path,
    ) -> Result<(), Failure> {
        self.fence()?;
        if self.active.is_some() || self.unknown.is_some() {
            return Err(failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("original frontier is active or uncertain"),
            ));
        }
        if let Some(actual) = self.loaded {
            if actual.binding.local != peer {
                return Err(failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("cannot change original replay/local identity"),
                ));
            }
            return Ok(());
        }
        // A missing frontier is fresh only before ANY final ledger footprint.
        // Never mint min0 over an old Bound/unmarked/foreign directory and later
        // reinterpret its missing image as an interrupted initialization.
        match fs::symlink_metadata(ledger_directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(failure(Stage::BackendQuarantine, Outcome::Unknown, error)),
            Ok(_) => {
                return Err(failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("missing frontier with existing replay ledger footprint"),
                ));
            }
        }
        let mut id = [0; 32];
        getrandom::fill(&mut id)
            .map_err(|e| failure(Stage::Write, Outcome::NotCommitted, io::Error::other(e)))?;
        if id == [0; 32] {
            return Err(failure(
                Stage::Write,
                Outcome::NotCommitted,
                io::Error::other("invalid public bootstrap identity"),
            ));
        }
        self.update_bound(
            Persisted {
                state: State {
                    dirty: false,
                    reserved: 0,
                },
                binding: Binding {
                    id,
                    local: peer,
                    minimum: 0,
                },
            },
            || {},
        )
    }
    /// Attach only an actual initialized/loaded complete ledger. New frontier
    /// initialization persists its identity before any epoch, signature or PS
    /// STORE. Existing V2 binding is never replaced, even after clean shutdown.
    pub fn attach_catalog(&mut self, catalog: CatalogLease) -> Result<(), Failure> {
        self.fence()?;
        if self.loaded.is_none() {
            return Err(failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("persist bootstrap intent before ledger creation"),
            ));
        }
        if self.active.is_some() || self.unknown.is_some() {
            return Err(failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("frontier has an active or uncertain original epoch"),
            ));
        }
        catalog.validate_binding().map_err(|e| {
            failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other(e),
            )
        })?;
        if let Some(actual) = self.loaded
            && (actual.binding.id != *catalog.identity().as_bytes()
                || actual.binding.local != catalog.local()
                || catalog.generation() < actual.binding.minimum)
        {
            return Err(failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("foreign, replaced or rolled-back replay ledger"),
            ));
        }
        catalog
            .claim_frontier(&self.brand, self.loaded.is_none())
            .map_err(|error| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other(error),
                )
            })?;
        let promote = self.loaded.filter(|value| value.binding.minimum == 0);
        if let Some(mut actual) = promote {
            if actual.state.dirty
                || actual.state.reserved != 0
                || catalog.is_bound()
                || catalog.generation() != 1
            {
                return Err(failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("invalid original initialization phase"),
                ));
            }
            actual.binding.minimum = 1;
            self.update_bound(actual, || {})?;
        }
        self.catalog = Some(catalog);

        Ok(())
    }
    /// Start after actual same-identity complete-catalog recovery. A new dirty
    /// process may recover because every remote replay write was preceded by
    /// local ledger+frontier persistence, not because old IO is quiescent. V1,
    /// missing/replaced/older/unknown catalogs and changed local identities fail.
    pub fn begin(&mut self, peer: EddsaPublicKey) -> Result<Epoch, Failure> {
        self.fence()?;
        if self.unknown.is_some() || self.active.is_some() || self.loaded.is_none() {
            return Err(failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("original frontier has no certain initialized ledger"),
            ));
        }
        let catalog = self.catalog.as_ref().ok_or_else(|| {
            failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("actual complete replay ledger proof required"),
            )
        })?;
        catalog.validate_recovery().map_err(|e| {
            failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other(e),
            )
        })?;
        let actual = self.loaded.ok_or_else(|| {
            failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("missing frontier"),
            )
        })?;
        if actual.binding.minimum == 0
            || actual.binding.id != *catalog.identity().as_bytes()
            || actual.binding.local != peer
            || catalog.local() != peer
            || catalog.generation() < actual.binding.minimum
        {
            return Err(failure(
                Stage::BackendQuarantine,
                Outcome::Unknown,
                io::Error::other("original local identity or ledger binding differs"),
            ));
        }
        let serial = self.serial.checked_add(1).ok_or_else(|| {
            failure(
                Stage::Reservation,
                Outcome::NotCommitted,
                io::Error::other("epoch generation exhausted"),
            )
        })?;
        self.update(
            State {
                dirty: true,
                reserved: actual.state.reserved,
            },
            || {},
        )?;
        self.serial = serial;
        self.active = Some((serial, peer));
        Ok(Epoch {
            owner: self.brand.clone(),
            serial,
            peer,
        })
    }
    /// The only local authorization for an original PS STORE: actual Floor,
    /// same ledger source/local identity, then actual durable frontier minGen.
    /// Failure preserves the original Floor; uncertainty never becomes permit.
    pub fn authorize_replay(&mut self, floor: Floor) -> Result<ReplayPermit, ReplayRejected> {
        let result = (|| -> Result<(u64, EddsaPublicKey), Failure> {
            self.fence()?;
            if self.unknown.is_some() {
                return Err(failure(
                    Stage::Recovery,
                    Outcome::Unknown,
                    io::Error::other("frontier publication unresolved"),
                ));
            }
            let (serial, local) = self.active.ok_or_else(|| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("no current epoch"),
                )
            })?;
            floor.validate().map_err(|e| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other(e),
                )
            })?;
            let catalog = self.catalog.as_ref().ok_or_else(|| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("no current ledger"),
                )
            })?;
            if !catalog.owns(&floor) || floor.local() != local {
                return Err(failure(
                    Stage::BackendQuarantine,
                    Outcome::NotCommitted,
                    io::Error::other("floor belongs to another original ledger/local identity"),
                ));
            }
            let mut actual = self.loaded.ok_or_else(|| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("missing frontier"),
                )
            })?;
            if actual.binding.id != *floor.identity().as_bytes() || actual.binding.local != local {
                return Err(failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("floor binding differs"),
                ));
            }
            if floor.generation() > actual.binding.minimum {
                actual.binding.minimum = floor.generation();
                self.update_bound(actual, || {})?;
            }
            Ok((serial, local))
        })();
        match result {
            Ok((serial, local)) => Ok(ReplayPermit {
                owner: self.brand.clone(),
                serial,
                local,
                floor,
            }),
            Err(error) => Err(ReplayRejected { floor, error }),
        }
    }
    /// Recheck the exact original active permit before actual PS enqueue.
    pub fn validate_replay(&self, permit: &ReplayPermit) -> Result<(), gnunet_types::Error> {
        permit.floor.validate()?;
        if self.unknown.is_some()
            || !Arc::ptr_eq(&self.brand, &permit.owner)
            || self.active != Some((permit.serial, permit.local))
        {
            return Err(gnunet_types::Error::Stale);
        }
        Ok(())
    }
    /// Reserve a nonreused signed-time range only after exact file/directory
    /// durability. No timestamp is returned on any failed/unknown commit.
    pub fn reserve(&mut self, utc: u64, count: u64) -> Result<(u64, u64), Failure> {
        self.reserve_observed(utc, count, || {})
    }
    fn reserve_observed(
        &mut self,
        utc: u64,
        count: u64,
        after: impl FnOnce(),
    ) -> Result<(u64, u64), Failure> {
        self.fence()?;
        if self.active.is_none() || self.unknown.is_some() {
            return Err(failure(
                Stage::Reservation,
                Outcome::Unknown,
                io::Error::other("no current certain frontier epoch"),
            ));
        }
        self.catalog
            .as_ref()
            .ok_or_else(|| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("missing original replay ledger"),
                )
            })?
            .validate()
            .map_err(|e| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other(e),
                )
            })?;
        if count == 0 {
            return Err(failure(
                Stage::Reservation,
                Outcome::NotCommitted,
                io::Error::other("empty frontier reservation"),
            ));
        }
        let floor = self.loaded.map_or(0, |s| s.state.reserved);
        let start = utc.max(floor.checked_add(1).ok_or_else(|| {
            failure(
                Stage::Reservation,
                Outcome::NotCommitted,
                io::Error::other("frontier exhausted"),
            )
        })?);
        let end = start.checked_add(count - 1).ok_or_else(|| {
            failure(
                Stage::Reservation,
                Outcome::NotCommitted,
                io::Error::other("frontier exhausted"),
            )
        })?;
        self.update(
            State {
                dirty: true,
                reserved: end,
            },
            after,
        )?;
        Ok((start, end))
    }
    fn settle(&mut self) -> Result<(), Failure> {
        let Some(expected) = self.unknown else {
            return self.fence();
        };
        self.fence()?;
        self.directory_sync()
            .map_err(|e| failure(Stage::Recovery, Outcome::Unknown, e))?;
        let actual = self.read().map_err(|mut e| {
            e.outcome = Outcome::Unknown;
            e
        })?;
        if actual != Some(expected) {
            return Err(failure(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original uncertain frontier readback differs"),
            ));
        }
        self.loaded = Some(expected);
        self.unknown = None;
        Ok(())
    }
    /// Mark only this original fully retired pool clean. On any error the caller
    /// receives the same proof; a later actor cannot silently substitute for it.
    pub fn finish(&mut self, proof: Quiescent) -> Result<(), FinishRejected> {
        if !Arc::ptr_eq(&self.brand, &proof.epoch.owner)
            || self.active != Some((proof.epoch.serial, proof.epoch.peer))
        {
            return Err(FinishRejected {
                proof,
                error: failure(
                    Stage::BackendQuarantine,
                    Outcome::NotCommitted,
                    io::Error::other("foreign/stale quiescent proof"),
                ),
            });
        }
        if let Err(error) = self.settle() {
            return Err(FinishRejected { proof, error });
        }
        let state = State {
            dirty: false,
            reserved: self.loaded.map_or(0, |s| s.state.reserved),
        };
        if self.loaded.map(|value| value.state) != Some(state)
            && let Err(error) = self.update(state, || {})
        {
            return Err(FinishRejected { proof, error });
        }
        self.active = None;
        Ok(())
    }
    fn update(&mut self, state: State, after: impl FnOnce()) -> Result<(), Failure> {
        let binding = self
            .loaded
            .ok_or_else(|| {
                failure(
                    Stage::BackendQuarantine,
                    Outcome::Unknown,
                    io::Error::other("original durable bootstrap intent required"),
                )
            })?
            .binding;
        self.update_bound(Persisted { state, binding }, after)
    }
    fn update_bound(&mut self, state: Persisted, after: impl FnOnce()) -> Result<(), Failure> {
        self.fence()?;
        if self.unknown.is_some() {
            return Err(failure(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original frontier commit unresolved"),
            ));
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)
            .map_err(|e| failure(Stage::Write, Outcome::NotCommitted, io::Error::other(e)))?;
        let label: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let path = self.parent.join(format!(".tcp-frontier-{label}.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| failure(Stage::Write, Outcome::NotCommitted, e))?;
        let meta = file
            .metadata()
            .map_err(|e| failure(Stage::Write, Outcome::NotCommitted, e))?;
        let mut temporary = Temporary {
            path,
            identity: (meta.dev(), meta.ino()),
            renamed: false,
        };
        file.write_all(&state.bytes())
            .map_err(|e| failure(Stage::Write, Outcome::NotCommitted, e))?;
        file.sync_all()
            .map_err(|e| failure(Stage::Write, Outcome::NotCommitted, e))?;
        self.fence()?;
        fs::rename(&temporary.path, &self.path)
            .map_err(|e| failure(Stage::Write, Outcome::NotCommitted, e))?;
        temporary.renamed = true;
        self.unknown = Some(state);
        after();
        self.directory_sync()
            .map_err(|e| failure(Stage::DirectorySync, Outcome::Unknown, e))?;
        let actual = self.read().map_err(|mut e| {
            e.outcome = Outcome::Unknown;
            e
        })?;
        if actual != Some(state) {
            return Err(failure(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original frontier commit readback differs"),
            ));
        }
        self.loaded = Some(state);
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
            && let Ok(meta) = fs::symlink_metadata(&self.path)
            && meta.is_file()
            && (meta.dev(), meta.ino()) == self.identity
        {
            let _removed = fs::remove_file(&self.path);
        }
    }
}
