//! Persisted stable-file unindex through the original native transfer owner.
//!
//! Private WAL receipts preserve actual local acknowledgements. A fresh run
//! rehashes the complete file before reusing them. An unfinished intent fences
//! ordinary resume; only explicit `restart_uncertain` admits a new independent
//! cleanup attempt, retaining the old uncertainty without reporting success.
use crate::{
    Buffers, Control as NativeControl,
    durable::store::{self, Store},
    extraction::{self, MetadataSettings},
    network::unindex::{self, Observation, Operation, Recorder},
};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::Hash512State;
use gnunet_datastore_host::Client;
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::time::Instant;

const MANIFEST: u16 = 0x5500;
const SOURCE: u16 = 0x5501;
const KEYWORDS: u16 = 0x5502;
const BEGIN: u16 = 0x5503;
const INTENT: u16 = 0x5504;
const RECEIPT: u16 = 0x5505;
const END: u16 = 0x5506;
const RESTART: u16 = 0x5507;
const CANCEL: u16 = 0x5508;
const KEYWORD_END: u16 = 0x5509;
const NOT_SUBMITTED: u16 = 0x550a;
const MAGIC: &[u8; 8] = b"FSUNIDX2";

/// Explicit original private storage and mutation-attempt budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Underlying checksummed WAL, record, file and retained-body bounds.
    pub storage: store::Limits,
    /// Number of recorded original mutation attempts across all runs/restarts.
    pub max_operations: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            storage: store::Limits::default(),
            max_operations: 16384,
        }
    }
}
/// Immutable original task policy; no native deadline or source token is stored.
#[derive(Debug)]
pub struct Manifest {
    /// Original canonical absolute native filename, without lossy conversion.
    pub filename: PathBuf,
    /// Literal additional keyword labels selected at creation.
    pub extra_keywords: Vec<Vec<u8>>,
    /// Original automatic extraction selection, restored without loading a
    /// provider. Once KEYWORDS is recorded, its exact terms take precedence.
    pub metadata: MetadataSettings,
    /// Lifetime bound on recorded mutation attempts, including refused admission.
    pub max_operations: u32,
}
/// Local logical phase. A pending intent remains independently visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No original run admitted.
    Ready,
    /// Internal active run marker, derived as Interrupted on status.
    Running,
    /// Original native owners retired after caller pause or safe deadline.
    Paused,
    /// Original failed run; retained uncertainty stays independently visible.
    Failed,
    /// Every selected original cleanup stage has its actual accepted receipt.
    Complete,
    /// Permanently cancelled, retaining unfinished original mutations.
    Cancelled,
    /// Running history without the exclusive live run borrow.
    Interrupted,
}
/// Cooperative intent for this original run, with native retirement before END.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Continue this original run.
    Continue,
    /// Retire native work and retain the task for a later explicit run.
    Pause,
    /// Retire native work and permanently stop future runs.
    Cancel,
}
/// Immutable original mutation binding; it conveys no native completion token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Original {
    /// 1 is content REMOVE; 2 is FS Unindex; 3 is exact keyword REMOVE.
    pub kind: u8,
    /// SHA512 of kind and exact original operation bytes, never a private wire ID.
    pub digest: [u8; 64],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Intent {
    kind: u8,
    digest: [u8; 64],
    key: [u8; 64],
}
impl Intent {
    fn original(self) -> Original {
        Original {
            kind: self.kind,
            digest: self.digest,
        }
    }

    fn of(operation: Operation<'_>) -> Self {
        let mut hash = Hash512State::new();
        let (kind, key) = match operation {
            Operation::Remove {
                key,
                value,
                keyword,
            } => {
                let kind = if keyword { 3 } else { 1 };
                hash.update(&[kind]);
                hash.update(key);
                hash.update(value);
                (kind, *key)
            }
            Operation::Unindex { file_id } => {
                hash.update(&[2]);
                hash.update(file_id);
                (2, *file_id)
            }
        };
        Self {
            kind,
            digest: hash.finish(),
            key,
        }
    }
    fn encode(self) -> [u8; 129] {
        let mut bytes = [0; 129];
        bytes[0] = self.kind;
        bytes[1..65].copy_from_slice(&self.digest);
        bytes[65..].copy_from_slice(&self.key);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, Cause> {
        if bytes.len() != 129 || !matches!(bytes[0], 1..=3) {
            return Err(Cause::Malformed);
        }
        Ok(Self {
            kind: bytes[0],
            digest: bytes[1..65].try_into().map_err(|_| Cause::Malformed)?,
            key: bytes[65..].try_into().map_err(|_| Cause::Malformed)?,
        })
    }
}
/// Local current state and historical counters, not present store absence proof.
#[derive(Clone, Copy, Debug)]
pub struct Status {
    /// Running WAL reopened or a dropped run is reported as Interrupted.
    pub phase: Phase,
    /// Original fresh run generations admitted so far.
    pub runs: u32,
    /// Original mutation intents, including unfinished/explicitly abandoned ones.
    pub operations: u32,
    /// Distinct exact original operations with persisted accepted responses.
    pub accepted: usize,
    /// Original request with no durable terminal receipt; ordinary run refuses it.
    pub pending: Option<Original>,
    /// Count of previous unfinished intents explicitly left unknown on restart.
    pub abandoned_uncertain: u32,
    /// Recorded original attempts definitively refused before native admission.
    pub not_submitted: u32,
    /// Full original source hash and size have been recorded.
    pub source_bound: bool,
    /// Original complete selected keyword set has been recorded.
    pub keywords_bound: bool,
    /// Keyword selections with an original accepted REMOVE or actual DATA_END.
    pub completed_keywords: usize,
    /// The original WAL writer has an uncertain storage failure.
    pub fenced: bool,
    /// The original exclusive run future currently owns native work.
    pub active: bool,
}
impl Status {
    fn resumable(self) -> bool {
        self.phase == Phase::Paused && self.pending.is_none() && !self.active && !self.fenced
    }
}

/// Original structural/storage/caller-policy failure.
#[derive(Debug)]
pub enum Cause {
    /// Actual bounded WAL or physical writer/authority failure.
    Storage(store::Error),
    /// Actual native path preparation/open refusal.
    Io(std::io::Error),
    /// Original explicit allocation, capacity, shape or cryptographic refusal.
    Protocol(Fault),
    /// Original automatic selection/snapshot error, including provider limits.
    Metadata(extraction::Error),
    /// Task records or record ordering are inconsistent.
    Malformed,
    /// The actual fully hashed source differs from the original source binding.
    SourceChanged,
    /// An unfinished original mutation requires an explicit new attempt decision.
    Uncertain(Original),
    /// This completed or permanently cancelled task admits no new run.
    Terminal,
}
impl From<store::Error> for Cause {
    fn from(e: store::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<std::io::Error> for Cause {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<Fault> for Cause {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<extraction::Error> for Cause {
    fn from(e: extraction::Error) -> Self {
        Self::Metadata(e)
    }
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Metadata(e) => e.fmt(f),
            Self::Malformed => f.write_str("malformed durable unindex history"),
            Self::SourceChanged => f.write_str("durable unindex original source changed"),
            Self::Uncertain(o) => write!(
                f,
                "unfinished original unindex operation: {o:?}; explicit restart required"
            ),
            Self::Terminal => f.write_str("durable unindex task is terminal"),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Metadata(e) => Some(e),
            _ => None,
        }
    }
}
/// Actual native result remains distinct from its independent journal failure.
#[derive(Debug)]
pub struct Failure {
    /// Last durable local state, retaining any original unresolved intent.
    pub status: Status,
    /// Original native operation, response, uncertainty and cleanup failures.
    pub native: Option<Box<unindex::Failure>>,
    /// Actual native successful report retained if later WAL settlement failed.
    pub completed: Option<unindex::Report>,
    /// Original storage, source, admission or lifecycle failure.
    pub cause: Option<Cause>,
    /// Independent state settlement failure when an earlier local failure
    /// already exists; neither replaces the original other cause.
    pub secondary: Option<Cause>,
}
impl Failure {
    /// Whether the exact original run stopped at a safe caller-Pause/deadline
    /// boundary with no pending mutation or independent state/retirement error.
    /// This permits a new bounded run, never replays an uncertain old request.
    pub fn resumable(&self) -> bool {
        self.status.resumable()
            && self.cause.is_none()
            && self.secondary.is_none()
            && self.completed.is_none()
            && self.native.as_ref().is_some_and(|native| {
                native.keywords.is_none()
                    && native.keyword_context.is_none()
                    && native.store_cleanup.is_none()
                    && native.fs_cleanup.is_none()
                    && native.fs_failure.is_none()
                    && native.settlement.is_none()
                    && native.preceding.is_none()
                    && (matches!(
                        &native.operation,
                        Some(
                            crate::network::Error::Cancelled(_)
                                | crate::network::Error::Deadline { first_io: None }
                        )
                    ) || native.report.observation.requested_cancel
                        && matches!(
                            &native.operation,
                            Some(crate::network::Error::Protocol(Fault::Cancelled))
                        ))
            })
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "durable unindex {:?}", self.status)?;
        if let Some(e) = &self.cause {
            write!(f, "; state: {e}")?;
        }
        if let Some(e) = &self.secondary {
            write!(f, "; independent state settlement: {e}")?;
        }
        if let Some(e) = &self.native {
            write!(f, "; native: {e}")?;
        }
        if let Some(r) = &self.completed {
            write!(f, "; actual native completion: {r:?}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
            .or_else(|| self.native.as_ref().map(|e| e.as_ref() as _))
    }
}
/// One native successful run and its separately persisted local terminal state.
#[derive(Debug)]
pub struct Report {
    /// Separately persisted logical terminal state.
    pub status: Status,
    /// Actual current native work, with historical reused receipts separated.
    pub native: unindex::Report,
}

impl Report {
    /// Whether this separately recorded task outcome permits a fresh bounded run.
    /// Accepted native Complete is terminal; a local Paused phase alone never
    /// grants an old uncertain request another transmission.
    pub fn resumable(&self) -> bool {
        self.status.resumable()
    }
}

struct State {
    phase: Phase,
    runs: u32,
    operations: u32,
    accepted: HashMap<[u8; 64], u8>,
    pending: Option<Intent>,
    abandoned: u32,
    not_submitted: u32,
    source: Option<([u8; 64], u64)>,
    keywords: Option<Vec<Vec<u8>>>,
    completed_keywords: HashSet<[u8; 64]>,
}
impl State {
    fn new() -> Self {
        Self {
            phase: Phase::Ready,
            runs: 0,
            operations: 0,
            accepted: HashMap::new(),
            pending: None,
            abandoned: 0,
            not_submitted: 0,
            source: None,
            keywords: None,
            completed_keywords: HashSet::new(),
        }
    }
    fn apply(&mut self, kind: u16, bytes: &[u8], limit: u32) -> Result<(), Cause> {
        match kind {
            SOURCE
                if self.phase == Phase::Running && self.source.is_none() && bytes.len() == 72 =>
            {
                let hash = bytes[..64].try_into().map_err(|_| Cause::Malformed)?;
                let size =
                    u64::from_be_bytes(bytes[64..].try_into().map_err(|_| Cause::Malformed)?);
                self.source = Some((hash, size));
            }
            KEYWORDS
                if self.phase == Phase::Running
                    && self.source.is_some()
                    && self.keywords.is_none() =>
            {
                self.keywords = Some(decode_keywords(bytes)?);
            }
            BEGIN
                if bytes.len() == 4
                    && !matches!(self.phase, Phase::Complete | Phase::Cancelled)
                    && self.pending.is_none() =>
            {
                let next = u32::from_be_bytes(bytes.try_into().map_err(|_| Cause::Malformed)?);
                if self.runs.checked_add(1) != Some(next) {
                    return Err(Cause::Malformed);
                }
                self.runs = next;
                self.phase = Phase::Running;
            }
            INTENT
                if self.phase == Phase::Running
                    && self.source.is_some()
                    && self.keywords.is_some()
                    && self.pending.is_none() =>
            {
                let op = Intent::decode(bytes)?;
                if self.operations >= limit || self.accepted.contains_key(&op.digest) {
                    return Err(Cause::Malformed);
                }
                if op.kind == 2
                    && self.source.is_none_or(|(file_id, _)| {
                        Intent::of(Operation::Unindex { file_id: &file_id }) != op
                    })
                {
                    return Err(Cause::Malformed);
                }
                self.operations += 1;
                self.pending = Some(op);
            }
            RECEIPT if self.phase == Phase::Running && bytes.len() == 134 => {
                let op = Intent::decode(&bytes[..129])?;
                if self.pending != Some(op) || bytes[133] > 1 {
                    return Err(Cause::Malformed);
                }
                let code =
                    i32::from_be_bytes(bytes[129..133].try_into().map_err(|_| Cause::Malformed)?);
                if bytes[133] == 1 {
                    if code < 0 || op.kind == 2 && code != 1 {
                        return Err(Cause::Malformed);
                    }
                    self.accepted.try_reserve(1).map_err(|_| Fault::Capacity)?;
                    self.accepted.insert(op.digest, op.kind);
                    if op.kind == 3 {
                        if self.completed_keywords.len()
                            >= self.keywords.as_ref().map_or(0, Vec::len)
                        {
                            return Err(Cause::Malformed);
                        }
                        self.completed_keywords
                            .try_reserve(1)
                            .map_err(|_| Fault::Capacity)?;
                        self.completed_keywords.insert(op.key);
                    }
                }
                self.pending = None;
            }
            KEYWORD_END
                if self.phase == Phase::Running
                    && self.pending.is_none()
                    && self.keywords.is_some()
                    && bytes.len() == 64 =>
            {
                let key = bytes.try_into().map_err(|_| Cause::Malformed)?;
                if self.completed_keywords.contains(&key)
                    || self.completed_keywords.len() >= self.keywords.as_ref().map_or(0, Vec::len)
                {
                    return Err(Cause::Malformed);
                }
                self.completed_keywords
                    .try_reserve(1)
                    .map_err(|_| Fault::Capacity)?;
                self.completed_keywords.insert(key);
            }
            END if self.phase == Phase::Running && bytes.len() == 1 => {
                self.phase = match bytes[0] {
                    2 => Phase::Paused,
                    3 => Phase::Failed,
                    4 if self.pending.is_none()
                        && self.source.is_some()
                        && self.keywords.is_some()
                        && self.accepted.values().any(|kind| *kind == 2)
                        && self.completed_keywords.len()
                            == self.keywords.as_ref().map_or(0, Vec::len) =>
                    {
                        Phase::Complete
                    }
                    5 => Phase::Cancelled,
                    _ => return Err(Cause::Malformed),
                };
            }
            NOT_SUBMITTED if self.phase == Phase::Running => {
                let op = Intent::decode(bytes)?;
                if self.pending != Some(op) {
                    return Err(Cause::Malformed);
                }
                self.not_submitted = self.not_submitted.checked_add(1).ok_or(Fault::Overflow)?;
                self.pending = None;
            }
            RESTART if !matches!(self.phase, Phase::Complete | Phase::Cancelled) => {
                let op = Intent::decode(bytes)?;
                if self.pending != Some(op) {
                    return Err(Cause::Malformed);
                }
                self.abandoned = self.abandoned.checked_add(1).ok_or(Fault::Overflow)?;
                self.pending = None;
                self.phase = Phase::Paused;
            }
            CANCEL if bytes.is_empty() && self.phase != Phase::Complete => {
                self.phase = Phase::Cancelled
            }
            _ => return Err(Cause::Malformed),
        }
        Ok(())
    }
}
fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, Cause> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Fault::Capacity)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
fn copy_keywords(values: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Cause> {
    let mut out = Vec::new();
    out.try_reserve_exact(values.len())
        .map_err(|_| Fault::Capacity)?;
    for value in values {
        out.push(copy_bytes(value)?);
    }
    Ok(out)
}
fn encode_keywords(values: &[Vec<u8>]) -> Result<Vec<u8>, Cause> {
    if values.len() > 256 {
        return Err(Fault::Capacity.into());
    }
    let size = values
        .iter()
        .try_fold(4usize, |n, v| n.checked_add(4)?.checked_add(v.len()))
        .ok_or(Fault::Overflow)?;
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value)
            || value.is_empty()
            || value.len() > 4096
            || value.contains(&0)
        {
            return Err(Fault::InvalidInput.into());
        }
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}
fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], Cause> {
    let out = bytes.get(..length).ok_or(Cause::Malformed)?;
    *bytes = &bytes[length..];
    Ok(out)
}
fn number(bytes: &mut &[u8]) -> Result<u32, Cause> {
    Ok(u32::from_be_bytes(
        take(bytes, 4)?.try_into().map_err(|_| Cause::Malformed)?,
    ))
}
fn decode_keywords(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, Cause> {
    let count = number(&mut bytes)? as usize;
    if count > 256 {
        return Err(Cause::Malformed);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| Fault::Capacity)?;
    for _ in 0..count {
        let n = number(&mut bytes)? as usize;
        if n == 0 || n > 4096 {
            return Err(Cause::Malformed);
        }
        let value = take(&mut bytes, n)?;
        if value.contains(&0) {
            return Err(Cause::Malformed);
        }
        if out.iter().any(|v: &Vec<u8>| v == value) {
            return Err(Cause::Malformed);
        }
        out.push(copy_bytes(value)?);
    }
    if !bytes.is_empty() {
        return Err(Cause::Malformed);
    }
    Ok(out)
}

/// One exclusively locked durable original unindex job; no background task.
pub struct Task {
    store: Store,
    manifest: Manifest,
    id: [u8; 32],
    state: State,
    active: Arc<AtomicBool>,
}
struct Active(Arc<AtomicBool>);
impl Active {
    fn finish(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.finish();
    }
}
impl Task {
    /// Create a new private task. It opens no MQ and performs no mutation.
    /// Literal labels and extraction settings are fixed here; automatic labels
    /// are fixed at the first fully hashed run before any destructive request.
    pub fn create(
        path: impl AsRef<Path>,
        filename: impl AsRef<Path>,
        extra_keywords: &[Vec<u8>],
        metadata: MetadataSettings,
        limits: Limits,
    ) -> Result<Self, Cause> {
        if limits.max_operations == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let filename = std::fs::canonicalize(filename)?;
        let file = crate::open_input(&filename).map_err(|e| match e {
            crate::Error::Io(e) => Cause::Io(e),
            _ => Cause::Protocol(Fault::InvalidInput),
        })?;
        if !file.metadata()?.is_file() {
            return Err(Fault::InvalidInput.into());
        }
        let raw = filename.as_os_str().as_bytes();
        if raw.len() > 4096 || raw.contains(&0) {
            return Err(Fault::InvalidInput.into());
        }
        let words = encode_keywords(extra_keywords)?;
        let metadata = metadata.snapshot()?;
        let metadata_length = u32::try_from(metadata.len()).map_err(|_| Fault::Capacity)?;
        let body_bytes = 52usize
            .checked_add(raw.len())
            .and_then(|n| n.checked_add(metadata.len()))
            .and_then(|n| n.checked_add(words.len()))
            .ok_or(Fault::Overflow)?;
        let mut store = Store::create(path, limits.storage)?;
        let id = *store.task_id();
        let mut body = Vec::new();
        body.try_reserve_exact(body_bytes)
            .map_err(|_| Fault::Capacity)?;
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&id);
        body.extend_from_slice(&limits.max_operations.to_be_bytes());
        body.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        body.extend_from_slice(raw);
        body.extend_from_slice(&metadata_length.to_be_bytes());
        body.extend_from_slice(&metadata);
        body.extend_from_slice(&words);
        store.append(MANIFEST, &body)?;
        Self::from_store(store, limits)
    }
    /// Reopen bounded history under the original physical exclusive writer lock.
    /// This validates records; it does not read/hash the source or open a socket.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, Cause> {
        Self::from_store(Store::open(path, limits.storage)?, limits)
    }
    pub(crate) fn open_registered(
        path: impl AsRef<Path>,
        storage: store::Limits,
        expected: crate::FileIdentity,
    ) -> Result<Self, Cause> {
        Self::from_store(
            Store::open_registered(path, storage, expected)?,
            Limits {
                storage,
                max_operations: u32::MAX,
            },
        )
    }
    pub(crate) fn directory_identity(&self) -> std::io::Result<crate::FileIdentity> {
        crate::FileIdentity::of(self.store.directory())
    }
    fn from_store(mut store: Store, limits: Limits) -> Result<Self, Cause> {
        let expected_id = *store.task_id();
        let first = store.read_record(0)?.ok_or(Cause::Malformed)?;
        if first.kind != MANIFEST {
            return Err(Cause::Malformed);
        }
        let mut bytes = first.bytes;
        if take(&mut bytes, 8)? != MAGIC {
            return Err(Cause::Malformed);
        }
        let id = take(&mut bytes, 32)?
            .try_into()
            .map_err(|_| Cause::Malformed)?;
        if id != expected_id {
            return Err(Cause::Malformed);
        }
        let max_operations = number(&mut bytes)?;
        if max_operations == 0 || max_operations > limits.max_operations {
            return Err(Fault::Capacity.into());
        }
        let length = number(&mut bytes)? as usize;
        if length == 0 || length > 4096 {
            return Err(Cause::Malformed);
        }
        let raw = take(&mut bytes, length)?;
        if raw.contains(&0) {
            return Err(Cause::Malformed);
        }
        let filename = PathBuf::from(std::ffi::OsString::from_vec(copy_bytes(raw)?));
        if !filename.is_absolute() {
            return Err(Cause::Malformed);
        }
        let metadata_length = number(&mut bytes)? as usize;
        let metadata = MetadataSettings::from_snapshot(take(&mut bytes, metadata_length)?)?;
        let extra_keywords = decode_keywords(bytes)?;
        let mut state = State::new();
        for index in 1..store.record_count() {
            let record = store.read_record(index)?.ok_or(Cause::Malformed)?;
            state.apply(record.kind, record.bytes, max_operations)?;
        }
        Ok(Self {
            store,
            manifest: Manifest {
                filename,
                extra_keywords,
                metadata,
                max_operations,
            },
            id,
            state,
            active: Arc::new(AtomicBool::new(false)),
        })
    }
    /// Original immutable task policy.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// Original random task identity, never a protocol/native operation token.
    pub const fn task_id(&self) -> &[u8; 32] {
        &self.id
    }
    /// Local recorded facts. Running without the exclusive run borrow is an
    /// interrupted attempt; neither this status nor old ACKs prove current absence.
    pub fn status(&self) -> Status {
        Status {
            phase: if self.state.phase == Phase::Running && !self.active.load(Ordering::Acquire) {
                Phase::Interrupted
            } else {
                self.state.phase
            },
            runs: self.state.runs,
            operations: self.state.operations,
            accepted: self.state.accepted.len(),
            pending: self.state.pending.map(Intent::original),
            abandoned_uncertain: self.state.abandoned,
            not_submitted: self.state.not_submitted,
            source_bound: self.state.source.is_some(),
            keywords_bound: self.state.keywords.is_some(),
            completed_keywords: self.state.completed_keywords.len(),
            fenced: self.store.failure().is_some(),
            active: self.active.load(Ordering::Acquire),
        }
    }
    fn append(&mut self, kind: u16, body: &[u8]) -> Result<(), Cause> {
        // Receipt map allocation must precede durable append, so a successful
        // record cannot be followed by an unrepresentable in-memory state.
        if kind == RECEIPT && body.get(133) == Some(&1) {
            self.state
                .accepted
                .try_reserve(1)
                .map_err(|_| Fault::Capacity)?;
        }
        if kind == KEYWORD_END
            || kind == RECEIPT && body.first() == Some(&3) && body.get(133) == Some(&1)
        {
            self.state
                .completed_keywords
                .try_reserve(1)
                .map_err(|_| Fault::Capacity)?;
        }
        let keywords = if kind == KEYWORDS {
            if self.state.phase != Phase::Running
                || self.state.source.is_none()
                || self.state.keywords.is_some()
            {
                return Err(Cause::Malformed);
            }
            Some(decode_keywords(body)?)
        } else {
            None
        };
        self.store.append(kind, body)?;
        if let Some(words) = keywords {
            self.state.keywords = Some(words);
            Ok(())
        } else {
            self.state.apply(kind, body, self.manifest.max_operations)
        }
    }
    /// Explicitly leave the unfinished original request Unknown, then permit a
    /// separately bounded new attempt. This never upgrades it to an ACK or
    /// automatically retries it. Callers must make this decision explicitly.
    pub fn restart_uncertain(&mut self) -> Result<Status, Cause> {
        if matches!(self.state.phase, Phase::Complete | Phase::Cancelled) {
            return Err(Cause::Terminal);
        }
        let op = self.state.pending.ok_or(Fault::NotReady)?;
        self.append(RESTART, &op.encode())?;
        Ok(self.status())
    }
    /// Permanently stop future work. Any unfinished old mutation stays visible;
    /// cancellation does not establish its outcome or remote deletion.
    pub fn cancel(&mut self) -> Result<Status, Cause> {
        if self.state.phase == Phase::Complete {
            return Err(Cause::Terminal);
        }
        if self.state.phase != Phase::Cancelled {
            self.append(CANCEL, &[])?;
        }
        Ok(self.status())
    }
    fn failure(&self, cause: Cause) -> Box<Failure> {
        self.active.store(false, Ordering::Release);
        Box::new(Failure {
            status: self.status(),
            native: None,
            completed: None,
            cause: Some(cause),
            secondary: None,
        })
    }
    /// Drive the same immediate native unindex owner with persisted intent and
    /// actual receipt barriers. Every run owns fresh finite absolute/native
    /// deadlines. Rehash precedes historical receipt reuse; no original unknown
    /// request is automatically replayed after interruption or transport loss.
    pub async fn run(
        &mut self,
        buffers: &mut Buffers,
        fs_source: EndpointSource,
        store: Client<'_, '_, '_>,
        deadline: AbsoluteTime,
        native_deadline: Instant,
        mut control: impl FnMut(Observation) -> Control,
    ) -> Result<Report, Box<Failure>> {
        if matches!(self.state.phase, Phase::Complete | Phase::Cancelled) {
            return Err(self.failure(Cause::Terminal));
        }
        if let Some(op) = self.state.pending {
            return Err(self.failure(Cause::Uncertain(op.original())));
        }
        self.active.store(true, Ordering::Release);
        let active = Active(self.active.clone());
        let run = match self.state.runs.checked_add(1) {
            Some(n) => n,
            None => return Err(self.failure(Fault::Overflow.into())),
        };
        if let Err(e) = self.append(BEGIN, &run.to_be_bytes()) {
            return Err(self.failure(e));
        }
        let filename = match copy_bytes(self.manifest.filename.as_os_str().as_bytes()) {
            Ok(bytes) => PathBuf::from(std::ffi::OsString::from_vec(bytes)),
            Err(e) => return Err(self.failure(e)),
        };
        let mut input = match crate::open_input(&filename) {
            Ok(file) => file,
            Err(e) => {
                let original = match e {
                    crate::Error::Io(e) => Cause::Io(e),
                    _ => Fault::InvalidInput.into(),
                };
                let result = self.append(END, &[3]);
                let mut failure = self.failure(original);
                failure.secondary = result.err();
                return Err(failure);
            }
        };
        let extras = match copy_keywords(&self.manifest.extra_keywords) {
            Ok(v) => v,
            Err(e) => return Err(self.failure(e)),
        };
        let mut refs = Vec::new();
        if refs.try_reserve_exact(extras.len()).is_err() {
            return Err(self.failure(Fault::Capacity.into()));
        }
        refs.extend(extras.iter().map(Vec::as_slice));
        let mut options = unindex::Options::new(deadline, native_deadline);
        options.extra_keywords = &refs;
        options.metadata = self.manifest.metadata.clone();
        let mut requested = Control::Continue;
        let (native, mut cause) = {
            let mut recorder = Journal {
                task: self,
                error: None,
            };
            let native = buffers
                .unindex_file_recorded(
                    &mut input,
                    &filename,
                    fs_source,
                    store,
                    options,
                    |observation| {
                        let next = control(observation);
                        if requested != Control::Cancel && next != Control::Continue {
                            requested = next;
                        }
                        if requested == Control::Continue {
                            NativeControl::Continue
                        } else {
                            NativeControl::Cancel
                        }
                    },
                    &mut recorder,
                )
                .await;
            (native, recorder.error.take())
        };
        active.finish();
        let safe_deadline = self.state.pending.is_none()
            && native.as_ref().err().is_some_and(|failure| {
                matches!(
                    &failure.operation,
                    Some(crate::network::Error::Deadline { .. })
                )
            });
        let end = match requested {
            Control::Cancel => 5,
            Control::Pause => 2,
            Control::Continue if native.is_ok() => 4,
            Control::Continue if safe_deadline => 2,
            Control::Continue => 3,
        };
        if cause.is_none() {
            cause = self.append(END, &[end]).err();
        }
        let status = self.status();
        match (native, cause) {
            (Ok(native), None) => Ok(Report { status, native }),
            (Ok(completed), cause) => Err(Box::new(Failure {
                status,
                native: None,
                completed: Some(completed),
                cause,
                secondary: None,
            })),
            (Err(native), cause) => Err(Box::new(Failure {
                status,
                native: Some(native),
                completed: None,
                cause,
                secondary: None,
            })),
        }
    }
}
struct Journal<'a> {
    task: &'a mut Task,
    error: Option<Cause>,
}
impl Journal<'_> {
    fn retain<T>(&mut self, result: Result<T, Cause>) -> Result<T, Fault> {
        result.map_err(|e| {
            if self.error.is_none() {
                self.error = Some(e);
            }
            Fault::Io
        })
    }
}
impl Recorder for Journal<'_> {
    fn source(&mut self, file_id: [u8; 64], bytes: u64) -> Result<(), Fault> {
        let result = match self.task.state.source {
            Some(original) if original != (file_id, bytes) => Err(Cause::SourceChanged),
            Some(_) => Ok(()),
            None => {
                let mut body = [0; 72];
                body[..64].copy_from_slice(&file_id);
                body[64..].copy_from_slice(&bytes.to_be_bytes());
                self.task.append(SOURCE, &body)
            }
        };
        self.retain(result)
    }
    fn retained_keywords(&mut self) -> Result<Option<Vec<Vec<u8>>>, Fault> {
        let result = self
            .task
            .state
            .keywords
            .as_ref()
            .map(|values| copy_keywords(values))
            .transpose();
        self.retain(result)
    }
    fn keywords(&mut self, words: &mut Vec<Vec<u8>>, complete: bool) -> Result<(), Fault> {
        let result = if let Some(original) = &self.task.state.keywords {
            if words == original {
                Ok(())
            } else {
                Err(Cause::Malformed)
            }
        } else if !complete {
            Err(Fault::NotReady.into())
        } else {
            encode_keywords(words).and_then(|body| self.task.append(KEYWORDS, &body))
        };
        self.retain(result)
    }
    fn keyword(&mut self, query: &[u8; 64]) -> Result<bool, Fault> {
        Ok(self.task.state.completed_keywords.contains(query))
    }
    fn keyword_end(&mut self, query: &[u8; 64]) -> Result<(), Fault> {
        let result = self.task.append(KEYWORD_END, query);
        self.retain(result)
    }
    fn before(&mut self, operation: Operation<'_>) -> Result<bool, Fault> {
        let op = Intent::of(operation);
        let result = if self.task.state.accepted.get(&op.digest) == Some(&op.kind) {
            Ok(true)
        } else if let Some(old) = self.task.state.pending {
            Err(Cause::Uncertain(old.original()))
        } else if self.task.state.operations >= self.task.manifest.max_operations {
            Err(Fault::Capacity.into())
        } else {
            self.task.append(INTENT, &op.encode()).map(|()| false)
        };
        self.retain(result)
    }
    fn not_submitted(&mut self, operation: Operation<'_>) -> Result<(), Fault> {
        let result = self
            .task
            .append(NOT_SUBMITTED, &Intent::of(operation).encode());
        self.retain(result)
    }
    fn received(
        &mut self,
        operation: Operation<'_>,
        code: i32,
        accepted: bool,
    ) -> Result<(), Fault> {
        let op = Intent::of(operation);
        let mut body = [0; 134];
        body[..129].copy_from_slice(&op.encode());
        body[129..133].copy_from_slice(&code.to_be_bytes());
        body[133] = u8::from(accepted);
        let result = self.task.append(RECEIPT, &body);
        self.retain(result)
    }
}
