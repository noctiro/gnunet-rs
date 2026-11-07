//! Durable source-bound native availability observations, not timeless reachability.
//! Private WAL history never constructs a new native `Observed`. Fresh runs own
//! original native retrieval; only its private completion can produce a receipt.
mod codec;
#[cfg(test)]
mod tests;
#[cfg(feature = "network")]
use crate::FileIdentity;
use crate::{
    Buffers, Control as NativeControl, Progress,
    durable::store::{self, Store},
    network::{self, probe},
    search::availability::Summary,
};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content, Uri,
    content::{BLOCK_BYTES, Layout, TAG_BYTES},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::{ffi::OsStr, fmt, fs::File, path::Path};

const MANIFEST: u16 = 0x5100;
const INTENT: u16 = 0x5101;
const OBSERVATION: u16 = 0x5102;
const ABANDON: u16 = 0x5103;
const CANCEL: u16 = 0x5104;

/// Explicit lifetime admission and original private WAL budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual record/body/file bounds used by the original store.
    pub storage: store::Limits,
    /// Maximum admitted attempts, including cancellation/interruption/setup errors.
    pub max_attempts: u32,
    /// Maximum authenticated successes plus written inconclusive deadlines.
    pub max_trials: u32,
    /// Maximum retained original terminal record bytes across this task.
    pub max_history_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            storage: store::Limits::default(),
            max_attempts: 32,
            max_trials: 8,
            max_history_bytes: 16 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Cause> {
        if self.max_attempts == 0
            || self.max_trials == 0
            || self.max_trials > i32::MAX as u32
            || self.max_history_bytes == 0
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        Ok(())
    }
}
/// Immutable original resolved target and ordinary native query policy.
#[derive(Clone, Debug)]
pub struct Manifest {
    /// Canonical resolved CHK or signature-verified LOC URI, with no final NUL.
    pub uri: Vec<u8>,
    /// Native options; the stored deadline is zero and each run supplies a fresh one.
    pub options: probe::Options,
    /// Optional opaque local search-context binding; not an external signature.
    pub origin: Option<[u8; 64]>,
    /// Original lifetime attempt budget.
    pub max_attempts: u32,
    /// Original completed observational trial budget.
    pub max_trials: u32,
    /// Original maximum retained terminal bytes.
    pub max_history_bytes: u64,
}
impl Manifest {
    /// Parse the original target, checking any LOC signature again.
    pub fn content(&self) -> Result<Content, Cause> {
        match Uri::parse(&self.uri, gnunet_fs::Limits::default())? {
            Uri::Content(c) => Ok(c),
            Uri::Location(l) => Ok(l.content()),
            _ => Err(ProtocolError::InvalidInput.into()),
        }
    }
    fn validate(&self) -> Result<(), Cause> {
        if self.uri.len() > 4096
            || self.max_attempts == 0
            || self.max_trials == 0
            || self.max_trials > i32::MAX as u32
            || self.max_history_bytes == 0
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let uri = Uri::parse(&self.uri, gnunet_fs::Limits::default())?;
        let (content, target) = match uri {
            Uri::Content(c) => (c, [0; 32]),
            Uri::Location(l) => (l.content(), *l.peer().as_bytes()),
            _ => return Err(ProtocolError::InvalidInput.into()),
        };
        let mut encoded = vec![0; uri.encoded_len()?];
        uri.encode(&mut encoded)?;
        let o = self.options;
        if encoded != self.uri
            || o.transfer.deadline != AbsoluteTime::from_micros(0)
            || o.transfer.target != target
            || o.transfer.queries_per_connection == 0
            || o.transfer.io_slice_bytes == 0
            || o.max_file_bytes < content.size
            || o.max_path_blocks == 0
            || o.max_path_blocks > 8
            || o.max_encoded_bytes == 0
            || o.max_encoded_bytes > 8 * (BLOCK_BYTES + TAG_BYTES) as u128
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        Ok(())
    }
}
/// Cooperative intent for the original probe owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Continue the original native retrieval.
    Continue,
    /// Stop this observation while keeping the task reusable.
    Pause,
    /// Stop this observation and permanently cancel future task runs.
    Cancel,
}
/// Historical task lifecycle, never proof of a live socket or current availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Original manifest exists and no attempt has been admitted.
    Ready,
    /// Original intent has no terminal observation; inspect `active` separately.
    Running,
    /// An observation settled and another bounded attempt may be admitted.
    Paused,
    /// Explicit local cancellation prohibits fresh runs.
    Cancelled,
    /// The original or caller admission budget has been reached.
    Exhausted,
}
/// One original intent coordinate. Diagnostic fields cannot mint a native receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attempt {
    /// One-based original task-local attempt number.
    pub ordinal: u32,
    /// Original durable intent sequence.
    pub intent_record: u64,
    /// Original canonical leaf ordinal, including a partial tail or empty leaf0.
    pub leaf: u64,
    /// Accepted source-clock sample before durable admission.
    pub admitted: AbsoluteTime,
    /// Original finite absolute run deadline.
    pub deadline: AbsoluteTime,
}
/// Actual observation classification. A written deadline is inconclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// Real root-authenticated native selected-range retrieval.
    Success = 0,
    /// Original deadline after at least one complete SEARCH was written.
    Inconclusive = 1,
    /// Deadline before a complete SEARCH was written.
    SetupDeadline = 2,
    /// Caller/native cancellation, excluded from trials.
    Cancelled = 3,
    /// Content/query/tag authentication refusal.
    Authentication = 4,
    /// Native protocol refusal.
    Protocol = 5,
    /// Source-clock uncertainty or regression.
    Clock = 6,
    /// Work, memory or arithmetic policy refusal.
    Resource = 7,
    /// Original OS/socket failure.
    Transport = 8,
    /// Invalid native configuration or operation setup.
    Setup = 9,
    /// Other original local adapter refusal.
    Local = 10,
    /// Other original native backend refusal.
    Other = 11,
}
/// Lightweight historical observation metadata. It is not a fresh native proof.
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    /// Original intent/leaf/deadline coordinate.
    pub attempt: Attempt,
    /// Original actual observation classification.
    pub kind: Kind,
    /// Actual authenticated prefix work; history is revalidated before new work.
    pub progress: Progress,
    /// Actual completed original SEARCH writes.
    pub queries_written: u64,
    /// Original native owner start, absent for setup refusal.
    pub started: Option<AbsoluteTime>,
    /// Original last accepted source sample; not an invented failure completion time.
    pub last_checked: Option<AbsoluteTime>,
    /// Whether that original native owner explicitly retired.
    pub retired: bool,
    /// Caller intent kept separate from native classification.
    pub wanted: Control,
}
/// Cheap original historical facts; no socket or transcript replay is started.
#[derive(Clone, Copy, Debug)]
pub struct Status {
    /// Historical lifecycle derived from original records and admission bounds.
    pub phase: Phase,
    /// Actual execution ownership of this Rust object.
    pub active: bool,
    /// Historical observational counts only; no new native receipt is implied.
    pub historical: Summary,
    /// Original intent awaiting exact settlement or explicit abandonment.
    pub pending: Option<Attempt>,
    /// Explicitly abandoned read-only observations, excluded from completed trials.
    pub interrupted: u32,
    /// Logical original terminal body bytes retained.
    pub history_bytes: u64,
    /// Complete checked WAL record count.
    pub state_records: usize,
    /// Original uncertain append prevents further writes on this owner.
    pub fenced: bool,
}
/// Original local refusal, keeping storage certainty and replay authentication.
#[derive(Debug)]
pub enum Cause {
    /// Original storage stage, certainty and actual native I/O cause.
    Storage(store::Error),
    /// Original checked scalar, bound, clock or source binding refusal.
    Protocol(ProtocolError),
    /// Original local buffer/filesystem failure.
    Local(crate::Error),
    /// Original pure historical transcript authentication refusal.
    Transcript(Box<network::Error>),
    /// Strict private record shape/sequence/state refusal.
    Format,
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Local(e) => e.fmt(f),
            Self::Transcript(e) => e.fmt(f),
            Self::Format => f.write_str("invalid probe task record"),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Local(e) => Some(e),
            Self::Transcript(e) => Some(e),
            Self::Format => None,
        }
    }
}
impl From<store::Error> for Cause {
    fn from(e: store::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<ProtocolError> for Cause {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<crate::Error> for Cause {
    fn from(e: crate::Error) -> Self {
        Self::Local(e)
    }
}

/// Local failure while independently retaining actual native observation/receipt.
#[derive(Debug)]
pub struct Failure {
    /// Original local setup, state, transcript or WAL refusal.
    pub cause: Cause,
    /// Genuine local settlement receipt, retained if its WAL write failed.
    pub receipt: Option<Receipt>,
    /// Original actual native result and path, never reconstructed from history.
    pub recorded: Option<probe::Recorded>,
    /// Actual current historical status when an owner had been loaded.
    pub status: Option<Status>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// Actual native observation whose original terminal record crossed the WAL barrier.
#[derive(Debug)]
pub struct Outcome {
    /// Private original local settlement authority; contains no native constructor.
    pub receipt: Receipt,
    /// Original native result/path, available independently to its Session owner.
    pub recorded: probe::Recorded,
    /// Actual task history after the terminal barrier.
    pub status: Status,
}
/// A non-constructible original task/intent-bound local settlement authority.
/// Recording never opens a connection and cannot create a native observation.
pub struct Receipt {
    task: [u8; 32],
    manifest: [u8; 64],
    attempt: Attempt,
    body: Vec<u8>,
    hash: [u8; 64],
    kind: Kind,
}
impl fmt::Debug for Receipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeReceipt")
            .field("attempt", &self.attempt)
            .field("kind", &self.kind)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
impl Receipt {
    /// Original local task intent bound to this actual observation.
    #[must_use]
    pub const fn attempt(&self) -> Attempt {
        self.attempt
    }
    /// Original actual native result classification.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Hash of the exact immutable terminal body, useful only for diagnostics.
    #[must_use]
    pub const fn body_hash(&self) -> [u8; 64] {
        self.hash
    }
    /// Record only the original task/intent; identical known settlement is
    /// idempotent. No fresh request, proof or availability claim is created.
    pub fn record(&self, task: &mut Task) -> Result<Status, Cause> {
        task.record(self)
    }
}
/// Independent local finish failure without ownership of caller's native result.
#[derive(Debug)]
pub(crate) struct FinishFailure {
    pub cause: Cause,
    pub receipt: Option<Receipt>,
}
#[derive(Debug)]
struct Slot {
    attempt: Attempt,
    observation: Option<Observation>,
    terminal_hash: Option<[u8; 64]>,
    record_index: Option<usize>,
    abandoned: bool,
}
struct TerminalApply {
    observation: Observation,
    summary: Summary,
    history_bytes: u64,
    last_now: Option<AbsoluteTime>,
    cancelled: bool,
    slot: usize,
}
struct State {
    slots: Vec<Slot>,
    pending: Option<Attempt>,
    historical: Summary,
    interrupted: u32,
    history_bytes: u64,
    cancelled: bool,
    last_now: Option<AbsoluteTime>,
}
impl State {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            pending: None,
            historical: Summary::default(),
            interrupted: 0,
            history_bytes: 0,
            cancelled: false,
            last_now: None,
        }
    }
    fn add_intent(
        &mut self,
        attempt: Attempt,
        manifest: &Manifest,
        limits: Limits,
    ) -> Result<(), Cause> {
        if self.cancelled
            || self.pending.is_some()
            || self.slots.len() >= manifest.max_attempts.min(limits.max_attempts) as usize
            || self.historical.trials >= manifest.max_trials.min(limits.max_trials)
            || attempt.ordinal as usize != self.slots.len() + 1
            || attempt.deadline <= attempt.admitted
            || attempt.deadline.as_micros() == u64::MAX
            || self.last_now.is_some_and(|last| attempt.admitted < last)
        {
            return Err(ProtocolError::Conflict.into());
        }
        Layout::new(manifest.content()?.size).leaf(attempt.leaf)?;
        self.slots
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        self.slots.push(Slot {
            attempt,
            observation: None,
            terminal_hash: None,
            record_index: None,
            abandoned: false,
        });
        self.pending = Some(attempt);
        self.historical.attempts = attempt.ordinal;
        self.last_now = Some(attempt.admitted);
        Ok(())
    }
    fn abandon(&mut self, attempt: Attempt) -> Result<(), Cause> {
        if self.pending != Some(attempt) {
            return Err(ProtocolError::StaleGeneration.into());
        }
        let slot = self
            .slots
            .get_mut(attempt.ordinal as usize - 1)
            .ok_or(Cause::Format)?;
        slot.abandoned = true;
        self.pending = None;
        self.interrupted = self
            .interrupted
            .checked_add(1)
            .ok_or(ProtocolError::Overflow)?;
        Ok(())
    }
    fn prepare_terminal(
        &self,
        t: &codec::Terminal,
        bytes: usize,
        manifest: &Manifest,
        limits: Limits,
    ) -> Result<TerminalApply, Cause> {
        if self.pending != Some(t.observation.attempt) {
            return Err(ProtocolError::StaleGeneration.into());
        }
        let history_bytes = self
            .history_bytes
            .checked_add(bytes as u64)
            .ok_or(ProtocolError::Overflow)?;
        if history_bytes > manifest.max_history_bytes.min(limits.max_history_bytes) {
            return Err(ProtocolError::Capacity.into());
        }
        let mut summary = self.historical;
        let observation = t.observation;
        let add = |value: &mut u32| -> Result<(), Cause> {
            *value = value.checked_add(1).ok_or(ProtocolError::Overflow)?;
            Ok(())
        };
        match observation.kind {
            Kind::Success => {
                add(&mut summary.successes)?;
                add(&mut summary.trials)?;
            }
            Kind::Inconclusive => add(&mut summary.trials)?,
            Kind::SetupDeadline => add(&mut summary.setup_deadlines)?,
            Kind::Cancelled => add(&mut summary.cancelled)?,
            kind => add(match kind {
                Kind::Authentication => &mut summary.errors.authentication,
                Kind::Protocol => &mut summary.errors.protocol,
                Kind::Clock => &mut summary.errors.clock,
                Kind::Resource => &mut summary.errors.resource,
                Kind::Transport => &mut summary.errors.transport,
                Kind::Setup => &mut summary.errors.setup,
                Kind::Local => &mut summary.errors.local,
                Kind::Other => &mut summary.errors.other,
                _ => return Err(Cause::Format),
            })?,
        }
        if t.transport_loss {
            add(&mut summary.errors.transport)?;
        }
        if summary.trials > manifest.max_trials.min(limits.max_trials)
            || summary.successes > summary.trials
        {
            return Err(ProtocolError::Capacity.into());
        }
        if let (Some(start), Some(end)) = (observation.started, observation.last_checked) {
            summary.source_elapsed = summary
                .source_elapsed
                .checked_add(end.duration_since(start)?)?;
        }
        summary.queries_written = summary
            .queries_written
            .checked_add(observation.queries_written)
            .ok_or(ProtocolError::Overflow)?;
        let slot = observation
            .attempt
            .ordinal
            .checked_sub(1)
            .ok_or(Cause::Format)? as usize;
        let original = self.slots.get(slot).ok_or(Cause::Format)?;
        if original.attempt != observation.attempt
            || original.observation.is_some()
            || original.abandoned
        {
            return Err(Cause::Format);
        }
        let last_now = observation.last_checked.map_or(self.last_now, |now| {
            Some(self.last_now.map_or(now, |last| last.max(now)))
        });
        Ok(TerminalApply {
            observation,
            summary,
            history_bytes,
            last_now,
            cancelled: self.cancelled || observation.wanted == Control::Cancel,
            slot,
        })
    }
    fn apply_terminal(&mut self, update: TerminalApply, index: usize, hash: [u8; 64]) {
        let slot = &mut self.slots[update.slot];
        slot.observation = Some(update.observation);
        slot.terminal_hash = Some(hash);
        slot.record_index = Some(index);
        self.pending = None;
        self.historical = update.summary;
        self.history_bytes = update.history_bytes;
        self.cancelled = update.cancelled;
        self.last_now = update.last_now;
    }
    fn terminal(
        &mut self,
        t: &codec::Terminal,
        index: usize,
        hash: [u8; 64],
        bytes: usize,
        manifest: &Manifest,
        limits: Limits,
    ) -> Result<(), Cause> {
        let update = self.prepare_terminal(t, bytes, manifest, limits)?;
        self.apply_terminal(update, index, hash);
        Ok(())
    }
}
/// Exclusive original task owner. Status/reopen are historical, not fresh probes.
pub struct Task {
    store: Store,
    manifest: Manifest,
    manifest_hash: [u8; 64],
    limits: Limits,
    state: State,
    active: bool,
}
impl Task {
    /// Create an explicitly chosen resolved target without any native I/O.
    pub fn create(
        path: impl AsRef<Path>,
        uri: Uri<'_>,
        options: probe::Options,
        limits: Limits,
    ) -> Result<Self, Box<Failure>> {
        Self::create_with(
            || Store::create(path, limits.storage),
            uri,
            options,
            limits,
            None,
        )
    }
    /// Create below an already anchored directory. `origin` is local context,
    /// never a signature or proof of current content availability.
    pub(crate) fn create_at(
        parent: &File,
        name: &OsStr,
        uri: Uri<'_>,
        options: probe::Options,
        limits: Limits,
        origin: Option<[u8; 64]>,
    ) -> Result<Self, Box<Failure>> {
        Self::create_with(
            || Store::create_at(parent, name, limits.storage),
            uri,
            options,
            limits,
            origin,
        )
    }
    fn create_with(
        make: impl FnOnce() -> Result<Store, store::Error>,
        uri: Uri<'_>,
        mut options: probe::Options,
        limits: Limits,
        origin: Option<[u8; 64]>,
    ) -> Result<Self, Box<Failure>> {
        let result = (|| -> Result<Self, Cause> {
            limits.validate()?;
            if !matches!(uri, Uri::Content(_) | Uri::Location(_)) {
                return Err(ProtocolError::InvalidInput.into());
            }
            let bytes = uri.encoded_len()?;
            if bytes > 4096 {
                return Err(ProtocolError::TooLarge.into());
            }
            let mut raw = Vec::new();
            raw.try_reserve_exact(bytes)
                .map_err(|_| ProtocolError::Capacity)?;
            raw.resize(bytes, 0);
            uri.encode(&mut raw)?;
            options.transfer.deadline = AbsoluteTime::from_micros(0);
            let manifest = Manifest {
                uri: raw,
                options,
                origin,
                max_attempts: limits.max_attempts,
                max_trials: limits.max_trials,
                max_history_bytes: limits.max_history_bytes,
            };
            manifest.validate()?;
            let body = codec::encode_manifest(&manifest)?;
            let hash = gnunet_crypto::hash512(&body);
            let mut store = make()?;
            store.append(MANIFEST, &body)?;
            Ok(Self {
                store,
                manifest,
                manifest_hash: hash,
                limits,
                state: State::new(),
                active: false,
            })
        })();
        result.map_err(|cause| {
            Box::new(Failure {
                cause,
                receipt: None,
                recorded: None,
                status: None,
            })
        })
    }
    /// Reopen original checked history; no fresh native observation is minted.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, Box<Failure>> {
        Self::open_with(|| Store::open(path, limits.storage), limits)
    }
    pub(crate) fn open_at(
        parent: &File,
        name: &OsStr,
        limits: Limits,
    ) -> Result<Self, Box<Failure>> {
        Self::open_with(|| Store::open_at(parent, name, limits.storage), limits)
    }
    #[cfg(feature = "network")]
    pub(crate) fn open_registered(
        path: impl AsRef<Path>,
        limits: Limits,
        expected: FileIdentity,
    ) -> Result<Self, Box<Failure>> {
        Self::open_with(
            || Store::open_registered(path, limits.storage, expected),
            limits,
        )
    }
    fn open_with(
        make: impl FnOnce() -> Result<Store, store::Error>,
        limits: Limits,
    ) -> Result<Self, Box<Failure>> {
        let result = (|| -> Result<Self, Cause> {
            limits.validate()?;
            let mut store = make()?;
            let first = store.read_record(0)?.ok_or(Cause::Format)?;
            if first.kind != MANIFEST {
                return Err(Cause::Format);
            }
            let manifest = codec::decode_manifest(first.bytes)?;
            manifest.validate()?;
            let hash = gnunet_crypto::hash512(first.bytes);
            let mut task = Self {
                store,
                manifest,
                manifest_hash: hash,
                limits,
                state: State::new(),
                active: false,
            };
            let count = task.store.record_count();
            let task_id = *task.store.task_id();
            let mut buffers = Buffers::new();
            for index in 1..count {
                let row = task.store.read_record(index)?.ok_or(Cause::Format)?;
                match row.kind {
                    INTENT => {
                        let attempt = codec::decode_attempt(row.bytes)?;
                        if attempt.intent_record != row.sequence {
                            return Err(Cause::Format);
                        }
                        task.state.add_intent(attempt, &task.manifest, limits)?;
                    }
                    OBSERVATION => {
                        let terminal = codec::decode_terminal(row.bytes)?;
                        validate_terminal(
                            &task.manifest,
                            (task_id, task.manifest_hash),
                            &terminal,
                            &mut buffers,
                        )?;
                        task.state.terminal(
                            &terminal,
                            index,
                            gnunet_crypto::hash512(row.bytes),
                            row.bytes.len(),
                            &task.manifest,
                            limits,
                        )?;
                    }
                    ABANDON => task.state.abandon(codec::decode_attempt(row.bytes)?)?,
                    CANCEL => {
                        if !row.bytes.is_empty()
                            || task.state.pending.is_some()
                            || task.state.cancelled
                        {
                            return Err(Cause::Format);
                        }
                        task.state.cancelled = true;
                    }
                    _ => return Err(Cause::Format),
                }
            }
            Ok(task)
        })();
        result.map_err(|cause| {
            Box::new(Failure {
                cause,
                receipt: None,
                recorded: None,
                status: None,
            })
        })
    }
    /// Immutable original target/context and policy.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// Original secure-random local task identity.
    #[must_use]
    pub fn task_id(&self) -> &[u8; 32] {
        self.store.task_id()
    }
    #[cfg(feature = "network")]
    pub(crate) fn directory_identity(&self) -> std::io::Result<FileIdentity> {
        FileIdentity::of(self.store.directory())
    }
    /// Actual lightweight original historical metadata in stable attempt order.
    pub fn observations(&self) -> impl Iterator<Item = &Observation> {
        self.state
            .slots
            .iter()
            .filter_map(|slot| slot.observation.as_ref())
    }
    /// Inspect original facts without a socket or fresh authentication claim.
    #[must_use]
    pub fn status(&self) -> Status {
        let phase = if self.state.cancelled {
            Phase::Cancelled
        } else if self.state.pending.is_some() {
            Phase::Running
        } else if self.state.historical.attempts
            >= self.manifest.max_attempts.min(self.limits.max_attempts)
            || self.state.historical.trials >= self.manifest.max_trials.min(self.limits.max_trials)
        {
            Phase::Exhausted
        } else if self.state.slots.is_empty() {
            Phase::Ready
        } else {
            Phase::Paused
        };
        Status {
            phase,
            active: self.active,
            historical: self.state.historical,
            pending: self.state.pending,
            interrupted: self.state.interrupted,
            history_bytes: self.state.history_bytes,
            state_records: self.store.record_count(),
            fenced: self.store.fenced(),
        }
    }
    /// Explicitly abandon an interrupted read-only observation. No completed
    /// trial, absence, native duration or socket-retirement fact is invented.
    pub fn abandon_interrupted(&mut self) -> Result<Status, Cause> {
        if self.active {
            return Err(ProtocolError::WouldBlock.into());
        }
        let attempt = self.state.pending.ok_or(ProtocolError::NotReady)?;
        let body = codec::encode_attempt(attempt)?;
        self.store.append(ABANDON, &body)?;
        self.state.abandon(attempt)?;
        Ok(self.status())
    }
    /// Permanently cancel local future scheduling. An unresolved read-only intent
    /// is explicitly abandoned first; already recorded observations stay intact.
    pub fn cancel(&mut self) -> Result<Status, Cause> {
        if self.active {
            return Err(ProtocolError::WouldBlock.into());
        }
        if self.state.cancelled {
            return Ok(self.status());
        }
        if self.state.pending.is_some() {
            self.abandon_interrupted()?;
        }
        self.store.append(CANCEL, &[])?;
        self.state.cancelled = true;
        Ok(self.status())
    }
    /// Read and reauthenticate original stored path prefixes. This starts no
    /// network work and does not create a new native observation.
    pub fn verify_history(&mut self, buffers: &mut Buffers) -> Result<(), Cause> {
        let task_id = *self.store.task_id();
        for slot in &self.state.slots {
            if let Some(index) = slot.record_index {
                let row = self.store.read_record(index)?.ok_or(Cause::Format)?;
                if Some(gnunet_crypto::hash512(row.bytes)) != slot.terminal_hash {
                    return Err(Cause::Format);
                }
                let terminal = codec::decode_terminal(row.bytes)?;
                validate_terminal(
                    &self.manifest,
                    (task_id, self.manifest_hash),
                    &terminal,
                    buffers,
                )?;
            }
        }
        Ok(())
    }
    pub(crate) fn begin_recorded(
        &mut self,
        source: &EndpointSource,
        leaf: u64,
        deadline: AbsoluteTime,
    ) -> Result<Attempt, Cause> {
        if self.active {
            return Err(ProtocolError::WouldBlock.into());
        }
        if self.state.cancelled {
            return Err(ProtocolError::Cancelled.into());
        }
        if self.state.pending.is_some() {
            return Err(ProtocolError::OutcomeUnknown.into());
        }
        if self.status().phase == Phase::Exhausted {
            return Err(ProtocolError::Capacity.into());
        }
        let now = source.clock().sample()?.now;
        self.begin_at(leaf, deadline, now)
    }
    fn begin_at(
        &mut self,
        leaf: u64,
        deadline: AbsoluteTime,
        now: AbsoluteTime,
    ) -> Result<Attempt, Cause> {
        if self.active
            || self.state.pending.is_some()
            || self.state.cancelled
            || self.status().phase == Phase::Exhausted
        {
            return Err(ProtocolError::Conflict.into());
        }
        if deadline.as_micros() == u64::MAX {
            return Err(ProtocolError::InvalidInput.into());
        }
        if self.state.last_now.is_some_and(|last| now < last) {
            return Err(ProtocolError::TimeUncertain.into());
        }
        if deadline <= now {
            return Err(ProtocolError::Deadline.into());
        }
        let mut node = Layout::new(self.manifest.content()?.size).leaf(leaf)?;
        let mut terminal_bound = 512usize
            + 4096
            + gnunet_wire::official::fs::CLIENT_PUT_PREFIX
            + BLOCK_BYTES
            + TAG_BYTES;
        loop {
            terminal_bound = terminal_bound
                .checked_add(
                    4 + gnunet_wire::official::fs::CLIENT_PUT_PREFIX
                        + node.plaintext_bytes()
                        + TAG_BYTES,
                )
                .ok_or(ProtocolError::Overflow)?;
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
        if self
            .state
            .history_bytes
            .checked_add(terminal_bound as u64)
            .is_none_or(|bytes| {
                bytes
                    > self
                        .manifest
                        .max_history_bytes
                        .min(self.limits.max_history_bytes)
            })
            || self
                .store
                .record_count()
                .checked_add(2)
                .is_none_or(|records| records > self.limits.storage.max_records)
        {
            return Err(ProtocolError::Capacity.into());
        }
        self.store.check_append(
            terminal_bound
                .checked_add(512)
                .ok_or(ProtocolError::Overflow)?,
        )?;
        let attempt = Attempt {
            ordinal: self
                .state
                .historical
                .attempts
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?,
            intent_record: u64::try_from(self.store.record_count())
                .map_err(|_| ProtocolError::Overflow)?
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?,
            leaf,
            admitted: now,
            deadline,
        };
        let body = codec::encode_attempt(attempt)?;
        self.state
            .slots
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        let sequence = self.store.append(INTENT, &body)?;
        if sequence != attempt.intent_record {
            return Err(Cause::Format);
        }
        self.state
            .add_intent(attempt, &self.manifest, self.limits)?;
        Ok(attempt)
    }
    pub(crate) fn finish_recorded(
        &mut self,
        attempt: Attempt,
        result: &Result<probe::Observed, probe::Failure>,
        frames: &[Vec<u8>],
        wanted: Control,
        buffers: &mut Buffers,
    ) -> Result<(Receipt, Status), Box<FinishFailure>> {
        let prepared = (|| -> Result<Receipt, Cause> {
            if self.state.pending != Some(attempt) {
                return Err(ProtocolError::StaleGeneration.into());
            }
            let terminal = codec::Terminal::native(
                &self.manifest,
                (*self.store.task_id(), self.manifest_hash),
                attempt,
                result,
                frames,
                wanted,
            )?;
            validate_terminal(
                &self.manifest,
                (*self.store.task_id(), self.manifest_hash),
                &terminal,
                buffers,
            )?;
            let body = codec::encode_terminal(&terminal)?;
            let hash = gnunet_crypto::hash512(&body);
            Ok(Receipt {
                task: *self.store.task_id(),
                manifest: self.manifest_hash,
                attempt,
                body,
                hash,
                kind: terminal.observation.kind,
            })
        })();
        let receipt = match prepared {
            Ok(receipt) => receipt,
            Err(cause) => {
                return Err(Box::new(FinishFailure {
                    cause,
                    receipt: None,
                }));
            }
        };
        match receipt.record(self) {
            Ok(status) => Ok((receipt, status)),
            Err(cause) => Err(Box::new(FinishFailure {
                cause,
                receipt: Some(receipt),
            })),
        }
    }
    /// Admit the original durable intent, perform one actual native recorded
    /// probe and settle its exact terminal bytes. Native errors remain in
    /// `recorded.result()`; this Result distinguishes local ledger refusal.
    pub async fn run(
        &mut self,
        source: EndpointSource,
        buffers: &mut Buffers,
        leaf: u64,
        deadline: AbsoluteTime,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        let setup = self.begin_recorded(&source, leaf, deadline);
        let attempt = match setup {
            Ok(attempt) => attempt,
            Err(cause) => {
                return Err(Box::new(Failure {
                    cause,
                    receipt: None,
                    recorded: None,
                    status: Some(self.status()),
                }));
            }
        };
        let mut options = self.manifest.options;
        options.transfer.deadline = deadline;
        let content = self.manifest.content().map_err(|cause| {
            Box::new(Failure {
                cause,
                receipt: None,
                recorded: None,
                status: Some(self.status()),
            })
        })?;
        self.active = true;
        let active = Active(&mut self.active);
        let mut wanted = Control::Continue;
        let recorded = buffers
            .probe_recorded(source, content, leaf, options, |progress| {
                if wanted == Control::Continue {
                    wanted = control(progress);
                }
                if wanted == Control::Continue {
                    NativeControl::Continue
                } else {
                    NativeControl::Cancel
                }
            })
            .await;
        drop(active);
        match self.finish_recorded(
            attempt,
            recorded.result(),
            recorded.frames(),
            wanted,
            buffers,
        ) {
            Ok((receipt, status)) => Ok(Outcome {
                receipt,
                recorded,
                status,
            }),
            Err(error) => Err(Box::new(Failure {
                cause: error.cause,
                receipt: error.receipt,
                recorded: Some(recorded),
                status: Some(self.status()),
            })),
        }
    }
    fn record(&mut self, receipt: &Receipt) -> Result<Status, Cause> {
        if self.active {
            return Err(ProtocolError::WouldBlock.into());
        }
        if receipt.task != *self.store.task_id() || receipt.manifest != self.manifest_hash {
            return Err(ProtocolError::StaleGeneration.into());
        }
        let slot = self
            .state
            .slots
            .get(receipt.attempt.ordinal as usize - 1)
            .ok_or(ProtocolError::StaleGeneration)?;
        if slot.attempt != receipt.attempt {
            return Err(ProtocolError::StaleGeneration.into());
        }
        if let Some(hash) = slot.terminal_hash {
            return if hash == receipt.hash {
                Ok(self.status())
            } else {
                Err(ProtocolError::Conflict.into())
            };
        }
        if self.state.pending != Some(receipt.attempt) || slot.abandoned {
            return Err(ProtocolError::StaleGeneration.into());
        }
        let terminal = codec::decode_terminal(&receipt.body)?;
        let next_bytes = self
            .state
            .history_bytes
            .checked_add(receipt.body.len() as u64)
            .ok_or(ProtocolError::Overflow)?;
        if next_bytes
            > self
                .manifest
                .max_history_bytes
                .min(self.limits.max_history_bytes)
        {
            return Err(ProtocolError::Capacity.into());
        }
        let update = self.state.prepare_terminal(
            &terminal,
            receipt.body.len(),
            &self.manifest,
            self.limits,
        )?;
        let index = self.store.record_count();
        self.store.append(OBSERVATION, &receipt.body)?;
        self.state.apply_terminal(update, index, receipt.hash);
        Ok(self.status())
    }
}
struct Active<'a>(&'a mut bool);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        *self.0 = false;
    }
}
fn validate_terminal(
    manifest: &Manifest,
    scope: ([u8; 32], [u8; 64]),
    terminal: &codec::Terminal,
    buffers: &mut Buffers,
) -> Result<(), Cause> {
    if terminal.task != scope.0 || terminal.manifest != scope.1 {
        return Err(ProtocolError::Conflict.into());
    }
    let o = terminal.observation;
    let a = o.attempt;
    let content = manifest.content()?;
    if o.started.is_some() != o.last_checked.is_some()
        || o.started.is_some_and(|start| start < a.admitted)
        || o.started.is_some_and(|_| !o.retired)
        || o.started.is_none() && (o.queries_written != 0 || o.progress.blocks != 0 || o.retired)
    {
        return Err(Cause::Format);
    }
    if let (Some(start), Some(end)) = (o.started, o.last_checked) {
        end.duration_since(start)?;
    }
    let (progress, proof) = probe::revalidate_prefix(content, a.leaf, &terminal.frames, buffers)
        .map_err(|e| Cause::Transcript(Box::new(e)))?;
    if progress != o.progress
        || progress.blocks > manifest.options.max_path_blocks
        || progress.encoded_bytes > manifest.options.max_encoded_bytes
        || progress.plaintext_bytes > {
            let range = Layout::new(content.size).leaf(a.leaf)?.range();
            range.end - range.start
        }
        || terminal.frames.len() > 8
        || terminal.last_response.len()
            > gnunet_wire::official::fs::CLIENT_PUT_PREFIX + BLOCK_BYTES + TAG_BYTES
        || terminal.diagnostic.len() > 4096
        || o.queries_written < o.progress.blocks
        || terminal.transport_loss && !matches!(o.kind, Kind::Inconclusive | Kind::SetupDeadline)
    {
        return Err(Cause::Format);
    }
    match o.kind {
        Kind::Success => {
            if proof.is_none()
                || o.queries_written == 0
                || !o.retired
                || o.last_checked.is_none_or(|end| end >= a.deadline)
                || !terminal.diagnostic.is_empty()
                || !terminal.last_response.is_empty()
            {
                return Err(Cause::Format);
            }
        }
        Kind::Inconclusive if o.queries_written == 0 => return Err(Cause::Format),
        Kind::SetupDeadline if o.queries_written != 0 => return Err(Cause::Format),
        _ => {}
    }
    Ok(())
}
