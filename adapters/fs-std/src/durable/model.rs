//! Typed replay of bounded durable download facts. This is not source authentication.
use super::{codec, store::Store};
use crate::{
    network::tree_download::{TreeDownloadOptions, paths::root_id},
    output::{CommitStage, FileIdentity},
};
use gnunet_fs::{Content, Location, Uri, directory::walk::Kind};
use std::ops::Range;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

/// Strict typed replay refusal, independent of native output/storage certainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// Private event version/type is unsupported.
    Version,
    /// Truncated, trailing, invalid-boolean or malformed field bytes.
    Format,
    /// A numeric, allocation, byte, task or depth bound was exceeded.
    Limit,
    /// WAL sequence/index is not the expected contiguous original prefix.
    Order,
    /// Original entry/parent/path/content or inode facts differ.
    Binding,
    /// The event does not follow the retained original state.
    Transition,
    /// Official URI parser or LOC signature verification refused.
    Protocol(gnunet_types::Error),
}
impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS durable task model: {self:?}")
    }
}
impl std::error::Error for ModelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
impl From<gnunet_types::Error> for ModelError {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
/// Explicit interpretation of the original root. A CHK alone carries no file
/// type, so a failed directory parse must never select the file path implicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootMode {
    /// Authenticate and recursively materialize an official directory.
    Directory,
    /// Retrieve this original absolute interval into a regular file. Bytes
    /// outside the interval are sparse placeholders, without authentication.
    File {
        /// Original absolute interval, within the original Content size.
        selection: Range<u64>,
    },
}
impl RootMode {
    pub(super) fn kind(&self) -> Kind {
        match self {
            Self::Directory => Kind::Directory,
            Self::File { .. } => Kind::File,
        }
    }
}
/// Immutable persisted download inputs; run deadline is deliberately omitted by codec.
#[derive(Clone, Debug)]
pub struct Manifest {
    /// Exact original CHK/LOC URI; LOC is reparsed and signature-verified.
    pub root_uri: Vec<u8>,
    /// Exact native path beneath the caller's selected output parent.
    pub relative: PathBuf,
    /// Caller-selected root interpretation and, for files, exact original range.
    pub mode: RootMode,
    /// Complete numeric policy; decoded transfer.deadline is zero.
    pub options: TreeDownloadOptions,
}
impl Manifest {
    /// Reparse original official content identity under persisted URI limits.
    pub fn root_content(&self) -> Result<Content, ModelError> {
        match Uri::parse(&self.root_uri, self.options.directory.uri)? {
            Uri::Content(c) => Ok(c),
            Uri::Location(loc) => Ok(loc.content()),
            _ => Err(ModelError::Format),
        }
    }
    /// Check immutable inputs without creating paths or runtime sources.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.root_uri.len() > codec::MAX_URI_BYTES {
            return Err(ModelError::Limit);
        }
        validate_path(&self.relative, false)?;
        if matches!(self.mode, RootMode::File { .. }) {
            validate_name(self.relative.as_os_str().as_bytes())?;
            if self.relative.file_name() == Some(std::ffi::OsStr::new(crate::OWNER_MARKER_NAME)) {
                return Err(ModelError::Binding);
            }
        }
        let o = self.options;
        if o.transfer.io_slice_bytes == 0
            || o.transfer.queries_per_connection == 0
            || (matches!(self.mode, RootMode::Directory)
                && (o.namespace.queries == 0
                    || o.namespace.queries > 64
                    || o.namespace.results == 0
                    || o.max_entries.checked_add(1).is_none()))
        {
            return Err(ModelError::Limit);
        }
        let root = self.root_content()?;
        if let Uri::Location(location) = Uri::parse(&self.root_uri, self.options.directory.uri)?
            && o.transfer.target != *location.peer().as_bytes()
        {
            return Err(ModelError::Binding);
        }
        if root.size > o.transfer.limits.max_file_bytes
            || (matches!(self.mode, RootMode::Directory) && root.size > o.directory.max_extent)
            || (matches!(self.mode, RootMode::Directory)
                && u128::from(root.size) > o.max_total_bytes)
        {
            return Err(ModelError::Limit);
        }
        if let RootMode::File { selection } = &self.mode
            && (selection.start > selection.end || selection.end > root.size)
        {
            return Err(ModelError::Binding);
        }
        Ok(())
    }
}
/// Historical task phase; a loaded Running phase is not evidence of live I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Manifest exists; no runtime is implied.
    Ready,
    /// A caller explicitly began a run.
    Running,
    /// Stop fresh effects and settle original operations.
    PauseRequested,
    /// Original operations settled with no outstanding temporary cleanup.
    Paused,
    /// Caller cancellation request is durable; original operations must settle.
    CancelRequested,
    /// Caller cancelled intent after original cleanup/commit reconciliation.
    Cancelled,
    /// Complete verified output and task barriers were recorded.
    Complete,
    /// Original run failed; retained facts remain available for reconciliation.
    Failed,
}
/// Stable authenticated-driver coordinates, never a serialized Walk ordinal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryBinding {
    /// Driver hash of actual parent source/range/raw URI and safe path membership.
    pub id: [u8; 64],
    /// Original parent entry; only the root has none.
    pub parent: Option<[u8; 64]>,
    /// Exact root-relative native path; root is empty.
    pub path: PathBuf,
    /// Caller classification from the authenticated directory entry.
    pub kind: Kind,
    /// Fixed selected content, including namespace resolution's immutable choice.
    pub content: Content,
}
/// Original exclusive temporary; keep this after successful cleanup for provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TempFact {
    /// Exact selected parent-directory inode.
    pub parent: FileIdentity,
    /// Exact exclusive temporary inode.
    pub identity: FileIdentity,
    /// Exact single-component native temporary name.
    pub name: OsString,
}
/// Only an index into the original Store: no duplicate large proof body is owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionRef {
    /// Zero-based original NamespaceSelected WAL record.
    pub record_index: usize,
    /// Immutable selected complete content identity.
    pub selected: Content,
    /// Immutable original signed LOC placement, when present.
    pub location: Option<Location>,
}
/// Retained facts for one stable path, not a newly minted verification receipt.
#[derive(Clone, Debug)]
pub struct EntryState {
    /// Exact original driver binding, checked again on real parent reparse.
    pub binding: EntryBinding,
    /// Directory creation was authorized before any mkdir effect.
    pub directory_intent: bool,
    /// Actual directory identity after original naming barriers.
    pub created: Option<FileIdentity>,
    /// Original complete authenticated directory receipt was observed.
    pub verified: bool,
    /// Original file temporary identity/name, retained even after cleanup.
    pub temporary: Option<TempFact>,
    /// Exact pre-link commit intent was durably recorded.
    pub intent: bool,
    /// Known durable final file identity; never cleared by ResetPending.
    pub committed: Option<FileIdentity>,
    /// The original exact temporary cleanup succeeded.
    pub cleanup: bool,
    /// A cleanup failure was actually observed, independent of commit stage.
    pub cleanup_failed: bool,
    /// Actual original final-name disposition, independent of cleanup.
    pub stage: CommitStage,
    /// Immutable namespace decision's original WAL index.
    pub selection: Option<SelectionRef>,
}
impl EntryState {
    fn new(binding: EntryBinding) -> Self {
        Self {
            binding,
            directory_intent: false,
            created: None,
            verified: false,
            temporary: None,
            intent: false,
            committed: None,
            cleanup: false,
            cleanup_failed: false,
            stage: CommitStage::NotLinked,
            selection: None,
        }
    }
}
/// Small owned event fields and a borrowed proof span. Encoding copies proof once
/// into the WAL body; replay never retains another proof allocation in State.
#[derive(Clone, Debug)]
pub enum Event<'a> {
    /// Must be the first and sole immutable manifest.
    Manifest(Manifest),
    /// Task-owned root identity after naming/owner-marker barriers.
    RootAttached(FileIdentity),
    /// Actual file destination parent and its task-owned marked staging root.
    FileAttached {
        /// Actual destination parent held independently of its pathname.
        parent: FileIdentity,
        /// Original task-owned marked staging directory.
        staging: FileIdentity,
    },
    /// A fresh child-directory effect is about to begin.
    DirectoryIntent(EntryBinding),
    /// Actual directory naming barriers completed.
    DirectoryCreated {
        /// Original stable driver entry identifier.
        id: [u8; 64],
        /// Actual originally observed inode.
        identity: FileIdentity,
    },
    /// Actual strict full-parent directory receipt completed.
    DirectoryVerified {
        /// Original stable driver entry identifier.
        id: [u8; 64],
    },
    /// Original exclusive temporary was created before content output.
    TempOwned {
        /// Exact original source/path/content binding.
        binding: EntryBinding,
        /// Original exclusive temporary and physical parent.
        temporary: TempFact,
    },
    /// Original authenticated temporary is about to be linked.
    CommitIntent {
        /// Original stable driver entry identifier.
        id: [u8; 64],
    },
    /// Actual original no-clobber link and durability barriers completed.
    FileCommitted {
        /// Original stable driver entry identifier.
        id: [u8; 64],
        /// Actual originally observed inode.
        identity: FileIdentity,
    },
    /// Independent exact temporary cleanup disposition and actual commit stage.
    Cleanup {
        /// Original stable driver entry identifier.
        id: [u8; 64],
        /// Whether the exact original cleanup actually succeeded.
        success: bool,
        /// Actual output disposition, independent of cleanup success.
        stage: CommitStage,
    },
    /// Caller proved final+temp absence or exact temporary cleanup before retry.
    ResetPending {
        /// Original stable driver entry identifier.
        id: [u8; 64],
    },
    /// Root validates proof against actual original SKS before effects/reuse.
    NamespaceSelected {
        /// Exact original source/path/content binding.
        binding: Box<EntryBinding>,
        /// Immutable selected content identity.
        selected: Content,
        /// Exact original signed placement, when selected.
        location: Option<Location>,
        /// Borrowed complete namespace proof; State keeps only its record index.
        proof: &'a [u8],
    },
    /// Typed historical lifecycle state, not a string-parsed error.
    Phase(Phase),
}
/// Original immutable inputs and bounded historical entry facts.
#[derive(Debug)]
pub struct State {
    /// Persisted immutable tree inputs.
    pub manifest: Manifest,
    /// Actual task-owned output root identity, if attachment completed.
    pub root: Option<FileIdentity>,
    /// Actual destination parent paired with a file task's marked staging root.
    pub file_parent: Option<FileIdentity>,
    /// Historical lifecycle phase; runtime status maps crashed Running separately.
    pub phase: Phase,
    /// Every recorded stable entry, including the root.
    pub entries: BTreeMap<[u8; 64], EntryState>,
    applied: u64,
    root_id: [u8; 64],
    path_bytes: usize,
    scheduled_bytes: u128,
    path_index: BTreeMap<[u8; 64], [u8; 64]>,
}
impl State {
    /// Read exactly the checked Store prefix one record at a time. No endpoint,
    /// path effect or proof authentication occurs here; source membership must
    /// be reparsed, and original storage failures remain distinct from model errors.
    pub fn load(store: &mut Store) -> Result<Self, super::Cause> {
        let first = store.read_record(0)?.ok_or(ModelError::Format)?;
        if first.sequence != 1 {
            return Err(ModelError::Order.into());
        }
        let Event::Manifest(manifest) = codec::decode_event(first.kind, first.bytes)? else {
            return Err(ModelError::Format.into());
        };
        let content = manifest.root_content()?;
        let binding = EntryBinding {
            id: root_id(content),
            parent: None,
            path: if matches!(manifest.mode, RootMode::Directory) {
                PathBuf::new()
            } else {
                manifest.relative.clone()
            },
            kind: manifest.mode.kind(),
            content,
        };
        let mut entries = BTreeMap::new();
        let mut path_index = BTreeMap::new();
        path_index.insert(
            gnunet_crypto::hash512(binding.path.as_os_str().as_bytes()),
            binding.id,
        );
        entries.insert(binding.id, EntryState::new(binding));
        let mut state = Self {
            manifest,
            root: None,
            file_parent: None,
            phase: Phase::Ready,
            entries,
            applied: 1,
            root_id: root_id(content),
            path_bytes: 0,
            scheduled_bytes: u128::from(content.size),
            path_index,
        };
        for index in 1..store.record_count() {
            let record = store.read_record(index)?.ok_or(ModelError::Order)?;
            state.apply(record.sequence, index, record.kind, record.bytes)?;
        }
        Ok(state)
    }
    /// Number of exact original accepted records, including the manifest.
    #[must_use]
    pub const fn applied(&self) -> u64 {
        self.applied
    }
    /// Bind current real-driver work to a retained entry. Unknown entries return
    /// None only after parent/path/resource checks; changed fields always refuse.
    pub fn entry(&self, binding: &EntryBinding) -> Result<Option<&EntryState>, ModelError> {
        self.check_binding(binding)?;
        Ok(self.entries.get(&binding.id))
    }
    /// Pure preflight BEFORE append, so an illegal transition cannot poison WAL.
    pub fn check(&self, event: &Event<'_>) -> Result<(), ModelError> {
        match event {
            Event::Manifest(_) => return Err(ModelError::Transition),
            Event::RootAttached(identity) => {
                let root = self.get(&self.root_id)?;
                if !matches!(self.manifest.mode, RootMode::Directory)
                    || root.binding.parent.is_some()
                    || root.binding.kind != Kind::Directory
                {
                    return Err(ModelError::Binding);
                }
                if self.root.is_some_and(|known| known != *identity) {
                    return Err(ModelError::Binding);
                }
            }
            Event::FileAttached { parent, staging } => {
                if !matches!(self.manifest.mode, RootMode::File { .. })
                    || self.root.is_some_and(|known| known != *staging)
                    || self.file_parent.is_some_and(|known| known != *parent)
                {
                    return Err(ModelError::Binding);
                }
            }
            Event::DirectoryIntent(b) => {
                self.fresh_effect()?;
                self.check_binding(b)?;
                if b.kind != Kind::Directory || b.parent.is_none() {
                    return Err(ModelError::Transition);
                }
            }
            Event::DirectoryCreated { id, identity } => {
                let e = self.get(id)?;
                if e.binding.kind != Kind::Directory
                    || !e.directory_intent
                    || e.created.is_some_and(|known| known != *identity)
                {
                    return Err(ModelError::Transition);
                }
            }
            Event::DirectoryVerified { id } => {
                let e = self.get(id)?;
                if e.binding.kind != Kind::Directory || e.created.is_none() {
                    return Err(ModelError::Transition);
                }
            }
            Event::TempOwned { binding, temporary } => {
                self.fresh_effect()?;
                self.check_binding(binding)?;
                if binding.kind != Kind::File {
                    return Err(ModelError::Transition);
                }
                validate_name(temporary.name.as_bytes())?;
                let parent = if binding.parent.is_none() {
                    self.root
                } else {
                    binding
                        .parent
                        .and_then(|id| self.entries.get(&id))
                        .and_then(|e| e.created)
                };
                if parent != Some(temporary.parent) {
                    return Err(ModelError::Binding);
                }
                if let Some(e) = self.entries.get(&binding.id)
                    && (e.committed.is_some() || e.intent || (e.temporary.is_some() && !e.cleanup))
                {
                    return Err(ModelError::Transition);
                }
            }
            Event::CommitIntent { id } => {
                self.fresh_effect()?;
                let e = self.file(id)?;
                if e.temporary.is_none() || e.cleanup || e.committed.is_some() {
                    return Err(ModelError::Transition);
                }
            }
            Event::FileCommitted { id, identity } => {
                let e = self.file(id)?;
                if !e.intent
                    || e.temporary.as_ref().is_none_or(|t| t.identity != *identity)
                    || e.committed.is_some_and(|known| known != *identity)
                {
                    return Err(ModelError::Transition);
                }
            }
            Event::Cleanup { id, success, stage } => {
                let e = self.file(id)?;
                if e.temporary.is_none()
                    || (e.cleanup && !*success)
                    || stage_rank(*stage) < stage_rank(e.stage)
                    || (*stage != CommitStage::NotLinked && !e.intent)
                    || (*stage == CommitStage::Durable && e.committed.is_none())
                {
                    return Err(ModelError::Transition);
                }
            }
            Event::ResetPending { id } => {
                let e = self.file(id)?;
                if e.committed.is_some() || e.temporary.is_none() {
                    return Err(ModelError::Transition);
                }
            }
            Event::NamespaceSelected {
                binding,
                selected,
                location,
                proof,
            } => {
                self.fresh_effect()?;
                self.check_binding(binding)?;
                if binding.parent.is_none()
                    || binding.content != *selected
                    || location.is_some_and(|l| l.content() != *selected)
                    || proof.is_empty()
                    || proof.len() > codec::MAX_EVENT_BYTES
                    || self.entries.get(&binding.id).is_some_and(|e| {
                        e.selection.is_some() || e.directory_intent || e.temporary.is_some()
                    })
                {
                    return Err(ModelError::Binding);
                }
            }
            Event::Phase(phase) => match phase {
                Phase::Ready if self.phase != Phase::Ready => return Err(ModelError::Transition),
                Phase::Running
                    if matches!(self.phase, Phase::Cancelled | Phase::CancelRequested) =>
                {
                    return Err(ModelError::Transition);
                }
                Phase::PauseRequested
                    if !matches!(self.phase, Phase::Running | Phase::PauseRequested) =>
                {
                    return Err(ModelError::Transition);
                }
                Phase::CancelRequested if self.phase == Phase::Cancelled => {
                    return Err(ModelError::Transition);
                }
                Phase::Paused if self.phase != Phase::PauseRequested || self.unsettled_files() => {
                    return Err(ModelError::Transition);
                }
                Phase::Cancelled
                    if self.phase != Phase::CancelRequested || self.unsettled_files() =>
                {
                    return Err(ModelError::Transition);
                }
                Phase::Complete
                    if self.phase != Phase::Running
                        || self.root.is_none()
                        || self.entries.values().any(|e| match e.binding.kind {
                            Kind::Directory => e.created.is_none() || !e.verified,
                            Kind::File => {
                                e.committed.is_none()
                                    || !e.cleanup
                                    || e.stage != CommitStage::Durable
                            }
                        }) =>
                {
                    return Err(ModelError::Transition);
                }
                _ => {}
            },
        }
        Ok(())
    }
    /// Replay one original next record atomically after complete decode/check.
    /// Caller serializes append+apply under the same original writer mutex.
    pub fn apply(
        &mut self,
        sequence: u64,
        index: usize,
        kind: u16,
        bytes: &[u8],
    ) -> Result<(), ModelError> {
        if self.applied.checked_add(1) != Some(sequence)
            || u64::try_from(index).ok() != Some(self.applied)
        {
            return Err(ModelError::Order);
        }
        let event = codec::decode_event(kind, bytes)?;
        self.check(&event)?;
        match event {
            Event::Manifest(_) => return Err(ModelError::Transition),
            Event::RootAttached(identity) => {
                let e = self
                    .entries
                    .get_mut(&self.root_id)
                    .ok_or(ModelError::Binding)?;
                if e.binding.kind == Kind::Directory {
                    e.directory_intent = true;
                    e.created = Some(identity);
                }
                self.root = Some(identity);
            }
            Event::FileAttached { parent, staging } => {
                self.file_parent = Some(parent);
                self.root = Some(staging);
            }
            Event::DirectoryIntent(binding) => {
                self.admit(binding)?.directory_intent = true;
            }
            Event::DirectoryCreated { id, identity } => {
                self.get_mut(&id)?.created = Some(identity);
            }
            Event::DirectoryVerified { id } => {
                self.get_mut(&id)?.verified = true;
            }
            Event::TempOwned { binding, temporary } => {
                let e = self.admit(binding)?;
                e.temporary = Some(temporary);
                e.cleanup = false;
                e.cleanup_failed = false;
                e.stage = CommitStage::NotLinked;
            }
            Event::CommitIntent { id } => {
                self.get_mut(&id)?.intent = true;
            }
            Event::FileCommitted { id, identity } => {
                let e = self.get_mut(&id)?;
                e.committed = Some(identity);
                e.stage = CommitStage::Durable;
            }
            Event::Cleanup { id, success, stage } => {
                let e = self.get_mut(&id)?;
                e.cleanup = success;
                e.cleanup_failed = !success;
                e.stage = stage;
            }
            Event::ResetPending { id } => {
                let e = self.get_mut(&id)?;
                e.temporary = None;
                e.intent = false;
                e.cleanup = false;
                e.cleanup_failed = false;
                e.stage = CommitStage::NotLinked;
            }
            Event::NamespaceSelected {
                binding,
                selected,
                location,
                proof: _,
            } => {
                self.admit(*binding)?.selection = Some(SelectionRef {
                    record_index: index,
                    selected,
                    location,
                });
            }
            Event::Phase(phase) => {
                self.phase = phase;
            }
        }
        self.applied = sequence;
        Ok(())
    }
    fn unsettled_files(&self) -> bool {
        self.entries
            .values()
            .any(|e| (e.temporary.is_some() && !e.cleanup) || (e.intent && e.committed.is_none()))
    }
    fn fresh_effect(&self) -> Result<(), ModelError> {
        if self.phase != Phase::Running {
            return Err(ModelError::Transition);
        }
        Ok(())
    }
    fn get(&self, id: &[u8; 64]) -> Result<&EntryState, ModelError> {
        self.entries.get(id).ok_or(ModelError::Binding)
    }
    fn get_mut(&mut self, id: &[u8; 64]) -> Result<&mut EntryState, ModelError> {
        self.entries.get_mut(id).ok_or(ModelError::Binding)
    }
    fn file(&self, id: &[u8; 64]) -> Result<&EntryState, ModelError> {
        let e = self.get(id)?;
        if e.binding.kind != Kind::File {
            return Err(ModelError::Transition);
        }
        Ok(e)
    }
    fn check_binding(&self, b: &EntryBinding) -> Result<(), ModelError> {
        validate_path(&b.path, b.parent.is_none())?;
        if let Some(e) = self.entries.get(&b.id) {
            if e.binding != *b {
                return Err(ModelError::Binding);
            }
            return Ok(());
        }
        let p = b
            .parent
            .and_then(|id| self.entries.get(&id))
            .ok_or(ModelError::Binding)?;
        if p.binding.kind != Kind::Directory
            || !p.verified
            || p.created.is_none()
            || b.path.parent() != Some(p.binding.path.as_path())
        {
            return Err(ModelError::Binding);
        }
        if self.entries.len() > self.manifest.options.max_entries
            || b.path.components().count() > self.manifest.options.max_depth
            || b.content.size > self.manifest.options.transfer.limits.max_file_bytes
            || (b.kind == Kind::Directory
                && b.content.size > self.manifest.options.directory.max_extent)
            || self
                .scheduled_bytes
                .checked_add(u128::from(b.content.size))
                .is_none_or(|n| n > self.manifest.options.max_total_bytes)
            || self
                .path_bytes
                .checked_add(b.path.as_os_str().as_bytes().len())
                .is_none_or(|n| n > self.manifest.options.max_path_bytes)
        {
            return Err(ModelError::Limit);
        }
        if self
            .path_index
            .contains_key(&gnunet_crypto::hash512(b.path.as_os_str().as_bytes()))
        {
            return Err(ModelError::Binding);
        }
        Ok(())
    }
    fn admit(&mut self, b: EntryBinding) -> Result<&mut EntryState, ModelError> {
        let id = b.id;
        if !self.entries.contains_key(&id) {
            self.path_bytes += b.path.as_os_str().as_bytes().len();
            self.scheduled_bytes += u128::from(b.content.size);
            self.path_index
                .insert(gnunet_crypto::hash512(b.path.as_os_str().as_bytes()), id);
            self.entries.insert(id, EntryState::new(b));
        }
        self.get_mut(&id)
    }
}
fn stage_rank(stage: CommitStage) -> u8 {
    match stage {
        CommitStage::NotLinked => 0,
        CommitStage::LinkedUnknown => 1,
        CommitStage::Durable => 2,
    }
}
pub(super) fn validate_name(bytes: &[u8]) -> Result<(), ModelError> {
    if bytes.is_empty()
        || bytes.len() > 4096
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|b| matches!(b, 0 | b'/' | b'\\'))
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Err(ModelError::Format);
    }
    Ok(())
}
pub(super) fn validate_path(path: &Path, empty: bool) -> Result<(), ModelError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        return if empty {
            Ok(())
        } else {
            Err(ModelError::Format)
        };
    }
    if bytes.len() > 4096 {
        return Err(ModelError::Limit);
    }
    let mut count = 0;
    for part in bytes.split(|b| *b == b'/') {
        validate_name(part)?;
        count += 1;
        if count > 128 {
            return Err(ModelError::Limit);
        }
    }
    Ok(())
}
