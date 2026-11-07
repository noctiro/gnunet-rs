//! Bounded recursive work ownership over source-authenticated directory entries.
//! No I/O, namespace authentication, MIME inference or filesystem output occurs here.
use super::{RangeRef, VerifiedDirectory, VerifiedEntry};
use crate::{Content, Uri, content::VerifiedFile};
use core::ptr;
use gnunet_crypto::EddsaPublicKey;

/// Nonzero-sized identity storage borrowed for the entire walk and its handles.
#[derive(Debug, Default)]
pub struct Instance {
    _marker: u8,
}
impl Instance {
    /// Make a fresh walk identity without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { _marker: 0 }
    }
}
/// Original task identity; retained slots are never recycled within a walk.
#[derive(Clone, Copy, Debug)]
pub struct TaskId<'a> {
    instance: &'a Instance,
    index: usize,
}
impl PartialEq for TaskId<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.instance, other.instance) && self.index == other.index
    }
}
impl Eq for TaskId<'_> {}
/// One admitted attempt. Retrying never reuses its generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptId<'a> {
    task: TaskId<'a>,
    generation: u64,
}
impl<'a> AttemptId<'a> {
    /// Original task whose host operation this attempt owns.
    #[must_use]
    pub const fn task(self) -> TaskId<'a> {
        self.task
    }
}
/// Explicit caller classification; a MIME claim does not select this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Read and authenticate the file; do not interpret it as a directory.
    File,
    /// Read, strictly parse and schedule every directory entry.
    Directory,
}
/// Treatment of the same Content and Kind through distinct entry paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedPolicy {
    /// Reuse one retained task; completion still waits for that actual task.
    Reuse,
    /// Schedule each entry path separately, charging its bytes again.
    VisitAgain,
}
/// Treatment of a directory referring to an ancestor directory Content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CyclePolicy {
    /// Refuse this entry without consuming it or changing the parent cursor.
    Reject,
    /// Record the cycle explicitly and avoid unbounded recursive descent.
    Skip,
}
/// Resource bounds; slots additionally retain the root and every accepted entry.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Root is depth0; this bounds both file and directory child depths.
    pub max_depth: usize,
    /// Unique parent-entry records admitted, excluding the root.
    pub max_entries: usize,
    /// Root plus each scheduled resolved task size; reused/cycle edges cost zero.
    pub max_total_bytes: u128,
    /// Queued, resolving, reading and cancelling tasks combined.
    pub max_queued: usize,
    /// Same content through distinct paths.
    pub shared: SharedPolicy,
    /// Ancestor directory cycles.
    pub cycles: CyclePolicy,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_entries: 4096,
            max_total_bytes: 1024 * 1024 * 1024,
            max_queued: 256,
            shared: SharedPolicy::Reuse,
            cycles: CyclePolicy::Reject,
        }
    }
}
/// Typed refusal. A refused entry/resolution does not consume its original task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Caller task-history or namespace-identifier storage is insufficient.
    Capacity,
    /// Recursion depth exceeded.
    Depth,
    /// Total unique parent entries exceeded.
    Entries,
    /// Scheduled content bytes exceeded.
    Bytes,
    /// Too many nonterminal tasks.
    Queue,
    /// An original task/attempt belongs elsewhere or is no longer active.
    Stale,
    /// Entry or completion belongs to another parent/target Content.
    Source,
    /// A prior parent range was overlapped or observations were out of order.
    Order,
    /// Classification differs from the original admitted intent.
    Kind,
    /// An ancestor directory cycle was refused by policy.
    Cycle,
    /// A directory receipt does not cover every entry observed by this attempt.
    Incomplete,
    /// This task still requires explicit namespace resolution.
    Unresolved,
    /// Cancellation blocks fresh effects; admitted attempts still need draining.
    Cancelled,
    /// Checked counter representation failed.
    Overflow,
    /// The original entry URI could not be parsed.
    Uri(super::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "directory walk {self:?}")
    }
}
impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug)]
enum Target {
    Content(Content),
    Namespace {
        key: EddsaPublicKey,
        start: usize,
        end: usize,
    },
}
/// Observable task disposition. Quiescent and completed are separate facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// Ready for an original host read or namespace resolution attempt.
    Queued,
    /// Host owns an admitted attempt.
    Active,
    /// Cancellation requested; original host attempt is still owned.
    Cancelling,
    /// Known file/directory receipt accepted.
    Done,
    /// This edge shares another original task's result.
    Shared,
    /// Explicit ancestor-cycle policy decision.
    CycleSkipped,
    /// Intent cancelled after no admitted host operation remains.
    Cancelled,
}
#[derive(Clone, Copy, Debug)]
struct Origin {
    parent: usize,
    range: RangeRef,
}
/// Caller-owned task/history slot. Its fields cannot manufacture a live task.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    origin: Option<Origin>,
    target: Target,
    kind: Kind,
    depth: usize,
    state: State,
    shared: usize,
    generation: u64,
    observed: usize,
    observed_end: u64,
}
impl Slot {
    /// Initialize caller storage. Only the prefix used by a Walk is meaningful;
    /// unused slots and unused identifier bytes are not cleared by the owner.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            origin: None,
            target: Target::Content(Content {
                key: [0; 64],
                query: [0; 64],
                size: 0,
            }),
            kind: Kind::File,
            depth: 0,
            state: State::Cancelled,
            shared: 0,
            generation: 0,
            observed: 0,
            observed_end: 0,
        }
    }
}
impl Default for Slot {
    fn default() -> Self {
        Self::empty()
    }
}
/// Exact work requested from the host. Namespace identifiers remain in the arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    /// Read this CHK's actual blocks with FileReader.
    Content(Content),
    /// Resolve this key and namespace_identifier(attempt), then return a Content.
    Namespace(EddsaPublicKey),
}
/// One original host attempt, without a spawned worker or hidden retry.
#[derive(Clone, Copy, Debug)]
pub struct Work<'a> {
    /// Correlate every result/retry/cancel acknowledgement to this exact attempt.
    pub id: AttemptId<'a>,
    /// Explicit interpretation of eventual authenticated content.
    pub kind: Kind,
    /// Root-relative depth.
    pub depth: usize,
    /// Actual content read or unresolved namespace request.
    pub request: Request,
}
/// Entry/resolution disposition, including decisions that start no new I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission<'a> {
    /// New or resolved Content is ready for a fresh read attempt.
    Queued(TaskId<'a>),
    /// A namespace remains queued for a distinct resolution attempt.
    Namespace(TaskId<'a>),
    /// Retained edge depends on the other task's real outcome.
    Shared {
        /// Retained entry edge requesting this shared result.
        task: TaskId<'a>,
        /// Original task whose actual completion satisfies the edge.
        with: TaskId<'a>,
    },
    /// Explicitly recorded cycle; no recursive host task was admitted.
    CycleSkipped(TaskId<'a>),
    /// Original parent entry was already admitted, including after parent retry.
    Replay(TaskId<'a>),
}
/// Terminal disposition of one actual original host attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// A verified receipt was recorded.
    Done,
    /// Original attempt ended; same task awaits a new generation.
    Retrying,
    /// Original attempt ended under cancellation, without a success claim.
    Cancelled,
}
/// Policy-complete accounting, without availability, path or durable-output credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    /// Root plus every retained entry edge, including shared/cycle decisions.
    pub tasks: usize,
    /// Number of distinct admitted parent-entry records.
    pub entries: usize,
    /// Sum of actually scheduled Content sizes.
    pub content_bytes: u128,
    /// Actual file/directory jobs with accepted verified receipts.
    pub done: usize,
    /// Shared edges, whose original job must also finish.
    pub shared: usize,
    /// Explicit ancestor cycles avoided by policy.
    pub skipped_cycles: usize,
    /// Cancelled intents, never counted as successful jobs.
    pub cancelled: usize,
}

/// Caller-driven bounded recursive scheduler. Slots and namespace bytes remain
/// retained for this walk, so retries and shared paths cannot relabel history.
pub struct Walk<'a> {
    instance: &'a Instance,
    slots: &'a mut [Slot],
    names: &'a mut [u8],
    used: usize,
    names_used: usize,
    queued: usize,
    ready: usize,
    bytes: u128,
    next_start: usize,
    limits: Limits,
    cancelled: bool,
}
impl<'a> Walk<'a> {
    /// Admit the root after all limits are checked; refusal changes no slots.
    pub fn new(
        instance: &'a mut Instance,
        slots: &'a mut [Slot],
        names: &'a mut [u8],
        root: Content,
        kind: Kind,
        limits: Limits,
    ) -> Result<Self, Error> {
        if slots.is_empty() {
            return Err(Error::Capacity);
        }
        if limits.max_queued == 0 {
            return Err(Error::Queue);
        }
        if u128::from(root.size) > limits.max_total_bytes {
            return Err(Error::Bytes);
        }
        slots[0] = Slot {
            target: Target::Content(root),
            kind,
            state: State::Queued,
            ..Slot::empty()
        };
        Ok(Self {
            instance,
            slots,
            names,
            used: 1,
            names_used: 0,
            queued: 1,
            ready: 1,
            bytes: u128::from(root.size),
            next_start: 0,
            limits,
            cancelled: false,
        })
    }
    fn id(&self, index: usize) -> TaskId<'a> {
        TaskId {
            instance: self.instance,
            index,
        }
    }
    fn index(&self, id: TaskId<'_>) -> Result<usize, Error> {
        if !ptr::eq(id.instance, self.instance) || id.index >= self.used {
            return Err(Error::Stale);
        }
        Ok(id.index)
    }
    fn attempt(&self, id: AttemptId<'_>) -> Result<usize, Error> {
        let index = self.index(id.task)?;
        let slot = self.slots[index];
        if slot.generation != id.generation
            || !matches!(slot.state, State::Active | State::Cancelling)
        {
            return Err(Error::Stale);
        }
        Ok(index)
    }
    /// Original root task, available before any I/O.
    #[must_use]
    pub fn root(&self) -> TaskId<'a> {
        self.id(0)
    }
    /// Current disposition of this exact retained task.
    pub fn state(&self, id: TaskId<'_>) -> Result<State, Error> {
        Ok(self.slots[self.index(id)?].state)
    }
    /// Checked position in this walk's retained task storage. Native owners can
    /// index their parallel path metadata without searching or forging handles.
    pub fn ordinal(&self, id: TaskId<'_>) -> Result<usize, Error> {
        self.index(id)
    }
    /// Original parent task and authenticated entry coordinates; root has none.
    pub fn origin(&self, id: TaskId<'_>) -> Result<Option<(TaskId<'a>, RangeRef)>, Error> {
        Ok(self.slots[self.index(id)?]
            .origin
            .map(|o| (self.id(o.parent), o.range)))
    }
    /// Grow retained task/name storage without invalidating task or attempt ids.
    /// Both capacities are preflighted; refusal changes neither caller buffer.
    pub fn replace_storage(
        &mut self,
        slots: &'a mut [Slot],
        names: &'a mut [u8],
    ) -> Result<(&'a mut [Slot], &'a mut [u8]), Error> {
        if slots.len() < self.used || names.len() < self.names_used {
            return Err(Error::Capacity);
        }
        slots[..self.used].copy_from_slice(&self.slots[..self.used]);
        names[..self.names_used].copy_from_slice(&self.names[..self.names_used]);
        Ok((
            core::mem::replace(&mut self.slots, slots),
            core::mem::replace(&mut self.names, names),
        ))
    }
    /// Admit at most one task using round-robin queued order. A failed original
    /// must be explicitly retried; a namespace is a request, never a fake file.
    pub fn begin(&mut self) -> Result<Option<Work<'a>>, Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if self.ready == 0 {
            return Ok(None);
        }
        let Some(index) = (self.next_start..self.used)
            .chain(0..self.next_start)
            .find(|&i| self.slots[i].state == State::Queued)
        else {
            return Ok(None);
        };
        let generation = self.slots[index]
            .generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let slot = &mut self.slots[index];
        slot.generation = generation;
        slot.state = State::Active;
        slot.observed = 0;
        slot.observed_end = 0;
        let (kind, depth, request) = (
            slot.kind,
            slot.depth,
            match slot.target {
                Target::Content(c) => Request::Content(c),
                Target::Namespace { key, .. } => Request::Namespace(key),
            },
        );
        self.next_start = index + 1;
        self.ready -= 1;
        Ok(Some(Work {
            id: AttemptId {
                task: self.id(index),
                generation,
            },
            kind,
            depth,
            request,
        }))
    }
    /// Exact namespace bytes retained before the source parser reuses its carry.
    pub fn namespace_identifier(&self, id: AttemptId<'_>) -> Result<&[u8], Error> {
        let index = self.attempt(id)?;
        match self.slots[index].target {
            Target::Namespace { start, end, .. } => Ok(&self.names[start..end]),
            Target::Content(_) => Err(Error::Kind),
        }
    }
    fn decision(
        &self,
        parent: Option<usize>,
        content: Content,
        kind: Kind,
        exclude: Option<usize>,
    ) -> Result<(State, Option<usize>, u128), Error> {
        if kind == Kind::Directory {
            let mut next = parent;
            while let Some(index) = next {
                let slot = self.slots[index];
                if slot.kind == Kind::Directory
                    && matches!(slot.target, Target::Content(c) if c == content)
                {
                    return match self.limits.cycles {
                        CyclePolicy::Reject => Err(Error::Cycle),
                        CyclePolicy::Skip => Ok((State::CycleSkipped, None, 0)),
                    };
                }
                next = slot.origin.map(|o| o.parent);
            }
        }
        if self.limits.shared == SharedPolicy::Reuse
            && let Some(index) = (0..self.used).find(|&i| {
                Some(i) != exclude
                    && self.slots[i].kind == kind
                    && matches!(
                        self.slots[i].state,
                        State::Queued | State::Active | State::Done
                    )
                    && matches!(self.slots[i].target, Target::Content(c) if c == content)
            })
        {
            return Ok((State::Shared, Some(index), 0));
        }
        let bytes = self
            .bytes
            .checked_add(u128::from(content.size))
            .ok_or(Error::Overflow)?;
        if bytes > self.limits.max_total_bytes {
            return Err(Error::Bytes);
        }
        Ok((State::Queued, None, u128::from(content.size)))
    }
    fn admission(&self, index: usize) -> Admission<'a> {
        let task = self.id(index);
        match self.slots[index].state {
            State::Shared => Admission::Shared {
                task,
                with: self.id(self.slots[index].shared),
            },
            State::CycleSkipped => Admission::CycleSkipped(task),
            _ if matches!(self.slots[index].target, Target::Namespace { .. }) => {
                Admission::Namespace(task)
            }
            _ => Admission::Queued(task),
        }
    }
    /// Schedule only a real VerifiedEntry from this currently active directory.
    /// Resource refusal leaves both parent observation progress and task storage
    /// unchanged, so the same lending entry can be retried after host progress.
    pub fn admit(
        &mut self,
        parent: AttemptId<'_>,
        verified: VerifiedEntry<'_>,
        kind: Kind,
    ) -> Result<Admission<'a>, Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        let parent_index = self.attempt(parent)?;
        let parent_slot = self.slots[parent_index];
        if parent_slot.kind != Kind::Directory {
            return Err(Error::Kind);
        }
        let Target::Content(source) = parent_slot.target else {
            return Err(Error::Unresolved);
        };
        if verified.source() != source {
            return Err(Error::Source);
        }
        let entry = verified.entry();
        let range = entry.range;
        let existing = (1..self.used).find(|&i| {
            self.slots[i]
                .origin
                .is_some_and(|o| o.parent == parent_index && o.range == range)
        });
        if let Some(index) = existing {
            if self.slots[index].kind != kind {
                return Err(Error::Kind);
            }
            if range.end <= parent_slot.observed_end {
                return Ok(Admission::Replay(self.id(index)));
            }
        }
        if range.start < parent_slot.observed_end || range.end <= range.start {
            return Err(Error::Order);
        }
        let observed = parent_slot.observed.checked_add(1).ok_or(Error::Overflow)?;
        if let Some(index) = existing {
            self.slots[parent_index].observed = observed;
            self.slots[parent_index].observed_end = range.end;
            return Ok(Admission::Replay(self.id(index)));
        }
        if self.used > self.limits.max_entries {
            return Err(Error::Entries);
        }
        if self.used == self.slots.len() {
            return Err(Error::Capacity);
        }
        let depth = parent_slot.depth.checked_add(1).ok_or(Error::Overflow)?;
        if depth > self.limits.max_depth {
            return Err(Error::Depth);
        }
        let uri = entry.uri().map_err(Error::Uri)?;
        let (target, state, shared, charge, name) = match uri {
            Uri::Content(content) => {
                let (state, shared, charge) =
                    self.decision(Some(parent_index), content, kind, None)?;
                (Target::Content(content), state, shared, charge, None)
            }
            Uri::Location(location) => {
                let content = location.content();
                let (state, shared, charge) =
                    self.decision(Some(parent_index), content, kind, None)?;
                (Target::Content(content), state, shared, charge, None)
            }
            Uri::Namespace(namespace) => {
                let bytes = namespace.identifier();
                let end = self
                    .names_used
                    .checked_add(bytes.len())
                    .ok_or(Error::Overflow)?;
                if end > self.names.len() {
                    return Err(Error::Capacity);
                }
                (
                    Target::Namespace {
                        key: namespace.key(),
                        start: self.names_used,
                        end,
                    },
                    State::Queued,
                    None,
                    0,
                    Some(bytes),
                )
            }
            Uri::Keywords(_) => return Err(Error::Kind),
        };
        if state == State::Queued && self.queued >= self.limits.max_queued {
            return Err(Error::Queue);
        }
        let index = self.used;
        if let Some(bytes) = name {
            self.names[self.names_used..self.names_used + bytes.len()].copy_from_slice(bytes);
            self.names_used += bytes.len();
        }
        self.slots[index] = Slot {
            origin: Some(Origin {
                parent: parent_index,
                range,
            }),
            target,
            kind,
            depth,
            state,
            shared: shared.unwrap_or(0),
            ..Slot::empty()
        };
        self.used += 1;
        self.bytes += charge;
        self.queued += usize::from(state == State::Queued);
        self.ready += usize::from(state == State::Queued);
        self.slots[parent_index].observed = observed;
        self.slots[parent_index].observed_end = range.end;
        Ok(self.admission(index))
    }
    /// Return an original namespace-resolution result. The caller's namespace
    /// owner authenticates its binding; this scheduler makes no namespace claim.
    /// Refusal keeps that same unresolved active attempt for correction/retry.
    pub fn resolve_namespace(
        &mut self,
        id: AttemptId<'_>,
        content: Content,
    ) -> Result<Admission<'a>, Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        let index = self.attempt(id)?;
        let slot = self.slots[index];
        if !matches!(slot.target, Target::Namespace { .. }) {
            return Err(Error::Kind);
        }
        let (state, shared, charge) = self.decision(
            slot.origin.map(|o| o.parent),
            content,
            slot.kind,
            Some(index),
        )?;
        self.slots[index].target = Target::Content(content);
        self.slots[index].state = state;
        self.slots[index].shared = shared.unwrap_or(0);
        self.bytes += charge;
        if state != State::Queued {
            self.queued -= 1;
        } else {
            self.ready += 1;
        }
        Ok(self.admission(index))
    }
    fn settle(&mut self, index: usize) -> Disposition {
        let cancelled = self.slots[index].state == State::Cancelling;
        self.slots[index].state = if cancelled {
            State::Cancelled
        } else {
            State::Done
        };
        self.queued -= 1;
        if cancelled {
            Disposition::Cancelled
        } else {
            Disposition::Done
        }
    }
    /// Accept only an actual complete FileReader receipt for the original file.
    pub fn finish_file(
        &mut self,
        id: AttemptId<'_>,
        file: VerifiedFile,
    ) -> Result<Disposition, Error> {
        let index = self.attempt(id)?;
        if self.slots[index].kind != Kind::File {
            return Err(Error::Kind);
        }
        if !matches!(self.slots[index].target, Target::Content(c) if c == file.content()) {
            return Err(Error::Source);
        }
        Ok(self.settle(index))
    }
    /// Strict directory completion must match this original Content and every
    /// entry observed in the current attempt. No omitted entry becomes success.
    pub fn finish_directory(
        &mut self,
        id: AttemptId<'_>,
        directory: VerifiedDirectory,
    ) -> Result<Disposition, Error> {
        let index = self.attempt(id)?;
        if self.slots[index].kind != Kind::Directory {
            return Err(Error::Kind);
        }
        if !matches!(self.slots[index].target, Target::Content(c) if c == directory.content()) {
            return Err(Error::Source);
        }
        if self.slots[index].state != State::Cancelling
            && self.slots[index].observed != directory.entries()
        {
            return Err(Error::Incomplete);
        }
        Ok(self.settle(index))
    }
    /// The host reports that the original failed/deferred operation is terminal.
    /// A fresh generation is required on begin; cancellation cannot revive work.
    pub fn retry(&mut self, id: AttemptId<'_>) -> Result<Disposition, Error> {
        let index = self.attempt(id)?;
        if self.slots[index].state == State::Cancelling {
            return Ok(self.settle(index));
        }
        self.slots[index].state = State::Queued;
        self.ready += 1;
        Ok(Disposition::Retrying)
    }
    /// Cancel queued intent immediately, retaining admitted originals until the
    /// host drains them and calls cancelled or returns their actual receipt.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        for slot in &mut self.slots[..self.used] {
            match slot.state {
                State::Queued => {
                    slot.state = State::Cancelled;
                    self.queued -= 1;
                    self.ready -= 1;
                }
                State::Active => slot.state = State::Cancelling,
                _ => {}
            }
        }
    }
    /// Acknowledge physical termination of this exact original cancelled attempt.
    pub fn cancelled(&mut self, id: AttemptId<'_>) -> Result<Disposition, Error> {
        let index = self.attempt(id)?;
        if self.slots[index].state != State::Cancelling {
            return Err(Error::Stale);
        }
        Ok(self.settle(index))
    }
    /// True only when no admitted original is active. Queued work can still exist.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        !self.slots[..self.used]
            .iter()
            .any(|s| matches!(s.state, State::Active | State::Cancelling))
    }
    /// Current policy accounting, independently of completion or cancellation.
    #[must_use]
    pub fn summary(&self) -> Summary {
        let count = |state| {
            self.slots[..self.used]
                .iter()
                .filter(|s| s.state == state)
                .count()
        };
        Summary {
            tasks: self.used,
            entries: self.used - 1,
            content_bytes: self.bytes,
            done: count(State::Done),
            shared: count(State::Shared),
            skipped_cycles: count(State::CycleSkipped),
            cancelled: count(State::Cancelled),
        }
    }
    /// Policy traversal is complete only after every original has a verified
    /// receipt and every shared dependency finished. Cancellation is never success.
    #[must_use]
    pub fn completion(&self) -> Option<Summary> {
        if self.cancelled || self.queued != 0 {
            return None;
        }
        let ready = self.slots[..self.used].iter().all(|slot| match slot.state {
            State::Done | State::CycleSkipped => true,
            State::Shared => self.slots[slot.shared].state == State::Done,
            _ => false,
        });
        ready.then(|| self.summary())
    }
}
