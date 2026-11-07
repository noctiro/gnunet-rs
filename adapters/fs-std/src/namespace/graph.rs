//! Bounded local update graph for acknowledged namespace publications.
//! This private index is not a wire extension or a claim of remote availability.
mod codec;
mod components;
#[cfg(test)]
mod task_origin_tests;
#[cfg(test)]
mod tests;
use crate::durable::store::{self, Store};
use codec::Index;
use gnunet_fs::{Uri, metadata};
use gnunet_fs_codec::Inflate;
use std::{collections::HashMap, fmt, mem::size_of, path::Path};
const MANIFEST: u16 = 0x3301;
const ACCEPTED: u16 = 0x3302;
const MAGIC: &[u8; 8] = b"GNFSUIG2";

/// Caller policy for the retained local graph, independently of WAL limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum acknowledged publication records, including duplicate labels/URIs.
    pub max_records: usize,
    /// Maximum distinct source and update labels, including empty labels.
    pub max_labels: usize,
    /// Maximum bytes in each literal identifier or update, excluding a terminator.
    pub max_label_bytes: usize,
    /// Maximum complete canonical target URI bytes.
    pub max_uri_bytes: usize,
    /// Maximum one encoded record body or prepared publication candidate.
    pub max_record_bytes: usize,
    /// Logical row/index metadata and owned unique-label buffer capacities.
    /// Store framing/index capacity and reusable validation scratch are separate.
    pub max_retained_bytes: usize,
    /// Actual URI parser limits; LOC signatures are checked on prepare and reopen.
    pub uri: gnunet_fs::Limits,
    /// Strict official metadata envelope and inflation limits.
    pub metadata: metadata::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 65_536,
            max_labels: 65_536,
            max_label_bytes: 8192,
            max_uri_bytes: 16_384,
            max_record_bytes: 8 * 1024 * 1024,
            max_retained_bytes: 32 * 1024 * 1024,
            uri: gnunet_fs::Limits::default(),
            metadata: metadata::Limits::default(),
        }
    }
}
/// Typed graph refusal. Storage errors retain original stage/certainty and cause.
#[derive(Clone, Debug)]
pub enum Error {
    /// Original locked WAL or native filesystem failure.
    Storage(store::Error),
    /// Official URI encoding/parsing or checked representation refusal.
    Protocol(gnunet_types::Error),
    /// Official strict metadata or complete-member zlib refusal.
    Metadata(metadata::Error),
    /// Unsupported private graph format version.
    Version,
    /// Malformed/trailing private fields or a forbidden interior NUL.
    Format,
    /// Explicit retained-memory, record, label or byte policy refused.
    Limit,
    /// Namespace, original store identity, label identity or prepared prefix differs.
    Binding,
    /// Accepted WAL prefix and original prepared record order differ.
    Order,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Metadata(e) => e.fmt(f),
            other => write!(f, "FS namespace graph: {other:?}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Metadata(e) => Some(e),
            _ => None,
        }
    }
}
impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<metadata::Error> for Error {
    fn from(e: metadata::Error) -> Self {
        Self::Metadata(e)
    }
}

/// One caller-selected publication to remember after actual local acceptance.
/// A missing update belongs to untracked publication and is not this type.
#[derive(Clone, Copy)]
pub struct Record<'a> {
    /// Exact C-string payload; empty is legal, interior NUL is refused.
    pub identifier: &'a [u8],
    /// Exact caller-supplied update, including an explicitly selected empty value.
    pub update: &'a [u8],
    /// Any official FS target URI variant.
    pub uri: Uri<'a>,
    /// Exact complete selected metadata wire artifact, or explicit absence.
    /// This does not assert that unselected source metadata was published.
    pub metadata: Option<&'a [u8]>,
}
/// The selected original graph store and public namespace. These persisted
/// coordinates are local binding data, not a native or publication capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Original private graph WAL identity.
    pub store_id: [u8; 32],
    /// Original public namespace bound in the graph manifest.
    pub namespace: [u8; 32],
}
/// A local original graph-record position. It grants no publication rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordId(usize);
impl RecordId {
    /// Zero-based local publication-record position.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}
/// An immutable original publication plan retained across a later local WAL error.
/// Its private binding permits explicit graph-only recovery without repeating PUT.
pub struct Prepared {
    store_id: [u8; 32],
    namespace: [u8; 32],
    expected: usize,
    body: Vec<u8>,
    index: Index,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedNamespaceRecord")
            .field("expected_record", &self.expected)
            .field("body_bytes", &self.body.len())
            .field("identifier_bytes", &self.identifier().len())
            .field("update_bytes", &self.update().len())
            .finish_non_exhaustive()
    }
}
impl Prepared {
    /// Exact original identifier selected before native publication.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        self.index.identifier.get(&self.body)
    }
    /// Exact original update selected before native publication.
    #[must_use]
    pub fn update(&self) -> &[u8] {
        self.index.update.get(&self.body)
    }
    /// Complete canonical target URI selected before native publication.
    #[must_use]
    pub fn raw_uri(&self) -> &[u8] {
        self.index.uri.get(&self.body)
    }
    /// Exact selected complete metadata artifact.
    #[must_use]
    pub fn metadata(&self) -> Option<&[u8]> {
        self.index.metadata.map(|r| r.get(&self.body))
    }
}
/// A task-bound candidate independent of the graph's current append position.
/// Only an actual original publication receipt may authorize recording it.
pub struct TaskPrepared {
    binding: Binding,
    origin: [u8; 32],
    body: Vec<u8>,
    index: Index,
}
impl fmt::Debug for TaskPrepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedTaskNamespaceRecord")
            .field("binding", &self.binding)
            .field("origin", &self.origin)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
impl TaskPrepared {
    /// Original selected physical graph and public namespace binding.
    #[must_use]
    pub const fn binding(&self) -> Binding {
        self.binding
    }
    /// Original publication task identity, never a wire request identifier.
    #[must_use]
    pub const fn origin(&self) -> [u8; 32] {
        self.origin
    }
    /// Hash of the exact canonical graph body, including origin and version.
    /// This candidate digest does not establish that the graph accepted it.
    #[must_use]
    pub fn body_hash(&self) -> [u8; 64] {
        gnunet_crypto::hash512(&self.body)
    }
    /// Exact original selected namespace identifier.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        self.index.identifier.get(&self.body)
    }
    /// Exact original selected update, including explicitly selected empty bytes.
    #[must_use]
    pub fn update(&self) -> &[u8] {
        self.index.update.get(&self.body)
    }
    /// Complete canonical original target URI.
    #[must_use]
    pub fn raw_uri(&self) -> &[u8] {
        self.index.uri.get(&self.body)
    }
    /// Original exact selected official metadata artifact.
    #[must_use]
    pub fn metadata(&self) -> Option<&[u8]> {
        self.index.metadata.map(|r| r.get(&self.body))
    }
}
/// Actual original graph acceptance, constructed only after the original body
/// was appended durably or an exact existing original row was confirmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskReceipt {
    binding: Binding,
    origin: [u8; 32],
    id: RecordId,
    body_hash: [u8; 64],
    newly_recorded: bool,
}
impl TaskReceipt {
    /// Original actual graph store and namespace.
    #[must_use]
    pub const fn binding(self) -> Binding {
        self.binding
    }
    /// Original task identity retained by the graph record.
    #[must_use]
    pub const fn origin(self) -> [u8; 32] {
        self.origin
    }
    /// Exact original local record position; no new publication right is granted.
    #[must_use]
    pub const fn id(self) -> RecordId {
        self.id
    }
    /// Hash of the original actual accepted graph record body.
    #[must_use]
    pub const fn body_hash(self) -> [u8; 64] {
        self.body_hash
    }
    /// True only when this invocation actually appended the original record.
    #[must_use]
    pub const fn newly_recorded(self) -> bool {
        self.newly_recorded
    }
}
/// One checked record view in the Store's reusable buffer. A later record read
/// requires releasing this view; the complete history is not retained in memory.
#[derive(Clone, Copy)]
pub struct StoredRecord<'a> {
    id: RecordId,
    index: &'a Index,
    body: &'a [u8],
}
impl<'a> StoredRecord<'a> {
    /// Original local record position.
    #[must_use]
    pub const fn id(self) -> RecordId {
        self.id
    }
    /// Exact source identifier bytes.
    #[must_use]
    pub fn identifier(self) -> &'a [u8] {
        self.index.identifier.get(self.body)
    }
    /// Exact update identifier bytes, including explicitly selected empty values.
    #[must_use]
    pub fn update(self) -> &'a [u8] {
        self.index.update.get(self.body)
    }
    /// Complete canonical target URI bytes.
    #[must_use]
    pub fn raw_uri(self) -> &'a [u8] {
        self.index.uri.get(self.body)
    }
    /// Parse the original URI under explicit policy; signed LOC is verified again.
    pub fn uri(self, limits: gnunet_fs::Limits) -> Result<Uri<'a>, gnunet_types::Error> {
        Uri::parse(self.raw_uri(), limits)
    }
    /// Task origin for durable task publication records; immediate records have None.
    #[must_use]
    pub const fn task_origin(self) -> Option<[u8; 32]> {
        self.index.origin
    }
    /// Exact selected official metadata artifact, not unselected caller metadata.
    #[must_use]
    pub fn metadata(self) -> Option<&'a [u8]> {
        self.index.metadata.map(|r| r.get(self.body))
    }
}
struct LabelRef {
    bytes: Vec<u8>,
    first: Option<RecordId>,
    last: Option<RecordId>,
}
struct Row {
    index: Index,
    source: [u8; 64],
    target: [u8; 64],
    next: Option<RecordId>,
}
struct Children<'a> {
    graph: &'a Graph,
    next: Option<RecordId>,
}
impl Iterator for Children<'_> {
    type Item = RecordId;
    fn next(&mut self) -> Option<Self::Item> {
        let id = self.next?;
        let row = self.graph.rows.get(id.0)?;
        self.next = row.next;
        Some(id)
    }
}
struct NewLabel {
    hash: [u8; 64],
    bytes: Vec<u8>,
}
struct NewLabels {
    items: [Option<NewLabel>; 2],
    len: usize,
}
/// One locked persistent namespace graph. Open loads history without any network work.
pub struct Graph {
    store: Store,
    namespace: [u8; 32],
    limits: Limits,
    rows: Vec<Row>,
    labels: HashMap<[u8; 64], LabelRef>,
    origins: HashMap<[u8; 32], RecordId>,
    retained: usize,
    scratch: Vec<u8>,
    inflater: Inflate,
}
impl Graph {
    pub(crate) fn directory_identity(&self) -> std::io::Result<crate::FileIdentity> {
        crate::FileIdentity::of(self.store.directory())
    }
    /// Create a private graph and durably bind its first record to this public key.
    pub fn create(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        limits: Limits,
        storage: store::Limits,
    ) -> Result<Self, Error> {
        validate_limits(limits)?;
        let mut store = Store::create(path, storage)?;
        let mut body = [0; 42];
        body[..8].copy_from_slice(MAGIC);
        body[8..10].copy_from_slice(&2u16.to_be_bytes());
        body[10..].copy_from_slice(&namespace);
        store.append(MANIFEST, &body)?;
        Ok(Self::empty(store, namespace, limits))
    }
    /// Load the exact original known prefix under its exclusive writer lock.
    /// Wrong namespace, malformed records and complete corruption are refused.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        limits: Limits,
        storage: store::Limits,
    ) -> Result<Self, Error> {
        Self::open_with(namespace, limits, || Store::open(path, storage))
    }
    /// Check the original registered directory descriptor before touching its
    /// lock/WAL or performing recovery; then load the same bound namespace graph.
    pub(crate) fn open_registered(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        limits: Limits,
        storage: store::Limits,
        expected: crate::FileIdentity,
    ) -> Result<Self, Error> {
        Self::open_with(namespace, limits, || {
            Store::open_registered(path, storage, expected)
        })
    }
    fn open_with(
        namespace: [u8; 32],
        limits: Limits,
        open: impl FnOnce() -> Result<Store, store::Error>,
    ) -> Result<Self, Error> {
        validate_limits(limits)?;
        let mut store = open()?;
        let first = store.read_record(0)?.ok_or(Error::Format)?;
        if first.kind != MANIFEST || first.bytes.len() != 42 || &first.bytes[..8] != MAGIC {
            return Err(Error::Format);
        }
        if first.bytes[8..10] != 2u16.to_be_bytes() {
            return Err(Error::Version);
        }
        if first.bytes[10..] != namespace {
            return Err(Error::Binding);
        }
        let mut graph = Self::empty(store, namespace, limits);
        let count = graph.store.record_count();
        for index in 1..count {
            let native = graph.store.read_record(index)?.ok_or(Error::Order)?;
            if native.kind != ACCEPTED {
                return Err(Error::Format);
            }
            let spans = codec::decode(native.bytes)?;
            codec::validate(
                native.bytes,
                &spans,
                limits,
                &mut graph.scratch,
                &mut graph.inflater,
            )?;
            if spans
                .origin
                .is_some_and(|origin| graph.origins.contains_key(&origin))
            {
                return Err(Error::Binding);
            }
            let (new, retained) = admission(
                graph.limits,
                &graph.rows,
                &graph.labels,
                &graph.origins,
                graph.retained,
                native.bytes,
                &spans,
            )?;
            graph.rows.try_reserve(1).map_err(|_| Error::Limit)?;
            if spans.origin.is_some() {
                graph.origins.try_reserve(1).map_err(|_| Error::Limit)?;
            }
            graph
                .labels
                .try_reserve(new.len)
                .map_err(|_| Error::Limit)?;
            let source = gnunet_crypto::hash512(spans.identifier.get(native.bytes));
            let target = gnunet_crypto::hash512(spans.update.get(native.bytes));
            graph.rows.push(Row {
                index: spans,
                source,
                target,
                next: None,
            });
            for label in new.items.into_iter().flatten() {
                graph.labels.insert(
                    label.hash,
                    LabelRef {
                        bytes: label.bytes,
                        first: None,
                        last: None,
                    },
                );
            }
            if let Some(origin) = spans.origin {
                graph.origins.insert(origin, RecordId(index - 1));
            }
            graph.link(RecordId(index - 1), source)?;
            graph.retained = retained;
        }
        Ok(graph)
    }
    fn empty(store: Store, namespace: [u8; 32], limits: Limits) -> Self {
        Self {
            store,
            namespace,
            limits,
            rows: Vec::new(),
            labels: HashMap::new(),
            origins: HashMap::new(),
            retained: 0,
            scratch: Vec::new(),
            inflater: Inflate::new(),
        }
    }
    /// Original public namespace identity, without a possession assertion.
    #[must_use]
    pub const fn namespace(&self) -> &[u8; 32] {
        &self.namespace
    }
    /// Original physical graph and public namespace coordinates, without implying
    /// native publication acceptance or key possession.
    #[must_use]
    pub fn binding(&self) -> Binding {
        Binding {
            store_id: *self.store.task_id(),
            namespace: self.namespace,
        }
    }
    /// Logical retained bytes charged to this graph's explicit policy.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained
    }
    /// Original uncertain native storage failure, if this writer is fenced.
    #[must_use]
    pub fn storage_failure(&self) -> Option<&store::Error> {
        self.store.failure()
    }
    /// Number of accepted publication rows, excluding the manifest or pending append.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.rows.len()
    }
    /// Snapshot of accepted positions. These IDs retain no body or graph borrow.
    pub fn record_ids(&self) -> impl ExactSizeIterator<Item = RecordId> + use<> {
        (0..self.rows.len()).map(RecordId)
    }
    /// Source label from the bounded metadata index, without a fresh disk read.
    #[must_use]
    pub fn record_identifier(&self, id: RecordId) -> Option<&[u8]> {
        let row = self.rows.get(id.0)?;
        self.labels
            .get(&row.source)
            .map(|label| label.bytes.as_slice())
    }
    /// Read and check this original record against the Store's accepted digest.
    /// Actual IO, authority and corruption errors remain distinct from a missing ID.
    pub fn record(&mut self, id: RecordId) -> Result<Option<StoredRecord<'_>>, Error> {
        let Some(row) = self.rows.get(id.0) else {
            return Ok(None);
        };
        let native = self
            .store
            .read_record(id.0.checked_add(1).ok_or(Error::Order)?)?
            .ok_or(Error::Order)?;
        if native.kind != ACCEPTED {
            return Err(Error::Order);
        }
        Ok(Some(StoredRecord {
            id,
            index: &row.index,
            body: native.bytes,
        }))
    }
    /// Accepted positions under this exact identifier, preserving duplicates.
    /// Collecting IDs requires only bounded metadata; read each body explicitly.
    pub fn children(&self, identifier: &[u8]) -> impl Iterator<Item = RecordId> {
        let next = self
            .labels
            .get(&gnunet_crypto::hash512(identifier))
            .filter(|known| known.bytes == identifier)
            .and_then(|known| known.first);
        Children { graph: self, next }
    }
    /// Representatives of source strongly connected components, giving a minimum
    /// directed reachability cover as in the official implementation and chain test.
    /// Each representative is the earliest retained record at its byte-smallest label.
    /// It represents a label, not its sole URI/update: enumerate `children` at that
    /// label to obtain every publication and outgoing edge before following updates.
    pub fn roots(&self) -> Result<Vec<RecordId>, Error> {
        components::roots(self, true)
    }
    /// One representative for every strongly connected component, including those
    /// reachable from other components. This exposes the header's literal SCC view.
    /// Enumerate `children` of each representative label to retain all its records.
    pub fn component_roots(&self) -> Result<Vec<RecordId>, Error> {
        components::roots(self, false)
    }
    /// Validate and allocate the exact immutable local record before any native PUT.
    /// The caller must serialize native publication with this original mutable graph.
    pub(crate) fn prepare(&mut self, record: Record<'_>) -> Result<Prepared, Error> {
        self.check_prefix()?;
        let (body, index) = codec::encode(record, self.limits)?;
        codec::validate(
            &body,
            &index,
            self.limits,
            &mut self.scratch,
            &mut self.inflater,
        )?;
        self.reserve(&body, &index)?;
        Ok(Prepared {
            store_id: *self.store.task_id(),
            namespace: self.namespace,
            expected: self.rows.len(),
            body,
            index,
        })
    }
    /// Remember an actually acknowledged publication once. A retry is local only:
    /// an exact matching original WAL position is returned without another append.
    /// A failure borrows the immutable prepared plan so its native acceptance and
    /// original candidate can remain available to the caller independently.
    pub(crate) fn append_accepted(&mut self, prepared: &Prepared) -> Result<RecordId, Error> {
        if prepared.store_id != *self.store.task_id() || prepared.namespace != self.namespace {
            return Err(Error::Binding);
        }
        self.check_prefix()?;
        if prepared.expected < self.rows.len() {
            let native = self
                .store
                .read_record(prepared.expected.checked_add(1).ok_or(Error::Order)?)?
                .ok_or(Error::Order)?;
            if native.kind == ACCEPTED && native.bytes == prepared.body {
                return Ok(RecordId(prepared.expected));
            }
            return Err(Error::Binding);
        }
        if prepared.expected != self.rows.len() {
            return Err(Error::Order);
        }
        self.append_candidate(&prepared.body, prepared.index)
    }
    /// Validate a stable task-origin candidate without reserving a graph position.
    /// Existing identical origins are confirmed even when graph quotas are full.
    pub(crate) fn prepare_task(
        &mut self,
        binding: Binding,
        origin: [u8; 32],
        record: Record<'_>,
    ) -> Result<TaskPrepared, Error> {
        if binding != self.binding() {
            return Err(Error::Binding);
        }
        self.check_prefix()?;
        let (body, index) = codec::encode_task(record, origin, self.limits)?;
        codec::validate(
            &body,
            &index,
            self.limits,
            &mut self.scratch,
            &mut self.inflater,
        )?;
        let prepared = TaskPrepared {
            binding,
            origin,
            body,
            index,
        };
        if self.confirm_task(&prepared)?.is_none() {
            self.reserve(&prepared.body, &prepared.index)?;
        }
        Ok(prepared)
    }
    /// Confirm the original exact task record without any write or native work.
    /// A conflicting reuse of an origin is an error rather than a second record.
    pub(crate) fn confirm_task(
        &mut self,
        prepared: &TaskPrepared,
    ) -> Result<Option<TaskReceipt>, Error> {
        if prepared.binding != self.binding() || prepared.index.origin != Some(prepared.origin) {
            return Err(Error::Binding);
        }
        self.check_prefix()?;
        let Some(&id) = self.origins.get(&prepared.origin) else {
            return Ok(None);
        };
        let native = self
            .store
            .read_record(id.0.checked_add(1).ok_or(Error::Order)?)?
            .ok_or(Error::Order)?;
        if native.kind != ACCEPTED || native.bytes != prepared.body {
            return Err(Error::Binding);
        }
        Ok(Some(TaskReceipt {
            binding: prepared.binding,
            origin: prepared.origin,
            id,
            body_hash: gnunet_crypto::hash512(native.bytes),
            newly_recorded: false,
        }))
    }
    /// Record only an actually acknowledged task publication, with stable origin
    /// deduplication across graph/task journal crashes and unrelated graph appends.
    pub(crate) fn append_task_accepted(
        &mut self,
        prepared: &TaskPrepared,
    ) -> Result<TaskReceipt, Error> {
        if let Some(receipt) = self.confirm_task(prepared)? {
            return Ok(receipt);
        }
        let id = self.append_candidate(&prepared.body, prepared.index)?;
        Ok(TaskReceipt {
            binding: prepared.binding,
            origin: prepared.origin,
            id,
            body_hash: prepared.body_hash(),
            newly_recorded: true,
        })
    }
    fn append_candidate(&mut self, body: &[u8], index: Index) -> Result<RecordId, Error> {
        codec::validate(
            body,
            &index,
            self.limits,
            &mut self.scratch,
            &mut self.inflater,
        )?;
        let (new, retained) = self.reserve(body, &index)?;
        let id = RecordId(self.rows.len());
        let expected = self.rows.len().checked_add(2).ok_or(Error::Order)?;
        let sequence = self.store.append(ACCEPTED, body)?;
        if usize::try_from(sequence).ok() != Some(expected) {
            return Err(Error::Order);
        }
        let source = gnunet_crypto::hash512(index.identifier.get(body));
        let target = gnunet_crypto::hash512(index.update.get(body));
        self.rows.push(Row {
            index,
            source,
            target,
            next: None,
        });
        for label in new.items.into_iter().flatten() {
            self.labels.insert(
                label.hash,
                LabelRef {
                    bytes: label.bytes,
                    first: None,
                    last: None,
                },
            );
        }
        if let Some(origin) = index.origin {
            self.origins.insert(origin, id);
        }
        self.link(id, source)?;
        self.retained = retained;
        Ok(id)
    }
    fn link(&mut self, id: RecordId, source: [u8; 64]) -> Result<(), Error> {
        let label = self.labels.get_mut(&source).ok_or(Error::Order)?;
        let previous = label.last;
        if label.first.is_none() {
            label.first = Some(id);
        }
        label.last = Some(id);
        if let Some(previous) = previous {
            self.rows.get_mut(previous.0).ok_or(Error::Order)?.next = Some(id);
        }
        Ok(())
    }
    fn check_prefix(&self) -> Result<(), Error> {
        if let Some(error) = self.store.failure() {
            return Err(error.clone().into());
        }
        if self.rows.len().checked_add(1) != Some(self.store.record_count()) {
            return Err(Error::Order);
        }
        Ok(())
    }
    fn reserve(&mut self, body: &[u8], index: &Index) -> Result<(NewLabels, usize), Error> {
        let (new, retained) = admission(
            self.limits,
            &self.rows,
            &self.labels,
            &self.origins,
            self.retained,
            body,
            index,
        )?;
        self.store.check_append(body.len())?;
        self.rows.try_reserve(1).map_err(|_| Error::Limit)?;
        self.labels.try_reserve(new.len).map_err(|_| Error::Limit)?;
        if index.origin.is_some() {
            self.origins.try_reserve(1).map_err(|_| Error::Limit)?;
        }
        Ok((new, retained))
    }
}
fn admission(
    limits: Limits,
    rows: &[Row],
    labels: &HashMap<[u8; 64], LabelRef>,
    origins: &HashMap<[u8; 32], RecordId>,
    retained: usize,
    body: &[u8],
    index: &Index,
) -> Result<(NewLabels, usize), Error> {
    if rows.len() >= limits.max_records {
        return Err(Error::Limit);
    }
    if index
        .origin
        .is_some_and(|origin| origins.contains_key(&origin))
    {
        return Err(Error::Binding);
    }
    let mut new = NewLabels {
        items: [None, None],
        len: 0,
    };
    let mut charge = retained
        .checked_add(size_of::<Row>())
        .and_then(|n| {
            n.checked_add(if index.origin.is_some() {
                size_of::<([u8; 32], RecordId)>()
            } else {
                0
            })
        })
        .filter(|n| *n <= limits.max_retained_bytes)
        .ok_or(Error::Limit)?;
    for span in [index.identifier, index.update] {
        let label = span.get(body);
        let hash = gnunet_crypto::hash512(label);
        if let Some(known) = labels.get(&hash) {
            if known.bytes != label {
                return Err(Error::Binding);
            }
        } else if let Some(known) = new.items.iter().flatten().find(|known| known.hash == hash) {
            if known.bytes != label {
                return Err(Error::Binding);
            }
        } else {
            if labels
                .len()
                .checked_add(new.len)
                .is_none_or(|n| n >= limits.max_labels)
            {
                return Err(Error::Limit);
            }
            let remaining = limits
                .max_retained_bytes
                .checked_sub(charge)
                .and_then(|n| n.checked_sub(size_of::<([u8; 64], LabelRef)>()))
                .ok_or(Error::Limit)?;
            if label.len() > remaining {
                return Err(Error::Limit);
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(label.len())
                .map_err(|_| Error::Limit)?;
            if bytes.capacity() > remaining {
                return Err(Error::Limit);
            }
            charge = charge
                .checked_add(size_of::<([u8; 64], LabelRef)>())
                .and_then(|n| n.checked_add(bytes.capacity()))
                .ok_or(Error::Limit)?;
            bytes.extend_from_slice(label);
            new.items[new.len] = Some(NewLabel { hash, bytes });
            new.len += 1;
        }
    }
    Ok((new, charge))
}

fn validate_limits(limits: Limits) -> Result<(), Error> {
    if limits.max_retained_bytes == 0
        || limits.max_record_bytes == 0
        || limits.max_record_bytes > u32::MAX as usize
        || limits.max_label_bytes > u32::MAX as usize
        || limits.max_uri_bytes > u32::MAX as usize
    {
        return Err(Error::Limit);
    }
    Ok(())
}
