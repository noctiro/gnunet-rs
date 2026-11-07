//! Bounded keyword/namespace searches over the actual local FS CLIENT port.
//! No task or Resolver is created. The source factory supplies one dedicated
//! endpoint source per query, in the same logical clock domain and deadline.
//! Keyword hits are aggregated by URI with mandatory intersection and optional
//! applicability counts. Namespace update labels create real subsequent queries
//! in the same namespace; a bounded graph prevents cycles from spawning MQs.
pub mod automatic;
pub mod availability;
pub mod observation;
pub mod probe;
pub mod proof;
pub mod task;
use crate::ipc;
use gnunet_fs::{
    Content, Location, Uri,
    client::Instance,
    metadata::{self as md, Format},
    ublock::{self, Context as BlockContext, Kind, Opener},
};
use gnunet_fs_codec::Inflate;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::SEARCH_LOOPBACK_ONLY;
use observation::{Pending, Staged};
use proof::{NamespaceSelection, Retained as RetainedProof};
use std::{
    fmt,
    future::poll_fn,
    mem::size_of,
    slice::IterMut,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::time::Instant;

/// Explicit host resource bounds; reaching one retains the pending native event.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Distinct active keyword/namespace queries, including followed update labels.
    pub queries: usize,
    /// Complete URI results retained, including not-yet-visible mandatory matches.
    pub results: usize,
    /// Logical retained URI/metadata/label/graph bytes, excluding native frame and
    /// fixed cryptographic buffers (which have their own explicit limits).
    pub retained_bytes: usize,
    /// Maximum metadata records after semantic merge for one URI.
    pub metadata_entries: usize,
    /// Maximum logical owned metadata record/field bytes for one URI.
    pub metadata_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queries: 64,
            results: 1024,
            retained_bytes: 16 * 1024 * 1024,
            metadata_entries: 4096,
            metadata_bytes: 1024 * 1024,
        }
    }
}
/// Original operation policy shared by all query connections and update children.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Caller-selected anonymity for every query, including update children.
    pub anonymity: u32,
    /// Request only the service's local datastore, with no synthetic negative end.
    pub local_only: bool,
    /// Original absolute logical deadline in each endpoint source's clock domain.
    pub deadline: AbsoluteTime,
    /// Search graph and retained result bounds.
    pub limits: Limits,
    /// Actual block authentication/decryption and URI/metadata decoding bounds.
    pub block: ublock::Limits,
    /// Low-level seen-set replay and raw-block policy.
    pub protocol: ipc::ProtocolLimits,
    /// Native frame and I/O bounds per dedicated MQ.
    pub native: ipc::Limits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnerStamp(u64);
impl OwnerStamp {
    fn new() -> Result<Self, ProtocolError> {
        // This counter grants identity only; relaxed ordering is sufficient.
        // Exhaustion refuses construction permanently instead of reusing a stamp.
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map(Self)
        .map_err(|_| ProtocolError::Overflow)
    }
}

/// A result-table index sealed to one original Session. It grants no file,
/// publication or transport rights and cannot select a different Session's hit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultId(usize, OwnerStamp);
impl ResultId {
    /// Diagnostic index scoped to the original session.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}
/// A local query graph index; it is never a field of an FS message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryId(usize);
impl QueryId {
    /// Diagnostic index scoped to the original session.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Complete native search failure, retaining the real lower-layer cause.
#[derive(Debug)]
pub enum Error {
    /// Native CLIENT/configuration/socket refusal.
    Transport(ipc::Error),
    /// Original URI, clock or resource arithmetic failure.
    Protocol(ProtocolError),
    /// Authenticated block could not be decrypted or interpreted.
    Block(ublock::Error),
    /// An explicit aggregate/graph/metadata bound was reached.
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Block(e) => e.fmt(f),
            Self::Limit => f.write_str("FS search resource limit exceeded"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Block(e) => Some(e),
            Self::Limit => None,
        }
    }
}
impl From<ipc::Error> for Error {
    fn from(e: ipc::Error) -> Self {
        Self::Transport(e)
    }
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<ublock::Error> for Error {
    fn from(e: ublock::Error) -> Self {
        Self::Block(e)
    }
}

/// An owned metadata record with the original C-compatible duplicate/enrichment
/// rules. A metadata label is not authorization to open an OS path.
#[derive(Debug)]
pub struct MetadataItem {
    kind: u32,
    format: Format,
    data: Vec<u8>,
    plugin: Option<Vec<u8>>,
    mime: Option<Vec<u8>>,
}
impl MetadataItem {
    /// Borrow the complete record, retaining final terminators and arbitrary bytes.
    #[must_use]
    pub fn item(&self) -> md::Item<'_> {
        md::Item {
            kind: self.kind,
            format: self.format,
            data: &self.data,
            plugin: self.plugin.as_deref(),
            mime: self.mime.as_deref(),
        }
    }
    fn from_item(item: md::Item<'_>) -> Result<Self, Error> {
        Ok(Self {
            kind: item.kind,
            format: item.format,
            data: copy(item.data)?,
            plugin: copy_name(item.plugin)?,
            mime: copy_name(item.mime)?,
        })
    }
    fn bytes(&self) -> usize {
        size_of::<Self>()
            + self.data.len()
            + self.plugin.as_ref().map_or(0, Vec::len)
            + self.mime.as_ref().map_or(0, Vec::len)
    }
    fn normalize(&mut self) {
        if matches!(self.kind, 2 | 180) {
            let length = md::c_prefix(&self.data).len();
            for byte in &mut self.data[..length] {
                if *byte == b'\\' {
                    *byte = b'/';
                }
            }
        }
    }
}

/// A retained URI result. Namespace results are scoped to the actual source
/// query, so identical content at successive labels can still advance updates.
pub struct ResultRecord {
    uri: Vec<u8>,
    identity: Identity,
    metadata: Vec<MetadataItem>,
    matched: Vec<QueryId>,
    mandatory_missing: usize,
    optional_support: usize,
    scope: Option<QueryId>,
    continuation: Option<QueryId>,
    proof: Option<RetainedProof>,
    probe_book: Option<usize>,
}
impl ResultRecord {
    /// Canonical complete URI bytes, excluding a final NUL.
    #[must_use]
    pub fn raw_uri(&self) -> &[u8] {
        &self.uri
    }
    /// Parse the result with explicit caller limits. LOC claims are verified again.
    pub fn uri(&self, limits: gnunet_fs::Limits) -> Result<Uri<'_>, ProtocolError> {
        Uri::parse(&self.uri, limits)
    }
    /// Complete metadata union in stable descending data-size order.
    #[must_use]
    pub fn metadata(&self) -> &[MetadataItem] {
        &self.metadata
    }
    /// Query connections whose authenticated records contributed to this URI.
    #[must_use]
    pub fn matched_queries(&self) -> &[QueryId] {
        &self.matched
    }
    /// Whether all mandatory keywords are satisfied (always true for SKS results).
    #[must_use]
    pub fn visible(&self) -> bool {
        self.mandatory_missing == 0
    }
    /// Mandatory input positions still missing from this retained URI.
    /// Duplicate input terms retain their original weighting.
    #[must_use]
    pub const fn mandatory_missing(&self) -> usize {
        self.mandatory_missing
    }
    /// Number of supported optional terms, with duplicate input positions counted.
    #[must_use]
    pub const fn applicability(&self) -> usize {
        self.optional_support
    }
    /// Source namespace query; None is the shared top-level KSK aggregation scope.
    #[must_use]
    pub const fn source_namespace_query(&self) -> Option<QueryId> {
        self.scope
    }
    /// Actual automatically followed update query in the same namespace.
    #[must_use]
    pub const fn continuation(&self) -> Option<QueryId> {
        self.continuation
    }
}

/// Borrowed provenance of an actual query owned by this session.
pub struct QueryInfo<'a> {
    /// Literal decoded keyword or SKS identifier, without a mandatory marker/NUL.
    pub label: &'a [u8],
    /// Query derived with the official fs-ublock context.
    pub query: &'a [u8; 64],
    /// Explicit keyword or namespace interpretation.
    pub kind: Kind,
    /// Original namespace public key; anonymous for keyword queries.
    pub namespace: &'a [u8; 32],
    /// Results that linked to this update query; a reused query may have parents.
    pub parents: &'a [ResultId],
}

/// A real search event or one native progress step. There is no whole-search
/// completion or negative lookup event: silence is not a service response.
#[expect(
    clippy::large_enum_variant,
    reason = "Inline native progress preserves owned event/error provenance without a fallible allocation after acceptance"
)]
pub enum Step {
    /// First visible result after satisfying all mandatory terms, or a new SKS URI.
    Result {
        /// Session-local table entry.
        result: ResultId,
    },
    /// A previously visible URI acquired another matched keyword and metadata.
    Update {
        /// Session-local table entry.
        result: ResultId,
    },
    /// A complete authenticated result was retained but lacks mandatory support.
    Pending {
        /// Session-local table entry.
        result: ResultId,
    },
    /// Duplicate, expired or irrelevant already-filtered result.
    Ignored,
    /// An untrusted advertisement was refused; the query remains live.
    Rejected {
        /// Original query.
        query: QueryId,
        /// Exact authentication/plaintext interpretation refusal.
        cause: Error,
    },
    /// One native step, including actual backoff/unavailability/observation timeout.
    Native {
        /// Original query.
        query: QueryId,
        /// Original native step, without a fabricated FS event.
        step: ipc::Step,
    },
    /// A query reached a terminal native/protocol failure. Other queries remain
    /// caller-driven; no successful empty result set is inferred.
    Failed {
        /// Original query.
        query: QueryId,
        /// Original failure.
        cause: ipc::Error,
    },
}

struct Spec {
    label: Vec<u8>,
    namespace: Option<[u8; 32]>,
    mandatory: usize,
    optional: usize,
}
struct Query<'id, const KNOWN: usize> {
    spec: Spec,
    opener: Opener,
    client: ipc::Client<'id, 'static, KNOWN>,
    parents: Vec<ResultId>,
    origin: Option<ResultId>,
    stopped: bool,
}
#[derive(Eq, PartialEq)]
enum Identity {
    Content(Content),
    Namespace([u8; 32], Vec<u8>),
    Keywords(Vec<(bool, Vec<u8>)>),
    Location(Location),
}
impl Identity {
    fn from_uri(uri: Uri<'_>) -> Result<Self, Error> {
        Ok(match uri {
            Uri::Content(value) => Self::Content(value),
            Uri::Namespace(value) => {
                Self::Namespace(*value.key().as_bytes(), copy(value.identifier())?)
            }
            Uri::Location(value) => Self::Location(value),
            Uri::Keywords(value) => {
                let mut terms = Vec::new();
                reserve(&mut terms, value.len())?;
                for term in value.iter() {
                    let mut bytes = filled(term.len())?;
                    term.write(&mut bytes)?;
                    terms.push((term.mandatory(), bytes));
                }
                // Equality is independent of term order and retains each
                // duplicate. Reusing one matching term for multiple positions
                // would make equality asymmetric and merge different results.
                terms.sort_unstable();
                Self::Keywords(terms)
            }
        })
    }
    fn extra_bytes(&self) -> usize {
        match self {
            Self::Namespace(_, id) => id.len(),
            Self::Keywords(terms) => terms
                .iter()
                .map(|(_, bytes)| size_of::<(bool, Vec<u8>)>() + bytes.len())
                .sum(),
            _ => 0,
        }
    }
}

struct Incoming {
    uri: Vec<u8>,
    metadata: Vec<MetadataItem>,
    update: Vec<u8>,
}
struct Upgrade {
    index: usize,
    mime: Option<Vec<u8>>,
    utf8: bool,
}
struct Merge {
    additions: Vec<MetadataItem>,
    upgrades: Vec<Upgrade>,
    extra_bytes: usize,
}

/// Caller-driven, fully retained multi-query search. F supplies one independent
/// source for each query; it must preserve the caller's Resolver and clock domain.
/// This native search selects the GNUnet absolute-time source profile: clock
/// values must be UTC microseconds as in service_runtime::clock::SystemClock,
/// not an arbitrary monotonic origin. Expiry is filtered before raw seen commit.
/// `identities` bounds lifetime query creation, including update descendants.
pub struct Session<'id, F, const KNOWN: usize>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    owner: OwnerStamp,
    identities: IterMut<'id, Instance>,
    source: F,
    clock: Option<Arc<dyn gnunet_service_runtime::clock::RuntimeClock>>,
    last_now: Option<AbsoluteTime>,
    options: Options,
    queries: Vec<Query<'id, KNOWN>>,
    initial_queries: usize,
    results: Vec<ResultRecord>,
    probe_books: Vec<availability::Book>,
    mandatory: usize,
    retained: usize,
    cursor: usize,
    pending: Option<Pending>,
    live_started: bool,
    last_replayed: Option<AbsoluteTime>,
    capture_namespace_proof: bool,
    plain: Vec<u8>,
    metadata_plain: Vec<u8>,
    inflater: Inflate,
    closed: bool,
}
impl<'id, F, const KNOWN: usize> Session<'id, F, KNOWN>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    /// Prepare actual queries without opening sockets. All mandatory/optional
    /// positions are preserved; identical decoded labels share one MQ and one
    /// verified hit satisfies all their identical positions.
    pub fn new(
        query: Uri<'_>,
        identities: &'id mut [Instance],
        source: F,
        options: Options,
    ) -> Result<Self, Error> {
        Self::new_mode(query, identities, source, options, false)
    }

    /// Retain bounded original signed records for a later durable SKS selection.
    /// Ordinary `new` retains no raw proof copy. Only namespace queries qualify.
    pub fn new_with_namespace_proof(
        query: Uri<'_>,
        identities: &'id mut [Instance],
        source: F,
        options: Options,
    ) -> Result<Self, Error> {
        if !matches!(query, Uri::Namespace(_)) {
            return Err(ProtocolError::InvalidInput.into());
        }
        Self::new_mode(query, identities, source, options, true)
    }

    fn new_mode(
        query: Uri<'_>,
        identities: &'id mut [Instance],
        source: F,
        options: Options,
        capture_namespace_proof: bool,
    ) -> Result<Self, Error> {
        if options.limits.queries == 0 || options.limits.results == 0 || identities.is_empty() {
            return Err(Error::Limit);
        }
        let mut specs: Vec<Spec> = Vec::new();
        let mut mandatory = 0_usize;
        match query {
            Uri::Keywords(keywords) => {
                if keywords.len() > options.block.uri.max_keywords {
                    return Err(Error::Limit);
                }
                for keyword in keywords.iter() {
                    if keyword.len() > options.block.max_label_bytes {
                        return Err(Error::Limit);
                    }
                    let mut label = filled(keyword.len())?;
                    keyword.write(&mut label)?;
                    mandatory = mandatory
                        .checked_add(usize::from(keyword.mandatory()))
                        .ok_or(ProtocolError::Overflow)?;
                    if let Some(spec) = specs.iter_mut().find(|spec| spec.label == label) {
                        if keyword.mandatory() {
                            spec.mandatory += 1;
                        } else {
                            spec.optional += 1;
                        }
                    } else {
                        if specs.len() >= options.limits.queries || specs.len() >= identities.len()
                        {
                            return Err(Error::Limit);
                        }
                        reserve(&mut specs, 1)?;
                        specs.push(Spec {
                            label,
                            namespace: None,
                            mandatory: usize::from(keyword.mandatory()),
                            optional: usize::from(!keyword.mandatory()),
                        });
                    }
                }
            }
            Uri::Namespace(namespace) => {
                reserve(&mut specs, 1)?;
                specs.push(Spec {
                    label: copy(namespace.identifier())?,
                    namespace: Some(*namespace.key().as_bytes()),
                    mandatory: 0,
                    optional: 0,
                });
            }
            _ => return Err(ProtocolError::InvalidInput.into()),
        }
        if specs.len() > options.limits.queries || specs.len() > identities.len() {
            return Err(Error::Limit);
        }
        let mut session = Self {
            owner: OwnerStamp::new()?,
            identities: identities.iter_mut(),
            source,
            clock: None,
            last_now: None,
            options,
            queries: Vec::new(),
            initial_queries: specs.len(),
            results: Vec::new(),
            probe_books: Vec::new(),
            mandatory,
            retained: 0,
            cursor: 0,
            pending: None,
            live_started: false,
            last_replayed: None,
            capture_namespace_proof,
            plain: Vec::new(),
            metadata_plain: Vec::new(),
            inflater: Inflate::new(),
            closed: false,
        };
        reserve(&mut session.queries, specs.len())?;
        for spec in specs {
            session.add_query(spec, None)?;
        }
        Ok(session)
    }

    /// Consume one proof-enabled session into an immutable chosen CHK/LOC.
    /// A result ID from a different Session is refused as Stale.
    /// Original raw UBLOCKs and labels are moved, without another raw proof
    /// copy. Every dedicated MQ is retired; retirement trouble remains separate
    /// from the already authenticated selection. Persist before output effects.
    pub fn finish_namespace_selection(
        mut self,
        chosen: ResultId,
    ) -> Result<NamespaceSelection, Error> {
        let (proof, selected, location) = proof::NamespaceProof::from_session(&mut self, chosen)?;
        let cleanup = if self.closed {
            None
        } else {
            self.cancel().err()
        };
        Ok(NamespaceSelection {
            proof,
            selected,
            location,
            cleanup,
        })
    }

    fn result_id(&self, index: usize) -> ResultId {
        ResultId(index, self.owner)
    }
    fn owns_result(&self, id: ResultId) -> bool {
        id.1 == self.owner
    }
    /// Retained result; foreign IDs are refused even if their index exists here.
    #[must_use]
    pub fn result(&self, id: ResultId) -> Option<&ResultRecord> {
        if !self.owns_result(id) {
            return None;
        }
        self.results.get(id.0)
    }
    /// All retained results, including those still missing mandatory terms.
    #[must_use]
    pub fn results(&self) -> &[ResultRecord] {
        &self.results
    }
    /// Exact query provenance and update graph parents.
    #[must_use]
    pub fn query(&self, id: QueryId) -> Option<QueryInfo<'_>> {
        self.queries.get(id.0).map(|q| QueryInfo {
            label: &q.spec.label,
            query: q.opener.query(),
            kind: q.opener.kind(),
            namespace: q.opener.namespace_key(),
            parents: &q.parents,
        })
    }
    /// Number of actual unique query owners, including update descendants.
    #[must_use]
    pub fn query_count(&self) -> usize {
        self.queries.len()
    }
    /// Increase or replace aggregate resource policy without consuming a pending
    /// native event. Existing retained state must still fit the new bounds.
    pub fn set_limits(&mut self, limits: Limits) -> Result<(), Error> {
        if limits.queries < self.queries.len()
            || limits.results < self.results.len()
            || limits.retained_bytes < self.retained
            || self.results.iter().any(|r| {
                r.metadata.len() > limits.metadata_entries
                    || metadata_bytes(&r.metadata) > limits.metadata_bytes
            })
        {
            return Err(Error::Limit);
        }
        self.options.limits = limits;
        Ok(())
    }
    /// Cancel every dedicated query MQ. Detached probes remain caller-owned and
    /// must be stopped or dropped separately. Continue closing query owners if one port refuses;
    /// the first actual native cause is returned. No synthetic cancel is sent.
    pub fn cancel(&mut self) -> Result<(), Error> {
        self.abort(ProtocolError::Cancelled)
    }
    fn abort(&mut self, cause: ProtocolError) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let mut first = None;
        for query in &mut self.queries {
            if !query.stopped {
                if let Err(error) = query.client.abort_with_cause(cause)
                    && first.is_none()
                {
                    first = Some(error);
                }
                query.stopped = true;
            }
        }
        self.closed = true;
        self.pending = None;
        match first {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
    /// Progress all query MQs fairly. Dropping this wait keeps native partial I/O,
    /// query owners, decoded results and any pending event in the session.
    pub async fn drive(&mut self, observation_deadline: Option<Instant>) -> Result<Step, Error> {
        match self.drive_staged(observation_deadline).await? {
            Staged::Advertisement => self.accept_staged(),
            Staged::Step(step) => Ok(step),
        }
    }
    /// Progress the original native queries until an authenticated advertisement
    /// is staged or a native/search progress event is available. A staged record
    /// changes no aggregate result or update graph. Persist its `observation`
    /// before explicitly calling `accept_staged` in durable consumers.
    /// Repeated waits retain the same staged advertisement and original MQ.
    pub async fn drive_staged(
        &mut self,
        observation_deadline: Option<Instant>,
    ) -> Result<Staged, Error> {
        poll_fn(|cx| self.poll_drive_staged(cx, observation_deadline)).await
    }
    fn poll_drive_staged(
        &mut self,
        cx: &mut Context<'_>,
        observation_deadline: Option<Instant>,
    ) -> Poll<Result<Staged, Error>> {
        self.live_started = true;
        if self.closed {
            return Poll::Ready(Err(ProtocolError::Closed.into()));
        }
        let observed = self
            .clock
            .as_ref()
            .ok_or(ProtocolError::NotReady)
            .and_then(|clock| clock.sample().map(|sample| sample.now));
        let cause = match observed {
            Ok(now) => {
                let cause = if self.last_now.is_some_and(|last| now < last) {
                    Some(ProtocolError::TimeUncertain)
                } else if now >= self.options.deadline {
                    Some(ProtocolError::Deadline)
                } else {
                    None
                };
                self.last_now = Some(now);
                cause
            }
            Err(cause) => Some(cause),
        };
        if let Some(cause) = cause {
            // Even a retained resource-refused advertisement cannot postpone
            // the original operation deadline or clock refusal indefinitely.
            return Poll::Ready(match self.abort(cause) {
                Ok(()) => Err(cause.into()),
                Err(error) => Err(error),
            });
        }
        if self.pending.is_some() {
            return Poll::Ready(self.stage_pending());
        }
        let count = self.queries.len();
        let mut active = false;
        for offset in 0..count {
            let index = (self.cursor + offset) % count;
            if self.queries[index].stopped {
                continue;
            }
            active = true;
            match self.queries[index]
                .client
                .poll_drive(cx, observation_deadline)
            {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    self.cursor = (index + 1) % count;
                    let id = QueryId(index);
                    return Poll::Ready(match result {
                        Ok(ipc::Step::Event(received)) => {
                            let observed_at = self.queries[index].client.observed_time();
                            self.pending = Some(Pending {
                                query: id,
                                received,
                                observed_at,
                                incoming: None,
                            });
                            self.stage_pending()
                        }
                        Ok(step) => {
                            if matches!(step, ipc::Step::Finished) {
                                self.queries[index].stopped = true;
                            }
                            Ok(Staged::Step(Step::Native { query: id, step }))
                        }
                        Err(cause) => {
                            if self.queries[index].client.failure().is_some() {
                                self.queries[index].stopped = true;
                                Ok(Staged::Step(Step::Failed { query: id, cause }))
                            } else {
                                // Capacity/allocation refusals may retain the native
                                // frame and MQ. Keep it live for retry or real cancel.
                                Err(Error::Transport(cause))
                            }
                        }
                    });
                }
            }
        }
        if active {
            Poll::Pending
        } else {
            Poll::Ready(Err(ProtocolError::Closed.into()))
        }
    }

    fn add_query(&mut self, spec: Spec, parent: Option<ResultId>) -> Result<QueryId, Error> {
        if parent.is_some_and(|id| !self.owns_result(id)) {
            return Err(ProtocolError::Stale.into());
        }
        let needed = spec
            .label
            .len()
            .checked_add(size_of::<Query<'id, KNOWN>>())
            .and_then(|n| n.checked_add(parent.map_or(0, |_| size_of::<ResultId>())))
            .ok_or(ProtocolError::Overflow)?;
        self.check_room(needed)?;
        if self.queries.len() >= self.options.limits.queries || self.identities.len() == 0 {
            return Err(Error::Limit);
        }
        let opener = match spec.namespace {
            Some(namespace) => {
                BlockContext::namespace(&namespace, &spec.label, self.options.block)?
            }
            None => BlockContext::keyword(&spec.label, self.options.block)?,
        }
        .into_opener();
        let source = (self.source)()?;
        if self.clock.is_none() {
            self.clock = Some(source.clock());
        }
        let mut parents = Vec::new();
        if let Some(parent) = parent {
            reserve(&mut parents, 1)?;
            parents.push(parent);
        }
        reserve(&mut self.queries, 1)?;
        let mut client = ipc::Client::new_with_identity(
            || self.identities.next().ok_or(ProtocolError::Capacity),
            ipc::Request::Search(ipc::Search {
                options: if self.options.local_only {
                    SEARCH_LOOPBACK_ONLY
                } else {
                    0
                },
                block_type: ipc::BlockType::UBLOCK,
                anonymity: self.options.anonymity,
                target: [0; 32],
                query: *opener.query(),
                seen: &[],
            }),
            source,
            self.options.protocol,
            self.options.native,
            self.options.deadline,
        )?;
        client.filter_expired_ublocks_using_source_absolute_time()?;
        let id = QueryId(self.queries.len());
        self.queries.push(Query {
            spec,
            opener,
            client,
            parents,
            origin: if self.capture_namespace_proof {
                parent
            } else {
                None
            },
            stopped: false,
        });
        self.retained += needed;
        Ok(id)
    }
    fn check_room(&self, bytes: usize) -> Result<(), Error> {
        if self
            .retained
            .checked_add(bytes)
            .is_none_or(|n| n > self.options.limits.retained_bytes)
        {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }

    fn decode_block(&mut self, id: QueryId, wire: &[u8]) -> Result<Incoming, Error> {
        let length = wire
            .len()
            .checked_sub(ublock::HEADER_BYTES + ublock::TAG_BYTES)
            .ok_or(ProtocolError::Truncated)?;
        grow(&mut self.plain, length)?;
        let plaintext = self
            .queries
            .get(id.0)
            .ok_or(ProtocolError::Stale)?
            .opener
            .open(wire, &mut self.plain)?;
        let scratch = metadata_scratch(plaintext.bytes());
        if scratch > self.options.block.metadata.max_plain_bytes {
            return Err(ublock::Error::Metadata(md::Error::Limit).into());
        }
        grow(&mut self.metadata_plain, scratch)?;
        let record = plaintext.decode(
            &mut self.metadata_plain,
            &mut self.inflater,
            md::Mode::Strict,
        )?;
        let uri = record.uri()?;
        let mut canonical = filled(uri.encoded_len()?)?;
        uri.encode(&mut canonical)?;
        let mut metadata = Vec::new();
        if let Some(value) = record.metadata() {
            reserve(&mut metadata, value.accepted_entries())?;
            for item in value.items() {
                metadata.push(MetadataItem::from_item(item)?);
            }
        }
        // The C search first deserializes each artifact into its own metadata
        // container (normalization/deduplication), then duplicates/merges that
        // container into a result. Keep these two insertion layers distinct.
        let import = merge_plan(
            &[],
            metadata,
            Limits {
                metadata_entries: self.options.block.metadata.max_entries,
                ..self.options.limits
            },
        )?;
        let mut metadata = Vec::new();
        reserve(&mut metadata, import.additions.len())?;
        apply_merge(&mut metadata, import);
        Ok(Incoming {
            uri: canonical,
            metadata,
            update: copy(record.update_identifier())?,
        })
    }

    fn match_incoming(
        &self,
        query: QueryId,
        incoming: &Incoming,
    ) -> Result<(Identity, Option<usize>), Error> {
        let namespace = self
            .queries
            .get(query.0)
            .ok_or(ProtocolError::Stale)?
            .spec
            .namespace;
        let scope = namespace.map(|_| query);
        let uri = Uri::parse(&incoming.uri, self.options.block.uri)?;
        let identity = Identity::from_uri(uri)?;
        let found = self
            .results
            .iter()
            .position(|result| result.scope == scope && result.identity == identity);
        Ok((identity, found))
    }

    fn accept(
        &mut self,
        query: QueryId,
        incoming: Incoming,
        wire: &[u8],
        expiration: gnunet_wire::official::AbsoluteTime,
        observed_at: AbsoluteTime,
    ) -> Result<Step, Error> {
        let namespace = self.queries[query.0].spec.namespace;
        let scope = namespace.map(|_| query);
        let (identity, found) = self.match_incoming(query, &incoming)?;
        if let Some(index) = found
            && self.results[index].matched.contains(&query)
        {
            return Ok(Step::Ignored);
        }
        if found.is_none() && self.results.len() >= self.options.limits.results {
            return Err(Error::Limit);
        }
        let existing = found.map_or(&[][..], |index| self.results[index].metadata.as_slice());
        let merge = merge_plan(existing, incoming.metadata, self.options.limits)?;
        let metadata_after = metadata_bytes(existing)
            .checked_add(merge.extra_bytes)
            .ok_or(ProtocolError::Overflow)?;
        if metadata_after > self.options.limits.metadata_bytes {
            return Err(Error::Limit);
        }
        let mut added = merge
            .extra_bytes
            .checked_add(size_of::<QueryId>())
            .ok_or(ProtocolError::Overflow)?;
        if found.is_none() {
            added = added
                .checked_add(incoming.uri.len())
                .and_then(|n| n.checked_add(size_of::<ResultRecord>()))
                .ok_or(ProtocolError::Overflow)?;
        }
        let mandatory = self.queries[query.0].spec.mandatory;
        let optional = self.queries[query.0].spec.optional;
        let missing = found
            .map_or(
                if namespace.is_some() {
                    0
                } else {
                    self.mandatory
                },
                |index| self.results[index].mandatory_missing,
            )
            .checked_sub(mandatory)
            .ok_or(ProtocolError::Conflict)?;
        let support = found
            .map_or(0, |index| self.results[index].optional_support)
            .checked_add(optional)
            .ok_or(ProtocolError::Overflow)?;
        // Prepare every fallible aggregation allocation before adding a child
        // or changing any result/match/metadata state.
        let result_id = self.result_id(found.unwrap_or(self.results.len()));
        let mut fresh_matches = Vec::new();
        let mut fresh_metadata = Vec::new();
        let mut fresh_identity = None;
        if found.is_none() {
            added = added
                .checked_add(identity.extra_bytes())
                .ok_or(ProtocolError::Overflow)?;
            fresh_identity = Some(identity);
        }
        if let Some(index) = found {
            reserve(&mut self.results[index].matched, 1)?;
            reserve(&mut self.results[index].metadata, merge.additions.len())?;
        } else {
            reserve(&mut self.results, 1)?;
            reserve(&mut fresh_matches, 1)?;
            reserve(&mut fresh_metadata, merge.additions.len())?;
        }
        let mut proof = None;
        if self.capture_namespace_proof && found.is_none() {
            added = added
                .checked_add(proof::retained_charge(wire.len())?)
                .ok_or(ProtocolError::Overflow)?;
            // The ResultRecord's fixed RetainedProof storage is already in its
            // size accounting. Charge the raw body and reserve the one consuming
            // export's fixed workspace before result, graph and child commit.
            self.check_room(added)?;
            proof = Some(RetainedProof {
                query,
                parent: self.queries[query.0].origin,
                wire: copy(wire)?,
                observed_at,
                expiration,
            });
        }
        self.check_room(added)?;
        let mut continuation = None;
        if let Some(namespace) = namespace
            && !incoming.update.is_empty()
        {
            if let Some(index) = self.queries.iter().position(|q| {
                q.spec.namespace == Some(namespace) && q.spec.label == incoming.update
            }) {
                if !self.queries[index].parents.contains(&result_id) {
                    self.check_room(
                        added
                            .checked_add(size_of::<ResultId>())
                            .ok_or(ProtocolError::Overflow)?,
                    )?;
                    reserve(&mut self.queries[index].parents, 1)?;
                    // No fallible actions remain after this graph change.
                    self.queries[index].parents.push(result_id);
                    added += size_of::<ResultId>();
                }
                continuation = Some(QueryId(index));
            } else {
                // Account the result and child together before creating a native
                // owner. The child factory opens no socket during construction.
                let child_bytes = incoming
                    .update
                    .len()
                    .checked_add(size_of::<ResultId>())
                    .and_then(|n| n.checked_add(size_of::<Query<'id, KNOWN>>()))
                    .ok_or(ProtocolError::Overflow)?;
                self.check_room(
                    added
                        .checked_add(child_bytes)
                        .ok_or(ProtocolError::Overflow)?,
                )?;
                continuation = Some(self.add_query(
                    Spec {
                        label: incoming.update,
                        namespace: Some(namespace),
                        mandatory: 0,
                        optional: 0,
                    },
                    Some(result_id),
                )?);
            }
        }
        let index = result_id.0;
        if let Some(identity) = fresh_identity {
            self.results.push(ResultRecord {
                uri: incoming.uri,
                identity,
                metadata: fresh_metadata,
                matched: fresh_matches,
                mandatory_missing: if namespace.is_some() {
                    0
                } else {
                    self.mandatory
                },
                optional_support: 0,
                scope,
                continuation,
                proof,
                probe_book: None,
            });
        }
        let result = &mut self.results[index];
        let was_visible = result.visible();
        apply_merge(&mut result.metadata, merge);
        result.matched.push(query);
        result.mandatory_missing = missing;
        result.optional_support = support;
        if continuation.is_some() {
            result.continuation = continuation;
        }
        self.retained += added;
        if !result.visible() {
            Ok(Step::Pending { result: result_id })
        } else if found.is_none() || !was_visible {
            Ok(Step::Result { result: result_id })
        } else {
            Ok(Step::Update { result: result_id })
        }
    }
}

fn merge_plan(
    existing: &[MetadataItem],
    incoming: Vec<MetadataItem>,
    limits: Limits,
) -> Result<Merge, Error> {
    let mut additions: Vec<MetadataItem> = Vec::new();
    let mut upgrades: Vec<Upgrade> = Vec::new();
    reserve(&mut additions, incoming.len())?;
    reserve(&mut upgrades, incoming.len())?;
    for mut item in incoming {
        if let Some(index) = existing
            .iter()
            .position(|old| old.kind == item.kind && old.data == item.data)
        {
            let old = &existing[index];
            let slot = if let Some(index) = upgrades.iter().position(|u| u.index == index) {
                index
            } else {
                upgrades.push(Upgrade {
                    index,
                    mime: None,
                    utf8: false,
                });
                upgrades.len() - 1
            };
            if old.mime.is_none() && upgrades[slot].mime.is_none() {
                upgrades[slot].mime = item.mime.take();
            }
            upgrades[slot].utf8 |= old.format == Format::CString && item.format == Format::Utf8;
        } else if let Some(old) = additions
            .iter_mut()
            .find(|old| old.kind == item.kind && old.data == item.data)
        {
            if old.mime.is_none() {
                old.mime = item.mime.take();
            }
            if old.format == Format::CString && item.format == Format::Utf8 {
                old.format = Format::Utf8;
            }
        } else {
            item.normalize();
            additions.push(item);
        }
    }
    if existing
        .len()
        .checked_add(additions.len())
        .is_none_or(|n| n > limits.metadata_entries)
    {
        return Err(Error::Limit);
    }
    let extra_bytes = additions
        .iter()
        .try_fold(0_usize, |sum, item| {
            sum.checked_add(item.bytes()).ok_or(ProtocolError::Overflow)
        })?
        .checked_add(
            upgrades
                .iter()
                .filter_map(|u| u.mime.as_ref())
                .map(Vec::len)
                .sum::<usize>(),
        )
        .ok_or(ProtocolError::Overflow)?;
    Ok(Merge {
        additions,
        upgrades,
        extra_bytes,
    })
}
fn apply_merge(metadata: &mut Vec<MetadataItem>, merge: Merge) {
    for upgrade in merge.upgrades {
        if let Some(mime) = upgrade.mime {
            metadata[upgrade.index].mime = Some(mime);
        }
        if upgrade.utf8 {
            metadata[upgrade.index].format = Format::Utf8;
        }
    }
    for item in merge.additions {
        let index = metadata
            .iter()
            .position(|old| old.data.len() < item.data.len())
            .unwrap_or(metadata.len());
        metadata.insert(index, item);
    }
}
fn metadata_scratch(plaintext: &[u8]) -> usize {
    let Some(first) = plaintext.iter().position(|b| *b == 0) else {
        return 0;
    };
    let rest = &plaintext[first + 1..];
    let Some(second) = rest.iter().position(|b| *b == 0) else {
        return 0;
    };
    let metadata = &rest[second + 1..];
    let Some(header) = metadata.get(..md::HEADER_BYTES) else {
        return 0;
    };
    if header[0] & 0x80 == 0 {
        return 0;
    }
    u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize
}
fn metadata_bytes(metadata: &[MetadataItem]) -> usize {
    metadata.iter().map(MetadataItem::bytes).sum()
}
fn retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::Limit
            | Error::Protocol(ProtocolError::Capacity)
            | Error::Block(ublock::Error::Capacity | ublock::Error::Metadata(md::Error::Capacity))
    )
}
fn reserve<T>(values: &mut Vec<T>, additional: usize) -> Result<(), Error> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| Error::Limit)
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    reserve(&mut output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(output)
}
fn copy_name(value: Option<&[u8]>) -> Result<Option<Vec<u8>>, Error> {
    value
        .map(|v| copy(&v[..md::c_prefix(v).len() + 1]))
        .transpose()
}
fn filled(length: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    reserve(&mut output, length)?;
    output.resize(length, 0);
    Ok(output)
}
fn grow(output: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    if output.len() < length {
        reserve(output, length - output.len())?;
        output.resize(length, 0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Fallible search regressions assert authenticated matching and atomic admission"
    )]
    use super::*;
    use gnunet_crypto::{EddsaPublicKey, gns::EdkeySecret};
    use gnunet_fs::{Keyword, Keywords, Namespace, ublock::Publisher};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    type Factory = fn() -> Result<ipc::EndpointSource, ipc::Error>;

    fn source() -> Result<ipc::EndpointSource, ipc::Error> {
        // Construction opens no socket; actual native driving is covered by
        // the IPC tests. These cases exercise real signatures/AEAD and queries.
        Ok(ipc::EndpointSource::unix(
            std::env::temp_dir().join("gnunet-search-unused.sock"),
        ))
    }
    fn options() -> Options {
        Options {
            anonymity: 1,
            local_only: true,
            deadline: AbsoluteTime::from_micros(u64::MAX),
            limits: Limits::default(),
            block: ublock::Limits::default(),
            protocol: ipc::ProtocolLimits::default(),
            native: ipc::Limits::default(),
        }
    }
    fn content(byte: u8) -> Uri<'static> {
        Uri::Content(Content {
            key: [byte; 64],
            query: [byte + 1; 64],
            size: u64::from(byte),
        })
    }
    fn seal(
        publisher: &Publisher<'_>,
        update: &[u8],
        uri: Uri<'_>,
        metadata: &[md::Item<'_>],
    ) -> TestResult<Vec<u8>> {
        let mut order = vec![0; metadata.len()];
        let mut scratch = vec![0; 4096];
        let plan = md::plan_uncompressed(
            metadata,
            &mut order,
            &mut scratch,
            md::Limits::default(),
            md::Options::default(),
        )?;
        let mut output = vec![0; 4096];
        Ok(publisher
            .seal(update, uri, Some(&plan), &mut output)?
            .bytes()
            .to_vec())
    }
    fn ingest<const N: usize>(
        session: &mut Session<'_, Factory, N>,
        query: QueryId,
        wire: &[u8],
    ) -> Result<Step, Error> {
        let incoming = session.decode_block(query, wire)?;
        session.accept(
            query,
            incoming,
            wire,
            gnunet_wire::official::AbsoluteTime::NEVER,
            AbsoluteTime::from_micros(0),
        )
    }
    fn title(format: Format, mime: Option<&[u8]>) -> md::Item<'_> {
        md::Item {
            kind: 4,
            format,
            data: b"title\0",
            plugin: None,
            mime,
        }
    }
    #[test]
    fn keyword_uri_identity_preserves_multiplicity_and_ignores_order() -> TestResult {
        let a = [
            Keyword::new(b"alpha", false)?,
            Keyword::new(b"alpha", false)?,
        ];
        let b = [
            Keyword::new(b"alpha", false)?,
            Keyword::new(b"beta", false)?,
        ];
        let c = [
            Keyword::new(b"beta", false)?,
            Keyword::new(b"alpha", false)?,
        ];
        let a = Identity::from_uri(Uri::Keywords(Keywords::new(&a)?))?;
        let b = Identity::from_uri(Uri::Keywords(Keywords::new(&b)?))?;
        let c = Identity::from_uri(Uri::Keywords(Keywords::new(&c)?))?;
        assert!(a != b && b != a);
        assert!(b == c && c == b);
        Ok(())
    }
    fn filename(data: &[u8]) -> md::Item<'_> {
        md::Item {
            kind: 2,
            format: Format::CString,
            data,
            plugin: None,
            mime: None,
        }
    }

    #[test]
    fn real_keyword_hits_gate_mandatory_merge_metadata_and_refuse_atomically() -> TestResult {
        let terms = [
            Keyword::new(b"alpha", true)?,
            Keyword::new(b"beta", true)?,
            Keyword::new(b"gamma", false)?,
        ];
        let mut identities = core::array::from_fn::<_, 4, _>(|_| Instance::new());
        let mut session = Session::<_, 8>::new(
            Uri::Keywords(Keywords::new(&terms)?),
            &mut identities,
            source as Factory,
            options(),
        )?;
        let alpha = seal(
            &Publisher::keyword(b"alpha", ublock::Limits::default())?,
            b"",
            content(1),
            &[title(Format::CString, None), filename(b"a/b\0")],
        )?;
        let beta = seal(
            &Publisher::keyword(b"beta", ublock::Limits::default())?,
            b"",
            content(1),
            &[title(Format::Utf8, Some(b"text/plain\0"))],
        )?;
        let gamma = seal(
            &Publisher::keyword(b"gamma", ublock::Limits::default())?,
            b"",
            content(1),
            &[filename(b"a\\b\0")],
        )?;
        // A genuine advertisement for a different derived query cannot create
        // or promote a result through another query slot.
        assert!(session.decode_block(QueryId(1), &alpha).is_err());
        assert!(session.results().is_empty());
        assert!(matches!(
            ingest(&mut session, QueryId(0), &alpha)?,
            Step::Pending { result } if result == session.result_id(0)
        ));
        let before = session.retained;
        let mut tight = session.options.limits;
        tight.retained_bytes = before;
        session.set_limits(tight)?;
        assert!(matches!(
            ingest(&mut session, QueryId(1), &beta),
            Err(Error::Limit)
        ));
        let result = session
            .result(session.result_id(0))
            .ok_or(ProtocolError::NotFound)?;
        assert!(!result.visible());
        assert_eq!(result.matched_queries(), &[QueryId(0)]);
        assert_eq!(result.metadata().len(), 2);
        let old = result
            .metadata()
            .iter()
            .find(|item| item.item().kind == 4)
            .ok_or(ProtocolError::NotFound)?
            .item();
        assert_eq!(old.format, Format::CString);
        assert_eq!(old.mime, None);
        assert_eq!(session.retained, before);
        session.set_limits(Limits::default())?;
        assert!(matches!(
            ingest(&mut session, QueryId(1), &beta)?,
            Step::Result { result } if result == session.result_id(0)
        ));
        assert!(matches!(
            ingest(&mut session, QueryId(2), &gamma)?,
            Step::Update { result } if result == session.result_id(0)
        ));
        let result = session
            .result(session.result_id(0))
            .ok_or(ProtocolError::NotFound)?;
        assert!(result.visible());
        assert_eq!(result.applicability(), 1);
        assert_eq!(result.metadata().len(), 2); // Deserialize normalization precedes result merge.
        let title = result
            .metadata()
            .iter()
            .find(|item| item.item().kind == 4)
            .ok_or(ProtocolError::NotFound)?
            .item();
        assert_eq!(title.format, Format::Utf8);
        assert_eq!(title.mime, Some(&b"text/plain\0"[..]));
        assert!(matches!(
            ingest(&mut session, QueryId(1), &beta)?,
            Step::Ignored
        ));
        session.cancel()?;
        Ok(())
    }

    #[test]
    fn result_ids_refuse_same_index_from_another_session_and_namespace_export() -> TestResult {
        let secret = EdkeySecret::from_seed([43; 32]);
        let root = Namespace::new(EddsaPublicKey::from_bytes(secret.public_key()), b"root")?;
        let mut first_identities = [Instance::new()];
        let mut second_identities = [Instance::new()];
        let mut first = Session::<_, 8>::new_with_namespace_proof(
            Uri::Namespace(root),
            &mut first_identities,
            source as Factory,
            options(),
        )?;
        let mut second = Session::<_, 8>::new_with_namespace_proof(
            Uri::Namespace(root),
            &mut second_identities,
            source as Factory,
            options(),
        )?;
        let publisher = Publisher::namespace(&secret, b"root", ublock::Limits::default())?;
        let first_wire = seal(&publisher, b"", content(1), &[])?;
        let second_wire = seal(&publisher, b"", content(2), &[])?;
        let first_id = match ingest(&mut first, QueryId(0), &first_wire)? {
            Step::Result { result } => result,
            _ => return Err("first authenticated result was not emitted".into()),
        };
        let second_id = match ingest(&mut second, QueryId(0), &second_wire)? {
            Step::Result { result } => result,
            _ => return Err("second authenticated result was not emitted".into()),
        };
        assert_eq!(first_id.index(), 0);
        assert_eq!(second_id.index(), 0);
        assert_ne!(first_id, second_id);
        assert!(first.result(first_id).is_some());
        assert!(second.result(second_id).is_some());
        assert!(first.result(second_id).is_none());
        assert!(second.result(first_id).is_none());
        assert!(matches!(
            second.finish_namespace_selection(first_id),
            Err(Error::Protocol(ProtocolError::Stale))
        ));
        let selection = first.finish_namespace_selection(first_id)?;
        let expected = match content(1) {
            Uri::Content(value) => value,
            _ => return Err("expected fixed CHK".into()),
        };
        assert_eq!(selection.selected, expected);
        selection.proof.verify(
            root,
            selection.selected,
            selection.location,
            Limits::default(),
            ublock::Limits::default(),
        )?;
        Ok(())
    }

    #[test]
    fn namespace_updates_admit_real_child_queries_keep_scope_and_stop_cycles() -> TestResult {
        let secret = EdkeySecret::from_seed([17; 32]);
        let public = secret.public_key();
        let root = Namespace::new(EddsaPublicKey::from_bytes(public), b"root")?;
        let mut identities = core::array::from_fn::<_, 4, _>(|_| Instance::new());
        let mut policy = options();
        policy.limits.queries = 1;
        let mut session = Session::<_, 8>::new(
            Uri::Namespace(root),
            &mut identities,
            source as Factory,
            policy,
        )?;
        let first = seal(
            &Publisher::namespace(&secret, b"root", ublock::Limits::default())?,
            b"next",
            content(1),
            &[],
        )?;
        assert!(matches!(
            ingest(&mut session, QueryId(0), &first),
            Err(Error::Limit)
        ));
        assert!(session.results().is_empty());
        assert_eq!(session.query_count(), 1);
        session.set_limits(Limits::default())?;
        assert!(matches!(
            ingest(&mut session, QueryId(0), &first)?,
            Step::Result { result } if result == session.result_id(0)
        ));
        assert_eq!(session.query_count(), 2);
        let child = session.query(QueryId(1)).ok_or(ProtocolError::NotFound)?;
        assert_eq!(child.namespace, &public);
        assert_eq!(child.label, b"next");
        assert_eq!(child.parents, &[session.result_id(0)]);
        let expected = BlockContext::namespace(&public, b"next", ublock::Limits::default())?;
        assert_eq!(child.query, expected.query());
        let cycle = seal(
            &Publisher::namespace(&secret, b"next", ublock::Limits::default())?,
            b"root",
            content(2),
            &[],
        )?;
        assert!(matches!(
            ingest(&mut session, QueryId(1), &cycle)?,
            Step::Result { result } if result == session.result_id(1)
        ));
        assert_eq!(session.query_count(), 2);
        assert_eq!(
            session
                .result(session.result_id(1))
                .and_then(ResultRecord::continuation),
            Some(QueryId(0))
        );
        // Identical content at the next namespace label is a separate scoped
        // result and can lead to another authenticated update identifier.
        let later = seal(
            &Publisher::namespace(&secret, b"next", ublock::Limits::default())?,
            b"later",
            content(1),
            &[],
        )?;
        assert!(matches!(
            ingest(&mut session, QueryId(1), &later)?,
            Step::Result { result } if result == session.result_id(2)
        ));
        assert_eq!(session.query_count(), 3);
        assert_eq!(
            session
                .result(session.result_id(2))
                .and_then(ResultRecord::continuation),
            Some(QueryId(2))
        );
        assert!(matches!(
            ingest(&mut session, QueryId(0), &first)?,
            Step::Ignored
        ));
        session.cancel()?;
        Ok(())
    }
}
