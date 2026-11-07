//! Durable prepared publications over actual official DATASTORE PUTs.
//! Immutable local payloads are verified before sending; unresolved original
//! mutations are never automatically replayed. This introduces no wire fields.
pub mod auto_prepare;
mod codec;
mod graph_runner;
mod graph_state;
mod index_runner;
mod model;
pub mod plan;
mod registration;
mod runner;
use crate::{
    Buffers, Repository,
    durable::store::{self, Store},
    network::{self, BlockOptions},
};
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_datastore_host::{Interruption, Outcome as NativeOutcome};
use gnunet_fs::{Keywords, Uri, metadata};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::datastore::{Data, Request, Response};
pub use graph_runner::{GraphOutcome, GraphResult};
pub use graph_state::{GraphTarget, Recorded as GraphRecorded};
pub use index_runner::NativeIndexResult;
pub use model::{Attempt, Counts, Disposition, Manifest, ModelError, NoEffect, Pending, Phase};
pub use registration::{Disposition as IndexDisposition, Pending as IndexPending};
use std::{ffi::OsStr, fmt, fs::File, path::Path};

/// Preparation and original journal budgets; neither is a protocol size change.
#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    /// File/URI/metadata/payload and ordered-plan bounds.
    pub plan: plan::Limits,
    /// Original private WAL record/body/file bounds.
    pub storage: store::Limits,
}
/// Explicit caller intent; cancellation never rolls back remote accepted effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Continue the original run.
    Continue,
    /// Stop fresh PUTs and retire original native work.
    Pause,
    /// Stop permanently, retaining accepted and uncertain mutation facts.
    Cancel,
}
/// A completed artifact or a settled local caller stop, never remote availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// Every ordered PUT has an original accepted reply and payload verification.
    Complete,
    /// Caller pause settled with no unresolved request.
    CallerPause,
    /// The original run deadline ended observation.
    Deadline,
    /// Caller cancellation settled; accepted/unknown remote effects remain.
    Cancelled,
}
/// Actual native operation admission, distinct from its eventual effect knowledge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// The runner created no original native operation.
    NotSubmitted,
    /// The original operation was admitted; inspect its actual terminal outcome.
    Submitted,
}
/// Original native result, bound privately to the actual task and intent. Only
/// this owner can reconcile its real reply; projected fields cannot mint a receipt.
pub struct NativeResult {
    task: [u8; 32],
    attempt: Attempt,
    submission: Submission,
    outcome: Option<NativeOutcome>,
    interruption: Option<Interruption>,
    requested_cancel: bool,
    cause: Option<network::Error>,
    settlement_error: Option<ConnectError>,
    frame: Option<OwnedFrame>,
    failed: bool,
}
impl NativeResult {
    /// Original operation admission, not a guessed send state.
    #[must_use]
    pub const fn submission(&self) -> Submission {
        self.submission
    }
    /// Actual original native completion; absent before submission.
    #[must_use]
    pub const fn outcome(&self) -> Option<NativeOutcome> {
        self.outcome
    }
    /// Actual native interruption, separate from caller control intent.
    #[must_use]
    pub const fn interruption(&self) -> Option<Interruption> {
        self.interruption
    }
    /// The control callback requested native cancellation.
    #[must_use]
    pub const fn requested_cancel(&self) -> bool {
        self.requested_cancel
    }
    /// Original driving/deadline/remote refusal cause, when present.
    #[must_use]
    pub fn cause(&self) -> Option<&network::Error> {
        self.cause.as_ref()
    }
    /// Independent failure taking the original operation after native retirement.
    #[must_use]
    pub fn settlement_error(&self) -> Option<&ConnectError> {
        self.settlement_error.as_ref()
    }
    /// Exact original retained reply bytes; never synthesized by re-encoding.
    #[must_use]
    pub fn response_bytes(&self) -> Option<&[u8]> {
        self.frame
            .as_ref()
            .map(OwnedFrame::bytes)
            .or_else(|| match self.cause.as_ref() {
                Some(network::Error::Store(e)) => e.response_bytes(),
                _ => None,
            })
    }
    /// Parse the original actual reply, including non-UTF8 diagnostics.
    pub fn response(&self) -> Result<Option<Response<'_>>, ProtocolError> {
        self.response_bytes().map(Response::decode).transpose()
    }
    /// Actual original local attempt coordinate, not a native capability.
    #[must_use]
    pub const fn attempt(&self) -> Attempt {
        self.attempt
    }
    /// Record this original completion only, after reopening the same journal if
    /// needed. This never opens a connection or repeats a weighted PUT.
    pub fn record(&self, task: &mut Task) -> Result<Effect, Cause> {
        if task.active {
            return Err(Cause::State("publication task already running"));
        }
        self.record_inner(&mut task.store, &mut task.state)
    }
}
impl fmt::Debug for NativeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicationNativeResult")
            .field("attempt", &self.attempt)
            .field("submission", &self.submission)
            .field("outcome", &self.outcome)
            .field("interruption", &self.interruption)
            .field("requested_cancel", &self.requested_cancel)
            .field("cause", &self.cause)
            .field("settlement_error", &self.settlement_error)
            .field("reply_bytes", &self.response_bytes().map(<[u8]>::len))
            .finish()
    }
}
/// Effect recorded from an original owner, independent of caller lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// Actual nonnegative PUT STATUS; zero may already have updated scores.
    Accepted,
    /// Original owner proved no request bytes were exposed.
    NotApplied,
    /// A negative peer declaration needs explicit retry authorization.
    Refused,
    /// Original effect remains unresolved; never automatically retry.
    Uncertain,
}
/// Independent actual FS registration prefix; PUT counts never establish it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IndexProgress {
    /// Original actual registration prefix when this run began.
    pub historical: usize,
    /// Actual IndexStarted replies recorded in the original WAL.
    pub recorded: usize,
    /// Actual IndexStarted replies observed in this invocation, even on WAL failure.
    pub new_accepted: usize,
    /// Exact number of named indexed sources.
    pub total: usize,
    /// Original unresolved registration, distinct from a PUT intent.
    pub pending: Option<IndexPending>,
}
/// Original graph bookkeeping and this invocation's independent graph checks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GraphProgress {
    /// An explicit update (including empty bytes) selected a persistent graph.
    pub required: bool,
    /// Historical original graph effect admitted to the task WAL.
    pub recorded: Option<GraphRecorded>,
    /// This invocation confirmed the actual original graph record and body.
    pub verified: bool,
    /// This invocation actually appended the task-origin graph record.
    pub newly_recorded: bool,
}
/// Known prefix and actual current-run observations stay separate.
#[derive(Clone, Copy, Debug, Default)]
pub struct Progress {
    /// Original accepted prefix when this run began.
    pub historical: Counts,
    /// Original and current-run FS registration facts.
    pub indexes: IndexProgress,
    /// Original graph history and current graph verification remain separate.
    pub graph: GraphProgress,
    /// Complete accepted replies currently admitted to the WAL.
    pub recorded: Counts,
    /// Actual accepted replies observed this run, even if a later WAL write failed.
    pub new_accepted: Counts,
    /// Ordered current plan size; zero before a manifest is available.
    pub total_puts: usize,
    /// Complete plan payload verification succeeded during this invocation.
    pub payloads_verified: bool,
    /// Current local verification work; it is not publication acceptance.
    pub verification: crate::Progress,
    /// Original current intent, if any; not a wire operation identifier.
    pub pending: Option<Pending>,
    /// Complete original journal record count.
    pub state_records: usize,
}
/// Structurally loaded history; status starts no payload read or native query.
#[derive(Clone, Copy, Debug)]
pub struct Status {
    /// Last original durable lifecycle phase.
    pub phase: Phase,
    /// Independently recorded original FS registrations.
    pub indexes: IndexProgress,
    /// Structural historical graph facts only; status performs no graph IO.
    pub graph: GraphProgress,
    /// This object currently owns a running future.
    pub active: bool,
    /// Running/requested history has no settled live owner.
    pub interrupted: bool,
    /// Original accepted prefix from real retained replies.
    pub recorded: Counts,
    /// Immutable number of ordered PUTs.
    pub total_puts: usize,
    /// Original unresolved intent/peer declaration.
    pub pending: Option<Pending>,
    /// Bare intent or Unknown cannot safely be repeated.
    pub uncertain: bool,
    /// Original peer refusal requires an explicit local retry choice.
    pub requires_explicit_retry: bool,
    /// Original pause/cancel intent retained across uncertainty/failure.
    pub requested: Option<Phase>,
    /// Complete original journal record count.
    pub state_records: usize,
    /// An uncertain original append prevents further writes on this owner.
    pub fenced: bool,
}
/// Explicit original refusal, keeping storage/native certainty unchanged.
#[derive(Debug)]
pub enum Cause {
    /// Original private WAL stage/certainty and native error.
    Storage(store::Error),
    /// Original typed task model refusal.
    Model(ModelError),
    /// Original namespace graph binding, resource or WAL refusal.
    Graph(crate::namespace::graph::Error),
    /// Original source, payload or cryptographic verification failure.
    Plan(plan::Error),
    /// Original client/source/deadline refusal before an operation existed.
    Client(ConnectError),
    /// Original generic transfer/source-clock refusal outside a native attempt.
    Transfer(network::Error),
    /// Original protocol or clock/resource refusal.
    Protocol(ProtocolError),
    /// Explicit ownership, unresolved mutation or lifecycle precondition.
    State(&'static str),
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Model(e) => e.fmt(f),
            Self::Graph(e) => e.fmt(f),
            Self::Plan(e) => e.fmt(f),
            Self::Client(e) => e.fmt(f),
            Self::Transfer(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::State(e) => f.write_str(e),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Model(e) => Some(e),
            Self::Graph(e) => Some(e),
            Self::Plan(e) => Some(e),
            Self::Client(e) => Some(e),
            Self::Transfer(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::State(_) => None,
        }
    }
}
impl From<crate::namespace::graph::Error> for Cause {
    fn from(e: crate::namespace::graph::Error) -> Self {
        Self::Graph(e)
    }
}
impl From<store::Error> for Cause {
    fn from(e: store::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<ModelError> for Cause {
    fn from(e: ModelError) -> Self {
        Self::Model(e)
    }
}
impl From<plan::Error> for Cause {
    fn from(e: plan::Error) -> Self {
        Self::Plan(e)
    }
}
impl From<ConnectError> for Cause {
    fn from(e: ConnectError) -> Self {
        Self::Client(e)
    }
}
impl From<ProtocolError> for Cause {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
/// Actual acceptance and payload proof, separate from native cleanup trouble.
#[derive(Debug)]
pub struct Completed {
    /// Fresh genuine payload verification; not deserialized from the manifest.
    pub verified: plan::VerifiedPlan,
    /// Original and this-run acceptance facts.
    pub progress: Progress,
}
/// Settled result. Cancellation can retain an unresolved remote effect; it
/// means no future work is authorized, not that accepted writes were rolled back.
#[derive(Debug)]
pub struct Outcome {
    /// Explicit complete or stop reason.
    pub reason: StopReason,
    /// Historical and current-run facts.
    pub progress: Progress,
    /// Present only for known complete ordered publication and fresh payload proof.
    pub completed: Option<Completed>,
    /// Actual final original native result, when an operation ran.
    pub last_native: Option<NativeResult>,
    /// Actual final original FS registration result, if registration ran.
    pub last_index: Option<NativeIndexResult>,
    /// Actual final local graph acceptance, independent of the task WAL.
    pub last_graph: Option<GraphResult>,
    /// Independent connection retirement failure after all accepted effects.
    pub cleanup: Option<ConnectError>,
}
/// Complete original failure; a local write failure cannot erase an actual ACK.
#[derive(Debug)]
pub struct Failure {
    /// Original local refusal, absent when only the native outcome failed.
    pub cause: Option<Cause>,
    /// Actual original native completion/failure and exact retained reply.
    pub native: Option<NativeResult>,
    /// Actual original FS registration result retained independently of WAL failure.
    pub index: Option<NativeIndexResult>,
    /// Actual graph success retained if a later independent task write failed.
    pub graph: Option<GraphResult>,
    /// Independent physical retirement failure.
    pub cleanup: Option<ConnectError>,
    /// Independent failure recording task lifecycle.
    pub state_failure: Option<Cause>,
    /// Known progress before/after the independent failures.
    pub progress: Progress,
    /// Original caller stop intent, without claiming a successful state append.
    pub requested_stop: Option<StopReason>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FS publication task did not settle")?;
        if let Some(e) = &self.cause {
            write!(f, ": {e}")?;
        }
        if let Some(n) = &self.native {
            write!(f, "; native {:?} {:?}", n.submission, n.outcome)?;
            if let Some(e) = n.cause() {
                write!(f, ": {e}")?;
            }
        }
        if let Some(index) = &self.index {
            write!(f, "; index {:?}", index.registration())?;
            if let Some(error) = index.failure() {
                write!(f, ": {error}")?;
            }
        }
        if let Some(graph) = &self.graph {
            write!(
                f,
                "; graph accepted record {}",
                graph.receipt().id().index()
            )?;
        }
        if let Some(e) = &self.cleanup {
            write!(f, "; cleanup: {e}")?;
        }
        if let Some(e) = &self.state_failure {
            write!(f, "; state: {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|e| e as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|n| n.cause())
                    .map(|e| e as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.index
                    .as_ref()
                    .and_then(NativeIndexResult::failure)
                    .map(|e| e as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.index
                    .as_ref()
                    .and_then(NativeIndexResult::retirement_error)
                    .map(|e| e as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.cleanup
                    .as_ref()
                    .map(|e| e as &(dyn std::error::Error + 'static))
            })
    }
}
/// One original locked publication task. Payload objects use the same anchored
/// journal directory descriptor; mutable run ownership excludes another writer.
pub struct Task {
    store: Store,
    state: model::State,
    active: bool,
}
impl Task {
    pub(crate) fn directory_identity(&self) -> std::io::Result<crate::FileIdentity> {
        crate::FileIdentity::of(self.store.directory())
    }
    fn prepare(
        path: impl AsRef<Path>,
        blocks: BlockOptions,
        limits: Limits,
        build: impl FnOnce(&mut Repository) -> Result<plan::Plan, plan::Error>,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare_graph(path, blocks, limits, None, build)
    }
    fn prepare_admitted(
        path: impl AsRef<Path>,
        blocks: BlockOptions,
        limits: Limits,
        build: impl FnOnce(&mut Repository) -> Result<plan::Plan, plan::Error>,
        admit: impl FnOnce(&Manifest, usize) -> Result<(), plan::Error>,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare_graph_admitted(path, blocks, limits, None, build, admit)
    }
    fn prepare_graph(
        path: impl AsRef<Path>,
        blocks: BlockOptions,
        limits: Limits,
        graph: Option<&mut crate::namespace::graph::Graph>,
        build: impl FnOnce(&mut Repository) -> Result<plan::Plan, plan::Error>,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare_graph_admitted(path, blocks, limits, graph, build, |_, _| Ok(()))
    }
    fn prepare_graph_admitted(
        path: impl AsRef<Path>,
        blocks: BlockOptions,
        limits: Limits,
        graph: Option<&mut crate::namespace::graph::Graph>,
        build: impl FnOnce(&mut Repository) -> Result<plan::Plan, plan::Error>,
        admit: impl FnOnce(&Manifest, usize) -> Result<(), plan::Error>,
    ) -> Result<Self, Box<Failure>> {
        let result = (|| -> Result<Self, Cause> {
            let mut store = Store::create(path, limits.storage)?;
            let mut repo = Repository::open_child(store.directory(), OsStr::new("objects"))
                .map_err(plan::Error::Host)?;
            let plan = build(&mut repo)?;
            let manifest = Manifest {
                graph: graph.as_ref().map(|g| GraphTarget {
                    binding: g.binding(),
                }),
                plan,
                blocks,
                limits: limits.plan,
            };
            manifest.validate()?;
            if let Some(graph) = graph {
                let plan::Artifact::Namespace {
                    identifier,
                    update,
                    target_uri,
                    metadata,
                    ..
                } = &manifest.plan.artifact
                else {
                    return Err(Cause::State("graph target requires namespace preparation"));
                };
                let target = manifest.graph.ok_or(ProtocolError::Stale)?;
                let uri = Uri::parse(target_uri, manifest.limits.ublock.uri)?;
                let _prepared = graph.prepare_task(
                    target.binding,
                    *store.task_id(),
                    crate::namespace::graph::Record {
                        identifier,
                        update,
                        uri,
                        metadata: metadata.as_deref(),
                    },
                )?;
            }
            let event = model::Event::Manifest(Box::new(manifest));
            let (kind, bytes) = codec::encode_event(&event)?;
            let model::Event::Manifest(manifest) = &event else {
                return Err(Cause::State("expected original preparation manifest"));
            };
            // Admission uses the real prepared plan and the existing canonical
            // WAL codec's exact body length. No task manifest becomes durable
            // or escapes to its group before the original owner grants credit.
            admit(manifest, bytes.len())?;
            store.append(kind, &bytes)?;
            drop(event);
            drop(bytes);
            let state = model::State::load(&mut store)?;
            Ok(Self {
                store,
                state,
                active: false,
            })
        })();
        result.map_err(empty_failure)
    }
    /// Prepare an immutable real full D/I file publication; source changes/EOF
    /// refusal may leave local objects but submit no native mutation.
    pub fn create_file(
        path: impl AsRef<Path>,
        input: &mut File,
        buffers: &mut Buffers,
        blocks: BlockOptions,
        limits: Limits,
        control: impl FnMut(crate::Progress) -> crate::Control,
    ) -> Result<Self, Box<Failure>> {
        let metadata = input
            .metadata()
            .map_err(|e| empty_failure(Cause::Plan(plan::Error::Host(e.into()))))?;
        plan::file_budget(metadata.len(), limits.plan).map_err(|e| empty_failure(e.into()))?;
        Self::prepare(path, blocks, limits, |repo| {
            plan::prepare_file(repo, input, buffers, limits.plan, control)
        })
    }
    /// Prepare exact type6 leaves and full index blocks from one named source.
    /// The source remains required for verification and future on-demand serving.
    pub fn create_indexed_file(
        path: impl AsRef<Path>,
        input: &mut File,
        filename: &Path,
        buffers: &mut Buffers,
        blocks: BlockOptions,
        limits: Limits,
        control: impl FnMut(crate::Progress) -> crate::Control,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare(path, blocks, limits, |repo| {
            let prepared =
                plan::indexed::prepare(repo, input, filename, buffers, limits.plan, control)?;
            Ok(plan::Plan {
                artifact: plan::Artifact::IndexedFile {
                    content: prepared.content,
                    source: prepared.source,
                },
                puts: prepared.puts,
            })
        })
    }
    /// Prepare a complete postorder directory publication without a service port.
    pub fn create_tree(
        path: impl AsRef<Path>,
        input: &crate::input_tree::InputDir,
        buffers: &mut Buffers,
        blocks: BlockOptions,
        limits: Limits,
        control: impl FnMut(crate::Progress) -> crate::Control,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare(path, blocks, limits, |repo| {
            let (tree, puts) =
                plan::tree::prepare_tree(repo, input, None, buffers, limits.plan, control)?;
            Ok(plan::Plan {
                artifact: plan::Artifact::Tree(tree),
                puts,
            })
        })
    }
    /// Prepare on-demand regular files and complete directory artifacts. Named
    /// sources remain required after preparation; no registration is performed.
    pub fn create_indexed_tree(
        path: impl AsRef<Path>,
        input: &crate::input_tree::InputDir,
        named_root: &Path,
        buffers: &mut Buffers,
        blocks: BlockOptions,
        limits: Limits,
        control: impl FnMut(crate::Progress) -> crate::Control,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare(path, blocks, limits, |repo| {
            let (tree, puts) = plan::tree::prepare_tree(
                repo,
                input,
                Some(named_root),
                buffers,
                limits.plan,
                control,
            )?;
            Ok(plan::Plan {
                artifact: plan::Artifact::Tree(tree),
                puts,
            })
        })
    }
    /// Prepare an anchored tree with explicit bounded metadata transformation.
    /// `named_root` selects real indexed leaves; None retains complete blocks.
    #[expect(
        clippy::too_many_arguments,
        reason = "Caller storage, real source, block policy and metadata authority are explicit"
    )]
    pub fn create_tree_with_metadata(
        path: impl AsRef<Path>,
        input: &crate::input_tree::InputDir,
        named_root: Option<&Path>,
        buffers: &mut Buffers,
        blocks: BlockOptions,
        limits: Limits,
        metadata: &mut impl plan::tree::MetadataProvider,
        control: impl FnMut(crate::Progress) -> crate::Control,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare(path, blocks, limits, |repo| {
            let (tree, puts) = plan::tree::prepare_tree_with_metadata(
                repo,
                input,
                named_root,
                buffers,
                limits.plan,
                metadata,
                control,
            )?;
            Ok(plan::Plan {
                artifact: plan::Artifact::Tree(tree),
                puts,
            })
        })
    }
    /// Prepare every ordered KSK term, including repeated weighted terms.
    pub fn create_keywords(
        path: impl AsRef<Path>,
        query: Keywords<'_>,
        target: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        blocks: BlockOptions,
        limits: Limits,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare(path, blocks, limits, |repo| {
            plan::prepare_keywords(repo, query, target, metadata, limits.plan)
        })
    }
    /// Seal one exact namespace payload using the original validated key file.
    /// Only signed public artifacts, never seed bytes, enter the task.
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit key, identifier, update, target and original task policy remain separate"
    )]
    pub fn create_namespace(
        path: impl AsRef<Path>,
        key: &crate::namespace::key::KeyFile,
        identifier: &[u8],
        update: &[u8],
        target: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        blocks: BlockOptions,
        limits: Limits,
    ) -> Result<Self, Box<Failure>> {
        Self::prepare(path, blocks, limits, |repo| {
            plan::prepare_namespace(repo, key, identifier, update, target, metadata, limits.plan)
        })
    }
    /// Seal a namespace publication and retain its optional graph selection.
    /// None is untracked; Some(empty) keeps an explicit graph record, although
    /// both use the same empty update bytes on the official wire.
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit task, managed key/graph, namespace fields and publication policy"
    )]
    pub fn create_managed_namespace(
        path: impl AsRef<Path>,
        key: &crate::namespace::key::KeyFile,
        graph: &mut crate::namespace::graph::Graph,
        identifier: &[u8],
        update: Option<&[u8]>,
        target: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        blocks: BlockOptions,
        limits: Limits,
    ) -> Result<Self, Box<Failure>> {
        if graph.namespace() != &key.public_key() {
            return Err(empty_failure(
                crate::namespace::graph::Error::Binding.into(),
            ));
        }
        let tracked = update.is_some().then_some(graph);
        Self::prepare_graph(path, blocks, limits, tracked, |repo| {
            plan::prepare_namespace(
                repo,
                key,
                identifier,
                update.unwrap_or_default(),
                target,
                metadata,
                limits.plan,
            )
        })
    }
    /// Lock and structurally replay the original journal, without payload/native I/O.
    pub fn open(path: impl AsRef<Path>, limits: store::Limits) -> Result<Self, Box<Failure>> {
        Self::open_with(|| Store::open(path, limits))
    }
    /// Open only the catalog's original directory before journal recovery can
    /// touch any replacement. The original typed history is then loaded normally.
    #[cfg(feature = "network")]
    pub(crate) fn open_registered(
        path: impl AsRef<Path>,
        limits: store::Limits,
        expected: crate::FileIdentity,
    ) -> Result<Self, Box<Failure>> {
        Self::open_with(|| Store::open_registered(path, limits, expected))
    }
    fn open_with(open: impl FnOnce() -> Result<Store, store::Error>) -> Result<Self, Box<Failure>> {
        let result = (|| -> Result<Self, Cause> {
            let mut store = open()?;
            let state = model::State::load(&mut store)?;
            Ok(Self {
                store,
                state,
                active: false,
            })
        })();
        result.map_err(empty_failure)
    }
    /// Original immutable prepared artifacts and exact weighted policy.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.state.manifest
    }
    /// Original random physical journal identity.
    #[must_use]
    pub fn task_id(&self) -> &[u8; 32] {
        self.store.task_id()
    }
    /// Inspect known historical facts only; no payload verification is inferred.
    #[must_use]
    pub fn status(&self) -> Status {
        Status {
            phase: self.state.phase,
            indexes: self.index_progress(),
            graph: graph_runner::progress(&self.state, false, false),
            active: self.active,
            interrupted: !self.active
                && matches!(
                    self.state.phase,
                    Phase::Running | Phase::PauseRequested | Phase::CancelRequested
                ),
            recorded: self.state.counts,
            total_puts: self.state.manifest.plan.puts.len(),
            pending: self.state.pending,
            uncertain: self.state.uncertain(),
            requires_explicit_retry: self.state.requires_explicit_retry(),
            requested: self.state.requested,
            state_records: self.store.record_count(),
            fenced: self.store.fenced(),
        }
    }
    /// Authorize one retry only after a retained actual FS IndexFailed reply.
    /// Unknown or bare registration intents cannot use this permission.
    pub fn retry_index_refused(&mut self) -> Result<(), Cause> {
        if self.active {
            return Err(Cause::State("publication task already running"));
        }
        let attempt = self
            .state
            .indexes
            .pending
            .ok_or(Cause::State("no refused registration"))?
            .attempt;
        append(
            &mut self.store,
            &mut self.state,
            model::Event::Index(registration::Event::RetryRefused { attempt }),
        )
    }
    fn index_progress(&self) -> IndexProgress {
        IndexProgress {
            historical: self.state.indexes.accepted.len(),
            recorded: self.state.indexes.accepted.len(),
            new_accepted: 0,
            total: self.state.manifest.plan.index_sources().len(),
            pending: self.state.indexes.pending,
        }
    }
    /// Explicitly authorize retry after a retained negative peer declaration.
    /// Unknown and receipt-less intent can never use this method.
    pub fn retry_refused(&mut self) -> Result<(), Cause> {
        if self.active {
            return Err(Cause::State("publication task already running"));
        }
        let attempt = self
            .state
            .pending
            .ok_or(Cause::State("no refused intent"))?
            .attempt;
        append(
            &mut self.store,
            &mut self.state,
            model::Event::RetryRefused { attempt },
        )
    }
    /// Persist cancellation intent without undoing accepted or unknown remote effects.
    pub fn request_cancel(&mut self) -> Result<(), Cause> {
        if self.active {
            return Err(Cause::State("publication task already running"));
        }
        if self.state.phase == Phase::Cancelled || self.state.phase == Phase::CancelRequested {
            return Ok(());
        }
        phase(&mut self.store, &mut self.state, Phase::CancelRequested)
    }
    /// Settle idle cancellation. The exclusive physical lock excludes the old owner;
    /// a pending Unknown is retained in status and never becomes a replay permission.
    pub fn settle_cancel(&mut self) -> Result<Outcome, Box<Failure>> {
        if self.active || self.state.phase != Phase::CancelRequested {
            return Err(self.fail(Cause::State("idle cancellation requires CancelRequested")));
        }
        phase(&mut self.store, &mut self.state, Phase::Cancelled).map_err(|e| self.fail(e))?;
        Ok(Outcome {
            reason: StopReason::Cancelled,
            progress: self.progress(),
            completed: None,
            last_native: None,
            last_index: None,
            last_graph: None,
            cleanup: None,
        })
    }
    /// Reverify immutable payloads and resume only a known-safe accepted prefix.
    /// A fresh finite deadline is required; no original mutation is resubmitted.
    pub async fn run(
        &mut self,
        source: EndpointSource,
        buffers: &mut Buffers,
        deadline: AbsoluteTime,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        self.run_sources(None, None, source, buffers, deadline, control)
            .await
    }
    /// Resume on-demand sources through an explicit official FS registration port
    /// and a separate original DATASTORE port. Both use the same deadline domain.
    pub async fn run_indexed(
        &mut self,
        fs_source: EndpointSource,
        source: EndpointSource,
        buffers: &mut Buffers,
        deadline: AbsoluteTime,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        self.run_sources(None, Some(fs_source), source, buffers, deadline, control)
            .await
    }
    /// Resume with the exact original namespace graph. Accepted PUT history is
    /// reverified; graph reconciliation never repeats a confirmed mutation.
    pub async fn run_managed(
        &mut self,
        source: EndpointSource,
        graph: &mut crate::namespace::graph::Graph,
        buffers: &mut Buffers,
        deadline: AbsoluteTime,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        self.run_sources(Some(graph), None, source, buffers, deadline, control)
            .await
    }
    /// Reconcile already accepted namespace history using only local payloads
    /// and the original graph. This constructs no native client or deadline.
    /// Explicit bookkeeping after cancellation preserves the Cancelled phase.
    pub fn record_namespace_graph(
        &mut self,
        graph: &mut crate::namespace::graph::Graph,
        buffers: &mut Buffers,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<GraphOutcome, Box<Failure>> {
        if self.active
            || self.state.pending.is_some()
            || self.state.indexes.pending.is_some()
            || self.state.counts.accepted != self.state.manifest.plan.puts.len()
            || self.state.accepted.len() != 1
        {
            return Err(self.fail(Cause::State(
                "graph-only reconciliation requires the complete actual original namespace ACK",
            )));
        }
        graph_runner::binding(&self.state, graph).map_err(|e| self.fail(e))?;
        let cancelled = matches!(self.state.phase, Phase::CancelRequested | Phase::Cancelled)
            || self.state.requested == Some(Phase::CancelRequested);
        if cancelled {
            if self.state.phase != Phase::Cancelled {
                if self.state.phase != Phase::CancelRequested {
                    phase(&mut self.store, &mut self.state, Phase::CancelRequested)
                        .map_err(|e| self.fail(e))?;
                }
                phase(&mut self.store, &mut self.state, Phase::Cancelled)
                    .map_err(|e| self.fail(e))?;
            }
        } else {
            phase(&mut self.store, &mut self.state, Phase::Running).map_err(|e| self.fail(e))?;
        }
        self.active = true;
        let mut run = runner::Run {
            store: &mut self.store,
            state: &mut self.state,
            active: &mut self.active,
        };
        graph_runner::record(&mut run, graph, buffers, control, cancelled)
    }
    async fn run_sources(
        &mut self,
        graph: Option<&mut crate::namespace::graph::Graph>,
        fs_source: Option<EndpointSource>,
        source: EndpointSource,
        buffers: &mut Buffers,
        deadline: AbsoluteTime,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        if self.state.manifest.graph.is_some() && graph.is_none() {
            return Err(self.fail(Cause::State(
                "tracked namespace publication requires its original graph",
            )));
        }
        if let Some(graph) = graph.as_ref() {
            graph_runner::binding(&self.state, graph).map_err(|e| self.fail(e))?;
        }
        if !self.state.manifest.plan.index_sources().is_empty() && fs_source.is_none() {
            return Err(self.fail(Cause::State(
                "indexed publication requires an original FS source",
            )));
        }
        if self.active
            || matches!(self.state.phase, Phase::Cancelled | Phase::CancelRequested)
            || self.state.requested == Some(Phase::CancelRequested)
        {
            return Err(self.fail(Cause::State(
                "cancel intent cannot resume fresh publication",
            )));
        }
        if self.state.pending.is_some() || self.state.indexes.pending.is_some() {
            return Err(self.fail(Cause::State("original intent needs a real receipt or explicit refusal retry; Unknown cannot replay")));
        }
        if deadline.as_micros() == u64::MAX {
            return Err(self.fail(ProtocolError::InvalidInput.into()));
        }
        phase(&mut self.store, &mut self.state, Phase::Running).map_err(|e| self.fail(e))?;
        self.active = true;
        let mut run = runner::Run {
            store: &mut self.store,
            state: &mut self.state,
            active: &mut self.active,
        };
        run.drive(graph, fs_source, source, buffers, deadline, control)
            .await
    }
    fn progress(&self) -> Progress {
        Progress {
            historical: self.state.counts,
            indexes: self.index_progress(),
            graph: graph_runner::progress(&self.state, false, false),
            recorded: self.state.counts,
            total_puts: self.state.manifest.plan.puts.len(),
            pending: self.state.pending,
            state_records: self.store.record_count(),
            ..Progress::default()
        }
    }
    fn fail(&self, cause: Cause) -> Box<Failure> {
        let mut error = empty_failure(cause);
        error.progress = self.progress();
        error
    }
}
fn append(
    store: &mut Store,
    state: &mut model::State,
    event: model::Event<'_>,
) -> Result<(), Cause> {
    if state.applied() != store.record_count() as u64 {
        return Err(Cause::State("unapplied original publication prefix"));
    }
    state.prepare(&event)?;
    let (kind, bytes) = codec::encode_event(&event)?;
    let sequence = store.append(kind, &bytes)?;
    let index = store
        .record_count()
        .checked_sub(1)
        .ok_or(Cause::State("missing original appended record"))?;
    state.apply(sequence, index, kind, &bytes)?;
    Ok(())
}
fn phase(store: &mut Store, state: &mut model::State, phase: Phase) -> Result<(), Cause> {
    let counts = state.counts;
    append(store, state, model::Event::Phase { phase, counts })
}
fn empty_failure(cause: Cause) -> Box<Failure> {
    Box::new(Failure {
        cause: Some(cause),
        native: None,
        index: None,
        graph: None,
        cleanup: None,
        state_failure: None,
        progress: Progress::default(),
        requested_stop: None,
    })
}
fn request<'a>(put: &'a plan::Put, blocks: BlockOptions, body: &'a [u8]) -> Request<'a> {
    Request::Put(Data {
        reservation: 0,
        kind: put.kind,
        priority: blocks.priority,
        anonymity: blocks.anonymity,
        replication: blocks.replication,
        uid: 0,
        expiration: blocks.expiration,
        key: &put.key,
        value: body,
    })
}
fn read_request(
    repo: &mut Repository,
    put: &plan::Put,
    blocks: BlockOptions,
    body: &mut Vec<u8>,
    wire: &mut Vec<u8>,
) -> Result<[u8; 64], Cause> {
    body.try_reserve(put.payload.bytes.saturating_sub(body.len()))
        .map_err(|_| ProtocolError::Capacity)?;
    body.resize(put.payload.bytes, 0);
    let used = repo
        .read_payload(&put.payload.hash, body)
        .map_err(plan::Error::Host)?;
    if used != put.payload.bytes {
        return Err(plan::Error::Binding.into());
    }
    let message = request(put, blocks, body);
    let size = message.encoded_len()?;
    wire.try_reserve(size.saturating_sub(wire.len()))
        .map_err(|_| ProtocolError::Capacity)?;
    wire.resize(size, 0);
    message.encode(wire)?;
    Ok(gnunet_crypto::hash512(wire))
}

#[cfg(test)]
mod tests;
