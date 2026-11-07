//! Explicit persistent search tasks over original authenticated observations.
//! Reopening loads history; running revalidates it through the same Session.
mod codec;
mod model;
mod runner;
use super::{Options, QueryId, QueryInfo, ResultId, ResultRecord, Step};
use crate::{
    durable::store::{self, Store},
    ipc,
};
use gnunet_fs::Uri;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
pub use model::{Counts, Manifest, ModelError, Phase};
use std::{fmt, path::Path};

/// Explicit raw-observation and physical journal bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original WAL record/body/file bounds, including lifecycle records.
    pub storage: store::Limits,
    /// Upper bound on retained authenticated observations.
    pub max_observations: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            storage: store::Limits::default(),
            max_observations: 65_536,
        }
    }
}
/// Cooperative intent; neither pause nor cancellation deletes historical results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Continue the same run.
    Continue,
    /// Persist pause intent and retire original native work.
    Pause,
    /// Persist cancellation intent and retire original native work.
    Cancel,
}
/// A settled caller observation stop. There is no whole-search completion state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// Caller requested a pause.
    CallerPause,
    /// The caller's operation deadline elapsed; silence proves no absence.
    Deadline,
    /// Explicit cancellation settled; fresh work requires a separate task.
    Cancelled,
}
/// Historical facts and current authenticated runtime progress remain separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    /// Last historical runtime summary when this run began.
    pub historical: Counts,
    /// Complete raw observations admitted to the original WAL.
    pub recorded_observations: usize,
    /// Original observations revalidated and aggregated in this invocation.
    pub replayed_observations: usize,
    /// Raw observations newly recorded during this invocation.
    pub new_observations: usize,
    /// Current result records, including mandatory-pending matches.
    pub results: usize,
    /// Currently revalidated results satisfying all mandatory terms.
    pub visible_results: usize,
    /// Current query graph size, not a count of connected peers or MQs.
    pub queries: usize,
    /// Results becoming visible during live work; historical replay is excluded.
    pub new_visible_results: usize,
    /// Complete original WAL record count.
    pub state_records: usize,
}
/// Borrowed current-run events. Historical results do not claim current freshness
/// or availability; their original signed source is revalidated before emission.
pub enum Event<'a> {
    /// A bounded control checkpoint; no result is inferred.
    Tick,
    /// One fully revalidated historical visible result.
    Restored {
        /// Local identifier scoped to this reconstructed Session.
        result: ResultId,
        /// Actual reconstructed result and metadata.
        record: &'a ResultRecord,
        /// Actual namespace source, when present.
        query: Option<QueryInfo<'a>>,
        /// Actual followed namespace update query, when present.
        continuation: Option<QueryInfo<'a>>,
    },
    /// Actual native or high-level live Session step.
    Live {
        /// Original step, including real refusals or partial mandatory results.
        step: &'a Step,
        /// Corresponding actual aggregate record, when present.
        record: Option<&'a ResultRecord>,
        /// Actual query source, when available.
        query: Option<QueryInfo<'a>>,
        /// Actual followed update, when present.
        continuation: Option<QueryInfo<'a>>,
    },
}
/// One actual terminal query error. Other queries may continue independently.
#[derive(Debug)]
pub struct QueryFailure {
    /// Original runtime-local query coordinate.
    pub query: QueryId,
    /// Original native error; not reconstructed from a display string.
    pub cause: ipc::Error,
}
/// Settled result after original native retirement and the state barrier.
#[derive(Debug)]
pub struct Outcome {
    /// Why caller observation ended, never whole-network completion.
    pub reason: StopReason,
    /// Historical and current-run facts.
    pub progress: Progress,
    /// Actual independently failed query owners during this run.
    pub query_failures: Vec<QueryFailure>,
    /// Original native/shared deadline observation, if it produced the stop.
    pub deadline_observation: Option<super::Error>,
}
/// Original task refusal, without changing storage or native certainty.
#[derive(Debug)]
pub enum Cause {
    /// Original WAL stage/certainty and native cause.
    Storage(store::Error),
    /// Strict local model or immutable binding refusal.
    Model(ModelError),
    /// Original live or replay authentication/aggregate failure.
    Search(super::Error),
    /// Original clock, checked representation or caller limit refusal.
    Protocol(ProtocolError),
    /// A local ownership or lifecycle precondition refused.
    State(&'static str),
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Model(e) => e.fmt(f),
            Self::Search(e) => e.fmt(f),
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
            Self::Search(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::State(_) => None,
        }
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
impl From<super::Error> for Cause {
    fn from(e: super::Error) -> Self {
        Self::Search(e)
    }
}
impl From<ProtocolError> for Cause {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
/// Original run failure with independent native retirement and state-write errors.
#[derive(Debug)]
pub struct Failure {
    /// Original operation refusal; absent when only retirement failed.
    pub cause: Option<Cause>,
    /// Independent original native retirement failure.
    pub cleanup: Option<super::Error>,
    /// Independent failure recording the terminal task state.
    pub state_failure: Option<Cause>,
    /// Exact known historical/current progress even when a later barrier failed.
    pub progress: Progress,
    /// Actual independently failed query owners.
    pub query_failures: Vec<QueryFailure>,
    /// Requested stop; its presence does not assert durable settled state.
    pub requested_stop: Option<StopReason>,
    /// Original deadline observation even if retirement or state recording failed.
    pub deadline_observation: Option<super::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FS search task failed")?;
        if let Some(e) = &self.cause {
            write!(f, ": {e}")?;
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
                self.cleanup
                    .as_ref()
                    .map(|e| e as &(dyn std::error::Error + 'static))
            })
            .or_else(|| {
                self.state_failure
                    .as_ref()
                    .map(|e| e as &(dyn std::error::Error + 'static))
            })
    }
}
/// Cheap historical status; inspecting starts no sockets or authentication work.
#[derive(Clone, Copy, Debug)]
pub struct Status {
    /// Original durable lifecycle phase.
    pub phase: Phase,
    /// This object currently owns an executing future.
    pub active: bool,
    /// Running/requested history remains without a settled original outcome.
    pub interrupted: bool,
    /// Original complete raw observation records, including unaggregated tails.
    pub recorded_observations: usize,
    /// Last historical summary; no current verification is implied.
    pub historical: Counts,
    /// Complete original record count.
    pub state_records: usize,
    /// An uncertain original write prevents further appends on this owner.
    pub fenced: bool,
}
/// One exclusive persistent search owner. Its mutable run borrow prevents another
/// writer or control callback from mutating the same task concurrently.
pub struct Task {
    store: Store,
    state: model::State,
    active: bool,
}
impl Task {
    #[cfg(feature = "network")]
    pub(crate) fn directory_identity(&self) -> std::io::Result<crate::FileIdentity> {
        crate::FileIdentity::of(self.store.directory())
    }
    /// Persist immutable KSK/SKS inputs. No search query or runtime is started.
    pub fn create(
        path: impl AsRef<Path>,
        query: Uri<'_>,
        mut options: Options,
        limits: Limits,
    ) -> Result<Self, Box<Failure>> {
        let result = (|| -> Result<Self, Cause> {
            options.deadline = AbsoluteTime::from_micros(0);
            let length = query.encoded_len()?;
            if length > codec::MAX_URI_BYTES {
                return Err(ModelError::Limit.into());
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| ProtocolError::Capacity)?;
            bytes.resize(length, 0);
            query.encode(&mut bytes)?;
            let manifest = Manifest {
                query_uri: bytes,
                options,
                max_observations: limits.max_observations,
            };
            manifest.validate()?;
            let mut store = Store::create(path, limits.storage)?;
            let (kind, body) = codec::encode_event(&model::Event::Manifest(manifest))?;
            store.append(kind, &body)?;
            let state = model::State::load(&mut store)?;
            Ok(Self {
                store,
                state,
                active: false,
            })
        })();
        result.map_err(empty_failure)
    }
    /// Lock and structurally load history. Actual result authentication requires run.
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
    /// Immutable original inputs and numeric policy.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.state.manifest
    }
    /// Original random physical journal identity.
    #[must_use]
    pub fn task_id(&self) -> &[u8; 32] {
        self.store.task_id()
    }
    /// Inspect known historical facts only.
    #[must_use]
    pub fn status(&self) -> Status {
        Status {
            phase: self.state.phase,
            active: self.active,
            interrupted: !self.active
                && matches!(
                    self.state.phase,
                    Phase::Running | Phase::PauseRequested | Phase::CancelRequested
                ),
            recorded_observations: self.state.observations.len(),
            historical: self.state.counts,
            state_records: self.store.record_count(),
            fenced: self.store.fenced(),
        }
    }
    /// Persist local cancellation intent; completed historical results remain intact.
    pub fn request_cancel(&mut self) -> Result<(), Cause> {
        if self.active {
            return Err(Cause::State("search task already running"));
        }
        if matches!(self.state.phase, Phase::CancelRequested | Phase::Cancelled) {
            return Ok(());
        }
        let counts = self.state.counts;
        append(
            &mut self.store,
            &mut self.state,
            model::Event::Phase {
                phase: Phase::CancelRequested,
                counts,
            },
        )
    }
    /// Settle idle cancellation without opening any query. The exclusive lock and
    /// mutable borrow exclude a previous active runtime owned by this task.
    pub fn settle_cancel(&mut self) -> Result<Outcome, Box<Failure>> {
        if self.active || self.state.phase != Phase::CancelRequested {
            return Err(self.fail(Cause::State("idle cancellation requires CancelRequested")));
        }
        let progress = historical_progress(&self.store, &self.state);
        let counts = self.state.counts;
        append(
            &mut self.store,
            &mut self.state,
            model::Event::Phase {
                phase: Phase::Cancelled,
                counts,
            },
        )
        .map_err(|cause| {
            Box::new(Failure {
                cause: Some(cause),
                cleanup: None,
                state_failure: None,
                progress,
                query_failures: Vec::new(),
                requested_stop: Some(StopReason::Cancelled),
                deadline_observation: None,
            })
        })?;
        Ok(Outcome {
            reason: StopReason::Cancelled,
            progress: historical_progress(&self.store, &self.state),
            query_failures: Vec::new(),
            deadline_observation: None,
        })
    }
    fn fail(&self, cause: Cause) -> Box<Failure> {
        Box::new(Failure {
            cause: Some(cause),
            cleanup: None,
            state_failure: None,
            progress: historical_progress(&self.store, &self.state),
            query_failures: Vec::new(),
            requested_stop: None,
            deadline_observation: None,
        })
    }
    /// Revalidate original observations and continue actual native searches with
    /// a new finite deadline. Control zero-work pause precedes historical replay.
    /// Dropping this future retires its owned Session but writes no settled phase.
    pub async fn run(
        &mut self,
        source: ipc::EndpointSource,
        deadline: AbsoluteTime,
        control: impl FnMut(Progress, Event<'_>) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        if self.active || matches!(self.state.phase, Phase::Cancelled | Phase::CancelRequested) {
            return Err(self.fail(Cause::State("search cancellation cannot resume fresh work")));
        }
        if deadline.as_micros() == u64::MAX {
            return Err(self.fail(ProtocolError::InvalidInput.into()));
        }
        let counts = self.state.counts;
        let progress = historical_progress(&self.store, &self.state);
        append(
            &mut self.store,
            &mut self.state,
            model::Event::Phase {
                phase: Phase::Running,
                counts,
            },
        )
        .map_err(|cause| {
            Box::new(Failure {
                cause: Some(cause),
                cleanup: None,
                state_failure: None,
                progress,
                query_failures: Vec::new(),
                requested_stop: None,
                deadline_observation: None,
            })
        })?;
        self.active = true;
        let mut run = runner::Run {
            attempted_stop: None,
            store: &mut self.store,
            state: &mut self.state,
            active: &mut self.active,
        };
        run.drive(source, deadline, control).await
    }
}
fn append(
    store: &mut Store,
    state: &mut model::State,
    event: model::Event<'_>,
) -> Result<(), Cause> {
    if state.applied() != store.record_count() as u64 {
        return Err(Cause::State("unapplied original search task prefix"));
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
fn historical_progress(store: &Store, state: &model::State) -> Progress {
    Progress {
        historical: state.counts,
        recorded_observations: state.observations.len(),
        state_records: store.record_count(),
        ..Progress::default()
    }
}
fn empty_failure(cause: Cause) -> Box<Failure> {
    Box::new(Failure {
        cause: Some(cause),
        cleanup: None,
        state_failure: None,
        progress: Progress::default(),
        query_failures: Vec::new(),
        requested_stop: None,
        deadline_observation: None,
    })
}
