//! Execute the original typed task owners, never projected catalog success.
//!
//! Registration is local scheduling intent. Every admission reopens the actual
//! locked task, compares its random identity and original physical directory,
//! and keeps all original mutation certainty and native/state failures intact.

use super::{Blocked, Error, Execution, State, Stop, catalog};
use crate::{
    Buffers, FileIdentity, OutputDir, Repository,
    durable::{self, store},
    namespace::graph::{Graph, Limits as GraphLimits},
    network::probe,
    probe_task, publication, search, unindex_task,
};
use catalog::{Directory, Kind, Policy, Registration};
use gnunet_client_host::EndpointSource;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    sync::Arc,
};

pub(crate) enum Run {
    Skipped {
        reason: Blocked,
        state: State,
    },
    Finished {
        execution: Box<Execution>,
        after: Option<State>,
        state_error: Option<durable::Cause>,
    },
}

enum Owner {
    Download(Box<durable::Task>),
    Search(Box<search::task::Task>),
    Publication(Box<publication::Task>),
    Probe(Box<probe_task::Task>),
    Unindex(Box<unindex_task::Task>),
}
impl Owner {
    fn id(&self) -> Result<[u8; 32], Error> {
        match self {
            Self::Download(task) => task
                .task_id()
                .map_err(|cause| Error::DownloadState(Box::new(cause))),
            Self::Search(task) => Ok(*task.task_id()),
            Self::Publication(task) => Ok(*task.task_id()),
            Self::Probe(task) => Ok(*task.task_id()),
            Self::Unindex(task) => Ok(*task.task_id()),
        }
    }
    fn directory_identity(&self) -> Result<FileIdentity, Error> {
        match self {
            Self::Download(task) => task.directory_identity(),
            Self::Search(task) => task.directory_identity(),
            Self::Publication(task) => task.directory_identity(),
            Self::Probe(task) => task.directory_identity(),
            Self::Unindex(task) => task.directory_identity(),
        }
        .map_err(Error::Io)
    }
    fn status(&self) -> Result<State, durable::Cause> {
        match self {
            Self::Download(task) => task.status().map(State::Download),
            Self::Search(task) => Ok(State::Search(task.status())),
            Self::Publication(task) => Ok(State::Publication(Box::new(task.status()))),
            Self::Probe(task) => Ok(State::Probe(Box::new(task.status()))),
            Self::Unindex(task) => Ok(State::Unindex(task.status())),
        }
    }
}

fn shape(kind: Kind, output_parent: bool, cache: bool, graph: bool) -> Result<(), Error> {
    let valid = match kind {
        Kind::Download => output_parent && cache && !graph,
        Kind::Search | Kind::Probe | Kind::Unindex => !output_parent && !cache && !graph,
        Kind::Publication => !output_parent && !cache,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Protocol(ProtocolError::InvalidInput))
    }
}
fn same_directory(directory: &Directory, actual: FileIdentity) -> Result<(), Error> {
    if directory.identity() == actual {
        Ok(())
    } else {
        Err(Error::Catalog(catalog::Error::Authority))
    }
}
fn open(kind: Kind, directory: &Directory, storage: store::Limits) -> Result<Owner, Error> {
    // The registered open checks its actual root descriptor before reading,
    // repairing or syncing a WAL. The later descriptor comparison stays
    // explicit; an earlier path stat never authorizes a different opened task.
    directory.revalidate().map_err(Error::Catalog)?;
    let owner = match kind {
        Kind::Download => Owner::Download(Box::new(
            durable::Task::open_registered(directory.path(), storage, directory.identity())
                .map_err(Error::Download)?,
        )),
        Kind::Search => Owner::Search(Box::new(
            search::task::Task::open_registered(directory.path(), storage, directory.identity())
                .map_err(Error::Search)?,
        )),
        Kind::Publication => Owner::Publication(Box::new(
            publication::Task::open_registered(directory.path(), storage, directory.identity())
                .map_err(Error::Publication)?,
        )),
        Kind::Unindex => Owner::Unindex(Box::new(
            unindex_task::Task::open_registered(directory.path(), storage, directory.identity())
                .map_err(Error::Unindex)?,
        )),
        Kind::Probe => Owner::Probe(Box::new(
            probe_task::Task::open_registered(
                directory.path(),
                probe_task::Limits {
                    storage,
                    max_attempts: u32::MAX,
                    max_trials: i32::MAX as u32,
                    max_history_bytes: u64::MAX,
                },
                directory.identity(),
            )
            .map_err(Error::Probe)?,
        )),
    };
    same_directory(directory, owner.directory_identity()?)?;
    Ok(owner)
}

fn graph(
    task: &publication::Task,
    directory: Option<&Directory>,
    storage: store::Limits,
) -> Result<Option<Graph>, Error> {
    match (task.manifest().graph, directory) {
        (Some(target), Some(directory)) => {
            directory.revalidate().map_err(Error::Catalog)?;
            let graph = Graph::open_registered(
                directory.path(),
                target.binding.namespace,
                GraphLimits::default(),
                storage,
                directory.identity(),
            )
            .map_err(Error::Graph)?;
            same_directory(directory, graph.directory_identity().map_err(Error::Io)?)?;
            if graph.binding() != target.binding {
                return Err(Error::Protocol(ProtocolError::Conflict));
            }
            Ok(Some(graph))
        }
        (None, None) => Ok(None),
        _ => Err(Error::Protocol(ProtocolError::InvalidInput)),
    }
}

/// Bind explicit existing typed task/configuration without starting a native
/// operation or authorizing a retry. The physical descriptor and random task
/// identity are read from the actual task owner before recording its path.
pub fn bind(
    kind: Kind,
    path: &Path,
    output_parent: Option<&Path>,
    cache: Option<&Path>,
    graph_path: Option<&Path>,
    policy: Policy,
    storage: store::Limits,
) -> Result<Registration, Error> {
    policy.validate().map_err(Error::Catalog)?;
    shape(
        kind,
        output_parent.is_some(),
        cache.is_some(),
        graph_path.is_some(),
    )?;
    let task = Directory::capture(path).map_err(Error::Catalog)?;
    let owner = open(kind, &task, storage)?;
    let registration = Registration {
        task_id: owner.id()?,
        kind,
        task,
        output_parent: output_parent
            .map(Directory::capture)
            .transpose()
            .map_err(Error::Catalog)?,
        cache: cache
            .map(Directory::capture)
            .transpose()
            .map_err(Error::Catalog)?,
        graph: graph_path
            .map(Directory::capture)
            .transpose()
            .map_err(Error::Catalog)?,
        policy,
    };
    if let Owner::Publication(task) = &owner {
        drop(graph(task, registration.graph.as_ref(), storage)?);
    }
    Ok(registration)
}

pub(super) fn blocked(state: &State) -> Option<Blocked> {
    match state {
        State::Download(status) => {
            if status.active {
                Some(Blocked::Active)
            } else if status.fenced {
                Some(Blocked::Fenced)
            } else if matches!(
                status.phase,
                durable::Phase::Cancelled | durable::Phase::CancelRequested
            ) {
                Some(Blocked::Cancelled)
            } else if status.phase == durable::Phase::Complete {
                Some(Blocked::Complete)
            } else {
                // Original commit intents and cleanup debt are reconciled by
                // durable::Task::run, never guessed safe or discarded here.
                None
            }
        }
        State::Search(status) => {
            if status.active {
                Some(Blocked::Active)
            } else if status.fenced {
                Some(Blocked::Fenced)
            } else if matches!(
                status.phase,
                search::task::Phase::Cancelled | search::task::Phase::CancelRequested
            ) {
                Some(Blocked::Cancelled)
            } else {
                None
            }
        }
        State::Probe(status) => {
            if status.active {
                Some(Blocked::Active)
            } else if status.fenced {
                Some(Blocked::Fenced)
            } else if status.phase == probe_task::Phase::Cancelled {
                Some(Blocked::Cancelled)
            } else if status.pending.is_some() {
                // An old read-only intent is not a completed trial. Generic
                // scheduling never silently abandons it or invents an outcome.
                Some(Blocked::Interrupted)
            } else if status.phase == probe_task::Phase::Exhausted {
                Some(Blocked::Exhausted)
            } else {
                None
            }
        }
        State::Unindex(status) => {
            if status.active {
                Some(Blocked::Active)
            } else if status.fenced {
                Some(Blocked::Fenced)
            } else if status.phase == unindex_task::Phase::Cancelled {
                Some(Blocked::Cancelled)
            } else if status.phase == unindex_task::Phase::Complete {
                Some(Blocked::Complete)
            } else if status.pending.is_some() {
                Some(Blocked::PendingMutation)
            } else if matches!(
                status.phase,
                unindex_task::Phase::Ready
                    | unindex_task::Phase::Paused
                    | unindex_task::Phase::Interrupted
            ) {
                // Every destructive request has a durable intent before native
                // admission. An interrupted owner with no pending intent has
                // no unresolved mutation to replay; this is a fresh run.
                None
            } else {
                Some(Blocked::Interrupted)
            }
        }
        State::Publication(status) => {
            if status.active {
                Some(Blocked::Active)
            } else if status.fenced {
                Some(Blocked::Fenced)
            } else if matches!(
                status.phase,
                publication::Phase::Cancelled | publication::Phase::CancelRequested
            ) || matches!(
                status.requested,
                Some(publication::Phase::Cancelled | publication::Phase::CancelRequested)
            ) {
                Some(Blocked::Cancelled)
            } else if status.phase == publication::Phase::Complete {
                Some(Blocked::Complete)
            } else if status.pending.is_some()
                || status.indexes.pending.is_some()
                || status.uncertain
                || status.requires_explicit_retry
            {
                Some(Blocked::PendingMutation)
            } else {
                None
            }
        }
    }
}
fn deadline(source: &EndpointSource, slice_us: u64) -> Result<AbsoluteTime, Error> {
    let now = source.clock().sample().map_err(Error::Protocol)?.now;
    let end = now
        .as_micros()
        .checked_add(slice_us)
        .ok_or(Error::Protocol(ProtocolError::Overflow))?;
    if end == u64::MAX {
        return Err(Error::Protocol(ProtocolError::InvalidInput));
    }
    Ok(AbsoluteTime::from_micros(end))
}
struct LeafEntropy {
    file: File,
    cause: Option<io::Error>,
}
impl gnunet_crypto::Entropy for LeafEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), ProtocolError> {
        match self.file.read_exact(output) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.cause = Some(cause);
                Err(ProtocolError::Entropy)
            }
        }
    }
}
fn select_leaf(content: gnunet_fs::Content) -> Result<u64, Error> {
    // No entropy descriptor is needed when only the actual leaf0 exists.
    if gnunet_fs::content::Layout::new(content.size).leaf_count() == 1 {
        return Ok(0);
    }
    let mut entropy = LeafEntropy {
        file: File::open("/dev/urandom").map_err(Error::Io)?,
        cause: None,
    };
    probe::sample_leaf(content, &mut entropy)
        .map_err(|cause| entropy.cause.map_or(Error::Protocol(cause), Error::Io))
}
fn not_started(error: Error) -> Run {
    Run::Finished {
        execution: Box::new(Execution::NotStarted(error)),
        after: None,
        state_error: None,
    }
}

pub(crate) async fn run(
    registration: Registration,
    storage: store::Limits,
    fs: EndpointSource,
    ds: EndpointSource,
    stop: Stop,
) -> Run {
    if let Err(error) = registration
        .policy
        .validate()
        .map_err(Error::Catalog)
        .and_then(|()| {
            shape(
                registration.kind,
                registration.output_parent.is_some(),
                registration.cache.is_some(),
                registration.graph.is_some(),
            )
        })
    {
        return not_started(error);
    }
    let mut owner = match open(registration.kind, &registration.task, storage) {
        Ok(owner) => owner,
        Err(error) => return not_started(error),
    };
    match owner.id() {
        Ok(id) if id == registration.task_id => {}
        Ok(_) => return not_started(Error::Protocol(ProtocolError::Conflict)),
        Err(error) => return not_started(error),
    }
    let state = match owner.status() {
        Ok(state) => state,
        Err(cause) => return not_started(Error::DownloadState(Box::new(cause))),
    };
    if let Some(reason) = blocked(&state) {
        return Run::Skipped { reason, state };
    }
    let quota = registration.policy.quota;
    let execution = match &mut owner {
        Owner::Download(task) => {
            let setup = (|| -> Result<(Repository, AbsoluteTime), Error> {
                let parent = registration
                    .output_parent
                    .as_ref()
                    .ok_or(Error::Protocol(ProtocolError::InvalidInput))?;
                let cache = registration
                    .cache
                    .as_ref()
                    .ok_or(Error::Protocol(ProtocolError::InvalidInput))?;
                let mut parent = OutputDir::from_directory(parent.open().map_err(Error::Catalog)?)
                    .map_err(Error::Local)?;
                let cache = Repository::from_directory(cache.open().map_err(Error::Catalog)?)
                    .map_err(Error::Local)?;
                task.attach(&mut parent).map_err(Error::Download)?;
                Ok((cache, deadline(&fs, registration.policy.slice_us)?))
            })();
            match setup {
                Ok((mut cache, deadline)) => {
                    let mut buffers = Buffers::new();
                    Execution::Download(
                        task.run(fs, &mut buffers, &mut cache, deadline, |progress| {
                            if stop.is_requested()
                                || quota.is_some_and(|maximum| progress.new_files >= maximum)
                            {
                                durable::TaskControl::Pause
                            } else {
                                durable::TaskControl::Continue
                            }
                        })
                        .await
                        .map(Box::new),
                    )
                }
                Err(error) => Execution::NotStarted(error),
            }
        }
        Owner::Search(task) => match deadline(&fs, registration.policy.slice_us) {
            Ok(deadline) => Execution::Search(
                task.run(fs, deadline, |progress, _event| {
                    if stop.is_requested()
                        || quota.is_some_and(|maximum| progress.new_visible_results >= maximum)
                    {
                        search::task::Control::Pause
                    } else {
                        search::task::Control::Continue
                    }
                })
                .await,
            ),
            Err(error) => Execution::NotStarted(error),
        },
        Owner::Probe(task) => {
            let setup = (|| -> Result<(u64, AbsoluteTime), Error> {
                let content = task
                    .manifest()
                    .content()
                    .map_err(|cause| Error::ProbeState(Box::new(cause)))?;
                let leaf = select_leaf(content)?;
                Ok((leaf, deadline(&fs, registration.policy.slice_us)?))
            })();
            match setup {
                Ok((leaf, deadline)) => {
                    let mut buffers = Buffers::new();
                    // One run admits exactly one selected observation, already
                    // within any positive per-run quota. Only the original task
                    // can record intent/terminal state or abandon interruption.
                    Execution::Probe(
                        task.run(fs, &mut buffers, leaf, deadline, |_| {
                            if stop.is_requested() {
                                probe_task::Control::Pause
                            } else {
                                probe_task::Control::Continue
                            }
                        })
                        .await
                        .map(Box::new),
                    )
                }
                Err(error) => Execution::NotStarted(error),
            }
        }
        Owner::Unindex(task) => {
            let setup = (|| -> Result<(Vec<u8>, AbsoluteTime, tokio::time::Instant), Error> {
                if !Arc::ptr_eq(&fs.clock(), &ds.clock()) {
                    return Err(Error::Protocol(ProtocolError::InvalidInput));
                }
                let hard = tokio::time::Instant::now()
                    .checked_add(std::time::Duration::from_micros(
                        registration.policy.slice_us,
                    ))
                    .ok_or(Error::Protocol(ProtocolError::Overflow))?;
                let deadline = deadline(&fs, registration.policy.slice_us)?;
                let mut request = Vec::new();
                request
                    .try_reserve_exact(65535)
                    .map_err(|_| Error::Protocol(ProtocolError::Capacity))?;
                request.resize(65535, 0);
                Ok((request, deadline, hard))
            })();
            match setup {
                Err(error) => Execution::NotStarted(error),
                Ok((mut request, deadline, hard)) => {
                    use gnunet_datastore_host as protocol;
                    let mut instance = protocol::Instance::new();
                    let mut slots = [protocol::Slot::new(&mut request)];
                    let mut reservations = [];
                    let client = protocol::ProtocolClient::new(
                        &mut instance,
                        &mut slots,
                        &mut reservations,
                        protocol::ProtocolLimits {
                            max_pending: 1,
                            max_lifetime: gnunet_types::Duration(registration.policy.slice_us),
                            ..protocol::ProtocolLimits::default()
                        },
                    );
                    match client {
                        Err(error) => Execution::NotStarted(Error::Protocol(error)),
                        Ok(client) => match gnunet_datastore_host::Client::new(
                            client,
                            ds,
                            gnunet_datastore_host::Limits {
                                reply_frames: 1,
                                reply_bytes: 65535,
                                ..gnunet_datastore_host::Limits::default()
                            },
                        ) {
                            Err(error) => Execution::NotStarted(Error::Transport(error)),
                            Ok(client) => {
                                let mut buffers = Buffers::new();
                                Execution::Unindex(
                                    task.run(
                                        &mut buffers,
                                        fs,
                                        client,
                                        deadline,
                                        hard,
                                        |observation| {
                                            // Historical receipt reuse earns no current quota.
                                            let replies = observation
                                                .content_positive
                                                .saturating_add(observation.content_zero)
                                                .saturating_add(observation.keyword_positive)
                                                .saturating_add(observation.keyword_zero);
                                            let quota_reached =
                                                quota.is_some_and(|maximum| match usize::try_from(
                                                    replies,
                                                ) {
                                                    Ok(replies) => replies >= maximum,
                                                    Err(_) => true,
                                                });
                                            if stop.is_requested() || quota_reached {
                                                unindex_task::Control::Pause
                                            } else {
                                                unindex_task::Control::Continue
                                            }
                                        },
                                    )
                                    .await
                                    .map(Box::new),
                                )
                            }
                        },
                    }
                }
            }
        }
        Owner::Publication(task) => {
            let setup = (|| -> Result<(Option<Graph>, AbsoluteTime), Error> {
                if !Arc::ptr_eq(&fs.clock(), &ds.clock()) {
                    return Err(Error::Protocol(ProtocolError::InvalidInput));
                }
                let graph = graph(task, registration.graph.as_ref(), storage)?;
                Ok((graph, deadline(&fs, registration.policy.slice_us)?))
            })();
            match setup {
                Ok((mut graph, deadline)) => {
                    let mut buffers = Buffers::new();
                    let control = |progress: publication::Progress| {
                        if stop.is_requested()
                            || quota
                                .is_some_and(|maximum| progress.new_accepted.accepted >= maximum)
                        {
                            publication::Control::Pause
                        } else {
                            publication::Control::Continue
                        }
                    };
                    let actual = if let Some(graph) = &mut graph {
                        task.run_managed(ds, graph, &mut buffers, deadline, control)
                            .await
                    } else if !task.manifest().plan.index_sources().is_empty() {
                        task.run_indexed(fs, ds, &mut buffers, deadline, control)
                            .await
                    } else {
                        task.run(ds, &mut buffers, deadline, control).await
                    };
                    Execution::Publication(actual.map(Box::new))
                }
                Err(error) => Execution::NotStarted(error),
            }
        }
    };
    let (after, state_error) = match owner.status() {
        Ok(state) => (Some(state), None),
        Err(cause) => (None, Some(cause)),
    };
    Run::Finished {
        execution: Box::new(execution),
        after,
        state_error,
    }
}
