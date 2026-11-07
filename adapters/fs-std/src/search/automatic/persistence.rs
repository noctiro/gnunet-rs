//! Original result-context bindings and durable observations of the same causal
//! native run used by Session accounting. Stored history never mints Observed.
use super::{Policy, Stop};
use crate::{
    Buffers, Control,
    durable::store::{self, Store},
    ipc,
    network::{self, DownloadOptions},
    probe_task,
    search::{OwnerStamp, ResultId, Session, probe},
};
use gnunet_crypto::Hash512State;
use gnunet_fs::Uri;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::{collections::HashMap, ffi::OsString, fmt, fs, path::Path};

const MANIFEST: u16 = 0x5200;
const REGISTER: u16 = 0x5201;
const MAGIC: &[u8] = b"FS-AUTO-PROBE-SET-1";

/// Original local persistence/setup error, independent of the native result.
#[derive(Debug)]
pub enum Error {
    /// Original set-journal failure and its append certainty.
    Storage(store::Error),
    /// Original individual probe task open/create failure.
    Task(Box<probe_task::Failure>),
    /// Original individual probe state/transcript refusal.
    Cause(probe_task::Cause),
    /// Checked resource, representation or immutable context refusal.
    Protocol(ProtocolError),
    /// Original directory metadata failure.
    Io(std::io::Error),
    /// This target's original lifetime bound was already reached.
    Exhausted(Box<probe_task::Status>),
    /// Original cancellation prevents fresh automatic work.
    Cancelled(Box<probe_task::Status>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Task(e) => e.fmt(f),
            Self::Cause(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Exhausted(_) => f.write_str("persistent probe observation budget exhausted"),
            Self::Cancelled(_) => f.write_str("persistent probe task was cancelled"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Task(e) => Some(e),
            Self::Cause(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Exhausted(_) | Self::Cancelled(_) => None,
        }
    }
}
impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<probe_task::Cause> for Error {
    fn from(e: probe_task::Cause) -> Self {
        Self::Cause(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// An exclusive bounded observation set. Children are selected by immutable
/// search-context hashes and opened beneath its original directory FD. The set
/// tracks original task identities; it stores no fresh success or absence fact.
pub struct Persistence {
    store: Store,
    tasks: HashMap<[u8; 64], [u8; 32]>,
    limits: probe_task::Limits,
    max_tasks: usize,
    context: Option<(OwnerStamp, [u8; 64])>,
}
impl Persistence {
    /// Create or reopen an explicitly selected private set, with at most1024
    /// original target contexts. Probe-task lifetime limits remain independent.
    pub fn open(path: impl AsRef<Path>, limits: probe_task::Limits) -> Result<Self, Error> {
        Self::open_with_limit(path, limits, 1024)
    }
    /// Set an explicit target-context cap. Opening validates set metadata only;
    /// each original child history is authenticated before its fresh admission.
    pub fn open_with_limit(
        path: impl AsRef<Path>,
        limits: probe_task::Limits,
        max_tasks: usize,
    ) -> Result<Self, Error> {
        if max_tasks == 0 {
            return Err(ProtocolError::InvalidInput.into());
        }
        let path = path.as_ref();
        let mut store = match fs::symlink_metadata(path) {
            Ok(_) => Store::open(path, limits.storage)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut store = Store::create(path, limits.storage)?;
                store.append(MANIFEST, MAGIC)?;
                store
            }
            Err(error) => return Err(error.into()),
        };
        let first = store.read_record(0)?.ok_or(ProtocolError::Malformed)?;
        if first.kind != MANIFEST || first.bytes != MAGIC {
            return Err(ProtocolError::Malformed.into());
        }
        let count = store.record_count();
        if count.saturating_sub(1) > max_tasks {
            return Err(ProtocolError::Capacity.into());
        }
        let mut tasks = HashMap::new();
        tasks
            .try_reserve(count.saturating_sub(1))
            .map_err(|_| ProtocolError::Capacity)?;
        for index in 1..count {
            let row = store.read_record(index)?.ok_or(ProtocolError::Malformed)?;
            if row.kind != REGISTER || row.bytes.len() != 96 {
                return Err(ProtocolError::Malformed.into());
            }
            let origin: [u8; 64] = row.bytes[..64]
                .try_into()
                .map_err(|_| ProtocolError::Malformed)?;
            let id: [u8; 32] = row.bytes[64..]
                .try_into()
                .map_err(|_| ProtocolError::Malformed)?;
            if tasks.insert(origin, id).is_some() {
                return Err(ProtocolError::Malformed.into());
            }
        }
        // Keep the original exclusive store/FD. No second path lookup or
        // automatic adoption of arbitrary journals is performed on discovery.
        Ok(Self {
            store,
            tasks,
            limits,
            max_tasks,
            context: None,
        })
    }
    /// Number of original registered contexts, not live peers or fresh results.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }
    /// Whether no original context has been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    /// Reconcile only a private original recording receipt, without opening any
    /// service source or making a new native observation. Current Session counts
    /// are independent and are not replayed or restored by this operation.
    pub fn reconcile(&mut self, outcome: &Outcome) -> Result<probe_task::Status, Error> {
        if outcome.set_id != *self.store.task_id()
            || self.tasks.get(&outcome.origin) != Some(&outcome.task_id)
        {
            return Err(ProtocolError::Stale.into());
        }
        let receipt = outcome.receipt.as_ref().ok_or(ProtocolError::NotReady)?;
        let mut task =
            probe_task::Task::open_at(self.store.directory(), &name(outcome.origin), self.limits)
                .map_err(Error::Task)?;
        if task.task_id() != &outcome.task_id || task.manifest().origin != Some(outcome.origin) {
            return Err(ProtocolError::Conflict.into());
        }
        receipt.record(&mut task).map_err(Error::Cause)
    }
}

/// Original durable result of one actual current native run. The native proof
/// is separately retained by the original Session Completion/Report.
#[derive(Debug)]
pub struct Outcome {
    set_id: [u8; 32],
    /// Stable opaque original query/target/revision context, never a wire field.
    pub origin: [u8; 64],
    /// Original random child task identity.
    pub task_id: [u8; 32],
    /// Original immutable recording receipt, retained across a local WAL failure.
    pub receipt: Option<probe_task::Receipt>,
    /// Historical status after this original settlement attempt.
    pub status: Option<probe_task::Status>,
    /// Independent original persistence error. It cannot erase the native proof.
    pub cause: Option<probe_task::Cause>,
}
impl Outcome {
    /// Whether this locally recorded safe observation may use caller repeat
    /// policy. Exhaustion, cancellation and persistence failure stop this target.
    #[must_use]
    pub fn repeatable(&self) -> bool {
        self.cause.is_none()
            && self
                .status
                .as_ref()
                .is_some_and(|status| status.phase == probe_task::Phase::Paused)
    }
}

pub(super) struct Prepared {
    task: Option<probe_task::Task>,
    origin: [u8; 64],
    set_id: [u8; 32],
}
pub(super) struct Finished {
    pub buffers: Buffers,
    pub run: Run,
}
pub(super) enum Run {
    Executed {
        completion: Box<probe::Completion>,
        persistence: Option<Box<Outcome>>,
    },
    NotStarted {
        ticket: Box<probe::Probe>,
        cause: Error,
    },
}
fn name(origin: [u8; 64]) -> OsString {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(134);
    name.push_str("probe-");
    for byte in origin {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 15) as usize] as char);
    }
    name.into()
}
fn field(hash: &mut Hash512State, bytes: &[u8]) -> Result<(), Error> {
    hash.update(
        &u64::try_from(bytes.len())
            .map_err(|_| ProtocolError::Overflow)?
            .to_be_bytes(),
    );
    hash.update(bytes);
    Ok(())
}
fn context<F, const KNOWN: usize>(session: &Session<'_, F, KNOWN>) -> Result<[u8; 64], Error>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    let mut hash = Hash512State::new();
    hash.update(b"gnunet-rs/fs/probe-context/1");
    hash.update(&session.options.anonymity.to_be_bytes());
    hash.update(&[u8::from(session.options.local_only)]);
    hash.update(
        &u64::try_from(session.initial_queries)
            .map_err(|_| ProtocolError::Overflow)?
            .to_be_bytes(),
    );
    for query in session.queries.iter().take(session.initial_queries) {
        field(&mut hash, &query.spec.label)?;
        match query.spec.namespace {
            Some(namespace) => {
                hash.update(&[1]);
                hash.update(&namespace);
            }
            None => hash.update(&[0]),
        }
        hash.update(
            &u64::try_from(query.spec.mandatory)
                .map_err(|_| ProtocolError::Overflow)?
                .to_be_bytes(),
        );
        hash.update(
            &u64::try_from(query.spec.optional)
                .map_err(|_| ProtocolError::Overflow)?
                .to_be_bytes(),
        );
    }
    Ok(hash.finish())
}
fn options<F, const KNOWN: usize>(
    session: &Session<'_, F, KNOWN>,
    uri: Uri<'_>,
    policy: &Policy,
) -> network::probe::Options
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    let mut transfer = match uri {
        Uri::Location(loc) => DownloadOptions::location(loc, AbsoluteTime::from_micros(0)),
        _ => DownloadOptions::new(AbsoluteTime::from_micros(0)),
    };
    transfer.anonymity = session.options.anonymity;
    transfer.local_only = session.options.local_only;
    transfer.queries_per_connection = policy.native.queries_per_connection;
    transfer.io_slice_bytes = policy.native.io_slice_bytes;
    network::probe::Options {
        transfer,
        max_file_bytes: policy.native.max_file_bytes,
        max_path_blocks: policy.native.max_path_blocks,
        max_encoded_bytes: policy.native.max_encoded_bytes,
    }
}
fn same_options(a: network::probe::Options, b: network::probe::Options) -> bool {
    a.max_file_bytes == b.max_file_bytes
        && a.max_path_blocks == b.max_path_blocks
        && a.max_encoded_bytes == b.max_encoded_bytes
        && a.transfer.anonymity == b.transfer.anonymity
        && a.transfer.local_only == b.transfer.local_only
        && a.transfer.target == b.transfer.target
        && a.transfer.queries_per_connection == b.transfer.queries_per_connection
        && a.transfer.io_slice_bytes == b.transfer.io_slice_bytes
        && a.transfer.limits.max_file_bytes == b.transfer.limits.max_file_bytes
        && a.transfer.limits.max_encoded_bytes == b.transfer.limits.max_encoded_bytes
}
pub(super) fn prepare<F, const KNOWN: usize>(
    persistence: Option<&mut Persistence>,
    session: &Session<'_, F, KNOWN>,
    result: ResultId,
    policy: &Policy,
) -> Result<Prepared, Error>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    let Some(persistence) = persistence else {
        return Ok(Prepared {
            task: None,
            origin: [0; 64],
            set_id: [0; 32],
        });
    };
    if let Some(error) = persistence.store.failure() {
        return Err(Error::Storage(error.clone()));
    }
    let record = session.result(result).ok_or(ProtocolError::Stale)?;
    let uri = record.uri(session.options.block.uri)?;
    if !matches!(uri, Uri::Content(_) | Uri::Location(_)) {
        return Err(ProtocolError::Unsupported.into());
    }
    let root = match persistence.context {
        Some((owner, hash)) if owner == session.owner => hash,
        _ => {
            let hash = context(session)?;
            persistence.context = Some((session.owner, hash));
            hash
        }
    };
    let mut hash = Hash512State::new();
    hash.update(b"gnunet-rs/fs/probe-result/1");
    hash.update(&root);
    field(&mut hash, record.raw_uri())?;
    if let Some(scope) = record.source_namespace_query() {
        let query = session.query(scope).ok_or(ProtocolError::Stale)?;
        hash.update(&[1]);
        hash.update(query.query);
        hash.update(query.namespace);
        field(&mut hash, query.label)?;
    } else {
        hash.update(&[0]);
    }
    let origin = hash.finish();
    let selected = name(origin);
    let expected = options(session, uri, policy);
    let mut task = if let Some(expected_id) = persistence.tasks.get(&origin) {
        let task =
            probe_task::Task::open_at(persistence.store.directory(), &selected, persistence.limits)
                .map_err(Error::Task)?;
        if task.task_id() != expected_id {
            return Err(ProtocolError::Conflict.into());
        }
        task
    } else {
        if persistence.tasks.len() >= persistence.max_tasks {
            return Err(ProtocolError::Capacity.into());
        }
        persistence
            .tasks
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        persistence.store.check_append(96)?;
        let exists = nix::sys::stat::fstatat(
            persistence.store.directory(),
            selected.as_os_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        );
        let task = match exists {
            Ok(_) => {
                let task = probe_task::Task::open_at(
                    persistence.store.directory(),
                    &selected,
                    persistence.limits,
                )
                .map_err(Error::Task)?;
                let status = task.status();
                // An orphan can only come from creation before registration.
                // Never adopt unindexed native history as a new target context.
                if status.phase != probe_task::Phase::Ready || status.historical.attempts() != 0 {
                    return Err(ProtocolError::Conflict.into());
                }
                task
            }
            Err(nix::errno::Errno::ENOENT) => probe_task::Task::create_at(
                persistence.store.directory(),
                &selected,
                uri,
                expected,
                persistence.limits,
                Some(origin),
            )
            .map_err(Error::Task)?,
            Err(error) => return Err(Error::Io(error.into())),
        };
        if task.manifest().origin != Some(origin)
            || task.manifest().uri != record.raw_uri()
            || !same_options(task.manifest().options, expected)
        {
            return Err(ProtocolError::Conflict.into());
        }
        let mut body = [0; 96];
        body[..64].copy_from_slice(&origin);
        body[64..].copy_from_slice(task.task_id());
        persistence.store.append(REGISTER, &body)?;
        persistence.tasks.insert(origin, *task.task_id());
        task
    };
    if task.manifest().origin != Some(origin)
        || task.manifest().uri != record.raw_uri()
        || !same_options(task.manifest().options, expected)
    {
        return Err(ProtocolError::Conflict.into());
    }
    let status = task.status();
    if status.phase == probe_task::Phase::Cancelled {
        return Err(Error::Cancelled(Box::new(status)));
    }
    if status.phase == probe_task::Phase::Exhausted {
        return Err(Error::Exhausted(Box::new(status)));
    }
    if status.pending.is_some() {
        task.abandon_interrupted()?;
    }
    Ok(Prepared {
        task: Some(task),
        origin,
        set_id: *persistence.store.task_id(),
    })
}
pub(super) async fn run(
    mut prepared: Prepared,
    ticket: probe::Probe,
    mut buffers: Buffers,
    stop: Stop,
) -> Finished {
    let Some(task) = prepared.task.as_mut() else {
        let completion = ticket
            .run(&mut buffers, |_| {
                if stop.is_requested() {
                    Control::Cancel
                } else {
                    Control::Continue
                }
            })
            .await;
        return Finished {
            buffers,
            run: Run::Executed {
                completion: Box::new(completion),
                persistence: None,
            },
        };
    };
    let manifest = task.manifest();
    let native = ticket.native_options();
    if manifest.content().ok() != Some(ticket.content()) || !same_options(manifest.options, native)
    {
        return Finished {
            buffers,
            run: Run::NotStarted {
                ticket: Box::new(ticket),
                cause: Error::Protocol(ProtocolError::Conflict),
            },
        };
    }
    let attempt =
        match task.begin_recorded(ticket.source(), ticket.leaf(), native.transfer.deadline) {
            Ok(attempt) => attempt,
            Err(cause) => {
                return Finished {
                    buffers,
                    run: Run::NotStarted {
                        ticket: Box::new(ticket),
                        cause: Error::Cause(cause),
                    },
                };
            }
        };
    let (completion, frames) = ticket
        .run_recorded(&mut buffers, |_| {
            if stop.is_requested() {
                Control::Cancel
            } else {
                Control::Continue
            }
        })
        .await;
    let wanted = if stop.is_requested() {
        probe_task::Control::Pause
    } else {
        probe_task::Control::Continue
    };
    let task_id = *task.task_id();
    let (receipt, status, cause) = match task.finish_recorded(
        attempt,
        completion.observation(),
        &frames,
        wanted,
        &mut buffers,
    ) {
        Ok((receipt, status)) => (Some(receipt), Some(status), None),
        Err(failure) => (failure.receipt, Some(task.status()), Some(failure.cause)),
    };
    let persistence = Some(Box::new(Outcome {
        set_id: prepared.set_id,
        origin: prepared.origin,
        task_id,
        receipt,
        status,
        cause,
    }));
    Finished {
        buffers,
        run: Run::Executed {
            completion: Box::new(completion),
            persistence,
        },
    }
}
