//! Full and indexed D/I publication over real service acknowledgements.
mod index_registration;
use super::{Error, TimeLimit};
use crate::ipc::{self, Received};
use crate::{Buffers, Control, Limits, Progress};
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_crypto::Hash512State;
use gnunet_datastore_host::{Client, Interruption, Loss, Outcome, Reservation, Step, Taken};
use gnunet_fs::client::{Event as IndexEvent, Failure as NativeIndexFailure};
use gnunet_fs::{
    Content,
    content::{FileEncoder, Layout, TAG_BYTES},
};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::{AbsoluteTime, Duration, Error as ProtocolError};
use gnunet_wire::official::datastore::{Data, Request, Response};
pub(crate) use index_registration::{IndexAnswer, controlled as register_index_controlled};
use std::{
    fmt, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt},
};

/// Official caller-selected storage metadata. These are policy values, not
/// protocol defaults; local acceptance does not promise remote replication.
#[derive(Clone, Copy, Debug)]
pub struct BlockOptions {
    /// Exact absolute expiry timestamp sent to DATASTORE.
    pub expiration: AbsoluteTime,
    /// Requested storage priority; duplicate PUT can add to existing priority.
    pub priority: u32,
    /// Official anonymity value, carried unchanged.
    pub anonymity: u32,
    /// Replication score; duplicate PUT can add to an existing score.
    pub replication: u32,
}
/// One full file insertion policy.
#[derive(Clone, Copy, Debug)]
pub struct PublishOptions {
    /// One absolute target in the supplied DATASTORE client's source clock.
    pub deadline: AbsoluteTime,
    /// Caller-selected official block metadata.
    pub blocks: BlockOptions,
    /// File and encoded-tree resource bounds.
    pub limits: Limits,
    /// Request exact connection-bound byte/entry capacity before the first PUT.
    /// A reservation is not an atomic transaction or a replication guarantee.
    pub reserve_space: bool,
}
impl PublishOptions {
    /// Full insertion using no reservation; rid=0 is an official operation.
    #[must_use]
    pub fn new(deadline: AbsoluteTime, blocks: BlockOptions) -> Self {
        Self {
            deadline,
            blocks,
            limits: Limits::default(),
            reserve_space: false,
        }
    }
}

/// Exact refused or uncertain store operation. The original reply is retained
/// without another allocation; a later cleanup failure cannot erase its cause.
pub struct StoreFailure {
    /// Original block query, absent for reservation/release operations.
    pub query: Option<[u8; 64]>,
    /// Actual service status or known local/uncertain outcome.
    pub outcome: Outcome,
    /// Original timeout/cancellation, even if a real reply arrived while draining.
    pub interruption: Option<Interruption>,
    /// Original driving/deadline error, if any.
    pub cause: Option<Box<Error>>,
    /// Independent physical-retirement failure, if one occurred.
    pub retirement_error: Option<gnunet_client_host::ConnectError>,
    frame: Option<OwnedFrame>,
}
impl StoreFailure {
    /// Exact original retained reply bytes, without re-encoding.
    #[must_use]
    pub fn response_bytes(&self) -> Option<&[u8]> {
        self.frame.as_ref().map(OwnedFrame::bytes)
    }
    /// Actual original service reply, including its raw diagnostic when present.
    pub fn response(&self) -> Result<Option<Response<'_>>, ProtocolError> {
        self.frame
            .as_ref()
            .map(|frame| Response::decode(frame.bytes()))
            .transpose()
    }
    pub(super) fn from_taken(
        taken: Taken<'_>,
        query: Option<[u8; 64]>,
        cause: Option<Error>,
    ) -> Self {
        Self {
            query,
            outcome: taken.completion.outcome,
            interruption: taken.completion.interruption,
            cause: cause.map(Box::new),
            retirement_error: None,
            frame: taken.into_frame(),
        }
    }
}
impl fmt::Debug for StoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreFailure")
            .field("query", &self.query)
            .field("outcome", &self.outcome)
            .field("interruption", &self.interruption)
            .field("cause", &self.cause)
            .field("retirement_error", &self.retirement_error)
            .field("reply_bytes", &self.frame.as_ref().map(OwnedFrame::len))
            .finish()
    }
}
impl fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS DATASTORE operation: {:?}", self.outcome)?;
        if let Some(error) = &self.cause {
            write!(f, ": {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for StoreFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_deref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}
/// Every real file PUT, including the root, was acknowledged by the local store.
/// Full mode stores ciphertext; indexed mode stores DBLOCK type6 descriptors.
/// A STATUS of1 cannot distinguish new insertion from an existing block update.
#[derive(Debug)]
pub struct StoredFile {
    /// Actual CHK root and exact declared file length.
    pub content: Content,
    /// Only actually acknowledged blocks and their bytes are counted.
    pub progress: Progress,
    /// Reservation cleanup trouble after known file acceptance. Already accepted
    /// blocks remain accepted; the owned connection is still physically closed.
    pub cleanup: Option<StoreFailure>,
}

/// Current operation admission, not an assertion about other operations on a client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Submission {
    /// No operation ID was created by this execution.
    NotSubmitted,
    /// The original operation was admitted; use its actual outcome for effect certainty.
    Submitted,
}
/// Original execution refusal, retaining operation admission and settlement facts.
#[derive(Debug)]
pub(crate) struct ExecutionFailure {
    pub(crate) submission: Submission,
    pub(crate) cause: Error,
    /// The control callback requested cancellation; this is not a native completion.
    pub(crate) requested_cancel: bool,
    /// Original failure taking the retired operation, if no actual completion was available.
    pub(crate) settlement_error: Option<ConnectError>,
}

pub(crate) struct Answer<'id> {
    pub(crate) taken: Taken<'id>,
    pub(crate) cause: Option<Error>,
    /// Caller intent is independent of the native completion's interruption.
    pub(crate) requested_cancel: bool,
}

pub(super) async fn execute<'id>(
    store: &mut Client<'id, '_, '_>,
    time: &mut TimeLimit,
    request: Request<'_>,
    reservation: Option<Reservation<'id>>,
    query: Option<[u8; 64]>,
) -> Result<Answer<'id>, Error> {
    execute_inner(store, time, request, reservation, query, || true, false)
        .await
        .map_err(|failure| failure.cause)
}

/// Drive one original operation; true continues and false requests cancellation.
/// Observation ticks retain the same pending drive future and original deadline.
/// An Ok Answer is an actual terminal completion, not an assertion of PUT success.
pub(crate) async fn execute_controlled<'id>(
    store: &mut Client<'id, '_, '_>,
    time: &mut TimeLimit,
    request: Request<'_>,
    reservation: Option<Reservation<'id>>,
    query: Option<[u8; 64]>,
    control: impl FnMut() -> bool,
) -> Result<Answer<'id>, Box<ExecutionFailure>> {
    execute_inner(store, time, request, reservation, query, control, true).await
}
async fn execute_inner<'id>(
    store: &mut Client<'id, '_, '_>,
    time: &mut TimeLimit,
    request: Request<'_>,
    reservation: Option<Reservation<'id>>,
    query: Option<[u8; 64]>,
    mut control: impl FnMut() -> bool,
    observe_control: bool,
) -> Result<Answer<'id>, Box<ExecutionFailure>> {
    time.during(std::future::ready(())).await.map_err(|cause| {
        Box::new(ExecutionFailure {
            submission: Submission::NotSubmitted,
            cause,
            requested_cancel: false,
            settlement_error: None,
        })
    })?;
    if observe_control && !control() {
        return Err(Box::new(ExecutionFailure {
            submission: Submission::NotSubmitted,
            cause: ProtocolError::Cancelled.into(),
            requested_cancel: true,
            settlement_error: None,
        }));
    }
    let timeout = Duration(
        time.remaining()
            .0
            .min(store.protocol_limits().max_lifetime.0),
    );
    let fallback = if matches!(request, Request::Reserve { .. } | Request::Release { .. }) {
        Outcome::ReservationLost
    } else {
        Outcome::Unknown
    };
    let operation = store
        .submit(request, reservation, timeout)
        .map_err(|cause| {
            Box::new(ExecutionFailure {
                submission: Submission::NotSubmitted,
                cause: cause.into(),
                requested_cancel: false,
                settlement_error: None,
            })
        })?;
    let mut cause = None;
    let mut requested_cancel = false;
    loop {
        match store.take(operation) {
            Ok(taken) => {
                return Ok(Answer {
                    taken,
                    cause,
                    requested_cancel,
                });
            }
            Err(ConnectError::Protocol(ProtocolError::NotReady)) => {}
            Err(error) => {
                return Err(retire_execution(
                    store,
                    operation,
                    query,
                    fallback,
                    error.into(),
                    requested_cancel,
                ));
            }
        }
        let observed = drive_controlled(
            store,
            time,
            &mut control,
            observe_control && !requested_cancel,
        )
        .await;
        let step = match observed {
            DriveObservation::Step(step) => step,
            DriveObservation::Cancel => {
                requested_cancel = true;
                if let Err(error) = store.cancel(operation) {
                    return Err(retire_execution(
                        store,
                        operation,
                        query,
                        fallback,
                        error.into(),
                        true,
                    ));
                }
                // The original operation remains authoritative. A queued request
                // can now be Cancelled/NotSent; a written one drains one reply
                // or retires with Unknown. Neither path creates another submit.
                continue;
            }
        };
        let error = match step {
            Ok(Ok(Step::ConnectRetry { error, .. })) => {
                if cause.is_none() {
                    cause = Some(ConnectError::Io(error).into());
                }
                continue;
            }
            Ok(Ok(Step::Connected(_))) => {
                cause = None;
                continue;
            }
            Ok(Ok(Step::Lost { cause: loss, .. })) => {
                if cause.is_none() {
                    cause = Some(match loss {
                        Loss::Io(error) => ConnectError::Io(error).into(),
                        Loss::Protocol(error) => error.into(),
                        Loss::Deadline => ProtocolError::Deadline.into(),
                        Loss::Requested => ProtocolError::Closed.into(),
                    });
                }
                continue;
            }
            Ok(Ok(Step::Unavailable(error))) => error.into(),
            Ok(Ok(Step::Capacity)) => ProtocolError::Capacity.into(),
            Ok(Ok(Step::Closed)) => ProtocolError::Closed.into(),
            Ok(Ok(_)) => continue,
            Ok(Err(error)) => error.into(),
            Err(error) => error,
        };
        return Err(retire_execution(
            store,
            operation,
            query,
            fallback,
            error,
            requested_cancel,
        ));
    }
}

enum DriveObservation<'id> {
    Step(Result<Result<Step<'id>, ConnectError>, Error>),
    Cancel,
}
async fn drive_controlled<'id>(
    store: &mut Client<'id, '_, '_>,
    time: &mut TimeLimit,
    control: &mut impl FnMut() -> bool,
    observe: bool,
) -> DriveObservation<'id> {
    // Continue ticks never reconstruct this future, its native partial cursors,
    // its operation ID, its current channel, or either original deadline.
    let mut native = std::pin::pin!(time.during(store.drive(None)));
    let mut observe_tick = std::pin::pin!(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if !control() {
                return DriveObservation::Cancel;
            }
        }
    });
    std::future::poll_fn(|cx| {
        use std::{future::Future, task::Poll};
        match native.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(DriveObservation::Step(result)),
            Poll::Pending if observe => observe_tick.as_mut().poll(cx),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
fn retire_execution<'id>(
    store: &mut Client<'id, '_, '_>,
    operation: gnunet_datastore_host::Operation<'id>,
    query: Option<[u8; 64]>,
    fallback: Outcome,
    cause: Error,
    requested_cancel: bool,
) -> Box<ExecutionFailure> {
    // Physically retire before classifying this same original operation. Even
    // an unexpected take refusal cannot discard its operation ID and skip this.
    let retirement_error = store.close().err();
    let (mut failure, settlement_error) = match store.take(operation) {
        Ok(taken) => (StoreFailure::from_taken(taken, query, Some(cause)), None),
        Err(error) => (
            StoreFailure {
                query,
                outcome: fallback,
                interruption: None,
                cause: Some(Box::new(cause)),
                retirement_error: None,
                frame: None,
            },
            Some(error),
        ),
    };
    failure.retirement_error = retirement_error;
    Box::new(ExecutionFailure {
        submission: Submission::Submitted,
        cause: Error::Store(Box::new(failure)),
        requested_cancel,
        settlement_error,
    })
}

pub(super) fn accepted(answer: &Answer<'_>) -> bool {
    answer.taken.completion.interruption.is_none()
        && matches!(
            answer.taken.completion.outcome,
            Outcome::Status { code: 1, .. }
        )
}
// The PUT continuation permits zero (already present) and positive success.
// A duplicate may still change scores, so zero must never trigger replay.
pub(super) fn accepted_put(answer: &Answer<'_>) -> bool {
    answer.taken.completion.interruption.is_none()
        && matches!(answer.taken.completion.outcome,Outcome::Status{code,..} if code>=0)
}
pub(super) fn refused(answer: Answer<'_>, query: Option<[u8; 64]>) -> Error {
    Error::Store(Box::new(StoreFailure::from_taken(
        answer.taken,
        query,
        answer.cause,
    )))
}

/// Actual index registration certainty, independent of later DATASTORE writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexRegistration {
    /// Native owner established that no index mutation was exposed.
    NotSubmitted,
    /// Original index mutation may have been processed; it is never replayed.
    Unknown,
    /// An actual IndexFailed response was received and retained.
    Refused,
    /// An actual IndexStarted response was received. It conveys no path ownership.
    Acknowledged,
}
/// Original index-side cause and response, preserved without a fabricated ACK.
pub struct RegistrationFailure {
    /// Exact original mutation certainty or actual explicit refusal.
    pub registration: IndexRegistration,
    /// Original returned socket, configuration, protocol or operation deadline cause.
    pub cause: Option<Error>,
    /// Earlier connection-attempt cause, cleared after actual connection recovery.
    pub preceding: Option<Error>,
    /// Original native FS failure, retaining cause separately from outcome.
    pub failure: Option<NativeIndexFailure>,
    /// Exact original management event, including raw non-UTF8 refusal bytes.
    pub response: Option<Received>,
    /// Independent error while physically retiring the original MQ.
    pub retirement_error: Option<ConnectError>,
}
impl fmt::Debug for RegistrationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationFailure")
            .field("registration", &self.registration)
            .field("cause", &self.cause)
            .field("preceding", &self.preceding)
            .field("failure", &self.failure)
            .field("response", &self.response.as_ref().map(Received::event))
            .field("retirement_error", &self.retirement_error)
            .finish()
    }
}
impl fmt::Display for RegistrationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS index registration {:?}", self.registration)?;
        if let Some(response) = &self.response
            && let IndexEvent::IndexFailed(message) = response.event()
        {
            write!(f, ": {}", String::from_utf8_lossy(message))?;
        }
        if let Some(cause) = &self.cause {
            write!(f, ": {cause}")?;
        }
        Ok(())
    }
}
impl std::error::Error for RegistrationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}
/// Original failure phase of an explicitly indexed publication.
#[derive(Debug)]
pub enum IndexPublishCause {
    /// Native file validation, encoding, cancellation or DATASTORE result.
    Transfer(Error),
    /// Original official FS registration refusal or uncertain mutation.
    Registration(Box<RegistrationFailure>),
}
impl fmt::Display for IndexPublishCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transfer(error) => error.fmt(f),
            Self::Registration(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for IndexPublishCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transfer(error) => Some(error),
            Self::Registration(error) => Some(error.as_ref()),
        }
    }
}
impl From<Error> for IndexPublishCause {
    fn from(error: Error) -> Self {
        Self::Transfer(error)
    }
}
impl From<ProtocolError> for IndexPublishCause {
    fn from(error: ProtocolError) -> Self {
        Self::Transfer(error.into())
    }
}
impl From<crate::Error> for IndexPublishCause {
    fn from(error: crate::Error) -> Self {
        Self::Transfer(error.into())
    }
}
impl From<io::Error> for IndexPublishCause {
    fn from(error: io::Error) -> Self {
        Self::Transfer(error.into())
    }
}
/// Failure preserves both the actual index phase and the acknowledged PUT prefix.
#[derive(Debug)]
pub struct IndexPublishError {
    /// Whole-file hash, present only after the complete first pass was validated.
    pub file_id: Option<[u8; 64]>,
    /// Actual registration phase, independent of the following transfer outcome.
    pub registration: IndexRegistration,
    /// Bytes actually hashed in the initial streaming validation pass.
    pub hashed_bytes: u64,
    /// Actual acknowledged node prefix; encoded_bytes counts computed ciphertext.
    pub progress: Progress,
    /// Actual DATASTORE payload bytes acknowledged, including type6 descriptors.
    pub stored_bytes: u128,
    /// Original error, including any uncertain PUT or index mutation.
    pub cause: IndexPublishCause,
    /// Independent retirement trouble after a known positive IndexStarted.
    pub index_retirement_error: Option<ConnectError>,
}
impl fmt::Display for IndexPublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "indexed FS publication {:?} after {} acknowledged nodes: {}",
            self.registration, self.progress.blocks, self.cause
        )
    }
}
impl std::error::Error for IndexPublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// Registration was acknowledged and every real file PUT, including root,
/// was acknowledged. No new-registration, owned-path or future availability
/// claim can be inferred from the official IndexStarted message.
#[derive(Debug)]
pub struct IndexedFile {
    /// Whole plaintext-file hash used in every type6 record.
    pub file_id: [u8; 64],
    /// Actual CHK, acknowledged encoding work and reservation cleanup result.
    pub stored: StoredFile,
    /// Actual acknowledged DATASTORE payload bytes, separate from CHK ciphertext.
    pub stored_bytes: u128,
    /// Independent retirement trouble after known index registration acceptance.
    pub index_retirement_error: Option<ConnectError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: i64,
    modified_nanos: i64,
    changed: i64,
    changed_nanos: i64,
}
impl Stamp {
    fn capture(metadata: &std::fs::Metadata) -> Result<Self, Error> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "indexed FS source must be a regular file",
            )
            .into());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        })
    }
}
// The duplicate descriptor is only used for metadata. Reads/seeks stay on the
// caller's original File; no whole-file collection or path-reopen reader exists.
struct IndexedGuard {
    file: File,
    path: PathBuf,
    stamp: Stamp,
    file_id: [u8; 64],
    hash: Hash512State,
}
impl IndexedGuard {
    async fn stable(&self) -> Result<(), Error> {
        let original = Stamp::capture(&self.file.metadata().await?)?;
        let path = Stamp::capture(&tokio::fs::metadata(&self.path).await?)?;
        if original != self.stamp || path != self.stamp {
            return Err(crate::Error::SourceChanged.into());
        }
        Ok(())
    }
    async fn finish(&self) -> Result<(), Error> {
        if self.hash.clone().finish() != self.file_id {
            return Err(crate::Error::SourceChanged.into());
        }
        self.stable().await
    }
}
struct Run<'a, 'id, 'slots, 'buffers> {
    store: &'a mut Client<'id, 'slots, 'buffers>,
    time: &'a mut TimeLimit,
    options: PublishOptions,
    indexed: Option<&'a mut IndexedGuard>,
    progress: &'a mut Progress,
    stored_bytes: &'a mut u128,
}
/// Exact actual payload total shared by reservations and composite budgets.
/// Indexed data leaves are 72-byte type6 descriptors; index nodes remain full.
pub(crate) fn payload_bytes_wide(layout: Layout, indexed: bool) -> Result<u128, ProtocolError> {
    if indexed {
        let direct =
            u128::from(layout.size()) + u128::from(layout.leaf_count()) * TAG_BYTES as u128;
        layout
            .encoded_tree_bytes()
            .checked_sub(direct)
            .and_then(|n| n.checked_add(u128::from(layout.leaf_count()) * 72))
            .ok_or(ProtocolError::Overflow)
    } else {
        Ok(layout.encoded_tree_bytes())
    }
}
fn payload_bytes(layout: Layout, indexed: bool) -> Result<u64, ProtocolError> {
    u64::try_from(payload_bytes_wide(layout, indexed)?).map_err(|_| ProtocolError::TooLarge)
}
async fn read_exact(input: &mut (impl AsyncRead + Unpin), output: &mut [u8]) -> io::Result<()> {
    let mut used = 0;
    while used < output.len() {
        match input.read(&mut output[used..]).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "FS source shorter than declared size",
                ));
            }
            Ok(read) => used += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn abort_cause(error: &Error) -> ProtocolError {
    match error {
        Error::Protocol(error) => *error,
        Error::Deadline { .. } => ProtocolError::Deadline,
        Error::Cancelled(_) => ProtocolError::Cancelled,
        _ => ProtocolError::Io,
    }
}
fn registration_failure<const N: usize>(
    client: &mut ipc::Client<'_, '_, N>,
    cause: Error,
    preceding: Option<Error>,
) -> RegistrationFailure {
    let retirement_error = client.abort_with_cause(abort_cause(&cause)).err();
    let failure = client.failure();
    let registration =
        if failure.is_some_and(|failure| failure.outcome == ProtocolError::OutcomeUnknown) {
            IndexRegistration::Unknown
        } else {
            IndexRegistration::NotSubmitted
        };
    RegistrationFailure {
        registration,
        cause: Some(cause),
        preceding,
        failure,
        response: None,
        retirement_error,
    }
}
async fn register_index(
    source: EndpointSource,
    file_id: [u8; 64],
    filename: &Path,
    time: &mut TimeLimit,
    deadline: AbsoluteTime,
) -> Result<Option<ConnectError>, Box<RegistrationFailure>> {
    index_registration::immediate(source, file_id, filename, time, deadline)
        .await
        .map(|answer| answer.retirement_error)
}

impl Buffers {
    /// Stream exact size bytes and actual full D/I DATASTORE PUTs using one
    /// dedicated idle client. Dropping the future closes its original MQ; any
    /// acknowledged prefix remains and exposed mutations are never replayed.
    pub async fn store_file<'id>(
        &mut self,
        input: &mut (impl AsyncRead + Unpin),
        size: u64,
        store: Client<'id, '_, '_>,
        options: PublishOptions,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<StoredFile, Error> {
        let mut progress = Progress::default();
        let mut stored_bytes = 0;
        self.store_file_tracked(
            input,
            size,
            store,
            options,
            &mut progress,
            &mut stored_bytes,
            control,
        )
        .await
    }
    /// Internal composite-operation entry retaining every actual ACK even when
    /// a later error occurs before another control callback. Counters must be
    /// initially empty and remain owned by the caller on both Ok and Err.
    #[expect(
        clippy::too_many_arguments,
        reason = "Composite publication retains original ACK counters independently of the returned cause"
    )]
    pub(super) async fn store_file_tracked<'id>(
        &mut self,
        input: &mut (impl AsyncRead + Unpin),
        size: u64,
        mut store: Client<'id, '_, '_>,
        options: PublishOptions,
        progress: &mut Progress,
        stored_bytes: &mut u128,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<StoredFile, Error> {
        if *progress != Progress::default()
            || *stored_bytes != 0
            || store.pending() != 0
            || store.retained_replies() != (0, 0)
        {
            return Err(ProtocolError::NotReady.into());
        }
        self.prepare(
            Content {
                key: [0; 64],
                query: [0; 64],
                size,
            },
            options.limits,
        )?;
        let mut time = TimeLimit::new(store.clock(), options.deadline)?;
        self.store_prepared(
            input,
            size,
            Run {
                store: &mut store,
                time: &mut time,
                options,
                indexed: None,
                progress,
                stored_bytes,
            },
            &mut control,
        )
        .await
    }
    /// Publish an actual regular file through acknowledged IndexStart and type6
    /// descriptors for data leaves, with normal encrypted index nodes. The
    /// original file is hashed in bounded chunks, rewound and encoded a second
    /// time; both hashes, FD/path metadata and EOF are checked before root PUT.
    ///
    /// filename is canonicalized and must identify the caller's original File.
    /// The same numeric deadline must belong to both supplied service clocks.
    /// The callback receives acknowledged encoding progress: it remains zero
    /// during the initial hash, while failure.hashed_bytes reports that work.
    /// Each original mutation is submitted once. No automatic unindex rollback
    /// is performed because IndexStarted may refer to a preexisting path. A
    /// returned receipt asserts local acceptance, never future source retention.
    pub async fn store_indexed_file<'id>(
        &mut self,
        input: &mut File,
        filename: &Path,
        fs_source: EndpointSource,
        mut store: Client<'id, '_, '_>,
        options: PublishOptions,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<IndexedFile, Box<IndexPublishError>> {
        let mut file_id = None;
        let mut registration = IndexRegistration::NotSubmitted;
        let mut hashed_bytes = 0;
        let mut progress = Progress::default();
        let mut stored_bytes = 0;
        let mut index_retirement_error = None;
        let result: Result<StoredFile, IndexPublishCause> = async {
            if store.pending() != 0 || store.retained_replies() != (0, 0) {
                return Err(ProtocolError::NotReady.into());
            }
            let mut time = TimeLimit::new(store.clock(), options.deadline)?;
            if control(progress) == Control::Cancel {
                return Err(Error::Cancelled(progress).into());
            }
            let original = Stamp::capture(&time.during(input.metadata()).await??)?;
            self.prepare(
                Content {
                    key: [0; 64],
                    query: [0; 64],
                    size: original.bytes,
                },
                options.limits,
            )?;
            let path = time.during(tokio::fs::canonicalize(filename)).await??;
            let alias = Stamp::capture(&time.during(tokio::fs::metadata(&path)).await??)?;
            if original != alias {
                return Err(Error::from(crate::Error::SourceChanged).into());
            }
            let metadata_file = time.during(input.try_clone()).await??;
            time.during(input.seek(io::SeekFrom::Start(0))).await??;
            let mut hash = Hash512State::new();
            while hashed_bytes < original.bytes {
                if control(progress) == Control::Cancel {
                    return Err(Error::Cancelled(progress).into());
                }
                let length = (original.bytes - hashed_bytes).min(self.plain.len() as u64) as usize;
                let read = match time.during(input.read(&mut self.plain[..length])).await? {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "indexed FS source shortened during hash",
                        )
                        .into());
                    }
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                };
                hash.update(&self.plain[..read]);
                hashed_bytes += read as u64;
            }
            let mut extra = [0];
            loop {
                match time.during(input.read(&mut extra)).await? {
                    Ok(0) => break,
                    Ok(_) => return Err(Error::from(crate::Error::SourceChanged).into()),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let hash = hash.finish();
            let mut guard = IndexedGuard {
                file: metadata_file,
                path,
                stamp: original,
                file_id: hash,
                hash: Hash512State::new(),
            };
            time.during(guard.stable()).await??;
            file_id = Some(hash);
            if control(progress) == Control::Cancel {
                return Err(Error::Cancelled(progress).into());
            }
            match register_index(fs_source, hash, &guard.path, &mut time, options.deadline).await {
                Ok(cleanup) => {
                    registration = IndexRegistration::Acknowledged;
                    index_retirement_error = cleanup;
                }
                Err(failure) => {
                    registration = failure.registration;
                    return Err(IndexPublishCause::Registration(failure));
                }
            }
            time.during(guard.stable()).await??;
            time.during(input.seek(io::SeekFrom::Start(0))).await??;
            self.store_prepared(
                input,
                original.bytes,
                Run {
                    store: &mut store,
                    time: &mut time,
                    options,
                    indexed: Some(&mut guard),
                    progress: &mut progress,
                    stored_bytes: &mut stored_bytes,
                },
                &mut control,
            )
            .await
            .map_err(Into::into)
        }
        .await;
        match result {
            Ok(stored) => Ok(IndexedFile {
                file_id: match file_id {
                    Some(id) => id,
                    None => {
                        return Err(Box::new(IndexPublishError {
                            file_id: None,
                            registration,
                            hashed_bytes,
                            progress,
                            stored_bytes,
                            cause: ProtocolError::NotReady.into(),
                            index_retirement_error,
                        }));
                    }
                },
                stored,
                stored_bytes,
                index_retirement_error,
            }),
            Err(cause) => Err(Box::new(IndexPublishError {
                file_id,
                registration,
                hashed_bytes,
                progress,
                stored_bytes,
                cause,
                index_retirement_error,
            })),
        }
    }
    async fn store_prepared<'id>(
        &mut self,
        input: &mut (impl AsyncRead + Unpin),
        size: u64,
        run: Run<'_, 'id, '_, '_>,
        control: &mut impl FnMut(Progress) -> Control,
    ) -> Result<StoredFile, Error> {
        let Run {
            store,
            time,
            options,
            mut indexed,
            progress,
            stored_bytes,
        } = run;
        let layout = Layout::new(size);
        let mut reservation = None;
        if options.reserve_space {
            let amount = payload_bytes(layout, indexed.is_some())?;
            let mut entries = 0u64;
            for level in 0..layout.levels() {
                entries = entries
                    .checked_add(layout.node_count(level)?)
                    .ok_or(ProtocolError::Overflow)?;
            }
            let entries = u32::try_from(entries).map_err(|_| ProtocolError::TooLarge)?;
            let answer = execute(
                store,
                time,
                Request::Reserve { amount, entries },
                None,
                None,
            )
            .await?;
            if answer.taken.completion.interruption.is_some()
                || !matches!(answer.taken.completion.outcome,Outcome::Status{code,..} if code>0)
            {
                return Err(refused(answer, None));
            }
            reservation = Some(
                answer
                    .taken
                    .completion
                    .reservation
                    .ok_or(ProtocolError::Malformed)?,
            );
        }
        let mut encoder = FileEncoder::new(size, &mut self.keys)?;
        while let Some(node) = encoder.next() {
            time.during(std::future::ready(())).await?;
            if control(*progress) == Control::Cancel {
                return Err(Error::Cancelled(*progress));
            }
            let encoded = if node.level() == 0 {
                let length = node.plaintext_bytes();
                time.during(read_exact(input, &mut self.plain[..length]))
                    .await??;
                if let Some(guard) = indexed.as_deref_mut() {
                    guard.hash.update(&self.plain[..length]);
                }
                encoder.push_data(&self.plain[..length], &mut self.encoded)?
            } else {
                encoder.emit_index(&mut self.index, &mut self.encoded)?
            };
            if encoder.next().is_none() {
                let mut extra = [0];
                loop {
                    match time.during(input.read(&mut extra)).await? {
                        Ok(0) => break,
                        Ok(_) => return Err(crate::Error::SourceChanged.into()),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if let Some(guard) = indexed.as_deref_mut() {
                    time.during(guard.finish()).await??;
                }
            }
            let key = encoded.block().key().query;
            let ciphertext = encoded.block().bytes();
            let mut descriptor = [0; 72];
            let (kind, bytes) = if node.level() == 0 {
                if let Some(guard) = indexed.as_deref() {
                    descriptor[..64].copy_from_slice(&guard.file_id);
                    descriptor[64..].copy_from_slice(&node.range().start.to_be_bytes());
                    (6, descriptor.as_slice())
                } else {
                    (1, ciphertext)
                }
            } else {
                (2, ciphertext)
            };
            let answer = execute(
                store,
                time,
                Request::Put(Data {
                    reservation: reservation.map_or(0, Reservation::value),
                    kind,
                    priority: options.blocks.priority,
                    anonymity: options.blocks.anonymity,
                    replication: options.blocks.replication,
                    uid: 0,
                    expiration: options.blocks.expiration,
                    key: &key,
                    value: bytes,
                }),
                reservation,
                Some(key),
            )
            .await?;
            if !accepted_put(&answer) {
                return Err(refused(answer, Some(key)));
            }
            progress.blocks += 1;
            progress.encoded_bytes += ciphertext.len() as u128;
            *stored_bytes += bytes.len() as u128;
            if node.level() == 0 {
                progress.plaintext_bytes += node.plaintext_bytes() as u64;
            }
        }
        let content = encoder.content().ok_or(ProtocolError::NotReady)?;
        let cleanup = if let Some(token) = reservation {
            match execute(
                store,
                time,
                Request::Release {
                    reservation: token.value(),
                },
                Some(token),
                None,
            )
            .await
            {
                Ok(answer) if accepted(&answer) => None,
                Ok(answer) => Some(StoreFailure::from_taken(answer.taken, None, answer.cause)),
                Err(Error::Store(failure)) => Some(*failure),
                Err(error) => Some(StoreFailure {
                    query: None,
                    outcome: Outcome::ReservationLost,
                    interruption: None,
                    cause: Some(Box::new(error)),
                    retirement_error: None,
                    frame: None,
                }),
            }
        } else {
            None
        };
        // Explicit close releases connection-scoped reservations even when a
        // RELEASE reply was lost. It cannot revoke any already accepted block.
        let close_error = store.close().err();
        let cleanup = match (cleanup, close_error) {
            (Some(mut failure), error) => {
                if failure.retirement_error.is_none() {
                    failure.retirement_error = error;
                }
                Some(failure)
            }
            (None, Some(error)) => Some(StoreFailure {
                query: None,
                outcome: Outcome::ReservationLost,
                interruption: None,
                cause: None,
                retirement_error: Some(error),
                frame: None,
            }),
            (None, None) => None,
        };
        Ok(StoredFile {
            content,
            progress: *progress,
            cleanup,
        })
    }
}

#[cfg(test)]
mod execute_tests;
