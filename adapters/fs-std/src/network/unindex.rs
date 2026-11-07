//! File-bound local unindex: exact DATASTORE removals, then original FS acknowledgement.
use super::{Error, TimeLimit, publish};
use crate::{Buffers, Control, Limits, Progress, extraction, ipc};
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_crypto::Hash512State;
use gnunet_datastore_host::{Client, Outcome};
use gnunet_fs::{
    Content, Uri,
    client::{Event, Failure as NativeFailure},
    content::FileEncoder,
    ublock,
};
use gnunet_fs_codec::Inflate;
use gnunet_types::{AbsoluteTime, Error as Fault};
use gnunet_wire::official::datastore::{Request, Response};
use std::{
    fmt,
    fs::File,
    future::Future,
    io::{self, Read, Seek},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

/// Private persistence boundary around the existing single native owner.
/// Only the durable task supplies retained receipt authority; immediate callers
/// keep the ordinary path and cannot inject a synthetic original completion.
pub(crate) trait Recorder {
    fn source(&mut self, _file_id: [u8; 64], _bytes: u64) -> Result<(), Fault> {
        Ok(())
    }
    fn retained_keywords(&mut self) -> Result<Option<Vec<Vec<u8>>>, Fault> {
        Ok(None)
    }
    fn keywords(&mut self, _keywords: &mut Vec<Vec<u8>>, _complete: bool) -> Result<(), Fault> {
        Ok(())
    }
    fn keyword(&mut self, _query: &[u8; 64]) -> Result<bool, Fault> {
        Ok(false)
    }
    fn keyword_end(&mut self, _query: &[u8; 64]) -> Result<(), Fault> {
        Ok(())
    }
    /// true means a matching historical accepted receipt, separately reported.
    fn before(&mut self, _operation: Operation<'_>) -> Result<bool, Fault> {
        Ok(false)
    }
    fn not_submitted(&mut self, _operation: Operation<'_>) -> Result<(), Fault> {
        Ok(())
    }
    fn received(
        &mut self,
        _operation: Operation<'_>,
        _code: i32,
        _accepted: bool,
    ) -> Result<(), Fault> {
        Ok(())
    }
}
pub(crate) struct Immediate;
impl Recorder for Immediate {}
#[derive(Clone, Copy)]
pub(crate) enum Operation<'a> {
    Remove {
        key: &'a [u8; 64],
        value: &'a [u8],
        keyword: bool,
    },
    Unindex {
        file_id: &'a [u8; 64],
    },
}

/// Explicit original operation and bounded cleanup policy.
#[derive(Clone, Debug)]
pub struct Options<'a> {
    /// Original canonical target shared by every file and service step.
    pub deadline: AbsoluteTime,
    /// Original native target, captured before the caller's canonical sample.
    pub native_deadline: Instant,
    /// Whole-file/tree preparation bounds.
    pub limits: Limits,
    /// Exact automatic extraction selection. Manual publication annotations
    /// are refused because they do not describe unindex keyword recovery.
    pub metadata: extraction::MetadataSettings,
    /// Additional known literal keywords; no implicit search/Unicode conversion.
    pub extra_keywords: &'a [&'a [u8]],
    /// Maximum combined reconstructed and explicitly supplied distinct keywords.
    pub max_keywords: usize,
    /// Maximum returned UBLOCK rows per keyword, including rejected rows.
    pub max_rows_per_keyword: usize,
    /// Maximum returned UBLOCK rows across the complete operation.
    pub max_total_rows: usize,
    /// Actual UBLOCK authentication/decoding bounds.
    pub block: ublock::Limits,
}
impl<'a> Options<'a> {
    /// Default bounded file cleanup with no additional caller-known keywords.
    #[must_use]
    pub fn new(deadline: AbsoluteTime, native_deadline: Instant) -> Self {
        Self {
            deadline,
            native_deadline,
            limits: Limits::default(),
            metadata: extraction::MetadataSettings::default(),
            extra_keywords: &[],
            max_keywords: 256,
            max_rows_per_keyword: 4096,
            max_total_rows: 16384,
            block: ublock::Limits::default(),
        }
    }
}
/// Actual cumulative local work; no remote deletion or storage-durability claim.
#[derive(Clone, Copy, Debug, Default)]
pub struct Observation {
    /// Actual first-pass plaintext bytes hashed on the original descriptor.
    pub hashed_bytes: u64,
    /// Matching historical accepted REMOVE receipts reused after full source
    /// rehash; these are not actual current-run DATASTORE responses.
    pub retained_removals: u64,
    /// Historical keyword selections settled by a persisted matching REMOVE
    /// receipt or DATA_END; these are not actual current-run native queries.
    pub retained_keyword_selections: u64,
    /// Actual second-pass encoding work, separately from accepted removals.
    pub encoded: Progress,
    /// Positive raw REMOVE statuses observed for D/I values.
    pub content_positive: u64,
    /// Zero raw REMOVE statuses for D/I values (absence/backend-error ambiguity).
    pub content_zero: u64,
    /// Exact keyword queries admitted to the original DATASTORE owner.
    pub keyword_queries: u64,
    /// Actual DATA rows inspected, including unrelated or invalid blocks.
    pub keyword_rows: u64,
    /// Authenticated keyword rows that matched this file's exact CHK.
    pub keyword_matches: u64,
    /// Actual keyword queries ended with DATA_END (not whole-store absence proof).
    pub keyword_ends: u64,
    /// Positive raw REMOVE statuses for exact matching UBLOCK values.
    pub keyword_positive: u64,
    /// Zero raw REMOVE statuses for matching UBLOCK values.
    pub keyword_zero: u64,
    /// Invalid, foreign or differently targeted UBLOCK rows retained in the store.
    pub skipped_rows: u64,
    /// Actual bytes written on the original FS UNINDEX request.
    pub fs_written_bytes: usize,
    /// Actual original DATASTORE control requested cancellation.
    pub requested_cancel: bool,
    /// Most recent original raw REMOVE status, without reinterpretation.
    pub last_status: Option<i32>,
    /// Whether the last DATASTORE request was actually admitted, separately from its outcome.
    pub last_store_submitted: bool,
}
/// Owned final facts, including any actual original FS acknowledgement frame.
pub struct Report {
    /// Whole-file SHA512 after exact EOF and stamp verification; None before that.
    pub file_id: Option<[u8; 64]>,
    /// Actual second-pass tree root after exact EOF, second hash and stamp checks.
    pub content: Option<Content>,
    /// Actual cumulative work and accepted response facts.
    pub observation: Observation,
    /// Number of reconstructed current-file keywords.
    pub reconstructed_keywords: usize,
    /// Number of distinct reconstructed plus explicitly supplied keywords.
    pub selected_keywords: usize,
    /// Original FS Client was locally admitted (not proof its request was written).
    pub fs_admitted: bool,
    /// True only after the original Client accepted its matching Unindexed event.
    pub unindexed: bool,
    /// Original accepted FS acknowledgement retained by a durable task. No
    /// current native Client/Received is manufactured for this historical fact.
    pub retained_unindexed: bool,
    response: Option<ipc::Received>,
}
impl Report {
    /// Exact original query-bound FS response, retained only as a local observation.
    #[must_use]
    pub fn response(&self) -> Option<&ipc::Received> {
        self.response.as_ref()
    }
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnindexReport")
            .field("file_id", &self.file_id)
            .field("content", &self.content)
            .field("observation", &self.observation)
            .field("reconstructed_keywords", &self.reconstructed_keywords)
            .field("selected_keywords", &self.selected_keywords)
            .field("fs_admitted", &self.fs_admitted)
            .field("unindexed", &self.unindexed)
            .field("retained_unindexed", &self.retained_unindexed)
            .field("original_response_retained", &self.response.is_some())
            .finish()
    }
}
/// Independent original work, metadata-extraction and physical retirement failures.
#[derive(Debug)]
pub struct Failure {
    /// Actual work and responses, preserved even if later cleanup failed.
    pub report: Report,
    /// Original file, protocol, cancellation, native or DATASTORE uncertainty.
    pub operation: Option<Error>,
    /// Current-file extraction failed before any destructive native request.
    /// Original provider/cleanup causes remain owned by this failure.
    pub keywords: Option<extraction::Error>,
    /// Original keyword lookup-context preparation error.
    pub keyword_context: Option<ublock::Error>,
    /// Original DATASTORE physical close error, after any original receipts.
    pub store_cleanup: Option<ConnectError>,
    /// Original FS physical close error, after any original response.
    pub fs_cleanup: Option<ipc::Error>,
    /// Actual pure FS failure/OutcomeUnknown after retiring the original MQ.
    pub fs_failure: Option<NativeFailure>,
    /// Independent actual failure taking the original retired DATASTORE operation.
    pub settlement: Option<ConnectError>,
    /// Most recent initial FS connection retry cause, if final admission never succeeded.
    pub preceding: Option<ipc::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "file unindex {:?}", self.report)?;
        if let Some(e) = &self.operation {
            write!(f, "; operation: {e}")?;
        }
        if let Some(e) = &self.keyword_context {
            write!(f, "; keyword context: {e}")?;
        }
        if let Some(e) = &self.keywords {
            write!(f, "; keyword reconstruction: {e}")?;
        }
        if let Some(e) = &self.store_cleanup {
            write!(f, "; datastore cleanup: {e}")?;
        }
        if let Some(e) = &self.fs_cleanup {
            write!(f, "; FS cleanup: {e}")?;
        }
        if let Some(e) = &self.fs_failure {
            write!(f, "; original FS outcome: {e:?}")?;
        }
        if let Some(e) = &self.settlement {
            write!(f, "; original operation settlement: {e}")?;
        }
        if let Some(e) = &self.preceding {
            write!(f, "; preceding FS connection: {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.operation
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
            .or_else(|| self.keyword_context.as_ref().map(|e| e as _))
            .or_else(|| self.keywords.as_ref().map(|e| e as _))
            .or_else(|| self.store_cleanup.as_ref().map(|e| e as _))
            .or_else(|| self.fs_cleanup.as_ref().map(|e| e as _))
            .or_else(|| self.settlement.as_ref().map(|e| e as _))
            .or_else(|| self.preceding.as_ref().map(|e| e as _))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    bytes: u64,
    mtime: i64,
    mn: i64,
    ctime: i64,
    cn: i64,
}
impl Stamp {
    fn of(file: &File) -> Result<Self, Error> {
        Self::metadata(&file.metadata()?)
    }
    fn metadata(m: &std::fs::Metadata) -> Result<Self, Error> {
        if !m.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unindex requires a regular original file",
            )
            .into());
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            bytes: m.len(),
            mtime: m.mtime(),
            mn: m.mtime_nsec(),
            ctime: m.ctime(),
            cn: m.ctime_nsec(),
        })
    }
    fn stable(self, file: &File, path: &Path) -> Result<(), Error> {
        if Self::of(file)? != self || Self::metadata(&std::fs::metadata(path)?)? != self {
            return Err(crate::Error::SourceChanged.into());
        }
        Ok(())
    }
}
async fn gate(
    time: &mut TimeLimit,
    observation: Observation,
    control: &mut impl FnMut(Observation) -> Control,
) -> Result<(), Error> {
    tokio::task::yield_now().await;
    time.during(std::future::ready(())).await?;
    if control(observation) == Control::Cancel {
        return Err(Error::Cancelled(observation.encoded));
    }
    Ok(())
}
fn add_keyword(out: &mut Vec<Vec<u8>>, value: &[u8], options: &Options<'_>) -> Result<(), Error> {
    if value.is_empty() || value.contains(&0) || value.len() > options.block.max_label_bytes {
        return Err(Fault::InvalidInput.into());
    }
    if out.iter().any(|v| v == value) {
        return Ok(());
    }
    if out.len() == options.max_keywords {
        return Err(Fault::Capacity.into());
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| Fault::Capacity)?;
    owned.extend_from_slice(value);
    out.try_reserve(1).map_err(|_| Fault::Capacity)?;
    out.push(owned);
    Ok(())
}
struct RunError {
    cause: Option<Error>,
    block: Option<ublock::Error>,
    settlement: Option<ConnectError>,
}
impl From<Error> for RunError {
    fn from(cause: Error) -> Self {
        Self {
            cause: Some(cause),
            block: None,
            settlement: None,
        }
    }
}
impl RunError {
    fn block(error: ublock::Error) -> Self {
        Self {
            cause: None,
            block: Some(error),
            settlement: None,
        }
    }
}
fn observe_remove_status(observation: &mut Observation, keyword: bool, code: i32) {
    observation.last_status = Some(code);
    match (keyword, code) {
        (false, 1..) => observation.content_positive += 1,
        (false, 0) => observation.content_zero += 1,
        (true, 1..) => observation.keyword_positive += 1,
        (true, 0) => observation.keyword_zero += 1,
        _ => {}
    }
}
#[expect(
    clippy::result_large_err,
    reason = "The bounded async frame preserves the original typed operation and settlement causes without an extra allocation on failure."
)]
#[expect(
    clippy::too_many_arguments,
    reason = "One exact removal retains its original request, native/canonical bound, control, cumulative observations and durable barrier together"
)]
async fn remove(
    store: &mut Client<'_, '_, '_>,
    time: &mut TimeLimit,
    key: &[u8; 64],
    value: &[u8],
    keyword: bool,
    observation: &mut Observation,
    control: &mut impl FnMut(Observation) -> Control,
    recorder: &mut impl Recorder,
) -> Result<(), RunError> {
    let operation = Operation::Remove {
        key,
        value,
        keyword,
    };
    if recorder.before(operation).map_err(Error::from)? {
        observation.retained_removals = observation
            .retained_removals
            .checked_add(1)
            .ok_or_else(|| Error::from(Fault::Overflow))?;
        return Ok(());
    }
    let answer = publish::execute_controlled(
        store,
        time,
        Request::Remove { key, value },
        None,
        Some(*key),
        || control(*observation) == Control::Continue,
    )
    .await;
    let answer = match answer {
        Ok(answer) => {
            observation.last_store_submitted = true;
            answer
        }
        Err(failure) => {
            observation.last_store_submitted = failure.submission == publish::Submission::Submitted;
            observation.requested_cancel |= failure.requested_cancel;
            if failure.submission == publish::Submission::NotSubmitted {
                // Journal retains its independent error. Return the original
                // actual native refusal, never replace it with a storage proxy.
                let _recorded_no_admission = recorder.not_submitted(operation);
            } else if let Error::Store(original) = &failure.cause
                && original.query == Some(*key)
                && let Outcome::Status { code, .. } = original.outcome
                && matches!(original.response(), Ok(Some(Response::Status(status))) if status.code == code)
            {
                // Physical retirement can take an already-received terminal
                // STATUS for this exact original operation. Keep that receipt
                // independently from the original timeout/cancel/cleanup error.
                observe_remove_status(observation, keyword, code);
                let _recorded_original_status = recorder.received(operation, code, code >= 0);
            }
            return Err(RunError {
                cause: Some(failure.cause),
                block: None,
                settlement: failure.settlement_error,
            });
        }
    };
    observation.requested_cancel |= answer.requested_cancel;
    if let Outcome::Status { code, .. } = answer.taken.completion.outcome {
        // The serialized original operation owns this actual STATUS even if
        // cancellation/deadline was recorded while draining it. Persist its
        // raw nonnegative terminal progress without claiming the run succeeded.
        observe_remove_status(observation, keyword, code);
        recorder
            .received(operation, code, code >= 0)
            .map_err(Error::from)?;
    }
    let accepted = answer.taken.completion.interruption.is_none()
        && matches!(answer.taken.completion.outcome,Outcome::Status{code,..} if code>=0);
    if !accepted || answer.cause.is_some() {
        return Err(publish::refused(answer, Some(*key)).into());
    }
    if answer.requested_cancel {
        return Err(Error::Cancelled(observation.encoded).into());
    }
    Ok(())
}
struct FsError {
    cause: Option<Error>,
    cleanup: Option<ipc::Error>,
    failure: Option<NativeFailure>,
    preceding: Option<ipc::Error>,
}
#[expect(
    clippy::result_large_err,
    reason = "One original FS operation retains its independent typed failure and retirement causes in the bounded async frame."
)]
async fn notify(
    source: EndpointSource,
    file_id: [u8; 64],
    time: &mut TimeLimit,
    deadline: AbsoluteTime,
    report: &mut Report,
    control: &mut impl FnMut(Observation) -> Control,
    recorder: &mut impl Recorder,
) -> Result<(), FsError> {
    gate(time, report.observation, control)
        .await
        .map_err(|e| FsError {
            cause: Some(e),
            cleanup: None,
            failure: None,
            preceding: None,
        })?;
    let operation = Operation::Unindex { file_id: &file_id };
    if recorder.before(operation).map_err(|cause| FsError {
        cause: Some(cause.into()),
        cleanup: None,
        failure: None,
        preceding: None,
    })? {
        report.retained_unindexed = true;
        return Ok(());
    }
    let mut identity = ipc::Instance::new();
    let mut client = ipc::Client::<0>::new(
        &mut identity,
        ipc::Request::Unindex { file_id },
        source,
        Default::default(),
        Default::default(),
        deadline,
    )
    .map_err(|e| {
        let _recorded_no_admission = recorder.not_submitted(operation);
        FsError {
            cause: Some(e.into()),
            cleanup: None,
            failure: None,
            preceding: None,
        }
    })?;
    report.fs_admitted = true;
    let mut preceding = None;
    let outcome: Result<(), Error> = async {
        loop {
            let step = {
                let mut pending = std::pin::pin!(time.during(client.drive(None)));
                let mut tick = std::pin::pin!(tokio::time::sleep(Duration::from_millis(50)));
                std::future::poll_fn(|cx| {
                    if control(report.observation) == Control::Cancel {
                        return Poll::Ready(Err(Error::Cancelled(report.observation.encoded)));
                    }
                    if tick.as_mut().poll(cx).is_ready() {
                        tick.as_mut()
                            .reset(Instant::now() + Duration::from_millis(50));
                        cx.waker().wake_by_ref();
                    }
                    pending.as_mut().poll(cx)
                })
                .await
            }??;
            match step {
                ipc::Step::Event(response) => {
                    if !matches!(response.event(), Event::Unindexed) {
                        return Err(Fault::Malformed.into());
                    }
                    report.unindexed = true;
                    report.response = Some(response);
                    recorder.received(operation, 1, true)?;
                    return Ok(());
                }
                ipc::Step::Written { bytes, .. } => report.observation.fs_written_bytes += bytes,
                ipc::Step::Connected => preceding = None,
                ipc::Step::Retry { cause, .. } => {
                    if client.failure().is_some() {
                        return Err(cause.into());
                    }
                    if preceding.is_none() {
                        preceding = Some(cause);
                    }
                }
                ipc::Step::Unavailable(error) => return Err(error.into()),
                ipc::Step::Finished => return Err(Fault::NotReady.into()),
                _ => {}
            }
        }
    }
    .await;
    let cause = outcome.err();
    let abort = match &cause {
        Some(Error::Protocol(cause)) => *cause,
        Some(Error::Deadline { .. }) => Fault::Deadline,
        Some(Error::Cancelled(_)) => Fault::Cancelled,
        Some(_) => Fault::Io,
        None => Fault::Cancelled,
    };
    let cleanup = client.abort_with_cause(abort).err();
    let failure = client.failure();
    drop(client);
    if cause.is_some() || cleanup.is_some() {
        Err(FsError {
            cause,
            cleanup,
            failure,
            preceding,
        })
    } else {
        Ok(())
    }
}
impl Buffers {
    /// Unindex the version represented by this original stable regular descriptor.
    /// Two streamed hashes and stamp/EOF checks bind it to the actual D/I tree.
    /// Exact local DATASTORE values are removed once under original operations;
    /// uncertainty stops new mutations and never authorizes automatic replay.
    ///
    /// Current-file automatic keywords plus explicit known labels are only a
    /// bounded cleanup selection. For each, at most its first authenticated row
    /// targeting this exact CHK is removed; unrelated values remain untouched.
    /// Finally, only a matching original FS Unindexed response sets `unindexed`.
    /// Neither it nor a zero DATASTORE status proves all historical/custom or
    /// remote advertisements disappeared. File calls are synchronous bounded
    /// chunk operations; their OS blocking time cannot be forcibly interrupted.
    pub async fn unindex_file(
        &mut self,
        input: &mut File,
        filename: &Path,
        fs_source: EndpointSource,
        store: Client<'_, '_, '_>,
        options: Options<'_>,
        control: impl FnMut(Observation) -> Control,
    ) -> Result<Report, Box<Failure>> {
        self.unindex_file_recorded(
            input,
            filename,
            fs_source,
            store,
            options,
            control,
            &mut Immediate,
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "The sole existing file/native owner accepts one explicit private persistence boundary without replacing original request ownership"
    )]
    pub(crate) async fn unindex_file_recorded(
        &mut self,
        input: &mut File,
        filename: &Path,
        fs_source: EndpointSource,
        mut store: Client<'_, '_, '_>,
        options: Options<'_>,
        mut control: impl FnMut(Observation) -> Control,
        recorder: &mut impl Recorder,
    ) -> Result<Report, Box<Failure>> {
        let mut report = Report {
            file_id: None,
            content: None,
            observation: Observation::default(),
            reconstructed_keywords: 0,
            selected_keywords: 0,
            fs_admitted: false,
            unindexed: false,
            retained_unindexed: false,
            response: None,
        };
        let mut keyword_error = None;
        let mut store_cleanup = None;
        let mut fs_cleanup = None;
        let mut fs_failure = None;
        let mut settlement = None;
        let mut preceding = None;
        let mut store_closed = false;
        let outcome = async {
            if !Arc::ptr_eq(&store.clock(), &fs_source.clock())
                || store.pending() != 0
                || store.retained_replies() != (0, 0)
                || options.max_keywords == 0
                || options.max_keywords > 4096
                || options.max_rows_per_keyword == 0
                || options.max_rows_per_keyword > 65536
                || options.max_total_rows == 0
                || options.max_total_rows > 1048576
                || options.block.max_label_bytes == 0
                || options.block.max_label_bytes > 4096
                || options.block.max_wire_bytes > 65535
                || options.block.metadata.max_plain_bytes > 8 * 1024 * 1024
                || options.extra_keywords.len() > options.max_keywords
            {
                return Err(RunError::from(Error::from(Fault::InvalidInput)));
            }
            if options.metadata.manual_items() != 0 {
                keyword_error = Some(extraction::Error::MetadataSettings(
                    gnunet_extractor_host::NativeError::Invalid(
                        "unindex excludes manual publication annotations",
                    ),
                ));
                return Ok(());
            }
            let mut time =
                TimeLimit::bounded(store.clock(), options.deadline, options.native_deadline)?;
            gate(&mut time, report.observation, &mut control).await?;
            let original = Stamp::of(input)?;
            original.stable(input, filename)?;
            self.prepare(
                Content {
                    key: [0; 64],
                    query: [0; 64],
                    size: original.bytes,
                },
                options.limits,
            )
            .map_err(Error::from)?;
            input.rewind().map_err(Error::from)?;
            let mut hash = Hash512State::new();
            while report.observation.hashed_bytes < original.bytes {
                gate(&mut time, report.observation, &mut control).await?;
                original.stable(input, filename)?;
                let count = (original.bytes - report.observation.hashed_bytes)
                    .min(self.plain.len() as u64) as usize;
                let read = match input.read(&mut self.plain[..count]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    value => value.map_err(Error::from)?,
                };
                if read == 0 {
                    return Err(Error::from(crate::Error::SourceChanged).into());
                }
                original.stable(input, filename)?;
                hash.update(&self.plain[..read]);
                report.observation.hashed_bytes += read as u64;
            }
            let mut extra = [0u8; 1];
            loop {
                gate(&mut time, report.observation, &mut control).await?;
                match input.read(&mut extra) {
                    Ok(0) => break,
                    Ok(_) => return Err(Error::from(crate::Error::SourceChanged).into()),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(Error::from(e).into()),
                }
            }
            original.stable(input, filename)?;
            let file_id = hash.finish();
            report.file_id = Some(file_id);
            recorder
                .source(file_id, original.bytes)
                .map_err(Error::from)?;
            let retained_keywords = recorder.retained_keywords().map_err(Error::from)?;
            let mut keywords = if let Some(words) = retained_keywords {
                words
            } else {
                match extraction::file_keywords_with_metadata(
                    input,
                    filename,
                    Default::default(),
                    options.metadata.clone(),
                    |_| {
                        if Instant::now() >= options.native_deadline {
                            Control::Cancel
                        } else {
                            control(report.observation)
                        }
                    },
                ) {
                    Ok(terms) => {
                        report.reconstructed_keywords = terms.len();
                        terms
                    }
                    Err(e) => {
                        keyword_error = Some(e);
                        return Ok(());
                    }
                }
            };
            gate(&mut time, report.observation, &mut control).await?;
            original.stable(input, filename)?;
            if keywords.len() > options.max_keywords {
                return Err(Error::from(Fault::Capacity).into());
            }
            for keyword in options.extra_keywords {
                add_keyword(&mut keywords, keyword, &options)?;
            }
            recorder
                .keywords(&mut keywords, true)
                .map_err(Error::from)?;
            report.selected_keywords = keywords.len();
            input.rewind().map_err(Error::from)?;
            let mut second = Hash512State::new();
            let mut encoder =
                FileEncoder::new(original.bytes, &mut self.keys).map_err(Error::from)?;
            while let Some(node) = encoder.next() {
                gate(&mut time, report.observation, &mut control).await?;
                original.stable(input, filename)?;
                let encoded = if node.level() == 0 {
                    let count = node.plaintext_bytes();
                    let mut got = 0;
                    while got < count {
                        gate(&mut time, report.observation, &mut control).await?;
                        match input.read(&mut self.plain[got..count]) {
                            Ok(0) => return Err(Error::from(crate::Error::SourceChanged).into()),
                            Ok(n) => got += n,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(Error::from(e).into()),
                        }
                    }
                    original.stable(input, filename)?;
                    second.update(&self.plain[..count]);
                    encoder
                        .push_data(&self.plain[..count], &mut self.encoded)
                        .map_err(Error::from)?
                } else {
                    encoder
                        .emit_index(&mut self.index, &mut self.encoded)
                        .map_err(Error::from)?
                };
                if encoder.next().is_none() {
                    loop {
                        gate(&mut time, report.observation, &mut control).await?;
                        match input.read(&mut extra) {
                            Ok(0) => break,
                            Ok(_) => return Err(Error::from(crate::Error::SourceChanged).into()),
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(Error::from(e).into()),
                        }
                    }
                    original.stable(input, filename)?;
                    if second.clone().finish() != file_id {
                        return Err(Error::from(crate::Error::SourceChanged).into());
                    }
                }
                let key = encoded.block().key().query;
                let ciphertext = encoded.block().bytes();
                report.observation.encoded.blocks += 1;
                report.observation.encoded.encoded_bytes += ciphertext.len() as u128;
                if node.level() == 0 {
                    report.observation.encoded.plaintext_bytes += node.plaintext_bytes() as u64;
                }
                let mut descriptor = [0u8; 72];
                let value = if node.level() == 0 {
                    descriptor[..64].copy_from_slice(&file_id);
                    descriptor[64..].copy_from_slice(&node.range().start.to_be_bytes());
                    descriptor.as_slice()
                } else {
                    ciphertext
                };
                remove(
                    &mut store,
                    &mut time,
                    &key,
                    value,
                    false,
                    &mut report.observation,
                    &mut control,
                    recorder,
                )
                .await?;
            }
            let content = encoder
                .content()
                .ok_or_else(|| Error::from(Fault::NotReady))?;
            report.content = Some(content);
            original.stable(input, filename)?;
            let mut inflater = Inflate::new();
            if !keywords.is_empty() {
                crate::resize(&mut self.record, options.block.max_wire_bytes, 0)
                    .map_err(Error::from)?;
            }
            for keyword in &keywords {
                gate(&mut time, report.observation, &mut control).await?;
                original.stable(input, filename)?;
                let opener =
                    ublock::Context::keyword(keyword, options.block).map_err(RunError::block)?;
                let query = *opener.query();
                if recorder.keyword(&query).map_err(Error::from)? {
                    report.observation.retained_keyword_selections += 1;
                    continue;
                }
                let mut next_uid = 0;
                for ordinal in 0..options.max_rows_per_keyword {
                    gate(&mut time, report.observation, &mut control).await?;
                    if report.observation.keyword_rows >= options.max_total_rows as u64 {
                        return Err(Error::from(Fault::Capacity).into());
                    }
                    let answer = match publish::execute_controlled(
                        &mut store,
                        &mut time,
                        Request::Get {
                            key: Some(&query),
                            kind: 9,
                            next_uid,
                            random: false,
                        },
                        None,
                        Some(query),
                        || control(report.observation) == Control::Continue,
                    )
                    .await
                    {
                        Ok(answer) => {
                            report.observation.keyword_queries += 1;
                            report.observation.last_store_submitted = true;
                            answer
                        }
                        Err(failure) => {
                            report.observation.last_store_submitted =
                                failure.submission == publish::Submission::Submitted;
                            if failure.submission == publish::Submission::Submitted {
                                report.observation.keyword_queries += 1;
                            }
                            report.observation.requested_cancel |= failure.requested_cancel;
                            return Err(RunError {
                                cause: Some(failure.cause),
                                block: None,
                                settlement: failure.settlement_error,
                            });
                        }
                    };
                    report.observation.requested_cancel |= answer.requested_cancel;
                    if answer.taken.completion.interruption.is_some()
                        || answer.requested_cancel
                        || answer.cause.is_some()
                    {
                        return Err(publish::refused(answer, Some(query)).into());
                    }
                    if !answer.taken.response().is_ok_and(|response| {
                        matches!(response, Some(Response::Data(_) | Response::End))
                    }) {
                        return Err(publish::refused(answer, Some(query)).into());
                    }
                    let frame = answer
                        .taken
                        .into_frame()
                        .ok_or_else(|| Error::from(Fault::NotReady))?;
                    let data = match Response::decode(frame.bytes()).map_err(Error::from)? {
                        Response::End => {
                            report.observation.keyword_ends += 1;
                            recorder.keyword_end(&query).map_err(Error::from)?;
                            break;
                        }
                        Response::Data(data) => data,
                        _ => return Err(Error::from(Fault::Malformed).into()),
                    };
                    report.observation.keyword_rows += 1;
                    if data.uid < next_uid {
                        return Err(Error::from(Fault::Stale).into());
                    }
                    let matches = if data.kind == 9 && data.key == &query {
                        match opener.open(data.value, &mut self.record) {
                            Ok(plain) => {
                                crate::resize(
                                    &mut self.metadata_plain,
                                    options.block.metadata.max_plain_bytes,
                                    0,
                                )
                                .map_err(Error::from)?;
                                plain
                                    .decode(
                                        &mut self.metadata_plain,
                                        &mut inflater,
                                        gnunet_fs::metadata::Mode::Strict,
                                    )
                                    .and_then(|record| record.uri())
                                    .is_ok_and(|uri| match uri {
                                        Uri::Content(found) => {
                                            found.key == content.key && found.query == content.query
                                        }
                                        Uri::Location(location) => {
                                            let found = location.content();
                                            found.key == content.key && found.query == content.query
                                        }
                                        _ => false,
                                    })
                            }
                            Err(_) => false,
                        }
                    } else {
                        false
                    };
                    if matches {
                        report.observation.keyword_matches += 1;
                        original.stable(input, filename)?;
                        remove(
                            &mut store,
                            &mut time,
                            &query,
                            data.value,
                            true,
                            &mut report.observation,
                            &mut control,
                            recorder,
                        )
                        .await?;
                        break;
                    }
                    report.observation.skipped_rows += 1;
                    next_uid = data
                        .uid
                        .checked_add(1)
                        .ok_or_else(|| Error::from(Fault::Overflow))?;
                    if ordinal + 1 == options.max_rows_per_keyword {
                        return Err(Error::from(Fault::Capacity).into());
                    }
                }
            }
            gate(&mut time, report.observation, &mut control).await?;
            original.stable(input, filename)?;
            store_cleanup = store.close().err();
            store_closed = true;
            match notify(
                fs_source,
                file_id,
                &mut time,
                options.deadline,
                &mut report,
                &mut control,
                recorder,
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(failure) => {
                    fs_cleanup = failure.cleanup;
                    fs_failure = failure.failure;
                    preceding = failure.preceding;
                    match failure.cause {
                        Some(cause) => Err(cause.into()),
                        None => Ok(()),
                    }
                }
            }
        }
        .await;
        if !store_closed {
            store_cleanup = store.close().err();
        }
        drop(store);
        let (operation, keyword_context) = match outcome {
            Ok(()) => (None, None),
            Err(error) => {
                settlement = error.settlement;
                (error.cause, error.block)
            }
        };
        if operation.is_some()
            || keyword_context.is_some()
            || keyword_error.is_some()
            || store_cleanup.is_some()
            || fs_cleanup.is_some()
        {
            Err(Box::new(Failure {
                report,
                operation,
                keywords: keyword_error,
                keyword_context,
                store_cleanup,
                fs_cleanup,
                fs_failure,
                settlement,
                preceding,
            }))
        } else {
            Ok(report)
        }
    }
}
