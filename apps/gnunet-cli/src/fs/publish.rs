//! One-shot ordinary publication, sharing actual auto-share metadata/KSK plans.
//! The preparation worker is joined and requests optional LOCs from the CLI's FS owner.
mod location;
pub(super) mod progress;
pub(super) mod settings;
mod standalone;
use super::stop::StopEvents;
use super::{
    publication_options,
    service::{duration, target},
};
use gnunet::fs_host::{
    Buffers,
    extraction::MetadataSettings,
    ipc::EndpointSource,
    publication::{
        self as task, Task,
        auto_prepare::{self, Annotations, MetadataArtifact, Policy, Prepared, RootKeywords},
    },
};
use serde_json::{Value, json};
pub(crate) use standalone::run as run_official;
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(super) struct Mode {
    pub indexed: bool,
    pub tree: bool,
}
struct Arguments {
    source: PathBuf,
    store: PathBuf,
    fs: Option<PathBuf>,
    state: Option<PathBuf>,
    interval: u64,
    metadata: super::metadata_options::Arguments,
    publication: publication_options::Selection,
}
fn arguments(args: &[impl AsRef<OsStr>], mode: Mode) -> Result<Arguments, Box<dyn Error>> {
    let mut positional = Vec::new();
    positional.try_reserve_exact(4)?;
    let mut state = None;
    let mut metadata = super::metadata_options::Arguments::default();
    let mut publication = publication_options::Selection::default();
    let mut literal = false;
    let mut i = 0;
    while i < args.len() {
        let raw = args[i].as_ref();
        if !literal && raw == OsStr::new("--") {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && metadata.consume(args, &mut i, true)? {
            continue;
        }
        if !literal && publication.consume(args, &mut i)? {
            continue;
        }
        if !literal && raw == OsStr::new("--state") {
            i += 1;
            if state.is_some() {
                return Err("--state may be specified only once".into());
            }
            state = Some(PathBuf::from(
                args.get(i)
                    .ok_or("--state requires a new directory")?
                    .as_ref(),
            ));
        } else {
            if !literal && raw.as_encoded_bytes().starts_with(b"-") {
                return Err("unknown publication option (use -- for a literal path)".into());
            }
            if positional.len() == 4 {
                return Err("too many publication arguments".into());
            }
            positional.push(raw);
        }
        i += 1;
    }
    let count = if mode.indexed { 3 } else { 2 };
    if !(count..=count + 1).contains(&positional.len()) {
        return Err(
            "publication requires service socket(s), source and optional timeout seconds".into(),
        );
    }
    let interval = duration(positional.get(count))?;
    let source = PathBuf::from(positional[count - 1]);
    if source_is_tree(&source)? != mode.tree {
        return Err(
            "publication source must be the selected regular file or directory, never a symlink"
                .into(),
        );
    }
    Ok(Arguments {
        source,
        store: PathBuf::from(positional[usize::from(mode.indexed)]),
        fs: mode.indexed.then(|| PathBuf::from(positional[0])),
        state,
        interval,
        metadata,
        publication,
    })
}
fn source_is_tree(source: &Path) -> Result<bool, Box<dyn Error>> {
    let kind = std::fs::symlink_metadata(source)?.file_type();
    if !kind.is_file() && !kind.is_dir() {
        return Err("publication requires a regular file or directory".into());
    }
    Ok(kind.is_dir())
}
fn state_directory(selected: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(path) = selected {
        super::create_private_directory(&path)?;
        return std::fs::canonicalize(path);
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..64 {
        let serial = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("publication state sequence exhausted"))?;
        let path =
            std::env::temp_dir().join(format!("gnunet-publish-{}-{serial}", std::process::id()));
        match super::create_private_directory(&path) {
            Ok(()) => return std::fs::canonicalize(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "publication state name attempts exhausted",
    ))
}
struct Gate {
    stop: Arc<AtomicBool>,
    observed_cancel: Arc<AtomicBool>,
    signals: StopEvents,
    alarm: std::pin::Pin<Box<tokio::time::Sleep>>,
    hard: Instant,
    expired: bool,
    signal_error: Option<io::Error>,
}
impl Gate {
    fn new(hard: Instant) -> io::Result<Self> {
        Ok(Self {
            stop: Arc::new(AtomicBool::new(false)),
            observed_cancel: Arc::new(AtomicBool::new(false)),
            signals: StopEvents::new()?,
            alarm: Box::pin(tokio::time::sleep_until(hard.into())),
            hard,
            expired: false,
            signal_error: None,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) {
        if Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready() {
            self.expired = true;
            self.stop.store(true, Ordering::Release);
        }
        if !self.stop.load(Ordering::Acquire) && self.signals.poll(cx) {
            self.stop.store(true, Ordering::Release);
            self.signal_error = self.signals.take_failure();
            if self.signal_error.is_none() {
                self.observed_cancel.store(true, Ordering::Release);
            }
        }
    }
}
#[derive(Debug)]
enum OperationFailure {
    Source(gnunet_client_host::ConnectError),
    Native(Box<task::Failure>),
    Incomplete(Box<task::Outcome>),
}
impl fmt::Display for OperationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(e) => e.fmt(f),
            Self::Native(e) => e.fmt(f),
            Self::Incomplete(o) => write!(f, "publication task stopped/cleanup failed: {o:?}"),
        }
    }
}
impl Error for OperationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(e) => Some(e),
            Self::Native(e) => Some(e.as_ref()),
            Self::Incomplete(o) => o
                .cleanup
                .as_ref()
                .map(|e| e as &(dyn Error + 'static))
                .or_else(|| {
                    o.last_native
                        .as_ref()
                        .and_then(|n| n.settlement_error())
                        .map(|e| e as _)
                })
                .or_else(|| {
                    o.last_index
                        .as_ref()
                        .and_then(|n| n.retirement_error())
                        .map(|e| e as _)
                }),
        }
    }
}
#[derive(Debug)]
struct Failure {
    state: PathBuf,
    original: Option<Box<dyn Error>>,
    worker: Option<io::Error>,
    signal: Option<io::Error>,
    stopped: bool,
    expired: bool,
    cancel_observed: bool,
    task: Option<OperationFailure>,
    output: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "publication command did not finish cleanly; original tasks retained at {:?}",
            self.state
        )?;
        if let Some(e) = &self.original {
            write!(f, "; original: {e}")?;
        }
        if let Some(e) = &self.worker {
            write!(f, "; preparation worker: {e}")?;
        }
        if let Some(e) = &self.task {
            write!(f, "; task: {e}")?;
        }
        if let Some(e) = &self.signal {
            write!(f, "; signal: {e}")?;
        }
        if let Some(e) = &self.output {
            write!(f, "; output: {e}")?;
        }
        write!(
            f,
            "; stopped={}, deadline={}, signal_cancel_observed={}",
            self.stopped, self.expired, self.cancel_observed
        )
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.task.as_ref().map(|e| e as _))
            .or_else(|| self.worker.as_ref().map(|e| e as _))
            .or_else(|| self.signal.as_ref().map(|e| e as _))
            .or_else(|| self.output.as_ref().map(|e| e as _))
    }
}
fn completed(
    result: Result<task::Outcome, Box<task::Failure>>,
) -> Result<task::Outcome, OperationFailure> {
    let outcome = result.map_err(OperationFailure::Native)?;
    if outcome.reason != task::StopReason::Complete
        || outcome.completed.is_none()
        || outcome.cleanup.is_some()
        || outcome
            .last_native
            .as_ref()
            .is_some_and(|n| n.settlement_error().is_some())
        || outcome
            .last_index
            .as_ref()
            .is_some_and(|n| n.retirement_error().is_some())
    {
        return Err(OperationFailure::Incomplete(Box::new(outcome)));
    }
    Ok(outcome)
}
async fn run_task(
    original: &mut Task,
    store: &EndpointSource,
    fs: Option<&EndpointSource>,
    deadline: gnunet::types::AbsoluteTime,
    gate: &mut Gate,
    buffers: &mut Buffers,
) -> Result<task::Outcome, OperationFailure> {
    // Construct exactly one original run. Loss/Unknown never restarts it here.
    let stop = Arc::clone(&gate.stop);
    let observed_cancel = Arc::clone(&gate.observed_cancel);
    let hard = gate.hard;
    let store = store.duplicate().map_err(OperationFailure::Source)?;
    let result = if let Some(fs) = fs {
        let fs = fs.duplicate().map_err(OperationFailure::Source)?;
        let running = original.run_indexed(fs, store, buffers, deadline, move |_| {
            // Verification may call this cooperatively inside one Future poll.
            // Preserve the same native hard even before the outer poll returns.
            // Keep an already observed user cancel even if native time later
            // reaches hard. Other stop facts never imply a user cancellation.
            // The Task's own canonical-deadline precedence is unchanged.
            if observed_cancel.load(Ordering::Acquire) {
                task::Control::Cancel
            } else if Instant::now() >= hard || stop.load(Ordering::Acquire) {
                task::Control::Pause
            } else {
                task::Control::Continue
            }
        });
        let mut running = std::pin::pin!(running);
        poll_fn(|cx| {
            gate.poll(cx);
            running.as_mut().poll(cx)
        })
        .await
    } else {
        let running = original.run(store, buffers, deadline, move |_| {
            // Verification may call this cooperatively inside one Future poll.
            // Preserve the same native hard even before the outer poll returns.
            // Keep an already observed user cancel even if native time later
            // reaches hard. Other stop facts never imply a user cancellation.
            // The Task's own canonical-deadline precedence is unchanged.
            if observed_cancel.load(Ordering::Acquire) {
                task::Control::Cancel
            } else if Instant::now() >= hard || stop.load(Ordering::Acquire) {
                task::Control::Pause
            } else {
                task::Control::Continue
            }
        });
        let mut running = std::pin::pin!(running);
        poll_fn(|cx| {
            gate.poll(cx);
            running.as_mut().poll(cx)
        })
        .await
    };
    completed(result)
}
pub(super) fn run(
    args: &[impl AsRef<OsStr>],
    mode: Mode,
    out: &mut super::Output<'_, impl Write>,
) -> Result<(), Box<dyn Error>> {
    let mut args = arguments(args, mode)?;
    let hard = Instant::now()
        .checked_add(Duration::from_micros(args.interval))
        .ok_or("publication native deadline overflow")?;
    out.deadline(hard);
    let store = EndpointSource::unix(std::mem::take(&mut args.store));
    let fs = args.fs.take().map_or(FsAccess::None, |path| {
        FsAccess::Index(EndpointSource::unix_with_clock(path, store.clock()))
    });
    let deadline = target(&store, args.interval)?;
    let blocks = args.publication.select(store.clock().as_ref())?;
    let metadata = std::mem::take(&mut args.metadata).select()?;
    if Instant::now() >= hard {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "metadata configuration exceeded the original publication deadline",
        )
        .into());
    }
    let execution = Execution {
        source: args.source,
        state: args.state,
        hard,
        store,
        fs,
        deadline,
        blocks,
        metadata,
        root_keywords: RootKeywords::default(),
        creation_time: None,
        style: Style::Json,
        namespace: None,
        verbose: 0,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(execute(execution, out))
}
struct Execution {
    source: PathBuf,
    state: Option<PathBuf>,
    hard: Instant,
    store: EndpointSource,
    fs: FsAccess,
    deadline: gnunet::types::AbsoluteTime,
    blocks: gnunet::fs_host::network::BlockOptions,
    metadata: MetadataSettings,
    root_keywords: RootKeywords,
    creation_time: Option<gnunet::types::AbsoluteTime>,
    style: Style,
    namespace: Option<(standalone::namespace::Authorization, Option<PathBuf>)>,
    verbose: u32,
}

enum FsAccess {
    None,
    Index(EndpointSource),
    Sign(EndpointSource),
    IndexAndSign(EndpointSource),
}

impl FsAccess {
    fn configured(endpoint: EndpointSource, indexed: bool, anonymity: u32) -> Self {
        match (indexed, anonymity == 0) {
            (false, false) => Self::None,
            (true, false) => Self::Index(endpoint),
            (false, true) => Self::Sign(endpoint),
            (true, true) => Self::IndexAndSign(endpoint),
        }
    }

    fn index(&self) -> Option<&EndpointSource> {
        match self {
            Self::Index(endpoint) | Self::IndexAndSign(endpoint) => Some(endpoint),
            Self::None | Self::Sign(_) => None,
        }
    }

    fn signer(&self) -> Option<&EndpointSource> {
        match self {
            Self::Sign(endpoint) | Self::IndexAndSign(endpoint) => Some(endpoint),
            Self::None | Self::Index(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Style {
    Json,
    Official,
}
async fn execute(
    execution: Execution,
    out: &mut super::Output<'_, impl Write>,
) -> Result<(), Box<dyn Error>> {
    let Execution {
        source,
        state,
        hard,
        store,
        fs,
        deadline,
        blocks,
        metadata,
        root_keywords,
        creation_time,
        style,
        namespace,
        verbose,
    } = execution;
    let manual_items = metadata.manual_items();
    let automatic_keywords = metadata.automatic_keywords_enabled();
    let format_extraction = metadata.format_extraction_enabled();

    let mut gate = Gate::new(hard)?;
    let state = state_directory(state)?;
    let mut failure = Failure {
        state: state.clone(),
        original: None,
        worker: None,
        signal: None,
        stopped: false,
        expired: false,
        cancel_observed: false,
        task: None,
        output: None,
    };
    let index = fs.index();
    let policy = Policy {
        indexed: index.is_some(),
        metadata: gnunet::fs_host::extraction::Policy {
            extract: automatic_keywords,
            creation_time,
            ..Default::default()
        },
        ..Policy::default()
    };
    let worker_state = state.clone();
    let display_source = matches!(style, Style::Official).then(|| source.clone());
    let verbose_source = (verbose != 0).then(|| source.clone());
    let (reporter, updates) = progress::channel(verbose);
    let stop = Arc::clone(&gate.stop);
    let (worker_signer, signing_owner) = fs
        .signer()
        .map(|source| location::Owner::new(source, blocks.expiration, deadline, hard))
        .unzip();
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    let worker = std::thread::Builder::new()
        .name("gnunet-fs-prepare".into())
        .spawn(move || {
            let mut buffers = Buffers::new();
            let mut report = |event: task::plan::tree::Event<'_>| {
                reporter
                    .as_ref()
                    .map_or(gnunet::fs_host::Control::Continue, |reporter| {
                        reporter.report(event)
                    })
            };
            let observer: task::plan::tree::Observer<'_> = (verbose != 0).then_some(&mut report);
            let control = move |_| {
                if stop.load(Ordering::Acquire) || Instant::now() >= hard {
                    gnunet::fs_host::Control::Cancel
                } else {
                    gnunet::fs_host::Control::Continue
                }
            };
            let annotations = Annotations {
                metadata,
                root_keywords: &root_keywords,
                observer,
            };
            let result = if let Some(signer) = worker_signer {
                auto_prepare::prepare_with_locations(
                    &worker_state,
                    &source,
                    &mut buffers,
                    blocks,
                    task::Limits::default(),
                    policy,
                    annotations,
                    &mut |content| signer.sign(content),
                    control,
                )
            } else {
                auto_prepare::prepare_with_annotations(
                    &worker_state,
                    &source,
                    &mut buffers,
                    blocks,
                    task::Limits::default(),
                    policy,
                    annotations,
                    control,
                )
            };
            let _undelivered = sender.send(result);
        });
    let mut prepared: Option<Prepared> = None;
    match worker {
        Err(e) => failure.worker = Some(e),
        Ok(worker) => {
            let mut warning = None;
            let result = {
                let stop = Arc::clone(&gate.stop);
                let mut signer = std::pin::pin!(async {
                    if let Some(owner) = signing_owner {
                        owner.run(&stop, &mut warning).await;
                    }
                });
                let mut preparation = std::pin::pin!(async {
                    if let Some(source) = verbose_source.as_deref() {
                        failure.output =
                            progress::drain(updates, source, out, &mut gate).await.err();
                    }
                    poll_fn(|cx| {
                        gate.poll(cx);
                        std::pin::Pin::new(&mut receiver).poll(cx)
                    })
                    .await
                });
                let mut signer_finished = false;
                poll_fn(|cx| {
                    let result = preparation.as_mut().poll(cx);
                    if !signer_finished {
                        signer_finished = signer.as_mut().poll(cx).is_ready();
                    }
                    result
                })
                .await
            };
            if let Some(reason) = warning {
                let _diagnostic = writeln!(
                    io::stderr().lock(),
                    "FS location signing unavailable, using CHK for remaining objects: {reason}"
                );
            }
            // A cancel/deadline does not detach the worker or abandon its local
            // journal. A non-preemptible filesystem syscall may delay this join.
            if worker.join().is_err() {
                failure.worker = Some(io::Error::other("publication preparation worker panicked"));
            }
            match result {
                Ok(Ok(value)) => prepared = Some(value),
                Ok(Err(e)) => failure.original = Some(Box::new(e)),
                Err(e) => failure.original = Some(Box::new(e)),
            }
        }
    }
    let mut summaries = Vec::<Value>::new();
    let mut completed_tasks = 0usize;
    let mut content_uri = None;
    let mut display_records = None;
    let mut expected_keywords = 0usize;
    let mut metadata_objects = 0usize;
    if let Some(mut prepared) = prepared {
        expected_keywords = prepared.keywords.len();
        metadata_objects = prepared.metadata.len();
        if matches!(style, Style::Json) {
            content_uri = Some(prepared.content_uri.clone());
        }
        // Enabled automatic metadata with no usable KSK is an explicit refusal,
        // never successful searchable publication via an empty placeholder.
        if automatic_keywords && expected_keywords == 0 {
            failure.original.get_or_insert_with(||"automatic metadata produced no representable keyword task; use -D for explicit content-only publication".into());
        }
        if matches!(style, Style::Official) {
            display_records = Some(prepared.metadata);
        }
        if failure.original.is_none() && failure.worker.is_none() {
            let mut buffers = Buffers::new();
            for (name, original, index) in
                std::iter::once((Path::new("content"), &mut prepared.content, index)).chain(
                    prepared
                        .keywords
                        .iter_mut()
                        .map(|k| (k.name.as_path(), &mut k.task, None)),
                )
            {
                poll_fn(|cx| {
                    gate.poll(cx);
                    Poll::Ready(())
                })
                .await;
                if gate.stop.load(Ordering::Acquire) {
                    break;
                }
                match run_task(original, &store, index, deadline, &mut gate, &mut buffers).await {
                    Ok(outcome) => {
                        completed_tasks += 1;
                        if matches!(style, Style::Json) {
                            summaries.push(json!({"task":name.to_str(),"task_bytes":crate::argument::native_bytes(name.as_os_str()),"accepted_puts":outcome.progress.recorded.accepted,
                                    "accepted_bytes":outcome.progress.recorded.bytes,"verified_puts":outcome.completed.as_ref().map(|c|c.verified.puts())}));
                        }
                    }
                    Err(e) => {
                        failure.task = Some(e);
                        break;
                    }
                }
            }
        }
    }
    let all_tasks = completed_tasks == expected_keywords + 1;
    let mut namespace_uri = None;
    if all_tasks && let Some((namespace, graph_root)) = namespace {
        let result = async {
            let root = display_records
                .as_ref()
                .and_then(|records| {
                    records
                        .iter()
                        .find(|record| record.relative.as_os_str().is_empty())
                })
                .ok_or("publication namespace has no prepared root")?;
            let target = gnunet::fs::Uri::parse(&root.target, Default::default())?;
            if !matches!(
                target,
                gnunet::fs::Uri::Content(_) | gnunet::fs::Uri::Location(_)
            ) {
                return Err::<_, Box<dyn Error>>(
                    "publication namespace root is not a CHK or LOC URI".into(),
                );
            }
            let uri = namespace.uri()?;
            namespace
                .publish_content(
                    store,
                    target,
                    &root.wire,
                    gnunet::fs_host::network::ublock::UblockOptions::new(deadline, blocks),
                    graph_root.as_deref(),
                    &mut gate,
                )
                .await?;
            Ok(uri)
        }
        .await;
        match result {
            Ok(uri) => namespace_uri = Some(uri),
            Err(error) => failure.original = Some(error),
        }
    }
    // Capture a hard observed by a synchronous verification callback before
    // reporting the result. Do not restart a timer or replace the original run.
    poll_fn(|cx| {
        gate.poll(cx);
        Poll::Ready(())
    })
    .await;
    failure.stopped = gate.stop.load(Ordering::Acquire);
    failure.expired = gate.expired;
    failure.cancel_observed = gate.observed_cancel.load(Ordering::Acquire);
    failure.signal = gate.signal_error.take();
    let success = all_tasks
        && failure.original.is_none()
        && failure.worker.is_none()
        && failure.task.is_none()
        && !failure.stopped
        && failure.signal.is_none();
    out.cleanup()?;
    let output = if let Some(source) = display_source {
        if success {
            let records = display_records.ok_or("publication has no completed object directory")?;
            official_receipt(out, &source, records, namespace_uri.as_deref())
        } else {
            Ok(())
        }
    } else {
        (|| -> io::Result<()> {
            serde_json::to_writer(&mut *out,&json!({"event":if success{"fs_publication_complete"}else{"fs_publication_incomplete"},
                "state_directory":state.to_str(),"state_directory_bytes":crate::argument::native_bytes(state.as_os_str()),"state_retained":true,"uri_bytes":content_uri,
                "metadata_objects":metadata_objects,"manual_metadata_items":manual_items,"expected_keyword_tasks":expected_keywords,"automatic_keywords_enabled":automatic_keywords,"format_extraction_enabled":format_extraction,
                "native_deadline":failure.expired,"stop_observed":failure.stopped,"signal_cancel_observed":failure.cancel_observed,
                "completed_tasks":summaries,"searchability":"only the actually accepted selected keyword tasks; no global reachability proof",
                "error":if success{None}else{Some(failure.to_string())},"task_facts":failure.task.as_ref().map(|e|format!("{e:?}"))}))
                .map_err(io::Error::other)?;
            writeln!(out)?;
            out.flush()
        })()
    };
    if let Err(error) = output {
        failure.output.get_or_insert(error);
    }
    poll_fn(|cx| {
        gate.poll(cx);
        Poll::Ready(())
    })
    .await;
    failure.stopped |= gate.stop.load(Ordering::Acquire);
    failure.expired |= gate.expired;
    failure.cancel_observed |= gate.observed_cancel.load(Ordering::Acquire);
    if failure.signal.is_none() {
        failure.signal = gate.signal_error.take();
    }
    if success && failure.output.is_none() && !failure.stopped && failure.signal.is_none() {
        Ok(())
    } else {
        Err(Box::new(failure) as Box<dyn Error>)
    }
}

fn official_receipt(
    out: &mut impl Write,
    source: &Path,
    records: Vec<MetadataArtifact>,
    namespace_uri: Option<&[u8]>,
) -> io::Result<()> {
    for record in records {
        official_object(out, source, &record.relative, &record.target)?;
        if record.relative.as_os_str().is_empty()
            && let Some(uri) = namespace_uri
        {
            official_namespace(out, uri)?;
        }
    }
    out.flush()
}

fn official_namespace(out: &mut impl Write, uri: &[u8]) -> io::Result<()> {
    out.write_all(b"Namespace URI is `")?;
    out.write_all(uri)?;
    out.write_all(b"'.\n")
}

fn official_object(
    out: &mut impl Write,
    source: &Path,
    relative: &Path,
    uri: &[u8],
) -> io::Result<()> {
    let path;
    let selected = if relative.as_os_str().is_empty() {
        source
    } else {
        path = source.join(relative);
        &path
    };
    out.write_all(b"Publishing `")?;
    out.write_all(&crate::argument::native_bytes(selected.as_os_str()))?;
    out.write_all(b"' done.\nURI is `")?;
    out.write_all(uri)?;
    out.write_all(b"'.\n")
}
