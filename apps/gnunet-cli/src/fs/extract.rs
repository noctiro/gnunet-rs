//! Offline metadata preview over one owned, joined extraction worker. There is
//! no repository, publication plan, content encoder or service endpoint here.
use super::{publish::progress, stop::StopEvents};
use gnunet::fs::metadata as md;
use gnunet::fs_host::{
    Control,
    extraction::{
        self, ExtractedObject, InspectionEvent, InspectionFailure, InspectionReport, Limits,
        MetadataSettings, Policy,
    },
    publication::plan::tree::Event,
};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

struct Arguments {
    source: PathBuf,
    interval: u64,
    metadata: super::metadata_options::Arguments,
}
fn arguments(args: &[impl AsRef<OsStr>]) -> Result<Arguments, Box<dyn Error>> {
    let mut source = None;
    let mut timeout = None;
    let mut metadata = super::metadata_options::Arguments::default();
    let mut literal = false;
    let mut at = 0;
    while at < args.len() {
        let raw = args[at].as_ref();
        if !literal && raw == OsStr::new("--") {
            literal = true;
            at += 1;
            continue;
        }
        if !literal && metadata.consume(args, &mut at, true)? {
            continue;
        }
        if !literal && raw == OsStr::new("--timeout") {
            if timeout.is_some() {
                return Err("extract timeout specified more than once".into());
            }
            at += 1;
            timeout = Some(args.get(at).ok_or("--timeout requires seconds")?.as_ref());
        } else {
            if !literal && raw.as_encoded_bytes().starts_with(b"-") {
                return Err("unknown extraction option (use -- for a literal path)".into());
            }
            if source.replace(PathBuf::from(raw)).is_some() {
                return Err("extract requires exactly one source file or directory".into());
            }
        }
        at += 1;
    }
    Ok(Arguments {
        source: source.ok_or("extract requires a source file or directory")?,
        interval: super::service::duration(timeout.as_ref())?,
        metadata,
    })
}

struct Gate {
    stop: Arc<AtomicBool>,
    signals: StopEvents,
    alarm: std::pin::Pin<Box<tokio::time::Sleep>>,
    hard: Instant,
    expired: bool,
    cancelled: bool,
    signal_error: Option<io::Error>,
}
impl Gate {
    fn new(hard: Instant) -> io::Result<Self> {
        Ok(Self {
            stop: Arc::new(AtomicBool::new(false)),
            signals: StopEvents::new()?,
            alarm: Box::pin(tokio::time::sleep_until(hard.into())),
            hard,
            expired: false,
            cancelled: false,
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
            self.cancelled = self.signal_error.is_none();
        }
    }
}

#[derive(Debug)]
struct Failure {
    report: InspectionReport,
    emitted: u64,
    joined: bool,
    expired: bool,
    cancelled: bool,
    original: Option<Box<InspectionFailure>>,
    worker: Option<io::Error>,
    signal: Option<io::Error>,
    output: Option<io::Error>,
    terminal_output: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS metadata extraction incomplete: generated {}, emitted {}, joined {}, deadline {}, cancelled {}",
            self.report.objects, self.emitted, self.joined, self.expired, self.cancelled
        )?;
        if let Some(e) = &self.original {
            write!(f, "; extraction: {e}")?;
        }
        if let Some(e) = &self.worker {
            write!(f, "; worker: {e}")?;
        }
        if let Some(e) = &self.signal {
            write!(f, "; signal: {e}")?;
        }
        if let Some(e) = &self.output {
            write!(f, "; object output: {e}")?;
        }
        if let Some(e) = &self.terminal_output {
            write!(f, "; terminal output: {e}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .map(|e| e as &dyn Error)
            .or_else(|| self.worker.as_ref().map(|e| e as _))
            .or_else(|| self.signal.as_ref().map(|e| e as _))
            .or_else(|| self.output.as_ref().map(|e| e as _))
            .or_else(|| self.terminal_output.as_ref().map(|e| e as _))
    }
}
impl Failure {
    fn complete(&self) -> bool {
        self.joined
            && !self.expired
            && !self.cancelled
            && self.original.is_none()
            && self.worker.is_none()
            && self.signal.is_none()
            && self.output.is_none()
    }
}

// Serialize borrowed byte slices directly. The largest live object is bounded
// by the shared extraction policy; neither JSON Values nor a tree are retained.
fn row(out: &mut (impl Write + ?Sized), ordinal: u64, object: &ExtractedObject) -> io::Result<()> {
    let metadata =
        match md::decode_uncompressed(&object.metadata, md::Limits::default(), md::Mode::Strict)
            .map_err(io::Error::other)?
        {
            md::Decoded::Present(metadata) => metadata,
            md::Decoded::NullMarker => {
                return Err(io::Error::other("extracted metadata is a null marker"));
            }
        };
    write!(
        out,
        "{{\"event\":\"fs_extracted_object\",\"ordinal\":{ordinal},\"directory\":{},\"source_bytes\":{},\"relative\":",
        object.directory, object.source_bytes
    )?;
    serde_json::to_writer(&mut *out, &object.relative.to_str()).map_err(io::Error::other)?;
    out.write_all(b",\"relative_bytes\":")?;
    serde_json::to_writer(
        &mut *out,
        &crate::argument::native_bytes(object.relative.as_os_str()),
    )
    .map_err(io::Error::other)?;
    out.write_all(b",\"metadata\":[")?;
    for (index, item) in metadata.items().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        write!(
            out,
            "{{\"kind\":{},\"format\":{},\"text\":",
            item.kind, item.format as u32
        )?;
        serde_json::to_writer(&mut *out, &item.utf8().ok().flatten()).map_err(io::Error::other)?;
        out.write_all(b",\"data_bytes\":")?;
        serde_json::to_writer(&mut *out, item.data).map_err(io::Error::other)?;
        out.write_all(b",\"plugin_bytes\":")?;
        serde_json::to_writer(&mut *out, &item.plugin).map_err(io::Error::other)?;
        out.write_all(b",\"mime_bytes\":")?;
        serde_json::to_writer(&mut *out, &item.mime).map_err(io::Error::other)?;
        out.write_all(b"}")?;
    }
    out.write_all(b"],\"keyword_bytes\":")?;
    serde_json::to_writer(&mut *out, &object.keywords).map_err(io::Error::other)?;
    out.write_all(b",\"provider_observation\":")?;
    let provider = object.provider.map(|p| match p {
        gnunet::fs_host::extraction::MetadataObservation::EmptyUnknown => "empty-unknown",
        gnunet::fs_host::extraction::MetadataObservation::Records => "records",
    });
    serde_json::to_writer(&mut *out, &provider).map_err(io::Error::other)?;
    out.write_all(b"}\n")?;
    out.flush()
}
fn terminal(out: &mut impl Write, failure: &Failure) -> io::Result<()> {
    let r = failure.report;
    let event = if failure.complete() {
        "fs_extract_complete"
    } else {
        "fs_extract_incomplete"
    };
    let value = serde_json::json!({"event":event,"objects":r.objects,"files":r.files,"directories":r.directories,
        "source_bytes":r.source_bytes,"metadata_bytes":r.metadata_bytes,"keywords":r.keywords,"emitted":failure.emitted,
        "worker_joined":failure.joined,"deadline_elapsed":failure.expired,"cancelled":failure.cancelled,
        "extraction_error":failure.original.as_ref().map(ToString::to_string),
        "worker_error":failure.worker.as_ref().map(ToString::to_string),"signal_error":failure.signal.as_ref().map(ToString::to_string),
        "object_output_error":failure.output.as_ref().map(ToString::to_string)});
    serde_json::to_writer(&mut *out, &value).map_err(io::Error::other)?;
    out.write_all(b"\n")?;
    out.flush()
}

pub(super) fn run(
    args: &[impl AsRef<OsStr>],
    out: &mut super::Output<'_, impl Write>,
) -> Result<(), Box<dyn Error>> {
    let args = arguments(args)?;
    let hard = Instant::now()
        .checked_add(Duration::from_micros(args.interval))
        .ok_or("extraction deadline is too large")?;
    let metadata = args.metadata.select()?;
    inspect(
        args.source,
        hard,
        metadata,
        Policy::default(),
        out,
        |out, ordinal, object| row(out, ordinal, object),
        Display::Grouped,
    )
}

pub(super) enum Display {
    Grouped,
    Official {
        verbose: u32,
        publication_date: Option<Vec<u8>>,
    },
}

enum Row {
    Object(ExtractedObject),
    Update(progress::Update),
}

fn closed_output() -> extraction::Error {
    extraction::Error::Io(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "extraction output receiver closed",
    ))
}

pub(super) fn inspect(
    source: PathBuf,
    hard: Instant,
    metadata: MetadataSettings,
    mut policy: Policy,
    out: &mut super::Output<'_, impl Write>,
    mut write_object: impl FnMut(&mut dyn Write, u64, &ExtractedObject) -> io::Result<()>,
    display: Display,
) -> Result<(), Box<dyn Error>> {
    out.deadline(hard);
    policy.extract = metadata.automatic_keywords_enabled();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let mut gate = Gate::new(hard)?;
            let mut failure = Failure {
                report: InspectionReport::default(),
                emitted: 0,
                joined: false,
                expired: false,
                cancelled: false,
                original: None,
                worker: None,
                signal: None,
                output: None,
                terminal_output: None,
            };
            let stop = Arc::clone(&gate.stop);
            let worker_stop = Arc::clone(&stop);
            let (sender, mut objects) = tokio::sync::mpsc::channel(1);
            let phases = sender.clone();
            let json_summary = matches!(display, Display::Grouped);
            let verbose = match &display {
                Display::Grouped => 0,
                Display::Official { verbose, .. } => *verbose,
            };
            let verbose_source = (verbose != 0).then(|| source.clone());
            let (done, mut result) = tokio::sync::oneshot::channel();
            let worker = std::thread::Builder::new()
                .name("gnunet-fs-extract".into())
                .spawn(move || {
                    let control = move |_| {
                        if worker_stop.load(Ordering::Acquire) || Instant::now() >= hard {
                            Control::Cancel
                        } else {
                            Control::Continue
                        }
                    };
                    let visit = move |object| {
                        if stop.load(Ordering::Acquire) || Instant::now() >= hard {
                            return Err(extraction::Error::Cancelled);
                        }
                        // The consumer continues draining after any stop/output
                        // refusal until this sender closes, so backpressure can
                        // wait for that actual event without a polling wake loop.
                        sender
                            .blocking_send(Row::Object(object))
                            .map_err(|_| closed_output())?;
                        if stop.load(Ordering::Acquire) || Instant::now() >= hard {
                            return Err(extraction::Error::Cancelled);
                        }
                        Ok(())
                    };
                    let observe = move |event: InspectionEvent<'_>| {
                        let send = |phase| -> Result<(), extraction::Error> {
                            if let Some(update) = progress::select(verbose, phase) {
                                phases
                                    .blocking_send(Row::Update(update))
                                    .map_err(|_| closed_output())?;
                            }
                            Ok(())
                        };
                        match event {
                            InspectionEvent::Scanning {
                                relative,
                                directory,
                            } => send(Event::Scanning {
                                relative,
                                directory,
                            }),
                            InspectionEvent::Extracted(relative) => {
                                send(Event::Extracted(relative))
                            }
                            InspectionEvent::Complete => {
                                send(Event::ScanComplete)?;
                                send(Event::MetadataComplete)
                            }
                        }
                    };
                    let result = match display {
                        Display::Grouped => extraction::inspect_observed(
                            &source,
                            Limits::default(),
                            policy,
                            metadata,
                            control,
                            visit,
                            observe,
                        ),
                        Display::Official {
                            publication_date, ..
                        } => extraction::inspect_trimmed(
                            &source,
                            Limits::default(),
                            policy,
                            metadata,
                            publication_date.as_deref(),
                            control,
                            visit,
                            observe,
                        ),
                    };
                    let _undelivered = done.send(result);
                });
            match worker {
                Err(error) => failure.worker = Some(error),
                Ok(worker) => {
                    while let Some(item) = poll_fn(|cx| {
                        gate.poll(cx);
                        objects.poll_recv(cx)
                    })
                    .await
                    {
                        if failure.output.is_none() && !gate.stop.load(Ordering::Acquire) {
                            let output = match item {
                                Row::Object(object) => {
                                    write_object(out, failure.emitted + 1, &object)
                                        .map(|()| failure.emitted += 1)
                                }
                                Row::Update(update) => {
                                    let source = verbose_source.as_deref().ok_or_else(|| {
                                        io::Error::other("missing extraction progress source")
                                    });
                                    source.and_then(|source| {
                                        progress::write_update(out, source, update)
                                    })
                                }
                            };
                            if let Err(error) = output {
                                failure.output = Some(error);
                                gate.stop.store(true, Ordering::Release);
                            }
                        }
                    }
                    let outcome = poll_fn(|cx| {
                        gate.poll(cx);
                        std::pin::Pin::new(&mut result).poll(cx)
                    })
                    .await;
                    let joined = worker.join();
                    failure.joined = true;
                    if joined.is_err() {
                        failure.worker = Some(io::Error::other("extraction worker panicked"));
                    }
                    match outcome {
                        Ok(Ok(report)) => failure.report = report,
                        Ok(Err(error)) => {
                            failure.report = error.report;
                            failure.original = Some(error);
                        }
                        Err(error) => {
                            failure
                                .worker
                                .get_or_insert_with(|| io::Error::other(error));
                        }
                    }
                }
            }
            poll_fn(|cx| {
                gate.poll(cx);
                Poll::Ready(())
            })
            .await;
            failure.expired = gate.expired;
            failure.cancelled = gate.cancelled;
            failure.signal = gate.signal_error;
            let complete = failure.complete();
            out.cleanup()?;
            if json_summary {
                failure.terminal_output = terminal(out, &failure).err();
            }
            if complete && failure.terminal_output.is_none() {
                Ok(())
            } else {
                Err(Box::new(failure) as Box<dyn Error>)
            }
        })
}

#[cfg(test)]
mod tests;
