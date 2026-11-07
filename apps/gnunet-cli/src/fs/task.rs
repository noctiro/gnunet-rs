//! Explicit durable task creation, history inspection and resumed execution.
use super::publication::hex;
use super::service::{duration, target};
use gnunet::{
    fs::{Limits as UriLimits, Uri},
    fs_host::{
        Buffers, OutputDir, Repository,
        durable::{
            Cause, Disposition, Failure, FileOptions, Phase, RootMode, Status, Task, TaskControl,
            TaskProgress, store,
        },
        ipc::EndpointSource,
        network::{DownloadOptions, tree_download::TreeDownloadOptions},
    },
    types::AbsoluteTime,
};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    error::Error,
    ffi::OsStr,
    future::Future,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
    task::Poll,
};
use tokio::signal::unix::{SignalKind, signal};

fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
}
fn phase(phase: Phase) -> &'static str {
    match phase {
        Phase::Ready => "ready",
        Phase::Running => "running",
        Phase::PauseRequested => "pause_requested",
        Phase::Paused => "paused",
        Phase::CancelRequested => "cancel_requested",
        Phase::Cancelled => "cancelled",
        Phase::Complete => "complete",
        Phase::Failed => "failed",
    }
}
fn status_value(status: Status) -> Value {
    json!({
        "phase":phase(status.phase), "active_owner":status.active,
        "interrupted":status.interrupted,
        "root_identity":status.root.map(|id|json!({"device":id.device,"inode":id.inode})),
        "historical_files_known":status.known_files,
        "cleanup_pending":status.cleanup_pending, "uncertain_commits":status.uncertain_commits,
        "state_records":status.state_records, "state_fenced":status.fenced,
    })
}
pub(super) fn progress_value(progress: TaskProgress) -> Value {
    json!({
        "historical_files_known":progress.historical_files,
        "files_revalidated_this_run":progress.revalidated_files,
        "files_newly_committed_this_run":progress.new_files,
        "files_confirmed_this_run":progress.output.files_committed,
        "directories_created_this_run":progress.output.directories_created,
        "directories_verified_this_run":progress.output.directories_verified,
        "file_bytes_confirmed_this_run":progress.output.file_bytes,
        "cleanup_pending":progress.cleanup_pending,
        "uncertain_commits":progress.uncertain_commits,
        "state_records":progress.state_records,
        "file":progress.file.map(|file|json!({"selection_start":file.start,"selection_end":file.end,
            "authenticated_bytes":file.authenticated.plaintext_bytes,"authenticated_blocks":file.authenticated.blocks,
            "delivered_bytes":file.delivered_bytes,"delivered_chunks":file.delivered_chunks,
            "pending_delivery":file.pending_delivery,"selection_verified":file.selection_verified,
            "sink_finish_started":file.finish_started,"output_stage":format!("{:?}",file.output),
            "destination":file.destination.map(|value|format!("{value:?}"))})),
    })
}
fn cause_value(cause: &Cause) -> Value {
    match cause {
        Cause::Storage(error) => {
            let failure = error.failure();
            json!({"kind":"storage", "stage":failure.stage,
                "classification":format!("{:?}",failure.kind),
                "certainty":format!("{:?}",failure.certainty), "error":error.to_string()})
        }
        Cause::Model(error) => json!({"kind":"model", "classification":format!("{error:?}")}),
        Cause::Operation(error) => json!({"kind":"operation", "error":error.to_string()}),
        Cause::Output(error) => json!({
            "kind":"output", "commit_stage":format!("{:?}",error.stage),
            "authenticated_receipt":error.receipt.is_some(),
            "operation":error.operation.as_ref().map(ToString::to_string),
            "observer":error.observer.as_ref().map(cause_value),
            "cleanup":error.cleanup.as_ref().map(ToString::to_string),
        }),
        Cause::RangeOutput(error) => {
            json!({"kind":"range_output","commit_stage":format!("{:?}",error.stage),
            "receipt":error.receipt.as_ref().map(range_value),"operation":error.operation.as_ref().map(ToString::to_string),
            "observer":error.observer.as_ref().map(cause_value),"cleanup":error.cleanup.as_ref().map(ToString::to_string)})
        }
        Cause::Directory(error) => json!({
            "kind":"directory", "stage":format!("{:?}",error.stage),
            "created":error.created,
            "identity":error.identity.map(|id|json!({"device":id.device,"inode":id.inode})),
            "error":error.operation.to_string(),
        }),
        Cause::Revalidate(error) => json!({
            "kind":"revalidation", "stage":format!("{:?}",error.stage),
            "identity":error.identity.map(|id|json!({"device":id.device,"inode":id.inode})),
            "authenticated_receipt":error.receipt.is_some(), "error":error.operation.to_string(),
        }),
        Cause::RangeRevalidate(error) => {
            json!({"kind":"range_revalidation","stage":format!("{:?}",error.stage),
            "identity":error.identity.map(|id|json!({"device":id.device,"inode":id.inode})),
            "receipt":error.receipt.as_ref().map(range_value),"error":error.operation.to_string()})
        }
        Cause::Committed(error) => json!({
            "kind":"committed", "identity":{"device":error.identity.device,"inode":error.identity.inode},
            "authenticated_receipt":true, "subsequent_failure":cause_value(&error.cause),
        }),
        Cause::RangeCommitted(error) => {
            json!({"kind":"range_committed","identity":{"device":error.identity.device,"inode":error.identity.inode},
            "receipt":range_value(&error.receipt),"subsequent_failure":cause_value(&error.cause)})
        }
        Cause::Reconcile { path, reason } => json!({
            "kind":"reconciliation_required", "path":path.to_str(),
            "path_bytes":path.as_os_str().as_bytes(), "reason":reason,
        }),
        Cause::State(reason) => json!({"kind":"state_precondition", "reason":reason}),
    }
}
pub(super) fn range_value(read: &gnunet::fs_host::network::range::ReadRange) -> Value {
    json!({"selection_start":read.selection.start,"selection_end":read.selection.end,
        "content_bytes":read.content.size,"whole_file_selection":read.selection.start==0&&read.selection.end==read.content.size,
        "selection_verified":matches!(read.completion,gnunet::fs_host::network::range::Completion::Verified(_)),
        "destination":format!("{:?}",read.destination),"authenticated_bytes":read.authenticated.plaintext_bytes,
        "delivered_bytes":read.delivered_bytes,"delivered_chunks":read.delivered_chunks})
}
fn mode_value(mode: &RootMode) -> Value {
    match mode {
        RootMode::Directory => json!({"kind":"directory"}),
        RootMode::File { selection } => {
            json!({"kind":"file","selection_start":selection.start,"selection_end":selection.end})
        }
    }
}
fn failed(out: &mut impl Write, error: Box<Failure>) -> Box<dyn Error> {
    // Preserve the original typed task failure if writing diagnostic output also fails.
    let _output = row(
        out,
        &json!({
            "event":"fs_task_failed", "path":error.path.to_str(),
            "path_bytes":error.path.as_os_str().as_bytes(),
            "progress":progress_value(error.progress), "cause":cause_value(&error.cause),
            "state_failure":error.state_failure.as_ref().map(cause_value),
            "interruption":error.interruption.as_ref().map(ToString::to_string),
            "namespace_cleanup":error.namespace_cleanup.as_ref().map(ToString::to_string),
            "file_completion":error.file.as_ref().map(range_value),
            "error":error.to_string(),
        }),
    );
    error
}
pub(super) fn create_file(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    if args.len() < 3 {
        return Err("task-create-file requires task, CHK/LOC and new output file".into());
    }
    let root = Uri::parse(args[1].as_ref().as_bytes(), UriLimits::default())?;
    let content = match root {
        Uri::Content(content) => content,
        Uri::Location(location) => location.content(),
        _ => return Err("file task requires a CHK or LOC URI".into()),
    };
    let mut offset = None;
    let mut length = None;
    let mut anonymity = None;
    let mut local = false;
    let mut at = 3;
    while at < args.len() {
        let name = args[at].as_ref().as_bytes();
        if name == b"--local-only" {
            if local {
                return Err("duplicate --local-only".into());
            }
            local = true;
            at += 1;
            continue;
        }
        let value = args
            .get(at + 1)
            .ok_or("file task option requires a value")?
            .as_ref()
            .to_str()
            .ok_or("file task option requires UTF-8 digits")?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("file task option requires unsigned decimal digits".into());
        }
        match name {
            b"--offset" => {
                if offset.replace(value.parse::<u64>()?).is_some() {
                    return Err("duplicate --offset".into());
                }
            }
            b"--length" => {
                if length.replace(value.parse::<u64>()?).is_some() {
                    return Err("duplicate --length".into());
                }
            }
            b"-a" | b"--anonymity" => {
                if anonymity.replace(value.parse::<u32>()?).is_some() {
                    return Err("duplicate anonymity".into());
                }
            }
            _ => return Err("unknown file task option".into()),
        }
        at += 2;
    }
    let start = offset.unwrap_or(0);
    let end = match length {
        Some(length) => start
            .checked_add(length)
            .ok_or("selected file range overflows")?,
        None => content.size,
    };
    if start > end || end > content.size {
        return Err("selected file range lies outside original content".into());
    }
    let (parent, name) = destination(Path::new(args[2].as_ref()))?;
    let mut parent = OutputDir::open(parent)?;
    let mut download = DownloadOptions::new(AbsoluteTime::from_micros(0));
    download.anonymity = anonymity.unwrap_or(1);
    download.local_only = local;
    let task = Task::create_file(
        Path::new(args[0].as_ref()),
        &mut parent,
        name,
        root,
        FileOptions {
            download,
            selection: Some(start..end),
        },
        store::Limits::default(),
    )
    .map_err(|error| failed(out, error))?;
    row(
        out,
        &json!({"event":"fs_file_task_created","task_id":hex(&task.task_id()?),"status":status_value(task.status()?),
        "mode":mode_value(&task.manifest()?.mode),"output_name_bytes":name.as_bytes()}),
    )?;
    Ok(())
}
fn destination(path: &Path) -> Result<(&Path, &OsStr), Box<dyn Error>> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or("task output requires a name beneath an existing parent")?;
    Ok((parent, name))
}

pub(super) fn create(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let root = Uri::parse(args[1].as_ref().as_bytes(), UriLimits::default())?;
    if !matches!(root, Uri::Content(_) | Uri::Location(_)) {
        return Err("task-create requires a directory CHK or LOC URI".into());
    }
    let (parent, name) = destination(Path::new(args[2].as_ref()))?;
    let mut parent = OutputDir::open(parent)?;
    // Deadline zero is a manifest placeholder; every run supplies a new deadline.
    let options = TreeDownloadOptions::new(DownloadOptions::new(AbsoluteTime::from_micros(0)));
    let task = Task::create(
        Path::new(args[0].as_ref()),
        &mut parent,
        name,
        root,
        options,
        store::Limits::default(),
    )
    .map_err(|error| failed(out, error))?;
    row(
        out,
        &json!({
            "event":"fs_task_created", "task_id":hex(&task.task_id()?),
            "status":status_value(task.status()?),
            "output_name_bytes":name.as_bytes(),
        }),
    )?;
    Ok(())
}
pub(super) fn status(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error))?;
    let manifest = task.manifest()?;
    row(
        out,
        &json!({
            "event":"fs_task_status", "task_id":hex(&task.task_id()?),
            "status":status_value(task.status()?), "output_revalidated":false,
            "root_uri":std::str::from_utf8(&manifest.root_uri).ok(),
            "root_uri_bytes":manifest.root_uri, "output_name_bytes":manifest.relative.as_os_str().as_bytes(),
            "mode":mode_value(&manifest.mode),
        }),
    )?;
    Ok(())
}
pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let interval = duration(args.get(3))?;
    let limit = args
        .get(4)
        .map(|raw| -> Result<usize, Box<dyn Error>> {
            let text = raw
                .as_ref()
                .to_str()
                .ok_or("new-files-per-run must be UTF-8 digits")?;
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("new-files-per-run must be nonnegative decimal digits".into());
            }
            Ok(text.parse()?)
        })
        .transpose()?;
    let source = EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let deadline = target(&source, interval)?;
    let task_path = Path::new(args[1].as_ref());
    let mut task =
        Task::open(task_path, store::Limits::default()).map_err(|error| failed(out, error))?;
    let manifest = task.manifest()?;
    let (parent, name) = destination(Path::new(args[2].as_ref()))?;
    if manifest.relative != Path::new(name) {
        return Err("selected output name differs from the original task manifest".into());
    }
    let mut parent = OutputDir::open(parent)?;
    task.attach(&mut parent)
        .map_err(|error| failed(out, error))?;
    let mut cache = Repository::open(task_path.join("cache"))?;
    let mut buffers = Buffers::new();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut interrupt = signal(SignalKind::interrupt())?;
            let mut terminate = signal(SignalKind::terminate())?;
            let stop = Cell::new(false);
            let mut signal_error = None;
            let mut run =
                std::pin::pin!(
                    task.run(source, &mut buffers, &mut cache, deadline, |progress| {
                        if stop.get() || limit.is_some_and(|limit| progress.new_files >= limit) {
                            TaskControl::Pause
                        } else {
                            TaskControl::Continue
                        }
                    })
                );
            let result = std::future::poll_fn(|cx| {
                if !stop.get() {
                    for source in [&mut interrupt, &mut terminate] {
                        if let Poll::Ready(value) = source.poll_recv(cx) {
                            stop.set(true);
                            if value.is_none() {
                                signal_error = Some(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "task signal source closed",
                                ));
                            }
                        }
                    }
                }
                run.as_mut().poll(cx)
            })
            .await;
            if let Some(cause) = signal_error {
                let (outcome, task) = match result {
                    Ok(done) => (Some(done), None),
                    Err(error) => (None, Some(error)),
                };
                return Err(Box::new(SignalFailure {
                    cause,
                    outcome,
                    task,
                }) as Box<dyn Error>);
            }
            Ok::<_, Box<dyn Error>>(result)
        })?;
    match result {
        Ok(done) => {
            let event = match done.disposition {
                Disposition::Complete => "fs_task_complete",
                Disposition::Paused => "fs_task_paused",
                Disposition::Cancelled => "fs_task_cancelled",
            };
            row(
                out,
                &json!({
                    "event":event, "task_id":hex(&task.task_id()?),
                    "status":status_value(task.status()?), "progress":progress_value(done.progress),
                    "walk":done.walk.map(|walk|json!({"entries":walk.entries,"scheduled_content_bytes":walk.content_bytes})),
                    "file_completion":done.file.as_ref().map(range_value),
                }),
            )?;
            Ok(())
        }
        Err(error) => Err(failed(out, error)),
    }
}
#[derive(Debug)]
struct SignalFailure {
    cause: io::Error,
    outcome: Option<gnunet::fs_host::durable::Outcome>,
    task: Option<Box<Failure>>,
}
impl std::fmt::Display for SignalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task signal source: {}", self.cause)?;
        if let Some(error) = &self.task {
            write!(f, "; original task: {error}")?;
        }
        if let Some(done) = &self.outcome {
            write!(f, "; original task settled {:?}", done.disposition)?;
        }
        Ok(())
    }
}
impl Error for SignalFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.task {
            Some(error) => Some(error.as_ref()),
            None => Some(&self.cause),
        }
    }
}

/// Explicit local cancellation settlement; starts no FS query.
pub(super) fn cancel(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let path = Path::new(args[0].as_ref());
    let mut task =
        Task::open(path, store::Limits::default()).map_err(|error| failed(out, error))?;
    let manifest = task.manifest()?;
    let (parent, name) = destination(Path::new(args[1].as_ref()))?;
    if manifest.relative != Path::new(name) {
        return Err("selected output name differs from the original task manifest".into());
    }
    let mut parent = OutputDir::open(parent)?;
    task.attach(&mut parent)
        .map_err(|error| failed(out, error))?;
    task.request_cancel()?;
    if task.status()?.phase == Phase::Cancelled {
        row(
            out,
            &json!({"event":"fs_task_cancelled","task_id":hex(&task.task_id()?),"status":status_value(task.status()?)}),
        )?;
        return Ok(());
    }
    let mut cache = Repository::open(path.join("cache"))?;
    let done = task
        .settle_cancel(&mut parent, &mut Buffers::new(), &mut cache, |_| {
            gnunet::fs_host::Control::Continue
        })
        .map_err(|error| failed(out, error))?;
    row(
        out,
        &json!({"event":"fs_task_cancelled","task_id":hex(&task.task_id()?),"status":status_value(task.status()?),"progress":progress_value(done.progress)}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Normal CLI dispatch is checked against its actual persisted file-task selection"
    )]
    fn normal_file_task_creation_freezes_selection_and_lookup_policy() -> Result<(), Box<dyn Error>>
    {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temporary = Temporary(std::env::temp_dir().join(format!(
            "gnunet-cli-file-task-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir(&temporary.0)?;
        let mut repository = Repository::open(temporary.0.join("cache"))?;
        let bytes = b"normal regular-file content, not a directory";
        let content = Buffers::new()
            .publish(
                &mut io::Cursor::new(bytes),
                bytes.len() as u64,
                &mut repository,
                gnunet::fs_host::Limits::default(),
                |_| gnunet::fs_host::Control::Continue,
            )?
            .content;
        let uri = Uri::Content(content);
        let mut encoded = vec![0; uri.encoded_len()?];
        uri.encode(&mut encoded)?;
        let task_path = temporary.0.join("task");
        let output_path = temporary.0.join("file");
        let args = vec![
            OsString::from("task-create-file"),
            task_path.into_os_string(),
            OsString::from(std::str::from_utf8(&encoded)?),
            output_path.into_os_string(),
            "--offset".into(),
            "12".into(),
            "--length".into(),
            "8".into(),
            "--anonymity".into(),
            "0".into(),
            "--local-only".into(),
        ];
        let mut output = Vec::new();
        super::super::run(&args, &mut output)?;
        let task = Task::open(temporary.0.join("task"), store::Limits::default())?;
        let manifest = task.manifest()?;
        assert_eq!(manifest.mode, RootMode::File { selection: 12..20 });
        assert_eq!(manifest.options.transfer.anonymity, 0);
        assert!(manifest.options.transfer.local_only);
        assert!(!temporary.0.join("file").exists());
        assert!(std::str::from_utf8(&output)?.contains("fs_file_task_created"));
        Ok(())
    }
}
