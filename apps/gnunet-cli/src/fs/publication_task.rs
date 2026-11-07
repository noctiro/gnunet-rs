//! Prepared publications: immutable local payloads and original DATASTORE receipts.
use super::{
    publication::hex,
    publication_options,
    service::{duration, target},
};
use gnunet::{
    fs::{Limits as UriLimits, Namespace, Uri},
    fs_host::{
        Buffers,
        durable::store,
        ipc::EndpointSource,
        namespace::{
            graph::{Graph, Limits as GraphLimits},
            key::KeyFile,
        },
        network,
        publication::{
            self as task, Attempt, Control, Counts, Disposition, GraphProgress, GraphRecorded,
            GraphResult, IndexDisposition, IndexPending, IndexProgress, Limits, Manifest,
            NativeIndexResult, NativeResult, Pending, Phase, Progress, Status, StopReason, Task,
            plan::Artifact,
        },
    },
    wire::{datastore::Response, fs::Response as FsResponse},
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
}
fn phase(value: Phase) -> &'static str {
    match value {
        Phase::Ready => "ready",
        Phase::Running => "running",
        Phase::PauseRequested => "pause_requested",
        Phase::Paused => "paused",
        Phase::CancelRequested => "cancel_requested",
        Phase::Cancelled => "cancelled",
        Phase::Complete => "complete",
        Phase::Failed => "failed",
        Phase::Uncertain => "uncertain",
    }
}
fn reason(value: StopReason) -> &'static str {
    match value {
        StopReason::Complete => "complete",
        StopReason::CallerPause => "caller_pause",
        StopReason::Deadline => "caller_deadline",
        StopReason::Cancelled => "cancelled",
    }
}
fn counts(value: Counts) -> Value {
    json!({"accepted":value.accepted,"payload_bytes":value.bytes})
}
fn attempt(value: Attempt, manifest: Option<&Manifest>) -> Value {
    let put = manifest.and_then(|manifest| manifest.plan.puts.get(value.index));
    json!({"index":value.index,"intent_record":value.intent_record,"request_hash_hex":hex(&value.request_hash),
        "put":put.map(|put|json!({"kind":put.kind,"lookup_key_hex":hex(&put.key),
            "payload_hash_hex":hex(&put.payload.hash),"payload_bytes":put.payload.bytes,
            "position":put.position.map(|position|json!({"level":position.level,"index":position.index}))}))})
}
fn pending(value: Pending, manifest: Option<&Manifest>) -> Value {
    let disposition = match value.disposition {
        Disposition::Intent => json!({"kind":"intent","automatic_retry_allowed":false}),
        Disposition::Refused {
            record_index,
            interruption,
        } => {
            json!({"kind":"refused","record_index":record_index,"interruption":interruption.map(|value|format!("{value:?}")),
                "automatic_retry_allowed":false,"requires_explicit_retry":true})
        }
        Disposition::Unknown {
            record_index,
            outcome,
            interruption,
        } => {
            json!({"kind":"unknown","record_index":record_index,"outcome":format!("{outcome:?}"),
                "interruption":interruption.map(|value|format!("{value:?}")),"automatic_retry_allowed":false})
        }
    };
    json!({"attempt":attempt(value.attempt,manifest),"disposition":disposition})
}
fn index_attempt(value: Attempt, manifest: Option<&Manifest>) -> Value {
    let source = manifest.and_then(|manifest| manifest.plan.index_sources().get(value.index));
    json!({"index":value.index,"intent_record":value.intent_record,"request_hash_hex":hex(&value.request_hash),
        "source":source.map(|source|json!({"file_id_hex":hex(&source.file_id),
            "path":std::str::from_utf8(&source.path).ok(),"path_hex":hex(&source.path),"bytes":source.stamp.bytes}))})
}
fn index_pending(value: IndexPending, manifest: Option<&Manifest>) -> Value {
    let disposition = match value.disposition {
        IndexDisposition::Intent => json!({"kind":"intent","automatic_retry_allowed":false}),
        IndexDisposition::Refused {
            record_index,
            interruption,
        } => json!({"kind":"refused","record_index":record_index,
            "interruption":interruption.map(|value|format!("{value:?}")),"automatic_retry_allowed":false,"requires_explicit_retry":true}),
        IndexDisposition::Unknown {
            record_index,
            interruption,
        } => json!({"kind":"unknown","record_index":record_index,
            "interruption":interruption.map(|value|format!("{value:?}")),"automatic_retry_allowed":false}),
    };
    json!({"attempt":index_attempt(value.attempt,manifest),"disposition":disposition})
}
fn indexes(value: IndexProgress, manifest: Option<&Manifest>) -> Value {
    json!({"historical":value.historical,"recorded":value.recorded,"new_accepted":value.new_accepted,
        "total":value.total,"pending":value.pending.map(|value|index_pending(value,manifest))})
}
fn graph_record(value: GraphRecorded, manifest: Option<&Manifest>) -> Value {
    json!({"store_id_hex":hex(&value.binding.store_id),"namespace_hex":hex(&value.binding.namespace),
        "origin_task_id_hex":hex(&value.origin),"attempt":attempt(value.attempt,manifest),
        "record":value.record_index,"body_hash_hex":hex(&value.body_hash)})
}
fn graph_progress(value: GraphProgress, manifest: Option<&Manifest>) -> Value {
    json!({"required":value.required,"recorded":value.recorded.map(|value|graph_record(value,manifest)),
        "verified":value.verified,"newly_recorded":value.newly_recorded})
}
fn graph_result(value: &GraphResult, manifest: Option<&Manifest>) -> Value {
    let receipt = value.receipt();
    json!({"store_id_hex":hex(&receipt.binding().store_id),"namespace_hex":hex(&receipt.binding().namespace),
        "origin_task_id_hex":hex(receipt.origin().as_ref()),"attempt":attempt(value.attempt(),manifest),
        "record":receipt.id().index(),"body_hash_hex":hex(receipt.body_hash().as_ref()),
        "newly_recorded":receipt.newly_recorded()})
}
fn status(value: Status, manifest: &Manifest) -> Value {
    json!({"phase":phase(value.phase),"active_owner":value.active,"interrupted":value.interrupted,
        "historical":counts(value.recorded),"recorded":counts(value.recorded),"total_puts":value.total_puts,
        "pending":value.pending.map(|value|pending(value,Some(manifest))),"indexes":indexes(value.indexes,Some(manifest)),"graph":graph_progress(value.graph,Some(manifest)),"uncertain":value.uncertain,
        "requires_explicit_retry":value.requires_explicit_retry,"requested_phase":value.requested.map(phase),
        "state_records":value.state_records,"state_fenced":value.fenced,"payload_verification_performed_by_status":false})
}
fn progress(value: Progress, manifest: Option<&Manifest>) -> Value {
    json!({"historical":counts(value.historical),"recorded":counts(value.recorded),
        "new_accepted":counts(value.new_accepted),"total_puts":value.total_puts,
        "payloads_verified":value.payloads_verified,"verification":{
            "plaintext_bytes":value.verification.plaintext_bytes,"blocks":value.verification.blocks,
            "encoded_bytes":value.verification.encoded_bytes},
        "pending":value.pending.map(|value|pending(value,manifest)),"indexes":indexes(value.indexes,manifest),"graph":graph_progress(value.graph,manifest),"state_records":value.state_records})
}
fn cause(value: &task::Cause) -> Value {
    match value {
        task::Cause::Storage(error) => {
            let failure = error.failure();
            json!({"kind":"storage","stage":failure.stage,"classification":format!("{:?}",failure.kind),
                "certainty":format!("{:?}",failure.certainty),"error":error.to_string()})
        }
        task::Cause::Graph(error) => {
            json!({"kind":"namespace_graph","classification":format!("{error:?}"),"error":error.to_string()})
        }
        task::Cause::Model(error) => {
            json!({"kind":"model","classification":format!("{error:?}"),"error":error.to_string()})
        }
        task::Cause::Plan(error) => {
            json!({"kind":"plan","classification":format!("{error:?}"),"error":error.to_string()})
        }
        task::Cause::Client(error) => {
            json!({"kind":"client","classification":format!("{error:?}"),"error":error.to_string()})
        }
        task::Cause::Transfer(error) => network_error(error),
        task::Cause::Protocol(error) => {
            json!({"kind":"protocol","classification":format!("{error:?}"),"error":error.to_string()})
        }
        task::Cause::State(message) => json!({"kind":"state_precondition","reason":message}),
    }
}
fn network_error(value: &network::Error) -> Value {
    match value {
        network::Error::Store(error) => {
            json!({"kind":"datastore","query_hex":error.query.as_ref().map(|query|hex(query)),
            "outcome":format!("{:?}",error.outcome),"interruption":error.interruption.map(|value|format!("{value:?}")),
            "cause":error.cause.as_deref().map(network_error),
            "retirement_error":error.retirement_error.as_ref().map(ToString::to_string),
            "error":error.to_string()})
        }
        network::Error::Deadline { first_io } => {
            json!({"kind":"deadline","first_io":first_io.as_ref().map(ToString::to_string)})
        }
        _ => json!({"classification":format!("{value:?}"),"error":value.to_string()}),
    }
}
fn native(value: &NativeResult, manifest: Option<&Manifest>) -> Value {
    let response = match value.response() {
        Ok(Some(Response::Status(status))) => json!({"kind":"status","code":status.code,
            "min_expiration_micros":status.min_expiration.as_micros(),"message_hex":status.message.map(hex)}),
        Ok(Some(Response::Data(data))) => {
            json!({"kind":"data","block_kind":data.kind,"uid":data.uid,
            "lookup_key_hex":hex(data.key),"value_bytes":data.value.len()})
        }
        Ok(Some(Response::End)) => json!({"kind":"data_end"}),
        Ok(None) => Value::Null,
        Err(error) => {
            json!({"decode_error":error.to_string(),"classification":format!("{error:?}")})
        }
    };
    json!({"attempt":attempt(value.attempt(),manifest),"submission":format!("{:?}",value.submission()),
        "outcome":value.outcome().map(|value|format!("{value:?}")),
        "interruption":value.interruption().map(|value|format!("{value:?}")),"requested_cancel":value.requested_cancel(),
        "response":response,"response_frame_hex":value.response_bytes().map(hex),
        "cause":value.cause().map(network_error),"settlement_error":value.settlement_error().map(ToString::to_string)})
}
fn native_index(value: &NativeIndexResult, manifest: Option<&Manifest>) -> Value {
    let response = match value.response() {
        Ok(Some(FsResponse::IndexStarted)) => json!({"kind":"index_started"}),
        Ok(Some(FsResponse::IndexFailed { message })) => {
            json!({"kind":"index_failed","message_hex":hex(message)})
        }
        Ok(Some(_)) => json!({"kind":"unexpected_fs_reply"}),
        Ok(None) => Value::Null,
        Err(error) => {
            json!({"decode_error":error.to_string(),"classification":format!("{error:?}")})
        }
    };
    let failure=value.failure().map(|failure|json!({"registration":format!("{:?}",failure.registration),
        "cause":failure.cause.as_ref().map(network_error),"preceding":failure.preceding.as_ref().map(network_error),
        "native_failure":failure.failure.map(|failure|json!({"cause":format!("{:?}",failure.cause),"outcome":format!("{:?}",failure.outcome)})),
        "retirement_error":failure.retirement_error.as_ref().map(ToString::to_string),"error":failure.to_string()}));
    json!({"attempt":index_attempt(value.attempt(),manifest),"registration":format!("{:?}",value.registration()),
        "requested_cancel":value.requested_cancel(),"interruption":value.interruption().map(|value|format!("{value:?}")),
        "response":response,"response_frame_hex":value.response_bytes().map(hex),
        "failure":failure,"retirement_error":value.retirement_error().map(ToString::to_string)})
}
fn failure_row(value: &task::Failure, original: Option<&Task>) -> Value {
    let manifest = original.map(Task::manifest);
    json!({"event":"fs_publish_task_failed","task_id":original.map(|task|hex(task.task_id())),
        "cause":value.cause.as_ref().map(cause),"native":value.native.as_ref().map(|value|native(value,manifest)),
        "index":value.index.as_ref().map(|value|native_index(value,manifest)),
        "graph":value.graph.as_ref().map(|value|graph_result(value,manifest)),
        "cleanup_error":value.cleanup.as_ref().map(ToString::to_string),"state_failure":value.state_failure.as_ref().map(cause),
        "requested_stop":value.requested_stop.map(reason),"progress":progress(value.progress,manifest),
        "status":original.map(|task|status(task.status(),task.manifest())),"error":value.to_string()})
}
fn outcome_row(value: &task::Outcome, original: &Task) -> Value {
    let manifest = original.manifest();
    json!({"event":match value.reason {StopReason::Complete=>"fs_publish_task_complete",StopReason::Cancelled=>"fs_publish_task_cancelled",_=>"fs_publish_task_paused"},
        "task_id":hex(original.task_id()),"reason":reason(value.reason),"status":status(original.status(),manifest),
        "progress":progress(value.progress,Some(manifest)),
        "completed":value.completed.as_ref().map(|completed|json!({"verified_puts":completed.verified.puts(),
            "verified_payload_bytes":completed.verified.bytes(),"file_verified":completed.verified.file().is_some(),
            "progress":progress(completed.progress,Some(manifest))})),
        "last_native":value.last_native.as_ref().map(|value|native(value,Some(manifest))),
        "last_index":value.last_index.as_ref().map(|value|native_index(value,Some(manifest))),
        "last_graph":value.last_graph.as_ref().map(|value|graph_result(value,Some(manifest))),
        "cleanup_error":value.cleanup.as_ref().map(ToString::to_string)})
}
fn graph_outcome_row(value: &task::GraphOutcome, original: &Task) -> Value {
    let manifest = original.manifest();
    json!({"event":if value.record.is_some(){"fs_publish_task_graph_recorded"}else{"fs_publish_task_graph_paused"},
        "task_id":hex(original.task_id()),"phase":phase(value.phase),"status":status(original.status(),manifest),
        "progress":progress(value.progress,Some(manifest)),
        "completed":value.completed.as_ref().map(|completed|json!({"verified_puts":completed.verified.puts(),
            "verified_payload_bytes":completed.verified.bytes(),"file_verified":completed.verified.file().is_some(),
            "progress":progress(completed.progress,Some(manifest))})),
        "last_graph":value.record.as_ref().map(|value|graph_result(value,Some(manifest))),
        "network_endpoint_supplied":false})
}
fn uri_bytes(uri: Uri<'_>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0; uri.encoded_len()?];
    uri.encode(&mut bytes)?;
    Ok(bytes)
}
fn artifact(value: &Artifact) -> Result<Value, Box<dyn Error>> {
    Ok(match value {
        Artifact::File(content) => {
            let uri = uri_bytes(content.uri())?;
            json!({"kind":"file","uri":std::str::from_utf8(&uri).ok(),"uri_bytes":uri})
        }
        Artifact::IndexedFile { content, source } => {
            let uri = uri_bytes(content.uri())?;
            json!({"kind":"indexed_file","uri":std::str::from_utf8(&uri).ok(),"uri_bytes":uri,
                "file_id_hex":hex(&source.file_id),"source_count":1,"bytes":source.stamp.bytes,
                "source_required_for_resume_and_serving":true})
        }
        Artifact::Tree(tree) => {
            let uri = uri_bytes(tree.root.uri())?;
            json!({"kind":"tree","uri":std::str::from_utf8(&uri).ok(),"uri_bytes":uri,
                "objects":tree.objects.len(),"source_count":tree.sources.len(),"indexed":!tree.sources.is_empty(),
                "indexed_sources_required_for_resume_and_serving":!tree.sources.is_empty()})
        }
        Artifact::Keywords {
            query_uri,
            target_uri,
            metadata,
        } => json!({"kind":"keywords",
            "query_uri":std::str::from_utf8(query_uri).ok(),"query_uri_bytes":query_uri,
            "target_uri":std::str::from_utf8(target_uri).ok(),"target_uri_bytes":target_uri,"selected_metadata_wire_hex":metadata.as_deref().map(hex)}),
        Artifact::Namespace {
            public,
            identifier,
            update,
            target_uri,
            metadata,
        } => {
            let uri = uri_bytes(Uri::Namespace(Namespace::new(
                gnunet::crypto::EddsaPublicKey::from_bytes(*public),
                identifier,
            )?))?;
            json!({"kind":"namespace","public_key_hex":hex(public),"identifier_hex":hex(identifier),"update_hex":hex(update),
                "uri":std::str::from_utf8(&uri).ok(),"uri_bytes":uri,
                "target_uri":std::str::from_utf8(target_uri).ok(),"target_uri_bytes":target_uri,"selected_metadata_wire_hex":metadata.as_deref().map(hex)})
        }
    })
}
fn task_row(event: &str, task: &Task) -> Result<Value, Box<dyn Error>> {
    let manifest = task.manifest();
    Ok(
        json!({"event":event,"task_id":hex(task.task_id()),"status":status(task.status(),manifest),
        "artifact":artifact(&manifest.plan.artifact)?,"graph_target":manifest.graph.as_ref().map(|target|json!({"store_id_hex":hex(&target.binding.store_id),"namespace_hex":hex(&target.binding.namespace)})),"blocks":{"priority":manifest.blocks.priority,
            "anonymity":manifest.blocks.anonymity,"replication":manifest.blocks.replication,
            "expiration_micros":manifest.blocks.expiration.as_micros()}}),
    )
}
/// Preserve the original task/native result when diagnostic output also fails.
#[derive(Debug)]
struct CommandFailure {
    task: Option<Box<task::Failure>>,
    outcome: Option<Box<task::Outcome>>,
    graph: Option<Box<task::GraphOutcome>>,
    cause: Option<Box<task::Cause>>,
    output: Option<io::Error>,
    diagnostic: Option<io::Error>,
}
impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FS publication task command failed")?;
        if let Some(error) = &self.task {
            write!(f, ": {error}")?;
        }
        if let Some(error) = &self.cause {
            write!(f, ": {error}")?;
        }
        if let Some(error) = self
            .outcome
            .as_ref()
            .and_then(|value| value.cleanup.as_ref())
        {
            write!(f, "; cleanup: {error}")?;
        }
        if let Some(error) = self
            .outcome
            .as_ref()
            .and_then(|value| value.last_index.as_ref())
            .and_then(NativeIndexResult::retirement_error)
        {
            write!(f, "; index cleanup: {error}")?;
        }
        if let Some(graph) = &self.graph {
            write!(
                f,
                "; graph phase {:?}, recorded {}",
                graph.phase,
                graph.record.is_some()
            )?;
        }
        if let Some(error) = &self.output {
            write!(f, "; progress output: {error}")?;
        }
        if let Some(error) = &self.diagnostic {
            write!(f, "; diagnostic output: {error}")?;
        }
        Ok(())
    }
}
impl Error for CommandFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(error) = &self.task {
            Some(error.as_ref())
        } else if let Some(error) = &self.cause {
            Some(error.as_ref())
        } else if let Some(error) = self
            .outcome
            .as_ref()
            .and_then(|value| value.cleanup.as_ref())
        {
            Some(error)
        } else if let Some(error) = self
            .outcome
            .as_ref()
            .and_then(|value| value.last_index.as_ref())
            .and_then(NativeIndexResult::retirement_error)
        {
            Some(error)
        } else if let Some(error) = &self.output {
            Some(error)
        } else {
            self.diagnostic
                .as_ref()
                .map(|error| error as &(dyn Error + 'static))
        }
    }
}
fn failed(
    out: &mut impl Write,
    error: Box<task::Failure>,
    original: Option<&Task>,
) -> Box<dyn Error> {
    let diagnostic = row(out, &failure_row(&error, original)).err();
    Box::new(CommandFailure {
        task: Some(error),
        outcome: None,
        graph: None,
        cause: None,
        output: None,
        diagnostic,
    })
}
fn refused(out: &mut impl Write, error: task::Cause, original: &Task) -> Box<dyn Error> {
    let diagnostic = row(
        out,
        &json!({"event":"fs_publish_task_command_refused","task_id":hex(original.task_id()),
        "cause":cause(&error),"status":status(original.status(),original.manifest())}),
    )
    .err();
    Box::new(CommandFailure {
        task: None,
        outcome: None,
        graph: None,
        cause: Some(Box::new(error)),
        output: None,
        diagnostic,
    })
}
fn preparation_blocks(
    selection: publication_options::Selection,
) -> Result<network::BlockOptions, Box<dyn Error>> {
    // Offline preparation has an actual clock, without inventing an endpoint
    // merely to obtain one. The selected policy becomes the task's manifest.
    selection.select(&gnunet_service_runtime::clock::SystemClock)
}
fn prepared(task: Task, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    row(out, &task_row("fs_publish_task_prepared", &task)?)?;
    Ok(())
}
pub(super) fn create_file(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::content_arguments(args)?;
    let args = parsed.positional;
    let mut input = gnunet::fs_host::open_input(args[1])?;
    let task = Task::create_file(
        Path::new(args[0]),
        &mut input,
        &mut Buffers::new(),
        preparation_blocks(parsed.publication)?,
        Limits::default(),
        |_| gnunet::fs_host::Control::Continue,
    )
    .map_err(|error| failed(out, error, None))?;
    prepared(task, out)
}
pub(super) fn create_indexed_file(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::content_arguments(args)?;
    let args = parsed.positional;
    let filename = Path::new(args[1]);
    let mut input = gnunet::fs_host::open_input(filename)?;
    let task = Task::create_indexed_file(
        Path::new(args[0]),
        &mut input,
        filename,
        &mut Buffers::new(),
        preparation_blocks(parsed.publication)?,
        Limits::default(),
        |_| gnunet::fs_host::Control::Continue,
    )
    .map_err(|error| failed(out, error, None))?;
    prepared(task, out)
}
pub(super) fn create_tree(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    prepare_tree(args, out, false)
}
pub(super) fn create_indexed_tree(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    prepare_tree(args, out, true)
}
fn prepare_tree(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
    indexed: bool,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::content_arguments(args)?;
    let args = parsed.positional;
    let named_root = Path::new(args[1]);
    let input = gnunet::fs_host::input_tree::InputDir::open(named_root)?;
    let mut buffers = Buffers::new();
    let blocks = preparation_blocks(parsed.publication)?;
    let task = if indexed {
        Task::create_indexed_tree(
            Path::new(args[0]),
            &input,
            named_root,
            &mut buffers,
            blocks,
            Limits::default(),
            |_| gnunet::fs_host::Control::Continue,
        )
    } else {
        Task::create_tree(
            Path::new(args[0]),
            &input,
            &mut buffers,
            blocks,
            Limits::default(),
            |_| gnunet::fs_host::Control::Continue,
        )
    }
    .map_err(|error| failed(out, error, None))?;
    prepared(task, out)
}
pub(super) fn create_keywords(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::keyword_arguments(args, false)?;
    let args = parsed.positional;
    let mut metadata = super::publish::settings::RecordMetadata::new(parsed.manual)?;
    let metadata = metadata.plan()?;
    let Uri::Keywords(query) = Uri::parse(args[1].as_bytes(), UriLimits::default())? else {
        return Err("publish-task-keywords requires a KSK URI".into());
    };
    let target = Uri::parse(args[2].as_bytes(), UriLimits::default())?;
    let task = Task::create_keywords(
        Path::new(args[0]),
        query,
        target,
        metadata.as_ref(),
        preparation_blocks(parsed.publication)?,
        Limits::default(),
    )
    .map_err(|error| failed(out, error, None))?;
    prepared(task, out)
}
pub(super) fn create_namespace(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::metadata_arguments(args, 5, 5, &[])?;
    let args = parsed.positional;
    let mut metadata = super::publish::settings::RecordMetadata::new(parsed.manual)?;
    let metadata = metadata.plan()?;
    let key = KeyFile::open(Path::new(args[1]))?;
    let target = Uri::parse(args[4].as_bytes(), UriLimits::default())?;
    let task = Task::create_namespace(
        Path::new(args[0]),
        &key,
        args[2].as_bytes(),
        args[3].as_bytes(),
        target,
        metadata.as_ref(),
        preparation_blocks(parsed.publication)?,
        Limits::default(),
    )
    .map_err(|error| failed(out, error, None))?;
    prepared(task, out)
}
pub(super) fn create_managed_namespace(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let parsed = super::publish::settings::metadata_arguments(args, 5, 5, &[b"--update"])?;
    let update = parsed.value(b"--update").map(OsStr::as_bytes);
    let args = parsed.positional;
    let mut metadata = super::publish::settings::RecordMetadata::new(parsed.manual)?;
    let metadata = metadata.plan()?;
    let key = KeyFile::open(Path::new(args[1]))?;
    let mut graph = Graph::open(
        Path::new(args[2]),
        key.public_key(),
        GraphLimits::default(),
        store::Limits::default(),
    )?;
    let target = Uri::parse(args[4].as_bytes(), UriLimits::default())?;
    let task = Task::create_managed_namespace(
        Path::new(args[0]),
        &key,
        &mut graph,
        args[3].as_bytes(),
        update,
        target,
        metadata.as_ref(),
        preparation_blocks(parsed.publication)?,
        Limits::default(),
    )
    .map_err(|error| failed(out, error, None))?;
    prepared(task, out)
}
fn open_graph(original: &Task, path: &Path) -> Result<Graph, task::Cause> {
    let Artifact::Namespace { public, .. } = &original.manifest().plan.artifact else {
        return Err(task::Cause::State(
            "managed graph commands require a namespace publication",
        ));
    };
    Graph::open(
        path,
        *public,
        GraphLimits::default(),
        store::Limits::default(),
    )
    .map_err(task::Cause::Graph)
}
pub(super) fn status_command(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error, None))?;
    row(out, &task_row("fs_publish_task_status", &task)?)?;
    Ok(())
}
fn quota(raw: Option<&impl AsRef<OsStr>>) -> Result<Option<usize>, Box<dyn Error>> {
    raw.map(|raw| -> Result<usize, Box<dyn Error>> {
        let text = raw
            .as_ref()
            .to_str()
            .ok_or("new-acks-per-run must be UTF-8 digits")?;
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("new-acks-per-run must be nonnegative decimal digits".into());
        }
        Ok(text.parse::<usize>()?)
    })
    .transpose()
}
pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    run_inner(args, out, RunMode::Plain)
}
pub(super) fn run_indexed(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    run_inner(args, out, RunMode::Indexed)
}
pub(super) fn run_managed(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    run_inner(args, out, RunMode::Managed)
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum RunMode {
    Plain,
    Indexed,
    Managed,
}
fn run_inner(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
    mode: RunMode,
) -> Result<(), Box<dyn Error>> {
    let indexed = mode == RunMode::Indexed;
    let managed = mode == RunMode::Managed;
    let offset = usize::from(indexed);
    let extra = usize::from(indexed || managed);
    let interval = duration(args.get(extra + 2))?;
    let limit = quota(args.get(extra + 3))?;
    let fs_source =
        indexed.then(|| EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf()));
    let mut task = Task::open(
        Path::new(args[offset + 1].as_ref()),
        store::Limits::default(),
    )
    .map_err(|error| failed(out, error, None))?;
    let mut graph = if managed {
        Some(
            open_graph(&task, Path::new(args[2].as_ref()))
                .map_err(|error| refused(out, error, &task))?,
        )
    } else {
        None
    };
    let source = EndpointSource::unix(Path::new(args[offset].as_ref()).to_path_buf());
    let deadline = target(&source, interval)?;
    let mut start = task_row("fs_publish_task_run_started", &task)?;
    start["deadline_micros"] = json!(deadline.as_micros());
    start["new_acks_per_run"] = json!(limit);
    start["index_endpoint_supplied"] = json!(indexed);
    start["managed_graph_supplied"] = json!(managed);
    row(out, &start)?;
    let task_id = *task.task_id();
    let mut output = None;
    let mut last = None;
    let mut buffers = Buffers::new();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
        let observe=|value:Progress| {
            // Zero pauses at the runner's first control observation, before
            // reading payloads. Historical receipts never consume this quota.
            if output.is_some() || limit.is_some_and(|limit| value.new_accepted.accepted >= limit) {
                return Control::Pause;
            }
            let current = (
                value.recorded,
                value.new_accepted,
                value.payloads_verified,
                value.pending,
                value.indexes.recorded,
                value.indexes.new_accepted,
                value.indexes.pending,
                value.graph.required,value.graph.recorded,value.graph.verified,value.graph.newly_recorded,
            );
            if last != Some(current) {
                // The final row binds pending requests back to the manifest;
                // the live row still retains their original exact hash/index.
                output = row(
                    out,
                    &json!({"event":"fs_publish_task_progress","task_id":hex(&task_id),"progress":progress(value,None)}),
                )
                .err();
                last = Some(current);
            }
            if output.is_some() {
                Control::Pause
            } else {
                Control::Continue
            }
        };
        if let Some(graph)=graph.as_mut(){
            task.run_managed(source,graph,&mut buffers,deadline,observe).await
        }else if let Some(fs_source)=fs_source {
            task.run_indexed(fs_source,source,&mut buffers,deadline,observe).await
        }else{
            task.run(source,&mut buffers,deadline,observe).await
        }
    });
    match result {
        Ok(done) => {
            let diagnostic = row(out, &outcome_row(&done, &task)).err();
            if output.is_some()
                || diagnostic.is_some()
                || done.cleanup.is_some()
                || done
                    .last_index
                    .as_ref()
                    .and_then(NativeIndexResult::retirement_error)
                    .is_some()
            {
                return Err(Box::new(CommandFailure {
                    task: None,
                    outcome: Some(Box::new(done)),
                    graph: None,
                    cause: None,
                    output,
                    diagnostic,
                }));
            }
            Ok(())
        }
        Err(error) => {
            let diagnostic = row(out, &failure_row(&error, Some(&task))).err();
            Err(Box::new(CommandFailure {
                task: Some(error),
                outcome: None,
                graph: None,
                cause: None,
                output,
                diagnostic,
            }))
        }
    }
}
pub(super) fn record_graph(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error, None))?;
    let mut graph = open_graph(&task, Path::new(args[1].as_ref()))
        .map_err(|error| refused(out, error, &task))?;
    row(
        out,
        &task_row("fs_publish_task_graph_record_started", &task)?,
    )?;
    let task_id = *task.task_id();
    let mut output = None;
    let mut last = None;
    let result=task.record_namespace_graph(&mut graph,&mut Buffers::new(),|value| {
        if output.is_some(){return Control::Pause;}
        let current=(value.recorded,value.payloads_verified,value.graph.required,value.graph.recorded,value.graph.verified,value.graph.newly_recorded);
        if last!=Some(current){
            output=row(out,&json!({"event":"fs_publish_task_progress","task_id":hex(&task_id),"progress":progress(value,None)})).err();
            last=Some(current);
        }
        if output.is_some(){Control::Pause}else{Control::Continue}
    });
    match result {
        Ok(done) => {
            let diagnostic = row(out, &graph_outcome_row(&done, &task)).err();
            if output.is_some() || diagnostic.is_some() {
                return Err(Box::new(CommandFailure {
                    task: None,
                    outcome: None,
                    graph: Some(Box::new(done)),
                    cause: None,
                    output,
                    diagnostic,
                }));
            }
            Ok(())
        }
        Err(error) => {
            let diagnostic = row(out, &failure_row(&error, Some(&task))).err();
            Err(Box::new(CommandFailure {
                task: Some(error),
                outcome: None,
                graph: None,
                cause: None,
                output,
                diagnostic,
            }))
        }
    }
}
pub(super) fn cancel(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error, None))?;
    task.request_cancel()
        .map_err(|error| refused(out, error, &task))?;
    if task.status().phase == Phase::Cancelled {
        row(out, &task_row("fs_publish_task_cancelled", &task)?)?;
        return Ok(());
    }
    let done = task
        .settle_cancel()
        .map_err(|error| failed(out, error, Some(&task)))?;
    row(out, &outcome_row(&done, &task))?;
    Ok(())
}
pub(super) fn retry_refused(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error, None))?;
    task.retry_refused()
        .map_err(|error| refused(out, error, &task))?;
    row(
        out,
        &task_row("fs_publish_task_refusal_retry_authorized", &task)?,
    )?;
    Ok(())
}

pub(super) fn retry_index_refused(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut task = Task::open(Path::new(args[0].as_ref()), store::Limits::default())
        .map_err(|error| failed(out, error, None))?;
    task.retry_index_refused()
        .map_err(|error| refused(out, error, &task))?;
    row(
        out,
        &task_row("fs_publish_task_index_refusal_retry_authorized", &task)?,
    )?;
    Ok(())
}
