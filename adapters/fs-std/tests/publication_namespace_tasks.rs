//! Actual namespace PUT replies across independent task/graph WAL failures.
//! Dedicated Rust socket peers establish no unchanged-C or P2P acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible native task cases assert original replies, graph effects and exact local recovery"
)]
use gnunet_client_host::EndpointSource;
use gnunet_datastore_host::Outcome as NativeOutcome;
use gnunet_fs::{
    Content, Uri, metadata as md,
    ublock::{Context, Limits as ArtifactLimits},
};
use gnunet_fs_host::{
    Buffers,
    durable::store,
    namespace::{
        graph::{self, Graph},
        key::KeyFile,
    },
    network::BlockOptions,
    publication::{
        Cause, Control, Counts, Disposition, Limits, Phase, StopReason, Task, plan::Put,
    },
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::datastore::{Request, Response, Status};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
    time::timeout,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(8);
const LABEL: &[u8] = b"tracked-\xff";
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-nst-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn bind(&self) -> io::Result<(PathBuf, UnixListener)> {
        let path = self.0.join("ds.sock");
        let listener = UnixListener::bind(&path)?;
        Ok((path, listener))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn blocks() -> BlockOptions {
    BlockOptions {
        expiration: AbsoluteTime::from_micros(1_234_567_890),
        priority: 7,
        anonymity: 2,
        replication: 3,
    }
}
fn content() -> Content {
    Content {
        key: [41; 64],
        query: [42; 64],
        size: 17,
    }
}
fn prepare(path: &Path, key: &KeyFile, graph: &mut Graph) -> TestResult<Task> {
    Ok(Task::create_managed_namespace(
        path,
        key,
        graph,
        LABEL,
        Some(b""),
        content().uri(),
        None,
        blocks(),
        Limits::default(),
    )?)
}
fn source(path: &Path) -> TestResult<(EndpointSource, AbsoluteTime)> {
    let source = EndpointSource::unix(path.to_owned());
    let deadline = AbsoluteTime::from_micros(
        source
            .clock()
            .sample()?
            .now
            .as_micros()
            .checked_add(5_000_000)
            .ok_or("deadline overflow")?,
    );
    Ok((source, deadline))
}
fn ack(code: i32) -> TestResult<Vec<u8>> {
    let mut bytes = vec![0; 96];
    let used = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(13),
        message: Some(b"actual namespace \xff\0"),
    })
    .encode(&mut bytes)?;
    bytes.truncate(used);
    Ok(bytes)
}
async fn frame(stream: &mut UnixStream) -> TestResult<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err("short original native frame".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn closed(stream: &mut UnixStream) -> TestResult {
    let mut bytes = [0];
    assert_eq!(stream.read(&mut bytes).await?, 0);
    Ok(())
}
async fn no_connection(listener: &UnixListener) -> TestResult {
    assert!(
        timeout(Duration::from_millis(60), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
fn inspect(bytes: &[u8], expected: Put, public: &[u8; 32]) -> TestResult<[u8; 64]> {
    let Request::Put(value) = Request::decode(bytes)? else {
        return Err("expected original namespace PUT".into());
    };
    assert_eq!(
        (
            value.reservation,
            value.kind,
            value.priority,
            value.anonymity,
            value.replication,
            value.uid
        ),
        (0, 9, 7, 2, 3, 0)
    );
    assert_eq!(value.expiration, blocks().expiration);
    assert_eq!(value.key, &expected.key);
    assert_eq!(value.value.len(), expected.payload.bytes);
    assert_eq!(gnunet_crypto::hash512(value.value), expected.payload.hash);
    let context = Context::namespace(public, LABEL, ArtifactLimits::default())?;
    assert_eq!(value.key, context.query());
    let mut plain = vec![0; value.value.len()];
    let opened = context.open(value.value, &mut plain)?;
    let mut scratch = vec![0; 4096];
    let decoded = opened.decode(
        &mut scratch,
        &mut gnunet_fs_codec::Inflate::new(),
        md::Mode::Strict,
    )?;
    assert!(matches!(decoded.uri()?,Uri::Content(found) if found==content()));
    assert_eq!(decoded.update_identifier(), b"");
    assert!(decoded.metadata().is_none());
    Ok(gnunet_crypto::hash512(bytes))
}
fn move_root(path: &Path, saved: &Path) -> io::Result<()> {
    fs::rename(path, saved)?;
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
fn restore_root(path: &Path, saved: &Path) -> io::Result<()> {
    fs::remove_dir(path)?;
    fs::rename(saved, path)
}

#[test]
fn actual_namespace_ack_survives_graph_failure_then_graph_only_recovery_and_distinct_task_origins()
-> TestResult {
    runtime()?.block_on(async {
        let temp=Temporary::new()?;let graph_path=temp.0.join("graph");let saved_graph=temp.0.join("original-graph");
        let key_path=temp.0.join("key");let key=KeyFile::create(&key_path)?;let public=key.public_key();
        let mut graph=Graph::create(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
        let binding=graph.binding();let first_path=temp.0.join("first");let second_path=temp.0.join("second");
        // Both tasks prepare before any graph append; neither owns a graph row number.
        let mut first=prepare(&first_path,&key,&mut graph)?;let mut second=prepare(&second_path,&key,&mut graph)?;
        let first_id=*first.task_id();let second_id=*second.task_id();assert_ne!(first_id,second_id);
        let first_put=first.manifest().plan.puts[0];let second_put=second.manifest().plan.puts[0];
        drop(key);fs::remove_file(&key_path)?;
        let (socket,listener)=temp.bind()?;let first_ack=ack(0)?;let second_ack=ack(7)?;
        let (recovered_tx,recovered_rx)=oneshot::channel();let (checked_tx,checked_rx)=oneshot::channel();
        let peer=async {
            let (mut stream,_)=listener.accept().await?;let first_hash=inspect(&frame(&mut stream).await?,first_put,&public)?;
            move_root(&graph_path,&saved_graph)?;stream.write_all(&first_ack).await?;closed(&mut stream).await?;
            recovered_rx.await?;no_connection(&listener).await?;
            checked_tx.send(()).map_err(|()|io::Error::other("graph recovery host disappeared"))?;
            let (mut stream,_)=listener.accept().await?;let second_hash=inspect(&frame(&mut stream).await?,second_put,&public)?;
            stream.write_all(&second_ack).await?;closed(&mut stream).await?;no_connection(&listener).await?;
            Ok::<_,Box<dyn std::error::Error>>((first_hash,second_hash))
        };
        let host=async {
            let mut buffers=Buffers::new();let (endpoint,deadline)=source(&socket)?;
            let mut failure=first.run_managed(endpoint,&mut graph,&mut buffers,deadline,|_|Control::Continue).await.err().ok_or("foreign graph authority became successful publication")?;
            assert!(matches!(&failure.cause,Some(Cause::Graph(graph::Error::Storage(error))) if error.failure().kind==store::FailureKind::Authority));
            assert_eq!(failure.progress.new_accepted,Counts {accepted:1,bytes:first_put.payload.bytes as u128});
            assert_eq!(failure.progress.recorded,failure.progress.new_accepted);
            assert!(failure.progress.graph.required);assert!(failure.progress.graph.recorded.is_none());
            assert!(!failure.progress.graph.verified);assert!(failure.graph.is_none());
            let native=failure.native.take().ok_or("graph failure erased original STATUS0")?;
            assert!(matches!(native.outcome(),Some(NativeOutcome::Status {code:0,..})));
            assert_eq!(native.response_bytes(),Some(first_ack.as_slice()));assert!(native.interruption().is_none());
            assert_eq!(first.status().recorded.accepted,1);assert!(!first.status().fenced);assert!(first.status().pending.is_none());
            assert_eq!(graph.record_count(),0);assert!(graph.storage_failure().is_some());
            let native_attempt=native.attempt();restore_root(&graph_path,&saved_graph)?;drop(graph);drop(first);
            let mut graph=Graph::open(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
            assert_eq!(graph.binding(),binding);assert_eq!(graph.record_count(),0);
            let mut first=Task::open(&first_path,store::Limits::default())?;
            assert_eq!(first.status().recorded.accepted,1);assert!(first.status().graph.recorded.is_none());
            let recovered=first.record_namespace_graph(&mut graph,&mut buffers,|_|Control::Continue)?;
            assert_eq!(recovered.phase,Phase::Complete);assert!(recovered.completed.is_some());
            assert_eq!(recovered.progress.new_accepted,Counts::default());assert_eq!(recovered.progress.recorded.accepted,1);
            assert!(recovered.progress.payloads_verified && recovered.progress.graph.verified && recovered.progress.graph.newly_recorded);
            let actual=recovered.record.ok_or("graph-only recovery has no original graph receipt")?;
            assert_eq!(actual.attempt(),native_attempt);assert_eq!(actual.receipt().binding(),binding);
            assert_eq!(actual.receipt().origin(),first_id);assert_eq!(actual.receipt().id().index(),0);
            assert!(actual.receipt().newly_recorded());assert!(first.status().graph.recorded.is_some());
            assert_eq!(graph.record_count(),1);assert_eq!(graph.record(actual.receipt().id())?.ok_or("actual graph record absent")?.task_origin(),Some(first_id));
            let repeated=first.record_namespace_graph(&mut graph,&mut buffers,|_|Control::Continue)?;
            assert_eq!(repeated.phase,Phase::Complete);assert!(repeated.completed.is_some());assert!(repeated.progress.graph.verified);
            assert!(!repeated.progress.graph.newly_recorded);assert_eq!(graph.record_count(),1);
            recovered_tx.send(()).map_err(|()|io::Error::other("graph recovery peer disappeared"))?;checked_rx.await?;
            let (endpoint,deadline)=source(&socket)?;let done=second.run_managed(endpoint,&mut graph,&mut buffers,deadline,|_|Control::Continue).await?;
            assert_eq!(done.reason,StopReason::Complete);assert!(done.completed.is_some());assert_eq!(done.progress.new_accepted.accepted,1);
            assert!(done.progress.graph.verified && done.progress.graph.newly_recorded && done.progress.graph.recorded.is_some());
            let second_native=done.last_native.ok_or("second distinct task lost actual STATUS7")?;
            assert!(matches!(second_native.outcome(),Some(NativeOutcome::Status {code:7,..})));
            assert_eq!(second_native.response_bytes(),Some(second_ack.as_slice()));
            let second_hash=second_native.attempt().request_hash;let second_graph=done.last_graph.ok_or("second task has no graph receipt")?;
            assert_eq!(second_graph.receipt().origin(),second_id);assert_eq!(second_graph.receipt().id().index(),1);
            assert_eq!(graph.children(LABEL).count(),2);assert_eq!(graph.record_count(),2);
            assert_eq!(graph.record_ids().map(|id| Ok(graph.record(id)?.ok_or("graph record absent")?.task_origin())).collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,vec![Some(first_id),Some(second_id)]);
            drop(first);drop(second);drop(graph);
            let graph=Graph::open(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
            assert_eq!(graph.record_count(),2);let reopened=Task::open(&first_path,store::Limits::default())?;
            assert_eq!(reopened.status().phase,Phase::Complete);assert!(reopened.status().graph.recorded.is_some());
            assert!(!reopened.status().graph.verified);
            Ok::<_,Box<dyn std::error::Error>>((native_attempt.request_hash,second_hash))
        };
        let (host,peer)=timeout(WAIT,async{tokio::try_join!(host,peer)}).await??;assert_eq!(host,peer);Ok(())
    })
}

#[test]
fn actual_graph_success_survives_task_wal_failure_and_original_graph_receipt_records_without_native_or_graph_replay()
-> TestResult {
    runtime()?.block_on(async {
        let temp=Temporary::new()?;let graph_path=temp.0.join("graph");let task_path=temp.0.join("task");let saved_task=temp.0.join("original-task");
        let key=KeyFile::create(temp.0.join("key"))?;let public=key.public_key();
        let mut graph=Graph::create(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
        let mut task=prepare(&task_path,&key,&mut graph)?;let task_id=*task.task_id();let put=task.manifest().plan.puts[0];
        let (socket,listener)=temp.bind()?;let actual_ack=ack(7)?;let (done_tx,done_rx)=oneshot::channel();
        let peer=async {
            let (mut stream,_)=listener.accept().await?;let hash=inspect(&frame(&mut stream).await?,put,&public)?;
            stream.write_all(&actual_ack).await?;closed(&mut stream).await?;done_rx.await?;no_connection(&listener).await?;
            Ok::<_,Box<dyn std::error::Error>>(hash)
        };
        let host=async {
            let mut buffers=Buffers::new();let (endpoint,deadline)=source(&socket)?;let mut injected=false;let mut inject_error=None;
            let result=task.run_managed(endpoint,&mut graph,&mut buffers,deadline,|progress| {
                if !injected && progress.graph.verified && progress.graph.newly_recorded && progress.graph.recorded.is_none() {
                    injected=true;
                    if let Err(error)=move_root(&task_path,&saved_task) {inject_error=Some(error);return Control::Cancel;}
                }
                Control::Continue
            }).await;
            if let Some(error)=inject_error {return Err::<_,Box<dyn std::error::Error>>(Box::new(error));}
            assert!(injected);let mut failure=result.err().ok_or("foreign task authority erased actual graph success")?;
            assert!(matches!(&failure.cause,Some(Cause::Storage(error)) if error.failure().kind==store::FailureKind::Authority));
            assert_eq!(failure.progress.new_accepted.accepted,1);assert_eq!(failure.progress.recorded.accepted,1);
            assert!(failure.progress.graph.verified && failure.progress.graph.newly_recorded && failure.progress.graph.recorded.is_none());
            let native=failure.native.take().ok_or("graph fact WAL failure erased actual original PUT reply")?;
            assert_eq!(native.response_bytes(),Some(actual_ack.as_slice()));assert!(matches!(native.outcome(),Some(NativeOutcome::Status {code:7,..})));
            let receipt=failure.graph.take().ok_or("graph fact WAL failure erased actual graph receipt")?;
            assert_eq!(receipt.attempt(),native.attempt());assert_eq!(receipt.receipt().origin(),task_id);
            assert_eq!(receipt.receipt().id().index(),0);assert!(receipt.receipt().newly_recorded());
            assert_eq!(graph.record_count(),1);assert!(task.status().graph.recorded.is_none());assert!(task.status().fenced);
            restore_root(&task_path,&saved_task)?;assert!(receipt.record(&mut task).is_err());assert!(task.status().fenced);drop(task);
            let mut task=Task::open(&task_path,store::Limits::default())?;
            assert_eq!(task.task_id(),&task_id);assert_eq!(task.status().recorded.accepted,1);assert!(task.status().graph.recorded.is_none());
            let records=task.status().state_records;receipt.record(&mut task)?;
            assert_eq!(task.status().state_records,records+1);assert!(task.status().graph.recorded.is_some());assert_eq!(graph.record_count(),1);
            let records=task.status().state_records;receipt.record(&mut task)?;assert_eq!(task.status().state_records,records);assert_eq!(graph.record_count(),1);
            let done=task.record_namespace_graph(&mut graph,&mut buffers,|_|Control::Continue)?;
            assert_eq!(done.phase,Phase::Complete);assert!(done.completed.is_some());assert_eq!(done.progress.new_accepted,Counts::default());
            assert!(done.progress.graph.verified && !done.progress.graph.newly_recorded && done.progress.graph.recorded.is_some());
            assert_eq!(graph.record_count(),1);let original=done.record.ok_or("fresh confirmation lost original graph fact")?;
            assert_eq!(original.receipt().id(),receipt.receipt().id());assert_eq!(original.receipt().body_hash(),receipt.receipt().body_hash());
            assert!(!original.receipt().newly_recorded());let hash=native.attempt().request_hash;drop(task);drop(graph);
            let task=Task::open(&task_path,store::Limits::default())?;let graph=Graph::open(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
            assert_eq!(task.status().phase,Phase::Complete);assert!(task.status().graph.recorded.is_some());assert_eq!(graph.record_count(),1);
            done_tx.send(()).map_err(|()|io::Error::other("graph WAL fixture peer disappeared"))?;Ok::<_,Box<dyn std::error::Error>>(hash)
        };
        let (host,peer)=timeout(WAIT,async{tokio::try_join!(host,peer)}).await??;assert_eq!(host,peer);Ok(())
    })
}

#[test]
fn written_namespace_put_without_reply_cannot_authorize_graph_only_recovery_or_a_second_put()
-> TestResult {
    runtime()?.block_on(async {
        let temp = Temporary::new()?;
        let graph_path = temp.0.join("graph");
        let task_path = temp.0.join("task");
        let key = KeyFile::create(temp.0.join("key"))?;
        let public = key.public_key();
        let mut graph = Graph::create(
            &graph_path,
            public,
            graph::Limits::default(),
            store::Limits::default(),
        )?;
        let mut task = prepare(&task_path, &key, &mut graph)?;
        let put = task.manifest().plan.puts[0];
        let (socket, listener) = temp.bind()?;
        let (done_tx, done_rx) = oneshot::channel();
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let hash = inspect(&frame(&mut stream).await?, put, &public)?;
            drop(stream);
            done_rx.await?;
            no_connection(&listener).await?;
            Ok::<_, Box<dyn std::error::Error>>(hash)
        };
        let host = async {
            let mut buffers = Buffers::new();
            let (endpoint, deadline) = source(&socket)?;
            let failure = task
                .run_managed(endpoint, &mut graph, &mut buffers, deadline, |_| {
                    Control::Continue
                })
                .await
                .err()
                .ok_or("unacknowledged PUT became namespace graph success")?;
            assert_eq!(failure.progress.recorded, Counts::default());
            assert_eq!(failure.progress.new_accepted, Counts::default());
            assert!(failure.graph.is_none());
            let native = failure
                .native
                .ok_or("Unknown PUT lost its original native completion")?;
            assert_eq!(native.outcome(), Some(NativeOutcome::Unknown));
            assert!(native.response_bytes().is_none());
            let before = task.status();
            let pending = before.pending.ok_or("Unknown PUT did not remain pending")?;
            assert_eq!(pending.attempt, native.attempt());
            assert!(matches!(pending.disposition, Disposition::Unknown { .. }));
            assert!(before.uncertain && before.graph.required && before.graph.recorded.is_none());
            assert_eq!(graph.record_count(), 0);
            let graph_only = task
                .record_namespace_graph(&mut graph, &mut buffers, |_| Control::Continue)
                .err()
                .ok_or("Unknown PUT authorized graph-only recording")?;
            assert!(matches!(graph_only.cause, Some(Cause::State(_))));
            assert!(graph_only.graph.is_none());
            assert_eq!(task.status().state_records, before.state_records);
            assert_eq!(graph.record_count(), 0);
            drop(task);
            let mut task = Task::open(&task_path, store::Limits::default())?;
            let records = task.status().state_records;
            let (endpoint, deadline) = source(&socket)?;
            let refused = task
                .run_managed(endpoint, &mut graph, &mut buffers, deadline, |_| {
                    Control::Continue
                })
                .await
                .err()
                .ok_or("reopen resubmitted Unknown namespace PUT")?;
            assert!(matches!(refused.cause, Some(Cause::State(_))));
            assert!(refused.native.is_none());
            assert!(task.retry_refused().is_err());
            assert!(
                task.record_namespace_graph(&mut graph, &mut buffers, |_| Control::Continue)
                    .is_err()
            );
            assert_eq!(task.status().state_records, records);
            assert_eq!(task.status().pending, Some(pending));
            assert_eq!(graph.record_count(), 0);
            task.request_cancel()?;
            assert_eq!(task.settle_cancel()?.reason, StopReason::Cancelled);
            assert_eq!(task.status().pending, Some(pending));
            assert!(task.status().uncertain);
            assert_eq!(graph.record_count(), 0);
            let records = task.status().state_records;
            assert!(
                task.record_namespace_graph(&mut graph, &mut buffers, |_| Control::Continue)
                    .is_err()
            );
            assert_eq!(task.status().state_records, records);
            assert_eq!(graph.record_count(), 0);
            done_tx
                .send(())
                .map_err(|()| io::Error::other("Unknown namespace fixture peer disappeared"))?;
            Ok::<_, Box<dyn std::error::Error>>(native.attempt().request_hash)
        };
        let (host, peer) = timeout(WAIT, async { tokio::try_join!(host, peer) }).await??;
        assert_eq!(host, peer);
        Ok(())
    })
}
