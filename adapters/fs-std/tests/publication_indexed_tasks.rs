//! Original FS registration and DATASTORE PUTs through real local native peers.
//! These task recovery profiles establish no unchanged-C or P2P acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native task fixtures assert actual original replies, uncertain mutations and WAL receipt recovery"
)]
use gnunet_client_host::EndpointSource;
use gnunet_datastore_host::Outcome as NativeOutcome;
use gnunet_fs::{
    Content,
    content::{self, BLOCK_BYTES},
};
use gnunet_fs_host::{
    Buffers,
    durable::store,
    network::{BlockOptions, IndexRegistration},
    publication::{
        Cause, Control, Counts, Effect, IndexDisposition, Limits, Phase, StopReason, Task,
        plan::{Artifact, Put, indexed::Source},
    },
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::{
    datastore::{Request, Response, Status},
    fs::{Request as IndexRequest, Response as IndexResponse},
};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
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
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let p = std::env::temp_dir().join(format!(
            "gnunet-pubix-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
struct Socket(PathBuf);
impl Socket {
    fn bind(root: &Path, name: &str) -> io::Result<(Self, UnixListener)> {
        let path = root.join(name);
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn policy() -> BlockOptions {
    BlockOptions {
        expiration: AbsoluteTime::from_micros(9_999_999),
        priority: 7,
        anonymity: 2,
        replication: 3,
    }
}
fn prepared(temp: &Temporary) -> TestResult<(Task, PathBuf, Source, Content, Vec<Put>)> {
    let source = temp.0.join("original-source");
    fs::write(&source, vec![0x74; 2 * BLOCK_BYTES])?;
    let mut input = gnunet_fs_host::open_input(&source)?;
    let task = Task::create_indexed_file(
        temp.0.join("task"),
        &mut input,
        &source,
        &mut Buffers::new(),
        policy(),
        Limits::default(),
        |_| gnunet_fs_host::Control::Continue,
    )?;
    let Artifact::IndexedFile {
        content,
        source: binding,
    } = &task.manifest().plan.artifact
    else {
        return Err("expected indexed source task".into());
    };
    let binding = binding.clone();
    let content = *content;
    let puts = task.manifest().plan.puts.clone();
    assert_eq!(puts.len(), 3);
    assert_eq!(puts[0].kind, 6);
    assert_eq!(puts[1].kind, 6);
    assert_eq!(puts[2].kind, 2);
    assert_eq!(puts[0].key, puts[1].key);
    assert_ne!(puts[0].payload.hash, puts[1].payload.hash);
    Ok((task, source, binding, content, puts))
}
fn endpoints(
    fs: &Socket,
    ds: &Socket,
) -> TestResult<(EndpointSource, EndpointSource, AbsoluteTime)> {
    let fs_source = EndpointSource::unix(fs.0.clone());
    let ds_source = EndpointSource::unix(ds.0.clone());
    let deadline = AbsoluteTime::from_micros(
        ds_source
            .clock()
            .sample()?
            .now
            .as_micros()
            .checked_add(6_000_000)
            .ok_or("deadline overflow")?,
    );
    Ok((fs_source, ds_source, deadline))
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("short actual native frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn closed(stream: &mut UnixStream) -> io::Result<()> {
    let mut extra = [0];
    assert_eq!(stream.read(&mut extra).await?, 0);
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
fn index_ack() -> TestResult<Vec<u8>> {
    let mut wire = vec![0; 64];
    let used = IndexResponse::IndexStarted.encode(&mut wire)?;
    wire.truncate(used);
    Ok(wire)
}
fn put_ack(code: i32) -> TestResult<Vec<u8>> {
    let mut wire = vec![0; 64];
    let used = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(13),
        message: Some(b"actual \xff\0"),
    })
    .encode(&mut wire)?;
    wire.truncate(used);
    Ok(wire)
}
fn inspect_index(bytes: &[u8], source: &Source) -> TestResult<[u8; 64]> {
    let IndexRequest::IndexStart {
        device,
        inode,
        file_id,
        filename,
    } = IndexRequest::decode(bytes)?
    else {
        return Err("expected original INDEX_START".into());
    };
    assert_eq!((device, inode), (0, 0));
    assert_eq!(file_id, source.file_id);
    assert_eq!(filename, source.path);
    let request = IndexRequest::IndexStart {
        device: 0,
        inode: 0,
        file_id: source.file_id,
        filename: &source.path,
    };
    let mut exact = vec![0; request.encoded_len()?];
    request.encode(&mut exact)?;
    assert_eq!(bytes, exact);
    Ok(gnunet_crypto::hash512(bytes))
}
fn inspect_put(bytes: &[u8], put: Put, source: &Source) -> TestResult<[u8; 64]> {
    let Request::Put(value) = Request::decode(bytes)? else {
        return Err("expected original PUT".into());
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
        (0, put.kind, 7, 2, 3, 0)
    );
    assert_eq!(value.expiration, policy().expiration);
    assert_eq!(value.key, &put.key);
    assert_eq!(value.value.len(), put.payload.bytes);
    assert_eq!(gnunet_crypto::hash512(value.value), put.payload.hash);
    let position = put.position.ok_or("missing canonical node coordinate")?;
    if position.level == 0 {
        assert_eq!(value.kind, 6);
        assert_eq!(value.value.len(), 72);
        assert_eq!(&value.value[..64], &source.file_id);
        assert_eq!(
            u64::from_be_bytes(value.value[64..].try_into()?),
            position.index * BLOCK_BYTES as u64
        );
        let mut encoded = vec![0; BLOCK_BYTES + content::TAG_BYTES];
        let real = content::encode_data(&vec![0x74; BLOCK_BYTES], &mut encoded)?;
        assert_eq!(value.key, &real.key().query);
    } else {
        assert_eq!(value.kind, 2);
        assert_eq!(put.payload.hash, put.key);
    }
    Ok(gnunet_crypto::hash512(bytes))
}
fn full_bytes(puts: &[Put]) -> u128 {
    puts.iter().map(|p| p.payload.bytes as u128).sum()
}

#[test]
fn index_and_put_prefixes_resume_independently_without_replay_and_changed_sources_refuse()
-> TestResult {
    runtime()?.block_on(async {
        let temp = Temporary::new()?;
        let (mut task, source, binding, content, puts) = prepared(&temp)?;
        let task_path = temp.0.join("task");
        let (fs_socket, fs_listener) = Socket::bind(&temp.0, "fs.sock")?;
        let (ds_socket, ds_listener) = Socket::bind(&temp.0, "ds.sock")?;
        let (fs_done_tx, fs_done_rx) = oneshot::channel();
        let (ds_done_tx, ds_done_rx) = oneshot::channel();
        let ack = index_ack()?;
        let first_ack = put_ack(0)?;
        let fs_peer = async {
            let (mut stream, _) = fs_listener.accept().await?;
            let original = frame(&mut stream).await?;
            let hash = inspect_index(&original, &binding)?;
            stream.write_all(&ack).await?;
            closed(&mut stream).await?;
            fs_done_rx.await?;
            no_connection(&fs_listener).await?;
            Ok::<_, Box<dyn std::error::Error>>(hash)
        };
        let ds_peer = async {
            let mut hashes = Vec::new();
            let (mut stream, _) = ds_listener.accept().await?;
            hashes.push(inspect_put(&frame(&mut stream).await?, puts[0], &binding)?);
            stream.write_all(&first_ack).await?;
            closed(&mut stream).await?;
            let (mut stream, _) = ds_listener.accept().await?;
            for (index, put) in puts.iter().enumerate().skip(1) {
                hashes.push(inspect_put(&frame(&mut stream).await?, *put, &binding)?);
                stream
                    .write_all(&put_ack(if index == 1 { 7 } else { 1 })?)
                    .await?;
            }
            closed(&mut stream).await?;
            ds_done_rx.await?;
            no_connection(&ds_listener).await?;
            Ok::<_, Box<dyn std::error::Error>>(hashes)
        };
        let host = async {
            let mut buffers = Buffers::new();
            let (_, ds, deadline) = endpoints(&fs_socket, &ds_socket)?;
            let before = task.status();
            let refusal = task
                .run(ds, &mut buffers, deadline, |_| Control::Continue)
                .await
                .err()
                .ok_or("plain run silently omitted original FS registration")?;
            assert!(matches!(refusal.cause, Some(Cause::State(_))));
            assert!(refusal.index.is_none() && refusal.native.is_none());
            assert_eq!(task.status().state_records, before.state_records);
            let (fs, ds, deadline) = endpoints(&fs_socket, &ds_socket)?;
            let paused = task
                .run_indexed(fs, ds, &mut buffers, deadline, |p| {
                    if p.new_accepted.accepted >= 1 {
                        Control::Pause
                    } else {
                        Control::Continue
                    }
                })
                .await?;
            assert_eq!(paused.reason, StopReason::CallerPause);
            assert_eq!(paused.progress.indexes.new_accepted, 1);
            assert_eq!(paused.progress.indexes.recorded, 1);
            assert_eq!(paused.progress.new_accepted.accepted, 1);
            assert_eq!(paused.progress.recorded.accepted, 1);
            let index = paused
                .last_index
                .ok_or("actual IndexStarted owner missing")?;
            assert_eq!(index.registration(), IndexRegistration::Acknowledged);
            assert_eq!(index.response_bytes(), Some(ack.as_slice()));
            assert!(matches!(
                index.response()?,
                Some(IndexResponse::IndexStarted)
            ));
            let first = paused.last_native.ok_or("actual first PUT owner missing")?;
            assert!(matches!(
                first.outcome(),
                Some(NativeOutcome::Status { code: 0, .. })
            ));
            assert_eq!(first.response_bytes(), Some(first_ack.as_slice()));
            let index_hash = index.attempt().request_hash;
            let first_hash = first.attempt().request_hash;
            drop(task);
            let mut task = Task::open(&task_path, store::Limits::default())?;
            assert_eq!(task.status().phase, Phase::Paused);
            assert_eq!(task.status().indexes.recorded, 1);
            assert_eq!(task.status().recorded.accepted, 1);
            let (fs, ds, deadline) = endpoints(&fs_socket, &ds_socket)?;
            let complete = task
                .run_indexed(fs, ds, &mut buffers, deadline, |_| Control::Continue)
                .await?;
            assert_eq!(complete.reason, StopReason::Complete);
            assert_eq!(complete.progress.indexes.historical, 1);
            assert_eq!(complete.progress.indexes.new_accepted, 0);
            assert_eq!(complete.progress.indexes.recorded, 1);
            assert!(complete.last_index.is_none());
            assert_eq!(complete.progress.historical.accepted, 1);
            assert_eq!(complete.progress.new_accepted.accepted, 2);
            assert_eq!(
                complete.progress.recorded,
                Counts {
                    accepted: 3,
                    bytes: full_bytes(&puts)
                }
            );
            let proof = complete
                .completed
                .ok_or("missing fresh indexed reader proof")?;
            assert_eq!(
                proof
                    .verified
                    .file()
                    .ok_or("indexed completion lacks actual FileReader")?
                    .verified
                    .content(),
                content
            );
            let final_hash = complete
                .last_native
                .ok_or("final actual IBLOCK owner missing")?
                .attempt()
                .request_hash;
            let recorded = task.status().recorded;
            let mut input = fs::OpenOptions::new().write(true).open(&source)?;
            input.write_all(b"changed")?;
            input.sync_all()?;
            let (fs, ds, deadline) = endpoints(&fs_socket, &ds_socket)?;
            let refused = task
                .run_indexed(fs, ds, &mut buffers, deadline, |_| Control::Continue)
                .await
                .err()
                .ok_or("changed source became successful offline completion")?;
            assert!(matches!(refused.cause, Some(Cause::Plan(_))));
            assert!(refused.index.is_none() && refused.native.is_none());
            assert!(!refused.progress.payloads_verified);
            assert_eq!(task.status().recorded, recorded);
            assert_eq!(task.status().indexes.recorded, 1);
            fs_done_tx
                .send(())
                .map_err(|()| io::Error::other("FS fixture disappeared"))?;
            ds_done_tx
                .send(())
                .map_err(|()| io::Error::other("DATASTORE fixture disappeared"))?;
            Ok::<_, Box<dyn std::error::Error>>((index_hash, first_hash, final_hash))
        };
        let (observed, index_hash, put_hashes) =
            timeout(WAIT, async { tokio::try_join!(host, fs_peer, ds_peer) }).await??;
        assert_eq!(observed.0, index_hash);
        assert_eq!(observed.1, put_hashes[0]);
        assert_eq!(observed.2, put_hashes[2]);
        assert_ne!(put_hashes[0], put_hashes[1]);
        Ok(())
    })
}

#[test]
fn written_index_start_without_reply_remains_unknown_after_reopen_and_cancel() -> TestResult {
    runtime()?.block_on(async {
        let temp = Temporary::new()?;
        let (mut task, _, binding, _, _) = prepared(&temp)?;
        let task_path = temp.0.join("task");
        let (fs_socket, fs_listener) = Socket::bind(&temp.0, "fs.sock")?;
        let (ds_socket, ds_listener) = Socket::bind(&temp.0, "ds.sock")?;
        let (done_tx, done_rx) = oneshot::channel();
        let peer = async {
            let (mut stream, _) = fs_listener.accept().await?;
            let original = frame(&mut stream).await?;
            let hash = inspect_index(&original, &binding)?;
            // A complete original INDEX_START was actually received. Its actual
            // MQ closes without either IndexStarted or IndexFailed.
            drop(stream);
            done_rx.await?;
            no_connection(&fs_listener).await?;
            no_connection(&ds_listener).await?;
            Ok::<_, Box<dyn std::error::Error>>(hash)
        };
        let host = async {
            let mut buffers = Buffers::new();
            let (fs, ds, deadline) = endpoints(&fs_socket, &ds_socket)?;
            let failure = task
                .run_indexed(fs, ds, &mut buffers, deadline, |_| Control::Continue)
                .await
                .err()
                .ok_or("lost IndexStarted became known completion")?;
            assert!(failure.native.is_none());
            assert_eq!(failure.progress.new_accepted, Counts::default());
            assert_eq!(failure.progress.indexes.recorded, 0);
            assert_eq!(failure.progress.indexes.new_accepted, 0);
            let native = failure
                .index
                .ok_or("lost registration erased original native result")?;
            assert_eq!(native.registration(), IndexRegistration::Unknown);
            assert!(native.response_bytes().is_none());
            assert!(
                native
                    .failure()
                    .and_then(|f| f.failure)
                    .is_some_and(|f| f.outcome == ProtocolError::OutcomeUnknown)
            );
            let before = task.status();
            let pending = before
                .indexes
                .pending
                .ok_or("Unknown registration did not remain pending")?;
            assert_eq!(pending.attempt, native.attempt());
            assert!(matches!(
                pending.disposition,
                IndexDisposition::Unknown { .. }
            ));
            assert!(before.uncertain);
            assert!(!before.requires_explicit_retry);
            assert_eq!(before.recorded, Counts::default());
            let hash = native.attempt().request_hash;
            drop(task);
            let mut task = Task::open(&task_path, store::Limits::default())?;
            assert_eq!(task.status().indexes.pending, Some(pending));
            let (fs, ds, deadline) = endpoints(&fs_socket, &ds_socket)?;
            let refused = task
                .run_indexed(fs, ds, &mut buffers, deadline, |_| Control::Continue)
                .await
                .err()
                .ok_or("reopen replayed unknown registration")?;
            assert!(matches!(refused.cause, Some(Cause::State(_))));
            assert!(refused.index.is_none() && refused.native.is_none());
            assert_eq!(task.status().state_records, before.state_records);
            assert!(task.retry_index_refused().is_err());
            assert_eq!(task.status().state_records, before.state_records);
            task.request_cancel()?;
            let cancelled = task.settle_cancel()?;
            assert_eq!(cancelled.reason, StopReason::Cancelled);
            assert_eq!(task.status().phase, Phase::Cancelled);
            assert_eq!(task.status().indexes.pending, Some(pending));
            assert!(task.status().uncertain);
            assert_eq!(task.status().recorded, Counts::default());
            drop(task);
            let mut task = Task::open(&task_path, store::Limits::default())?;
            let records = task.status().state_records;
            let (fs, ds, deadline) = endpoints(&fs_socket, &ds_socket)?;
            assert!(
                task.run_indexed(fs, ds, &mut buffers, deadline, |_| Control::Continue)
                    .await
                    .is_err()
            );
            assert_eq!(task.status().state_records, records);
            assert_eq!(task.status().indexes.pending, Some(pending));
            done_tx
                .send(())
                .map_err(|()| io::Error::other("Unknown fixture disappeared"))?;
            Ok::<_, Box<dyn std::error::Error>>(hash)
        };
        let (host, peer) = timeout(WAIT, async { tokio::try_join!(host, peer) }).await??;
        assert_eq!(host, peer);
        Ok(())
    })
}

#[test]
fn actual_index_started_survives_wal_failure_and_original_receipt_records_without_resend()
-> TestResult {
    runtime()?.block_on(async{
        let temp=Temporary::new()?;let (mut task,_,binding,content,puts)=prepared(&temp)?;let task_path=temp.0.join("task");let saved=temp.0.join("original-task");let task_id=*task.task_id();
        let (fs_socket,fs_listener)=Socket::bind(&temp.0,"fs.sock")?;let (ds_socket,ds_listener)=Socket::bind(&temp.0,"ds.sock")?;let ack=index_ack()?;
        let (fs_done_tx,fs_done_rx)=oneshot::channel();let (ds_done_tx,ds_done_rx)=oneshot::channel();let permitted=Arc::new(AtomicBool::new(false));let released=permitted.clone();
        let fs_peer=async{
            let (mut stream,_)=fs_listener.accept().await?;let original=frame(&mut stream).await?;let hash=inspect_index(&original,&binding)?;
            fs::rename(&task_path,&saved)?;fs::create_dir(&task_path)?;fs::set_permissions(&task_path,fs::Permissions::from_mode(0o700))?;
            stream.write_all(&ack).await?;closed(&mut stream).await?;fs_done_rx.await?;no_connection(&fs_listener).await?;Ok::<_,Box<dyn std::error::Error>>(hash)
        };
        let ds_peer=async{
            let (mut stream,_)=ds_listener.accept().await?;assert!(released.load(Ordering::SeqCst));let mut hashes=Vec::new();
            for put in &puts{hashes.push(inspect_put(&frame(&mut stream).await?,*put,&binding)?);stream.write_all(&put_ack(1)?).await?;}
            closed(&mut stream).await?;ds_done_rx.await?;no_connection(&ds_listener).await?;Ok::<_,Box<dyn std::error::Error>>(hashes)
        };
        let host=async{
            let mut buffers=Buffers::new();let (fs,ds,deadline)=endpoints(&fs_socket,&ds_socket)?;let mut failure=task.run_indexed(fs,ds,&mut buffers,deadline,|_|Control::Continue).await.err().ok_or("foreign WAL authority became registration success")?;
            assert!(matches!(&failure.cause,Some(Cause::Storage(error)) if error.failure().kind==store::FailureKind::Authority));assert!(failure.native.is_none());assert!(failure.progress.payloads_verified);assert_eq!(failure.progress.new_accepted,Counts::default());assert_eq!(failure.progress.indexes.new_accepted,1);assert_eq!(failure.progress.indexes.recorded,0);
            let native=failure.index.take().ok_or("WAL failure erased original IndexStarted owner")?;assert_eq!(native.registration(),IndexRegistration::Acknowledged);assert_eq!(native.response_bytes(),Some(ack.as_slice()));assert!(matches!(native.response()?,Some(IndexResponse::IndexStarted)));
            let pending=task.status().indexes.pending.ok_or("WAL failure erased original registration intent")?;assert_eq!(pending.attempt,native.attempt());assert_eq!(pending.disposition,IndexDisposition::Intent);assert!(task.status().fenced);assert!(task.status().uncertain);
            fs::remove_dir(&task_path)?;fs::rename(&saved,&task_path)?;assert!(native.record(&mut task).is_err());assert!(task.status().fenced);drop(task);
            let mut task=Task::open(&task_path,store::Limits::default())?;assert_eq!(task.task_id(),&task_id);assert!(!task.status().fenced);assert_eq!(task.status().indexes.pending,Some(pending));assert_eq!(native.record(&mut task)?,Effect::Accepted);assert_eq!(task.status().indexes.recorded,1);assert!(task.status().indexes.pending.is_none());assert!(!task.status().uncertain);
            let records=task.status().state_records;assert_eq!(native.record(&mut task)?,Effect::Accepted);assert_eq!(task.status().state_records,records);let index_hash=native.attempt().request_hash;
            permitted.store(true,Ordering::SeqCst);let (fs,ds,deadline)=endpoints(&fs_socket,&ds_socket)?;let done=task.run_indexed(fs,ds,&mut buffers,deadline,|_|Control::Continue).await?;
            assert_eq!(done.reason,StopReason::Complete);assert_eq!(done.progress.indexes.historical,1);assert_eq!(done.progress.indexes.new_accepted,0);assert_eq!(done.progress.indexes.recorded,1);assert!(done.last_index.is_none());assert_eq!(done.progress.new_accepted,Counts{accepted:3,bytes:full_bytes(&puts)});assert_eq!(done.progress.recorded,done.progress.new_accepted);
            assert_eq!(done.completed.ok_or("no fresh indexed completion proof")?.verified.file().ok_or("no actual FileReader receipt")?.verified.content(),content);
            let last=done.last_native.ok_or("no actual final IBLOCK owner")?.attempt().request_hash;drop(task);let reopened=Task::open(&task_path,store::Limits::default())?;assert_eq!(reopened.status().phase,Phase::Complete);assert_eq!(reopened.status().indexes.recorded,1);assert_eq!(reopened.status().recorded.accepted,3);
            fs_done_tx.send(()).map_err(|()|io::Error::other("FS ACK fixture disappeared"))?;ds_done_tx.send(()).map_err(|()|io::Error::other("DATASTORE ACK fixture disappeared"))?;
            Ok::<_,Box<dyn std::error::Error>>((index_hash,last))
        };
        let (host,index_hash,put_hashes)=timeout(WAIT,async{tokio::try_join!(host,fs_peer,ds_peer)}).await??;assert_eq!(host.0,index_hash);assert_eq!(host.1,put_hashes[2]);Ok(())
    })
}
