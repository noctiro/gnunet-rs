//! Actual original DATASTORE receipts across durable publication failure boundaries.
//! Local Rust peers exercise wire contracts; they grant no official-C acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native publication fixtures assert original receipts, signature proofs and retry generations"
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
    namespace::key::KeyFile,
    network::BlockOptions,
    publication::{
        Cause, Control, Counts, Disposition, Effect, Limits, Phase, StopReason, Submission, Task,
        plan::Artifact,
    },
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::datastore::{Data, Request, Response, Status};
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
const WAIT: Duration = Duration::from_secs(5);
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-publication-receipt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-publication-receipt-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _cleanup = fs::remove_file(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn source(socket: &Socket) -> TestResult<(EndpointSource, AbsoluteTime)> {
    let source = EndpointSource::unix(socket.0.clone());
    let deadline = AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 4_000_000);
    Ok((source, deadline))
}
fn blocks() -> BlockOptions {
    BlockOptions {
        expiration: AbsoluteTime::from_micros(99),
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
fn keyword_task(path: &Path, query: &[u8]) -> TestResult<Task> {
    let Uri::Keywords(keywords) = Uri::parse(query, gnunet_fs::Limits::default())? else {
        return Err("expected KSK".into());
    };
    Ok(Task::create_keywords(
        path,
        keywords,
        content().uri(),
        None,
        blocks(),
        Limits::default(),
    )?)
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("short native frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn status_bytes(code: i32) -> Result<Vec<u8>, gnunet_types::Error> {
    let mut bytes = vec![0; 64];
    let n = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(123),
        // Preserve exact non-UTF8 diagnostics, including the original terminator.
        message: Some(b"receipt \xff\xfe\0"),
    })
    .encode(&mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}
async fn closed(stream: &mut UnixStream) -> io::Result<()> {
    let mut extra = [0];
    assert_eq!(stream.read(&mut extra).await?, 0);
    Ok(())
}
fn inspect(
    value: Data<'_>,
    context: Context<'_>,
    update: &[u8],
    metadata: Option<&[u8]>,
) -> TestResult<usize> {
    assert_eq!(
        (
            value.reservation,
            value.kind,
            value.priority,
            value.anonymity,
            value.replication,
            value.uid,
        ),
        (0, 9, 7, 2, 3, 0)
    );
    assert_eq!(value.expiration, blocks().expiration);
    assert_eq!(value.key, context.query());
    let mut plain = vec![0; value.value.len()];
    let opened = context.open(value.value, &mut plain)?;
    let mut scratch = vec![0; 4096];
    let decoded = opened.decode(
        &mut scratch,
        &mut gnunet_fs_codec::Inflate::new(),
        md::Mode::Strict,
    )?;
    assert!(matches!(decoded.uri()?, Uri::Content(found) if found == content()));
    assert_eq!(decoded.update_identifier(), update);
    assert_eq!(decoded.raw_metadata(), metadata.unwrap_or_default());
    assert_eq!(decoded.metadata().is_some(), metadata.is_some());
    Ok(value.value.len())
}
fn payload_bytes(task: &Task) -> u128 {
    task.manifest()
        .plan
        .puts
        .iter()
        .map(|put| put.payload.bytes as u128)
        .sum()
}

#[test]
fn sealed_repeated_keywords_and_deleted_namespace_key_accept_zero_and_other_positive_statuses()
-> TestResult {
    runtime()?.block_on(async {
        let temporary = Temporary::new()?;
        let ksk_path = temporary.0.join("keywords");
        let namespace_path = temporary.0.join("namespace");
        let mut ksk = keyword_task(&ksk_path, b"gnunet://fs/ksk/%2Balpha+alpha+beta")?;
        assert_eq!(ksk.manifest().plan.puts.len(), 3);
        assert_eq!(ksk.manifest().plan.puts[0], ksk.manifest().plan.puts[1]);
        let ksk_bytes = payload_bytes(&ksk);
        let key_path = temporary.0.join("key");
        let key = KeyFile::create(&key_path)?;
        let public = key.public_key();
        let items = [md::Item {
            kind: 42,
            format: md::Format::Binary,
            data: b"prepared before deleting the private key",
            plugin: None,
            mime: None,
        }];
        let mut order = [0];
        let mut scratch = [0; 1024];
        let metadata = md::plan_uncompressed(
            &items,
            &mut order,
            &mut scratch,
            md::Limits::default(),
            md::Options::default(),
        )?;
        let mut metadata_bytes = vec![0; metadata.report().wire_bytes];
        metadata.write(&mut metadata_bytes)?;
        let mut namespace = Task::create_namespace(
            &namespace_path,
            &key,
            b"\xfforiginal",
            b"\xfenext",
            content().uri(),
            Some(&metadata),
            blocks(),
            Limits::default(),
        )?;
        let namespace_bytes = payload_bytes(&namespace);
        fs::remove_file(&key_path)?;
        drop(key);
        assert!(KeyFile::open(&key_path).is_err());
        assert!(matches!(
            namespace.manifest().plan.artifact,
            Artifact::Namespace { public: found, .. } if found == public
        ));
        let (socket, listener) = Socket::bind()?;
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let mut observed = 0;
            let mut first = None;
            for (index, (label, code)) in [
                (b"alpha".as_slice(), 0),
                (b"alpha".as_slice(), 7),
                (b"beta".as_slice(), 0),
            ]
            .into_iter()
            .enumerate()
            {
                let original = frame(&mut stream).await?;
                let Request::Put(value) = Request::decode(&original)? else {
                    return Err("expected original keyword PUT".into());
                };
                observed += inspect(
                    value,
                    Context::keyword(label, ArtifactLimits::default())?,
                    b"",
                    None,
                )? as u128;
                if index == 0 {
                    first = Some(original);
                } else if index == 1 {
                    assert_eq!(Some(original.as_slice()), first.as_deref());
                }
                stream.write_all(&status_bytes(code)?).await?;
            }
            closed(&mut stream).await?;
            assert_eq!(observed, ksk_bytes);
            let (mut stream, _) = listener.accept().await?;
            let original = frame(&mut stream).await?;
            let Request::Put(value) = Request::decode(&original)? else {
                return Err("expected presealed namespace PUT".into());
            };
            let observed = inspect(
                value,
                Context::namespace(&public, b"\xfforiginal", ArtifactLimits::default())?,
                b"\xfenext",
                Some(&metadata_bytes),
            )?;
            assert_eq!(observed as u128, namespace_bytes);
            stream.write_all(&status_bytes(7)?).await?;
            closed(&mut stream).await?;
            assert!(
                timeout(Duration::from_millis(80), listener.accept())
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let publish = async {
            let mut buffers = Buffers::new();
            let (endpoint, deadline) = source(&socket)?;
            let done = ksk
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await?;
            assert_eq!(done.reason, StopReason::Complete);
            assert!(done.completed.is_some());
            assert!(done.progress.payloads_verified);
            assert_eq!(
                done.progress.new_accepted,
                Counts {
                    accepted: 3,
                    bytes: ksk_bytes
                }
            );
            assert_eq!(done.progress.recorded, done.progress.new_accepted);
            let native = done.last_native.as_ref().ok_or("missing actual STATUS0")?;
            assert_eq!(native.submission(), Submission::Submitted);
            assert!(matches!(
                native.outcome(),
                Some(NativeOutcome::Status { code: 0, .. })
            ));
            assert_eq!(native.response_bytes(), Some(status_bytes(0)?.as_slice()));
            drop(ksk);
            let mut reopened = Task::open(&ksk_path, store::Limits::default())?;
            assert_eq!(reopened.status().phase, Phase::Complete);
            assert_eq!(
                reopened.status().recorded,
                Counts {
                    accepted: 3,
                    bytes: ksk_bytes
                }
            );
            assert!(!reopened.status().uncertain);
            assert!(!reopened.status().requires_explicit_retry);
            assert!(reopened.status().pending.is_none());
            let (endpoint, deadline) = source(&socket)?;
            let checked = reopened
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await?;
            assert_eq!(checked.reason, StopReason::Complete);
            assert_eq!(checked.progress.historical.accepted, 3);
            assert_eq!(checked.progress.new_accepted, Counts::default());
            assert!(checked.last_native.is_none());
            assert_eq!(
                checked
                    .completed
                    .ok_or("missing fresh KSK proof")?
                    .verified
                    .puts(),
                3
            );
            let (endpoint, deadline) = source(&socket)?;
            let done = namespace
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await?;
            assert_eq!(done.reason, StopReason::Complete);
            assert!(done.progress.payloads_verified);
            assert_eq!(
                done.progress.recorded,
                Counts {
                    accepted: 1,
                    bytes: namespace_bytes
                }
            );
            let native = done.last_native.ok_or("missing actual STATUS7")?;
            assert!(matches!(
                native.outcome(),
                Some(NativeOutcome::Status { code: 7, .. })
            ));
            assert_eq!(native.response_bytes(), Some(status_bytes(7)?.as_slice()));
            drop(namespace);
            let mut reopened = Task::open(&namespace_path, store::Limits::default())?;
            assert_eq!(
                reopened.status().recorded,
                Counts {
                    accepted: 1,
                    bytes: namespace_bytes
                }
            );
            assert!(reopened.status().pending.is_none());
            assert!(!reopened.status().requires_explicit_retry);
            let (endpoint, deadline) = source(&socket)?;
            let checked = reopened
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await?;
            assert_eq!(checked.reason, StopReason::Complete);
            assert_eq!(checked.progress.new_accepted, Counts::default());
            assert!(checked.progress.payloads_verified);
            assert!(checked.last_native.is_none());
            assert_eq!(
                checked
                    .completed
                    .ok_or("missing fresh namespace proof")?
                    .verified
                    .puts(),
                1
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        timeout(WAIT, async { tokio::try_join!(publish, peer) }).await??;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn negative_status_needs_explicit_retry_and_old_native_owner_cannot_settle_a_new_generation()
-> TestResult {
    runtime()?.block_on(async {
        let temporary = Temporary::new()?;
        let path = temporary.0.join("task");
        let mut task = keyword_task(&path, b"gnunet://fs/ksk/refused")?;
        let expected_bytes = payload_bytes(&task);
        let (socket, listener) = Socket::bind()?;
        let refusal = status_bytes(-1)?;
        let (blocked_tx, blocked_rx) = oneshot::channel();
        let (checked_tx, checked_rx) = oneshot::channel();
        let peer = async {
            let mut first = None;
            let mut blocked_rx = Some(blocked_rx);
            let mut checked_tx = Some(checked_tx);
            for generation in 0..3 {
                let (mut stream, _) = listener.accept().await?;
                let original = frame(&mut stream).await?;
                let Request::Put(value) = Request::decode(&original)? else {
                    return Err("expected original retry PUT".into());
                };
                assert_eq!(
                    inspect(
                        value,
                        Context::keyword(b"refused", ArtifactLimits::default())?,
                        b"",
                        None
                    )? as u128,
                    expected_bytes
                );
                if let Some(first) = &first {
                    assert_eq!(&original, first);
                } else {
                    first = Some(original);
                }
                let reply = if generation < 2 {
                    refusal.clone()
                } else {
                    status_bytes(1)?
                };
                stream.write_all(&reply).await?;
                closed(&mut stream).await?;
                if generation == 0 {
                    blocked_rx
                        .take()
                        .ok_or("missing blocked-run observation")?
                        .await?;
                    assert!(
                        timeout(Duration::from_millis(60), listener.accept())
                            .await
                            .is_err()
                    );
                    checked_tx
                        .take()
                        .ok_or("missing retry fixture handshake")?
                        .send(())
                        .map_err(|()| io::Error::other("retry fixture host disappeared"))?;
                }
            }
            assert!(
                timeout(Duration::from_millis(80), listener.accept())
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let publish = async {
            let mut buffers = Buffers::new();
            let (endpoint, deadline) = source(&socket)?;
            let mut first = task
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await
                .err()
                .ok_or("negative STATUS became accepted")?;
            assert_eq!(first.progress.new_accepted, Counts::default());
            assert_eq!(first.progress.recorded, Counts::default());
            let old = first
                .native
                .take()
                .ok_or("negative STATUS lost its native owner")?;
            assert!(matches!(
                old.outcome(),
                Some(NativeOutcome::Status { code: -1, .. })
            ));
            assert_eq!(old.response_bytes(), Some(refusal.as_slice()));
            assert!(matches!(old.response()?, Some(Response::Status(value)) if value.code == -1));
            let before = task.status();
            assert!(before.requires_explicit_retry);
            assert!(!before.uncertain);
            let first_pending = before
                .pending
                .ok_or("negative STATUS erased the pending refusal")?;
            assert!(matches!(
                first_pending.disposition,
                Disposition::Refused { .. }
            ));
            assert_eq!(first_pending.attempt, old.attempt());
            drop(task);
            let mut task = Task::open(&path, store::Limits::default())?;
            assert_eq!(task.status().pending, before.pending);
            assert!(task.status().requires_explicit_retry);
            let (endpoint, deadline) = source(&socket)?;
            let blocked = task
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await
                .err()
                .ok_or("ordinary run replayed a refusal")?;
            assert!(blocked.native.is_none());
            assert_eq!(task.status().state_records, before.state_records);
            assert_eq!(task.status().pending, before.pending);
            blocked_tx
                .send(())
                .map_err(|()| io::Error::other("retry fixture peer disappeared"))?;
            checked_rx.await?;
            task.retry_refused()?;
            assert!(task.status().pending.is_none());
            assert!(!task.status().requires_explicit_retry);
            assert_eq!(task.status().state_records, before.state_records + 1);
            let (endpoint, deadline) = source(&socket)?;
            let second = task
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await
                .err()
                .ok_or("second negative STATUS became accepted")?;
            let current = task
                .status()
                .pending
                .ok_or("new original refusal missing")?;
            assert!(matches!(current.disposition, Disposition::Refused { .. }));
            assert_eq!(current.attempt.index, old.attempt().index);
            assert_eq!(current.attempt.request_hash, old.attempt().request_hash);
            assert!(current.attempt.intent_record > old.attempt().intent_record);
            assert_eq!(
                second
                    .native
                    .as_ref()
                    .ok_or("new native owner missing")?
                    .attempt(),
                current.attempt
            );
            let records = task.status().state_records;
            assert!(matches!(old.record(&mut task), Err(Cause::State(_))));
            assert_eq!(task.status().state_records, records);
            assert_eq!(task.status().pending, Some(current));
            assert_eq!(task.status().recorded, Counts::default());
            task.retry_refused()?;
            let (endpoint, deadline) = source(&socket)?;
            let done = task
                .run(endpoint, &mut buffers, deadline, |_| Control::Continue)
                .await?;
            assert_eq!(done.reason, StopReason::Complete);
            assert_eq!(
                done.progress.new_accepted,
                Counts {
                    accepted: 1,
                    bytes: expected_bytes
                }
            );
            assert_eq!(done.progress.recorded, done.progress.new_accepted);
            assert!(task.status().pending.is_none());
            assert!(!task.status().requires_explicit_retry);
            assert!(matches!(
                done.last_native
                    .ok_or("missing actual successful retry")?
                    .outcome(),
                Some(NativeOutcome::Status { code: 1, .. })
            ));
            drop(task);
            let reopened = Task::open(&path, store::Limits::default())?;
            assert_eq!(reopened.status().phase, Phase::Complete);
            assert_eq!(
                reopened.status().recorded,
                Counts {
                    accepted: 1,
                    bytes: expected_bytes
                }
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        timeout(WAIT, async { tokio::try_join!(publish, peer) }).await??;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn actual_ack_survives_wal_authority_failure_and_records_without_repeating_the_put() -> TestResult {
    runtime()?.block_on(async {
        let temporary = Temporary::new()?;
        let path = temporary.0.join("task");
        let saved = temporary.0.join("original-task");
        let mut task = keyword_task(&path, b"gnunet://fs/ksk/accepted")?;
        let task_id = *task.task_id();
        let expected_bytes = payload_bytes(&task);
        let (socket, listener) = Socket::bind()?;
        let ack = status_bytes(1)?;
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let original = frame(&mut stream).await?;
            let Request::Put(value) = Request::decode(&original)? else {
                return Err("expected actual original PUT".into());
            };
            assert_eq!(inspect(value, Context::keyword(b"accepted", ArtifactLimits::default())?, b"", None)? as u128, expected_bytes);
            // The peer has observed the exact authenticated original request.
            // Replace only this fixture's root before returning the real ACK.
            fs::rename(&path, &saved)?;
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            stream.write_all(&ack).await?;
            closed(&mut stream).await?;
            assert!(timeout(Duration::from_millis(100), listener.accept()).await.is_err());
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let publish = async {
            let mut buffers = Buffers::new();
            let (endpoint, deadline) = source(&socket)?;
            let mut failure = task.run(endpoint, &mut buffers, deadline, |_| Control::Continue).await.err().ok_or("changed WAL authority became publication success")?;
            assert!(matches!(&failure.cause, Some(Cause::Storage(error)) if error.failure().kind == store::FailureKind::Authority));
            assert_eq!(failure.progress.new_accepted, Counts { accepted: 1, bytes: expected_bytes });
            assert_eq!(failure.progress.recorded, Counts::default());
            assert!(failure.progress.payloads_verified);
            let native = failure.native.take().ok_or("actual ACK owner was erased by WAL failure")?;
            assert_eq!(native.submission(), Submission::Submitted);
            assert!(matches!(native.outcome(), Some(NativeOutcome::Status { code: 1, min_expiration }) if min_expiration == AbsoluteTime::from_micros(123)));
            assert_eq!(native.response_bytes(), Some(ack.as_slice()));
            assert!(matches!(native.response()?, Some(Response::Status(status)) if status.code == 1 && status.message == Some(b"receipt \xff\xfe\0".as_slice())));
            assert!(task.status().fenced);
            assert!(task.status().uncertain);
            let original_intent = task.status().pending.ok_or("failed ACK append erased the original intent")?;
            assert_eq!(original_intent.attempt, native.attempt());
            assert_eq!(original_intent.disposition, Disposition::Intent);
            // Repair only the fixture's empty replacement. A fenced original
            // owner remains unusable even after its physical name is restored.
            fs::remove_dir(&path)?;
            fs::rename(&saved, &path)?;
            assert!(native.record(&mut task).is_err());
            assert!(task.status().fenced);
            assert_eq!(task.status().recorded, Counts::default());
            drop(task);
            let mut reopened = Task::open(&path, store::Limits::default())?;
            assert_eq!(reopened.task_id(), &task_id);
            assert_eq!(reopened.status().recorded, Counts::default());
            assert_eq!(reopened.status().pending, Some(original_intent));
            assert!(reopened.status().uncertain);
            assert!(!reopened.status().fenced);
            assert_eq!(native.record(&mut reopened)?, Effect::Accepted);
            assert_eq!(reopened.status().recorded, Counts { accepted: 1, bytes: expected_bytes });
            assert!(reopened.status().pending.is_none());
            assert!(!reopened.status().uncertain);
            // Reattaching the same original ACK is idempotent ledger access.
            let records = reopened.status().state_records;
            assert_eq!(native.record(&mut reopened)?, Effect::Accepted);
            assert_eq!(reopened.status().state_records, records);
            drop(reopened);
            let mut reopened = Task::open(&path, store::Limits::default())?;
            let (endpoint, deadline) = source(&socket)?;
            let done = reopened.run(endpoint, &mut buffers, deadline, |_| Control::Continue).await?;
            assert_eq!(done.reason, StopReason::Complete);
            assert!(done.progress.payloads_verified);
            assert_eq!(done.progress.historical, Counts { accepted: 1, bytes: expected_bytes });
            assert_eq!(done.progress.recorded, done.progress.historical);
            assert_eq!(done.progress.new_accepted, Counts::default());
            assert!(done.last_native.is_none());
            let proof = done.completed.ok_or("historical ACK completion lacks fresh payload proof")?;
            assert_eq!(proof.verified.puts(), 1);
            assert_eq!(proof.verified.bytes(), expected_bytes);
            assert_eq!(reopened.status().phase, Phase::Complete);
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        timeout(WAIT, async { tokio::try_join!(publish, peer) }).await??;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
