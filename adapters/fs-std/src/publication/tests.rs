//! Real local task/WAL/spool/native frames; this fixture is not C/P2P acceptance.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible end-to-end tests assert actual receipts, immutable payloads and retained mutation uncertainty"
)]
use super::*;
use crate::BlockSource;
use gnunet_fs::{
    Content,
    content::{BLOCK_BYTES, NodeRef},
};
use gnunet_wire::official::{AbsoluteTime, datastore::Status as NativeStatus};
use std::{
    fs,
    io::{self, Write},
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
    time::{sleep, timeout},
};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-pt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn bind(&self) -> io::Result<(PathBuf, UnixListener)> {
        let path = self.0.join("native.sock");
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
        priority: 7,
        anonymity: 2,
        replication: 3,
        expiration: AbsoluteTime::from_micros(1_234_567_890),
    }
}
fn prepared(temp: &Temporary) -> TestResult<(Task, Vec<u8>, PathBuf)> {
    // Identical complete data leaves must remain two weighted native PUTs.
    let bytes = vec![0x73; 2 * BLOCK_BYTES];
    let source = temp.0.join("source");
    fs::write(&source, &bytes)?;
    let mut input = crate::open_input(&source)?;
    let task = Task::create_file(
        temp.0.join("task"),
        &mut input,
        &mut Buffers::new(),
        blocks(),
        Limits::default(),
        |_| crate::Control::Continue,
    )?;
    assert_eq!(task.manifest().plan.puts.len(), 3);
    assert_eq!(
        task.manifest().plan.puts[0].payload,
        task.manifest().plan.puts[1].payload
    );
    assert_eq!(
        task.manifest().plan.puts[0].key,
        task.manifest().plan.puts[1].key
    );
    assert_ne!(
        task.manifest().plan.puts[0].position,
        task.manifest().plan.puts[1].position
    );
    Ok((task, bytes, source))
}
fn content(task: &Task) -> TestResult<Content> {
    match task.manifest().plan.artifact {
        plan::Artifact::File(content) => Ok(content),
        _ => Err("expected actual full-file artifact".into()),
    }
}
fn source(path: &Path) -> TestResult<(EndpointSource, AbsoluteTime)> {
    let source = EndpointSource::unix(path.to_owned());
    let now = source.clock().sample()?.now;
    let deadline = AbsoluteTime::from_micros(
        now.as_micros()
            .checked_add(30_000_000)
            .ok_or("deadline overflow")?,
    );
    Ok((source, deadline))
}
async fn frame(stream: &mut UnixStream) -> TestResult<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err("short native frame".into());
    }
    let mut bytes = vec![0; n];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn exact_put(bytes: &[u8], put: plan::Put, policy: BlockOptions) -> TestResult {
    let Request::Put(data) = Request::decode(bytes)? else {
        return Err("expected PUT".into());
    };
    assert_eq!((data.reservation, data.uid), (0, 0));
    assert_eq!(
        (data.priority, data.anonymity, data.replication),
        (policy.priority, policy.anonymity, policy.replication)
    );
    assert_eq!(data.expiration, policy.expiration);
    assert_eq!(data.kind, put.kind);
    assert_eq!(data.key, &put.key);
    assert_eq!(data.value.len(), put.payload.bytes);
    assert_eq!(gnunet_crypto::hash512(data.value), put.payload.hash);
    Ok(())
}
fn acknowledgement() -> TestResult<Vec<u8>> {
    // Code zero is accepted too; the existing object can receive score updates.
    let response = Response::Status(NativeStatus {
        code: 0,
        min_expiration: AbsoluteTime::from_micros(77),
        message: Some(b"accepted \xff\0"),
    });
    let mut wire = vec![0; 65535];
    let used = response.encode(&mut wire)?;
    wire.truncate(used);
    Ok(wire)
}
async fn closed(stream: &mut UnixStream) -> TestResult {
    let mut extra = [0];
    assert_eq!(stream.read(&mut extra).await?, 0);
    Ok(())
}
async fn no_connection(listener: &UnixListener) -> TestResult {
    assert!(
        timeout(Duration::from_millis(40), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
async fn acknowledged(
    task: &mut Task,
    path: &Path,
    listener: &UnixListener,
    count: usize,
    pause: bool,
) -> TestResult<(Outcome, Vec<Vec<u8>>)> {
    let start = task.status().recorded.accepted;
    let puts = task.manifest().plan.puts.clone();
    let policy = task.manifest().blocks;
    let reply = acknowledgement()?;
    let peer = async {
        let (mut stream, _) = listener.accept().await?;
        let mut frames = Vec::new();
        for put in puts.iter().skip(start).take(count) {
            let bytes = frame(&mut stream).await?;
            exact_put(&bytes, *put, policy)?;
            frames.push(bytes);
            stream.write_all(&reply).await?;
        }
        closed(&mut stream).await?;
        Ok::<_, Box<dyn std::error::Error>>(frames)
    };
    let host = async {
        let (source, deadline) = source(path)?;
        let answer = task
            .run(source, &mut Buffers::new(), deadline, |progress| {
                if pause && progress.recorded.accepted >= start + count {
                    Control::Pause
                } else {
                    Control::Continue
                }
            })
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(answer)
    };
    let (frames, outcome) = timeout(WAIT, async { tokio::try_join!(peer, host) }).await??;
    no_connection(listener).await?;
    Ok((outcome, frames))
}
struct Received<'a>(&'a [Vec<u8>]);
impl BlockSource for Received<'_> {
    fn read_block(&mut self, node: NodeRef, output: &mut [u8]) -> crate::Result<usize> {
        for bytes in self.0 {
            let Request::Put(data) = Request::decode(bytes)? else {
                return Err(crate::Error::Corrupt);
            };
            if data.key == &node.key().query {
                let n = data.value.len();
                if output.len() < n {
                    return Err(crate::Error::Corrupt);
                }
                output[..n].copy_from_slice(data.value);
                return Ok(n);
            }
        }
        Err(crate::Error::Corrupt)
    }
}
fn object(root: &Path, hash: [u8; 64]) -> PathBuf {
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    root.join(&hex[..2]).join(&hex[2..])
}
#[test]
fn original_ack_prefix_survives_reopen_source_removal_and_repeated_weighted_blocks() -> TestResult {
    runtime()?.block_on(async {
        let temp = Temporary::new()?;
        let (path, listener) = temp.bind()?;
        let (mut task, plaintext, original) = prepared(&temp)?;
        let expected_content = content(&task)?;
        let expected_uri = Uri::Content(expected_content);
        let mut uri = vec![0; expected_uri.encoded_len()?];
        expected_uri.encode(&mut uri)?;
        let puts = task.manifest().plan.puts.clone();
        let identity = *task.task_id();
        let (paused, mut frames) = acknowledged(&mut task, &path, &listener, 1, true).await?;
        assert_eq!(paused.reason, StopReason::CallerPause);
        assert!(paused.completed.is_none());
        assert!(paused.progress.payloads_verified);
        assert_eq!(paused.progress.new_accepted.accepted, 1);
        assert_eq!(task.status().phase, Phase::Paused);
        assert!(!task.status().uncertain);
        assert_eq!(task.status().recorded.accepted, 1);
        assert_eq!(
            task.state.accepted[0].attempt.request_hash,
            gnunet_crypto::hash512(&frames[0])
        );
        drop(task);
        fs::remove_file(&original)?;
        let mut reopened = Task::open(temp.0.join("task"), store::Limits::default())?;
        assert_eq!(reopened.task_id(), &identity);
        assert_eq!(reopened.manifest().plan.puts, puts);
        assert_eq!(reopened.status().recorded.accepted, 1);
        assert_eq!(
            reopened.state.accepted[0].attempt.request_hash,
            gnunet_crypto::hash512(&frames[0])
        );
        let (outcome, remaining) = acknowledged(&mut reopened, &path, &listener, 2, false).await?;
        frames.extend(remaining);
        assert_eq!(outcome.reason, StopReason::Complete);
        assert!(outcome.cleanup.is_none());
        assert_eq!(outcome.progress.historical.accepted, 1);
        assert_eq!(outcome.progress.new_accepted.accepted, 2);
        assert_eq!(outcome.progress.recorded.accepted, 3);
        let completed = outcome.completed.ok_or("missing actual completion")?;
        let real = completed
            .verified
            .file()
            .ok_or("missing core FileReader receipt")?;
        assert_eq!(real.verified.content(), expected_content);
        let actual_uri = Uri::Content(real.verified.content());
        let mut actual = vec![0; actual_uri.encoded_len()?];
        actual_uri.encode(&mut actual)?;
        assert_eq!(actual, uri);
        assert_eq!(completed.verified.puts(), 3);
        assert_eq!(reopened.status().phase, Phase::Complete);
        assert_eq!(frames.len(), 3);
        for (accepted, bytes) in reopened.state.accepted.iter().zip(&frames) {
            assert_eq!(accepted.attempt.request_hash, gnunet_crypto::hash512(bytes));
            let record = reopened
                .store
                .read_record(accepted.record_index)?
                .ok_or("missing original ACK")?;
            let (_, raw, _) = codec::accepted_view(record.kind, record.bytes)?;
            assert_eq!(raw, acknowledgement()?);
        }
        assert_eq!(Request::decode(&frames[0])?, Request::decode(&frames[1])?);
        let mut output = Vec::new();
        let receipt = Buffers::new().copy_to(
            &mut Received(&frames),
            expected_content,
            &mut output,
            crate::Limits::default(),
            |_| crate::Control::Continue,
        )?;
        assert_eq!(receipt.verified.content(), expected_content);
        assert_eq!(output, plaintext);
        Ok(())
    })
}
#[test]
fn a_fully_written_unacknowledged_put_remains_unknown_after_reopen_and_cancel() -> TestResult {
    runtime()?.block_on(async {
        let temp = Temporary::new()?;
        let (path, listener) = temp.bind()?;
        let (mut task, _, _) = prepared(&temp)?;
        let first = task.manifest().plan.puts[0];
        let policy = task.manifest().blocks;
        let seen = Arc::new(AtomicBool::new(false));
        let received = seen.clone();
        let paused = Arc::new(AtomicBool::new(false));
        let stop = paused.clone();
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let bytes = frame(&mut stream).await?;
            exact_put(&bytes, first, policy)?;
            received.store(true, Ordering::SeqCst);
            // Quiet after receiving the entire mutation; never manufacture ACK.
            while !stop.load(Ordering::SeqCst) {
                sleep(Duration::from_millis(2)).await;
            }
            stream.shutdown().await?;
            drop(stream);
            Ok::<_, Box<dyn std::error::Error>>(bytes)
        };
        let host = async {
            let (source, deadline) = source(&path)?;
            let failure = task
                .run(source, &mut Buffers::new(), deadline, |_| {
                    if seen.load(Ordering::SeqCst) {
                        paused.store(true, Ordering::SeqCst);
                        Control::Pause
                    } else {
                        Control::Continue
                    }
                })
                .await
                .err()
                .ok_or("unknown mutation became settled publication")?;
            assert_eq!(failure.requested_stop, Some(StopReason::CallerPause));
            let native = failure
                .native
                .as_ref()
                .ok_or("missing original native result")?;
            assert_eq!(native.submission(), Submission::Submitted);
            assert_eq!(native.outcome(), Some(NativeOutcome::Unknown));
            assert_eq!(native.interruption(), Some(Interruption::Cancelled));
            assert!(native.response_bytes().is_none());
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (bytes, ()) = timeout(WAIT, async { tokio::try_join!(peer, host) }).await??;
        let pending = task.status().pending.ok_or("missing unknown intent")?;
        assert_eq!(pending.attempt.request_hash, gnunet_crypto::hash512(&bytes));
        assert!(matches!(
            pending.disposition,
            Disposition::Unknown {
                outcome: NativeOutcome::Unknown,
                ..
            }
        ));
        assert_eq!(task.status().phase, Phase::Uncertain);
        assert!(task.status().uncertain);
        assert_eq!(task.status().recorded.accepted, 0);
        drop(task);
        let mut reopened = Task::open(temp.0.join("task"), store::Limits::default())?;
        assert_eq!(reopened.status().pending, Some(pending));
        let records = reopened.status().state_records;
        let (source, deadline) = source(&path)?;
        let failure = reopened
            .run(source, &mut Buffers::new(), deadline, |_| Control::Continue)
            .await
            .err()
            .ok_or("unknown mutation auto-replayed")?;
        assert!(matches!(failure.cause, Some(Cause::State(_))));
        assert_eq!(reopened.status().state_records, records);
        assert_eq!(reopened.status().pending, Some(pending));
        no_connection(&listener).await?;
        reopened.request_cancel()?;
        let cancelled = reopened.settle_cancel()?;
        assert_eq!(cancelled.reason, StopReason::Cancelled);
        assert!(cancelled.completed.is_none());
        assert_eq!(reopened.status().phase, Phase::Cancelled);
        assert_eq!(reopened.status().pending, Some(pending));
        assert!(reopened.status().uncertain);
        drop(reopened);
        let cancelled = Task::open(temp.0.join("task"), store::Limits::default())?;
        assert_eq!(cancelled.status().phase, Phase::Cancelled);
        assert_eq!(cancelled.status().pending, Some(pending));
        no_connection(&listener).await?;
        Ok(())
    })
}
#[test]
fn changed_spool_payload_prevents_new_puts_and_keeps_the_original_ack_prefix() -> TestResult {
    runtime()?.block_on(async {
        let temp = Temporary::new()?;
        let (path, listener) = temp.bind()?;
        let (mut task, _, original) = prepared(&temp)?;
        let hash = task.manifest().plan.puts[0].payload.hash;
        let (paused, frames) = acknowledged(&mut task, &path, &listener, 1, true).await?;
        assert_eq!(paused.reason, StopReason::CallerPause);
        let accepted = task.state.accepted[0].attempt;
        assert_eq!(accepted.request_hash, gnunet_crypto::hash512(&frames[0]));
        drop(task);
        fs::remove_file(original)?;
        let target = object(&temp.0.join("task/objects"), hash);
        let mut damaged = fs::OpenOptions::new().write(true).open(target)?;
        damaged.write_all(b"damaged ciphertext")?;
        damaged.sync_all()?;
        drop(damaged);
        let mut reopened = Task::open(temp.0.join("task"), store::Limits::default())?;
        assert_eq!(reopened.status().recorded.accepted, 1);
        let (source, deadline) = source(&path)?;
        let failure = reopened
            .run(source, &mut Buffers::new(), deadline, |_| Control::Continue)
            .await
            .err()
            .ok_or("damaged immutable payload reached native publication")?;
        assert!(matches!(failure.cause, Some(Cause::Plan(_))));
        assert!(failure.native.is_none());
        assert!(!failure.progress.payloads_verified);
        assert_eq!(failure.progress.historical.accepted, 1);
        assert_eq!(failure.progress.recorded.accepted, 1);
        assert_eq!(reopened.state.accepted[0].attempt, accepted);
        assert!(reopened.status().pending.is_none());
        no_connection(&listener).await?;
        drop(reopened);
        let loaded = Task::open(temp.0.join("task"), store::Limits::default())?;
        assert_eq!(loaded.status().recorded.accepted, 1);
        assert_eq!(loaded.state.accepted[0].attempt, accepted);
        Ok(())
    })
}
