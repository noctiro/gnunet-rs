//! Actual native range success survives an independent original WAL-name refusal.
//! Local Rust official-wire peers establish only this receipt/recovery scope;
//! this is not original-C, P2P, or whole-node interoperability acceptance.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The fallible native receipt regression asserts original frames, authority and recovery facts"
)]
use gnunet_fs::{
    Content, Uri,
    content::{self, BLOCK_BYTES, TAG_BYTES},
};
use gnunet_fs_host::{
    Buffers,
    durable::store::{Certainty, FailureKind},
    ipc::EndpointSource,
    network::probe,
    probe_task::{self, Cause, Control, Kind, Limits, Phase, Task},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
use std::{
    fs, io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        loop {
            let path = std::env::temp_dir().join(format!(
                "gnunet-probe-receipt-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < header.len() {
        return Err(io::Error::other("invalid native frame length"));
    }
    let mut bytes = vec![0; length];
    bytes[..header.len()].copy_from_slice(&header);
    stream.read_exact(&mut bytes[header.len()..]).await?;
    Ok(bytes)
}

#[test]
fn actual_probe_success_receipt_survives_wal_authority_failure_and_records_only_original_task()
-> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temporary::new()?;
            let plaintext = b"actual authenticated probe before independent journal refusal";
            let mut ciphertext = vec![0; BLOCK_BYTES + TAG_BYTES];
            let encoded = content::encode_data(plaintext, &mut ciphertext)?;
            let key = encoded.key();
            let cipher = encoded.bytes().to_vec();
            let content = Content {
                key: key.key,
                query: key.query,
                size: plaintext.len() as u64,
            };
            let path = temp.0.join("task");
            let wal = path.join("records.wal");
            let saved = path.join("records.saved");
            let socket = temp.0.join("fs.sock");
            let listener = UnixListener::bind(&socket)?;
            let source = EndpointSource::unix(socket);
            let now = source.clock().sample()?.now;
            let deadline = AbsoluteTime::from_micros(now.as_micros() + 5_000_000);
            let options = probe::Options::new(deadline);
            let limits = Limits::default();
            let mut task = Task::create(&path, Uri::Content(content), options, limits)?;
            let original_id = *task.task_id();
            let searches = AtomicUsize::new(0);
            let mut injected = false;
            let mut injection_error = None;
            let mut original_wal = None;
            let mut original_inode = None;
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let original = frame(&mut stream).await?;
                let Request::Search(search) = Request::decode(&original)? else {
                    return Err("expected the actual original FS SEARCH".into());
                };
                assert_eq!(search.block_type, BlockType::DBLOCK);
                assert_eq!(search.query, content.query);
                assert_eq!(search.options, 0);
                assert_eq!(search.anonymity, 1);
                assert_eq!(search.target, [0; 32]);
                assert!(search.seen.is_empty());
                searches.fetch_add(1, Ordering::Relaxed);
                let response = Response::Put(ClientPut {
                    block_type: BlockType::DBLOCK,
                    expiration: AbsoluteTime::from_micros(now.as_micros() + 60_000_000),
                    last_transmission: AbsoluteTime::from_micros(7),
                    num_transmissions: 17,
                    respect_offered: 13,
                    block: &cipher,
                });
                let mut bytes = vec![0; response.encoded_len()?];
                response.encode(&mut bytes)?;
                for chunk in bytes.chunks(7) {
                    stream.write_all(chunk).await?;
                }
                // The genuine original owner closes after native success, even
                // though the independent ledger append will subsequently refuse.
                let mut extra = [0];
                assert_eq!(stream.read(&mut extra).await?, 0);
                Ok::<_, Box<dyn std::error::Error>>(bytes)
            };
            let run = async {
                let actual = task
                    .run(source, &mut Buffers::new(), 0, deadline, |progress| {
                        if progress.blocks == 1 && !injected {
                            injected = true;
                            let action = (|| -> io::Result<()> {
                                let bytes = fs::read(&wal)?;
                                let identity = fs::metadata(&wal)?;
                                fs::rename(&wal, &saved)?;
                                original_wal = Some(bytes);
                                original_inode = Some((identity.dev(), identity.ino()));
                                Ok(())
                            })();
                            if let Err(error) = action {
                                injection_error = Some(error);
                            }
                        }
                        Control::Continue
                    })
                    .await;
                Ok::<_, Box<dyn std::error::Error>>(actual)
            };
            let (actual, raw) = timeout(Duration::from_secs(3), async {
                tokio::try_join!(run, peer)
            })
            .await??;
            if let Some(error) = injection_error {
                return Err(error.into());
            }
            assert!(injected);
            assert!(!wal.exists());
            let failure = actual
                .err()
                .ok_or("expected original WAL-name authority refusal")?;
            match &failure.cause {
                Cause::Storage(error) => {
                    assert_eq!(error.failure().stage, "name-authority");
                    assert_eq!(error.failure().certainty, Certainty::NotWritten);
                    // Missing original name retains actual ENOENT, rather than
                    // inventing a replaced-inode or unknown append declaration.
                    assert_eq!(error.failure().kind, FailureKind::Io);
                    assert_eq!(
                        error.failure().io.as_ref().map(|e| e.kind()),
                        Some(io::ErrorKind::NotFound)
                    );
                }
                other => return Err(format!("unexpected original ledger cause: {other}").into()),
            }
            let probe_task::Failure {
                receipt,
                recorded,
                status,
                ..
            } = *failure;
            let receipt =
                receipt.ok_or("actual native receipt was lost by independent WAL failure")?;
            let recorded = recorded.ok_or("actual native proof/path was lost by WAL failure")?;
            let Ok(observed) = recorded.result() else {
                return Err("independent ledger refusal replaced actual native success".into());
            };
            assert_eq!(receipt.kind(), Kind::Success);
            assert_eq!(observed.verified().content(), content);
            assert_eq!(observed.range(), 0..content.size);
            assert_eq!(observed.progress().blocks, 1);
            assert_eq!(observed.progress().plaintext_bytes, content.size);
            assert_eq!(observed.queries_written(), 1);
            assert!(observed.retired());
            assert_eq!(observed.last_response(), raw.as_slice());
            assert_eq!(recorded.frames(), &[raw]);
            let before = status.ok_or("missing actual original task status")?;
            assert_eq!(before.phase, Phase::Running);
            assert!(!before.active);
            assert_eq!(before.pending, Some(receipt.attempt()));
            assert_eq!(before.historical.successes(), 0);
            assert_eq!(before.historical.trials(), 0);
            let bytes = original_wal.ok_or("missing preserved original WAL bytes")?;
            let identity = original_inode.ok_or("missing preserved original WAL identity")?;
            assert_eq!(fs::read(&saved)?, bytes);
            let metadata = fs::metadata(&saved)?;
            assert_eq!((metadata.dev(), metadata.ino()), identity);
            drop(task);
            fs::rename(&saved, &wal)?;
            assert_eq!(fs::read(&wal)?, bytes);
            let metadata = fs::metadata(&wal)?;
            assert_eq!((metadata.dev(), metadata.ino()), identity);
            let mut reopened = Task::open(&path, limits)?;
            assert_eq!(*reopened.task_id(), original_id);
            assert_eq!(fs::read(&wal)?, bytes);
            let pending = reopened.status();
            assert_eq!(pending.pending, Some(receipt.attempt()));
            let settled = receipt.record(&mut reopened)?;
            assert_eq!(settled.state_records, pending.state_records + 1);
            assert_eq!(settled.phase, Phase::Paused);
            assert_eq!(settled.pending, None);
            assert_eq!(settled.historical.successes(), 1);
            assert_eq!(settled.historical.trials(), 1);
            assert_eq!(settled.historical.rank(), 1);
            let committed = fs::read(&wal)?;
            assert!(committed.starts_with(&bytes));
            reopened.verify_history(&mut Buffers::new())?;
            let again = receipt.record(&mut reopened)?;
            assert_eq!(again.state_records, settled.state_records);
            assert_eq!(again.historical.trials(), 1);
            assert_eq!(fs::read(&wal)?, committed);
            let foreign_path = temp.0.join("foreign");
            let mut foreign = Task::create(&foreign_path, Uri::Content(content), options, limits)?;
            assert_ne!(*foreign.task_id(), original_id);
            let foreign_wal = foreign_path.join("records.wal");
            let foreign_before = fs::read(&foreign_wal)?;
            assert!(matches!(
                receipt.record(&mut foreign),
                Err(Cause::Protocol(ProtocolError::StaleGeneration))
            ));
            assert_eq!(foreign.status().phase, Phase::Ready);
            assert_eq!(foreign.status().historical.trials(), 0);
            assert_eq!(fs::read(&foreign_wal)?, foreign_before);
            tokio::task::yield_now().await;
            assert_eq!(searches.load(Ordering::Relaxed), 1);
            let extra_connection =
                std::future::poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_ready())).await;
            assert!(!extra_connection);
            Ok(())
        })
}
