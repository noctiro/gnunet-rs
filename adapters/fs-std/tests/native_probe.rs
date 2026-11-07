//! Actual FS MQ observations of one encrypted Merkle path, including tail/empty
//! roots, cooperative cancellation and independently retained corrupt replies.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native range tests assert real wire requests, receipts and original owner retirement"
)]
use gnunet_fs::{
    Content,
    content::{BLOCK_BYTES, EncodedNode, Layout, TAG_BYTES},
};
use gnunet_fs_host::{
    BlockSink, Buffers, Control, Insert, Limits, Progress,
    ipc::EndpointSource,
    network::{DownloadOptions, Error, probe::Options},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Blocks = HashMap<[u8; 64], (BlockType, Vec<u8>)>;
struct Temp(PathBuf);
impl Temp {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-native-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct Store(Blocks);
impl BlockSink for Store {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> gnunet_fs_host::Result<Insert> {
        let kind = if encoded.node().level() == 0 {
            BlockType::DBLOCK
        } else {
            BlockType::IBLOCK
        };
        self.0.insert(
            encoded.block().key().query,
            (kind, encoded.block().bytes().to_vec()),
        );
        Ok(Insert::Created)
    }
}
fn tree(data: &[u8]) -> Result<(Content, Blocks), gnunet_fs_host::Error> {
    let mut store = Store::default();
    let published = Buffers::new().publish(
        &mut io::Cursor::new(data),
        data.len() as u64,
        &mut store,
        Limits::default(),
        |_| Control::Continue,
    )?;
    Ok((published.content, store.0))
}
fn options(source: &EndpointSource) -> Result<Options, ProtocolError> {
    let transfer = DownloadOptions {
        anonymity: 7,
        target: [73; 32],
        io_slice_bytes: 7,
        ..DownloadOptions::new(AbsoluteTime::from_micros(
            source.clock().sample()?.now.as_micros() + 5_000_000,
        ))
    };
    Ok(Options::from(transfer))
}
async fn request(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("short FS frame"));
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}
fn reply(kind: BlockType, block: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let response = Response::Put(ClientPut {
        block_type: kind,
        expiration: AbsoluteTime::from_micros(1),
        last_transmission: AbsoluteTime::from_micros(0),
        num_transmissions: 0,
        respect_offered: 0,
        block,
    });
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    Ok(bytes)
}
fn selected<'a>(
    frame: &[u8],
    blocks: &'a Blocks,
) -> Result<(BlockType, &'a [u8]), Box<dyn std::error::Error>> {
    let Request::Search(search) = Request::decode(frame)? else {
        return Err("unexpected FS request".into());
    };
    assert_eq!(search.options, 0);
    assert_eq!(search.anonymity, 7);
    assert_eq!(search.target, [73; 32]);
    let (kind, block) = blocks
        .get(&search.query)
        .ok_or("unexpected non-path query")?;
    assert_eq!(*kind, search.block_type);
    Ok((*kind, block))
}

#[test]
fn native_probe_fetches_only_tail_path_and_real_empty_root() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for data in [vec![19; 3 * BLOCK_BYTES + 19], Vec::new()] {
                let temp = Temp::new()?;
                let (content, blocks) = tree(&data)?;
                let layout = Layout::new(content.size);
                let leaf = layout.leaf_count() - 1;
                let range = layout.leaf(leaf)?.range();
                let socket = temp.0.join("fs.sock");
                let listener = UnixListener::bind(&socket)?;
                let source = EndpointSource::unix(socket);
                let mut policy = options(&source)?;
                // Whole-file encoded work is irrelevant to this one-path budget.
                policy.transfer.limits.max_encoded_bytes = 0;
                let mut node = layout.leaf(leaf)?;
                let mut encoded = 0u128;
                let mut expected = 0u64;
                loop {
                    expected += 1;
                    encoded += (node.plaintext_bytes() + TAG_BYTES) as u128;
                    let Some(parent) = node.parent() else { break };
                    node = parent;
                }
                policy.max_path_blocks = expected;
                policy.max_encoded_bytes = encoded;
                let peer = async {
                    let (mut stream, _) = listener.accept().await?;
                    let mut sent = Vec::new();
                    for index in 0..expected {
                        let frame = request(&mut stream).await?;
                        let (kind, block) = selected(&frame, &blocks)?;
                        if index == expected - 1 {
                            assert_eq!(kind, BlockType::DBLOCK);
                            assert_eq!(block.len(), (range.end - range.start) as usize + TAG_BYTES);
                        }
                        let actual = reply(kind, block)?;
                        // Physical slices exercise the same retained read cursor.
                        for chunk in actual.chunks(11) {
                            stream.write_all(chunk).await?;
                        }
                        sent.push(actual);
                    }
                    let mut extra = [0];
                    assert_eq!(stream.read(&mut extra).await?, 0);
                    Ok::<_, Box<dyn std::error::Error>>(sent)
                };
                let run = async {
                    let recorded = Buffers::new()
                        .probe_recorded(source, content, leaf, policy, |_| Control::Continue)
                        .await;
                    assert_eq!(recorded.frames().len(), expected as usize);
                    assert!(recorded.result().is_ok());
                    let (result, frames) = recorded.into_parts();
                    result
                        .map(|observed| (observed, frames))
                        .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
                };
                let ((observed, frames), raw) = timeout(Duration::from_secs(3), async {
                    tokio::try_join!(run, peer)
                })
                .await??;
                assert_eq!(observed.verified().content(), content);
                assert_eq!(observed.range(), range);
                assert_eq!(observed.leaf(), leaf);
                assert_eq!(observed.progress().blocks, expected);
                assert_eq!(observed.progress().plaintext_bytes, range.end - range.start);
                assert_eq!(observed.progress().encoded_bytes, encoded);
                assert_eq!(observed.queries_written(), expected);
                assert_eq!(frames, raw);
                assert_eq!(
                    observed.last_response(),
                    raw.last().ok_or("missing actual response")?.as_slice()
                );
                let mut replay = Buffers::new();
                let historical = gnunet_fs_host::network::probe::revalidate(
                    content,
                    leaf,
                    &frames,
                    &mut replay,
                )?;
                assert_eq!(historical, observed.verified());
                let (progress, completion) = gnunet_fs_host::network::probe::revalidate_prefix(
                    content,
                    leaf,
                    &frames,
                    &mut replay,
                )?;
                assert_eq!(completion, Some(historical));
                assert_eq!(
                    (
                        progress.blocks,
                        progress.plaintext_bytes,
                        progress.encoded_bytes
                    ),
                    (
                        observed.progress().blocks,
                        observed.progress().plaintext_bytes,
                        observed.progress().encoded_bytes
                    )
                );
                let (prefix, incomplete) = gnunet_fs_host::network::probe::revalidate_prefix(
                    content,
                    leaf,
                    &frames[..frames.len() - 1],
                    &mut replay,
                )?;
                assert!(incomplete.is_none());
                assert_eq!(prefix.blocks, expected - 1);
                assert_eq!(prefix.plaintext_bytes, 0);
                assert!(matches!(
                    gnunet_fs_host::network::probe::revalidate(
                        content,
                        leaf,
                        &frames[..frames.len() - 1],
                        &mut replay
                    ),
                    Err(Error::Protocol(ProtocolError::Malformed))
                ));
                let mut extra = frames.clone();
                extra.push(frames[0].clone());
                assert!(matches!(
                    gnunet_fs_host::network::probe::revalidate(content, leaf, &extra, &mut replay),
                    Err(Error::Protocol(ProtocolError::Malformed))
                ));
                let mut wrong_type = frames.clone();
                let actual_type = if layout.root_level() == 0 {
                    BlockType::IBLOCK
                } else {
                    BlockType::DBLOCK
                };
                wrong_type[0][4..8].copy_from_slice(&actual_type.value().to_be_bytes());
                assert!(matches!(
                    gnunet_fs_host::network::probe::revalidate(
                        content,
                        leaf,
                        &wrong_type,
                        &mut replay
                    ),
                    Err(Error::Protocol(ProtocolError::Authentication))
                ));
                let mut corrupt = frames.clone();
                let last = corrupt.last_mut().ok_or("missing actual response")?;
                let byte = last.last_mut().ok_or("missing actual ciphertext")?;
                *byte ^= 1;
                assert!(matches!(
                    gnunet_fs_host::network::probe::revalidate(
                        content,
                        leaf,
                        &corrupt,
                        &mut replay
                    ),
                    Err(Error::Protocol(ProtocolError::Authentication))
                ));
                assert_eq!(observed.policy().target, [73; 32]);
                assert!(observed.finished() >= observed.started());
                assert!(observed.retired());
            }
            Ok(())
        })
}

#[test]
fn quiet_partial_leaf_cancel_preserves_authenticated_path_and_original_mq() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temp::new()?;
            let (content, blocks) = tree(&vec![21; BLOCK_BYTES + 19])?;
            let socket = temp.0.join("fs.sock");
            let listener = UnixListener::bind(&socket)?;
            let source = EndpointSource::unix(socket);
            let policy = options(&source)?;
            let cancel = Arc::new(AtomicBool::new(false));
            let wanted = cancel.clone();
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let first = request(&mut stream).await?;
                let (kind, block) = selected(&first, &blocks)?;
                assert_eq!(kind, BlockType::IBLOCK);
                let root = reply(kind, block)?;
                stream.write_all(&root).await?;
                let next = request(&mut stream).await?;
                let (kind, block) = selected(&next, &blocks)?;
                assert_eq!(kind, BlockType::DBLOCK);
                let leaf = reply(kind, block)?;
                // Leave a genuine incomplete response on the original read cursor.
                stream.write_all(&leaf[..5]).await?;
                wanted.store(true, Ordering::SeqCst);
                let mut extra = [0];
                assert_eq!(stream.read(&mut extra).await?, 0);
                Ok::<_, Box<dyn std::error::Error>>(root)
            };
            let run = async {
                let recorded = Buffers::new()
                    .probe_recorded(source, content, 1, policy, |_| {
                        if cancel.load(Ordering::SeqCst) {
                            Control::Cancel
                        } else {
                            Control::Continue
                        }
                    })
                    .await;
                let (result, frames) = recorded.into_parts();
                let failure = result.err().ok_or("expected cancellation")?;
                assert!(matches!(failure.cause(), Error::Cancelled(_)));
                assert_eq!(failure.progress().blocks, 1);
                assert_eq!(failure.progress().plaintext_bytes, 0);
                assert_eq!(failure.queries_written(), 2);
                assert_eq!(failure.range(), Some(BLOCK_BYTES as u64..content.size));
                assert!(failure.retired());
                Ok::<_, Box<dyn std::error::Error>>((failure, frames))
            };
            let ((failure, frames), root) = timeout(Duration::from_secs(3), async {
                tokio::try_join!(run, peer)
            })
            .await??;
            assert_eq!(failure.last_response(), root);
            assert_eq!(frames, vec![root]);
            let (prefix, proof) = gnunet_fs_host::network::probe::revalidate_prefix(
                content,
                1,
                &frames,
                &mut Buffers::new(),
            )?;
            assert!(proof.is_none());
            assert_eq!(
                (prefix.blocks, prefix.plaintext_bytes, prefix.encoded_bytes),
                (
                    failure.progress().blocks,
                    failure.progress().plaintext_bytes,
                    failure.progress().encoded_bytes
                )
            );
            let extra_connection =
                std::future::poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_ready())).await;
            assert!(!extra_connection);
            Ok(())
        })
}

#[test]
fn bad_native_type_retains_exact_reply_and_path_budget_refuses_before_query() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temp::new()?;
            let (content, blocks) = tree(&[31])?;
            let socket = temp.0.join("fs.sock");
            let listener = UnixListener::bind(&socket)?;
            let source = EndpointSource::unix(socket);
            let mut policy = options(&source)?;
            policy.max_path_blocks = 0;
            let failure = Buffers::new()
                .probe(source.duplicate()?, content, 0, policy, |_| {
                    Control::Continue
                })
                .await
                .err()
                .ok_or("expected budget refusal")?;
            assert!(matches!(
                failure.cause(),
                Error::Local(gnunet_fs_host::Error::Limit)
            ));
            assert_eq!(failure.range(), Some(0..1));
            assert_eq!(failure.queries_written(), 0);
            assert_eq!(failure.progress(), Progress::default());
            assert!(failure.started().is_none());
            assert!(!failure.retired());
            assert!(
                !std::future::poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_ready())).await
            );
            policy.max_path_blocks = 1;
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let frame = request(&mut stream).await?;
                let (_, block) = selected(&frame, &blocks)?;
                // Same authentic query bytes, wrong actual response block type.
                let raw = reply(BlockType::IBLOCK, block)?;
                stream.write_all(&raw).await?;
                let mut extra = [0];
                assert_eq!(stream.read(&mut extra).await?, 0);
                Ok::<_, Box<dyn std::error::Error>>(raw)
            };
            let run = async {
                let failure = Buffers::new()
                    .probe(source, content, 0, policy, |_| Control::Continue)
                    .await
                    .err()
                    .ok_or("expected authentication refusal")?;
                assert!(matches!(
                    failure.cause(),
                    Error::Protocol(ProtocolError::Authentication)
                ));
                assert_eq!(failure.progress(), Progress::default());
                assert_eq!(failure.queries_written(), 1);
                assert!(failure.retired());
                Ok::<_, Box<dyn std::error::Error>>(failure)
            };
            let (failure, raw) = timeout(Duration::from_secs(3), async {
                tokio::try_join!(run, peer)
            })
            .await??;
            assert_eq!(failure.last_response(), raw);
            Ok(())
        })
}

#[test]
fn quiet_native_deadline_is_an_inconclusive_attempt_and_setup_deadline_is_distinct() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temp::new()?;
            let socket = temp.0.join("fs.sock");
            let listener = UnixListener::bind(&socket)?;
            let source = EndpointSource::unix(socket);
            let content = Content {
                key: [11; 64],
                query: [22; 64],
                size: 1,
            };
            let mut policy = options(&source)?;
            policy.transfer.deadline =
                AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros());
            let refused = Buffers::new()
                .probe(source.duplicate()?, content, 0, policy, |_| {
                    Control::Continue
                })
                .await
                .err()
                .ok_or("expected setup deadline")?;
            assert!(matches!(refused.cause(), Error::Deadline { .. }));
            assert_eq!(refused.queries_written(), 0);
            assert!(refused.started().is_none());
            assert!(!refused.retired());
            policy.transfer.deadline =
                AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 200_000);
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let frame = request(&mut stream).await?;
                assert!(matches!(Request::decode(&frame)?, Request::Search(search)
                    if search.query == content.query && search.block_type == BlockType::DBLOCK));
                let mut extra = [0];
                assert_eq!(stream.read(&mut extra).await?, 0);
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let run = async {
                let failure = Buffers::new()
                    .probe(source, content, 0, policy, |_| Control::Continue)
                    .await
                    .err()
                    .ok_or("expected native deadline")?;
                assert!(matches!(
                    failure.cause(),
                    Error::Deadline { first_io: None }
                ));
                assert_eq!(failure.queries_written(), 1);
                assert_eq!(failure.progress(), Progress::default());
                assert!(failure.started().is_some());
                assert!(failure.last_checked().is_some());
                assert!(failure.last_response().is_empty());
                assert!(failure.retired());
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            timeout(Duration::from_secs(3), async {
                tokio::try_join!(run, peer)
            })
            .await??;
            Ok(())
        })
}
