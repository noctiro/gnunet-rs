//! Whole-file transfer over actual local test MQs and real encrypted trees.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Transfer tests assert authentication, stream and deadline boundaries"
)]
use gnunet_fs::{
    Content,
    content::{BLOCK_BYTES, EncodedNode},
};
use gnunet_fs_host::{
    BlockSink, Buffers, Control, Insert, Limits, Repository,
    ipc::EndpointSource,
    network::{DownloadOptions, Error},
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temp(PathBuf);
impl Temp {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-net-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
type Blocks = HashMap<[u8; 64], (BlockType, Vec<u8>)>;
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
        Ok(Insert::Created(gnunet_fs_host::Retention::Volatile))
    }
}
fn tree(data: &[u8]) -> Result<(Content, Blocks), gnunet_fs_host::Error> {
    let mut store = Store::default();
    let completed = Buffers::new().publish(
        &mut io::Cursor::new(data),
        data.len() as u64,
        &mut store,
        Limits::default(),
        |_| Control::Continue,
    )?;
    Ok((completed.content, store.0))
}
fn options(source: &EndpointSource, micros: u64) -> Result<DownloadOptions, gnunet_types::Error> {
    Ok(DownloadOptions {
        anonymity: 0,
        local_only: true,
        queries_per_connection: 2,
        io_slice_bytes: 4096,
        ..DownloadOptions::new(AbsoluteTime::from_micros(
            source.clock().sample()?.now.as_micros() + micros,
        ))
    })
}
async fn request(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err(io::Error::other("short frame"));
    }
    let mut frame = vec![0; n];
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(Some(frame))
}
fn reply(kind: BlockType, block: &[u8]) -> Result<Vec<u8>, gnunet_types::Error> {
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

#[test]
fn named_partial_download_reuses_verified_data_and_indices_and_honors_delete() -> TestResult {
    use gnunet_fs_host::{IncompleteOutput, OutputDir};
    use std::{fs, num::NonZeroU32};

    async fn requested(
        stream: &mut UnixStream,
        blocks: &Blocks,
    ) -> Result<[u8; 64], Box<dyn std::error::Error>> {
        let wire = request(stream).await?.ok_or("missing download request")?;
        let Request::Search(search) = Request::decode(&wire)? else {
            return Err("expected a download search".into());
        };
        let (kind, block) = blocks
            .get(&search.query)
            .ok_or("unexpected download query")?;
        assert_eq!(*kind, search.block_type);
        stream.write_all(&reply(*kind, block)?).await?;
        Ok(search.query)
    }

    let temp = Temp::new()?;
    let mut data = vec![17; BLOCK_BYTES * 2 + 23];
    data[BLOCK_BYTES..BLOCK_BYTES * 2].fill(29);
    data[BLOCK_BYTES * 2..].fill(47);
    let (content, blocks) = tree(&data)?;
    let first = gnunet_fs::content::encode_data(
        &data[..BLOCK_BYTES],
        &mut vec![0; BLOCK_BYTES + gnunet_fs::content::TAG_BYTES],
    )?
    .key()
    .query;
    let mut output = OutputDir::open(&temp.0)?;
    let mut buffers = Buffers::new();
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let socket = temp.0.join("resume.sock");
        let listener = UnixListener::bind(&socket)?;
        for (filename, policy) in [("discard", IncompleteOutput::Delete), ("keep", IncompleteOutput::Keep)] {
            let source = EndpointSource::unix(socket.clone());
            let transfer = DownloadOptions {queries_per_connection: 8, request_parallelism: NonZeroU32::MIN, ..options(&source, 3_000_000)?};
            let pull = output.download_resumable(filename, source, content, &mut buffers, transfer, policy, |progress| {
                if progress.plaintext_bytes < BLOCK_BYTES as u64 { Control::Continue } else { Control::Cancel }
            });
            let server = async {
                let (mut stream, _) = listener.accept().await?;
                assert_eq!(requested(&mut stream, &blocks).await?, content.query);
                assert_eq!(requested(&mut stream, &blocks).await?, first);
                assert!(request(&mut stream).await?.is_none());
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (stopped, served) = timeout(Duration::from_secs(4), async { tokio::join!(pull, server) }).await?;
            served?;
            assert!(matches!(stopped, Err(gnunet_fs_host::Error::Transfer(error)) if matches!(*error, Error::Cancelled(_))));
        }
        assert!(!temp.0.join("discard").exists());
        let path = temp.0.join("keep");
        let partial = fs::read(&path)?;
        assert_eq!(&partial[..BLOCK_BYTES], &data[..BLOCK_BYTES]);
        let index = BLOCK_BYTES * 3;
        let (kind, ciphertext) = blocks.get(&content.query).ok_or("missing original index")?;
        assert_eq!(*kind, BlockType::IBLOCK);
        let mut plain_index = [0; 3 * gnunet_fs::content::CHK_BYTES];
        gnunet_fs::content::open_index(gnunet_fs::content::NodeRef::root(content).key(), ciphertext, &mut plain_index)?;
        assert_eq!(&partial[index..], &plain_index);
        let source = EndpointSource::unix(socket);
        let transfer = DownloadOptions {queries_per_connection: 8, ..options(&source, 3_000_000)?};
        let pull = output.download_resumable("keep", source, content, &mut buffers, transfer, IncompleteOutput::Keep, |_|Control::Continue);
        let server = async {
            let (mut stream, _) = listener.accept().await?;
            let next = requested(&mut stream, &blocks).await?;
            let last = requested(&mut stream, &blocks).await?;
            assert_ne!(next, last);
            assert!([next,last].into_iter().all(|query| query != first && query != content.query));
            assert!(request(&mut stream).await?.is_none());
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (read, served) = timeout(Duration::from_secs(4), async { tokio::join!(pull, server) }).await?;
        served?;
        assert_eq!(read?.verified.content(), content);
        assert_eq!(fs::read(&path)?, data);

        // Completed plaintext can be reauthenticated without an available MQ.
        let source = EndpointSource::unix(temp.0.join("offline.sock"));
        let transfer = options(&source, 1_000_000)?;
        let read = output.download_resumable("keep", source, content, &mut buffers, transfer, IncompleteOutput::Delete, |_|Control::Continue).await?;
        assert_eq!(read.verified.content(), content);
        assert_eq!(fs::read(&path)?, data);

        let unrelated = temp.0.join("already-there");
        fs::write(&unrelated, b"unrelated file")?;
        let source = EndpointSource::unix(temp.0.join("resume.sock"));
        let transfer = DownloadOptions { queries_per_connection: 8, request_parallelism: NonZeroU32::MIN, ..options(&source, 3_000_000)? };
        let pull = output.download_resumable("already-there", source, content, &mut buffers, transfer, IncompleteOutput::Delete, |_| Control::Continue);
        let server = async {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(requested(&mut stream, &blocks).await?, content.query);
            assert_eq!(requested(&mut stream, &blocks).await?, first);
            assert!(request(&mut stream).await?.is_none());
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (result, served) = timeout(Duration::from_secs(4), async { tokio::join!(pull, server) }).await?;
        served?;
        assert!(result.is_err());
        assert_eq!(fs::read(unrelated)?, b"unrelated file");
        Ok(())
    })
}
async fn serve(
    listener: UnixListener,
    blocks: Blocks,
    count: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut served = 0;
    let mut connections = 0;
    while served < count {
        let (mut stream, _) = listener.accept().await?;
        connections += 1;
        let mut previous: Option<Vec<u8>> = None;
        while let Some(bytes) = request(&mut stream).await? {
            let Request::Search(search) = Request::decode(&bytes)? else {
                return Err("unexpected request".into());
            };
            let (kind, block) = blocks.get(&search.query).ok_or("missing test query")?;
            assert_eq!(*kind, search.block_type);
            assert_eq!(search.options, 1);
            assert_eq!(search.anonymity, 0);
            if let Some(bytes) = &previous {
                stream.write_all(bytes).await?;
            }
            let bytes = reply(*kind, block)?;
            stream.write_all(&bytes).await?;
            previous = Some(bytes);
            served += 1;
            if served == count {
                let mut one = [0];
                assert_eq!(stream.read(&mut one).await?, 0);
                break;
            }
        }
    }
    Ok(connections)
}

#[test]
fn sibling_requests_overlap_and_reverse_replies_keep_authenticated_file_order() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temp::new()?;
            let socket = temp.0.join("fs.sock");
            let listener = UnixListener::bind(&socket)?;
            let mut data = vec![3; 3 * BLOCK_BYTES + 17];
            data[BLOCK_BYTES..2 * BLOCK_BYTES].fill(9);
            data[3 * BLOCK_BYTES..].fill(12);
            let (content, blocks) = tree(&data)?;
            let server = async {
                let (mut stream, _) = listener.accept().await?;
                let frame = request(&mut stream).await?.ok_or("missing root lookup")?;
                assert!(matches!(Request::decode(&frame)?, Request::Search(search)
                    if search.query == content.query && search.block_type == BlockType::IBLOCK));
                let (kind, root) = blocks.get(&content.query).ok_or("missing test root")?;
                stream.write_all(&reply(*kind, root)?).await?;
                let mut queries = Vec::new();
                // All three distinct siblings must be sent before any is answered.
                for _ in 0..3 {
                    let frame = request(&mut stream)
                        .await?
                        .ok_or("missing sibling lookup")?;
                    let Request::Search(search) = Request::decode(&frame)? else {
                        return Err("wrong sibling request".into());
                    };
                    assert_eq!(search.block_type, BlockType::DBLOCK);
                    assert!(!queries.contains(&search.query));
                    queries.push(search.query);
                }
                for query in queries.into_iter().rev() {
                    let (kind, block) = blocks.get(&query).ok_or("missing sibling block")?;
                    stream.write_all(&reply(*kind, block)?).await?;
                }
                assert!(request(&mut stream).await?.is_none());
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let source = EndpointSource::unix(socket);
            let policy = DownloadOptions {
                request_parallelism: std::num::NonZeroU32::new(4)
                    .ok_or(gnunet_types::Error::Malformed)?,
                queries_per_connection: 8,
                ..options(&source, 5_000_000)?
            };
            let mut output = Vec::new();
            let mut buffers = Buffers::new();
            let transfer = buffers.download(source, content, &mut output, None, policy, |_| {
                Control::Continue
            });
            let (result, server) = timeout(Duration::from_secs(3), async {
                tokio::join!(transfer, server)
            })
            .await?;
            let result = result?;
            server?;
            assert_eq!(result.progress.blocks, 5);
            assert_eq!(output, data);
            Ok(())
        })
}

#[test]
fn authenticated_multiblock_and_empty_download_reuses_bounded_mq_and_verified_cache() -> TestResult
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for data in [vec![43; 3 * BLOCK_BYTES + 19], Vec::new()] {
                let temp = Temp::new()?;
                let (content, blocks) = tree(&data)?;
                let network_count = blocks.len();
                let layout = gnunet_fs::content::Layout::new(content.size);
                let mut count = 0;
                for level in 0..layout.levels() {
                    count += layout.node_count(level)? as usize;
                }
                let socket = temp.0.join("fs.sock");
                let listener = UnixListener::bind(&socket)?;
                let server = tokio::spawn(serve(listener, blocks, network_count));
                let source = EndpointSource::unix(socket);
                let policy = options(&source, 5_000_000)?;
                let mut cache = Repository::open(temp.0.join("cache"))?;
                let mut output = Vec::new();
                let mut buffers = Buffers::new();
                let completed = timeout(
                    Duration::from_secs(3),
                    buffers.download(
                        source,
                        content,
                        &mut output,
                        Some(&mut cache),
                        policy,
                        |_| Control::Continue,
                    ),
                )
                .await??;
                assert_eq!(completed.verified.content(), content);
                assert_eq!(output, data);
                assert_eq!(completed.progress.blocks, count as u64);
                let connections = timeout(Duration::from_secs(2), server)
                    .await??
                    .map_err(|e| io::Error::other(e.to_string()))?;
                assert_eq!(connections, network_count.div_ceil(2));
                let source = EndpointSource::unix(temp.0.join("does-not-exist.sock"));
                let policy = options(&source, 5_000_000)?;
                let mut cached = Vec::new();
                let result = buffers
                    .download(
                        source,
                        content,
                        &mut cached,
                        Some(&mut cache),
                        policy,
                        |_| Control::Continue,
                    )
                    .await?;
                assert_eq!(result.verified.content(), content);
                assert_eq!(cached, data);
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}

#[test]
fn matching_ciphertext_query_with_wrong_plaintext_key_never_writes_or_completes() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temp::new()?;
            let (mut content, blocks) = tree(b"root-bound plaintext")?;
            content.key[0] ^= 1;
            let socket = temp.0.join("fs.sock");
            let listener = UnixListener::bind(&socket)?;
            let server = tokio::spawn(serve(listener, blocks, 1));
            let source = EndpointSource::unix(socket);
            let policy = options(&source, 5_000_000)?;
            let mut output = Vec::new();
            let result = Buffers::new()
                .download(source, content, &mut output, None, policy, |_| {
                    Control::Continue
                })
                .await;
            assert!(matches!(
                result,
                Err(Error::Protocol(gnunet_types::Error::Authentication))
            ));
            assert!(output.is_empty());
            server.await?.map_err(|e| io::Error::other(e.to_string()))?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}

#[test]
fn original_deadline_also_bounds_a_partially_written_plaintext_output() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temp::new()?;
            let (content, blocks) = tree(&[61; 4096])?;
            let socket = temp.0.join("fs.sock");
            let listener = UnixListener::bind(&socket)?;
            let server = tokio::spawn(serve(listener, blocks, 1));
            let source = EndpointSource::unix(socket);
            let policy = options(&source, 100_000)?;
            let (mut output, mut receiver) = tokio::io::duplex(1);
            let result = timeout(
                Duration::from_secs(2),
                Buffers::new().download(source, content, &mut output, None, policy, |_| {
                    Control::Continue
                }),
            )
            .await?;
            assert!(matches!(result, Err(Error::Deadline { .. })));
            let mut one = [0];
            receiver.read_exact(&mut one).await?;
            assert_eq!(one, [61]);
            server.await?.map_err(|e| io::Error::other(e.to_string()))?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}
