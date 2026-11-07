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
        Ok(Insert::Created)
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
