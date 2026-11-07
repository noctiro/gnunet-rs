//! One actual private Unix FS CLIENT flow across a cache miss and task restart.
//! The peer serves real encoder outputs; it is a bounded protocol fixture, not
//! a production FS daemon, original-C or P2P interoperability observation.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The finite native flow asserts actual requests, authenticated bytes and original MQ retirement"
)]
use gnunet_crypto::EddsaPrivateKey;
use gnunet_fs::{
    Content, Location, Uri,
    content::{BLOCK_BYTES, BlockKey, EncodedNode, Layout, NodeRef},
};
use gnunet_fs_host::{
    BlockSink, BlockSource, Buffers, Control, Insert, Limits, OutputDir, Repository,
    durable::{Disposition, FileOptions, Phase, RootMode, Task, TaskControl, store},
    ipc::EndpointSource,
    network::{DownloadOptions, range::Destination},
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response, SEARCH_LOOPBACK_ONLY};
use std::{
    collections::HashMap,
    fs, io,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ANONYMITY: u32 = 7;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-file-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
type Blocks = HashMap<[u8; 64], (BlockType, Vec<u8>)>;
#[derive(Default)]
struct Encoded {
    blocks: Blocks,
    leaves: HashMap<u64, BlockKey>,
}
impl BlockSink for Encoded {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> gnunet_fs_host::Result<Insert> {
        let kind = if encoded.node().level() == 0 {
            BlockType::DBLOCK
        } else {
            BlockType::IBLOCK
        };
        let key = encoded.block().key();
        if encoded.node().level() == 0 {
            self.leaves.insert(encoded.node().ordinal(), key);
        }
        if let Some((previous_kind, previous)) = self.blocks.get(&key.query) {
            if *previous_kind != kind || previous.as_slice() != encoded.block().bytes() {
                return Err(gnunet_fs_host::Error::Corrupt);
            }
            return Ok(Insert::Existing);
        }
        self.blocks
            .insert(key.query, (kind, encoded.block().bytes().to_vec()));
        Ok(Insert::Created)
    }
}
fn content(bytes: &[u8]) -> TestResult<(Content, Encoded)> {
    let mut encoded = Encoded::default();
    let done = Buffers::new().publish(
        &mut io::Cursor::new(bytes),
        bytes.len() as u64,
        &mut encoded,
        Limits::default(),
        |_| Control::Continue,
    )?;
    Ok((done.content, encoded))
}
fn until(source: &EndpointSource) -> TestResult<AbsoluteTime> {
    let micros = source
        .clock()
        .sample()?
        .now
        .as_micros()
        .checked_add(4_000_000)
        .ok_or("fixture deadline overflow")?;
    Ok(AbsoluteTime::from_micros(micros))
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=4096).contains(&length) {
        return Err(io::Error::other("invalid bounded FS fixture request"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn serve(
    listener: &UnixListener,
    blocks: &Blocks,
    expected: &[[u8; 64]],
    placement: [u8; 32],
) -> TestResult<Vec<[u8; 64]>> {
    let (mut stream, _) = listener.accept().await?;
    let mut observed = Vec::new();
    for expected in expected {
        let bytes = frame(&mut stream).await?;
        let Request::Search(search) = Request::decode(&bytes)? else {
            return Err("file task issued a non-search request".into());
        };
        assert_eq!(&search.query, expected);
        assert_eq!(search.anonymity, ANONYMITY);
        assert_eq!(search.options, SEARCH_LOOPBACK_ONLY);
        assert_eq!(search.target, placement);
        assert!(search.seen.is_empty());
        let (kind, block) = blocks
            .get(expected)
            .ok_or("requested block was not encoded")?;
        assert_eq!(search.block_type, *kind);
        let reply = Response::Put(ClientPut {
            block_type: *kind,
            expiration: AbsoluteTime::from_micros(1),
            last_transmission: AbsoluteTime::from_micros(0),
            num_transmissions: 0,
            respect_offered: 0,
            block,
        });
        let mut response = vec![0; reply.encoded_len()?];
        reply.encode(&mut response)?;
        stream.write_all(&response).await?;
        observed.push(search.query);
    }
    // The same original MQ must close, rather than transmit a new query after
    // pause or completion. This is an actual native EOF, not a readiness flag.
    let mut extra = [0; 1];
    assert_eq!(stream.read(&mut extra).await?, 0);
    Ok(observed)
}
fn joined<T, U>(work: TestResult<T>, peer: TestResult<U>) -> TestResult<(T, U)> {
    match (work, peer) {
        (Ok(work), Ok(peer)) => Ok((work, peer)),
        (Err(work), Err(peer)) => {
            Err(format!("original file task: {work}; independent Unix peer: {peer}").into())
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[test]
fn cache_miss_loc_range_pauses_original_mq_then_reopened_task_fetches_only_missing_leaf()
-> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            timeout(Duration::from_secs(12), async {
                let temporary = Temporary::new()?;
                let plain: Vec<u8> = (0..2 * BLOCK_BYTES + 19)
                    .map(|index| (index % 251) as u8)
                    .collect();
                let (content, encoded) = content(&plain)?;
                let first_leaf = *encoded.leaves.get(&0).ok_or("first encoder leaf missing")?;
                let second_leaf = *encoded
                    .leaves
                    .get(&1)
                    .ok_or("second encoder leaf missing")?;
                let selection = BLOCK_BYTES as u64 - 5..BLOCK_BYTES as u64 + 11;
                let signer = EddsaPrivateKey::from_seed([41; 32]);
                let location = Location::sign(
                    content,
                    &signer,
                    AbsoluteTime::from_micros(5_000_000_000_000_000),
                )?;
                let placement = *location.peer().as_bytes();
                let mut parent = OutputDir::open(&temporary.0)?;
                let task_path = temporary.0.join("task");
                let cache_path = temporary.0.join("cache");
                let socket_path = temporary.0.join("fs.sock");
                let listener = UnixListener::bind(&socket_path)?;
                let policy = DownloadOptions {
                    anonymity: ANONYMITY,
                    local_only: true,
                    queries_per_connection: 8,
                    io_slice_bytes: 37,
                    ..DownloadOptions::new(AbsoluteTime::from_micros(0))
                };
                let mut task = Task::create_file(
                    &task_path,
                    &mut parent,
                    "selected",
                    Uri::Location(location),
                    FileOptions {
                        download: policy,
                        selection: Some(selection.clone()),
                    },
                    store::Limits::default(),
                )?;
                let mut cache = Repository::open(&cache_path)?;
                let mut scratch = vec![0; BLOCK_BYTES + 16];
                assert!(
                    matches!(cache.read_block(NodeRef::root(content), &mut scratch),
                Err(gnunet_fs_host::Error::Io(error)) if error.kind()==io::ErrorKind::NotFound)
                );
                let source = EndpointSource::unix(socket_path.clone());
                let deadline = until(&source)?;
                let mut buffers = Buffers::new();
                let prefix = [content.query, first_leaf.query];
                let peer = serve(&listener, &encoded.blocks, &prefix, placement);
                let work = async {
                    let done = task
                        .run(source, &mut buffers, &mut cache, deadline, |progress| {
                            if progress
                                .file
                                .is_some_and(|file| file.authenticated.blocks >= 2)
                            {
                                TaskControl::Pause
                            } else {
                                TaskControl::Continue
                            }
                        })
                        .await?;
                    assert_eq!(done.disposition, Disposition::Paused);
                    assert_eq!(task.status()?.phase, Phase::Paused);
                    let progress = done.progress.file.ok_or("paused file progress missing")?;
                    assert_eq!(progress.authenticated.blocks, 2);
                    assert_eq!(progress.authenticated.plaintext_bytes, 5);
                    assert_eq!(
                        (
                            done.progress.cleanup_pending,
                            done.progress.uncertain_commits
                        ),
                        (0, 0)
                    );
                    assert!(!temporary.0.join("selected").exists());
                    Ok(())
                };
                let (work, peer) = tokio::join!(work, peer);
                let (_, observed) = joined(work, peer)?;
                assert_eq!(observed.as_slice(), &prefix);
                let layout = Layout::new(content.size);
                let first = NodeRef::new(layout.leaf(0)?, first_leaf);
                let second = NodeRef::new(layout.leaf(1)?, second_leaf);
                assert!(
                    cache
                        .read_block(NodeRef::root(content), &mut scratch)
                        .is_ok()
                );
                assert!(cache.read_block(first, &mut scratch).is_ok());
                assert!(matches!(cache.read_block(second,&mut scratch),
                Err(gnunet_fs_host::Error::Io(error)) if error.kind()==io::ErrorKind::NotFound));
                drop(task);
                drop(cache);
                let mut task = Task::open(&task_path, store::Limits::default())?;
                assert_eq!(
                    task.manifest()?.mode,
                    RootMode::File {
                        selection: selection.clone()
                    }
                );
                assert_eq!(task.manifest()?.options.transfer.target, placement);
                task.attach(&mut parent)?;
                let mut cache = Repository::open(&cache_path)?;
                let source = EndpointSource::unix(socket_path);
                let deadline = until(&source)?;
                let missing = [second_leaf.query];
                let peer = serve(&listener, &encoded.blocks, &missing, placement);
                let work = async {
                    let done = task
                        .run(source, &mut buffers, &mut cache, deadline, |_| {
                            TaskControl::Continue
                        })
                        .await?;
                    assert_eq!(done.disposition, Disposition::Complete);
                    assert_eq!(task.status()?.phase, Phase::Complete);
                    let read = done.file.ok_or("completed selected receipt missing")?;
                    assert_eq!(read.selection, selection);
                    assert_eq!(read.destination, Destination::SinkCompleted);
                    assert_eq!(read.authenticated.blocks, 3);
                    assert_eq!(read.delivered_bytes, 16);
                    assert!(done.walk.is_none());
                    assert_eq!(
                        (
                            done.progress.cleanup_pending,
                            done.progress.uncertain_commits
                        ),
                        (0, 0)
                    );
                    let actual = fs::read(temporary.0.join("selected"))?;
                    assert_eq!(actual.len() as u64, content.size);
                    assert_eq!(
                        &actual[selection.start as usize..selection.end as usize],
                        &plain[selection.start as usize..selection.end as usize]
                    );
                    assert_eq!(actual[0], 0);
                    assert!(!cache.cleanup_pending());
                    Ok(())
                };
                let (work, peer) = tokio::join!(work, peer);
                let (_, observed) = joined(work, peer)?;
                assert_eq!(observed.as_slice(), &missing);
                Ok::<_, Box<dyn std::error::Error>>(())
            })
            .await
        })??;
    Ok(())
}
