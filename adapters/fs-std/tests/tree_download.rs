//! Focused recursive extraction over actual encrypted repository blocks.
//! No FS fixture or service is running; a missing endpoint detects cache/inline misses.
#![cfg(all(any(unix, windows), feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible extraction tests assert real authenticated output and parent completion boundaries"
)]
use gnunet_fs::{
    Content,
    content::EncodedNode,
    directory as dir,
    metadata::{self as md, Compression, Format, Item},
};
use gnunet_fs_codec::Compressor;
use gnunet_fs_host::{
    BlockSink, Buffers, Control, Insert, Limits, OWNER_MARKER_NAME, OutputDir, Repository,
    ipc::EndpointSource,
    network::{DownloadOptions, tree_download::TreeDownloadOptions},
};
use gnunet_types::AbsoluteTime;
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::time::timeout;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-tree-download-{}-{}",
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
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn options(source: &EndpointSource) -> Result<TreeDownloadOptions, gnunet_types::Error> {
    Ok(TreeDownloadOptions::new(DownloadOptions {
        anonymity: 0,
        local_only: true,
        ..DownloadOptions::new(AbsoluteTime::from_micros(
            source.clock().sample()?.now.as_micros() + 2_000_000,
        ))
    }))
}
fn metadata(items: &[Item<'_>]) -> TestResult<Vec<u8>> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 32 * 1024];
    let mut coded = vec![0; 32 * 1024];
    let plan = md::plan(
        items,
        &mut order,
        &mut plain,
        &mut coded,
        &mut Compressor::new(),
        md::Limits::default(),
        md::Options {
            compression: Compression::Never,
            ..md::Options::default()
        },
    )?;
    let mut bytes = vec![0; plan.report().wire_bytes];
    plan.write(&mut bytes)?;
    Ok(bytes)
}
fn entry_metadata(name: &[u8], directory: bool, hint: Option<&[u8]>) -> TestResult<Vec<u8>> {
    let mut items = vec![Item {
        kind: 180,
        format: Format::CString,
        data: name,
        plugin: Some(b"tree-download-test\0"),
        mime: Some(b"text/plain\0"),
    }];
    if directory {
        items.push(dir::MIME_ITEM);
    }
    if let Some(data) = hint {
        items.push(Item {
            kind: 174,
            format: Format::Binary,
            data,
            plugin: None,
            mime: None,
        });
    }
    metadata(&items)
}
fn directory_bytes(entries: &[(Content, Vec<u8>)]) -> TestResult<Vec<u8>> {
    let root_bytes = metadata(&[dir::MIME_ITEM])?;
    let root = dir::PreparedMetadata::validate(
        &root_bytes,
        &mut [],
        &mut md::NoCodec,
        md::Limits::default(),
    )?;
    let mut arenas: Vec<_> = entries
        .iter()
        .map(|(_, bytes)| vec![0; bytes.len() + 512])
        .collect();
    let mut records = Vec::new();
    for ((content, bytes), arena) in entries.iter().zip(arenas.iter_mut()) {
        let metadata = dir::PreparedMetadata::validate(
            bytes,
            &mut [],
            &mut md::NoCodec,
            md::Limits::default(),
        )?;
        records.push(dir::PreparedEntry::prepare(content.uri(), metadata, arena)?);
    }
    let mut placements = vec![dir::Placement::default(); records.len()];
    let plan = dir::plan(
        root,
        &records,
        &mut placements,
        dir::BuildOptions::default(),
    )?;
    let mut bytes = vec![0; usize::try_from(plan.report().wire_bytes)?];
    plan.write(&mut bytes)?;
    Ok(bytes)
}
fn publish(buffers: &mut Buffers, bytes: &[u8], sink: &mut impl BlockSink) -> TestResult<Content> {
    Ok(buffers
        .publish(
            &mut io::Cursor::new(bytes),
            bytes.len() as u64,
            sink,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content)
}
struct Discard;
impl BlockSink for Discard {
    fn insert_block(&mut self, _node: EncodedNode<'_>) -> gnunet_fs_host::Result<Insert> {
        Ok(Insert::Created(gnunet_fs_host::Retention::Volatile))
    }
}

#[cfg(unix)]
#[test]
fn recursive_files_overlap_without_occupying_other_admitted_destinations() -> TestResult {
    use gnunet_fs::content::BLOCK_BYTES;
    use gnunet_fs_host::BlockSource;
    use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
    use std::num::NonZeroU32;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };

    async fn query(stream: &mut UnixStream) -> TestResult<[u8; 64]> {
        let size = stream.read_u16().await?;
        let mut frame = vec![0; usize::from(size)];
        frame
            .get_mut(..2)
            .ok_or("short search frame")?
            .copy_from_slice(&size.to_be_bytes());
        stream.read_exact(&mut frame[2..]).await?;
        let Request::Search(search) = Request::decode(&frame)? else {
            return Err("expected a file block lookup".into());
        };
        assert_eq!(search.block_type, BlockType::DBLOCK);
        Ok(search.query)
    }

    async fn send(stream: &mut UnixStream, content: Content, cache: &mut Repository) -> TestResult {
        let mut block = vec![0; BLOCK_BYTES + gnunet_fs::content::TAG_BYTES];
        let size = cache.read_block(gnunet_fs::content::NodeRef::root(content), &mut block)?;
        let response = Response::Put(ClientPut {
            block_type: BlockType::DBLOCK,
            expiration: AbsoluteTime::from_micros(1),
            last_transmission: AbsoluteTime::from_micros(0),
            num_transmissions: 0,
            respect_offered: 0,
            block: &block[..size],
        });
        let mut frame = vec![0; response.encoded_len()?];
        response.encode(&mut frame)?;
        stream.write_all(&frame).await?;
        Ok(())
    }

    let temporary = Temporary::new()?;
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let first = publish(&mut buffers, b"first", &mut cache)?;
    let second = publish(&mut buffers, b"second", &mut cache)?;
    let third = publish(&mut buffers, b"third", &mut cache)?;
    let reserved = format!("0{:07}", std::process::id() % 10_000_000);
    let record_name = format!("{reserved}\0");
    let a = directory_bytes(&[
        (first, entry_metadata(b"first.bin\0", false, None)?),
        (second, entry_metadata(record_name.as_bytes(), false, None)?),
    ])?;
    let b = directory_bytes(&[(third, entry_metadata(b"third.bin\0", false, None)?)])?;
    let left = publish(&mut buffers, &a, &mut cache)?;
    let right = publish(&mut buffers, &b, &mut cache)?;
    let root = directory_bytes(&[
        (left, entry_metadata(b"a/\0", true, None)?),
        (right, entry_metadata(b"b/\0", true, None)?),
    ])?;
    let root = publish(&mut buffers, &root, &mut cache)?;
    assert!(
        [root, left, right]
            .into_iter()
            .all(|content| content.size < BLOCK_BYTES as u64)
    );
    let mut output = OutputDir::open(&temporary.0)?;
    let tree = temporary.0.join("tree");
    runtime()?.block_on(async {
        let socket = temporary.0.join("fs.sock");
        let listener = UnixListener::bind(&socket)?;
        let source = EndpointSource::unix(socket.clone());
        let mut policy = options(&source)?;
        policy.file_parallelism = NonZeroU32::MIN.saturating_add(2);
        policy.transfer.request_parallelism = policy.file_parallelism;
        let server = async {
            let (mut directory, _) = listener.accept().await?;
            assert_eq!(query(&mut directory).await?, root.query);
            send(&mut directory, root, &mut cache).await?;
            let mut directories = vec![left, right];
            while !directories.is_empty() {
                let (mut stream, _) = listener.accept().await?;
                let received = query(&mut stream).await?;
                let index = directories
                    .iter()
                    .position(|entry| entry.query == received)
                    .ok_or("expected another directory before files")?;
                send(&mut stream, directories.swap_remove(index), &mut cache).await?;
            }
            let mut files = vec![first, second, third];
            let mut ready = Vec::new();
            while !files.is_empty() {
                let (mut stream, _) = listener.accept().await?;
                let received = query(&mut stream).await?;
                let index = files
                    .iter()
                    .position(|entry| entry.query == received)
                    .ok_or("expected a distinct verified file")?;
                ready.push((stream, files.swap_remove(index)));
            }
            assert_eq!(fs::read_dir(tree.join("a"))?.count(), 0);
            assert_eq!(fs::read_dir(tree.join("b"))?.count(), 0);
            for (mut stream, content) in ready.into_iter().rev() {
                send(&mut stream, content, &mut cache).await?;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let work = output.download_tree("tree", source, root, &mut buffers, None, policy, |_| {
            Control::Continue
        });
        let (finished, served) =
            timeout(Duration::from_secs(3), async { tokio::join!(work, server) }).await?;
        served?;
        let finished = finished?;
        assert_eq!(finished.progress.files_committed, 3);
        assert_eq!(finished.walk.done, 6);
        assert_eq!(fs::read(tree.join("a/first.bin"))?, b"first");
        assert_eq!(fs::read(tree.join("a").join(&reserved))?, b"second");
        assert_eq!(fs::read(tree.join("b/third.bin"))?, b"third");
        assert_eq!(fs::read_dir(tree.join("a"))?.count(), 2);
        assert_eq!(fs::read_dir(tree.join("b"))?.count(), 1);
        assert!(
            !fs::read_dir(&temporary.0)?
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".gnunet-fs-"))
        );
        // Reopen the tree, authenticate the directories again and reuse completed files.
        let source = EndpointSource::unix(socket);
        let mut resume = options(&source)?;
        resume.file_parallelism = policy.file_parallelism;
        let server = async {
            let mut directories = vec![root, left, right];
            while !directories.is_empty() {
                let (mut stream, _) = listener.accept().await?;
                let received = query(&mut stream).await?;
                let index = directories
                    .iter()
                    .position(|entry| entry.query == received)
                    .ok_or("completed file was requested again")?;
                send(&mut stream, directories.swap_remove(index), &mut cache).await?;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let work = output.download_tree_resumable(
            "tree",
            source,
            root,
            &mut buffers,
            resume,
            gnunet_fs_host::IncompleteOutput::Keep,
            |_| Control::Continue,
        );
        let (resumed, served) =
            timeout(Duration::from_secs(3), async { tokio::join!(work, server) }).await?;
        served?;
        let resumed = resumed?;
        assert_eq!(resumed.walk.done, 6);
        assert_eq!(resumed.progress.files_committed, 3);
        assert_eq!(resumed.progress.directories_created, 0);
        Ok(())
    })
}

#[test]
fn cached_multi_path_content_and_official_directory_names_accept_verified_inline_and_fallback()
-> TestResult {
    let temporary = Temporary::new()?;
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let shared_bytes = b"shared";
    let shared = publish(&mut buffers, shared_bytes, &mut cache)?;
    let inline_bytes = b"authenticated inline content absent from repository";
    let inline = publish(&mut buffers, inline_bytes, &mut Discard)?;
    let nested_bytes = directory_bytes(&[
        (shared, entry_metadata(b"first.bin\0", false, None)?),
        (shared, entry_metadata(b"second.bin\0", false, None)?),
    ])?;
    let nested = publish(&mut buffers, &nested_bytes, &mut cache)?;
    let empty_bytes = directory_bytes(&[])?;
    let empty = publish(&mut buffers, &empty_bytes, &mut cache)?;
    let root_bytes = directory_bytes(&[
        (nested, entry_metadata(b"nested/\0", true, None)?),
        (empty, entry_metadata(b"empty/\0", true, None)?),
        // Same length as the true file: hash authentication must reject this hint.
        (
            shared,
            entry_metadata(b"fallback.bin\0", false, Some(b"broken"))?,
        ),
        (
            inline,
            entry_metadata(b"inline.bin\0", false, Some(inline_bytes))?,
        ),
    ])?;
    let root = publish(&mut buffers, &root_bytes, &mut cache)?;
    let mut output = OutputDir::open(&temporary.0)?;
    runtime()?.block_on(async {
        let source = EndpointSource::unix(temporary.0.join("no-fs-service.sock"));
        let policy = options(&source)?;
        let done = timeout(
            Duration::from_secs(3),
            output.download_tree(
                "tree",
                source,
                root,
                &mut buffers,
                Some(&mut cache),
                policy,
                |_| Control::Continue,
            ),
        )
        .await??;
        assert!(done.progress.root_created);
        assert_eq!(done.progress.directories_created, 3);
        assert_eq!(done.progress.directories_verified, 3);
        assert_eq!(done.progress.files_committed, 4);
        assert_eq!(
            done.progress.file_bytes,
            (shared_bytes.len() * 3 + inline_bytes.len()) as u128
        );
        assert_eq!(done.walk.tasks, 7);
        assert_eq!(done.walk.done, 7);
        assert_eq!(done.walk.shared, 0); // Distinct names each have a committed file.
        let tree = temporary.0.join("tree");
        for name in ["nested/first.bin", "nested/second.bin", "fallback.bin"] {
            assert_eq!(fs::read(tree.join(name))?, shared_bytes);
        }
        assert_eq!(fs::read(tree.join("inline.bin"))?, inline_bytes);
        assert!(tree.join("empty").is_dir());
        assert_eq!(fs::read_dir(tree.join("empty"))?.count(), 0);
        assert_eq!(fs::read_dir(tree.join("nested"))?.count(), 2);
        assert_eq!(fs::read_dir(&tree)?.count(), 4);

        // A full optional-hint budget must leave the same tree retrievable.
        assert_eq!(publish(&mut buffers, inline_bytes, &mut cache)?, inline);
        let source = EndpointSource::unix(temporary.0.join("no-fs-service.sock"));
        let mut policy = options(&source)?;
        policy.max_total_inline_bytes = 0;
        let cached = timeout(
            Duration::from_secs(3),
            output.download_tree(
                "cache-only-tree",
                source,
                root,
                &mut buffers,
                Some(&mut cache),
                policy,
                |_| Control::Continue,
            ),
        )
        .await??;
        assert_eq!(cached.progress.files_committed, 4);
        assert_eq!(
            fs::read(temporary.0.join("cache-only-tree/inline.bin"))?,
            inline_bytes
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn authenticated_directory_with_invalid_late_record_never_publishes_queued_child_files()
-> TestResult {
    let temporary = Temporary::new()?;
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let child = publish(&mut buffers, b"must remain only in the cache", &mut cache)?;
    let mut malformed =
        directory_bytes(&[(child, entry_metadata(b"not-published.bin\0", false, None)?)])?;
    malformed.extend_from_slice(b"not-a-terminated-entry-uri");
    // Authentication of the complete CHK succeeds; strict directory syntax fails
    // only after delivering the valid, authenticated first membership record.
    let malformed = publish(&mut buffers, &malformed, &mut cache)?;
    let root_bytes = directory_bytes(&[(malformed, entry_metadata(b"bad/\0", true, None)?)])?;
    let root = publish(&mut buffers, &root_bytes, &mut cache)?;
    let mut output = OutputDir::open(&temporary.0)?;
    runtime()?.block_on(async {
        let source = EndpointSource::unix(temporary.0.join("no-fs-service.sock"));
        let policy = options(&source)?;
        let failed = timeout(
            Duration::from_secs(3),
            output.download_tree(
                "tree",
                source,
                root,
                &mut buffers,
                Some(&mut cache),
                policy,
                |_| Control::Continue,
            ),
        )
        .await?
        .err()
        .ok_or("invalid directory syntax was accepted")?;
        assert_eq!(failed.path, Path::new("tree/bad"));
        assert!(failed.progress.root_created);
        assert_eq!(failed.progress.directories_created, 2);
        assert_eq!(failed.progress.directories_verified, 1);
        assert_eq!(failed.progress.files_committed, 0);
        assert_eq!(failed.progress.file_bytes, 0);
        let walk = failed.walk.ok_or("original walk history was discarded")?;
        assert_eq!(walk.tasks, 3);
        assert_eq!(walk.done, 1);
        assert!(failed.namespace_cleanup.is_none());
        assert!(failed.interruption.is_none());
        let bad = temporary.0.join("tree/bad");
        assert!(bad.is_dir()); // Authenticated parent name; not a verified child directory.
        assert_eq!(fs::read_dir(&bad)?.count(), 0);
        assert!(!bad.join("not-published.bin").exists());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn cancellation_preserves_independent_temporary_cleanup_failure() -> TestResult {
    let temporary = Temporary::new()?;
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let plaintext = b"inline cancellation with independent original temporary cleanup";
    let child = publish(&mut buffers, plaintext, &mut Discard)?;
    let root_bytes = directory_bytes(&[(
        child,
        entry_metadata(b"file.bin\0", false, Some(plaintext))?,
    )])?;
    let root = publish(&mut buffers, &root_bytes, &mut cache)?;
    let mut output = OutputDir::open(&temporary.0)?;
    let tree = temporary.0.join("tree");
    runtime()?.block_on(async {
        let source = EndpointSource::unix(temporary.0.join("no-fs-service.sock"));
        let policy = options(&source)?;
        let mut foreign_path = None;
        let mut fixture_error = None;
        let failed = timeout(
            Duration::from_secs(3),
            output.download_tree(
                "tree",
                source,
                root,
                &mut buffers,
                Some(&mut cache),
                policy,
                |_| {
                    if foreign_path.is_none()
                        && let Ok(entries) = fs::read_dir(&tree)
                        && let Some(entry) = entries.filter_map(Result::ok).find(|entry| {
                            entry.file_name() != OWNER_MARKER_NAME
                                && entry.file_name() != "file.bin"
                                && entry.file_type().is_ok_and(|kind| kind.is_file())
                        })
                    {
                        let path = entry.path();
                        // Model an independent actor replacing an active private
                        // name. Original output cleanup must retain that actor's
                        // inode and report its own cleanup failure.
                        if let Err(error) = fs::rename(&path, tree.join("held-owned-inode")) {
                            fixture_error = Some(error);
                            return Control::Cancel;
                        }
                        if let Err(error) = fs::write(&path, b"foreign sentinel") {
                            fixture_error = Some(error);
                            return Control::Cancel;
                        }
                        foreign_path = Some(path);
                        return Control::Cancel;
                    }
                    Control::Continue
                },
            ),
        )
        .await?
        .err()
        .ok_or("fixture cancellation did not interrupt extraction")?;
        if let Some(error) = fixture_error {
            return Err(error.into());
        }
        let foreign_path =
            foreign_path.ok_or("control never observed an actual owned temporary")?;
        assert!(
            matches!(&failed.cause,
                gnunet_fs_host::Error::CleanupFailed { cause, .. }
                    if matches!(cause.as_ref(), gnunet_fs_host::Error::Cancelled)
            ),
            "tree extraction discarded the original independent cleanup failure: {}",
            failed.cause
        );
        assert!(matches!(
            &failed.interruption,
            Some(gnunet_fs_host::Error::Cancelled)
        ));
        assert_eq!(failed.progress.files_committed, 0);
        assert_eq!(failed.progress.file_bytes, 0);
        assert_eq!(failed.progress.directories_verified, 1);
        assert!(!tree.join("file.bin").exists());
        assert_eq!(fs::read(foreign_path)?, b"foreign sentinel");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[tokio::test(start_paused = true)]
async fn expired_enclosing_transfer_refuses_tree_before_creating_output() -> TestResult {
    let temporary = Temporary::new()?;
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let root = publish(&mut buffers, &directory_bytes(&[])?, &mut cache)?;
    let mut output = OutputDir::open(&temporary.0)?;
    let source = EndpointSource::unix(temporary.0.join("unused.sock"));
    let mut policy = options(&source)?;
    policy.transfer.native_deadline = Some(tokio::time::Instant::now());
    let error = output
        .download_tree(
            "expired",
            source,
            root,
            &mut buffers,
            Some(&mut cache),
            policy,
            |_| Control::Continue,
        )
        .await
        .err()
        .ok_or("expired outer transfer was admitted")?;
    assert!(matches!(
        error.cause,
        gnunet_fs_host::Error::Transfer(ref error)
            if matches!(error.as_ref(), gnunet_fs_host::network::Error::Deadline { .. })
    ));
    assert!(!error.progress.root_created);
    assert!(error.walk.is_none());
    assert!(!temporary.0.join("expired").exists());
    Ok(())
}
