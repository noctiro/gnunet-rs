//! Focused recursive extraction over actual encrypted repository blocks.
//! No FS fixture or service is running; a missing endpoint detects cache/inline misses.
#![cfg(all(unix, feature = "service"))]
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
    BlockSink, Buffers, Control, Insert, Limits, OutputDir, Repository,
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
        Ok(Insert::Created)
    }
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
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".gnunet-fs-output-")
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
