//! Durable extraction uses actual encrypted blocks, anchored output and real replay.
//! A missing native endpoint makes unintended cache misses fail the operation.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible functional cases assert original durable state and authenticated physical output"
)]
use gnunet_fs::{
    Content, directory as dir,
    metadata::{self as md, Compression, Format, Item},
};
use gnunet_fs_codec::Compressor;
use gnunet_fs_host::{
    Buffers, Control, Limits, OWNER_MARKER_NAME, OutputDir, Repository,
    durable::{Cause, Disposition, FileOptions, Phase, RootMode, Task, TaskControl, store},
    ipc::EndpointSource,
    network::{DownloadOptions, tree_download::TreeDownloadOptions},
};
use gnunet_types::AbsoluteTime;
use std::{
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
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
            "gnunet-fs-durable-task-{}-{}",
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
fn deadline(source: &EndpointSource) -> Result<AbsoluteTime, gnunet_types::Error> {
    Ok(AbsoluteTime::from_micros(
        source.clock().sample()?.now.as_micros() + 5_000_000,
    ))
}
fn policy() -> TreeDownloadOptions {
    let mut options = TreeDownloadOptions::new(DownloadOptions {
        anonymity: 0,
        local_only: true,
        ..DownloadOptions::new(AbsoluteTime::from_micros(0))
    });
    options.max_entries = 16;
    options.max_path_bytes = 4096;
    options.max_namespace_bytes = 1024;
    options
}
fn metadata(items: &[Item<'_>]) -> TestResult<Vec<u8>> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 32768];
    let mut coded = vec![0; 32768];
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
fn entry_metadata(name: &[u8], directory: bool) -> TestResult<Vec<u8>> {
    let mut items = vec![Item {
        kind: 180,
        format: Format::CString,
        data: name,
        plugin: Some(b"durable-task-test\0"),
        mime: Some(b"text/plain\0"),
    }];
    if directory {
        items.push(dir::MIME_ITEM);
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
fn publish(buffers: &mut Buffers, bytes: &[u8], cache: &mut Repository) -> TestResult<Content> {
    Ok(buffers
        .publish(
            &mut io::Cursor::new(bytes),
            bytes.len() as u64,
            cache,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content)
}
#[test]
fn regular_file_pause_reopen_and_complete_reuses_authenticated_cache() -> TestResult {
    let temporary = Temporary::new()?;
    let bytes: Vec<u8> = (0..100_000).map(|index| (index % 251) as u8).collect();
    let mut buffers = Buffers::new();
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let content = publish(&mut buffers, &bytes, &mut cache)?;
    let mut parent = OutputDir::open(&temporary.0)?;
    let mut task = Task::create_file(
        temporary.0.join("task"),
        &mut parent,
        "file",
        gnunet_fs::Uri::Content(content),
        FileOptions::new(policy().transfer),
        store::Limits::default(),
    )?;
    runtime()?.block_on(async {
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let done = timeout(
            Duration::from_secs(3),
            task.run(source, &mut buffers, &mut cache, until, |progress| {
                if progress
                    .file
                    .is_some_and(|file| file.authenticated.blocks >= 2)
                {
                    TaskControl::Pause
                } else {
                    TaskControl::Continue
                }
            }),
        )
        .await??;
        assert_eq!(done.disposition, Disposition::Paused);
        assert!(
            done.progress
                .file
                .is_some_and(|file| file.authenticated.blocks >= 2)
        );
        assert!(!temporary.0.join("file").exists());
        assert_eq!(done.progress.cleanup_pending, 0);
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(task);
    drop(cache);
    let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
    task.attach(&mut parent)?;
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    runtime()?.block_on(async {
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let done = timeout(
            Duration::from_secs(3),
            task.run(source, &mut buffers, &mut cache, until, |_| {
                TaskControl::Continue
            }),
        )
        .await??;
        assert_eq!(done.disposition, Disposition::Complete);
        assert!(done.walk.is_none());
        let read = done.file.ok_or("file completion receipt missing")?;
        assert_eq!(read.selection, 0..content.size);
        assert_eq!(
            read.destination,
            gnunet_fs_host::network::range::Destination::SinkCompleted
        );
        assert_eq!(fs::read(temporary.0.join("file"))?, bytes);
        let identity = inode(&temporary.0.join("file"))?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let checked = task
            .run(source, &mut buffers, &mut cache, until, |_| {
                TaskControl::Continue
            })
            .await?;
        assert_eq!(checked.progress.revalidated_files, 1);
        assert_eq!(checked.progress.new_files, 0);
        assert_eq!(
            checked
                .file
                .ok_or("revalidation receipt missing")?
                .destination,
            gnunet_fs_host::network::range::Destination::ExistingFileCompared
        );
        assert_eq!(inode(&temporary.0.join("file"))?, identity);
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[test]
fn regular_file_loc_selection_reopens_without_claiming_unselected_bytes() -> TestResult {
    use std::os::unix::fs::FileExt;
    let temporary = Temporary::new()?;
    let bytes: Vec<u8> = (0..70_000).map(|index| (index % 239 + 1) as u8).collect();
    let mut buffers = Buffers::new();
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let content = publish(&mut buffers, &bytes, &mut cache)?;
    let signer = gnunet_crypto::EddsaPrivateKey::from_seed([19; 32]);
    let location = gnunet_fs::Location::sign(
        content,
        &signer,
        AbsoluteTime::from_micros(5_000_000_000_000_000),
    )?;
    let selection = 32_766..32_780;
    let mut parent = OutputDir::open(&temporary.0)?;
    let task = Task::create_file(
        temporary.0.join("task"),
        &mut parent,
        "slice",
        gnunet_fs::Uri::Location(location),
        FileOptions {
            download: policy().transfer,
            selection: Some(selection.clone()),
        },
        store::Limits::default(),
    )?;
    drop(task);
    let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
    assert_eq!(
        task.manifest()?.mode,
        RootMode::File {
            selection: selection.clone()
        }
    );
    assert_eq!(
        task.manifest()?.options.transfer.target,
        *location.peer().as_bytes()
    );
    task.attach(&mut parent)?;
    runtime()?.block_on(async {
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let done = timeout(
            Duration::from_secs(3),
            task.run(source, &mut buffers, &mut cache, until, |_| {
                TaskControl::Continue
            }),
        )
        .await??;
        assert_eq!(
            done.file.ok_or("selected receipt missing")?.selection,
            selection
        );
        assert!(done.walk.is_none());
        let sparse = fs::read(temporary.0.join("slice"))?;
        assert_eq!(sparse.len() as u64, content.size);
        assert_eq!(&sparse[32_766..32_780], &bytes[32_766..32_780]);
        assert_eq!(sparse[0], 0);
        let file = fs::OpenOptions::new()
            .write(true)
            .open(temporary.0.join("slice"))?;
        assert_eq!(file.write_at(&[99], 0)?, 1);
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let checked = task
            .run(source, &mut buffers, &mut cache, until, |_| {
                TaskControl::Continue
            })
            .await?;
        assert_eq!(
            checked
                .file
                .ok_or("selected comparison missing")?
                .destination,
            gnunet_fs_host::network::range::Destination::ExistingFileCompared
        );
        assert_eq!(file.write_at(&[0], selection.start)?, 1);
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let error = task
            .run(source, &mut buffers, &mut cache, until, |_| {
                TaskControl::Continue
            })
            .await
            .err()
            .ok_or("selected plaintext tampering was accepted")?;
        assert!(matches!(error.cause, Cause::RangeRevalidate(_)));
        assert_eq!(
            fs::read(temporary.0.join("slice"))?[selection.start as usize],
            0
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[test]
fn regular_file_cancel_settles_original_stage_without_starting_a_lookup() -> TestResult {
    let temporary = Temporary::new()?;
    let mut buffers = Buffers::new();
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let content = publish(&mut buffers, b"cancel original file", &mut cache)?;
    let mut parent = OutputDir::open(&temporary.0)?;
    let mut task = Task::create_file(
        temporary.0.join("task"),
        &mut parent,
        "cancelled",
        gnunet_fs::Uri::Content(content),
        FileOptions::new(policy().transfer),
        store::Limits::default(),
    )?;
    runtime()?.block_on(async {
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        assert_eq!(
            task.run(source, &mut buffers, &mut cache, until, |_| {
                TaskControl::Pause
            })
            .await?
            .disposition,
            Disposition::Paused
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(task);
    let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
    task.request_cancel()?;
    let done = task.settle_cancel(&mut parent, &mut buffers, &mut cache, |_| Control::Continue)?;
    assert_eq!(done.disposition, Disposition::Cancelled);
    assert_eq!(task.status()?.phase, Phase::Cancelled);
    assert_eq!(done.progress.cleanup_pending, 0);
    assert!(!temporary.0.join("cancelled").exists());
    Ok(())
}
#[test]
fn regular_file_empty_selection_differs_from_authenticated_empty_content() -> TestResult {
    for empty_content in [false, true] {
        let temporary = Temporary::new()?;
        let mut buffers = Buffers::new();
        let mut seed_cache = Repository::open(temporary.0.join("seed"))?;
        let bytes = if empty_content {
            b"".as_slice()
        } else {
            b"nonempty original".as_slice()
        };
        let content = publish(&mut buffers, bytes, &mut seed_cache)?;
        let mut cache = if empty_content {
            seed_cache
        } else {
            Repository::open(temporary.0.join("empty-cache"))?
        };
        let mut parent = OutputDir::open(&temporary.0)?;
        let mut task = Task::create_file(
            temporary.0.join("task"),
            &mut parent,
            "empty-selection",
            gnunet_fs::Uri::Content(content),
            FileOptions {
                download: policy().transfer,
                selection: Some(0..0),
            },
            store::Limits::default(),
        )?;
        runtime()?.block_on(async {
            let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
            let until = deadline(&source)?;
            let done = timeout(
                Duration::from_secs(3),
                task.run(source, &mut buffers, &mut cache, until, |_| {
                    TaskControl::Continue
                }),
            )
            .await??;
            assert_eq!(done.disposition, Disposition::Complete);
            let read = done.file.ok_or("empty selection result missing")?;
            assert_eq!(
                fs::metadata(temporary.0.join("empty-selection"))?.len(),
                content.size
            );
            if empty_content {
                assert!(matches!(
                    read.completion,
                    gnunet_fs_host::network::range::Completion::Verified(_)
                ));
                assert_eq!(read.authenticated.blocks, 1);
                assert_eq!(
                    read.destination,
                    gnunet_fs_host::network::range::Destination::SinkCompleted
                );
            } else {
                assert!(matches!(
                    read.completion,
                    gnunet_fs_host::network::range::Completion::EmptySelection
                ));
                assert_eq!(read.authenticated.blocks, 0);
                assert_eq!(
                    read.destination,
                    gnunet_fs_host::network::range::Destination::Untouched
                );
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}
fn expected() -> Vec<(PathBuf, Vec<u8>)> {
    let shared: Vec<u8> = (0..40123).map(|i| (i % 251) as u8).collect();
    vec![
        (PathBuf::from("first.bin"), shared.clone()),
        (PathBuf::from("second.bin"), shared),
        (
            PathBuf::from("nested/third.bin"),
            b"third authenticated payload".to_vec(),
        ),
    ]
}
fn seed(temporary: &Temporary) -> TestResult<Content> {
    let mut buffers = Buffers::new();
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let bytes = expected();
    let shared = publish(&mut buffers, &bytes[0].1, &mut cache)?;
    let third = publish(&mut buffers, &bytes[2].1, &mut cache)?;
    let nested_bytes = directory_bytes(&[(third, entry_metadata(b"third.bin\0", false)?)])?;
    let nested = publish(&mut buffers, &nested_bytes, &mut cache)?;
    let root_bytes = directory_bytes(&[
        (shared, entry_metadata(b"first.bin\0", false)?),
        (shared, entry_metadata(b"second.bin\0", false)?),
        (nested, entry_metadata(b"nested/\0", true)?),
    ])?;
    publish(&mut buffers, &root_bytes, &mut cache)
}
fn create(temporary: &Temporary, root: Content) -> TestResult<Task> {
    Ok(Task::create(
        temporary.0.join("task"),
        &mut OutputDir::open(&temporary.0)?,
        "tree",
        root.uri(),
        policy(),
        store::Limits::default(),
    )?)
}
fn inode(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}
fn committed(temporary: &Temporary) -> TestResult<PathBuf> {
    let paths: Vec<_> = expected()
        .into_iter()
        .filter_map(|(name, _)| {
            temporary
                .0
                .join("tree")
                .join(&name)
                .is_file()
                .then_some(name)
        })
        .collect();
    assert_eq!(paths.len(), 1);
    paths
        .into_iter()
        .next()
        .ok_or_else(|| "no committed file".into())
}
async fn pause_after_first(temporary: &Temporary, root: Content) -> TestResult<PathBuf> {
    let mut task = create(temporary, root)?;
    let mut buffers = Buffers::new();
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
    let until = deadline(&source)?;
    let paused = timeout(
        Duration::from_secs(3),
        task.run(source, &mut buffers, &mut cache, until, |p| {
            if p.new_files >= 1 {
                TaskControl::Pause
            } else {
                TaskControl::Continue
            }
        }),
    )
    .await??;
    assert_eq!(paused.disposition, Disposition::Paused);
    assert_eq!(paused.progress.new_files, 1);
    assert_eq!(paused.progress.revalidated_files, 0);
    assert_eq!(paused.progress.cleanup_pending, 0);
    assert_eq!(paused.progress.uncertain_commits, 0);
    let status = task.status()?;
    assert_eq!(status.phase, Phase::Paused);
    assert_eq!(status.known_files, 1);
    assert!(!status.active);
    assert!(!status.interrupted);
    assert!(!status.fenced);
    committed(temporary)
}

#[test]
fn reopen_paused_tree_revalidates_original_inode_then_finishes_real_walk() -> TestResult {
    let temporary = Temporary::new()?;
    let root = seed(&temporary)?;
    runtime()?.block_on(async {
        let known = pause_after_first(&temporary, root).await?;
        let known_path = temporary.0.join("tree").join(&known);
        let identity = inode(&known_path)?;
        // The original Task and Repository have both been dropped: the stable
        // physical WAL lock and on-disk cache must be reopened, not reused.
        let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
        assert_eq!(task.status()?.phase, Phase::Paused);
        assert_eq!(task.status()?.known_files, 1);
        assert_eq!(
            task.manifest()?.options.transfer.deadline,
            AbsoluteTime::from_micros(0)
        );
        task.attach(&mut OutputDir::open(&temporary.0)?)?;
        let mut cache = Repository::open(temporary.0.join("cache"))?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let done = timeout(
            Duration::from_secs(3),
            task.run(source, &mut Buffers::new(), &mut cache, until, |_| {
                TaskControl::Continue
            }),
        )
        .await??;
        assert_eq!(done.disposition, Disposition::Complete);
        assert_eq!(done.progress.historical_files, 1);
        assert_eq!(done.progress.revalidated_files, 1);
        assert_eq!(done.progress.new_files, 2);
        assert_eq!(done.progress.output.files_committed, 3);
        assert_eq!(done.progress.cleanup_pending, 0);
        assert_eq!(done.progress.uncertain_commits, 0);
        let walk = done.walk.ok_or("complete output lacks real walk summary")?;
        assert_eq!(walk.tasks, 5);
        assert_eq!(walk.done, 5);
        assert_eq!(inode(&known_path)?, identity);
        for (path, bytes) in expected() {
            assert_eq!(fs::read(temporary.0.join("tree").join(path))?, bytes);
        }
        assert_eq!(fs::read_dir(temporary.0.join("tree"))?.count(), 4);
        assert_eq!(fs::read_dir(temporary.0.join("tree/nested"))?.count(), 2);
        assert_eq!(task.status()?.phase, Phase::Complete);
        assert_eq!(task.status()?.known_files, 3);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn same_size_same_inode_changed_plaintext_refuses_resume_without_overwrite() -> TestResult {
    let temporary = Temporary::new()?;
    let root = seed(&temporary)?;
    runtime()?.block_on(async {
        let known = pause_after_first(&temporary, root).await?;
        let path = temporary.0.join("tree").join(&known);
        let identity = inode(&path)?;
        let mut changed = fs::read(&path)?;
        let first = changed.first_mut().ok_or("expected nonempty fixture")?;
        *first ^= 1;
        fs::write(&path, &changed)?;
        assert_eq!(inode(&path)?, identity);
        let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
        task.attach(&mut OutputDir::open(&temporary.0)?)?;
        let mut cache = Repository::open(temporary.0.join("cache"))?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let failed = timeout(
            Duration::from_secs(3),
            task.run(source, &mut Buffers::new(), &mut cache, until, |_| {
                TaskControl::Continue
            }),
        )
        .await?
        .err()
        .ok_or("changed plaintext was accepted")?;
        assert!(matches!(failed.cause, Cause::Revalidate(_)));
        assert_eq!(failed.path, Path::new("tree").join(&known));
        assert_eq!(failed.progress.historical_files, 1);
        assert_eq!(failed.progress.revalidated_files, 0);
        assert_eq!(failed.progress.new_files, 0);
        assert_eq!(task.status()?.known_files, 1);
        assert_eq!(task.status()?.phase, Phase::Failed);
        assert_eq!(fs::read(&path)?, changed);
        assert_eq!(inode(&path)?, identity);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn unclaimed_output_is_retained_and_replaced_root_with_copied_owner_is_refused() -> TestResult {
    let temporary = Temporary::new()?;
    let root = seed(&temporary)?;
    runtime()?.block_on(async {
        let mut task = create(&temporary, root)?;
        let mut cache = Repository::open(temporary.0.join("cache"))?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let done = timeout(
            Duration::from_secs(3),
            task.run(source, &mut Buffers::new(), &mut cache, until, |_| {
                TaskControl::Continue
            }),
        )
        .await??;
        assert_eq!(done.disposition, Disposition::Complete);
        drop(task);
        let orphan = temporary.0.join("tree/unclaimed.bin");
        fs::write(&orphan, b"caller-owned foreign file")?;
        let orphan_id = inode(&orphan)?;
        let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
        task.attach(&mut OutputDir::open(&temporary.0)?)?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let failed = timeout(
            Duration::from_secs(3),
            task.run(source, &mut Buffers::new(), &mut cache, until, |_| {
                TaskControl::Continue
            }),
        )
        .await?
        .err()
        .ok_or("unclaimed output was silently accepted")?;
        assert!(matches!(failed.cause, Cause::Reconcile { .. }));
        assert_eq!(failed.path, Path::new("tree/unclaimed.bin"));
        assert_eq!(failed.progress.revalidated_files, 3);
        assert_eq!(failed.progress.new_files, 0);
        assert_eq!(task.status()?.known_files, 3);
        assert_eq!(fs::read(&orphan)?, b"caller-owned foreign file");
        assert_eq!(inode(&orphan)?, orphan_id);
        drop(task);
        fs::rename(temporary.0.join("tree"), temporary.0.join("original-tree"))?;
        fs::create_dir(temporary.0.join("tree"))?;
        fs::set_permissions(temporary.0.join("tree"), fs::Permissions::from_mode(0o700))?;
        let _copied = fs::copy(
            temporary.0.join("original-tree").join(OWNER_MARKER_NAME),
            temporary.0.join("tree").join(OWNER_MARKER_NAME),
        )?;
        fs::write(temporary.0.join("tree/sentinel"), b"foreign root")?;
        let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
        let refused = task
            .attach(&mut OutputDir::open(&temporary.0)?)
            .err()
            .ok_or("replacement root with copied marker was adopted")?;
        assert!(matches!(refused.cause, Cause::Directory(_)));
        assert_eq!(task.status()?.known_files, 3);
        assert_eq!(
            fs::read(temporary.0.join("tree/sentinel"))?,
            b"foreign root"
        );
        for (path, bytes) in expected() {
            assert_eq!(
                fs::read(temporary.0.join("original-tree").join(path))?,
                bytes
            );
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn pause_after_synced_intent_reconciles_absent_link_and_history_revalidation_can_pause()
-> TestResult {
    let temporary = Temporary::new()?;
    let payload = b"one real authenticated output";
    let root = {
        let mut buffers = Buffers::new();
        let mut cache = Repository::open(temporary.0.join("cache"))?;
        let file = publish(&mut buffers, payload, &mut cache)?;
        let bytes = directory_bytes(&[(file, entry_metadata(b"only.bin\0", false)?)])?;
        publish(&mut buffers, &bytes, &mut cache)?
    };
    runtime()?.block_on(async {
        let mut task = create(&temporary, root)?;
        let mut cache = Repository::open(temporary.0.join("cache"))?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let mut saw_synced_intent = false;
        let paused = timeout(
            Duration::from_secs(3),
            task.run(source, &mut Buffers::new(), &mut cache, until, |p| {
                if p.uncertain_commits > 0 && p.new_files == 0 {
                    saw_synced_intent = true;
                    TaskControl::Pause
                } else {
                    TaskControl::Continue
                }
            }),
        )
        .await??;
        assert!(saw_synced_intent);
        assert_eq!(paused.disposition, Disposition::Paused);
        assert_eq!(paused.progress.new_files, 0);
        assert_eq!(paused.progress.cleanup_pending, 0);
        assert_eq!(paused.progress.uncertain_commits, 0);
        assert_eq!(task.status()?.known_files, 0);
        assert!(!temporary.0.join("tree/only.bin").exists());
        assert_eq!(fs::read_dir(temporary.0.join("tree"))?.count(), 1);
        drop(task);
        drop(cache);
        let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
        task.attach(&mut OutputDir::open(&temporary.0)?)?;
        let mut cache = Repository::open(temporary.0.join("cache"))?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let done = timeout(
            Duration::from_secs(3),
            task.run(source, &mut Buffers::new(), &mut cache, until, |_| {
                TaskControl::Continue
            }),
        )
        .await??;
        assert_eq!(done.disposition, Disposition::Complete);
        assert_eq!(done.progress.new_files, 1);
        assert_eq!(fs::read(temporary.0.join("tree/only.bin"))?, payload);
        let identity = inode(&temporary.0.join("tree/only.bin"))?;
        drop(task);
        drop(cache);
        let mut task = Task::open(temporary.0.join("task"), store::Limits::default())?;
        task.attach(&mut OutputDir::open(&temporary.0)?)?;
        let mut cache = Repository::open(temporary.0.join("cache"))?;
        let source = EndpointSource::unix(temporary.0.join("absent-fs.sock"));
        let until = deadline(&source)?;
        let mut history_checkpoints = 0;
        let paused = timeout(
            Duration::from_secs(3),
            task.run(source, &mut Buffers::new(), &mut cache, until, |p| {
                if p.historical_files == 1
                    && p.output.directories_verified == 1
                    && p.revalidated_files == 0
                {
                    history_checkpoints += 1;
                    // The first checkpoint is before the sole file; the next
                    // is in its original full plaintext re-encoding operation.
                    if history_checkpoints >= 2 {
                        return TaskControl::Pause;
                    }
                }
                TaskControl::Continue
            }),
        )
        .await??;
        assert_eq!(history_checkpoints, 2);
        assert_eq!(paused.disposition, Disposition::Paused);
        assert_eq!(paused.progress.historical_files, 1);
        assert_eq!(paused.progress.revalidated_files, 0);
        assert_eq!(paused.progress.new_files, 0);
        assert_eq!(paused.progress.cleanup_pending, 0);
        assert_eq!(paused.progress.uncertain_commits, 0);
        assert_eq!(task.status()?.phase, Phase::Paused);
        assert_eq!(task.status()?.known_files, 1);
        assert_eq!(fs::read(temporary.0.join("tree/only.bin"))?, payload);
        assert_eq!(inode(&temporary.0.join("tree/only.bin"))?, identity);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
