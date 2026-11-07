//! A physical crash-prefix fixture, not a native process-kill claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The fallible crash fixture asserts genuine content receipts and refusal boundaries"
)]
use super::{Task, lock};
use crate::durable::{Cause, Disposition, EntryBinding, Phase, TempFact, model::Event, store};
use crate::network::{
    DownloadOptions,
    tree_download::{
        TreeDownloadOptions,
        paths::{Job, Paths, root_id},
    },
};
use crate::{Buffers, CommitStage, Control, FileIdentity, Limits, OutputDir, Repository};
use gnunet_fs::{
    Content, directory as dir,
    metadata::{self as md, Compression, Format, Item},
};
use gnunet_fs_codec::Compressor;
use gnunet_types::AbsoluteTime;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-cancel-settle-{}-{now}-{}",
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
fn metadata(items: &[Item<'_>]) -> TestResult<Vec<u8>> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 4096];
    let mut coded = vec![0; 4096];
    let plan = md::plan(
        items,
        &mut order,
        &mut plain,
        &mut coded,
        &mut Compressor::new(),
        md::Limits::default(),
        md::Options {
            compression: Compression::Never,
            ..Default::default()
        },
    )?;
    let mut bytes = vec![0; plan.report().wire_bytes];
    plan.write(&mut bytes)?;
    Ok(bytes)
}
fn directory(child: Content) -> TestResult<Vec<u8>> {
    let root_bytes = metadata(&[dir::MIME_ITEM])?;
    let item_bytes = metadata(&[Item {
        kind: 180,
        format: Format::CString,
        data: b"file.bin\0",
        plugin: None,
        mime: None,
    }])?;
    let root = dir::PreparedMetadata::validate(
        &root_bytes,
        &mut [],
        &mut md::NoCodec,
        md::Limits::default(),
    )?;
    let item = dir::PreparedMetadata::validate(
        &item_bytes,
        &mut [],
        &mut md::NoCodec,
        md::Limits::default(),
    )?;
    let mut arena = vec![0; item_bytes.len() + 512];
    let entries = [dir::PreparedEntry::prepare(child.uri(), item, &mut arena)?];
    let mut placements = [dir::Placement::default()];
    let plan = dir::plan(
        root,
        &entries,
        &mut placements,
        dir::BuildOptions::default(),
    )?;
    let mut bytes = vec![0; usize::try_from(plan.report().wire_bytes)?];
    plan.write(&mut bytes)?;
    Ok(bytes)
}
fn publish(buffers: &mut Buffers, cache: &mut Repository, bytes: &[u8]) -> TestResult<Content> {
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
fn interrupted_cancel_reconciles_real_original_link_without_replacing_foreign_names() -> TestResult
{
    let temporary = Temporary::new()?;
    let task_path = temporary.0.join("task");
    let tree = temporary.0.join("tree");
    let final_path = tree.join("file.bin");
    let temp_name = ".gnunet-fs-output-crash-fixture";
    let temp_path = tree.join(temp_name);
    let mut cache = Repository::open(temporary.0.join("cache"))?;
    let mut buffers = Buffers::new();
    let bytes: Vec<_> = (0..70_013).map(|n| (n % 251) as u8).collect();
    let child = publish(&mut buffers, &mut cache, &bytes)?;
    let directory_bytes = directory(child)?;
    let root = publish(&mut buffers, &mut cache, &directory_bytes)?;
    let mut parent = OutputDir::open(&temporary.0)?;
    let mut policy = TreeDownloadOptions::new(DownloadOptions::new(AbsoluteTime::from_micros(0)));
    policy.max_namespace_bytes = 64;
    let mut task = Task::create(
        &task_path,
        &mut parent,
        "tree",
        root.uri(),
        policy,
        store::Limits::default(),
    )?;

    // Derive the entry coordinates through the real authenticated parent parser
    // and original shared Paths/Walk admission; no VerifiedFile is fabricated.
    let mut instance = dir::walk::Instance::new();
    let mut slots = vec![dir::walk::Slot::empty(); 2];
    let mut names = [0; 64];
    let mut owner = dir::walk::Walk::new(
        &mut instance,
        &mut slots,
        &mut names,
        root,
        dir::walk::Kind::Directory,
        dir::walk::Limits {
            max_depth: 64,
            max_entries: 1,
            max_total_bytes: policy.max_total_bytes,
            max_queued: 2,
            shared: dir::walk::SharedPolicy::VisitAgain,
            cycles: dir::walk::CyclePolicy::Reject,
        },
    )?;
    let mut paths = Paths {
        jobs: vec![Job {
            id: root_id(root),
            parent: None,
            kind: dir::walk::Kind::Directory,
            path: Arc::new(PathBuf::new()),
            target: [0; 32],
            inline: None,
        }],
        names: BTreeSet::new(),
        path_bytes: 0,
        inline_bytes: 0,
    };
    let work = owner.begin()?.ok_or("missing root work")?;
    let receipt = buffers.visit_directory(
        &mut cache,
        root,
        Limits::default(),
        policy.directory,
        |entry| paths.admit(&mut owner, work.id, Path::new(""), entry, policy),
    )?;
    owner.finish_directory(work.id, receipt)?;
    let job = paths.jobs.get(1).ok_or("missing admitted child")?;
    let binding = EntryBinding {
        id: job.id,
        parent: job.parent,
        path: job.path.as_ref().clone(),
        kind: job.kind,
        content: child,
    };
    let Some(super::AttachedOutput::Directory(output)) = task.output.as_ref() else {
        return Err("missing original directory output".into());
    };
    let parent_id = output.identity()?;
    {
        let mut state = lock(&task.session)?;
        state.append(Event::Phase(Phase::Running))?;
        state.append(Event::DirectoryVerified { id: root_id(root) })?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)?;
    let original = FileIdentity::of(&file)?;
    lock(&task.session)?.append(Event::TempOwned {
        binding: binding.clone(),
        temporary: TempFact {
            parent: parent_id,
            identity: original,
            name: temp_name.into(),
        },
    })?;
    let read = buffers.copy_to(&mut cache, child, &mut file, Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(read.verified.content(), child);
    file.sync_all()?;
    lock(&task.session)?.append(Event::CommitIntent { id: binding.id })?;
    fs::hard_link(&temp_path, &final_path)?;
    File::open(&tree)?.sync_all()?;
    drop(file);
    // The physical link exists, but FileCommitted/Cleanup never reached WAL.
    // The cancellation request itself is durable; this is an intentionally
    // constructed crash boundary, not evidence of killing a native process.
    task.request_cancel()?;
    drop(task);

    let mut task = Task::open(&task_path, store::Limits::default())?;
    task.attach(&mut parent)?;
    let status = task.status()?;
    assert_eq!(status.phase, Phase::CancelRequested);
    assert_eq!(
        (
            status.known_files,
            status.cleanup_pending,
            status.uncertain_commits
        ),
        (0, 1, 1)
    );
    let source = gnunet_client_host::EndpointSource::unix(temporary.0.join("no-fs-service.sock"));
    let deadline = AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 1_000_000);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let refused = runtime.block_on(task.run(source, &mut buffers, &mut cache, deadline, |_| {
        crate::durable::TaskControl::Continue
    }));
    assert!(matches!(refused,Err(error) if matches!(error.cause,Cause::State(_))));
    assert_eq!(task.status()?.phase, Phase::CancelRequested);
    assert_eq!(task.status()?.state_records, status.state_records);

    // A foreign final name cannot be adopted, overwritten, or deleted.
    let held_original = tree.join("held-original");
    fs::rename(&final_path, &held_original)?;
    let foreign = b"foreign final must remain";
    fs::write(&final_path, foreign)?;
    let foreign_id = FileIdentity::of(&File::open(&final_path)?)?;
    let refused = task.settle_cancel(&mut parent, &mut buffers, &mut cache, |_| Control::Continue);
    assert!(matches!(refused,Err(error) if matches!(error.cause,Cause::Reconcile{..})));
    assert_eq!(fs::read(&final_path)?, foreign);
    assert_eq!(FileIdentity::of(&File::open(&final_path)?)?, foreign_id);
    assert_eq!(FileIdentity::of(&File::open(&temp_path)?)?, original);
    assert_eq!(task.status()?.phase, Phase::CancelRequested);
    fs::remove_file(&final_path)?; // Explicit test-fixture action, not task cleanup.
    fs::rename(&held_original, &final_path)?;

    // Matching path, inode and byte count still do not certify Content.
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    fs::write(&final_path, &corrupt)?;
    File::open(&final_path)?.sync_all()?;
    let refused = task.settle_cancel(&mut parent, &mut buffers, &mut cache, |_| Control::Continue);
    assert!(matches!(refused, Err(error) if matches!(&error.cause,
        Cause::Revalidate(failure) if matches!(&failure.operation, crate::Error::SourceChanged))));
    assert_eq!(task.status()?.phase, Phase::CancelRequested);
    assert_eq!(task.status()?.known_files, 0);
    assert_eq!(fs::read(&final_path)?, corrupt);
    assert_eq!(FileIdentity::of(&File::open(&final_path)?)?, original);
    fs::write(&final_path, &bytes)?; // Explicit fixture restoration, same inode.
    File::open(&final_path)?.sync_all()?;

    // Retain a foreign temporary replacement. Actual final revalidation and its
    // barriers must remain known when precise original-temp cleanup then fails.
    fs::remove_file(&temp_path)?;
    let foreign_temp = b"foreign temporary must remain";
    fs::write(&temp_path, foreign_temp)?;
    let foreign_temp_id = FileIdentity::of(&File::open(&temp_path)?)?;
    let failed =
        match task.settle_cancel(&mut parent, &mut buffers, &mut cache, |_| Control::Continue) {
            Err(failed) => failed,
            Ok(_) => return Err("foreign temporary was incorrectly accepted".into()),
        };
    match &failed.cause {
        Cause::Committed(commit) => {
            assert_eq!(commit.identity, original);
            assert_eq!(commit.receipt.verified.content(), child);
            assert_eq!(commit.receipt.progress.plaintext_bytes, bytes.len() as u64);
            assert!(matches!(
                commit.cause.as_ref(),
                Cause::Operation(crate::Error::SourceChanged)
            ));
        }
        other => return Err(format!("missing real committed receipt: {other}").into()),
    }
    assert_eq!(failed.progress.output.files_committed, 1);
    assert_eq!(failed.progress.revalidated_files, 1);
    assert_eq!(failed.progress.new_files, 0);
    assert_eq!(fs::read(&final_path)?, bytes);
    assert_eq!(fs::read(&temp_path)?, foreign_temp);
    assert_eq!(FileIdentity::of(&File::open(&temp_path)?)?, foreign_temp_id);
    let status = task.status()?;
    assert_eq!(status.phase, Phase::CancelRequested);
    assert_eq!(
        (
            status.known_files,
            status.cleanup_pending,
            status.uncertain_commits
        ),
        (1, 1, 0)
    );
    {
        let state = lock(&task.session)?;
        let entry = state
            .state
            .entries
            .get(&binding.id)
            .ok_or("missing reconciled child")?;
        assert_eq!(entry.committed, Some(original));
        assert_eq!(entry.stage, CommitStage::Durable);
        assert!(!entry.cleanup);
    }
    drop(task);
    fs::remove_file(&temp_path)?; // The fixture explicitly resolves its own foreign file.
    let mut task = Task::open(&task_path, store::Limits::default())?;
    let cancelled =
        task.settle_cancel(&mut parent, &mut buffers, &mut cache, |_| Control::Continue)?;
    assert_eq!(cancelled.disposition, Disposition::Cancelled);
    assert!(cancelled.walk.is_none());
    assert_eq!(cancelled.progress.historical_files, 1);
    assert_eq!(cancelled.progress.output.files_committed, 0);
    assert_eq!(cancelled.progress.revalidated_files, 0);
    assert_eq!(cancelled.progress.cleanup_pending, 0);
    assert_eq!(cancelled.progress.uncertain_commits, 0);
    assert_eq!(fs::read(&final_path)?, bytes);
    assert_eq!(FileIdentity::of(&File::open(&final_path)?)?, original);
    assert!(!temp_path.exists());
    assert_eq!(task.status()?.phase, Phase::Cancelled);
    drop(task);
    let task = Task::open(&task_path, store::Limits::default())?;
    let final_status = task.status()?;
    assert_eq!(final_status.phase, Phase::Cancelled);
    assert_eq!(
        (
            final_status.known_files,
            final_status.cleanup_pending,
            final_status.uncertain_commits
        ),
        (1, 0, 0)
    );
    Ok(())
}
