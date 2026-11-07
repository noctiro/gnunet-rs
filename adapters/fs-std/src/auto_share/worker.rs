//! One explicit bounded file/preparation worker. It never owns a network source.
use super::{
    Error, Limits, Stop,
    catalog::{MetadataRef, TaskRef, metadata_relative},
    scan::{self, Entry, Snapshot},
};
use crate::input_tree::{FrameSource, InputDir, Kind, stamp};
use crate::{
    Buffers,
    network::BlockOptions,
    publication::{
        self,
        auto_prepare::{self, Policy},
    },
};
use std::{
    fs::File,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
};
use tokio::sync::oneshot;
pub(super) struct NamedTask {
    pub name: Vec<u8>,
    pub task: publication::Task,
    pub uri: Vec<u8>,
    pub target: Vec<u8>,
}
pub(super) struct Group {
    pub tasks: Vec<NamedTask>,
    pub uri: Vec<u8>,
    pub bytes: u64,
    pub metadata: Vec<MetadataRef>,
}
pub(super) struct Prepare {
    pub root: PathBuf,
    pub root_id: (u64, u64),
    pub entry: Entry,
    pub group: PathBuf,
    pub blocks: BlockOptions,
    pub policy: Policy,
    pub metadata: crate::extraction::MetadataSettings,
    pub limits: Limits,
}
struct Preparation {
    input: Prepare,
    group_id: (u64, u64),
}

pub(super) struct Load {
    pub path: PathBuf,
    pub tasks: Vec<TaskRef>,
    pub metadata: Vec<MetadataRef>,
    pub uri: Vec<u8>,
    pub bytes: u64,
    pub limits: Limits,
}
enum Job {
    Load(Box<Load>),
    Scan {
        root: PathBuf,
        root_id: (u64, u64),
        limits: scan::ScanLimits,
    },
    Prepare(Box<Preparation>),
    Size {
        path: PathBuf,
        identity: (u64, u64),
        limits: scan::ScanLimits,
    },
}
enum Value {
    Scan(Snapshot),
    Group(Group),
    Size(u64),
}
struct Request {
    job: Job,
    reply: oneshot::Sender<Result<Value, Error>>,
}
pub(super) struct Worker {
    sender: Option<SyncSender<Request>>,
    finished: Option<oneshot::Receiver<()>>,
    thread: Option<JoinHandle<()>>,
    busy: Arc<AtomicBool>,
    stop: Stop,
}
fn identity(file: &File) -> Result<(u64, u64), Error> {
    let s = stamp(file).map_err(super::ScanError::from)?;
    Ok((s.device, s.inode))
}
fn internal_limits(limits: Limits) -> Result<scan::ScanLimits, Error> {
    let mut scan = limits.scan;
    scan.objects = 1_000_000;
    scan.children = 65536;
    scan.depth = 16;
    scan.names_bytes = 64 * 1024 * 1024;
    scan.file_bytes = limits.version_reservation;
    Ok(scan)
}
fn prepare(request: Preparation, buffers: &mut Buffers, stop: &Stop) -> Result<Group, Error> {
    let Preparation {
        input: request,
        group_id,
    } = request;
    let before = scan::single(
        &request.root,
        request.root_id,
        &request.entry.name,
        request.limits.scan,
        stop,
    )?;
    if before != request.entry {
        return Err(super::ScanError::Changed.into());
    }
    let group = InputDir::open(&request.group).map_err(super::ScanError::from)?;
    if identity(group.descriptor())? != group_id {
        return Err(Error::Binding("original preparation group changed"));
    }
    let input = request.root.join(super::component(&request.entry.name)?);
    let prepared = auto_prepare::prepare_with_metadata(
        &request.group,
        &input,
        buffers,
        request.blocks,
        request.limits.publication,
        request.policy,
        request.metadata,
        |_| {
            if stop.requested() {
                crate::Control::Cancel
            } else {
                crate::Control::Continue
            }
        },
    )
    .map_err(Error::Preparation)?;
    let after = scan::single(
        &request.root,
        request.root_id,
        &request.entry.name,
        request.limits.scan,
        stop,
    )?;
    if after != request.entry {
        return Err(super::ScanError::Changed.into());
    }
    let auto_prepare::Prepared {
        content,
        keywords,
        content_uri,
        metadata,
    } = prepared;
    let mut tasks = Vec::new();
    tasks
        .try_reserve_exact(
            keywords
                .len()
                .checked_add(1)
                .ok_or(Error::Binding("prepared task count overflow"))?,
        )
        .map_err(|_| Error::Binding("prepared task table allocation"))?;
    tasks.push(NamedTask {
        name: b"content".to_vec(),
        task: content,
        uri: content_uri.clone(),
        target: content_uri.clone(),
    });
    use std::os::unix::ffi::OsStrExt;
    for keyword in keywords {
        let name = keyword.name.as_os_str().as_bytes();
        super::component(name)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(name.len())
            .map_err(|_| Error::Binding("task name allocation"))?;
        owned.extend_from_slice(name);
        // These canonical KSK/target bytes came from the actual prepared task builder;
        // validate them before releasing its public projections/metadata workspace.
        if !matches!(
            gnunet_fs::Uri::parse(&keyword.uri, request.limits.publication.plan.ublock.uri)?,
            gnunet_fs::Uri::Keywords(_)
        ) || !matches!(
            gnunet_fs::Uri::parse(&keyword.target, request.limits.publication.plan.ublock.uri)?,
            gnunet_fs::Uri::Content(_)
        ) {
            return Err(Error::Binding("prepared keyword artifact mismatch"));
        }
        tasks.push(NamedTask {
            name: owned,
            task: keyword.task,
            uri: keyword.uri,
            target: keyword.target,
        });
    }
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(metadata.len())
        .map_err(|_| Error::Binding("metadata binding allocation"))?;
    for artifact in &metadata {
        super::component(artifact.name.as_os_str().as_bytes())?;
        if artifact.relative.is_absolute()
            || artifact
                .relative
                .components()
                .any(|p| !matches!(p, std::path::Component::Normal(_)))
        {
            return Err(Error::Binding("prepared metadata relative path"));
        }
        if !matches!(
            gnunet_fs::Uri::parse(&artifact.target, request.limits.publication.plan.ublock.uri)?,
            gnunet_fs::Uri::Content(_)
        ) {
            return Err(Error::Binding("prepared metadata target mismatch"));
        }
        let _parsed = gnunet_fs::metadata::decode_uncompressed(
            &artifact.wire,
            gnunet_fs::metadata::Limits {
                max_coded_bytes: request.policy.metadata.max_metadata_bytes,
                max_plain_bytes: request.policy.metadata.max_metadata_bytes,
                max_entries: request.policy.metadata.max_metadata_items,
            },
            gnunet_fs::metadata::Mode::Strict,
        )
        .map_err(|_| Error::Binding("prepared metadata encoding"))?;
        let mut hash = gnunet_crypto::Hash512State::new();
        hash.update(&artifact.wire);
        retained.push(MetadataRef {
            name: artifact.name.as_os_str().as_bytes().to_vec(),
            relative: artifact.relative.as_os_str().as_bytes().to_vec(),
            target: artifact.target.clone(),
            hash: hash.finish(),
            bytes: artifact.wire.len(),
        });
    }
    if !matches!(
        gnunet_fs::Uri::parse(&content_uri, request.limits.publication.plan.ublock.uri)?,
        gnunet_fs::Uri::Content(_)
    ) {
        return Err(Error::Binding("prepared root is not CHK"));
    }
    let actual = scan::owned_bytes(
        &request.group,
        group_id,
        internal_limits(request.limits)?,
        stop,
    )?;
    let future_wal = (tasks.len() as u64)
        .checked_mul(request.limits.publication.storage.max_file_bytes)
        .ok_or(Error::Binding("future WAL quota overflow"))?;
    let bytes = actual
        .checked_add(future_wal)
        .filter(|n| *n <= request.limits.version_reservation)
        .ok_or(Error::Binding(
            "prepared group exceeds original byte reservation",
        ))?;
    Ok(Group {
        tasks,
        uri: content_uri,
        bytes,
        metadata: retained,
    })
}
impl Worker {
    pub fn new(stop: Stop) -> Result<Self, Error> {
        let (sender, receiver) = mpsc::sync_channel::<Request>(1);
        let (done, finished) = oneshot::channel();
        let busy = Arc::new(AtomicBool::new(false));
        let active = Arc::clone(&busy);
        let cancellation = stop.clone();
        let thread = thread::Builder::new()
            .name("gnunet-auto-share-files".to_owned())
            .spawn(move || {
                let mut buffers = Buffers::new();
                while let Ok(request) = receiver.recv() {
                    let result = if cancellation.requested() {
                        Err(super::ScanError::Stopped.into())
                    } else {
                        match request.job {
                            Job::Load(job) => load(*job, &cancellation).map(Value::Group),
                            Job::Scan {
                                root,
                                root_id,
                                limits,
                            } => scan::observe(&root, root_id, limits, &cancellation)
                                .map(Value::Scan)
                                .map_err(Error::Scan),
                            Job::Prepare(job) => {
                                prepare(*job, &mut buffers, &cancellation).map(Value::Group)
                            }
                            Job::Size {
                                path,
                                identity,
                                limits,
                            } => scan::owned_bytes(&path, identity, limits, &cancellation)
                                .map(Value::Size)
                                .map_err(Error::Scan),
                        }
                    };
                    // A canceled observation cannot make a pending job reusable: only the actual
                    // worker completion clears busy. Dropped prepared tasks admit no native IO.
                    active.store(false, Ordering::Release);
                    let _unobserved = request.reply.send(result);
                }
                drop(buffers);
                let _closed = done.send(());
            })?;
        Ok(Self {
            sender: Some(sender),
            finished: Some(finished),
            thread: Some(thread),
            busy,
            stop,
        })
    }
    async fn call(&mut self, job: Job) -> Result<Value, Error> {
        if self.stop.requested() {
            return Err(super::ScanError::Stopped.into());
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Binding("original file worker remains busy"));
        }
        let (reply, receive) = oneshot::channel();
        let Some(sender) = &self.sender else {
            self.busy.store(false, Ordering::Release);
            return Err(Error::Binding("file worker already retired"));
        };
        if let Err(error) = sender.try_send(Request { job, reply }) {
            self.busy.store(false, Ordering::Release);
            return Err(Error::Io(std::io::Error::other(error.to_string())));
        }
        receive
            .await
            .map_err(|_| Error::Binding("original file worker ended without its result"))?
    }
    pub async fn scan(
        &mut self,
        root: PathBuf,
        root_id: (u64, u64),
        limits: scan::ScanLimits,
    ) -> Result<Snapshot, Error> {
        match self
            .call(Job::Scan {
                root,
                root_id,
                limits,
            })
            .await?
        {
            Value::Scan(v) => Ok(v),
            _ => Err(Error::Binding("wrong original worker result")),
        }
    }
    pub async fn prepare(&mut self, request: Prepare) -> Result<Group, Error> {
        let descriptor = InputDir::open(&request.group).map_err(super::ScanError::from)?;
        let group_id = identity(descriptor.descriptor())?;
        match self
            .call(Job::Prepare(Box::new(Preparation {
                input: request,
                group_id,
            })))
            .await?
        {
            Value::Group(value) => Ok(value),
            _ => Err(Error::Binding("wrong original worker result")),
        }
    }
    pub async fn load(&mut self, request: Load) -> Result<Group, Error> {
        match self.call(Job::Load(Box::new(request))).await? {
            Value::Group(group) => Ok(group),
            _ => Err(Error::Binding("wrong restore worker result")),
        }
    }
    pub async fn size(&mut self, path: PathBuf, limits: Limits) -> Result<u64, Error> {
        let input = InputDir::open(&path).map_err(super::ScanError::from)?;
        let identity = identity(input.descriptor())?;
        match self
            .call(Job::Size {
                path,
                identity,
                limits: internal_limits(limits)?,
            })
            .await?
        {
            Value::Size(v) => Ok(v),
            _ => Err(Error::Binding("wrong original size result")),
        }
    }
    /// No fresh clock or force-cancel fiction. The original bounded job observes
    /// stop between filesystem/encoding operations; a synchronous OS call may block.
    /// After the worker's final resource-drop signal, join retains actual outcome.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.stop.request();
        self.sender = None;
        let lost = if let Some(done) = self.finished.take() {
            done.await.is_err()
        } else {
            false
        };
        let panicked = self.thread.take().is_some_and(|t| t.join().is_err());
        if panicked {
            return Err(Error::Binding("auto-share file worker panicked"));
        }
        if lost {
            return Err(Error::Binding(
                "file worker closed without final resource report",
            ));
        }
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.request();
        self.sender = None;
    }
}

/// Compare the whole immediate group namespace before allocating/opening any
/// restored Task plan. Listing metadata is descriptor-anchored, sorted, bounded
/// and contains no file payload reads. Task-owned markers/WAL/block files remain
/// inside the exact Task directories and are checked by the existing Task loader.
/// Ordinary group metadata files are explicit File members, never extra Tasks.
fn restore_members(request: &Load, root: &InputDir, stop: &Stop) -> Result<FrameSource, Error> {
    if request.tasks.is_empty()
        || request.tasks.len() > 4097
        || u64::try_from(request.metadata.len())
            .map_err(|_| Error::Binding("restore metadata count"))?
            > request.limits.scan.objects
    {
        return Err(Error::Binding("restored group member bounds"));
    }
    let count = request
        .tasks
        .len()
        .checked_add(request.metadata.len())
        .ok_or(Error::Binding("restore member count overflow"))?;
    // Borrow only names already retained by this original catalog version.
    // This small bounded index precedes the much larger Task/WAL recovery set.
    let mut wanted = Vec::new();
    wanted
        .try_reserve_exact(count)
        .map_err(|_| Error::Binding("restore member index allocation"))?;
    let mut names_bytes = 0usize;
    for (name, kind) in request
        .tasks
        .iter()
        .map(|t| (t.name.as_slice(), Kind::Directory))
        .chain(
            request
                .metadata
                .iter()
                .map(|m| (m.name.as_slice(), Kind::File)),
        )
    {
        if stop.requested() {
            return Err(super::ScanError::Stopped.into());
        }
        super::component(name)?;
        if name.len() > 255 {
            return Err(Error::Binding("restore member name bound"));
        }
        names_bytes = names_bytes
            .checked_add(name.len())
            .ok_or(Error::Binding("restore member name budget overflow"))?;
        wanted.push((name, kind));
    }
    wanted.sort_unstable_by(|a, b| a.0.cmp(b.0));
    if wanted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::Binding("duplicate restored Task/metadata member"));
    }
    if stop.requested() {
        return Err(super::ScanError::Stopped.into());
    }
    let members = FrameSource::scan(root.descriptor().try_clone()?, count, 255, names_bytes)
        .map_err(super::ScanError::from)?;
    if members.names.len() != wanted.len()
        || members
            .names
            .iter()
            .zip(&wanted)
            .any(|(actual, (name, kind))| actual.bytes.as_slice() != *name || actual.kind != *kind)
    {
        return Err(Error::Binding(
            "restored group Task/metadata collection mismatch",
        ));
    }
    members.verify().map_err(super::ScanError::from)?;
    Ok(members)
}

fn load(request: Load, stop: &Stop) -> Result<Group, Error> {
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };
    use std::io::Read;
    let root = InputDir::open(&request.path).map_err(super::ScanError::from)?;
    let original = identity(root.descriptor())?;
    let members = restore_members(&request, &root, stop)?;
    // A restored group may retain many WALs. Charge the whole original collection
    // before any Task allocates its decoded record/plan tables.
    let mut wal_total = 0u64;
    for t in &request.tasks {
        if stop.requested() {
            return Err(super::ScanError::Stopped.into());
        }
        let dir = InputDir::open(request.path.join(super::component(&t.name)?))
            .map_err(super::ScanError::from)?;
        let fd = openat(
            dir.descriptor(),
            "records.wal",
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        let file = File::from(fd);
        let m = file.metadata()?;
        if !m.is_file() {
            return Err(Error::Binding("restored task WAL not regular"));
        }
        wal_total = wal_total
            .checked_add(m.len())
            .filter(|n| *n <= request.limits.preparation.max_group_plan_bytes as u64)
            .ok_or(Error::Binding("restored group WAL memory budget"))?;
    }
    let mut tasks = Vec::new();
    tasks
        .try_reserve_exact(request.tasks.len())
        .map_err(|_| Error::Binding("restore task allocation"))?;
    for (index, t) in request.tasks.into_iter().enumerate() {
        if stop.requested() {
            return Err(super::ScanError::Stopped.into());
        }
        let task = publication::Task::open(
            request.path.join(super::component(&t.name)?),
            request.limits.publication.storage,
        )
        .map_err(Error::Task)?;
        if task.task_id() != &t.id {
            return Err(Error::Binding("restored task id not original"));
        }
        let root_content = match &task.manifest().plan.artifact {
            publication::plan::Artifact::File(c)
            | publication::plan::Artifact::IndexedFile { content: c, .. } => Some(*c),
            publication::plan::Artifact::Tree(tree) => Some(tree.root),
            publication::plan::Artifact::Keywords {
                query_uri,
                target_uri,
                ..
            } if index > 0 && query_uri == &t.uri && target_uri == &t.target => None,
            _ => return Err(Error::Binding("restored task artifact mismatch")),
        };
        if let Some(content) = root_content
            && (index != 0
                || t.name != b"content"
                || t.uri != request.uri
                || t.target != request.uri
                || !matches!(gnunet_fs::Uri::parse(&request.uri,request.limits.publication.plan.ublock.uri)?,gnunet_fs::Uri::Content(c) if c==content))
        {
            return Err(Error::Binding("restored content CHK mismatch"));
        }
        tasks.push(NamedTask {
            name: t.name,
            task,
            uri: t.uri,
            target: t.target,
        });
    }
    if tasks.is_empty() {
        return Err(Error::Binding("restored group has no content"));
    }
    let objects = match &tasks[0].task.manifest().plan.artifact {
        publication::plan::Artifact::File(_) | publication::plan::Artifact::IndexedFile { .. } => 1,
        publication::plan::Artifact::Tree(tree) => tree.objects.len(),
        _ => return Err(Error::Binding("missing restored content")),
    };
    if request.metadata.len() != objects {
        return Err(Error::Binding("incomplete original metadata collection"));
    }
    for m in &request.metadata {
        if stop.requested() {
            return Err(super::ScanError::Stopped.into());
        }
        metadata_relative(&m.relative)?;
        let fd = openat(
            root.descriptor(),
            super::component(&m.name)?,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        let file = File::from(fd);
        let stat = file.metadata()?;
        if !stat.is_file()
            || stat.len() != m.bytes as u64
            || m.bytes > request.limits.preparation.metadata.max_metadata_bytes
        {
            return Err(Error::Binding("restored metadata length/type"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(m.bytes + 1)
            .map_err(|_| Error::Binding("metadata restore allocation"))?;
        file.take(m.bytes as u64 + 1).read_to_end(&mut bytes)?;
        let mut hash = gnunet_crypto::Hash512State::new();
        hash.update(&bytes);
        if bytes.len() != m.bytes || hash.finish() != m.hash {
            return Err(Error::Binding("restored metadata bytes not original"));
        }
        gnunet_fs::metadata::decode_uncompressed(
            &bytes,
            gnunet_fs::metadata::Limits {
                max_coded_bytes: request.limits.preparation.metadata.max_metadata_bytes,
                max_plain_bytes: request.limits.preparation.metadata.max_metadata_bytes,
                max_entries: request.limits.preparation.metadata.max_metadata_items,
            },
            gnunet_fs::metadata::Mode::Strict,
        )
        .map_err(|_| Error::Binding("restored metadata v2"))?;
        let content =
            match gnunet_fs::Uri::parse(&m.target, request.limits.publication.plan.ublock.uri)? {
                gnunet_fs::Uri::Content(c) => c,
                _ => return Err(Error::Binding("restored metadata target CHK")),
            };
        let matches = match &tasks[0].task.manifest().plan.artifact {
            publication::plan::Artifact::File(c)
            | publication::plan::Artifact::IndexedFile { content: c, .. } => {
                m.relative.is_empty() && *c == content
            }
            publication::plan::Artifact::Tree(tree) => tree
                .objects
                .iter()
                .any(|o| o.path == m.relative && o.content == content),
            _ => false,
        };
        if !matches {
            return Err(Error::Binding("restored metadata object binding"));
        }
    }
    // No member may have appeared/disappeared while the original recovery set
    // was opened; child WAL recovery does not change the immediate group names.
    members.verify().map_err(super::ScanError::from)?;
    let named = InputDir::open(&request.path).map_err(super::ScanError::from)?;
    if identity(root.descriptor())? != original || identity(named.descriptor())? != original {
        return Err(Error::Binding("restored group changed"));
    }
    Ok(Group {
        tasks,
        uri: request.uri,
        bytes: request.bytes,
        metadata: request.metadata,
    })
}
