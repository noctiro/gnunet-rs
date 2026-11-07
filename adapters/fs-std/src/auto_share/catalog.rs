//! Bounded atomic private catalog under the existing anchored FS owned-store lock.
//! Publication task WALs retain authority for individual original mutations.
use super::{
    Error, Limits, STATE, component, relative,
    scan::{Entry, EntryKind},
};
use crate::{
    durable::store::Store,
    input_tree::{InputDir, stamp},
};
use gnunet_crypto::Hash512State;
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
    unistd::{UnlinkatFlags, unlinkat},
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};
const MARK: u16 = 0x4153;
const MAGIC: &[u8; 8] = b"FSASHR01";
const IMAGE: &str = "auto-share-state-v1";
const NEXT: &str = "auto-share-next-v1";
const MAX_IMAGE: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Preparing,
    Ready,
    Blocked,
    Complete,
    Superseded,
}
#[derive(Clone, Debug)]
pub(super) struct TaskRef {
    pub name: Vec<u8>,
    pub id: [u8; 32],
    pub uri: Vec<u8>,
    pub target: Vec<u8>,
}
#[derive(Clone, Debug)]
pub(super) struct MetadataRef {
    pub name: Vec<u8>,
    pub relative: Vec<u8>,
    pub target: Vec<u8>,
    pub hash: [u8; 64],
    pub bytes: usize,
}
/// A retained actual original reply is diagnostic evidence only. No decoder can
/// use this raw projection to mint a publication::NativeResult or accepted ACK.
#[derive(Clone, Debug)]
pub(super) struct Reply {
    pub task: usize,
    pub index: bool,
    pub attempt: usize,
    pub request: [u8; 64],
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug)]
pub(super) struct Version {
    pub id: u64,
    pub name: Vec<u8>,
    pub fingerprint: [u8; 64],
    pub kind: EntryKind,
    pub phase: Phase,
    pub tasks: Vec<TaskRef>,
    pub metadata: Vec<MetadataRef>,
    pub uri: Vec<u8>,
    pub charged: u64,
    pub replies: Vec<Reply>,
}
pub(super) struct Catalog {
    store: Store,
    root: PathBuf,
    pub directory: PathBuf,
    pub root_id: (u64, u64),
    pub versions: Vec<Version>,
    limits: Limits,
    generation: u64,
    next: u64,
    fenced: bool,
}
fn hash(bytes: &[u8]) -> [u8; 64] {
    let mut h = Hash512State::new();
    h.update(bytes);
    h.finish()
}
fn copy(b: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(b.len())
        .map_err(|_| Error::Binding("catalog allocation bound"))?;
    v.extend_from_slice(b);
    Ok(v)
}
fn put(v: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    if v.len().checked_add(b.len()).is_none_or(|n| n > MAX_IMAGE) {
        return Err(Error::Binding("auto-share catalog image bound"));
    }
    v.try_reserve(b.len())
        .map_err(|_| Error::Binding("catalog allocation"))?;
    v.extend_from_slice(b);
    Ok(())
}
fn num(v: &mut Vec<u8>, n: u64) -> Result<(), Error> {
    put(v, &n.to_be_bytes())
}
fn blob(v: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    num(v, b.len() as u64)?;
    put(v, b)
}
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .p
            .checked_add(n)
            .ok_or(Error::Binding("catalog decode overflow"))?;
        let b = self
            .b
            .get(self.p..end)
            .ok_or(Error::Binding("short catalog image"))?;
        self.p = end;
        Ok(b)
    }
    fn n(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| Error::Binding("catalog integer"))?,
        ))
    }
    fn bytes(&mut self, limit: usize) -> Result<Vec<u8>, Error> {
        let n = usize::try_from(self.n()?).map_err(|_| Error::Binding("catalog length"))?;
        if n > limit {
            return Err(Error::Binding("catalog field bound"));
        }
        copy(self.take(n)?)
    }
}
fn io(
    stage: &'static str,
    visible: bool,
    error: std::io::Error,
    cleanup: Option<std::io::Error>,
) -> Error {
    Error::Catalog {
        stage,
        visible,
        original: std::sync::Arc::new(error),
        cleanup: cleanup.map(std::sync::Arc::new),
    }
}
impl Catalog {
    pub fn open(root: &Path, limits: Limits) -> Result<Self, Error> {
        let root = std::fs::canonicalize(root)?;
        let input = InputDir::open(&root).map_err(super::ScanError::from)?;
        let stamp = stamp(input.descriptor()).map_err(super::ScanError::from)?;
        let directory = root.join(OsStr::from_bytes(STATE));
        let (mut store, created) = match std::fs::symlink_metadata(&directory) {
            Ok(_) => (Store::open(&directory, limits.catalog)?, false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut s =
                    Store::create_at(input.descriptor(), OsStr::from_bytes(STATE), limits.catalog)?;
                let mut header = Vec::new();
                put(&mut header, MAGIC)?;
                num(&mut header, stamp.device)?;
                num(&mut header, stamp.inode)?;
                blob(&mut header, root.as_os_str().as_bytes())?;
                s.append(MARK, &header)?;
                (s, true)
            }
            Err(e) => return Err(e.into()),
        };
        let record_count = store.record_count();
        let first = store
            .read_record(0)?
            .ok_or(Error::Binding("marked auto-share root lost its manifest"))?;
        if first.kind != MARK || record_count != 1 {
            return Err(Error::Binding(
                "foreign FS store is not an auto-share catalog",
            ));
        }
        let mut header = Reader {
            b: first.bytes,
            p: 0,
        };
        if header.take(8)? != MAGIC
            || header.n()? != stamp.device
            || header.n()? != stamp.inode
            || header.bytes(4096)? != root.as_os_str().as_bytes()
            || header.p != header.b.len()
        {
            return Err(Error::Binding("auto-share root/manifest mismatch"));
        }
        let mut this = Self {
            store,
            root,
            directory,
            root_id: (stamp.device, stamp.inode),
            versions: Vec::new(),
            limits,
            generation: 0,
            next: 1,
            fenced: false,
        };
        // The fixed temp is in this recognized private Rust-owned namespace. Observe
        // its actual opened inode before unlink. It is never adopted as committed.
        match openat(
            this.store.directory(),
            IMAGE,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                if !file.metadata()?.is_file() {
                    return Err(Error::Binding("catalog image is not regular"));
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(MAX_IMAGE + 1)
                    .map_err(|_| Error::Binding("catalog allocation"))?;
                file.take((MAX_IMAGE + 1) as u64).read_to_end(&mut bytes)?;
                if bytes.len() > MAX_IMAGE {
                    return Err(Error::Binding("catalog image exceeds bound"));
                }
                this.decode(&bytes)?;
            }
            Err(nix::errno::Errno::ENOENT) => {
                if !created {
                    return Err(Error::Binding(
                        "marked auto-share root lost canonical image",
                    ));
                }
                // Only the truly fresh owned-store header (generation0, no group directory)
                // may initialize. Existing incomplete/foreign namespace is not empty success.
                let directory = crate::input_tree::FrameSource::scan(
                    this.store.directory().try_clone()?,
                    16,
                    255,
                    4096,
                )
                .map_err(super::ScanError::from)?;
                if directory
                    .names
                    .iter()
                    .any(|n| !matches!(n.bytes.as_slice(), b".lock" | b"records.wal"))
                {
                    return Err(Error::Binding(
                        "existing auto-share catalog lost canonical image",
                    ));
                }
                this.commit()?;
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32).into()),
        }
        this.recover_temp()?;
        Ok(this)
    }
    pub fn check_root(&self) -> Result<(), Error> {
        if self.fenced {
            return Err(Error::Binding("auto-share catalog is fenced"));
        }
        let root = InputDir::open(&self.root).map_err(super::ScanError::from)?;
        let a = stamp(root.descriptor()).map_err(super::ScanError::from)?;
        let named = InputDir::open(&self.directory).map_err(super::ScanError::from)?;
        let x = stamp(named.descriptor()).map_err(super::ScanError::from)?;
        let y = stamp(self.store.directory()).map_err(super::ScanError::from)?;
        if (a.device, a.inode) != self.root_id || (x.device, x.inode) != (y.device, y.inode) {
            return Err(Error::Binding("auto-share original directory changed"));
        }
        Ok(())
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn last(&self, name: &[u8]) -> Option<&Version> {
        self.versions.iter().rev().find(|v| v.name == name)
    }
    pub fn version(&self, id: u64) -> Result<&Version, Error> {
        self.versions
            .iter()
            .find(|v| v.id == id)
            .ok_or(Error::Binding("unknown original version"))
    }
    pub fn path(&self, id: u64) -> PathBuf {
        self.directory.join(relative(id))
    }
    pub fn reserve(&mut self, entry: &Entry) -> Result<u64, Error> {
        self.check_root()?;
        if self.versions.len() == self.limits.versions {
            return Err(Error::Binding("auto-share version bound exhausted"));
        }
        if self
            .last(&entry.name)
            .is_some_and(|v| v.phase == Phase::Blocked)
        {
            return Err(Error::Binding("original unknown version blocks this path"));
        }
        if !self.versions.iter().any(|v| v.name == entry.name) {
            let mut names = std::collections::HashSet::new();
            names
                .try_reserve(self.limits.entries)
                .map_err(|_| Error::Binding("catalog name allocation"))?;
            for v in &self.versions {
                names.insert(v.name.as_slice());
            }
            if names.len() >= self.limits.entries {
                return Err(Error::Binding("auto-share entry bound exhausted"));
            }
        }
        let used = self.versions.iter().try_fold(0u64, |n, v| {
            n.checked_add(v.charged)
                .ok_or(Error::Binding("catalog quota overflow"))
        })?;
        if used
            .checked_add(self.limits.version_reservation)
            .is_none_or(|n| n > self.limits.retained_bytes)
        {
            return Err(Error::Binding("auto-share retained file quota exhausted"));
        }
        let id = self.next;
        self.next = id
            .checked_add(1)
            .ok_or(Error::Binding("version identifier exhausted"))?;
        self.versions
            .try_reserve(1)
            .map_err(|_| Error::Binding("catalog version allocation"))?;
        self.versions.push(Version {
            id,
            name: copy(&entry.name)?,
            fingerprint: entry.fingerprint,
            kind: entry.kind,
            phase: Phase::Preparing,
            tasks: Vec::new(),
            metadata: Vec::new(),
            uri: Vec::new(),
            charged: self.limits.version_reservation,
            replies: Vec::new(),
        });
        self.commit()?;
        // Actual original intent is durable before this fresh path is made. A crash
        // here burns the id; this path is never renamed/reused for another version.
        nix::sys::stat::mkdirat(
            self.store.directory(),
            relative(id).as_path(),
            Mode::S_IRWXU,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        self.store.directory().sync_all()?;
        Ok(id)
    }
    pub fn prepared(
        &mut self,
        id: u64,
        tasks: Vec<TaskRef>,
        metadata: Vec<MetadataRef>,
        uri: Vec<u8>,
        bytes: u64,
    ) -> Result<(), Error> {
        let v = self
            .versions
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(Error::Binding("prepared unknown version"))?;
        if v.phase != Phase::Preparing || tasks.is_empty() || bytes > v.charged {
            return Err(Error::Binding("prepared version/budget mismatch"));
        }
        for t in &tasks {
            component(&t.name)?;
        }
        v.tasks = tasks;
        v.metadata = metadata;
        v.uri = uri;
        v.charged = bytes;
        v.phase = Phase::Ready;
        self.commit()
    }
    pub fn phase(&mut self, id: u64, phase: Phase, replies: Vec<Reply>) -> Result<(), Error> {
        let v = self
            .versions
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(Error::Binding("unknown original version transition"))?;
        if v.phase == Phase::Blocked && phase != Phase::Blocked {
            return Err(Error::Binding("cannot revive fenced original version"));
        }
        if phase == Phase::Complete && v.phase != Phase::Ready {
            return Err(Error::Binding("unprepared version cannot complete"));
        }
        v.phase = phase;
        if !replies.is_empty() {
            v.replies = replies
        }
        self.commit()
    }
    pub fn account(&mut self, id: u64, bytes: u64) -> Result<(), Error> {
        let v = self
            .versions
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(Error::Binding("unknown retained version"))?;
        if bytes > v.charged {
            return Err(Error::Binding("owned group grew beyond reserved bytes"));
        }
        v.charged = bytes;
        self.commit()
    }
    fn encode(&self, generation: u64) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        put(&mut out, MAGIC)?;
        put(&mut out, self.store.task_id())?;
        num(&mut out, generation)?;
        num(&mut out, self.next)?;
        num(&mut out, self.versions.len() as u64)?;
        for v in &self.versions {
            num(&mut out, v.id)?;
            blob(&mut out, &v.name)?;
            put(&mut out, &v.fingerprint)?;
            put(
                &mut out,
                &[
                    match v.kind {
                        EntryKind::File => 1,
                        EntryKind::Directory => 2,
                    },
                    match v.phase {
                        Phase::Preparing => 1,
                        Phase::Ready => 2,
                        Phase::Blocked => 3,
                        Phase::Complete => 4,
                        Phase::Superseded => 5,
                    },
                ],
            )?;
            num(&mut out, v.charged)?;
            blob(&mut out, &v.uri)?;
            num(&mut out, v.tasks.len() as u64)?;
            for t in &v.tasks {
                blob(&mut out, &t.name)?;
                put(&mut out, &t.id)?;
                blob(&mut out, &t.uri)?;
                blob(&mut out, &t.target)?
            }
            num(&mut out, v.metadata.len() as u64)?;
            for m in &v.metadata {
                blob(&mut out, &m.name)?;
                blob(&mut out, &m.relative)?;
                blob(&mut out, &m.target)?;
                put(&mut out, &m.hash)?;
                num(&mut out, m.bytes as u64)?;
            }
            num(&mut out, v.replies.len() as u64)?;
            for r in &v.replies {
                num(&mut out, r.task as u64)?;
                put(&mut out, &[u8::from(r.index)])?;
                num(&mut out, r.attempt as u64)?;
                put(&mut out, &r.request)?;
                blob(&mut out, &r.bytes)?
            }
        }
        let check = hash(&out);
        put(&mut out, &check)?;
        Ok(out)
    }
    fn decode(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let split = bytes
            .len()
            .checked_sub(64)
            .ok_or(Error::Binding("short auto-share image"))?;
        let (body, checksum) = bytes.split_at(split);
        if hash(body) != checksum {
            return Err(Error::Binding("auto-share image checksum"));
        }
        let mut r = Reader { b: body, p: 0 };
        if r.take(8)? != MAGIC || r.take(32)? != self.store.task_id() {
            return Err(Error::Binding("foreign auto-share image"));
        }
        self.generation = r.n()?;
        self.next = r.n()?;
        let count = usize::try_from(r.n()?).map_err(|_| Error::Binding("version count"))?;
        if self.generation == 0 || self.next == 0 || count > self.limits.versions {
            return Err(Error::Binding("auto-share generation/count"));
        }
        self.versions
            .try_reserve_exact(count)
            .map_err(|_| Error::Binding("catalog allocation"))?;
        let mut previous = 0;
        let mut charged = 0u64;
        let mut names = std::collections::HashSet::new();
        names
            .try_reserve(self.limits.entries)
            .map_err(|_| Error::Binding("catalog name allocation"))?;
        for _ in 0..count {
            let id = r.n()?;
            let name = r.bytes(self.limits.scan.name_bytes)?;
            component(&name)?;
            if id <= previous || id >= self.next {
                return Err(Error::Binding("reused auto-share version"));
            }
            previous = id;
            names.insert(copy(&name)?);
            if names.len() > self.limits.entries {
                return Err(Error::Binding("catalog entry count"));
            }
            let fingerprint = r
                .take(64)?
                .try_into()
                .map_err(|_| Error::Binding("fingerprint"))?;
            let tag = r.take(2)?;
            let kind = match tag[0] {
                1 => EntryKind::File,
                2 => EntryKind::Directory,
                _ => return Err(Error::Binding("catalog entry type")),
            };
            let phase = match tag[1] {
                1 => Phase::Preparing,
                2 => Phase::Ready,
                3 => Phase::Blocked,
                4 => Phase::Complete,
                5 => Phase::Superseded,
                _ => return Err(Error::Binding("catalog phase")),
            };
            let bytes = r.n()?;
            charged = charged
                .checked_add(bytes)
                .filter(|n| *n <= self.limits.retained_bytes)
                .ok_or(Error::Binding("catalog retained quota"))?;
            let uri = r.bytes(65535)?;
            let n = usize::try_from(r.n()?).map_err(|_| Error::Binding("task count"))?;
            if n > 4097 {
                return Err(Error::Binding("task count bound"));
            }
            let mut tasks = Vec::new();
            tasks
                .try_reserve_exact(n)
                .map_err(|_| Error::Binding("task table allocation"))?;
            for _ in 0..n {
                let name = r.bytes(255)?;
                component(&name)?;
                let id = r
                    .take(32)?
                    .try_into()
                    .map_err(|_| Error::Binding("task id"))?;
                if tasks.iter().any(|t: &TaskRef| t.name == name) {
                    return Err(Error::Binding("duplicate task name"));
                }
                tasks.push(TaskRef {
                    name,
                    id,
                    uri: r.bytes(65535)?,
                    target: r.bytes(65535)?,
                })
            }
            let n = usize::try_from(r.n()?).map_err(|_| Error::Binding("metadata count"))?;
            if u64::try_from(n).map_err(|_| Error::Binding("metadata count conversion"))?
                > self.limits.scan.objects
            {
                return Err(Error::Binding("metadata count bound"));
            }
            let mut metadata = Vec::new();
            metadata
                .try_reserve_exact(n)
                .map_err(|_| Error::Binding("metadata table allocation"))?;
            for _ in 0..n {
                let name = r.bytes(255)?;
                component(&name)?;
                let relative = r.bytes(self.limits.scan.names_bytes)?;
                metadata_relative(&relative)?;
                let target = r.bytes(65535)?;
                let hash = r
                    .take(64)?
                    .try_into()
                    .map_err(|_| Error::Binding("metadata hash"))?;
                let bytes =
                    usize::try_from(r.n()?).map_err(|_| Error::Binding("metadata bytes"))?;
                if bytes > self.limits.preparation.metadata.max_metadata_bytes
                    || metadata
                        .iter()
                        .any(|m: &MetadataRef| m.name == name || m.relative == relative)
                {
                    return Err(Error::Binding("metadata size/duplicate binding"));
                }
                metadata.push(MetadataRef {
                    name,
                    relative,
                    target,
                    hash,
                    bytes,
                });
            }
            let n = usize::try_from(r.n()?).map_err(|_| Error::Binding("reply count"))?;
            if n > 2 {
                return Err(Error::Binding("reply count bound"));
            }
            let mut replies = Vec::new();
            replies
                .try_reserve_exact(n)
                .map_err(|_| Error::Binding("reply allocation"))?;
            for _ in 0..n {
                let task = usize::try_from(r.n()?).map_err(|_| Error::Binding("reply task"))?;
                let index = match r.take(1)?[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Binding("reply type")),
                };
                let attempt =
                    usize::try_from(r.n()?).map_err(|_| Error::Binding("reply attempt"))?;
                let request = r
                    .take(64)?
                    .try_into()
                    .map_err(|_| Error::Binding("request hash"))?;
                let bytes = r.bytes(65535)?;
                if task >= tasks.len() {
                    return Err(Error::Binding("reply task binding"));
                }
                replies.push(Reply {
                    task,
                    index,
                    attempt,
                    request,
                    bytes,
                })
            }
            if matches!(phase, Phase::Ready | Phase::Complete) && tasks.is_empty() {
                return Err(Error::Binding("ready version without original tasks"));
            }
            self.versions.push(Version {
                id,
                name,
                fingerprint,
                kind,
                phase,
                tasks,
                metadata,
                uri,
                charged: bytes,
                replies,
            });
        }
        if r.p != body.len() {
            return Err(Error::Binding("trailing auto-share image"));
        }
        Ok(())
    }
    fn recover_temp(&self) -> Result<(), Error> {
        match openat(
            self.store.directory(),
            NEXT,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                let a = file.metadata()?;
                if !a.is_file() {
                    return Err(Error::Binding("foreign temporary auto-share image"));
                }
                use std::os::unix::fs::MetadataExt;
                let b = nix::sys::stat::fstatat(
                    self.store.directory(),
                    NEXT,
                    nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
                )
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                if a.dev() != b.st_dev as u64 || a.ino() != b.st_ino as u64 {
                    return Err(Error::Binding("temporary catalog inode changed"));
                }
                unlinkat(self.store.directory(), NEXT, UnlinkatFlags::NoRemoveDir)
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                self.store.directory().sync_all()?;
                Ok(())
            }
            Err(nix::errno::Errno::ENOENT) => Ok(()),
            Err(e) => Err(std::io::Error::from_raw_os_error(e as i32).into()),
        }
    }
    fn commit(&mut self) -> Result<(), Error> {
        self.check_root()?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::Binding("catalog generation exhausted"))?;
        let bytes = self.encode(generation)?;
        let fd = openat(
            self.store.directory(),
            NEXT,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        let mut file = File::from(fd);
        let m = match file.metadata() {
            Ok(m) => m,
            Err(error) => {
                self.fenced = true;
                return Err(io(
                    "temporary catalog inode",
                    false,
                    error,
                    Some(std::io::Error::other(
                        "created temporary inode could not be observed; path left untouched",
                    )),
                ));
            }
        };
        use std::os::unix::fs::MetadataExt;
        let mut visible = false;
        let result = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            nix::fcntl::renameat(self.store.directory(), NEXT, self.store.directory(), IMAGE)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            visible = true;
            self.store.directory().sync_all()?;
            Ok(())
        })();
        if let Err(error) = result {
            self.fenced = true;
            let cleanup = if !visible {
                match nix::sys::stat::fstatat(
                    self.store.directory(),
                    NEXT,
                    nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
                ) {
                    Ok(now)
                        if {
                            #[cfg_attr(
                                target_os = "linux",
                                expect(
                                    clippy::unnecessary_cast,
                                    reason = "Native dev_t widening is required by the narrower macOS stat layout"
                                )
                            )]
                            let device = now.st_dev as u64;
                            device == m.dev() && now.st_ino == m.ino()
                        } =>
                    {
                        unlinkat(self.store.directory(), NEXT, UnlinkatFlags::NoRemoveDir)
                            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                            .err()
                    }
                    Ok(_) => Some(std::io::Error::other(
                        "temporary image replaced; foreign inode left untouched",
                    )),
                    Err(nix::errno::Errno::ENOENT) => None,
                    Err(e) => Some(std::io::Error::from_raw_os_error(e as i32)),
                }
            } else {
                None
            };
            return Err(io("atomic catalog commit", visible, error, cleanup));
        }
        self.generation = generation;
        Ok(())
    }
}

/// Empty denotes the selected top-level object; every other component is literal.
pub(super) fn metadata_relative(bytes: &[u8]) -> Result<(), Error> {
    if bytes.contains(&0) {
        return Err(Error::Binding("NUL metadata path"));
    }
    let path = Path::new(OsStr::from_bytes(bytes));
    if path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(Error::Binding("metadata relative path"));
    }
    Ok(())
}
