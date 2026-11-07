//! Independent marker-qualified Rust snapshot store. Production alone opens its
//! own explicitly selected private namespace; no business key format is parsed.
use gnunet_crypto::hash512_parts;
use gnunet_types::Error;
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;
#[path = "tcp_directory.rs"]
mod tcp_directory;

const HEADER: usize = 88;
/// Fixed independent production namespace. The caller cannot inject arbitrary
/// marker/file names or use another service's qualified directory by accident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Namespace {
    /// Existing independent Rust IDENTITY snapshot format, never a C ego store.
    Identity,
    /// Independent Rust NAMESTORE authority snapshot format.
    Namestore,
    /// Independent Rust public REVOCATION certificate/fact snapshot.
    Revocation,
    /// Independent Rust REST/OIDC signer and issued grant/access state.
    Oidc,
    /// Independent Rust MESSENGER authenticated history and metadata.
    Messenger,
    /// Independent Rust HOSTLIST learned public URL/quality history.
    Hostlist,
    /// Independent Rust TRANSPORT public generation timestamp highwater.
    Transport,
    /// Independent Rust TRANSPORT public DV LEARN and BOX sender watermarks.
    TransportDv,
    /// Independent TCP authenticated replay floors, distinct from T1/DV state.
    TransportTcp,
    /// GNS publication expiration/nonce highwaters; no records or secret keys.
    GnsPublication,
}
impl Namespace {
    const fn marker(self) -> &'static [u8] {
        match self {
            Self::Identity => b"GNUNET-RUST-IDENTITY-STORE\nversion=1\n",
            Self::Namestore => b"GNUNET-RUST-NAMESTORE-SNAPSHOT\nversion=1\n",
            Self::Revocation => b"GNUNET-RUST-REVOCATION-SNAPSHOT\nversion=1\n",
            Self::Oidc => b"GNUNET-RUST-REST-OIDC-SNAPSHOT\nversion=1\n",
            Self::Messenger => b"GNUNET-RUST-MESSENGER-SNAPSHOT\nversion=1\n",
            Self::Hostlist => b"GNUNET-RUST-HOSTLIST-SNAPSHOT\nversion=1\n",
            Self::Transport => b"GNUNET-RUST-TRANSPORT-MONOTIME\nversion=1\n",
            Self::TransportDv => b"GNUNET-RUST-TRANSPORT-DV-PUBLIC\nversion=1\n",
            Self::TransportTcp => b"GNUNET-RUST-TCP-REPLAY-LEDGER\nversion=2\n",
            Self::GnsPublication => b"GNUNET-RUST-GNS-PUBLICATION-NONCES\nversion=1\n",
        }
    }
    const fn mark(self) -> &'static str {
        match self {
            Self::Identity => ".identity-rust-store",
            Self::Namestore => ".namestore-rust-store",
            Self::Revocation => ".revocation-rust-store",
            Self::Oidc => ".rest-oidc-rust-store",
            Self::Messenger => ".messenger-rust-store",
            Self::Hostlist => ".hostlist-rust-store",
            Self::Transport => ".transport-rust-monotime-store",
            Self::TransportDv => ".transport-rust-dv-store",
            Self::TransportTcp => ".tcp-rust-replay-store",
            Self::GnsPublication => ".gns-publication-rust-store",
        }
    }
    const fn image(self) -> &'static str {
        match self {
            Self::Identity => "identity.snapshot",
            Self::Namestore => "namestore.snapshot",
            Self::Revocation => "revocation.snapshot",
            Self::Oidc => "rest-oidc.snapshot",
            Self::Messenger => "messenger.snapshot",
            Self::Hostlist => "hostlist.snapshot",
            Self::Transport => "transport-monotime.snapshot",
            Self::TransportDv => "transport-dv.snapshot",
            Self::TransportTcp => "tcp-replay.snapshot",
            Self::GnsPublication => "gns-publication.snapshot",
        }
    }
    const fn lock(self) -> &'static str {
        match self {
            Self::Identity => ".identity-rust.lock",
            Self::Namestore => ".namestore-rust.lock",
            Self::Revocation => ".revocation-rust.lock",
            Self::Oidc => ".rest-oidc-rust.lock",
            Self::Messenger => ".messenger-rust.lock",
            Self::Hostlist => ".hostlist-rust.lock",
            Self::Transport => ".transport-rust-monotime.lock",
            Self::TransportDv => ".transport-rust-dv.lock",
            Self::TransportTcp => ".tcp-rust-replay.lock",
            Self::GnsPublication => ".gns-publication-rust.lock",
        }
    }
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Identity => b"GNIDST01",
            Self::Namestore => b"GNNMST01",
            Self::Revocation => b"GNREV001",
            Self::Oidc => b"GNOIDC01",
            Self::Messenger => b"GNMSG001",
            Self::Hostlist => b"GNHOST01",
            Self::Transport => b"GNTRNS01",
            Self::TransportDv => b"GNDVST01",
            Self::TransportTcp => b"GNTCPS02",
            Self::GnsPublication => b"GNGNSP01",
        }
    }
    const fn temporary(self) -> &'static str {
        match self {
            Self::Identity => "pending.",
            Self::Namestore => "namestore.pending.",
            Self::Revocation => "revocation.pending.",
            Self::Oidc => "rest-oidc.pending.",
            Self::Messenger => "messenger.pending.",
            Self::Hostlist => "hostlist.pending.",
            Self::Transport => "transport-monotime.pending.",
            Self::TransportDv => "transport-dv.pending.",
            Self::TransportTcp => "tcp-replay.pending.",
            Self::GnsPublication => "gns-publication.pending.",
        }
    }
    pub(crate) const fn thread_name(self) -> &'static str {
        match self {
            Self::Identity => "gnunet-identity-store",
            Self::Namestore => "gnunet-namestore-store",
            Self::Revocation => "gnunet-revocation-store",
            Self::Oidc => "gnunet-rest-oidc-store",
            Self::Messenger => "gnunet-messenger-store",
            Self::Hostlist => "gnunet-hostlist-store",
            Self::Transport => "gnunet-transport-monotime-store",
            Self::TransportDv => "gnunet-transport-dv-store",
            Self::TransportTcp => "gnunet-tcp-replay-store",
            Self::GnsPublication => "gnunet-gns-nonce",
        }
    }
}
fn namespace_guard(directory: &Path, namespace: Namespace) -> Result<(), Failure> {
    for other in [
        Namespace::Identity,
        Namespace::Namestore,
        Namespace::Revocation,
        Namespace::Oidc,
        Namespace::Messenger,
        Namespace::Hostlist,
        Namespace::Transport,
        Namespace::TransportDv,
        Namespace::TransportTcp,
        Namespace::GnsPublication,
    ] {
        if other == namespace {
            continue;
        }
        match fs::symlink_metadata(directory.join(other.mark())) {
            Ok(_) => return Err(failure("foreign-namespace", Error::Authentication, None)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(os("namespace-marker-probe", e)),
        }
    }
    Ok(())
}
/// Maximum opaque canonical core snapshot body. No unbounded secret cache exists.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum serialized body, including all names/key bytes and core metadata.
    pub body_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            body_bytes: 4 * 1024 * 1024,
        }
    }
}
/// Publication exposure of an original filesystem transaction, not an IPC ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exposure {
    /// Original canonical snapshot was not replaced. An owned temporary may still
    /// need cleanup; its independent cleanup error is retained.
    NotPublished,
    /// Replacement was attempted; committed outcome cannot be asserted.
    Unknown,
}
/// Original storage cause and independent actual cleanup failure. No secret body
/// or key is printable through this value.
#[derive(Debug)]
pub struct Failure {
    /// Original operation stage.
    pub stage: &'static str,
    /// Original known/unknown publication state.
    pub exposure: Exposure,
    /// Original protocol/resource classification.
    pub reason: Error,
    /// Original OS error, if any.
    pub io: Option<io::Error>,
    /// Independent owned temporary cleanup failure.
    pub cleanup: Option<io::Error>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snapshot store {}: {:?} ({:?})",
            self.stage, self.reason, self.exposure
        )?;
        if let Some(e) = &self.io {
            write!(f, ": {e}")?;
        }
        if let Some(e) = &self.cleanup {
            write!(f, "; independent cleanup: {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.io.as_ref().map(|e| e as _)
    }
}
fn failure(stage: &'static str, reason: Error, io: Option<io::Error>) -> Failure {
    Failure {
        stage,
        exposure: Exposure::NotPublished,
        reason,
        io,
        cleanup: None,
    }
}
fn os(stage: &'static str, e: io::Error) -> Failure {
    failure(stage, Error::Storage, Some(e))
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Inode(u64, u64);
fn id(m: &fs::Metadata) -> Inode {
    Inode(m.dev(), m.ino())
}
fn metadata(file: &File, directory: bool, stage: &'static str) -> Result<Inode, Failure> {
    let m = file.metadata().map_err(|e| os(stage, e))?;
    let regular = if directory {
        m.is_dir()
    } else {
        m.is_file() && m.nlink() == 1
    };
    if !regular || m.uid() != nix::unistd::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err(failure(stage, Error::Authentication, None));
    }
    Ok(id(&m))
}
fn path_id(path: &Path, directory: bool, stage: &'static str) -> Result<Inode, Failure> {
    let m = fs::symlink_metadata(path).map_err(|e| os(stage, e))?;
    let regular = if directory {
        m.is_dir()
    } else {
        m.is_file() && m.nlink() == 1
    };
    if m.file_type().is_symlink()
        || !regular
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o077 != 0
    {
        return Err(failure(stage, Error::Authentication, None));
    }
    Ok(id(&m))
}
fn open_read(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
fn make_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
/// Only actual recovery creates this value. Its secret body has no Debug/Clone.
pub struct Loaded {
    namespace: Namespace,
    created_directory: bool,
    generation: u64,
    body: Zeroizing<Vec<u8>>,
    recovered_temporaries: usize,
}
impl Loaded {
    /// Whether this exact open created the private directory. A marked directory
    /// with no canonical image is not a newly created store.
    #[must_use]
    pub const fn created_directory(&self) -> bool {
        self.created_directory
    }
    /// Actual qualified source namespace; check before interpreting its body.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Actual stored committed generation;0 means no prior canonical image.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Metadata count of safely retired pre-publication owned temporaries.
    #[must_use]
    pub const fn recovered_temporaries(&self) -> usize {
        self.recovered_temporaries
    }
    /// Transfer secret snapshot ownership into the production pure service.
    #[must_use]
    pub fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}
/// Actual successful original snapshot replacement. Constructor is private.
#[derive(Clone, Copy, Debug)]
pub struct Committed {
    namespace: Namespace,
    generation: u64,
}
impl Committed {
    /// Namespace of the actual original snapshot publication.
    #[must_use]
    pub const fn namespace(self) -> Namespace {
        self.namespace
    }

    /// Generation that really reached file+directory synchronization/readback.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}
/// One marker-qualified directory and exclusive writer lease. The store retains
/// descriptor/fence metadata, never a second long-lived canonical secret cache.
pub struct Store {
    namespace: Namespace,
    directory: PathBuf,
    dir: File,
    dir_id: Inode,
    marker: File,
    marker_id: Inode,
    lock: File,
    lock_id: Inode,
    image: Option<(File, Inode)>,
    generation: u64,
    limits: Limits,
    failure: Option<Arc<Failure>>,
}
// Return the actual writer lease as an owner, so first initialization can
// hold it before exposing the complete marker to another process.
fn writer_lease(directory: &Path, lock_name: &str) -> Result<(File, Inode), Failure> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(lock_name))
        .map_err(|e| os("writer-open", e))?;
    let identity = metadata(&lock, false, "writer-policy")?;
    lock.try_lock().map_err(|e| match e {
        fs::TryLockError::Error(e) => os("writer-lock", e),
        e => failure("writer-lock", Error::Conflict, Some(io::Error::other(e))),
    })?;
    Ok((lock, identity))
}
impl Store {
    /// Create a brand-new directory, or reopen only an already marked private
    /// Rust store. Existing unmarked/foreign directories are refused unchanged.
    /// The parent must already exist; foreground may create its own selected
    /// public parent before calling, never the final store directory itself.
    pub fn open(
        namespace: Namespace,
        directory: impl AsRef<Path>,
        limits: Limits,
    ) -> Result<(Self, Loaded), Failure> {
        if limits.body_bytes == 0
            || limits.body_bytes > 64 * 1024 * 1024
            || limits.body_bytes.checked_add(HEADER).is_none()
        {
            return Err(failure("limits", Error::Capacity, None));
        }
        let marker_data = namespace.marker();
        let mark_name = namespace.mark();
        let image_name = namespace.image();
        let lock_name = namespace.lock();
        let directory = directory.as_ref();
        let parent = directory
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        #[cfg(target_os = "freebsd")]
        let _initialization = {
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(parent)
                .map_err(|e| os("open-initialization-parent", e))?;
            parent
                .lock()
                .map_err(|e| os("lock-initialization-parent", e))?;
            parent
        };
        let new = if namespace == Namespace::TransportTcp {
            tcp_directory::create(directory, mark_name, marker_data)?
        } else {
            match DirBuilder::new().mode(0o700).create(directory) {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(os("create-store-directory", e)),
            }
        };
        let original_dir = path_id(directory, true, "directory-policy")?;
        let directory = fs::canonicalize(directory).map_err(|e| os("canonical-directory", e))?;
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&directory)
            .map_err(|e| os("open-directory", e))?;
        if metadata(&dir, true, "directory-policy")? != original_dir {
            return Err(failure("directory-replaced", Error::Conflict, None));
        }
        namespace_guard(&directory, namespace)?;
        let initial_writer = if new && namespace != Namespace::TransportTcp {
            Some(writer_lease(&directory, lock_name)?)
        } else {
            None
        };
        let marker = if new && namespace != Namespace::TransportTcp {
            // Every ordinary fresh namespace holds its writer lease before a
            // complete marker becomes visible. A second opener cannot steal the
            // creator's unique new-directory authority before its first commit.
            let marker_path = directory.join(format!("{mark_name}.initializing"));
            let mut marker = make_file(&marker_path).map_err(|e| os("create-marker", e))?;
            marker
                .write_all(marker_data)
                .map_err(|e| os("write-marker", e))?;
            marker.sync_all().map_err(|e| os("sync-marker", e))?;
            fs::rename(&marker_path, directory.join(mark_name))
                .map_err(|e| os("publish-initialization-marker", e))?;
            dir.sync_all().map_err(|e| os("sync-new-directory", e))?;
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent)
                .map_err(|e| os("open-parent", e))?;
            parent.sync_all().map_err(|e| os("sync-parent", e))?;
            marker
        } else {
            // This is the sole read before marker qualification: a fixed public
            // marker, never an ego key or unrecognized existing file.
            match open_read(&directory.join(mark_name)) {
                Err(error)
                    if namespace == Namespace::GnsPublication
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    // Another fresh creator may still own initialization. No
                    // existing directory is modified or adopted here. The nonce
                    // caller may wait only within its original hard target;
                    // present malformed markers/canonical images still fail.
                    return Err(failure(
                        "initialization-pending",
                        Error::NotReady,
                        Some(error),
                    ));
                }
                result => result.map_err(|e| os("marked-store-required", e))?,
            }
        };
        let marker_id = metadata(&marker, false, "marker-policy")?;
        let mut marker_bytes = [0u8; 64];
        let mut read_marker =
            open_read(&directory.join(mark_name)).map_err(|e| os("read-marker", e))?;
        if metadata(&read_marker, false, "marker-policy")? != marker_id
            || read_marker
                .metadata()
                .map_err(|e| os("marker-size", e))?
                .len()
                != marker_data.len() as u64
        {
            return Err(failure("marker-identity", Error::Authentication, None));
        }
        read_marker
            .read_exact(
                marker_bytes
                    .get_mut(..marker_data.len())
                    .ok_or_else(|| failure("marker-limit", Error::Capacity, None))?,
            )
            .map_err(|e| os("read-marker", e))?;
        if &marker_bytes[..marker_data.len()] != marker_data {
            return Err(failure("marker-format", Error::Authentication, None));
        }
        if namespace == Namespace::TransportTcp && !new {
            // A previous process may have stopped after publishing the complete
            // marker but before syncing its parent entry. Qualify it first.
            tcp_directory::sync_parent(&directory)?;
        }
        let (lock, lock_id) = match initial_writer {
            Some(lease) => lease,
            None => writer_lease(&directory, lock_name)?,
        };
        dir.sync_all().map_err(|e| os("writer-directory-sync", e))?;
        #[cfg(target_os = "freebsd")]
        drop(_initialization);
        let mut store = Self {
            namespace,
            directory,
            dir,
            dir_id: original_dir,
            marker,
            marker_id,
            lock,
            lock_id,
            image: None,
            generation: 0,
            limits,
            failure: None,
        };
        store.namespace_fence()?;
        let mut recovered = 0;
        // A new exclusive process writer cannot overlap an old admitted IO job.
        // Recognized pending names were never canonical image publications.
        for item in fs::read_dir(&store.directory).map_err(|e| os("enumerate-store", e))? {
            let item = item.map_err(|e| os("enumerate-store", e))?;
            let name = item.file_name();
            if [
                std::ffi::OsStr::new(mark_name),
                std::ffi::OsStr::new(lock_name),
                std::ffi::OsStr::new(image_name),
            ]
            .contains(&name.as_os_str())
            {
                continue;
            }
            let Some(name) = name.to_str() else {
                return Err(failure("unknown-store-entry", Error::Storage, None));
            };
            if !name
                .strip_prefix(namespace.temporary())
                .is_some_and(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                || recovered != 0
            {
                return Err(failure("unknown-store-entry", Error::Storage, None));
            }
            let path = item.path();
            let before = path_id(&path, false, "pending-policy")?;
            if path_id(&path, false, "pending-replaced")? != before {
                return Err(failure("pending-replaced", Error::Conflict, None));
            }
            fs::remove_file(&path).map_err(|e| os("retire-pending", e))?;
            store
                .dir
                .sync_all()
                .map_err(|e| os("sync-retired-pending", e))?;
            recovered += 1;
        }
        let path = store.directory.join(image_name);
        let (generation, body) = match open_read(&path) {
            Ok(mut image) => {
                let image_id = metadata(&image, false, "image-policy")?;
                let (generation, body) = store.read_image(&mut image)?;
                image.sync_all().map_err(|e| os("recovery-image-sync", e))?;
                store
                    .dir
                    .sync_all()
                    .map_err(|e| os("recovery-directory-sync", e))?;
                store.image = Some((image, image_id));
                (generation, body)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (0, Zeroizing::new(Vec::new())),
            Err(e) => return Err(os("open-image", e)),
        };
        store.generation = generation;
        store.fence()?;
        Ok((
            store,
            Loaded {
                namespace,
                created_directory: new,
                generation,
                body,
                recovered_temporaries: recovered,
            },
        ))
    }
    fn namespace_fence(&self) -> Result<(), Failure> {
        if let Err(mut error) = namespace_guard(&self.directory, self.namespace) {
            // Losing the qualified namespace invalidates this original writer,
            // independently of whether its own rename was attempted yet.
            error.exposure = Exposure::Unknown;
            return Err(error);
        }
        for (path, file, expected, directory) in [
            (self.directory.clone(), &self.dir, self.dir_id, true),
            (
                self.directory.join(self.namespace.mark()),
                &self.marker,
                self.marker_id,
                false,
            ),
            (
                self.directory.join(self.namespace.lock()),
                &self.lock,
                self.lock_id,
                false,
            ),
        ] {
            if metadata(file, directory, "fence-fd")? != expected
                || path_id(&path, directory, "fence-path")? != expected
            {
                return Err(failure("fence-lost", Error::OutcomeUnknown, None));
            }
        }
        Ok(())
    }
    fn fence(&self) -> Result<(), Failure> {
        self.namespace_fence()?;
        match (
            &self.image,
            fs::symlink_metadata(self.directory.join(self.namespace.image())),
        ) {
            (None, Err(e)) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            (Some((file, expected)), Ok(m))
                if id(&m) == *expected
                    && !m.file_type().is_symlink()
                    && metadata(file, false, "image-fence-fd")? == *expected =>
            {
                Ok(())
            }
            (_, Err(e)) => Err(os("image-fence", e)),
            _ => Err(failure("image-fence-lost", Error::OutcomeUnknown, None)),
        }
    }
    fn read_image(&self, file: &mut File) -> Result<(u64, Zeroizing<Vec<u8>>), Failure> {
        let len = file.metadata().map_err(|e| os("image-size", e))?.len();
        if len < HEADER as u64 || len > self.limits.body_bytes as u64 + HEADER as u64 {
            return Err(failure("image-size", Error::Storage, None));
        }
        let mut head = [0u8; HEADER];
        file.read_exact(&mut head)
            .map_err(|e| os("image-header", e))?;
        let generation = u64::from_be_bytes(
            head[8..16]
                .try_into()
                .map_err(|_| failure("image-header", Error::Storage, None))?,
        );
        let body_len = u64::from_be_bytes(
            head[16..24]
                .try_into()
                .map_err(|_| failure("image-header", Error::Storage, None))?,
        );
        if &head[..8] != self.namespace.magic()
            || generation == 0
            || body_len != len - HEADER as u64
        {
            return Err(failure("image-format", Error::Storage, None));
        }
        let mut body = Zeroizing::new(Vec::new());
        body.try_reserve_exact(body_len as usize)
            .map_err(|_| failure("load-allocation", Error::Capacity, None))?;
        body.resize(body_len as usize, 0);
        file.read_exact(&mut body)
            .map_err(|e| os("image-body", e))?;
        if hash512_parts(&[&head[..24], &body]) != head[24..88] {
            return Err(failure("image-checksum", Error::Storage, None));
        }
        Ok((generation, body))
    }
    /// This exact original qualified namespace, immutable for the Store lifetime.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }
    /// Actual committed generation, never an issued/admitted-write count.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Retain the exact first cause independently of any returned completion.
    #[must_use]
    pub fn failure(&self) -> Option<&Arc<Failure>> {
        self.failure.as_ref()
    }
    /// Replace the original canonical snapshot atomically. The provided body is
    /// a bounded Zeroizing owned snapshot from the pure core. Local syscall errors
    /// never return Committed; rename/sync/readback ambiguity permanently fences
    /// this process writer. A fresh explicit reopen recovers actual disk bytes.
    pub fn commit(
        &mut self,
        expected: u64,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Committed, Arc<Failure>> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        if expected != self.generation || body.len() > self.limits.body_bytes {
            return Err(Arc::new(failure(
                "commit-precondition",
                Error::InvalidInput,
                None,
            )));
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Arc::new(failure("generation", Error::Overflow, None)))?;
        let path = self
            .directory
            .join(format!("{}{next:016x}", self.namespace.temporary()));
        let mut temporary = None;
        let mut exposed = false;
        let result = (|| {
            self.fence()?;
            let mut file = make_file(&path).map_err(|e| os("create-pending", e))?;
            let temp_id = metadata(&file, false, "pending-policy")?;
            temporary = Some(temp_id);
            let mut head = [0u8; HEADER];
            head[..8].copy_from_slice(self.namespace.magic());
            head[8..16].copy_from_slice(&next.to_be_bytes());
            head[16..24].copy_from_slice(&(body.len() as u64).to_be_bytes());
            let checksum = hash512_parts(&[&head[..24], &body]);
            head[24..88].copy_from_slice(&checksum);
            file.write_all(&head).map_err(|e| os("write-header", e))?;
            file.write_all(&body).map_err(|e| os("write-body", e))?;
            file.sync_all().map_err(|e| os("sync-pending", e))?;
            self.fence()?;
            if path_id(&path, false, "pending-before-publish")? != temp_id {
                return Err(failure("pending-replaced", Error::Conflict, None));
            }
            exposed = true;
            fs::rename(&path, self.directory.join(self.namespace.image()))
                .map_err(|e| os("publish-image", e))?;
            self.image = Some((file, temp_id));
            self.dir
                .sync_all()
                .map_err(|e| os("sync-published-directory", e))?;
            self.fence()?;
            let mut check = open_read(&self.directory.join(self.namespace.image()))
                .map_err(|e| os("readback-open", e))?;
            if metadata(&check, false, "readback-policy")? != temp_id {
                return Err(failure("readback-replaced", Error::Conflict, None));
            }
            let (generation, check_body) = self.read_image(&mut check)?;
            if generation != next || check_body.as_slice() != body.as_slice() {
                return Err(failure("readback-mismatch", Error::Storage, None));
            }
            self.fence()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.generation = next;
                Ok(Committed {
                    namespace: self.namespace,
                    generation: next,
                })
            }
            Err(mut error) => {
                if exposed || error.reason == Error::OutcomeUnknown {
                    error.exposure = Exposure::Unknown;
                }
                if !exposed && let Some(expected) = temporary {
                    let cleanup = (|| {
                        let current =
                            path_id(&path, false, "cleanup-pending").map_err(io::Error::other)?;
                        if current != expected {
                            return Err(io::Error::other("owned pending file was replaced"));
                        }
                        fs::remove_file(&path)?;
                        self.dir.sync_all()
                    })();
                    error.cleanup = cleanup.err();
                }
                let error = Arc::new(error);
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }
}
