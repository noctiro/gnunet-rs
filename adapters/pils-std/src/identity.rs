//! Official raw32 initial key material and one durable, fenced writer lifetime.
//! Synchronous setup runs before the service runtime and never inside socket polling.
use gnunet_pils::MasterKey;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
type FileIdentity = (u64, u64);
fn identity(meta: &Metadata) -> FileIdentity {
    (meta.dev(), meta.ino())
}
fn private_file(meta: &Metadata, uid: u32, length: Option<u64>) -> io::Result<()> {
    if !meta.is_file() || length.is_some_and(|length| meta.len() != length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PILS object is not an exact regular file",
        ));
    }
    if meta.uid() != uid || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PILS file requires the effective owner, one link and private permissions",
        ));
    }
    Ok(())
}
fn private_directory(meta: &Metadata, uid: u32) -> io::Result<()> {
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PILS parent must be owned by the service account and not writable by other accounts",
        ));
    }
    Ok(())
}
fn fingerprint(meta: &Metadata) -> (FileIdentity, u64, i64, i64, i64, i64) {
    (
        identity(meta),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}
struct RawKey {
    file: File,
    bytes: Zeroizing<[u8; 32]>,
    identity: FileIdentity,
}
fn read_key(path: &Path, uid: u32) -> io::Result<RawKey> {
    // Check the path before opening as well: a dangling symlink is not a missing
    // key and must never select identity creation.
    let before = fs::symlink_metadata(path)?;
    private_file(&before, uid, Some(32))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    private_file(&opened, uid, Some(32))?;
    if fingerprint(&opened) != fingerprint(&before) {
        return Err(io::Error::other("PILS key changed during open"));
    }
    let mut bytes = Zeroizing::new([0; 32]);
    file.read_exact(bytes.as_mut())?;
    let mut trailing = Zeroizing::new([0; 1]);
    if file.read(trailing.as_mut())? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PILS key has trailing bytes",
        ));
    }
    let held = file.metadata()?;
    let actual = fs::symlink_metadata(path)?;
    private_file(&held, uid, Some(32))?;
    private_file(&actual, uid, Some(32))?;
    if fingerprint(&held) != fingerprint(&opened) || fingerprint(&actual) != fingerprint(&opened) {
        return Err(io::Error::other("PILS key changed during read"));
    }
    Ok(RawKey {
        file,
        bytes,
        identity: identity(&opened),
    })
}
struct Fence {
    parent: PathBuf,
    directory: File,
    directory_identity: FileIdentity,
    guard_path: PathBuf,
    guard: File,
    guard_identity: FileIdentity,
    uid: u32,
}
impl Fence {
    fn open(path: &Path) -> io::Result<(Self, PathBuf)> {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "PILS identity path has no filename",
            )
        })?;
        let requested_parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Same directory-creation policy as the common private_parents helper;
        // keep the default identity loader independent of async-runtime crates.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(requested_parent)?;
        let parent = fs::canonicalize(requested_parent)?;
        let uid = nix::unistd::geteuid().as_raw();
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&parent)?;
        let dm = directory.metadata()?;
        private_directory(&dm, uid)?;
        let path = parent.join(name);
        let mut guard_name = name.to_os_string();
        guard_name.push(".pils-lock");
        let guard_path = parent.join(guard_name);
        let guard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&guard_path)?;
        // The persistent guard is never removed or replaced. This is actual OS
        // exclusion, not a PID-file convention.
        guard.try_lock()?;
        let gm = guard.metadata()?;
        private_file(&gm, uid, None)?;
        let fence = Self {
            parent,
            directory,
            directory_identity: identity(&dm),
            guard_path,
            guard,
            guard_identity: identity(&gm),
            uid,
        };
        fence.verify()?;
        Ok((fence, path))
    }
    fn verify(&self) -> io::Result<()> {
        if nix::unistd::geteuid().as_raw() != self.uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PILS writer process identity changed",
            ));
        }
        let actual_directory = fs::symlink_metadata(&self.parent)?;
        let held_directory = self.directory.metadata()?;
        private_directory(&actual_directory, self.uid)?;
        private_directory(&held_directory, self.uid)?;
        let actual_guard = fs::symlink_metadata(&self.guard_path)?;
        let held_guard = self.guard.metadata()?;
        private_file(&actual_guard, self.uid, None)?;
        private_file(&held_guard, self.uid, None)?;
        if identity(&actual_directory) != self.directory_identity
            || identity(&held_directory) != self.directory_identity
            || identity(&actual_guard) != self.guard_identity
            || identity(&held_guard) != self.guard_identity
        {
            return Err(io::Error::other("original PILS writer fence path changed"));
        }
        Ok(())
    }
}
/// Exclusive PILS writer lease. The foreground must retain this owner until all
/// physical service streams are closed and its original key owners are dropped.
/// No Clone/Debug is provided. This fences cooperating Rust writers; callers
/// must own the namespace and exclude concurrent hostile path replacement.
pub struct KeyLease {
    key: File,
    key_path: PathBuf,
    key_identity: FileIdentity,
    fence: Fence,
}
impl KeyLease {
    /// Check original held/path directory, lock and key identities/permissions.
    /// This reads metadata only; it performs no fsync, new write or key reload.
    /// A failure must retire the original physical service before reuse.
    pub fn verify_fence(&self) -> io::Result<()> {
        self.fence.verify()?;
        let actual = fs::symlink_metadata(&self.key_path)?;
        let held = self.key.metadata()?;
        private_file(&actual, self.fence.uid, Some(32))?;
        private_file(&held, self.fence.uid, Some(32))?;
        if identity(&actual) != self.key_identity || identity(&held) != self.key_identity {
            return Err(io::Error::other("original PILS initial key path changed"));
        }
        Ok(())
    }
}
/// Load an existing official raw32 seed without creating a writer or a file.
/// Symlinks, multiple links, a different effective owner and group/other access
/// are refused. Malformed or changing files cannot silently select a new key.
pub fn load_existing(path: &Path) -> io::Result<MasterKey> {
    let raw = read_key(path, nix::unistd::geteuid().as_raw())?;
    Ok(MasterKey::from_seed(*raw.bytes))
}
/// Load or durably create the official raw32 IKM under one actual writer fence.
/// This synchronous startup boundary must precede runtime/worker construction.
/// Existing committed bytes are file/parent-synchronized and reread to settle a
/// prior interrupted directory barrier before any identity is returned. A failed
/// post-rename sync returns no key/lease; next startup reconciles that same file.
/// Existing malformed files are never replaced or treated as missing.
pub fn load_or_create(path: &Path) -> io::Result<(MasterKey, KeyLease)> {
    let (fence, path) = Fence::open(path)?;
    // Only absence at the initial lookup permits generation. An existing key
    // that disappears or becomes unreadable midway is a failed original read,
    // never permission to generate a replacement identity.
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let raw = read_key(&path, fence.uid)?;
            fence.verify()?;
            raw.file.sync_all()?;
            fence.directory.sync_all()?;
            return adopt(fence, path, raw.identity, &raw.bytes);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(io::Error::other)?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("PILS identity path lost filename"))?;
    let mut temporary_name = name.to_os_string();
    temporary_name.push(format!(".new-{:032x}", u128::from_be_bytes(random)));
    let temporary_path = fence.parent.join(temporary_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary_path)?;
    let meta = file.metadata()?;
    let mut temporary = Temporary {
        path: temporary_path,
        identity: identity(&meta),
        renamed: false,
    };
    private_file(&meta, fence.uid, Some(0))?;
    file.write_all(seed.as_ref())?;
    file.sync_all()?;
    let written = file.metadata()?;
    private_file(&written, fence.uid, Some(32))?;
    if identity(&written) != temporary.identity {
        return Err(io::Error::other("PILS temporary inode changed"));
    }
    fence.verify()?;
    let temporary_meta = fs::symlink_metadata(&temporary.path)?;
    private_file(&temporary_meta, fence.uid, Some(32))?;
    if identity(&temporary_meta) != temporary.identity {
        return Err(io::Error::other("PILS temporary path changed"));
    }
    // Exclude an already observed target. The caller owns this private writer
    // namespace; metadata/rename are not an atomic defense against that caller
    // concurrently replacing its own files or a non-cooperating historical C writer.
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "PILS initial key appeared during creation",
            ));
        }
        Err(error) => return Err(error),
    }
    fs::rename(&temporary.path, &path)?;
    temporary.renamed = true;
    // A failure from here is uncertain durability, never a usable identity.
    fence.directory.sync_all()?;
    adopt(fence, path, temporary.identity, &seed)
}
fn adopt(
    fence: Fence,
    path: PathBuf,
    expected_identity: FileIdentity,
    expected: &[u8; 32],
) -> io::Result<(MasterKey, KeyLease)> {
    fence.verify()?;
    let raw = read_key(&path, fence.uid)?;
    if raw.identity != expected_identity || raw.bytes.as_ref() != expected {
        return Err(io::Error::other(
            "PILS synchronized original key readback changed",
        ));
    }
    let key = MasterKey::from_seed(*raw.bytes);
    let lease = KeyLease {
        key: raw.file,
        key_path: path,
        key_identity: raw.identity,
        fence,
    };
    lease.verify_fence()?;
    Ok((key, lease))
}
struct Temporary {
    path: PathBuf,
    identity: FileIdentity,
    renamed: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if self.renamed {
            return;
        }
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && meta.is_file()
            && identity(&meta) == self.identity
        {
            let _cleanup = fs::remove_file(&self.path);
        }
    }
}
