//! Anchored native files and the original cross-process writer fence.
use super::Error;
use gnunet_crypto::Hash256State;
use gnunet_types::Error as ProtocolError;
use nix::{
    errno::Errno,
    fcntl::{AtFlags, OFlag, open, openat, renameat},
    sys::stat::{Mode, mkdirat},
    unistd::{UnlinkatFlags, linkat, unlinkat},
};
use std::{
    fs::{self, File, Metadata, TryLockError},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
pub(super) const WAL: &str = "transactions.wal";
pub(super) const SNAPSHOT: &str = "index.snapshot";
const LOCK: &str = ".writer.lock";
const VALUES: &str = "values";
const DIRECTORY: OFlag = OFlag::from_bits_retain(
    OFlag::O_RDONLY.bits()
        | OFlag::O_DIRECTORY.bits()
        | OFlag::O_NOFOLLOW.bits()
        | OFlag::O_CLOEXEC.bits(),
);
const READ: OFlag = OFlag::from_bits_retain(
    OFlag::O_RDONLY.bits()
        | OFlag::O_NOFOLLOW.bits()
        | OFlag::O_NONBLOCK.bits()
        | OFlag::O_CLOEXEC.bits(),
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Inode {
    dev: u64,
    ino: u64,
}
impl Inode {
    fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
        }
    }
}
pub(super) struct Files {
    path: PathBuf,
    pub(super) root: File,
    pub(super) values: File,
    pub(super) wal: File,
    lock: File,
    root_id: Inode,
    values_id: Inode,
    wal_id: Inode,
    lock_id: Inode,
    pub(super) snapshot_id: Option<Inode>,
    snapshot_candidate: Option<Inode>,
    garbage: Option<fs::ReadDir>,
    garbage_root: Option<fs::ReadDir>,
    garbage_values_done: bool,
    nonce: u64,
}
impl Files {
    pub(super) fn open(path: &Path) -> Result<Self, Error> {
        let name = path
            .file_name()
            .ok_or_else(|| Error::protocol("root-name", ProtocolError::InvalidInput))?;
        let parent = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .map_err(|e| Error::io("root-parent", e))?;
        let parent_file = File::from(
            open(&parent, DIRECTORY, Mode::empty())
                .map_err(|e| Error::io("root-parent-open", e.into()))?,
        );
        match mkdirat(&parent_file, name, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(Error::io("root-create", e.into())),
        }
        let root = File::from(
            openat(&parent_file, name, DIRECTORY, Mode::empty())
                .map_err(|e| Error::io("root-open", e.into()))?,
        );
        let path = parent.join(name);
        let lock = File::from(
            openat(
                &root,
                LOCK,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_NONBLOCK
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(|e| Error::io("writer-open", e.into()))?,
        );
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::protocol("writer-busy", ProtocolError::Conflict));
            }
            Err(TryLockError::Error(error)) => return Err(Error::io("writer-lock", error)),
        }
        let lock_meta = lock
            .metadata()
            .map_err(|e| Error::io("writer-metadata", e))?;
        if !lock_meta.is_file() || lock_meta.nlink() != 1 {
            return Err(Error::protocol("writer-kind", ProtocolError::Conflict));
        }
        ensure_format(&root, &path)?;
        match mkdirat(&root, VALUES, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(Error::io("values-create", e.into())),
        }
        let values = File::from(
            openat(&root, VALUES, DIRECTORY, Mode::empty())
                .map_err(|e| Error::io("values-open", e.into()))?,
        );
        let wal = File::from(
            openat(
                &root,
                WAL,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_NONBLOCK
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(|e| Error::io("wal-open", e.into()))?,
        );
        let wal_meta = wal.metadata().map_err(|e| Error::io("wal-metadata", e))?;
        if !wal_meta.is_file() || wal_meta.nlink() != 1 {
            return Err(Error::protocol("wal-kind", ProtocolError::InvalidInput));
        }
        root.sync_all().map_err(|e| Error::io("root-sync", e))?;
        parent_file
            .sync_all()
            .map_err(|e| Error::io("root-parent-sync", e))?;
        let root_id = Inode::of(&root.metadata().map_err(|e| Error::io("root-metadata", e))?);
        let values_id = Inode::of(
            &values
                .metadata()
                .map_err(|e| Error::io("values-metadata", e))?,
        );
        let mut files = Self {
            path,
            root,
            values,
            wal,
            lock,
            root_id,
            values_id,
            wal_id: Inode::of(&wal_meta),
            lock_id: Inode::of(&lock_meta),
            snapshot_id: None,
            snapshot_candidate: None,
            garbage: None,
            garbage_root: None,
            garbage_values_done: false,
            nonce: 0,
        };
        files.snapshot_id = files
            .snapshot()?
            .map(|file| {
                file.metadata()
                    .map(|m| Inode::of(&m))
                    .map_err(|e| Error::io("snapshot-metadata", e))
            })
            .transpose()?;
        files.verify()?;
        Ok(files)
    }
    pub(super) fn verify(&self) -> Result<(), Error> {
        let root = fs::symlink_metadata(&self.path).map_err(|e| Error::io("root-authority", e))?;
        if !root.is_dir()
            || root.file_type().is_symlink()
            || Inode::of(&root) != self.root_id
            || Inode::of(
                &self
                    .root
                    .metadata()
                    .map_err(|e| Error::io("held-root", e))?,
            ) != self.root_id
            || Inode::of(
                &self
                    .lock
                    .metadata()
                    .map_err(|e| Error::io("held-lock", e))?,
            ) != self.lock_id
        {
            return Err(Error::protocol(
                "physical-authority",
                ProtocolError::Conflict,
            ));
        }
        for (name, flags, expected) in [
            (LOCK, READ, self.lock_id),
            (WAL, READ, self.wal_id),
            (VALUES, DIRECTORY, self.values_id),
        ] {
            let file = File::from(
                openat(&self.root, name, flags, Mode::empty())
                    .map_err(|e| Error::io("named-authority", e.into()))?,
            );
            if Inode::of(
                &file
                    .metadata()
                    .map_err(|e| Error::io("named-authority-metadata", e))?,
            ) != expected
            {
                return Err(Error::protocol("named-authority", ProtocolError::Conflict));
            }
        }
        let snapshot = self
            .snapshot()?
            .map(|file| {
                file.metadata()
                    .map(|m| Inode::of(&m))
                    .map_err(|e| Error::io("snapshot-authority-metadata", e))
            })
            .transpose()?;
        if snapshot != self.snapshot_id
            && !self
                .snapshot_candidate
                .is_some_and(|candidate| snapshot == Some(candidate))
        {
            return Err(Error::protocol(
                "snapshot-authority",
                ProtocolError::Conflict,
            ));
        }
        Ok(())
    }
    pub(super) fn snapshot(&self) -> Result<Option<File>, Error> {
        match openat(&self.root, SNAPSHOT, READ, Mode::empty()) {
            Ok(fd) => {
                let file = File::from(fd);
                if !file
                    .metadata()
                    .map_err(|e| Error::io("snapshot-kind", e))?
                    .is_file()
                {
                    return Err(Error::protocol("snapshot-kind", ProtocolError::Malformed));
                }
                Ok(Some(file))
            }
            Err(Errno::ENOENT) => Ok(None),
            Err(e) => Err(Error::io("snapshot-open", e.into())),
        }
    }
    pub(super) fn temporary(&mut self, values: bool) -> Result<Temporary, Error> {
        let directory = if values { &self.values } else { &self.root };
        let directory = directory
            .try_clone()
            .map_err(|e| Error::io("temporary-directory", e))?;
        for _ in 0..1024 {
            let nonce = self.nonce;
            self.nonce = nonce
                .checked_add(1)
                .ok_or_else(|| Error::protocol("temporary-sequence", ProtocolError::Overflow))?;
            let name = format!(".tmp-{}-{nonce}", std::process::id());
            match openat(
                &directory,
                name.as_str(),
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            ) {
                Ok(fd) => {
                    let file = File::from(fd);
                    let inode = Inode::of(
                        &file
                            .metadata()
                            .map_err(|e| Error::io("temporary-metadata", e))?,
                    );
                    return Ok(Temporary {
                        directory,
                        name,
                        file,
                        inode,
                        published: false,
                    });
                }
                Err(Errno::EEXIST) => {}
                Err(e) => return Err(Error::io("temporary-open", e.into())),
            }
        }
        Err(Error::protocol(
            "temporary-collisions",
            ProtocolError::Capacity,
        ))
    }
    pub(super) fn install_snapshot(&mut self, temporary: &mut Temporary) -> Result<(), Error> {
        temporary.verify_snapshot()?;
        self.snapshot_candidate = Some(temporary.inode);
        renameat(&self.root, temporary.name.as_str(), &self.root, SNAPSHOT)
            .map_err(|e| Error::io("snapshot-rename", e.into()))?;
        temporary.published = true;
        let installed = self.snapshot()?.ok_or_else(|| {
            Error::protocol("installed-snapshot-missing", ProtocolError::Conflict)
        })?;
        let metadata = installed
            .metadata()
            .map_err(|error| Error::io("installed-snapshot-metadata", error))?;
        if !metadata.is_file() || metadata.nlink() != 1 || Inode::of(&metadata) != temporary.inode {
            return Err(Error::protocol(
                "installed-snapshot-authority",
                ProtocolError::Conflict,
            ));
        }
        self.snapshot_id = Some(temporary.inode);
        self.root
            .sync_all()
            .map_err(|e| Error::io("snapshot-directory-sync", e))?;
        self.snapshot_candidate = None;
        Ok(())
    }
    pub(super) fn adopt_snapshot(&mut self) -> Result<(), Error> {
        self.snapshot_id = self
            .snapshot()?
            .map(|file| {
                file.metadata()
                    .map(|meta| Inode::of(&meta))
                    .map_err(|e| Error::io("settled-snapshot-metadata", e))
            })
            .transpose()?;
        self.snapshot_candidate = None;
        Ok(())
    }
    pub(super) fn check_object(&self, uid: u64, length: u64) -> Result<(), Error> {
        self.object(uid, length).map(|_| ())
    }
    pub(super) fn put_object(&mut self, uid: u64, value: &[u8]) -> Result<(), Error> {
        let mut temporary = self.temporary(true)?;
        for chunk in value.chunks(8192) {
            temporary
                .file
                .write_all(chunk)
                .map_err(|e| Error::io("value-write", e))?;
        }
        temporary
            .file
            .sync_all()
            .map_err(|e| Error::io("value-sync", e))?;
        let name = object_name(uid);
        match linkat(
            &self.values,
            temporary.name.as_str(),
            &self.values,
            name.as_slice(),
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(Errno::EEXIST) => {
                return Err(Error::protocol(
                    "unreferenced-value-collision",
                    ProtocolError::Conflict,
                ));
            }
            Err(e) => return Err(Error::io("value-link", e.into())),
        }
        self.values
            .sync_all()
            .map_err(|e| Error::io("value-directory-sync", e))?;
        temporary.remove()?;
        self.values
            .sync_all()
            .map_err(|e| Error::io("value-temporary-sync", e))?;
        Ok(())
    }
    pub(super) fn read_object(
        &self,
        uid: u64,
        length: u64,
        digest: &[u8; 32],
        output: &mut [u8],
    ) -> Result<(), Error> {
        if output.len() as u64 != length {
            return Err(Error::protocol("value-output", ProtocolError::Capacity));
        }
        let mut file = self.object(uid, length)?;
        let mut hash = Hash256State::new();
        let result = (|| {
            for chunk in output.chunks_mut(8192) {
                file.read_exact(chunk)
                    .map_err(|error| Error::io("value-read", error))?;
                hash.update(chunk);
            }
            if hash.finish() != *digest {
                return Err(Error::protocol(
                    "value-checksum",
                    ProtocolError::Authentication,
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            output.fill(0);
        }
        result
    }
    pub(super) fn equals_object(
        &self,
        uid: u64,
        value: &[u8],
        digest: &[u8; 32],
    ) -> Result<bool, Error> {
        let mut file = self.object(uid, value.len() as u64)?;
        let mut scratch = [0; 8192];
        let mut hash = Hash256State::new();
        let mut equal = true;
        for chunk in value.chunks(scratch.len()) {
            file.read_exact(&mut scratch[..chunk.len()])
                .map_err(|e| Error::io("value-compare", e))?;
            hash.update(&scratch[..chunk.len()]);
            equal &= scratch[..chunk.len()] == *chunk;
        }
        if hash.finish() != *digest {
            return Err(Error::protocol(
                "value-compare-checksum",
                ProtocolError::Authentication,
            ));
        }
        Ok(equal)
    }
    fn object(&self, uid: u64, length: u64) -> Result<File, Error> {
        let name = object_name(uid);
        let file = File::from(
            openat(&self.values, name.as_slice(), READ, Mode::empty())
                .map_err(|e| Error::io("value-open", e.into()))?,
        );
        let metadata = file
            .metadata()
            .map_err(|e| Error::io("value-metadata", e))?;
        if !metadata.is_file() || metadata.len() != length || metadata.nlink() != 1 {
            return Err(Error::protocol("value-shape", ProtocolError::Malformed));
        }
        Ok(file)
    }
    pub(super) fn remove_object(&self, uid: u64) -> Result<(), Error> {
        match unlinkat(
            &self.values,
            object_name(uid).as_slice(),
            UnlinkatFlags::NoRemoveDir,
        ) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(Error::io("value-cleanup", e.into())),
        }
    }
    fn remove_unreferenced(&self, uid: u64) -> Result<bool, Error> {
        // UID is absent from the authoritative metadata index. Only the internal
        // regular UID object can be removed; a symlink/directory is refused.
        match openat(
            &self.values,
            object_name(uid).as_slice(),
            READ,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                if !file
                    .metadata()
                    .map_err(|e| Error::io("orphan-kind", e))?
                    .is_file()
                {
                    return Err(Error::protocol("orphan-kind", ProtocolError::Conflict));
                }
                self.remove_object(uid).map(|()| true)
            }
            Err(Errno::ENOENT) => Ok(false),
            Err(e) => Err(Error::io("orphan-open", e.into())),
        }
    }
    pub(super) fn replace_unreferenced(&self, uid: u64) -> Result<(), Error> {
        if self.remove_unreferenced(uid)? {
            self.values
                .sync_all()
                .map_err(|error| Error::io("orphan-directory-sync", error))?;
        }
        Ok(())
    }
    pub(super) fn reset_garbage(&mut self) {
        self.garbage = None;
        self.garbage_root = None;
        self.garbage_values_done = false;
    }
    pub(super) fn collect_orphans(
        &mut self,
        live: impl Fn(u64) -> bool,
        maximum: usize,
    ) -> Result<(usize, bool), Error> {
        if maximum == 0 {
            return Err(Error::protocol(
                "garbage-budget",
                ProtocolError::InvalidInput,
            ));
        }
        let mut removed = 0;
        for _ in 0..maximum {
            let in_values = !self.garbage_values_done;
            if in_values && self.garbage.is_none() {
                self.garbage = Some(
                    fs::read_dir(self.path.join(VALUES))
                        .map_err(|e| Error::io("garbage-directory", e))?,
                );
            }
            if !in_values && self.garbage_root.is_none() {
                self.garbage_root = Some(
                    fs::read_dir(&self.path).map_err(|e| Error::io("garbage-root-directory", e))?,
                );
            }
            let next = if in_values {
                self.garbage.as_mut().and_then(Iterator::next)
            } else {
                self.garbage_root.as_mut().and_then(Iterator::next)
            };
            let Some(entry) = next else {
                if in_values {
                    self.garbage = None;
                    self.garbage_values_done = true;
                    continue;
                }
                self.garbage_root = None;
                self.garbage_values_done = false;
                if removed != 0 {
                    self.values
                        .sync_all()
                        .map_err(|e| Error::io("garbage-sync", e))?;
                    self.root
                        .sync_all()
                        .map_err(|e| Error::io("garbage-root-sync", e))?;
                }
                return Ok((removed, false));
            };
            let entry = entry.map_err(|e| Error::io("garbage-entry", e))?;
            let name = entry.file_name();
            let raw = name.as_encoded_bytes();
            if in_values && let Some(uid) = parse_object(raw) {
                if !live(uid) && self.remove_unreferenced(uid)? {
                    removed += 1;
                }
            } else if is_temporary(raw) {
                let directory = if in_values { &self.values } else { &self.root };
                let file = File::from(
                    openat(directory, raw, READ, Mode::empty())
                        .map_err(|e| Error::io("stale-temporary-open", e.into()))?,
                );
                if !file
                    .metadata()
                    .map_err(|e| Error::io("stale-temporary-metadata", e))?
                    .is_file()
                {
                    return Err(Error::protocol(
                        "stale-temporary-kind",
                        ProtocolError::Conflict,
                    ));
                }
                unlinkat(directory, raw, UnlinkatFlags::NoRemoveDir)
                    .map_err(|e| Error::io("stale-temporary-remove", e.into()))?;
                removed += 1;
            }
        }
        if removed != 0 {
            self.values
                .sync_all()
                .map_err(|e| Error::io("garbage-sync", e))?;
            self.root
                .sync_all()
                .map_err(|e| Error::io("garbage-root-sync", e))?;
        }
        Ok((removed, true))
    }
}
pub(super) struct Temporary {
    directory: File,
    name: String,
    pub(super) file: File,
    inode: Inode,
    published: bool,
}
impl Temporary {
    fn verify_snapshot(&self) -> Result<(), Error> {
        let held = self
            .file
            .metadata()
            .map_err(|error| Error::io("snapshot-held-candidate", error))?;
        let file = File::from(
            openat(&self.directory, self.name.as_str(), READ, Mode::empty())
                .map_err(|error| Error::io("snapshot-named-candidate", error.into()))?,
        );
        let named = file
            .metadata()
            .map_err(|error| Error::io("snapshot-named-candidate-metadata", error))?;
        if !held.is_file()
            || !named.is_file()
            || held.nlink() != 1
            || named.nlink() != 1
            || Inode::of(&held) != self.inode
            || Inode::of(&named) != self.inode
        {
            return Err(Error::protocol(
                "snapshot-candidate-authority",
                ProtocolError::Conflict,
            ));
        }
        Ok(())
    }
    fn remove(&mut self) -> Result<(), Error> {
        let file = File::from(
            openat(&self.directory, self.name.as_str(), READ, Mode::empty())
                .map_err(|e| Error::io("temporary-cleanup-open", e.into()))?,
        );
        if Inode::of(
            &file
                .metadata()
                .map_err(|e| Error::io("temporary-cleanup-metadata", e))?,
        ) != self.inode
        {
            return Err(Error::protocol(
                "temporary-cleanup-authority",
                ProtocolError::Conflict,
            ));
        }
        unlinkat(
            &self.directory,
            self.name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|e| Error::io("temporary-cleanup", e.into()))?;
        self.published = true;
        Ok(())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.published
            && let Ok(fd) = openat(&self.directory, self.name.as_str(), READ, Mode::empty())
        {
            let file = File::from(fd);
            if file
                .metadata()
                .is_ok_and(|m| m.is_file() && Inode::of(&m) == self.inode)
            {
                let _cleanup = unlinkat(
                    &self.directory,
                    self.name.as_str(),
                    UnlinkatFlags::NoRemoveDir,
                );
            }
        }
    }
}
fn object_name(uid: u64) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = [0; 16];
    for (position, byte) in name.iter_mut().enumerate() {
        *byte = HEX[((uid >> ((15 - position) * 4)) & 15) as usize];
    }
    name
}
fn is_temporary(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b".tmp-") else {
        return false;
    };
    let Some(split) = rest.iter().position(|b| *b == b'-') else {
        return false;
    };
    split != 0
        && split + 1 < rest.len()
        && rest[..split].iter().all(u8::is_ascii_digit)
        && rest[split + 1..].iter().all(u8::is_ascii_digit)
}
fn parse_object(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 16 {
        return None;
    }
    let mut uid = 0_u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return None,
        };
        uid = uid * 16 + u64::from(digit);
    }
    (uid != 0).then_some(uid)
}

fn ensure_format(root: &File, path: &Path) -> Result<(), Error> {
    const NAME: &str = ".format";
    const MAGIC: &[u8; 8] = b"GNDST001";
    match openat(root, NAME, READ, Mode::empty()) {
        Ok(fd) => {
            let mut file = File::from(fd);
            let meta = file
                .metadata()
                .map_err(|e| Error::io("format-metadata", e))?;
            if !meta.is_file() || meta.len() != MAGIC.len() as u64 {
                return Err(Error::protocol("format", ProtocolError::Unsupported));
            }
            let mut actual = [0; 8];
            file.read_exact(&mut actual)
                .map_err(|e| Error::io("format-read", e))?;
            if actual != *MAGIC {
                return Err(Error::protocol("format", ProtocolError::Unsupported));
            }
            Ok(())
        }
        Err(Errno::ENOENT) => {
            for entry in fs::read_dir(path).map_err(|e| Error::io("format-directory", e))? {
                let entry = entry.map_err(|e| Error::io("format-entry", e))?;
                if entry.file_name().as_encoded_bytes() != LOCK.as_bytes() {
                    return Err(Error::protocol(
                        "unrecognized-directory",
                        ProtocolError::Unsupported,
                    ));
                }
            }
            let mut file = File::from(
                openat(
                    root,
                    NAME,
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_EXCL
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                    Mode::S_IRUSR | Mode::S_IWUSR,
                )
                .map_err(|e| Error::io("format-create", e.into()))?,
            );
            file.write_all(MAGIC)
                .map_err(|e| Error::io("format-write", e))?;
            file.sync_all().map_err(|e| Error::io("format-sync", e))?;
            root.sync_all()
                .map_err(|e| Error::io("format-directory-sync", e))
        }
        Err(e) => Err(Error::io("format-open", e.into())),
    }
}
