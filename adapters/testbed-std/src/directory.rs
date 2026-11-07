//! Marked Rust-owned directory/counter and atomic configuration publication.
//! No key, peer runtime or controller protocol is embedded in this utility.
use crate::*;
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};
const MARK: &str = ".testbed-rust-owner";
const MAGIC: &[u8] = b"GNUNET-RUST-TESTBED-DIRECTORY\nversion=1\n";
fn open(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}
fn read_small(path: &Path, max: usize) -> Result<Vec<u8>, Failure> {
    let mut file = open(path, false).map_err(|e| Failure::io("open metadata", path, e))?;
    if !file
        .metadata()
        .map_err(|e| Failure::io("metadata", path, e))?
        .is_file()
    {
        return Err(Cause::Changed.into());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(max + 1)
        .map_err(|_| Fault::Capacity)?;
    Read::by_ref(&mut file)
        .take(u64::try_from(max + 1).map_err(|_| Fault::Overflow)?)
        .read_to_end(&mut bytes)
        .map_err(|e| Failure::io("read metadata", path, e))?;
    if bytes.len() > max {
        return Err(Fault::TooLarge.into());
    }
    Ok(bytes)
}
fn create_exact(path: &Path, body: &[u8]) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| Failure::io("create owned metadata", path, e))?;
    file.write_all(body)
        .and_then(|()| file.sync_all())
        .map_err(|e| Failure::io("commit owned metadata", path, e))
}
fn sync(path: &Path) -> Result<(), Failure> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| Failure::io("sync directory", path, e))
}
/// One actual locked marked root. Drop closes the original File owner only;
/// removal is explicit and independently reported.
pub(crate) struct Directory {
    pub path: PathBuf,
    lock: File,
    dev: u64,
    ino: u64,
    temporary: u64,
    pub fenced: bool,
}
impl Directory {
    pub fn create(options: &Options, allocation: u64) -> Result<(Self, u64), Failure> {
        let (path, created) = if let Some(path) = &options.prefix {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()
                    .map_err(|e| Failure::io("current directory", path, e))?
                    .join(path)
            };
            if path.as_os_str().as_bytes().len() > options.limits.path_bytes {
                return Err(Fault::TooLarge.into());
            }
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => (path, true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (path, false),
                Err(e) => return Err(Failure::io("create prefix", path, e)),
            }
        } else {
            let label = options.label.as_os_str().as_bytes();
            if label.is_empty()
                || label == b"."
                || label == b".."
                || label.iter().any(|b| matches!(b, 0 | b'/'))
            {
                return Err(Fault::InvalidInput.into());
            }
            let mut found = None;
            for n in 0..options.limits.directory_attempts {
                let mut name = options.label.clone();
                name.push(format!("-{}-{allocation}-{n}", std::process::id()));
                let path = options.temporary_parent.join(name);
                if path.as_os_str().as_bytes().len() > options.limits.path_bytes {
                    return Err(Fault::TooLarge.into());
                }
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        found = Some(path);
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(Failure::io("create temporary directory", path, e)),
                }
            }
            (found.ok_or(Fault::Capacity)?, true)
        };
        if path.as_os_str().as_bytes().len() > options.limits.path_bytes {
            return Err(Fault::TooLarge.into());
        }
        let stat =
            fs::symlink_metadata(&path).map_err(|e| Failure::io("root metadata", &path, e))?;
        if !stat.is_dir() || stat.file_type().is_symlink() || stat.mode() & 0o077 != 0 {
            return Err(Cause::ForeignDirectory.into());
        }
        let marker = path.join(MARK);
        let mut initialized = created;
        match fs::symlink_metadata(&marker) {
            Ok(m) => {
                if !m.is_file()
                    || m.file_type().is_symlink()
                    || read_small(&marker, MAGIC.len())? != MAGIC
                {
                    return Err(Cause::ForeignDirectory.into());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if fs::read_dir(&path)
                    .map_err(|e| Failure::io("inspect empty root", &path, e))?
                    .next()
                    .is_some()
                {
                    return Err(Cause::ForeignDirectory.into());
                }
                create_exact(&marker, MAGIC)?;
                initialized = true
            }
            Err(e) => return Err(Failure::io("inspect marker", marker, e)),
        }
        let lock_path = path.join(".testbed-rust.lock");
        let lock =
            open(&lock_path, true).map_err(|e| Failure::io("open root lock", &lock_path, e))?;
        if !lock
            .metadata()
            .map_err(|e| Failure::io("root lock metadata", &lock_path, e))?
            .is_file()
        {
            return Err(Cause::Changed.into());
        }
        lock.try_lock()
            .map_err(|e| Failure::io("lock root", &lock_path, io::Error::other(e)))?;
        let directory = Self {
            path,
            lock,
            dev: stat.dev(),
            ino: stat.ino(),
            temporary: 0,
            fenced: false,
        };
        let counter = directory.path.join(".testbed-rust.counter");
        let high = if initialized {
            create_exact(&counter, b"0\n")?;
            sync(&directory.path)?;
            0
        } else {
            let bytes = read_small(&counter, 21)?;
            let digits = bytes.strip_suffix(b"\n").ok_or(Cause::Changed)?;
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return Err(Cause::Changed.into());
            }
            std::str::from_utf8(digits)
                .map_err(|_| Cause::Changed)?
                .parse::<u64>()
                .map_err(|_| Cause::Changed)?
        };
        directory.check()?;
        Ok((directory, high))
    }
    pub fn check(&self) -> Result<(), Failure> {
        if self.fenced {
            return Err(Cause::Changed.into());
        }
        self.check_identity()
    }
    fn check_identity(&self) -> Result<(), Failure> {
        let m = fs::symlink_metadata(&self.path)
            .map_err(|e| Failure::io("check owned root", &self.path, e))?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.dev() != self.dev
            || m.ino() != self.ino
            || m.mode() & 0o077 != 0
            || read_small(&self.path.join(MARK), MAGIC.len())? != MAGIC
        {
            return Err(Cause::Changed.into());
        }
        Ok(())
    }
    pub fn counter(&mut self, n: u64) -> Result<(), Failure> {
        self.check()?;
        let target = self.path.join(".testbed-rust.counter");
        let result = self.publish(&target, format!("{n}\n").as_bytes(), Replace::Allowed);
        if result.is_err() {
            self.fenced = true;
        }
        result.map(|_| ())
    }
    /// Atomic publication preserving the original installation exposure on failure.
    pub fn publish(
        &mut self,
        target: &Path,
        body: &[u8],
        replace: Replace,
    ) -> Result<Published, Failure> {
        self.check()?;
        let resolved;
        let target = if target.is_absolute() {
            target
        } else {
            resolved = std::env::current_dir()
                .map_err(|e| Failure::io("resolve publication directory", target, e))?
                .join(target);
            resolved.as_path()
        };
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let sequence = self.temporary.checked_add(1).ok_or(Fault::Overflow)?;
        self.temporary = sequence;
        let temporary = parent.join(format!(
            ".testbed-rust-{}-{}-{sequence}.new",
            std::process::id(),
            self.ino
        ));
        let mut stage = Exposure::Unchanged;
        let outcome: Result<Published, Failure> = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)
                .map_err(|e| Failure::io("create configuration stage", &temporary, e))?;
            stage = Exposure::Staged;
            file.write_all(body)
                .and_then(|()| file.sync_all())
                .map_err(|e| Failure::io("write configuration stage", &temporary, e))?;
            if replace == Replace::Allowed {
                fs::rename(&temporary, target)
                    .map_err(|e| Failure::io("install configuration", target, e))?;
                stage = Exposure::Installed
            } else {
                fs::hard_link(&temporary, target)
                    .map_err(|e| Failure::io("install new configuration", target, e))?;
                stage = Exposure::Installed;
                fs::remove_file(&temporary)
                    .map_err(|e| Failure::io("remove installed stage", &temporary, e))?;
            }
            sync(parent)?;
            Ok(Published {
                path: target.to_path_buf(),
                bytes: body.len(),
            })
        })();
        match outcome {
            Ok(v) => Ok(v),
            Err(mut failure) => {
                failure.exposure = stage;
                if stage == Exposure::Staged
                    && let Err(e) = fs::remove_file(&temporary)
                    && e.kind() != io::ErrorKind::NotFound
                {
                    failure.add(Cause::Io {
                        operation: "remove failed stage",
                        path: temporary,
                        error: e,
                    })
                }
                if stage == Exposure::Installed {
                    self.fenced = true;
                }
                Err(failure)
            }
        }
    }
    pub fn remove(self, remove_paths: bool) -> Result<Removal, Failure> {
        let path = self.path.clone();
        if !remove_paths {
            return Ok(Removal::Kept(path));
        }
        self.check_identity()?;
        fs::remove_dir_all(&path).map_err(|e| Failure::io("remove owned root", &path, e))?;
        if let Some(parent) = path.parent() {
            sync(parent)?;
        }
        Ok(Removal::Removed(path))
    }
    /// Actual original locked descriptor is kept through the last native effect.
    pub fn locked(&self) -> bool {
        self.lock.metadata().is_ok()
    }
}
