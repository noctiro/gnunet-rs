use super::{Cause, Limits};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Directory {
    path: PathBuf,
    dev: u64,
    ino: u64,
    verified: bool,
}
fn serial() -> Result<u64, Cause> {
    for _ in 0..32 {
        let n = NEXT.load(Ordering::Relaxed);
        let next = n.checked_add(1).ok_or(Cause::Limit)?;
        if NEXT
            .compare_exchange(n, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(next);
        }
    }
    Err(Cause::Limit)
}
impl Directory {
    pub(super) fn create(root: &Path, owner: &mut Option<Self>) -> Result<(), Cause> {
        if owner.is_some() {
            return Err(Cause::Input);
        }
        let root_meta = fs::symlink_metadata(root)?;
        if !root_meta.is_dir() {
            return Err(Cause::Input);
        }
        for _ in 0..32 {
            let path = root.join(format!("gnunet-bcd-{}-{}", std::process::id(), serial()?));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    // Retain the successful mkdir fact before fallible metadata.
                    // Failure leaves an explicit unknown directory owner; it is
                    // never silently dropped or used to delete a replacement.
                    *owner = Some(Self {
                        path,
                        dev: 0,
                        ino: 0,
                        verified: false,
                    });
                    let created = owner.as_mut().ok_or(Cause::Artifact)?;
                    let meta = fs::symlink_metadata(&created.path)?;
                    if !meta.is_dir() || meta.mode() & 0o077 != 0 {
                        return Err(Cause::Input);
                    }
                    created.dev = meta.dev();
                    created.ino = meta.ino();
                    created.verified = true;
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(Cause::Limit)
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn check(&self) -> Result<(), Cause> {
        if !self.verified {
            return Err(Cause::Artifact);
        }
        let m = fs::symlink_metadata(&self.path)?;
        if !m.is_dir() || m.dev() != self.dev || m.ino() != self.ino || m.mode() & 0o077 != 0 {
            return Err(Cause::Input);
        }
        Ok(())
    }
    fn new_file(&self, name: &str) -> Result<File, Cause> {
        self.check()?;
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.join(name))?)
    }
    pub(super) fn write(
        &self,
        bytes: &[u8],
        mut guard: impl FnMut() -> Result<(), Cause>,
    ) -> Result<(), Cause> {
        self.write_parts("document.tex", &[bytes], &mut guard)
    }
    pub(super) fn write_uri(
        &self,
        uri: &[u8],
        mut guard: impl FnMut() -> Result<(), Cause>,
    ) -> Result<(), Cause> {
        self.write_parts("uri.txt", &[uri, b"X"], &mut guard)
    }
    fn write_parts(
        &self,
        name: &str,
        parts: &[&[u8]],
        guard: &mut impl FnMut() -> Result<(), Cause>,
    ) -> Result<(), Cause> {
        guard()?;
        let mut file = self.new_file(name)?;
        for bytes in parts {
            let mut at = 0;
            while at < bytes.len() {
                guard()?;
                let n = file.write(&bytes[at..bytes.len().min(at + 4096)])?;
                if n == 0 {
                    return Err(Cause::Io(std::io::Error::other(
                        "zero renderer input write",
                    )));
                }
                at += n;
            }
        }
        guard()?;
        file.flush()?;
        Ok(())
    }
    pub(super) fn logs(&self, png: bool) -> Result<(File, File), Cause> {
        Ok((
            self.new_file(if png { "gs.stdout" } else { "tex.stdout" })?,
            self.new_file(if png { "gs.stderr" } else { "tex.stderr" })?,
        ))
    }
    pub(super) fn budget(&self, limits: Limits) -> Result<(), Cause> {
        self.check()?;
        let mut files = 0usize;
        let mut bytes = 0u64;
        for entry in fs::read_dir(&self.path)? {
            files = files.checked_add(1).ok_or(Cause::Limit)?;
            if files > limits.work_files {
                return Err(Cause::Limit);
            }
            let entry = entry?;
            let m = fs::symlink_metadata(entry.path())?;
            if !m.is_file() || m.nlink() != 1 {
                return Err(Cause::Artifact);
            }
            bytes = bytes.checked_add(m.len()).ok_or(Cause::Limit)?;
            let name = entry.file_name();
            let log = name.to_str().is_some_and(|n| {
                n.ends_with(".stdout") || n.ends_with(".stderr") || n.ends_with(".log")
            });
            if bytes > limits.work_bytes as u64 || (log && m.len() > limits.log_bytes as u64) {
                return Err(Cause::Limit);
            }
        }
        Ok(())
    }
    pub(super) fn artifact(
        &self,
        png: bool,
        maximum: usize,
        mut guard: impl FnMut() -> Result<(), Cause>,
    ) -> Result<Vec<u8>, Cause> {
        guard()?;
        self.check()?;
        let path = self
            .path
            .join(if png { "gns-bcd.png" } else { "gns-bcd.pdf" });
        let observed = fs::symlink_metadata(&path)?;
        if !observed.is_file() || observed.nlink() != 1 {
            return Err(Cause::Artifact);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let actual = file.metadata()?;
        if observed.dev() != actual.dev()
            || observed.ino() != actual.ino()
            || !actual.is_file()
            || actual.nlink() != 1
        {
            return Err(Cause::Artifact);
        }
        let len = usize::try_from(actual.len()).map_err(|_| Cause::Limit)?;
        if len == 0 || len > maximum {
            return Err(Cause::Limit);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| Cause::Limit)?;
        if bytes.capacity() > maximum {
            return Err(Cause::Limit);
        }
        bytes.resize(len, 0);
        let mut at = 0;
        while at < len {
            guard()?;
            let n = file.read(&mut bytes[at..len.min(at + 4096)])?;
            if n == 0 {
                return Err(Cause::Artifact);
            }
            at += n;
        }
        guard()?;
        let valid = if png {
            bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.ends_with(b"\0\0\0\0IEND\xaeB`\x82")
        } else {
            bytes.starts_with(b"%PDF-")
                && bytes[len.saturating_sub(1024)..]
                    .windows(5)
                    .any(|v| v == b"%%EOF")
        };
        if !valid {
            return Err(Cause::Artifact);
        }
        Ok(bytes)
    }
    /// Only after actual child reaping. No recursive traversal or foreign path.
    pub(super) fn remove(&self, maximum: usize) -> Result<(), Cause> {
        self.check()?;
        let mut count = 0;
        for entry in fs::read_dir(&self.path)? {
            count += 1;
            if count > maximum {
                return Err(Cause::Limit);
            }
            self.check()?;
            let entry = entry?;
            if fs::symlink_metadata(entry.path())?.is_dir() {
                return Err(Cause::Artifact);
            }
            fs::remove_file(entry.path())?;
        }
        self.check()?;
        fs::remove_dir(&self.path)?;
        Ok(())
    }
}
