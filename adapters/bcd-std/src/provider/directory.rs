//! Private job files selected through held original native directory objects.
use super::{Cause, Limits};
use gnunet_native::filesystem::{
    self, Directory as NativeDirectory, EntryInfo, FileIdentity, FileInfo,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Directory {
    root: NativeDirectory,
    name: OsString,
    path: PathBuf,
    original: Option<NativeDirectory>,
}
fn observe(file: &File) -> Result<FileInfo, Cause> {
    match filesystem::file_info(file)? {
        EntryInfo::File(info) if filesystem::file_links(file)? == 1 => Ok(info),
        _ => Err(Cause::Artifact),
    }
}
impl Directory {
    pub(super) fn create(root: &Path, owner: &mut Option<Self>) -> Result<(), Cause> {
        if owner.is_some() {
            return Err(Cause::Input);
        }
        let parent = NativeDirectory::open(root)?;
        for _ in 0..32 {
            let serial = NEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| Cause::Limit)?;
            let name = OsString::from(format!("gnunet-bcd-{}-{serial}", std::process::id()));
            let result = parent.create_private_directory(&name);
            if result
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::AlreadyExists)
            {
                continue;
            }
            // Any error beyond creation can leave an unqualified effect. Keep
            // its selected name in the job report without inventing a handle.
            *owner = Some(Self {
                root: parent,
                path: root.join(&name),
                name,
                original: None,
            });
            let created = owner.as_mut().ok_or(Cause::Artifact)?;
            created.original = Some(result?);
            created.check()?;
            return Ok(());
        }
        Err(Cause::Limit)
    }
    fn native(&self) -> Result<&NativeDirectory, Cause> {
        self.original.as_ref().ok_or(Cause::Artifact)
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn check(&self) -> Result<(), Cause> {
        let directory = self.native()?;
        directory.validate_private()?;
        if !matches!(self.root.entry_info(&self.name)?, EntryInfo::Directory(info)
            if info.identity == FileIdentity::of(directory.as_file())?)
        {
            return Err(Cause::Artifact);
        }
        let selected = NativeDirectory::open(&self.path)?;
        if FileIdentity::of(selected.as_file())? != FileIdentity::of(directory.as_file())? {
            return Err(Cause::Artifact);
        }
        Ok(())
    }
    fn new_file(&self, name: &str) -> Result<File, Cause> {
        self.check()?;
        Ok(self.native()?.create_private_file(OsStr::new(name))?)
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
        let result = (|| {
            for bytes in parts {
                let mut at = 0;
                while at < bytes.len() {
                    guard()?;
                    let n = file.write(&bytes[at..bytes.len().min(at + 4096)])?;
                    if n == 0 {
                        return Err(Cause::Io(io::ErrorKind::WriteZero.into()));
                    }
                    at += n;
                }
            }
            guard()?;
            file.flush()?;
            Ok::<_, Cause>(())
        })();
        let close = filesystem::close(file);
        match (result, close) {
            (Err(original), Err(close)) => Err(Cause::FileClose {
                original: Box::new(original),
                close,
            }),
            (Err(original), Ok(())) => Err(original),
            (Ok(()), Err(error)) => Err(error.into()),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
    pub(super) fn logs(&self, png: bool) -> Result<(File, File), Cause> {
        Ok((
            self.new_file(if png { "gs.stdout" } else { "tex.stdout" })?,
            self.new_file(if png { "gs.stderr" } else { "tex.stderr" })?,
        ))
    }
    pub(super) fn budget(&self, limits: Limits) -> Result<(), Cause> {
        self.check()?;
        let directory = self.native()?;
        let mut count = 0usize;
        let mut bytes = 0u64;
        for name in directory.entries()? {
            let name = name?;
            count = count.checked_add(1).ok_or(Cause::Limit)?;
            if count > limits.work_files {
                return Err(Cause::Limit);
            }
            let file = directory.open_file(&name)?;
            let info = observe(&file)?;
            if !matches!(directory.entry_info(&name)?, EntryInfo::File(named) if named.identity == info.identity)
            {
                return Err(Cause::Artifact);
            }
            bytes = bytes.checked_add(info.bytes).ok_or(Cause::Limit)?;
            let log = name.to_str().is_some_and(|name| {
                name.ends_with(".stdout") || name.ends_with(".stderr") || name.ends_with(".log")
            });
            if bytes > limits.work_bytes as u64 || log && info.bytes > limits.log_bytes as u64 {
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
        let directory = self.native()?;
        let name = OsStr::new(if png { "gns-bcd.png" } else { "gns-bcd.pdf" });
        let mut file = directory.open_file(name)?;
        let before = observe(&file)?;
        if directory.entry_info(name)? != EntryInfo::File(before) {
            return Err(Cause::Artifact);
        }
        let len = usize::try_from(before.bytes).map_err(|_| Cause::Limit)?;
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
        if observe(&file)? != before || directory.entry_info(name)? != EntryInfo::File(before) {
            return Err(Cause::Artifact);
        }
        let mut extra = [0];
        if file.read(&mut extra)? != 0 {
            return Err(Cause::Artifact);
        }
        filesystem::close(file)?;
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
    /// Only the original job directory may be removed after actual child reaping.
    pub(super) fn remove(&self, maximum: usize) -> Result<(), Cause> {
        let directory = self.native()?;
        directory.validate_private()?;
        let mut count = 0usize;
        for name in directory.entries()? {
            count = count.checked_add(1).ok_or(Cause::Limit)?;
            if count > maximum {
                return Err(Cause::Limit);
            }
            let name = name?;
            let file = directory.open_file(&name)?;
            observe(&file)?;
            directory.remove_file(&name, &file)?;
        }
        self.root.remove_directory(&self.name, directory)?;
        Ok(())
    }
}
