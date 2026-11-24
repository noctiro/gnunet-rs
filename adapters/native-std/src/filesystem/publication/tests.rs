#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions inspect real private-file publication, original-object retention and rejected namespace replacement"
)]
use super::*;
use std::{io::Read, path::PathBuf};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Scratch {
    path: PathBuf,
    directory: Directory,
}
impl Scratch {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let base = std::env::temp_dir().canonicalize()?;
        let name = format!(
            "native-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let directory = Directory::open(&base)?.create_private_directory(OsStr::new(&name))?;
        Ok(Self {
            path: base.join(name),
            directory,
        })
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        // This fixture excludes external namespace administration. Each original
        // child is opened and matched before cleanup; no recursive path removal.
        if let Ok(entries) = std::fs::read_dir(&self.path) {
            for entry in entries.flatten() {
                if let Ok(file) = self.directory.open_file(&entry.file_name()) {
                    let _removed = self.directory.remove_file(&entry.file_name(), &file);
                }
            }
        }
        let _removed = std::fs::remove_dir(&self.path);
    }
}
fn bytes(mut file: &File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
#[test]
fn replacement_keeps_the_original_read_object_and_reports_the_barrier() -> Result {
    let s = Scratch::new()?;
    let name = OsStr::new("config");
    let (old, _) =
        publish(&s.directory, name, b"old", Destination::Create, || Ok(()))?.into_parts();
    let (new, barrier) =
        publish(&s.directory, name, b"new", Destination::Replace, || Ok(()))?.into_parts();
    assert_eq!(bytes(&old)?, b"old");
    assert_eq!(bytes(&new)?, b"new");
    assert_ne!(
        filesystem::FileIdentity::of(&old)?,
        filesystem::FileIdentity::of(&new)?
    );
    assert!(s.directory.same_file(name, &new)?);
    filesystem::validate_private_file(&new)?;
    #[cfg(unix)]
    assert_eq!(barrier, DirectorySync::Synchronized);
    #[cfg(windows)]
    assert_eq!(barrier, s.directory.sync()?);
    Ok(())
}

#[test]
fn named_stage_retains_its_original_after_a_failed_replacement() -> Result {
    let s = Scratch::new()?;
    let name = OsStr::new("stage");
    let target = OsStr::new("occupied");
    let occupied = s.directory.create_private_directory(target)?;
    let mut writer = s.directory.create_private_file(name)?;
    writer.write_all(b"original")?;
    let (mut original, native) = seal(&s.directory, name, writer, 8)?.replace(target)?;
    assert!(native.is_err());
    assert!(s.directory.same_file(name, &original)?);
    assert!(s.directory.same_directory(target, &occupied)?);
    assert!(original.write(b"changed").is_err());
    assert_eq!(bytes(&original)?, b"original");
    s.directory.remove_directory(target, &occupied)?;
    Ok(())
}
#[test]
fn create_conflict_preserves_the_original_destination() -> Result {
    let s = Scratch::new()?;
    let name = OsStr::new("config");
    let (old, _) =
        publish(&s.directory, name, b"old", Destination::Create, || Ok(()))?.into_parts();
    let Err(failure) = publish(&s.directory, name, b"new", Destination::Create, || Ok(())) else {
        return Err("existing destination was replaced".into());
    };
    assert_eq!(failure.cause.kind(), io::ErrorKind::AlreadyExists);
    assert!(matches!(failure.cleanup, Cleanup::Retired));
    assert!(s.directory.same_file(name, &old)?);
    assert_eq!(bytes(&old)?, b"old");
    assert_eq!(std::fs::read_dir(&s.path)?.count(), 1);
    Ok(())
}
#[cfg(windows)]
#[test]
fn new_file_rename_refuses_the_stage_as_destination() -> Result {
    let s = Scratch::new()?;
    let source = OsStr::new("stage");
    let target = OsStr::new("config");
    let mut writer = s.directory.create_private_file(source)?;
    writer.write_all(b"original")?;
    let staged = seal(&s.directory, source, writer, 8)?;
    let error = s
        .directory
        .rename_new_file(source, &staged.file, source)
        .err()
        .ok_or("a stage was accepted as its own destination")?;
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert!(s.directory.same_file(source, &staged.file)?);

    s.directory.rename_new_file(source, &staged.file, target)?;
    assert!(
        matches!(s.directory.entry_info(source), Err(e) if e.kind() == io::ErrorKind::NotFound)
    );
    assert!(s.directory.same_file(target, &staged.file)?);
    assert_eq!(filesystem::file_links(&staged.file)?, 1);
    assert_eq!(bytes(&staged.file)?, b"original");
    Ok(())
}
#[test]
fn original_guard_refusal_prevents_publication_and_retires_the_stage() -> Result {
    let s = Scratch::new()?;
    let name = OsStr::new("config");
    let Err(failure) = publish(&s.directory, name, b"new", Destination::Replace, || {
        Err(io::ErrorKind::TimedOut.into())
    }) else {
        return Err("expired guard published".into());
    };
    assert!(!failure.may_have_published);
    assert_eq!(failure.stage, "before-publication");
    assert!(matches!(failure.cleanup, Cleanup::Retired));
    assert_eq!(std::fs::read_dir(&s.path)?.count(), 0);
    Ok(())
}
#[cfg(windows)]
#[test]
fn published_file_flush_refusal_preserves_the_replacement() -> Result {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

    let s = Scratch::new()?;
    let stage = OsStr::new("stage");
    let name = OsStr::new("config");
    let mut writer = s.directory.create_private_file(stage)?;
    writer.write_all(b"new")?;
    let (original, replacement) = seal(&s.directory, stage, writer, 3)?.replace(name)?;
    replacement?;

    // Apply both fences after the rename, which needs FILE_ADD_FILE access
    // to the directory. Only the post-publication durability barriers fail.
    let _directory_fence = Directory::open_source(&s.path)?;
    let _read_fence = File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(s.path.join(name))?;
    assert_eq!(s.directory.sync()?, crate::DirectorySync::Unavailable);
    let Err(failure) = synchronize_published(&s.directory, name, &original) else {
        return Err("publication without a successful original-file flush was acknowledged".into());
    };
    assert_eq!(failure.stage, "published-file-sync");
    assert!(failure.may_have_published);
    assert!(matches!(failure.cleanup, Cleanup::Retired));
    assert!(s.directory.same_file(name, &original)?);
    assert_eq!(bytes(&original)?, b"new");
    assert_eq!(std::fs::read_dir(&s.path)?.count(), 1);
    Ok(())
}

#[test]
fn changed_stage_is_neither_published_nor_removed_as_the_original() -> Result {
    let s = Scratch::new()?;
    let name = OsStr::new("config");
    let Err(failure) = publish(&s.directory, name, b"new", Destination::Replace, || {
        let entry = std::fs::read_dir(&s.path)?
            .next()
            .ok_or(io::ErrorKind::NotFound)??;
        std::fs::rename(entry.path(), s.path.join("original"))?;
        s.directory
            .create_private_file(&entry.file_name())?
            .write_all(b"replacement")?;
        Ok(())
    }) else {
        return Err("replacement stage was published".into());
    };
    assert!(matches!(failure.cleanup, Cleanup::Failed(_)));
    assert!(matches!(s.directory.entry_info(name), Err(e) if e.kind() == io::ErrorKind::NotFound));
    assert_eq!(std::fs::read_dir(&s.path)?.count(), 2);
    assert_eq!(std::fs::read(s.path.join("original"))?, b"new");
    Ok(())
}

#[cfg(unix)]
fn stage_writer(scratch: &Scratch, target: &OsStr) -> io::Result<File> {
    for entry in std::fs::read_dir(&scratch.path)? {
        let name = entry?.file_name();
        if name != target {
            return scratch.directory.open_file_for_update(&name);
        }
    }
    Err(io::ErrorKind::NotFound.into())
}

#[cfg(unix)]
#[test]
fn same_original_stage_modified_by_guard_never_replaces_destination() -> Result {
    let s = Scratch::new()?;
    let name = OsStr::new("config");
    let (old, _) =
        publish(&s.directory, name, b"old", Destination::Create, || Ok(()))?.into_parts();
    let Err(failure) = publish(
        &s.directory,
        name,
        b"new payload",
        Destination::Replace,
        || {
            let mut writer = stage_writer(&s, name)?;
            writer.write_all(b"bad payload")?;
            writer.set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))?;
            writer.sync_all()?;
            filesystem::close(writer)
        },
    ) else {
        return Err("modified original stage was published".into());
    };
    assert_eq!(failure.stage, "before-publication-fence");
    assert!(!failure.may_have_published);
    assert!(failure.writer_close.is_none());
    assert!(matches!(failure.cleanup, Cleanup::Retired));
    assert!(s.directory.same_file(name, &old)?);
    assert_eq!(bytes(&old)?, b"old");
    assert_eq!(std::fs::read_dir(&s.path)?.count(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn same_original_stage_made_nonprivate_by_guard_is_not_published() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new()?;
    let name = OsStr::new("config");
    let (old, _) =
        publish(&s.directory, name, b"old", Destination::Create, || Ok(()))?.into_parts();
    let Err(failure) = publish(
        &s.directory,
        name,
        b"new payload",
        Destination::Replace,
        || {
            let writer = stage_writer(&s, name)?;
            writer.set_permissions(std::fs::Permissions::from_mode(0o640))?;
            filesystem::close(writer)
        },
    ) else {
        return Err("nonprivate original stage was published".into());
    };
    assert_eq!(failure.stage, "before-publication-fence");
    assert_eq!(failure.cause.kind(), io::ErrorKind::PermissionDenied);
    assert!(!failure.may_have_published);
    assert!(failure.writer_close.is_none());
    assert!(matches!(failure.cleanup, Cleanup::Retired));
    assert!(s.directory.same_file(name, &old)?);
    assert_eq!(bytes(&old)?, b"old");
    assert_eq!(std::fs::read_dir(&s.path)?.count(), 1);
    Ok(())
}
