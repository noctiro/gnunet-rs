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
    assert_eq!(barrier, DirectorySync::Unavailable);
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
