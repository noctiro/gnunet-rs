//! Actual original-object reads and Windows read-only view lifetimes.
#![cfg(any(unix, windows))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native regressions assert independent original-object, cursor and lifetime observations"
)]
use gnunet_native::filesystem::{
    Directory, ExclusiveFile, FileIdentity, FileReader, file_links, private_single_file_identity,
    validate_readonly,
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn prepared_directory_publication_refuses_existing_and_changed_names() -> Result {
    let scratch = Scratch::create()?;
    let parent = Directory::open(&scratch.0)?;
    let source = parent.create_private_directory(OsStr::new("stage"))?;
    let destination = parent.create_private_directory(OsStr::new("selected"))?;
    let error = parent
        .publish_directory(OsStr::new("stage"), &source, OsStr::new("selected"))
        .err()
        .ok_or("existing directory must never be replaced")?;
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert!(parent.same_directory(OsStr::new("stage"), &source)?);
    assert!(parent.same_directory(OsStr::new("selected"), &destination)?);
    parent.remove_directory(OsStr::new("selected"), &destination)?;
    parent.publish_directory(OsStr::new("stage"), &source, OsStr::new("selected"))?;
    assert!(parent.same_directory(OsStr::new("selected"), &source)?);
    let foreign = parent.create_private_directory(OsStr::new("stage"))?;
    assert!(
        parent
            .remove_directory(OsStr::new("stage"), &source)
            .is_err()
    );
    assert!(
        parent
            .publish_directory(OsStr::new("stage"), &source, OsStr::new("next"))
            .is_err()
    );
    assert!(parent.same_directory(OsStr::new("stage"), &foreign)?);
    let file = source.create_private_file(OsStr::new("marker"))?;
    assert!(
        parent
            .remove_directory(OsStr::new("selected"), &source)
            .is_err()
    );
    source.remove_file(OsStr::new("marker"), &file)?;
    parent.remove_directory(OsStr::new("selected"), &source)?;
    Ok(())
}

#[test]
fn atomic_replacement_retains_old_readers_and_refuses_a_foreign_source_name() -> Result {
    let scratch = Scratch::create()?;
    let directory = Directory::open(&scratch.0)?;
    let mut old = directory.create_private_file(OsStr::new("image"))?;
    old.write_all(b"old bytes")?;
    old.sync_all()?;
    let reader = FileReader::from_file(&old)?;
    let mut next = directory.create_private_file(OsStr::new("next"))?;
    next.write_all(b"new bytes")?;
    next.sync_all()?;
    directory.replace_file(OsStr::new("next"), &next, OsStr::new("image"))?;
    assert!(!scratch.0.join("next").exists());
    assert_eq!(fs::read(scratch.0.join("image"))?, b"new bytes");
    let mut bytes = [0; 9];
    reader.read_exact_at(&mut bytes, 0)?;
    assert_eq!(&bytes, b"old bytes");
    assert!(directory.same_file(OsStr::new("image"), &next)?);
    let mut pending = directory.create_private_file(OsStr::new("next"))?;
    pending.write_all(b"original source")?;
    fs::rename(scratch.0.join("next"), scratch.0.join("held"))?;
    fs::write(scratch.0.join("next"), b"foreign source")?;
    assert!(
        directory
            .replace_file(OsStr::new("next"), &pending, OsStr::new("image"))
            .is_err()
    );
    assert_eq!(fs::read(scratch.0.join("image"))?, b"new bytes");
    assert_eq!(fs::read(scratch.0.join("next"))?, b"foreign source");
    assert_eq!(fs::read(scratch.0.join("held"))?, b"original source");
    Ok(())
}
struct Scratch(PathBuf);
impl Scratch {
    fn create() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "gnunet-native-file-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let temporary = std::env::temp_dir();
        let parent = Directory::open(&temporary)?;
        drop(parent.create_private_directory(OsStr::new(&name))?);
        Ok(Self(temporary.join(name)))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn positional_reads_retain_the_original_object_and_do_not_move_the_callers_cursor() -> Result {
    let scratch = Scratch::create()?;
    let directory = Directory::open(&scratch.0)?;
    let mut writer = directory.create_private_file(OsStr::new("source"))?;
    writer.write_all(b"original bytes")?;
    assert!(validate_readonly(&writer).is_err());
    drop(writer);
    let source = File::open(scratch.0.join("source"))?;
    validate_readonly(&source)?;
    let mut cursor = &source;
    cursor.seek(SeekFrom::Start(5))?;
    let identity = FileIdentity::of(&source)?;
    let reader = FileReader::from_file(&source)?;
    let mut output = [0; 8];
    assert_eq!(reader.read_at(&mut output, 0)?, 8);
    assert_eq!(&output, b"original");
    reader.read_exact_at(&mut output, 1)?;
    assert_eq!(&output, b"riginal ");
    assert_eq!(
        reader
            .read_exact_at(&mut output, 12)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    assert_eq!(cursor.stream_position()?, 5);
    fs::rename(scratch.0.join("source"), scratch.0.join("retained"))?;
    fs::write(scratch.0.join("source"), b"foreign!")?;
    assert_eq!(reader.read_at(&mut output, 0)?, 8);
    assert_eq!(&output, b"original");
    assert_eq!(cursor.stream_position()?, 5);
    assert_eq!(FileIdentity::of(&source)?, identity);
    assert_ne!(
        FileIdentity::of(&File::open(scratch.0.join("source"))?)?,
        identity
    );
    Ok(())
}

#[test]
fn private_file_identity_refuses_hard_link_aliases_and_native_lock_release_is_observable() -> Result
{
    let scratch = Scratch::create()?;
    let directory = Directory::open(&scratch.0)?;
    let file = directory.create_private_file(OsStr::new("lock"))?;
    let original = private_single_file_identity(&file)?;
    assert_eq!(file_links(&file)?, 1);
    fs::hard_link(scratch.0.join("lock"), scratch.0.join("alias"))?;
    assert_eq!(file_links(&file)?, 2);
    assert!(private_single_file_identity(&file).is_err());
    fs::remove_file(scratch.0.join("alias"))?;
    assert_eq!(private_single_file_identity(&file)?, original);
    let owner = ExclusiveFile::try_lock(file)?;
    let contender = directory.open_file_for_update(OsStr::new("lock"))?;
    assert!(matches!(
        ExclusiveFile::try_lock(contender),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(owner);
    let next = ExclusiveFile::try_lock(directory.open_file_for_update(OsStr::new("lock"))?)?;
    assert_eq!(FileIdentity::of(next.as_file())?, original);
    Ok(())
}
#[cfg(windows)]
#[test]
fn mutation_directories_and_source_sharing_fences_have_distinct_native_roles() -> Result {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    let scratch = Scratch::create()?;
    let mutation = Directory::open(&scratch.0)?;
    let writer = || {
        File::options()
            .access_mode(FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&scratch.0)
    };
    let opened = writer()?;
    assert!(Directory::open_source(&scratch.0).is_err());
    drop(opened);
    let source = Directory::open_source(&scratch.0)?;
    assert!(writer().is_err());
    assert_eq!(
        FileIdentity::of(source.as_file())?,
        FileIdentity::of(mutation.as_file())?
    );
    drop(source);
    drop(writer()?);
    Ok(())
}

#[cfg(windows)]
#[test]
#[expect(
    unsafe_code,
    reason = "The test owns an unchanged private ordinary file and retains its successful read-only view through the bounded raw copy"
)]
fn read_only_mapping_pins_the_original_extent_and_releases_it_explicitly() -> Result {
    use gnunet_native::filesystem::ReadMapping;
    let scratch = Scratch::create()?;
    let directory = Directory::open(&scratch.0)?;
    let mut writer = directory.create_private_file(OsStr::new("mapped"))?;
    writer.write_all(b"payload")?;
    let source = directory.open_file(OsStr::new("mapped"))?;
    assert!(ReadMapping::open(&writer, 7).is_err());
    assert!(ReadMapping::open(&source, 8).is_err());
    let mut mapping = ReadMapping::open(&source, 7)?;
    assert_eq!(mapping.len(), 7);
    let mut output = [0; 7];
    // SAFETY: this private unchanged mapping retains exactly seven readable
    // bytes; destination is a separate initialized seven-byte allocation.
    unsafe {
        std::ptr::copy_nonoverlapping(
            mapping.as_ptr()?.cast::<u8>(),
            output.as_mut_ptr(),
            output.len(),
        );
    }
    assert_eq!(&output, b"payload");
    assert!(writer.set_len(0).is_err());
    assert_eq!(source.metadata()?.len(), 7);
    assert!(mapping.close()?);
    assert!(!mapping.close()?);
    assert!(mapping.as_ptr().is_err());
    writer.set_len(0)?;
    let mut empty = ReadMapping::open(&source, 0)?;
    assert!(empty.is_empty());
    assert!(!empty.as_ptr()?.is_null());
    assert!(empty.close()?);
    Ok(())
}
