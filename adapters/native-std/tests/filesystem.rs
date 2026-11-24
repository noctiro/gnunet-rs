//! Actual original-object reads and Windows read-only view lifetimes.
#![cfg(any(unix, windows))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native regressions assert independent original-object, cursor and lifetime observations"
)]
use gnunet_native::filesystem::{
    Directory, EntryInfo, ExclusiveFile, FileIdentity, FileInfo, FileReader, file_info, file_links,
    private_data_file_info, private_single_file_identity, publication, validate_readonly,
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
fn published_file_snapshots_stay_exact_across_native_reads_and_detect_real_changes() -> Result {
    for destination in [
        publication::Destination::Create,
        publication::Destination::Replace,
    ] {
        let scratch = Scratch::create()?;
        let directory = Directory::open(&scratch.0)?;
        let name = OsStr::new("image");
        let expected = [0x5a; 32];
        if matches!(destination, publication::Destination::Replace) {
            drop(publication::publish(
                &directory,
                name,
                &[0x27; 32],
                publication::Destination::Create,
                || Ok(()),
            )?);
        }
        let (file, barrier) =
            publication::publish(&directory, name, &expected, destination, || Ok(()))?.into_parts();
        validate_readonly(&file)?;
        let original = private_data_file_info(&file).map_err(|error| {
            io::Error::new(error.kind(), format!(
                "{destination:?} after publication: {error}; held={:?}, named={:?}, links={:?}, barrier={barrier:?}",
                file_info(&file), directory.entry_info(name), file_links(&file)
            ))
        })?;
        let stage = |label| format!("{destination:?}: {label}; barrier={barrier:?}");
        assert_published_snapshot(&directory, &file, original, &stage("published read lease"));
        let reader = FileReader::from_file(&file)?;
        assert_published_snapshot(&directory, &file, original, &stage("reader acquisition"));
        let mut bytes = [0; 32];
        reader.read_exact_at(&mut bytes, 0)?;
        assert_eq!(bytes, expected);
        assert_published_snapshot(&directory, &file, original, &stage("exact data read"));
        assert_eq!(reader.read_at(&mut [0], 32)?, 0);
        assert_published_snapshot(&directory, &file, original, &stage("EOF read"));
        drop(reader);
        directory.sync()?;
        assert_published_snapshot(&directory, &file, original, &stage("directory barrier"));

        // The immutable read phase is over. A separately opened actual writer
        // must now invalidate the same original's exact extent fence.
        let writer = directory.open_file_for_update(name)?;
        writer.set_len(31)?;
        assert_ne!(file_info(&file)?, EntryInfo::File(original));
        gnunet_native::filesystem::close(writer)?;
        let (replacement, _) = publication::publish(
            &directory,
            name,
            &expected,
            publication::Destination::Replace,
            || Ok(()),
        )?
        .into_parts();
        assert!(!directory.same_file(name, &file)?);
        assert_ne!(
            FileIdentity::of(&replacement)?,
            original.identity,
            "equal bytes must never identify a replacement as the original"
        );
    }
    Ok(())
}

fn assert_published_snapshot(directory: &Directory, file: &File, expected: FileInfo, stage: &str) {
    let held = file_info(file);
    let named = directory.entry_info(OsStr::new("image"));
    let links = file_links(file);
    let qualified = private_data_file_info(file);
    let selected = directory.same_file(OsStr::new("image"), file);
    assert!(
        matches!(&held, Ok(EntryInfo::File(observed)) if *observed == expected)
            && matches!(&named, Ok(EntryInfo::File(observed)) if *observed == expected)
            && matches!(&qualified, Ok(observed) if *observed == expected)
            && matches!(links, Ok(1))
            && matches!(selected, Ok(true)),
        "{stage}: expected={expected:?}; held={held:?}; named={named:?}; private={qualified:?}; links={links:?}; selected={selected:?}"
    );
}

#[cfg(target_os = "freebsd")]
#[test]
fn file_snapshot_rechecks_bytes_if_only_ctime_changed() -> Result {
    use gnunet_native::filesystem::PrivateFileSnapshot;

    let scratch = Scratch::create()?;
    let directory = Directory::open(&scratch.0)?;
    let name = OsStr::new("snapshot");
    let (file, _) = publication::publish(
        &directory,
        name,
        b"one",
        publication::Destination::Create,
        || Ok(()),
    )?
    .into_parts();
    let mut before = private_data_file_info(&file)?;
    // Reproduce the two observations around a delayed inode change without
    // depending on when UFS happens to process its pending metadata work.
    before.times.changed -= 1;
    let confirmed =
        PrivateFileSnapshot::new(before, b"one").confirm_read(&directory, name, &file)?;
    assert_eq!(confirmed.initial().identity, before.identity);
    assert_ne!(confirmed.initial().times.changed, before.times.changed);
    confirmed.verify(&directory, name, &file)?;

    let modified = file.metadata()?.modified()?;
    let mut writer = directory.open_file_for_update(name)?;
    writer.write_all(b"two")?;
    writer.set_modified(modified)?;
    writer.sync_all()?;
    drop(writer);
    let mut observed = private_data_file_info(&file)?;
    assert_eq!(observed.identity, before.identity);
    assert_eq!(observed.bytes, before.bytes);
    assert_eq!(observed.times.modified, before.times.modified);
    observed.times.changed -= 1;
    assert!(
        PrivateFileSnapshot::new(observed, b"one")
            .confirm_read(&directory, name, &file)
            .is_err()
    );
    Ok(())
}

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
    drop(destination);
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
    drop(file);
    parent.remove_directory(OsStr::new("selected"), &source)?;
    Ok(())
}

#[cfg(target_os = "freebsd")]
#[test]
fn directory_publication_selects_its_source_under_the_parent_lock() -> Result {
    use std::{sync::mpsc, thread, time::Duration};

    let scratch = Scratch::create()?;
    let parent = Directory::open(&scratch.0)?;
    let original = parent.create_private_directory(OsStr::new("stage"))?;
    let foreign = parent.create_private_directory(OsStr::new("foreign"))?;
    // Open independently, as a cooperating publisher would. A duplicate of
    // the original descriptor would share its flock ownership.
    let lease = File::open(&scratch.0)?;
    lease.lock()?;
    let stage = scratch.0.join("stage");
    let saved = scratch.0.join("saved");
    let borrowed = scratch.0.join("foreign");
    fs::rename(&stage, &saved)?;
    fs::rename(&borrowed, &stage)?;

    thread::scope(|scope| -> Result {
        let (started, worker_started) = mpsc::sync_channel(1);
        let (finished, completion) = mpsc::sync_channel(1);
        let parent = &parent;
        let original = &original;
        scope.spawn(move || {
            let _reported = started.send(());
            let result =
                parent.publish_directory(OsStr::new("stage"), original, OsStr::new("selected"));
            let _reported = finished.send(result);
        });
        let restored = (|| -> Result {
            worker_started.recv()?;
            if !matches!(
                completion.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                return Err("publication observed the staged name outside the parent lock".into());
            }
            fs::rename(&stage, &borrowed)?;
            fs::rename(&saved, &stage)?;
            Ok(())
        })();
        drop(lease);
        restored?;
        completion.recv()??;
        Ok(())
    })?;
    assert!(parent.same_directory(OsStr::new("selected"), &original)?);
    assert!(parent.same_directory(OsStr::new("foreign"), &foreign)?);
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
    // A concurrent Unix fork can temporarily retain the locked open file description.
    #[cfg(unix)]
    let inherited = owner.as_file().try_clone()?;
    drop(owner);
    let next = ExclusiveFile::try_lock(directory.open_file_for_update(OsStr::new("lock"))?)?;
    assert_eq!(FileIdentity::of(next.as_file())?, original);
    #[cfg(unix)]
    assert_eq!(FileIdentity::of(&inherited)?, original);
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
