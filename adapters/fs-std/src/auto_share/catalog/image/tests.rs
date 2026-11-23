//! Real held-file mutations and anchored name checks, without a race fixture.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native file assertions preserve fallible setup and observation errors"
)]
use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "gnunet-catalog-fence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let temporary = std::env::temp_dir();
        let parent = Directory::open(&temporary)?;
        drop(parent.create_private_directory(OsStr::new(&name))?);
        Ok(Self(temporary.join(name)))
    }
    fn directory(&self) -> io::Result<Directory> {
        Directory::open(&self.0)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn diagnostic(error: &Error) -> std::result::Result<&FenceError, &'static str> {
    let Error::Io(error) = error else {
        return Err("catalog fence lost its typed native diagnostic");
    };
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<FenceError>())
        .ok_or("missing original catalog fence diagnostic")
}

#[test]
fn changed_held_contents_report_metadata_without_claiming_name_replacement() -> Result {
    let scratch = Scratch::new()?;
    let directory = scratch.directory()?;
    let mut image = Image::new(directory.as_file())?;
    image.write(b"original")?;
    let original = image.original.as_ref().ok_or("missing original image")?;
    let before = original.info;
    let mut writer = directory.open_file_for_update(OsStr::new(IMAGE))?;
    writer.write_all(b" appended")?;
    writer.sync_all()?;
    assert!(directory.same_file(OsStr::new(IMAGE), &original.file)?);

    let error = image.selected().err().ok_or("changed image accepted")?;
    let diagnostic = diagnostic(&error)?;
    assert_eq!(diagnostic.stage, "selected");
    let FenceCause::Metadata {
        before: captured,
        after,
    } = &diagnostic.cause
    else {
        return Err("same-object modification was not a metadata refusal".into());
    };
    assert_eq!(*captured, before);
    assert_eq!(after.identity, before.identity);
    assert_ne!(after.bytes, before.bytes);
    assert!(error.to_string().contains("bytes=true"));
    assert_eq!(image.original.as_ref().ok_or("original lost")?.info, before);
    Ok(())
}

#[test]
fn published_and_reopened_catalogs_retain_only_read_leases() -> Result {
    let scratch = Scratch::new()?;
    let directory = scratch.directory()?;
    let mut image = Image::new(directory.as_file())?;
    image.write(b"original")?;
    let original = image.original.as_ref().ok_or("missing original image")?;
    filesystem::validate_readonly(&original.file)?;
    assert!((&original.file).write(b"changed").is_err());
    image.write(b"replacement")?;
    let replacement = image.original.as_ref().ok_or("missing replacement image")?;
    filesystem::validate_readonly(&replacement.file)?;
    assert!((&replacement.file).write(b"changed").is_err());
    assert!(directory.same_file(OsStr::new(IMAGE), &replacement.file)?);
    assert!(
        matches!(directory.entry_info(OsStr::new(NEXT)), Err(error) if error.kind() == io::ErrorKind::NotFound)
    );

    let mut reopened = Image::new(directory.as_file())?;
    assert_eq!(reopened.read()?.as_deref(), Some(b"replacement".as_slice()));
    let read = reopened.original.as_ref().ok_or("missing reopened image")?;
    filesystem::validate_readonly(&read.file)?;
    assert!((&read.file).write(b"changed").is_err());
    assert_eq!(fs::read(scratch.0.join(IMAGE))?, b"replacement");
    Ok(())
}

#[test]
fn unchanged_held_file_reports_the_distinct_selected_name() -> Result {
    let scratch = Scratch::new()?;
    let directory = scratch.directory()?;
    let mut held = directory.create_private_file(OsStr::new("held"))?;
    held.write_all(b"original")?;
    held.sync_all()?;
    filesystem::close(held)?;
    let held = directory.open_file(OsStr::new("held"))?;
    let info = private_data_file_info(&held)?;
    let mut named = directory.create_private_file(OsStr::new(IMAGE))?;
    named.write_all(b"foreign!")?;
    named.sync_all()?;
    let named_info = private_data_file_info(&named)?;
    // Stage actual held-file facts with an independently replaced selection.
    // Neither equal bytes nor metadata can authorize that foreign name.
    let image = Image {
        directory,
        original: Some(Original { file: held, info }),
        naming_sync: None,
    };
    let error = image.selected().err().ok_or("foreign name accepted")?;
    let diagnostic = diagnostic(&error)?;
    assert_eq!(diagnostic.stage, "selected name");
    let FenceCause::Named {
        held,
        observed_after_rejection: Ok(EntryInfo::File(observed)),
    } = &diagnostic.cause
    else {
        return Err("name mismatch lost its independent native observation".into());
    };
    assert_eq!(*held, info);
    assert_eq!(observed.identity, named_info.identity);
    assert_ne!(observed.identity, held.identity);
    assert_eq!(fs::read(scratch.0.join(IMAGE))?, b"foreign!");
    Ok(())
}

#[cfg(unix)]
#[test]
fn changed_private_file_policy_preserves_the_native_cause() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new()?;
    let directory = scratch.directory()?;
    let mut image = Image::new(directory.as_file())?;
    image.write(b"original")?;
    let original = image.original.as_ref().ok_or("missing original image")?;
    original
        .file
        .set_permissions(fs::Permissions::from_mode(0o640))?;
    let error = image.selected().err().ok_or("unqualified image accepted")?;
    let diagnostic = diagnostic(&error)?;
    assert_eq!(diagnostic.stage, "selected file policy");
    let FenceCause::Native(original) = &diagnostic.cause else {
        return Err("private policy error was relabeled as metadata/name drift".into());
    };
    assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
    assert!(std::error::Error::source(diagnostic).is_some());
    Ok(())
}
