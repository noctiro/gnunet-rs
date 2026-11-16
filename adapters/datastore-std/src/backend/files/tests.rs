//! Recovery after an applied replacement retains both original image identities.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native recovery assertions inspect original objects and actual namespace effects"
)]
use super::*;
use std::io::Write;

#[test]
fn applied_snapshot_can_be_settled_while_the_old_image_is_still_pinned()
-> Result<(), Box<dyn std::error::Error>> {
    let parent_path = std::env::temp_dir();
    let parent = Directory::open(&parent_path)?;
    let name = format!("gds-image-{}", std::process::id());
    let root = parent.create_private_directory(OsStr::new(&name))?;
    let path = parent_path.join(&name);
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut files = Files::open(&path)?;
        let mut old = files.temporary(false)?;
        old.file.write_all(b"old snapshot")?;
        old.file.sync_all()?;
        files.install_snapshot(&mut old)?;
        let old_id = FileIdentity::of(files.snapshot_pin.as_ref().ok_or("old image missing")?)?;

        let mut candidate = files.temporary(false)?;
        candidate.file.write_all(b"new snapshot")?;
        candidate.file.sync_all()?;
        candidate.verify()?;
        files.snapshot_candidate = Some(candidate.file.try_clone()?);
        files.dirty(false);
        candidate.published = true;
        files.root.replace_file(
            OsStr::new(&candidate.name),
            &candidate.file,
            OsStr::new(SNAPSHOT),
        )?;
        // Model the exact boundary before a replacement completion or barrier
        // can be recorded. The old handle pins an unlinked original object.
        assert_eq!(
            FileIdentity::of(files.snapshot_pin.as_ref().ok_or("old pin missing")?)?,
            old_id
        );
        assert_ne!(old_id, candidate.identity);
        assert_eq!(files.directory_sync(), None);
        files.verify()?;
        files.adopt_snapshot()?;
        files.sync_names()?;
        files.verify()?;
        assert_eq!(
            FileIdentity::of(
                files
                    .snapshot_pin
                    .as_ref()
                    .ok_or("selected image missing")?
            )?,
            candidate.identity
        );
        #[cfg(unix)]
        assert_eq!(files.directory_sync(), Some(DirectorySync::Synchronized));
        #[cfg(windows)]
        assert_eq!(files.directory_sync(), Some(DirectorySync::Unavailable));
        Ok(())
    })();
    drop(root);
    let cleanup = fs::remove_dir_all(path);
    result?;
    cleanup?;
    Ok(())
}
