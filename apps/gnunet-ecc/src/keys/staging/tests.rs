//! Cleanup must follow original native objects across a directory replacement.
use super::*;
use gnunet_native::filesystem::Directory;
use std::ffi::OsStr;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        // This uniquely created private fixture excludes external namespace
        // administration and contains only this test's own files/directories.
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions distinguish original sibling retirement from a replacement directory's untouched file"
)]
fn cleanup_uses_the_original_directory_after_its_path_is_replaced() -> Result<(), Failure> {
    let base = std::env::temp_dir().canonicalize()?;
    let serial = NEXT
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| "ECC test serial exhausted")?;
    let name = format!("ecc-cleanup-{}-{serial}", std::process::id());
    let root = Directory::open(&base)?.create_private_directory(OsStr::new(&name))?;
    let scratch = Scratch(base.join(name));
    drop(root.create_private_directory(OsStr::new("source"))?);
    let source = scratch.0.join("source");
    let moved = scratch.0.join("moved");
    let mut owner = None;
    Staging::create(&source.join("keys"), &mut owner)?;
    let mut stage = owner.ok_or("missing ECC test staging owner")?;
    let sibling = stage.name.clone();
    // Windows refuses a directory rename with a live descendant handle.
    // Move the held file out and back without replacing its original object.
    #[cfg(windows)]
    std::fs::rename(source.join(&sibling), scratch.0.join(&sibling))?;
    std::fs::rename(&source, &moved)?;
    #[cfg(windows)]
    std::fs::rename(scratch.0.join(&sibling), moved.join(&sibling))?;
    drop(root.create_private_directory(OsStr::new("source"))?);
    let replacement = source.join(&sibling);
    std::fs::write(&replacement, b"replacement")?;

    stage.cleanup()?;

    assert_eq!(std::fs::read(&replacement)?, b"replacement");
    assert!(
        !moved.join(&sibling).try_exists()?,
        "original sibling was retained"
    );
    assert!(
        stage.retained_path().is_none(),
        "retired sibling reported as live"
    );
    Ok(())
}
