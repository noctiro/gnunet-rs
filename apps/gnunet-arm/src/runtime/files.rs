//! Explicit --delete traversal; links are removed without traversing targets.
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, io, path::Path};
#[cfg(windows)]
const REPARSE_POINT: u32 = 0x400;
#[cfg(windows)]
fn clear_readonly(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    if metadata.file_attributes() & REPARSE_POINT == 0 && metadata.permissions().readonly() {
        let mut permissions = metadata.permissions();
        #[expect(
            clippy::permissions_set_readonly_false,
            reason = "Windows std Permissions changes FILE_ATTRIBUTE_READONLY without changing the DACL"
        )]
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}
pub(super) fn remove_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    clear_readonly(path, &fs::symlink_metadata(path)?)?;
    fs::remove_file(path)
}
pub(super) fn remove_tree(path: &Path) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const DIRECTORY: u32 = 0x10;
        if metadata.file_attributes() & REPARSE_POINT != 0 {
            if metadata.file_attributes() & DIRECTORY != 0 {
                fs::remove_dir(path)?;
            } else {
                fs::remove_file(path)?;
            }
            return Ok(true);
        }
        clear_readonly(path, &metadata)?;
    }
    if metadata.is_symlink() {
        fs::remove_file(path)?;
        return Ok(true);
    }
    #[cfg(unix)]
    // Keep the source CLI's best-effort owner-access adjustment for ordinary
    // entries. A failed adjustment is followed by the actual removal attempt.
    drop(fs::set_permissions(path, fs::Permissions::from_mode(0o700)));
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            remove_tree(&entry?.path())?;
        }
        fs::remove_dir(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, path::PathBuf};
    fn check(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            let mut nonce = [0; 16];
            gnunet_native::entropy::fill(&mut nonce)?;
            let name = format!("gn-arm-delete-{:032x}", u128::from_be_bytes(nonce));
            let parent = std::env::temp_dir();
            gnunet_native::filesystem::Directory::open(&parent)?
                .create_private_directory(OsStr::new(&name))?;
            Ok(Self(parent.join(name)))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    #[test]
    fn deleting_a_link_preserves_the_target_and_its_permissions() -> io::Result<()> {
        use std::os::unix::fs::symlink;
        let directory = Directory::new()?;
        let target = directory.0.join("target");
        fs::create_dir(&target)?;
        fs::write(target.join("retained"), b"retained")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o500))?;
        let before = fs::metadata(&target)?.permissions().mode();
        let link = directory.0.join("link");
        symlink(&target, &link)?;
        check(remove_tree(&link)?, "original link was not removed")?;
        check(
            fs::read(target.join("retained"))? == b"retained",
            "link target content changed",
        )?;
        check(
            fs::metadata(&target)?.permissions().mode() == before,
            "link target permissions changed",
        )?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(windows)]
    #[test]
    fn deleting_a_readonly_nested_file_clears_only_its_native_flag() -> io::Result<()> {
        let directory = Directory::new()?;
        let tree = directory.0.join("tree");
        fs::create_dir(&tree)?;
        let file = tree.join("readonly");
        fs::write(&file, b"owned")?;
        let mut permissions = fs::metadata(&file)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&file, permissions)?;
        check(remove_tree(&tree)?, "readonly tree was not removed")?;
        check(!tree.exists(), "removed tree still exists")?;
        check(!remove_tree(&tree)?, "absent tree reported removal")?;
        Ok(())
    }
}
