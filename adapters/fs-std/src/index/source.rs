//! Native observations and the optional official Unix identifier shortcut.
use gnunet_native::filesystem::FileInfo;
use std::{fs::File, io, path::Path};
pub(super) fn info(file: &File) -> io::Result<FileInfo> {
    crate::input::file_info(file)
}
pub(super) fn named_info(path: &Path) -> io::Result<FileInfo> {
    // INDEX_START permits ordinary symlinks. Compare a fresh resolved original
    // handle with the one hashed; a nofollow observation would reject valid IPC.
    info(&crate::input::open(path)?)
}
#[cfg(unix)]
pub(super) fn identifiers(file: &File, before: FileInfo, device: u64, inode: u64) -> bool {
    use gnunet_native::filesystem::FileIdentityParts;
    let FileIdentityParts::Unix {
        inode: original, ..
    } = before.identity.parts()
    else {
        return false;
    };
    (device != 0 || inode != 0)
        && inode == original
        && nix::sys::statvfs::fstatvfs(file)
            .is_ok_and(|v| u128::from(v.filesystem_id()) == u128::from(device))
}
#[cfg(windows)]
pub(super) fn identifiers(_: &File, _: FileInfo, _: u64, _: u64) -> bool {
    // A Windows 128-bit file ID cannot be represented by the Unix wire fields.
    // Use the official whole-file hash path, without fabricating identifiers.
    false
}
