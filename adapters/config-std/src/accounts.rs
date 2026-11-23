//! Safe host account lookup for the official secret-file diagnostic text.
use crate::Error;
#[cfg(unix)]
use std::fs;
use std::path::Path;
/// Host account-name lookup. Values remain opaque Unix bytes; no shell command
/// or process-global environment mutation is used.
pub trait NssResolver {
    /// Account name for a numeric UID, or None for the C `<unknown>` result.
    fn user_name(&self, uid: u32) -> Option<Vec<u8>>;
    /// Group name for a numeric GID, or None for the C `<unknown>` result.
    fn group_name(&self, gid: u32) -> Option<Vec<u8>>;
}
/// Reentrant native Unix account lookup.
pub struct NativeNss;
#[cfg(unix)]
impl NssResolver for NativeNss {
    fn user_name(&self, uid: u32) -> Option<Vec<u8>> {
        let user = gnunet_native::accounts::user_by_uid(uid).ok()??;
        Some(user.name().to_bytes().to_vec())
    }
    fn group_name(&self, gid: u32) -> Option<Vec<u8>> {
        gnunet_native::accounts::group_name(gid)
            .ok()?
            .map(std::ffi::CString::into_bytes)
    }
}
#[cfg(unix)]
pub(crate) fn secret_stat(path: &Path) -> Result<Vec<u8>, Error> {
    use std::os::unix::fs::MetadataExt;
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(b"<can't stat file>".to_vec());
    };
    let mut text = NativeNss
        .user_name(metadata.uid())
        .unwrap_or_else(|| b"<unknown>".to_vec());
    text.push(b':');
    text.extend_from_slice(
        &NativeNss
            .group_name(metadata.gid())
            .unwrap_or_else(|| b"<unknown>".to_vec()),
    );
    text.push(b' ');
    text.extend_from_slice(format!("{:o}", metadata.mode()).as_bytes());
    Ok(text)
}
#[cfg(windows)]
pub(crate) fn secret_stat(path: &Path) -> Result<Vec<u8>, Error> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return Ok(format!("<can't query file: {error}>").into_bytes()),
    };
    // Owner and attributes are separate time-local observations on this same
    // opened object. A metadata failure cannot invalidate an earlier file read.
    let owner = gnunet_native::identity::file_owner(&file).map_or_else(
        |error| format!("<owner SID unavailable: {error}>"),
        |sid| sid.to_string(),
    );
    use std::os::windows::fs::MetadataExt;
    let attributes = file.metadata().map_or_else(
        |error| format!("<attributes unavailable: {error}>"),
        |metadata| format!("0x{:08x}", metadata.file_attributes()),
    );
    Ok(format!("owner_sid={owner} attributes={attributes}").into_bytes())
}
#[cfg(not(any(unix, windows)))]
pub(crate) fn secret_stat(_path: &Path) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported)
}
