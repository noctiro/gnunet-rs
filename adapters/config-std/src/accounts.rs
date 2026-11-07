//! Safe host account lookup for the official secret-file diagnostic text.
use crate::{Error, path_bytes};
use std::{fs, path::Path};
/// Host account-name lookup. Values remain opaque Unix bytes; no shell command
/// or process-global environment mutation is used.
pub trait NssResolver {
    /// Account name for a numeric UID, or None for the C `<unknown>` result.
    fn user_name(&self, uid: u32) -> Option<Vec<u8>>;
    /// Group name for a numeric GID, or None for the C `<unknown>` result.
    fn group_name(&self, gid: u32) -> Option<Vec<u8>>;
}
/// Reentrant native Unix NSS lookup through the maintained safe uzers API.
pub struct NativeNss;
#[cfg(unix)]
impl NssResolver for NativeNss {
    fn user_name(&self, uid: u32) -> Option<Vec<u8>> {
        let user = uzers::get_user_by_uid(uid)?;
        path_bytes(Path::new(user.name())).ok().map(<[u8]>::to_vec)
    }
    fn group_name(&self, gid: u32) -> Option<Vec<u8>> {
        let group = uzers::get_group_by_gid(gid)?;
        path_bytes(Path::new(group.name())).ok().map(<[u8]>::to_vec)
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
#[cfg(not(unix))]
pub(crate) fn secret_stat(_path: &Path) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported)
}
