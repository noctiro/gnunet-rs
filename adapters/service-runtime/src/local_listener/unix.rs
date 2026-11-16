//! Unix startup-only private bind, stale-path qualification and exact modes.
use super::PreparedLocalListener;
use crate::{CreatedPath, LocalListenerAccess, private_parents};
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use tokio::net::UnixStream;
impl LocalListenerAccess {
    fn modes(self) -> (u32, u32) {
        match self {
            Self::Owner => (0o700, 0o700),
            Self::Group => (0o770, 0o750),
            Self::Everyone => (0o777, 0o755),
        }
    }
}
fn access_parents(path: &std::path::Path, mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut component = PathBuf::new();
    for part in parent.components() {
        component.push(part.as_os_str());
        // FreeBSD reports EISDIR for mkdir("/"). Existing directories need
        // no creation syscall and must retain their current permissions.
        match fs::metadata(&component) {
            Ok(metadata) if metadata.is_dir() => continue,
            Ok(_) => return Err(io::ErrorKind::NotADirectory.into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match fs::DirBuilder::new().mode(mode).create(&component) {
            Ok(()) => {
                // Initial creation is at most this restrictive under the current
                // umask. Only the directory just created by this owner is widened
                // to its requested mode; existing parents are never changed.
                fs::set_permissions(&component, fs::Permissions::from_mode(mode))?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::IsADirectory
                ) =>
            {
                if !fs::metadata(&component)?.is_dir() {
                    return Err(io::ErrorKind::NotADirectory.into());
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
pub(super) async fn prepare(
    path: PathBuf,
    access: LocalListenerAccess,
    backlog: i32,
) -> io::Result<PreparedLocalListener> {
    let (socket_mode, parent_mode) = access.modes();
    if access == LocalListenerAccess::default() {
        private_parents(&path)?;
    } else {
        access_parents(&path, parent_mode)?;
    }
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let observed = (metadata.dev(), metadata.ino());
            match tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&path)).await {
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    let old = CreatedPath::from_observed(path.clone(), observed.0, observed.1);
                    old.remove()?;
                }
                Ok(Ok(_)) => return Err(io::ErrorKind::AddrInUse.into()),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(io::ErrorKind::TimedOut.into()),
            }
        }
        Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let prepared = crate::activation::unix::bind_private_checked(&path, backlog, socket_mode)?;
    Ok(PreparedLocalListener {
        socket: prepared.listener.into(),
        path: prepared.path,
        warnings: prepared.warnings,
    })
}
