//! Native local streams with original private directory and endpoint ownership.
use gnunet_service_runtime::{CreatedPath, local};
use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce[..12])?;
        let base = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("pils-{:024x}", u128::from_le_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&base)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(base.join(name)))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
pub struct LocalListener {
    pub socket: local::Listener,
    _path: CreatedPath,
}
impl LocalListener {
    pub async fn bind(path: &Path) -> io::Result<Self> {
        let prepared = gnunet_service_runtime::local_listener::prepare(
            path.to_owned(),
            Default::default(),
            128,
        )
        .await?;
        let (socket, path, warnings) = prepared.into_parts();
        if !warnings.is_empty() {
            return Err(io::Error::other(format!(
                "native local listener warnings: {warnings:?}"
            )));
        }
        #[cfg(unix)]
        let socket = {
            let owned: std::os::fd::OwnedFd = socket.into();
            local::Listener::from_std(std::os::unix::net::UnixListener::from(owned))?
        };
        #[cfg(windows)]
        let socket = local::Listener::from_bound_socket(socket)?;
        Ok(Self {
            socket,
            _path: path,
        })
    }
}
