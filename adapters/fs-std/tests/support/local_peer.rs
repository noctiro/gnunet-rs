//! Original local FS peers using each platform's real AF_UNIX transport.
use gnunet_native::filesystem::Directory;
use gnunet_service_runtime::local::Stream;
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

pub struct Temporary(pub PathBuf);
impl Temporary {
    pub fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // macOS's per-user temporary path can exceed sockaddr_un before the
        // test adds its own leaf. Keep the owned private root short on Unix.
        #[cfg(unix)]
        let base = fs::canonicalize("/tmp")?;
        #[cfg(windows)]
        let base = std::env::temp_dir();
        let name = format!(
            "gfs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        drop(Directory::open(&base)?.create_private_directory(name.as_ref())?);
        Ok(Self(base.join(name)))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

pub struct Listener {
    #[cfg(unix)]
    local: gnunet_service_runtime::local::Listener,
    #[cfg(windows)]
    bound: gnunet_service_runtime::BoundListeners,
}
impl Listener {
    pub async fn bind(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            Ok(Self {
                local: gnunet_service_runtime::local::Listener::bind(path)?,
            })
        }
        #[cfg(windows)]
        {
            use gnunet_service_runtime::{BoundListeners, LocalListenerAccess};
            let mut config = gnunet_config::Configuration::default();
            config.set_value(
                b"fs",
                b"UNIXPATH",
                Some(gnunet_native::os_bytes::encode(path.as_os_str()).as_ref()),
            )?;
            let bound =
                BoundListeners::bind_configured(&config, b"fs", LocalListenerAccess::Owner).await?;
            if !bound.failures().is_empty() || bound.listeners().len() != 1 {
                return Err(io::Error::other("expected one private local FS listener").into());
            }
            Ok(Self { bound })
        }
    }
    pub async fn accept(&self) -> io::Result<(Stream, ())> {
        std::future::poll_fn(|cx| self.poll_accept(cx)).await
    }
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Stream, ())>> {
        #[cfg(unix)]
        let listener = &self.local;
        #[cfg(windows)]
        let listener = match self.bound.listeners().as_slice() {
            [gnunet_service_runtime::service::Listener::Unix(listener)] => *listener,
            _ => return Poll::Ready(Err(io::Error::other("local FS listener unavailable"))),
        };
        listener
            .poll_accept(cx)
            .map(|result| result.map(|(stream, _)| (stream, ())))
    }
}
