//! Real native AF_UNIX fixture I/O with original endpoint cleanup ownership.
use gnunet_service_runtime::{CreatedPath, local};
pub use local::Stream;
use std::{io, path::Path};
#[cfg(unix)]
type Address = tokio::net::unix::SocketAddr;
#[cfg(windows)]
type Address = local::Address;

pub struct Listener {
    // The listening socket closes before its original endpoint is retired.
    inner: local::Listener,
    _path: CreatedPath,
}
impl Listener {
    /// Bind only inside a caller-owned private fixture directory. Namespace
    /// replacement is excluded until the original socket/path owner is dropped.
    pub async fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            // The fixture root already excludes other users. Tokio's direct
            // bind avoids changing the process-wide umask in parallel tests.
            let inner = local::Listener::bind(path)?;
            let owned = CreatedPath::capture(path.to_owned())?;
            Ok(Self {
                inner,
                _path: owned,
            })
        }
        #[cfg(windows)]
        {
            let prepared = gnunet_service_runtime::local_listener::prepare(
                path.to_owned(),
                Default::default(),
                128,
            )
            .await?;
            let (socket, owned, warnings) = prepared.into_parts();
            let inner = local::Listener::from_bound_socket(socket)?;
            let owner = Self {
                inner,
                _path: owned,
            };
            if !warnings.is_empty() {
                return Err(io::Error::other(format!(
                    "local fixture preparation warnings: {warnings:?}"
                )));
            }
            Ok(owner)
        }
    }
    pub async fn accept(&self) -> io::Result<(Stream, Address)> {
        self.inner.accept().await
    }
}
