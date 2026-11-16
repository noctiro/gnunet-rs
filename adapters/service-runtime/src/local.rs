//! Native AF_UNIX stream owners. Byte framing and peer admission remain separate.
#[cfg(unix)]
pub use tokio::net::{UnixListener as Listener, UnixStream as Stream};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use gnunet_native::local_socket::Address;
#[cfg(windows)]
pub use windows::{Listener, Stream};
