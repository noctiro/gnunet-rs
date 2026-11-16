//! Native inherited-listener ownership, independent of domain protocols.
#[cfg(unix)]
pub(crate) mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::ActivatedSocket;
#[cfg(unix)]
pub use unix::Activation;
#[cfg(target_os = "macos")]
pub use unix::DARWIN_SOCKET_INFO_BUFFER_BYTES;
#[cfg(target_os = "macos")]
pub use unix::DARWIN_SOCKET_OPTIONS_OFFSET;
#[cfg(unix)]
pub use unix::PrivateListener;
#[cfg(unix)]
pub use unix::bind_private;
#[cfg(unix)]
pub use unix::bind_private_with_backlog;
#[cfg(unix)]
pub use unix::bind_private_with_permissions;
#[cfg(unix)]
pub use unix::capture;
#[cfg(windows)]
pub use windows::ActivatedSocket;
#[cfg(windows)]
pub use windows::Activation;

#[cfg(unix)]
impl Activation {
    /// Borrow original listeners in declaration order, without native I/O.
    pub fn sockets(&self) -> &[ActivatedSocket] {
        &self.sockets
    }
    /// Number of original declared listeners.
    pub fn len(&self) -> usize {
        self.sockets.len()
    }
    /// Whether no listener transfer was declared.
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
    /// Transfer all original listener owners without cloning or rebinding.
    pub fn into_sockets(self) -> Vec<ActivatedSocket> {
        self.sockets
    }
}
