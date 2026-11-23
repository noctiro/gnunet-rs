//! Native Unix datagrams and stable descriptor ownership.
use gnunet_service_runtime::readiness::RegisteredIo;
use socket2::{Domain, SockAddr, SockRef, Socket, Type};
use std::{
    fmt, fs, io,
    mem::offset_of,
    os::{
        fd::OwnedFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt},
        },
    },
    path::{Path, PathBuf},
    task::{Context, Poll},
};
mod receive;

const PATH_OFFSET: usize = offset_of!(libc::sockaddr_un, sun_path);
const PATH_CAPACITY: usize = size_of::<libc::sockaddr_un>() - PATH_OFFSET;

pub(crate) const DATAGRAM_LIMIT: usize = if cfg!(any(target_os = "macos", target_os = "ios")) {
    2048
} else {
    65535
};

/// Literal source/destination address, preserving the actual native address and
/// its length. Abstract names use the pinned full sun_path zero-filled profile.
#[derive(Clone)]
pub struct Address {
    raw: SockAddr,
    path: Vec<u8>,
}
impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        match (self.is_abstract(), other.is_abstract()) {
            (false, false) => self.path == other.path,
            (true, true) => self.raw == other.raw,
            _ => false,
        }
    }
}
impl Eq for Address {}
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixAddress")
            .field("native_len", &self.raw.len())
            .field("path_bytes", &self.path.len())
            .field("abstract", &self.is_abstract())
            .finish()
    }
}
fn copy(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(input.len())
        .map_err(io::Error::other)?;
    data.extend_from_slice(input);
    Ok(data)
}
impl Address {
    pub(crate) fn validate(path: &[u8]) -> io::Result<()> {
        if !cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd"
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix address profile is not qualified for this OS",
            ));
        }
        if path.is_empty() || path.contains(&0) || path.len() >= PATH_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or overlong Unix path",
            ));
        }
        if path.starts_with(b"@") && !cfg!(any(target_os = "linux", target_os = "android")) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract Unix namespace requires the Linux socket ABI",
            ));
        }
        Ok(())
    }

    /// Build a filesystem endpoint or the full-width Linux ABI abstract name.
    pub fn new(path: &[u8]) -> io::Result<Self> {
        Self::validate(path)?;
        let raw = if path[0] == b'@' {
            // The original full sockaddr includes the remaining zero padding
            // in the abstract name on the supported Linux socket ABI.
            let mut name = [0; PATH_CAPACITY];
            name[1..path.len()].copy_from_slice(&path[1..]);
            SockAddr::unix(Path::new(std::ffi::OsStr::from_bytes(&name)))?
        } else {
            SockAddr::unix(Path::new(std::ffi::OsStr::from_bytes(path)))?
        };
        Ok(Self {
            raw,
            path: copy(path)?,
        })
    }
    fn received(raw: SockAddr) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "unnamed or unrepresentable Unix sender",
            )
        };
        let name = receive::path_bytes(&raw).ok_or_else(invalid)?;
        if let Some(name) = raw.as_abstract_namespace() {
            let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
            let mut path = Vec::new();
            path.try_reserve_exact(end + 1).map_err(io::Error::other)?;
            path.push(b'@');
            path.extend_from_slice(&name[..end]);
            return Ok(Self { raw, path });
        }
        // BSD can report the pathname without a terminator. Honor the native
        // returned extent and preserve every non-NUL filename byte.
        let path = name.strip_suffix(&[0]).unwrap_or(name);
        if path.is_empty() || path.contains(&0) {
            return Err(invalid());
        }
        Ok(Self {
            path: copy(path)?,
            raw,
        })
    }
    /// Original path bytes, including an abstract at-sign; no UTF8 inference.
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    /// Actual retained native socket address length, not a reconstructed length.
    pub fn native_len(&self) -> usize {
        self.raw.len() as usize
    }
    /// Whether this address belongs to the native abstract namespace.
    pub fn is_abstract(&self) -> bool {
        self.raw.as_abstract_namespace().is_some()
    }
}
struct PathOwner {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl PathOwner {
    fn capture(path: PathBuf) -> io::Result<Self> {
        let m = fs::symlink_metadata(&path)?;
        if !m.file_type().is_socket() {
            return Err(io::Error::other("new Unix bind path is no longer a socket"));
        }
        Ok(Self {
            path,
            device: m.dev(),
            inode: m.ino(),
        })
    }
    fn remove(self) -> PathCleanup {
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => PathCleanup::Absent,
            Err(e) => PathCleanup::Unknown(e),
            Ok(m)
                if m.dev() != self.device
                    || m.ino() != self.inode
                    || !m.file_type().is_socket() =>
            {
                PathCleanup::Replaced
            }
            Ok(_) => match fs::remove_file(self.path) {
                Ok(()) => PathCleanup::Removed,
                Err(e) => PathCleanup::Unknown(e),
            },
        }
    }
}
/// Actual independently reported cleanup of the original bound filesystem name.
#[derive(Debug)]
pub enum PathCleanup {
    /// No filesystem path was created (including abstract namespace).
    NotCreated,
    /// Bind created a name, but original inode observation failed. No unowned
    /// path was removed and absence cannot be established by this receipt.
    UnobservedBoundName,
    /// Original observed device/inode was actually unlinked.
    Removed,
    /// Its name was actually absent at observation.
    Absent,
    /// A different object is present and was left untouched.
    Replaced,
    /// Actual original cleanup error; no successful absence is inferred.
    Unknown(io::Error),
}
/// One native close attempt, independent of path cleanup or caller clock state.
#[derive(Debug)]
pub struct Close {
    /// Whether there really was an owned descriptor to close.
    pub had_descriptor: bool,
    /// Original close errno. Interrupted/error close is not retried on a reused fd.
    pub descriptor_error: Option<io::Error>,
    /// Actual original name cleanup, with replacements retained.
    pub path: PathCleanup,
}
impl Close {
    fn none() -> Self {
        Self {
            had_descriptor: false,
            descriptor_error: None,
            path: PathCleanup::NotCreated,
        }
    }
}
/// Actual constructor error plus independent descriptor/path cleanup.
#[derive(Debug)]
pub struct Failure {
    /// Original allocation/socket/bind/registration/kernel error.
    pub cause: io::Error,
    /// Actual cleanup, never substituted for the original cause.
    pub cleanup: Close,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unix datagram: {}; cleanup={:?}",
            self.cause, self.cleanup
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn close_fd(fd: OwnedFd, path: Option<PathOwner>) -> Close {
    let error = nix::unistd::close(fd).err().map(io::Error::from);
    Close {
        had_descriptor: true,
        descriptor_error: error,
        path: path.map_or(PathCleanup::NotCreated, PathOwner::remove),
    }
}
/// Actual owned socket configuration, not an inferred MTU/delivery guarantee.
#[derive(Clone, Copy, Debug)]
pub struct Buffers {
    /// Real SO_SNDBUF value returned by the original bound socket.
    pub send: usize,
    /// Real SO_RCVBUF value returned by the original bound socket.
    pub receive: usize,
}
/// One actual kernel datagram read, including its real truncation/ancillary flags.
#[derive(Debug)]
pub struct Received {
    /// Actual bytes copied into caller storage.
    pub bytes: usize,
    /// Original native sender address when representable.
    pub source: Option<Address>,
    /// Local address conversion failure after input consumption, not socket loss.
    pub source_error: Option<io::Error>,
    /// Kernel MSG_TRUNC: never decode this prefix as an entire datagram.
    pub truncated: bool,
    /// Kernel MSG_CTRUNC: no ancillary ownership is accepted by this interface.
    pub ancillary_truncated: bool,
}
/// Exclusive original descriptor/reactor and observed filesystem-name owner.
/// Call bind only inside a live caller-owned Tokio reactor. There are no tasks.
#[must_use = "retain and explicitly close the actual socket to observe cleanup errors"]
pub struct OwnedDatagram {
    io: Option<RegisteredIo>,
    path: Option<PathOwner>,
    address: Address,
    buffers: Buffers,
}
impl OwnedDatagram {
    /// Create/nonblock/bind one new Unix datagram. An existing path is never
    /// unlinked/taken over. Caller excludes hostile metadata/unlink path races,
    /// as with the shared SERVICE CreatedPath contract. New parents use0700.
    pub fn bind(
        address: Address,
        send_buffer: usize,
        receive_buffer: usize,
    ) -> Result<Self, Failure> {
        let socket = Socket::new(Domain::UNIX, Type::DGRAM, None).map_err(|cause| Failure {
            cause,
            cleanup: Close::none(),
        })?;
        let mut path = None;
        let mut unobserved_bound_name = false;
        let configured = (|| {
            if send_buffer == 0
                || receive_buffer == 0
                || i32::try_from(send_buffer).is_err()
                || i32::try_from(receive_buffer).is_err()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid Unix socket buffer bound",
                ));
            }
            socket.set_nonblocking(true)?;
            socket.set_send_buffer_size(send_buffer)?;
            socket.set_recv_buffer_size(receive_buffer)?;
            if !address.is_abstract() {
                let filename = PathBuf::from(std::ffi::OsStr::from_bytes(address.path()));
                let parent = filename
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new("."));
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            socket.bind(&address.raw)?;
            if !address.is_abstract() {
                unobserved_bound_name = true;
                path = Some(PathOwner::capture(PathBuf::from(
                    std::ffi::OsStr::from_bytes(address.path()),
                ))?);
                unobserved_bound_name = false;
            }
            Ok::<_, io::Error>(Buffers {
                send: socket.send_buffer_size()?,
                receive: socket.recv_buffer_size()?,
            })
        })();
        let fd: OwnedFd = socket.into();
        let buffers = match configured {
            Ok(v) => v,
            Err(cause) => {
                let mut cleanup = close_fd(fd, path);
                if unobserved_bound_name {
                    cleanup.path = PathCleanup::UnobservedBoundName;
                }
                return Err(Failure { cause, cleanup });
            }
        };
        let io = match RegisteredIo::new(fd) {
            Ok(io) => io,
            Err(error) => {
                return Err(Failure {
                    cause: error.error,
                    cleanup: close_fd(error.descriptor, path),
                });
            }
        };
        Ok(Self {
            io: Some(io),
            path,
            address,
            buffers,
        })
    }
    /// Exact original bound address.
    pub fn address(&self) -> &Address {
        &self.address
    }
    /// Actual observed buffer sizes. Caller combines limits conservatively and
    /// still handles genuine EMSGSIZE; this is not a remote-delivery capability.
    pub const fn buffers(&self) -> Buffers {
        self.buffers
    }
    /// One nonblocking original datagram receive. A completed datagram is never
    /// retained in a hidden task; caller receives true truncation and raw length.
    pub fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<Received>> {
        if buffer.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty Unix receive allowance",
            )));
        }
        let Some(io) = &self.io else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Unix socket closed",
            )));
        };
        io.poll_read_with(cx, |fd| receive::datagram(fd, buffer))
    }
    /// One actual nonblocking datagram send, preserving the original errno.
    /// Backpressure can depend on the destination rather than the writable
    /// readiness of this unconnected socket.
    pub fn try_send(&self, destination: &Address, packet: &[u8]) -> io::Result<usize> {
        let io = self
            .io
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Unix socket closed"))?;
        SockRef::from(io.descriptor()).send_to_with_flags(
            packet,
            &destination.raw,
            libc::MSG_DONTWAIT,
        )
    }
    /// Physically deregister/close exactly once, then independently remove only
    /// the observed original socket inode. No clock or successful ACK is needed.
    pub fn close(&mut self) -> Close {
        match self.io.take() {
            Some(io) => close_fd(io.into_owned(), self.path.take()),
            None => Close::none(),
        }
    }
}

impl Drop for OwnedDatagram {
    fn drop(&mut self) {
        let _outcome = self.close();
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;

    #[test]
    fn abstract_address_retains_the_full_native_name() -> io::Result<()> {
        let path = b"@gnunet-\xff";
        let address = Address::new(path)?;
        let name = address
            .raw
            .as_abstract_namespace()
            .ok_or_else(|| io::Error::other("missing native abstract address"))?;
        let end = path.len() - 1;
        if address.native_len() != size_of::<libc::sockaddr_un>()
            || name.len() != 107
            || name[..end] != path[1..]
            || name[end..].iter().any(|byte| *byte != 0)
            || Address::received(address.raw)?.path() != path
        {
            return Err(io::Error::other("changed native abstract address bytes"));
        }
        Ok(())
    }
}
