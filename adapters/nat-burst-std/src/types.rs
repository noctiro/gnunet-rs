//! Ownership, finite bounds, and diagnostic receipts for the public utility.
use crate::wire::{BurstMessage, BurstSync, Endian};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    fmt, io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::net::UdpSocket;

/// Caller-owned allocation domain. Every new attempt consumes a checked brand.
pub struct Instance {
    next: AtomicU64,
}
impl Instance {
    /// Create a fresh domain without sockets, tasks, entropy, or global state.
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }
    pub(crate) fn allocate(&self) -> Result<Attempt<'_>, Fault> {
        let previous = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Fault::Overflow)?;
        Ok(Attempt {
            instance: self,
            allocation: previous + 1,
        })
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

/// Original attempt brand; new explicit intents cannot reuse retired tokens.
#[derive(Clone, Copy)]
pub struct Attempt<'id> {
    instance: &'id Instance,
    allocation: u64,
}
impl PartialEq for Attempt<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.instance, other.instance) && self.allocation == other.allocation
    }
}
impl Eq for Attempt<'_> {}
impl fmt::Debug for Attempt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Attempt")
            .field(&(self.instance as *const Instance))
            .field(&self.allocation)
            .finish()
    }
}

/// An original descriptor role; serial zero is the caller's default socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketId<'id> {
    pub(crate) attempt: Attempt<'id>,
    pub(crate) serial: u32,
}
impl<'id> SocketId<'id> {
    /// Original attempt allocation.
    pub fn attempt(self) -> Attempt<'id> {
        self.attempt
    }
    /// Whether this is the caller-owned dispatcher socket.
    pub fn is_default(self) -> bool {
        self.serial == 0
    }
}

/// Original fixed input; the owner never resolves or changes the remote IP.
#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    /// Initial remote endpoint. Scan probes use this same IP with ports 1024..65535.
    pub remote: SocketAddr,
    /// Explicit initialized public bytes used on every outgoing datagram.
    /// The pinned C initial probe uses zeros; callers may use `[0; 32]` likewise.
    pub public_peer: [u8; 32],
    /// Byte order of our native enum/unsigned-int fields.
    pub local_order: Endian,
    /// Byte order of the remote producer's native enum/unsigned-int fields.
    pub remote_order: Endian,
    /// Actual local average RTT in microseconds, supplied by the caller.
    pub local_rtt_micros: u64,
    /// Actual received synchronization message, decoded with its original profile.
    pub remote_sync: BurstSync,
    /// Absolute original logical lifetime, including the synchronization delay.
    pub until: AbsoluteTime,
}

/// Actual already-synchronized communicator command. TRANSPORT has performed
/// the public readiness check and delay before issuing its original 1253.
/// There is no remote sync value or synthetic RTT at this entry point.
#[derive(Clone, Copy, Debug)]
pub struct ReadyParameters {
    /// Actual remote literal IP/default port selected by the command owner.
    pub remote: SocketAddr,
    /// Explicit initialized public bytes on each probe, never authentication.
    pub public_peer: [u8; 32],
    /// Actual producer ABI for our public native unsigned field.
    pub local_order: Endian,
    /// Explicit producer ABI of the received probe, retained as raw assertions.
    pub remote_order: Endian,
    /// Original finite canonical request bound.
    pub until: AbsoluteTime,
    /// Original native hard reserved before any clock/configuration work.
    pub hard: std::time::Instant,
}

/// Bounded native resources. No default can allocate more than 512 scan sockets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneously owned scan sockets, in 1..=512; default socket is excluded.
    pub sockets: usize,
    /// Minimum interval between distinct port attempts; nonzero, default 10us.
    pub send_interval: Duration,
    /// Per-scan-socket lifetime and pending default-send bound; default 100ms.
    pub socket_lifetime: Duration,
    /// Maximum completed send/receive/bind actions per poll, in 1..=1024.
    /// Readiness registration additionally visits at most 512 live socket rows.
    pub io_budget: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            sockets: 512,
            send_interval: Duration::from_micros(10),
            socket_lifetime: Duration::from_millis(100),
            io_budget: 32,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<Self, Fault> {
        if !(1..=512).contains(&self.sockets)
            || !(1..=1024).contains(&self.io_budget)
            || self.send_interval.is_zero()
            || self.socket_lifetime.is_zero()
        {
            return Err(Fault::InvalidInput);
        }
        Ok(self)
    }
}

/// Original failing native action; the associated OS error is preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoAction {
    /// Read the supplied default socket's local binding.
    LocalAddress,
    /// Inspect whether the default socket was already connected.
    PeerAddress,
    /// Bind a fresh scan socket without address/port reuse.
    Bind,
    /// Set nonblocking mode on a newly owned socket.
    Nonblocking,
    /// Attach a fresh nonblocking socket to the caller's Tokio I/O reactor.
    Reactor,
    /// Submit one complete UDP datagram.
    Send,
    /// Receive one complete UDP datagram on an owned scan socket.
    Receive,
}
/// A creation/admission failure; no native success is fabricated.
#[derive(Debug)]
pub enum Error {
    /// Bounded protocol, capacity, or lifetime failure.
    Fault(Fault),
    /// Original logical clock or subscription failure.
    Clock(Fault),
    /// Actual native error with original action and port.
    Io {
        /// Original syscall category.
        action: IoAction,
        /// Local attempted port, when known.
        port: Option<u16>,
        /// Actual unmodified error.
        error: io::Error,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fault(error) | Self::Clock(error) => Some(error),
            Self::Io { error, .. } => Some(error),
        }
    }
}
impl From<Fault> for Error {
    fn from(value: Fault) -> Self {
        Self::Fault(value)
    }
}

/// Terminal reason. Descriptor retirement is independent of clock success.
#[derive(Debug)]
pub enum Cause {
    /// The caller explicitly cancelled this attempt.
    Cancelled,
    /// Original logical deadline or immutable native hard bound elapsed.
    Deadline(DeadlineKind),
    /// Every scan port was attempted and every created socket expired.
    Exhausted,
    /// One unauthenticated observation selected a socket.
    Selected,
    /// Original clock error, including failure while handling dispatched input.
    Clock(Fault),
    /// Actual socket error; all other newly owned sockets are retired first.
    Io {
        /// Original native action.
        action: IoAction,
        /// Original local port.
        port: u16,
        /// Actual original OS error.
        error: io::Error,
    },
    /// A datagram write exposed an unexpected positive prefix; no suffix is sent.
    Partial {
        /// Original socket token's local port.
        port: u16,
        /// Actual positive byte count.
        written: usize,
    },
    /// A native timer target could not be represented.
    Overflow,
}

/// Which immutable/original finite bound ended the attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineKind {
    /// Original canonical logical `until` was observed.
    Logical,
    /// Immutable native hard bound derived once at admission elapsed.
    Hard,
    /// The initial default probe could not be written within its send bound.
    InitialSend,
}

/// Local counters. None establishes remote processing, authentication, or reachability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Bind attempts made, including occupied ports.
    pub ports_attempted: u32,
    /// Successfully created and bound scan sockets.
    pub sockets_opened: u32,
    /// Whole 36-byte UDP datagrams accepted by the local kernel.
    pub datagrams_written: u32,
    /// Owned scan sockets retired by their original 100ms (or configured) bound.
    pub expired: u32,
}

/// Actual stop state after retiring all unselected owned handles and the default
/// clone. Rust socket Drop does not expose a close errno; no close ACK is claimed.
#[derive(Debug)]
pub struct End<'id> {
    /// Original allocation, never a new-source replacement.
    pub attempt: Attempt<'id>,
    /// Original reason retained independently of descriptor retirement.
    pub cause: Cause,
    /// Actual local operation counts.
    pub report: Report,
}

/// Descriptor ownership transferred by an unauthenticated socket observation.
pub enum SelectedSocket {
    /// The caller already owns the default socket; this is only its Arc clone.
    Default(Arc<UdpSocket>),
    /// A newly bound scan socket; no other owner is retained by the burst owner.
    Scan(UdpSocket),
}
impl SelectedSocket {
    /// Borrow the selected actual socket for subsequent caller-owned I/O.
    pub fn socket(&self) -> &UdpSocket {
        match self {
            Self::Default(socket) => socket,
            Self::Scan(socket) => socket,
        }
    }
}
impl fmt::Debug for SelectedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default(_) => "DefaultSocket",
            Self::Scan(_) => "ScanSocket",
        })
    }
}

/// A literal source-IP/length match, without peer authentication or ACK semantics.
#[derive(Debug)]
pub struct Selection<'id> {
    /// Original descriptor role and allocation.
    pub id: SocketId<'id>,
    /// The actual selected descriptor; all other scan sockets have been retired.
    pub socket: SelectedSocket,
    /// Actual source endpoint returned by recvfrom or the caller dispatcher.
    pub remote: SocketAddr,
    /// Raw asserted public identity and native advertised port.
    pub message: BurstMessage,
}

/// Synchronous observation emitted during a foreground poll.
pub enum Event<'a, 'id> {
    /// A complete probe was accepted by the local UDP socket only.
    Written {
        /// Original socket token.
        id: SocketId<'id>,
        /// Actual destination used.
        remote: SocketAddr,
    },
    /// This scan port was occupied. The exact bind error is provided before advance.
    Occupied {
        /// Attempted local port.
        port: u16,
        /// Actual AddrInUse error.
        error: &'a io::Error,
    },
    /// Non-burst data received on a scan socket, forwarded unchanged, including
    /// empty or >36-byte datagrams. It remains valid for this callback only.
    Datagram {
        /// Original socket token.
        id: SocketId<'id>,
        /// Actual sender.
        remote: SocketAddr,
        /// Original application bytes, without modification.
        bytes: &'a [u8],
        /// Input filled the 65536-byte buffer: completeness is
        /// unknown for a nonstandard jumbo datagram. Never classify it as a probe.
        at_capacity: bool,
    },
}
impl fmt::Debug for Event<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Written { id, remote } => f
                .debug_struct("Written")
                .field("id", id)
                .field("remote", remote)
                .finish(),
            Self::Occupied { port, error } => f
                .debug_struct("Occupied")
                .field("port", port)
                .field("error", error)
                .finish(),
            Self::Datagram {
                id,
                remote,
                bytes,
                at_capacity,
            } => f
                .debug_struct("Datagram")
                .field("id", id)
                .field("remote", remote)
                .field("length", &bytes.len())
                .field("at_capacity", at_capacity)
                .field("bytes", &"[redacted]")
                .finish(),
        }
    }
}

/// One caller-driven poll outcome. Future cancellation retains all cursors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// At least one actual local action or expiry occurred; poll again for progress.
    Progress,
    /// A selected socket is retained until `take_selection` or owner drop.
    Selected,
    /// No further work; `end` retains the original reason.
    Stopped,
}
/// Caller-dispatched default-socket input classification; input ownership stays
/// with the caller in every case, so unrelated application data is never consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Not active for this owner, wrong source IP, or not an exact 36-byte probe.
    Unrelated,
    /// Exact original default socket/source-IP/length observation selected it.
    Selected,
}
