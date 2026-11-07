//! Official direct-IP DHT datagrams. This owner adds no handshake, encryption,
//! fragmentation, retry or acknowledgement. An incoming identity is a claim;
//! a successful send is only the actual local datagram syscall result.
use gnunet_types::Error as Fault;
use gnunet_wire::official::core::PeerId as PeerIdentity;
use std::{
    cell::{Cell, RefCell},
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    sync::Arc,
    task::Waker,
};
use tokio::time::Instant;
mod addresses;
mod client;
pub use client::Client;
/// Largest standard IPv6 UDP payload without jumbograms, including our envelope.
pub const MAX_DATAGRAM_BYTES: usize = 65_527;
/// Largest single IPv6 DHT frame after the official 32-byte identity.
pub const MAX_FRAME_BYTES: usize = MAX_DATAGRAM_BYTES - 32;
/// Largest standard IPv4 UDP payload, including our identity envelope.
pub const V4_MAX_DATAGRAM_BYTES: usize = 65_507;
/// Largest single IPv4 DHT frame after the official 32-byte identity.
pub const V4_MAX_FRAME_BYTES: usize = V4_MAX_DATAGRAM_BYTES - 32;
fn datagram_limit(endpoint: SocketAddr) -> usize {
    match endpoint {
        SocketAddr::V4(_) => V4_MAX_DATAGRAM_BYTES,
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => V4_MAX_DATAGRAM_BYTES,
        SocketAddr::V6(_) => MAX_DATAGRAM_BYTES,
    }
}
/// Explicit finite native storage and original official underlay configuration.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// None binds available IPv4/IPv6 wildcards, skipping only explicitly
    /// unsupported native families; Some strictly binds that numeric family.
    pub bind: Option<IpAddr>,
    /// Official UDP_PORT; zero requests an actual ephemeral bound port.
    pub port: u16,
    /// Official configured IP network-size estimate, not a received NSE proof.
    pub network_size: u64,
    /// Maximum live or retiring endpoint generations.
    pub targets: usize,
    /// Maximum queued original datagrams.
    pub sends: usize,
    /// Maximum aggregate actual queued datagram buffer capacities.
    pub send_bytes: usize,
    /// Maximum simultaneously owned incoming packet buffers, including callers.
    pub packets: usize,
    /// Complete actual getifaddrs snapshot bounds.
    pub interfaces: gnunet_native::interfaces::Limits,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            bind: None,
            port: 6666,
            network_size: 4,
            targets: 256,
            sends: 64,
            send_bytes: 8 * 1024 * 1024,
            packets: 4,
            interfaces: gnunet_native::interfaces::Limits::default(),
        }
    }
}
/// One caller-owned native source domain. Generations are never reused.
#[derive(Debug, Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Create an empty domain, without sockets or tasks.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    fn next(&self) -> Result<u64, Error> {
        let next = self.next.get().checked_add(1).ok_or(Fault::Overflow)?;
        self.next.set(next);
        Ok(next)
    }
}
/// Original endpoint generation and its presumed public identity, not an
/// authenticated CORE peer. Only this underlay can construct one.
#[derive(Clone, Copy, Debug)]
pub struct Peer<'id> {
    instance: &'id Instance,
    serial: u64,
    identity: PeerIdentity,
    endpoint: SocketAddr,
}
impl PartialEq for Peer<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.instance, other.instance) && self.serial == other.serial
    }
}
impl Eq for Peer<'_> {}
impl Peer<'_> {
    /// Exact expected or actually received identity claim.
    #[must_use]
    pub const fn identity(self) -> PeerIdentity {
        self.identity
    }
    /// Original numeric native endpoint.
    #[must_use]
    pub const fn endpoint(self) -> SocketAddr {
        self.endpoint
    }
    /// Maximum frame for this exact endpoint's real address family. IPv4-mapped
    /// addresses obey IPv4's smaller limit, independently of enabled sockets.
    #[must_use]
    pub fn frame_limit(self) -> usize {
        datagram_limit(self.endpoint) - 32
    }
    /// Local diagnostic generation, never wire authority.
    #[must_use]
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
/// One original datagram admission, not a remote delivery receipt.
#[derive(Clone, Copy, Debug)]
pub struct SendId<'id> {
    instance: &'id Instance,
    serial: u64,
}
impl PartialEq for SendId<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.instance, other.instance) && self.serial == other.serial
    }
}
impl Eq for SendId<'_> {}
impl SendId<'_> {
    /// Original diagnostic generation.
    #[must_use]
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
/// Actual configured socket/interface address, without reachability authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    /// Original native address and actual bound port, retaining IPv6 scope.
    pub endpoint: SocketAddr,
    url: String,
}
impl Address {
    /// Exact numeric official ip+udp URL bytes.
    #[must_use]
    pub fn url(&self) -> &[u8] {
        self.url.as_bytes()
    }
}
#[derive(Debug)]
struct Stamp {
    buffers: RefCell<Vec<Vec<u8>>>,
    waker: RefCell<Option<Waker>>,
}
/// One actual complete received datagram. Return it to its original client with
/// release; dropping it also returns the exact original buffer credit.
pub struct Packet<'id> {
    owner: Rc<Stamp>,
    peer: Peer<'id>,
    bytes: Vec<u8>,
    length: usize,
}
impl<'id> Packet<'id> {
    /// Exact original presumed sender/source generation.
    #[must_use]
    pub const fn peer(&self) -> Peer<'id> {
        self.peer
    }
    /// Exactly one validated DHT frame, without its identity envelope.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.bytes[32..self.length]
    }
}
impl Drop for Packet<'_> {
    fn drop(&mut self) {
        // The fixed initialized buffer stays whole; only length is public.
        // Recycling a tiny packet need not clear or resize 64 KiB of storage.
        let bytes = std::mem::take(&mut self.bytes);
        self.owner.buffers.borrow_mut().push(bytes);
        if let Some(waker) = self.owner.waker.borrow().as_ref() {
            waker.wake_by_ref();
        }
    }
}
impl fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpPacket")
            .field("peer", &self.peer)
            .field("frame_bytes", &(self.length - 32))
            .finish()
    }
}
/// Why this original endpoint is being physically retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectReason {
    /// Explicit original source stop.
    Closed,
    /// Actual local PILS identity changed.
    IdentityChanged,
    /// Bounded endpoint capacity evicted this least-preferred/oldest owner.
    Evicted,
    /// The same native address presented another identity claim.
    ClaimChanged,
}
/// Original local datagram disposition. None asserts remote processing.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// One full original datagram was accepted by the actual socket syscall.
    Written,
    /// Caller cancelled before this datagram was sent.
    Cancelled,
    /// The original fixed native deadline elapsed before sending.
    Deadline,
    /// The original endpoint/source retired before sending.
    Disconnected(DisconnectReason),
    /// The actual send syscall failed; no replacement attempt is made.
    Failed(Arc<io::Error>),
}
/// One actual underlay observation. Connected is endpoint admission, not an
/// authenticated handshake, and Finished reports only original local IO.
#[derive(Debug)]
pub enum Event<'id> {
    /// Original endpoint is available for local datagram admission.
    Connected(Peer<'id>),
    /// All pending sends of this exact endpoint have returned before retirement.
    Disconnected {
        /// Original retired endpoint.
        peer: Peer<'id>,
        /// Actual retirement cause.
        reason: DisconnectReason,
    },
    /// Original complete actual incoming datagram, owning one buffer credit.
    Message(Packet<'id>),
    /// Original datagram terminal fact, emitted exactly once.
    Finished {
        /// Original admission.
        send: SendId<'id>,
        /// Original endpoint generation.
        peer: Peer<'id>,
        /// Actual local outcome.
        outcome: Outcome,
        /// Actual socket-written bytes including the 32-byte envelope.
        written: usize,
        /// Original DHT frame length excluding its envelope.
        frame_bytes: usize,
    },
    /// A complete actual interface/binding snapshot changed.
    AddressesChanged {
        /// Monotonic address bytes or complete-snapshot validity revision.
        revision: u64,
    },
    /// A complete refresh failed; the prior snapshot was retained unchanged.
    AddressRefreshFailed(io::Error),
    /// An isolated native datagram/network error or interrupted receive.
    /// This does not identify a remote endpoint or revise an earlier send fact.
    ReceiveError {
        /// Actual bound socket on which the receive returned this error.
        local: SocketAddr,
        /// Original native error; the socket remains available for later IO.
        error: io::Error,
    },
    /// An actual incoming datagram was refused without changing a peer owner.
    Discarded {
        /// Actual datagram source.
        endpoint: SocketAddr,
        /// Actual framing/admission refusal.
        reason: Fault,
    },
    /// Actual sockets closed and all original endpoint/send terminal debt drained.
    Closed,
}
/// Original configuration/framing or native IO refusal.
#[derive(Debug)]
pub enum Error {
    /// Original typed local protocol/resource error.
    Protocol(Fault),
    /// Original socket/interface error.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(value: Fault) -> Self {
        Self::Protocol(value)
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Focused native loopback cases assert original datagram, generation, buffer and retirement facts; setup failures are returned"
)]
mod tests;
