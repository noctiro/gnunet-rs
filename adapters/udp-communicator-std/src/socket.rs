//! One owned native UDP socket with retained atomic TX and explicit RX consumption.
//! Waiting futures borrow this owner; cancellation cannot recreate or drop its packet.
use gnunet_types::{Error, Rejected};
use gnunet_udp_communicator_core::send::{Datagram, Policy};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, net::UdpSocket};
use zeroize::{Zeroize, Zeroizing};
mod discovery;
const RECEIVE_BYTES: usize = 65536;
// A receipt outlives a mutable borrow and can survive an owner's Drop. A checked,
// never-reused process identity prevents collision after a socket move or rebind.
static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketId(u64);
impl SocketId {
    fn next() -> Result<Self, Error> {
        NEXT_SOCKET
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map(Self)
            .map_err(|_| Error::Overflow)
    }
}
/// Actual fixed source UDP payload profile, before Initial/BOX framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// 1480 - IPv4 header20 - UDP header8 = 1452 bytes.
    Ipv4,
    /// IPv6 minimum MTU1280 - IPv6 header40 - UDP header8 = 1232 bytes.
    Ipv6,
}
impl Profile {
    /// Exact normal source datagram payload size before optional rekey overhead.
    #[must_use]
    pub const fn datagram_bytes(self) -> usize {
        match self {
            Self::Ipv4 => 1452,
            Self::Ipv6 => 1232,
        }
    }
    /// Exact source initial application MTU, excluding KX48/confirmation104.
    #[must_use]
    pub const fn initial_mtu(self) -> usize {
        self.datagram_bytes() - 152
    }
    /// Exact source BOX application MTU, excluding BOX48.
    #[must_use]
    pub const fn boxed_mtu(self) -> usize {
        self.datagram_bytes() - 48
    }
    /// Fixed C adds the leading rekey36 to the original full BOX extent.
    #[must_use]
    pub const fn maximum_transmitted(self) -> usize {
        self.datagram_bytes() + 36
    }
    /// Default bounded sender choices using this actual socket family profile.
    #[must_use]
    pub fn sender_policy(self) -> Policy {
        Policy {
            datagram_bytes: self.datagram_bytes(),
            ..Policy::default()
        }
    }
    fn accepts(self, address: SocketAddr) -> bool {
        match (self, address) {
            (Self::Ipv4, SocketAddr::V4(_)) => true,
            (Self::Ipv6, SocketAddr::V6(v)) => v.ip().to_ipv4_mapped().is_none(),
            _ => false,
        }
    }
}
/// Native operation failure; actual OS errors retain their original cause.
#[derive(Debug)]
pub enum SocketError {
    /// Explicit resource/framing/lifecycle rejection.
    Core(Error),
    /// Original native socket failure.
    Io(io::Error),
}
impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(e) => write!(f, "UDP socket: {e}"),
            Self::Io(e) => write!(f, "UDP socket: {e}"),
        }
    }
}
impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(_) => None,
            Self::Io(e) => Some(e),
        }
    }
}
impl From<Error> for SocketError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
impl From<io::Error> for SocketError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
struct Pending {
    target: SocketAddr,
    packet: Datagram,
}
/// Local completion of one complete atomic UDP syscall. It is not delivery or
/// incoming flow-control authority and never replenishes cryptographic ACK credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sent {
    /// Original operation of the retained immutable packet.
    pub operation: u64,
    /// Actual native target used by this operation.
    pub target: SocketAddr,
    /// Complete bytes transferred by the single syscall.
    pub bytes: usize,
}
/// Receipt for one retained original datagram. Copies are diagnostics; the owner
/// checks the private original socket identity and generation before access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    owner: SocketId,
    generation: u64,
    address: SocketAddr,
    bytes: usize,
}
impl Receipt {
    /// Actual source address returned by the original receive syscall.
    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }
    /// Actual datagram payload extent; no native struct size is inferred.
    #[must_use]
    pub const fn len(self) -> usize {
        self.bytes
    }
    /// Whether the original datagram had a zero-length payload.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bytes == 0
    }
}
/// Sole socket/TX/RX reader. Bound default IPv6 sockets set IPV6_V6ONLY;
/// adopted utility scan descriptors keep their actual configuration. All IPv6
/// owners reject mapped-v4 destinations. Addresses do not assert peer identity.
pub struct DatagramSocket {
    owner: SocketId,
    socket: Option<Arc<UdpSocket>>,
    local: SocketAddr,
    profile: Profile,
    pending: Option<Pending>,
    discovery: Option<discovery::Pending>,
    receive: Zeroizing<Vec<u8>>,
    receipt: Option<Receipt>,
    generation: u64,
}
impl DatagramSocket {
    /// Bind a real nonblocking native socket inside an active Tokio IO runtime.
    /// Construction reserves one full65536-byte RX buffer before publication.
    pub fn bind(address: SocketAddr) -> Result<Self, SocketError> {
        let profile = if address.is_ipv4() {
            Profile::Ipv4
        } else {
            Profile::Ipv6
        };
        if !profile.accepts(address) {
            return Err(Error::InvalidInput.into());
        }
        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if profile == Profile::Ipv6 {
            socket.set_only_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        let standard: std::net::UdpSocket = socket.into();
        Self::adopt(UdpSocket::from_std(standard)?)
    }
    /// Adopt the exact actual scan descriptor; it is never rebound or cloned as
    /// another receive owner. Allocation precedes any publication of this owner.
    pub(crate) fn adopt(socket: UdpSocket) -> Result<Self, SocketError> {
        let local = socket.local_addr()?;
        let profile = if local.is_ipv4() {
            Profile::Ipv4
        } else {
            Profile::Ipv6
        };
        if local.port() == 0 || !profile.accepts(local) {
            return Err(Error::InvalidInput.into());
        }
        let mut receive = Vec::new();
        receive
            .try_reserve_exact(RECEIVE_BYTES)
            .map_err(|_| Error::Capacity)?;
        receive.resize(RECEIVE_BYTES, 0);
        Ok(Self {
            owner: SocketId::next()?,
            socket: Some(Arc::new(socket)),
            local,
            profile,
            pending: None,
            discovery: None,
            receive: Zeroizing::new(receive),
            receipt: None,
            generation: 0,
        })
    }
    /// Sharing is only for the public burst sender. Its API never reads this
    /// default socket: this DatagramSocket remains its sole reader/dispatcher.
    #[cfg(feature = "transport")]
    pub(crate) fn shared(&self) -> Result<Arc<UdpSocket>, Error> {
        self.socket.as_ref().cloned().ok_or(Error::Closed)
    }
    /// Original actual local endpoint, retained for teardown diagnostics.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local
    }
    /// Actual socket-family source payload profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    /// Admit exactly one original immutable prepared packet. Refusal returns that
    /// same owner. There is no implicit send, payload copy or nonce regeneration.
    pub fn queue(
        &mut self,
        target: SocketAddr,
        packet: Datagram,
    ) -> Result<(), Rejected<Datagram>> {
        let reason = if self.socket.is_none() {
            Some(Error::Stale)
        } else if self.has_pending_send() {
            Some(Error::Capacity)
        } else if !self.profile.accepts(target) {
            Some(Error::InvalidInput)
        } else if packet.bytes().len() > self.profile.maximum_transmitted() {
            Some(Error::TooLarge)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Rejected {
                reason,
                value: packet,
            });
        }
        self.pending = Some(Pending { target, packet });
        Ok(())
    }
    /// Inspect retained original TX bytes, including while its wait was cancelled.
    #[must_use]
    pub fn pending(&self) -> Option<(SocketAddr, &Datagram)> {
        self.pending.as_ref().map(|p| (p.target, &p.packet))
    }
    /// Explicitly cancel only the original native TX owner. Its core preparation
    /// has already burned a BOX sequence and no grant is fabricated by cancellation.
    pub fn cancel_send(&mut self) -> Option<(SocketAddr, Datagram)> {
        self.pending.take().map(|p| (p.target, p.packet))
    }
    /// Send the whole immutable datagram in one syscall. Pending and errors retain
    /// the same original packet; no suffix send or local delivery receipt exists.
    pub fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Sent, SocketError>> {
        let socket = self.socket.as_ref().ok_or(Error::Stale)?;
        let pending = self.pending.as_ref().ok_or(Error::NotReady)?;
        match socket.poll_send_to(cx, pending.packet.bytes(), pending.target) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(SocketError::Io(error))),
            Poll::Ready(Ok(n)) => {
                if n != pending.packet.bytes().len() {
                    return Poll::Ready(Err(SocketError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "atomic UDP send returned a short extent",
                    ))));
                }
                let sent = Sent {
                    operation: pending.packet.operation(),
                    target: pending.target,
                    bytes: n,
                };
                drop(self.pending.take());
                Poll::Ready(Ok(sent))
            }
        }
    }
    /// Await the same retained original TX. Dropping this future keeps ownership.
    pub async fn send(&mut self) -> Result<Sent, SocketError> {
        std::future::poll_fn(|cx| self.poll_send(cx)).await
    }
    /// Read one actual datagram into this owner's preallocated full-size buffer.
    /// Repeated polls return the same receipt until explicit consumption; waiting
    /// cancellation cannot consume a second packet or lose the original payload.
    pub fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<Receipt, SocketError>> {
        if let Some(receipt) = self.receipt {
            return Poll::Ready(Ok(receipt));
        }
        let socket = self.socket.as_ref().ok_or(Error::Stale)?;
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let mut buffer = ReadBuf::new(&mut self.receive);
        match socket.poll_recv_from(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(SocketError::Io(error))),
            Poll::Ready(Ok(address)) => {
                let bytes = buffer.filled().len();
                if bytes == RECEIVE_BYTES {
                    self.receive.as_mut_slice().zeroize();
                    return Poll::Ready(Err(Error::TooLarge.into()));
                }
                let receipt = Receipt {
                    owner: self.owner,
                    generation,
                    address,
                    bytes,
                };
                self.generation = generation;
                self.receipt = Some(receipt);
                Poll::Ready(Ok(receipt))
            }
        }
    }
    /// Await the same original RX slot. Dropping this future keeps ownership.
    pub async fn receive(&mut self) -> Result<Receipt, SocketError> {
        std::future::poll_fn(|cx| self.poll_receive(cx)).await
    }
    /// Borrow only this original socket/generation's actual payload extent.
    pub fn bytes(&self, receipt: Receipt) -> Result<&[u8], Error> {
        if self.receipt != Some(receipt) {
            return Err(Error::Stale);
        }
        Ok(&self.receive[..receipt.bytes])
    }
    /// Retire exactly the original datagram after authentication or explicit
    /// rejection. Plaintext/ciphertext scratch is erased before the next receive.
    pub fn consume(&mut self, receipt: Receipt) -> Result<(), Error> {
        if self.receipt != Some(receipt) {
            return Err(Error::Stale);
        }
        self.receive[..receipt.bytes].zeroize();
        self.receipt = None;
        Ok(())
    }
    /// This owner has released its socket handle. Other explicit Arc owners may
    /// still retain the OS descriptor; this is distinct from having no IO debt.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.socket.is_none()
    }
    /// No retained native send or received datagram remains. An open socket by
    /// itself is not a callback, delivery receipt or hidden background operation.
    #[must_use]
    pub const fn is_quiescent(&self) -> bool {
        self.pending.is_none() && self.discovery.is_none() && self.receipt.is_none()
    }
    /// Retire the real socket and erase buffered original data. Prepared unsent
    /// packet owners drop here; their cryptographic sequences remain burned.
    pub fn close(&mut self) {
        drop(self.socket.take());
        self.retire_packets();
    }
    /// Retire original packet slots while the process keeps its sole socket
    /// reader. Old receipts cannot regain access after a generation cut.
    pub(crate) fn retire_packets(&mut self) {
        self.discovery = None;
        drop(self.pending.take());
        self.receive.as_mut_slice().zeroize();
        self.receipt = None;
    }
}
