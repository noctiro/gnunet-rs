use super::*;
use gnunet_wire::official::Frame;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    future::Future,
    net::UdpSocket as StdSocket,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    time::{Sleep, sleep_until},
};
const SCAN_INTERVAL: Duration = Duration::from_secs(60);
struct Target<'id> {
    peer: Peer<'id>,
    preferred: bool,
    touched: u64,
    announced: bool,
    retiring: Option<DisconnectReason>,
}
struct Sending<'id> {
    id: SendId<'id>,
    peer: Peer<'id>,
    bytes: Vec<u8>,
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
    cancelled: bool,
}
struct Binding {
    socket: UdpSocket,
    local: SocketAddr,
}
/// Caller-polled bounded direct-IP owner. Construction and polling require a
/// Tokio IO/time context; no worker, detached task or retransmission is started.
pub struct Client<'id> {
    instance: &'id Instance,
    config: Config,
    stamp: Rc<Stamp>,
    identity: Option<[u8; 32]>,
    changing: bool,
    sockets: Vec<Binding>,
    bound: Vec<SocketAddr>,
    targets: Vec<Target<'id>>,
    sends: VecDeque<Sending<'id>>,
    send_bytes: usize,
    addresses: Vec<Address>,
    address_revision: u64,
    addresses_current: bool,
    address_changed: bool,
    refresh: Pin<Box<Sleep>>,
    next_read: usize,
    send_first: bool,
    packet: Option<Packet<'id>>,
    closing: bool,
    closed: bool,
}
fn vector<T>(count: usize) -> Result<Vec<T>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(count)
        .map_err(|_| Fault::Capacity)?;
    Ok(value)
}
fn socket_buffers(socket: &UdpSocket) -> io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    let requested = 2 * MAX_DATAGRAM_BYTES;
    socket.set_send_buffer_size(requested)?;
    socket.set_recv_buffer_size(requested)?;
    if socket.send_buffer_size()? < MAX_DATAGRAM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DHT IP send buffer cannot hold a maximum datagram",
        ));
    }
    if socket.recv_buffer_size()? < MAX_DATAGRAM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DHT IP receive buffer cannot hold a maximum datagram",
        ));
    }
    Ok(())
}
fn isolated_receive_error(error: &io::Error) -> bool {
    // UDP may report asynchronous errors for earlier datagrams on this socket
    // (udp(7)); neither a current peer nor an earlier send can be inferred.
    // EINTR only interrupts this receive. Return once instead of retrying here.
    // Resource failures (including ENOBUFS/ENOMEM), bad descriptors and opaque
    // registration errors keep the original source-failure path.
    matches!(
        error.raw_os_error(),
        Some(
            libc::ECONNREFUSED
                | libc::ENETUNREACH
                | libc::EHOSTUNREACH
                | libc::EMSGSIZE
                | libc::EINTR
        )
    )
}
fn bind(endpoint: SocketAddr) -> io::Result<Binding> {
    let socket = Socket::new(
        if endpoint.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if endpoint.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&endpoint.into())?;
    let socket = UdpSocket::from_std(StdSocket::from(socket))?;
    let local = socket.local_addr()?;
    Ok(Binding { socket, local })
}
fn family_unavailable(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT)
    )
}
impl<'id> Client<'id> {
    /// Bind the actual configured numeric sockets and snapshot real interfaces.
    /// No CORE, resolver, NSE service or private key is opened by this owner.
    pub fn new(instance: &'id mut Instance, config: Config) -> Result<Self, Error> {
        if config.targets == 0
            || config.targets > 65_536
            || config.sends == 0
            || config.sends > 65_536
            || config.packets == 0
            || config.packets > 1024
            || config.send_bytes < 36
            || config.interfaces.addresses > 65_536
        {
            return Err(Fault::InvalidInput.into());
        }
        let mut sockets = vector(2)?;
        match config.bind {
            Some(ip) => sockets.push(bind(SocketAddr::new(ip, config.port))?),
            None => {
                let mut port = config.port;
                let mut unavailable = None;
                for ip in [
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ] {
                    match bind(SocketAddr::new(ip, port)) {
                        Ok(binding) => {
                            port = binding.local.port();
                            sockets.push(binding);
                        }
                        Err(error) if family_unavailable(&error) => unavailable = Some(error),
                        Err(error) => return Err(error.into()),
                    }
                }
                if sockets.is_empty() {
                    return Err(unavailable
                        .unwrap_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::Unsupported,
                                "no IP datagram family available",
                            )
                        })
                        .into());
                }
            }
        }
        // Buffer setup is outside family-unavailable fallback: a failed option
        // or insufficient readback is an original construction failure, never
        // silently converted into a successful reduced-family owner.
        for binding in &sockets {
            socket_buffers(&binding.socket)?;
        }
        let mut bound = vector(sockets.len())?;
        bound.extend(sockets.iter().map(|socket| socket.local));
        let addresses = addresses::snapshot(config, &bound)?;
        let mut buffers = vector(config.packets)?;
        for _ in 0..config.packets {
            let mut buffer = vector(65_536)?;
            buffer.resize(65_536, 0);
            buffers.push(buffer);
        }
        let mut sends = VecDeque::new();
        sends
            .try_reserve_exact(config.sends)
            .map_err(|_| Fault::Capacity)?;
        let targets = vector(config.targets)?;
        let refresh = Box::pin(sleep_until(Instant::now() + SCAN_INTERVAL));
        Ok(Self {
            instance,
            config,
            stamp: Rc::new(Stamp {
                buffers: RefCell::new(buffers),
                waker: RefCell::new(None),
            }),
            identity: None,
            changing: false,
            sockets,
            bound,
            targets,
            sends,
            send_bytes: 0,
            addresses,
            address_revision: 1,
            addresses_current: true,
            address_changed: true,
            refresh,
            next_read: 0,
            send_first: true,
            packet: None,
            closing: false,
            closed: false,
        })
    }
    /// Apply an actual PILS identity. Changing it first retires every old
    /// endpoint/send; new admission waits until those original facts drain.
    pub fn set_identity(&mut self, identity: [u8; 32]) -> Result<(), Error> {
        if self.closing {
            return Err(Fault::Closed.into());
        }
        if self.identity != Some(identity) {
            for target in &mut self.targets {
                target
                    .retiring
                    .get_or_insert(DisconnectReason::IdentityChanged);
            }
            self.changing = !self.targets.is_empty();
            self.packet = None;
            self.identity = Some(identity);
            self.wake();
        }
        Ok(())
    }
    /// Current applied actual PILS identity, independently of old retirement debt.
    #[must_use]
    pub const fn identity(&self) -> Option<[u8; 32]> {
        self.identity
    }
    /// Actual socket binding products, including an actual ephemeral port.
    #[must_use]
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.bound
    }
    /// Maximum frame carried by at least one actually bound family. A single
    /// available IPv4 socket never advertises the larger IPv6 admission bound;
    /// no live sockets (after close) returns zero.
    #[must_use]
    pub fn frame_limit(&self) -> usize {
        self.sockets
            .iter()
            .map(|socket| datagram_limit(socket.local) - 32)
            .max()
            .unwrap_or(0)
    }
    /// Last complete actual interface/binding snapshot.
    #[must_use]
    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }
    /// Monotonic address bytes/validity revision. Losing snapshot validity also
    /// fences a not-yet-published address signature's original context.
    #[must_use]
    pub const fn address_revision(&self) -> u64 {
        self.address_revision
    }
    /// Whether the retained addresses came from the latest complete successful
    /// snapshot. Failure retains historical bytes, which cannot justify a new
    /// signed expiration until an actual complete refresh succeeds.
    #[must_use]
    pub const fn addresses_current(&self) -> bool {
        self.addresses_current
    }
    /// Original configured IP network-size estimate, without a subscription.
    #[must_use]
    pub const fn network_size(&self) -> u64 {
        self.config.network_size
    }
    fn wake(&self) {
        if let Some(waker) = self.stamp.waker.borrow().as_ref() {
            waker.wake_by_ref();
        }
    }
    fn live(&self) -> Result<(), Error> {
        if self.closing {
            Err(Fault::Closed.into())
        } else if self.identity.is_none() || self.changing {
            Err(Fault::NotReady.into())
        } else {
            Ok(())
        }
    }
    fn target(&self, peer: Peer<'id>) -> Result<usize, Error> {
        if !std::ptr::eq(peer.instance, self.instance) {
            return Err(Fault::StaleGeneration.into());
        }
        self.targets
            .iter()
            .position(|target| target.peer == peer)
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    fn retire(&mut self, index: usize, reason: DisconnectReason) {
        let peer = self.targets[index].peer;
        self.targets[index].retiring.get_or_insert(reason);
        if self
            .packet
            .as_ref()
            .is_some_and(|packet| packet.peer == peer)
        {
            self.packet = None;
        }
        self.wake();
    }
    fn admit(&mut self, identity: [u8; 32], endpoint: SocketAddr) -> Result<Peer<'id>, Error> {
        self.live()?;
        if Some(identity) == self.identity {
            return Err(Fault::InvalidInput.into());
        }
        if !self
            .sockets
            .iter()
            .any(|socket| socket.local.is_ipv4() == endpoint.is_ipv4())
        {
            return Err(Fault::Unsupported.into());
        }
        if let Some(index) = self
            .targets
            .iter()
            .position(|target| target.peer.endpoint == endpoint)
        {
            let target = &mut self.targets[index];
            if target.retiring.is_some() {
                return Err(Fault::WouldBlock.into());
            }
            if target.peer.identity.0 != identity {
                self.retire(index, DisconnectReason::ClaimChanged);
                return Err(Fault::WouldBlock.into());
            }
            target.touched = self.instance.next()?;
            return Ok(target.peer);
        }
        if self.targets.len() == self.config.targets {
            if self.targets.iter().any(|target| target.retiring.is_some()) {
                return Err(Fault::WouldBlock.into());
            }
            if let Some(index) = self
                .targets
                .iter()
                .enumerate()
                .filter(|(_, target)| target.retiring.is_none())
                .min_by_key(|(_, target)| (target.preferred, target.touched))
                .map(|(index, _)| index)
            {
                self.retire(index, DisconnectReason::Evicted);
            }
            return Err(Fault::WouldBlock.into());
        }
        let serial = self.instance.next()?;
        let peer = Peer {
            instance: self.instance,
            serial,
            identity: PeerIdentity(identity),
            endpoint,
        };
        self.targets.push(Target {
            peer,
            preferred: false,
            touched: serial,
            announced: false,
            retiring: None,
        });
        self.wake();
        Ok(peer)
    }
    /// Admit one numeric official address hint. This is not a completed remote
    /// handshake. WouldBlock can request an old target's retirement; retry only
    /// the caller's still-current original hint after its terminal facts drain.
    pub fn try_connect(&mut self, identity: [u8; 32], url: &[u8]) -> Result<Peer<'id>, Error> {
        let port = if self.config.port == 0 {
            self.bound.first().ok_or(Fault::Closed)?.port()
        } else {
            self.config.port
        };
        self.admit(identity, addresses::endpoint(url, port)?)
    }
    /// Retain/drop the preference on the exact original endpoint generation.
    pub fn set_preference(&mut self, peer: Peer<'id>, preferred: bool) -> Result<(), Error> {
        let index = self.target(peer)?;
        if self.targets[index].retiring.is_some() {
            return Err(Fault::Closed.into());
        }
        self.targets[index].preferred = preferred;
        Ok(())
    }
    /// Observe original peer and bounded queue/byte credit without allocation,
    /// new IO, a clock sample or admission. The caller still guards its original
    /// deadline; send independently rechecks that fixed target before native IO.
    pub fn request_available(&self, peer: Peer<'id>, frame_bytes: usize) -> Result<bool, Error> {
        self.live()?;
        let index = self.target(peer)?;
        if self.targets[index].retiring.is_some() {
            return Err(Fault::Closed.into());
        }
        if frame_bytes < 4 {
            return Err(Fault::InvalidInput.into());
        }
        if frame_bytes > peer.frame_limit() {
            return Err(Fault::TooLarge.into());
        }
        Ok(self.sends.len() < self.config.sends
            && self
                .send_bytes
                .checked_add(32 + frame_bytes)
                .is_some_and(|bytes| bytes <= self.config.send_bytes))
    }
    /// Copy one complete official DHT frame once into its original bounded
    /// datagram. Its fixed native deadline is never renewed or retransmitted.
    pub fn send(
        &mut self,
        peer: Peer<'id>,
        frame: &[u8],
        hard: Instant,
    ) -> Result<SendId<'id>, Error> {
        self.live()?;
        let index = self.target(peer)?;
        if self.targets[index].retiring.is_some() {
            return Err(Fault::Closed.into());
        }
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        if frame.len() > peer.frame_limit() {
            return Err(Fault::TooLarge.into());
        }
        Frame::decode(frame)?;
        if self.sends.len() == self.config.sends {
            return Err(Fault::WouldBlock.into());
        }
        let length = 32 + frame.len();
        if self
            .send_bytes
            .checked_add(length)
            .is_none_or(|bytes| bytes > self.config.send_bytes)
        {
            return Err(Fault::WouldBlock.into());
        }
        let mut bytes = vector(length)?;
        let charge = self
            .send_bytes
            .checked_add(bytes.capacity())
            .ok_or(Fault::Overflow)?;
        if charge > self.config.send_bytes {
            return Err(Fault::WouldBlock.into());
        }
        bytes.extend_from_slice(&self.identity.ok_or(Fault::NotReady)?);
        bytes.extend_from_slice(frame);
        let id = SendId {
            instance: self.instance,
            serial: self.instance.next()?,
        };
        self.sends.push_back(Sending {
            id,
            peer,
            bytes,
            hard,
            alarm: Box::pin(sleep_until(hard)),
            cancelled: false,
        });
        self.send_bytes = charge;
        self.wake();
        Ok(id)
    }
    /// Stop this exact queued original datagram without sending or replaying it.
    pub fn cancel(&mut self, id: SendId<'id>) -> Result<(), Error> {
        let send = self
            .sends
            .iter_mut()
            .find(|send| send.id == id)
            .ok_or(Fault::StaleGeneration)?;
        send.cancelled = true;
        self.wake();
        Ok(())
    }
    /// Return an original packet credit. Drop also returns its exact buffer;
    /// another owner's packet can never replenish this owner's buffer pool.
    pub fn release(&mut self, packet: Packet<'id>) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.stamp, &packet.owner) {
            return Err(Fault::StaleGeneration.into());
        }
        drop(packet);
        Ok(())
    }
    /// Close actual sockets immediately, without sampling a clock. Poll until
    /// every original send/endpoint fate and the final Closed fact are returned.
    pub fn close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.sockets.clear();
        self.packet = None;
        self.addresses.clear();
        self.addresses_current = false;
        for target in &mut self.targets {
            target.retiring.get_or_insert(DisconnectReason::Closed);
        }
        self.wake();
    }
    fn finished(
        &mut self,
        index: usize,
        outcome: Outcome,
        written: usize,
    ) -> Result<Event<'id>, Error> {
        let send = self.sends.remove(index).ok_or(Fault::Stale)?;
        self.send_bytes = self
            .send_bytes
            .checked_sub(send.bytes.capacity())
            .ok_or(Fault::Overflow)?;
        Ok(Event::Finished {
            send: send.id,
            peer: send.peer,
            outcome,
            written,
            frame_bytes: send.bytes.len() - 32,
        })
    }
    fn sends(&mut self, cx: &mut Context<'_>, write: bool) -> Result<Option<Event<'id>>, Error> {
        for index in 0..self.sends.len() {
            let send = &mut self.sends[index];
            let target = self
                .targets
                .iter()
                .find(|target| target.peer == send.peer)
                .ok_or(Fault::Stale)?;
            if let Some(reason) = target.retiring {
                return self
                    .finished(index, Outcome::Disconnected(reason), 0)
                    .map(Some);
            }
            if send.cancelled {
                return self.finished(index, Outcome::Cancelled, 0).map(Some);
            }
            if Instant::now() >= send.hard || send.alarm.as_mut().poll(cx).is_ready() {
                return self.finished(index, Outcome::Deadline, 0).map(Some);
            }
        }
        if !write {
            return Ok(None);
        }
        for index in 0..self.sends.len() {
            let send = &self.sends[index];
            if Instant::now() >= send.hard {
                return self.finished(index, Outcome::Deadline, 0).map(Some);
            }
            let socket = self
                .sockets
                .iter()
                .find(|socket| socket.local.is_ipv4() == send.peer.endpoint.is_ipv4())
                .ok_or(Fault::Closed)?;
            match socket
                .socket
                .poll_send_to(cx, &send.bytes, send.peer.endpoint)
            {
                Poll::Pending => {}
                Poll::Ready(Ok(written)) if written == send.bytes.len() => {
                    return self.finished(index, Outcome::Written, written).map(Some);
                }
                Poll::Ready(Ok(written)) => {
                    return self
                        .finished(
                            index,
                            Outcome::Failed(Arc::new(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "short UDP datagram write",
                            ))),
                            written,
                        )
                        .map(Some);
                }
                Poll::Ready(Err(error)) => {
                    return self
                        .finished(index, Outcome::Failed(Arc::new(error)), 0)
                        .map(Some);
                }
            }
        }
        Ok(None)
    }
    /// Check original cancellation, retirement and fixed send deadlines without
    /// new IO or a logical-clock sample. A host may call this before canonical
    /// clock stabilization so existing native bounds cannot be postponed.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<Option<Event<'id>>, Error> {
        *self.stamp.waker.borrow_mut() = Some(cx.waker().clone());
        self.sends(cx, false)
    }
    fn receive(&mut self, cx: &mut Context<'_>) -> Result<Option<Event<'id>>, Error> {
        let Some(mut bytes) = self.stamp.buffers.borrow_mut().pop() else {
            return Ok(None);
        };
        for offset in 0..self.sockets.len() {
            let index = (self.next_read + offset) % self.sockets.len();
            let mut buffer = ReadBuf::new(&mut bytes);
            if let Poll::Ready(result) = self.sockets[index].socket.poll_recv_from(cx, &mut buffer)
            {
                let received = result.map(|endpoint| (buffer.filled().len(), endpoint));
                return self.recv_result(index, bytes, received);
            }
        }
        self.stamp.buffers.borrow_mut().push(bytes);
        Ok(None)
    }
    fn recv_result(
        &mut self,
        index: usize,
        bytes: Vec<u8>,
        received: io::Result<(usize, SocketAddr)>,
    ) -> Result<Option<Event<'id>>, Error> {
        // Errors consume this turn just as a datagram does. The next call starts
        // with the other bound family, with no immediate retry or self-wake.
        self.next_read = (index + 1) % self.sockets.len();
        let (length, endpoint) = match received {
            Ok(received) => received,
            Err(error) => {
                self.stamp.buffers.borrow_mut().push(bytes);
                return if isolated_receive_error(&error) {
                    Ok(Some(Event::ReceiveError {
                        local: self.sockets[index].local,
                        error,
                    }))
                } else {
                    Err(error.into())
                };
            }
        };
        let endpoint = addresses::normalize(endpoint);
        let parsed = (|| -> Result<[u8; 32], Error> {
            if length > datagram_limit(endpoint) || length > bytes.len() {
                return Err(Fault::TooLarge.into());
            }
            if length < 36 {
                return Err(Fault::Truncated.into());
            }
            Frame::decode(&bytes[32..length])?;
            bytes[..32].try_into().map_err(|_| Fault::Truncated.into())
        })();
        let peer = parsed.and_then(|identity| self.admit(identity, endpoint));
        match peer {
            Ok(peer) => {
                self.packet = Some(Packet {
                    owner: self.stamp.clone(),
                    peer,
                    bytes,
                    length,
                });
                if let Some(target) = self
                    .targets
                    .iter_mut()
                    .find(|target| target.peer == peer && !target.announced)
                {
                    target.announced = true;
                    return Ok(Some(Event::Connected(peer)));
                }
                Ok(self.packet.take().map(Event::Message))
            }
            Err(error) => {
                self.stamp.buffers.borrow_mut().push(bytes);
                let Error::Protocol(reason) = error else {
                    return Err(error);
                };
                Ok(Some(Event::Discarded { endpoint, reason }))
            }
        }
    }
    #[cfg(test)]
    pub(super) fn inject_receive_error(
        &mut self,
        error: io::Error,
    ) -> Result<Option<Event<'id>>, Error> {
        let bytes = self
            .stamp
            .buffers
            .borrow_mut()
            .pop()
            .ok_or(Fault::NotReady)?;
        self.recv_result(self.next_read, bytes, Err(error))
    }
    /// Drive finite original work and real socket/deadline/refresh wakes. Each
    /// call performs at most one terminal send or one received datagram.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'id>, Error>> {
        *self.stamp.waker.borrow_mut() = Some(cx.waker().clone());
        if !self.closing && self.refresh.as_mut().poll(cx).is_ready() {
            self.refresh.as_mut().reset(Instant::now() + SCAN_INTERVAL);
            match addresses::snapshot(self.config, &self.bound) {
                Ok(addresses) if addresses != self.addresses || !self.addresses_current => {
                    let revision = self
                        .address_revision
                        .checked_add(1)
                        .ok_or(Fault::Overflow)?;
                    self.addresses = addresses;
                    self.address_revision = revision;
                    self.addresses_current = true;
                    self.address_changed = true;
                }
                Ok(_) => {}
                Err(error) => {
                    if self.addresses_current {
                        self.address_revision = self
                            .address_revision
                            .checked_add(1)
                            .ok_or(Fault::Overflow)?;
                        self.addresses_current = false;
                    }
                    self.address_changed = false;
                    return Poll::Ready(Ok(Event::AddressRefreshFailed(error)));
                }
            }
        }
        if let Some(target) = self
            .targets
            .iter_mut()
            .find(|target| !target.announced && target.retiring.is_none())
        {
            target.announced = true;
            return Poll::Ready(Ok(Event::Connected(target.peer)));
        }
        // Terminal debt precedes receive work, including during source change
        // and close. Normal socket writes and reads alternate below.
        if let Some(event) = self.sends(cx, false)? {
            return Poll::Ready(Ok(event));
        }
        if let Some(index) = self.targets.iter().position(|target| {
            target.retiring.is_some() && !self.sends.iter().any(|send| send.peer == target.peer)
        }) {
            let target = self.targets.remove(index);
            let reason = target.retiring.ok_or(Fault::Stale)?;
            if self.targets.is_empty() {
                self.changing = false;
            }
            return Poll::Ready(Ok(Event::Disconnected {
                peer: target.peer,
                reason,
            }));
        }
        if self.targets.is_empty() {
            self.changing = false;
        }
        if self.closing {
            if !self.closed {
                self.closed = true;
                return Poll::Ready(Ok(Event::Closed));
            }
            return Poll::Pending;
        }
        if let Some(packet) = self.packet.take() {
            return Poll::Ready(Ok(Event::Message(packet)));
        }
        if self.address_changed {
            self.address_changed = false;
            return Poll::Ready(Ok(Event::AddressesChanged {
                revision: self.address_revision,
            }));
        }
        if self.identity.is_none() || self.changing {
            return Poll::Pending;
        }
        for write in [self.send_first, !self.send_first] {
            let event = if write {
                self.sends(cx, true)?
            } else {
                self.receive(cx)?
            };
            if let Some(event) = event {
                self.send_first = !write;
                return Poll::Ready(Ok(event));
            }
        }
        Poll::Pending
    }
}
