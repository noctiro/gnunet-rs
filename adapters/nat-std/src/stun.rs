//! Actual original bound-UDP STUN sender. Polling is caller-driven and every
//! sent transaction survives a dropped drive future in this owner. Received
//! datagrams stay with the application's original UDP dispatcher.
use crate::{
    Error,
    deadline::{Bounds, Gate},
    interfaces::{native, portable},
    resolve::Lookup,
};
use gnunet_client_host::resolution::SharedResolution;
use gnunet_nat::{
    address::SocketAddress,
    stun::{self, Transaction},
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    future::poll_fn,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::UdpSocket;
/// Explicit bounded request policy; no socket is created by this type.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual Resolver addresses/transactions.
    pub addresses: usize,
    /// Enable standard IPv6 STUN when the caller socket isIPv6.
    pub ipv6: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            addresses: 32,
            ipv6: false,
        }
    }
}
/// Actual local send facts, never a mapped address/reachability receipt.
#[derive(Debug)]
pub enum Event {
    /// A complete20-byte datagram was written on the original supplied socket.
    Written {
        /// Original server endpoint.
        server: SocketAddress,
        /// Original public transaction id.
        transaction: [u8; 12],
    },
    /// Actual send failure for this original server; other original attempts can continue.
    SendFailed {
        /// Original endpoint.
        server: SocketAddress,
        /// Actual IO error, never replaced by a success.
        error: std::io::Error,
    },
    /// Actual END of the original Resolver stream and all admitted sends.
    Finished {
        /// Number of actual whole-datagram writes.
        written: usize,
        /// Number of actual socket send failures.
        failed: usize,
    },
    /// One actual DNS callback was processed. It is not a native write.
    Activity,
}
struct Attempt {
    transaction: Transaction,
    packet: [u8; 20],
}
/// Owned original STUN job with finite absolute/native bounds and explicit
/// cancellation. It never reads from/steals the caller's application socket.
pub struct Request {
    socket: Arc<UdpSocket>,
    gate: Gate,
    lookup: Lookup,
    limits: Limits,
    port: u16,
    index: usize,
    pending: Option<Attempt>,
    transactions: Vec<Transaction>,
    failed: usize,
    finished: bool,
    cancelled: bool,
}
impl Request {
    /// Start real selected-Resolver DNS and reserve the original bounded clock
    /// listener. The UDP socket has already been actually bound by the caller.
    pub fn start(
        resolver: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        socket: Arc<UdpSocket>,
        server: &[u8],
        port: u16,
        bounds: Bounds,
        limits: Limits,
    ) -> Result<Self, Error> {
        if port == 0 || limits.addresses == 0 || limits.addresses > 4096 {
            return Err(Fault::InvalidInput.into());
        }
        if !Arc::ptr_eq(&resolver.clock(), &clock) {
            return Err(Fault::InvalidInput.into());
        }
        let gate = Gate::new(clock, bounds)?;
        let lookup = Lookup::start(&resolver, &gate, server, limits.addresses)?;
        let mut transactions = Vec::new();
        transactions
            .try_reserve_exact(limits.addresses)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            socket,
            gate,
            lookup,
            limits,
            port,
            index: 0,
            pending: None,
            transactions,
            failed: 0,
            finished: false,
            cancelled: false,
        })
    }
    /// Original shared socket identity. This does not transfer read ownership.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
    /// Actual original complete writes whose responses may still arrive.
    pub fn written(&self) -> &[Transaction] {
        &self.transactions
    }
    /// Original immutable bounds.
    pub fn bounds(&self) -> Bounds {
        self.gate.bounds()
    }
    /// Poll one finite unit of actual DNS/socket work. Hard expiration and clock
    /// failure cancel original DNS/pending IO before returning an error.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Error>> {
        if self.cancelled {
            return Poll::Ready(Err(Fault::Cancelled.into()));
        }
        match self.gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.cancel();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(_)) => {}
        }
        if self.finished {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if let Some(attempt) = &mut self.pending {
            let server = attempt.transaction.server();
            let n = match self
                .socket
                .poll_send_to(cx, &attempt.packet, native(server))
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.pending = None;
                    self.failed += 1;
                    return Poll::Ready(Ok(Event::SendFailed { server, error }));
                }
                Poll::Ready(Ok(n)) => n,
            };
            if n != 20 {
                self.pending = None;
                self.failed += 1;
                return Poll::Ready(Ok(Event::SendFailed {
                    server,
                    error: std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "short STUN UDP datagram write",
                    ),
                }));
            }
            let now = match self.gate.check() {
                Ok(n) => n,
                Err(e) => {
                    // Actual local send happened; retain it as a cancelled transaction even if receipt time expired.
                    let mut old = self.pending.take().ok_or(Fault::NotReady)?.transaction;
                    old.cancel();
                    self.transactions.push(old);
                    self.cancel();
                    return Poll::Ready(Err(e));
                }
            };
            attempt.transaction.written(now)?;
            let transaction = *attempt.transaction.id();
            let sent = self.pending.take().ok_or(Fault::NotReady)?.transaction;
            self.transactions.push(sent);
            return Poll::Ready(Ok(Event::Written {
                server,
                transaction,
            }));
        }
        if !self.lookup.is_complete() {
            match self.lookup.poll(cx, &mut self.gate) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.cancel();
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(_)) => {}
            }
        }
        if let Some(&ip) = self.lookup.addresses().get(self.index) {
            self.index += 1;
            let local = self.socket.local_addr()?;
            if ip.is_ipv6() != local.is_ipv6() || ip.is_ipv6() && !self.limits.ipv6 {
                return Poll::Ready(Ok(Event::Activity));
            }
            let server = portable(SocketAddr::new(ip, self.port));
            let now = self.gate.check()?;
            let mut id = [0; 12];
            getrandom::fill(&mut id).map_err(Error::Entropy)?;
            let transaction = Transaction::new(id, server, self.gate.bounds().expires, now)?;
            let mut packet = [0; 20];
            stun::binding_request(&id, &mut packet)?;
            self.pending = Some(Attempt {
                transaction,
                packet,
            });
            return Poll::Ready(Ok(Event::Activity));
        }
        if self.lookup.is_complete() {
            self.finished = true;
            return Poll::Ready(Ok(Event::Finished {
                written: self.transactions.len(),
                failed: self.failed,
            }));
        }
        Poll::Ready(Ok(Event::Activity))
    }
    /// A cancellable wait borrows this owner; partial DNS/native send cursors
    /// remain owned here when the caller drops the future.
    pub async fn drive(&mut self) -> Result<Event, Error> {
        poll_fn(|cx| self.poll(cx)).await
    }
    /// Dispatch a datagram actually received by the caller's original socket.
    /// Exact socket Arc identity, server, txid and original bounds are checked.
    /// Unknown packets/transactions remain unconsumed by this STUN job.
    pub fn on_datagram(
        &mut self,
        socket: &Arc<UdpSocket>,
        sender: SocketAddr,
        packet: &[u8],
    ) -> Result<Option<SocketAddress>, Error> {
        if self.cancelled {
            return Err(Fault::Cancelled.into());
        }
        if !Arc::ptr_eq(&self.socket, socket) {
            return Err(Fault::StaleGeneration.into());
        }
        let now = self.gate.check()?;
        let sender = portable(sender);
        for transaction in &mut self.transactions {
            if transaction.server() != sender {
                continue;
            }
            match transaction.receive(sender, packet, now) {
                Ok(Some(address)) => return Ok(Some(address)),
                Ok(None) | Err(Fault::Stale) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }
    /// Actual original DNS cancellation. No wire CANCEL or mapping removal is
    /// fabricated. Late datagrams can no longer update this job.
    pub fn cancel(&mut self) {
        self.lookup.cancel();
        self.pending = None;
        for transaction in &mut self.transactions {
            transaction.cancel();
        }
        self.cancelled = true;
    }
}
/// Parse one actual configured STUN server (host or host:port, bracketedIPv6),
/// defaulting to3478. No DNS is performed and no shell syntax is accepted.
pub fn parse_server(input: &str) -> Result<(&str, u16), Fault> {
    if input.is_empty()
        || input
            .as_bytes()
            .iter()
            .any(|c| c.is_ascii_whitespace() || *c == 0)
    {
        return Err(Fault::InvalidInput);
    }
    if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(Fault::Malformed)?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| Fault::Malformed)?;
        let port = if tail.is_empty() {
            3478
        } else {
            tail.strip_prefix(':')
                .ok_or(Fault::Malformed)?
                .parse()
                .map_err(|_| Fault::Malformed)?
        };
        if port == 0 {
            return Err(Fault::InvalidInput);
        }
        return Ok((host, port));
    }
    let (host, port) = match input.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            (host, port.parse().map_err(|_| Fault::Malformed)?)
        }
        _ => {
            if input.contains(':') {
                input
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(|_| Fault::Malformed)?;
            }
            (input, 3478)
        }
    };
    if host.is_empty() || port == 0 {
        return Err(Fault::InvalidInput);
    }
    Ok((host, port))
}
