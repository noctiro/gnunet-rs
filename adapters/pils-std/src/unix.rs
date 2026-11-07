use gnunet_pils::{Action, Service};
use gnunet_wire::official::MessageHeader;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
};
use zeroize::{Zeroize, Zeroizing};

/// Local resource bounds, never new wire limits or protocol fields.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneous physical clients.
    pub clients: usize,
    /// Maximum retained incoming bytes per client, at least one common header.
    pub receive_bytes: usize,
    /// Maximum retained unsent output bytes per client.
    pub transmit_bytes: usize,
    /// Maximum accepts in one host step.
    pub accepts_per_step: usize,
    /// Public canonical address scratch used by the service.
    pub address_bytes: usize,
}
/// Local activity counts; no counter asserts remote processing or durability.
#[derive(Default, Debug)]
pub struct Progress {
    /// New physical clients admitted.
    pub accepted: usize,
    /// Complete original client frames processed.
    pub requests: usize,
    /// Bytes actually accepted by native socket writes.
    pub written: usize,
    /// Physical clients closed due to EOF, malformed input or local backpressure.
    pub closed: usize,
}
struct Client {
    stream: UnixStream,
    rx: Vec<u8>,
    tx: VecDeque<Zeroizing<Vec<u8>>>,
    offset: usize,
    queued: usize,
}
impl Client {
    fn queue(&mut self, bytes: &[u8], limit: usize) -> bool {
        let Some(n) = self.queued.checked_add(bytes.len()) else {
            return false;
        };
        if n > limit {
            return false;
        }
        self.tx.push_back(Zeroizing::new(bytes.to_vec()));
        self.queued = n;
        true
    }
    fn write(&mut self) -> io::Result<usize> {
        let Some(frame) = self.tx.front() else {
            return Ok(0);
        };
        match self.stream.write(&frame[self.offset..]) {
            Ok(0) => Err(io::Error::new(io::ErrorKind::WriteZero, "PILS write zero")),
            Ok(n) => {
                self.offset += n;
                self.queued -= n;
                if self.offset == frame.len() {
                    let _completed = self.tx.pop_front();
                    self.offset = 0;
                }
                Ok(n)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }
}
/// One actual listener, key service and retained per-connection RX/TX cursors.
/// Poll cancellation never loses a partial outgoing secret frame. Dropping this
/// owner closes all sockets and erases queued output. Listener path cleanup and
/// single-writer KeyLease belong to the outer lifecycle owner.
pub struct Host<const H: usize = 4096> {
    listener: UnixListener,
    service: Service<H>,
    limits: Limits,
    clients: BTreeMap<u64, Client>,
    next: u64,
    scratch: Vec<u8>,
    out: Zeroizing<Vec<u8>>,
}
impl<const H: usize> Host<H> {
    /// Adopt an already authorized/bound listener; no private socket convention.
    pub fn new(listener: UnixListener, service: Service<H>, limits: Limits) -> io::Result<Self> {
        if limits.clients == 0
            || limits.receive_bytes < 4
            || limits.transmit_bytes < service.announcement().len()
            || limits.accepts_per_step == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid PILS resource bounds",
            ));
        }
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            service,
            limits,
            clients: BTreeMap::new(),
            next: 0,
            scratch: vec![0; limits.address_bytes],
            out: Zeroizing::new(vec![0; 104]),
        })
    }
    /// Borrow the current domain owner; callers cannot rotate it while borrowed.
    #[must_use]
    pub const fn service(&self) -> &Service<H> {
        &self.service
    }
    /// Current physical clients, excluding already closed sockets.
    #[must_use]
    pub fn clients(&self) -> usize {
        self.clients.len()
    }
    /// Perform bounded native work at an explicit logical absolute time. Each
    /// existing client gets one write, one read and one frame-processing chance.
    pub fn poll_once(&mut self, now: u64) -> io::Result<Progress> {
        let mut progress = Progress::default();
        for _ in 0..self.limits.accepts_per_step {
            if self.clients.len() == self.limits.clients {
                break;
            }
            let (stream, _) = match self.listener.accept() {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(e) => return Err(e),
            };
            stream.set_nonblocking(true)?;
            self.next = self
                .next
                .checked_add(1)
                .ok_or_else(|| io::Error::other("PILS client generation exhausted"))?;
            let mut client = Client {
                stream,
                rx: Vec::new(),
                tx: VecDeque::new(),
                offset: 0,
                queued: 0,
            };
            if !client.queue(self.service.announcement(), self.limits.transmit_bytes) {
                return Err(io::Error::other(
                    "initial PILS announcement exceeds output budget",
                ));
            }
            self.clients.insert(self.next, client);
            progress.accepted += 1;
        }
        let ids: Vec<_> = self.clients.keys().copied().collect();
        for id in ids {
            let Some(client) = self.clients.get_mut(&id) else {
                continue;
            };
            let write = client.write();
            match write {
                Ok(n) => progress.written += n,
                Err(_) => {
                    self.clients.remove(&id);
                    progress.closed += 1;
                    continue;
                }
            }
            let mut buffer = [0_u8; 8192];
            let available = self
                .limits
                .receive_bytes
                .saturating_sub(client.rx.len())
                .min(buffer.len());
            if available > 0 {
                match client.stream.read(&mut buffer[..available]) {
                    Ok(0) => {
                        self.clients.remove(&id);
                        progress.closed += 1;
                        continue;
                    }
                    Ok(n) => client.rx.extend_from_slice(&buffer[..n]),
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        self.clients.remove(&id);
                        progress.closed += 1;
                        continue;
                    }
                }
            }
            if client.rx.len() < 4 {
                continue;
            }
            let header = match MessageHeader::decode(&client.rx[..4]) {
                Ok(h) if h.size() <= self.limits.receive_bytes => h,
                _ => {
                    self.clients.remove(&id);
                    progress.closed += 1;
                    continue;
                }
            };
            if client.rx.len() < header.size() {
                continue;
            }
            let action = self.service.receive(
                &client.rx[..header.size()],
                &mut self.scratch,
                now,
                &mut self.out,
            );
            client.rx.drain(..header.size());
            match action {
                Ok(Action::Reply { len, .. }) => {
                    if !client.queue(&self.out[..len], self.limits.transmit_bytes) {
                        self.clients.remove(&id);
                        progress.closed += 1;
                    }
                }
                Ok(Action::Broadcast { .. }) => {
                    let update = self.service.announcement();
                    self.clients.retain(|_, client| {
                        let keep = client.queue(update, self.limits.transmit_bytes);
                        if !keep {
                            progress.closed += 1
                        }
                        keep
                    });
                }
                Ok(Action::Unchanged) => {}
                Err(_) => {
                    self.clients.remove(&id);
                    progress.closed += 1;
                }
            }
            self.out.as_mut_slice().zeroize();
            progress.requests += 1;
        }
        Ok(progress)
    }
}
