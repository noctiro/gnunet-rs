//! Explicit OS bootstrap for configured IPC endpoint names only.
//!
//! This port is deliberately not a public replacement for the ordinary shared
//! GNUnet Resolver. The original user query is never an input to this module.
use crate::Error;
use gnunet_client_host::resolution::{
    AddressLookup, ResolutionContext, ResolutionTimer, SharedResolution,
};
use gnunet_service_runtime::{clock::RuntimeClock, connection::ConnectionLease};
use gnunet_types::Error as Fault;
use std::{
    fmt, io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

const MAX_NAME_BYTES: usize = 1024;
const MAX_ADDRESSES: usize = 32;
const MAX_ADDRESS_BYTES: usize = 1024;

pub(crate) fn context(
    configuration: &gnunet_config::Configuration,
    shared: SharedResolution,
    hard: Instant,
) -> Result<SharedResolution, Error> {
    let mut names = [None, None];
    for (slot, section) in names
        .iter_mut()
        .zip([b"gns".as_slice(), b"identity".as_slice()])
    {
        let has_tcp = configuration
            .get_number(section, b"PORT")
            .ok()
            .and_then(|p| u16::try_from(p).ok())
            .is_some_and(|p| p != 0);
        if !has_tcp {
            continue;
        }
        let Some(name) = configuration.get(section, b"HOSTNAME") else {
            continue;
        };
        // An unused malformed TCP fallback does not invalidate a working Unix
        // endpoint. If it is actually selected, it fails the whitelist below.
        if name.is_empty() || name.len() > MAX_NAME_BYTES || name.contains(&0) {
            continue;
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(name.len())
            .map_err(|_| Fault::Capacity)?;
        copy.extend_from_slice(name);
        *slot = Some(copy);
    }
    Ok(Arc::new(Bootstrap {
        names,
        shared,
        hard,
    }))
}
struct Bootstrap {
    names: [Option<Vec<u8>>; 2],
    shared: SharedResolution,
    hard: Instant,
}
// A late OS error retains its actual cause independently of the original hard.
// No hostname, user query, key material or invented address is stored here.
#[derive(Debug)]
struct OsFailure {
    original: io::Error,
    expired: bool,
}
impl fmt::Display for OsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSS IPC endpoint OS lookup (original deadline elapsed={}): {}",
            self.expired, self.original
        )
    }
}
impl std::error::Error for OsFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
fn gate(hard: Instant) -> io::Result<()> {
    if Instant::now() >= hard {
        Err(io::Error::new(io::ErrorKind::TimedOut, Fault::Deadline))
    } else {
        Ok(())
    }
}
impl Bootstrap {
    fn lookup(
        &self,
        name: &[u8],
        ipv4: bool,
        timeout: Duration,
    ) -> io::Result<Option<Box<dyn AddressLookup>>> {
        gate(self.hard)?;
        if !self
            .names
            .iter()
            .flatten()
            .any(|configured| configured.as_slice() == name)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                Fault::PermissionDenied,
            ));
        }
        // Literal and reserved-loopback semantics still come from the same
        // original broker; only configured ordinary hostnames use OS NSS.
        let text = std::str::from_utf8(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, Fault::InvalidInput))?;
        if name.eq_ignore_ascii_case(b"localhost") || text.parse::<IpAddr>().is_ok() {
            return if ipv4 {
                self.shared.lookup_ipv4(name, timeout)
            } else {
                self.shared.lookup(name, timeout)
            };
        }
        // The actual worker's reentry latch is already set. A synchronous GNU
        // NSS callback into any hook of this DSO returns UNAVAIL without a new
        // worker; the system's configured non-GNS modules resolve the endpoint.
        if !crate::worker::bootstrap_suppressed() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                Fault::PermissionDenied,
            ));
        }
        let hard = Instant::now()
            .checked_add(timeout)
            .map_or(self.hard, |target| self.hard.min(target));
        gate(hard)?;
        let resolved = (text, 0).to_socket_addrs();
        // No address, END or connection effect is published before this native
        // check, even if the unpreemptible OS resolver returned successfully.
        let expired = Instant::now() >= hard;
        let resolved = match resolved {
            Err(original) => {
                return Err(io::Error::new(
                    if expired {
                        io::ErrorKind::TimedOut
                    } else {
                        original.kind()
                    },
                    OsFailure { original, expired },
                ));
            }
            Ok(resolved) => {
                if expired {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, Fault::Deadline));
                }
                resolved
            }
        };
        let mut addresses = [SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)); MAX_ADDRESSES];
        let mut received = 0usize;
        let mut length = 0usize;
        for address in resolved {
            gate(hard)?;
            received = received
                .checked_add(1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, Fault::Overflow))?;
            if received > MAX_ADDRESSES
                || received
                    .checked_mul(size_of::<SocketAddr>())
                    .is_none_or(|n| n > MAX_ADDRESS_BYTES)
            {
                return Err(io::Error::new(io::ErrorKind::OutOfMemory, Fault::Capacity));
            }
            if !ipv4 || address.is_ipv4() {
                // Keep the original full sockaddr; CLIENT changes only the
                // actual configured service port before its native connect.
                addresses[length] = address;
                length += 1;
            }
        }
        gate(hard)?;
        Ok(Some(Box::new(Addresses {
            addresses,
            length,
            next: 0,
            offered: false,
            hard,
        })))
    }
}
impl ResolutionContext for Bootstrap {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.shared.clock()
    }
    fn lookup(&self, name: &[u8], timeout: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Bootstrap::lookup(self, name, false, timeout)
    }
    fn lookup_ipv4(
        &self,
        name: &[u8],
        timeout: Duration,
    ) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Bootstrap::lookup(self, name, true, timeout)
    }
    fn timer(&self, duration: Duration) -> io::Result<ResolutionTimer> {
        gate(self.hard)?;
        let timer = self.shared.timer(duration)?;
        gate(self.hard)?;
        Ok(timer)
    }
}
struct Addresses {
    addresses: [SocketAddr; MAX_ADDRESSES],
    length: usize,
    next: usize,
    offered: bool,
    hard: Instant,
}
impl Addresses {
    fn poll_address(&mut self, native: bool) -> Poll<io::Result<Option<SocketAddr>>> {
        if let Err(error) = gate(self.hard) {
            return Poll::Ready(Err(error));
        }
        if self.offered {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                Fault::NotReady,
            )));
        }
        if self.next == self.length {
            return Poll::Ready(Ok(None));
        }
        let address = self.addresses[self.next];
        if !native
            && matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
        {
            // An IP-only observer cannot carry this actual native metadata.
            // Refuse before offering a callback; never downgrade it to scope0.
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                Fault::Unsupported,
            )));
        }
        self.offered = true;
        Poll::Ready(Ok(Some(address)))
    }
}
impl AddressLookup for Addresses {
    fn poll_next(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<Option<IpAddr>>> {
        self.poll_address(false)
            .map(|result| result.map(|address| address.map(|socket| socket.ip())))
    }
    fn poll_socket_addr(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<Option<SocketAddr>>> {
        self.poll_address(true)
    }
    fn address_effect_done(&mut self) -> io::Result<()> {
        if !self.offered {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, Fault::NotReady));
        }
        // Consume this original callback even on expiry, so it cannot authorize
        // another socket effect. The original attempt is then retired by CLIENT.
        self.offered = false;
        self.next += 1;
        gate(self.hard)
    }
    fn connected(self: Box<Self>) -> io::Result<Box<dyn ConnectionLease>> {
        gate(self.hard)?;
        if self.offered {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, Fault::NotReady));
        }
        // getaddrinfo already settled synchronously; this lease owns only its
        // actual bounded address storage, with no invented remote ACK or MQ.
        Ok(self)
    }
}
impl ConnectionLease for Addresses {}
