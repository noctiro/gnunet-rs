//! Same externally visible loopback/local-prefix/WAN categories as public nt.c.
//! A snapshot is time-local metadata, never address/peer authentication.
use gnunet_native::interfaces::{self, InterfaceAddress};
use std::{io, net::SocketAddr, time::Duration};
use tokio::time::Instant;
pub(crate) struct Scanner {
    rows: Vec<InterfaceAddress>,
    valid: bool,
    next: Instant,
    limits: interfaces::Limits,
    interval: Duration,
}
impl Scanner {
    pub(crate) fn new(limits: interfaces::Limits, interval: Duration) -> io::Result<Self> {
        let rows = interfaces::snapshot(limits)?;
        let next = Instant::now()
            .checked_add(interval)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(Self {
            rows,
            valid: true,
            next,
            limits,
            interval,
        })
    }
    pub(crate) fn next(&self) -> Instant {
        self.next
    }
    pub(crate) fn refresh(&mut self) -> io::Result<bool> {
        if Instant::now() < self.next {
            return Ok(false);
        }
        // A failure is not a complete empty snapshot or a claim that old metadata
        // is current. Keep only bounded capacity, classify new observations Unknown.
        self.next = Instant::now()
            .checked_add(self.interval)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        match interfaces::snapshot(self.limits) {
            Ok(rows) => {
                self.rows = rows;
                self.valid = true;
                Ok(true)
            }
            Err(error) => {
                self.valid = false;
                Err(error)
            }
        }
    }
    pub(crate) fn classify(&self, remote: SocketAddr) -> u32 {
        if remote.ip().is_loopback() {
            return 1;
        }
        if !self.valid {
            return 0;
        }
        interfaces::classify(&self.rows, remote)
    }
}
