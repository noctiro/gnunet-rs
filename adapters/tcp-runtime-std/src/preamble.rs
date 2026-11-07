//! Original-socket TCP preamble admission, before any peer authentication.
//!
//! The normal four consumed KX bytes are returned to the existing Session's
//! persistent RX cursor. A probe's claimed PID only selects that Session's
//! expected signer; the probe never authenticates or retires a reversal request.
use crate::NativeConnect;
use gnunet_crypto::EddsaPublicKey;
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::nat;
use gnunet_tcp_communicator_host::Connect;
use gnunet_types::{Error, Rejected};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    time::{Instant, Sleep},
};

/// Fixed original prototype targets, including time already spent connecting.
/// The caller supplies logical samples from its existing selected clock.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    until: u64,
    hard: Instant,
}
impl Bounds {
    /// Retain finite targets minted once by the original accept/reversal owner.
    /// The first actual poll also checks the caller's current logical sample.
    pub fn new(until: u64, hard: Instant) -> Result<Self, Error> {
        if until == 0 || until == u64::MAX || Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        Ok(Self { until, hard })
    }
    /// Original logical target; handoff does not renew it.
    #[must_use]
    pub const fn until(self) -> u64 {
        self.until
    }
    /// Original independently finite native target.
    #[must_use]
    pub const fn hard(self) -> Instant {
        self.hard
    }
    fn expired(self, now: u64) -> bool {
        Instant::now() >= self.hard || now >= self.until
    }
}

struct Guard {
    bounds: Bounds,
    alarm: Option<Pin<Box<Sleep>>>,
}
impl Guard {
    const fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            alarm: None,
        }
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        if Instant::now() >= self.bounds.hard {
            return true;
        }
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(self.bounds.hard)));
        alarm.as_mut().poll(cx).is_ready()
    }
    fn close(&mut self) {
        self.alarm = None;
    }
}

/// An original physical failure. Counts are actual native transfers only.
#[derive(Debug)]
pub struct Failure {
    /// Exact deadline, protocol or native cause.
    pub cause: Cause,
    /// Actual bytes consumed from the original socket.
    pub read: usize,
    /// Actual clear-probe bytes written to the original socket.
    pub written: usize,
    /// Original targets; no retry or clock adjustment renews them.
    pub bounds: Bounds,
}
/// No implicit retry, authenticated identity or clean close is inferred.
#[derive(Debug)]
pub enum Cause {
    /// Either original target expired.
    Deadline,
    /// Original socket ended before the selected preamble was complete.
    Eof,
    /// Actual connect/read/write failure.
    Native(io::Error),
    /// Local framing or address refusal.
    Protocol(Error),
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP preamble: {:?}", self.cause)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Cause::Native(error) => Some(error),
            _ => None,
        }
    }
}

/// A framing decision about bytes from this one original native connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preamble {
    /// The actual first four KX bytes, still unverified ciphertext. They must
    /// enter the same Session's original persistent RX cursor exactly once.
    Handshake {
        /// Consumed original bytes, with no additional envelope.
        prefix: [u8; 4],
    },
    /// An exact official clear probe, consumed separately from the ensuing KX.
    Probe {
        /// Claimed signer. Only the subsequent real signed KX authenticates it.
        claimed: EddsaPublicKey,
    },
}
/// One positive original read; a pending poll claims no transferred bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadProgress {
    /// Actual bytes transferred by this read.
    pub bytes: usize,
    /// Cumulative actual bytes retained for this preamble, at most 36.
    pub retained: usize,
    /// The original preamble is now classified and available for move-only handoff.
    pub complete: bool,
}

/// Bounded classification of one accepted connection. Drop closes that same
/// connection; canceling a poll future neither loses its prefix nor creates a peer.
pub struct Admission {
    connection: Option<Connection>,
    guard: Guard,
    bytes: [u8; 36],
    used: usize,
    preamble: Option<Preamble>,
    closed: bool,
}
impl Admission {
    /// Take only the unique actual accepted connection and its original targets.
    #[must_use]
    pub const fn new(connection: Connection, bounds: Bounds) -> Self {
        Self {
            connection: Some(connection),
            guard: Guard::new(bounds),
            bytes: [0; 36],
            used: 0,
            preamble: None,
            closed: false,
        }
    }
    fn fail(&mut self, cause: Cause) -> Failure {
        self.abort();
        Failure {
            cause,
            read: self.used,
            written: 0,
            bounds: self.guard.bounds,
        }
    }
    /// Physically close this original socket without sampling any clock.
    /// No close errno or authentication outcome is invented by Drop.
    pub fn abort(&mut self) {
        self.closed = true;
        self.guard.close();
        drop(self.connection.take());
    }
    /// Check/register the fixed native target before the enclosing canonical
    /// clock wait. A real expiry closes this original socket and is returned once.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Failure> {
        if !self.closed && self.guard.expired(cx) {
            Some(self.fail(Cause::Deadline))
        } else {
            None
        }
    }
    /// Inspect only this original framing decision; it grants no registry right.
    #[must_use]
    pub const fn preamble(&self) -> Option<Preamble> {
        self.preamble
    }
    /// Retain the same original targets throughout the admission phase.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.guard.bounds
    }
    /// Actual original bytes retained, including after explicit abort. This is
    /// not a completed read, authenticated peer or registry admission receipt.
    #[must_use]
    pub const fn retained(&self) -> usize {
        self.used
    }
    /// Perform at most one nonblocking read, consuming exactly four bytes first
    /// and only the remaining 32 bytes when the official probe header matches.
    /// There is no peek/readability loop and no read of the following KX/tail.
    pub fn poll(&mut self, cx: &mut Context<'_>, now: u64) -> Poll<Result<ReadProgress, Failure>> {
        if let Some(failure) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(failure));
        }
        if self.closed {
            return Poll::Pending;
        }
        if self.guard.bounds.expired(now) {
            return Poll::Ready(Err(self.fail(Cause::Deadline)));
        }
        if self.preamble.is_some() {
            return Poll::Pending;
        }
        let end = if self.used < 4 { 4 } else { 36 };
        let read = {
            let Some(connection) = self.connection.as_mut() else {
                return Poll::Ready(Err(self.fail(Cause::Protocol(Error::Closed))));
            };
            let mut buffer = ReadBuf::new(&mut self.bytes[self.used..end]);
            match Pin::new(connection).poll_read(cx, &mut buffer) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        };
        let bytes = match read {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(self.fail(Cause::Native(error))));
            }
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(self.fail(Cause::Eof))),
            Poll::Ready(Ok(bytes)) => bytes,
        };
        self.used += bytes;
        if self.guard.bounds.expired(now) {
            return Poll::Ready(Err(self.fail(Cause::Deadline)));
        }
        if self.used == 4 {
            let prefix = [self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]];
            if !nat::is_probe_header(&prefix) {
                self.preamble = Some(Preamble::Handshake { prefix });
            }
        } else if self.used == self.bytes.len() {
            let mut reader = nat::Reader::new();
            let used = reader.push(&self.bytes);
            match reader.view() {
                Ok(nat::Preamble::Probe(claimed)) if used == self.bytes.len() => {
                    self.preamble = Some(Preamble::Probe { claimed });
                }
                _ => return Poll::Ready(Err(self.fail(Cause::Protocol(Error::Malformed)))),
            }
        }
        Poll::Ready(Ok(ReadProgress {
            bytes,
            retained: self.used,
            complete: self.preamble.is_some(),
        }))
    }
    /// Move the same original connection and consumed prefix/probe into the
    /// caller's existing registry/Session flow. Recheck original targets at handoff;
    /// their expiry permanently closes the socket before returning the rejection.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected handoff returns the original unique native owner and prefix without new allocation"
    )]
    pub fn into_parts(
        mut self,
        now: u64,
    ) -> Result<(Connection, Preamble, Bounds), Rejected<Self>> {
        let reason = if self.closed {
            Some(Error::Closed)
        } else if self.guard.bounds.expired(now) {
            self.abort();
            Some(Error::Deadline)
        } else if self.preamble.is_none() {
            Some(Error::NotReady)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Rejected {
                reason,
                value: self,
            });
        }
        let (Some(connection), Some(preamble)) = (self.connection.take(), self.preamble) else {
            self.abort();
            return Err(Rejected {
                reason: Error::Closed,
                value: self,
            });
        };
        Ok((connection, preamble, self.guard.bounds))
    }
}

/// Actual connectback progress, independent of subsequent signature verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectProgress {
    /// The same original connect future completed with an actual connection.
    Connected,
    /// A positive native write of the exact original official clear probe.
    Written {
        /// Actual bytes transferred by this operation.
        bytes: usize,
        /// Cumulative actual probe bytes transferred, at most 36.
        total: usize,
        /// The exact 36-byte probe has been wholly written locally.
        complete: bool,
    },
}
/// IPv4 connectback/probe writer. Its physical outbound socket subsequently
/// hosts an inbound-role Session; no second connection or Session is created here.
pub struct ConnectBack {
    connecting: Option<Connect<'static>>,
    connection: Option<Connection>,
    guard: Guard,
    probe: [u8; 36],
    written: usize,
    closed: bool,
}
impl ConnectBack {
    /// Start the real IPv4 nonzero-port connect only while both original targets
    /// remain live. `local` is the caller's actual current PILS public identity.
    pub fn begin(
        remote: SocketAddr,
        local: EddsaPublicKey,
        bounds: Bounds,
        now: u64,
    ) -> Result<Self, Failure> {
        let cause = if bounds.expired(now) {
            Some(Cause::Deadline)
        } else if !remote.is_ipv4() || remote.port() == 0 {
            Some(Cause::Protocol(Error::InvalidInput))
        } else {
            None
        };
        if let Some(cause) = cause {
            return Err(Failure {
                cause,
                read: 0,
                written: 0,
                bounds,
            });
        }
        let mut probe = [0; 36];
        nat::probe(local, &mut probe).map_err(|error| Failure {
            cause: Cause::Protocol(error),
            read: 0,
            written: 0,
            bounds,
        })?;
        if bounds.expired(now) {
            return Err(Failure {
                cause: Cause::Deadline,
                read: 0,
                written: 0,
                bounds,
            });
        }
        let connecting = NativeConnect::begin(remote).map_err(|error| Failure {
            cause: Cause::Native(error),
            read: 0,
            written: 0,
            bounds,
        })?;
        if bounds.expired(now) {
            drop(connecting);
            return Err(Failure {
                cause: Cause::Deadline,
                read: 0,
                written: 0,
                bounds,
            });
        }
        Ok(Self {
            connecting: Some(connecting.into_future()),
            connection: None,
            guard: Guard::new(bounds),
            probe,
            written: 0,
            closed: false,
        })
    }
    fn fail(&mut self, cause: Cause) -> Failure {
        self.abort();
        Failure {
            cause,
            read: 0,
            written: self.written,
            bounds: self.guard.bounds,
        }
    }
    /// Drop only the original connect attempt/socket, independent of clock health.
    pub fn abort(&mut self) {
        self.closed = true;
        self.guard.close();
        drop(self.connecting.take());
        drop(self.connection.take());
    }
    /// Register/check the original native bound before any outer clock wait.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Failure> {
        if !self.closed && self.guard.expired(cx) {
            Some(self.fail(Cause::Deadline))
        } else {
            None
        }
    }
    /// Original immutable prototype targets, never refreshed by connect/write progress.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.guard.bounds
    }
    /// Actual probe prefix already written, including after explicit abort.
    /// A positive incomplete prefix has an uncertain remote processing outcome.
    #[must_use]
    pub const fn written(&self) -> usize {
        self.written
    }
    /// Whether the actual complete probe was written on this original connection.
    #[must_use]
    pub fn complete(&self) -> bool {
        !self.closed && self.connection.is_some() && self.written == self.probe.len()
    }
    /// Poll one original connect completion or one actual probe write. Pending
    /// retains the same future/socket/cursor; no background task is spawned.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
    ) -> Poll<Result<ConnectProgress, Failure>> {
        if let Some(failure) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(failure));
        }
        if self.closed {
            return Poll::Pending;
        }
        if self.guard.bounds.expired(now) {
            return Poll::Ready(Err(self.fail(Cause::Deadline)));
        }
        if let Some(connecting) = &mut self.connecting {
            let connection = match connecting.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(self.fail(Cause::Native(error))));
                }
                Poll::Ready(Ok(connection)) => connection,
            };
            self.connecting = None;
            self.connection = Some(connection);
            if self.guard.bounds.expired(now) {
                return Poll::Ready(Err(self.fail(Cause::Deadline)));
            }
            return Poll::Ready(Ok(ConnectProgress::Connected));
        }
        if self.complete() {
            return Poll::Pending;
        }
        let Some(connection) = self.connection.as_ref() else {
            return Poll::Ready(Err(self.fail(Cause::Protocol(Error::Closed))));
        };
        match connection.poll_write_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(self.fail(Cause::Native(error))));
            }
            Poll::Ready(Ok(())) => {}
        }
        // Readiness grants no time extension; check again before the actual write.
        if self.guard.bounds.expired(now) {
            return Poll::Ready(Err(self.fail(Cause::Deadline)));
        }
        let result = self
            .connection
            .as_ref()
            .map(|connection| connection.try_write(&self.probe[self.written..]));
        let bytes = match result {
            Some(Ok(0)) => {
                return Poll::Ready(Err(
                    self.fail(Cause::Native(io::ErrorKind::WriteZero.into()))
                ));
            }
            Some(Ok(bytes)) => bytes,
            Some(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                // Cached readiness may not have registered this poll's waker.
                // try_write clears it on WouldBlock; yield once so the next
                // original poll registers readiness after checking both bounds.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Some(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Some(Err(error)) => return Poll::Ready(Err(self.fail(Cause::Native(error)))),
            None => return Poll::Ready(Err(self.fail(Cause::Protocol(Error::Closed)))),
        };
        self.written += bytes;
        if self.guard.bounds.expired(now) {
            return Poll::Ready(Err(self.fail(Cause::Deadline)));
        }
        Poll::Ready(Ok(ConnectProgress::Written {
            bytes,
            total: self.written,
            complete: self.written == self.probe.len(),
        }))
    }
    /// Move the same original socket only after its full local probe write,
    /// preserving the remaining original prototype bounds for the real Session.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected handoff retains the original connect/socket/write cursor without replacement allocation"
    )]
    pub fn into_connection(mut self, now: u64) -> Result<(Connection, Bounds), Rejected<Self>> {
        let reason = if self.closed {
            Some(Error::Closed)
        } else if self.guard.bounds.expired(now) {
            self.abort();
            Some(Error::Deadline)
        } else if !self.complete() {
            Some(Error::NotReady)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Rejected {
                reason,
                value: self,
            });
        }
        let Some(connection) = self.connection.take() else {
            self.abort();
            return Err(Rejected {
                reason: Error::Closed,
                value: self,
            });
        };
        Ok((connection, self.guard.bounds))
    }
}
