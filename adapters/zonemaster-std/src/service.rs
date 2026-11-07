//! Actual empty-handler GNUNET_SERVICE endpoint. ZONEMASTER exposes no domain
//! IPC command; a connection grants no private key or publication authority.
use crate::Failure;
use gnunet_service_runtime::{
    accepted::AcceptState,
    credentials::UnixAccess,
    framing::{Accounting, Budget, Framed, Limits as FrameLimits, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions},
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Bounded normal SERVICE resources, independent of background job resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actually admitted idle/pending clients.
    pub clients: usize,
    /// Maximum complete ordinary GNUnet frame.
    pub frame_bytes: usize,
    /// Native syscall quantum.
    pub io_slice_bytes: usize,
    /// Finite actual first/idle-frame lifetime.
    pub idle: Duration,
    /// First partial frame suffix lifetime, never renewed.
    pub partial: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 128,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            idle: Duration::from_secs(60),
            partial: Duration::from_secs(10),
        }
    }
}
struct Client {
    framed: Framed<()>,
    idle: Instant,
    partial: Option<Instant>,
}
/// Actual SERVICE events; no domain protocol reply/readiness is invented.
pub enum Event {
    /// Actual socket accepted and admitted.
    Accepted {
        /// Original bounded native socket diagnostics.
        diagnostics: gnunet_native::network::Diagnostics,
    },
    /// Original unadmitted source failed; other sources remain live.
    Admission {
        /// Original admission failure.
        error: Failure,
        /// Bounded diagnostics from the same accepted socket.
        diagnostics: gnunet_native::network::Diagnostics,
    },
    /// ACL rejected an actual original unadmitted socket.
    Rejected {
        /// Same socket's bounded diagnostics.
        diagnostics: gnunet_native::network::Diagnostics,
    },
    /// One original client was closed/ignored according to policy.
    Closed,
    /// Actual positive byte movement.
    Activity,
    /// Actual canonical accept/initialization observation.
    Socket(gnunet_service_runtime::accepted::SocketEvent),
}
/// Actual bounded socket/ACL/framing owner with zero message handlers.
pub struct Server {
    clients: Vec<Client>,
    accept: AcceptState,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    alarm: Option<Pin<Box<Sleep>>>,
    cursor: usize,
    stopped: bool,
}
impl Server {
    /// Reserve finite metadata; bind/accept/permission work belongs to foreground.
    pub fn new(limits: Limits, options: ServiceOptions, unix: UnixAccess) -> Result<Self, Failure> {
        if limits.clients == 0
            || !(4..=65535).contains(&limits.frame_bytes)
            || limits.io_slice_bytes == 0
            || limits.idle.is_zero()
            || limits.partial.is_zero()
        {
            return Err("invalid empty zonemaster SERVICE limits".into());
        }
        for d in [limits.idle, limits.partial] {
            Instant::now()
                .checked_add(d)
                .ok_or("SERVICE native deadline overflow")?;
        }
        let mut clients = Vec::new();
        clients
            .try_reserve_exact(limits.clients)
            .map_err(|_| gnunet_types::Error::Capacity)?;
        Ok(Self {
            clients,
            accept: Default::default(),
            limits,
            options,
            unix,
            alarm: None,
            cursor: 0,
            stopped: false,
        })
    }
    fn remove(&mut self, i: usize) {
        let mut client = self.clients.remove(i);
        client.framed.retire();
        drop(client);
        self.accept.client_closed();
    }
    /// Check/register only original native client bounds; no clock/IO/decode.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Event> {
        let now = Instant::now();
        if let Some(i) = self
            .clients
            .iter()
            .position(|c| now >= c.idle || c.partial.is_some_and(|at| now >= at))
        {
            self.remove(i);
            return Some(Event::Closed);
        }
        let due = self
            .clients
            .iter()
            .map(|c| c.partial.unwrap_or(c.idle).min(c.idle))
            .min();
        if let Some(at) = due {
            let alarm = self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        } else {
            self.alarm = None;
        }
        None
    }
    /// Poll actual accepted clients and listeners. Unknown complete messages are
    /// ignored only for the shared official TOLERANT policy; otherwise original
    /// source closes. No ACK, handler or key-return operation is invented.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
    ) -> Poll<Result<Event, Failure>> {
        if let Some(event) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(event));
        }
        if self.stopped {
            return Poll::Pending;
        }
        for i in 0..self.clients.len() {
            let result = self.clients[i].framed.poll_read(cx);
            match result {
                Poll::Ready(Err(_)) | Poll::Ready(Ok(ReadStep::Eof)) => {
                    self.remove(i);
                    return Poll::Ready(Ok(Event::Closed));
                }
                Poll::Ready(Ok(ReadStep::Progress { complete, bytes: _ })) => {
                    let c = &mut self.clients[i];
                    if complete {
                        let bytes = c.framed.frame().ok_or(gnunet_types::Error::NotReady)?;
                        if gnunet_wire::official::Frame::decode(bytes).is_err() {
                            self.remove(i);
                            return Poll::Ready(Ok(Event::Closed));
                        }
                        if !self.options.tolerant {
                            self.remove(i);
                            return Poll::Ready(Ok(Event::Closed));
                        }
                        c.framed.release_frame();
                        c.partial = None;
                        c.idle = Instant::now()
                            .checked_add(self.limits.idle)
                            .ok_or(gnunet_types::Error::Overflow)?;
                    } else if c.partial.is_none() {
                        c.partial = Some(
                            Instant::now()
                                .checked_add(self.limits.partial)
                                .ok_or(gnunet_types::Error::Overflow)?
                                .min(c.idle),
                        );
                    }
                    return Poll::Ready(Ok(Event::Activity));
                }
                Poll::Pending => {}
            }
        }
        if self.clients.len() < self.limits.clients && self.accept.ready() {
            for offset in 0..listeners.len() {
                let index = (self.cursor + offset) % listeners.len();
                match listeners[index].poll_canonical_connection(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Ok(Event::Socket(self.accept.failed(error))));
                    }
                    Poll::Ready(Ok(accepted)) => {
                        let allowed = match accepted.peer() {
                            PeerAddress::Unix => match self.unix.allows(accepted.connection()) {
                                Ok(allowed) => allowed,
                                Err(error) => {
                                    let (connection, _, diagnostics) = accepted.into_parts();
                                    drop(connection);
                                    return Poll::Ready(Ok(Event::Admission {
                                        error: Box::new(error),
                                        diagnostics,
                                    }));
                                }
                            },
                            PeerAddress::Tcp(peer) => self.options.access.allows(peer.ip()),
                        };
                        if !allowed {
                            let (connection, _, diagnostics) = accepted.into_parts();
                            drop(connection);
                            return Poll::Ready(Ok(Event::Rejected { diagnostics }));
                        }
                        let (connection, _, diagnostics) = accepted.into_parts();
                        let framed = match Framed::new(
                            connection,
                            FrameLimits {
                                frame_bytes: self.limits.frame_bytes,
                                ordinary: Budget::default(),
                                reserved: Budget::default(),
                                accounting: Accounting::Retained,
                                io_slice_bytes: self.limits.io_slice_bytes,
                            },
                        ) {
                            Ok(framed) => framed,
                            Err(error) => {
                                return Poll::Ready(Ok(Event::Admission {
                                    error: error.into(),
                                    diagnostics,
                                }));
                            }
                        };
                        self.clients.push(Client {
                            framed,
                            idle: Instant::now()
                                .checked_add(self.limits.idle)
                                .ok_or(gnunet_types::Error::Overflow)?,
                            partial: None,
                        });
                        self.cursor = (index + 1) % listeners.len();
                        return Poll::Ready(Ok(Event::Accepted { diagnostics }));
                    }
                }
            }
        }
        Poll::Pending
    }
    /// Physically close every actual client before listener owners are dropped.
    pub fn stop(&mut self) {
        self.stopped = true;
        while !self.clients.is_empty() {
            self.remove(self.clients.len() - 1)
        }
        self.alarm = None;
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}
