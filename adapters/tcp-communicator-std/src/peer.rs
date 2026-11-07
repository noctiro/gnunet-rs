//! One physical peer owner; process services and routing live in Communicator.
use crate::manager::{Connect, HandshakeBounds, PendingSend, Send};
use crate::{Activity, HostError};
use gnunet_crypto::Entropy;
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::session::{Phase, Session, Time, WriteResult};
use gnunet_types::Error;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
pub(crate) struct ProtoGuard {
    bounds: HandshakeBounds,
    alarm: Pin<Box<tokio::time::Sleep>>,
}
impl ProtoGuard {
    pub(crate) fn new(bounds: HandshakeBounds) -> Self {
        Self {
            bounds,
            alarm: Box::pin(tokio::time::sleep_until(bounds.hard())),
        }
    }
}
pub(crate) struct Peer<'a> {
    pub core: Box<Session<'a>>,
    pub peer: Option<Connection>,
    pub connecting: Option<Connect<'a>>,
    pub address: Vec<u8>,
    pub network: u32,
    pub qid: u32,
    pub queue: bool,
    pub reannounce: bool,
    pub rx: Vec<u8>,
    pub rx_position: usize,
    pub rx_size: usize,
    pub initial: Option<ProtoGuard>,
    pub pending_send: Option<Send>,
    pub sends: VecDeque<PendingSend>,
}
impl Peer<'_> {
    fn initial_live(&mut self) -> bool {
        if self.core.phase() == Phase::Closed {
            self.initial = None;
        }
        self.initial.is_some()
    }
    pub(crate) fn settle_proto(&mut self, now: u64) {
        // Capture successful establishment in the SAME original progress turn,
        // before the caller can suspend. Crossing either original bound leaves
        // the guard live so the next pre-IO check really closes this socket.
        if self.core.phase() == Phase::Established
            && self.initial.as_ref().is_some_and(|guard| {
                now < guard.bounds.until() && tokio::time::Instant::now() < guard.bounds.hard()
            })
        {
            self.initial = None;
        }
    }
    fn expire_proto(&mut self) -> HostError {
        // Actual original socket/future drops before reporting failure. Core
        // native_lost still leaves its ordinary service/credit cleanup to drive.
        self.peer = None;
        self.connecting = None;
        self.initial = None;
        self.core.native_lost();
        Error::Deadline.into()
    }
    pub(crate) fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<HostError> {
        if !self.initial_live() {
            return None;
        }
        let guard = self.initial.as_mut()?;
        if tokio::time::Instant::now() >= guard.bounds.hard()
            || guard.alarm.as_mut().poll(cx).is_ready()
        {
            return Some(self.expire_proto());
        }
        None
    }
    pub(crate) fn check_proto_time(&mut self, now: u64) -> Option<HostError> {
        if !self.initial_live() {
            return None;
        }
        if self.initial.as_ref().is_some_and(|guard| {
            now >= guard.bounds.until() || tokio::time::Instant::now() >= guard.bounds.hard()
        }) {
            Some(self.expire_proto())
        } else {
            None
        }
    }
    pub(crate) fn poll_connect(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Activity, HostError>> {
        let Some(connect) = self.connecting.as_mut() else {
            return Poll::Pending;
        };
        match connect.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.connecting = None;
                match result {
                    Ok(connection) => {
                        self.peer = Some(connection);
                        Poll::Ready(Ok(Activity::Io))
                    }
                    Err(error) => {
                        self.core.native_lost();
                        Poll::Ready(Err(HostError::Peer(error)))
                    }
                }
            }
        }
    }

    pub(crate) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Activity, HostError>> {
        if matches!(
            self.core.phase(),
            Phase::Closing | Phase::Detached | Phase::Closed
        ) {
            return Poll::Pending;
        }
        if self.rx_position < self.rx_size {
            match self
                .core
                .ingest(&self.rx[self.rx_position..self.rx_size], time, entropy)
            {
                Ok(n) if n > 0 => {
                    self.rx_position += n;
                    return Poll::Ready(Ok(Activity::Parsed));
                }
                Ok(_) => {}
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
        // The KX reader checks its original deadline before recv; ordinary readers run
        // actual recv first, then the source remaining-time branch below.
        if self.core.phase() == Phase::Initial {
            self.core.tick(time.now);
        }
        if self.core.read_interest()
            && self.rx_position == self.rx_size
            && let Some(peer) = self.peer.as_mut()
        {
            let mut buf = ReadBuf::new(&mut self.rx);
            match Pin::new(peer).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len();
                    if n == 0 {
                        self.core.native_lost();
                    } else {
                        self.rx_position = 0;
                        self.rx_size = n;
                        self.core.native_read_progress(time.now);
                    }
                    return Poll::Ready(Ok(Activity::Io));
                }
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(e)) => {
                    self.core.native_lost();
                    return Poll::Ready(Err(HostError::Peer(e)));
                }
                Poll::Pending => {}
            }
        }
        self.core.tick(time.now);
        Poll::Pending
    }
    pub(crate) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Activity, HostError>> {
        if self.core.write_interest()
            && let Some(peer) = self.peer.as_ref()
        {
            match peer.poll_write_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let t = match self.core.write_ready(time, entropy) {
                        Ok(Some(t)) => t,
                        Ok(None) => return Poll::Pending,
                        Err(e) => return Poll::Ready(Err(e.into())),
                    };
                    let bytes = match self.core.write_bytes(t) {
                        Ok(b) => b,
                        Err(e) => return Poll::Ready(Err(e.into())),
                    };
                    let result = match peer.try_write(bytes) {
                        Ok(0) => WriteResult::Zero,
                        Ok(n) => WriteResult::Bytes(n),
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            WriteResult::Retry
                        }
                        Err(e) => {
                            let ack = self.core.written(t, WriteResult::Fatal, time, entropy);
                            return Poll::Ready(match ack {
                                Ok(()) => Err(HostError::Peer(e)),
                                Err(e) => Err(e.into()),
                            });
                        }
                    };
                    return Poll::Ready(
                        self.core
                            .written(t, result, time, entropy)
                            .map(|()| {
                                if matches!(result, WriteResult::Retry | WriteResult::Zero) {
                                    Activity::Retry
                                } else {
                                    Activity::Io
                                }
                            })
                            .map_err(HostError::from),
                    );
                }
                Poll::Ready(Err(e)) => {
                    self.core.native_lost();
                    return Poll::Ready(Err(HostError::Peer(e)));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
