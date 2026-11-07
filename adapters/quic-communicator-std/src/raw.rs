//! Actual Quinn stream4 IO. No transport-node/TCP/UDP business dependency.
use gnunet_transport_quic::{Instance, Role, raw as profile};
use gnunet_types::{Error as Protocol, MonoInstant};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};
/// Exact original local send token, minted by the communicator's MQ owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendId(pub(crate) u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameId<'id> {
    epoch: gnunet_transport_quic::Epoch<'id>,
    serial: u64,
}
pub(crate) struct FrameView<'a, 'id> {
    pub(crate) id: FrameId<'id>,
    pub(crate) bytes: &'a [u8],
}
struct Sending {
    id: SendId,
    bytes: Zeroizing<Vec<u8>>,
    at: usize,
    hard: Instant,
}
/// Actual stream IO failure. No payload, key or unauthenticated diagnostic bytes.
#[derive(Debug)]
pub(crate) enum Failure {
    Protocol(Protocol),
    Connection(quinn::ConnectionError),
    Read(quinn::ReadError),
    Write(quinn::WriteError),
}
impl From<Protocol> for Failure {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
/// Actual provider progress only; accepted plaintext is never a UDP-byte receipt.
pub(crate) enum Step {
    Pending,
    Activity {
        read: usize,
    },
    StreamsReady,
    Claim([u8; 32]),
    Frame,
    IdentityAccepted(usize),
    ProviderAccepted {
        id: SendId,
        bytes: usize,
        complete: bool,
    },
    Fin,
}
/// One actual QUIC connection with original external slab and original identity.
/// The otherwise-unused stream0 is retained without FIN/reset/STOP; C closes
/// the connection on FIN of ANY stream. Never await0 before continuing to4.
pub(crate) struct Link<'id, 'buf> {
    connection: quinn::Connection,
    profile: Option<profile::Connection<'id, 'buf>>,
    zero: Option<(quinn::SendStream, quinn::RecvStream)>,
    streams: Option<(quinn::SendStream, quinn::RecvStream)>,
    role: Role,
    tx: Option<Sending>,
    closed: bool,
    fin: bool,
    frame: Option<FrameId<'id>>,
    next_frame: u64,
    rx: [u8; 1024],
    rx_at: usize,
    rx_used: usize,
}
impl<'id, 'buf> Link<'id, 'buf> {
    /// Real completed handshake is required by the outer concrete endpoint
    /// owner. Its negotiated ALPN is checked before local profile admission.
    pub(crate) fn adopt(
        connection: &quinn::Connection,
        instance: &'id Instance,
        now: MonoInstant,
        loan: &mut Option<&'buf mut [u8]>,
        options: profile::Options,
    ) -> Result<Self, Failure> {
        let data = connection.handshake_data().ok_or(Protocol::NotReady)?;
        let data = data
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .map_err(|_| Protocol::Unsupported)?;
        let alpn = data.protocol.as_deref().ok_or(Protocol::Unsupported)?;
        let profile = profile::Connection::new_in(instance, alpn, now, loan, options)?;
        Ok(Self {
            connection: connection.clone(),
            profile: Some(profile),
            zero: None,
            streams: None,
            role: options.role,
            tx: None,
            closed: false,
            fin: false,
            frame: None,
            next_frame: 0,
            rx: [0; 1024],
            rx_at: 0,
            rx_used: 0,
        })
    }
    pub(crate) fn may_send(&self, now: MonoInstant) -> Result<bool, Failure> {
        if self.closed {
            return Err(Protocol::Closed.into());
        }
        Ok(self.streams.is_some()
            && self
                .profile
                .as_ref()
                .ok_or(Protocol::Closed)?
                .may_send(now)?)
    }
    pub(crate) fn frame(&self, now: MonoInstant) -> Result<Option<FrameView<'_, 'id>>, Failure> {
        let profile = self.profile.as_ref().ok_or(Protocol::Closed)?;
        match profile.frame(now) {
            Ok(bytes) => Ok(Some(FrameView {
                id: self.frame.ok_or(Protocol::Conflict)?,
                bytes,
            })),
            Err(Protocol::NotReady) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    /// Actual original FC completion only. Clock-free; stale frame callbacks
    /// cannot release a later frame even on that same long-lived stream4.
    pub(crate) fn release_frame(&mut self, id: FrameId<'id>) -> Result<usize, Failure> {
        if self.frame != Some(id) {
            return Err(Protocol::Stale.into());
        }
        let profile = self.profile.as_mut().ok_or(Protocol::Closed)?;
        let bytes = if self.closed {
            0
        } else {
            profile.release_frame()?
        };
        self.frame = None;
        Ok(bytes)
    }
    pub(crate) fn queue(
        &mut self,
        id: SendId,
        bytes: &[u8],
        hard: Instant,
        now: MonoInstant,
    ) -> Result<(), Failure> {
        if !self.may_send(now)? {
            return Err(Protocol::NotReady.into());
        }
        if self.tx.is_some() {
            return Err(Protocol::Capacity.into());
        }
        if Instant::now() >= hard {
            return Err(Protocol::Deadline.into());
        }
        gnunet_wire::official::Frame::decode(bytes)?;
        if bytes.len() > profile::ADVERTISED_MTU {
            return Err(Protocol::TooLarge.into());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Protocol::Capacity)?;
        owned.extend_from_slice(bytes);
        self.tx = Some(Sending {
            id,
            bytes: Zeroizing::new(owned),
            at: 0,
            hard,
        });
        Ok(())
    }
    /// Whole provider acceptance retains original metadata until the concrete
    /// communicator's original Sent callback bookkeeping actually takes it.
    pub(crate) fn take_accepted(&mut self, id: SendId) -> Result<(), Failure> {
        let row = self.tx.as_ref().ok_or(Protocol::Stale)?;
        if row.id != id {
            return Err(Protocol::Stale.into());
        }
        if row.at != row.bytes.len() {
            return Err(Protocol::NotReady.into());
        }
        self.tx = None;
        Ok(())
    }
    fn poll_streams(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        if self.streams.is_some() {
            return Ok(false);
        }
        // Exactly two canonical ids, so this bounded loop cannot wait on0 data.
        for _ in 0..2 {
            let result = if matches!(self.role, Role::Initiator { .. }) {
                let open = self.connection.open_bi();
                let mut open = std::pin::pin!(open);
                open.as_mut().poll(cx)
            } else {
                let accept = self.connection.accept_bi();
                let mut accept = std::pin::pin!(accept);
                accept.as_mut().poll(cx)
            };
            let pair = match result {
                Poll::Pending => return Ok(false),
                Poll::Ready(Err(e)) => return Err(Failure::Connection(e)),
                Poll::Ready(Ok(p)) => p,
            };
            let id = u64::from(pair.0.id());
            if id == 0 && self.zero.is_none() {
                self.zero = Some(pair);
                continue;
            }
            if id == 4 && self.zero.is_some() {
                self.streams = Some(pair);
                return Ok(true);
            }
            // Close whole original connection first; then dropping this extra
            // unexpected stream cannot implicitly FIN an otherwise-live C peer.
            self.connection
                .close(quinn::VarInt::from_u32(0), b"unexpected raw stream");
            drop(pair);
            self.closed = true;
            return Err(Protocol::Malformed.into());
        }
        Ok(false)
    }
    /// Actual stream0 traffic is a protocol error; a bounded nonblocking probe
    /// never waits on it and never originates a FIN/reset/STOP on the live peer.
    fn poll_zero(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if let Some((_, recv)) = &mut self.zero {
            let mut one = [0u8; 1];
            match recv.poll_read(cx, &mut one) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Err(Failure::Read(e)),
                Poll::Ready(Ok(_)) => return Err(Protocol::Malformed.into()),
            }
        }
        Ok(())
    }
    /// One fair actual connection IO step. Source/native gate is checked by the
    /// concrete owner before this call and socket wrapper before native IO.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>, now: MonoInstant) -> Result<Step, Failure> {
        if self.closed {
            return Err(Protocol::Closed.into());
        }
        if let Some(error) = self.connection.close_reason() {
            return Err(Failure::Connection(error));
        }
        if self.poll_streams(cx)? {
            return Ok(Step::StreamsReady);
        }
        self.poll_zero(cx)?;
        let Some((send, recv)) = &mut self.streams else {
            return Ok(Step::Pending);
        };
        let profile = self.profile.as_mut().ok_or(Protocol::Closed)?;
        if matches!(self.role, Role::Initiator { .. }) {
            let suffix = profile.identity_suffix(now)?;
            if !suffix.is_empty() {
                return match Pin::new(&mut *send).poll_write(cx, suffix) {
                    Poll::Pending => Ok(Step::Pending),
                    Poll::Ready(Err(e)) => Err(Failure::Write(e)),
                    Poll::Ready(Ok(0)) => Err(Protocol::Io.into()),
                    Poll::Ready(Ok(n)) => {
                        profile.identity_accepted(n)?;
                        Ok(Step::IdentityAccepted(n))
                    }
                };
            }
        }
        if let Some(tx) = &mut self.tx
            && tx.at < tx.bytes.len()
        {
            if Instant::now() >= tx.hard {
                return Err(Protocol::Deadline.into());
            }
            match Pin::new(&mut *send).poll_write(cx, &tx.bytes[tx.at..]) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Err(Failure::Write(e)),
                Poll::Ready(Ok(0)) => return Err(Protocol::Io.into()),
                Poll::Ready(Ok(n)) => {
                    tx.at = tx.at.checked_add(n).ok_or(Protocol::Overflow)?;
                    if tx.at > tx.bytes.len() {
                        return Err(Protocol::Conflict.into());
                    }
                    return Ok(Step::ProviderAccepted {
                        id: tx.id,
                        bytes: n,
                        complete: tx.at == tx.bytes.len(),
                    });
                }
            }
        }
        match profile.frame(now) {
            Ok(_) => return Ok(Step::Frame),
            Err(Protocol::NotReady) => {}
            Err(e) => return Err(e.into()),
        }
        if self.fin {
            return Ok(Step::Pending);
        }
        if self.rx_at == self.rx_used {
            match recv.poll_read(cx, &mut self.rx) {
                Poll::Pending => return Ok(Step::Pending),
                Poll::Ready(Err(e)) => return Err(Failure::Read(e)),
                Poll::Ready(Ok(0)) => {
                    profile.finish(4)?;
                    self.fin = true;
                    return Ok(Step::Fin);
                }
                Poll::Ready(Ok(n)) => {
                    self.rx_at = 0;
                    self.rx_used = n
                }
            }
        }
        let step = profile.push(4, &self.rx[self.rx_at..self.rx_used], now)?;
        self.rx_at += step.consumed;
        if let Some(claim) = step.claim {
            return Ok(Step::Claim(claim.0));
        }
        if step.frame {
            let serial = self.next_frame.checked_add(1).ok_or(Protocol::Overflow)?;
            self.next_frame = serial;
            self.frame = Some(FrameId {
                epoch: profile.epoch(),
                serial,
            });
            return Ok(Step::Frame);
        }
        if step.consumed > 0 {
            Ok(Step::Activity {
                read: step.consumed,
            })
        } else {
            Ok(Step::Pending)
        }
    }
    /// Actual original connection close is requested before stream handles may
    /// drop. This is local shutdown only; driver/UDP drain still remains owned.
    pub(crate) fn close(&mut self) {
        if !self.closed {
            self.connection.close(quinn::VarInt::from_u32(0), b"");
            self.closed = true
        }
        if let Some(profile) = &mut self.profile {
            profile.retire();
        }
    }
    /// Original retained send acceptance; zero differs from an exposed prefix.
    pub(crate) fn pending_send(&self) -> Option<(SendId, usize, usize)> {
        self.tx.as_ref().map(|s| (s.id, s.at, s.bytes.len()))
    }
    /// Caller must first confirm actual original backend driver, incoming FC and
    /// communicator output debts retired. No new source may borrow early.
    pub(crate) fn recycle(mut self) -> Result<&'buf mut [u8], Failure> {
        self.close();
        drop(self.streams.take());
        drop(self.zero.take());
        self.rx.zeroize();
        self.profile
            .take()
            .map(|p| p.recycle())
            .ok_or_else(|| Protocol::Stale.into())
    }
}
impl Drop for Link<'_, '_> {
    fn drop(&mut self) {
        self.close();
        self.rx.zeroize();
    }
}
