//! Bounded TCP communicator service/session driver. Native and service ownership
//! persists in this value across cancellation of any wait future. It implements
//! no substitute TRANSPORT, CORE, PEERSTORE or PILS service.
#![forbid(unsafe_code)]
#![cfg(unix)]
/// Original scan/store durability task identities and real process port.
pub mod history;
mod link;
mod manager;
mod peer;
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_hello::{Hello, Limits, SignatureProfile};
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::{
    services,
    session::{Session, Time},
};
use gnunet_types::Error;
use link::Link;
pub use manager::{
    Communicator, Connect, CreateId, CreateRequest, HandshakeBounds, ManagerCapacity,
    NativeAdmission, OwnedFailure, Progress, SessionId,
};
use std::{
    future::poll_fn,
    io,
    task::{Context, Poll},
};
/// Actual source clock port. Logical absolute scheduling time may regress;
/// signed persistent monotime is independent. A provider must wake registered
/// waiters and advance revision when its explicit offset/speedup changes.
pub trait Clock {
    /// Read actual current logical time and actual independently generated stamp.
    fn read(&mut self) -> Result<Time, Error>;
    /// Offset/speedup revision; this is local metadata and never a wire field.
    fn revision(&self) -> u64;
    /// Register the current waiter. Ready consumes a real clock-change event.
    fn poll_change(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}
/// Original failure observed while driving one actual service MQ.
#[derive(Debug)]
pub enum ServiceCause {
    /// Actual original socket read/write failure, retained without replacement.
    Io(io::Error),
    /// Actual response decoding or domain callback rejection on that MQ.
    Protocol(Error),
}
impl std::fmt::Display for ServiceCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "service IO: {error}"),
            Self::Protocol(error) => write!(f, "service response: {error}"),
        }
    }
}
impl std::error::Error for ServiceCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}
/// A service task failure and its separate original-MQ retirement outcome.
/// No later cleanup rejection replaces the socket or callback cause.
#[derive(Debug)]
pub struct ServiceFailure {
    /// Original observed socket or response/callback cause.
    pub cause: ServiceCause,
    /// Independent rejection while retiring that same MQ and its callbacks.
    pub retirement: Option<Error>,
}
impl ServiceFailure {
    /// Whether this value records native IO without a retirement rejection.
    /// This does not perform or prove retirement or grant reconnect authority.
    #[must_use]
    pub const fn io_retired(&self) -> bool {
        matches!(
            self,
            Self {
                cause: ServiceCause::Io(_),
                retirement: None,
            }
        )
    }
}
impl From<io::Error> for ServiceFailure {
    fn from(cause: io::Error) -> Self {
        Self {
            cause: ServiceCause::Io(cause),
            retirement: None,
        }
    }
}
impl std::fmt::Display for ServiceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cause)?;
        if let Some(error) = self.retirement {
            write!(f, "; independent MQ retirement: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for ServiceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// Explicit service/native failure, never reported as a successful host effect.
#[derive(Debug)]
pub enum HostError {
    /// Finite caller resource or protocol/core rejection.
    Core(Error),
    /// Actual original peer TCP error.
    Peer(io::Error),
    /// Original PEERSTORE task cause and its independent MQ retirement result.
    Peerstore(ServiceFailure),
    /// Original TRANSPORT task cause and its independent MQ retirement result.
    Transport(ServiceFailure),
}
impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(error) => write!(f, "TCP core: {error}"),
            Self::Peer(error) => write!(f, "TCP peer: {error}"),
            Self::Peerstore(error) => write!(f, "TCP PEERSTORE: {error}"),
            Self::Transport(error) => write!(f, "TCP TRANSPORT: {error}"),
        }
    }
}
impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Peer(error) => Some(error),
            Self::Peerstore(error) | Self::Transport(error) => Some(&error.cause),
        }
    }
}
impl HostError {
    /// Whether TRANSPORT records native IO without an independent retirement
    /// rejection. The enclosing owner must observe its actual MQ retirement
    /// and still decides whether recovery is allowed.
    #[must_use]
    pub const fn transport_io_retired(&self) -> bool {
        match self {
            Self::Transport(failure) => failure.io_retired(),
            _ => false,
        }
    }
    pub(crate) fn service_failure(
        peerstore: bool,
        cause: ServiceCause,
        retire: impl FnOnce() -> Result<(), Error>,
    ) -> Self {
        // Retain the original observed cause while this exact source's cleanup
        // runs once. A refusal is an independent fact, never a replacement.
        let retirement = retire().err();
        let failure = ServiceFailure { cause, retirement };
        if peerstore {
            Self::Peerstore(failure)
        } else {
            Self::Transport(failure)
        }
    }
}
impl From<Error> for HostError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
/// Finite host admission bounds, separate from official wire/config defaults.
#[derive(Clone, Copy, Debug)]
pub struct Capacity {
    /// Maximum persistent IPC bytes per service connection, at least65535.
    pub ipc_bytes: usize,
    /// Maximum persistent IPC frame count per service connection.
    pub ipc_frames: usize,
    /// Maximum live receive callbacks for this physical session.
    pub callbacks: usize,
}
/// One actual owned progress observation; neither readability nor a plan is ACKed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activity {
    /// A real native/service IO operation transferred bytes or reported EOF.
    Io,
    /// A real syscall returned zero, EAGAIN or EINTR; no byte progress is claimed.
    Retry,
    /// Previously read persistent ciphertext was actually parsed/consumed.
    Parsed,
    /// Actual local cryptographic/plaintext state advanced without a syscall.
    Prepared,
    /// An actual service envelope was admitted to bounded persistent TX.
    Admitted,
    /// An actual reply/callback was consumed.
    Callback,
    /// An actual original peer connection was closed.
    Closed,
    /// An original incoming control request needs the multi-session registry.
    Registry,
}
/// One-session convenience facade over the same shared-process implementation.
/// It exists for explicit component fixtures; multi-peer processes use Communicator.
pub struct Driver<'a> {
    inner: Communicator<'a>,
    session: SessionId,
}
impl<'a> Driver<'a> {
    /// Adopt one actual socket and one real service pair, using the common manager.
    pub fn new(
        core: Session<'a>,
        peer: Connection,
        services: [Connection; 2],
        capacity: Capacity,
        address: &[u8],
        network: u32,
    ) -> Result<Self, HostError> {
        let mut inner = Communicator::new(
            services,
            capacity,
            ManagerCapacity {
                sessions: 1,
                pending_sends: 1,
                commands: 1,
            },
        )?;
        let session = inner
            .admit(Box::new(core), peer, address, network)
            .map_err(|r| r.reason)?;
        Ok(Self { inner, session })
    }
    /// Inspect the sole original core. This facade cannot retire or replace its ID.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "Private one-session facade never exposes retirement or replacement of its original session"
    )]
    pub fn core(&self) -> &Session<'a> {
        self.inner
            .core(&self.session)
            .expect("sole session remains owned by this facade")
    }
    /// All original native/callback owners and shared queued bytes have drained.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.inner.is_quiescent()
    }
    /// Begin authenticated close on the sole actual peer.
    pub fn finish(&mut self, time: Time) -> Result<(), HostError> {
        self.inner.finish(&self.session, time)
    }
    /// Record an actual native peer loss; still drive explicit service cleanup.
    pub fn lost(&mut self) {
        let _original = self.inner.lost(&self.session);
    }
    /// Retire only the original failed PEERSTORE MQ and callback epoch.
    /// Returns only a local epoch/state rejection, not a replacement IO cause.
    pub fn peerstore_lost(&mut self, time: Time) -> Result<(), Error> {
        self.inner.peerstore_lost(time)
    }
    /// Retire only the original failed TRANSPORT MQ and callback epoch.
    /// Returns only a local epoch/state rejection, not a replacement IO cause.
    pub fn transport_lost(&mut self, time: Time) -> Result<(), Error> {
        self.inner.transport_lost(time)
    }
    /// Attach a genuinely connected replacement without reviving old callbacks.
    pub fn attach_peerstore(
        &mut self,
        connection: Connection,
    ) -> Result<(), gnunet_types::Rejected<Connection>> {
        self.inner.attach_peerstore(connection)
    }
    /// Reannounce the original queue on one genuinely connected replacement MQ.
    pub fn attach_transport(
        &mut self,
        connection: Connection,
    ) -> Result<(), gnunet_types::Rejected<Connection>> {
        self.inner.attach_transport(connection)
    }
    /// Poll the same rotating shared-service/peer scheduler as the multi-peer manager.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        history: &mut impl history::ReplayHistory,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Activity, HostError>> {
        self.inner
            .poll_step(cx, time, history, entropy)
            .map(|r| r.map(|p| p.activity))
    }
    /// Drive using one retained timer and the caller's distinct logical/signed clocks.
    pub fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        clock: &mut (impl Clock + history::ReplayHistory),
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Activity, HostError>> {
        self.inner
            .poll_drive(cx, clock, entropy)
            .map(|r| r.map(|p| p.activity))
    }
    /// Cancellation preserves all original native and service owners.
    pub async fn drive(
        &mut self,
        clock: &mut (impl Clock + history::ReplayHistory),
        entropy: &mut impl Entropy,
    ) -> Result<Activity, HostError> {
        poll_fn(|cx| self.poll_drive(cx, clock, entropy)).await
    }
    /// Wait for one actual step without dropping the original I/O state on cancellation.
    pub async fn step(
        &mut self,
        time: Time,
        history: &mut impl history::ReplayHistory,
        entropy: &mut impl Entropy,
    ) -> Result<Activity, HostError> {
        poll_fn(|cx| self.poll_step(cx, time, history, entropy)).await
    }
}

#[cfg(test)]
mod failure_tests;
/// Verify the actual PILS HELLO and key-ring match using the caller's IKM.
/// Default HELLO profile authenticates metadata only, never its address list.
pub fn pils_key(
    update: &[u8],
    seed: &[u8; 32],
    scratch: &mut [u8],
    limits: Limits,
    profile: SignatureProfile,
) -> Result<EddsaPrivateKey, Error> {
    let update = services::Pils::decode(update)?;
    let hello = Hello::parse_block(update.block(), scratch, limits)?;
    hello.verify_signature(profile)?;
    let key = update.derive(seed)?;
    if key.public_key() != hello.peer() {
        return Err(Error::Authentication);
    }
    Ok(key)
}

/// Verify one actual PILS HELLO and derive a complete atomic key ring. Expiration
/// is retained as source metadata; this is not a claim that addresses are signed.
pub fn pils_ring(
    update: &[u8],
    seed: &[u8; 32],
    scratch: &mut [u8],
    limits: Limits,
    profile: SignatureProfile,
) -> Result<gnunet_tcp_communicator_core::session::KeyRing, Error> {
    let update = services::Pils::decode(update)?;
    let hello = Hello::parse_block(update.block(), scratch, limits)?;
    hello.verify_signature(profile)?;
    let keys = update.key_ring(seed)?;
    if keys.public() != hello.peer() {
        return Err(Error::Authentication);
    }
    Ok(keys)
}

/// Actual PILS subscription with persistent RX, independent of any waiting future.
/// It does not invent an identity while waiting for a real valid HELLO update.
pub struct PilsFeed {
    link: Link,
}
impl PilsFeed {
    /// Take the one actual connected local PILS stream and allocate bounded RX.
    pub fn new(connection: Connection) -> Result<Self, Error> {
        Ok(Self {
            link: Link::new(connection, 65535, 1)?,
        })
    }
    /// Borrow only the complete received original message. Release it after
    /// verification and atomic replacement, or close the feed on a fatal error.
    #[must_use]
    pub fn update(&self) -> Option<&[u8]> {
        self.link.frame()
    }
    /// Consume the same original complete update after its actual application.
    pub fn release(&mut self) {
        self.link.release();
    }
    /// Poll the actual original stream; partial header/body bytes remain owned.
    pub fn poll_update(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ServiceCause>> {
        if self.link.frame().is_some() {
            return Poll::Ready(Ok(()));
        }
        match self.link.poll_rx(cx) {
            Poll::Ready(Ok(())) => {
                if self.link.frame().is_some() {
                    Poll::Ready(Ok(()))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            other => other,
        }
    }
    /// Cancellation-safe wait for a complete real PILS message.
    pub async fn wait(&mut self) -> Result<(), ServiceCause> {
        poll_fn(|cx| self.poll_update(cx)).await
    }
}
