//! Explicit bounded Node construction and observations.
use crate::{connection, identity_dh, server};
use gnunet_cadet::{
    connection::Book,
    peer,
    tunnel::{context, controller},
};
use gnunet_types::{Error as ProtocolError, MonoInstant};
use std::{error::Error as StdError, fmt};

/// Shared caller-buffer package lent only while a channel is actually live.
pub use peer::Buffers as ChannelBuffers;

/// Independently constructed actual native/pure owners. Every backing array
/// and domain is caller-owned outside this movable Node.
pub struct Parts<
    'node,
    'core,
    'book,
    'pils,
    'server,
    'app,
    'appstore,
    'appbytes,
    'store,
    'bytes,
    const C: usize = 64,
    const S: usize = 32,
    const O: usize = 32,
    const P: usize = 16,
> {
    /// Borrow the application IPC owner, including its original loopback channels.
    /// The caller retains the server across construction failure and peer teardown.
    pub server: &'server mut server::Server<'app, 'appstore, 'appbytes>,
    /// Real bounded route/neighbor/frame owner.
    pub book: Book<'book, 'store, 'bytes, P>,
    /// Actual CORE MQ, bound to exactly that Book authority/local identity.
    pub bridge: connection::Bridge<'core, 'book, 'store, C, S>,
    /// One actual shared source-bound PILS DH MQ.
    pub identity_dh: identity_dh::Port<'node, 'pils, 'store, O>,
}
/// Fixed caller pools. Vectors are consumed once and never grown at runtime.
/// Crypto and payload backing storage stays outside Node and may be shared as
/// a bounded slab divided into these exclusive free packages at construction.
pub struct Storage<'node, 'store, 'bytes> {
    /// Stable node domain and fixed live context registry.
    pub contexts: context::Registry<'node>,
    /// Stable checked channel-allocation domain shared by every peer channel.
    pub channel_domain: &'node peer::Instance,
    /// Exactly two crypto stores per simultaneously live logical tunnel.
    pub tunnels: Vec<controller::Stores<'store>>,
    /// Free whole buffer packages, borrowed/recycled by actual live channels.
    pub channels: Vec<ChannelBuffers<'store, 'bytes>>,
    /// One retained decrypted packet, reused only after consume/drop.
    pub plaintext: &'store mut [u8],
    /// One global two-region outgoing plaintext/ciphertext staging slab:
    /// at least 2*(channel.payload_bytes+12)+112 bytes, independent of channels.
    pub ciphertext: &'store mut [u8],
}
/// Explicit local policy. All protocol layouts remain the official layouts.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Shared fixed original-control/channel frame correlations.
    pub pending_frames: usize,
    /// Concurrent incoming CTN reservations for original loose/live/retiring
    /// channels and pending negative responses. Fully retired originals release
    /// their slots; waiting for a listener consumes no channel payload slab.
    pub used_channels: usize,
    /// Reliable-channel window/payload/retry policy.
    pub channel: peer::Limits,
    /// KX/ratchet/staging and original-candidate timers.
    pub tunnel: controller::Limits,
    /// Original local opening budget, never renewed by retries/refusal.
    pub opening_micros: u64,
    /// A tunnel with no channels may retire after this real idle duration.
    pub idle_micros: u64,
    /// Bounded route retry/retirement cadence in native elapsed microseconds.
    pub route_tick_micros: u64,
    /// Cipher packets before an authenticated permitted send DH ratchet.
    pub ratchet_messages: u32,
    /// Maximum age before an authenticated permitted send DH ratchet.
    pub ratchet_micros: u64,
    /// Explicit bounded actual directory snapshots and independent management MQs.
    pub management: crate::management::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            pending_frames: 32,
            used_channels: 1024,
            channel: peer::Limits {
                window: 1,
                ..peer::Limits::default()
            },
            tunnel: controller::Limits::default(),
            opening_micros: 120_000_000,
            idle_micros: 120_000_000,
            route_tick_micros: 250_000,
            ratchet_messages: 64,
            ratchet_micros: 3_600_000_000,
            management: crate::management::Limits::default(),
        }
    }
}
/// Exact native poll boundary which returned its original error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeStage {
    /// Actual CORE client/Book bridge poll.
    CoreBridge,
    /// Actual shared PILS identity-DH client poll.
    IdentityDh,
}
/// Actual failure retains its original native layer/cause.
#[derive(Debug)]
pub enum Error {
    /// Pure source/capacity/protocol refusal.
    Protocol(ProtocolError),
    /// Actual CORE or shared PILS native failure.
    Native(crate::Error),
    /// Poll-boundary diagnosis with the unchanged original native error.
    NativeAt {
        /// Actual native owner which returned Err.
        stage: NativeStage,
        /// Actual CORE driver failure context, when its poll supplied one.
        core_context: Option<gnunet_core_client_host::OperationContext>,
        /// Original typed error, retained as the standard error source.
        cause: crate::Error,
    },
    /// Actual accepted application service failure.
    Application(server::Error),
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        Self::Native(e)
    }
}
impl From<server::Error> for Error {
    fn from(e: server::Error) -> Self {
        Self::Application(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "CADET Node: {e}"),
            Self::Native(e) => write!(f, "CADET Node native: {e}"),
            Self::NativeAt {
                stage,
                core_context,
                cause,
            } => write!(
                f,
                "CADET Node native {stage:?} context={core_context:?}: {cause}"
            ),
            Self::Application(e) => write!(f, "CADET Node application: {e}"),
        }
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::NativeAt { cause, .. } => Some(cause),
            Self::Application(e) => Some(e),
        }
    }
}
/// A source-authenticated packet/effect refused by an actual local bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Refusal {
    /// Original expected end-to-end peer, distinct from raw CID.
    pub peer: [u8; 32],
    /// Actual raw CTN if a channel packet was involved.
    pub channel: Option<u32>,
    /// Concrete permanent/refusable resource reason.
    pub reason: ProtocolError,
}
/// One actual caller-driven bounded action. Original rich native loss events
/// remain owned here; no queue/write is reported as peer application delivery.
pub enum Step<'node, 'core, 'book, 'pils, const O: usize = 32> {
    /// One original application IO/effect step.
    Application(server::Progress),
    /// Actual CORE Book/physical progress; mandatory effects were processed.
    Core(connection::Step<'core, 'book>),
    /// Actual original shared PILS progress; secret result remains private.
    IdentityDh(identity_dh::Step<'node, 'pils, O>),
    /// One committed pure/retirement action; no physical write inferred.
    Progress,
    /// One explicit actual packet/open refusal, with bounded original metadata.
    Refused(Refusal),
    /// Persisted monotime range exhausted; caller reserves outside socket poll.
    MonotimeRequired,
    /// Caller observation budget ended; original jobs/cursors remain retained.
    WaitDeadline,
    /// Local MQs stopped and every tracked original peer effect really retired.
    Quiescent,
    /// Peer debt retired while the same application MQs and cursors are paused.
    PeersRetired,
}
/// Fixed cumulative observations, without peer application delivery claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Actual tunnel context allocations.
    pub tunnels: u64,
    /// Actual peer-channel owner allocations.
    pub channels: u64,
    /// Authenticated first OPENs retained while their local port was closed.
    pub loose_retained: u64,
    /// Original retained OPENs actually bound to a later registered listener.
    pub loose_bound: u64,
    /// Original closed-port waits expired locally, without sending DESTROY.
    pub loose_expired: u64,
    /// Actual remote DESTROYs removed an original pending closed-port wait.
    pub loose_destroyed: u64,
    /// Whole authenticated input packets, including consumed protocol controls.
    pub authenticated: u64,
    /// Explicit packet/resource/permanent drops.
    pub dropped: u64,
    /// Original prepared peer packets explicitly dropped by a diagnostic request.
    pub diagnostic_drops: u64,
    /// Actual admitted peer copies of retained local service payloads.
    pub admitted: u64,
    /// Actual peer accepted payloads, not application-work acknowledgements.
    pub peer_accepted: u64,
    /// Actual local-app receive_done handed back to the original peer owner.
    pub receive_done: u64,
    /// Original local openings failed after explicit refusal/retirement.
    pub failed_opens: u64,
}
/// Independent actual source-stop results. Continue polling original effects;
/// this is not a claim that applications or external signing jobs drained.
pub struct Close<'core, 'book, 'pils, const O: usize = 32> {
    /// Actual original CORE retirement, including an independent clock refusal.
    pub core: Result<Option<connection::Step<'core, 'book>>, crate::Error>,
    /// Clock-independent physical stop/detach of all accepted application MQs.
    pub applications: Result<(), server::Error>,
    /// Actual original shared-DH operations retired by physical source close.
    pub identity_dh: [Option<gnunet_pils::client::OperationId<'pils>>; O],
}
/// Independent peer-only stops; application MQs remain owned and paused.
pub struct PeerClose<'core, 'book, 'pils, const O: usize = 32> {
    /// Actual original CORE retirement, including an independent refusal.
    pub core: Result<Option<connection::Step<'core, 'book>>, crate::Error>,
    /// Actual shared-DH operations retired by physical source close.
    pub identity_dh: [Option<gnunet_pils::client::OperationId<'pils>>; O],
    /// Logical identity-bound endpoint retirement, retaining actual peer debt.
    pub applications: Result<(), ProtocolError>,
}
/// Original local demand waiting for an explicitly supplied discovery/transport
/// port. Observing it grants no route, current neighbor or remote success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Discovery<'app> {
    /// Original generational application open intent.
    pub open: gnunet_cadet::service::Open<'app>,
    /// Exact expected end-to-end peer.
    pub peer: [u8; 32],
    /// Original native elapsed opening bound, never renewed by discovery retries.
    pub expires: MonoInstant,
}
/// Read-only original demand for a TRANSPORT application preference. This is
/// neither a current CORE neighbor nor proof of a connected/authenticated peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportDemand<'node, 'app> {
    /// Original non-reusable tunnel context, including its local domain.
    pub scope: gnunet_cadet::tunnel::context::Scope<'node>,
    /// Exact original local application generation; None is an independently
    /// confirmed tunnel retained until normal Node retirement/idle policy.
    pub channel: Option<gnunet_cadet::service::Channel<'app>>,
    /// An opening keeps its exact original intent and native elapsed/hard targets.
    /// None requires an already established channel or confirmed tunnel.
    pub opening: Option<(Discovery<'app>, std::time::Instant)>,
}
/// Original signing work, ready for the actual signer adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signing<'book> {
    /// Original Book-minted purpose38 request, never a public signature.
    pub request: gnunet_cadet::connection::SignRequest<'book>,
    /// Original native elapsed effect deadline.
    pub expires: MonoInstant,
}
