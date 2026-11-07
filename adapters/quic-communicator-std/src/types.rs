//! Explicit source, bounded resource and actual local observation types.
use gnunet_client_host::EndpointSource;
use gnunet_types::Error as Protocol;
use std::{cell::Cell, fmt, net::SocketAddr, time::Duration};
/// Stable caller-owned allocation domains. No task, global state or native IO.
#[derive(Default)]
pub struct Instance {
    pub(crate) next: Cell<u64>,
    pub(crate) profile: gnunet_transport_quic::Instance,
    pub(crate) nat: gnunet_nat_client_host::Instance,
}
impl Instance {
    /// Construct storage without using a runtime or entropy.
    pub fn new() -> Self {
        Self::default()
    }
}
/// One original communicator allocation. Pointer plus checked allocation prevents
/// a later source from accepting an old queue/callback as a new observation.
#[derive(Clone, Copy)]
pub struct Epoch<'id> {
    pub(crate) owner: &'id Instance,
    pub(crate) allocation: u64,
}
impl PartialEq for Epoch<'_> {
    fn eq(&self, b: &Self) -> bool {
        std::ptr::eq(self.owner, b.owner) && self.allocation == b.allocation
    }
}
impl Eq for Epoch<'_> {}
impl fmt::Debug for Epoch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("QuicSource").field(&self.allocation).finish()
    }
}
/// Fixed actual selectors. Their clock and Resolver remain caller-owned.
pub struct Sources {
    /// Standard TRANSPORT communicator MQ, not a custom transport protocol.
    pub transport: EndpointSource,
    /// Public local PILS observation, with explicit metadata-only default profile.
    pub pils: EndpointSource,
    /// Optional actual NAT service. None is an explicit local-only profile.
    pub nat: Option<Nat>,
}
/// Explicit original NAT source/profile; no native sockaddr ABI is inferred.
pub struct Nat {
    /// Original service selector, snapshotted with the other live selectors.
    pub source: EndpointSource,
    /// Exact client/service producer ABIs.
    pub profiles: gnunet_nat_client_host::Profiles,
    /// Official configuration section without a terminal NUL.
    pub section: Vec<u8>,
    /// Maximum live original address callbacks/advertisements.
    pub addresses: usize,
}
/// Bounded operation/source resources. QUIC driver slots are connections+1;
/// retired connection metadata holds its original slot until actual driver exit.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concrete backend windows, connection and stream caps.
    pub backend: crate::endpoint::Limits,
    /// Actual interface snapshot metadata caps; no silent partial snapshots.
    pub interfaces: gnunet_native::interfaces::Limits,
    /// Actual read-only local-prefix classification refresh interval.
    pub interface_refresh: Duration,
    /// Raw incoming complete frame bound; independent of advertised TX1000.
    pub raw_body: usize,
    /// H3 per-stream body bound, matching C internal1452 by default.
    pub h3_body: usize,
    /// H3 decoded header byte budget per original request.
    pub h3_headers: usize,
    /// Outstanding H3 GET requests,1..16; caller slots require polls+2.
    pub h3_polls: usize,
    /// Original finite H3 request/long-poll lifetime.
    pub h3_request_timeout: Duration,
    /// Maximum total request intents per original H3 source.
    pub h3_requests: u64,
    /// Retained original communicator FIFO frame cap, at least4.
    pub output_frames: usize,
    /// Retained actual FIFO bytes, at least131070.
    pub output_bytes: usize,
    /// Finite native read/write slice.
    pub io_slice: usize,
    /// Fixed initial readiness allowance.
    pub startup: Duration,
    /// Original send, first-input and incoming callback lifetime.
    pub operation: Duration,
    /// Actual connection inactivity lifetime, renewed only by positive IO.
    pub idle: Duration,
    /// Finite complete allocation lifetime, never renewed by reconnect/rollback.
    pub lifetime: Duration,
    /// Actual source close/drain allowance.
    pub close_grace: Duration,
    /// Explicit PILS HELLO signature profile; Reference029 covers metadata only.
    pub identity_profile: gnunet_pils::Profile,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            backend: crate::endpoint::Limits::default(),
            interfaces: gnunet_native::interfaces::Limits::default(),
            interface_refresh: Duration::from_secs(120),
            raw_body: 1232,
            h3_body: 1452,
            h3_headers: 4096,
            h3_polls: 16,
            h3_request_timeout: Duration::from_secs(30),
            h3_requests: 65536,
            output_frames: 16,
            output_bytes: 1048560,
            io_slice: 65535,
            startup: Duration::from_secs(30),
            operation: Duration::from_secs(30),
            idle: Duration::from_secs(300),
            lifetime: Duration::from_secs(86400),
            close_grace: Duration::from_secs(3),
            identity_profile: gnunet_pils::Profile::Reference029,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Fault> {
        if self.backend.connections == 0
            || self.backend.connections > 65535
            || self.output_frames < 4
            || self.output_frames > 65535
            || self.output_bytes < 131070
            || self.io_slice == 0
            || !(1000..=gnunet_wire::official::communicator::MAX_INCOMING).contains(&self.raw_body)
            || !(1080..=gnunet_wire::official::communicator::MAX_INCOMING).contains(&self.h3_body)
            || self.h3_headers < 128
            || self.h3_headers > 65535
            || !(1..=16).contains(&self.h3_polls)
            || self.h3_requests == 0
        {
            return Err(Protocol::InvalidInput.into());
        }
        for d in [
            self.startup,
            self.operation,
            self.idle,
            self.lifetime,
            self.close_grace,
            self.h3_request_timeout,
            self.interface_refresh,
        ] {
            if d.is_zero()
                || d.as_micros() > u64::MAX as u128
                || tokio::time::Instant::now().checked_add(d).is_none()
            {
                return Err(Protocol::InvalidInput.into());
            }
        }
        Ok(())
    }
}
/// Real original cause, preserving native/backend diagnostics without plaintext.
#[derive(Debug)]
pub enum Fault {
    /// Protocol, clock, ownership or capacity refusal.
    Protocol(Protocol),
    /// Actual shared CLIENT/configuration/Resolver error.
    Client(gnunet_client_host::ConnectError),
    /// Actual native IO error.
    Io(std::io::Error),
    /// Actual QUIC initial connect refusal.
    Connect(quinn::ConnectError),
    /// Actual original QUIC connection failure.
    Connection(quinn::ConnectionError),
    /// Actual original stream read failure.
    Read(quinn::ReadError),
    /// Actual original stream write failure.
    Write(quinn::WriteError),
    /// Actual NAT client/configuration failure.
    Nat(gnunet_nat_client_host::Error),
    /// Original NAT source retired; its raw end cause is retained separately.
    NatLost,
    /// Original PILS identity/source was lost, changed or expired.
    IdentityLost,
    /// Original physical PILS source cause, retained by the operation owner.
    IdentitySource {
        /// Actual observer epoch serial, for diagnostics only.
        epoch: u64,
        /// Original native/protocol/resource/EOF cause.
        cause: gnunet_pils_host::client::LossCause,
    },
    /// Actual original TRANSPORT EOF.
    TransportLost,
    /// Pinned Quinn constructor violated its reserved driver contract.
    BackendInvariant,
    /// Actual H3 application/backend error, including unknown provider exposure.
    #[cfg(feature = "h3-profile")]
    Http3(crate::h3_link::Failure),
}
impl From<Protocol> for Fault {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Fault {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}
impl From<std::io::Error> for Fault {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<gnunet_nat_client_host::Error> for Fault {
    fn from(e: gnunet_nat_client_host::Error) -> Self {
        Self::Nat(e)
    }
}
impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QUIC communicator: {self:?}")
    }
}
impl std::error::Error for Fault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Client(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Connect(e) => Some(e),
            Self::Connection(e) => Some(e),
            Self::Read(e) => Some(e),
            Self::Write(e) => Some(e),
            Self::Nat(e) => Some(e),
            Self::IdentitySource { cause, .. } => match cause {
                gnunet_pils_host::client::LossCause::Io(e) => Some(e),
                gnunet_pils_host::client::LossCause::Protocol(e)
                | gnunet_pils_host::client::LossCause::Resource(e) => Some(e),
                gnunet_pils_host::client::LossCause::Setup(e) => Some(e),
                gnunet_pils_host::client::LossCause::Eof
                | gnunet_pils_host::client::LossCause::Requested => None,
            },
            #[cfg(feature = "h3-profile")]
            Self::Http3(e) => Some(e),
            Self::NatLost | Self::IdentityLost | Self::TransportLost | Self::BackendInvariant => {
                None
            }
        }
    }
}
/// Actual original local TRANSPORT source retirement, without payload bytes.
/// The backend allocation/QUIC endpoint is a separate, surviving owner.
#[derive(Clone, Copy, Debug)]
pub struct TransportLoss {
    /// Original local source generation.
    pub generation: u64,
    /// Fresh replacement generation, never an alias of the original source.
    pub next_generation: u64,
    /// Actual retained native RX prefix, including a complete held input.
    pub input_bytes: usize,
    /// Whether the original complete input was still held at physical close.
    pub held_input: bool,
    /// Original queued output frames retired.
    pub outputs: usize,
    /// Original outputs with a known positive native prefix.
    pub exposed_outputs: usize,
    /// Sum of actual retired-output native write prefixes.
    pub output_bytes: usize,
}
/// Actual observation. Claimed peer proposals never imply GNUnet authentication.
#[derive(Debug)]
pub enum Event<'id> {
    /// Actual socket bind; no handshake/identity assertion.
    Bound {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Address actually assigned to the bound socket.
        address: SocketAddr,
    },
    /// Actual original communicator MQ attachment.
    Attached(Epoch<'id>),
    /// Replacement local source attached; the backend epoch stays unchanged.
    TransportAttached {
        /// Current physical TRANSPORT MQ generation.
        generation: u64,
    },
    /// The current source's REGISTER was actually wholly written.
    TransportRegistered {
        /// Original source generation of the completed REGISTER.
        generation: u64,
    },
    /// Current REGISTER, addresses and surviving queues have whole announcement writes.
    /// This is local reconstruction only, not peer validation or payload delivery.
    TransportRestored {
        /// Current source generation whose announcement prefix completed.
        generation: u64,
    },
    /// Original local source retired; backend connections remain independently owned.
    TransportLost {
        /// Exact original source, byte-prefix and retirement observations.
        facts: TransportLoss,
        /// Actual native EOF or connection failure which retired that source.
        cause: Fault,
    },
    /// One original FIFO frame retired, retaining its known actual prefix only.
    TransportOutputRetired {
        /// Original source generation; never the replacement source.
        generation: u64,
        /// Public purpose of the retired frame.
        kind: &'static str,
        /// Original queue name if this frame referred to a queue.
        queue: Option<u32>,
        /// Original SEND identifier if this frame was its result.
        message_id: Option<[u8; 8]>,
        /// Original incoming FC identifier, if present.
        flow_id: Option<[u8; 8]>,
        /// Actual native output prefix.
        bytes: usize,
    },
    /// Original incoming callback authority retired without a synthetic ACK.
    IncomingRetired {
        /// Original physical TRANSPORT MQ generation.
        generation: u64,
        /// Original callback identifier, not reassigned to a fresh MQ.
        flow_id: [u8; 8],
        /// Whether the original incoming frame had actually wholly written.
        written: bool,
    },
    /// Actual original PILS loss cause, before source retirement; no mutation
    /// replay or new identity is inferred from this diagnostic.
    IdentityEnded {
        /// Original physical observer epoch; no replacement authority.
        epoch: u64,
        /// Actual unfinished original FEED operations.
        feeds: usize,
        /// Actual retained original crypto operations.
        retained: usize,
    },
    /// Healthy identity cut, before any next-generation connection admission.
    IdentityRetiring {
        /// Original process endpoint epoch.
        epoch: Epoch<'id>,
        /// Identity frozen into the old connection generation.
        previous: [u8; 32],
        /// Latest verified public target; it may still coalesce.
        next: [u8; 32],
        /// Actual old physical IPC source retirement, without replay.
        facts: TransportLoss,
    },
    /// One original connection driver retired at its original bound.
    IdentityDriverRetired {
        /// Original process endpoint epoch.
        epoch: Epoch<'id>,
        /// Original row/queue whose driver was canceled or completed.
        queue: u32,
        /// A real pending future was force-dropped rather than completed.
        forced: bool,
    },
    /// Original rows/loans retired and actual new local announcements completed.
    IdentityRestored {
        /// Same retained process endpoint epoch.
        epoch: Epoch<'id>,
        /// Current verified public identity, not peer authentication.
        peer: [u8; 32],
    },
    /// Whole local registration write plus actual public PILS identity observed.
    Ready {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Local public identity returned by the original PILS source.
        peer: [u8; 32],
    },
    /// Actual PILS observation with exact HELLO signature coverage.
    Identity {
        /// Local public identity returned by the original PILS source.
        peer: [u8; 32],
        /// Signature coverage reported by that PILS observation.
        coverage: gnunet_hello::SignatureCoverage,
    },
    /// A concrete handshake or local stream progressed. No remote message ACK.
    Activity,
    /// Original real queue metadata admitted to its actual MQ FIFO. This is
    /// neither a whole local write nor an authenticated remote route.
    Queue {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original communicator queue identifier.
        queue: u32,
        /// Public peer claim attached to this queue, without authentication.
        peer: [u8; 32],
        /// Whether this original connection was accepted locally.
        inbound: bool,
    },
    /// Actual original local plaintext provider acceptance (not UDP/remote ACK).
    ProviderAccepted {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original communicator queue identifier.
        queue: u32,
        /// Original message identifier from the communicator command.
        message_id: [u8; 8],
        /// Positive plaintext bytes accepted by the local provider in this step.
        bytes: usize,
        /// Whether the whole original plaintext message was locally accepted.
        complete: bool,
    },
    /// Actual positive local communicator MQ write.
    Written {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Positive bytes physically written to the original local MQ in this step.
        bytes: usize,
        /// Whether this original IPC frame was wholly written.
        complete: bool,
    },
    /// Original Sent result-frame bytes actually written, with its own MQ ids.
    /// This is separate from local provider plaintext acceptance and remote ACK.
    ResultWritten {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original communicator queue identifier.
        queue: u32,
        /// Original message identifier from the communicator command.
        message_id: [u8; 8],
        /// Positive result-frame bytes written to the original MQ in this step.
        bytes: usize,
        /// Whether the whole original result frame was physically written.
        complete: bool,
    },
    /// Actual whole original queue setup write, still not remote authentication.
    QueueWritten {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original communicator queue identifier.
        queue: u32,
    },
    /// Actual incoming whole IPC write; original FC debt remains outstanding.
    IncomingWritten {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original flow-control identifier retained until its service callback.
        flow_id: [u8; 8],
    },
    /// Exact original service flow callback, after its actual whole local write.
    Received {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original flow-control identifier acknowledged by the local service.
        flow_id: [u8; 8],
        /// Original public peer claim attached to the incoming frame.
        peer: [u8; 32],
    },
    /// Actual queue retired; no later queue is rebound to its numeric id.
    QueueRetired {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original communicator queue identifier.
        queue: u32,
    },
    /// Original plaintext send retired with actual accepted prefix/result exposure.
    SendRetired {
        /// Original backend instance epoch.
        epoch: Epoch<'id>,
        /// Original communicator queue identifier.
        queue: u32,
        /// Original message identifier from the communicator command.
        message_id: [u8; 8],
        /// Known original plaintext prefix accepted by the local provider.
        accepted: usize,
        /// Length of the original plaintext message.
        total: usize,
        /// Whether its whole original Sent result was physically written to MQ.
        result_written: bool,
        /// Actual original Sent result-frame prefix physically written to the MQ.
        result_bytes: usize,
        /// Actual provider reported possible exposure beyond the known prefix.
        unknown: bool,
    },
    /// Actual backend/caller request refused without claiming a remote result.
    Rejected(Fault),
    /// Original actual NAT source end, including real cause and retained callbacks.
    NatEnded(gnunet_nat_client_host::End<'id>),
    /// Original NAT reversal notification; pinned communicator has no reversal implementation.
    ReversalUnsupported,
    /// Unsupported actual standard communicator command, no fake response.
    Unsupported,
}
/// Caller-driven observation result; a canceled drive future preserves all cursors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// At least one actual state/IO change.
    Activity,
    /// Caller observation target only, no cancellation.
    WaitDeadline,
    /// All owned sources were physically retired.
    Stopped,
}
/// Actual source shutdown facts, independent of the first operation error.
#[derive(Debug)]
pub struct Closed {
    /// Concrete backend close/force-drop report, if bind had completed.
    pub backend: Option<crate::endpoint::Closed>,
    /// Independent cleanup error, not a replacement for an earlier failure.
    pub cleanup: Option<Fault>,
    /// Original incoming callback debts lost by physical MQ retirement.
    pub incoming_lost: usize,
    /// Original sends retired; accepted bytes were reported via SendRetired.
    pub sends_retired: usize,
    /// Actual identity cuts that retired original IPC/connection authority.
    pub identity_updates: u64,
    /// Such cuts followed by actual local announcement restoration.
    pub identity_recoveries: u64,
    /// Original connection futures force-dropped during identity recovery.
    pub identity_forced_drivers: usize,
}

/// Caller-owned profile loan pools. Each variant is fixed for the original
/// source; it cannot be changed to rebind old callbacks or TLS sessions.
pub enum Buffers<'pool, 'id, 'slots, 'buf> {
    /// One raw whole-frame slab per connection; each at least Limits.raw_body.
    Raw(&'pool mut [Option<&'buf mut [u8]>]),
    /// One original H3 slot-array loan per connection. Each array has at least
    /// h3_polls+2 fresh Slots with body slabs at least Limits.h3_body.
    Http3(&'pool mut [Option<&'slots mut [gnunet_transport_quic::h3::Slot<'id, 'buf>]>]),
}
impl Buffers<'_, '_, '_, '_> {
    pub(crate) fn available(&self) -> bool {
        match self {
            Self::Raw(l) => l.iter().all(Option::is_some),
            Self::Http3(l) => l.iter().all(Option::is_some),
        }
    }
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Raw(l) => l.len(),
            Self::Http3(l) => l.len(),
        }
    }
}
