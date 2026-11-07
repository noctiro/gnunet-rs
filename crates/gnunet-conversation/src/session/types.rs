use crate::{Peer, Port};
use alloc::vec::Vec;
use core::marker::PhantomData;
use gnunet_types::Error;

/// Exclusive brand root for one real local IPC Line. No native work is hidden.
#[derive(Default)]
pub struct Instance {
    pub(super) _private: u8,
}
impl Instance {
    /// Create a fresh independent Line brand.
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
/// Actual original nonzero-sized Instance borrow. Lifetimes alone are not
/// nominal owner brands: two independent borrows can share a lexical lifetime.
#[derive(Clone, Copy)]
pub(super) struct Domain<'id>(pub(super) &'id Instance);
impl PartialEq for Domain<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.0, other.0)
    }
}
impl Eq for Domain<'_> {}
impl core::fmt::Debug for Domain<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LineDomain")
    }
}
macro_rules! id {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name<'id> {
            pub(super) serial: u64,
            pub(super) domain: Domain<'id>,
            pub(super) brand: PhantomData<&'id mut Instance>,
        }
        impl $name<'_> {
            /// Original in-process serial, never transmitted as a protocol ID.
            pub const fn value(self) -> u64 {
                self.serial
            }
        }
    };
}
/// Original native Channel owner; the slot and serial are never wire fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallId<'id> {
    pub(super) serial: u64,
    pub(super) domain: Domain<'id>,
    pub(super) slot: usize,
    pub(super) brand: PhantomData<&'id mut Instance>,
}
impl CallId<'_> {
    /// Original in-process monotonic serial, not the opaque local CID.
    pub const fn value(self) -> u64 {
        self.serial
    }
}
id!(
    EffectId,
    "One original effect lease; a receipt never authorizes a replacement effect."
);
/// Native owner's actual local identity/source assertion. Construct only from
/// a current authenticated identity provider, not from the caller's ego key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    peer: Peer,
    epoch: u64,
}
impl Identity {
    /// Bind actual local peer bytes and a nonzero native identity generation.
    pub fn new(peer: Peer, epoch: u64) -> Result<Self, Error> {
        if epoch == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self { peer, epoch })
    }
    /// Actual local peer context used by RingInfo signatures.
    pub const fn peer(&self) -> &Peer {
        &self.peer
    }
    /// Original identity source generation; never a wire field.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}
/// One actual CADET MQ/source generation supplied by the native owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source(u64);
impl Source {
    /// Brand a nonzero actual source generation; no connection is created.
    pub fn new(generation: u64) -> Result<Self, Error> {
        if generation == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self(generation))
    }
    /// Original native generation.
    pub const fn value(self) -> u64 {
        self.0
    }
}
/// Validated per-Line storage and original time limits. Amounts bound retained
/// core-owned capacities, not allocator overhead, crypto stack or process RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum simultaneously retained call owners, including undrained closes.
    pub calls: usize,
    /// Normal queued effects, excluding reserved retirement slots.
    pub effects: usize,
    /// Maximum complete official frame, additionally clamped by CADET64348.
    pub frame_bytes: usize,
    /// Sum of actual queued frame Vec capacities.
    pub queued_bytes: usize,
    /// Metadata capacities plus simultaneous queued frame capacities.
    pub retained_bytes: usize,
    /// Original setup/ringing timeout in monotonic microseconds; default one day.
    pub ring_timeout: u64,
    /// Original lifetime of an admitted output/credit intent in microseconds.
    pub write_timeout: u64,
    /// Original close deadline, never renewed by cleanup retries.
    pub close_timeout: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            calls: 32,
            effects: 128,
            frame_bytes: 64348,
            queued_bytes: 1048576,
            retained_bytes: 2097152,
            ring_timeout: 86400000000,
            write_timeout: 10000000,
            close_timeout: 30000000,
        }
    }
}
impl Limits {
    /// Validate finite resource profiles before allocating any metadata.
    pub fn validate(self) -> Result<Self, Error> {
        if self.calls == 0
            || self.calls > 1024
            || self.effects < 3
            || self.effects > 8192
            || !(128..=65535).contains(&self.frame_bytes)
            || self.queued_bytes < self.frame_bytes
            || self.retained_bytes < self.queued_bytes
            || self.ring_timeout == 0
            || self.write_timeout == 0
            || self.close_timeout == 0
            || self.ring_timeout == u64::MAX
            || self.write_timeout == u64::MAX
            || self.close_timeout == u64::MAX
        {
            return Err(Error::InvalidInput);
        }
        Ok(self)
    }
}
/// Actual protocol state; Connected requires a real pickup or local acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Outgoing native open/ringing effects have not yet been written.
    Opening,
    /// Incoming channel awaits a valid authenticated740.
    AwaitRing,
    /// Authenticated incoming call awaits the local client's pickup.
    Ringing,
    /// Outgoing ring was written; only actual742 can complete pickup.
    Calling,
    /// Actual pickup was accepted; media may flow subject to suspension.
    Connected,
    /// No new normal work is allowed; original physical effects still settle.
    Closing,
    /// Actual channel is gone; remaining original effects can still be observed.
    Closed,
}
/// Retained causal end reason. No variant implies remote receipt or user action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndReason {
    /// The actual local client requested hangup.
    LocalHangUp,
    /// Actual peer741 was accepted on the original channel.
    RemoteHangUp,
    /// The original owner was cancelled or explicitly disconnected.
    Cancelled(Error),
    /// Actual protocol, source, time or I/O failure.
    Failed(Error),
}
/// Result of classifying a real local request, never a service acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestOutcome<'id> {
    /// The original request was admitted to bounded state/effect storage.
    Admitted,
    /// The actual outgoing call owner was created.
    Calling(CallId<'id>),
    /// A stale local CID or already closing call was ignored as in the C API.
    Ignored,
}
/// One actual operation for the native owner. Frames contain only original
/// public protocol/audio data; no private734 material is retained here.
pub enum Action<'id> {
    /// Open this Line's actual CADET port.
    OpenPort {
        /// Original port.
        port: Port,
    },
    /// Create a real outgoing CADET channel at the exact target/port.
    OpenChannel {
        /// Original call.
        call: CallId<'id>,
        /// Target network peer, not caller ego.
        target: Peer,
        /// Original destination port.
        port: Port,
    },
    /// Write the whole original peer frame on its bound channel.
    PeerFrame {
        /// Original call.
        call: CallId<'id>,
        /// Exact original complete frame.
        frame: Vec<u8>,
    },
    /// Write the whole original notification/audio frame on this local IPC.
    ClientFrame {
        /// Original call.
        call: CallId<'id>,
        /// Exact original complete frame.
        frame: Vec<u8>,
    },
    /// Return credit for exactly one original input delivery after admission.
    ReceiveDone {
        /// Original call.
        call: CallId<'id>,
        /// Original native delivery serial, never wire data.
        delivery: u64,
    },
    /// Physically destroy this original Channel, without inventing a peer ACK.
    CloseChannel {
        /// Original call.
        call: CallId<'id>,
    },
    /// Retire this Line's original port and prohibit new incoming channels.
    ClosePort {
        /// Original port.
        port: Port,
    },
    /// Physically close this original local IPC.
    CloseClient,
}
impl core::fmt::Debug for Action<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self {
            Self::OpenPort { .. } => "OpenPort",
            Self::OpenChannel { .. } => "OpenChannel",
            Self::PeerFrame { .. } => "PeerFrame",
            Self::ClientFrame { .. } => "ClientFrame",
            Self::ReceiveDone { .. } => "ReceiveDone",
            Self::CloseChannel { .. } => "CloseChannel",
            Self::ClosePort { .. } => "ClosePort",
            Self::CloseClient => "CloseClient",
        };
        f.debug_struct(kind)
            .field("call", &self.call())
            .field("retained_frame_bytes", &self.bytes())
            .finish_non_exhaustive()
    }
}
impl<'id> Action<'id> {
    /// Original call, if this operation has channel authority.
    pub const fn call(&self) -> Option<CallId<'id>> {
        match self {
            Self::OpenChannel { call, .. }
            | Self::PeerFrame { call, .. }
            | Self::ClientFrame { call, .. }
            | Self::ReceiveDone { call, .. }
            | Self::CloseChannel { call } => Some(*call),
            _ => None,
        }
    }
    pub(super) const fn close(&self) -> bool {
        matches!(
            self,
            Self::CloseChannel { .. } | Self::ClosePort { .. } | Self::CloseClient
        )
    }
    pub(super) fn bytes(&self) -> usize {
        match self {
            Self::PeerFrame { frame, .. } | Self::ClientFrame { frame, .. } => frame.capacity(),
            _ => 0,
        }
    }
}
/// Original pending effect. Its metadata and bytes survive cancellation until
/// the native owner settles the actual original physical outcome.
#[derive(Debug)]
pub struct Effect<'id> {
    pub(super) id: EffectId<'id>,
    pub(super) action: Action<'id>,
    pub(super) deadline: u64,
    pub(super) admitted: bool,
    pub(super) cancelled: bool,
    pub(super) predecessors: [Option<EffectId<'id>>; 2],
}
impl<'id> Effect<'id> {
    /// Original unforgeable in-process lease.
    pub const fn id(&self) -> EffectId<'id> {
        self.id
    }
    /// Original native operation/payload.
    pub const fn action(&self) -> &Action<'id> {
        &self.action
    }
    /// Original hard deadline, never renewed by retries.
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }
    /// Whether the native owner has admitted this original lease.
    pub const fn admitted(&self) -> bool {
        self.admitted
    }
    /// Known cancelled intent. Settle Unsent if no physical I/O occurred;
    /// otherwise preserve the real Written/Lost outcome.
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }
}
/// Actual native outcome. Written is local physical completion, never remote
/// acceptance, pickup, audio delivery, or business success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// One inner input was processed, while its original outer DATA remains
    /// held by the native owner. Only ReceiveDone accepts this; no ACK/credit
    /// write is claimed. The final inner needs real receive_done Written.
    Processed,
    /// Actual whole local write or completed native operation.
    Written,
    /// Original operation provably never exposed its bytes/effect.
    Unsent(Error),
    /// Actual operation ended with an independent cause and exposure fact.
    Lost {
        /// Original classified native cause.
        reason: Error,
        /// Whether any original operation bytes/effect escaped.
        exposed: bool,
    },
}
/// Consumed original effect and independent actual receipt. Owned frame storage
/// is transferred, not cloned; the caller controls diagnostic retention.
#[derive(Debug)]
pub struct Terminal<'id> {
    /// Original effect identifier.
    pub id: EffectId<'id>,
    /// Original action and exact bytes.
    pub action: Action<'id>,
    /// Real completion, never synthesized from cancellation intent.
    pub completion: Completion,
}
/// Final call facts available only after actual channel disappearance and all
/// original effects have settled. This is not a media/remote-delivery receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallReport<'id> {
    /// Original call authority.
    pub call: CallId<'id>,
    /// Opaque local CID echoed on the original Line.
    pub cid: u32,
    /// Actual remote network peer, distinct from the ringing ego key.
    pub peer: Peer,
    /// First causal reason ending this call.
    pub reason: EndReason,
    /// First actual Unsent/Lost/source cause, including a normal cancellation
    /// classification; this is independent of the initiating end reason.
    pub failure: Option<Error>,
    /// Actual whole PeerRing740 write was observed.
    pub ring_written: bool,
    /// Actual remote pickup742 was observed.
    pub remote_pickup: bool,
    /// Actual local pickup742 whole write was observed.
    pub local_pickup_written: bool,
    /// Actual peer741 was observed, not inferred from EOF.
    pub remote_hangup: bool,
    /// Actual local peer741 whole write was observed.
    pub local_hangup_written: bool,
}

/// Pausable finite effect-scan round. New append-only work is excluded until
/// reset, so a continuous audio producer cannot prevent a blocked round ending.
#[derive(Default)]
pub struct EffectScan {
    pub(super) after: u64,
    pub(super) fence: Option<u64>,
}
impl EffectScan {
    /// Start an independent scan cursor with no frozen round yet.
    pub const fn new() -> Self {
        Self {
            after: 0,
            fence: None,
        }
    }
    /// Explicitly start a fresh round including subsequently appended work.
    pub fn reset(&mut self) {
        self.after = 0;
        self.fence = None;
    }
}
/// One bounded scheduling result. Activity is not physical I/O or wire credit.
pub enum EffectScanStep<'a, 'id> {
    /// Eligible original owner head, respecting all original dependencies.
    Ready(&'a Effect<'id>),
    /// Check budget exhausted; resume this same cursor without renewing time.
    Pending,
    /// Frozen round completed. Reset, then wait for actual I/O/state changes;
    /// unconditionally waking again would create a busy loop on blocked owners.
    End,
}
