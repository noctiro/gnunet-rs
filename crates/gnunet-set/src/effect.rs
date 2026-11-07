//! Exact original immutable bytes and physical-retirement debts.
use crate::{Client, EffectId, Incoming, Operation, OperationType, PeerOwner};
use alloc::vec::Vec;
use gnunet_types::Error;
/// One original external effect, with no fabricated processing acknowledgement.
#[derive(Debug)]
pub enum Action<'id> {
    /// Announce this actual listener's standard application port.
    OpenPort {
        /// Original listener client generation.
        listener: Client<'id>,
        /// Public set operation accepted on this listener.
        operation: OperationType,
        /// Standard CADET application port.
        app_id: [u8; 64],
    },
    /// Retire only this listener and unaccepted offers, leaving adopted operations.
    ClosePort {
        /// Original listener generation.
        listener: Client<'id>,
        /// Original actual application port.
        app_id: [u8; 64],
    },
    /// Open an actual original outgoing channel, not a peer-online assertion.
    OpenPeer {
        /// Original committed operation generation.
        operation: Operation<'id>,
        /// Actual target identity from the client request.
        peer: [u8; 32],
        /// Standard original application port.
        app_id: [u8; 64],
    },
    /// Transfer the very same actual incoming channel to an accepted operation.
    /// This is local ownership work with no packet or replacement connection.
    AdoptPeer {
        /// Original actual incoming channel/offer owner.
        incoming: Incoming<'id>,
        /// Newly committed operation owning that same channel after adoption.
        operation: Operation<'id>,
    },
    /// Exactly one immutable official peer frame on its original channel owner.
    PeerSend {
        /// Actual original pending-offer or committed-operation owner.
        owner: PeerOwner<'id>,
        /// Complete standard bytes, never a private envelope or generator.
        bytes: Vec<u8>,
    },
    /// Physically retire only the original channel and its original IO debts.
    ClosePeer {
        /// Original channel ownership; no raw request ID can replace it.
        owner: PeerOwner<'id>,
    },
    /// One immutable official response on its original local client source.
    ClientFrame {
        /// Original client/source generation.
        client: Client<'id>,
        /// Original operation where applicable, absent for copy/iteration/offers.
        operation: Option<Operation<'id>>,
        /// Complete original standard response bytes.
        bytes: Vec<u8>,
    },
    /// Physically close the original refused local source without a private error.
    CloseClient {
        /// Original client generation.
        client: Client<'id>,
        /// Original pure classification; the host keeps independent native cause.
        reason: Error,
    },
}
impl Action<'_> {
    pub(crate) fn bytes(&self) -> usize {
        match self {
            Self::PeerSend { bytes, .. } | Self::ClientFrame { bytes, .. } => bytes.capacity(),
            _ => 0,
        }
    }
}
/// One retained effect; admission and completion refer only to this immutable work.
#[derive(Debug)]
pub struct Effect<'id> {
    /// Original local effect capability, never an on-wire request ID.
    pub id: EffectId<'id>,
    /// Actual original immutable action.
    pub action: Action<'id>,
    pub(crate) admitted: bool,
    pub(crate) ordering: Ordering<'id>,
}
/// Original native/local completion, independent of a remote semantic result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// Exact original frame whole-written or exact local Adopt/Close applied.
    Written,
    /// Original action provably never entered its external sink.
    Unsent(Error),
    /// Original exposure or processing is uncertain; never replay this work.
    Lost(Error),
}
/// Original terminal work returned for caller diagnostics/cause retention.
#[derive(Debug)]
pub struct Terminal<'id> {
    /// Exact original action and local token.
    pub effect: CompletedEffect<'id>,
    /// Actual host-reported disposition.
    pub completion: Completion,
}

/// Original action moved out of its retired queue slot. Private admission and
/// dependency-index metadata has no purpose in a native terminal receipt.
/// Moving these fields requires no allocation on failure or cleanup paths.
#[derive(Debug)]
pub struct CompletedEffect<'id> {
    /// Exact original immutable effect capability.
    pub id: EffectId<'id>,
    /// Original action and its owned bytes, moved without copying.
    pub action: Action<'id>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ordering<'id> {
    pub client: Option<Client<'id>>,
    pub channel: Option<PeerOwner<'id>>,
    pub port: Option<[u8; 64]>,
    pub incoming_listener: Option<Client<'id>>,
    pub close_listener: Option<Client<'id>>,
}
impl Ordering<'_> {
    pub fn precedes(&self, later: &Self) -> bool {
        (self.client.is_some() && self.client == later.client)
            || (self.channel.is_some() && self.channel == later.channel)
            || (self.port.is_some() && self.port == later.port)
            || (self.incoming_listener.is_some() && self.incoming_listener == later.close_listener)
    }
}
/// Pausable, allocation-free fair scan over a frozen upper effect serial. Cursor
/// values are local ordering hints, never effect admission or native completion.
pub struct EffectScan<'id> {
    pub(crate) after: Option<EffectId<'id>>,
    pub(crate) candidate: Option<EffectId<'id>>,
    pub(crate) checked: Option<EffectId<'id>>,
    pub(crate) fence: Option<EffectId<'id>>,
    pub(crate) end: bool,
}
impl EffectScan<'_> {
    /// Begin a fresh bounded round. Appended effects belong to the next round.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            after: None,
            candidate: None,
            checked: None,
            fence: None,
            end: false,
        }
    }
    /// Start another round after all ready sinks or original IO were attempted.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}
impl Default for EffectScan<'_> {
    fn default() -> Self {
        Self::new()
    }
}
/// One bounded scan result, distinct from native activity or completion.
pub enum EffectScanStep<'a, 'id> {
    /// One semantic owner head; same-client, original-channel, port and local
    /// adoption/listener-close dependencies are all settled. Cursor advances.
    Ready(&'a Effect<'id>),
    /// Check budget exhausted. Preserve this scan and continue after yielding.
    Pending,
    /// This frozen round is exhausted, empty or belongs to another domain.
    /// No implicit wrap or self-wake is requested; reset for a future round.
    End,
}
