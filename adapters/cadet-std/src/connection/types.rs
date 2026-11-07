//! Bound original CORE/Book source tokens, explicit effects and caller storage.
use crate::Error;
use gnunet_cadet::connection::{self, Attempt, Book, Frame, Neighbor};
use gnunet_core_client_host::{
    self as core, ConnectionEpoch, Message, OwnedTraffic, PayloadState, PayloadWrite, Peer,
    Progress, SendId,
};
use gnunet_types::{Error as ProtocolError, MonoInstant};
use gnunet_wire::official::{
    core::{ClassOrder, REMOTE_REQUEST_LIMIT},
    message_type as mt,
};
/// Only the seven peer-facing messages handled by the official CADET CORE owner.
pub const MESSAGE_TYPES: [u16; 7] = [
    mt::CADET_CONNECTION_CREATE.value(),
    mt::CADET_CONNECTION_CREATE_ACK.value(),
    mt::CADET_CONNECTION_BROKEN.value(),
    mt::CADET_CONNECTION_DESTROY.value(),
    mt::CADET_TUNNEL_KX.value(),
    mt::CADET_TUNNEL_KX_AUTH.value(),
    mt::CADET_TUNNEL_ENCRYPTED.value(),
];
/// Remote single-message CORE cap; the native outer frame bound applies too.
pub const MAX_PEER_FRAME: usize = REMOTE_REQUEST_LIMIT - 1;

/// Original actual CORE source, never reconstructed from raw PID/CID bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source<'core, 'book> {
    pub(super) epoch: ConnectionEpoch<'core>,
    pub(super) peer: Peer<'core>,
    pub(super) neighbor: Neighbor<'book>,
}
impl<'core, 'book> Source<'core, 'book> {
    /// Original service MQ generation.
    #[must_use]
    pub const fn epoch(self) -> ConnectionEpoch<'core> {
        self.epoch
    }
    /// Original announced CORE peer generation.
    #[must_use]
    pub const fn peer(self) -> Peer<'core> {
        self.peer
    }
    /// Corresponding actual Book neighbor allocation.
    #[must_use]
    pub const fn neighbor(self) -> Neighbor<'book> {
        self.neighbor
    }
}
/// One successful actual native admission followed by the original Book start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding<'core, 'book> {
    pub(super) source: Source<'core, 'book>,
    pub(super) send: SendId<'core>,
    pub(super) attempt: Attempt<'book>,
}
impl<'core, 'book> Binding<'core, 'book> {
    /// Original physical source domain.
    #[must_use]
    pub const fn source(self) -> Source<'core, 'book> {
        self.source
    }
    /// Actual original native operation; no finite wire echo is substituted.
    #[must_use]
    pub const fn send(self) -> SendId<'core> {
        self.send
    }
    /// Original connection physical attempt.
    #[must_use]
    pub const fn attempt(self) -> Attempt<'book> {
        self.attempt
    }
    /// Original immutable Book frame allocation.
    #[must_use]
    pub const fn frame(self) -> Frame<'book> {
        self.attempt.frame()
    }
}

/// Synchronous mandatory effect sink. The bridge invokes each committed Book
/// input/start/exposure/completion once before releasing its original bytes.
/// Callbacks cannot refuse; reserve bounded coordinator effects beforehand or
/// process them inline, including every successful Fresh ResetProof. No default
/// success/no-op implementation is provided by this module.
/// Every `now` belongs to the bridge's original native Timebase epoch, never
/// the configured logical absolute source or a wire monotime reservation.
pub trait Observer<'core, 'book, const P: usize> {
    /// Consume an actual original announced peer's newly admitted Neighbor,
    /// including a retained replacement admitted after its old physical drain.
    fn neighbor(
        &mut self,
        source: Source<'core, 'book>,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    );
    /// Consume actual route retirement after all this original peer's native
    /// sends stopped. New same-PID Neighbor allocation happens afterwards.
    fn retired(
        &mut self,
        source: Source<'core, 'book>,
        routes: usize,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    );
    /// Consume actual Book input effects, with borrowed original complete bytes.
    /// Cryptographic/session verification remains the independent controller.
    fn input<'message>(
        &mut self,
        source: Source<'core, 'book>,
        event: connection::Event<'book, 'message>,
        wire: &'message [u8],
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    );
    /// Bind higher-layer original metadata before any subsequent native poll.
    fn started(
        &mut self,
        binding: Binding<'core, 'book>,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    );
    /// First actual positive original CORE_SEND write, never request/READY.
    fn exposed(
        &mut self,
        binding: Binding<'core, 'book>,
        state: PayloadState<'core>,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    );
    /// Consume actual original terminal Book facts before frame storage release.
    /// None means the Book frame was never admitted to a native operation.
    fn completed(
        &mut self,
        completion: connection::Completion<'book>,
        binding: Option<Binding<'core, 'book>>,
        state: Option<PayloadState<'core>>,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    );
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Phase {
    Waiting,
    Live,
    Disconnected,
    MqLost,
}
#[derive(Clone, Copy)]
pub(super) struct PeerRecord<'core, 'book> {
    pub(super) epoch: ConnectionEpoch<'core>,
    pub(super) peer: Peer<'core>,
    pub(super) neighbor: Option<Neighbor<'book>>,
    pub(super) phase: Phase,
}
/// Caller-owned bounded original-peer metadata, including retiring generations.
#[derive(Clone, Copy)]
pub struct PeerSlot<'core, 'book> {
    pub(super) record: Option<PeerRecord<'core, 'book>>,
}
impl PeerSlot<'_, '_> {
    /// Empty original-peer storage; no peer/Neighbor is authorized.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl Default for PeerSlot<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(super) struct SendRecord<'core, 'book> {
    pub(super) source: Source<'core, 'book>,
    pub(super) send: SendId<'core>,
    pub(super) frame: Frame<'book>,
    pub(super) attempt: Option<Attempt<'book>>,
    pub(super) written: usize,
    pub(super) total: usize,
    pub(super) aborting: Option<ProtocolError>,
    pub(super) budget: Option<BudgetState>,
}
impl<'core, 'book> SendRecord<'core, 'book> {
    pub(super) fn binding(self) -> Option<Binding<'core, 'book>> {
        self.attempt.map(|attempt| Binding {
            source: self.source,
            send: self.send,
            attempt,
        })
    }
}
/// Caller-owned bounded original SendId/Frame/Attempt correlation storage.
#[derive(Clone, Copy)]
pub struct SendSlot<'core, 'book> {
    pub(super) record: Option<SendRecord<'core, 'book>>,
}
impl SendSlot<'_, '_> {
    /// Empty original-send metadata; no operation is admitted.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl Default for SendSlot<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}
/// Optional finite lifetime for each separately admitted original native send.
/// Neither progress, cancellation nor a replacement peer refreshes its targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendBudget {
    /// Relative microseconds from this actual send admission to cancellation.
    pub lifetime_micros: u64,
    /// Fixed extra interval for the original partial payload suffix to drain.
    /// The original MQ is actually retired at this hard bound if still needed.
    pub retirement_grace_micros: u64,
}
impl Default for SendBudget {
    fn default() -> Self {
        Self {
            lifetime_micros: 10_000_000,
            retirement_grace_micros: 5_000_000,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct BudgetState {
    /// Fixed native elapsed targets in the original Timebase epoch.
    pub(super) expires: MonoInstant,
    pub(super) hard_stop: MonoInstant,
    /// Separate absolute deadline actually submitted to the CORE service.
    pub(super) wire_deadline: u64,
    pub(super) expired: bool,
}
/// Actual result of canceling one exact native SendId at its original expiry.
/// It never supplies a synthesized private PayloadState or remote acknowledgement.
pub enum Expiration {
    /// The SDK returned the original source before any CORE_SEND payload byte.
    /// Its corresponding actual Book Unsent callback already happened once.
    Cancelled(core::SendCompletion<core::Message>),
    /// An exposed original immutable payload suffix is still owned by the SDK.
    Draining,
    /// Actual cancellation refusal; retain the original mapping and hard bound.
    Refused(Error),
}
/// Explicit native resource, QoS and absolute CORE-send-deadline policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Existing real native CORE client's separately bounded source/wire limits.
    pub core: core::Limits,
    /// CORE native-order PeerClass profile; unrelated to network byte order.
    pub class_order: ClassOrder,
    /// Actual outgoing CORE priority; caller chooses source protocol policy.
    pub priority: u32,
    /// Actual absolute CORE deadline when send_budget is None; FOREVER is MAX.
    pub send_deadline: u64,
    /// Optional per-admission finite native lifetime. Some also overrides the
    /// fixed CORE deadline with that admission's absolute sample plus lifetime;
    /// absolute adjustments never change its independent native expiry.
    pub send_budget: Option<SendBudget>,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            core: core::Limits::default(),
            class_order: ClassOrder::Little,
            priority: 0,
            send_deadline: u64::MAX,
            send_budget: None,
        }
    }
}
/// Explicit genuine receive/drop observations; no received bytes are ACKed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    /// CORE direction/preview cannot authorize an inbound complete peer frame.
    Observation,
    /// No original current source record exists, or source is retiring/waiting.
    Source,
    /// Loopback belongs to the local SERVICE path rather than a remote neighbor.
    Loopback,
    /// Decode/source/path/resource refusal from transactional Book.receive.
    Protocol(ProtocolError),
}
/// Bounded cumulative observations, not application delivery statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Actual committed input callback count.
    pub inputs: u64,
    /// Explicit local packet drops after original complete native input.
    pub dropped: u64,
    /// Subset of drops caused by transactional Book capacity refusal.
    pub capacity_drops: u64,
    /// Actual native send admissions bound to Book attempts.
    pub started: u64,
    /// First positive original CORE_SEND exposures.
    pub exposed: u64,
    /// Actual original terminal Book callbacks, including never-started frames.
    pub completed: u64,
    /// Original finite send expiries, each observed only once.
    pub expired_sends: u64,
    /// Actual MQ reconnect retirements forced at an original hard bound.
    pub forced_reconnects: u64,
    /// Actual original cancellation refusals, without inferring retirement.
    pub cancellation_errors: u64,
}
/// One actual caller-visible action. Successful Book effects were already
/// synchronously consumed; returned tokens remain observations of that action.
pub enum Step<'core, 'book> {
    /// Actual service stream attached; peer authorization still awaits INIT_REPLY.
    Connected(ConnectionEpoch<'core>),
    /// Actual own-peer assertion matched the originally bound Book local identity.
    Identity(Peer<'core>),
    /// Actual own-peer mismatch; no external Neighbor was minted, bridge halted.
    IdentityMismatch {
        /// Original actual source.
        epoch: ConnectionEpoch<'core>,
        /// Actual announced local identity.
        actual: Peer<'core>,
        /// Book's original expected identity.
        expected: [u8; 32],
    },
    /// Actual remote announcement mapped to an original Neighbor.
    Neighbor(Source<'core, 'book>),
    /// Actual announcement retained pending bounded Book capacity/old generation.
    Waiting {
        /// Original epoch.
        epoch: ConnectionEpoch<'core>,
        /// Actual new peer generation.
        peer: Peer<'core>,
        /// Actual refusal, when resource-based.
        reason: Option<ProtocolError>,
    },
    /// Original disconnected generation is fully physically retired in Book.
    Retired {
        /// Original peer generation.
        peer: Peer<'core>,
        /// Retired Book routes.
        routes: usize,
    },
    /// Successful committed Book input was synchronously observed.
    Input {
        /// Actual original source.
        source: Source<'core, 'book>,
        /// Original complete peer frame length.
        bytes: usize,
    },
    /// Explicit loss of original complete native input, returned unchanged.
    Dropped {
        /// Original MQ.
        epoch: ConnectionEpoch<'core>,
        /// Actual raw wire peer.
        peer: core::PeerId,
        /// Original announced peer, if supplied by CORE.
        connection: Option<Peer<'core>>,
        /// Original owned full bytes or preview.
        traffic: OwnedTraffic,
        /// Concrete drop reason.
        reason: DropReason,
    },
    /// Final immutable source admission and original Book start already observed.
    Started(Binding<'core, 'book>),
    /// Native request admission refused; Book was never started or exposed.
    SendRefused {
        /// Original queued Book frame.
        frame: Frame<'book>,
        /// Actual local refusal.
        reason: ProtocolError,
        /// Same immutable source returned by native send.
        source: Message,
    },
    /// A Book start failed after actual native request admission. Cancellation is
    /// actual; Some returns the original unwritten source, None still drains.
    StartRefused {
        /// Original native operation.
        send: SendId<'core>,
        /// Original queued Book frame.
        frame: Frame<'book>,
        /// Actual Book refusal.
        reason: ProtocolError,
        /// Actual synchronous native cancellation, if any.
        cancelled: Option<core::SendCompletion<Message>>,
        /// Actual refusal to synchronously cancel; the original mapping/source
        /// remains retained for native terminal drain, with no Book exposure.
        cancellation_error: Option<Error>,
    },
    /// One original finite send expired. Actual synchronous cancellation has
    /// already produced its Book callback; partial output remains original work.
    SendExpired {
        /// Exact original bound attempt, if its Book start succeeded.
        binding: Option<Binding<'core, 'book>>,
        /// Exact original native operation, never a raw request echo.
        send: SendId<'core>,
        /// Original native elapsed expiry in this bridge's Timebase epoch.
        expires: MonoInstant,
        /// Original hard physical retirement bound, never refreshed.
        hard_stop: MonoInstant,
        /// Actual cancellation/source ownership result.
        outcome: Expiration,
    },
    /// Matching wire READY is only this original operation's native send permit.
    Permit {
        /// Exact bound original operation, if started.
        binding: Option<Binding<'core, 'book>>,
        /// Actual service capacity.
        capacity: u16,
    },
    /// Actual original positive write, applied before any next service input.
    Writing {
        /// Exact original bound attempt.
        binding: Binding<'core, 'book>,
        /// Actual private-minted byte-range receipt.
        receipt: PayloadWrite<'core>,
    },
    /// Actual native terminal source returned; Book callback/release is complete.
    Finished {
        /// Exact original bound attempt, if Book start succeeded.
        binding: Option<Binding<'core, 'book>>,
        /// Actual private physical state.
        state: PayloadState<'core>,
        /// Actual local native terminal result/source.
        completion: core::SendCompletion<Message>,
    },
    /// One never-native-admitted Book completion was synchronously observed.
    BookCompleted(connection::Completion<'book>),
    /// Actual MQ already stopped; its original sources/notices still drain.
    Lost {
        /// Original retired MQ.
        epoch: ConnectionEpoch<'core>,
        /// Actual native retirement cause.
        cause: core::LossCause,
    },
    /// Other genuine CORE lifecycle/control/observational progress.
    Core(Progress<'core>),
}
