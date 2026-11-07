use core::{cell::Cell, ptr};
pub use gnunet_block::bloom::NativeEndian;
use gnunet_types::Error;
/// Explicit stable node domain; unique local allocation ids never enter the wire.
#[derive(Debug, Default)]
pub struct Instance {
    pub(crate) next: Cell<u64>,
}
impl Instance {
    /// Fresh stable allocation domain.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Handle<'id> {
    pub domain: &'id Instance,
    pub index: usize,
    pub serial: u64,
}
impl PartialEq for Handle<'_> {
    fn eq(&self, o: &Self) -> bool {
        ptr::eq(self.domain, o.domain) && self.index == o.index && self.serial == o.serial
    }
}
impl Eq for Handle<'_> {}
macro_rules! token {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name<'id>(pub(crate) Handle<'id>);
        impl $name<'_> {
            /// Diagnostic checked local allocation, not protocol authority.
            #[must_use]
            pub const fn value(self) -> u64 {
                self.0.serial
            }
        }
    };
}
token!(Client, "Original actual local IPC source allocation.");
token!(
    Set,
    "Original logical set allocation; snapshots may outlive its release."
);
token!(
    Listener,
    "Original logical application listener allocation."
);
token!(
    Operation,
    "Original intersection operation allocation, never a wire RID."
);
/// Original actual application-port binding. A reannouncement mints a new token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Port<'id> {
    pub(crate) listener: Listener<'id>,
    pub(crate) serial: u64,
}
impl<'id> Port<'id> {
    /// Original logical registration.
    #[must_use]
    pub const fn listener(self) -> Listener<'id> {
        self.listener
    }
}
/// Bound actual end-to-end CADET source. Constructed only at the explicit trusted
/// peer port boundary, never inferred from raw app ids or plaintext frame fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSource<'id> {
    pub(crate) operation: Operation<'id>,
    pub(crate) serial: u64,
    pub(crate) peer: [u8; 32],
}
impl<'id> PeerSource<'id> {
    /// Original logical operation.
    #[must_use]
    pub const fn operation(self) -> Operation<'id> {
        self.operation
    }
    /// Expected actual end-to-end peer, not a ciphertext-independent proof.
    #[must_use]
    pub const fn peer(self) -> [u8; 32] {
        self.peer
    }
}
/// Original application message permission to grant this CADET channel credit.
/// This is semantic receive_done, not a local-MQ write or remote delivery proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery<'id> {
    pub(crate) source: PeerSource<'id>,
    pub(crate) serial: u64,
}
impl<'id> Delivery<'id> {
    /// Exact original source requiring application credit.
    #[must_use]
    pub const fn source(self) -> PeerSource<'id> {
        self.source
    }
}
/// Destination of one immutable prepared frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination<'id> {
    /// Original local accepted MQ.
    Client(Client<'id>),
    /// Original actual peer channel.
    Peer(PeerSource<'id>),
}
/// Original immutable output effect. No public integer-to-effect constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Effect<'id> {
    pub(crate) operation: Operation<'id>,
    pub(crate) serial: u64,
    pub(crate) destination: Destination<'id>,
}
impl<'id> Effect<'id> {
    /// Original operation.
    #[must_use]
    pub const fn operation(self) -> Operation<'id> {
        self.operation
    }
    /// Exact original native destination, including allocation generation.
    #[must_use]
    pub const fn destination(self) -> Destination<'id> {
        self.destination
    }
}
/// Prepared immutable bytes and their original effect. Caller must retain the
/// complete original bytes through actual writing/physical loss, never reencode.
pub struct Prepared<'a, 'id> {
    /// Original immutable output provenance.
    pub effect: Effect<'id>,
    /// Complete official IPC/CADET application frame.
    pub bytes: &'a [u8],
}
/// Immutable borrowed element view; it grants no set/operation ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    /// Application-specific semantic u16 type.
    pub element_type: u16,
    /// Entire retained element bytes.
    pub data: &'a [u8],
}
/// Result policy on the local caller only; the P2P protocol is identical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultMode {
    /// Emit elements proven absent, then DONE/FAILURE.
    Removed,
    /// Emit the final surviving intersection only after agreement.
    Intersection,
}
impl ResultMode {
    pub(crate) fn from_raw(v: u32) -> Self {
        if v == 1 {
            Self::Intersection
        } else {
            Self::Removed
        }
    }
}
/// Actual protocol/lifecycle phase, independent of output queue admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Incoming channel has not sent its first operation request.
    AwaitRequest,
    /// Actual listener has been notified; waiting for local accept.
    AwaitAccept,
    /// Outgoing actual channel is not yet attached/request-written.
    Opening,
    /// Count was sent; waiting for first filter or peer count.
    CountSent,
    /// Alternating genuine Bloom filters are reducing the snapshot.
    Bloom,
    /// Local agreement found; results drain before P2P DONE.
    SendingDone,
    /// Original P2P DONE actually wrote; wait for peer channel close.
    AwaitClose,
    /// Validated peer DONE; local results and own close still drain.
    ReceivedDone,
    /// Expected peer close or responder conclusion was observed.
    Finished,
    /// Actual protocol/resource failure, no saved-success.
    Failed,
    /// Explicit local cancel/source loss; no new result is fabricated.
    Canceled,
}
/// Read-only operation facts. Count/hash equality is the official probabilistic
/// reconciliation criterion, not proof of a malicious remote party's input set.
#[derive(Clone, Copy, Debug)]
pub struct OperationInfo {
    /// Actual phase.
    pub phase: Phase,
    /// Original request id, if committed to a set.
    pub request_id: u32,
    /// Actual current surviving local snapshot count.
    pub current_size: u32,
    /// Actual announced latest remote count.
    pub remote_size: u32,
    /// Actual expected peer.
    pub peer: [u8; 32],
    /// Original deadline, never reset by queue/write progress.
    pub deadline: u64,
    /// Original failure when present.
    pub failure: Option<Error>,
}
/// Original physical peer loss facts; already exposed application frames are
/// never replayed onto a replacement source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerLoss<'id> {
    /// Original physical-stop cause, even for a protocol-expected close.
    pub reason: Error,
    /// Original actual source.
    pub source: PeerSource<'id>,
    /// Original output still retained at stop.
    pub pending: Option<Effect<'id>>,
    /// Actual positive write occurred.
    pub exposed: bool,
    /// Actual original native queue admission was reported.
    pub queued: bool,
    /// Original uncredited application input, if any.
    pub delivery: Option<Delivery<'id>>,
    /// Protocol had already authorized this close.
    pub expected: bool,
}
/// Original physical local MQ stop, before logical resources are canceled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientLoss<'id> {
    /// Original physical-stop cause.
    pub reason: Error,
    /// Original accepted source.
    pub client: Client<'id>,
    /// Original immutable local result/suggestion.
    pub pending: Option<Effect<'id>>,
    /// Actual positive write occurred.
    pub exposed: bool,
    /// Actual original native queue admission was reported.
    pub queued: bool,
    /// Operations logically canceled, still requiring peer drain.
    pub operations: usize,
    /// Actual port binding that caller must retire separately.
    pub port: Option<Port<'id>>,
}
/// Explicit resource and native compatibility profile, independent of wire ids.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Entire element value bound; must also fit RESULT framing.
    pub element_bytes: usize,
    /// Actual allowed Bloom storage/rounds per operation.
    pub bloom_bytes: usize,
    /// Maximum container bit-selection hash rounds.
    pub hash_rounds: u32,
    /// Maximum generated Bloom filters before resource failure.
    pub exchanges: u32,
    /// Initial incoming-channel timeout in caller microseconds.
    pub incoming_micros: u64,
    /// Exact native size/type hash and mutator encoding.
    pub native: NativeEndian,
    /// Actual local C consumer ABI; no layout heuristic is encoded on the wire.
    pub result_layout: gnunet_wire::official::seti::ResultLayout,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            element_bytes: 65535 - gnunet_wire::official::seti::RESULT_PREFIX,
            bloom_bytes: 1024 * 1024,
            hash_rounds: 256,
            exchanges: 1024,
            incoming_micros: 60_000_000,
            native: NativeEndian::native(),
            result_layout: gnunet_wire::official::seti::ResultLayout::native(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Reference {
    pub index: usize,
    pub serial: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct ClientState {
    pub serial: u64,
    pub set: Option<Reference>,
    pub listener: Option<Reference>,
    pub pending: Option<EffectMeta>,
}
/// Caller-owned actual-client metadata row.
#[derive(Clone, Copy)]
pub struct ClientSlot {
    pub(crate) state: Option<ClientState>,
}
impl ClientSlot {
    /// Empty row.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }
}
impl Default for ClientSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct SetState {
    pub serial: u64,
    pub client: Reference,
    pub generation: u64,
    pub count: u32,
}
/// Caller-owned logical-set metadata row.
#[derive(Clone, Copy)]
pub struct SetSlot {
    pub(crate) state: Option<SetState>,
}
impl SetSlot {
    /// Empty row.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }
}
impl Default for SetSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct ListenerState {
    pub serial: u64,
    pub client: Reference,
    pub app: [u8; 64],
    pub port: Option<u64>,
}
/// Caller-owned listener metadata row.
#[derive(Clone, Copy)]
pub struct ListenerSlot {
    pub(crate) state: Option<ListenerState>,
}
impl ListenerSlot {
    /// Empty row; actual announcement remains an explicit port effect.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }
}
impl Default for ListenerSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct ElementState {
    pub set: Reference,
    pub active: bool,
    pub references: u32,
    pub element_type: u16,
    pub len: usize,
    pub hash: [u8; 64],
    pub added: u64,
}
/// Shared element storage. Variable-sized caller slabs avoid reserving a maximum
/// payload buffer separately for every operation or cloning element bodies.
pub struct ElementSlot<'a> {
    pub(crate) bytes: &'a mut [u8],
    pub(crate) state: Option<ElementState>,
}
impl<'a> ElementSlot<'a> {
    /// One unused payload slab.
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, state: None }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Request,
    Count,
    Bloom { length: usize, last: bool },
    Done,
    Suggestion,
    Element { index: usize },
    Terminal { status: u16 },
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct EffectMeta {
    pub operation: Reference,
    pub serial: u64,
    pub action: Action,
    pub exposed: bool,
    pub queued: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NextPeer {
    None,
    Request,
    Count,
    Bloom,
    Done,
}
#[derive(Clone, Copy)]
pub(crate) struct InputState {
    pub serial: u64,
    pub ready: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct OperationState {
    pub serial: u64,
    pub client: Option<Reference>,
    pub set: Option<Reference>,
    pub listener: Option<Reference>,
    pub peer: [u8; 32],
    pub app: [u8; 64],
    pub request_id: u32,
    pub accept_id: u32,
    pub phase: Phase,
    pub mode: ResultMode,
    pub generation: u64,
    pub source: Option<u64>,
    pub peer_dead: bool,
    pub close: bool,
    pub context: usize,
    pub suggestion_sent: bool,
    pub deadline: u64,
    pub count: u32,
    pub remote: u32,
    pub remote_known: bool,
    pub xor: [u8; 64],
    pub remote_xor: [u8; 64],
    pub salt: u32,
    pub k: u32,
    pub bloom: usize,
    pub tx: usize,
    pub rx: usize,
    pub rx_total: usize,
    pub build: bool,
    pub rounds: u32,
    pub next: NextPeer,
    pub pending_peer: Option<EffectMeta>,
    pub pending_client: Option<EffectMeta>,
    pub input: Option<InputState>,
    pub terminal: bool,
    pub failure: Option<Error>,
}
impl OperationState {
    pub fn empty(serial: u64, peer: [u8; 32], app: [u8; 64], deadline: u64) -> Self {
        Self {
            serial,
            client: None,
            set: None,
            listener: None,
            peer,
            app,
            request_id: 0,
            accept_id: 0,
            phase: Phase::Opening,
            mode: ResultMode::Removed,
            generation: 0,
            source: None,
            peer_dead: true,
            close: false,
            context: 0,
            suggestion_sent: false,
            deadline,
            count: 0,
            remote: 0,
            remote_known: false,
            xor: [0; 64],
            remote_xor: [0; 64],
            salt: 0,
            k: 0,
            bloom: 0,
            tx: 0,
            rx: 0,
            rx_total: 0,
            build: false,
            rounds: 0,
            next: NextPeer::None,
            pending_peer: None,
            pending_client: None,
            input: None,
            terminal: false,
            failure: None,
        }
    }
}
/// Fixed operation backing. Three compact bitmaps reference shared element rows;
/// Bloom storage is reused between send/receive, context storage is independent.
pub struct OperationSlot<'a> {
    pub(crate) members: &'a mut [u8],
    pub(crate) active: &'a mut [u8],
    pub(crate) reported: &'a mut [u8],
    pub(crate) bloom: &'a mut [u8],
    pub(crate) context: &'a mut [u8],
    pub(crate) state: Option<OperationState>,
}
impl<'a> OperationSlot<'a> {
    /// Empty original operation storage; Service checks bitmap bounds.
    #[must_use]
    pub fn new(
        members: &'a mut [u8],
        active: &'a mut [u8],
        reported: &'a mut [u8],
        bloom: &'a mut [u8],
        context: &'a mut [u8],
    ) -> Self {
        Self {
            members,
            active,
            reported,
            bloom,
            context,
            state: None,
        }
    }
}
pub(crate) fn bit(bytes: &[u8], index: usize) -> bool {
    bytes[index / 8] & (1 << (index % 8)) != 0
}
pub(crate) fn set_bit(bytes: &mut [u8], index: usize, yes: bool) {
    let mask = 1 << (index % 8);
    if yes {
        bytes[index / 8] |= mask
    } else {
        bytes[index / 8] &= !mask
    }
}
pub(crate) fn xor(to: &mut [u8; 64], value: &[u8; 64]) {
    for (a, b) in to.iter_mut().zip(value) {
        *a ^= *b
    }
}
