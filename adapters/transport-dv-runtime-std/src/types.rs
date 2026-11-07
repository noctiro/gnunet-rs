//! Caller/native boundaries: tokens are local brands, never protocol fields.
use crate::*;
/// Caller-owned allocation domain, reused for bounded metadata rows. Checked IDs
/// never recycle; no global allocator ID or implicit process singleton exists.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Construct no network, storage, crypto or timers.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    pub(crate) fn next(&self) -> Result<u64, Protocol> {
        let n = self.next.get().checked_add(1).ok_or(Protocol::Overflow)?;
        self.next.set(n);
        Ok(n)
    }
}
/// Original actor/input or output identity. Never an on-wire request ID.
#[derive(Clone, Copy)]
pub struct Token<'id> {
    pub(crate) domain: &'id Instance,
    pub(crate) serial: u64,
}
impl PartialEq for Token<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.domain, other.domain) && self.serial == other.serial
    }
}
impl Eq for Token<'_> {}
impl fmt::Debug for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DvRuntimeToken").field(&self.serial).finish()
    }
}
/// Exact registered direct transport queue lease. It is not end-to-end DV peer
/// authentication. Its original ClientId was minted by the real Engine. The
/// caller port must call attach only for an actually eligible current queue and
/// detach on its source/queue retirement, never on a raw peer string alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Neighbour<'id> {
    pub(crate) token: Token<'id>,
    pub(crate) client: gnunet_transport::ClientId,
    pub(crate) peer: PeerId,
    pub(crate) queue: u32,
    pub(crate) reverse: bool,
}
impl Neighbour<'_> {
    /// Original direct peer claimed by the actual eligible transport queue.
    pub const fn peer(&self) -> PeerId {
        self.peer
    }
    /// Actual Engine-minted local owner, not a raw client number.
    pub fn client(&self) -> &gnunet_transport::ClientId {
        &self.client
    }
    /// Actual registered incoming-link reverse reachability fact, supplied by
    /// the native queue owner; this is not cryptographic peer authentication.
    pub const fn reverse_link(&self) -> bool {
        self.reverse
    }
    /// Original local queue number; the private lease disambiguates reuse.
    pub const fn queue(&self) -> u32 {
        self.queue
    }
}
/// Original caller-operation limits captured BEFORE any earlier Engine/native
/// queue wait. These are trusted time-port inputs, not authentication receipts.
/// Actor admission may only narrow them; no capacity retry renews either target.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    /// Original GNUnet canonical absolute target (not remote sender monotime).
    pub until: gnunet_wire::official::AbsoluteTime,
    /// Original immutable actual native target.
    pub hard: Instant,
}
impl Budget {
    /// Check only the captured native target, without sampling the canonical
    /// clock. This does not establish source liveness or authentication.
    pub fn check_native(self) -> Result<(), Protocol> {
        if Instant::now() >= self.hard {
            Err(Protocol::Deadline)
        } else {
            Ok(())
        }
    }
}
/// Original input phase before the failed transition/cancellation. Tags contain
/// no packet, key material, provider object or application-owned metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputPhase {
    /// Unprocessed LEARN signature/route admission.
    Learn,
    /// A source watermark load has not yet completed.
    LearnSourceLoad,
    /// A source watermark store has not yet been admitted.
    LearnSourceStore,
    /// An admitted source watermark store awaits its actual receipt.
    LearnStore,
    /// Verified LEARN retained for its original bounded forward planner.
    LearnReady,
    /// Unprocessed BOX routing/material lookup.
    Box,
    /// Original BOX still owns a forwarding output.
    Forwarding,
    /// Original PILS decapsulation operation awaits its actual result.
    Decapsulating,
    /// Original material selected for BOX authentication.
    Material,
    /// Original durable BOX admission is waiting.
    Waiting,
    /// Original private BOX admission is ready for promotion.
    Ready,
    /// Original BOX admission refusal awaits processing.
    Refused,
    /// Original authenticated grant awaits external Engine admission.
    Granted,
    /// Original row already completed processing.
    Finished,
}
/// Original output phase before the failed transition/cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputPhase {
    /// Original purpose37 PILS signing operation.
    Probe,
    /// Original purpose36 PILS signing operation.
    Forward,
    /// Original purpose30 PILS certification/BOX sealing operation.
    Seal,
    /// Immutable output awaiting or retaining native admission.
    Ready,
    /// Original native output still requires a real physical outcome.
    AwaitPhysical,
    /// Original output already has its terminal local outcome.
    Finished,
}
/// Readonly facts about the unique retained output of a forwarding input,
/// captured before cancellation changes either row. Its token identifies an
/// existing output; copying it constructs no owner or physical write authority.
#[derive(Clone, Copy, Debug)]
pub struct ForwardChildFailure<'id> {
    /// Actual original output identity, also enumerable through output_tokens.
    pub token: Token<'id>,
    /// Exact original signing/queue/retirement phase at this snapshot.
    pub phase: OutputPhase,
    /// Actor has received this output's actual native-queued callback.
    /// False does not independently prove the external owner has no frame.
    pub queued: bool,
    /// Actor has received this output's actual positive-byte callback.
    pub exposed: bool,
    /// Retained original terminal outcome, never inferred from phase or time.
    pub outcome: Option<WriteOutcome>,
    /// Same output's immutable canonical and native targets, never renewed.
    pub budget: Budget,
}
/// Bounded original row facts, copied before a failing transition consumes its
/// state. These observations never manufacture admission, ACK or source loss.
#[derive(Clone, Copy, Debug)]
pub enum FailureState<'id> {
    /// Original received frame's retained processing/child-output ownership.
    Input {
        /// Exact original processing phase.
        phase: InputPhase,
        /// Native elapsed time since actual actor input admission.
        age: std::time::Duration,
        /// Original retained child-output count.
        forwards: usize,
        /// Original LEARN/BOX planning flag.
        planning: bool,
        /// A detached original provider debt is already in this row's debt
        /// field. False does not deny work owned inside its current phase.
        detached_disk_debt: bool,
        /// Present only for a Forwarding input with exactly one retained
        /// output whose original parent token matches this input. Absence is
        /// diagnostic uncertainty, never permission to settle or drop an owner.
        forwarding_child: Option<ForwardChildFailure<'id>>,
    },
    /// Original output's retained routing and physical callback observations.
    Output {
        /// Exact original signing/queue/retirement phase.
        phase: OutputPhase,
        /// Original parent input when this is a forwarded output.
        parent: Option<Token<'id>>,
        /// Actual original local target whose outputs share causal ordering.
        ordered_target: Option<PeerId>,
        /// This actor has received its original queued callback. False alone
        /// does not prove the external owner has no retained native frame.
        queued: bool,
        /// This actor has received its original positive-byte callback.
        exposed: bool,
        /// Retained actual local outcome, if already observed.
        outcome: Option<WriteOutcome>,
    },
}
/// Inline diagnostic snapshot taken before original row state is moved or
/// canceled. No payload, secret, new queue or refreshed budget is retained.
#[derive(Clone, Debug)]
pub struct FailureContext<'id> {
    /// Original row's canonical and native targets, including earlier waits.
    pub budget: Budget,
    /// Original source guard's canonical and independent native targets.
    pub source: Budget,
    /// Original adopted PILS identity's absolute expiry, never a refreshed HELLO.
    pub identity_until: gnunet_wire::official::AbsoluteTime,
    /// Native time at this snapshot, before the failing transition/cancellation.
    pub observed_native: Instant,
    /// Existing canonical sample used by that transition, or None when the
    /// native guard failed before any canonical sampling. No new sample occurs.
    pub observed_absolute: Option<gnunet_wire::official::AbsoluteTime>,
    /// Exact original typed ClientId/queue/peer/generation, not a current lease.
    pub neighbour: Neighbour<'id>,
    /// Original typed processing/physical facts.
    pub state: FailureState<'id>,
}
/// Explicit bounded RAM/CPU/native policies. Buffer bytes are supplied once in
/// Storage, not allocated at maximum size per logical peer/channel.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneous retained incoming physical frames.
    pub inputs: usize,
    /// Simultaneous signed/encrypted/forwarded output frames.
    pub outputs: usize,
    /// Actual eligible direct queue leases.
    pub neighbours: usize,
    /// Shared retained input/output packet-buffer and pre-seal plaintext capacities.
    pub bytes: usize,
    /// Largest complete official frame accepted/sent, <=65535.
    pub frame_bytes: usize,
    /// Logical lifetime captured at original operation admission.
    pub operation: Duration,
    /// Actual immutable per-operation native budget, independent of UTC rollback.
    pub native_operation: std::time::Duration,
    /// Original finite physical PILS/source lifetime; new HELLO/cache hits do
    /// not renew this native bound or reopen a retired Source allocation.
    pub source: std::time::Duration,
    /// Cancelled PILS suffix grace, followed by actual close of the original MQ.
    pub retirement_grace: std::time::Duration,
    /// First partial PILS input frame deadline; activity cannot renew it.
    pub input: std::time::Duration,
    /// Bounded per-poll state transitions, excluding bounded signature work.
    pub quantum: usize,
    /// Fixed reusable-material lease captured only on a real miss. Canonical
    /// and native targets are independently capped by the original Source and
    /// identity; packet/route deadlines and cache hits cannot renew this lease.
    pub material_lifetime: std::time::Duration,
    /// Maximum unique nonces under one certified send material epoch.
    pub material_messages: u32,
    /// Existing route policy, including real probe lifetime.
    pub routes: dv::routes::Limits,
    /// Fixed live replay hash-probe bounds.
    pub replay: replay::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            inputs: 16,
            outputs: 16,
            neighbours: 64,
            bytes: 1024 * 1024,
            frame_bytes: 65535,
            operation: Duration(30_000_000),
            native_operation: std::time::Duration::from_secs(30),
            source: std::time::Duration::from_secs(86400),
            retirement_grace: std::time::Duration::from_secs(2),
            input: std::time::Duration::from_secs(10),
            quantum: 8,
            material_lifetime: std::time::Duration::from_secs(300),
            material_messages: 65536,
            routes: Default::default(),
            replay: Default::default(),
        }
    }
}
/// Caller-fixed metadata and shared plaintext pool. Each whole output loan is
/// moved into its actual authentication/commit/replay owner then erased and
/// returned. The runtime stores no reference into its own Vec/metadata.
pub struct Storage<'slots, 'source, 'id, 'out> {
    /// Empty route slots, independent of output/payload buffers.
    pub routes: &'slots mut [dv::routes::RouteSlot],
    /// Empty original probe slots.
    pub probes: &'slots mut [dv::routes::ProbeSlot],
    /// Empty source watermark admission slots.
    pub sources: &'slots mut [dv::routes::SourceSlot],
    /// Empty fixed certified send-key slots.
    pub send: &'slots mut [cache::SendSlot<'source, 'id>],
    /// Empty fixed decapsulated receive-key slots.
    pub receive: &'slots mut [cache::ReceiveSlot<'source, 'id>],
    /// Original one-source replay watermark slots.
    pub replay_peers: &'slots mut [replay::PeerSlot<'id>],
    /// Original one-source exact nonce slots.
    pub replay_nonces: &'slots mut [replay::NonceSlot<'id>],
    /// Shared nonempty caller output loans. Capacity is validated once; each
    /// loan can serve differently sized live packets without per-peer padding.
    pub plaintext: Vec<&'out mut [u8]>,
    /// One shared temporary AEAD/signature work buffer, >=frame_bytes.
    pub scratch: &'slots mut [u8],
}
/// Actual stage/cause, with no secret payload Debug/JSON exposure.
#[derive(Debug)]
pub enum Error {
    /// Original codec/resource/source/cancel/route refusal.
    Protocol(Protocol),
    /// This original incoming Budget expired before admission. The caller still
    /// owns its exact input/FC debt; this fact asserts no source liveness.
    InputBudgetExpired,
    /// This exact retained task or supplied original Budget expired. Its caller
    /// still owns the original token/debt; this fact asserts no source liveness.
    TaskBudgetExpired,
    /// Original actual PILS native owner cause.
    Pils(gnunet_client_host::ConnectError),
    /// Actual job/source/result refusal.
    Crypto(gnunet_transport_dv_crypto_host::Error),
    /// Original persistent provider cause, including Unknown and cleanup.
    Store(store::Error),
    /// Original physical PILS source loss, preserved before explicit close.
    Source {
        /// Actual native owner's first source-loss cause.
        cause: gnunet_pils_host::client::LossCause,
        /// Number of original native operations retained at source loss.
        retained: usize,
    },
    /// Original durable/live BOX gate refused.
    Box(box_admission::Reason),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DV runtime: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<Protocol> for Error {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Pils(e)
    }
}
impl From<gnunet_transport_dv_crypto_host::Error> for Error {
    fn from(e: gnunet_transport_dv_crypto_host::Error) -> Self {
        Self::Crypto(e)
    }
}
impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Self::Store(e)
    }
}
/// Required handling of one unadmitted original incoming frame. The observing
/// boundary supplies this policy independently of its numeric error value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputRefusalDisposition {
    /// Local bounded capacity or allocation is temporarily unavailable. Retain
    /// the exact frame, caller origin and original targets for a later attempt.
    Deferred,
    /// This input or its original neighbour lease cannot be admitted. It may be
    /// discarded under its original physical/FC owner; this does not declare
    /// the peer malicious or the whole Actor source lost.
    Rejected,
    /// This original input budget expired before admission. Dropping that input
    /// grants no knowledge about the independent Actor/source lifetime.
    Expired,
    /// The shared Actor/source/clock or its admission authority failed. Retrying
    /// only this frame cannot repair it; retire under the original owner policy.
    /// This tag is not itself proof of a physical MQ close.
    Source,
}
/// An incoming frame was never accepted. Its original caller-owned debt and
/// cause survive together with handling selected at the actual failure site.
pub struct InputRefused<J> {
    /// Same non-Clone caller physical/FC attribution, never relabelled.
    pub origin: J,
    /// Original failure, including provider errors with protocol-like values.
    pub error: Error,
    /// Handling supplied by the admission boundary, not inferred from `error`.
    pub disposition: InputRefusalDisposition,
}
/// Caller output was never accepted. Retains the exact original external debt.
pub struct Refused<J> {
    /// Original caller-owned physical frame/FC attribution, unmodified.
    pub origin: J,
    /// Actual admission refusal; no native success or FC reply occurred.
    pub error: Error,
}
/// Exactly what happened locally to one original output, never remote delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// Original complete frame actually written.
    Written,
    /// Physical owner retired; Some tracks actual positive-byte exposure, None
    /// preserves unavailable native cursor knowledge.
    Lost(Option<bool>),
    /// No physical queue admission occurred.
    Unsent,
}
/// End of one retained input, without sending any FC/CORE reply. Caller must
/// settle the SAME original native flow-control debt under its own source lease.
pub struct Finished<'id, J> {
    /// Original physical input metadata, never relabelled to a new source.
    pub origin: J,
    /// Input processing outcome; only Delivery means actual Engine admission.
    pub disposition: Disposition,
    /// Original BOX store debt (if callback cancelled after actual admission).
    pub disk_debt: Option<box_admission::Debt<'id>>,
}
/// Input processing facts. No variant is a remote application ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Valid LEARN was processed, and all caller-selected forward effects ended.
    Learned,
    /// BOX forwarded; original physical output fact retained separately.
    Forwarded(WriteOutcome),
    /// Actual verified inner frame was admitted by the caller Engine port.
    Delivered,
    /// Explicit original processing/cancellation/source failure.
    Dropped,
}
