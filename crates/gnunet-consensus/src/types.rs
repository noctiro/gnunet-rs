use crate::{Error, wire::RoundContext};
use alloc::vec::Vec;
use core::{cell::Cell, fmt};
/// Non-cloneable original owner domain; no wire ID can replace its brand.
pub struct Instance {
    next: Cell<Option<u64>>,
}
impl Instance {
    /// Create an unused local computation domain without IO or entropy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(Some(1)),
        }
    }
    pub(crate) fn allocate(&self) -> Result<u64, Error> {
        let n = self.next.get().ok_or(Error::Overflow)?;
        self.next.set(n.checked_add(1));
        Ok(n)
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
macro_rules! id {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name<'id> {
            pub(crate) brand: &'id Instance,
            pub(crate) session: u64,
            pub(crate) serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, r: &Self) -> bool {
                core::ptr::eq(self.brand, r.brand)
                    && self.session == r.session
                    && self.serial == r.serial
            }
        }
        impl Eq for $name<'_> {}
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.session)
                    .field(&self.serial)
                    .finish()
            }
        }
    };
}
id!(
    TaskId,
    "One original generic SET reconciliation operation, never reused across phases."
);
id!(
    SetId,
    "One original immutable native SET source population."
);
id!(
    OfferId,
    "One actual incoming generic SET factory/offer on the original listener."
);
id!(
    EffectId,
    "One original immutable native/output/retirement effect."
);
/// Explicit memory/owner/work policy; no value is a private wire field.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum canonical participants including the actual local peer.
    pub peers: usize,
    /// Maximum distinct wrapper elements, including actual peer markers.
    pub elements: usize,
    /// Maximum actual owned wrapper payload allocation across the unique pool.
    pub payload_bytes: usize,
    /// Maximum opaque application payload before its three-byte wrapper.
    pub element_bytes: usize,
    /// Maximum tasks retained for one actual phase/repetition.
    pub tasks: usize,
    /// Maximum live original immutable SET sources, including close debts.
    pub sets: usize,
    /// Maximum retained actual pending incoming offers, including future phases.
    pub offers: usize,
    /// Actual retained allocations plus fixed object metadata limit.
    pub retained_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peers: 32,
            elements: 8192,
            payload_bytes: 16 * 1024 * 1024,
            element_bytes: crate::wire::MAX_APPLICATION_ELEMENT_BYTES,
            tasks: 4096,
            sets: 64,
            offers: 1024,
            retained_bytes: 128 * 1024 * 1024,
        }
    }
}
impl Limits {
    /// Validate explicit finite profiles before participant/graph admission.
    pub fn validate(self) -> Result<(), Error> {
        if self.peers == 0
            || self.peers > 2046
            || self.elements == 0
            || u32::try_from(self.elements).is_err()
            || self.element_bytes > crate::wire::MAX_APPLICATION_ELEMENT_BYTES
            || self.payload_bytes < 3
            || self.tasks == 0
            || self.sets == 0
            || self.offers == 0
            || self.retained_bytes < self.payload_bytes
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Original classified session failure, independent of real cleanup errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// First original business/source cause.
    pub cause: Error,
    /// Whether the original failure was cancellation.
    pub cancelled: bool,
}
/// Readonly local phase at the first business failure. These tags create no
/// task, message, source or permission to replay a phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureStage {
    /// Public insertions are still allowed.
    Collect,
    /// Concluded; waiting for the original start/listener.
    WaitStart,
    /// Preparing a preface SET and its original tasks.
    Setup,
    /// Running a preface all-to-all phase.
    Run,
    /// Allocating the next repetition's local gradecast metadata.
    InitRep,
    /// Driving parallel LEAD/ECHO/CONFIRM chains.
    Gradecast,
    /// Applying the qualified leader ballot.
    Apply,
    /// Retiring the listener or emitting qualified public output.
    Finish,
    /// Original sources/effects are being retired.
    Closing,
    /// All original local retirement obligations were settled.
    Stopped,
}
/// Readonly labels of one original immutable SET population. These copied
/// serial/phase values cannot recreate its branded SetId or authorize IO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetContext {
    /// Local source serial within this original Session.
    pub serial: u64,
    /// Actual source phase, including separate LEAD/ECHO/CONFIRM populations.
    pub kind: u16,
    /// Original repetition, or -1 for a preface.
    pub repetition: i16,
    /// Original leader, or -1 for a preface.
    pub leader: i16,
    /// Immutable canonical source target.
    pub deadline: u64,
    /// Frozen population member count, without copying any member bytes.
    pub members: usize,
    /// Original population setup was actually settled.
    pub ready: bool,
    /// Actual original source loss, if already applied.
    pub retired: Option<Error>,
}

/// Original task state before its first failure transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureTaskState {
    /// No original reconciliation effect was published.
    Planned,
    /// Original reconciliation effect awaits native disposition.
    Starting,
    /// Original commit was written; remote terminal result is pending.
    Active,
    /// Original successful result or local self-task was already terminal.
    Done,
    /// Original task was already failed.
    Failed,
    /// Original cancellation awaits actual retirement.
    Cancel,
}
/// First failed task's immutable labels, captured before its state changes.
/// Serial numbers are local diagnostic labels, not reusable task capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskFailureContext {
    /// Original recorded task failure, independent of a later session failure.
    pub cause: Error,
    /// Actual local stage when this task first failed.
    pub stage: FailureStage,
    /// Original local task serial within this Session.
    pub task_serial: u64,
    /// Original local immutable SET serial within this Session.
    pub set_serial: u64,
    /// Original official phase/repetition/leader/role context.
    pub round: RoundContext,
    /// Original peer's index in the canonical participant roster.
    pub peer_index: usize,
    /// State before the original failure transition.
    pub state: FailureTaskState,
    /// Last already-supplied canonical observation; no clock is sampled here.
    pub observed_canonical: u64,
}
/// Grades of leader rows still retained at the snapshot boundary. Ungraded
/// retained rows must not look like grade0 evidence; old removed rounds are not
/// reconstructed as current grades.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LeaderGrades {
    /// Retained leaders whose final grade has not completed.
    pub pending: usize,
    /// Completed grade0 leaders.
    pub zero: usize,
    /// Completed grade1 leaders.
    pub one: usize,
    /// Completed grade2 leaders.
    pub two: usize,
}
/// Remote tasks still retained at snapshot time, excluding local self-tasks.
/// Closed phase rows may already be gone: these are not historical totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetainedTasks {
    /// Retained tasks with an actual matching successful SET terminal result.
    pub done: usize,
    /// Retained tasks whose original semantic failure is terminal.
    pub failed: usize,
    /// Planned/starting/active/cancel-pending original tasks.
    pub unfinished: usize,
}
/// Retained remote task states for the five actual network phases.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TasksByKind {
    /// Kind0, initial all-to-all.
    pub initial: RetainedTasks,
    /// Kind1, size-preface all-to-all.
    pub size: RetainedTasks,
    /// Kind2, leader dissemination.
    pub lead: RetainedTasks,
    /// Kind3, echo.
    pub echo: RetainedTasks,
    /// Kind5, confirmation.
    pub confirm: RetainedTasks,
}
/// Inline metadata at the first business fail/cancel, before cleanup changes
/// phase or removes original owners. No payload, secret, IO owner or scheduler
/// is retained. Cleanup and later failures never replace this snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureContext {
    /// Same first cause as Outcome::failure.
    pub cause: Error,
    /// Actual stage before entering Closing.
    pub stage: FailureStage,
    /// Kind0/1 only while preparing/running a single preface; parallel gradecast
    /// chains have independent kinds, represented by their task context below.
    pub kind: Option<u16>,
    /// Current exact-agreement repetition, absent during the preface.
    pub repetition: Option<usize>,
    /// Original canonical participant count, including local.
    pub participants: usize,
    /// Original fixed n-faults threshold, including local.
    pub strong: usize,
    /// Actually committed nonzero-grade leaders in the current round ballot.
    pub positive_leaders: usize,
    /// Completed leader grade histogram and genuinely ungraded leaders.
    pub grades: LeaderGrades,
    /// Remote task rows still retained at this exact failure boundary.
    pub tasks: TasksByKind,
    /// Earliest task failure, even if its old phase/source rows were removed.
    pub first_task: Option<TaskFailureContext>,
    /// Last canonical observation already supplied to this Session.
    pub observed_canonical: u64,
}

/// Outcome facts, never inferred from EOF, local commit write or task count alone.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outcome {
    /// First original session failure.
    pub failure: Option<Failure>,
    /// First independent physical retirement failure.
    pub cleanup_failure: Option<Error>,
    /// True only when final consensus element frames and real525 were whole-written.
    pub client_done_written: bool,
}
/// Original SET operation result. Native host supplies its actual SDK/source fact.
#[derive(Clone, Copy, Debug)]
pub enum SetEvent<'a> {
    /// The remote original set contains a value absent from this frozen input.
    AddLocal {
        /// Actual standard outer type,25 for consensus wrappers.
        element_type: u16,
        /// Actual unmodified SET result body.
        data: &'a [u8],
    },
    /// This original set contains a value absent from the peer's original set.
    AddRemote {
        /// Actual standard outer type.
        element_type: u16,
        /// Actual unmodified SET result body.
        data: &'a [u8],
    },
    /// Actual matching terminal SET DONE, never a local commit acknowledgement.
    Done {
        /// Actual public SET result current_size (hint for first size phase).
        current_size: u64,
    },
    /// Actual original operation terminal failure, not a fabricated peer response.
    Failure(Error),
}
/// Immutable original native action; there is no private peer transport.
pub enum Action<'id> {
    /// Establish the actual generic SET UNION listener on the derived app hash.
    Listen {
        /// Original standard SET application hash.
        global_id: [u8; 64],
    },
    /// Create/populate one actual SET source from its immutable core view.
    PrepareSet {
        /// Original source capability used by set_len/set_element.
        set: SetId<'id>,
    },
    /// Actual original prepare/accept and commit; local Written is not remote DONE.
    Reconcile {
        /// Original operation capability.
        task: TaskId<'id>,
        /// Immutable original input set.
        set: SetId<'id>,
        /// Actual intended/accepted remote identity.
        peer: [u8; 32],
        /// Exact official547 context.
        context: RoundContext,
        /// Original actual pending offer, absent for outgoing.
        incoming: Option<OfferId<'id>>,
        /// Actual old SET uint8 Byzantine lower bound.
        lower_bound: u8,
    },
    /// Reject the same actual pending factory offer, not a replacement source.
    RejectOffer {
        /// Original admitted offer.
        offer: OfferId<'id>,
    },
    /// Physically retire the same original operation and any admitted native IO.
    CancelTask {
        /// Original actual task owner.
        task: TaskId<'id>,
    },
    /// Physically retire the original immutable SET source and its IO debts.
    CloseSet {
        /// Original actual SET owner.
        set: SetId<'id>,
    },
    /// Retire the original actual SET listener and outstanding incoming offers.
    CloseListener,
    /// One actual normal523 application payload; data is owned through completion.
    ClientElement {
        /// Original application type.
        element_type: u16,
        /// Original owned payload without the consensus wrapper.
        data: Vec<u8>,
    },
    /// Real normal525; no ACK/EOF/timeout substitute.
    ClientDone,
    /// Physically close the original failed client without a private failure frame.
    CloseClient {
        /// Original classified cause; host preserves native error separately.
        cause: Error,
    },
}
impl Action<'_> {
    /// Exact installed old SET operation for source creation/listening: UNION2.
    #[must_use]
    pub const fn set_operation(&self) -> Option<u32> {
        match self {
            Self::Listen { .. } | Self::PrepareSet { .. } => Some(2),
            _ => None,
        }
    }
    /// Exact public old SET result mode for reconciliation: SYMMETRIC1.
    #[must_use]
    pub const fn result_mode(&self) -> Option<u32> {
        if matches!(self, Self::Reconcile { .. }) {
            Some(1)
        } else {
            None
        }
    }
    /// Exact original standard SET options, with no hidden force-full alias or
    /// private algorithm. A real native caller must pass these on the same intent.
    #[must_use]
    pub const fn set_options(&self) -> Option<gnunet_wire::official::set::Options> {
        match self {
            Self::Reconcile { lower_bound, .. } => Some(gnunet_wire::official::set::Options {
                force_delta: 0,
                force_full: 0,
                byzantine: 1,
                byzantine_lower_bound: *lower_bound,
            }),
            _ => None,
        }
    }

    pub(crate) fn cleanup(&self) -> bool {
        matches!(
            self,
            Self::RejectOffer { .. }
                | Self::CancelTask { .. }
                | Self::CloseSet { .. }
                | Self::CloseListener
                | Self::CloseClient { .. }
        )
    }
}
/// One retained effect with original immutable source/output ownership.
pub struct Effect<'id> {
    /// Original non-reused capability.
    pub id: EffectId<'id>,
    /// Exact original immutable action.
    pub action: Action<'id>,
    pub(crate) admitted: bool,
    pub(crate) deadline: Option<u64>,
}
impl Effect<'_> {
    /// Original frozen absolute UTC bound for new IO; None denotes physical
    /// cleanup only, not permission to mint a replacement source or deadline.
    #[must_use]
    pub const fn deadline(&self) -> Option<u64> {
        self.deadline
    }
    /// Actual local admission fact, independent of completion.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        self.admitted
    }
}
/// Original native disposition, never inferred from a queued operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// All original local writes, or original local control, actually completed.
    Written,
    /// Original action was provably never admitted; unfinished created resources
    /// must be physically retired before reporting this disposition.
    Unsent(Error),
    /// Original exposure is unknown; stop and physically retire before this receipt.
    Lost(Error),
    /// Actual physical cleanup of a cleanup action, with no invented wire write.
    Retired,
}
/// Actual pending disposition accompanying retirement of its original SET.
/// An uncommitted incoming preparation remains a separate listener obligation.
#[derive(Clone, Copy)]
pub enum RetiredEffect<'id> {
    /// The original operation/preparation has its native disposition; this does
    /// not imply that a remote peer processed any locally written bytes.
    Disposition {
        /// Exact original pending effect.
        effect: EffectId<'id>,
        /// Actual whole/zero/unknown exposure, or actual cancellation retirement.
        completion: Completion,
    },
    /// The host still owns this exact not-yet-committed incoming preparation.
    /// It must reject it on the original listener, never just drop its handle.
    Uncommitted {
        /// Exact original pending reconciliation effect.
        effect: EffectId<'id>,
        /// Exact original incoming offer whose Prepared is still owned.
        offer: OfferId<'id>,
        /// Original reason for its provably unadmitted operation.
        cause: Error,
    },
}
/// Actual original terminal receipt, moved without allocation or payload cloning.
pub struct Terminal<'id> {
    /// Original immutable effect and its payload.
    pub effect: Effect<'id>,
    /// Actual native completion class.
    pub completion: Completion,
}

/// Actual application payload acceptance fact. Opaque is legal public data and
/// never implies successful block/signature/source authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadValidation {
    /// Application bytes accepted under the selected opaque/unknown-type policy.
    Opaque,
    /// The explicitly selected validator actually checked this typed payload.
    Checked,
}
/// Caller-selected application/block validation policy at the original input
/// readpoint. There is no implicit mapping of every application type to BLOCK.
pub trait Validator {
    /// An unregistered application type may return Opaque; an explicitly selected
    /// check that actually fails returns its real classified error. Never return
    /// Checked merely because the numeric type exists in a registry.
    fn check(
        &mut self,
        payload_type: u16,
        data: &[u8],
        now: u64,
    ) -> Result<PayloadValidation, Error>;
}
