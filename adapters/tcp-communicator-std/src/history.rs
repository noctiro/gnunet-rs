//! Real local replay durability port, called sequentially with the same process
//! Clock. The production implementation retains private ledger/frontier receipts;
//! no public u64, bool or queue count is a successful persistence constructor.
use crate::SessionId;
use gnunet_crypto::EddsaPublicKey;
use gnunet_tcp_communicator_core::session::ReplayKind;
use gnunet_types::Error;
use std::task::{Context, Poll};
/// Immutable original scan/store identity. Only the actual Manager can mint it
/// from an admitted verified ReplayStart and original session/MQ generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayTask {
    session: SessionId,
    epoch: u64,
    scan: u32,
    peer: EddsaPublicKey,
    kind: ReplayKind,
    stamp: u64,
}
impl ReplayTask {
    pub(crate) fn new(
        session: SessionId,
        epoch: u64,
        scan: u32,
        peer: EddsaPublicKey,
        kind: ReplayKind,
        stamp: u64,
    ) -> Self {
        Self {
            session,
            epoch,
            scan,
            peer,
            kind,
            stamp,
        }
    }
    /// Original session allocation/generation, never a newly found equal peer.
    #[must_use]
    pub const fn session(&self) -> &SessionId {
        &self.session
    }
    /// Actual verified public peer at original replay admission.
    #[must_use]
    pub const fn peer(&self) -> EddsaPublicKey {
        self.peer
    }
    /// Original independent official key family.
    #[must_use]
    pub const fn kind(&self) -> ReplayKind {
        self.kind
    }
    /// Original already signature-checked received monotonic timestamp.
    #[must_use]
    pub const fn stamp(&self) -> u64 {
        self.stamp
    }
    /// Original PEERSTORE physical epoch, diagnostic/source comparison only.
    #[must_use]
    pub const fn peerstore_epoch(&self) -> u64 {
        self.epoch
    }
    /// Original scan's actual RID, not a reusable request constructor.
    #[must_use]
    pub const fn scan(&self) -> u32 {
        self.scan
    }
    /// Same actual manager allocation, independently of peer/session equality.
    #[must_use]
    pub fn same_process(&self, other: &Self) -> bool {
        self.session.same_process(&other.session)
    }
}
/// Actual local process progress; it never claims a PS STORE_RESULT or grants
/// Session's original iterator a NEXT, STOP, END or callback credit.
#[derive(Clone, Debug)]
pub enum HistoryProgress {
    /// Original worker IO/receipt state really advanced.
    Activity,
    /// Original task's local IO/permit debt really retired after requested close.
    Retired {
        /// Exact original task, with no source retag.
        task: ReplayTask,
        /// Original publication may have happened; never persistence success.
        uncertain: bool,
    },
}
/// Sequential business port on the same concrete process object as Clock.
/// Implementations must use actual qualified durable receipts, and retain those
/// original receipts internally while returning Pending or queue backpressure.
/// There is no NoLedger/default-success implementation.
pub trait ReplayHistory {
    /// Actual same-source durable floor. Never fabricate an iterator record or
    /// END; caller uses Session.replay_floor only after the real Start admission.
    fn local_floor(&mut self, original: &ReplayTask) -> Result<Option<u64>, Error>;
    /// Ready only after actual ledger commit and actual frontier minimum-gen
    /// persistence, retaining that task's private permit until store_admitted.
    fn poll_store(
        &mut self,
        cx: &mut Context<'_>,
        original: &ReplayTask,
        verified_stamp: u64,
    ) -> Poll<Result<(), Error>>;
    /// Report only original actual PS FIFO admission, not remote write/result.
    /// This is an infallible report of the actual queue fact. An internal
    /// diagnostic failure must latch/fence, not make the caller replay an
    /// already admitted STORE as if it were unsent.
    fn store_admitted(&mut self, original: &ReplayTask, actual_stamp: u64);
    /// Retire original business permission; actual admitted disk work must still
    /// produce its physical outcome before HistoryProgress::Retired is returned.
    fn retire_history(&mut self, original: &ReplayTask) -> Result<(), Error>;
    /// Advance the original worker and original task retirements, also during
    /// clock-free shutdown. No new work, deadline, key or source is created here.
    fn poll_history(&mut self, cx: &mut Context<'_>) -> Poll<Result<HistoryProgress, Error>>;
}
