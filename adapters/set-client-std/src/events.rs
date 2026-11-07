//! Original computation and continuation receipts, never fabricated wire ACKs.
use crate::{
    Bounds, Cause, CopyId, CopyTicket, ElementOwned, Epoch, Error, IterationId, MutationId,
    OperationId, Status,
};
use crate::{prepared::Acceptance, session::TransportLoss};
use std::sync::Arc;
/// Actual local mutation kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    /// Add one original element.
    Add,
    /// Remove one original element.
    Remove,
}
/// Original mutation exposure, without a service-processing acknowledgement.
pub struct MutationReceipt {
    /// Original local continuation token.
    pub id: MutationId,
    /// Original mutation kind.
    pub kind: MutationKind,
    /// Actual bytes written on this MQ.
    pub written: usize,
    /// Actual whole request write.
    pub whole: bool,
    /// Immutable original write budget.
    pub original: Bounds,
}
/// Why the caller stopped delivery for an original operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationCause {
    /// Explicit caller request.
    Requested,
    /// Original operation deadline.
    Deadline,
}
/// Original operation state retained at a real terminal or source loss.
pub struct OperationReceipt {
    /// Original caller token.
    pub id: OperationId,
    /// Original correlation on this Set MQ, never reused.
    pub request_id: u32,
    /// Actual request prefix written.
    pub written: usize,
    /// Actual whole Evaluate/Accept write, without a processing ACK.
    pub request_written: bool,
    /// HALF_DONE was actually observed; this alone is not completion.
    pub half_done: bool,
    /// Last actual current_size field, if a result was observed.
    pub current_size: Option<u64>,
    /// Local cancellation intent, after which no results are delivered.
    pub cancellation: Option<CancellationCause>,
    /// Actual local whole CANCEL write, without a service ACK.
    pub cancellation_written: bool,
    /// Original immutable caller budget.
    pub original: Bounds,
    pub(crate) acceptance: Option<Arc<Acceptance>>,
}
/// Original enumeration state, including a still-retiring canceled generation.
pub struct IterationReceipt {
    /// Original local enumeration token.
    pub id: IterationId,
    /// Original wire iteration generation.
    pub generation: u16,
    /// Actual Iterate request prefix.
    pub written: usize,
    /// Actual Iterate whole write.
    pub request_written: bool,
    /// Original elements exposed to the caller.
    pub elements: u64,
    /// Cancellation intent; it is not a wire END.
    pub cancellation: Option<CancellationCause>,
    /// Actual original IterAck0 whole write.
    pub stop_written: bool,
    /// Original caller target.
    pub original: Bounds,
    pub(crate) cleanup: Option<Bounds>,
    pub(crate) awaiting_ack: bool,
    pub(crate) ack_pending: Option<bool>,
}
/// Original lazy-copy query state.
pub struct CopyReceipt {
    /// Original local query token.
    pub id: CopyId,
    /// Original CopyLazyPrepare actual prefix.
    pub written: usize,
    /// Actual whole request write.
    pub request_written: bool,
    /// Original caller target.
    pub original: Bounds,
}
/// Actual closed Set source and all still-owned original operation metadata.
pub struct SetLoss {
    /// Actual refusing bound/check, present only for a recorded deadline.
    pub deadline: Option<Box<crate::DeadlineContext>>,
    /// Actual transport exposure, captured before physical retirement.
    pub transport: TransportLoss,
    /// Original cause, not replaced by cleanup/admission failure.
    pub cause: Cause,
    /// Independent failure to queue the original deadline cancellation, if any.
    pub cleanup: Option<Error>,
    /// Actual still-unconfirmed mutation continuations.
    pub mutations: Vec<MutationReceipt>,
    /// Actual original unfinished operations; none became a successful result.
    pub operations: Vec<OperationReceipt>,
    /// Actual unfinished enumeration, if any. Storage was allocated when the
    /// original enumeration was admitted; receipt assembly allocates nothing.
    /// A deadline's cold context was already allocated by its refusing check.
    pub iteration: Option<Box<IterationReceipt>>,
    /// Actual unfinished lazy-copy query, if any.
    pub copy: Option<CopyReceipt>,
}
/// Local result of asking to cancel an original operation.
pub enum CancelDisposition {
    /// Original request had zero exposure and was actually removed.
    Unsent(OperationReceipt),
    /// Original CANCEL was admitted behind a previously whole-written request.
    Queued,
    /// Partial original request forced retirement of its actual MQ.
    SourceRetired(SetLoss),
}
/// Actual source-driven Set progress.
pub enum SetProgress {
    /// Original physical source attached; initializer is not yet a whole write.
    Attached(Epoch),
    /// Original socket attempt failed before attachment.
    Retry(std::io::Error),
    /// Actual local initializer prefix or whole write; no service ACK exists.
    InitializerWritten {
        /// Original physical source.
        epoch: Epoch,
        /// Actual positive bytes.
        bytes: usize,
        /// Actual whole Create/CopyLazyConnect write.
        complete: bool,
    },
    /// Actual original Add/Remove continuation. Only a whole write completes it.
    MutationWritten(MutationReceipt),
    /// Actual original Evaluate/Accept prefix or whole write.
    OperationWritten {
        /// Original local operation.
        operation: OperationId,
        /// Actual bytes this syscall.
        bytes: usize,
        /// Actual whole request write.
        complete: bool,
    },
    /// One original result, including nonterminal HALF_DONE; status remains typed.
    Result {
        /// Original operation token.
        operation: OperationId,
        /// Actual original source.
        epoch: Epoch,
        /// Actual service current_size.
        current_size: u64,
        /// Actual public status.
        status: Status,
        /// Actual bytes, empty for status-only markers.
        element: ElementOwned,
        /// Original receipt only for actual DONE/FAILURE.
        terminal: Option<OperationReceipt>,
    },
    /// A canceled/unknown original RID was consumed without another callback.
    StaleResult {
        /// Original raw correlation, not fresh authority.
        request_id: u32,
    },
    /// Actual local CANCEL whole write; it is not service processing/termination.
    OperationCancelled(OperationReceipt),
    /// Deadline cancellation was admitted locally, not yet whole-written.
    CancellationQueued(OperationId),
    /// Actual one-at-a-time enumeration element; caller must choose IterAck.
    IterElement {
        /// Original iteration.
        iteration: IterationId,
        /// Actual element bytes.
        element: ElementOwned,
    },
    /// Actual original header-only enumeration end.
    IterDone(IterationReceipt),
    /// Local iteration cancellation after zero exposure or whole IterAck0.
    /// No wire IterDone/stop ACK is invented.
    IterationCancelled(IterationReceipt),
    /// Actual cookie response; only this single-use ticket can attach its copy.
    CopyReady {
        /// Original query receipt.
        request: CopyReceipt,
        /// Original opaque cookie/source authority.
        ticket: CopyTicket,
    },
    /// Bounded native cursor/control progress, without processing acknowledgement.
    Activity,
    /// Original MQ physically retired with original state and actual cause.
    Lost(SetLoss),
}
