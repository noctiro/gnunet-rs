//! Typed publication history. Loading records does not verify immutable payloads.
use super::{
    codec,
    graph_state::{self, GraphTarget},
    plan::{self, Plan},
    registration,
};
use crate::{durable::store::Store, network::BlockOptions};
use gnunet_datastore_host::{Interruption, Outcome};
use gnunet_wire::official::datastore::Response;
use std::fmt;

/// Original strict local-history refusal, separate from native write certainty.
#[derive(Debug)]
pub enum ModelError {
    /// An unsupported private format/event version was encountered.
    Version,
    /// Truncated, trailing, noncanonical or malformed private fields.
    Format,
    /// An explicit budget or checked representation was exceeded.
    Limit,
    /// The original WAL sequence/index does not match the next checked prefix.
    Order,
    /// Original row, request digest or intent coordinate differs.
    Binding,
    /// This event does not follow the retained original lifecycle/disposition.
    Transition,
    /// The immutable plan failed its original structural/artifact-policy check.
    Plan(plan::Error),
    /// The actual official response parser refused the retained bytes.
    Protocol(gnunet_types::Error),
}
impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
            other => write!(f, "FS publication task history: {other:?}"),
        }
    }
}
impl std::error::Error for ModelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(e) => Some(e),
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}
impl From<gnunet_types::Error> for ModelError {
    fn from(error: gnunet_types::Error) -> Self {
        Self::Protocol(error)
    }
}
/// Immutable prepared publication and exact weighted PUT policy. No seed, native
/// lifetime token, reservation or previous runtime deadline is retained here.
#[derive(Clone, Debug)]
pub struct Manifest {
    /// Prepared artifact and ordered exact payload references.
    pub plan: Plan,
    /// Priority/anonymity/replication/expiry carried unchanged on every PUT.
    pub blocks: BlockOptions,
    /// Original preparation and payload-verification budgets.
    pub limits: plan::Limits,
    /// Original graph target only for an explicitly tracked single namespace publication.
    pub graph: Option<GraphTarget>,
}
impl Manifest {
    /// Check immutable shape and policy without reading payloads or opening MQs.
    /// Running must independently obtain the plan's actual verification receipt.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limits.max_plan_bytes > codec::MAX_EVENT_BYTES {
            return Err(ModelError::Limit);
        }
        self.plan.validate(self.limits).map_err(ModelError::Plan)?;
        if let Some(target) = self.graph {
            target.validate(&self.plan)?;
        }
        if self.plan.puts.is_empty() {
            return Err(ModelError::Format);
        }
        Ok(())
    }
}
/// Durable lifecycle; an interrupted original intent never authorizes a replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Immutable preparation exists, with no runtime implied.
    Ready,
    /// A caller explicitly began a run.
    Running,
    /// Caller pause is durable; retire the original native operation.
    PauseRequested,
    /// Original work retired with no unresolved current mutation.
    Paused,
    /// Cancellation intent is durable; no new publication may begin.
    CancelRequested,
    /// Local cancellation settled; already accepted or uncertain effects remain.
    Cancelled,
    /// Every ordered PUT has an actual accepted reply, with no current intent.
    Complete,
    /// Original run failed while retaining its complete facts.
    Failed,
    /// An original mutation cannot safely be repeated or inferred from readback.
    Uncertain,
}
/// Exact known accepted prefix, derived only from retained actual replies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// Ordered plan positions with real nonnegative PUT STATUS replies.
    pub accepted: usize,
    /// Actual payload bytes in that prefix, including repeated weighted PUTs.
    pub bytes: u128,
}
/// One original intent coordinate. This is a local WAL binding, never a wire
/// identifier or a recreated native Operation/Epoch capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attempt {
    /// Original zero-based ordered plan position.
    pub index: usize,
    /// Hash of the exact original encoded PUT, including its immutable policy.
    pub request_hash: [u8; 64],
    /// Zero-based original Intent record position, disambiguating explicit retries.
    pub intent_record: usize,
}
/// Original exclusive owner proved that no request bytes were exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoEffect {
    /// Failure/control occurred before the native request was submitted.
    NotSubmitted,
    /// A leased original frame was removed before its first physical write.
    NotSent,
    /// Native cancellation completed before any send was leased.
    CancelledBeforeSend,
    /// Native timeout completed before any send was leased.
    TimedOutBeforeSend,
    /// Original FS registration owner proved zero exposure; this makes no
    /// claim about admission or a DATASTORE frame lease.
    UnexposedRegistration,
}
/// Last retained disposition of the one original unresolved intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Only intent is durable. Reopen must conservatively refuse auto-replay.
    Intent,
    /// The peer actually declared a negative result, which is not a no-send proof.
    Refused {
        /// Original Refused record containing exact terminated reply bytes.
        record_index: usize,
        /// Actual independent caller interruption, when present.
        interruption: Option<Interruption>,
    },
    /// Original outcome/retained diagnostic, without a fabricated accepted reply.
    Unknown {
        /// Original Unknown record; its response may be absent or malformed.
        record_index: usize,
        /// Actual native terminal outcome, without laundering it into an ACK.
        outcome: Outcome,
        /// Actual independent caller interruption, when present.
        interruption: Option<Interruption>,
    },
}
/// Original unresolved mutation. Even an intent without a result can have reached
/// the peer before a process failure; absence of a receipt grants no retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Exact original row/request/intent binding.
    pub attempt: Attempt,
    /// Original effect knowledge, independent of lifecycle phase.
    pub disposition: Disposition,
}
/// Small index of an actual accepted reply. The original Store owns bytes once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedRef {
    /// Original actual mutation attempt, including retry generation.
    pub attempt: Attempt,
    /// Original Accepted record holding the complete raw STATUS.
    pub record_index: usize,
    /// Original timeout/cancellation does not revoke an actual accepted reply.
    pub interruption: Option<Interruption>,
}
/// Small checked events and borrowed actual native replies.
#[derive(Debug)]
pub enum Event<'a> {
    /// First immutable manifest; boxed only for this large one-time record.
    Manifest(Box<Manifest>),
    /// Independent original FS INDEX_START history, never inferred from PUT ACKs.
    Index(registration::Event<'a>),
    /// An original actual graph effect after the real namespace PUT was accepted.
    GraphRecorded(graph_state::Recorded),
    /// Must be synced before the original exact PUT may be submitted.
    Intent {
        /// Ordered current plan position.
        index: usize,
        /// Exact original encoded PUT digest.
        request_hash: [u8; 64],
    },
    /// A real nonnegative PUT STATUS was received for this exact original attempt.
    Accepted {
        /// Original row/request/intent generation.
        attempt: Attempt,
        /// Complete actual official STATUS, including its original diagnostics.
        response: &'a [u8],
        /// Actual independent original caller interruption.
        interruption: Option<Interruption>,
    },
    /// The original owner proved zero exposure, so this position may safely retry.
    NotApplied {
        /// Exact original attempt whose owner proved no send.
        attempt: Attempt,
        /// Native/local proof class; a remote negative reply is never such proof.
        reason: NoEffect,
        /// Actual independent original caller interruption.
        interruption: Option<Interruption>,
    },
    /// Preserve a negative actual peer declaration; it does not clear the intent.
    Refused {
        /// Exact original mutation attempt.
        attempt: Attempt,
        /// Complete actual negative STATUS.
        response: &'a [u8],
        /// Actual independent original caller interruption.
        interruption: Option<Interruption>,
    },
    /// Preserve the original unresolved effect and optional diagnostic bytes.
    Unknown {
        /// Exact original mutation attempt.
        attempt: Attempt,
        /// Actual native result; even a projected STATUS cannot mint a raw ACK.
        outcome: Outcome,
        /// Original optional diagnostic frame, including malformed replies.
        response: Option<&'a [u8]>,
        /// Actual independent original caller interruption.
        interruption: Option<Interruption>,
    },
    /// Explicit caller authorization to try a peer-refused request again. It
    /// applies only to Refused, never bare intents or native Unknown outcomes.
    RetryRefused {
        /// Exact refused original attempt selected by the caller.
        attempt: Attempt,
    },
    /// Lifecycle fact with the exact already-established prefix, not a new ACK.
    Phase {
        /// Original lifecycle fact.
        phase: Phase,
        /// Must exactly equal counts derived from actual Accepted records.
        counts: Counts,
    },
}
/// Checked original history. Only a run-time payload verifier can authenticate
/// the plan; this model never manufactures a file/content verification receipt.
pub struct State {
    /// Immutable original artifact and weighted PUT policy.
    pub manifest: Manifest,
    /// Last original durable lifecycle phase.
    pub phase: Phase,
    /// Exact accepted prefix, independent of current native/runtime activity.
    pub counts: Counts,
    /// Small references to actual accepted replies in original order.
    pub accepted: Vec<AcceptedRef>,
    /// One original unresolved intent, if any.
    pub pending: Option<Pending>,
    /// Actual original FS index-registration prefix and unresolved intent.
    pub indexes: registration::State,
    /// Original graph effect history, separate from current graph/payload verification.
    pub graph: graph_state::State,
    /// Last requested pause/cancel, retained across Failed/Uncertain outcomes.
    pub requested: Option<Phase>,
    task_id: [u8; 32],
    applied: u64,
    interrupted_run: bool,
}
impl State {
    /// Read and replay the checked WAL, without network or publication-payload I/O.
    pub fn load(store: &mut Store) -> Result<Self, super::Cause> {
        let first = store.read_record(0)?.ok_or(ModelError::Format)?;
        if first.sequence != 1 {
            return Err(ModelError::Order.into());
        }
        let Event::Manifest(manifest) = codec::decode_event(first.kind, first.bytes)? else {
            return Err(ModelError::Format.into());
        };
        let mut state = Self {
            manifest: *manifest,
            phase: Phase::Ready,
            counts: Counts::default(),
            accepted: Vec::new(),
            pending: None,
            indexes: registration::State::default(),
            graph: graph_state::State::default(),
            task_id: *store.task_id(),
            requested: None,
            applied: 1,
            interrupted_run: false,
        };
        for index in 1..store.record_count() {
            let record = store.read_record(index)?.ok_or(ModelError::Order)?;
            state.apply(record.sequence, index, record.kind, record.bytes)?;
        }
        Ok(state)
    }
    /// Number of exact original complete records already applied.
    #[must_use]
    pub const fn applied(&self) -> u64 {
        self.applied
    }
    /// An original interruption occurred since this run's Running record.
    #[cfg(test)]
    #[must_use]
    pub const fn current_run_interrupted(&self) -> bool {
        self.interrupted_run
    }
    /// A bare intent or Unknown outcome cannot be implicitly replayed.
    #[must_use]
    pub fn uncertain(&self) -> bool {
        self.indexes.uncertain()
            || self
                .pending
                .is_some_and(|p| !matches!(p.disposition, Disposition::Refused { .. }))
    }
    /// A peer refusal requires explicit local caller authorization before retry.
    #[must_use]
    pub fn requires_explicit_retry(&self) -> bool {
        self.indexes.requires_explicit_retry()
            || self
                .pending
                .is_some_and(|p| matches!(p.disposition, Disposition::Refused { .. }))
    }
    /// Validate the transition before any actual WAL append.
    pub fn check(&self, event: &Event<'_>) -> Result<(), ModelError> {
        match event {
            Event::Manifest(_) => return Err(ModelError::Transition),
            Event::GraphRecorded(fact) => {
                if matches!(self.phase, Phase::Ready | Phase::Complete)
                    || self.pending.is_some()
                    || !self
                        .indexes
                        .complete(self.manifest.plan.index_sources().len())
                    || self.counts.accepted != self.manifest.plan.puts.len()
                {
                    return Err(ModelError::Transition);
                }
                self.graph.check(
                    fact,
                    self.manifest.graph,
                    self.task_id,
                    self.accepted.first().map(|a| a.attempt),
                )?;
            }
            Event::Index(event) => {
                if self.pending.is_some()
                    || matches!(event, registration::Event::RetryRefused { .. })
                        && self.requested == Some(Phase::CancelRequested)
                {
                    return Err(ModelError::Transition);
                }
                self.indexes
                    .check(event, self.manifest.plan.index_sources().len(), self.phase)?;
            }
            Event::Intent { index, .. } => {
                if self.phase != Phase::Running
                    || self.pending.is_some()
                    || !self
                        .indexes
                        .complete(self.manifest.plan.index_sources().len())
                {
                    return Err(ModelError::Transition);
                }
                if *index != self.counts.accepted || *index >= self.manifest.plan.puts.len() {
                    return Err(ModelError::Order);
                }
            }
            Event::Accepted {
                attempt, response, ..
            } => {
                self.original(*attempt)?;
                if !matches!(
                    self.pending.map(|p| p.disposition),
                    Some(Disposition::Intent)
                ) {
                    return Err(ModelError::Transition);
                }
                if !effect_phase(self.phase) {
                    return Err(ModelError::Transition);
                }
                let Response::Status(status) = Response::decode(response)? else {
                    return Err(ModelError::Format);
                };
                if status.code < 0 {
                    return Err(ModelError::Format);
                }
                let _next = self.next_counts()?;
            }
            Event::NotApplied { attempt, .. }
            | Event::Refused { attempt, .. }
            | Event::Unknown { attempt, .. } => {
                if matches!(
                    event,
                    Event::NotApplied {
                        reason: NoEffect::UnexposedRegistration,
                        ..
                    }
                ) {
                    return Err(ModelError::Format);
                }
                self.original(*attempt)?;
                if !effect_phase(self.phase)
                    || !matches!(
                        self.pending.map(|p| p.disposition),
                        Some(Disposition::Intent)
                    )
                {
                    return Err(ModelError::Transition);
                }
                if let Event::Refused { response, .. } = event {
                    let Response::Status(status) = Response::decode(response)? else {
                        return Err(ModelError::Format);
                    };
                    if status.code >= 0 {
                        return Err(ModelError::Format);
                    }
                }
                if let Event::Unknown {
                    response: Some(response),
                    ..
                } = event
                    && response.len() > codec::MAX_RESPONSE_BYTES
                {
                    return Err(ModelError::Limit);
                }
            }
            Event::RetryRefused { attempt } => {
                self.original(*attempt)?;
                if matches!(
                    self.phase,
                    Phase::CancelRequested | Phase::Cancelled | Phase::Complete
                ) || !matches!(
                    self.pending.map(|p| p.disposition),
                    Some(Disposition::Refused { .. })
                ) {
                    return Err(ModelError::Transition);
                }
            }
            Event::Phase { phase, counts } => {
                if *counts != self.counts {
                    return Err(ModelError::Binding);
                }
                match phase {
                    Phase::Ready
                        if self.phase != Phase::Ready
                            || self.counts != Counts::default()
                            || self.pending.is_some()
                            || self.graph.recorded.is_some()
                            || !self.indexes.accepted.is_empty()
                            || self.indexes.pending.is_some() =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::Running
                        if matches!(self.phase, Phase::CancelRequested | Phase::Cancelled)
                            || self.pending.is_some()
                            || self.indexes.pending.is_some() =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::PauseRequested
                        if !matches!(self.phase, Phase::Running | Phase::PauseRequested) =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::Paused
                        if self.phase != Phase::PauseRequested
                            || self.pending.is_some()
                            || self.indexes.pending.is_some() =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::CancelRequested if self.phase == Phase::Cancelled => {
                        return Err(ModelError::Transition);
                    }
                    Phase::Cancelled if self.phase != Phase::CancelRequested => {
                        return Err(ModelError::Transition);
                    }
                    Phase::Complete
                        if self.phase != Phase::Running
                            || self.pending.is_some()
                            || self.interrupted_run
                            || !self
                                .indexes
                                .complete(self.manifest.plan.index_sources().len())
                            || self.counts.accepted != self.manifest.plan.puts.len()
                            || !self.graph.complete(self.manifest.graph) =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::Failed
                        if matches!(
                            self.phase,
                            Phase::Ready | Phase::CancelRequested | Phase::Cancelled
                        ) =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::Uncertain
                        if (self.pending.is_none() && self.indexes.pending.is_none())
                            || matches!(
                                self.phase,
                                Phase::Ready | Phase::Cancelled | Phase::Complete
                            ) =>
                    {
                        return Err(ModelError::Transition);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
    /// Reserve only an affected small receipt index before its real append.
    pub fn prepare(&mut self, event: &Event<'_>) -> Result<(), ModelError> {
        self.check(event)?;
        if let Event::Index(event) = event {
            self.indexes.prepare(event)?;
        }
        if matches!(event, Event::Accepted { .. }) {
            self.accepted
                .try_reserve(1)
                .map_err(|_| ModelError::Limit)?;
        }
        Ok(())
    }
    /// Apply the exact next complete record after full decoding and validation.
    pub fn apply(
        &mut self,
        sequence: u64,
        index: usize,
        kind: u16,
        bytes: &[u8],
    ) -> Result<(), ModelError> {
        if self.applied.checked_add(1) != Some(sequence)
            || u64::try_from(index).ok() != Some(self.applied)
        {
            return Err(ModelError::Order);
        }
        let event = codec::decode_event(kind, bytes)?;
        self.prepare(&event)?;
        let interruption = match &event {
            Event::Index(event) => event.interruption(),
            Event::Accepted { interruption, .. }
            | Event::NotApplied { interruption, .. }
            | Event::Refused { interruption, .. }
            | Event::Unknown { interruption, .. } => *interruption,
            _ => None,
        };
        if interruption.is_some() {
            self.interrupted_run = true;
        }
        match event {
            Event::Manifest(_) => return Err(ModelError::Transition),
            Event::Index(event) => self.indexes.apply(index, event)?,
            Event::GraphRecorded(fact) => self.graph.recorded = Some(fact),
            Event::Intent {
                index: row,
                request_hash,
            } => {
                self.pending = Some(Pending {
                    attempt: Attempt {
                        index: row,
                        request_hash,
                        intent_record: index,
                    },
                    disposition: Disposition::Intent,
                })
            }
            Event::Accepted {
                attempt,
                interruption,
                ..
            } => {
                let next = self.next_counts()?;
                self.accepted.push(AcceptedRef {
                    attempt,
                    record_index: index,
                    interruption,
                });
                self.counts = next;
                self.pending = None;
            }
            Event::NotApplied { .. } | Event::RetryRefused { .. } => self.pending = None,
            Event::Refused { interruption, .. } => {
                let pending = self.pending.as_mut().ok_or(ModelError::Binding)?;
                pending.disposition = Disposition::Refused {
                    record_index: index,
                    interruption,
                };
            }
            Event::Unknown {
                outcome,
                interruption,
                ..
            } => {
                let pending = self.pending.as_mut().ok_or(ModelError::Binding)?;
                pending.disposition = Disposition::Unknown {
                    record_index: index,
                    outcome,
                    interruption,
                };
            }
            Event::Phase { phase, .. } => {
                if matches!(phase, Phase::PauseRequested | Phase::CancelRequested) {
                    self.requested = Some(phase);
                }
                if matches!(phase, Phase::Running | Phase::Complete) {
                    self.requested = None;
                }
                if phase == Phase::Running {
                    self.interrupted_run = false;
                }
                self.phase = phase;
            }
        }
        self.applied = sequence;
        Ok(())
    }
    fn original(&self, attempt: Attempt) -> Result<(), ModelError> {
        if self
            .pending
            .is_none_or(|pending| pending.attempt != attempt)
            || attempt.index != self.counts.accepted
            || attempt.index >= self.manifest.plan.puts.len()
        {
            return Err(ModelError::Binding);
        }
        Ok(())
    }
    fn next_counts(&self) -> Result<Counts, ModelError> {
        let put = self
            .manifest
            .plan
            .puts
            .get(self.counts.accepted)
            .ok_or(ModelError::Order)?;
        Ok(Counts {
            accepted: self
                .counts
                .accepted
                .checked_add(1)
                .ok_or(ModelError::Limit)?,
            bytes: self
                .counts
                .bytes
                .checked_add(put.payload.bytes as u128)
                .ok_or(ModelError::Limit)?,
        })
    }
}
fn effect_phase(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::Running
            | Phase::PauseRequested
            | Phase::CancelRequested
            | Phase::Failed
            | Phase::Uncertain
            | Phase::Cancelled
    )
}
#[cfg(test)]
mod tests;
