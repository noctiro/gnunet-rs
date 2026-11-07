//! Actual task-origin namespace bookkeeping after the original native ACK.
use super::*;
use crate::namespace::graph::{self, Graph, Record, TaskPrepared, TaskReceipt};

/// Actual graph acceptance retained independently of the task WAL barrier.
/// Only the original graph owner constructs its private receipt.
#[derive(Debug)]
pub struct GraphResult {
    receipt: TaskReceipt,
    attempt: Attempt,
}
impl GraphResult {
    /// Actual original graph identity, record, body hash and append disposition.
    #[must_use]
    pub const fn receipt(&self) -> &TaskReceipt {
        &self.receipt
    }
    /// Original actual accepted namespace PUT that authorized this bookkeeping.
    #[must_use]
    pub const fn attempt(&self) -> Attempt {
        self.attempt
    }
    /// Admit only this original graph fact to the original task WAL. This does
    /// not write the graph or create a native operation.
    pub fn record(&self, task: &mut Task) -> Result<(), Cause> {
        if task.active {
            return Err(Cause::State("publication task already running"));
        }
        self.record_inner(&mut task.store, &mut task.state)
    }
    fn fact(&self) -> GraphRecorded {
        GraphRecorded {
            binding: self.receipt.binding(),
            origin: self.receipt.origin(),
            attempt: self.attempt,
            record_index: self.receipt.id().index(),
            body_hash: self.receipt.body_hash(),
        }
    }
    pub(super) fn record_inner(
        &self,
        store: &mut Store,
        state: &mut model::State,
    ) -> Result<(), Cause> {
        if self.receipt.origin() != *store.task_id() {
            return Err(Cause::State("graph receipt belongs to another task"));
        }
        let target = state
            .manifest
            .graph
            .ok_or(Cause::State("no tracked namespace graph"))?;
        let accepted = state
            .accepted
            .first()
            .ok_or(Cause::State("namespace PUT has no actual accepted reply"))?;
        if target.binding != self.receipt.binding()
            || accepted.attempt != self.attempt
            || state.accepted.len() != 1
            || state.counts.accepted != state.manifest.plan.puts.len()
            || state.pending.is_some()
            || state.indexes.pending.is_some()
        {
            return Err(Cause::State(
                "graph receipt differs from original accepted namespace publication",
            ));
        }
        let fact = self.fact();
        if let Some(recorded) = state.graph.recorded {
            if recorded == fact {
                return Ok(());
            }
            return Err(Cause::State(
                "graph receipt differs from recorded original effect",
            ));
        }
        append(store, state, model::Event::GraphRecorded(fact))
    }
}
/// Explicit graph-only reconciliation with fresh payload proof and original ACK
/// history. Cancellation can retain its terminal phase while settling history.
#[derive(Debug)]
pub struct GraphOutcome {
    /// Original and current-run facts; this operation never adds native ACKs.
    pub progress: Progress,
    /// Actual graph result, independent of a subsequent task WAL write.
    pub record: Option<GraphResult>,
    /// Fresh proof and complete original state; absent for caller stop/cancel.
    pub completed: Option<Completed>,
    /// Actual durable lifecycle after this invocation.
    pub phase: Phase,
}
pub(super) fn binding(state: &model::State, graph: &Graph) -> Result<(), Cause> {
    let plan::Artifact::Namespace { public, .. } = &state.manifest.plan.artifact else {
        return Err(Cause::State(
            "graph bookkeeping requires one namespace artifact",
        ));
    };
    if graph.namespace() != public
        || state
            .manifest
            .graph
            .is_some_and(|t| t.binding != graph.binding())
    {
        return Err(graph::Error::Binding.into());
    }
    Ok(())
}
pub(super) fn prepare(
    state: &model::State,
    origin: [u8; 32],
    graph: &mut Graph,
) -> Result<Option<TaskPrepared>, Cause> {
    binding(state, graph)?;
    let Some(target) = state.manifest.graph else {
        return Ok(None);
    };
    let plan::Artifact::Namespace {
        identifier,
        update,
        target_uri,
        metadata,
        ..
    } = &state.manifest.plan.artifact
    else {
        return Err(Cause::State("graph target has no namespace artifact"));
    };
    let uri = Uri::parse(target_uri, state.manifest.limits.ublock.uri)?;
    let prepared = graph.prepare_task(
        target.binding,
        origin,
        Record {
            identifier,
            update,
            uri,
            metadata: metadata.as_deref(),
        },
    )?;
    if let Some(fact) = state.graph.recorded {
        let original = graph
            .confirm_task(&prepared)?
            .ok_or(Cause::State("recorded original graph effect is missing"))?;
        if fact.binding != original.binding()
            || fact.origin != original.origin()
            || fact.record_index != original.id().index()
            || fact.body_hash != original.body_hash()
        {
            return Err(Cause::State(
                "actual graph differs from original task history",
            ));
        }
    }
    Ok(Some(prepared))
}
pub(super) fn commit(
    state: &model::State,
    graph: &mut Graph,
    prepared: &TaskPrepared,
) -> Result<GraphResult, Cause> {
    if state.counts.accepted != state.manifest.plan.puts.len()
        || state.accepted.len() != 1
        || state.pending.is_some()
        || state.indexes.pending.is_some()
    {
        return Err(Cause::State(
            "graph bookkeeping needs the complete original namespace ACK",
        ));
    }
    let receipt = graph.append_task_accepted(prepared)?;
    let attempt = state.accepted.first().ok_or(ProtocolError::Stale)?.attempt;
    let result = GraphResult { receipt, attempt };
    if state.graph.recorded.is_some_and(|old| old != result.fact()) {
        return Err(Cause::State(
            "actual graph receipt conflicts with original task history",
        ));
    }
    Ok(result)
}
pub(super) fn progress(
    state: &model::State,
    verified: bool,
    newly_recorded: bool,
) -> GraphProgress {
    GraphProgress {
        required: state.manifest.graph.is_some(),
        recorded: state.graph.recorded,
        verified,
        newly_recorded,
    }
}
fn local_progress(
    run: &runner::Run<'_>,
    payloads_verified: bool,
    verification: crate::Progress,
    verified: bool,
    newly: bool,
) -> Progress {
    Progress {
        historical: run.state.counts,
        recorded: run.state.counts,
        indexes: IndexProgress {
            historical: run.state.indexes.accepted.len(),
            recorded: run.state.indexes.accepted.len(),
            new_accepted: 0,
            total: run.state.manifest.plan.index_sources().len(),
            pending: run.state.indexes.pending,
        },
        graph: progress(run.state, verified, newly),
        total_puts: run.state.manifest.plan.puts.len(),
        payloads_verified,
        verification,
        pending: run.state.pending,
        state_records: run.store.record_count(),
        ..Progress::default()
    }
}
fn stopped(
    run: &mut runner::Run<'_>,
    wanted: &mut Option<Control>,
    decision: Control,
    cancelled: bool,
) -> Result<(), Cause> {
    if decision == Control::Continue {
        return Ok(());
    }
    *wanted = Some(decision);
    if cancelled {
        return Ok(());
    }
    let target = if decision == Control::Cancel {
        Phase::CancelRequested
    } else {
        Phase::PauseRequested
    };
    if run.state.phase != target {
        phase(run.store, run.state, target)?;
    }
    Ok(())
}
pub(super) fn record(
    run: &mut runner::Run<'_>,
    graph: &mut Graph,
    buffers: &mut Buffers,
    mut control: impl FnMut(Progress) -> Control,
    cancelled: bool,
) -> Result<GraphOutcome, Box<Failure>> {
    let mut verified = None;
    let mut graph_result = None;
    let mut graph_verified = false;
    let mut newly = false;
    let mut verification = crate::Progress::default();
    let mut wanted = None;
    let operation: Result<(), Cause> = (|| {
        let decision = control(local_progress(run, false, verification, false, false));
        stopped(run, &mut wanted, decision, cancelled)?;
        if wanted.is_some() {
            return Ok(());
        }
        let mut repo = Repository::open_child(run.store.directory(), OsStr::new("objects"))
            .map_err(plan::Error::Host)?;
        let proof =
            run.state
                .manifest
                .plan
                .verify(&mut repo, buffers, run.state.manifest.limits, |p| {
                    verification = p;
                    let decision = control(local_progress(run, false, p, false, false));
                    if decision == Control::Continue {
                        crate::Control::Continue
                    } else {
                        wanted = Some(decision);
                        crate::Control::Cancel
                    }
                });
        if let Some(decision) = wanted {
            stopped(run, &mut wanted, decision, cancelled)?;
        }
        match proof {
            Ok(proof) => verified = Some(proof),
            Err(plan::Error::Host(crate::Error::Cancelled)) if wanted.is_some() => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let mut body = Vec::new();
        let mut wire = Vec::new();
        runner::verify_history(run.store, run.state, &mut repo, &mut body, &mut wire)?;
        if wanted.is_some() {
            return Ok(());
        }
        let prepared = prepare(run.state, *run.store.task_id(), graph)?;
        let decision = control(local_progress(run, true, verification, false, false));
        stopped(run, &mut wanted, decision, cancelled)?;
        if wanted.is_some() {
            return Ok(());
        }
        if let Some(prepared) = prepared {
            let actual = commit(run.state, graph, &prepared)?;
            newly = actual.receipt().newly_recorded();
            graph_verified = true;
            graph_result = Some(actual);
            // Report actual graph acceptance before the independent task WAL
            // barrier. Any stop/write failure keeps this original receipt.
            let decision = control(local_progress(run, true, verification, true, newly));
            stopped(run, &mut wanted, decision, cancelled)?;
            graph_result
                .as_ref()
                .ok_or(ProtocolError::Stale)?
                .record_inner(run.store, run.state)?;
        }
        Ok(())
    })();
    let mut cause = operation.err();
    if cause.is_none() {
        let target = if cancelled || wanted == Some(Control::Cancel) {
            Phase::Cancelled
        } else if wanted == Some(Control::Pause) {
            Phase::Paused
        } else {
            Phase::Complete
        };
        let result = if target == Phase::Cancelled && run.state.phase == Phase::Cancelled {
            Ok(())
        } else {
            phase(run.store, run.state, target)
        };
        match result {
            Ok(()) => {
                let progress =
                    local_progress(run, verified.is_some(), verification, graph_verified, newly);
                let completed = if target == Phase::Complete {
                    Some(Completed {
                        verified: verified.ok_or_else(|| {
                            empty_failure(Cause::State(
                                "complete graph bookkeeping lacks current payload proof",
                            ))
                        })?,
                        progress,
                    })
                } else {
                    None
                };
                return Ok(GraphOutcome {
                    progress,
                    record: graph_result,
                    completed,
                    phase: run.state.phase,
                });
            }
            Err(error) => cause = Some(error),
        }
    }
    let mut state_failure = None;
    if !run.store.fenced()
        && !matches!(run.state.phase, Phase::Cancelled | Phase::CancelRequested)
        && let Err(error) = phase(run.store, run.state, Phase::Failed)
    {
        state_failure = Some(error);
    }
    Err(Box::new(Failure {
        cause,
        native: None,
        index: None,
        graph: graph_result,
        cleanup: None,
        state_failure,
        progress: local_progress(run, verified.is_some(), verification, graph_verified, newly),
        requested_stop: wanted.map(|c| {
            if c == Control::Cancel {
                StopReason::Cancelled
            } else {
                StopReason::CallerPause
            }
        }),
    }))
}
