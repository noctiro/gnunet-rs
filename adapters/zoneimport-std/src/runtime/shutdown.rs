//! Clock-free physical retirement and original business debt settlement.
use super::*;
use crate::{LocalOutcome, SourceFailure};
impl<'id> Runtime<'id> {
    pub(super) fn local_outcome(&mut self, fact: LocalOutcome) {
        if let Some(slot) = self
            .report
            .local_outcomes
            .iter_mut()
            .find(|slot| slot.is_none())
        {
            *slot = Some(fact);
        } else {
            self.report.additional_local_outcomes =
                self.report.additional_local_outcomes.saturating_add(1);
        }
    }
    pub(super) fn source_error(&mut self, error: SourceFailure) {
        if let Some(slot) = self
            .report
            .source_errors
            .iter_mut()
            .find(|slot| slot.is_none())
        {
            *slot = Some(error);
        } else {
            self.report.additional_source_errors =
                self.report.additional_source_errors.saturating_add(1);
        }
    }
    pub(super) fn identity_loss(&mut self, loss: identity::Loss<'_>) {
        self.report.identity = Some(Loss {
            epoch: loss.epoch.map(|epoch| epoch.diagnostic()),
            operations: loss.operations,
            exposed: loss.exposed,
        });
    }
    pub(super) fn ns_loss(&mut self, loss: namestore::Loss<'_>) {
        self.report.namestore = Some(Loss {
            epoch: loss.epoch.map(|epoch| epoch.diagnostic()),
            operations: loss.operations,
            exposed: loss.exposed,
        });
    }
    pub(super) fn scan_closed(&mut self, scan: &mut Scan<'_>) {
        if !scan.closed {
            scan.closed = true;
            self.report.iterators_closed = self.report.iterators_closed.saturating_add(1);
        }
        if let Some(loss) = scan.iterator.take_close_report()
            && loss
                .control
                .is_some_and(|control| !matches!(control.submission, namestore::Submission::Unsent))
        {
            self.report.iterator_controls_exposed =
                self.report.iterator_controls_exposed.saturating_add(1);
        }
    }
    /// Permanently stop admission and physically close the same actual sources.
    /// Original local terminal observations remain owned and must be polled;
    /// this method grants neither remote rollback nor a successful join.
    pub fn begin_close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.initial = None;
        // Core latches earlier business failures before cancellation changes
        // pending phases, and retains later real terminal service rejections.
        self.core.stop();
        if let Some(client) = &mut self.identity {
            if let Some(loss) = client.close() {
                self.identity_loss(loss);
            }
        } else {
            self.identity_closed = true;
        }
        if let Some(client) = &mut self.namestore {
            if let Some(loss) = client.close() {
                self.ns_loss(loss);
            }
        } else {
            self.namestore_closed = true;
        }
        if !self.stopped_dns {
            self.report.dns = Some(self.dns.stop());
            self.stopped_dns = true;
        }
        for row in self.pending.iter_mut().flatten() {
            match &mut row.native {
                Native::Scan(scan) => {
                    let _original_loss = scan.iterator.close();
                }
                Native::Query(query) => {
                    query.request = None;
                    if let Some(mut tcp) = query.tcp.take() {
                        let _original = tcp.cancel();
                        self.report.tcp_closed = self.report.tcp_closed.saturating_add(1);
                    }
                }
                _ => {}
            }
        }
        if let Some(waker) = self.waiting.take() {
            waker.wake();
        }
    }
    pub(super) fn retire_action(
        &mut self,
        job: JobId,
        kind: Kind,
        admitted: bool,
        _observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let index = self
            .pending
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|row| row.job == job));
        let Some(index) = index else {
            // A pure action can expire or be stopped before its port admitted it.
            // Only the original Core fact permits this zero-native retirement.
            if admitted {
                return Err(Fault::StaleGeneration.into());
            }
            self.core.retirement_started(&job)?;
            let result = self.core.retired(&job, core::Retirement::Unsent)?;
            return self.release(result);
        };
        let row = self.pending[index].as_mut().ok_or(Fault::StaleGeneration)?;
        if row.kind != kind {
            return Err(Fault::StaleGeneration.into());
        }
        if row.retiring {
            return Ok(());
        }
        let immediate = match &mut row.native {
            Native::Deferred => true,
            Native::Query(query) => {
                if let Some(request) = query.request.take() {
                    self.dns.resolve_cancel(request)?;
                }
                if let Some(mut tcp) = query.tcp.take() {
                    let _original = tcp.cancel();
                    self.report.tcp_closed = self.report.tcp_closed.saturating_add(1);
                }
                true
            }
            Native::Scan(scan) => {
                let _original_loss = scan.iterator.close();
                false
            }
            Native::Create { operation, .. } => {
                let _actual = self
                    .identity
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .cancel(*operation)
                    .map_err(Error::Identity)?;
                false
            }
            Native::Check { operation, .. }
            | Native::Delegate { operation }
            | Native::Store { operation, .. } => {
                let _actual = self
                    .namestore
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .cancel(*operation)?;
                false
            }
            Native::Settled => {
                // The original native terminal failed Core application earlier.
                // Suppress only this repeated pure retirement selection; keep
                // its original row and the nonquiescent report for the caller.
                // Defer grants no completion, result or physical cancellation.
                self.stalled = true;
                self.core.defer(&job)?;
                row.retiring = true;
                return Ok(());
            }
        };
        // No native cause or positive prefix is erased by this Core observation.
        self.core.retirement_started(&job)?;
        self.pending[index]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .retiring = true;
        if immediate {
            let result = self.core.retired(&job, core::Retirement::Unsent);
            let original = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
            self.finish_row(index, original, result)?;
        }
        Ok(())
    }
    pub(super) fn finish_row(
        &mut self,
        index: usize,
        mut row: Pending<'id>,
        result: Result<core::Completion, Fault>,
    ) -> Result<(), Error> {
        match result {
            Ok(completion) => {
                self.release(completion)?;
                if !matches!(row.native, Native::Deferred) {
                    self.report.completed = self.report.completed.saturating_add(1);
                }
                if !self.closing {
                    self.resume_deferred()?;
                }
                Ok(())
            }
            Err(error) => {
                // A real terminal was consumed already. Never poll/replay it or
                // fabricate another Core receipt after a partially applied error.
                row.native = Native::Settled;
                self.pending[index] = Some(row);
                self.stalled = true;
                Err(error.into())
            }
        }
    }
    pub(super) fn evicted(
        &mut self,
        request: RequestId,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let Some(index) = self.pending.iter().position(|slot| {
            slot.as_ref().is_some_and(
                |row| matches!(&row.native, Native::Query(query) if query.request == Some(request)),
            )
        }) else {
            return Err(Fault::StaleGeneration.into());
        };
        let row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
        // DNSSTUB's real Admission.evicted has already retired this exact raw
        // request; the old read result cannot be rebound to the new allocation.
        let result = if row.retiring {
            self.core.retired(&row.job, core::Retirement::Unsent)
        } else {
            self.core.dns_failed(&row.job, core::ReadFailure::Source)
        };
        observe(Event::ReadFailed {
            job: row.job.diagnostic(),
            reason: core::ReadFailure::Source,
        });
        self.metrics.add(6, 1);
        self.finish_row(index, row, result)
    }
    /// Drain original local terminal observations after physical close, without
    /// consulting canonical time. Errors retain their owner and may be followed
    /// by further cleanup polls; a stalled invariant never becomes fake Closed.
    pub fn poll_close(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Poll<Result<Progress, Error>> {
        self.begin_close();
        self.waiting = Some(cx.waker().clone());
        // Each call gives at most one actual callback to the observer.
        match self.poll_owned(cx, observe, true) {
            Ok(true) => return Poll::Ready(Ok(Progress::Activity)),
            Err(error) => return Poll::Ready(Err(error)),
            Ok(false) => {}
        }
        match self.core.next_retirement() {
            Err(error) => return Poll::Ready(Err(error.into())),
            Ok(Some(action)) => {
                let job = action.job;
                let core::ActionKind::Retire { kind, admitted } = action.kind else {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                };
                if let Err(error) = self.retire_action(job, kind, admitted, observe) {
                    return Poll::Ready(Err(error));
                }
                cx.waker().wake_by_ref();
                return Poll::Ready(Ok(Progress::Activity));
            }
            Ok(None) => {}
        }
        self.report.core_quiescent = self.core.quiescent();
        self.report.payloads_remaining = self.answers.iter().flatten().count();
        if self.identity_closed
            && self.namestore_closed
            && self.pending.iter().all(Option::is_none)
            && self.report.core_quiescent
            && self.report.payloads_remaining == 0
        {
            self.keys.clear();
            return Poll::Ready(Ok(Progress::Closed));
        }
        Poll::Pending
    }
}
