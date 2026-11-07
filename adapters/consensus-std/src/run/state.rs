//! Actual original IPC/PILS/SET cooperative state; no spawned task or private RPC.
use super::{Control, Wait, check, pils_cause, poll_pils};
use crate::{
    Bounds, Bridge, Error, Progress, ServerLimits, SessionReport,
    core::{self, Completion, EffectId, PayloadValidation, Validator},
};
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::{
    clock::RuntimeClock,
    framing::{Class, Framed, OwnedFrame, ReadStep},
};
use gnunet_set_client_host as set;
use gnunet_types::Error as Fault;
use gnunet_wire::official::consensus::ClientRequest;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
struct PublicOpaque;
impl Validator for PublicOpaque {
    fn check(&mut self, _: u16, _: &[u8], _: u64) -> Result<PayloadValidation, Fault> {
        Ok(PayloadValidation::Opaque)
    }
}
struct Output<'id> {
    effect: EffectId<'id>,
    bytes: Option<Vec<u8>>,
    length: usize,
    written: usize,
    queued: bool,
    whole: bool,
}
pub(super) struct Admission<'pils, 'a> {
    pub clock: Arc<dyn RuntimeClock>,
    pub limits: ServerLimits,
    pub original: Bounds,
    pub control: &'a Control,
    pub identity: gnunet_pils::client::Identity<'pils>,
}
pub(super) struct State<'id, 'pils, 'a> {
    io: Framed<()>,
    bridge: Bridge<'id, 'pils>,
    pils: &'a mut pils::Client<'pils, 1>,
    clock: Arc<dyn RuntimeClock>,
    limits: ServerLimits,
    original: Bounds,
    control: &'a Control,
    identity: gnunet_pils::client::Identity<'pils>,
    report: SessionReport,
    wait: Option<Wait>,
    partial: Option<Wait>,
    input_bytes: usize,
    held_now: Option<u64>,
    output: Option<Output<'id>>,
    class: usize,
    ipc_closed: bool,
    pils_closed: bool,
    cleanup_until: Option<Instant>,
    policy: PublicOpaque,
}
impl<'id, 'pils, 'a> State<'id, 'pils, 'a> {
    pub fn new(
        io: Framed<()>,
        bridge: Bridge<'id, 'pils>,
        pils: &'a mut pils::Client<'pils, 1>,
        admission: Admission<'pils, 'a>,
        mut report: SessionReport,
    ) -> Self {
        let Admission {
            clock,
            limits,
            original,
            control,
            identity,
        } = admission;
        let wait = match Wait::new(clock.clone(), original) {
            Ok(wait) => Some(wait),
            Err(error) => {
                report.primary.get_or_insert(error);
                None
            }
        };
        Self {
            io,
            bridge,
            pils,
            clock,
            limits,
            original,
            control,
            identity,
            report,
            wait,
            partial: None,
            input_bytes: 0,
            held_now: None,
            output: None,
            class: 0,
            ipc_closed: false,
            pils_closed: false,
            cleanup_until: None,
            policy: PublicOpaque,
        }
    }
    fn fail(&mut self, error: Error) {
        if self.bridge.session().outcome().client_done_written {
            self.report.cleanup.get_or_insert(error);
        } else {
            self.report.primary.get_or_insert(error);
        }
    }
    fn guard(&self) -> Result<u64, Error> {
        if self
            .partial
            .as_ref()
            .is_some_and(|wait| Instant::now() >= wait.bounds.hard)
        {
            return Err(Fault::Deadline.into());
        }
        let now = check(self.clock.as_ref(), self.original, self.control)?;
        if self
            .partial
            .as_ref()
            .is_some_and(|wait| Instant::now() >= wait.bounds.hard || now >= wait.bounds.expires)
        {
            return Err(Fault::Deadline.into());
        }
        let original = self.report.local_peer.ok_or(Fault::NotReady)?;
        let current = self.pils.identity().ok_or(Fault::Unavailable)?;
        if current.epoch() != self.identity.epoch()
            || *current.peer().as_bytes() != original
            || current.expiration().as_micros() <= now
        {
            return Err(Fault::Unavailable.into());
        }
        if Instant::now() >= self.original.hard {
            return Err(Fault::Deadline.into());
        }
        Ok(now)
    }
    fn terminal(&mut self, terminal: core::Terminal<'id>) {
        match terminal.completion {
            Completion::Written => self.report.written = self.report.written.saturating_add(1),
            Completion::Unsent(_) => self.report.unsent = self.report.unsent.saturating_add(1),
            Completion::Lost(_) => self.report.lost = self.report.lost.saturating_add(1),
            Completion::Retired => self.report.retired = self.report.retired.saturating_add(1),
        }
    }
    fn store_loss(&mut self, loss: set::SetLoss) {
        self.report.sources_retired = self.report.sources_retired.saturating_add(1);
        self.report.retired_input_bytes = self
            .report
            .retired_input_bytes
            .saturating_add(loss.transport.partial_input);
        let important = !matches!(loss.cause, set::Cause::Requested)
            || !loss.operations.is_empty()
            || !loss.mutations.is_empty()
            || loss.iteration.is_some()
            || loss.copy.is_some();
        if !important {
            return;
        }
        if self.report.set_losses.len() < self.report.set_losses.capacity() {
            self.report.set_losses.push(loss);
        } else if self.report.extra_set_loss.is_none() {
            self.report.extra_set_loss = Some(loss);
            self.report.undrained = self.report.undrained.saturating_add(1);
            self.fail(Fault::Capacity.into());
        } else {
            self.report.undrained = self.report.undrained.saturating_add(1);
            self.fail(Fault::Capacity.into());
        }
        // Keep room for every currently live source after a global close. No
        // additional phase IO is started once normal retained diagnostics fill.
        if self.report.set_losses.len() >= self.limits.bridge.core.sets
            && self.cleanup_until.is_none()
        {
            self.fail(Fault::Capacity.into());
        }
    }
    fn observe(&mut self, progress: Progress<'id>) -> Result<(), Error> {
        match progress {
            Progress::Activity => {}
            Progress::Terminal(terminal) => self.terminal(terminal),
            Progress::OperationBound { .. } => {
                self.report.operations_bound = self.report.operations_bound.saturating_add(1)
            }
            Progress::SourceRefused { refusal, .. } => {
                self.report.record_source_refusal(refusal);
            }
            Progress::Fault(error) => self.fail(error),
            Progress::TaskFault { .. } => {}
            Progress::Rejected { cause, .. } => {
                self.report.rejected_offers = self.report.rejected_offers.saturating_add(1);
                self.report.first_rejection.get_or_insert(cause);
            }
            Progress::Offer { .. } => {}
            Progress::Set { event, .. } => match event {
                set::SetProgress::Lost(loss) => self.store_loss(loss),
                set::SetProgress::Retry(error) => {
                    self.report.connect_retries = self.report.connect_retries.saturating_add(1);
                    self.report.last_retry = Some(error);
                }
                set::SetProgress::Result { status, .. } => match status {
                    set::Status::Done => {
                        self.report.set_done = self.report.set_done.saturating_add(1)
                    }
                    set::Status::Failure => {
                        self.report.set_failed = self.report.set_failed.saturating_add(1)
                    }
                    set::Status::HalfDone => {
                        self.report.set_half_done = self.report.set_half_done.saturating_add(1)
                    }
                    _ => {}
                },
                _ => {}
            },
            Progress::Listener(event) => match event {
                set::ListenProgress::Lost(loss) => {
                    if self.report.listener_loss.is_none() {
                        self.report.listener_loss = Some(loss);
                    } else if self.report.listener_cleanup.is_none() {
                        self.report.listener_cleanup = Some(loss);
                    } else {
                        self.report.undrained = self.report.undrained.saturating_add(1);
                        self.fail(Fault::Capacity.into());
                    }
                }
                set::ListenProgress::Retry(error) => {
                    self.report.connect_retries = self.report.connect_retries.saturating_add(1);
                    self.report.last_retry = Some(error);
                }
                _ => {}
            },
            Progress::Cancelled { .. } => {}
            Progress::ClientFrame { effect, bytes } => {
                if self.output.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let length = bytes.len();
                self.output = Some(Output {
                    effect,
                    bytes: Some(bytes),
                    length,
                    written: 0,
                    queued: false,
                    whole: false,
                });
            }
            Progress::CloseClient { effect, .. } => {
                self.io.retire();
                self.ipc_closed = true;
                let terminal = self.bridge.complete_client(effect, Completion::Retired)?;
                self.terminal(terminal);
            }
            Progress::Stopped(outcome) => {
                self.report.outcome = Some(outcome);
            }
        }
        Ok(())
    }
    fn poll_identity(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.pils_closed {
            return Ok(false);
        }
        // Native/control first: a fallible PILS provider may not start after the
        // original hard. It is then checked again before any IPC/SET turn.
        check(self.clock.as_ref(), self.original, self.control)?;
        if Instant::now() >= self.original.hard {
            return Err(Fault::Deadline.into());
        }
        let progress = match poll_pils(self.pils, cx, self.original.hard) {
            Poll::Pending => return Ok(false),
            Poll::Ready(Err(error)) => return Err(error.into()),
            Poll::Ready(Ok(progress)) => progress,
        };
        match progress {
            pils::Progress::Lost { cause, report, .. } => {
                let why = pils_cause(&cause);
                self.report.pils_loss_retained = report.retained();
                self.report.pils_loss_feeds = report.feeds().count();
                self.report.pils_loss = Some(cause);
                return Err(why.into());
            }
            pils::Progress::Unavailable(error) => return Err(error.into()),
            pils::Progress::ConnectRetry { error, .. } => {
                self.report.connect_retries = self.report.connect_retries.saturating_add(1);
                self.report.last_retry = Some(error);
            }
            pils::Progress::WaitDeadline => return Err(Fault::Deadline.into()),
            pils::Progress::Closed => return Err(Fault::Closed.into()),
            _ => {}
        }
        self.guard()?;
        Ok(true)
    }
    fn input(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.ipc_closed {
            return Ok(false);
        }
        let now = self.guard()?;
        if let Some(bytes) = self.io.frame() {
            let origin = *self.held_now.get_or_insert(now);
            let result = match ClientRequest::decode(bytes)? {
                ClientRequest::Insert { element_type, data } => {
                    self.bridge
                        .insert(element_type, data, origin, &mut self.policy)
                }
                ClientRequest::Conclude => self.bridge.conclude(origin),
                ClientRequest::Join(_) => Err(Fault::Malformed.into()),
            };
            match result {
                Ok(()) => {}
                Err(Error::Protocol(Fault::WouldBlock | Fault::NotReady)) => return Ok(false),
                Err(error) => return Err(error),
            }
            self.io.release_frame();
            self.partial = None;
            self.held_now = None;
            self.input_bytes = 0;
            return Ok(true);
        }
        if let Some(wait) = &mut self.partial {
            wait.poll(cx)?;
        }
        // The shared check/provider above can spend real time; no fresh syscall
        // is allowed after its unchanged native hard or known source loss.
        self.guard()?;
        let before = Instant::now();
        match self.io.poll_read(cx) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                if self.bridge.session().outcome().client_done_written {
                    self.ipc_closed = true;
                    self.io.retire();
                    Ok(true)
                } else {
                    Err(Fault::Closed.into())
                }
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                self.input_bytes = self.input_bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
                if bytes != 0 && self.partial.is_none() {
                    let now = self.clock.sample()?.now.as_micros();
                    let micros = u64::try_from(self.limits.partial_input.as_micros())
                        .map_err(|_| Fault::Overflow)?;
                    let expires = now
                        .checked_add(micros)
                        .ok_or(Fault::Overflow)?
                        .min(self.original.expires);
                    let hard = before
                        .checked_add(self.limits.partial_input)
                        .ok_or(Fault::Overflow)?
                        .min(self.original.hard);
                    self.partial = Some(Wait::new(self.clock.clone(), Bounds { expires, hard })?);
                }
                Ok(true)
            }
        }
    }
    fn output(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let Some(output) = self.output.as_ref() else {
            return Ok(false);
        };
        self.guard()?;
        if !self.bridge.session().effect_io_allowed(output.effect) {
            return Err(Fault::Cancelled.into());
        }
        let output = self.output.as_mut().ok_or(Fault::NotReady)?;
        if !output.queued {
            let bytes = output.bytes.take().ok_or(Fault::NotReady)?;
            self.io.reserve(bytes.len(), Class::Ordinary)?;
            self.io
                .enqueue_owned(OwnedFrame::new(bytes), (), Class::Ordinary)
                .map_err(|error| error.reason)?;
            output.queued = true;
        }
        // Exact original gates immediately before every write syscall. The
        // framing cursor and original effect remain paired through retirement.
        self.guard()?;
        let id = self.output.as_ref().ok_or(Fault::NotReady)?.effect;
        if !self.bridge.session().effect_io_allowed(id) {
            return Err(Fault::Cancelled.into());
        }
        let step = match self.io.poll_write(cx) {
            Poll::Pending => return Ok(false),
            Poll::Ready(result) => result?,
        };
        let output = self.output.as_mut().ok_or(Fault::NotReady)?;
        // Preserve the physical whole fact even if later summary bookkeeping
        // refuses a counter or the core completion returns an error.
        output.whole = step.complete;
        output.written = output
            .written
            .checked_add(step.bytes)
            .ok_or(Fault::Overflow)?;
        self.report.client_bytes = self
            .report
            .client_bytes
            .checked_add(step.bytes)
            .ok_or(Fault::Overflow)?;
        if output.written > output.length {
            return Err(Fault::Conflict.into());
        }
        if step.complete {
            output.whole = true;
            // Record the real whole-write before later EOF/deadline handling.
            let terminal = self
                .bridge
                .complete_client(output.effect, Completion::Written)?;
            self.output = None;
            self.terminal(terminal);
        }
        if Instant::now() >= self.original.hard {
            return Err(Fault::Deadline.into());
        }
        Ok(true)
    }
    fn close_output(&mut self) {
        self.io.retire();
        self.ipc_closed = true;
        if let Some(output) = &self.output {
            self.report.pending_output_bytes = output.written;
            self.report.pending_output_whole = output.whole;
            let why = self.report.primary.as_ref().map_or_else(
                || {
                    self.bridge
                        .session()
                        .outcome()
                        .failure
                        .map_or(Fault::Cancelled, |f| f.cause)
                },
                Error::classified,
            );
            let completion = if output.whole {
                Completion::Written
            } else if output.written == 0 {
                Completion::Unsent(why)
            } else {
                Completion::Lost(why)
            };
            match self.bridge.complete_client(output.effect, completion) {
                Ok(terminal) => {
                    self.output = None;
                    self.terminal(terminal);
                    self.report.pending_output_bytes = 0;
                    self.report.pending_output_whole = false;
                }
                Err(error) => {
                    self.report.cleanup.get_or_insert(error);
                }
            }
        }
    }
    fn stop_physical(&mut self) {
        if self.cleanup_until.is_some() {
            return;
        }
        let start = Instant::now();
        self.cleanup_until.get_or_insert_with(|| {
            start
                .checked_add(self.limits.retirement_grace)
                .unwrap_or(start)
        });
        self.wait = None;
        self.partial = None;
        let why = self.report.primary.as_ref().map_or_else(
            || {
                self.control
                    .reason()
                    .or_else(|| self.bridge.session().outcome().failure.map(|f| f.cause))
                    .unwrap_or(Fault::Cancelled)
            },
            Error::classified,
        );
        if let Err(error) = self.bridge.cancel(why) {
            self.report.cleanup.get_or_insert(error);
        }
        self.close_output();
        if let Err(error) = self.bridge.retire_sources() {
            self.report.cleanup.get_or_insert(error);
        }
        if !self.pils_closed {
            self.report.pils_pending = self.pils.close().iter().flatten().count();
            self.pils_closed = true;
        }
    }
    fn close_poll(&mut self, cx: &mut Context<'_>) -> Poll<SessionReport> {
        if self.cleanup_until.is_none() {
            self.stop_physical();
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(self.cleanup(cx))
    }
    fn cleanup(&mut self, cx: &mut Context<'_>) -> SessionReport {
        self.stop_physical();
        let until = self.cleanup_until.unwrap_or_else(Instant::now);
        while Instant::now() < until {
            match self.bridge.poll_retirement(cx, &mut self.policy) {
                Poll::Ready(Ok(progress)) => {
                    if let Err(error) = self.observe(progress) {
                        self.report.cleanup.get_or_insert(error);
                        break;
                    }
                    if self.bridge.is_quiescent() {
                        break;
                    }
                }
                Poll::Ready(Err(error)) => {
                    self.report.cleanup.get_or_insert(error);
                    break;
                }
                Poll::Pending => break,
            }
        }
        let drained = self.bridge.is_quiescent();
        if !drained {
            self.report.undrained = self.report.undrained.saturating_add(1);
            self.report
                .cleanup
                .get_or_insert_with(|| Fault::NotReady.into());
        }
        // On bounded incomplete bookkeeping, retain original native receipts
        // after physical close; taking a list never upgrades logical drainage.
        loop {
            match self.bridge.take_retired_loss() {
                Ok(Some(loss)) => self.store_loss(loss),
                Ok(None) => break,
                Err(error) => {
                    self.report.cleanup.get_or_insert(error);
                    break;
                }
            }
        }
        if let Some(refusal) = self.bridge.take_source_refusal() {
            self.report.record_source_refusal(refusal);
        }
        self.report.outcome = Some(self.bridge.session().outcome());
        self.report.task_failures = Some(self.bridge.session().task_failures());
        self.report.failure_context = self.bridge.session().failure_context();
        self.report.first_source_loss = self.bridge.first_source_loss();
        self.report.retired_input_bytes = self
            .report
            .retired_input_bytes
            .saturating_add(self.input_bytes);
        self.input_bytes = 0;
        self.report.physical_closed =
            self.ipc_closed && self.pils_closed && self.bridge.physical_retired();
        std::mem::take(&mut self.report)
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<SessionReport> {
        if self.control.reason().is_some()
            || self.report.primary.is_some()
            || self.report.cleanup.is_some()
            || self.ipc_closed
            || self.bridge.is_quiescent()
            || self.bridge.session().outcome().failure.is_some()
            || self.bridge.session().outcome().client_done_written
        {
            return self.close_poll(cx);
        }
        if let Err(error) = self.guard() {
            self.fail(error);
            return self.close_poll(cx);
        }
        if let Some(wait) = &mut self.wait
            && let Err(error) = wait.poll(cx)
        {
            self.fail(error);
            return self.close_poll(cx);
        }
        let pils_progress = match self.poll_identity(cx) {
            Ok(progress) => progress,
            Err(error) => {
                self.fail(error);
                return self.close_poll(cx);
            }
        };
        // A real PILS provider above may consume the old hard; key/source changes
        // and cancellation are observed before every subsequent new IO class.
        if let Err(error) = self.guard() {
            self.fail(error);
            return self.close_poll(cx);
        }
        for _ in 0..3 {
            if let Err(error) = self.guard() {
                self.fail(error);
                return self.close_poll(cx);
            }
            let class = self.class;
            self.class = (self.class + 1) % 3;
            let result = match class {
                0 => self.output(cx),
                1 => self.input(cx),
                _ => {
                    let current = self.pils.identity();
                    match self.bridge.poll_progress(cx, current, &mut self.policy) {
                        Poll::Pending => Ok(false),
                        Poll::Ready(Err(error)) => Err(error),
                        Poll::Ready(Ok(progress)) => self.observe(progress).map(|()| true),
                    }
                }
            };
            match result {
                Err(error) => {
                    self.fail(error);
                    return self.close_poll(cx);
                }
                Ok(true) => {
                    if self.report.primary.is_some()
                        || self.report.cleanup.is_some()
                        || self.ipc_closed
                        || self.bridge.is_quiescent()
                        || self.bridge.session().outcome().failure.is_some()
                        || self.bridge.session().outcome().client_done_written
                    {
                        return self.close_poll(cx);
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Ok(false) => {}
            }
        }
        if pils_progress {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}
