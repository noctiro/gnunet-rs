//! Actual fair consumers of the one Actor/Bridge/Scheduler. This struct keeps
//! only cursors; every source, pool, loan, entropy port and worker stays outside.
use crate::{
    Failure,
    dv_control::{Receipts, Service, Turn},
    dv_schedule::{self, Scheduler},
    generation::Reservations,
    owner::{Owner, TransportContext, TransportWork},
    sender::DvScope,
};
use gnunet_crypto::Entropy;
use gnunet_transport_dv_bridge_host::{self as bridge, Actor, Bridge};
use gnunet_transport_dv_runtime_host as actor;
use gnunet_transport_host::dv_bridge::Ports;
use gnunet_types::Error;
use std::task::{Context, Poll};
/// A real process request or actual source transition, not remote completion.
pub(crate) enum Signal {
    Activity,
    Stop,
    Rebuild,
}
pub(crate) struct Driver {
    reports: crate::foreground::Reports,
    classes: ClassScan,
    input: usize,
    output: usize,
    quantum: usize,
    cleanup: Vec<Failure>,
}
/// A clipped poll retains which of the seven actual consumers still need
/// inspection. Only new local work starts another pass; a complete idle pass
/// stops self-waking and leaves the registered external sources in charge.
#[derive(Default)]
struct ClassScan {
    next: usize,
    remaining: usize,
}
impl ClassScan {
    fn begin_pass(&mut self) {
        if self.remaining == 0 {
            self.local_work();
        }
    }
    fn local_work(&mut self) {
        self.remaining = 7;
    }
    fn take_class(&mut self) -> Option<usize> {
        if self.remaining == 0 {
            return None;
        }
        let class = self.next;
        self.next = (self.next + 1) % 7;
        self.remaining -= 1;
        Some(class)
    }
    fn retain_children(&mut self, pending: bool) {
        if pending {
            self.local_work();
        }
    }
    fn needs_pass(&self) -> bool {
        self.remaining != 0
    }
}
/// Visit each original metadata slot at most once. A temporary refusal is not
/// progress and cannot hide a later independently actionable original owner.
fn scan_inputs<E>(
    cursor: &mut usize,
    count: usize,
    mut visit: impl FnMut(usize) -> Result<bool, E>,
) -> Result<bool, E> {
    if count == 0 {
        return Ok(false);
    }
    let mut index = *cursor % count;
    for _ in 0..count {
        *cursor = (index + 1) % count;
        if visit(index)? {
            return Ok(true);
        }
        index = *cursor;
    }
    Ok(false)
}

impl Driver {
    pub(crate) fn new(quantum: usize, reports: crate::foreground::Reports) -> Result<Self, Error> {
        if quantum == 0 {
            return Err(Error::InvalidInput);
        }
        let mut cleanup = Vec::new();
        cleanup.try_reserve_exact(8).map_err(|_| Error::Capacity)?;
        Ok(Self {
            reports,
            classes: ClassScan::default(),
            input: 0,
            output: 0,
            quantum,
            cleanup,
        })
    }
    pub(crate) fn take_cleanup(&mut self) -> Vec<Failure> {
        std::mem::take(&mut self.cleanup)
    }
    pub(crate) fn retirements<'owner, E: Entropy>(
        &self,
        owner: &mut Owner<'owner, E>,
        scope: &DvScope<'owner>,
    ) {
        if let Ok(server) = owner.dv_server(scope)
            && let Some(original) = server.take_native_retirement()
        {
            self.reports
                .observe(crate::owner::Event::NativeRetired(original));
        }
    }
    pub(crate) fn receipts<'id, 'source, 'pils, 'slots, 'out, 'owner, E: Entropy>(
        actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out>,
        owner: &Owner<'owner, E>,
        scheduler: &mut Scheduler<'id, 'pils, 'owner>,
        notes: &mut Receipts<'owner>,
    ) -> Result<(), Failure> {
        while let Some(event) = notes.pop() {
            let mut original = Some(event);
            if let Some(event) = scheduler.observe_owner(actor, owner, &mut original) {
                observe_schedule(&notes.reports, event, actor.is_closed())?;
            }
            if let Some(original) = original {
                notes.reports.observe(original);
            }
        }
        Ok(())
    }
    /// Single actual native observer seam. No Owner/Scheduler reborrow occurs
    /// while Owner lends its disjoint native/signing/entropy/store fields.
    pub(crate) fn native<'id, 'source, 'pils, 'slots, 'out, 'owner, E: Entropy>(
        bridge: &mut Bridge<'id>,
        actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out>,
        cx: &mut Context<'_>,
        context: TransportContext<'_, 'owner, E>,
    ) -> Poll<Result<gnunet_transport_host::Step, Failure>> {
        let actual = match context.work {
            TransportWork::Step => bridge.poll_server(
                context.server,
                actor,
                cx,
                None,
                context.times,
                Ports {
                    signer: context.signer,
                    entropy: context.entropy,
                    store: context.store,
                },
            ),
            TransportWork::Tick => bridge.poll_tick(
                context.server,
                actor,
                cx,
                context.times,
                context.entropy,
                context.store,
            ),
            TransportWork::Retry => bridge.poll_retry(
                context.server,
                actor,
                cx,
                context.times,
                context.entropy,
                context.store,
            ),
        };
        actual.map(|result| result.map_err(|error| Box::new(error) as Failure))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Disjoint actual caller-owned ports; no self-reference or hidden provider tasks"
    )]
    pub(crate) fn poll<'id, 'source, 'pils, 'slots, 'out, 'owner, E: Entropy, P: Entropy>(
        &mut self,
        cx: &mut Context<'_>,
        service: &mut Service<'_, '_, '_>,
        owner: &mut Owner<'owner, E>,
        actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out>,
        bridge: &mut Bridge<'id>,
        scheduler: &mut Scheduler<'id, 'pils, 'owner>,
        transmit: &mut crate::dv_transmit::Transmit<'id>,
        scope: &DvScope<'owner>,
        reservations: &mut Reservations,
        entropy: &mut P,
        notes: &mut Receipts<'owner>,
    ) -> Poll<Result<Signal, Failure>> {
        let control = {
            let mut native = |cx: &mut Context<'_>, context: TransportContext<'_, 'owner, E>| {
                Self::native(bridge, actor, cx, context)
            };
            service.poll(cx, owner, reservations, notes, &mut native)
        };
        if matches!(&control, Poll::Ready(Err(_)) | Poll::Ready(Ok(Turn::Stop))) {
            scheduler.close(actor);
            actor.close();
            self.cleanup
                .extend(owner.stop(&mut |event| notes.observe(event)));
        } else if owner.dv_scope().as_ref() != Some(scope) {
            scheduler.close(actor);
            actor.close();
        }
        if let Err(original) = Self::receipts(actor, owner, scheduler, notes) {
            scheduler.close(actor);
            actor.close();
            self.cleanup
                .extend(owner.stop(&mut |event| notes.observe(event)));
            if let Poll::Ready(Err(first)) = control {
                self.cleanup.push(original);
                return Poll::Ready(Err(first));
            }
            return Poll::Ready(Err(original));
        }
        match control {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(Turn::Stop)) => return Poll::Ready(Ok(Signal::Stop)),
            _ => {}
        }
        if owner.dv_scope().as_ref() != Some(scope) || actor.is_closed() {
            return Poll::Ready(Ok(Signal::Rebuild));
        }
        self.classes.begin_pass();
        let mut changed = control.is_ready();
        if changed {
            self.classes.local_work();
        }
        for _ in 0..self.quantum {
            let Some(class) = self.classes.take_class() else {
                break;
            };
            let step = (|| -> Result<bool, Failure> {
                match class {
                    0 => {
                        let before = actor.neighbours().count();
                        let times = owner.dv_times(scope)?;
                        let server = owner.dv_server(scope)?;
                        match bridge.sync_neighbours(server, actor, times) {
                            Ok(()) => {}
                            Err(error) if temporary_bridge(&error) => return Ok(false),
                            Err(error) => return Err(Box::new(error)),
                        }
                        let paths_changed = match bridge.sync_paths(server, actor, times) {
                            Ok(changed) => changed,
                            Err(error) if temporary_bridge(&error) => return Ok(false),
                            Err(error) => return Err(Box::new(error)),
                        };
                        // Actual path publication may queue CORE/control work
                        // even when the number of direct neighbours is stable.
                        Ok(paths_changed || before != actor.neighbours().count())
                    }
                    1 => {
                        let times = owner.dv_times(scope)?;
                        let received =
                            match bridge.receive_one(owner.dv_server(scope)?, actor, times) {
                                Ok(received) => received,
                                // A just-read complete frame may reach this class
                                // before the next native Server turn stages it.
                                // Retain that original input; do not retire its MQ.
                                Err(error) if temporary_bridge(&error) => return Ok(false),
                                Err(error) => return Err(Box::new(error)),
                            };
                        match received {
                            bridge::Receive::Empty => Ok(false),
                            bridge::Receive::Admitted(_)
                            | bridge::Receive::Expired { .. }
                            | bridge::Receive::Discarded { .. } => Ok(true),
                            bridge::Receive::Deferred(actual) => {
                                if actual.disposition != actor::InputRefusalDisposition::Deferred {
                                    self.reports.diagnostic(format_args!(
                                        "TRANSPORT DV original input refusal: {}",
                                        actual.error
                                    ));
                                }
                                Ok(false)
                            }
                        }
                    }
                    2 => match scheduler.poll(
                        cx,
                        actor,
                        owner,
                        reservations,
                        entropy,
                        &mut |event| notes.observe(event),
                    ) {
                        Poll::Ready(Ok(event)) => {
                            observe_schedule(&notes.reports, event, actor.is_closed())?;
                            Ok(true)
                        }
                        Poll::Ready(Err(error)) => Err(error),
                        Poll::Pending => Ok(false),
                    },
                    3 => match transmit.drive(bridge, actor, owner, scheduler, scope, entropy)? {
                        crate::dv_transmit::Progress::Idle
                        | crate::dv_transmit::Progress::WaitingForRange => Ok(false),
                        crate::dv_transmit::Progress::Retired
                        | crate::dv_transmit::Progress::Submitted(_) => Ok(true),
                        crate::dv_transmit::Progress::Refused(actual) => {
                            if !temporary_actor(&actual.error) {
                                self.reports.diagnostic(format_args!(
                                    "TRANSPORT DV original virtual TX refusal: {}",
                                    actual.error
                                ));
                            }
                            Ok(false)
                        }
                    },
                    4 => {
                        let result = actor.poll(cx);
                        match result {
                            Poll::Pending => Ok(false),
                            Poll::Ready(Err(error)) => Err(Box::new(error)),
                            Poll::Ready(Ok(actor::Step::Activity | actor::Step::Store(_))) => {
                                Ok(true)
                            }
                            Poll::Ready(Ok(actor::Step::Failed {
                                token,
                                error,
                                context,
                            })) => {
                                let child = match &context.state {
                                    actor::FailureState::Input {
                                        forwarding_child: Some(child),
                                        ..
                                    } => Some(child.token),
                                    actor::FailureState::Output { .. } => Some(token),
                                    _ => None,
                                };
                                // Diagnostic lookup must not sample time, drive
                                // IO or refuse the original failure/retirement.
                                let native = child.and_then(|child| {
                                    owner
                                        .dv_server(scope)
                                        .ok()
                                        .and_then(|server| bridge.output_diagnostic(server, child))
                                });
                                self.reports.diagnostic(format_args!(
                                    "TRANSPORT DV actual job {token:?} failed: {error}; original={context:?}; original_child_native={native:?}"
                                ));
                                if actor.is_closed() {
                                    return Err(Box::new(error));
                                }
                                Ok(true)
                            }
                            // These are actual one-time state transitions. Their
                            // consumer may already have run in this pass, so
                            // retain another bounded pass without inventing IO
                            // progress. Repeated terminal hints below do not.
                            Poll::Ready(Ok(
                                actor::Step::LearnReady { .. }
                                | actor::Step::OutputReady(_)
                                | actor::Step::DeliveryReady(_),
                            )) => {
                                scheduler.scan_changed();
                                self.classes.local_work();
                                Ok(false)
                            }
                            Poll::Ready(Ok(_)) => Ok(false),
                        }
                    }
                    5 => self.output_one(owner, actor, bridge, scope, false),
                    _ => self.input_one(owner, actor, bridge, scope, false),
                }
            })();
            self.retirements(owner, scope);
            match step {
                Ok(progress) => {
                    changed |= progress;
                    if progress {
                        self.classes.local_work();
                    }
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
            if let Err(error) = Self::receipts(actor, owner, scheduler, notes) {
                return Poll::Ready(Err(error));
            }
            if actor.is_closed() || owner.dv_scope().as_ref() != Some(scope) {
                return Poll::Ready(Ok(Signal::Rebuild));
            }
        }
        // Native guards can physically close a MQ without an IO callback. Read
        // its actual retained transfer states and release only original FC.
        let settled = bridge.settle_send(owner.dv_server(scope)?, actor);
        self.retirements(owner, scope);
        match settled {
            Ok(Some(_)) => {
                changed = true;
                self.classes.local_work();
            }
            Ok(None) => {}
            Err(error) => return Poll::Ready(Err(Box::new(error))),
        }
        match bridge.release_input(owner.dv_server(scope)?) {
            Ok(Some(_actual)) => {
                changed = true;
                self.classes.local_work();
            }
            Ok(None) => {}
            Err(error) if temporary_bridge(&error) => {}
            Err(error) => return Poll::Ready(Err(Box::new(error))),
        }
        if let Err(error) = bridge.reap_transfers(owner.dv_server(scope)?) {
            return Poll::Ready(Err(Box::new(error)));
        }
        // A child's wake can be coalesced with an earlier parent continuation.
        // Keep its explicit local scan debt until every nested pass is complete.
        self.classes
            .retain_children(scheduler.scan_pending() || actor.input_scan_pending());
        if changed {
            Poll::Ready(Ok(Signal::Activity))
        } else {
            if self.classes.needs_pass() {
                // Only a clipped scan or one-time new readiness owes this
                // continuation. Stable blocked owners do not refresh the debt.
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }
    pub(crate) fn output_one<'id, 'source, 'pils, 'slots, 'out, 'owner, E: Entropy>(
        &mut self,
        owner: &mut Owner<'owner, E>,
        actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out>,
        bridge: &mut Bridge<'id>,
        scope: &DvScope<'owner>,
        closing: bool,
    ) -> Result<bool, Failure> {
        let count = actor.output_tokens().count();
        if count == 0 {
            return Ok(false);
        }
        // Cleanup remains available even while an ordinary target's head is
        // awaiting its original native result. Do not park on a blocked later
        // slot and depend on an unrelated future wakeup to find the ready head.
        let start = self.output % count;
        let mut terminal = None;
        for (token, progress) in actor
            .output_states()
            .skip(start)
            .chain(actor.output_states().take(start))
        {
            if matches!(
                progress,
                actor::OutputProgress::Finished | actor::OutputProgress::Retiring
            ) {
                terminal = Some((token, progress));
                break;
            }
        }
        let (token, progress) = if let Some(original) = terminal {
            original
        } else {
            if closing {
                return Ok(false);
            }
            let count = actor
                .admissible_output_tokens()
                .filter(|token| !bridge.output_staged(*token))
                .count();
            if count == 0 {
                return Ok(false);
            }
            let token = actor
                .admissible_output_tokens()
                .filter(|token| !bridge.output_staged(*token))
                .nth(self.output % count)
                .ok_or(Error::Stale)?;
            (token, actor::OutputProgress::Ready)
        };
        self.output = self.output.wrapping_add(1);
        match progress {
            actor::OutputProgress::Finished => {
                let _actual = bridge.finish_output(owner.dv_server(scope)?, actor, token)?;
                Ok(true)
            }
            actor::OutputProgress::Retiring => {
                bridge.retire_output(owner.dv_server(scope)?, actor, token)?;
                Ok(true)
            }
            actor::OutputProgress::Ready if !closing && !bridge.output_staged(token) => {
                let times = owner.dv_times(scope)?;
                match bridge.queue_output(owner.dv_server(scope)?, actor, token, times) {
                    Ok(bridge::Queued::Staged | bridge::Queued::Retired) => Ok(true),
                    Ok(bridge::Queued::AlreadyStaged) => Ok(false),
                    Err(error) => match error.scope {
                        bridge::TaskFailureScope::Deferred => Ok(false),
                        bridge::TaskFailureScope::Task => {
                            self.reports.diagnostic(format_args!(
                                "TRANSPORT DV original output retired: {error}"
                            ));
                            cancel_task(actor, token, error)
                        }
                        bridge::TaskFailureScope::Source => Err(Box::new(error)),
                    },
                }
            }
            _ => Ok(false),
        }
    }
    pub(crate) fn input_one<'id, 'source, 'pils, 'slots, 'out, 'owner, E: Entropy>(
        &mut self,
        owner: &mut Owner<'owner, E>,
        actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out>,
        bridge: &mut Bridge<'id>,
        scope: &DvScope<'owner>,
        closing: bool,
    ) -> Result<bool, Failure> {
        let count = actor.input_states().len();
        let reports = &self.reports;
        scan_inputs(&mut self.input, count, |index| {
            // The Vec-backed metadata iterator indexes without looking up a
            // token again. Any successful mutation ends this scan; temporary
            // refusals keep the original row positions and tokens unchanged.
            let (token, progress) = actor.input_states().nth(index).ok_or(Error::Stale)?;
            match progress {
                actor::InputProgress::Finished => match bridge.finish_input(actor, token) {
                    Ok(()) => Ok(true),
                    Err(error) if temporary_bridge(&error) => Ok(false),
                    Err(error) => Err(Box::new(error) as Failure),
                },
                actor::InputProgress::DeliveryReady if !closing => {
                    let times = owner.dv_times(scope)?;
                    let mut signer = owner.dv_signer(scope)?;
                    match bridge.deliver(owner.dv_server(scope)?, actor, token, times, &mut signer)
                    {
                        Ok(_) => Ok(true),
                        Err(error) => match error.scope {
                            bridge::TaskFailureScope::Deferred => Ok(false),
                            bridge::TaskFailureScope::Task => {
                                reports.diagnostic(format_args!(
                                    "TRANSPORT DV original inner frame dropped: {error}"
                                ));
                                cancel_task(actor, token, error)
                            }
                            bridge::TaskFailureScope::Source => Err(Box::new(error) as Failure),
                        },
                    }
                }
                _ => Ok(false),
            }
        })
    }
}
/// An independent cancellation refusal cannot replace the original task
/// cause. The original wrapper now requires shared-source retirement instead.
fn cancel_task<'id>(
    actor: &mut Actor<'id, '_, '_, '_, '_>,
    token: actor::Token<'id>,
    mut original: bridge::TaskFailure,
) -> Result<bool, Failure> {
    match actor.cancel(token) {
        Ok(()) => Ok(true),
        Err(cleanup) => {
            original.scope = bridge::TaskFailureScope::Source;
            original
                .error
                .cleanup
                .get_or_insert(bridge::Cause::Actor(cleanup));
            Err(Box::new(original))
        }
    }
}
fn temporary_actor(error: &actor::Error) -> bool {
    matches!(
        error,
        actor::Error::Protocol(Error::Capacity | Error::WouldBlock | Error::NotReady)
    )
}
fn temporary_bridge(error: &bridge::Error) -> bool {
    matches!(
        error.cause,
        bridge::Cause::Protocol(Error::Capacity | Error::WouldBlock | Error::NotReady)
    )
}
pub(crate) fn observe_schedule(
    reports: &crate::foreground::Reports,
    event: dv_schedule::Event<'_>,
    closed: bool,
) -> Result<(), Failure> {
    match event {
        dv_schedule::Event::Failed { error, .. } if closed => Err(error),
        dv_schedule::Event::Failed { error, .. } => {
            reports.diagnostic(format_args!(
                "TRANSPORT DV actual scheduled job failed: {error}"
            ));
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "dv_driver/scan_tests.rs"]
mod scan_tests;
