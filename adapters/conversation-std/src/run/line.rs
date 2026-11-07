use super::{
    Bounds, CallLease, ClientOrigin, Control, LocalEvent, Mailbox, Origin, Registry, yield_once,
};
use crate::{CallSummary, Error, Limits, LineReport, Sources};
use gnunet_cadet_host as cadet;
use gnunet_conversation::{
    Action, CallId, Completion, EffectId, EffectScan, EffectScanStep, Identity, Instance, Session,
    Source,
};
use gnunet_pils::client::{
    Identity as PilsIdentity, Inbound as PilsInbound, Instance as PilsInstance,
};
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::framing::Framed;
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    mem::size_of,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Sleep;
mod effects;
mod identity;
mod input;
mod peers;
mod retire;
mod session;

struct Packet<'c> {
    received: cadet::Received<'c>,
    validation: usize,
    validated: bool,
    offset: usize,
    waiting: Option<u64>,
    bound: Bounds,
}
struct Call<'s, 'c> {
    id: CallId<'s>,
    channel: Option<cadet::Channel<'c>>,
    source: Option<Source>,
    gone: bool,
    retiring: Option<Fault>,
    input: Option<Packet<'c>>,
    _lease: CallLease,
}
struct Reject<'c> {
    channel: cadet::Channel<'c>,
    reason: Fault,
    bound: Bounds,
    queued: bool,
}
#[derive(Clone, Copy)]
enum NativeKind<'s, 'c> {
    Effect(EffectId<'s>),
    Reject(cadet::Channel<'c>),
    Internal,
}
struct PendingNative<'s, 'c> {
    call: Option<CallId<'s>>,
    ack: Option<(CallId<'s>, u64)>,
    transmit: cadet::Transmit<'c>,
    kind: NativeKind<'s, 'c>,
    attempted: bool,
    exposed: bool,
    known_written: bool,
    closing: bool,
    bound: Bounds,
}
struct PendingClient<'s> {
    effect: EffectId<'s>,
    written: usize,
    attempted: bool,
    known_written: bool,
    bound: Bounds,
}
struct State<'s, 'p, 'c, 'slots> {
    io: Framed<ClientOrigin>,
    pils: pils::Client<'p, 1>,
    cadet: cadet::Client<'c, 'slots>,
    sources: Sources,
    limits: Limits,
    origin: Origin,
    last_now: u64,
    native_metadata: usize,
    control: Arc<Control>,
    registry: Rc<Registry>,
    events: Mailbox,
    session: session::LineSession<'s, 'p>,
    source: Option<Source>,
    retired: Option<cadet::Loss<'c>>,
    port: Option<cadet::Port<'c>>,
    port_hash: Option<[u8; 64]>,
    calls: Vec<Option<Call<'s, 'c>>>,
    rejects: Vec<Reject<'c>>,
    pending_native: Option<PendingNative<'s, 'c>>,
    pending_client: Option<PendingClient<'s>>,
    scan: EffectScan,
    dirty: bool,
    scan_end: bool,
    first: Option<Bounds>,
    startup: Option<Bounds>,
    client_input: Option<Bounds>,
    pils_input: Option<Bounds>,
    cadet_input: Option<Bounds>,
    ttl: Option<Bounds>,
    next_delivery: Option<u64>,
    call_cursor: usize,
    class: usize,
    tolerant: bool,
    client_lost: bool,
    report: LineReport,
    closed: bool,
    alarm: Pin<Box<Sleep>>,
}
impl<'s, 'p, 'c, 'slots> State<'s, 'p, 'c, 'slots> {
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.origin.now()?;
        self.last_now = self.last_now.max(now);
        Ok(now)
    }
    fn utc(&self) -> Result<u64, Error> {
        Ok(self
            .control
            .check(self.sources.clock.as_ref(), self.session.core().is_some())?)
    }
    fn selected(&self) -> Result<Identity, Error> {
        self.session
            .core()
            .map(Session::identity)
            .ok_or_else(|| Fault::NotReady.into())
    }
    fn earliest(&self) -> Result<Option<Bounds>, Error> {
        let mut result: Option<Bounds> = None;
        for b in self
            .first
            .into_iter()
            .chain(self.startup)
            .chain(self.client_input)
            .chain(self.pils_input)
            .chain(self.cadet_input)
            .chain(self.ttl)
            .chain(self.pending_client.as_ref().map(|p| p.bound))
            .chain(self.pending_native.as_ref().map(|p| p.bound))
            .chain(
                self.calls
                    .iter()
                    .flatten()
                    .filter_map(|c| c.input.as_ref().map(|p| p.bound)),
            )
            .chain(self.rejects.iter().map(|r| r.bound))
        {
            result = Some(match result {
                Some(old) if old.hard <= b.hard && old.canonical <= b.canonical => old,
                Some(old) => Bounds {
                    hard: old.hard.min(b.hard),
                    canonical: old.canonical.min(b.canonical),
                },
                None => b,
            });
        }
        // A retained connect future must not start an already expired queued
        // Open effect after a Resolver callback. Once attached, dynamic exact
        // effect gates govern calls; unrelated setup timers are maintained here.
        if self.cadet.epoch().is_none()
            && let Some(deadline) = self.session.core().and_then(Session::next_deadline)
        {
            let b = self.origin.at(deadline)?;
            result = Some(match result {
                Some(old) => Bounds {
                    hard: old.hard.min(b.hard),
                    canonical: old.canonical.min(b.canonical),
                },
                None => b,
            });
        }
        Ok(result)
    }
    fn refresh(&self) -> Result<(), Error> {
        self.control.targets(self.earliest()?)?;
        Ok(())
    }
    fn guard(&self, cx: &mut Context<'_>) -> Result<(), Error> {
        if let Some(reason) = self.control.reason() {
            return Err(reason.into());
        }
        if !self.registry.healthy() {
            return Err(Fault::NotReady.into());
        }
        self.refresh()?;
        self.control
            .check(self.sources.clock.as_ref(), self.session.core().is_some())?;
        if self.session.core().is_some() {
            identity::current(&self.pils, self.session.observed())?;
        }
        let _ = cx;
        Ok(())
    }
    fn arm(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        let mut at = self.earliest()?.map(|b| b.hard);
        if let Some(d) = self.session.core().and_then(Session::next_deadline) {
            let d = self.origin.at(d)?.hard;
            at = Some(at.map_or(d, |old| old.min(d)));
        }
        if let Some(at) = at {
            self.alarm.as_mut().reset(at.into());
            if self.alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Ok(())
    }
    fn usage(&self) -> Result<usize, Error> {
        let call_table = self
            .calls
            .capacity()
            .checked_mul(size_of::<Option<Call<'s, 'c>>>())
            .ok_or(Fault::Overflow)?;
        let reject_table = self
            .rejects
            .capacity()
            .checked_mul(size_of::<Reject<'c>>())
            .ok_or(Fault::Overflow)?;
        let packets = self
            .calls
            .iter()
            .flatten()
            .filter_map(|c| c.input.as_ref())
            .try_fold(0usize, |n, p| {
                n.checked_add(p.received.frame().retained_bytes())
                    .ok_or(Fault::Overflow)
            })?;
        let core = self.session.core().map_or(Ok(0), Session::retained_bytes)?;
        let envelope = self
            .limits
            .frame_bytes
            .max(self.limits.cadet.frame_bytes)
            .max(self.limits.pils.frame_bytes)
            .checked_mul(8)
            .and_then(|n| n.checked_add(self.limits.hello.maximum_address_bytes))
            .and_then(|n| n.checked_add(256 * 1024))
            .ok_or(Fault::Overflow)?;
        let events = self.events.retained()?;
        core.checked_add(self.io.retained_storage_bytes()?)
            .and_then(|n| n.checked_add(call_table))
            .and_then(|n| n.checked_add(reject_table))
            .and_then(|n| n.checked_add(packets))
            .and_then(|n| {
                n.checked_add(
                    size_of::<Self>()
                        + size_of::<Sleep>()
                        + size_of::<Control>()
                        + 2 * size_of::<usize>(),
                )
            })
            .and_then(|n| n.checked_add(events))
            .and_then(|n| n.checked_add(self.native_metadata))
            .and_then(|n| n.checked_add(envelope))
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn account(&self) -> Result<(), Error> {
        if self.usage()? > self.limits.line_bytes {
            Err(Fault::Capacity.into())
        } else {
            Ok(())
        }
    }
    fn native_gate(&self) -> Result<(), cadet::Error> {
        self.control.check(self.sources.clock.as_ref(), true)?;
        identity::current(&self.pils, self.session.observed())?;
        if !self.pending_allowed()? {
            return Err(Fault::Cancelled.into());
        }
        if let Some(pending) = &self.pending_native
            && let NativeKind::Effect(id) = pending.kind
        {
            let core = self.session.core().ok_or(Fault::NotReady)?;
            let current = core.identity();
            if !core.effect_io_allowed(id, &current, self.origin.now()?)? {
                return Err(Fault::Cancelled.into());
            }
        }
        Ok(())
    }
    fn pending_allowed(&self) -> Result<bool, Fault> {
        let Some(core) = self.session.core() else {
            return Ok(true);
        };
        let current = core.identity();
        let now = self.origin.now()?;
        if let Some(pending) = &self.pending_native
            && !pending.known_written
            && let NativeKind::Effect(id) = pending.kind
        {
            if !core.effect_io_allowed(id, &current, now)? {
                return Ok(false);
            }
            if !pending.closing
                && pending.call.is_some_and(|id| {
                    self.calls
                        .iter()
                        .flatten()
                        .any(|c| c.id == id && (c.gone || c.retiring.is_some()))
                })
            {
                return Ok(false);
            }
        }
        if let Some(pending) = &self.pending_client
            && !pending.known_written
            && !core.effect_io_allowed(pending.effect, &current, now)?
        {
            return Ok(false);
        }
        Ok(true)
    }
    fn mark(&mut self) {
        self.dirty = true;
        self.events.progress();
    }
    fn settle(&mut self, id: EffectId<'s>, completion: Completion) -> Result<(), Error> {
        let terminal = self
            .session
            .core_mut()
            .ok_or(Fault::NotReady)?
            .complete_effect(id, completion, self.last_now)?;
        match completion {
            Completion::Written => {
                self.report.effects_written = self.report.effects_written.saturating_add(1);
                match terminal.action {
                    Action::ClientFrame { .. } => {
                        self.report.client_frames_written =
                            self.report.client_frames_written.saturating_add(1)
                    }
                    Action::PeerFrame { .. } => {
                        self.report.peer_frames_written =
                            self.report.peer_frames_written.saturating_add(1)
                    }
                    _ => {}
                }
            }
            Completion::Processed => {
                self.report.processed_inners = self.report.processed_inners.saturating_add(1)
            }
            Completion::Unsent(_) => {
                self.report.effects_unsent = self.report.effects_unsent.saturating_add(1)
            }
            Completion::Lost { .. } => {
                self.report.effects_lost = self.report.effects_lost.saturating_add(1)
            }
        }
        self.mark();
        Ok(())
    }
    fn collect_reports(&mut self) -> Result<bool, Error> {
        let count = self.calls.len();
        for offset in 0..count {
            let index = (self.call_cursor + offset) % count;
            let Some(call) = self.calls[index].as_ref() else {
                continue;
            };
            if !self.events.room()? {
                return Ok(false);
            }
            let Some(report) = self
                .session
                .core_mut()
                .ok_or(Fault::NotReady)?
                .take_report(call.id)?
            else {
                continue;
            };
            let summary = CallSummary {
                call: report.call.value(),
                cid: report.cid,
                peer: report.peer,
                reason: report.reason,
                failure: report.failure,
                ring_written: report.ring_written,
                remote_pickup: report.remote_pickup,
                local_pickup_written: report.local_pickup_written,
                remote_hangup: report.remote_hangup,
                local_hangup_written: report.local_hangup_written,
            };
            self.events.emit(LocalEvent::CallClosed(summary))?;
            self.calls[index] = None;
            self.report.calls_closed = self.report.calls_closed.saturating_add(1);
            self.call_cursor = (index + 1) % count;
            self.mark();
            return Ok(true);
        }
        Ok(false)
    }
    fn maintain(&mut self) -> Result<bool, Error> {
        let now = self.now()?;
        let Some(core) = self.session.core_mut() else {
            return Ok(false);
        };
        let before = core.pending_effects();
        core.tick(now)?;
        let progress = core.progress(now)? || core.pending_effects() != before;
        if let Some(error) = core.failure() {
            return Err(error.into());
        }
        if !self.pending_allowed()? {
            return Err(Fault::Cancelled.into());
        }
        if progress {
            self.mark();
        }
        Ok(progress)
    }
    fn turn(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Error>> {
        if let Some(reason) = self.control.reason() {
            return Poll::Ready(Err(reason.into()));
        }
        self.maintain()?;
        self.guard(cx)?;
        self.account()?;
        if self.session.core().is_some() && self.collect_reports()? {
            return Poll::Ready(Ok(true));
        }
        for offset in 0..6 {
            self.guard(cx)?;
            let class = (self.class + offset) % 6;
            let progressed = match class {
                0 => self.poll_identity(cx)?,
                1 if self.session.core().is_some() => self.poll_cadet(cx)?,
                2 => self.client_read(cx)?,
                3 if self.session.core().is_some() => self.client_write(cx)?,
                4 if self.session.core().is_some() => self.effect_step()?,
                5 if self.session.core().is_some() => self.peer_input()?,
                _ => false,
            };
            if progressed {
                self.class = (class + 1) % 6;
                // A bounded scan/preflight step is CPU progress. It must not
                // reset the frozen effect round when all real owners block.
                self.events.progress();
                self.arm(cx)?;
                return Poll::Ready(Ok(true));
            }
        }
        self.class = (self.class + 1) % 6;
        self.arm(cx)?;
        Poll::Pending
    }
    async fn drive(&mut self) -> Result<(), Error> {
        loop {
            poll_fn(|cx| self.turn(cx)).await?;
            yield_once().await;
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "one original Line's explicitly scoped native sources, brands, bounds and controls"
)]
pub(crate) async fn run(
    io: Framed<ClientOrigin>,
    sources: Sources,
    limits: Limits,
    origin: Origin,
    first: Bounds,
    startup: Bounds,
    control: Arc<Control>,
    registry: Rc<Registry>,
    events: Mailbox,
    tolerant: bool,
) -> LineReport {
    let mut report = LineReport {
        cadet_closed: true,
        pils_closed: true,
        ..LineReport::default()
    };
    let mut brand = Instance::new();
    let mut pils_instance = PilsInstance::new();
    let mut cadet_instance = cadet::Instance::new();
    let result: Result<LineReport, Error> = async {
        let mut ports = Vec::new();
        ports.try_reserve_exact(1).map_err(|_| Fault::Capacity)?;
        ports.push(cadet::PortSlot::new());
        let slots = limits.core.calls.checked_add(1).ok_or(Fault::Overflow)?;
        let mut channels = Vec::new();
        channels
            .try_reserve_exact(slots)
            .map_err(|_| Fault::Capacity)?;
        channels.resize_with(slots, cadet::ChannelSlot::new);
        let mut calls = Vec::new();
        calls
            .try_reserve_exact(limits.core.calls)
            .map_err(|_| Fault::Capacity)?;
        calls.resize_with(limits.core.calls, || None);
        let mut rejects = Vec::new();
        rejects
            .try_reserve_exact(slots)
            .map_err(|_| Fault::Capacity)?;
        let native_metadata = ports
            .capacity()
            .checked_mul(size_of::<cadet::PortSlot>())
            .and_then(|n| {
                channels
                    .capacity()
                    .checked_mul(size_of::<cadet::ChannelSlot>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Fault::Overflow)?;
        control.check(sources.clock.as_ref(), false)?;
        let pils = pils::Client::<1>::new_guarded(
            &mut pils_instance,
            sources.pils.duplicate()?,
            limits.pils_profile,
            limits.pils,
            limits.hello,
            control.connect_guard(sources.clock.clone(), false),
        )?;
        let cadet = cadet::Client::new_guarded(
            &mut cadet_instance,
            sources.cadet.duplicate()?,
            &mut ports,
            &mut channels,
            limits.cadet,
            control.connect_guard(sources.clock.clone(), true),
        )?;
        let report = LineReport {
            pils_closed: false,
            cadet_closed: false,
            ..LineReport::default()
        };
        let mut state = State {
            io,
            pils,
            cadet,
            sources,
            limits,
            origin,
            last_now: origin.now()?,
            native_metadata,
            control,
            registry,
            events,
            session: session::LineSession::new(&mut brand),
            source: None,
            retired: None,
            port: None,
            port_hash: None,
            calls,
            rejects,
            pending_native: None,
            pending_client: None,
            scan: EffectScan::new(),
            dirty: true,
            scan_end: true,
            first: Some(first),
            startup: Some(startup),
            client_input: None,
            pils_input: None,
            cadet_input: None,
            ttl: None,
            next_delivery: Some(1),
            call_cursor: 0,
            class: 0,
            tolerant,
            client_lost: false,
            report,
            closed: false,
            alarm: Box::pin(tokio::time::sleep(Duration::ZERO)),
        };
        state.account()?;
        let result = state.drive().await;
        let report = state.finish(result.err());
        Ok(report)
    }
    .await;
    match result {
        Ok(done) => done,
        Err(error) => {
            report.primary = Some(error);
            report.physical_closed = true;
            report
        }
    }
}
