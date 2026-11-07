//! Pinned local futures keep every actual borrowed brand on its original stack.
use crate::{Bounds, Bridge, Error, ServerLimits, SessionReport, Sources, core};
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Framed, OwnedFrame, ReadStep},
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use gnunet_wire::official::consensus::ClientRequest;
use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    pin::{Pin, pin},
    rc::Rc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
mod state;
pub(crate) struct Control {
    reason: Cell<Option<Fault>>,
}
impl Control {
    pub fn new() -> Self {
        Self {
            reason: Cell::new(None),
        }
    }
    pub fn cancel(&self, reason: Fault) {
        if self.reason.get().is_none() {
            self.reason.set(Some(reason));
        }
    }
    pub fn reason(&self) -> Option<Fault> {
        self.reason.get()
    }
}
struct Key {
    owner: u64,
    global: [u8; 64],
}
pub(crate) struct Registry {
    keys: Vec<Key>,
}
impl Registry {
    pub fn new(max: usize) -> Result<Self, Fault> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(max).map_err(|_| Fault::Capacity)?;
        Ok(Self { keys })
    }
    pub fn retained_bytes(&self) -> Result<usize, Fault> {
        self.keys
            .capacity()
            .checked_mul(std::mem::size_of::<Key>())
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<RefCell<Self>>() + 2 * std::mem::size_of::<usize>(),
                )
            })
            .ok_or(Fault::Overflow)
    }
}
struct Lease {
    registry: Rc<RefCell<Registry>>,
    owner: u64,
    released: bool,
}
impl Lease {
    fn claim(registry: Rc<RefCell<Registry>>, owner: u64, global: [u8; 64]) -> Result<Self, Error> {
        {
            let mut keys = registry.try_borrow_mut().map_err(|_| Fault::Conflict)?;
            if keys.keys.iter().any(|key| key.global == global) {
                return Err(Fault::Conflict.into());
            }
            if keys.keys.len() == keys.keys.capacity() {
                return Err(Fault::Capacity.into());
            }
            keys.keys.push(Key { owner, global });
        }
        Ok(Self {
            registry,
            owner,
            released: false,
        })
    }
    fn release(&mut self) -> Result<(), Error> {
        if self.released {
            return Ok(());
        }
        let mut keys = self
            .registry
            .try_borrow_mut()
            .map_err(|_| Fault::Conflict)?;
        let at = keys
            .keys
            .iter()
            .position(|key| key.owner == self.owner)
            .ok_or(Fault::StaleGeneration)?;
        keys.keys.swap_remove(at);
        self.released = true;
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _actual = self.release();
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Origin {
    pub overall: Bounds,
    pub first: Bounds,
}
pub(crate) fn origin(
    clock: &dyn RuntimeClock,
    limits: ServerLimits,
    start: Instant,
) -> Result<Origin, Error> {
    let hard = start.checked_add(limits.operation).ok_or(Fault::Overflow)?;
    let first_hard = start
        .checked_add(limits.first_input)
        .ok_or(Fault::Overflow)?
        .min(hard);
    let now = clock.sample()?.now.as_micros();
    let us = |duration: Duration| u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow);
    let expires = now
        .checked_add(us(limits.operation)?)
        .filter(|n| *n != u64::MAX)
        .ok_or(Fault::Overflow)?;
    let first = now
        .checked_add(us(limits.first_input)?)
        .filter(|n| *n != u64::MAX)
        .ok_or(Fault::Overflow)?
        .min(expires);
    if Instant::now() >= first_hard {
        return Err(Fault::Deadline.into());
    }
    Ok(Origin {
        overall: Bounds { expires, hard },
        first: Bounds {
            expires: first,
            hard: first_hard,
        },
    })
}
pub(super) fn check(
    clock: &dyn RuntimeClock,
    bounds: Bounds,
    control: &Control,
) -> Result<u64, Error> {
    if let Some(reason) = control.reason() {
        return Err(reason.into());
    }
    if Instant::now() >= bounds.hard {
        return Err(Fault::Deadline.into());
    }
    let now = clock.sample()?.now.as_micros();
    if let Some(reason) = control.reason() {
        return Err(reason.into());
    }
    if Instant::now() >= bounds.hard || now >= bounds.expires {
        return Err(Fault::Deadline.into());
    }
    Ok(now)
}
struct Wait {
    bounds: Bounds,
    canonical: Pin<Box<Deadline>>,
    native: Pin<Box<tokio::time::Sleep>>,
}
impl Wait {
    fn new(clock: std::sync::Arc<dyn RuntimeClock>, bounds: Bounds) -> Result<Self, Error> {
        Ok(Self {
            bounds,
            canonical: Box::pin(Deadline::at(
                clock,
                AbsoluteTime::from_micros(bounds.expires),
            )?),
            native: Box::pin(tokio::time::sleep_until(bounds.hard.into())),
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if Instant::now() >= self.bounds.hard || self.native.as_mut().poll(cx).is_ready() {
            return Err(Fault::Deadline.into());
        }
        match self.canonical.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Err(Fault::Deadline.into()),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Pending => Ok(()),
        }
    }
}
pub(super) fn poll_pils<'a>(
    client: &mut pils::Client<'a, 1>,
    cx: &mut Context<'_>,
    deadline: Instant,
) -> Poll<Result<pils::Progress<'a, 1>, gnunet_client_host::ConnectError>> {
    // drive's wait is cancellation-safe; the native client retains every cursor.
    let future = client.drive(Some(tokio::time::Instant::from_std(deadline)));
    let mut future = pin!(future);
    future.as_mut().poll(cx)
}
fn pils_cause(cause: &pils::LossCause) -> Fault {
    match cause {
        pils::LossCause::Eof => Fault::Closed,
        pils::LossCause::Io(_) => Fault::Io,
        pils::LossCause::Protocol(e) | pils::LossCause::Resource(e) => *e,
        pils::LossCause::Setup(_) => Fault::Unavailable,
        pils::LossCause::Requested => Fault::Cancelled,
    }
}
async fn read_join(
    io: &mut Framed<()>,
    sources: &Sources,
    limits: ServerLimits,
    origin: Origin,
    control: &Control,
    report: &mut SessionReport,
) -> Result<OwnedFrame, Error> {
    let mut first = Wait::new(sources.clock(), origin.first)?;
    let mut partial = None;
    let mut bytes_read = 0usize;
    let result = poll_fn(|cx| -> Poll<Result<OwnedFrame, Error>> {
        check(sources.clock.as_ref(), origin.first, control)?;
        first.poll(cx)?;
        if let Some(wait) = &mut partial {
            Wait::poll(wait, cx)?;
        }
        if let Some(bytes) = io.frame() {
            if !matches!(ClientRequest::decode(bytes)?, ClientRequest::Join(_)) {
                return Poll::Ready(Err(Fault::Malformed.into()));
            }
            let frame = OwnedFrame::copy_from(bytes)?;
            check(sources.clock.as_ref(), origin.first, control)?;
            io.release_frame();
            return Poll::Ready(Ok(frame));
        }
        // A fallible shared provider above may have consumed the native hard.
        if Instant::now() >= origin.first.hard {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        let before_read = Instant::now();
        match io.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Err(Fault::Closed.into())),
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                bytes_read = bytes_read.checked_add(bytes).ok_or(Fault::Overflow)?;
                if bytes != 0 && partial.is_none() {
                    let mut bounds = Bounds::new(sources.clock.as_ref(), limits.partial_input)?;
                    bounds.expires = bounds.expires.min(origin.first.expires);
                    bounds.hard = bounds.hard.min(origin.first.hard).min(
                        before_read
                            .checked_add(limits.partial_input)
                            .ok_or(Fault::Overflow)?,
                    );
                    partial = Some(Wait::new(sources.clock(), bounds)?);
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    })
    .await;
    if result.is_err() {
        report.retired_input_bytes = report.retired_input_bytes.saturating_add(bytes_read);
    }
    result
}
async fn identity<'a>(
    client: &mut pils::Client<'a, 1>,
    sources: &Sources,
    origin: Bounds,
    control: &Control,
    report: &mut SessionReport,
) -> Result<gnunet_pils::client::Identity<'a>, Error> {
    let mut wait = Wait::new(sources.clock(), origin)?;
    poll_fn(
        |cx| -> Poll<Result<gnunet_pils::client::Identity<'a>, Error>> {
            check(sources.clock.as_ref(), origin, control)?;
            wait.poll(cx)?;
            if let Some(identity) = client.identity() {
                return Poll::Ready(Ok(identity));
            }
            if Instant::now() >= origin.hard {
                return Poll::Ready(Err(Fault::Deadline.into()));
            }
            match poll_pils(client, cx, origin.hard) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(pils::Progress::Inbound(
                    gnunet_pils::client::Inbound::Identity { identity, .. },
                ))) => Poll::Ready(Ok(identity)),
                Poll::Ready(Ok(pils::Progress::ConnectRetry { error, .. })) => {
                    report.connect_retries = report.connect_retries.saturating_add(1);
                    report.last_retry = Some(error);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Ok(pils::Progress::Unavailable(e))) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(pils::Progress::Lost {
                    cause,
                    report: lost,
                    ..
                })) => {
                    let why = pils_cause(&cause);
                    report.pils_loss_retained = lost.retained();
                    report.pils_loss_feeds = lost.feeds().count();
                    report.pils_loss = Some(cause);
                    Poll::Ready(Err(why.into()))
                }
                Poll::Ready(Ok(pils::Progress::WaitDeadline)) => {
                    Poll::Ready(Err(Fault::Deadline.into()))
                }
                Poll::Ready(Ok(pils::Progress::Closed)) => Poll::Ready(Err(Fault::Closed.into())),
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        },
    )
    .await
}
/// Each future owns its actual socket and keeps PILS/core domains on this pinned
/// stack. There is no self-referential stored SDK or spawned task.
pub(crate) async fn session(
    id: u64,
    mut io: Framed<()>,
    sources: Sources,
    limits: ServerLimits,
    origin: Origin,
    registry: Rc<RefCell<Registry>>,
    control: Rc<Control>,
) -> SessionReport {
    let mut report = SessionReport::default();
    let Some(loss_slots) = limits
        .bridge
        .core
        .sets
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
    else {
        io.retire();
        report.primary = Some(Fault::Overflow.into());
        report.physical_closed = true;
        return report;
    };
    if report.set_losses.try_reserve_exact(loss_slots).is_err() {
        io.retire();
        report.primary = Some(Fault::Capacity.into());
        report.physical_closed = true;
        return report;
    }
    let frame = match read_join(&mut io, &sources, limits, origin, &control, &mut report).await {
        Ok(frame) => frame,
        Err(error) => {
            io.retire();
            report.primary = Some(error);
            report.physical_closed = true;
            return report;
        }
    };
    let join = match ClientRequest::decode(frame.bytes()) {
        Ok(ClientRequest::Join(join)) => join,
        Ok(_) => {
            io.retire();
            report.primary = Some(Fault::Malformed.into());
            report.physical_closed = true;
            return report;
        }
        Err(error) => {
            io.retire();
            report.primary = Some(error.into());
            report.physical_closed = true;
            return report;
        }
    };
    let native_before_sample = Instant::now();
    let now = match check(sources.clock.as_ref(), origin.overall, &control) {
        Ok(now) => now,
        Err(error) => {
            io.retire();
            report.primary = Some(error);
            report.physical_closed = true;
            return report;
        }
    };
    if now >= join.deadline {
        io.retire();
        report.primary = Some(Fault::Deadline.into());
        report.physical_closed = true;
        return report;
    }
    let remaining = join.deadline.saturating_sub(now);
    let until = origin.overall.hard.min(
        native_before_sample
            .checked_add(Duration::from_micros(remaining))
            .unwrap_or(origin.overall.hard),
    );
    let original = Bounds {
        expires: origin.overall.expires.min(join.deadline),
        hard: until,
    };
    let mut pils_domain = gnunet_pils::client::Instance::new();
    let core_domain = core::Instance::new();
    let mut pils = match sources
        .pils
        .duplicate()
        .map_err(Error::from)
        .and_then(|source| {
            pils::Client::<1>::new(
                &mut pils_domain,
                source,
                limits.profile,
                limits.pils,
                limits.hello,
            )
            .map_err(Error::from)
        }) {
        Ok(client) => client,
        Err(error) => {
            io.retire();
            report.primary = Some(error);
            report.physical_closed = true;
            return report;
        }
    };
    let local = match identity(&mut pils, &sources, original, &control, &mut report).await {
        Ok(identity) => identity,
        Err(error) => {
            io.retire();
            report.pils_pending = pils.close().iter().flatten().count();
            report.primary = Some(error);
            report.physical_closed = true;
            return report;
        }
    };
    report.local_peer = Some(*local.peer().as_bytes());
    let result = (|| -> Result<Bridge<'_, '_>, Error> {
        let now = check(sources.clock.as_ref(), original, &control)?;
        let factory = crate::Factory::new(sources.set.duplicate()?)?;
        Bridge::new(
            &core_domain,
            local,
            join,
            factory,
            limits.bridge,
            original,
            now,
        )
    })();
    let mut bridge = match result {
        Ok(bridge) => bridge,
        Err(error) => {
            io.retire();
            report.pils_pending = pils.close().iter().flatten().count();
            report.primary = Some(error);
            report.physical_closed = true;
            return report;
        }
    };
    let mut lease = match Lease::claim(registry, id, bridge.session().global_id()) {
        Ok(lease) => Some(lease),
        Err(error) => {
            report.primary = Some(error);
            if let Err(cleanup) = bridge.cancel(Fault::Conflict) {
                report.cleanup = Some(cleanup);
            }
            None
        }
    };
    let mut state = state::State::new(
        io,
        bridge,
        &mut pils,
        state::Admission {
            clock: sources.clock(),
            limits,
            original,
            control: &control,
            identity: local,
        },
        report,
    );
    let mut report = poll_fn(|cx| state.poll(cx)).await;
    if let Some(lease) = &mut lease
        && let Err(error) = lease.release()
    {
        report.cleanup.get_or_insert(error);
        report.undrained = report.undrained.saturating_add(1);
    }
    report
}
