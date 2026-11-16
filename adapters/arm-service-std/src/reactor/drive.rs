//! Bounded settlement and fair ordinary-source scheduling.
use super::*;

impl<'view, 'scope, 'spec, 'slots, 'bytes, C: Clock>
    Driver<'view, 'scope, 'spec, 'slots, 'bytes, C>
{
    pub(super) fn settle(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let resource_client = self.owner.resource_closures().next();
        if let Some(client) = resource_client {
            let index = self
                .state
                .sessions
                .iter()
                .position(|s| s.id == client)
                .ok_or(Error::Mapping)?;
            self.close(index, true)?;
            return Ok(true);
        }
        if self.managed.apply_next(self.owner)? {
            return Ok(true);
        }
        if self.timer(cx)? {
            return Ok(true);
        }
        let source_callback = matches!(self.owner.phase(), Phase::Configuring | Phase::Starting)
            || self.state.scanning
            || self.state.shutdown_sending;
        // A request/demand callback's actual native effect completes before an
        // unrelated child-death callback, just like the source synchronous body.
        if self.native(cx)? {
            return Ok(true);
        }
        if self.state.native_waiting {
            return Ok(false);
        }
        if self.state.shutdown_sending {
            // shutdown_task's complete synchronous TERM pass precedes the
            // next child_death callback; no consuming wait runs in its middle.
            self.state.shutdown_sending = false;
            return Ok(true);
        }
        if !source_callback && self.reap()? {
            return Ok(true);
        }
        if self.handoff()? {
            return Ok(true);
        }
        if self.owner.take_shutdown_request() {
            self.state.shutdown_requested = true;
        }
        if self.state.shutdown_requested
            && !matches!(self.owner.phase(), Phase::Draining | Phase::Closed)
        {
            let utc = self.utc()?;
            self.state.scanning = false;
            self.state.shutdown_sending = true;
            self.owner.begin_shutdown(utc);
            return Ok(true);
        }
        if matches!(self.owner.phase(), Phase::Configuring | Phase::Starting) {
            let _more = self.owner.startup_next()?;
            return Ok(true);
        }
        if self.state.scanning && self.owner.phase() == Phase::Serving {
            let utc = self.utc()?;
            let _next = self.owner.restart(utc)?;
            // An automatic spawn pauses this source scan until its real native
            // acknowledgment. Do not reinterpret Some(now) as a timer callback.
            self.state.pending_native = self.owner.take_native()?.map(|effect| match effect {
                NativeEffect::Spawn {
                    ticket,
                    child,
                    service,
                    pipe_control,
                    ..
                } => Native::Spawn {
                    ticket,
                    child,
                    service,
                    pipe: pipe_control,
                },
                NativeEffect::Term { ticket, child } => Native::Term { ticket, child },
            });
            self.state.scanning = self.state.pending_native.is_some();
            return Ok(true);
        }
        if let Some(ticket) = self.owner.take_runtime_shutdown() {
            drop(self.state.control.take());
            while let Some(session) = self.state.sessions.first() {
                let persisted = self.owner.client_persisted(session.id)?;
                let session = self.state.sessions.remove(0);
                if persisted {
                    self.state.persisted.push(session.io.into_connection());
                } else {
                    drop(session);
                    self.state.counters.closed = self.state.counters.closed.saturating_add(1);
                }
            }
            self.state.timer = None;
            self.owner.runtime_shutdown_applied(ticket)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn ordinary_ready(&self) -> Result<bool, Error> {
        for session in &self.state.sessions {
            if session.io.ordinary_ready().map_err(Error::Io)? {
                return Ok(true);
            }
        }
        if matches!(self.owner.phase(), Phase::Serving | Phase::Draining) {
            if self.owner.phase() == Phase::Serving && self.managed.ordinary_ready()? {
                return Ok(true);
            }
            if self.state.control_accept.ready()
                && let Some(control) = self.state.control.as_ref()
            {
                for listener in control.listeners() {
                    if listener.level_readiness().map_err(Error::Io)?.is_some() {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    /// Poll one full ordinary callback settlement. At a cooperative budget yield,
    /// no unrelated I/O or IDLE callback is polled ahead of unfinished effects.
    pub fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<Result<Activity, Error>> {
        let mut progressed = false;
        loop {
            for _ in 0..self.state.limits.settlement_budget {
                match self.settle(cx) {
                    Ok(true) => progressed = true,
                    Ok(false) => break,
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            if self.state.native_waiting {
                return Poll::Pending;
            }
            // Check settlement once more to distinguish budget from idle. It
            // performs at most one operation and retains all effects on errors.
            match self.settle(cx) {
                Ok(true) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(error)),
                Ok(false) => {}
            }
            if self.state.native_waiting {
                return Poll::Pending;
            }
            if self.owner.phase() == Phase::Closed {
                return Poll::Ready(Ok(Activity::Closed));
            }
            if progressed {
                return Poll::Ready(Ok(Activity::Progress));
            }
            // C appends each continuation to its ready FIFO. Rotate ordinary
            // sources and stream directions after actual work, retaining this
            // scheduling state in the caller-owned State across cancellation.
            let first = self.state.next_ordinary;
            let lanes = if cfg!(windows) { 4 } else { 3 };
            for lane in (first..lanes).chain(0..first) {
                let work = match lane {
                    0 if matches!(self.owner.phase(), Phase::Serving | Phase::Draining) => {
                        match self.poll_accept(cx) {
                            Poll::Ready(result) => result,
                            Poll::Pending => Ok(false),
                        }
                    }
                    1 => self.poll_sessions(cx),
                    2 if self.owner.phase() == Phase::Serving => {
                        match self.managed.poll_event(cx) {
                            Poll::Ready(Ok(_event)) => self
                                .managed
                                .deliver(self.owner)
                                .map(|()| true)
                                .map_err(Error::from),
                            Poll::Ready(Err(error)) => Err(error.into()),
                            Poll::Pending => Ok(false),
                        }
                    }
                    3 => self.poll_controls(cx),
                    _ => Ok(false),
                };
                match work {
                    Ok(true) => {
                        self.state.next_ordinary = (lane + 1) % lanes;
                        progressed = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            if progressed {
                continue;
            }
            if let Poll::Ready(signal) = process::poll_exit(self.children, cx) {
                if let Err(error) = signal {
                    return Poll::Ready(Err(error.into()));
                }
                match self.reap() {
                    Ok(true) => {
                        progressed = true;
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            // Source IDLE priority: only after no ordinary ready callback.
            // Tokio's cached hint may lag a real queued descriptor. Give the
            // runtime a chance to refresh it before dispatching IDLE. This
            // probes only enabled tasks, never an empty always-writable stream.
            if self.state.timer.is_some() {
                match self.ordinary_ready() {
                    Ok(true) => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Ok(false) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            let due = if let Some(timer) = self.state.timer.as_ref() {
                timer.at_utc != u64::MAX
            } else {
                false
            };
            if due {
                let now = match self.utc() {
                    Ok(now) => now,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                if let Some(timer) = self.state.timer.as_mut() {
                    if now >= timer.at_utc {
                        let id = timer.id;
                        if let Err(error) = self.owner.timer_fired(id) {
                            return Poll::Ready(Err(error.into()));
                        }
                        self.state.timer = None;
                        self.state.scanning = true;
                        self.state.counters.timer_callbacks =
                            self.state.counters.timer_callbacks.saturating_add(1);
                        progressed = true;
                        continue;
                    }
                    if let Some(sleep) = timer.sleep.as_mut()
                        && sleep.as_mut().poll(cx).is_ready()
                    {
                        // A backward source UTC change does not expire the
                        // registration. Retain its identity and re-arm its hint.
                        let delta = Duration::from_micros(timer.at_utc.saturating_sub(now));
                        let Some(deadline) = Instant::now().checked_add(delta) else {
                            return Poll::Ready(Err(Error::Capacity));
                        };
                        sleep.as_mut().reset(deadline);
                        let _registered = sleep.as_mut().poll(cx);
                    }
                }
            }
            return Poll::Pending;
        }
    }
    /// Wait for one actual complete callback settlement. Cancellation retains all
    /// owned RX/TX, timer registrations, native leases and consuming wait events.
    pub async fn drive(&mut self) -> Result<Activity, Error> {
        std::future::poll_fn(|cx| self.poll_drive(cx)).await
    }
}
