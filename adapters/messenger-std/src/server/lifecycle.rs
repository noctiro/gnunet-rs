use super::*;
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    pub(super) fn close_app(
        &mut self,
        row: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event),
    ) {
        if let Some(mut app) = self.apps[row].take() {
            // Physical owner first, independent of clock/Core capacity or later cleanup.
            app.io.retire();
            if let Some(out) = app.output.take() {
                if out.sent > 0 {
                    self.report.unknown = self.report.unknown.saturating_add(1)
                }
                observe(Event::OutputLost {
                    sequence: out.sequence,
                    exposed: Some(out.sent > 0),
                });
                if let Some(task) = out.task {
                    self.finish_task(task)
                }
            }
            if let Some(input) = app.entry_input.take() {
                observe(Event::EntryFailed {
                    client: app.client.clone(),
                    key: input.key,
                    door: input.door,
                    reason: Fault::Closed.into(),
                });
            }
            if let Some(input) = app.open_input.take() {
                observe(Event::OpenFailed {
                    client: app.client.clone(),
                    key: input.key,
                    reason: Fault::Closed.into(),
                });
            }
            for l in app.rooms {
                if let Some(pending) = l.pending_entry {
                    observe(Event::EntryFailed {
                        client: app.client.clone(),
                        key: pending.request.key,
                        door: pending.request.door,
                        reason: Fault::Closed.into(),
                    });
                }
                if let Some(pending) = l.pending_open {
                    observe(Event::OpenFailed {
                        client: app.client.clone(),
                        key: pending.request.key,
                        reason: Fault::Closed.into(),
                    });
                }
                self.drain_events();
                match self.core.source_stopped(l.source) {
                    Err(e) => self.remember(e.into()),
                    Ok(()) if l.counted => self.statistics.closed_room(),
                    Ok(()) => {}
                }
            }
            for task in &mut self.tasks {
                if task.as_ref().is_some_and(|t|matches!(t.destination,Destination::App{client,..} if client==app.client.serial)){*task=None}
            }
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed {
                client: app.client,
                cause,
            });
        }
    }
    pub(super) fn fail_entry(
        &mut self,
        row: usize,
        index: usize,
        reason: Error,
        observe: &mut impl FnMut(Event),
    ) {
        if let Some(app) = self.apps[row].as_mut()
            && let Some(pending) = app.rooms[index].pending_entry.take()
        {
            observe(Event::EntryFailed {
                client: app.client.clone(),
                key: pending.request.key,
                door: pending.request.door,
                reason,
            });
        }
    }
    pub(super) fn fail_entry_input(
        &mut self,
        row: usize,
        reason: Error,
        observe: &mut impl FnMut(Event),
    ) {
        if let Some(app) = self.apps[row].as_mut()
            && let Some(input) = app.entry_input.take()
        {
            observe(Event::EntryFailed {
                client: app.client.clone(),
                key: input.key,
                door: input.door,
                reason,
            });
        }
    }
    pub(super) fn fail_open(
        &mut self,
        row: usize,
        index: usize,
        reason: Error,
        observe: &mut impl FnMut(Event),
    ) {
        if let Some(app) = self.apps[row].as_mut()
            && let Some(pending) = app.rooms[index].pending_open.take()
        {
            observe(Event::OpenFailed {
                client: app.client.clone(),
                key: pending.request.key,
                reason,
            });
        }
    }
    pub(super) fn fail_open_input(
        &mut self,
        row: usize,
        reason: Error,
        observe: &mut impl FnMut(Event),
    ) {
        if let Some(app) = self.apps[row].as_mut()
            && let Some(input) = app.open_input.take()
        {
            observe(Event::OpenFailed {
                client: app.client.clone(),
                key: input.key,
                reason,
            });
        }
    }
    fn complete_open_input(&self, app: &App<'c>) -> Option<OpenInput> {
        let input_until = app.input_until?;
        let Request::Open { room, .. } = Request::decode(app.io.frame()?).ok()? else {
            return None;
        };
        if !app.rooms.iter().any(|lease| {
            lease.phase != LeasePhase::Closing
                && self
                    .core
                    .room_key(lease.room)
                    .is_ok_and(|key| key == room.key)
        }) {
            return None;
        }
        let until = match app.open_input {
            Some(input) if input.key == *room.key => input.until.min(input_until),
            Some(_) => return None,
            None => input_until,
        };
        Some(OpenInput {
            key: *room.key,
            until,
        })
    }
    fn complete_active_entry(&self, app: &App<'c>) -> Option<EntryInput> {
        let input_until = app.input_until?;
        let Request::Entry { room, .. } = Request::decode(app.io.frame()?).ok()? else {
            return None;
        };
        if !app.rooms.iter().any(|lease| {
            lease.phase == LeasePhase::Active
                && self
                    .core
                    .room_key(lease.room)
                    .is_ok_and(|key| key == room.key)
        }) {
            return None;
        }
        let until = match app.entry_input {
            Some(input) if input.key == *room.key && input.door == *room.door => {
                input.until.min(input_until)
            }
            Some(_) => return None,
            None => input_until,
        };
        Some(EntryInput {
            key: *room.key,
            door: *room.door,
            target: app.entry_input.and_then(|input| input.target),
            until,
        })
    }
    // Only the additional room request is refused. Complete backpressured input is
    // retained until this original bound; incomplete input keeps its old MQ rule.
    fn expire_requests(&mut self, now: Instant, observe: &mut impl FnMut(Event)) -> bool {
        for row in 0..self.apps.len() {
            // A complete read is observable before process_app runs, including
            // while history is frozen. Capture real complete additional room
            // requests with their already established input hard bound. This also
            // prevents a later expiry check in this turn from closing its MQ.
            let captured = self.apps[row]
                .as_ref()
                .and_then(|app| self.complete_active_entry(app));
            if let Some(input) = captured
                && let Some(app) = self.apps[row].as_mut()
            {
                app.entry_input = Some(input);
            }
            let captured_open = self.apps[row]
                .as_ref()
                .and_then(|app| self.complete_open_input(app));
            if let Some(input) = captured_open
                && let Some(app) = self.apps[row].as_mut()
            {
                app.open_input = Some(input);
            }
            let Some(app) = self.apps[row].as_ref() else {
                continue;
            };
            if let Some(input) = app.open_input
                && (now >= input.until || app.input_until.is_some_and(|until| now >= until))
                && self.complete_open_input(app).is_some()
            {
                self.fail_open_input(row, Fault::Deadline.into(), observe);
                if let Some(app) = self.apps[row].as_mut() {
                    app.io.release_frame();
                    app.input_until = None;
                }
                return true;
            }
            if let Some(input) = app.entry_input
                && (now >= input.until || app.input_until.is_some_and(|until| now >= until))
                && app.rooms.iter().any(|lease| {
                    lease.phase == LeasePhase::Active
                        && self
                            .core
                            .room_key(lease.room)
                            .is_ok_and(|key| *key == input.key)
                })
            {
                self.fail_entry_input(row, Fault::Deadline.into(), observe);
                if let Some(app) = self.apps[row].as_mut() {
                    app.io.release_frame();
                    app.input_until = None;
                }
                return true;
            }
            let count = app.rooms.len();
            for index in 0..count {
                if self.apps[row].as_ref().is_some_and(|app| {
                    app.rooms[index]
                        .pending_open
                        .is_some_and(|pending| now >= pending.request.until)
                }) {
                    self.fail_open(row, index, Fault::Deadline.into(), observe);
                    return true;
                }
                if self.apps[row].as_ref().is_some_and(|app| {
                    app.rooms[index]
                        .pending_entry
                        .is_some_and(|pending| now >= pending.request.until)
                }) {
                    self.fail_entry(row, index, Fault::Deadline.into(), observe);
                    return true;
                }
            }
        }
        false
    }
    pub(super) fn remember(&mut self, error: Error) {
        if self.cleanup.is_none() {
            self.cleanup = Some(error)
        }
    }
    /// First independent cleanup failure. Taking it does not erase an original
    /// operational error returned by poll and does not manufacture quiescence.
    pub fn take_cleanup_error(&mut self) -> Option<Error> {
        self.cleanup.take()
    }
    /// Actually close this exact original accepted MQ. No wire CANCEL is invented.
    pub fn close_client(
        &mut self,
        client: &Client,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let row = self
            .apps
            .iter()
            .position(|a| a.as_ref().is_some_and(|a| a.client == *client))
            .ok_or(Fault::StaleGeneration)?;
        self.close_app(row, CloseCause::Shutdown, observe);
        Ok(())
    }
    /// Stop new room/app admission; soft drains original queued app/peer frames.
    /// A containing PROGRAM supplies a finite grace then calls close_all.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode)
        }
    }
    /// Actual no-clock physical stop of every independent owner, before Core/source
    /// cleanup. Drop cannot claim remote delivery, durable history or wire revoke.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event)) -> Report {
        if self.closed {
            return self.report;
        }
        self.closed = true;
        self.shutdown = Some(ShutdownMode::Immediate);
        for row in 0..self.apps.len() {
            self.close_app(row, CloseCause::Shutdown, observe)
        }
        let loss = match self.cadet.close() {
            Ok(r) => r,
            Err(e) => {
                self.remember(e.into());
                None
            }
        };
        if let Some(out) = self.peer_output.take() {
            let exposed = loss
                .and_then(|l| l.pending)
                .filter(|p| p.transmit == out.transmit)
                .map(|p| p.exposed);
            if exposed != Some(false) {
                self.report.unknown = self.report.unknown.saturating_add(1)
            }
            observe(Event::OutputLost {
                sequence: out.sequence,
                exposed,
            });
        }
        self.report.stopped_signatures = self.signs.iter().flatten().count();
        self.retire_pils();
        for r in &mut self.received {
            *r = None
        }
        for t in &mut self.tasks {
            *t = None
        }
        for s in &mut self.signs {
            *s = None
        }
        for i in 0..self.tunnels.len() {
            if let Some(t) = self.tunnels[i].take() {
                self.drain_events();
                if let Err(e) = self.core.source_stopped(t.source) {
                    self.remember(e.into())
                }
            }
        }
        for i in 0..self.rooms.len() {
            if let Some(r) = self.rooms[i].take() {
                self.drain_events();
                if let Err(e) = self.core.source_stopped(r.signer) {
                    self.remember(e.into())
                }
                self.drain_events();
                if self.history.is_none()
                    && let Err(e) = self.core.forget_room(r.room)
                {
                    self.remember(e.into())
                }
            }
        }
        self.drain_events();
        self.report
    }
    fn expired(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        let now = Instant::now();
        // Classify/retire complete additional room input with the same native
        // timestamp used by the generic input-expiry decision below.
        if self.expire_requests(now, observe) {
            return Ok(true);
        }
        for r in &mut self.retrievals {
            if r.as_ref().is_some_and(|r| now >= r.until) {
                *r = None
            }
        }
        for row in 0..self.apps.len() {
            if let Some(app) = self.apps[row].as_ref() {
                let complete_request = self.complete_active_entry(app).is_some()
                    || self.complete_open_input(app).is_some();
                let expired = (!app.has_request && now >= app.until)
                    || (!complete_request && app.input_until.is_some_and(|u| now >= u))
                    || app.output.as_ref().is_some_and(|o| now >= o.until)
                    || app.rooms.iter().any(|l| {
                        l.proposal_until.is_some_and(|u| now >= u)
                            || l.sync_until.is_some_and(|u| now >= u)
                    })
                    || app.rooms.iter().any(|l| {
                        matches!(l.phase, LeasePhase::Opening | LeasePhase::Entering)
                            && now >= l.until
                    });
                if expired {
                    self.close_app(row, CloseCause::Deadline, observe);
                    return Ok(true);
                }
            }
        }
        let pending = self.cadet.pending_transmit();
        if self.cadet_pending.as_ref().map(|(t, _)| *t) != pending {
            self.cadet_pending = pending.map(|t| (t, now + self.limits.operation_lifetime));
        }
        if self.peer_output.as_ref().is_some_and(|o| now >= o.until)
            || self.cadet_pending.is_some_and(|(_, until)| now >= until)
        {
            // Shared CADET MQ has no per-frame physical cancellation. Retire this exact
            // original MQ before invalidating channels; never replay an exposed frame.
            let original = self.cadet.reconnect()?;
            if let cadet::Step::Lost { report, cause, .. } = original {
                self.cadet_lost(Some(report), Some(cause), observe)?;
            } else {
                return Err(Fault::Conflict.into());
            }
            return Ok(true);
        }
        for i in 0..self.received.len() {
            if self.received[i].as_ref().is_some_and(|r| now >= r.until) {
                let channel = self.received[i]
                    .as_ref()
                    .ok_or(Fault::Stale)?
                    .input
                    .channel();
                self.received[i] = None;
                if let Some(t) = self
                    .tunnels
                    .iter_mut()
                    .flatten()
                    .find(|t| t.channel == channel)
                {
                    t.closing = true
                }
                return Ok(true);
            }
        }
        for i in 0..self.tunnels.len() {
            if let Some(t) = self.tunnels[i].as_mut()
                && !t.compatible
                && !t.closing
                && now >= t.until
            {
                t.closing = true;
                let channel = t.channel;
                self.discard_tunnel_input(channel);
                return Ok(true);
            }
        }
        for i in 0..self.tasks.len() {
            if self.tasks[i].as_ref().is_some_and(|t| now >= t.until) {
                let task = self.tasks[i].take().ok_or(Fault::Stale)?;
                match task.destination {
                    Destination::App { client, .. } => {
                        if let Some(row) = self
                            .apps
                            .iter()
                            .position(|a| a.as_ref().is_some_and(|a| a.client.serial == client))
                        {
                            self.close_app(row, CloseCause::Deadline, observe)
                        }
                    }
                    Destination::Peer(channel) => {
                        if let Some(t) = self
                            .tunnels
                            .iter_mut()
                            .flatten()
                            .find(|t| t.channel == channel)
                        {
                            t.closing = true
                        }
                        self.discard_tunnel_input(channel);
                    }
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn core_step(&mut self) -> Result<bool, Error> {
        if self.history_frozen() {
            return Ok(false);
        }
        self.drain_events();
        for n in 0..self.rooms.len() {
            let i = (self.room_cursor + n) % self.rooms.len();
            let Some(r) = self.rooms[i].as_ref() else {
                continue;
            };
            let room = r.room;
            let n = self.core.advance(room, self.last_now)?;
            self.drain_events();
            if n > 0 {
                self.room_cursor = (i + 1) % self.rooms.len();
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn accept_poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.apps.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let row = (self.listener_cursor + n) % listeners.len();
            match listeners[row].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(Event::Socket(self.accept.failed(e)));
                    self.listener_cursor = (row + 1) % listeners.len();
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(a)) => {
                    self.listener_cursor = (row + 1) % listeners.len();
                    self.admit(a, observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if self.shutdown == Some(ShutdownMode::Immediate) {
            self.close_all(observe);
            return Poll::Ready(Ok(Progress::Closed));
        }
        if self.expire_requests(Instant::now(), observe) {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Poll::Ready(sample) = self.subscription.poll_changed(cx, self.revision) {
            let sample = sample?;
            self.revision = sample.revision;
        }
        self.drain_events();
        let sample = self.ports.clock.sample()?;
        self.last_now = sample.now.as_micros();
        self.revision = sample.revision;
        if self.expired(observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        for n in 0..7 {
            let class = (self.class + n) % 7;
            let result = match class {
                0 => self.accept_poll(cx, listeners, observe),
                1 => {
                    let mut result = Poll::Pending;
                    for n in 0..self.apps.len() {
                        let row = (self.app_cursor + n) % self.apps.len();
                        if self.apps[row].is_none() {
                            continue;
                        }
                        match self.app_poll(cx, row, observe) {
                            Poll::Pending => {}
                            p => {
                                self.app_cursor = (row + 1) % self.apps.len();
                                result = p;
                                break;
                            }
                        }
                    }
                    result
                }
                2 => self.cadet_poll(cx, observe),
                3 => self.signer_poll(cx, observe),
                4 => match self.relay_step(observe) {
                    Ok(true) => Poll::Ready(Ok(Progress::Activity)),
                    Ok(false) => Poll::Pending,
                    Err(e) if busy(&e) => Poll::Pending,
                    Err(e) => Poll::Ready(Err(e)),
                },
                5 => match self.core_step() {
                    Ok(true) => Poll::Ready(Ok(Progress::Activity)),
                    Ok(false) => Poll::Pending,
                    Err(e) => Poll::Ready(Err(e)),
                },
                _ => self.history_poll(cx, observe),
            };
            if result.is_ready() {
                self.class = (class + 1) % 7;
                return result;
            }
        }
        let now = Instant::now();
        if until.is_some_and(|u| now >= u) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        // Fixed finite scheduler tick also checks original dependency/input deadlines
        // when an inactive service/source has no current FD readiness notification.
        let wake = until.map_or(now + Duration::from_millis(20), |u| {
            u.min(now + Duration::from_millis(20))
        });
        let wake = self
            .history
            .as_ref()
            .and_then(crate::history::History::deadline)
            .filter(|deadline| *deadline > now)
            .map_or(wake, |deadline| wake.min(deadline));
        let wake = self
            .identity_deadline()
            .map_or(wake, |deadline| wake.min(deadline));
        let wake = self
            .apps
            .iter()
            .flatten()
            .flat_map(|app| {
                app.entry_input
                    .map(|input| input.until)
                    .into_iter()
                    .chain(app.open_input.map(|input| input.until))
                    .chain(app.rooms.iter().flat_map(|lease| {
                        lease
                            .pending_entry
                            .map(|pending| pending.request.until)
                            .into_iter()
                            .chain(lease.pending_open.map(|pending| pending.request.until))
                    }))
            })
            .min()
            .map_or(wake, |deadline| wake.min(deadline));
        self.timer.as_mut().reset(wake);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// Fair bounded caller polling. Future cancellation leaves every original
    /// native cursor and signing job owned here; it never sends a fictitious ACK.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.poll_inner(cx, listeners, until, observe);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.close_all(observe);
        }
        if matches!(&result, Poll::Ready(Ok(Progress::Activity))) {
            self.yield_due = true
        }
        result
    }
    /// Drive the same owner, without a hidden task or implicit Resolver.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, until, observe)).await
    }
}
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Drop for Server<'c, 'slots, 'p, E, O> {
    fn drop(&mut self) {
        self.close_all(&mut |_| {});
    }
}
