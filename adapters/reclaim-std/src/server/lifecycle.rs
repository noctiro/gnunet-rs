use super::*;
impl<'n, 'g> Server<'n, 'g> {
    fn retirement_target(&self, tag: Tag) -> Result<Instant, Error> {
        let hard = self
            .entry(tag)?
            .hard
            .checked_add(self.limits.retirement_grace)
            .ok_or(Fault::Overflow)?;
        Ok(Instant::now()
            .checked_add(self.limits.retirement_grace)
            .ok_or(Fault::Overflow)?
            .min(hard))
    }
    fn maintain(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        let mut changed = false;
        let native = Instant::now();
        let now = self.last_now;
        for entry in self.jobs.iter_mut().flatten() {
            entry.job.expire(now);
            if native >= entry.hard {
                entry.job.expire(entry.job.deadline());
            }
            if entry.job.response().is_some() && entry.output_until.is_none() {
                entry.output_until = Some(
                    native
                        .checked_add(self.limits.output_lifetime)
                        .ok_or(Fault::Overflow)?,
                );
            }
        }
        let mut close = None;
        for (row, peer) in self.peers.iter().enumerate() {
            let Some(peer) = peer else { continue };
            if peer.first && native >= peer.first_until
                || peer.input_until.is_some_and(|t| native >= t)
            {
                close = Some((row, CloseCause::Deadline));
                break;
            }
            let mut has_jobs = false;
            for entry in self
                .jobs
                .iter()
                .flatten()
                .filter(|e| e.client.as_ref() == Some(&peer.client))
            {
                has_jobs = true;
                if entry.output_until.is_some_and(|t| native >= t) {
                    close = Some((row, CloseCause::Deadline));
                    break;
                }
                if !entry.stopped
                    && entry.job.response().is_none()
                    && let Some(end) = entry.job.status().end
                    && end != End::Complete
                {
                    close = Some((row, CloseCause::Provider(end)));
                    break;
                }
            }
            if close.is_some() {
                break;
            }
            if self.shutdown.is_some() && !has_jobs {
                close = Some((row, CloseCause::Shutdown));
                break;
            }
        }
        if let Some((row, cause)) = close {
            self.close_peer(row, cause, observe);
            changed = true;
        }
        if self.scan.as_ref().is_some_and(|scan| {
            self.entry(scan.tag)
                .is_ok_and(|entry| entry.job.status().end.is_some())
        }) {
            let scan = self.scan.take().ok_or(Fault::Stale)?;
            self.close_scan(scan, Fault::Cancelled, observe)?;
            changed = true;
        }
        if let Some((tag, operation, cancelling)) = self
            .ns_active
            .as_ref()
            .map(|a| (a.binding.tag, a.operation, a.binding.cancelling))
        {
            let cancel = self.entry(tag)?.job.status().end.is_some();
            if cancel && !cancelling {
                let target = self.retirement_target(tag)?;
                self.ns.cancel(operation)?;
                let active = self.ns_active.as_mut().ok_or(Fault::Stale)?;
                active.binding.cancelling = true;
                active.binding.retire_at = Some(target);
                changed = true;
            }
            if self.ns_active.as_ref().is_some_and(|a| {
                a.binding.retire_at.is_some_and(|t| native >= t) && !a.binding.forced
            }) {
                self.ns_active.as_mut().ok_or(Fault::Stale)?.binding.forced = true;
                let event = self.ns.reconnect()?;
                self.namestore_event(event, observe)?;
                self.report.forced = self.report.forced.saturating_add(1);
                changed = true;
            }
        }
        if let Some((tag, query, cancelling)) = self
            .gns_active
            .as_ref()
            .map(|a| (a.binding.tag, a.query, a.binding.cancelling))
        {
            let cancel = self.entry(tag)?.job.status().end.is_some();
            if cancel && !cancelling {
                let target = self.retirement_target(tag)?;
                if self.gns.live(query) {
                    self.gns.cancel(query)?;
                }
                let active = self.gns_active.as_mut().ok_or(Fault::Stale)?;
                active.binding.cancelling = true;
                active.binding.retire_at = Some(target);
                changed = true;
            }
            if self
                .gns_active
                .as_ref()
                .is_some_and(|a| a.binding.cancelling)
                && self.gns.pending_writes() == 0
            {
                let active = self.gns_active.take().ok_or(Fault::Stale)?;
                let result = (|| {
                    if self.entry(active.binding.tag)?.job.status().provider_debt {
                        self.entry_mut(active.binding.tag)?
                            .job
                            .retired(&active.binding.effect, &active.binding.source)?;
                    }
                    self.progress(active.binding.tag, observe)
                })();
                if result.is_err() {
                    self.gns_active = Some(active);
                }
                result?;
                changed = true;
            } else if self.gns_active.as_ref().is_some_and(|a| {
                a.binding.retire_at.is_some_and(|t| native >= t) && !a.binding.forced
            }) {
                self.gns_active.as_mut().ok_or(Fault::Stale)?.binding.forced = true;
                let event = self.gns.reconnect()?;
                self.gns_event(event, observe)?;
                self.report.forced = self.report.forced.saturating_add(1);
                changed = true;
            }
        }
        if let Some(tag) = self.writer {
            let release = self.entry(tag).is_err()
                || self.entry(tag).is_ok_and(|e| {
                    !e.job.status().provider_debt
                        && (e.job.status().end.is_some() || e.job.response().is_some())
                });
            if release {
                self.writer = None;
                changed = true;
            }
        }
        for row in 0..self.jobs.len() {
            let remove = self.jobs[row].as_ref().is_some_and(|e| {
                e.job.quiescent()
                    && !self
                        .ns_active
                        .as_ref()
                        .is_some_and(|a| a.binding.tag == e.tag)
                    && !self
                        .gns_active
                        .as_ref()
                        .is_some_and(|a| a.binding.tag == e.tag)
                    && !self.scan.as_ref().is_some_and(|s| s.tag == e.tag)
            });
            if remove {
                let entry = self.jobs[row].take().ok_or(Fault::Stale)?;
                if entry.job.status().outcome_unknown {
                    self.report.unknown = self.report.unknown.saturating_add(1);
                }
                changed = true;
            }
        }
        Ok(changed)
    }
    fn stop_backends(&mut self, observe: &mut impl FnMut(Event)) {
        // Native owner closure happens BEFORE any pure retirement callback. None
        // of these paths samples a clock or pretends close is a remote receipt.
        let ns_report = self.ns.close();
        let _gns_report = self.gns.close();
        if let Some((_, source)) = self.ns_source.take() {
            source.lost();
        }
        if let Some((_, source)) = self.gns_source.take() {
            source.lost();
        }
        if let Some(scan) = self.scan.take()
            && let Err(error) = self.close_scan(scan, Fault::Closed, observe)
        {
            observe(Event::Cleanup(match error {
                Error::Protocol(e) | Error::Clock(e) => e,
                _ => Fault::Io,
            }));
        }
        if let Some(active) = self.ns_active.take() {
            active.binding.source.lost();
            let now = self.last_now;
            let any_exposed = active.binding.sent > 0 || ns_report.is_some_and(|r| r.exposed > 0);
            if let Ok(entry) = self.entry_mut(active.binding.tag)
                && entry.job.status().provider_debt
            {
                let completion = if let Some(code) = active.known_code {
                    Completion::Stored(code)
                } else if any_exposed {
                    Completion::Unknown
                } else {
                    Completion::Failed(Fault::Closed)
                };
                if let Err(error) = entry.job.complete(
                    &active.binding.effect,
                    &active.binding.source,
                    completion,
                    now,
                ) {
                    observe(Event::Cleanup(error));
                }
            }
            if let Err(error) = self.progress(active.binding.tag, observe) {
                observe(Event::Cleanup(match error {
                    Error::Protocol(e) | Error::Clock(e) => e,
                    _ => Fault::Io,
                }));
            }
            self.report.forced = self.report.forced.saturating_add(1);
        }
        if let Some(active) = self.gns_active.take() {
            active.binding.source.lost();
            if let Ok(entry) = self.entry_mut(active.binding.tag)
                && entry.job.status().provider_debt
                && let Err(error) = entry
                    .job
                    .retired(&active.binding.effect, &active.binding.source)
            {
                observe(Event::Cleanup(error));
            }
            if let Err(error) = self.progress(active.binding.tag, observe) {
                observe(Event::Cleanup(match error {
                    Error::Protocol(e) | Error::Clock(e) => e,
                    _ => Fault::Io,
                }));
            }
            self.report.forced = self.report.forced.saturating_add(1);
        }
    }
    /// Close every real app/provider owner independently of clock/Resolver health.
    /// Preserve proven/unknown original mutation outcomes; no remote rollback,
    /// GNS cache flush or successful consumer delivery is claimed.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event)) -> Report {
        self.shutdown = Some(ShutdownMode::Immediate);
        for row in 0..self.peers.len() {
            self.close_peer(row, CloseCause::Shutdown, observe);
        }
        self.stop_backends(observe);
        for entry in self.jobs.iter_mut().flatten() {
            entry.client = None;
            entry.job.output_lost();
        }
        for entry in &mut self.jobs {
            if let Some(entry) = entry.take() {
                if entry.job.status().outcome_unknown {
                    self.report.unknown = self.report.unknown.saturating_add(1);
                }
                if entry.job.status().provider_debt {
                    observe(Event::Cleanup(Fault::OutcomeUnknown));
                }
            }
        }
        self.identity.lost();
        self.entropy.lost();
        self.credential.lost();
        self.writer = None;
        self.closed = true;
        self.report
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(Error::Clock(error))),
            Poll::Ready(Ok(sample)) => self.revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = self.ports.clock.sample().map_err(Error::Clock)?;
        if sample.now.as_micros() < self.last_now {
            return Poll::Ready(Err(Error::Clock(Fault::TimeUncertain)));
        }
        self.revision = sample.revision;
        self.last_now = sample.now.as_micros();
        if self.shutdown == Some(ShutdownMode::Immediate) {
            self.close_all(observe);
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if self.maintain(observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown.is_some()
            && self.peers.iter().all(Option::is_none)
            && self.jobs.iter().all(Option::is_none)
        {
            self.stop_backends(observe);
            self.closed = true;
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if until.is_some_and(|t| Instant::now() >= t) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for n in 0..6 {
            let class = (self.class + n) % 6;
            let result = match class {
                0 => self.poll_namestore(cx, until, observe),
                1 => self.poll_gns(cx, until, observe),
                2 => self.poll_scan(cx, until, observe),
                3 => {
                    let mut result = Poll::Pending;
                    for n in 0..self.jobs.len() {
                        let row = (self.job_cursor + n) % self.jobs.len();
                        match self.offer(row, observe) {
                            Ok(true) => {
                                self.job_cursor = (row + 1) % self.jobs.len();
                                result = Poll::Ready(Ok(Progress::Activity));
                                break;
                            }
                            Ok(false) => {}
                            Err(error) => {
                                result = Poll::Ready(Err(error));
                                break;
                            }
                        }
                    }
                    result
                }
                4 => {
                    let mut result = Poll::Pending;
                    for n in 0..self.peers.len() {
                        let row = (self.peer_cursor + n) % self.peers.len();
                        if self.peers[row].is_some() {
                            let step = self.peer(cx, row, observe);
                            if step.is_ready() {
                                self.peer_cursor = (row + 1) % self.peers.len();
                                result = step;
                                break;
                            }
                        }
                    }
                    result
                }
                _ => self.accept_peer(cx, listeners, observe),
            };
            if result.is_ready() {
                self.class = (class + 1) % 6;
                return result;
            }
        }
        let mut target = until;
        let mut add = |t: Instant| {
            target = Some(target.map_or(t, |old| old.min(t)));
        };
        for peer in self.peers.iter().flatten() {
            if peer.first {
                add(peer.first_until)
            }
            if let Some(t) = peer.input_until {
                add(t)
            }
        }
        for entry in self.jobs.iter().flatten() {
            if entry.job.status().end.is_none() {
                add(entry.hard)
            }
            if let Some(t) = entry.output_until {
                add(t)
            }
        }
        for t in self
            .ns_retry
            .into_iter()
            .chain(self.gns_retry)
            .chain(
                self.ns_active
                    .as_ref()
                    .and_then(|a| a.binding.retire_at.filter(|_| !a.binding.forced)),
            )
            .chain(
                self.gns_active
                    .as_ref()
                    .and_then(|a| a.binding.retire_at.filter(|_| !a.binding.forced)),
            )
        {
            add(t)
        }
        if let Some(target) = target {
            self.timer.as_mut().reset(target);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    /// One fair bounded caller-driven turn. Dropping a waiting future preserves
    /// every original cursor/operation. Fatal errors close independent real MQs
    /// before returning the original failure, without requiring a clock sample.
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
            self.yield_due = true;
        }
        result
    }
    /// Wait by polling this exact owner. Cancellation is not an IO cancellation;
    /// close_client/close_all or the original finite deadlines retire IO.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, until, &mut observe)).await
    }
}
impl Drop for Server<'_, '_> {
    fn drop(&mut self) {
        self.close_all(&mut |_| {});
    }
}
