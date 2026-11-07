use super::*;
impl<'id, 'port> Owner<'id, 'port> {
    pub(super) fn sources(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        // A bounded monitor fence can fill under continuous mutations. Really
        // retire the older snapshot before freeing its fence, never silently
        // allow an old row to supersede a newer live monitor observation.
        if self.core.fence_pressure() && self.inventory.is_some() {
            self.stop_stream(Kind::Inventory)?;
            return Ok(Some(Event::Activity));
        }
        if self.monitor.is_none() && self.monitor_retry.is_none() {
            let bounds = Bound::after(now, self.limits.source_lifetime)?;
            let native = namestore::Monitor::new(
                self.ids.namestore,
                self.monitor_source.duplicate()?,
                None,
                false,
                0,
                bounds.expires,
                self.limits.namestore,
            )?;
            let operation = native.operation();
            let source = match self.core.source_started(Kind::Monitor, now) {
                Ok(source) => source,
                Err(Fault::Capacity) => {
                    drop(native);
                    self.delay()?;
                    return Ok(Some(Event::Backpressure));
                }
                Err(error) => return Err(error.into()),
            };
            self.monitor = Some(native);
            self.monitor_state = Some(Stream {
                source,
                kind: Kind::Monitor,
                operation,
                epoch: None,
                bounds,
                initial: Some(
                    Instant::now()
                        .checked_add(self.limits.control_timeout)
                        .ok_or(Fault::Overflow)?
                        .min(bounds.hard),
                ),
                partial: None,
                control: None,
                intent: None,
                pending: None,
                terminal: None,
                started: false,
                synchronized: false,
                seen: 0,
                started_at: now,
            });
            return Ok(Some(Event::Admitted));
        }
        if self.inventory.is_none()
            && self.inventory_retry.is_none()
            && now >= self.core.inventory_at()
            && self
                .monitor_state
                .as_ref()
                .is_some_and(|s| s.synchronized && s.terminal.is_none())
        {
            let bounds = Bound::after(now, self.limits.source_lifetime)?;
            let native = namestore::ZoneIterator::new(
                self.ids.namestore,
                self.inventory_source.duplicate()?,
                None,
                0,
                bounds.expires,
                self.limits.namestore,
            )?;
            let operation = native.operation();
            let source = match self.core.source_started(Kind::Inventory, now) {
                Ok(source) => source,
                Err(Fault::Capacity) => {
                    drop(native);
                    self.delay()?;
                    return Ok(Some(Event::Backpressure));
                }
                Err(error) => return Err(error.into()),
            };
            self.inventory = Some(native);
            self.metrics.bump(Counter::Iterations);
            self.inventory_state = Some(Stream {
                source,
                kind: Kind::Inventory,
                operation,
                epoch: None,
                bounds,
                initial: Some(
                    Instant::now()
                        .checked_add(self.limits.control_timeout)
                        .ok_or(Fault::Overflow)?
                        .min(bounds.hard),
                ),
                partial: None,
                control: None,
                intent: None,
                pending: None,
                terminal: None,
                started: false,
                synchronized: false,
                seen: 0,
                started_at: now,
            });
            return Ok(Some(Event::Admitted));
        }
        for kind in [Kind::Monitor, Kind::Inventory] {
            if self
                .state(kind)
                .is_some_and(|s| !s.bounds.live(now) && s.terminal.is_none())
            {
                self.stop_stream(kind)?;
                return Ok(Some(Event::Activity));
            }
        }
        self.credits(now)
    }
    fn granted(&self, kind: Kind) -> u64 {
        match kind {
            Kind::Monitor => self.monitor.as_ref().map_or(0, namestore::Monitor::credit),
            Kind::Inventory => self
                .inventory
                .as_ref()
                .map_or(0, namestore::ZoneIterator::credit),
        }
    }
    fn projected(&self, kind: Kind) -> u64 {
        self.granted(kind)
            .saturating_add(self.state(kind).map_or(0, |s| {
                s.intent.as_ref().map_or(0, |i| i.limit)
                    + s.control.as_ref().map_or(0, |(_, _, n)| *n)
            }))
    }
    fn credits(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        let occupied = self
            .projected(Kind::Monitor)
            .saturating_add(self.projected(Kind::Inventory));
        let free = u64::try_from(self.core.capacity())
            .map_err(|_| Fault::Overflow)?
            .saturating_sub(occupied);
        for kind in [Kind::Monitor, Kind::Inventory] {
            let Some(state) = self.state(kind) else {
                continue;
            };
            if !state.started
                || state.pending.is_some()
                || state.terminal.is_some()
                || state.control.is_some()
            {
                continue;
            }
            if kind == Kind::Inventory && self.credit_at.is_some_and(|at| at > now) {
                continue;
            }
            if state.intent.is_none() {
                let desired = if kind == Kind::Monitor {
                    self.limits
                        .monitor_credit
                        .saturating_sub(self.projected(kind))
                } else {
                    if self.granted(kind) > 0 {
                        0
                    } else {
                        self.limits.batch
                    }
                };
                let amount = free.min(desired);
                if amount == 0 {
                    continue;
                }
                let original = Bound::after(now, self.limits.control_timeout)?;
                let bounds = Bound {
                    expires: original.expires.min(state.bounds.expires),
                    hard: original.hard.min(state.bounds.hard),
                };
                self.state_mut(kind).ok_or(Fault::Stale)?.intent = Some(Intent {
                    limit: amount,
                    bounds,
                });
            }
            let intent = self
                .state(kind)
                .and_then(|s| s.intent.as_ref())
                .ok_or(Fault::Conflict)?;
            if !intent.bounds.live(now) {
                self.stop_stream(kind)?;
                return Ok(Some(Event::Activity));
            }
            let limit = intent.limit;
            let bounds = intent.bounds;
            let result = match kind {
                Kind::Monitor => self
                    .monitor
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .next(limit, bounds.expires),
                Kind::Inventory => self
                    .inventory
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .next(limit, bounds.expires),
            };
            match result {
                Ok(control) => {
                    let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                    state.intent = None;
                    state.control = Some((control, bounds, limit));
                    return Ok(Some(Event::Admitted));
                }
                Err(e) if retryable(&e) => {
                    self.delay()?;
                    return Ok(Some(Event::Backpressure));
                }
                Err(e) => {
                    self.stop_stream(kind)?;
                    self.failure(e.into());
                    return Ok(Some(Event::Activity));
                }
            }
        }
        Ok(None)
    }
    pub(super) fn stream_progress(
        &mut self,
        kind: Kind,
        p: namestore::Progress<'id>,
        now: u64,
    ) -> Result<Event, Failure> {
        if self.state(kind).is_none_or(|s| s.kind != kind) {
            return Err(Fault::Stale.into());
        }
        match p {
            namestore::Progress::Connected(epoch) => {
                let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                if state.epoch.is_some() {
                    return Err(Fault::Conflict.into());
                }
                state.epoch = Some(epoch);
                Ok(Event::Activity)
            }
            namestore::Progress::Written {
                epoch, operation, ..
            } => {
                let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                if state.epoch != Some(epoch) || state.operation != operation {
                    return Err(Fault::Stale.into());
                }
                state.started = true;
                Ok(Event::Activity)
            }
            namestore::Progress::Synchronized { epoch, operation } => {
                let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                if state.epoch != Some(epoch)
                    || state.operation != operation
                    || kind != Kind::Monitor
                {
                    return Err(Fault::Stale.into());
                }
                state.synchronized = true;
                state.initial = None;
                state.partial = None;
                Ok(Event::Activity)
            }
            namestore::Progress::Record {
                epoch,
                operation,
                reply,
            } => {
                if kind == Kind::Monitor {
                    self.metrics.bump(Counter::Monitor);
                }
                let timeout = Duration::from_micros(self.pure.job_timeout);
                let bounds = Bound::after(now, timeout)?;
                let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                if state.epoch != Some(epoch)
                    || state.operation != operation
                    || !state.started
                    || state.pending.is_some()
                {
                    return Err(Fault::Stale.into());
                }
                state.initial = None;
                state.partial = None;
                state.pending = Some(Pending {
                    reply,
                    received: now,
                    bounds,
                });
                Ok(Event::Record)
            }
            namestore::Progress::ControlQueued { epoch, control, .. } => {
                let state = self.state(kind).ok_or(Fault::Stale)?;
                if state.epoch != Some(epoch)
                    || state
                        .control
                        .as_ref()
                        .is_none_or(|(original, _, _)| *original != control)
                {
                    return Err(Fault::Stale.into());
                }
                Ok(Event::Activity)
            }
            namestore::Progress::ControlWritten { epoch, control, .. } => {
                let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                if state.epoch != Some(epoch)
                    || state
                        .control
                        .as_ref()
                        .is_none_or(|(original, _, _)| *original != control)
                {
                    return Err(Fault::Stale.into());
                }
                let amount = state.control.as_ref().map_or(0, |(_, _, n)| *n);
                state.control = None;
                if kind == Kind::Inventory && !self.first_inventory {
                    let delay = self
                        .core
                        .publication_delay()
                        .saturating_mul(amount)
                        .min(900_000_000)
                        .min(self.core.publication_window());
                    self.credit_at = Some(now.saturating_add(delay));
                    self.metrics.set(Counter::Delay, delay / amount.max(1));
                }
                Ok(Event::Activity)
            }
            namestore::Progress::Activity { read_bytes, .. } => {
                if read_bytes > 0 {
                    let at = Instant::now()
                        .checked_add(self.limits.control_timeout)
                        .ok_or(Fault::Overflow)?;
                    let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                    if state.partial.is_none() {
                        state.partial = Some(at.min(state.bounds.hard));
                    }
                }
                Ok(Event::Activity)
            }
            namestore::Progress::Completed(_) | namestore::Progress::Lost { .. } => {
                let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                state.initial = None;
                state.partial = None;
                state.control = None;
                state.intent = None;
                state.terminal = Some(p);
                Ok(Event::Activity)
            }
            namestore::Progress::ConnectRetry { error, .. } => {
                self.delay()?;
                Ok(Event::Failure(Box::new(error)))
            }
            namestore::Progress::Unavailable(error) => {
                self.stop_stream(kind)?;
                self.delay()?;
                Ok(Event::Failure(error.into()))
            }
            namestore::Progress::Ignored { .. } => {
                self.state_mut(kind).ok_or(Fault::Stale)?.partial = None;
                Ok(Event::Activity)
            }
            namestore::Progress::Queued { .. } | namestore::Progress::WaitDeadline => {
                Ok(Event::Activity)
            }
            namestore::Progress::Closed => {
                self.stop_stream(kind)?;
                Ok(Event::Activity)
            }
        }
    }
    pub(super) fn terminals(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        for kind in [Kind::Monitor, Kind::Inventory] {
            let terminal = self.state_mut(kind).and_then(|s| s.terminal.take());
            let Some(p) = terminal else { continue };
            let source = self.state(kind).ok_or(Fault::Stale)?.source;
            let complete = if let namestore::Progress::Completed(c) = &p {
                let state = self.state(kind).ok_or(Fault::Stale)?;
                if c.operation != state.operation || c.epoch != state.epoch {
                    return Err(Fault::Stale.into());
                }
                match &c.outcome {
                    namestore::Outcome::Reply(reply) => {
                        matches!(reply.view()?, namestore::ipc::Response::End { .. })
                            && kind == Kind::Inventory
                    }
                    namestore::Outcome::Local { .. } => false,
                }
            } else {
                false
            };
            if complete {
                self.metrics
                    .set(Counter::Public, self.core.last_inventory_count());
                self.core.source_finished(source, true, now)?;
                self.first_inventory = false;
                if let Some(mut native) = self.inventory.take() {
                    let _actual = native.close();
                }
                self.inventory_state = None;
            } else {
                if kind == Kind::Monitor {
                    self.metrics.bump(Counter::MonitorErrors);
                }
                self.stop_stream(kind)?;
                if let namestore::Progress::Lost { cause, .. } = p {
                    self.failure(format!("zonemaster original NAMESTORE source: {cause:?}").into());
                }
            }
            return Ok(Some(Event::Activity));
        }
        Ok(None)
    }
    pub(super) fn records(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        for kind in [Kind::Monitor, Kind::Inventory] {
            if self.core.capacity() == 0 {
                continue;
            }
            let Some((source, pending)) = self
                .state_mut(kind)
                .and_then(|s| s.pending.take().map(|p| (s.source, p)))
            else {
                continue;
            };
            if !pending.bounds.live(now) {
                self.stop_stream(kind)?;
                return Ok(Some(Event::Activity));
            }
            let view = pending.reply.view()?;
            let namestore::ipc::Response::Records {
                zone,
                label,
                expires,
                records,
                ..
            } = view
            else {
                return Err(Fault::Malformed.into());
            };
            if !label.is_canonical() {
                self.stop_stream(kind)?;
                return Ok(Some(Event::Failure(Fault::Malformed.into())));
            }
            let key = gnunet_identity::SecretKey::from_serialized(zone.expose_serialized())?;
            let count = records.count();
            let bounds = pending.bounds;
            let prepared = match material::prepare(
                material::Input {
                    zone,
                    label: label.bytes(),
                    records: records.records(),
                    source_expiry: expires.as_micros(),
                },
                pending.received,
                self.limits.material,
                gnunet_gnsrecord_text::is_critical,
                if self.cache.is_some() {
                    material::Destinations::PublicAndLocal
                } else {
                    material::Destinations::PublicOnly
                },
            ) {
                Ok(p) => p,
                Err(error) => {
                    self.failure(error.into());
                    return Ok(Some(Event::Record));
                }
            };
            let result = self.core.submit(
                schedule::Submission {
                    source,
                    key: &key,
                    label: label.bytes(),
                    prepared,
                    expires: bounds.expires,
                },
                now,
            );
            match result {
                Ok(job) => {
                    if kind == Kind::Inventory && count > 0 {
                        let state = self.state_mut(kind).ok_or(Fault::Stale)?;
                        state.seen = state.seen.saturating_add(1);
                    }
                    if let Some(job) = job {
                        if self.jobs.len() >= self.jobs.capacity() {
                            return Err(Fault::Capacity.into());
                        }
                        self.jobs.push(JobRow {
                            job,
                            source,
                            bounds,
                            ticket: None,
                            worker_returned: false,
                            worker_result: None,
                            cache: None,
                            public: false,
                            cancelled: false,
                            cancel_started: false,
                            native_retired: false,
                        });
                    }
                    if kind == Kind::Monitor
                        && let Some(at) = self.credit_at
                    {
                        self.credit_at =
                            Some(at.min(now.saturating_add(self.core.publication_window())));
                    }
                    return Ok(Some(Event::Record));
                }
                Err(Fault::Capacity) => {
                    self.state_mut(kind).ok_or(Fault::Stale)?.pending = Some(pending);
                    self.delay()?;
                    return Ok(Some(Event::Backpressure));
                }
                Err(error) => {
                    self.failure(error.into());
                    return Ok(Some(Event::Record));
                }
            }
        }
        Ok(None)
    }
}
