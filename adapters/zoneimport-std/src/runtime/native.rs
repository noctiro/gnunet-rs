//! Fair caller polling. Native bounds precede every canonical wait.
use super::*;
mod dns;
mod inventory;
mod store;
impl<'id> Runtime<'id> {
    /// Check and register the original native hard bounds, without reading the
    /// canonical clock or admitting new business. Real local terminals use the
    /// same original operation mapping as ordinary poll. Closing disables this
    /// gate so an already reported deadline cannot starve clock-free cleanup.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<Option<Progress>, Error> {
        if self.closing {
            return Ok(None);
        }
        if let Some(initial) = &mut self.initial
            && let Err(error) = initial.native_guard(cx)
        {
            self.initial = None;
            return Err(error.into());
        }
        // Register every live operation, even if another class is repeatedly
        // ready. An expired row is cancelled once; the actual source retains
        // any immutable partial suffix and publishes its true local result.
        for index in 0..self.pending.len() {
            let expired = match &mut self.pending[index] {
                Some(row) if !row.expired && !matches!(row.native, Native::Settled) => {
                    row.budget.native_guard(cx).is_err()
                }
                _ => false,
            };
            if expired {
                self.pending[index]
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .expired = true;
                self.expire(index, observe)?;
                return Ok(Some(Progress::Activity));
            }
        }
        if let Some(event) = self
            .namestore
            .as_mut()
            .and_then(|client| client.poll_native_guard(cx))
        {
            self.ns_event(event, observe)?;
            return Ok(Some(Progress::Activity));
        }
        for offset in 0..self.pending.len() {
            let index = (self.cursor + offset) % self.pending.len();
            let event = match self.pending[index].as_mut().map(|row| &mut row.native) {
                Some(Native::Scan(scan)) => scan.iterator.poll_native_guard(cx),
                _ => continue,
            };
            match event {
                Ok(Some(event)) => {
                    self.cursor = (index + 1) % self.pending.len();
                    self.scan_event(index, event, observe)?;
                    return Ok(Some(Progress::Activity));
                }
                Ok(None) => {}
                Err(error) => {
                    self.source_error(crate::SourceFailure::Iterator(namestore::LossCause::Ports(
                        error,
                    )));
                    self.scan_failed(index, observe)?;
                    return Ok(Some(Progress::Activity));
                }
            }
        }
        Ok(None)
    }
    fn expire(&mut self, index: usize, observe: &mut impl FnMut(Event<'_>)) -> Result<(), Error> {
        let mut row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
        observe(Event::Deadline {
            job: row.job.diagnostic(),
            kind: row.kind,
        });
        let immediate = match &mut row.native {
            Native::Deferred => Some(self.core.reject(&row.job)),
            Native::Query(query) => {
                if let Some(request) = query.request.take() {
                    self.dns.resolve_cancel(request)?;
                }
                if let Some(mut tcp) = query.tcp.take() {
                    let _original = tcp.cancel();
                    self.report.tcp_closed = self.report.tcp_closed.saturating_add(1);
                }
                Some(if row.retiring {
                    self.core.retired(&row.job, core::Retirement::Unsent)
                } else {
                    self.core.dns_failed(&row.job, core::ReadFailure::Deadline)
                })
            }
            Native::Scan(scan) => {
                let _original = scan.iterator.close();
                None
            }
            Native::Create { .. } => {
                // Physically retire this original single-operation source now,
                // without waiting for a canonical sample. Its retained Local
                // completion still settles this job. Reconnection only permits
                // later independent CREATE jobs; it cannot replay this one.
                if self.limits.identity.reconnect {
                    let event = self
                        .identity
                        .as_mut()
                        .ok_or(Fault::StaleGeneration)?
                        .reconnect()
                        .map_err(Error::Identity)?;
                    let identity::Progress::Lost { report, cause } = event else {
                        return Err(Fault::Conflict.into());
                    };
                    self.identity_disconnected(report, cause)?;
                } else if let Some(loss) = self.identity.as_mut().and_then(identity::Client::close)
                {
                    self.identity_loss(loss);
                }
                None
            }
            Native::Check { operation, .. }
            | Native::Delegate { operation }
            | Native::Store { operation, .. } => {
                self.namestore
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .cancel(*operation)?;
                None
            }
            Native::Settled => None,
        };
        if let Some(result) = immediate {
            if row.kind == Kind::Query {
                self.metrics.add(6, 1);
                self.query_outcome(&result, core::ReadFailure::Deadline);
            }
            self.finish_row(index, row, result)?;
        } else {
            self.pending[index] = Some(row);
        }
        Ok(())
    }
    fn activate(&mut self) -> Result<bool, Error> {
        if !self.sealed || self.identity.is_some() || self.closing {
            return Ok(false);
        }
        let lifetime = Duration::from_micros(self.core.policy().operation.as_micros());
        let budget = Budget::new(&self.clock, lifetime)?;
        let endpoint = self.ports.identity.duplicate()?;
        budget.check(&self.clock)?;
        let client =
            identity::Client::monitor(self.instances.identity, endpoint, self.limits.identity)
                .map_err(Error::Identity)?;
        self.initial = Some(budget);
        self.identity = Some(client);
        Ok(true)
    }
    pub(super) fn poll_owned(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
        closing: bool,
    ) -> Result<bool, Error> {
        // Rotate after every attempted class, including Pending. A ready output
        // or one busy iterator cannot hide another source's actual result.
        let classes = if closing { 5 } else { 6 };
        for offset in 0..classes {
            let class = (self.class + offset) % classes;
            let progressed = match class {
                0 => self.poll_identity(cx, observe)?,
                1 => self.poll_ns(cx, observe)?,
                2 => self.poll_scans(cx, observe)?,
                3 if !closing => self.poll_udp(cx, observe)?,
                4 if !closing => self.poll_tcp(cx, observe)?,
                5 if self.initialized => self.requested(observe)?,
                _ => false,
            };
            if progressed {
                self.class = (class + 1) % classes;
                return Ok(true);
            }
        }
        self.class = (self.class + 1) % classes;
        Ok(false)
    }
    fn wakeup(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if let Poll::Ready(result) = self.subscription.poll_changed(cx, self.revision) {
            self.revision = result?.revision;
        }
        let sample = self.clock.sample()?;
        let wake = self.core.next_wakeup();
        let mut at = wake
            .mono
            .map(|target| self.clock.native(target))
            .transpose()?;
        if let Some(target) = wake
            .absolute
            .filter(|target| target.as_micros() != u64::MAX)
        {
            let delta = target
                .as_micros()
                .saturating_sub(sample.absolute.as_micros());
            let logical = Instant::now()
                .checked_add(Duration::from_micros(delta))
                .ok_or(Fault::Overflow)?;
            at = Some(at.map_or(logical, |native| native.min(logical)));
        }
        if let Some(at) = at {
            if self.wake_at != Some(at) {
                self.wake.as_mut().reset(at);
                self.wake_at = Some(at);
            }
            let _registered = self.wake.as_mut().poll(cx);
        } else {
            self.wake_at = None;
        }
        self.metrics.set(
            13,
            self.pending
                .iter()
                .flatten()
                .filter_map(|row| match &row.native {
                    Native::Scan(scan) => usize::try_from(scan.iterator.credit()).ok(),
                    _ => None,
                })
                .fold(0usize, usize::saturating_add),
        );
        let facts = self.core.metrics();
        self.metrics.set(
            14,
            usize::try_from(facts.names.saturating_sub(facts.cache_hits)).unwrap_or(usize::MAX),
        );
        Ok(())
    }
    /// Drive the same original physical owners and at most one observable native
    /// step. Existing clients alone own loss-triggered backoff and new epochs;
    /// no hidden task, synthesized result, periodic reconnect or new clock.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Poll<Result<Progress, Error>> {
        if self.closing {
            return self.poll_close(cx, observe);
        }
        self.waiting = Some(cx.waker().clone());
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = (|| -> Result<Option<Progress>, Error> {
            if let Some(progress) = self.poll_native_guard(cx, observe)? {
                return Ok(Some(progress));
            }
            if !self.sealed {
                return Ok(None);
            }
            if self.activate()? {
                return Ok(Some(Progress::Activity));
            }
            let was_initialized = self.initialized;
            if self.poll_owned(cx, observe, false)? {
                return Ok(Some(if !was_initialized && self.initialized {
                    Progress::Initialized
                } else {
                    Progress::Activity
                }));
            }
            self.metrics.idle(self.core.pending_jobs() == 0);
            self.wakeup(cx)?;
            Ok(None)
        })();
        match result {
            Ok(Some(progress)) => {
                self.yield_due = true;
                Poll::Ready(Ok(progress))
            }
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}
