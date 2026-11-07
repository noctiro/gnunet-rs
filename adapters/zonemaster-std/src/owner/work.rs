use super::*;
impl<'id, 'port> Owner<'id, 'port> {
    pub(super) fn cancelled_work(&mut self) -> Result<Option<Event>, Failure> {
        for i in 0..self.jobs.len() {
            let job = self.jobs[i].job;
            if !self.jobs[i].cancelled && self.core.cancelled(job)? {
                self.jobs[i].cancelled = true;
            }
            if !self.jobs[i].cancelled {
                continue;
            }
            if !self.jobs[i].cancel_started {
                if let Some(ticket) = &self.jobs[i].ticket {
                    ticket.cancel();
                }
                if self.jobs[i].public {
                    if let Err(error) = self.publish.stop(job) {
                        self.failures.push(error)
                    }
                    self.jobs[i].public = false;
                    self.core.native_done(job, true, false)?;
                }
                if let Some(operation) = self.jobs[i].cache {
                    match self
                        .cache
                        .as_mut()
                        .ok_or(Fault::Unavailable)?
                        .cancel(operation)
                    {
                        Ok(namecache::Cancellation::Draining) => {}
                        Ok(_) => {
                            self.jobs[i].cache = None;
                            self.core.native_done(job, false, false)?;
                        }
                        Err(error) => {
                            // Unknown cancellation cannot drop an original suffix.
                            // Close this exact shared cache MQ, retaining every
                            // original affected job as a failed/local interest.
                            if let Some(cache) = &mut self.cache {
                                let actual = cache.reconnect()?;
                                self.cache_progress(actual)?;
                            }
                            self.failures.push(error.into());
                        }
                    }
                }
                self.jobs[i].cancel_started = true;
                self.core.cancellation_started(job)?;
                return Ok(Some(Event::Activity));
            }
            if let Some(returned) = self.jobs[i].worker_result.take() {
                drop(returned.result);
                self.core.worker_discarded(job)?;
            }
            if self.jobs[i].cache.is_none() && !self.jobs[i].public && !self.jobs[i].native_retired
            {
                self.core.cancelled_native(job)?;
                self.jobs[i].native_retired = true;
                return Ok(Some(Event::Activity));
            }
        }
        Ok(None)
    }
    pub(super) fn submit_work(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        if let Some(sealing) = self.core.take_sealing(now)? {
            let job = sealing.job;
            let row = self
                .jobs
                .iter()
                .find(|r| r.job == job)
                .ok_or(Fault::Stale)?;
            if !row.bounds.live(now) {
                self.core.return_sealing(sealing)?;
                self.core.cancel(job)?;
                return Ok(Some(Event::Activity));
            }
            match self.pool.submit(sealing, row.bounds.hard) {
                Ok(ticket) => {
                    self.jobs
                        .iter_mut()
                        .find(|r| r.job == job)
                        .ok_or(Fault::Stale)?
                        .ticket = Some(ticket);
                    return Ok(Some(Event::Admitted));
                }
                Err(rejected) => {
                    let error = rejected.reason;
                    self.core.return_sealing(rejected.value)?;
                    if matches!(error, Fault::WouldBlock | Fault::Capacity) {
                        self.delay()?;
                        return Ok(Some(Event::Backpressure));
                    }
                    return Err(error.into());
                }
            }
        }
        let public_ready = self.jobs.iter().filter(|r| r.public).count() < self.limits.publications;
        let cache_ready = !self.cache_blocked && self.cache.is_some();
        let Some(work) = self.core.next_work_ready(now, public_ready, cache_ready)? else {
            return Ok(None);
        };
        match work {
            Work::Finish { job } => {
                let i = self
                    .jobs
                    .iter()
                    .position(|r| r.job == job)
                    .ok_or(Fault::Stale)?;
                if self.jobs[i].ticket.is_some() && !self.jobs[i].worker_returned {
                    return Err(Fault::WouldBlock.into());
                }
                if self.jobs[i].public || self.jobs[i].cache.is_some() {
                    return Err(Fault::WouldBlock.into());
                }
                self.core.retired(job)?;
                self.jobs.remove(i);
                Ok(Some(Event::Activity))
            }
            Work::Cancel { job } => {
                let row = self
                    .jobs
                    .iter_mut()
                    .find(|r| r.job == job)
                    .ok_or(Fault::Stale)?;
                row.cancelled = true;
                Ok(Some(Event::Activity))
            }
            Work::Public {
                job,
                block,
                expires,
            } => {
                let row = self
                    .jobs
                    .iter()
                    .find(|r| r.job == job)
                    .ok_or(Fault::Stale)?;
                if !row.bounds.live(now) {
                    self.core.cancel(job)?;
                    return Ok(Some(Event::Activity));
                }
                let input = publish::Put {
                    public: block.retain(),
                    job,
                    block_type: 11,
                    replication: 5,
                    options: 1,
                    expires,
                    hard: row.bounds.hard,
                };
                match self.publish.put(input) {
                    Ok(()) => {
                        self.metrics.bump(Counter::Puts);
                        self.core.native_queued(job, true)?;
                        self.jobs
                            .iter_mut()
                            .find(|r| r.job == job)
                            .ok_or(Fault::Stale)?
                            .public = true;
                        Ok(Some(Event::Admitted))
                    }
                    Err(error) => {
                        // Port errors may follow admission. Physically retire that
                        // exact original job before marking local failure. Never
                        // replay or report the unknown frame as processed success.
                        if let Err(cleanup) = self.publish.stop(job) {
                            self.failures.push(cleanup)
                        }
                        self.failures.push(error);
                        self.core.native_refused(job, true)?;
                        Ok(Some(Event::Activity))
                    }
                }
            }
            Work::Cache {
                job,
                block,
                expires,
            } => {
                let row = self
                    .jobs
                    .iter()
                    .find(|r| r.job == job)
                    .ok_or(Fault::Stale)?;
                if !row.bounds.live(now) {
                    self.core.cancel(job)?;
                    return Ok(Some(Event::Activity));
                }
                let Some(cache) = &mut self.cache else {
                    return Err(Fault::Unavailable.into());
                };
                match cache.cache(block.bytes(), expires) {
                    Ok(operation) => {
                        self.metrics.bump(Counter::CachePushed);
                        self.core.native_queued(job, false)?;
                        self.jobs
                            .iter_mut()
                            .find(|r| r.job == job)
                            .ok_or(Fault::Stale)?
                            .cache = Some(operation);
                        Ok(Some(Event::Admitted))
                    }
                    Err(error) if retryable(&error) => {
                        self.delay()?;
                        Ok(Some(Event::Backpressure))
                    }
                    Err(error) => {
                        self.core.native_refused(job, false)?;
                        self.failures.push(error.into());
                        Ok(Some(Event::Activity))
                    }
                }
            }
        }
    }
}
