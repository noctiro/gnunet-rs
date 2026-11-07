use super::*;
use gnunet_identity::SecretKey;
use gnunet_wire::official::namestore as wire;
impl<'n, 'g> Server<'n, 'g> {
    pub(super) fn progress(
        &mut self,
        tag: Tag,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let status = self.entry(tag)?.job.status();
        self.report.completions = self.report.completions.saturating_add(1);
        observe(Event::ProviderResult {
            job: tag.serial,
            status,
        });
        Ok(())
    }
    fn exposure<T>(
        &mut self,
        binding: &mut Native<T>,
        bytes: usize,
        whole: bool,
    ) -> Result<(), Error> {
        if bytes < binding.sent || bytes > binding.total {
            return Err(Fault::Conflict.into());
        }
        let entry = self.entry_mut(binding.tag)?;
        if bytes > binding.sent {
            let delta = bytes - binding.sent;
            binding.sent = bytes;
            entry.job.exposed(&binding.effect, &binding.source, delta)?;
        }
        if whole {
            entry
                .job
                .written(&binding.effect, &binding.source, binding.total)?;
        }
        Ok(())
    }
    pub(super) fn offer(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let Some(entry) = self.jobs[index].as_ref() else {
            return Ok(false);
        };
        if entry.client.is_none() || entry.job.status().end.is_some() {
            return Ok(false);
        }
        let Some(prepared) = entry.job.prepared()? else {
            return Ok(false);
        };
        if !entry.readonly {
            if self.writer.is_some_and(|tag| tag != entry.tag) {
                return Ok(false);
            }
            self.writer = Some(entry.tag);
        }
        let tag = entry.tag;
        let effect = prepared.effect.clone();
        let deadline = prepared.deadline;
        let now = self.last_now;
        match prepared.action {
            Action::PublicKey { .. } | Action::Identifier | Action::Presentation { .. } => {
                let source = match prepared.action {
                    Action::PublicKey { .. } => self.identity.clone(),
                    Action::Identifier => self.entropy.clone(),
                    _ => self.credential.clone(),
                };
                let entry = self.jobs[index].as_mut().ok_or(Fault::Stale)?;
                let actual = self.providers.run(&mut entry.job, &source, now);
                if let Some(cause) = self.providers.take_failure() {
                    observe(Event::SystemFailed {
                        job: tag.serial,
                        cause,
                    });
                }
                actual?;
                self.report.submitted = self.report.submitted.saturating_add(1);
                observe(Event::Submitted {
                    job: tag.serial,
                    provider: source.provider(),
                });
                self.progress(tag, observe)?;
                Ok(true)
            }
            Action::Scan { key } => {
                if self.scan.is_some() {
                    return Ok(false);
                }
                let key = SecretKey::from_serialized(key.expose_serialized())?;
                let iterator = ns::ZoneIterator::new(
                    self.ns_instance,
                    self.ports.namestore.duplicate()?,
                    Some(&key),
                    1,
                    deadline,
                    self.ns_limits,
                )?;
                self.scan = Some(Scan {
                    tag,
                    effect,
                    iterator,
                    source: None,
                    epoch: None,
                    total: wire::ITERATE_PREFIX + gnunet_identity::KEY_LEN,
                    sent: 0,
                });
                Ok(true)
            }
            Action::Store {
                key,
                label,
                records,
            } => {
                if self.ns_active.is_some() {
                    return Ok(false);
                }
                let Some((epoch, source)) = self
                    .ns_source
                    .as_ref()
                    .filter(|(_, s)| s.is_live())
                    .cloned()
                else {
                    return Ok(false);
                };
                let key = SecretKey::from_serialized(key.expose_serialized())?;
                let set = wire::StoreSet {
                    label: wire::CString::new(label)?,
                    records,
                    reserved: 0,
                };
                let mut bytes = Zeroizing::new(Vec::new());
                bytes
                    .try_reserve_exact(set.encoded_len()?)
                    .map_err(|_| Fault::Capacity)?;
                bytes.resize(set.encoded_len()?, 0);
                set.encode(&mut bytes)?;
                let sets = wire::RecordSets::new(&bytes, 1)?;
                // The actual RID changes bytes, never the encoded length.
                // Finish every fallible size check before native admission.
                let total = wire::Request::Store {
                    rid: 0,
                    zone: key.view()?,
                    single_tx: 1,
                    reserved: 0,
                    sets,
                }
                .encoded_len()?;
                let operation = self.ns.store(&key, sets, true, deadline)?;
                self.ns_active = Some(Store {
                    binding: Native {
                        tag,
                        effect: effect.clone(),
                        source: source.clone(),
                        epoch,
                        total,
                        sent: 0,
                        cancelling: false,
                        retire_at: None,
                        forced: false,
                    },
                    operation,
                    known_code: None,
                });
                self.entry_mut(tag)?.job.admitted(&effect, &source, now)?;
                self.report.submitted = self.report.submitted.saturating_add(1);
                observe(Event::Submitted {
                    job: tag.serial,
                    provider: Provider::Namestore,
                });
                Ok(true)
            }
            Action::Lookup {
                zone,
                label,
                record_type,
            } => {
                if self.gns_active.is_some() || self.gns.pending_writes() != 0 {
                    return Ok(false);
                }
                let Some((epoch, source)) = self
                    .gns_source
                    .as_ref()
                    .filter(|(_, s)| s.is_live())
                    .cloned()
                else {
                    return Ok(false);
                };
                let parameters = gns::Parameters {
                    zone,
                    record_type,
                    options: gns::LocalOptions::from_bits(self.limits.gns_options),
                    recursion_depth: self.limits.gns_recursion,
                };
                // Wire ID is irrelevant to size. The actual submitted ID/bytes
                // are assigned and owned only by the production native client.
                let total = gns::Lookup::new(gns::WireId([0; 4]), parameters, label)?.encoded_len();
                let kind = self
                    .entry(tag)?
                    .job
                    .lookup_kind(&effect)?
                    .ok_or(Fault::Conflict)?;
                let started = Instant::now();
                let query = self.gns.lookup(parameters, label)?;
                self.gns_active = Some(Query {
                    binding: Native {
                        tag,
                        effect: effect.clone(),
                        source: source.clone(),
                        epoch,
                        total,
                        sent: 0,
                        cancelling: false,
                        retire_at: None,
                        forced: false,
                    },
                    query,
                    reconnecting: false,
                    kind,
                    started,
                    callback_recorded: false,
                });
                self.entry_mut(tag)?.job.admitted(&effect, &source, now)?;
                self.report.submitted = self.report.submitted.saturating_add(1);
                observe(Event::Submitted {
                    job: tag.serial,
                    provider: Provider::Gns,
                });
                Ok(true)
            }
        }
    }
    pub(super) fn poll_namestore(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.ns_retry.is_some_and(|t| Instant::now() < t) {
            return Poll::Pending;
        }
        self.ns_retry = None;
        let event = match self.ns.poll(cx, until) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        self.namestore_event(event, observe)?;
        Poll::Ready(Ok(Progress::Activity))
    }
    pub(super) fn namestore_event(
        &mut self,
        event: ns::Progress<'n>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        match event {
            ns::Progress::Connected(epoch) => {
                if let Some((_, source)) = self.ns_source.take() {
                    source.lost();
                }
                let source = self.factory.bind(Provider::Namestore)?;
                observe(Event::Connected {
                    provider: Provider::Namestore,
                    source: source.allocation(),
                });
                self.ns_source = Some((epoch, source));
            }
            ns::Progress::Queued {
                epoch, operation, ..
            } => {
                let active = self.ns_active.as_ref().ok_or(Fault::Stale)?;
                if operation != active.operation || epoch != active.binding.epoch {
                    return Err(Fault::StaleGeneration.into());
                }
            }
            ns::Progress::Activity { written_bytes, .. } if written_bytes > 0 => {
                let mut active = self.ns_active.take().ok_or(Fault::Stale)?;
                let result = active
                    .binding
                    .sent
                    .checked_add(written_bytes)
                    .ok_or(Fault::Overflow)
                    .map_err(Error::from)
                    .and_then(|count| self.exposure(&mut active.binding, count, false));
                self.ns_active = Some(active);
                result?;
            }
            ns::Progress::Written {
                epoch, operation, ..
            } => {
                let mut active = self.ns_active.take().ok_or(Fault::Stale)?;
                let result = if operation != active.operation || epoch != active.binding.epoch {
                    Err(Fault::StaleGeneration.into())
                } else {
                    let total = active.binding.total;
                    self.exposure(&mut active.binding, total, true)
                };
                self.ns_active = Some(active);
                result?;
            }
            ns::Progress::Completed(completion) => {
                let mut active = self.ns_active.take().ok_or(Fault::Stale)?;
                let result = self.store_completion(&mut active, completion, observe);
                if result.is_err() {
                    self.ns_active = Some(active);
                }
                result?;
            }
            ns::Progress::Lost { report, cause } => {
                observe(Event::BackendLost {
                    provider: Provider::Namestore,
                    epoch: report.epoch.map(|e| e.diagnostic()),
                    cause: LostCause::Namestore(cause),
                });
                if let Some((_, source)) = self.ns_source.take() {
                    source.lost();
                }
                if let Some(active) = &self.ns_active {
                    let tag = active.binding.tag;
                    let now = self.last_now;
                    self.entry_mut(tag)?.job.expire(now);
                }
            }
            ns::Progress::Unavailable(error) => {
                self.ns_retry = Some(
                    Instant::now()
                        .checked_add(Duration::from_secs(1))
                        .ok_or(Fault::Overflow)?,
                );
                observe(Event::Unavailable {
                    provider: Provider::Namestore,
                    error,
                });
            }
            ns::Progress::Closed => {
                if self.ns_active.is_some() {
                    return Err(Fault::OutcomeUnknown.into());
                }
            }
            ns::Progress::Record { .. }
            | ns::Progress::Synchronized { .. }
            | ns::Progress::ControlQueued { .. }
            | ns::Progress::ControlWritten { .. } => return Err(Fault::Malformed.into()),
            _ => {}
        }
        Ok(())
    }
    fn store_completion(
        &mut self,
        active: &mut Store<'n>,
        completion: ns::Completion<'n>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        if completion.operation != active.operation
            || completion.epoch.is_some_and(|e| e != active.binding.epoch)
        {
            return Err(Fault::StaleGeneration.into());
        }
        let now = self.last_now;
        match completion.outcome {
            ns::Outcome::Reply(reply) => {
                let wire::Response::Generic { code, .. } = reply.view()? else {
                    return Err(Fault::Malformed.into());
                };
                active.known_code = Some(code);
                if active.binding.sent != active.binding.total {
                    let total = active.binding.total;
                    self.exposure(&mut active.binding, total, true)?;
                }
                self.entry_mut(active.binding.tag)?.job.complete(
                    &active.binding.effect,
                    &active.binding.source,
                    Completion::Stored(code),
                    now,
                )?;
            }
            ns::Outcome::Local { submission, .. } => {
                let (count, whole) = match submission {
                    ns::Submission::Unsent => (0, false),
                    ns::Submission::Partial { bytes, total } => {
                        if total != active.binding.total {
                            return Err(Fault::Conflict.into());
                        }
                        (bytes, false)
                    }
                    ns::Submission::Written { bytes } => (bytes, true),
                };
                if count > active.binding.sent {
                    self.exposure(&mut active.binding, count, whole)?;
                }
                let result = if count == 0 {
                    Completion::Failed(Fault::Closed)
                } else {
                    Completion::Unknown
                };
                self.entry_mut(active.binding.tag)?.job.complete(
                    &active.binding.effect,
                    &active.binding.source,
                    result,
                    now,
                )?;
            }
        }
        self.progress(active.binding.tag, observe)
    }
    pub(super) fn poll_gns(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.gns_retry.is_some_and(|t| Instant::now() < t) {
            return Poll::Pending;
        }
        self.gns_retry = None;
        let event = {
            let mut future = std::pin::pin!(self.gns.drive(until));
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r?,
            }
        };
        self.gns_event(event, observe)?;
        Poll::Ready(Ok(Progress::Activity))
    }
    pub(super) fn gns_event(
        &mut self,
        event: gns::Progress<'g>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        match event {
            gns::Progress::Connected(epoch) => {
                if let Some((_, source)) = self.gns_source.take() {
                    source.lost();
                }
                let source = self.factory.bind(Provider::Gns)?;
                observe(Event::Connected {
                    provider: Provider::Gns,
                    source: source.allocation(),
                });
                self.gns_source = Some((epoch, source.clone()));
                self.rebind_gns(epoch, &source, observe)?;
            }
            gns::Progress::Activity {
                epoch,
                written_bytes,
                ..
            } if written_bytes > 0 => {
                let mut active = self.gns_active.take().ok_or(Fault::Stale)?;
                let result = if active.reconnecting || epoch != active.binding.epoch {
                    Err(Fault::StaleGeneration.into())
                } else {
                    active
                        .binding
                        .sent
                        .checked_add(written_bytes)
                        .ok_or(Fault::Overflow)
                        .map_err(Error::from)
                        .and_then(|bytes| self.exposure(&mut active.binding, bytes, false))
                };
                self.gns_active = Some(active);
                result?;
            }
            gns::Progress::Written { epoch, query } => {
                let mut active = self.gns_active.take().ok_or(Fault::Stale)?;
                let result = if active.reconnecting
                    || query != active.query
                    || epoch != active.binding.epoch
                {
                    Err(Fault::StaleGeneration.into())
                } else {
                    let total = active.binding.total;
                    self.exposure(&mut active.binding, total, true)
                };
                self.gns_active = Some(active);
                result?;
            }
            gns::Progress::Answer(answer) => {
                let mut active = self.gns_active.take().ok_or(Fault::Stale)?;
                let result = self.query_answer(&mut active, answer, observe);
                if result.is_err() {
                    self.gns_active = Some(active);
                }
                result?;
            }
            gns::Progress::Refused {
                epoch,
                query,
                reason,
            } => {
                let active = self.gns_active.take().ok_or(Fault::Stale)?;
                let result = (|| {
                    if active.reconnecting || query != active.query || epoch != active.binding.epoch
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    let now = self.last_now;
                    self.entry_mut(active.binding.tag)?.job.complete(
                        &active.binding.effect,
                        &active.binding.source,
                        Completion::Failed(reason),
                        now,
                    )?;
                    self.progress(active.binding.tag, observe)
                })();
                if result.is_err() {
                    self.gns_active = Some(active);
                }
                result?;
            }
            gns::Progress::Lost { epoch, cause, .. } => {
                observe(Event::BackendLost {
                    provider: Provider::Gns,
                    epoch: Some(epoch.diagnostic()),
                    cause: LostCause::Gns(cause),
                });
                if self
                    .gns_source
                    .as_ref()
                    .is_some_and(|(old, _)| *old != epoch)
                {
                    return Err(Fault::StaleGeneration.into());
                }
                let mut active = self.gns_active.take();
                let parked = (|| -> Result<bool, Error> {
                    let Some(active) = &mut active else {
                        return Ok(false);
                    };
                    if active.binding.epoch != epoch || active.reconnecting {
                        return Err(Fault::StaleGeneration.into());
                    }
                    if !active.binding.cancelling && self.gns.live(active.query) {
                        let now = self.last_now;
                        let entry = self.entry_mut(active.binding.tag)?;
                        entry.job.expire(now);
                        if Instant::now() >= entry.hard {
                            entry.job.expire(entry.job.deadline());
                        }
                        if entry.job.status().end.is_none() {
                            // raw Lost follows real old-MQ retirement and a
                            // scheduled retry of this exact QueryId. Park before
                            // revoking Source, so no intermediate Job poll can
                            // turn this recoverable read into SourceLost.
                            entry
                                .job
                                .park_lookup(&active.binding.effect, &active.binding.source)?;
                            active.reconnecting = true;
                            return Ok(true);
                        }
                    }
                    Ok(false)
                })();
                // This physical loss is real even if the logical park fails.
                if let Some((_, source)) = self.gns_source.take() {
                    source.lost();
                }
                let parked = match parked {
                    Ok(parked) => parked,
                    Err(error) => {
                        self.gns_active = active;
                        return Err(error);
                    }
                };
                if parked {
                    self.gns_active = active;
                } else if let Some(active) = active {
                    let result = (|| {
                        if self.gns.live(active.query) {
                            self.gns.cancel(active.query)?;
                        }
                        let now = self.last_now;
                        self.entry_mut(active.binding.tag)?.job.complete(
                            &active.binding.effect,
                            &active.binding.source,
                            Completion::Failed(Fault::Io),
                            now,
                        )?;
                        self.progress(active.binding.tag, observe)
                    })();
                    if result.is_err() {
                        self.gns_active = Some(active);
                    }
                    result?;
                }
            }
            gns::Progress::Unavailable(error) => {
                self.gns_retry = Some(
                    Instant::now()
                        .checked_add(Duration::from_secs(1))
                        .ok_or(Fault::Overflow)?,
                );
                observe(Event::Unavailable {
                    provider: Provider::Gns,
                    error,
                });
            }
            gns::Progress::Capacity(_) => return Err(Fault::Capacity.into()),
            gns::Progress::Closed if self.gns_active.is_some() => {
                return Err(Fault::Closed.into());
            }
            _ => {}
        }
        Ok(())
    }
    fn rebind_gns(
        &mut self,
        epoch: gns::Epoch<'g>,
        source: &Source,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let Some(mut active) = self.gns_active.take() else {
            return Ok(());
        };
        let result = (|| -> Result<(), Error> {
            if !active.reconnecting || active.binding.epoch == epoch {
                return Err(Fault::StaleGeneration.into());
            }
            let live = self.gns.live(active.query);
            let now = self.last_now;
            let entry = self.entry_mut(active.binding.tag)?;
            entry.job.expire(now);
            if Instant::now() >= entry.hard {
                entry.job.expire(entry.job.deadline());
            }
            if entry.job.status().end.is_some() || active.binding.cancelling {
                // Keep the original parked receipt/source for the existing
                // cancellation path; the queued native query must not reissue.
                if live {
                    self.gns.cancel(active.query)?;
                }
                return Ok(());
            }
            if !live {
                // The exact logical native query is genuinely gone. Physical
                // old-MQ retirement is known, but no new read may be fabricated.
                entry
                    .job
                    .retired(&active.binding.effect, &active.binding.source)?;
                return self.progress(active.binding.tag, observe);
            }
            entry
                .job
                .rebind_lookup(&active.binding.effect, &active.binding.source, source, now)?;
            active.binding.source = source.clone();
            active.binding.epoch = epoch;
            active.binding.sent = 0;
            active.reconnecting = false;
            // started, effect, QueryId, total and all original operation/grace
            // targets remain unchanged. raw client owns the actual reissue.
            Ok(())
        })();
        self.gns_active = Some(active);
        result
    }
    fn query_answer(
        &mut self,
        active: &mut Query<'g>,
        answer: gns::Answer<'g>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        if active.reconnecting
            || answer.query() != active.query
            || answer.epoch() != active.binding.epoch
        {
            return Err(Fault::StaleGeneration.into());
        }
        let now = self.last_now;
        let ended = self.entry(active.binding.tag)?.job.status().end.is_some();
        let elapsed = active.started.elapsed().as_micros();
        if ended {
            self.entry_mut(active.binding.tag)?
                .job
                .retired(&active.binding.effect, &active.binding.source)?;
        } else {
            let records = answer.result()?.records();
            // One valid original callback (also zero records), before fallible
            // allocation/business completion. Cancel/refusal/loss never counts.
            if !active.binding.cancelling
                && active.binding.source.is_live()
                && !active.callback_recorded
            {
                self.metrics.callback(active.kind, elapsed);
                active.callback_recorded = true;
            }
            let mut values = Vec::new();
            values
                .try_reserve_exact(records.len())
                .map_err(|_| Fault::Capacity)?;
            for record in records.iter() {
                values.push(record?);
            }
            let len = gnunet_gnsrecord::serialized_len(&values)?;
            let mut bytes = Zeroizing::new(Vec::new());
            bytes.try_reserve_exact(len).map_err(|_| Fault::Capacity)?;
            bytes.resize(len, 0);
            gnunet_gnsrecord::serialize(&values, &mut bytes)?;
            let records = wire::Records::new(
                &bytes,
                u16::try_from(values.len()).map_err(|_| Fault::TooLarge)?,
            )?;
            self.entry_mut(active.binding.tag)?.job.complete(
                &active.binding.effect,
                &active.binding.source,
                Completion::Records(records),
                now,
            )?;
        }
        self.progress(active.binding.tag, observe)
    }
    pub(super) fn poll_scan(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        let Some(mut scan) = self.scan.take() else {
            return Poll::Pending;
        };
        let event = match scan.iterator.poll(cx, until) {
            Poll::Pending => {
                self.scan = Some(scan);
                return Poll::Pending;
            }
            Poll::Ready(Err(error)) => {
                let cleanup = self.close_scan(scan, Fault::Io, observe);
                if let Err(e) = cleanup {
                    observe(Event::Cleanup(match e {
                        Error::Protocol(e) | Error::Clock(e) => e,
                        _ => Fault::Io,
                    }));
                }
                return Poll::Ready(Err(error.into()));
            }
            Poll::Ready(Ok(event)) => event,
        };
        match self.scan_event(&mut scan, event, observe) {
            Ok(true) => self.scan = Some(scan),
            Ok(false) => self.close_scan(scan, Fault::Closed, observe)?,
            Err(error) => {
                let cleanup = self.close_scan(scan, Fault::Io, observe);
                if let Err(e) = cleanup {
                    observe(Event::Cleanup(match e {
                        Error::Protocol(e) | Error::Clock(e) => e,
                        _ => Fault::Io,
                    }));
                }
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(Progress::Activity))
    }
    fn scan_event(
        &mut self,
        scan: &mut Scan<'n>,
        event: ns::Progress<'n>,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let now = self.last_now;
        match event {
            ns::Progress::Connected(epoch) => {
                if self.entry(scan.tag)?.job.status().end.is_some() {
                    return Ok(false);
                }
                let source = self.factory.bind(Provider::Namestore)?;
                self.entry_mut(scan.tag)?
                    .job
                    .admitted(&scan.effect, &source, now)?;
                observe(Event::Connected {
                    provider: Provider::Namestore,
                    source: source.allocation(),
                });
                scan.source = Some(source);
                scan.epoch = Some(epoch);
                self.report.submitted = self.report.submitted.saturating_add(1);
                observe(Event::Submitted {
                    job: scan.tag.serial,
                    provider: Provider::Namestore,
                });
            }
            ns::Progress::Queued {
                epoch, operation, ..
            } => {
                if Some(epoch) != scan.epoch || operation != scan.iterator.operation() {
                    return Err(Fault::StaleGeneration.into());
                }
            }
            ns::Progress::Activity { written_bytes, .. }
                if written_bytes > 0 && scan.sent < scan.total =>
            {
                let delta = written_bytes.min(scan.total - scan.sent);
                scan.sent += delta;
                let source = scan.source.as_ref().ok_or(Fault::NotReady)?;
                self.entry_mut(scan.tag)?
                    .job
                    .exposed(&scan.effect, source, delta)?;
            }
            ns::Progress::Written {
                epoch, operation, ..
            } => {
                if Some(epoch) != scan.epoch || operation != scan.iterator.operation() {
                    return Err(Fault::StaleGeneration.into());
                }
                let source = scan.source.as_ref().ok_or(Fault::NotReady)?;
                let entry = self.entry_mut(scan.tag)?;
                if scan.sent < scan.total {
                    entry
                        .job
                        .exposed(&scan.effect, source, scan.total - scan.sent)?;
                    scan.sent = scan.total;
                }
                entry.job.written(&scan.effect, source, scan.total)?;
            }
            ns::Progress::Record {
                epoch,
                operation,
                reply,
            } => {
                if Some(epoch) != scan.epoch || operation != scan.iterator.operation() {
                    return Err(Fault::StaleGeneration.into());
                }
                let wire::Response::Records {
                    zone,
                    label,
                    records,
                    ..
                } = reply.view()?
                else {
                    return Err(Fault::Malformed.into());
                };
                let source = scan.source.as_ref().ok_or(Fault::NotReady)?;
                if let Err(error) = self.entry_mut(scan.tag)?.job.row(
                    &scan.effect,
                    source,
                    zone,
                    label.bytes(),
                    records,
                    now,
                ) {
                    observe(Event::ProviderFailed {
                        job: scan.tag.serial,
                        provider: Provider::Namestore,
                        reason: error,
                    });
                    return Ok(false);
                }
                scan.iterator
                    .next(1, self.entry(scan.tag)?.job.deadline())?;
            }
            ns::Progress::Completed(completion) => {
                if completion.operation != scan.iterator.operation()
                    || completion.epoch.is_some_and(|e| Some(e) != scan.epoch)
                {
                    return Err(Fault::StaleGeneration.into());
                }
                let Some(source) = scan.source.as_ref() else {
                    self.entry_mut(scan.tag)?.job.cancel();
                    return Ok(false);
                };
                let result = match completion.outcome {
                    ns::Outcome::Reply(reply) => {
                        if !matches!(reply.view()?, wire::Response::End { .. }) {
                            return Err(Fault::Malformed.into());
                        }
                        Completion::ScanEnd
                    }
                    ns::Outcome::Local { .. } => Completion::Failed(Fault::Io),
                };
                self.entry_mut(scan.tag)?
                    .job
                    .complete(&scan.effect, source, result, now)?;
                // Native wrapper really closes the scan MQ before Completed.
                source.lost();
                self.progress(scan.tag, observe)?;
                return Ok(false);
            }
            ns::Progress::Lost { report, cause } => {
                observe(Event::BackendLost {
                    provider: Provider::Namestore,
                    epoch: report.epoch.map(|e| e.diagnostic()),
                    cause: LostCause::Namestore(cause),
                });
                return Ok(false);
            }
            ns::Progress::Unavailable(error) => {
                observe(Event::Unavailable {
                    provider: Provider::Namestore,
                    error,
                });
                return Ok(false);
            }
            ns::Progress::Closed => return Ok(false),
            _ => {}
        }
        Ok(true)
    }
    pub(super) fn close_scan(
        &mut self,
        mut scan: Scan<'n>,
        reason: Fault,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let actual = scan
            .iterator
            .close()
            .or_else(|| scan.iterator.take_close_report());
        if let Some(report) = actual {
            observe(Event::ScanRetired {
                job: scan.tag.serial,
                epoch: report.epoch.map(|e| e.diagnostic()),
                control: report
                    .control
                    .map(|c| (c.control.diagnostic(), c.kind, c.submission)),
            });
        }
        if let Some(source) = scan.source.take() {
            source.lost();
            let now = self.last_now;
            let entry = self.entry_mut(scan.tag)?;
            if entry.job.status().provider_debt {
                entry
                    .job
                    .complete(&scan.effect, &source, Completion::Failed(reason), now)?;
            }
            self.progress(scan.tag, observe)?;
        } else {
            self.entry_mut(scan.tag)?.job.cancel();
        }
        Ok(())
    }
}
