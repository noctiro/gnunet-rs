use super::{Control, Mailbox, Output, QueryReport, Targets, expiration, publish, yield_once};
use crate::{Error, Limits, Sources};
use gnunet_abd::{Action, Credential, LookupId, Outcome, Principal, Query, Record, Time};
use gnunet_gns_client_host as gns;
use gnunet_identity::SecretKey;
use gnunet_namestore_client_host as ns;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{MessageHeader, abd as ipc, message_type as mt};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use zeroize::Zeroizing;

fn skipped(error: Fault) -> bool {
    matches!(
        error,
        Fault::Authentication
            | Fault::InvalidInput
            | Fault::Malformed
            | Fault::Unsupported
            | Fault::Truncated
            | Fault::Timeout
    )
}
fn time(
    sources: &Sources,
    targets: Targets,
    limits: Limits,
    control: &Control,
) -> Result<Time, Error> {
    if let Some(reason) = control.reason() {
        return Err(reason.into());
    }
    targets.observe(sources.clock.as_ref(), limits.utc_uncertainty)
}
fn owned(n: usize, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    if n > limit {
        return Err(Fault::Capacity.into());
    }
    let mut v = Zeroizing::new(Vec::new());
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    if v.capacity() > limit {
        return Err(Fault::Capacity.into());
    }
    v.resize(n, 0);
    Ok(v)
}
fn path_valid(path: &[u8], limits: Limits) -> Result<bool, Error> {
    if path.len() > limits.core.name_bytes {
        return Err(Fault::Capacity.into());
    }
    if path.is_empty() || path.contains(&0) || core::str::from_utf8(path).is_err() {
        return Ok(false);
    }
    let mut count = 0usize;
    for part in path.split(|b| *b == b'.') {
        if part.is_empty() {
            return Ok(false);
        }
        count = count.checked_add(1).ok_or(Fault::Overflow)?;
        if count > limits.core.depth {
            return Err(Fault::Capacity.into());
        }
    }
    Ok(true)
}
fn credential_bounds(value: ipc::Delegate<'_>, limits: Limits) -> Result<(), Error> {
    if value.issuer_attribute.len() > limits.core.name_bytes
        || value
            .subject_attribute
            .is_some_and(|a| a.len() > limits.core.name_bytes)
    {
        return Err(Fault::Capacity.into());
    }
    Ok(())
}
async fn collect_credentials(
    secret: &SecretKey,
    query: &mut Query<'_>,
    sources: &Sources,
    limits: Limits,
    targets: Targets,
    control: &Control,
    report: &mut QueryReport,
) -> Result<(), Error> {
    time(sources, targets, limits, control)?;
    let instance = ns::Instance::new();
    let mut client = ns::Client::new(&instance, sources.namestore.duplicate()?, limits.namestore)?;
    let operation = client.lookup(secret, b"@", 0, targets.canonical)?;
    let mut alarm = Box::pin(tokio::time::sleep_until(targets.hard.into()));
    let mut written = false;
    let result: Result<ns::Reply, Error> = async {
        loop {
            let event = poll_fn(|cx| {
                if let Some(cause) = control.reason() {
                    return Poll::Ready(Err(cause.into()));
                }
                if alarm.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(Fault::Deadline.into()));
                }
                targets.check(sources.clock.as_ref())?;
                if let Some(reason) = control.reason() {
                    return Poll::Ready(Err(reason.into()));
                }
                client.poll(cx, None).map_err(Error::from)
            })
            .await?;
            time(sources, targets, limits, control)?;
            match event {
                ns::Progress::Written {
                    operation: actual, ..
                } if actual == operation => {
                    if written {
                        return Err(Fault::Replay.into());
                    }
                    written = true;
                    report.collection_writes = report.collection_writes.saturating_add(1)
                }
                ns::Progress::Completed(done) => {
                    if done.operation != operation {
                        return Err(Fault::StaleGeneration.into());
                    }
                    if !written && matches!(&done.outcome, ns::Outcome::Reply(_)) {
                        return Err(Fault::NotReady.into());
                    }
                    return match done.outcome {
                        ns::Outcome::Reply(reply) => Ok(reply),
                        ns::Outcome::Local { reason, .. } => Err(match reason {
                            ns::LocalReason::Cancelled => Fault::Cancelled,
                            ns::LocalReason::Deadline => Fault::Deadline,
                            _ => Fault::Closed,
                        }
                        .into()),
                    };
                }
                ns::Progress::Lost { cause, .. } => return Err(Error::Namestore(cause)),
                ns::Progress::Unavailable(error) => return Err(error.into()),
                ns::Progress::Closed => return Err(Fault::Closed.into()),
                ns::Progress::ConnectRetry { .. }
                | ns::Progress::Connected(_)
                | ns::Progress::Queued { .. }
                | ns::Progress::Activity { .. }
                | ns::Progress::Written { .. }
                | ns::Progress::Ignored { .. } => {}
                _ => return Err(Fault::Malformed.into()),
            }
        }
    }
    .await;
    // Actual original MQ first; drain only clock-free local completions. No
    // partial/unknown lookup is reissued on a replacement private-key source.
    let _closed = client.close();
    let mut cx = Context::from_waker(Waker::noop());
    while let Some(event) = client.poll_native_guard(&mut cx) {
        if !matches!(event, ns::Progress::Completed(_)) {
            report.cleanup.get_or_insert(Fault::NotReady.into());
        }
    }
    if client.pending() != 0 {
        report.undrained = report.undrained.saturating_add(client.pending());
        report.cleanup.get_or_insert(Fault::NotReady.into());
    }
    let reply = result?;
    let ns::ipc::Response::Lookup {
        zone,
        label,
        found,
        records,
        ..
    } = reply.view()?
    else {
        return Err(Fault::Malformed.into());
    };
    let echoed = SecretKey::from_serialized(zone.expose_serialized())?;
    if !secret.constant_time_eq(&echoed) || label.bytes() != b"@" || !label.is_canonical() {
        return Err(Fault::Authentication.into());
    }
    if found == 0 {
        if records.count() != 0 {
            return Err(Fault::Malformed.into());
        }
        return Ok(());
    }
    if found != 1 {
        return Err(Error::LookupStatus(found));
    }
    for record in records.records().iter() {
        let record = record?;
        if record.record_type.value() != 65_548
            || !record
                .flags
                .contains(gnunet_gnsrecord::RecordFlags::PRIVATE)
        {
            continue;
        }
        let now = time(sources, targets, limits, control)?;
        match expiration(record, now) {
            Ok(_) => {}
            Err(Error::Protocol(e)) if skipped(e) => {
                report.ignored = report.ignored.saturating_add(1);
                continue;
            }
            Err(e) => return Err(e),
        }
        let value = match ipc::SignedDelegate::decode(record.data) {
            Ok(v) => v,
            Err(e) if skipped(e) => {
                report.ignored = report.ignored.saturating_add(1);
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        credential_bounds(value.delegate(), limits)?;
        if let Some(path) = value.delegate().subject_attribute
            && !path_valid(path, limits)?
        {
            report.ignored = report.ignored.saturating_add(1);
            continue;
        }
        match Credential::verify_record(
            record.data,
            now,
            limits.core.name_bytes,
            limits
                .core
                .retained_bytes
                .checked_sub(query.retained_bytes()?)
                .ok_or(Fault::Capacity)?,
        ) {
            Ok(value) => query.add_credential(value, now)?,
            Err(e) if skipped(e) => report.ignored = report.ignored.saturating_add(1),
            Err(e) => return Err(e.into()),
        }
        yield_once().await;
    }
    Ok(())
}

struct Mapping<'a, 'g> {
    core: LookupId<'a>,
    source: u64,
    query: gns::QueryId<'g>,
    admitted: bool,
    written: bool,
    zone: Principal,
    name: Vec<u8>,
    record_type: u32,
}
struct State<'a, 'g, 'r> {
    query: Query<'a>,
    gns: gns::Client<'g>,
    epoch: Option<gns::Epoch<'g>>,
    maps: Vec<Mapping<'a, 'g>>,
    next: Option<u64>,
    clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    limits: Limits,
    targets: Targets,
    control: Rc<Control>,
    mailbox: Mailbox,
    report: &'r mut QueryReport,
    rid: u32,
    collect: bool,
    alarm: Pin<Box<tokio::time::Sleep>>,
    closed: bool,
}
impl State<'_, '_, '_> {
    fn observe(&self) -> Result<Time, Error> {
        if let Some(cause) = self.control.reason() {
            return Err(cause.into());
        }
        self.targets
            .observe(self.clock.as_ref(), self.limits.utc_uncertainty)
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if let Some(cause) = self.control.reason() {
            return Err(cause.into());
        }
        if self.alarm.as_mut().poll(cx).is_ready() {
            return Err(Fault::Deadline.into());
        }
        self.targets.check(self.clock.as_ref())?;
        if let Some(cause) = self.control.reason() {
            return Err(cause.into());
        }
        Ok(())
    }
    fn close_sources(&mut self) {
        if self.closed {
            return;
        }
        let _closed = self.gns.close();
        self.closed = true;
        for mapping in self.maps.drain(..) {
            if mapping.admitted
                && let Err(error) = self.query.finish_lookup(mapping.core, mapping.source)
            {
                self.report.cleanup.get_or_insert(error.into());
                self.report.undrained = self.report.undrained.saturating_add(1);
            }
        }
    }
    fn queue(&mut self) -> Result<bool, Error> {
        let mut progressed = false;
        for _ in 0..self.limits.work_units {
            let Some(effect) = self.query.effect() else {
                break;
            };
            let id = effect.id;
            let (zone, name, record_type) = match effect.action {
                Action::Cancel { .. } => {
                    self.close_sources();
                    return Ok(true);
                }
                Action::Lookup {
                    zone,
                    attribute,
                    record_type,
                } => {
                    if self.maps.len() >= 64 {
                        break;
                    }
                    let mut name = Vec::new();
                    name.try_reserve_exact(attribute.len())
                        .map_err(|_| Fault::Capacity)?;
                    if name.capacity() > self.limits.core.name_bytes {
                        return Err(Fault::Capacity.into());
                    }
                    name.extend_from_slice(attribute);
                    (zone, name, record_type)
                }
            };
            self.observe()?;
            let source = self.next.ok_or(Fault::Overflow)?;
            let following = source.checked_add(1);
            let query = match self.gns.lookup(
                gns::Parameters {
                    zone: gns::ZoneKey::from_wire(zone.bytes())?,
                    options: gns::LocalOptions::DEFAULT,
                    recursion_depth: 128,
                    record_type: gns::RecordType::new(record_type),
                },
                &name,
            ) {
                Ok(value) => value,
                Err(gnunet_client_host::ConnectError::Protocol(
                    Fault::Capacity | Fault::WouldBlock,
                )) => break,
                Err(error) => return Err(error.into()),
            };
            self.next = following;
            // Metadata capacity was reserved before any actual GNS query. Even
            // a pure-admission refusal leaves this physical owner tracked.
            self.maps.push(Mapping {
                core: id,
                source,
                query,
                admitted: false,
                written: false,
                zone,
                name,
                record_type,
            });
            self.report.lookups = self.report.lookups.saturating_add(1);
            self.query.admit(id, source)?;
            self.maps.last_mut().ok_or(Fault::Conflict)?.admitted = true;
            progressed = true;
        }
        Ok(progressed)
    }
    async fn edge(&self, edge: ipc::Chain<'_>, backward: u16) -> Result<(), Error> {
        if self.collect {
            return Ok(());
        }
        self.observe()?;
        let response = ipc::Response::Intermediate {
            id: self.rid,
            backward,
            edge,
        };
        let mut bytes = owned(response.encoded_len()?, self.limits.frame_bytes)?;
        response.encode(&mut bytes)?;
        publish(
            &self.mailbox,
            &self.control,
            Output {
                frame: OwnedFrame::new(std::mem::take(&mut *bytes)),
                terminal: false,
                valid_until: None,
            },
        )
        .await
    }
    async fn answer(&mut self, answer: gns::Answer<'_>) -> Result<(), Error> {
        if self.epoch != Some(answer.epoch()) {
            return Err(Fault::StaleGeneration.into());
        }
        let index = self
            .maps
            .iter()
            .position(|m| m.query == answer.query())
            .ok_or(Fault::StaleGeneration)?;
        if !self.maps[index].written {
            return Err(Fault::NotReady.into());
        }
        let id = self.maps[index].core;
        let source = self.maps[index].source;
        let record_type = self.maps[index].record_type;
        let zone = self.maps[index].zone;
        let mut name = Vec::new();
        name.try_reserve_exact(self.maps[index].name.len())
            .map_err(|_| Fault::Capacity)?;
        if name.capacity() > self.limits.core.name_bytes {
            return Err(Fault::Capacity.into());
        }
        name.extend_from_slice(&self.maps[index].name);
        self.report.answers = self.report.answers.saturating_add(1);
        for record in answer.result()?.records().iter() {
            let record = record?;
            if record.record_type.value() != record_type {
                continue;
            }
            let now = self.observe()?;
            let expires = match expiration(record, now) {
                Ok(value) => value,
                Err(Error::Protocol(e)) if skipped(e) => {
                    self.report.ignored = self.report.ignored.saturating_add(1);
                    continue;
                }
                Err(e) => return Err(e),
            };
            if record_type == 65_548 {
                let decoded = match ipc::SignedDelegate::decode(record.data) {
                    Ok(value) => value,
                    Err(e) if skipped(e) => {
                        self.report.ignored = self.report.ignored.saturating_add(1);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                credential_bounds(decoded.delegate(), self.limits)?;
                if let Some(path) = decoded.delegate().subject_attribute
                    && !path_valid(path, self.limits)?
                {
                    self.report.ignored = self.report.ignored.saturating_add(1);
                    continue;
                }
                let available = self
                    .limits
                    .core
                    .retained_bytes
                    .checked_sub(self.query.retained_bytes()?)
                    .ok_or(Fault::Capacity)?;
                let value = match Credential::verify_record(
                    record.data,
                    now,
                    self.limits.core.name_bytes,
                    available,
                ) {
                    Ok(value) => value,
                    Err(e) if skipped(e) => {
                        self.report.ignored = self.report.ignored.saturating_add(1);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                self.query
                    .verified_delegate(id, source, value, expires, now)?;
                let fields = decoded.delegate();
                self.edge(
                    ipc::Chain {
                        issuer: fields.issuer,
                        subject: fields.subject,
                        issuer_attribute: fields.issuer_attribute,
                        subject_attribute: fields.subject_attribute,
                    },
                    0,
                )
                .await?;
            } else {
                let policy = match ipc::Policy::decode(record.data, self.limits.core.record_layout)
                {
                    Ok(value) => value,
                    Err(e) if skipped(e) => {
                        self.report.ignored = self.report.ignored.saturating_add(1);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                if policy.count() == 0 {
                    self.report.ignored = self.report.ignored.saturating_add(1);
                    continue;
                }
                let mut valid = true;
                for term in policy.iter() {
                    if let Some(path) = term.attribute
                        && !path_valid(path, self.limits)?
                    {
                        valid = false;
                        break;
                    }
                }
                if !valid {
                    self.report.ignored = self.report.ignored.saturating_add(1);
                    continue;
                }
                self.query.record(
                    id,
                    source,
                    Record {
                        record_type,
                        data: record.data,
                        expiration_us: expires,
                    },
                    now,
                )?;
                for term in policy.iter() {
                    self.edge(
                        ipc::Chain {
                            issuer: zone.view()?,
                            subject: term.subject,
                            issuer_attribute: &name,
                            subject_attribute: term.attribute,
                        },
                        1,
                    )
                    .await?;
                }
            }
            yield_once().await;
        }
        self.query.finish_lookup(id, source)?;
        self.maps.swap_remove(index);
        Ok(())
    }
    async fn run(&mut self) -> Result<Outcome, Error> {
        loop {
            let now = self.observe()?;
            self.query.advance(now, self.limits.work_units)?;
            if self.query.outcome(now)?.is_some() {
                self.close_sources();
                if !self.query.is_quiescent() {
                    return Err(Fault::NotReady.into());
                }
                return self
                    .query
                    .outcome(self.observe()?)?
                    .ok_or_else(|| Fault::NotReady.into());
            }
            let queued = self.queue()?;
            let progress = self
                .query
                .advance(self.observe()?, self.limits.work_units)?;
            if self.query.outcome(self.observe()?)?.is_some() {
                continue;
            }
            let event = poll_fn(|cx| {
                self.guard(cx)?;
                match self.gns.poll(cx, None) {
                    Poll::Ready(value) => Poll::Ready(value.map(Some).map_err(Error::from)),
                    Poll::Pending if queued || progress => Poll::Ready(Ok(None)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            self.observe()?;
            match event {
                Some(gns::Progress::Connected(epoch)) => {
                    if self.epoch.is_some() {
                        return Err(Fault::StaleGeneration.into());
                    }
                    self.epoch = Some(epoch);
                }
                Some(gns::Progress::Written { epoch, query }) => {
                    if self.epoch != Some(epoch) {
                        return Err(Fault::StaleGeneration.into());
                    }
                    let row = self
                        .maps
                        .iter_mut()
                        .find(|m| m.query == query)
                        .ok_or(Fault::StaleGeneration)?;
                    if row.written {
                        return Err(Fault::Replay.into());
                    }
                    row.written = true;
                    self.report.lookup_writes = self.report.lookup_writes.saturating_add(1);
                }
                Some(gns::Progress::Answer(answer)) => self.answer(answer).await?,
                Some(gns::Progress::Lost { cause, .. }) => return Err(Error::Gns(cause)),
                Some(gns::Progress::Refused { reason, .. }) => return Err(reason.into()),
                Some(gns::Progress::Unavailable(error)) => return Err(error.into()),
                Some(gns::Progress::Capacity(_)) => return Err(Fault::Capacity.into()),
                Some(gns::Progress::Closed) => return Err(Fault::Closed.into()),
                Some(
                    gns::Progress::Ignored(_)
                    | gns::Progress::Activity { .. }
                    | gns::Progress::ConnectRetry { .. }
                    | gns::Progress::WaitDeadline,
                )
                | None => {}
            }
            self.observe()?;
            yield_once().await;
        }
    }
}
impl Drop for State<'_, '_, '_> {
    fn drop(&mut self) {
        self.query.cancel();
        self.close_sources();
        if !self.query.is_quiescent() {
            self.report.undrained = self
                .report
                .undrained
                .saturating_add(self.query.pending_sources());
            self.report.cleanup.get_or_insert(Fault::NotReady.into());
        }
    }
}

fn terminal(
    query: &Query<'_>,
    rid: u32,
    outcome: Outcome,
    limits: Limits,
) -> Result<Output, Error> {
    let (found, valid_until) = match outcome {
        Outcome::Authorized { valid_until_us } => (1, Some(valid_until_us)),
        Outcome::Denied => (0, None),
        Outcome::Failed(error) => return Err(error.into()),
        Outcome::Cancelled => return Err(Fault::Cancelled.into()),
    };
    let mut chain_bytes = 0usize;
    let mut chain_count = 0u32;
    let mut credential_bytes = 0usize;
    let mut credential_count = 0u32;
    if found == 1 {
        for edge in query.proof_edges() {
            chain_bytes = chain_bytes
                .checked_add(edge?.encoded_len()?)
                .ok_or(Fault::Overflow)?;
            chain_count = chain_count.checked_add(1).ok_or(Fault::Overflow)?;
        }
        for value in query.proof_credentials() {
            credential_bytes = credential_bytes
                .checked_add(value.view()?.delegate().ipc_len(true)?)
                .ok_or(Fault::Overflow)?;
            credential_count = credential_count.checked_add(1).ok_or(Fault::Overflow)?;
        }
    }
    let n = 20usize
        .checked_add(chain_bytes)
        .and_then(|v| v.checked_add(credential_bytes))
        .ok_or(Fault::Overflow)?;
    MessageHeader::from_total_size(mt::ABD_VERIFY_RESULT, n)?;
    let mut body = owned(n - 20, limits.frame_bytes)?;
    let mut at = 0usize;
    if found == 1 {
        for edge in query.proof_edges() {
            at = at
                .checked_add(edge?.encode(&mut body[at..])?)
                .ok_or(Fault::Overflow)?;
        }
        for value in query.proof_credentials() {
            at = at
                .checked_add(value.view()?.delegate().encode_ipc(&mut body[at..], true)?)
                .ok_or(Fault::Overflow)?;
        }
    }
    if at != body.len() {
        return Err(Fault::Conflict.into());
    }
    let response = ipc::Response::Result {
        kind: mt::ABD_VERIFY_RESULT,
        id: rid,
        found,
        chain: ipc::Chains::new(&body[..chain_bytes], chain_count)?,
        delegates: ipc::Delegates::new(&body[chain_bytes..], credential_count)?,
    };
    let mut bytes = owned(response.encoded_len()?, limits.frame_bytes)?;
    response.encode(&mut bytes)?;
    Ok(Output {
        frame: OwnedFrame::new(std::mem::take(&mut *bytes)),
        terminal: true,
        valid_until,
    })
}

pub(crate) async fn run(
    raw: OwnedFrame,
    sources: Sources,
    limits: Limits,
    targets: Targets,
    control: Rc<Control>,
    mailbox: Mailbox,
) -> QueryReport {
    let mut report = QueryReport::new();
    let result: Result<(), Error> = async {
        let now = time(&sources, targets, limits, &control)?;
        let request = ipc::Request::decode(raw.bytes())?;
        let brand = gnunet_abd::Instance::new();
        let (rid, issuer, subject, attribute, resolution, collect, secret) = match &request {
            ipc::Request::Verify {
                id,
                issuer,
                subject,
                attribute,
                resolution,
                ..
            } => (
                *id,
                Principal::from_key(*issuer),
                Principal::from_key(*subject),
                *attribute,
                *resolution,
                false,
                None,
            ),
            ipc::Request::Collect {
                id,
                issuer,
                subject,
                attribute,
                resolution,
            } => {
                let secret = SecretKey::from_serialized(subject.bytes())?;
                (
                    *id,
                    Principal::from_key(*issuer),
                    Principal::new(secret.public_key()?)?,
                    *attribute,
                    *resolution,
                    true,
                    Some(secret),
                )
            }
        };
        let deadline = u64::try_from(targets.hard.duration_since(targets.start).as_micros())
            .map_err(|_| Fault::Overflow)?;
        let mut query = Query::new(
            &brand,
            issuer,
            attribute,
            subject,
            resolution,
            limits.core,
            deadline,
            now,
        )?;
        if let ipc::Request::Verify { delegates, .. } = request {
            if usize::try_from(delegates.count()).map_err(|_| Fault::TooLarge)?
                > limits.core.credentials
            {
                return Err(Fault::Capacity.into());
            }
            for leaf in delegates.iter() {
                let now = time(&sources, targets, limits, &control)?;
                credential_bounds(leaf, limits)?;
                let available = limits
                    .core
                    .retained_bytes
                    .checked_sub(query.retained_bytes()?)
                    .ok_or(Fault::Capacity)?;
                match Credential::verify_ipc(leaf, now, limits.core.name_bytes, available) {
                    Ok(value) => query.add_credential(value, now)?,
                    Err(error) if skipped(error) => {
                        report.ignored = report.ignored.saturating_add(1)
                    }
                    Err(error) => return Err(error.into()),
                }
                yield_once().await;
            }
        }
        // Parsed public fields and the separately erased key owner are now
        // independent; the original sensitive IPC frame need not be retained.
        drop(raw);
        if let Some(secret) = secret {
            collect_credentials(
                &secret,
                &mut query,
                &sources,
                limits,
                targets,
                &control,
                &mut report,
            )
            .await?;
        }
        time(&sources, targets, limits, &control)?;
        let mut gns_instance = gns::Instance::new();
        let gns = gns::Client::new(&mut gns_instance, sources.gns.duplicate()?, limits.gns)?;
        let mut maps = Vec::new();
        maps.try_reserve_exact(64).map_err(|_| Fault::Capacity)?;
        if maps.capacity() > 64 {
            return Err(Fault::Capacity.into());
        }
        let mut state = State {
            query,
            gns,
            epoch: None,
            maps,
            next: Some(1),
            clock: sources.clock.clone(),
            limits,
            targets,
            control: control.clone(),
            mailbox: mailbox.clone(),
            report: &mut report,
            rid,
            collect,
            alarm: Box::pin(tokio::time::sleep_until(targets.hard.into())),
            closed: false,
        };
        let outcome = match state.run().await {
            Ok(outcome) => outcome,
            Err(error) => {
                let classified = error.classified();
                if classified == Fault::Cancelled {
                    state.query.cancel();
                    state.report.outcome = Some(Outcome::Cancelled);
                } else {
                    state.query.fail(classified);
                    state.report.outcome = Some(Outcome::Failed(classified));
                }
                return Err(error);
            }
        };
        state.report.outcome = Some(outcome);
        let now = state.observe()?;
        let actual = state.query.outcome(now)?.ok_or(Fault::NotReady)?;
        let output = terminal(&state.query, rid, actual, limits)?;
        publish(&mailbox, &control, output).await?;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        report.primary.get_or_insert(error);
    }
    report
}
