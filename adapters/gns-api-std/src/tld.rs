//! One original user-name lookup through the official zTLD/configuration/ego routes.
//!
//! This is an ordinary client owner, not a GNS service or DNS fallback. The
//! selected GNS service remains responsible for record authentication. All
//! phases share the caller's original logical/native bounds and actual clock.
use gnunet_config::Configuration;
use gnunet_gns_client_host::{
    BoundedClient, Instance, LocalOptions, MAX_NAME_BYTES, Parameters, QueryId, RecordType,
    ZoneKey, clock,
};
use gnunet_identity_client_host as identity;
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
mod types;
pub use types::*;

// The actual IDENTITY RESULT_CODE for a missing exact/suffix lookup. Other
// codes are service failures; a lost or canceled lookup never proves absence.
const IDENTITY_NOT_FOUND: u32 = 200;

enum Stage {
    Identity,
    Gns,
    Closed,
}
struct Query {
    record_type: RecordType,
    recursion_depth: u16,
}

/// Dedicated, caller-polled original lookup. Construction creates no socket,
/// task, Resolver or service. Dropping a drive future preserves this same owner.
pub struct Lookup<'gns, 'id> {
    gns: BoundedClient<'gns, 1, MAX_NAME_BYTES>,
    identity: Option<identity::Lookup<'id>>,
    query: Option<QueryId<'gns>>,
    stage: Stage,
    name: Vec<u8>,
    request: Query,
    bounds: Bounds,
    clock: Arc<dyn clock::RuntimeClock>,
    subscription: Option<Box<dyn clock::ClockSubscription>>,
    revision: u64,
    timer: Option<Pin<Box<Sleep>>>,
    report: Report<'gns, 'id>,
}

impl<'gns, 'id> Lookup<'gns, 'id> {
    /// Select a route using the explicit configuration snapshot. A malformed
    /// selected mapping is an error, not a reason to try a shorter suffix.
    /// Sources must share the exact actual clock Arc. Name bytes are not case
    /// folded, IDNA-converted or otherwise rewritten here.
    pub fn new(
        gns_instance: &'gns mut Instance,
        identity_instance: &'id identity::Instance,
        sources: Sources,
        configuration: &Configuration,
        request: Request<'_>,
        bounds: Bounds,
        limits: Limits,
    ) -> Result<Self, Cause> {
        check_native(bounds)?;
        if (bounds.until == u64::MAX) != bounds.hard.is_none()
            || limits.name_bytes == 0
            || limits.name_bytes > 65535
            || request.name.is_empty()
            || request.name.len() > limits.name_bytes
            || request.name.contains(&0)
        {
            return Err(Cause::Protocol(Fault::InvalidInput));
        }
        let clock = sources.gns.clock();
        if !Arc::ptr_eq(&clock, &sources.identity.clock()) {
            return Err(Cause::Protocol(Fault::Conflict));
        }
        let subscription = clock.subscribe().map_err(Cause::Clock)?;
        let sample = clock.sample().map_err(Cause::Clock)?;
        check_native(bounds)?;
        if bounds.until != u64::MAX && sample.now.as_micros() >= bounds.until {
            return Err(Cause::LogicalDeadline);
        }
        let name = copy(request.name)?;
        let selected = select(configuration, &name, bounds)?;
        let query = Query {
            record_type: request.record_type,
            recursion_depth: request.recursion_depth,
        };
        check_native(bounds)?;
        let gns = BoundedClient::new(gns_instance, sources.gns, limits.gns).map_err(Cause::Gns)?;
        let mut owner = Self {
            gns,
            identity: None,
            query: None,
            stage: Stage::Gns,
            name,
            request: query,
            bounds,
            clock,
            subscription: Some(subscription),
            revision: sample.revision,
            timer: bounds
                .hard
                .map(|hard| Box::pin(tokio::time::sleep_until(hard))),
            report: Report::default(),
        };
        match selected {
            Some((zone, relative)) => owner.admit(zone, &relative, request.options)?,
            None => {
                owner.check()?;
                let lookup = identity::Lookup::by_suffix(
                    identity_instance,
                    sources.identity,
                    &owner.name,
                    bounds.until,
                    limits.identity,
                )
                .map_err(Cause::Identity)?;
                owner.report.identity_operation = Some(lookup.operation());
                owner.identity = Some(lookup);
                owner.stage = Stage::Identity;
                owner.check()?;
            }
        }
        Ok(owner)
    }

    /// Immutable original targets, never rebuilt on a phase transition/retry.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }

    fn check(&self) -> Result<(), Cause> {
        check_native(self.bounds)?;
        let sample = self.clock.sample().map_err(Cause::Clock)?;
        check_native(self.bounds)?;
        if self.bounds.until != u64::MAX && sample.now.as_micros() >= self.bounds.until {
            return Err(Cause::LogicalDeadline);
        }
        Ok(())
    }

    fn admit(&mut self, zone: ZoneKey, name: &[u8], options: LocalOptions) -> Result<(), Cause> {
        self.check()?;
        let query = self
            .gns
            .lookup(
                Parameters {
                    zone,
                    options,
                    recursion_depth: self.request.recursion_depth,
                    record_type: self.request.record_type,
                },
                name,
            )
            .map_err(Cause::Gns)?;
        self.query = Some(query);
        self.report.query = Some(query);
        self.stage = Stage::Gns;
        self.check()
    }

    /// Stop only these original dedicated owners, without clock or new IO.
    /// Actual close metadata and independent cancel failures are transferred
    /// once. No wire cancellation ACK or successful resolution is synthesized.
    pub fn close(&mut self) -> Option<Report<'gns, 'id>> {
        if matches!(self.stage, Stage::Closed) {
            return None;
        }
        self.stage = Stage::Closed;
        if let Some(query) = self.query.take() {
            match self.gns.cancel(query) {
                Ok(()) => self.report.gns_cancelled = true,
                Err(error) => self.report.gns_cancel_error = Some(error),
            }
        }
        if let Some(lookup) = self.identity.as_mut() {
            match lookup.cancel() {
                Ok(loss) => {
                    self.report.identity_cancelled = true;
                    self.report.identity_retirement = loss;
                }
                Err(error) => self.report.identity_cancel_error = Some(error),
            }
            if let Some(loss) = lookup.close() {
                self.report.identity_retirement = Some(loss);
            }
            self.report.identity_closed = true;
        }
        self.identity = None;
        if let Some(gnunet_gns_client_host::Progress::Lost {
            epoch,
            cause,
            retained_queries,
        }) = self.gns.close()
        {
            self.report.gns_retirement = Some(GnsRetirement {
                epoch,
                cause,
                retained_queries,
            });
        }
        self.report.gns_closed = true;
        self.subscription = None;
        self.timer = None;
        Some(std::mem::take(&mut self.report))
    }

    /// Explicit cancellation is actual original-owner retirement, not NotGns.
    pub fn cancel(&mut self) -> Option<Report<'gns, 'id>> {
        self.close()
    }

    fn failed(&mut self, cause: Cause) -> Failure<'gns, 'id> {
        Failure {
            cause,
            report: self.close().unwrap_or_default(),
        }
    }

    /// Check/register the original native hard before canonical-clock waiting.
    /// A returned failure has already physically closed both original sources.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Failure<'gns, 'id>> {
        if matches!(self.stage, Stage::Closed) {
            return None;
        }
        let expired = self
            .timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready());
        if expired || self.bounds.hard.is_some_and(|hard| Instant::now() >= hard) {
            Some(self.failed(Cause::NativeDeadline))
        } else {
            None
        }
    }

    fn finish_identity(
        &mut self,
        operation: identity::Operation<'id>,
        outcome: identity::LookupOutcome,
    ) -> Result<Option<Outcome<'gns, 'id>>, Cause> {
        if self.report.identity_operation != Some(operation) {
            return Err(Cause::Protocol(Fault::StaleGeneration));
        }
        // Lookup::Finished has already stopped its actual original MQ.
        self.report.identity_finished = true;
        self.report.identity_closed = true;
        self.identity = None;
        match outcome {
            identity::LookupOutcome::Found(identity) => {
                self.check()?;
                let relative = strip_suffix(&self.name, identity.name())?;
                self.check()?;
                let public = identity.public_key().map_err(Cause::Protocol)?;
                self.check()?;
                let zone = ZoneKey::from_wire(&public).map_err(Cause::Protocol)?;
                drop(identity);
                let options = if relative.contains(&b'.') {
                    LocalOptions::LOCAL_MASTER
                } else {
                    LocalOptions::NO_DHT
                };
                self.admit(zone, &relative, options)?;
                Ok(None)
            }
            identity::LookupOutcome::ResultCode(IDENTITY_NOT_FOUND) => {
                self.check()?;
                let report = self.close().unwrap_or_default();
                Ok(Some(Outcome::NotGns { report }))
            }
            identity::LookupOutcome::ResultCode(code) => Err(Cause::IdentityResult(code)),
            identity::LookupOutcome::Local {
                reason,
                submission,
                result_code,
            } => Err(Cause::IdentityLocal {
                reason,
                submission,
                result_code,
            }),
        }
    }

    /// Poll one original source step. Empty real GNS answers are still Answer;
    /// source loss/refusal/endpoint errors can never become a DNS fallback.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Progress<'gns, 'id>, Failure<'gns, 'id>>> {
        if matches!(self.stage, Stage::Closed) {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if let Some(failure) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(failure));
        }
        if let Some(subscription) = self.subscription.as_mut() {
            match subscription.poll_changed(cx, self.revision) {
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(self.failed(Cause::Clock(error))));
                }
                Poll::Ready(Ok(sample)) => self.revision = sample.revision,
                Poll::Pending => {}
            }
        }
        if let Err(cause) = self.check() {
            return Poll::Ready(Err(self.failed(cause)));
        }
        match self.stage {
            Stage::Identity => {
                let result = self
                    .identity
                    .as_mut()
                    .ok_or(Cause::Protocol(Fault::Stale))
                    .map(|lookup| lookup.poll(cx, self.bounds.hard));
                match result {
                    Err(cause) => Poll::Ready(Err(self.failed(cause))),
                    Ok(Poll::Pending) => Poll::Pending,
                    Ok(Poll::Ready(Err(error))) => {
                        Poll::Ready(Err(self.failed(Cause::Identity(error))))
                    }
                    Ok(Poll::Ready(Ok(identity::LookupProgress::Finished {
                        operation,
                        outcome,
                        ..
                    }))) => match self.finish_identity(operation, outcome) {
                        Ok(Some(outcome)) => Poll::Ready(Ok(Progress::Finished(outcome))),
                        Ok(None) => {
                            cx.waker().wake_by_ref();
                            Poll::Ready(Ok(Progress::Routed))
                        }
                        Err(cause) => Poll::Ready(Err(self.failed(cause))),
                    },
                    Ok(Poll::Ready(Ok(identity::LookupProgress::Source(event)))) => match event {
                        identity::Progress::Lost { report, cause } => {
                            self.report.identity_source_loss = Some(report);
                            Poll::Ready(Err(self.failed(Cause::IdentitySource(cause))))
                        }
                        identity::Progress::Unavailable(error) => {
                            Poll::Ready(Err(self.failed(Cause::Identity(error))))
                        }
                        identity::Progress::Closed => {
                            Poll::Ready(Err(self.failed(Cause::Protocol(Fault::Closed))))
                        }
                        event => Poll::Ready(Ok(Progress::Identity(event))),
                    },
                    Ok(Poll::Ready(Ok(identity::LookupProgress::Closed))) => {
                        Poll::Ready(Err(self.failed(Cause::Protocol(Fault::Closed))))
                    }
                }
            }
            Stage::Gns => match self.gns.poll(cx, self.bounds.hard) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(self.failed(Cause::Gns(error)))),
                Poll::Ready(Ok(gnunet_gns_client_host::Progress::Answer(answer))) => {
                    if self.query != Some(answer.query()) {
                        return Poll::Ready(Err(
                            self.failed(Cause::Protocol(Fault::StaleGeneration))
                        ));
                    }
                    self.report.gns_answer_received = true;
                    self.query = None;
                    if let Err(cause) = self.check() {
                        return Poll::Ready(Err(self.failed(cause)));
                    }
                    let report = self.close().unwrap_or_default();
                    Poll::Ready(Ok(Progress::Finished(Outcome::Answer { answer, report })))
                }
                Poll::Ready(Ok(gnunet_gns_client_host::Progress::Lost {
                    epoch,
                    cause,
                    retained_queries,
                })) => {
                    self.report.gns_source_loss = Some((epoch, retained_queries));
                    // raw poll returns Lost only after retiring that MQ and
                    // successfully arranging its retry. This private one-slot
                    // client must still own this exact uncanceled query; the
                    // global retained count is diagnostic, never that proof.
                    if self.query.is_some_and(|query| self.gns.live(query)) {
                        // Transfer the actual owned loss cause to the caller,
                        // then keep driving this same client/query/Bounds. No
                        // new lookup, native hard or canonical target is made.
                        Poll::Ready(Ok(Progress::Gns(gnunet_gns_client_host::Progress::Lost {
                            epoch,
                            cause,
                            retained_queries,
                        })))
                    } else {
                        Poll::Ready(Err(self.failed(Cause::GnsSource(cause))))
                    }
                }
                Poll::Ready(Ok(gnunet_gns_client_host::Progress::Unavailable(error))) => {
                    Poll::Ready(Err(self.failed(Cause::Gns(error))))
                }
                Poll::Ready(Ok(gnunet_gns_client_host::Progress::Refused { reason, .. })) => {
                    self.query = None;
                    Poll::Ready(Err(self.failed(Cause::Protocol(reason))))
                }
                Poll::Ready(Ok(gnunet_gns_client_host::Progress::Closed)) => {
                    Poll::Ready(Err(self.failed(Cause::Protocol(Fault::Closed))))
                }
                Poll::Ready(Ok(event)) => Poll::Ready(Ok(Progress::Gns(event))),
            },
            Stage::Closed => Poll::Ready(Ok(Progress::Closed)),
        }
    }

    /// The same native and logical budgets apply after this future is canceled.
    #[expect(
        clippy::result_large_err,
        reason = "Failure transfers original source and cancellation outcomes inline without another allocation"
    )]
    pub async fn drive(&mut self) -> Result<Progress<'gns, 'id>, Failure<'gns, 'id>> {
        poll_fn(|cx| self.poll(cx)).await
    }
}

impl Drop for Lookup<'_, '_> {
    fn drop(&mut self) {
        let _report = self.close();
    }
}

fn check_native(bounds: Bounds) -> Result<(), Cause> {
    if bounds.hard.is_some_and(|hard| Instant::now() >= hard) {
        Err(Cause::NativeDeadline)
    } else {
        Ok(())
    }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, Cause> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| Cause::Protocol(Fault::Capacity))?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn strip_suffix(name: &[u8], suffix: &[u8]) -> Result<Vec<u8>, Cause> {
    if suffix.is_empty() || !name.ends_with(suffix) {
        return Err(Cause::Protocol(Fault::Malformed));
    }
    if name.len() == suffix.len() {
        return copy(b"@");
    }
    let end = name.len() - suffix.len() - 1;
    if name[end] != b'.' {
        return Err(Cause::Protocol(Fault::Malformed));
    }
    copy(&name[..end])
}

fn select(
    configuration: &Configuration,
    name: &[u8],
    bounds: Bounds,
) -> Result<Option<(ZoneKey, Vec<u8>)>, Cause> {
    check_native(bounds)?;
    let last = name.rsplit(|&byte| byte == b'.').next().unwrap_or(name);
    if let Ok(text) = std::str::from_utf8(last)
        && let Ok(zone) = ZoneKey::from_ztld(text)
    {
        return Ok(Some((zone, strip_suffix(name, last)?)));
    }
    let mut key = Vec::new();
    key.try_reserve_exact(name.len() + 1)
        .map_err(|_| Cause::Protocol(Fault::Capacity))?;
    let mut offset = 0;
    loop {
        check_native(bounds)?;
        if name.get(offset) == Some(&b'.') {
            offset += 1;
        }
        let suffix = &name[offset..];
        key.clear();
        key.push(b'.');
        key.extend_from_slice(suffix);
        if let Some(value) = configuration.get(b"gns", &key) {
            let text =
                std::str::from_utf8(value).map_err(|_| Cause::Configuration(Fault::Malformed))?;
            let zone = ZoneKey::from_ztld(text).map_err(Cause::Configuration)?;
            // The selected suffix is already matched by construction, including
            // the original C trailing-dot empty-suffix configuration case.
            let relative = if suffix.is_empty() {
                copy(&name[..name.len() - 1])?
            } else {
                strip_suffix(name, suffix)?
            };
            return Ok(Some((zone, relative)));
        }
        let Some(dot) = suffix.iter().position(|&byte| byte == b'.') else {
            return Ok(None);
        };
        offset += dot;
    }
}
