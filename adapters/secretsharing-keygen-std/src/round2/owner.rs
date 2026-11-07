use super::{
    BuildFailure, ClosedSource, Limits, LocalContribution, LocalTranscript, OwnSignature, Progress,
    Rejection, Report,
    validator::{Input, Job, Start, Step},
};
use crate::{
    Bounds, CompletedRound1, Error, SigningSession, Transcript,
    own::{OwnRevealBuilder, PreparedReveal, ValidationContext},
};
use gnunet_client_host::EndpointSource;
use gnunet_consensus_client_host as consensus;
use gnunet_pils::client::{self as pc, KeyTarget};
use gnunet_pils_host::client as pils;
use gnunet_secretsharing as math;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::consensus::Join;
use std::{
    future::{Future, poll_fn},
    mem::{replace, size_of, take},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

#[expect(
    clippy::large_enum_variant,
    reason = "Exclusive owned producer/signing/validation stages share fixed storage"
)]
enum Own<'id> {
    Producing(OwnRevealBuilder),
    Unsigned(PreparedReveal),
    Signing {
        reveal: PreparedReveal,
        target: pc::Identity<'id>,
    },
    Validating {
        transcript: Transcript,
        job: Job<'id>,
    },
    Inserting {
        transcript: Transcript,
        job: Job<'id>,
        insert: Option<consensus::InsertId>,
    },
    Complete(Transcript),
    Closed,
}
impl Own<'_> {
    fn view(&self) -> Result<ValidationContext<'_>, Error> {
        match self {
            Self::Producing(builder) => builder.validation_context(),
            Self::Unsigned(reveal) | Self::Signing { reveal, .. } => {
                Ok(reveal.validation_context())
            }
            Self::Validating { transcript, .. }
            | Self::Inserting { transcript, .. }
            | Self::Complete(transcript) => Ok(ValidationContext::from(transcript)),
            Self::Closed => Err(Fault::Closed.into()),
        }
    }
    fn heap(&self) -> Result<usize, Error> {
        match self {
            Self::Producing(builder) => builder
                .retained_bytes()?
                .checked_sub(size_of::<OwnRevealBuilder>())
                .ok_or_else(|| Fault::Overflow.into()),
            Self::Unsigned(reveal) | Self::Signing { reveal, .. } => reveal
                .retained_bytes()?
                .checked_sub(size_of::<PreparedReveal>())
                .ok_or_else(|| Fault::Overflow.into()),
            Self::Validating { transcript, job }
            | Self::Inserting {
                transcript, job, ..
            } => {
                let work = job.retained_bytes()?;
                transcript_heap(transcript)?
                    .checked_add(job.input_retained_bytes())
                    .and_then(|n| n.checked_add(work))
                    .ok_or_else(|| Fault::Overflow.into())
            }
            Self::Complete(transcript) => transcript_heap(transcript),
            Self::Closed => Ok(0),
        }
    }
    fn cancel(&mut self) {
        match self {
            Self::Producing(builder) => builder.cancel(),
            Self::Validating { job, .. } | Self::Inserting { job, .. } => job.cancel(),
            _ => {}
        }
        *self = Self::Closed;
    }
}
fn transcript_heap(transcript: &Transcript) -> Result<usize, Error> {
    let polynomial = transcript.polynomial.retained_bytes()?;
    let coefficients = transcript.coefficients.retained_bytes()?;
    transcript
        .roster
        .capacity()
        .checked_mul(32)
        .and_then(|n| {
            transcript
                .commitments
                .capacity()
                .checked_mul(size_of::<Option<crate::PeerCommitment>>())
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| n.checked_add(polynomial))
        .and_then(|n| n.checked_add(coefficients))
        .ok_or_else(|| Fault::Overflow.into())
}
fn blocked(error: &consensus::Error) -> bool {
    matches!(
        error,
        consensus::Error::Protocol(Fault::WouldBlock | Fault::NotReady)
    )
}
fn check_target(clock: &dyn RuntimeClock, bounds: Bounds, deadline: u64) -> Result<u64, Fault> {
    if Instant::now() >= bounds.hard {
        return Err(Fault::Deadline);
    }
    let now = clock.sample()?.now.as_micros();
    if Instant::now() >= bounds.hard || now >= bounds.expires || now >= deadline {
        return Err(Fault::Deadline);
    }
    Ok(now)
}
/// One actual second-round source with the same persistent original PILS owner.
/// Local and remote statements share the exact validator and retain honest,
/// distinct provenance. No local523 or replacement signer is synthesized.
pub struct Round2<'id> {
    native: consensus::Client,
    session: SigningSession<'id>,
    clock: Arc<dyn RuntimeClock>,
    bounds: Bounds,
    deadline: u64,
    limits: Limits,
    candidates: Vec<Option<LocalContribution<'id>>>,
    own: Own<'id>,
    remote: Option<Job<'id>>,
    group: math::Group,
    random: crate::owner::Random,
    conclude_admitted: bool,
    source_closed: bool,
    closed: bool,
    class: usize,
    fixed_reservation: usize,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    report: Option<Report<'id>>,
}
impl<'id> Round2<'id> {
    /// Adopt the actual continuing signing source. Constructor refusal closes
    /// its original owners and returns their real report without losing brands.
    #[expect(
        clippy::result_large_err,
        reason = "Return original linear source facts without a cleanup allocation"
    )]
    pub fn new(
        completed: CompletedRound1<'id>,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, BuildFailure<'id>> {
        let (transcript, mut session) = completed.into_parts();
        let mut native = None;
        let prepared = (|| -> Result<_, Error> {
            limits.validate()?;
            let clock = transcript.clock.clone();
            if !Arc::ptr_eq(&clock, &source.clock())
                || !Arc::ptr_eq(&clock, &session.client.clock())
            {
                return Err(Fault::InvalidInput.into());
            }
            check_target(clock.as_ref(), transcript.bounds, transcript.deadline)?;
            if transcript.local >= transcript.roster.len() {
                return Err(Fault::InvalidInput.into());
            }
            if session.identity.peer().as_bytes() != &transcript.roster[transcript.local]
                || session.client.epoch() != Some(session.identity.epoch())
            {
                return Err(Fault::StaleGeneration.into());
            }
            crate::admission::round2_reveal_extent(
                &transcript.roster,
                transcript.threshold,
                limits.reveal_bytes,
                limits.consensus.frame_bytes,
            )?;
            let start = transcript
                .start
                .checked_add(
                    transcript
                        .deadline
                        .checked_sub(transcript.start)
                        .ok_or(Fault::InvalidInput)?
                        / 2,
                )
                .ok_or(Fault::Overflow)?;
            let bounds = transcript.bounds;
            let deadline = transcript.deadline;
            let source = source.fixed_endpoint()?;
            let source_bytes = source
                .fixed_endpoint_storage_bytes()?
                .ok_or(Fault::NotReady)?;
            let fixed_reservation = size_of::<Self>()
                .checked_add(source_bytes)
                .and_then(|n| n.checked_add(limits.consensus.retained_bytes))
                .and_then(|n| {
                    limits
                        .consensus
                        .frame_bytes
                        .checked_mul(2)
                        .and_then(|m| n.checked_add(m))
                })
                .ok_or(Fault::Overflow)?;
            let outside = fixed_reservation
                .checked_add(session.retained_bytes()?)
                .ok_or(Fault::Overflow)?;
            let count = transcript.roster.len();
            let input = transcript_heap(&transcript)?;
            let requested = count
                .checked_mul(size_of::<Option<LocalContribution<'id>>>())
                .ok_or(Fault::Overflow)?;
            if outside
                .checked_add(input)
                .and_then(|n| n.checked_add(requested))
                .ok_or(Fault::Overflow)?
                > limits.retained_bytes
            {
                return Err(Fault::Capacity.into());
            }
            let mut candidates = Vec::new();
            candidates
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            let metadata = candidates
                .capacity()
                .checked_mul(size_of::<Option<LocalContribution<'id>>>())
                .ok_or(Fault::Overflow)?;
            let outside = outside.checked_add(metadata).ok_or(Fault::Overflow)?;
            if outside.checked_add(input).ok_or(Fault::Overflow)? > limits.retained_bytes {
                return Err(Fault::Capacity.into());
            }
            candidates.resize_with(count, || None);
            // Create/queue the real JOIN before any producer work; the first
            // source turn drives it independently of potentially long proof jobs.
            native = Some(consensus::Client::new(
                source,
                Join {
                    session: transcript.session,
                    start,
                    deadline: transcript.deadline,
                    peers: &transcript.roster,
                },
                limits.consensus,
                bounds,
            )?);
            let mut producer_limits = limits;
            producer_limits.retained_bytes = limits
                .retained_bytes
                .checked_sub(outside)
                .and_then(|n| n.checked_add(size_of::<OwnRevealBuilder>()))
                .ok_or(Fault::Capacity)?;
            let builder = OwnRevealBuilder::new(transcript, producer_limits)?;
            let group = math::Group::new()?;
            Ok((
                clock,
                bounds,
                deadline,
                fixed_reservation,
                candidates,
                builder,
                group,
            ))
        })();
        match prepared {
            Ok((clock, bounds, deadline, fixed_reservation, candidates, builder, group)) => {
                let Some(native) = native.take() else {
                    let round1 = session.close();
                    let report = Report {
                        round1,
                        pils_idle: session.client.is_idle(),
                        ..Report::default()
                    };
                    return Err(BuildFailure {
                        error: Fault::Stale.into(),
                        report,
                    });
                };
                let owner = Self {
                    native,
                    session,
                    clock,
                    bounds,
                    deadline,
                    limits,
                    candidates,
                    own: Own::Producing(builder),
                    remote: None,
                    group,
                    random: Default::default(),
                    conclude_admitted: false,
                    source_closed: false,
                    closed: false,
                    class: 0,
                    fixed_reservation,
                    timer: None,
                    report: Some(Report::default()),
                };
                Ok(owner)
            }
            Err(error) => {
                let loss = native.as_mut().map(consensus::Client::close);
                let round1 = session.close();
                let report = Report {
                    loss,
                    round1,
                    pils_idle: session.client.is_idle(),
                    ..Report::default()
                };
                Err(BuildFailure { error, report })
            }
        }
    }
    /// Original unchanged canonical/native targets.
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }
    /// Actual source and signing facts, never a cloned secret result.
    pub fn report(&self) -> Option<&Report<'id>> {
        self.report.as_ref()
    }
    fn facts(&mut self) -> Result<&mut Report<'id>, Error> {
        self.report.as_mut().ok_or_else(|| Fault::Closed.into())
    }
    /// Actual retained input capacities plus finite native reservations.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let own = self.own.heap()?;
        let mut bytes = self
            .fixed_reservation
            .checked_add(self.session.retained_bytes()?)
            .and_then(|n| {
                self.candidates
                    .capacity()
                    .checked_mul(size_of::<Option<LocalContribution<'id>>>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(own))
            .ok_or(Fault::Overflow)?;
        for candidate in self.candidates.iter().flatten() {
            let coefficients = candidate.coefficients.retained_bytes()?;
            bytes = bytes
                .checked_add(candidate.evidence.retained_bytes())
                .and_then(|n| n.checked_add(coefficients))
                .and_then(|n| {
                    candidate
                        .missing
                        .capacity()
                        .checked_mul(size_of::<u16>())
                        .and_then(|m| n.checked_add(m))
                })
                .ok_or(Fault::Overflow)?;
        }
        if let Some(job) = &self.remote {
            let work = job.retained_bytes()?;
            bytes = bytes
                .checked_add(job.input_retained_bytes())
                .and_then(|n| n.checked_add(work))
                .ok_or(Fault::Overflow)?;
        }
        Ok(bytes)
    }
    fn account(&self) -> Result<(), Error> {
        if self.retained_bytes()? > self.limits.retained_bytes {
            Err(Fault::Capacity.into())
        } else {
            Ok(())
        }
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<u64, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        self.account()?;
        if self.timer.is_none() {
            self.timer = Some(Box::pin(tokio::time::sleep_until(self.bounds.hard.into())));
        }
        if self
            .timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
        {
            return Err(Fault::Deadline.into());
        }
        let now = check_target(self.clock.as_ref(), self.bounds, self.deadline)?;
        let current = self
            .session
            .client
            .identity()
            .ok_or(Fault::StaleGeneration)?;
        let original = self.session.identity;
        if current.epoch() != original.epoch()
            || current.peer() != original.peer()
            || current.address_hash() != original.address_hash()
            || current.coverage() != original.coverage()
            || original.expiration().as_micros() <= now
            || current.expiration().as_micros() <= now
        {
            return Err(Fault::StaleGeneration.into());
        }
        if !self.source_closed
            && let Some(loss) = self.native.poll_native_guard(cx)
        {
            self.source_closed = true;
            self.facts()?.loss = Some(loss);
            return Err(Fault::Deadline.into());
        }
        Ok(now)
    }
    fn retire(&mut self) {
        if self.closed {
            return;
        }
        if !self.source_closed {
            let loss = self.native.close();
            if let Some(report) = &mut self.report {
                report.loss.get_or_insert(loss);
            }
            self.source_closed = true;
        }
        let round1 = self.session.close();
        if let Some(report) = &mut self.report {
            report.round1 = round1;
            report.pils_idle = self.session.client.is_idle();
            report.signature_result_unknown = report.signature_operation.is_some_and(|operation| {
                report
                    .signature_completion
                    .as_ref()
                    .is_none_or(|completion| completion.operation() != operation)
            });
            if let Some(error) = self.random.error.take() {
                report.entropy_error.get_or_insert(error);
            }
            if let Some(job) = &self.remote {
                report.unfinished_dealer = Some(job.dealer());
                report.unfinished_recipient = Some(job.recipient());
            }
        }
        if let Some(job) = &mut self.remote {
            job.cancel();
        }
        self.remote = None;
        self.own.cancel();
        self.candidates = Vec::new();
        self.timer = None;
        self.closed = true;
    }
    /// Physically close both original sources before erasing all private work.
    pub fn close(&mut self) -> Option<Report<'id>> {
        if let Some(report) = &mut self.report
            && !self.closed
        {
            report.cancelled = true;
        }
        self.retire();
        self.report.take()
    }
    /// Transfer actual final facts once physical retirement has occurred.
    pub fn take_report(&mut self) -> Option<Report<'id>> {
        if self.closed {
            self.report.take()
        } else {
            None
        }
    }
    fn reject(
        &mut self,
        peer: Option<[u8; 32]>,
        reason: Rejection,
    ) -> Result<Progress<'id>, Error> {
        let report = self.facts()?;
        report.rejected = report.rejected.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(Progress::Rejected { peer, reason })
    }
    fn own_refusal(&mut self, reason: Rejection) -> Error {
        let error = match &reason {
            Rejection::Shape(error) | Rejection::Signature(error) => (*error).into(),
            Rejection::Math(error) => (*error).into(),
            Rejection::Paillier(error) => (*error).into(),
            Rejection::NoRound1 => math::Error::Roster.into(),
            _ => Fault::Authentication.into(),
        };
        if let Some(report) = &mut self.report {
            report.own_rejection = Some(reason);
        }
        error
    }
    fn pils_event(&mut self, event: pils::Progress<'id, 1>) -> Result<bool, Error> {
        match event {
            pils::Progress::Inbound(pc::Inbound::Identity { identity, .. }) => {
                if identity.epoch() != self.session.identity.epoch()
                    || identity.peer() != self.session.identity.peer()
                {
                    return Err(Fault::StaleGeneration.into());
                }
            }
            pils::Progress::Inbound(pc::Inbound::Complete(completion)) => {
                let valid = (|| -> Result<(), Error> {
                    if self.report.as_ref().and_then(|r| r.signature_operation)
                        != Some(completion.operation())
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    let Own::Signing { target, .. } = &self.own else {
                        return Err(Fault::Stale.into());
                    };
                    let pc::Completion::Signature {
                        peer,
                        announced: Some(announced),
                        ..
                    } = &completion
                    else {
                        return Err(Fault::Authentication.into());
                    };
                    if *peer != target.peer()
                        || announced.epoch() != target.epoch()
                        || announced.peer() != target.peer()
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    Ok(())
                })();
                self.facts()?.signature_completion = Some(completion);
                valid?;
            }
            pils::Progress::Written(written) => {
                if self.report.as_ref().and_then(|r| r.signature_operation)
                    == Some(written.operation)
                {
                    if written.kind != pc::OperationKind::Sign || written.canceled {
                        return Err(Fault::Cancelled.into());
                    }
                    self.facts()?.signature_written = Some(written);
                }
            }
            pils::Progress::Lost {
                epoch,
                cause,
                report,
            } => {
                self.facts()?.pils_loss = Some(crate::PilsLoss {
                    epoch,
                    cause,
                    report,
                });
                return Err(Fault::Unavailable.into());
            }
            pils::Progress::ConnectRetry { error, .. } => {
                self.facts()?.pils_retry.get_or_insert(error);
            }
            pils::Progress::Unavailable(error) => return Err(error.into()),
            pils::Progress::Closed => return Err(Fault::Closed.into()),
            pils::Progress::WaitDeadline => return Ok(false),
            pils::Progress::Connected(epoch) => {
                if epoch != self.session.identity.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
            }
            pils::Progress::Inbound(pc::Inbound::Ignored) | pils::Progress::Activity { .. } => {}
        }
        Ok(true)
    }
    fn own_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'id>>, Error> {
        self.guard(cx)?;
        match &mut self.own {
            Own::Producing(builder) => {
                if builder.advance(&mut self.random, self.limits.math.units_per_turn)?
                    == math::Progress::Ready
                {
                    self.own = Own::Unsigned(builder.take_result()?);
                }
            }
            Own::Unsigned(reveal) => {
                let target = self
                    .session
                    .client
                    .identity()
                    .ok_or(Fault::StaleGeneration)?;
                let operation = self
                    .session
                    .client
                    .sign(reveal.signed_bytes(), KeyTarget::Exact(target))?;
                self.facts()?.signature_operation = Some(operation);
                let Own::Unsigned(reveal) = replace(&mut self.own, Own::Closed) else {
                    return Err(Fault::Stale.into());
                };
                self.own = Own::Signing { reveal, target };
            }
            Own::Signing { .. } => {
                let report = self.report.as_ref().ok_or(Fault::Closed)?;
                let Some(written) = report.signature_written else {
                    return Ok(None);
                };
                let Some(pc::Completion::Signature { signature, .. }) =
                    report.signature_completion.as_ref()
                else {
                    return Ok(None);
                };
                let signature = *signature;
                let operation = report.signature_operation.ok_or(Fault::Stale)?;
                let Own::Signing { reveal, target } = replace(&mut self.own, Own::Closed) else {
                    return Err(Fault::Stale.into());
                };
                let (transcript, bytes) = reveal.accept_signature(signature)?.into_parts();
                let base = self
                    .retained_bytes()?
                    .checked_add(transcript_heap(&transcript)?)
                    .ok_or(Fault::Overflow)?;
                let available = self
                    .limits
                    .retained_bytes
                    .checked_sub(base)
                    .ok_or(Fault::Capacity)?;
                let signing = OwnSignature {
                    operation,
                    identity: target,
                    written,
                    signature,
                };
                match Job::prepare(
                    Input::Own { bytes, signing },
                    &ValidationContext::from(&transcript),
                    &self.candidates,
                    self.limits,
                    available,
                )? {
                    Start::Job(job) => self.own = Own::Validating { transcript, job },
                    Start::Rejected { reason, .. } => return Err(self.own_refusal(reason)),
                }
            }
            Own::Validating { transcript, job } => {
                match job.advance(
                    &ValidationContext::from(&*transcript),
                    &self.group,
                    self.limits,
                )? {
                    Step::Activity => {}
                    Step::Ready => {
                        let Own::Validating { transcript, job } =
                            replace(&mut self.own, Own::Closed)
                        else {
                            return Err(Fault::Stale.into());
                        };
                        self.own = Own::Inserting {
                            transcript,
                            job,
                            insert: None,
                        };
                    }
                    Step::Rejected(reason) => return Err(self.own_refusal(reason)),
                }
            }
            Own::Inserting { job, insert, .. } => {
                if insert.is_some() {
                    return Ok(None);
                }
                match self.native.insert(0, job.reveal_bytes()?) {
                    Ok(id) => *insert = Some(id),
                    Err(error) if blocked(&error) => return Ok(None),
                    Err(error) => return Err(error.into()),
                }
            }
            Own::Complete(_) => {
                if self.conclude_admitted {
                    return Ok(None);
                }
                match self.native.conclude() {
                    Ok(()) => self.conclude_admitted = true,
                    Err(error) if blocked(&error) => return Ok(None),
                    Err(error) => return Err(error.into()),
                }
            }
            Own::Closed => return Err(Fault::Closed.into()),
        }
        self.guard(cx)?;
        self.account()?;
        Ok(Some(Progress::Activity))
    }
    fn remote_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'id>>, Error> {
        self.guard(cx)?;
        let Some(job) = &mut self.remote else {
            return Ok(None);
        };
        let view = self.own.view()?;
        match job.advance(&view, &self.group, self.limits)? {
            Step::Activity => {
                self.account()?;
                Ok(Some(Progress::Activity))
            }
            Step::Ready => {
                let local = view.local;
                let count = view.roster.len();
                self.guard(cx)?;
                let job = self.remote.take().ok_or(Fault::Stale)?;
                if self.report.as_ref().and_then(|r| r.epoch.as_ref()) != job.remote_epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                let dealer = job.dealer();
                let candidate = job.take_result(local, count, None)?;
                let slot = self.candidates.get_mut(dealer).ok_or(Fault::Stale)?;
                if slot.as_ref().is_some_and(|old| old.complete_for(count)) {
                    return Err(Fault::Conflict.into());
                }
                let replaced = slot.replace(candidate).is_some();
                let report = self.facts()?;
                report.candidates = report
                    .candidates
                    .checked_add(usize::from(!replaced))
                    .ok_or(Fault::Overflow)?;
                self.account()?;
                Ok(Some(Progress::Candidate { dealer }))
            }
            Step::Rejected(reason) => {
                let peer = view.roster.get(job.dealer()).copied();
                job.cancel();
                self.remote = None;
                self.reject(peer, reason).map(Some)
            }
        }
    }
    fn source(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'id>>, Error> {
        if self.source_closed {
            return Ok(None);
        }
        self.guard(cx)?;
        // A held remote input blocks further RX assignment, while the original
        // real TX cursor must still flush JOIN/own INSERT/CONCLUDE on that MQ.
        let progress = if self.remote.is_some() {
            self.native.poll_transmit(cx)
        } else {
            self.native.poll_progress(cx)
        };
        let event = match progress {
            Poll::Pending => return Ok(None),
            Poll::Ready(event) => event?,
        };
        match event {
            consensus::Progress::Attached(epoch) => {
                if self
                    .report
                    .as_ref()
                    .and_then(|r| r.epoch.as_ref())
                    .is_some_and(|old| old != &epoch)
                {
                    return Err(Fault::StaleGeneration.into());
                }
                self.facts()?.epoch = Some(epoch);
            }
            consensus::Progress::Written(receipt) => {
                if self.report.as_ref().and_then(|r| r.epoch.as_ref()) != Some(&receipt.epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                match &receipt.kind {
                    consensus::Kind::Join => self.facts()?.join = Some(receipt),
                    consensus::Kind::Conclude => {
                        if !matches!(self.own, Own::Complete(_))
                            || self.report.as_ref().is_none_or(|r| r.own_insert.is_none())
                        {
                            return Err(Fault::Stale.into());
                        }
                        self.facts()?.conclude = Some(receipt);
                    }
                    consensus::Kind::Insert(id) => {
                        let Own::Inserting {
                            insert: Some(original),
                            ..
                        } = &self.own
                        else {
                            return Err(Fault::Stale.into());
                        };
                        if id != original {
                            return Err(Fault::StaleGeneration.into());
                        }
                        let Own::Inserting {
                            transcript, job, ..
                        } = replace(&mut self.own, Own::Closed)
                        else {
                            return Err(Fault::Stale.into());
                        };
                        let dealer = transcript.local;
                        let count = transcript.roster.len();
                        let candidate = job.take_result(dealer, count, Some(receipt.clone()))?;
                        if !candidate.complete_for(count) || self.candidates[dealer].is_some() {
                            return Err(math::Error::Roster.into());
                        }
                        self.candidates[dealer] = Some(candidate);
                        self.own = Own::Complete(transcript);
                        let report = self.facts()?;
                        report.own_insert = Some(receipt);
                        report.candidates =
                            report.candidates.checked_add(1).ok_or(Fault::Overflow)?;
                        self.account()?;
                        return Ok(Some(Progress::Candidate { dealer }));
                    }
                }
            }
            consensus::Progress::Element(observation) => {
                if self.remote.is_some() {
                    return Err(Fault::Conflict.into());
                }
                if self.report.as_ref().and_then(|r| r.epoch.as_ref()) != Some(observation.epoch())
                {
                    return Err(Fault::StaleGeneration.into());
                }
                let available = self
                    .limits
                    .retained_bytes
                    .checked_sub(self.retained_bytes()?)
                    .ok_or(Fault::Capacity)?;
                match Job::prepare(
                    Input::Remote(observation),
                    &self.own.view()?,
                    &self.candidates,
                    self.limits,
                    available,
                )? {
                    Start::Job(job) => {
                        self.remote = Some(job);
                        self.account()?;
                    }
                    Start::Rejected { peer, reason } => return self.reject(peer, reason).map(Some),
                }
            }
            consensus::Progress::Done { epoch, .. } => {
                if self.remote.is_some()
                    || self.report.as_ref().and_then(|r| r.epoch.as_ref()) != Some(&epoch)
                    || self
                        .report
                        .as_ref()
                        .is_none_or(|r| r.conclude.is_none() || r.own_insert.is_none())
                    || !matches!(self.own, Own::Complete(_))
                {
                    return Err(Fault::Malformed.into());
                }
                self.source_closed = true;
                self.facts()?.done = true;
                return Ok(Some(Progress::ConsensusDone));
            }
            consensus::Progress::Lost(loss) => {
                self.source_closed = true;
                self.facts()?.loss = Some(loss);
                return Err(Fault::Unavailable.into());
            }
            consensus::Progress::Retry(error) => {
                self.facts()?.retry.get_or_insert(error);
            }
            consensus::Progress::Activity => {}
        }
        Ok(Some(Progress::Activity))
    }
    fn finish(&mut self) -> Result<Progress<'id>, Error> {
        let report = self.report.as_ref().ok_or(Fault::Closed)?;
        if self.remote.is_some()
            || !report.done
            || report.own_insert.is_none()
            || !self.source_closed
        {
            return Err(Fault::NotReady.into());
        }
        let epoch = report.epoch.as_ref().ok_or(Fault::StaleGeneration)?;
        let join = report.join.as_ref().ok_or(Fault::NotReady)?;
        let conclude = report.conclude.as_ref().ok_or(Fault::NotReady)?;
        if epoch.live()
            || &join.epoch != epoch
            || &conclude.epoch != epoch
            || !matches!(&join.kind, consensus::Kind::Join)
            || !matches!(&conclude.kind, consensus::Kind::Conclude)
        {
            return Err(Fault::StaleGeneration.into());
        }
        let source = ClosedSource {
            epoch: epoch.clone(),
            join: join.clone(),
            conclude: conclude.clone(),
        };
        let Own::Complete(transcript) = replace(&mut self.own, Own::Closed) else {
            return Err(Fault::NotReady.into());
        };
        let closed = LocalTranscript {
            round1: transcript,
            candidates: take(&mut self.candidates),
            source,
        };
        self.retire();
        if self
            .report
            .as_ref()
            .is_none_or(|r| !r.pils_idle || r.round1.is_none())
        {
            return Err(Fault::NotReady.into());
        }
        self.facts()?.completed = true;
        Ok(Progress::Complete(closed))
    }
    /// Observe PILS first, then one fair producer/validator/source turn. All
    /// native actions retain their original bounds and stable operation IDs.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'id>, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        let result = (|| -> Result<Option<Progress<'id>>, Error> {
            self.guard(cx)?;
            let clock = self.clock.clone();
            let bounds = self.bounds;
            let deadline = self.deadline;
            let mut before_io = || {
                check_target(clock.as_ref(), bounds, deadline)
                    .map(|_| ())
                    .map_err(Into::into)
            };
            let observed =
                match self
                    .session
                    .client
                    .poll_guarded(cx, Some(bounds.hard.into()), &mut before_io)
                {
                    Poll::Pending => false,
                    Poll::Ready(event) => self.pils_event(event?)?,
                };
            self.guard(cx)?;
            if self.report.as_ref().is_some_and(|r| r.done) {
                return self.finish().map(Some);
            }
            for _ in 0..3 {
                let class = self.class;
                self.class = (self.class + 1) % 3;
                let progress = match class {
                    0 => self.source(cx)?,
                    1 => self.own_step(cx)?,
                    _ => self.remote_step(cx)?,
                };
                if progress.is_some() {
                    return Ok(progress);
                }
            }
            Ok(observed.then_some(Progress::Activity))
        })();
        match result {
            Ok(Some(progress)) => Poll::Ready(Ok(progress)),
            Ok(None) => Poll::Pending,
            Err(error) => {
                self.retire();
                Poll::Ready(Err(error))
            }
        }
    }
    /// A dropped wait retains original partial frames and jobs; explicit close
    /// is the only cancellation operation.
    pub async fn drive(&mut self) -> Result<Progress<'id>, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Round2<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}
