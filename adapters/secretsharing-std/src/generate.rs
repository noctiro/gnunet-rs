//! Standard780 generation, retaining the local fast path and real native stages.
use crate::{Error, GenerateFacts, Limits, Sources, run::Targets};
use gnunet_pils::client::{self as pc, Identity};
use gnunet_pils_host::client as pils;
use gnunet_secretsharing::{self as math, AggregateMaterial, PolynomialGenerator};
use gnunet_secretsharing_keygen_host as keygen;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{Frame, secretsharing as ipc};
use std::{
    future::Future,
    mem::{size_of, take},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::Zeroizing;

mod state;
use state::State;

pub(crate) const RESPONSE_BYTES: usize = 4 + ipc::SHARE_PREFIX + ipc::SHARE_ROW_BYTES;

fn target_time(original: Targets, clock: &dyn RuntimeClock) -> Result<u64, Fault> {
    if Instant::now() >= original.hard {
        return Err(Fault::Deadline);
    }
    let now = clock.sample()?.now.as_micros();
    if Instant::now() >= original.hard || now >= original.canonical {
        return Err(Fault::Deadline);
    }
    Ok(now)
}

/// One exact original intent, retained while waiting for the operation permit.
pub(crate) struct Request {
    bytes: Zeroizing<Vec<u8>>,
    session: [u8; 64],
    start: u64,
    deadline: u64,
    threshold: usize,
}
impl Request {
    pub(crate) fn from_frame(bytes: Zeroizing<Vec<u8>>, limits: Limits) -> Result<Self, Error> {
        if bytes.capacity() > limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        let ipc::Request::Generate(raw) = ipc::Request::decode(Frame::decode(&bytes)?)? else {
            return Err(Fault::Conflict.into());
        };
        if raw.start >= raw.deadline
            || raw.threshold == 0
            || usize::from(raw.threshold) > limits.decrypt.peers
            || raw.peers.len() / 32 > limits.decrypt.peers
        {
            return Err(Fault::InvalidInput.into());
        }
        let (session, start, deadline, threshold) = (
            *raw.session,
            raw.start,
            raw.deadline,
            usize::from(raw.threshold),
        );
        Ok(Self {
            bytes,
            session,
            start,
            deadline,
            threshold,
        })
    }
    fn accepts(&self, local: &[u8; 32]) -> Result<bool, Error> {
        let ipc::Request::Generate(raw) = ipc::Request::decode(Frame::decode(&self.bytes)?)? else {
            return Err(Fault::Conflict.into());
        };
        Ok(self.threshold == 1 && (raw.peers.is_empty() || raw.peers == local.as_slice()))
    }
    fn into_native(mut self, limits: keygen::Limits) -> Result<keygen::Request, Error> {
        Ok(keygen::Request::from_frame(take(&mut *self.bytes), limits)?)
    }
}

struct Random {
    error: Option<getrandom::Error>,
    hard: Instant,
}
impl math::Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Fault> {
        if self.error.is_some() {
            bytes.fill(0);
            return Err(Fault::EntropyUnavailable);
        }
        if Instant::now() >= self.hard {
            bytes.fill(0);
            return Err(Fault::Deadline);
        }
        getrandom::fill(bytes).map_err(|error| {
            bytes.fill(0);
            self.error = Some(error);
            Fault::EntropyUnavailable
        })?;
        if Instant::now() >= self.hard {
            bytes.fill(0);
            return Err(Fault::Deadline);
        }
        Ok(())
    }
}

/// Original response storage remains zeroizing through secure queue admission.
pub(crate) struct Generated {
    frame: Zeroizing<Vec<u8>>,
}
impl Generated {
    fn allocate(length: usize, frame_bytes: usize, available: usize) -> Result<Self, Error> {
        if length > frame_bytes || length > usize::from(u16::MAX) {
            return Err(Fault::Capacity.into());
        }
        // The original buffer and secure queue copy coexist at admission.
        output_peak(length, available)?;
        let mut frame = Zeroizing::new(Vec::new());
        frame
            .try_reserve_exact(length)
            .map_err(|_| Fault::Capacity)?;
        output_peak(frame.capacity(), available)?;
        frame.resize(length, 0);
        Ok(Self { frame })
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.frame.as_ref()
    }
}

fn output_peak(capacity: usize, available: usize) -> Result<(), Error> {
    if capacity.checked_mul(2).ok_or(Fault::Overflow)? > available {
        Err(Fault::Capacity.into())
    } else {
        Ok(())
    }
}

/// Exclusive original generator. The first actual identity chooses a local or
/// multiparty path without opening a second PILS connection or changing epoch.
#[expect(
    clippy::large_enum_variant,
    reason = "Exclusive native/local owners share bounded future storage without a new boxed stage"
)]
pub(crate) enum Owner<'id> {
    Local(Singleton<'id>),
    Native(Multiparty<'id>),
}
impl<'id> Owner<'id> {
    pub(crate) fn new(
        instance: &'id mut pc::Instance,
        sources: &Sources,
        request: Request,
        limits: Limits,
        original: Targets,
    ) -> Result<Self, Error> {
        Ok(Self::Local(Singleton::new(
            instance, sources, request, limits, original,
        )?))
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Generated>, Error>> {
        match self {
            Self::Local(local) => match local.poll(cx) {
                Poll::Ready(Ok(Some(LocalProgress::Native))) => {
                    let native = local.take_native()?;
                    *self = Self::Native(native);
                    Poll::Ready(Ok(None))
                }
                Poll::Ready(Ok(Some(LocalProgress::Complete(result)))) => {
                    Poll::Ready(Ok(Some(result)))
                }
                Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            },
            Self::Native(native) => native.poll(cx),
        }
    }
    pub(crate) fn close(&mut self) -> Option<GenerateFacts> {
        match self {
            Self::Local(local) => local.close(),
            Self::Native(native) => native.close(),
        }
    }
}

enum LocalProgress {
    Native,
    Complete(Generated),
}

/// Actual local PILS observation and bounded singleton arithmetic jobs.
pub(crate) struct Singleton<'id> {
    pils: Option<pils::Client<'id, 1>>,
    sources: Option<keygen::Sources>,
    identity: Option<Identity<'id>>,
    clock: Arc<dyn RuntimeClock>,
    original: Targets,
    request: Option<Request>,
    limits: Limits,
    group: math::Group,
    state: State,
    start: u64,
    start_wait: Option<Pin<Box<Deadline>>>,
    random: Random,
    fixed_bytes: usize,
    connection_guard_bytes: usize,
    report: Option<GenerateFacts>,
}
impl<'id> Singleton<'id> {
    fn new(
        instance: &'id mut pc::Instance,
        sources: &Sources,
        request: Request,
        limits: Limits,
        original: Targets,
    ) -> Result<Self, Error> {
        original.check(sources.clock.as_ref())?;
        let original = original.deadline(sources.clock.as_ref(), request.deadline)?;
        if request.start >= original.canonical {
            return Err(Fault::Deadline.into());
        }
        let connect_clock = sources.clock();
        let connect_gate = move || {
            target_time(original, connect_clock.as_ref())
                .map(|_| ())
                .map_err(std::io::Error::other)
        };
        let guard_bytes = std::mem::size_of_val(&connect_gate)
            .checked_add(2 * size_of::<usize>())
            .ok_or(Fault::Overflow)?;
        let fixed_bytes = size_of::<Owner<'id>>()
            .checked_add(guard_bytes)
            .ok_or(Fault::Overflow)?
            .checked_add(
                sources
                    .consensus
                    .fixed_endpoint_storage_bytes()?
                    .ok_or(Fault::NotReady)?,
            )
            .and_then(|n| n.checked_add(request.bytes.capacity()))
            .and_then(|n| n.checked_add(size_of::<Deadline>() + 2 * size_of::<usize>()))
            .ok_or(Fault::Overflow)?;
        let requested_pils = sources
            .pils
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::NotReady)?
            .checked_add(
                limits
                    .decrypt
                    .pils
                    .frame_bytes
                    .checked_mul(4)
                    .ok_or(Fault::Overflow)?,
            )
            .and_then(|n| n.checked_add(limits.decrypt.hello.maximum_address_bytes))
            .ok_or(Fault::Overflow)?;
        if fixed_bytes
            .checked_add(requested_pils)
            .ok_or(Fault::Overflow)?
            > limits.operation_bytes
        {
            return Err(Fault::Capacity.into());
        }
        let pils = pils::Client::new_guarded(
            instance,
            sources.pils.duplicate()?,
            limits.decrypt.profile,
            limits.decrypt.pils,
            limits.decrypt.hello,
            Arc::new(connect_gate),
        )?;
        if fixed_bytes
            .checked_add(pils.storage_reservation_bytes()?)
            .ok_or(Fault::Overflow)?
            > limits.operation_bytes
        {
            return Err(Fault::Capacity.into());
        }
        let start = request.start;
        let report = GenerateFacts::new(request.session, start, request.deadline);
        Ok(Self {
            pils: Some(pils),
            sources: Some(sources.generation()?),
            identity: None,
            clock: sources.clock(),
            original,
            request: Some(request),
            limits,
            group: math::Group::new()?,
            state: State::Waiting,
            start,
            start_wait: None,
            random: Random {
                error: None,
                hard: original.hard,
            },
            fixed_bytes,
            connection_guard_bytes: guard_bytes,
            report: Some(report),
        })
    }
    fn facts(&mut self) -> Result<&mut GenerateFacts, Error> {
        self.report.as_mut().ok_or(Fault::NotReady.into())
    }
    fn take_native(&mut self) -> Result<Multiparty<'id>, Error> {
        self.guard()?;
        // This selector has not admitted any signing operation. The exact
        // observed physical PILS owner moves into the real protocol pipeline.
        let client = self.pils.as_ref().ok_or(Fault::Closed)?;
        if !client.is_idle() {
            return Err(Fault::NotReady.into());
        }
        let output_bytes = self
            .limits
            .frame_bytes
            .checked_mul(2)
            .ok_or(Fault::Overflow)?;
        let fixed = size_of::<Owner<'id>>()
            .checked_add(output_bytes)
            .and_then(|n| n.checked_add(self.connection_guard_bytes))
            .ok_or(Fault::Overflow)?;
        let available = self
            .limits
            .operation_bytes
            .checked_sub(fixed)
            .ok_or(Fault::Capacity)?;
        let limits = self.limits.generation(available);
        limits.validate()?;
        let request = self
            .request
            .take()
            .ok_or(Fault::NotReady)?
            .into_native(limits)?;
        let sources = self.sources.take().ok_or(Fault::NotReady)?;
        let client = self.pils.take().ok_or(Fault::Closed)?;
        let result = keygen::Generation::from_pils(
            client,
            self.identity.ok_or(Fault::NotReady)?,
            sources,
            request,
            limits,
            keygen::Bounds {
                expires: self.original.canonical,
                hard: self.original.hard,
            },
        );
        let native = match result {
            Ok(native) => native,
            Err(error) => {
                // from_pils performs no signing/IO; its failed construction
                // closes the transferred, actually idle client before return.
                self.state.close();
                if let Some(facts) = &mut self.report {
                    facts.pils_idle = true;
                }
                return Err(error.into());
            }
        };
        let mut facts = self.report.take().ok_or(Fault::NotReady)?;
        facts.multiparty = true;
        self.state.close();
        self.start_wait = None;
        Ok(Multiparty {
            native,
            clock: self.clock.clone(),
            original: self.original,
            limits: self.limits,
            fixed_bytes: fixed,
            output_bytes,
            report: Some(facts),
            closed: false,
        })
    }
    fn guard(&self) -> Result<u64, Error> {
        if self.state.is_closed() {
            return Err(Fault::Closed.into());
        }
        let now = target_time(self.original, self.clock.as_ref())?;
        if let Some(identity) = self.identity {
            let current = self
                .pils
                .as_ref()
                .ok_or(Fault::Closed)?
                .identity()
                .ok_or(Fault::StaleGeneration)?;
            if identity.epoch() != current.epoch()
                || identity.peer() != current.peer()
                || current.expiration().as_micros() <= now
            {
                return Err(Fault::StaleGeneration.into());
            }
        }
        self.account()?;
        Ok(now)
    }
    fn account(&self) -> Result<(), Error> {
        let bytes = self
            .live_fixed_bytes()?
            .checked_add(self.state.retained_bytes()?)
            .ok_or(Fault::Overflow)?;
        if bytes > self.limits.operation_bytes {
            return Err(Fault::Capacity.into());
        }
        Ok(())
    }
    fn live_fixed_bytes(&self) -> Result<usize, Error> {
        self.fixed_bytes
            .checked_add(
                self.pils
                    .as_ref()
                    .map_or(Ok(0), |pils| pils.storage_reservation_bytes())?,
            )
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn event(&mut self, event: pils::Progress<'id, 1>) -> Result<bool, Error> {
        match event {
            pils::Progress::Inbound(pc::Inbound::Identity { identity, .. }) => {
                if let Some(old) = self.identity {
                    if old.epoch() != identity.epoch() || old.peer() != identity.peer() {
                        return Err(Fault::StaleGeneration.into());
                    }
                } else {
                    self.identity = Some(identity);
                    self.facts()?.identity = Some((
                        *identity.peer().as_bytes(),
                        identity.epoch().value(),
                        identity.expiration().as_micros(),
                    ));
                    if !self
                        .request
                        .as_ref()
                        .ok_or(Fault::NotReady)?
                        .accepts(identity.peer().as_bytes())?
                    {
                        self.facts()?.multiparty = true;
                        return Ok(true);
                    }
                    self.request = None;
                    self.state =
                        State::Generating(PolynomialGenerator::new(1, self.limits.decrypt.math)?);
                    self.account()?;
                }
            }
            pils::Progress::Lost {
                epoch,
                cause,
                report,
            } => {
                let facts = self.facts()?;
                facts.pils_lost = Some((epoch.value(), report.retained()));
                facts.pils_loss = Some(cause);
                return Err(Fault::Unavailable.into());
            }
            pils::Progress::ConnectRetry { error, .. } => {
                self.facts()?.pils_retry.get_or_insert(error);
            }
            pils::Progress::Unavailable(error) => return Err(error.into()),
            pils::Progress::Closed => return Err(Fault::Closed.into()),
            pils::Progress::Inbound(pc::Inbound::Complete(_)) => {
                return Err(Fault::Authentication.into());
            }
            _ => {}
        }
        Ok(false)
    }
    fn work(&mut self, cx: &mut Context<'_>) -> Result<Option<Generated>, Error> {
        let now = self.guard()?;
        if self.identity.is_none() {
            return Ok(None);
        }
        let peer = *self.identity.ok_or(Fault::NotReady)?.peer().as_bytes();
        let fixed_bytes = self.live_fixed_bytes()?;
        if self.state.advance(
            &mut self.random,
            peer,
            &self.group,
            self.limits,
            fixed_bytes,
        )? {
            self.account()?;
            return Ok(None);
        }
        if now < self.start {
            if self.start_wait.is_none() {
                self.start_wait = Some(Box::pin(Deadline::at(
                    self.clock.clone(),
                    gnunet_types::AbsoluteTime::from_micros(self.start),
                )?));
            }
            if let Some(wait) = &mut self.start_wait {
                match wait.as_mut().poll(cx) {
                    Poll::Pending => return Ok(None),
                    Poll::Ready(result) => result?,
                }
            }
            self.start_wait = None;
            // Re-observe actual time/identity after a fallible deadline source.
            if self.guard()? < self.start {
                let mut wait = Box::pin(Deadline::at(
                    self.clock.clone(),
                    gnunet_types::AbsoluteTime::from_micros(self.start),
                )?);
                if let Poll::Ready(result) = wait.as_mut().poll(cx) {
                    result?;
                    return Err(Fault::TimeUncertain.into());
                }
                self.start_wait = Some(wait);
                return Ok(None);
            }
        }
        self.guard()?;
        let live = self.state.retained_bytes()?;
        let available = self
            .limits
            .operation_bytes
            .checked_sub(fixed_bytes)
            .and_then(|n| n.checked_sub(live))
            .ok_or(Fault::Capacity)?;
        let generated = encode_share(peer, self.state.material()?, self.limits, available)?;
        self.guard()?;
        self.facts()?.selection = Some((1, Some(0)));
        self.retire();
        if !self.report.as_ref().is_some_and(|r| r.pils_idle) {
            return Err(Fault::NotReady.into());
        }
        self.facts()?.completed = true;
        Ok(Some(generated))
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<LocalProgress>, Error>> {
        self.guard()?;
        let original = self.original;
        let clock = self.clock.clone();
        let mut before_io = || {
            target_time(original, clock.as_ref())
                .map(|_| ())
                .map_err(Into::into)
        };
        let event = self.pils.as_mut().ok_or(Fault::Closed)?.poll_guarded(
            cx,
            Some(original.hard.into()),
            &mut before_io,
        );
        let mut activity = false;
        match event {
            Poll::Ready(Ok(event)) => {
                if self.event(event)? {
                    return Poll::Ready(Ok(Some(LocalProgress::Native)));
                }
                activity = true;
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Pending => {}
        }
        self.guard()?;
        let doing_math = self.state.doing_math();
        match self.work(cx)? {
            Some(result) => Poll::Ready(Ok(Some(LocalProgress::Complete(result)))),
            None if activity || doing_math => Poll::Ready(Ok(None)),
            None => Poll::Pending,
        }
    }
    fn retire(&mut self) {
        if self.state.is_closed() {
            return;
        }
        let (retired, idle) = match &mut self.pils {
            Some(pils) => {
                let retired = pils.close();
                (retired, pils.is_idle())
            }
            None => ([None], false),
        };
        if let Some(report) = &mut self.report {
            report.pils_retired = retired.map(|op| op.map(|op| op.value()));
            report.pils_idle = idle;
            report.entropy_error = self.random.error.take();
        }
        self.state.close();
        self.request = None;
        self.sources = None;
        self.start_wait = None;
    }
    fn close(&mut self) -> Option<GenerateFacts> {
        self.retire();
        self.report.take()
    }
}
impl Drop for Singleton<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Same-epoch native generation and its finite output reservation. The native
/// owner budgets every original phase; a separate maximum-frame allowance
/// covers the live zeroizing result and secure queue copy at handoff.
pub(crate) struct Multiparty<'id> {
    native: keygen::Generation<'id>,
    clock: Arc<dyn RuntimeClock>,
    original: Targets,
    limits: Limits,
    fixed_bytes: usize,
    output_bytes: usize,
    report: Option<GenerateFacts>,
    closed: bool,
}
impl Multiparty<'_> {
    fn account(&self) -> Result<(), Error> {
        let retained = self
            .native
            .retained_bytes()?
            .checked_add(self.fixed_bytes)
            .ok_or(Fault::Overflow)?;
        if retained > self.limits.operation_bytes {
            Err(Fault::Capacity.into())
        } else {
            Ok(())
        }
    }
    fn capture(&mut self, report: keygen::GenerationReport<'_>) -> Result<(), Error> {
        let facts = self.report.as_mut().ok_or(Fault::NotReady)?;
        facts.completed = report.completed;
        facts.pils_idle = report.pils_idle;
        if let Some(round1) = report.round1 {
            if let Some(identity) = round1.identity {
                facts.identity = Some((
                    *identity.peer().as_bytes(),
                    identity.epoch().value(),
                    identity.expiration().as_micros(),
                ));
            }
            if facts.pils_retry.is_none() {
                facts.pils_retry = round1.pils_retry;
            }
            facts.pils_retired = round1.pils_retired.map(|id| id.map(|id| id.value()));
            facts.entropy_error = round1.entropy_error;
            if let Some(loss) = round1.pils_loss {
                facts.pils_lost = Some((loss.epoch.value(), loss.report.retained()));
                facts.pils_loss = Some(loss.cause);
            }
            facts.signatures[0] = Some(crate::types::GenerationSignatureFacts {
                operation: round1.signature_operation.map(|id| id.value()),
                written: round1.signature_written,
                completion: round1
                    .signature_completion
                    .as_ref()
                    .map(crate::types::signature_fact),
                unknown: round1.signature_result_unknown,
            });
            facts.rounds[0] = Some(crate::types::GenerationConsensusFacts {
                contribution: round1.contribution.map(Into::into),
                completion: (round1.conclude_written, round1.consensus_done),
                loss: round1.consensus_loss,
                retry: round1.consensus_retry,
            });
        }
        if let Some(round2) = report.round2 {
            if facts.pils_retry.is_none() {
                facts.pils_retry = round2.pils_retry;
            }
            if let Some(loss) = round2.pils_loss
                && facts.pils_loss.is_none()
            {
                facts.pils_lost = Some((loss.epoch.value(), loss.report.retained()));
                facts.pils_loss = Some(loss.cause);
            }
            facts.signatures[1] = Some(crate::types::GenerationSignatureFacts {
                operation: round2.signature_operation.map(|id| id.value()),
                written: round2.signature_written.is_some(),
                completion: round2
                    .signature_completion
                    .as_ref()
                    .map(crate::types::signature_fact),
                unknown: round2.signature_result_unknown,
            });
            facts.rounds[1] = Some(crate::types::GenerationConsensusFacts {
                contribution: round2.own_insert.map(Into::into),
                completion: (round2.conclude.is_some(), round2.done),
                loss: round2.loss,
                retry: round2.retry,
            });
        }
        self.closed = true;
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Generated>, Error>> {
        target_time(self.original, self.clock.as_ref())?;
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        self.account()?;
        match self.native.poll_progress(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(keygen::GenerationProgress::Complete(finalized))) => {
                target_time(self.original, self.clock.as_ref())?;
                let result_bytes = finalized.retained_bytes()?;
                let peak = self
                    .native
                    .retained_bytes()?
                    .checked_add(self.fixed_bytes)
                    .and_then(|n| n.checked_add(result_bytes))
                    .ok_or(Fault::Overflow)?;
                if peak > self.limits.operation_bytes {
                    return Poll::Ready(Err(Fault::Capacity.into()));
                }
                let rows = finalized.material().participants().len();
                let length = rows
                    .checked_mul(ipc::SHARE_ROW_BYTES)
                    .and_then(|n| n.checked_add(ipc::SHARE_PREFIX + 4))
                    .ok_or(Fault::Overflow)?;
                let mut generated =
                    Generated::allocate(length, self.limits.frame_bytes, self.output_bytes)?;
                let actual = finalized
                    .encode_secret_ready(generated.frame.as_mut(), self.limits.index_order)?;
                if actual != length {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
                target_time(self.original, self.clock.as_ref())?;
                self.report.as_mut().ok_or(Fault::NotReady)?.selection =
                    Some((rows, finalized.material().local_position()));
                let report = self.native.take_report().ok_or(Fault::NotReady)?;
                let healthy = report.completed && report.pils_idle;
                self.capture(report)?;
                if !healthy {
                    return Poll::Ready(Err(Fault::NotReady.into()));
                }
                Poll::Ready(Ok(Some(generated)))
            }
            Poll::Ready(Ok(_)) => {
                self.account()?;
                Poll::Ready(Ok(None))
            }
        }
    }
    fn close(&mut self) -> Option<GenerateFacts> {
        if !self.closed
            && let Some(report) = self.native.close()
        {
            let _captured = self.capture(report);
        }
        self.report.take()
    }
}
impl Drop for Multiparty<'_> {
    fn drop(&mut self) {
        let _report = self.close();
    }
}

// Shape formation is private to the actual completed singleton owner. It is
// not a constructor of a remote-qualified DKG or FAIR certificate.
fn encode_share(
    peer: [u8; 32],
    material: &AggregateMaterial,
    limits: Limits,
    available: usize,
) -> Result<Generated, Error> {
    let member = material.participants().first().ok_or(Fault::NotReady)?;
    if material.local_position() != Some(0)
        || material.participants().len() != 1
        || material.threshold() != 1
        || member.peer != peer
        || member.original_index != 0
    {
        return Err(Fault::Conflict.into());
    }
    let public = material.public_key().to_bytes();
    let sigma = member.sigma.to_bytes();
    let secret = material.secret().to_bytes();
    let mut generated = Generated::allocate(RESPONSE_BYTES, limits.frame_bytes, available)?;
    ipc::ShareEncoder {
        threshold: 1,
        my_peer: 0,
        public_key: &public,
        secret: &secret,
        peers: 1,
        order: limits.index_order,
    }
    .encode_secret_ready(generated.frame.as_mut(), |_| ipc::ShareRow {
        peer,
        sigma,
        original_index: 0,
    })?;
    Ok(generated)
}

#[cfg(test)]
mod tests;
