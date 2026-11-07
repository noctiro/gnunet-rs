use crate::{Bounds, Error, Limits, PilsLoss, Progress, Report, Request, Sources};
use gnunet_consensus_client_host as consensus;
use gnunet_pils::client::{self as pc, Identity, KeyTarget, OperationId};
use gnunet_pils_host::client as pils;
use gnunet_secretsharing::{
    self as math, CombineJob, MembershipJob, PartialProver, PartialVerifier, Participant, Roster,
    RosterCheck, Scalar, Subgroup, UnsignedPartial, VerifiedPartial,
};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    consensus::Join,
    secretsharing::{self as ipc, SignedElement},
};
use std::{
    future::{Future, poll_fn},
    mem::{size_of, size_of_val},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

// Local-quorum IO uses the exact original targets after provider work too.
fn target_time(bounds: Bounds, clock: &dyn RuntimeClock) -> Result<u64, Fault> {
    if Instant::now() >= bounds.hard {
        return Err(Fault::Deadline);
    }
    let now = clock.sample()?.now.as_micros();
    if Instant::now() >= bounds.hard || now >= bounds.expires {
        return Err(Fault::Deadline);
    }
    Ok(now)
}

#[derive(Default)]
struct Random {
    error: Option<getrandom::Error>,
}
impl math::Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Fault> {
        if self.error.is_some() {
            out.fill(0);
            return Err(Fault::EntropyUnavailable);
        }
        getrandom::fill(out).map_err(|e| {
            out.fill(0);
            self.error = Some(e);
            Fault::EntropyUnavailable
        })
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Cipher,
    Public,
    Members,
    Roster,
    Prove,
    Sign,
    OwnVerify,
    Insert,
    Receive,
    Combine,
    Closed,
}
/// One actual original781 owner. Polling starts no hidden worker or service.
/// All native sources, original intents and mathematical cursors survive an
/// observation future being dropped; explicit close physically retires every
/// constructed MQ. Threshold one needs no CONSENSUS source.
pub struct Decrypt<'a> {
    pils: pils::Client<'a, 1>,
    consensus: Option<consensus::Client>,
    local_threshold_one: bool,
    clock: Arc<dyn RuntimeClock>,
    bounds: Bounds,
    limits: Limits,
    identity: Option<Identity<'a>>,
    consensus_epoch: Option<consensus::Epoch>,
    request: Option<Request>,
    start: u64,
    deadline: u64,
    local: usize,
    count: usize,
    cipher_raw: [u8; 256],
    group: math::Group,
    cipher: Option<math::Ciphertext>,
    cipher_check: Option<math::CiphertextCheck>,
    member_check: Option<MembershipJob>,
    public: Option<Subgroup>,
    members: Vec<Participant>,
    member_at: usize,
    roster_check: Option<RosterCheck>,
    roster: Option<Roster>,
    prover: Option<PartialProver>,
    unsigned: Option<UnsignedPartial>,
    signed: Option<[u8; 872]>,
    sign: Option<OperationId<'a>>,
    verifier: Option<PartialVerifier>,
    verifier_peer: Option<[u8; 32]>,
    held: Option<consensus::Observation>,
    partials: Vec<VerifiedPartial>,
    insert: Option<consensus::InsertId>,
    combining: Option<CombineJob<'static>>,
    phase: Phase,
    random: Random,
    consensus_closed: bool,
    own_inserted: bool,
    closed: bool,
    turn: bool,
    fixed_reservation: usize,
    roster_bytes: usize,
    partial_bytes: usize,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    start_wait: Option<Pin<Box<Deadline>>>,
    report: Option<Report<'a>>,
}
impl<'a> Decrypt<'a> {
    /// Adopt the original request and actual selected sources. Only source
    /// subscriptions/public setup are constructed; no I/O or entropy is polled.
    pub fn new(
        instance: &'a mut pc::Instance,
        sources: Sources,
        request: Request,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = sources.pils.clock();
        let native = Instant::now();
        let now = clock.sample()?.now.as_micros();
        let expires = original.expires.min(request.deadline);
        let remaining = expires
            .checked_sub(now)
            .filter(|v| *v != 0)
            .ok_or(Fault::Deadline)?;
        let hard = native
            .checked_add(Duration::from_micros(remaining))
            .ok_or(Fault::Overflow)?
            .min(original.hard);
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let bounds = Bounds { expires, hard };
        let threshold = usize::from(request.share()?.threshold());
        let local_threshold_one = threshold == 1;
        if local_threshold_one && request.start >= expires {
            return Err(Fault::Deadline.into());
        }
        let source_bytes = if local_threshold_one {
            sources
                .pils
                .fixed_endpoint_storage_bytes()?
                .ok_or(Fault::NotReady)?
        } else {
            sources.bytes
        };
        let connect_clock = clock.clone();
        let connect_gate = move || {
            target_time(bounds, connect_clock.as_ref())
                .map(|_| ())
                .map_err(std::io::Error::other)
        };
        let local_bytes = if local_threshold_one {
            size_of_val(&connect_gate)
                .checked_add(2 * size_of::<usize>())
                .and_then(|n| n.checked_add(size_of::<Deadline>()))
                .ok_or(Fault::Overflow)?
        } else {
            0
        };
        let consensus_bytes = if local_threshold_one {
            0
        } else {
            limits
                .consensus
                .retained_bytes
                .checked_add(limits.consensus.frame_bytes)
                .ok_or(Fault::Overflow)?
        };
        let partial_count = if local_threshold_one {
            1
        } else {
            request.count
        };
        let peer_count = if local_threshold_one {
            0
        } else {
            request.count
        };
        let fixed_reservation = size_of::<Self>()
            .checked_add(source_bytes)
            .and_then(|n| n.checked_add(local_bytes))
            .and_then(|n| n.checked_add(consensus_bytes))
            .and_then(|n| {
                limits
                    .pils
                    .frame_bytes
                    .checked_mul(4)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(limits.hello.maximum_address_bytes))
            .ok_or(Fault::Overflow)?;
        let projected = fixed_reservation
            .checked_add(request.bytes.capacity())
            .and_then(|n| {
                request
                    .count
                    .checked_mul(size_of::<Participant>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                partial_count
                    .checked_mul(size_of::<VerifiedPartial>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| peer_count.checked_mul(32).and_then(|m| n.checked_add(m)))
            .ok_or(Fault::Overflow)?;
        if projected > limits.retained_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut members = Vec::new();
        members
            .try_reserve_exact(request.count)
            .map_err(|_| Fault::Capacity)?;
        let mut partials = Vec::new();
        partials
            .try_reserve_exact(partial_count)
            .map_err(|_| Fault::Capacity)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(peer_count)
            .map_err(|_| Fault::Capacity)?;
        let share = request.share()?;
        for index in 0..peer_count {
            peers.push(*share.peer(index)?.ok_or(Fault::Malformed)?);
        }
        let roster_bytes = members
            .capacity()
            .checked_mul(size_of::<Participant>())
            .ok_or(Fault::Overflow)?;
        let partial_bytes = partials
            .capacity()
            .checked_mul(size_of::<VerifiedPartial>())
            .ok_or(Fault::Overflow)?;
        let allocated = fixed_reservation
            .checked_add(roster_bytes)
            .and_then(|n| n.checked_add(partial_bytes))
            .and_then(|n| n.checked_add(request.bytes.capacity()))
            .and_then(|n| {
                peers
                    .capacity()
                    .checked_mul(32)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Fault::Overflow)?;
        if allocated > limits.retained_bytes {
            return Err(Fault::Capacity.into());
        }
        let consensus = if local_threshold_one {
            None
        } else {
            Some(consensus::Client::new(
                sources.consensus,
                Join {
                    session: gnunet_crypto::hash512(&request.cipher),
                    start: request.start,
                    deadline: request.deadline,
                    peers: &peers,
                },
                limits.consensus,
                bounds,
            )?)
        };
        drop(peers);
        let pils = if local_threshold_one {
            pils::Client::new_guarded(
                instance,
                sources.pils,
                limits.profile,
                limits.pils,
                limits.hello,
                Arc::new(connect_gate),
            )?
        } else {
            pils::Client::new(
                instance,
                sources.pils,
                limits.profile,
                limits.pils,
                limits.hello,
            )?
        };
        let group = math::Group::new()?;
        let cipher_check = Some(math::CiphertextCheck::new(
            &request.cipher,
            &group,
            limits.math,
        )?);
        let start = request.start;
        let deadline = request.deadline;
        let local = request.local;
        let count = request.count;
        let cipher_raw = request.cipher;
        let report = Report {
            ciphertext: cipher_raw,
            session: gnunet_crypto::hash512(&cipher_raw),
            start,
            deadline,
            participants: count,
            threshold,
            local_threshold_one,
            ..Report::default()
        };
        Ok(Self {
            pils,
            consensus,
            local_threshold_one,
            clock,
            bounds,
            limits,
            identity: None,
            consensus_epoch: None,
            request: Some(request),
            start,
            deadline,
            local,
            count,
            cipher_raw,
            group,
            cipher: None,
            cipher_check,
            member_check: None,
            public: None,
            members,
            member_at: 0,
            roster_check: None,
            roster: None,
            prover: None,
            unsigned: None,
            signed: None,
            sign: None,
            verifier: None,
            verifier_peer: None,
            held: None,
            partials,
            insert: None,
            combining: None,
            phase: Phase::Cipher,
            random: Random::default(),
            consensus_closed: local_threshold_one,
            own_inserted: false,
            closed: false,
            turn: false,
            fixed_reservation,
            roster_bytes,
            partial_bytes,
            timer: None,
            start_wait: None,
            report: Some(report),
        })
    }
    /// Original actual request start, not a renewed local timer.
    pub const fn start(&self) -> u64 {
        self.start
    }
    /// Original actual request deadline, independent of the clamped parent hard.
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }
    /// Exact ciphertext-derived session context; local threshold one sends no JOIN.
    pub fn session_id(&self) -> [u8; 64] {
        gnunet_crypto::hash512(&self.cipher_raw)
    }
    fn facts(&mut self) -> Result<&mut Report<'a>, Error> {
        self.report.as_mut().ok_or_else(|| Fault::Closed.into())
    }
    /// Actual retained owner allocation reservation. The original Roster and
    /// verified-partial Vec move into Combine and remain counted exactly once.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.fixed_reservation
            .checked_add(self.roster_bytes)
            .and_then(|n| n.checked_add(self.partial_bytes))
            .and_then(|n| n.checked_add(self.request.as_ref().map_or(0, |r| r.bytes.capacity())))
            .ok_or_else(|| Fault::Overflow.into())
    }
    /// Original source/operation facts, without cloning any source/secret result.
    pub fn report(&self) -> Option<&Report<'a>> {
        self.report.as_ref()
    }
    /// Actual original canonical/native targets; never renewed by source retry.
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }
    fn native(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if Instant::now() >= self.bounds.hard {
            return Err(Fault::Deadline.into());
        }
        if self.timer.is_none() {
            self.timer = Some(Box::pin(tokio::time::sleep_until(self.bounds.hard.into())));
        }
        if self
            .timer
            .as_mut()
            .is_some_and(|t| t.as_mut().poll(cx).is_ready())
        {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn signing_identity(&self, now: u64) -> Result<Identity<'a>, Error> {
        let original = self.identity.ok_or(Fault::NotReady)?;
        let actual = self.pils.identity().ok_or(Fault::StaleGeneration)?;
        if self.pils.epoch() != Some(original.epoch())
            || actual.epoch() != original.epoch()
            || actual.peer() != original.peer()
            || actual.address_hash() != original.address_hash()
            || actual.coverage() != original.coverage()
            || original.expiration().as_micros() <= now
            || actual.expiration().as_micros() <= now
        {
            return Err(Fault::StaleGeneration.into());
        }
        // Original transcript/proof identity and bounds are never refreshed.
        // Only this new Exact admission consumes the current announcement.
        Ok(actual)
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<u64, Error> {
        self.native(cx)?;
        let now = self.clock.sample()?.now.as_micros();
        self.native(cx)?;
        if now >= self.bounds.expires {
            return Err(Fault::Deadline.into());
        }
        if let Some(original) = self.identity {
            let current = self.pils.identity().ok_or(Fault::StaleGeneration)?;
            if original.epoch() != current.epoch()
                || original.peer() != current.peer()
                || current.expiration().as_micros() <= now
                || (self.local_threshold_one && original.expiration().as_micros() <= now)
            {
                return Err(Fault::StaleGeneration.into());
            }
        }
        Ok(now)
    }
    fn erase(&mut self) {
        if let Some(j) = &mut self.cipher_check {
            j.cancel();
        }
        if let Some(j) = &mut self.member_check {
            j.cancel();
        }
        if let Some(j) = &mut self.roster_check {
            j.cancel();
        }
        if let Some(j) = &mut self.prover {
            j.cancel();
        }
        if let Some(j) = &mut self.verifier {
            j.cancel();
        }
        if let Some(j) = &mut self.combining {
            j.cancel();
        }
        self.request = None;
        self.prover = None;
        self.unsigned = None;
        self.signed = None;
        self.cipher_check = None;
        self.member_check = None;
        self.roster_check = None;
        self.verifier = None;
        self.combining = None;
        self.roster = None;
        self.members = Vec::new();
        self.partials = Vec::new();
        self.held = None;
        self.roster_bytes = 0;
        self.partial_bytes = 0;
    }
    fn retire(&mut self) {
        if self.closed {
            return;
        }
        // Physically stop every constructed source before fallible/pure cleanup.
        if !self.consensus_closed
            && let Some(consensus) = &mut self.consensus
        {
            let loss = consensus.close();
            if let Some(r) = &mut self.report {
                r.consensus_loss.get_or_insert(loss);
            }
            self.consensus_closed = true;
        }
        let retired = self.pils.close();
        let idle = self.pils.is_idle();
        if let Some(r) = &mut self.report {
            r.signature_result_unknown = self.sign.is_some() && r.signature_completion.is_none();
            r.pils_retired = retired;
            r.pils_idle = idle;
        }
        self.closed = true;
        self.phase = Phase::Closed;
        self.timer = None;
        self.start_wait = None;
        self.erase();
    }
    /// Physically close all constructed original MQs, retain actual unfinished-operation
    /// facts and erase original secret work. No cancel wire or replay exists.
    pub fn close(&mut self) -> Option<Report<'a>> {
        if !self.closed
            && let Some(r) = &mut self.report
        {
            r.cancelled = true;
        }
        self.retire();
        self.report.take()
    }
    /// Transfer final facts only after this original owner physically retired.
    pub fn take_report(&mut self) -> Option<Report<'a>> {
        if self.closed {
            self.report.take()
        } else {
            None
        }
    }
    fn failed(&mut self, error: Error) -> Poll<Result<Progress, Error>> {
        self.retire();
        Poll::Ready(Err(error))
    }
    fn pils_event(&mut self, event: pils::Progress<'a, 1>) -> Result<(), Error> {
        match event {
            pils::Progress::Inbound(pc::Inbound::Identity { identity, .. }) => {
                if let Some(original) = self.identity {
                    if original.epoch() != identity.epoch() || original.peer() != identity.peer() {
                        return Err(Fault::StaleGeneration.into());
                    }
                } else {
                    let request = self.request.as_ref().ok_or(Fault::NotReady)?;
                    let share = request.share()?;
                    if share.peer(request.local)?.ok_or(Fault::Malformed)?
                        != identity.peer().as_bytes()
                    {
                        return Err(Fault::PermissionDenied.into());
                    }
                    self.identity = Some(identity);
                    self.facts()?.identity = Some(identity);
                }
            }
            pils::Progress::Inbound(pc::Inbound::Complete(completion)) => {
                let outcome = (|| -> Result<[u8; 872], Error> {
                    if Some(completion.operation()) != self.sign {
                        return Err(Fault::StaleGeneration.into());
                    }
                    let pc::Completion::Signature {
                        peer,
                        signature,
                        announced,
                        ..
                    } = &completion
                    else {
                        return Err(Fault::Authentication.into());
                    };
                    let original = self.identity.ok_or(Fault::NotReady)?;
                    let announced = announced.ok_or(Fault::StaleGeneration)?;
                    if *peer != original.peer()
                        || announced.epoch() != original.epoch()
                        || announced.peer() != original.peer()
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    Ok(self
                        .unsigned
                        .take()
                        .ok_or(Fault::NotReady)?
                        .accept_signature(*signature)?)
                })();
                self.facts()?.signature_completion = Some(completion);
                let signed = outcome?;
                self.signed = Some(signed);
                self.phase = Phase::OwnVerify;
            }
            pils::Progress::Written(written) => {
                if Some(written.operation) == self.sign {
                    self.facts()?.signature_written = true;
                }
            }
            pils::Progress::Lost {
                epoch,
                cause,
                report,
            } => {
                self.facts()?.pils_loss = Some(PilsLoss {
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
            _ => {}
        }
        Ok(())
    }
    fn checked_member(&self, index: usize) -> Result<Participant, Error> {
        self.roster
            .as_ref()
            .ok_or(Fault::NotReady)?
            .get(index)
            .ok_or_else(|| Fault::Malformed.into())
    }
    fn math_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress>, Error> {
        if self.identity.is_none() {
            return Ok(None);
        }
        let units = self.limits.math.units_per_turn;
        match self.phase {
            Phase::Cipher => {
                let job = self.cipher_check.as_mut().ok_or(Fault::NotReady)?;
                if job.advance(units)? == math::Progress::Ready {
                    self.cipher = Some(job.take_result()?);
                    self.cipher_check = None;
                    let public = *self
                        .request
                        .as_ref()
                        .ok_or(Fault::NotReady)?
                        .share()?
                        .public_key()?;
                    self.member_check = Some(MembershipJob::new(
                        math::Element::from_bytes(&public)?,
                        &self.group,
                        self.limits.math,
                    )?);
                    self.phase = Phase::Public;
                }
            }
            Phase::Public => {
                let job = self.member_check.as_mut().ok_or(Fault::NotReady)?;
                if job.advance(units)? == math::Progress::Ready {
                    self.public = Some(job.take_result()?);
                    self.member_check = None;
                    self.phase = Phase::Members;
                }
            }
            Phase::Members => {
                if self.member_at == self.count {
                    let threshold = usize::from(
                        self.request
                            .as_ref()
                            .ok_or(Fault::NotReady)?
                            .share()?
                            .threshold(),
                    );
                    let members = std::mem::take(&mut self.members);
                    self.roster_check = Some(Roster::check(
                        members,
                        threshold,
                        self.public.ok_or(Fault::NotReady)?,
                        self.limits.math,
                    )?);
                    self.phase = Phase::Roster;
                } else {
                    if self.member_check.is_none() {
                        let sigma = *self
                            .request
                            .as_ref()
                            .ok_or(Fault::NotReady)?
                            .share()?
                            .sigma(self.member_at)?
                            .ok_or(Fault::Malformed)?;
                        self.member_check = Some(MembershipJob::new(
                            math::Element::from_bytes(&sigma)?,
                            &self.group,
                            self.limits.math,
                        )?);
                    }
                    let job = self.member_check.as_mut().ok_or(Fault::NotReady)?;
                    if job.advance(units)? == math::Progress::Ready {
                        let sigma = job.take_result()?;
                        self.member_check = None;
                        let request = self.request.as_ref().ok_or(Fault::NotReady)?;
                        let share = request.share()?;
                        let peer = *share.peer(self.member_at)?.ok_or(Fault::Malformed)?;
                        let original_index = share
                            .original_index(self.member_at, request.order)?
                            .ok_or(Fault::Malformed)?;
                        self.members.push(Participant {
                            peer,
                            original_index,
                            sigma,
                        });
                        self.member_at += 1;
                    }
                }
            }
            Phase::Roster => {
                let check = self.roster_check.as_mut().ok_or(Fault::NotReady)?;
                if check.advance(units)? == math::Progress::Ready {
                    self.roster = Some(check.take_result()?);
                    self.roster_check = None;
                    let local = self.checked_member(self.local)?;
                    let identity = self.identity.ok_or(Fault::NotReady)?;
                    if local.peer != *identity.peer().as_bytes() {
                        return Err(math::Error::Roster.into());
                    }
                    let secret = Scalar::from_bytes(
                        self.request
                            .as_ref()
                            .ok_or(Fault::NotReady)?
                            .share()?
                            .secret()?,
                    )?;
                    self.prover = Some(PartialProver::new(
                        &self.group,
                        self.cipher.ok_or(Fault::NotReady)?,
                        local.peer,
                        local.sigma,
                        secret,
                        self.limits.math,
                    )?);
                    self.request = None;
                    self.phase = Phase::Prove;
                }
            }
            Phase::Prove => {
                let job = self.prover.as_mut().ok_or(Fault::NotReady)?;
                if job.advance(&mut self.random, units)? == math::Progress::Ready {
                    self.unsigned = Some(job.take_unsigned()?);
                    self.prover = None;
                    self.phase = Phase::Sign;
                }
            }
            Phase::Sign => {
                if self.sign.is_none() {
                    let now = self.guard(cx)?;
                    let target = self.signing_identity(now)?;
                    let region = self
                        .unsigned
                        .as_ref()
                        .ok_or(Fault::NotReady)?
                        .signed_bytes();
                    let op = self.pils.sign(region, KeyTarget::Exact(target))?;
                    self.sign = Some(op);
                    self.facts()?.signature_operation = Some(op);
                } else {
                    return Ok(None);
                }
            }
            Phase::OwnVerify => {
                if self.verifier.is_none() {
                    let local = self.checked_member(self.local)?;
                    let bytes = self.signed.as_ref().ok_or(Fault::NotReady)?;
                    self.verifier = Some(PartialVerifier::new(
                        &self.group,
                        self.cipher.ok_or(Fault::NotReady)?,
                        local.peer,
                        local.original_index,
                        local.sigma,
                        bytes,
                        self.limits.math,
                    )?);
                    self.verifier_peer = Some(local.peer);
                }
                let job = self.verifier.as_mut().ok_or(Fault::NotReady)?;
                if job.advance(units)? == math::Progress::Ready {
                    let partial = job.take_result()?;
                    self.verifier = None;
                    self.partials.push(partial);
                    self.facts()?.verified = self.partials.len();
                    self.verifier_peer = None;
                    if self.local_threshold_one {
                        self.signed = None;
                        self.begin_combine()?;
                    } else {
                        self.phase = Phase::Insert;
                    }
                }
            }
            Phase::Insert => {
                self.guard(cx)?;
                if self.insert.is_none() {
                    let bytes = self.signed.as_ref().ok_or(Fault::NotReady)?;
                    match self
                        .consensus
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .insert(0, bytes)
                    {
                        Ok(insert) => self.insert = Some(insert),
                        Err(consensus::Error::Protocol(Fault::WouldBlock)) => return Ok(None),
                        Err(error) => return Err(error.into()),
                    }
                }
                match self.consensus.as_mut().ok_or(Fault::NotReady)?.conclude() {
                    Ok(()) => {
                        self.signed = None;
                        self.phase = Phase::Receive;
                    }
                    Err(consensus::Error::Protocol(Fault::WouldBlock)) => return Ok(None),
                    Err(error) => return Err(error.into()),
                }
            }
            Phase::Receive => {
                if let Some(verifier) = &mut self.verifier {
                    match verifier.advance(units) {
                        Ok(math::Progress::Ready) => {
                            let partial = verifier.take_result()?;
                            self.verifier = None;
                            self.verifier_peer = None;
                            self.partials.push(partial);
                            self.facts()?.verified = self.partials.len();
                        }
                        Ok(math::Progress::Advanced) => {}
                        Err(error) if Self::invalid(error) => {
                            self.verifier = None;
                            let peer = self.verifier_peer.take();
                            return self.reject(peer, error).map(Some);
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else if let Some(observation) = self.held.take() {
                    return self.observation(observation).map(Some);
                } else if self.report.as_ref().is_some_and(|r| r.consensus_done) {
                    if !self.own_inserted
                        || !self.report.as_ref().is_some_and(|r| r.conclude_written)
                    {
                        return Err(Fault::NotReady.into());
                    }
                    self.begin_combine()?;
                } else {
                    return Ok(None);
                }
            }
            Phase::Combine => {
                if self.local_threshold_one && !self.start_ready(cx)? {
                    return Ok(None);
                }
                let job = self.combining.as_mut().ok_or(Fault::NotReady)?;
                if job.advance(units)? == math::Progress::Ready {
                    self.guard(cx)?;
                    let plaintext = self
                        .combining
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .take_result()?;
                    self.facts()?.completed = true;
                    self.retire();
                    return Ok(Some(Progress::Done(plaintext)));
                }
            }
            Phase::Closed => return Err(Fault::Closed.into()),
        }
        Ok(Some(Progress::Activity))
    }
    fn begin_combine(&mut self) -> Result<(), Error> {
        let roster = self.roster.take().ok_or(Fault::NotReady)?;
        if self.partials.len() < roster.threshold() {
            return Err(math::Error::Roster.into());
        }
        self.combining = Some(CombineJob::new_owned(
            roster,
            self.cipher.ok_or(Fault::NotReady)?,
            std::mem::take(&mut self.partials),
            &self.group,
            self.limits.math,
        )?);
        self.phase = Phase::Combine;
        Ok(())
    }
    fn start_ready(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.guard(cx)? >= self.start {
            self.start_wait = None;
            return Ok(true);
        }
        if self.start_wait.is_none() {
            self.start_wait = Some(Box::pin(Deadline::at(
                self.clock.clone(),
                gnunet_types::AbsoluteTime::from_micros(self.start),
            )?));
        }
        let wait = self.start_wait.as_mut().ok_or(Fault::NotReady)?;
        match wait.as_mut().poll(cx) {
            Poll::Pending => return Ok(false),
            Poll::Ready(result) => result?,
        }
        self.start_wait = None;
        // A completed future is never polled again. Provider work cannot renew
        // the original hard or grant output before the original start.
        if self.guard(cx)? < self.start {
            let mut wait = Box::pin(Deadline::at(
                self.clock.clone(),
                gnunet_types::AbsoluteTime::from_micros(self.start),
            )?);
            if let Poll::Ready(result) = wait.as_mut().poll(cx) {
                result?;
                return Err(Fault::TimeUncertain.into());
            }
            self.start_wait = Some(wait);
            return Ok(false);
        }
        Ok(true)
    }
    fn invalid(error: math::Error) -> bool {
        matches!(
            error,
            math::Error::InvalidInput
                | math::Error::InvalidProof
                | math::Error::Roster
                | math::Error::Source(
                    Fault::Authentication
                        | Fault::Malformed
                        | Fault::Truncated
                        | Fault::Unsupported
                )
        )
    }
    fn reject(&mut self, peer: Option<[u8; 32]>, reason: math::Error) -> Result<Progress, Error> {
        let report = self.facts()?;
        report.rejected = report.rejected.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(Progress::Rejected { peer, reason })
    }
    fn observation(&mut self, observation: consensus::Observation) -> Result<Progress, Error> {
        if self.consensus_epoch.as_ref() != Some(observation.epoch()) {
            return Err(Fault::StaleGeneration.into());
        }
        let consensus::ClientResponse::Element { element_type, data } = observation.response()?
        else {
            return Err(Fault::Malformed.into());
        };
        if element_type != 0 || data.len() != ipc::DECRYPT_ELEMENT_BYTES {
            return self.reject(None, math::Error::InvalidInput);
        }
        let bytes: &[u8; 872] = data.try_into().map_err(|_| Fault::Malformed)?;
        let element = match SignedElement::decryption(bytes) {
            Ok(value) => value,
            Err(error) => return self.reject(None, math::Error::Source(error)),
        };
        let peer = *element.peer()?;
        if self.partials.iter().any(|p| p.peer() == &peer) {
            return self.reject(Some(peer), math::Error::Roster);
        }
        let roster = self.roster.as_ref().ok_or(Fault::NotReady)?;
        let member = (0..roster.len())
            .filter_map(|i| roster.get(i))
            .find(|m| m.peer == peer);
        let Some(member) = member else {
            return self.reject(Some(peer), math::Error::Roster);
        };
        match PartialVerifier::new(
            &self.group,
            self.cipher.ok_or(Fault::NotReady)?,
            peer,
            member.original_index,
            member.sigma,
            bytes,
            self.limits.math,
        ) {
            Ok(verifier) => {
                self.verifier = Some(verifier);
                self.verifier_peer = Some(peer);
                Ok(Progress::Activity)
            }
            Err(error) if Self::invalid(error) => self.reject(Some(peer), error),
            Err(error) => Err(error.into()),
        }
    }
    fn consensus_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress>, Error> {
        if self.identity.is_none() || self.consensus_closed || self.held.is_some() {
            return Ok(None);
        }
        self.guard(cx)?;
        // This native guard runs before any new source IO and physically closes
        // first if its original child deadline has already expired.
        if let Some(loss) = self
            .consensus
            .as_mut()
            .ok_or(Fault::NotReady)?
            .poll_native_guard(cx)
        {
            self.consensus_closed = true;
            self.facts()?.consensus_loss = Some(loss);
            return Err(Fault::Deadline.into());
        }
        let event = match self
            .consensus
            .as_mut()
            .ok_or(Fault::NotReady)?
            .poll_progress(cx)
        {
            Poll::Pending => return Ok(None),
            Poll::Ready(event) => event?,
        };
        match event {
            consensus::Progress::Attached(epoch) => {
                if self.consensus_epoch.as_ref().is_some_and(|e| e != &epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                self.consensus_epoch = Some(epoch);
            }
            consensus::Progress::Written(receipt) => {
                if self.consensus_epoch.as_ref() != Some(&receipt.epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                match &receipt.kind {
                    consensus::Kind::Insert(id) => {
                        if Some(id) != self.insert.as_ref() {
                            return Err(Fault::StaleGeneration.into());
                        }
                        self.own_inserted = true;
                        self.facts()?.contribution = Some(receipt);
                        return Ok(Some(Progress::ContributionWritten));
                    }
                    consensus::Kind::Conclude => self.facts()?.conclude_written = true,
                    consensus::Kind::Join => {}
                }
            }
            consensus::Progress::Element(observation) => {
                if self.consensus_epoch.as_ref() != Some(observation.epoch()) {
                    return Err(Fault::StaleGeneration.into());
                }
                self.held = Some(observation);
            }
            consensus::Progress::Done { epoch, .. } => {
                if self.consensus_epoch.as_ref() != Some(&epoch)
                    || !self.own_inserted
                    || !self.report.as_ref().is_some_and(|r| r.conclude_written)
                {
                    return Err(Fault::Malformed.into());
                }
                self.consensus_closed = true;
                self.facts()?.consensus_done = true;
                return Ok(Some(Progress::ConsensusDone));
            }
            consensus::Progress::Lost(loss) => {
                self.consensus_closed = true;
                self.facts()?.consensus_loss = Some(loss);
                return Err(Fault::Unavailable.into());
            }
            consensus::Progress::Retry(error) => {
                self.facts()?.consensus_retry.get_or_insert(error);
            }
            consensus::Progress::Activity => {}
        }
        Ok(Some(Progress::Activity))
    }
    /// Poll one bounded native/math turn. Actual PILS is always observed first;
    /// each subsequent fallible-provider boundary rechecks the original native,
    /// identity/epoch and canonical gates before any further normal IO/result.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if let Err(error) = self.guard(cx) {
            return self.failed(error);
        }
        let pils_event = if self.local_threshold_one {
            let bounds = self.bounds;
            let clock = self.clock.clone();
            let identity_expires = self.identity.map(|identity| {
                self.pils
                    .identity()
                    .map_or(identity.expiration().as_micros(), |current| {
                        identity
                            .expiration()
                            .as_micros()
                            .min(current.expiration().as_micros())
                    })
            });
            let mut before_io = || {
                let now = target_time(bounds, clock.as_ref())?;
                if identity_expires.is_some_and(|expires| now >= expires) {
                    return Err(Fault::StaleGeneration.into());
                }
                Ok(())
            };
            self.pils
                .poll_guarded(cx, Some(bounds.hard.into()), &mut before_io)
        } else {
            let mut wait = std::pin::pin!(self.pils.drive(Some(self.bounds.hard.into())));
            wait.as_mut().poll(cx)
        };
        let mut activity = false;
        match pils_event {
            Poll::Ready(Ok(event)) => {
                activity = true;
                if let Err(error) = self.pils_event(event) {
                    return self.failed(error);
                }
            }
            Poll::Ready(Err(error)) => return self.failed(error.into()),
            Poll::Pending => {}
        }
        self.turn = !self.turn;
        for class in 0..2 {
            if let Err(error) = self.guard(cx) {
                return self.failed(error);
            }
            let result = if (class == 0) == self.turn {
                self.math_step(cx)
            } else {
                self.consensus_step(cx)
            };
            match result {
                Ok(Some(progress)) => return Poll::Ready(Ok(progress)),
                Ok(None) => {}
                Err(error) => {
                    if let Some(entropy) = self.random.error.take()
                        && let Some(r) = &mut self.report
                    {
                        r.entropy_error.get_or_insert(entropy);
                    }
                    return self.failed(error);
                }
            }
        }
        if activity {
            Poll::Ready(Ok(Progress::Activity))
        } else {
            Poll::Pending
        }
    }
    /// Cancel-safe observation future; dropping it does not drop native cursors,
    /// original proof jobs, retained source results or request hard bounds.
    pub async fn progress(&mut self) -> Result<Progress, Error> {
        tokio::task::yield_now().await;
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Decrypt<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}
