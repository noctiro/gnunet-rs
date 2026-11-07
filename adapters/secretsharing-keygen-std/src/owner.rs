mod work;
use work::{Material, Work};

use crate::{
    Bounds, CompletedRound1, Error, Limits, PeerCommitment, PilsLoss, Progress, Rejection, Report,
    Request, SigningSession, Sources, Transcript,
};
use gnunet_consensus_client_host as consensus;
use gnunet_paillier as paillier;
use gnunet_pils::client::{self as pc, Identity, KeyTarget};
use gnunet_pils_host::client as pils;
use gnunet_secretsharing::{self as math, CommitmentJob, PolynomialGenerator};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    Frame,
    consensus::Join,
    secretsharing::{self as ipc, SignedElement},
};
use std::{
    future::{Future, poll_fn},
    mem::size_of,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
#[derive(Default)]
pub(crate) struct Random {
    pub(crate) error: Option<getrandom::Error>,
}
impl math::Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Fault> {
        if self.error.is_some() {
            out.fill(0);
            return Err(Fault::EntropyUnavailable);
        }
        getrandom::fill(out).map_err(|error| {
            out.fill(0);
            self.error = Some(error);
            Fault::EntropyUnavailable
        })
    }
}
/// Actual original780 Round1 owner, not a complete DKG/782 service. Polling uses
/// the real original sources and existing bounded arithmetic jobs; no worker,
/// alternate protocol, fake acknowledgement or mutation replay is introduced.
pub struct Round1<'a> {
    pils: Option<pils::Client<'a, 1>>,
    consensus: Option<consensus::Client>,
    consensus_source: Option<gnunet_client_host::EndpointSource>,
    clock: Arc<dyn RuntimeClock>,
    bounds: Bounds,
    limits: Limits,
    identity: Option<Identity<'a>>,
    consensus_epoch: Option<consensus::Epoch>,
    request: Option<Request>,
    roster: Vec<[u8; 32]>,
    rows: Vec<Option<PeerCommitment>>,
    local: usize,
    group: math::Group,
    work: Work,
    // INSERT write observations can arrive after Work has advanced to Receive.
    insert: Option<consensus::InsertId>,
    random: Random,
    consensus_closed: bool,
    closed: bool,
    turn: bool,
    fixed_reservation: usize,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    report: Option<Report<'a>>,
}
enum CommitmentAdmission {
    Accepted,
    Rejected {
        peer: Option<[u8; 32]>,
        reason: Rejection,
    },
}
#[derive(Clone, Copy)]
enum CommitmentOrigin {
    Own,
    Consensus,
}
// This is the actual Round1 admission path, independent of native source polling.
// A row is owned only after its signature and modulus both pass. Official C
// overwrites an earlier commitment after another valid signature; keeping the
// first complete row avoids callback-order replacement without treating the
// SID-less signed region as an equivocation certificate or revoking that row.
fn admit_commitment(
    roster: &[[u8; 32]],
    rows: &mut [Option<PeerCommitment>],
    local: usize,
    origin: CommitmentOrigin,
    element_type: u16,
    bytes: &[u8],
) -> Result<CommitmentAdmission, Error> {
    if rows.len() != roster.len() || local >= roster.len() {
        return Err(Fault::Stale.into());
    }
    let rejected = |peer, reason| Ok(CommitmentAdmission::Rejected { peer, reason });
    if element_type != 0 {
        return rejected(None, Rejection::Shape(Fault::Unsupported));
    }
    let fields = match SignedElement::commitment(bytes) {
        Ok(fields) => fields,
        Err(error) => return rejected(None, Rejection::Shape(error)),
    };
    let peer = *fields.peer()?;
    let index = match roster.binary_search(&peer) {
        Ok(index) => index,
        Err(_) => return rejected(Some(peer), Rejection::Foreign),
    };
    match origin {
        // Public CONSENSUS does not echo locally inserted elements. An old
        // signed local statement has no SID and cannot choose the new local
        // ephemeral modulus before the actual signing/INSERT path does so.
        CommitmentOrigin::Consensus if index == local => {
            return rejected(Some(peer), Rejection::LocalStatement);
        }
        CommitmentOrigin::Own if index != local => return Err(Fault::Authentication.into()),
        _ => {}
    }
    let public = gnunet_crypto::EddsaPublicKey::from_bytes(peer);
    let signature = gnunet_crypto::EddsaSignature::from_bytes(*fields.signature()?);
    if let Err(error) = public.verify(ipc::DKG1_PURPOSE, fields.signed_bytes(), &signature) {
        return rejected(Some(peer), Rejection::Signature(error));
    }
    if rows[index].is_some() {
        return rejected(Some(peer), Rejection::Duplicate);
    }
    let key = match paillier::PublicKey::from_bytes(fields.paillier_key()?) {
        Ok(key) => key,
        Err(error) => return rejected(Some(peer), Rejection::Modulus(error)),
    };
    rows[index] = Some(PeerCommitment {
        bytes: bytes.try_into().map_err(|_| Fault::Malformed)?,
        key,
    });
    Ok(CommitmentAdmission::Accepted)
}
fn record_commitment<'a>(
    report: &mut Report<'a>,
    admission: CommitmentAdmission,
) -> Result<Option<Progress<'a>>, Error> {
    let (peer, reason) = match admission {
        CommitmentAdmission::Accepted => {
            report.verified = report.verified.checked_add(1).ok_or(Fault::Overflow)?;
            return Ok(None);
        }
        CommitmentAdmission::Rejected { peer, reason } => (peer, reason),
    };
    report.rejected = report.rejected.checked_add(1).ok_or(Fault::Overflow)?;
    Ok(Some(Progress::Rejected { peer, reason }))
}
impl<'a> Round1<'a> {
    /// Adopt the exact original intent and selected sources. Only public setup
    /// and source subscriptions are constructed; no entropy or source IO is polled.
    pub fn new(
        instance: &'a mut pc::Instance,
        sources: Sources,
        request: Request,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        Self::construct(sources, request, limits, original, None, |source| {
            Ok(pils::Client::new(
                instance,
                source,
                limits.profile,
                limits.pils,
                limits.hello,
            )?)
        })
    }
    /// Adopt the already-observed original idle PILS owner. The actual source,
    /// branded identity and shared clock remain unchanged; no new client,
    /// instance or connection is created for this phase.
    pub fn from_pils(
        client: pils::Client<'a, 1>,
        observed: Identity<'a>,
        sources: Sources,
        request: Request,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        let mut original_client = Some(client);
        let result = Self::construct(
            sources,
            request,
            limits,
            original,
            Some(observed),
            |_source| original_client.take().ok_or_else(|| Fault::Closed.into()),
        );
        if result.is_err()
            && let Some(mut client) = original_client.take()
        {
            let _retired = client.close();
        }
        result
    }
    fn construct(
        sources: Sources,
        request: Request,
        limits: Limits,
        original: Bounds,
        observed: Option<Identity<'a>>,
        make_pils: impl FnOnce(gnunet_client_host::EndpointSource) -> Result<pils::Client<'a, 1>, Error>,
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
        let consensus_bytes = sources
            .consensus
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::NotReady)?;
        let base_reservation = size_of::<Self>()
            .checked_add(consensus_bytes)
            .and_then(|n| n.checked_add(limits.consensus.retained_bytes))
            .and_then(|n| {
                limits
                    .consensus
                    .frame_bytes
                    .checked_mul(2)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Fault::Overflow)?;
        // Preclaim the requested fresh client's existing storage policy before
        // constructing it. An adopted client is charged below by its actual
        // retained storage and original limits, never a new smaller estimate.
        let requested_pils = sources
            .pils
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::NotReady)?
            .checked_add(
                limits
                    .pils
                    .frame_bytes
                    .checked_mul(4)
                    .ok_or(Fault::Overflow)?,
            )
            .and_then(|n| n.checked_add(limits.hello.maximum_address_bytes))
            .ok_or(Fault::Overflow)?;
        let admit = |pils_bytes: usize| -> Result<usize, Error> {
            let fixed = base_reservation
                .checked_add(pils_bytes)
                .ok_or(Fault::Overflow)?;
            if fixed
                .checked_add(request.bytes.capacity())
                .and_then(|n| n.checked_add(limits.math.retained_bytes))
                .ok_or(Fault::Overflow)?
                > limits.retained_bytes
            {
                return Err(Fault::Capacity.into());
            }
            Ok(fixed)
        };
        admit(requested_pils)?;
        let group = math::Group::new()?;
        let mut pils = make_pils(sources.pils)?;
        let adopted = (|| -> Result<_, Error> {
            if !Arc::ptr_eq(&clock, &pils.clock()) || !pils.is_idle() {
                return Err(Fault::InvalidInput.into());
            }
            if let Some(original) = observed {
                let current = pils.identity().ok_or(Fault::StaleGeneration)?;
                if pils.epoch() != Some(original.epoch())
                    || current.epoch() != original.epoch()
                    || current.peer() != original.peer()
                    || current.address_hash() != original.address_hash()
                    || current.coverage() != original.coverage()
                    || original.expiration().as_micros() <= now
                    || current.expiration().as_micros() <= now
                {
                    return Err(Fault::StaleGeneration.into());
                }
            }
            admit(pils.storage_reservation_bytes()?)?;
            if Instant::now() >= hard {
                return Err(Fault::Deadline.into());
            }
            Ok(())
        })();
        match adopted {
            Ok(()) => {}
            Err(error) => {
                let _retired = pils.close();
                return Err(error);
            }
        }
        Ok(Self {
            pils: Some(pils),
            consensus: None,
            consensus_source: Some(sources.consensus),
            clock,
            bounds: Bounds { expires, hard },
            limits,
            identity: observed,
            consensus_epoch: None,
            request: Some(request),
            roster: Vec::new(),
            rows: Vec::new(),
            local: 0,
            group,
            work: Work::Identity,
            insert: None,
            random: Random::default(),
            consensus_closed: false,
            closed: false,
            turn: false,
            fixed_reservation: base_reservation,
            timer: None,
            report: Some(Report {
                identity: observed,
                ..Report::default()
            }),
        })
    }
    fn facts(&mut self) -> Result<&mut Report<'a>, Error> {
        self.report.as_mut().ok_or_else(|| Fault::Closed.into())
    }
    fn pils(&self) -> Result<&pils::Client<'a, 1>, Error> {
        self.pils.as_ref().ok_or_else(|| Fault::Closed.into())
    }
    fn pils_mut(&mut self) -> Result<&mut pils::Client<'a, 1>, Error> {
        self.pils.as_mut().ok_or_else(|| Fault::Closed.into())
    }
    /// Actual original canonical/native bounds, never renewed by retries.
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }
    /// Borrow original source facts without cloning error/secret material.
    pub fn report(&self) -> Option<&Report<'a>> {
        self.report.as_ref()
    }
    /// Actual owner vector/job capacities plus finite native reservation.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let mut n = self
            .fixed_reservation
            .checked_add(
                self.pils
                    .as_ref()
                    .map_or(Ok(0), |pils| pils.storage_reservation_bytes())?,
            )
            .ok_or(Fault::Overflow)?
            .checked_add(self.request.as_ref().map_or(0, |r| r.bytes.capacity()))
            .and_then(|n| n.checked_add(self.roster.capacity().checked_mul(32)?))
            .and_then(|n| {
                n.checked_add(
                    self.rows
                        .capacity()
                        .checked_mul(size_of::<Option<PeerCommitment>>())?,
                )
            })
            .ok_or(Fault::Overflow)?;
        let work = self.work.retained_bytes()?;
        n = n.checked_add(work).ok_or(Fault::Overflow)?;
        Ok(n)
    }
    fn account(&self) -> Result<(), Error> {
        if self.retained_bytes()? > self.limits.retained_bytes {
            Err(Fault::Capacity.into())
        } else {
            Ok(())
        }
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
        let actual = self.pils()?.identity().ok_or(Fault::StaleGeneration)?;
        if self.pils()?.epoch() != Some(original.epoch())
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
        self.account()?;
        let now = self.clock.sample()?.now.as_micros();
        self.native(cx)?;
        if now >= self.bounds.expires {
            return Err(Fault::Deadline.into());
        }
        if let Some(original) = self.identity {
            let current = self.pils()?.identity().ok_or(Fault::StaleGeneration)?;
            if original.epoch() != current.epoch()
                || original.peer() != current.peer()
                || current.expiration().as_micros() <= now
            {
                return Err(Fault::StaleGeneration.into());
            }
        }
        Ok(now)
    }
    fn normalize(&mut self, identity: Identity<'a>) -> Result<(), Error> {
        let request = self.request.as_ref().ok_or(Fault::NotReady)?;
        let ipc::Request::Generate(original) =
            ipc::Request::decode(Frame::decode(&request.bytes)?)?
        else {
            return Err(Fault::Malformed.into());
        };
        let peers = original.peers.as_chunks::<32>().0;
        let reserve = crate::admission::normalized_count(peers, identity.peer().as_bytes())?;
        // Normalize runs before any mathematical job. Keep its whole existing
        // reservation while admitting metadata, then replace requested vector
        // extents by actual capacities before the next allocation.
        let base = self
            .fixed_reservation
            .checked_add(self.pils()?.storage_reservation_bytes()?)
            .ok_or(Fault::Overflow)?
            .checked_add(request.bytes.capacity())
            .and_then(|n| n.checked_add(self.limits.math.retained_bytes))
            .ok_or(Fault::Overflow)?;
        let admit = |roster: usize, rows: usize| {
            let bytes = roster
                .checked_mul(32)
                .and_then(|n| n.checked_add(rows.checked_mul(size_of::<Option<PeerCommitment>>())?))
                .and_then(|n| n.checked_add(base))
                .ok_or(Fault::Overflow)?;
            if bytes > self.limits.retained_bytes {
                return Err(Fault::Capacity.into());
            }
            Ok::<(), Error>(())
        };
        admit(reserve, reserve)?;
        self.roster
            .try_reserve_exact(reserve)
            .map_err(|_| Fault::Capacity)?;
        admit(self.roster.capacity(), reserve)?;
        // Check the full original reveal envelope before allocating row
        // metadata, opening CONSENSUS or starting any Paillier work. The
        // commitment-only Round1 frame policy does not cap a later reveal.
        self.local = crate::admission::normalize_reserved(
            &mut self.roster,
            peers,
            identity.peer().as_bytes(),
            request.threshold,
            self.limits.peers,
        )?;
        // The same retained PILS connection must sign the complete future
        // purpose22 region. Refuse its real native capacity now, before any
        // Paillier search, rather than constructing an unrepresentable reveal.
        let reveal = ipc::reveal_encoded_len(self.roster.len(), request.threshold)?;
        let region = reveal.checked_sub(64).ok_or(Fault::Overflow)?;
        let sign_frame = gnunet_wire::official::pils::sign_request_len(region)?;
        if sign_frame > self.limits.pils.frame_bytes
            || sign_frame > self.pils()?.limits().frame_bytes
        {
            return Err(Fault::TooLarge.into());
        }
        self.rows
            .try_reserve_exact(self.roster.len())
            .map_err(|_| Fault::Capacity)?;
        admit(self.roster.capacity(), self.rows.capacity())?;
        self.rows.resize_with(self.roster.len(), || None);
        self.account()?;
        let source = self.consensus_source.take().ok_or(Fault::StaleGeneration)?;
        self.consensus = Some(consensus::Client::new(
            source,
            Join {
                session: request.session,
                start: request.start,
                deadline: request.deadline,
                peers: &self.roster,
            },
            self.limits.consensus,
            self.bounds,
        )?);
        self.work = Work::Keygen(paillier::Keygen::new(self.limits.paillier)?);
        Ok(())
    }
    fn erase(&mut self) {
        self.work.cancel();
        self.request = None;
        self.roster = Vec::new();
        self.rows = Vec::new();
        self.consensus_source = None;
    }
    fn retire_consensus(&mut self) {
        if !self.consensus_closed {
            if let Some(client) = &mut self.consensus {
                let loss = client.close();
                if let Some(report) = &mut self.report {
                    report.consensus_loss.get_or_insert(loss);
                }
            }
            self.consensus_closed = true;
        }
    }
    fn retire(&mut self) {
        if self.closed {
            return;
        }
        self.retire_consensus();
        if let Some(mut pils) = self.pils.take() {
            let retired = pils.close();
            let idle = pils.is_idle();
            if let Some(report) = &mut self.report {
                report.signature_result_unknown = report.signature_result_missing();
                report.pils_retired = retired;
                report.pils_idle = idle;
            }
        }
        self.closed = true;
        self.timer = None;
        self.erase();
    }
    /// Physically retire original sources, retain their independent facts and
    /// erase owned secret work. No cancellation ACK or final share is invented.
    pub fn close(&mut self) -> Option<Report<'a>> {
        if !self.closed
            && let Some(report) = &mut self.report
        {
            report.cancelled = true;
        }
        self.retire();
        self.report.take()
    }
    /// Transfer facts only after the original sources really retired.
    pub fn take_report(&mut self) -> Option<Report<'a>> {
        if self.closed {
            self.report.take()
        } else {
            None
        }
    }
    fn failed(&mut self, error: Error) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(error) = self.random.error.take()
            && let Some(report) = &mut self.report
        {
            report.entropy_error.get_or_insert(error);
        }
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
                    self.identity = Some(identity);
                    self.facts()?.identity = Some(identity);
                }
            }
            pils::Progress::Inbound(pc::Inbound::Complete(completion)) => {
                let valid = (|| -> Result<[u8; 64], Error> {
                    if self.report.as_ref().and_then(|r| r.signature_operation)
                        != Some(completion.operation())
                    {
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
                    Ok(*signature.as_bytes())
                })();
                self.facts()?.signature_completion = Some(completion);
                let signature = valid?;
                let Work::Signing { bytes, .. } = &mut self.work else {
                    return Err(Fault::NotReady.into());
                };
                bytes[..64].copy_from_slice(&signature);
                let Work::Signing { material, bytes } =
                    std::mem::replace(&mut self.work, Work::Closed)
                else {
                    return Err(Fault::NotReady.into());
                };
                self.work = Work::Insert {
                    material,
                    bytes,
                    own_validated: false,
                };
            }
            pils::Progress::Written(receipt) => {
                if self.report.as_ref().and_then(|r| r.signature_operation)
                    == Some(receipt.operation)
                {
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
    fn accept(&mut self, element_type: u16, bytes: &[u8]) -> Result<Option<Progress<'a>>, Error> {
        let admission = admit_commitment(
            &self.roster,
            &mut self.rows,
            self.local,
            CommitmentOrigin::Consensus,
            element_type,
            bytes,
        )?;
        record_commitment(self.facts()?, admission)
    }
    fn finish(&mut self) -> Result<Progress<'a>, Error> {
        let report = self.report.as_ref().ok_or(Fault::NotReady)?;
        let request = self.request.as_ref().ok_or(Fault::NotReady)?;
        if !report.consensus_done || !report.conclude_written || report.contribution.is_none() {
            return Err(Fault::NotReady.into());
        }
        if report.verified < request.threshold
            || self.rows.get(self.local).is_none_or(Option::is_none)
        {
            return Err(math::Error::Roster.into());
        }
        if !self.pils()?.is_idle()
            || report.signature_completion.is_none()
            || !report.signature_written
            || self
                .consensus_epoch
                .as_ref()
                .is_none_or(consensus::Epoch::live)
        {
            return Err(Fault::NotReady.into());
        }
        let identity = self.identity.ok_or(Fault::StaleGeneration)?;
        let Material {
            polynomial,
            coefficients,
            keypair,
        } = self.work.take_material()?;
        let transcript = Transcript {
            bounds: self.bounds,
            clock: self.clock.clone(),
            session: request.session,
            start: request.start,
            deadline: request.deadline,
            threshold: request.threshold,
            local: self.local,
            roster: std::mem::take(&mut self.roster),
            commitments: std::mem::take(&mut self.rows),
            polynomial,
            coefficients,
            keypair,
        };
        // The original Round1 CONSENSUS is physically retired. Keep PILS live:
        // its exact original source/instance and identity are required by the
        // next signing operation, rather than a replacement connection.
        self.retire_consensus();
        let client = self.pils.take().ok_or(Fault::Closed)?;
        let mut report = self.report.take().ok_or(Fault::Closed)?;
        report.completed = true;
        self.closed = true;
        self.timer = None;
        self.erase();
        Ok(Progress::Complete(CompletedRound1 {
            transcript,
            session: SigningSession::new(client, identity, report),
        }))
    }
    fn insert_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'a>>, Error> {
        {
            let Work::Insert {
                bytes,
                own_validated,
                ..
            } = &mut self.work
            else {
                return Err(Fault::NotReady.into());
            };
            if !*own_validated {
                let admission = admit_commitment(
                    &self.roster,
                    &mut self.rows,
                    self.local,
                    CommitmentOrigin::Own,
                    0,
                    bytes,
                )?;
                let report = self.report.as_mut().ok_or(Fault::Closed)?;
                if let Some(Progress::Rejected { reason, .. }) =
                    record_commitment(report, admission)?
                {
                    return Err(Error::LocalCommitment(reason));
                }
                *own_validated = true;
            }
        }
        self.guard(cx)?;
        let Work::Insert { bytes, .. } = &self.work else {
            return Err(Fault::NotReady.into());
        };
        let client = self.consensus.as_mut().ok_or(Fault::NotReady)?;
        if self.insert.is_none() {
            match client.insert(0, bytes) {
                Ok(insert) => self.insert = Some(insert),
                Err(consensus::Error::Protocol(Fault::WouldBlock)) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        match client.conclude() {
            Ok(()) => {
                let Work::Insert { material, .. } = std::mem::replace(&mut self.work, Work::Closed)
                else {
                    return Err(Fault::NotReady.into());
                };
                self.work = Work::Receive(material);
            }
            Err(consensus::Error::Protocol(Fault::WouldBlock)) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        self.account()?;
        Ok(Some(Progress::Activity))
    }
    fn math_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'a>>, Error> {
        if self.identity.is_none() {
            return Ok(None);
        }
        // Advance each real cursor in place. Moving the large Work is restricted
        // to actual stage transitions, never one move per mathematical budget.
        match &mut self.work {
            Work::Identity => {
                self.normalize(self.identity.ok_or(Fault::NotReady)?)?;
            }
            Work::Keygen(job) => {
                if job.advance(&mut self.random, self.limits.paillier.units_per_turn)?
                    == paillier::Progress::Ready
                {
                    let keypair = job.take_result()?;
                    let threshold = self.request.as_ref().ok_or(Fault::NotReady)?.threshold;
                    let job = PolynomialGenerator::new(threshold, self.limits.math)?;
                    self.work = Work::Polynomial { keypair, job };
                }
            }
            Work::Polynomial { job, .. } => {
                if job.advance(&mut self.random, self.limits.math.units_per_turn)?
                    == math::Progress::Ready
                {
                    let polynomial = job.take_result()?;
                    let job = CommitmentJob::new_owned(polynomial, &self.group)?;
                    let Work::Polynomial { keypair, .. } =
                        std::mem::replace(&mut self.work, Work::Closed)
                    else {
                        return Err(Fault::NotReady.into());
                    };
                    self.work = Work::Commitments { keypair, job };
                }
            }
            Work::Commitments { job, .. } => {
                if job.advance(self.limits.math.units_per_turn)? == math::Progress::Ready {
                    let Work::Commitments { keypair, job } =
                        std::mem::replace(&mut self.work, Work::Closed)
                    else {
                        return Err(Fault::NotReady.into());
                    };
                    // This consuming API owns the sole original polynomial. On
                    // refusal its local owners drop; failed() retires the MQs.
                    let (polynomial, coefficients) = job.take_owned_result()?;
                    self.work = Work::Unsigned(Material {
                        keypair,
                        polynomial,
                        coefficients,
                    });
                }
            }
            Work::Unsigned(material) => {
                let peer = *self.identity.ok_or(Fault::NotReady)?.peer().as_bytes();
                let key = material.keypair.public_key().to_bytes();
                let hash = material.coefficients.presecret_hash()?;
                let mut bytes = [0; ipc::COMMIT_BYTES];
                ipc::CommitmentFields {
                    signature: &[0; 64],
                    peer: &peer,
                    paillier_key: &key,
                    commitment: &hash,
                }
                .encode(&mut bytes)?;
                let now = self.guard(cx)?;
                let target = self.signing_identity(now)?;
                let operation = self
                    .pils_mut()?
                    .sign(&bytes[64..], KeyTarget::Exact(target))?;
                // Preserve admission history independently of the active stage,
                // including a whole-write that arrives after Complete.
                self.facts()?.signature_operation = Some(operation);
                let Work::Unsigned(material) = std::mem::replace(&mut self.work, Work::Closed)
                else {
                    return Err(Fault::NotReady.into());
                };
                self.work = Work::Signing { material, bytes };
            }
            Work::Signing { .. } => return Ok(None),
            Work::Insert { .. } => return self.insert_step(cx),
            Work::Receive(_) => {
                if self.report.as_ref().is_some_and(|r| r.consensus_done) {
                    return self.finish().map(Some);
                }
                return Ok(None);
            }
            Work::Closed => return Ok(None),
        }
        self.account()?;
        Ok(Some(Progress::Activity))
    }
    fn consensus_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'a>>, Error> {
        if self.identity.is_none() || self.consensus_closed || self.consensus.is_none() {
            return Ok(None);
        }
        self.guard(cx)?;
        let client = self.consensus.as_mut().ok_or(Fault::NotReady)?;
        if let Some(loss) = client.poll_native_guard(cx) {
            self.consensus_closed = true;
            self.facts()?.consensus_loss = Some(loss);
            return Err(Fault::Deadline.into());
        }
        let event = match client.poll_progress(cx) {
            Poll::Pending => return Ok(None),
            Poll::Ready(event) => event?,
        };
        match event {
            consensus::Progress::Attached(epoch) => {
                if self
                    .consensus_epoch
                    .as_ref()
                    .is_some_and(|old| old != &epoch)
                {
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
                        if self.insert.as_ref() != Some(id) {
                            return Err(Fault::StaleGeneration.into());
                        }
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
                let consensus::ClientResponse::Element { element_type, data } =
                    observation.response()?
                else {
                    return Err(Fault::Malformed.into());
                };
                if let Some(progress) = self.accept(element_type, data)? {
                    return Ok(Some(progress));
                }
            }
            consensus::Progress::Done { epoch, .. } => {
                if self.consensus_epoch.as_ref() != Some(&epoch)
                    || !self
                        .report
                        .as_ref()
                        .is_some_and(|r| r.contribution.is_some() && r.conclude_written)
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
    /// One bounded original source/math turn. PILS is observed first; every later
    /// normal provider/IO boundary rechecks the same native hard and actual identity.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        if let Err(error) = self.guard(cx) {
            return self.failed(error);
        }
        let event = {
            let Some(pils) = self.pils.as_mut() else {
                return self.failed(Fault::Closed.into());
            };
            let mut wait = std::pin::pin!(pils.drive(Some(self.bounds.hard.into())));
            wait.as_mut().poll(cx)
        };
        let mut activity = false;
        match event {
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
            let outcome = if (class == 0) == self.turn {
                self.math_step(cx)
            } else {
                self.consensus_step(cx)
            };
            match outcome {
                Ok(Some(progress)) => return Poll::Ready(Ok(progress)),
                Ok(None) => {}
                Err(error) => return self.failed(error),
            }
        }
        if activity {
            Poll::Ready(Ok(Progress::Activity))
        } else {
            Poll::Pending
        }
    }
    /// Cancel-safe observation future; dropping it preserves every original
    /// mathematical/source cursor. Explicit close actually retires both MQs.
    pub async fn progress(&mut self) -> Result<Progress<'a>, Error> {
        tokio::task::yield_now().await;
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Round1<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}

#[cfg(test)]
mod commitment_tests {
    use super::*;
    fn signed(
        key: &gnunet_crypto::EddsaPrivateKey,
        modulus: [u8; 256],
        marker: u8,
    ) -> Result<[u8; ipc::COMMIT_BYTES], Error> {
        let mut out = [0; ipc::COMMIT_BYTES];
        ipc::CommitmentFields {
            signature: &[0; 64],
            peer: key.public_key().as_bytes(),
            paillier_key: &modulus,
            commitment: &[marker; 64],
        }
        .encode(&mut out)?;
        let signature = key.sign(ipc::DKG1_PURPOSE, &out[64..])?;
        out[..64].copy_from_slice(signature.as_bytes());
        Ok(out)
    }
    fn modulus() -> [u8; 256] {
        let mut modulus = [0; 256];
        modulus[0] = 0x80;
        modulus[255] = 3;
        modulus
    }
    fn check(value: bool) -> Result<(), Error> {
        if value {
            Ok(())
        } else {
            Err(Fault::Conflict.into())
        }
    }
    struct Context {
        roster: [[u8; 32]; 2],
        local: usize,
        dealer: usize,
    }
    impl Context {
        fn new(remote: &gnunet_crypto::EddsaPrivateKey) -> Result<Self, Error> {
            let local = *gnunet_crypto::EddsaPrivateKey::from_seed([0; 32])
                .public_key()
                .as_bytes();
            let dealer = *remote.public_key().as_bytes();
            let mut roster = [local, dealer];
            roster.sort_unstable();
            Ok(Self {
                local: roster.binary_search(&local).map_err(|_| Fault::Stale)?,
                dealer: roster.binary_search(&dealer).map_err(|_| Fault::Stale)?,
                roster,
            })
        }
        fn admit(
            &self,
            rows: &mut [Option<PeerCommitment>],
            bytes: &[u8],
        ) -> Result<CommitmentAdmission, Error> {
            admit_commitment(
                &self.roster,
                rows,
                self.local,
                CommitmentOrigin::Consensus,
                0,
                bytes,
            )
        }
    }
    #[test]
    fn signed_invalid_modulus_does_not_reserve_the_peer_before_a_valid_commitment()
    -> Result<(), Error> {
        let key = gnunet_crypto::EddsaPrivateKey::from_seed([7; 32]);
        let context = Context::new(&key)?;
        let invalid = signed(&key, [0; 256], 2)?;
        let valid = signed(&key, modulus(), 1)?;
        let mut rows = [None, None];
        let mut report = Report::default();
        let rejected = record_commitment(&mut report, context.admit(&mut rows, &invalid)?)?;
        check(matches!(
            rejected,
            Some(Progress::Rejected {
                reason: Rejection::Modulus(_),
                ..
            })
        ))?;
        check(rows[context.dealer].is_none() && report.verified == 0 && report.rejected == 1)?;
        check(record_commitment(&mut report, context.admit(&mut rows, &valid)?)?.is_none())?;
        check(
            rows[context.dealer]
                .as_ref()
                .is_some_and(|row| row.bytes == valid),
        )?;
        check(report.verified == 1 && report.rejected == 1)
    }
    #[test]
    fn first_valid_commitment_survives_later_different_signed_inputs() -> Result<(), Error> {
        let key = gnunet_crypto::EddsaPrivateKey::from_seed([8; 32]);
        let context = Context::new(&key)?;
        let first = signed(&key, modulus(), 1)?;
        let later_valid = signed(&key, modulus(), 2)?;
        let later_invalid = signed(&key, [0; 256], 3)?;
        let mut rows = [None, None];
        let mut report = Report::default();
        check(record_commitment(&mut report, context.admit(&mut rows, &first)?)?.is_none())?;
        for bytes in [&later_valid, &later_invalid, &first] {
            let rejected = record_commitment(&mut report, context.admit(&mut rows, bytes)?)?;
            check(matches!(
                rejected,
                Some(Progress::Rejected {
                    reason: Rejection::Duplicate,
                    ..
                })
            ))?;
            check(
                rows[context.dealer]
                    .as_ref()
                    .is_some_and(|row| row.bytes == first),
            )?;
            check(report.verified == 1)?;
        }
        check(report.rejected == 3)
    }
    #[test]
    fn unauthenticated_input_does_not_poison_or_replace_the_original_row() -> Result<(), Error> {
        let key = gnunet_crypto::EddsaPrivateKey::from_seed([9; 32]);
        let context = Context::new(&key)?;
        let valid = signed(&key, modulus(), 1)?;
        let mut forged = signed(&key, modulus(), 2)?;
        forged[0] ^= 1;
        let mut rows = [None, None];
        for populated in [false, true] {
            if populated {
                check(matches!(
                    context.admit(&mut rows, &valid)?,
                    CommitmentAdmission::Accepted
                ))?;
            }
            check(matches!(
                context.admit(&mut rows, &forged)?,
                CommitmentAdmission::Rejected {
                    reason: Rejection::Signature(_),
                    ..
                }
            ))?;
            check(if populated {
                rows[context.dealer]
                    .as_ref()
                    .is_some_and(|row| row.bytes == valid)
            } else {
                rows[context.dealer].is_none()
            })?;
        }
        Ok(())
    }
    #[test]
    fn remote_local_statements_cannot_preempt_or_replace_the_real_own_path() -> Result<(), Error> {
        let remote = gnunet_crypto::EddsaPrivateKey::from_seed([10; 32]);
        let context = Context::new(&remote)?;
        let key = gnunet_crypto::EddsaPrivateKey::from_seed([0; 32]);
        let old = signed(&key, modulus(), 1)?;
        let own = signed(&key, modulus(), 2)?;
        let mut rows = [None, None];
        let mut report = Report::default();
        let rejected = record_commitment(&mut report, context.admit(&mut rows, &old)?)?;
        check(matches!(
            rejected,
            Some(Progress::Rejected {
                reason: Rejection::LocalStatement,
                ..
            })
        ))?;
        check(rows[context.local].is_none() && report.verified == 0)?;
        let accepted = admit_commitment(
            &context.roster,
            &mut rows,
            context.local,
            CommitmentOrigin::Own,
            0,
            &own,
        )?;
        check(record_commitment(&mut report, accepted)?.is_none())?;
        for bytes in [&old, &own] {
            let rejected = record_commitment(&mut report, context.admit(&mut rows, bytes)?)?;
            check(matches!(
                rejected,
                Some(Progress::Rejected {
                    reason: Rejection::LocalStatement,
                    ..
                })
            ))?;
            check(
                rows[context.local]
                    .as_ref()
                    .is_some_and(|row| row.bytes == own),
            )?;
            check(report.verified == 1)?;
        }
        check(report.rejected == 3)
    }
}
