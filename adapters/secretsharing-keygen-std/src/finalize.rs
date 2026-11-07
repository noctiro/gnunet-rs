//! Closing a real Round2 receiver and aggregating its accepted contributions.
//!
//! This implements the end-of-round result contract, including an insufficient
//! ready count and a local nonmember. It does not supply an own FAIR producer.
use crate::{
    Bounds, Error,
    round2::{ClosedSource, ContributionEvidence, LocalContribution, LocalTranscript},
};
use gnunet_secretsharing::{self as math, AggregateContribution, AggregateJob, AggregateMaterial};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::secretsharing as ipc;
use std::{
    mem::{replace, size_of},
    sync::Arc,
    time::Instant,
};

/// Exact original dealer disposition after the real Round2 source closed.
/// Rejected packets are not contributions and cannot mutate an accepted owner.
pub enum Disposition<'id> {
    /// No locally validated contribution was received for this original index.
    Missing,
    /// The local value checked, but some original recipients lacked Round1 keys.
    /// This contribution is excluded without shrinking the original roster.
    Incomplete {
        /// Actual original remote observation or local signing/insertion evidence.
        evidence: ContributionEvidence<'id>,
        /// Actual completed original-recipient equation checks.
        equation_checks: usize,
        /// Exact original recipient indices without checked keys.
        missing: Vec<u16>,
    },
    /// All original recipients checked under their original Round1 keys.
    Accepted(ContributionEvidence<'id>),
}

#[expect(
    clippy::large_enum_variant,
    reason = "Move each unique arithmetic owner between inline stages without a new heap allocation"
)]
enum State<'id> {
    Selecting {
        candidates: Vec<Option<LocalContribution<'id>>>,
        contributions: Vec<AggregateContribution>,
        at: usize,
        coefficient_bytes: usize,
    },
    Aggregating(AggregateJob),
    Ready(AggregateMaterial),
    Closed,
}

/// Caller-polled generation finalization. Its only constructor consumes the
/// closed-source Round2 type; a boolean or a caller-selected list cannot stand
/// in for real525. Original scalar owners are moved, never cloned.
pub struct Finalization<'id> {
    source: Option<ClosedSource>,
    session: [u8; 64],
    roster: Vec<[u8; 32]>,
    local: usize,
    threshold: usize,
    dispositions: Vec<Disposition<'id>>,
    clock: Arc<dyn RuntimeClock>,
    bounds: Bounds,
    deadline: u64,
    math: math::Limits,
    maximum_bytes: usize,
    state: State<'id>,
}
impl<'id> Finalization<'id> {
    /// Release unused Round1 polynomial/Paillier private material before making
    /// any new selection allocations. The requested and actual Vec capacities
    /// are preflighted against one enclosing reservation.
    pub fn new(
        transcript: LocalTranscript<'id>,
        math: math::Limits,
        maximum_bytes: usize,
    ) -> Result<Self, Error> {
        math.validate()?;
        let (round1, candidates, source) = transcript.into_parts();
        let crate::TranscriptParts {
            bounds,
            clock,
            session,
            deadline,
            threshold,
            local,
            roster,
            commitments,
            polynomial,
            coefficients,
            keypair,
            start: _,
        } = round1.into_parts();
        // Make private-owner retirement explicit before any new reservation.
        drop((commitments, polynomial, coefficients, keypair));
        check_target(bounds, deadline, clock.as_ref())?;
        let count = roster.len();
        if count == 0
            || count > math.participants
            || threshold == 0
            || threshold > count
            || local >= count
            || candidates.len() != count
            || roster.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(Fault::InvalidInput.into());
        }
        let input = selection_bytes(&candidates, candidates.capacity())?;
        let baseline = size_of::<Self>()
            .checked_add(vector_bytes::<[u8; 32]>(roster.capacity())?)
            .and_then(|n| n.checked_add(input))
            .ok_or(Fault::Overflow)?;
        let requested = vector_bytes::<Disposition<'id>>(count)?
            .checked_add(vector_bytes::<AggregateContribution>(count)?)
            .ok_or(Fault::Overflow)?;
        bounded(baseline, requested, maximum_bytes)?;
        let mut dispositions = Vec::new();
        dispositions
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        bounded(
            baseline,
            vector_bytes::<Disposition<'id>>(dispositions.capacity())?
                .checked_add(vector_bytes::<AggregateContribution>(count)?)
                .ok_or(Fault::Overflow)?,
            maximum_bytes,
        )?;
        let mut contributions = Vec::new();
        contributions
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        bounded(
            baseline,
            vector_bytes::<Disposition<'id>>(dispositions.capacity())?
                .checked_add(vector_bytes::<AggregateContribution>(
                    contributions.capacity(),
                )?)
                .ok_or(Fault::Overflow)?,
            maximum_bytes,
        )?;
        let owner = Self {
            source: Some(source),
            session,
            roster,
            local,
            threshold,
            dispositions,
            clock,
            bounds,
            deadline,
            math,
            maximum_bytes,
            state: State::Selecting {
                candidates,
                contributions,
                at: 0,
                coefficient_bytes: 0,
            },
        };
        owner.guard()?;
        Ok(owner)
    }

    fn guard(&self) -> Result<(), Error> {
        check_target(self.bounds, self.deadline, self.clock.as_ref())
    }

    fn step(&mut self) -> Result<math::Progress, Error> {
        match &mut self.state {
            State::Selecting {
                candidates,
                contributions,
                at,
                coefficient_bytes,
            } if *at < candidates.len() => {
                let index = *at;
                let disposition = if let Some(candidate) = candidates[index].take() {
                    let parts = candidate.into_parts();
                    if parts.dealer != index
                        || parts.recipient != self.local
                        || parts.coefficients.threshold() != self.threshold
                        || parts.evidence.epoch()
                            != self.source.as_ref().ok_or(Fault::Closed)?.epoch()
                    {
                        return Err(Fault::Conflict.into());
                    }
                    if parts.missing.is_empty() {
                        if parts.equation_checks != self.roster.len() {
                            return Err(Fault::Conflict.into());
                        }
                        *coefficient_bytes = coefficient_bytes
                            .checked_add(parts.coefficients.retained_bytes()?)
                            .ok_or(Fault::Overflow)?;
                        contributions.push(AggregateContribution::new(
                            self.roster[index],
                            u16::try_from(index).map_err(|_| Fault::TooLarge)?,
                            parts.coefficients,
                            parts.scalar,
                        ));
                        Disposition::Accepted(parts.evidence)
                    } else {
                        // The local decrypted scalar cannot qualify a dealer
                        // whose original recipient checks were incomplete.
                        Disposition::Incomplete {
                            evidence: parts.evidence,
                            equation_checks: parts.equation_checks,
                            missing: parts.missing,
                        }
                    }
                } else {
                    Disposition::Missing
                };
                self.dispositions.push(disposition);
                *at += 1;
                Ok(math::Progress::Advanced)
            }
            State::Selecting { .. } => {
                let State::Selecting {
                    candidates,
                    contributions,
                    ..
                } = replace(&mut self.state, State::Closed)
                else {
                    return Err(Fault::Closed.into());
                };
                drop(candidates);
                let outside = self.outside_bytes()?;
                let mut limits = self.math;
                limits.retained_bytes = limits.retained_bytes.min(
                    self.maximum_bytes
                        .checked_sub(outside)
                        .ok_or(Fault::Capacity)?,
                );
                self.state = State::Aggregating(AggregateJob::new(
                    contributions,
                    self.roster[self.local],
                    u16::try_from(self.local).map_err(|_| Fault::TooLarge)?,
                    self.threshold,
                    &math::Group::new()?,
                    limits,
                )?);
                Ok(math::Progress::Advanced)
            }
            State::Aggregating(job) => {
                if job.advance(1)? == math::Progress::Ready {
                    self.state = State::Ready(job.take_result()?);
                    Ok(math::Progress::Ready)
                } else {
                    Ok(math::Progress::Advanced)
                }
            }
            State::Ready(_) => Ok(math::Progress::Ready),
            State::Closed => Err(Fault::Closed.into()),
        }
    }

    /// At most `units` original-index decisions or existing arithmetic steps.
    /// Source failures retain their actual first error; every failure/cancel
    /// releases the partial secret owners and cannot later produce a result.
    pub fn advance(&mut self, units: u16) -> Result<math::Progress, Error> {
        let run = (|| {
            if matches!(self.state, State::Closed) {
                return Err(Fault::Closed.into());
            }
            if units == 0 || units > self.math.units_per_turn {
                return Err(Fault::Capacity.into());
            }
            self.guard()?;
            for _ in 0..units {
                let progress = self.step()?;
                self.guard()?;
                if progress == math::Progress::Ready {
                    return Ok(progress);
                }
            }
            Ok(math::Progress::Advanced)
        })();
        if run.is_err() {
            self.cancel();
        }
        run
    }

    /// Transfer the actual closed round result exactly once. This can be a
    /// standard insufficient/nonmember result; no usable decrypt roster or own
    /// signed reveal is inferred from it.
    pub fn take_result(&mut self) -> Result<Finalized<'id>, Error> {
        if !matches!(self.state, State::Ready(_)) {
            return Err(Fault::NotReady.into());
        }
        if let Err(error) = self.guard() {
            self.cancel();
            return Err(error);
        }
        let State::Ready(material) = replace(&mut self.state, State::Closed) else {
            return Err(Fault::Closed.into());
        };
        Ok(Finalized {
            source: self.source.take().ok_or(Fault::Closed)?,
            session: self.session,
            roster: std::mem::take(&mut self.roster),
            local: self.local,
            dispositions: std::mem::take(&mut self.dispositions),
            material,
        })
    }

    fn outside_bytes(&self) -> Result<usize, Error> {
        let metadata = vector_bytes::<[u8; 32]>(self.roster.capacity())?
            .checked_add(vector_bytes::<Disposition<'id>>(
                self.dispositions.capacity(),
            )?)
            .ok_or(Fault::Overflow)?;
        let mut bytes = size_of::<Self>()
            .checked_add(metadata)
            .ok_or(Fault::Overflow)?;
        bytes = bytes
            .checked_add(evidence_bytes(&self.dispositions)?)
            .ok_or(Fault::Overflow)?;
        Ok(bytes)
    }

    /// Actual owned Vec capacities, including source evidence and all existing
    /// simultaneous arithmetic owners. This is a reservation, not measured RSS.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let extra = match &self.state {
            State::Selecting {
                candidates,
                contributions,
                coefficient_bytes,
                ..
            } => selection_bytes(candidates, candidates.capacity())?
                .checked_add(*coefficient_bytes)
                .ok_or(Fault::Overflow)?
                .checked_add(vector_bytes::<AggregateContribution>(
                    contributions.capacity(),
                )?)
                .ok_or(Fault::Overflow)?,
            State::Aggregating(job) => job.retained_bytes()?,
            State::Ready(material) => material.retained_bytes()?,
            State::Closed => 0,
        };
        self.outside_bytes()?
            .checked_add(extra)
            .ok_or_else(|| Fault::Overflow.into())
    }

    /// Erase all pending scalars, release evidence and close this local owner.
    pub fn cancel(&mut self) {
        if let State::Aggregating(job) = &mut self.state {
            job.cancel();
        }
        self.state = State::Closed;
        self.roster = Vec::new();
        self.dispositions = Vec::new();
        self.source = None;
    }
}

/// Actual round result. Its material is not automatically a usable Roster;
/// callers must explicitly apply `Roster::check` before threshold decryption.
pub struct Finalized<'id> {
    source: ClosedSource,
    session: [u8; 64],
    roster: Vec<[u8; 32]>,
    local: usize,
    dispositions: Vec<Disposition<'id>>,
    material: AggregateMaterial,
}
impl<'id> Finalized<'id> {
    /// Original whole-write/525/physical-close source facts.
    pub const fn source(&self) -> &ClosedSource {
        &self.source
    }
    /// Unchanged original session identifier.
    pub const fn session(&self) -> &[u8; 64] {
        &self.session
    }
    /// Original roster, including every absent or incomplete participant.
    pub fn original_roster(&self) -> &[[u8; 32]] {
        &self.roster
    }
    /// Original local polynomial index, never a reduced ready-list position.
    pub const fn local_index(&self) -> usize {
        self.local
    }
    /// Actual decision at an original dealer index.
    pub fn disposition(&self, index: usize) -> Option<&Disposition<'id>> {
        self.dispositions.get(index)
    }
    /// Actual aggregate, which can have fewer ready rows than its threshold.
    pub const fn material(&self) -> &AggregateMaterial {
        &self.material
    }
    /// Actual retained result capacities and evidence frames after handoff.
    /// Fixed object storage is included; allocator overhead and RSS are not.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let capacities = vector_bytes::<[u8; 32]>(self.roster.capacity())?
            .checked_add(self.material.retained_bytes()?)
            .ok_or(Fault::Overflow)?;
        let bytes = size_of::<Self>()
            .checked_add(capacities)
            .ok_or(Fault::Overflow)?;
        let metadata = vector_bytes::<Disposition<'id>>(self.dispositions.capacity())?
            .checked_add(evidence_bytes(&self.dispositions)?)
            .ok_or(Fault::Overflow)?;
        bytes
            .checked_add(metadata)
            .ok_or_else(|| Fault::Overflow.into())
    }
    /// Write the standard783 result without cloning a scalar or allocating
    /// column buffers. The original threshold remains unchanged; a local
    /// nonmember uses the ready-count sentinel. The caller erases output.
    pub fn encode_secret_ready(
        &self,
        out: &mut [u8],
        order: ipc::IndexOrder,
    ) -> Result<usize, Error> {
        let rows = self.material.participants();
        let secret = self.material.secret().to_bytes();
        ipc::ShareEncoder {
            threshold: u16::try_from(self.material.threshold()).map_err(|_| Fault::TooLarge)?,
            my_peer: u16::try_from(self.material.local_position().unwrap_or(rows.len()))
                .map_err(|_| Fault::TooLarge)?,
            public_key: &self.material.public_key().to_bytes(),
            secret: &secret,
            peers: rows.len(),
            order,
        }
        .encode_secret_ready(out, |i| ipc::ShareRow {
            peer: rows[i].peer,
            sigma: rows[i].sigma.to_bytes(),
            original_index: rows[i].original_index,
        })
        .map_err(Error::from)
    }
    /// Move the unique aggregate and all original source evidence once.
    pub fn into_parts(self) -> FinalizedParts<'id> {
        FinalizedParts {
            material: self.material,
            session: self.session,
            local: self.local,
            roster: self.roster,
            dispositions: self.dispositions,
            source: self.source,
        }
    }
}
/// Exclusive result owners and original metadata, including a nonmember's
/// original local point which cannot be recovered from selected rows alone.
pub struct FinalizedParts<'id> {
    /// Actual aggregate mathematics, not implicit usable-roster admission.
    pub material: AggregateMaterial,
    /// Original session identifier.
    pub session: [u8; 64],
    /// Original local polynomial index.
    pub local: usize,
    /// Complete original roster.
    pub roster: Vec<[u8; 32]>,
    /// Original-index dispositions and retained source frames.
    pub dispositions: Vec<Disposition<'id>>,
    /// Actual closed-source facts.
    pub source: ClosedSource,
}

fn check_target(bounds: Bounds, deadline: u64, clock: &dyn RuntimeClock) -> Result<(), Error> {
    if Instant::now() >= bounds.hard {
        return Err(Fault::Deadline.into());
    }
    let now = clock.sample()?.now.as_micros();
    if Instant::now() >= bounds.hard || now >= bounds.expires || now >= deadline {
        return Err(Fault::Deadline.into());
    }
    Ok(())
}

fn evidence_bytes(dispositions: &[Disposition<'_>]) -> Result<usize, Error> {
    let mut bytes = 0usize;
    for disposition in dispositions {
        let extra = match disposition {
            Disposition::Missing => 0,
            Disposition::Accepted(evidence) => evidence.retained_bytes(),
            Disposition::Incomplete {
                evidence, missing, ..
            } => evidence
                .retained_bytes()
                .checked_add(vector_bytes::<u16>(missing.capacity())?)
                .ok_or(Fault::Overflow)?,
        };
        bytes = bytes.checked_add(extra).ok_or(Fault::Overflow)?;
    }
    Ok(bytes)
}

fn vector_bytes<T>(capacity: usize) -> Result<usize, Error> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or_else(|| Fault::Overflow.into())
}
fn bounded(base: usize, extra: usize, maximum: usize) -> Result<(), Error> {
    if base.checked_add(extra).ok_or(Fault::Overflow)? > maximum {
        Err(Fault::Capacity.into())
    } else {
        Ok(())
    }
}
fn selection_bytes(
    candidates: &[Option<LocalContribution<'_>>],
    capacity: usize,
) -> Result<usize, Error> {
    let mut bytes = vector_bytes::<Option<LocalContribution<'_>>>(capacity)?;
    for candidate in candidates.iter().flatten() {
        bytes = bytes
            .checked_add(candidate.coefficients().retained_bytes()?)
            .and_then(|n| n.checked_add(candidate.evidence().retained_bytes()))
            .ok_or(Fault::Overflow)?;
        // Access the owned vector's capacity through the local crate owner.
        bytes = bytes
            .checked_add(vector_bytes::<u16>(candidate.missing.capacity())?)
            .ok_or(Fault::Overflow)?;
    }
    Ok(bytes)
}
