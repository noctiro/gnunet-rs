//! The singleton's unique mathematical owner at each actual bounded stage.
use super::{Error, Fault, Limits, math};
use math::{
    AggregateContribution, AggregateJob, AggregateMaterial, CommitmentJob, Commitments, Polynomial,
    PolynomialGenerator,
};
use std::mem::{replace, size_of};

#[expect(
    clippy::large_enum_variant,
    reason = "One bounded inline job replaces the larger sum of exclusive job fields without a new heap owner"
)]
pub(super) enum State {
    // Also the empty handoff slot if consuming a completed job refuses its
    // successor. It deliberately is not Closed: Owner must still retire PILS.
    Waiting,
    Generating(PolynomialGenerator),
    Committing(CommitmentJob<'static>),
    Coefficients {
        polynomial: Polynomial,
        commitments: Commitments,
    },
    Aggregating(AggregateJob),
    Ready(AggregateMaterial),
    Closed,
}
impl State {
    pub(super) fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }

    pub(super) fn doing_math(&self) -> bool {
        matches!(
            self,
            Self::Generating(_)
                | Self::Committing(_)
                | Self::Coefficients { .. }
                | Self::Aggregating(_)
        )
    }

    /// Each owned allocation is charged by exactly one current stage. Inline
    /// jobs and scalars are already covered by Owner's fixed reservation.
    pub(super) fn retained_bytes(&self) -> Result<usize, Error> {
        Ok(match self {
            Self::Waiting | Self::Closed => 0,
            Self::Generating(job) => job.retained_bytes()?,
            Self::Committing(job) => job.retained_bytes()?,
            Self::Coefficients {
                polynomial,
                commitments,
            } => polynomial
                .retained_bytes()?
                .checked_add(commitments.retained_bytes()?)
                .ok_or(Fault::Overflow)?,
            Self::Aggregating(job) => job.retained_bytes()?,
            Self::Ready(material) => material.retained_bytes()?,
        })
    }

    /// Advance one original arithmetic turn in place. A completed job alone
    /// transfers its unique input/output owners into the following stage; no
    /// following job consumes an additional turn in the same call.
    pub(super) fn advance(
        &mut self,
        entropy: &mut impl math::Entropy,
        peer: [u8; 32],
        group: &math::Group,
        limits: Limits,
        fixed_bytes: usize,
    ) -> Result<bool, Error> {
        let units = limits.decrypt.math.units_per_turn;
        match self {
            Self::Waiting => Err(Fault::NotReady.into()),
            Self::Ready(_) => Ok(false),
            Self::Closed => Err(Fault::Closed.into()),
            Self::Generating(job) => {
                if job.advance(entropy, units)? == math::Progress::Ready {
                    let polynomial = job.take_result()?;
                    *self = Self::Committing(CommitmentJob::new_owned(polynomial, group)?);
                }
                Ok(true)
            }
            Self::Committing(job) => {
                if job.advance(units)? == math::Progress::Ready {
                    // Consuming the real completed owned job is the only move
                    // out of this stage; Advanced keeps its large cursor put.
                    let Self::Committing(job) = replace(self, Self::Waiting) else {
                        return Err(Fault::NotReady.into());
                    };
                    let (polynomial, commitments) = job.take_owned_result()?;
                    if polynomial.threshold() != 1 || commitments.threshold() != 1 {
                        return Err(Fault::Conflict.into());
                    }
                    *self = Self::Coefficients {
                        polynomial,
                        commitments,
                    };
                }
                Ok(true)
            }
            Self::Coefficients { polynomial, .. } => {
                // Evaluate the original one-coefficient polynomial at the
                // actual local point before releasing its sole secret owner.
                let mut evaluation = polynomial.evaluate(0, group);
                if evaluation.advance(1)? != math::Progress::Ready {
                    return Err(Fault::NotReady.into());
                }
                let scalar = evaluation.take_result()?;
                drop(evaluation);
                let Self::Coefficients {
                    polynomial,
                    commitments,
                } = replace(self, Self::Waiting)
                else {
                    return Err(Fault::NotReady.into());
                };
                drop(polynomial);
                *self = Self::Aggregating(aggregate(
                    commitments,
                    scalar,
                    peer,
                    group,
                    limits,
                    fixed_bytes,
                )?);
                Ok(true)
            }
            Self::Aggregating(job) => {
                if job.advance(units)? == math::Progress::Ready {
                    *self = Self::Ready(job.take_result()?);
                }
                Ok(true)
            }
        }
    }

    pub(super) fn material(&self) -> Result<&AggregateMaterial, Error> {
        match self {
            Self::Ready(material) => Ok(material),
            _ => Err(Fault::NotReady.into()),
        }
    }

    /// Called only after the physical PILS source is retired. Dropping the one
    /// active variant erases its owned scalars and releases every allocation.
    pub(super) fn close(&mut self) {
        match self {
            Self::Generating(job) => job.cancel(),
            Self::Committing(job) => job.cancel(),
            Self::Aggregating(job) => job.cancel(),
            _ => {}
        }
        *self = Self::Closed;
    }
}

fn aggregate(
    commitments: Commitments,
    scalar: math::Scalar,
    peer: [u8; 32],
    group: &math::Group,
    limits: Limits,
    fixed_bytes: usize,
) -> Result<AggregateJob, Error> {
    let mut math_limits = limits.decrypt.math;
    math_limits.retained_bytes = math_limits.retained_bytes.min(
        limits
            .operation_bytes
            .checked_sub(fixed_bytes)
            .ok_or(Fault::Capacity)?,
    );
    let coefficient_bytes = commitments.retained_bytes()?;
    if coefficient_bytes
        .checked_add(size_of::<AggregateContribution>())
        .ok_or(Fault::Overflow)?
        > math_limits.retained_bytes
    {
        return Err(Fault::Capacity.into());
    }
    let mut contributions = Vec::new();
    contributions
        .try_reserve_exact(1)
        .map_err(|_| Fault::Capacity)?;
    let capacity = contributions
        .capacity()
        .checked_mul(size_of::<AggregateContribution>())
        .and_then(|bytes| bytes.checked_add(coefficient_bytes))
        .ok_or(Fault::Overflow)?;
    if capacity > math_limits.retained_bytes {
        return Err(Fault::Capacity.into());
    }
    contributions.push(AggregateContribution::new(peer, 0, commitments, scalar));
    // This is the same aggregate mathematics as caller-selected multi-dealer
    // inputs. It grants no remote qualification or FAIR/DKG authority.
    Ok(AggregateJob::new(
        contributions,
        peer,
        0,
        1,
        group,
        math_limits,
    )?)
}
