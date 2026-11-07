use crate::{
    Commitments, Error, Group, Limits, Participant, PolynomialCheck, Progress, Scalar, ShareCheck,
    Subgroup,
};
use alloc::vec::Vec;

/// One caller-selected dealer's checked subgroup coefficients and its scalar
/// for the actual local original point. This is mathematical input, not a FAIR
/// proof, authenticated reveal, qualified dealer or completed DKG decision.
pub struct AggregateContribution {
    peer: [u8; 32],
    original_index: u16,
    coefficients: Option<Commitments>,
    local_share: Option<Scalar>,
}
impl AggregateContribution {
    /// Adopt both original owners without cloning secret or public vectors.
    /// The aggregate job checks their degree and local mathematical association.
    #[must_use]
    pub fn new(
        peer: [u8; 32],
        original_index: u16,
        coefficients: Commitments,
        local_share: Scalar,
    ) -> Self {
        Self {
            peer,
            original_index,
            coefficients: Some(coefficients),
            local_share: Some(local_share),
        }
    }
}

/// Actual aggregate scalar and selected public rows, derived at the original
/// local evaluation point and degree even when too few dealers were selected
/// or the local peer is not selected. This is not a usable decryption Roster,
/// FAIR proof, transcript, source or DKG qualification decision. A consumer that
/// requires a usable roster must explicitly perform Roster::check separately.
pub struct AggregateMaterial {
    secret: Scalar,
    members: Vec<Participant>,
    threshold: usize,
    public_key: Subgroup,
    local_position: Option<usize>,
}
impl AggregateMaterial {
    /// Actual checked sum of the local input scalars modulo the fixed q.
    #[must_use]
    pub const fn secret(&self) -> &Scalar {
        &self.secret
    }
    /// Caller-selected rows in unchanged order and original index space. Empty
    /// selection and fewer rows than threshold remain mathematical outcomes.
    #[must_use]
    pub fn participants(&self) -> &[Participant] {
        &self.members
    }
    /// Original coefficient count/threshold; never reduced to selected count.
    #[must_use]
    pub const fn threshold(&self) -> usize {
        self.threshold
    }
    /// Product of selected constant coefficients; identity for an empty set.
    #[must_use]
    pub const fn public_key(&self) -> Subgroup {
        self.public_key
    }
    /// Selected row of the original local peer/index tuple, or None when that
    /// tuple was not selected. The secret is still evaluated at its original
    /// point; an original polynomial index is never a reduced row offset.
    #[must_use]
    pub const fn local_position(&self) -> Option<usize> {
        self.local_position
    }
    /// Transfer the unique secret, selected rows, original threshold, public key
    /// and optional local position once. This performs no roster admission.
    #[must_use]
    pub fn into_parts(self) -> (Scalar, Vec<Participant>, usize, Subgroup, Option<usize>) {
        (
            self.secret,
            self.members,
            self.threshold,
            self.public_key,
            self.local_position,
        )
    }
    /// Actual retained public vector capacity; secret scalar storage is inline.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.members
            .capacity()
            .checked_mul(core::mem::size_of::<Participant>())
            .ok_or(Error::Overflow)
    }
}

enum Stage {
    Initialize,
    Admit,
    Unique,
    Dealer,
    Polynomial,
    Share,
    Multiply,
    Sigma,
    SigmaPolynomial,
}

/// Bounded owned final-aggregation mathematics over one caller-selected dealer
/// set. Each dealer's scalar must match its committed polynomial at the actual
/// local original index. Coefficients are multiplied once, then the existing
/// exponentiated Horner job derives each retained participant's aggregate sigma.
///
/// No signature, consensus completion, FAIR knowledge/range proof, dealer
/// qualification or native DKG success is inferred from these equations.
pub struct AggregateJob {
    group: Group,
    limits: Limits,
    local_peer: [u8; 32],
    local_original_index: u16,
    threshold: usize,
    contributions: Option<Vec<AggregateContribution>>,
    aggregate: Option<Vec<Subgroup>>,
    members: Option<Vec<Participant>>,
    coefficients: Option<Commitments>,
    polynomial: Option<PolynomialCheck<'static>>,
    share: Option<ShareCheck>,
    secret: Option<Scalar>,
    public_key: Option<Subgroup>,
    result: Option<AggregateMaterial>,
    stage: Stage,
    at: usize,
    other: usize,
    local_position: Option<usize>,
    retained: usize,
    input_vector_bytes: usize,
    aggregate_vector_bytes: usize,
    failure: Option<Error>,
    taken: bool,
}
impl AggregateJob {
    /// Adopt the unchanged selected set and actual local evaluation tuple. The
    /// original threshold is positive/bounded independently of selected count;
    /// all simultaneous requested capacities are checked before allocation. A
    /// metadata scan charges every coefficient allocation, including spare capacity;
    /// polynomial degree, local tuple consistency and pair uniqueness advance later.
    pub fn new(
        contributions: Vec<AggregateContribution>,
        local_peer: [u8; 32],
        local_original_index: u16,
        threshold: usize,
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let count = contributions.len();
        if threshold == 0 || threshold > limits.participants || count > limits.participants {
            return Err(Error::Roster);
        }
        let input_vector_bytes =
            limits.bytes::<AggregateContribution>(contributions.capacity(), 0)?;
        let mut input_bytes = input_vector_bytes;
        for contribution in &contributions {
            let bytes = contribution
                .coefficients
                .as_ref()
                .ok_or(Error::InvalidInput)?
                .retained_bytes()?;
            input_bytes = limits.bytes::<u8>(bytes, input_bytes)?;
        }
        let requested = limits.bytes::<Subgroup>(threshold, input_bytes)?;
        limits.bytes::<Participant>(count, requested)?;
        let mut aggregate = Vec::new();
        aggregate
            .try_reserve_exact(threshold)
            .map_err(|_| Error::Capacity)?;
        let aggregate_vector_bytes = limits.bytes::<Subgroup>(aggregate.capacity(), 0)?;
        let with_aggregate = limits.bytes::<u8>(aggregate_vector_bytes, input_bytes)?;
        limits.bytes::<Participant>(count, with_aggregate)?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        let retained = limits.bytes::<Participant>(members.capacity(), with_aggregate)?;
        Ok(Self {
            group: group.clone(),
            limits,
            local_peer,
            local_original_index,
            threshold,
            contributions: Some(contributions),
            aggregate: Some(aggregate),
            members: Some(members),
            coefficients: None,
            polynomial: None,
            share: None,
            secret: Some(Scalar::zero()),
            public_key: None,
            result: None,
            stage: Stage::Initialize,
            at: 0,
            other: 1,
            local_position: None,
            retained,
            input_vector_bytes,
            aggregate_vector_bytes,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self) -> Result<(), Error> {
        match self.stage {
            Stage::Initialize => {
                let aggregate = self.aggregate.as_mut().ok_or(Error::NotReady)?;
                if aggregate.len() < self.threshold {
                    aggregate.push(Subgroup::identity());
                } else {
                    self.stage = Stage::Admit;
                }
            }
            Stage::Admit => {
                let contributions = self.contributions.as_ref().ok_or(Error::NotReady)?;
                if self.at == contributions.len() {
                    self.at = 0;
                    self.other = 1;
                    self.stage = Stage::Unique;
                    return Ok(());
                }
                let contribution = &contributions[self.at];
                if contribution
                    .coefficients
                    .as_ref()
                    .ok_or(Error::NotReady)?
                    .threshold()
                    != self.threshold
                {
                    return Err(Error::Roster);
                }
                let local_peer = contribution.peer == self.local_peer;
                let local_index = contribution.original_index == self.local_original_index;
                if local_peer != local_index {
                    return Err(Error::Roster);
                }
                if local_peer {
                    self.local_position = Some(self.at);
                }
                self.members
                    .as_mut()
                    .ok_or(Error::NotReady)?
                    .push(Participant {
                        peer: contribution.peer,
                        original_index: contribution.original_index,
                        sigma: Subgroup::identity(),
                    });
                self.at += 1;
            }
            Stage::Unique => {
                let members = self.members.as_ref().ok_or(Error::NotReady)?;
                if self.at + 1 >= members.len() {
                    self.at = 0;
                    self.stage = Stage::Dealer;
                } else if self.other >= members.len() {
                    self.at += 1;
                    self.other = self.at + 1;
                } else {
                    let a = members[self.at];
                    let b = members[self.other];
                    if a.peer == b.peer || a.original_index == b.original_index {
                        return Err(Error::Roster);
                    }
                    self.other += 1;
                }
            }
            Stage::Dealer => {
                let contributions = self.contributions.as_mut().ok_or(Error::NotReady)?;
                if self.at == contributions.len() {
                    self.contributions = None;
                    self.retained = self
                        .retained
                        .checked_sub(self.input_vector_bytes)
                        .ok_or(Error::Overflow)?;
                    self.at = 0;
                    let aggregate = self.aggregate.take().ok_or(Error::NotReady)?;
                    let coefficients = Commitments::from_members(aggregate, self.limits)?;
                    self.public_key = coefficients.get(0);
                    self.coefficients = Some(coefficients);
                    self.stage = Stage::Sigma;
                } else {
                    let coefficients = contributions[self.at]
                        .coefficients
                        .take()
                        .ok_or(Error::NotReady)?;
                    self.polynomial = Some(PolynomialCheck::new_owned(
                        coefficients,
                        self.local_original_index,
                        None,
                        &self.group,
                    ));
                    self.stage = Stage::Polynomial;
                }
            }
            Stage::Polynomial => {
                if self
                    .polynomial
                    .as_mut()
                    .ok_or(Error::NotReady)?
                    .advance(1)?
                    == Progress::Ready
                {
                    let (coefficients, sigma) = self
                        .polynomial
                        .take()
                        .ok_or(Error::NotReady)?
                        .take_owned_result()?;
                    self.coefficients = Some(coefficients);
                    let share = self.contributions.as_mut().ok_or(Error::NotReady)?[self.at]
                        .local_share
                        .take()
                        .ok_or(Error::NotReady)?;
                    self.share = Some(ShareCheck::new(share, sigma, &self.group, self.limits)?);
                    self.stage = Stage::Share;
                }
            }
            Stage::Share => {
                if self.share.as_mut().ok_or(Error::NotReady)?.advance(1)? == Progress::Ready {
                    let share = self.share.as_mut().ok_or(Error::NotReady)?.take_result()?;
                    self.share = None;
                    self.secret = Some(
                        self.secret
                            .take()
                            .ok_or(Error::NotReady)?
                            .add(share, &self.group),
                    );
                    self.other = 0;
                    self.stage = Stage::Multiply;
                }
            }
            Stage::Multiply => {
                if self.other == self.threshold {
                    let coefficients = self.coefficients.take().ok_or(Error::NotReady)?;
                    self.retained = self
                        .retained
                        .checked_sub(coefficients.retained_bytes()?)
                        .ok_or(Error::Overflow)?;
                    drop(coefficients);
                    self.at += 1;
                    self.stage = Stage::Dealer;
                } else {
                    let coefficient = self
                        .coefficients
                        .as_ref()
                        .ok_or(Error::NotReady)?
                        .get(self.other)
                        .ok_or(Error::NotReady)?;
                    let aggregate = self.aggregate.as_mut().ok_or(Error::NotReady)?;
                    aggregate[self.other] =
                        aggregate[self.other].multiply(coefficient, &self.group);
                    self.other += 1;
                }
            }
            Stage::Sigma => {
                let members = self.members.as_ref().ok_or(Error::NotReady)?;
                if self.at == members.len() {
                    self.coefficients = None;
                    self.retained = self
                        .retained
                        .checked_sub(self.aggregate_vector_bytes)
                        .ok_or(Error::Overflow)?;
                    let members = self.members.take().ok_or(Error::NotReady)?;
                    self.result = Some(AggregateMaterial {
                        secret: self.secret.take().ok_or(Error::NotReady)?,
                        members,
                        threshold: self.threshold,
                        public_key: self.public_key.ok_or(Error::NotReady)?,
                        local_position: self.local_position,
                    });
                } else {
                    self.polynomial = Some(PolynomialCheck::new_owned(
                        self.coefficients.take().ok_or(Error::NotReady)?,
                        members[self.at].original_index,
                        None,
                        &self.group,
                    ));
                    self.stage = Stage::SigmaPolynomial;
                }
            }
            Stage::SigmaPolynomial => {
                if self
                    .polynomial
                    .as_mut()
                    .ok_or(Error::NotReady)?
                    .advance(1)?
                    == Progress::Ready
                {
                    let (coefficients, sigma) = self
                        .polynomial
                        .take()
                        .ok_or(Error::NotReady)?
                        .take_owned_result()?;
                    self.coefficients = Some(coefficients);
                    self.members.as_mut().ok_or(Error::NotReady)?[self.at].sigma = sigma;
                    self.at += 1;
                    self.stage = Stage::Sigma;
                }
            }
        }
        Ok(())
    }
    fn fail(&mut self, error: Error) -> Error {
        let error = *self.failure.get_or_insert(error);
        self.contributions = None;
        self.aggregate = None;
        self.members = None;
        self.coefficients = None;
        self.polynomial = None;
        self.share = None;
        self.secret = None;
        self.result = None;
        self.public_key = None;
        self.local_position = None;
        self.retained = 0;
        error
    }
    /// At most units existing Horner/exponent steps, fixed field operations,
    /// original association checks or constant-size ownership transitions.
    /// Invalid work admission is sticky and erases even an untaken result.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        let units = match self.limits.units(units) {
            Ok(units) => units,
            Err(error) => return Err(self.fail(error)),
        };
        if self.result.is_some() {
            return Ok(Progress::Ready);
        }
        for _ in 0..units {
            if let Err(error) = self.step() {
                return Err(self.fail(error));
            }
            if self.result.is_some() {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume only the complete checked mathematical result once.
    pub fn take_result(&mut self) -> Result<AggregateMaterial, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        self.retained = 0;
        Ok(result)
    }
    /// Erase all original secret inputs, partial scalar/power work and untaken
    /// output, releasing every owned vector. Cancellation remains sticky.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
    /// Actual combined live Vec capacities, including spare input slots and all
    /// coefficient owners while moved through existing owned arithmetic jobs.
    /// Fixed inline job storage is the enclosing owner's separate reservation.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.limits.bytes::<u8>(self.retained, 0)
    }
}

#[cfg(test)]
mod tests;
