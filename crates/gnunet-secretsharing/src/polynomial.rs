use crate::{
    Entropy, Error, Group, Limits, Progress, Scalar, Subgroup,
    field::{G, Pow, Pow1, Sampler, mul},
};
use alloc::vec::Vec;
use crypto_bigint::U1024;
use zeroize::Zeroizing;

/// Original Shamir coefficient vector a0..a(t-1), with secret erasure per slot.
/// It is never cloned or changed while any borrowed arithmetic job exists.
pub struct Polynomial {
    coefficients: Vec<Scalar>,
    limits: Limits,
}
impl Polynomial {
    /// Adopt exactly one owned coefficient allocation. The threshold is its real
    /// length, not a missing/zero field recovered from an unrelated wire header.
    pub fn from_coefficients(coefficients: Vec<Scalar>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if coefficients.is_empty() || coefficients.len() > limits.participants {
            return Err(Error::Capacity);
        }
        limits.bytes::<Scalar>(coefficients.capacity(), 0)?;
        Ok(Self {
            coefficients,
            limits,
        })
    }
    /// Actual threshold/number of coefficients.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.coefficients.len()
    }
    /// Actual retained allocation capacity, including unused allocated slots.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.limits.bytes::<Scalar>(self.coefficients.capacity(), 0)
    }
    /// Begin actual Horner evaluation at original DKG index+1 (in1..65536),
    /// never at a position in a reduced final roster.
    pub fn evaluate<'a>(&'a self, original_index: u16, group: &Group) -> Evaluation<'a> {
        Evaluation::new_view(PolynomialView::Borrowed(self), original_index, group)
    }
    /// Begin actual coefficient exponentiation; output allocation and the
    /// original polynomial's allocation must fit together in the same budget.
    pub fn commitments<'a>(&'a self, group: &Group) -> Result<CommitmentJob<'a>, Error> {
        CommitmentJob::new_view(PolynomialView::Borrowed(self), group)
    }
}
/// True uniformly sampled nonzero coefficients, one bounded rejection draw per
/// unit. Counts/capacity are reserved before the first entropy call.
pub struct PolynomialGenerator {
    coefficients: Option<Vec<Scalar>>,
    threshold: usize,
    sampler: Sampler,
    limits: Limits,
    result: Option<Polynomial>,
    failure: Option<Error>,
    taken: bool,
}
impl PolynomialGenerator {
    /// Reserve only the actual original threshold, not maximum participants.
    pub fn new(threshold: usize, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if threshold == 0 || threshold > limits.participants {
            return Err(Error::Capacity);
        }
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(threshold)
            .map_err(|_| Error::Capacity)?;
        limits.bytes::<Scalar>(coefficients.capacity(), 0)?;
        Ok(Self {
            coefficients: Some(coefficients),
            threshold,
            sampler: Sampler::new(limits),
            limits,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self, entropy: &mut impl Entropy) -> Result<(), Error> {
        if let Some(scalar) = self.sampler.step(entropy)? {
            let coefficients = self.coefficients.as_mut().ok_or(Error::NotReady)?;
            coefficients.push(scalar);
            self.sampler = Sampler::new(self.limits);
            if coefficients.len() == self.threshold {
                let coefficients = self.coefficients.take().ok_or(Error::NotReady)?;
                self.result = Some(Polynomial::from_coefficients(coefficients, self.limits)?);
            }
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.coefficients = None;
        self.result = None;
        e
    }
    /// Advance at most units actual128-byte rejection draws.
    pub fn advance(&mut self, entropy: &mut impl Entropy, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.result.is_some() {
            return Ok(Progress::Ready);
        }
        let count = match self.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            if let Err(e) = self.step(entropy) {
                return Err(self.fail(e));
            }
            if self.result.is_some() {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume the actual completed original secret polynomial once.
    pub fn take_result(&mut self) -> Result<Polynomial, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let out = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(out)
    }
    /// Erase all accepted coefficients and partial original sampling state.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
    /// Actual current coefficient allocation, not count times a configured max.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        match &self.coefficients {
            Some(v) => self.limits.bytes::<Scalar>(v.capacity(), 0),
            None => match &self.result {
                Some(p) => p.retained_bytes(),
                None => Ok(0),
            },
        }
    }
}
/// Borrowed or uniquely owned original polynomial and zeroizing Horner state.
/// Both input modes use the same bounded coefficient multiply/add algorithm.
pub struct Evaluation<'a> {
    group: Group,
    polynomial: Option<PolynomialView<'a>>,
    at: usize,
    x: U1024,
    accumulator: Option<Zeroizing<U1024>>,
    limits: Limits,
    result: Option<Scalar>,
    failure: Option<Error>,
    taken: bool,
}
impl<'a> Evaluation<'a> {
    fn new_view(polynomial: PolynomialView<'a>, original_index: u16, group: &Group) -> Self {
        let at = polynomial.threshold();
        let limits = polynomial.limits;
        Self {
            group: group.clone(),
            polynomial: Some(polynomial),
            at,
            x: U1024::from_u32(u32::from(original_index) + 1),
            accumulator: Some(Zeroizing::new(U1024::ZERO)),
            limits,
            result: None,
            failure: None,
            taken: false,
        }
    }
    fn step(&mut self) -> Result<Progress, Error> {
        if self.at != 0 {
            self.at -= 1;
            let accumulator = self.accumulator.as_ref().ok_or(Error::NotReady)?;
            let coefficients = &self
                .polynomial
                .as_ref()
                .ok_or(Error::NotReady)?
                .coefficients;
            let coefficient = coefficients.get(self.at).ok_or(Error::InvalidInput)?;
            let product = self.group.mul_q(accumulator, &self.x);
            self.accumulator = Some(self.group.add_q(&product, &coefficient.0));
        }
        if self.at == 0 {
            self.result = Some(Scalar(self.accumulator.take().ok_or(Error::NotReady)?));
            Ok(Progress::Ready)
        } else {
            Ok(Progress::Advanced)
        }
    }
    /// One original coefficient multiply/add per unit, with no float exponent or
    /// unbounded degree loop inside a step.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.result.is_some() {
            return Ok(Progress::Ready);
        }
        let count = match self.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            match self.step() {
                Ok(Progress::Ready) => return Ok(Progress::Ready),
                Ok(Progress::Advanced) => {}
                Err(error) => return Err(self.fail(error)),
            }
        }
        Ok(Progress::Advanced)
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.accumulator = None;
        self.result = None;
        // Dropping the owned view erases each scalar and releases its actual
        // allocation now. A borrowed polynomial remains with its caller.
        self.polynomial = None;
        e
    }
    /// Consume exactly the original evaluated scalar once. An owned input is
    /// erased/released here; use take_owned_result to retain that polynomial.
    pub fn take_result(&mut self) -> Result<Scalar, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let out = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        self.polynomial = None;
        Ok(out)
    }
    /// Immediately erase/release owned coefficients and partial/result scalars.
    /// A borrowed polynomial remains unchanged with its original owner.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
    /// Actual owned polynomial capacity, including spare allocated slots.
    /// Borrowed input is charged by its caller and contributes zero here;
    /// accumulator/result scalar storage is inline rather than a Vec allocation.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        match &self.polynomial {
            Some(PolynomialView::Owned(polynomial)) => polynomial.retained_bytes(),
            Some(PolynomialView::Borrowed(_)) | None => Ok(0),
        }
    }
}
impl Evaluation<'static> {
    /// Adopt the original secret polynomial without cloning its coefficients,
    /// a self-reference or a second evaluation algorithm. The exact original
    /// index+1 remains in1..65536.
    #[must_use]
    pub fn new_owned(polynomial: Polynomial, original_index: u16, group: &Group) -> Self {
        Self::new_view(PolynomialView::Owned(polynomial), original_index, group)
    }
    /// Transfer the unique original polynomial and its completed scalar. A
    /// failed, cancelled or incomplete evaluation cannot yield either owner.
    pub fn take_owned_result(mut self) -> Result<(Polynomial, Scalar), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        let result = self.result.take().ok_or(Error::NotReady)?;
        match self.polynomial.take().ok_or(Error::NotReady)? {
            PolynomialView::Owned(polynomial) => Ok((polynomial, result)),
            PolynomialView::Borrowed(_) => Err(Error::InvalidInput),
        }
    }
}
/// Actual exponentiated coefficients in their original polynomial order.
pub struct Commitments {
    pub(crate) members: Vec<Subgroup>,
    limits: Limits,
}
impl Commitments {
    /// Adopt already membership-checked original values without copying.
    pub fn from_members(members: Vec<Subgroup>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if members.is_empty() || members.len() > limits.participants {
            return Err(Error::Capacity);
        }
        limits.bytes::<Subgroup>(members.capacity(), 0)?;
        Ok(Self { members, limits })
    }
    /// Actual coefficient count/threshold, not remote claimed availability.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.members.len()
    }
    /// One exact original exponentiated coefficient.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<Subgroup> {
        self.members.get(index).copied()
    }
    /// Actual retained allocation capacity.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.limits.bytes::<Subgroup>(self.members.capacity(), 0)
    }
    /// Actual public constant-term commitment used by DKG round1.
    pub fn presecret_hash(&self) -> Result<[u8; 64], Error> {
        let first = self.members.first().ok_or(Error::InvalidInput)?;
        Ok(gnunet_crypto::hash512(&first.to_bytes()))
    }
}
enum PolynomialView<'a> {
    Borrowed(&'a Polynomial),
    Owned(Polynomial),
}
impl core::ops::Deref for PolynomialView<'_> {
    type Target = Polynomial;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
        }
    }
}
/// Original bounded real exponentiation of each secret polynomial coefficient.
pub struct CommitmentJob<'a> {
    group: Group,
    polynomial: PolynomialView<'a>,
    members: Option<Vec<Subgroup>>,
    pow: Option<Pow1>,
    at: usize,
    result: Option<Commitments>,
    failure: Option<Error>,
    taken: bool,
}
impl<'a> CommitmentJob<'a> {
    fn new_view(polynomial: PolynomialView<'a>, group: &Group) -> Result<Self, Error> {
        let mut members = Vec::new();
        members
            .try_reserve_exact(polynomial.threshold())
            .map_err(|_| Error::Capacity)?;
        polynomial
            .limits
            .bytes::<Subgroup>(members.capacity(), polynomial.retained_bytes()?)?;
        Ok(Self {
            group: group.clone(),
            polynomial,
            members: Some(members),
            pow: None,
            at: 0,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self) -> Result<(), Error> {
        if self.at == self.polynomial.threshold() {
            let members = self.members.take().ok_or(Error::NotReady)?;
            self.result = Some(Commitments::from_members(members, self.polynomial.limits)?);
            return Ok(());
        }
        if self.pow.is_none() {
            self.pow = Some(Pow::new(
                &G,
                &self.polynomial.coefficients[self.at].0,
                1024,
                &self.group.p,
            )?);
            return Ok(());
        }
        if self.pow.as_mut().ok_or(Error::NotReady)?.step() {
            let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
            self.members
                .as_mut()
                .ok_or(Error::NotReady)?
                .push(Subgroup(*value));
            self.at += 1;
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.pow = None;
        self.members = None;
        self.result = None;
        if let PolynomialView::Owned(polynomial) = &mut self.polynomial {
            polynomial.coefficients.clear();
        }
        e
    }
    /// One exponent bit or bounded coefficient transition per unit.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.result.is_some() {
            return Ok(Progress::Ready);
        }
        let count = match self.polynomial.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            if let Err(e) = self.step() {
                return Err(self.fail(e));
            }
            if self.result.is_some() {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume only the completed ordered exponentiated coefficient vector.
    pub fn take_result(&mut self) -> Result<Commitments, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let out = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(out)
    }
    /// Erase all owned powers and retire the output snapshot.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
    /// Actual combined live input and output vector allocations.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let input = self.polynomial.retained_bytes()?;
        let capacity = self.members.as_ref().map_or_else(
            || self.result.as_ref().map_or(0, |r| r.members.capacity()),
            Vec::capacity,
        );
        self.polynomial.limits.bytes::<Subgroup>(capacity, input)
    }
}
impl CommitmentJob<'static> {
    /// Adopt the actual original secret polynomial for caller-driven polling.
    /// This shares the borrowed job's exact algorithm without a self-reference,
    /// secret clone or independent exponentiation implementation.
    pub fn new_owned(polynomial: Polynomial, group: &Group) -> Result<Self, Error> {
        Self::new_view(PolynomialView::Owned(polynomial), group)
    }
    /// Transfer the original polynomial and its real completed commitments.
    /// Refusal/cancel/drop erases any owned secret coefficients; no new result
    /// can be produced from a partial or failed exponentiation job.
    pub fn take_owned_result(mut self) -> Result<(Polynomial, Commitments), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        let commitments = self.result.take().ok_or(Error::NotReady)?;
        match self.polynomial {
            PolynomialView::Owned(polynomial) => Ok((polynomial, commitments)),
            PolynomialView::Borrowed(_) => Err(Error::InvalidInput),
        }
    }
}
enum CommitmentView<'a> {
    Borrowed(&'a Commitments),
    Owned(Commitments),
}
impl core::ops::Deref for CommitmentView<'_> {
    type Target = Commitments;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
        }
    }
}
/// Actual exponentiated Horner evaluation. It checks the same original share
/// index as secret Horner evaluation, avoiding the C floating pow/truncation.
pub struct PolynomialCheck<'a> {
    group: Group,
    commitments: CommitmentView<'a>,
    at: usize,
    x: U1024,
    value: Subgroup,
    pow: Option<Pow1>,
    expected: Option<Subgroup>,
    result: Option<Subgroup>,
    failure: Option<Error>,
    taken: bool,
}
impl<'a> PolynomialCheck<'a> {
    /// expected=None derives a sigma; Some verifies the supplied original one.
    pub fn new(
        commitments: &'a Commitments,
        original_index: u16,
        expected: Option<Subgroup>,
        group: &Group,
    ) -> Self {
        Self::new_view(
            CommitmentView::Borrowed(commitments),
            original_index,
            expected,
            group,
        )
    }
    fn new_view(
        commitments: CommitmentView<'a>,
        original_index: u16,
        expected: Option<Subgroup>,
        group: &Group,
    ) -> Self {
        let at = commitments.threshold();
        Self {
            group: group.clone(),
            commitments,
            at,
            x: U1024::from_u32(u32::from(original_index) + 1),
            value: Subgroup::identity(),
            pow: None,
            expected,
            result: None,
            failure: None,
            taken: false,
        }
    }
    fn step(&mut self) -> Result<(), Error> {
        if self.at == 0 {
            if self.expected.is_some_and(|x| x != self.value) {
                return Err(Error::InvalidProof);
            }
            self.result = Some(self.value);
            return Ok(());
        }
        if self.pow.is_none() {
            self.pow = Some(Pow::new(&self.value.0, &self.x, 32, &self.group.p)?);
            return Ok(());
        }
        if self.pow.as_mut().ok_or(Error::NotReady)?.step() {
            let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
            self.at -= 1;
            self.value = Subgroup(*mul(
                &value,
                &self.commitments.members[self.at].0,
                &self.group.p,
            ));
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.pow = None;
        self.result = None;
        e
    }
    /// At most units public-index exponent bits or bounded coefficient steps.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.result.is_some() {
            return Ok(Progress::Ready);
        }
        let count = match self.commitments.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            if let Err(e) = self.step() {
                return Err(self.fail(e));
            }
            if self.result.is_some() {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume the actually derived/checked original sigma.
    pub fn take_result(&mut self) -> Result<Subgroup, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let out = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(out)
    }
    /// Cancel the original work without certifying a sigma.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
    /// Actual original coefficient allocation retained by this owned/borrowed view.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.commitments.retained_bytes()
    }
}

impl PolynomialCheck<'static> {
    /// Adopt the original checked coefficient vector without a self-reference,
    /// clone or second Horner algorithm. Original index+1 remains unchanged.
    pub fn new_owned(
        commitments: Commitments,
        original_index: u16,
        expected: Option<Subgroup>,
        group: &Group,
    ) -> Self {
        Self::new_view(
            CommitmentView::Owned(commitments),
            original_index,
            expected,
            group,
        )
    }
    /// Transfer the exact original coefficients and actually completed sigma.
    /// Failed/partial/cancelled jobs cannot produce a checked result.
    pub fn take_owned_result(mut self) -> Result<(Commitments, Subgroup), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        let result = self.result.take().ok_or(Error::NotReady)?;
        match self.commitments {
            CommitmentView::Owned(commitments) => Ok((commitments, result)),
            CommitmentView::Borrowed(_) => Err(Error::InvalidInput),
        }
    }
}

#[cfg(test)]
mod owned_evaluation_tests {
    use super::*;

    fn check(condition: bool) -> Result<(), Error> {
        if condition {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }

    fn polynomial() -> Result<Polynomial, Error> {
        let mut coefficients = Vec::new();
        // Deliberate spare slots distinguish allocation accounting from length.
        coefficients
            .try_reserve_exact(5)
            .map_err(|_| Error::Capacity)?;
        for value in [2u64, 3, 5] {
            let mut bytes = [0; 128];
            bytes[120..].copy_from_slice(&value.to_be_bytes());
            coefficients.push(Scalar::from_bytes(&bytes)?);
        }
        Polynomial::from_coefficients(coefficients, Limits::default())
    }

    fn value_is(scalar: &Scalar, expected: u64) -> Result<(), Error> {
        let bytes = scalar.to_bytes();
        check(bytes[..120].iter().all(|v| *v == 0) && bytes[120..] == expected.to_be_bytes())
    }

    #[test]
    fn owned_and_borrowed_evaluation_match_original_points_and_return_the_same_allocation()
    -> Result<(), Error> {
        let group = Group::new()?;
        let mut original = polynomial()?;
        let allocation = original.coefficients.as_ptr();
        let retained = original.retained_bytes()?;
        check(retained > original.threshold() * core::mem::size_of::<Scalar>())?;
        // These exact values also detect wrapping original65535+1 back to0.
        for (index, expected) in [(0, 10), (7, 346), (u16::MAX, 21_475_033_090)] {
            let borrowed = {
                let mut job = original.evaluate(index, &group);
                check(job.retained_bytes()? == 0)?;
                check(job.advance(2)? == Progress::Advanced)?;
                check(job.advance(1)? == Progress::Ready)?;
                job.take_result()?
            };
            value_is(&borrowed, expected)?;
            let mut job = Evaluation::new_owned(original, index, &group);
            check(job.retained_bytes()? == retained)?;
            check(job.x == U1024::from_u32(u32::from(index) + 1))?;
            check(job.advance(1)? == Progress::Advanced)?;
            check(job.advance(2)? == Progress::Ready)?;
            check(job.retained_bytes()? == retained)?;
            let (returned, scalar) = job.take_owned_result()?;
            check(
                returned.coefficients.as_ptr() == allocation
                    && returned.retained_bytes()? == retained,
            )?;
            check(borrowed.to_bytes().as_ref() == scalar.to_bytes().as_ref())?;
            value_is(&scalar, expected)?;
            original = returned;
        }
        Ok(())
    }

    #[test]
    fn owned_failure_and_cancel_release_coefficients_and_all_secret_results_immediately()
    -> Result<(), Error> {
        let group = Group::new()?;
        let mut job = Evaluation::new_owned(polynomial()?, u16::MAX, &group);
        check(job.advance(1)? == Progress::Advanced)?;
        check(matches!(job.advance(0), Err(Error::Capacity)))?;
        check(
            job.polynomial.is_none()
                && job.accumulator.is_none()
                && job.result.is_none()
                && job.retained_bytes()? == 0,
        )?;
        job.cancel();
        check(matches!(job.advance(1), Err(Error::Capacity)))?;
        check(matches!(job.take_owned_result(), Err(Error::Capacity)))?;

        for ready in [false, true] {
            let mut job = Evaluation::new_owned(polynomial()?, u16::MAX, &group);
            check(
                job.advance(if ready { 3 } else { 1 })?
                    == if ready {
                        Progress::Ready
                    } else {
                        Progress::Advanced
                    },
            )?;
            job.cancel();
            check(
                job.polynomial.is_none()
                    && job.accumulator.is_none()
                    && job.result.is_none()
                    && job.retained_bytes()? == 0,
            )?;
            check(matches!(job.advance(1), Err(Error::Cancelled)))?;
            check(matches!(job.take_owned_result(), Err(Error::Cancelled)))?;
        }
        Ok(())
    }

    #[test]
    fn borrowed_cancel_preserves_the_original_and_scalar_only_take_releases_owned_input()
    -> Result<(), Error> {
        let group = Group::new()?;
        let original = polynomial()?;
        let retained = original.retained_bytes()?;
        {
            let mut job = original.evaluate(7, &group);
            check(job.advance(1)? == Progress::Advanced)?;
            job.cancel();
            check(
                job.polynomial.is_none()
                    && job.accumulator.is_none()
                    && job.result.is_none()
                    && job.retained_bytes()? == 0,
            )?;
            check(matches!(job.take_result(), Err(Error::Cancelled)))?;
        }
        check(original.threshold() == 3 && original.retained_bytes()? == retained)?;
        let mut job = Evaluation::new_owned(original, 7, &group);
        check(job.advance(3)? == Progress::Ready)?;
        let scalar = job.take_result()?;
        value_is(&scalar, 346)?;
        check(
            job.polynomial.is_none()
                && job.accumulator.is_none()
                && job.result.is_none()
                && job.retained_bytes()? == 0,
        )?;
        job.cancel();
        check(matches!(job.advance(1), Err(Error::Finished)))?;
        check(matches!(job.take_result(), Err(Error::Finished)))
    }
}

#[cfg(test)]
mod owned_commitment_tests {
    use super::*;
    #[test]
    fn owned_cancel_cannot_transfer_secret_material_as_a_completed_result() -> Result<(), Error> {
        let limits = Limits::default();
        let polynomial = Polynomial::from_coefficients(alloc::vec![Scalar::zero()], limits)?;
        let group = Group::new()?;
        let mut job = CommitmentJob::new_owned(polynomial, &group)?;
        job.cancel();
        match job.take_owned_result() {
            Err(Error::Cancelled) => Ok(()),
            _ => Err(Error::InvalidProof),
        }
    }
    #[test]
    fn owned_polynomial_check_retains_original65536_point_and_rejects_cancelled_transfer()
    -> Result<(), Error> {
        let commitments =
            Commitments::from_members(alloc::vec![Subgroup::identity()], Limits::default())?;
        let group = Group::new()?;
        let mut job = PolynomialCheck::new_owned(commitments, u16::MAX, None, &group);
        if job.x != U1024::from_u32(65536) {
            return Err(Error::InvalidProof);
        }
        job.cancel();
        match job.take_owned_result() {
            Err(Error::Cancelled) => Ok(()),
            _ => Err(Error::InvalidProof),
        }
    }
}
