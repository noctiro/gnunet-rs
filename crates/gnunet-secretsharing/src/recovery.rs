//! Bounded mathematical recovery of the small rational plaintext described by
//! Fouque--Stern section3.2. This is not a FAIR certificate or proof producer.
use crate::{
    Error, Group, Limits, Progress, Scalar,
    field::{Pow, Pow1, Q},
};
use crypto_bigint::{CtAssign, CtEq, CtLt, NonZero, U1024, U2048, U4096};
use gnunet_paillier::{Plaintext, PublicKey};
use zeroize::{Zeroize, Zeroizing};

const ROUNDS: u16 = 2048;
const A: U2048 = U2048::ONE.shl_vartime(1024);
const B: U4096 = U4096::ONE.shl_vartime(512);

#[derive(Clone, Copy)]
enum Stage {
    Euclid,
    Prepare,
    Invert,
}

/// Recover a mathematical scalar from a Paillier plaintext y congruent to a/b
/// modulo the original n, with0<=a<2^1024 and0<|b|<2^512. The fixed public
/// modulus profile gives n>2*A*B, making that bounded rational unique.
///
/// This job does not verify a FAIR proof, authenticate a sender, or match g^x
/// to a commitment. The caller must still perform those independent checks.
/// It returns only an owned Scalar, never a qualification or final783 token.
/// There is no heap, entropy, variable round count or secret-dependent early
/// Euclidean termination. Every unit is one fixed-width constant-time division
/// turn, a fixed-size preparation, or an existing modular-exponentiation bit.
pub struct FairRecoveryJob {
    group: Group,
    limits: Limits,
    n: U2048,
    original: Zeroizing<U2048>,
    r0: Zeroizing<U2048>,
    r1: Zeroizing<U2048>,
    t0: Zeroizing<U4096>,
    t1: Zeroizing<U4096>,
    numerator: Option<Zeroizing<U1024>>,
    inverse: Option<Pow1>,
    rounds: u16,
    stage: Stage,
    result: Option<Scalar>,
    failure: Option<Error>,
    taken: bool,
}
impl FairRecoveryJob {
    /// Adopt the unique original decrypted plaintext and pin its exact modulus.
    /// Even a complete recovery remains an unqualified mathematical candidate.
    pub fn new(
        key: &PublicKey,
        value: Plaintext,
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let n = U2048::from_be_slice(&key.to_bytes());
        let bytes = value.to_bytes();
        let original = Zeroizing::new(U2048::from_be_slice(bytes.as_ref()));
        if *original >= n {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            group: group.clone(),
            limits,
            n,
            r0: Zeroizing::new(n),
            r1: Zeroizing::new(*original),
            original,
            t0: Zeroizing::new(U4096::ZERO),
            t1: Zeroizing::new(U4096::ONE),
            numerator: None,
            inverse: None,
            rounds: 0,
            stage: Stage::Euclid,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn erase_work(&mut self) {
        self.original.zeroize();
        self.r0.zeroize();
        self.r1.zeroize();
        self.t0.zeroize();
        self.t1.zeroize();
        self.numerator = None;
        self.inverse = None;
    }
    fn fail(&mut self, error: Error) -> Error {
        let error = *self.failure.get_or_insert(error);
        self.erase_work();
        self.result = None;
        error
    }
    fn euclid(&mut self) -> Result<(), Error> {
        // Stop changing the state at the first remainder below A, but execute
        // every remaining division and multiplication on the same schedule.
        // Two active Euclidean turns at least halve the remainder, so2048
        // turns suffice from any original2048-bit plaintext/modulus pair.
        let active = !self.r1.ct_lt(&A);
        let mut divisor = Zeroizing::new(U2048::ONE);
        divisor.ct_assign(&self.r1, active);
        let divisor = Zeroizing::new(
            NonZero::new(*divisor)
                .into_option()
                .ok_or(Error::InvalidInput)?,
        );
        let (quotient, remainder) = self.r0.div_rem(&divisor);
        let quotient: Zeroizing<U4096> = Zeroizing::new(quotient.resize());
        let remainder = Zeroizing::new(remainder);
        // Signed coefficients use a4096-bit two's-complement container.
        // Extended-Euclidean coefficients for these inputs stay within n;
        // the product before subtraction needs at most4096 unsigned bits.
        let product = Zeroizing::new(quotient.wrapping_mul(&self.t1));
        let next = Zeroizing::new(self.t0.wrapping_sub(&product));
        self.r0.ct_assign(&self.r1, active);
        self.r1.ct_assign(&remainder, active);
        self.t0.ct_assign(&self.t1, active);
        self.t1.ct_assign(&next, active);
        self.rounds += 1;
        if self.rounds == ROUNDS {
            self.stage = Stage::Prepare;
        }
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), Error> {
        let negative = self.t1.bit(4095);
        let mut denominator = Zeroizing::new(*self.t1);
        let negated = Zeroizing::new(self.t1.wrapping_neg());
        denominator.ct_assign(&negated, negative);
        if !bool::from(self.r1.ct_lt(&A) & denominator.ct_lt(&B) & denominator.is_nonzero()) {
            return Err(Error::InvalidProof);
        }
        // Check the exact original congruence before reducing to the group
        // field. This also refuses an unrelated small rational candidate.
        let original: Zeroizing<U4096> = Zeroizing::new(self.original.resize());
        let product = Zeroizing::new(denominator.wrapping_mul(&original));
        let n: U4096 = self.n.resize();
        let divisor = NonZero::new(n).into_option().ok_or(Error::InvalidInput)?;
        let (quotient, residue) = product.div_rem(&divisor);
        let _quotient = Zeroizing::new(quotient);
        let mut residue = Zeroizing::new(residue);
        let mut negative_residue = Zeroizing::new(n.wrapping_sub(&residue));
        negative_residue.ct_assign(&U4096::ZERO, residue.ct_eq(&U4096::ZERO));
        residue.ct_assign(&negative_residue, negative);
        let numerator: Zeroizing<U4096> = Zeroizing::new(self.r1.resize());
        if !bool::from(residue.ct_eq(&*numerator)) {
            return Err(Error::InvalidProof);
        }
        let q: U2048 = Q.resize();
        let divisor = NonZero::new(q).into_option().ok_or(Error::InvalidInput)?;
        let (quotient, numerator) = self.r1.div_rem(&divisor);
        let _quotient = Zeroizing::new(quotient);
        self.numerator = Some(Zeroizing::new(numerator.resize()));
        let denominator: Zeroizing<U1024> = Zeroizing::new(denominator.resize());
        let exponent = Q.wrapping_sub(&U1024::from_u32(2));
        self.inverse = Some(Pow::new(&denominator, &exponent, 1024, &self.group.q)?);
        self.original.zeroize();
        self.r0.zeroize();
        self.r1.zeroize();
        self.t0.zeroize();
        self.stage = Stage::Invert;
        Ok(())
    }
    fn step(&mut self) -> Result<(), Error> {
        match self.stage {
            Stage::Euclid => self.euclid(),
            Stage::Prepare => self.prepare(),
            Stage::Invert => {
                if self.inverse.as_mut().ok_or(Error::NotReady)?.step() {
                    let inverse = self.inverse.take().ok_or(Error::NotReady)?.finish()?;
                    let numerator = self.numerator.take().ok_or(Error::NotReady)?;
                    let mut scalar = self.group.mul_q(&numerator, &inverse);
                    let mut negated = Zeroizing::new(Q.wrapping_sub(&scalar));
                    negated.ct_assign(&U1024::ZERO, scalar.ct_eq(&U1024::ZERO));
                    scalar.ct_assign(&negated, self.t1.bit(4095));
                    self.result = Some(Scalar(scalar));
                    self.erase_work();
                }
                Ok(())
            }
        }
    }
    /// Advance at most units fixed arithmetic turns. Even canonical direct
    /// scalars use the same2048 reconstruction turns and1024 inverse bits.
    /// Invalid work admission is sticky and erases an untaken result.
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
    /// Consume the unique recovered mathematical scalar exactly once. The
    /// caller must still match its original exponentiated polynomial value.
    pub fn take_result(&mut self) -> Result<Scalar, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(result)
    }
    /// Erase original plaintext, Euclidean work, inverse and untaken scalar.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}

#[cfg(test)]
mod tests;
