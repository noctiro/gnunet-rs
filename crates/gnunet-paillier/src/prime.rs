//! Real finite1024-bit prime search and original2048-bit Paillier key creation.
use crate::{
    Entropy, Error, KeyPair, Limits, PRIME_ROUNDS, PrivateKey, Progress, PublicKey, U1024, U2048,
    pow::Pow,
};
use crypto_bigint::{
    Limb, NonZero, Odd,
    modular::{FixedMontyForm, FixedMontyParams},
    nlimbs,
};
use zeroize::{Zeroize, Zeroizing};
const SMALL_PRIMES: [u16; 53] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];
#[derive(Clone, Copy, Eq, PartialEq)]
enum TestPhase {
    Sieve,
    Sample,
    Power,
    Square,
    Passed,
    Composite,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum TestProgress {
    Advanced,
    Passed,
    Composite,
}
struct PrimeTest {
    candidate: Zeroizing<U1024>,
    minus_one: Zeroizing<U1024>,
    exponent: Zeroizing<U1024>,
    powers_of_two: u32,
    sieve: usize,
    rounds: u16,
    draws: u32,
    square_at: u32,
    phase: TestPhase,
    params: Option<Zeroizing<FixedMontyParams<{ nlimbs(1024) }>>>,
    pow: Option<Pow<{ nlimbs(1024) }>>,
    value: Option<Zeroizing<FixedMontyForm<{ nlimbs(1024) }>>>,
}
impl PrimeTest {
    fn new(candidate: Zeroizing<U1024>) -> Result<Self, Error> {
        if candidate.bits() != 1024 || !candidate.bit_vartime(0) {
            return Err(Error::InvalidKey);
        }
        let minus_one = Zeroizing::new(candidate.wrapping_sub(&U1024::ONE));
        let powers_of_two = minus_one.trailing_zeros();
        if powers_of_two == 0 || powers_of_two >= 1024 {
            return Err(Error::InvalidKey);
        }
        let exponent = Zeroizing::new(minus_one.shr(powers_of_two));
        Ok(Self {
            candidate,
            minus_one,
            exponent,
            powers_of_two,
            sieve: 0,
            rounds: 0,
            draws: 0,
            square_at: 0,
            phase: TestPhase::Sieve,
            params: None,
            pow: None,
            value: None,
        })
    }
    fn pass_round(&mut self) -> Result<TestProgress, Error> {
        let rounds = self.rounds.checked_add(1).ok_or(Error::Capacity)?;
        self.pow = None;
        self.value = None;
        self.rounds = rounds;
        self.draws = 0;
        if rounds == PRIME_ROUNDS {
            self.phase = TestPhase::Passed;
            Ok(TestProgress::Passed)
        } else {
            self.phase = TestPhase::Sample;
            Ok(TestProgress::Advanced)
        }
    }
    fn composite(&mut self) -> TestProgress {
        self.pow = None;
        self.value = None;
        self.phase = TestPhase::Composite;
        TestProgress::Composite
    }
    fn sample(
        &mut self,
        entropy: &mut impl Entropy,
        limits: Limits,
    ) -> Result<TestProgress, Error> {
        let draws = self.draws.checked_add(1).ok_or(Error::Capacity)?;
        if draws > limits.rejections {
            return Err(Error::Capacity);
        }
        self.draws = draws;
        let mut bytes = Zeroizing::new([0u8; 128]);
        entropy.fill(bytes.as_mut()).map_err(Error::Entropy)?;
        let sample = Zeroizing::new(U1024::from_be_slice(bytes.as_ref()));
        let bound = Zeroizing::new(self.candidate.wrapping_sub(&U1024::from(3u8)));
        if *sample >= *bound {
            return Ok(TestProgress::Advanced);
        }
        let base = Zeroizing::new(sample.wrapping_add(&U1024::from(2u8)));
        self.pow = Some(Pow::new(
            &base,
            &self.exponent,
            1024,
            self.params.as_ref().ok_or(Error::NotReady)?,
        )?);
        self.phase = TestPhase::Power;
        Ok(TestProgress::Advanced)
    }
    fn step(&mut self, entropy: &mut impl Entropy, limits: Limits) -> Result<TestProgress, Error> {
        match self.phase {
            TestPhase::Sieve => {
                let prime = *SMALL_PRIMES.get(self.sieve).ok_or(Error::InvalidKey)?;
                let divisor = NonZero::new(Limb::from(prime))
                    .into_option()
                    .ok_or(Error::InvalidKey)?;
                let rem = Zeroizing::new(self.candidate.rem_limb(divisor));
                if *rem == Limb::ZERO {
                    return Ok(self.composite());
                }
                self.sieve += 1;
                if self.sieve == SMALL_PRIMES.len() {
                    let odd = Zeroizing::new(
                        Odd::new(*self.candidate)
                            .into_option()
                            .ok_or(Error::InvalidKey)?,
                    );
                    self.params = Some(Zeroizing::new(FixedMontyParams::new(*odd)));
                    self.phase = TestPhase::Sample;
                }
                Ok(TestProgress::Advanced)
            }
            TestPhase::Sample => self.sample(entropy, limits),
            TestPhase::Power => {
                if !self.pow.as_mut().ok_or(Error::NotReady)?.step() {
                    return Ok(TestProgress::Advanced);
                }
                let y = self.pow.take().ok_or(Error::NotReady)?.finish()?;
                if *y == U1024::ONE || *y == *self.minus_one {
                    return self.pass_round();
                }
                if self.powers_of_two <= 1 {
                    return Ok(self.composite());
                }
                let params = self.params.as_ref().ok_or(Error::NotReady)?;
                self.value = Some(Zeroizing::new(FixedMontyForm::new(&y, params)));
                self.square_at = 1;
                self.phase = TestPhase::Square;
                Ok(TestProgress::Advanced)
            }
            TestPhase::Square => {
                if self.square_at >= self.powers_of_two {
                    return Ok(self.composite());
                }
                let value = self.value.as_mut().ok_or(Error::NotReady)?;
                let next = Zeroizing::new(value.square());
                value.zeroize();
                **value = *next;
                let y = Zeroizing::new(value.retrieve());
                if *y == *self.minus_one {
                    return self.pass_round();
                }
                if *y == U1024::ONE {
                    return Ok(self.composite());
                }
                self.square_at += 1;
                if self.square_at == self.powers_of_two {
                    return Ok(self.composite());
                }
                Ok(TestProgress::Advanced)
            }
            TestPhase::Passed => Ok(TestProgress::Passed),
            TestPhase::Composite => Ok(TestProgress::Composite),
        }
    }
}
impl Drop for PrimeTest {
    fn drop(&mut self) {
        // This count is derived from the selected secret factor, not merely
        // public work quota. Numeric secret owners erase their own storage.
        self.powers_of_two.zeroize();
        self.sieve.zeroize();
        self.rounds.zeroize();
        self.draws.zeroize();
        self.square_at.zeroize();
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Search,
    Assemble,
    Complete,
    Retired,
}
/// A real finite strong-prime-test search. Owns and erases every candidate,
/// accepted factor, private component and partially filled entropy buffer.
/// Primality is probabilistic with an explicit >=128-bit aggregate assurance
/// bound, not a mathematical certificate or a placeholder odd-number provider.
pub struct Keygen {
    limits: Limits,
    phase: Phase,
    candidates: u32,
    test: Option<PrimeTest>,
    p: Option<Zeroizing<U1024>>,
    q: Option<Zeroizing<U1024>>,
    result: Option<KeyPair>,
    failure: Option<Error>,
}
impl Keygen {
    /// Create original key-generation state; no entropy or arithmetic is executed.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            limits,
            phase: Phase::Search,
            candidates: 0,
            test: None,
            p: None,
            q: None,
            result: None,
            failure: None,
        })
    }
    fn draw_candidate(&mut self, entropy: &mut impl Entropy) -> Result<(), Error> {
        let count = self.candidates.checked_add(1).ok_or(Error::Capacity)?;
        if count > self.limits.candidates {
            return Err(Error::Capacity);
        }
        self.candidates = count;
        let mut bytes = Zeroizing::new([0u8; 128]);
        entropy.fill(bytes.as_mut()).map_err(Error::Entropy)?;
        // Two high bits give a genuine2048-bit product of two1024-bit factors;
        // the low bit is odd. The remaining1021 bits are actual caller entropy.
        bytes[0] |= 0xc0;
        bytes[127] |= 1;
        let candidate = Zeroizing::new(U1024::from_be_slice(bytes.as_ref()));
        self.test = Some(PrimeTest::new(candidate)?);
        Ok(())
    }
    fn search(&mut self, entropy: &mut impl Entropy) -> Result<(), Error> {
        let Some(test) = &mut self.test else {
            return self.draw_candidate(entropy);
        };
        match test.step(entropy, self.limits)? {
            TestProgress::Advanced => {}
            TestProgress::Composite => {
                self.test = None;
            }
            TestProgress::Passed => {
                let test = self.test.take().ok_or(Error::NotReady)?;
                let prime = Zeroizing::new(*test.candidate);
                if let Some(p) = &self.p {
                    if **p != *prime {
                        self.q = Some(prime);
                        self.phase = Phase::Assemble;
                    }
                } else {
                    self.p = Some(prime);
                }
            }
        }
        Ok(())
    }
    fn assemble(&mut self) -> Result<(), Error> {
        let p = self.p.as_ref().ok_or(Error::NotReady)?;
        let q = self.q.as_ref().ok_or(Error::NotReady)?;
        if **p == **q {
            return Err(Error::InvalidKey);
        }
        let n: U2048 = p.concatenating_mul(q);
        let pm1 = Zeroizing::new(p.wrapping_sub(&U1024::ONE));
        let qm1 = Zeroizing::new(q.wrapping_sub(&U1024::ONE));
        let lambda: Zeroizing<U2048> = Zeroizing::new(pm1.concatenating_mul(&qm1));
        let odd = Zeroizing::new(Odd::new(n).into_option().ok_or(Error::InvalidKey)?);
        let mu = Zeroizing::new(
            lambda
                .invert_odd_mod(&odd)
                .into_option()
                .ok_or(Error::InvalidKey)?,
        );
        let public = PublicKey::from_integer(n)?;
        self.result = Some(KeyPair {
            public,
            private: PrivateKey { n, lambda, mu },
        });
        self.p = None;
        self.q = None;
        self.test = None;
        self.phase = Phase::Complete;
        Ok(())
    }
    fn stop(&mut self, error: Error) -> Error {
        let original = *self.failure.get_or_insert(error);
        self.test = None;
        self.p = None;
        self.q = None;
        self.result = None;
        self.phase = Phase::Retired;
        original
    }
    /// Advance actual bounded search/primality/power/arithmetic units using only
    /// this entropy port. Random refusals consume the original finite budget.
    pub fn advance(&mut self, entropy: &mut impl Entropy, units: u16) -> Result<Progress, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.phase == Phase::Retired {
            return Err(Error::Finished);
        }
        if self.phase == Phase::Complete {
            return Ok(Progress::Ready);
        }
        let count = match self.limits.units(units) {
            Ok(count) => count,
            Err(error) => return Err(self.stop(error)),
        };
        for _ in 0..count {
            let result = match self.phase {
                Phase::Search => self.search(entropy),
                Phase::Assemble => self.assemble(),
                Phase::Complete => return Ok(Progress::Ready),
                Phase::Retired => return Err(Error::Finished),
            };
            if let Err(error) = result {
                return Err(self.stop(error));
            }
            if self.phase == Phase::Complete {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume exactly the actual generated pair, never an unfinished candidate.
    pub fn take_result(&mut self) -> Result<KeyPair, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.phase != Phase::Complete {
            return Err(if self.phase == Phase::Retired {
                Error::Finished
            } else {
                Error::NotReady
            });
        }
        let result = self.result.take().ok_or(Error::Finished)?;
        self.phase = Phase::Retired;
        Ok(result)
    }
    /// Erase all still-owned original candidates/factors/key material immediately.
    pub fn cancel(&mut self) {
        if self.phase != Phase::Retired {
            self.stop(Error::Cancelled);
        }
    }
}
