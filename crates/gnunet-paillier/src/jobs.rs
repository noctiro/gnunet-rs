//! Caller-driven original encryption/decryption jobs, with secret state ownership.
use crate::{
    Ciphertext, Entropy, Error, Limits, Plaintext, PrivateKey, Progress, PublicKey, U2048, U4096,
    pow::Pow,
};
use crypto_bigint::{
    NonZero, Odd,
    modular::{FixedMontyForm, FixedMontyParams},
    nlimbs,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Sample,
    Power,
    Complete,
    Retired,
}
/// Exact completed encryption and its actual uniformly sampled unit randomizer.
/// The randomizer is secret proof material: it is never cloned or formatted and
/// is erased unless explicitly transferred into the caller's zeroizing owner.
pub struct EncryptionWitness {
    modulus: [u8; 256],
    ciphertext: Ciphertext,
    randomizer: Zeroizing<[u8; 256]>,
}
impl EncryptionWitness {
    /// Original public modulus used for this ciphertext and randomizer.
    #[must_use]
    pub const fn modulus(&self) -> &[u8; 256] {
        &self.modulus
    }
    /// Actual completed ciphertext, with its unchanged original operation count.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }
    /// Transfer the ciphertext and the exact secret unit randomizer once. The
    /// caller retains responsibility for the returned zeroizing witness owner.
    #[must_use]
    pub fn into_parts(self) -> (Ciphertext, Zeroizing<[u8; 256]>) {
        (self.ciphertext, self.randomizer)
    }
}

// Retention changes only ownership of the one actual sampled unit. Both public
// jobs use this same sampling, encryption, bounded power and retirement engine.
trait Retention {
    type Output;
    fn sampled(&mut self, randomizer: Zeroizing<U2048>);
    fn complete(&mut self, key: &PublicKey, ciphertext: Ciphertext) -> Result<Self::Output, Error>;
    fn clear(&mut self);
}
struct DiscardRandomizer;
impl Retention for DiscardRandomizer {
    type Output = Ciphertext;
    fn sampled(&mut self, _randomizer: Zeroizing<U2048>) {}
    fn complete(
        &mut self,
        _key: &PublicKey,
        ciphertext: Ciphertext,
    ) -> Result<Self::Output, Error> {
        Ok(ciphertext)
    }
    fn clear(&mut self) {}
}
struct RetainRandomizer {
    randomizer: Option<Zeroizing<U2048>>,
}
impl Retention for RetainRandomizer {
    type Output = EncryptionWitness;
    fn sampled(&mut self, randomizer: Zeroizing<U2048>) {
        self.randomizer = Some(randomizer);
    }
    fn complete(&mut self, key: &PublicKey, ciphertext: Ciphertext) -> Result<Self::Output, Error> {
        let integer = self.randomizer.take().ok_or(Error::NotReady)?;
        let encoded = Zeroizing::new(integer.to_be_bytes());
        let mut randomizer = Zeroizing::new([0; 256]);
        randomizer.copy_from_slice(encoded.as_ref());
        Ok(EncryptionWitness {
            modulus: key.to_bytes(),
            ciphertext,
            randomizer,
        })
    }
    fn clear(&mut self) {
        self.randomizer = None;
    }
}
struct EncryptionCore<R: Retention> {
    key: PublicKey,
    limits: Limits,
    phase: Phase,
    attempts: u32,
    operations: i32,
    gm: Option<Zeroizing<U4096>>,
    pow: Option<Pow<{ nlimbs(4096) }>>,
    result: Option<R::Output>,
    retention: R,
    failure: Option<Error>,
}
impl<R: Retention> EncryptionCore<R> {
    fn new(
        key: &PublicKey,
        plaintext: Plaintext,
        desired: u32,
        limits: Limits,
        retention: R,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let operations = key.operations(&plaintext.0, desired)?;
        // Binomial identity (1+n)^m == 1+n*m mod n² for an actual Zn residue.
        let product: Zeroizing<U4096> = Zeroizing::new(key.n.concatenating_mul(&plaintext.0));
        let gm = Zeroizing::new(product.wrapping_add(&U4096::ONE));
        if *gm >= key.square {
            return Err(Error::Range);
        }
        Ok(Self {
            key: key.clone(),
            limits,
            phase: Phase::Sample,
            attempts: 0,
            operations,
            gm: Some(gm),
            pow: None,
            result: None,
            retention,
            failure: None,
        })
    }
    fn sample(&mut self, entropy: &mut impl Entropy) -> Result<(), Error> {
        let attempts = self.attempts.checked_add(1).ok_or(Error::Capacity)?;
        if attempts > self.limits.rejections {
            return Err(Error::Capacity);
        }
        self.attempts = attempts;
        let mut raw = Zeroizing::new([0u8; 256]);
        entropy.fill(raw.as_mut()).map_err(Error::Entropy)?;
        if self.key.n.bits() == 2047 {
            raw[0] &= 0x7f;
        }
        let r = Zeroizing::new(U2048::from_be_slice(raw.as_ref()));
        // Correct Paillier uses a uniformly sampled unit, never r=0 or a
        // noninvertible value. Rejection is bounded, never replaced by a constant.
        if *r == U2048::ZERO || *r >= self.key.n {
            return Ok(());
        }
        let gcd = Zeroizing::new(r.gcd(&self.key.n));
        if *gcd != U2048::ONE {
            return Ok(());
        }
        let base: Zeroizing<U4096> = Zeroizing::new(r.resize());
        let exponent: U4096 = self.key.n.resize();
        self.pow = Some(Pow::new(&base, &exponent, 2048, &self.key.params)?);
        self.retention.sampled(r);
        self.phase = Phase::Power;
        Ok(())
    }
    fn finish_power(&mut self) -> Result<(), Error> {
        let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
        let gm = self.gm.as_ref().ok_or(Error::Finished)?;
        let random = Zeroizing::new(FixedMontyForm::new(&value, &self.key.params));
        let message = Zeroizing::new(FixedMontyForm::new(gm, &self.key.params));
        let product = Zeroizing::new(random.mul(&message));
        let integer = Zeroizing::new(product.retrieve());
        let ciphertext = Ciphertext::from_integer(&integer, self.operations);
        self.result = Some(self.retention.complete(&self.key, ciphertext)?);
        self.gm = None;
        self.phase = Phase::Complete;
        Ok(())
    }
    fn stop(&mut self, error: Error) -> Error {
        let original = *self.failure.get_or_insert(error);
        self.pow = None;
        self.gm = None;
        self.result = None;
        self.retention.clear();
        self.phase = Phase::Retired;
        original
    }
    fn advance(&mut self, entropy: &mut impl Entropy, units: u16) -> Result<Progress, Error> {
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
                Phase::Sample => self.sample(entropy),
                Phase::Power => match self.pow.as_mut() {
                    Some(pow) => {
                        let complete = pow.step();
                        if complete {
                            self.finish_power()
                        } else {
                            Ok(())
                        }
                    }
                    None => Err(Error::NotReady),
                },
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
    fn take_result(&mut self) -> Result<R::Output, Error> {
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
    fn cancel(&mut self) {
        if self.phase != Phase::Retired {
            self.stop(Error::Cancelled);
        }
    }
}

/// Actual encryption of one owned secret residue. No background task or global
/// entropy exists. Cancellation/error/drop erases original message/nonce/power.
/// The ordinary job retains no separate sampled randomizer after its power starts.
pub struct EncryptJob {
    core: EncryptionCore<DiscardRandomizer>,
}
impl EncryptJob {
    pub(crate) fn new(
        key: &PublicKey,
        plaintext: Plaintext,
        desired: u32,
        limits: Limits,
    ) -> Result<Self, Error> {
        Ok(Self {
            core: EncryptionCore::new(key, plaintext, desired, limits, DiscardRandomizer)?,
        })
    }
    /// Advance at most the explicit number of original work units. Only nonce
    /// sampling calls this supplied entropy port, and partial failed fills erase.
    pub fn advance(&mut self, entropy: &mut impl Entropy, units: u16) -> Result<Progress, Error> {
        self.core.advance(entropy, units)
    }
    /// Consume only an actual completed original ciphertext, exactly once.
    pub fn take_result(&mut self) -> Result<Ciphertext, Error> {
        self.core.take_result()
    }
    /// Erase all still-owned original secret work, without returning a fake result.
    pub fn cancel(&mut self) {
        self.core.cancel();
    }
}

/// The same bounded encryption with an explicit owned witness result. The one
/// retained randomizer is the unit that actually formed the ciphertext; source
/// failure, cancellation and drop erase it along with unfinished secret work.
pub struct EncryptWithWitnessJob {
    core: EncryptionCore<RetainRandomizer>,
}
impl EncryptWithWitnessJob {
    pub(crate) fn new(
        key: &PublicKey,
        plaintext: Plaintext,
        desired: u32,
        limits: Limits,
    ) -> Result<Self, Error> {
        Ok(Self {
            core: EncryptionCore::new(
                key,
                plaintext,
                desired,
                limits,
                RetainRandomizer { randomizer: None },
            )?,
        })
    }
    /// Advance the same finite sampling and exponent-bit schedule as EncryptJob.
    pub fn advance(&mut self, entropy: &mut impl Entropy, units: u16) -> Result<Progress, Error> {
        self.core.advance(entropy, units)
    }
    /// Consume the actual original ciphertext and its secret unit witness once.
    pub fn take_result(&mut self) -> Result<EncryptionWitness, Error> {
        self.core.take_result()
    }
    /// Erase the original randomizer, power and any untaken witness result.
    pub fn cancel(&mut self) {
        self.core.cancel();
    }
}

/// Actual original decryption with an owned, zeroizing mathematical key
/// snapshot. The containing protocol must explicitly cancel it on authority
/// retirement; replacing a key never rebinds already admitted arithmetic.
pub struct DecryptJob {
    mu: Zeroizing<U2048>,
    public: PublicKey,
    limits: Limits,
    pow: Option<Pow<{ nlimbs(4096) }>>,
    result: Option<Plaintext>,
    ready: bool,
    taken: bool,
    failure: Option<Error>,
}
impl DecryptJob {
    pub(crate) fn new(
        private: &PrivateKey,
        public: &PublicKey,
        cipher: &Ciphertext,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if private.n != public.n {
            return Err(Error::InvalidKey);
        }
        let c = Zeroizing::new(public.validate_cipher(cipher)?);
        let exponent: Zeroizing<U4096> = Zeroizing::new(private.lambda.resize());
        let pow = Pow::new(&c, &exponent, 2048, &public.params)?;
        Ok(Self {
            mu: Zeroizing::new(*private.mu),
            public: public.clone(),
            limits,
            pow: Some(pow),
            result: None,
            ready: false,
            taken: false,
            failure: None,
        })
    }
    fn finish_power(&mut self) -> Result<(), Error> {
        let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
        if *value == U4096::ZERO {
            return Err(Error::InvalidCipher);
        }
        let numerator = Zeroizing::new(value.wrapping_sub(&U4096::ONE));
        let divisor = Zeroizing::new(
            NonZero::new(self.public.n)
                .into_option()
                .ok_or(Error::InvalidKey)?,
        );
        let (quotient, remainder) = numerator.div_rem(&divisor);
        let quotient = Zeroizing::new(quotient);
        let remainder = Zeroizing::new(remainder);
        if *remainder != U2048::ZERO || *quotient >= self.public.n.resize() {
            return Err(Error::InvalidCipher);
        }
        let reduced: Zeroizing<U2048> = Zeroizing::new(quotient.resize());
        let modulus = Zeroizing::new(
            Odd::new(self.public.n)
                .into_option()
                .ok_or(Error::InvalidKey)?,
        );
        let params = Zeroizing::new(FixedMontyParams::new(*modulus));
        let value = Zeroizing::new(FixedMontyForm::new(&reduced, &params));
        let mu = Zeroizing::new(FixedMontyForm::new(&self.mu, &params));
        let product = Zeroizing::new(value.mul(&mu));
        self.result = Some(Plaintext(Zeroizing::new(product.retrieve())));
        self.mu.zeroize();
        self.ready = true;
        Ok(())
    }
    fn stop(&mut self, error: Error) -> Error {
        let original = *self.failure.get_or_insert(error);
        self.pow = None;
        self.mu.zeroize();
        self.result = None;
        self.ready = false;
        original
    }
    /// Advance a bounded number of constant-pattern private exponent bits.
    /// No fresh entropy, source, allocation or native operation occurs here.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.ready {
            return Ok(Progress::Ready);
        }
        let count = match self.limits.units(units) {
            Ok(count) => count,
            Err(error) => return Err(self.stop(error)),
        };
        for _ in 0..count {
            let complete = match self.pow.as_mut() {
                Some(pow) => pow.step(),
                None => return Err(self.stop(Error::NotReady)),
            };
            if complete {
                if let Err(error) = self.finish_power() {
                    return Err(self.stop(error));
                }
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume only the actual reconstructed Zn plaintext, exactly once.
    pub fn take_result(&mut self) -> Result<Plaintext, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if !self.ready {
            return Err(Error::NotReady);
        }
        let result = self.result.take().ok_or(Error::Finished)?;
        self.taken = true;
        Ok(result)
    }
    /// Erase all retained secret exponentiation and plaintext on this original job.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.stop(Error::Cancelled);
        }
    }
}
