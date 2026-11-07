//! Checked construction for the original fixed FAIR transcript.
//!
//! The original1024-bit response cannot represent general legal shares under
//! this construction. Such an attempt returns the actual TooLarge error; it
//! never reduces z modulo q, truncates it, biases the share or retries a new
//! challenge. A completed transcript is not a general knowledge/range certificate.
use crate::{
    Entropy, Error, Group, Limits, Progress, Scalar,
    field::{G, Pow, Pow1, Q, encode, mul},
};
use crypto_bigint::{NonZero, Odd, U1024, U2048, U4096, modular::FixedMontyParams, nlimbs};
use gnunet_crypto::hash512_parts;
use gnunet_paillier::{EncryptWithWitnessJob, PublicKey};
use gnunet_wire::official::secretsharing::{FAIR_ENCRYPTION_BYTES, FairEncryptionFields};
use zeroize::{Zeroize, Zeroizing};

type Params2 = FixedMontyParams<{ nlimbs(2048) }>;
type Params4 = FixedMontyParams<{ nlimbs(4096) }>;
type Pow2 = Pow<{ nlimbs(2048) }>;
type Pow4 = Pow<{ nlimbs(4096) }>;

struct Secrets {
    share: Scalar,
    nonce: Zeroizing<U2048>,
    beta: Zeroizing<U2048>,
    s: Zeroizing<U2048>,
}
struct Fields {
    ciphertext: [u8; 516],
    h: [u8; 128],
    t1: [u8; 128],
    t2: [u8; 512],
    z: [u8; 128],
    w: [u8; 256],
}
impl Fields {
    fn empty() -> Self {
        Self {
            ciphertext: [0; 516],
            h: [0; 128],
            t1: [0; 128],
            t2: [0; 512],
            z: [0; 128],
            w: [0; 256],
        }
    }
    fn as_wire(&self) -> FairEncryptionFields<'_> {
        FairEncryptionFields {
            ciphertext: &self.ciphertext,
            h: &self.h,
            t1: &self.t1,
            t2: &self.t2,
            z: &self.z,
            w: &self.w,
        }
    }
    fn clear(&mut self) {
        self.ciphertext.zeroize();
        self.h.zeroize();
        self.t1.zeroize();
        self.t2.zeroize();
        self.z.zeroize();
        self.w.zeroize();
    }
}
#[expect(
    clippy::large_enum_variant,
    reason = "Exclusive inline jobs reuse fixed owner storage without a heap allocation per arithmetic stage"
)]
enum Work {
    Encrypt(EncryptWithWitnessJob),
    Beta,
    Randomizer { attempts: u32 },
    H(Pow1),
    T1(Pow1),
    T2(Pow4),
    W(Pow2),
    Ready,
    Closed,
}

/// Actual canonical-share construction with explicit entropy and bounded work.
/// The same actual Paillier randomizer is retained for the response. Normal
/// encryption never exposes or retains it through this adapter by accident.
pub struct FairProver {
    group: Group,
    limits: Limits,
    modulus: [u8; 256],
    n: U2048,
    square: U4096,
    params2: Params2,
    params4: Params4,
    secrets: Option<Secrets>,
    fields: Fields,
    work: Work,
    failure: Option<Error>,
    taken: bool,
}
impl FairProver {
    /// Consume the actual scalar and pin the original recipient key. No entropy
    /// or proof generation occurs in the constructor, and the share is not
    /// replaced by a smaller representative to satisfy the wire response width.
    pub fn new(
        share: Scalar,
        key: &PublicKey,
        group: &Group,
        limits: Limits,
        paillier: gnunet_paillier::Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        paillier.validate()?;
        let modulus = key.to_bytes();
        let n = U2048::from_be_slice(&modulus);
        let square = n.concatenating_square();
        let params2 = Params2::new(Odd::new(n).into_option().ok_or(Error::InvalidInput)?);
        let params4 = Params4::new(Odd::new(square).into_option().ok_or(Error::InvalidInput)?);
        let raw = share.to_bytes();
        let plaintext = key.plaintext(raw.as_ref())?;
        // The official FAIR ciphertext counter is zero, and participates in e.
        let encrypt = key.encrypt_with_witness(plaintext, 0, paillier)?;
        Ok(Self {
            group: group.clone(),
            limits,
            modulus,
            n,
            square,
            params2,
            params4,
            secrets: Some(Secrets {
                share,
                nonce: Zeroizing::new(U2048::ZERO),
                beta: Zeroizing::new(U2048::ZERO),
                s: Zeroizing::new(U2048::ZERO),
            }),
            fields: Fields::empty(),
            work: Work::Encrypt(encrypt),
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self, entropy: &mut impl Entropy) -> Result<(), Error> {
        match &mut self.work {
            Work::Encrypt(job) => {
                if job.advance(entropy, 1)? == gnunet_paillier::Progress::Ready {
                    let witness = job.take_result()?;
                    if witness.modulus() != &self.modulus {
                        return Err(Error::InvalidInput);
                    }
                    let (ciphertext, nonce) = witness.into_parts();
                    self.fields.ciphertext = ciphertext.to_wire();
                    self.secrets.as_mut().ok_or(Error::NotReady)?.nonce =
                        Zeroizing::new(U2048::from_be_slice(nonce.as_ref()));
                    self.work = Work::Beta;
                }
            }
            Work::Beta => {
                let mut bytes = Zeroizing::new([0; 256]);
                entropy.fill(bytes.as_mut()).map_err(Error::Source)?;
                // Preserve the original2048-bit beta draw in full. Reduction is
                // used only in group arithmetic, never in the integer response.
                self.secrets.as_mut().ok_or(Error::NotReady)?.beta =
                    Zeroizing::new(U2048::from_be_slice(bytes.as_ref()));
                self.work = Work::Randomizer { attempts: 0 };
            }
            Work::Randomizer { attempts } => {
                *attempts = attempts.checked_add(1).ok_or(Error::Capacity)?;
                if *attempts > self.limits.rejections {
                    return Err(Error::Capacity);
                }
                let mut bytes = Zeroizing::new([0; 256]);
                entropy.fill(bytes.as_mut()).map_err(Error::Source)?;
                let value = Zeroizing::new(U2048::from_be_slice(bytes.as_ref()));
                if *value == U2048::ZERO || *value >= self.n {
                    return Ok(());
                }
                let gcd = Zeroizing::new(value.gcd(&self.n));
                if *gcd != U2048::ONE {
                    return Ok(());
                }
                let secrets = self.secrets.as_mut().ok_or(Error::NotReady)?;
                secrets.s = value;
                self.work = Work::H(Pow::new(&G, &secrets.share.0, 1024, &self.group.p)?);
            }
            Work::H(job) => {
                if job.step() {
                    let Work::H(job) = core::mem::replace(&mut self.work, Work::Closed) else {
                        return Err(Error::NotReady);
                    };
                    self.fields.h = encode(&*job.finish()?);
                    let secrets = self.secrets.as_ref().ok_or(Error::NotReady)?;
                    let q = NonZero::new(Q.resize::<{ nlimbs(2048) }>())
                        .into_option()
                        .ok_or(Error::InvalidInput)?;
                    let division = Zeroizing::new(secrets.beta.div_rem(&q));
                    let exponent: Zeroizing<U1024> = Zeroizing::new(division.1.resize());
                    self.work = Work::T1(Pow::new(&G, &exponent, 1024, &self.group.p)?);
                }
            }
            Work::T1(job) => {
                if job.step() {
                    let Work::T1(job) = core::mem::replace(&mut self.work, Work::Closed) else {
                        return Err(Error::NotReady);
                    };
                    self.fields.t1 = encode(&*job.finish()?);
                    let base: Zeroizing<U4096> =
                        Zeroizing::new(self.secrets.as_ref().ok_or(Error::NotReady)?.s.resize());
                    let exponent = self.n.resize();
                    self.work = Work::T2(Pow::new(&base, &exponent, 2048, &self.params4)?);
                }
            }
            Work::T2(job) => {
                if job.step() {
                    let Work::T2(job) = core::mem::replace(&mut self.work, Work::Closed) else {
                        return Err(Error::NotReady);
                    };
                    let random = job.finish()?;
                    let secrets = self.secrets.as_ref().ok_or(Error::NotReady)?;
                    let n = NonZero::new(self.n)
                        .into_option()
                        .ok_or(Error::InvalidInput)?;
                    let division = Zeroizing::new(secrets.beta.div_rem(&n));
                    // Exact binomial identity; beta itself is retained unchanged.
                    let gm = Zeroizing::new(
                        self.n
                            .concatenating_mul(&division.1)
                            .wrapping_add(&U4096::ONE),
                    );
                    if *gm >= self.square {
                        return Err(Error::InvalidInput);
                    }
                    let t2 = mul(&gm, &random, &self.params4);
                    self.fields.t2.copy_from_slice(t2.to_be_bytes().as_ref());
                    let digest = hash512_parts(&[
                        &self.fields.ciphertext,
                        &self.fields.h,
                        &self.fields.t1,
                        &self.fields.t2,
                    ]);
                    let mut padded = [0; 256];
                    padded[192..].copy_from_slice(&digest);
                    let e = U2048::from_be_slice(&padded);
                    self.fields.z = checked_response(&secrets.beta, &e, &secrets.share)?;
                    self.work = Work::W(Pow::new(&secrets.nonce, &e, 512, &self.params2)?);
                }
            }
            Work::W(job) => {
                if job.step() {
                    let Work::W(job) = core::mem::replace(&mut self.work, Work::Closed) else {
                        return Err(Error::NotReady);
                    };
                    let power = job.finish()?;
                    let value = mul(
                        &power,
                        &self.secrets.as_ref().ok_or(Error::NotReady)?.s,
                        &self.params2,
                    );
                    self.fields.w.copy_from_slice(value.to_be_bytes().as_ref());
                    self.secrets = None;
                    self.work = Work::Ready;
                }
            }
            Work::Ready | Work::Closed => return Err(Error::NotReady),
        }
        Ok(())
    }
    fn fail(&mut self, error: Error) -> Error {
        let error = *self.failure.get_or_insert(error);
        if let Work::Encrypt(job) = &mut self.work {
            job.cancel();
        }
        self.work = Work::Closed;
        self.secrets = None;
        self.fields.clear();
        error
    }
    /// Advance at most the requested actual sampling, fixed arithmetic or
    /// exponent-bit units. The original entropy/profile refusal is sticky.
    pub fn advance(&mut self, entropy: &mut impl Entropy, units: u16) -> Result<Progress, Error> {
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
        if matches!(self.work, Work::Ready) {
            return Ok(Progress::Ready);
        }
        for _ in 0..units {
            if let Err(error) = self.step(entropy) {
                return Err(self.fail(error));
            }
            if matches!(self.work, Work::Ready) {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Return only the complete original1668-byte transcript, exactly once.
    /// No VerifiedFairProof, range certificate or native write is fabricated.
    pub fn take_result(&mut self) -> Result<[u8; FAIR_ENCRYPTION_BYTES], Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if !matches!(self.work, Work::Ready) {
            return Err(Error::NotReady);
        }
        let mut output = [0; FAIR_ENCRYPTION_BYTES];
        self.fields
            .as_wire()
            .encode(&mut output)
            .map_err(Error::Source)?;
        self.fields.clear();
        self.work = Work::Closed;
        self.taken = true;
        Ok(output)
    }
    /// Retire the original attempt and erase all secret nonce/share/power state.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
impl Drop for FairProver {
    fn drop(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}

fn checked_response(beta: &U2048, challenge: &U2048, share: &Scalar) -> Result<[u8; 128], Error> {
    // Actual widths: beta2048, challenge512, canonical x1023. The full product
    // and sum fit4096 bits, so this addition never wraps. No mod-q reduction.
    let x: Zeroizing<U2048> = Zeroizing::new(share.0.resize());
    let product = Zeroizing::new(challenge.concatenating_mul(&x));
    let beta: Zeroizing<U4096> = Zeroizing::new(beta.resize());
    let response = Zeroizing::new(product.wrapping_add(&beta));
    if response.bits() > 1024 {
        return Err(Error::Source(gnunet_types::Error::TooLarge));
    }
    let narrow: Zeroizing<U1024> = Zeroizing::new(response.resize());
    Ok(encode(&narrow))
}

#[cfg(test)]
mod tests;
