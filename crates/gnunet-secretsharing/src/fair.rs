//! Exact original fair-encryption transcript and real equation checks.
//!
//! These checks do NOT turn the inconsistent pinned producer into a proven
//! general-purpose fair-encryption NIZK. In particular this module exposes no
//! VerifiedFairProof or fake producer. The missing response-range construction
//! is an explicit unfinished interoperability/security requirement.
use crate::{
    Element, Error, Group, Limits, Progress, Subgroup,
    field::{G, Pow, Pow1, Q, mul},
};
use crypto_bigint::{Odd, U1024, U2048, U4096, modular::FixedMontyParams, nlimbs};
use gnunet_crypto::hash512;
use gnunet_paillier::{Ciphertext, PublicKey};
use gnunet_wire::official::secretsharing::{FAIR_ENCRYPTION_BYTES, FairEncryption};

type Params4 = FixedMontyParams<{ nlimbs(4096) }>;
type Pow4 = Pow<{ nlimbs(4096) }>;
/// Original fields whose unit/membership and two public equations really held.
/// This is explicitly not a fairness/knowledge/range/DKG certificate.
pub struct FairEquationResult {
    modulus: [u8; 256],
    cipher: Ciphertext,
    h: Subgroup,
}
impl FairEquationResult {
    /// Exact original Paillier modulus, not a later key/configuration view.
    #[must_use]
    pub const fn modulus(&self) -> &[u8; 256] {
        &self.modulus
    }
    /// Exact original Paillier ciphertext including its signed count.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext {
        &self.cipher
    }
    /// Actually subgroup-checked original h=g^x claim; no knowledge is certified.
    #[must_use]
    pub const fn h(&self) -> Subgroup {
        self.h
    }
}
/// Bounded exact-transcript arithmetic checker for
/// g^z=t1*h^e modp and (1+n)^z*w^n=t2*c^e modn².
/// e is SHA512(c516||h128||t1_128||t2_512), interpreted BE; it is already below q.
pub struct FairEquationCheck {
    group: Group,
    limits: Limits,
    modulus: [u8; 256],
    n: U2048,
    square: U4096,
    params: Params4,
    cipher: Option<Ciphertext>,
    c: U4096,
    h: U1024,
    t1: U1024,
    t2: U4096,
    z: U1024,
    w: U2048,
    e: U1024,
    phase: u8,
    pow1: Option<Pow1>,
    pow4: Option<Pow4>,
    left1: Option<U1024>,
    left4: Option<U4096>,
    result: Option<FairEquationResult>,
    failure: Option<Error>,
    taken: bool,
}
impl FairEquationCheck {
    /// Pin one exact original public modulus and complete proof. No signature,
    /// roster choice, challenge truncation, C undefined read or fallback occurs.
    pub fn new(
        key: &PublicKey,
        proof: &[u8; FAIR_ENCRYPTION_BYTES],
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let fields = FairEncryption::decode(proof).map_err(Error::Source)?;
        let modulus = key.to_bytes();
        let n = U2048::from_be_slice(&modulus);
        let square: U4096 = n.concatenating_square();
        let params = Params4::new(Odd::new(square).into_option().ok_or(Error::InvalidInput)?);
        let cipher = Ciphertext::from_wire(*fields.ciphertext().map_err(Error::Source)?);
        let raw = cipher.to_wire();
        let c = U4096::from_be_slice(&raw[4..]);
        let h = Element::from_bytes(fields.h().map_err(Error::Source)?)?.0;
        let t1 = Element::from_bytes(fields.t1().map_err(Error::Source)?)?.0;
        let t2 = U4096::from_be_slice(fields.t2().map_err(Error::Source)?);
        let z = U1024::from_be_slice(fields.z().map_err(Error::Source)?);
        let w = U2048::from_be_slice(fields.w().map_err(Error::Source)?);
        if c == U4096::ZERO
            || c >= square
            || t2 == U4096::ZERO
            || t2 >= square
            || h == U1024::ZERO
            || t1 == U1024::ZERO
            || w == U2048::ZERO
            || w >= n
        {
            return Err(Error::InvalidProof);
        }
        let digest = hash512(&proof[..1284]);
        let mut padded = [0; 128];
        padded[64..].copy_from_slice(&digest);
        let e = U1024::from_be_slice(&padded);
        Ok(Self {
            group: group.clone(),
            limits,
            modulus,
            n,
            square,
            params,
            cipher: Some(cipher),
            c,
            h,
            t1,
            t2,
            z,
            w,
            e,
            phase: 0,
            pow1: None,
            pow4: None,
            left1: None,
            left4: None,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self) -> Result<(), Error> {
        match self.phase {
            0 => {
                if self.c.gcd(&self.square) != U4096::ONE {
                    return Err(Error::InvalidProof);
                }
                self.phase = 1;
            }
            1 => {
                if self.t2.gcd(&self.square) != U4096::ONE {
                    return Err(Error::InvalidProof);
                }
                self.phase = 2;
            }
            2 => {
                if self.w.gcd(&self.n) != U2048::ONE {
                    return Err(Error::InvalidProof);
                }
                self.pow1 = Some(Pow::new(&self.h, &Q, 1024, &self.group.p)?);
                self.phase = 3;
            }
            3 => {
                if self.pow1.as_mut().ok_or(Error::NotReady)?.step() {
                    let member = self.pow1.take().ok_or(Error::NotReady)?.finish()?;
                    if *member != U1024::ONE {
                        return Err(Error::InvalidProof);
                    }
                    self.pow1 = Some(Pow::new(&self.t1, &Q, 1024, &self.group.p)?);
                    self.phase = 4;
                }
            }
            4 => {
                if self.pow1.as_mut().ok_or(Error::NotReady)?.step() {
                    let member = self.pow1.take().ok_or(Error::NotReady)?.finish()?;
                    if *member != U1024::ONE {
                        return Err(Error::InvalidProof);
                    }
                    self.pow1 = Some(Pow::new(&G, &self.z, 1024, &self.group.p)?);
                    self.phase = 5;
                }
            }
            5 => {
                if self.pow1.as_mut().ok_or(Error::NotReady)?.step() {
                    let left = self.pow1.take().ok_or(Error::NotReady)?.finish()?;
                    self.left1 = Some(*left);
                    self.pow1 = Some(Pow::new(&self.h, &self.e, 512, &self.group.p)?);
                    self.phase = 6;
                }
            }
            6 => {
                if self.pow1.as_mut().ok_or(Error::NotReady)?.step() {
                    let power = self.pow1.take().ok_or(Error::NotReady)?.finish()?;
                    let right = mul(&self.t1, &power, &self.group.p);
                    if Some(*right) != self.left1 {
                        return Err(Error::InvalidProof);
                    }
                    self.left1 = None;
                    let base: U4096 = self.n.resize();
                    let base = base.wrapping_add(&U4096::ONE);
                    let exponent: U4096 = self.z.resize();
                    self.pow4 = Some(Pow::new(&base, &exponent, 1024, &self.params)?);
                    self.phase = 7;
                }
            }
            7 => {
                if self.pow4.as_mut().ok_or(Error::NotReady)?.step() {
                    let left = self.pow4.take().ok_or(Error::NotReady)?.finish()?;
                    self.left4 = Some(*left);
                    let base: U4096 = self.w.resize();
                    let exponent: U4096 = self.n.resize();
                    self.pow4 = Some(Pow::new(&base, &exponent, 2048, &self.params)?);
                    self.phase = 8;
                }
            }
            8 => {
                if self.pow4.as_mut().ok_or(Error::NotReady)?.step() {
                    let random = self.pow4.take().ok_or(Error::NotReady)?.finish()?;
                    let previous = self.left4.take().ok_or(Error::NotReady)?;
                    self.left4 = Some(*mul(&previous, &random, &self.params));
                    let exponent: U4096 = self.e.resize();
                    self.pow4 = Some(Pow::new(&self.c, &exponent, 512, &self.params)?);
                    self.phase = 9;
                }
            }
            9 => {
                if self.pow4.as_mut().ok_or(Error::NotReady)?.step() {
                    let power = self.pow4.take().ok_or(Error::NotReady)?.finish()?;
                    let right = mul(&self.t2, &power, &self.params);
                    if Some(*right) != self.left4 {
                        return Err(Error::InvalidProof);
                    }
                    self.left4 = None;
                    self.result = Some(FairEquationResult {
                        modulus: self.modulus,
                        cipher: self.cipher.take().ok_or(Error::NotReady)?,
                        h: Subgroup(self.h),
                    });
                    self.phase = 10;
                }
            }
            _ => return Err(Error::NotReady),
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.pow1 = None;
        self.pow4 = None;
        self.cipher = None;
        self.result = None;
        e
    }
    /// Each unit performs one fixed-size public GCD or exponent bit. GCD is a
    /// fixed4096/2048-bit bounded public primitive, not secret-dependent work.
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
            if let Err(e) = self.step() {
                return Err(self.fail(e));
            }
            if self.result.is_some() {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume actual equation results once, without calling them a fair proof.
    pub fn take_result(&mut self) -> Result<FairEquationResult, Error> {
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
    /// Retire the original arithmetic checker, never synthesize acceptance.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
