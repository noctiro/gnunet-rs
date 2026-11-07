use crate::{
    Element, Entropy, Error, Group, Limits, MembershipJob, Progress, Scalar, Subgroup,
    field::{G, P, Pow, Pow1, Q, Sampler, mul},
};
use crypto_bigint::{CtAssign, Limb, U1024};
use zeroize::{Zeroize, Zeroizing};

/// Owner-held canonical Zp plaintext, including zero and nonsubgroup residues.
/// It has no implicit formatting/cloning; exports belong to the caller.
pub struct Plaintext(pub(crate) Zeroizing<U1024>);
impl Plaintext {
    /// Import any original128-byte representative, reducing modulo p as the
    /// ordinary C encryption multiply does. No subgroup restriction is imposed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 128]) -> Self {
        let mut value = Zeroizing::new(U1024::from_be_slice(bytes));
        // P has its top bit set: every128-byte input is below2P. One fixed
        // subtraction and masked assignment therefore preserves exact modP
        // semantics without branching on this private representative.
        let (mut reduced, mut borrow) = value.borrowing_sub(&P, Limb::ZERO);
        value.ct_assign(&reduced, borrow.is_zero());
        reduced.zeroize();
        borrow.zeroize();
        Self(value)
    }
    /// Explicit export; this crate erases its own independent owner on drop.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 128]> {
        let encoded = Zeroizing::new(self.0.to_be_bytes());
        let mut out = Zeroizing::new([0; 128]);
        out.copy_from_slice(encoded.as_ref());
        out
    }
}
enum Magnitude<'a> {
    Borrowed(&'a [u8]),
    Owned(Zeroizing<[u8; 8]>),
}
impl Magnitude<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(b) => b,
            Self::Owned(b) => b.as_ref(),
        }
    }
}
/// Original exponent-to-plaintext job. It first reduces an arbitrary immutable
/// signed magnitude modulo q, one input byte per step, then computes g^x.
pub struct PlaintextGenerate<'a> {
    group: Group,
    limits: Limits,
    input: Option<Magnitude<'a>>,
    at: usize,
    negative: bool,
    exponent: Option<Zeroizing<U1024>>,
    pow: Option<Pow1>,
    result: Option<Plaintext>,
    failure: Option<Error>,
    taken: bool,
}
impl<'a> PlaintextGenerate<'a> {
    /// Pin the caller's immutable original exponent for this job's lifetime.
    /// Its explicit finite byte cap is the selected retained-input budget;
    /// no secret MPI or pointer is stored outside the Rust borrow.
    pub fn from_signed_bytes(
        group: &Group,
        magnitude: &'a [u8],
        negative: bool,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if magnitude.len() > limits.retained_bytes {
            return Err(Error::Capacity);
        }
        Ok(Self {
            group: group.clone(),
            limits,
            input: Some(Magnitude::Borrowed(magnitude)),
            at: 0,
            negative,
            exponent: Some(Zeroizing::new(U1024::ZERO)),
            pow: None,
            result: None,
            failure: None,
            taken: false,
        })
    }
    /// Generate the public API's g^exponent, handling i64::MIN without negating
    /// it in signed arithmetic or invoking the fixed C overflow.
    pub fn from_i64(group: &Group, exponent: i64, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            group: group.clone(),
            limits,
            input: Some(Magnitude::Owned(Zeroizing::new(
                exponent.unsigned_abs().to_be_bytes(),
            ))),
            at: 0,
            negative: exponent < 0,
            exponent: Some(Zeroizing::new(U1024::ZERO)),
            pow: None,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self) -> Result<(), Error> {
        if let Some(input) = &self.input {
            if self.at < input.bytes().len() {
                let x = self.exponent.as_ref().ok_or(Error::NotReady)?;
                let shifted = self.group.mul_q(x, &U1024::from_u32(256));
                let next = self.group.add_q(
                    &shifted,
                    &U1024::from_u32(u32::from(input.bytes()[self.at])),
                );
                self.exponent = Some(next);
                self.at += 1;
                return Ok(());
            }
            let mut x = self.exponent.take().ok_or(Error::NotReady)?;
            if self.negative && *x != U1024::ZERO {
                *x = Q.wrapping_sub(&x)
            }
            self.pow = Some(Pow::new(&G, &x, 1024, &self.group.p)?);
            self.input = None;
            return Ok(());
        }
        let pow = self.pow.as_mut().ok_or(Error::NotReady)?;
        if pow.step() {
            let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
            self.result = Some(Plaintext(value));
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.input = None;
        self.exponent = None;
        self.pow = None;
        self.result = None;
        e
    }
    /// Consume at most units original bytes/exponent bits; no entropy is used.
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
    /// Consume the actually completed original plaintext once.
    pub fn take_result(&mut self) -> Result<Plaintext, Error> {
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
    /// Erase job-owned magnitude/exponent/power/result; borrowed input remains
    /// the caller's separate erasure responsibility.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
/// Exact original c1||c2 ciphertext. c1 is an actual subgroup member while c2
/// retains arbitrary canonical Zp, including zero and nonsubgroup elements.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ciphertext {
    pub(crate) c1: Subgroup,
    pub(crate) c2: Element,
    raw: [u8; 256],
}
impl Ciphertext {
    /// Compose only an already checked c1 with a canonical c2.
    #[must_use]
    pub fn new(c1: Subgroup, c2: Element) -> Self {
        let mut raw = [0; 256];
        raw[..128].copy_from_slice(&c1.to_bytes());
        raw[128..].copy_from_slice(&c2.to_bytes());
        Self { c1, c2, raw }
    }
    /// Original first multiplicative component.
    #[must_use]
    pub const fn c1(self) -> Subgroup {
        self.c1
    }
    /// Original unrestricted second residue.
    #[must_use]
    pub const fn c2(self) -> Element {
        self.c2
    }
    /// Exact public256-byte original ciphertext. Arithmetic uses residues;
    /// signatures/challenges and operation equality retain the original bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 256] {
        self.raw
    }
}
/// Real cooperative wire admission, with no parser flag standing in for c1
/// subgroup validation.
pub struct CiphertextCheck {
    membership: MembershipJob,
    c2: Element,
    raw: [u8; 256],
    taken: bool,
}
impl CiphertextCheck {
    /// Preserve both original representatives; reduce for arithmetic and begin
    /// actual c1 validation. c2 is not subjected to a subgroup test.
    pub fn new(bytes: &[u8; 256], group: &Group, limits: Limits) -> Result<Self, Error> {
        let c1 = Element::reduce_bytes(bytes[..128].try_into().map_err(|_| Error::InvalidInput)?);
        let c2 = Element::reduce_bytes(bytes[128..].try_into().map_err(|_| Error::InvalidInput)?);
        Ok(Self {
            membership: MembershipJob::new(c1, group, limits)?,
            c2,
            raw: *bytes,
            taken: false,
        })
    }
    /// Advance actual c1 membership under the original work cap.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        self.membership.advance(units)
    }
    /// Consume the original checked ciphertext, never a substituted pair.
    pub fn take_result(&mut self) -> Result<Ciphertext, Error> {
        if self.taken {
            return Err(Error::Finished);
        }
        let c1 = self.membership.take_result()?;
        self.taken = true;
        Ok(Ciphertext {
            c1,
            c2: self.c2,
            raw: self.raw,
        })
    }
    /// Retire actual original work.
    pub fn cancel(&mut self) {
        self.membership.cancel();
    }
}
/// Actual ElGamal encryption, with an owned original plaintext/key snapshot and
/// explicit entropy. No ciphertext is available before both powers complete.
pub struct EncryptJob {
    group: Group,
    limits: Limits,
    key: Subgroup,
    message: Option<Plaintext>,
    nonce: Option<Scalar>,
    sampler: Sampler,
    pow: Option<Pow1>,
    c1: Option<Subgroup>,
    result: Option<Ciphertext>,
    failure: Option<Error>,
    taken: bool,
}
impl EncryptJob {
    /// Pin one actual public group key and transfer the original secret message.
    pub fn new(
        key: Subgroup,
        message: Plaintext,
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            group: group.clone(),
            limits,
            key,
            message: Some(message),
            nonce: None,
            sampler: Sampler::new(limits),
            pow: None,
            c1: None,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self, entropy: &mut impl Entropy) -> Result<(), Error> {
        if self.pow.is_none() {
            let Some(nonce) = self.sampler.step(entropy)? else {
                return Ok(());
            };
            self.pow = Some(Pow::new(&G, &nonce.0, 1024, &self.group.p)?);
            self.nonce = Some(nonce);
            return Ok(());
        }
        if !self.pow.as_mut().ok_or(Error::NotReady)?.step() {
            return Ok(());
        }
        let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
        if self.c1.is_none() {
            self.c1 = Some(Subgroup(*value));
            let nonce = self.nonce.take().ok_or(Error::NotReady)?;
            self.pow = Some(Pow::new(&self.key.0, &nonce.0, 1024, &self.group.p)?);
            return Ok(());
        }
        let message = self.message.take().ok_or(Error::NotReady)?;
        let c2 = *mul(&value, &message.0, &self.group.p);
        self.result = Some(Ciphertext::new(
            self.c1.take().ok_or(Error::NotReady)?,
            Element(c2),
        ));
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.message = None;
        self.nonce = None;
        self.pow = None;
        self.result = None;
        e
    }
    /// One entropy draw or exponent bit per unit; partial failed fills and all
    /// job-owned secret state are erased before the exact error is returned.
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
    /// Consume exactly the original completed c1/c2 pair.
    pub fn take_result(&mut self) -> Result<Ciphertext, Error> {
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
    /// Retire original secret encryption work without a result.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
