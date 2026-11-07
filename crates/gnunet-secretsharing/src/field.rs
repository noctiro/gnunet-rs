use crate::{Entropy, Error, Limits, Progress};
use crypto_bigint::{
    CtAssign, Odd, U1024, Uint,
    modular::{FixedMontyForm, FixedMontyParams},
    nlimbs,
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const P: U1024 = U1024::from_be_hex(
    "8a347d3d69e8b2dd7d1b12a08dfbccbebf4ca6f4269a0814e158a34312964d946b3ef228823172bcf30fc08f772774cb404f9bc002a6f66b09a79d810d67c4f8cb3bedc6060e3c8ef874b1b64df716c7d2b002da880e269438d5a776e6b5f253c8df56a16b1c7ce58def07c03db48238aadfc52a354a27ed285b0c1675cad3f3",
);
pub(crate) const Q: U1024 = U1024::from_be_hex(
    "451a3e9eb4f4596ebe8d895046fde65f5fa6537a134d040a70ac51a1894b26ca359f79144118b95e7987e047bb93ba65a027cde001537b3584d3cec086b3e27c659df6e303071e477c3a58db26fb8b63e958016d4407134a1c6ad3bb735af929e46fab50b58e3e72c6f783e01eda411c556fe2951aa513f6942d860b3ae569f9",
);
pub(crate) const G: U1024 = U1024::from_be_hex(
    "05c00c36d2e822950087ef09d8252994adc4e48fe3ec70269f035b46063aff0c99b633fd64df4302442e1914c829a41505a275438871f365e91c123d5303ef9e90f4b8cb89bf86cc9b513e74a726349cfd9f953674fab5d511e1c078fc72d72b34086fc82b4b951989eb85325cb203ff98df76bc366bba1d7024c3650f60d0da",
);
pub(crate) type Params = FixedMontyParams<{ nlimbs(1024) }>;

/// Fixed public parameters from the pinned GNUnet header. No custom group or
/// fallback algorithm can be selected by incoming wire bytes.
#[derive(Clone)]
pub struct Group {
    pub(crate) p: Params,
    pub(crate) q: Params,
}
impl Group {
    /// Construct public reusable Montgomery parameters; no entropy or heap.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            p: Params::new(Odd::new(P).into_option().ok_or(Error::InvalidInput)?),
            q: Params::new(Odd::new(Q).into_option().ok_or(Error::InvalidInput)?),
        })
    }
    /// Official prime modulus, encoded in the original128-byte BE field.
    #[must_use]
    pub fn modulus(&self) -> [u8; 128] {
        encode(&P)
    }
    /// Official subgroup order, encoded in the original128-byte BE field.
    #[must_use]
    pub fn order(&self) -> [u8; 128] {
        encode(&Q)
    }
    /// Official subgroup generator.
    #[must_use]
    pub const fn generator(&self) -> Subgroup {
        Subgroup(G)
    }
    pub(crate) fn mul_q(&self, a: &U1024, b: &U1024) -> Zeroizing<U1024> {
        mul(a, b, &self.q)
    }
    pub(crate) fn add_q(&self, a: &U1024, b: &U1024) -> Zeroizing<U1024> {
        let a = Zeroizing::new(FixedMontyForm::new(a, &self.q));
        let b = Zeroizing::new(FixedMontyForm::new(b, &self.q));
        let sum = Zeroizing::new(a.add(&b));
        Zeroizing::new(sum.retrieve())
    }
    #[cfg(feature = "alloc")]
    pub(crate) fn sub_q(&self, a: &U1024, b: &U1024) -> Zeroizing<U1024> {
        let a = Zeroizing::new(FixedMontyForm::new(a, &self.q));
        let b = Zeroizing::new(FixedMontyForm::new(b, &self.q));
        let difference = Zeroizing::new(a.sub(&b));
        Zeroizing::new(difference.retrieve())
    }
}
pub(crate) fn mul<const N: usize>(
    a: &Uint<N>,
    b: &Uint<N>,
    params: &FixedMontyParams<N>,
) -> Zeroizing<Uint<N>> {
    let a = Zeroizing::new(FixedMontyForm::new(a, params));
    let b = Zeroizing::new(FixedMontyForm::new(b, params));
    let product = Zeroizing::new(a.mul(&b));
    Zeroizing::new(product.retrieve())
}
pub(crate) fn encode(value: &U1024) -> [u8; 128] {
    let mut bytes = [0; 128];
    bytes.copy_from_slice(value.to_be_bytes().as_ref());
    bytes
}

/// Canonical arbitrary residue0<=x<p. This type deliberately does not imply
/// subgroup membership: ordinary plaintexts and ciphertext c2 may be any Zp
/// residue, including zero.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Element(pub(crate) U1024);
impl Element {
    /// Reduce any original128-byte representative modulo the fixed p. Since
    /// p is1024 bits, one subtraction suffices. This grants no membership.
    #[must_use]
    pub fn reduce_bytes(bytes: &[u8; 128]) -> Self {
        let mut x = U1024::from_be_slice(bytes);
        if x >= P {
            x = x.wrapping_sub(&P);
        }
        Self(x)
    }
    /// Admit a canonical fixed-width residue, without silently reducing bytes.
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Error> {
        let x = U1024::from_be_slice(bytes);
        if x >= P {
            return Err(Error::InvalidInput);
        }
        Ok(Self(x))
    }
    /// Original canonical bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 128] {
        encode(&self.0)
    }
}
/// A nonzero residue whose membership in the fixed order-q subgroup was
/// actually checked, or was derived from already checked members.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Subgroup(pub(crate) U1024);
impl Subgroup {
    /// Multiplicative identity is valid (e.g. an aggregate secret may be zero).
    #[must_use]
    pub const fn identity() -> Self {
        Self(U1024::ONE)
    }
    /// Original canonical public bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 128] {
        encode(&self.0)
    }
    /// Forget membership while retaining the same residue.
    #[must_use]
    pub const fn element(self) -> Element {
        Element(self.0)
    }
    /// Product of actual members in the same fixed group.
    #[must_use]
    pub fn multiply(self, other: Self, group: &Group) -> Self {
        Self(*mul(&self.0, &other.0, &group.p))
    }
}
/// Original secret scalar0<=s<q; no Clone/Debug or nonzero-only assumption.
pub struct Scalar(pub(crate) Zeroizing<U1024>);
impl Scalar {
    /// Additive zero is a valid aggregate/share value, even though freshly
    /// sampled individual C polynomial coefficients are nonzero.
    #[must_use]
    pub fn zero() -> Self {
        Self(Zeroizing::new(U1024::ZERO))
    }
    /// Actual addition of two owned scalar residues in the fixed field. DKG
    /// authorization/which contributions to include remains with its owner.
    #[must_use]
    pub fn add(self, other: Self, group: &Group) -> Self {
        Self(group.add_q(&self.0, &other.0))
    }
    /// Import canonical original share/coefficient bytes. Caller erases its
    /// separately retained source buffer; this owner erases its own copy.
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Error> {
        let x = Zeroizing::new(U1024::from_be_slice(bytes));
        if *x >= Q {
            return Err(Error::InvalidInput);
        }
        Ok(Self(x))
    }
    /// Explicit secret export into caller-owned zeroizing storage.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 128]> {
        let encoded = Zeroizing::new(self.0.to_be_bytes());
        let mut bytes = Zeroizing::new([0; 128]);
        bytes.copy_from_slice(encoded.as_ref());
        bytes
    }
    /// Convert an actual original Paillier decryption to an exact scalar. A
    /// residue with a nonzero high half is not silently truncated or restored
    /// using the C source's unrelated rational-reconstruction path.
    pub fn from_paillier(value: gnunet_paillier::Plaintext) -> Result<Self, Error> {
        let bytes = value.to_bytes();
        if bytes[..128].iter().any(|b| *b != 0) {
            return Err(Error::InvalidInput);
        }
        Self::from_bytes(bytes[128..].try_into().map_err(|_| Error::InvalidInput)?)
    }
}

/// Real validation of an owned decrypted preshare against its original public
/// exponentiated commitment. Mathematical equality is necessary; an original
/// Paillier decrypt completion/consensus write alone cannot mint a valid share.
pub struct ShareCheck {
    share: Option<Scalar>,
    expected: Subgroup,
    pow: Option<Pow1>,
    limits: Limits,
    ready: bool,
    failure: Option<Error>,
    taken: bool,
}
impl ShareCheck {
    /// Transfer the actual original scalar and pin its original expected g^s.
    pub fn new(
        share: Scalar,
        expected: Subgroup,
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let pow = Some(Pow::new(&G, &share.0, 1024, &group.p)?);
        Ok(Self {
            share: Some(share),
            expected,
            pow,
            limits,
            ready: false,
            failure: None,
            taken: false,
        })
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.share = None;
        self.pow = None;
        self.ready = false;
        e
    }
    /// One fixed-capacity secret exponent bit per unit.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.ready {
            return Ok(Progress::Ready);
        }
        let count = match self.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            let pow = self.pow.as_mut().ok_or(Error::NotReady)?;
            if pow.step() {
                let actual = self.pow.take().ok_or(Error::NotReady)?.finish()?;
                if *actual != self.expected.0 {
                    return Err(self.fail(Error::InvalidProof));
                }
                self.ready = true;
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume the actually matched original share exactly once.
    pub fn take_result(&mut self) -> Result<Scalar, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if !self.ready {
            return Err(Error::NotReady);
        }
        let result = self.share.take().ok_or(Error::Finished)?;
        self.taken = true;
        Ok(result)
    }
    /// Erase original secret/power without accepting it.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}

/// Original fixed-capacity constant-pattern exponent state. One step consumes
/// one public-capacity bit and exactly two Montgomery products.
pub(crate) struct Pow<const N: usize> {
    base: Zeroizing<FixedMontyForm<N>>,
    value: Zeroizing<FixedMontyForm<N>>,
    exponent: Zeroizing<Uint<N>>,
    remaining: u32,
}
impl<const N: usize> Pow<N> {
    pub(crate) fn new(
        base: &Uint<N>,
        exponent: &Uint<N>,
        bits: u32,
        params: &FixedMontyParams<N>,
    ) -> Result<Self, Error> {
        if bits == 0
            || bits > Uint::<N>::BITS
            || exponent.bits() > bits
            || *base >= *params.modulus().as_ref()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            base: Zeroizing::new(FixedMontyForm::new(base, params)),
            value: Zeroizing::new(FixedMontyForm::one(params)),
            exponent: Zeroizing::new(*exponent),
            remaining: bits,
        })
    }
    pub(crate) fn step(&mut self) -> bool {
        if self.remaining == 0 {
            return true;
        }
        let bit = self.remaining - 1;
        let square = Zeroizing::new(self.value.square());
        let product = Zeroizing::new(square.mul(&self.base));
        self.value.zeroize();
        *self.value = *square;
        self.value.ct_assign(&product, self.exponent.bit(bit));
        self.remaining = bit;
        bit == 0
    }
    pub(crate) fn finish(self) -> Result<Zeroizing<Uint<N>>, Error> {
        if self.remaining != 0 {
            return Err(Error::NotReady);
        }
        Ok(Zeroizing::new(self.value.retrieve()))
    }
}
pub(crate) type Pow1 = Pow<{ nlimbs(1024) }>;

/// Bounded original membership check. Parsing an Element cannot construct a
/// Subgroup; only this actual exponentiation (or existing members) can do so.
pub struct MembershipJob {
    value: U1024,
    pow: Option<Pow1>,
    limits: Limits,
    result: Option<Subgroup>,
    failure: Option<Error>,
    taken: bool,
}
impl MembershipJob {
    /// Start the real x^q==1 check. Zero is invalid, identity is allowed.
    pub fn new(value: Element, group: &Group, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if value.0 == U1024::ZERO {
            return Err(Error::InvalidProof);
        }
        Ok(Self {
            value: value.0,
            pow: Some(Pow::new(&value.0, &Q, 1024, &group.p)?),
            limits,
            result: None,
            failure: None,
            taken: false,
        })
    }
    /// Perform at most the selected number of original exponent-bit steps.
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
            let Some(pow) = &mut self.pow else {
                return Err(self.fail(Error::NotReady));
            };
            if pow.step() {
                let answer = self.pow.take().ok_or(Error::NotReady)?.finish()?;
                if *answer != U1024::ONE {
                    return Err(self.fail(Error::InvalidProof));
                }
                self.result = Some(Subgroup(self.value));
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.pow = None;
        self.result = None;
        e
    }
    /// Consume one actual checked member, exactly once.
    pub fn take_result(&mut self) -> Result<Subgroup, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let r = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(r)
    }
    /// Retire original work; no successful result is made.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
pub(crate) struct Sampler {
    attempts: u32,
    limits: Limits,
}
impl Sampler {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            attempts: 0,
            limits,
        }
    }
    pub(crate) fn step(&mut self, entropy: &mut impl Entropy) -> Result<Option<Scalar>, Error> {
        self.attempts = self.attempts.checked_add(1).ok_or(Error::Capacity)?;
        if self.attempts > self.limits.rejections {
            return Err(Error::Capacity);
        }
        let mut bytes = Zeroizing::new([0; 128]);
        entropy.fill(bytes.as_mut()).map_err(Error::Source)?;
        bytes[0] &= 0x7f;
        let value = Zeroizing::new(U1024::from_be_slice(bytes.as_ref()));
        if *value == U1024::ZERO || *value >= Q {
            return Ok(None);
        }
        Ok(Some(Scalar(value)))
    }
}
