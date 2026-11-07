//! Fixed-capacity, secret-exponent constant-pattern modular exponentiation.
use crate::Error;
use crypto_bigint::{
    CtAssign, Uint,
    modular::{FixedMontyForm, FixedMontyParams},
};
use zeroize::{Zeroize, Zeroizing};

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
            return Err(Error::Range);
        }
        Ok(Self {
            base: Zeroizing::new(FixedMontyForm::new(base, params)),
            value: Zeroizing::new(FixedMontyForm::one(params)),
            exponent: Zeroizing::new(*exponent),
            remaining: bits,
        })
    }
    // One public-capacity exponent bit, two Montgomery products, branchless
    // selection for the secret bit. No source, clock, allocation or entropy IO.
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
