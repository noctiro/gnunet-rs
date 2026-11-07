use crate::{Error, MAX_ROWS};
use crypto_bigint::{CheckedAdd, CheckedSub, U256, U2048};
use gnunet_paillier::{Plaintext, PublicKey};
use gnunet_types::Error as CoreError;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The C offset is2^(2048/3), not a negotiated or private protocol field.
const OFFSET_BIT: u32 = 2048 / 3;

fn offset(public: &PublicKey, coefficient: i128) -> Result<Plaintext, Error> {
    let coefficient = Zeroizing::new(coefficient);
    let base = Zeroizing::new(U2048::ONE.shl(OFFSET_BIT));
    let amount = Zeroizing::new(U2048::from_u128(coefficient.unsigned_abs()));
    let value = Zeroizing::new(if *coefficient < 0 {
        base.checked_sub(&amount)
            .into_option()
            .ok_or(CoreError::Overflow)?
    } else {
        base.checked_add(&amount)
            .into_option()
            .ok_or(CoreError::Overflow)?
    });
    let bytes = Zeroizing::new(value.to_be_bytes());
    Ok(public.plaintext(bytes.as_ref())?)
}
/// Alice's actual positive offset plaintext S+a, including i64::MIN.
pub fn alice_value(public: &PublicKey, value: i64) -> Result<Plaintext, Error> {
    offset(public, i128::from(value))
}
/// Bob's first original column plaintext S-r-b, with a safe signed32 mask.
pub fn bob_left(public: &PublicKey, value: i64, mask: i32) -> Result<Plaintext, Error> {
    offset(public, -i128::from(mask) - i128::from(value))
}
/// Bob's independent second original column plaintext S-r.
pub fn bob_right(public: &PublicKey, mask: i32) -> Result<Plaintext, Error> {
    offset(public, -i128::from(mask))
}

fn add(a: &U256, b: &U256) -> Result<U256, Error> {
    a.checked_add(b)
        .into_option()
        .ok_or_else(|| CoreError::Overflow.into())
}
fn square(value: i128) -> Result<U256, Error> {
    let magnitude = Zeroizing::new(U256::from_u128(value.unsigned_abs()));
    magnitude
        .checked_mul(&magnitude)
        .into_option()
        .ok_or_else(|| CoreError::Overflow.into())
}
fn row_bound() -> U256 {
    U256::ONE.shl(63).wrapping_add(&U256::ONE.shl(31))
}
fn sum_bound(rows: usize, base: U256) -> Result<U256, Error> {
    let rows = u64::try_from(rows).map_err(|_| CoreError::Overflow)?;
    base.checked_mul(&base)
        .into_option()
        .ok_or(CoreError::Overflow)?
        .checked_mul(&U256::from_u64(rows))
        .into_option()
        .ok_or_else(|| CoreError::Overflow.into())
}

/// Bob's actual bounded square sums, accumulated one original coefficient at a
/// time. Positive plaintexts are below2^151 at the configured maximum count.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BobSums {
    rows: usize,
    count: usize,
    sum: U256,
    prime: U256,
}
impl BobSums {
    /// Select the exact completed intersection size, including zero.
    pub fn new(rows: usize) -> Result<Self, Error> {
        if rows > MAX_ROWS {
            return Err(CoreError::Capacity.into());
        }
        Ok(Self {
            rows,
            count: 0,
            sum: U256::ZERO,
            prime: U256::ZERO,
        })
    }
    /// Add one actual b and original signed32 mask. Every failure occurs before
    /// either sum or count commits; even MIN values never use signed negation.
    pub fn push(&mut self, value: i64, mask: i32) -> Result<(), Error> {
        if self.count == self.rows {
            return Err(Error::Phase);
        }
        let left = Zeroizing::new(square(i128::from(mask) + i128::from(value))?);
        let right = Zeroizing::new(square(i128::from(mask))?);
        let sum = Zeroizing::new(add(&self.sum, &left)?);
        let prime = Zeroizing::new(add(&self.prime, &right)?);
        self.sum = *sum;
        self.prime = *prime;
        self.count += 1;
        Ok(())
    }
    /// The real plaintext SUM((r+b)^2), ready only after every original row.
    pub fn sum(&self, public: &PublicKey) -> Result<Plaintext, Error> {
        self.plaintext(public, &self.sum)
    }
    /// The real plaintext SUM(r^2), ready only after every original row.
    pub fn prime(&self, public: &PublicKey) -> Result<Plaintext, Error> {
        self.plaintext(public, &self.prime)
    }
    fn plaintext(&self, public: &PublicKey, value: &U256) -> Result<Plaintext, Error> {
        if self.count != self.rows {
            return Err(Error::Phase);
        }
        let bytes = Zeroizing::new(value.to_be_bytes());
        Ok(public.plaintext(bytes.as_ref())?)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Signed {
    negative: bool,
    magnitude: U256,
}
impl Signed {
    fn zero() -> Self {
        Self {
            negative: false,
            magnitude: U256::ZERO,
        }
    }
    fn add(&mut self, negative: bool, value: &U256) -> Result<(), Error> {
        let (sign, magnitude) = if self.negative == negative {
            (negative, add(&self.magnitude, value)?)
        } else if self.magnitude >= *value {
            (self.negative, self.magnitude.wrapping_sub(value))
        } else {
            (negative, value.wrapping_sub(&self.magnitude))
        };
        let magnitude = Zeroizing::new(magnitude);
        self.negative = sign && *magnitude != U256::ZERO;
        self.magnitude = *magnitude;
        Ok(())
    }
}

fn unsigned(bytes: &[u8; 256], bound: &U256) -> Result<U256, Error> {
    if bytes[..224].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidResult);
    }
    let value = U256::from_be_slice(&bytes[224..]);
    if value > *bound {
        return Err(Error::InvalidResult);
    }
    Ok(value)
}
fn unoffset_square(bytes: &[u8; 256]) -> Result<U256, Error> {
    let raw = Zeroizing::new(U2048::from_be_slice(bytes));
    let twice = Zeroizing::new(U2048::ONE.shl(OFFSET_BIT + 1));
    let difference = Zeroizing::new(if *raw >= *twice {
        raw.wrapping_sub(&twice)
    } else {
        twice.wrapping_sub(&raw)
    });
    // |a-b-r| <=2^64+2^31. Each i64/32 endpoint is supported safely.
    let bound = Zeroizing::new(U2048::ONE.shl(64).wrapping_add(&U2048::ONE.shl(31)));
    if *difference > *bound {
        return Err(Error::InvalidResult);
    }
    let small = Zeroizing::new(difference.resize::<{ crypto_bigint::nlimbs(256) }>());
    small
        .checked_mul(&small)
        .into_option()
        .ok_or_else(|| CoreError::Overflow.into())
}

/// Alice's real decrypted-column accumulator. The two equal SUM(a^2) terms in
/// the C expression cancel exactly, so they need neither memory nor recomputation.
/// Data remains unauthenticated arithmetic supplied by the actual Bob peer;
/// range checks are not a proof that the peer used its claimed private vector.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AliceMath {
    rows: usize,
    left: usize,
    right: usize,
    have_sum: bool,
    have_prime: bool,
    sum: U256,
    prime: U256,
    left_squares: U256,
    right_squares: U256,
    consumed: bool,
}
impl AliceMath {
    /// Adopt the actual original SETI DONE count, not the remote frame count.
    pub fn new(rows: usize) -> Result<Self, Error> {
        if rows > MAX_ROWS {
            return Err(CoreError::Capacity.into());
        }
        Ok(Self {
            rows,
            left: 0,
            right: 0,
            have_sum: false,
            have_prime: false,
            sum: U256::ZERO,
            prime: U256::ZERO,
            left_squares: U256::ZERO,
            right_squares: U256::ZERO,
            consumed: false,
        })
    }
    /// Adopt actual D(s) once, bounded by the selected i64/signed32 profile.
    pub fn sum(&mut self, bytes: &[u8; 256]) -> Result<(), Error> {
        if self.have_sum || self.consumed {
            return Err(Error::Phase);
        }
        let value = Zeroizing::new(unsigned(bytes, &sum_bound(self.rows, row_bound())?)?);
        self.sum = *value;
        self.have_sum = true;
        Ok(())
    }
    /// Adopt actual D(s') once, independently of the first ciphertext.
    pub fn prime(&mut self, bytes: &[u8; 256]) -> Result<(), Error> {
        if self.have_prime || self.consumed {
            return Err(Error::Phase);
        }
        let value = Zeroizing::new(unsigned(bytes, &sum_bound(self.rows, U256::ONE.shl(31))?)?);
        self.prime = *value;
        self.have_prime = true;
        Ok(())
    }
    /// Add actual D(Kp)-2S squared, without truncating2048-bit residues.
    pub fn left(&mut self, bytes: &[u8; 256]) -> Result<(), Error> {
        if self.left == self.rows || self.consumed {
            return Err(Error::Phase);
        }
        let value = Zeroizing::new(unoffset_square(bytes)?);
        let sum = Zeroizing::new(add(&self.left_squares, &value)?);
        self.left_squares = *sum;
        self.left += 1;
        Ok(())
    }
    /// Add actual D(Kq)-2S squared from the distinct second interleaved column.
    pub fn right(&mut self, bytes: &[u8; 256]) -> Result<(), Error> {
        if self.right == self.rows || self.consumed {
            return Err(Error::Phase);
        }
        let value = Zeroizing::new(unoffset_square(bytes)?);
        let sum = Zeroizing::new(add(&self.right_squares, &value)?);
        self.right_squares = *sum;
        self.right += 1;
        Ok(())
    }
    /// Produce (D(s)-D(s')+SUM(Kq-2S)^2-SUM(Kp-2S)^2)/2 exactly once.
    /// An odd numerator, missing column, overflow or out-of-i64-product bound
    /// is an actual failure; integer division never silently rounds it.
    pub fn finish(&mut self) -> Result<Product, Error> {
        if self.consumed {
            return Err(Error::Finished);
        }
        if !self.have_sum || !self.have_prime || self.left != self.rows || self.right != self.rows {
            return Err(Error::Phase);
        }
        let mut numerator = Signed::zero();
        numerator.add(false, &self.sum)?;
        numerator.add(true, &self.prime)?;
        numerator.add(false, &self.right_squares)?;
        numerator.add(true, &self.left_squares)?;
        if numerator.magnitude.bit_vartime(0) {
            return Err(Error::InvalidResult);
        }
        let magnitude = Zeroizing::new(numerator.magnitude.shr(1));
        if *magnitude > sum_bound(self.rows, U256::ONE.shl(63))? {
            return Err(Error::InvalidResult);
        }
        let product = Product {
            negative: numerator.negative && *magnitude != U256::ZERO,
            magnitude: *magnitude,
        };
        self.zeroize();
        self.consumed = true;
        Ok(product)
    }
}

/// A checked full signed product, rather than the ECC bounded-i32 result.
/// It is erased on drop and never implicitly formatted or cloned.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Product {
    negative: bool,
    magnitude: U256,
}
impl Product {
    /// The standard public result sign, exactly-1,0 or1.
    #[must_use]
    pub fn range(&self) -> i32 {
        if self.magnitude == U256::ZERO {
            0
        } else if self.negative {
            -1
        } else {
            1
        }
    }
    /// Actual positive GCRYMPI_FMT_STD magnitude, including its necessary
    /// leading zero sign octet. The sign itself is the separate range field.
    #[must_use]
    pub fn mpi(&self) -> Mpi {
        let raw = Zeroizing::new(self.magnitude.to_be_bytes());
        let raw: &[u8] = raw.as_ref();
        let first = raw.iter().position(|byte| *byte != 0).unwrap_or(raw.len());
        let length = raw.len() - first;
        let prefix = usize::from(length != 0 && raw[first] & 0x80 != 0);
        let mut bytes = [0; 33];
        bytes[prefix..prefix + length].copy_from_slice(&raw[first..]);
        Mpi {
            bytes,
            length: prefix + length,
        }
    }
}
/// Owned zeroizing standard MPI result bytes; no native or client write receipt.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mpi {
    bytes: [u8; 33],
    length: usize,
}
impl Mpi {
    /// Exact public output payload, empty for zero.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
