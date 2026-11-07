use core::fmt;

/// Actual refusal of the original mathematical job; never a negative proof
/// result synthesized from resource, cancellation or source failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Exact supplied entropy/provider classification.
    Source(gnunet_types::Error),
    /// Exact original Paillier primitive failure.
    Paillier(gnunet_paillier::Error),
    /// Noncanonical/out-of-domain value or inconsistent caller association.
    InvalidInput,
    /// Actual group, signature, commitment or proof equation failure.
    InvalidProof,
    /// Distinct original indices/peers or threshold policy do not match.
    Roster,
    /// Finite capacity/allocation/rejection/work policy could not be met.
    Capacity,
    /// A checked size calculation overflowed.
    Overflow,
    /// This original result is not complete.
    NotReady,
    /// The original job/result has already retired or been consumed.
    Finished,
    /// Explicit cancellation erased owned secret work.
    Cancelled,
}
impl From<gnunet_types::Error> for Error {
    fn from(error: gnunet_types::Error) -> Self {
        Self::Source(error)
    }
}
impl From<gnunet_paillier::Error> for Error {
    fn from(error: gnunet_paillier::Error) -> Self {
        Self::Paillier(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secretsharing mathematical refusal: {self:?}")
    }
}
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Source(e) => Some(e),
            Self::Paillier(e) => Some(e),
            _ => None,
        }
    }
}
/// Actual bounded arithmetic progress, with no native/publication implication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// At least one finite original work cursor advanced.
    Advanced,
    /// A completed actual result can be consumed once.
    Ready,
}
/// Explicit local resource policy; counts are not preallocated maxima.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum exponent bits/arithmetic steps per advance,1..64.
    pub units_per_turn: u16,
    /// Total entropy draws for one scalar/nonce,1..2^20.
    pub rejections: u32,
    /// Maximum admitted original roster/polynomial count,1..65535.
    pub participants: usize,
    /// Actual retained Vec capacity bytes, including each simultaneous snapshot.
    pub retained_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            units_per_turn: 8,
            rejections: 4096,
            participants: 1024,
            retained_bytes: 16 << 20,
        }
    }
}
impl Limits {
    /// Reject unbounded/unusable policy before allocation or entropy.
    pub fn validate(self) -> Result<(), Error> {
        if self.units_per_turn == 0
            || self.units_per_turn > 64
            || self.rejections == 0
            || self.rejections > 1 << 20
            || !(1..=65535).contains(&self.participants)
            || self.retained_bytes == 0
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(crate) fn units(self, units: u16) -> Result<usize, Error> {
        if units == 0 || units > self.units_per_turn {
            return Err(Error::Capacity);
        }
        Ok(usize::from(units))
    }
    #[cfg(feature = "alloc")]
    pub(crate) fn bytes<T>(self, capacity: usize, extra: usize) -> Result<usize, Error> {
        let bytes = capacity
            .checked_mul(core::mem::size_of::<T>())
            .and_then(|n| n.checked_add(extra))
            .ok_or(Error::Overflow)?;
        if bytes > self.retained_bytes {
            return Err(Error::Capacity);
        }
        Ok(bytes)
    }
}
