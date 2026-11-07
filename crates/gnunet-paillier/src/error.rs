use core::fmt;
/// Exact primitive refusal; no case is a substitute successful value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The explicit provider failed. Its exact original classification is retained.
    Entropy(gnunet_types::Error),
    /// Invalid modulus/key components or mismatched original public/private key.
    InvalidKey,
    /// Ciphertext is not a valid unit under the actual original modulus.
    InvalidCipher,
    /// Plaintext/value/operation count is outside its mathematical range.
    Range,
    /// The finite caller-selected candidate/rejection/work budget was exhausted.
    Capacity,
    /// Explicit original job cancellation; secret state has been erased.
    Cancelled,
    /// Actual arithmetic has not reached its result boundary.
    NotReady,
    /// This original result was already consumed or its state is no longer live.
    Finished,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(error) => write!(f, "original Paillier entropy error: {error}"),
            Self::InvalidKey => f.write_str("invalid original Paillier key"),
            Self::InvalidCipher => f.write_str("invalid original Paillier ciphertext"),
            Self::Range => f.write_str("Paillier value is outside its mathematical range"),
            Self::Capacity => f.write_str("original Paillier work budget exhausted"),
            Self::Cancelled => f.write_str("original Paillier job cancelled"),
            Self::NotReady => f.write_str("original Paillier arithmetic is pending"),
            Self::Finished => f.write_str("original Paillier state retired"),
        }
    }
}
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Entropy(error) => Some(error),
            _ => None,
        }
    }
}
/// Actual bounded computation progress; Ready means a real result can be taken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// A finite original arithmetic/search cursor advanced.
    Advanced,
    /// Real arithmetic completed; take_result consumes the original value once.
    Ready,
}
