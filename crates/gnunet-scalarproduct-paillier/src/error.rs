use core::fmt;

/// An original refusal, never a substitute successful product or peer receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Bounded allocation, arithmetic, snapshot or protocol input failed.
    Core(gnunet_types::Error),
    /// Original explicit entropy or real Paillier arithmetic failure.
    Primitive(gnunet_paillier::Error),
    /// Input is not legal in this original session phase.
    Phase,
    /// Decrypted data is inconsistent with the selected signed-i64/signed32
    /// profile, or the final numerator is not exactly divisible by two.
    InvalidResult,
    /// Original absolute session deadline, without reconnect renewal.
    Deadline,
    /// The actual caller clock went backwards or became unavailable.
    Clock,
    /// Explicit cancellation of this original intent.
    Cancelled,
    /// Original result or retained token was already consumed.
    Finished,
}
impl From<gnunet_types::Error> for Error {
    fn from(value: gnunet_types::Error) -> Self {
        Self::Core(value)
    }
}
impl From<gnunet_paillier::Error> for Error {
    fn from(value: gnunet_paillier::Error) -> Self {
        Self::Primitive(value)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "original scalarproduct input/resource error: {error}"),
            Self::Primitive(error) => write!(f, "original Paillier error: {error}"),
            Self::Phase => f.write_str("unexpected original Paillier session phase"),
            Self::InvalidResult => f.write_str("invalid Paillier scalarproduct arithmetic result"),
            Self::Deadline => f.write_str("original Paillier scalarproduct deadline"),
            Self::Clock => f.write_str("original Paillier scalarproduct clock unavailable"),
            Self::Cancelled => f.write_str("original Paillier scalarproduct cancelled"),
            Self::Finished => f.write_str("original Paillier scalarproduct state retired"),
        }
    }
}
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Primitive(error) => Some(error),
            _ => None,
        }
    }
}
