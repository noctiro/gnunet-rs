/// Actual service code, retaining extension numeric codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Code(u32);

impl Code {
    /// The requested no-op or original provider commit completed.
    pub const NONE: Self = Self(0);
    /// Actual backend failure without a more specific cause.
    pub const UNKNOWN: Self = Self(5000);
    /// No matching delegation was found.
    pub const ZONE_NOT_FOUND: Self = Self(5002);
    /// Empty deletion found no ordinary records.
    pub const RECORD_NOT_FOUND: Self = Self(5003);
    /// Inconsistent or malformed authoritative data.
    pub const RECORD_DATA_INVALID: Self = Self(5008);
    /// Advisory begin found no existing label.
    pub const NO_RESULTS: Self = Self(5010);
    /// A complete actual response cannot fit declared limits.
    pub const RECORD_TOO_BIG: Self = Self(5012);
    /// Actual backend refused an operation.
    pub const BACKEND_FAILED: Self = Self(5013);
    /// Actual authoritative store failed.
    pub const STORE_FAILED: Self = Self(5014);
    /// Invalid NFC label.
    pub const LABEL_INVALID: Self = Self(5015);
    /// Preserve an actual extension code.
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }
    /// Original numeric code.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}
