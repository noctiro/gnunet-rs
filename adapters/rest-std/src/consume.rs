//! Interpretation of the selected RECLAIM source's actual response word.
use crate::Error;
use gnunet_gnsrecord::ZoneKey;

/// Explicit wire-status producer profile for the actual RECLAIM backend.
/// This is source configuration, shared by ordinary REST and OpenID consumers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConsumeProfile {
    /// Canonical BE32 GNUNET_OK=1, GNUNET_NO=0, GNUNET_SYSERR=-1.
    #[default]
    Canonical,
    /// Pinned little-endian C assignment of htons(int32_status) to uint32_t.
    CNativeLittle,
}

/// Actual service-result classification. Unknown words are never normalized to
/// either success or authorization denial, including another producer's word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeStatus {
    /// Exact GNUNET_OK under the selected original producer profile.
    Success,
    /// Exact GNUNET_NO: this ticket/RP authorization was denied.
    Denied,
    /// Exact GNUNET_SYSERR: provider failure, not evidence of revocation.
    Failed,
    /// A word outside the selected producer's documented result domain.
    Unknown,
}

/// Why an actual consume reply cannot authorize an application success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeFailure {
    /// Actual GNUNET_NO from the selected original service.
    Denied,
    /// Actual GNUNET_SYSERR from the selected original service.
    Service,
    /// Unrecognized word, without a guessed producer or outcome.
    Unknown,
    /// A success/authorization-denial reply carried no matching ticket issuer.
    IssuerMismatch,
}

impl ConsumeProfile {
    /// Classify without changing the caller's original raw word.
    pub const fn classify(self, raw: u32) -> ConsumeStatus {
        let (success, failed) = match self {
            Self::Canonical => (1, u32::MAX),
            // C service consume_result_cb writes a u32 using htons. On a
            // little-endian host, 1 => [00,01,00,00], -1 => [ff,ff,00,00].
            Self::CNativeLittle => (0x0001_0000, 0xffff_0000),
        };
        if raw == success {
            ConsumeStatus::Success
        } else if raw == 0 {
            ConsumeStatus::Denied
        } else if raw == failed {
            ConsumeStatus::Failed
        } else {
            ConsumeStatus::Unknown
        }
    }

    pub(crate) fn validate(
        self,
        raw: u32,
        identity: Option<ZoneKey>,
        issuer: ZoneKey,
    ) -> Result<(), Error> {
        let cause = match self.classify(raw) {
            ConsumeStatus::Success if identity == Some(issuer) => return Ok(()),
            ConsumeStatus::Success => ConsumeFailure::IssuerMismatch,
            ConsumeStatus::Denied if identity == Some(issuer) => ConsumeFailure::Denied,
            ConsumeStatus::Denied => ConsumeFailure::IssuerMismatch,
            ConsumeStatus::Failed => ConsumeFailure::Service,
            ConsumeStatus::Unknown => ConsumeFailure::Unknown,
        };
        Err(Error::Consume { raw, cause })
    }
}

#[cfg(test)]
mod tests;
