//! Borrowed RFC 6698 TLSA certificate associations. DNS authenticity, the
//! service binding and proof of private-key possession belong to the TLS owner.

use gnunet_types::Error;

const PREFIX: usize = 3;

/// RFC 6698 certificate usage. Each value has its own authentication policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Usage {
    /// A certificate on a valid PKIX path must match.
    PkixTrustAnchor = 0,
    /// An independently PKIX-validated end entity must match.
    PkixEndEntity = 1,
    /// The matched material is the DANE trust anchor for the path.
    DaneTrustAnchor = 2,
    /// The matching end entity is authenticated by the DANE association.
    DaneEndEntity = 3,
}

/// TLSA certificate selector. Selected DER must come from the same TLS peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Selector {
    /// The complete DER encoding of the candidate certificate.
    Certificate = 0,
    /// The complete DER encoding of its SubjectPublicKeyInfo.
    SubjectPublicKeyInfo = 1,
}

/// Certificate association with its exact checked comparison width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Matching<'a> {
    /// Whole selected DER bytes. The TLS owner validates their structure.
    Exact(&'a [u8]),
    /// SHA-256 of the selected DER bytes.
    Sha256(&'a [u8; 32]),
    /// SHA-512 of the selected DER bytes.
    Sha512(&'a [u8; 64]),
}

/// Structurally usable association, independent of DNS provenance and TLS proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Association<'a> {
    usage: Usage,
    selector: Selector,
    matching: Matching<'a>,
}

impl<'a> Association<'a> {
    /// Parse one original DNS TLSA RDATA field.
    pub fn parse(rdata: &'a [u8]) -> Result<Self, Error> {
        if rdata.len() > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        let (&[usage, selector, matching], data) = rdata
            .split_first_chunk::<PREFIX>()
            .ok_or(Error::Truncated)?;
        Self::from_fields(usage, selector, matching, data)
    }

    /// Borrow decoded TLSA fields from an existing trusted record container.
    /// Unsupported parameter values and malformed comparisons remain distinct.
    pub fn from_fields(
        usage: u8,
        selector: u8,
        matching: u8,
        data: &'a [u8],
    ) -> Result<Self, Error> {
        let usage = match usage {
            0 => Usage::PkixTrustAnchor,
            1 => Usage::PkixEndEntity,
            2 => Usage::DaneTrustAnchor,
            3 => Usage::DaneEndEntity,
            _ => return Err(Error::Unsupported),
        };
        let selector = match selector {
            0 => Selector::Certificate,
            1 => Selector::SubjectPublicKeyInfo,
            _ => return Err(Error::Unsupported),
        };
        let matching = match matching {
            0 if !data.is_empty() => Matching::Exact(data),
            0 => return Err(Error::Malformed),
            1 => Matching::Sha256(data.try_into().map_err(|_| Error::Malformed)?),
            2 => Matching::Sha512(data.try_into().map_err(|_| Error::Malformed)?),
            _ => return Err(Error::Unsupported),
        };
        Ok(Self {
            usage,
            selector,
            matching,
        })
    }

    /// Required authentication policy for the candidate.
    #[must_use]
    pub const fn usage(self) -> Usage {
        self.usage
    }

    /// Which exact DER encoding supplies the comparison.
    #[must_use]
    pub const fn selector(self) -> Selector {
        self.selector
    }

    /// Checked comparison method and original association data.
    #[must_use]
    pub const fn matching(self) -> Matching<'a> {
        self.matching
    }

    /// Compare the bytes already selected by the TLS owner. This boolean
    /// makes no assertion about DER validity, certification path, or handshake.
    #[cfg(feature = "tlsa-hash")]
    #[must_use]
    pub fn matches_selected(self, selected_der: &[u8]) -> bool {
        use sha2::{Digest, Sha256, Sha512};
        match self.matching {
            Matching::Exact(expected) => expected == selected_der,
            Matching::Sha256(expected) => {
                expected == &<[u8; 32]>::from(Sha256::digest(selected_der))
            }
            Matching::Sha512(expected) => {
                expected == &<[u8; 64]>::from(Sha512::digest(selected_der))
            }
        }
    }
}

#[cfg(test)]
mod tests;
