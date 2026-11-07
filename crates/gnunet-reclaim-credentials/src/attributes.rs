//! Exact Unicode18 lowercase/NFD attribute names using shared pure text tables.
use crate::{Claim, Failure, Stage};
use gnunet_reclaim::{Attribute, AttributeType, CredentialType, Identifier, Name, Sensitive};
use gnunet_types::Error;
use zeroize::Zeroize;

/// Explicit decoded-name/scalar scratch. It allocates nothing; Drop and each
/// failed conversion erase all borrowed scratch. The feature reuses IDENTITY's
/// existing fixed Unicode tables without depending on any service/runtime.
pub struct NameScratch<'a> {
    decoded: &'a mut [u8],
    lowered: &'a mut [u32],
    normalized: &'a mut [u32],
    ordering: &'a mut [u32],
}
impl<'a> NameScratch<'a> {
    /// Bind and erase caller scratch buffers.
    pub fn new(
        decoded: &'a mut [u8],
        lowered: &'a mut [u32],
        normalized: &'a mut [u32],
        ordering: &'a mut [u32],
    ) -> Self {
        let mut this = Self {
            decoded,
            lowered,
            normalized,
            ordering,
        };
        this.clear();
        this
    }
    /// Explicitly erase original scratch without touching successful output owners.
    pub fn clear(&mut self) {
        self.decoded.zeroize();
        self.lowered.zeroize();
        self.normalized.zeroize();
        self.ordering.zeroize();
    }
}
impl Drop for NameScratch<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
impl core::fmt::Debug for NameScratch<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NameScratch([REDACTED])")
    }
}
impl Claim<'_> {
    /// Build an actual STRING Attribute, applying the fixed official lowercase/
    /// NFD profile to the decoded key. IDs/credential reference/flags start at
    /// zero, matching the source extraction helper; the caller may explicitly
    /// bind them to an original stored credential afterwards.
    ///
    /// Uses caller-owned output and erased scratch, not an allocated JSON tree.
    /// Successful Attribute borrows the output owners. Every failure erases both
    /// whole output buffers and scratch. A name/value exceeding BE16 is refused.
    pub fn attribute<'a>(
        self,
        name_out: &'a mut [u8],
        value_out: &'a mut [u8],
        scratch: &mut NameScratch<'_>,
    ) -> Result<Attribute<'a>, Failure> {
        let result = (|| {
            let value_len = self
                .value
                .attribute_len()
                .map_err(|e| Failure::credential(CredentialType::JWT, Stage::Format, e))?;
            u16::try_from(value_len).map_err(|_| {
                Failure::credential(CredentialType::JWT, Stage::Format, Error::TooLarge)
            })?;
            if value_len > value_out.len() {
                return Err(Failure::credential(
                    CredentialType::JWT,
                    Stage::Format,
                    Error::Capacity,
                ));
            }
            let decoded = self
                .name
                .decode(scratch.decoded)
                .map_err(|e| Failure::credential(CredentialType::JWT, Stage::Name, e))?;
            let n = gnunet_identity::normalize_name_into(
                &scratch.decoded[..decoded],
                name_out,
                scratch.lowered,
                scratch.normalized,
                scratch.ordering,
            )
            .map_err(|e| Failure::credential(CredentialType::JWT, Stage::Name, e))?;
            u16::try_from(n).map_err(|_| {
                Failure::credential(CredentialType::JWT, Stage::Name, Error::TooLarge)
            })?;
            self.value
                .write_attribute(value_out)
                .map_err(|e| Failure::credential(CredentialType::JWT, Stage::Format, e))?;
            Ok((n, value_len))
        })();
        scratch.clear();
        let (n, value_len) = match result {
            Ok(v) => v,
            Err(error) => {
                name_out.zeroize();
                value_out.zeroize();
                return Err(error);
            }
        };
        let name = Name::new(&name_out[..n])
            .map_err(|e| Failure::credential(CredentialType::JWT, Stage::Name, e))?;
        Ok(Attribute::new(
            Identifier::ZERO,
            Identifier::ZERO,
            AttributeType::STRING,
            name,
            Sensitive::new(&value_out[..value_len]),
        ))
    }
}
