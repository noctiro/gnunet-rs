//! Official GNUnet v0.29.1 GNS encrypted record blocks.
//!
//! Block decoding checks structure only; public-key binding and signatures must
//! be verified before interpreting the encrypted record data.
#![no_std]
#![forbid(unsafe_code)]

use gnunet_crypto::{
    gns::{self, EdkeySecret, PkeySecret},
    hash512, hkdf_gnunet, symmetric,
};
use gnunet_gnsrecord::{
    MAX_BLOCK_SIZE, RecordData, RecordFlags, RecordIter, RecordSet, ZoneKey, ZoneKeyType,
};
use gnunet_types::Error;
use zeroize::{Zeroize, Zeroizing};
mod label;
mod nfc_data;
pub use label::Label;
mod publication;
pub use publication::{Publication, prepare_publication_at};

/// Fixed official header: size/type, derived public key, signature and expiry.
pub const BLOCK_HEADER_LEN: usize = 112;
/// Official purpose number for encrypted GNS record blocks.
pub const RECORD_SIGNATURE_PURPOSE: u32 = 15;
/// Reference block resolver's maximum number of records.
pub const MAX_RECORDS: usize = 2048;

/// Owner-held typed zone secret, with both official key constructions.
pub enum ZoneSecret {
    /// Edwards25519 ECDSA zone scalar.
    Pkey(PkeySecret),
    /// Ed25519 zone seed.
    Edkey(EdkeySecret),
}
impl ZoneSecret {
    /// Derive the official typed public zone identifier.
    #[must_use]
    pub fn public_key(&self) -> ZoneKey {
        match self {
            Self::Pkey(key) => ZoneKey::new(ZoneKeyType::Pkey, key.public_key()),
            Self::Edkey(key) => ZoneKey::new(ZoneKeyType::Edkey, key.public_key()),
        }
    }
    /// Seal an already serialized public record set. Relative expiration,
    /// private and maintenance records must be handled by the publishing owner
    /// before this call; they are refused to prevent unintended publication.
    /// The caller controls block expiry and must authorize the publication.
    /// Capacity/policy refusal leaves output unchanged; cryptographic failure
    /// erases the portion reserved for the block.
    pub fn seal<'a>(
        &self,
        label: Label<'_>,
        expiration: u64,
        plaintext: &[u8],
        output: &'a mut [u8],
    ) -> Result<Block<'a>, Error> {
        self.seal_validated(label, expiration, plaintext, output, false)
    }
    /// Seal an authoritative complete record set only for the owner's local
    /// NAMECACHE. PRIVATE flags are retained, unlike public DHT publication.
    /// Relative/maintenance records remain rejected. This shares the official
    /// encryption/signature format and primitives; destination authorization
    /// belongs to the caller, which must never publish this full set to DHT.
    /// Source, expiration and zeroizing plaintext ownership remain explicit.
    pub fn seal_for_namecache<'a>(
        &self,
        label: Label<'_>,
        expiration: u64,
        plaintext: &[u8],
        output: &'a mut [u8],
    ) -> Result<Block<'a>, Error> {
        self.seal_validated(label, expiration, plaintext, output, true)
    }
    fn seal_validated<'a>(
        &self,
        label: Label<'_>,
        expiration: u64,
        plaintext: &[u8],
        output: &'a mut [u8],
        local_cache: bool,
    ) -> Result<Block<'a>, Error> {
        if plaintext.len() > MAX_BLOCK_SIZE {
            return Err(Error::TooLarge);
        }
        let records = RecordSet::parse_padded(plaintext, MAX_RECORDS)?;
        for record in records.iter() {
            let flags = record?.flags;
            let refused = RecordFlags::MAINTENANCE.bits()
                | RecordFlags::RELATIVE_EXPIRATION.bits()
                | if local_cache {
                    0
                } else {
                    RecordFlags::PRIVATE.bits()
                };
            if flags.bits() & refused != 0 {
                return Err(Error::InvalidInput);
            }
        }
        let zone = self.public_key();
        let overhead = if zone.kind() == ZoneKeyType::Edkey {
            16
        } else {
            0
        };
        let size = BLOCK_HEADER_LEN + plaintext.len() + overhead;
        if output.len() < size {
            return Err(Error::Capacity);
        }
        let block = &mut output[..size];
        let result = self.seal_into(label, expiration, plaintext, zone, block);
        if let Err(error) = result {
            block.zeroize();
            return Err(error);
        }
        Block::decode(block)
    }
    fn seal_into(
        &self,
        label: Label<'_>,
        expiration: u64,
        plaintext: &[u8],
        zone: ZoneKey,
        block: &mut [u8],
    ) -> Result<(), Error> {
        let material = Material::derive(zone, label, expiration)?;
        let size = u32::try_from(block.len()).map_err(|_| Error::TooLarge)?;
        block[..4].copy_from_slice(&size.to_be_bytes());
        block[4..8].copy_from_slice(&zone.kind().record_type().value().to_be_bytes());
        block[104..112].copy_from_slice(&expiration.to_be_bytes());
        match self {
            Self::Pkey(key) => {
                let derived = key.derive(label.as_str(), "gns")?;
                block[8..40].copy_from_slice(&derived.public_key());
                block[112..].copy_from_slice(plaintext);
                symmetric::aes256ctr(&material.key, &material.aes_iv(), &mut block[112..])?;
                // The signature's last eight bytes temporarily hold the purpose
                // prefix, making expiry+ciphertext one contiguous signed region.
                write_purpose(block)?;
                let signature = derived.sign(RECORD_SIGNATURE_PURPOSE, &[&block[96..]])?;
                block[40..104].copy_from_slice(&signature);
            }
            Self::Edkey(key) => {
                let derived = key.derive(label.as_str(), "gns")?;
                block[8..40].copy_from_slice(&derived.public_key());
                symmetric::xsalsa20poly1305_seal(
                    &material.key,
                    &material.nonce,
                    plaintext,
                    &mut block[112..],
                )?;
                write_purpose(block)?;
                let signature = derived.sign(RECORD_SIGNATURE_PURPOSE, &[&block[96..]])?;
                block[40..104].copy_from_slice(&signature);
            }
        }
        Ok(())
    }
}
fn write_purpose(block: &mut [u8]) -> Result<(), Error> {
    let signed_size = u32::try_from(block.len() - 96).map_err(|_| Error::TooLarge)?;
    block[96..100].copy_from_slice(&signed_size.to_be_bytes());
    block[100..104].copy_from_slice(&RECORD_SIGNATURE_PURPOSE.to_be_bytes());
    Ok(())
}
struct Material {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 24],
}
impl Material {
    fn derive(zone: ZoneKey, label: Label<'_>, expiration: u64) -> Result<Self, Error> {
        let mut result = Self {
            key: Zeroizing::new([0; 32]),
            nonce: [0; 24],
        };
        match zone.kind() {
            ZoneKeyType::Pkey => {
                hkdf_gnunet(
                    b"gns-aes-ctx-key",
                    zone.key(),
                    &[label.as_str().as_bytes()],
                    result.key.as_mut(),
                )?;
                hkdf_gnunet(
                    b"gns-aes-ctx-iv",
                    zone.key(),
                    &[label.as_str().as_bytes()],
                    &mut result.nonce[..4],
                )?;
                result.nonce[4..12].copy_from_slice(&expiration.to_be_bytes());
                result.nonce[15] = 1;
            }
            ZoneKeyType::Edkey => {
                hkdf_gnunet(
                    b"gns-xsalsa-ctx-key",
                    zone.key(),
                    &[label.as_str().as_bytes()],
                    result.key.as_mut(),
                )?;
                hkdf_gnunet(
                    b"gns-xsalsa-ctx-iv",
                    zone.key(),
                    &[label.as_str().as_bytes()],
                    &mut result.nonce[..16],
                )?;
                result.nonce[16..].copy_from_slice(&expiration.to_be_bytes());
            }
        }
        Ok(result)
    }
    fn aes_iv(&self) -> [u8; 16] {
        let mut iv = [0; 16];
        iv.copy_from_slice(&self.nonce[..16]);
        iv
    }
}

/// Derive a DHT query from the original zone and normalized label. The key type
/// selects the zone construction but is not included in the final SHA512 input.
pub fn query(zone: ZoneKey, label: Label<'_>) -> Result<[u8; 64], Error> {
    Ok(hash512(&gns::derive_public(
        zone.key(),
        label.as_str(),
        "gns",
    )?))
}

/// A complete borrowed GNS record block with its exact official zone type.
#[derive(Clone, Copy, Debug)]
pub struct Block<'a> {
    bytes: &'a [u8],
    kind: ZoneKeyType,
}
impl<'a> Block<'a> {
    /// Check the exact advertised size, supported type and payload width.
    /// This does not verify the signature or bind the block to a requested zone.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < BLOCK_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let size = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::Truncated)?);
        if usize::try_from(size).map_err(|_| Error::TooLarge)? != bytes.len() {
            return Err(Error::Malformed);
        }
        let kind = match u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Error::Truncated)?) {
            65536 => ZoneKeyType::Pkey,
            65556 => ZoneKeyType::Edkey,
            _ => return Err(Error::Unsupported),
        };
        let payload = bytes.len() - BLOCK_HEADER_LEN;
        if payload > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        if kind == ZoneKeyType::Edkey && payload < 16 {
            return Err(Error::Truncated);
        }
        Ok(Self { bytes, kind })
    }
    /// Exact original bytes, including the total size and zone-type prefix.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// PKEY or EDKEY, retained independently from key bytes.
    #[must_use]
    pub const fn kind(self) -> ZoneKeyType {
        self.kind
    }
    /// Encrypted record bytes, including EDKEY's leading Poly1305 tag.
    #[must_use]
    pub fn ciphertext(self) -> &'a [u8] {
        &self.bytes[BLOCK_HEADER_LEN..]
    }
    /// Official block expiration in absolute UTC microseconds.
    pub fn expiration(self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.bytes[104..112]
                .try_into()
                .map_err(|_| Error::Truncated)?,
        ))
    }
    /// Untrusted carried signing key. Use `verify_for` to bind it to a zone/name.
    pub fn derived_public_key(self) -> Result<[u8; 32], Error> {
        self.bytes[8..40].try_into().map_err(|_| Error::Truncated)
    }
    /// Query implied by the carried key, without proof of authority.
    pub fn query(self) -> Result<[u8; 64], Error> {
        Ok(hash512(&self.derived_public_key()?))
    }
    /// Verify the official signature against the block's carried derived key.
    /// This is GNUNET_GNSRECORD_block_verify: it proves possession of that key,
    /// not authority for any requested zone/name, and performs no decryption.
    /// A cache client must separately bind block.query() to its original query.
    pub fn verify_signature(self) -> Result<(), Error> {
        let public = self.derived_public_key()?;
        let mut prefix = [0; 16];
        prefix[..4].copy_from_slice(
            &u32::try_from(self.ciphertext().len() + 16)
                .map_err(|_| Error::TooLarge)?
                .to_be_bytes(),
        );
        prefix[4..8].copy_from_slice(&RECORD_SIGNATURE_PURPOSE.to_be_bytes());
        prefix[8..].copy_from_slice(&self.bytes[104..112]);
        let signature = self.bytes[40..104]
            .try_into()
            .map_err(|_| Error::Truncated)?;
        let parts = [&prefix[..], self.ciphertext()];
        match self.kind {
            ZoneKeyType::Pkey => {
                gns::verify_pkey(&public, RECORD_SIGNATURE_PURPOSE, &parts, &signature)?
            }
            ZoneKeyType::Edkey => {
                gns::verify_edkey(&public, RECORD_SIGNATURE_PURPOSE, &parts, &signature)?
            }
        }
        Ok(())
    }
    /// Verify both the requested zone/name binding and the official purpose
    /// signature. A signature over a block's carried key alone is insufficient.
    pub fn verify_for(self, zone: ZoneKey, label: Label<'_>) -> Result<VerifiedBlock<'a>, Error> {
        if zone.kind() != self.kind {
            return Err(Error::Authentication);
        }
        let expected = gns::derive_public(zone.key(), label.as_str(), "gns")?;
        let public = self.derived_public_key()?;
        if public != expected {
            return Err(Error::Authentication);
        }
        self.verify_signature()?;
        let material = Material::derive(zone, label, self.expiration()?)?;
        Ok(VerifiedBlock {
            block: self,
            material,
        })
    }
}

/// A signature-checked block bound to one original zone and normalized name.
pub struct VerifiedBlock<'a> {
    block: Block<'a>,
    material: Material,
}
impl<'a> VerifiedBlock<'a> {
    /// Borrow the authenticated exact wire bytes.
    #[must_use]
    pub const fn block(&self) -> Block<'a> {
        self.block
    }
    /// Decrypt into caller storage and validate all record framing before
    /// exposing a view. No plaintext is released before signature validation.
    /// `now` is trusted absolute UTC microseconds supplied by the owning host.
    /// Refuse expired blocks and erase written plaintext on parse/auth failure.
    pub fn open_at<'b>(&self, now: u64, output: &'b mut [u8]) -> Result<OpenedRecords<'b>, Error> {
        if self.block.expiration()? < now {
            return Err(Error::Timeout);
        }
        let ciphertext = self.block.ciphertext();
        let plain_len = ciphertext.len()
            - if self.block.kind == ZoneKeyType::Edkey {
                16
            } else {
                0
            };
        if plain_len > MAX_BLOCK_SIZE {
            return Err(Error::TooLarge);
        }
        if output.len() < plain_len {
            return Err(Error::Capacity);
        }
        let plaintext = &mut output[..plain_len];
        match self.block.kind {
            ZoneKeyType::Pkey => {
                plaintext.copy_from_slice(ciphertext);
                symmetric::aes256ctr(&self.material.key, &self.material.aes_iv(), plaintext)?;
            }
            ZoneKeyType::Edkey => symmetric::xsalsa20poly1305_open(
                &self.material.key,
                &self.material.nonce,
                ciphertext,
                plaintext,
            )?,
        }
        if let Err(error) = RecordSet::parse_padded(plaintext, MAX_RECORDS) {
            plaintext.zeroize();
            return Err(error);
        }
        let records = RecordSet::parse_padded(plaintext, MAX_RECORDS)?;
        Ok(OpenedRecords { records, now })
    }
}
/// Fully framed decrypted records. Resolution filters expired/relative records
/// and suppresses shadows until all active records of their type have expired.
pub struct OpenedRecords<'a> {
    records: RecordSet<'a>,
    now: u64,
}
impl<'a> OpenedRecords<'a> {
    /// Iterate applicable records, preserving unknown flags/types and clearing
    /// SHADOW only on selected fallback records. Data borrows the caller buffer.
    #[must_use]
    pub fn iter(&self) -> ApplicableRecords<'a> {
        ApplicableRecords {
            original: self.records,
            remaining: self.records.iter(),
            now: self.now,
        }
    }
}
/// Bounded filtering iterator over an authenticated decrypted record set.
pub struct ApplicableRecords<'a> {
    original: RecordSet<'a>,
    remaining: RecordIter<'a>,
    now: u64,
}
impl<'a> Iterator for ApplicableRecords<'a> {
    type Item = Result<RecordData<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut record = match self.remaining.next()? {
                Ok(record) => record,
                Err(error) => return Some(Err(error)),
            };
            if record.has_relative_expiration() || record.expiration_time < self.now {
                continue;
            }
            if record.flags.contains(RecordFlags::SHADOW) {
                let mut suppressed = false;
                for other in self.original.iter() {
                    let other = match other {
                        Ok(other) => other,
                        Err(error) => return Some(Err(error)),
                    };
                    if other.record_type == record.record_type
                        && !other.has_relative_expiration()
                        && !other.flags.contains(RecordFlags::SHADOW)
                        && other.expiration_time >= self.now
                    {
                        suppressed = true;
                        break;
                    }
                }
                if suppressed {
                    continue;
                }
                record.flags = record.flags.without(RecordFlags::SHADOW);
            }
            return Some(Ok(record));
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Authentication, publication and expiry boundary assertions."
    )]
    use super::*;
    use gnunet_gnsrecord::{RecordType, serialize};
    fn record<'a>(
        kind: RecordType,
        expiry: u64,
        flags: RecordFlags,
        data: &'a [u8],
    ) -> RecordData<'a> {
        RecordData {
            expiration_time: expiry,
            record_type: kind,
            flags,
            data,
        }
    }

    #[test]
    fn filtering_is_order_independent_and_never_returns_relative_or_expired_shadow()
    -> Result<(), Error> {
        let records = [
            record(RecordType::TXT, 50, RecordFlags::SHADOW, b"fallback"),
            record(RecordType::TXT, 10, RecordFlags::NONE, b"active"),
            record(
                RecordType::A,
                100,
                RecordFlags::RELATIVE_EXPIRATION,
                &[192, 0, 2, 1],
            ),
            record(RecordType::TXT, 1, RecordFlags::SHADOW, b"expired"),
        ];
        let mut wire = [0; 256];
        let size = serialize(&records, &mut wire)?;
        let set = RecordSet::parse_padded(&wire[..size], MAX_RECORDS)?;
        let mut at_boundary = OpenedRecords {
            records: set,
            now: 10,
        }
        .iter();
        assert_eq!(at_boundary.next().ok_or(Error::NotFound)??.data, b"active");
        assert!(at_boundary.next().is_none());
        let mut after = OpenedRecords {
            records: set,
            now: 11,
        }
        .iter();
        let selected = after.next().ok_or(Error::NotFound)??;
        assert_eq!(selected.data, b"fallback");
        assert!(!selected.flags.contains(RecordFlags::SHADOW));
        assert!(after.next().is_none());
        let sole = [record(RecordType::TXT, 1, RecordFlags::SHADOW, b"expired")];
        let size = serialize(&sole, &mut wire)?;
        let sole = OpenedRecords {
            records: RecordSet::parse_padded(&wire[..size], MAX_RECORDS)?,
            now: 2,
        };
        assert!(sole.iter().next().is_none());
        Ok(())
    }

    #[test]
    fn publication_converts_relative_removes_private_and_extends_shadow_lifetime()
    -> Result<(), Error> {
        let mut scalars = ['\0'; 20];
        let mut text = [0; 20];
        let label = Label::normalize("test", &mut scalars, &mut text)?;
        let records = [
            record(
                RecordType::TXT,
                10,
                RecordFlags::RELATIVE_EXPIRATION,
                b"active",
            ),
            record(RecordType::TXT, 50, RecordFlags::SHADOW, b"fallback"),
            record(RecordType::TXT, 100, RecordFlags::PRIVATE, b"secret"),
            record(RecordType::TOMBSTONE, 100, RecordFlags::MAINTENANCE, b""),
            record(RecordType::TXT, 4, RecordFlags::NONE, b"expired"),
        ];
        let placeholder = record(RecordType::TXT, 0, RecordFlags::NONE, b"");
        let mut out = [placeholder; 5];
        let public =
            prepare_publication_at(label, &records, 5, |kind| kind == RecordType::TXT, &mut out)?;
        assert_eq!(public.records().len(), 2);
        assert_eq!(public.records()[0].expiration_time, 15);
        assert!(!public.records()[0].has_relative_expiration());
        assert!(public.records()[0].flags.contains(RecordFlags::CRITICAL));
        assert_eq!(public.expiration(), 50);
        let mut small = [placeholder; 1];
        assert!(matches!(
            prepare_publication_at(label, &records, 5, |_| false, &mut small),
            Err(Error::Capacity)
        ));
        assert_eq!(small, [placeholder]);
        let mixed = [
            record(RecordType::EDKEY, 100, RecordFlags::NONE, &[3; 32]),
            record(RecordType::TXT, 100, RecordFlags::NONE, b"invalid"),
        ];
        assert!(matches!(
            prepare_publication_at(label, &mixed, 5, |_| false, &mut out),
            Err(Error::InvalidInput)
        ));
        let mut apex_bytes = [0; 20];
        let apex = Label::normalize("@", &mut scalars, &mut apex_bytes)?;
        assert!(matches!(
            prepare_publication_at(apex, &mixed[..1], 5, |_| false, &mut out),
            Err(Error::InvalidInput)
        ));
        let forever = [record(
            RecordType::TXT,
            u64::MAX,
            RecordFlags::RELATIVE_EXPIRATION,
            b"forever",
        )];
        assert_eq!(
            prepare_publication_at(label, &forever, 5, |_| false, &mut out)?.expiration(),
            u64::MAX
        );
        Ok(())
    }

    #[test]
    fn malformed_padding_and_relative_private_publication_are_refused_atomically()
    -> Result<(), Error> {
        let owner = ZoneSecret::Edkey(EdkeySecret::from_seed([1; 32]));
        let mut chars = ['\0'; 8];
        let mut name = [0; 8];
        let label = Label::normalize("test", &mut chars, &mut name)?;
        let mut wire = [0; 32];
        let mut output = [0xa5; 256];
        for flags in [
            RecordFlags::PRIVATE,
            RecordFlags::MAINTENANCE,
            RecordFlags::RELATIVE_EXPIRATION,
        ] {
            let records = [record(RecordType::TXT, 100, flags, b"x")];
            let size = serialize(&records, &mut wire)?;
            assert!(matches!(
                owner.seal(label, 100, &wire[..size], &mut output),
                Err(Error::InvalidInput)
            ));
            assert_eq!(output, [0xa5; 256]);
        }
        let size = serialize(
            &[record(RecordType::TXT, 100, RecordFlags::NONE, b"x")],
            &mut wire,
        )?;
        wire[size - 1] = 1;
        assert!(matches!(
            owner.seal(label, 100, &wire[..size], &mut output),
            Err(Error::Truncated | Error::Malformed)
        ));
        assert_eq!(output, [0xa5; 256]);
        wire[size - 1] = 0;
        assert!(matches!(
            owner.seal(label, 100, &wire[..size], &mut output[..1]),
            Err(Error::Capacity)
        ));
        assert_eq!(output, [0xa5; 256]);
        assert!(matches!(Block::decode(&[0; 111]), Err(Error::Truncated)));
        let mut bad = [0; 112];
        bad[..4].copy_from_slice(&112_u32.to_be_bytes());
        bad[4..8].copy_from_slice(&65556_u32.to_be_bytes());
        assert!(matches!(Block::decode(&bad), Err(Error::Truncated)));
        Ok(())
    }

    #[test]
    fn excessive_record_count_and_wire_width_are_bounded_before_output() -> Result<(), Error> {
        let owner = ZoneSecret::Pkey(PkeySecret::from_bytes([3; 32])?);
        let mut chars = ['\0'; 4];
        let mut name = [0; 4];
        let label = Label::normalize("test", &mut chars, &mut name)?;
        let records = [record(RecordType::TXT, 100, RecordFlags::NONE, b"x"); MAX_RECORDS + 1];
        let mut plaintext = [0; (MAX_RECORDS + 1) * 17];
        gnunet_gnsrecord::serialize_to_size(&records, &mut plaintext)?;
        let mut output = [0xa5; 256];
        assert!(matches!(
            owner.seal(label, 100, &plaintext, &mut output),
            Err(Error::Capacity)
        ));
        assert_eq!(output, [0xa5; 256]);
        let mut oversized = [0; BLOCK_HEADER_LEN + 65536];
        let size = u32::try_from(oversized.len()).map_err(|_| Error::Overflow)?;
        oversized[..4].copy_from_slice(&size.to_be_bytes());
        oversized[4..8].copy_from_slice(&65536_u32.to_be_bytes());
        assert!(matches!(Block::decode(&oversized), Err(Error::TooLarge)));
        Ok(())
    }

    #[test]
    fn authenticated_bad_tag_and_malformed_plaintext_erase_output() -> Result<(), Error> {
        let seed = [7; 32];
        let owner = ZoneSecret::Edkey(EdkeySecret::from_seed(seed));
        let mut chars = ['\0'; 8];
        let mut text = [0; 8];
        let label = Label::normalize("test", &mut chars, &mut text)?;
        let zone = owner.public_key();
        let mut bytes = [0; 256];
        let mut records = [0; 32];
        let n = serialize(
            &[record(RecordType::TXT, 100, RecordFlags::NONE, b"x")],
            &mut records,
        )?;
        let length = owner
            .seal(label, 100, &records[..n], &mut bytes)?
            .as_bytes()
            .len();
        bytes[112] ^= 1;
        write_purpose(&mut bytes[..length])?;
        let derived = EdkeySecret::from_seed(seed).derive(label.as_str(), "gns")?;
        let signature = derived.sign(15, &[&bytes[96..length]])?;
        bytes[40..104].copy_from_slice(&signature);
        let verified = Block::decode(&bytes[..length])?.verify_for(zone, label)?;
        let mut output = [0xa5; 64];
        assert!(matches!(
            verified.open_at(0, &mut output),
            Err(Error::Authentication)
        ));
        assert_eq!(&output[..n], &[0; 32][..n]);
        assert_eq!(&output[n..], &[0xa5; 64][n..]);
        // Re-sign a correctly encrypted but malformed serialized set, as a
        // malicious authenticated zone owner could do; parsing must erase it.
        records[31] = 1;
        let material = Material::derive(zone, label, 100)?;
        symmetric::xsalsa20poly1305_seal(
            &material.key,
            &material.nonce,
            &records,
            &mut bytes[112..length],
        )?;
        write_purpose(&mut bytes[..length])?;
        let signature = derived.sign(15, &[&bytes[96..length]])?;
        bytes[40..104].copy_from_slice(&signature);
        let verified = Block::decode(&bytes[..length])?.verify_for(zone, label)?;
        output.fill(0xa5);
        assert!(matches!(
            verified.open_at(0, &mut output),
            Err(Error::Malformed | Error::Truncated)
        ));
        assert_eq!(&output[..32], &[0; 32]);
        Ok(())
    }
}
