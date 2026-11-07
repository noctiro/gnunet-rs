//! Durable knowledge restored from the actual marked snapshot is not fresh PoW
//! validation. Accepted facts remain revoked even after original admission expiry.
use gnunet_gnsrecord::ZoneKey;
use gnunet_revocation::{Certificate, CheckedCertificate, PROOF_BYTES, RevocationConfig};
use gnunet_snapshot_host::{Namespace, backend::Loaded};
use gnunet_types::Error;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"GNRVDB01";
const PREFIX: usize = 16;
const FACT: usize = 24 + PROOF_BYTES;
/// Original durably accepted public knowledge. This type never mints a fresh
/// CheckedCertificate; getters expose only persisted public fields/provenance.
#[derive(Clone)]
pub struct StoredFact {
    certificate: Certificate,
    score: u32,
    policy: RevocationConfig,
    accepted_at: u64,
}

impl StoredFact {
    /// Exact original public certificate retained in full, never an8-byte header.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
    /// Original accepted score metadata; not a claim it was recomputed on recovery.
    pub const fn score(&self) -> u32 {
        self.score
    }
    /// Original policy used by that durable acceptance.
    pub const fn policy(&self) -> RevocationConfig {
        self.policy
    }
    /// Original acceptance time, not this startup's clock sample.
    pub const fn accepted_at(&self) -> u64 {
        self.accepted_at
    }
    fn checked(checked: CheckedCertificate) -> Self {
        Self {
            certificate: checked.certificate().clone(),
            score: checked.score(),
            policy: checked.policy(),
            accepted_at: checked.checked_at(),
        }
    }
}
/// Finite permanent revocation inventory. Only actual marked Loaded recovers it;
/// host-only staged state stays separate until an exact durable commit receipt.
pub struct Inventory {
    pub(super) records: Vec<StoredFact>,
    index: Vec<usize>,
    pub(super) generation: u64,
    pub(super) maximum: usize,
    pub(super) body_bytes: usize,
    pub(super) blocked: bool,
}
pub(super) struct Planned {
    pub records: Vec<StoredFact>,
    position: usize,
}
fn index(records: &[StoredFact], maximum: usize) -> Result<Vec<usize>, Error> {
    let mut index = Vec::new();
    index
        .try_reserve_exact(maximum)
        .map_err(|_| Error::Capacity)?;
    index.extend(0..records.len());
    index.sort_unstable_by(|&a, &b| {
        records[a]
            .certificate
            .public_encoding()
            .cmp(records[b].certificate.public_encoding())
    });
    if index.windows(2).any(|pair| {
        records[pair[0]].certificate.public_encoding()
            == records[pair[1]].certificate.public_encoding()
    }) {
        return Err(Error::Conflict);
    }
    Ok(index)
}
fn read32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn read64(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
impl Inventory {
    /// Consume actual shared-store recovery, checking the exact namespace before
    /// interpreting any opaque body. No C/foreign/unmarked DB is adopted.
    pub fn recover(loaded: Loaded, maximum: usize, body_bytes: usize) -> Result<Self, Error> {
        if loaded.namespace() != Namespace::Revocation || maximum == 0 || body_bytes < PREFIX {
            return Err(Error::Authentication);
        }
        let generation = loaded.generation();
        if generation == 0 && !loaded.created_directory() {
            return Err(Error::OutcomeUnknown);
        }
        let bytes = loaded.into_body();
        let mut records = Vec::new();
        records
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        if bytes.is_empty() && generation != 0 {
            return Err(Error::Malformed);
        }
        if !bytes.is_empty() {
            if bytes.len() > body_bytes
                || bytes.len() < PREFIX
                || &bytes[..8] != MAGIC
                || read32(&bytes, 12)? != 0
            {
                return Err(Error::Malformed);
            }
            let count = usize::try_from(read32(&bytes, 8)?).map_err(|_| Error::Overflow)?;
            if count > maximum
                || count.checked_mul(FACT).and_then(|n| n.checked_add(PREFIX)) != Some(bytes.len())
            {
                return Err(Error::Malformed);
            }
            for row in bytes[PREFIX..].as_chunks::<FACT>().0 {
                let accepted_at = read64(row, 0)?;
                let score = read32(row, 8)?;
                let policy = RevocationConfig {
                    matching_bits: read32(row, 12)?,
                    epoch_duration: read64(row, 16)?,
                };
                let certificate = Certificate::copy(gnunet_revocation::Proof::parse(&row[24..])?);
                let proof = certificate.proof()?;
                if score > 512
                    || policy.matching_bits >= 512
                    || policy.epoch_duration == 0
                    || !proof.ordered()
                    || gnunet_block::revocation::valid_at(
                        score,
                        policy,
                        proof.timestamp(),
                        accepted_at,
                    ) != gnunet_block::ReturnValue::Yes
                {
                    return Err(Error::Malformed);
                }
                records.push(StoredFact {
                    certificate,
                    score,
                    policy,
                    accepted_at,
                });
            }
        }
        let index = index(&records, maximum)?;
        Ok(Self {
            records,
            index,
            generation,
            maximum,
            body_bytes,
            blocked: false,
        })
    }
    /// Number of actual durable accepted facts.
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Whether no durable accepted fact exists.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Actual original committed storage generation, independent of network writes.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Permanent known-revoked result; expiry cannot revive accepted keys.
    pub fn revoked(&self, key: ZoneKey) -> bool {
        let key = key.to_wire();
        self.index
            .binary_search_by(|&i| self.records[i].certificate.public_encoding().cmp(&key))
            .is_ok()
    }
    /// Immutable public inventory for new flooding/anti-entropy intents.
    pub fn facts(&self) -> impl ExactSizeIterator<Item = &StoredFact> {
        self.records.iter()
    }
    pub(super) fn plan(
        &self,
        checked: CheckedCertificate,
        policy: RevocationConfig,
        now: u64,
    ) -> Result<Planned, Error> {
        if self.blocked {
            return Err(Error::OutcomeUnknown);
        }
        if !checked.current_at(policy, now)? {
            return Err(Error::Authentication);
        }
        if self.records.len() == self.maximum {
            return Err(Error::Capacity);
        }
        let position = self
            .index
            .binary_search_by(|&i| {
                self.records[i]
                    .certificate
                    .public_encoding()
                    .cmp(checked.certificate().public_encoding())
            })
            .err()
            .ok_or(Error::Conflict)?;
        let mut after = Vec::new();
        after
            .try_reserve_exact(self.maximum)
            .map_err(|_| Error::Capacity)?;
        after.extend(self.records.iter().cloned());
        after.push(StoredFact::checked(checked));
        Ok(Planned {
            records: after,
            position,
        })
    }
    pub(super) fn publish(&mut self, planned: Planned) -> Result<(), Error> {
        // All capacity was reserved before admission. Record order stays append
        // only, so existing peer cursors retain their original meaning.
        if planned.records.len() != self.records.len().checked_add(1).ok_or(Error::Overflow)?
            || planned.records.len() > self.maximum
            || self.index.capacity() < planned.records.len()
            || planned.position > self.index.len()
        {
            self.blocked = true;
            return Err(Error::OutcomeUnknown);
        }
        let added = self.records.len();
        self.records = planned.records;
        self.index.insert(planned.position, added);
        Ok(())
    }
    pub(super) fn image(&self, records: &[StoredFact]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let n = records
            .len()
            .checked_mul(FACT)
            .and_then(|n| n.checked_add(PREFIX))
            .ok_or(Error::Overflow)?;
        if n > self.body_bytes {
            return Err(Error::Capacity);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
        out.resize(n, 0);
        out[..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(
            &u32::try_from(records.len())
                .map_err(|_| Error::Capacity)?
                .to_be_bytes(),
        );
        for (row, record) in out[PREFIX..]
            .as_chunks_mut::<FACT>()
            .0
            .iter_mut()
            .zip(records)
        {
            row[..8].copy_from_slice(&record.accepted_at.to_be_bytes());
            row[8..12].copy_from_slice(&record.score.to_be_bytes());
            row[12..16].copy_from_slice(&record.policy.matching_bits.to_be_bytes());
            row[16..24].copy_from_slice(&record.policy.epoch_duration.to_be_bytes());
            row[24..].copy_from_slice(record.certificate.bytes());
        }
        Ok(Zeroizing::new(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_gnsrecord::ZoneKeyType;

    // Public structural rows only: no checked proof, Loaded/storage, hashing,
    // worker, key constructor, signature or native provider is created.
    fn row(value: u8) -> StoredFact {
        StoredFact {
            certificate: Certificate::from_parts(
                ZoneKey::new(ZoneKeyType::Edkey, [value; 32]),
                1,
                0,
                &[0; 32],
                &[0; 64],
            ),
            score: 0,
            policy: gnunet_revocation::DEFAULT_POLICY,
            accepted_at: 1,
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Public index assertions with fallible bounded allocation"
    )]
    fn public_index_preserves_append_order_and_rejects_duplicates() -> Result<(), Error> {
        let records = vec![row(3), row(1)];
        let mut inventory = Inventory {
            index: index(&records, 3)?,
            records,
            generation: 1,
            maximum: 3,
            body_bytes: 4096,
            blocked: false,
        };
        assert!(inventory.revoked(ZoneKey::new(ZoneKeyType::Edkey, [1; 32])));
        assert!(!inventory.revoked(ZoneKey::new(ZoneKeyType::Edkey, [2; 32])));
        let mut records = inventory.records.clone();
        records.push(row(0));
        inventory.publish(Planned {
            records,
            position: 0,
        })?;
        assert_eq!(
            inventory.records[0].certificate.bytes(),
            row(3).certificate.bytes()
        );
        assert_eq!(
            inventory.records[1].certificate.bytes(),
            row(1).certificate.bytes()
        );
        assert_eq!(
            inventory.records[2].certificate.bytes(),
            row(0).certificate.bytes()
        );
        assert_eq!(inventory.index, [2, 1, 0]);
        assert!(inventory.revoked(ZoneKey::new(ZoneKeyType::Edkey, [0; 32])));
        assert!(matches!(index(&[row(1), row(1)], 2), Err(Error::Conflict)));
        Ok(())
    }
}
