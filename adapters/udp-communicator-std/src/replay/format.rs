//! Exact existing identity-bound replay image and checked record bounds.
use super::{CHECKSUM, HEADER, JournalError, PeerId};
use gnunet_types::Error;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Record {
    pub(super) peer: PeerId,
    pub(super) monotonic: u64,
}
#[derive(Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) highwater: u64,
    pub(super) records: Vec<Record>,
}
impl Snapshot {
    pub(super) fn duplicate(&self, maximum: usize) -> Result<Self, JournalError> {
        let mut records = Vec::new();
        records
            .try_reserve_exact(
                self.records
                    .len()
                    .checked_add(1)
                    .ok_or(Error::Overflow)?
                    .min(maximum),
            )
            .map_err(|_| Error::Capacity)?;
        records.extend_from_slice(&self.records);
        Ok(Self {
            highwater: self.highwater,
            records,
        })
    }
    pub(super) fn encode(&self, local: PeerId) -> Result<Vec<u8>, JournalError> {
        let size = HEADER
            .checked_add(self.records.len().checked_mul(40).ok_or(Error::Overflow)?)
            .and_then(|n| n.checked_add(CHECKSUM))
            .ok_or(Error::Overflow)?;
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
        out.extend_from_slice(b"GUR1");
        out.extend_from_slice(&local);
        out.extend_from_slice(&self.highwater.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(self.records.len())
                .map_err(|_| Error::TooLarge)?
                .to_be_bytes(),
        );
        for record in &self.records {
            out.extend_from_slice(&record.peer);
            out.extend_from_slice(&record.monotonic.to_be_bytes());
        }
        let checksum = gnunet_crypto::hash256(&out);
        out.extend_from_slice(&checksum);
        Ok(out)
    }
    pub(super) fn decode(
        input: &[u8],
        local: PeerId,
        maximum: usize,
    ) -> Result<Self, JournalError> {
        if input.len() < HEADER + CHECKSUM || input.get(..4) != Some(b"GUR1") {
            return Err(Error::Storage.into());
        }
        if input.get(4..36) != Some(local.as_slice()) {
            return Err(Error::Authentication.into());
        }
        let count =
            u32::from_be_bytes(input[44..48].try_into().map_err(|_| Error::Truncated)?) as usize;
        let length = HEADER
            .checked_add(count.checked_mul(40).ok_or(Error::Overflow)?)
            .and_then(|n| n.checked_add(CHECKSUM))
            .ok_or(Error::Overflow)?;
        if count > maximum || input.len() != length {
            return Err(Error::Storage.into());
        }
        if input[length - CHECKSUM..] != gnunet_crypto::hash256(&input[..length - CHECKSUM]) {
            return Err(Error::Storage.into());
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        for raw in input[HEADER..length - CHECKSUM].as_chunks::<40>().0 {
            let peer = raw[..32].try_into().map_err(|_| Error::Truncated)?;
            if records
                .last()
                .is_some_and(|previous: &Record| previous.peer >= peer)
            {
                return Err(Error::Storage.into());
            }
            records.push(Record {
                peer,
                monotonic: u64::from_be_bytes(raw[32..].try_into().map_err(|_| Error::Truncated)?),
            });
        }
        Ok(Self {
            highwater: u64::from_be_bytes(input[36..44].try_into().map_err(|_| Error::Truncated)?),
            records,
        })
    }
}
