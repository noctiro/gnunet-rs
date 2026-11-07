//! Old SET's 32 independent native-column strata, not SETU's estimator format.
use crate::{
    Snapshot,
    ibf::{self, Ibf, Peel},
    wire::IbfSlice,
};
use alloc::vec::Vec;
use gnunet_types::Error;
pub(crate) struct Strata {
    pub filters: Vec<Ibf>,
    cursor: usize,
}
impl Strata {
    pub fn allocation_peak() -> Result<usize, Error> {
        ibf::STRATA
            .checked_mul(core::mem::size_of::<Ibf>())
            .and_then(|n| {
                ibf::STRATA
                    .checked_mul(ibf::STRATUM_BUCKETS)
                    .and_then(|cells| cells.checked_mul(core::mem::size_of::<ibf::Cell>()))
                    .and_then(|cells| n.checked_add(cells))
            })
            .ok_or(Error::Overflow)
    }
    pub fn new(snapshot: &Snapshot) -> Result<Self, Error> {
        let mut filters = Vec::new();
        filters
            .try_reserve_exact(ibf::STRATA)
            .map_err(|_| Error::Capacity)?;
        if filters.capacity() > ibf::STRATA {
            return Err(Error::Capacity);
        }
        for _ in 0..ibf::STRATA {
            filters.push(Ibf::new(
                ibf::STRATUM_BUCKETS,
                ibf::STRATUM_BUCKETS,
                snapshot.abi().order,
            )?);
        }
        Ok(Self { filters, cursor: 0 })
    }
    pub fn build(&mut self, snapshot: &Snapshot) -> Result<bool, Error> {
        let end = self.cursor.saturating_add(32).min(snapshot.len());
        for index in self.cursor..end {
            let key = ibf::element_key(
                snapshot.hash(index).ok_or(Error::Stale)?,
                snapshot.abi().order,
            )?;
            // The reference's out-of-range shift/index is not protocol authority.
            // Saturating this estimator hint keeps every real key in a valid stratum.
            let stratum = (key.trailing_ones() as usize).min(ibf::STRATA - 1);
            self.filters[stratum].add(key, 1)?;
        }
        self.cursor = end;
        Ok(self.cursor == snapshot.len())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(ibf::STRATA_BYTES)
            .map_err(|_| Error::Capacity)?;
        if bytes.capacity() > ibf::STRATA_BYTES {
            return Err(Error::Capacity);
        }
        for filter in &self.filters {
            bytes.extend_from_slice(&filter.encode_slice(0, ibf::STRATUM_BUCKETS)?);
        }
        Ok(bytes)
    }
    pub fn difference(
        &self,
        remote: &[u8],
        stratum: usize,
        running: u64,
    ) -> Result<(u64, bool), Error> {
        if remote.len() != ibf::STRATA_BYTES || stratum >= ibf::STRATA {
            return Err(Error::Malformed);
        }
        let mut diff = Ibf::new(
            ibf::STRATUM_BUCKETS,
            ibf::STRATUM_BUCKETS,
            self.filters[stratum].order(),
        )?;
        let start = stratum * ibf::STRATUM_BYTES;
        diff.receive_slice(
            0,
            IbfSlice::decode(&remote[start..start + ibf::STRATUM_BYTES])?,
        )?;
        diff.subtract(&self.filters[stratum])?;
        let mut count = 0u64;
        loop {
            match diff.peel()? {
                Peel::Item { .. } if count < ibf::STRATUM_BUCKETS as u64 => count += 1,
                Peel::Empty => {
                    return Ok((
                        running.checked_add(count).ok_or(Error::Overflow)?,
                        stratum == 0,
                    ));
                }
                _ => {
                    let total = running.checked_add(count).ok_or(Error::Overflow)?;
                    return Ok((
                        total
                            .checked_mul(1u64 << (stratum + 1))
                            .ok_or(Error::Overflow)?,
                        true,
                    ));
                }
            }
        }
    }
    pub fn charged(&self) -> Result<usize, Error> {
        self.filters.iter().try_fold(
            self.filters
                .capacity()
                .checked_mul(core::mem::size_of::<Ibf>())
                .ok_or(Error::Overflow)?,
            |n, f| {
                n.checked_add(
                    f.cells
                        .capacity()
                        .checked_mul(core::mem::size_of::<ibf::Cell>())
                        .ok_or(Error::Overflow)?,
                )
                .ok_or(Error::Overflow)
            },
        )
    }
}
