//! Bounded flat original-message reassembly, independent of communicator tokens.
use crate::{PeerId, p2p::Fragment};
use alloc::vec::Vec;
use gnunet_types::Error;
use zeroize::Zeroizing;

pub(crate) const EXPIRY: u64 = 4 * 60 * 1_000_000;

pub(crate) struct Assembly {
    pub(crate) source: Option<crate::dv_bridge::Source>,
    pub(crate) peer: PeerId,
    pub(crate) id: [u8; 8],
    pub(crate) expires: u64,
    body: Zeroizing<Vec<u8>>,
    seen: Vec<u8>,
    missing: usize,
}
impl Assembly {
    pub(crate) fn new(peer: PeerId, id: [u8; 8], total: u16, now: u64) -> Result<Self, Error> {
        if total < 4 {
            return Err(Error::Malformed);
        }
        let length = usize::from(total);
        let mut body = Vec::new();
        body.try_reserve_exact(length)
            .map_err(|_| Error::Capacity)?;
        body.resize(length, 0);
        let mut seen = Vec::new();
        seen.try_reserve_exact(length.div_ceil(8))
            .map_err(|_| Error::Capacity)?;
        seen.resize(length.div_ceil(8), 0);
        Ok(Self {
            source: None,
            peer,
            id,
            expires: now.saturating_add(EXPIRY),
            body: Zeroizing::new(body),
            seen,
            missing: length,
        })
    }
    pub(crate) fn bind_source(mut self, source: Option<crate::dv_bridge::Source>) -> Self {
        self.source = source;
        self
    }
    pub(crate) fn charge(&self) -> usize {
        self.body.len() + self.seen.len()
    }
    pub(crate) fn insert(&mut self, fragment: Fragment<'_>) -> Result<bool, Error> {
        let offset = usize::from(fragment.offset);
        if fragment.message_id != self.id
            || usize::from(fragment.total) != self.body.len()
            || fragment.body.is_empty()
            || offset
                .checked_add(fragment.body.len())
                .ok_or(Error::Overflow)?
                > self.body.len()
        {
            return Err(Error::Malformed);
        }
        // Validate all overlaps before changing any byte or coverage count.
        for (i, value) in fragment.body.iter().enumerate() {
            let index = offset + i;
            if self.seen[index / 8] & (1 << (index % 8)) != 0 && self.body[index] != *value {
                return Err(Error::Malformed);
            }
        }
        for (i, value) in fragment.body.iter().enumerate() {
            let index = offset + i;
            let mask = 1 << (index % 8);
            if self.seen[index / 8] & mask == 0 {
                self.seen[index / 8] |= mask;
                self.body[index] = *value;
                self.missing -= 1;
            }
        }
        Ok(self.missing == 0)
    }
    pub(crate) fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}
