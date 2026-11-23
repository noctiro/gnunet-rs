//! Sorted, unique provenance for locally observed service identities.

use crate::Error;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_types::Error as Fault;
use zeroize::Zeroize;

type Peer = [u8; 32];

enum Storage<'id> {
    #[cfg(feature = "alloc")]
    Heap(Vec<Peer>),
    Fixed {
        cells: &'id mut [Peer],
        len: usize,
    },
}

pub(crate) struct SignerTable<'id>(Storage<'id>);

impl<'id> SignerTable<'id> {
    #[cfg(feature = "alloc")]
    pub const fn new() -> Self {
        Self(Storage::Heap(Vec::new()))
    }

    pub fn fixed(cells: &'id mut [Peer], limit: usize) -> Result<Self, Error> {
        if cells.len() != limit {
            return Err(Fault::Capacity.into());
        }
        cells.iter_mut().zeroize();
        Ok(Self(Storage::Fixed { cells, len: 0 }))
    }

    pub fn required_bytes(limit: usize) -> Result<usize, Error> {
        limit
            .checked_mul(size_of::<Peer>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.capacity())
    }

    pub fn peers(&self) -> &[Peer] {
        match &self.0 {
            #[cfg(feature = "alloc")]
            Storage::Heap(peers) => peers,
            Storage::Fixed { cells, len } => &cells[..*len],
        }
    }

    /// Store a new observation, returning only the additional retained charge.
    /// Heap growth must fit beside the old allocation until copying finishes.
    pub fn remember(&mut self, peer: Peer, limit: usize, budget: usize) -> Result<usize, Error> {
        let index = match self.peers().binary_search(&peer) {
            Ok(_) => return Ok(0),
            Err(index) => index,
        };
        let len = self.peers().len();
        if len >= limit {
            return Err(Fault::Capacity.into());
        }
        let added = if len == self.capacity() {
            let target = len.checked_mul(2).ok_or(Fault::Overflow)?.max(1).min(limit);
            self.reserve(target, budget)?
        } else {
            0
        };
        match &mut self.0 {
            #[cfg(feature = "alloc")]
            Storage::Heap(peers) => peers.insert(index, peer),
            Storage::Fixed { cells, len } => {
                cells.copy_within(index..*len, index + 1);
                cells[index] = peer;
                *len += 1;
            }
        }
        Ok(added)
    }

    /// Restore an already bounded archive prefix into a new table.
    pub fn restore(&mut self, peers: &[Peer], budget: usize) -> Result<usize, Error> {
        if !self.peers().is_empty() {
            return Err(Fault::Conflict.into());
        }
        if peers.windows(2).any(|p| p[0] >= p[1]) {
            return Err(Fault::Malformed.into());
        }
        let added = self.reserve(peers.len(), budget)?;
        match &mut self.0 {
            #[cfg(feature = "alloc")]
            Storage::Heap(stored) => stored.extend_from_slice(peers),
            Storage::Fixed { cells, len } => {
                cells[..peers.len()].copy_from_slice(peers);
                *len = peers.len();
            }
        }
        Ok(added)
    }

    fn capacity(&self) -> usize {
        match &self.0 {
            #[cfg(feature = "alloc")]
            Storage::Heap(peers) => peers.capacity(),
            Storage::Fixed { cells, .. } => cells.len(),
        }
    }

    fn reserve(&mut self, target: usize, budget: usize) -> Result<usize, Error> {
        if target <= self.capacity() {
            return Ok(0);
        }
        #[cfg(not(feature = "alloc"))]
        let _ = budget;
        match &mut self.0 {
            #[cfg(feature = "alloc")]
            Storage::Heap(current) => Self::grow(current, target, budget),
            Storage::Fixed { .. } => Err(Fault::Capacity.into()),
        }
    }

    #[cfg(feature = "alloc")]
    fn grow(current: &mut Vec<Peer>, target: usize, budget: usize) -> Result<usize, Error> {
        if Self::required_bytes(target)? > budget {
            return Err(Fault::Capacity.into());
        }
        let mut next = Vec::new();
        next.try_reserve_exact(target)
            .map_err(|_| Fault::Capacity)?;
        let bytes = Self::required_bytes(next.capacity())?;
        if bytes > budget {
            return Err(Fault::Capacity.into());
        }
        let growth = bytes - Self::required_bytes(current.capacity())?;
        next.extend_from_slice(current);
        current.zeroize();
        *current = next;
        Ok(growth)
    }
}

impl Drop for SignerTable<'_> {
    fn drop(&mut self) {
        match &mut self.0 {
            #[cfg(feature = "alloc")]
            Storage::Heap(peers) => peers.zeroize(),
            Storage::Fixed { cells, .. } => cells.iter_mut().zeroize(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check caller-owned provenance ordering, charge and erasure"
    )]
    fn fixed_provenance_restores_and_grows_within_its_charged_cells() -> Result<(), Error> {
        let mut cells = [[7; 32]; 2];
        let mut table = SignerTable::fixed(&mut cells, 2)?;
        assert_eq!(table.bytes()?, SignerTable::required_bytes(2)?);
        assert_eq!(
            table.restore(&[[4; 32], [3; 32]], 0),
            Err(Fault::Malformed.into())
        );
        assert_eq!(table.restore(&[[4; 32]], 0)?, 0);
        assert_eq!(table.remember([3; 32], 2, 0)?, 0);
        assert_eq!(table.remember([3; 32], 2, 0)?, 0);
        assert_eq!(table.remember([5; 32], 2, 0), Err(Fault::Capacity.into()));
        assert_eq!(table.peers(), &[[3; 32], [4; 32]]);
        drop(table);
        assert_eq!(cells, [[0; 32]; 2]);
        Ok(())
    }
}
