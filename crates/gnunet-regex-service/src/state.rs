//! Strict noalloc original state-block view. All edges are checked before use.
use gnunet_regex::Hash;
use gnunet_types::Error;
fn u16_at(bytes: &[u8], at: usize) -> Result<usize, Error> {
    let b = bytes.get(at..at + 2).ok_or(Error::Truncated)?;
    Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
}
/// Original borrowed block; construction checks the complete token collection.
#[derive(Clone, Copy, Debug)]
pub struct StateBlock<'a> {
    bytes: &'a [u8],
    destinations: usize,
    edges: usize,
    rows: usize,
    proof_start: usize,
    proof_end: usize,
}
/// One literal byte edge, with the actual original destination proof hash.
#[derive(Clone, Copy, Debug)]
pub struct StateEdge<'a> {
    /// Exact original destination proof key.
    pub destination: Hash,
    /// Non-NUL literal token; an empty token is not followed during traversal.
    pub label: &'a [u8],
}
impl<'a> StateBlock<'a> {
    /// Decode exactly the official deduplicated destination/edge/proof/token layout.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() >= gnunet_regex::MAX_BLOCK_BYTES {
            return Err(Error::TooLarge);
        }
        let destinations = u16_at(bytes, 6)?;
        let edges = u16_at(bytes, 4)?;
        let rows = 8 + destinations * 64;
        let proof_start = rows + edges * 4;
        let proof_end = proof_start
            .checked_add(u16_at(bytes, 0)?)
            .ok_or(Error::Overflow)?;
        let proof = bytes.get(proof_start..proof_end).ok_or(Error::Truncated)?;
        if proof.contains(&0) {
            return Err(Error::Malformed);
        }
        let mut at = proof_end;
        for i in 0..edges {
            if u16_at(bytes, rows + i * 4)? >= destinations {
                return Err(Error::Malformed);
            }
            let length = u16_at(bytes, rows + i * 4 + 2)?;
            let end = at.checked_add(length).ok_or(Error::Overflow)?;
            let token = bytes.get(at..end).ok_or(Error::Truncated)?;
            if token.contains(&0) {
                return Err(Error::Malformed);
            }
            at = end;
        }
        if at != bytes.len() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes,
            destinations,
            edges,
            rows,
            proof_start,
            proof_end,
        })
    }
    /// Exact original proof, with no synthetic NUL.
    #[must_use]
    pub fn proof(self) -> &'a [u8] {
        &self.bytes[self.proof_start..self.proof_end]
    }
    /// Official state key, SHA512 of the complete proof bytes.
    #[must_use]
    pub fn key(self) -> Hash {
        gnunet_regex::proof_key(self.proof())
    }
    /// Only the official integer YES1 denotes acceptance.
    #[must_use]
    pub fn accepting(self) -> bool {
        self.bytes[2..4] == [0, 1]
    }
    /// Number of completely checked literal edges.
    #[must_use]
    pub fn edge_count(self) -> usize {
        self.edges
    }
    /// Borrow an exact edge without allocating or imposing UTF8.
    pub fn edge(self, index: usize) -> Result<StateEdge<'a>, Error> {
        if index >= self.edges {
            return Err(Error::InvalidInput);
        }
        let mut at = self.proof_end;
        for i in 0..index {
            at += u16_at(self.bytes, self.rows + i * 4 + 2)?;
        }
        let size = u16_at(self.bytes, self.rows + index * 4 + 2)?;
        let destination = u16_at(self.bytes, self.rows + index * 4)?;
        if destination >= self.destinations {
            return Err(Error::Malformed);
        }
        Ok(StateEdge {
            destination: self.bytes[8 + destination * 64..8 + (destination + 1) * 64]
                .try_into()
                .map_err(|_| Error::Truncated)?,
            label: &self.bytes[at..at + size],
        })
    }
    /// Official traversal chooses the first longest nonempty matching edge.
    pub fn longest(self, remaining: &[u8]) -> Result<Option<StateEdge<'a>>, Error> {
        let mut found: Option<StateEdge<'a>> = None;
        let mut at = self.proof_end;
        for index in 0..self.edges {
            let row = self.rows + index * 4;
            let destination = u16_at(self.bytes, row)?;
            let size = u16_at(self.bytes, row + 2)?;
            let label = &self.bytes[at..at + size];
            at += size;
            if !label.is_empty()
                && remaining.starts_with(label)
                && found.is_none_or(|old| label.len() > old.label.len())
            {
                found = Some(StateEdge {
                    destination: self.bytes[8 + destination * 64..8 + (destination + 1) * 64]
                        .try_into()
                        .map_err(|_| Error::Truncated)?,
                    label,
                });
            }
        }
        Ok(found)
    }
}
