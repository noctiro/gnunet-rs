//! Defined regex block helper behavior, with explicit safe bounds rejection.
use crate::{Hash, ReturnValue};
use gnunet_crypto::hash512;
use gnunet_types::Error;
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let value = bytes.get(offset..offset + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}
/// Borrowed structural prefix. Source get_key deliberately does not validate
/// edge token totals; an accepting-state early return also bypasses iteration.
#[derive(Clone, Copy, Debug)]
pub struct State<'a> {
    bytes: &'a [u8],
    destinations: usize,
    edges: usize,
    proof_start: usize,
    proof_len: usize,
}
impl<'a> State<'a> {
    /// Validate only the original fixed/destination/edge/proof prefix.
    pub fn parse_prefix(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 8 {
            return Err(Error::Truncated);
        }
        let destinations = usize::from(u16_at(bytes, 6)?);
        let edges = usize::from(u16_at(bytes, 4)?);
        let proof_len = usize::from(u16_at(bytes, 0)?);
        let proof_start = 8 + destinations * 64 + edges * 4;
        let end = proof_start.checked_add(proof_len).ok_or(Error::Overflow)?;
        if bytes.len() < end {
            return Err(Error::Truncated);
        }
        Ok(Self {
            bytes,
            destinations,
            edges,
            proof_start,
            proof_len,
        })
    }
    /// The exact proof-byte SHA512, independent of accepting flag and token bytes.
    #[must_use]
    pub fn key(self) -> Hash {
        hash512(&self.bytes[self.proof_start..self.proof_start + self.proof_len])
    }
    /// Raw network u16 flag, as source ntohs on its int16 field.
    pub fn accepting(self) -> Result<u16, Error> {
        u16_at(self.bytes, 2)
    }
    /// Match source REGEX_BLOCK_check. None is a NULL xquery, distinct from a
    /// present empty C string. A present slice must contain its terminator. Source
    /// out-of-range destination pointer construction is safely rejected here.
    pub fn check(self, query: Option<&Hash>, xquery: Option<&[u8]>) -> Result<ReturnValue, Error> {
        if query.is_some_and(|query| *query != self.key()) {
            return Ok(ReturnValue::SysErr);
        }
        let xquery = match xquery {
            None => None,
            Some(bytes) => Some(
                bytes
                    .split(|b| *b == 0)
                    .next()
                    .filter(|_| bytes.contains(&0))
                    .ok_or(Error::Malformed)?,
            ),
        };
        if self.accepting()? == 1 && xquery.is_none_or(|query| query.is_empty()) {
            return Ok(ReturnValue::Yes);
        }
        let edges_start = 8 + self.destinations * 64;
        let mut expected = self.proof_start + self.proof_len;
        for index in 0..self.edges {
            expected = expected
                .checked_add(usize::from(u16_at(
                    self.bytes,
                    edges_start + index * 4 + 2,
                )?))
                .ok_or(Error::Overflow)?;
        }
        if expected != self.bytes.len() {
            return Ok(ReturnValue::SysErr);
        }
        let mut cursor = self.proof_start + self.proof_len;
        let mut found = false;
        for index in 0..self.edges {
            let row = edges_start + index * 4;
            let destination = usize::from(u16_at(self.bytes, row)?);
            let len = usize::from(u16_at(self.bytes, row + 2)?);
            if destination >= self.destinations {
                return Err(Error::Malformed);
            }
            let token = self
                .bytes
                .get(cursor..cursor + len)
                .ok_or(Error::Truncated)?;
            if let Some(query) = xquery
                && query.len() >= len
                && query[..len] == *token
            {
                found = true;
            }
            cursor += len;
        }
        Ok(if xquery.is_none() || found {
            ReturnValue::Yes
        } else {
            ReturnValue::No
        })
    }
}
