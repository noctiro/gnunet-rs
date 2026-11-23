//! Allocation-free transitions for original REGEX search queries.

use crate::StateBlock;
use gnunet_regex::{
    Hash,
    accept::{AcceptBlock, Verified},
    first_key,
};
use gnunet_types::Error;

/// Official replication level for REGEX DHT operations.
pub const DHT_REPLICATION: u32 = 5;

/// Which block can be used to advance an original REGEX query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryKind {
    /// State graph edge or terminal state (REGEX).
    State,
    /// A signed match for a fully consumed query (REGEX_ACCEPT).
    Accept,
}

impl QueryKind {
    /// Exact GNUnet DHT block type.
    #[must_use]
    pub const fn block_type(self) -> u32 {
        match self {
            Self::State => 22,
            Self::Accept => 23,
        }
    }

    /// Official DHT options. Only accepting queries record the route.
    #[must_use]
    pub const fn options(self) -> u32 {
        match self {
            Self::State => 1,
            Self::Accept => 3,
        }
    }
}

/// A query coordinate within one original byte string.
///
/// The owner retains the original string and binds each query to a distinct
/// backend operation. Only coordinates within the same original search can
/// be deduplicated, and equality includes key, offset and query kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchQuery {
    key: Hash,
    offset: usize,
    kind: QueryKind,
}

/// Consequence of one fully checked state block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateStep {
    /// Next query, if the block matches or accepts the remaining input.
    pub next: Option<SearchQuery>,
    /// Edges examined for traversal. No edges are examined at end of input.
    pub inspected: usize,
}

impl SearchQuery {
    /// Hash the first at most 24 bytes of the interpreted, NUL-free input.
    ///
    /// # Errors
    /// Rejects an input containing a NUL. The IPC codec supplies the
    /// interpreted bytes excluding the terminator.
    pub fn start(input: &[u8]) -> Result<Self, Error> {
        if input.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let (offset, key) = first_key(input);
        Ok(Self {
            key,
            offset,
            kind: QueryKind::State,
        })
    }

    /// Original state proof hash used as the DHT lookup key.
    #[must_use]
    pub const fn key(&self) -> &Hash {
        &self.key
    }

    /// Number of original bytes consumed so far.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Expected official block kind.
    #[must_use]
    pub const fn kind(self) -> QueryKind {
        self.kind
    }

    /// Check the DHT key and type against the original query.
    ///
    /// The service owner must still correlate the backend operation and check
    /// the DHT value's expiration separately.
    #[must_use]
    pub fn matches_reply(&self, key: &Hash, block_type: u32) -> bool {
        self.key() == key && self.kind.block_type() == block_type
    }

    fn remaining(self, input: &[u8]) -> Result<&[u8], Error> {
        input.get(self.offset..).ok_or(Error::InvalidInput)
    }

    /// Borrow the state xquery payload from the same input, without the NUL.
    /// Accepting queries have no payload, distinct from an empty state suffix.
    ///
    /// # Errors
    /// Rejects an input ending before the offset, or before/after an accepting
    /// query's exact end position.
    pub fn suffix(self, input: &[u8]) -> Result<Option<&[u8]>, Error> {
        let remaining = self.remaining(input)?;
        match self.kind {
            QueryKind::State => Ok(Some(remaining)),
            QueryKind::Accept if remaining.is_empty() => Ok(None),
            QueryKind::Accept => Err(Error::InvalidInput),
        }
    }

    /// Write the NUL-terminated state suffix, or zero bytes for Accept.
    ///
    /// # Errors
    /// Rejects an invalid input position or an output too small for the
    /// complete xquery; on error the output remains unchanged.
    pub fn write_xquery(self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let Some(suffix) = self.suffix(input)? else {
            return Ok(0);
        };
        let length = suffix.len().checked_add(1).ok_or(Error::Overflow)?;
        let out = output.get_mut(..length).ok_or(Error::Capacity)?;
        let (terminator, body) = out.split_last_mut().ok_or(Error::Capacity)?;
        body.copy_from_slice(suffix);
        *terminator = 0;
        Ok(length)
    }

    /// Authenticate the state proof key and select the first longest
    /// nonempty matching edge, or start Accept at a fully consumed state.
    ///
    /// # Errors
    /// Rejects wrong-kind queries, invalid offsets, malformed blocks and a
    /// state proof hash that does not equal the expected key.
    pub fn state(self, input: &[u8], block: &[u8]) -> Result<StateStep, Error> {
        if self.kind != QueryKind::State {
            return Err(Error::InvalidInput);
        }
        let remaining = self.remaining(input)?;
        let state = StateBlock::decode(block)?;
        if state.key() != self.key {
            return Err(Error::Authentication);
        }
        if remaining.is_empty() {
            return Ok(StateStep {
                next: state.accepting().then_some(Self {
                    kind: QueryKind::Accept,
                    ..self
                }),
                inspected: 0,
            });
        }
        let next = state.longest(remaining)?.map(|edge| Self {
            key: edge.destination,
            offset: self.offset + edge.label.len(),
            kind: QueryKind::State,
        });
        Ok(StateStep {
            next,
            inspected: state.edge_count(),
        })
    }

    /// Check the exact accepting block, query key, EdDSA signature and signed
    /// expiration. The result's peer is authenticated independently of
    /// any DHT route metadata.
    ///
    /// # Errors
    /// Rejects wrong-kind queries, invalid or expired accepting blocks, and
    /// a key or signature that fails authentication.
    pub fn accept(self, block: &[u8], now: u64) -> Result<Verified<'_>, Error> {
        if self.kind != QueryKind::Accept {
            return Err(Error::InvalidInput);
        }
        AcceptBlock::decode(block)?.verify(now, self.key())
    }
}
