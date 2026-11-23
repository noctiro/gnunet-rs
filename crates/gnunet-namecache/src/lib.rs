//! Independent official NAMECACHE response validation and ciphertext cache.
//! No zone secrets, record plaintext, resolver, host recovery, or native I/O.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod cache;
#[cfg(feature = "alloc")]
pub use cache::{Cache, Limits, Stats};
/// Fixed, caller-owned storage for opaque encrypted GNS blocks.
pub mod fixed;
/// Existing official encrypted block view; signature checks use public keys only.
pub use gnunet_gnscrypto::Block;
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, namecache::Response};

/// Actual memory-cache result, separate from a native publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertOutcome {
    /// A previously absent query now has a stored block.
    Inserted,
    /// Same or later expiration replaced the old block with the actual new bytes.
    Replaced,
    /// Equal expiration and identical bytes were already present.
    AlreadyPresent,
    /// An existing later-expiring version remains authoritative for lookup.
    RetainedNewer,
}

#[derive(Clone, Copy)]
struct BlockInfo {
    query: [u8; 64],
    expiration: AbsoluteTime,
}

impl BlockInfo {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let block = Block::decode(bytes)?;
        Ok(Self {
            query: block.query()?,
            expiration: AbsoluteTime::from_micros(block.expiration()?),
        })
    }

    fn retained(self, existing: &[u8], incoming: Self, proposed: &[u8]) -> Option<InsertOutcome> {
        if self.expiration > incoming.expiration {
            Some(InsertOutcome::RetainedNewer)
        } else if self.expiration == incoming.expiration && existing == proposed {
            Some(InsertOutcome::AlreadyPresent)
        } else {
            None
        }
    }
}

fn lookup_response(rid: u32, block: Option<Block<'_>>) -> Result<Response<'_>, Error> {
    let (expiration, block) = match block {
        Some(block) => (
            AbsoluteTime::from_micros(block.expiration()?),
            block.as_bytes(),
        ),
        None => (AbsoluteTime::UNIX_EPOCH, &[][..]),
    };
    Ok(Response::Lookup {
        rid,
        expiration,
        block,
    })
}

/// Check a lookup response against its original query using public material
/// only. Expiration0 is the official miss sentinel, even with a nonempty body.
/// Hits require exact block framing, matching query and inner/outer expiration,
/// and the official carried-key signature. This proves no zone/name authority
/// and does not decrypt. Expiry filtering belongs to the calling cache consumer;
/// the native reference cache can return blocks pending periodic expiration.
pub fn verify_lookup<'a>(
    query: &[u8; 64],
    expiration: AbsoluteTime,
    body: &'a [u8],
) -> Result<Option<Block<'a>>, Error> {
    if expiration == AbsoluteTime::UNIX_EPOCH {
        return Ok(None);
    }
    let block = Block::decode(body)?;
    if block.expiration()? != expiration.as_micros() {
        return Err(Error::Malformed);
    }
    if block.query()? != *query {
        return Err(Error::Authentication);
    }
    block.verify_signature()?;
    Ok(Some(block))
}
