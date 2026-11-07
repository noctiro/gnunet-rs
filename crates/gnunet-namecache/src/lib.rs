//! Independent official NAMECACHE response validation and ciphertext cache.
//! No zone secrets, record plaintext, resolver, host recovery, or native I/O.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod cache;
#[cfg(feature = "alloc")]
pub use cache::*;
/// Existing official encrypted block view; signature checks use public keys only.
pub use gnunet_gnscrypto::Block;
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;

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
