//! Actual explicit RPS entropy/ranking ports; invoked only by the caller.
use gnunet_rps::{Peer, Random, Rank};
use gnunet_types::Error;
/// Foreground native entropy, retaining the first original provider failure.
#[derive(Debug, Default)]
pub struct NativeRandom {
    failure: Option<getrandom::Error>,
}
impl NativeRandom {
    /// Consume the actual retained entropy failure independently from its pure
    /// `Unavailable` classification. No retry or replacement entropy is supplied.
    pub fn take_error(&mut self) -> Option<getrandom::Error> {
        self.failure.take()
    }
}
impl Random for NativeRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(output).map_err(|error| {
            output.fill(0);
            if self.failure.is_none() {
                self.failure = Some(error);
            }
            Error::Unavailable
        })
    }
}
/// Standard actual HMAC-SHA512 min-wise ranking, with no extra domain bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct HmacRank;
impl Rank for HmacRank {
    fn rank(&mut self, key: &[u8; 64], peer: &Peer) -> Result<[u8; 64], Error> {
        Ok(*gnunet_crypto::hmac512_parts(key, &[peer.as_slice()]))
    }
}
/// Official main RPS CADET port: SHA512 of `b"rps"` without NUL.
#[must_use]
pub fn main_group_hash() -> [u8; 64] {
    gnunet_crypto::hash512(b"rps")
}
/// Official subgroup port from the C string prefix of the shared value. Uses
/// the existing GNUnet compatibility HKDF, salt `b"rps"` and no context chunks;
/// it does not substitute a simple hash or expose/store the original secret.
pub fn subgroup_hash(shared: &[u8]) -> Result<[u8; 64], Error> {
    let end = shared.iter().position(|b| *b == 0).unwrap_or(shared.len());
    let mut output = [0; 64];
    gnunet_crypto::hkdf_gnunet(b"rps", &shared[..end], &[], &mut output)?;
    Ok(output)
}
