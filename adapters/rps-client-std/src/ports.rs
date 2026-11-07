//! Actual entropy and standard ranking ports, called only by this owner.
use gnunet_rps::{Peer, Random, Rank};
use gnunet_types::Error;
#[derive(Default)]
pub(crate) struct NativeRandom {
    failure: Option<getrandom::Error>,
}
impl NativeRandom {
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
pub(crate) struct HmacRank;
impl Rank for HmacRank {
    fn rank(&mut self, key: &[u8; 64], peer: &Peer) -> Result<[u8; 64], Error> {
        Ok(*gnunet_crypto::hmac512_parts(key, &[peer.as_slice()]))
    }
}
/// Derive the official subgroup port from the C-string prefix of a shared value.
/// Uses GNUnet HKDF with salt `b"rps"`, original shared bytes and no context.
/// No private state, replacement hash or extra domain bytes are introduced.
pub fn subgroup_hash(shared: &[u8]) -> Result<[u8; 64], Error> {
    let end = shared.iter().position(|b| *b == 0).unwrap_or(shared.len());
    let mut output = [0; 64];
    gnunet_crypto::hkdf_gnunet(b"rps", &shared[..end], &[], &mut output)?;
    Ok(output)
}
