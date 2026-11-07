//! Pure GNUnet REGEX grammar, matching, compressed states and DHT artifacts.
//! Default builds allocate nothing. The explicit `alloc` feature enables the
//! complete bounded compiler; no native, service or network port is present.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
/// Official initial lookup prefix length in bytes, not bits or characters.
pub const INITIAL_BYTES: usize = 24;
/// Official REGEX_BLOCK_create rejects sizes >=62 KiB.
pub const MAX_BLOCK_BYTES: usize = 62 * 1024;
/// Official SHA-512 key.
pub type Hash = [u8; 64];
/// Hash exact proof bytes; there is no NUL or regular-expression normalization.
#[must_use]
pub fn proof_key(proof: &[u8]) -> Hash {
    gnunet_crypto::hash512(proof)
}
/// Hash the first min(length,24) raw bytes. The returned consumption is bytes.
/// C-string callers must provide bytes before the first NUL explicitly.
#[must_use]
pub fn first_key(input: &[u8]) -> (usize, Hash) {
    let n = input.len().min(INITIAL_BYTES);
    (n, proof_key(&input[..n]))
}
/// Official accepting-block codec, purpose 18 material and actual verification.
pub mod accept;
mod block;
pub use block::{BlockEdge, EdgeSource, encode_state, state_block_len};
#[cfg(feature = "alloc")]
mod compile;
#[cfg(feature = "alloc")]
pub use compile::{Automaton, BuildError, Edge, Limit, Limits, Record, State};
