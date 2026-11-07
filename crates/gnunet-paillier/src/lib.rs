//! Real bounded GNUnet Paillier arithmetic using explicit caller-owned entropy.
//!
//! Public modulus256BE, ciphertext BE32 remaining counter followed by512BE bytes.
//! Jobs perform actual Montgomery arithmetic and primality tests; progress,
//! cancellation and drop never fabricate a key, ciphertext or decrypted value.
#![no_std]
#![forbid(unsafe_code)]
mod error;
mod jobs;
mod keys;
mod pow;
mod prime;
use crypto_bigint::{U1024, U2048, U4096};
pub use error::{Error, Progress};
pub use gnunet_crypto::Entropy;
pub use jobs::{DecryptJob, EncryptJob, EncryptWithWitnessJob, EncryptionWitness};
pub use keys::{Ciphertext, KeyPair, Limits, Plaintext, PrivateKey, PublicKey};
pub use prime::Keygen;
/// Public key/modulus extent in bytes.
pub const MODULUS_BYTES: usize = 256;
/// Official ciphertext integer extent in bytes,4096bits.
pub const CIPHER_BITS_BYTES: usize = 512;
/// Complete ciphertext including signed BE32 homomorphic-operation counter.
pub const CIPHERTEXT_BYTES: usize = 516;
/// Secret lambda followed by mu, each a256-byte unsigned big-endian integer.
pub const PRIVATE_KEY_BYTES: usize = 512;
/// Independent strong Miller–Rabin bases per accepted1024-bit factor.
/// At most2^20 candidate draws gives overall false-prime union bound <=2^-140.
pub const PRIME_ROUNDS: u16 = 80;

#[cfg(test)]
mod tests;
