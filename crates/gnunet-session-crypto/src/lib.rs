//! Official v0.29.1 X25519, HPKE, CAKE and communicator crypto primitives.
//! This crate has no network, clock, allocator, handshake admission or hidden RNG.
#![no_std]
#![forbid(unsafe_code)]
pub mod aead;
/// Official Elligator2 public mapping and 0x0022 KEM with explicit entropy.
pub mod elligator;
pub mod exchange;
pub mod gcm;
pub mod hpke;
mod kdf;
pub mod session;
pub mod transcript;
pub mod udp;
pub use kdf::{Prk, hkdf_expand, hkdf_extract};
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod oracle_tests;
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) fn hex<const N: usize>(text: &str) -> Result<[u8; N], gnunet_types::Error> {
        if text.len() != N * 2 {
            return Err(gnunet_types::Error::InvalidInput);
        }
        let mut out = [0; N];
        for (i, p) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let f = |c| match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(gnunet_types::Error::InvalidInput),
            };
            out[i] = (f(p[0])? << 4) | f(p[1])?;
        }
        Ok(out)
    }
}
