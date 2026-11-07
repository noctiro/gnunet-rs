//! GNUnet's historical HMAC-SHA512 extract / HMAC-SHA256 expand construction.
use gnunet_types::Error;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

// Standard HMAC orchestration over RustCrypto SHA-2. Keep the padded key in an
// explicitly erased owner: hmac 0.13's get_der_key temporary has no drop erasure.
// SHA-2's enabled zeroize feature also erases the hash state and block buffers.
macro_rules! hmac {
    ($name:ident, $hash:ty, $block:literal, $digest:literal) => {
        fn $name<'a>(
            key: &[u8],
            parts: impl IntoIterator<Item = &'a [u8]>,
        ) -> Zeroizing<[u8; $digest]> {
            let mut pad = Zeroizing::new([0_u8; $block]);
            if key.len() > pad.len() {
                let mut hashed = <$hash>::digest(key);
                pad[..$digest].copy_from_slice(&hashed);
                hashed.zeroize();
            } else {
                pad[..key.len()].copy_from_slice(key);
            }
            for byte in pad.iter_mut() {
                *byte ^= 0x36;
            }
            let mut inner = <$hash>::new();
            inner.update(pad.as_ref());
            for part in parts {
                inner.update(part);
            }
            let mut inner_digest = inner.finalize();
            for byte in pad.iter_mut() {
                *byte ^= 0x36 ^ 0x5c;
            }
            let mut outer = <$hash>::new();
            outer.update(pad.as_ref());
            outer.update(&inner_digest);
            inner_digest.zeroize();
            let mut digest = outer.finalize();
            let mut result = Zeroizing::new([0_u8; $digest]);
            result.copy_from_slice(&digest);
            digest.zeroize();
            result
        }
    };
}
hmac!(hmac_sha512, Sha512, 128, 64);
hmac!(hmac_sha256, Sha256, 64, 32);

pub(crate) fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    hmac_sha512(key, parts.iter().copied())
}

/// Exact `GNUNET_CRYPTO_hkdf_gnunet`: concatenate info slices without lengths
/// or NUL terminators. This differs from standard HKDF-SHA256's extract step.
/// Output is erased if its size exceeds 255 SHA-256 blocks.
pub fn hkdf_gnunet(
    salt: &[u8],
    ikm: &[u8],
    info: &[&[u8]],
    output: &mut [u8],
) -> Result<(), Error> {
    if output.len() > 255 * 32 {
        output.zeroize();
        return Err(Error::InvalidInput);
    }
    let prk = hmac512(salt, &[ikm]);
    expand256(prk.as_ref(), info, output)
}

pub(crate) fn hkdf256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    if output.len() > 255 * 32 {
        output.zeroize();
        return Err(Error::InvalidInput);
    }
    let prk = hmac_sha256(salt, [ikm]);
    expand256(prk.as_ref(), &[info], output)
}

fn expand256(prk: &[u8], info: &[&[u8]], output: &mut [u8]) -> Result<(), Error> {
    let mut previous = Zeroizing::new([0_u8; 32]);
    let mut previous_len = 0;
    for (index, chunk) in output.chunks_mut(32).enumerate() {
        let counter = [u8::try_from(index + 1).map_err(|_| Error::Overflow)?];
        let next = hmac_sha256(
            prk,
            core::iter::once(&previous[..previous_len])
                .chain(info.iter().copied())
                .chain(core::iter::once(counter.as_slice())),
        );
        previous.copy_from_slice(next.as_ref());
        chunk.copy_from_slice(&previous[..chunk.len()]);
        previous_len = 32;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "KDF boundary and framing assertions."
    )]
    use super::*;
    use crate::test_support::hex;

    #[test]
    fn rfc4231_short_and_hashed_keys() -> Result<(), Error> {
        // RFC 4231 sections 4.2 and 4.7. Separate message slices exercise the
        // streaming contract used by RFC6979 and GNUnet's ordered KDF context.
        let cases: [(&[u8], &[u8], &str, &str); 2] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            ),
        ];
        for (key, message, expected256, expected512) in cases {
            let parts = [&message[..3], &[], &message[3..]];
            assert_eq!(*hmac_sha256(key, parts), hex::<32>(expected256)?);
            assert_eq!(*hmac512(key, &parts), hex::<64>(expected512)?);
        }
        Ok(())
    }

    #[test]
    fn split_info_has_no_framing_and_oversized_output_is_erased() -> Result<(), Error> {
        let mut whole = [0; 97];
        let mut split = [0; 97];
        hkdf_gnunet(b"salt", b"input", &[b"context"], &mut whole)?;
        hkdf_gnunet(b"salt", b"input", &[b"con", b"", b"text"], &mut split)?;
        assert_eq!(whole, split);
        let mut oversized = [0xa5; 255 * 32 + 1];
        assert_eq!(
            hkdf_gnunet(b"salt", b"input", &[], &mut oversized),
            Err(Error::InvalidInput)
        );
        assert_eq!(oversized, [0; 255 * 32 + 1]);
        Ok(())
    }
}
