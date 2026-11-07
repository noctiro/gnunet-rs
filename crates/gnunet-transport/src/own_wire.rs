//! Official purpose29 local-address certificates and public PEERSTORE values.
//!
//! Network classification and record expiry are unsigned hints. A verified
//! certificate binds only its original native address and generation timestamp
//! to the verifying peer; it grants no listener, resource or reachability lease.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512};
use gnunet_types::Error;

/// Official `GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS`.
pub const PURPOSE: u32 = 29;
/// Purpose header8, generation time8 and address SHA51264.
pub const REGION_BYTES: usize = 80;
/// Official public own-address subsystem, without its wire NUL.
pub const SUBSYSTEM: &[u8] = b"transport";
/// Official public own-address key, without its wire NUL.
pub const KEY: &[u8] = b"transport-peer-hello";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Construct the complete immutable signed region. `native` excludes its NUL.
pub fn signed_region(native: &[u8], generated: u64) -> Result<[u8; REGION_BYTES], Error> {
    check_native(native)?;
    let mut out = [0; REGION_BYTES];
    out[..4].copy_from_slice(&(REGION_BYTES as u32).to_be_bytes());
    out[4..8].copy_from_slice(&PURPOSE.to_be_bytes());
    out[8..16].copy_from_slice(&generated.to_be_bytes());
    out[16..].copy_from_slice(&hash512(native));
    Ok(out)
}

/// A borrowed public value. Parsing alone confers no signature authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRecord<'a> {
    /// Original EdDSA signature, not a signature over network/record expiry.
    pub signature: EddsaSignature,
    /// Authenticated generation timestamp; not a cache expiration.
    pub generated: u64,
    /// Unsigned network hint from the original communicator.
    pub network: u32,
    /// Original opaque native address, without its final NUL.
    pub native: &'a [u8],
}
impl AddressRecord<'_> {
    /// Verify the exact purpose29 region under the record's expected peer.
    pub fn verify(&self, expected_peer: EddsaPublicKey) -> Result<(), Error> {
        expected_peer.verify(
            PURPOSE,
            &signed_region(self.native, self.generated)?,
            &self.signature,
        )
    }
    /// Exact canonical value length, including the final NUL.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        check_native(self.native)?;
        self.native
            .len()
            .checked_add(92)
            .and_then(|n| n.checked_add(digits(self.generated)))
            .and_then(|n| n.checked_add(digits(u64::from(self.network))))
            .ok_or(Error::Overflow)
    }
    /// Encode once into caller storage. A short output remains unchanged.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        let needed = self.encoded_len()?;
        let output = output.get_mut(..needed).ok_or(Error::Capacity)?;
        encode_signature(self.signature.as_bytes(), &mut output[..88]);
        output[88] = b';';
        let mut offset = 89;
        offset += decimal(self.generated, &mut output[offset..]);
        output[offset] = b';';
        offset += 1;
        offset += decimal(u64::from(self.network), &mut output[offset..]);
        output[offset] = b';';
        offset += 1;
        output[offset..offset + self.native.len()].copy_from_slice(self.native);
        output[needed - 1] = 0;
        Ok(needed)
    }
}
impl<'a> AddressRecord<'a> {
    /// Parse a bounded exact value, accepting canonical producer decimal/base64.
    /// Only the first three semicolons delimit fields; native bytes stay intact.
    pub fn parse(input: &'a [u8]) -> Result<Self, Error> {
        let body = input.strip_suffix(&[0]).ok_or(Error::Malformed)?;
        if body.contains(&0) {
            return Err(Error::Malformed);
        }
        let mut fields = body.splitn(4, |b| *b == b';');
        let signature = decode_signature(fields.next().ok_or(Error::Malformed)?)?;
        let generated = parse_decimal(fields.next().ok_or(Error::Malformed)?)?;
        let network = u32::try_from(parse_decimal(fields.next().ok_or(Error::Malformed)?)?)
            .map_err(|_| Error::Overflow)?;
        let native = fields.next().ok_or(Error::Malformed)?;
        check_native(native)?;
        Ok(Self {
            signature: EddsaSignature::from_bytes(signature),
            generated,
            network,
            native,
        })
    }
}

/// Checked maximum canonical value size for any u64/u32 decimal fields.
pub fn maximum_value_bytes(native_bytes: usize) -> Result<usize, Error> {
    native_bytes.checked_add(122).ok_or(Error::Overflow)
}

fn check_native(native: &[u8]) -> Result<(), Error> {
    if native.is_empty() || native.contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn digits(mut value: u64) -> usize {
    let mut count = 1;
    while value >= 10 {
        value /= 10;
        count += 1;
    }
    count
}
fn decimal(mut value: u64, output: &mut [u8]) -> usize {
    let count = digits(value);
    for i in (0..count).rev() {
        output[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    count
}
fn parse_decimal(input: &[u8]) -> Result<u64, Error> {
    if input.is_empty() || input.len() > 20 || (input.len() > 1 && input[0] == b'0') {
        return Err(Error::Malformed);
    }
    input.iter().try_fold(0u64, |value, digit| {
        if !digit.is_ascii_digit() {
            return Err(Error::Malformed);
        }
        value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(*digit - b'0')))
            .ok_or(Error::Overflow)
    })
}
fn encode_signature(input: &[u8; 64], out: &mut [u8]) {
    for (source, output) in input[..63]
        .as_chunks::<3>()
        .0
        .iter()
        .zip(out[..84].as_chunks_mut::<4>().0.iter_mut())
    {
        output[0] = BASE64[usize::from(source[0] >> 2)];
        output[1] = BASE64[usize::from((source[0] & 3) << 4 | source[1] >> 4)];
        output[2] = BASE64[usize::from((source[1] & 15) << 2 | source[2] >> 6)];
        output[3] = BASE64[usize::from(source[2] & 63)];
    }
    out[84] = BASE64[usize::from(input[63] >> 2)];
    out[85] = BASE64[usize::from((input[63] & 3) << 4)];
    out[86..88].copy_from_slice(b"==");
}
fn sextet(byte: u8) -> Result<u8, Error> {
    BASE64
        .iter()
        .position(|b| *b == byte)
        .map(|i| i as u8)
        .ok_or(Error::Malformed)
}
fn decode_signature(input: &[u8]) -> Result<[u8; 64], Error> {
    if input.len() != 88 || &input[86..] != b"==" {
        return Err(Error::Malformed);
    }
    let mut out = [0; 64];
    for (source, output) in input[..84]
        .as_chunks::<4>()
        .0
        .iter()
        .zip(out[..63].as_chunks_mut::<3>().0.iter_mut())
    {
        let a = sextet(source[0])?;
        let b = sextet(source[1])?;
        let c = sextet(source[2])?;
        let d = sextet(source[3])?;
        output[0] = a << 2 | b >> 4;
        output[1] = b << 4 | c >> 2;
        output[2] = c << 6 | d;
    }
    let a = sextet(input[84])?;
    let b = sextet(input[85])?;
    if b & 15 != 0 {
        return Err(Error::Malformed);
    }
    out[63] = a << 2 | b >> 4;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Protocol mutation assertions preserve the exact original record."
    )]
    use super::*;
    use gnunet_crypto::EddsaPrivateKey;

    #[test]
    fn original_region_and_unsigned_fields_have_distinct_authority() -> Result<(), Error> {
        let key = EddsaPrivateKey::from_seed([17; 32]);
        let native = b"tcp-127.0.0.1:2086;opaque";
        let region = signed_region(native, 19)?;
        assert_eq!(
            &region[..16],
            &[0, 0, 0, 80, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 19]
        );
        assert_eq!(&region[16..], &hash512(native));
        let record = AddressRecord {
            signature: key.sign(PURPOSE, &region)?,
            generated: 19,
            network: 7,
            native,
        };
        record.verify(key.public_key())?;
        AddressRecord {
            network: 0,
            ..record
        }
        .verify(key.public_key())?;
        assert!(
            AddressRecord {
                generated: 20,
                ..record
            }
            .verify(key.public_key())
            .is_err()
        );
        assert!(
            AddressRecord {
                native: b"tcp-127.0.0.1:2087;opaque",
                ..record
            }
            .verify(key.public_key())
            .is_err()
        );
        assert!(
            record
                .verify(EddsaPrivateKey::from_seed([18; 32]).public_key())
                .is_err()
        );
        let mut other_purpose = region;
        other_purpose[7] = 7;
        assert!(
            key.public_key()
                .verify(PURPOSE, &other_purpose, &record.signature)
                .is_err()
        );
        let mut encoded = [0xa5; 256];
        let len = record.encode(&mut encoded)?;
        assert_eq!(AddressRecord::parse(&encoded[..len])?, record);
        assert_eq!(encoded[len], 0xa5);
        Ok(())
    }

    #[test]
    fn max_decimals_exact_capacity_padding_and_terminator() -> Result<(), Error> {
        let record = AddressRecord {
            signature: EddsaSignature::from_bytes(core::array::from_fn(|i| i as u8)),
            generated: u64::MAX,
            network: u32::MAX,
            native: b"a-",
        };
        assert_eq!(record.encoded_len()?, maximum_value_bytes(2)?);
        let mut out = [0xa5; 124];
        assert_eq!(record.encode(&mut out[..123]), Err(Error::Capacity));
        assert_eq!(out, [0xa5; 124]);
        assert_eq!(record.encode(&mut out)?, 124);
        assert_eq!(AddressRecord::parse(&out)?, record);
        assert_eq!(&out[84..89], b"Pw==;");
        for len in 0..out.len() {
            assert!(AddressRecord::parse(&out[..len]).is_err());
        }
        let mut bad = out;
        bad[85] = b'x'; // nonzero discarded padding bits
        assert!(AddressRecord::parse(&bad).is_err());
        bad = out;
        bad[0] = b'-'; // URL-safe base64 is not the producer format
        assert!(AddressRecord::parse(&bad).is_err());
        bad = out;
        bad[90] = 0;
        assert!(AddressRecord::parse(&bad).is_err());
        assert!(signed_region(b"a-\0", 0).is_err());
        assert_eq!(maximum_value_bytes(usize::MAX), Err(Error::Overflow));
        Ok(())
    }
}
