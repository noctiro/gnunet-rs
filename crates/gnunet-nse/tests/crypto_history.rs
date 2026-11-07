//! Independent cryptographic and exact estimator boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check source-derived crypto/float boundaries."
)]
use gnunet_crypto::{EddsaPrivateKey, pow};
use gnunet_nse::{
    crypto::{self, Authentication, ReferenceEndian, WorkBits},
    history,
};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, nse::flood::Fields};

fn signed(key: &EddsaPrivateKey, proof: [u8; 8]) -> Result<[u8; 132], Error> {
    let mut fields = Fields {
        hops: 0,
        timestamp: AbsoluteTime::from_micros(123),
        matching_bits: u32::MAX,
        origin: *key.public_key().as_bytes(),
        proof,
        signature: [0; 64],
    };
    let mut payload = [0; 60];
    fields.encode_signed(&mut payload)?;
    fields.signature = *key.sign(14, &payload)?.as_bytes();
    let mut bytes = [0; 132];
    fields.encode(&mut bytes)?;
    Ok(bytes)
}
#[test]
fn actual_argon_gate_signature_original_bytes_and_zero_mode() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let public = *key.public_key().as_bytes();
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    let mut valid = None;
    let mut invalid = None;
    for n in 0_u64..64 {
        let proof = n.to_be_bytes();
        if crypto::valid_proof(WorkBits::new(1)?, &public, &proof, &mut memory)? {
            valid = Some(proof);
        } else {
            invalid = Some(proof);
        }
        if valid.is_some() && invalid.is_some() {
            break;
        }
    }
    let good = signed(&key, valid.ok_or(Error::NotFound)?)?;
    assert_eq!(
        crypto::admit(&good, WorkBits::new(1)?, &mut memory)?.authentication(),
        Authentication::SignatureAndWork
    );
    let bad_work = signed(&key, invalid.ok_or(Error::NotFound)?)?;
    assert_eq!(
        crypto::admit(&bad_work, WorkBits::new(1)?, &mut memory).err(),
        Some(Error::Authentication)
    );
    let mut bad_signature = good;
    bad_signature[100] ^= 1;
    assert_eq!(
        crypto::admit(&bad_signature, WorkBits::new(1)?, &mut memory).err(),
        Some(Error::Authentication)
    );
    assert_eq!(
        crypto::admit(&bad_signature, WorkBits::new(0)?, &mut [])?.authentication(),
        Authentication::ZeroWorkUnauthenticated
    );
    let mut hops = good;
    hops[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        crypto::admit(&hops, WorkBits::new(1)?, &mut memory)?
            .fields()
            .signature,
        good[68..132]
    );
    assert_eq!(
        crypto::admit(&good, WorkBits::new(1)?, &mut []).err(),
        Some(Error::Capacity)
    );
    assert_eq!(crypto::SALT, *b"gnunet-nse-proof");
    assert_eq!(WorkBits::default().get(), 15);
    assert_eq!(WorkBits::new(512), Err(Error::InvalidInput));
    assert_eq!(
        crypto::admit(&bad_work, WorkBits::default(), &mut memory).err(),
        Some(Error::Authentication)
    );
    Ok(())
}
#[test]
fn raw_proof_bytes_and_internal_timestamp_profiles_are_explicit() -> Result<(), Error> {
    let identity = core::array::from_fn(|i| i as u8);
    let proof = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    let hash = crypto::proof_hash(&identity, &proof, &mut memory)?;
    let mut input = [0; 40];
    input[..8].copy_from_slice(&proof);
    input[8..].copy_from_slice(&identity);
    let mut expected = [0; 64];
    pow::hash(b"gnunet-nse-proof", &input, &mut expected, &mut memory)?;
    assert_eq!(hash, expected);
    let time = 0x0102_0304_0506_0708;
    assert_eq!(
        ReferenceEndian::Little.timestamp(time),
        [8, 7, 6, 5, 4, 3, 2, 1]
    );
    assert_eq!(
        ReferenceEndian::Big.timestamp(time),
        [1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(crypto::leading_zeros(&[0; 64]), 512);
    let mut leading = [0; 64];
    leading[2] = 0x10;
    assert_eq!(crypto::leading_zeros(&leading), 19);
    for profile in [ReferenceEndian::Little, ReferenceEndian::Big] {
        let a = gnunet_crypto::hash512(&profile.timestamp(time));
        let b = gnunet_crypto::hash512(&identity);
        let xor = core::array::from_fn(|i| a[i] ^ b[i]);
        assert_eq!(
            crypto::matching_bits(time, &identity, profile),
            u32::from(crypto::leading_zeros(&xor))
        );
    }
    Ok(())
}
#[test]
fn west_weights_zero_one_nan_peer_floor_and_checked_linear_count() -> Result<(), Error> {
    let empty = history::summarize(&[], 0)?;
    assert_eq!(empty.mean, 0.0);
    assert_eq!(empty.deviation, 0.0);
    assert_eq!(empty.log2_size, 0.0);
    let one = history::summarize(&[15], 0)?;
    assert_eq!(one.mean, 15.0);
    assert!(one.deviation.is_nan());
    assert_eq!(one.log2_size, 15.0 - 0.332747);
    let two = history::summarize(&[10, 0], 1)?;
    assert_eq!(two.mean, 6.0);
    assert!((two.deviation - libm::sqrt(48.0)).abs() < 1e-12);
    let floored = history::summarize(&[0, 0], 8)?;
    assert_eq!(floored.log2_size, 3.0);
    assert_eq!(floored.linear_count()?, 8);
    assert_eq!(
        history::summarize(&[u32::MAX; 64], 1)?.linear_count(),
        Err(Error::Overflow)
    );
    assert_eq!(history::summarize(&[0; 65], 1).err(), Some(Error::Capacity));
    assert_eq!(history::matching_delay(1000, 15, 15.0)?, 500.0);
    assert_eq!(
        history::matching_delay(0, 15, 15.0),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        history::matching_delay(1000, 0, f64::NAN),
        Err(Error::InvalidInput)
    );
    let estimate = one.estimate(123);
    let mut bytes = [0; 32];
    estimate.encode(&mut bytes)?;
    assert!(
        gnunet_wire::official::nse::Estimate::decode(&bytes)?
            .deviation
            .value()
            .is_nan()
    );
    assert_eq!(bytes[4..8], [0; 4]);
    Ok(())
}

#[test]
fn actual_normal_c_default15_proof_signature_and_unsigned_hops() -> Result<(), Error> {
    fn hex(text: &str) -> Result<Vec<u8>, Error> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                let nibble = |c| match c {
                    b'0'..=b'9' => Ok(c - b'0'),
                    b'a'..=b'f' => Ok(c - b'a' + 10),
                    _ => Err(Error::InvalidInput),
                };
                Ok(nibble(p[0])? * 16 + nibble(p[1])?)
            })
            .collect()
    }
    let mut lines = include_str!("fixtures/default15-C.txt").lines();
    let mut bytes = hex(lines.next().ok_or(Error::Truncated)?)?;
    let expected = hex(lines.next().ok_or(Error::Truncated)?)?;
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    let original = crypto::admit(&bytes, WorkBits::default(), &mut memory)?;
    assert_eq!(original.authentication(), Authentication::SignatureAndWork);
    let fields = original.fields();
    let hash = crypto::proof_hash(&fields.origin, &fields.proof, &mut memory)?;
    assert_eq!(hash.as_slice(), expected);
    assert!(crypto::leading_zeros(&hash) >= 15);
    bytes[4..8].copy_from_slice(&900_u32.to_be_bytes());
    assert_eq!(
        crypto::admit(&bytes, WorkBits::default(), &mut memory)?
            .fields()
            .hops,
        900
    );
    bytes[68..132].fill(0);
    assert_eq!(
        crypto::admit(&bytes, WorkBits::default(), &mut memory).err(),
        Some(Error::Authentication)
    );
    assert_eq!(
        crypto::admit(&bytes, WorkBits::new(0)?, &mut [])?.authentication(),
        Authentication::ZeroWorkUnauthenticated
    );
    Ok(())
}
