//! Known answers for DNSKEY and RRSIG wire encodings.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare public DNSSEC fixtures and exact refusal results"
)]

use super::{Backend, canonical_ed448_point};
use crate::{
    Error, Name, decode_hex_native,
    dnssec::{
        Anchor, Crypto, Dnskey, Rrset, Scratch, denial::Sha1, trust_dnskeys,
        trust_dnskeys_with_anchors,
    },
};
use gnunet_crypto::EddsaPrivateKey;

// OpenSSL-generated public keys and signatures over MESSAGE, in DNS wire
// format. The RSA fixture uses a 1024-bit modulus and exponent 65537.
const MESSAGE: &[u8] = b"GNUnet DNSSEC compatibility";
const RSA_KEY: &str = concat!(
    "03010001cc8bebfd8fbf0411faedb3ccd55dbf4a6cd0f0ed807822cffc2cec93",
    "e1f9a9df73d253883a2baabf660dff420bcef3647cf855b011f389de78c34222",
    "12f23badab151f09f2fd023ad47a8507ff4c7dfd178e8bf5001772b99344eedc",
    "2eed9800cf8f905505227e921f413612e4b0d279b4c0be63273f1ea34484a8b4",
    "e6a2fe77",
);
const RSA_SHA1: &str = concat!(
    "0b058ca675564fe520cfb75b0a346344b62387b2ead3b36803164c371a6d468b",
    "f57e224ca36cfa3fc84e9ff3740cb0a65c05e9976af105afbe259c81b8a09903",
    "af2d75c3800e033f7b885a678e457612b3b86d2dea132d2d8c7540afb22753f3",
    "d1048b3029bdb542980d948c569b32b291e3bc69be1bf82bdd9f48cb165557dd",
);
const RSA_SHA256: &str = concat!(
    "bd1b99c899bf014a16c4f7bd040ad9ed3f3d28190d1192020257bbbabe81d7e0",
    "64fb9a4fe18f0ecdf18fb43cc2454f0963b1aa59d3e8068f1acfd9d148418f74",
    "870c8fd34b006ae51550127f4269bcb0eb0920da564a1cda7c84c5821fddaca9",
    "aa1c7d445ab8af3c6a03a87fa8855dd7a01f322e827bcbc388635e16696a1bd6",
);
const RSA_SHA512: &str = concat!(
    "90d492bb6eb0c5d95049f3bedb5eaa561d993af13dcf9d310537136a2a5463c7",
    "6b18efdee39e49ff6b7494251619df0d143ea278045b9262a5edd64f3b87577e",
    "88329bb46b39d6653478f94a2305c227b396ab02ff61eb8e18e3b1b047be8e67",
    "4abf15176192d2fbcb8a3e931c17b60e4169fb80d80f000551faa4d4c5151d32",
);
const P256_KEY: &str = concat!(
    "034cc50177202e4109902b674bd3543883ff0748b01c92dadc0c928a3f9a7cea",
    "c9763c0e8e1eaea8eb6e7d126d0c073ede734d8170b1f911a4096484e0c9ffd1",
);
const P256_SIGNATURE: &str = concat!(
    "b55aa611167a8cd22f3b29fdb90cdd9a3ef9d7d606f991fe60be7eb5cd7ac6c2",
    "12cf84284aaa547429cafc63b388c2d4610ab35d9aa82734a6b546cd26fafa31",
);
const P384_KEY: &str = concat!(
    "670d5fea8ab098376b8e0f87faf881b14b01ad9667027694732b2a402e71ad38",
    "5f6565b0c866a35daad136c7914e6f159586cbe5c3846752a00a3720505d4153",
    "b6a53e7744a5c56858cfff83db2fe60568ae951b085694d67aeeaa58c2ad318c",
);
const P384_SIGNATURE: &str = concat!(
    "fe758e0bfa0a2fcafe1b9e461b092c944196413eacbe89657914c812e783e0b0",
    "a41eac4f2892c4011af9b9848b7a32d36f029bbc7ef05b3aa3ce42aa834c03bb",
    "5e3e76d2017007981c4f475369306524b6087aef38b403f43427b8e989bf358a",
);

fn hex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let mut output = [0; N];
    if text.len() != 2 * N || decode_hex_native(text.as_bytes(), &mut output)? != N {
        return Err(Error::Malformed);
    }
    Ok(output)
}

fn check_signature<const N: usize>(
    algorithm: u8,
    key: &[u8],
    message: &[u8],
    mut signature: [u8; N],
) {
    assert_eq!(
        Backend.verify(algorithm, key, message, &signature),
        Ok(()),
        "algorithm {algorithm} must accept its known signature"
    );
    assert_eq!(
        Backend.verify(algorithm, key, message, &signature[..N - 1]),
        Err(Error::Malformed)
    );
    signature[N - 1] ^= 1;
    assert_eq!(
        Backend.verify(algorithm, key, message, &signature),
        Err(Error::Authentication),
        "algorithm {algorithm} must reject a changed signature"
    );
}

#[test]
fn rsa_sha_families_verify_at_the_minimum_modulus_size() -> Result<(), Error> {
    let key = hex::<132>(RSA_KEY)?;
    let sha1 = hex::<128>(RSA_SHA1)?;
    check_signature(5, &key, MESSAGE, sha1);
    check_signature(7, &key, MESSAGE, sha1);
    check_signature(8, &key, MESSAGE, hex::<128>(RSA_SHA256)?);
    check_signature(10, &key, MESSAGE, hex::<128>(RSA_SHA512)?);
    assert_eq!(
        Backend.verify(8, &key, MESSAGE, &sha1),
        Err(Error::Authentication)
    );
    Ok(())
}

#[test]
fn ecdsa_accepts_fixed_coordinates_and_both_valid_s_representatives() -> Result<(), Error> {
    let key = hex::<64>(P256_KEY)?;
    let mut signature = hex::<64>(P256_SIGNATURE)?;
    check_signature(13, &key, MESSAGE, signature);
    // Both s and n - s verify for this r and message.
    let high_s = hex::<32>("ed307bd6b555ab8cd635039c4c773d2b5bdc47500c6f77504d0483f5d5682b20")?;
    signature[32..].copy_from_slice(&high_s);
    assert_eq!(Backend.verify(13, &key, MESSAGE, &signature), Ok(()));
    check_signature(
        14,
        &hex::<96>(P384_KEY)?,
        MESSAGE,
        hex::<96>(P384_SIGNATURE)?,
    );
    Ok(())
}

#[test]
fn ed25519_verifies_the_empty_message_vector() -> Result<(), Error> {
    // RFC 8032 section 7.1 TEST 1.
    let key = hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?;
    let signature = hex::<64>(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ))?;
    check_signature(15, &key, b"", signature);
    assert_eq!(
        Backend.verify(200, &key, b"", &signature),
        Err(Error::Unsupported)
    );
    let mut weak_key = [0; 32];
    weak_key[0] = 1;
    let mut weak_signature = [0; 64];
    weak_signature[0] = 1;
    assert_eq!(
        Backend.verify(15, &weak_key, b"", &weak_signature),
        Err(Error::Authentication)
    );
    Ok(())
}

#[test]
fn ed448_verifies_the_empty_message_vector_and_checks_original_point_encodings() -> Result<(), Error>
{
    // RFC 8032 §7.4, empty message and empty context.
    let key = hex::<57>(concat!(
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778",
        "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
    ))?;
    let signature = hex::<114>(concat!(
        "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2",
        "b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9d",
        "f63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61",
        "149f05a7363268c71d95808ff2e652600",
    ))?;
    assert!(Backend.supports_signature(16));
    check_signature(16, &key, b"", signature);
    assert_eq!(
        Backend.verify(16, &key[..56], b"", &signature),
        Err(Error::Malformed)
    );

    let mut noncanonical = key;
    noncanonical[56] |= 1;
    assert!(!canonical_ed448_point(&noncanonical));
    assert_eq!(
        Backend.verify(16, &noncanonical, b"", &signature),
        Err(Error::Authentication)
    );
    let mut noncanonical_r = signature;
    noncanonical_r[56] |= 1;
    assert_eq!(
        Backend.verify(16, &key, b"", &noncanonical_r),
        Err(Error::Authentication)
    );

    // The field modulus itself is one past the greatest canonical coordinate.
    let mut boundary = [0xff; 57];
    boundary[28] = 0xfe;
    boundary[56] = 0;
    assert!(!canonical_ed448_point(&boundary));
    boundary[0] -= 1;
    assert!(canonical_ed448_point(&boundary));
    let mut identity = [0; 57];
    identity[0] = 1;
    assert_eq!(
        Backend.verify(16, &identity, b"", &signature),
        Err(Error::Authentication)
    );
    Ok(())
}

#[test]
fn ds_and_nsec3_hashes_match_known_answers() -> Result<(), Error> {
    let sha1 = hex::<20>("a9993e364706816aba3e25717850c26c9cd0d89d")?;
    let sha256 = hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")?;
    let sha384 = hex::<48>(concat!(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed",
        "8086072ba1e7cc2358baeca134c825a7",
    ))?;
    for (algorithm, expected) in [
        (1, sha1.as_slice()),
        (2, sha256.as_slice()),
        (4, sha384.as_slice()),
    ] {
        let mut output = [0x5a; 49];
        let written = Backend.digest(algorithm, &[b"a", b"", b"bc"], &mut output)?;
        assert_eq!(written, expected.len());
        assert_eq!(&output[..written], expected);
        assert!(output[written..].iter().all(|byte| *byte == 0x5a));
    }
    let mut output = [0; 20];
    Backend.hash(b"abc", &mut output)?;
    assert_eq!(output, sha1);
    let mut short = [0x5a; 19];
    assert_eq!(
        Backend.digest(1, &[b"abc"], &mut short),
        Err(Error::Capacity)
    );
    assert_eq!(short, [0x5a; 19]);
    assert_eq!(
        Backend.digest(3, &[b"abc"], &mut output),
        Err(Error::Unsupported)
    );
    let too_many_parts = [b"".as_slice(); 65];
    assert_eq!(
        Backend.digest(1, &too_many_parts, &mut output),
        Err(Error::TooLarge)
    );
    assert_eq!(output, sha1);
    Ok(())
}

const OWNER: &[u8; 9] = b"\x07example\0";

fn signed_example_key() -> Result<([u8; 36], [u8; 91]), Error> {
    let private = EddsaPrivateKey::from_seed([29; 32]);
    let mut key = [0; 36];
    key[..4].copy_from_slice(&[1, 1, 3, 15]);
    key[4..].copy_from_slice(private.public_key().as_bytes());
    let tag = Dnskey::parse(&key)?.tag().to_be_bytes();
    // The real Ed25519 DNSKEY self-signature covers the RFC 4034 canonical RR.
    let mut rrsig = [0; 18 + 9 + 64];
    rrsig[..4].copy_from_slice(&[0, 48, 15, 1]);
    rrsig[4..8].copy_from_slice(&100u32.to_be_bytes());
    rrsig[8..12].copy_from_slice(&300u32.to_be_bytes());
    rrsig[12..16].copy_from_slice(&100u32.to_be_bytes());
    rrsig[16..18].copy_from_slice(&tag);
    rrsig[18..27].copy_from_slice(OWNER);
    let mut canonical = [0; 27 + 9 + 10 + 36];
    canonical[..27].copy_from_slice(&rrsig[..27]);
    canonical[27..36].copy_from_slice(OWNER);
    canonical[36..46].copy_from_slice(&[0, 48, 0, 1, 0, 0, 0, 100, 0, 36]);
    canonical[46..].copy_from_slice(&key);
    rrsig[27..].copy_from_slice(private.sign_raw(&canonical).as_bytes());
    Ok((key, rrsig))
}

#[test]
fn digest_preference_considers_only_supported_dnskey_algorithms() -> Result<(), Error> {
    let zone = Name::from_wire(OWNER)?;
    let (key, rrsig) = signed_example_key()?;
    let tag = Dnskey::parse(&key)?.tag().to_be_bytes();
    let keys = Rrset {
        owner: zone,
        kind: 48,
        class: 1,
        ttl: 100,
        records: &[&key],
    };
    let signatures = Rrset {
        owner: zone,
        kind: 46,
        class: 1,
        ttl: 100,
        records: &[&rrsig],
    };

    let mut sha1 = [0; 24];
    sha1[..4].copy_from_slice(&[tag[0], tag[1], 15, 1]);
    assert_eq!(Backend.digest(1, &[OWNER, &key], &mut sha1[4..]), Ok(20));
    let mut unsupported_sha256 = [0; 36];
    unsupported_sha256[..4].copy_from_slice(&[tag[0], tag[1], 200, 2]);
    let mut mismatched_sha256 = unsupported_sha256;
    mismatched_sha256[2] = 15;

    let mut message = [0; 128];
    let mut record = [0; 48];
    let mut order = [0; 1];
    let mut scratch = Scratch {
        message: &mut message,
        record: &mut record,
        order: &mut order,
    };
    let mut trust = |anchors: &[&[u8]]| {
        trust_dnskeys(zone, anchors, keys, signatures, 200, &Backend, &mut scratch)
            .map(|trusted| trusted.ttl())
    };
    assert_eq!(trust(&[&unsupported_sha256, &sha1]), Ok(100));
    assert_eq!(
        trust(&[&mismatched_sha256, &sha1]),
        Err(Error::Authentication)
    );
    assert_eq!(trust(&[&unsupported_sha256]), Err(Error::Unsupported));
    Ok(())
}

#[test]
fn exact_dnskey_anchor_authenticates_the_whole_apex_rrset() -> Result<(), Error> {
    let zone = Name::from_wire(OWNER)?;
    let (key, rrsig) = signed_example_key()?;
    let tag = Dnskey::parse(&key)?.tag().to_be_bytes();
    let mut collision = key;
    collision[4..6].copy_from_slice(&key[6..8]);
    collision[6..8].copy_from_slice(&key[4..6]);
    assert_ne!(collision, key);
    assert_eq!(Dnskey::parse(&collision)?.tag().to_be_bytes(), tag);

    let keys = Rrset {
        owner: zone,
        kind: 48,
        class: 1,
        ttl: 100,
        records: &[&key],
    };
    let modified = Rrset {
        records: &[&key, &collision],
        ..keys
    };
    let signatures = Rrset {
        kind: 46,
        records: &[&rrsig],
        ..keys
    };
    let mut mismatched_ds = [0; 36];
    mismatched_ds[..4].copy_from_slice(&[tag[0], tag[1], 15, 2]);
    let mut message = [0; 192];
    let mut record = [0; 48];
    let mut order = [0; 2];
    let mut scratch = Scratch {
        message: &mut message,
        record: &mut record,
        order: &mut order,
    };
    let mut trust = |anchors: &[Anchor<'_>], keys| {
        trust_dnskeys_with_anchors(zone, anchors, keys, signatures, 200, &Backend, &mut scratch)
            .map(|trusted| trusted.ttl())
    };
    assert_eq!(trust(&[Anchor::Dnskey(&key)], keys), Ok(100));
    assert_eq!(
        trust(&[Anchor::Ds(&mismatched_ds), Anchor::Dnskey(&key)], keys),
        Ok(100)
    );
    assert_eq!(
        trust(&[Anchor::Dnskey(&collision)], keys),
        Err(Error::Authentication)
    );
    assert_eq!(
        trust(&[Anchor::Dnskey(&key)], modified),
        Err(Error::Authentication)
    );
    Ok(())
}
