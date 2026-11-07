//! Actual identity, profile, cryptographic-response and atomicity regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol and real resource regressions assert independent expected outcomes"
)]
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_hello::{HelloBuilder, Limits};
use gnunet_pils::{Action, HELLO_LIFETIME, MasterKey, Profile, Service};
use gnunet_session_crypto::exchange::{EcdhePublic, EcdheSecret, kem_encapsulate};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, SignaturePurpose,
    pils::{PeerUpdate, Request, Response},
};

fn limits() -> Limits {
    Limits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 2048,
        maximum_addresses: 32,
    }
}
fn service<const H: usize>(profile: Profile) -> Result<Service<H>, Error> {
    Service::new(
        MasterKey::from_seed(core::array::from_fn(|i| i as u8)),
        profile,
        100,
        limits(),
    )
}
fn feed(addresses: &[&[u8]], out: &mut [u8]) -> Result<usize, Error> {
    let mut storage = [0; 2048];
    let mut builder = HelloBuilder::new(&mut storage, limits());
    for uri in addresses {
        builder.add_address(uri)?;
    }
    let hello = builder.with_signature(
        EddsaPublicKey::from_bytes([0; 32]),
        EddsaSignature::from_bytes([0; 64]),
        AbsoluteTime::from_micros(0),
    );
    let mut block = [0; 2200];
    let n = hello.encode_block(&mut block)?;
    Request::Feed { block: &block[..n] }.encode(out)
}
fn hex<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    if s.len() != N * 2 {
        return Err(Error::InvalidInput);
    }
    let mut out = [0; N];
    for (i, p) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |c| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Error::InvalidInput),
        };
        out[i] = (digit(p[0])? << 4) | digit(p[1])?;
    }
    Ok(out)
}
#[test]
fn normal_c_public_library_derivation_vector_and_layout_profile() -> Result<(), Error> {
    let service = service::<4096>(Profile::Reference029)?;
    assert_eq!(
        service.identity().public_key().as_bytes(),
        &hex("996cf9ebe64558a400728a748096c18d32bc3f00e068328c9110f765478a9db7")?
    );
    assert_eq!(
        service.with_active_seed(|s| *s)?,
        hex("e45b6427b1550d885dddd65de72ef39d7c8e9a88488b2e33c1ca72c7a60da398")?
    );
    let mut scratch = [0; 2048];
    let hello = service.verify_update(service.announcement(), &mut scratch, 100)?;
    assert_eq!(hello.expiration().as_micros(), 100 + HELLO_LIFETIME);
    assert_eq!(hello.address_count(), 0);
    Ok(())
}
#[test]
fn draft_text_and_published_vector_diverge_explicitly_without_fallback() -> Result<(), Error> {
    let master = MasterKey::from_seed(hex(
        "50d7b652a4efeadff37396909785e5952171a02178c8e7d450fa907925fafd98",
    )?);
    let published_hash = hex(
        "6c57def87391551d2d5b16abb8072e42dc389a3a85723fcba26afdcaccaea0273af57a3e0e1d87778099afb0e9a00995c444927a120f0170732d4fe0f50e3cb2",
    )?;
    // Full LSD0014 section7.1 input -> canonical address hash -> source key.
    // Insert out of order: the official HELLO canonical order is descending
    // strcmp, not the host language's default ascending string sort.
    let mut addresses = [0; 2048];
    let mut builder = HelloBuilder::new(&mut addresses, limits());
    for uri in [
        b"gnunet+https://example.gnu".as_slice(),
        b"gnunet+udp://6.7.8.9",
        b"gnunet+tcp://1.2.3.4",
    ] {
        builder.add_address(uri)?;
    }
    let hash = builder.address_hash(Profile::ReferenceDeterministic.hello());
    assert_eq!(hash, published_hash);
    let expected = hex::<32>("9b8d17711be50a07e7d984bd9c1e6d9cf5492cfb2713f8cb42eaf251573f39d7")?;
    assert_eq!(
        master.with_active_seed(&hash, Profile::ReferenceDeterministic, |s| *s)?,
        expected
    );
    let text = master.with_active_seed(&hash, Profile::Lsd0014Text, |s| *s)?;
    assert_ne!(text, expected);
    assert_eq!(
        text,
        hex("9aebaaab89560e4459661307dc2b23490989ccf947684702772fddd6c3d8fd04")?
    );
    Ok(())
}
#[test]
fn actual_normal_profile_refreshes_addresses_without_claiming_address_authentication()
-> Result<(), Error> {
    let mut service = service::<4096>(Profile::configured(None, None)?)?;
    let original = service.identity().public_key();
    let mut frame = [0; 2400];
    let n = feed(&[b"tcp://127.0.0.1:1234"], &mut frame)?;
    assert_eq!(
        service.receive(&frame[..n], &mut [0; 2048], 200, &mut [])?,
        Action::Broadcast {
            identity_changed: false
        }
    );
    assert_eq!(service.identity().public_key(), original);
    let mut scratch = [0; 2048];
    let hello = service.verify_update(service.announcement(), &mut scratch, 200)?;
    assert_eq!(hello.address_count(), 1);
    assert_eq!(
        hello.verify_signature(Profile::Reference029.hello())?,
        gnunet_hello::SignatureCoverage::MetadataOnly
    );
    Ok(())
}
#[test]
fn deterministic_rotation_is_reversible_and_unchanged_feed_is_atomic() -> Result<(), Error> {
    let mut service = service::<4096>(Profile::configured(Some(b"deterministic"), None)?)?;
    let original = service.identity().public_key();
    let mut frame = [0; 2400];
    let n = feed(&[b"tcp://127.0.0.1:1234"], &mut frame)?;
    assert_eq!(
        service.receive(&frame[..n], &mut [0; 2048], 200, &mut [])?,
        Action::Broadcast {
            identity_changed: true
        }
    );
    assert_ne!(service.identity().public_key(), original);
    let retained = service.announcement().to_vec();
    assert_eq!(
        service.receive(&frame[..n], &mut [0; 2048], 999, &mut [])?,
        Action::Unchanged
    );
    assert_eq!(service.announcement(), retained);
    let n = feed(&[], &mut frame)?;
    assert_eq!(
        service.receive(&frame[..n], &mut [0; 2048], 300, &mut [])?,
        Action::Broadcast {
            identity_changed: true
        }
    );
    assert_eq!(service.identity().public_key(), original);
    Ok(())
}
#[test]
fn explicit_source_choices_cannot_override_a_conflicting_or_unknown_node_profile()
-> Result<(), Error> {
    assert_eq!(
        Profile::configured(Some(b"deterministic"), Some(b"reference029")),
        Err(Error::Conflict)
    );
    assert_eq!(
        Profile::configured(Some(b"unknown"), Some(b"deterministic")),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        Profile::configured(Some(b"reference029"), Some(b"reference-0.29.1"))?,
        Profile::Reference029
    );
    assert_eq!(
        Profile::configured(None, Some(b"deterministic"))?,
        Profile::ReferenceDeterministic
    );
    assert_eq!(
        Profile::configured(Some(b"deterministic"), Some(b"reference-deterministic"))?,
        Profile::ReferenceDeterministic
    );
    let textual = Profile::configured(Some(b"lsd0014-text"), Some(b"lsd0014-text"))?;
    assert_eq!(textual, Profile::Lsd0014Text);
    assert_eq!(
        Profile::configured(Some(b"deterministic"), Some(b"lsd0014-text")),
        Err(Error::Conflict)
    );
    // Identical address coverage does not make the published contextual-label
    // derivation interchangeable with the official conditional build.
    assert_ne!(
        service::<4096>(textual)?.identity().public_key(),
        service::<4096>(Profile::ReferenceDeterministic)?
            .identity()
            .public_key()
    );
    Ok(())
}
#[test]
fn malformed_and_capacity_refusal_never_replace_the_active_identity() -> Result<(), Error> {
    let mut service = service::<176>(Profile::ReferenceDeterministic)?;
    let retained = service.announcement().to_vec();
    let mut frame = [0; 2400];
    let n = feed(&[b"tcp://127.0.0.1:1234"], &mut frame)?;
    assert_eq!(
        service.receive(&frame[..n], &mut [0; 2048], 200, &mut []),
        Err(Error::Capacity)
    );
    assert_eq!(service.announcement(), retained);
    frame[4..8].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        service.receive(&frame[..n], &mut [0; 2048], 200, &mut []),
        Err(Error::Malformed)
    );
    assert_eq!(service.announcement(), retained);
    Ok(())
}
#[test]
fn sign_reply_binds_exact_purpose_and_uses_original_request() -> Result<(), Error> {
    let mut service = service::<4096>(Profile::Reference029)?;
    let mut region = [0x41; 48];
    SignaturePurpose::new(35, 40)?.encode(&mut region)?;
    let mut frame = [0; 128];
    let n = Request::Sign {
        request: u32::MAX,
        region: &region,
    }
    .encode(&mut frame)?;
    let mut out = [0; 104];
    assert_eq!(
        service.receive(&frame[..n], &mut [], 100, &mut out)?,
        Action::Reply {
            len: 104,
            crypto_error: None
        }
    );
    match Response::decode(&out)? {
        Response::Signature {
            request,
            peer,
            signature,
        } => {
            assert_eq!(request, u32::MAX);
            EddsaPublicKey::from_bytes(peer).verify(
                35,
                &region,
                &EddsaSignature::from_bytes(signature),
            )?;
            region[8] ^= 1;
            assert_eq!(
                EddsaPublicKey::from_bytes(peer).verify(
                    35,
                    &region,
                    &EddsaSignature::from_bytes(signature)
                ),
                Err(Error::Authentication)
            );
        }
        _ => return Err(Error::Malformed),
    }
    Ok(())
}
#[test]
fn kem_and_ecdh_results_match_the_actual_current_identity_and_zero_is_failure() -> Result<(), Error>
{
    let mut service = service::<4096>(Profile::Reference029)?;
    let ephemeral = EcdheSecret::from_bytes([7; 32]);
    let public = EcdhePublic::from_edwards(service.identity().public_key().as_bytes())?;
    let (enc, secret) = kem_encapsulate(public, &ephemeral)?;
    let expected = secret.into_secret_bytes();
    let mut frame = [0; 40];
    Request::Decapsulate {
        request: 71,
        encapsulation: *enc.as_bytes(),
    }
    .encode(&mut frame)?;
    let mut out = [0; 104];
    assert_eq!(
        service.receive(&frame, &mut [], 100, &mut out)?,
        Action::Reply {
            len: 40,
            crypto_error: None
        }
    );
    match Response::decode(&out[..40])? {
        Response::Decapsulation { request, key } => {
            assert_eq!(request, 71);
            assert_eq!(key, &*expected);
        }
        _ => return Err(Error::Malformed),
    }
    Request::Ecdh {
        request: 72,
        public: *ephemeral.public_key().as_bytes(),
    }
    .encode(&mut frame)?;
    let expected = ephemeral.exchange_hashed(public)?.into_secret_bytes();
    assert_eq!(
        service.receive(&frame, &mut [], 100, &mut out)?,
        Action::Reply {
            len: 72,
            crypto_error: None
        }
    );
    match Response::decode(&out[..72])? {
        Response::Ecdh { request, key } => {
            assert_eq!(request, 72);
            assert_eq!(key, &*expected);
        }
        _ => return Err(Error::Malformed),
    }
    Request::Decapsulate {
        request: 73,
        encapsulation: [0; 32],
    }
    .encode(&mut frame)?;
    assert_eq!(
        service.receive(&frame, &mut [], 100, &mut out)?,
        Action::Reply {
            len: 40,
            crypto_error: Some(Error::Authentication)
        }
    );
    match Response::decode(&out[..40])? {
        Response::Decapsulation { key, .. } => assert_eq!(key, &[0; 32]),
        _ => return Err(Error::Malformed),
    }
    Ok(())
}
#[test]
fn foreign_master_and_bad_signature_fail_before_identity_publication() -> Result<(), Error> {
    let service = service::<4096>(Profile::ReferenceDeterministic)?;
    let other = Service::<4096>::new(
        MasterKey::from_seed([42; 32]),
        Profile::ReferenceDeterministic,
        100,
        limits(),
    )?;
    let mut scratch = [0; 2048];
    assert_eq!(
        service.verify_update(other.announcement(), &mut scratch, 100),
        Err(Error::Authentication)
    );
    let mut bytes = service.announcement().to_vec();
    bytes[72 + 32] ^= 1;
    assert_eq!(
        service.verify_update(&bytes, &mut scratch, 100),
        Err(Error::Authentication)
    );
    let update = PeerUpdate::decode(service.announcement())?;
    assert_eq!(update.hash, service.address_hash());
    Ok(())
}
#[test]
fn invalid_purpose_and_short_response_storage_preserve_output() -> Result<(), Error> {
    let mut service = service::<4096>(Profile::Reference029)?;
    let mut region = [0; 48];
    SignaturePurpose::new(35, 40)?.encode(&mut region)?;
    let mut frame = [0; 56];
    Request::Sign {
        request: 1,
        region: &region,
    }
    .encode(&mut frame)?;
    let mut out = [0xa5; 103];
    assert_eq!(
        service.receive(&frame, &mut [], 100, &mut out),
        Err(Error::Capacity)
    );
    assert_eq!(out, [0xa5; 103]);
    frame[8..12].copy_from_slice(&49_u32.to_be_bytes());
    let mut out = [0xa5; 104];
    assert!(service.receive(&frame, &mut [], 100, &mut out).is_err());
    assert_eq!(out, [0xa5; 104]);
    Ok(())
}
