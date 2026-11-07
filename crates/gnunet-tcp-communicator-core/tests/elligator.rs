//! Elligator resource/suite/identity boundaries; C failures are never replayed here.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible tests assert exact crypto/resource observations"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_session_crypto::{
    elligator::{self, Representative, Secret},
    exchange::{EcdhePublic, EcdheSecret},
};
use gnunet_tcp_communicator_core::{
    initial,
    record::{Receiver, Record},
    wire,
};
use gnunet_types::Error;
use std::num::NonZeroUsize;
struct ZeroEntropy {
    calls: Vec<usize>,
    fail: bool,
}
impl Entropy for ZeroEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.calls.push(out.len());
        out.fill(0);
        if self.fail {
            Err(Error::Entropy)
        } else {
            Ok(())
        }
    }
}
fn usable() -> Result<Secret, Error> {
    for i in 1..=255 {
        let key = Secret::from_bytes([i; 32]);
        if key.public(0).is_ok() {
            return Ok(key);
        }
    }
    Err(Error::Entropy)
}
#[test]
fn zero_special_scalar_and_zero_loworder_decapsulation_are_safe_errors() {
    assert!(matches!(
        Secret::from_bytes([0; 32]).public(0),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        elligator::decapsulate(
            &EcdheSecret::from_bytes([9; 32]),
            Representative::from_bytes([0; 32])
        ),
        Err(Error::Authentication)
    ));
}
#[test]
fn exact_entropy_call_order_and_bounded_rejection_do_not_fake_keys() -> Result<(), Error> {
    let attempts = NonZeroUsize::new(3).ok_or(Error::InvalidInput)?;
    let mut e = ZeroEntropy {
        calls: vec![],
        fail: false,
    };
    assert!(matches!(
        Secret::generate(&mut e, attempts),
        Err(Error::Capacity)
    ));
    assert_eq!(e.calls, [32, 1, 32, 1, 32, 1]);
    let mut e = ZeroEntropy {
        calls: vec![],
        fail: false,
    };
    assert!(matches!(
        elligator::encapsulate_random(
            EcdheSecret::from_bytes([9; 32]).public_key(),
            &mut e,
            attempts
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(e.calls, [1, 32, 1, 32, 1, 32, 1]);
    let mut e = ZeroEntropy {
        calls: vec![],
        fail: true,
    };
    assert!(matches!(
        Secret::generate(&mut e, attempts),
        Err(Error::Entropy)
    ));
    assert_eq!(e.calls, [32]);
    Ok(())
}
#[test]
fn representative_top_bits_are_mapping_ignored_but_kem_context_bound() -> Result<(), Error> {
    let key = usable()?;
    let recipient = EcdheSecret::from_bytes([9; 32]);
    let mut proofs = Vec::new();
    let mut public = None;
    for tweak in [0, 2, 4, 6] {
        let (enc, secret) = elligator::encapsulate(recipient.public_key(), &key, tweak)?;
        let mapped = elligator::decode(enc).public;
        if let Some(expected) = public {
            assert_eq!(mapped, expected)
        } else {
            public = Some(mapped)
        }
        let mut proof = [0; 32];
        secret.expand(&[b"same"], &mut proof)?;
        proofs.push(proof);
    }
    for i in 0..proofs.len() {
        for j in i + 1..proofs.len() {
            assert_ne!(proofs[i], proofs[j]);
        }
    }
    Ok(())
}
#[test]
fn inverse_safe_profile_rejects_noncanonical_coordinates() {
    assert!(matches!(
        elligator::encode(EcdhePublic::from_bytes([255; 32]), 0),
        Err(Error::InvalidInput)
    ));
}
#[test]
fn real_initial_kem_signature_ctr_and_next_ack_share_one_stream_position() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let exchange = EcdheSecret::from_eddsa_seed([2; 32]);
    let special = usable()?;
    let (first, mut sender) =
        initial::prepare(&alice, bob.public_key(), &special, 6, 123, &[4; 32])?;
    assert_eq!(first.len(), 168);
    let opened = initial::open(
        bob.public_key(),
        &exchange,
        Some(alice.public_key()),
        &first,
    )?;
    assert_eq!(opened.sender(), alice.public_key());
    assert_eq!(opened.monotonic(), 123);
    assert_eq!(opened.challenge(), &[4; 32]);
    let mut ack = wire::acknowledgement(&alice, bob.public_key(), 124, &[5; 32])?;
    sender.handshake_fragment(&mut ack)?;
    let mut storage = vec![0; wire::MAX_RECORD];
    let mut receive =
        Receiver::with_direction(opened.into_direction(), &mut storage).map_err(|r| r.reason)?;
    receive.push(&ack)?;
    if let Record::Ack(bytes) = receive.record()? {
        assert_eq!(
            wire::verify_ack(bytes, bob.public_key(), &[5; 32])?,
            alice.public_key()
        );
    } else {
        return Err(Error::Malformed);
    }
    Ok(())
}
#[test]
fn initial_wrong_recipient_sender_rep_ciphertext_and_private_pair_reject() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ex = EcdheSecret::from_eddsa_seed([2; 32]);
    let special = usable()?;
    let (first, _direction) =
        initial::prepare(&alice, bob.public_key(), &special, 6, 123, &[4; 32])?;
    assert!(matches!(
        initial::open(bob.public_key(), &ex, Some(bob.public_key()), &first),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        initial::open(alice.public_key(), &ex, None, &first),
        Err(Error::Authentication)
    ));
    for i in [0, 31, 32, 64, 100, 167] {
        let mut bad = first;
        bad[i] ^= 1;
        assert!(initial::open(bob.public_key(), &ex, None, &bad).is_err());
    }
    Ok(())
}
