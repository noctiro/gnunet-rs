//! Original owned signing effects; no test service or fabricated peer result.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify original effect and signature authority"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::{
    ClientId, Engine, Limits, Output, PeerId, Signer,
    p2p::{Challenge, Validation},
    signing::ValidationMode,
};
use gnunet_types::Error;
struct Deferred(PeerId);
impl Signer for Deferred {
    fn identity(&self) -> PeerId {
        self.0
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
        Err(Error::Unsupported)
    }
    fn validation_mode(&self) -> ValidationMode {
        ValidationMode::Deferred
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(7);
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut v = vec![0; size];
    v[..2].copy_from_slice(&(size as u16).to_be_bytes());
    v[2..4].copy_from_slice(&kind.to_be_bytes());
    v
}
fn queue(peer: PeerId, qid: u32) -> Vec<u8> {
    let mut v = frame(1204, 74);
    v[4..8].copy_from_slice(&qid.to_be_bytes());
    v[8..40].copy_from_slice(&peer.0);
    v[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    v[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    v[64..].copy_from_slice(b"tcp-local\0");
    v
}
fn incoming(peer: PeerId, nonce: u8) -> Vec<u8> {
    let c = Challenge {
        nonce: [nonce; 32],
        origin: 90 + u64::from(nonce),
    }
    .encode();
    let mut v = frame(1202, 88 + c.len());
    v[16..24].copy_from_slice(&1_000_000_u64.to_be_bytes());
    v[24..56].copy_from_slice(&peer.0);
    v[88..].copy_from_slice(&c);
    v
}
fn setup(e: &mut Engine, s: &mut Deferred) -> Result<ClientId, Error> {
    let id = e.accept()?;
    let mut r = frame(1211, 16);
    r[4..8].copy_from_slice(&1_u32.to_be_bytes());
    r[12..].copy_from_slice(b"tcp\0");
    e.receive(&id, &r, 100, s, &mut Random)?;
    Ok(id)
}
fn drain(e: &mut Engine) {
    while e.output().is_some() {}
}
#[test]
fn original_snapshot_and_actual_signer_are_verified_before_one_original_route_is_admitted()
-> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([1; 32]);
    let mut s = Deferred(PeerId(*key.public_key().as_bytes()));
    let mut e = Engine::new(s.identity(), Limits::default())?;
    let owner = setup(&mut e, &mut s)?;
    let peer = PeerId([9; 32]);
    e.receive(&owner, &queue(peer, 3), 100, &mut s, &mut Random)?;
    drain(&mut e);
    e.receive(&owner, &incoming(peer, 5), 101, &mut s, &mut Random)?;
    let request = e.validation_request().ok_or(Error::NotFound)?.clone();
    assert_eq!(request.client(), &owner);
    assert_eq!(request.peer(), peer);
    assert_eq!(request.signer(), s.identity());
    assert_eq!(
        request.region(),
        &Validation::signed_region(&[5; 32], 1_000_000)
    );
    assert_eq!(e.snapshot().pending_validation_signatures, 1);
    assert!(e.output().is_none());
    e.claim_validation(request.id())?;
    assert!(e.validation_request().is_none());
    let signature = *key.sign(35, request.region())?.as_bytes();
    assert_eq!(
        e.complete_validation(request.id(), PeerId([8; 32]), signature, 102),
        Err(Error::Authentication)
    );
    let mut changed = *request.region();
    changed[8] ^= 1;
    let wrong = *key.sign(35, &changed)?.as_bytes();
    assert!(
        e.complete_validation(request.id(), s.identity(), wrong, 102)
            .is_err()
    );
    assert!(e.validation_live(request.id()));
    e.complete_validation(request.id(), s.identity(), signature, 102)?;
    assert!(!e.validation_live(request.id()));
    assert_eq!(e.snapshot().pending_validation_signatures, 0);
    assert_eq!(
        e.complete_validation(request.id(), s.identity(), signature, 102),
        Err(Error::Stale)
    );
    e.tick(102, &mut Random)?;
    let mut responses = 0;
    while let Some(o) = e.output() {
        if let Output::Frame { client, bytes } = o
            && bytes[2..4] == 1209_u16.to_be_bytes()
            && bytes[50..52] == 1304_u16.to_be_bytes()
        {
            let v = Validation::decode(&bytes[48..])?;
            assert_eq!(client, owner);
            assert_eq!(v.nonce, [5; 32]);
            assert_eq!(v.origin, 95);
            v.verify(s.identity().0)?;
            responses += 1;
        }
    }
    assert_eq!(responses, 1);
    Ok(())
}
#[test]
fn physical_route_retirement_and_foreign_engine_tokens_cannot_authorize_replacements()
-> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([1; 32]);
    let mut s = Deferred(PeerId(*key.public_key().as_bytes()));
    let mut e = Engine::new(s.identity(), Limits::default())?;
    let owner = setup(&mut e, &mut s)?;
    let a = PeerId([9; 32]);
    let b = PeerId([8; 32]);
    for (peer, qid) in [(a, 3), (b, 4)] {
        e.receive(&owner, &queue(peer, qid), 100, &mut s, &mut Random)?;
    }
    drain(&mut e);
    e.receive(&owner, &incoming(a, 5), 101, &mut s, &mut Random)?;
    let old = e.validation_request().ok_or(Error::NotFound)?.clone();
    e.claim_validation(old.id())?;
    e.receive(&owner, &incoming(b, 6), 101, &mut s, &mut Random)?;
    let healthy = e.validation_request().ok_or(Error::NotFound)?.clone();
    e.claim_validation(healthy.id())?;
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3_u32.to_be_bytes());
    down[8..40].copy_from_slice(&a.0);
    e.receive(&owner, &down, 102, &mut s, &mut Random)?;
    assert!(!e.validation_live(old.id()));
    assert!(e.validation_live(healthy.id()));
    assert_eq!(e.snapshot().clients, 1);
    assert_eq!(e.snapshot().queues, 1);
    e.receive(&owner, &queue(a, 3), 103, &mut s, &mut Random)?;
    let signature = *key.sign(35, old.region())?.as_bytes();
    assert_eq!(
        e.complete_validation(old.id(), s.identity(), signature, 104),
        Err(Error::Stale)
    );
    let mut foreign = Engine::new(s.identity(), Limits::default())?;
    let healthy_signature = *key.sign(35, healthy.region())?.as_bytes();
    assert_eq!(
        foreign.complete_validation(healthy.id(), s.identity(), healthy_signature, 104),
        Err(Error::Stale)
    );
    // An invalid clock sample must fail without consuming the live original;
    // test it separately so it cannot mask the foreign-engine token boundary.
    assert_eq!(
        e.complete_validation(healthy.id(), s.identity(), healthy_signature, u64::MAX),
        Err(Error::InvalidInput)
    );
    assert!(e.validation_live(healthy.id()));
    let foreign_owner = setup(&mut foreign, &mut s)?;
    assert!(foreign_owner != owner);
    e.close(&owner)?;
    assert!(!e.validation_live(healthy.id()));
    assert_eq!(e.snapshot().pending_validation_signatures, 0);
    Ok(())
}
#[test]
fn bounded_admission_cancellation_and_expiry_keep_original_ids_without_input_replay()
-> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([1; 32]);
    let mut s = Deferred(PeerId(*key.public_key().as_bytes()));
    let mut e = Engine::new(
        s.identity(),
        Limits {
            control_messages: 1,
            ..Limits::default()
        },
    )?;
    let owner = setup(&mut e, &mut s)?;
    let peer = PeerId([9; 32]);
    e.receive(&owner, &queue(peer, 3), 100, &mut s, &mut Random)?;
    drain(&mut e);
    e.receive(&owner, &incoming(peer, 5), 101, &mut s, &mut Random)?;
    let old = e.validation_request().ok_or(Error::NotFound)?.clone();
    e.receive(&owner, &incoming(peer, 6), 102, &mut s, &mut Random)?;
    assert_eq!(e.snapshot().pending_validation_signatures, 1);
    assert_eq!(
        e.validation_request().ok_or(Error::NotFound)?.id(),
        old.id()
    );
    e.cancel_validation(old.id())?;
    e.receive(&owner, &incoming(peer, 7), 103, &mut s, &mut Random)?;
    let next = e.validation_request().ok_or(Error::NotFound)?.clone();
    assert_ne!(old.id(), next.id());
    assert_eq!(
        next.region(),
        &Validation::signed_region(&[7; 32], 1_000_000)
    );
    e.claim_validation(next.id())?;
    e.tick(60_000_103, &mut Random)?;
    assert!(!e.validation_live(next.id()));
    assert_eq!(
        e.complete_validation(
            next.id(),
            s.identity(),
            *key.sign(35, next.region())?.as_bytes(),
            60_000_103
        ),
        Err(Error::Stale)
    );
    Ok(())
}
