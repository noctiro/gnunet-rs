//! Caller-driven certificate lifecycle; no native IO or C acceptance credit.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Exact operation and resource invariants are asserted while setup failures propagate."
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::own_hello::HelloCandidate;
use gnunet_transport::{
    ClientId, Engine, Limits, PeerId, Signer,
    own::{self, Authority, Certificate, CommitOutcome, CommitResult},
};
use gnunet_types::Error;

struct Identity;
impl Signer for Identity {
    fn identity(&self) -> PeerId {
        PeerId([1; 32])
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
        Err(Error::Unavailable)
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(5);
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut b = vec![0; size];
    b[..2].copy_from_slice(&(size as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    b
}
fn owner(e: &mut Engine) -> Result<ClientId, Error> {
    let client = e.accept()?;
    let mut b = frame(1211, 16);
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[12..].copy_from_slice(b"tcp\0");
    e.receive(&client, &b, 1, &mut Identity, &mut Random)?;
    Ok(client)
}
fn add(e: &mut Engine, client: &ClientId, validity: u64) -> Result<(), Error> {
    add_at(e, client, validity, 2)
}
fn add_at(e: &mut Engine, client: &ClientId, validity: u64, now: u64) -> Result<(), Error> {
    let address = b"tcp-127.0.0.1:2086";
    let mut b = frame(1200, 21 + address.len());
    b[8..16].copy_from_slice(&validity.to_be_bytes());
    b[16..20].copy_from_slice(&1u32.to_be_bytes());
    b[20..20 + address.len()].copy_from_slice(address);
    e.receive(client, &b, now, &mut Identity, &mut Random)?;
    Ok(())
}
fn setup(validity: u64) -> Result<(Engine, ClientId), Error> {
    let mut e = Engine::new(PeerId([1; 32]), Limits::default())?;
    let client = owner(&mut e)?;
    add(&mut e, &client, validity)?;
    Ok((e, client))
}
fn certificate(e: &Engine, authority: Authority) -> Result<Certificate, Error> {
    Certificate::new(
        e.local_addresses().next().ok_or(Error::NotFound)?,
        authority,
        4096,
    )
}
fn sign(
    c: &mut Certificate,
    key: &EddsaPrivateKey,
    now: u64,
    stamp: u64,
) -> Result<own::OfferId, Error> {
    let id = c.prepare(now, stamp)?.clone();
    let signature = key.sign(29, c.signature_offer().ok_or(Error::NotReady)?.region)?;
    c.signing_admitted(&id)?;
    assert!(c.signed(&id, key.public_key(), signature)?);
    Ok(id)
}

#[test]
fn identical_zero_aid_adds_and_readd_never_adopt_the_original_result() -> Result<(), Error> {
    let (mut engine, client) = setup(120_000_000)?;
    let first = engine
        .local_addresses()
        .next()
        .ok_or(Error::NotFound)?
        .lease
        .clone();
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let authority = Authority::from_verified_peer(key.public_key());
    let mut old = certificate(&engine, authority.clone())?;
    let id = old.prepare(1, 123)?.clone();
    let signature = key.sign(29, old.signature_offer().ok_or(Error::NotReady)?.region)?;
    old.signing_admitted(&id)?;
    add(&mut engine, &client, 120_000_000)?;
    let duplicate = engine
        .local_addresses()
        .nth(1)
        .ok_or(Error::NotFound)?
        .lease
        .clone();
    assert_ne!(first, duplicate);
    engine.receive(&client, &frame(1201, 8), 3, &mut Identity, &mut Random)?;
    assert!(engine.owns_local_address(&first));
    assert!(!engine.owns_local_address(&duplicate));
    engine.receive(&client, &frame(1201, 8), 4, &mut Identity, &mut Random)?;
    old.retire();
    add_at(&mut engine, &client, 120_000_000, 5)?;
    let replacement = engine
        .local_addresses()
        .next()
        .ok_or(Error::NotFound)?
        .lease
        .clone();
    assert_ne!(first, replacement);
    assert_eq!(old.cancellation_required(), Some(&id));
    assert!(!old.signed(&id, key.public_key(), signature)?);
    assert!(old.effects_quiescent());
    assert!(old.record_draft().is_none());
    let mut new = certificate(&engine, authority)?;
    new.prepare(5, 124)?;
    assert_eq!(
        new.signed(&id, key.public_key(), signature),
        Err(Error::Stale)
    );
    assert!(engine.owns_local_address(&replacement));
    Ok(())
}

#[test]
fn reconstructed_slot_and_mutated_public_view_cannot_adopt_an_original() -> Result<(), Error> {
    let (engine, _) = setup(120_000_000)?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let authority = Authority::from_verified_peer(key.public_key());
    let mut first = certificate(&engine, authority.clone())?;
    let mut replacement = certificate(&engine, authority.clone())?;
    let old = first.prepare(10, 100)?.clone();
    let signature = key.sign(29, first.signature_offer().ok_or(Error::NotReady)?.region)?;
    let new = replacement.prepare(10, 100)?.clone();
    assert_ne!(old, new); // same lease/key/stamp still belongs to a different slot
    replacement.signing_admitted(&new)?;
    assert_eq!(
        replacement.signed(&old, key.public_key(), signature),
        Err(Error::Stale)
    );
    let mut view = engine.local_addresses().next().ok_or(Error::NotFound)?;
    view.address = b"tcp-127.0.0.1:2087";
    assert_eq!(
        Certificate::new(view, authority, 4096).err(),
        Some(Error::Stale)
    );
    Ok(())
}

#[test]
fn unknown_commit_keeps_original_until_recovery_and_does_not_reissue_signature() -> Result<(), Error>
{
    let (engine, _) = setup(120_000_000)?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let authority = Authority::from_verified_peer(key.public_key());
    let mut c = certificate(&engine, authority.clone())?;
    let id = sign(&mut c, &key, 10, 100)?;
    let original = c.record_draft().ok_or(Error::NotReady)?.value.to_vec();
    c.commit_started(&id)?;
    assert_eq!(
        c.commit_finished(&id, CommitOutcome::Unknown(Error::Storage), 11)?,
        CommitResult::Unknown(Error::Storage)
    );
    assert!(!c.effects_quiescent());
    assert!(c.current().is_none());
    assert_eq!(c.prepare(100_000_000, 101).err(), Some(Error::Conflict));
    assert!(c.signature_offer().is_none());
    let replacement_authority = Authority::from_verified_peer(key.public_key());
    assert_ne!(authority, replacement_authority); // same peer is not the same physical authority
    c.retire();
    assert_eq!(
        c.recovered(&id, CommitOutcome::Committed, 12)?,
        CommitResult::Committed {
            retired: true,
            refresh: Ok(30_000_012)
        }
    );
    assert!(c.effects_quiescent());
    assert_eq!(c.current().ok_or(Error::NotReady)?.value, original);
    assert_eq!(c.prepare(100_000_000, 101).err(), Some(Error::Stale));
    assert_eq!(
        c.recovered(&id, CommitOutcome::Committed, 13),
        Err(Error::Stale)
    );
    Ok(())
}

#[test]
fn failed_candidate_preserves_old_durable_record_and_future_attempt_is_fresh_paced()
-> Result<(), Error> {
    let (engine, _) = setup(0)?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let mut c = certificate(&engine, Authority::from_verified_peer(key.public_key()))?;
    let first = sign(&mut c, &key, 10, 100)?;
    assert_eq!(c.record_draft().ok_or(Error::NotReady)?.expiry, 10);
    c.commit_started(&first)?;
    c.commit_finished(&first, CommitOutcome::Committed, 11)?;
    let original = c.current().ok_or(Error::NotReady)?.value.to_vec();
    assert_eq!(c.prepare(30_000_010, 101).err(), Some(Error::NotReady));
    let second = sign(&mut c, &key, 30_000_011, 101)?;
    assert_ne!(first, second);
    c.commit_started(&second)?;
    assert_eq!(
        c.commit_finished(
            &second,
            CommitOutcome::NotCommitted(Error::Storage),
            30_000_012
        )?,
        CommitResult::NotCommitted {
            cause: Error::Storage,
            retry: Ok(60_000_012)
        }
    );
    assert_eq!(c.current().ok_or(Error::NotReady)?.value, original);
    assert_eq!(c.prepare(60_000_011, 102).err(), Some(Error::NotReady));
    assert_eq!(c.prepare(60_000_012, 101).err(), Some(Error::Replay));
    assert!(c.prepare(60_000_012, 102).is_ok());
    Ok(())
}

#[test]
fn finite_forever_and_maximum_deadlines_are_explicit_without_partial_effects() -> Result<(), Error>
{
    assert_eq!(own::refresh_interval(0), own::REFRESH_FLOOR);
    assert_eq!(own::refresh_interval(120_000_000), own::REFRESH_FLOOR);
    assert_eq!(own::refresh_interval(u64::MAX), own::REFRESH_CAP);
    let (engine, _) = setup(u64::MAX)?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let mut c = certificate(&engine, Authority::from_verified_peer(key.public_key()))?;
    assert_eq!(
        c.prepare(u64::MAX - own::REFRESH_CAP, 1).err(),
        Some(Error::Overflow)
    );
    assert!(c.effects_quiescent());
    assert_eq!(c.refresh_deadline(), Some(0));
    let id = sign(&mut c, &key, 1, 1)?;
    assert_eq!(c.record_draft().ok_or(Error::NotReady)?.expiry, u64::MAX);
    c.commit_started(&id)?;
    assert_eq!(
        c.commit_finished(&id, CommitOutcome::Committed, u64::MAX - own::REFRESH_FLOOR)?,
        CommitResult::Committed {
            retired: false,
            refresh: Err(Error::Overflow)
        }
    );
    assert!(c.current().is_some()); // known commit is consumed despite the later clock error
    assert!(c.refresh_deadline().is_none());
    assert_eq!(c.prepare(u64::MAX, 2).err(), Some(Error::Overflow));
    Ok(())
}

#[test]
fn publisher_checks_every_real_wrapper_without_reducing_external_observation() -> Result<(), Error>
{
    let normal = own::PublicationBounds::checked(8, 4096, 65535, 65535)?;
    assert_eq!(normal.address_bytes, 2064);
    assert_eq!(normal.hello_record_bytes - normal.pils_bytes, 31);
    own::PublicationBounds::checked(65, 4096, 65535, 65535)?;
    assert_eq!(
        own::PublicationBounds::checked(1, 130_714, 65535, 65535),
        Err(Error::Capacity)
    );
    let boundary = own::PublicationBounds::checked(1, 130_646, 65535, 65535)?;
    assert_eq!(boundary.own_record_bytes, 65535);
    assert_eq!(
        own::PublicationBounds::checked(8, 4096, 176, 65535),
        Err(Error::Capacity)
    );
    assert_eq!(
        own::PublicationBounds::checked(8, 4096, 65535, 207),
        Err(Error::Capacity)
    );
    let empty = own::PublicationBounds::checked(0, 0, 176, 207)?;
    assert_eq!((empty.address_bytes, empty.own_record_bytes), (0, 0));
    Ok(())
}

#[test]
fn certificate_refuses_an_unrepresentable_public_frame_before_signing() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([17; 32]);
    for native_bytes in [65_322, 65_323] {
        let mut engine = Engine::new(
            PeerId([1; 32]),
            Limits {
                control_messages: 1,
                control_bytes: 2 * native_bytes + 2,
                ..Limits::default()
            },
        )?;
        let client = owner(&mut engine)?;
        let mut address = vec![b'x'; native_bytes];
        address[..4].copy_from_slice(b"tcp-");
        let mut add = frame(1200, 21 + native_bytes);
        add[8..16].copy_from_slice(&120_000_000_u64.to_be_bytes());
        add[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        add[20..20 + native_bytes].copy_from_slice(&address);
        engine.receive(&client, &add, 2, &mut Identity, &mut Random)?;
        let local = engine.local_addresses().next().ok_or(Error::NotFound)?;
        let lease = local.lease.clone();
        let certificate = Certificate::new(
            local,
            Authority::from_verified_peer(key.public_key()),
            u16::MAX as usize,
        );
        if native_bytes == 65_322 {
            let mut certificate = certificate?;
            sign(&mut certificate, &key, 3, u64::MAX)?;
            let draft = certificate.record_draft().ok_or(Error::NotReady)?;
            assert_eq!(draft.value.len() + 60 + 10 + 21, u16::MAX as usize);
        } else {
            assert_eq!(certificate.err(), Some(Error::Capacity));
        }
        assert!(engine.owns_local_address(&lease));
        assert_eq!(engine.local_addresses().count(), 1);
    }
    Ok(())
}

#[test]
fn aggregate_uses_original_set_common_encoder_and_actual_metadata_coverage() -> Result<(), Error> {
    let (mut engine, client) = setup(120_000_000)?;
    let feed = engine
        .address_publication()?
        .ok_or(Error::NotReady)?
        .id()
        .clone();
    engine.claim_address_publication(&feed)?;
    engine.address_publication_written(&feed)?;
    assert!(engine.address_publication()?.is_none());
    assert_eq!(engine.address_snapshot()?.uris().count(), 1);
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let authority = Authority::from_verified_peer(key.public_key());
    let bounds = own::PublicationBounds::checked(8, 4096, 65535, 65535)?;
    let mut candidate =
        HelloCandidate::prepare(engine.address_snapshot()?, authority.clone(), 10, bounds, 8)?;
    let id = candidate.id().clone();
    let mut scratch = [0; 4096];
    let signature = candidate.with_builder(&mut scratch, |builder| {
        Ok(builder
            .sign(
                &key,
                candidate.expiry(),
                gnunet_hello::SignatureProfile::Gnunet029,
            )?
            .signature())
    })?;
    candidate.signing_admitted(&id)?;
    assert_eq!(
        candidate.signed(&id, key.public_key(), signature, &mut []),
        Err(Error::Capacity)
    );
    assert!(candidate.signed(&id, key.public_key(), signature, &mut scratch)?);
    let bytes = candidate.projection().flatten().ok_or(Error::NotReady)?;
    let mut parse_storage = [0; 4096];
    let hello = gnunet_hello::Hello::parse_message(
        bytes,
        None,
        &mut parse_storage,
        gnunet_hello::Limits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 4096,
            maximum_addresses: 64,
        },
    )?;
    assert_eq!(
        hello
            .verify_at(
                gnunet_hello::SignatureProfile::Gnunet029,
                gnunet_hello::AbsoluteTime::from_micros(10)
            )?
            .coverage(),
        gnunet_hello::SignatureCoverage::MetadataOnly
    );
    assert_eq!(
        gnunet_hello::message_expiration(bytes)?.as_micros(),
        10 + own::HELLO_TTL
    );
    assert!(candidate.matches(&engine.address_snapshot()?, &authority));
    engine.close(&client)?;
    assert!(!candidate.matches(&engine.address_snapshot()?, &authority));
    candidate.retire();
    assert!(candidate.projection().is_none());
    Ok(())
}

#[test]
fn empty_set_is_managed_withdrawal_and_original_unknown_survives_retirement() -> Result<(), Error> {
    let engine = Engine::new(PeerId([1; 32]), Limits::default())?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let authority = Authority::from_verified_peer(key.public_key());
    let bounds = own::PublicationBounds::checked(8, 4096, 65535, 65535)?;
    let mut empty =
        HelloCandidate::prepare(engine.address_snapshot()?, authority.clone(), 10, bounds, 8)?;
    assert!(!empty.needs_signature());
    assert_eq!(empty.projection(), Some(None));
    let other =
        HelloCandidate::prepare(engine.address_snapshot()?, authority.clone(), 10, bounds, 8)?;
    assert_ne!(empty.id(), other.id());
    assert_eq!(empty.commit_started(other.id()), Err(Error::Stale));
    let id = empty.id().clone();
    empty.commit_started(&id)?;
    empty.commit_finished(&id, CommitOutcome::Unknown(Error::Storage))?;
    empty.retire();
    assert!(!empty.effects_quiescent());
    assert_eq!(
        empty.recovered(other.id(), CommitOutcome::Committed),
        Err(Error::Stale)
    );
    empty.recovered(&id, CommitOutcome::Committed)?;
    assert!(empty.effects_quiescent());
    let mut scratch = [];
    let builder = gnunet_hello::HelloBuilder::new(
        &mut scratch,
        gnunet_hello::Limits {
            maximum_input_bytes: 112,
            maximum_address_bytes: 0,
            maximum_addresses: 0,
        },
    );
    let hello = builder.sign(
        &key,
        gnunet_hello::AbsoluteTime::from_micros(10 + own::HELLO_TTL),
        gnunet_hello::SignatureProfile::Gnunet029,
    )?;
    let mut binary = [0; 112];
    hello.encode_message(&mut binary)?;
    assert_eq!(gnunet_hello::message_expiration(&binary)?.as_micros(), 0);
    assert!(
        HelloCandidate::prepare(
            engine.address_snapshot()?,
            authority,
            u64::MAX - own::HELLO_TTL,
            bounds,
            8
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn aggregate_refresh_is_finite_only_after_known_commit_and_forever_hint_cannot_disable_it()
-> Result<(), Error> {
    let (engine, _client) = setup(u64::MAX)?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let authority = Authority::from_verified_peer(key.public_key());
    let bounds = own::PublicationBounds::checked(8, 4096, 65535, 65535)?;
    let mut candidate =
        HelloCandidate::prepare(engine.address_snapshot()?, authority.clone(), 10, bounds, 8)?;
    let id = candidate.id().clone();
    assert_eq!(candidate.refresh_deadline(), None);
    let signature = key.sign(7, candidate.signed_region())?;
    candidate.signing_admitted(&id)?;
    candidate.signed(&id, key.public_key(), signature, &mut [0; 4096])?;
    candidate.commit_started(&id)?;
    assert_eq!(candidate.refresh_deadline(), None);
    candidate.commit_finished(&id, CommitOutcome::Unknown(Error::Storage))?;
    assert_eq!(candidate.refresh_deadline(), None);
    candidate.recovered(&id, CommitOutcome::Committed)?;
    assert_eq!(candidate.refresh_deadline(), Some(10 + own::REFRESH_CAP));
    assert!(candidate.refresh_deadline().ok_or(Error::NotReady)? < candidate.expiry().as_micros());
    candidate.retire();
    assert_eq!(candidate.refresh_deadline(), None);
    let empty = Engine::new(PeerId([1; 32]), Limits::default())?;
    let mut withdrawal =
        HelloCandidate::prepare(empty.address_snapshot()?, authority, 10, bounds, 8)?;
    let id = withdrawal.id().clone();
    withdrawal.commit_started(&id)?;
    withdrawal.commit_finished(&id, CommitOutcome::Committed)?;
    assert_eq!(withdrawal.refresh_deadline(), None);
    Ok(())
}
