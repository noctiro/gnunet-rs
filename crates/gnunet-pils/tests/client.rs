//! Typed operation ownership, actual crypto, reconnect and secret-buffer boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible behavioral regressions assert independent protocol/resource outcomes"
)]
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512};
use gnunet_hello::{HelloBuilder, SignatureCoverage};
use gnunet_pils::{
    Action, HELLO_LIFETIME, HelloLimits, MasterKey, Profile, Service,
    client::{
        Client, Completion, Epoch, Failure, FeedDisposition, Identity, Inbound, Instance,
        KeyTarget, LocalKeyStatus, OperationKind, Outbound,
    },
};
use gnunet_session_crypto::exchange::{EcdhePublic, EcdheSecret, kem_encapsulate};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, SignaturePurpose,
    pils::{Request, Response},
};
type Owner<'a> = Client<'a, 8, 1024, 2048>;
fn limits() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 1024,
        maximum_addresses: 32,
    }
}
fn owner(instance: &mut Instance, profile: Profile) -> Result<Owner<'_>, Error> {
    Client::new(instance, profile, limits())
}
fn service(profile: Profile) -> Result<Service<2048>, Error> {
    Service::new(MasterKey::from_seed([17; 32]), profile, 100, limits())
}
fn region() -> Result<[u8; 24], Error> {
    let mut r = [0x41; 24];
    SignaturePurpose::new(35, 16)?.encode(&mut r)?;
    Ok(r)
}
fn announcement<'a>(
    c: &mut Owner<'a>,
    e: Epoch<'a>,
    s: &Service<2048>,
    now: u64,
) -> Result<Identity<'a>, Error> {
    let mut bytes = s.announcement().to_vec();
    let result = c.receive(
        e,
        &mut bytes,
        &mut [0; 1024],
        AbsoluteTime::from_micros(now),
    )?;
    assert!(bytes.iter().all(|b| *b == 0));
    match result {
        Inbound::Identity { identity, .. } => Ok(identity),
        _ => Err(Error::Malformed),
    }
}
fn connect<'a>(c: &mut Owner<'a>, s: &Service<2048>) -> Result<(Epoch<'a>, Identity<'a>), Error> {
    let e = c.begin_connection(AbsoluteTime::from_micros(0))?;
    Ok((e, announcement(c, e, s, 100)?))
}
fn take<'a>(c: &mut Owner<'a>, e: Epoch<'a>) -> Result<(Outbound<'a>, Vec<u8>), Error> {
    let mut out = [0xcc; 1024];
    let tx = c.next_request(e, &mut out)?.ok_or(Error::NotReady)?;
    assert_eq!(&out[tx.len..], &vec![0xcc; out.len() - tx.len]);
    Ok((tx, out[..tx.len].to_vec()))
}
fn written<'a>(c: &mut Owner<'a>, e: Epoch<'a>) -> Result<(Outbound<'a>, Vec<u8>), Error> {
    let (tx, bytes) = take(c, e)?;
    let fact = c.written(e, tx.transmit)?;
    assert_eq!(fact.operation, tx.operation);
    assert_eq!(fact.kind, tx.kind);
    assert!(!fact.canceled);
    Ok((tx, bytes))
}
fn reply(s: &mut Service<2048>, request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = [0; 104];
    match s.receive(request, &mut [0; 1024], 100, &mut out)? {
        Action::Reply { len, .. } => Ok(out[..len].to_vec()),
        _ => Err(Error::Malformed),
    }
}
fn rotate(s: &mut Service<2048>, addresses: &[&[u8]]) -> Result<(), Error> {
    let mut scratch = [0; 1024];
    let mut builder = HelloBuilder::new(&mut scratch, limits());
    for address in addresses {
        builder.add_address(address)?;
    }
    let hello = builder.with_signature(
        EddsaPublicKey::from_bytes([0; 32]),
        EddsaSignature::from_bytes([0; 64]),
        AbsoluteTime::from_micros(0),
    );
    let mut block = [0; 1200];
    let n = hello.encode_block(&mut block)?;
    let mut frame = [0; 1240];
    let n = Request::Feed { block: &block[..n] }.encode(&mut frame)?;
    assert!(matches!(
        s.receive(&frame[..n], &mut [0; 1024], 200, &mut [])?,
        Action::Broadcast { .. }
    ));
    Ok(())
}
#[test]
fn initial_announcement_binds_profile_hash_identity_and_matching_local_key() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut c = owner(&mut instance, Profile::Reference029)?;
    let s = service(Profile::Reference029)?;
    assert_eq!(
        c.enable_local_key(MasterKey::from_seed([17; 32]))?,
        LocalKeyStatus::Waiting
    );
    let (e, identity) = connect(&mut c, &s)?;
    assert_eq!(identity.peer(), s.identity().public_key());
    assert_eq!(identity.peer_hash(), hash512(identity.peer().as_bytes()));
    assert_eq!(identity.address_hash(), s.address_hash());
    assert_eq!(identity.coverage(), SignatureCoverage::MetadataOnly);
    assert_eq!(c.local_key_status(), LocalKeyStatus::Matched);
    assert_eq!(
        c.local_key().ok_or(Error::NotReady)?.public_key(),
        identity.peer()
    );
    assert_eq!(c.last_announcement(), s.announcement());
    c.connection_lost(e, AbsoluteTime::from_micros(0))?;
    assert!(c.identity().is_none() && c.local_key().is_none());
    assert_eq!(c.local_key_status(), LocalKeyStatus::Waiting);
    assert_eq!(c.last_announcement(), s.announcement());
    Ok(())
}
#[test]
fn invalid_expired_and_capacity_refused_announcements_do_not_replace_original_authority()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let s = service(Profile::Reference029)?;
    let (e, identity) = connect(&mut c, &s)?;
    for offset in [4, 72, 104] {
        let mut bytes = s.announcement().to_vec();
        bytes[offset] ^= 1;
        assert!(
            c.receive(
                e,
                &mut bytes,
                &mut [0; 1024],
                AbsoluteTime::from_micros(100)
            )
            .is_err()
        );
        assert!(bytes.iter().all(|b| *b == 0));
        assert_eq!(c.identity(), Some(identity));
        assert_eq!(c.last_announcement(), s.announcement());
    }
    let mut bytes = s.announcement().to_vec();
    assert!(matches!(
        c.receive(
            e,
            &mut bytes,
            &mut [0; 1024],
            AbsoluteTime::from_micros(101 + HELLO_LIFETIME)
        ),
        Err(Error::Timeout)
    ));
    assert!(bytes.iter().all(|b| *b == 0));
    assert_eq!(c.identity(), Some(identity));
    let mut bytes = s.announcement().to_vec();
    bytes.extend_from_slice(&[0; 2048]);
    assert!(
        c.receive(e, &mut bytes, &mut [], AbsoluteTime::from_micros(100))
            .is_err()
    );
    assert_eq!(c.identity(), Some(identity));
    Ok(())
}
#[test]
fn profile_coverage_and_textual_label_difference_are_explicit_without_fallback() -> Result<(), Error>
{
    for profile in [Profile::Reference029, Profile::ReferenceDeterministic] {
        let mut i = Instance::new();
        let mut c = owner(&mut i, profile)?;
        let mut s = service(profile)?;
        let (e, before) = connect(&mut c, &s)?;
        rotate(&mut s, &[b"tcp://127.0.0.1:1234"])?;
        let after = announcement(&mut c, e, &s, 200)?;
        assert_eq!(
            before.peer() == after.peer(),
            profile == Profile::Reference029
        );
        let mut altered = s.announcement().to_vec();
        let last = altered.len() - 2;
        altered[last] = b'5';
        let result = c.receive(
            e,
            &mut altered,
            &mut [0; 1024],
            AbsoluteTime::from_micros(200),
        );
        if profile == Profile::Reference029 {
            assert!(matches!(result, Ok(Inbound::Identity { .. })));
        } else {
            assert!(matches!(result, Err(Error::Authentication)));
        }
        assert!(altered.iter().all(|b| *b == 0));
    }
    let mut i = Instance::new();
    let mut text = owner(&mut i, Profile::Lsd0014Text)?;
    let mut source = service(Profile::ReferenceDeterministic)?;
    rotate(&mut source, &[b"tcp://127.0.0.1:1234"])?;
    text.enable_local_key(MasterKey::from_seed([17; 32]))?;
    let (_, id) = connect(&mut text, &source)?;
    assert_eq!(text.local_key_status(), LocalKeyStatus::Mismatch);
    assert!(text.local_key().is_none());
    assert_eq!(text.identity(), Some(id));
    Ok(())
}
#[test]
fn signature_verifies_exact_original_region_and_full_write_is_not_a_remote_ack() -> Result<(), Error>
{
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let mut s = service(Profile::Reference029)?;
    let (e, identity) = connect(&mut c, &s)?;
    let payload = region()?;
    let op = c.sign(&payload, KeyTarget::Exact(identity))?;
    let (tx, bytes) = take(&mut c, e)?;
    let mut result = reply(&mut s, &bytes)?;
    assert!(matches!(
        c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(100)),
        Err(Error::NotReady)
    ));
    assert!(result.iter().all(|b| *b == 0));
    assert_eq!(c.pending(), 1);
    c.written(e, tx.transmit)?;
    assert_eq!(c.pending(), 1);
    let mut result = reply(&mut s, &bytes)?;
    match c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(100))? {
        Inbound::Complete(Completion::Signature {
            operation,
            peer,
            signature,
            announced,
        }) => {
            assert_eq!(operation, op);
            assert_eq!(peer, identity.peer());
            assert_eq!(announced, Some(identity));
            peer.verify(35, &payload, &signature)?;
        }
        _ => return Err(Error::Malformed),
    }
    assert_eq!(c.pending(), 0);
    assert!(result.iter().all(|b| *b == 0));
    Ok(())
}
#[test]
fn actual_kem_and_ecdh_results_transfer_distinct_secret_owners_and_erase_original_frames()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let mut s = service(Profile::Reference029)?;
    let (e, identity) = connect(&mut c, &s)?;
    let ephemeral = EcdheSecret::from_bytes([7; 32]);
    let public = EcdhePublic::from_edwards(identity.peer().as_bytes())?;
    let (enc, expected_kem) = kem_encapsulate(public, &ephemeral)?;
    let expected_kem = expected_kem.into_secret_bytes();
    let expected_dh = ephemeral.exchange_hashed(public)?.into_secret_bytes();
    let kem = c.decapsulate(*enc.as_bytes(), KeyTarget::Exact(identity))?;
    let dh = c.ecdh(
        *ephemeral.public_key().as_bytes(),
        KeyTarget::Exact(identity),
    )?;
    let (kem_tx, kem_bytes) = written(&mut c, e)?;
    let (dh_tx, dh_bytes) = written(&mut c, e)?;
    assert_eq!(kem_tx.operation, kem);
    assert_eq!(dh_tx.operation, dh);
    let mut dh_result = reply(&mut s, &dh_bytes)?;
    match c.receive(e, &mut dh_result, &mut [], AbsoluteTime::from_micros(100))? {
        Inbound::Complete(Completion::Ecdh {
            operation,
            identity: observed,
            mut key,
        }) => {
            assert_eq!(operation, dh);
            assert_eq!(observed, identity);
            assert_eq!(key.as_bytes(), expected_dh.as_ref());
            key.erase();
            assert_eq!(key.as_bytes(), &[0; 64]);
        }
        _ => return Err(Error::Malformed),
    }
    let mut kem_result = reply(&mut s, &kem_bytes)?;
    match c.receive(e, &mut kem_result, &mut [], AbsoluteTime::from_micros(100))? {
        Inbound::Complete(Completion::Decapsulated {
            operation,
            identity: observed,
            key,
        }) => {
            assert_eq!(operation, kem);
            assert_eq!(observed, identity);
            assert_eq!(key.as_bytes(), expected_kem.as_ref());
        }
        _ => return Err(Error::Malformed),
    }
    assert!(dh_result.iter().chain(kem_result.iter()).all(|b| *b == 0));
    assert_eq!(c.pending(), 0);
    Ok(())
}
#[test]
fn reference_zero_crypto_results_and_invalid_signature_are_explicit_failed_completions()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let mut s = service(Profile::Reference029)?;
    let (e, identity) = connect(&mut c, &s)?;
    for kind in [
        OperationKind::Sign,
        OperationKind::Decapsulate,
        OperationKind::Ecdh,
    ] {
        let op = match kind {
            OperationKind::Sign => c.sign(&region()?, KeyTarget::ServiceCurrent)?,
            OperationKind::Decapsulate => c.decapsulate([0; 32], KeyTarget::ServiceCurrent)?,
            OperationKind::Ecdh => c.ecdh([0; 32], KeyTarget::ServiceCurrent)?,
            _ => return Err(Error::Malformed),
        };
        let (_, bytes) = written(&mut c, e)?;
        let mut result = reply(&mut s, &bytes)?;
        if kind == OperationKind::Sign {
            result[36..100].fill(0);
        }
        assert!(
            matches!(c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(100))?, Inbound::Complete(Completion::Failed { operation, reason: Failure::CryptoRejected, .. }) if operation == op)
        );
        assert!(result.iter().all(|b| *b == 0));
    }
    let op = c.sign(&region()?, KeyTarget::Exact(identity))?;
    let (_, bytes) = written(&mut c, e)?;
    let mut result = reply(&mut s, &bytes)?;
    result[50] ^= 1;
    assert!(
        matches!(c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(100))?, Inbound::Complete(Completion::Failed { operation, reason: Failure::InvalidSignature, .. }) if operation == op)
    );
    Ok(())
}
#[test]
fn cancel_foreign_ids_and_late_results_cannot_complete_a_reused_operation_slot() -> Result<(), Error>
{
    let (mut ia, mut ib) = (Instance::new(), Instance::new());
    let mut a = owner(&mut ia, Profile::Reference029)?;
    let mut b = owner(&mut ib, Profile::Reference029)?;
    let mut s = service(Profile::Reference029)?;
    let (ea, _) = connect(&mut a, &s)?;
    let (eb, _) = connect(&mut b, &s)?;
    let old = a.sign(&region()?, KeyTarget::ServiceCurrent)?;
    let other = b.sign(&region()?, KeyTarget::ServiceCurrent)?;
    assert_eq!(old.value(), other.value());
    assert_ne!(old, other);
    assert_eq!(a.cancel(other), Err(Error::Stale));
    let (old_tx, old_bytes) = take(&mut a, ea)?;
    let (other_tx, _) = take(&mut b, eb)?;
    assert_eq!(old_tx.transmit.value(), other_tx.transmit.value());
    assert_eq!(a.written(ea, other_tx.transmit), Err(Error::Stale));
    a.cancel(old)?;
    let new = a.sign(&region()?, KeyTarget::ServiceCurrent)?;
    assert_eq!(a.pending(), 1);
    assert!(a.next_request(ea, &mut [0; 1024])?.is_none());
    assert!(a.written(ea, old_tx.transmit)?.canceled);
    assert_eq!(a.written(ea, old_tx.transmit), Err(Error::Stale));
    let mut result = reply(&mut s, &old_bytes)?;
    assert!(matches!(
        a.receive(ea, &mut result, &mut [], AbsoluteTime::from_micros(100))?,
        Inbound::Ignored
    ));
    assert!(result.iter().all(|b| *b == 0));
    let (_, new_bytes) = written(&mut a, ea)?;
    assert!(matches!(
        Request::decode(&new_bytes)?,
        Request::Sign { request: 1, .. }
    ));
    let mut result = reply(&mut s, &new_bytes)?;
    assert!(matches!(
        a.receive(eb, &mut result, &mut [], AbsoluteTime::from_micros(100)),
        Err(Error::Stale)
    ));
    assert_eq!(a.pending(), 1);
    assert!(result.iter().all(|b| *b == 0));
    let mut result = reply(&mut s, &new_bytes)?;
    assert!(
        matches!(a.receive(ea, &mut result, &mut [], AbsoluteTime::from_micros(100))?, Inbound::Complete(Completion::Signature { operation, .. }) if operation == new)
    );
    let mut result = reply(&mut s, &new_bytes)?;
    assert!(matches!(
        a.receive(ea, &mut result, &mut [], AbsoluteTime::from_micros(100))?,
        Inbound::Ignored
    ));
    assert_eq!(a.pending(), 0);
    Ok(())
}
#[test]
fn physical_mq_loss_replays_exact_crypto_bytes_with_new_original_transmit_authority()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let mut s = service(Profile::Reference029)?;
    let (old, identity) = connect(&mut c, &s)?;
    let op = c.sign(&region()?, KeyTarget::Exact(identity))?;
    let (first, original) = take(&mut c, old)?;
    let loss = c.connection_lost(old, AbsoluteTime::from_micros(100))?;
    assert_eq!(loss.retained(), 1);
    assert_eq!(loss.feeds().count(), 0);
    assert!(c.identity().is_none());
    let new = c.begin_connection(AbsoluteTime::from_micros(0))?;
    assert_ne!(new, old);
    assert_eq!(c.written(new, first.transmit), Err(Error::Stale));
    announcement(&mut c, new, &s, 100)?;
    let (retry, replay) = written(&mut c, new)?;
    assert_eq!(replay, original);
    assert_eq!(retry.operation, op);
    assert_ne!(retry.transmit, first.transmit);
    let mut old_result = reply(&mut s, &original)?;
    assert!(matches!(
        c.receive(
            old,
            &mut old_result,
            &mut [],
            AbsoluteTime::from_micros(100)
        ),
        Err(Error::Stale)
    ));
    assert_eq!(c.pending(), 1);
    assert!(old_result.iter().all(|b| *b == 0));
    let mut result = reply(&mut s, &replay)?;
    assert!(
        matches!(c.receive(new, &mut result, &mut [], AbsoluteTime::from_micros(100))?, Inbound::Complete(Completion::Signature { operation, .. }) if operation == op)
    );
    Ok(())
}
#[test]
fn key_rotation_fails_exact_dh_without_relabelling_secret_bytes() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::ReferenceDeterministic)?;
    let mut s = service(Profile::ReferenceDeterministic)?;
    let (e, original) = connect(&mut c, &s)?;
    let exact = c.ecdh([7; 32], KeyTarget::Exact(original))?;
    let current = c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
    let (_, exact_bytes) = written(&mut c, e)?;
    let (_, current_bytes) = written(&mut c, e)?;
    rotate(&mut s, &[b"tcp://127.0.0.1:42"])?;
    let next = announcement(&mut c, e, &s, 200)?;
    assert_ne!(original.peer(), next.peer());
    assert_eq!(
        c.ecdh([7; 32], KeyTarget::Exact(original)),
        Err(Error::Stale)
    );
    let mut result = reply(&mut s, &exact_bytes)?;
    assert!(
        matches!(c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(200))?, Inbound::Complete(Completion::Failed { operation, reason: Failure::KeyChanged, .. }) if operation == exact)
    );
    assert!(result.iter().all(|b| *b == 0));
    let mut result = reply(&mut s, &current_bytes)?;
    assert!(
        matches!(c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(200))?, Inbound::Complete(Completion::Ecdh { operation, identity, .. }) if operation == current && identity == next)
    );
    Ok(())
}
#[test]
fn feed_and_sign_hello_use_official_blocks_without_inventing_a_feed_ack() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::ReferenceDeterministic)?;
    let mut s = service(Profile::ReferenceDeterministic)?;
    let (e, _) = connect(&mut c, &s)?;
    let mut storage = [0; 1024];
    let mut builder = HelloBuilder::new(&mut storage, limits());
    builder.add_address(b"tcp://127.0.0.1:7")?;
    let feed = c.feed_addresses(e, &builder, AbsoluteTime::from_micros(200), &mut [0; 1200])?;
    let (out, bytes) = written(&mut c, e)?;
    assert_eq!(out.operation, feed);
    assert_eq!(out.kind, OperationKind::Feed);
    assert_eq!(c.pending(), 0);
    assert!(matches!(
        s.receive(&bytes, &mut [0; 1024], 200, &mut [])?,
        Action::Broadcast {
            identity_changed: true
        }
    ));
    let id = announcement(&mut c, e, &s, 200)?;
    let expiration = AbsoluteTime::from_micros(400);
    let sign = c.sign_hello(&builder, expiration, KeyTarget::Exact(id))?;
    let (_, bytes) = written(&mut c, e)?;
    let mut result = reply(&mut s, &bytes)?;
    match c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(200))? {
        Inbound::Complete(Completion::Signature {
            operation,
            peer,
            signature,
            ..
        }) => {
            assert_eq!(operation, sign);
            builder
                .with_signature(peer, signature, expiration)
                .verify_at(
                    Profile::ReferenceDeterministic.hello(),
                    AbsoluteTime::from_micros(200),
                )?;
        }
        _ => return Err(Error::Malformed),
    }
    Ok(())
}
#[test]
fn loss_reports_original_feed_submission_boundaries_without_replay() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let s = service(Profile::Reference029)?;
    let (e, _) = connect(&mut c, &s)?;
    let mut store = [];
    let builder = HelloBuilder::new(&mut store, limits());
    let first = c.feed_addresses(e, &builder, AbsoluteTime::from_micros(100), &mut [0; 104])?;
    let second = c.feed_addresses(e, &builder, AbsoluteTime::from_micros(100), &mut [0; 104])?;
    let crypto = c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
    let (out, _) = take(&mut c, e)?;
    assert_eq!(out.operation, first);
    let loss = c.connection_lost(e, AbsoluteTime::from_micros(100))?;
    let feeds: Vec<_> = loss.feeds().collect();
    assert_eq!(feeds.len(), 2);
    assert!(
        feeds
            .iter()
            .any(|f| f.operation == first && f.disposition == FeedDisposition::SubmissionUnknown)
    );
    assert!(
        feeds
            .iter()
            .any(|f| f.operation == second && f.disposition == FeedDisposition::NotSubmitted)
    );
    assert_eq!(loss.retained(), 1);
    let new = c.begin_connection(AbsoluteTime::from_micros(0))?;
    let (retry, _) = take(&mut c, new)?;
    assert_eq!(retry.operation, crypto);
    Ok(())
}
#[test]
fn wrong_response_family_and_unannounced_keys_do_not_fake_success() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let e = c.begin_connection(AbsoluteTime::from_micros(0))?;
    let op = c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
    let (_, bytes) = written(&mut c, e)?;
    let rid = match Request::decode(&bytes)? {
        Request::Ecdh { request, .. } => request,
        _ => return Err(Error::Malformed),
    };
    let mut wrong = [0; 40];
    Response::Decapsulation {
        request: rid,
        key: &[8; 32],
    }
    .encode(&mut wrong)?;
    assert!(matches!(
        c.receive(e, &mut wrong, &mut [], AbsoluteTime::from_micros(100)),
        Err(Error::Malformed)
    ));
    assert_eq!(c.pending(), 1);
    assert_eq!(wrong, [0; 40]);
    let mut out = [0; 72];
    Response::Ecdh {
        request: rid,
        key: &[8; 64],
    }
    .encode(&mut out)?;
    assert!(
        matches!(c.receive(e, &mut out, &mut [], AbsoluteTime::from_micros(100))?, Inbound::Complete(Completion::Failed { operation, reason: Failure::IdentityUnavailable, .. }) if operation == op)
    );
    assert_eq!(out, [0; 72]);
    Ok(())
}
#[test]
fn bounded_resources_and_short_output_refuse_atomically_without_consuming_wire_numbers()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::<1, 40, 176>::new(&mut i, Profile::Reference029, limits())?;
    assert_eq!(
        c.sign(&[0; 8], KeyTarget::ServiceCurrent),
        Err(Error::InvalidInput)
    );
    let mut oversized = [7; 41];
    SignaturePurpose::new(35, 33)?.encode(&mut oversized)?;
    assert_eq!(
        c.sign(&oversized, KeyTarget::ServiceCurrent),
        Err(Error::Capacity)
    );
    let op = c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
    assert_eq!(
        c.decapsulate([7; 32], KeyTarget::ServiceCurrent),
        Err(Error::Capacity)
    );
    let e = c.begin_connection(AbsoluteTime::from_micros(0))?;
    let mut short = [0xa5; 39];
    assert_eq!(c.next_request(e, &mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 39]);
    let mut bytes = [0; 40];
    let tx = c.next_request(e, &mut bytes)?.ok_or(Error::NotReady)?;
    assert_eq!(tx.operation, op);
    assert!(matches!(
        Request::decode(&bytes)?,
        Request::Ecdh { request: 0, .. }
    ));
    let retired = c.close();
    assert_eq!(retired, [Some(op)]);
    assert_eq!(c.close(), [None]);
    assert_eq!(c.cancel(op), Err(Error::Stale));
    assert_eq!(c.pending(), 0);
    Ok(())
}
#[test]
fn canonical_backoff_zero_ready_cap_forever_and_result_reset_are_explicit() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    c.connection_unavailable(AbsoluteTime::from_micros(100))?;
    assert_eq!(c.next_wakeup(), Some(AbsoluteTime::from_micros(0)));
    assert!(c.connection_needed(AbsoluteTime::from_micros(0)));
    let mut now = 0;
    for step in 0..32 {
        c.connection_unavailable(AbsoluteTime::from_micros(now))?;
        let next = c.next_wakeup().ok_or(Error::NotReady)?.as_micros();
        let delay = 1000u64.saturating_mul(1u64 << step).min(900_000_000);
        assert_eq!(next, now + delay);
        assert!(!c.connection_needed(AbsoluteTime::from_micros(next - 1)));
        assert!(c.connection_needed(AbsoluteTime::from_micros(next)));
        now = next;
    }
    let e = c.begin_connection(AbsoluteTime::from_micros(now))?;
    let mut ignored = [0; 40];
    Response::Decapsulation {
        request: 177,
        key: &[7; 32],
    }
    .encode(&mut ignored)?;
    assert!(matches!(
        c.receive(e, &mut ignored, &mut [], AbsoluteTime::from_micros(0))?,
        Inbound::Ignored
    ));
    c.connection_lost(e, AbsoluteTime::from_micros(u64::MAX - 1))?;
    assert!(c.connection_needed(AbsoluteTime::from_micros(0)));
    c.connection_unavailable(AbsoluteTime::from_micros(u64::MAX - 1))?;
    assert_eq!(c.next_wakeup(), Some(AbsoluteTime::from_micros(u64::MAX)));
    assert!(!c.connection_needed(AbsoluteTime::from_micros(u64::MAX)));
    Ok(())
}
#[test]
fn local_key_enable_catches_up_mismatch_is_explicit_and_close_retires_every_original_owner()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let s = service(Profile::Reference029)?;
    let (_, id) = connect(&mut c, &s)?;
    assert_eq!(
        c.enable_local_key(MasterKey::from_seed([99; 32]))?,
        LocalKeyStatus::Mismatch
    );
    assert!(c.local_key().is_none());
    assert_eq!(c.with_active_seed(|_| true), Err(Error::NotReady));
    assert_eq!(c.identity(), Some(id));
    assert_eq!(
        c.enable_local_key(MasterKey::from_seed([17; 32]))?,
        LocalKeyStatus::Matched
    );
    assert_eq!(
        c.local_key().ok_or(Error::NotReady)?.public_key(),
        id.peer()
    );
    let constructed =
        c.with_active_seed(|seed| gnunet_crypto::EddsaPrivateKey::from_seed(*seed).public_key())?;
    assert_eq!(constructed, id.peer());
    let a = c.ecdh([7; 32], KeyTarget::Exact(id))?;
    let b = c.sign(&region()?, KeyTarget::ServiceCurrent)?;
    c.cancel(a)?;
    let retired = c.close();
    assert_eq!(
        retired.iter().flatten().copied().collect::<Vec<_>>(),
        vec![b]
    );
    assert!(c.identity().is_none() && c.local_key().is_none());
    assert_eq!(c.local_key_status(), LocalKeyStatus::Disabled);
    assert!(c.next_wakeup().is_none());
    Ok(())
}

#[test]
fn actual_kem_rotated_key_is_not_mislabelled_as_the_original_exact_identity() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::ReferenceDeterministic)?;
    let mut s = service(Profile::ReferenceDeterministic)?;
    let (e, identity) = connect(&mut c, &s)?;
    let ephemeral = EcdheSecret::from_bytes([9; 32]);
    let (enc, original_secret) = kem_encapsulate(
        EcdhePublic::from_edwards(identity.peer().as_bytes())?,
        &ephemeral,
    )?;
    let op = c.decapsulate(*enc.as_bytes(), KeyTarget::Exact(identity))?;
    let (_, bytes) = written(&mut c, e)?;
    rotate(&mut s, &[b"tcp://127.0.0.1:15"])?;
    let changed = announcement(&mut c, e, &s, 200)?;
    assert_ne!(changed.peer(), identity.peer());
    let mut result = reply(&mut s, &bytes)?;
    match Response::decode(&result)? {
        Response::Decapsulation { key, .. } => {
            assert_ne!(key, original_secret.into_secret_bytes().as_ref())
        }
        _ => return Err(Error::Malformed),
    }
    assert!(
        matches!(c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(200))?, Inbound::Complete(Completion::Failed { operation, reason: Failure::KeyChanged, .. }) if operation == op)
    );
    assert!(result.iter().all(|b| *b == 0));
    Ok(())
}
#[test]
fn service_current_signature_returns_actual_new_signer_and_exact_target_refuses_it()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::ReferenceDeterministic)?;
    let mut s = service(Profile::ReferenceDeterministic)?;
    let (e, old) = connect(&mut c, &s)?;
    let exact = c.sign(&region()?, KeyTarget::Exact(old))?;
    let current = c.sign(&region()?, KeyTarget::ServiceCurrent)?;
    let (_, exact_bytes) = written(&mut c, e)?;
    let (_, current_bytes) = written(&mut c, e)?;
    rotate(&mut s, &[b"tcp://127.0.0.1:19"])?;
    let new = announcement(&mut c, e, &s, 200)?;
    let mut result = reply(&mut s, &exact_bytes)?;
    assert!(
        matches!(c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(200))?, Inbound::Complete(Completion::Failed { operation, reason: Failure::KeyChanged, .. }) if operation == exact)
    );
    let mut result = reply(&mut s, &current_bytes)?;
    match c.receive(e, &mut result, &mut [], AbsoluteTime::from_micros(200))? {
        Inbound::Complete(Completion::Signature {
            operation,
            peer,
            announced,
            signature,
        }) => {
            assert_eq!(operation, current);
            assert_eq!(peer, new.peer());
            assert_ne!(peer, old.peer());
            assert_eq!(announced, Some(new));
            peer.verify(35, &region()?, &signature)?;
        }
        _ => return Err(Error::Malformed),
    }
    Ok(())
}
#[test]
fn valid_oversized_announcement_is_capacity_refused_before_replacing_verified_key()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::<1, 40, 176>::new(&mut i, Profile::ReferenceDeterministic, limits())?;
    let mut s = service(Profile::ReferenceDeterministic)?;
    c.enable_local_key(MasterKey::from_seed([17; 32]))?;
    let e = c.begin_connection(AbsoluteTime::from_micros(0))?;
    let mut initial = s.announcement().to_vec();
    c.receive(
        e,
        &mut initial,
        &mut [0; 1024],
        AbsoluteTime::from_micros(100),
    )?;
    let old = c.identity().ok_or(Error::NotReady)?;
    let key = c.local_key().ok_or(Error::NotReady)?.public_key();
    rotate(&mut s, &[b"tcp://127.0.0.1:20"])?;
    let mut update = s.announcement().to_vec();
    assert!(update.len() > 176);
    assert!(matches!(
        c.receive(
            e,
            &mut update,
            &mut [0; 1024],
            AbsoluteTime::from_micros(200)
        ),
        Err(Error::Capacity)
    ));
    assert!(update.iter().all(|b| *b == 0));
    assert_eq!(c.identity(), Some(old));
    assert_eq!(c.local_key().ok_or(Error::NotReady)?.public_key(), key);
    Ok(())
}
#[test]
fn well_framed_unknown_messages_are_ignored_but_malformed_frames_do_not_complete_operations()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = owner(&mut i, Profile::Reference029)?;
    let e = c.begin_connection(AbsoluteTime::from_micros(0))?;
    let op = c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
    let mut unknown = [0; 4];
    gnunet_wire::official::MessageHeader::from_total_size(65530u16.into(), 4)?
        .encode(&mut unknown)?;
    assert!(matches!(
        c.receive(e, &mut unknown, &mut [], AbsoluteTime::from_micros(100))?,
        Inbound::Ignored
    ));
    assert_eq!(unknown, [0; 4]);
    assert_eq!(c.pending(), 1);
    let mut malformed = [0, 5, 0xff, 0xfa];
    assert!(
        c.receive(e, &mut malformed, &mut [], AbsoluteTime::from_micros(100))
            .is_err()
    );
    assert_eq!(malformed, [0; 4]);
    assert_eq!(c.pending(), 1);
    c.cancel(op)?;
    Ok(())
}
#[test]
fn canceled_and_foreign_epoch_secret_replies_are_erased_without_completing_new_work()
-> Result<(), Error> {
    let (mut ia, mut ib) = (Instance::new(), Instance::new());
    let mut c = owner(&mut ia, Profile::Reference029)?;
    let mut foreign = owner(&mut ib, Profile::Reference029)?;
    let mut s = service(Profile::Reference029)?;
    let (e, identity) = connect(&mut c, &s)?;
    let (other, _) = connect(&mut foreign, &s)?;
    let ephemeral = EcdheSecret::from_bytes([7; 32]);
    let (enc, _) = kem_encapsulate(
        EcdhePublic::from_edwards(identity.peer().as_bytes())?,
        &ephemeral,
    )?;
    for kind in [OperationKind::Decapsulate, OperationKind::Ecdh] {
        let original = if kind == OperationKind::Decapsulate {
            c.decapsulate(*enc.as_bytes(), KeyTarget::ServiceCurrent)?
        } else {
            c.ecdh(
                *ephemeral.public_key().as_bytes(),
                KeyTarget::ServiceCurrent,
            )?
        };
        let (_, bytes) = written(&mut c, e)?;
        let mut result = reply(&mut s, &bytes)?;
        assert!(result[4..36].iter().any(|b| *b != 0));
        assert!(matches!(
            c.receive(other, &mut result, &mut [], AbsoluteTime::from_micros(100)),
            Err(Error::Stale)
        ));
        assert!(result.iter().all(|b| *b == 0));
        assert_eq!(c.pending(), 1);
        c.cancel(original)?;
        let new = c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
        let mut late = reply(&mut s, &bytes)?;
        assert!(late[4..36].iter().any(|b| *b != 0));
        assert!(matches!(
            c.receive(e, &mut late, &mut [], AbsoluteTime::from_micros(100))?,
            Inbound::Ignored
        ));
        assert!(late.iter().all(|b| *b == 0));
        assert_eq!(c.pending(), 1);
        c.cancel(new)?;
    }
    Ok(())
}

#[test]
fn operation_quiescence_distinguishes_logical_cancel_copied_frame_and_physical_close()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut c = owner(&mut instance, Profile::Reference029)?;
    let mut service = service(Profile::Reference029)?;
    let (e, identity) = connect(&mut c, &service)?;
    let region = region()?;
    let queued = c.sign(&region, KeyTarget::Exact(identity))?;
    assert!(!c.operation_quiescent(queued)?);
    c.cancel(queued)?;
    assert!(c.operation_quiescent(queued)?);
    let copied = c.sign(&region, KeyTarget::Exact(identity))?;
    let (tx, request) = take(&mut c, e)?;
    assert_eq!(tx.operation, copied);
    c.cancel(copied)?;
    assert!(!c.operation_quiescent(copied)?);
    assert!(c.written(e, tx.transmit)?.canceled);
    assert!(c.operation_quiescent(copied)?);
    let mut response = reply(&mut service, &request)?;
    assert!(matches!(
        c.receive(
            e,
            &mut response,
            &mut [0; 1024],
            AbsoluteTime::from_micros(100)
        )?,
        Inbound::Ignored
    ));
    assert!(c.operation_quiescent(copied)?);
    let closing = c.sign(&region, KeyTarget::Exact(identity))?;
    let (tx, _) = take(&mut c, e)?;
    assert_eq!(tx.operation, closing);
    c.cancel(closing)?;
    assert!(!c.operation_quiescent(closing)?);
    let _closed = c.close();
    assert!(c.operation_quiescent(closing)?);
    let mut other_instance = Instance::new();
    let other = owner(&mut other_instance, Profile::Reference029)?;
    assert_eq!(other.operation_quiescent(closing), Err(Error::Stale));
    Ok(())
}
