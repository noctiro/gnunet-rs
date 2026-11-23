//! Real purpose7 HELLO and purpose6 path proofs; no peer connection is invented.
use super::*;
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service};
use gnunet_wire::official::{dht::Path as WirePath, dht::ipc::RequestId, pils};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact first-hop slots, alternate selection and source ownership"
)]
fn alternate_first_hops_survive_refresh_and_candidate_expiry() -> Result<()> {
    let candidate = |first, via, expires| Candidate {
        path: vec![[1; 32], [first; 32], [via; 32], [9; 32]],
        expires,
        attempted: false,
    };
    let mut paths = Paths::new();
    paths.insert(candidate(2, 5, 100), 10, 0);
    paths.insert(candidate(3, 5, 30), 11, 0);
    paths.insert(candidate(4, 5, 70), 12, 0);
    paths.insert(candidate(2, 6, 80), 13, 1);
    let mut expired = 0;
    let (first, refreshed) = paths
        .next_after(0, 1, &mut expired)
        .ok_or(Fault::NotReady)?;
    assert_eq!(refreshed.path, [[1; 32], [2; 32], [6; 32], [9; 32]]);
    assert_eq!(
        paths.entries[first].as_ref().map(|(_, source)| *source),
        Some(13)
    );
    let (second, alternate) = paths
        .next_after(first + 1, 1, &mut expired)
        .ok_or(Fault::NotReady)?;
    assert_eq!(alternate.path[1], [3; 32]);
    assert_eq!(
        paths.entries[second].as_ref().map(|(_, source)| *source),
        Some(11)
    );
    let (third, alternate) = paths
        .next_after(first + 1, 30, &mut expired)
        .ok_or(Fault::NotReady)?;
    assert_eq!(alternate.path[1], [4; 32]);
    assert_eq!(
        paths.entries[third].as_ref().map(|(_, source)| *source),
        Some(12)
    );
    let (attempted, _) = paths.entries[first].as_mut().ok_or(Fault::NotReady)?;
    attempted.attempted = true;
    paths.insert(candidate(2, 6, 90), 15, 30);
    paths.insert(candidate(7, 8, 60), 14, 30);
    let (next, alternative) = paths
        .next_after(0, 30, &mut expired)
        .ok_or(Fault::NotReady)?;
    assert_eq!(next, second);
    assert_eq!(alternative.path[1], [7; 32]);
    let (retry, previous) = paths
        .next_after(PATHS_PER_GET, 30, &mut expired)
        .ok_or(Fault::NotReady)?;
    assert_eq!(retry, first + PATHS_PER_GET);
    assert_eq!(previous.path[1], [2; 32]);
    assert_eq!(expired, 1);
    assert_eq!(
        paths.entries[second].as_ref().map(|(_, source)| *source),
        Some(14)
    );
    assert_eq!(
        paths.entries[first].as_ref().map(|(_, source)| *source),
        Some(15)
    );
    assert_eq!(
        paths.entries[third].as_ref().map(|(_, source)| *source),
        Some(12)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Compare actual generated signatures, selected profile and original path-binding refusal"
)]
fn nonempty_hello_and_recorded_path_use_selected_signature_profile() -> Result<()> {
    let now = 1_000;
    let expiration = now + 1_000_000;
    let local = [0x41; 32];
    for profile in [Profile::Reference029, Profile::ReferenceDeterministic] {
        let mut service = Service::<4096>::new(
            MasterKey::from_seed([0x65; 32]),
            profile,
            now,
            HelloLimits {
                maximum_input_bytes: 4096,
                maximum_address_bytes: 2048,
                maximum_addresses: 16,
            },
        )?;
        let initial = pils::PeerUpdate::decode(service.announcement())?;
        let mut block = initial.block.to_vec();
        block.extend_from_slice(b"tcp://127.0.0.1:1234\0");
        let mut input = vec![0; block.len() + 8];
        let length = pils::Request::Feed { block: &block }.encode(&mut input)?;
        let mut scratch = [0; 2048];
        let mut output = [0; 104];
        assert!(matches!(
            service.receive(&input[..length], &mut scratch, now, &mut output)?,
            Action::Broadcast { .. }
        ));
        let update = pils::PeerUpdate::decode(service.announcement())?;
        let expected = *service.identity().public_key().as_bytes();
        let region = gnunet_dht::path::region(
            &gnunet_crypto::hash512(update.block),
            expiration,
            &[0; 32],
            &local,
        );
        let signature = service.identity().sign(&region)?;
        let mut recorded = [0; 96];
        recorded[..64].copy_from_slice(signature.as_bytes());
        recorded[64..].copy_from_slice(&expected);
        let key = [0; 64];
        let result = dht::ipc::ResultMessage {
            block_type: HELLO,
            options: RECORD_ROUTE,
            put_path: WirePath::empty(),
            get_path: WirePath::new(&recorded)?,
            id: RequestId([0x19; 8]),
            expiration: AbsoluteTime::from_micros(expiration),
            key: &key,
            truncated_peer: None,
            payload: update.block,
        };
        let candidate = validate(
            result,
            expected,
            local,
            now,
            16,
            profile.hello(),
            &mut scratch,
        )?;
        assert_eq!(candidate.path, [local, expected]);
        assert_eq!(candidate.expires, expiration);
        let wrong = match profile {
            Profile::Reference029 => SignatureProfile::DeterministicPidDerivation,
            _ => SignatureProfile::Gnunet029,
        };
        assert_eq!(
            validate(result, expected, local, now, 16, wrong, &mut scratch).err(),
            Some(Fault::Authentication)
        );
        let mut changed_recipient = local;
        changed_recipient[0] ^= 1;
        assert_eq!(
            validate(
                result,
                expected,
                changed_recipient,
                now,
                16,
                profile.hello(),
                &mut scratch
            )
            .err(),
            Some(Fault::Authentication)
        );
    }
    Ok(())
}
