//! Real purpose7 HELLO and purpose6 path proofs; no peer connection is invented.
use super::*;
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service};
use gnunet_wire::official::{dht::Path as WirePath, dht::ipc::RequestId, pils};

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
