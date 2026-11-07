//! Actual official record/identity component boundaries; no daemon proof.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible component tests assert exact protocol/resource observations"
)]
use gnunet_crypto::EddsaPrivateKey;
use gnunet_session_crypto::Prk;
use gnunet_tcp_communicator_core::{
    record::{Direction, Receiver, Record},
    wire::{self, Confirmation, Representative, Shape},
};
use gnunet_types::Error;
fn prk() -> Prk {
    Prk::from_bytes([42; 32])
}
fn payload() -> [u8; 8] {
    [0, 8, 0, 17, 1, 2, 3, 4]
}
#[test]
fn special_box_size_and_fixed_layouts_are_not_generic_frame_lengths() -> Result<(), Error> {
    assert_eq!(Shape::decode(&[255, 255, 5, 171])?, Shape::Box(u16::MAX));
    assert_eq!(Shape::Box(u16::MAX).length(), 65571);
    for n in 0..4 {
        assert_eq!(Shape::decode(&[0, 36, 5, 172][..n]), Err(Error::Truncated));
    }
    for (kind, size) in [
        (wire::ACK_TYPE, wire::ACK),
        (wire::REKEY_TYPE, wire::REKEY),
        (wire::FINISH_TYPE, wire::BOX_PREFIX),
    ] {
        for wrong in [size - 1, size + 1] {
            let mut header = [0; 4];
            header[..2].copy_from_slice(&(wrong as u16).to_be_bytes());
            header[2..].copy_from_slice(&kind.to_be_bytes());
            assert_eq!(Shape::decode(&header), Err(Error::Malformed));
        }
    }
    assert_eq!(Shape::decode(&[0, 4, 255, 255]), Err(Error::Unsupported));
    Ok(())
}
#[test]
fn source_signature_purposes_bind_both_identities_representation_time_and_challenge()
-> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let enc = Representative([3; 32]);
    let challenge = [4; 32];
    let mut c = wire::confirmation(&alice, bob.public_key(), enc, 123, &challenge)?;
    let view = Confirmation::decode(&c)?;
    view.verify(bob.public_key(), enc)?;
    assert_eq!(view.sender(), alice.public_key());
    assert_eq!(view.monotonic(), 123);
    assert_eq!(view.challenge(), &challenge);
    assert_eq!(
        view.verify(alice.public_key(), enc),
        Err(Error::Authentication)
    );
    assert_eq!(
        view.verify(bob.public_key(), Representative([8; 32])),
        Err(Error::Authentication)
    );
    for offset in [0, 32, 95, 96, 103, 104, 135] {
        let old = c[offset];
        c[offset] ^= 1;
        assert_eq!(
            Confirmation::decode(&c)?.verify(bob.public_key(), enc),
            Err(Error::Authentication)
        );
        c[offset] = old;
    }
    assert!(Confirmation::decode(&c[..135]).is_err());
    let mut extra = c.to_vec();
    extra.push(0);
    assert!(Confirmation::decode(&extra).is_err());
    Ok(())
}
#[test]
fn ack_and_rekey_verify_source_domains_without_implied_peerstore_admission() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let challenge = [4; 32];
    let ack = wire::acknowledgement(&alice, bob.public_key(), u64::MAX, &challenge)?;
    assert_eq!(
        wire::verify_ack(&ack, bob.public_key(), &challenge)?,
        alice.public_key()
    );
    assert_eq!(
        wire::verify_ack(&ack, bob.public_key(), &[5; 32]),
        Err(Error::Authentication)
    );
    assert_eq!(
        wire::verify_ack(&ack, alice.public_key(), &challenge),
        Err(Error::Authentication)
    );
    let mut rekey = wire::rekey(&alice, bob.public_key(), &[8; 32], 77)?;
    assert_eq!(
        wire::verify_rekey(&rekey, alice.public_key(), bob.public_key())?,
        ([8; 32], 77)
    );
    for offset in [36, 68, 131, 132, 139] {
        rekey[offset] ^= 1;
        assert_eq!(
            wire::verify_rekey(&rekey, alice.public_key(), bob.public_key()),
            Err(Error::Authentication)
        );
        rekey[offset] ^= 1;
    }
    Ok(())
}
#[test]
fn every_capacity_refusal_preserves_output_and_next_stream_cipher_ratchet() -> Result<(), Error> {
    let input = payload();
    let n = wire::BOX_PREFIX + input.len();
    let mut sender = Direction::new(&prk())?;
    for capacity in 0..n {
        let mut output = vec![0xcc; capacity];
        assert_eq!(sender.seal_box(&input, &mut output), Err(Error::Capacity));
        assert!(output.iter().all(|x| *x == 0xcc));
    }
    let mut expected = [0; 44];
    let mut actual = [0; 44];
    Direction::new(&prk())?.seal_box(&input, &mut expected)?;
    sender.seal_box(&input, &mut actual)?;
    assert_eq!(actual, expected);
    for capacity in 0..36 {
        let mut output = vec![0xcc; capacity];
        assert_eq!(sender.seal_finish(&mut output), Err(Error::Capacity));
        assert!(output.iter().all(|x| *x == 0xcc));
    }
    Ok(())
}
#[test]
fn fragmented_records_repeated_view_and_finish_are_bounded_and_ordered() -> Result<(), Error> {
    let mut sender = Direction::new(&prk())?;
    let mut first = [0; 44];
    let mut second = [0; 44];
    let mut fin = [0; 36];
    sender.seal_box(&payload(), &mut first)?;
    sender.seal_box(&payload(), &mut second)?;
    sender.seal_finish(&mut fin)?;
    assert_ne!(first, second);
    let mut storage = vec![0xcc; wire::MAX_RECORD];
    let mut recv = Receiver::new(&prk(), &mut storage)?;
    for frame in [&first[..], &second[..]] {
        for byte in frame {
            assert_eq!(recv.push(&[*byte])?, 1);
        }
        assert_eq!(recv.record()?, Record::Box(&payload()));
        assert_eq!(recv.record()?, Record::Box(&payload()));
        assert_eq!(recv.push(&[0]), Err(Error::WouldBlock));
        recv.release()?;
    }
    assert_eq!(recv.push(&fin)?, fin.len());
    assert_eq!(recv.record()?, Record::Finish);
    recv.release()?;
    assert_eq!(recv.push(&[]), Err(Error::Closed));
    drop(recv);
    assert!(storage.iter().all(|x| *x == 0 || *x == 0xcc));
    Ok(())
}
#[test]
fn tampered_mac_poison_closes_decoder_and_erases_plaintext_on_drop() -> Result<(), Error> {
    let mut sender = Direction::new(&prk())?;
    let mut frame = [0; 44];
    sender.seal_box(&payload(), &mut frame)?;
    frame[7] ^= 1;
    let mut storage = vec![0xcc; wire::MAX_RECORD];
    let mut recv = Receiver::new(&prk(), &mut storage)?;
    recv.push(&frame)?;
    assert_eq!(recv.record(), Err(Error::Authentication));
    assert_eq!(recv.push(&frame), Err(Error::Closed));
    assert_eq!(recv.record(), Err(Error::Closed));
    drop(recv);
    assert!(storage[..44].iter().all(|x| *x == 0));
    Ok(())
}
#[test]
fn coalesced_rekey_stops_old_cipher_exactly_before_new_key_bytes() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let new = Prk::from_bytes([19; 32]);
    let plain = wire::rekey(&alice, bob.public_key(), &[5; 32], 7)?;
    let mut sender = Direction::new(&prk())?;
    let mut encrypted = [0; 140];
    sender.seal_rekey(&plain, &new, &mut encrypted)?;
    let mut after = [0; 44];
    sender.seal_box(&payload(), &mut after)?;
    let mut combined = encrypted.to_vec();
    combined.extend_from_slice(&after);
    let mut storage = vec![0; wire::MAX_RECORD];
    for split in [0, 1, 3, 4, 17, 139, 140] {
        let mut recv = Receiver::new(&prk(), &mut storage)?;
        assert_eq!(recv.push(&combined[..split])?, split);
        if split < 140 {
            assert_eq!(recv.record(), Err(Error::WouldBlock));
            assert_eq!(recv.push(&combined[split..])?, 140 - split);
        }
        if let Record::Rekey(bytes) = recv.record()? {
            assert_eq!(
                wire::verify_rekey(bytes, alice.public_key(), bob.public_key())?,
                ([5; 32], 7)
            );
        } else {
            return Err(Error::Malformed);
        }
        assert_eq!(recv.release(), Err(Error::NotReady));
        recv.rekey(&new)?;
        assert_eq!(recv.push(&combined[140..])?, 44);
        assert_eq!(recv.record()?, Record::Box(&payload()));
    }
    Ok(())
}
#[test]
fn unsigned_record_layer_ack_does_not_advance_box_mac_ratchet() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let challenge = [4; 32];
    let mut ack = wire::acknowledgement(&alice, bob.public_key(), 1, &challenge)?;
    let mut sender = Direction::new(&prk())?;
    sender.handshake_fragment(&mut ack)?;
    let mut frame = [0; 44];
    sender.seal_box(&payload(), &mut frame)?;
    let mut storage = vec![0; wire::MAX_RECORD];
    let mut recv = Receiver::new(&prk(), &mut storage)?;
    recv.push(&ack)?;
    if let Record::Ack(bytes) = recv.record()? {
        assert_eq!(
            wire::verify_ack(bytes, bob.public_key(), &challenge)?,
            alice.public_key()
        );
    } else {
        return Err(Error::Malformed);
    }
    recv.release()?;
    recv.push(&frame)?;
    assert_eq!(recv.record()?, Record::Box(&payload()));
    Ok(())
}
#[test]
fn maximum65535_payload_is_a65571_record_and_small_workspaces_reject() -> Result<(), Error> {
    let mut payload = vec![3; 65535];
    payload[..2].copy_from_slice(&u16::MAX.to_be_bytes());
    let mut cipher = vec![0; wire::MAX_RECORD];
    let mut sender = Direction::new(&prk())?;
    assert_eq!(sender.seal_box(&payload, &mut cipher)?, 65571);
    let mut storage = vec![0; wire::MAX_RECORD];
    assert!(matches!(
        Receiver::new(&prk(), &mut storage[..wire::MAX_RECORD - 1]),
        Err(Error::Capacity)
    ));
    let mut recv = Receiver::new(&prk(), &mut storage)?;
    assert_eq!(recv.push(&cipher)?, 65571);
    assert_eq!(recv.record()?, Record::Box(&payload));
    Ok(())
}
#[test]
fn too_small_receiver_storage_returns_original_partial_stream_owner() -> Result<(), Error> {
    let mut sender = Direction::new(&prk())?;
    let mut incoming = Direction::new(&prk())?;
    let mut prefix = [7; 136];
    sender.handshake_fragment(&mut prefix)?;
    incoming.handshake_fragment(&mut prefix)?;
    assert!(prefix.iter().all(|x| *x == 7));
    let mut short = [0; 4];
    let rejected = match Receiver::with_direction(incoming, &mut short) {
        Err(r) => r,
        Ok(_) => return Err(Error::Malformed),
    };
    assert_eq!(rejected.reason, Error::Capacity);
    let mut bytes = [0; 44];
    sender.seal_box(&payload(), &mut bytes)?;
    let mut storage = vec![0; wire::MAX_RECORD];
    let mut receive =
        Receiver::with_direction(rejected.value, &mut storage).map_err(|r| r.reason)?;
    receive.push(&bytes)?;
    assert_eq!(receive.record()?, Record::Box(&payload()));
    Ok(())
}
