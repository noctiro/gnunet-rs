//! Volatile replay ports exercise ordering only, never claim durable file evidence.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite public replay/window assertions with fallible setup"
)]
use gnunet_crypto::Entropy;
use gnunet_session_crypto::udp::DatagramKey;
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity, handshake,
    receive::{Policy, Receiver, ReplayStore},
    send::{Policy as TxPolicy, Sender},
    wire::Body,
};
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        self.0 += 1;
        for (i, v) in b.iter_mut().enumerate() {
            *v = self
                .0
                .wrapping_mul(71)
                .wrapping_add(i as u64 * 13)
                .to_le_bytes()[i % 8];
        }
        Ok(())
    }
}
struct Volatile {
    local: [u8; 32],
    peer: [u8; 32],
    latest: Option<u64>,
    calls: usize,
    refuse: Option<Error>,
}
impl ReplayStore for Volatile {
    fn commit(&mut self, local: [u8; 32], peer: [u8; 32], time: u64) -> Result<(), Error> {
        self.calls += 1;
        if local != self.local || peer != self.peer {
            return Err(Error::Authentication);
        }
        if let Some(error) = self.refuse {
            return Err(error);
        }
        if self.latest.is_some_and(|last| time <= last) {
            return Err(Error::Replay);
        }
        self.latest = Some(time);
        Ok(())
    }
}
fn message(n: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..2].copy_from_slice(&8u16.to_be_bytes());
    b[4..].copy_from_slice(&n.to_be_bytes());
    b
}
fn tx(a: &Identity, b: &Identity) -> Result<Sender, Error> {
    Sender::new(
        a.peer(),
        b.peer(),
        TxPolicy {
            datagram_bytes: 192,
            secrets: 4,
            ..TxPolicy::default()
        },
        100,
    )
}
fn replay(a: &Identity, b: &Identity) -> Volatile {
    Volatile {
        local: b.peer(),
        peer: a.peer(),
        latest: None,
        calls: 0,
        refuse: None,
    }
}
#[test]
fn fresh_authenticated_ack_recovers_retained_sender_after_peer_receive_state_restarts()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = tx(&a, &b)?;
    let mut entropy = Random(1);
    let mut replay = replay(&a, &b);
    let mut receiver = Receiver::new(b.peer(), a.peer(), Policy::default())?;
    let mut scratch = [0; 256];
    let initial = sender.initial(&a, &message(1), 1, 100, &mut entropy)?;
    let received = receiver.initial(&b, initial.bytes(), &mut scratch, &mut replay)?;
    sender.acknowledge(
        b.peer(),
        received.acknowledgements[0].ok_or(Error::NotReady)?,
        100,
    )?;
    let first = sender.boxed(&a, &message(2), 101, &mut entropy)?;
    assert_eq!(
        receiver.boxed(&b, first.bytes(), &mut scratch)?.message(),
        Some(message(2).as_slice())
    );
    // Keep the replay namespace and sender; retire only volatile receive keys.
    drop(receiver);
    let mut receiver = Receiver::new(b.peer(), a.peer(), Policy::default())?;
    let fresh = sender.initial(&a, &message(3), 2, 102, &mut entropy)?;
    let received = receiver.initial(&b, fresh.bytes(), &mut scratch, &mut replay)?;
    sender.acknowledge(
        b.peer(),
        received.acknowledgements[0].ok_or(Error::NotReady)?,
        102,
    )?;
    let next = sender.boxed(&a, &message(4), 103, &mut entropy)?;
    assert_eq!(
        receiver.boxed(&b, next.bytes(), &mut scratch)?.message(),
        Some(message(4).as_slice())
    );
    assert_eq!(replay.latest, Some(2));
    assert!(matches!(
        receiver.initial(&b, initial.bytes(), &mut scratch, &mut replay),
        Err(Error::Replay)
    ));
    Ok(())
}
#[test]
fn replay_persistence_refusal_never_publishes_payload_key_or_ack_and_preserves_error_identity()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = tx(&a, &b)?;
    let mut entropy = Random(1);
    let packet = sender.initial(&a, &message(1), 1, 100, &mut entropy)?;
    let mut receiver = Receiver::new(b.peer(), a.peer(), Policy::default())?;
    let mut replay = replay(&a, &b);
    let mut scratch = [0xa5; 160];
    for cause in [Error::Storage, Error::OutcomeUnknown] {
        replay.refuse = Some(cause);
        assert!(
            matches!(receiver.initial(&b,packet.bytes(),&mut scratch,&mut replay),Err(e) if e==cause)
        );
        assert_eq!(receiver.secrets(), 0);
        assert_eq!(receiver.available(), 0);
        assert_eq!(&scratch[..144], &[0; 144]);
        assert_eq!(&scratch[144..], &[0xa5; 16]);
    }
    replay.refuse = None;
    let accepted = receiver.initial(&b, packet.bytes(), &mut scratch, &mut replay)?;
    assert_eq!(accepted.message(), Some(message(1).as_slice()));
    assert_eq!(
        accepted.acknowledgements[0].ok_or(Error::Stale)?.allowed,
        128
    );
    assert_eq!(receiver.available(), 128);
    assert_eq!(replay.calls, 3);
    assert!(matches!(
        receiver.initial(&b, packet.bytes(), &mut scratch, &mut replay),
        Err(Error::Replay)
    ));
    assert_eq!(replay.calls, 3);
    Ok(())
}
#[test]
fn authenticated_old_kx_after_receiver_restart_is_rejected_by_the_same_replay_namespace()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = tx(&a, &b)?;
    let mut entropy = Random(1);
    let packet = sender.initial(&a, &message(1), 1, 100, &mut entropy)?;
    let mut replay = replay(&a, &b);
    let mut scratch = [0; 160];
    let mut receiver = Receiver::new(b.peer(), a.peer(), Policy::default())?;
    receiver.initial(&b, packet.bytes(), &mut scratch, &mut replay)?;
    receiver.close();
    let mut replacement = Receiver::new(b.peer(), a.peer(), Policy::default())?;
    assert!(matches!(
        replacement.initial(&b, packet.bytes(), &mut scratch, &mut replay),
        Err(Error::Replay)
    ));
    assert_eq!(replacement.available(), 0);
    let fresh = sender.initial(&a, &message(2), 2, 101, &mut entropy)?;
    assert_eq!(
        replacement
            .initial(&b, fresh.bytes(), &mut scratch, &mut replay)?
            .message(),
        Some(message(2).as_slice())
    );
    Ok(())
}
#[test]
fn out_of_order_boxes_consume_only_their_original_kid_and_bad_tag_cannot_burn_valid_credit()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = tx(&a, &b)?;
    let mut entropy = Random(1);
    let packet = sender.initial(&a, &message(1), 1, 100, &mut entropy)?;
    let mut replay = replay(&a, &b);
    let mut scratch = [0xa5; 160];
    let mut receiver = Receiver::new(b.peer(), a.peer(), Policy::default())?;
    let received = receiver.initial(&b, packet.bytes(), &mut scratch, &mut replay)?;
    sender.acknowledge(
        b.peer(),
        received.acknowledgements[0].ok_or(Error::Stale)?,
        100,
    )?;
    let first = sender.boxed(&a, &message(2), 101, &mut entropy)?;
    let second = sender.boxed(&a, &message(3), 102, &mut entropy)?;
    let mut bad = first.bytes().to_vec();
    bad[32] ^= 1;
    assert!(matches!(
        receiver.boxed(&b, &bad, &mut scratch),
        Err(Error::Authentication)
    ));
    assert_eq!(receiver.available(), 128);
    assert_eq!(
        receiver.boxed(&b, second.bytes(), &mut scratch)?.message(),
        Some(message(3).as_slice())
    );
    assert_eq!(receiver.available(), 127);
    assert_eq!(
        receiver.boxed(&b, first.bytes(), &mut scratch)?.message(),
        Some(message(2).as_slice())
    );
    assert_eq!(receiver.available(), 126);
    assert!(matches!(
        receiver.boxed(&b, first.bytes(), &mut scratch),
        Err(Error::Replay)
    ));
    assert_eq!(receiver.available(), 126);
    assert_eq!(&scratch[144..], &[0xa5; 16]);
    Ok(())
}
#[test]
fn acknowledged_keys_are_cached_before_publication_and_refills_keep_a_bounded_span()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = tx(&a, &b)?;
    let mut entropy = Random(1);
    let packet = sender.initial(&a, &message(1), 1, 100, &mut entropy)?;
    let mut replay = replay(&a, &b);
    let mut scratch = [0; 160];
    let mut receiver = Receiver::new(
        b.peer(),
        a.peer(),
        Policy {
            secrets: 2,
            ..Policy::default()
        },
    )?;
    let received = receiver.initial(&b, packet.bytes(), &mut scratch, &mut replay)?;
    sender.acknowledge(
        b.peer(),
        received.acknowledgements[0].ok_or(Error::Stale)?,
        100,
    )?;
    let mut grants = 0;
    for sequence in 1..=240 {
        let packet = sender.boxed(
            &a,
            &message(sequence),
            100 + u64::from(sequence),
            &mut entropy,
        )?;
        let received = receiver.boxed(&b, packet.bytes(), &mut scratch)?;
        assert_eq!(received.message(), Some(message(sequence).as_slice()));
        for ack in received.acknowledgements.into_iter().flatten() {
            sender.acknowledge(b.peer(), ack, 100 + u64::from(sequence))?;
            grants += 1;
        }
        assert!(receiver.available() <= 161);
        assert_eq!(receiver.secrets(), 1);
    }
    assert!(grants >= 3);
    Ok(())
}
#[test]
fn authenticated_rekey_preflight_installs_only_cached_new_secret_and_keeps_old_window_valid()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = Sender::new(
        a.peer(),
        b.peer(),
        TxPolicy {
            datagram_bytes: 192,
            secrets: 2,
            maximum_secret_bytes: 800,
            rekey_after_bytes: 192,
            rekey_after_us: u64::MAX,
            ..TxPolicy::default()
        },
        100,
    )?;
    let mut entropy = Random(1);
    let initial = sender.initial(&a, &message(1), 1, 100, &mut entropy)?;
    let mut replay = replay(&a, &b);
    let mut scratch = [0; 200];
    let mut receiver = Receiver::new(
        b.peer(),
        a.peer(),
        Policy {
            secrets: 2,
            ..Policy::default()
        },
    )?;
    let accepted = receiver.initial(&b, initial.bytes(), &mut scratch, &mut replay)?;
    sender.acknowledge(
        b.peer(),
        accepted.acknowledgements[0].ok_or(Error::Stale)?,
        100,
    )?;
    let old = sender.boxed(&a, &message(2), 101, &mut entropy)?;
    let rekey = sender.boxed(&a, &message(3), 102, &mut entropy)?;
    let accepted = receiver.boxed(&b, rekey.bytes(), &mut scratch)?;
    assert_eq!(accepted.message(), Some(message(3).as_slice()));
    let new_ack = accepted.acknowledgements[1].ok_or(Error::Stale)?;
    sender.acknowledge(b.peer(), new_ack, 102)?;
    assert_eq!(receiver.secrets(), 2);
    let new = sender.boxed(&a, &message(4), 103, &mut entropy)?;
    assert_eq!(
        receiver.boxed(&b, new.bytes(), &mut scratch)?.message(),
        Some(message(4).as_slice())
    );
    assert_eq!(
        receiver.boxed(&b, old.bytes(), &mut scratch)?.message(),
        Some(message(2).as_slice())
    );
    receiver.close();
    assert_eq!(receiver.available(), 0);
    assert!(matches!(
        receiver.boxed(&b, new.bytes(), &mut scratch),
        Err(Error::Stale)
    ));
    Ok(())
}
#[test]
fn wrong_identity_or_peer_cannot_activate_initial_or_rekey_windows() -> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let c = Identity::from_seed([7; 32]);
    let mut sender = tx(&a, &b)?;
    let mut entropy = Random(1);
    let initial = sender.initial(&a, &message(1), 1, 100, &mut entropy)?;
    let mut replay = replay(&a, &b);
    let mut scratch = [0; 160];
    let mut receiver = Receiver::new(b.peer(), c.peer(), Policy::default())?;
    assert!(matches!(
        receiver.initial(&b, initial.bytes(), &mut scratch, &mut replay),
        Err(Error::Authentication)
    ));
    assert_eq!(replay.calls, 0);
    assert_eq!(receiver.available(), 0);
    let mut receiver = Receiver::new(b.peer(), a.peer(), Policy::default())?;
    assert!(matches!(
        receiver.initial(&c, initial.bytes(), &mut scratch, &mut replay),
        Err(Error::Authentication)
    ));
    assert_eq!(replay.calls, 0);
    let accepted = receiver.initial(&b, initial.bytes(), &mut scratch, &mut replay)?;
    sender.acknowledge(
        b.peer(),
        accepted.acknowledgements[0].ok_or(Error::Stale)?,
        100,
    )?;
    let packet = sender.boxed(&a, &message(2), 101, &mut entropy)?;
    assert!(matches!(
        receiver.boxed(&c, packet.bytes(), &mut scratch),
        Err(Error::Authentication)
    ));
    assert_eq!(receiver.available(), 128);
    // Independent primitive open below checks that no plaintext parser silently
    // invents another application message from trailing padding.
    let mut other = [0; 160];
    let opened = handshake::open(&b, initial.bytes(), &mut other)?;
    let master = opened.into_secret()?.into_master();
    let n = DatagramKey::derive(&master, 1)?.open_box(packet.bytes(), &mut other)?;
    assert_eq!(
        Body::decode(&other[..n])?.message,
        Some(message(2).as_slice())
    );
    Ok(())
}

#[test]
fn a_duplicate_rekey_ack_cannot_publish_keys_evicted_by_the_same_new_initial_admission()
-> Result<(), Error> {
    use gnunet_udp_communicator_core::wire::{Control, Rekey};
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = Sender::new(
        a.peer(),
        b.peer(),
        TxPolicy {
            datagram_bytes: 192,
            secrets: 4,
            maximum_secret_bytes: 800,
            rekey_after_bytes: 192,
            rekey_after_us: u64::MAX,
            ..TxPolicy::default()
        },
        100,
    )?;
    let mut random = Random(1);
    let first = sender.initial(&a, &message(1), 1, 100, &mut random)?;
    let mut gate = replay(&a, &b);
    let mut receiver = Receiver::new(
        b.peer(),
        a.peer(),
        Policy {
            secrets: 2,
            ..Policy::default()
        },
    )?;
    let mut scratch = [0; 200];
    let accepted = receiver.initial(&b, first.bytes(), &mut scratch, &mut gate)?;
    sender.acknowledge(
        b.peer(),
        accepted.acknowledgements[0].ok_or(Error::Stale)?,
        100,
    )?;
    sender.boxed(&a, &message(2), 101, &mut random)?;
    let rekey = sender.boxed(&a, &message(3), 102, &mut random)?;
    let mut raw = [0; 200];
    let mut old = [0; 200];
    let opened = handshake::open(&b, first.bytes(), &mut old)?;
    let master = opened.into_secret()?.into_master();
    let n = DatagramKey::derive(&master, 2)?.open_box(rekey.bytes(), &mut raw)?;
    let header = match Body::decode(&raw[..n])?.control {
        Some(Control::Rekey(r)) => r,
        _ => return Err(Error::Malformed),
    };
    let accepted = receiver.boxed(&b, rekey.bytes(), &mut scratch)?;
    let offered = accepted.acknowledgements[1].ok_or(Error::Stale)?;
    // Withhold its first ACK, then receive a legitimate signed KX carrying the
    // same rekey encapsulation. Both newly offered windows must remain cached.
    let mut repeated = [0; 36];
    Rekey(header.0).encode(&mut repeated)?;
    let intermediate = sender.initial(&a, &message(98), 2, 103, &mut random)?;
    receiver.initial(&b, intermediate.bytes(), &mut scratch, &mut gate)?;
    let new = sender.initial(&a, &repeated, 3, 104, &mut random)?;
    let accepted = receiver.initial(&b, new.bytes(), &mut scratch, &mut gate)?;
    assert_eq!(accepted.acknowledgements[1], Some(offered));
    assert_eq!(receiver.secrets(), 2);
    sender.acknowledge(b.peer(), offered, 104)?;
    let next = sender.boxed(&a, &message(4), 105, &mut random)?;
    assert_eq!(
        receiver.boxed(&b, next.bytes(), &mut scratch)?.message(),
        Some(message(4).as_slice())
    );
    Ok(())
}
