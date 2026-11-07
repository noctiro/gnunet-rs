//! Public nonce/ACK ownership; no native send or C-session proof.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite key-window and immutable datagram assertions with fallible setup"
)]
use gnunet_crypto::Entropy;
use gnunet_session_crypto::{Prk, udp::DatagramKey};
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity, handshake,
    send::{Grant, Mode, Policy, Sender},
    wire::{Ack, Body, Control},
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
fn message(n: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..2].copy_from_slice(&8u16.to_be_bytes());
    b[4..].copy_from_slice(&n.to_be_bytes());
    b
}
fn policy() -> Policy {
    Policy {
        datagram_bytes: 192,
        secrets: 2,
        ..Policy::default()
    }
}
fn inspect(b: &Identity, packet: &[u8]) -> Result<(Ack, Prk), Error> {
    let mut scratch = vec![0; packet.len()];
    let opened = handshake::open(b, packet, &mut scratch)?;
    let cmac = *opened.cmac().ok_or(Error::Stale)?;
    let master = opened.into_secret()?.into_master();
    assert!(scratch.iter().all(|v| *v == 0));
    Ok((Ack { allowed: 128, cmac }, master))
}
#[test]
fn actual_ack_limit_consumes_unique_sequences_and_packet_cancellation_burns_the_original_nonce()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut random = Random(1);
    let mut sender = Sender::new(a.peer(), b.peer(), policy(), 100)?;
    let initial = sender.initial(&a, &message(1), 1, 100, &mut random)?;
    assert_eq!(initial.mode(), Mode::Initial);
    assert_eq!(sender.available(), 0);
    let (ack, master) = inspect(&b, initial.bytes())?;
    assert_eq!(
        sender.acknowledge(b.peer(), ack, 100)?,
        Grant::Increased {
            delta: 128,
            available: 128
        }
    );
    let cancelled = sender.boxed(&a, &message(2), 101, &mut random)?;
    assert_eq!(
        cancelled.mode(),
        Mode::Box {
            sequence: 1,
            rekey: false
        }
    );
    drop(cancelled);
    let next = sender.boxed(&a, &message(3), 102, &mut random)?;
    assert_eq!(
        next.mode(),
        Mode::Box {
            sequence: 2,
            rekey: false
        }
    );
    assert_eq!(sender.available(), 126);
    let mut scratch = [0; 144];
    let n = DatagramKey::derive(&master, 2)?.open_box(next.bytes(), &mut scratch)?;
    assert_eq!(
        Body::decode(&scratch[..n])?.message,
        Some(message(3).as_slice())
    );
    assert_eq!(sender.acknowledge(b.peer(), ack, 103)?, Grant::Unchanged);
    assert_eq!(sender.available(), 126);
    Ok(())
}
#[test]
fn wrong_peer_lower_duplicate_unknown_and_closed_owner_ack_cannot_mint_new_key_credit()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut random = Random(1);
    let mut sender = Sender::new(a.peer(), b.peer(), policy(), 100)?;
    let packet = sender.initial(&a, &message(1), 1, 100, &mut random)?;
    let (ack, _) = inspect(&b, packet.bytes())?;
    assert_eq!(
        sender.acknowledge(a.peer(), ack, 100),
        Err(Error::Authentication)
    );
    assert_eq!(sender.available(), 0);
    let unknown = Ack {
        allowed: 128,
        cmac: [0; 64],
    };
    assert_eq!(sender.acknowledge(b.peer(), unknown, 100)?, Grant::Unknown);
    assert_eq!(
        sender.acknowledge(b.peer(), ack, 100)?,
        Grant::Increased {
            delta: 128,
            available: 128
        }
    );
    assert_eq!(
        sender.acknowledge(b.peer(), Ack { allowed: 8, ..ack }, 100)?,
        Grant::Unchanged
    );
    assert_eq!(sender.available(), 128);
    sender.close();
    assert_eq!(sender.available(), 0);
    assert_eq!(sender.acknowledge(b.peer(), ack, 100), Err(Error::Stale));
    Ok(())
}
#[test]
fn entropy_clock_and_monotime_refusal_preserve_admission_and_the_original_packet_bytes()
-> Result<(), Error> {
    struct Refuse;
    impl Entropy for Refuse {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Entropy)
        }
    }
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut random = Random(1);
    let mut sender = Sender::new(a.peer(), b.peer(), policy(), 100)?;
    assert!(matches!(
        sender.initial(&a, &message(1), 1, 99, &mut random),
        Err(Error::TimeUncertain)
    ));
    assert!(matches!(
        sender.initial(&a, &message(1), 1, 100, &mut Refuse),
        Err(Error::Entropy)
    ));
    assert_eq!(sender.secrets(), 0);
    let packet = sender.initial(&a, &message(1), 1, 100, &mut random)?;
    assert_eq!(packet.operation(), 1);
    let original = packet.bytes().to_vec();
    let (ack, _) = inspect(&b, packet.bytes())?;
    sender.acknowledge(b.peer(), ack, 100)?;
    assert!(matches!(
        sender.initial(&a, &message(2), 1, 100, &mut random),
        Err(Error::Replay)
    ));
    assert!(matches!(
        sender.boxed(&a, &message(2), 101, &mut Refuse),
        Err(Error::Entropy)
    ));
    assert_eq!(sender.available(), 128);
    assert_eq!(packet.bytes(), original);
    let next = sender.boxed(&a, &message(3), 101, &mut random)?;
    assert_eq!(next.operation(), 2);
    assert_eq!(
        next.mode(),
        Mode::Box {
            sequence: 1,
            rekey: false
        }
    );
    Ok(())
}
#[test]
fn authenticated_rekey_selects_newest_confirmed_master_and_preserves_original_inflight_packet()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut random = Random(1);
    let p = Policy {
        maximum_secret_bytes: 800,
        rekey_after_bytes: 192,
        rekey_after_us: u64::MAX,
        ..policy()
    };
    let mut sender = Sender::new(a.peer(), b.peer(), p, 100)?;
    let initial = sender.initial(&a, &message(1), 1, 100, &mut random)?;
    let (ack, old_master) = inspect(&b, initial.bytes())?;
    sender.acknowledge(b.peer(), ack, 100)?;
    let old_packet = sender.boxed(&a, &message(2), 101, &mut random)?;
    let rekey = sender.boxed(&a, &message(3), 102, &mut random)?;
    assert_eq!(
        rekey.mode(),
        Mode::Box {
            sequence: 2,
            rekey: true
        }
    );
    assert_eq!(rekey.bytes().len(), 228);
    let mut scratch = [0; 180];
    let n = DatagramKey::derive(&old_master, 2)?.open_box(rekey.bytes(), &mut scratch)?;
    let body = Body::decode(&scratch[..n])?;
    assert_eq!(body.message, Some(message(3).as_slice()));
    let new = match body.control {
        Some(Control::Rekey(r)) => b.decapsulate_rekey(r.0)?,
        _ => return Err(Error::Malformed),
    };
    sender.acknowledge(
        b.peer(),
        Ack {
            allowed: 64,
            cmac: gnunet_session_crypto::session::udp_cmac(&new)?,
        },
        103,
    )?;
    let packet = sender.boxed(&a, &message(4), 103, &mut random)?;
    assert_eq!(
        packet.mode(),
        Mode::Box {
            sequence: 1,
            rekey: false
        }
    );
    let n = DatagramKey::derive(&new, 1)?.open_box(packet.bytes(), &mut scratch)?;
    assert_eq!(
        Body::decode(&scratch[..n])?.message,
        Some(message(4).as_slice())
    );
    let n = DatagramKey::derive(&old_master, 1)?.open_box(old_packet.bytes(), &mut scratch)?;
    assert_eq!(
        Body::decode(&scratch[..n])?.message,
        Some(message(2).as_slice())
    );
    Ok(())
}
#[test]
fn bounded_master_eviction_and_old_ack_never_refill_a_new_generation() -> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut random = Random(1);
    let mut sender = Sender::new(a.peer(), b.peer(), policy(), 100)?;
    let first = sender.initial(&a, &message(1), 1, 100, &mut random)?;
    let (old, _) = inspect(&b, first.bytes())?;
    sender.initial(&a, &message(2), 2, 101, &mut random)?;
    sender.initial(&a, &message(3), 3, 102, &mut random)?;
    assert_eq!(sender.secrets(), 2);
    assert_eq!(sender.acknowledge(b.peer(), old, 102)?, Grant::Unknown);
    assert_eq!(sender.available(), 0);
    sender.close();
    let mut replacement = Sender::new(a.peer(), b.peer(), policy(), 103)?;
    replacement.initial(&a, &message(4), 4, 103, &mut random)?;
    assert_eq!(replacement.acknowledge(b.peer(), old, 103)?, Grant::Unknown);
    Ok(())
}
