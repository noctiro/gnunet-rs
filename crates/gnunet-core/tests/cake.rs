//! Real production owners exercise transcript, confirmation, loss and recovery.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Protocol regression assertions identify failed state transitions"
)]
use gnunet_core::{
    session::{Event, Identity, Phase, Session},
    wire::WordOrder,
};
use gnunet_crypto::Entropy;
use gnunet_types::Error;

struct Random(u64, usize);
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.1 += bytes.len();
        for byte in bytes {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}
fn pair<'a>(a: &'a Identity, b: &'a Identity) -> Result<(Session<'a>, Session<'a>), Error> {
    let first = Session::new(a, b.public_key(), WordOrder::Little, b"resolver;dht")?;
    let second = Session::new(b, a.public_key(), WordOrder::Little, b"core")?;
    Ok(if first.phase() == Phase::Ready {
        (first, second)
    } else {
        (second, first)
    })
}

struct Flights {
    hello: Vec<u8>,
    response: Vec<u8>,
    done: Vec<u8>,
    ack: Vec<u8>,
}
fn exchange(
    i: &mut Session<'_>,
    r: &mut Session<'_>,
    random: &mut Random,
) -> Result<Flights, Error> {
    let mut output = [0; 2048];
    let mut scratch = [0; 2048];
    let Event::Send(n) = i.tick(0, random, &mut output)? else {
        return Err(Error::NotReady);
    };
    let hello = output[..n].to_vec();
    let Event::Send(n) = r.receive(0, &hello, random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let response = output[..n].to_vec();
    let Event::Send(n) = i.receive(0, &response, random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    assert!(!i.established());
    let done = output[..n].to_vec();
    let Event::Established(n) = r.receive(0, &done, random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let ack = output[..n].to_vec();
    assert_eq!(
        i.receive(0, &ack, random, &mut output, &mut scratch)?,
        Event::Established(0)
    );
    assert!(i.established() && r.established());
    Ok(Flights {
        hello,
        response,
        done,
        ack,
    })
}
const MESSAGE: [u8; 9] = [0, 9, 0, 1, b'h', b'e', b'l', b'l', b'o'];

#[test]
fn authenticated_class_commits_with_finished_and_keeps_old_association_metadata()
-> Result<(), Error> {
    let a = Identity::from_seed([71; 32]);
    let b = Identity::from_seed([72; 32]);
    let sa = Session::<1024>::with_class(&a, b.public_key(), WordOrder::Little, b"", 3)?;
    let sb = Session::<1024>::with_class(&b, a.public_key(), WordOrder::Little, b"", 5)?;
    let a_initiates = sa.phase() == Phase::Ready;
    let (mut i, mut r, iclass, rclass) = if a_initiates {
        (sa, sb, 3, 5)
    } else {
        (sb, sa, 5, 3)
    };
    let mut entropy = Random(97, 0);
    let mut out = [0; 2048];
    let mut plain = [0; 2048];
    assert_eq!((i.peer_class(), r.peer_class()), (None, None));
    let Event::Send(n) = i.tick(0, &mut entropy, &mut out)? else {
        return Err(Error::NotReady);
    };
    let ih = out[..n].to_vec();
    let Event::Send(n) = r.receive(0, &ih, &mut entropy, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let rh = out[..n].to_vec();
    assert_eq!(r.peer_class(), None);
    let Event::Send(n) = i.receive(0, &rh, &mut entropy, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let done = out[..n].to_vec();
    assert_eq!(i.peer_class(), None);
    let mut bad = done.clone();
    bad[4] ^= 1;
    assert_eq!(
        r.receive(0, &bad, &mut entropy, &mut out, &mut plain),
        Err(Error::Authentication)
    );
    assert_eq!(r.peer_class(), None);
    let Event::Established(n) = r.receive(0, &done, &mut entropy, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let ack = out[..n].to_vec();
    assert_eq!(r.peer_class(), Some(iclass));
    assert_eq!(
        i.receive(0, &ack, &mut entropy, &mut out, &mut plain)?,
        Event::Established(0)
    );
    assert_eq!(i.peer_class(), Some(rclass));
    let (iid, rid) = if a_initiates { (&a, &b) } else { (&b, &a) };
    let mut next = Session::<1024>::with_class(iid, rid.public_key(), WordOrder::Little, b"", 11)?;
    let Event::Send(n) = next.tick(10, &mut entropy, &mut out)? else {
        return Err(Error::NotReady);
    };
    let ih = out[..n].to_vec();
    let Event::Send(n) = r.receive(10, &ih, &mut entropy, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let rh = out[..n].to_vec();
    assert_eq!(r.peer_class(), Some(iclass));
    let Event::Send(n) = next.receive(10, &rh, &mut entropy, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let done = out[..n].to_vec();
    let mut bad = done.clone();
    bad[4] ^= 1;
    assert_eq!(
        r.receive(10, &bad, &mut entropy, &mut out, &mut plain),
        Err(Error::Authentication)
    );
    assert_eq!(r.peer_class(), Some(iclass));
    let Event::Established(n) = r.receive(10, &done, &mut entropy, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let ack = out[..n].to_vec();
    assert_eq!(r.peer_class(), Some(11));
    assert_eq!(
        next.receive(10, &ack, &mut entropy, &mut out, &mut plain)?,
        Event::Established(0)
    );
    assert_eq!(next.peer_class(), Some(rclass));
    Ok(())
}

#[test]
fn complete_handshake_and_bidirectional_application_records() -> Result<(), Error> {
    let a = Identity::from_seed([1; 32]);
    let b = Identity::from_seed([2; 32]);
    let (mut i, mut r) = pair(&a, &b)?;
    let mut random = Random(17, 0);
    let f = exchange(&mut i, &mut r, &mut random)?;
    assert!(f.hello.len() > 194 && f.response.len() > 178);
    assert_eq!((f.done.len(), f.ack.len()), (104, 40));
    let mut output = [0; 2048];
    let mut scratch = [0; 2048];
    let n = i.send(1, &MESSAGE, &mut output)?;
    let frame = output[..n].to_vec();
    assert_eq!(
        r.receive(1, &frame, &mut random, &mut output, &mut scratch)?,
        Event::Payload(MESSAGE.len())
    );
    assert_eq!(&scratch[..MESSAGE.len()], &MESSAGE);
    let n = r.send(2, &MESSAGE, &mut output)?;
    let frame = output[..n].to_vec();
    assert_eq!(
        i.receive(2, &frame, &mut random, &mut output, &mut scratch)?,
        Event::Payload(MESSAGE.len())
    );
    assert_eq!(&scratch[..MESSAGE.len()], &MESSAGE);
    Ok(())
}

#[test]
fn duplicate_flights_are_byte_identical_and_consume_no_new_entropy() -> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([4; 32]);
    let (mut i, mut r) = pair(&a, &b)?;
    let mut random = Random(31, 0);
    let mut output = [0; 2048];
    let mut scratch = [0; 2048];
    let Event::Send(n) = i.tick(0, &mut random, &mut output)? else {
        return Err(Error::NotReady);
    };
    let hello = output[..n].to_vec();
    let used = random.1;
    assert_eq!(i.tick(1_000_000, &mut random, &mut output)?, Event::Send(n));
    assert_eq!(&output[..n], &hello);
    assert_eq!(random.1, used);
    let Event::Send(n) = r.receive(1_000_000, &hello, &mut random, &mut output, &mut scratch)?
    else {
        return Err(Error::NotReady);
    };
    let response = output[..n].to_vec();
    let used = random.1;
    assert_eq!(
        r.receive(1_000_001, &hello, &mut random, &mut output, &mut scratch)?,
        Event::Send(n)
    );
    assert_eq!(&output[..n], &response);
    assert_eq!(random.1, used);
    let Event::Send(n) = i.receive(1_000_002, &response, &mut random, &mut output, &mut scratch)?
    else {
        return Err(Error::NotReady);
    };
    let done = output[..n].to_vec();
    assert_eq!(
        i.receive(1_000_003, &response, &mut random, &mut output, &mut scratch)?,
        Event::Send(n)
    );
    assert_eq!(&output[..n], &done);
    let Event::Established(n) =
        r.receive(1_000_004, &done, &mut random, &mut output, &mut scratch)?
    else {
        return Err(Error::NotReady);
    };
    let ack1 = output[..n].to_vec();
    assert_eq!(
        r.receive(1_000_005, &done, &mut random, &mut output, &mut scratch)?,
        Event::Send(n)
    );
    let ack2 = output[..n].to_vec();
    assert_ne!(ack1, ack2);
    assert_eq!(
        i.receive(1_000_006, &ack2, &mut random, &mut output, &mut scratch)?,
        Event::Established(0)
    );
    assert_eq!(
        i.receive(1_000_007, &ack1, &mut random, &mut output, &mut scratch)?,
        Event::None
    );
    assert_eq!(
        i.receive(1_000_008, &ack2, &mut random, &mut output, &mut scratch),
        Err(Error::Replay)
    );
    Ok(())
}

#[test]
fn unauthenticated_handshake_bytes_do_not_poison_later_valid_flight() -> Result<(), Error> {
    let a = Identity::from_seed([5; 32]);
    let b = Identity::from_seed([6; 32]);
    let (mut i, mut r) = pair(&a, &b)?;
    let mut random = Random(41, 0);
    let mut output = [0; 2048];
    let mut scratch = [0; 2048];
    let Event::Send(n) = i.tick(0, &mut random, &mut output)? else {
        return Err(Error::NotReady);
    };
    let hello = output[..n].to_vec();
    for offset in [4, 8, 80, 176, n - 1] {
        let mut bad = hello.clone();
        bad[offset] ^= 1;
        assert!(
            r.receive(1, &bad, &mut random, &mut output, &mut scratch)
                .is_err()
        );
        assert_eq!(r.phase(), Phase::AwaitInitiator);
        assert!(!r.established());
    }
    let Event::Send(n) = r.receive(2, &hello, &mut random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let response = output[..n].to_vec();
    let mut bad = response.clone();
    bad[n - 1] ^= 1;
    assert_eq!(
        i.receive(3, &bad, &mut random, &mut output, &mut scratch),
        Err(Error::Authentication)
    );
    assert_eq!(i.phase(), Phase::InitiatorHelloSent);
    let Event::Send(n) = i.receive(4, &response, &mut random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let done = output[..n].to_vec();
    let mut bad = done.clone();
    bad[68] ^= 1;
    assert_eq!(
        r.receive(5, &bad, &mut random, &mut output, &mut scratch),
        Err(Error::Authentication)
    );
    assert_eq!(r.phase(), Phase::ResponderHelloSent);
    assert!(!r.established());
    assert!(matches!(
        r.receive(6, &done, &mut random, &mut output, &mut scratch)?,
        Event::Established(40)
    ));
    Ok(())
}

#[test]
fn failed_future_epoch_does_not_erase_committed_replay_or_liveness() -> Result<(), Error> {
    let a = Identity::from_seed([7; 32]);
    let b = Identity::from_seed([8; 32]);
    let (mut i, mut r) = pair(&a, &b)?;
    let mut random = Random(51, 0);
    exchange(&mut i, &mut r, &mut random)?;
    let mut output = [0; 2048];
    let mut scratch = [0; 2048];
    let n = i.send(1, &MESSAGE, &mut output)?;
    let frame = output[..n].to_vec();
    assert_eq!(
        r.receive(1, &frame, &mut random, &mut output, &mut scratch)?,
        Event::Payload(MESSAGE.len())
    );
    let deadline = r.next_deadline();
    for epoch in [1_u64, 10, 20, 21, u64::MAX] {
        let mut bad = frame.clone();
        bad[4..12].copy_from_slice(&epoch.to_be_bytes());
        assert!(
            r.receive(50_000, &bad, &mut random, &mut output, &mut scratch)
                .is_err()
        );
        assert_eq!(r.next_deadline(), deadline);
        assert!(r.established());
        assert_eq!(
            r.receive(50_001, &frame, &mut random, &mut output, &mut scratch),
            Err(Error::Replay)
        );
    }
    Ok(())
}

#[test]
fn old_association_survives_new_unauthenticated_exchange_until_finished() -> Result<(), Error> {
    let a = Identity::from_seed([9; 32]);
    let b = Identity::from_seed([10; 32]);
    let (mut old_i, mut r) = pair(&a, &b)?;
    let (mut new_i, _) = pair(&a, &b)?;
    let mut random = Random(71, 0);
    exchange(&mut old_i, &mut r, &mut random)?;
    let mut output = [0; 2048];
    let mut scratch = [0; 2048];
    let n = old_i.send(1, &MESSAGE, &mut output)?;
    let old = output[..n].to_vec();
    let Event::Send(n) = new_i.tick(2, &mut random, &mut output)? else {
        return Err(Error::NotReady);
    };
    let hello = output[..n].to_vec();
    let Event::Send(n) = r.receive(2, &hello, &mut random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let response = output[..n].to_vec();
    assert_eq!(r.phase(), Phase::ResponderHelloSent);
    assert!(r.established());
    assert_eq!(
        r.receive(3, &old, &mut random, &mut output, &mut scratch)?,
        Event::Payload(MESSAGE.len())
    );
    let Event::Send(n) = new_i.receive(4, &response, &mut random, &mut output, &mut scratch)?
    else {
        return Err(Error::NotReady);
    };
    let done = output[..n].to_vec();
    let Event::Established(n) = r.receive(4, &done, &mut random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let ack = output[..n].to_vec();
    assert_eq!(
        new_i.receive(4, &ack, &mut random, &mut output, &mut scratch)?,
        Event::Established(0)
    );
    assert!(
        r.receive(5, &old, &mut random, &mut output, &mut scratch)
            .is_err()
    );
    let n = new_i.send(6, &MESSAGE, &mut output)?;
    let new = output[..n].to_vec();
    assert_eq!(
        r.receive(6, &new, &mut random, &mut output, &mut scratch)?,
        Event::Payload(MESSAGE.len())
    );
    Ok(())
}

#[test]
fn record_capacity_refusal_and_clock_rollback_preserve_original_targets() -> Result<(), Error> {
    let a = Identity::from_seed([11; 32]);
    let b = Identity::from_seed([12; 32]);
    let (mut i, mut r) = pair(&a, &b)?;
    let mut random = Random(81, 0);
    let mut tiny = [0; 100];
    assert_eq!(i.tick(0, &mut random, &mut tiny), Err(Error::Capacity));
    assert_eq!(random.1, 0);
    let mut output = [0; 2048];
    assert!(matches!(
        i.tick(100, &mut random, &mut output)?,
        Event::Send(_)
    ));
    assert_eq!(i.next_deadline(), 1_000_100);
    assert_eq!(i.tick(1, &mut random, &mut output)?, Event::None);
    assert_eq!(i.next_deadline(), 1_000_100);
    let (mut i, _) = pair(&a, &b)?;
    exchange(&mut i, &mut r, &mut random)?;
    assert_eq!(i.send(1, &MESSAGE, &mut [0; 40]), Err(Error::Capacity));
    let n = i.send(1, &MESSAGE, &mut output)?;
    let frame = output[..n].to_vec();
    assert_eq!(
        r.receive(1, &frame, &mut random, &mut output, &mut [0; 2048])?,
        Event::Payload(MESSAGE.len())
    );
    Ok(())
}

#[test]
fn unanswered_authenticated_association_is_lost_after_three_probes() -> Result<(), Error> {
    let a = Identity::from_seed([13; 32]);
    let b = Identity::from_seed([14; 32]);
    let (mut i, mut r) = pair(&a, &b)?;
    let mut random = Random(91, 0);
    exchange(&mut i, &mut r, &mut random)?;
    let mut output = [0; 2048];
    for now in [30_000_000, 60_000_000, 90_000_000] {
        assert!(matches!(
            i.tick(now, &mut random, &mut output)?,
            Event::Send(44)
        ));
        assert!(i.established());
    }
    assert_eq!(i.tick(120_000_000, &mut random, &mut output)?, Event::Lost);
    assert!(!i.established());
    assert_eq!(
        i.send(120_000_001, &MESSAGE, &mut output),
        Err(Error::NotReady)
    );
    assert!(matches!(
        i.tick(120_000_002, &mut random, &mut output)?,
        Event::Send(_)
    ));
    Ok(())
}

#[test]
fn aborted_unconfirmed_exchange_must_not_be_confirmed_by_old_ack() -> Result<(), Error> {
    let a = Identity::from_seed([31; 32]);
    let b = Identity::from_seed([32; 32]);
    let (mut i, mut r) = pair(&a, &b)?;
    let mut random = Random(991, 0);
    let mut output = [0; 2048];
    let mut scratch = [0; 2048];
    let Event::Send(n) = i.tick(0, &mut random, &mut output)? else {
        return Err(Error::NotReady);
    };
    let first_hello = output[..n].to_vec();
    let Event::Send(n) = r.receive(0, &first_hello, &mut random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let response = output[..n].to_vec();
    let Event::Send(n) = i.receive(0, &response, &mut random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let done = output[..n].to_vec();
    let Event::Established(n) = r.receive(0, &done, &mut random, &mut output, &mut scratch)? else {
        return Err(Error::NotReady);
    };
    let old_ack = output[..n].to_vec();
    assert_eq!(i.phase(), Phase::InitiatorDoneSent);
    assert!(!i.established());
    for now in [1_000_000, 3_000_000, 7_000_000, 15_000_000, 31_000_000] {
        assert_eq!(i.tick(now, &mut random, &mut output)?, Event::Send(104));
    }
    let Event::Send(n) = i.tick(63_000_000, &mut random, &mut output)? else {
        return Err(Error::NotReady);
    };
    assert_eq!(i.phase(), Phase::InitiatorHelloSent);
    assert_ne!(&output[..n], &first_hello);
    let result = i.receive(63_000_001, &old_ack, &mut random, &mut output, &mut scratch);
    assert!(
        !i.established(),
        "old ACK confirmed abandoned association during new exchange: {result:?}, phase {:?}",
        i.phase()
    );
    assert_eq!(i.phase(), Phase::InitiatorHelloSent);
    Ok(())
}
