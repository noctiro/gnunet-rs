//! Bounded session lifecycle fixtures. Effect ACKs here are explicit test ports,
//! not evidence of a native syscall, normal daemon, or PEERSTORE execution.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Protocol tests assert exact fallible lifecycle results"
)]
use core::num::NonZeroUsize;
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_session_crypto::exchange::EcdheSecret;
use gnunet_tcp_communicator_core::{
    session::{
        self, Buffers, CompletionSlot, Effect, Identity, Phase, Policy, ReplayKind, ResultKind,
        Scope, Session, Time, WriteResult,
    },
    wire,
};
use gnunet_types::Error;

struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        for byte in output {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = self.0 as u8;
        }
        Ok(())
    }
}
struct Storage {
    rx: Vec<u8>,
    tx: Vec<u8>,
    plain: Vec<u8>,
    completions: Vec<CompletionSlot>,
}
impl Storage {
    fn new(n: usize) -> Self {
        Self {
            rx: vec![0; wire::MAX_RECORD],
            tx: vec![0; session::CIPHERTEXT_CAPACITY],
            plain: vec![0; wire::MAX_RECORD],
            completions: (0..n).map(|_| CompletionSlot::default()).collect(),
        }
    }
    fn buffers(&mut self) -> Buffers<'_> {
        Buffers {
            receive: &mut self.rx,
            transmit: &mut self.tx,
            plaintext: &mut self.plain,
            completions: &mut self.completions,
        }
    }
}
fn policy(n: usize) -> Result<Policy, Error> {
    let mut p = Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
    p.max_backpressure = n;
    Ok(p)
}
fn time(n: u64) -> Time {
    Time {
        now: n,
        signed: 1000 + n,
    }
}
fn make<'a>(
    scope: &'a mut Scope,
    storage: &'a mut Storage,
    key: &'a EddsaPrivateKey,
    exchange: &'a EcdheSecret,
    target: Option<gnunet_crypto::EddsaPublicKey>,
    p: Policy,
    entropy: &mut Random,
) -> Result<Session<'a>, Error> {
    Session::new(
        scope,
        Identity::new(key, exchange)?,
        target,
        storage.buffers(),
        p,
        time(0),
        entropy,
    )
}
fn transfer(
    a: &mut Session<'_>,
    b: &mut Session<'_>,
    r: &mut Random,
    n: u64,
    fragment: usize,
) -> Result<(), Error> {
    for _ in 0..64 {
        let Some(t) = a.write_ready(time(n), r)? else {
            if !a.write_interest() {
                return Ok(());
            }
            continue;
        };
        let bytes = a.write_bytes(t)?;
        let count = bytes.len().min(fragment);
        let owned = bytes[..count].to_vec();
        let used = b.ingest(&owned, time(n), r)?;
        if used != count {
            return Err(Error::WouldBlock);
        }
        b.native_read_progress(n);
        a.written(t, WriteResult::Bytes(count), time(n), r)?;
    }
    Err(Error::Capacity)
}
fn services(s: &mut Session<'_>, r: &mut Random, n: u64) -> Result<(), Error> {
    for _ in 0..32 {
        let Some(t) = s.next_effect()? else {
            return Ok(());
        };
        match s.effect(t)? {
            Effect::ReplayStart { .. } => {
                s.acknowledge(t, ResultKind::Success, time(n), r)?;
                s.replay_record(t, None, time(n))?;
            }
            Effect::ReplayStore { .. } => {
                s.acknowledge(t, ResultKind::Success, time(n), r)?;
                s.replay_stored(t, true)?;
            }
            Effect::QueueAdd(..) | Effect::QueueDelete | Effect::SendContinue | Effect::Close => {
                s.acknowledge(t, ResultKind::Success, time(n), r)?
            }
            _ => return Err(Error::Conflict),
        }
    }
    Err(Error::Capacity)
}
fn establish(a: &mut Session<'_>, b: &mut Session<'_>, r: &mut Random) -> Result<(), Error> {
    transfer(a, b, r, 1, 37)?;
    services(b, r, 2)?;
    transfer(b, a, r, 3, 43)?;
    services(a, r, 4)?;
    transfer(a, b, r, 5, 31)?;
    services(b, r, 6)?;
    transfer(b, a, r, 7, 29)?;
    services(a, r, 8)?;
    assert_eq!(a.phase(), Phase::Established);
    assert_eq!(b.phase(), Phase::Established);
    Ok(())
}
fn message() -> [u8; 8] {
    [0, 8, 0, 17, 1, 2, 3, 4]
}

#[test]
fn both_roles_fragmented_kx_and_ack_require_actual_declared_effect_results() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(2), Storage::new(2));
    let mut r = Random(73);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(2)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(2)?, &mut r)?;
    transfer(&mut a, &mut b, &mut r, 1, 36)?;
    assert_eq!(b.phase(), Phase::InitialReplay);
    assert!(!b.write_interest());
    let t = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(
        matches!(b.effect(t)?,Effect::ReplayStart{kind:ReplayKind::Handshake,peer,..} if peer==alice.public_key())
    );
    assert_eq!(b.next_effect()?, Some(t));
    b.acknowledge(t, ResultKind::Success, time(2), &mut r)?;
    b.replay_record(t, None, time(2))?;
    transfer(&mut b, &mut a, &mut r, 3, 43)?;
    services(&mut a, &mut r, 4)?;
    transfer(&mut a, &mut b, &mut r, 5, 31)?;
    services(&mut b, &mut r, 6)?;
    transfer(&mut b, &mut a, &mut r, 7, 29)?;
    services(&mut a, &mut r, 8)?;
    assert_eq!(a.phase(), Phase::Established);
    assert_eq!(b.phase(), Phase::Established);
    assert_eq!(b.replay_record(t, None, time(9)), Err(Error::Stale));
    assert_eq!(
        a.acknowledge(t, ResultKind::Success, time(9), &mut r),
        Err(Error::Stale)
    );
    Ok(())
}
#[test]
fn box_completion_backpressure_and_original_callback_survive_native_close() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(74);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    establish(&mut a, &mut b, &mut r)?;
    a.send(&message())?;
    transfer(&mut a, &mut b, &mut r, 10, 64)?;
    let receive = b.next_effect()?.ok_or(Error::NotReady)?;
    let completion = match b.effect(receive)? {
        Effect::Receive {
            peer,
            message: m,
            completion,
        } => {
            assert_eq!(peer, alice.public_key());
            assert_eq!(m, message());
            completion
        }
        _ => return Err(Error::Conflict),
    };
    b.acknowledge(receive, ResultKind::Queued, time(11), &mut r)?;
    assert_eq!(b.backpressure(), 1);
    assert!(!b.read_interest());
    assert_eq!(b.deadline(), None);
    b.native_lost();
    services(&mut b, &mut r, 12)?;
    assert_eq!(b.phase(), Phase::Detached);
    b.completed(completion, false, 13)?;
    assert_eq!(b.phase(), Phase::Closed);
    assert_eq!(b.completed(completion, true, 14), Err(Error::Stale));
    Ok(())
}
#[test]
fn write_retry_zero_partial_and_immutable_lease_are_not_false_progress() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let mut scope = Scope::new();
    let mut storage = Storage::new(1);
    let mut r = Random(75);
    let mut a = make(
        &mut scope,
        &mut storage,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let t = a.write_ready(time(1), &mut r)?.ok_or(Error::NotReady)?;
    let original = a.write_bytes(t)?.to_vec();
    assert_eq!(a.write_ready(time(2), &mut r)?, Some(t));
    a.written(t, WriteResult::Retry, time(3), &mut r)?;
    let t = a.write_ready(time(4), &mut r)?.ok_or(Error::NotReady)?;
    assert_eq!(a.write_bytes(t)?, original);
    a.written(t, WriteResult::Zero, time(5), &mut r)?;
    let t = a.write_ready(time(6), &mut r)?.ok_or(Error::NotReady)?;
    assert_eq!(a.write_bytes(t)?, original);
    assert_eq!(
        a.written(t, WriteResult::Bytes(original.len() + 1), time(7), &mut r),
        Err(Error::InvalidInput)
    );
    assert_eq!(a.write_ready(time(7), &mut r)?, Some(t));
    a.written(t, WriteResult::Bytes(17), time(8), &mut r)?;
    let next = a.write_ready(time(9), &mut r)?.ok_or(Error::NotReady)?;
    assert_eq!(a.write_bytes(next)?, &original[17..]);
    assert_eq!(a.write_bytes(t), Err(Error::Stale));
    a.native_lost();
    assert_eq!(a.next_effect()?, None);
    a.written(next, WriteResult::Fatal, time(10), &mut r)?;
    let close = a.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(a.effect(close)?, Effect::Close));
    a.acknowledge(close, ResultKind::Success, time(10), &mut r)?;
    assert_eq!(a.phase(), Phase::Closed);
    Ok(())
}
#[test]
fn finish_is_authenticated_and_original_five_second_deadline_is_not_extended() -> Result<(), Error>
{
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(76);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    establish(&mut a, &mut b, &mut r)?;
    a.finish(time(20))?;
    assert_eq!(a.deadline(), Some(20 + session::FINISH_US));
    transfer(&mut a, &mut b, &mut r, 21, 64)?;
    assert_eq!(b.phase(), Phase::Closing);
    assert_eq!(a.phase(), Phase::Closing);
    services(&mut a, &mut r, 22)?;
    services(&mut b, &mut r, 22)?;
    assert_eq!(a.phase(), Phase::Closed);
    assert_eq!(b.phase(), Phase::Closed);
    Ok(())
}
#[test]
fn replay_operation_end_invalidates_and_future_stored_timestamp_requires_finish()
-> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(77);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    transfer(&mut a, &mut b, &mut r, 1, 64)?;
    let t = b.next_effect()?.ok_or(Error::NotReady)?;
    b.acknowledge(t, ResultKind::Success, time(2), &mut r)?;
    b.replay_record(t, Some(&u64::MAX.to_be_bytes()), time(3))?;
    assert_eq!(b.phase(), Phase::Finishing);
    b.tick(3 + session::FINISH_US);
    assert_eq!(b.phase(), Phase::Closing);
    let cancel = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(
        b.effect(cancel)?,
        Effect::ReplayCancel(ReplayKind::Handshake, false, _)
    ));
    b.acknowledge(cancel, ResultKind::Success, time(4), &mut r)?;
    assert_eq!(b.replay_record(t, None, time(4)), Err(Error::Stale));
    services(&mut b, &mut r, 5)?;
    assert_eq!(b.phase(), Phase::Closed);
    Ok(())
}

#[test]
fn complete_scan_precedes_one_final_store_and_failed_commit_closes_peer() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(78);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    transfer(&mut a, &mut b, &mut r, 1, 64)?;
    let query = b.next_effect()?.ok_or(Error::NotReady)?;
    b.acknowledge(query, ResultKind::Success, time(2), &mut r)?;
    b.replay_record(query, Some(&0u64.to_be_bytes()), time(3))?;
    let next = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(b.effect(next)?,Effect::ReplayNext(ReplayKind::Handshake,q) if q==query));
    b.acknowledge(next, ResultKind::Success, time(3), &mut r)?;
    // No store may mutate the live serial-based SQLite iterator.
    assert_eq!(b.next_effect()?, None);
    b.replay_record(query, None, time(4))?;
    let store = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(
        matches!(b.effect(store)?,Effect::ReplayStore{kind:ReplayKind::Handshake,value,..}if value==1000u64.to_be_bytes())
    );
    b.acknowledge(store, ResultKind::Success, time(3), &mut r)?;
    b.replay_stored(store, false)?;
    assert_eq!(b.phase(), Phase::Closing);
    assert_eq!(b.diagnostics().replay_store_failures, 1);
    assert_eq!(b.replay_stored(store, true), Err(Error::Stale));
    assert_eq!(b.replay_record(query, None, time(5)), Err(Error::Stale));
    Ok(())
}
#[test]
fn terminal_callback_revokes_unexecuted_next_lease_instead_of_using_dead_query() -> Result<(), Error>
{
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(79);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    transfer(&mut a, &mut b, &mut r, 1, 64)?;
    let query = b.next_effect()?.ok_or(Error::NotReady)?;
    b.acknowledge(query, ResultKind::Success, time(2), &mut r)?;
    b.replay_record(query, Some(&[0; 7]), time(3))?;
    let next = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(
        b.effect(next)?,
        Effect::ReplayNext(ReplayKind::Handshake, _)
    ));
    b.replay_record(query, None, time(4))?;
    assert!(matches!(b.effect(next), Err(Error::Stale)));
    let store = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(
        b.effect(store)?,
        Effect::ReplayStore {
            kind: ReplayKind::Handshake,
            ..
        }
    ));
    b.acknowledge(store, ResultKind::Success, time(4), &mut r)?;
    b.replay_stored(store, true)?;
    assert_eq!(b.next_effect()?, None);
    Ok(())
}
#[test]
fn independent_key_generations_preserve_original_public_identity() -> Result<(), Error> {
    use gnunet_tcp_communicator_core::session::KeyRing;
    let original_keys = KeyRing::from_seed([1; 32]);
    let original = Identity::from_keys(&original_keys);
    let next_keys = KeyRing::from_seed([2; 32]);
    let next = Identity::from_keys(&next_keys);
    assert_eq!(
        original.public(),
        EddsaPrivateKey::from_seed([1; 32]).public_key()
    );
    assert_eq!(
        next.public(),
        EddsaPrivateKey::from_seed([2; 32]).public_key()
    );
    assert_ne!(original.public(), next.public());
    Ok(())
}

#[test]
fn absolute_scheduler_clock_regression_does_not_become_signature_time_or_immediate_timeout()
-> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let mut scope = Scope::new();
    let mut storage = Storage::new(1);
    let mut r = Random(80);
    let mut a = Session::new(
        &mut scope,
        Identity::new(&alice, &ae)?,
        Some(bob.public_key()),
        storage.buffers(),
        policy(1)?,
        Time {
            now: 1_000_000,
            signed: 99_000_000,
        },
        &mut r,
    )?;
    assert_eq!(a.deadline(), Some(1_000_000 + session::IDLE_US));
    a.tick(1);
    assert_eq!(a.phase(), Phase::Initial);
    a.tick(1_000_000 + session::IDLE_US);
    assert_eq!(a.phase(), Phase::Closing);
    Ok(())
}

fn drained(s: &mut Session<'_>, r: &mut Random, now: u64) -> Result<Vec<u8>, Error> {
    let mut all = Vec::new();
    for _ in 0..32 {
        if let Some(t) = s.write_ready(time(now), r)? {
            let bytes = s.write_bytes(t)?.to_vec();
            let n = bytes.len();
            all.extend_from_slice(&bytes);
            s.written(t, WriteResult::Bytes(n), time(now), r)?;
        } else if !s.write_interest() {
            return Ok(all);
        }
    }
    Err(Error::Capacity)
}
#[test]
fn actual_session_time_rekey_uses_old_cipher_then_new_direction_at_exact_next_byte()
-> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(81);
    let mut p = policy(1)?;
    p.rekey_interval_us = 1000;
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        p,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, p, &mut r)?;
    establish(&mut a, &mut b, &mut r)?;
    a.send(&message())?;
    let bytes = drained(&mut a, &mut r, 1001)?;
    assert_eq!(bytes.len(), 44 + wire::REKEY);
    services(&mut a, &mut r, 1001)?;
    let n = b.ingest(&bytes, time(1001), &mut r)?;
    assert_eq!(n, 44);
    let recv = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(b.effect(recv)?,Effect::Receive{message:m,..}if m==message()));
    b.acknowledge(recv, ResultKind::Dropped, time(1001), &mut r)?;
    assert_eq!(b.ingest(&bytes[n..], time(1001), &mut r)?, wire::REKEY);
    let query = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(
        b.effect(query)?,
        Effect::ReplayStart {
            kind: ReplayKind::Rekey,
            received: 2001,
            ..
        }
    ));
    b.acknowledge(query, ResultKind::Success, time(1001), &mut r)?;
    b.replay_record(query, None, time(1001))?;
    a.send(&message())?;
    let next = drained(&mut a, &mut r, 1002)?;
    assert_eq!(next.len(), 44);
    assert_eq!(b.ingest(&next, time(1002), &mut r)?, 44);
    let recv = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(b.effect(recv)?,Effect::Receive{message:m,..}if m==message()));
    b.acknowledge(recv, ResultKind::Dropped, time(1002), &mut r)?;
    Ok(())
}
#[test]
fn overlapping_rekeys_keep_original_queries_latest_stamp_and_capacity_cleanup() -> Result<(), Error>
{
    for credits in [3, 4] {
        let alice = EddsaPrivateKey::from_seed([1; 32]);
        let bob = EddsaPrivateKey::from_seed([2; 32]);
        let ae = EcdheSecret::from_eddsa_seed([1; 32]);
        let be = EcdheSecret::from_eddsa_seed([2; 32]);
        let (mut sa, mut sb) = (Scope::new(), Scope::new());
        let (mut ba, mut bb) = (Storage::new(2), Storage::new(2));
        let mut random = Random(91);
        let mut p = policy(2)?;
        p.rekey_interval_us = 1000;
        p.max_replay_operations = credits;
        let mut a = make(
            &mut sa,
            &mut ba,
            &alice,
            &ae,
            Some(bob.public_key()),
            p,
            &mut random,
        )?;
        let mut b = make(&mut sb, &mut bb, &bob, &be, None, p, &mut random)?;
        establish(&mut a, &mut b, &mut random)?;
        a.send(&message())?;
        let first = drained(&mut a, &mut random, 1001)?;
        services(&mut a, &mut random, 1001)?;
        assert_eq!(b.ingest(&first, time(1001), &mut random)?, 44);
        let receive = b.next_effect()?.ok_or(Error::NotReady)?;
        b.acknowledge(
            receive,
            if credits == 3 {
                ResultKind::Queued
            } else {
                ResultKind::Dropped
            },
            time(1001),
            &mut random,
        )?;
        let original_completion = receive;
        assert_eq!(
            b.ingest(&first[44..], time(1001), &mut random)?,
            wire::REKEY
        );
        let original = b.next_effect()?.ok_or(Error::NotReady)?;
        b.acknowledge(original, ResultKind::Success, time(1001), &mut random)?;
        // No END is delivered. A second real encrypted rekey arrives while the
        // first original query is live, exactly the slow/tailing-backend case.
        a.send(&message())?;
        let second = drained(&mut a, &mut random, 2002)?;
        services(&mut a, &mut random, 2002)?;
        assert_eq!(b.ingest(&second, time(2002), &mut random)?, 44);
        let receive = b.next_effect()?.ok_or(Error::NotReady)?;
        b.acknowledge(receive, ResultKind::Dropped, time(2002), &mut random)?;
        if credits == 3 {
            assert_eq!(
                b.ingest(&second[44..], time(2002), &mut random),
                Err(Error::Capacity)
            );
            assert_eq!(b.phase(), Phase::Closing);
            b.native_lost();
            let cancel = b.next_effect()?.ok_or(Error::NotReady)?;
            assert!(
                matches!(b.effect(cancel)?,Effect::ReplayCancel(ReplayKind::Rekey,false,q)if q==original)
            );
            b.acknowledge(cancel, ResultKind::Success, time(2002), &mut random)?;
            services(&mut b, &mut random, 2002)?;
            assert_eq!(b.phase(), Phase::Detached);
            b.completed(original_completion, true, 2003)?;
            assert_eq!(b.phase(), Phase::Closed);
            continue;
        }
        assert_eq!(
            b.ingest(&second[44..], time(2002), &mut random)?,
            wire::REKEY
        );
        let newer = b.next_effect()?.ok_or(Error::NotReady)?;
        assert_ne!(original, newer);
        b.acknowledge(newer, ResultKind::Success, time(2002), &mut random)?;
        b.replay_record(original, Some(&2001u64.to_be_bytes()), time(2003))?;
        let next = b.next_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(b.effect(next)?,Effect::ReplayNext(ReplayKind::Rekey,q)if q==original));
        b.acknowledge(next, ResultKind::Success, time(2003), &mut random)?;
        b.replay_record(original, None, time(2004))?;
        let store = b.next_effect()?.ok_or(Error::NotReady)?;
        assert!(
            matches!(b.effect(store)?,Effect::ReplayStore{kind:ReplayKind::Rekey,value,..}if value==3002u64.to_be_bytes())
        );
        b.acknowledge(store, ResultKind::Success, time(2004), &mut random)?;
        b.replay_stored(store, true)?;
        b.replay_record(newer, None, time(2004))?;
        let store = b.next_effect()?.ok_or(Error::NotReady)?;
        b.acknowledge(store, ResultKind::Success, time(2004), &mut random)?;
        b.replay_stored(store, true)?;
        assert_eq!(b.phase(), Phase::Established);
    }
    Ok(())
}
#[test]
fn forever_saturated_source_deadlines_never_expire_at_the_sentinel() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let mut scope = Scope::new();
    let mut storage = Storage::new(1);
    let mut r = Random(82);
    let p = policy(1)?;
    let mut s = Session::new(
        &mut scope,
        Identity::new(&alice, &ae)?,
        Some(bob.public_key()),
        storage.buffers(),
        p,
        Time {
            now: u64::MAX - 2,
            signed: 123,
        },
        &mut r,
    )?;
    assert_eq!(s.deadline(), Some(u64::MAX));
    s.tick(u64::MAX);
    assert_eq!(s.phase(), Phase::Initial);
    s.native_lost();
    services(&mut s, &mut r, 1)?;
    assert_eq!(s.phase(), Phase::Closed);
    Ok(())
}

#[test]
fn repeated_finish_emits_one_valid_record_without_postponing_hard_timer() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(83);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    establish(&mut a, &mut b, &mut r)?;
    a.finish(time(10))?;
    a.finish(time(20))?;
    assert_eq!(a.deadline(), Some(10 + session::FINISH_US));
    let bytes = drained(&mut a, &mut r, 21)?;
    assert_eq!(bytes.len(), 36);
    assert_eq!(a.send(&message()), Err(Error::NotReady));
    assert_eq!(b.ingest(&bytes, time(21), &mut r)?, wire::BOX_PREFIX);
    assert_eq!(b.phase(), Phase::Closing);
    services(&mut a, &mut r, 22)?;
    services(&mut b, &mut r, 22)?;
    assert_eq!(a.phase(), Phase::Closed);
    assert_eq!(b.phase(), Phase::Closed);
    Ok(())
}
#[test]
fn finish_preserves_unsent_box_and_original_partial_write_lease() -> Result<(), Error> {
    for lease_before_close in [false, true] {
        let alice = EddsaPrivateKey::from_seed([1; 32]);
        let bob = EddsaPrivateKey::from_seed([2; 32]);
        let ae = EcdheSecret::from_eddsa_seed([1; 32]);
        let be = EcdheSecret::from_eddsa_seed([2; 32]);
        let (mut sa, mut sb) = (Scope::new(), Scope::new());
        let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
        let mut r = Random(85);
        let mut a = make(
            &mut sa,
            &mut ba,
            &alice,
            &ae,
            Some(bob.public_key()),
            policy(1)?,
            &mut r,
        )?;
        let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
        establish(&mut a, &mut b, &mut r)?;
        a.send(&message())?;
        let original = if lease_before_close {
            Some(a.write_ready(time(10), &mut r)?.ok_or(Error::NotReady)?)
        } else {
            None
        };
        let original_bytes = original
            .map(|ticket| a.write_bytes(ticket).map(<[u8]>::to_vec))
            .transpose()?;
        a.finish(time(11))?;
        a.finish(time(12))?;
        assert_eq!(a.deadline(), Some(11 + session::FINISH_US));
        assert_eq!(a.send(&message()), Err(Error::NotReady));
        assert_eq!(a.next_effect()?, None);
        let ticket = a.write_ready(time(13), &mut r)?.ok_or(Error::NotReady)?;
        if let Some(original) = original {
            assert_eq!(ticket, original);
            assert_eq!(
                a.write_bytes(ticket)?,
                original_bytes.as_deref().ok_or(Error::NotReady)?
            );
        }
        let prefix = a.write_bytes(ticket)?[..3].to_vec();
        assert_eq!(b.ingest(&prefix, time(13), &mut r)?, prefix.len());
        a.written(ticket, WriteResult::Bytes(prefix.len()), time(13), &mut r)?;
        // Retry the close during an actual partial record; neither the old
        // ciphertext cursor nor the pending FINISH may be replaced.
        a.finish(time(14))?;
        let tail = drained(&mut a, &mut r, 15)?;
        assert_eq!(
            tail.len(),
            wire::BOX_PREFIX + message().len() - prefix.len() + wire::BOX_PREFIX
        );
        let used = b.ingest(&tail, time(15), &mut r)?;
        assert_eq!(used, wire::BOX_PREFIX + message().len() - prefix.len());
        let received = b.next_effect()?.ok_or(Error::NotReady)?;
        assert!(
            matches!(b.effect(received)?, Effect::Receive { message: actual, .. } if actual == message())
        );
        b.acknowledge(received, ResultKind::Dropped, time(15), &mut r)?;
        assert_eq!(b.ingest(&tail[used..], time(15), &mut r)?, wire::BOX_PREFIX);
        assert_eq!(b.phase(), Phase::Closing);
        services(&mut a, &mut r, 16)?;
        services(&mut b, &mut r, 16)?;
        assert_eq!(a.phase(), Phase::Closed);
        assert_eq!(b.phase(), Phase::Closed);
    }
    Ok(())
}
#[test]
fn finish_deadline_closes_without_emitting_a_replacement_record() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(86);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    establish(&mut a, &mut b, &mut r)?;
    a.send(&message())?;
    a.finish(time(10))?;
    a.finish(time(20))?;
    // A ready writer enforces the original bound without waiting for a
    // separate idle scheduler/timer turn or generating replacement bytes.
    assert_eq!(a.write_ready(time(10 + session::FINISH_US), &mut r)?, None);
    assert_eq!(a.phase(), Phase::Closing);
    services(&mut a, &mut r, 10 + session::FINISH_US)?;
    assert_eq!(a.phase(), Phase::Closed);
    Ok(())
}
#[test]
fn late_queue_registration_result_cannot_reopen_finishing_session() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ae = EcdheSecret::from_eddsa_seed([1; 32]);
    let be = EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut sa, mut sb) = (Scope::new(), Scope::new());
    let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
    let mut r = Random(87);
    let mut a = make(
        &mut sa,
        &mut ba,
        &alice,
        &ae,
        Some(bob.public_key()),
        policy(1)?,
        &mut r,
    )?;
    let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
    transfer(&mut a, &mut b, &mut r, 1, 37)?;
    services(&mut b, &mut r, 2)?;
    transfer(&mut b, &mut a, &mut r, 3, 43)?;
    services(&mut a, &mut r, 4)?;
    transfer(&mut a, &mut b, &mut r, 5, 31)?;
    let query = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(
        b.effect(query)?,
        Effect::ReplayStart {
            kind: ReplayKind::Acknowledgement,
            ..
        }
    ));
    b.acknowledge(query, ResultKind::Success, time(6), &mut r)?;
    let register = b.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(b.effect(register)?, Effect::QueueAdd(..)));
    b.finish(time(7))?;
    b.acknowledge(register, ResultKind::Success, time(8), &mut r)?;
    assert_eq!(b.phase(), Phase::Finishing);
    b.progress(time(8), &mut r)?;
    assert_eq!(b.phase(), Phase::Finishing);
    assert_eq!(b.send(&message()), Err(Error::NotReady));
    b.replay_record(query, None, time(8))?;
    b.tick(7 + session::FINISH_US);
    services(&mut b, &mut r, 7 + session::FINISH_US)?;
    assert_eq!(b.phase(), Phase::Closed);
    Ok(())
}
#[test]
fn abrupt_retirement_preserves_original_write_result_without_a_send_continuation()
-> Result<(), Error> {
    for issued_write in [false, true] {
        let alice = EddsaPrivateKey::from_seed([1; 32]);
        let bob = EddsaPrivateKey::from_seed([2; 32]);
        let ae = EcdheSecret::from_eddsa_seed([1; 32]);
        let be = EcdheSecret::from_eddsa_seed([2; 32]);
        let (mut sa, mut sb) = (Scope::new(), Scope::new());
        let (mut ba, mut bb) = (Storage::new(1), Storage::new(1));
        let mut r = Random(84);
        let mut a = make(
            &mut sa,
            &mut ba,
            &alice,
            &ae,
            Some(bob.public_key()),
            policy(1)?,
            &mut r,
        )?;
        let mut b = make(&mut sb, &mut bb, &bob, &be, None, policy(1)?, &mut r)?;
        establish(&mut a, &mut b, &mut r)?;
        a.send(&message())?;
        let original = if issued_write {
            Some(a.write_ready(time(20), &mut r)?.ok_or(Error::NotReady)?)
        } else {
            None
        };
        let ciphertext = original
            .map(|ticket| a.write_bytes(ticket).map(<[u8]>::to_vec))
            .transpose()?;
        // Explicit fixture port: the original native owner was lost. This is
        // terminal retirement, not an assertion that kernel-written bytes can
        // be unsent or that a future polling wait may replace the old stream.
        a.native_lost();
        assert_eq!(a.phase(), Phase::Closing);
        assert_eq!(a.send(&message()), Err(Error::NotReady));
        assert!(!a.read_interest());
        assert!(!a.write_interest());
        let down = a.next_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(a.effect(down)?, Effect::QueueDelete));
        a.acknowledge(down, ResultKind::Success, time(21), &mut r)?;
        if let Some(ticket) = original {
            // The issued operation still owns its old result. Close cannot
            // erase/reuse its bytes or fabricate a completion on its behalf.
            assert_eq!(a.next_effect()?, None);
            assert_eq!(a.write_ready(time(21), &mut r)?, Some(ticket));
            assert_eq!(
                a.write_bytes(ticket)?,
                ciphertext.as_deref().ok_or(Error::NotReady)?
            );
            a.written(ticket, WriteResult::Fatal, time(21), &mut r)?;
            assert_eq!(
                a.written(ticket, WriteResult::Fatal, time(21), &mut r),
                Err(Error::Stale)
            );
        } else {
            assert_eq!(a.write_ready(time(21), &mut r)?, None);
        }
        let close = a.next_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(a.effect(close)?, Effect::Close));
        a.acknowledge(close, ResultKind::Success, time(22), &mut r)?;
        assert_eq!(a.phase(), Phase::Closed);
        assert_eq!(a.next_effect()?, None);
        assert_eq!(a.write_ready(time(22), &mut r)?, None);
        assert_eq!(a.send(&message()), Err(Error::NotReady));
        if let Some(ticket) = original {
            assert_eq!(a.write_bytes(ticket), Err(Error::Stale));
        }
        // Remote EOF uses its separate original retirement, without a forged
        // authenticated FINISH or application receive for the aborted BOX.
        b.native_lost();
        services(&mut b, &mut r, 22)?;
        assert_eq!(b.phase(), Phase::Closed);
    }
    Ok(())
}
