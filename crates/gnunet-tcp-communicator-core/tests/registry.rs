//! Original scoped generation/cleanup and exact NAT address boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Bounded registry tests assert exact rejection and cleanup results"
)]
use core::num::NonZeroUsize;
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_session_crypto::exchange::EcdheSecret;
use gnunet_tcp_communicator_core::{
    nat,
    registry::{Address, Pending, REVERSAL_US, Registry, Slot},
    session::{
        Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Effect, Identity, Phase, Policy, ResultKind,
        Scope, Session, Time,
    },
    wire,
};
use gnunet_types::Error;
struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Entropy)
    }
}
fn policy() -> Result<Policy, Error> {
    let mut p = Policy::reference(NonZeroUsize::new(32).ok_or(Error::InvalidInput)?);
    p.max_backpressure = 1;
    Ok(p)
}
#[test]
fn bound_slots_are_atomic_and_generations_reject_cross_reuse_and_foreign_scope() -> Result<(), Error>
{
    let key = EddsaPrivateKey::from_seed([1; 32]);
    let ex = EcdheSecret::from_eddsa_seed([1; 32]);
    let (mut a_scope, mut b_scope) = (Scope::new(), Scope::new());
    let (mut a_slots, mut b_slots) = ([Slot::new()], [Slot::new()]);
    let (mut a, mut b) = (
        Registry::new(&mut a_scope, &mut a_slots, false),
        Registry::new(&mut b_scope, &mut b_slots, false),
    );
    let id = a.accepted(b"tcp-127.0.0.1:1234")?;
    let foreign = b.accepted(b"tcp-127.0.0.1:1234")?;
    assert_ne!(id, foreign);
    assert_eq!(a.session(foreign).map(|_| ()), Err(Error::Stale));
    assert_eq!(a.occupied(), 1);
    assert_eq!(a.accepted(b"tcp-127.0.0.1:1235"), Err(Error::Capacity));
    assert_eq!(a.address(id)?, b"tcp-127.0.0.1:1234");
    let (mut rx, mut tx, mut pl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let mut callbacks = [CompletionSlot::default()];
    let mut random = NoEntropy;
    let s = Session::managed(
        a.session(id)?,
        Identity::new(&key, &ex)?,
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut pl,
            completions: &mut callbacks,
        },
        policy()?,
        Time { now: 0, signed: 0 },
        &mut random,
    )
    .map_err(|r| r.reason)?;
    let mut s = s;
    assert_eq!(a.failed(id), Err(Error::Conflict));
    assert_eq!(a.retire(&s), Err(Error::WouldBlock));
    s.native_lost();
    let old = s.next_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(s.effect(old)?, Effect::Close));
    s.acknowledge(
        old,
        ResultKind::Success,
        Time { now: 1, signed: 1 },
        &mut random,
    )?;
    a.retire(&s)?;
    let storage = s.into_buffers().map_err(|r| r.reason)?;
    let new = a.accepted(b"tcp-127.0.0.1:1234")?;
    assert_ne!(new, id);
    assert_eq!(a.address(id), Err(Error::Stale));
    let mut next = Session::managed(
        a.session(new)?,
        Identity::new(&key, &ex)?,
        storage,
        policy()?,
        Time { now: 2, signed: 2 },
        &mut random,
    )
    .map_err(|r| r.reason)?;
    next.native_lost();
    let close = next.next_effect()?.ok_or(Error::NotReady)?;
    assert_ne!(close, old);
    assert_eq!(
        next.acknowledge(
            old,
            ResultKind::Success,
            Time { now: 3, signed: 3 },
            &mut random
        ),
        Err(Error::Stale)
    );
    next.acknowledge(
        close,
        ResultKind::Success,
        Time { now: 3, signed: 3 },
        &mut random,
    )?;
    assert_eq!(next.phase(), Phase::Closed);
    a.retire(&next)?;
    Ok(())
}
#[test]
fn failed_constructor_returns_every_original_buffer_without_mutating_sentinels() -> Result<(), Error>
{
    let key = EddsaPrivateKey::from_seed([1; 32]);
    let ex = EcdheSecret::from_eddsa_seed([1; 32]);
    let remote = EddsaPrivateKey::from_seed([2; 32]);
    let mut scope = Scope::new();
    let mut slots = [Slot::new()];
    let mut registry = Registry::new(&mut scope, &mut slots, false);
    let (id, kind) = registry.outbound(remote.public_key(), b"tcp-127.0.0.1:80")?;
    assert_eq!(kind, Pending::Connect);
    assert_eq!(registry.session(id).map(|_| ()), Err(Error::NotReady));
    registry.connected(id)?;
    let (mut rx, mut tx, mut pl) = (
        vec![0xa5; wire::MAX_RECORD],
        vec![0xb6; CIPHERTEXT_CAPACITY],
        vec![0xc7; wire::MAX_RECORD],
    );
    let mut callbacks = [CompletionSlot::default()];
    let result = Session::managed(
        registry.session(id)?,
        Identity::new(&key, &ex)?,
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut pl,
            completions: &mut callbacks,
        },
        policy()?,
        Time { now: 0, signed: 0 },
        &mut NoEntropy,
    );
    let rejected = match result {
        Err(r) => r,
        Ok(_) => return Err(Error::Conflict),
    };
    assert_eq!(rejected.reason, Error::Entropy);
    assert!(rejected.value.1.receive.iter().all(|x| *x == 0xa5));
    assert!(rejected.value.1.transmit.iter().all(|x| *x == 0xb6));
    assert!(rejected.value.1.plaintext.iter().all(|x| *x == 0xc7));
    assert_eq!(registry.session(id).map(|_| ()), Err(Error::NotReady));
    registry.cancel(rejected.value.0).map_err(|r| r.reason)?;
    assert_eq!(registry.occupied(), 0);
    Ok(())
}
#[test]
fn source_nat_wait_uses_ip_and_peer_and_original_admission_deadline() -> Result<(), Error> {
    let a = EddsaPrivateKey::from_seed([1; 32]).public_key();
    let b = EddsaPrivateKey::from_seed([2; 32]).public_key();
    let mut scope = Scope::new();
    let mut slots = [Slot::new(), Slot::new()];
    let mut r = Registry::new(&mut scope, &mut slots, false);
    let (id, p) = r.outbound(a, b"tcp-127.0.0.1:0")?;
    assert_eq!(p, Pending::Reversal);
    assert_eq!(r.expire(u64::MAX), None);
    r.reversal_admitted(id, 123)?;
    assert_eq!(r.outbound(a, b"tcp-127.0.0.1:0000"), Err(Error::Conflict));
    let (id_b, _) = r.outbound(b, b"tcp-127.0.0.1:0")?;
    assert_eq!(
        r.reversed(b, "127.0.0.1".parse().map_err(|_| Error::InvalidInput)?),
        Err(Error::NotFound)
    );
    assert_eq!(r.expire(123 + REVERSAL_US - 1), None);
    assert_eq!(r.expire(123 + REVERSAL_US), Some(id));
    assert_eq!(r.session(id).map(|_| ()), Err(Error::Stale));
    assert_eq!(
        r.reversal_admitted(id_b, u64::MAX - 1),
        Err(Error::Overflow)
    );
    // Refusing an unrepresentable finite bound cannot manufacture a waiting
    // request with an infinite timeout or consume its original planned intent.
    r.reversal_planned(id_b)?;
    assert_eq!(r.expire(u64::MAX - 1), None);
    assert_eq!(r.expire(u64::MAX), None);
    r.failed(id_b)?;
    Ok(())
}
#[test]
fn defined_source_port_conversion_and_ipv6_disable_do_not_invent_dns() -> Result<(), Error> {
    for (text, port) in [
        (b"tcp-127.0.0.1:00000000080".as_slice(), 80),
        (b"tcp-127.0.0.1: +80 \t", 80),
        (b"tcp-127.0.0.1:70000", 0),
        (b"tcp-127.0.0.1:garbage", 0),
        (b"tcp-127.0.0.1", 0),
    ] {
        assert_eq!(Address::parse(text)?.socket().port(), port);
    }
    assert_eq!(
        Address::parse(b"tcp-127.0.0.1:4294967296"),
        Err(Error::Overflow)
    );
    assert!(Address::parse(b"tcp-public.invalid:80").is_err());
    assert!(Address::parse(b"tcp-[::1]:80")?.socket().is_ipv6());
    let mut scope = Scope::new();
    let mut slots = [Slot::new()];
    let mut r = Registry::new(&mut scope, &mut slots, true);
    assert_eq!(
        r.outbound(
            EddsaPrivateKey::from_seed([1; 32]).public_key(),
            b"tcp-[::1]:80"
        ),
        Err(Error::Unavailable)
    );
    Ok(())
}
#[test]
fn exact_native_profiles_and_typed_probe_preserve_fragmented_handshake() -> Result<(), Error> {
    for profile in [nat::Profile::Darwin, nat::Profile::Linux] {
        for text in ["127.0.0.1:80", "[::1]:443"] {
            let s = text.parse().map_err(|_| Error::InvalidInput)?;
            let mut raw = [0; 28];
            let n = nat::address(profile, s, &mut raw)?;
            let view = nat::Native::parse(profile, &raw[..n])?;
            assert_eq!(view.socket(), s);
            assert_eq!(view.bytes(), &raw[..n]);
            let mut message = [0; 128];
            let size = nat::register(&[view], &mut message)?;
            assert_eq!(&message[4..6], &[3, 6]);
            assert_eq!(size, 10 + n + b"communicator-tcp\0".len());
        }
    }
    let mut reader = nat::Reader::new();
    let mut handshake = [0x5a; 168];
    handshake[0] = 1;
    assert_eq!(reader.push(&handshake[..36]), 36);
    assert!(!reader.complete());
    assert_eq!(reader.push(&handshake[36..]), 132);
    assert_eq!(reader.view()?, nat::Preamble::Handshake(&handshake));
    let peer = EddsaPrivateKey::from_seed([7; 32]).public_key();
    let mut bytes = [0; 36];
    nat::probe(peer, &mut bytes)?;
    let mut reader = nat::Reader::new();
    for b in bytes {
        assert_eq!(reader.push(&[b]), 1);
    }
    assert_eq!(reader.view()?, nat::Preamble::Probe(peer));
    Ok(())
}
