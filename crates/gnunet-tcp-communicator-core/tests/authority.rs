//! Source-independent safe-API authority regression; no network or C process.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Regression asserts exact authority results"
)]
use core::num::NonZeroUsize;
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_session_crypto::exchange::EcdheSecret;
use gnunet_tcp_communicator_core::{
    registry::{Registry, Slot},
    session::{
        Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, Policy, ResultKind, Scope, Session,
        Time,
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
#[test]
fn linear_admission_rejects_second_constructor_and_foreign_retirement() -> Result<(), Error> {
    let mut scope = Scope::new();
    let mut slots = [Slot::new()];
    let mut registry = Registry::new(&mut scope, &mut slots, false);
    let id = registry.accepted(b"tcp-127.0.0.1:80")?;
    let key = EddsaPrivateKey::from_seed([1; 32]);
    let ex = EcdheSecret::from_eddsa_seed([1; 32]);
    let identity = Identity::new(&key, &ex)?;
    let mut policy = Policy::reference(NonZeroUsize::new(1).ok_or(Error::Capacity)?);
    policy.max_backpressure = 1;
    let (mut arx, mut atx, mut apl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let (mut brx, mut btx, mut bpl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let (mut ac, mut bc) = ([CompletionSlot::default()], [CompletionSlot::default()]);
    let admission = registry.session(id)?;
    assert_eq!(registry.session(id).map(|_| ()), Err(Error::NotReady));
    let mut first = Session::managed(
        admission,
        identity,
        Buffers {
            receive: &mut arx,
            transmit: &mut atx,
            plaintext: &mut apl,
            completions: &mut ac,
        },
        policy,
        Time { now: 0, signed: 0 },
        &mut NoEntropy,
    )
    .map_err(|r| r.reason)?;
    let mut foreign_scope = Scope::new();
    let mut other = Session::new(
        &mut foreign_scope,
        identity,
        None,
        Buffers {
            receive: &mut brx,
            transmit: &mut btx,
            plaintext: &mut bpl,
            completions: &mut bc,
        },
        policy,
        Time { now: 0, signed: 0 },
        &mut NoEntropy,
    )?;
    first.native_lost();
    other.native_lost();
    let a = first.next_effect()?.ok_or(Error::NotReady)?;
    let b = other.next_effect()?.ok_or(Error::NotReady)?;
    assert_ne!(a, b);
    other.acknowledge(
        b,
        ResultKind::Success,
        Time { now: 1, signed: 1 },
        &mut NoEntropy,
    )?;
    assert_eq!(registry.retire(&other), Err(Error::Stale));
    assert_eq!(registry.occupied(), 1);
    assert!(first.effect(a).is_ok());
    first.acknowledge(
        a,
        ResultKind::Success,
        Time { now: 1, signed: 1 },
        &mut NoEntropy,
    )?;
    registry.retire(&first)?;
    assert_eq!(registry.occupied(), 0);
    Ok(())
}
