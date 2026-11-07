//! Private finite owner witnesses, not native syscall or daemon evidence.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite owner cases assert exact authority-preserving branches"
)]
use super::*;
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for byte in out {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (self.0 >> 24) as u8;
        }
        Ok(())
    }
}
#[test]
fn serial_max_keeps_original_write_ack_and_close_cleanup_without_new_mint() -> Result<(), Error> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ex = EcdheSecret::from_eddsa_seed([1; 32]);
    let mut scope = Scope::new();
    let (mut rx, mut tx, mut plain) = (
        std::vec![0;wire::MAX_RECORD],
        std::vec![0;CIPHERTEXT_CAPACITY],
        std::vec![0;wire::MAX_RECORD],
    );
    let mut callbacks = [CompletionSlot::default()];
    let mut random = Random(31);
    let mut policy =
        Policy::reference(core::num::NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
    policy.max_backpressure = 1;
    let time = Time { now: 0, signed: 0 };
    let mut s = Session::new(
        &mut scope,
        Identity::new(&alice, &ex)?,
        Some(bob.public_key()),
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut plain,
            completions: &mut callbacks,
        },
        policy,
        time,
        &mut random,
    )?;
    s.serial = u64::MAX - 1;
    let original = s.write_ready(time, &mut random)?.ok_or(Error::NotReady)?;
    assert_eq!(original.serial, u64::MAX);
    s.native_lost();
    assert_eq!(s.next_effect()?, None);
    s.written(original, WriteResult::Fatal, time, &mut random)?;
    let close = s.next_effect()?.ok_or(Error::NotReady)?;
    assert_eq!(close.serial, 0);
    assert!(matches!(s.effect(close)?, Effect::Close));
    s.acknowledge(close, ResultKind::Success, time, &mut random)?;
    assert_eq!(s.phase(), Phase::Closed);
    assert_eq!(
        s.written(original, WriteResult::Zero, time, &mut random),
        Err(Error::Stale)
    );
    Ok(())
}
#[test]
fn exhausted_mint_finishes_original_query_and_does_not_admit_phantom_operation() -> Result<(), Error>
{
    let key = EddsaPrivateKey::from_seed([1; 32]);
    let ex = EcdheSecret::from_eddsa_seed([1; 32]);
    let mut scope = Scope::new();
    let (mut rx, mut tx, mut plain) = (
        std::vec![0;wire::MAX_RECORD],
        std::vec![0;CIPHERTEXT_CAPACITY],
        std::vec![0;wire::MAX_RECORD],
    );
    let mut callbacks = [CompletionSlot::default()];
    let mut random = Random(31);
    let mut policy =
        Policy::reference(core::num::NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
    policy.max_backpressure = 1;
    let time = Time { now: 0, signed: 0 };
    let mut s = Session::new(
        &mut scope,
        Identity::new(&key, &ex)?,
        None,
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut plain,
            completions: &mut callbacks,
        },
        policy,
        time,
        &mut random,
    )?;
    s.replay[0] = Replay {
        kind: ReplayKind::Handshake,
        serial: 9,
        store_serial: 0,
        state: ReplayState::NextReady,
        received: 3,
        query: true,
        store: false,
    };
    s.serial = u64::MAX;
    assert_eq!(s.next_effect(), Err(Error::Capacity));
    assert_eq!(s.phase(), Phase::Closing);
    let cancel = s.next_effect()?.ok_or(Error::NotReady)?;
    assert_eq!(cancel.serial, 9);
    assert!(matches!(
        s.effect(cancel)?,
        Effect::ReplayCancel(ReplayKind::Handshake, false, _)
    ));
    s.acknowledge(cancel, ResultKind::Success, time, &mut random)?;
    let close = s.next_effect()?.ok_or(Error::NotReady)?;
    s.acknowledge(close, ResultKind::Success, time, &mut random)?;
    assert_eq!(s.phase(), Phase::Closed);
    Ok(())
}

// Focused owner fixture: the initial ciphertext is no longer pending and the
// stream is idle. This does not claim a real peer handshake or socket write.
fn with_idle_write_owner(
    check: impl FnOnce(&mut Session<'_>, Time, &mut Random) -> Result<(), Error>,
) -> Result<(), Error> {
    let local = EddsaPrivateKey::from_seed([47; 32]);
    let remote = EddsaPrivateKey::from_seed([53; 32]);
    let exchange = EcdheSecret::from_eddsa_seed([47; 32]);
    let mut scope = Scope::new();
    let (mut rx, mut tx, mut plain) = (
        std::vec![0; wire::MAX_RECORD],
        std::vec![0; CIPHERTEXT_CAPACITY],
        std::vec![0; wire::MAX_RECORD],
    );
    let mut completions = [CompletionSlot::default()];
    let mut random = Random(59);
    let mut policy =
        Policy::reference(core::num::NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
    policy.max_backpressure = 1;
    let time = Time {
        now: 100,
        signed: 100,
    };
    let mut session = Session::new(
        &mut scope,
        Identity::new(&local, &exchange)?,
        Some(remote.public_key()),
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut plain,
            completions: &mut completions,
        },
        policy,
        time,
        &mut random,
    )?;
    session.tx[..session.tx_len].zeroize();
    session.tx_len = 0;
    session.write_scheduled = false;
    session.phase = Phase::Established;
    session.rekey_left = 1;
    session.rekey_deadline = u64::MAX;
    check(&mut session, time, &mut random)
}

#[test]
fn idle_writable_turn_without_ciphertext_does_not_mint_or_reschedule() -> Result<(), Error> {
    with_idle_write_owner(|session, time, random| {
        let serial = session.serial;
        assert_eq!(session.write_ready(time, random)?, None);
        assert!(!session.write_interest());
        // A stale writable notification with no new plaintext remains idle.
        session.write_scheduled = true;
        assert_eq!(session.write_ready(time, random)?, None);
        assert_eq!(session.serial, serial);
        assert_eq!(session.tx_len, 0);
        assert_eq!(session.write_lease, None);
        assert!(!session.write_interest());
        Ok(())
    })
}

#[test]
fn idle_finish_exposes_new_ciphertext_without_a_write_receipt() -> Result<(), Error> {
    with_idle_write_owner(|session, time, random| {
        session.finish(time)?;
        assert_eq!(session.tx_len, 0);
        // Close reserves the intent. Its one record is staged only after all
        // earlier plaintext/ciphertext has drained, in the writable turn.
        assert_eq!(session.plain_len, 0);
        assert!(session.finish_pending);
        assert!(!session.continue_send);
        assert_eq!(session.write_lease, None);
        let timeout = session.timeout;
        let finish_deadline = session.finish_deadline;
        let metrics = session.metrics();
        let ticket = session.write_ready(time, random)?.ok_or(Error::NotReady)?;
        assert_eq!(session.write_bytes(ticket)?.len(), wire::BOX_PREFIX);
        assert_eq!(session.tx_len, wire::BOX_PREFIX);
        assert_eq!(session.plain_len, 0);
        assert!(!session.finish_pending);
        assert_eq!(session.phase(), Phase::Finishing);
        assert_eq!(session.timeout, timeout);
        assert_eq!(session.finish_deadline, finish_deadline);
        assert_eq!(session.metrics(), metrics);
        // Re-polling returns the same original cursor and does not prepare or
        // acknowledge a second record. Only written() can consume these bytes.
        assert_eq!(session.write_ready(time, random)?, Some(ticket));
        let ciphertext = session.write_bytes(ticket)?.to_vec();
        session.written(ticket, WriteResult::Retry, time, random)?;
        let retry = session.write_ready(time, random)?.ok_or(Error::NotReady)?;
        assert_eq!(session.write_bytes(retry)?, ciphertext);
        assert_eq!(session.phase(), Phase::Finishing);
        assert_eq!(session.finish_deadline, finish_deadline);
        assert!(!session.continue_send);
        Ok(())
    })
}
