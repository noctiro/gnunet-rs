#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare decoded wire fragments in fallible tests."
)]

use super::*;

const MTU: u16 = 64;
const RETENTION: RelativeTime = RelativeTime::from_micros(100);

struct TestEntropy;

impl Entropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(0x35);
        Ok(())
    }
}

fn frame() -> [u8; 72] {
    let mut frame = [43; 72];
    frame[..4].copy_from_slice(&[0, 72, 0, 83]);
    frame
}

#[test]
fn refused_attempt_keeps_its_id_and_each_admission_advances_the_original() -> Result<(), Error> {
    let mut sender = Sender::new(NonZeroU16::new(MTU).ok_or(Error::InvalidInput)?, RETENTION)?;
    let frame = frame();
    let mut scratch = [0; 64];
    let mut first = ([0; 8], [0; 16]);
    assert_eq!(
        sender.send(
            MonoInstant(1),
            &frame,
            &mut scratch,
            &mut TestEntropy,
            |wire, span| {
                assert_eq!(span, Span::Partial);
                let fragment = Fragment::decode(wire)?;
                first = (fragment.message_id, fragment.ack);
                assert_eq!(fragment.offset, 0);
                assert_eq!(fragment.body, &frame[..32]);
                Err::<(), _>(Error::WouldBlock)
            },
        ),
        Err(Error::WouldBlock)
    );
    assert_eq!(sender.deadline(), Some(MonoInstant(101)));

    let initial = sender.send(
        MonoInstant(2),
        &frame,
        &mut scratch,
        &mut TestEntropy,
        |wire, span| {
            assert_eq!(span, Span::Partial);
            let fragment = Fragment::decode(wire)?;
            assert_eq!((fragment.message_id, fragment.ack), first);
            assert_eq!(fragment.total, 72);
            assert_eq!(fragment.offset, 0);
            Ok(fragment.ack)
        },
    )?;
    assert_eq!(initial, Progress::Partial(first.1));

    let second = sender.send(
        MonoInstant(3),
        &frame,
        &mut scratch,
        &mut TestEntropy,
        |wire, span| {
            assert_eq!(span, Span::Partial);
            let fragment = Fragment::decode(wire)?;
            assert_eq!(fragment.message_id, first.0);
            assert_ne!(fragment.ack, first.1);
            assert_eq!(fragment.offset, 32);
            assert_eq!(fragment.body, &frame[32..64]);
            Ok(fragment.ack)
        },
    )?;
    let Progress::Partial(second_id) = second else {
        return Err(Error::Conflict);
    };

    assert_eq!(
        sender.send(
            MonoInstant(4),
            &frame,
            &mut scratch,
            &mut TestEntropy,
            |wire, span| {
                assert_eq!(span, Span::Final);
                let fragment = Fragment::decode(wire)?;
                assert_eq!(fragment.message_id, first.0);
                assert_ne!(fragment.ack, first.1);
                assert_ne!(fragment.ack, second_id);
                assert_eq!(fragment.offset, 64);
                assert_eq!(fragment.body, &frame[64..]);
                Ok(())
            },
        )?,
        Progress::Complete(())
    );
    assert!(!sender.is_active());
    assert_eq!(sender.deadline(), None);
    Ok(())
}

#[test]
fn mutation_expiry_and_validation_loss_do_not_replay_an_original() -> Result<(), Error> {
    let mut sender = Sender::new(NonZeroU16::new(MTU).ok_or(Error::InvalidInput)?, RETENTION)?;
    let mut frame = frame();
    let mut scratch = [0; 64];
    let mut refused = ([0; 8], [0; 16]);
    assert_eq!(
        sender.send(
            MonoInstant(0),
            &frame,
            &mut scratch,
            &mut TestEntropy,
            |wire, _span| {
                let fragment = Fragment::decode(wire)?;
                refused = (fragment.message_id, fragment.ack);
                Err::<(), _>(Error::WouldBlock)
            },
        ),
        Err(Error::WouldBlock)
    );
    frame[71] ^= 1;
    let reject_late_admission = |_wire: &[u8], _span| Err::<(), _>(Error::Io);
    assert_eq!(
        sender.send(
            MonoInstant(99),
            &frame,
            &mut scratch,
            &mut TestEntropy,
            reject_late_admission,
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        sender.send(
            MonoInstant(100),
            &frame,
            &mut scratch,
            &mut TestEntropy,
            reject_late_admission,
        ),
        Err(Error::Deadline)
    );
    sender.cancel();
    assert_eq!(sender.deadline(), None);
    assert_eq!(
        sender.send(
            MonoInstant(102),
            &frame,
            &mut scratch,
            &mut TestEntropy,
            |wire, _span| {
                let fragment = Fragment::decode(wire)?;
                assert_ne!(fragment.message_id, refused.0);
                assert_ne!(fragment.ack, refused.1);
                assert_eq!(fragment.offset, 0);
                Ok(())
            },
        )?,
        Progress::Partial(())
    );
    Ok(())
}
