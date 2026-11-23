use super::*;
use crate::p2p::acknowledgements;

const FRAME: [u8; 8] = [0, 8, 0, 83, 1, 2, 3, 4];
const SECOND: [u8; 8] = [0, 8, 0, 83, 5, 6, 7, 8];

fn fragment(id: u8, attempt: u8, offset: u16, body: &[u8]) -> Fragment<'_> {
    Fragment {
        offset,
        total: 8,
        ack: [attempt; 16],
        message_id: [id; 8],
        body,
    }
}

fn receive<const N: usize>(
    owner: &mut Reassembly<'_, N>,
    now: MonoInstant,
    fragment: Fragment<'_>,
) -> Result<Receive, Error> {
    owner.receive(now, fragment, |_, _| Ok(()))
}

fn packed<'a, const N: usize>(
    frame_bytes: usize,
    body: &'a mut [u8],
    coverage: &'a mut [u8],
) -> Result<Reassembly<'a, N>, Error> {
    Reassembly::new(
        frame_bytes,
        FragmentLane::partition(frame_bytes, body, coverage)?,
    )
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact protocol receipt and delivery state"
)]
fn matching_overlap_merges_and_conflicting_overlap_has_no_effect() -> Result<(), Error> {
    let mut body = [0; 8];
    let mut coverage = [0; 1];
    let mut owner = packed::<1>(8, &mut body, &mut coverage)?;
    let mut ack = [0; ACK_HEADER_LEN + 4 * ACK_ENTRY_LEN];
    assert_eq!(
        receive(&mut owner, MonoInstant(1), fragment(1, 1, 4, &FRAME[4..]))?,
        Receive::Partial
    );
    assert_eq!(
        receive(&mut owner, MonoInstant(2), fragment(1, 2, 3, &[0, 0])),
        Err(Error::Malformed)
    );
    let wrong_total = Fragment {
        total: 7,
        ..fragment(1, 3, 3, &FRAME[3..6])
    };
    assert_eq!(
        receive(&mut owner, MonoInstant(3), wrong_total),
        Err(Error::Malformed)
    );
    assert_eq!(
        receive(&mut owner, MonoInstant(4), fragment(9, 4, 0, &FRAME)),
        Err(Error::Capacity)
    );
    assert_eq!(
        receive(&mut owner, MonoInstant(5), fragment(1, 5, 0, &FRAME[..6]))?,
        Receive::Complete
    );
    assert_eq!(owner.frame(), Some(FRAME.as_slice()));
    assert_eq!(
        receive(&mut owner, MonoInstant(6), fragment(1, 6, 3, &FRAME[3..]))?,
        Receive::Duplicate
    );
    owner.clear_completed();
    assert_eq!(owner.frame(), None);
    assert_eq!(
        receive(&mut owner, MonoInstant(7), fragment(1, 7, 0, &FRAME[..1]))?,
        Receive::Duplicate
    );
    assert_eq!(
        owner.poll_ack(MonoInstant(10), &mut ack, |wire| {
            assert_eq!(wire[4..8], 4_u32.to_be_bytes());
            assert!(acknowledgements(wire)?.eq([
                (9, [1; 16]),
                (5, [5; 16]),
                (4, [6; 16]),
                (3, [7; 16])
            ]));
            Ok(())
        })?,
        Some(())
    );
    assert_eq!(owner.ack_deadline(), None);
    assert_eq!(
        receive(&mut owner, MonoInstant(11), fragment(9, 8, 0, &FRAME[..2]))?,
        Receive::Partial
    );
    assert_eq!(
        receive(&mut owner, MonoInstant(12), fragment(1, 9, 3, &FRAME[3..])),
        Err(Error::Replay)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert retirement and caller buffer extents"
)]
fn expired_or_dropped_storage_is_released() -> Result<(), Error> {
    let mut body = [0xa5; 16];
    let mut coverage = [0xff; 2];
    {
        let mut owner = packed::<1>(8, &mut body, &mut coverage)?;
        assert_eq!(
            receive(&mut owner, MonoInstant(10), fragment(1, 1, 4, &FRAME[4..]))?,
            Receive::Partial
        );
        let expires = MonoInstant(10).after(REASSEMBLY_LIFETIME)?;
        assert_eq!(owner.expiry(), Some(expires));
        assert_eq!(owner.ack_deadline(), Some(MonoInstant(10)));
        assert!(!owner.expire(MonoInstant(expires.0 - 1)));
        assert!(owner.expire(expires));
        assert_eq!(owner.expiry(), None);
        assert_eq!(owner.ack_deadline(), None);
        assert_eq!(
            receive(&mut owner, expires, fragment(2, 2, 0, &FRAME))?,
            Receive::Complete
        );
        assert_eq!(owner.expiry(), None);
    }
    assert_eq!(body[..8], [0; 8]);
    assert_eq!(body[8..], [0xa5; 8]);
    assert_eq!(coverage, [0, 0xff]);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert queue pressure and actual cumulative admission"
)]
fn lower_rejection_does_not_commit_acknowledgements() -> Result<(), Error> {
    let mut body = [0; 8];
    let mut coverage = [0; 1];
    let mut owner = packed::<1>(8, &mut body, &mut coverage)?;
    assert_eq!(
        receive(&mut owner, MonoInstant(1), fragment(1, 1, 0, &FRAME[..4]))?,
        Receive::Partial
    );
    for attempt in 2..=ACK_CAPACITY as u8 {
        assert_eq!(
            receive(
                &mut owner,
                MonoInstant(u64::from(attempt)),
                fragment(1, attempt, 0, &FRAME[..4])
            )?,
            Receive::Duplicate
        );
    }
    let mut ack = [0; ACK_HEADER_LEN + 2 * ACK_ENTRY_LEN];
    let refused = owner.poll_ack(MonoInstant(40), &mut ack, |wire| {
        assert_eq!(wire[4..8], 2_u32.to_be_bytes());
        assert!(acknowledgements(wire)?.eq([(39, [1; 16]), (38, [2; 16])]));
        Err::<(), Error>(Error::WouldBlock)
    });
    assert_eq!(refused, Err(Error::WouldBlock));
    assert_eq!(owner.ack_deadline(), Some(MonoInstant(1)));
    assert_eq!(
        receive(&mut owner, MonoInstant(41), fragment(1, 50, 4, &FRAME[4..]))?,
        Receive::Complete
    );
    assert_eq!(owner.frame(), Some(FRAME.as_slice()));
    assert_eq!(owner.ack_deadline(), Some(MonoInstant(2)));
    assert_eq!(
        owner.poll_ack(MonoInstant(42), &mut ack, |wire| {
            assert_eq!(wire[4..8], 2_u32.to_be_bytes());
            assert!(acknowledgements(wire)?.eq([(40, [2; 16]), (39, [3; 16])]));
            Ok(())
        })?,
        Some(())
    );
    assert_eq!(owner.ack_deadline(), Some(MonoInstant(4)));
    assert_eq!(
        owner.poll_ack(MonoInstant(45), &mut ack, |wire| {
            assert_eq!(wire[4..8], 4_u32.to_be_bytes());
            assert!(acknowledgements(wire)?.eq([(41, [4; 16]), (40, [5; 16])]));
            Ok(())
        })?,
        Some(())
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert final invalid bytes cannot yield an ACK"
)]
fn malformed_extent_and_nested_box_never_complete() -> Result<(), Error> {
    let mut body = [0; 8];
    let mut coverage = [0; 1];
    let mut owner = packed::<1>(8, &mut body, &mut coverage)?;
    let mut invalid = FRAME;
    invalid[1] = 9;
    assert!(receive(&mut owner, MonoInstant(5), fragment(1, 1, 0, &invalid)).is_err());
    invalid[1] = 8;
    invalid[2..4].copy_from_slice(&mt::TRANSPORT_RELIABILITY_BOX.value().to_be_bytes());
    assert_eq!(
        receive(&mut owner, MonoInstant(6), fragment(1, 2, 0, &invalid)),
        Err(Error::Unsupported)
    );
    assert_eq!(owner.frame(), None);
    assert_eq!(owner.ack_deadline(), None);
    assert_eq!(
        receive(&mut owner, MonoInstant(7), fragment(2, 3, 0, &FRAME))?,
        Receive::Complete
    );
    owner.clear();
    assert_eq!(owner.frame(), None);
    assert_eq!(owner.ack_deadline(), None);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert independent lane state, FIFO delivery and shared ACK causes"
)]
fn interleaved_originals_complete_in_fifo_order() -> Result<(), Error> {
    let mut body = [0xff; 18];
    let mut coverage = [0xff; 4];
    let mut owner = packed::<2>(9, &mut body, &mut coverage)?;
    let mut checked = 0;
    assert_eq!(
        owner.receive(MonoInstant(1), fragment(1, 1, 0, &FRAME[..5]), |_, _| {
            checked += 1;
            Err(Error::Conflict)
        })?,
        Receive::Partial
    );
    assert_eq!(
        receive(&mut owner, MonoInstant(2), fragment(2, 2, 4, &SECOND[4..]))?,
        Receive::Partial
    );
    assert_eq!(
        receive(&mut owner, MonoInstant(2), fragment(3, 3, 0, &FRAME)),
        Err(Error::Capacity)
    );
    assert_eq!(
        owner.receive(
            MonoInstant(3),
            fragment(2, 4, 0, &SECOND[..5]),
            |frame, _| {
                checked += 1;
                assert_eq!(frame.payload(), &SECOND[4..]);
                Ok(())
            }
        )?,
        Receive::Complete
    );
    assert_eq!(
        owner.receive(
            MonoInstant(3),
            fragment(1, 5, 4, &FRAME[4..]),
            |frame, _| {
                checked += 1;
                assert_eq!(frame.payload(), &FRAME[4..]);
                Ok(())
            }
        )?,
        Receive::Complete
    );
    assert_eq!(
        owner.receive(MonoInstant(3), fragment(2, 6, 4, &SECOND[4..]), |_, _| {
            checked += 1;
            Err(Error::Conflict)
        })?,
        Receive::Duplicate
    );
    assert_eq!(checked, 2);
    assert_eq!(owner.frame(), Some(SECOND.as_slice()));
    owner.clear_completed();
    assert_eq!(owner.frame(), Some(FRAME.as_slice()));
    owner.clear_completed();
    assert_eq!(owner.frame(), None);
    let mut ack = [0; ACK_HEADER_LEN + 5 * ACK_ENTRY_LEN];
    assert_eq!(
        owner.poll_ack(MonoInstant(5), &mut ack, |wire| {
            assert!(acknowledgements(wire)?.eq([
                (4, [1; 16]),
                (3, [2; 16]),
                (2, [4; 16]),
                (2, [5; 16]),
                (2, [6; 16])
            ]));
            Ok(())
        })?,
        Some(())
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert expiry, failed admission and bounded retired ID protection"
)]
fn lanes_expire_independently_and_retain_separate_retired_ids() -> Result<(), Error> {
    let mut body = [0xff; 16];
    let mut coverage = [0xff; 2];
    let mut owner = packed::<2>(8, &mut body, &mut coverage)?;
    assert_eq!(
        receive(&mut owner, MonoInstant(10), fragment(1, 1, 0, &FRAME[..4]))?,
        Receive::Partial
    );
    assert_eq!(
        receive(&mut owner, MonoInstant(11), fragment(2, 2, 4, &SECOND[4..]))?,
        Receive::Partial
    );
    let deadline = MonoInstant(10).after(REASSEMBLY_LIFETIME)?;
    assert!(owner.expire(deadline));
    assert_eq!(owner.expiry(), Some(MonoInstant(deadline.0 + 1)));
    assert_eq!(
        receive(&mut owner, deadline, fragment(2, 3, 0, &SECOND[..4]))?,
        Receive::Complete
    );
    assert_eq!(
        owner.receive(deadline, fragment(3, 4, 0, &FRAME), |_, _| Err(
            Error::Unsupported
        )),
        Err(Error::Unsupported)
    );
    assert_eq!(owner.frame(), Some(SECOND.as_slice()));
    owner.clear_completed();
    assert_eq!(
        receive(&mut owner, deadline, fragment(3, 5, 0, &FRAME))?,
        Receive::Complete
    );
    owner.clear_completed();
    assert_eq!(
        receive(
            &mut owner,
            MonoInstant(deadline.0 + 1),
            fragment(4, 6, 0, &FRAME[..4])
        )?,
        Receive::Partial
    );
    assert_eq!(
        receive(
            &mut owner,
            MonoInstant(deadline.0 + 2),
            fragment(5, 7, 4, &FRAME[4..])
        )?,
        Receive::Partial
    );
    assert_eq!(
        receive(
            &mut owner,
            MonoInstant(deadline.0 + 3),
            fragment(2, 8, 0, &SECOND)
        ),
        Err(Error::Replay)
    );
    assert_eq!(
        receive(
            &mut owner,
            MonoInstant(deadline.0 + 3),
            fragment(3, 9, 0, &FRAME)
        ),
        Err(Error::Replay)
    );
    assert_eq!(owner.frame(), None);
    let mut ack = [0; ACK_HEADER_LEN + 5 * ACK_ENTRY_LEN];
    assert_eq!(
        owner.poll_ack(MonoInstant(deadline.0 + 3), &mut ack, |wire| {
            assert!(
                acknowledgements(wire)?
                    .map(|(_, id)| id)
                    .eq([[3; 16], [5; 16], [6; 16], [7; 16]])
            );
            Ok(())
        })?,
        Some(())
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert large original delivery through official fragment encoding"
)]
fn one_wide_lane_receives_an_fs_sized_dv_box() -> Result<(), Error> {
    use crate::{
        PeerId,
        direct::RoutingFrame,
        direct_fragment_send::{Progress, Sender},
        dv::{BOX_PREFIX, BoxHeader, MAX_HOPS},
    };
    use core::num::NonZeroU16;
    use gnunet_crypto::Entropy;
    use gnunet_types::RelativeTime;

    struct EntropyFixture;
    impl Entropy for EntropyFixture {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
            output.fill(42);
            Ok(())
        }
    }

    const WIDE: usize = 35 * 1024;
    const SMALL: usize = 4096;
    const BOX: usize = 1536;
    let mut ordinary = [0; SMALL];
    let mut ordinary_map = [0; SMALL.div_ceil(8)];
    let mut wide = [0; WIDE];
    let mut wide_map = [0; WIDE.div_ceil(8)];
    let mut owner = Reassembly::new(
        WIDE,
        [
            FragmentLane::new(&mut wide, &mut wide_map)?,
            FragmentLane::new(&mut ordinary, &mut ordinary_map)?,
        ],
    )?;
    let now = MonoInstant(1);
    assert_eq!(
        receive(&mut owner, now, fragment(1, 1, 0, &FRAME[..4]))?,
        Receive::Partial
    );

    // TRANSPORT handles an opaque canonical DV frame. End-to-end opening
    // belongs to DV and is outside this reassembly fixture.
    let mut message = [0; WIDE];
    let size = BoxHeader {
        without_fc: false,
        encapsulation: [1; 32],
        nonce: [2; 24],
        mac: [3; 16],
    }
    .encode(
        &[PeerId([4; 32]); MAX_HOPS],
        &[0x5a; WIDE - BOX_PREFIX - 32 * MAX_HOPS],
        &mut message,
    )?;
    assert_eq!(size, WIDE);
    let mtu = NonZeroU16::new(BOX as u16).ok_or(Error::InvalidInput)?;
    let mut sender = Sender::new(mtu, RelativeTime::from_micros(1_000_000))?;
    let mut scratch = [0; BOX];
    let mut entropy = EntropyFixture;
    let mut completed = false;
    let maximum_body = BOX - crate::p2p::FRAGMENT_HEADER_LEN;
    for _ in 0..WIDE.div_ceil(maximum_body) {
        let progress = sender.send(now, &message, &mut scratch, &mut entropy, |wire, _| {
            assert!(wire.len() <= BOX);
            owner.receive(now, Fragment::decode(wire)?, |_, raw| {
                assert!(matches!(RoutingFrame::decode(raw)?, RoutingFrame::Box(_)));
                Ok(())
            })
        })?;
        if let Progress::Complete(received) = progress {
            assert_eq!(received, Receive::Complete);
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert_eq!(
        receive(&mut owner, now, fragment(1, 2, 4, &FRAME[4..]))?,
        Receive::Complete
    );
    assert_eq!(owner.frame(), Some(message.as_slice()));
    owner.clear_completed();
    assert_eq!(owner.frame(), Some(FRAME.as_slice()));
    Ok(())
}
