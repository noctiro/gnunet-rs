//! One pure transport model of the actual full/delta protocol. The model's
//! explicit write/close callbacks are not original-C/native interoperability.
#![cfg(feature = "zlib")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "One focused pure protocol model asserts immutable original scopes and actual algorithm output"
)]
use gnunet_setu::{
    set::{Limits as SetLimits, Set},
    union::{Limits, Phase, ResultEntry, Union},
    wire::{Abi, Element, Options, Peer, Status},
    zlib::Zlib,
};
use gnunet_types::Error;
fn set(range: core::ops::Range<u32>, abi: Abi) -> Result<Set, Error> {
    let mut set = Set::new(SetLimits::default(), abi)?;
    for n in range {
        set.add(Element {
            kind: 7,
            data: &n.to_be_bytes(),
        })?;
    }
    Ok(set)
}
fn drain(union: &mut Union, reports: &mut Vec<ResultEntry>) {
    while let Some(result) = union.next_result() {
        reports.push(result);
    }
}
fn shuttle(source: &mut Union, target: &mut Union, codec: &mut Zlib) -> Result<bool, Error> {
    let Some(output) = source.outbound() else {
        return Ok(false);
    };
    let token = output.transmission;
    let bytes = output.bytes.to_vec();
    // This is the model's actual complete local write. Processing at the
    // destination still requires its distinct receive call below.
    source.sent(&token)?;
    target.receive(&bytes, codec)?;
    Ok(true)
}
fn run(full: bool, abi: Abi) -> Result<(), Error> {
    let mut left_set = set(0..64, abi)?;
    let right_set = set(32..96, abi)?;
    let options = Options {
        force_delta: u8::from(!full),
        force_full: u8::from(full),
        symmetric: 1,
        ..Options::default()
    };
    let snapshot = left_set.snapshot()?;
    let generation = snapshot.generation();
    assert!(left_set.remove(Element {
        kind: 7,
        data: &0u32.to_be_bytes()
    })?);
    assert!(left_set.add(Element {
        kind: 7,
        data: &1000u32.to_be_bytes()
    })?);
    assert_eq!(snapshot.len(), 64);
    assert_eq!(snapshot.generation(), generation);
    let mut left = Union::initiate(snapshot, options, Limits::default(), [3; 64], None)?;
    let output = left.outbound().ok_or(Error::NotReady)?;
    let first_token = output.transmission;
    let first = output.bytes.to_vec();
    let again = left.outbound().ok_or(Error::NotReady)?;
    assert_eq!(again.transmission, first_token);
    assert_eq!(again.bytes, first);
    let Peer::Operation { count, .. } = Peer::decode(&first, abi)? else {
        return Err(Error::Malformed);
    };
    left.sent(&first_token)?;
    let mut right = Union::accept(right_set.snapshot()?, options, Limits::default(), count)?;
    assert_eq!(right.sent(&first_token), Err(Error::Stale));
    let mut left_codec = Zlib::new();
    let mut right_codec = Zlib::new();
    let (mut lr, mut rr) = (Vec::new(), Vec::new());
    let mut retired = false;
    for _ in 0..100_000 {
        left.advance(&mut left_codec, 8)?;
        right.advance(&mut right_codec, 8)?;
        let a = shuttle(&mut left, &mut right, &mut right_codec)?;
        let b = shuttle(&mut right, &mut left, &mut left_codec)?;
        drain(&mut left, &mut lr);
        drain(&mut right, &mut rr);
        assert!(!lr.iter().chain(rr.iter()).any(|r| r.status == Status::Done));
        if left.close_needed() || right.close_needed() {
            assert_ne!(left.phase(), Phase::Failed);
            assert_ne!(right.phase(), Phase::Failed);
            // Only the model's actual physical retirement now permits terminal
            // callbacks. A queued OVER or local send cannot fabricate this.
            left.retired();
            right.retired();
            retired = true;
            break;
        }
        if !a && !b && left.phase() == Phase::Failed {
            return Err(Error::NotReady);
        }
    }
    assert!(retired);
    drain(&mut left, &mut lr);
    drain(&mut right, &mut rr);
    for reports in [&lr, &rr] {
        assert_eq!(
            reports
                .iter()
                .filter(|r| r.status == Status::AddLocal)
                .count(),
            32
        );
        assert_eq!(
            reports.iter().filter(|r| r.status == Status::Done).count(),
            1
        );
        assert!(!reports.iter().any(|r| r.status == Status::Failure));
        assert_eq!(reports.last().ok_or(Error::NotReady)?.current_size, 96);
    }
    let mut local: Vec<u32> = lr
        .iter()
        .filter(|r| r.status == Status::AddLocal)
        .map(|r| {
            let data = r.element.as_ref().ok_or(Error::NotFound)?.borrowed().data;
            Ok(u32::from_be_bytes(
                data.try_into().map_err(|_| Error::Malformed)?,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    local.sort_unstable();
    assert_eq!(local, (64..96).collect::<Vec<_>>());
    if !full {
        assert_eq!(
            lr.iter().filter(|r| r.status == Status::AddRemote).count(),
            32
        );
        assert_eq!(
            rr.iter().filter(|r| r.status == Status::AddRemote).count(),
            32
        );
        assert!(left.rounds() > 0 && right.rounds() > 0);
    }
    Ok(())
}
#[test]
fn immutable_snapshots_full_delta_and_original_retirement() -> Result<(), Error> {
    let abi = Abi::native();
    assert_eq!(Abi { align64: 8, ..abi }.accept_len(), 56);
    assert_eq!(Abi { align64: 8, ..abi }.result_len(), 24);
    run(false, abi)?;
    run(true, abi)?;
    let mut cancelled = Union::initiate(
        set(0..1, abi)?.snapshot()?,
        Options::default(),
        Limits::default(),
        [0; 64],
        None,
    )?;
    let output = cancelled.outbound().ok_or(Error::NotReady)?;
    let token = output.transmission;
    let bytes = output.bytes.to_vec();
    cancelled.cancel();
    assert!(cancelled.close_needed());
    let original = cancelled.outbound().ok_or(Error::NotReady)?;
    assert_eq!(original.transmission, token);
    assert_eq!(original.bytes, bytes);
    assert!(cancelled.next_result().is_none());
    cancelled.retired();
    assert!(cancelled.outbound().is_none());
    assert!(cancelled.next_result().is_none());
    Ok(())
}

#[test]
fn symmetric_full_return_reports_only_proven_missing_after_queue_credit() -> Result<(), Error> {
    let abi = Abi::native();
    for symmetric in [0, 1] {
        let local = set(0..2, abi)?;
        let options = Options {
            force_full: 1,
            symmetric,
            ..Options::default()
        };
        let limits = Limits {
            output_frames: 1,
            ..Limits::default()
        };
        let mut union = Union::accept(local.snapshot()?, options, limits, 2)?;
        let mut codec = Zlib::new();
        union.advance(&mut codec, 8)?;
        let strata = union.outbound().ok_or(Error::NotReady)?;
        let ticket = strata.transmission;
        assert!(matches!(
            Peer::decode(strata.bytes, abi)?,
            Peer::Strata { .. }
        ));
        union.sent(&ticket)?;
        let mut frame = [0; 64];
        let n = Peer::Full {
            request: false,
            remote_difference: 1,
            remote_size: 2,
            local_difference: 1,
            padding: &[0; 16],
        }
        .encode(abi, &mut frame)?;
        union.receive(&frame[..n], &mut codec)?;
        for value in [0u32, 2] {
            let bytes = value.to_be_bytes();
            let n = Peer::FullElement(Element {
                kind: 7,
                data: &bytes,
            })
            .encode(abi, &mut frame)?;
            union.receive(&frame[..n], &mut codec)?;
        }
        let local_result = union.next_result().ok_or(Error::NotReady)?;
        assert_eq!(local_result.status, Status::AddLocal);
        assert_eq!(
            local_result.element.ok_or(Error::NotReady)?.borrowed().data,
            &2u32.to_be_bytes()
        );
        assert!(union.next_result().is_none());
        let n = Peer::FullDone.encode(abi, &mut frame)?;
        union.receive(&frame[..n], &mut codec)?;
        union.advance(&mut codec, 8)?;
        let output = union.outbound().ok_or(Error::NotReady)?;
        let ticket = output.transmission;
        let bytes = output.bytes.to_vec();
        let Peer::FullElement(sent) = Peer::decode(&bytes, abi)? else {
            return Err(Error::Malformed);
        };
        assert_eq!(sent.data, &1u32.to_be_bytes()); // Common0 was not sent again.
        if symmetric != 0 {
            let remote = union.next_result().ok_or(Error::NotReady)?;
            assert_eq!(remote.status, Status::AddRemote);
            assert_eq!(
                remote.element.ok_or(Error::NotReady)?.borrowed().data,
                &1u32.to_be_bytes()
            );
        }
        assert!(union.next_result().is_none()); // Neither queueing nor a lease is DONE.
        let again = union.outbound().ok_or(Error::NotReady)?;
        assert_eq!(again.transmission, ticket);
        assert_eq!(again.bytes, bytes);
        assert_eq!(union.advance(&mut codec, 8)?, 0); // FullDone still lacks queue credit.
        assert!(union.next_result().is_none()); // Cursor does not duplicate the notification.
        union.sent(&ticket)?;
        union.advance(&mut codec, 8)?;
        let done = union.outbound().ok_or(Error::NotReady)?;
        let done_ticket = done.transmission;
        assert!(matches!(Peer::decode(done.bytes, abi)?, Peer::FullDone));
        union.sent(&done_ticket)?;
        let n = Peer::Over.encode(abi, &mut frame)?;
        union.receive(&frame[..n], &mut codec)?;
        assert!(union.close_needed());
        assert!(union.next_result().is_none());
        union.retired(); // Explicit pure source-retirement receipt, never native evidence.
        assert_eq!(
            union.next_result().ok_or(Error::NotReady)?.status,
            Status::Done
        );
        assert!(union.next_result().is_none());
    }
    Ok(())
}
