//! Finite resource and old-result authority tests; no peer/socket is started.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Public owner tests compare finite resource/epoch state and callback authority."
)]
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{
        ConnectionEpoch, GetId, Outbound, OutboundKind, StatisticsHandle as Core, WatchId,
    },
};
use gnunet_types::{AbsoluteTime, Error};
const END: &[u8] = b"\0\x04\0\xab";
fn selector(name: &[u8]) -> Selector<'_> {
    Selector {
        subsystem: b"s",
        name,
    }
}
fn send<'owner, const A: usize, const N: usize, const W: usize, const WW: usize, const T: usize>(
    h: &mut Core<'owner, A, N, W, WW, T>,
    epoch: ConnectionEpoch<'owner>,
) -> Result<(Outbound<'owner>, Vec<u8>), Error> {
    let mut output = [0xa5; 128];
    let frame = h.next_request(epoch, &mut output)?.ok_or(Error::NotReady)?;
    h.on_frame_written(epoch, frame.transmit)?;
    Ok((frame, output[..frame.len].to_vec()))
}
// Scenario equivalence compares wire bytes and diagnostic slot/generation
// values. Branded capabilities from independent owners must never compare equal.
#[derive(Debug, PartialEq, Eq)]
struct Replay {
    gets: Vec<gnunet_types::GenerationalId>,
    watches: Vec<gnunet_types::GenerationalId>,
    frames: Vec<Vec<u8>>,
}

fn small_name_replay(refuse: bool) -> Result<Replay, Error> {
    type H<'owner> = Core<'owner, 5, 8, 2, 4, 2>;
    let mut instance = gnunet_client::statistics_handle::Instance::new();
    let mut h = H::new(&mut instance, b"s", true)?.ok_or(Error::Unavailable)?;
    let get = h.get(selector(b"g"))?;
    h.set(b"a", 5, true)?;
    let watch = h.watch(selector(b"w"))?;
    let mut names = [0xa5; 8];
    assert_eq!(h.watch_selector(watch, &mut names)?.name, b"w");
    if refuse {
        // s+NUL+6 name bytes+NUL exceeds this explicitly selected N=8.
        let too_long = selector(b"123456");
        assert_eq!(h.get(too_long), Err(Error::Capacity));
        assert_eq!(h.watch(too_long), Err(Error::Capacity));
        assert_eq!(h.set(too_long.name, 99, false), Err(Error::Capacity));
        assert_eq!(h.pending_actions(), 3);
        assert_eq!(h.live_watches(), 1);
        assert!(h.get_callbacks_enabled(get));
        assert_eq!(h.pending_completions(), 0);
        assert_eq!(h.connection_epoch(), None);
        assert_eq!(h.watch_selector(watch, &mut names)?.name, b"w");
    }
    // A valid second GET must still obtain the remaining terminal reservation.
    let followup = h.get(selector(b"h"))?;
    let second = h.watch(selector(b"y"))?;
    let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let mut frames = Vec::new();
    let (out, bytes) = send(&mut h, epoch)?;
    assert_eq!(out.kind, OutboundKind::Get(get));
    assert_eq!(bytes, b"\0\x08\0\xa9s\0g\0");
    frames.push(bytes);
    h.receive(epoch, END, AbsoluteTime::from_micros(1))?;
    let done = h.take_completion().ok_or(Error::NotReady)?;
    assert_eq!(done.get, get);
    assert_eq!(done.result, Ok(()));
    let (_out, bytes) = send(&mut h, epoch)?;
    assert_eq!(bytes, b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x05s\0a\0");
    frames.push(bytes);
    let (out, bytes) = send(&mut h, epoch)?;
    assert_eq!(out.kind, OutboundKind::Get(followup));
    assert_eq!(bytes, b"\0\x08\0\xa9s\0h\0");
    frames.push(bytes);
    h.receive(epoch, END, AbsoluteTime::from_micros(2))?;
    let done = h.take_completion().ok_or(Error::NotReady)?;
    assert_eq!(done.get, followup);
    assert_eq!(done.result, Ok(()));
    for (wire_id, logical, name) in [(0, watch, b"w".as_slice()), (1, second, b"y".as_slice())] {
        let (out, bytes) = send(&mut h, epoch)?;
        assert_eq!(
            out.kind,
            OutboundKind::Watch {
                wire_id,
                logical: Some(logical)
            }
        );
        assert_eq!(&bytes[4..], [b"s\0".as_slice(), name, b"\0"].concat());
        frames.push(bytes);
    }
    Ok(Replay {
        gets: vec![get.resource_id(), followup.resource_id()],
        watches: vec![watch.resource_id(), second.resource_id()],
        frames,
    })
}
#[test]
fn small_name_refusals_preserve_original_ids_fifo_value_and_persistence() -> Result<(), Error> {
    assert_eq!(small_name_replay(true)?, small_name_replay(false)?);
    Ok(())
}

fn logical_watch_replay(refuse: bool) -> Result<Replay, Error> {
    type H<'owner> = Core<'owner, 4, 16, 1, 4, 2>;
    let mut instance = gnunet_client::statistics_handle::Instance::new();
    let mut h = H::new(&mut instance, b"s", true)?.ok_or(Error::Unavailable)?;
    let old = h.watch(selector(b"old"))?;
    if refuse {
        assert_eq!(h.watch(selector(b"second")), Err(Error::Capacity));
        assert_eq!(h.live_watches(), 1);
        assert_eq!(h.pending_actions(), 1);
        let mut names = [0xa5; 16];
        assert_eq!(h.watch_selector(old, &mut names)?.name, b"old");
    }
    h.watch_cancel(old)?;
    let new = h.watch(selector(b"new"))?;
    assert_eq!(old.resource_id().index, new.resource_id().index);
    assert_ne!(old, new);
    assert!(h.watch_cancel(old).is_err());
    assert!(h.owns_watch(new));
    let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (out, bytes) = send(&mut h, epoch)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 0,
            logical: Some(new)
        }
    );
    assert_eq!(bytes, b"\0\x0a\0\xacs\0new\0");
    Ok(Replay {
        gets: Vec::new(),
        watches: vec![old.resource_id(), new.resource_id()],
        frames: vec![bytes],
    })
}
#[test]
fn full_logical_watch_refusal_consumes_no_slot_generation_or_queued_copy() -> Result<(), Error> {
    assert_eq!(logical_watch_replay(true)?, logical_watch_replay(false)?);
    Ok(())
}

fn wire_limit_replay(refuse: bool) -> Result<Replay, Error> {
    type H<'owner> = Core<'owner, 4, 16, 2, 1, 2>;
    let mut instance = gnunet_client::statistics_handle::Instance::new();
    let mut h = H::new(&mut instance, b"s", true)?.ok_or(Error::Unavailable)?;
    let old = h.watch(selector(b"old"))?;
    let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (first, bytes) = send(&mut h, epoch)?;
    assert_eq!(
        first.kind,
        OutboundKind::Watch {
            wire_id: 0,
            logical: Some(old)
        }
    );
    let mut frames = vec![bytes];
    if refuse {
        assert_eq!(h.watch(selector(b"new")), Err(Error::Capacity));
        assert_eq!(h.pending_actions(), 0);
        assert_eq!(h.live_watches(), 1);
    }
    h.watch_cancel(old)?;
    if refuse {
        // Local cancellation frees W capacity, never this connection's issued WID.
        assert_eq!(h.watch(selector(b"new")), Err(Error::Capacity));
        assert_eq!(h.live_watches(), 0);
        assert_eq!(h.pending_actions(), 0);
    }
    assert!(h.next_request(epoch, &mut [0xa5; 128])?.is_none());
    h.connection_lost(epoch, Error::Io, AbsoluteTime::from_micros(1))?;
    let new = h.watch(selector(b"new"))?;
    let fresh = h.begin_connection(AbsoluteTime::from_micros(1001))?;
    let (out, bytes) = send(&mut h, fresh)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 0,
            logical: Some(new)
        }
    );
    assert_eq!(bytes, b"\0\x0a\0\xacs\0new\0");
    frames.push(bytes);
    Ok(Replay {
        gets: Vec::new(),
        watches: vec![old.resource_id(), new.resource_id()],
        frames,
    })
}
#[test]
fn exhausted_wire_ids_refuse_before_state_changes_and_reset_only_on_new_connection()
-> Result<(), Error> {
    assert_eq!(wire_limit_replay(true)?, wire_limit_replay(false)?);
    Ok(())
}

type Owner<'owner> = Core<'owner, 8, 32, 2, 4, 4>;
#[derive(Debug, PartialEq, Eq)]
struct State<'owner> {
    epoch: Option<ConnectionEpoch<'owner>>,
    current: Option<GetId<'owner>>,
    pending: usize,
    terminals: usize,
    watches: usize,
    transmit: usize,
    mq_length: usize,
    watch_name: Vec<u8>,
}
fn state<'owner>(h: &Owner<'owner>, watch: WatchId<'owner>) -> Result<State<'owner>, Error> {
    let mut names = [0xa5; 32];
    let watch_name = h.watch_selector(watch, &mut names)?.name.to_vec();
    Ok(State {
        epoch: h.connection_epoch(),
        current: h.active_get(),
        pending: h.pending_actions(),
        terminals: h.pending_completions(),
        watches: h.live_watches(),
        transmit: h.transmit_count(),
        mq_length: h.mq_nontransmitted_length(),
        watch_name,
    })
}
#[test]
fn stale_epoch_and_transmit_completions_cannot_change_new_original_queue() -> Result<(), Error> {
    let mut instance = gnunet_client::statistics_handle::Instance::new();
    let mut h = Owner::new(&mut instance, b"s", true)?.ok_or(Error::Unavailable)?;
    let watch = h.watch(selector(b"watch"))?;
    h.set(b"old", 1, true)?;
    let old_epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (old_tx, _) = send(&mut h, old_epoch)?;
    send(&mut h, old_epoch)?;
    h.connection_lost(old_epoch, Error::Io, AbsoluteTime::from_micros(1))?;
    h.set(b"pending", 9, true)?;
    let get = h.get(selector(b"query"))?;
    let epoch = h.begin_connection(AbsoluteTime::from_micros(1001))?;
    send(&mut h, epoch)?;
    let mut buffer = [0xa5; 128];
    let current = h.next_request(epoch, &mut buffer)?.ok_or(Error::NotReady)?;
    assert_eq!(current.kind, OutboundKind::Get(get));
    h.set(b"tail", 17, false)?;
    let expected = state(&h, watch)?;
    assert_eq!(
        h.on_first_send_attempt(old_epoch, old_tx.transmit),
        Err(Error::StaleGeneration)
    );
    assert_eq!(state(&h, watch)?, expected);
    assert_eq!(
        h.on_frame_written(old_epoch, old_tx.transmit),
        Err(Error::StaleGeneration)
    );
    assert_eq!(state(&h, watch)?, expected);
    assert_eq!(
        h.connection_lost(old_epoch, Error::Io, AbsoluteTime::from_micros(1001)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(state(&h, watch)?, expected);
    assert_eq!(
        h.receive(old_epoch, END, AbsoluteTime::from_micros(1001)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(state(&h, watch)?, expected);
    let mut scratch = [0xa5; 128];
    assert_eq!(
        h.next_request(old_epoch, &mut scratch),
        Err(Error::StaleGeneration)
    );
    assert_eq!(scratch, [0xa5; 128]);
    assert_eq!(state(&h, watch)?, expected);
    assert!(h.on_first_send_attempt(epoch, old_tx.transmit).is_err());
    assert_eq!(state(&h, watch)?, expected);
    assert!(h.on_frame_written(epoch, old_tx.transmit).is_err());
    assert_eq!(state(&h, watch)?, expected);
    h.on_frame_written(epoch, current.transmit)?;
    h.receive(epoch, END, AbsoluteTime::from_micros(1002))?;
    let done = h.take_completion().ok_or(Error::NotReady)?;
    assert_eq!(done.get, get);
    assert_eq!(done.result, Ok(()));
    let (out, _) = send(&mut h, epoch)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 0,
            logical: Some(watch)
        }
    );
    let (_, bytes) = send(&mut h, epoch)?;
    assert_eq!(&bytes[8..16], &17_u64.to_be_bytes());
    assert_eq!(&bytes[16..], b"s\0tail\0");
    h.begin_destroy(false, AbsoluteTime::from_micros(2001))?;
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.unconfirmed_mutations, 3);
    assert_eq!(report.unconfirmed_persistent_mutations, 2);
    assert!(h.is_closed());
    let before = (
        h.connection_epoch(),
        h.pending_actions(),
        h.pending_completions(),
        h.transmit_count(),
    );
    assert!(h.on_first_send_attempt(epoch, current.transmit).is_err());
    assert!(h.on_frame_written(epoch, current.transmit).is_err());
    assert!(
        h.connection_lost(epoch, Error::Io, AbsoluteTime::from_micros(999999))
            .is_err()
    );
    assert!(
        h.receive(epoch, END, AbsoluteTime::from_micros(999999))
            .is_err()
    );
    h.tick(AbsoluteTime::from_micros(u64::MAX))?;
    assert_eq!(
        (
            h.connection_epoch(),
            h.pending_actions(),
            h.pending_completions(),
            h.transmit_count()
        ),
        before
    );
    assert!(h.take_completion().is_none());
    assert!(h.take_destroy_report().is_none());
    Ok(())
}
