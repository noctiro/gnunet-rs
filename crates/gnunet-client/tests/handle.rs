//! High-level owner semantics, independent literals and original C action ordering.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible tests assert original queue/callback ownership and independently specified official frames"
)]
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{
        ConnectionEpoch, DestroyOutcome, GetFlow, Inbound, Outbound, OutboundKind, SetterAdmission,
        StatisticsHandle,
    },
};
use gnunet_types::{AbsoluteTime, Error};

type Handle<'owner> = StatisticsHandle<'owner, 8, 64, 4, 16, 8>;
fn new<'owner>(
    instance: &'owner mut gnunet_client::statistics_handle::Instance,
) -> Result<Handle<'owner>, Error> {
    Handle::new(instance, b"s", true)?.ok_or(Error::Unavailable)
}
fn selector(name: &[u8]) -> Selector<'_> {
    Selector {
        subsystem: b"s",
        name,
    }
}
fn take<'owner, const A: usize, const N: usize, const W: usize, const WW: usize, const T: usize>(
    h: &mut StatisticsHandle<'owner, A, N, W, WW, T>,
    e: ConnectionEpoch<'owner>,
) -> Result<(Outbound<'owner>, Vec<u8>), Error> {
    let mut bytes = [0; 128];
    let out = h.next_request(e, &mut bytes)?.ok_or(Error::NotReady)?;
    Ok((out, bytes[..out.len].to_vec()))
}
fn sent<'owner, const A: usize, const N: usize, const W: usize, const WW: usize, const T: usize>(
    h: &mut StatisticsHandle<'owner, A, N, W, WW, T>,
    e: ConnectionEpoch<'owner>,
) -> Result<(Outbound<'owner>, Vec<u8>), Error> {
    let (out, bytes) = take(h, e)?;
    h.on_frame_written(e, out.transmit)?;
    Ok((out, bytes))
}
const VALUE: &[u8] = b"\0\x14\0\xaa\x80\0\0\x07\0\0\0\0\0\0\0\x09s\0a\0";
const END: &[u8] = b"\0\x04\0\xab";
const CONFIRM: &[u8] = b"\0\x04\0\xaf";
fn watch_value(wid: u32, value: u64) -> [u8; 24] {
    let mut out = [0; 24];
    out[..8].copy_from_slice(b"\0\x18\0\xad\0\0\0\x02");
    out[8..12].copy_from_slice(&wid.to_be_bytes());
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

#[test]
fn lazy_create_zero_update_and_pending_setter_coalescing() -> Result<(), Error> {
    let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
    assert!(Handle::new(&mut statistics_instance_1, b"ignored\0subsystem", false)?.is_none());
    let mut statistics_instance_4 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_4)?;
    assert!(!h.connection_needed(AbsoluteTime::from_micros(0)));
    assert_eq!(h.update(b"a", 0, true)?, SetterAdmission::Noop);
    assert!(!h.connection_needed(AbsoluteTime::from_micros(0)));
    assert_eq!(h.set(b"a", 20, false)?, SetterAdmission::Queued);
    let get = h.get(selector(b"a"))?;
    assert_eq!(h.update(b"a", -30, true)?, SetterAdmission::Coalesced);
    assert_eq!(h.update(b"a", 10, false)?, SetterAdmission::Coalesced);
    assert_eq!(h.pending_actions(), 2);
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (_, bytes) = sent(&mut h, e)?;
    assert_eq!(bytes, b"\0\x14\0\xa8\0\0\0\0\0\0\0\0\0\0\0\x0as\0a\0");
    let (out, bytes) = sent(&mut h, e)?;
    assert_eq!(out.kind, OutboundKind::Get(get));
    assert_eq!(bytes, b"\0\x08\0\xa9s\0a\0");
    h.receive(e, END, AbsoluteTime::from_micros(1))?;
    assert_eq!(
        h.take_completion().map(|v| (v.get, v.result)),
        Some((get, Ok(())))
    );
    assert!(h.is_idle());
    assert_eq!(h.connection_epoch(), Some(e));
    Ok(())
}

#[test]
fn updates_wrapping_zero_coalescence_and_latest_persistence_are_not_noops() -> Result<(), Error> {
    let mut statistics_instance_5 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_5)?;
    h.update(b"a", -1, false)?;
    h.update(b"a", 1, true)?;
    assert_eq!(h.update(b"a", 0, false)?, SetterAdmission::Noop);
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (_, bytes) = sent(&mut h, e)?;
    assert_eq!(bytes, b"\0\x14\0\xa8\0\0\0\x03\0\0\0\0\0\0\0\0s\0a\0");
    h.set(b"a", u64::MAX, false)?;
    h.update(b"a", 1, true)?;
    h.update(b"a", i64::MIN, true)?;
    let (_, bytes) = sent(&mut h, e)?;
    assert_eq!(bytes, b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\0s\0a\0");
    h.set(b"a", 1, false)?;
    h.set(b"A", 2, false)?;
    h.update(b"a", 4, false)?;
    let (_, bytes) = sent(&mut h, e)?;
    assert_eq!(&bytes[8..16], &5u64.to_be_bytes());
    assert_eq!(&bytes[16..], b"s\0a\0");
    let (_, bytes) = sent(&mut h, e)?;
    assert_eq!(&bytes[8..16], &2u64.to_be_bytes());
    assert_eq!(&bytes[16..], b"s\0A\0");
    Ok(())
}

#[test]
fn queued_and_current_cancel_keep_original_stream_tombstones() -> Result<(), Error> {
    let mut statistics_instance_6 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_6)?;
    let first = h.get(selector(b"a"))?;
    h.get_cancel(first)?;
    assert!(!h.connection_needed(AbsoluteTime::from_micros(0)));
    assert_eq!(h.pending_completions(), 0);
    let current = h.get(selector(b"a"))?;
    assert_ne!(current, first);
    assert!(h.get_cancel(first).is_err());
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, e)?;
    assert!(
        matches!(h.receive(e,VALUE,AbsoluteTime::from_micros(1))?,Inbound::GetValue{get,..}if get==current)
    );
    h.get_cancel(current)?;
    let next = h.get(selector(b"next"))?;
    assert_eq!(
        h.receive(e, VALUE, AbsoluteTime::from_micros(2))?,
        Inbound::None
    );
    assert!(h.next_request(e, &mut [0; 128])?.is_none());
    assert_eq!(h.active_get(), Some(current));
    h.receive(e, END, AbsoluteTime::from_micros(3))?;
    assert!(h.take_completion().is_none());
    assert_eq!(h.connection_epoch(), Some(e));
    let (out, _) = sent(&mut h, e)?;
    assert_eq!(out.kind, OutboundKind::Get(next));
    h.receive(e, END, AbsoluteTime::from_micros(4))?;
    assert_eq!(
        h.take_completion().map(|c| (c.get, c.result)),
        Some((next, Ok(())))
    );
    Ok(())
}

#[test]
fn iterator_abort_retains_end_callback_but_not_disconnect_callback() -> Result<(), Error> {
    let mut statistics_instance_7 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_7)?;
    let first = h.get(selector(b"a"))?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, e)?;
    h.receive(e, VALUE, AbsoluteTime::from_micros(1))?;
    h.get_value_result(first, GetFlow::AbortIteration)?;
    assert_eq!(
        h.receive(e, VALUE, AbsoluteTime::from_micros(2))?,
        Inbound::None
    );
    h.receive(e, END, AbsoluteTime::from_micros(3))?;
    assert_eq!(
        h.take_completion().map(|c| (c.get, c.result)),
        Some((first, Ok(())))
    );
    let second = h.get(selector(b"a"))?;
    sent(&mut h, e)?;
    h.get_value_result(second, GetFlow::AbortIteration)?;
    h.connection_lost(e, Error::Io, AbsoluteTime::from_micros(4))?;
    assert!(h.take_completion().is_none());
    assert_eq!(h.next_wakeup(), Some(AbsoluteTime::from_micros(1004)));
    Ok(())
}

#[test]
fn watch_cancelled_registration_still_consumes_wid_on_existing_connection() -> Result<(), Error> {
    let mut statistics_instance_8 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_8)?;
    h.set(b"anchor", 0, false)?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, e)?;
    let old = h.watch(selector(b"old"))?;
    let live = h.watch(selector(b"live"))?;
    h.watch_cancel(old)?;
    let (out, bytes) = sent(&mut h, e)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 0,
            logical: None
        }
    );
    assert_eq!(bytes, b"\0\x0a\0\xacs\0old\0");
    let (out, _) = sent(&mut h, e)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 1,
            logical: Some(live)
        }
    );
    assert_eq!(
        h.receive(e, &watch_value(0, 5), AbsoluteTime::from_micros(1))?,
        Inbound::None
    );
    assert!(
        matches!(h.receive(e,&watch_value(1,7),AbsoluteTime::from_micros(2))?,Inbound::WatchValue{watch,notification}if watch==live&&notification.persistent()&&notification.value==7)
    );
    let mut names = [0xa5; 64];
    let selector = h.watch_selector(live, &mut names)?;
    assert_eq!(selector.name, b"live");
    assert!(h.watch_selector(old, &mut names).is_err());
    Ok(())
}

#[test]
fn reconnect_compacts_wire_ids_without_reassigning_cancelled_logical_ids() -> Result<(), Error> {
    let mut statistics_instance_9 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_9)?;
    let old = h.watch(selector(b"old"))?;
    let live = h.watch(selector(b"live"))?;
    let first = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, first)?;
    sent(&mut h, first)?;
    h.watch_cancel(old)?;
    h.connection_lost(first, Error::Io, AbsoluteTime::from_micros(1))?;
    h.set(b"pending", 5, false)?;
    let get = h.get(selector(b"query"))?;
    let second = h.begin_connection(AbsoluteTime::from_micros(1001))?;
    assert_ne!(first, second);
    let (out, _) = sent(&mut h, second)?;
    assert!(matches!(out.kind, OutboundKind::Mutation { .. }));
    let (out, _) = sent(&mut h, second)?;
    assert_eq!(out.kind, OutboundKind::Get(get));
    h.receive(second, END, AbsoluteTime::from_micros(1002))?;
    h.take_completion();
    let (out, bytes) = sent(&mut h, second)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 0,
            logical: Some(live)
        }
    );
    assert_eq!(&bytes[4..], b"s\0live\0");
    assert!(
        matches!(h.receive(second,&watch_value(0,11),AbsoluteTime::from_micros(1003))?,Inbound::WatchValue{watch,..}if watch==live)
    );
    let replacement = h.watch(selector(b"replacement"))?;
    assert_eq!(old.resource_id().index, replacement.resource_id().index);
    assert_ne!(old, replacement);
    let (out, _) = sent(&mut h, second)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 1,
            logical: Some(replacement)
        }
    );
    assert!(
        matches!(h.receive(second,&watch_value(0,12),AbsoluteTime::from_micros(1004))?,Inbound::WatchValue{watch,..}if watch==live)
    );
    assert_eq!(
        h.receive(first, END, AbsoluteTime::from_micros(1005)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(h.connection_epoch(), Some(second));
    Ok(())
}

#[test]
fn live_watches_reserve_reconnect_action_capacity_and_refusals_are_atomic() -> Result<(), Error> {
    type Small<'owner> = StatisticsHandle<'owner, 3, 16, 1, 4, 1>;
    let mut statistics_instance_2 = gnunet_client::statistics_handle::Instance::new();
    let mut h = Small::new(&mut statistics_instance_2, b"s", true)?.ok_or(Error::Unavailable)?;
    let live = h.watch(selector(b"w"))?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, e)?;
    let get = h.get(selector(b"g"))?;
    h.set(b"a", 5, true)?;
    assert_eq!(h.set(b"b", 9, false), Err(Error::Capacity));
    assert_eq!(h.pending_actions(), 2);
    assert_eq!(h.live_watches(), 1);
    h.connection_lost(e, Error::Io, AbsoluteTime::from_micros(0))?;
    let next = h.begin_connection(AbsoluteTime::from_micros(1000))?;
    let (out, _) = sent(&mut h, next)?;
    assert_eq!(out.kind, OutboundKind::Get(get));
    h.receive(next, END, AbsoluteTime::from_micros(1001))?;
    h.take_completion();
    let (_, bytes) = sent(&mut h, next)?;
    assert_eq!(&bytes[4..8], &2u32.to_be_bytes());
    assert_eq!(&bytes[8..16], &5u64.to_be_bytes());
    let (out, _) = sent(&mut h, next)?;
    assert_eq!(
        out.kind,
        OutboundKind::Watch {
            wire_id: 0,
            logical: Some(live)
        }
    );
    h.set(b"a", 7, false)?;
    let mut scratch = [0xa5; 8];
    assert_eq!(h.next_request(next, &mut scratch), Err(Error::Capacity));
    assert_eq!(scratch, [0xa5; 8]);
    let (_, bytes) = sent(&mut h, next)?;
    assert_eq!(&bytes[8..16], &7u64.to_be_bytes());
    Ok(())
}

#[test]
fn terminal_reservation_and_old_generations_prevent_callback_loss() -> Result<(), Error> {
    type Small<'owner> = StatisticsHandle<'owner, 1, 8, 0, 0, 1>;
    let mut statistics_instance_3 = gnunet_client::statistics_handle::Instance::new();
    let mut h = Small::new(&mut statistics_instance_3, b"s", true)?.ok_or(Error::Unavailable)?;
    let old = h.get(selector(b"a"))?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, e)?;
    h.receive(e, END, AbsoluteTime::from_micros(1))?;
    assert_eq!(h.get(selector(b"b")), Err(Error::Capacity));
    h.get_cancel(old)?;
    assert_eq!(h.pending_completions(), 0);
    let next = h.get(selector(b"b"))?;
    assert_ne!(next, old);
    assert!(h.get_cancel(old).is_err());
    sent(&mut h, e)?;
    h.connection_lost(e, Error::Io, AbsoluteTime::from_micros(2))?;
    assert_eq!(
        h.take_completion().map(|c| (c.get, c.result)),
        Some((next, Err(Error::Io)))
    );
    Ok(())
}

#[test]
fn partial_zero_and_full_send_boundaries_match_mq_nontransmitted_length() -> Result<(), Error> {
    let mut statistics_instance_10 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_10)?;
    h.set(b"a", 1, false)?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (first, _) = take(&mut h, e)?;
    assert_eq!(h.mq_nontransmitted_length(), 1);
    h.set(b"b", 2, false)?;
    assert!(h.next_request(e, &mut [0; 64])?.is_none());
    h.on_first_send_attempt(e, first.transmit)?;
    assert_eq!(h.mq_nontransmitted_length(), 0);
    let (second, _) = take(&mut h, e)?;
    assert_eq!(h.transmit_count(), 2);
    assert_eq!(h.mq_nontransmitted_length(), 1);
    assert_eq!(
        h.on_first_send_attempt(e, second.transmit),
        Err(Error::Conflict)
    );
    h.on_frame_written(e, first.transmit)?;
    assert_eq!(h.mq_nontransmitted_length(), 1);
    h.on_frame_written(e, second.transmit)?;
    assert_eq!(h.transmit_count(), 0);
    assert_eq!(h.mq_nontransmitted_length(), 0);
    h.connection_lost(e, Error::Io, AbsoluteTime::from_micros(1))?;
    let next = h.begin_connection(AbsoluteTime::from_micros(1001))?;
    assert!(h.next_request(next, &mut [0; 64])?.is_none());
    h.begin_destroy(false, AbsoluteTime::from_micros(1002))?;
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.outcome, DestroyOutcome::Discarded);
    assert_eq!(report.unconfirmed_mutations, 2);
    Ok(())
}

#[test]
fn deferred_destroy_requires_fully_written_barrier_and_exact_confirmation() -> Result<(), Error> {
    let mut statistics_instance_11 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_11)?;
    h.set(b"a", 1, true)?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (first, _) = take(&mut h, e)?;
    h.get(selector(b"drop"))?;
    h.watch(selector(b"drop"))?;
    h.set(b"b", 2, false)?;
    h.begin_destroy(true, AbsoluteTime::from_micros(10))?;
    assert!(h.is_destroying());
    assert_eq!(h.next_wakeup(), Some(AbsoluteTime::from_micros(5010)));
    assert_eq!(h.pending_actions(), 1);
    h.on_frame_written(e, first.transmit)?;
    sent(&mut h, e)?;
    let (out, bytes) = sent(&mut h, e)?;
    assert_eq!(out.kind, OutboundKind::Disconnect);
    assert_eq!(bytes, b"\0\x04\0\xae");
    h.receive(e, CONFIRM, AbsoluteTime::from_micros(100))?;
    // statistics_api.c handle_disconnect_confirm schedules add_now(do_destroy).
    assert!(!h.is_closed());
    assert_eq!(
        h.destruction_deadline(),
        Some(AbsoluteTime::from_micros(5010))
    );
    assert!(h.take_destroy_report().is_none());
    h.tick(AbsoluteTime::from_micros(0))?;
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.outcome, DestroyOutcome::ProcessingConfirmed);
    assert_eq!(report.unconfirmed_mutations, 0);
    assert!(h.is_closed());
    assert!(h.take_completion().is_none());
    Ok(())
}

#[test]
fn destroy_immediate_and_expired_confirm_never_fabricate_processing_success() -> Result<(), Error> {
    let mut statistics_instance_12 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_12)?;
    h.set(b"a", 1, true)?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (out, _) = take(&mut h, e)?;
    h.on_first_send_attempt(e, out.transmit)?;
    h.set(b"b", 2, false)?;
    h.begin_destroy(true, AbsoluteTime::from_micros(1))?;
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.outcome, DestroyOutcome::Discarded);
    assert_eq!(report.queued_mutations_discarded, 1);
    assert_eq!(report.unconfirmed_mutations, 1);
    let mut statistics_instance_13 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_13)?;
    h.set(b"a", 1, true)?;
    let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let (out, _) = take(&mut h, e)?;
    h.begin_destroy(true, AbsoluteTime::from_micros(0))?;
    h.on_frame_written(e, out.transmit)?;
    sent(&mut h, e)?;
    assert_eq!(
        h.receive(e, CONFIRM, AbsoluteTime::from_micros(5000)),
        Err(Error::Deadline)
    );
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.outcome, DestroyOutcome::Deadline);
    assert_eq!(report.unconfirmed_mutations, 1);
    assert_eq!(report.unconfirmed_persistent_mutations, 1);
    Ok(())
}

#[test]
fn malformed_or_premature_terminal_retires_only_original_epoch() -> Result<(), Error> {
    let mut statistics_instance_14 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_14)?;
    h.set(b"a", 1, false)?;
    let old = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, old)?;
    assert_eq!(
        h.receive(old, END, AbsoluteTime::from_micros(1)),
        Err(Error::Malformed)
    );
    assert_eq!(h.connection_epoch(), None);
    let current = h.begin_connection(AbsoluteTime::from_micros(1001))?;
    assert_ne!(current, old);
    assert_eq!(
        h.receive(old, END, AbsoluteTime::from_micros(1002)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(h.connection_epoch(), Some(current));
    h.set(b"a", 1, false)?;
    let (out, _) = take(&mut h, current)?;
    h.begin_destroy(true, AbsoluteTime::from_micros(1002))?;
    h.on_frame_written(current, out.transmit)?;
    let (out, _) = take(&mut h, current)?;
    assert_eq!(out.kind, OutboundKind::Disconnect);
    assert_eq!(
        h.receive(current, CONFIRM, AbsoluteTime::from_micros(1003)),
        Err(Error::Malformed)
    );
    assert_eq!(
        h.take_destroy_report().map(|r| r.outcome),
        Some(DestroyOutcome::ConnectionLost)
    );
    Ok(())
}

#[test]
fn a_later_barrier_never_acknowledges_mutations_from_a_lost_epoch() -> Result<(), Error> {
    let mut statistics_instance_15 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_15)?;
    h.update(b"a", 7, true)?;
    let first = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, first)?;
    h.connection_lost(first, Error::Io, AbsoluteTime::from_micros(1))?;
    h.set(b"b", 9, false)?;
    let second = h.begin_connection(AbsoluteTime::from_micros(1001))?;
    let (out, _) = take(&mut h, second)?;
    h.begin_destroy(true, AbsoluteTime::from_micros(1002))?;
    h.on_frame_written(second, out.transmit)?;
    sent(&mut h, second)?;
    h.receive(second, CONFIRM, AbsoluteTime::from_micros(1003))?;
    assert!(!h.is_closed());
    assert!(h.take_destroy_report().is_none());
    h.tick(AbsoluteTime::from_micros(0))?;
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.outcome, DestroyOutcome::ProcessingConfirmed);
    assert_eq!(report.unconfirmed_mutations, 1);
    assert_eq!(report.unconfirmed_persistent_mutations, 1);
    Ok(())
}

#[test]
fn invalid_service_configuration_never_creates_a_virtual_mq() -> Result<(), Error> {
    let mut statistics_instance_16 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_16)?;
    h.set(b"a", 1, false)?;
    h.connection_unavailable(AbsoluteTime::from_micros(0))?;
    assert_eq!(h.connection_epoch(), None);
    assert_eq!(h.transmit_count(), 0);
    assert_eq!(h.next_wakeup(), Some(AbsoluteTime::from_micros(1000)));
    assert_eq!(h.set(b"a", 2, true)?, SetterAdmission::Coalesced);
    assert_eq!(
        h.connection_unavailable(AbsoluteTime::from_micros(999)),
        Err(Error::NotReady)
    );
    h.connection_unavailable(AbsoluteTime::from_micros(1000))?;
    assert_eq!(h.next_wakeup(), Some(AbsoluteTime::from_micros(3000)));
    assert_eq!(h.pending_actions(), 1);
    h.begin_destroy(true, AbsoluteTime::from_micros(1001))?;
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.outcome, DestroyOutcome::Discarded);
    assert_eq!(report.queued_mutations_discarded, 1);
    assert_eq!(report.unconfirmed_mutations, 0);
    let mut statistics_instance_17 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_17)?;
    let get = h.get(selector(b"a"))?;
    h.connection_unavailable(AbsoluteTime::from_micros(0))?;
    h.get_cancel(get)?;
    assert_eq!(h.pending_actions(), 0);
    assert!(!h.connection_needed(AbsoluteTime::from_micros(999)));
    assert!(h.connection_needed(AbsoluteTime::from_micros(1000)));
    Ok(())
}

#[test]
fn unregistered_message_preserves_current_get_but_registered_bad_end_fails() -> Result<(), Error> {
    let mut statistics_instance_18 = gnunet_client::statistics_handle::Instance::new();
    let mut h = new(&mut statistics_instance_18)?;
    let first = h.get(selector(b"a"))?;
    let second = h.get(selector(b"next"))?;
    let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
    sent(&mut h, epoch)?;
    // Valid outer size, no registered handler, arbitrary uninterpreted body.
    assert_eq!(
        h.receive(
            epoch,
            b"\0\x07\xfd\xe8\xff\0\x01",
            AbsoluteTime::from_micros(1)
        )?,
        Inbound::None
    );
    assert_eq!(h.connection_epoch(), Some(epoch));
    assert_eq!(h.active_get(), Some(first));
    assert_eq!(h.pending_actions(), 1);
    assert!(h.take_completion().is_none());
    assert!(matches!(
        h.receive(epoch, VALUE, AbsoluteTime::from_micros(2))?,
        Inbound::GetValue { get, .. } if get == first
    ));
    h.receive(epoch, END, AbsoluteTime::from_micros(3))?;
    assert_eq!(
        h.take_completion().map(|c| (c.get, c.result)),
        Some((first, Ok(())))
    );
    assert_eq!(sent(&mut h, epoch)?.0.kind, OutboundKind::Get(second));
    // END has a registered fixed-size handler: its trailing byte is malformed.
    assert!(
        h.receive(epoch, b"\0\x05\0\xab\0", AbsoluteTime::from_micros(4))
            .is_err()
    );
    assert_eq!(h.connection_epoch(), None);
    let failed = h.take_completion().ok_or(Error::NotReady)?;
    assert_eq!(failed.get, second);
    assert!(failed.result.is_err());
    assert!(h.take_completion().is_none());
    Ok(())
}
