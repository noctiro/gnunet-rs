//! Instance brands reject foreign local authority without changing official bytes.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check foreign-owner refusal and original-operation controls"
)]
use gnunet_client::{
    statistics::{Selector, WatchSession},
    statistics_handle::{Instance, StatisticsHandle},
};
use gnunet_types::{AbsoluteTime, Error};
fn selector(name: &[u8]) -> Selector<'_> {
    Selector {
        subsystem: b"owner",
        name,
    }
}
#[test]
fn foreign_get_watch_epoch_and_transmit_cannot_change_the_original_owner() -> Result<(), Error> {
    let mut ia = Instance::new();
    let mut ib = Instance::new();
    let mut a =
        StatisticsHandle::<4, 64, 2, 8, 4>::new(&mut ia, b"a", true)?.ok_or(Error::Unavailable)?;
    let mut b =
        StatisticsHandle::<4, 64, 2, 8, 4>::new(&mut ib, b"b", true)?.ok_or(Error::Unavailable)?;
    let ga = a.get(selector(b"get-a"))?;
    let gb = b.get(selector(b"get-b"))?;
    assert_eq!(ga.resource_id(), gb.resource_id());
    assert_ne!(ga, gb);
    assert_eq!(b.get_cancel(ga), Err(Error::Stale));
    assert!(b.get_callbacks_enabled(gb));
    assert!(a.get_callbacks_enabled(ga));
    let wa = a.watch(selector(b"watch-a"))?;
    let wb = b.watch(selector(b"watch-b"))?;
    assert_eq!(wa.resource_id(), wb.resource_id());
    assert_ne!(wa, wb);
    assert_eq!(b.watch_cancel(wa), Err(Error::Stale));
    assert!(b.owns_watch(wb));
    assert!(a.owns_watch(wa));
    let ea = a.begin_connection(AbsoluteTime::from_micros(0))?;
    let eb = b.begin_connection(AbsoluteTime::from_micros(0))?;
    assert_eq!(ea.value(), eb.value());
    assert_ne!(ea, eb);
    let mut scratch = [0xa5; 128];
    assert!(b.next_request(ea, &mut scratch).is_err());
    assert_eq!(scratch, [0xa5; 128]);
    let oa = a.next_request(ea, &mut scratch)?.ok_or(Error::NotReady)?;
    let ob = b.next_request(eb, &mut scratch)?.ok_or(Error::NotReady)?;
    assert_eq!(oa.transmit.value(), ob.transmit.value());
    assert_ne!(oa.transmit, ob.transmit);
    assert!(b.on_frame_written(eb, oa.transmit).is_err());
    assert_eq!((a.transmit_count(), b.transmit_count()), (1, 1));
    b.on_frame_written(eb, ob.transmit)?;
    assert_eq!(b.transmit_count(), 0);
    assert_eq!(a.transmit_count(), 1);
    // The owner can move: its authority references separate caller storage.
    let mut moved = a;
    assert!(moved.owns_get(ga));
    moved.get_cancel(ga)?;
    assert!(!moved.get_callbacks_enabled(ga));
    Ok(())
}
#[test]
fn short_watch_session_ids_keep_wire_numbers_but_refuse_a_foreign_session() -> Result<(), Error> {
    let mut ia = Instance::new();
    let mut ib = Instance::new();
    let mut a = WatchSession::<2>::new(&mut ia);
    let mut b = WatchSession::<2>::new(&mut ib);
    let mut first = [0; 64];
    let (wa, na) = a.start(selector(b"a"), &mut first)?;
    let mut second = [0; 64];
    let (wb, nb) = b.start(selector(b"b"), &mut second)?;
    assert_eq!(wa.value(), 0);
    assert_eq!(wb.value(), 0);
    assert_ne!(wa, wb);
    assert_eq!(na, nb);
    assert_eq!(&first[..4], &second[..4]);
    assert_eq!(b.cancel(wa), Err(Error::Stale));
    assert!(!b.is_closed());
    let frame = b"\0\x18\0\xad\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09";
    let ua = a.receive(frame)?.ok_or(Error::NotReady)?;
    let ub = b.receive(frame)?.ok_or(Error::NotReady)?;
    assert_eq!(ua.id, wa);
    assert_eq!(ub.id, wb);
    assert_eq!(ua.selector.name, b"a");
    assert_eq!(ub.selector.name, b"b");
    b.cancel(wb)?;
    assert!(b.receive(frame)?.is_none());
    assert!(a.receive(frame)?.is_some());
    Ok(())
}
