//! Registered-handler policy and original-operation/result authority.
//! Early WATCH/CONFIRM inputs are deliberately stricter than the pinned C
//! implementation; valid service interactions never require those inputs.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The witness tests assert protocol/result authority and unregistered dispatch."
)]
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{DestroyOutcome, Inbound, OutboundKind, StatisticsHandle},
};
use gnunet_types::{AbsoluteTime, Error};
type Owner<'owner> = StatisticsHandle<'owner, 8, 64, 4, 8, 8>;
fn owner<'owner>(
    instance: &'owner mut gnunet_client::statistics_handle::Instance,
) -> Result<Owner<'owner>, Error> {
    Owner::new(instance, b"s", true)?.ok_or(Error::Unavailable)
}
fn selector(name: &[u8]) -> Selector<'_> {
    Selector {
        subsystem: b"s",
        name,
    }
}
const END: &[u8] = b"\0\x04\0\xab";
const CONFIRM: &[u8] = b"\0\x04\0\xaf";
#[test]
fn logical_watch_queued_behind_get_has_no_callback_until_wire_registration() -> Result<(), Error> {
    let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
    let mut h = owner(&mut statistics_instance_1)?;
    let get = h.get(selector(b"query"))?;
    let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let frame = h
        .next_request(epoch, &mut [0; 128])?
        .ok_or(Error::NotReady)?;
    h.on_frame_written(epoch, frame.transmit)?;
    let watch = h.watch(selector(b"future"))?;
    assert!(h.owns_watch(watch));
    assert!(h.next_request(epoch, &mut [0; 128])?.is_none());
    let mut notification = [0; 24];
    notification[..4].copy_from_slice(b"\0\x18\0\xad");
    notification[23] = 77;
    assert_eq!(
        h.receive(epoch, &notification, AbsoluteTime::from_micros(1)),
        Err(Error::Malformed)
    );
    assert_eq!(h.connection_epoch(), None);
    let completion = h.take_completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.get, get);
    assert!(completion.result.is_err());
    assert!(h.owns_watch(watch));
    Ok(())
}
#[test]
fn early_confirmation_cannot_certify_partially_written_update_and_barrier() -> Result<(), Error> {
    let mut statistics_instance_2 = gnunet_client::statistics_handle::Instance::new();
    let mut h = owner(&mut statistics_instance_2)?;
    h.set(b"update", 999, true)?;
    let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
    let mutation = h
        .next_request(epoch, &mut [0; 128])?
        .ok_or(Error::NotReady)?;
    h.begin_destroy(true, AbsoluteTime::from_micros(0))?;
    h.on_first_send_attempt(epoch, mutation.transmit)?;
    let barrier = h
        .next_request(epoch, &mut [0; 128])?
        .ok_or(Error::NotReady)?;
    assert_eq!(barrier.kind, OutboundKind::Disconnect);
    assert_eq!(
        h.receive(epoch, CONFIRM, AbsoluteTime::from_micros(1)),
        Err(Error::Malformed)
    );
    let report = h.take_destroy_report().ok_or(Error::NotReady)?;
    assert_eq!(report.outcome, DestroyOutcome::ConnectionLost);
    assert_eq!(report.unconfirmed_mutations, 1);
    assert_eq!(report.unconfirmed_persistent_mutations, 1);
    Ok(())
}
#[test]
fn all_unregistered_directions_ignore_opaque_body_without_losing_get() -> Result<(), Error> {
    for typ in [168_u16, 169, 172, 174, 4, 65000] {
        let mut statistics_instance_3 = gnunet_client::statistics_handle::Instance::new();
        let mut h = owner(&mut statistics_instance_3)?;
        let get = h.get(selector(b"query"))?;
        let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let frame = h
            .next_request(epoch, &mut [0; 128])?
            .ok_or(Error::NotReady)?;
        h.on_frame_written(epoch, frame.transmit)?;
        let mut foreign = [0; 7];
        foreign[..2].copy_from_slice(&7_u16.to_be_bytes());
        foreign[2..4].copy_from_slice(&typ.to_be_bytes());
        foreign[4..].copy_from_slice(&[0xFF, 0, 1]);
        assert_eq!(
            h.receive(epoch, &foreign, AbsoluteTime::from_micros(1))?,
            Inbound::None
        );
        assert_eq!(h.active_get(), Some(get));
        assert_eq!(h.connection_epoch(), Some(epoch));
        h.receive(epoch, END, AbsoluteTime::from_micros(2))?;
        assert!(h.take_completion().ok_or(Error::NotReady)?.result.is_ok());
    }
    Ok(())
}
