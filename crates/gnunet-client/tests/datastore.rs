//! Caller-buffer datastore ownership without a daemon or native connection.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check original request identity, certainty and reservation accounting"
)]
use gnunet_client::datastore::*;
use gnunet_types::{Duration, Error, MonoInstant};
use gnunet_wire::official::AbsoluteTime;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn send<'a>(
    client: &mut Client<'a, '_, '_>,
    epoch: Epoch<'a>,
    now: u64,
) -> Result<Transmission<'a>, Error> {
    let token = client
        .next_send(epoch, MonoInstant(now))?
        .ok_or(Error::NotReady)?
        .token();
    client.written(token)?;
    Ok(token)
}
fn status<'a>(
    client: &mut Client<'a, '_, '_>,
    epoch: Epoch<'a>,
    code: i32,
    now: u64,
) -> Result<Completion<'a>, Error> {
    let mut bytes = [0; 128];
    let n = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(19),
        message: if code == -1 { Some(b"error\0") } else { None },
    })
    .encode(&mut bytes)?;
    Ok(client
        .receive(epoch, &bytes[..n], MonoInstant(now))?
        .ok_or(Error::NotReady)?
        .completion)
}
fn value<'a>(key: &'a [u8; 64], value: &'a [u8], reservation: u32) -> Data<'a> {
    Data {
        reservation,
        kind: 5,
        priority: 3,
        anonymity: 0,
        replication: 2,
        uid: 0,
        expiration: AbsoluteTime::from_micros(99),
        key,
        value,
    }
}

#[test]
fn reservation_capacity_cancel_refund_release_and_real_single_data() -> TestResult {
    let mut instance = Instance::new();
    let mut a = [0; 512];
    let mut b = [0; 512];
    let mut c = [0; 512];
    let mut slots = [Slot::new(&mut a), Slot::new(&mut b), Slot::new(&mut c)];
    let mut reservations = [ReservationSlot::default(); 1];
    let mut client = Client::new(
        &mut instance,
        &mut slots,
        &mut reservations,
        Limits {
            max_pending: 3,
            ..Limits::default()
        },
    )?;
    let epoch = client.begin_connection(MonoInstant(0))?;
    let reserve = client.submit(
        Request::Reserve {
            amount: 3,
            entries: 1,
        },
        None,
        MonoInstant(0),
        Duration(100),
    )?;
    send(&mut client, epoch, 1)?;
    let reply = status(&mut client, epoch, 23, 2)?;
    assert_eq!(reply.operation, reserve);
    let reservation = client
        .take(reserve)?
        .reservation
        .ok_or("reservation missing")?;
    assert_eq!(reservation.value(), 23);
    let key = [11; 64];
    let put = Request::Put(value(&key, b"abc", reservation.value()));
    let abandoned = client.submit(put, Some(reservation), MonoInstant(3), Duration(100))?;
    assert_eq!(
        client.submit(put, Some(reservation), MonoInstant(3), Duration(100)),
        Err(Error::Capacity)
    );
    client.cancel(abandoned, MonoInstant(4))?;
    assert_eq!(client.take(abandoned)?.outcome, Outcome::Cancelled);
    let stored = client.submit(put, Some(reservation), MonoInstant(4), Duration(100))?;
    let release = client.submit(
        Request::Release { reservation: 23 },
        Some(reservation),
        MonoInstant(4),
        Duration(100),
    )?;
    send(&mut client, epoch, 5)?;
    status(&mut client, epoch, 1, 6)?;
    assert!(matches!(
        client.take(stored)?.outcome,
        Outcome::Status { code: 1, .. }
    ));
    send(&mut client, epoch, 7)?;
    status(&mut client, epoch, 1, 8)?;
    client.take(release)?;
    assert_eq!(
        client.submit(put, Some(reservation), MonoInstant(8), Duration(100)),
        Err(Error::Stale)
    );
    let get = client.submit(
        Request::Get {
            key: Some(&key),
            kind: 5,
            next_uid: 0,
            random: false,
        },
        None,
        MonoInstant(9),
        Duration(100),
    )?;
    let next = client.submit(
        Request::ZeroAnonymity {
            kind: 5,
            next_uid: 0,
        },
        None,
        MonoInstant(9),
        Duration(100),
    )?;
    send(&mut client, epoch, 10)?;
    let mut bytes = [0; 256];
    let n = Response::Data(Data {
        uid: 42,
        ..value(&key, b"abc", 0)
    })
    .encode(&mut bytes)?;
    let reply = client
        .receive(epoch, &bytes[..n], MonoInstant(11))?
        .ok_or("data missing")?;
    assert_eq!(reply.completion.operation, get);
    assert!(
        matches!(reply.response, Response::Data(data) if data.value == b"abc" && data.uid == 42)
    );
    assert_eq!(client.take(get)?.outcome, Outcome::Data { uid: 42 });
    // A DATA already ended the original query; no fabricated END is required.
    send(&mut client, epoch, 12)?;
    let n = Response::End.encode(&mut bytes)?;
    client
        .receive(epoch, &bytes[..n], MonoInstant(13))?
        .ok_or("end missing")?;
    assert_eq!(client.take(next)?.outcome, Outcome::NotFound);
    Ok(())
}

#[test]
fn active_cancel_drains_then_disconnect_preserves_unknown_and_unsent_work() -> TestResult {
    let mut instance = Instance::new();
    let mut a = [0; 512];
    let mut b = [0; 512];
    let mut c = [0; 512];
    let mut slots = [Slot::new(&mut a), Slot::new(&mut b), Slot::new(&mut c)];
    let mut reservations = [];
    let mut client = Client::new(
        &mut instance,
        &mut slots,
        &mut reservations,
        Limits {
            max_pending: 3,
            ..Limits::default()
        },
    )?;
    let epoch = client.begin_connection(MonoInstant(0))?;
    let key = [7; 64];
    let put = client.submit(
        Request::Put(value(&key, b"abc", 0)),
        None,
        MonoInstant(0),
        Duration(100),
    )?;
    let get = client.submit(
        Request::Get {
            key: None,
            kind: 0,
            next_uid: 0,
            random: true,
        },
        None,
        MonoInstant(0),
        Duration(100),
    )?;
    send(&mut client, epoch, 1)?;
    client.cancel(put, MonoInstant(2))?;
    assert!(client.next_send(epoch, MonoInstant(2))?.is_none());
    let reply = status(&mut client, epoch, 1, 3)?;
    assert_eq!(reply.interruption, Some(Interruption::Cancelled));
    assert!(matches!(
        client.take(put)?.outcome,
        Outcome::Status { code: 1, .. }
    ));
    send(&mut client, epoch, 4)?;
    client.retire(epoch, MonoInstant(5))?;
    assert_eq!(client.take(get)?.outcome, Outcome::Interrupted);
    let replacement = client.begin_connection(MonoInstant(6))?;
    let remove = client.submit(
        Request::Remove {
            key: &key,
            value: b"abc",
        },
        None,
        MonoInstant(6),
        Duration(100),
    )?;
    let retained = client.submit(Request::Replication, None, MonoInstant(6), Duration(100))?;
    let token = client
        .next_send(replacement, MonoInstant(7))?
        .ok_or("lease missing")?
        .token();
    client.cancel(remove, MonoInstant(7))?;
    assert!(client.needs_retire());
    assert_eq!(client.written(token), Err(Error::NotReady));
    client.retire(replacement, MonoInstant(8))?;
    assert_eq!(client.take(remove)?.outcome, Outcome::Unknown);
    let third = client.begin_connection(MonoInstant(9))?;
    assert_eq!(
        client
            .next_send(third, MonoInstant(9))?
            .ok_or("unsent replication lost")?
            .token()
            .operation(),
        retained
    );
    // Retire the leased replication query: selecting it can decrement a score.
    client.retire(third, MonoInstant(10))?;
    assert_eq!(client.take(retained)?.outcome, Outcome::Unknown);
    let mut end = [0; 4];
    Response::End.encode(&mut end)?;
    assert!(matches!(
        client.receive(epoch, &end, MonoInstant(10)),
        Err(Error::Stale)
    ));
    Ok(())
}

#[test]
fn finite_timeout_poison_and_drop_never_fabricate_success() -> TestResult {
    let mut instance = Instance::new();
    let mut a = [0; 256];
    let mut b = [0; 256];
    let mut slots = [Slot::new(&mut a), Slot::new(&mut b)];
    let mut reservations = [ReservationSlot::default(); 1];
    let mut client = Client::new(
        &mut instance,
        &mut slots,
        &mut reservations,
        Limits {
            max_pending: 2,
            drain_timeout: Duration(5),
            ..Limits::default()
        },
    )?;
    let epoch = client.begin_connection(MonoInstant(0))?;
    let expires = client.submit(
        Request::Get {
            key: None,
            kind: 0,
            next_uid: 0,
            random: false,
        },
        None,
        MonoInstant(0),
        Duration(2),
    )?;
    client.advance(MonoInstant(2))?;
    assert_eq!(client.take(expires)?.outcome, Outcome::TimedOut);
    let reserve = client.submit(
        Request::Reserve {
            amount: 1,
            entries: 1,
        },
        None,
        MonoInstant(2),
        Duration(2),
    )?;
    send(&mut client, epoch, 3)?;
    client.advance(MonoInstant(4))?;
    assert!(!client.needs_retire());
    assert_eq!(client.next_deadline(), Some(MonoInstant(9)));
    client.advance(MonoInstant(9))?;
    assert!(client.needs_retire());
    client.retire(epoch, MonoInstant(9))?;
    assert_eq!(client.take(reserve)?.outcome, Outcome::ReservationLost);
    let second = client.begin_connection(MonoInstant(10))?;
    let drop = client.submit(Request::Drop, None, MonoInstant(10), Duration(10))?;
    send(&mut client, second, 11)?;
    assert_eq!(client.take(drop)?.outcome, Outcome::DropUnconfirmed);
    assert!(client.needs_retire());
    client.retire(second, MonoInstant(12))?;
    assert!(!client.connection_needed());
    assert_eq!(client.begin_connection(MonoInstant(13)), Err(Error::Closed));
    Ok(())
}
