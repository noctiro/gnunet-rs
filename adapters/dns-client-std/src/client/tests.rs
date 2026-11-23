//! Original callback capacity and expiry tests without an attached socket.
use super::*;
use gnunet_service_runtime::clock::SystemClock;

fn callback<'a>(epoch: Epoch<'a>, number: u8, until: u64, hard: Instant) -> Row<'a> {
    Row {
        token: Request {
            epoch,
            serial: u64::from(number),
        },
        id: [number; 8],
        until,
        hard,
        drain: None,
        reply: None,
        queued: false,
        sent: 0,
        total: 0,
        charge: 0,
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Original callback tokens, budgets and deadlines are the regression contract"
)]
fn full_reply_budget_preserves_expired_drops_and_other_callbacks() -> Result<(), Error> {
    let owner = Instance::new();
    let limits = Limits {
        requests: 3,
        frame_bytes: 64,
        source_bytes: 32,
        ..Limits::default()
    };
    let mut client = Client::new(
        &owner,
        EndpointSource::unix_with_clock(
            std::path::PathBuf::from("dns-client-budget-fixture"),
            Arc::new(SystemClock),
        ),
        ipc::POST_RESOLUTION,
        limits,
    )?;
    let epoch = Epoch {
        owner: &owner,
        allocation: client.allocation,
        serial: 1,
    };
    let hard = Instant::now() + Duration::from_secs(60);
    client.epoch = Some(epoch);
    client.rows.extend([
        callback(epoch, 2, 2, hard),
        callback(epoch, 3, 50, hard),
        callback(epoch, 4, 4, hard),
    ]);
    let first = client.rows[0].token;
    let last = client.rows[2].token;
    client.set_reply(1, ipc::Decision::Answer(&[7; 16]))?;
    assert_eq!(client.bytes, limits.source_bytes);
    assert!(
        client
            .read(&mut Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );

    assert!(client.expire(10)?.is_none());
    let drain = client.rows[0].drain.ok_or(Fault::NotReady)?;
    assert_eq!(client.rows[2].drain, Some(drain));
    assert!(drain <= hard);
    assert_eq!(client.epoch(), Some(epoch));
    assert!(client.rows[1].reply.is_some());
    assert!(matches!(
        client.reply(last, ipc::Decision::Forward),
        Err(Error::Protocol(Fault::Deadline))
    ));

    // Release the separate reply reservation to exercise the same expiry
    // admission again, without claiming any socket or write observation.
    let released = client.rows.remove(1);
    client.bytes -= released.charge;
    assert_eq!(client.expire(1)?, Some(first));
    assert_eq!(client.expire(1)?, Some(last));
    assert!(client.expire(1)?.is_none());
    for row in &client.rows {
        assert_eq!(row.drain, Some(drain));
        let frame = row.reply.as_ref().ok_or(Fault::NotReady)?;
        assert!(matches!(
            ipc::Request::decode(frame.bytes())?,
            ipc::Request::Reply { id, decision: ipc::Decision::Drop } if id == row.id
        ));
    }
    Ok(())
}
