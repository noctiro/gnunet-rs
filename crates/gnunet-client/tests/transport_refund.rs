//! Original connection/generation send-refund ownership regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Ownership assertions identify protocol regressions"
)]
use gnunet_client::transport::{
    Event, Instance, PeerId, Request, Response, SendOutcome, Start, TransportClient,
};
use gnunet_types::Error;
const PEER: PeerId = PeerId([17; 32]);
const MESSAGE: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];
#[test]
fn same_identity_refund_returns_to_retired_budget_not_new_peer() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut client = TransportClient::<2, 4, 8>::new(&mut instance, Start::new(None, true))?;
    let mut out = [0; 128];
    let (epoch, _) = client.begin(&mut out)?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(mut old) = client.receive(epoch, &out[..n])? else {
        return Err(Error::NotReady);
    };
    for _ in 0..16 {
        let (send, n) = client.prepare_send(old, 0, &MESSAGE, &mut out)?;
        assert!(matches!(Request::decode(&out[..n])?, Request::Send { .. }));
        client.send_bytes_written(send, n)?;
        assert_eq!(client.take_send_result(send)?, SendOutcome::Written);
        let n = Response::Disconnected(PEER).encode(&mut out)?;
        client.receive(epoch, &out[..n])?;
        let n = Response::Connected(PEER).encode(&mut out)?;
        let Event::Connected(new) = client.receive(epoch, &out[..n])? else {
            return Err(Error::NotReady);
        };
        assert_eq!(client.send_credit(old), Err(Error::Stale));
        let (send, n) = client.prepare_send(new, 0, &MESSAGE, &mut out)?;
        client.send_bytes_written(send, n)?;
        let n = Response::SendCredit(PEER).encode(&mut out)?;
        assert_eq!(
            client.receive(epoch, &out[..n])?,
            Event::LateSendCredit(PEER)
        );
        assert_eq!(client.send_credit(new)?, 3);
        assert_eq!(client.receive(epoch, &out[..n])?, Event::SendCredit(new));
        assert_eq!(client.send_credit(new)?, 4);
        assert_eq!(client.take_send_result(send)?, SendOutcome::Written);
        old = new;
    }
    Ok(())
}

#[test]
fn old_unwritten_cancel_releases_only_its_deferred_promise() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut c = TransportClient::<1, 3, 4>::new(&mut instance, Start::new(None, true))?;
    let mut out = [0; 128];
    let (e, _) = c.begin(&mut out)?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(old) = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let (old_send, _) = c.prepare_send(old, 0, &MESSAGE, &mut out)?;
    let n = Response::Disconnected(PEER).encode(&mut out)?;
    c.receive(e, &out[..n])?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(new) = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let (send, n) = c.prepare_send(new, 0, &MESSAGE, &mut out)?;
    c.send_bytes_written(send, n)?;
    let n = Response::SendCredit(PEER).encode(&mut out)?;
    assert_eq!(c.receive(e, &out[..n])?, Event::SendCredit(new));
    assert_eq!(c.send_credit(new)?, 4);
    c.cancel_unwritten(old_send)?;
    assert_eq!(c.send_credit(new)?, 4);
    assert_eq!(c.take_send_result(old_send)?, SendOutcome::CancelledUnsent);
    assert_eq!(c.cancel_unwritten(old_send), Err(Error::Stale));
    assert_eq!(c.take_send_result(send)?, SendOutcome::Written);
    Ok(())
}
#[test]
fn retired_unwritten_frame_can_start_and_drain_without_new_generation_credit() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut c = TransportClient::<1, 3, 4>::new(&mut instance, Start::new(None, true))?;
    let mut out = [0; 128];
    let (e, _) = c.begin(&mut out)?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(old) = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let (old_send, old_len) = c.prepare_send(old, 0, &MESSAGE, &mut out)?;
    let n = Response::Disconnected(PEER).encode(&mut out)?;
    c.receive(e, &out[..n])?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(new) = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let (send, len) = c.prepare_send(new, 0, &MESSAGE, &mut out)?;
    c.send_bytes_written(old_send, 1)?;
    assert_eq!(c.cancel_unwritten(old_send), Err(Error::Conflict));
    c.cancel_started(old_send)?;
    c.send_bytes_written(old_send, old_len - 1)?;
    assert_eq!(
        c.take_send_result(old_send)?,
        SendOutcome::CancelledAfterWrite
    );
    c.send_bytes_written(send, len)?;
    let n = Response::SendCredit(PEER).encode(&mut out)?;
    assert_eq!(c.receive(e, &out[..n])?, Event::LateSendCredit(PEER));
    assert_eq!(c.send_credit(new)?, 3);
    assert_eq!(c.receive(e, &out[..n])?, Event::SendCredit(new));
    assert_eq!(c.send_credit(new)?, 4);
    Ok(())
}
#[test]
fn bounded_refund_accounts_reject_send_before_commit_but_never_block_disconnect()
-> Result<(), Error> {
    const OTHER: PeerId = PeerId([34; 32]);
    let mut instance = Instance::new();
    let mut c = TransportClient::<1, 3, 4, 1>::new(&mut instance, Start::new(None, true))?;
    let mut out = [0; 128];
    let (e, _) = c.begin(&mut out)?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(old) = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let (send, len) = c.prepare_send(old, 0, &MESSAGE, &mut out)?;
    c.send_bytes_written(send, len)?;
    c.take_send_result(send)?;
    let n = Response::Disconnected(PEER).encode(&mut out)?;
    assert!(matches!(c.receive(e, &out[..n])?, Event::Disconnected(_)));
    let n = Response::Connected(OTHER).encode(&mut out)?;
    let Event::Connected(new) = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let mut rejected = [0xa5; 128];
    assert_eq!(
        c.prepare_send(new, 0, &MESSAGE, &mut rejected),
        Err(Error::Capacity)
    );
    assert_eq!(rejected, [0xa5; 128]);
    assert_eq!(c.send_credit(new)?, 4);
    let n = Response::SendCredit(PEER).encode(&mut out)?;
    assert_eq!(c.receive(e, &out[..n])?, Event::LateSendCredit(PEER));
    assert_eq!(c.peer(OTHER), Some(new));
    let (send, _) = c.prepare_send(new, 0, &MESSAGE, &mut out)?;
    c.cancel_unwritten(send)?;
    assert_eq!(c.send_credit(new)?, 4);
    Ok(())
}
#[test]
fn physical_connection_loss_clears_debt_and_old_tokens_cannot_credit_reconnect() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut c = TransportClient::<1, 3, 4, 1>::new(&mut instance, Start::new(None, true))?;
    let mut out = [0; 128];
    let (old_epoch, _) = c.begin(&mut out)?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(old) = c.receive(old_epoch, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let (old_send, _) = c.prepare_send(old, 0, &MESSAGE, &mut out)?;
    let n = Response::Disconnected(PEER).encode(&mut out)?;
    c.receive(old_epoch, &out[..n])?;
    c.connection_lost(old_epoch)?;
    let (epoch, _) = c.begin(&mut out)?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(new) = c.receive(epoch, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let (send, _) = c.prepare_send(new, 0, &MESSAGE, &mut out)?;
    assert_eq!(c.cancel_unwritten(old_send), Err(Error::Conflict));
    assert_eq!(c.send_bytes_written(old_send, 1), Err(Error::Closed));
    assert_eq!(c.take_send_result(old_send)?, SendOutcome::ConnectionLost);
    assert_eq!(c.send_credit(new)?, 3);
    let n = Response::SendCredit(PEER).encode(&mut out)?;
    assert_eq!(c.receive(old_epoch, &out[..n]), Err(Error::Stale));
    assert_eq!(c.send_credit(new)?, 3);
    c.cancel_unwritten(send)?;
    assert_eq!(c.send_credit(new)?, 4);
    Ok(())
}
#[test]
fn zero_refund_storage_supports_receive_only_without_admitting_untracked_send() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut c = TransportClient::<1, 1, 4, 0>::new(&mut instance, Start::new(None, true))?;
    let mut out = [0; 128];
    let (e, _) = c.begin(&mut out)?;
    let n = Response::Connected(PEER).encode(&mut out)?;
    let Event::Connected(peer) = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    assert_eq!(
        c.prepare_send(peer, 0, &MESSAGE, &mut out),
        Err(Error::Capacity)
    );
    assert_eq!(c.send_credit(peer)?, 4);
    let n = Response::Received {
        peer: PEER,
        message: &MESSAGE,
    }
    .encode(&mut out)?;
    let Event::Received { receive, .. } = c.receive(e, &out[..n])? else {
        return Err(Error::NotReady);
    };
    let n = c.complete_receive(receive, &mut out)?;
    assert!(matches!(
        Request::decode(&out[..n])?,
        Request::ReceiveContinue { increase: 1, .. }
    ));
    Ok(())
}
