//! A service can announce a new link before it parses an old committed SEND.
use super::*;
#[tokio::test(flavor = "current_thread")]
async fn review_same_identity_late_old_send_ok_is_not_extra_new_credit()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([92; 32]);
    let b = (1u8..=100)
        .map(|n| Identity::from_seed([n; 32]))
        .find(|b| {
            Session::<1024>::new(&a, b.public_key(), WordOrder::Little, b"")
                .is_ok_and(|s| s.phase() == Phase::Ready)
        })
        .ok_or("no initiator test identity")?;
    let id = PeerId(*b.public_key().as_bytes());
    let mut host = Host::with_clock(
        &a,
        b"",
        PeerClass::SERVER,
        endpoint()?,
        Limits::default(),
        ServiceOptions::default(),
        Arc::new(ManualClock::new(0)),
    )?;
    let (connection, mut stream) = pair()?;
    host.attach_transport(connection)?;
    let mut bytes = [0; 40];
    tr::Response::Connected(tr::PeerId(id.0)).encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    let old = alongside(&mut host, async {
        let start = frame(&mut stream).await?;
        let send = frame(&mut stream).await?;
        Ok((start, send))
    })
    .await?;
    assert!(matches!(tr::Request::decode(&old.1)?,tr::Request::Send{peer,..}if peer.0==id.0));
    for event in [
        tr::Response::Disconnected(tr::PeerId(id.0)),
        tr::Response::Connected(tr::PeerId(id.0)),
    ] {
        event.encode(&mut bytes)?;
        stream.write_all(&bytes).await?;
    }
    let new = alongside(&mut host, async { Ok(frame(&mut stream).await?) }).await?;
    assert!(matches!(tr::Request::decode(&new)?,tr::Request::Send{peer,..}if peer.0==id.0));
    // Original physical TX FIFO has now emitted one old and one new SEND.
    // The service refunds both once, in that same order, after new CONNECT.
    for _ in 0..2 {
        tr::Response::SendCredit(tr::PeerId(id.0)).encode(&mut bytes)?;
        stream.write_all(&bytes).await?;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), host.drive(&[], |_| {}))
            .await
            .is_err()
    );
    assert!(
        host.transport.is_some(),
        "old-generation refund poisoned the new physical MQ"
    );
    assert_eq!(
        host.peers.get(&id).map(|p| p.credits),
        Some(tr::SEND_WINDOW)
    );
    host.shutdown();
    Ok(())
}
