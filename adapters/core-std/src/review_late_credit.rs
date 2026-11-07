//! Independent actual Unix MQ witness. Normal C explicitly permits late SEND_OK.
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn review_actual_late_send_ok_keeps_other_peer_and_original_mq()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([92; 32]);
    let b = (1u8..=100)
        .map(|n| Identity::from_seed([n; 32]))
        .find(|b| {
            Session::<1024>::new(&a, b.public_key(), WordOrder::Little, b"")
                .is_ok_and(|s| s.phase() == Phase::Ready)
        })
        .ok_or("no initiator test identity")?;
    let c = Identity::from_seed([110; 32]);
    let aid = PeerId(*b.public_key().as_bytes());
    let bid = PeerId(*c.public_key().as_bytes());
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
    tr::Response::Connected(tr::PeerId(aid.0)).encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    let first = alongside(&mut host, async {
        let start = frame(&mut stream).await?;
        let send = frame(&mut stream).await?;
        Ok((start, send))
    })
    .await?;
    assert!(matches!(
        tr::Request::decode(&first.0)?,
        tr::Request::Start(_)
    ));
    assert!(matches!(tr::Request::decode(&first.1)?, tr::Request::Send{peer,..} if peer.0==aid.0));
    // The original SEND has actually left this MQ. A service DISCONNECT can cross
    // that SEND; C still sends its SEND_OK, and its public client ignores it.
    for event in [
        tr::Response::Connected(tr::PeerId(bid.0)),
        tr::Response::Disconnected(tr::PeerId(aid.0)),
        tr::Response::SendCredit(tr::PeerId(aid.0)),
    ] {
        event.encode(&mut bytes)?;
        stream.write_all(&bytes).await?;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), host.drive(&[], |_| {}))
            .await
            .is_err()
    );
    assert!(!host.peers.contains_key(&aid));
    assert!(
        host.transport.is_some(),
        "late original SEND_OK retired the entire physical MQ"
    );
    assert!(
        host.peers.contains_key(&bid),
        "unrelated peer was lost due to late credit"
    );
    host.shutdown();
    Ok(())
}
