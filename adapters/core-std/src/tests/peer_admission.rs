//! Peer admission is independent of the original shared TRANSPORT lifetime.
use super::*;

fn host(identity: &Identity) -> Result<Host<'_>, Box<dyn std::error::Error>> {
    Ok(Host::with_clock(
        identity,
        b"",
        PeerClass::SERVER,
        endpoint()?,
        Limits {
            max_peers: 1,
            ..Limits::default()
        },
        ServiceOptions::default(),
        Arc::new(ManualClock::new(0)),
    )?)
}

#[tokio::test(flavor = "current_thread")]
async fn excess_peer_preserves_the_original_mq_and_admitted_session()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed([61; 32]);
    let admitted = Identity::from_seed([62; 32]);
    let excess = Identity::from_seed([63; 32]);
    let mut host = host(&identity)?;
    let (session, _remote) = more_tests::established_sessions(&identity, &admitted)?;
    let admitted = PeerId(*admitted.public_key().as_bytes());
    let excess = PeerId(*excess.public_key().as_bytes());
    let (connection, mut stream) = pair().await?;
    host.attach_transport(connection)?;
    let mut bytes = [0; 40];
    host.peers.insert(
        admitted,
        Peer {
            session,
            credits: tr::SEND_WINDOW,
            ciphertexts: VecDeque::new(),
            bytes: 0,
            state: 7,
            timeout: 30_000_000,
        },
    );
    tr::Response::Connected(tr::PeerId(excess.0)).encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), host.drive(&[], |_| {}))
            .await
            .is_err(),
        "the live host should keep waiting after local admission refusal"
    );
    assert!(
        host.transport.is_some(),
        "excess peer retired the shared MQ"
    );
    assert_eq!(
        host.report.transport_losses, 0,
        "admission is not source loss"
    );
    assert_eq!(
        host.peers.len(),
        1,
        "only the admitted peer consumes a slot"
    );
    assert!(
        host.peers.contains_key(&admitted),
        "admitted session was discarded"
    );
    assert!(
        host.peers[&admitted].session.established(),
        "the original authenticated session must retain its keys and phase"
    );
    assert_eq!(host.report.peer_refusals, 1);
    host.shutdown();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unadmitted_input_returns_credit_without_adding_a_session()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed([71; 32]);
    let admitted = Identity::from_seed([72; 32]);
    let excess = Identity::from_seed([73; 32]);
    let mut host = host(&identity)?;
    let admitted = PeerId(*admitted.public_key().as_bytes());
    let excess = PeerId(*excess.public_key().as_bytes());
    let (connection, mut stream) = pair().await?;
    host.attach_transport(connection)?;
    let mut bytes = [0; 64];
    let n = tr::Response::Connected(tr::PeerId(admitted.0)).encode(&mut bytes)?;
    host.transport_frame(&bytes[..n], 0)?;
    let n = tr::Response::Connected(tr::PeerId(excess.0)).encode(&mut bytes)?;
    assert!(
        host.transport_frame(&bytes[..n], 0).is_ok(),
        "peer capacity refusal must consume the notification"
    );
    let n = tr::Response::Received {
        peer: tr::PeerId(excess.0),
        message: &MESSAGE,
    }
    .encode(&mut bytes)?;
    host.transport_frame(&bytes[..n], 0)?;
    assert_eq!(
        host.peers.len(),
        1,
        "discarded input must not allocate a session"
    );
    assert!(
        host.retired_credits.is_empty(),
        "unadmitted input creates no send debt"
    );
    let (start, credit) = alongside(&mut host, async {
        Ok((frame(&mut stream).await?, frame(&mut stream).await?))
    })
    .await?;
    assert!(matches!(
        tr::Request::decode(&start)?,
        tr::Request::Start(_)
    ));
    assert!(
        matches!(tr::Request::decode(&credit)?,
        tr::Request::ReceiveContinue { peer, increase: 1 } if peer.0 == excess.0),
        "only the actual discarded receive creates credit"
    );
    assert_eq!(host.report.receive_credits, 1);
    assert_eq!(host.report.unadmitted_records, 1);
    assert_eq!(host.report.transport_losses, 0);
    let n = tr::Response::Disconnected(tr::PeerId(admitted.0)).encode(&mut bytes)?;
    host.transport_frame(&bytes[..n], 0)?;
    let n = tr::Response::Disconnected(tr::PeerId(excess.0)).encode(&mut bytes)?;
    host.transport_frame(&bytes[..n], 0)?;
    let n = tr::Response::Connected(tr::PeerId(excess.0)).encode(&mut bytes)?;
    host.transport_frame(&bytes[..n], 0)?;
    assert!(
        host.peers.contains_key(&excess),
        "a later real connection may use freed capacity"
    );
    host.shutdown();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn mandatory_receive_credit_exhaustion_remains_source_fatal()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed([81; 32]);
    let remote = Identity::from_seed([82; 32]);
    let mut host = Host::with_clock(
        &identity,
        b"",
        PeerClass::SERVER,
        endpoint()?,
        Limits {
            max_peers: 1,
            max_pending_frames: 1,
            ..Limits::default()
        },
        ServiceOptions::default(),
        Arc::new(ManualClock::new(0)),
    )?;
    let (connection, _stream) = pair().await?;
    host.attach_transport(connection)?;
    let mut bytes = [0; 64];
    let n =
        tr::Response::Connected(tr::PeerId(*remote.public_key().as_bytes())).encode(&mut bytes)?;
    host.transport_frame(&bytes[..n], 0)?;
    // START holds the ordinary slot. Six actual discarded inputs fill the
    // configured 4*max_peers+2 credit reserve without polling any writes.
    for peer_byte in 1..=6 {
        let peer = tr::PeerId([peer_byte; 32]);
        let n = tr::Response::Connected(peer).encode(&mut bytes)?;
        host.transport_frame(&bytes[..n], 0)?;
        let n = tr::Response::Received {
            peer,
            message: &MESSAGE,
        }
        .encode(&mut bytes)?;
        host.transport_frame(&bytes[..n], 0)?;
    }
    let n = tr::Response::Received {
        peer: tr::PeerId([6; 32]),
        message: &MESSAGE,
    }
    .encode(&mut bytes)?;
    assert!(
        matches!(
            host.transport_frame(&bytes[..n], 0),
            Err(ingress::Failure::Source(Error::Capacity))
        ),
        "a receive cannot be consumed without bounded storage for its credit"
    );
    assert_eq!(host.report.receive_credits, 6);
    assert_eq!(host.report.unadmitted_records, 6);
    assert_eq!(host.peers.len(), 1);
    host.shutdown();
    Ok(())
}
