//! Actual frame ownership, loss and verified identity boundaries.
use super::*;
#[tokio::test(flavor = "current_thread")]
async fn forever_clock_does_not_turn_a_waiting_peer_into_ready_work()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([53; 32]);
    let b = Identity::from_seed([54; 32]);
    let (identity, remote) = if gnunet_core::wire::is_initiator(
        a.public_key().as_bytes(),
        b.public_key().as_bytes(),
        WordOrder::Little,
    ) {
        (&b, &a)
    } else {
        (&a, &b)
    };
    let mut host = Host::with_clock(
        identity,
        b"",
        PeerClass::UNKNOWN,
        endpoint()?,
        Limits::default(),
        ServiceOptions::default(),
        Arc::new(ManualClock::new(u64::MAX)),
    )?;
    host.connect_now = false;
    host.retry_at = u64::MAX;
    let mut bytes = [0; 40];
    tr::Response::Connected(tr::PeerId(*remote.public_key().as_bytes())).encode(&mut bytes)?;
    host.transport_frame(&bytes, u64::MAX)?;
    assert!(!host.maintenance(u64::MAX)?);
    assert!(!host.maintenance(u64::MAX)?);
    host.shutdown();
    Ok(())
}
fn established_sessions<'a>(
    a: &'a Identity,
    b: &'a Identity,
) -> Result<(Session<'a, 1024>, Session<'a, 1024>), Error> {
    let mut sa = Session::new(a, b.public_key(), WordOrder::Little, b"")?;
    let mut sb = Session::new(b, a.public_key(), WordOrder::Little, b"")?;
    let (i, r) = if sa.phase() == Phase::Ready {
        (&mut sa, &mut sb)
    } else {
        (&mut sb, &mut sa)
    };
    let mut out = vec![0; 65535];
    let mut plain = vec![0; 65535];
    let CryptoEvent::Send(n) = i.tick(0, &mut Random, &mut out)? else {
        return Err(Error::NotReady);
    };
    let ih = out[..n].to_vec();
    let CryptoEvent::Send(n) = r.receive(0, &ih, &mut Random, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let rh = out[..n].to_vec();
    let CryptoEvent::Send(n) = i.receive(0, &rh, &mut Random, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let done = out[..n].to_vec();
    let CryptoEvent::Established(n) = r.receive(0, &done, &mut Random, &mut out, &mut plain)?
    else {
        return Err(Error::NotReady);
    };
    let ack = out[..n].to_vec();
    assert_eq!(
        i.receive(0, &ack, &mut Random, &mut out, &mut plain)?,
        CryptoEvent::Established(0)
    );
    Ok((sa, sb))
}
#[tokio::test(flavor = "current_thread")]
async fn plaintext_waits_for_real_transport_credit_and_admitted_ciphertext_is_original()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([64; 32]);
    let b = Identity::from_seed([65; 32]);
    let (session, mut remote) = established_sessions(&a, &b)?;
    let clock = Arc::new(ManualClock::new(0));
    let mut host = Host::with_clock(
        &a,
        b"",
        PeerClass::UNKNOWN,
        endpoint()?,
        Limits {
            io_slice_bytes: 1,
            ..Default::default()
        },
        ServiceOptions::default(),
        clock,
    )?;
    let id = PeerId(*b.public_key().as_bytes());
    host.peers.insert(
        id,
        Peer {
            session,
            credits: 0,
            ciphertexts: VecDeque::new(),
            bytes: 0,
            state: 7,
            timeout: 30_000_000,
        },
    );
    let (connection, mut stream) = pair()?;
    host.attach_transport(connection)?;
    init(&mut host.applications, 1, 0, &[0])?;
    connected(&mut host.applications, id);
    drop(outputs(&mut host.applications, 1));
    request(&mut host.applications, 1, id, 8, 1)?;
    send(&mut host.applications, 1, id, &MESSAGE)?;
    host.maintenance(0)?;
    assert!(host.applications.submission(0).is_some());
    assert!(host.peers[&id].ciphertexts.is_empty());
    let mut credit = [0; 40];
    tr::Response::SendCredit(tr::PeerId(id.0)).encode(&mut credit)?;
    host.transport_frame(&credit, 0)?;
    host.maintenance(0)?;
    assert!(host.applications.submission(0).is_none());
    assert!(host.peers[&id].ciphertexts.is_empty());
    assert_eq!(host.peers[&id].credits, 0);
    let actual = alongside(&mut host, async {
        let first = frame(&mut stream).await?;
        let second = frame(&mut stream).await?;
        Ok((first, second))
    })
    .await?;
    assert!(matches!(
        tr::Request::decode(&actual.0)?,
        tr::Request::Start(_)
    ));
    let tr::Request::Send {
        priority, message, ..
    } = tr::Request::decode(&actual.1)?
    else {
        return Err("expected real queued TRANSPORT_SEND".into());
    };
    assert_eq!(priority, 1);
    let mut out = vec![0; 65535];
    let mut plain = vec![0; 65535];
    assert_eq!(
        remote.receive(0, message, &mut Random, &mut out, &mut plain)?,
        CryptoEvent::Payload(8)
    );
    assert_eq!(&plain[..8], MESSAGE);
    host.shutdown();
    assert_eq!(stream.read(&mut [0; 1]).await?, 0);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn authenticated_association_loss_discards_unadmitted_work_before_app_disconnect()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([66; 32]);
    let b = Identity::from_seed([67; 32]);
    let (session, _remote) = established_sessions(&a, &b)?;
    let clock = Arc::new(ManualClock::new(0));
    let mut host = Host::with_clock(
        &a,
        b"",
        PeerClass::UNKNOWN,
        endpoint()?,
        Limits::default(),
        ServiceOptions::default(),
        clock,
    )?;
    let id = PeerId(*b.public_key().as_bytes());
    host.peers.insert(
        id,
        Peer {
            session,
            credits: 0,
            ciphertexts: VecDeque::new(),
            bytes: 0,
            state: 7,
            timeout: 30_000_000,
        },
    );
    init(&mut host.applications, 1, 0, &[0])?;
    connected(&mut host.applications, id);
    drop(outputs(&mut host.applications, 1));
    request(&mut host.applications, 1, id, 8, 1)?;
    send(&mut host.applications, 1, id, &MESSAGE)?;
    request(&mut host.applications, 1, id, 8, 2)?;
    host.peers
        .get_mut(&id)
        .ok_or(Error::Stale)?
        .enqueue(vec![0, 4, 0, 85], 0);
    let original_phase = host.peers[&id].session.phase();
    let original_deadline = host.peers[&id].session.next_deadline();
    assert!(host.peers[&id].session.established());
    host.maintenance(300_000_000)?;
    let report = host.report();
    assert_eq!(report.transport_disconnections, 0);
    assert_eq!(report.association_expirations, 1);
    assert_eq!(report.transport_losses, 0);
    assert_eq!(
        report.first_peer_loss,
        Some(PeerLoss {
            origin: PeerLossOrigin::AssociationExpired,
            peer: id,
            phase: original_phase,
            established: true,
            next_deadline: original_deadline,
            observed_at: 300_000_000,
            send_credits: 0,
            queued_ciphertexts: 1,
            queued_ciphertext_bytes: 4,
        })
    );
    assert!(!host.peers[&id].session.established());
    assert!(host.peers[&id].ciphertexts.is_empty());
    assert!(host.applications.find_submission(|_| true).is_none());
    let frames = outputs(&mut host.applications, 1);
    assert!(
        matches!(Response::decode(frames.last().ok_or(Error::NotReady)?,ClassOrder::Little)?,Response::Disconnected(peer) if peer==id)
    );
    send(&mut host.applications, 1, id, &MESSAGE)?;
    assert!(host.applications.find_submission(|_| true).is_none());
    host.shutdown();
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn transport_peer_loss_ignores_unknown_and_unconfirmed_and_retains_first_origin()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([78; 32]);
    let b = Identity::from_seed([79; 32]);
    let (session, _remote) = established_sessions(&a, &b)?;
    let mut host = Host::with_clock(
        &a,
        b"",
        PeerClass::UNKNOWN,
        endpoint()?,
        Limits::default(),
        ServiceOptions::default(),
        Arc::new(ManualClock::new(0)),
    )?;
    let id = PeerId(*b.public_key().as_bytes());
    host.peers.insert(
        id,
        Peer {
            session,
            credits: tr::SEND_WINDOW,
            ciphertexts: VecDeque::new(),
            bytes: 0,
            state: u32::MAX,
            timeout: 0,
        },
    );
    init(&mut host.applications, 1, 0, &[0])?;
    host.peer_state(id); // Publish the actually formed CAKE association.
    drop(outputs(&mut host.applications, 1));
    host.peers
        .get_mut(&id)
        .ok_or(Error::Stale)?
        .enqueue(vec![0, 4, 0, 85], 0);
    let phase = host.peers[&id].session.phase();
    let next_deadline = host.peers[&id].session.next_deadline();
    assert!(host.peers[&id].session.established());
    let mut bytes = [0; 40];
    tr::Response::Disconnected(tr::PeerId(id.0)).encode(&mut bytes)?;
    host.transport_frame(&bytes, 12_345)?;
    let first = PeerLoss {
        origin: PeerLossOrigin::TransportDisconnected,
        peer: id,
        phase,
        established: true,
        next_deadline,
        observed_at: 12_345,
        send_credits: tr::SEND_WINDOW,
        queued_ciphertexts: 1,
        queued_ciphertext_bytes: 4,
    };
    assert!(!host.peers.contains_key(&id));
    assert_eq!(host.report().first_peer_loss, Some(first));
    assert_eq!(host.report().transport_disconnections, 1);
    assert_eq!(host.report().association_expirations, 0);
    let frames = outputs(&mut host.applications, 1);
    assert!(matches!(
        Response::decode(frames.last().ok_or(Error::NotReady)?, ClassOrder::Little)?,
        Response::Disconnected(peer) if peer == id
    ));
    // An absent peer and a real, still-unconfirmed Session cannot claim this
    // public authenticated-association loss or replace its first observation.
    host.transport_frame(&bytes, 9_000)?;
    host.peers.insert(
        id,
        Peer {
            session: Session::new(&a, b.public_key(), WordOrder::Little, b"")?,
            credits: tr::SEND_WINDOW,
            ciphertexts: VecDeque::new(),
            bytes: 0,
            state: u32::MAX,
            timeout: 0,
        },
    );
    assert!(!host.peers[&id].session.established());
    host.transport_frame(&bytes, 10_000)?;
    assert_eq!(host.report().transport_disconnections, 1);
    assert_eq!(host.report().first_peer_loss, Some(first));
    let (session, _remote) = established_sessions(&a, &b)?;
    host.peers.insert(
        id,
        Peer {
            session,
            credits: 0,
            ciphertexts: VecDeque::new(),
            bytes: 0,
            state: u32::MAX,
            timeout: 0,
        },
    );
    host.peer_state(id);
    drop(outputs(&mut host.applications, 1));
    host.maintenance(300_000_000)?;
    assert!(!host.peers[&id].session.established());
    assert_eq!(host.report().association_expirations, 1);
    assert_eq!(host.report().transport_disconnections, 1);
    assert_eq!(host.report().transport_losses, 0);
    assert_eq!(host.report().first_peer_loss, Some(first));
    host.shutdown();
    assert_eq!(host.report().first_peer_loss, Some(first));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn actual_pils_feed_binds_expiration_context_hash_and_explicit_profile_before_publication()
-> Result<(), Box<dyn std::error::Error>> {
    use gnunet_hello::{HelloBuilder, Limits as HelloLimits};
    use gnunet_pils::{MasterKey, Profile, Service};
    use gnunet_wire::official::{AbsoluteTime, pils::PeerUpdate};
    let limits = HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 65535,
        maximum_addresses: 128,
    };
    let master = MasterKey::from_seed([93; 32]);
    let service = Service::<4096>::new(
        MasterKey::from_seed([93; 32]),
        Profile::Reference029,
        10_000_000,
        limits,
    )?;
    let clock = Arc::new(ManualClock::new(10_000_000));
    let (connection, mut stream) = pair()?;
    let mut feed = startup::PilsFeed::with_clock(connection, clock.clone())?;
    for part in service.announcement().chunks(3) {
        stream.write_all(part).await?;
    }
    let initial = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| feed.poll_identity(cx, &master)),
    )
    .await??;
    assert_eq!(initial.public_key(), service.identity().public_key());
    let hash = [99; 64];
    let key = master.with_active_seed(&hash, Profile::Reference029, |seed| {
        gnunet_crypto::EddsaPrivateKey::from_seed(*seed)
    })?;
    let mut empty = [];
    let builder = HelloBuilder::new(&mut empty, limits);
    let hello = builder.sign(
        &key,
        AbsoluteTime::from_micros(u64::MAX),
        Profile::Reference029.hello(),
    )?;
    let mut block = vec![0; hello.block_len()?];
    hello.encode_block(&mut block)?;
    let mut invalid = vec![0; block.len() + 72];
    PeerUpdate {
        hash,
        block: &block,
    }
    .encode(&mut invalid)?;
    stream.write_all(&invalid).await?;
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| feed.poll_identity(cx, &master))
        )
        .await?,
        Err(HostError::Protocol(Error::Authentication))
    ));
    clock.change(10_000_000 + gnunet_pils::HELLO_LIFETIME + 1, false)?;
    stream.write_all(service.announcement()).await?;
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| feed.poll_identity(cx, &master))
        )
        .await?,
        Err(HostError::Protocol(Error::Timeout))
    ));
    let (connection, mut stream) = pair()?;
    let mut other = startup::PilsFeed::with_profile(
        connection,
        Arc::new(ManualClock::new(10_000_000)),
        Profile::Lsd0014Text,
    )?;
    stream.write_all(service.announcement()).await?;
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| other.poll_identity(cx, &master))
        )
        .await?,
        Err(HostError::Protocol(Error::Authentication))
    ));
    Ok(())
}
