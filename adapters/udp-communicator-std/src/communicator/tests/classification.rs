//! Original private TCP/UDP inputs; no C, LAN or NAT interoperability claim.
use super::*;

fn refusal() -> io::Error {
    io::Error::other("fixture classification unavailable")
}
fn refused(event: Option<Activity>, remote: PeerId, target: SocketAddr, use_: AddressUse) -> Test {
    check(matches!(event, Some(Activity::ClassificationFailed {
        peer, target: actual, operation, error,
    }) if peer == remote && actual == target && operation == use_
        && error.to_string() == "fixture classification unavailable"))
}
async fn load(owner: &mut Communicator<'_>, service: &mut TcpStream, bytes: &[u8]) -> Test {
    service.write_all(bytes).await?;
    while owner.io.frame().is_none() {
        poll_fn(|cx| owner.io.poll_read(cx)).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn classification_refusal_preserves_mq_replay_kid_and_healthy_endpoint() -> Test {
    tokio::time::timeout(Duration::from_secs(5), async {
        let scratch = Scratch::new()?;
        let local = Identity::from_seed([3; 32]);
        let remote = Identity::from_seed([5; 32]);
        let a = UdpSocket::bind("127.0.0.1:0").await?;
        let b = UdpSocket::bind("127.0.0.1:0").await?;
        let target = a.local_addr()?;
        let other = b.local_addr()?;
        let (mut owner, mut service) = owner(&local).await?;
        let address = owner.sockets[0].local_address();
        let generation = owner.transport_generation();
        let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
        let reject = Cell::new(false);
        drain(&mut owner).await?;
        check(matches!(Request::decode(&read_frame(&mut service).await?)?, Request::Register { .. }))?;

        load(&mut owner, &mut service, &create(remote.peer(), target)?).await?;
        refused(owner.command(&local, &mut journal, 100, &mut Random(&reject), &mut |_| Err(refusal()))?,
            remote.peer(), target, AddressUse::Create { request: [1, 2, 3, 4] })?;
        check(owner.io.frame().is_none() && owner.endpoints() == 0)?;
        drain(&mut owner).await?;
        check(matches!(Request::decode(&read_frame(&mut service).await?)?, Request::Created([1, 2, 3, 4], false)))?;

        let mut sender = Sender::new(remote.peer(), local.peer(), owner.sockets[0].profile().sender_policy(), 100)?;
        let message = [0, 5, 0, 0, 0x44];
        let initial = sender.initial(&remote, &message, 10, 100, &mut Random(&reject))?;
        a.send_to(initial.bytes(), address).await?;
        let receipt = owner.sockets[0].receive().await?;
        refused(owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| Err(refusal()))?,
            remote.peer(), target, AddressUse::Initial)?;
        check(journal.latest(remote.peer())?.is_none() && owner.peers() == 0 && owner.endpoints() == 0 && owner.effects.is_empty())?;

        // Retransmit the exact signed KX after the provider recovers.
        a.send_to(initial.bytes(), address).await?;
        let receipt = owner.sockets[0].receive().await?;
        check(matches!(owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| Ok(1))?, Some(Activity::Incoming { boxed: false, .. })))?;
        check(journal.latest(remote.peer())? == Some(10) && owner.peers() == 1 && owner.endpoints() == 1)?;
        drain(&mut owner).await?;
        let _queue = setup(&read_frame(&mut service).await?)?;
        let ack = read_frame(&mut service).await?;
        let Request::Backchannel { message: ack, .. } = Request::decode(&ack)? else {
            return Err("expected actual KX acknowledgement".into());
        };
        sender.acknowledge(local.peer(), Ack::decode_backchannel(ack)?, 100)?;
        check(matches!(Request::decode(&read_frame(&mut service).await?)?, Request::Incoming { message: actual, .. } if actual == message))?;

        let boxed = sender.boxed(&remote, &message, 101, &mut Random(&reject))?;
        let mut forged = boxed.bytes().to_vec();
        forged[32] ^= 1;
        b.send_to(&forged, address).await?;
        let receipt = owner.sockets[0].receive().await?;
        let calls = Cell::new(0);
        check(matches!(owner.incoming(0, &local, &mut journal, receipt, 101, &mut |_| {
            calls.set(calls.get() + 1); Err(refusal())
        })?, Some(Activity::Discarded(Error::Authentication))))?;
        check(calls.get() == 0)?;

        b.send_to(boxed.bytes(), address).await?;
        let receipt = owner.sockets[0].receive().await?;
        refused(owner.incoming(0, &local, &mut journal, receipt, 101, &mut |_| Err(refusal()))?,
            remote.peer(), other, AddressUse::Boxed)?;
        let index = owner.peer_index(remote.peer()).ok_or(Error::NotFound)?;
        check(owner.peers[index].as_ref().ok_or(Error::NotFound)?.receiver.available() == 128
            && owner.endpoints() == 1 && owner.effects.is_empty())?;

        // The original live address needs no new classification and can admit
        // the exact refused BOX while the provider is still unavailable.
        a.send_to(boxed.bytes(), address).await?;
        let receipt = owner.sockets[0].receive().await?;
        check(matches!(owner.incoming(0, &local, &mut journal, receipt, 101, &mut |_| Err(refusal()))?, Some(Activity::Incoming { boxed: true, .. })))?;
        check(owner.peers[index].as_ref().ok_or(Error::NotFound)?.receiver.available() == 127)?;
        drain(&mut owner).await?;
        check(matches!(Request::decode(&read_frame(&mut service).await?)?, Request::Incoming { message: actual, .. } if actual == message))?;
        check(owner.sockets[0].local_address() == address && owner.transport_generation() == generation
            && owner.transport_attached() && !owner.is_closed())?;
        owner.close();
        Ok(())
    }).await?
}

#[tokio::test(flavor = "current_thread")]
async fn hint_and_passive_probe_classification_failures_consume_only_their_inputs() -> Test {
    tokio::time::timeout(Duration::from_secs(5), async {
        let scratch = Scratch::new()?;
        let local = Identity::from_seed([3; 32]);
        let remote = Identity::from_seed([5; 32]);
        let source = UdpSocket::bind("127.0.0.1:0").await?;
        let target = source.local_addr()?;
        let instance = burst::Instance::new();
        let (mut owner, _service) = owner(&local).await?;
        owner.enable_burst(
            &instance,
            Arc::new(gnunet_service_runtime::clock::SystemClock),
            Default::default(),
        )?;
        owner.enable_discovery(Default::default())?;
        let address = owner.sockets[0].local_address();
        let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
        drain(&mut owner).await?;

        // Build a signature for the actual loopback source below the LAN
        // snapshot validator. It is sent only to the private loopback socket.
        let state = owner.discovery.as_mut().ok_or(Error::NotReady)?;
        state.rows.push(discovery::Row {
            interface: discovery::Interface {
                source: target,
                index: 1,
                broadcast: None,
            },
            due: 100,
            join_due: 100,
            packet: None,
        });
        let signed = state.packet(0, &remote)?;
        state.rows.clear();
        source.send_to(&signed, address).await?;
        let receipt = owner.sockets[0].receive().await?;
        refused(
            owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| {
                Err(refusal())
            })?,
            remote.peer(),
            target,
            AddressUse::Discovery,
        )?;
        check(owner.take_discovered().is_none() && owner.effects.is_empty())?;
        source.send_to(&signed, address).await?;
        let receipt = owner.sockets[0].receive().await?;
        check(matches!(
            owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| Ok(1))?,
            Some(Activity::Discovered)
        ))?;
        check(owner.take_discovered().is_some_and(|hint| {
            hint.peer == remote.peer() && hint.source == target && hint.network == 1
        }))?;

        let probe = gnunet_nat_burst_host::wire::BurstMessage {
            peer: remote.peer(),
            local_port: 0,
        }
        .to_bytes(
            owner
                .burst
                .as_ref()
                .ok_or(Error::NotReady)?
                .policy
                .remote_order,
        );
        source.send_to(&probe, address).await?;
        let receipt = owner.sockets[0].receive().await?;
        refused(
            owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| {
                Err(refusal())
            })?,
            remote.peer(),
            target,
            AddressUse::Probe,
        )?;
        check(owner.endpoints() == 0 && owner.peers() == 0 && owner.effects.is_empty())?;
        source.send_to(&probe, address).await?;
        let receipt = owner.sockets[0].receive().await?;
        check(matches!(
            owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| Ok(1))?,
            Some(Activity::Burst)
        ))?;
        check(
            owner.endpoints() == 1
                && owner.peers() == 0
                && owner.effects.len() == 1
                && owner.transport_attached()
                && !owner.is_closed(),
        )?;
        owner.close();
        Ok(())
    })
    .await?
}
