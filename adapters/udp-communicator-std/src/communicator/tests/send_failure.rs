//! Actual native send refusal and independent healthy loopback transmission.
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn native_destination_failure_keeps_the_shared_socket_and_other_endpoint() -> Test {
    tokio::time::timeout(Duration::from_secs(5), native_failure()).await?
}
async fn native_failure() -> Test {
    let scratch = Scratch::new()?;
    let local = Identity::from_seed([3; 32]);
    let bad = Identity::from_seed([5; 32]);
    let good = Identity::from_seed([7; 32]);
    let destination = UdpSocket::bind("127.0.0.1:0").await?;
    let target = destination.local_addr()?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    let (socket, options, send_bytes) = {
        // A buffer below one atomic datagram yields a native refusal.
        // This reference only observes/restores options on the original
        // socket; it performs no send or receive and is dropped before stop.
        let socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
        let options = socket.shared()?;
        let native = socket2::SockRef::from(options.as_ref());
        let bytes = native.send_buffer_size()?;
        native.set_send_buffer_size(1)?;
        (socket, options, bytes)
    };
    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    let socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    let refused = target;
    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    let refused: SocketAddr = "127.0.0.1:0".parse()?;
    let (mut owner, mut service) = owner_on(&local, socket).await?;
    owner.enable_discovery(Default::default())?;
    owner.update_interfaces(&[])?;
    let original_socket = owner.sockets[0].local_address();
    let original_generation = owner.transport_generation();
    // The optional LAN send uses the production native send path but an opaque
    // fixture packet and a private loopback target. No LAN announcement escapes.
    let interface = crate::discovery::Interface {
        source: original_socket,
        index: 1,
        broadcast: Some(std::net::Ipv4Addr::LOCALHOST),
    };
    let hard = Instant::now() + Duration::from_secs(2);
    owner.sockets[0].queue_discovery(original_socket, 1, refused, 1, [0; 96], hard)?;
    owner.discovery.as_mut().ok_or(Error::Stale)?.pending[0] = Some(crate::discovery::Pending {
        operation: 1,
        interface,
        target: refused,
    });
    let event = poll_fn(|cx| match owner.discovery_step(cx, &local, 100) {
        Ok(Some(event)) => Poll::Ready(Ok(event)),
        Ok(None) => Poll::Pending,
        Err(error) => Poll::Ready(Err(error)),
    })
    .await?;
    check(matches!(event, Activity::DiscoveryFailed {
        socket: 0,
        operation: crate::discovery::Operation::Send { interface: original, target: intended },
        error: SocketError::Io(error),
    } if original == interface && intended == refused && error.raw_os_error().is_some()))?;
    check(
        !owner.sockets[0].has_pending_send()
            && owner.discovery.as_ref().ok_or(Error::Stale)?.pending[0].is_none(),
    )?;
    let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
    let failures = Cell::new(0usize);
    let sent = Cell::new(0usize);
    let stage = Cell::new("registration");
    let reject_entropy = Cell::new(false);
    let driving = drive_observed(&mut owner, &local, &mut journal, &reject_entropy, |event| {
        match event {
            Activity::SendError {
                socket,
                peer,
                target,
                error,
            } => {
                check(
                    socket == 0
                        && peer == bad.peer()
                        && target == refused
                        && error.raw_os_error().is_some(),
                )?;
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                socket2::SockRef::from(options.as_ref()).set_send_buffer_size(send_bytes)?;
                failures.set(failures.get() + 1);
            }
            Activity::NativeSent { .. } => sent.set(sent.get() + 1),
            _ => {}
        }
        Ok(())
    });
    let scenario = async {
        check(matches!(
            Request::decode(&read_frame(&mut service).await?)?,
            Request::Register { .. }
        ))?;
        stage.set("failed destination CREATE");
        service.write_all(&create(bad.peer(), refused)?).await?;
        let bad_queue = setup(&read_frame(&mut service).await?)?;
        check(matches!(
            Request::decode(&read_frame(&mut service).await?)?,
            Request::Created(_, true)
        ))?;
        stage.set("healthy destination CREATE");
        service.write_all(&create(good.peer(), target)?).await?;
        let good_queue = setup(&read_frame(&mut service).await?)?;
        check(matches!(
            Request::decode(&read_frame(&mut service).await?)?,
            Request::Created(_, true)
        ))?;
        stage.set("failed destination SEND result");
        service
            .write_all(&send(bad.peer(), bad_queue, [1; 8], &[0, 5, 0, 0, 0x11])?)
            .await?;
        ack(
            &read_frame(&mut service).await?,
            bad.peer(),
            bad_queue,
            [1; 8],
            false,
        )?;
        stage.set("failed destination DOWN");
        check(
            matches!(Request::decode(&read_frame(&mut service).await?)?,Request::QueueDown(q,p) if q==bad_queue && p==bad.peer()),
        )?;
        let message = [0, 5, 0, 0, 0x22];
        stage.set("healthy destination SEND result");
        service
            .write_all(&send(good.peer(), good_queue, [2; 8], &message)?)
            .await?;
        ack(
            &read_frame(&mut service).await?,
            good.peer(),
            good_queue,
            [2; 8],
            true,
        )?;
        let mut packet = [0; 2048];
        let size = destination.recv(&mut packet).await?;
        let mut scratch = [0; 2048];
        let opened = handshake::open(&good, &packet[..size], &mut scratch)?;
        check(
            opened.sender() == local.peer()
                && gnunet_udp_communicator_core::wire::Body::decode(opened.body())?.message
                    == Some(&message),
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let result: Test = tokio::select! { result=driving=>result, result=scenario=>result };
    result.map_err(|error| -> Box<dyn std::error::Error> {
        format!(
            "stage={} failed={} sent={}: {error}",
            stage.get(),
            failures.get(),
            sent.get()
        )
        .into()
    })?;
    stage.set("original socket and surviving endpoint");
    check(
        failures.get() == 1
            && sent.get() == 1
            && owner.endpoints() == 1
            && owner.sockets[0].local_address() == original_socket
            && owner.transport_generation() == original_generation
            && owner.transport_attached(),
    )?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    drop(options);
    owner.close();
    Ok(())
}
