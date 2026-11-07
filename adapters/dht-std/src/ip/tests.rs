//! Actual private numeric loopback datagrams, not DHT business/C interoperability
//! or authenticated-peer evidence. No interface traffic is emitted by snapshots.
use super::*;
use std::{future::poll_fn, time::Duration};
use tokio::{net::UdpSocket, runtime::Builder};

fn raw_socket(endpoint: SocketAddr) -> Result<UdpSocket, Error> {
    let socket = socket2::Socket::new(
        if endpoint.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if endpoint.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_send_buffer_size(2 * MAX_DATAGRAM_BYTES)?;
    socket.set_recv_buffer_size(2 * MAX_DATAGRAM_BYTES)?;
    if socket.send_buffer_size()? < MAX_DATAGRAM_BYTES
        || socket.recv_buffer_size()? < MAX_DATAGRAM_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw loopback buffers cannot hold a maximum datagram",
        )
        .into());
    }
    socket.set_nonblocking(true)?;
    socket.bind(&endpoint.into())?;
    Ok(UdpSocket::from_std(std::net::UdpSocket::from(socket))?)
}
fn config(ip: IpAddr) -> Config {
    Config {
        bind: Some(ip),
        port: 0,
        packets: 1,
        ..Config::default()
    }
}
fn frame(length: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0x5a; length];
    bytes
        .get_mut(..2)
        .ok_or(Fault::InvalidInput)?
        .copy_from_slice(
            &u16::try_from(length)
                .map_err(|_| Fault::TooLarge)?
                .to_be_bytes(),
        );
    bytes
        .get_mut(2..4)
        .ok_or(Fault::InvalidInput)?
        .copy_from_slice(&135u16.to_be_bytes());
    Ok(bytes)
}
async fn next<'id>(client: &mut Client<'id>) -> Result<Event<'id>, Error> {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(2), poll_fn(|cx| client.poll(cx)))
            .await
            .map_err(|_| Fault::Deadline)??;
        if !matches!(event, Event::AddressesChanged { .. }) {
            return Ok(event);
        }
    }
}
async fn closed(client: &mut Client<'_>) -> Result<(), Error> {
    client.close();
    for _ in 0..1024 {
        if matches!(next(client).await?, Event::Closed) {
            return Ok(());
        }
    }
    Err(Fault::Capacity.into())
}

#[test]
fn isolated_receive_error_preserves_original_send_and_actual_udp_source() -> Result<(), Error> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = Client::new(&mut instance, config(IpAddr::V4(Ipv4Addr::LOCALHOST)))?;
        client.set_identity([1; 32])?;
        let remote = raw_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        let destination = client.local_addrs()[0];
        let peer = client.try_connect([2; 32], format!("ip+udp://{}", remote.local_addr()?).as_bytes())?;
        assert!(matches!(next(&mut client).await?, Event::Connected(actual) if actual == peer));
        let bytes = frame(4)?;
        let send = client.send(peer, &bytes, Instant::now() + Duration::from_secs(2))?;
        let original = next(&mut client).await?;
        assert!(matches!(&original, Event::Finished {
            send: actual, peer: original_peer, outcome: Outcome::Written, written: 36, frame_bytes: 4,
        } if *actual == send && *original_peer == peer), "{original:?}");
        let mut received = [0; 64];
        let (length, sender) = tokio::time::timeout(Duration::from_secs(2), remote.recv_from(&mut received)).await.map_err(|_| Fault::Deadline)??;
        assert_eq!(length, 36);
        assert_eq!(sender, destination);
        assert_eq!(&received[..32], &[1; 32]);
        assert_eq!(&received[32..length], bytes);

        // Model the native result through the production receive branch. This
        // does not claim that this host emitted Linux's asynchronous UDP error.
        let event = client.inject_receive_error(io::Error::from_raw_os_error(libc::ECONNREFUSED))?;
        assert!(matches!(event, Some(Event::ReceiveError { local, error })
            if local == destination && error.raw_os_error() == Some(libc::ECONNREFUSED)));
        assert!(matches!(client.cancel(send), Err(Error::Protocol(Fault::StaleGeneration))));
        assert!(client.request_available(peer, bytes.len())?);
        let mut incoming = [2; 32].to_vec();
        incoming.extend_from_slice(&bytes);
        tokio::time::timeout(Duration::from_secs(2), remote.send_to(&incoming, destination)).await.map_err(|_| Fault::Deadline)??;
        let Event::Message(packet) = next(&mut client).await? else { return Err(Fault::Conflict.into()); };
        assert_eq!(packet.peer(), peer);
        assert_eq!(packet.frame(), bytes);
        client.release(packet)?;
        // The receive error neither requeues the already written send nor
        // manufactures a remote-delivery failure or a replacement generation.
        assert!(matches!(remote.try_recv_from(&mut received), Err(error) if error.kind() == io::ErrorKind::WouldBlock));

        // Resource/descriptor failures are not granted the isolated-error
        // contract. The same buffer loan and branch preserve each native cause.
        for code in [libc::ENOBUFS, libc::ENOMEM, libc::EBADF] {
            assert!(matches!(client.inject_receive_error(io::Error::from_raw_os_error(code)),
                Err(Error::Io(error)) if error.raw_os_error() == Some(code)));
        }
        assert!(matches!(client.inject_receive_error(io::Error::other("opaque registration failure")),
            Err(Error::Io(error)) if error.to_string() == "opaque registration failure"));
        closed(&mut client).await
    })
}

#[test]
fn actual_v4_and_v6_envelopes_maximum_payload_and_original_buffer_reuse() -> Result<(), Error> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        for ip in [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)] {
            let mut instance = Instance::new();
            let mut client = Client::new(&mut instance, config(ip))?;
            client.set_identity([1; 32])?;
            let remote = raw_socket(SocketAddr::new(ip, 0))?;
            let endpoint = remote.local_addr()?;
            let destination = client.local_addrs()[0];
            assert!(client.addresses().iter().any(|address| address.endpoint == destination));
            let peer = client.try_connect([2; 32], format!("ip+udp://{endpoint}").as_bytes())?;
            assert!(matches!(next(&mut client).await?, Event::Connected(actual) if actual == peer));
            let maximum_frame = if ip.is_ipv4() { V4_MAX_FRAME_BYTES } else { MAX_FRAME_BYTES };
            let maximum_datagram = maximum_frame + 32;
            assert_eq!(peer.frame_limit(), maximum_frame);
            assert_eq!(client.frame_limit(), maximum_frame);
            if ip.is_ipv6() { assert_eq!(maximum_frame, V4_MAX_FRAME_BYTES + 20); }
            else {
                let mapped = format!("ip+udp://[::ffff:127.0.0.1]:{}", endpoint.port());
                assert_eq!(client.try_connect([2; 32], mapped.as_bytes())?, peer);
            }
            let unsupported = if ip.is_ipv4() { b"ip+udp://[::1]:1".as_slice() } else { b"ip+udp://127.0.0.1:1".as_slice() };
            assert!(matches!(client.try_connect([3; 32], unsupported), Err(Error::Protocol(Fault::Unsupported))));
            let bytes = frame(maximum_frame)?;
            assert!(client.request_available(peer, bytes.len())?);
            let send = client.send(peer, &bytes, Instant::now() + Duration::from_secs(2))?;
            let event = next(&mut client).await?;
            assert!(matches!(&event, Event::Finished {
                send: actual, peer: original, outcome: Outcome::Written, written,
                frame_bytes,
            } if *actual == send && *original == peer && *written == maximum_datagram && *frame_bytes == maximum_frame), "{event:?}");
            let mut input = vec![0; 65_536];
            let (length, sender) = tokio::time::timeout(Duration::from_secs(2), remote.recv_from(&mut input)).await.map_err(|_| Fault::Deadline)??;
            assert_eq!(sender, destination);
            assert_eq!(length, maximum_datagram);
            assert_eq!(&input[..32], &[1; 32]);
            assert_eq!(&input[32..length], bytes);
            assert!(matches!(client.request_available(peer, maximum_frame + 1), Err(Error::Protocol(Fault::TooLarge))));
            assert!(matches!(client.send(peer, &frame(maximum_frame + 1)?, Instant::now() + Duration::from_secs(2)), Err(Error::Protocol(Fault::TooLarge))));
            input[..32].copy_from_slice(&[2; 32]);
            remote.send_to(&input[..length], destination).await?;
            let Event::Message(packet) = next(&mut client).await? else { return Err(Fault::Conflict.into()); };
            assert_eq!(packet.peer(), peer);
            assert_eq!(packet.frame(), bytes);
            let original_buffer = packet.frame().as_ptr();
            drop(packet);
            remote.send_to(&input[..length], destination).await?;
            let Event::Message(packet) = next(&mut client).await? else { return Err(Fault::Conflict.into()); };
            assert_eq!(packet.frame().as_ptr(), original_buffer);
            client.release(packet)?;
            let mut malformed = [2; 32].to_vec(); malformed.extend(frame(4)?); malformed.push(0);
            remote.send_to(&malformed, destination).await?;
            assert!(matches!(next(&mut client).await?, Event::Discarded { endpoint: actual, reason: Fault::InvalidInput } if actual == endpoint));
            closed(&mut client).await?;
        }
        Ok(())
    })
}

#[test]
fn bounded_eviction_cancellation_and_original_deadline_never_send_or_retarget_old_work()
-> Result<(), Error> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = Client::new(&mut instance, Config { targets: 1, sends: 2, ..config(IpAddr::V4(Ipv4Addr::LOCALHOST)) })?;
        client.set_identity([1; 32])?;
        let first = raw_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        let second = raw_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        let original = client.try_connect([2; 32], format!("ip+udp://{}", first.local_addr()?).as_bytes())?;
        assert!(matches!(next(&mut client).await?, Event::Connected(peer) if peer == original));
        let bytes = frame(4)?;
        let a = client.send(original, &bytes, Instant::now() + Duration::from_secs(2))?;
        let b = client.send(original, &bytes, Instant::now() + Duration::from_secs(2))?;
        assert!(!client.request_available(original, bytes.len())?);
        let new_url = format!("ip+udp://{}", second.local_addr()?);
        for _ in 0..3 { assert!(matches!(client.try_connect([3; 32], new_url.as_bytes()), Err(Error::Protocol(Fault::WouldBlock)))); }
        for expected in [a, b] {
            assert!(matches!(next(&mut client).await?, Event::Finished { send, peer, outcome: Outcome::Disconnected(DisconnectReason::Evicted), written: 0, .. }
                if send == expected && peer == original));
        }
        assert!(matches!(next(&mut client).await?, Event::Disconnected { peer, reason: DisconnectReason::Evicted } if peer == original));
        let replacement = client.try_connect([3; 32], new_url.as_bytes())?;
        assert_ne!(replacement, original);
        assert!(matches!(client.send(original, &bytes, Instant::now() + Duration::from_secs(2)), Err(Error::Protocol(Fault::StaleGeneration))));
        assert!(matches!(next(&mut client).await?, Event::Connected(peer) if peer == replacement));
        let cancelled = client.send(replacement, &bytes, Instant::now() + Duration::from_secs(2))?;
        client.cancel(cancelled)?;
        assert!(matches!(next(&mut client).await?, Event::Finished { send, outcome: Outcome::Cancelled, written: 0, .. } if send == cancelled));
        let deadline = client.send(replacement, &bytes, Instant::now() + Duration::from_millis(5))?;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let event = poll_fn(|cx| match client.poll_native_guard(cx) {
            Ok(Some(event)) => std::task::Poll::Ready(Ok(event)),
            Ok(None) => std::task::Poll::Pending,
            Err(error) => std::task::Poll::Ready(Err(error)),
        }).await?;
        assert!(matches!(event, Event::Finished { send, outcome: Outcome::Deadline, written: 0, .. } if send == deadline));
        let pending = client.send(replacement, &bytes, Instant::now() + Duration::from_secs(2))?;
        client.close();
        assert!(matches!(next(&mut client).await?, Event::Finished { send, outcome: Outcome::Disconnected(DisconnectReason::Closed), written: 0, .. } if send == pending));
        assert!(matches!(next(&mut client).await?, Event::Disconnected { peer, reason: DisconnectReason::Closed } if peer == replacement));
        assert!(matches!(next(&mut client).await?, Event::Closed));
        let mut input = [0; 64];
        for socket in [&first, &second] { assert!(matches!(socket.try_recv_from(&mut input), Err(error) if error.kind() == io::ErrorKind::WouldBlock)); }
        Ok(())
    })
}

#[test]
fn endpoint_claim_and_local_identity_changes_retire_original_generations_before_new_admission()
-> Result<(), Error> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = Client::new(&mut instance, config(IpAddr::V4(Ipv4Addr::LOCALHOST)))?;
        client.set_identity([1; 32])?;
        let remote = raw_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        let destination = client.local_addrs()[0];
        let url = format!("ip+udp://{}", remote.local_addr()?);
        let old = client.try_connect([2; 32], url.as_bytes())?;
        assert!(matches!(next(&mut client).await?, Event::Connected(peer) if peer == old));
        let bytes = frame(4)?;
        let mut packet = [3; 32].to_vec(); packet.extend_from_slice(&bytes);
        remote.send_to(&packet, destination).await?;
        assert!(matches!(next(&mut client).await?, Event::Discarded { reason: Fault::WouldBlock, .. }));
        assert!(matches!(next(&mut client).await?, Event::Disconnected { peer, reason: DisconnectReason::ClaimChanged } if peer == old));
        remote.send_to(&packet, destination).await?;
        let Event::Connected(current) = next(&mut client).await? else { return Err(Fault::Conflict.into()); };
        assert_ne!(current, old); assert_eq!(current.identity().0, [3; 32]);
        let Event::Message(packet) = next(&mut client).await? else { return Err(Fault::Conflict.into()); };
        client.release(packet)?;
        let pending = client.send(current, &bytes, Instant::now() + Duration::from_secs(2))?;
        client.set_identity([4; 32])?;
        assert!(matches!(client.try_connect([3; 32], url.as_bytes()), Err(Error::Protocol(Fault::NotReady))));
        assert!(matches!(next(&mut client).await?, Event::Finished { send, peer, outcome: Outcome::Disconnected(DisconnectReason::IdentityChanged), written: 0, .. } if send == pending && peer == current));
        assert!(matches!(next(&mut client).await?, Event::Disconnected { peer, reason: DisconnectReason::IdentityChanged } if peer == current));
        let peer = client.try_connect([3; 32], url.as_bytes())?;
        assert_ne!(peer, current);
        assert!(matches!(next(&mut client).await?, Event::Connected(actual) if actual == peer));
        let send = client.send(peer, &bytes, Instant::now() + Duration::from_secs(2))?;
        assert!(matches!(next(&mut client).await?, Event::Finished { send: actual, outcome: Outcome::Written, .. } if actual == send));
        let mut received = [0; 64];
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), remote.recv_from(&mut received)).await.map_err(|_| Fault::Deadline)??;
        assert_eq!(&received[..32], &[4; 32]); assert_eq!(&received[32..length], bytes);
        closed(&mut client).await
    })
}
