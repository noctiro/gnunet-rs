//! Native IPC receipts and original Source lifetime, without peer authentication.
use super::*;
use crate::test_support::Directory;
use gnunet_service_runtime::{
    clock::SystemClock,
    local::{Listener, Stream},
};
use gnunet_wire::official::cadet::{Request as CadetRequest, Response as CadetResponse};

type Failure = Box<dyn std::error::Error>;
struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Fault> {
        Err(Fault::Entropy)
    }
}
fn check(condition: bool) -> Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err("native output ownership invariant".into())
    }
}
async fn read_exact(stream: &Stream, bytes: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream.readable().await?;
        match stream.try_read(&mut bytes[offset..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
async fn response(stream: &Stream, response: CadetResponse<'_>) -> Result<(), Failure> {
    let mut bytes = [0; 8];
    let length = response.encode(&mut bytes)?;
    let mut offset = 0;
    while offset < length {
        stream.writable().await?;
        match stream.try_write(&bytes[offset..length]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[test]
fn cancellation_and_expiry_of_unwritten_output_preserve_other_channels() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { tokio::time::timeout(Duration::from_secs(30), unwritten()).await? })
}
async fn unwritten() -> Result<(), Failure> {
    let directory = Directory::new()?;
    let path = directory.0.join("c");
    let listener = Listener::bind(&path)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let mut domain = core::Instance::new();
    let mut cadet_domain = cadet::Instance::new();
    let mut pils_domain = pc::Instance::new();
    let mut ports = [cadet::PortSlot::new()];
    let mut channels = [cadet::ChannelSlot::new(); 4];
    let limits = Limits {
        clients: 1,
        rooms: 1,
        client_rooms: 1,
        tunnels: 4,
        deliveries: 8,
        signatures: 1,
        min_routers: 0,
        io_slice_bytes: 1,
        ..Limits::default()
    };
    let mut server = Server::<_, 1>::new(
        &mut domain,
        &mut cadet_domain,
        &mut pils_domain,
        &mut ports,
        &mut channels,
        core::Limits {
            rooms: 1,
            sources_per_room: 4,
            ..core::Limits::default()
        },
        limits,
        Ports {
            options: ServiceOptions::default(),
            unix: UnixAccess::default(),
            clock: clock.clone(),
            cadet: EndpointSource::unix_with_clock(path, clock.clone()),
            pils: EndpointSource::unix_with_clock(directory.0.join("unused-pils"), clock),
        },
        NoEntropy,
    )?;
    let cadet::Step::Connected(epoch) = server.cadet.drive(None).await? else {
        return Err("MQ not attached".into());
    };
    let (peer, _) = listener.accept().await?;
    let room = server.core.room([7; 64], None)?;
    server.drain_events();
    for row in 0..4 {
        let remote = [u8::try_from(row + 1)?; 32];
        let channel = server.cadet.open(remote, [9; 64])?;
        let transmit = server.cadet.pending_transmit().ok_or(Fault::NotReady)?;
        let writing = async {
            loop {
                match server.cadet.drive(None).await? {
                    cadet::Step::Written(written) if written.transmit == transmit => break,
                    cadet::Step::Activity { .. } => {}
                    _ => return Err("CREATE not written".into()),
                }
            }
            Ok::<_, Failure>(())
        };
        let mut frame = [0; 108];
        let (written, captured) = tokio::join!(writing, read_exact(&peer, &mut frame));
        written?;
        captured?;
        let CadetRequest::ChannelCreate { channel: wire, .. } = CadetRequest::decode(&frame)?
        else {
            return Err("wrong CREATE".into());
        };
        response(&peer, CadetResponse::Ack { channel: wire }).await?;
        loop {
            match server.cadet.drive(None).await? {
                cadet::Step::Credit {
                    channel: actual,
                    available: 1,
                } if actual == channel => break,
                cadet::Step::Activity { .. } => {}
                _ => return Err("original credit absent".into()),
            }
        }
        let source = server.core.attach_source(
            room,
            SourceRole::Peer(remote),
            padding::Decode::Required,
            None,
        )?;
        server.tunnels[row] = Some(Tunnel {
            room,
            source,
            channel,
            peer: remote,
            compatible: true,
            info_queued: true,
            closing: false,
            remote_closed: false,
            bootstrap: 0,
            until: Instant::now() + limits.operation_lifetime,
        });
    }
    let first = server.tunnels[0].as_ref().ok_or(Fault::NotFound)?.channel;
    let second = server.tunnels[1].as_ref().ok_or(Fault::NotFound)?.channel;
    for (sequence, expired, row) in [(11, false, 0), (12, true, 1)] {
        let channel = server.tunnels[row].as_ref().ok_or(Fault::NotFound)?.channel;
        let transmit = server.cadet.send(channel, 0, &[0, 4, 0, 0])?;
        let until = if expired {
            Instant::now() - Duration::from_millis(1)
        } else {
            Instant::now() + limits.operation_lifetime
        };
        server.peer_output = Some(PeerOutput {
            transmit,
            target: PeerTarget::Channel(channel),
            sequence,
            task: Some(sequence),
            until,
        });
        server.tasks[0] = Some(Task {
            sequence,
            room,
            hash: [4; 64],
            destination: Destination::Peer(channel),
            recent: false,
            requested: false,
            queued: true,
            until,
        });
        server.cadet_pending = Some((transmit, until));
        if !expired {
            server.tunnels[row].as_mut().ok_or(Fault::NotFound)?.closing = true;
        }
        let mut cancelled = None;
        let mut observe = |event| {
            if let Event::OutputLost { sequence, exposed } = event {
                cancelled = Some((sequence, exposed));
            }
        };
        if expired {
            server.expire_cadet_output(&mut observe)?;
        } else {
            check(server.reconcile_peer_output(&mut observe)?)?;
        }
        check(
            cancelled == Some((sequence, Some(false)))
                && server.peer_output.is_none()
                && server.cadet_pending.is_none()
                && server.tasks[0].is_none()
                && server.cadet.channel_info(first)?.send_credit == 1
                && server.cadet.channel_info(second)?.send_credit == 1
                && server.cadet.epoch() == Some(epoch)
                && server.report.unknown == 0,
        )?;
        check(
            matches!(peer.try_read(&mut [0]),Err(error) if error.kind()==io::ErrorKind::WouldBlock),
        )?;
    }
    #[cfg(unix)]
    {
        let third = server.tunnels[2].as_ref().ok_or(Fault::NotFound)?.channel;
        closed_prefix(&mut server, &peer, third).await?;
    }
    let fourth = server.tunnels[3].as_ref().ok_or(Fault::NotFound)?.channel;
    expired_prefix(&mut server, &peer, fourth).await?;
    server.close_all(&mut |_| {});
    if let Some(error) = server.take_cleanup_error() {
        return Err(error.into());
    }
    Ok(())
}

async fn expired_prefix<'c>(
    server: &mut Server<'c, '_, '_, NoEntropy, 1>,
    peer: &Stream,
    channel: cadet::Channel<'c>,
) -> Result<(), Failure> {
    let source = server
        .tunnels
        .iter()
        .flatten()
        .find(|t| t.channel == channel)
        .ok_or(Fault::NotFound)?
        .source;
    let transmit = server.cadet.send(channel, 0, &[0, 4, 0, 0])?;
    let until = Instant::now() + Duration::from_millis(50);
    server.peer_output = Some(PeerOutput {
        transmit,
        target: PeerTarget::Channel(channel),
        sequence: 14,
        task: None,
        until,
    });
    server.cadet_pending = Some((transmit, until));
    check(matches!(
        server.cadet.drive(None).await?,
        cadet::Step::Activity {
            written_bytes: 1,
            ..
        }
    ))?;
    read_exact(peer, &mut [0]).await?;
    tokio::time::sleep_until(until).await;
    let mut lost = false;
    let mut written = false;
    let mut actual = None;
    poll_fn(|cx| {
        server.cadet_poll(cx, &mut |event| match event {
            Event::OutputLost {
                sequence: 14,
                exposed: Some(true),
            } => lost = true,
            Event::Written { sequence: 14, .. } => written = true,
            Event::CadetLost { pending, .. } => actual = pending,
            _ => {}
        })
    })
    .await?;
    check(
        lost && !written
            && actual == Some((transmit.value(), true))
            && server.peer_output.is_none()
            && server.cadet_pending.is_none()
            && server.cadet.epoch().is_none()
            && server.core.source_room(source).is_err()
            && server.tunnels.iter().all(Option::is_none)
            && server.report.unknown == 1,
    )?;
    // The first original byte was observed above; the expired suffix never ran.
    peer.readable().await?;
    check(peer.try_read(&mut [0])? == 0)
}

/// Unix stream backpressure lets the real Destroyed response arrive while a
/// one-byte-quantum DATA still has an unwritten suffix. This is native cursor
/// evidence only; the opaque inner frame is not a signed Messenger message.
#[cfg(unix)]
async fn closed_prefix<'c>(
    server: &mut Server<'c, '_, '_, NoEntropy, 1>,
    peer: &Stream,
    channel: cadet::Channel<'c>,
) -> Result<(), Failure> {
    let tunnel = server
        .tunnels
        .iter()
        .flatten()
        .find(|t| t.channel == channel)
        .ok_or(Fault::NotFound)?;
    let (source, room) = (tunnel.source, tunnel.room);
    let epoch = server.cadet.epoch();
    let wire = server.cadet.channel_info(channel)?.wire_id;
    let mut payload = vec![0x42; 60_000];
    payload[..2].copy_from_slice(&60_000u16.to_be_bytes());
    payload[2..4].copy_from_slice(&[0, 0]);
    let transmit = server.cadet.send(channel, 0, &payload)?;
    let until = Instant::now() + server.limits.operation_lifetime;
    server.peer_output = Some(PeerOutput {
        transmit,
        target: PeerTarget::Channel(channel),
        sequence: 13,
        task: Some(13),
        until,
    });
    server.tasks[0] = Some(Task {
        sequence: 13,
        room,
        hash: [5; 64],
        destination: Destination::Peer(channel),
        recent: false,
        requested: false,
        queued: true,
        until,
    });
    server.cadet_pending = Some((transmit, until));
    check(matches!(
        server.cadet.drive(None).await?,
        cadet::Step::Activity {
            written_bytes: 1,
            ..
        }
    ))?;
    let mut captured = vec![0; payload.len() + 12];
    read_exact(peer, &mut captured[..1]).await?;
    response(peer, CadetResponse::ChannelDestroy { channel: wire }).await?;
    loop {
        poll_fn(|cx| server.cadet_poll(cx, &mut |_| {})).await?;
        if server
            .tunnels
            .iter()
            .flatten()
            .any(|t| t.channel == channel && t.remote_closed)
        {
            break;
        }
        check(server.peer_output.is_some())?;
    }
    check(
        !server.retire_remote_tunnel()?
            && server.core.source_room(source)? == room
            && server
                .peer_output
                .as_ref()
                .is_some_and(|out| out.transmit == transmit && out.until == until)
            && server.tasks[0].is_some(),
    )?;
    let writing = async {
        let mut written = false;
        while server.peer_output.is_some() {
            poll_fn(|cx| {
                server.cadet_poll(cx, &mut |event| {
                    if let Event::Written {
                        sequence: 13,
                        peer: true,
                    } = event
                    {
                        written = true;
                    }
                })
            })
            .await?;
        }
        check(written)
    };
    let (written, captured_result) = tokio::join!(writing, read_exact(peer, &mut captured[1..]));
    written?;
    captured_result?;
    check(
        matches!(CadetRequest::decode(&captured)?,CadetRequest::Data {channel:actual,messages,..}
        if actual == wire && messages == payload),
    )?;
    check(
        server.tasks[0].is_none()
            && server.retire_remote_tunnel()?
            && server.core.source_room(source).is_err()
            && server.cadet.epoch() == epoch
            && server.report.unknown == 0,
    )?;
    Ok(())
}
