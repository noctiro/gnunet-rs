//! Native MQ loss with more original channels than Core observation slots.
//! The socket peer captures IPC only; it provides no remote authentication.
use super::*;
use crate::test_support::Directory;
use gnunet_service_runtime::{clock::SystemClock, local::Listener};

type Failure = Box<dyn std::error::Error>;
struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Fault> {
        Err(Fault::Entropy)
    }
}

#[test]
fn one_lost_mq_retires_all_sources_with_a_full_small_event_queue() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let directory = Directory::new()?;
                let path = directory.0.join("c");
                let listener = Listener::bind(&path)?;
                let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
                let mut domain = core::Instance::new();
                let mut cadet_domain = cadet::Instance::new();
                let mut pils_domain = pc::Instance::new();
                let mut ports = [cadet::PortSlot::new()];
                let mut channels = std::array::from_fn::<_, 10, _>(|_| cadet::ChannelSlot::new());
                let limits = Limits {
                    clients: 1,
                    rooms: 1,
                    client_rooms: 1,
                    tunnels: 10,
                    deliveries: 16,
                    signatures: 1,
                    min_routers: 0,
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
                        sources_per_room: 10,
                        events: 8,
                        ..core::Limits::default()
                    },
                    limits,
                    Ports {
                        options: ServiceOptions::default(),
                        unix: UnixAccess::default(),
                        clock: clock.clone(),
                        cadet: EndpointSource::unix_with_clock(path, clock.clone()),
                        pils: EndpointSource::unix_with_clock(
                            directory.0.join("unused-pils"),
                            clock,
                        ),
                    },
                    NoEntropy,
                )?;
                let (attached, peer) = tokio::join!(server.cadet.drive(None), listener.accept());
                if !matches!(attached?, cadet::Step::Connected(_)) {
                    return Err("CADET MQ did not attach".into());
                }
                let (peer, _) = peer?;
                let room = server.core.room([7; 64], None)?;
                server.drain_events();
                let mut sources = Vec::new();
                for row in 0..10 {
                    let remote = [u8::try_from(row + 1)?; 32];
                    let channel = server.cadet.open(remote, [9; 64])?;
                    let transmit = server.cadet.pending_transmit().ok_or(Fault::NotReady)?;
                    loop {
                        match server.cadet.drive(None).await? {
                            cadet::Step::Written(written) if written.transmit == transmit => break,
                            cadet::Step::Activity { .. } => {}
                            _ => return Err("original CADET open did not write".into()),
                        }
                    }
                    let mut request = [0; 108];
                    let mut offset = 0;
                    while offset < request.len() {
                        peer.readable().await?;
                        match peer.try_read(&mut request[offset..]) {
                            Ok(0) => return Err("original CADET IPC capture reached EOF".into()),
                            Ok(n) => offset += n,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if !matches!(
                        gnunet_wire::official::cadet::Request::decode(&request)?,
                        gnunet_wire::official::cadet::Request::ChannelCreate { .. }
                    ) {
                        return Err("capture did not contain the original ChannelCreate".into());
                    }
                    let source = server.core.attach_source(
                        room,
                        SourceRole::Peer(remote),
                        padding::Decode::Required,
                        None,
                    )?;
                    sources.push(source);
                    server.tunnels[row] = Some(Tunnel {
                        room,
                        source,
                        channel,
                        peer: remote,
                        compatible: false,
                        info_queued: false,
                        closing: false,
                        remote_closed: false,
                        bootstrap: 0,
                        until: Instant::now() + limits.operation_lifetime,
                    });
                    // Leave the last eight real attachments in the eight-slot
                    // observation queue when the shared physical source disappears.
                    if row < 2 {
                        server.drain_events();
                    }
                }
                let cadet::Step::Lost { report, cause, .. } = server.cadet.reconnect()? else {
                    return Err("original MQ did not physically retire".into());
                };
                server.cadet_lost(Some(report), Some(cause), &mut |_| {})?;
                if server.tunnels.iter().any(Option::is_some)
                    || sources
                        .iter()
                        .any(|source| server.core.source_room(*source).is_ok())
                {
                    return Err("lost MQ left an original Core source or tunnel alive".into());
                }
                server.close_all(&mut |_| {});
                if let Some(error) = server.take_cleanup_error() {
                    return Err(error.into());
                }
                Ok::<_, Failure>(())
            })
            .await?
        })
}
