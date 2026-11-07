#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible actual socket models assert original accepted MQ, cursor, exposure and protocol observations"
)]
use super::*;
use gnunet_service_runtime::clock::SystemClock;
use gnunet_wire::official::{
    MessageType,
    cadet::{CLIENT_CHANNEL_BOUNDARY, Response},
};
use std::{error::Error as StdError, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
type Failure = Box<dyn StdError + Send + Sync>;
const PORT: [u8; 64] = [3; 64];
const BATCH: [u8; 8] = [0, 4, 0x12, 0x34, 0, 4, 0x12, 0x35];
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn request(stream: &mut TcpStream, request: Request<'_>) -> Result<(), Failure> {
    let mut output = [0; 256];
    let length = request.encode(&mut output)?;
    for chunk in output[..length].chunks(3) {
        stream.write_all(chunk).await?;
    }
    Ok(())
}
async fn frame(stream: &mut TcpStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err("short official frame".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn until<'id, 'slots, 'bytes>(
    server: &mut Server<'id, 'slots, 'bytes>,
    listeners: &[Listener<'_>],
    mut done: impl FnMut(&Server<'id, 'slots, 'bytes>) -> bool,
    observe: &mut impl FnMut(Event<'id>),
) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !done(server) {
        // Every Pending observation future is immediately canceled. All actual
        // original accept/read/write state belongs to Server, never the wait.
        let result = poll_fn(|cx| {
            let future = server.drive(listeners, Some(deadline), &mut *observe);
            let mut future = std::pin::pin!(future);
            Poll::Ready(future.as_mut().poll(cx))
        })
        .await;
        match result {
            Poll::Pending => tokio::task::yield_now().await,
            Poll::Ready(Ok(Progress::WaitDeadline)) => {
                return Err("native model observation timed out".into());
            }
            Poll::Ready(result) => {
                result?;
            }
        }
    }
    Ok(())
}

#[test]
fn actual_identity_cut_keeps_one_mq_port_and_partial_original_output() -> Result<(), Failure> {
    runtime()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let listeners = [Listener::Tcp(&listener)];
            let mut instance = core::Instance::new();
            let mut clients = [core::ClientSlot::new(); 1];
            let mut ports = [core::PortSlot::new(); 1];
            let mut channels = [core::ChannelSlot::new(); 4];
            let mut storage = [[0; 16]; 6];
            let mut messages = storage
                .each_mut()
                .map(|bytes| core::MessageSlot::new(bytes));
            let service = core::Service::new(
                &mut instance,
                [1; 32],
                &mut clients,
                &mut ports,
                &mut channels,
                &mut messages,
                core::Limits {
                    window: 1,
                    loop_payload_bytes: 16,
                    remote_payload_bytes: 16,
                },
            )?;
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let mut server = Server::new(
                service,
                Limits {
                    clients: 1,
                    io_slice_bytes: 2,
                },
                ServiceOptions::default(),
                UnixAccess::default(),
                clock,
            )?;
            let mut application = TcpStream::connect(listener.local_addr()?).await?;
            request(&mut application, Request::PortOpen { port: PORT }).await?;
            request(
                &mut application,
                Request::ChannelCreate {
                    channel: CLIENT_CHANNEL_BOUNDARY,
                    peer: [1; 32],
                    port: PORT,
                    options: 0,
                },
            )
            .await?;
            let mut port = None;
            let mut old = None;
            until(
                &mut server,
                &listeners,
                |server| server.report().written_bytes > 0,
                &mut |event| {
                    if let Event::Input { event, .. } = event {
                        match event {
                            core::Event::PortOpened(actual) => port = Some(actual),
                            core::Event::ChannelCreated(actual) => old = Some(actual),
                            _ => {}
                        }
                    }
                },
            )
            .await?;
            let port = port.ok_or("original port missing")?;
            let old = old.ok_or("original local channel missing")?;
            let original = server.clients().next().ok_or("original MQ missing")?;
            assert_eq!(server.report().written_frames, 0);
            assert_eq!(server.report().written_bytes, 2);
            server.retire_identity_channels()?;
            assert!(server.identity_channels_retired());
            server.rebind_local_peer([2; 32])?;
            assert_eq!(server.port_hash(port)?, PORT);
            assert_eq!(
                server.resolve_port_challenge(&peer::hash_port(&PORT, &[1; 32])),
                None
            );
            assert_eq!(
                server.resolve_port_challenge(&peer::hash_port(&PORT, &[2; 32])),
                Some(PORT)
            );
            until(
                &mut server,
                &listeners,
                |s| s.report().written_frames == 3,
                &mut |_| {},
            )
            .await?;
            assert_eq!(
                Response::decode(&frame(&mut application).await?)?,
                Response::ChannelCreate {
                    channel: 0,
                    peer: [1; 32],
                    port: PORT,
                    options: 0,
                }
            );
            for _ in 0..2 {
                assert!(matches!(
                    Response::decode(&frame(&mut application).await?)?,
                    Response::Ack { .. }
                ));
            }
            request(
                &mut application,
                Request::ChannelCreate {
                    channel: CLIENT_CHANNEL_BOUNDARY + 1,
                    peer: [2; 32],
                    port: PORT,
                    options: 0,
                },
            )
            .await?;
            until(
                &mut server,
                &listeners,
                |s| s.report().written_frames == 6,
                &mut |_| {},
            )
            .await?;
            assert_eq!(
                Response::decode(&frame(&mut application).await?)?,
                Response::ChannelCreate {
                    channel: 1,
                    peer: [2; 32],
                    port: PORT,
                    options: 0,
                }
            );
            for _ in 0..2 {
                assert!(matches!(
                    Response::decode(&frame(&mut application).await?)?,
                    Response::Ack { .. }
                ));
            }
            request(
                &mut application,
                Request::Data {
                    channel: CLIENT_CHANNEL_BOUNDARY,
                    priority: 9,
                    messages: &BATCH,
                },
            )
            .await?;
            until(
                &mut server,
                &listeners,
                |s| s.report().written_frames == 8,
                &mut |_| {},
            )
            .await?;
            assert_eq!(
                Response::decode(&frame(&mut application).await?)?,
                Response::Data {
                    channel: 0,
                    priority: 9,
                    messages: &BATCH,
                }
            );
            assert_eq!(
                Response::decode(&frame(&mut application).await?)?,
                Response::Ack {
                    channel: CLIENT_CHANNEL_BOUNDARY
                }
            );
            assert_eq!(server.channel_info(old)?.peer, [1; 32]);
            assert_eq!(server.clients().next(), Some(original));
            assert_eq!(server.report().accepted, 1);
            assert_eq!(server.report().closed, 0);
            server.rebind_local_peer([1; 32])?;
            assert_eq!(server.port_hash(port)?, PORT);
            server.close_all(&mut |_| {})?;
            assert_eq!(server.report().closed, 1);
            Ok::<(), Failure>(())
        })
        .await?
    })
}

#[test]
fn actual_loopback_complete_strings_and_remote_intents_survive_canceled_waits()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listeners = [Listener::Tcp(&listener)];
        let mut instance = core::Instance::new();
        let mut clients = [core::ClientSlot::new(); 1];
        let mut ports = [core::PortSlot::new(); 1];
        let mut channels = [core::ChannelSlot::new(); 4];
        let mut storage = [[0; 16]; 5];
        let mut messages = storage
            .each_mut()
            .map(|bytes| core::MessageSlot::new(bytes));
        let service = core::Service::new(
            &mut instance,
            [1; 32],
            &mut clients,
            &mut ports,
            &mut channels,
            &mut messages,
            core::Limits {
                window: 1,
                loop_payload_bytes: 16,
                remote_payload_bytes: 16,
            },
        )?;
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let mut server = Server::new(
            service,
            Limits {
                clients: 1,
                io_slice_bytes: 2,
            },
            ServiceOptions::default(),
            UnixAccess::default(),
            clock.clone(),
        )?;
        assert!(Arc::ptr_eq(&server.clock(), &clock));
        let mut application = TcpStream::connect(listener.local_addr()?).await?;
        request(&mut application, Request::PortOpen { port: PORT }).await?;
        request(
            &mut application,
            Request::ChannelCreate {
                channel: CLIENT_CHANNEL_BOUNDARY,
                peer: [1; 32],
                port: PORT,
                options: u32::MAX,
            },
        )
        .await?;
        let mut outgoing = None;
        let mut incoming = None;
        until(
            &mut server,
            &listeners,
            |server| server.report().written_frames == 3,
            &mut |event| match event {
                Event::Input {
                    event: core::Event::ChannelCreated(channel),
                    ..
                } => outgoing = Some(channel),
                Event::LocalBound(channel) => incoming = Some(channel),
                _ => {}
            },
        )
        .await?;
        let outgoing = outgoing.ok_or("missing actual outgoing endpoint")?;
        let incoming = incoming.ok_or("missing actual loopback binding")?;
        let client = server
            .clients()
            .next()
            .ok_or("missing actual accepted source")?;
        assert_eq!(outgoing.client(), client);
        assert_eq!(incoming.client(), client);
        assert_eq!(incoming.wire_id(), 0);
        let announcement = frame(&mut application).await?;
        assert_eq!(
            Response::decode(&announcement)?,
            Response::ChannelCreate {
                channel: 0,
                peer: [1; 32],
                port: PORT,
                options: 0
            }
        );
        let first_credit = frame(&mut application).await?;
        let second_credit = frame(&mut application).await?;
        assert_eq!(
            Response::decode(&first_credit)?,
            Response::Ack {
                channel: CLIENT_CHANNEL_BOUNDARY
            }
        );
        assert_eq!(
            Response::decode(&second_credit)?,
            Response::Ack { channel: 0 }
        );
        request(
            &mut application,
            Request::Data {
                channel: CLIENT_CHANNEL_BOUNDARY,
                priority: 0xa1b2_c3d4,
                messages: &BATCH,
            },
        )
        .await?;
        until(
            &mut server,
            &listeners,
            |server| server.report().written_frames == 5,
            &mut |_| {},
        )
        .await?;
        let payload = frame(&mut application).await?;
        assert_eq!(
            Response::decode(&payload)?,
            Response::Data {
                channel: 0,
                priority: 0xa1b2_c3d4,
                messages: &BATCH
            }
        );
        let source_credit = frame(&mut application).await?;
        assert_eq!(
            Response::decode(&source_credit)?,
            Response::Ack {
                channel: CLIENT_CHANNEL_BOUNDARY
            }
        );
        assert!(server.channel_info(incoming)?.receive_pending);
        assert_eq!(server.channel_info(outgoing)?.allowance, 1);
        request(&mut application, Request::Ack { channel: 0 }).await?;
        until(
            &mut server,
            &listeners,
            |server| server.report().inputs == 4,
            &mut |_| {},
        )
        .await?;
        assert!(!server.channel_info(incoming)?.receive_pending);

        request(
            &mut application,
            Request::ChannelCreate {
                channel: CLIENT_CHANNEL_BOUNDARY + 1,
                peer: [2; 32],
                port: PORT,
                options: 0,
            },
        )
        .await?;
        until(
            &mut server,
            &listeners,
            |server| server.report().inputs == 5,
            &mut |_| {},
        )
        .await?;
        let remote = server
            .next_open()
            .ok_or("missing explicit real peer open intent")?;
        assert_eq!(server.channel_info(remote.channel())?.allowance, 0);
        let progress = server
            .drive(
                &listeners,
                Some(Instant::now() + Duration::from_millis(2)),
                |_| {},
            )
            .await?;
        assert_eq!(progress, Progress::WaitDeadline);
        assert_eq!(server.report().written_frames, 5);
        assert!(server.next_send().is_none());
        drop(application);
        until(
            &mut server,
            &listeners,
            |server| server.report().closed == 1,
            &mut |_| {},
        )
        .await?;
        assert_eq!(server.canceling_open(), Some(remote));
        // No backend work was started by the native adapter; the explicit port
        // has now stopped its original dispatched intent before failing it.
        server.open_failed(remote)?;
        assert!(server.canceling_open().is_none());
        assert!(matches!(
            server.close(client, CloseCause::Requested, &mut |_| {}),
            Err(Error::Protocol(ProtocolError::StaleGeneration))
        ));
        let report = server.shutdown(ShutdownMode::Immediate, |_| {}).await?;
        assert_eq!(report.accepted, 1);
        assert_eq!(report.closed, 1);
        Ok(())
    })
}

#[test]
fn partial_original_output_loss_and_known_monitor_refusal_keep_true_source_facts()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listeners = [Listener::Tcp(&listener)];
        let mut instance = core::Instance::new();
        let mut clients = [core::ClientSlot::new(); 1];
        let mut ports = [core::PortSlot::new(); 1];
        let mut channels = [core::ChannelSlot::new(); 2];
        let mut storage = [[0; 16]; 3];
        let mut messages = storage
            .each_mut()
            .map(|bytes| core::MessageSlot::new(bytes));
        let service = core::Service::new(
            &mut instance,
            [1; 32],
            &mut clients,
            &mut ports,
            &mut channels,
            &mut messages,
            core::Limits {
                window: 1,
                loop_payload_bytes: 16,
                remote_payload_bytes: 16,
            },
        )?;
        let mut server = Server::new(
            service,
            Limits {
                clients: 1,
                io_slice_bytes: 1,
            },
            ServiceOptions {
                tolerant: true,
                ..ServiceOptions::default()
            },
            UnixAccess::default(),
            Arc::new(SystemClock),
        )?;
        let mut old_application = TcpStream::connect(listener.local_addr()?).await?;
        request(&mut old_application, Request::PortOpen { port: PORT }).await?;
        request(
            &mut old_application,
            Request::ChannelCreate {
                channel: CLIENT_CHANNEL_BOUNDARY,
                peer: [1; 32],
                port: PORT,
                options: 0,
            },
        )
        .await?;
        until(
            &mut server,
            &listeners,
            |server| server.report().written_bytes == 1,
            &mut |_| {},
        )
        .await?;
        let original = server.clients().next().ok_or("missing original MQ")?;
        let loss = server.close(original, CloseCause::Requested, &mut |_| {})?;
        assert_eq!(loss.client, original);
        assert_eq!(loss.channels, 2);
        assert!(loss.exposed);
        let pending = loss.pending.ok_or("missing original partial frame")?;
        assert_eq!(pending.client(), original);
        assert_eq!(pending.kind(), core::OutputKind::Incoming);
        assert_eq!(server.report().written_frames, 0);
        let mut prefix = Vec::new();
        old_application.read_to_end(&mut prefix).await?;
        assert_eq!(prefix, [0]);
        let mut fresh_application = TcpStream::connect(listener.local_addr()?).await?;
        until(
            &mut server,
            &listeners,
            |server| server.report().accepted == 2,
            &mut |_| {},
        )
        .await?;
        let fresh = server.clients().next().ok_or("missing fresh MQ")?;
        assert_ne!(fresh, original);
        assert!(matches!(
            server.close(original, CloseCause::Requested, &mut |_| {}),
            Err(Error::Protocol(ProtocolError::StaleGeneration))
        ));
        let mut unknown = [0; 4];
        MessageHeader::from_total_size(MessageType::new(u16::MAX), 4)?.encode(&mut unknown)?;
        fresh_application.write_all(&unknown).await?;
        until(
            &mut server,
            &listeners,
            |server| server.report().ignored == 1,
            &mut |_| {},
        )
        .await?;
        assert_eq!(server.clients().count(), 1);
        assert_eq!(server.report().outputs, 1);
        request(&mut fresh_application, Request::ListPeers).await?;
        let mut unsupported = false;
        until(
            &mut server,
            &listeners,
            |server| server.report().closed == 2,
            &mut |event| {
                if let Event::Closed {
                    loss,
                    cause: CloseCause::Fault(Error::Protocol(ProtocolError::Unsupported)),
                } = event
                {
                    assert_eq!(loss.client, fresh);
                    assert!(loss.pending.is_none());
                    assert!(!loss.exposed);
                    unsupported = true;
                }
            },
        )
        .await?;
        assert!(unsupported);
        let mut no_fake_end = Vec::new();
        fresh_application.read_to_end(&mut no_fake_end).await?;
        assert!(no_fake_end.is_empty());
        assert_eq!(server.report().written_bytes, 1);
        Ok(())
    })
}

// Directory facts are an explicit metadata fixture; CORE/KX is not modeled as
// actual by this test. Production Node captures those facts from its real owners.
#[test]
fn independent_management_snapshots_partial_loss_and_application_origins_stay_separate()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let listeners = [Listener::Tcp(&listener)];
            let mut instance = core::Instance::new();
            let mut clients = [core::ClientSlot::new(); 4];
            let mut ports = [core::PortSlot::new(); 2];
            let mut channels = [core::ChannelSlot::new(); 2];
            let mut storage = [[0; 16]; 6];
            let mut messages = storage.each_mut().map(|b| core::MessageSlot::new(b));
            let service = core::Service::new(
                &mut instance,
                [0; 32],
                &mut clients,
                &mut ports,
                &mut channels,
                &mut messages,
                core::Limits {
                    window: 1,
                    loop_payload_bytes: 16,
                    remote_payload_bytes: 16,
                },
            )?;
            let mut server = Server::new(
                service,
                Limits {
                    clients: 4,
                    io_slice_bytes: 1,
                },
                ServiceOptions::default(),
                UnixAccess::default(),
                Arc::new(SystemClock),
            )?;
            let limits = management::Limits {
                queries: 3,
                records: 256,
                path_identities: 512,
                snapshot_bytes: 16384,
            };
            server.enable_management(limits)?;
            let mut slow = TcpStream::connect(listener.local_addr()?).await?;
            request(&mut slow, Request::ListPeers).await?;
            until(
                &mut server,
                &listeners,
                |s| s.report().inputs == 1,
                &mut |_| {},
            )
            .await?;
            let original = server
                .pending_management()
                .ok_or("missing actual original peer query")?;
            assert_eq!(original.kind(), management::Kind::Peers);
            assert!(
                !server
                    .management_report(original.client())?
                    .ok_or("missing original report")?
                    .snapshot
            );
            assert_eq!(server.report().outputs, 0);
            // A real enabled provider has not bound a capture yet. An elapsed wait
            // cannot fabricate the END of an empty successful list.
            assert_eq!(
                server
                    .drive(
                        &listeners,
                        Some(Instant::now() + Duration::from_millis(2)),
                        |_| {}
                    )
                    .await?,
                Progress::WaitDeadline
            );
            assert_eq!(server.report().written_bytes, 0);
            let mut directory = management::Directory::new([0; 32], limits)?;
            for id in 1..=100_u8 {
                directory.path(&[[id; 32]])?;
            }
            let snapshot = directory.snapshot(management::Kind::Peers)?;
            let original_bytes = snapshot.bytes();
            server.bind_management(original, snapshot)?;
            until(
                &mut server,
                &listeners,
                |s| s.report().written_bytes == 1,
                &mut |_| {},
            )
            .await?;
            let partial = server
                .management_report(original.client())?
                .ok_or("missing original partial report")?;
            assert_eq!(partial.written_bytes, 1);
            assert!(partial.exposed);
            assert!(
                !partial
                    .pending
                    .ok_or("missing original immutable response")?
                    .is_end()
            );
            // The unfinished large query remains live while a different real MQ
            // enters the ordinary application branch without a management origin.
            let mut application = TcpStream::connect(listener.local_addr()?).await?;
            request(&mut application, Request::PortOpen { port: PORT }).await?;
            let mut ordinary = None;
            until(
                &mut server,
                &listeners,
                |s| s.report().inputs == 2,
                &mut |event| {
                    if let Event::Input {
                        client,
                        event: core::Event::PortOpened(_),
                    } = event
                    {
                        ordinary = Some(client);
                    }
                },
            )
            .await?;
            let ordinary =
                ordinary.ok_or("ordinary application did not progress beside slow query")?;
            assert_ne!(ordinary, original.client());
            assert_eq!(server.management_report(ordinary)?, None);
            assert_eq!(
                server
                    .management_report(original.client())?
                    .ok_or("lost slow query")?
                    .terminal,
                management::Terminal::Pending
            );

            let mut monitor = TcpStream::connect(listener.local_addr()?).await?;
            request(&mut monitor, Request::ListTunnels).await?;
            until(
                &mut server,
                &listeners,
                |s| s.report().inputs == 3,
                &mut |_| {},
            )
            .await?;
            let tunnel_query = server
                .pending_management()
                .ok_or("missing independent tunnel query")?;
            assert_eq!(tunnel_query.kind(), management::Kind::Tunnels);
            let mut directory = management::Directory::new([0; 32], limits)?;
            directory.path(&[[1; 32]])?;
            directory.connection([1; 32])?;
            directory.tunnel([1; 32], 2, 5)?;
            server.bind_management(tunnel_query, directory.snapshot(management::Kind::Tunnels)?)?;
            until(
                &mut server,
                &listeners,
                |s| {
                    s.management_report(tunnel_query.client())
                        .ok()
                        .flatten()
                        .is_some_and(|r| r.terminal == management::Terminal::EndWritten)
                },
                &mut |_| {},
            )
            .await?;
            let record = frame(&mut monitor).await?;
            assert_eq!(
                Response::decode(&record)?,
                Response::TunnelInfo {
                    peer: [1; 32],
                    channels: 2,
                    connections: 1,
                    encryption_state: 5,
                    connection_state: 0
                }
            );
            assert_eq!(
                Response::decode(&frame(&mut monitor).await?)?,
                Response::TunnelsEnd
            );
            assert_eq!(
                server
                    .management_report(original.client())?
                    .ok_or("slow query lost")?
                    .terminal,
                management::Terminal::Pending
            );

            // Same MQ may start its next query only after its original END really
            // finished writing. Target index1 excludes the local peer and the direct
            // neighbor; this is the actual official indirect-path wire structure.
            request(&mut monitor, Request::GetPath { peer: [2; 32] }).await?;
            until(
                &mut server,
                &listeners,
                |s| s.report().inputs == 4,
                &mut |_| {},
            )
            .await?;
            let path_query = server
                .pending_management()
                .ok_or("missing next original path query")?;
            assert_eq!(path_query.client(), tunnel_query.client());
            assert!(path_query.value() > tunnel_query.value());
            let mut directory = management::Directory::new([0; 32], limits)?;
            directory.path(&[[1; 32]])?;
            directory.path(&[[1; 32], [2; 32]])?;
            server.bind_management(
                path_query,
                directory.snapshot(management::Kind::Paths([2; 32]))?,
            )?;
            until(
                &mut server,
                &listeners,
                |s| {
                    s.management_report(path_query.client())
                        .ok()
                        .flatten()
                        .is_some_and(|r| {
                            r.query == path_query && r.terminal == management::Terminal::EndWritten
                        })
                },
                &mut |_| {},
            )
            .await?;
            let record = frame(&mut monitor).await?;
            let Response::PathInfo { offset, peers } = Response::decode(&record)? else {
                return Err("missing actual path response".into());
            };
            assert_eq!(offset, 1);
            assert_eq!(peers.iter().collect::<Vec<_>>(), [[1; 32], [2; 32]]);
            assert_eq!(
                Response::decode(&frame(&mut monitor).await?)?,
                Response::PathsEnd
            );

            until(
                &mut server,
                &listeners,
                |s| {
                    s.management_report(original.client())
                        .ok()
                        .flatten()
                        .is_some_and(|r| r.exposed && r.pending.is_some())
                },
                &mut |_| {},
            )
            .await?;
            let before = server
                .management_report(original.client())?
                .ok_or("missing close report")?;
            assert!(before.written_bytes > 0);
            assert!(before.written_bytes < u64::try_from(original_bytes)?);
            let mut stopped = None;
            let loss = server.close(original.client(), CloseCause::Requested, &mut |event| {
                if let Event::Management(management::Event::Stopped(report)) = event {
                    stopped = Some(report);
                }
            })?;
            assert_eq!(loss.client, original.client());
            assert!(loss.pending.is_none());
            assert!(!loss.exposed); // management bytes never changed pure app output
            let stopped = stopped.ok_or("management original loss facts were discarded")?;
            assert_eq!(stopped.query, original);
            assert_eq!(stopped.written_bytes, before.written_bytes);
            assert_eq!(stopped.terminal, management::Terminal::Interrupted);
            assert!(stopped.exposed);
            let mut prefix = Vec::new();
            slow.read_to_end(&mut prefix).await?;
            assert_eq!(u64::try_from(prefix.len())?, stopped.written_bytes);
            let mut cursor = 0;
            while prefix.len() - cursor >= 4 {
                let len = MessageHeader::decode(&prefix[cursor..])?.size();
                if prefix.len() - cursor < len {
                    break;
                }
                assert!(matches!(
                    Response::decode(&prefix[cursor..cursor + len])?,
                    Response::PeerInfo { .. }
                ));
                cursor += len;
            }
            assert!(cursor < prefix.len()); // true partial frame, no matching END
            request(&mut monitor, Request::GetChannel { peer: [1; 32] }).await?;
            let mut unsupported = false;
            until(
                &mut server,
                &listeners,
                |s| s.report().closed == 2,
                &mut |event| {
                    if let Event::Closed {
                        loss,
                        cause: CloseCause::Fault(Error::Protocol(ProtocolError::Unsupported)),
                    } = event
                    {
                        assert_eq!(loss.client, path_query.client());
                        unsupported = true;
                    }
                },
            )
            .await?;
            assert!(unsupported);
            let mut no_channel_end = Vec::new();
            monitor.read_to_end(&mut no_channel_end).await?;
            assert!(no_channel_end.is_empty());

            let mut replacement = TcpStream::connect(listener.local_addr()?).await?;
            request(&mut replacement, Request::ListPeers).await?;
            until(
                &mut server,
                &listeners,
                |s| s.report().inputs == 5,
                &mut |_| {},
            )
            .await?;
            let fresh = server
                .pending_management()
                .ok_or("missing fresh original query")?;
            assert_ne!(fresh.client(), original.client());
            let directory = management::Directory::new([0; 32], limits)?;
            assert_eq!(
                server.bind_management(original, directory.snapshot(management::Kind::Peers)?),
                Err(ProtocolError::StaleGeneration)
            );
            assert!(
                !server
                    .management_report(fresh.client())?
                    .ok_or("fresh query report missing")?
                    .snapshot
            );
            server.close_all(&mut |_| {})?;
            assert_eq!(server.report().accepted, 4);
            assert_eq!(server.report().closed, 4);
            Ok::<(), Failure>(())
        })
        .await
    })??;
    Ok(())
}
