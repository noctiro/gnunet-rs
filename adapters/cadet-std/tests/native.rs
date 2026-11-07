//! Real caller-owned Unix MQs witness retained cursors, credit and physical loss.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible native tests assert actual original socket effects and retained source identity"
)]
use gnunet_cadet_host::{
    Channel, ChannelSlot, Client, EndpointSource, Epoch, Error, Instance, Limits, LossCause,
    PortSlot, Step, Transmit,
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::cadet::{CLIENT_CHANNEL_BOUNDARY, Request, Response};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn StdError + Send + Sync>;
const MESSAGE: [u8; 8] = [0, 8, 0x12, 0x34, 1, 2, 3, 4];
const PORT: [u8; 64] = [5; 64];
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-cadet-native-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
    fn source(&self) -> EndpointSource {
        EndpointSource::unix(self.0.clone())
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err("short CADET frame".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn response(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = [0; 256];
    let length = response.encode(&mut bytes)?;
    for part in bytes[..length].chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn next<'id>(client: &mut Client<'id, '_>) -> Result<Step<'id>, Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // Poll and immediately cancel each pending observation. Only the native
        // owner may retain original connect/read/write state between these waits.
        let result = poll_fn(|cx| {
            let driving = client.drive(Some(deadline));
            let mut driving = std::pin::pin!(driving);
            Poll::Ready(driving.as_mut().poll(cx))
        })
        .await;
        match result {
            Poll::Ready(event) => return event,
            Poll::Pending => tokio::task::yield_now().await,
        }
    }
}
async fn connected<'id>(client: &mut Client<'id, '_>) -> Result<Epoch<'id>, Failure> {
    match next(client).await? {
        Step::Connected(source) => Ok(source),
        _ => Err("missing actual attachment".into()),
    }
}
async fn written<'id>(
    client: &mut Client<'id, '_>,
    expected: Transmit<'id>,
) -> Result<(), Failure> {
    loop {
        match next(client).await? {
            Step::Activity { .. } => {}
            Step::Written(actual) if actual.transmit == expected => return Ok(()),
            _ => return Err("event before original frame fully written".into()),
        }
    }
}
async fn credit<'id>(client: &mut Client<'id, '_>, expected: Channel<'id>) -> Result<(), Failure> {
    loop {
        match next(client).await? {
            Step::Activity { .. } => {}
            Step::Credit {
                channel,
                available: 1,
            } if channel == expected => return Ok(()),
            _ => return Err("missing actual CADET send credit".into()),
        }
    }
}

#[test]
fn original_partial_frames_survive_canceled_waits_and_processing_is_explicit() -> Result<(), Failure>
{
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = frame(&mut stream).await?;
            assert!(matches!(Request::decode(&first)?, Request::ChannelCreate { channel: CLIENT_CHANNEL_BOUNDARY, options: 0, .. }));
            response(&mut stream, Response::Ack { channel: CLIENT_CHANNEL_BOUNDARY }).await?;
            let data = frame(&mut stream).await?;
            assert!(matches!(Request::decode(&data)?, Request::Data { channel: CLIENT_CHANNEL_BOUNDARY, priority: 0xa1b2_c3d4, messages } if messages == MESSAGE));
            response(&mut stream, Response::Data { channel: CLIENT_CHANNEL_BOUNDARY, priority: 0, messages: &MESSAGE }).await?;
            let ack = frame(&mut stream).await?;
            assert_eq!(Request::decode(&ack)?, Request::Ack { channel: CLIENT_CHANNEL_BOUNDARY });
            response(&mut stream, Response::ChannelDestroy { channel: CLIENT_CHANNEL_BOUNDARY }).await?;
            assert_eq!(stream.read(&mut [0; 1]).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut identity = Instance::new();
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 2];
        let mut client = Client::new(&mut identity, socket.source(), &mut ports, &mut channels, Limits { io_slice_bytes: 1, ..Limits::default() })?;
        let source = connected(&mut client).await?;
        let channel = client.open([7; 32], PORT)?;
        assert_eq!(channel.epoch(), source);
        let create = client_pending(&client)?;
        written(&mut client, create).await?;
        assert!(matches!(client.send(channel, 0, &MESSAGE), Err(Error::Protocol(ProtocolError::WouldBlock))));
        credit(&mut client, channel).await?;
        let transmit = client.send(channel, 0xa1b2_c3d4, &MESSAGE)?;
        assert!(matches!(next(&mut client).await?, Step::Activity { written_bytes: 1, .. }));
        written(&mut client, transmit).await?;
        let received = loop {
            match next(&mut client).await? {
                Step::Activity { .. } => {},
                Step::Data(received) => break received,
                _ => return Err("missing actual owned DATA".into()),
            }
        };
        assert_eq!(received.channel(), channel);
        assert_eq!(received.messages(), MESSAGE);
        assert_eq!(received.frame().len(), 12 + MESSAGE.len());
        let delivery = received.delivery();
        drop(received);
        assert!(client.channel_info(channel)?.receive_pending);
        assert!(matches!(client.drive(Some(Instant::now() + Duration::from_millis(5))).await?, Step::WaitDeadline));
        let processing = client.receive_done(delivery)?;
        written(&mut client, processing).await?;
        assert!(matches!(client.receive_done(delivery), Err(Error::Protocol(ProtocolError::StaleGeneration))));
        loop {
            match next(&mut client).await? {
                Step::Activity { .. } => {},
                Step::Destroyed(original) if original == channel => break,
                _ => return Err("missing original channel destroy".into()),
            }
        }
        assert!(client.close()?.is_some());
        assert!(matches!(client.drive(None).await?, Step::Closed));
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
fn client_pending<'id>(client: &Client<'id, '_>) -> Result<Transmit<'id>, Failure> {
    client
        .pending_transmit()
        .ok_or_else(|| "missing original pending frame".into())
}

#[test]
fn physical_retirement_keeps_original_exposure_and_reannounces_ports_without_payload_replay()
-> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            assert_eq!(
                Request::decode(&frame(&mut first).await?)?,
                Request::PortOpen { port: PORT }
            );
            assert!(matches!(
                Request::decode(&frame(&mut first).await?)?,
                Request::ChannelCreate {
                    channel: CLIENT_CHANNEL_BOUNDARY,
                    ..
                }
            ));
            response(
                &mut first,
                Response::Ack {
                    channel: CLIENT_CHANNEL_BOUNDARY,
                },
            )
            .await?;
            let mut prefix = [0; 1];
            first.read_exact(&mut prefix).await?;
            assert_eq!(prefix, [0]);
            let mut rest = Vec::new();
            first.read_to_end(&mut rest).await?;
            assert!(rest.is_empty());
            let (mut second, _) = listener.accept().await?;
            assert_eq!(
                Request::decode(&frame(&mut second).await?)?,
                Request::PortOpen { port: PORT }
            );
            let mut unexpected = Vec::new();
            second.read_to_end(&mut unexpected).await?;
            assert!(unexpected.is_empty());
            Ok::<_, Failure>(())
        });
        let mut identity = Instance::new();
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 1];
        let mut client = Client::new(
            &mut identity,
            socket.source(),
            &mut ports,
            &mut channels,
            Limits {
                io_slice_bytes: 1,
                ..Limits::default()
            },
        )?;
        let first_source = connected(&mut client).await?;
        let port = client.listen(PORT)?;
        let announce = client_pending(&client)?;
        written(&mut client, announce).await?;
        let channel = client.open([8; 32], PORT)?;
        let create = client_pending(&client)?;
        written(&mut client, create).await?;
        credit(&mut client, channel).await?;
        let data = client.send(channel, 0, &MESSAGE)?;
        assert!(matches!(
            next(&mut client).await?,
            Step::Activity {
                written_bytes: 1,
                ..
            }
        ));
        let Step::Lost {
            report,
            cause: LossCause::Requested,
            ..
        } = client.reconnect()?
        else {
            return Err("missing physical retirement".into());
        };
        assert_eq!(report.epoch, first_source);
        assert_eq!(report.channels, 1);
        assert!(
            report
                .pending
                .is_some_and(|pending| pending.transmit == data && pending.exposed)
        );
        assert!(!client.port_announced(port)?);
        assert!(matches!(
            client.channel_info(channel),
            Err(Error::Protocol(ProtocolError::StaleGeneration))
        ));
        let next_source = connected(&mut client).await?;
        assert_ne!(first_source, next_source);
        loop {
            match next(&mut client).await? {
                Step::Activity { .. } => {}
                Step::Written(_) => break,
                _ => return Err("port not reannounced on original new MQ".into()),
            }
        }
        assert!(client.port_announced(port)?);
        assert!(client.pending_transmit().is_none());
        let loss = client.close()?.ok_or("missing second epoch close")?;
        assert_eq!(loss.channels, 0);
        assert!(loss.pending.is_none());
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn capacity_refusal_retains_original_frame_and_unknown_port_is_rejected() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(
                Request::decode(&frame(&mut stream).await?)?,
                Request::PortOpen { port: PORT }
            );
            response(
                &mut stream,
                Response::ChannelCreate {
                    channel: 0,
                    peer: [1; 32],
                    port: PORT,
                    options: 0,
                },
            )
            .await?;
            response(
                &mut stream,
                Response::ChannelCreate {
                    channel: 1,
                    peer: [2; 32],
                    port: PORT,
                    options: 0,
                },
            )
            .await?;
            assert_eq!(
                Request::decode(&frame(&mut stream).await?)?,
                Request::ChannelDestroy { channel: 0 }
            );
            response(
                &mut stream,
                Response::ChannelCreate {
                    channel: 2,
                    peer: [3; 32],
                    port: [6; 64],
                    options: 0,
                },
            )
            .await?;
            response(
                &mut stream,
                Response::Data {
                    channel: 1,
                    priority: 0,
                    messages: &MESSAGE,
                },
            )
            .await?;
            assert_eq!(
                Request::decode(&frame(&mut stream).await?)?,
                Request::ChannelDestroy { channel: 2 }
            );
            assert_eq!(stream.read(&mut [0; 1]).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut identity = Instance::new();
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 1];
        let mut client = Client::new(
            &mut identity,
            socket.source(),
            &mut ports,
            &mut channels,
            Limits {
                io_slice_bytes: 3,
                ..Limits::default()
            },
        )?;
        let source = connected(&mut client).await?;
        let _port = client.listen(PORT)?;
        let announce = client_pending(&client)?;
        written(&mut client, announce).await?;
        let original = loop {
            match next(&mut client).await? {
                Step::Activity { .. } => {}
                Step::Incoming { channel, .. } => break channel,
                _ => return Err("first incoming channel missing".into()),
            }
        };
        loop {
            match next(&mut client).await? {
                Step::Activity { .. } => {}
                Step::Blocked {
                    source: actual,
                    reason: ProtocolError::Capacity,
                    input_retained: true,
                } => {
                    assert_eq!(actual, source);
                    break;
                }
                _ => return Err("capacity did not retain original create".into()),
            }
        }
        assert!(matches!(
            next(&mut client).await?,
            Step::Blocked {
                reason: ProtocolError::Capacity,
                input_retained: true,
                ..
            }
        ));
        let destroy = client.destroy(original)?;
        written(&mut client, destroy).await?;
        let Step::Incoming {
            channel: replacement,
            ..
        } = next(&mut client).await?
        else {
            return Err("retained original frame was not retried".into());
        };
        assert_eq!(replacement.wire_id(), 1);
        assert_ne!(replacement, original);
        let rejected = loop {
            match next(&mut client).await? {
                Step::Activity { .. } => {}
                Step::RejectedIncoming {
                    channel: 2,
                    transmit,
                    ..
                } => break transmit,
                _ => return Err("unknown port not rejected".into()),
            }
        };
        written(&mut client, rejected).await?;
        loop {
            match next(&mut client).await? {
                Step::Activity { .. } => {}
                Step::Data(received) => {
                    assert_eq!(received.channel(), replacement);
                    assert_eq!(received.messages(), MESSAGE);
                    break;
                }
                _ => return Err("replacement DATA missing".into()),
            }
        }
        assert!(client.close()?.is_some());
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
