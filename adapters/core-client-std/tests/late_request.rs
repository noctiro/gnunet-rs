//! Actual bidirectional Unix order for a retained old request after peer reconnect.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The witness asserts original permit authority and exact physical ordering."
)]
use gnunet_client::core::{
    ClassOrder, ConnectionEpoch, CoreClient, Event, Instance, PeerClass, PeerId, Request, Response,
    SendOutcome,
};
use gnunet_service_runtime::{
    connection::Connection,
    framing::{Accounting, Budget, Class, Framed, Limits, OwnedFrame, ReadStep},
};
use std::{error::Error, future::poll_fn, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const ORDER: ClassOrder = ClassOrder::Little;
const LOCAL: PeerId = PeerId([0x22; 32]);
const A: PeerId = PeerId([0x11; 32]);
const B: PeerId = PeerId([0x33; 32]);
const MSG: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];
type Core<'i> = CoreClient<'i, 4, 8>;
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    response: Response<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut bytes = [0; 128];
    let len = response.encode(&mut bytes, ORDER)?;
    stream.write_all(&bytes[..len]).await?;
    Ok(())
}
async fn frame(
    stream: &mut tokio::net::UnixStream,
    first: Option<u8>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut h = [0; 4];
    if let Some(byte) = first {
        h[0] = byte;
        stream.read_exact(&mut h[1..]).await?;
    } else {
        stream.read_exact(&mut h).await?;
    }
    let len = u16::from_be_bytes([h[0], h[1]]) as usize;
    if len < 4 {
        return Err("short frame".into());
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&h);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn event<'i>(
    core: &mut Core<'i>,
    framed: &mut Framed<u8>,
    epoch: ConnectionEpoch<'i>,
) -> Result<Event<'i, 'static>, Box<dyn Error + Send + Sync>> {
    loop {
        match poll_fn(|cx| framed.poll_read(cx)).await? {
            ReadStep::Eof => return Err("unexpected EOF".into()),
            ReadStep::Progress {
                complete: false, ..
            } => {}
            ReadStep::Progress { complete: true, .. } => {
                let response = core.receive(epoch, framed.frame().ok_or("missing frame")?)?;
                let owned = match response {
                    Event::Ready {
                        local,
                        previous_identity,
                    } => Event::Ready {
                        local,
                        previous_identity,
                    },
                    Event::Connected(p) => Event::Connected(p),
                    Event::Disconnected(p) => Event::Disconnected(p),
                    Event::SendReady { send, capacity } => Event::SendReady { send, capacity },
                    Event::IgnoredReady { peer, request_id } => {
                        Event::IgnoredReady { peer, request_id }
                    }
                    _ => return Err("unexpected event".into()),
                };
                assert!(framed.release_frame());
                return Ok(owned);
            }
        }
    }
}
#[test]
fn retained_partial_old_request_cannot_grant_new_generation()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    runtime
        .block_on(tokio::time::timeout(Duration::from_secs(3), async {
            let (client, mut server) = tokio::net::UnixStream::pair()?;
            let server_task = tokio::spawn(async move {
                let init = frame(&mut server, None).await?;
                assert!(matches!(Request::decode(&init)?, Request::Init { .. }));
                write_response(
                    &mut server,
                    Response::InitReply {
                        identity: LOCAL,
                        class: PeerClass::SERVER,
                    },
                )
                .await?;
                write_response(
                    &mut server,
                    Response::Connected {
                        peer: A,
                        class: PeerClass::ROUTER,
                    },
                )
                .await?;
                write_response(
                    &mut server,
                    Response::Connected {
                        peer: B,
                        class: PeerClass::ROUTER,
                    },
                )
                .await?;
                // Read only one real request byte. It has not yet been parsed or admitted.
                let mut first = [0; 1];
                server.read_exact(&mut first).await?;
                write_response(&mut server, Response::Disconnected(A)).await?;
                write_response(
                    &mut server,
                    Response::Connected {
                        peer: A,
                        class: PeerClass::ROUTER,
                    },
                )
                .await?;
                // The original request is parsed only after the new same-PID record exists.
                let old = frame(&mut server, Some(first[0])).await?;
                let (id, size) = match Request::decode(&old)? {
                    Request::SendRequest {
                        peer,
                        request_id,
                        size,
                        ..
                    } if peer == A => (request_id, size),
                    _ => return Err("not original request".into()),
                };
                write_response(
                    &mut server,
                    Response::SendReady {
                        peer: A,
                        request_id: id,
                        size,
                    },
                )
                .await?;
                Ok::<_, Box<dyn Error + Send + Sync>>((id, size, old.len()))
            });
            let mut instance = Instance::new();
            let mut core = Core::new(&mut instance, ORDER, 0, &[0])?;
            let mut output = [0; 128];
            let (epoch, len) = core.begin(&mut output)?;
            let mut framed = Framed::new(
                Connection::from_unix(client),
                Limits {
                    frame_bytes: 65535,
                    ordinary: Budget {
                        frames: 4,
                        bytes: 4 * 65535,
                    },
                    reserved: Budget::default(),
                    accounting: Accounting::Retained,
                    io_slice_bytes: 1,
                },
            )?;
            framed
                .enqueue_owned(OwnedFrame::copy_from(&output[..len])?, 0, Class::Ordinary)
                .map_err(|r| r.reason)?;
            while framed.queued_frames() > 0 {
                poll_fn(|cx| framed.poll_write(cx)).await?;
            }
            assert!(matches!(
                event(&mut core, &mut framed, epoch).await?,
                Event::Ready { .. }
            ));
            let old_peer = match event(&mut core, &mut framed, epoch).await? {
                Event::Connected(p) => p,
                _ => return Err("no old A".into()),
            };
            let healthy_b = match event(&mut core, &mut framed, epoch).await? {
                Event::Connected(p) => p,
                _ => return Err("no B".into()),
            };
            let (old, old_len) = core
                .request_send(old_peer, 0, 0, MSG, &mut output)
                .map_err(|r| r.reason)?;
            let old_id = match Request::decode(&output[..old_len])? {
                Request::SendRequest { request_id, .. } => request_id,
                _ => return Err("old wire".into()),
            };
            framed
                .enqueue_owned(
                    OwnedFrame::copy_from(&output[..old_len])?,
                    1,
                    Class::Ordinary,
                )
                .map_err(|r| r.reason)?;
            let first = poll_fn(|cx| framed.poll_write(cx)).await?;
            assert_eq!(first.origin, 1);
            assert_eq!(first.bytes, 1);
            assert!(!first.complete);
            assert_eq!(
                event(&mut core, &mut framed, epoch).await?,
                Event::Disconnected(old_peer)
            );
            assert_eq!(
                core.finish(old).map_err(|r| r.reason)?.outcome,
                SendOutcome::PeerDisconnected
            );
            let new_peer = match event(&mut core, &mut framed, epoch).await? {
                Event::Connected(p) => p,
                _ => return Err("no new A".into()),
            };
            assert_ne!(new_peer, old_peer);
            let (new, new_len) = core
                .request_send(new_peer, 0, 0, MSG, &mut output)
                .map_err(|r| r.reason)?;
            framed
                .enqueue_owned(
                    OwnedFrame::copy_from(&output[..new_len])?,
                    2,
                    Class::Ordinary,
                )
                .map_err(|r| r.reason)?;
            // Complete ONLY the old original frame. New request bytes remain entirely local.
            loop {
                let progress = poll_fn(|cx| framed.poll_write(cx)).await?;
                assert_eq!(progress.origin, 1);
                if progress.complete {
                    break;
                }
            }
            let response = event(&mut core, &mut framed, epoch).await?;
            let observed = server_task.await??;
            assert_eq!(observed, (old_id, 8, old_len));
            assert_eq!(framed.queued_frames(), 1);
            assert_eq!(
                response,
                Event::IgnoredReady {
                    peer: A,
                    request_id: old_id
                }
            );
            assert_eq!(
                core.prepare_payload(&new, &mut output).err(),
                Some(gnunet_types::Error::NotReady)
            );
            assert_eq!(core.peer(B), Some(healthy_b));
            framed.retire();
            core.connection_lost(epoch)?;
            let result = core.finish(new).map_err(|r| r.reason)?;
            assert_eq!(result.outcome, SendOutcome::ConnectionLost);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }))
        .map_err(Box::<dyn Error + Send + Sync>::from)??;
    Ok(())
}
