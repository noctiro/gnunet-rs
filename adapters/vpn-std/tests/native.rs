//! One actual Unix IPC model, with real AF_UNSPEC allocation failure because no
//! TUN/route was attached. No TUN qualification, exit or VPN data-path is faked.
#![expect(
    clippy::panic_in_result_fn,
    reason = "One focused native IPC model checks exact original frames, source retirement and finite cleanup"
)]
use gnunet_service_runtime::{
    clock::{ClockSample, ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
    service::{Listener, ServiceOptions},
};
use gnunet_types::Error as Fault;
use gnunet_vpn::{
    Address, ClientSlot, Engine, FlowSlot, Instance, LeaseSlot, Limits as CoreLimits, Outcome,
    PacketSlot, RequestSlot, Response, Storage, WireRequest,
};
use gnunet_vpn_host::server::{Error, Event, Limits, Progress, Server};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
struct Clock {
    fail: AtomicBool,
}
struct Subscription;
impl ClockSubscription for Subscription {
    fn poll_changed(&mut self, _: &mut Context<'_>, _: u64) -> Poll<Result<ClockSample, Fault>> {
        Poll::Pending
    }
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        if self.fail.load(Ordering::SeqCst) {
            Err(Fault::NotReady)
        } else {
            Ok(ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(1_000_000),
                revision: 0,
            })
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        Ok(Box::new(Subscription))
    }
}
fn request(id: [u8; 8]) -> WireRequest {
    WireRequest::Internet {
        reserved: 0,
        expires: 10_000_000,
        result_af: 0,
        destination: Address::V4([203, 0, 113, 9]),
        request_id: id,
    }
}
async fn send(stream: &mut UnixStream, id: [u8; 8]) -> Result<(), Box<dyn StdError>> {
    let r = request(id);
    let mut bytes = vec![0; r.encoded_len()?];
    r.encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}
async fn response(stream: &mut UnixStream) -> Result<Response, Box<dyn StdError>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(16..=32).contains(&n) {
        return Err("invalid actual response length".into());
    }
    let mut bytes = vec![0; n];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Response::decode(&bytes)?)
}
#[test]
fn bounded_capacity_original_rids_and_clock_loss_after_partial_write()
-> Result<(), Box<dyn StdError>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir =
            std::path::PathBuf::from(format!("/tmp/gvpn-ipc-{}-{nonce:x}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let path = dir.join("a");
        let listener = UnixListener::bind(&path)?;
        let clock = Arc::new(Clock {
            fail: AtomicBool::new(false),
        });
        let mut domain = Instance::new();
        let mut clients = [ClientSlot::new(); 2];
        let mut requests = [RequestSlot::new(); 1];
        let mut leases = [LeaseSlot::new(); 1];
        let mut flows = [FlowSlot::new(); 1];
        let mut slab = [0; 1284];
        let mut packets = [PacketSlot::new(&mut slab)];
        let core = Engine::new(
            &mut domain,
            Storage {
                clients: &mut clients,
                requests: &mut requests,
                leases: &mut leases,
                flows: &mut flows,
                packets: &mut packets,
            },
            CoreLimits {
                packet_bytes: 1280,
                ..CoreLimits::default()
            },
        )?;
        let mut server = Server::new(
            core,
            clock.clone(),
            Limits {
                clients: 2,
                requests_per_client: 2,
                io_slice_bytes: 1,
                input_timeout: Duration::from_secs(3),
                send_timeout: Duration::from_secs(3),
                ..Limits::default()
            },
            ServiceOptions::default(),
            UnixAccess::default(),
        )?;
        let mut a = UnixStream::connect(&path).await?;
        let mut b = UnixStream::connect(&path).await?;
        let until = Instant::now() + Duration::from_secs(5);
        let result = async {
            let mut blocked = 0;
            {
                // Same opaque RID on different actual MQs is legal. The single
                // request row forces complete RX Capacity while old TX drains.
                let actor = async {
                    send(&mut a, [0x91; 8]).await?;
                    send(&mut b, [0x91; 8]).await?;
                    for value in [response(&mut a).await?, response(&mut b).await?] {
                        assert_eq!(value.request_id, [0x91; 8]);
                        assert_eq!(value.address, None);
                    }
                    Ok::<_, Box<dyn StdError>>(())
                };
                let mut actor = std::pin::pin!(actor);
                poll_fn(|cx| {
                    if let Poll::Ready(result) = actor.as_mut().poll(cx) {
                        return Poll::Ready(result);
                    }
                    match server.poll(cx, &[Listener::Unix(&listener)], Some(until), &mut |e| {
                        if matches!(e, Event::Backpressured(_)) {
                            blocked += 1;
                        }
                    }) {
                        Poll::Ready(Ok(Progress::Activity)) => cx.waker().wake_by_ref(),
                        Poll::Ready(Ok(_)) => {
                            return Poll::Ready(Err("initial IPC model deadline".into()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Pending => {}
                    }
                    Poll::Pending
                })
                .await?;
            }
            assert!(blocked > 0);
            assert_eq!(server.report().written_frames, 2);
            assert_eq!(server.engine().requests().count(), 0);
            // Reuse the original RID only after its actual row retired. Stop
            // after exactly one positive byte, then make the logical clock fail.
            send(&mut a, [0x91; 8]).await?;
            poll_fn(|cx| {
                let mut exposed = false;
                match server.poll(
                    cx,
                    &[Listener::Unix(&listener)],
                    Some(until),
                    &mut |event| {
                        if let Event::Write {
                            bytes: 1,
                            complete: false,
                            ..
                        } = event
                        {
                            exposed = true;
                        }
                    },
                ) {
                    Poll::Ready(Ok(Progress::Activity)) => {
                        if exposed {
                            return Poll::Ready(Ok::<_, Box<dyn StdError>>(()));
                        }
                        cx.waker().wake_by_ref();
                    }
                    Poll::Ready(Ok(_)) => {
                        return Poll::Ready(Err("partial IPC model deadline".into()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {}
                }
                Poll::Pending
            })
            .await?;
            clock.fail.store(true, Ordering::SeqCst);
            let mut exposed_lost = false;
            poll_fn(|cx| {
                match server.poll(
                    cx,
                    &[Listener::Unix(&listener)],
                    Some(until),
                    &mut |event| {
                        if let Event::Retired { info, .. } = event
                            && matches!(
                                info.outcome,
                                Outcome::Lost {
                                    queued: true,
                                    exposed: true,
                                    reason: Fault::NotReady
                                }
                            )
                        {
                            exposed_lost = true;
                        }
                    },
                ) {
                    Poll::Ready(Err(Error::Protocol(Fault::NotReady))) => {
                        Poll::Ready(Ok::<_, Box<dyn StdError>>(()))
                    }
                    _ => Poll::Ready(Err(
                        "original clock error not returned after physical cleanup".into(),
                    )),
                }
            })
            .await?;
            assert!(exposed_lost);
            assert!(server.ipc_quiescent());
            assert_eq!(server.engine().requests().count(), 0);
            let mut suffix = Vec::new();
            a.read_to_end(&mut suffix).await?;
            assert_eq!(suffix.len(), 1);
            let mut other = Vec::new();
            b.read_to_end(&mut other).await?;
            assert!(other.is_empty());
            assert_eq!(server.report().accepted, 2);
            assert_eq!(server.report().closed, 2);
            assert_eq!(server.report().inputs, 3);
            assert_eq!(server.report().retired_requests, 3);
            assert_eq!(server.report().written_frames, 2);
            Ok::<_, Box<dyn StdError>>(())
        }
        .await;
        let stopped = server.shutdown(|_| {});
        drop(server);
        drop(a);
        drop(b);
        drop(listener);
        std::fs::remove_dir_all(dir)?;
        result?;
        if let Some(error) = stopped.failure {
            return Err(error.into());
        }
        Ok(())
    })
}
