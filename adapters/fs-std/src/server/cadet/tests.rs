//! Focused real Unix IPC fixtures, not official C or peer interoperability.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert actual native write prefixes, source retirement and retained positive ownership"
)]
use super::*;
use gnunet_cadet_host::{
    ChannelSlot, EndpointSource, Instance, Limits as NativeLimits, PortSlot, TransmitKind,
};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, SystemClock};
use gnunet_wire::official::cadet::{Request, Response};
use std::{
    error::Error as StdError,
    future::poll_fn,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Waker,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{sleep_until, timeout},
};

type Failure = Box<dyn StdError + Send + Sync>;
const WAIT: Duration = Duration::from_secs(5);
const QUERY_LIFETIME: Duration = Duration::from_millis(400);
const PEER: [u8; 32] = [0x22; 32];

struct Socket(PathBuf);
impl Socket {
    fn bind() -> Result<(Self, UnixListener), Failure> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = PathBuf::from(format!(
            "/tmp/gnrs-fs-cadet-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
    fn source(&self) -> EndpointSource {
        EndpointSource::unix_with_clock(self.0.clone(), Arc::new(FrozenClock))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}

/// Source time never reaches its query target. Only the original native hard
/// can settle a paused write or no-effect intent in these fixtures.
struct FrozenClock;
impl RuntimeClock for FrozenClock {
    fn sample(&self) -> Result<ClockSample, ProtocolError> {
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(1_000_000),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, ProtocolError> {
        SystemClock.subscribe()
    }
}

fn native<'id, 'slots>(
    instance: &'id mut Instance,
    ports: &'slots mut [PortSlot],
    channels: &'slots mut [ChannelSlot],
    source: EndpointSource,
    io_slice_bytes: usize,
) -> Result<Client<'id, 'slots>, Error> {
    Client::new(
        instance,
        source,
        ports,
        channels,
        NativeLimits {
            io_slice_bytes,
            ..NativeLimits::default()
        },
    )
}
fn search(query: [u8; 64]) -> Search<'static> {
    Search {
        options: 0,
        block_type: BlockType::DBLOCK,
        anonymity: 0,
        target: PEER,
        query,
        seen: &[],
    }
}
async fn drive_until<'id, 'slots>(
    router: &mut Router<'id, 'slots>,
    ready: impl Fn(&Router<'id, 'slots>) -> bool,
) -> Result<(), Failure> {
    timeout(WAIT, async {
        while !ready(router) {
            match poll_fn(|cx| router.poll_inner(cx, false)).await? {
                PeerProgress::Activity | PeerProgress::Ended(_) => {}
                _ => return Err("delivery escaped the disabled consumer gate".into()),
            }
            tokio::task::yield_now().await;
        }
        Ok::<(), Failure>(())
    })
    .await?
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    timeout(WAIT, async {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
        if length < 4 {
            return Err(io::Error::other("short native frame").into());
        }
        let mut bytes = vec![0; length];
        bytes[..4].copy_from_slice(&header);
        stream.read_exact(&mut bytes[4..]).await?;
        Ok::<_, Failure>(bytes)
    })
    .await?
}
async fn response(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    timeout(WAIT, stream.write_all(&bytes)).await??;
    Ok(())
}
async fn opened(stream: &mut UnixStream) -> Result<u32, Failure> {
    let bytes = frame(stream).await?;
    let Request::ChannelCreate {
        channel,
        peer,
        port,
        options,
    } = Request::decode(&bytes)?
    else {
        return Err("new MQ replayed application data instead of creating its own channel".into());
    };
    assert_eq!(peer, PEER);
    assert_eq!(port, hash512(PORT_LABEL));
    assert_eq!(options, 0);
    response(stream, Response::Ack { channel }).await?;
    Ok(channel)
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

#[test]
fn cancelled_partial_query_keeps_original_hard_and_recovers_without_replay() -> Result<(), Failure>
{
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let mut instance = Instance::new();
        let mut ports = [];
        let mut channels = [ChannelSlot::new(); 1];
        let client = native(&mut instance, &mut ports, &mut channels, socket.source(), 1)?;
        let mut router = Router::new(
            client,
            Limits {
                routes: 1,
                timeout: QUERY_LIFETIME,
            },
        )?;
        assert_eq!(router.admit(1, search([3; 64]))?, RouteAdmission::Queued);
        let hard = router.routes[0].hard;
        drive_until(&mut router, |r| r.client.epoch().is_some()).await?;
        let (mut peer, _) = timeout(WAIT, listener.accept()).await??;
        drive_until(&mut router, |r| {
            r.routes[0].channel.is_some() && r.client.pending_transmit().is_none()
        })
        .await?;
        opened(&mut peer).await?;
        drive_until(&mut router, |r| r.routes[0].query_write.is_some()).await?;
        let original = router.routes[0]
            .query_write
            .ok_or("original query was not admitted")?;
        assert_eq!(original.kind(), TransmitKind::Data);
        let mut prefix = [0; 1];
        timeout(WAIT, peer.read_exact(&mut prefix)).await??;
        PeerRouter::cancel(&mut router, 1)?;
        PeerRouter::cancel(&mut router, 1)?;
        assert_eq!(router.routes[0].hard, hard);
        assert!(router.routes[0].deadline.is_none());
        assert_eq!(router.admit(2, search([4; 64]))?, RouteAdmission::Idle);
        assert!(matches!(
            router.admit(2, search([4; 64])),
            Err(Error::Protocol(ProtocolError::StaleGeneration))
        ));

        // Dropped/paused observations retain a real one-byte native prefix.
        // Logical time is frozen; cancellation cannot grant a fresh lifetime.
        sleep_until(hard + Duration::from_millis(5)).await;
        drive_until(&mut router, |r| r.report.hard_retirements == 1).await?;
        let retired = router
            .report
            .last_retirement
            .as_ref()
            .ok_or("native retirement was not recorded")?;
        assert!(matches!(retired.cause, LossCause::Requested));
        let pending = retired
            .report
            .pending
            .ok_or("partial query was forgotten")?;
        assert_eq!(pending.transmit, original);
        assert!(pending.exposed);
        assert_eq!(router.report.timeouts, 0, "cancel is not a query timeout");
        assert!(router.routes.is_empty());
        assert!(router.native_target().is_none());

        let mut tail = Vec::new();
        timeout(WAIT, peer.read_to_end(&mut tail)).await??;
        assert!(
            tail.is_empty(),
            "old partial query was written after its hard bound"
        );

        assert_eq!(router.admit(3, search([5; 64]))?, RouteAdmission::Queued);
        drive_until(&mut router, |r| {
            r.routes[0].channel.is_some() && r.client.pending_transmit().is_none()
        })
        .await?;
        let (mut replacement, _) = timeout(WAIT, listener.accept()).await??;
        let new_channel = opened(&mut replacement).await?;
        drive_until(&mut router, |r| r.routes[0].metadata.is_some()).await?;
        let bytes = frame(&mut replacement).await?;
        let Request::Data {
            channel, messages, ..
        } = Request::decode(&bytes)?
        else {
            return Err("replacement MQ did not send the newly admitted query".into());
        };
        assert_eq!(channel, new_channel);
        assert_eq!(*Query::decode(messages)?.query, [5; 64]);
        PeerRouter::close(&mut router)?;
        Ok(())
    })
}

#[test]
fn observed_positive_survives_its_hard_and_another_routes_actual_source_retirement()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let mut instance = Instance::new();
        let mut ports = [];
        let mut channels = [ChannelSlot::new(); 2];
        let client = native(
            &mut instance,
            &mut ports,
            &mut channels,
            socket.source(),
            65535,
        )?;
        let mut router = Router::new(
            client,
            Limits {
                routes: 2,
                timeout: QUERY_LIFETIME,
            },
        )?;
        let mut storage = [0; 256];
        let encoded = gnunet_fs::content::encode_data(b"retained local fixture", &mut storage)?;
        let mut reply = vec![0; 16 + encoded.bytes().len()];
        Reply {
            block_type: BlockType::DBLOCK,
            expiration: AbsoluteTime::NEVER,
            block: encoded.bytes(),
        }
        .encode(&mut reply)?;
        assert_eq!(
            router.admit(1, search(encoded.key().query))?,
            RouteAdmission::Queued
        );
        let first_hard = router.routes[0].hard;
        drive_until(&mut router, |r| r.client.epoch().is_some()).await?;
        let (mut peer, _) = timeout(WAIT, listener.accept()).await??;
        drive_until(&mut router, |r| {
            r.routes[0].channel.is_some() && r.client.pending_transmit().is_none()
        })
        .await?;
        let channel = opened(&mut peer).await?;
        drive_until(&mut router, |r| r.routes[0].metadata.is_some()).await?;
        let _query = frame(&mut peer).await?;
        response(
            &mut peer,
            Response::Data {
                channel,
                priority: 0,
                messages: &reply,
            },
        )
        .await?;
        drive_until(&mut router, |r| r.retained_results() == 1).await?;
        assert!(router.native_target().is_none());
        sleep_until(first_hard + Duration::from_millis(5)).await;
        match poll_fn(|cx| Poll::Ready(router.poll_inner(cx, false))).await {
            Poll::Pending | Poll::Ready(Ok(PeerProgress::Activity)) => {}
            Poll::Ready(Err(error)) => return Err(error.into()),
            _ => return Err("an already held positive expired under backpressure".into()),
        }
        assert_eq!(router.retained_results(), 1);
        assert_eq!(router.report.hard_timeouts, 0);
        assert_eq!(router.report.losses, 0);

        assert_eq!(router.admit(2, search([9; 64]))?, RouteAdmission::Queued);
        let second_hard = router.routes[1].hard;
        drive_until(&mut router, |r| {
            r.routes[1].channel.is_some() && r.client.pending_transmit().is_none()
        })
        .await?;
        sleep_until(second_hard + Duration::from_millis(5)).await;
        drive_until(&mut router, |r| r.report.hard_retirements == 1).await?;
        assert_eq!(router.report.hard_timeouts, 1);
        assert_eq!(router.retained_results(), 1);
        assert!(router.routes[0].channel.is_none());
        assert!(
            router.routes[0]
                .packet
                .as_ref()
                .is_some_and(|p| !p.needs_ack)
        );
        assert!(router.native_target().is_none());
        let result = timeout(WAIT, poll_fn(|cx| router.poll_inner(cx, true))).await??;
        let PeerProgress::CadetReply { route, frame, .. } = result else {
            return Err("retired-source positive did not reach its original consumer".into());
        };
        assert_eq!(route, 1);
        assert_eq!(frame.bytes(), reply);
        PeerRouter::close(&mut router)?;
        Ok(())
    })
}

#[test]
fn unattached_intent_expires_without_a_fabricated_source_retirement() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let (socket, _listener) = Socket::bind()?;
        let mut instance = Instance::new();
        let mut ports = [];
        let mut channels = [ChannelSlot::new(); 1];
        let client = native(&mut instance, &mut ports, &mut channels, socket.source(), 1)?;
        let mut router = Router::new(
            client,
            Limits {
                routes: 1,
                timeout: Duration::from_millis(10),
            },
        )?;
        router.admit(1, search([3; 64]))?;
        sleep_until(router.routes[0].hard + Duration::from_millis(5)).await;
        assert!(matches!(
            poll_fn(|cx| router.poll_inner(cx, false)).await?,
            PeerProgress::Ended(1)
        ));
        assert!(router.client.epoch().is_none());
        assert!(router.report.last_retirement.is_none());
        assert_eq!(router.report.hard_timeouts, 1);
        assert_eq!(router.report.hard_retirements, 0);
        assert!(router.native_target().is_none());
        PeerRouter::close(&mut router)?;
        Ok(())
    })
}

#[test]
fn newly_processed_positive_after_original_hard_cannot_gain_a_deadline_exemption()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let mut instance = Instance::new();
        let mut ports = [];
        let mut channels = [ChannelSlot::new(); 1];
        let client = native(
            &mut instance,
            &mut ports,
            &mut channels,
            socket.source(),
            65535,
        )?;
        let mut router = Router::new(
            client,
            Limits {
                routes: 1,
                timeout: QUERY_LIFETIME,
            },
        )?;
        let mut storage = [0; 256];
        let encoded = gnunet_fs::content::encode_data(b"late local fixture", &mut storage)?;
        let mut reply = vec![0; 16 + encoded.bytes().len()];
        Reply {
            block_type: BlockType::DBLOCK,
            expiration: AbsoluteTime::NEVER,
            block: encoded.bytes(),
        }
        .encode(&mut reply)?;
        router.admit(1, search(encoded.key().query))?;
        let hard = router.routes[0].hard;
        drive_until(&mut router, |r| r.client.epoch().is_some()).await?;
        let (mut peer, _) = timeout(WAIT, listener.accept()).await??;
        drive_until(&mut router, |r| {
            r.routes[0].channel.is_some() && r.client.pending_transmit().is_none()
        })
        .await?;
        let channel = opened(&mut peer).await?;
        drive_until(&mut router, |r| r.routes[0].metadata.is_some()).await?;
        let _query = frame(&mut peer).await?;
        response(
            &mut peer,
            Response::Data {
                channel,
                priority: 0,
                messages: &reply,
            },
        )
        .await?;
        // Acquire an actual native receive token, then delay only its first
        // application admission. No Received/epoch/proof is fabricated here.
        let original = timeout(WAIT, async {
            loop {
                match poll_fn(|cx| router.client.poll(cx, None)).await? {
                    Step::Data(original) => return Ok::<_, Failure>(original),
                    Step::Activity { .. } | Step::Credit { .. } => {}
                    _ => return Err("unexpected source event before the real reply".into()),
                }
            }
        })
        .await??;
        sleep_until(hard + Duration::from_millis(5)).await;
        let mut cx = Context::from_waker(Waker::noop());
        router.data(original, &mut cx)?;
        assert_eq!(router.retained_results(), 0);
        assert_eq!(router.report.hard_timeouts, 1);
        assert!(!router.routes[0].active);
        assert!(router.expire_native()?);
        assert_eq!(router.report.hard_retirements, 1);
        assert_eq!(router.retained_results(), 0);
        PeerRouter::close(&mut router)?;
        Ok(())
    })
}

#[test]
fn zero_submicrosecond_and_unrepresentable_timeouts_refuse_before_native_work()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let (socket, _listener) = Socket::bind()?;
        for duration in [Duration::ZERO, Duration::from_nanos(1), Duration::MAX] {
            let mut instance = Instance::new();
            let mut ports = [];
            let mut channels = [ChannelSlot::new(); 1];
            let client = native(&mut instance, &mut ports, &mut channels, socket.source(), 1)?;
            assert!(matches!(
                Router::new(
                    client,
                    Limits {
                        routes: 1,
                        timeout: duration,
                    }
                ),
                Err(Error::Protocol(ProtocolError::InvalidInput))
            ));
        }
        Ok(())
    })
}
