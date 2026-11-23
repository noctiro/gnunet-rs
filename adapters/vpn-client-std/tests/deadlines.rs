//! Actual loopback prefix exposure with a frozen/failing canonical clock.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Original bytes, clock-free cancellation and native retirement are asserted"
)]
use gnunet_client_host::resolution::{AddressLookup, ResolutionContext, ResolutionTimer};
use gnunet_service_runtime::{
    clock::{ClockSample, ClockSubscription, Deadline, RuntimeClock},
    connection::ConnectionLease,
};
use gnunet_types::{AbsoluteTime, Error};
use gnunet_vpn_client_host::{
    Address, AfProfile, Cancel, Client, EndpointSource, Family, Instance, Limits, LossCause,
    Outcome, Progress, Reason, Submission,
};
use gnunet_wire::official::vpn;
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::Instant,
};
type Failure = Box<dyn StdError + Send + Sync>;

struct Clock {
    fail: AtomicBool,
    calls: AtomicUsize,
}
struct Subscription;
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            return Err(Error::Deadline);
        }
        Ok(ClockSample {
            now: AbsoluteTime::from_micros(1_000_000),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        Ok(Box::new(Subscription))
    }
}
impl ClockSubscription for Subscription {
    fn poll_changed(&mut self, _: &mut Context<'_>, _: u64) -> Poll<Result<ClockSample, Error>> {
        Poll::Pending
    }
}
struct Ports(Arc<Clock>);
struct Lookup(u8);
struct Lease;
impl ConnectionLease for Lease {}
impl AddressLookup for Lookup {
    fn poll_next(&mut self, _: &mut Context<'_>) -> Poll<io::Result<Option<IpAddr>>> {
        match self.0 {
            0 => {
                self.0 = 1;
                Poll::Ready(Ok(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))))
            }
            1 => Poll::Ready(Err(io::Error::other("numeric result not acknowledged"))),
            _ => Poll::Ready(Ok(None)),
        }
    }
    fn address_effect_done(&mut self) -> io::Result<()> {
        if self.0 != 1 {
            return Err(io::Error::other("no original numeric result"));
        }
        self.0 = 2;
        Ok(())
    }
    fn connected(self: Box<Self>) -> io::Result<Box<dyn ConnectionLease>> {
        if self.0 != 2 {
            return Err(io::Error::other("numeric effect not acknowledged"));
        }
        Ok(Box::new(Lease))
    }
}
impl ResolutionContext for Ports {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.0.clone()
    }
    fn lookup(&self, host: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        if host != b"127.0.0.1" {
            return Err(io::Error::other("fixture accepts numeric loopback only"));
        }
        Ok(Some(Box::new(Lookup(0))))
    }
    fn timer(&self, delay: Duration) -> io::Result<ResolutionTimer> {
        let timer = Deadline::after(self.0.clone(), delay).map_err(io::Error::other)?;
        Ok(Box::pin(
            async move { timer.await.map_err(io::Error::other) },
        ))
    }
}
fn source(address: SocketAddr, clock: Arc<Clock>) -> Result<EndpointSource, Failure> {
    let mut config = gnunet_config::Configuration::default();
    config.set_value(b"vpn", b"HOSTNAME", Some(b"127.0.0.1"))?;
    config.set_value(b"vpn", b"PORT", Some(address.port().to_string().as_bytes()))?;
    Ok(EndpointSource::configuration(
        config,
        b"vpn",
        Arc::new(Ports(clock)),
    ))
}
async fn prefix(client: &mut Client<'_>, listener: TcpListener) -> Result<TcpStream, Failure> {
    let until = Instant::now() + Duration::from_secs(5);
    let mut sending = std::pin::pin!(async {
        loop {
            match client.drive(Some(until)).await? {
                Progress::Activity {
                    written_bytes: 3, ..
                } => return Ok::<(), Failure>(()),
                Progress::WaitDeadline => return Err("prefix write timed out".into()),
                Progress::Lost { .. } | Progress::Completed { .. } | Progress::Closed => {
                    return Err("allocation ended before prefix exposure".into());
                }
                _ => {}
            }
        }
    });
    let mut reading = std::pin::pin!(async move {
        let (mut peer, _) = listener.accept().await?;
        let mut bytes = [0; 3];
        peer.read_exact(&mut bytes).await?;
        assert_eq!(
            bytes,
            [0, 36, 0],
            "actual prefix of the official IPv4 redirect"
        );
        Ok::<_, Failure>(peer)
    });
    let mut written = false;
    let mut peer = None;
    tokio::time::timeout_at(
        until,
        poll_fn(|cx| {
            if !written && let Poll::Ready(result) = sending.as_mut().poll(cx) {
                if let Err(error) = result {
                    return Poll::Ready(Err(error));
                }
                written = true;
            }
            if peer.is_none()
                && let Poll::Ready(result) = reading.as_mut().poll(cx)
            {
                match result {
                    Ok(value) => peer = Some(value),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            if written && peer.is_some() {
                Poll::Ready(peer.take().ok_or_else(|| "original peer absent".into()))
            } else {
                Poll::Pending
            }
        }),
    )
    .await?
}

#[test]
fn partial_response_retires_its_original_mq_without_a_clock_sample() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let clock = Arc::new(Clock {
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut instance = Instance::new();
        let profile = AfProfile::native();
        let mut client = Client::new(
            &mut instance,
            source(listener.local_addr()?, clock.clone())?,
            profile,
            Limits {
                io_slice_bytes: 3,
                input_timeout: Duration::from_millis(200),
                ..Limits::default()
            },
        )?;
        let operation = client.internet(
            Address::V4([192, 0, 2, 1]),
            Some(Family::V4),
            u64::MAX,
            10_000_000,
        )?;
        let mut peer = prefix(&mut client, listener).await?;
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            match client.drive(Some(until)).await? {
                Progress::Written {
                    operation: sent, ..
                } if sent == operation => break,
                Progress::Activity { .. } => {}
                _ => return Err("original VPN request did not finish writing".into()),
            }
        }
        let mut request = [0; 36];
        request[..3].copy_from_slice(&[0, 36, 0]);
        tokio::time::timeout_at(until, peer.read_exact(&mut request[3..])).await??;
        let vpn::Request::Internet { request_id, .. } =
            vpn::Request::decode_with_profile(&request, profile)?
        else {
            return Err("expected original redirect".into());
        };
        let response = vpn::Response {
            request_id,
            address: Some(Address::V4([10, 0, 0, 1])),
        };
        let mut bytes = vec![0; response.encoded_len()?];
        response.encode_with_profile(&mut bytes, profile)?;
        let request_deadline = client
            .next_native_deadline()
            .ok_or("missing request deadline")?;
        let mut input_deadline = None;
        for byte in &bytes[..2] {
            peer.write_all(std::slice::from_ref(byte)).await?;
            assert!(matches!(
                client.drive(Some(until)).await?,
                Progress::Activity { read_bytes: 1, .. }
            ));
            let current = client
                .next_native_deadline()
                .ok_or("missing input deadline")?;
            assert!(current < request_deadline);
            if let Some(first) = input_deadline {
                assert_eq!(
                    current, first,
                    "new bytes renewed the partial response deadline"
                );
            } else {
                input_deadline = Some(current);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        clock.fail.store(true, Ordering::Relaxed);
        let calls = clock.calls.load(Ordering::Relaxed);
        let loss = tokio::time::timeout_at(
            until,
            poll_fn(|cx| {
                client
                    .poll_native_guard(cx)
                    .map_or(Poll::Pending, Poll::Ready)
            }),
        )
        .await??;
        let Progress::Lost {
            epoch: Some(epoch),
            cause: LossCause::Deadline,
        } = loss
        else {
            return Err("partial input did not retire the original MQ".into());
        };
        assert!(matches!(client.next_event(), Some(Progress::Completed {
            epoch: Some(original_epoch), operation: original,
            outcome: Outcome::Local { reason: Reason::Lost, submission: Submission::Unknown },
        }) if original_epoch == epoch && original == operation));
        assert_eq!(clock.calls.load(Ordering::Relaxed), calls);
        assert_eq!(client.pending(), 0);
        assert!(client.next_native_deadline().is_none());
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout_at(until, peer.read(&mut byte)).await??,
            0
        );
        Ok(())
    })
}

#[test]
fn partial_cancel_does_not_consult_the_failed_clock() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let clock = Arc::new(Clock { fail: AtomicBool::new(false), calls: AtomicUsize::new(0) });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut instance = Instance::new();
        let mut client = Client::new(&mut instance, source(listener.local_addr()?, clock.clone())?, AfProfile::native(), Limits {
            io_slice_bytes: 3, retirement_grace_micros: 20_000, ..Limits::default()
        })?;
        let operation = client.internet(Address::V4([192, 0, 2, 1]), Some(Family::V4), u64::MAX, 3_000_000)?;
        let mut peer = prefix(&mut client, listener).await?;
        clock.fail.store(true, Ordering::Relaxed);
        let calls = clock.calls.load(Ordering::Relaxed);
        let cancelled = client.cancel(operation);
        assert!(matches!(cancelled, Ok(Cancel::Draining)), "failed clock replaced cancellation: {cancelled:?}");
        assert_eq!(clock.calls.load(Ordering::Relaxed), calls, "cancellation must not sample canonical time");
        let loss = tokio::time::timeout(Duration::from_secs(1), poll_fn(|cx| {
            client.poll_native_guard(cx).map_or(Poll::Pending, Poll::Ready)
        })).await??;
        assert!(matches!(loss, Progress::Lost { cause: LossCause::Deadline, .. }), "native retirement must precede any failed canonical clock access");
        assert_eq!(clock.calls.load(Ordering::Relaxed), calls);
        assert!(matches!(client.next_event(), Some(Progress::Completed {
            operation: original, outcome: Outcome::Local { reason: Reason::Cancelled, submission: Submission::Unknown }, ..
        }) if original == operation));
        assert_eq!(client.pending(), 0);
        let mut byte = [0; 1];
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??, 0);
        client.close()?;
        Ok(())
    })
}

#[test]
fn an_unissued_response_window_expires_without_a_clock_sample() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let clock = Arc::new(Clock { fail: AtomicBool::new(false), calls: AtomicUsize::new(0) });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut instance = Instance::new();
        let mut client = Client::new(&mut instance, source(listener.local_addr()?, clock.clone())?, AfProfile::native(), Limits::default())?;
        let operation = client.internet(Address::V4([192, 0, 2, 1]), Some(Family::V4), u64::MAX, 1_100_000)?;
        clock.fail.store(true, Ordering::Relaxed);
        let calls = clock.calls.load(Ordering::Relaxed);
        let event = tokio::time::timeout(Duration::from_secs(1), poll_fn(|cx| {
            client.poll_native_guard(cx).map_or(Poll::Pending, Poll::Ready)
        })).await??;
        assert!(matches!(event, Progress::Completed {
            epoch: None, operation: original, outcome: Outcome::Local { reason: Reason::Deadline, submission: Submission::Unsent }
        } if original == operation));
        assert_eq!(clock.calls.load(Ordering::Relaxed), calls);
        assert_eq!(client.pending(), 0);
        assert!(tokio::time::timeout(Duration::from_millis(10), listener.accept()).await.is_err(), "retirement must not start an idle connection");
        client.close()?;
        Ok(())
    })
}
