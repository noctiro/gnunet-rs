//! Slow providers may not create a socket or expose a queued MQ prefix late.
use super::*;
use gnunet_service_runtime::clock::{ClockSample, SystemClock};
use std::sync::atomic::AtomicBool;

struct SlowClock {
    armed: AtomicBool,
}
impl RuntimeClock for SlowClock {
    fn sample(&self) -> Result<ClockSample, Protocol> {
        if self.armed.swap(false, Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(60));
        }
        SystemClock.sample()
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Protocol> {
        SystemClock.subscribe()
    }
}

#[test]
fn slow_clock_cannot_create_a_socket_or_write_a_prefix_after_expiry() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for mode in 0..3 {
                let attached = mode == 2;
                let directory = Directory::new()?;
                let service_path = directory.0.join("transport");
                let socket_path = directory.0.join("datagram");
                let listener = UnixListener::bind(&service_path)?;
                let clock = Arc::new(SlowClock {
                    armed: AtomicBool::new(false),
                });
                let instance = Instance::new();
                let mut pils_instance = gnunet_pils::client::Instance::new();
                let mut runtime = Runtime::bind(
                    &instance,
                    &mut pils_instance,
                    Sources {
                        transport: EndpointSource::unix_with_clock(service_path, clock.clone()),
                        pils: EndpointSource::unix_with_clock(
                            directory.0.join("pils"),
                            clock.clone(),
                        ),
                    },
                    socket_path.as_os_str().as_bytes(),
                    Limits::default(),
                )?;
                let peer = if attached {
                    poll_fn(|cx| runtime.poll_connect(cx, &mut |_| {})).await?;
                    let (peer, _) = listener.accept().await?;
                    let now = clock.sample()?.now.as_micros();
                    runtime.enqueue(
                        encode(Request::Register {
                            characteristics: Characteristics::Reliable,
                            can_burst: false,
                            prefix: b"unix",
                        })?,
                        Role::Register,
                        runtime.operation(now)?,
                        &mut |_| {},
                    )?;
                    Some(peer)
                } else {
                    None
                };
                runtime.parent.hard = Instant::now() + Duration::from_millis(40);
                clock.armed.store(true, Ordering::SeqCst);
                if mode == 1 {
                    // Bypass the outer scheduler: the retained connector itself
                    // must refuse after a clock provider crosses the bound.
                    let result = runtime.poll_connect(
                        &mut Context::from_waker(std::task::Waker::noop()),
                        &mut |_| {},
                    );
                    check(matches!(result, Poll::Ready(Err(_))))?;
                    check(
                        listener
                            .poll_accept(&mut Context::from_waker(std::task::Waker::noop()))
                            .is_pending(),
                    )?;
                    runtime.close(&mut |_| {});
                    continue;
                }
                let result = runtime.poll(
                    &mut Context::from_waker(std::task::Waker::noop()),
                    None,
                    &mut |_| {},
                );
                check(matches!(
                    result,
                    Poll::Ready(Err(Error {
                        cause: Fault::Deadline,
                        ..
                    }))
                ))?;
                check(runtime.closed && !socket_path.exists())?;
                if let Some(mut peer) = peer {
                    let mut byte = [0];
                    check(peer.read(&mut byte).await? == 0)?;
                } else {
                    check(
                        listener
                            .poll_accept(&mut Context::from_waker(std::task::Waker::noop()))
                            .is_pending(),
                    )?;
                }
            }
            Ok(())
        })
}
