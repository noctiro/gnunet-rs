//! Actual immutable-bound and explicit Clock-port provenance. No remote result
//! or source success is supplied by these deadline/refusal-only cases.
use super::*;
use crate::{Cause, LossOrigin, OperationType};
use gnunet_client_host::{ConnectError, resolution::PortError};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, SystemClock};
use std::{
    error::Error as StdError,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::Waker,
    time::Duration,
};

type Failure = Box<dyn StdError>;
struct Clock {
    now: AtomicU64,
    sample_refused: AtomicBool,
    subscribe_refused: AtomicBool,
    notify_refused: Arc<AtomicBool>,
    advance_on_sample: AtomicU64,
}
impl Clock {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(1_000_000),
            sample_refused: AtomicBool::new(false),
            subscribe_refused: AtomicBool::new(false),
            notify_refused: Arc::new(AtomicBool::new(false)),
            advance_on_sample: AtomicU64::new(0),
        }
    }
}
struct Subscription {
    refused: Arc<AtomicBool>,
    original: Box<dyn ClockSubscription>,
}
impl ClockSubscription for Subscription {
    fn poll_changed(
        &mut self,
        cx: &mut Context<'_>,
        revision: u64,
    ) -> Poll<Result<ClockSample, Fault>> {
        if self.refused.load(Ordering::Acquire) {
            Poll::Ready(Err(Fault::Deadline))
        } else {
            self.original.poll_changed(cx, revision)
        }
    }
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        if self.sample_refused.load(Ordering::Acquire) {
            return Err(Fault::Deadline);
        }
        let advance = self.advance_on_sample.swap(0, Ordering::AcqRel);
        if advance != 0 {
            self.now.store(advance, Ordering::Release);
        }
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(self.now.load(Ordering::Acquire)),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        if self.subscribe_refused.load(Ordering::Acquire) {
            return Err(Fault::Deadline);
        }
        Ok(Box::new(Subscription {
            refused: self.notify_refused.clone(),
            original: SystemClock.subscribe()?,
        }))
    }
}
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err("SET failure provenance changed".into())
    }
}
fn session(clock: Arc<Clock>, original: Bounds) -> Result<Session<u8>, Error> {
    Session::new(
        // These guards/refused ports end before any connect is polled. This
        // path is never created or used as a substitute remote SET service.
        EndpointSource::unix_with_clock("/tmp/gnrs-set-unused-provenance.sock".into(), clock),
        crate::encode(gnunet_wire::official::set::ClientRequest::Create {
            operation: OperationType::Union as u32,
        })?,
        Limits::default(),
        original,
    )
}
fn clock_protocol_deadline(error: Error) -> Result<(), Failure> {
    check(error.origin() == LossOrigin::Clock)?;
    check(matches!(
        error,
        Error::Clock(ConnectError::Protocol(Fault::Deadline))
    ))
}
fn clock_port_deadline(error: Error) -> Result<(), Failure> {
    check(error.origin() == LossOrigin::Clock)?;
    let Error::Clock(ConnectError::Io(error)) = error else {
        return Err("actual Clock port I/O marker was replaced".into());
    };
    let port = PortError::from_io(&error).ok_or("original Clock port marker missing")?;
    check(
        port.cause()
            .get_ref()
            .and_then(|error| error.downcast_ref::<Fault>())
            == Some(&Fault::Deadline),
    )
}

#[test]
fn clock_deadline_is_distinct_from_actual_bound_expiry() -> Result<(), Failure> {
    let clock = Clock::new();
    let original = Bounds::new(&clock, Duration::from_secs(30))?;
    clock.sample_refused.store(true, Ordering::Release);
    let error = match Bounds::new(&clock, Duration::from_secs(30)) {
        Ok(_) => return Err("refused Clock constructed a new budget".into()),
        Err(error) => error,
    };
    clock_protocol_deadline(error)?;
    let error = match original.check(&clock) {
        Ok(()) => return Err("refused Clock validated a budget".into()),
        Err(error) => error,
    };
    clock_protocol_deadline(error)?;
    clock.sample_refused.store(false, Ordering::Release);
    clock.now.store(original.expires, Ordering::Release);
    let error = original
        .check(&clock)
        .err()
        .ok_or("expired original budget passed")?;
    let context = error
        .deadline_context()
        .ok_or("actual bound context missing")?;
    check(
        context.scope == DeadlineScope::Budget
            && context.expires == Some(original.expires)
            && context.hard == original.hard
            && context.observed_canonical == Some(original.expires),
    )?;
    check(Cause::from(error).origin() == LossOrigin::Bounds)?;
    // An identical low-level value cannot reclassify a shared provider refusal.
    check(Cause::from(Error::clock(Fault::Deadline)).origin() == LossOrigin::Clock)
}

#[test]
fn actual_channel_subscription_and_notification_keep_clock_port_errors() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let clock = Arc::new(Clock::new());
            let original = Bounds::new(clock.as_ref(), Duration::from_secs(30))?;
            clock.subscribe_refused.store(true, Ordering::Release);
            let error = match session(clock.clone(), original) {
                Ok(_) => return Err(Failure::from("refused subscription constructed a Session")),
                Err(error) => error,
            };
            clock_port_deadline(error)?;
            clock.subscribe_refused.store(false, Ordering::Release);
            let mut owner = session(clock.clone(), original)?;
            clock.notify_refused.store(true, Ordering::Release);
            let mut cx = Context::from_waker(Waker::noop());
            let cause = match owner.poll(&mut cx) {
                Poll::Ready(Err(cause)) => cause,
                _ => return Err("refused notification lost its original failure".into()),
            };
            check(cause.origin() == LossOrigin::Clock)?;
            check(cause.deadline_context().is_none())?;
            clock_port_deadline(cause)
        })
}

#[test]
fn canonical_and_native_session_targets_produce_same_deadline_cause() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for native in [false, true] {
                let clock = Arc::new(Clock::new());
                let lifetime = if native {
                    Duration::from_millis(80)
                } else {
                    Duration::from_secs(30)
                };
                let original = Bounds::new(clock.as_ref(), lifetime)?;
                let mut owner = session(clock.clone(), original)?;
                if native {
                    tokio::time::sleep_until(original.hard.into()).await;
                    // A clock-free native refusal must not sample this provider.
                    clock.sample_refused.store(true, Ordering::Release);
                } else {
                    clock.now.store(original.expires, Ordering::Release);
                }
                let mut cx = Context::from_waker(Waker::noop());
                let cause = match owner.poll(&mut cx) {
                    Poll::Ready(Err(cause)) => cause,
                    _ => return Err(Failure::from("expired original Session target continued")),
                };
                check(cause.origin() == LossOrigin::Bounds)?;
                let context = cause
                    .deadline_context()
                    .ok_or("original Session target missing")?;
                check(
                    context.scope == DeadlineScope::Overall
                        && context.hard == original.hard
                        && context.expires == Some(original.expires)
                        && context.observed_canonical
                            == if native { None } else { Some(original.expires) }
                        && (!native || context.observed_native >= original.hard),
                )?;
                check(matches!(Cause::from(cause), Cause::Deadline))?;
                check(
                    owner.original().hard == original.hard
                        && owner.original().expires == original.expires,
                )?;
            }
            Ok(())
        })
}

struct Socket(std::path::PathBuf);
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}

#[test]
fn final_native_read_checks_existing_partial_target_before_clearing_it() -> Result<(), Failure> {
    use std::{
        future::{Future, poll_fn},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let socket = Socket(
                format!("/tmp/gnrs-set-postio-{}-{stamp:x}.sock", std::process::id()).into(),
            );
            let listener = UnixListener::bind(&socket.0)?;
            let clock = Arc::new(Clock::new());
            let original = Bounds::new(clock.as_ref(), Duration::from_secs(5))?;
            let mut owner: Session<u8> = Session::new(
                EndpointSource::unix_with_clock(socket.0.clone(), clock.clone()),
                crate::encode(gnunet_wire::official::set::ClientRequest::Create { operation: 2 })?,
                Limits {
                    input_timeout: Duration::from_secs(1),
                    ..Limits::default()
                },
                original,
            )?;
            let mut accept = std::pin::pin!(listener.accept());
            let mut peer = None;
            tokio::time::timeout(
                Duration::from_secs(3),
                poll_fn(|cx| -> Poll<Result<(), Failure>> {
                    if peer.is_none()
                        && let Poll::Ready(result) = accept.as_mut().poll(cx)
                    {
                        peer = Some(result?.0);
                    }
                    match owner.poll(cx) {
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                        Poll::Pending => {}
                    }
                    if owner.ready() && peer.is_some() {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }),
            )
            .await??;
            let mut peer = peer.ok_or("missing actual postIO peer")?;
            let mut initializer = [0; 8];
            peer.read_exact(&mut initializer).await?;
            check(matches!(
                gnunet_wire::official::set::ClientRequest::decode(&initializer)?,
                gnunet_wire::official::set::ClientRequest::Create { operation: 2 }
            ))?;
            // Only the real transport is exercised: this complete public CopyLazy
            // frame is never classified as a SET query result or a peer completion.
            let response = gnunet_wire::official::set::ClientResponse::CopyLazy {
                cookie: [1, 2, 3, 4],
            };
            let mut bytes = [0; 8];
            response.encode(&mut bytes, crate::Abi::native())?;
            peer.write_all(&bytes[..4]).await?;
            tokio::time::timeout(Duration::from_secs(3), poll_fn(|cx| owner.read(cx))).await??;
            let partial = owner.input.ok_or("real original partial target missing")?;
            check(
                owner
                    .channel
                    .framing()
                    .is_some_and(|framed| framed.frame().is_none()),
            )?;
            peer.write_all(&bytes[4..]).await?;
            // read() first performs actual native IO. It already has the original
            // partial, so its first Clock sample is the existing postIO check.
            clock
                .advance_on_sample
                .store(partial.expires, Ordering::Release);
            let error = tokio::time::timeout(Duration::from_secs(3), poll_fn(|cx| owner.read(cx)))
                .await?
                .err()
                .ok_or("last read crossing the original partial target passed")?;
            let context = error
                .deadline_context()
                .ok_or("postIO bound context missing")?;
            check(
                context.scope == DeadlineScope::PartialInput
                    && context.hard == partial.hard
                    && context.expires == Some(partial.expires)
                    && context.observed_canonical == Some(partial.expires)
                    && context.observed_native < partial.hard
                    && owner
                        .channel
                        .framing()
                        .is_some_and(|framed| framed.frame() == Some(bytes.as_slice()))
                    && owner.input.is_some_and(|bound| {
                        bound.hard == partial.hard && bound.expires == partial.expires
                    }),
            )?;
            let _actual = owner.retire(true);
            Ok(())
        })
}
