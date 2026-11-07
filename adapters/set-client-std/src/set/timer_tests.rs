//! Real private Unix SDK writes and native owner deadlines; no peer SET result
//! or official C interoperability success is fabricated by these fixtures.
use super::*;
use crate::{Factory, ResultMode};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock, SystemClock};
use gnunet_wire::official::set::ClientRequest;
use std::{
    error::Error as StdError,
    future::Future,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{sleep_until, timeout},
};

type Failure = Box<dyn StdError>;
const WAIT: Duration = Duration::from_secs(3);
const SHORT: Duration = Duration::from_millis(80);
const CLEANUP: Duration = Duration::from_millis(240);

/// Source time cannot expire any canonical target. The native owner waiters
/// must still wake, including after the earlier original deadline is replaced
/// by the already captured iteration/CANCEL cleanup policy.
struct FrozenClock;
impl RuntimeClock for FrozenClock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(1_000_000),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}
struct Socket(PathBuf);
impl Socket {
    fn bind() -> Result<(Self, UnixListener), Failure> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = PathBuf::from(format!(
            "/tmp/gnrs-set-timer-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err("original owner deadline/receipt changed".into())
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn frame(peer: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    timeout(WAIT, async {
        let mut header = [0; 4];
        peer.read_exact(&mut header).await?;
        let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
        if size < 4 {
            return Err(io::Error::other("short actual SET request").into());
        }
        let mut bytes = vec![0; size];
        bytes[..4].copy_from_slice(&header);
        peer.read_exact(&mut bytes[4..]).await?;
        Ok::<_, Failure>(bytes)
    })
    .await?
}
async fn initialized() -> Result<(Socket, Set, UnixStream), Failure> {
    initialized_with_clock(Arc::new(FrozenClock)).await
}
async fn initialized_with_clock(
    clock: Arc<dyn RuntimeClock>,
) -> Result<(Socket, Set, UnixStream), Failure> {
    initialized_with_limits(
        clock,
        Limits {
            write_timeout: CLEANUP,
            ..Limits::default()
        },
    )
    .await
}
async fn initialized_with_limits(
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
) -> Result<(Socket, Set, UnixStream), Failure> {
    let (socket, listener) = Socket::bind()?;
    let factory = Factory::new(EndpointSource::unix_with_clock(socket.0.clone(), clock))?;
    let original = Bounds::new(factory.clock().as_ref(), Duration::from_secs(5))?;
    let mut owner = factory.set(OperationType::Union, limits, original)?;
    let mut accept = std::pin::pin!(listener.accept());
    let mut peer = None;
    timeout(
        WAIT,
        poll_fn(|cx| -> Poll<Result<(), Failure>> {
            if peer.is_none()
                && let Poll::Ready(result) = accept.as_mut().poll(cx)
            {
                peer = Some(result?.0);
            }
            match owner.poll_progress(cx) {
                Poll::Ready(Ok(SetProgress::Lost(_))) => {
                    return Poll::Ready(Err("initializer source retired".into()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
            if owner.initialized() && peer.is_some() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }),
    )
    .await??;
    let mut peer = peer.ok_or("missing actual accepted source")?;
    check(matches!(
        ClientRequest::decode(&frame(&mut peer).await?)?,
        ClientRequest::Create { operation: 2 }
    ))?;
    Ok((socket, owner, peer))
}
async fn operation(
    owner: &mut Set,
    peer: &mut UnixStream,
    original: Bounds,
) -> Result<OperationId, Failure> {
    let prepared = Prepared::evaluate(
        [2; 32],
        [7; 64],
        &[],
        ResultMode::Symmetric,
        crate::Options::default(),
    )?;
    let id = owner
        .commit(prepared, original)
        .map_err(|failure| failure.error)?;
    timeout(
        WAIT,
        poll_fn(|cx| -> Poll<Result<(), Failure>> {
            match owner.poll_progress(cx) {
                Poll::Ready(Ok(SetProgress::OperationWritten {
                    operation,
                    complete: true,
                    ..
                })) => {
                    check(operation == id)?;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(SetProgress::Lost(_))) => {
                    Poll::Ready(Err("operation retired before its real whole write".into()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await??;
    check(matches!(
        ClientRequest::decode(&frame(peer).await?)?,
        ClientRequest::Evaluate { .. }
    ))?;
    Ok(id)
}
async fn loss(owner: &mut Set) -> Result<SetLoss, Failure> {
    // The peer stays open and sends nothing. This future can only progress
    // when a real owner alarm wakes its registered task.
    Ok(timeout(
        Duration::from_millis(500),
        poll_fn(|cx| match owner.poll_native_guard(cx) {
            Some(loss) => Poll::Ready(loss),
            None => Poll::Pending,
        }),
    )
    .await?)
}
async fn eof(peer: &mut UnixStream) -> Result<(), Failure> {
    let mut byte = [0; 1];
    check(timeout(WAIT, peer.read(&mut byte)).await?? == 0)
}

#[test]
fn retired_session_never_rearms_its_original_native_deadline() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let (socket, _listener) = Socket::bind()?;
        let factory = Factory::new(EndpointSource::unix(socket.0.clone()))?;
        let original = Bounds::new(factory.clock().as_ref(), SHORT)?;
        let mut owner = factory.set(OperationType::Union, Limits::default(), original)?;
        // Arm the actual transport owner before retiring an unattached intent.
        let expired = poll_fn(|cx| Poll::Ready(owner.session.native_expired(cx))).await;
        check(expired.is_none())?;
        let receipt = owner.session.retire(true);
        check(receipt.epoch.is_none() && receipt.pending_frames == 0)?;
        sleep_until((original.hard + Duration::from_millis(5)).into()).await;
        let expired = poll_fn(|cx| Poll::Ready(owner.session.native_expired(cx))).await;
        check(expired.is_none())
    })
}

#[test]
fn later_operation_with_earliest_hard_wakes_without_session_timer_clobber() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let (_socket, mut owner, mut peer) = initialized().await?;
        let clock = owner.session.clock();
        let long = Bounds::new(clock.as_ref(), Duration::from_secs(2))?;
        let first = operation(&mut owner, &mut peer, long).await?;
        let short = Bounds::new(clock.as_ref(), SHORT)?;
        let second = operation(&mut owner, &mut peer, short).await?;
        // Both actual frames are already whole-written; no transport write
        // bound can accidentally stand in for the operation owner's timer.
        check(
            owner
                .operations
                .iter()
                .all(|receipt| !owner.session.contains(Tag::Operation(receipt.request_id))),
        )?;
        let loss = loss(&mut owner).await?;
        check(matches!(loss.cause, Cause::Deadline))?;
        check(loss.transport.pending_frames == 0 && loss.operations.len() == 2)?;
        let context = loss.deadline.ok_or("operation deadline context missing")?;
        check(
            context.scope
                == DeadlineScope::Operation {
                    serial: second.serial,
                    request_id: u32::try_from(second.serial)?,
                }
                && context.hard == short.hard
                && context.expires == Some(short.expires)
                && context.observed_canonical.is_none()
                && context.observed_native >= short.hard,
        )?;
        for (id, original) in [(first, long), (second, short)] {
            let receipt = loss
                .operations
                .iter()
                .find(|r| r.id == id)
                .ok_or("lost operation")?;
            check(receipt.request_written && receipt.written != 0)?;
            check(
                receipt.original.expires == original.expires
                    && receipt.original.hard == original.hard,
            )?;
        }
        eof(&mut peer).await
    })
}

#[test]
fn cancelled_operation_drops_old_deadline_but_original_cancel_write_still_expires()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let (_socket, mut owner, mut peer) = initialized().await?;
        let original = Bounds::new(owner.session.clock().as_ref(), SHORT)?;
        let id = operation(&mut owner, &mut peer, original).await?;
        check(matches!(owner.cancel(&id)?, CancelDisposition::Queued))?;
        let rid = owner
            .operations
            .first()
            .ok_or("missing canceled operation")?
            .request_id;
        check(owner.session.contains(Tag::Cancel(rid)))?;
        // Both alarms had observed the earlier operation deadline. Resetting
        // the transport alarm later and removing the Set target must clear it.
        sleep_until((original.hard + Duration::from_millis(5)).into()).await;
        let observed = poll_fn(|cx| Poll::Ready(owner.poll_native_guard(cx))).await;
        check(observed.is_none())?;
        let loss = loss(&mut owner).await?;
        check(matches!(loss.cause, Cause::Deadline) && loss.transport.pending_frames == 1)?;
        let context = loss
            .deadline
            .ok_or("cancel-write deadline context missing")?;
        check(
            context.scope == DeadlineScope::Write(DeadlineWrite::Cancel { request_id: rid })
                && context.observed_canonical.is_none()
                && context.observed_native >= context.hard,
        )?;
        let receipt = loss.operations.first().ok_or("lost canceled original")?;
        check(receipt.id == id && receipt.cancellation == Some(CancellationCause::Requested))?;
        check(receipt.request_written && !receipt.cancellation_written)?;
        check(
            receipt.original.expires == original.expires && receipt.original.hard == original.hard,
        )?;
        eof(&mut peer).await
    })
}

#[test]
fn iteration_cleanup_replaces_original_hard_and_wakes_without_a_transport_frame()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let (_socket, mut owner, mut peer) = initialized().await?;
        let original = Bounds::new(owner.session.clock().as_ref(), SHORT)?;
        let id = owner.iterate(original)?;
        timeout(
            WAIT,
            poll_fn(|cx| -> Poll<Result<(), Failure>> {
                match owner.poll_progress(cx) {
                    Poll::Ready(Ok(SetProgress::Lost(_))) => {
                        return Poll::Ready(Err("iteration lost before whole write".into()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                    Poll::Pending => {}
                }
                if owner.iteration.as_ref().is_some_and(|r| r.request_written) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await??;
        check(matches!(
            ClientRequest::decode(&frame(&mut peer).await?)?,
            ClientRequest::Iterate
        ))?;
        check(matches!(
            owner.cancel_iteration(&id)?,
            IterCancelDisposition::Pending
        ))?;
        let cleanup = owner
            .iteration
            .as_ref()
            .and_then(|r| r.cleanup)
            .ok_or("missing original cleanup")?;
        check(cleanup.hard > original.hard && !owner.session.contains(Tag::Iterate(id.serial)))?;
        sleep_until((original.hard + Duration::from_millis(5)).into()).await;
        let observed = poll_fn(|cx| Poll::Ready(owner.poll_native_guard(cx))).await;
        check(observed.is_none())?;
        let loss = loss(&mut owner).await?;
        check(matches!(loss.cause, Cause::Deadline) && loss.transport.pending_frames == 0)?;
        let context = loss.deadline.ok_or("iteration-cleanup context missing")?;
        check(
            context.scope
                == DeadlineScope::Iteration {
                    serial: id.serial,
                    generation: 0,
                    cleanup: true,
                }
                && context.hard == cleanup.hard
                && context.expires == Some(cleanup.expires)
                && context.observed_canonical.is_none()
                && context.observed_native >= cleanup.hard,
        )?;
        let receipt = loss.iteration.ok_or("lost iteration cleanup receipt")?;
        check(receipt.id == id && receipt.cancellation == Some(CancellationCause::Requested))?;
        check(
            receipt.original.expires == original.expires && receipt.original.hard == original.hard,
        )?;
        check(
            receipt
                .cleanup
                .is_some_and(|r| r.hard == cleanup.hard && r.expires == cleanup.expires),
        )?;
        eof(&mut peer).await
    })
}

struct AdvancingClock(AtomicU64);
impl RuntimeClock for AdvancingClock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(self.0.load(Ordering::Acquire)),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}

#[test]
fn synchronous_bound_failure_retires_same_owner_with_original_receipts() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let clock = Arc::new(AdvancingClock(AtomicU64::new(1_000_000)));
        let (_socket, mut owner, mut peer) = initialized_with_clock(clock.clone()).await?;
        let original = Bounds::new(clock.as_ref(), Duration::from_secs(2))?;
        let id = operation(&mut owner, &mut peer, original).await?;
        // Preserve a second actually admitted, still-unwritten mutation. The
        // failing Add below must not become another accepted continuation.
        let mutation = owner.add(gnunet_wire::official::set::Element {
            element_type: 0,
            data: b"original pending mutation",
        })?;
        let epoch = owner
            .epoch()
            .cloned()
            .ok_or("missing original physical source")?;
        clock
            .0
            .store(owner.session.original().expires, Ordering::Release);
        let error = match owner.add(gnunet_wire::official::set::Element {
            element_type: 0,
            data: b"expired mutation must not be admitted",
        }) {
            Ok(_) => return Err(Failure::from("expired synchronous Add was admitted")),
            Err(error) => error,
        };
        check(matches!(error, Error::Deadline(_)) && error.origin() == crate::LossOrigin::Bounds)?;
        let context = error
            .deadline_context()
            .ok_or("synchronous context missing")?;
        let original_record = match &error {
            Error::Deadline(context) => std::ptr::from_ref(context.as_ref()),
            _ => return Err(Failure::from("synchronous deadline lost its record")),
        };
        let source = owner.session.original();
        check(
            context.scope == DeadlineScope::Overall
                && context.expires == Some(source.expires)
                && context.hard == source.hard
                && context.observed_canonical == Some(source.expires),
        )?;
        let loss = owner.retire_after(error);
        let retained = loss
            .deadline
            .ok_or("synchronous context not moved to loss")?;
        check(std::ptr::from_ref(retained.as_ref()) == original_record)?;
        check(
            retained.scope == context.scope
                && retained.expires == context.expires
                && retained.hard == context.hard
                && retained.observed_native == context.observed_native
                && retained.observed_canonical == context.observed_canonical,
        )?;
        check(matches!(loss.cause, Cause::Deadline))?;
        check(loss.cause.origin() == crate::LossOrigin::Bounds)?;
        check(owner.epoch().is_none() && !epoch.live() && loss.transport.epoch == Some(epoch))?;
        check(loss.cleanup.is_none() && loss.operations.len() == 1 && loss.mutations.len() == 1)?;
        let receipt = &loss.operations[0];
        check(receipt.id == id && receipt.request_written && receipt.written != 0)?;
        check(
            receipt.original.expires == original.expires && receipt.original.hard == original.hard,
        )?;
        let receipt = &loss.mutations[0];
        check(receipt.id == mutation && receipt.written == 0 && !receipt.whole)?;
        check(loss.transport.pending_frames == 1)
    })
}

// Observe the actual retained native frame without consuming it. This does not
// inject a result or mark any write/operation complete.
async fn input_state(owner: &mut Set, complete: bool) -> Result<Option<Bounds>, Failure> {
    timeout(
        WAIT,
        poll_fn(|cx| -> Poll<Result<Option<Bounds>, Failure>> {
            match owner.poll_progress(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(SetProgress::Lost(_))) => {
                    return Poll::Ready(Err(
                        "response source lost before selected native extent".into()
                    ));
                }
                Poll::Ready(Ok(SetProgress::Activity)) => {}
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err(
                        "response consumed before selected native extent".into()
                    ));
                }
                Poll::Pending => return Poll::Pending,
            }
            let (partial, held) = owner.session.input_state();
            if held == complete && (complete || partial.is_some()) {
                Poll::Ready(Ok(partial))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await?
}

#[test]
fn completed_response_ends_partial_phase_but_not_original_operation() -> Result<(), Failure> {
    runtime()?.block_on(async {
        // Complete in-bound + later delivery; complete in-bound + original
        // operation expiry; and an actually incomplete original response.
        for profile in 0..3 {
            let clock = Arc::new(AdvancingClock(AtomicU64::new(1_000_000)));
            let (_socket, mut owner, mut peer) = initialized_with_limits(
                clock.clone(),
                Limits {
                    input_timeout: SHORT,
                    write_timeout: CLEANUP,
                    ..Limits::default()
                },
            )
            .await?;
            let original = Bounds::new(clock.as_ref(), Duration::from_secs(2))?;
            let id = operation(&mut owner, &mut peer, original).await?;
            let epoch = owner.epoch().cloned().ok_or("missing original epoch")?;
            let request_id = owner
                .operations
                .iter()
                .find(|receipt| receipt.id == id)
                .ok_or("missing original request")?
                .request_id;
            // This actual private native response is nonterminal. It witnesses
            // SDK framing/lifetime, not a peer DONE or C interoperability.
            let response = gnunet_wire::official::set::ClientResponse::Result {
                current_size: 1,
                request_id,
                status: crate::Status::AddLocal as u16,
                element: crate::Element {
                    element_type: 25,
                    data: b"original",
                },
            };
            let mut bytes = vec![0; response.encoded_len(owner.limits.abi)?];
            response.encode(&mut bytes, owner.limits.abi)?;
            peer.write_all(&bytes[..4]).await?;
            let partial = input_state(&mut owner, false)
                .await?
                .ok_or("real partial target missing")?;
            if profile != 2 {
                peer.write_all(&bytes[4..]).await?;
                check(input_state(&mut owner, true).await?.is_none())?;
            }
            let at = if profile == 1 {
                original.expires
            } else {
                partial.expires
            };
            clock.0.store(at, Ordering::Release);
            let event = timeout(WAIT, owner.progress()).await??;
            if profile == 0 {
                let SetProgress::Result {
                    operation,
                    epoch: actual,
                    status,
                    element,
                    terminal,
                    ..
                } = event
                else {
                    return Err(Failure::from("completed in-bound frame was not delivered"));
                };
                check(
                    operation == id
                        && actual == epoch
                        && actual.live()
                        && status == crate::Status::AddLocal
                        && element.data == b"original"
                        && terminal.is_none()
                        && owner.operations.len() == 1,
                )?;
                let receipt = &owner.operations[0];
                check(
                    receipt.original.hard == original.hard
                        && receipt.original.expires == original.expires,
                )?;
                let _actual = owner.close();
            } else {
                let SetProgress::Lost(loss) = event else {
                    return Err(Failure::from("original live bound was bypassed"));
                };
                let context = loss
                    .deadline
                    .ok_or("actual response/operation context missing")?;
                let (scope, target) = if profile == 1 {
                    (
                        DeadlineScope::Operation {
                            serial: id.serial,
                            request_id,
                        },
                        original,
                    )
                } else {
                    (DeadlineScope::PartialInput, partial)
                };
                check(
                    matches!(loss.cause, Cause::Deadline)
                        && context.scope == scope
                        && context.expires == Some(target.expires)
                        && context.hard == target.hard
                        && context.observed_canonical == Some(at)
                        && context.observed_native < target.hard
                        && loss.operations.len() == 1
                        && loss.operations[0].id == id
                        && loss.operations[0].original.hard == original.hard,
                )?;
            }
            eof(&mut peer).await?;
        }
        Ok(())
    })
}

#[test]
fn initial_and_copy_alarms_name_the_original_owner_without_clock_sample() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let (socket, _listener) = Socket::bind()?;
        let factory = Factory::new(EndpointSource::unix_with_clock(
            socket.0.clone(),
            Arc::new(FrozenClock),
        ))?;
        let original = Bounds::new(factory.clock().as_ref(), Duration::from_secs(5))?;
        let mut owner = factory.set(
            OperationType::Union,
            Limits {
                initial_timeout: SHORT,
                ..Limits::default()
            },
            original,
        )?;
        let initial_loss = loss(&mut owner).await?;
        let context = initial_loss
            .deadline
            .ok_or("original initial target missing")?;
        check(
            context.scope == DeadlineScope::Initial
                && context.expires == Some(1_080_000)
                && context.hard < original.hard
                && context.observed_native >= context.hard
                && context.observed_canonical.is_none()
                && initial_loss.transport.epoch.is_none(),
        )?;
        let (_socket, mut owner, mut peer) = initialized().await?;
        let original = Bounds::new(owner.session.clock().as_ref(), SHORT)?;
        let id = owner.copy_lazy(original)?;
        timeout(
            WAIT,
            poll_fn(|cx| -> Poll<Result<(), Failure>> {
                match owner.poll_progress(cx) {
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(SetProgress::Lost(_))) => {
                        return Poll::Ready(Err("copy source lost before whole request".into()));
                    }
                    Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                    Poll::Pending => {}
                }
                if owner
                    .copy
                    .as_ref()
                    .is_some_and(|receipt| receipt.request_written)
                {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await??;
        check(matches!(
            ClientRequest::decode(&frame(&mut peer).await?)?,
            ClientRequest::CopyLazyPrepare
        ))?;
        let loss = loss(&mut owner).await?;
        let context = loss.deadline.ok_or("original copy target missing")?;
        check(
            context.scope == DeadlineScope::Copy { serial: id.serial }
                && context.hard == original.hard
                && context.expires == Some(original.expires)
                && context.observed_canonical.is_none()
                && context.observed_native >= original.hard
                && loss
                    .copy
                    .as_ref()
                    .is_some_and(|receipt| receipt.id == id && receipt.request_written),
        )?;
        eof(&mut peer).await
    })
}
