//! Actual private Unix SET owner retirement at zero/partial/whole operation
//! exposure. Local core receipts are explicit; no peer DONE/vote is supplied.
use super::*;
use gnunet_client_host::EndpointSource;
use std::{
    future::poll_fn,
    io::Read,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
type Failure = Box<dyn std::error::Error>;

// Advance only the canonical sample while retaining the real native owner and
// its original operation targets. No SET result or vote is supplied.
struct SourceClock(AtomicU64);
impl gnunet_service_runtime::clock::RuntimeClock for SourceClock {
    fn sample(&self) -> Result<gnunet_service_runtime::clock::ClockSample, Fault> {
        Ok(gnunet_service_runtime::clock::ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(self.0.load(Ordering::Relaxed)),
            revision: 0,
        })
    }
    fn subscribe(
        &self,
    ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, Fault> {
        gnunet_service_runtime::clock::SystemClock.subscribe()
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("consensus-loss-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err("original source retirement boundary changed".into())
    }
}
async fn initialized(owner: &mut set::Set, socket: &UnixListener) -> Result<UnixStream, Failure> {
    let mut peer = None;
    let mut whole = false;
    tokio::time::timeout(
        Duration::from_secs(3),
        poll_fn(|cx| -> Poll<Result<(), Failure>> {
            if peer.is_none() {
                match socket.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(true)?;
                        peer = Some(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Poll::Ready(Err(error.into())),
                }
            }
            match owner.poll_progress(cx) {
                Poll::Ready(Ok(set::SetProgress::InitializerWritten {
                    complete: true, ..
                })) => whole = true,
                Poll::Ready(Ok(set::SetProgress::Lost(_))) => {
                    return Poll::Ready(Err("initializer lost".into()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
            if whole && peer.is_some() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }),
    )
    .await??;
    let mut peer = peer.ok_or("missing original peer")?;
    let mut bytes = [0; 8];
    check(peer.read(&mut bytes)? == bytes.len())?;
    check(matches!(
        gnunet_wire::official::set::ClientRequest::decode(&bytes)?,
        gnunet_wire::official::set::ClientRequest::Create { operation: 2 }
    ))?;
    Ok(peer)
}
async fn source_loss(profile: usize) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let path = directory.0.join("set.sock");
    let socket = UnixListener::bind(&path)?;
    socket.set_nonblocking(true)?;
    let clock = Arc::new(SourceClock(AtomicU64::new(
        gnunet_service_runtime::clock::SystemClock
            .sample()?
            .now
            .as_micros(),
    )));
    let factory = Factory::new(EndpointSource::unix_with_clock(path, clock.clone()))?;
    let outer = Bounds::new(factory.clock().as_ref(), Duration::from_secs(30))?;
    let now = factory.clock().sample()?.now.as_micros();
    let domain = core::Instance::new();
    let mut session = core::Session::new(
        &domain,
        [1; 32],
        Join {
            session: [7; 64],
            start: now,
            deadline: outer.expires,
            peers: &[[1; 32], [2; 32]],
        },
        core::Limits::default(),
        set::Abi::native(),
        now,
    )?;
    let listen = session.effect().ok_or("missing listener effect")?.id;
    session.admit_effect(listen)?;
    let _local_listener = session.complete_effect(listen, Completion::Written)?;
    session.conclude(now)?;
    session.step(now, 64)?;
    let prepare = session.effect().ok_or("missing population effect")?;
    let Action::PrepareSet { set: source } = prepare.action else {
        return Err("wrong population effect".into());
    };
    let prepare_id = prepare.id;
    let targets = Bridge::clamp(
        factory.clock().as_ref(),
        outer,
        prepare.deadline().ok_or("missing original deadline")?,
    )?;
    let mut native = factory.set(
        set::OperationType::Union,
        set::Limits {
            io_slice_bytes: 1,
            ..set::Limits::default()
        },
        targets,
    )?;
    let peer = initialized(&mut native, &socket).await?;
    session.admit_effect(prepare_id)?;
    let _actual_create = session.complete_effect(prepare_id, Completion::Written)?;
    session.step(now, 64)?;
    let effect = session.effect().ok_or("missing original reconcile")?;
    let Action::Reconcile {
        task,
        context,
        peer: target,
        ..
    } = effect.action
    else {
        return Err("wrong reconcile effect".into());
    };
    let effect_id = effect.id;
    session.admit_effect(effect_id)?;
    let mut context_bytes = [0; 16];
    context.encode(&mut context_bytes)?;
    let prepared = set::Prepared::evaluate(
        target,
        session.global_id(),
        &context_bytes,
        set::ResultMode::Symmetric,
        set::Options::default(),
    )?;
    let mut operation_targets = targets;
    if profile == 3 {
        operation_targets.hard = operation_targets.hard.min(
            Instant::now()
                .checked_add(Duration::from_millis(80))
                .ok_or(Fault::Overflow)?,
        );
    }
    if profile == 0 {
        // Real preflight on this same initialized owner, before binding the
        // transcript's original operation. No bytes of this operation escape.
        let probe = set::Prepared::evaluate(
            target,
            session.global_id(),
            &context_bytes,
            set::ResultMode::Symmetric,
            set::Options::default(),
        )?;
        let probe_id = native
            .commit(probe, operation_targets)
            .map_err(|failure| failure.error)?;
        let set::CancelDisposition::Unsent(receipt) = native.cancel(&probe_id)? else {
            return Err("unwritten SDK cancellation lost its original receipt".into());
        };
        check(
            receipt.id == probe_id
                && receipt.written == 0
                && !receipt.request_written
                && receipt.cancellation == Some(set::CancellationCause::Requested)
                && receipt.original.expires == operation_targets.expires
                && receipt.original.hard == operation_targets.hard,
        )?;
        check(cancellation_cause(receipt.cancellation) == Fault::Cancelled)?;
        // Typed semantic consistency only: the SDK currently has no producer
        // for Deadline cancellation intent; no such native receipt is forged.
        check(cancellation_cause(Some(set::CancellationCause::Deadline)) == Fault::Deadline)?;
    }
    let operation = native
        .commit(prepared, operation_targets)
        .map_err(|failure| failure.error)?;
    if profile != 0 {
        tokio::time::timeout(
            Duration::from_secs(3),
            poll_fn(|cx| -> Poll<Result<(), Failure>> {
                match native.poll_progress(cx) {
                    Poll::Ready(Ok(set::SetProgress::OperationWritten {
                        operation: id,
                        bytes,
                        complete,
                    })) => {
                        check(id == operation && bytes != 0)?;
                        if profile == 1 || complete {
                            return Poll::Ready(Ok(()));
                        }
                        cx.waker().wake_by_ref();
                    }
                    Poll::Ready(Ok(set::SetProgress::Lost(_))) => {
                        return Poll::Ready(Err("operation lost before selected prefix".into()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                    Poll::Pending => {}
                }
                Poll::Pending
            }),
        )
        .await??;
    }
    let loss = if profile == 0 {
        native.close()
    } else if (2..=4).contains(&profile) {
        if profile != 3 {
            clock.0.store(operation_targets.expires, Ordering::Relaxed);
            check(Instant::now() < operation_targets.hard)?;
        } else {
            tokio::time::sleep_until(operation_targets.hard.into()).await;
            check(clock.sample()?.now.as_micros() < operation_targets.expires)?;
        }
        let loss = if profile == 4 {
            // The first observer may be synchronous population, rather than
            // progress(). It still retires the same real MQ and receipts.
            let error = native
                .add(set::Element {
                    element_type: 0,
                    data: &[7],
                })
                .err()
                .ok_or("expired original population accepted a mutation")?;
            check(matches!(error, set::Error::Deadline(_)))?;
            native.retire_after(error)
        } else {
            tokio::time::timeout(
                Duration::from_secs(3),
                poll_fn(|cx| match native.poll_progress(cx) {
                    Poll::Ready(Ok(set::SetProgress::Lost(loss))) => Poll::Ready(Ok(loss)),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::from(error))),
                    Poll::Ready(Ok(_)) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }),
            )
            .await??
        };
        check(matches!(loss.cause, set::Cause::Deadline))?;
        loss
    } else {
        drop(peer);
        tokio::time::timeout(
            Duration::from_secs(3),
            poll_fn(|cx| match native.poll_progress(cx) {
                Poll::Ready(Ok(set::SetProgress::Lost(loss))) => Poll::Ready(Ok(loss)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::from(error))),
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            }),
        )
        .await??
    };
    let receipt = loss
        .operations
        .iter()
        .find(|receipt| receipt.id == operation)
        .ok_or("lost original operation receipt")?;
    check(match profile {
        0 => receipt.written == 0 && !receipt.request_written,
        1 => receipt.written > 0 && !receipt.request_written,
        _ => receipt.request_written,
    })?;
    check(
        loss.transport.epoch.is_some()
            && native.epoch().is_none()
            && receipt.original.expires == operation_targets.expires
            && receipt.original.hard == operation_targets.hard,
    )?;
    let why = cause(&loss.cause);
    check(!global_loss(&loss.cause))?;
    let completion = operation_loss(Some(receipt), true, why);
    let terminal = session
        .source_retired(
            source,
            why,
            Some(core::RetiredEffect::Disposition {
                effect: effect_id,
                completion,
            }),
        )?
        .ok_or("missing original effect terminal")?;
    check(terminal.completion == completion && terminal.effect.id == effect_id)?;
    check(!session.task_live(task) && !session.set_live(source))?;
    check(session.outcome().failure.is_none() && !session.outcome().client_done_written)
}
#[test]
fn actual_zero_partial_whole_set_owner_losses_preserve_disposition_without_session_success()
-> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            source_loss(0).await?;
            source_loss(1).await?;
            source_loss(usize::MAX).await
        })
}

#[test]
fn canonical_and_native_deadline_losses_retire_only_the_original_population() -> Result<(), Failure>
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            source_loss(2).await?;
            source_loss(3).await?;
            source_loss(4).await
        })
}

#[test]
fn shared_port_origin_preserves_the_global_fence_for_the_same_error_word() -> Result<(), Failure> {
    for local in [
        set::Cause::Deadline,
        set::Cause::Failure(set::Error::Protocol(Fault::Deadline)),
        set::Cause::OriginalSourceRetired,
        set::Cause::Failure(set::Error::Io(std::io::Error::from_raw_os_error(54))),
    ] {
        check(!global_loss(&local))?;
    }
    for shared in [
        set::Cause::Failure(set::Error::Clock(
            gnunet_client_host::ConnectError::Protocol(Fault::Deadline),
        )),
        set::Cause::Failure(set::Error::Client(
            gnunet_client_host::ConnectError::Protocol(Fault::Deadline),
        )),
    ] {
        check(global_loss(&shared))?;
        let set::Cause::Failure(error) = shared else {
            return Err("expected original shared port error".into());
        };
        check(global_error(&Error::Set(error)))?;
    }
    check(!global_error(&Error::Set(set::Error::Protocol(
        Fault::Deadline,
    ))))?;
    Ok(())
}
