//! Real local SET rejection writes and core retirement; no peer agreement claim.
use super::*;
use crate::{Bounds, Factory};
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::{
    clock::{ClockSample, ClockSubscription, RuntimeClock, SystemClock},
    local::{Listener, Stream},
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::{
    consensus::Join,
    set::{ClientRequest, ClientResponse},
};
use std::{
    future::{Future, poll_fn},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Failure = Box<dyn std::error::Error>;

struct Clock(AtomicU64);
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        Ok(ClockSample {
            now: AbsoluteTime::from_micros(self.0.load(Ordering::Relaxed)),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let path = std::env::temp_dir().join(format!(
            "gc-r-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        gnunet_native::filesystem::Directory::open(&std::env::temp_dir())?
            .create_private_directory(path.file_name().ok_or("missing private directory name")?)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
#[track_caller]
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "original rejection lifecycle changed at {}",
            std::panic::Location::caller()
        ))
        .into())
    }
}
async fn frame(peer: &mut Stream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    peer.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < header.len() {
        return Err("invalid frame size".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    peer.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn incoming(
    native: &mut set::Listener,
    peer: &mut Stream,
    context: RoundContext,
    accept_id: u32,
    abi: set::Abi,
) -> Result<set::Prepared, Failure> {
    let mut context_bytes = [0; 16];
    context.encode(&mut context_bytes)?;
    let request = ClientResponse::Request {
        accept_id,
        peer: [4; 32],
        context: &context_bytes,
    };
    let mut bytes = vec![0; request.encoded_len(abi)?];
    request.encode(&mut bytes, abi)?;
    peer.write_all(&bytes).await?;
    poll_fn(|cx| {
        match native.poll_progress(cx, &mut |_| set::Decision::Accept {
            mode: set::ResultMode::Symmetric,
            options: set::Options::default(),
        }) {
            Poll::Ready(Ok(set::ListenProgress::Accepted(prepared))) => Poll::Ready(Ok(prepared)),
            Poll::Ready(Ok(set::ListenProgress::Activity)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err("unexpected listener event during offer".into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::from(error))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn rejection_lifecycle() -> Result<(), Failure> {
    let directory = Directory::new()?;
    let path = directory.0.join("s");
    let socket = Listener::bind(&path)?;
    let now = SystemClock.sample()?.now.as_micros();
    let clock = Arc::new(Clock(AtomicU64::new(now)));
    let factory = Factory::new(EndpointSource::unix_with_clock(path, clock.clone()))?;
    let original = Bounds::new(factory.clock().as_ref(), Duration::from_secs(60))?;
    let domain = core::Instance::new();
    let mut session = core::Session::new(
        &domain,
        [1; 32],
        Join {
            session: [7; 64],
            start: now,
            deadline: original.expires,
            peers: &[[1; 32], [2; 32], [3; 32], [4; 32]],
        },
        core::Limits::default(),
        set::Abi::native(),
        now,
    )?;
    let listen = session.effect().ok_or("missing listener effect")?.id;
    session.admit_effect(listen)?;
    let abi = set::Abi::native();
    let mut native = factory.listen(
        set::OperationType::Union,
        session.global_id(),
        set::Limits {
            io_slice_bytes: 1,
            ..set::Limits::default()
        },
        original,
    )?;
    let mut accepting = Box::pin(socket.accept());
    let (mut peer, mut written) = (None, false);
    poll_fn(|cx| -> Poll<Result<(), Failure>> {
        if peer.is_none()
            && let Poll::Ready(result) = accepting.as_mut().poll(cx)
        {
            peer = Some(result?.0);
        }
        match native.poll_progress(cx, &mut |_| set::Decision::Reject) {
            Poll::Ready(Ok(set::ListenProgress::Written {
                rejected: None,
                complete: true,
                ..
            })) => written = true,
            Poll::Ready(Ok(
                set::ListenProgress::Attached(_)
                | set::ListenProgress::Activity
                | set::ListenProgress::Written {
                    complete: false, ..
                },
            )) => cx.waker().wake_by_ref(),
            Poll::Ready(Ok(_)) => return Poll::Ready(Err("listener did not initialize".into())),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Pending => {}
        }
        if written && peer.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    let _listened = session.complete_effect(listen, Completion::Written)?;
    let mut peer = peer.ok_or("missing original listener socket")?;
    check(matches!(
        ClientRequest::decode(&frame(&mut peer).await?)?,
        ClientRequest::Listen { .. }
    ))?;
    let context = RoundContext {
        kind: 0,
        peer1: 3,
        peer2: 0,
        repetition: -1,
        leader: -1,
        contested: 0,
    };
    let prepared = incoming(&mut native, &mut peer, context, 17, abi).await?;
    let offer = session.offer([4; 32], context, now)?;
    session.conclude(now)?;
    session.step(now, 1)?;
    let end = session
        .next_deadline()
        .ok_or("missing original phase deadline")?;
    clock.0.store(end, Ordering::Relaxed);
    session.step(end, 64)?;
    let pending = session
        .effect()
        .ok_or("expired phase did not retire its offer")?;
    check(matches!(pending.action, Action::RejectOffer { offer: original } if original == offer))?;
    let effect = pending.id;
    session.admit_effect(effect)?;
    let rejection = native
        .reject_prepared(prepared)
        .map_err(|failure| failure.error)?;
    let mut offers = vec![Offer {
        id: offer,
        state: OfferState::Rejecting(rejection),
    }];
    let mut terminal = None;
    let mut partials = 0;
    poll_fn(|cx| -> Poll<Result<(), Failure>> {
        match native.poll_progress(cx, &mut |_| set::Decision::Reject) {
            Poll::Ready(Ok(
                event @ set::ListenProgress::Written {
                    rejected: Some(_),
                    complete,
                    ..
                },
            )) => {
                settle_rejection(&mut session, &mut offers, &mut terminal, &event)?;
                if complete {
                    return Poll::Ready(Ok(()));
                }
                partials += 1;
                check(
                    session.effect().is_some_and(|pending| pending.id == effect)
                        && offers.len() == 1
                        && terminal.is_none(),
                )?;
                cx.waker().wake_by_ref();
            }
            Poll::Ready(Ok(set::ListenProgress::Activity)) => cx.waker().wake_by_ref(),
            Poll::Ready(Ok(_)) => return Poll::Ready(Err("rejection source changed".into())),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Pending => {}
        }
        Poll::Pending
    })
    .await?;
    check(partials > 0 && offers.is_empty())?;
    let terminal = terminal.ok_or("missing cleanup terminal")?;
    check(terminal.effect.id == effect && terminal.completion == Completion::Retired)?;
    check(matches!(
        ClientRequest::decode(&frame(&mut peer).await?)?,
        ClientRequest::Reject { accept_id: 17 }
    ))?;
    check(
        session.outcome().failure.is_none()
            && !session.outcome().client_done_written
            && session.listener_live(),
    )?;
    // The same physical listener accepts the next phase's actual request.
    let next = RoundContext { kind: 1, ..context };
    let _next_prepared = incoming(&mut native, &mut peer, next, 18, abi).await?;
    let next_offer = session.offer([4; 32], next, end)?;
    check(next_offer != offer && session.offer_live(next_offer))?;
    let _loss = native.close();
    Ok(())
}

#[test]
fn whole_rejection_retires_only_its_offer_and_keeps_the_listener_usable() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), rejection_lifecycle()).await?
        })
}
