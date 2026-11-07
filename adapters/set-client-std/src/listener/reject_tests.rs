//! Real private Unix IPC faults/queue writes, not a SET peer/agreement receipt.
use super::*;
use crate::Factory;
use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Failure = Box<dyn std::error::Error>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("set-reject-{}-{stamp}", std::process::id()));
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
        Err("original rejection ownership changed".into())
    }
}
async fn initialized(
    factory: &Factory,
    socket: &UnixListener,
) -> Result<(Listener, UnixStream), Failure> {
    let bounds = Bounds::new(factory.clock().as_ref(), Duration::from_secs(30))?;
    let limits = Limits {
        io_slice_bytes: 1,
        queued_frames: 1,
        ..Limits::default()
    };
    let mut listener = factory.listen(OperationType::Union, [7; 64], limits, bounds)?;
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
            match listener.poll_progress(cx, &mut |_| Decision::Reject) {
                Poll::Ready(Ok(ListenProgress::Written {
                    rejected: None,
                    complete: true,
                    ..
                })) => whole = true,
                Poll::Ready(Ok(ListenProgress::Lost(_))) => {
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
    let mut peer = peer.ok_or("missing original Unix peer")?;
    let mut bytes = [0; 72];
    check(peer.read(&mut bytes)? == bytes.len())?;
    check(matches!(
        ClientRequest::decode(&bytes)?,
        ClientRequest::Listen { operation: 2, .. }
    ))?;
    Ok((listener, peer))
}
async fn accepted(
    listener: &mut Listener,
    peer: &mut UnixStream,
    id: u32,
) -> Result<Prepared, Failure> {
    let request = ClientResponse::Request {
        accept_id: id,
        peer: [3; 32],
        context: &[],
    };
    let mut bytes = [0; 40];
    request.encode(&mut bytes, listener.limits.abi)?;
    peer.write_all(&bytes)?;
    tokio::time::timeout(
        Duration::from_secs(3),
        poll_fn(|cx| {
            match listener.poll_progress(cx, &mut |_| Decision::Accept {
                mode: ResultMode::Symmetric,
                options: Options::default(),
            }) {
                Poll::Ready(Ok(ListenProgress::Accepted(prepared))) => Poll::Ready(Ok(prepared)),
                Poll::Ready(Ok(ListenProgress::Lost(_))) => {
                    Poll::Ready(Err("offer source lost".into()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::from(error))),
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await?
}

#[test]
fn original_prepared_reject_checks_domain_epoch_capacity_and_actual_whole_write()
-> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let directory = Directory::new()?;
            let path = directory.0.join("set.sock");
            let socket = UnixListener::bind(&path)?;
            socket.set_nonblocking(true)?;
            let factory = Factory::new(EndpointSource::unix(path.clone()))?;
            let foreign = Factory::new(EndpointSource::unix(path))?;
            let (mut original, mut peer) = initialized(&factory, &socket).await?;
            let (mut other_epoch, _other_peer) = initialized(&factory, &socket).await?;
            let (mut other_domain, _foreign_peer) = initialized(&foreign, &socket).await?;
            let a = accepted(&mut original, &mut peer, 11).await?;
            let b = accepted(&mut original, &mut peer, 12).await?;
            let c = accepted(&mut original, &mut peer, 13).await?;
            let d = accepted(&mut original, &mut peer, 14).await?;
            let e = accepted(&mut original, &mut peer, 15).await?;
            let failure = other_domain
                .reject_prepared(d)
                .err()
                .ok_or("foreign domain accepted")?;
            check(matches!(failure.error, Error::Protocol(Fault::Stale)))?;
            let failure = other_epoch
                .reject_prepared(failure.prepared)
                .err()
                .ok_or("foreign epoch accepted")?;
            check(matches!(failure.error, Error::Protocol(Fault::Stale)))?;
            let a = original
                .reject_prepared(a)
                .map_err(|failure| failure.error)?;
            let _b = original
                .reject_prepared(b)
                .map_err(|failure| failure.error)?;
            // Reserved control writes may use the one ordinary slot plus both
            // reserved slots. Queue three real requests before the fourth
            // original preparation must be returned by the capacity refusal.
            let _c = original
                .reject_prepared(c)
                .map_err(|failure| failure.error)?;
            let failure = original
                .reject_prepared(failure.prepared)
                .err()
                .ok_or("full reserved queue accepted")?;
            check(matches!(failure.error, Error::Protocol(Fault::Capacity)))?;
            let mut partial = false;
            tokio::time::timeout(
                Duration::from_secs(3),
                poll_fn(|cx| -> Poll<Result<(), Failure>> {
                    match original.poll_progress(cx, &mut |_| Decision::Reject) {
                        Poll::Ready(Ok(ListenProgress::Written {
                            epoch,
                            rejected: Some(id),
                            complete,
                            ..
                        })) => {
                            check(a.matches(&epoch, id))?;
                            if complete {
                                return Poll::Ready(check(partial));
                            }
                            partial = true;
                            cx.waker().wake_by_ref();
                        }
                        Poll::Ready(Ok(ListenProgress::Lost(_))) => {
                            return Poll::Ready(Err("reject lost".into()));
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                        Poll::Pending => {}
                    }
                    Poll::Pending
                }),
            )
            .await??;
            let mut reject = [0; 8];
            check(peer.read(&mut reject)? == reject.len())?;
            check(matches!(
                ClientRequest::decode(&reject)?,
                ClientRequest::Reject { accept_id: 11 }
            ))?;
            // The admission failure returned the same original preparation. Its
            // retry is now legal, but remains only queued, with no whole-write fact.
            let d = original
                .reject_prepared(failure.prepared)
                .map_err(|failure| failure.error)?;
            let epoch = original
                .session
                .epoch()
                .cloned()
                .ok_or("missing original epoch")?;
            check(d.matches(&epoch, 14))?;
            let loss = original.close();
            check(!epoch.live() && loss.transport.initializer_written)?;
            let failure = other_epoch
                .reject_prepared(e)
                .err()
                .ok_or("retired epoch was reused")?;
            check(matches!(failure.error, Error::Protocol(Fault::Stale)))?;
            let evaluate = Prepared::evaluate(
                [3; 32],
                [7; 64],
                &[],
                ResultMode::Symmetric,
                Options::default(),
            )?;
            let failure = other_epoch
                .reject_prepared(evaluate)
                .err()
                .ok_or("Evaluate rejected another source")?;
            check(matches!(
                failure.error,
                Error::Protocol(Fault::InvalidInput)
            ))
        })
}
