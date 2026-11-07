//! Native local MQ witnesses only; no QUIC/TLS/peer or processing ACK is simulated.
use super::*;
use std::{
    error::Error,
    future::{Future, poll_fn},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type TestError = Box<dyn Error>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, TestError> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path =
            PathBuf::from("/tmp").join(format!("gqr-{}-{stamp:x}-{serial:x}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, TestError> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
fn ipc_error(error: Failure) -> TestError {
    format!("actual local MQ failure: {error:?}").into()
}
async fn attach(ipc: &mut Ipc, listener: &UnixListener) -> Result<UnixStream, TestError> {
    let mut accept = std::pin::pin!(listener.accept());
    let mut peer = None;
    let mut attached = false;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            if peer.is_none()
                && let Poll::Ready(result) = accept.as_mut().poll(cx)
            {
                match result {
                    Ok((stream, _)) => peer = Some(stream),
                    Err(error) => return Poll::Ready(Err(error.into())),
                }
            }
            if !attached {
                match ipc.poll_recovering(cx, |_, _, _| {}) {
                    Ok(Step::Attached) => attached = true,
                    Ok(Step::Pending | Step::Activity) => {}
                    Ok(_) => return Poll::Ready(Err("unexpected pre-attachment action".into())),
                    Err(error) => return Poll::Ready(Err(ipc_error(error))),
                }
            }
            if attached && let Some(peer) = peer.take() {
                return Poll::Ready(Ok(peer));
            }
            if attached {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }),
    )
    .await?
}
fn new_ipc(directory: &Directory) -> Result<(Ipc, UnixListener, Instant), TestError> {
    let path = directory.0.join("s");
    let listener = UnixListener::bind(&path)?;
    let hard = Instant::now() + Duration::from_secs(30);
    let ipc = Ipc::new(
        EndpointSource::unix(path),
        4,
        131070,
        1,
        hard,
        Duration::from_secs(5),
    )
    .map_err(ipc_error)?;
    Ok((ipc, listener, hard))
}
#[test]
fn native_eof_retires_exact_partial_mq_and_reconnects_without_fifo_replay() -> Result<(), TestError>
{
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut ipc, listener, hard) = new_ipc(&directory)?;
        let mut peer = attach(&mut ipc, &listener).await?;
        ipc.enqueue(Request::Register { characteristics: gnunet_wire::official::communicator::Characteristics::Reliable,
            can_burst: false, prefix: b"quic" }, Role::Register, hard).map_err(ipc_error)?;
        // The original peer leaves a real two-byte incomplete header and closes
        // only its write half; remaining positive writes stay valid observations.
        peer.write_all(&[0, 8]).await?;
        peer.shutdown().await?;
        let mut written = 0;
        let mut retired = Vec::new();
        let facts = tokio::time::timeout(Duration::from_secs(2), poll_fn(|cx| {
            match ipc.poll_recovering(cx, |generation, role, bytes| retired.push((generation, role.kind(), bytes))) {
                Ok(Step::Written { bytes, complete: false, .. }) => { written += bytes; cx.waker().wake_by_ref(); Poll::Pending }
                Ok(Step::Activity) => { cx.waker().wake_by_ref(); Poll::Pending }
                Ok(Step::Lost { facts, cause: Failure::Io(error) })
                    if error.kind() == std::io::ErrorKind::UnexpectedEof => Poll::Ready(Ok(facts)),
                Ok(Step::Pending) => Poll::Pending,
                Ok(_) => Poll::Ready(Err("original source did not retire the pending prefix".into())),
                Err(error) => Poll::Ready(Err(ipc_error(error))),
            }
        })).await??;
        if facts.generation != 1 || facts.next_generation != 2 || facts.input_bytes != 2 || facts.held_input
            || facts.outputs != 1 || facts.exposed_outputs != 1 || facts.output_bytes != written
            || written == 0 || retired != [(1, "register", written)] || ipc.hard != hard {
            return Err("loss changed original generation/prefix/absolute bound".into());
        }
        let mut replacement = attach(&mut ipc, &listener).await?;
        let mut probe = [0; 1];
        if !matches!(replacement.try_read(&mut probe), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock) {
            return Err("an original output prefix was replayed into the new MQ".into());
        }
        ipc.enqueue(Request::Register { characteristics: gnunet_wire::official::communicator::Characteristics::Reliable,
            can_burst: false, prefix: b"quic" }, Role::Register, hard).map_err(ipc_error)?;
        tokio::time::timeout(Duration::from_secs(2), poll_fn(|cx| {
            match ipc.poll_recovering(cx, |_, _, _| {}) {
                Ok(Step::Written { complete: true, .. }) => Poll::Ready(Ok(())),
                Ok(Step::Written { .. } | Step::Activity) => { cx.waker().wake_by_ref(); Poll::Pending },
                Ok(Step::Pending) => Poll::Pending,
                Ok(_) => Poll::Ready(Err("fresh registration did not wholly write".into())),
                Err(error) => Poll::Ready(Err(ipc_error(error))),
            }
        })).await??;
        let expected = Request::Register { characteristics: gnunet_wire::official::communicator::Characteristics::Reliable,
            can_burst: false, prefix: b"quic" };
        let mut bytes = vec![0; expected.encoded_len().map_err(|e| format!("{e:?}"))?];
        tokio::time::timeout(Duration::from_secs(2), replacement.read_exact(&mut bytes)).await??;
        if !matches!(Request::decode(&bytes).map_err(|e| format!("{e:?}"))?, Request::Register { prefix: b"quic", .. })
            || ipc.generation() != 2 || ipc.hard != hard {
            return Err("fresh current registration or original owner bound changed".into());
        }
        ipc.close();
        Ok(())
    })
}
#[test]
fn native_malformed_complete_header_is_fatal_not_a_reconnect() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut ipc, listener, hard) = new_ipc(&directory)?;
        let mut peer = attach(&mut ipc, &listener).await?;
        peer.write_all(&[0, 3, 0, 0]).await?;
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| match ipc.poll_recovering(cx, |_, _, _| {}) {
                Err(Failure::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                    Poll::Ready(Ok(()))
                }
                Err(error) => Poll::Ready(Err(ipc_error(error))),
                Ok(Step::Activity) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Ok(Step::Pending) => Poll::Pending,
                Ok(_) => Poll::Ready(Err("malformed input was accepted or reconnected".into())),
            }),
        )
        .await??;
        if ipc.generation() != 1
            || ipc.hard != hard
            || ipc.channel.framing().map(|f| f.read_progress_bytes()) != Some(4)
        {
            return Err("malformed first-header source/prefix changed".into());
        }
        ipc.close();
        Ok(())
    })
}

#[test]
fn native_announcement_prefix_waits_for_removals_without_waiting_for_later_data()
-> Result<(), TestError> {
    runtime()?.block_on(async {
        async fn announce(ipc: &mut Ipc) -> Result<(), TestError> {
            tokio::time::timeout(
                Duration::from_secs(2),
                poll_fn(|cx| match ipc.poll_recovering(cx, |_, _, _| {}) {
                    Ok(Step::Written { .. } | Step::Activity) => {
                        if ipc.announcements_written() {
                            Poll::Ready(Ok(()))
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                    Ok(Step::Pending) => Poll::Pending,
                    Ok(_) => Poll::Ready(Err("unexpected announcement source transition".into())),
                    Err(error) => Poll::Ready(Err(ipc_error(error))),
                }),
            )
            .await?
        }
        let directory = Directory::new()?;
        let (mut ipc, listener, hard) = new_ipc(&directory)?;
        let mut peer = attach(&mut ipc, &listener).await?;
        ipc.enqueue(Request::DeleteAddress(7), Role::Address, hard)
            .map_err(ipc_error)?;
        let result = Request::Sent {
            message_id: [1; 8],
            queue: 3,
            peer: [2; 32],
            status: 0,
        };
        ipc.enqueue(result, Role::Sent(3, [1; 8]), hard)
            .map_err(ipc_error)?;
        if ipc.announcements_written() {
            return Err("queued deletion became a whole write".into());
        }
        announce(&mut ipc).await?;
        if ipc.outputs.len() != 1 {
            return Err("announcement waited for unrelated later data".into());
        }
        // A new removal admitted during restoration establishes a new original
        // prefix, even though the old control prefix had already completed.
        ipc.enqueue(Request::DeleteAddress(8), Role::Address, hard)
            .map_err(ipc_error)?;
        ipc.enqueue(result, Role::Sent(3, [1; 8]), hard)
            .map_err(ipc_error)?;
        if ipc.announcements_written() {
            return Err("pending removal was omitted from restoration".into());
        }
        announce(&mut ipc).await?;
        if ipc.outputs.len() != 1 {
            return Err("later data incorrectly gates recovery".into());
        }
        let mut prefix = vec![0; 16 + result.encoded_len().map_err(|e| format!("{e:?}"))?];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut prefix)).await??;
        if !matches!(
            Request::decode(&prefix[..8]).map_err(|e| format!("{e:?}"))?,
            Request::DeleteAddress(7)
        ) || !matches!(
            Request::decode(&prefix[prefix.len() - 8..]).map_err(|e| format!("{e:?}"))?,
            Request::DeleteAddress(8)
        ) {
            return Err("original control prefix did not physically reach the peer".into());
        }
        ipc.close();
        Ok(())
    })
}

#[test]
fn native_result_capacity_uses_exact_wire_extent_and_preserves_held_command()
-> Result<(), TestError> {
    runtime()?.block_on(async {
        async fn drain(
            ipc: &mut Ipc,
            peer: &mut UnixStream,
            frames: usize,
            count: usize,
        ) -> Result<Vec<u8>, TestError> {
            let mut bytes = vec![0; count];
            {
                let mut read = std::pin::pin!(peer.read_exact(&mut bytes));
                let mut read_done = false;
                let mut written = 0;
                tokio::time::timeout(
                    Duration::from_secs(2),
                    poll_fn(|cx| {
                        let mut progress = false;
                        if written < frames {
                            match ipc.poll_write(cx) {
                                Ok(Step::Written { complete, .. }) => {
                                    written += usize::from(complete);
                                    progress = true;
                                }
                                Ok(Step::Pending) => {}
                                Ok(_) => {
                                    return Poll::Ready(Err(
                                        "unexpected native output state".into(),
                                    ));
                                }
                                Err(error) => return Poll::Ready(Err(ipc_error(error))),
                            }
                        }
                        if !read_done && let Poll::Ready(result) = read.as_mut().poll(cx) {
                            match result {
                                Ok(_) => read_done = true,
                                Err(error) => return Poll::Ready(Err(error.into())),
                            }
                        }
                        if written == frames && read_done {
                            return Poll::Ready(Ok(()));
                        }
                        if progress {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }),
                )
                .await??;
            }
            Ok(bytes)
        }
        fn incoming_frame(size: usize) -> Result<Vec<u8>, TestError> {
            let mut bytes = vec![0; size - 88];
            let extent = u16::try_from(bytes.len())?;
            bytes[..2].copy_from_slice(&extent.to_be_bytes());
            Ok(bytes)
        }
        fn incoming(bytes: &[u8]) -> Request<'_> {
            Request::Incoming {
                flow_control: false,
                flow_id: [0; 8],
                validity: 1,
                peer: [3; 32],
                neighbour: [0; 32],
                message: bytes,
            }
        }
        let directory = Directory::new()?;
        let path = directory.0.join("capacity");
        let listener = UnixListener::bind(&path)?;
        let hard = Instant::now() + Duration::from_secs(10);
        let mut ipc = Ipc::new(
            EndpointSource::unix(path),
            4,
            131070,
            65535,
            hard,
            Duration::from_secs(5),
        )
        .map_err(ipc_error)?;
        let mut peer = attach(&mut ipc, &listener).await?;
        let mut command = [0; 52];
        command[..4].copy_from_slice(&[0, 52, 4, 185]); // SEND1209
        command[4..8].copy_from_slice(&7u32.to_be_bytes());
        command[8..16].copy_from_slice(&[1; 8]);
        command[16..48].copy_from_slice(&[2; 32]);
        command[48..].copy_from_slice(&[0, 4, 0, 0]);
        peer.write_all(&command).await?;
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| match ipc.poll_recovering(cx, |_, _, _| {}) {
                Ok(Step::Frame) => Poll::Ready(Ok(())),
                Ok(Step::Pending) => Poll::Pending,
                Ok(Step::Activity) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Ok(_) => Poll::Ready(Err("unexpected command source state".into())),
                Err(error) => Poll::Ready(Err(ipc_error(error))),
            }),
        )
        .await??;
        let input_hard = ipc.input_hard().ok_or("missing original input deadline")?;
        let first = incoming_frame(65535)?;
        let second = incoming_frame(65484)?;
        ipc.enqueue(incoming(&first), Role::Control, hard)
            .map_err(ipc_error)?;
        ipc.enqueue(incoming(&second), Role::Control, hard)
            .map_err(ipc_error)?;
        let result = Request::Sent {
            message_id: [1; 8],
            queue: 7,
            peer: [2; 32],
            status: 0,
        };
        let sequence = ipc.next;
        // There are spare frame slots and precisely51 bytes, but SENT needs52.
        // The former48-byte preflight incorrectly admitted this boundary.
        if !ipc.room(1, 48)
            || ipc.room_request(result).map_err(ipc_error)?
            || ipc.next != sequence
            || ipc.outputs.len() != 2
            || ipc.input_hard() != Some(input_hard)
            || !matches!(ipc.frame().map_err(ipc_error)?, Some(Response::Send(7, mid, peer, message))
                if mid == [1; 8] && peer == [2; 32] && message == [0, 4, 0, 0])
        {
            return Err("result pressure changed the held command or admitted a short extent".into());
        }
        let first_wire = drain(&mut ipc, &mut peer, 1, 65535).await?;
        if !matches!(Request::decode(&first_wire).map_err(|e| format!("{e:?}"))?, Request::Incoming { message, .. } if message == first)
            || !ipc.room_request(result).map_err(ipc_error)?
            || ipc.input_hard() != Some(input_hard)
        {
            return Err("whole original output did not restore exact result capacity".into());
        }
        ipc.enqueue(result, Role::Sent(7, [1; 8]), input_hard)
            .map_err(ipc_error)?;
        ipc.release().map_err(ipc_error)?;
        let remaining = drain(&mut ipc, &mut peer, 2, 65484 + 52).await?;
        if ipc.next != sequence + 1
            || !ipc.outputs.is_empty()
            || !matches!(Request::decode(&remaining[..65484]).map_err(|e| format!("{e:?}"))?, Request::Incoming { message, .. } if message == second)
            || Request::decode(&remaining[65484..]).map_err(|e| format!("{e:?}"))? != result
        {
            return Err("capacity recovery duplicated, reordered or changed the original result".into());
        }
        ipc.close();
        Ok(())
    })
}

#[test]
fn explicit_identity_pause_closes_original_mq_and_defers_reconnect_until_domain_resume()
-> Result<(), TestError> {
    runtime()?.block_on(async {
        let directory=Directory::new()?;
        let (mut ipc,listener,hard)=new_ipc(&directory)?;
        let mut original=attach(&mut ipc,&listener).await?;
        ipc.enqueue(Request::Register {characteristics:gnunet_wire::official::communicator::Characteristics::Reliable,can_burst:false,prefix:b"quic"},Role::Register,hard).map_err(ipc_error)?;
        loop {
            match ipc.poll_recovering(&mut Context::from_waker(std::task::Waker::noop()),|_,_,_|{}).map_err(ipc_error)? {
                Step::Written {bytes,complete:false,..} if bytes>0=>break,
                _=>tokio::task::yield_now().await,
            }
        }
        let mut retired=Vec::new();
        let facts=ipc.retire_source(|generation,role,bytes|retired.push((generation,role,bytes))).map_err(ipc_error)?;
        if facts.generation!=1 || facts.next_generation!=2 || facts.exposed_outputs!=1 || retired!=[(1,Role::Register,1)] {return Err("actual old prefix differs".into());}
        let mut tail=Vec::new();original.read_to_end(&mut tail).await?;
        if tail.len()!=1 {return Err("old physical MQ did not close after its exact prefix".into());}
        let mut cx=Context::from_waker(std::task::Waker::noop());
        for _ in 0..8 {
            if !matches!(ipc.poll_recovering(&mut cx,|_,_,_|{}).map_err(ipc_error)?,Step::Pending) || listener.poll_accept(&mut cx).is_ready() {return Err("paused source reconnected early".into());}
        }
        ipc.resume_source().map_err(ipc_error)?;
        let fresh=attach(&mut ipc,&listener).await?;
        if !ipc.outputs.is_empty() || ipc.generation()!=2 || !matches!(fresh.try_read(&mut [0;32]),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock) {return Err("old FIFO crossed the source cut".into());}
        ipc.close();
        Ok(())
    })
}
