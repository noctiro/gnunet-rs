//! Prepared original native-source witnesses; not peer computation or authorization.
use super::*;
use std::{error::Error as StdError, future::Future, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn StdError>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // The counter separates parallel tests even on a coarse system clock.
        let path = std::env::temp_dir().join(format!("gsd-{}-{serial}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn attached(
    client: &mut Client,
    listener: &UnixListener,
) -> Result<(UnixStream, Epoch), Failure> {
    let mut accept = std::pin::pin!(listener.accept());
    let mut stream = None;
    let mut epoch: Option<Epoch> = None;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| -> Poll<Result<_, Failure>> {
            if stream.is_none()
                && let Poll::Ready(result) = accept.as_mut().poll(cx)
            {
                stream = Some(result?.0);
            }
            if let Some(original) = epoch.as_ref() {
                if let Some(stream) = stream.take() {
                    return Poll::Ready(Ok((stream, original.clone())));
                }
                return Poll::Pending;
            }
            match client.poll_progress(cx) {
                Poll::Ready(Ok(Progress::Attached(original))) => {
                    epoch = Some(original);
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err("unexpected pre-attachment progress".into()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
            Poll::Pending
        }),
    )
    .await?
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err("short original native frame".into());
    }
    let mut bytes = vec![0; n];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn lost(client: &mut Client) -> Result<(Loss, Receipt), Failure> {
    let mut last = client.receipt();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client.drive().await? {
                Progress::Written { receipt, .. } => last = receipt,
                Progress::Activity { .. } => {}
                Progress::Lost(loss) => return Ok((loss, last)),
                _ => return Err("source failure became a typed result".into()),
            }
        }
    })
    .await?
}
async fn pressure(client: &mut Client) -> Result<(), Failure> {
    let mut turns = 0usize;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| -> Poll<Result<(), Failure>> {
            for _ in 0..4096 {
                turns += 1;
                if turns > 200_000 {
                    return Poll::Ready(Err("no bounded native TX pressure".into()));
                }
                match client.write(cx) {
                    Poll::Ready(Ok(Progress::Written { .. })) if !client.whole => {}
                    Poll::Ready(Ok(_)) => {
                        return Poll::Ready(Err("request completed before native pressure".into()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending if client.written > 0 && !client.whole => {
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }),
    )
    .await??;
    Ok(())
}
async fn whole(client: &mut Client) -> Result<Receipt, Failure> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client.drive().await? {
                Progress::Written {
                    complete: true,
                    receipt,
                    ..
                } => return Ok(receipt),
                Progress::Written { .. } | Progress::Activity { .. } => {}
                _ => return Err("ordinary request did not write wholly".into()),
            }
        }
    })
    .await?
}

fn client(
    directory: &Directory,
    large: bool,
    io_slice_bytes: usize,
) -> Result<(Client, UnixListener), Failure> {
    let path = directory.0.join("s");
    let listener = UnixListener::bind(&path)?;
    let source = EndpointSource::unix(path);
    let bounds = Bounds::new(source.clock().as_ref(), Duration::from_secs(30))?;
    let attribute = vec![b'a'; if large { 65_400 } else { 1 }];
    let mut key = [3; ipc::KEY_BYTES];
    key[..4].copy_from_slice(&ipc::EDKEY.to_be_bytes());
    let request = ipc::Request::Verify {
        id: 17,
        subject: ipc::Key::new(&key)?,
        issuer: ipc::Key::new(&key)?,
        attribute: &attribute,
        resolution: ipc::BOTH,
        delegates: ipc::Delegates::new(&[], 0)?,
    };
    Ok((
        Client::new(
            source,
            &request,
            Limits {
                io_slice_bytes,
                ..Limits::default()
            },
            bounds,
        )?,
        listener,
    ))
}
fn response() -> Result<Vec<u8>, Failure> {
    let response = ipc::Response::Result {
        kind: gnunet_wire::official::message_type::ABD_VERIFY_RESULT,
        id: 17,
        found: 1,
        chain: ipc::Chains::new(&[], 0)?,
        delegates: ipc::Delegates::new(&[], 0)?,
    };
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn native_partial_request_pending_still_observes_original_read_half_eof() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, true, 31)?;
        let (mut peer, epoch) = attached(&mut client, &listener).await?;
        // No peer read drains request bytes: reach an actual native Pending.
        pressure(&mut client).await?;
        let before = client.receipt();
        let original = client.bounds();
        let write_target = client
            .write
            .as_ref()
            .ok_or("original write target missing")?
            .targets;
        peer.shutdown().await?;
        client.io_class = 0; // Pending TX must fall through to the same original RX.
        let (loss, last) = lost(&mut client).await?;
        if !matches!(loss.cause, Cause::Eof)
            || loss.receipt.epoch.as_ref() != Some(&epoch)
            || loss.receipt.written_bytes != last.written_bytes
            || loss.receipt.written_bytes < before.written_bytes
            || loss.receipt.request_written
            || loss.receipt.request_bytes != before.request_bytes
            || loss.receipt.response_bytes != 0
            || client.bounds().hard != original.hard
            || client.bounds().expires != original.expires
            || Instant::now() >= write_target.hard
            || !client.closed
        {
            return Err(
                "TX pressure hid EOF or changed original prefix/source/bounds facts".into(),
            );
        }
        Ok(())
    })
}
#[test]
fn complete_expected_reply_before_whole_request_is_a_refusal() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, true, 1)?;
        let (mut peer, epoch) = attached(&mut client, &listener).await?;
        // A queued reply alone does not establish that its complete frame is
        // read before a small request finishes. Reach actual native TX Pending
        // with the large original request; do not drain this peer's read half.
        pressure(&mut client).await?;
        let before = client.receipt();
        let original = client.bounds();
        let response = response()?;
        peer.write_all(&response).await?;
        client.io_class = 0; // Retain the real Pending TX-first duplex path.
        let (loss, last) = lost(&mut client).await?;
        if !matches!(
            loss.cause,
            Cause::Failure(Error::Protocol(Fault::Malformed))
        ) || loss.receipt.request_written
            || before.request_written
            || before.written_bytes == 0
            || loss.receipt.written_bytes != last.written_bytes
            || loss.receipt.written_bytes < before.written_bytes
            || loss.receipt.request_bytes != before.request_bytes
            || client.bounds().hard != original.hard
            || client.bounds().expires != original.expires
            || loss.receipt.response_bytes != response.len()
            || loss.receipt.epoch.as_ref() != Some(&epoch)
            || !client.closed
        {
            return Err("premature original reply was promoted or lost its exact prefix".into());
        }
        Ok(())
    })
}
#[test]
fn malformed_first_header_retains_actual_four_bytes_before_retirement() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, false, 31)?;
        let (mut peer, _) = attached(&mut client, &listener).await?;
        peer.write_all(&[0, 3, 0, 0]).await?;
        let (loss, _) = lost(&mut client).await?;
        if !matches!(loss.cause, Cause::Failure(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::InvalidData)
            || loss.receipt.response_bytes != 4
            || !client.closed
        {
            return Err("malformed native header lost actual retained bytes/error".into());
        }
        Ok(())
    })
}

#[test]
fn whole_original_request_still_accepts_exact_expected_response() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, false, 65535)?;
        let (mut peer, epoch) = attached(&mut client, &listener).await?;
        let written = whole(&mut client).await?;
        if !written.request_written || written.written_bytes != written.request_bytes {
            return Err("whole original request receipt missing".into());
        }
        if !matches!(
            ipc::Request::decode(&frame(&mut peer).await?)?,
            ipc::Request::Verify { id: 17, .. }
        ) {
            return Err("actual original verify request missing".into());
        }
        let response = response()?;
        peer.write_all(&response).await?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client.drive().await? {
                    Progress::Result {
                        observation,
                        receipt,
                    } => {
                        if !matches!(
                            observation.view()?,
                            ipc::Response::Result {
                                id: 17,
                                found: 1,
                                ..
                            }
                        ) || observation.bytes() != response
                            || receipt.epoch.as_ref() != Some(&epoch)
                            || !receipt.request_written
                            || receipt.response_bytes != response.len()
                            || !client.closed
                        {
                            return Err("ordinary original result/source/receipt changed".into());
                        }
                        return Ok::<(), Failure>(());
                    }
                    Progress::Activity { .. } => {}
                    _ => return Err("ordinary whole-request response became loss".into()),
                }
            }
        })
        .await??;
        let mut byte = [0; 1];
        if tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte)).await?? != 0 {
            return Err("terminal result left old MQ open".into());
        }
        Ok(())
    })
}
