//! Actual native malformed-head witnesses through both shared-session callers.
use crate::{
    Bounds, Cause, Decision, EndpointSource, Factory, Limits, ListenProgress, Listener, LossOrigin,
    OperationType, Set, SetProgress, TransportLoss,
};
use std::{
    error::Error,
    future::{Future, poll_fn},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn Error>;
struct Directory(PathBuf);
static DIRECTORY_SERIAL: AtomicUsize = AtomicUsize::new(0);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let serial = DIRECTORY_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gsetprefix-{}-{stamp:x}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
enum Native {
    Set(Box<Set>),
    Listener(Box<Listener>),
}
enum Step {
    Whole,
    Activity,
    Lost(TransportLoss, Cause),
}
impl Native {
    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<Step, Failure>> {
        let value = match self {
            Self::Set(owner) => match owner.poll_progress(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(SetProgress::InitializerWritten { complete: true, .. })) => {
                    Step::Whole
                }
                Poll::Ready(Ok(SetProgress::Lost(loss))) => Step::Lost(loss.transport, loss.cause),
                Poll::Ready(Ok(_)) => Step::Activity,
            },
            Self::Listener(owner) => match owner.poll_progress(cx, &mut |_| Decision::Reject) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(ListenProgress::Written {
                    complete: true,
                    rejected: None,
                    ..
                })) => Step::Whole,
                Poll::Ready(Ok(ListenProgress::Lost(loss))) => {
                    Step::Lost(loss.transport, loss.cause)
                }
                Poll::Ready(Ok(_)) => Step::Activity,
            },
        };
        Poll::Ready(Ok(value))
    }
}
async fn initialized(owner: &mut Native, listener: &UnixListener) -> Result<UnixStream, Failure> {
    let mut accept = std::pin::pin!(listener.accept());
    let mut peer = None;
    let mut whole = false;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| -> Poll<Result<UnixStream, Failure>> {
            if peer.is_none()
                && let Poll::Ready(result) = accept.as_mut().poll(cx)
            {
                peer = Some(result?.0);
            }
            match owner.poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(Step::Whole)) => {
                    whole = true;
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Ok(Step::Activity)) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(Step::Lost(_, _))) => {
                    return Poll::Ready(Err("original initializer lost".into()));
                }
            }
            if whole && let Some(peer) = peer.take() {
                return Poll::Ready(Ok(peer));
            }
            Poll::Pending
        }),
    )
    .await?
}
async fn malformed(listener_role: bool, slice: usize) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let path = directory.0.join("set.sock");
    let listener = UnixListener::bind(&path)?;
    let factory = Factory::new(EndpointSource::unix(path))?;
    let limits = Limits {
        io_slice_bytes: slice,
        ..Limits::default()
    };
    let bounds = Bounds::new(factory.clock().as_ref(), Duration::from_secs(30))?;
    let mut owner = if listener_role {
        Native::Listener(Box::new(factory.listen(
            OperationType::Union,
            [6; 64],
            limits,
            bounds,
        )?))
    } else {
        Native::Set(Box::new(factory.set(
            OperationType::Union,
            limits,
            bounds,
        )?))
    };
    let mut peer = initialized(&mut owner, &listener).await?;
    let mut header = [0; 4];
    peer.read_exact(&mut header).await?;
    let extent = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if extent < 4 {
        return Err("short actual initializer".into());
    }
    let mut actual = vec![0; extent];
    actual[..4].copy_from_slice(&header);
    peer.read_exact(&mut actual[4..]).await?;
    match gnunet_wire::official::set::ClientRequest::decode(&actual)? {
        gnunet_wire::official::set::ClientRequest::Create { operation }
            if !listener_role && operation == OperationType::Union as u32 => {}
        gnunet_wire::official::set::ClientRequest::Listen { operation, app_id }
            if listener_role && operation == OperationType::Union as u32 && app_id == [6; 64] => {}
        _ => return Err("real Set/Listen initializer mismatch".into()),
    }
    // With slice65535, Framed retains4 then fails before any Progress. With
    // slice1, the first3 Progress reports exist: the loss must be4, not7.
    peer.write_all(&[0, 3, 0, 0]).await?;
    let (loss, cause) = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| -> Poll<Result<(TransportLoss, Cause), Failure>> {
            match owner.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(Step::Lost(loss, cause))) => Poll::Ready(Ok((loss, cause))),
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }),
    )
    .await??;
    if cause.origin() != LossOrigin::Source {
        return Err("native framing failure lost its original source origin".into());
    }
    let Cause::Failure(crate::Error::Io(error)) = cause else {
        return Err("native framing failure lost its actual I/O error".into());
    };
    if error.kind() != std::io::ErrorKind::InvalidData || error.get_ref().is_some() {
        return Err("native framing error object/kind was replaced".into());
    }
    if loss.partial_input != 4
        || !loss.initializer_written
        || loss.initializer_bytes != extent
        || loss.epoch.as_ref().is_none_or(|epoch| epoch.live())
    {
        return Err("actual original malformed head/initializer/epoch loss facts changed".into());
    }
    Ok(())
}
#[test]
fn actual_set_and_listener_first_malformed_header_preserves_all4bytes() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            malformed(false, 65535).await?;
            malformed(true, 65535).await
        })
}
#[test]
fn actual_set_and_listener_partial_malformed_header_counts_same_head_once() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            malformed(false, 1).await?;
            malformed(true, 1).await
        })
}
