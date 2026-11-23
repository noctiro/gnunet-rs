//! Original local client disconnect while PILS is still establishing identity.
use super::*;
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::{
    clock::SystemClock,
    connection::Connection,
    framing::{Accounting, Budget, Limits},
};
use gnunet_wire::official::consensus::Join;
use std::{ffi::OsStr, io, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn std::error::Error>;

#[test]
fn eof_after_join_retires_the_original_pils_attempt() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut nonce = [0; 8];
            gnunet_native::entropy::fill(&mut nonce)?;
            let name = format!("gnunet-consensus-{:016x}", u64::from_ne_bytes(nonce));
            let parent = std::env::temp_dir();
            let directory = gnunet_native::filesystem::Directory::open(&parent)?;
            directory.create_private_directory(OsStr::new(&name))?;
            let scratch = Scratch(parent.join(name));
            let path = scratch.0.join("pils");
            let upstream = UnixListener::bind(&path)?;
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let sources = Sources::new(
                EndpointSource::unix_with_clock(path, clock.clone()),
                EndpointSource::unix_with_clock(scratch.0.join("set"), clock.clone()),
            )?;
            let (service, mut peer) = UnixStream::pair()?;
            let limits = ServerLimits::default();
            let io = Framed::new(
                Connection::from_unix(service),
                Limits {
                    frame_bytes: limits.frame_bytes,
                    ordinary: Budget {
                        frames: 1,
                        bytes: limits.frame_bytes,
                    },
                    reserved: Budget::default(),
                    accounting: Accounting::Retained,
                    io_slice_bytes: limits.io_slice_bytes,
                },
            )?;
            let origin = origin(clock.as_ref(), limits, Instant::now())?;
            let request = ClientRequest::Join(Join {
                session: [5; 64],
                start: clock.sample()?.now.as_micros(),
                deadline: origin.overall.expires,
                peers: &[],
            });
            let mut bytes = vec![0; request.encoded_len()?];
            request.encode(&mut bytes)?;
            peer.write_all(&bytes).await?;
            verify_disconnect(io, peer, upstream, sources, limits, origin).await
        })
}

async fn verify_disconnect(
    framed: Framed<()>,
    peer: UnixStream,
    upstream: UnixListener,
    sources: Sources,
    limits: ServerLimits,
    origin: Origin,
) -> Result<(), Failure> {
    let wait = Duration::from_secs(2);
    let mut running = pin!(session(
        1,
        framed,
        sources,
        limits,
        origin,
        Rc::new(RefCell::new(Registry::new(1)?)),
        Rc::new(Control::new()),
    ));
    let mut accepting = pin!(upstream.accept());
    let (mut pils_peer, _) = tokio::time::timeout(
        wait,
        poll_fn(|cx| {
            if running.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::other(
                    "session ended before waiting for PILS",
                )));
            }
            accepting.as_mut().poll(cx)
        }),
    )
    .await??;
    // The original PILS connection exists, but has provided no identity.
    drop(peer);
    let report = tokio::time::timeout(wait, running).await?;
    if report.primary.as_ref().map(Error::classified) != Some(Fault::Closed)
        || !report.physical_closed
        || report.outcome.is_some()
    {
        return Err("disconnect failed to retire pre-session owners".into());
    }
    let mut byte = [0; 1];
    if tokio::time::timeout(wait, pils_peer.read(&mut byte)).await?? != 0 {
        return Err("original PILS connection did not retire".into());
    }
    Ok(())
}

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
