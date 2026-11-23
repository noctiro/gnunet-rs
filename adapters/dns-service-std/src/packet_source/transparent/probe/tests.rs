use super::*;
use std::future::poll_fn;
use tokio::{sync::mpsc as async_mpsc, time::timeout};

const LIMIT: Duration = Duration::from_secs(2);

#[test]
fn one_request_is_retained_and_retirement_waits_for_exit() -> io::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?
        .block_on(exercise())
}

async fn exercise() -> io::Result<()> {
    let (started, mut observed) = async_mpsc::unbounded_channel();
    let (release, hold) = mpsc::channel::<()>();
    let mut worker = Worker::start(move |request: u32| {
        started.send(request).map_err(io::Error::other)?;
        hold.recv().map_err(io::Error::other)?;
        Ok::<_, io::Error>(request)
    })?;

    worker.submit(10)?;
    if timeout(LIMIT, observed.recv()).await? != Some(10) {
        return Err(io::Error::other(
            "the original worker request did not start",
        ));
    }
    if !worker.busy()
        || !matches!(worker.submit(11), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
    {
        return Err(io::Error::other(
            "the outstanding request lost its receipt slot",
        ));
    }
    release.send(()).map_err(io::Error::other)?;
    let receipt = timeout(LIMIT, poll_fn(|cx| worker.poll(cx))).await???;
    if receipt != 10 || worker.busy() {
        return Err(io::Error::other("the worker lost the original receipt"));
    }

    worker.submit(12)?;
    if timeout(LIMIT, observed.recv()).await? != Some(12) {
        return Err(io::Error::other("the second worker request did not start"));
    }
    let waiting = poll_fn(|cx| Poll::Ready(worker.poll_retired(cx).is_pending())).await;
    if !waiting || !matches!(worker.submit(13), Err(e) if e.kind() == io::ErrorKind::NotConnected) {
        return Err(io::Error::other(
            "a live worker retired or accepted new work",
        ));
    }
    release.send(()).map_err(io::Error::other)?;
    timeout(LIMIT, poll_fn(|cx| worker.poll_retired(cx))).await??;
    if worker.thread.is_some() {
        return Err(io::Error::other("the retirement receipt preceded the join"));
    }
    Ok(())
}
