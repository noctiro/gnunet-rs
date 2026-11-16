//! Normal local-service sockets on Unix and Windows, retaining the caller path.
#[path = "local.rs"]
mod listener;
use gnunet_service_runtime::local::Stream;
use std::{future::poll_fn, io, path::Path};
pub(crate) async fn pair(path: &Path) -> io::Result<(Stream, Stream)> {
    let listener = listener::bind(path)?;
    let (peer, original) = tokio::join!(
        Stream::connect(path),
        poll_fn(|cx| listener.poll_accept(cx))
    );
    let (original, _) = original?;
    Ok((original, peer?))
}
