//! Actual native short-write and original remaining-byte budget regression.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Physical FIFO assertions accompany fallible local setup"
)]
use crate::framed::Framed;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::io::AsyncReadExt;
#[tokio::test(flavor = "current_thread")]
async fn actual_bounded_prefix_reclaims_remaining_budget_without_changing_original_fifo()
-> Result<(), Box<dyn std::error::Error>> {
    let (connection, mut peer) = crate::test_support::pair().await?;
    let mut io = Framed::new(connection, 65535)?;
    let mut first = vec![0x5a; 65535];
    first[..4].copy_from_slice(&[255, 255, 0, 99]);
    io.queue_owned(first.clone())?;
    let next = [0, 4, 0, 100];
    assert_eq!(
        io.queue_owned(next.to_vec()),
        Err(gnunet_types::Error::WouldBlock),
        "the original frame must consume the complete byte budget"
    );
    // The production write quantum bounds the prefix independently of native
    // TCP buffer sizing and receive-window update timers.
    let progress = poll_fn(|cx| io.poll_write_status(cx)).await?;
    assert!(
        progress.bytes >= next.len() && progress.bytes < first.len(),
        "bounded original native prefix required, got {}",
        progress.bytes
    );
    assert_eq!(progress.completed_frames, 0);
    // Reclaim the positive write before the peer consumes any bytes. Admission
    // depends on remaining wire bytes, not peer delivery or whole-frame release.
    io.queue_owned(next.to_vec())?;
    let mut actual = vec![0; first.len() + next.len()];
    {
        let read = async { peer.read_exact(&mut actual).await };
        tokio::pin!(read);
        tokio::time::timeout(
            Duration::from_secs(3),
            poll_fn(|cx| {
                match io.poll_write(cx) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
                    Poll::Pending => {}
                }
                Pin::new(&mut read).poll(cx)
            }),
        )
        .await??;
    }
    first.extend(next);
    assert_eq!(actual, first);
    Ok(())
}
