//! Original physical FIFO/cancellation witnesses, shared before and after extraction.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Physical FIFO assertions accompany fallible setup"
)]
use super::*;
use std::future::poll_fn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn message(value: u8) -> Vec<u8> {
    vec![0, 8, 0, 99, value, value, value, value]
}
async fn write_step(link: &mut Link) -> std::io::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), poll_fn(|cx| link.poll_tx(cx))).await??;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_partial_original_survives_cancellation_and_later_frame_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let (connection, mut peer) = pair()?;
    let mut link = Link::new(connection, 65535, 4, 1)?;
    let first = message(1);
    let removed = message(2);
    let next = message(3);
    link.enqueue(first.clone())?;
    link.enqueue(removed)?;
    write_step(&mut link).await?;
    let mut actual = [0; 1];
    peer.read_exact(&mut actual).await?;
    assert_eq!(actual[0], first[0]);
    assert_eq!(link.cancel_unwritten(|_| true), 1);
    link.enqueue(next.clone())?;
    for _ in 0..15 {
        write_step(&mut link).await?;
    }
    let mut tail = vec![0; 15];
    peer.read_exact(&mut tail).await?;
    let mut all = actual.to_vec();
    all.extend(tail);
    let mut expected = first;
    expected.extend(next);
    assert_eq!(all, expected);
    assert!(
        tokio::time::timeout(Duration::from_millis(5), poll_fn(|cx| link.poll_tx(cx)))
            .await
            .is_err()
    );
    link.enqueue(message(4))?;
    for _ in 0..8 {
        write_step(&mut link).await?;
    }
    let mut last = [0; 8];
    peer.read_exact(&mut last).await?;
    assert_eq!(last.as_slice(), message(4));
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_split_header_and_retained_complete_frame_survive_dropped_waits()
-> Result<(), Box<dyn std::error::Error>> {
    let (connection, mut peer) = pair()?;
    let mut link = Link::new(connection, 65535, 4, 1)?;
    let first = message(5);
    let next = message(6);
    peer.write_all(&first[..3]).await?;
    let waiting = tokio::time::timeout(
        Duration::from_millis(5),
        poll_fn(|cx| match link.poll_rx(cx) {
            Poll::Ready(Ok(true)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(false)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }),
    )
    .await;
    assert!(waiting.is_err());
    assert!(link.frame().is_none());
    peer.write_all(&first[3..]).await?;
    peer.write_all(&next).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| match link.poll_rx(cx) {
            Poll::Ready(Ok(true)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(false)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }),
    )
    .await??;
    assert_eq!(link.frame(), Some(first.as_slice()));
    assert!(
        tokio::time::timeout(Duration::from_millis(5), poll_fn(|cx| link.poll_rx(cx)))
            .await
            .is_err()
    );
    assert_eq!(link.frame(), Some(first.as_slice()));
    link.release();
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| match link.poll_rx(cx) {
            Poll::Ready(Ok(true)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(false)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }),
    )
    .await??;
    assert_eq!(link.frame(), Some(next.as_slice()));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clock_failure_prevents_physical_start_write_and_recovery_keeps_original_frame()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed([0x62; 32]);
    let clock = Arc::new(ManualClock::new(100));
    let mut host = Host::with_clock(
        &identity,
        b"",
        PeerClass::UNKNOWN,
        endpoint()?,
        Limits::default(),
        ServiceOptions::default(),
        clock.clone(),
    )?;
    host.connect_now = false;
    host.retry_at = u64::MAX;
    let (connection, mut peer) = pair()?;
    host.attach_transport(connection)?;
    clock.change(100, true)?;
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        host.poll(&mut cx, &[], &mut |_| {}),
        Poll::Ready(Err(HostError::Clock(Error::TimeUncertain)))
    ));
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(5), peer.read(&mut byte))
            .await
            .is_err()
    );
    clock.change(100, false)?;
    let start = alongside(&mut host, async { Ok(frame(&mut peer).await?) }).await?;
    assert!(matches!(
        TransportRequest::decode(&start)?,
        TransportRequest::Start(_)
    ));
    host.shutdown();
    assert!(!clock.subscribed()?);
    Ok(())
}
