//! Actual native short-write and original remaining-byte budget regression.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Physical FIFO assertions accompany fallible local setup"
)]
use crate::framed::Framed;
use gnunet_service_runtime::connection::Connection;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::io::AsyncReadExt;
trait BorrowedCaseAdapter {
    fn queue(&mut self, bytes: &[u8]) -> Result<(), gnunet_types::Error>;
}
impl BorrowedCaseAdapter for Framed {
    fn queue(&mut self, bytes: &[u8]) -> Result<(), gnunet_types::Error> {
        self.queue_owned(bytes.to_vec())
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_short_write_reclaims_remaining_budget_without_changing_original_fifo()
-> Result<(), Box<dyn std::error::Error>> {
    let (a, b) = std::os::unix::net::UnixStream::pair()?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    socket2::SockRef::from(&a).set_send_buffer_size(1024)?;
    socket2::SockRef::from(&b).set_recv_buffer_size(1024)?;
    let connection = Connection::from_unix(tokio::net::UnixStream::from_std(a)?);
    let mut peer = tokio::net::UnixStream::from_std(b)?;
    let mut io = Framed::new(connection, 65535)?;
    let mut first = vec![0x5a; 65535];
    first[..4].copy_from_slice(&[255, 255, 0, 99]);
    io.queue(&first)?;
    poll_fn(|cx| io.poll_write(cx)).await?;
    peer.readable().await?;
    let mut prefix = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        match peer.try_read(&mut buffer) {
            Ok(0) => return Err("early EOF".into()),
            Ok(n) => prefix.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
        }
    }
    assert!(
        prefix.len() >= 4 && prefix.len() < first.len(),
        "real native short prefix required, got {}",
        prefix.len()
    );
    let next = [0, 4, 0, 100];
    io.queue(&next)?;
    let mut suffix = vec![0; first.len() + next.len() - prefix.len()];
    {
        let read = async { peer.read_exact(&mut suffix).await };
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
    prefix.extend(suffix);
    first.extend(next);
    assert_eq!(prefix, first);
    Ok(())
}
