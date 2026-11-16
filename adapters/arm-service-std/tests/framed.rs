//! Real owned stream framing; no service dispatch or native process is simulated.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite actual IO and cursor invariants are asserted while IO setup errors propagate"
)]
use gnunet_arm_service_host::framed::{Error, FramedConnection, Received};
use gnunet_service_runtime::connection::Connection;
use std::{error::Error as StdError, future::poll_fn, task::Poll, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Test = Result<(), Box<dyn StdError>>;
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn pair() -> Result<(Connection, Connection), Box<dyn StdError>> {
    use gnunet_service_runtime::{
        LocalListenerAccess,
        local::{Listener, Stream},
    };
    let mut nonce = [0; 16];
    gnunet_native::entropy::fill(&mut nonce)?;
    let parent = std::env::temp_dir();
    let name = format!("gn-arm-frame-{:032x}", u128::from_be_bytes(nonce));
    gnunet_native::filesystem::Directory::open(&parent)?
        .create_private_directory(std::ffi::OsStr::new(&name))?;
    let directory = Directory(parent.join(name));
    let path = directory.0.join("ipc");
    let prepared = gnunet_service_runtime::local_listener::prepare(
        path.clone(),
        LocalListenerAccess::Owner,
        5,
    )
    .await?;
    let (socket, _path, _warnings) = prepared.into_parts();
    #[cfg(unix)]
    let listener = Listener::from_std(socket.into())?;
    #[cfg(windows)]
    let listener = Listener::from_bound_socket(socket)?;
    let (peer, accepted) = tokio::try_join!(Stream::connect(&path), listener.accept())?;
    Ok((
        Connection::from_unix(accepted.0),
        Connection::from_unix(peer),
    ))
}
async fn frame(io: &mut FramedConnection) -> Result<Vec<u8>, Error> {
    poll_fn(|cx| match io.poll_receive(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(Received::Frame(bytes))) => Poll::Ready(Ok(bytes.to_vec())),
        Poll::Ready(Ok(Received::Eof { .. })) => Poll::Ready(Err(Error::Closed)),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    })
    .await
}
#[test]
fn fragmented_header_and_body_survive_cancel_and_do_not_advance_until_consumed() -> Test {
    runtime()?.block_on(async {
        let (a, mut peer) = pair().await?;
        let mut io = FramedConnection::new(a, 65535, 65535, 4, 1)?;
        peer.write_all(&[0, 8]).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(5), frame(&mut io))
                .await
                .is_err()
        );
        peer.write_all(&[0, 8, 1, 2, 3, 4, 0, 4, 0, 15]).await?;
        let first = frame(&mut io).await?;
        assert_eq!(first, vec![0, 8, 0, 8, 1, 2, 3, 4]);
        assert_eq!(frame(&mut io).await?, first);
        io.consume_frame()?;
        assert_eq!(frame(&mut io).await?, vec![0, 4, 0, 15]);
        io.consume_frame()?;
        peer.shutdown().await?;
        let eof = poll_fn(|cx| match io.poll_receive(cx) {
            Poll::Ready(Ok(Received::Eof { partial })) => Poll::Ready(Ok(partial)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Pending,
        })
        .await?;
        assert!(!eof);
        Ok(())
    })
}
#[test]
fn zero_small_and_over_capacity_frames_retire_without_synthetic_empty_buffer_eof() -> Test {
    runtime()?.block_on(async {
        for (header, capacity) in [
            (vec![0, 0, 0, 8], 64),
            (vec![0, 3, 0, 8], 64),
            (vec![0, 8, 0, 8], 4),
        ] {
            let (a, mut peer) = pair().await?;
            let mut io = FramedConnection::new(a, capacity, 64, 4, 8)?;
            peer.write_all(&header).await?;
            let first = frame(&mut io).await;
            assert!(matches!(first, Err(Error::Malformed | Error::Capacity)));
            assert!(matches!(frame(&mut io).await, Err(Error::Closed)));
            assert!(matches!(io.enqueue(&[0, 4, 0, 15]), Err(Error::Closed)));
        }
        Ok(())
    })
}
#[test]
fn durable_fifo_and_mq_length_follow_partial_actual_write_attempts() -> Test {
    runtime()?.block_on(async {
        let (a, mut peer) = pair().await?;
        let mut io = FramedConnection::new(a, 64, 8, 2, 1)?;
        io.enqueue(&[0, 4, 0, 15])?;
        io.enqueue(&[0, 4, 0, 15])?;
        assert_eq!(io.mq_length(), 2);
        assert!(matches!(io.enqueue(&[0, 4, 0, 15]), Err(Error::Capacity)));
        assert_eq!(io.pending_bytes(), 8);
        assert!(poll_fn(|cx| io.poll_send(cx)).await?);
        assert_eq!(io.pending_bytes(), 7);
        assert_eq!(io.mq_length(), 1, "actual partial head is in flight");
        let mut byte = [0];
        peer.read_exact(&mut byte).await?;
        assert_eq!(byte, [0]);
        // Canceling a pending outer caller retains the original offsets/envelopes.
        while !io.tx_empty() {
            assert!(poll_fn(|cx| io.poll_send(cx)).await?);
        }
        assert_eq!(io.mq_length(), 0);
        assert_eq!(io.pending_bytes(), 0);
        let mut rest = [0; 7];
        peer.read_exact(&mut rest).await?;
        assert_eq!(rest, [4, 0, 15, 0, 4, 0, 15]);
        Ok(())
    })
}
