//! Portable I/O interruption and original-deadline regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert independent cursor/deadline outcomes while propagating actual I/O failures"
)]
use super::{read_frame, write_all_until};
use crate::IpcError;
use std::{io, pin::Pin, task::Poll, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
struct Interruptible {
    input: &'static [u8],
    received: usize,
    read_polls: usize,
    write_polls: usize,
    sent: Vec<u8>,
    perpetual: bool,
}
impl Interruptible {
    fn new(input: &'static [u8]) -> Self {
        Self {
            input,
            received: 0,
            read_polls: 0,
            write_polls: 0,
            sent: Vec::new(),
            perpetual: false,
        }
    }
}
impl AsyncRead for Interruptible {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let state = self.get_mut();
        state.read_polls += 1;
        if state.perpetual || state.read_polls == 2 {
            return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
        }
        let count = 2
            .min(buf.remaining())
            .min(state.input.len() - state.received);
        buf.put_slice(&state.input[state.received..state.received + count]);
        state.received += count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Interruptible {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let state = self.get_mut();
        state.write_polls += 1;
        if state.perpetual || state.write_polls == 2 {
            return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
        }
        let count = 2.min(bytes.len());
        state.sent.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[test]
fn interrupted_partial_stream_keeps_original_frame_and_send_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
            let deadline=Instant::now()+Duration::from_secs(1);
            let mut stream=Interruptible::new(b"\0\x04\0\xab");
            let mut bytes=[0xa5;32];
            let size=read_frame(&mut stream,&mut bytes,deadline).await?;
            assert_eq!(&bytes[..size],b"\0\x04\0\xab");
            assert_eq!(stream.received,4);assert_eq!(stream.read_polls,3);
            write_all_until(&mut stream,b"\0\x04\0\xae",deadline).await?;
            assert_eq!(stream.sent,b"\0\x04\0\xae");assert_eq!(stream.write_polls,3);
            assert!(matches!(read_frame(&mut stream,&mut bytes,deadline).await,Err(IpcError::Io(error)) if error.kind()==io::ErrorKind::UnexpectedEof));
            Ok(())
        })
}
#[test]
fn repeated_interruptions_do_not_extend_the_original_io_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut stream = Interruptible::new(b"\0\x04\0\xab");
            stream.perpetual = true;
            let mut bytes = [0; 4];
            assert!(matches!(
                read_frame(
                    &mut stream,
                    &mut bytes,
                    Instant::now() + Duration::from_millis(2)
                )
                .await,
                Err(IpcError::Deadline)
            ));
            assert_eq!(stream.received, 0);
            assert!(matches!(
                write_all_until(
                    &mut stream,
                    b"frame",
                    Instant::now() + Duration::from_millis(2)
                )
                .await,
                Err(IpcError::Deadline)
            ));
            assert!(stream.sent.is_empty());
            Ok(())
        })
}
