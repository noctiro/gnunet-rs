//! Official GNUnet Unix/TCP stream IPC on Unix hosts.
//!
//! Each one-shot STATISTICS operation uses one caller-supplied absolute deadline.
//! After it takes the stream, cancellation, malformed replies and deadline expiry
//! retire the connection. Its preflight rejection submits no I/O and preserves an
//! otherwise usable connection. Persistent owners and the weak synchronous
//! presence test document their separate scheduling and observation contracts.
#![forbid(unsafe_code)]
#![cfg(unix)]

/// Shared host address policy, re-exported for IPC admission configuration.
pub use gnunet_service_runtime::acl;
pub mod handle;
pub mod producer;
/// Shared host Unix address shaping used by service endpoint selection.
pub use gnunet_service_runtime::network;
pub mod server;

mod watch;
pub use watch::StatisticsWatchClient;

use gnunet_client::statistics::{self, GetSession, Response, Selector, Set, Statistic};
use gnunet_types::Error;
use gnunet_wire::official::MessageHeader;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    path::Path,
    pin::Pin,
    task::Poll,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UnixStream,
    time::{Instant, timeout_at},
};

/// Boundary failures from the OS, original deadline or official message validation.
#[derive(Debug)]
pub enum IpcError {
    /// Official service configuration/path validation failed.
    Configuration(gnunet_config::Error),
    /// An OS/socket failure.
    Io(io::Error),
    /// Invalid/unsupported official message or exhausted caller capacity.
    Protocol(Error),
    /// The original operation deadline elapsed.
    Deadline,
    /// A failed/cancelled operation has retired this connection.
    Closed,
}
impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "IPC configuration: {error}"),
            Self::Io(error) => write!(f, "IPC I/O: {error}"),
            Self::Protocol(error) => write!(f, "IPC protocol: {error:?}"),
            Self::Deadline => f.write_str("IPC deadline elapsed"),
            Self::Closed => f.write_str("IPC connection closed"),
        }
    }
}
impl std::error::Error for IpcError {}
impl From<gnunet_client_host::ConnectError> for IpcError {
    fn from(error: gnunet_client_host::ConnectError) -> Self {
        match error {
            gnunet_client_host::ConnectError::Configuration(e) => Self::Configuration(e),
            gnunet_client_host::ConnectError::Io(e) => Self::Io(e),
            gnunet_client_host::ConnectError::Protocol(e) => Self::Protocol(e),
        }
    }
}
impl From<gnunet_config::Error> for IpcError {
    fn from(value: gnunet_config::Error) -> Self {
        Self::Configuration(value)
    }
}
impl From<io::Error> for IpcError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<Error> for IpcError {
    fn from(value: Error) -> Self {
        Self::Protocol(value)
    }
}

/// Official statistics connection; there is at most one original operation.
pub struct StatisticsClient {
    stream: Option<UnixStream>,
}
impl StatisticsClient {
    /// Connect before the original deadline, without submitting an expired connect.
    /// Socket ownership and configuration-file resolution belong to the caller.
    pub async fn connect(path: impl AsRef<Path>, deadline: Instant) -> Result<Self, IpcError> {
        check_deadline(deadline)?;
        let operation = async {
            check_deadline(deadline)?;
            let connection = UnixStream::connect(path);
            tokio::pin!(connection);
            let stream = poll_fn(|context| {
                if let Err(error) = check_deadline(deadline) {
                    return Poll::Ready(Err(error));
                }
                connection
                    .as_mut()
                    .poll(context)
                    .map(|result| result.map_err(IpcError::Io))
            })
            .await?;
            check_deadline(deadline)?;
            Ok::<_, IpcError>(stream)
        };
        let stream = timeout_at(deadline, operation)
            .await
            .map_err(|_| IpcError::Deadline)??;
        check_deadline(deadline)?;
        Ok(Self {
            stream: Some(stream),
        })
    }
    /// Whether an admitted operation's error or cancellation retired the stream.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
    /// GET until its exact END, within the original deadline and value/byte capacities.
    /// Each callback only borrows this frame. Callback errors retire the connection.
    /// An unpolled future submits no request; dropping an admitted future closes it.
    pub async fn get(
        &mut self,
        selector: Selector<'_>,
        maximum_values: usize,
        scratch: &mut [u8],
        deadline: Instant,
        mut accept: impl FnMut(Statistic<'_>) -> Result<(), Error>,
    ) -> Result<usize, IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        let mut session = GetSession::new(maximum_values);
        let size = session.start(selector, scratch)?;
        check_deadline(deadline)?;
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let operation = async {
            write_all_until(&mut stream, &scratch[..size], deadline).await?;
            let mut count = 0usize;
            loop {
                let size = read_frame(&mut stream, scratch, deadline).await?;
                match session.receive(&scratch[..size])? {
                    Response::Value(value) => {
                        check_deadline(deadline)?;
                        accept(value)?;
                        check_deadline(deadline)?;
                        count = count.checked_add(1).ok_or(Error::Overflow)?;
                    }
                    Response::End => {
                        check_deadline(deadline)?;
                        return Ok::<usize, IpcError>(count);
                    }
                }
            }
        };
        let result = timeout_at(deadline, operation)
            .await
            .map_err(|_| IpcError::Deadline)?;
        if result.is_ok() {
            check_deadline(deadline)?;
            self.stream = Some(stream);
        }
        result
    }
    /// SET followed by the official DISCONNECT confirmation, closing this connection.
    /// A lost confirmation never reports success; an update may already have taken effect.
    /// No automatic retry is performed for such an ambiguous outcome.
    pub async fn set_and_disconnect(
        &mut self,
        update: Set<'_>,
        scratch: &mut [u8],
        deadline: Instant,
    ) -> Result<(), IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        let size = update.encode(scratch)?;
        check_deadline(deadline)?;
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let result = timeout_at(deadline, async {
            write_all_until(&mut stream, &scratch[..size], deadline).await?;
            let size = statistics::encode_disconnect(scratch)?;
            write_all_until(&mut stream, &scratch[..size], deadline).await?;
            let size = read_frame(&mut stream, scratch, deadline).await?;
            statistics::confirm_disconnect(&scratch[..size])?;
            check_deadline(deadline)?;
            Ok::<(), IpcError>(())
        })
        .await
        .map_err(|_| IpcError::Deadline)?;
        if result.is_ok() {
            check_deadline(deadline)?;
        }
        result
    }
}
fn check_deadline(deadline: Instant) -> Result<(), IpcError> {
    if Instant::now() >= deadline {
        Err(IpcError::Deadline)
    } else {
        Ok(())
    }
}
async fn read_exact_until(
    stream: &mut (impl AsyncRead + Unpin),
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), IpcError> {
    let mut position = 0;
    check_deadline(deadline)?;
    while position < output.len() {
        // Check at every actual I/O poll: timeout_at polls the inner future first,
        // even when a previously pending socket becomes Ready after the deadline.
        let count = poll_fn(|context| {
            if let Err(error) = check_deadline(deadline) {
                return Poll::Ready(Err(error));
            }
            let mut buffer = ReadBuf::new(&mut output[position..]);
            match retry_interrupted(
                Pin::new(&mut *stream).poll_read(context, &mut buffer),
                context,
            ) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(IpcError::Io(error))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        check_deadline(deadline)?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        position = position.checked_add(count).ok_or(Error::Overflow)?;
    }
    check_deadline(deadline)
}
async fn write_all_until(
    stream: &mut (impl AsyncWrite + Unpin),
    input: &[u8],
    deadline: Instant,
) -> Result<(), IpcError> {
    let mut position = 0;
    check_deadline(deadline)?;
    while position < input.len() {
        let count = poll_fn(|context| {
            if let Err(error) = check_deadline(deadline) {
                return Poll::Ready(Err(error));
            }
            match retry_interrupted(
                Pin::new(&mut *stream).poll_write(context, &input[position..]),
                context,
            ) {
                Poll::Ready(Ok(count)) => Poll::Ready(Ok(count)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(IpcError::Io(error))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        check_deadline(deadline)?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero).into());
        }
        position = position.checked_add(count).ok_or(Error::Overflow)?;
    }
    check_deadline(deadline)
}
async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin),
    scratch: &mut [u8],
    deadline: Instant,
) -> Result<usize, IpcError> {
    check_deadline(deadline)?;
    if scratch.len() < 4 {
        return Err(Error::Capacity.into());
    }
    read_exact_until(stream, &mut scratch[..4], deadline).await?;
    let header = MessageHeader::decode(&scratch[..4])?;
    if header.size() > scratch.len() {
        return Err(Error::Capacity.into());
    }
    read_exact_until(stream, &mut scratch[4..header.size()], deadline).await?;
    check_deadline(deadline)?;
    Ok(header.size())
}

fn retry_interrupted<T>(
    result: Poll<io::Result<T>>,
    cx: &std::task::Context<'_>,
) -> Poll<io::Result<T>> {
    match result {
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Real socket tests assert protocol and lifecycle outcomes while propagating I/O failures"
    )]
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    static NEXT: AtomicU64 = AtomicU64::new(1);
    fn socket_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "gnunet-ipc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
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
        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
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
    #[test]
    fn fragmented_official_reply_and_original_deadline() -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let path = socket_path();
                let listener = UnixListener::bind(&path)?;
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await?;
                    let mut request = [0; 6];
                    stream.read_exact(&mut request).await?;
                    assert_eq!(&request, b"\0\x06\0\xa9\0\0");
                    let value = b"\0\x14\0\xaa\x80\0\0\x03\0\0\0\0\0\0\0\x09a\0b\0\0\x04\0\xab";
                    for byte in value {
                        stream.write_all(&[*byte]).await?;
                    }
                    Ok::<(), io::Error>(())
                });
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut client = StatisticsClient::connect(&path, deadline).await?;
                let mut values = Vec::new();
                let count = client
                    .get(
                        Selector {
                            subsystem: b"",
                            name: b"",
                        },
                        1,
                        &mut [0; 64],
                        deadline,
                        |v| {
                            values.push((v.uid(), v.value, v.persistent()));
                            Ok(())
                        },
                    )
                    .await?;
                assert_eq!(count, 1);
                assert_eq!(values, [(3, 9, true)]);
                assert!(!client.is_closed());
                server.await??;
                std::fs::remove_file(path)?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
    #[test]
    fn partial_reply_timeout_retires_connection() -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let path = socket_path();
                let listener = UnixListener::bind(&path)?;
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await?;
                    let mut request = [0; 6];
                    stream.read_exact(&mut request).await?;
                    stream.write_all(b"\0\x14\0\xaa\0").await?;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok::<(), io::Error>(())
                });
                let deadline = Instant::now() + Duration::from_millis(50);
                let mut client = StatisticsClient::connect(&path, deadline).await?;
                assert!(matches!(
                    client
                        .get(
                            Selector {
                                subsystem: b"",
                                name: b""
                            },
                            1,
                            &mut [0; 64],
                            deadline,
                            |_| Ok(())
                        )
                        .await,
                    Err(IpcError::Deadline)
                ));
                assert!(client.is_closed());
                assert!(matches!(
                    client
                        .get(
                            Selector {
                                subsystem: b"",
                                name: b""
                            },
                            1,
                            &mut [0; 64],
                            Instant::now() + Duration::from_secs(1),
                            |_| Ok(())
                        )
                        .await,
                    Err(IpcError::Closed)
                ));
                server.await??;
                std::fs::remove_file(path)?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
    #[test]
    fn synchronously_ready_end_cannot_complete_after_callback_crosses_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let path = socket_path();
                let listener = UnixListener::bind(&path)?;
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await?;
                    let mut request = [0; 6];
                    stream.read_exact(&mut request).await?;
                    assert_eq!(&request, b"\0\x06\0\xa9\0\0");
                    stream
                        .write_all(b"\0\x14\0\xaa\x80\0\0\x03\0\0\0\0\0\0\0\x09a\0b\0\0\x04\0\xab")
                        .await?;
                    let mut byte = [0; 1];
                    match stream.read(&mut byte).await {
                        Ok(0) => {}
                        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                        other => {
                            return Err(io::Error::other(format!(
                                "deadline retirement did not close peer: {other:?}"
                            )));
                        }
                    }
                    Ok::<(), io::Error>(())
                });
                let mut client =
                    StatisticsClient::connect(&path, Instant::now() + Duration::from_secs(2))
                        .await?;
                let mut callbacks = 0;
                let result = client
                    .get(
                        Selector {
                            subsystem: b"",
                            name: b"",
                        },
                        1,
                        &mut [0; 64],
                        Instant::now() + Duration::from_millis(50),
                        |_| {
                            callbacks += 1;
                            std::thread::sleep(Duration::from_millis(100));
                            Ok(())
                        },
                    )
                    .await;
                assert_eq!(callbacks, 1);
                assert!(matches!(result, Err(IpcError::Deadline)));
                assert!(client.is_closed());
                server.await??;
                std::fs::remove_file(path)?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
    #[test]
    fn expired_connect_submits_no_connection() -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let path = socket_path();
                let listener = UnixListener::bind(&path)?;
                let past = Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .ok_or(Error::Overflow)?;
                assert!(matches!(
                    StatisticsClient::connect(&path, past).await,
                    Err(IpcError::Deadline)
                ));
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), listener.accept())
                        .await
                        .is_err()
                );
                drop(listener);
                std::fs::remove_file(path)?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
    #[test]
    fn preflight_capacity_and_expiry_submit_no_bytes_and_preserve_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let path = socket_path();
                let listener = UnixListener::bind(&path)?;
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await?;
                    let mut byte = [0; 1];
                    assert!(
                        tokio::time::timeout(Duration::from_millis(30), stream.read(&mut byte))
                            .await
                            .is_err()
                    );
                    let mut request = [0; 6];
                    stream.read_exact(&mut request).await?;
                    assert_eq!(&request, b"\0\x06\0\xa9\0\0");
                    stream.write_all(b"\0\x04\0\xab").await?;
                    Ok::<(), io::Error>(())
                });
                let future = Instant::now() + Duration::from_secs(2);
                let mut client = StatisticsClient::connect(&path, future).await?;
                let selector = Selector {
                    subsystem: b"",
                    name: b"",
                };
                let past = Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .ok_or(Error::Overflow)?;
                let mut scratch = [0xa5; 64];
                assert!(matches!(
                    client
                        .get(selector, 0, &mut scratch, past, |_| Ok(()))
                        .await,
                    Err(IpcError::Deadline)
                ));
                assert!(matches!(
                    client
                        .set_and_disconnect(
                            Set {
                                selector,
                                flags: 0,
                                value: 1
                            },
                            &mut scratch,
                            past
                        )
                        .await,
                    Err(IpcError::Deadline)
                ));
                assert_eq!(scratch, [0xa5; 64]);
                assert!(!client.is_closed());
                assert!(matches!(
                    client
                        .get(selector, 0, &mut [0; 5], future, |_| Ok(()))
                        .await,
                    Err(IpcError::Protocol(Error::Capacity))
                ));
                assert!(matches!(
                    client
                        .set_and_disconnect(
                            Set {
                                selector,
                                flags: 0,
                                value: 1
                            },
                            &mut [0; 17],
                            future
                        )
                        .await,
                    Err(IpcError::Protocol(Error::Capacity))
                ));
                assert!(!client.is_closed());
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert_eq!(
                    client
                        .get(selector, 0, &mut scratch, future, |_| Err(
                            Error::InvalidInput
                        ))
                        .await?,
                    0
                );
                assert!(!client.is_closed());
                server.await??;
                std::fs::remove_file(path)?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
    #[test]
    fn dropping_a_partially_read_operation_retires_the_socket()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let path = socket_path();
                let listener = UnixListener::bind(&path)?;
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await?;
                    let mut request = [0; 6];
                    stream.read_exact(&mut request).await?;
                    assert_eq!(&request, b"\0\x06\0\xa9\0\0");
                    stream.write_all(&[0]).await?;
                    let mut byte = [0; 1];
                    assert_eq!(stream.read(&mut byte).await?, 0);
                    Ok::<(), io::Error>(())
                });
                let future = Instant::now() + Duration::from_secs(2);
                let mut client = StatisticsClient::connect(&path, future).await?;
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(100),
                        client.get(
                            Selector {
                                subsystem: b"",
                                name: b""
                            },
                            1,
                            &mut [0; 64],
                            future,
                            |_| Ok(())
                        )
                    )
                    .await
                    .is_err()
                );
                assert!(client.is_closed());
                assert!(matches!(
                    client
                        .get(
                            Selector {
                                subsystem: b"",
                                name: b""
                            },
                            1,
                            &mut [0; 64],
                            future,
                            |_| Ok(())
                        )
                        .await,
                    Err(IpcError::Closed)
                ));
                server.await??;
                std::fs::remove_file(path)?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
    #[test]
    fn malformed_reply_and_callback_refusal_retire_the_socket()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                for malformed in [true, false] {
                    let path = socket_path();
                    let listener = UnixListener::bind(&path)?;
                    let server = tokio::spawn(async move {
                        let (mut stream, _) = listener.accept().await?;
                        let mut request = [0; 6];
                        stream.read_exact(&mut request).await?;
                        if malformed {
                            stream.write_all(b"\0\x03\0\xaa").await?;
                        } else {
                            stream
                                .write_all(b"\0\x14\0\xaa\x80\0\0\x03\0\0\0\0\0\0\0\x09a\0b\0")
                                .await?;
                        }
                        let mut byte = [0; 1];
                        assert_eq!(stream.read(&mut byte).await?, 0);
                        Ok::<(), io::Error>(())
                    });
                    let future = Instant::now() + Duration::from_secs(2);
                    let mut client = StatisticsClient::connect(&path, future).await?;
                    let result = client
                        .get(
                            Selector {
                                subsystem: b"",
                                name: b"",
                            },
                            1,
                            &mut [0; 64],
                            future,
                            |_| Err(Error::PermissionDenied),
                        )
                        .await;
                    if malformed {
                        assert!(matches!(
                            result,
                            Err(IpcError::Protocol(Error::InvalidInput))
                        ));
                    } else {
                        assert!(matches!(
                            result,
                            Err(IpcError::Protocol(Error::PermissionDenied))
                        ));
                    }
                    assert!(client.is_closed());
                    server.await??;
                    std::fs::remove_file(path)?;
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
}
