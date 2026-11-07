//! Real public CLIENT transport ownership over self-owned Unix/TCP sockets.
#![forbid(unsafe_code)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Assertions check actual public transport and caller cursor ownership."
    )]
    use gnunet_client_host::{ConnectionAttempt, Endpoint};
    use gnunet_service_runtime::connection::Connection;
    use std::{
        future::{Future, poll_fn},
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    type Test = Result<(), Box<dyn std::error::Error>>;
    const GET: [u8; 8] = [0, 8, 0, 169, b's', 0, b'n', 0];
    const END: [u8; 4] = [0, 4, 0, 171];
    struct Driver {
        attempt: Option<Pin<Box<ConnectionAttempt>>>,
        connection: Option<Connection>,
        tx: usize,
        rx: [u8; 4],
        used: usize,
    }
    impl Driver {
        fn new(attempt: ConnectionAttempt) -> Self {
            Self {
                attempt: Some(Box::pin(attempt)),
                connection: None,
                tx: 0,
                rx: [0xa5; 4],
                used: 0,
            }
        }
        fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.connection.is_some() {
                return Poll::Ready(Ok(()));
            }
            let result = self
                .attempt
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?
                .as_mut()
                .poll(cx);
            match result {
                Poll::Pending => Poll::Pending,
                Poll::Ready(value) => {
                    self.connection = Some(value?);
                    self.attempt = None;
                    Poll::Ready(Ok(()))
                }
            }
        }
        fn poll(&mut self, cx: &mut Context<'_>, raw_write: bool) -> Poll<io::Result<()>> {
            match self.poll_connect(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            let stream = self
                .connection
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?;
            if self.tx < GET.len() {
                let end = (self.tx + 1).min(GET.len());
                let result = if raw_write {
                    match stream.poll_write_ready(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result?,
                    }
                    match stream.try_write(&GET[self.tx..end]) {
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                || error.kind() == io::ErrorKind::Interrupted =>
                        {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        value => Poll::Ready(value),
                    }
                } else {
                    Pin::new(&mut *stream).poll_write(cx, &GET[self.tx..end])
                };
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(value) => {
                        let n = value?;
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        self.tx += n;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }
            if self.used < self.rx.len() {
                let mut buf = ReadBuf::new(&mut self.rx[self.used..self.used + 1]);
                match Pin::new(stream).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                }
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                self.used += buf.filled().len();
                if self.used < self.rx.len() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            Poll::Ready(Ok(()))
        }
        async fn drive(&mut self, raw_write: bool) -> io::Result<()> {
            poll_fn(|cx| self.poll(cx, raw_write)).await
        }
    }
    async fn server(
        mut stream: impl AsyncRead + AsyncWrite + Unpin,
        release: tokio::sync::oneshot::Receiver<()>,
    ) -> io::Result<()> {
        let mut get = [0; 8];
        stream.read_exact(&mut get).await?;
        assert_eq!(get, GET);
        stream.write_all(&END[..2]).await?;
        release.await.map_err(|_| io::ErrorKind::BrokenPipe)?;
        stream.write_all(&END[2..]).await?;
        assert_eq!(stream.read(&mut [0]).await?, 0);
        Ok(())
    }
    async fn exercise(
        mut driver: Driver,
        release: tokio::sync::oneshot::Sender<()>,
        raw_write: bool,
        label: &str,
    ) -> Test {
        let pending = poll_fn(|cx| match driver.poll_connect(cx) {
            Poll::Pending => Poll::Ready(Ok(true)),
            Poll::Ready(result) => Poll::Ready(result.map(|_| false)),
        })
        .await?;
        let held = driver
            .attempt
            .as_ref()
            .map(|future| future.as_ref().get_ref() as *const ConnectionAttempt);
        let canceled = driver.drive(raw_write);
        drop(canceled);
        assert_eq!(
            held,
            driver
                .attempt
                .as_ref()
                .map(|future| future.as_ref().get_ref() as *const ConnectionAttempt)
        );
        tokio::time::timeout(
            Duration::from_secs(3),
            poll_fn(|cx| {
                let step = driver.poll(cx, raw_write);
                if let Poll::Ready(Err(error)) = step {
                    return Poll::Ready(Err(error));
                }
                if driver.used == 2 {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await??;
        assert_eq!(driver.tx, GET.len());
        assert_eq!(&driver.rx[..2], &END[..2]);
        assert!(
            tokio::time::timeout(Duration::from_millis(2), driver.drive(raw_write))
                .await
                .is_err()
        );
        assert_eq!(driver.used, 2);
        assert!(driver.connection.is_some());
        assert!(driver.attempt.is_none());
        release
            .send(())
            .map_err(|_| "server release receiver closed")?;
        tokio::time::timeout(Duration::from_secs(3), driver.drive(raw_write)).await??;
        assert_eq!(driver.used, 4);
        assert_eq!(driver.rx, END);
        drop(driver);
        let _observed_first_poll = (label, pending);
        Ok(())
    }
    #[cfg(unix)]
    struct SocketPath(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for SocketPath {
        fn drop(&mut self) {
            match std::fs::remove_file(&self.0) {
                Ok(()) | Err(_) => {}
            }
        }
    }
    #[test]
    #[cfg(unix)]
    fn public_unix_attempt_is_lazy_and_canceled_wait_retains_original_io() -> Test {
        fn traits<T: AsyncRead + AsyncWrite + Send + Unpin>() {}
        traits::<Connection>();
        fn future_traits<T: Future<Output = io::Result<Connection>> + Send + Unpin>() {}
        future_traits::<ConnectionAttempt>();
        let path =
            std::env::temp_dir().join(format!("gnunet-facade-review-{}.sock", std::process::id()));
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        let _owned_path = SocketPath(path.clone());
        listener.set_nonblocking(true)?;
        let endpoint = Endpoint::unix(path)?;
        let attempt = endpoint.attempt(0);
        assert_eq!(
            listener.accept().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let listener = tokio::net::UnixListener::from_std(listener)?;
                let (send, receive) = tokio::sync::oneshot::channel();
                let peer = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await?;
                    server(stream, receive).await
                });
                exercise(Driver::new(attempt), send, false, "Unix").await?;
                peer.await??;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
    #[test]
    fn public_configured_tcp_attempt_reuses_native_stream_without_resolver_dependency() -> Test {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let mut config = gnunet_config::Configuration::new(Default::default());
        config.set_value(b"statistics", b"HOSTNAME", Some(b"127.0.0.1"))?;
        config.set_value(
            b"statistics",
            b"PORT",
            Some(listener.local_addr()?.port().to_string().as_bytes()),
        )?;
        let mut domain =
            crate::resolution_domain::Domain::new(gnunet_config::Configuration::default())?;
        let endpoint = Endpoint::configuration(config, b"statistics", domain.resolution())?;
        let attempt = endpoint.attempt(1);
        assert_eq!(
            listener.accept().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                domain.start()?;
                let listener = tokio::net::TcpListener::from_std(listener)?;
                let (send, receive) = tokio::sync::oneshot::channel();
                let peer = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await?;
                    server(stream, receive).await
                });
                exercise(Driver::new(attempt), send, true, "TCP").await?;
                peer.await??;
                Ok(())
            })
    }
}
