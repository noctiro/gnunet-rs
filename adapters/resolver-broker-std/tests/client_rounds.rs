//! Preserve native Unix/TCP round selection and the original live lookup timeout.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Real private sockets assert endpoint and original deadline ownership"
)]
#[expect(
    dead_code,
    reason = "Shared IO helper module includes assertions exercised by the other integration targets"
)]
#[path = "support/assertions.rs"]
mod support;
use gnunet_client_host::Endpoint;
use gnunet_config::Configuration;
use gnunet_resolver_broker::{Driver, LiveConfiguration, Progress};
use gnunet_service_runtime::connection::Connection;
use std::{
    future::{Future, poll_fn},
    net::Ipv4Addr,
    task::Poll,
    time::Duration,
};
use support::{Dir, Result, cfg, runtime, setup};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    time::{Instant, timeout},
};

async fn connected<const R: usize, const N: usize>(
    driver: &mut Driver<R, N>,
    future: impl Future<Output = std::io::Result<Connection>>,
) -> Result<Connection> {
    let until = Instant::now() + Duration::from_secs(10);
    tokio::pin!(future);
    loop {
        let mut drive = Box::pin(driver.drive_waiting(Some(until), |_| {}));
        let result = poll_fn(|cx| {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                return Poll::Ready(result.map(Some));
            }
            match drive.as_mut().poll(cx) {
                Poll::Ready(Ok(Progress::WaitDeadline)) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "outer guard expired",
                ))),
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        if let Some(connection) = result {
            return Ok(connection);
        }
    }
}

#[test]
fn combined_endpoints_use_unix_on_even_rounds_tcp_on_odd_and_fallback_after_real_unix_failure()
-> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let path = dir.socket("service");
        let unix = UnixListener::bind(&path)?;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut service = Configuration::default();
        service.set_value(
            b"owned",
            b"UNIXPATH",
            Some(path.as_os_str().as_encoded_bytes()),
        )?;
        service.set_value(b"owned", b"HOSTNAME", Some(b"127.0.0.1"))?;
        service.set_value(
            b"owned",
            b"PORT",
            Some(tcp.local_addr()?.port().to_string().as_bytes()),
        )?;
        let (context, mut driver) =
            setup::<4, 128>(LiveConfiguration::new(Configuration::default()))?;
        let endpoint = Endpoint::configuration(service, b"owned", context.resolution_context())?;
        for round in [0, 1, 2] {
            let mut stream = connected(&mut driver, endpoint.attempt(round)).await?;
            stream.write_all(b"x").await?;
            let mut marker = [0];
            if round == 1 {
                let (mut peer, _) = timeout(Duration::from_secs(1), tcp.accept()).await??;
                peer.read_exact(&mut marker).await?;
                assert!(
                    timeout(Duration::from_millis(10), unix.accept())
                        .await
                        .is_err()
                );
            } else {
                let (mut peer, _) = timeout(Duration::from_secs(1), unix.accept()).await??;
                peer.read_exact(&mut marker).await?;
                assert!(
                    timeout(Duration::from_millis(10), tcp.accept())
                        .await
                        .is_err()
                );
            }
            assert_eq!(marker, *b"x");
            drop(stream);
            assert_eq!(context.pending_requests()?, 0);
        }
        drop(unix);
        std::fs::remove_file(path)?;
        let mut stream = connected(&mut driver, endpoint.attempt(2)).await?;
        stream.write_all(b"f").await?;
        let (mut peer, _) = timeout(Duration::from_secs(1), tcp.accept()).await??;
        let mut marker = [0];
        peer.read_exact(&mut marker).await?;
        assert_eq!(marker, *b"f");
        drop(stream);
        drop(peer);
        assert_eq!(context.pending_requests()?, 0);
        driver.disconnect()?;
        Ok(())
    })
}

#[test]
fn unreachable_valid_resolver_expires_the_original_five_second_client_lookup() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        // A present UNIXPATH is source-admissible, even though its own listener
        // does not exist. Do not confuse this with no-handle admission failure.
        let (context, mut driver) =
            setup::<4, 128>(LiveConfiguration::new(cfg(&dir.socket("missing"))?))?;
        let mut service = Configuration::default();
        service.set_value(b"owned", b"HOSTNAME", Some(b"unreachable-owned.invalid"))?;
        service.set_value(b"owned", b"PORT", Some(b"1"))?;
        let endpoint = Endpoint::configuration(service, b"owned", context.resolution_context())?;
        let start = Instant::now();
        let error = connected(&mut driver, endpoint.attempt(0))
            .await
            .err()
            .ok_or("query unexpectedly connected")?;
        assert!(start.elapsed() >= Duration::from_millis(4500), "{error}");
        assert!(
            start.elapsed() < Duration::from_secs(9),
            "outer guard must not impersonate native timeout"
        );
        assert_eq!(context.pending_requests()?, 0);
        driver.disconnect()?;
        Ok(())
    })
}
