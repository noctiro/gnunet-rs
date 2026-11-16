//! Original Unix stream fixtures for one-shot client retirement and deadlines.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert actual framing and lifetime outcomes while propagating fixture I/O failures"
)]
use super::*;
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};
static NEXT: AtomicU64 = AtomicU64::new(1);
fn socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "gnunet-ipc-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
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
                StatisticsClient::connect(&path, Instant::now() + Duration::from_secs(2)).await?;
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
fn dropping_a_partially_read_operation_retires_the_socket() -> Result<(), Box<dyn std::error::Error>>
{
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
fn malformed_reply_and_callback_refusal_retire_the_socket() -> Result<(), Box<dyn std::error::Error>>
{
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
