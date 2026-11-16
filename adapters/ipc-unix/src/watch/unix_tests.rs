//! Original Unix stream WATCH fixtures.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible real socket tests assert framing, cancellation and ownership outcomes"
)]
use super::*;
use std::{error::Error as StdError, io, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn pair<'a, const N: usize>(
    instance: &'a mut Instance,
) -> io::Result<(StatisticsWatchClient<'a, N>, Stream)> {
    let (stream, peer) = Stream::pair()?;
    Ok((
        StatisticsWatchClient {
            stream: Some(stream),
            session: WatchSession::new(instance),
        },
        peer,
    ))
}

#[test]
fn fragmented_notifications_keep_original_ids_after_cancellation() -> Result<(), Box<dyn StdError>>
{
    runtime()?.block_on(async {
            let mut instance=Instance::new();
            let (mut client, mut peer) = pair::<2>(&mut instance)?;
            let server = tokio::spawn(async move {
                let mut requests = [0; 20];
                peer.read_exact(&mut requests).await?;
                assert_eq!(&requests, b"\0\x0a\0\xaca\0old\0\0\x0a\0\xaca\0new\0");
                let values = b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\x18\0\xad\0\0\0\x02\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\x07";
                for byte in values { peer.write_all(&[*byte]).await?; }
                Ok::<_, io::Error>(())
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut scratch = [0; 64];
            let old = client.watch(Selector { subsystem: b"a", name: b"old" }, &mut scratch, deadline).await?;
            let new = client.watch(Selector { subsystem: b"a", name: b"new" }, &mut scratch, deadline).await?;
            client.cancel(old)?;
            let update = client.next(&mut scratch, deadline).await?;
            assert_eq!(update.id, new);
            assert_eq!(update.selector.name, b"new");
            assert_eq!(update.notification.value, 7);
            assert!(update.notification.persistent());
            assert!(!client.is_closed());
            client.close();
            assert!(client.is_closed());
            server.await??;
            Ok(())
        })
}

#[test]
fn cancelled_partial_receive_closes_the_actual_socket() -> Result<(), Box<dyn StdError>> {
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let (mut client, mut peer) = pair::<1>(&mut instance)?;
        let server = tokio::spawn(async move {
            let mut request = [0; 6];
            peer.read_exact(&mut request).await?;
            assert_eq!(&request, b"\0\x06\0\xac\0\0");
            peer.write_all(b"\0\x18\0\xad\0").await?;
            assert_eq!(peer.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut scratch = [0; 64];
        client
            .watch(
                Selector {
                    subsystem: b"",
                    name: b"",
                },
                &mut scratch,
                deadline,
            )
            .await?;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                client.next(&mut scratch, deadline)
            )
            .await
            .is_err()
        );
        assert!(client.is_closed());
        assert!(matches!(
            client.next(&mut scratch, deadline).await,
            Err(IpcError::Closed)
        ));
        server.await??;
        Ok(())
    })
}

#[test]
fn unknown_wid_retires_connection_and_expired_preflight_preserves_it()
-> Result<(), Box<dyn StdError>> {
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let (mut client, mut peer) = pair::<1>(&mut instance)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let past = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .ok_or(Error::Overflow)?;
        let mut scratch = [0xa5; 64];
        assert!(matches!(
            client
                .watch(
                    Selector {
                        subsystem: b"",
                        name: b""
                    },
                    &mut scratch,
                    past
                )
                .await,
            Err(IpcError::Deadline)
        ));
        assert_eq!(scratch, [0xa5; 64]);
        assert!(!client.is_closed());
        let server = tokio::spawn(async move {
            let mut request = [0; 6];
            peer.read_exact(&mut request).await?;
            peer.write_all(b"\0\x18\0\xad\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\x01")
                .await?;
            assert_eq!(peer.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let id = client
            .watch(
                Selector {
                    subsystem: b"",
                    name: b"",
                },
                &mut scratch,
                deadline,
            )
            .await?;
        assert_eq!(id.value(), 0);
        assert!(matches!(
            client.next(&mut scratch, deadline).await,
            Err(IpcError::Protocol(Error::Malformed))
        ));
        assert!(client.is_closed());
        server.await??;
        Ok(())
    })
}

#[test]
fn unpolled_watch_and_rejected_preflight_submit_nothing_and_keep_wid_zero()
-> Result<(), Box<dyn StdError>> {
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let (mut client, mut peer) = pair::<1>(&mut instance)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let selector = Selector {
            subsystem: b"a",
            name: b"b",
        };
        let mut scratch = [0xa5; 32];
        let unpolled = client.watch(selector, &mut scratch, deadline);
        drop(unpolled);
        assert_eq!(scratch, [0xa5; 32]);
        assert!(!client.is_closed());
        assert!(matches!(
            peer.try_read(&mut [0; 1]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            client
                .watch(
                    Selector {
                        subsystem: b"a\0hidden",
                        name: b"b",
                    },
                    &mut scratch,
                    deadline,
                )
                .await,
            Err(IpcError::Protocol(Error::InvalidInput))
        ));
        assert!(matches!(
            client.watch(selector, &mut scratch[..4], deadline).await,
            Err(IpcError::Protocol(Error::Capacity))
        ));
        assert_eq!(scratch, [0xa5; 32]);
        assert!(!client.is_closed());
        let id = client.watch(selector, &mut scratch, deadline).await?;
        assert_eq!(id.value(), 0);
        let mut request = [0; 8];
        peer.read_exact(&mut request).await?;
        assert_eq!(&request, b"\0\x08\0\xaca\0b\0");
        client.close();
        assert_eq!(peer.read(&mut [0; 1]).await?, 0);
        Ok(())
    })
}

#[test]
fn cancelled_notifications_never_extend_the_original_next_deadline() -> Result<(), Box<dyn StdError>>
{
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let (mut client, mut peer) = pair::<1>(&mut instance)?;
        let server = tokio::spawn(async move {
            let mut request = [0; 8];
            peer.read_exact(&mut request).await?;
            assert_eq!(&request, b"\0\x08\0\xaca\0b\0");
            let cancelled = b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01";
            for _ in 0..32 {
                peer.write_all(cancelled).await?;
            }
            assert_eq!(peer.read(&mut [0; 1]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let mut scratch = [0; 32];
        let id = client
            .watch(
                Selector {
                    subsystem: b"a",
                    name: b"b",
                },
                &mut scratch,
                Instant::now() + Duration::from_secs(2),
            )
            .await?;
        client.cancel(id)?;
        let deadline = Instant::now() + Duration::from_millis(30);
        let result =
            tokio::time::timeout(Duration::from_secs(2), client.next(&mut scratch, deadline))
                .await?;
        assert!(matches!(result, Err(IpcError::Deadline)));
        assert!(client.is_closed());
        assert!(matches!(client.cancel(id), Err(IpcError::Closed)));
        server.await??;
        Ok(())
    })
}
