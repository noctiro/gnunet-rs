//! A bounded client for official STATISTICS WATCH subscriptions.
use crate::{IpcError, StatisticsClient, check_deadline, read_frame, write_all_until};
use gnunet_client::statistics::{Instance, Selector, WatchId, WatchSession, WatchUpdate};
use gnunet_types::Error;
use std::path::Path;
use tokio::{
    net::UnixStream,
    time::{Instant, timeout_at},
};

/// A dedicated WATCH connection with at most N requests in its lifetime. It
/// holds caller-borrowed selectors and receives only official WATCH_VALUE frames.
/// GET/SET use a separate [`StatisticsClient`], keeping their untagged terminal
/// messages out of this subscription stream.
pub struct StatisticsWatchClient<'a, const N: usize> {
    stream: Option<UnixStream>,
    session: WatchSession<'a, N>,
}
impl<'a, const N: usize> StatisticsWatchClient<'a, N> {
    /// Connect within the caller's original deadline. Local socket authority and
    /// official configuration resolution remain the caller's responsibility.
    pub async fn connect(
        instance: &'a mut Instance,
        path: impl AsRef<Path>,
        deadline: Instant,
    ) -> Result<Self, IpcError> {
        let mut connection = StatisticsClient::connect(path, deadline).await?;
        Ok(Self {
            stream: connection.stream.take(),
            session: WatchSession::new(instance),
        })
    }
    /// Whether an admitted I/O error, timeout, cancellation or explicit close
    /// retired this connection and all further callback authority.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
    /// Send one WATCH. Success establishes only successful local submission:
    /// upstream has no WATCH acknowledgement and zero values need not produce
    /// an initial notification. The returned WID follows connection order.
    /// Dropping this admitted future closes the stream; it cannot be resumed on
    /// another connection with the same watch IDs.
    pub async fn watch(
        &mut self,
        selector: Selector<'a>,
        scratch: &mut [u8],
        deadline: Instant,
    ) -> Result<WatchId<'a>, IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        let (id, size) = self.session.start(selector, scratch)?;
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let result = timeout_at(
            deadline,
            write_all_until(&mut stream, &scratch[..size], deadline),
        )
        .await
        .map_err(|_| IpcError::Deadline)
        .and_then(|value| value)
        .and_then(|()| check_deadline(deadline));
        match result {
            Ok(()) => {
                self.stream = Some(stream);
                Ok(id)
            }
            Err(error) => {
                self.session.close();
                Err(error)
            }
        }
    }
    /// Wait for the next still-active watch within this call's absolute
    /// deadline. Suppressed notifications for cancelled WIDs are consumed under
    /// the same deadline. No synthetic initial value or END is generated.
    /// Dropping an admitted wait retires the connection to avoid losing a
    /// partially consumed frame and assigning its suffix to another operation.
    pub async fn next(
        &mut self,
        scratch: &mut [u8],
        deadline: Instant,
    ) -> Result<WatchUpdate<'a>, IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        check_deadline(deadline)?;
        if scratch.len() < 24 {
            return Err(Error::Capacity.into());
        }
        let mut stream = self.stream.take().ok_or(IpcError::Closed)?;
        let result = timeout_at(deadline, async {
            loop {
                let size = read_frame(&mut stream, scratch, deadline).await?;
                if let Some(update) = self.session.receive(&scratch[..size])? {
                    check_deadline(deadline)?;
                    return Ok::<_, IpcError>(update);
                }
            }
        })
        .await
        .map_err(|_| IpcError::Deadline)
        .and_then(|value| value)
        .and_then(|value| {
            check_deadline(deadline)?;
            Ok(value)
        });
        match result {
            Ok(update) => {
                self.stream = Some(stream);
                Ok(update)
            }
            Err(error) => {
                self.session.close();
                Err(error)
            }
        }
    }
    /// Suppress future local notifications for this ID. No wire unwatch exists;
    /// the service retains its watch until this connection actually closes.
    /// `id` must have been issued by this same client instance. IDs from another
    /// connection, including a replacement connection, are not interchangeable.
    pub fn cancel(&mut self, id: WatchId<'a>) -> Result<(), IpcError> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        self.session.cancel(id)?;
        Ok(())
    }
    /// Close the actual socket and revoke all local watches immediately.
    pub fn close(&mut self) {
        self.stream.take();
        self.session.close();
    }
}

#[cfg(test)]
mod tests {
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
    ) -> io::Result<(StatisticsWatchClient<'a, N>, UnixStream)> {
        let (stream, peer) = UnixStream::pair()?;
        Ok((
            StatisticsWatchClient {
                stream: Some(stream),
                session: WatchSession::new(instance),
            },
            peer,
        ))
    }

    #[test]
    fn fragmented_notifications_keep_original_ids_after_cancellation()
    -> Result<(), Box<dyn StdError>> {
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
    fn cancelled_notifications_never_extend_the_original_next_deadline()
    -> Result<(), Box<dyn StdError>> {
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
}
