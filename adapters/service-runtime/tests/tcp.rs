//! The same native acceptance and framing contract on every supported desktop OS.
#![forbid(unsafe_code)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual original socket, wire prefix and FIFO assertions accompany fallible setup"
)]
use gnunet_service_runtime::{
    framing::{Accounting, Budget, Class, Framed, Limits},
    service::{Listener, PeerAddress},
};
use std::{future::poll_fn, io, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

#[test]
fn accepted_tcp_retains_exact_partial_wire_and_original_queue()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let mut peer = TcpStream::connect(listener.local_addr()?).await?;
                let accepted =
                    poll_fn(|cx| Listener::Tcp(&listener).poll_canonical_connection(cx)).await?;
                assert_eq!(accepted.peer(), PeerAddress::Tcp(peer.local_addr()?));
                assert!(accepted.diagnostics().is_empty());
                let (connection, _, _) = accepted.into_parts();
                let mut framed = Framed::new(
                    connection,
                    Limits {
                        frame_bytes: 65535,
                        ordinary: Budget {
                            frames: 2,
                            bytes: 16,
                        },
                        reserved: Budget::default(),
                        accounting: Accounting::Remaining,
                        io_slice_bytes: 1,
                    },
                )?;
                let first = [0, 8, 0, 99, 1, 2, 3, 4];
                let second = [0, 8, 0, 99, 5, 6, 7, 8];
                framed.enqueue_copy(&first, 11_u32, Class::Ordinary)?;
                let initial = poll_fn(|cx| framed.poll_write(cx)).await?;
                assert_eq!(
                    (initial.origin, initial.bytes, initial.complete),
                    (11, 1, false)
                );
                let mut bytes = [0; 16];
                peer.read_exact(&mut bytes[..1]).await?;
                framed.enqueue_copy(&second, 12_u32, Class::Ordinary)?;
                let mut written = 1;
                while framed.queued_frames() != 0 {
                    let progress = poll_fn(|cx| framed.poll_write(cx)).await?;
                    written += progress.bytes;
                }
                peer.read_exact(&mut bytes[1..]).await?;
                assert_eq!(written, 16);
                assert_eq!(&bytes[..8], &first);
                assert_eq!(&bytes[8..], &second);
                assert_eq!(framed.charged_bytes(), 0);
                framed.retire();
                assert_eq!(peer.read(&mut bytes).await?, 0);
                Ok::<(), Box<dyn std::error::Error>>(())
            })
            .await
            .map_err(io::Error::other)?
        })
}

#[test]
fn configured_tcp_binding_uses_actual_port_and_retains_exclusive_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let available = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = available.local_addr()?.port();
        drop(available);
        let mut config = gnunet_config::Configuration::default();
        config.set_number(b"test", b"PORT", u64::from(port))?;
        config.set_value(b"test", b"BINDTO", Some(b"127.0.0.1"))?;
        config.set_value(b"test", b"DISABLEV6", Some(b"YES"))?;
        let bound = gnunet_service_runtime::BoundListeners::bind_tcp(&config, b"test")?;
        assert!(bound.failures().is_empty());
        assert_eq!(bound.listeners().len(), 1);
        assert!(gnunet_service_runtime::BoundListeners::bind_tcp(&config, b"test").is_err());
        let _peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let listeners = bound.listeners();
        let accepted = tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| listeners[0].poll_canonical_connection(cx)),
        )
        .await??;
        assert!(matches!(accepted.peer(), PeerAddress::Tcp(_)));
        assert!(accepted.diagnostics().is_empty());
        let (connection, _, _) = accepted.into_parts();
        assert!(
            gnunet_service_runtime::credentials::UnixAccess {
                match_uid: true,
                match_gid: false,
            }
            .allows(&connection)
            .is_err(),
            "a process identity must not authenticate a TCP peer"
        );
        Ok(())
    })
}
