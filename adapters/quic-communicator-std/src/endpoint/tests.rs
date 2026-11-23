//! Original native endpoint/driver retirement on private loopback sockets.
use super::*;
type Test = Result<(), Box<dyn std::error::Error>>;

#[test]
fn ipv6_endpoint_uses_one_native_family_and_refuses_unusable_dials() -> Test {
    let wildcard = native::bind("[::]:0".parse()?)?;
    if !socket2::SockRef::from(&wildcard).only_v6()? {
        return Err("wildcard socket accepts IPv4-mapped traffic".into());
    }
    drop(wildcard);

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let peer = tokio::net::UdpSocket::bind("[::1]:0").await?;
            for profile in [crate::tls::Profile::Raw, crate::tls::Profile::Http3] {
                let mut endpoint = Endpoint::bind(
                    "[::1]:0".parse()?,
                    Tls::fresh(profile, vec!["gnunet".into()])?,
                    Limits {
                        connections: 1,
                        ..Limits::default()
                    },
                    Instant::now() + Duration::from_secs(5),
                )
                .map_err(crate::Fault::from)?;
                for address in [
                    "127.0.0.1:1234",
                    "[::ffff:127.0.0.1]:1234",
                    "[::1%1]:1234",
                    "[fe80::1]:1234",
                    "[::]:1234",
                    "[::1]:0",
                    "[ff02::1]:1234",
                ] {
                    if !matches!(
                        endpoint.dial(address.parse()?).err(),
                        Some(Failure::Protocol(
                            Protocol::InvalidInput | Protocol::Unsupported
                        ))
                    ) {
                        return Err(
                            format!("unusable destination reached the backend: {address}").into(),
                        );
                    }
                }
                let connecting = endpoint
                    .dial(peer.local_addr()?)
                    .map_err(crate::Fault::from)?;
                drop(connecting);
                endpoint.close().map_err(crate::Fault::from)?;
            }
            Ok(())
        })
}

#[test]
fn canceling_original_connection_driver_preserves_endpoint_and_rejects_old_ticket() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let tls = Tls::fresh(crate::tls::Profile::Raw, vec!["gnunet".into()])?;
            let mut endpoint = Endpoint::bind(
                "127.0.0.1:0".parse()?,
                tls,
                Limits::default(),
                Instant::now() + Duration::from_secs(30),
            )
            .map_err(|e| format!("{e:?}"))?;
            let bound = endpoint.local_addr();
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let original = endpoint
                .dial(peer.local_addr()?)
                .map_err(|e| format!("{e:?}"))?;
            let id = original.driver.clone();
            drop(original);
            if endpoint
                .cancel_driver(&endpoint.endpoint_driver.clone())
                .is_ok()
            {
                return Err("endpoint driver was canceled as a connection".into());
            }
            if !endpoint.cancel_driver(&id).map_err(|e| format!("{e:?}"))?
                || !endpoint.driver_done(&id).map_err(|e| format!("{e:?}"))?
            {
                return Err("original driver did not actually retire".into());
            }
            endpoint.release_driver(&id).map_err(|e| format!("{e:?}"))?;
            let fresh = endpoint
                .dial(peer.local_addr()?)
                .map_err(|e| format!("{e:?}"))?;
            let next = fresh.driver.clone();
            drop(fresh);
            if next == id || endpoint.cancel_driver(&id).is_ok() || endpoint.local_addr() != bound {
                return Err("driver ticket or native endpoint was reused".into());
            }
            endpoint
                .cancel_driver(&next)
                .map_err(|e| format!("{e:?}"))?;
            endpoint
                .release_driver(&next)
                .map_err(|e| format!("{e:?}"))?;
            endpoint.close().map_err(|e| format!("{e:?}"))?;
            Ok(())
        })
}

#[test]
fn expired_connection_driver_keeps_original_endpoint_and_fresh_driver_eligible() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let tls = Tls::fresh(crate::tls::Profile::Http3, vec!["gnunet".into()])?;
            let mut endpoint = Endpoint::bind(
                "127.0.0.1:0".parse()?,
                tls,
                Limits {
                    connections: 1,
                    ..Limits::default()
                },
                Instant::now() + Duration::from_secs(30),
            )
            .map_err(|error| format!("{error:?}"))?;
            let bound = endpoint.local_addr();
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let original = endpoint
                .dial(peer.local_addr()?)
                .map_err(|error| format!("{error:?}"))?;
            let old = original.driver.clone();
            drop(original);
            let original_bound = Instant::now() - Duration::from_micros(1);
            endpoint
                .retire_driver_at(&old, original_bound)
                .map_err(|error| format!("{error:?}"))?;
            endpoint
                .retire_driver_at(&old, Instant::now() + Duration::from_secs(20))
                .map_err(|error| format!("{error:?}"))?;
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            endpoint
                .poll_drivers(&mut cx)
                .map_err(|error| format!("{error:?}"))?;
            if !endpoint
                .driver_done(&old)
                .map_err(|error| format!("{error:?}"))?
                || !endpoint
                    .driver_was_canceled(&old)
                    .map_err(|error| format!("{error:?}"))?
                || endpoint.is_poisoned()
            {
                return Err("expired original driver did not retire independently".into());
            }
            endpoint
                .release_driver(&old)
                .map_err(|error| format!("{error:?}"))?;
            let fresh = endpoint
                .dial(peer.local_addr()?)
                .map_err(|error| format!("{error:?}"))?;
            let next = fresh.driver.clone();
            if next == old
                || endpoint.local_addr() != bound
                || endpoint.retire_driver_at(&old, original_bound).is_ok()
            {
                return Err(
                    "old retirement crossed into a fresh driver or replaced its endpoint".into(),
                );
            }
            endpoint
                .poll_drivers(&mut cx)
                .map_err(|error| format!("{error:?}"))?;
            if endpoint
                .driver_done(&next)
                .map_err(|error| format!("{error:?}"))?
            {
                return Err("fresh connection inherited the old retirement deadline".into());
            }
            drop(fresh);
            endpoint
                .cancel_driver(&next)
                .map_err(|error| format!("{error:?}"))?;
            endpoint
                .release_driver(&next)
                .map_err(|error| format!("{error:?}"))?;
            endpoint.close().map_err(|error| format!("{error:?}"))?;
            Ok(())
        })
}
